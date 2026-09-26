"""Durable follower through authenticated in-process binding/record APIs and real Store rows.

Discovery pages are an injected contract fixture; its server-side query is tested
by the independent candidates module. No socket or deployment is involved.
"""
import asyncio
import copy
import dataclasses
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from tests import test_verification_records as casebook
from tests import test_verification_api_boundary as edge
from local_observe.http import TransportError
from local_observe.inventory.validation import digest, utc_text
from local_observe.platform import cli, verification_follower as follower
from local_observe.platform.api import create_app
from local_observe.store import client as facade

NOW = casebook.RECORD_NOW


def settings(root):
    return follower.config({'schema_version': 1, 'platform_url': 'https://platform.example.com/platform',
                            'platform_token_file': str(root / 'platform-token'),
                            'cursor_path': str(root / 'cursor.json'),
                            'store_url': 'https://store.example.com', 'store_user': 'readonly',
                            'store_password_file': str(root / 'store-password'), 'page_size': 2})


class Telemetry:
    def __init__(self, values=(95,), *, mutate=None, unavailable=False):
        self.values, self.mutate, self.unavailable = values, mutate, unavailable
        self.calls = []

    def read(self, query_type, *, window, parameters, selectors):
        self.calls.append((query_type, window, parameters, selectors))
        rows = [facade.MetricSample(selectors['metric_name'], value,
                                   utc_text(window.instant('end') - dt.timedelta(seconds=1)),
                                   resource_id=parameters['resource_id']) for value in self.values]
        outcome = facade.build_outcome(facade.QUERY_KINDS[query_type], parameters, window,
                                        [] if self.unavailable else rows,
                                        series_exists=not self.unavailable)
        return self.mutate(outcome) if self.mutate else outcome


class Platform:
    """Discovery fixture, real authenticated ASGI for captured bindings and record writes."""
    def __init__(self, case, gate):
        self.case = case
        self.app = create_app(case['store'], edge.CREDENTIALS, gate)
        # This in-process bridge needs no Windows overlapped I/O. A selector loop
        # keeps thread-future wakeups independent of the host's Proactor policy.
        self.loop = asyncio.SelectorEventLoop()
        self.calls = []
        self.pages = None
        self.lost_ack = False
        self.bad_ack = False
        self.identity = 'verify-worker'

    def close(self):
        self.app.verification_api.close()
        self.loop.run_until_complete(asyncio.wait_for(self.app.verification_api.wait_idle(), timeout=10))
        self.loop.close()

    def candidate(self):
        return {'execution_id': self.case['execution_id'], 'action_id': self.case['action_id'],
                'finished_at': utc_text(self.case['terminal'])}

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        parsed = urlsplit(path)
        if parsed.path == '/v1/verification/candidates':
            if self.pages is not None:
                return 200, self.pages.pop(0)
            ids = self.case['store'].list_verifications(self.case['execution_id'], casebook.VERIFIER)
            return 200, {'items': [] if ids else [self.candidate()], 'next_after': None}
        response = self.loop.run_until_complete(asyncio.wait_for(edge.drive(
            self.app, method, parsed.path, query_string=parsed.query.encode(),
            body=json.dumps(payload).encode() if payload is not None else b'', identity=self.identity), timeout=10))
        if method == 'POST' and self.lost_ack:
            self.lost_ack = False
            raise TransportError('simulated lost acknowledgement')
        if method == 'POST' and self.bad_ack:
            return 200, {'verification_id': 'a' * 64, 'created': True}
        return response.status, response.payload


class FollowerTests(casebook.VerificationFixture):
    def setUp(self):
        super().setUp()
        self.clock = edge.ServerClock(NOW).install(self)
        self.case = self.executed(self.bound(policy=self.policy()))
        self.platform = Platform(self.case, self.gate)
        self.addCleanup(self.platform.close)
        self.settings = settings(self.root)
        self.telemetry = Telemetry()

    def tick(self, *, now=NOW, telemetry=None):
        return follower.tick(self.settings, self.platform, lambda: telemetry or self.telemetry, now=now)

    def record(self):
        ids = self.case['store'].list_verifications(self.case['execution_id'], casebook.VERIFIER)
        self.assertEqual(len(ids), 1)
        return self.case['store'].get_verification(ids[0], casebook.VERIFIER)

    def test_succeeded_run_with_still_firing_metric_is_durable_not_cleared(self):
        result = self.tick()
        self.assertEqual(result['submitted'], 1)
        record = self.record()
        self.assertEqual(record['verdict'], 'not_cleared')
        self.assertEqual(record['recorded_by'], 'verify-worker')
        self.assertEqual(self.case['store'].records('executions')[0]['status'], 'succeeded')
        self.assertEqual(self.case['store'].status()['incidents'], {'open': 1})
        self.assertEqual(set(self.telemetry.calls[0][2]), {'resource_id', 'rule_id', 'artifact_sha256'})
        self.assertEqual(self.telemetry.calls[0][3], {'metric_name': casebook.SERIES})
        self.assertTrue(all('/actions/' not in path and '/events' not in path
                            for _, path, _ in self.platform.calls))

    def test_captured_binding_survives_changed_current_policy(self):
        self.case['store'].verification_policy = self.policy(mapping=self.mapping(threshold=1000))
        self.tick()
        self.assertEqual(self.record()['origin']['threshold'], 90)
        self.assertEqual(self.record()['verdict'], 'not_cleared')

    def test_lost_ack_restarts_with_exact_pending_before_reads_even_after_expiry(self):
        self.platform.lost_ack = True
        with self.assertRaises(TransportError):
            self.tick()
        saved = Path(self.settings['cursor_path']).read_bytes()
        statement = json.loads(saved)['pending']['statements'][0]
        accepted_id = self.record()['verification_id']
        self.platform.calls.clear()
        self.clock.advance(dt.timedelta(days=40))
        with mock.patch.object(self.telemetry, 'read', side_effect=AssertionError('must not resample')):
            result = self.tick(now=self.clock.moment)
        self.assertEqual(result['status'], 'replayed')
        self.assertEqual(self.platform.calls, [('POST', '/v1/verification/records', statement)])
        self.assertEqual(self.record()['verification_id'], accepted_id)
        self.assertEqual(self.record()['verdict'], 'not_cleared')
        self.assertIsNone(follower.load_cursor(self.settings)['pending'])

    def test_bad_ack_preserves_pending_and_refuses_cursor_advance(self):
        self.platform.bad_ack = True
        with self.assertRaises(follower.FollowerError):
            self.tick()
        state = follower.load_cursor(self.settings)
        self.assertEqual(state['pending']['next_index'], 0)
        self.assertIsNone(state['after'])
        self.platform.bad_ack = False
        self.tick()
        self.assertEqual(self.record()['verdict'], 'not_cleared')

    def test_full_post_terminal_window_is_required_before_store_read(self):
        early = self.case['terminal'] + dt.timedelta(seconds=casebook.WINDOW_SECONDS - 1)
        self.assertEqual(self.tick(now=early)['waiting'], 1)
        self.assertEqual(self.telemetry.calls, [])
        self.assertEqual(self.tick()['submitted'], 1)

    def test_page_cursor_advances_across_empty_filtered_page_and_wraps_after_restart(self):
        execution = self.case['execution_id']
        self.platform.pages = [{'items': [], 'next_after': execution},
                               {'items': [], 'next_after': None},
                               {'items': [self.platform.candidate()], 'next_after': None}]
        self.tick()
        self.assertEqual(follower.load_cursor(self.settings)['after'], execution)
        self.tick()
        self.assertIsNone(follower.load_cursor(self.settings)['after'])
        self.tick()
        paths = [path for method, path, _ in self.platform.calls if 'candidates?' in path]
        self.assertNotIn('after=', paths[0])
        self.assertEqual(parse_qs(urlsplit(paths[1]).query)['after'], [execution])
        self.assertNotIn('after=', paths[2])
        self.assertEqual(self.record()['verdict'], 'not_cleared')

    def test_large_page_keeps_original_count_and_truthful_client_truncation(self):
        self.tick(telemetry=Telemetry(values=[1] * 20 + [999]))
        record = self.record()
        self.assertEqual(record['verdict'], 'unknown')
        self.assertEqual(record['reason'], 'evidence-truncated')
        self.assertEqual(record['receipt']['sample_count'], 21)
        self.assertTrue(record['receipt']['truncated'])
        self.assertEqual(len(record['samples']), 20)

    def test_unavailable_is_unknown_and_never_automatically_rechecked(self):
        self.tick(telemetry=Telemetry(unavailable=True))
        self.assertEqual(self.record()['verdict'], 'unknown')
        self.assertEqual(self.record()['reason'], 'store-unanswered')
        self.assertEqual(self.record()['samples'], [])
        self.assertEqual(self.tick()['submitted'], 0)
        self.assertEqual(self.telemetry.calls, [])

    def test_expired_read_is_recorded_unknown_without_detail(self):
        def expire(outcome):
            return dataclasses.replace(outcome, status='expired', samples=(), detail='private-backend-error')
        self.tick(telemetry=Telemetry(mutate=expire))
        record = self.record()
        self.assertEqual(record['verdict'], 'unknown')
        self.assertEqual(record['samples'], [])
        self.assertNotIn('private-backend-error', json.dumps(record))

    def test_foreign_scope_and_stale_samples_refused_and_revisited_without_posts(self):
        mutations = [lambda out: dataclasses.replace(out, samples=(dataclasses.replace(out.samples[0],
                                             resource_id=self.service),)),
                     lambda out: dataclasses.replace(out, samples=(dataclasses.replace(out.samples[0],
                                             timestamp=utc_text(casebook.NOW)),)),
                     lambda out: dataclasses.replace(out, receipt=dataclasses.replace(out.receipt,
                                             parameters={'resource_id': self.service}))]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                result = self.tick(telemetry=Telemetry(mutate=mutate))
                self.assertEqual(result['refused'], 1)
                self.assertEqual(result['submitted'], 0)
                self.assertFalse(any(method == 'POST' for method, _, _ in self.platform.calls))
        self.assertEqual(self.tick()['submitted'], 1)

    def test_off_origin_row_beyond_excerpt_is_still_refused(self):
        def mutate(out):
            return dataclasses.replace(out, samples=out.samples[:-1] +
                                       (dataclasses.replace(out.samples[-1], resource_id=self.service),))
        result = self.tick(telemetry=Telemetry(values=[1] * 21, mutate=mutate))
        self.assertEqual(result['refused'], 1)
        self.assertFalse(any(method == 'POST' for method, _, _ in self.platform.calls))

    def test_unauthorized_attestor_cannot_read_binding_or_write(self):
        self.platform.identity = 'test-detector'
        self.assertEqual(self.tick()['refused'], 1)
        self.assertEqual(self.telemetry.calls, [])
        self.assertEqual(self.case['store'].list_verifications(self.case['execution_id'], casebook.VERIFIER), [])

    def test_poison_cursor_and_changed_configuration_are_read_only_refusals(self):
        self.platform.lost_ack = True
        with self.assertRaises(TransportError):
            self.tick()
        path = Path(self.settings['cursor_path'])
        original = path.read_bytes()
        changed = dict(self.settings, page_size=1)
        with self.assertRaises(follower.FollowerError):
            follower.tick(changed, self.platform, lambda: self.telemetry, now=NOW)
        self.assertEqual(path.read_bytes(), original)
        poison = json.loads(original)
        poison['pending']['statements'][0]['outcome'] = 'unavailable'
        path.write_text(json.dumps(poison), encoding='utf-8')
        poisoned = path.read_bytes()
        previous = len(self.platform.calls)
        with self.assertRaises(follower.StateError):
            self.tick()
        self.assertEqual(path.read_bytes(), poisoned)
        self.assertEqual(len(self.platform.calls), previous)

    def test_scheduler_reloads_pending_after_lost_ack_without_resampling(self):
        config_path = self.root / 'config.json'
        config_path.write_text(json.dumps(self.settings), encoding='utf-8')
        self.platform.lost_ack = True
        stops = iter((False, False, True))
        sleeps = []
        with mock.patch.object(follower, 'JsonClient', return_value=self.platform), \
                mock.patch.object(follower.bounded, '_token', return_value='a' * 40), \
                mock.patch.object(follower, '_store', return_value=self.telemetry), \
                mock.patch('sys.stdout', new=io.StringIO()):
            result = follower.schedule(str(config_path), loop=True, interval=5,
                                       stop=lambda: next(stops), sleep=sleeps.append, clock=lambda: NOW)
        self.assertEqual(result, 0)
        self.assertEqual(sleeps, [5, 5])
        self.assertEqual(len(self.telemetry.calls), 1)
        posted = [body for method, _, body in self.platform.calls if method == 'POST']
        self.assertEqual(posted[0], posted[1])


class ConfigurationTests(unittest.TestCase):
    def test_disabled_module_and_cli_do_no_io_or_sleep(self):
        for environment in ({}, {follower.CONFIG_ENVIRONMENT: '  '}):
            with self.subTest(environment=environment), \
                    mock.patch.dict('os.environ', environment, clear=True), \
                    mock.patch.object(follower, '_read', side_effect=AssertionError('file I/O')), \
                    mock.patch.object(follower, 'JsonClient', side_effect=AssertionError('client')), \
                    mock.patch.object(follower, '_store', side_effect=AssertionError('store')), \
                    mock.patch.object(follower.bounded, '_token', side_effect=AssertionError('credential')), \
                    mock.patch.object(follower.time, 'sleep', side_effect=AssertionError('sleep')):
                self.assertEqual(follower.run(environ=environment), 0)
                with mock.patch('sys.argv', ['verify-follow', '--loop']):
                    self.assertEqual(follower.main(), 0)
                with mock.patch('sys.argv', ['lo-platform', 'verify-follow', '--loop']):
                    self.assertEqual(cli.main(), 0)

    def test_strict_configuration_and_interval(self):
        with tempfile.TemporaryDirectory() as directory:
            valid = settings(Path(directory))
            self.assertEqual(valid['platform_url'], 'https://platform.example.com/platform')
            for change in ({'page_size': True}, {'page_size': 33}, {'timeout': 0}, {'unknown': 1},
                           {'platform_url': 'http://platform.example.com'},
                           {'platform_url': 'https://user:password@platform.example.com'},
                           {'store_allow_http': 1}, {'cursor_path': 'relative'},
                           {'store_password_file': valid['platform_token_file']}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    follower.config(dict(valid, **change))
            for interval in (True, 0, 4, 3601, 3.5):
                with mock.patch.object(follower, 'run', side_effect=AssertionError('must not run')), \
                        mock.patch('sys.stdout', new=io.StringIO()):
                    self.assertEqual(follower.schedule('enabled.json', loop=True, interval=interval), 1)

    def test_oversized_duplicate_and_nonfinite_config_refuse_before_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for text in (' ' * (follower.MAX_CONFIG_BYTES + 1), '{"schema_version":1,"schema_version":1}',
                         '{"page_size":NaN}', '[' * 1100):
                path.write_text(text, encoding='utf-8')
                with mock.patch.object(follower.bounded, '_token', side_effect=AssertionError('credential')), \
                        mock.patch('sys.stdout', new=io.StringIO()):
                    self.assertEqual(follower.run(str(path)), 1)

    def test_discovery_shape_monotonicity_and_unknown_fields_refused(self):
        key = '00000000-0000-4000-8000-000000000001'
        for response in ({'items': [], 'next_after': key}, {'items': [], 'next_after': None, 'extra': 1},
                         {'items': [None], 'next_after': None}, {'items': [], 'next_after': 'invalid'}):
            with self.assertRaises((ValueError, follower.bounded._Refused)):
                follower.candidates(response, key, 1)

    def test_http_only_cli_refuses_database_before_any_follower_io(self):
        with mock.patch.object(follower, 'schedule', side_effect=AssertionError('must not run')), \
                mock.patch('sys.argv', ['lo-platform', '--database', 'state.db', 'verify-follow']), \
                mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit) as caught:
            cli.main()
        self.assertEqual(caught.exception.code, 2)

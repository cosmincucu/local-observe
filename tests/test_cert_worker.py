"""Durable certificate delivery through real Store intake, without external services."""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.http import TransportError
from local_observe.inventory.validation import digest, utc_text
from local_observe.platform.certcheck import CertFacts
from local_observe.platform import cert_worker as worker
from local_observe.platform.state import Actor, Store

NOW = dt.datetime(2026, 9, 10, 12, tzinfo=dt.timezone.utc)


class StoreTransport:
    def __init__(self, root):
        self.store = Store(root / 'store.db')
        self.actor = Actor('synthetics.tls', 'producer')
        self.calls = []
        self.lose = False
        self.now = NOW

    def request(self, method, path, payload):
        self.calls.append((path, copy.deepcopy(payload)))
        if path == '/v1/evidence':
            return 200, {'evidence_id': self.store.put_evidence(payload, self.actor, now=self.now)}
        result = self.store.intake(payload, self.actor, now=self.now)
        if self.lose:
            self.lose = False
            raise TransportError('Synthetic lost acknowledgement')
        return 200, result


class WorkerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = worker.config({'schema_version': 1, 'host': 'fixture.example', 'connect_ip': '127.0.0.1',
            'resource_id': '00000000-0000-4000-8000-000000000001', 'rule_id': 'cert', 'source': 'synthetics.tls',
            'platform_url': 'https://platform.example/platform', 'platform_token_file': str(self.root / 'token'),
            'cursor_path': str(self.root / 'cursor.json')})
        self.platform = StoreTransport(self.root)
        self.provider = mock.Mock(return_value=CertFacts(utc_text(NOW + dt.timedelta(days=20)), True, ['fixture.example']))
        self.factory = mock.Mock(return_value=self.provider)

    def tick(self, now=NOW):
        self.platform.now = now
        return worker.tick(self.settings, self.platform, self.factory, now=now)

    def test_evidence_precedes_events_and_resolves_through_real_store(self):
        self.assertEqual(self.tick(), 'delivered')
        self.assertEqual([p for p, _ in self.platform.calls[:3]], ['/v1/evidence'] * 3)
        event = self.platform.calls[-1][1]
        reference = event['evidence'][0]
        sample = self.platform.store.get_evidence(reference['source'], reference['parameters']['sample_id'], now=NOW)
        self.assertEqual(sample['sample']['value'], 20)
        self.assertEqual(self.tick(), 'idle')
        self.assertEqual(self.provider.call_count, 1)

    def test_lost_ack_restart_replays_exact_batch_without_fetch_after_expiry(self):
        self.platform.lose = True
        with self.assertRaises(TransportError):
            self.tick()
        pending = worker.load_cursor(self.settings)['pending']['batch']
        saved = Path(self.settings['cursor_path']).read_bytes()
        self.factory.side_effect = AssertionError('must not construct provider')
        self.platform.calls.clear()
        self.assertEqual(self.tick(NOW + dt.timedelta(days=40)), 'replayed')
        self.assertEqual(self.platform.calls,
                         [('/v1/evidence', s) for s in pending['samples']] +
                         [('/v1/events', e) for e in pending['events']])
        self.assertEqual(self.platform.store.get_evidence(
            self.settings['source'], pending['samples'][0]['sample_id'], now=self.platform.now),
            {'status': 'expired'})
        self.assertIsNone(worker.load_cursor(self.settings)['pending'])
        self.assertNotEqual(Path(self.settings['cursor_path']).read_bytes(), saved)
        self.assertEqual(len(self.platform.store.records('events')), len(pending['events']))

    def test_wrong_ack_retains_pending_bytes_and_retries_before_fetch(self):
        with mock.patch.object(self.platform, 'request', return_value=(200, {'evidence_id': 'wrong'})):
            with self.assertRaises(worker.WorkerError):
                self.tick()
            before = Path(self.settings['cursor_path']).read_bytes()
            with self.assertRaises(worker.WorkerError):
                self.tick(NOW + dt.timedelta(minutes=1))
        self.assertEqual(Path(self.settings['cursor_path']).read_bytes(), before)
        self.assertEqual(self.factory.call_count, 1)

    def test_measurement_failure_persists_only_coverage(self):
        self.provider.side_effect = OSError('private TLS response')
        self.assertEqual(self.tick(), 'delivered')
        self.assertEqual(len(self.platform.calls), 1)
        self.assertEqual(self.platform.calls[0][1]['kind'], 'coverage')
        self.assertNotIn('private TLS response', Path(self.settings['cursor_path']).read_text())

    def test_corrupt_and_changed_configuration_refuse_without_http_or_overwrite(self):
        self.platform.lose = True
        with self.assertRaises(TransportError):
            self.tick()
        path = Path(self.settings['cursor_path'])
        original = path.read_bytes()
        self.settings['port'] = 8443
        self.platform.calls.clear()
        with self.assertRaises(worker.WorkerError):
            self.tick()
        self.assertEqual(path.read_bytes(), original)
        self.settings['port'] = 443
        for value in [b'{"schema_version":1,"schema_version":1}', b'x' * (worker.MAX_CURSOR + 1), b'{}']:
            path.write_bytes(value)
            with self.assertRaises(worker.WorkerError):
                self.tick()
            self.assertEqual(path.read_bytes(), value)
        self.assertEqual(self.platform.calls, [])

    def test_foreign_pending_scope_refused_even_with_recomputed_fingerprint(self):
        self.platform.lose = True
        with self.assertRaises(TransportError):
            self.tick()
        state = worker.load_cursor(self.settings)
        state['pending']['batch']['events'][0]['source'] = 'foreign'
        state['pending']['fingerprint'] = digest(state['pending']['batch'])
        path = Path(self.settings['cursor_path'])
        path.write_text(json.dumps(state))
        before = path.read_bytes()
        with self.assertRaises(worker.WorkerError):
            self.tick()
        self.assertEqual(path.read_bytes(), before)

    def test_off_means_no_file_client_credentials_provider_or_sleep(self):
        for selected in (None, '', '  '):
            with mock.patch.object(worker, 'read_json', side_effect=AssertionError), \
                 mock.patch.object(worker, 'JsonClient', side_effect=AssertionError), \
                 mock.patch.object(worker, 'TLSProvider', side_effect=AssertionError), \
                 mock.patch.object(worker, 'read_credential', side_effect=AssertionError):
                self.assertEqual(worker.run(selected, environ={}, loop=True, sleep=mock.Mock(side_effect=AssertionError)), 0)
        with mock.patch.dict('os.environ', {}, clear=True):
            self.assertEqual(worker.main(['--loop']), 0)

    def test_strict_configuration_unknown_keys_bad_thresholds_and_credential_alias(self):
        for change in ({'unknown': True}, {'thresholds': [3, 30]}, {'timeout': True},
                       {'platform_token_file': self.settings['cursor_path']}, {'connect_ip': 'fixture.example'}):
            with self.assertRaises(ValueError):
                worker.config(dict(self.settings, **change))

    def test_two_scheduled_rounds_replay_lost_ack_without_remeasurement(self):
        config_path = self.root / 'config.json'
        config_path.write_text(json.dumps(self.settings))
        self.platform.lose = True
        sleep = mock.Mock()
        with mock.patch.object(worker, 'read_credential', return_value='x' * 32), \
             mock.patch.object(worker, 'JsonClient', return_value=self.platform), \
             mock.patch.object(worker, 'TLSProvider', return_value=self.provider):
            result = worker.run(str(config_path), loop=True, sleep=sleep,
                                clock=mock.Mock(side_effect=[NOW, NOW + dt.timedelta(days=40)]),
                                stop=mock.Mock(side_effect=[False, True]))
        self.assertEqual(result, 0)
        sleep.assert_called_once_with(60)
        self.assertEqual(self.provider.call_count, 1)

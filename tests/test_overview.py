import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
import asyncio
from unittest import mock
import httpx

from local_observe.platform.overview import overview
from local_observe.platform.homepage import configuration

NOW = dt.datetime(2026, 9, 6, 20, tzinfo=dt.timezone.utc)


class Store:
    """A partial double of `platform.state.Store`: enough for the overview read and the role gates.

    The refusal audit gave the POST edge one new store call — `record_refusal`, the durable audit row for a
    refusal this edge made itself, before any lifecycle method was entered — so the double names it and
    records what it was handed rather than inventing one. It writes nothing: the durability, the bounds,
    the write budget and the counters are tested against the real `Store` in `tests/test_refusal_audit.py`.
    """

    from local_observe.platform.notification_safety import NotificationPolicy
    notification_policy = NotificationPolicy()

    def __init__(self):
        self.refusals = []

    def record_refusal(self, attempt, actor, reason, subject=None, *, now=None):
        self.refusals.append((attempt, getattr(actor, 'identity', None), reason, subject))

    def status(self):
        return {'incidents': {'open': 2}, 'actions': {'pending': 1}, 'notifications': {'pending': 3, 'sending': 1, 'dead': 2}}


class OverviewTests(unittest.TestCase):
    def test_unconfigured_is_unknown_not_zero(self):
        value = overview(Store(), now=NOW)
        self.assertEqual(value['open_incidents'], 2)
        self.assertEqual(value['pending_deliveries'], 4)
        self.assertIsNone(value['failed_jobs'])
        self.assertEqual(value['jobs_display'], 'Unknown')

    def test_fresh_stale_future_and_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'overview.json'
            signals = {name: {'status': 'healthy', 'value': value, 'observed_at': NOW.isoformat(), 'max_age_seconds': 60, 'source': 'fixture'}
                for name, value in [('jobs', 0), ('backup', NOW.isoformat()), ('model', 'test-model')]}
            path.write_text(json.dumps({'schema_version': 1, 'signals': signals}))
            self.assertEqual(overview(Store(), path, now=NOW)['failed_jobs'], 0)
            for when in (NOW-dt.timedelta(seconds=1), NOW+dt.timedelta(seconds=61)):
                value = overview(Store(), path, now=when)
                self.assertIsNone(value['failed_jobs'])
                self.assertEqual(value['signals']['jobs']['status'], 'stale')
            signals['jobs']['value'] = -1
            path.write_text(json.dumps({'schema_version': 1, 'signals': signals}))
            self.assertIsNone(overview(Store(), path, now=NOW)['failed_jobs'])
            signals['backup']['value'] = (NOW+dt.timedelta(seconds=1)).isoformat()
            signals['model']['value'] = ''
            path.write_text(json.dumps({'schema_version': 1, 'signals': signals}))
            value = overview(Store(), path, now=NOW)
            self.assertEqual(value['backup_display'], 'Unknown')
            self.assertEqual(value['model_display'], 'Unknown')

    def test_homepage_three_tabs_and_private_token_reference(self):
        docs = configuration('https://operator.example.test', 'http://platform:8002/v1/overview')
        self.assertEqual(len({v['tab'] for v in docs['settings.yaml']['layout'].values()}), 3)
        self.assertEqual(len(docs['services.yaml'][0]['Platform']), 3)
        self.assertTrue(docs['settings.yaml']['layout']['Consoles']['initiallyCollapsed'])
        self.assertIn('HOMEPAGE_FILE_OVERVIEW_TOKEN', json.dumps(docs))
        self.assertIn('proxmox.yaml', docs)
        with self.assertRaises(ValueError):
            configuration('https://user:pass@example.com', 'http://platform')

    def test_malformed_snapshots_and_unknown_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'overview.json'
            for value in ([], None, {'schema_version': 1, 'signals': {'jobs': []}}, 'x'*65537):
                path.write_text(json.dumps(value))
                self.assertIsNone(overview(Store(), path, now=NOW)['failed_jobs'])
            path.write_text(json.dumps({'schema_version': 1, 'signals': {'jobs': {
                'status': 'unknown', 'value': None, 'observed_at': NOW.isoformat(),
                'max_age_seconds': 120, 'source': 'job observation unavailable'}}}))
            self.assertEqual(overview(Store(), path, now=NOW)['signals']['jobs']['source'], 'job observation unavailable')

    def test_summary_credential_cannot_read_records_or_mutate(self):
        from local_observe.platform.api import create_app
        async def check():
            token = 'summary-test-token-'*3
            app = create_app(Store(), [{'token': token, 'identity': 'portal', 'role': 'summary'}], None)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
                self.assertEqual((await client.get('/v1/overview')).status_code, 401)
                client.headers['Authorization'] = 'Bearer '+token
                self.assertEqual((await client.get('/v1/overview')).status_code, 200)
                self.assertEqual((await client.get('/v1/me')).json()['role'], 'summary')
                for path in ('/v1/status', '/v1/records/incidents', '/v1/inventory', '/v1/evidence'):
                    self.assertEqual((await client.get(path)).status_code, 403)
                for path in ('/v1/events', '/v1/actions/decision', '/v1/notifications/retry'):
                    self.assertEqual((await client.post(path, json={})).status_code, 403)
        asyncio.run(check())

    def test_job_summary_requires_complete_fresh_set(self):
        from local_observe.platform.overview_worker import jobs_signal
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'cursor.json'
            document = {'pending': None, 'last_end': NOW.isoformat(), 'jobs': [
                {'job': 'a', 'status': 'healthy'}, {'job': 'b', 'status': 'failed'}]}
            path.write_text(json.dumps(document))
            result = jobs_signal(path, ['a', 'b'], now=NOW)
            self.assertEqual((result['value'], result['status']), (1, 'degraded'))
            self.assertIsNone(jobs_signal(path, ['a', 'b', 'c'], now=NOW)['value'])
            self.assertIsNone(jobs_signal(path, ['a', 'b'], now=NOW+dt.timedelta(seconds=121))['value'])
            for state in ('unknown', 'running', 'unrecognised'):
                document['jobs'][0]['status'] = state
                path.write_text(json.dumps(document))
                self.assertIsNone(jobs_signal(path, ['a', 'b'], now=NOW)['value'])
            document['pending'] = {'batch': []}
            path.write_text(json.dumps(document))
            self.assertIsNone(jobs_signal(path, ['a', 'b'], now=NOW)['value'])

    def test_worker_publishes_json_config_paths_atomically(self):
        from local_observe.platform.overview_worker import publish
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'state.json'
            config = {'output': str(output), 'jobs_cursor': str(Path(directory)/'missing.json'), 'expected_jobs': ['test']}
            publish(config, now=NOW)
            self.assertIsNone(overview(Store(), output, now=NOW)['failed_jobs'])
            self.assertFalse(output.with_suffix('.tmp').exists())


MEASURED = {'schema_version': 1, 'context_tokens': 8192, 'tools': False, 'json_mode': True,
            'streaming': True, 'vision': False, 'parallel': 2, 'quant': 'Q4_K_M',
            'measured_tok_per_s': 12.5}


class ModelObservationTests(unittest.TestCase):
    """AI integration task 3: the producer behind a tile the Homepage has rendered since before anything wrote it.

    Four states and one hard property — with no `ai` block the worker opens no socket, so the
    absent-by-default world stays free. `unknown` is never healthy, and a stale observation nulls
    itself in `overview.py:54-55`, which these tests keep rather than change.
    """

    def signal(self, ai, *, ready=True, now=NOW):
        from local_observe.platform.overview_worker import model_signal
        with mock.patch('local_observe.platform.overview_worker.health_ready',
                        return_value=ready) as probe:
            result = model_signal(ai, now=now)
        return result, probe

    def test_not_deployed_is_disabled_and_opens_no_socket(self):
        result, probe = self.signal(None)
        self.assertEqual(result['status'], 'disabled')
        self.assertIsNone(result['value'])
        self.assertEqual(result['source'], 'ai component not deployed')
        probe.assert_not_called()

    def test_an_unusable_configuration_is_unknown_never_disabled(self):
        for ai in ([], 'http://ai:8080', {'model': 'qwen'}, {'health_url': 'http://ai:8080/health'}):
            with self.subTest(ai=repr(ai)[:30]):
                result, _probe = self.signal(ai)
                self.assertEqual(result['status'], 'unknown')
                self.assertEqual(result['source'], 'ai observation configuration unavailable')

    def test_a_serve_that_did_not_confirm_is_unknown(self):
        result, _probe = self.signal({'health_url': 'http://ai:8080/health', 'model': 'qwen3-30b'},
                                     ready=False)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['value'])
        self.assertEqual(result['source'], 'model serve health endpoint did not answer')

    def test_a_missing_or_oversized_label_cannot_be_published_as_a_value(self):
        for label in ('', '   ', 'q' * 161, 'two words', 'a\nb', None):
            with self.subTest(label=repr(label)[:16]):
                result, _probe = self.signal({'health_url': 'http://ai:8080/health', 'model': label})
                self.assertEqual(result['status'], 'unknown')
                self.assertEqual(result['source'], 'ai model label unavailable')

    def test_ready_but_unmeasured_is_degraded_and_still_names_the_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / 'capability.json'
            manifest.write_text(json.dumps(dict(MEASURED, context_tokens='unknown')), encoding='utf-8')
            ai = {'health_url': 'http://ai:8080/health', 'model': 'qwen3-30b',
                  'capability': str(manifest)}
            for broken in (ai, {**ai, 'capability': str(root / 'absent.json')},
                           {**ai, 'capability': ''}):
                with self.subTest(capability=repr(broken['capability'])[-14:]):
                    result, _probe = self.signal(broken)
                    self.assertEqual(result['status'], 'degraded')
                    self.assertEqual(result['value'], 'qwen3-30b')
                    self.assertIn('unmeasured', result['source'])
            manifest.write_text(json.dumps({key: value for key, value in MEASURED.items()
                                            if key != 'vision'}), encoding='utf-8')
            self.assertEqual(self.signal({**ai})[0]['status'], 'degraded', 'a missing field is not measured')
            manifest.write_text(json.dumps(MEASURED), encoding='utf-8')
            healthy, _probe = self.signal(ai)
            self.assertEqual((healthy['status'], healthy['value']), ('healthy', 'qwen3-30b'))

    def test_the_published_document_carries_both_signals_from_one_writer(self):
        from local_observe.platform.overview_worker import publish
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'state.json'
            with mock.patch('local_observe.platform.overview_worker.health_ready', return_value=True):
                publish({'output': str(output), 'jobs_cursor': str(root / 'missing.json'),
                         'expected_jobs': ['test'],
                         'ai': {'health_url': 'http://ai:8080/health', 'model': 'qwen3-30b'}}, now=NOW)
            document = json.loads(output.read_text(encoding='utf-8'))
            self.assertEqual(sorted(document['signals']), ['jobs', 'model'])
            self.assertEqual(document['signals']['model']['max_age_seconds'], 120)
            value = overview(Store(), output, now=NOW)
            self.assertEqual(value['resident_model'], 'qwen3-30b')
            self.assertEqual(value['model_display'], 'qwen3-30b')
            self.assertEqual(value['signals']['model']['status'], 'degraded')
            stale = overview(Store(), output, now=NOW + dt.timedelta(seconds=121))
            self.assertIsNone(stale['resident_model'])
            self.assertEqual(stale['model_display'], 'Stale')

    def test_a_malformed_or_credentialed_health_url_is_refused_without_a_request(self):
        from local_observe.platform.overview_worker import health_ready
        for url in ('http://user:pw@ai:8080/health', 'http://ai/health?x=1', 'http://ai/health#f',
                    'ftp://ai/health', 'not a url', '/health', '', None, 8080):
            with self.subTest(url=repr(url)[:28]), mock.patch(
                    'local_observe.platform.overview_worker.urllib.request.build_opener') as opener:
                self.assertFalse(health_ready(url, 3))
                opener.assert_not_called()
        for timeout in (0, 21, 'three', True):
            with self.subTest(timeout=timeout):
                self.assertFalse(health_ready('http://ai:8080/health', timeout))

    def test_a_200_ok_body_is_the_only_healthy_answer(self):
        from local_observe.platform.overview_worker import health_ready

        class Response:
            status = 200

            def __init__(self, body):
                self.body = body.encode()

            def read(self, _limit):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

        class Opener:
            def __init__(self, response):
                self.response = response

            def open(self, _request, timeout=None):
                return self.response

        for body, expected in ((json.dumps({'status': 'ok'}), True),
                              (json.dumps({'status': 'loading'}), False),
                              ('', False), ('not json', False),
                              (json.dumps({'status': 'ok', 'pad': 'p' * 5000}), False)):
            with self.subTest(body=body[:18]), mock.patch('local_observe.platform.overview_worker.urllib.request.build_opener',
                                                          return_value=Opener(Response(body))):
                self.assertEqual(health_ready('http://ai:8080/health', 3), expected)

        class Refusing(Opener):
            def open(self, _request, timeout=None):
                raise OSError('loading')

        with mock.patch('local_observe.platform.overview_worker.urllib.request.build_opener',
                        return_value=Refusing(None)):
            self.assertFalse(health_ready('http://ai:8080/health', 3))


if __name__ == '__main__':
    unittest.main()

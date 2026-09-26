"""Regression: the API says which side failed, and the delivery loop cannot fail silently.

Ledger api errors. Before this, `local_observe/platform/api.py` caught `StateError, InvalidInventory,
ValueError, KeyError, TypeError` and answered every one of them with 400
`invalid_or_unauthorised_operation`, so a `KeyError` from a bug in a handler was reported to the
client as their mistake and never logged; the delivery loop did `except Exception: pass`, so a
broken transport or a corrupt store was invisible forever; and the delivery mode defaulted to
`live`. Fixture style follows `tests/test_platform_runtime.py` (real `Store` on a temp path, the
ASGI app called directly, no socket) and `tests/test_regression_live_delivery.py` (the lifespan
driven by hand).
"""
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from local_observe.http import TransportError
from local_observe.inventory.validation import utc_text
from local_observe.platform.api import app_factory, create_app, stable_code
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, Store

READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
PRODUCER = {'identity': 'test-detector', 'role': 'producer', 'token': 'p' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
CREDENTIALS = [READER, PRODUCER, PROPOSER, HUMAN, SUMMARY]


async def call(app, method: str, path: str, token: str, body: bytes = b'',
               query: bytes = b'') -> tuple[int, dict]:
    """Send one request through the ASGI app itself and return its status plus decoded body."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)
    auth = (b'authorization', ('Bearer ' + token).encode())
    await app({'type': 'http', 'method': method, 'path': path, 'headers': [auth],
               'query_string': query}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class ErrorTaxonomyTests(unittest.TestCase):
    """Client mistakes stay 4xx with a stable code; a bug in a handler is a logged 500."""

    def setUp(self):
        """Give every test a fresh operational store and a clear environment (no startup pin)."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode='off'))

    def app(self, policy=None):
        """Build the app over the shared store; `policy` stands in for the action allowlist."""
        return create_app(self.store, CREDENTIALS, {} if policy is None else policy)

    def get(self, path: str, token: str = READER['token'], app=None,
            query: bytes = b'') -> tuple[int, dict]:
        """One GET through a freshly built app over the shared store."""
        return asyncio.run(call(app or self.app(), 'GET', path, token, b'', query))

    def post(self, path: str, body, token: str = PRODUCER['token'],
             app=None) -> tuple[int, dict]:
        """One POST whose body is a document (or raw bytes, to test malformed JSON)."""
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return asyncio.run(call(app or self.app(), 'POST', path, token, raw))

    def firing_event(self) -> dict:
        """Return one valid firing event for the producer credential, stamped just now."""
        moment = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        window = {'start': utc_text(moment - dt.timedelta(seconds=1)), 'end': utc_text(moment)}
        return event(PRODUCER['identity'], None, 'availability', 'availability', 'firing', window,
                     {'sample_id': 'api-errors'}, query_type='gatus-result')

    def test_state_conflict_is_400_conflict_with_the_state_sentence(self):
        """A decision on an action that is not pending is a state collision, not a malformed body."""
        status, body = self.post('/v1/actions/decision',
                                 {'action_id': str(uuid.uuid4()), 'decision': 'approved'}, HUMAN['token'])
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'conflict', 'detail': 'Action is not pending'})

    def test_event_retry_with_changed_contents_is_400_conflict(self):
        """The same source event id carrying different bytes is a conflict the caller cannot undo."""
        first = self.firing_event()
        self.assertEqual(self.post('/v1/events', first)[0], 200)
        status, body = self.post('/v1/events', dict(first, data_class='public'))
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'conflict', 'detail': 'Event retry changed contents'})

    def test_unauthorised_actor_is_400_not_authorised(self):
        """A reader that posts an event is refused by role, and the body says that is why."""
        status, body = self.post('/v1/events', self.firing_event(), READER['token'])
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'not_authorised',
                                'detail': 'Actor is not authorised for this operation'})

    def test_malformed_json_is_400_invalid_request_without_echoing_the_body(self):
        """Bad JSON is the caller's error; the detail is the decoder's position, not their text."""
        status, body = self.post('/v1/events', b'{"caller_field": "caller-value", ')
        self.assertEqual(status, 400)
        self.assertEqual(body['error'], 'invalid_request')
        self.assertNotIn('caller-value', json.dumps(body))
        self.assertNotIn('caller_field', json.dumps(body))

    def test_non_object_json_body_is_400_not_a_handler_type_error(self):
        """A JSON array body is a shape the client chose; it must not surface as our crash."""
        status, body = self.post('/v1/actions/decision', ['anything'], HUMAN['token'])
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'invalid_request', 'detail': 'Expected a JSON object body'})

    def test_bad_query_parameters_are_400_with_a_fixed_sentence(self):
        """A missing key or a non-numeric limit is answered without naming what was sent."""
        status, body = self.get('/v1/evidence')
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'invalid_request',
                                'detail': 'source and sample_id query parameters are required'})
        status, body = self.get('/v1/records/events', query=b'limit=not-a-number')
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'invalid_request', 'detail': 'limit must be an integer'})
        self.assertEqual(self.get('/v1/records/nothing')[1],
                         {'error': 'invalid_request', 'detail': 'Invalid bounded record query'})

    def test_handler_bug_is_500_internal_error_and_logged(self):
        """A KeyError from a broken action allowlist is our fault: class name out, traceback in."""
        missing_configuration_key = 'action-definition-table'

        def broken_policy(request):
            raise KeyError(missing_configuration_key)

        request = {'retry_key': 'once', 'incident_id': str(uuid.uuid4()), 'action': 'inspect',
                   'version': '1', 'targets': [], 'parameters': {}, 'evidence': [],
                   'expires_at': utc_text(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))}
        with self.assertLogs('local_observe.platform.api', level='ERROR') as captured:
            status, body = self.post('/v1/actions', request, PROPOSER['token'], app=self.app(broken_policy))
        self.assertEqual(status, 500)
        self.assertEqual(body, {'error': 'internal_error', 'detail': 'KeyError'})
        self.assertNotIn(missing_configuration_key, json.dumps(body))
        self.assertEqual([record.levelname for record in captured.records], ['ERROR'])
        failure = captured.records[0]
        self.assertEqual(failure.getMessage(), 'Platform request failed')
        self.assertEqual((failure.error_class, failure.method, failure.path),
                         ('KeyError', 'POST', '/v1/actions'))
        # The traceback is DEBUG-only (see the logging contract), so no exception text leaves.
        self.assertIsNone(failure.exc_info)

    def test_unclassified_state_sentence_defaults_to_invalid_request(self):
        """A refusal nobody has classified yet is still a 400 on the client, never a silent 500."""
        self.assertEqual(stable_code('Unapproved evidence parameter; no SQL or credentials'),
                         'invalid_request')
        status, body = self.post('/v1/events', {'not': 'a canonical event'})
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'invalid_request',
                                'detail': 'Invalid canonical event fields/version'})

    def test_a_refused_transport_is_400_not_a_crash(self):
        """A configured channel that refuses is reported as the platform sentence it is."""
        with patch('local_observe.platform.state.Store.status',
                   side_effect=TransportError('Endpoint unavailable or invalid JSON response')):
            status, body = self.get('/v1/status')
        self.assertEqual(status, 400)
        self.assertEqual(body, {'error': 'invalid_request',
                               'detail': 'Endpoint unavailable or invalid JSON response'})

    def test_broken_database_is_500_and_never_blames_the_caller(self):
        """A corrupt store is our fault: the driver's sentence stays in the log, not the body."""
        with patch('local_observe.platform.state.Store.status',
                   side_effect=sqlite3.DatabaseError('file is not a database')):
            with self.assertLogs('local_observe.platform.api', level='ERROR'):
                status, body = self.get('/v1/status')
        self.assertEqual(status, 500)
        self.assertEqual(body, {'error': 'internal_error', 'detail': 'DatabaseError'})
        self.assertNotIn('file is not a database', json.dumps(body))

    def test_authentication_authority_method_and_size_are_unchanged(self):
        """api errors leaves 401/403/404/405/413 and their code strings exactly as they were."""
        app = self.app()
        self.assertEqual(asyncio.run(call(app, 'GET', '/v1/status', 'wrong'))[1],
                         {'error': 'authentication_required'})
        self.assertEqual(asyncio.run(call(app, 'GET', '/v1/status', SUMMARY['token']))[1],
                         {'error': 'summary_only'})
        self.assertEqual(self.post('/v1/actions/decision',
                                   {'action_id': 'x', 'decision': 'approved', 'role': 'human'},
                                   HUMAN['token'], app=app)[1], {'error': 'not_found'})
        self.assertEqual(asyncio.run(call(app, 'GET', '/v1/nothing-here', READER['token']))[1],
                         {'error': 'not_found'})
        self.assertEqual(asyncio.run(call(app, 'DELETE', '/v1/status', READER['token']))[1],
                         {'error': 'method_not_allowed'})
        status, body = self.post('/v1/events', b'[' + b' ' * 70000 + b']', app=app)
        self.assertEqual(status, 413)
        self.assertEqual(body, {'error': 'body_too_large'})


class DeliveryLoopTests(unittest.TestCase):
    """A raising client must cost a log line and a counter, never the loop."""

    def setUp(self):
        """Fresh live-mode store plus a firing event, so the loop has something to attempt."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode='live'))
        moment = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        window = {'start': utc_text(moment - dt.timedelta(seconds=1)), 'end': utc_text(moment)}
        self.store.intake(event(PRODUCER['identity'], None, 'availability', 'availability', 'firing', window,
                                {'sample_id': 'loop'}, query_type='gatus-result'),
                          Actor(PRODUCER['identity'], PRODUCER['role']), now=moment)

    def test_loop_survives_a_client_that_raises_and_reports_it_on_runtime(self):
        """`delivery_loop_failures` rises, the unacked row stays un-sent, shutdown still completes."""
        class Broken:
            """A transport that fails in a way `deliver_one` deliberately does not catch."""

            def request(self, method, *, payload, headers):
                raise RuntimeError('unexpected programming error inside the transport')

        app = create_app(self.store, CREDENTIALS, {}, notification_client=Broken())

        async def drive():
            messages, started = asyncio.Queue(), asyncio.Event()

            async def send(message):
                if message['type'] == 'lifespan.startup.complete':
                    started.set()
            task = asyncio.create_task(app({'type': 'lifespan'}, messages.get, send))
            await messages.put({'type': 'lifespan.startup'})
            await asyncio.wait_for(started.wait(), timeout=10)
            try:
                observed, deadline = None, time.monotonic() + 20
                while time.monotonic() < deadline:
                    status, runtime = await call(app, 'GET', '/v1/runtime', READER['token'])
                    if runtime.get('delivery_loop_failures', 0) >= 1:
                        observed = (status, runtime)
                        break
                    await asyncio.sleep(0.1)
            finally:
                await messages.put({'type': 'lifespan.shutdown'})
                await asyncio.wait_for(task, timeout=10)
            return observed

        result = asyncio.run(drive())
        self.assertIsNotNone(result, 'the delivery loop died, or swallowed the failure')
        status, runtime = result
        self.assertEqual(status, 200)
        self.assertGreaterEqual(runtime['delivery_loop_failures'], 1)
        self.assertIsNotNone(runtime['delivery_loop_last_failure_at'])
        self.assertEqual(dt.datetime.fromisoformat(runtime['delivery_loop_last_failure_at']).utcoffset(),
                         dt.timedelta(0))
        self.assertEqual(runtime['notification_mode'], 'live')
        # Nothing was ever acknowledged: the row stays un-sent for the lease to hand back.
        self.assertNotIn('sent', self.store.status()['notifications'])

    def test_quiet_loop_reports_zero_failures(self):
        """The counter reads zero rather than absent while nothing has failed."""
        app = create_app(Store(self.root / 'quiet.db', NotificationPolicy(delivery_mode='off')),
                         CREDENTIALS, {})
        status, runtime = asyncio.run(call(app, 'GET', '/v1/runtime', READER['token']))
        self.assertEqual(status, 200)
        self.assertEqual(runtime['delivery_loop_failures'], 0)
        self.assertIsNone(runtime['delivery_loop_last_failure_at'])


class DefaultModeTests(unittest.TestCase):
    """An unset mode must not be the one that reaches a human channel."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.policy = self.root / 'actions.json'
        self.policy.write_text('{}')
        # scripts docs leftovers: the role list reaches the platform only as the file LO_PLATFORM_CREDENTIALS names,
        # so the fixture writes one instead of exporting the JSON the product no longer reads.
        self.credentials = self.root / 'platform-credentials.json'
        self.credentials.write_text(json.dumps(CREDENTIALS), encoding='utf-8')
        self.environment = {'LO_ACTION_POLICY': str(self.policy),
                            'LO_PLATFORM_CREDENTIALS': str(self.credentials),
                            'LO_STATE_PATH': str(self.root / 'state.db'), 'LO_INDEX_PATH': 'unused',
                            'LO_TELEGRAM_CONFIG': str(self.root / 'absent-secret.json'),
                            'LO_NOTIFY_URL': 'https://invalid.example',
                            'LO_NOTIFY_TOKEN': 'never-export-this'}

    def test_unset_mode_is_recording_and_never_reads_channel_credentials(self):
        """No `LO_NOTIFICATION_MODE`, no policy file: recording, with the channel paths untouched."""
        built = []

        def opened(path, notification_policy, *, verification_policy):
            store = Store(path, notification_policy, verification_policy=verification_policy)
            built.append(store)
            return store

        with patch.dict(os.environ, self.environment), \
                patch('local_observe.platform.api.action_policy', return_value={}), \
                patch('local_observe.platform.api.Store', side_effect=opened):
            app = app_factory()
            status, runtime = asyncio.run(call(app, 'GET', '/v1/runtime', READER['token']))
        self.assertEqual(status, 200)
        self.assertEqual(runtime['notification_mode'], 'recording')
        self.assertTrue(runtime['sender_configured'])
        self.assertEqual(len(built), 1)
        self.assertEqual(built[0].notification_policy.delivery_mode, 'recording')
        self.assertEqual(built[0].notification_safety_status()['delivery_mode'], 'recording')
        self.assertFalse((self.root / 'absent-secret.json').exists())

    def test_explicit_live_declaration_still_wins(self):
        """Recording is only the default; a declared mode is honoured exactly."""
        with patch.dict(os.environ, dict(self.environment, LO_NOTIFICATION_MODE='off')):
            status, runtime = asyncio.run(call(app_factory(), 'GET', '/v1/runtime', READER['token']))
        self.assertEqual(status, 200)
        self.assertEqual(runtime['notification_mode'], 'off')
        self.assertFalse(runtime['sender_configured'])

    def test_a_blank_mode_is_refused_by_name_and_boots_nothing(self):
        """`LO_NOTIFICATION_MODE=` is not "unset": the API refuses it as the CLI does (ledger notification and state leftovers).

        Before this, an empty value went straight into `NotificationPolicy`, which raised a sentence
        about the mode but never said which variable carried it — and the CLI, reading the same file,
        quietly answered `recording`. One input, two entry points, two answers is the defect.
        """
        for value in ('', '   '):
            with self.subTest(value=repr(value)), \
                    patch.dict(os.environ, dict(self.environment, LO_NOTIFICATION_MODE=value)):
                with self.assertRaisesRegex(ValueError, 'LO_NOTIFICATION_MODE') as caught:
                    app_factory()
            self.assertNotIn('never-export-this', str(caught.exception), 'the refusal named a credential value')
        self.assertFalse((self.root / 'state.db').exists(), 'a refused boot must not open operational state')

    def test_the_retired_environment_credentials_are_refused(self):
        """The env-JSON role list is a refusal at startup, not a fallback the file competes with."""
        rows = json.dumps(CREDENTIALS)
        for offered in ({'LO_PLATFORM_CREDENTIALS_JSON': rows},
                        {'LO_PLATFORM_CREDENTIALS_JSON': rows,
                         'LO_PLATFORM_CREDENTIALS': str(self.credentials)}):
            with self.subTest(keys=sorted(offered)), patch.dict(os.environ, dict(self.environment, **offered)):
                with self.assertRaisesRegex(ValueError, 'LO_PLATFORM_CREDENTIALS_JSON') as caught:
                    app_factory()
            self.assertNotIn('r' * 32, str(caught.exception), 'the refusal named a credential value')


if __name__ == '__main__':
    unittest.main()

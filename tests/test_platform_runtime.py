import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from local_observe.inventory.validation import utc_text
from local_observe.platform.api import app_factory, create_app
from local_observe.platform.detections import event
from local_observe.platform.source_pin import code_digest
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.presentation import records
from local_observe.platform.runtime import observe_startup
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
CREDENTIALS = [{'identity': 'reader', 'role': 'reader', 'token': 'r' * 32},
               {'identity': 'summary', 'role': 'summary', 'token': 's' * 32},
               {'identity': 'producer', 'role': 'producer', 'token': 'p' * 32}]


async def get(app, path, token='r' * 32):
    output = []
    async def receive():
        return {'type': 'http.request', 'body': b''}
    async def send(message):
        output.append(message)
    await app({'type': 'http', 'method': 'GET', 'path': path,
               'headers': [(b'authorization', ('Bearer ' + token).encode())]}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def store(self, mode):
        return Store(self.root / (mode + '.db'), NotificationPolicy(delivery_mode=mode))

    def intake(self, store):
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        store.intake(event('real-source', None, 'availability', 'availability', 'firing',
                           window, {'sample_id': 'runtime'}, query_type='gatus-result'),
                     Actor('real-source', 'producer'), now=now)
        return now

    def test_startup_pin_and_same_process_observation(self):
        pin = code_digest(ROOT)
        with patch.dict(os.environ, {'LO_PLATFORM_CODE_ROOT': str(ROOT), 'LO_PLATFORM_CODE_SHA256': pin,
                                     'UNRELATED_SECRET': 'never-export-this'}):
            app = create_app(self.store('off'), CREDENTIALS, {})
            status, info = asyncio.run(get(app, '/v1/runtime'))
        self.assertEqual(status, 200)
        self.assertEqual(info['pid'], os.getpid())
        self.assertEqual(info['startup_source_sha256'], pin)
        self.assertTrue(info['source_pin_verified'])
        self.assertEqual(info['notification_mode'], 'off')
        self.assertFalse(info['sender_configured'])
        self.assertEqual(info['loaded_modules']['local_observe.platform.api'], str((ROOT / 'local_observe/platform/api.py').resolve()))
        self.assertNotIn('never-export-this', json.dumps(info))
        self.assertEqual(asyncio.run(get(app, '/v1/runtime', 'bad'))[0], 401)
        self.assertEqual(asyncio.run(get(app, '/v1/runtime', 's' * 32))[0], 403)
        self.assertNotEqual(asyncio.run(get(app, '/v1/runtime', 'p' * 32))[0], 200)
        self.assertEqual(asyncio.run(get(app, '/v1/runtime'))[1], info)

    def test_pin_refusals_before_store_open(self):
        cases = [{'LO_PLATFORM_CODE_ROOT': str(ROOT)}, {'LO_PLATFORM_CODE_SHA256': '0' * 64},
                 {'LO_PLATFORM_CODE_ROOT': str(ROOT), 'LO_PLATFORM_CODE_SHA256': '0' * 64},
                 {'LO_PLATFORM_CODE_ROOT': str(self.root), 'LO_PLATFORM_CODE_SHA256': code_digest(ROOT)}]
        for env in cases:
            with self.subTest(env=env), patch.dict(os.environ, env), patch('local_observe.platform.api.Store') as store:
                with self.assertRaises(ValueError):
                    app_factory()
                store.assert_not_called()
        foreign = types.ModuleType('local_observe.foreign')
        foreign.__file__ = str(self.root / 'foreign.py')
        with patch.dict('sys.modules', {'local_observe.foreign': foreign}):
            with self.assertRaisesRegex(ValueError, 'Mixed platform'):
                observe_startup('off', False)

    def test_unpinned_is_explicit(self):
        self.assertFalse(observe_startup('off', False)['source_pin_verified'])

    def test_off_lifespan_never_claims_even_with_supplied_client(self):
        store = self.store('off')
        self.intake(store)
        app = create_app(store, CREDENTIALS, {}, notification_client=object())
        async def run():
            messages = asyncio.Queue()
            started = asyncio.Event()
            async def send(message):
                if message['type'] == 'lifespan.startup.complete':
                    started.set()
            task = asyncio.create_task(app({'type': 'lifespan'}, messages.get, send))
            await messages.put({'type': 'lifespan.startup'})
            await asyncio.wait_for(started.wait(), timeout=3)
            await asyncio.sleep(0.05)
            await messages.put({'type': 'lifespan.shutdown'})
            await asyncio.wait_for(task, timeout=3)
        with patch('local_observe.platform.api.deliver_one') as deliver:
            asyncio.run(run())
            deliver.assert_not_called()
        self.assertEqual(store.status()['notifications'], {'pending': 1})

    def test_recording_routes_real_sources_locally_and_does_not_replay(self):
        store = self.store('recording')
        now = self.intake(store)
        class Forbidden:
            def request(self, *args, **kwargs):
                raise AssertionError('Human channel must not be called')
        result = deliver_one(store, Forbidden(), now=now)
        self.assertEqual(result['destination'], 'recording-sink')
        rows = records(store, 'outbox', store.records('outbox'))
        self.assertIn('recorded locally; no message sent', rows[0]['display']['delivery_name'])
        self.assertEqual(rows[0]['delivery_safety']['destination'], 'recording-sink')
        self.assertEqual(deliver_one(Store(store.path), Forbidden(), now=now)['status'], 'idle')
        app = create_app(store, CREDENTIALS, {})
        info = asyncio.run(get(app, '/v1/runtime'))[1]
        self.assertEqual(info['notification_mode'], 'recording')
        self.assertTrue(info['sender_configured'])

    def test_off_direct_delivery_refuses_transport(self):
        store = self.store('off')
        now = self.intake(store)
        self.assertEqual(deliver_one(store, object(), now=now)['reason'], 'notifications-disabled')

    def test_live_activation_refuses_paused_backlog_across_restart(self):
        for mode in ('off', 'recording'):
            store = self.store(mode)
            store.start_notification_mode()
            self.intake(store)
            # The restart is the live startup the gate is about, so it says so: the policy default has
            # been `recording` since ledger test tooling and a bare Store here would reopen in that mode.
            restarted = Store(store.path, NotificationPolicy(delivery_mode='live'))
            with self.assertRaisesRegex(StateError, 'paused notification backlog'):
                restarted.start_notification_mode()
            # Explicit human reset suppresses backlog, never replays it.
            store.reset_notification_guard(Actor('operator', 'human'))
            restarted.start_notification_mode()
            self.assertEqual(deliver_one(restarted, object())['status'], 'idle')

    def test_factory_off_and_recording_never_read_channel_credentials(self):
        action = self.root / 'actions.json'
        action.write_text('{}')
        # scripts docs leftovers: role credentials are a mounted file, so the fixture mounts one rather than exporting
        # the JSON value the platform stopped reading.
        credentials = self.root / 'platform-credentials.json'
        credentials.write_text(json.dumps(CREDENTIALS), encoding='utf-8')
        for mode in ('off', 'recording'):
            env = {'LO_NOTIFICATION_MODE': mode, 'LO_ACTION_POLICY': str(action),
                   'LO_PLATFORM_CREDENTIALS': str(credentials),
                   'LO_STATE_PATH': str(self.root / (mode + '.db')), 'LO_INDEX_PATH': 'unused',
                   'LO_TELEGRAM_CONFIG': str(self.root / 'absent-secret.json'),
                   'LO_NOTIFY_URL': 'https://invalid.example', 'LO_NOTIFY_TOKEN': 'never-export-this'}
            with patch.dict(os.environ, env), patch('local_observe.platform.api.action_policy', return_value={}):
                app = app_factory()
                self.assertEqual(asyncio.run(get(app, '/v1/runtime'))[1]['notification_mode'], mode)

    def test_invalid_or_conflicting_modes_fail_closed(self):
        for mode in ('', 'OFF', 'record', None):
            with self.assertRaises(StateError):
                NotificationPolicy(delivery_mode=mode)
        policy = self.root / 'policy.json'
        policy.write_text('{"delivery_mode":"live"}')
        with patch.dict(os.environ, {'LO_NOTIFICATION_MODE': 'off', 'LO_NOTIFICATION_POLICY': str(policy)}):
            with self.assertRaisesRegex(ValueError, 'Conflicting notification'):
                app_factory()

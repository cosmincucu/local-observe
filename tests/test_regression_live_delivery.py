"""Regression: `delivery_mode='live'` must actually send, through the app's own delivery loop.

Ledger regression tests, from `docs/remediation/reports/REPORT_TESTS.md` §4 ("Delivery-mode transitions — Not
covered"). No pre-existing test brought the `create_app` lifespan up with a live sender, so a
regression that never started the loop — or that let its first exception kill it, since
`local_observe/platform/api.py:35-47` swallows every error the loop raises — was invisible; and
`GET /v1/notifications/safety` had no HTTP test at all. `Store.recover_executions()` was only ever
called directly, never through the lifespan that calls it.

Fixture style follows `tests/test_platform_runtime.py`: real `Store` on a temp path, an in-process
receiver instead of a socket, and the lifespan driven by hand.
"""
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from local_observe.http import TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform.api import create_app
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')
HUMAN = Actor('operator', 'human')
RUNNER = Actor('runner-1', 'executor')
CREDENTIALS = [{'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}]


async def get(app, path: str, token: str = 'r' * 32) -> tuple[int, dict]:
    """Call one GET through the ASGI app itself; no socket, no test HTTP client."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': b''}

    async def send(message):
        output.append(message)
    auth = (b'authorization', ('Bearer ' + token).encode())
    await app({'type': 'http', 'method': 'GET', 'path': path, 'headers': [auth]}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


async def wait_for(predicate, timeout: float, interval: float = 0.05) -> bool:
    """Poll `predicate` for at most `timeout` seconds; the loop under test ticks once per second."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(interval)
    return False


class FakeReceiver:
    """In-process stand-in for the notification channel; records the headers it was sent."""

    def __init__(self, failures: int = 0):
        self.payloads = []
        self.headers = []
        self.failures = failures
        self.errors = 0

    def request(self, method, *, payload, headers):
        """Fail the first `failures` sends with a transport error, then accept the delivery."""
        if self.failures:
            self.failures -= 1
            self.errors += 1
            raise TransportError('receiver unavailable')
        self.payloads.append(payload)
        self.headers.append(dict(headers))
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}

    @property
    def sends(self) -> int:
        return len(self.payloads)


class LiveDeliveryTests(unittest.TestCase):
    """The live path: startup, one send, retries across transport failures, crash reconciliation."""

    def setUp(self):
        """Build a declared inventory and an action policy, and keep the startup pin unset."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})

    def store(self, name: str) -> Store:
        """Return a fresh operational store in live delivery mode (the mode nothing tested)."""
        return Store(self.root / (name + '.db'), NotificationPolicy(delivery_mode='live'))

    def fire(self, store: Store, *, now: dt.datetime | None = None) -> str:
        """Intake one firing event with a fresh wall clock and return its outbox delivery id."""
        moment = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        window = {'start': utc_text(moment - dt.timedelta(seconds=1)), 'end': utc_text(moment)}
        store.intake(event(PRODUCER.identity, self.host, 'availability', 'availability', 'firing', window,
                           {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=moment)
        return store.records('outbox')[0]['id']

    def executing(self, store: Store) -> str:
        """Take an action as far as a runner claim, leaving an `executing` execution behind."""
        delivery_id = self.fire(store)
        incident = store.records('incidents')[0]['id']
        request = {'retry_key': 'once', 'incident_id': incident, 'action': 'inspect', 'version': '1',
                   'targets': [self.host], 'parameters': {}, 'evidence': [store.records('events')[0]['id']],
                   'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        action = store.propose_action(request, Actor('agent-1', 'proposer'), self.policy, now=NOW)
        store.decide(action['action_id'], 'approved', HUMAN, now=NOW)
        store.claim_action(action['action_id'], RUNNER, self.policy, now=NOW)
        return delivery_id

    async def drive(self, app, work):
        """Run the ASGI lifespan, hand the started app to `work`, then shut it down and report."""
        messages, started = asyncio.Queue(), asyncio.Event()

        async def send(message):
            if message['type'] == 'lifespan.startup.complete':
                started.set()
        task = asyncio.create_task(app({'type': 'lifespan'}, messages.get, send))
        await messages.put({'type': 'lifespan.startup'})
        await asyncio.wait_for(started.wait(), timeout=10)
        try:
            outcome = await work()
        finally:
            await messages.put({'type': 'lifespan.shutdown'})
            await asyncio.wait_for(task, timeout=10)
        return outcome

    def test_live_loop_sends_once_keyed_by_the_delivery_id(self):
        """Startup must put exactly one POST on the wire, with `Idempotency-Key` equal to the row id."""
        store = self.store('single')
        delivery_id = self.fire(store)
        receiver = FakeReceiver()
        app = create_app(store, CREDENTIALS, self.policy, notification_client=receiver)

        async def work():
            self.assertTrue(await wait_for(lambda: receiver.sends == 1, timeout=15), 'the live loop never sent')
            self.assertFalse(await wait_for(lambda: receiver.sends > 1, timeout=3), 'the delivery was sent twice')
            safety = await get(app, '/v1/notifications/safety')
            return store.status(), safety

        status, safety = asyncio.run(self.drive(app, work))
        self.assertEqual(status['notifications'], {'sent': 1})
        self.assertEqual(receiver.headers, [{'Idempotency-Key': delivery_id}])
        self.assertEqual(receiver.payloads[0]['delivery_id'], delivery_id)
        self.assertEqual(store.records('notification_attempts')[0]['result'], 'accepted')
        self.assertEqual(safety[0], 200)
        self.assertEqual(safety[1]['delivery_mode'], 'live')

    def test_live_loop_survives_two_transport_failures_then_delivers(self):
        """A receiver that is down twice must not kill the task: the outbox still ends `sent`."""
        store = self.store('flaky')
        delivery_id = self.fire(store)
        receiver = FakeReceiver(failures=2)
        app = create_app(store, CREDENTIALS, self.policy, notification_client=receiver)

        async def work():
            # Two failed leases back off (2 s then 4 s) and the loop only ticks once a second, so
            # this is a bounded wait rather than a fixed sleep.
            # Receiver acceptance precedes completion persistence; wait for the durable outcome too.
            self.assertTrue(await wait_for(
                lambda: receiver.sends == 1 and store.status()['notifications'] == {'sent': 1},
                timeout=60), 'the retry never reached durable sent state')
            return store.status()

        status = asyncio.run(self.drive(app, work))
        self.assertEqual(status['notifications'], {'sent': 1})
        self.assertEqual(receiver.errors, 2)
        self.assertEqual(receiver.headers, [{'Idempotency-Key': delivery_id}])
        attempts = store.records('notification_attempts')
        self.assertEqual(sorted(row['result'] for row in attempts), ['accepted', 'failed', 'failed'])
        self.assertTrue(all(row['finished_at'] for row in attempts), 'every attempt is closed')
        self.assertEqual(store.records('outbox')[0]['attempts'], 3)

    def test_startup_moves_an_interrupted_execution_to_unknown(self):
        """An execution left `executing` by a dead runner must be `unknown` after the lifespan starts."""
        store = self.store('recovery')
        self.executing(store)
        self.assertEqual(store.records('executions')[0]['status'], 'executing')
        self.assertEqual(store.status()['actions'], {'executing': 1})
        app = create_app(store, CREDENTIALS, self.policy, notification_client=FakeReceiver())

        asyncio.run(self.drive(app, work=lambda: asyncio.sleep(0)))

        self.assertEqual(store.records('executions')[0]['status'], 'unknown')
        self.assertEqual(store.status()['actions'], {'unknown': 1})
        self.assertIn('execution.unknown', [row['operation'] for row in store.records('audit')])


if __name__ == '__main__':
    unittest.main()

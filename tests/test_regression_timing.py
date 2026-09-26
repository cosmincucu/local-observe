"""Regression: delivery timing — exponential retry backoff, and a send budget that actually ages.

Ledger regression tests, from `docs/remediation/reports/REPORT_TESTS.md` §4. Two clocks in
`local_observe/platform/state.py` and `local_observe/platform/notification_safety.py` had no test:

* the retry backoff `available_at = now + min(300, 2 ** attempts)` (`state.py:204-206`) — the
  existing failure loops stepped the clock by whole minutes, which hides the backoff entirely, so a
  regression that removed it (a same-instant retry storm) passed CI;
* the sliding budget window `window_seconds` (`notification_safety.py:97-100`) — validated at
  construction but never aged: no pre-existing test ran reservations across a window boundary, and
  none asked what a human reset does to the count. regression tests could only document the answer it found; control
  state
  moved the count into `notification_reservations`, stored the reset instant beside the breaker and
  changed that answer, which is what `test_reset_moves_the_budget_window_to_the_reset_instant` now
  asserts (ledger notification budget asked which of the two behaviours was the design).

Every policy below names `delivery_mode='live'`: these tests count sends to a human channel, and the
platform default has been `recording` since ledger test tooling, which routes them to the local sink instead.
"""
import datetime as dt
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.state import Actor, Store

NOW = timestamp('2026-09-06T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')
LEASE_SECONDS = 30
# Backoff after failures with attempts 1..10; the 300 s clamp is reached at attempts 9 (2 ** 9 = 512).
EXPECTED_BACKOFF = [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]


class Receiver:
    """In-process notification channel that accepts every delivery it is given."""

    def __init__(self):
        self.calls = []

    def request(self, method, *, payload, headers):
        """Record the send and acknowledge it, so the outbox advances on each attempt."""
        self.calls.append(payload['delivery_id'])
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


class TimingTests(unittest.TestCase):
    """Backoff between retries, and the lifetime of a reservation inside the budget window."""

    def setUp(self):
        """Open a scratch directory; each test brings its own store and notification policy."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def store(self, name: str, policy: NotificationPolicy) -> Store:
        """Return a fresh operational store under `name` with the given notification policy."""
        return Store(self.root / (name + '.db'), policy)

    def fire(self, store: Store, source: str, *, now: dt.datetime = NOW) -> str:
        """Intake one firing event for `source` at `now` and return the delivery id it queued."""
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        store.intake(event(source, None, 'availability', 'availability', 'firing', window,
                           {'sample_id': 'fixture'}, query_type='gatus-result'), Actor(source, 'producer'), now=now)
        return store.records('outbox')[0]['id']

    def send_each(self, store: Store, prefix: str, offsets) -> tuple[list, Receiver]:
        """Deliver one incident per offset (a distinct producer each, so each opens its own) and
        return the `deliver_one` reports in order together with the provider that saw them."""
        provider = Receiver()
        results = []
        for index, offset in enumerate(offsets):
            moment = NOW + dt.timedelta(seconds=offset)
            self.fire(store, '%s-%d' % (prefix, index), now=moment)
            results.append(deliver_one(store, provider, now=moment))
        return results, provider

    def test_failed_delivery_backs_off_exponentially_and_clamps_at_three_hundred_seconds(self):
        """Each failure moves `available_at` by 2**attempts (clamped), and no earlier claim succeeds."""
        # A long event age and a wide budget keep suppression out of the way: this test is about the
        # retry clock only, so the tenth failure is still an eligible retry.
        policy = NotificationPolicy(delivery_mode='live', max_attempts=20, max_event_age_seconds=86400)
        store = self.store('backoff', policy)
        self.fire(store, PRODUCER.identity)
        now = NOW
        item = store.claim_notification(now=now, lease_seconds=LEASE_SECONDS, max_attempts=20)
        observed = []
        for _ in EXPECTED_BACKOFF:
            outcome = store.finish_notification(item['id'], item['claim_token'], False, now=now, max_attempts=20)
            self.assertEqual(outcome, 'pending')
            available = timestamp(store.records('outbox')[0]['available_at'])
            observed.append((available - now).total_seconds())
            # Too early by one second: nothing to hand out yet.
            self.assertIsNone(store.claim_notification(now=available - dt.timedelta(seconds=1),
                                                       lease_seconds=LEASE_SECONDS, max_attempts=20))
            now = available
            item = store.claim_notification(now=now, lease_seconds=LEASE_SECONDS, max_attempts=20)
            self.assertIsNotNone(item, 'the row must be claimable exactly at its available_at')
            self.assertEqual(item['destination'], 'human')
        self.assertEqual(observed, [float(value) for value in EXPECTED_BACKOFF])
        # The last iteration also proved the final available_at claimable, so one further lease is
        # live: the counter is the number of failures plus the attempt in flight.
        self.assertEqual(store.records('outbox')[0]['attempts'], len(EXPECTED_BACKOFF) + 1)
        self.assertEqual(store.status()['notifications'], {'sending': 1})
        self.assertFalse(store.notification_safety_status()['circuit_open'], 'retries must not trip the breaker')

    def test_reservations_age_out_of_the_budget_window(self):
        """Three sends spaced past the window fit a budget of two; the same three packed do not."""
        policy = NotificationPolicy(delivery_mode='live', max_attempts=2, window_seconds=60)
        aged_store = self.store('aged', policy)
        aged, aged_sink = self.send_each(aged_store, 'detector', (0, 61, 122))
        for offset, result in zip((0, 61, 122), aged):
            self.assertEqual(result['status'], 'sent', 'send at +%d s suppressed: %s' % (offset, result.get('reason')))
        self.assertEqual(len(aged_sink.calls), 3)
        self.assertFalse(aged_store.notification_safety_status()['circuit_open'],
                         'a budget that ages must not latch the breaker')

        # Control: identical budget, identical count; only the spacing differs.
        packed_store = self.store('packed', policy)
        packed, packed_sink = self.send_each(packed_store, 'detector', (0, 10, 20))
        self.assertEqual([row['status'] for row in packed], ['sent', 'sent', 'suppressed'])
        self.assertEqual(packed[-1]['reason'], 'flood-circuit-open')
        self.assertEqual(len(packed_sink.calls), 2)
        self.assertTrue(packed_store.notification_safety_status()['circuit_open'])

    def test_reset_moves_the_budget_window_to_the_reset_instant(self):
        """A human reset restarts the send budget at the instant of the reset (ledger control state, notification budget).

        `reset_notification_guard` unlatches the flood breaker (it appends `notification.circuit_reset`)
        and discards the pending backlog. From control state it also records the reset instant under
        `circuit:<channel>` in `notification_control`, and `reserve` counts reservations taken *after*
        that instant, so the slots that tripped the breaker stop being held against the next send.

        This test asserted the opposite until control state: the pre-v2 reset wrote no budget record, the two
        earlier `notification.reserved` rows were still inside `window_seconds`, and the next send
        re-latched the breaker — a reset that only worked once the window had aged out. It was filed as
        `test_reset_inside_window_relatches_documented`, documenting rather than deciding; the decision
        is now recorded here, in `local_observe/platform/README.md` and in the control state brief. The audit
        rows for those old slots are untouched: they stay the history of what was sent.
        """
        policy = NotificationPolicy(delivery_mode='live', max_attempts=2, window_seconds=600)
        store = self.store('reset', policy)
        sent, provider = self.send_each(store, 'detector', (0, 1))
        self.assertEqual([row['status'] for row in sent], ['sent', 'sent'])

        blocked = NOW + dt.timedelta(seconds=1)
        self.fire(store, 'detector-x', now=blocked)
        self.assertEqual(deliver_one(store, provider, now=blocked)['reason'], 'flood-circuit-open')
        self.assertTrue(store.notification_safety_status()['circuit_open'])

        self.assertEqual(store.reset_notification_guard(Actor('operator', 'human'), now=NOW + dt.timedelta(seconds=2)),
                         {'status': 'reset', 'backlog_replayed': False})
        self.assertFalse(store.notification_safety_status()['circuit_open'], 'the reset does unlatch the breaker')

        # Two seconds after the reset the two t0 reservations are older than the reset, so the window
        # is empty and the next send goes out instead of re-latching the breaker.
        later = NOW + dt.timedelta(seconds=3)
        self.fire(store, 'detector-y', now=later)
        result = deliver_one(store, provider, now=later)
        self.assertEqual((result['status'], result['destination']), ('sent', 'human'))
        self.assertFalse(store.notification_safety_status()['circuit_open'])
        self.assertEqual(store.notification_safety_status()['suppressed'], 1,
                         'the row refused before the reset stays refused')
        self.assertEqual(len(provider.calls), 3, 'the reset bought the next send')

        # The budget is restarted, not removed: the two fresh slots fill it again.
        self.fire(store, 'detector-z', now=later)
        self.assertEqual(deliver_one(store, provider, now=later)['status'], 'sent')
        self.fire(store, 'detector-w', now=later)
        self.assertEqual(deliver_one(store, provider, now=later)['reason'], 'flood-circuit-open')
        self.assertTrue(store.notification_safety_status()['circuit_open'])
        self.assertEqual(len(provider.calls), 4, 'a reset must not buy an unbounded channel')


if __name__ == '__main__':
    unittest.main()

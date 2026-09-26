"""Regression: a delivery lease that is never acknowledged must end the row, not loop forever.

Ledger regression tests, from `docs/remediation/reports/REPORT_TESTS.md` §4 ("Outbox claim/ack under crash —
Not covered"). The reconciliation branch in `local_observe/platform/state.py:165-196` runs when a
claim is still `sending` at its `lease_until`: it writes `notification_attempts.result='unknown'`,
and converts the outbox row to `dead` once `attempts` reaches the bound. Every pre-existing test
either acknowledged the delivery with `finish_notification` or expired the lease exactly once, so a
worker that claims, dies and is re-leased forever was never exercised — and
`records('notification_attempts')` was read by no test at all.

The scenario here is that death spiral: claim, crash, claim, crash … until the row is dead, with
`finish_notification` never called even once.
"""
import datetime as dt
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-06T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')
HUMAN = Actor('operator', 'human')
LEASE_SECONDS = 30
MAX_ATTEMPTS = 3
# One second past the last abandoned lease: the sweep that notices the expiry is what kills the row.
SWEEP = NOW + dt.timedelta(seconds=(LEASE_SECONDS + 1) * MAX_ATTEMPTS + 1)


class AbandonedLeaseTests(unittest.TestCase):
    """A worker that claims and dies repeatedly must exhaust its leases and stop being served."""

    def setUp(self):
        """Open a real Store on a temp path and intake one firing event that opens an incident."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        end = NOW
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        result = self.store.intake(
            event(PRODUCER.identity, None, 'availability', 'availability', 'firing', window,
                  {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=NOW)
        self.assertEqual(result['transition'], 'opened')
        self.delivery_id = self.store.records('outbox')[0]['id']
        self.assertEqual(self.store.status()['notifications'], {'pending': 1})

    def claim(self, now: dt.datetime, *, lease_seconds: int = LEASE_SECONDS, max_attempts: int = MAX_ATTEMPTS):
        """Lease the next due delivery with the bounds this file tests, at the instant `now`."""
        return self.store.claim_notification(now=now, lease_seconds=lease_seconds, max_attempts=max_attempts)

    def raw(self, table: str) -> list[dict]:
        """Read a whole table with raw sqlite, so un-redacted columns (claim tokens) are visible."""
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute(f'SELECT * FROM {table}')]

    def abandon_leases(self, max_attempts: int = MAX_ATTEMPTS) -> list[dict]:
        """Claim `max_attempts` times, never acknowledging, stepping past `lease_until` each time."""
        claims = []
        for attempt in range(max_attempts):
            moment = NOW + dt.timedelta(seconds=(LEASE_SECONDS + 1) * attempt)
            claims.append(self.claim(moment, max_attempts=max_attempts))
        self.assertTrue(all(claims), 'every abandoned lease below the bound is still handed out')
        return claims

    def test_row_dies_on_lease_expiry_not_on_acknowledgement(self):
        """The bound kills the row on lease expiry, with no acknowledgement ever sent."""
        claims = self.abandon_leases()
        # The final abandoned claim still holds the row as `sending`, and `finish_notification` is
        # never called anywhere in this file: expiry alone is what has to end this row.
        self.assertEqual(self.store.status()['notifications'], {'sending': 1})
        self.assertIsNotNone(self.raw('outbox')[0]['lease_until'])

        # One more claim after that lease expires converts the row to dead — and so has nothing
        # left to hand out, which is why it returns None.
        self.assertIsNone(self.claim(SWEEP))
        self.assertEqual(self.store.status()['notifications'], {'dead': 1})
        row = self.raw('outbox')[0]
        self.assertEqual((row['status'], row['attempts']), ('dead', MAX_ATTEMPTS))
        self.assertIsNone(row['claim_token'], 'a dead row must not keep a live lease token')
        self.assertIsNone(row['lease_until'])
        # Every abandoned claim was a distinct lease token over the same delivery id.
        self.assertEqual({claim['id'] for claim in claims}, {self.delivery_id})
        self.assertEqual(len({claim['claim_token'] for claim in claims}), MAX_ATTEMPTS)
        # Dead on expiry and never acknowledged: no attempt was ever resolved by a worker.
        results = {row['result'] for row in self.store.records('notification_attempts')}
        self.assertFalse(results & {'accepted', 'failed'})

    def test_every_abandoned_lease_leaves_a_closed_attempt_row(self):
        """Each dead lease closes its `notification_attempts` row as `unknown` with a `finished_at`."""
        self.abandon_leases()
        self.assertIsNone(self.claim(SWEEP))
        attempts = self.raw('notification_attempts')
        self.assertEqual(len(attempts), MAX_ATTEMPTS, 'one attempt row per abandoned lease')
        for row in attempts:
            self.assertEqual(row['result'], 'unknown', 'a lease that died unreconciled is unknown, never accepted')
            self.assertIsNotNone(row['finished_at'], 'a closed attempt must carry a finish time')
            self.assertEqual(row['outbox_id'], self.delivery_id)
        # The same history through the bounded reader: tokens gone, outcomes still readable.
        visible = self.store.records('notification_attempts')
        self.assertEqual(len(visible), MAX_ATTEMPTS)
        self.assertEqual({row['result'] for row in visible}, {'unknown'})
        self.assertTrue(all(row['finished_at'] for row in visible))

    def test_dead_row_is_never_leased_again_without_human_retry(self):
        """No later claim, at any clock or under any bound, hands the dead row back to a worker."""
        self.abandon_leases()
        for later in (MAX_ATTEMPTS, MAX_ATTEMPTS + 1, MAX_ATTEMPTS + 40):
            self.assertIsNone(self.claim(NOW + dt.timedelta(seconds=(LEASE_SECONDS + 1) * later)))
        self.assertIsNone(self.claim(NOW + dt.timedelta(days=1), lease_seconds=300, max_attempts=1))
        self.assertEqual(self.store.status()['notifications'], {'dead': 1})
        # Reopening the state file changes nothing: the row is dead on disk, not in memory.
        self.assertIsNone(Store(self.store.path).claim_notification(now=SWEEP))

    def test_only_human_retry_brings_the_row_back_and_resets_attempts(self):
        """Every non-human role is refused; a human retry returns the row to `pending`, attempts 0."""
        self.abandon_leases()
        self.claim(SWEEP)
        for impostor in ('proposer', 'executor', 'producer', 'reader', 'summary'):
            with self.assertRaises(StateError):
                self.store.retry_notification(self.delivery_id, Actor('someone', impostor), now=NOW)
        with self.assertRaises(StateError):
            self.store.retry_notification(self.delivery_id, Actor('', 'human'), now=NOW)

        self.assertEqual(self.store.retry_notification(self.delivery_id, HUMAN, now=NOW), {'status': 'pending'})
        row = self.raw('outbox')[0]
        self.assertEqual((row['status'], row['attempts']), ('pending', 0), 'a human retry starts a fresh budget')
        self.assertEqual(row['available_at'], utc_text(NOW))

        # The reset budget is real: the row is leasable again and the counter restarts from one.
        claim = self.claim(NOW)
        self.assertIsNotNone(claim)
        self.assertEqual(claim['id'], self.delivery_id)
        self.assertEqual(self.raw('outbox')[0]['attempts'], 1)
        self.assertEqual(self.store.status()['notifications'], {'sending': 1})
        # The reconciliation history of the earlier spiral is kept, not rewritten.
        self.assertEqual(len(self.raw('notification_attempts')), MAX_ATTEMPTS + 1)
        self.assertIn('notification.retry_requested', [row['operation'] for row in self.store.records('audit')])
        # The bounded reader never leaks the live lease token the database is currently holding.
        self.assertNotIn('claim_token', self.store.records('outbox')[0])
        self.assertNotIn(claim['claim_token'], json.dumps(self.store.records('outbox')[0]))


if __name__ == '__main__':
    unittest.main()

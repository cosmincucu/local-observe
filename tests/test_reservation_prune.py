"""state leftovers: `notification_reservations` finally gets pruned, and the prune cannot restart a budget.

Since schema v2 (control state) every reserved delivery leaves one row in `notification_reservations` and the
human-channel send budget is a count over those rows taken inside the current window. Nothing ever
deleted them, so the table grew for the life of the database and every claim scanned an ever-longer
list. `Store.prune_reservations` (ledger state leftovers) removes the rows that are provably history, and the
delivery loop calls it where it claims the outbox.

The row count is not the property worth testing — the count `notification_safety.reserve` makes is.
A prune that deleted a slot the budget was still holding would hand back a send that had already been
spent, and a rate limit that silently restarts is worse than an unbounded table: it is the flood
breaker believing its own lie. So each test below reads the number twice, once before the prune and
once after, with `WINDOW_COUNT` below quoted unchanged from `notification_safety.py`, and asserts the
prune never moved it. `notification_suppressions` is asserted to be untouched: a suppressed delivery
must never replay, whatever its age.

Two exemptions are asserted because they are the failure modes, not because they are exceptions: an
age-based prune of a test-window slot would restart a budget that has no age bound at all
(`test_a_slot_taken_inside_a_test_window_outrives_the_prune`), and the rows a human reset left behind
are pruned only once the reset — not the ageing window — is what excludes them
(`test_the_prune_never_moves_the_count_the_budget_is_made_from`). A third named test keeps the
never-replay rows and a channel this build has no policy for out of every delete
(`test_a_prune_leaves_suppressions_and_other_channels_alone`).
"""
import datetime as dt
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-08T09:00:00Z')
HUMAN = Actor('operator', 'human')
# The budget query as `notification_safety.reserve` runs it, quoted unchanged. Each test pairs it with
# the same `now` it hands the prune, so what is compared is the number delivery actually uses.
WINDOW_COUNT = ("SELECT count(*) FROM notification_reservations WHERE channel=? AND destination='human' "
                "AND julianday(at)>julianday(?)")
# The only budget query in the product that carries no time bound at all.
TEST_WINDOW_COUNT = 'SELECT count(*) FROM notification_reservations WHERE test_window=?'


class Receiver:
    """In-process notification channel that accepts every delivery it is given."""

    def __init__(self) -> None:
        """Start with an empty send log."""
        self.calls: list[str] = []

    def request(self, method, *, payload, headers):
        """Record the send and acknowledge it, so the outbox advances on each attempt."""
        self.calls.append(payload['delivery_id'])
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


class ReservationPruneTests(unittest.TestCase):
    """Which send slots may be deleted, and what no deletion may ever change."""

    def setUp(self) -> None:
        """Open a scratch directory; each test names its own database file."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @staticmethod
    def at(offset: int) -> dt.datetime:
        """Return the test instant `offset` seconds from `NOW`, so schedules read as offsets."""
        return NOW + dt.timedelta(seconds=offset)

    def store(self, name: str, policy: NotificationPolicy) -> Store:
        """Return a fresh operational store under `name` with the given notification policy."""
        return Store(self.root / (name + '.db'), policy)

    def fire(self, store: Store, source: str, status: str = 'firing', *, offset: int = 0) -> str:
        """Intake one event for `source` at `offset` and return the id of the delivery it queued."""
        now = self.at(offset)
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        before = {row['id'] for row in store.records('outbox')}
        store.intake(event(source, None, 'fixture', 'availability', status, window,
                           {'sample_id': 'fixture'}, query_type='gatus-result'), Actor(source, 'producer'), now=now)
        queued = [row['id'] for row in store.records('outbox') if row['id'] not in before]
        self.assertEqual(len(queued), 1, 'one event queues exactly one delivery')
        return queued[0]

    def send(self, store: Store, source: str, *, offset: int = 0) -> dict:
        """Queue and deliver one incident for `source` at `offset`, returning the `deliver_one` report."""
        self.fire(store, source, offset=offset)
        return deliver_one(store, Receiver(), now=self.at(offset))

    def rows(self, store: Store) -> list[tuple]:
        """Return every surviving slot as (outbox_id, channel, destination, test_window, at).

        Read with raw sqlite so no answer comes from the store being tested, the way
        `tests/test_control_state_migration.py` reads the same table across a migration.
        """
        with closing(sqlite3.connect(store.path)) as db:
            return db.execute('SELECT outbox_id,channel,destination,test_window,at '
                              'FROM notification_reservations ORDER BY id').fetchall()

    def window_count(self, store: Store, policy: NotificationPolicy, offset: int, reset_at: str = '') -> int:
        """Return what `reserve` would count at `offset`, from the stored slots alone."""
        start = self.at(offset) - dt.timedelta(seconds=policy.window_seconds)
        if reset_at:
            start = max(start, timestamp(reset_at))
        with closing(sqlite3.connect(store.path)) as db:
            return db.execute(WINDOW_COUNT, (policy.channel, utc_text(start))).fetchone()[0]

    def prune(self, store: Store, offset: int) -> int:
        """Call the prune on its own, in a transaction of its own, and return what it deleted."""
        with store.transaction() as connection:
            return store.prune_reservations(connection, self.at(offset))

    def test_a_slot_older_than_the_window_is_pruned_and_a_fresh_one_survives(self):
        """The table ages: a slot past the budget window goes, one inside it stays."""
        policy = NotificationPolicy(delivery_mode='live', max_attempts=10, window_seconds=600)
        store = self.store('ages', policy)
        self.send(store, 'detector-new', offset=-60)
        # The aged slot is written by hand rather than taken by an earlier claim, because a claim at
        # -700 would have it pruned by the claim at -60 before this test could see it — which is the
        # delivery-loop behaviour `test_the_delivery_loop_prunes_where_it_claims_the_outbox` asserts.
        with closing(sqlite3.connect(store.path)) as db:
            db.execute('INSERT INTO notification_reservations(outbox_id,channel,destination,test_window,at) '
                       "VALUES ('aged',?,'human',NULL,?)", (policy.channel, utc_text(self.at(-700))))
            db.commit()
        self.assertEqual(len(self.rows(store)), 2, 'one fresh slot and one aged one')

        self.assertEqual(self.prune(store, 0), 1, 'the aged slot is deleted')
        self.assertEqual([row[4] for row in self.rows(store)], [utc_text(self.at(-60))],
                         'the slot still inside the window is the one that survives')

    def test_the_prune_never_moves_the_count_the_budget_is_made_from(self):
        """Before and after a prune, `reserve` would count the same slots: that is the whole property."""
        policy = NotificationPolicy(delivery_mode='live', max_attempts=2, window_seconds=600)
        store = self.store('count', policy)
        self.send(store, 'detector-0', offset=0)
        self.send(store, 'detector-1', offset=1)
        self.fire(store, 'detector-2', offset=2)
        blocked = deliver_one(store, Receiver(), now=self.at(2))
        self.assertEqual(blocked['reason'], 'flood-circuit-open', 'a budget of two is full')
        self.assertTrue(store.notification_safety_status()['circuit_open'])

        # Nothing here is prunable: both slots are inside the window, which is what keeps the breaker
        # latched. The count is the number that produced the refusal, so it must not move.
        self.assertEqual(self.window_count(store, policy, 2), 2)
        self.assertEqual((self.prune(store, 2), self.window_count(store, policy, 2)), (0, 2))

        # A human reset moves the counting instant to itself, so the two slots that tripped the breaker
        # stop being held against the next send. That exclusion is what makes them history, and this is
        # the point where a prune that deleted anything the budget still counted would restart it.
        store.reset_notification_guard(HUMAN, now=self.at(3))
        reset_at = utc_text(self.at(3))
        self.assertEqual(self.window_count(store, policy, 4, reset_at), 0, 'the reset emptied the window')
        self.assertEqual([row[4] for row in self.rows(store)], [utc_text(self.at(0)), utc_text(self.at(1))],
                         'the reset itself deletes no slot')
        self.assertEqual((self.prune(store, 4), self.window_count(store, policy, 4, reset_at)), (2, 0),
                         'exactly the two slots behind the reset go, and the count says so already')

        # And the budget is restarted, not removed: two fresh slots fill it and latch it again.
        provider = Receiver()
        for offset in (4, 5):
            self.assertEqual(self.send(store, 'detector-fresh-%d' % offset, offset=offset)['status'], 'sent')
        self.fire(store, 'detector-full', offset=5)
        self.assertEqual(deliver_one(store, provider, now=self.at(5))['reason'], 'flood-circuit-open')
        self.assertEqual(len(provider.calls), 0, 'a prune must not buy an unbounded channel')

    def test_the_delivery_loop_prunes_where_it_claims_the_outbox(self):
        """No operator step to remember: the claim that scans the table is the place that trims it."""
        policy = NotificationPolicy(delivery_mode='live', max_attempts=10, window_seconds=600)
        store = self.store('claim', policy)
        self.send(store, 'detector-old', offset=-700)
        self.fire(store, 'detector-next', offset=0)
        self.assertEqual(deliver_one(store, Receiver(), now=self.at(0))['status'], 'sent')
        self.assertEqual([row[4] for row in self.rows(store)], [utc_text(self.at(0))],
                         'the claim at t0 aged the t-700 slot out on its way past')

    def test_a_slot_taken_inside_a_test_window_outrives_the_prune(self):
        """The test-window budget has no age bound, so pruning its slots would silently restart it.

        `window_seconds` is deliberately shorter than the approved test window: the one case where a
        plain "older than the configured window" rule would delete a slot that is still being counted.
        """
        window = {'id': 'r20-test', 'starts_at': utc_text(NOW),
                  'expires_at': utc_text(self.at(120)), 'max_attempts': 1}
        policy = NotificationPolicy(delivery_mode='live', max_attempts=10, window_seconds=60, test_window=window)
        store = self.store('test-window', policy)
        self.fire(store, 'stage-jobs', offset=10)
        first = deliver_one(store, Receiver(), now=self.at(10))
        self.assertEqual(first['destination'], 'human', 'an approved window is what puts a synthetic source out')
        self.assertEqual(len(self.rows(store)), 1)

        # At +119 the slot is 109 s old, well past the 60 s budget window, and it must still be there.
        self.assertEqual((self.prune(store, 119), self.window_count(store, policy, 119)), (0, 0))
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute(TEST_WINDOW_COUNT, (window['id'],)).fetchone()[0], 1)
        self.fire(store, 'stage-jobs', 'resolved', offset=119)
        refused = deliver_one(store, Receiver(), now=self.at(119))
        self.assertEqual(refused['reason'], 'test-budget-exhausted', 'the spent slot is still spent')

    def test_a_prune_leaves_suppressions_and_other_channels_alone(self):
        """Never-replay rows are never pruned, and a channel this build has no policy for is kept."""
        policy = NotificationPolicy(delivery_mode='live', max_attempts=10, window_seconds=600)
        store = self.store('kept', policy)
        self.fire(store, 'detector-refused', offset=0)
        refused = store.claim_notification(now=self.at(901), lease_seconds=30)
        self.assertEqual(refused['suppressed'], 'event-too-old')
        with closing(sqlite3.connect(store.path)) as db:
            db.execute('INSERT INTO notification_reservations(outbox_id,channel,destination,test_window,at) '
                       "VALUES ('elsewhere','other-channel','human',NULL,?)", (utc_text(self.at(-900)),))
            db.execute('INSERT INTO notification_suppressions(outbox_id,reason,at) VALUES (?,?,?)',
                       ('elsewhere-suppressed', 'kept-for-never-replay', utc_text(self.at(-900))))
            db.commit()

        # A prune far ahead of everything, run outside the delivery loop, so nothing else is in scope.
        with store.transaction() as connection:
            self.assertEqual(store.prune_reservations(connection, self.at(4000)), 0,
                             'a channel with no policy here has no knowable window, so its rows stay')
        self.assertEqual([row[1] for row in self.rows(store)], ['other-channel'])
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM notification_suppressions').fetchone()[0], 2,
                             'the refusal the delivery loop wrote, plus the one written by hand')
        with self.assertRaisesRegex(StateError, 'cannot be replayed'):
            store.retry_notification('elsewhere-suppressed', HUMAN, now=self.at(4000))


if __name__ == '__main__':
    unittest.main()

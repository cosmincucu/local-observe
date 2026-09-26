"""control state: notification control state crosses a schema migration with its meaning intact.

Until schema v2 the runtime control of notification delivery — the delivery mode, the latched flood
breaker, the send budget, the approved test windows and the list of deliveries that may never be
replayed — existed only as `SELECT … FROM audit … json_extract(detail, …)` (ledger control state). That made the
append-only audit log the source of truth for behaviour, so a migration could not move it and a changed
`detail` layout silently changed delivery. `state.MIGRATIONS[2]` moves that state into
`notification_control`, `notification_reservations` and `notification_suppressions`, back-filled from
those same audit rows, and the audit rows stay exactly as they were.

`as_v1()` creates the historical schema using only migration 1, then copies real lifecycle rows into
its actual tables and columns. Current control tables, newer columns and later indexes never enter
that fixture. The audit writes are asserted row for row against the sequence a v1 build produced,
because the premise of the migration is that control state changed none of them.

What every test compares is the old answer, computed from the audit log alone by the queries this
migration replaces (`V1_*` below, quoted unchanged), against the new answer read from the migrated file.
The one place where a migrated database deliberately behaves differently is the human reset, which control state
resolves as the brief instructs: see `test_a_reset_taken_at_v1_moves_the_budget_window_at_v2` here, and
`test_reset_moves_the_budget_window_to_the_reset_instant` in `tests/test_regression_timing.py` for a
database that never needed migrating.
"""
import datetime as dt
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from local_observe.inventory.validation import canonical, timestamp, utc_text
from local_observe.platform import cli, state
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-07T09:00:00Z')
HUMAN = Actor('operator', 'human')
# Two sends per ten minutes on one human channel: enough to latch the breaker inside a test body.
POLICY = NotificationPolicy(delivery_mode='live', max_attempts=2, window_seconds=600)
CHANNEL = POLICY.channel
# The schema a v1 file holds: `tests/test_state_migration.py` names the same set for the same reason.
V1_TABLES = {'actions', 'audit', 'conditions', 'events', 'evidence', 'executions', 'incidents',
             'notification_attempts', 'outbox', 'sqlite_sequence'}


class Receiver:
    """In-process notification channel that accepts every delivery it is given."""

    def __init__(self) -> None:
        """Start with an empty send log."""
        self.calls: list[str] = []

    def request(self, method, *, payload, headers):
        """Record the send and acknowledge it, so the outbox advances on each attempt."""
        self.calls.append(payload['delivery_id'])
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


class ControlStateMigrationTests(unittest.TestCase):
    """A schema-v1 platform's notification behavior after explicit migration to this build."""

    def setUp(self) -> None:
        """Open a scratch directory; each test names its own database file."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    # --- the v1 half of every comparison ------------------------------------------------------

    # Each of these is one of the queries `state.MIGRATIONS[2]` replaces, quoted unchanged, so what is
    # compared below is the old behaviour and not a paraphrase of it. The `state.py:176-180` and
    # `state.py:253-262` of the brief are V1_HEAD and V1_MODE; notification_safety.py:55-104 is the rest.
    V1_MODE = "SELECT detail FROM audit WHERE operation='notification.mode' ORDER BY sequence DESC LIMIT 1"
    V1_CIRCUIT = """SELECT operation FROM audit WHERE subject=? AND operation IN
        ('notification.circuit_open','notification.circuit_reset') ORDER BY sequence DESC LIMIT 1"""
    V1_SUPPRESSED = "SELECT count(*) FROM audit WHERE operation='notification.suppressed'"
    V1_SLOTS = """SELECT count(*) FROM audit WHERE operation='notification.reserved'
        AND json_extract(detail,'$.channel')=? AND json_extract(detail,'$.destination')='human'
        AND julianday(at)>julianday(?)"""
    V1_TEST_SLOTS = """SELECT count(*) FROM audit WHERE operation='notification.reserved'
        AND json_extract(detail,'$.test_window')=?"""
    V1_TEST_WINDOW = "SELECT detail FROM audit WHERE operation='notification.test_window' AND subject=? LIMIT 1"
    V1_HEAD = """SELECT o.id FROM outbox o WHERE o.status='pending' AND o.available_at<=?
        AND NOT EXISTS (SELECT 1 FROM outbox p WHERE p.incident_id=o.incident_id
            AND p.sequence<o.sequence AND p.status!='sent'
            AND NOT EXISTS (SELECT 1 FROM audit a WHERE a.subject=p.id
                AND a.operation='notification.suppressed')) ORDER BY o.sequence LIMIT 1"""

    def v1_view(self, path: Path, now: dt.datetime, *, window_seconds: int = POLICY.window_seconds) -> dict:
        """Answer, from the audit log of `path` alone, what schema v1 read for control at `now`.

        A v1 store would have released or refused a delivery on exactly these five numbers, which is
        what makes them the before-half of every assertion below.
        """
        with closing(sqlite3.connect(path)) as db:
            mode = db.execute(self.V1_MODE).fetchone()
            latched = db.execute(self.V1_CIRCUIT, (CHANNEL,)).fetchone()
            start = utc_text(now - dt.timedelta(seconds=window_seconds))
            slots = db.execute(self.V1_SLOTS, (CHANNEL, start)).fetchone()[0]
            suppressed = db.execute(self.V1_SUPPRESSED).fetchone()[0]
            head = db.execute(self.V1_HEAD, (utc_text(now),)).fetchone()
        return {'mode': json.loads(mode[0])['mode'] if mode else None,
                'circuit_open': bool(latched and latched[0] == 'notification.circuit_open'),
                'slots': slots, 'suppressed': suppressed, 'next': head[0] if head else None}

    def as_v1(self, store: Store) -> Path:
        """Copy real lifecycle rows into the tables and columns created by migration 1 only."""
        v1 = store.path.with_name(store.path.stem + '.v1' + store.path.suffix)
        with mock.patch.object(state, 'MIGRATIONS', {1: state.MIGRATIONS[1]}), \
                mock.patch.object(state, 'VERSION', 1), mock.patch.object(cli, 'VERSION', 1):
            Store(v1)
        with closing(sqlite3.connect(store.path)) as source, closing(sqlite3.connect(v1)) as db:
            self.assertEqual({row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                             V1_TABLES, 'a v1 file holds the v1 tables and nothing else')
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 1)
            schema_sql = 'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'
            schema = db.execute(schema_sql).fetchall()
            with db:
                for table in sorted(V1_TABLES - {'sqlite_sequence'}):
                    columns = ','.join('"' + row[1].replace('"', '""') + '"'
                                       for row in db.execute(f'PRAGMA table_info("{table}")'))
                    rows = source.execute(f'SELECT {columns} FROM "{table}" ORDER BY rowid').fetchall()
                    placeholders = ','.join('?' for _ in db.execute(f'PRAGMA table_info("{table}")'))
                    db.executemany(f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})', rows)
                    self.assertEqual(db.execute(f'SELECT {columns} FROM "{table}" ORDER BY rowid')
                                     .fetchall(), rows, f'Historical fixture changed {table} rows')
            self.assertEqual(db.execute(schema_sql).fetchall(), schema,
                             'copying rows must not introduce a later schema object')
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
        return v1

    def migrate(self, path: Path, policy: NotificationPolicy = POLICY) -> Store:
        """Migrate a v1 file in place, checking the version bookkeeping state migrations provides along the way.

        The version named at the end is this build's, not the version of the migration whose content
        these tests check: notifications carried the schema to v3, and what a v1 file must do is arrive where
        the running build lives — which is the statement that stays true at v4. Both halves are read,
        because `status()` answers with this module's `VERSION` constant and could not fail on its
        own: the number that has to be true is the one written into the file's header.
        """
        moved = Store(path, policy, migrate=True)
        self.assertEqual(moved.migrated_from, 1)
        self.assertIsNotNone(moved.migration_backup)
        self.assertEqual(moved.status()['schema_version'], state.VERSION)
        self.assertEqual(self.raw(moved, 'PRAGMA user_version')[0][0], state.VERSION,
                         'the migrated file must carry this build\'s version on disk')
        return moved

    def raw(self, store: Store, sql: str, parameters: tuple = ()) -> list[list]:
        """Run one read query against `store` with raw sqlite, so no answer comes from the store itself."""
        with closing(sqlite3.connect(store.path)) as db:
            return [list(row) for row in db.execute(sql, parameters)]

    def control_value(self, store: Store, key: str) -> str:
        """Return the value held under one notification control key."""
        rows = self.raw(store, 'SELECT value FROM notification_control WHERE key=?', (key,))
        self.assertEqual(len(rows), 1, 'control key %s was not back-filled' % key)
        return rows[0][0]

    def count(self, store: Store, sql: str, parameters: tuple = ()) -> int:
        """Return the single number one count query answers."""
        rows = self.raw(store, sql, parameters)
        self.assertEqual(len(rows), 1, 'not a scalar count: %s' % sql)
        return rows[0][0]

    # --- the shared scenario ------------------------------------------------------------------

    def fire(self, store: Store, source: str, status: str = 'firing', *, now: dt.datetime | None = None) -> str:
        """Intake one event for `source` and return the id of the delivery it queued."""
        now = now or NOW
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        before = {row['id'] for row in store.records('outbox')}
        store.intake(event(source, None, 'fixture', 'availability', status, window,
                           {'sample_id': 'fixture'}, query_type='gatus-result'), Actor(source, 'producer'), now=now)
        queued = [row['id'] for row in store.records('outbox') if row['id'] not in before]
        self.assertEqual(len(queued), 1, 'one event queues exactly one delivery')
        return queued[0]

    def latched_store(self, name: str) -> tuple[Store, dict, list, Receiver]:
        """Return a store holding the four artifacts control state moves: mode, slots, a latched breaker, a refusal.

        Two deliveries go out, the third is refused by the budget and latches the breaker, and a fourth
        waits behind it. Each of those left an audit row before control state and a control row after. The reports
        are the three `deliver_one` results, in order.
        """
        provider = Receiver()
        store = Store(self.root / (name + '.db'), POLICY)
        store.start_notification_mode(now=NOW)
        delivery, reports = {}, []
        for offset in (0, 1, 2):
            delivery[offset] = self.fire(store, 'detector-%d' % offset, now=NOW + dt.timedelta(seconds=offset))
            reports.append(deliver_one(store, provider, now=NOW + dt.timedelta(seconds=offset)))
        delivery['queued'] = self.fire(store, 'detector-3', now=NOW + dt.timedelta(seconds=3))
        return store, delivery, reports, provider

    def audit_history(self, path: Path) -> list[tuple]:
        """Return the audit log of `path` in write order, with raw sqlite."""
        with closing(sqlite3.connect(path)) as db:
            return db.execute('SELECT at,actor,operation,subject,detail FROM audit ORDER BY sequence').fetchall()

    def notification_audit_rows(self, path: Path) -> list[tuple]:
        """Return the `notification.*` audit rows of `path`, which is what the back-fill reads."""
        return [row for row in self.audit_history(path) if row[2].startswith('notification.')]

    # --- the migration writes what the audit log said -----------------------------------------

    def test_the_backfill_agrees_with_every_query_it_replaces(self) -> None:
        """Mode, breaker, slots and refusals arrive with the values the audit rows already held."""
        store, delivery, reports, provider = self.latched_store('backfill')
        self.assertEqual([report['status'] for report in reports], ['sent', 'sent', 'suppressed'])
        self.assertEqual(len(provider.calls), 2, 'the refused delivery must never have been sent')
        v1 = self.as_v1(store)
        # The audit half of control state: nothing here changed what the log records, so the back-fill has the
        # same rows a v1 build left in the field. `schema.migrated` is the only row it adds.
        self.assertEqual([row[2] for row in self.audit_history(v1)],
                         ['notification.mode', 'event.intake', 'notification.reserved', 'notification.sent',
                          'event.intake', 'notification.reserved', 'notification.sent',
                          'event.intake', 'notification.circuit_open', 'notification.suppressed',
                          'event.intake'])
        view = self.v1_view(v1, NOW + dt.timedelta(seconds=100))
        audited = self.notification_audit_rows(v1)
        moved = self.migrate(v1)

        self.assertEqual(self.control_value(moved, 'mode'), 'live')
        self.assertEqual(self.control_value(moved, 'mode'), view['mode'])
        self.assertEqual(json.loads(self.control_value(moved, 'circuit:primary')),
                         {'at': utc_text(NOW + dt.timedelta(seconds=2)), 'reset_at': '', 'state': 'open'},
                         'the breaker is back-filled latched, with no reset boundary to count from')
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM notification_suppressions'), view['suppressed'])
        self.assertEqual(self.raw(moved, 'SELECT outbox_id,channel,destination,test_window,at '
                                         'FROM notification_reservations ORDER BY id'),
                         [[delivery[0], CHANNEL, 'human', None, utc_text(NOW)],
                          [delivery[1], CHANNEL, 'human', None, utc_text(NOW + dt.timedelta(seconds=1))]],
                         'only the two sends are slots; the refusal took none')
        self.assertEqual(self.count(moved, "SELECT count(*) FROM notification_reservations WHERE channel=? AND "
                                           "destination='human' AND julianday(at)>julianday(?)",
                                    (CHANNEL, utc_text(NOW - dt.timedelta(seconds=1)))), view['slots'])
        self.assertEqual(self.raw(moved, 'SELECT outbox_id,reason,at FROM notification_suppressions'),
                         [[delivery[2], 'flood-circuit-open', utc_text(NOW + dt.timedelta(seconds=2))]])
        # The copy is not a move: the audit log keeps every row it held, control rows included.
        self.assertEqual(self.notification_audit_rows(moved.path), audited)

    def test_a_test_window_definition_survives_the_migration_and_stays_immutable(self) -> None:
        """A window approved at v1 keeps its definition, so reusing its id on new terms is refused."""
        window = {'id': 'approved-test', 'starts_at': utc_text(NOW),
                  'expires_at': utc_text(NOW + dt.timedelta(seconds=120)), 'max_attempts': 2}
        policy = NotificationPolicy(delivery_mode='live', test_window=window)
        provider = Receiver()
        store = Store(self.root / 'test-window.db', policy)
        self.fire(store, 'stage-jobs')
        self.assertEqual(deliver_one(store, provider, now=NOW)['destination'], 'human',
                         'an approved window is what puts a synthetic source on the human channel')
        v1 = self.as_v1(store)
        with closing(sqlite3.connect(v1)) as db:
            audited = db.execute(self.V1_TEST_WINDOW, (window['id'],)).fetchone()[0]
            self.assertEqual(db.execute(self.V1_TEST_SLOTS, (window['id'],)).fetchone()[0], 1)
        # Reopened with different terms under the same id: what the stored definition is there to catch.
        changed = NotificationPolicy(delivery_mode='live', test_window={**window, 'max_attempts': 10})
        moved = self.migrate(v1, changed)

        self.assertEqual(self.control_value(moved, 'test_window:approved-test'), canonical(window))
        self.assertEqual(self.control_value(moved, 'test_window:approved-test'), audited,
                         'the definition is the audit row, carried unchanged')
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM notification_reservations WHERE test_window=?',
                                    (window['id'],)), 1, 'the slot taken inside the window came across too')

        # The immutability is a property of the migrated row, not of a table nothing has used yet.
        self.fire(moved, 'stage-jobs', 'resolved', now=NOW + dt.timedelta(seconds=1))
        refused = deliver_one(moved, provider, now=NOW + dt.timedelta(seconds=1))
        self.assertEqual(refused['reason'], 'test-window-definition-changed')
        self.assertEqual(self.control_value(moved, 'test_window:approved-test'), canonical(window),
                         'a refusal must not overwrite the approved definition')
        self.assertEqual(len(provider.calls), 1, 'a refused test-window send must not reach the channel')

    def test_a_v1_file_is_refused_until_the_operator_migrates_it(self) -> None:
        """The migration stays opt-in, as state migrations made it: opening a v1 file names the command instead."""
        store, _, _, _ = self.latched_store('refusal')
        v1 = self.as_v1(store)
        before = v1.read_bytes()
        with self.assertRaisesRegex(StateError, r'version 1; run lo-platform migrate'):
            Store(v1, POLICY)
        self.assertEqual(v1.read_bytes(), before, 'refusing must not mean rewriting')
        self.migrate(v1)

    # --- what has to behave the same on both sides --------------------------------------------

    def test_control_state_and_the_next_claim_survive_the_migration(self) -> None:
        """Same status, same rows, same decision on the next delivery: one platform, two schema versions."""
        store, delivery, _, _ = self.latched_store('same-platform')
        status = store.notification_safety_status()
        history = self.audit_history(store.path)
        counts = store.status()
        self.assertEqual([status['circuit_open'], status['suppressed']], [True, 1])
        v1 = self.as_v1(store)
        view = self.v1_view(v1, NOW + dt.timedelta(seconds=4))
        moved = self.migrate(v1)

        self.assertEqual(moved.notification_safety_status(), status)
        self.assertEqual(moved.status(), counts, 'no outbox, incident or action row moved')
        self.assertEqual(self.audit_history(moved.path)[:len(history)], history)
        # One audit row per step that ran, and nothing else: a v1 file is carried to this build across
        # every migration in between, each committed with its own row (state migrations's design), so the count is
        # the number of steps rather than the number 1 that was true while the schema had two versions.
        self.assertEqual(len(self.audit_history(moved.path)), len(history) + state.VERSION - 1,
                         'exactly one audit row per migration step')
        self.assertEqual([row[2] for row in self.audit_history(moved.path)][len(history):],
                         ['schema.migrated'] * (state.VERSION - 1))
        self.assertEqual(self.audit_history(moved.path)[-1][2], 'schema.migrated')

        # What v1 would have handed out next, and what the migrated store hands out: same audit rows.
        self.assertEqual(view['next'], delivery['queued'])
        self.assertTrue(view['circuit_open'])
        self.assertEqual(moved.claim_notification(now=NOW + dt.timedelta(seconds=4)),
                         {'id': delivery['queued'], 'suppressed': 'flood-circuit-open', 'destination': 'human'})
        self.assertEqual(moved.notification_safety_status(), {**status, 'suppressed': status['suppressed'] + 1},
                         'a refused claim adds one suppression and changes nothing else')

    def test_a_backfilled_suppression_still_frees_the_head_of_the_line(self) -> None:
        """A suppressed row must not block its incident's next delivery, from either table.

        This is the head-of-line clause that used to ask the audit log whether a delivery had been
        suppressed. The suppression here is an `event-too-old` refusal, which takes no budget slot at
        all, so the migration has a refusal to carry and no slot to carry.
        """
        stale = NotificationPolicy(delivery_mode='live', max_event_age_seconds=60)
        fresh = NotificationPolicy(delivery_mode='live', max_event_age_seconds=900)
        store = Store(self.root / 'head-of-line.db', stale)
        blocked = self.fire(store, 'flapping')
        recovery = self.fire(store, 'flapping', 'resolved', now=NOW + dt.timedelta(seconds=1))
        refused = store.claim_notification(now=NOW + dt.timedelta(seconds=61))
        self.assertEqual((refused['id'], refused['suppressed']), (blocked, 'event-too-old'))
        self.assertEqual(store.notification_safety_status()['suppressed'], 1)
        v1 = self.as_v1(store)
        view = self.v1_view(v1, NOW + dt.timedelta(seconds=62))
        self.assertEqual([view['next'], view['slots'], view['suppressed']], [recovery, 0, 1],
                         'v1 let the recovery row past the suppressed alert')

        moved = self.migrate(v1, fresh)
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM notification_reservations'), 0)
        self.assertEqual(moved.notification_safety_status()['suppressed'], 1)
        claim = moved.claim_notification(now=NOW + dt.timedelta(seconds=62))
        self.assertEqual(claim['id'], view['next'])
        self.assertEqual(claim['destination'], 'human')
        self.assertEqual(claim['payload']['delivery_id'], view['next'])
        self.assertNotIn('suppressed', claim)
        for store_under_test in (moved, store):
            with self.assertRaisesRegex(StateError, 'cannot be replayed'):
                store_under_test.retry_notification(blocked, HUMAN, now=NOW + dt.timedelta(seconds=63))

    def test_a_mode_recorded_at_v1_still_gates_a_live_startup_at_v2(self) -> None:
        """`recording` in the audit log becomes a control row that still refuses a silent live start."""
        store = Store(self.root / 'mode-gate.db', NotificationPolicy(delivery_mode='recording'))
        store.start_notification_mode(now=NOW)
        self.fire(store, 'detector-0')
        v1 = self.as_v1(store)
        self.assertEqual(self.v1_view(v1, NOW)['mode'], 'recording')
        moved = self.migrate(v1, NotificationPolicy(delivery_mode='live'))

        with self.assertRaisesRegex(StateError, 'paused notification backlog'):
            moved.start_notification_mode(now=NOW + dt.timedelta(seconds=1))
        self.assertEqual(self.control_value(moved, 'mode'), 'recording')

        # The reconciliation the refusal asks for is what unlocks a live start, and it is still audited.
        moved.reset_notification_guard(HUMAN, now=NOW + dt.timedelta(seconds=2))
        moved.start_notification_mode(now=NOW + dt.timedelta(seconds=3))
        self.assertEqual(self.control_value(moved, 'mode'), 'live')
        self.assertEqual([json.loads(row[4])['mode'] for row in self.audit_history(moved.path)
                          if row[2] == 'notification.mode'], ['recording', 'live'],
                         'the audit log keeps recording every transition it always did')

    # --- the one documented difference --------------------------------------------------------

    def test_a_reset_taken_at_v1_moves_the_budget_window_at_v2(self) -> None:
        """The migration is where the control state answer to the ambiguity regression tests documented becomes visible.

        A v1 platform counted send slots from the ageing window alone, so a reset that unlatched the
        breaker bought no send: the slots that tripped it were still inside the window, and the next
        delivery re-latched it — the behaviour `tests/test_regression_timing.py` recorded before control state
        decided otherwise. Schema v2 stores the reset instant beside the breaker and counts from it, so
        a migrated database with byte-identical audit rows sends. That difference is the point of moving
        control out of the audit log, so it is asserted here rather than described in a comment.
        """
        provider = Receiver()
        store = Store(self.root / 'reset-boundary.db', POLICY)
        for offset in (0, 1):
            self.fire(store, 'detector-%d' % offset, now=NOW + dt.timedelta(seconds=offset))
            deliver_one(store, provider, now=NOW + dt.timedelta(seconds=offset))
        self.fire(store, 'detector-blocked', now=NOW + dt.timedelta(seconds=2))
        self.assertEqual(deliver_one(store, provider, now=NOW + dt.timedelta(seconds=2))['reason'],
                         'flood-circuit-open')
        store.reset_notification_guard(HUMAN, now=NOW + dt.timedelta(seconds=3))
        next_up = self.fire(store, 'detector-after', now=NOW + dt.timedelta(seconds=3))
        self.assertFalse(store.notification_safety_status()['circuit_open'], 'the reset did unlatch the breaker')
        v1 = self.as_v1(store)
        view = self.v1_view(v1, NOW + dt.timedelta(seconds=4))
        self.assertEqual([view['circuit_open'], view['slots']], [False, 2],
                         'v1 sees an unlatched breaker and a full window: the re-latch regression tests documented')
        history = self.audit_history(v1)
        moved = self.migrate(v1)
        self.assertEqual(self.audit_history(moved.path)[:len(history)], history,
                         'the two files agree about every audit row')

        self.assertEqual(json.loads(self.control_value(moved, 'circuit:primary')),
                         {'at': utc_text(NOW + dt.timedelta(seconds=3)),
                          'reset_at': utc_text(NOW + dt.timedelta(seconds=3)), 'state': 'closed'},
                         'the reset instant is what came across beside the breaker state')
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM notification_reservations'), 2,
                         'both v1 slots came across; it is the reset that makes them stop counting')
        self.assertEqual(self.count(moved, "SELECT count(*) FROM notification_reservations WHERE channel=? AND "
                                           "destination='human' AND julianday(at)>julianday(?)",
                                    (CHANNEL, utc_text(NOW + dt.timedelta(seconds=3)))), 0,
                         'the slots that tripped the breaker are behind the reset and stop counting')

        claim = moved.claim_notification(now=NOW + dt.timedelta(seconds=4))
        self.assertEqual(claim['id'], next_up)
        self.assertNotIn('suppressed', claim)
        self.assertEqual(claim['destination'], 'human')
        self.assertFalse(moved.notification_safety_status()['circuit_open'],
                         'the migrated platform did not re-latch where the v1 one would have')


if __name__ == '__main__':
    unittest.main()

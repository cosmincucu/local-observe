"""The suppression index: a lifetime of old maintenance windows may not silence a future one.

A declared window is a key in `notification_control` and rows are never deleted, so the read that asked
`key LIKE 'maintenance:%'` walked **every window ever declared** before it dropped the expired and
revoked ones. Past `MAX_WINDOW_ROWS` of that history it saw nothing at all, said `bound_exceeded` and
applied no window — while `declare_window`, which asked the same read only for `count`, kept accepting
new ones. The symptom is a platform that records every declaration and honours none of them, forever.

The fix is schema v5: ONE partial expression index over the documents that table already holds, keyed on
the end of a declared, unrevoked window. So the read asks for candidates — declared, unrevoked, not yet
expired, at most `MAX_WINDOW_ROWS` of them — and an old row spends neither a slot nor a page read. What
the index does *not* buy is authority: every candidate still passes the envelope, declared-block,
attestation and expiry checks in `_scan`, which is why the refusal cases are re-run here rather than
assumed.

The historical file is created using only migrations 1..4. Public-path declarations, revocations and
events are generated separately, then copied into the historical tables using their actual columns.
Every copied row is compared with its source; no future schema object enters the migration fixture.

Two properties are attacked from both ends:

* **old rows cost the read nothing.** 2048 expired plus 256 revoked genuine declarations — 2304 rows,
  past the 512 bound and past 2000 — leave a *new* declaration still suppressing, and the candidate
  query costs the index's work rather than the file's size.
* **the bound still means stop.** A candidate set past `MAX_WINDOW_ROWS` is refused *at declaration*,
  because a window this build cannot promise to apply must not be accepted as though it could.

Malformed control text is in scope too: it must not fail the migration, must not fail a later write, and
must not silence anything.
"""
import datetime as dt
from contextlib import closing, contextmanager
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from local_observe.inventory.validation import canonical, timestamp, utc_text
from local_observe.platform import cli, state, suppression
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store
from test_maintenance_windows import plant_window       # noqa: E402  (tests/ is not a package)

NOW = timestamp('2026-09-09T12:00:00Z')
HUMAN = Actor('operator', 'human')
PRODUCER = Actor('history-detector', 'producer')
RESOURCE = '7b3e9c1d-2f4a-4b5c-9d8e-1a2b3c4d5e6f'
OTHER = '1a2b3c4d-5e6f-4a5b-8c9d-0e1f2a3b4c5d'
UNTENDED = '3c4d5e6f-7a8b-4c9d-8e1a-2b3c4d5e6f7a'
RULE = 'disk-watermark'
#: Lifetime rows in the shared file: past the 512 candidate bound, past 2000 rows, and every one of them
#: a declaration a human really made (and, for the last block, really revoked) at a real instant.
EXPIRED_ROWS = 2048
REVOKED_ROWS = 256
#: Events filed beside the windows, so "the read does not scale with history" is not measured on a file
#: that happens to hold nothing else.
UNRELATED_EVENTS = 40
#: One window revoked while it still had hours to run: the single lifetime row a time predicate alone
#: would still have offered, so `revoked IS NULL` is what keeps it out of the candidate set.
REVOKED_LIVE_ROWS = 1
V4_COPY = r'\.pre-v4-\d{8}T\d{6}Z\.db$'


@contextmanager
def at_version(version: int):
    """Create and open files using only the selected release's migration scripts."""
    migrations = {target: state.MIGRATIONS[target] for target in range(1, version + 1)}
    with mock.patch.object(state, 'MIGRATIONS', migrations), \
            mock.patch.object(state, 'VERSION', version), mock.patch.object(cli, 'VERSION', version):
        yield


def at_v4():
    return at_version(4)


def declaration(reason: str, start: dt.datetime, end: dt.datetime, *,
                resource: str | None = RESOURCE, rule: str | None = None) -> dict:
    """One well-formed declaration: one selector, one bounded span, one printable reason."""
    return {'resource_id': resource, 'rule_id': rule, 'starts_at': utc_text(start),
            'ends_at': utc_text(end), 'reason': reason}


def verdict(status: str, at: dt.datetime, *, rule: str = RULE,
            resource: str | None = RESOURCE) -> dict:
    """One canonical event for `rule` on `resource`, at `at`."""
    window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
    return event(PRODUCER.identity, resource, rule, 'availability', status, window,
                 {'sample_id': 'fixture'}, query_type='gatus-result')


def resource_at(step: int, marker: int) -> str:
    """One synthetic resource id, so every declaration in the fixture is about a different resource."""
    return '%08x-%04x-4000-8000-000000000000' % (step, marker)


def build_v4(path: Path) -> Path:
    """Copy public-path rows into a file created from migrations 1..4 only."""
    store = Store(path)
    store.start_notification_mode(now=NOW)
    base = NOW - dt.timedelta(days=20)
    for step in range(EXPIRED_ROWS):
        start = base + dt.timedelta(minutes=step)
        suppression.declare_window(store, declaration('rotate the disk %d' % step, start,
                                                     start + dt.timedelta(seconds=60),
                                                     resource=resource_at(step, 0)),
                                   HUMAN, now=start)
    for step in range(REVOKED_ROWS):
        # A base well after the expired block's own horizon: a declaration is *live* until its end, so a
        # revoked window that overlapped the expired ones would still be a candidate at the instant the
        # next one was declared, and the fixture would trip the live bound it is meant to stay clear of.
        start = NOW - dt.timedelta(days=10) + dt.timedelta(minutes=step)
        answer = suppression.declare_window(store, declaration('cancelled job %d' % step, start,
                                                              start + dt.timedelta(hours=2),
                                                              resource=resource_at(step, 0x1000)),
                                            HUMAN, now=start)
        suppression.revoke_window(store, answer['id'], HUMAN, now=start)
    span_start = NOW - dt.timedelta(hours=1)
    answer = suppression.declare_window(store, declaration('stopped early', span_start,
                                                          NOW + dt.timedelta(hours=1),
                                                          resource=resource_at(0x8000, 0x1000)),
                                        HUMAN, now=span_start)
    suppression.revoke_window(store, answer['id'], HUMAN, now=NOW)
    for step in range(UNRELATED_EVENTS):
        at = NOW - dt.timedelta(minutes=2 + step)
        store.intake(verdict('firing', at, rule='history-rule-%d' % step,
                             resource=resource_at(step, 0x2000)), PRODUCER, now=at)
    snapshot = path.with_name('v4-source.db')
    with at_v4():
        Store(snapshot)
    with closing(sqlite3.connect(path)) as source, closing(sqlite3.connect(snapshot)) as target:
        tables = [row[0] for row in target.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        with target:
            for table in tables:
                columns = ','.join('"' + row[1].replace('"', '""') + '"'
                                   for row in target.execute(f'PRAGMA table_info("{table}")'))
                rows = source.execute(f'SELECT {columns} FROM "{table}" ORDER BY rowid').fetchall()
                placeholders = ','.join('?' for _ in target.execute(f'PRAGMA table_info("{table}")'))
                target.executemany(f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})', rows)
                copied = target.execute(f'SELECT {columns} FROM "{table}" ORDER BY rowid').fetchall()
                if copied != rows:
                    raise AssertionError(f'Historical fixture changed {table} rows')
        if target.execute('PRAGMA foreign_key_check').fetchall():
            raise AssertionError('Historical fixture has broken foreign keys')
    return snapshot


class MaintenanceHistoryTests(unittest.TestCase):
    """The v4 file, the v5 step, and what the window surface must still do afterwards."""

    @classmethod
    def setUpClass(cls) -> None:
        """Build the lifetime file once: it is the slow part of this file and no test may edit it."""
        source = tempfile.TemporaryDirectory()
        cls.addClassCleanup(source.cleanup)
        cls.v4 = build_v4(Path(source.name) / 'lifetime.db')

    def setUp(self) -> None:
        """Give each test its own copy of the lifetime file."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'case.db'
        self.path.write_bytes(self.v4.read_bytes())

    # --- helpers ------------------------------------------------------------------------------

    def migrated(self) -> Store:
        """Carry this test's copy to this build's schema explicitly, and hand back the open store."""
        return Store(self.path, migrate=True)

    def raw(self, sql: str, parameters: tuple = (), path: Path | None = None) -> list[list]:
        """Read a file with raw sqlite, so no answer here comes from the code under test."""
        with closing(sqlite3.connect(path or self.path)) as db:
            return [list(row) for row in db.execute(sql, parameters).fetchall()]

    def window_keys(self, path: Path | None = None) -> list[str]:
        """Every stored window key in the file, however untrustworthy its text is."""
        return [row[0] for row in
                self.raw('SELECT key FROM notification_control WHERE key LIKE ? ORDER BY key',
                         (state.MAINTENANCE_PREFIX + '%',), path)]

    def indexes(self, path: Path | None = None) -> set[str]:
        """The index names `notification_control` answers with, from SQLite's own catalog."""
        with closing(sqlite3.connect(path or self.path)) as db:
            return {row[1] for row in db.execute('PRAGMA index_list(notification_control)')}

    def tables(self, path: Path | None = None) -> set[str]:
        """Every table in the file — an index is not one, and that distinction is the whole design."""
        return {row[0] for row in
                self.raw("SELECT name FROM sqlite_master WHERE type='table'", (), path)}

    def integrity(self, path: Path | None = None) -> str:
        """SQLite's own verdict on a file, without any platform code opening it."""
        with closing(sqlite3.connect(path or self.path)) as db:
            return db.execute('PRAGMA integrity_check').fetchone()[0]

    def header_version(self, path: Path | None = None) -> int:
        """The `user_version` written in the file's own header."""
        with closing(sqlite3.connect(path or self.path)) as db:
            return db.execute('PRAGMA user_version').fetchone()[0]

    def plan(self, path: Path) -> str:
        """The EXPLAIN QUERY PLAN text of the candidate read, phrased exactly as `_scan` phrases it."""
        with closing(sqlite3.connect(path)) as db:
            rows = db.execute('EXPLAIN QUERY PLAN ' + suppression._CANDIDATE_SQL,
                              (utc_text(NOW), suppression.MAX_WINDOW_ROWS + 1)).fetchall()
        return ' '.join(row[3] for row in rows)

    def candidate_steps(self, path: Path) -> int:
        """How much SQLite work the candidate query costs in `path`, counted by its own progress handler.

        The handler fires once per 100 virtual-machine steps, so the count is a work proxy and not a
        latency claim — which is the right unit here: the defect was a read whose cost grew with the
        number of windows an operator had ever declared. The statement runs twice and only the second
        run is counted, so reading the file's schema is in neither number.
        """
        calls: list[int] = []
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.set_progress_handler(lambda: calls.append(1) or 0, 100)
            db.execute(suppression._CANDIDATE_SQL,
                       (utc_text(NOW), suppression.MAX_WINDOW_ROWS + 1)).fetchall()
            calls.clear()
            db.execute(suppression._CANDIDATE_SQL,
                       (utc_text(NOW), suppression.MAX_WINDOW_ROWS + 1)).fetchall()
        return len(calls)

    def ordered_pair(self, early: dt.datetime, late: dt.datetime,
                     end: dt.datetime) -> tuple[dict, dict]:
        """Two declarations whose ids sort the opposite way round to their starts.

        Window ids are digests, so which reason produces the later one is found by trying a short list
        rather than assumed. The case that has to be reachable is a live window whose key is lexically
        *later* than another live window's: a read that stopped at the first candidate, or one that
        ordered by key alone, would apply the wrong declaration or none.
        """
        reasons = ('swap the disk', 'rebuild the host', 'upgrade the agent', 'move the volume',
                   'reboot the node', 'rotate the certificate')
        for first in reasons:
            early_document = declaration(first, early, end)
            for second in reasons:
                if first == second:
                    continue
                late_document = declaration(second, late, end)
                if suppression.window_id(early_document) > suppression.window_id(late_document):
                    return early_document, late_document
        self.fail('no pair of declarations in the fixture ordered its ids the way the case needs')

    # --- the step -----------------------------------------------------------------------------

    @at_version(5)
    def test_the_v4_to_v5_step_adds_one_index_moves_no_row_and_is_rolled_back_by_the_copy(self):
        """The step is an index: same tables, same rows, one audited transaction, one usable copy.

        "Data unchanged except `schema.migrated`" is checked row for row on the tables that hold
        operator facts, and the rollback half is the copy itself: the v4 build opens it and reads the
        same status, while the *migrated* file is one it refuses rather than one it half-reads.
        """
        self.assertEqual(self.header_version(), 4)
        self.assertNotIn(state.MAINTENANCE_WINDOW_INDEX, self.indexes())
        with at_v4():
            before = Store(self.path).status()
        control = self.raw('SELECT key,value,updated_at FROM notification_control ORDER BY key')
        events, outbox = (self.raw('SELECT * FROM events ORDER BY rowid'),
                          self.raw('SELECT * FROM outbox ORDER BY sequence'))
        history = self.raw('SELECT at,actor,operation,subject,detail FROM audit ORDER BY sequence')
        tables = self.tables()

        moved = self.migrated()
        self.assertEqual(moved.migrated_from, 4)
        self.assertEqual(self.header_version(), state.VERSION)
        self.assertEqual(state.VERSION, 5)
        self.assertIn(state.MAINTENANCE_WINDOW_INDEX, self.indexes())
        self.assertEqual(self.tables(), tables, 'a fifth step joined the schema and no table did')
        self.assertEqual(self.raw('SELECT key,value,updated_at FROM notification_control ORDER BY key'),
                         control, 'the documents the index is built over did not move')
        self.assertEqual(self.raw('SELECT * FROM events ORDER BY rowid'), events)
        self.assertEqual(self.raw('SELECT * FROM outbox ORDER BY sequence'), outbox)
        after = self.raw('SELECT at,actor,operation,subject,detail FROM audit ORDER BY sequence')
        self.assertEqual(after[:len(history)], history, 'the audit log is carried, not rewritten')
        self.assertEqual(len(after), len(history) + 1, 'one step, one audited transaction')
        self.assertEqual(after[-1][1:3], [state.MIGRATE_ACTOR, 'schema.migrated'])
        detail = json.loads(after[-1][4])
        self.assertEqual(after[-1][3], str(state.VERSION), 'the row names the step that ran')
        self.assertEqual({key: detail[key] for key in ('from', 'to')},
                         {'from': 4, 'to': state.VERSION})
        self.assertEqual(detail['script_sha256'], state.digest(state.MAINTENANCE_WINDOW_SCHEMA))

        backup = moved.migration_backup
        self.assertIsNotNone(backup)
        self.assertRegex(backup.name, V4_COPY)
        self.assertEqual(self.header_version(backup), 4, 'the copy holds the pre-migration version')
        self.assertEqual(self.integrity(backup), 'ok')
        self.assertNotIn(state.MAINTENANCE_WINDOW_INDEX, self.indexes(backup))
        with at_v4():
            self.assertEqual(Store(backup).status(), before, 'the release that wrote it still runs it')
            with self.assertRaisesRegex(StateError, 'restore or migrate'):
                Store(self.path)

    def test_a_fresh_database_builds_the_same_index_from_the_same_scripts(self):
        """Creation and migration reach one shape, because creation applies the same scripts in order."""
        fresh = self.root / 'fresh.db'
        Store(fresh)
        self.assertEqual(self.header_version(fresh), state.VERSION)
        self.assertEqual(self.tables(fresh), self.tables(self.migrated().path))
        self.assertEqual(self.indexes(fresh), self.indexes(self.migrated().path))

    # --- the read -----------------------------------------------------------------------------

    def test_the_candidate_read_uses_the_index_and_not_the_size_of_the_history(self):
        """Two proofs of one claim: the plan names the index, and the work does not grow with the file.

        The file at the other end of the comparison holds 2304 window declarations and 40 unrelated
        events, and both numbers come from the statement `_scan` actually runs — so a future edit that
        quietly falls back to a table scan, or to sorting the candidates itself, fails here and not in
        an outage.
        """
        moved = self.migrated()
        self.assertEqual(suppression.declare_window(moved, declaration('swap the PSU', NOW,
                                                                      NOW + dt.timedelta(hours=1)),
                                                   HUMAN, now=NOW)['status'], 'declared')
        plan = self.plan(moved.path)
        self.assertIn(state.MAINTENANCE_WINDOW_INDEX, plan, plan)
        self.assertNotIn('USE TEMP B-TREE', plan, plan)

        small = self.root / 'small.db'
        suppression.declare_window(Store(small), declaration('swap the PSU', NOW,
                                                            NOW + dt.timedelta(hours=1)),
                                   HUMAN, now=NOW)
        cheap = self.candidate_steps(small)
        costly = self.candidate_steps(moved.path)
        self.assertLessEqual(costly, max(60, 4 * cheap),
                             f'the candidate query cost {costly} progress calls against {cheap}')

    def test_the_partial_range_names_exactly_the_window_keys(self):
        """The index's key range and the old `LIKE 'maintenance:%'` select the same rows, and nothing else.

        A range instead of a prefix pattern is what makes the partial index usable at all, so the two
        spellings have to agree — including on the mode, breaker and test-window keys that share the
        table and must stay out of the window read.
        """
        moved = self.migrated()
        suppression.declare_window(moved, declaration('clean the fan', NOW, NOW + dt.timedelta(hours=1)),
                                   HUMAN, now=NOW)
        ranged = [row[0] for row in self.raw('SELECT key FROM notification_control WHERE '
                                             + state.MAINTENANCE_WINDOW_KEYS + ' ORDER BY key')]
        self.assertTrue(ranged, 'a declared window must fall inside the partial index range')
        self.assertEqual(ranged, self.window_keys(),
                         'the range and the old prefix pattern select the same rows')

    def test_two_thousand_lifetimes_of_old_windows_leave_every_new_declaration_working(self):
        """The defect as its own test: history that no longer applies may not spend the read.

        2304 genuine declarations sit in the file, every one of them expired or revoked — including one
        revoked while it still had hours to run, which only the `revoked IS NULL` half of the index keeps
        out. A new resource window still silences a send, a new rule window still silences the rule it
        names and no other, and the read says it looked at two candidates rather than at a lifetime.
        """
        moved = self.migrated()
        self.assertGreater(len(self.window_keys()), 2000, 'the file out-grew the old bound')
        suppression.declare_window(moved, declaration('replace the disk', NOW,
                                                      NOW + dt.timedelta(hours=4)), HUMAN, now=NOW)
        suppression.declare_window(moved, declaration('collector offline', NOW,
                                                      NOW + dt.timedelta(hours=4),
                                                      resource=None, rule=RULE), HUMAN, now=NOW)
        at = NOW + dt.timedelta(minutes=1)
        covered = suppression.file_event(moved, verdict('firing', at), PRODUCER, now=at)
        self.assertTrue(covered['suppressed'], 'a resource selector still silences its resource')
        self.assertEqual(covered['decision'].cause, 'maintenance-window')
        rule_only = suppression.file_event(moved, verdict('firing', at, resource=OTHER), PRODUCER, now=at)
        self.assertTrue(rule_only['suppressed'], 'and a rule selector still silences its rule')
        self.assertIn(RULE, rule_only['decision'].reason)
        neighbour = suppression.file_event(moved, verdict('firing', at, rule='other-rule',
                                                        resource=UNTENDED), PRODUCER, now=at)
        self.assertFalse(neighbour['suppressed'], 'and neither reaches anything else')
        answer = suppression.live_windows(moved, now=NOW)
        self.assertEqual((answer['count'], answer['scanned'], answer['revoked'], answer['expired'],
                          answer['unusable'], answer['unattested'], answer['bound_exceeded']),
                         (2, 2, 0, 0, 0, 0, False),
                         'the counters describe the candidates read, never the lifetime stored')
        self.assertEqual(suppression.stats(moved, now=NOW)['windows']['declared'], 2)

    def test_a_live_window_whose_key_sorts_after_another_is_still_the_one_applied(self):
        """The SQL orders by end and key; the answer is ordered by start — the earlier one must not miss.

        The covering window here is the one whose key is lexically *later* (see `ordered_pair`), so a
        read that ordered by key, or that stopped at the first candidate it saw, would apply the wrong
        declaration.
        """
        moved = self.migrated()
        early, later = self.ordered_pair(NOW - dt.timedelta(minutes=30), NOW - dt.timedelta(minutes=5),
                                        NOW + dt.timedelta(hours=1))
        first = suppression.declare_window(moved, early, HUMAN, now=NOW)
        second = suppression.declare_window(moved, later, HUMAN, now=NOW)
        self.assertGreater(state.maintenance_key(first['id']), state.maintenance_key(second['id']),
                           'the fixture is the order the read has to survive')
        answer = suppression.live_windows(moved, now=NOW)
        self.assertEqual([window['reason'] for window in answer['windows']],
                         [early['reason'], later['reason']], 'ordered by start, not by key')
        covering = suppression.covering_window(moved, verdict('firing', NOW), now=NOW)
        self.assertEqual((covering['id'], covering['covers_now']), (first['id'], True))

    def test_the_thirty_second_live_window_is_still_the_limit_and_the_thirty_third_refused(self):
        """The live bound counts live windows, so 2304 dead ones may neither tighten nor loosen it.

        The 32nd declaration is the last acceptance and the 33rd is refused with the sentence an
        operator can act on; the candidate count says 32 on both sides, in which none of the lifetime
        rows ever appeared.
        """
        moved = self.migrated()
        for step in range(suppression.MAX_LIVE_WINDOWS):
            start = NOW + dt.timedelta(minutes=step)
            answer = suppression.declare_window(moved, declaration('staggered work %d' % step, start,
                                                                  start + dt.timedelta(minutes=30),
                                                                  resource=resource_at(step, 0x3000)),
                                                HUMAN, now=NOW)
            self.assertEqual(answer['status'], 'declared', f'window {step}')
        with self.assertRaisesRegex(StateError, 'live maintenance windows'):
            suppression.declare_window(moved, declaration('one too many', NOW,
                                                         NOW + dt.timedelta(minutes=30),
                                                         resource=resource_at(99, 0x3000)),
                                       HUMAN, now=NOW)
        answer = suppression.live_windows(moved, now=NOW)
        self.assertEqual((answer['count'], answer['scanned']),
                         (suppression.MAX_LIVE_WINDOWS, suppression.MAX_LIVE_WINDOWS))

    def test_exact_start_exact_expiry_revocation_and_a_repeat_behave_as_they_did(self):
        """The four boundaries the feature is named for, re-run on a migrated file.

        Covers at `starts_at`, stops at `ends_at` (so not one second past it), closes when a human
        revokes it, and answers an identical repeat with the stored window rather than a second silence.
        The last assertion is the new half: a revoked window stops being a candidate the moment it is
        revoked, so it spends no slot in the next read either.
        """
        moved = self.migrated()
        end = NOW + dt.timedelta(minutes=30)
        declared = suppression.declare_window(moved, declaration('replace the disk', NOW, end),
                                             HUMAN, now=NOW)
        self.assertEqual(suppression.decide(moved, verdict('firing', NOW), now=NOW).cause,
                         'maintenance-window', 'a window covers the instant it starts at')
        self.assertIsNone(suppression.decide(moved, verdict('firing', end), now=end).cause,
                          'and stops at the instant it ends')
        past = end + dt.timedelta(seconds=1)
        self.assertIsNone(suppression.decide(moved, verdict('firing', past), now=past).cause)
        repeat = suppression.declare_window(moved, declaration('replace the disk', NOW, end),
                                            Actor('second-operator', 'human'), now=NOW)
        self.assertEqual((repeat['status'], repeat['id']), ('duplicate', declared['id']))
        self.assertEqual(suppression.revoke_window(moved, declared['id'], HUMAN,
                                                   now=NOW + dt.timedelta(minutes=1))['status'], 'revoked')
        self.assertIsNone(suppression.covering_window(moved, verdict('firing', NOW), now=NOW))
        self.assertEqual(suppression.live_windows(moved, now=NOW)['scanned'], 0)

    # --- what still cannot apply --------------------------------------------------------------

    def test_a_tampered_or_unattested_live_row_is_a_candidate_and_still_applies_nothing(self):
        """The rows the index cannot distrust are still refused by the read that applies them.

        An unrevoked window with a future end is a candidate whatever else is true of it, so both rows
        below reach `_scan` and are stopped there: the one no human declared, and the one whose declared
        text moved after the fact. Both are counted, neither silences a page, and the tampered one can
        still be revoked — signing a cancellation can never silence anything.
        """
        moved = self.migrated()
        plant_window(moved, 'unattested-after-v5', start=NOW, end=NOW + dt.timedelta(hours=4),
                     attest=False)
        declared = suppression.declare_window(moved, declaration('widen me', NOW,
                                                                NOW + dt.timedelta(hours=2)),
                                             HUMAN, now=NOW)
        key = state.maintenance_key(declared['id'])
        with moved.transaction() as connection:
            document = json.loads(connection.execute('SELECT value FROM notification_control'
                                                     ' WHERE key=?', (key,)).fetchone()[0])
            document['declared']['ends_at'] = utc_text(NOW + dt.timedelta(hours=20))
            connection.execute('UPDATE notification_control SET value=? WHERE key=?',
                               (canonical(document), key))
        answer = suppression.live_windows(moved, now=NOW)
        self.assertEqual((answer['count'], answer['unattested'], answer['scanned']), (0, 2, 2))
        self.assertFalse(suppression.decide(moved, verdict('firing', NOW), now=NOW).suppressed)
        self.assertEqual(suppression.revoke_window(moved, declared['id'], HUMAN,
                                                   now=NOW)['status'], 'revoked')

    def test_malformed_control_text_survives_the_migration_and_breaches_nothing_afterwards(self):
        """Text that is not JSON cannot fail the migration, cannot fail a write, cannot silence a pager.

        `json_extract` raises on invalid JSON, which is why the index expression guards itself with
        `json_valid` *inside* the same CASE rather than beside it: a statement that could raise would
        fail this migration and every control write after it. The rows below are planted before the step
        runs, in the table and under the range the index covers, and the step is what has to survive them.
        """
        malformed = ['not json at all', '{"declared": {"ends_at": ', '{"declared":null,"revoked":null}',
                     '[]', '{"schema_version":1}']
        with closing(sqlite3.connect(self.path)) as db:
            for offset, text in enumerate(malformed):
                db.execute('INSERT INTO notification_control(key,value,updated_at) VALUES (?,?,?)',
                           ('maintenance:malformed-%d' % offset, text, utc_text(NOW)))
            db.execute('INSERT INTO notification_control(key,value,updated_at) VALUES (?,?,?)',
                       ('test_window:broken', 'not json at all', utc_text(NOW)))
            db.commit()
        self.assertEqual(self.header_version(), 4, 'the garbage is planted on a real v4 file')

        self.migrated()
        self.assertEqual(self.integrity(), 'ok')
        self.assertEqual(len(self.window_keys()),
                         EXPIRED_ROWS + REVOKED_ROWS + REVOKED_LIVE_ROWS + len(malformed),
                         'the migration neither deleted an unreadable row nor repaired one')
        moved = Store(self.path)
        answer = suppression.live_windows(moved, now=NOW)
        self.assertEqual((answer['count'], answer['scanned'], answer['unusable']), (0, 0, 0),
                         'unreadable text is not a candidate, so it is not a window either')
        self.assertIsNone(suppression.covering_window(moved, verdict('firing', NOW), now=NOW))
        self.assertFalse(suppression.decide(moved, verdict('firing', NOW), now=NOW).suppressed)
        # The writes still work, which is the half a statement error would have taken away.
        self.assertEqual(suppression.declare_window(moved, declaration('clear the queue', NOW,
                                                                      NOW + dt.timedelta(hours=1)),
                                                   HUMAN, now=NOW)['status'], 'declared')
        at = NOW + dt.timedelta(minutes=1)
        self.assertTrue(suppression.file_event(moved, verdict('firing', at), PRODUCER,
                                               now=at)['suppressed'])

    def test_a_candidate_set_past_the_bound_refuses_a_declaration_this_build_cannot_promise(self):
        """The refusal the new bound needs: an incomplete scan may not be answered with acceptance.

        `live_windows` applies nothing past `MAX_WINDOW_ROWS` candidates, so accepting a window into that
        set would take a human's word for a silence this build cannot promise to keep. The declaration
        is refused instead — the loud direction — and nothing is deleted to make room.
        """
        bound = Store(self.root / 'bound.db')
        for step in range(suppression.MAX_WINDOW_ROWS + 1):
            plant_window(bound, str(step), start=NOW - dt.timedelta(minutes=step),
                         end=NOW + dt.timedelta(minutes=30))
        self.assertTrue(suppression.live_windows(bound, now=NOW)['bound_exceeded'])
        with self.assertRaisesRegex(StateError, 'candidates exceed the read bound'):
            suppression.declare_window(bound, declaration('cannot be promised', NOW,
                                                         NOW + dt.timedelta(hours=1)), HUMAN, now=NOW)
        self.assertIsNone(suppression.covering_window(bound, verdict('firing', NOW), now=NOW))
        self.assertFalse(suppression.decide(bound, verdict('firing', NOW), now=NOW).suppressed)
        self.assertEqual(len(self.window_keys(bound.path)), suppression.MAX_WINDOW_ROWS + 1,
                         'a refusal is not a deletion: every row is still there')

    def test_a_full_candidate_set_refuses_the_insert_that_would_overflow_it(self):
        """Invalid candidates still spend slots; an accepted declaration must fit the next read."""
        bound = Store(self.root / 'full.db')
        for step in range(suppression.MAX_WINDOW_ROWS - 1):
            plant_window(bound, str(step), start=NOW, end=NOW + dt.timedelta(minutes=30), attest=False)
        accepted = suppression.declare_window(bound, declaration('last available slot', NOW,
                                                                 NOW + dt.timedelta(hours=1)),
                                              HUMAN, now=NOW)
        self.assertEqual(accepted['status'], 'declared')
        candidates = suppression.live_windows(bound, now=NOW)
        self.assertFalse(candidates['bound_exceeded'])
        self.assertEqual((candidates['scanned'], candidates['count']),
                         (suppression.MAX_WINDOW_ROWS, 1))
        history = self.raw('SELECT * FROM audit ORDER BY sequence', path=bound.path)
        controls = self.raw('SELECT * FROM notification_control ORDER BY key', path=bound.path)
        with self.assertRaisesRegex(StateError, 'candidates exceed the read bound'):
            suppression.declare_window(bound, declaration('cannot fit', NOW,
                                                         NOW + dt.timedelta(hours=1)), HUMAN, now=NOW)
        self.assertEqual(self.raw('SELECT * FROM audit ORDER BY sequence', path=bound.path), history)
        self.assertEqual(self.raw('SELECT * FROM notification_control ORDER BY key', path=bound.path),
                         controls)
        self.assertEqual(suppression.covering_window(bound, verdict('firing', NOW), now=NOW)['id'],
                         accepted['id'], 'the refusal preserves the last applicable declaration')


if __name__ == '__main__':
    unittest.main()

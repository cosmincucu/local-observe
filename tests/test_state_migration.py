"""state migrations: carrying the operational database across a schema version bump.

`local_observe/platform/state.py` used to accept exactly one shape of existing file —
`(application_id, user_version) == (0x4C4F5001, 1)` — plus the empty file, and had no migration code
at all. The first real `VERSION` bump would therefore have made every deployed platform database
unopenable while the suite stayed green (`docs/remediation/LEDGER.md` state migrations, from the regression tests
finding in
`docs/remediation/reports/REPORT_TESTS.md` §4). What is under test here is the mechanism that
replaces that: `MIGRATIONS` (target version -> the script that reaches it), an opt-in
`Store(..., migrate=True)` that writes a verified copy beside the file before changing anything, one
audited transaction per step, and the `lo-platform migrate` command.

That first bump arrived on 2026-09-07 with control state: `VERSION` is 2 and `MIGRATIONS[2]` is a real script
(notification control moved out of the audit table), not a probe. So the fake steps below are keyed
above the real ones, and the older database each test starts from is created by a build pinned *down*
to v1 (`at_v1`) instead of by whatever this checkout ships. What migration 2 contains is verified in
`tests/test_control_state_migration.py`; what it takes to run any migration is verified here.
"""
import datetime as dt
from contextlib import closing, contextmanager, redirect_stdout
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import cli, state
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-06T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')
V1_TABLES = {'actions', 'audit', 'conditions', 'events', 'evidence', 'executions', 'incidents',
             'notification_attempts', 'outbox', 'sqlite_sequence'}
# What a file this build creates holds: v1 plus the three tables control state moved notification control into,
# plus the two tables wave 6  added at v4 — a binding captured per action and the immutable
# statements filed against it — plus the one table correlation added at v7 to hold why several conditions are
# one incident. A new table changes what this pin means, so all are named here and the content of each
# step is verified in its own migration test (`tests/test_verification_records_migration.py`,
# `tests/test_incident_grouping_migration.py`).
CURRENT_TABLES = V1_TABLES | {'notification_control', 'notification_reservations',
                              'notification_suppressions', 'verification_bindings',
                              'verification_records', 'incident_members', 'runner_approvals',
                              'runner_requests', 'setup_plans'}
PROBE_V2 = 'CREATE TABLE migration_probe(x);\n'
PROBE_V3 = 'CREATE TABLE migration_probe_v3(x);\n'
PROBE_V4 = 'CREATE TABLE migration_probe_v4(x);\n'
BACKUP_NAME = re.compile(r'\.pre-v(\d+)-\d{8}T\d{6}Z\.db$')


class SchemaMigrationTests(unittest.TestCase):
    """What a build one schema version ahead must do — and refuse to do — with an older database."""

    def setUp(self):
        """Open a scratch directory; every file below is named by the test that creates it."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @contextmanager
    def at_v1(self):
        """Act as the released build whose schema is 1, which is the one that wrote every file below.

        Since control state a bare `Store(path)` makes a v2 database, so a test that then acts as a v2 build is
        ahead of nothing. `MIGRATIONS`, `state.VERSION` and `cli.VERSION` move together here exactly as
        `build` moves them upward; only the direction differs, because a release cannot unship a
        migration — it can only be older than the checkout it is being tested against.
        """
        with mock.patch.object(state, 'MIGRATIONS', {1: state.SCHEMA}), \
                mock.patch.object(state, 'VERSION', 1), mock.patch.object(cli, 'VERSION', 1):
            yield

    @contextmanager
    def build(self, version: int, migrations: dict[int, str]):
        """Act as the release whose schema is `version`.

        `MIGRATIONS`, `state.VERSION` and `cli.VERSION` move together on purpose: a real bump changes
        all three in one commit, so patching one without the others would test a build that cannot
        exist rather than the one being shipped. The mapping is *replaced* and not updated, because
        `MIGRATIONS[1]` must stay the whole v1 script and `VERSION` must name the highest key present:
        an updated dict would carry this checkout's later migrations under a lower `VERSION`, which is
        exactly the disagreement `_check_build` refuses to touch, and the test would be measuring a
        build error instead of the migration behaviour it names.
        """
        with mock.patch.object(state, 'MIGRATIONS', {1: state.SCHEMA, **migrations}), \
                mock.patch.object(state, 'VERSION', version), \
                mock.patch.object(cli, 'VERSION', version):
            yield

    def header(self, path: Path) -> tuple[int, int, list[str]]:
        """Read `application_id`, `user_version` and the sorted table names with raw sqlite."""
        with closing(sqlite3.connect(path)) as connection:
            return (connection.execute('PRAGMA application_id').fetchone()[0],
                    connection.execute('PRAGMA user_version').fetchone()[0],
                    sorted(row[0] for row in
                           connection.execute("SELECT name FROM sqlite_master WHERE type='table'")))

    def integrity(self, path: Path) -> str:
        """Return SQLite's own verdict on a file, without any platform code opening it."""
        with closing(sqlite3.connect(path)) as connection:
            return connection.execute('PRAGMA integrity_check').fetchone()[0]

    def count(self, path: Path, table: str) -> int:
        """Count rows of `table` with raw sqlite, so the answer cannot come from the store under test."""
        with closing(sqlite3.connect(path)) as connection:
            return connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]

    def fired(self, name: str, *, at: int | None = 1) -> tuple[Store, Path]:
        """Create a store at `<name>.db` with one firing event (incident + outbox row) at schema `at`.

        `at=1`, the default, writes the file as the released v1 build — what an operator would hand the
        migration, and the point every migration test below starts from. `at=None` means this checkout's
        own schema, for the tests that need an already-current database.
        """
        if at is None:
            store = Store(self.root / (name + '.db'))
        else:
            with self.at_v1():
                store = Store(self.root / (name + '.db'))
        window = {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)}
        store.intake(event(PRODUCER.identity, None, 'availability', 'availability', 'firing', window,
                           {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=NOW)
        return store, store.path

    def migrated(self, store: Store) -> list[dict]:
        """Return the audit rows this store holds for schema steps, newest first (`records` order)."""
        return [row for row in store.records('audit') if row['operation'] == 'schema.migrated']

    def copies(self, path: Path) -> list[Path]:
        """List the pre-migration copies that exist beside `path`, oldest name first."""
        return sorted(item for item in self.root.iterdir()
                      if item.name.startswith(path.name) and BACKUP_NAME.search(item.name))

    def platform(self, *argv: str) -> tuple[int, dict]:
        """Run the `lo-platform` entry point in process; return its exit code and the stdout JSON object."""
        buffer = io.StringIO()
        with redirect_stdout(buffer), mock.patch.object(sys, 'argv', ['lo-platform', *argv]):
            code = cli.main()
        return code, json.loads(buffer.getvalue())

    # --- creation ---------------------------------------------------------------------------

    def test_a_fresh_database_is_created_at_the_current_version_and_audits_nothing(self):
        """A new file gets `VERSION`, the whole schema and no audit rows: creation is not migration."""
        store = Store(self.root / 'fresh.db')
        app, version, tables = self.header(store.path)
        self.assertEqual((app, version), (state.APPLICATION_ID, state.VERSION))
        self.assertEqual(set(tables), CURRENT_TABLES)
        self.assertEqual(self.migrated(store), [])
        self.assertEqual(store.status()['schema_version'], state.VERSION)

    def test_a_fresh_database_applies_every_migration_in_one_step(self):
        """A build ahead of an empty file still builds it once: every script, one transaction, no audit."""
        with self.build(3, {2: PROBE_V2, 3: PROBE_V3}):
            store = Store(self.root / 'fresh-ahead.db')
        self.assertEqual(self.header(store.path)[1], 3)
        self.assertEqual(set(self.header(store.path)[2]), V1_TABLES | {'migration_probe', 'migration_probe_v3'})
        self.assertEqual(self.migrated(store), [], 'creating a database must not look like migrating one')
        self.assertEqual(self.copies(store.path), [], 'nothing existed to copy')

    def test_a_build_whose_version_and_migration_table_disagree_touches_nothing(self):
        """`VERSION == max(MIGRATIONS)` is checked before any file is opened, new or operational."""
        store, path = self.fired('disagree')
        with self.build(4, {2: PROBE_V2, 3: PROBE_V3}):
            with self.assertRaisesRegex(StateError, 'Build error'):
                Store(path)
            with self.assertRaisesRegex(StateError, 'Build error'):
                Store(self.root / 'disagree-fresh.db')
        self.assertEqual(self.header(path)[:2], (state.APPLICATION_ID, 1))
        self.assertEqual(store.status()['incidents'], {'open': 1})

    # --- refusing ---------------------------------------------------------------------------

    def test_an_older_database_is_refused_until_the_operator_asks_for_migration(self):
        """A v1 file under a v2 build names the command, and is left byte-for-byte as it was found."""
        _, path = self.fired('refuse')
        before = path.read_bytes()
        with self.build(2, {2: PROBE_V2}):
            with self.assertRaisesRegex(StateError, r'version 1; run lo-platform migrate'):
                Store(path)
            self.assertEqual(path.read_bytes(), before, 'refusing must not mean rewriting')
            self.assertEqual(self.copies(path), [], 'a refusal may not spend disk on a copy')
        self.assertEqual(self.header(path)[1], 1)
        # Read back as the release that wrote it: `status()` names the asking build's schema, so this
        # is the v1 view of the same rows, and it is the file — not the refusal — being described.
        with self.at_v1():
            self.assertEqual(Store(path).status(), {'schema_version': 1, 'incidents': {'open': 1},
                                                   'actions': {}, 'notifications': {'pending': 1}},
                             'the release that wrote it still opens it')

    def test_a_database_ahead_of_the_build_is_refused_even_when_migration_is_offered(self):
        """No silent downgrade: a newer file is refused by the same door as before, with no copy written."""
        _, path = self.fired('ahead')
        with self.build(2, {2: PROBE_V2}):
            self.assertEqual(Store(path, migrate=True).migrated_from, 1)
        self.assertEqual(self.header(path)[1], 2)
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('PRAGMA user_version=3')
            connection.commit()
        for offered in ({}, {'migrate': True}):
            with self.subTest(migrate=offered), self.assertRaisesRegex(StateError, 'restore or migrate'):
                with self.build(2, {2: PROBE_V2}):
                    Store(path, **offered)
        self.assertEqual(self.header(path)[1], 3, 'a refusal must leave the newer file alone')
        self.assertEqual(len(self.copies(path)), 1, 'only the migration that ran may write a copy')

    def test_migrating_does_not_open_the_door_to_a_database_this_platform_did_not_create(self):
        """`migrate=True` must not widen the refusal that predates it.

        Refusing a foreign database is already asserted twice — `tests/test_platform.py` points the
        store at the derived inventory index in `test_backup_and_unrelated_database`, and
        `tests/test_regression_schema_version.py` covers a file with `application_id` 0 and a table
        in it. What is new here is that the migration path is not an exception to either.
        """
        path = self.root / 'foreign.db'
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('CREATE TABLE somebody_else (id INTEGER PRIMARY KEY, note TEXT)')
            connection.execute("INSERT INTO somebody_else(note) VALUES ('not platform state')")
            connection.commit()
        with self.build(2, {2: PROBE_V2}):
            with self.assertRaisesRegex(StateError, 'restore or migrate'):
                Store(path, migrate=True)
        self.assertEqual(self.header(path), (0, 0, ['somebody_else']))
        self.assertEqual(self.count(path, 'somebody_else'), 1)

    def test_a_refused_foreign_database_is_left_byte_for_byte_as_found(self):
        """Refusal must not rewrite the file: opening a foreign SQLite database once flipped its journal
        header to WAL before the identity check ran (found in review of state migrations)."""
        path = self.root / 'foreign.db'
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('CREATE TABLE t(x)')
            connection.execute('INSERT INTO t VALUES (1)')
            connection.commit()
        before = path.read_bytes()
        with self.assertRaises(StateError):
            Store(path)
        with self.assertRaises(StateError):
            Store(path, migrate=True)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.root.iterdir() if p.name.startswith('foreign')), ['foreign.db'])

    def test_a_missing_step_in_the_migration_table_refuses_the_whole_run(self):
        """The mechanism cannot skip a version: a gap is refused before anything is copied or written.

        The gap is faked by claiming a schema whose middle step was never written: because `build`
        replaces the migration table, `{2: ..., 4: ...}` over a v1 file is genuinely missing step 3
        whatever this checkout's own `MIGRATIONS` happens to hold, so the mechanism and not the current
        version number is what is under test. Step 2 is a probe here rather than the control-table
        migration control state shipped — this file tests the mechanism,
        `tests/test_control_state_migration.py` tests that script's content.
        """
        store, path = self.fired('gap')
        with self.build(4, {2: PROBE_V2, 4: PROBE_V4}):
            with self.assertRaisesRegex(StateError, r'No migration from version 1 to 4: step \[3\] is absent'):
                Store(path, migrate=True)
        self.assertEqual(self.header(path)[:2], (state.APPLICATION_ID, 1))
        self.assertNotIn('migration_probe_v4', self.header(path)[2])
        self.assertEqual(self.copies(path), [])
        # `status()` names the schema of the build asking, not of the file, so what this proves is that
        # the refused run left the rows alone; the file's own version is the `header` assertion above.
        self.assertEqual(store.status(), {'schema_version': state.VERSION, 'incidents': {'open': 1},
                                         'actions': {}, 'notifications': {'pending': 1}})

    # --- migrating --------------------------------------------------------------------------

    def test_migrating_copies_the_database_first_and_keeps_every_row(self):
        """One step up: verified copy beside the file, new table, one audit row, state intact."""
        store, path = self.fired('migrate')
        with self.build(2, {2: PROBE_V2}):
            moved = Store(path, migrate=True)
            self.assertEqual(moved.migrated_from, 1)
            backup = moved.migration_backup
        self.assertIsNotNone(backup)
        self.assertEqual(backup.parent, path.parent, 'the copy must land beside the file it protects')
        self.assertRegex(backup.name, BACKUP_NAME)
        self.assertEqual(self.integrity(backup), 'ok')
        self.assertEqual(self.header(backup)[:2], (state.APPLICATION_ID, 1), 'the copy holds the pre-migration version')
        self.assertEqual(self.count(backup, 'events'), 1)
        self.assertEqual(self.header(path)[:2], (state.APPLICATION_ID, 2))
        self.assertIn('migration_probe', self.header(path)[2])
        rows = self.migrated(moved)
        self.assertEqual([(row['actor'], row['operation'], row['subject']) for row in rows],
                         [('platform-migrate', 'schema.migrated', '2')])
        detail = json.loads(rows[0]['detail'])
        self.assertEqual({key: detail[key] for key in ('from', 'to')}, {'from': 1, 'to': 2})
        self.assertRegex(detail['script_sha256'], re.compile(r'^[0-9a-f]{64}$'))
        self.assertEqual(moved.status(), store.status())
        self.assertEqual([row['id'] for row in moved.records('outbox')],
                         [row['id'] for row in store.records('outbox')])

    def test_a_migration_offered_to_a_current_database_reports_nothing_and_writes_nothing(self):
        """`migrate=True` on an up-to-date file is the CLI's `current` answer, not a zero-step migration."""
        store, path = self.fired('current', at=None)
        moved = Store(path, migrate=True)
        self.assertIsNone(moved.migrated_from)
        self.assertIsNone(moved.migration_backup)
        self.assertEqual(self.copies(path), [])
        self.assertEqual(self.migrated(moved), [])
        self.assertEqual(moved.status(), store.status())

    def test_a_failed_step_leaves_the_committed_one_and_the_next_run_applies_only_the_rest(self):
        """Crash between migrations: version 2 survives a broken v3, and fixing v3 continues from 2."""
        store, path = self.fired('crash')
        broken = {2: PROBE_V2, 3: 'CREATE TABLE migration_probe(x);\n'}  # v3 collides with what v2 made
        with self.build(3, broken):
            with self.assertRaisesRegex(StateError, r'stays at version 2'):
                Store(path, migrate=True)
        self.assertEqual(self.header(path)[1], 2, 'the committed step must survive the step that failed')
        self.assertIn('migration_probe', self.header(path)[2])
        self.assertNotIn('migration_probe_v3', self.header(path)[2])
        self.assertEqual(self.count(path, 'audit'), 2, 'the audit row of the failed step rolls back with it')
        with self.build(2, {2: PROBE_V2}):
            reopened = Store(path)
            self.assertEqual([row['subject'] for row in self.migrated(reopened)], ['2'])
            self.assertEqual(reopened.status(), store.status())
        with self.build(3, {2: PROBE_V2, 3: PROBE_V3}):
            moved = Store(path, migrate=True)
            self.assertEqual(moved.migrated_from, 2, 'the second run starts where the crash stopped, not at 1')
        self.assertEqual(self.header(path)[1], 3)
        self.assertEqual(sorted(row['subject'] for row in self.migrated(moved)), ['2', '3'], 'v2 is not applied twice')
        self.assertEqual([BACKUP_NAME.search(copy.name).group(1) for copy in self.copies(path)], ['1', '2'],
                         'one copy per migration that ran, each named for the version it holds')
        self.assertEqual(moved.status(), store.status())

    # --- the command ------------------------------------------------------------------------

    def test_the_cli_migrate_command_reports_current_and_migrated_in_the_same_shape(self):
        """`lo-platform migrate` prints one JSON object: `current` when there is nothing to do,
        `migrated` with the versions and the copy it wrote — and any other subcommand still refuses an
        older database rather than quietly opening it.
        """
        fresh = Store(self.root / 'cli-current.db').path
        self.assertEqual(self.platform('--database', str(fresh), 'migrate'),
                         (0, {'status': 'current', 'version': state.VERSION, 'backup': None}))
        self.assertEqual(self.copies(fresh), [])

        store, path = self.fired('cli')
        with self.build(2, {2: PROBE_V2}):
            self.assertEqual(self.platform('--database', str(path), 'status'),
                             (1, {'status': 'error', 'error_type': 'StateError'}))
            code, result = self.platform('--database', str(path), 'migrate')
            self.assertEqual(Store(path).status(), store.status(), 'the migrated file opens for the build that made it')
        self.assertEqual(code, 0)
        self.assertEqual(sorted(result), ['backup', 'from', 'status', 'to'])
        self.assertEqual((result['status'], result['from'], result['to']), ('migrated', 1, 2))
        backup = Path(result['backup'])
        self.assertTrue(backup.name.startswith(path.name + '.pre-v1-'), backup.name)
        self.assertEqual(self.integrity(backup), 'ok')


if __name__ == '__main__':
    unittest.main()

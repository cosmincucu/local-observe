"""correlation: schema v7 carries the operational database into grouping without touching a business row.

This file also covers schema v8 and v9. `MIGRATIONS[8]`  adds one index and nothing else —
`events_incident` over `events(incident_id)`, the membership pointer `Store.intake` writes — and its test
(`test_a_v7_file_gains_the_member_index_and_moves_no_row`) starts from a **v7** file for the same reason
the v6 case does: that is the file an installation is running when this build inherits it. `MIGRATIONS[9]`
 has the same shape one step later — one index, `incident_members_condition` over the
far end of the rationale table's primary key, which `suppression._absorbed_openings` reads — so its test
starts from a **v8** file and is otherwise the same four claims. The three tests whose subject is step 7
itself now run as the v7 build (`as_build(7)`, which moves `MIGRATIONS`,
`state.VERSION` and `cli.VERSION` together, the way `tests/test_escalation_history.py` rewinds to 1..6),
so every v7 assertion stays a literal 7 rather than being softened to `state.VERSION` and quietly stopped
being a test; step 8's test moves to `as_build(8)` for the identical reason (both assert "this step created
exactly one index", which a migration that ran past its own step would answer with two). The v1 chain is
deliberately **not** rewound: it travels every step this build ships, which
is the claim only the newest build can make.

`MIGRATIONS[7]` adds one table — `incident_members`, the durable reason several conditions are one incident
— plus the one index a new read needs, and no index for the read that already has one. It adds no column to
`incidents`, `conditions` or
`events`: `conditions.incident_id` is already the many-to-one pointer grouping needs (§4's identity pair),
and `tests/test_rca_progress.py` inserts seven values into `incidents` **by position**, so a column there
would be a change to a file this card does not own.

What this file exists to prove is the direction the migration mechanism was built for: an **operational**
database reaches grouping by migrating, and not one stored row changes on the way. The pre-grouping rows
are the ones the nightly copies hold, and a v1 or v6 file that could only be created at v7 would make the
upgrade an outage and the rollback a restore.

Three things are therefore asserted for every step below:

* the file lands on `VERSION` with the new table and indexes, and its *existing* rows are the same rows —
  compared column-for-column with raw sqlite, never through the store under test;
* one `schema.migrated` audit row names the step, and a verified copy sits beside the file named for the
  version it holds (`state migrations`'s promise, re-asserted for this step specifically);
* after the migration the file **groups**: a second condition on a declared neighbour joins the incident
  that survived the upgrade. That last clause is what "a v1 database must migrate, not fail open" means in
  a test, and it is the only one that would fail if the step created its table somewhere else.

The v1 and v6 starting points are built by pinning `MIGRATIONS`/`VERSION` down to that prefix — the
`tests/test_state_migration.py` and `tests/test_maintenance_history.py` convention — so the file really was
written by a build that could not have known table seven existed. No host, network or notification client
appears anywhere in this file.
"""
import ast
import contextlib
import datetime as dt
from contextlib import closing
import inspect
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest import mock
import uuid

from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import cli, correlation, rca, state, suppression
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, Store

NOW = timestamp('2026-09-10T12:00:00Z')
PRODUCER = Actor('grouping-migration-fixture', 'producer')
REVISION = 'grouping-migration-rev'
BACKUP_NAME = re.compile(r'\.pre-v(\d+)-\d{8}T\d{6}Z\.db$')
#: The one table migration 7 may create, and the one index it may create. Named so the assertion is
#: "exactly these": the mechanism that makes "only what the contract named" checkable rather than argued.
#: `incident_members` is absent from this set on purpose — the table's primary key covers the only read it
#: gets, and a second index on the same leading column would show up here as weight.
NEW_TABLES = {'incident_members'}
NEW_INDEXES = {'conditions_incident'}
#: The one object migration 8 may create, spelled as it appears in `sqlite_master`. Named here rather
#: than read from `state.EVENTS_INCIDENT_INDEX` so the assertion is about the name an operator greps for
#: and a `CREATE INDEX` that silently renamed it is a failure in this file.
MEMBER_INDEX = 'events_incident'
#: The one object migration 9 may create, spelled as it appears in `sqlite_master` and for the same
#: reason as above: the assertion is about the name an operator greps for, not about a constant that could
#: move with the `CREATE INDEX` it is meant to be checking.
CONDITION_INDEX = 'incident_members_condition'
#: The statement whose cost step 9 exists to remove, copied out of `suppression._absorbed_openings` in
#: full (bound parameters included) so the plan asserted below is the plan that read actually takes. An
#: assertion made against a simpler hand-written query would survive someone changing the real one.
ABSORBED_SQL = ('SELECT count(*) FROM (SELECT 1 FROM incident_members WHERE condition_key=?'
                ' AND julianday(at)>julianday(?) AND julianday(at)<=julianday(?) LIMIT ?)')
#: The business tables a v1 file already holds, whose rows migration 7 must leave alone. `audit` is not
#: among them: every migration appends one row to it by design, which the prefix assertion below checks.
PRESERVED = ('events', 'conditions', 'incidents', 'evidence', 'outbox', 'actions', 'executions')


def identifier(name: str) -> str:
    """A stable synthetic UUID for a synthetic name, never a real estate id."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'grouping-migration/' + name))


def absorbed_read() -> str:
    """The SQL text `suppression._absorbed_openings` executes, with its docstring stripped out.

    Every assertion about *the read* goes through this rather than raw `inspect.getsource`: the function's
    docstring discusses `INDEXED BY` and `incident_members` in prose, and prose is not the statement. The
    string constants are joined in source order with the interpolated table name left out, which is why no
    fragment asserted below spans the `{GROUPING_TABLE}` hole.
    """
    function = ast.parse(inspect.getsource(suppression._absorbed_openings)).body[0]
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    return ''.join(node.value for statement in body for node in ast.walk(statement)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str))


def declaration() -> dict:
    """Two declared neighbours joined by one `runs-on` relation, which is all grouping needs to test."""
    return {'schema_version': 1, 'resources': [
        {'id': identifier('host'), 'kind': 'host', 'name': 'host', 'aliases': [],
         'attributes': {'owner': 'team-platform'}, 'relations': []},
        {'id': identifier('api'), 'kind': 'service', 'name': 'api', 'aliases': [],
         'attributes': {'owner': 'team-api'},
         'relations': [{'type': 'runs-on', 'target': identifier('host')}]},
    ]}


class GroupingMigrationTests(unittest.TestCase):
    """An older platform file arriving at schema v7, and what it must still be able to do afterwards."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = self.root / 'inventory.db'
        index.build(declaration(), self.index_path, REVISION, now=NOW)

    # --- fixtures -----------------------------------------------------------------------------

    @contextlib.contextmanager
    def as_build(self, version: int):
        """Act as the release whose schema is `version`: the migration table truncated, the version with it.

        All three of `MIGRATIONS`, `state.VERSION` and `cli.VERSION` move together, because a real bump
        changes them in one commit — patching one alone would test a build that cannot exist.
        """
        migrations = {target: state.MIGRATIONS[target] for target in range(1, version + 1)}
        with mock.patch.object(state, 'MIGRATIONS', migrations), \
                mock.patch.object(state, 'VERSION', version), \
                mock.patch.object(cli, 'VERSION', version):
            yield

    def filing(self, rule: str, resource_id: str, *, at: dt.datetime = NOW,
               status: str = 'firing') -> dict:
        """One canonical event, so every file below starts from a real lifecycle row."""
        window = {'start': utc_text(at - dt.timedelta(minutes=1)), 'end': utc_text(at)}
        return event(PRODUCER.identity, resource_id, rule, 'availability', status, window,
                     {'rule_id': rule}, query_type='gatus-result')

    def at(self, version: int, name: str = 'state.db') -> Store:
        """Write a database as the build whose schema is `version`: one firing event, one open incident."""
        with self.as_build(version):
            store = Store(self.root / name)
            store.intake(self.filing('api.down', identifier('api')), PRODUCER, now=NOW)
        return store

    def migrate(self, name: str = 'state.db') -> Store:
        """Open the file this build would inherit, with the operator's `migrate` asked for."""
        return Store(self.root / name, migrate=True)

    def raw(self, sql: str, parameters: tuple = (), path: Path | None = None) -> list[sqlite3.Row]:
        """Read a file with raw sqlite, so no answer here comes from the store under test."""
        with closing(sqlite3.connect(path or self.root / 'state.db')) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    def objects(self, kind: str, path: Path | None = None) -> set[str]:
        """Every table or index name a file holds, SQLite's own PK autoindexes excluded.

        `sqlite_autoindex_*` is created by a PRIMARY KEY clause and is not a name this repository chose, so
        leaving it in the set below would make the assertion about *indexes written* into an assertion about
        how SQLite implements a constraint.
        """
        return {row[0] for row in self.raw(f"SELECT name FROM sqlite_master WHERE type='{kind}'", (), path)
                if not row[0].startswith('sqlite_autoindex_')}

    def rows_of(self, table: str, path: Path | None = None) -> list[tuple]:
        """Every row of `table` as tuples, in rowid order — the before/after comparison below."""
        with closing(sqlite3.connect(path or self.root / 'state.db')) as db:
            columns = [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')]
            marks = ','.join('"' + name + '"' for name in columns)
            return [tuple(row) for row in db.execute(f'SELECT {marks} FROM "{table}" ORDER BY rowid')]

    def snapshot(self, path: Path | None = None, tables: tuple[str, ...] = PRESERVED) -> dict[str, list[tuple]]:
        """The operational content of a file, as one comparable value.

        Only over tables whose columns no step between v1 and v7 moves. `DELIVERY_SCHEMA` (v3) adds columns
        to `outbox` and `notification_attempts` — a legitimate change, owned by notifications and tested by
        `tests/test_notification_attempts.py` — so the wide comparison below is a *v6* comparison, and the
        v1 chain uses the four tables that no step has ever altered plus the append-only checks.
        """
        return {table: self.rows_of(table, path) for table in tables}

    def audit_rows(self, path: Path | None = None) -> list[tuple]:
        """`audit` without its sequence, which is the only column a migration is allowed to extend."""
        with closing(sqlite3.connect(path or self.root / 'state.db')) as db:
            return [tuple(row) for row in db.execute('SELECT at,actor,operation,subject,detail FROM audit'
                                                   ' ORDER BY sequence')]

    def write(self, sql: str, parameters: tuple = ()) -> None:
        """Write the way a foreign caller would, and commit: an uncommitted row tests a rollback, not a CHECK."""
        with closing(sqlite3.connect(self.root / 'state.db')) as db:
            db.execute(sql, parameters)
            db.commit()

    def group_the_migrated(self, store: Store) -> dict:
        """File a neighbour's verdict through the grouping admission, on an upgraded file."""
        return store.intake(self.filing('host.down', identifier('host')), PRODUCER, now=NOW,
                           admission=store.grouping_admission(self.index_path, PRODUCER, now=NOW))

    # --- the shape of the step ----------------------------------------------------------------

    def test_the_schema_this_build_creates_holds_the_members_table_and_its_one_index(self):
        """The v7 shape, created by the v7 build: step 8 adds an index this assertion is not about."""
        with self.as_build(7):
            fresh = Store(self.root / 'fresh.db')
            self.assertTrue(NEW_TABLES <= self.objects('table', fresh.path))
            self.assertTrue(NEW_INDEXES <= self.objects('index', fresh.path))
            self.assertEqual(self.raw('PRAGMA user_version', (), fresh.path)[0][0], 7)
        # Unpatched on purpose: the claim is that *this* build names its own highest step, which a
        # migration table and a version patched in the same breath could never fail to satisfy.
        self.assertEqual(state.VERSION, max(state.MIGRATIONS), 'the build names its own highest step')

    def test_the_step_adds_no_column_to_any_business_row(self):
        """`incidents` stays seven columns wide, because a positional INSERT elsewhere depends on that."""
        self.at(6)
        columns = {table: [row['name'] for row in self.raw(f'PRAGMA table_info("{table}")')]
                  for table in ('incidents', 'conditions', 'events')}
        self.assertEqual(len(columns['incidents']), 7)
        self.migrate()
        for table, names in columns.items():
            with self.subTest(table=table):
                self.assertEqual([row['name'] for row in self.raw(f'PRAGMA table_info("{table}")')], names)

    def test_the_one_index_exists_because_a_read_asks_it_and_the_other_read_already_has_one(self):
        """An index nobody queries is weight, and so is a second index on a column already indexed.

        `conditions_incident` answers the per-resolution "is this the last open member?" count, which had no
        index in either direction before this step, and the view's member read. The rationale read is served
        by `incident_members`' own primary key, so this step deliberately creates **no** index for it — the
        assertion below names the index the plan chose and would fail if a redundant one were added to the
        schema or if the read degraded to a scan.
        """
        self.at(6)
        self.migrate()
        plans = {
            'SELECT count(*) FROM conditions WHERE incident_id=?': 'conditions_incident',
            'SELECT rationale FROM incident_members WHERE incident_id=?': 'sqlite_autoindex_incident_members_1',
        }
        for sql, expected in plans.items():
            with self.subTest(index=expected):
                plan = ' '.join(str(row[3]) for row in self.raw('EXPLAIN QUERY PLAN ' + sql, ('x',)))
                self.assertIn(expected, plan)

    def test_the_bound_in_the_check_is_the_number_the_writer_enforces(self):
        fresh = Store(self.root / 'bound.db')
        schema = self.raw('SELECT sql FROM sqlite_master WHERE name=?', ('incident_members',),
                         fresh.path)[0]['sql']
        self.assertIn(f'BETWEEN 1 AND {correlation.MAX_RATIONALE_CHARS}', schema)

    # --- migrating ---------------------------------------------------------------------------

    def test_a_v6_file_reaches_v7_with_every_stored_row_untouched(self):
        """The case that matters: the file an installation is running today, not an empty one.

        Migrated as the v7 build, because the assertions below are step 7's — among them "the index set
        gained exactly `conditions_incident`", which a migration that ran on to step 8 would answer with
        two indexes for reasons this test has nothing to do with. Step 8 has its own v7-starting test.
        """
        store = self.at(6)
        before, tables_before = self.snapshot(), self.objects('table')
        audit_before = self.audit_rows()
        self.assertNotIn('incident_members', tables_before)
        self.assertEqual(self.raw('PRAGMA user_version')[0][0], 6)

        with self.as_build(7):
            moved = self.migrate()
            self.assertEqual(moved.migrated_from, 6)
            self.assertEqual(self.raw('PRAGMA user_version')[0][0], 7)
            self.assertEqual(self.objects('table') - tables_before, NEW_TABLES)
            self.assertEqual(self.objects('index') - self.objects('index', moved.migration_backup),
                            NEW_INDEXES)
            self.assertEqual(self.snapshot(), before, 'migration 7 moves no business row')
            self.assertEqual(self.audit_rows()[:len(audit_before)], audit_before,
                            'and the audit table gained only its own migration row')
            rows = [row for row in moved.records('audit') if row['operation'] == 'schema.migrated']
            self.assertEqual([(row['actor'], row['subject']) for row in rows], [('platform-migrate', '7')])
            detail = json.loads(rows[0]['detail'])
            self.assertEqual((detail['from'], detail['to']), (6, 7))
            self.assertRegex(detail['script_sha256'], re.compile(r'^[0-9a-f]{64}$'))
            self.assertEqual(moved.status()['incidents'], store.status()['incidents'])

    def test_the_copy_beside_the_file_holds_the_version_it_protects(self):
        self.at(6)
        moved = self.migrate()
        backup = moved.migration_backup
        self.assertIsNotNone(backup)
        self.assertEqual(BACKUP_NAME.search(backup.name).group(1), '6')
        self.assertEqual(backup.parent, self.root)
        with closing(sqlite3.connect(backup)) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 6)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='incident_members'"
                                       ).fetchone()[0], 0)

    def test_a_v1_file_travels_the_whole_chain_and_arrives_at_grouping(self):
        """Nine steps, one audit row each, and not one v1 finding, condition or incident rewritten.

        Not rewound to the v7 build like the step-7 tests above: this is the file a very old install
        holds, and the claim it can make belongs to the newest build — every step it has ever shipped,
        applied in order, on one live-looking file.
        """
        self.at(1)
        before = self.snapshot(tables=('events', 'conditions', 'incidents', 'evidence'))
        audit_before, outbox_before = self.audit_rows(), self.rows_of('outbox')
        moved = self.migrate()
        self.assertEqual(moved.migrated_from, 1)
        self.assertEqual(self.raw('PRAGMA user_version')[0][0], state.VERSION)
        self.assertTrue(NEW_TABLES <= self.objects('table'))
        self.assertEqual(self.snapshot(tables=('events', 'conditions', 'incidents', 'evidence')), before,
                        'every v1 verdict survives every later step, byte for byte')
        self.assertEqual(self.audit_rows()[:len(audit_before)], audit_before,
                        'audit is append-only: the v1 rows are a prefix of the migrated ones')
        steps = [row['subject'] for row in moved.records('audit') if row['operation'] == 'schema.migrated']
        self.assertEqual(sorted(steps, key=int), ['2', '3', '4', '5', '6', '7', '8', '9', '10'])
        # v3 added four columns to `outbox`; the seven v1-era values a row already held must be the same
        # rows in the same order, with this build's defaults filled in beside them.
        after = self.rows_of('outbox')
        self.assertEqual([row[:len(outbox_before[0])] for row in after], outbox_before)

    def test_a_v7_file_gains_the_member_index_and_moves_no_row(self):
        """`events incident index`/step 8: one index over a column that has existed since v1, proven on a v7 file.

        Four things, in the order the v7 preamble's checklist states them. The file lands on step 8
        having gained **one** object and no table; its stored rows are the same rows, compared
        column-for-column with raw sqlite and never through the store under test; `audit` gained only its
        own step row and a verified copy of the v7 file sits beside it (`state migrations`, re-asserted for this
        step); and the index is not decoration — SQLite says so, twice: it is the only index on `events`
        (besides the one its own PRIMARY KEY implies), it covers `incident_id` alone and non-uniquely, and
        the plan for the read it was created for names it and no longer walks the table, which is the
        whole cost the step exists to remove.

        Migrated as the **v8 build**, for the same reason step 7's test rewinds to v7: "exactly one index"
        is this step's claim, and a run that continued into step 9 would answer it with two indexes for a
        reason this test has nothing to do with.
        """
        self.assertGreaterEqual(state.VERSION, 8)
        self.at(7)
        before, tables_before, indexes_before = self.snapshot(), self.objects('table'), self.objects('index')
        audit_before = self.audit_rows()
        self.assertNotIn(MEMBER_INDEX, indexes_before, 'the fixture already holds the index under test')
        self.assertEqual(self.raw('PRAGMA user_version')[0][0], 7)

        with self.as_build(8):
            moved = self.migrate()

            self.assertEqual(moved.migrated_from, 7)
            self.assertEqual(self.raw('PRAGMA user_version')[0][0], 8)
            self.assertEqual(self.objects('table'), tables_before, 'an index arrives with no new table')
            self.assertEqual(self.objects('index') - indexes_before, {MEMBER_INDEX},
                            'and with exactly one index, the one the contract names')
            self.assertEqual(self.snapshot(), before, 'migration 8 moves no business row')
            self.assertEqual(self.audit_rows()[:len(audit_before)], audit_before,
                            'and the audit table gained only its own migration row')
            rows = [row for row in moved.records('audit') if row['operation'] == 'schema.migrated']
            self.assertEqual([(row['actor'], row['subject']) for row in rows], [('platform-migrate', '8')])
            detail = json.loads(rows[0]['detail'])
            self.assertEqual((detail['from'], detail['to']), (7, 8))
            self.assertEqual(BACKUP_NAME.search(moved.migration_backup.name).group(1), '7')
            with closing(sqlite3.connect(moved.migration_backup)) as db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 7)
                self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name='events_incident'"
                                           ).fetchone()[0], 0, 'the copy is the file before the index')

        # What the created object actually is: one column, non-unique, the only hand-written index on the
        # table. Uniqueness would be a wrong promise (one incident owns many events) and a second index on
        # the same leading column is the weight step 7's test refuses from the other side.
        on_events = [row['name'] for row in self.raw("SELECT name FROM sqlite_master"
                                                    " WHERE type='index' AND tbl_name='events'")
                     if not row['name'].startswith('sqlite_autoindex_')]
        self.assertEqual(on_events, [MEMBER_INDEX])
        self.assertEqual([row['name'] for row in self.raw(f'PRAGMA index_info("{MEMBER_INDEX}")')],
                        ['incident_id'], 'the index is over the membership pointer and nothing else')
        self.assertEqual([row['unique'] for row in self.raw("PRAGMA index_list('events')")
                          if row['name'] == MEMBER_INDEX], [0], 'an incident owns many events')

        # And the plan, read off SQLite rather than asserted about it. Both halves: it names the index, and
        # it contains no scan of `events`, because a plan that seeks *and* scans is a plan that still pays.
        plan = ' '.join(str(row[3]) for row in self.raw('EXPLAIN QUERY PLAN ' + rca.MEMBER_SQL,
                                                       ('x', rca.MAX_MEMBER_ROWS + 1)))
        self.assertIn(f'USING INDEX {MEMBER_INDEX} (incident_id=?)', plan)
        self.assertNotIn('SCAN events', plan, 'a read that still walks the table did not get its index')

    def test_a_v8_file_gains_the_condition_index_and_moves_no_row(self):
        """`correlation followups 2`/step 9: one index over the far end of a key that has existed since step 7, on a v8 file.

        The same four claims as step 8, and the reason they are repeated rather than folded into a shared
        helper is that a shared helper is how "this step moved no row" stops being a claim about *this*
        step. Two things are specific to nine. The index is over `condition_key` — the second column of
        `incident_members`' own primary key, which is why the autoindex could not serve it and why the
        step 7 test asserted no index arrived on that table from the other side: a key on
        `(incident_id, condition_key)` answers reads **by incident**, and `suppression._absorbed_openings`
        asks by condition. And the plan is asserted against the statement that read actually runs, copied
        in full above rather than rewritten in a friendlier shape, with the copy itself pinned against the
        source of the function so the two cannot drift apart silently.
        """
        self.at(8)
        before, tables_before, indexes_before = self.snapshot(), self.objects('table'), self.objects('index')
        audit_before = self.audit_rows()
        self.assertNotIn(CONDITION_INDEX, indexes_before, 'the fixture already holds the index under test')
        self.assertIn(MEMBER_INDEX, indexes_before, 'the file an install runs today has step 8 in it')
        self.assertEqual(self.raw('PRAGMA user_version')[0][0], 8)

        with self.as_build(9):
            moved = self.migrate()
            rows = [row for row in moved.records('audit') if row['operation'] == 'schema.migrated']

        self.assertEqual(moved.migrated_from, 8)
        self.assertEqual(self.raw('PRAGMA user_version')[0][0], 9)
        self.assertEqual(self.objects('table'), tables_before, 'an index arrives with no new table')
        self.assertEqual(self.objects('index') - indexes_before, {CONDITION_INDEX},
                        'and with exactly one index, the one the contract names')
        self.assertEqual(self.snapshot(), before, 'migration 9 moves no business row')
        self.assertEqual(self.audit_rows()[:len(audit_before)], audit_before,
                        'and the audit table gained only its own migration row')
        self.assertEqual([(row['actor'], row['subject']) for row in rows], [('platform-migrate', '9')])
        detail = json.loads(rows[0]['detail'])
        self.assertEqual((detail['from'], detail['to']), (8, 9))
        self.assertEqual(BACKUP_NAME.search(moved.migration_backup.name).group(1), '8')
        with closing(sqlite3.connect(moved.migration_backup)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 8)
            self.assertEqual(db.execute("SELECT count(*) FROM sqlite_master WHERE name=?",
                                       (CONDITION_INDEX,)).fetchone()[0], 0,
                            'the copy is the file before the index')

        # The object itself: one column, non-unique (one condition is linked into many groups over the
        # life of the file), and the only hand-written index on the table step 7 left without one.
        on_members = [row['name'] for row in self.raw("SELECT name FROM sqlite_master"
                                                     " WHERE type='index' AND tbl_name='incident_members'")
                      if not row['name'].startswith('sqlite_autoindex_')]
        self.assertEqual(on_members, [CONDITION_INDEX])
        self.assertEqual([row['name'] for row in self.raw(f'PRAGMA index_info("{CONDITION_INDEX}")')],
                        ['condition_key'], 'the index is over the condition and nothing else')
        self.assertEqual([row['unique'] for row in self.raw("PRAGMA index_list('incident_members')")
                          if row['name'] == CONDITION_INDEX], [0], 'one condition joins many groups')

        # And the plan, twice: the copy above really is the statement the read runs, and that statement now
        # seeks rather than walks the table. A plan that seeks *and* scans is a plan that still pays, so
        # the scan half is asserted against this table by name — the co-routine the `LIMIT` subquery
        # produces is scanned over, and that is a scan of a bounded handful of matched rows.
        read = absorbed_read()
        for fragment in ('SELECT count(*) FROM (', 'WHERE condition_key=?', 'julianday(at)>julianday(?)',
                        'julianday(at)<=julianday(?)', 'LIMIT ?)'):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, read,
                            'the read this index was built for has changed shape; so must this fixture')
        plan = ' '.join(str(row[3]) for row in self.raw('EXPLAIN QUERY PLAN ' + ABSORBED_SQL,
                                                       ('x', '2026-01-01T00:00:00Z',
                                                        '2026-01-02T00:00:00Z', 65)))
        self.assertIn(f'USING INDEX {CONDITION_INDEX} (condition_key=?)', plan)
        self.assertNotIn('SCAN incident_members', plan,
                        'a read that still walks the link table did not get its index')

    def test_the_condition_index_is_not_named_by_the_read_it_serves(self):
        """`INDEXED BY` is refused on this read, and the refusal is the point rather than an omission.

        `_absorbed_openings` answers a file with no link table at all with **zero** (`_grouping_present`),
        which is the honest floor the flap count is allowed to quote. Naming the index would replace a
        pre-v9 file's correct zero with an SQLite error whose wording the caller cannot tell apart from "the
        database could not be opened", and that error would roll back the admission it was filed inside.
        The same choice step 8 made for the member read, asserted rather than argued — over the SQL the
        function executes and not over its prose, because that docstring names `INDEXED BY` precisely to
        say it is absent.
        """
        read = absorbed_read()
        self.assertNotIn('INDEXED BY', read)
        self.assertIn('condition_key=?', read, 'the read under assertion is the one the index serves')

    def test_a_pre_grouping_file_refuses_to_open_until_the_operator_asks(self):
        self.at(6)
        with self.assertRaisesRegex(state.StateError, 'version 6; run lo-platform migrate'):
            Store(self.root / 'state.db')
        self.assertEqual(self.raw('PRAGMA user_version')[0][0], 6, 'refusing must not rewrite')
        self.assertNotIn('incident_members', self.objects('table'))

    # --- what a migrated file must be able to do ----------------------------------------------

    def test_a_migrated_file_groups_the_way_a_new_one_does(self):
        """`api.down` opened its incident under the older build and knows nothing about groups.

        `host.down` arrives under this one and must land on that same incident instead of opening a second
        one — which is the only test in the suite that proves the new table is *usable* after a migration
        rather than merely present in `sqlite_master`.
        """
        for source in (1, 6):
            with self.subTest(from_version=source):
                for item in list(self.root.iterdir()):
                    if item.name != 'inventory.db':
                        item.unlink()
                self.at(source)
                moved = self.migrate()
                outcome = self.group_the_migrated(moved)
                anchor = self.raw('SELECT id FROM incidents')[0][0]
                self.assertEqual(outcome['incident_id'], anchor,
                                'the new condition joined the incident that survived the migration')
                self.assertEqual(self.raw('SELECT count(*) FROM incidents')[0][0], 1)
                stored = self.raw('SELECT rationale FROM incident_members')[0][0]
                self.assertIn('runs-on', stored, 'and the why came with it')
                self.assertLessEqual(len(stored), correlation.MAX_RATIONALE_CHARS)

    def test_a_migrated_file_still_resolves_an_ordinary_incident_as_it_always_did(self):
        """The pre-grouping shape is the new rule's no-member case, asserted on an upgraded file."""
        self.at(1)
        moved = self.migrate()
        at = NOW + dt.timedelta(minutes=2)
        outcome = moved.intake(self.filing('api.down', identifier('api'), at=at, status='resolved'),
                              PRODUCER, now=at)
        self.assertEqual(outcome['transition'], 'resolved')
        self.assertEqual(self.raw('SELECT status FROM incidents')[0][0], 'resolved')
        self.assertEqual(self.raw('SELECT incident_id FROM conditions')[0][0], None)

    def test_a_migrated_table_refuses_an_over_wide_rationale_as_a_fresh_one_would(self):
        """One `CREATE` text serves creation and migration alike, CHECK included."""
        self.at(1)
        self.migrate()
        fresh = Store(self.root / 'fresh-compare.db')
        self.assertEqual(self.raw('SELECT sql FROM sqlite_master WHERE name=?', ('incident_members',)),
                        self.raw('SELECT sql FROM sqlite_master WHERE name=?', ('incident_members',),
                                fresh.path))
        incident = self.raw('SELECT id FROM incidents')[0][0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.write('INSERT INTO incident_members(incident_id,condition_key,rationale,at)'
                      ' VALUES (?,?,?,?)',
                      (incident, 'key-wide', 'x' * (correlation.MAX_RATIONALE_CHARS + 1), utc_text(NOW)))
        self.write('INSERT INTO incident_members(incident_id,condition_key,rationale,at) VALUES (?,?,?,?)',
                  (incident, 'key-narrow', '{"kind":"temporal"}', utc_text(NOW)))
        self.assertEqual(self.raw('SELECT count(*) FROM incident_members')[0][0], 1,
                        'width is a property of the file; JSON validity is a property of the reader')


if __name__ == '__main__':
    unittest.main()

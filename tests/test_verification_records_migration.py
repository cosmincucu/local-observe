"""Wave 6 : schema v4, the two verification tables, and the file that gets there.

`state.MIGRATIONS[4]` creates `verification_bindings` and `verification_records` in **one** step, and
this file is the evidence that the step is what the contract says it is: both tables or neither, foreign
keys, one unique binding per action, one unique logical record id, an index for the execution lookup, and
append-only `UPDATE`/`DELETE` triggers on both. Migrations 1..3 are not touched, no historical action is
backfilled, and the whole thing runs on the existing `migrate=True` machinery (verified copy first, one
audited transaction per step) rather than on a new one.

`as_v3()` creates a file using migrations 1..3, then copies public-path lifecycle rows into its actual
tables and columns. Later schema objects never enter that fixture. `at_v3()` and `at_v4()` select the
released migration scripts and versions, so the v3->v4 step is also tested independently of newer steps.

What is asserted about the new tables is their **shape as behaviour**, not their columns: the contract
names the constraints and the triggers, not the schema text, so the tests ask SQLite to violate each rule
and require that it refuse. Column names, index names and trigger names are deliberately not pinned.

Every database here is a temporary file. No live state, no network, no shell.
"""
import datetime as dt
from contextlib import closing, contextmanager, redirect_stdout
import io
import json
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import cli, detections, state
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store
from local_observe.platform.verification_records import VerificationPolicy
from local_observe.store import client as facade
from local_observe.store.client import MetricSample, Window

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
TERMINAL = NOW + dt.timedelta(minutes=5)
RECORD_NOW = NOW + dt.timedelta(minutes=20)
EXPIRES = utc_text(NOW + dt.timedelta(hours=1))
DETECTOR = 'threshold-detector'
RULE = 'inspect.cpu'
RULE_VERSION = '3'
SERIES = 'lo_cpu'
PIN = 'a' * 64
WINDOW_SECONDS = 300
PRODUCER = Actor(DETECTOR, 'producer')
VERIFIER = Actor('verify-worker', 'producer')
HUMAN = Actor('operator', 'human')
AGENT = Actor('agent-1', 'proposer')
RUNNER = Actor('runner-1', 'executor')
READER = Actor('reader-1', 'reader')
BACKUP_NAME = re.compile(r'\.pre-v(\d+)-\d{8}T\d{6}Z\.db$')
# The tables the released v1 build wrote, and the tables v2/v3 added: what a v3 file holds.
V1_TABLES = {'actions', 'audit', 'conditions', 'events', 'evidence', 'executions', 'incidents',
             'notification_attempts', 'outbox', 'sqlite_sequence'}
V3_TABLES = V1_TABLES | {'notification_control', 'notification_reservations',
                         'notification_suppressions'}
NEW_TABLES = frozenset({'verification_bindings', 'verification_records'})


class VerificationSchemaFixture(unittest.TestCase):
    """A v3 database with real lifecycle rows in it, and the tools to carry it to this build's schema."""

    def setUp(self) -> None:
        """Open a scratch directory plus the inventory index the reviewed action policy reads."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        for resource in declared['resources']:
            resource['attributes']['remediation_enabled'] = True
        self.inventory = self.root / 'inventory.db'
        index.build(declared, self.inventory, 'fixture', now=NOW)
        self.gate = action_policy(self.inventory, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})

    # --- acting as an older build -------------------------------------------------------------

    @contextmanager
    def at_v3(self):
        """Act as the released build whose schema is 3: the migrations it shipped and no newer step.

        `MIGRATIONS`, `state.VERSION` and `cli.VERSION` move together because a real release bumps all
        three in one commit; the mapping is replaced rather than trimmed so the v3 build owns exactly the
        scripts it shipped and the new step does not exist for it at all.
        """
        migrations = {target: state.MIGRATIONS[target] for target in (1, 2, 3)}
        with mock.patch.object(state, 'MIGRATIONS', migrations), \
                mock.patch.object(state, 'VERSION', 3), mock.patch.object(cli, 'VERSION', 3):
            yield

    @contextmanager
    def at_v4(self):
        """Act as the released build whose schema is 4: the migrations it shipped and no newer step.

        The step this file freezes is v3 -> v4, and a checkout one schema newer has to run it the way that
        release ran it — one transaction, one copy, one audit row — which needs `MIGRATIONS`, `VERSION`
        and `cli.VERSION` naming 4 together. `tests/test_maintenance_history.py` builds a v4 file the same
        way and hands it to the step this checkout added.
        """
        migrations = {target: state.MIGRATIONS[target] for target in (1, 2, 3, 4)}
        with mock.patch.object(state, 'MIGRATIONS', migrations), \
                mock.patch.object(state, 'VERSION', 4), mock.patch.object(cli, 'VERSION', 4):
            yield

    def as_v3(self, store: Store) -> Path:
        """Copy real lifecycle rows into the tables and columns created by migrations 1..3."""
        v3 = store.path.with_name(store.path.stem + '.v3' + store.path.suffix)
        with self.at_v3():
            Store(v3)
        with closing(sqlite3.connect(store.path)) as source, closing(sqlite3.connect(v3)) as db:
            self.assertEqual({row[0] for row in
                              db.execute("SELECT name FROM sqlite_master WHERE type='table'")},
                             V3_TABLES, 'a v3 file holds the v3 tables and nothing else')
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 3)
            with db:
                for table in sorted(V3_TABLES - {'sqlite_sequence'}):
                    columns = ','.join('"' + row[1].replace('"', '""') + '"'
                                       for row in db.execute(f'PRAGMA table_info("{table}")'))
                    rows = source.execute(f'SELECT {columns} FROM "{table}" ORDER BY rowid').fetchall()
                    placeholders = ','.join('?' for _ in db.execute(f'PRAGMA table_info("{table}")'))
                    db.executemany(f'INSERT INTO "{table}" ({columns}) VALUES ({placeholders})', rows)
                    self.assertEqual(db.execute(f'SELECT {columns} FROM "{table}" ORDER BY rowid')
                                     .fetchall(), rows, f'Historical fixture changed {table} rows')
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
        return v3

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

    def rows(self, store: Store, table: str) -> list[list]:
        """Every row of one table with raw sqlite, so the answer cannot come from the store under test."""
        with closing(sqlite3.connect(store.path)) as db:
            return [list(row) for row in db.execute(f'SELECT * FROM {table} ORDER BY rowid')]

    def count(self, store: Store, sql: str, parameters: tuple = ()) -> int:
        """Return the single number one count query answers, read with raw sqlite."""
        with closing(sqlite3.connect(store.path)) as db:
            return db.execute(sql, parameters).fetchone()[0]

    def shape(self, store: Store, table: str) -> list[tuple]:
        """The column list of one table as SQLite sees it: name, type and the NOT NULL/PK flags."""
        with closing(sqlite3.connect(store.path)) as db:
            return [(row[1], row[2], row[3], row[5]) for row in db.execute(f'PRAGMA table_info({table})')]

    def migrated(self, store: Store) -> list[dict]:
        """The audit rows this store holds for schema steps, oldest first."""
        return [row for row in reversed(store.records('audit', 100))
                if row['operation'] == 'schema.migrated']

    def copies(self, path: Path) -> list[Path]:
        """The pre-migration copies beside `path`, oldest name first."""
        return sorted(item for item in self.root.iterdir()
                      if item.name.startswith(path.name) and BACKUP_NAME.search(item.name))

    def refused_by_sql(self, store: Store, statement: str) -> None:
        """Run one raw statement and require SQLite itself to refuse it.

        Used for the append-only boundaries: the trigger lives in the file, so the assertion is made on a
        connection the store does not own. Any constraint-violation class counts (`RAISE(ABORT)` from a
        trigger arrives as an `IntegrityError`); a statement that simply succeeds does not.
        """
        with closing(sqlite3.connect(store.path)) as db:
            with self.assertRaises(sqlite3.DatabaseError):
                db.execute(statement)
            db.rollback()

    def refuse_rewrite(self, store: Store, table: str) -> None:
        """Attempt the two rewrites an append-only table must refuse, by name-free SQL.

        The column is read from `PRAGMA table_info` rather than named, because the contract freezes the
        constraints and the triggers and not the column spelling: `UPDATE … SET first = first` still
        updates a row, which is all a `BEFORE UPDATE` trigger needs in order to fire.
        """
        with closing(sqlite3.connect(store.path)) as db:
            column = db.execute(f'PRAGMA table_info({table})').fetchall()[0][1]
        self.refused_by_sql(store, f'UPDATE {table} SET {column} = {column} WHERE 1=1')
        self.refused_by_sql(store, f'DELETE FROM {table}')

    def platform(self, *argv: str) -> tuple[int, dict]:
        """Run the `lo-platform` entry point in process; return its exit code and the stdout JSON object."""
        buffer = io.StringIO()
        with redirect_stdout(buffer), mock.patch.object(sys, 'argv', ['lo-platform', *argv]):
            code = cli.main()
        return code, json.loads(buffer.getvalue())

    # --- the scenario, run for real -----------------------------------------------------------

    def policy(self, **changes) -> VerificationPolicy:
        fields = {'source': DETECTOR, 'rule_id': RULE, 'rule_version': RULE_VERSION, 'condition': RULE,
                  'resource_id': self.host, 'query_type': 'metric-threshold',
                  'parameters': {'resource_id': self.host, 'rule_id': RULE, 'artifact_sha256': PIN},
                  'metric_name': SERIES, 'threshold': 90.0, 'comparison': 'lt',
                  'window_seconds': WINDOW_SECONDS, 'artifact_sha256': PIN}
        fields.update(changes)
        return VerificationPolicy({'schema_version': 1, 'verifiers': [VERIFIER.identity],
                                   'mappings': [fields]})

    def fired(self, store: Store, *, minute=0, status='firing') -> dict:
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        return store.intake(detections.event(DETECTOR, self.host, RULE, 'threshold', status, window,
                                             {'resource_id': self.host, 'rule_id': RULE,
                                              'artifact_sha256': PIN},
                                             query_type='metric-threshold', version=RULE_VERSION),
                            PRODUCER, now=end)

    def verified(self, store: Store, *, retry_key='once') -> dict:
        """Take one store from nothing to a bound action, a terminal execution and one stored statement.

        Everything is written through the public methods, so the rows the immutability tests attack are
        rows the platform itself made.
        """
        event = self.fired(store)
        action_id = store.propose_action(
            {'retry_key': retry_key, 'incident_id': event['incident_id'], 'action': 'inspect',
             'version': '1', 'targets': [self.host], 'parameters': {}, 'evidence': [event['event_id']],
             'expires_at': EXPIRES}, AGENT, self.gate, now=NOW)['action_id']
        store.decide(action_id, 'approved', HUMAN, now=NOW)
        claim = store.claim_action(action_id, RUNNER, self.gate, now=TERMINAL - dt.timedelta(minutes=1))
        store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'],
                                now=TERMINAL)
        binding = store.get_verification_binding(action_id, READER)
        window = {'start': utc_text(TERMINAL + dt.timedelta(seconds=60)),
                  'end': utc_text(TERMINAL + dt.timedelta(seconds=360))}
        rows = [MetricSample(name=SERIES, value=70.0, resource_id=self.host,
                             labels={'resource_id': self.host}, timestamp=window['start'])]
        receipt = facade.build_outcome(facade.QUERY_KINDS['metric-threshold'],
                                       {'resource_id': self.host, 'rule_id': RULE,
                                        'artifact_sha256': PIN},
                                       Window(start=window['start'], end=window['end']),
                                       rows).receipt.as_dict()
        answer = store.put_verification({'execution_id': claim['execution_id'],
                                         'binding_id': binding['binding_id'], 'window': window,
                                         'outcome': 'available', 'receipt': receipt,
                                         'samples': [{'resource_id': self.host, 'metric_name': SERIES,
                                                      'observed_at': window['start'], 'value': 70.0}]},
                                        VERIFIER, now=RECORD_NOW)
        return {'action_id': action_id, 'binding': binding, 'execution_id': claim['execution_id'],
                'verification_id': answer['verification_id']}

    def populated(self, name: str, *, policy=None) -> tuple[Store, Path]:
        """A current-schema store holding an event, an incident, an action, an execution and the audit rows."""
        store = Store(self.root / (name + '.db'), verification_policy=policy)
        self.fired(store)
        event = store.records('events', 10)[0]
        action_id = store.propose_action(
            {'retry_key': 'history', 'incident_id': event['incident_id'], 'action': 'inspect',
             'version': '1', 'targets': [self.host], 'parameters': {}, 'evidence': [event['id']],
             'expires_at': EXPIRES}, AGENT, self.gate, now=NOW)['action_id']
        store.decide(action_id, 'approved', HUMAN, now=NOW)
        claim = store.claim_action(action_id, RUNNER, self.gate, now=TERMINAL - dt.timedelta(minutes=1))
        store.execution_outcome(claim['execution_id'], 'failed', RUNNER, claim['runner_token'],
                                now=TERMINAL)
        return store, store.path


class VerificationMigrationTests(VerificationSchemaFixture):
    """What the v4 step must do, and everything it must refuse to do on the way."""

    def test_a_fresh_database_gets_both_tables_and_neither_may_be_rewritten(self):
        """Creation applies the same step, so a new file carries the same boundaries as a migrated one.

        The rows are written through the public API first: a trigger only fires on a statement that
        touches a row, so an emptiness check would prove nothing. The constraint half is read from SQLite
        (unique indexes, foreign keys, one index at all) because the contract names those properties and
        not the column or index spelling that delivers them.
        """
        store = Store(self.root / 'fresh.db', verification_policy=self.policy())
        _, version, tables = self.header(store.path)
        self.assertEqual(version, state.VERSION)
        self.assertTrue(NEW_TABLES <= set(tables), 'this step contributed its two tables')
        # The step stays frozen at what it was without freezing the *build* at it: as the release whose
        # schema is 4, a fresh file is exactly the v3 tables plus these two, at version 4. What this
        # checkout adds on top (schema v5's index over the control documents) reaches no table, which is
        # why the set above is the same on both sides and the version named above is not.
        with self.at_v4():
            v4 = Store(self.root / 'fresh-v4.db')
        self.assertEqual(self.header(v4.path)[1], 4, 'a v4 build stops at v4')
        self.assertEqual(set(self.header(v4.path)[2]), V3_TABLES | NEW_TABLES,
                         'the v3 -> v4 step is exactly these two tables')
        self.assertEqual(self.migrated(store), [], 'creation is not migration')
        self.verified(store)
        for table in sorted(NEW_TABLES):
            self.refuse_rewrite(store, table)
            with closing(sqlite3.connect(store.path)) as db:
                self.assertTrue(db.execute(f'PRAGMA foreign_key_list({table})').fetchall(),
                                f'{table} has no foreign key')
                indexes = db.execute(f'PRAGMA index_list({table})').fetchall()
                self.assertTrue(indexes, f'{table} has no index at all')
                self.assertTrue([row for row in indexes if row[2] == 1],
                                f'{table} has no unique constraint')
        self.assertEqual(self.count(store, 'SELECT count(*) FROM verification_records'), 1,
                         'a refused rewrite may not cost a stored statement')

    def test_a_version_three_database_is_refused_until_the_operator_asks_for_migration(self):
        """Opt-in stays opt-in: the refusal is byte-for-byte and writes no copy."""
        store, path = self.populated('refusal')
        v3 = self.as_v3(store)
        before = v3.read_bytes()
        with self.assertRaisesRegex(StateError, r'version 3; run lo-platform migrate'):
            Store(v3)
        self.assertEqual(v3.read_bytes(), before, 'refusing must not mean rewriting')
        self.assertEqual(self.copies(v3), [], 'a refusal may not spend disk on a copy')
        self.assertEqual(self.header(v3)[1], 3)
        with self.at_v3():
            reopened = Store(v3).status()
        self.assertEqual({key: value for key, value in reopened.items() if key != 'schema_version'},
                         {key: value for key, value in store.status().items()
                          if key != 'schema_version'}, 'the release that wrote it still reads it')
        self.assertEqual(reopened['schema_version'], 3, '`status` names the asking build, not the file')

    def test_migrating_adds_both_tables_and_keeps_every_row_that_was_there(self):
        """One step, one copy, one audit row, same state — then the new tables are usable and inert.

        The step runs as the release that shipped it ran it (`at_v4`), because this checkout is one schema
        newer and migrating a v3 file here would run **two** transactions: the copy, the audit-row count
        and the header would then describe the pair rather than the single step this contract freezes. The
        tail is the newer step, named as its own audited transaction.
        """
        store, path = self.populated('migrate')
        events, actions, executions = (self.rows(store, 'events'), self.rows(store, 'actions'),
                                       self.rows(store, 'executions'))
        history = self.rows(store, 'audit')
        v3 = self.as_v3(store)
        with self.at_v4():
            # `status()` names the asking build, so both halves of that comparison are taken as v4.
            before = store.status()
            moved = Store(v3, verification_policy=self.policy(), migrate=True)
            self.assertEqual(moved.migrated_from, 3)
            self.assertEqual(self.header(v3)[1], state.VERSION, 'the v4 build stops at the step it shipped')
            self.assertEqual(set(self.header(v3)[2]), V3_TABLES | NEW_TABLES)
            backup = moved.migration_backup
            self.assertIsNotNone(backup)
            self.assertEqual(backup.parent, path.parent, 'the copy must land beside the file it protects')
            self.assertRegex(backup.name, BACKUP_NAME)
            self.assertEqual(self.integrity(backup), 'ok')
            self.assertEqual(self.header(backup)[1], 3, 'the copy holds the pre-migration version')
            self.assertEqual([row['subject'] for row in self.migrated(moved)], [str(state.VERSION)])
            detail = json.loads(self.migrated(moved)[0]['detail'])
            self.assertEqual({key: detail[key] for key in ('from', 'to')}, {'from': 3,
                                                                           'to': state.VERSION})
            self.assertEqual(detail['script_sha256'], state.digest(state.VERIFICATION_SCHEMA),
                             'the audited row names the script that ran')
            self.assertEqual(len(self.migrated(moved)), 1, 'one step, one audited transaction')
            self.assertEqual(moved.status(), before)
            self.assertEqual(self.rows(moved, 'events'), events)
            self.assertEqual(self.rows(moved, 'actions'), actions)
            self.assertEqual(self.rows(moved, 'executions'), executions)
            self.assertEqual(self.rows(moved, 'audit')[:len(history)], history,
                             'the audit log is carried, not rewritten')
            self.assertEqual(len(self.rows(moved, 'audit')), len(history) + 1)

            written = self.verified(moved)
            self.assertEqual(moved.get_verification(written['verification_id'], READER)['verdict'], 'cleared')
            self.assertEqual(moved.get_verification_binding(written['action_id'],
                                                          READER)['status'], 'bound')
            reopen = Store(v3, verification_policy=self.policy())
            self.assertEqual(reopen.get_verification(written['verification_id'], HUMAN),
                             moved.get_verification(written['verification_id'], HUMAN))
            destination = self.root / 'restored.db'
            reopen.backup(destination)
            restored = Store(destination, verification_policy=self.policy())
            self.assertEqual(restored.get_verification(written['verification_id'], HUMAN),
                             reopen.get_verification(written['verification_id'], HUMAN),
                             'a restored copy reads the same immutable statement')
            self.assertEqual(self.integrity(destination), 'ok')
        # Snapshot after the v4 verification scenario: its public writes belong to the preserved state.
        v4_rows = {table: self.rows(moved, table)
                   for table in V3_TABLES | NEW_TABLES if table != 'sqlite_sequence'}
        moved = Store(v3, verification_policy=self.policy(), migrate=True)
        self.assertEqual(moved.migrated_from, 4)
        self.assertEqual(self.header(v3)[1], state.VERSION)
        self.assertEqual([row['subject'] for row in self.migrated(moved)],
                         [str(version) for version in range(4, state.VERSION + 1)],
                         'one audited transaction per step, in order')
        after = self.rows(moved, 'audit')
        self.assertEqual(after[:len(v4_rows['audit'])], v4_rows['audit'])
        self.assertEqual(len(after), len(v4_rows['audit']) + state.VERSION - 4)
        for table, rows in v4_rows.items():
            if table != 'audit':
                self.assertEqual(self.rows(moved, table), rows, f'The newer steps changed {table}')
        self.assertEqual(moved.get_verification(written['verification_id'],
                                               READER)['verdict'], 'cleared')
        self.assertEqual(len(self.copies(v3)), 2, 'one verified copy per migration that ran')

    def test_the_migration_backfills_no_binding_for_history(self):
        """Actions that proposed before the table existed stay `not-captured`, and the table stays empty.

        `verification_bindings` arriving with zero rows is the whole point: a binding is provenance the
        platform witnessed, and synthesising one from today's policy for a yesterday's action would put
        a reviewed numeric meaning behind a decision that was made without one. The positive control is
        in the same file — a NEW proposal after the migration does write a row.
        """
        store, _ = self.populated('no-backfill')
        v3 = self.as_v3(store)
        moved = Store(v3, verification_policy=self.policy(), migrate=True)
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_bindings'), 0)
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_records'), 0)
        historic = moved.records('actions', 10)[0]['id']
        binding = moved.get_verification_binding(historic, READER)
        self.assertEqual((binding['status'], binding['reason']), ('unbound', 'not-captured'))
        self.assertIsNone(binding['binding_id'])
        event = self.fired(moved, minute=1)
        action_id = moved.propose_action(
            {'retry_key': 'after-migration', 'incident_id': event['incident_id'], 'action': 'inspect',
             'version': '1', 'targets': [self.host], 'parameters': {}, 'evidence': [event['event_id']],
             'expires_at': EXPIRES}, AGENT, self.gate, now=NOW)['action_id']
        self.assertEqual(moved.get_verification_binding(action_id, READER)['status'], 'bound')
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_bindings'), 1,
                         'the empty table above was absence, not a broken write path')

    def test_both_new_tables_refuse_sql_level_rewrites_on_a_migrated_file(self):
        """The append-only boundary is in the file, so it holds for a reader holding only sqlite3."""
        store, _ = self.populated('append-only')
        v3 = self.as_v3(store)
        moved = Store(v3, verification_policy=self.policy(), migrate=True)
        written = self.verified(moved)
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_records'), 1)
        for table in ('verification_records', 'verification_bindings'):
            with self.subTest(table=table):
                self.refuse_rewrite(moved, table)
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_records'), 1)
        self.assertEqual(moved.get_verification(written['verification_id'], READER)['verdict'], 'cleared')
        reopen = Store(v3, verification_policy=self.policy())
        self.assertEqual(self.count(reopen, 'SELECT count(*) FROM verification_records'), 1,
                         'a refused rewrite may not cost a stored statement')

    def test_one_binding_per_action_and_one_record_per_logical_id_survive_the_migration(self):
        """Two checks on one action share one binding, and a replay adds no row anywhere.

        The unique constraints themselves are asserted against SQLite in the fresh-database test; what is
        asserted here is their meaning through the public surface after a migration: one binding row per
        action however many statements arrive for it, one record row per logical id however many
        credentials submit it, and both counts unchanged by a reopen — which is the difference between a
        stored identity and one re-derived per connection.
        """
        store, _ = self.populated('unique')
        v3 = self.as_v3(store)
        moved = Store(v3, verification_policy=self.policy(), migrate=True)
        written = self.verified(moved)
        answer = moved.put_verification({
            'execution_id': written['execution_id'], 'binding_id': written['binding']['binding_id'],
            'window': {'start': utc_text(TERMINAL + dt.timedelta(seconds=400)),
                       'end': utc_text(TERMINAL + dt.timedelta(seconds=700))},
            'outcome': 'unavailable', 'receipt': None, 'samples': []}, VERIFIER, now=RECORD_NOW)
        self.assertIs(answer['created'], True, 'a later window is a separate check')
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_bindings'), 1,
                         'two checks on one action still share one binding')
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_records'), 2)
        replay = moved.put_verification({
            'execution_id': written['execution_id'], 'binding_id': written['binding']['binding_id'],
            'window': {'start': utc_text(TERMINAL + dt.timedelta(seconds=400)),
                       'end': utc_text(TERMINAL + dt.timedelta(seconds=700))},
            'outcome': 'unavailable', 'receipt': None, 'samples': []}, VERIFIER, now=RECORD_NOW)
        self.assertEqual(replay, {**answer, 'created': False})
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_records'), 2)
        self.assertEqual(self.count(moved, 'SELECT count(*) FROM verification_bindings'), 1,
                         'a replay may not add a row anywhere')
        reopened = Store(v3, verification_policy=self.policy())
        self.assertEqual(self.count(reopened, 'SELECT count(*) FROM verification_bindings'), 1)
        self.assertEqual(self.count(reopened, 'SELECT count(*) FROM verification_records'), 2,
                         'the ids are stored, not derived per connection')

    def test_the_scripts_below_v4_are_unchanged_and_the_new_step_adds_only_two_tables(self):
        """A v3 database and a v4 database agree column-for-column on every table that already existed.

        If a migration below the new one had been edited, an already-deployed v3 file and a freshly built
        one would drift apart, and the drift would show up as a store reading its own history wrongly.
        Comparing `PRAGMA table_info` for every pre-existing table is the strongest statement available
        without quoting schema text this file has no business freezing.
        """
        with self.at_v3():
            old = Store(self.root / 'pinned-v3.db')
            self.fired(old)
            _, version, tables = self.header(old.path)
            self.assertEqual((version, set(tables)), (3, V3_TABLES))
            old_shape = {table: self.shape(old, table) for table in sorted(V3_TABLES)}
        moved = Store(self.root / 'pinned-v3.db', verification_policy=self.policy(), migrate=True)
        _, version, tables = self.header(moved.path)
        self.assertEqual(version, state.VERSION)
        self.assertTrue(NEW_TABLES <= set(tables))
        for table, columns in old_shape.items():
            self.assertEqual(self.shape(moved, table), columns, f'{table} changed under the new step')
        for table in sorted(NEW_TABLES):
            self.assertTrue(self.shape(moved, table), f'{table} was not created')
            with closing(sqlite3.connect(moved.path)) as db:
                self.assertEqual(db.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0,
                                 'the new step creates tables, it does not populate them')

    def test_a_build_pinned_to_the_old_schema_never_touches_the_new_tables(self):
        """The old build must keep working on an old file, with verification off and nothing queried.

        `verification_bindings` does not exist in this scenario at all, which is what makes it a proof: a
        default-off proposal path that reached for either new table would fail with a driver error here
        rather than accept the action. The full lifecycle is run, and the durable facts are the ones the
        v3 build always wrote.
        """
        with self.at_v3():
            store = Store(self.root / 'old-build.db')
            event = self.fired(store)
            action_id = store.propose_action(
                {'retry_key': 'old-build', 'incident_id': event['incident_id'], 'action': 'inspect',
                 'version': '1', 'targets': [self.host], 'parameters': {},
                 'evidence': [event['event_id']], 'expires_at': EXPIRES}, AGENT, self.gate,
                now=NOW)['action_id']
            store.decide(action_id, 'approved', HUMAN, now=NOW)
            claim = store.claim_action(action_id, RUNNER, self.gate,
                                      now=TERMINAL - dt.timedelta(minutes=1))
            store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'],
                                    now=TERMINAL)
            self.assertEqual(self.header(store.path)[2], sorted(V3_TABLES))
            self.assertEqual(store.status(), {'schema_version': 3, 'incidents': {'open': 1},
                                             'actions': {'succeeded': 1},
                                             'notifications': {'pending': 1}})
            self.assertEqual([json.loads(row['detail']).get('parameters_hash') is not None
                              for row in store.records('audit', 100)
                              if row['operation'] == 'action.proposed'], [True])
        # Reopened by *this* build, the same file is the one the migration is meant to receive.
        moved = Store(self.root / 'old-build.db', verification_policy=self.policy(), migrate=True)
        self.assertEqual(moved.migrated_from, 3)
        self.assertEqual({key: value for key, value in moved.status().items() if key != 'schema_version'},
                         {key: value for key, value in store.status().items() if key != 'schema_version'},
                         'the same lifecycle rows, read by the newer build')
        self.assertEqual(moved.status()['schema_version'], state.VERSION)
        self.assertEqual(moved.get_verification_binding(action_id,
                                                       READER)['reason'], 'not-captured')

    def test_the_migrate_command_reports_the_new_step_in_the_shape_it_already_had(self):
        """`lo-platform migrate` answers `migrated` with the versions and the copy it wrote — unchanged."""
        store, _ = self.populated('cli')
        v3 = self.as_v3(store)
        self.assertEqual(self.platform('--database', str(v3), 'status')[0], 1,
                         'status still refuses an un-migrated file')
        code, result = self.platform('--database', str(v3), 'migrate')
        self.assertEqual(code, 0)
        self.assertEqual(sorted(result), ['backup', 'from', 'status', 'to'])
        self.assertEqual((result['status'], result['from'], result['to']),
                         ('migrated', 3, state.VERSION))
        self.assertEqual(self.integrity(Path(result['backup'])), 'ok')
        moved = Store(v3, verification_policy=self.policy())
        self.assertEqual({key: value for key, value in moved.status().items()
                          if key != 'schema_version'},
                         {key: value for key, value in store.status().items()
                          if key != 'schema_version'})


if __name__ == '__main__':
    unittest.main()

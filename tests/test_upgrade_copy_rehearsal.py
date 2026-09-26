"""The copied-state rehearsal: offline file-copy and migration evidence, never old-image recovery proof.

The historical fixture executes only the real v1..v3 scripts, and the one older database migrated
below is built from the real first migration script itself rather than from a patched future version.
Its expected tables, columns and rows are independently enumerated below, not derived from Store or
copy_state's logical hashes. All handles close before copying; every path is temporary.
"""
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest import mock

from local_observe.deployment import state_copy
from local_observe.deployment.content import Conflict
from local_observe.deployment.state_copy import copy_state
from local_observe.platform import state
from local_observe.platform.state import StateError, Store


APPLICATION_ID = 0x4C4F5001
AT = '2026-09-01T12:00:00Z'
LATER = '2026-09-01T13:00:00Z'
RESOURCE = '10000000-0000-4000-8000-000000000001'
EVENT = '20000000-0000-4000-8000-000000000001'
INCIDENT = '30000000-0000-4000-8000-000000000001'
ACTION = '40000000-0000-4000-8000-000000000001'
EXECUTION = '50000000-0000-4000-8000-000000000001'
OUTBOX = '60000000-0000-4000-8000-000000000001'
ATTEMPT = '70000000-0000-4000-8000-000000000001'
EVIDENCE = '80000000-0000-4000-8000-000000000001'
FINGERPRINT = hashlib.sha256(b'offline historical fixture').hexdigest()
WINDOW = {'start': '2026-09-01T11:59:00Z', 'end': AT}
EVIDENCE_DOCUMENT = {
    'source': 'fixture-detector', 'query_type': 'gatus-result', 'parameters': {'sample_id': 'sample-1'},
    'window': WINDOW, 'schema_version': 1, 'expires_at': LATER,
}
EVENT_PAYLOAD = json.dumps({
    'schema_version': 1, 'source': 'fixture-detector', 'source_event_id': 'sample-1',
    'resource_id': RESOURCE, 'observed_at': AT, 'kind': 'availability', 'severity': 'warning',
    'data_class': 'internal', 'evidence': [EVIDENCE_DOCUMENT], 'rule_id': 'fixture-rule',
    'rule_version': '3', 'window': WINDOW, 'condition': 'fixture-high', 'status': 'firing',
}, sort_keys=True, separators=(',', ':'))
ACTION_PAYLOAD = json.dumps({
    'retry_key': 'retry-1', 'incident_id': INCIDENT, 'action': 'inspect', 'version': '1',
    'targets': [RESOURCE], 'parameters': {}, 'evidence': [EVENT], 'expires_at': LATER,
}, sort_keys=True, separators=(',', ':'))

# sqlite_sequence is SQLite's derived bookkeeping, checked separately from durable facts.
V3_TABLES = frozenset({
    'events', 'conditions', 'evidence', 'incidents', 'outbox', 'notification_attempts',
    'actions', 'executions', 'audit', 'notification_control', 'notification_reservations',
    'notification_suppressions',
})
V3_COLUMNS = {
    'events': ('id', 'source', 'source_event_id', 'fingerprint', 'received_at', 'payload', 'incident_id'),
    'conditions': ('key', 'watermark', 'event_id', 'status', 'incident_id'),
    'evidence': ('id', 'source', 'payload', 'fingerprint', 'expires_at'),
    'incidents': ('id', 'condition_key', 'resource_id', 'status', 'opened_at', 'updated_at', 'last_event_id'),
    'outbox': ('sequence', 'id', 'incident_id', 'payload', 'status', 'attempts', 'available_at',
               'lease_until', 'claim_token', 'channel', 'callback_token_hash', 'callback_expires_at',
               'callback_consumed_at'),
    'notification_attempts': ('id', 'outbox_id', 'started_at', 'finished_at', 'result', 'claim_token', 'cause'),
    'actions': ('id', 'requester', 'retry_key', 'fingerprint', 'payload', 'status', 'created_at',
                'expires_at', 'decided_by'),
    'executions': ('id', 'action_id', 'runner', 'token_hash', 'status', 'created_at', 'updated_at'),
    'audit': ('sequence', 'at', 'actor', 'operation', 'subject', 'detail'),
    'notification_control': ('key', 'value', 'updated_at'),
    'notification_reservations': ('id', 'outbox_id', 'channel', 'destination', 'test_window', 'at'),
    'notification_suppressions': ('outbox_id', 'reason', 'at'),
}
# Named insert/select columns keep the historical projection meaningful if later steps add columns.
# These are synthetic SQL storage fixtures, not verification grading or authorization examples.
V3_ROWS = {
    'events': [(EVENT, 'fixture-detector', 'sample-1', hashlib.sha256(EVENT_PAYLOAD.encode()).hexdigest(),
                AT, EVENT_PAYLOAD, INCIDENT)],
    'conditions': [('fixture-condition', AT, EVENT, 'firing', INCIDENT)],
    'evidence': [(EVIDENCE, 'fixture-detector', json.dumps(EVIDENCE_DOCUMENT), FINGERPRINT, LATER)],
    'incidents': [(INCIDENT, 'fixture-condition', RESOURCE, 'open', AT, AT, EVENT)],
    'outbox': [(7, OUTBOX, INCIDENT, '{"incident":"fixture"}', 'dead', 1, AT, None, None,
                'recording', FINGERPRINT, LATER, AT)],
    'notification_attempts': [(ATTEMPT, OUTBOX, AT, AT, 'failed', 'fixture-claim', 'rejected')],
    'actions': [(ACTION, 'fixture-proposer', 'retry-1', hashlib.sha256(ACTION_PAYLOAD.encode()).hexdigest(),
                 ACTION_PAYLOAD, 'succeeded', AT, LATER, 'fixture-human')],
    'executions': [(EXECUTION, ACTION, 'fixture-runner', FINGERPRINT, 'succeeded', AT, AT)],
    'audit': [(11, AT, 'fixture-human', 'action.approved', ACTION, '{}'),
              (12, AT, 'fixture-runner', 'execution.succeeded', EXECUTION, '{}')],
    'notification_control': [('mode', 'off', AT)],
    'notification_reservations': [(9, OUTBOX, 'recording', 'fixture-sink', None, AT)],
    'notification_suppressions': [(OUTBOX, 'mode-off', AT)],
}
VERIFICATION_COLUMNS = {
    'verification_bindings': ('action_id', 'status', 'reason', 'binding_id', 'origin', 'captured_at'),
    'verification_records': ('verification_id', 'execution_id', 'fingerprint', 'payload', 'verdict',
                             'reason', 'recorded_by', 'recorded_at'),
}
VERIFICATION_ROWS = {
    'verification_bindings': [(ACTION, 'unbound', 'origin-unmatched', None, None, AT)],
    'verification_records': [(FINGERPRINT, EXECUTION, FINGERPRINT, '{"fixture":"storage-copy"}',
                              'unknown', 'unbound', 'fixture-verifier', LATER)],
}


def rows(path, table, columns):
    """Read a named projection independently, without the product's logical-copy oracle."""
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute(f'SELECT {",".join(columns)} FROM {table} ORDER BY 1').fetchall()


def schema(path):
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
        return db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()


class UpgradeCopyRehearsalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        source_dir = self.root / 'source'
        source_dir.mkdir()
        self.source = source_dir / 'platform.db'
        with closing(sqlite3.connect(self.source)) as db:
            db.execute('PRAGMA foreign_keys=ON')
            for version in (1, 2, 3):
                db.executescript(state.MIGRATIONS[version])
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.execute('PRAGMA user_version=3')
            for table, expected in V3_ROWS.items():
                columns = V3_COLUMNS[table]
                db.executemany(f'INSERT INTO {table} ({",".join(columns)}) '
                               f'VALUES ({",".join("?" for _ in columns)})', expected)
            db.commit()
        self.source_bytes = self.source.read_bytes()
        self.source_schema = schema(self.source)
        self.assertHistorical(self.source, exact_audit=True)

    def assertHealthy(self, path, version):
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)) as db:
            self.assertEqual(db.execute('PRAGMA application_id').fetchone(), (APPLICATION_ID,))
            self.assertEqual(db.execute('PRAGMA user_version').fetchone(), (version,))
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchall(), [('ok',)])
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def assertHistorical(self, path, *, exact_audit=False):
        for table in sorted(V3_TABLES):
            with self.subTest(table=table, path=path.name):
                actual = rows(path, table, V3_COLUMNS[table])
                if table == 'audit' and not exact_audit:
                    actual = actual[:len(V3_ROWS['audit'])]
                self.assertEqual(actual, V3_ROWS[table])

    def assertSourceUnchanged(self):
        self.assertEqual(self.source.read_bytes(), self.source_bytes)
        self.assertEqual(schema(self.source), self.source_schema)
        self.assertHealthy(self.source, 3)
        self.assertHistorical(self.source, exact_audit=True)

    def copy(self, path=None, name='candidate', **kwargs):
        source = self.source if path is None else path
        # Default allow_checkpoint=False: the source has no open handles or writers.
        report = copy_state({'platform': (source, 'sqlite')}, self.root, self.root / name, **kwargs)
        self.assertIs(report['copy_verified'], True)
        self.assertIs(report['application_recovery_proven'], False)
        self.assertIs(report['cross_file_consistency_proven'], False)
        copied = self.root / name / 'platform.db'
        self.assertEqual(report['files']['platform']['sha256'], hashlib.sha256(copied.read_bytes()).hexdigest())
        self.assertEqual(report['total_bytes'], copied.stat().st_size)
        self.assertSourceUnchanged()
        return copied, report

    def migrate(self):
        candidate, _ = self.copy()
        store = Store(candidate, migrate=True)
        self.assertEqual(store.migrated_from, 3)
        self.assertHealthy(candidate, state.VERSION)
        self.assertSourceUnchanged()
        return store

    def assertMigrationAudit(self, path, targets, migrations, *, from_version: int = 3):
        """Check every audited step of one migration run against independent oracles.

        `detail['from']` names the version the run *started* at (`_audit_migration` is called with the
        version read from the file, not with the previous step), so the v3 fixture records `from: 3`
        for each of its steps and a real v1 file records `from: 1` for all of its own. Asserting the
        sequence continuation, the stored prefix and the script digest here is what keeps that
        difference checkable today instead of only when a fifth step exists.
        """
        actual = rows(path, 'audit', V3_COLUMNS['audit'])
        old_count = len(V3_ROWS['audit'])
        self.assertEqual(actual[:old_count], V3_ROWS['audit'])
        self.assertEqual(len(actual), old_count + len(targets))
        for offset, (row, target) in enumerate(zip(actual[old_count:], targets, strict=True), 1):
            sequence, at, actor, operation, subject, detail = row
            self.assertEqual(sequence, V3_ROWS['audit'][-1][0] + offset)
            self.assertEqual(dt.datetime.fromisoformat(at).utcoffset(), dt.timedelta(0))
            self.assertEqual((actor, operation, subject), ('platform-migrate', 'schema.migrated', str(target)))
            # digest(str) hashes canonical JSON text, including quotes and escaped newlines.
            script_json = json.dumps(migrations[target], sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False)
            self.assertEqual(json.loads(detail), {
                'from': from_version, 'to': target,
                'script_sha256': hashlib.sha256(script_json.encode()).hexdigest(),
            })

    def assertV3Backup(self, backup, candidate):
        self.assertIsNotNone(backup)
        self.assertEqual(backup.parent, candidate.parent)
        self.assertRegex(backup.name, r'^platform\.db\.pre-v3-\d{8}T\d{6}Z\.db$')
        self.assertHealthy(backup, 3)
        self.assertEqual(schema(backup), self.source_schema)
        self.assertHistorical(backup, exact_audit=True)

    def seedV1(self, name='v1-legacy'):
        """Write a separate v1 database from the real first migration, seeded with the audit rows only.

        `audit` carries the same columns in v1 as in v3, so these rows are what an operator would hand
        this build. No current `Store` fixture is involved (creating one would build the current schema),
        the file stays inside `self.root`, and `self.source` is never opened for writing.
        """
        directory = self.root / name
        directory.mkdir()
        path = directory / 'platform.db'
        with closing(sqlite3.connect(path)) as db:
            db.execute('PRAGMA foreign_keys=ON')
            db.executescript(state.MIGRATIONS[1])
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.execute('PRAGMA user_version=1')
            columns = V3_COLUMNS['audit']
            db.executemany(f'INSERT INTO audit ({",".join(columns)}) '
                           f'VALUES ({",".join("?" for _ in columns)})', V3_ROWS['audit'])
            db.commit()
        self.assertHealthy(path, 1)
        self.assertEqual(rows(path, 'audit', columns), V3_ROWS['audit'])
        return path

    def seedVerification(self, path):
        with closing(sqlite3.connect(path)) as db:
            db.execute('PRAGMA foreign_keys=ON')
            for table, expected in VERIFICATION_ROWS.items():
                columns = VERIFICATION_COLUMNS[table]
                db.executemany(f'INSERT INTO {table} ({",".join(columns)}) '
                               f'VALUES ({",".join("?" for _ in columns)})', expected)
            db.commit()

    def assertVerification(self, path):
        for table, expected in VERIFICATION_ROWS.items():
            self.assertEqual(rows(path, table, VERIFICATION_COLUMNS[table]), expected)

    def test_historical_fixture_has_exact_v3_shape_and_independent_nonempty_census(self):
        self.assertEqual(set(V3_ROWS), V3_TABLES)
        self.assertEqual({entry[1] for entry in self.source_schema if entry[0] == 'table'},
                         V3_TABLES | {'sqlite_sequence'})
        with closing(sqlite3.connect(self.source)) as db:
            for table, columns in V3_COLUMNS.items():
                self.assertEqual(tuple(row[1] for row in db.execute(f'PRAGMA table_info({table})')), columns)
                self.assertGreater(len(V3_ROWS[table]), 0)
            self.assertEqual(db.execute('PRAGMA foreign_key_list(executions)').fetchall(),
                             [(0, 0, 'actions', 'action_id', 'id', 'NO ACTION', 'NO ACTION', 'NONE')])
            self.assertEqual(db.execute('SELECT name,seq FROM sqlite_sequence ORDER BY name').fetchall(),
                             [('audit', 12), ('notification_reservations', 9), ('outbox', 7)])
        self.assertHealthy(self.source, 3)

    def test_historical_constraints_are_real_before_any_copy(self):
        # Each statement is expected to fail for its own reason, not merely as an IntegrityError: a
        # status bound is SQLite's CHECK refusal, a dangling action reference is its foreign-key
        # refusal, and the audit tamperings are the trigger messages read out of the stored schema
        # below rather than assumed from this file.
        append_only = 'append-only audit'
        expected = (
            ("UPDATE incidents SET status='invented'", 'CHECK constraint failed'),
            ("UPDATE outbox SET status='invented'", 'CHECK constraint failed'),
            ("UPDATE executions SET action_id='missing-action'", 'FOREIGN KEY constraint failed'),
            ("UPDATE audit SET detail='{}'", append_only),
            ('DELETE FROM audit', append_only),
        )
        with closing(sqlite3.connect(self.source)) as db:
            db.execute('PRAGMA foreign_keys=ON')
            triggers = db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                                  "AND tbl_name='audit' ORDER BY name").fetchall()
            for statement, reason in expected:
                with self.subTest(statement=statement, reason=reason), self.assertRaisesRegex(
                        sqlite3.IntegrityError, reason):
                    db.execute(statement)
                db.rollback()
        self.assertEqual([name for name, _ in triggers], ['audit_no_delete', 'audit_no_update'])
        self.assertEqual({re.search(r"RAISE\(ABORT,'([^']*)'\)", text).group(1) for _, text in triggers},
                         {append_only})
        self.assertSourceUnchanged()

    def test_closed_v3_copy_has_verified_bytes_and_independent_schema_and_rows(self):
        candidate, report = self.copy()
        self.assertHealthy(candidate, 3)
        self.assertEqual(schema(candidate), self.source_schema)
        self.assertHistorical(candidate, exact_audit=True)
        self.assertEqual(rows(candidate, 'sqlite_sequence', ('name', 'seq')),
                         [('audit', 12), ('notification_reservations', 9), ('outbox', 7)])
        logical = report['files']['platform']['logical']
        self.assertEqual(logical['table_count'], len(V3_TABLES) + 1)
        self.assertEqual(logical['row_count'], sum(len(expected) for expected in V3_ROWS.values()) + 3)
        self.assertEqual(list(self.source.parent.iterdir()), [self.source])

    def test_normal_current_store_refuses_v3_without_rewriting_candidate(self):
        candidate, _ = self.copy()
        before = candidate.read_bytes()
        with self.assertRaisesRegex(StateError, r'version 3; run lo-platform migrate'):
            Store(candidate)
        self.assertEqual(candidate.read_bytes(), before)
        self.assertEqual(list(candidate.parent.iterdir()), [candidate])
        self.assertHealthy(candidate, 3)
        self.assertHistorical(candidate, exact_audit=True)
        self.assertSourceUnchanged()

    def test_explicit_real_migration_preserves_rows_and_exact_audited_steps(self):
        store = self.migrate()
        self.assertV3Backup(store.migration_backup, store.path)
        self.assertHistorical(store.path)
        self.assertMigrationAudit(store.path, list(range(4, state.VERSION + 1)), state.MIGRATIONS)
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit'").fetchone(),
                             (12 + state.VERSION - 3,))
        self.assertSourceUnchanged()

    def test_real_v1_database_migrates_every_committed_step_and_audits_its_run_start_version(self):
        """A v1 file written by the real first script reaches `VERSION` with one audit row per step.

        This is the multi-step case that exists today (v1 -> 2 -> 3 -> 4), so `from` is checked against
        a genuine run start instead of a patched future `VERSION`. The v3 fixture file is untouched.
        """
        legacy = self.seedV1()
        v1_schema = schema(legacy)
        self.assertEqual({entry[1] for entry in v1_schema if entry[0] == 'table'},
                         (V3_TABLES - {'notification_control', 'notification_reservations',
                                       'notification_suppressions'}) | {'sqlite_sequence'})
        store = Store(legacy, migrate=True)
        steps = list(range(2, state.VERSION + 1))
        self.assertEqual(store.migrated_from, 1)
        self.assertHealthy(legacy, state.VERSION)
        self.assertMigrationAudit(legacy, steps, state.MIGRATIONS, from_version=1)
        self.assertTrue(V3_TABLES | set(VERIFICATION_COLUMNS) | {'sqlite_sequence'} <=
                        {entry[1] for entry in schema(legacy) if entry[0] == 'table'})
        # The v2 back-fill reads audit for control state and invents nothing from unrelated operations.
        self.assertEqual(rows(legacy, 'notification_control', V3_COLUMNS['notification_control']), [])
        # The copy is named for, and holds, the version the run started at: never reuse the v3 oracle.
        backup = store.migration_backup
        self.assertIsNotNone(backup)
        self.assertEqual(backup.parent, legacy.parent)
        self.assertEqual(list(legacy.parent.glob(legacy.name + '.pre-v*.db')), [backup])
        self.assertRegex(backup.name, r'^platform\.db\.pre-v1-\d{8}T\d{6}Z\.db$')
        self.assertHealthy(backup, 1)
        self.assertEqual(schema(backup), v1_schema)
        self.assertEqual(rows(backup, 'audit', V3_COLUMNS['audit']), V3_ROWS['audit'])
        self.assertTrue(legacy.is_relative_to(self.root) and backup.is_relative_to(self.root))
        self.assertSourceUnchanged()

    def test_reopening_current_candidate_is_idempotent_even_with_migrate_enabled(self):
        store = self.migrate()
        before = store.path.read_bytes()
        backups = sorted(store.path.parent.glob('platform.db.pre-v*.db'))
        for enabled in (False, True):
            reopened = Store(store.path, migrate=enabled)
            self.assertIsNone(reopened.migrated_from)
            self.assertIsNone(reopened.migration_backup)
        self.assertEqual(store.path.read_bytes(), before)
        # Read-only WAL inspection can leave empty sidecars; they are derived, not new backups.
        self.assertEqual(sorted(store.path.parent.glob('platform.db.pre-v*.db')), backups)
        self.assertMigrationAudit(store.path, list(range(4, state.VERSION + 1)), state.MIGRATIONS)
        self.assertSourceUnchanged()

    def test_both_verification_tables_exist_without_backfilling_old_actions(self):
        store = self.migrate()
        tables = {entry[1] for entry in schema(store.path) if entry[0] == 'table'}
        self.assertTrue(V3_TABLES | set(VERIFICATION_COLUMNS) <= tables)
        self.assertEqual(rows(store.path, 'actions', ('id',)), [(ACTION,)])
        for table, columns in VERIFICATION_COLUMNS.items():
            self.assertEqual(rows(store.path, table, columns), [])
        self.assertSourceUnchanged()

    def test_both_nonempty_verification_tables_refuse_update_and_delete(self):
        store = self.migrate()
        self.seedVerification(store.path)
        with closing(sqlite3.connect(store.path)) as db:
            for table in VERIFICATION_COLUMNS:
                for statement in (f"UPDATE {table} SET reason='changed'", f'DELETE FROM {table}'):
                    with self.subTest(statement=statement), self.assertRaisesRegex(
                            sqlite3.IntegrityError, 'append-only verification'):
                        db.execute(statement)
                    db.rollback()
        self.assertVerification(store.path)
        self.assertHealthy(store.path, state.VERSION)
        self.assertSourceUnchanged()

    def test_nonempty_verification_survives_backup_and_fresh_copy_restore(self):
        store = self.migrate()
        self.seedVerification(store.path)
        before = store.path.read_bytes()
        backup_dir = self.root / 'post-migration-backup'
        backup_dir.mkdir()
        backup = backup_dir / 'platform.db'
        store.backup(backup)
        self.assertEqual(store.path.read_bytes(), before)
        backup_before = backup.read_bytes()
        restored, _ = self.copy(backup, 'current-restore')
        self.assertEqual(backup.read_bytes(), backup_before)
        for path in (backup, restored):
            self.assertHealthy(path, state.VERSION)
            self.assertEqual(schema(path), schema(store.path))
            self.assertHistorical(path)
            self.assertVerification(path)
            self.assertMigrationAudit(path, list(range(4, state.VERSION + 1)), state.MIGRATIONS)
        self.assertIsNone(Store(restored).migrated_from)
        self.assertSourceUnchanged()

    def test_original_v3_restores_to_separate_directory_as_file_rollback_only(self):
        original_copy, _ = self.copy(name='original-v3')
        original_bytes = original_copy.read_bytes()
        candidate, _ = self.copy(original_copy)
        Store(candidate, migrate=True)
        candidate_before = candidate.read_bytes()
        restored, report = self.copy(original_copy, 'rollback-v3')
        self.assertIs(report['application_recovery_proven'], False)
        self.assertEqual(original_copy.read_bytes(), original_bytes)
        self.assertHealthy(restored, 3)
        self.assertEqual(schema(restored), self.source_schema)
        self.assertHistorical(restored, exact_audit=True)
        self.assertEqual(candidate.read_bytes(), candidate_before)
        self.assertHealthy(candidate, state.VERSION)
        self.assertSourceUnchanged()

    def test_missing_step_refuses_before_copy_or_any_real_migration(self):
        candidate, _ = self.copy()
        before = candidate.read_bytes()
        # Only fault tests simulate a future build; the real happy path never patches VERSION.
        future = state.VERSION + 2
        migrations = {**state.MIGRATIONS, future: 'CREATE TABLE unreachable_future(x);'}
        with mock.patch.object(state, 'VERSION', future), mock.patch.object(state, 'MIGRATIONS', migrations):
            with self.assertRaisesRegex(StateError, r'No migration .* is absent'):
                Store(candidate, migrate=True)
        self.assertEqual(candidate.read_bytes(), before)
        self.assertEqual(list(candidate.parent.iterdir()), [candidate])
        self.assertHealthy(candidate, 3)
        self.assertHistorical(candidate, exact_audit=True)
        self.assertSourceUnchanged()

    def test_failed_first_step_rolls_back_partial_ddl_and_keeps_verified_v3_backup(self):
        candidate, _ = self.copy()
        broken = {**state.MIGRATIONS, 4: state.MIGRATIONS[4] + '\nCREATE TABLE partial_step(x);\n'
                  'INSERT INTO nonexistent_fixture_table VALUES (1);'}
        with mock.patch.object(state, 'MIGRATIONS', broken):
            with self.assertRaisesRegex(StateError, 'stays at version 3'):
                Store(candidate, migrate=True)
        self.assertHealthy(candidate, 3)
        self.assertEqual(schema(candidate), self.source_schema)
        self.assertHistorical(candidate, exact_audit=True)
        backups = list(candidate.parent.glob('platform.db.pre-v3-*.db'))
        self.assertEqual(len(backups), 1)
        self.assertV3Backup(backups[0], candidate)
        self.assertSourceUnchanged()

    def test_failed_later_step_keeps_last_real_version_and_only_committed_audits(self):
        candidate, _ = self.copy()
        current = state.VERSION
        migrations = dict(state.MIGRATIONS)
        broken = {**migrations, current + 1: 'CREATE TABLE partial_future(x);\n'
                  'INSERT INTO nonexistent_fixture_table VALUES (1);'}
        with mock.patch.object(state, 'VERSION', current + 1), mock.patch.object(state, 'MIGRATIONS', broken):
            with self.assertRaisesRegex(StateError, f'stays at version {current}'):
                Store(candidate, migrate=True)
        self.assertHealthy(candidate, current)
        self.assertNotIn('partial_future', {entry[1] for entry in schema(candidate)})
        self.assertHistorical(candidate)
        self.assertMigrationAudit(candidate, list(range(4, current + 1)), migrations)
        backups = list(candidate.parent.glob('platform.db.pre-v3-*.db'))
        self.assertEqual(len(backups), 1)
        self.assertV3Backup(backups[0], candidate)
        self.assertIsNone(Store(candidate).migrated_from)
        self.assertSourceUnchanged()

    def test_migration_snapshot_collision_preserves_existing_copy_and_candidate(self):
        candidate, _ = self.copy()
        fixed = dt.datetime(2026, 9, 1, 12, tzinfo=dt.timezone.utc)
        backup = candidate.with_name('platform.db.pre-v3-20260901T120000Z.db')
        backup.write_bytes(self.source_bytes)
        before = candidate.read_bytes()
        # Freeze the clock `state` reads, and nothing wider: `state.dt` is the stdlib module object, so
        # patching an attribute on it would replace `datetime.datetime` for the whole process (other
        # tests, the interpreter's own imports and this file's oracles included). Wrapping the module
        # reference held by `state` keeps the freeze local to the code under test, which is also what
        # lets this test be selected on its own.
        real_datetime = dt.datetime
        frozen = mock.Mock(wraps=dt)
        frozen.datetime = mock.Mock(wraps=dt.datetime)
        frozen.datetime.now.return_value = fixed
        with mock.patch.object(state, 'dt', frozen):
            self.assertIs(dt.datetime, real_datetime)
            self.assertIs(state.dt.datetime, frozen.datetime)
            self.assertEqual(state.dt.datetime.now(dt.timezone.utc), fixed)
            with self.assertRaises(FileExistsError):
                Store(candidate, migrate=True)
        self.assertIs(state.dt, dt)
        self.assertIs(dt.datetime, real_datetime)
        self.assertEqual(backup.read_bytes(), self.source_bytes)
        self.assertEqual(candidate.read_bytes(), before)
        self.assertV3Backup(backup, candidate)
        self.assertHistorical(candidate, exact_audit=True)
        self.assertSourceUnchanged()

    def test_failed_snapshot_cannot_start_migration_before_safe_copy_exists(self):
        candidate, _ = self.copy()
        before = candidate.read_bytes()
        with mock.patch.object(Store, 'backup', autospec=True, side_effect=OSError('fixture backup failure')) as backup:
            with self.assertRaisesRegex(OSError, 'fixture backup failure'):
                Store(candidate, migrate=True)
        backup.assert_called_once()
        self.assertEqual(candidate.read_bytes(), before)
        self.assertEqual(list(candidate.parent.iterdir()), [candidate])
        self.assertHealthy(candidate, 3)
        self.assertHistorical(candidate, exact_audit=True)
        self.assertSourceUnchanged()

    def test_backup_collision_preserves_nonempty_verification_copy(self):
        store = self.migrate()
        self.seedVerification(store.path)
        destination = store.path.parent / 'already-backed-up.db'
        store.backup(destination)
        before = destination.read_bytes()
        with self.assertRaises(FileExistsError):
            store.backup(destination)
        self.assertEqual(destination.read_bytes(), before)
        self.assertVerification(destination)
        self.assertHealthy(destination, state.VERSION)
        self.assertSourceUnchanged()

    def test_existing_copy_output_is_not_overwritten(self):
        candidate, _ = self.copy()
        before = candidate.read_bytes()
        with self.assertRaises(FileExistsError):
            copy_state({'platform': (self.source, 'sqlite')}, self.root, candidate.parent)
        self.assertEqual(candidate.read_bytes(), before)
        self.assertHistorical(candidate, exact_audit=True)
        self.assertSourceUnchanged()

    def test_overlapping_copy_output_is_refused_without_creating_it(self):
        output = self.source.parent / 'overlap'
        with self.assertRaisesRegex(Conflict, 'overlaps'):
            copy_state({'platform': (self.source, 'sqlite')}, self.root, output)
        self.assertFalse(output.exists())
        self.assertSourceUnchanged()

    def test_insufficient_copy_budget_is_refused_without_creating_output(self):
        output = self.root / 'over-budget'
        with self.assertRaisesRegex(Conflict, 'exceed copy budget'):
            copy_state({'platform': (self.source, 'sqlite')}, self.root, output,
                       max_bytes=self.source.stat().st_size - 1)
        self.assertFalse(output.exists())
        self.assertSourceUnchanged()

    def test_logical_readback_mismatch_refuses_the_copy_and_retains_partial_output(self):
        """The copy is refused when the restored logical census disagrees, and nothing is cleaned up.

        The disagreement is injected deliberately: the source census is the real one and the restored
        census is the same dict with a foreign digest, so this pins the refusal and the documented
        retention of partial output. It is not a corruption demonstration and it claims nothing about
        application recovery — the retained file stays exactly what the oracle refused to certify.
        """
        with closing(sqlite3.connect(self.source.as_uri() + '?mode=ro', uri=True)) as db:
            source_census = state_copy._logical(db)
        mismatched = {**source_census, 'tables_sha256': hashlib.sha256(b'fixture readback').hexdigest()}
        self.assertNotEqual(mismatched, source_census)
        output = self.root / 'readback-mismatch'
        with mock.patch.object(state_copy, '_logical',
                               side_effect=[source_census, mismatched]) as census:
            with self.assertRaisesRegex(Conflict, 'Restored SQLite content differs'):
                copy_state({'platform': (self.source, 'sqlite')}, self.root, output)
        # Both censuses ran and no third lookup rescued the refusal.
        self.assertEqual(census.call_count, 2)
        self.assertTrue(all(isinstance(call.args[0], sqlite3.Connection) for call in census.call_args_list))
        retained = output / 'platform.db'
        self.assertEqual([item.name for item in output.iterdir()], [retained.name])
        self.assertGreater(retained.stat().st_size, 0)
        self.assertHealthy(retained, 3)
        self.assertHistorical(retained, exact_audit=True)
        self.assertSourceUnchanged()

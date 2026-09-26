"""Candidate acceptance exercises real migrated SQLite and refuses false success."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from local_observe.platform import escalation, state, suppression
from scripts import upgrade_acceptance as acceptance
from scripts import upgrade_driver as stage

IMAGE = 'sha256:' + 'a' * 64


class UpgradeAcceptanceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.copy = self.root / 'platform.db'
        with closing(sqlite3.connect(self.copy)) as db:
            for version in range(1, 5):
                db.executescript(state.MIGRATIONS[version])
            db.execute(f'PRAGMA application_id={state.APPLICATION_ID}')
            db.execute('PRAGMA user_version=4')
        state.Store(self.copy, migrate=True)
        self.before = self.copy.read_bytes()

    def run_candidate(self, *command, **kwargs):
        self.command = command
        self.options = kwargs
        return json.dumps(acceptance.exercise(self.copy, self.root))

    def test_real_migrated_indexes_and_history_checks_leave_copy_unchanged(self):
        # Real migrated files retain a WAL header. A read-only main file in a writable
        # directory permits SQLite's empty local sidecars without immutable=1.
        self.assertEqual(self.copy.read_bytes()[18:20], b'\x02\x02')
        self.copy.chmod(0o444)
        self.addCleanup(self.copy.chmod, 0o600)
        with closing(sqlite3.connect(self.copy.as_uri() + '?mode=ro', uri=True)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], state.VERSION)
            with self.assertRaisesRegex(sqlite3.OperationalError, 'readonly'):
                db.execute('CREATE TABLE forbidden(id INTEGER)')
        result = acceptance.run_acceptance(self.run_candidate, IMAGE, self.root)
        self.assertEqual(result['escalated'], 1)
        self.assertEqual(result['expired_windows'], 2048)
        self.assertEqual(result['unrelated_incidents'], 160)
        self.assertEqual(result['notification_attempts'], 0)
        self.assertEqual(self.copy.read_bytes(), self.before)
        self.assertEqual(list(self.root.glob('upgrade-acceptance-*')), [])
        self.assertEqual(self.options, {'timeout': 120})
        for flag in ('--network=none', '--read-only', '--pull=never', '--memory=384m', '--cpus=0.5'):
            self.assertIn(flag, self.command)
        self.assertIn('--workdir=/release', self.command)
        self.assertIn('--env=PYTHONPATH=/release', self.command)
        mounts = [self.command[i + 1] for i, part in enumerate(self.command) if part == '--mount']
        self.assertEqual(len(mounts), 2)
        self.assertTrue(all(value.endswith(',readonly') for value in mounts))
        self.assertIn(f'type=bind,source={self.copy},target=/tmp/copied.db,readonly', mounts)
        self.assertIn(IMAGE, self.command)

    def test_missing_or_wrong_definition_of_each_migration_index_refuses(self):
        for name in acceptance.INDEX_NAMES:
            for wrong_definition in (False, True):
                with self.subTest(index=name, wrong_definition=wrong_definition):
                    self.copy.write_bytes(self.before)
                    with closing(sqlite3.connect(self.copy)) as db:
                        db.execute(f'DROP INDEX {name}')
                        if wrong_definition:
                            db.execute(f'CREATE INDEX {name} ON incidents(updated_at)')
                    broken = self.copy.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'indexes differ'):
                        acceptance.exercise(self.copy, self.root)
                    self.assertEqual(self.copy.read_bytes(), broken)
                    self.assertEqual(list(self.root.glob('upgrade-acceptance-*')), [])

    def test_hidden_maintenance_window_is_detected(self):
        with mock.patch.object(suppression, 'covering_window', return_value=None):
            with self.assertRaisesRegex(ValueError, 'hides a current window'):
                acceptance.exercise(self.copy, self.root)
        self.assertEqual(self.copy.read_bytes(), self.before)

    def test_lost_old_incident_is_detected(self):
        real_tick = escalation.tick

        def lost(*args, **kwargs):
            result = real_tick(*args, **kwargs)
            if result['escalated']:
                result['escalated'] = 0
                result['closed'] = 1
            return result

        with mock.patch.object(escalation, 'tick', side_effect=lost):
            with self.assertRaisesRegex(ValueError, 'does not escalate'):
                acceptance.exercise(self.copy, self.root)
        self.assertEqual(self.copy.read_bytes(), self.before)

    def test_mutable_image_and_false_receipts_are_refused(self):
        run = mock.Mock()
        with self.assertRaisesRegex(ValueError, 'exact candidate image'):
            acceptance.run_acceptance(run, 'candidate:latest', self.root)
        run.assert_not_called()
        for answer in ('{}', '{"status":"pass"}', 'null', 'false'):
            with self.subTest(answer=answer):
                with self.assertRaisesRegex(ValueError, 'receipt refused'):
                    acceptance.run_acceptance(lambda *a, **k: answer, IMAGE, self.root)
        receipt = {'status': 'pass', 'schema_version': state.VERSION, 'indexes': list(acceptance.INDEX_NAMES),
                   'expired_windows': 2048, 'unrelated_incidents': 160,
                   'escalated': 1, 'notification_attempts': 0}
        for key, value in (('escalated', True), ('notification_attempts', False)):
            with self.subTest(boolean_field=key):
                spoofed = json.dumps(dict(receipt, **{key: value}))
                with self.assertRaisesRegex(ValueError, 'receipt refused'):
                    acceptance.run_acceptance(lambda *a, **k: spoofed, IMAGE, self.root)

    def test_checkpointed_wal_header_is_valid_but_pending_sidecars_refuse(self):
        run = mock.Mock()
        with closing(sqlite3.connect(self.copy)) as db:
            db.execute('PRAGMA journal_mode=WAL')
        self.assertEqual(self.copy.read_bytes()[18:20], b'\x02\x02')
        acceptance.copy_guard(self.copy)
        self.copy.write_bytes(self.before)
        for suffix in ('-wal', '-journal'):
            path = self.copy.with_name(self.copy.name + suffix)
            path.write_bytes(b'pending')
            try:
                with self.assertRaisesRegex(ValueError, 'Stop isolated writers'):
                    acceptance.run_acceptance(run, IMAGE, self.root)
            finally:
                path.unlink()
        run.assert_not_called()

    def test_optimized_python_refuses_before_any_container(self):
        with mock.patch.object(acceptance.sys, 'flags', mock.Mock(optimize=1)):
            with self.assertRaisesRegex(ValueError, 'optimized acceptance'):
                acceptance.run_acceptance(mock.Mock(), IMAGE, self.root)

    def test_candidate_boundary_failure_blocks_deployment_and_acceptance(self):
        order = []

        def prepared(*args):
            order.append('migrated')
            return {'candidate_state': {'user_version': state.VERSION}, 'durable_sha256': 'unchanged'}

        def checked(value):
            order.append('index-and-behavior')
            acceptance.run_acceptance(lambda *a, **k: '{}', IMAGE, self.root)

        deploy, accept = mock.Mock(), mock.Mock()
        with mock.patch.object(stage, 'prepare', side_effect=prepared):
            with self.assertRaisesRegex(ValueError, 'receipt refused'):
                stage.start_candidate(mock.Mock(), IMAGE, self.root, {}, lambda pin: pin,
                                      checked, deploy, accept, lambda: 'unchanged')
        self.assertEqual(order, ['migrated', 'index-and-behavior'])
        deploy.assert_not_called()
        accept.assert_not_called()

    def test_changed_copy_cannot_receive_a_success_receipt(self):
        def changed(*args, **kwargs):
            self.copy.write_bytes(self.before + b'changed')
            return '{}'

        with self.assertRaisesRegex(ValueError, 'changed the migrated copy'):
            acceptance.run_acceptance(changed, IMAGE, self.root)
        self.assertNotEqual(hashlib.sha256(self.copy.read_bytes()).digest(),
                            hashlib.sha256(self.before).digest())


if __name__ == '__main__':
    unittest.main()

"""Exercise the actual external-state orchestration on disposable files."""
from contextlib import closing, contextmanager
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'external_state_capture', Path(__file__).resolve().parents[1]/'scripts/stage_external_state.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExternalStateCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name).resolve()
        self.root = self.work/'external-state-fixture'
        self.root.mkdir()
        self.discovery = self.work/'discovery'
        self.overview = self.work/'overview'
        self.state = self.discovery/'state'
        for directory in (self.state/'proposals', self.discovery/'local_observe',
                          self.overview/'local_observe'):
            directory.mkdir(parents=True)
        for directory in (self.discovery, self.overview):
            (directory/'local_observe'/'fixture.py').write_text('PIN = 1')
        self.write(self.work/'active-discovery.json', {'deployment': str(self.discovery)})
        self.write(self.work/'active-homepage.json', {'overview_code': str(self.overview)})
        self.write(self.discovery/'discovery.json',
                   {'state': str(self.state), 'index': str(self.discovery/'index.db')})
        self.write(self.overview/'overview.json', {'output': str(self.overview/'state.json')})
        self.write(self.overview/'state.json', {'status': 'healthy', 'sequence': 7})
        self.write(self.state/'cursor.json', {'cursor': 'preserved'})
        self.write(self.state/'drift.json', {'observed': ['one']})
        self.write(self.state/'proposals'/'one.json', {'proposal': 'never-published'})
        (self.state/'worker.lock.owner.lock').touch()
        for path in (self.discovery/'index.db', self.state/'observations-one.db'):
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY, value TEXT)')
                db.execute("INSERT INTO evidence VALUES (1, 'retained')")
                db.commit()
        # Deliberately unusable retired metadata proves this is not a jobs dependency.
        (self.work/'active-jobs.json').write_text('historical opaque retained bytes')
        self.commands = []
        self.active = 'inactive'
        self.busy = False
        self.held = False
        self.next_run = 't 1000000000'
        self.discovery_config = (self.discovery/'discovery.json').as_posix()

    def write(self, path, value):
        path.write_text(json.dumps(value))

    def originals(self):
        return {p.relative_to(self.work).as_posix(): p.read_bytes()
                for p in self.work.rglob('*') if p.is_file() and not p.is_relative_to(self.root)}

    def command(self, *args):
        self.commands.append(args)
        if args == ('docker', 'ps', '-q', '--no-trunc'):
            return 'unchanged-container'
        if args[0] == 'busctl':
            return 'o "/timer"' if args[2] == 'call' else self.next_run
        if args[0] == 'systemctl':
            if args[-1] == 'Environment':
                if args[3] == 'local-observe-discovery.service':
                    return 'PRIVATE_VALUE=do-not-log LO_DISCOVERY_CONFIG='+self.discovery_config
                return 'LO_OVERVIEW_CONFIG='+(self.overview/'overview.json').as_posix()
            if args[-1] == 'ActiveState':
                return self.active if args[3] == 'local-observe-discovery.service' else 'active'
            return 'fixture'
        self.fail('Unexpected command '+repr(args))

    @contextmanager
    def lock(self, path):
        self.assertEqual(path, self.state/'worker.lock.owner.lock')
        self.assertFalse(self.held)
        if self.busy:
            raise BlockingIOError('writer owns lock')
        self.held = True
        try:
            yield
        finally:
            self.held = False

    def invoke(self, **kwargs):
        return MODULE.capture_external_state(self.root, self.work, self.command,
                                             lock=self.lock, monotonic=lambda: 0, **kwargs)

    def test_preflight_does_not_write_and_does_not_need_retired_jobs(self):
        before = self.originals()
        report = self.invoke()
        self.assertEqual(report['status'], 'preflight')
        self.assertEqual(report['files'], 8)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.originals(), before)
        self.assertFalse(any('jobs' in str(command) for command in self.commands))

    def test_actual_copy_and_independent_restore_preserve_all_selected_content(self):
        before = self.originals()
        from local_observe.deployment.state_copy import copy_state
        phases = []
        def observed_copy(sources, work, output, **kwargs):
            phases.append((output.name, self.held, kwargs.get('allow_checkpoint', False)))
            return copy_state(sources, work, output, **kwargs)
        with patch('local_observe.deployment.state_copy.copy_state', side_effect=observed_copy):
            report = self.invoke(capture=True)
        self.assertEqual(phases, [('index-backup', True, False), ('backup', True, True), ('restore', False, False)])
        self.assertTrue(report['restored_readback'])
        self.assertFalse(report['application_recovery_proven'])
        evidence = json.loads((self.root/'report.json').read_text())
        self.assertEqual(set(evidence['declared_source_sha256']), {'discovery', 'overview'})
        self.assertFalse(evidence['cross_file_consistency_proven'])
        self.assertEqual(set(evidence['files']), {
            'discovery-config', 'discovery-cursor', 'discovery-drift', 'discovery-index',
            'observations-one', 'proposal-0', 'overview-config', 'overview-state'})
        for directory in ('backup', 'restore'):
            self.assertEqual(json.loads((self.root/directory/'discovery-cursor.json').read_text()),
                             {'cursor': 'preserved'})
            with closing(sqlite3.connect(self.root/directory/'observations-one.db')) as db:
                self.assertEqual(db.execute('SELECT * FROM evidence').fetchall(), [(1, 'retained')])
        self.assertEqual(self.originals(), before)
        self.assertFalse(self.held)

    def test_active_writer_and_lock_contention_refuse_before_creation(self):
        before = self.originals()
        self.active = 'active'
        with self.assertRaisesRegex(ValueError, 'writer is active'):
            self.invoke(capture=True)
        self.active = 'inactive'
        self.busy = True
        with self.assertRaises(BlockingIOError):
            self.invoke(capture=True)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(self.originals(), before)

    def test_imminent_timer_refuses_and_never_changes_timer(self):
        self.next_run = 't 89000000'
        with self.assertRaisesRegex(ValueError, 'imminent'):
            self.invoke(capture=True)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_existing_evidence_refuses_without_overwriting(self):
        (self.root/'report.json').write_text('previous failure')
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.invoke(capture=True)
        self.assertEqual((self.root/'report.json').read_text(), 'previous failure')
        self.assertEqual(self.commands, [])

    def test_missing_source_refuses_before_copy(self):
        (self.state/'cursor.json').unlink()
        with self.assertRaises(FileNotFoundError):
            self.invoke(capture=True)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_database_retains_failed_copy_and_originals(self):
        (self.discovery/'index.db').write_bytes(b'not sqlite')
        before = self.originals()
        with self.assertRaises(sqlite3.DatabaseError):
            self.invoke(capture=True)
        self.assertTrue((self.root/'index-backup').is_dir())
        self.assertFalse((self.root/'report.json').exists())
        self.assertEqual(self.originals(), before)
        self.assertFalse(self.held)

    @unittest.skipUnless(__import__('os').name == 'posix', 'OS flock is Linux host boundary')
    def test_real_nonblocking_lock_refuses_an_existing_owner(self):
        path = self.state/'worker.lock.owner.lock'
        with MODULE.discovery_lock(path):
            with self.assertRaises(BlockingIOError):
                with MODULE.discovery_lock(path):
                    self.fail('Second owner acquired the discovery lock')

    def test_service_ledger_mismatch_refuses_before_lock_or_copy(self):
        self.discovery_config = (self.work/'other'/'discovery.json').as_posix()
        with patch.object(self, 'lock', side_effect=AssertionError):
            with self.assertRaisesRegex(ValueError, 'differs from ledger'):
                self.invoke(capture=True)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unowned_index_live_wal_refuses_without_checkpoint(self):
        path = self.discovery/'index.db'
        with closing(sqlite3.connect(path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('INSERT INTO evidence VALUES (2, "live")')
            writer.commit()
            wal = Path(str(path)+'-wal')
            original = wal.read_bytes()
            with self.assertRaisesRegex(ValueError, 'live WAL'):
                self.invoke(capture=True)
            self.assertEqual(wal.read_bytes(), original)
            self.assertEqual(writer.execute('SELECT count(*) FROM evidence').fetchone(), (2,))
        self.assertFalse((self.root/'backup').exists())
        self.assertFalse((self.root/'report.json').exists())

    def test_wrong_task_root_refuses_before_commands(self):
        with self.assertRaisesRegex(ValueError, 'fresh external-state'):
            MODULE.capture_external_state(self.discovery, self.work, self.command)
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()

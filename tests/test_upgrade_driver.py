"""Real historical SQLite migration behind an injected, Docker-free command boundary."""
import ast
import asyncio
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

import httpx

from local_observe.deployment.content import Conflict
from local_observe.deployment.release import inspect_sqlite
from local_observe.platform import state
from scripts import upgrade_rehearsal as driver
from scripts import upgrade_driver as stage
from test_upgrade_copy_rehearsal import (APPLICATION_ID, V3_COLUMNS, V3_ROWS,
                                       VERIFICATION_COLUMNS, VERIFICATION_ROWS)


IMAGE = 'sha256:' + 'a' * 64


class UpgradeDriverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.original = self.root / 'original.db'
        with closing(sqlite3.connect(self.original)) as db:
            for version in (1, 2, 3):
                db.executescript(state.MIGRATIONS[version])
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.execute('PRAGMA user_version=3')
            for table, rows in V3_ROWS.items():
                columns = V3_COLUMNS[table]
                db.executemany(f'INSERT INTO {table} ({",".join(columns)}) '
                               f'VALUES ({",".join("?" for _ in columns)})', rows)
            db.commit()
        self.original_bytes = self.original.read_bytes()
        self.directory = self.root / 'candidate'
        self.directory.mkdir()
        self.path = self.directory / 'platform.db'
        shutil.copyfile(self.original, self.path)
        self.pin = inspect_sqlite(self.path)
        self.calls = []
        self.contract = {'version': state.VERSION, 'application_id': state.APPLICATION_ID,
                         'actor': state.MIGRATE_ACTOR,
                         'scripts': {str(k): state.digest(v) for k, v in state.MIGRATIONS.items()}}
        self.after_migrate = lambda: None

    def command(self, *args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[:3], ('docker', 'run', '--rm'))
        for flag in ('--network=none', '--read-only', '--cap-drop=ALL',
                     '--security-opt=no-new-privileges:true'):
            self.assertIn(flag, args)
        self.assertEqual(args[args.index('--entrypoint') + 1:args.index('--entrypoint') + 4],
                         ('python', IMAGE, '-B'))
        if args[-2] == '-c':
            self.assertNotIn('--mount', args)
            self.assertEqual(args[-1], driver.RUNTIME_CONTRACT)
            return json.dumps(self.contract)
        self.assertEqual(args[-5:], ('-m', 'local_observe.platform.cli', '--database',
                                    '/data/platform.db', 'migrate'))
        self.assertEqual(args[args.index('--mount') + 1],
                         'type=bind,source=' + str(self.directory) + ',target=/data')
        store = state.Store(self.path, migrate=True)
        self.backup = store.migration_backup
        self.after_migrate()
        return json.dumps({'status': 'migrated', 'from': store.migrated_from,
                           'to': state.VERSION, 'backup': '/data/' + self.backup.name})

    def prepare(self):
        return driver.prepare(self.command, IMAGE, self.directory, self.pin)

    def test_real_v3_migrates_before_candidate_can_start_and_preserves_every_column(self):
        with self.assertRaises(state.StateError):
            state.Store(self.path)
        self.assertEqual(self.path.read_bytes(), self.original_bytes)
        result = self.prepare()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(result['candidate_state']['user_version'], state.VERSION)
        self.assertEqual(self.original.read_bytes(), self.original_bytes)
        self.assertEqual(inspect_sqlite(self.backup), self.pin)
        self.assertFalse(result['deploy_authorized'])
        self.assertEqual(result['durable_sha256'], driver.fingerprint(driver.snapshot(self.path)))
        self.assertIn('verification_records', driver.snapshot(self.path)['columns'])
        self.assertIn('verification_bindings', driver.snapshot(self.path)['columns'])

    def test_same_schema_skips_migration_and_retains_full_state(self):
        state.Store(self.path, migrate=True)
        self.pin = inspect_sqlite(self.path)
        before = self.path.read_bytes()
        result = self.prepare()
        self.assertEqual(len(self.calls), 1)
        self.assertIsNone(result['migration_backup'])
        self.assertEqual(self.path.read_bytes(), before)

    def test_wrong_original_pin_and_sidecar_refuse_before_any_command(self):
        bad = deepcopy(self.pin)
        bad['schema_sha256'] = '0' * 64
        with self.assertRaisesRegex(Conflict, 'pin'):
            driver.prepare(self.command, IMAGE, self.directory, bad)
        self.path.with_name('platform.db-wal').write_bytes(b'busy')
        with self.assertRaisesRegex(Conflict, 'writers'):
            self.prepare()
        self.assertEqual(self.calls, [])

    def test_runtime_version_is_authority_and_downgrade_is_refused(self):
        self.contract['version'] = 2
        self.contract['scripts'] = {k: v for k, v in self.contract['scripts'].items() if int(k) <= 2}
        with self.assertRaisesRegex(Conflict, 'cannot migrate'):
            self.prepare()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.path.read_bytes(), self.original_bytes)

    def test_failure_does_not_produce_acceptance_or_touch_original(self):
        def fail(*args, **kwargs):
            if args[-1] == 'migrate':
                raise RuntimeError('injected command failure')
            return self.command(*args, **kwargs)
        with self.assertRaisesRegex(RuntimeError, 'injected'):
            driver.prepare(fail, IMAGE, self.directory, self.pin)
        self.assertEqual(self.original.read_bytes(), self.original_bytes)
        self.assertEqual(self.path.read_bytes(), self.original_bytes)

    def test_migration_backup_tampering_refuses(self):
        def damage():
            with closing(sqlite3.connect(self.backup)) as db:
                db.execute("UPDATE notification_control SET value='recording'")
                db.commit()
        self.after_migrate = damage
        with self.assertRaisesRegex(Conflict, 'rollback copy'):
            self.prepare()

    def test_historical_table_outside_old_seven_table_list_is_checked(self):
        def damage():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("UPDATE notification_control SET value='recording'")
                db.commit()
        self.after_migrate = damage
        with self.assertRaisesRegex(Conflict, 'durable rows'):
            self.prepare()

    def test_changed_migration_script_hash_is_refused(self):
        self.contract['scripts']['4'] = '0' * 64
        with self.assertRaisesRegex(Conflict, 'candidate scripts'):
            self.prepare()

    def test_missing_verification_table_is_refused(self):
        def damage():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute('DROP TABLE verification_records')
                db.commit()
        self.after_migrate = damage
        with self.assertRaisesRegex(Conflict, 'verification storage'):
            self.prepare()

    def test_candidate_version_mismatch_is_refused(self):
        def damage():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute('PRAGMA user_version=5')
        self.after_migrate = damage
        with self.assertRaisesRegex(Conflict, 'version'):
            self.prepare()

    def test_added_audit_row_is_not_silently_accepted(self):
        def damage():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("INSERT INTO audit(at,actor,operation,subject,detail) VALUES"
                           " ('2026-09-01T00:00:00Z','other','extra','x','{}')")
                db.commit()
        self.after_migrate = damage
        with self.assertRaisesRegex(Conflict, 'audit row count'):
            self.prepare()

    def test_nonempty_verification_tables_survive_later_real_migrations(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(state.MIGRATIONS[4])
            db.execute('PRAGMA user_version=4')
            for table, rows in VERIFICATION_ROWS.items():
                columns = VERIFICATION_COLUMNS[table]
                db.executemany(f'INSERT INTO {table} ({",".join(columns)}) '
                               f'VALUES ({",".join("?" for _ in columns)})', rows)
            db.commit()
        self.pin = inspect_sqlite(self.path)
        before = driver.snapshot(self.path)
        self.prepare()
        after = driver.snapshot(self.path)
        for table in VERIFICATION_ROWS:
            self.assertTrue(before['rows'][table])
            self.assertEqual(before['rows'][table], after['rows'][table])

    def test_a_sequence_reset_cannot_hide_behind_unchanged_rows(self):
        def damage():
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("UPDATE sqlite_sequence SET seq=0 WHERE name='audit'")
                db.commit()
        self.after_migrate = damage
        with self.assertRaisesRegex(Conflict, 'sequence trails'):
            self.prepare()

    def test_candidate_startup_state_change_prevents_returning_an_accepted_release(self):
        def change(_):
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("UPDATE notification_control SET value='recording'")
                db.commit()
            return {'status': 'ok'}
        with self.assertRaisesRegex(ValueError, 'durable state changed'):
            stage.start_candidate(self.command, IMAGE, self.directory, self.pin,
                                  lambda pin: {'state': pin}, lambda value: None, lambda: None,
                                  change, lambda: driver.fingerprint(driver.snapshot(self.path)))

    def test_returning_to_original_copy_requires_second_migration(self):
        first = self.prepare()
        # A second fresh copy models rollback without deleting candidate state/backups.
        self.directory = self.root / 'restored'
        self.directory.mkdir()
        self.path = self.directory / 'platform.db'
        shutil.copyfile(self.original, self.path)
        second = self.prepare()
        self.assertEqual(first['candidate_state'], second['candidate_state'])
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(self.original.read_bytes(), self.original_bytes)

    def test_real_driver_orchestrators_migrate_fail_restore_original_then_migrate_again(self):
        from local_observe.deployment.release import backup_sqlite
        events = []
        checkpoint = self.root / 'rollback.db'
        receipt = backup_sqlite(self.path, checkpoint)
        original_hash = driver.fingerprint(driver.snapshot(self.path))
        checkpoint_bytes = checkpoint.read_bytes()
        old_image = 'sha256:' + 'b' * 64
        previous = {'image': old_image, 'state': self.pin}
        applied = self.root / 'last-applied.json'
        applied.write_text('original')
        def run(*args, **kwargs):
            events.append('migrate' if args[-1] == 'migrate' else 'runtime-contract')
            return self.command(*args, **kwargs)
        def make_release(pin):
            events.append('candidate-pin')
            return {'image': IMAGE, 'state': pin}
        def verify(value):
            self.assertEqual(value['state'], inspect_sqlite(self.path))
            events.append('verify-release')
        def failed_accept(value):
            events.append('failed-acceptance')
            self.assertEqual(value['image'], IMAGE)
            raise RuntimeError('injected candidate rejection')
        def candidate_start():
            events.append('candidate-start')
        def durable():
            return driver.fingerprint(driver.snapshot(self.path))
        with self.assertRaisesRegex(RuntimeError, 'candidate rejection'):
            stage.start_candidate(run, IMAGE, self.directory, self.pin, make_release, verify,
                                  candidate_start, failed_accept, durable)
        self.assertEqual(applied.read_text(), 'original')
        failed_path = self.path
        failed_bytes = failed_path.read_bytes()
        def original_start(directory):
            self.directory, self.path = directory, directory / 'platform.db'
            self.assertEqual(inspect_sqlite(self.path), self.pin)
            self.assertEqual(driver.snapshot(self.path), driver.snapshot(checkpoint))
            events.append('original-start')
        def original_accept(value):
            self.assertEqual(value['image'], old_image)
            events.append('original-acceptance')
            return {'status': 'ok'}
        stage.restore_original(lambda: events.append('stop'), checkpoint, self.root / 'restored',
                               receipt, previous, original_start, original_accept, durable, original_hash)
        self.assertEqual(applied.read_text(), 'original')
        self.assertEqual(failed_path.read_bytes(), failed_bytes)
        self.assertEqual(checkpoint.read_bytes(), checkpoint_bytes)
        def accepted(value):
            events.append('candidate-acceptance')
            return {'status': 'ok'}
        candidate, migration, _ = stage.start_candidate(
            run, IMAGE, self.directory, self.pin, make_release, verify, candidate_start, accepted, durable)
        self.assertEqual(candidate['state'], migration['candidate_state'])
        self.assertEqual(events, ['runtime-contract', 'migrate', 'candidate-pin', 'verify-release',
                                 'candidate-start', 'failed-acceptance', 'stop', 'original-start',
                                 'original-acceptance', 'runtime-contract', 'migrate', 'candidate-pin',
                                 'verify-release', 'candidate-start', 'candidate-acceptance'])
        self.assertEqual(self.original.read_bytes(), self.original_bytes)

    def test_driver_never_starts_candidate_after_migration_refusal(self):
        started = []
        self.contract['scripts']['4'] = '0' * 64
        with self.assertRaisesRegex(Conflict, 'candidate scripts'):
            stage.start_candidate(self.command, IMAGE, self.directory, self.pin,
                                  lambda pin: started.append('release'), lambda value: None,
                                  lambda: started.append('deploy'), lambda value: {}, lambda: '')
        self.assertEqual(started, [])

    def test_restore_checkpoint_tampering_refuses_before_output_is_created(self):
        receipt = {'state': self.pin, 'sha256': '0' * 64}
        output = self.root / 'restored'
        with self.assertRaisesRegex(Conflict, 'checkpoint changed'):
            driver.restore_copy(self.original, output, receipt)
        self.assertFalse(output.exists())

    def test_cross_schema_transition_does_not_weaken_production_contract(self):
        from test_release import ReleaseTests
        fixture = ReleaseTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        old = deepcopy(fixture.release)
        old['state']['platform'] = self.pin
        new = deepcopy(old)
        result = self.prepare()
        new['state']['platform'] = result['candidate_state']
        with self.assertRaises(Conflict):
            driver.transition(old, new, self.pin)
        self.assertFalse(driver.rehearsal_transition(old, new, self.pin, result['candidate_state'])
                         ['deploy_authorized'])
        self.assertFalse(driver.rehearsal_transition(old, old, self.pin, self.pin)['deploy_authorized'])
        new['contracts']['platform_api'] = 2
        with self.assertRaises(Conflict):
            driver.rehearsal_transition(old, new, self.pin, result['candidate_state'])
        with self.assertRaises(Conflict):
            driver.rehearsal_transition(old, old, self.pin, result['candidate_state'])



class StartupPreservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / 'platform.db'
        # Schema1 recorded the old startup mode only in audit. Migration2 creates
        # the control table and backfills that mode, so an off candidate must retain it.
        with closing(sqlite3.connect(self.path)) as db:
            db.executescript(state.MIGRATIONS[1])
            db.execute(f'PRAGMA application_id={state.APPLICATION_ID}')
            db.execute('PRAGMA user_version=1')
            db.execute("INSERT INTO audit(at,actor,operation,subject,detail) VALUES"
                       " ('2026-09-01T00:00:00+00:00','platform-runtime','notification.mode','platform',?)",
                       ('{"mode":"off"}',))
            db.commit()
        state.Store(self.path, migrate=True)
        self.before = driver.snapshot(self.path)
        self.assertEqual(self.before['rows']['notification_control'],
                         [('mode', 'off', '2026-09-01T00:00:00+00:00')])

    def boot(self, mode='off', require_off=True):
        from local_observe.platform.api import app_factory
        import os
        token = 'fixture-reader-' * 4
        credentials, policy = self.root / 'credentials.json', self.root / 'policy.json'
        credentials.write_text(json.dumps([{'identity': 'rehearsal-reader', 'role': 'reader', 'token': token}]))
        policy.write_text('{}')
        environment = {'LO_STATE_PATH': str(self.path), 'LO_PLATFORM_CREDENTIALS': str(credentials),
                       'LO_ACTION_POLICY': str(policy), 'LO_INDEX_PATH': str(self.root / 'absent.db'),
                       'LO_NOTIFICATION_MODE': mode}
        if mode is None:
            environment.pop('LO_NOTIFICATION_MODE')
        with mock.patch.dict(os.environ, environment, clear=True):
            app = app_factory()
            async def exercise():
                messages, started = asyncio.Queue(), asyncio.Event()
                async def send(message):
                    if message['type'] == 'lifespan.startup.complete':
                        started.set()
                task = asyncio.create_task(app({'type': 'lifespan'}, messages.get, send))
                try:
                    await messages.put({'type': 'lifespan.startup'})
                    await asyncio.wait_for(started.wait(), 10)
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                                 base_url='http://fixture') as client:
                        response = await client.get('/v1/runtime', headers={'Authorization': 'Bearer ' + token})
                    self.assertEqual(response.status_code, 200)
                    if require_off:
                        stage.require_off_runtime(response.json())
                finally:
                    await messages.put({'type': 'lifespan.shutdown'})
                    await asyncio.wait_for(task, 10)
            with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
                runner.run(exercise())
        return driver.snapshot(self.path)

    def start(self, accept):
        contract = {'version': state.VERSION, 'application_id': state.APPLICATION_ID,
                    'actor': state.MIGRATE_ACTOR,
                    'scripts': {str(k): state.digest(v) for k, v in state.MIGRATIONS.items()}}
        return stage.start_candidate(lambda *a, **kw: json.dumps(contract), IMAGE, self.root,
                                     inspect_sqlite(self.path), lambda pin: {'state': pin},
                                     lambda value: None, lambda: None, accept,
                                     lambda: driver.fingerprint(driver.snapshot(self.path)))

    def test_real_v1_migration_and_asgi_boot_keep_off_state_exactly_unchanged(self):
        def accept(_):
            self.boot()
            return {'status': 'ok'}
        _, migration, _ = self.start(accept)
        after = driver.snapshot(self.path)
        self.assertEqual(after, self.before)
        self.assertEqual(migration['durable_sha256'], driver.fingerprint(after))
        self.assertEqual(self.boot(), after)

    def test_real_mode_change_still_fails_the_complete_durable_comparison(self):
        def accept(_):
            self.boot(None, require_off=False)
            return {'status': 'ok'}
        with self.assertRaisesRegex(ValueError, 'durable state changed'):
            self.start(accept)
        after = driver.snapshot(self.path)
        self.assertNotEqual(after, self.before)
        self.assertEqual(len(after['rows']['audit']), len(self.before['rows']['audit']) + 1)

    def test_extra_control_or_audit_rows_are_not_exempted_after_real_startup(self):
        def accept(_):
            self.boot()
            with closing(sqlite3.connect(self.path)) as db:
                db.execute("INSERT INTO notification_control VALUES ('unexpected','off','2026-09-01T00:00:00Z')")
                db.execute("INSERT INTO audit(at,actor,operation,subject,detail) VALUES"
                           " ('2026-09-01T00:00:00Z','unexpected','extra','x','{}')")
                db.commit()
            return {'status': 'ok'}
        with self.assertRaisesRegex(ValueError, 'durable state changed'):
            self.start(accept)



if __name__ == '__main__':
    unittest.main()

import json
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest

from local_observe.deployment.content import Conflict
from local_observe.deployment.state_copy import _logical, copy_state


class StateCopyTests(unittest.TestCase):
    def test_verified_copies_do_not_claim_application_recovery_or_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root/'source'
            source.mkdir()
            (source/'cursor.json').write_text('{"pending":null,"secret":"not-in-report"}')
            with closing(sqlite3.connect(source/'state.db')) as db:
                db.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY, value BLOB)')
                db.execute('INSERT INTO evidence VALUES (1, ?)', (b'private-payload',))
                db.commit()
            inputs = {'cursor': (source/'cursor.json', 'json'), 'state': (source/'state.db', 'sqlite')}
            report = copy_state(inputs, root, root/'backup')
            self.assertTrue(report['copy_verified'])
            self.assertFalse(report['application_recovery_proven'])
            self.assertEqual(report['files']['state']['logical']['row_count'], 1)
            self.assertNotIn('private-payload', json.dumps(report))
            self.assertNotIn('not-in-report', json.dumps(report))
            with self.assertRaises(FileExistsError): copy_state(inputs, root, root/'backup')
            second = copy_state({'state': (root/'backup/state.db', 'sqlite')}, root, root/'restore')
            self.assertEqual(second['files']['state']['logical'], report['files']['state']['logical'])

    def test_scope_budget_and_malformed_json_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root/'source'
            source.mkdir()
            path = source/'cursor.json'
            path.write_text('{"pending":null}')
            inputs = {'cursor': (path, 'json')}
            for output, budget in ((source/'overlap', 100), (root/'too-small', 1)):
                with self.assertRaises(Conflict): copy_state(inputs, root, output, max_bytes=budget)
                self.assertFalse(output.exists())
            with self.assertRaises(Conflict): copy_state({'../escape': (path, 'json')}, root, root/'escape')
            path.write_text('invalid')
            with self.assertRaises(ValueError): copy_state(inputs, root, root/'invalid')
            self.assertEqual(path.read_text(), 'invalid')
            self.assertTrue((root/'invalid').is_dir())

    def test_a_live_wal_is_refused_and_only_an_explicit_checkpoint_carries_it(self):
        """A source whose `-wal` still holds the commit is copied only when the caller says so (state leftovers).

        The WAL is built the way it is in the field: a connection left open in WAL mode after a commit,
        so the newest pages live in the sidecar and nowhere else. `shutil.copy` of the `.db` alone is the
        failure the copy tool must refuse first — regression tests measured that such a snapshot opens as an empty
        platform and state migrations made the *migration* refuse it, which is after an operator has already carried
        the truncated copy away.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root/'source'
            source.mkdir()
            path = source/'state.db'
            with closing(sqlite3.connect(path)) as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY, value BLOB)')
                writer.execute('INSERT INTO evidence VALUES (1, ?)', (b'uncheckpointed-payload',))
                writer.commit()
                self.assertGreater((source/'state.db-wal').stat().st_size, 0, 'the commit is in the sidecar')
                shutil.copy(path, root/'bare.db')
                with closing(sqlite3.connect(root/'bare.db')) as alone:
                    tables = alone.execute("SELECT count(*) FROM sqlite_master WHERE name='evidence'").fetchone()[0]
                self.assertEqual(tables, 0, 'the row lives only in the -wal: a byte copy of the .db opens empty')
                inputs = {'state': (path, 'sqlite')}
                with self.assertRaisesRegex(Conflict, 'live WAL'):
                    copy_state(inputs, root, root/'refused')
                self.assertEqual([item.name for item in (root/'refused').iterdir()], [],
                                 'the refusal lands before any target file is opened')
                report = copy_state(inputs, root, root/'checkpointed', allow_checkpoint=True)
                self.assertEqual((source/'state.db-wal').stat().st_size, 0, 'TRUNCATE folded the sidecar in')
                with closing(sqlite3.connect(path)) as live:
                    self.assertEqual(report['files']['state']['logical'], _logical(live),
                                     'the copy carries the rows the source has now folded into its .db')
            self.assertEqual(report['files']['state']['logical']['row_count'], 1)

    def test_a_wal_or_shm_sidecar_is_never_an_input(self):
        """Copying a sidecar as bytes is the truncated snapshot itself, so it is refused by name."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root/'source'
            source.mkdir()
            with closing(sqlite3.connect(source/'state.db')) as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute('CREATE TABLE evidence (id INTEGER PRIMARY KEY)')
                writer.execute('INSERT INTO evidence VALUES (1)')
                writer.commit()
                for sidecar in ('state.db-wal', 'state.db-shm'):
                    self.assertTrue((source/sidecar).is_file(), sidecar)
                    with self.assertRaisesRegex(Conflict, 'sidecar'):
                        copy_state({sidecar.replace('.', '_'): (source/sidecar, 'sqlite')}, root, root/'sidecar')
                    self.assertFalse((root/'sidecar').exists())

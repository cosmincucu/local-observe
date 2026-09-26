"""Regression: the state file's own identity — schema version, foreign files, half-written state.

Ledger regression tests, from `docs/remediation/reports/REPORT_TESTS.md` §4 ("Schema migration / version upgrade
of the SQLite file — NOT COVERED AT ALL"). `local_observe/platform/state.py:88-98` refuses any file
whose `(application_id, user_version)` is not `(0x4C4F5001, 1)` unless it is completely empty, and
no test ever handed it a file at another version: the only related assertion pointed the store at
the inventory index database. The report's conclusion was that the first time `VERSION` is bumped
every existing operational database becomes unopenable and the suite stays green. Ledger state migrations is
the migration mechanism these tests describe the need for.

Dated note (2026-09-07, ledger control state): that first bump arrived, so "another schema version" can no
longer be the literals 2 and 3 — the numbers below are derived from `VERSION`, or this file would
begin passing by testing nothing. Version 1 is deliberately absent from the list: a v1 file is refused
too, but with the `lo-platform migrate` command named rather than this message, and that refusal is
`tests/test_state_migration.py` and `tests/test_control_state_migration.py` to assert.
"""
import datetime as dt
from contextlib import closing
import shutil
import sqlite3
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.detections import event
from local_observe.platform.state import APPLICATION_ID, VERSION, Actor, StateError, Store

NOW = timestamp('2026-09-06T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')


class StateFileIdentityTests(unittest.TestCase):
    """What the store must refuse to open, and what it must survive opening."""

    def setUp(self):
        """Open a scratch directory, plus the pragma shape of a store-created file for comparison."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.owned = self.pragmas(self.store('reference').path)

    def store(self, name: str) -> Store:
        """Return a fresh operational store at `<name>.db`, created by this test."""
        return Store(self.root / (name + '.db'))

    def pragmas(self, path: Path) -> tuple[int, int, int]:
        """Read `application_id`, `user_version` and the table count of a file with raw sqlite."""
        with closing(sqlite3.connect(path)) as connection:
            return (connection.execute('PRAGMA application_id').fetchone()[0],
                    connection.execute('PRAGMA user_version').fetchone()[0],
                    connection.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0])

    def fired(self, name: str) -> tuple[Store, Path]:
        """Create a store at `name`, intake one firing event, and return it with its path."""
        store = self.store(name)
        window = {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)}
        store.intake(event(PRODUCER.identity, None, 'availability', 'availability', 'firing', window,
                           {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=NOW)
        return store, store.path

    def reader(self, path: Path):
        """Hold a second read transaction open so committed frames stay in the `-wal` sidecar."""
        connection = sqlite3.connect(path, isolation_level=None)
        self.addCleanup(connection.close)
        connection.execute('BEGIN')
        connection.execute('SELECT count(*) FROM events')
        return connection

    def test_store_refuses_a_database_written_by_another_schema_version(self):
        """A `user_version` of 0 or of any version newer than this build must be refused, left as found."""
        for version in (0, VERSION + 1, VERSION + 2):
            store, path = self.fired('version-%d' % version)
            self.assertEqual(self.pragmas(path), (APPLICATION_ID, VERSION, self.owned[2]))
            with closing(sqlite3.connect(path)) as connection:
                connection.execute('PRAGMA user_version=%d' % version)
                connection.commit()
            with self.subTest(version=version):
                with self.assertRaisesRegex(StateError, 'restore or migrate'):
                    Store(path)
                # Refusing must not mean rewriting: no silent migration, no truncation, no re-schema.
                self.assertEqual(self.pragmas(path), (APPLICATION_ID, version, self.owned[2]))
                with closing(sqlite3.connect(path)) as connection:
                    self.assertEqual(connection.execute('SELECT count(*) FROM events').fetchone()[0], 1)
                    self.assertEqual(connection.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
                self.assertEqual(store.status()['incidents'], {'open': 1})

    def test_store_refuses_a_plain_sqlite_file_it_did_not_create(self):
        """`application_id = 0` with any table in it belongs to somebody else (`state.py:92-93`)."""
        path = self.root / 'foreign.db'
        with closing(sqlite3.connect(path)) as connection:
            connection.execute('CREATE TABLE somebody_else (id INTEGER PRIMARY KEY, note TEXT)')
            connection.execute("INSERT INTO somebody_else(note) VALUES ('not platform state')")
            connection.commit()
        self.assertEqual(self.pragmas(path), (0, 0, 1))
        with self.assertRaisesRegex(StateError, 'restore or migrate'):
            Store(path)
        self.assertEqual(self.pragmas(path), (0, 0, 1))
        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(connection.execute('SELECT note FROM somebody_else').fetchone()[0], 'not platform state')

    def test_a_zero_length_file_is_the_one_case_the_store_may_own(self):
        """The `(0, 0, 0)` exemption must create the platform schema and nothing else."""
        path = self.root / 'fresh.db'
        path.touch()
        self.assertEqual(self.pragmas(path), (0, 0, 0))
        store = Store(path)
        self.assertEqual(self.pragmas(path), (APPLICATION_ID, VERSION, self.owned[2]))
        self.assertEqual(store.status(), {'schema_version': VERSION, 'incidents': {}, 'actions': {},
                                          'notifications': {}})

    def test_a_rolled_back_transaction_from_a_killed_writer_leaves_no_state(self):
        """A `BEGIN IMMEDIATE` that dies before COMMIT must not open, nor leave its row behind."""
        store, path = self.fired('killed')
        self.assertEqual([row['operation'] for row in store.records('audit')], ['event.intake'])
        writer = sqlite3.connect(path, isolation_level=None)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        writer.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                       (utc_text(NOW), 'crash-probe', 'killed-writer-probe', 'probe', '{}'))
        self.assertTrue(writer.in_transaction)
        writer.close()  # the process "dies" here, and SQLite discards the open transaction

        reopened = Store(path)
        operations = [row['operation'] for row in reopened.records('audit')]
        self.assertNotIn('killed-writer-probe', operations, 'an uncommitted audit row survived the rollback')
        self.assertEqual(operations, ['event.intake'], 'committed history must survive untouched')
        self.assertEqual(reopened.status(), store.status())

    def test_a_copy_of_the_database_after_a_clean_close_is_complete(self):
        """With no other connection open, Store checkpoints the WAL and deletes the sidecar."""
        store, path = self.fired('clean-copy')
        sidecars = [item.name for item in self.root.iterdir() if item.name.startswith(path.name + '-')]
        self.assertEqual(sidecars, [], 'a live -wal sidecar was left behind by a closed store')
        copy = self.root / 'clean-copy.bin'
        shutil.copyfile(path, copy)
        self.assertEqual(Store(copy).status(), store.status())

    def forge_incomplete(self, path: Path) -> Path:
        """Return a copy of `path` whose header demands a `-wal` that this copy does not have.

        SQLite marks a self-contained database by copying its change counter (bytes 24..27) into the
        version-valid-for number (bytes 92..95); a mismatch is what those two fields exist to describe
        — content that only the `-wal` still has. The window is at SQLite's own page-write boundary,
        so no test here can stop inside it (killing writers mid-checkpoint produced none of them in
        40 attempts); the mismatch is therefore forged on a copy, one 4-byte field, and the identical
        untouched file is asserted to open just above so the refusal cannot be about anything else.
        """
        damaged = self.root / (path.name + '.orphaned')
        shutil.copyfile(path, damaged)
        header = bytearray(damaged.read_bytes()[:100])
        header[92:96] = (int.from_bytes(header[92:96], 'big') + 1).to_bytes(4, 'big')
        damaged.write_bytes(bytes(header) + damaged.read_bytes()[100:])
        return damaged

    def test_a_database_that_needs_a_wal_it_does_not_have_is_refused(self):
        """state migrations chose the fail-closed answer: a WAL-mode file whose header says its sidecar is still
        needed is refused when that sidecar is absent, rather than opening as a healthy-looking older
        platform. A complete file — the copy a clean close leaves behind — has matching counters and
        opens unchanged; `test_a_copy_of_the_database_after_a_clean_close_is_complete` asserts that for
        the general case and the first lines here assert it for this very file before damaging it.

        The limit of that check, measured on SQLite 3.49.1 while deciding it: while committed frames
        sit in the `-wal` the main file keeps its own counters as they were at the last checkpoint, so
        a copy taken over a running writer is *self-consistent and missing rows*, and nothing inside
        the `.db` can reveal it. That case is why CONTRACTS §7 requires the online backup API for a
        live database, and why `lo-platform backup` — `test_backup_captures_state_the_wal_still_holds`
        — stays the only copy method an operator may use on a running platform.
        """
        store, path = self.fired('wal-copy')
        complete = self.root / 'wal-copy.bin'
        self.reader(path)
        shutil.copyfile(path, complete)
        self.assertEqual(Store(complete).status(), store.status())

        damaged = self.forge_incomplete(complete)
        before = damaged.read_bytes()
        with self.assertRaisesRegex(StateError, 'incomplete without its -wal'):
            Store(damaged)
        self.assertEqual(damaged.read_bytes(), before, 'refusing must not mean rewriting the only copy')
        self.assertEqual(self.pragmas(damaged), (APPLICATION_ID, VERSION, self.owned[2]))

    def test_backup_captures_state_the_wal_still_holds(self):
        """`Store.backup()` is the copy that survives the same live-reader conditions."""
        store, path = self.fired('live-backup')
        self.reader(path)
        destination = self.root / 'live-backup-copy.db'
        store.backup(destination)
        restored = Store(destination)
        self.assertEqual(restored.status(), store.status())
        self.assertEqual([row['id'] for row in restored.records('outbox')],
                         [row['id'] for row in store.records('outbox')])
        self.assertEqual(self.pragmas(destination), (APPLICATION_ID, VERSION, self.owned[2]))


if __name__ == '__main__':
    unittest.main()

"""The verification history reader: boundary tests for `Store.list_verifications`, drafted from CONTRACT.md alone.

No `verification_reader.py` exists in this tree and no other worker's draft was read, so every assertion
is about the observable contract and never about a SQL alias, a helper name or a column order (planted
history is inserted by the column names read back from `PRAGMA table_info`). Covered: role and argument
refusals before any open (counting `sqlite3.connect`, with a control that the counter can see one),
exact-64 versus corrupt-65/huge/nontext/invalid ids, an absent file, tables or index, no payload bytes
transferred, a closed read-only connection that never asks for the write lock, and a step cost that
tracks the <=64 rows wanted rather than the 20 000 unrelated ones. The real lifecycle fixtures come from
`tests/test_verification_records`, imported as a module so its own test classes are never collected twice.
"""
import datetime as dt
from contextlib import closing
import re
import sqlite3
import sys
import tracemalloc
import unittest
import uuid
from pathlib import Path
from unittest import mock

from local_observe.inventory.validation import canonical
from local_observe.platform import verification_reader
from local_observe.platform.state import Actor

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_verification_records as scenario  # noqa: E402

CAP = 64
UNRELATED = 20_000
PAYLOAD_BYTES = 32 * 1024
PROGRESS = 10
SENTINEL = 'sentinel-never-transferred'
HEX64 = re.compile(r'\A[0-9a-f]{64}\Z')
READER, HUMAN, AGENT, RUNNER = scenario.READER, scenario.HUMAN, scenario.AGENT, scenario.RUNNER
VERIFIER, UNLISTED, SUMMARY = scenario.VERIFIER, scenario.UNLISTED, scenario.SUMMARY
PROPOSE_NOW, TERMINAL, RECORD_NOW = scenario.PROPOSE_NOW, scenario.TERMINAL, scenario.RECORD_NOW
WINDOW_SECONDS = scenario.WINDOW_SECONDS
# Every one of these must refuse the whole list: such a row is unusable, never a row to skip over.
CORRUPT = (('65-hex', 'a' * 64 + 'b'), ('63-hex', 'a' * 63), ('uppercase', 'A' * 64),
           ('non-hex', 'g' * 64), ('huge', 'a' * 4096), ('empty', ''), ('integer', 12345),
           ('bad-utf8-blob', b'\xff' * 64), ('null', None))


def hex_id(number: int) -> str:
    return '%064x' % number


class Opened:
    """Observe every `sqlite3.connect` made while the block runs: its arguments and the connection."""

    ARGUMENTS = ('database', 'timeout', 'detect_types', 'isolation_level', 'check_same_thread',
                 'factory', 'cached_statements', 'uri')

    def __init__(self, steps=None):
        self.calls, self.steps, self.connect = [], steps, sqlite3.connect

    def __enter__(self):
        def connect(*args, **kwargs):
            connection = self.connect(*args, **kwargs)
            if self.steps is not None:
                connection.set_progress_handler(lambda: self.steps.append(1) or 0, PROGRESS)
            self.calls.append((args, kwargs, connection))
            return connection
        self.patch = mock.patch('sqlite3.connect', side_effect=connect)
        self.patch.start()
        return self

    def __exit__(self, *exc_info):
        self.patch.stop()
        return False

    def bound(self, call):
        args, kwargs, _connection = call
        return dict(dict(zip(self.ARGUMENTS, args)), **kwargs)


class BoundaryTests(scenario.VerificationFixture):
    """`Store.list_verifications` and `verification_reader.list_records`, at their boundaries."""

    def planted(self, execution_id, verification_id, payload='{}'):
        return {'verification_id': verification_id, 'execution_id': execution_id, 'recorded_by': 'fixture',
                'fingerprint': 'f' * 64, 'payload': payload, 'verdict': 'unknown', 'reason': 'planted',
                'recorded_at': '2026-09-08T12:30:00Z'}

    def plant_many(self, store, rows):
        """Append record rows by column name: the corrupt and unrelated history no write path produces."""
        with closing(sqlite3.connect(store.path)) as db:
            columns = [item[1] for item in db.execute('PRAGMA table_info(verification_records)')]
            db.executemany('INSERT INTO verification_records(%s) VALUES (%s)'
                           % (','.join(columns), ','.join(['?'] * len(columns))),
                           [tuple(row[name] for name in columns) for row in rows])
            db.commit()

    def plant(self, store, execution_id, verification_id, payload='{}'):
        self.plant_many(store, [self.planted(execution_id, verification_id, payload)])

    def scan(self, store, execution):
        """Steps SQLite needs to find this execution's rows with the index defeated: the cost scale."""
        steps = []
        with closing(sqlite3.connect(store.path)) as db:
            db.set_progress_handler(lambda: steps.append(1) or 0, PROGRESS)
            found = db.execute('SELECT verification_id FROM verification_records '
                               'WHERE substr(execution_id, 1, 36)=?', (execution,)).fetchall()
        self.assertEqual(len(found), CAP, 'the control scan did not read the rows the read must want')
        return len(steps) * PROGRESS

    def test_the_reader_roles_and_the_currently_allowlisted_producer_may_list(self):
        case = self.executed(self.bound('roles'))
        issued = self.put(case)['verification_id']
        for actor in (READER, HUMAN, AGENT, RUNNER, VERIFIER):
            self.assertEqual(case['store'].list_verifications(case['execution_id'], actor), [issued])
        off = self.executed(self.bound('roles-off', policy=None))
        self.plant(off['store'], off['execution_id'], hex_id(7))
        self.assertEqual(off['store'].list_verifications(off['execution_id'], READER), [hex_id(7)],
                         'an ordinary reader must not need a verification policy mounted')
        denied = (VERIFIER, SUMMARY, UNLISTED, Actor('observer', 'watcher'), Actor('', 'reader'),
                  Actor('bad identity', 'reader'), READER.identity, None)
        with Opened() as seen:
            for actor in denied:
                store = off['store'] if actor is VERIFIER else case['store']
                execution = off['execution_id'] if actor is VERIFIER else case['execution_id']
                seen.calls.clear()
                self.refused(lambda store=store, execution=execution, actor=actor:
                             store.list_verifications(execution, actor))
                self.assertEqual(len(seen.calls), 0, 'a refused actor opened a database to be refused')
            case['store'].get_verification(issued, READER)
            self.assertGreater(len(seen.calls), 0, 'the observer saw no open at all, so it proved nothing')

    def test_an_execution_id_that_is_not_canonical_uuid_text_is_refused_before_any_open(self):
        case = self.executed(self.bound('bad-id'))
        wanted = case['execution_id']
        for value in (None, 1, True, 3.5, [], {}, b'', uuid.UUID(wanted), wanted.upper(), wanted[:-1],
                      wanted + '0', wanted.replace('-', ''), '{' + wanted + '}', 'x' * 36,
                      'sentinel-probe' + 'x' * 22, wanted + ' /tmp/private/state.db'):
            with Opened() as seen:
                self.refused(lambda value=value: case['store'].list_verifications(value, READER),
                             *([value] if isinstance(value, str) else ()))
                self.assertEqual(len(seen.calls), 0, f'list_verifications({value!r}) opened a database')

    def test_discovery_answers_sorted_readable_ids_for_the_execution_named_and_no_other(self):
        """Every id returned is a real id the existing reader can read, and only for the id asked about."""
        case = self.executed(self.bound('answer'))
        store = case['store']
        first = self.put(case)['verification_id']
        second = self.put(case, outcome='unavailable', receipt=None, samples=[], window=self.window(
            case, ends_at=RECORD_NOW - dt.timedelta(minutes=2)))['verification_id']
        listed = store.list_verifications(case['execution_id'], READER)
        self.assertIsInstance(listed, list)
        self.assertEqual(sorted(listed), sorted([first, second]))
        self.assertEqual(listed, sorted(listed), 'the answer is not lexical ascending')
        self.assertTrue(all(isinstance(item, str) and HEX64.fullmatch(item) for item in listed),
                        'discovery returned something that is not a lowercase SHA-256 id')
        for item in listed:
            self.assertEqual(store.get_verification(item, READER)['execution_id'], case['execution_id'],
                             'a discovered id does not read back through the existing reader')
        self.assertEqual(verification_reader.list_records(store, case['execution_id'], READER), listed)
        again = store.list_verifications(case['execution_id'], READER)
        self.assertIsNot(again, listed, 'one list object is handed to every caller')
        again.append('tampered')
        self.assertEqual(store.list_verifications(case['execution_id'], READER), listed)
        fired = self.fire(store, minute=1)
        other, _ = self.propose(store, case['incident_id'], [fired['event_id']], retry_key='other')
        store.decide(other['action_id'], 'approved', HUMAN, now=PROPOSE_NOW)
        running = store.claim_action(other['action_id'], RUNNER, self.gate, now=TERMINAL)
        self.assertEqual(store.list_verifications(running['execution_id'], READER), [],
                         'an executing run is not discoverable; it is usually empty')
        self.plant(store, running['execution_id'], hex_id(9))
        self.assertEqual(store.list_verifications(running['execution_id'], READER), [hex_id(9)],
                         'executing status is refused, though the contract allows it for discovery')
        self.assertEqual(store.list_verifications(case['execution_id'], READER), listed,
                         'one discovery borrowed another executions rows')
        self.refused(lambda: store.list_verifications(str(uuid.uuid4()), READER))

    def test_the_read_opens_closed_read_only_connections_and_writes_nothing(self):
        """One `BEGIN` read while a real writer holds the write lock, and the file does not move."""
        case = self.executed(self.bound('readonly'))
        store, execution = case['store'], case['execution_id']
        self.put(case)
        with closing(sqlite3.connect(store.path)) as db:
            db.execute('PRAGMA journal_mode=DELETE')
        before, audits = store.path.read_bytes(), len(store.records('audit', 100))
        writer = sqlite3.connect(store.path, timeout=10)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        with closing(sqlite3.connect(store.path, timeout=0.05)) as blocked:
            self.assertRaises(sqlite3.OperationalError, blocked.execute, 'BEGIN IMMEDIATE')
        with Opened() as seen:
            listed = store.list_verifications(execution, READER)
        writer.close()
        self.assertEqual(len(listed), 1, 'a read that asked for the write lock could not answer here')
        self.assertGreater(len(seen.calls), 0, 'no connection was opened, so nothing below was proved')
        for call in seen.calls:
            opened = seen.bound(call)
            target = str(opened['database'])
            self.assertTrue(target.startswith('file:') and target.endswith(f'/{store.path.name}?mode=ro'),
                            target)
            self.assertTrue(opened['uri'], 'a read-only URI needs uri=True to mean anything')
            self.assertIsNone(opened['isolation_level'], 'BEGIN is only a read mark under autocommit')
            self.assertEqual(float(opened.get('timeout', 0)), 10)
            self.assertRaises(sqlite3.ProgrammingError, call[2].execute, 'SELECT 1')
        self.assertEqual(store.path.read_bytes(), before, 'a discovery read wrote to the file')
        self.assertEqual(len(store.records('audit', 100)), audits, 'a discovery read audited itself')
        self.assertFalse(Path(str(store.path) + '-wal').exists())

    def test_an_absent_file_missing_tables_or_missing_index_refuses_and_repairs_nothing(self):
        """No migration, no created file, no scan fallback: the read names a schema failure and stops."""
        for shape in ('absent', 'no-tables', 'no-index'):
            case = self.executed(self.bound(shape))
            store, path = case['store'], case['store'].path
            recorded = self.put(case)['verification_id']
            self.assertEqual(store.list_verifications(case['execution_id'], READER), [recorded])
            with closing(sqlite3.connect(path)) as db:
                # Isolate persistent-byte assertions from SQLite's permissible WAL/shm bookkeeping.
                db.execute('PRAGMA journal_mode=DELETE')
                indexes = [row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' "
                    "AND tbl_name='verification_records' AND name NOT LIKE 'sqlite_%'")]
                if shape == 'no-tables':
                    db.executescript('DROP TABLE verification_records; DROP TABLE verification_bindings')
                elif shape == 'no-index':
                    self.assertTrue(indexes, 'the fixture file carries no execution index to attack')
                    db.executescript('DROP INDEX "%s"' % indexes[0])
            if shape == 'absent':
                path.unlink()
            present = sorted(item.name for item in self.root.iterdir())
            before = None if shape == 'absent' else path.read_bytes()
            with Opened() as seen:
                sentence = self.refused(lambda: store.list_verifications(case['execution_id'], READER))
            for call in seen.calls:
                self.assertRaises(sqlite3.ProgrammingError, call[2].execute, 'SELECT 1')
            self.assertFalse(any(character in sentence for character in ('/', '\\', str(self.root))))
            self.assertEqual(sorted(item.name for item in self.root.iterdir()), present,
                             f'{shape}: the read added or removed a file beside the database')
            if before is None:
                self.assertFalse(path.exists(), f'{shape}: the read created the operational database')
            else:
                self.assertEqual(path.read_bytes(), before,
                                 f'{shape}: the read migrated or rewrote a file it was only asked to read')

    def test_one_unusable_id_row_refuses_the_whole_list_rather_than_being_repaired_or_skipped(self):
        for label, value in CORRUPT:
            case = self.executed(self.bound('corrupt-' + label))
            good = self.put(case)['verification_id']
            self.assertEqual(case['store'].list_verifications(case['execution_id'], READER), [good])
            self.plant(case['store'], case['execution_id'], value)
            self.refused(lambda case=case: case['store'].list_verifications(case['execution_id'], READER))

    def test_sixty_four_ids_come_back_in_lexical_order_and_a_65th_row_refuses_not_truncates(self):
        case = self.executed(self.bound('cap'))
        issued = [self.put(case, outcome='unavailable', receipt=None, samples=[],
                           window=self.window(case, ends_at=RECORD_NOW - dt.timedelta(
                               seconds=WINDOW_SECONDS * offset)))['verification_id']
                  for offset in range(CAP)]
        listed = case['store'].list_verifications(case['execution_id'], READER)
        self.assertEqual(len(set(issued)), CAP, 'the fixture wrote fewer than 64 distinct records')
        self.assertEqual(listed, sorted(issued), 'the 64-record bound is not what this read honours')
        self.assertNotEqual(listed, issued, 'the answer is chronology, not the sorted ids promised')
        self.plant(case['store'], case['execution_id'], hex_id(9000))
        self.refused(lambda: case['store'].list_verifications(case['execution_id'], READER))

    def test_listing_a_wide_history_transfers_ids_only_and_never_the_stored_payloads(self):
        case = self.executed(self.bound('payload'))
        store, execution = case['store'], case['execution_id']
        wide = canonical({'marker': SENTINEL, 'pad': 'p' * PAYLOAD_BYTES})
        self.plant_many(store, [self.planted(execution, hex_id(i), wide) for i in range(CAP)])
        tracemalloc.start()
        listed = store.list_verifications(execution, READER)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertEqual(sorted(listed), sorted(hex_id(i) for i in range(CAP)))
        self.assertNotIn(SENTINEL, repr(listed), 'a stored payload reached the answer')
        self.assertLess(peak, 512 * 1024, f'{CAP} stored payloads cost {peak} bytes while listing ids')
        tracemalloc.start()
        document = store.get_verification(listed[0], READER)
        control = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        self.assertIn(SENTINEL, repr(document), 'the planted bytes are not in the stored row at all')
        self.assertGreaterEqual(control, PAYLOAD_BYTES, 'this measurement cannot see payload bytes')

    def test_the_query_cost_follows_the_rows_it_wants_and_not_the_unrelated_history_around_it(self):
        case = self.executed(self.bound('cost'))
        store, execution = case['store'], case['execution_id']
        wanted = [hex_id(i) for i in range(CAP)]
        self.plant_many(store, [self.planted(execution, item) for item in wanted] + [
            self.planted('%036x' % (20_000 + index), hex_id(100_000 + index))
            for index in range(UNRELATED)])
        steps = []
        with Opened(steps) as seen:
            listed = store.list_verifications(execution, READER)
        self.assertEqual(listed, sorted(wanted))
        self.assertGreater(len(seen.calls), 0)
        read = len(steps) * PROGRESS
        self.assertLess(read, 30_000, f'the read spent {read} SQLite steps looking for {CAP} ids')
        self.assertLess(read * 10, self.scan(store, execution),
                        'discovery cost grew with unrelated history: the index was not used')


if __name__ == '__main__':
    unittest.main()

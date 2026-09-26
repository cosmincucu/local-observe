"""Fair bounded RCA progress, including restart, corrupt state and known incident refusals."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from local_observe.inventory.validation import timestamp
from local_observe.platform import rca, rca_progress
from local_observe.platform.detections import event
from local_observe.platform.owner import exclusive_owner
from local_observe.platform.state import Actor, Store, ESCALATION_INCIDENTS_INDEX

NOW = timestamp('2026-09-09T12:00:00Z')
WINDOW = {'start': '2026-09-09T11:58:00Z', 'end': '2026-09-09T11:59:00Z'}
PRODUCER = Actor('progress-detector', 'producer')
SOURCE = 'progress-rca'


class ProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.number = 0

    def add(self, count: int) -> list[str]:
        for _ in range(count):
            self.number += 1
            rule = f'progress.{self.number}'
            self.store.intake(event(PRODUCER.identity, None, rule, 'availability', 'firing', WINDOW,
                                    {'rule_id': rule}, query_type='gatus-result'), PRODUCER, now=NOW)
        with closing(sqlite3.connect(self.store.path)) as connection:
            return [row[0] for row in connection.execute('SELECT id FROM incidents ORDER BY rowid')]

    def tick(self, limit: int = 5, **kwargs) -> dict:
        return rca.tick(self.store, config={'max_incidents': limit}, source=SOURCE, now=NOW, **kwargs)

    def cursor(self) -> Path:
        return rca_progress.location(self.store.path, SOURCE)

    def test_six_incidents_across_restart_finish_before_any_revisit(self) -> None:
        ids = self.add(6)
        first = self.tick()
        self.assertEqual(first['written'], 5)
        self.assertTrue(first['capped'])
        self.assertEqual(first['incidents_read'], 6)
        self.assertEqual(first['count_scope'], 'page')
        self.store = Store(self.store.path)  # New caller; progress must come from disk.
        second = self.tick()
        self.assertEqual([row['incident_id'] for row in second['results']], ids[5:])
        self.assertEqual(second['written'], 1)
        self.assertTrue(second['cycle_complete'])
        third = self.tick()
        self.assertEqual(third['unchanged'], 5)
        self.assertEqual(third['written'], 0)
        self.assertTrue(all(rca.read_latest(self.store, one) for one in ids))

    def test_more_than_100_incidents_and_new_arrivals_wait_for_the_next_fixed_cycle(self) -> None:
        ids = self.add(106)
        visited = [row['incident_id'] for row in self.tick(25)['results']]
        all_ids = self.add(3)
        for _ in range(4):
            result = self.tick(25)
            self.assertLessEqual(result['attempted'], 25)
            self.assertLessEqual(result['incidents_read'], 26)
            visited.extend(row['incident_id'] for row in result['results'])
        self.assertEqual(visited, ids)
        self.assertTrue(result['cycle_complete'])
        second_cycle = []
        for _ in range(5):
            second_cycle.extend(row['incident_id'] for row in self.tick(25)['results'])
        self.assertEqual(second_cycle, all_ids)
        self.assertTrue(all(rca.read_latest(self.store, one) for one in all_ids))

    def test_a_failed_incident_is_visible_and_does_not_starve_other_incidents(self) -> None:
        ids = self.add(6)
        with self.store.transaction() as connection:
            connection.execute('UPDATE incidents SET resource_id=? WHERE id=?', ('broken', ids[0]))
        with self.assertLogs('local_observe.platform.rca', level='WARNING') as logs:
            first = self.tick()
        self.assertEqual(first['failed'], 1)
        self.assertEqual(first['attempted'], 5)
        self.assertEqual(first['analyzed'], 4)
        self.assertEqual(first['failures'][0]['incident_id'], ids[0])
        self.assertIn('continuing the cycle', logs.output[0])
        self.assertEqual(self.tick()['results'][0]['incident_id'], ids[-1])
        self.assertIsNone(rca.read_latest(self.store, ids[0]))
        self.assertTrue(all(rca.read_latest(self.store, one) for one in ids[1:]))
        with self.store.transaction() as connection:
            connection.execute('UPDATE incidents SET resource_id=NULL WHERE id=?', (ids[0],))
        self.assertEqual(self.tick()['failed'], 0)
        self.assertIsNotNone(rca.read_latest(self.store, ids[0]))

    def test_crash_between_audit_and_progress_replays_idempotently_after_restart(self) -> None:
        ids = self.add(2)
        with patch.object(rca_progress.Progress, 'advance', side_effect=OSError('fixture crash')):
            with self.assertRaises(OSError):
                self.tick()
        self.assertIsNotNone(rca.read_latest(self.store, ids[0]))
        self.assertIsNone(rca.read_latest(self.store, ids[1]))
        result = self.tick()
        self.assertEqual((result['unchanged'], result['written']), (1, 1))

    def test_unknown_programming_error_is_not_silently_swallowed(self) -> None:
        self.add(1)
        with patch.object(rca, 'analyze', side_effect=RuntimeError('fixture bug')):
            with self.assertRaises(RuntimeError):
                self.tick()
        self.assertEqual(json.loads(self.cursor().read_text())['after'], 0)

    def test_read_connection_is_closed_before_analysis_and_model_budget_stays_bounded(self) -> None:
        self.add(6)
        opened = []
        connect, analyze = sqlite3.connect, rca.analyze
        budgets = []

        def tracked(database, *args, **kwargs):
            connection = connect(database, *args, **kwargs)
            if str(database).endswith('?mode=ro'):
                opened.append(connection)
            return connection

        def checked(*args, **kwargs):
            self.assertTrue(opened)
            for connection in opened:
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute('SELECT 1')
            budgets.append(kwargs['config']['max_model_calls'])
            return analyze(*args, **kwargs)

        with patch.object(rca_progress.sqlite3, 'connect', side_effect=tracked), \
                patch.object(rca, 'analyze', side_effect=checked):
            rca.tick(self.store, config={'max_incidents': 5, 'max_model_calls': 2}, source=SOURCE, now=NOW)
        self.assertEqual(budgets, [2, 1, 0, 0, 0])

    def test_closed_history_uses_index_seeks_and_cannot_exhaust_the_page_budget(self) -> None:
        ids = self.add(6)
        with self.store.transaction() as connection:
            event_id = connection.execute('SELECT id FROM events LIMIT 1').fetchone()[0]
            connection.executemany(
                'INSERT INTO incidents VALUES(?,?,NULL,\'resolved\',?,?,?)',
                [(str(uuid4()), f'closed-{number}', NOW.isoformat(), NOW.isoformat(), event_id)
                 for number in range(10_000)])
        with closing(sqlite3.connect(self.store.path)) as connection:
            for sql, parameters in [(rca_progress.HIGH_WATER_SQL, ()),
                                    (rca_progress.PAGE_SQL, (0, 2**63 - 1, 6))]:
                plans = [row[3] for row in connection.execute('EXPLAIN QUERY PLAN ' + sql, parameters)]
                self.assertTrue(any(ESCALATION_INCIDENTS_INDEX in plan for plan in plans), plans)
                self.assertFalse(any('SCAN incidents' in plan or 'TEMP B-TREE' in plan for plan in plans), plans)
        self.assertEqual([row['incident_id'] for row in self.tick()['results']], ids[:5])
        self.assertEqual([row['incident_id'] for row in self.tick()['results']], ids[5:])
        # A deliberately insufficient VM budget must refuse discovery without moving the cursor.
        before = self.cursor().read_bytes()
        with patch.object(rca_progress, 'READ_INSTRUCTIONS', 0):
            with self.assertRaises(rca_progress.ProgressError):
                self.tick()
        self.assertEqual(self.cursor().read_bytes(), before)

    def test_closed_tail_completes_cycle_and_next_tick_restarts(self) -> None:
        ids = self.add(6)
        self.tick()
        with self.store.transaction() as connection:
            connection.execute("UPDATE incidents SET status='resolved' WHERE id=?", (ids[-1],))
        result = self.tick()
        self.assertEqual(result['attempted'], 0)
        self.assertTrue(result['cycle_complete'])
        self.assertEqual(self.tick()['unchanged'], 5)

    def test_source_paths_and_database_bindings_are_distinct_and_foreign_cursor_is_refused(self) -> None:
        self.add(1)
        self.tick()
        self.assertNotEqual(self.cursor(), rca_progress.location(self.store.path, 'other-source'))
        self.assertNotIn(SOURCE, self.cursor().name)
        other = Store(self.root / 'other.db')
        foreign = rca_progress.location(other.path, SOURCE)
        foreign.write_bytes(self.cursor().read_bytes())
        before = foreign.read_bytes()
        with self.assertRaises(rca_progress.ProgressError):
            rca.tick(other, config={}, source=SOURCE, now=NOW)
        self.assertEqual(foreign.read_bytes(), before)

    def test_corrupt_oversized_duplicate_and_foreign_cursor_refusals_preserve_bytes(self) -> None:
        self.add(1)
        self.tick()
        valid = json.loads(self.cursor().read_text())
        documents = [b'{', b'x' * (rca_progress.MAX_CURSOR_BYTES + 1),
                     b'{"schema_version":1,"schema_version":1}',
                     json.dumps(dict(valid, after=True)).encode(),
                     json.dumps(dict(valid, after=-1)).encode(),
                     json.dumps(dict(valid, after=valid['high_water'] + 1)).encode(),
                     json.dumps(dict(valid, schema_version=True)).encode(),
                     json.dumps(dict(valid, source='foreign')).encode(),
                     json.dumps(dict(valid, extra=1)).encode()]
        for document in documents:
            with self.subTest(document=document[:80]):
                self.cursor().write_bytes(document)
                with self.assertRaises(rca_progress.ProgressError):
                    self.tick()
                self.assertEqual(self.cursor().read_bytes(), document)

    def test_owner_contention_refuses_before_analyzing_or_changing_progress(self) -> None:
        self.add(1)
        with exclusive_owner(self.cursor()):
            with patch.object(rca, 'analyze') as analyze:
                with self.assertRaises(OSError):
                    self.tick()
                analyze.assert_not_called()
        self.assertFalse(self.cursor().exists())
        self.assertEqual(self.tick()['written'], 1)

    def test_symlink_cursor_lock_and_database_ancestry_are_refused_without_touching_targets(self) -> None:
        self.add(1)
        targets = [self.cursor(), Path(str(self.cursor()) + '.owner.lock'), self.store.path.parent]
        real = Path.is_symlink
        for target in targets:
            with self.subTest(target=target.name):
                with patch.object(Path, 'is_symlink', lambda path: path == target or real(path)), \
                        patch.object(rca, 'analyze') as analyze:
                    with self.assertRaises(rca_progress.ProgressError):
                        self.tick()
                    analyze.assert_not_called()
        self.assertFalse(self.cursor().exists())

    def test_lost_derived_cursor_restarts_without_duplicate_explanation_rows(self) -> None:
        self.add(6)
        self.tick()
        self.cursor().unlink()  # Explicit isolated restore/reset scenario, after both owners exited.
        self.assertEqual(self.tick()['unchanged'], 5)
        self.assertEqual(self.tick()['written'], 1)
        with closing(sqlite3.connect(self.store.path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM audit WHERE operation='rca.explained'")
                             .fetchone()[0], 6)

    def test_same_path_older_database_restore_finishes_stale_tail_then_revisits_retained_incidents(self) -> None:
        ids = self.add(2)
        snapshot = self.root / 'older-state.db'
        with closing(sqlite3.connect(self.store.path)) as current, \
                closing(sqlite3.connect(snapshot)) as older:
            current.backup(older)
        self.add(4)
        self.tick()
        self.assertEqual(json.loads(self.cursor().read_text())['after'], 5)
        self.assertEqual(json.loads(self.cursor().read_text())['high_water'], 6)
        # All fixture owners exited. Restore older DB contents to the same canonical path, retaining
        # the newer derived cursor exactly as a separately restored sidecar can arrive.
        before = self.cursor().read_bytes()
        with closing(sqlite3.connect(snapshot)) as older, \
                closing(sqlite3.connect(self.store.path)) as current:
            older.backup(current)
        self.store = Store(self.store.path)
        self.assertEqual(self.cursor().read_bytes(), before)
        tail = self.tick()
        self.assertEqual(tail['attempted'], 0)
        self.assertTrue(tail['cycle_complete'])
        self.assertEqual(json.loads(self.cursor().read_text())['after'], 6)
        restarted = self.tick()
        self.assertEqual([row['incident_id'] for row in restarted['results']], ids)
        self.assertEqual(restarted['written'], 2)


if __name__ == '__main__':
    unittest.main()

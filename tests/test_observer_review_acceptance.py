"""Independent acceptance of review concurrency, bounded reads and existing-state opens."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
import threading
from unittest.mock import patch

from local_observe.observer.contract import ObserverError, digest
from local_observe.observer.journal import Journal
from local_observe.platform.observer_review import CYCLE_ROUTE, CYCLES_ROUTE
from test_observer_review_api import ReviewFixture


class ReviewAcceptanceTests(ReviewFixture):
    def test_simultaneous_reviews_have_one_winner_and_one_stale_refusal(self):
        self.seeded()
        barrier = threading.Barrier(2)
        fingerprint = digest(self.journal.get('quiet-1'))

        def submit(index):
            journal = Journal(self.state, create=False)
            try:
                barrier.wait(timeout=5)
                journal.feedback('quiet-1', f'concurrent-{index}',
                                 {'usefulness': 'useful', 'correctness': 'unsure'},
                                 reviewer=f'platform-human:operator-{index}',
                                 cycle_sha256=fingerprint, previous_feedback_id=None)
                return 'saved'
            except ObserverError as error:
                return str(error)
            finally:
                journal.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit, range(2)))
        self.assertCountEqual(results, ['saved', 'stale_review'])
        self.assertEqual(self.feedback_count(), 1)

    def test_replay_bounds_history_and_keeps_the_actual_latest_review(self):
        self.seeded()
        for index in range(101):
            self.journal.feedback('quiet-1', f'review-{index:03}',
                                  {'usefulness': 'unsure', 'correctness': 'unsure'})
        status, body = self.get(CYCLE_ROUTE, query=b'cycle_id=quiet-1')
        self.assertEqual(status, 200)
        self.assertEqual(body['feedback_total'], 101)
        self.assertTrue(body['feedback_truncated'])
        self.assertEqual(len(body['replay']['feedback']), 100)
        self.assertEqual(body['replay']['feedback'][0]['feedback_id'], 'review-001')
        self.assertEqual(body['latest_feedback_id'], 'review-100')
        self.assertEqual(self.feedback_count(), 101)

    def test_reading_records_does_not_change_database_bytes_or_mtime(self):
        self.seeded()
        database = self.state / 'observer.sqlite3'
        before = (hashlib.sha256(database.read_bytes()).hexdigest(), database.stat().st_mtime_ns)
        app = self.app()
        self.assertEqual(self.get(CYCLES_ROUTE, app=app)[0], 200)
        self.assertEqual(self.get(CYCLE_ROUTE, query=b'cycle_id=quiet-1', app=app)[0], 200)
        after = (hashlib.sha256(database.read_bytes()).hexdigest(), database.stat().st_mtime_ns)
        self.assertEqual(before, after)

    def test_missing_between_descriptor_check_and_sqlite_open_is_not_recreated(self):
        database = self.state / 'observer.sqlite3'
        original = sqlite3.connect

        def disappear(*args, **kwargs):
            database.unlink()
            return original(*args, **kwargs)

        with patch('local_observe.observer.journal.sqlite3.connect', side_effect=disappear):
            with self.assertRaises(sqlite3.OperationalError):
                Journal(self.state, create=False)
        self.assertFalse(database.exists())

    def test_unsafe_file_mode_refuses_service_startup(self):
        database = self.state / 'observer.sqlite3'
        database.chmod(0o644)
        try:
            with self.assertRaises(ValueError):
                self.app()
        finally:
            database.chmod(0o600)

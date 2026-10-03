"""Independent acceptance of review concurrency, bounded reads and existing-state opens."""
from concurrent.futures import ThreadPoolExecutor
import contextlib
import datetime as dt
import hashlib
import io
import json
import sqlite3
import threading
from unittest.mock import patch

from local_observe.observer.cli import main
from local_observe.observer.contract import ObserverError, digest, instant
from local_observe.observer.journal import Journal
from local_observe.platform.observer_review import CYCLE_ROUTE, CYCLES_ROUTE, FEEDBACK_ROUTE
from test_observer_review_api import HUMAN_A, ReviewFixture, submission


class ReviewAcceptanceTests(ReviewFixture):
    def test_human_correction_retrieval_export_and_withdrawal_across_restart(self):
        self.seeded()
        original = self.journal.get('quiet-1')
        fingerprint = digest(original)
        body = submission('quiet-1', 'correction-1', fingerprint, correctness='incorrect',
                          corrected_answer='CPU remained quiet; password=synthetic-correction-secret',
                          export_approved=True, review_seconds=31)
        status, saved = self.post(FEEDBACK_ROUTE, body)
        self.assertEqual(status, 200)
        feedback = saved['feedback']
        self.assertEqual(feedback['reviewer'], 'platform-human:' + HUMAN_A['identity'])
        self.assertNotIn('synthetic-correction-secret', feedback['corrected_answer'])
        self.assertEqual(self.post(FEEDBACK_ROUTE, body), (status, saved))
        self.assertEqual(self.feedback_count(), 1)
        before = instant(feedback['recorded_at']) + dt.timedelta(seconds=1)
        retrieve = {'before': before, 'limit': 10, 'max_bytes': 65536, 'exclude': 'next-cycle'}
        reopened = Journal(self.state, create=False)
        self.addCleanup(reopened.close)
        history = reopened.retrieve(**retrieve)
        self.assertEqual([row['cycle_id'] for row in history], ['quiet-1'])
        self.assertEqual(history[0]['trust'], 'untrusted_historical_example')
        self.assertEqual(reopened.retrieve(**{**retrieve, 'exclude': 'quiet-1'}), [])
        self.assertEqual(reopened.retrieve(**{**retrieve, 'before': instant(feedback['recorded_at'])}), [])
        export = self.state / 'approved.jsonl'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--state', str(self.state), 'export', '--output', str(export)]), 0)
        exported = [json.loads(line) for line in export.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]['feedback'], feedback)
        self.assertEqual(export.stat().st_mode & 0o777, 0o600)
        exported_digest = hashlib.sha256(export.read_bytes()).hexdigest()
        withdrawn = submission('quiet-1', 'correction-withdrawn', fingerprint, 'correction-1',
                               correctness='incorrect', corrected_answer='Do not reuse this correction.',
                               export_approved=False)
        self.assertEqual(self.post(FEEDBACK_ROUTE, withdrawn)[0], 200)
        self.assertEqual(reopened.examples(), [])
        self.assertEqual(reopened.retrieve(**retrieve), [])
        after = self.state / 'withdrawn.jsonl'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['--state', str(self.state), 'export', '--output', str(after)]), 0)
        self.assertEqual(after.read_bytes(), b'')
        self.assertEqual(hashlib.sha256(export.read_bytes()).hexdigest(), exported_digest)
        self.assertEqual(reopened.get('quiet-1'), original)
        self.assertEqual(len(reopened.replay('quiet-1')['feedback']), 2)

    def test_scalar_grade_and_uncertain_correction_never_become_training_examples(self):
        self.seeded()
        fingerprint = digest(self.journal.get('quiet-1'))
        scalar = submission('quiet-1', 'scalar', fingerprint)
        self.assertEqual(self.post(FEEDBACK_ROUTE, scalar)[0], 200)
        self.assertEqual(self.journal.examples(), [])
        uncertain = submission('quiet-1', 'uncertain', fingerprint, 'scalar', correctness='unsure',
                               corrected_answer='Independent answer is still unknown.', export_approved=True)
        self.assertEqual(self.post(FEEDBACK_ROUTE, uncertain)[0], 400)
        self.assertEqual(self.journal.examples(), [])
        self.assertEqual(self.feedback_count(), 1)

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

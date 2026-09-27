"""Workload measurements preserve unknown grades and distinguish latency from effort."""
import json
import sqlite3
from types import SimpleNamespace
import unittest

from local_observe.evaluation.feedback import summarize


class FeedbackMeasurementTests(unittest.TestCase):
    def fixture(self, resources):
        db = sqlite3.connect(':memory:')
        self.addCleanup(db.close)
        db.executescript('CREATE TABLE cycles(cycle_id TEXT,started_at TEXT,document TEXT); '
                        'CREATE TABLE feedback(cycle_id TEXT,recorded_at TEXT,document TEXT);')
        for hour, decision in enumerate(('tell', 'quiet', 'quiet', 'quiet')):
            instant = f'2026-01-01T{hour:02}:00:00Z'
            cycle = {'status': 'completed', 'coverage': 'complete', 'decision': decision,
                     'ended_at': instant, 'evidence': [{'resource_id': f'resource-{index}'}
                                                      for index in range(resources)]}
            db.execute('INSERT INTO cycles VALUES(?,?,?)', (f'cycle-{hour}', instant, json.dumps(cycle)))
        db.execute('INSERT INTO feedback VALUES(?,?,?)', ('cycle-0', '2026-01-01T00:02:00Z',
                   json.dumps({'correctness': 'unsure', 'recorded_at': '2026-01-01T00:02:00Z'})))
        return SimpleNamespace(db=db)

    def test_size_census_and_sampling_do_not_manufacture_known_truth(self):
        for size in (1, 8, 20):
            journal = self.fixture(size)
            report = summarize(journal, since='2026-01-01T00:00:00Z', until='2026-01-02T00:00:00Z', quiet_every=2)
            self.assertEqual(report['observed_resources'], size)
            self.assertEqual(report['response_rate'], .25)
            self.assertEqual(report['unknown_correctness_cycles'], 4)
            self.assertEqual(report['median_latest_feedback_latency_seconds'], 120)
            self.assertIsNone(report['active_human_review_seconds'])
            self.assertEqual([row['cycle_id'] for row in report['review_queue']], ['cycle-1', 'cycle-3'])

    def test_later_correction_cannot_leak_into_an_earlier_measurement(self):
        journal = self.fixture(1)
        journal.db.execute('INSERT INTO feedback VALUES(?,?,?)', ('cycle-0', '2026-01-02T00:02:00Z',
                           json.dumps({'correctness': 'correct', 'recorded_at': '2026-01-02T00:02:00Z'})))
        report = summarize(journal, since='2026-01-01T00:00:00Z', until='2026-01-02T00:00:00Z')
        self.assertEqual(report['known_correctness_cycles'], 0)

    def test_duration_is_optional_and_corrections_add_effort_without_relabelling_other_cycles(self):
        journal = self.fixture(8)
        for seconds in (30, 10):
            journal.db.execute('INSERT INTO feedback VALUES(?,?,?)', ('cycle-0', '2026-01-01T00:03:00Z',
                json.dumps({'correctness': 'correct', 'recorded_at': '2026-01-01T00:03:00Z',
                            'review_seconds': seconds})))
        report = summarize(journal, since='2026-01-01T00:00:00Z', until='2026-01-02T00:00:00Z')
        self.assertEqual(report['self_reported_review_seconds'], 40)
        self.assertEqual(report['feedback_versions_with_duration'], 2)
        self.assertEqual(report['feedback_versions_without_duration'], 1)
        self.assertIsNone(report['active_human_review_seconds'])
        self.assertEqual(report['unknown_correctness_cycles'], 3)

    def test_reviewing_one_quiet_cycle_does_not_shift_the_other_sample_positions(self):
        journal = self.fixture(1)
        journal.db.execute('INSERT INTO feedback VALUES(?,?,?)', ('cycle-1', '2026-01-01T01:02:00Z',
            json.dumps({'correctness': 'correct', 'recorded_at': '2026-01-01T01:02:00Z'})))
        report = summarize(journal, since='2026-01-01T00:00:00Z', until='2026-01-02T00:00:00Z', quiet_every=2)
        self.assertEqual([row['cycle_id'] for row in report['review_queue']], ['cycle-3'])

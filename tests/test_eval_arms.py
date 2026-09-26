"""Actual estimator and deployed-example static limits; shaping independent controls."""
import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from local_observe.evaluation.arms import downsample, judge, shape, threshold_defaults
from local_observe.evaluation.budget import enforced_limits
from local_observe.evaluation.fault_inject import RESOURCE, START, synthetic
from local_observe.evaluation.model import ROOT, CorpusError
from local_observe.inventory import index
from local_observe.inventory.validation import read_document
from local_observe.platform import anomaly
from local_observe.platform.notification_safety import NotificationPolicy


class ArmTests(unittest.TestCase):
    def test_seasonal_uses_actual_estimator_known_median_mad_and_band(self):
        t = START.timestamp()
        baseline = anomaly.train([(t - 86400, 10), (t - 172800, 12), (t - 259200, 14)], k=3)
        stats = baseline.buckets[anomaly.bucket_of('hour_of_day', t)]
        self.assertEqual(stats.median, 12)
        self.assertAlmostEqual(stats.mad_scaled, 2.9652)
        lo, hi = anomaly.band(baseline, t)
        self.assertAlmostEqual(lo, 3.1044); self.assertAlmostEqual(hi, 20.8956)
        self.assertEqual(len(anomaly.detect(baseline, [(t, 21)]).deviations), 1)

    def test_seasonal_missing_same_hour_is_unjudgeable_not_normal(self):
        corpus = synthetic()
        start = START.timestamp()
        context = {'series': copy.deepcopy(corpus['series']), 'evaluation': corpus['evaluation']}
        context['series'][0]['rows'] = [{'ts': start - 3600, 'v': 10}, {'ts': start, 'v': 12}]
        result = judge('seasonal', context, index_path=None)
        self.assertEqual(result['status'], 'unjudgeable')
        self.assertEqual(result['unjudgeable_points'], 1)

    def test_static_reads_example_resource_metric_mapping_without_reversed_ids(self):
        expected = {(row['resource_id'], row['series']): row['threshold']
                    for row in read_document(ROOT / 'examples/platform/forecast.yaml')['rules']}
        self.assertEqual(threshold_defaults(), expected)
        self.assertEqual(expected[RESOURCE, 'filesystem_used_bytes'], 90000000000)
        corpus = synthetic()
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / 'inventory.db'
            index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), inventory, 'test')
            result = judge('static-threshold', {'series': corpus['series'], 'evaluation': corpus['evaluation']},
                           index_path=inventory)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['kind'], 'threshold')

    def test_spc_spike_cusum_small_shift_and_quiet(self):
        training = [(i * 60, 10 + (-1 if i % 2 else 1)) for i in range(20)]
        self.assertEqual(shape(training, [(2000 + i * 60, 10) for i in range(8)])[0], [])
        self.assertEqual(shape(training, [(2000, 20)])[0], [2000])
        gradual = shape(training, [(2000 + i * 60, 11.5) for i in range(8)])[0]
        self.assertTrue(gradual)  # Within 3 sigma, accumulated shift still detected.
        self.assertEqual(shape([], [(2000, 20)]), ([], 1))
        self.assertEqual(downsample([(1, 1), (2, 3), (61, 8)]), [(2, 2), (61, 8)])

    def test_truth_never_reaches_judge_and_unknown_metric_is_explicit(self):
        with self.assertRaises(CorpusError):
            judge('seasonal', {'series': [], 'evaluation': {}, 'incidents': []}, index_path=None)
        corpus = synthetic(); corpus['series'][0]['metric'] = 'not-configured'
        result = judge('static-threshold', {'series': corpus['series'], 'evaluation': corpus['evaluation']},
                       index_path=None)
        self.assertEqual(result['status'], 'unjudgeable')
        self.assertEqual(result['unconfigured_series'], 1)

    def test_real_policy_limits_are_not_fabricated_daily_ceiling(self):
        policy = NotificationPolicy(max_attempts=7, window_seconds=300)
        report = enforced_limits(policy)
        self.assertEqual((report['max_attempts'], report['window_seconds']), (7, 300))
        self.assertTrue(report['latches_on_exhaustion'])
        self.assertTrue(report['reset_required'])
        self.assertIsNone(report['findings_per_day_ceiling'])

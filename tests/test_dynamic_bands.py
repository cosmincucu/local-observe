"""alert conditions: learned bands — the refusal before ``min_points``, the sustained layer, and reuse.

The claim this file exists to pin is the one the brief made hardest: **the estimator is event kinds's, not a
second port of `legacy:alerting/dynamic.py`.** That is pinned behaviourally, not by an import check —
`SeasonalTests` builds three days of a series that peaks at the same hour every day and asks the band to
judge the peak. A flat quantile band over the trailing window has no seasonality term to consult
(v0.1's `dynamic.py` has none), so it cannot pass this test; the per-hour
``median ± k·scaled-MAD`` band that `anomaly.train` learns passes it, and fails the same value at an hour
that never saw it. If someone re-ports the quantile maths, `SeasonalTests` fails with it.

The rest is what v0.1 had and this repository did not:

* **A band with too few points is `insufficient`, visible, and never fires.** Not a zero-deviation
  result, not a `resolved` verdict, not silence: the outcome word is in the returned `Verdict` and in the
  round summary, and the event it files is the ``coverage`` verdict `detections`/`conditions` file.
* **A band crossing must hold.** One out-of-band tick does not open a condition; a run that lasts
  ``for_seconds`` does; and a flap after that stays one condition, because the machine is
  `conditions.SustainedStateMachine` — the same code a static tier uses.
* **One document, one round.** A ``band`` rule is parsed by `conditions.rule`, judged by its own
  estimator, and delivered through the same cursor and the same intake path as a threshold rule.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import anomaly, conditions, dynamic_bands
from local_observe.platform.state import Actor, StateError, Store, validate_event
from local_observe.store.backends.memory import InMemoryStore, series

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
SOURCE = 'lo-conditions'
STEP = 300


def laid(values, *, end: dt.datetime = NOW, step: int = STEP):
    """Put values on a `STEP` grid whose newest point sits exactly at *end*."""
    return [(end.timestamp() - step * (len(values) - 1 - i), float(value))
            for i, value in enumerate(values)]


def band_rule(resource: str, **overrides) -> dynamic_bands.Band:
    document = {'id': 'mem.band', 'mode': 'band', 'resource_id': resource, 'source': SOURCE,
                'severity_source': 'sigma', 'severity_tier': 'high', 'min_points': 12,
                'min_per_bucket': 2, 'history_seconds': 86400, 'evaluation_seconds': STEP,
                'for_seconds': 600, 'max_age_seconds': 3600}
    document.update(overrides)
    return conditions.rule(document)            # the same loader a static rule uses


class BandConfigTests(unittest.TestCase):
    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def test_a_band_document_is_parsed_by_the_shared_loader_and_judges_itself(self):
        rule = band_rule(self.host)
        self.assertIsInstance(rule, dynamic_bands.Band)
        self.assertEqual(rule.mode, 'band')
        self.assertEqual((rule.kind, rule.query_type), ('anomaly', 'metric-threshold'))
        self.assertEqual(rule.severity(), 'warning')          # sigma `high`, resolved by the crosswalk
        self.assertEqual(len(rule.version), 16)

    def test_the_knobs_are_bounded_at_load_and_a_quieter_tier_is_not_a_different_condition(self):
        for broken in ({'k': 0.5}, {'min_points': 3}, {'min_per_bucket': 65},
                       {'history_seconds': 900_000}, {'season': 'day_of_month'},
                       {'for_seconds': -1}, {'window_points': 20}):
            with self.subTest(broken=list(broken)[0]), self.assertRaises(StateError):
                band_rule(self.host, **broken)
        loud = band_rule(self.host, severity_tier='critical')
        self.assertEqual(loud.severity(), 'critical')
        self.assertEqual(loud.version, band_rule(self.host).version)

    def test_a_history_shorter_than_its_own_sustain_window_refuses(self):
        with self.assertRaises(StateError):
            band_rule(self.host, for_seconds=86400, history_seconds=86400)
        with self.assertRaises(StateError):
            band_rule(self.host, for_seconds=43200, history_seconds=86400)   # for+clear+eval overflows


class InsufficientTests(unittest.TestCase):
    """The refusal v0.1 shipped and this repository never had: too few points is visible, never a verdict."""

    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def test_below_min_points_nothing_fires_and_the_reason_is_said(self):
        rule = band_rule(self.host, min_points=12)
        wild = laid([10] * 4 + [9000] * 4)
        result = rule.judge(wild, now=NOW)
        self.assertEqual(result.outcome, 'insufficient')
        self.assertEqual(result.status, None)
        self.assertLess(result.detail['training_points'], result.detail['min_points'])
        self.assertEqual(result.detail['reason'], 'band trained on fewer points than min_points')
        self.assertEqual([(item['kind'], item['status']) for item in result.events],
                         [('coverage', 'firing')], 'blindness files a coverage event and nothing else')
        validate_event(result.events[0], NOW)

    def test_an_empty_series_is_stale_and_not_an_in_band_result(self):
        result = band_rule(self.host).judge([], now=NOW)
        self.assertEqual((result.outcome, result.status), ('stale', None))

    def test_a_series_older_than_max_age_is_stale_and_closes_nothing(self):
        rule = band_rule(self.host, max_age_seconds=600)
        old = laid([10] * 20, end=NOW - dt.timedelta(hours=2))
        result = rule.judge(old, now=NOW)
        self.assertEqual(result.outcome, 'stale')
        self.assertEqual([item['kind'] for item in result.events], ['coverage'])
        self.assertEqual(result.events[0]['status'], 'firing')


class SustainedBandTests(unittest.TestCase):
    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def steady(self, count=301, value=10.0):
        """25 hours of points on the judgment grid, so every hour bucket holds training points."""
        return laid([value] * count)

    def test_a_single_out_of_band_tick_does_not_open_a_condition(self):
        rule = band_rule(self.host, for_seconds=600)          # three buckets must breach
        points = laid([10.0] * 300 + [9000.0])
        result = rule.judge(points, now=NOW)
        self.assertEqual(result.status, 'resolved')
        self.assertEqual(result.outcome, 'pending')
        self.assertEqual(result.state, 'pending')
        self.assertEqual(result.detail['deviations'], 1)      # it saw the spike and still did not fire
        self.assertEqual([item['status'] for item in result.events if item['kind'] == 'anomaly'],
                         ['resolved'])

    def test_a_breach_that_holds_across_the_sustain_window_fires_once(self):
        rule = band_rule(self.host, for_seconds=600)
        points = laid([10.0] * 296 + [9000.0] * 5)
        result = rule.judge(points, now=NOW)
        self.assertEqual((result.outcome, result.state, result.status), ('firing', 'firing', 'firing'))
        self.assertGreaterEqual(result.detail['buckets_judgeable'], 3)
        for item in result.events:
            validate_event(item, NOW)
        self.assertEqual([item['kind'] for item in result.events], ['coverage', 'anomaly'])

    def test_a_flap_after_firing_is_one_condition_and_a_sustained_clear_is_a_recovery(self):
        rule = band_rule(self.host, for_seconds=600)
        flapping = laid([10.0] * 296 + [9000.0, 9000.0, 9000.0, 9000.0, 10.0])
        self.assertEqual(rule.judge(flapping, now=NOW).status, 'firing',
                         'a breach inside the clear window has not cleared: that is the hysteresis')
        cleared = laid([10.0] * 296 + [9000.0] * 5 + [10.0] * 6)
        self.assertEqual(rule.judge(cleared, now=NOW).status, 'resolved')

    def test_every_band_filing_shares_one_condition_key_however_the_value_moves(self):
        """Identity is (rule, version, resource, window): the timestamp never enters it twice."""
        rule = band_rule(self.host, for_seconds=600)
        series_points = laid([10.0] * 296 + [9000.0] * 5)
        first = [item for item in rule.judge(series_points, now=NOW).events if item['kind'] == 'anomaly'][0]
        second = [item for item in rule.judge(series_points, now=NOW).events
                  if item['kind'] == 'anomaly'][0]
        self.assertEqual(first['source_event_id'], second['source_event_id'])
        self.assertEqual(first['rule_id'], 'mem.band')
        self.assertEqual(first['condition'], 'mem.band')


class SeasonalTests(unittest.TestCase):
    """The reuse proof: the band that judges a point is the one its own hour learned."""

    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def three_days(self, *, end: dt.datetime = NOW, peak_hour: int = 12, count: int = 72):
        """Hourly points for three days before *end*: 100 at `peak_hour` every day, 10 at every other hour."""
        origin = end - dt.timedelta(hours=count)
        return [((origin + dt.timedelta(hours=index)).timestamp(),
                 100.0 if (origin + dt.timedelta(hours=index)).hour == peak_hour else 10.0)
                for index in range(count)]

    def rule(self, **overrides):
        document = {'id': 'load.band', 'mode': 'band', 'resource_id': self.host, 'source': SOURCE,
                    'severity_source': 'sigma', 'severity_tier': 'high', 'min_points': 48,
                    'min_per_bucket': 3, 'history_seconds': 4 * 86400, 'evaluation_seconds': 3600,
                    'for_seconds': 0, 'max_age_seconds': 3600}
        document.update(overrides)
        return conditions.rule(document)

    def test_a_peak_that_repeats_every_day_is_inside_its_own_hour_and_never_fires(self):
        at_peak = self.three_days() + [(NOW.timestamp(), 100.0)]
        result = self.rule().judge(at_peak, now=NOW)
        self.assertEqual((result.outcome, result.status), ('resolved', 'resolved'))
        self.assertEqual(result.detail['deviations'], 0)
        self.assertEqual([item['kind'] for item in result.events], ['coverage', 'anomaly'])

    def test_the_same_value_at_an_hour_that_never_saw_it_is_outside_the_band_and_fires(self):
        at_three = timestamp('2026-09-08T03:00:00Z')
        result = self.rule().judge(self.three_days(end=at_three) + [(at_three.timestamp(), 100.0)],
                                  now=at_three)
        self.assertEqual(result.status, 'firing')
        self.assertEqual(result.detail['deviations'], 1)
        self.assertEqual([item['severity'] for item in result.events if item['kind'] == 'anomaly'],
                         ['warning'])

    def test_the_estimator_is_anomaly_train_and_not_a_second_implementation(self):
        """The maths lives in one place: this module's training *is* event kinds's function."""
        seen = []
        original = anomaly.train

        def spy(points, **kwargs):
            seen.append((len(points), kwargs))
            return original(points, **kwargs)

        anomaly.train = spy
        try:
            dynamic_bands.verdict(self.rule(), self.three_days() + [(NOW.timestamp(), 100.0)], now=NOW)
        finally:
            anomaly.train = original
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][1]['season'], 'hour_of_day')
        self.assertEqual(seen[0][1]['min_per_bucket'], 3)
        self.assertLess(seen[0][0], 73, 'the evaluated tail must not train the band that judges it')


class MixedRoundTests(unittest.TestCase):
    """One document, one cursor, one round: a threshold rule and a band rule side by side."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.store = Store(self.root / 'state.db')
        self.actor = Actor(SOURCE, 'producer')
        self.cursor = self.root / 'conditions.json'
        self.config = {'rules': [conditions.rule({'id': 'cpu.high', 'mode': 'threshold',
                                                  'resource_id': self.host, 'source': SOURCE,
                                                  'severity_source': 'sigma', 'severity_tier': 'high',
                                                  'threshold': 90, 'for_seconds': 600,
                                                  'evaluation_seconds': STEP, 'max_age_seconds': 3600,
                                                  'history_seconds': 86400, 'metric': 'cpu'}),
                                 band_rule(self.host, metric='mem')],
                       'interval_seconds': 300}
        rows = (series(40, name='cpu', resource_id=self.host,
                       start=utc_text(NOW - dt.timedelta(seconds=STEP * 40)),
                       step_seconds=STEP, value=95.0)
                + series(40, name='mem', resource_id=self.host,
                         start=utc_text(NOW - dt.timedelta(seconds=STEP * 40)),
                         step_seconds=STEP, value=42.0))
        self.reader = InMemoryStore(rows)
        self.now = NOW

    def deliver(self, item):
        self.store.intake(item, self.actor, now=self.now)

    def run_round(self, now=NOW):
        self.now = now
        return conditions.tick(self.index, self.config, self.cursor, self.reader, self.deliver,
                               now=now, state=conditions.load_cursor(self.cursor, self.config))

    def test_a_flat_learning_series_judges_the_band_as_in_band_and_the_threshold_as_firing(self):
        summary = self.run_round()
        self.assertEqual(summary['rules'], {'cpu.high': 'firing', 'mem.band': 'resolved'})
        self.assertEqual(summary['events'], 4)
        kinds: dict[str, str] = {}
        for row in self.store.records('events'):        # newest first: the first sighting of a kind wins
            item = json.loads(row['payload'])
            kinds.setdefault(item['kind'], item['status'])
        self.assertEqual(kinds, {'coverage': 'resolved', 'threshold': 'firing', 'anomaly': 'resolved'})
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_a_binding_change_across_rules_is_refused_not_re_baselined(self):
        self.run_round()
        other = {'rules': [self.config['rules'][0]], 'interval_seconds': 300}
        with self.assertRaises(StateError):
            conditions.load_cursor(self.cursor, other)


if __name__ == '__main__':
    unittest.main()

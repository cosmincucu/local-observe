"""forecast: the forecast models — the maths v0.1 ported, and the two floors this repository added.

The claim this file exists to pin is that the port kept the arithmetic and refused to keep v0.1's
**floor**. `legacy:forecast/models.py` would fit anything sortable: two points, three points, a `nan`.
Two points define a line exactly, so `r2` comes back 1.0 for the shape of the input rather than for
the strength of a trend, and v0.1's own next module divided by that slope to announce a crossing
(`legacy:forecast/timetothreshold.py:51`) — a page with no evidence behind it. Here:

* `MIN_FIT_POINTS` is 4, the same floor `anomaly.LIMITS['min_points']` holds for learning a band, and
  configuration cannot lower it;
* a non-finite sample is a refusal (`ModelRefused`) before any `fsum` can turn it into a plausible
  slope, because a `nan` slope makes every downstream comparison false and the caller cannot tell that
  from "no crossing coming";
* both models still answer the same question v0.1 asked, and on a clean ramp they answer it
  identically — the fixture's crossing instant is asserted as a **number** for each model, because a
  shape assertion would pass on a fit that was wrong by an hour.

The second half of the file is the read: `points_from_store` goes through `conditions.read_points`
over `local_observe/store/client.py`, so this package opens no transport and writes no SQL. That is
pinned behaviourally (the facade's refusals arrive as `SeriesRead.answered`, and a spy proves which
function the points came from) rather than by grepping prose.
"""
import datetime as dt
from pathlib import Path
import unittest

from local_observe.forecast import models, timetothreshold
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import conditions
from local_observe.store.backends.memory import InMemoryStore
from local_observe.store.client import MetricSample, StoreRefused, Window

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'local_observe' / 'forecast'
NOW = timestamp('2026-09-08T12:00:00Z')
STEP = 300
HOST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'


def laid(values, *, end: dt.datetime = NOW, step: int = STEP):
    """Put values on a *step* grid whose newest point sits at *end* (the half-open window's edge)."""
    return [(end.timestamp() - step * (len(values) - 1 - i), float(value))
            for i, value in enumerate(values)]


#: A clean ramp: 40 samples, +1 every 300 s, newest (value 49) 300 s before `NOW`. Its straight line
#: reaches 54 exactly 1200 s after `NOW`, so the crossing time is a number the fixture knows in advance
#: and both models must agree on to the microsecond.
RAMP = [10 + i for i in range(40)]
RAMP_POINTS = laid(RAMP, end=NOW - dt.timedelta(seconds=STEP))
RAMP_THRESHOLD = 54.0
RAMP_ETA = NOW.timestamp() + 1200.0


class TrendFitTests(unittest.TestCase):
    """The two ported fits, against a crossing time computed by hand from the fixture."""

    def test_both_models_predict_the_same_crossing_instant_on_a_clean_ramp(self):
        for name in models.MODELS:
            with self.subTest(model=name):
                fitted = models.fit(RAMP_POINTS, name, alpha=0.5, beta=0.3)
                prediction = timetothreshold.time_to_threshold(fitted, RAMP_THRESHOLD,
                                                               RAMP_POINTS[-1][0])
                self.assertEqual(prediction.state, 'crossing')
                self.assertAlmostEqual(prediction.eta_epoch_s, RAMP_ETA, delta=1e-6,
                                       msg=f'{name} missed the crossing the fixture defines')

    def test_the_fit_is_independent_of_the_order_points_arrive_in(self):
        shuffled = list(reversed(RAMP_POINTS))
        trend = models.fit_linear(shuffled)
        self.assertAlmostEqual(trend.slope, 1.0 / STEP, delta=1e-12)
        self.assertAlmostEqual(trend.r2, 1.0, delta=1e-9)

    def test_r2_is_one_for_a_flat_series_and_is_not_a_trend(self):
        flat = models.fit_linear(laid([7.5] * 12))
        self.assertEqual((flat.slope, flat.r2), (0.0, 1.0))
        prediction = timetothreshold.time_to_threshold(flat, 8.0, NOW.timestamp())
        self.assertEqual((prediction.state, prediction.eta_epoch_s), ('flat', None))
        self.assertIn('flat series', prediction.confidence_note)

    def test_holt_reports_the_state_a_projection_needs(self):
        fit = models.fit_holt(RAMP_POINTS, alpha=0.5, beta=0.3)
        self.assertAlmostEqual(fit.level, 49.0, delta=1e-9)
        self.assertAlmostEqual(fit.trend, 1.0, delta=1e-9)
        self.assertAlmostEqual(fit.step_s, float(STEP), delta=1e-9)
        self.assertEqual(fit.last_epoch_s, RAMP_POINTS[-1][0])
        self.assertAlmostEqual(fit.forecast(5), 54.0, delta=1e-9)


class RefusalTests(unittest.TestCase):
    """A fit that cannot be honest says so. None of these paths reaches an extrapolated ETA."""

    def test_a_non_finite_sample_is_refused_and_never_fitted(self):
        for poison in (float('nan'), float('inf'), float('-inf')):
            for name in models.MODELS:
                with self.subTest(model=name, value=str(poison)), self.assertRaises(models.ModelRefused):
                    models.fit(laid([10.0, 11.0, poison, 13.0]), name)

    def test_a_non_finite_newest_sample_becomes_insufficient_and_not_a_number(self):
        """The store hands back a poisoned sample; the round must report a state, not a crash or a fit."""
        rule = timetothreshold.rule(_document())
        points = [point for point in RAMP_POINTS]
        points[-1] = (points[-1][0], float('nan'))
        verdict = timetothreshold.verdict(rule, points, now=NOW)
        self.assertEqual((verdict.outcome, verdict.status), ('insufficient', None))
        self.assertEqual([item['kind'] for item in verdict.events], ['coverage'])
        self.assertIn('not finite', verdict.detail['reason'])

    def test_too_few_points_refuses_the_fit_and_the_module_floor_is_not_configurable(self):
        with self.assertRaises(models.ModelRefused):
            models.fit_linear(laid([10.0, 11.0, 12.0]))
        self.assertLessEqual(models.MIN_FIT_POINTS, 4)
        with self.assertRaises(ValueError):
            timetothreshold.rule(_document(min_points=3))

    def test_points_sharing_one_timestamp_are_unfittable_rather_than_vertical(self):
        with self.assertRaises(models.ModelRefused):
            models.fit_linear(laid([1.0, 2.0, 3.0, 4.0], step=0))

    def test_smoothing_constants_outside_the_unit_interval_are_refused(self):
        for knob in ({'alpha': 0.0}, {'beta': 1.5}, {'alpha': float('nan')}, {'beta': True}):
            with self.subTest(knob=list(knob)[0]), self.assertRaises(ValueError):
                timetothreshold.rule(_document(**knob))

    def test_an_unknown_model_name_is_refused_at_load(self):
        with self.assertRaises(ValueError):
            timetothreshold.rule(_document(model='prophet'))


class StoreReadTests(unittest.TestCase):
    """`points_from_store` reads through the facade — the one read this package has."""

    def document(self, **overrides):
        return _document(**overrides)

    def seeded(self, *, count=40, value=None, step=STEP, end=None):
        """Seed a series whose newest row sits one step inside the read window (half-open rule)."""
        end = end or (NOW - dt.timedelta(seconds=step))
        origin = end - dt.timedelta(seconds=step * (count - 1))
        rows = [MetricSample(name='disk_used', value=(value if value is not None else 10 + index),
                             resource_id=HOST, labels={'resource_id': HOST},
                             timestamp=utc_text(origin + dt.timedelta(seconds=step * index)))
                for index in range(count)]
        return InMemoryStore(rows)

    def test_the_series_arrives_as_fitted_points_and_the_answer_says_it_was_read(self):
        rule = timetothreshold.rule(self.document())
        reading = timetothreshold.points_from_store(self.seeded(), rule, end=NOW)
        self.assertEqual(reading.answered, 'ok')
        self.assertEqual(len(reading.points), 40)
        self.assertEqual(reading.points[0][1], 10.0)
        self.assertEqual(reading.points[-1][1], 49.0)
        # 40 samples at 300 s spacing, newest 300 s before NOW: the span the fit may see is 12 000 s,
        # which is well inside the 86 400 s the rule was allowed to ask for.
        self.assertAlmostEqual(reading.points[0][0], NOW.timestamp() - 12000, delta=1e-6)
        self.assertLessEqual(len(reading.points), 86400 // STEP)
        self.assertFalse(reading.truncated)
        self.assertEqual(reading.reads, 1)

    def test_a_series_the_store_has_never_seen_is_answered_not_extrapolated(self):
        rule = timetothreshold.rule(self.document())
        reading = timetothreshold.points_from_store(InMemoryStore(), rule, end=NOW)
        self.assertEqual(reading.answered, 'empty')
        self.assertEqual(reading.points, [])
        verdict = timetothreshold.verdict(rule, reading.points, now=NOW)
        self.assertEqual((verdict.outcome, verdict.status), ('stale', None))
        self.assertIn('fresh enough', verdict.detail['reason'])

    def test_a_store_that_raises_makes_the_round_fail_rather_than_judge_nothing(self):
        """A transport failure is not an empty series: it propagates, and the cursor keeps the window owed."""
        class Refusing(InMemoryStore):
            def read(self, *args, **kwargs):
                raise StoreRefused('fixture: this read will not run')

        rule = timetothreshold.rule(self.document())
        with self.assertRaises(StoreRefused):
            timetothreshold.points_from_store(Refusing(), rule, end=NOW)

    def test_the_points_come_from_the_merged_reader_and_from_nothing_else(self):
        """A spy on `conditions.read_points` is the proof that this package has one read path."""
        rule = timetothreshold.rule(self.document())
        seen = []
        original = conditions.read_points

        def spy(reader, subject, **kwargs):
            seen.append(subject.id)
            return original(reader, subject, **kwargs)

        conditions.read_points = spy
        try:
            timetothreshold.points_from_store(self.seeded(), rule, end=NOW)
        finally:
            conditions.read_points = original
        self.assertEqual(seen, [rule.id])

    def test_the_package_imports_no_transport_and_writes_no_sql(self):
        """Only `__main__` may post events, and nothing here may speak to the store directly."""
        files = sorted(path for path in PACKAGE.glob('*.py'))
        self.assertTrue(files, 'the forecast package disappeared')
        for path in files:
            source = path.read_text(encoding='utf-8')
            lines = [line.strip() for line in source.splitlines() if line.strip().startswith(('import ', 'from '))]
            joined = ' '.join(lines)
            for forbidden in ('urllib', 'socket', 'http.client', 'requests', 'clickhouse_driver',
                              'sqlite3.connect', 'psycopg'):
                self.assertNotIn(forbidden, joined, f'{path.name} imports a transport: {forbidden}')
            self.assertNotIn('SELECT', source, f'{path.name} carries SQL text')
            if path.name != '__main__.py':
                self.assertNotIn('JsonClient', joined, f'{path.name} posts events from outside __main__')
                self.assertNotIn('local_observe.http', joined, f'{path.name} opens the HTTP layer')
            if path.name == '__main__.py':
                self.assertIn('store_from_environment', source,
                              'the store facade must be reached through store facade\'s one constructor')

class SeriesBoundTests(unittest.TestCase):
    """The read span is bounded by the store's own window, so a forecast cannot out-remember intake."""

    def test_a_history_longer_than_the_store_window_is_refused_at_load(self):
        with self.assertRaises(ValueError):
            timetothreshold.rule(_document(history_seconds=7 * 86400 + 1))

    def test_a_window_the_store_would_refuse_is_refused_and_never_clamped(self):
        """The 7-day bound is a refusal at both ends: load-time, and in the facade when asked directly."""
        rule = timetothreshold.rule(_document(history_seconds=7 * 86400))
        self.assertEqual(rule.history_seconds, 7 * 86400)
        with self.assertRaises(StoreRefused):
            Window(start=utc_text(NOW - dt.timedelta(seconds=7 * 86400 + 60)), end=utc_text(NOW))

    def test_more_rows_than_one_page_may_be_reported_short_but_never_silently(self):
        """A truncated read is `SeriesRead.truncated`, which `conditions.tick` names in the round line."""
        rule = timetothreshold.rule(_document(history_seconds=7 * 86400, evaluation_seconds=60))
        rows = [MetricSample(name='disk_used', value=10.0 + index, resource_id=HOST,
                             labels={'resource_id': HOST},
                             timestamp=utc_text(NOW - dt.timedelta(seconds=60) * (2100 - index)))
                for index in range(2100)]
        reading = timetothreshold.points_from_store(InMemoryStore(rows), rule, end=NOW)
        self.assertTrue(reading.truncated)
        self.assertGreaterEqual(reading.reads, 1)


def _document(**overrides):
    """One forecast rule document, in the shape `examples/platform/forecast.yaml` uses."""
    document = {'id': 'pool-disk', 'series': 'disk_used', 'resource_id': HOST,
                'source': 'lo-forecast', 'severity_source': 'core-events-v1',
                'severity_tier': 'warning', 'threshold': RAMP_THRESHOLD, 'model': 'linear',
                'horizon_seconds': 3600, 'min_points': 4, 'evaluation_seconds': STEP,
                'history_seconds': 86400, 'max_age_seconds': 3600, 'for_seconds': 600}
    document.update(overrides)
    return document


if __name__ == '__main__':
    unittest.main()

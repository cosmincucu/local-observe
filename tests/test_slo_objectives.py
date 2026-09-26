"""error budget (part 1): what an objective means, and the arithmetic that never invents an attainment.

Two modules are pinned here, and each is a way the port could be quietly wrong:

* **`slo.objectives` classifies samples and nothing else.** An availability sample is good when it is
  truthy; a latency sample is good when it sits **at or under** the threshold (the boundary the claim
  "99 % of requests under 300 ms" is judged on, and v0.1's rule); a target of exactly 1.0 is refused
  because its error budget is zero and every bad sample would then divide by it.
* **`slo.budget` refuses to print a number it does not have.** Below `min_samples` the report is
  `insufficient_data` with attainment, remaining budget and burn rate all ``None`` — the failure mode
  this card exists to avoid is that collapse into 1.0, so it is asserted as ``None`` and not as "some
  small value". An empty burn window answers ``None`` for the same reason, and an overspent budget goes
  **negative** rather than clamping at zero.

The numbers are asserted as numbers, from a fixture whose shape the docstring states: a 432-second grid
of 201 points whose newest sits exactly at the evaluation instant, so the half-open compliance window
holds exactly 200 samples and every ratio below is hand-checkable (`1/200` over a 0.5 % budget is a burn
rate of 1.0 — the sustainable pace, and the reason the status beside it is still `ok`).
"""
import datetime as dt
from pathlib import Path
import unittest

from local_observe.slo import budget
from local_observe.slo.objectives import (AvailabilityObjective, LatencyObjective,
                                          error_budget_fraction)

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 9, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
# The fixture grid: 201 points 432 s apart, the newest exactly at NOW. `NOW - 86400` is the 201st point,
# and the window is half-open at that edge, so a 1-day compliance window holds exactly 200 samples.
STEP = 432
COUNT = 201
TARGET = 0.995


def samples(count: int = COUNT, *, step: int = STEP, end: dt.datetime = NOW,
            bad: tuple[int, ...] = ()) -> list[tuple[float, float]]:
    """An availability series on a fixed grid: position 0 is the newest point, `bad` names the failures.

    Every other point is a passing check (1.0) and a failed one is 0.0, so a test states which checks
    failed and nothing else — and the instants are derived from *end*, never read from a clock, so the
    same 201 points mean the same 201 instants in any timezone.
    """
    return [(end.timestamp() - step * position, 0.0 if position in bad else 1.0)
            for position in reversed(range(count))]


def availability(**overrides) -> AvailabilityObjective:
    """The headline objective: 99.5 % of checks pass, judged over a rolling day, floor of one sample."""
    document = {'name': 'demo-api.availability', 'target': TARGET, 'window_s': 86_400, 'min_samples': 1}
    document.update(overrides)
    return AvailabilityObjective(**document)


class ObjectiveTests(unittest.TestCase):
    """What a sample means, and the refusals that keep an objective from stating a nonsense question."""

    def test_an_availability_sample_is_good_when_it_is_truthy(self):
        objective = availability()
        self.assertTrue(objective.is_good(1.0))
        self.assertTrue(objective.is_good(True))
        self.assertFalse(objective.is_good(0.0))
        self.assertFalse(objective.is_good(False))

    def test_a_latency_sample_at_the_threshold_is_good_and_one_over_is_not(self):
        """The boundary belongs to the claim: v0.1's `<=` is kept, so 300 ms meets "under 300 ms"."""
        objective = LatencyObjective(name='demo-api.latency', threshold_s=0.3, target=0.99, window_s=300)
        self.assertTrue(objective.is_good(0.3))
        self.assertTrue(objective.is_good(0.2999))
        self.assertFalse(objective.is_good(0.3000001))

    def test_a_latency_objective_refuses_a_sample_it_cannot_measure(self):
        """Neither reading a malformed value as good nor as bad is an answer; the feed is the bug."""
        objective = LatencyObjective(name='demo-api.latency', threshold_s=0.3, target=0.99, window_s=300)
        for value in ('300ms', None, True):
            with self.assertRaises(ValueError, msg=repr(value)):
                objective.is_good(value)

    def test_the_error_budget_is_the_complement_of_the_target(self):
        self.assertAlmostEqual(error_budget_fraction(availability()), 0.005, places=12)
        self.assertAlmostEqual(error_budget_fraction(LatencyObjective(name='x', threshold_s=1.0,
                                                                      target=0.99, window_s=60)),
                               0.01, places=12)

    def test_a_target_of_exactly_one_is_refused_because_its_budget_is_zero(self):
        """Not a pedantic bound: burn rate divides by the budget, so target 1.0 makes any bad sample ∞."""
        with self.assertRaises(ValueError):
            availability(target=1.0)
        with self.assertRaises(ValueError):
            availability(target=0.0)

    def test_the_other_common_refusals_are_refusals_and_not_clamps(self):
        for broken in ({'min_samples': 0}, {'min_samples': True}, {'window_s': 0}, {'window_s': '1d'},
                       {'name': '   '}, {'name': None}):
            with self.assertRaises(ValueError, msg=str(broken)):
                availability(**broken)
        with self.assertRaises(ValueError):
            LatencyObjective(name='demo-api.latency', threshold_s=0, target=0.99, window_s=300)


class BudgetReportTests(unittest.TestCase):
    """Attainment, remaining budget and burn rate, on the fixture the module docstring states."""

    def setUp(self):
        self.objective = availability()

    def report(self, bad: tuple[int, ...] = (), **overrides) -> budget.BudgetReport:
        """One report over the fixture, with `bad` naming the failed checks by position from newest."""
        objective = availability(**overrides) if overrides else self.objective
        return budget.evaluate(objective, samples(bad=bad), NOW.timestamp())

    def test_the_window_is_half_open_at_the_far_edge_so_the_denominator_is_the_number_stated(self):
        report = self.report()
        self.assertEqual(report.total, 200)
        self.assertEqual((report.good, report.bad), (200, 0))
        self.assertAlmostEqual(report.attainment, 1.0, places=12)
        self.assertAlmostEqual(report.burn_rate, 0.0, places=12)
        self.assertAlmostEqual(report.remaining_budget_fraction, 1.0, places=12)
        # budget_fraction * total = 0.005 * 200 = one bad sample of headroom, in the window's own units.
        self.assertAlmostEqual(report.remaining_budget_abs, 1.0, places=12)
        self.assertEqual(report.status, budget.OK)
        self.assertAlmostEqual(report.window_end_s, NOW.timestamp(), places=6)
        self.assertAlmostEqual(report.window_start_s, NOW.timestamp() - 86_400, places=6)

    def test_one_bad_sample_in_two_hundred_burns_the_budget_at_exactly_the_sustainable_pace(self):
        """Burn 1.0 means "this pace spends the budget exactly at the window's edge" — and no overspend."""
        report = self.report(bad=(0,))
        self.assertEqual((report.total, report.good, report.bad), (200, 199, 1))
        self.assertAlmostEqual(report.attainment, 0.995, places=9)
        self.assertAlmostEqual(report.burn_rate, 1.0, places=9)
        self.assertAlmostEqual(report.remaining_budget_abs, 0.0, places=9)
        self.assertAlmostEqual(report.remaining_budget_fraction, 0.0, places=9)
        self.assertEqual(report.status, budget.OK)          # at the edge, not past it

    def test_five_bad_samples_exhaust_the_budget_and_the_overspend_is_reported_negative(self):
        report = self.report(bad=(0, 1, 2, 3, 4))
        self.assertEqual((report.good, report.bad), (195, 5))
        self.assertAlmostEqual(report.attainment, 0.975, places=9)
        self.assertAlmostEqual(report.burn_rate, 5.0, places=9)
        self.assertAlmostEqual(report.remaining_budget_abs, -4.0, places=9)
        self.assertAlmostEqual(report.remaining_budget_fraction, -4.0, places=9)
        self.assertEqual(report.status, budget.EXHAUSTED)

    def test_too_few_samples_is_a_status_and_four_none_values_never_a_fabricated_attainment(self):
        """The contract this module exists for: `insufficient_data` is a value, not a formatting choice."""
        report = self.report(bad=(0, 1), min_samples=201)
        self.assertEqual(report.status, budget.INSUFFICIENT_DATA)
        self.assertEqual((report.total, report.good, report.bad), (200, 198, 2),
                         'what the window held is still known, and is still reported')
        self.assertIsNone(report.attainment)
        self.assertIsNone(report.burn_rate)
        self.assertIsNone(report.remaining_budget_abs)
        self.assertIsNone(report.remaining_budget_fraction)
        self.assertAlmostEqual(report.budget_fraction, 0.005, places=12)

    def test_an_empty_window_reports_insufficient_rather_than_a_perfect_month(self):
        report = budget.evaluate(self.objective, [], NOW.timestamp())
        self.assertEqual(report.status, budget.INSUFFICIENT_DATA)
        self.assertEqual(report.total, 0)
        self.assertIsNone(report.attainment)
        self.assertIsNone(report.burn_rate)

    def test_the_availability_and_latency_classifiers_share_one_arithmetic(self):
        """Three bad of six is the same attainment whichever classifier judged them — no branch for it."""
        latency = LatencyObjective(name='demo-api.latency', threshold_s=0.3, target=0.5, window_s=3600)
        points = [(NOW.timestamp() - 60 * position, value) for position, value in
                  enumerate([0.1, 0.2, 0.3, 0.4, 0.3, 0.29])]
        report = budget.evaluate(latency, points, NOW.timestamp())
        self.assertEqual((report.total, report.good, report.bad), (6, 5, 1))
        self.assertAlmostEqual(report.attainment, 5 / 6, places=12)
        self.assertAlmostEqual(report.burn_rate, (1 / 6) / 0.5, places=12)


class BurnRateTests(unittest.TestCase):
    """The rate over an arbitrary window, and the ``None`` that keeps an empty one from passing."""

    def setUp(self):
        self.objective = availability()

    def test_the_rate_over_the_short_window_is_the_number_the_pair_is_judged_on(self):
        # 432 s apart: the last 300 s hold exactly one sample, and it is failed. (1/1) / 0.005 = 200.
        rate = budget.burn_rate(self.objective, samples(bad=(0,)), 300, NOW.timestamp())
        self.assertAlmostEqual(rate, 200.0, places=9)

    def test_an_empty_window_has_no_burn_rate_and_that_none_is_not_zero(self):
        """Zero burn is a measured statement about a healthy window; ``None`` is the absence of one."""
        series = samples(3, step=600, end=NOW - dt.timedelta(seconds=600))   # newest sits 600 s before NOW
        self.assertIsNone(budget.burn_rate(self.objective, series, 300, NOW.timestamp()))
        self.assertIsNone(budget.burn_rate(self.objective, [], 300, NOW.timestamp()))

    def test_a_window_the_function_cannot_measure_is_refused_not_guessed(self):
        for broken in (0, -60, True, '5m', float('nan')):
            with self.assertRaises(ValueError, msg=repr(broken)):
                budget.burn_rate(self.objective, samples(), broken, NOW.timestamp())


class InputBoundTests(unittest.TestCase):
    """Fail closed on the shape of a series, because every number above is a ratio over it."""

    def test_a_series_past_the_store_row_bound_is_refused_rather_than_sampled_down(self):
        oversized = [(NOW.timestamp(), 1.0)] * (budget.MAX_SAMPLES + 1)
        with self.assertRaises(ValueError):
            budget.evaluate(availability(), oversized, NOW.timestamp())

    def test_a_malformed_point_is_refused_by_both_entry_points(self):
        for broken in ([(NOW.timestamp(), 'up')], [(NOW.timestamp(), float('nan'))],
                       [('12:00', 1.0)], [(NOW.timestamp(), 1.0, 'extra')], [(NOW.timestamp(), None)],
                       'not-a-series'):
            with self.assertRaises(ValueError, msg=str(broken)):
                budget.burn_rate(availability(), broken, 300, NOW.timestamp())


class FastBurnPolicyTests(unittest.TestCase):
    """The pair's own refusals, kept from v0.1 — and the one field v0.1 carried that did not cross."""

    def test_the_defaults_are_the_canonical_one_hour_over_five_minutes_at_fourteen_point_four(self):
        policy = budget.FastBurnPolicy(objective=availability())
        self.assertEqual((policy.long_window_s, policy.short_window_s, policy.threshold),
                         (3600.0, 300.0, 14.4))
        self.assertFalse(hasattr(policy, 'severity'),
                         'loudness is a config field resolved by platform/vocabulary.severity; this '
                         'module may not name a severity rung')

    def test_the_short_window_must_be_the_short_one(self):
        for pair in ((300, 300), (300, 3600)):
            with self.assertRaises(ValueError, msg=str(pair)):
                budget.FastBurnPolicy(objective=availability(), long_window_s=pair[0],
                                      short_window_s=pair[1])

    def test_a_non_positive_or_unmeasurable_bound_is_refused(self):
        for broken in (0, -1, True, float('nan')):
            with self.assertRaises(ValueError, msg=repr(broken)):
                budget.FastBurnPolicy(objective=availability(), threshold=broken)
            with self.assertRaises(ValueError, msg=repr(broken)):
                budget.FastBurnPolicy(objective=availability(), short_window_s=broken)
            with self.assertRaises(ValueError, msg=repr(broken)):
                budget.FastBurnPolicy(objective=availability(), long_window_s=broken)


class SpanTextTests(unittest.TestCase):
    def test_one_function_formats_every_window_length_the_round_summary_prints(self):
        self.assertEqual(budget.window_span(3600), '1:00:00')
        self.assertEqual(budget.window_span(300), '0:05:00')
        self.assertEqual(budget.window_span(86_400), '1 day, 0:00:00')
        for broken in (-1, True, float('nan')):
            with self.assertRaises(ValueError, msg=repr(broken)):
                budget.window_span(broken)

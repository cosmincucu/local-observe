"""Trend models over metric series: OLS linear and Holt double-exponential, pure and bounded.

Ported from `legacy:forecast/models.py` (T3.2, 127 lines) with the arithmetic kept and the *floor* added.
Both models consume plain ``(epoch_seconds, value)`` pairs, so a read through the store facade, a
cursor replay and a test fixture are the same input — which is the property `alert conditions` built
`conditions.ordered_points` to guarantee, and this module's series arrives through it.

Nothing here reads a store, a file, a socket or a clock, and nothing here decides whether a number is
a finding: `timetothreshold.py` does that. This file answers one question — *given these points, where
does the line/slope go* — which is why it imports one contract constant and no transport. The one
import that is not stdlib is `store.client.MAX_ROWS`, restated here as `MAX_FIT_POINTS` rather than
copied as a literal: a series longer than the store can hand back in one read cannot be fitted
honestly either, and the two bounds must not be able to drift apart.

Two refusals are this port's, and both exist because v0.1's models would happily fit anything sortable:

* **non-finite values are refused** (`nan`, `inf`). v0.1 casts with `float()` and divides: an OLS fit
  over a `nan` returns a `nan` slope, and a `nan` slope reaches
  `legacy:forecast/timetothreshold.py:51`'s `(threshold - intercept) / slope` and answers `nan` — an ETA
  that is a number-shaped *nothing*, which `threshold_event` would happily build an event from. Here a
  poisoned sample is a refusal naming the position, before any arithmetic can launder it;
* **a hard floor of `MIN_FIT_POINTS`** (see below) that configuration cannot lower. v0.1's floor was
  two points, and a straight line through two points has `r2 == 1.0` by construction — a "perfect fit"
  that is arithmetic rather than evidence, extrapolated forever.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass

from local_observe.store.client import MAX_ROWS

#: The fewest samples a forecast may be fitted from, and the lowest value configuration may name.
#: Two points define a line exactly, so `r2` is identically 1.0 and there is no residual left to
#: disprove the trend with; three points can still be collinear by luck. Four is the floor this
#: repository already holds for learning anything from a series
#: (`anomaly.LIMITS['min_points'] == (4, SERIES_MAX_POINTS)`), so the two estimators refuse a thin
#: sample identically and no rule can be written that one can fit and the other must call
#: `insufficient`.
MIN_FIT_POINTS = 4
#: A series longer than one bounded store read cannot be honest about its own start
#: (`store.client.MAX_ROWS`); see the module docstring for why this is restated and not copied.
MAX_FIT_POINTS = MAX_ROWS
#: The two fits this package knows, and the one a rule document gets when it says nothing. Holt is the
#: default because it is the model v0.1 pointed its capacity series at: it tracks a level that has
#: moved, where OLS averages the whole span and so answers a *late* ETA for a ramp that started late.
MODELS = ('linear', 'holt')
DEFAULT_ALPHA = 0.5
DEFAULT_BETA = 0.3


class ModelRefused(ValueError):
    """A series these models will not fit. The reason names the rule, never the sample values."""


@dataclass(frozen=True)
class Trend:
    """OLS linear fit ``value(t) = slope * t + intercept``, with ``t`` in epoch seconds."""

    slope: float        # value units per second
    intercept: float    # value at epoch 0 — an artefact of the parameterisation, never a reading
    r2: float           # coefficient of determination in [0, 1]

    def value_at(self, epoch_s: float) -> float:
        """Return the fitted value at one instant (epoch seconds), which may be in the future."""
        return self.slope * epoch_s + self.intercept


@dataclass(frozen=True)
class HoltFit:
    """Holt double-exponential state after consuming the series (no seasonality, no damping).

    `trend` is per **step**, so `step_s` (the mean sample spacing) is what converts it into wall-clock
    time; projections are read forward from `last_epoch_s`, never from the instant the fit was asked
    for. `alpha`/`beta` travel with the state because the confidence note quotes them: a forecast is
    only interpretable next to the smoothing that produced it.
    """

    level: float
    trend: float          # value units per step
    alpha: float
    beta: float
    step_s: float         # mean spacing between samples, seconds
    last_epoch_s: float   # timestamp of the last consumed point

    def forecast(self, steps: float) -> float:
        """Return the projected value *steps* smoothing steps after the last consumed point."""
        return self.level + steps * self.trend


def checked(points: Sequence[tuple[float, float]], *, fn: str,
            min_points: int = MIN_FIT_POINTS) -> list[tuple[float, float]]:
    """Return *points* as finite, time-sorted ``(float, float)`` pairs; anything else is a refusal.

    The epoch *range* bound is not repeated here: `conditions.ordered_points` applies it to every
    series that reaches a rule (`EPOCH_MIN`/`EPOCH_MAX`), and this module converts no epoch into a
    datetime, so a wild-but-finite timestamp cannot do damage inside a fit. What is bounded here is
    what the arithmetic itself needs: enough points, finite values, distinct instants, and a length
    the caller could have read in one page.
    """
    if isinstance(points, (str, bytes)) or not isinstance(points, Sequence):
        raise ModelRefused(f'{fn} needs a sequence of (epoch_seconds, value) points')
    if len(points) > MAX_FIT_POINTS:
        raise ModelRefused(f'{fn} needs at most {MAX_FIT_POINTS} points, got {len(points)}')
    if not min_points <= len(points):
        raise ModelRefused(f'{fn} needs at least {min_points} points, got {len(points)}')
    ordered: list[tuple[float, float]] = []
    for position, point in enumerate(sorted(((float(t), float(v)) for t, v in points),
                                            key=lambda item: item[0])):
        if not all(math.isfinite(part) for part in point):
            raise ModelRefused(f'{fn}: point {position} is not finite; a trend through a nan or an '
                               'inf is a number-shaped nothing, not a forecast')
        ordered.append(point)
    if ordered[0][0] == ordered[-1][0]:
        raise ModelRefused(f'{fn}: every point shares one timestamp; a trend needs two instants')
    return ordered


def fit_linear(points: Sequence[tuple[float, float]], *,
               min_points: int = MIN_FIT_POINTS) -> Trend:
    """OLS fit of value against time, with the times centred on their own mean.

    Centring is not cosmetic: epoch magnitudes (~1.7e9) squared overflow the useful digits of a float
    and the slope arrives as noise, which is v0.1's reason in one line (`legacy:forecast/models.py:60`).
    `r2` is 1.0 for an exactly-flat series — the constant fit *is* exact there, and it is not a
    spurious trend: `timetothreshold` refuses a zero slope before it can be read as one.
    """
    ordered = checked(points, fn='fit_linear', min_points=min_points)
    xs = [t for t, _ in ordered]
    ys = [v for _, v in ordered]
    x_mean = math.fsum(xs) / len(xs)
    y_mean = math.fsum(ys) / len(ys)
    sxx = math.fsum((x - x_mean) ** 2 for x in xs)
    sxy = math.fsum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = y_mean - slope * x_mean
    ss_tot = math.fsum((y - y_mean) ** 2 for y in ys)
    if ss_tot == 0.0:
        r2 = 1.0
    else:
        ss_res = math.fsum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
        r2 = max(0.0, 1.0 - ss_res / ss_tot)
    return Trend(slope=slope, intercept=intercept, r2=r2)


def fit_holt(points: Sequence[tuple[float, float]], *, alpha: float = DEFAULT_ALPHA,
             beta: float = DEFAULT_BETA, min_points: int = MIN_FIT_POINTS) -> HoltFit:
    """Simple Holt (double-exponential, no seasonality) over the series, one step per sample.

    Irregular spacing is absorbed into `step_s` (the mean spacing) for time conversion, exactly as
    v0.1 does — so a series with gaps yields a projection whose *step* count is honest and whose
    seconds are an average. Initialisation is ``level = y0``, ``trend = y1 - y0``, which is exact on a
    clean ramp: the tests rely on that to assert an analytic crossing time from both models at once.

    Raises:
        ModelRefused: Either smoothing constant is outside ``(0, 1]`` — checked here as well as at
            configuration load, because these functions are importable on their own and a constant of
            ``0`` freezes the level at the first sample and then reports a forecast forever.
    """
    for name, value in (('alpha', alpha), ('beta', beta)):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
                or not 0.0 < value <= 1.0:
            raise ModelRefused(f'fit_holt: {name} must be in (0, 1], got {value!r}')
    ordered = checked(points, fn='fit_holt', min_points=min_points)
    xs = [t for t, _ in ordered]
    ys = [v for _, v in ordered]
    step_s = (xs[-1] - xs[0]) / (len(xs) - 1)
    level = ys[0]
    trend = ys[1] - ys[0]
    for value in ys[1:]:
        previous_level = level
        level = alpha * value + (1.0 - alpha) * (level + trend)
        trend = beta * (level - previous_level) + (1.0 - beta) * trend
    return HoltFit(level=level, trend=trend, alpha=alpha, beta=beta, step_s=step_s,
                   last_epoch_s=xs[-1])


def fit(points: Sequence[tuple[float, float]], model: str = 'holt', *,
        alpha: float = DEFAULT_ALPHA, beta: float = DEFAULT_BETA,
        min_points: int = MIN_FIT_POINTS) -> Trend | HoltFit:
    """Fit *points* with the named model, so a rule's knob is the only thing a caller passes.

    One dispatcher instead of a branch at every call site: `timetothreshold.verdict` refits this series
    once per evaluation bucket and must not be able to use one model for one bucket and another for the
    next, which is what two call sites with two defaults would eventually do.
    """
    if model == 'linear':
        return fit_linear(points, min_points=min_points)
    if model == 'holt':
        return fit_holt(points, alpha=alpha, beta=beta, min_points=min_points)
    raise ModelRefused(f'unknown forecast model {model!r}; this package fits {", ".join(MODELS)}')

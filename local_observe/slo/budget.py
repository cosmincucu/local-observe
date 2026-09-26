"""Error-budget attainment, burn rate and the multi-window fast-burn pair; pure and clock-injected.

Ported from `legacy:slo/errorbudget.py` (264 lines) with its arithmetic, its status words and its two
stated contracts intact:

* **too few samples is an answer, not a number.** A window holding fewer than the objective's
  `min_samples` yields :data:`INSUFFICIENT_DATA` with `attainment`, `remaining_budget_*` and `burn_rate`
  all ``None`` — never an attainment of 1.0 and never 0.0. Collapsing that status into a number is the
  exact failure this module exists to prevent, and :mod:`local_observe.slo.alerts` keeps it visible one
  layer up as a `coverage` event rather than a quiet `resolved`.
* **fast burn is two windows ANDed.** The pair (default 1 h / 5 m) fires only when **both** burn at or
  above the threshold: the long window proves the burn is sustained, so a blip cannot page, and the
  short window proves it is still happening, so a burn that stopped an hour ago cannot page either. One
  window burning is :data:`QUIET`, in both directions.

The clock is always injected (`now_s` on every function) and nothing here reads wall clock, sleeps,
imports a store or files an event. Two things from v0.1 did **not** cross, deliberately:

* **`burn_event()` has no twin here.** It built a `core.events.Event` and then
  `core.events.derive_dedup_key(event)`, whose inputs are `source + resource_ref + type + labels` — a
  dedup identity made of mutable label text, which `platform/vocabulary.py` refuses on the record ("add
  one label to a rule and every past incident becomes a different event"). This repository's identity is
  `conditions(key, watermark, event_id, status)` with `key = digest(source, rule_id, rule_version,
  resource_id, condition)` (`platform/state.py`), and **no timestamp is an input to it**, which is the
  same promise v0.1 made about its dedup key and is what lets a re-fire share one condition. The event
  itself is built by `platform/detections.event` in :mod:`.alerts`, which is the only event author in
  this package;
* **`FastBurnPolicy.severity` is gone.** v0.1 carried `severity: str = "critical"` on the policy from a
  five-rung ladder this repository does not admit (`state.validate_event` allows three, and
  `error`→`warning`/`critical` is a per-row decision). Loudness arrives as a *config field* resolved
  through `platform/vocabulary.severity`, so this file spells no severity word at all.

`Sample` stays `(epoch_s, value)` — the same point shape `platform/conditions.ordered_points` accepts and
`platform/anomaly.series_points` produces, so a store read, a cursor replay and a test fixture are
interchangeable inputs to these functions.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple

from local_observe.store.client import MAX_ROWS

from .objectives import Objective, error_budget_fraction

__all__ = ['OK', 'EXHAUSTED', 'INSUFFICIENT_DATA', 'FIRING', 'QUIET', 'BudgetReport', 'evaluate',
           'burn_rate', 'FastBurnPolicy', 'BurnCheck', 'check_fast_burn', 'WindowCounts']

#: Budget-report statuses. `INSUFFICIENT_DATA` is a *value*, not a formatting choice: every derived
#: number beside it is ``None``, and a caller that reads it as 100 % has undone this card.
OK, EXHAUSTED, INSUFFICIENT_DATA = 'ok', 'exhausted', 'insufficient_data'
#: Burn-check statuses, mirroring this repository's `firing`/`resolved` idiom (`QUIET` is v0.1's word for
#: "judged, and not firing"; the condition's own resolved event is built one layer up, in `.alerts`).
FIRING, QUIET = 'firing', 'quiet'
#: The point-list bound, taken from the store's own row cap so a caller cannot hand these functions a
#: series the read facade could never have produced. An oversized list is refused, never sampled down.
MAX_SAMPLES = MAX_ROWS

Sample = tuple[float, Any]  # (epoch_s, value) — a boolean-ish outcome or a metric value


class WindowCounts(NamedTuple):
    """How many samples one window held, split the only way an SLO cares about: good and bad.

    `total` is the sum, and it is the honest denominator of an attainment — reported on every path,
    including the ones where the floor was not met and no ratio may be printed.
    """

    good: int
    bad: int

    @property
    def total(self) -> int:
        """Return the sample count the split was made over."""
        return self.good + self.bad


def _iso(epoch_s: float) -> str:
    """Render one injected instant as UTC ISO-8601 text, for a status field and never for identity."""
    return datetime.fromtimestamp(epoch_s, timezone.utc).isoformat(timespec='microseconds')


def _points(samples: Sequence[Sample]) -> list[Sample]:
    """Return *samples* as a bounded list of ``(finite epoch, numeric-or-boolean value)`` pairs.

    Fail closed on shape, because every number in this module is a ratio over these points: a value that
    is text, a nan, or a tuple of the wrong length would turn a broken feed into an attainment figure.
    The bound is `MAX_SAMPLES` — the store's own row cap — so a caller that reads past what the facade
    can return is told so here rather than being silently truncated.
    """
    if not isinstance(samples, Sequence) or isinstance(samples, (str, bytes)):
        raise ValueError('error-budget samples must be a sequence of (epoch seconds, value) points')
    if len(samples) > MAX_SAMPLES:
        raise ValueError(f'error-budget series exceeds its bound of {MAX_SAMPLES} points')
    for point in samples:
        if not isinstance(point, tuple) or len(point) != 2:
            raise ValueError('error-budget sample must be an (epoch seconds, value) pair')
        epoch_s, value = point
        if isinstance(epoch_s, bool) or not isinstance(epoch_s, (int, float)) or not math.isfinite(epoch_s):
            raise ValueError('error-budget sample names no finite instant')
        if isinstance(value, str) or not isinstance(value, (bool, int, float)) \
                or (not isinstance(value, bool) and not math.isfinite(value)):
            raise ValueError('error-budget sample value is not numeric or boolean')
    return list(samples)


def _window(samples: Sequence[Sample], window_s: float, now_s: float) -> list[Sample]:
    """Return the samples inside the half-open rolling window ``(now_s - window_s, now_s]``.

    v0.1's boundary rule, kept verbatim: the evaluation instant is inclusive and the far edge exclusive,
    so two consecutive windows over one series share no sample and a point stamped exactly at the
    boundary belongs to the window that ends at it.
    """
    return [point for point in samples if now_s - window_s < point[0] <= now_s]


def _counts(objective: Objective, samples: Sequence[Sample]) -> WindowCounts:
    """Split one window's samples into good and bad using the objective's own classifier.

    A classifier that refuses (a text value against a latency objective) propagates: `is_good` deciding
    that a sample is meaningless is a bug in the feed, and neither counting it good nor counting it bad
    is an answer this module is allowed to invent.
    """
    good = sum(1 for _, value in samples if objective.is_good(value))
    return WindowCounts(good=good, bad=len(samples) - good)


@dataclass(frozen=True)
class BudgetReport:
    """Attainment and error-budget state of one objective at one instant.

    `status` is :data:`INSUFFICIENT_DATA` when the window held fewer than the objective's `min_samples`,
    and then **every derived number below is ``None``** — `total`, `good` and `bad` still count what was
    seen, because "we saw three samples" is known and "attainment is 0 %" is not. `remaining_budget_*`
    go negative on overspend (visible, with :data:`EXHAUSTED`) rather than clamping at zero, because a
    budget spent twice is a fact an operator needs and a clamp hides it. `burn_rate` is
    `bad-fraction / budget-fraction`, so 1.0 is the sustainable pace and 14.4 is the canonical fast-burn
    threshold (the pace that spends a 30-day budget in about 50 hours).
    """

    objective: str
    status: str  # OK | EXHAUSTED | INSUFFICIENT_DATA
    window_start_s: float
    window_end_s: float
    total: int
    good: int
    bad: int
    budget_fraction: float  # the allowed bad fraction, 1 - target
    attainment: float | None  # good / total
    remaining_budget_fraction: float | None
    remaining_budget_abs: float | None
    burn_rate: float | None


def evaluate(objective: Objective, samples: Sequence[Sample], now_s: float) -> BudgetReport:
    """Report attainment and remaining budget over *objective*'s rolling window ending at *now_s*.

    Fewer than `objective.min_samples` samples in that window is an :data:`INSUFFICIENT_DATA` report with
    its numbers left ``None``: an attainment is never invented. The status is decided by the *remaining*
    budget rather than by the attainment crossing the target, which is the same claim read from the other
    side and keeps `attainment` a number a reader can check against `good`/`bad`.
    """
    windowed = _window(_points(samples), objective.window_s, now_s)
    good, bad = _counts(objective, windowed)
    total = good + bad
    budget = error_budget_fraction(objective)
    if total < objective.min_samples:
        return BudgetReport(objective=objective.name, status=INSUFFICIENT_DATA,
                            window_start_s=now_s - objective.window_s, window_end_s=now_s,
                            total=total, good=good, bad=bad, budget_fraction=budget, attainment=None,
                            remaining_budget_fraction=None, remaining_budget_abs=None, burn_rate=None)
    attainment = good / total
    remaining_abs = budget * total - bad          # bad samples the window could still have absorbed
    burn = (bad / total) / budget
    return BudgetReport(objective=objective.name, status=OK if remaining_abs >= 0 else EXHAUSTED,
                        window_start_s=now_s - objective.window_s, window_end_s=now_s,
                        total=total, good=good, bad=bad, budget_fraction=budget, attainment=attainment,
                        remaining_budget_fraction=1.0 - burn, remaining_budget_abs=remaining_abs,
                        burn_rate=burn)


def burn_rate(objective: Objective, samples: Sequence[Sample], window_s: float,
              now_s: float) -> float | None:
    """Return the burn rate over an arbitrary rolling window ending at *now_s*, or ``None``.

    ``bad-fraction / budget-fraction``, so 1.0 is the sustainable pace. **An empty window returns
    ``None`` and not 0.0**: no data is not zero burn, and the caller must handle the distinction visibly
    — in this package that means :data:`INSUFFICIENT_DATA` on the check and a `coverage` event on the
    wire, never a quiet pass.
    """
    if isinstance(window_s, bool) or not isinstance(window_s, (int, float)) \
            or not math.isfinite(window_s) or window_s <= 0:
        raise ValueError('burn window must be a finite number of seconds above zero')
    windowed = _window(_points(samples), window_s, now_s)
    if not windowed:
        return None
    counts = _counts(objective, windowed)
    return (counts.bad / counts.total) / error_budget_fraction(objective)


@dataclass(frozen=True)
class FastBurnPolicy:
    """One objective plus the multi-window alert pair that watches it (v0.1's long/short defaults).

    `threshold` is the burn rate at or above which *both* windows must sit for the pair to fire. The
    defaults are the canonical 1 h / 5 m at 14.4x. Nothing here carries a severity: loudness is a config
    field resolved through `platform/vocabulary.severity`, and this module knows no volume word (see the
    module docstring for why v0.1's `severity` field did not cross).
    """

    objective: Objective
    long_window_s: float = 3600.0
    short_window_s: float = 300.0
    threshold: float = 14.4

    def __post_init__(self) -> None:
        """Refuse a pair that cannot mean what it says: inverted windows, a non-positive bound, a nan."""
        for name in ('long_window_s', 'short_window_s', 'threshold'):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
                    or value <= 0:
                raise ValueError(f'{name} must be a finite number above zero, got {value!r}')
        if self.short_window_s >= self.long_window_s:
            raise ValueError(f'short_window_s ({self.short_window_s!r}) must be shorter than '
                             f'long_window_s ({self.long_window_s!r})')

    def check(self, samples: Sequence[Sample], now_s: float) -> BurnCheck:
        """Return this policy's verdict over *samples* at *now_s* — :func:`check_fast_burn` swapped."""
        return check_fast_burn(self, samples, now_s)


@dataclass(frozen=True)
class BurnCheck:
    """One fast-burn evaluation at one instant, with both windows' numbers beside the verdict.

    `status` is :data:`FIRING` (both windows at or above the threshold), :data:`QUIET` (judged, and not)
    or :data:`INSUFFICIENT_DATA` when **either** window held no samples — an unjudgeable window is
    reported and never read as zero burn. `timestamp` is a rendering of the evaluation instant for a
    status line: it is not an identity input anywhere in this package, which is the property that keeps a
    re-fire on one condition (`.alerts` states where the identity lives).
    """

    objective: str
    status: str  # FIRING | QUIET | INSUFFICIENT_DATA
    long_burn_rate: float | None
    short_burn_rate: float | None
    threshold: float
    long_window_s: float
    short_window_s: float
    timestamp: str

    @property
    def burning(self) -> bool:
        """Return whether this check is the firing case — the only shape the sustained machine steps on."""
        return self.status == FIRING


def check_fast_burn(policy: FastBurnPolicy, samples: Sequence[Sample],
                    now_s: float) -> BurnCheck:
    """Judge the long/short pair at *now_s*, and refuse to guess about a window it could not measure.

    The order of the three branches is the whole rule and each one is tested: an unmeasurable window
    answers :data:`INSUFFICIENT_DATA` **before** the AND is evaluated (so "no samples" can never read as
    "under threshold", which would be a silent pass), and only then does one window burning answer
    :data:`QUIET`.
    """
    if not isinstance(policy, FastBurnPolicy):
        raise ValueError('fast-burn check needs a policy binding an objective to its window pair')
    if isinstance(now_s, bool) or not isinstance(now_s, (int, float)) or not math.isfinite(now_s):
        raise ValueError('fast-burn check needs a finite evaluation instant')
    bounded = _points(samples)
    long_burn = burn_rate(policy.objective, bounded, policy.long_window_s, now_s)
    short_burn = burn_rate(policy.objective, bounded, policy.short_window_s, now_s)
    if long_burn is None or short_burn is None:
        status = INSUFFICIENT_DATA
    elif long_burn >= policy.threshold and short_burn >= policy.threshold:
        status = FIRING
    else:
        status = QUIET
    return BurnCheck(objective=policy.objective.name, status=status, long_burn_rate=long_burn,
                     short_burn_rate=short_burn, threshold=policy.threshold,
                     long_window_s=policy.long_window_s, short_window_s=policy.short_window_s,
                     timestamp=_iso(now_s))


def window_span(seconds: float) -> str:
    """Render one window length as the short human text a log line and a round summary carry.

    Kept here rather than inlined in the producer so the compliance window, the burn windows and the
    numbers printed beside an attainment are formatted by one function — three spellings of "3600" in
    one operator view is how a reader starts doubting the numbers beside it.
    """
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not math.isfinite(seconds) \
            or seconds < 0:
        raise ValueError('window span must be a finite non-negative number of seconds')
    return str(timedelta(seconds=int(seconds)))

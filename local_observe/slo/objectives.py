"""SLO objective definitions: a target, a rolling compliance window, and a good/bad classifier.

Ported from `legacy:slo/objectives.py` with the maths, the field names and the refusals unchanged —
`AvailabilityObjective`, `LatencyObjective`, the `Objective` union and `error_budget_fraction` are
v0.1's, and the module still **imports nothing local**. That property is the port table's stated reason
for calling this package worth converting ("signal-source-agnostic by design"), so it is kept rather
than tidied away: whoever owns the definition of *good* owns the arithmetic in
:mod:`local_observe.slo.budget`, and neither one has ever heard of a store, a probe or an endpoint.
Evaluation lives there; this file only says what a sample means.

**Two signals are evaluable in this build, and both are named.** v0.1's docstring offered "any
availability/latency signal (synthetic checks, RUM beacons, inside-out probes) that can be reduced to
plain `(epoch_s, value)` pairs". The reduction still holds — a series *is* `(epoch seconds, value)` pairs
and nothing more is asked of a source — but the sources this tree can actually put such a series in
front of are exactly two, because reads come through `local_observe/store/client.py` and nowhere else
(store facade's one facade):

1. **a synthetics/Gatus availability series** — the pass/fail outcome of a synthetic check for one
   declared resource, present in the store as a numeric 0/1 series and judged by
   :class:`AvailabilityObjective`, where a truthy value is a success. The product never *writes* that
   series: a collector or an operator job is what turns a probe result into a sample, and where nothing
   writes one the read answers empty and `slo.budget` reports `insufficient_data` rather than an
   attainment of 1.0.
2. **any declared metric series** whose samples are values good up to a limit, judged by
   :class:`LatencyObjective` — the general "at least `target` of samples sit at or under `threshold_s`"
   classifier. The class keeps v0.1's name (renaming it would rename the ported maths for no reader's
   benefit); the threshold is not necessarily seconds, and no browser is implied by it.

**What this build cannot evaluate, stated by name and not by omission: the RUM feed.** dead code culled the
v0.1 stretch tier and lists RUM among what it culled, and synthetic monitoring scope re-confirmed that cull rather than
reversing it, so there is no real-user-monitoring source anywhere in this tree. Measured on this
checkout, `grep -rin "rum" local_observe` returns one line — the `rum.cwv_spike` row of
`platform/vocabulary.py`'s crosswalk, which is a decision about a v0.1 type word and not a source of
data. So **no latency-from-the-browser number exists here**, and a reader who wants one owes a producer
for the beacons before owing an objective; inventing one from synthetic latency would be a different
claim wearing the same name.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ['AvailabilityObjective', 'LatencyObjective', 'Objective', 'error_budget_fraction']


def _validate_common(name: str, target: float, window_s: float, min_samples: int) -> None:
    """Refuse an objective that could not state its own question: no id, no bound, no floor.

    `target` is exclusive at both ends on purpose. A target of exactly `1.0` has an error budget of zero,
    which makes every bad sample an infinite burn rate (`bad / budget-fraction` divides by the zero this
    refuses), and a target of `0.0` is a page that can never be satisfied and never burns.
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError('objective name must be a non-empty string')
    if isinstance(target, bool) or not isinstance(target, (int, float)) or not 0.0 < target < 1.0:
        raise ValueError(f'target must be a finite fraction in (0, 1) exclusive, got {target!r}')
    if isinstance(window_s, bool) or not isinstance(window_s, (int, float)) or not window_s > 0:
        raise ValueError(f'window_s must be > 0, got {window_s!r}')
    if isinstance(min_samples, bool) or not isinstance(min_samples, int) or min_samples < 1:
        raise ValueError(f'min_samples must be a whole number >= 1, got {min_samples!r}')


@dataclass(frozen=True)
class AvailabilityObjective:
    """Availability SLO: at least `target` of the samples in the rolling window must be successes.

    `name` carries the config document's `objective_id`, because that is what a burn event's `rule_id`
    and durable `condition` are built from (see :mod:`local_observe.slo.alerts`) — one objective, one
    condition, in the platform's own identity terms.

    `min_samples` is the smallest sample count for which an attainment number is meaningful; below it
    evaluation reports `insufficient_data` with attainment and burn as ``None`` rather than fabricating
    an attainment from a window it cannot measure. That refusal is the reason this field exists at all,
    and it is the behaviour a port may not soften: an SLO read as "100 % over one sample" is a lie that
    pages nobody until the sample count recovers.
    """

    name: str
    target: float  # e.g. 0.995 for 99.5 %
    window_s: float  # the rolling compliance window, in seconds
    min_samples: int = 1

    def __post_init__(self) -> None:
        """Check the three fields every objective shares."""
        _validate_common(self.name, self.target, self.window_s, self.min_samples)

    def is_good(self, value: Any) -> bool:
        """Return whether one sample is a success: a truthy value means the check passed."""
        return bool(value)


@dataclass(frozen=True)
class LatencyObjective:
    """Latency SLO: at least `target` of the samples in the rolling window complete within `threshold_s`.

    A sample *at* the threshold is good (`<=`), which is v0.1's rule and the one a paged-consistency
    claim needs: an objective of "99 % of requests under 300 ms" is judged on the same boundary it is
    quoted with. The value is whatever the series holds; the name is kept from v0.1 for the reason in
    this module's docstring.
    """

    name: str
    threshold_s: float  # a sample is good when its value is at or under this
    target: float  # e.g. 0.99 for "99 % of samples at or under the threshold"
    window_s: float  # the rolling compliance window, in seconds
    min_samples: int = 1

    def __post_init__(self) -> None:
        """Check the shared fields, then the threshold this classifier judges values against."""
        _validate_common(self.name, self.target, self.window_s, self.min_samples)
        if isinstance(self.threshold_s, bool) or not isinstance(self.threshold_s, (int, float)) \
                or not self.threshold_s > 0:
            raise ValueError(f'threshold_s must be > 0, got {self.threshold_s!r}')

    def is_good(self, value: Any) -> bool:
        """Return whether one sample sits at or under this objective's threshold.

        A non-numeric value is a refusal, never a quiet ``False``: counting a malformed sample as a
        breach would let a broken collector page as an outage, and counting it as good would hide one.
        """
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError('latency objective requires a numeric sample value')
        return float(value) <= self.threshold_s


#: Either classifier. The union is what `budget.py` takes, so no arithmetic branches on which one.
Objective = AvailabilityObjective | LatencyObjective


def error_budget_fraction(objective: Objective) -> float:
    """Return the fraction of samples allowed to be bad: ``1 - target``.

    A 99.5 % objective has a 0.5 % error budget, and a burn rate of 1.0 means bad samples are arriving
    at exactly the pace that spends this budget over the compliance window. Both `objectives.py` and
    `budget.py` derive that number from here and nowhere else, so the two halves of the port cannot
    disagree about what a budget *is*.
    """
    return 1.0 - objective.target

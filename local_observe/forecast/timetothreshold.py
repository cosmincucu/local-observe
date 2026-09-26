"""Time-to-threshold prediction as a sustained condition: *will exceed*, filed apart from *has exceeded*.

Ported from `legacy:forecast/timetothreshold.py` (T3.2, 139 lines) and rewired around three facts this
repository holds and v0.1 did not: the event vocabulary is closed (event vocabulary), a verdict needs a `for:`
duration before it is a condition (`alert conditions`), and loudness is a config field resolved through a
crosswalk (`event vocabulary`), never a word typed at an event.

**What the admitted vocabulary does with a prediction.** v0.1 emitted the free-form type
`forecast.threshold_predicted`; this repo has no `forecast` kind and inventing one is event vocabulary's call, not
a producer's — `vocabulary.REFUSALS` already refuses that type *by name*, and its reason ends
"forecast owes a decision (widen ``kind``, or an advisory that opens nothing), not a mapping". This
module therefore files the admitted word and puts the difference in the condition identity, exactly
as `detections.evaluate` does for coverage (``rule['id'] + '.coverage'``) and `escalation.stage_event`
does for a rung (``chain.rule_id + '.stage' + str(stage)``):

* a prediction is `kind='threshold'` — the same kind the *actual* breach uses, because it is the same
  measured quantity (a number against a limit) evaluated from the same rule document;
* its `rule_id` and `condition` are ``<rule>.predicted``, so the condition key
  `state.Store.intake` digests (``source, rule_id, rule_version, resource_id, condition``) differs from
  the base rule's: "will exceed" and "has exceeded" are two conditions with two incident histories,
  and an operator reads which page to believe off the event itself. `rule_version` differs too, because
  it digests the fit knobs;
* severity comes from `conditions.Rule.severity()` — the rule's own `severity_source`/`severity_tier`
  resolved by `vocabulary.severity`. No severity literal appears in this file, so retuning how loud a
  forecast is stays a config edit and never a code change.

**What that does *not* buy, stated plainly.** `state.Store.intake` opens an incident and books a
delivery for *any* firing event whatever its severity, so a predicted crossing is as loud as the
crosswalk says the rule is — not an advisory. The refusals and the `for:` discipline below are what
keep that loudness honest; whether a forecast should page at all is the decision
`vocabulary.REFUSALS` names, and this package ships without it rather than inventing a kind.

**The sustained part, and what is actually being sustained.** A prediction is not a sample — it is a
statement re-made from a window of samples — so what must hold before it becomes a condition is the
*prediction*, not the crossing (the crossing is in the future and cannot be observed to persist). Each
evaluation bucket inside the rule's sustain span is re-judged using only the data that existed at that
instant, and `conditions.SustainedStateMachine` — the same machine `conditions.verdict` and
`dynamic_bands.verdict` step, imported and not re-implemented — gets one step per bucket. A run of
agreeing evaluations lasting ``for_seconds`` fires; a single spiky sample is one step, is silent, and
never opens anything. That silence is the machine's documented behaviour and the reason it is reused.

**Refusals, each carrying its reason in the answer** (`Prediction.confidence_note`, which lands in the
round summary and the log line):

* flat or receding → `eta_epoch_s is None` **with** the reason, never a spurious "will exceed";
* a series shorter than `min_points`, or one that cannot be fitted at all → `insufficient` /
  `unfittable`, never an extrapolation from a handful of samples;
* a crossing further out than `horizon_seconds` → not this rule's business this round: a capacity note,
  not a page;
* a series **already** at or past its threshold → refused as a prediction and named as a breach,
  because the base rule's own threshold verdict files that fact and this module must not page twice for
  one excursion;
* non-finite samples → refused by `models.checked` before any division can turn them into a plausible
  ETA;
* a read span over 7 days → refused at load, not clamped, because `store.client.Window` and
  `state.validate_event` both refuse it and a producer discovering that mid-round would report a blind
  tick as a verdict.

The predicted instant has nowhere to live in a canonical event: `state.validate_event` admits a closed
fourteen-field object with no summary, label or raw bag. So `eta` is reported in the producer's log
line and its cursor detail and is **not** carried on the event — the event cites the same
`metric-threshold` evidence reference `conditions.condition_event` builds, which points at the samples
the fit was made from. That is a loss relative to v0.1 (`legacy:forecast/timetothreshold.py:132` put the
ETA in ``raw``) and it is deliberate: the alternative is inventing an event field.
"""
from __future__ import annotations

import datetime as dt
import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple

from local_observe.inventory.validation import digest, read_document, utc_text
from local_observe.log import get_logger
from local_observe.platform import conditions
from local_observe.platform.conditions import (FIRING, RESOLVED, Verdict, condition_event,
                                               coverage_event)
from local_observe.platform.state import StateError, label
from local_observe.store.client import MAX_ROWS, MAX_WINDOW_SECONDS
from . import models

log = get_logger(__name__)

#: The environment variable that names this producer's configuration file. Unset or blank is the
#: documented off switch (`producer_config`): one INFO line naming it, exit 0, nothing opened. The
#: sibling variables are ``LO_FORECAST_SOURCE`` (the producer identity, which must match its token) and
#: ``LO_FORECAST_CURSOR`` (where this producer's own cursor lives, which a named configuration makes
#: required), plus what every producer here already reads: ``LO_INDEX_PATH``,
#: ``LO_CLICKHOUSE_URL``/``_USER``/``_PASSWORD_FILE``, ``LO_PLATFORM_URL``, ``LO_PRODUCER_TOKEN`` and
#: ``LO_INTERNAL_ALLOW_HTTP``. None of them is added to `examples/full/.env.example` by this card.
CONFIG_ENVIRONMENT = 'LO_FORECAST_CONFIG'
SOURCE_ENVIRONMENT = 'LO_FORECAST_SOURCE'
CURSOR_ENVIRONMENT = 'LO_FORECAST_CURSOR'
#: The condition namespace that separates a forecast from the breach it predicts. It reads the way
#: `.coverage` and `.stage<N>` read, and for the same reason: an ordinary `state.label` value, so no
#: vocabulary widens to carry it.
PREDICTED_SUFFIX = 'predicted'
#: The closed set of answers a prediction can carry. Only `crossing` may ever become a condition;
#: every other word is the reason it is not, and travels with one.
PREDICTION_STATES = ('crossing', 'already', 'flat', 'receding', 'insufficient', 'unfittable')
#: The words one forecast rule can report for one tick. `firing`/`resolved`/`pending`/`stale` are
#: `conditions.OUTCOMES` with their same meanings; `insufficient` is `dynamic_bands`' word, reused
#: rather than renamed; `breached` is this module's own and names the tick the series crossed without
#: a prediction being filed. `conditions.tick` may additionally report `unreadable` for a read the
#: store refused; `unseen` never appears here, because absence belongs to the base rule's condition.
OUTCOMES = ('firing', 'resolved', 'pending', 'stale', 'insufficient', 'breached')
DEFAULT_MODEL = 'holt'
DEFAULT_HORIZON_SECONDS = 3600
MAX_RULES = conditions.MAX_RULES
MAX_CONFIG_BYTES = conditions.MAX_CONFIG_BYTES
#: How many bucket-ends one round may re-fit and step the machine at. Enforced at load
#: (`ForecastRule.__post_init__`) and never applied by dropping steps at runtime: a rule whose sustain
#: span needs more evaluations than this is a rule whose `for:` duration nobody could reconstruct, and
#: silently truncating there would read as a condition that never earns its filing. The cost of the
#: bound is that at the widest evaluation window (3600 s) a forecast rule cannot sustain a run longer
#: than 256 hours without raising `evaluation_seconds`.
MAX_SUSTAIN_STEPS = 256
# Every bound is a refusal at load and not a runtime surprise, in the `conditions.LIMITS` shape. The
# timing bounds the inner rule owns are not restated here — `conditions.LIMITS` checks them through
# `conditions.rule` — so only the forecast knobs are, and the history ceiling is the store facade's own
# window bound so the failure is a config sentence and not a `StoreRefused` mid-round (the same
# reasoning and the same number as `dynamic_bands.MAX_HISTORY_SECONDS`).
LIMITS: dict[str, tuple[float, float]] = {
    'horizon_seconds': (60, MAX_WINDOW_SECONDS), 'min_points': (models.MIN_FIT_POINTS, MAX_ROWS),
    'alpha': (0.0, 1.0), 'beta': (0.0, 1.0), 'history_seconds': (60, MAX_WINDOW_SECONDS)}
CONFIG_KEYS = frozenset({'rules', 'interval_seconds', 'cursor'})
#: A forecast rule document. `series` is the document's name for what `conditions` calls `metric` (the
#: brief names the key `series`; one field carries it, mapped at load, so one thing never has two
#: names). `threshold` and the timing fields are the *base* rule's own, which is the point: the
#: prediction and the breach it predicts are written from one number.
RULE_KEYS = frozenset({'id', 'series', 'resource_id', 'source', 'severity_source', 'severity_tier',
                       'threshold', 'model', 'horizon_seconds', 'min_points', 'alpha', 'beta',
                       'evaluation_seconds', 'history_seconds', 'max_age_seconds', 'for_seconds',
                       'resolve_seconds'})
#: Which keys are handed to `conditions.rule` (the base rule reads them under its own bounds) and
#: which stay with the fit. `series` arrives as the inner rule's `metric`, because that is the name the
#: store read narrows on. The two sets plus `series` are exactly :data:`RULE_KEYS`, and the refusal in
#: `rule()` is what keeps a key from landing in neither.
INNER_KEYS = frozenset({'id', 'resource_id', 'source', 'severity_source', 'severity_tier', 'threshold',
                        'evaluation_seconds', 'history_seconds', 'max_age_seconds', 'for_seconds',
                        'resolve_seconds'})
FIT_KEYS = ('model', 'alpha', 'beta', 'min_points', 'horizon_seconds')
RULE_TEXT_FIELDS = ('id', 'series', 'resource_id', 'source', 'severity_source', 'severity_tier')
RULE_INT_FIELDS = ('evaluation_seconds', 'history_seconds', 'max_age_seconds', 'for_seconds',
                   'resolve_seconds', 'min_points', 'horizon_seconds')
SMOOTHING_FIELDS = ('alpha', 'beta')


@dataclass(frozen=True)
class Prediction:
    """Where a fit says the threshold will be crossed, or the reason it will not.

    Ported from `legacy:forecast/timetothreshold.Prediction` with one field added: v0.1 distinguished its
    refusals by reading `confidence_note` prose, which is fine for a human and useless to a test or a
    round summary. `state` is the closed word for what happened (:data:`PREDICTION_STATES`) and the
    note keeps v0.1's job — saying *how confidently* (`r2`, the slope, the smoothing constants).
    """

    eta_epoch_s: float | None      # None unless a crossing is coming (`already` names the instant it happened)
    confidence_note: str           # always states why, and how confident
    threshold: float
    now_epoch_s: float
    model: str                     # 'linear' | 'holt'
    state: str

    def __post_init__(self) -> None:
        """Refuse the shapes that would let a non-crossing read as a crossing."""
        if self.state not in PREDICTION_STATES:
            raise StateError('Forecast prediction state is not one this module reports')
        has_eta = self.eta_epoch_s is not None
        if has_eta and (isinstance(self.eta_epoch_s, bool)
                        or not isinstance(self.eta_epoch_s, (int, float))
                        or not math.isfinite(self.eta_epoch_s)):
            raise StateError('A forecast instant, when present, must be a finite number')
        if has_eta and self.state not in ('crossing', 'already'):
            raise StateError('A refused forecast carries no instant')
        if self.state == 'crossing' and not has_eta:
            raise StateError('A predicted crossing needs an instant')

    @property
    def crossing(self) -> bool:
        """Whether this prediction may feed the state machine. Every other state is a refusal."""
        return self.state == 'crossing'

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe form the round summary and the log line carry."""
        return {'state': self.state, 'model': self.model, 'threshold': self.threshold,
                'eta': utc_text(dt.datetime.fromtimestamp(self.eta_epoch_s, dt.timezone.utc))
                if self.eta_epoch_s is not None else None, 'note': self.confidence_note}


class AtInstant(NamedTuple):
    """One bucket's answer: was it judgeable, did it predict a near crossing, and what did it see."""

    judgeable: bool
    crossing: bool
    value: Any
    prediction: Prediction | None
    detail: str | None = None


def _finite(value: Any, *, name: str) -> float:
    """Return *value* as a finite float, refusing the two numbers that would poison every comparison."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise StateError(f'Forecast {name} must be a finite number')
    return float(value)


def _linear_prediction(trend: models.Trend, threshold: float, now: float) -> Prediction:
    """Analytic crossing for an OLS fit: v0.1's three refusals, now each named.

    The order matters. `already` is checked before the slope, so a series that crossed on a flat fit
    is reported as a breach and not as a `flat` nothing — the operator needs "it happened", not "no
    news".
    """
    current = trend.value_at(now)
    if current >= threshold:
        return Prediction(now, f'already at or above threshold (fitted {current:g} against '
                               f'{threshold:g}, slope {trend.slope:+g}/s)', threshold, now, 'linear',
                          'already')
    if trend.slope == 0.0:
        return Prediction(None, 'flat series: no upward trend toward threshold', threshold, now,
                          'linear', 'flat')
    if trend.slope < 0.0:
        return Prediction(None, 'receding series: trending away from threshold', threshold, now,
                          'linear', 'receding')
    eta = (threshold - trend.intercept) / trend.slope          # analytic crossing
    return Prediction(eta, f'linear trend {trend.slope:+g}/s, r2={trend.r2:.4f}', threshold, now,
                      'linear', 'crossing')


def _holt_prediction(fit: models.HoltFit, threshold: float, now: float) -> Prediction:
    """Step projection for a Holt fit: steps to the threshold, converted by the mean sample spacing."""
    note_base = f'holt(alpha={fit.alpha:g}, beta={fit.beta:g}) trend {fit.trend:+g}/step'
    if fit.level >= threshold:
        return Prediction(now, f'already at or above threshold ({note_base})', threshold, now,
                          'holt', 'already')
    if fit.trend == 0.0:
        return Prediction(None, f'flat series: no upward trend toward threshold ({note_base})',
                          threshold, now, 'holt', 'flat')
    if fit.trend < 0.0:
        return Prediction(None, f'receding series: trending away from threshold ({note_base})',
                          threshold, now, 'holt', 'receding')
    steps = (threshold - fit.level) / fit.trend
    eta = fit.last_epoch_s + steps * fit.step_s
    return Prediction(eta, note_base, threshold, now, 'holt', 'crossing')


def time_to_threshold(model: models.Trend | models.HoltFit | Sequence[tuple[float, float]],
                      threshold: float, now: float, *,
                      min_points: int = models.MIN_FIT_POINTS) -> Prediction:
    """Estimate when *model* crosses *threshold* upward. Rising crossings only, as in v0.1.

    Accepts a fitted `models.Trend`/`models.HoltFit` or a raw point list (fitted here, by OLS). A
    degenerate series never raises and never fabricates: `insufficient` and `unfittable` arrive as a
    `Prediction` with `eta_epoch_s = None` **and the reason**, which is what the caller reports instead
    of a verdict.

    The direction is not a knob. `legacy:forecast/timetothreshold.py:80` estimates *rising* crossings, and
    a series that must **fall** past a limit (free space running out) is a falling crossing this module
    will not guess: `rule()` refuses `op` rather than shipping a condition that could never fire.
    Express a capacity rule as the *used* quantity rising.

    Raises:
        StateError: *threshold* or *now* is not finite. Either would make every comparison below false
            and hand back a `flat` verdict about a poisoned input.
    """
    threshold = _finite(threshold, name='threshold')
    now = _finite(now, name='now')
    if isinstance(model, models.Trend):
        return _linear_prediction(model, threshold, now)
    if isinstance(model, models.HoltFit):
        return _holt_prediction(model, threshold, now)
    points = list(model)
    if len(points) < min_points:
        return Prediction(None, f'insufficient series: {len(points)} points and this rule needs '
                                f'{min_points}; no trend is extrapolated from less',
                          threshold, now, 'linear', 'insufficient')
    try:
        trend = models.fit_linear(points, min_points=min_points)
    except models.ModelRefused as exc:
        return Prediction(None, f'unfittable series: {exc}', threshold, now, 'linear', 'unfittable')
    return _linear_prediction(trend, threshold, now)


@dataclass(frozen=True)
class ForecastRule:
    """One predictive rule: a `conditions.Rule` for the breach, plus the fit that predicts it.

    The reuse is the design. The inner rule (`watch`) carries the identity, the threshold, the
    comparison, every timing bound and the loudness, and it is built by `conditions.rule`, so a
    forecast rule cannot be configured in a way its own threshold rule would refuse. What this wrapper
    adds is the vocabulary delta (the ``.predicted`` condition namespace, `id`) and the fit's knobs.

    Satisfies `conditions.Judged` structurally, which is why its events are built by the same two
    functions a static tier and a learned band use, and why `conditions.read_points` and
    `conditions.tick` drive it with no forecast-specific code in either.
    """

    watch: conditions.Rule
    model: str = DEFAULT_MODEL
    alpha: float = models.DEFAULT_ALPHA
    beta: float = models.DEFAULT_BETA
    min_points: int = models.MIN_FIT_POINTS
    horizon_seconds: int = DEFAULT_HORIZON_SECONDS

    def __post_init__(self) -> None:
        """Check the forecast knobs, then the two bounds only a *predictive* rule needs."""
        if not isinstance(self.watch, conditions.Rule):
            raise StateError('A forecast rule must wrap a condition rule')
        if self.watch.mode != 'threshold':
            raise StateError('A forecast rule predicts a threshold crossing; no other mode has one')
        if self.watch.op != '>':
            raise StateError('Only a rising crossing is ported; express the rule as the value rising '
                             'past its limit (see time_to_threshold)')
        if self.model not in models.MODELS:
            raise StateError('Forecast model must be one of: ' + ', '.join(models.MODELS))
        for name in ('horizon_seconds', 'min_points', 'alpha', 'beta'):
            self._bounded(name, getattr(self, name))
        if not 0.0 < self.alpha <= 1.0 or not 0.0 < self.beta <= 1.0:
            raise StateError('Forecast smoothing constants must be in (0, 1]')
        if isinstance(self.min_points, bool) or not isinstance(self.min_points, int):
            raise StateError('Forecast min_points must be a whole number of points')
        if self.watch.history_seconds > LIMITS['history_seconds'][1]:
            raise StateError(f'Forecast history may not exceed '
                             f'{LIMITS["history_seconds"][1]:g} seconds: the store window and the '
                             f'event window both refuse a longer span')
        # A prediction can only be sustained while it lies *inside* its own horizon, and the run of
        # agreeing evaluations must last `for_seconds` before the condition earns a filing. Put those
        # together and a rule whose horizon is shorter than its `for_seconds` can never fire — exactly
        # the "a rule that can never fire, and nobody reads a refusal in a log" case `conditions.Rule`
        # refuses for `history_seconds`, refused here in the same place for the same reason.
        if self.horizon_seconds < self.watch.for_seconds:
            raise StateError('Forecast horizon must outlast its own for_seconds, or the condition can '
                             'never be sustained long enough to fire')
        # The reconstruction cost bound: one refit and one machine step per evaluation bucket inside the
        # sustain span. See MAX_SUSTAIN_STEPS for why it is a load refusal.
        steps = self.sustain_seconds // self.watch.evaluation_seconds + 1
        if steps > MAX_SUSTAIN_STEPS:
            raise StateError(f'Forecast sustain window needs {steps} evaluations per round, over the '
                             f'bound of {MAX_SUSTAIN_STEPS}; raise evaluation_seconds or shorten '
                             f'for_seconds')
        label(self.id)

    @staticmethod
    def _bounded(name: str, value: Any) -> float:
        """Return *value* inside :data:`LIMITS` for `name`, refusing anything else."""
        low, high = LIMITS[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
                or not low <= value <= high:
            raise StateError(f'Forecast {name} must be a finite number in {low:g}..{high:g}')
        return float(value)

    @property
    def id(self) -> str:
        """The `rule_id`/`condition` every event from this rule carries: the base rule, namespace said.

        This is the whole answer to "how is *will* told from *has*": the base rule's verdict arrives as
        ``r`` and this one as ``r.predicted``, so they are two conditions to `state.Store.intake` and an
        operator reads the difference off the name. Deliberately not a new `kind` (event vocabulary owns the
        vocabulary) and not a new severity word (`event vocabulary` owns the ladder).
        """
        return f'{self.watch.id}.{PREDICTED_SUFFIX}'

    @property
    def rule_id(self) -> str:
        """The base rule's own id, for prose: the round line and the refusal reasons say both names.

        Note the deliberate difference from `escalation.stage_event`, which keeps the *base* rule in the
        evidence parameters. A stage re-files the base verdict, so pooling it with the base rule's
        precision is right; a forecast is a different measurement, and notification budget's per-rule precision metric
        must not pool "predicted a crossing" with "crossed" — so `parameters.rule_id` here is the
        namespaced id, built by `conditions.condition_event` from `id`.
        """
        return self.watch.id

    @property
    def mode(self) -> str:
        """The producer word `conditions.cursor_binding` digests.

        ``forecast`` and not the inner rule's ``threshold``, so a forecast cursor cannot be resumed as a
        conditions cursor even when both documents name the same rule ids.
        """
        return 'forecast'

    @property
    def kind(self) -> str:
        """The `state.EVENT_KINDS` word this rule's verdict carries — the base rule's own word."""
        return self.watch.kind

    @property
    def query_type(self) -> str:
        """The evidence reference kind this rule's events cite — the base rule's, never a new one."""
        return self.watch.query_type

    @property
    def sustain_seconds(self) -> int:
        """How far back the machine must re-judge to reconstruct this rule's state at *now*."""
        return self.watch.for_seconds + self.watch.clear_seconds + self.watch.evaluation_seconds

    @property
    def resource_id(self) -> str:
        """The declared resource whose series this rule reads."""
        return self.watch.resource_id

    @property
    def source(self) -> str:
        """The producer identity every event from this rule is filed under."""
        return self.watch.source

    @property
    def metric(self) -> str | None:
        """The series name this rule reads (the document's `series`), narrowed in the store read."""
        return self.watch.metric

    @property
    def history_seconds(self) -> int:
        """The span the store is read over, and therefore the longest span a fit may see."""
        return self.watch.history_seconds

    @property
    def evaluation_seconds(self) -> int:
        """The bucket width: the event window, and the spacing of the re-judgements."""
        return self.watch.evaluation_seconds

    @property
    def max_age_seconds(self) -> int:
        """How old the newest sample may be and still be read as a statement about now."""
        return self.watch.max_age_seconds

    @property
    def version(self) -> str:
        """The `rule_version` this rule's events carry: the base binding plus the fit's own knobs.

        Same recipe and same reason as `conditions.Rule.version` and `dynamic_bands.Band.version`: a
        different estimator is a different condition, so retuning alpha must not inherit the incident a
        different model opened. Severity is excluded for the same reason — loudness is not judgment.
        """
        return digest(['forecast', PREDICTED_SUFFIX, self.watch.version, self.model, self.alpha,
                       self.beta, self.min_points, self.horizon_seconds])[:16]

    def threshold(self) -> float:
        """The limit the fit is projected against — the base rule's own number."""
        if self.watch.threshold is None:                       # pragma: no cover - mode checked above
            raise StateError('Forecast rule has no threshold')
        return float(self.watch.threshold)

    def severity(self) -> str:
        """This rule's firing loudness: resolved from its own config by the crosswalk, never spelled."""
        return self.watch.severity()

    def crosses(self, value: Any) -> bool:
        """Whether one observed sample has *already* breached — the base rule's own comparison."""
        return self.watch.crosses(value)

    def judge(self, points: Sequence[tuple[float, Any]], *,
              now: dt.datetime) -> Verdict:
        """Return this rule's verdict over *points* at *now*, so `conditions.tick` drives it unchanged."""
        return verdict(self, points, now=now)

    def prediction_at(self, points: Sequence[tuple[float, Any]], at_s: float) -> AtInstant:
        """Re-judge the fit as it stood at one instant, using no sample newer than that instant.

        The no-look-ahead rule is what makes the reconstructed run mean something: a machine stepped
        over a fit that could see the future would date a prediction earlier than it could have been
        made, which is the one error a sustained condition may not make (every other reconstruction
        cost in `conditions`/`dynamic_bands` can only delay a verdict, never invent one).

        A bucket that cannot be judged — too few points yet, an unfittable span, a poisoned sample — is
        ``judgeable=False``, and the caller **does not step the machine** for it. An unjudgeable bucket
        is never a non-crossing, and stepping with False would resolve a condition on the strength of
        nothing; that is `dynamic_bands.verdict`'s rule, copied because it is correct.
        """
        support = [point for point in points if point[0] <= at_s]
        value = support[-1][1] if support else None
        if len(support) < self.min_points:
            return AtInstant(False, False, value, None, f'{len(support)} points at this instant and '
                                                        f'{self.min_points} are needed')
        try:
            fitted = models.fit(support, self.model, alpha=self.alpha, beta=self.beta,
                                min_points=self.min_points)
        except models.ModelRefused as exc:
            return AtInstant(False, False, value, None, f'unfittable: {exc}')
        prediction = time_to_threshold(fitted, self.threshold(), at_s, min_points=self.min_points)
        if not prediction.crossing or prediction.eta_epoch_s is None:
            # The `eta is None` half of the test is unreachable through a valid `Prediction` —
            # `__post_init__` refuses a crossing without an instant — and is kept as the refusal rather
            # than as an assert, which `python -O` would delete.
            return AtInstant(True, False, value, prediction, prediction.confidence_note)
        if prediction.eta_epoch_s > at_s + self.horizon_seconds:
            return AtInstant(True, False, value, prediction,
                             f'crossing predicted at +{prediction.eta_epoch_s - at_s:g}s, beyond the '
                             f'{self.horizon_seconds}s horizon ({prediction.confidence_note})')
        return AtInstant(True, True, value, prediction, prediction.confidence_note)


def _bucket_instants(*, after_s: float, end_s: float, seconds: int) -> list[float]:
    """Return the grid instants in ``(after_s, end_s]``, oldest first, capped at one round's budget.

    `end_s` arrives already aligned to `seconds` by the caller, so these are the same instants the event
    windows end at: the machine is stepped on the platform's clock grid and not on one this module
    invents.
    """
    instants: list[float] = []
    instant = int(end_s)
    while instant > after_s and len(instants) < MAX_SUSTAIN_STEPS:
        instants.append(float(instant))
        instant -= seconds
    return list(reversed(instants))


def verdict(rule: ForecastRule, points: Sequence[tuple[float, Any]], *,
            now: dt.datetime) -> Verdict:
    """Judge one forecast rule over one series at one instant, reconstructing its sustained state.

    Returns a `conditions.Verdict` — the shape a static tier and a learned band return — so one round
    summary holds all three producers in one vocabulary. The refusal paths (`stale`, `insufficient`)
    file **only** the companion coverage event and say nothing about the condition, which is what keeps
    a blind tick from closing an incident an earlier one opened.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise StateError('Forecast evaluation needs an aware clock')
    ordered = conditions.ordered_points(points)
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // rule.evaluation_seconds
                                    * rule.evaluation_seconds, dt.timezone.utc)
    window = {'start': utc_text(end - dt.timedelta(seconds=rule.evaluation_seconds)),
              'end': utc_text(end)}
    end_s = end.timestamp()
    detail: dict[str, Any] = {'points': len(ordered), 'model': rule.model,
                              'min_points': int(rule.min_points),
                              'horizon_seconds': int(rule.horizon_seconds),
                              'threshold': rule.threshold(), 'rule': rule.rule_id}
    newest_s = ordered[-1][0] if ordered else None
    age = (end_s - newest_s) if newest_s is not None else None
    if age is None or not 0 <= age <= rule.max_age_seconds:
        # `detections.evaluate`'s rule, kept whole: this tick says one thing about the signal and
        # nothing about the condition, so the stored incident is left exactly as it was.
        detail.update({'age_seconds': None if age is None else int(age),
                       'max_age_seconds': rule.max_age_seconds,
                       'reason': 'no sample fresh enough to project from'})
        return Verdict('stale', 'unjudged', None, detail, [coverage_event(rule, window, False)])
    if len(ordered) < rule.min_points:
        detail.update({'insufficient': True,
                       'reason': f'the series holds {len(ordered)} points and this rule needs '
                                 f'{rule.min_points}; no trend is fitted from less'})
        return Verdict('insufficient', 'unjudged', None, detail, [coverage_event(rule, window, False)])

    machine = conditions.SustainedStateMachine(for_seconds=rule.watch.for_seconds,
                                               clear_seconds=rule.watch.clear_seconds)
    steps = _bucket_instants(after_s=end_s - rule.sustain_seconds, end_s=end_s,
                             seconds=rule.evaluation_seconds)
    final = rule.prediction_at(ordered, end_s)
    judged = 0
    for at_s in steps:
        step = final if at_s == end_s else rule.prediction_at(ordered, at_s)
        if not step.judgeable:
            continue                                  # never a step, and never a resolve
        judged += 1
        # A crossing that has already happened is not a prediction: the base rule files it, and this
        # condition starts clearing (and resolves after `resolve_seconds`) so one fact pages once.
        near = step.crossing and not rule.crosses(step.value)
        machine.step(rule.id, true=near, now=dt.datetime.fromtimestamp(at_s, dt.timezone.utc))
    detail.update({'steps': len(steps), 'steps_judged': judged,
                   'skipped_steps': len(steps) - judged,
                   'prediction': final.prediction.as_dict() if final.prediction else None})
    if final.prediction is None or not judged:
        # The newest instant could not be judged, so this tick says nothing about the condition. The
        # reason is the model's own sentence (too few points yet, or an unfittable span) rather than a
        # generic "nothing judged", because the operator's next action is to look at that series.
        detail.update({'insufficient': True,
                       'reason': final.detail or 'no bucket in the sustain span could be judged'})
        return Verdict('insufficient', 'unjudged', None, detail, [coverage_event(rule, window, False)])
    breached = rule.crosses(final.value)
    detail['breached'] = breached
    if breached:
        detail['reason'] = (f'the series is already at or past {rule.threshold():g}; that verdict '
                            f'belongs to rule {rule.rule_id}, not to a forecast of it')
    state = machine.state_of(rule.id)
    status = FIRING if state in conditions.HOLDING else RESOLVED
    detail.update({'state': state, 'value': final.value, 'age_seconds': int(age)})
    outcome = 'firing' if status == FIRING else ('pending' if state == 'pending' else 'resolved')
    return Verdict(outcome, state, status, detail,
                   [coverage_event(rule, window, True),
                    condition_event(rule, status, window, ordered[-1][0])])


def evaluate(rule: ForecastRule, points: Sequence[tuple[float, Any]], *,
             now: dt.datetime) -> list[dict[str, Any]]:
    """Return the canonical events one forecast rule owes at *now*."""
    return verdict(rule, points, now=now).events


def points_from_store(reader: Any, rule: ForecastRule, *,
                      end: dt.datetime) -> conditions.SeriesRead:
    """Read one rule's trailing series through `local_observe.store.client` — this package's only read.

    v0.1's `points_from_store(store_client, name, start, end, label_filter)` called
    ``StoreClient.query_range`` and returned a list of points. Three changes, each one a contract this
    repository fixed after v0.1 was written:

    * it goes through `conditions.read_points`, the merged reader, so this package opens no transport,
      writes no SQL, restates no row cap, and inherits the bounded truncation retry and the
      ``available``/``unavailable``/``expired`` verdicts (grep ``urllib`` and ``JsonClient`` across this
      package: the only hits are prose);
    * it returns a `conditions.SeriesRead`, not a bare list, because "the store refused", "the store
      has never seen this series" and "the window was empty" are three verdicts a list of points cannot
      tell apart, and the caller owes the operator the difference;
    * the window is derived from the rule's own `history_seconds` and the injected `end`, never from
      caller-supplied strings, so `store.client.Window`'s 7-day bound holds by construction and is
      refused at load (`LIMITS['history_seconds']`) rather than clamped silently.
    """
    return conditions.read_points(reader, rule, end=end)


def rule(document: Mapping[str, Any]) -> ForecastRule:
    """Build one validated `ForecastRule` from an operator document; an unknown key is a refusal.

    The base rule is built by `conditions.rule` itself, so every timing bound, the `for:`/history
    reconstruction chain and the severity crosswalk lookup are alert conditions's checks and not a copy of them. A
    `vocabulary.VocabularyError` from an unresolvable loudness propagates unchanged — it is a
    `ValueError`, the sentence a start-up path already knows how to print.
    """
    if not isinstance(document, Mapping):
        raise StateError('Forecast rule must be an object')
    missing = [name for name in RULE_TEXT_FIELDS if not isinstance(document.get(name), str)
               or not document[name]]
    threshold = document.get('threshold')
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        missing.append('threshold')
    if set(document) - RULE_KEYS or missing:
        raise StateError('Forecast rule fields are unknown or missing: '
                         + ', '.join(sorted(set(document) - RULE_KEYS) + missing))
    if 'model' in document and not isinstance(document['model'], str):
        raise StateError('Forecast model must be a name')
    for name in SMOOTHING_FIELDS:
        if name in document and (isinstance(document[name], bool)
                                 or not isinstance(document[name], (int, float))):
            raise StateError(f'Forecast {name} must be a number')
    for name in RULE_INT_FIELDS:
        if name in document and (isinstance(document[name], bool)
                                 or not isinstance(document[name], int)):
            raise StateError(f'Forecast {name} must be a whole number')
    inner = conditions.rule({'mode': 'threshold', 'op': '>', 'metric': document['series'],
                             **{key: value for key, value in document.items() if key in INNER_KEYS}})
    return ForecastRule(watch=inner,
                        **{key: value for key, value in document.items() if key in FIT_KEYS})


def load_config(path: Path | str) -> dict[str, Any]:
    """Read and validate one forecast document; the off switch is the absence of the file.

    The bounds on the file itself are `conditions.load_config`'s and reuse its constants: a byte cap
    applied to the bytes before the parse, a closed key set, 1..16 rules with unique ids, and an
    `interval_seconds` inside the same tick limits — the alignment of the evaluation window every rule
    in this document shares. The returned mapping is the shape `conditions.tick` consumes, so the round
    driver is not forked for a third producer.
    """
    candidate = Path(path)
    if len(candidate.read_bytes()) > MAX_CONFIG_BYTES:
        raise StateError('Forecast configuration exceeds its byte bound')
    document = read_document(candidate)
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS:
        raise StateError('Unknown forecast configuration keys')
    entries = document.get('rules')
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_RULES:
        raise StateError('Forecast rules must be 1-16 entries')
    parsed = [rule(entry) for entry in entries]
    if len({item.id for item in parsed}) != len(parsed):
        raise StateError('Forecast rule ids must be unique')
    interval = document.get('interval_seconds', conditions.DEFAULT_TICK_SECONDS)
    if isinstance(interval, bool) or not isinstance(interval, int) \
            or not conditions.TICK_LIMITS[0] <= interval <= conditions.TICK_LIMITS[1]:
        raise StateError(f'Forecast interval must be {conditions.TICK_LIMITS[0]}..'
                         f'{conditions.TICK_LIMITS[1]} seconds')
    cursor = document.get('cursor')
    if cursor is not None and (not isinstance(cursor, str) or not cursor or len(cursor) > 1024):
        raise StateError('Forecast cursor must be a short path')
    return {'rules': parsed, 'interval_seconds': interval, 'cursor': cursor}


def producer_config(environment: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Return the validated configuration, or None when the producer is not configured at all.

    An unset or blank ``LO_FORECAST_CONFIG`` is the documented off switch and answers one INFO line
    naming the variable — the rule `anomaly.producer_config` and `pathcheck.producer_config` follow, so
    "off" means one thing across the estate. A file that is named and cannot be read or parsed is **not**
    off: it raises, and `main` exits 1, because a producer that survived a broken configuration would
    be reporting a healthy capacity position on the strength of nothing at all.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CONFIG_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('Forecast producer is off; no configuration named',
                 extra={'variable': CONFIG_ENVIRONMENT})
        return None
    return load_config(raw)

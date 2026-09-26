"""Learned-band conditions: event kinds's estimator, this card's state machine, and a visible `insufficient`.

**The maths is deliberately not ported twice.** v0.1's `legacy:alerting/dynamic.py` learned a flat quantile
band (p01/p99 by linear interpolation over a `deque(maxlen)` of trailing values) per
``(metric, resource)``. event kinds merged `platform/anomaly.py`, which already learns a band per series and
already refuses to judge a thin one: :func:`anomaly.train` (``median ± k·scaled-MAD`` per seasonal
bucket), :func:`anomaly.band` (``None`` means *cannot judge*, never *normal*), :func:`anomaly.detect`
(deviations **and** the visibly-skipped points), :func:`anomaly.worst`. This module imports those and
adds the one thing v0.1 had and event kinds does not — the **sustained** layer, i.e. a band crossing that must
hold for ``for_seconds`` before it is filed and hold for the same span before it is cleared — driven by
the same `conditions.SustainedStateMachine` every other condition here uses, so a learned band and a
static threshold cannot disagree about what "held long enough" means.

Why the seasonal estimator and not the ported quantile one: a flat band over the trailing N points calls
the morning peak an outlier every morning on any diurnal metric, because v0.1's module has no
seasonality term at all. The estimator this repository already validated is also the better estimator,
and reusing it keeps one definition of scaled MAD, one `anomaly.LIMITS` ladder of bounds, and one
``insufficient`` path in this package. :func:`verdict` is the test that proves the claim: a value that
repeats at the same hour every day stays inside its own hour's band, and the same value arriving at an
hour that never saw it steps outside — a flat band cannot tell those two apart, so it cannot fail them
differently.

What was kept from v0.1, because it is the part that mattered: **the refusal**. A series with fewer than
``min_points`` training points is ``insufficient`` — named in the returned `conditions.Verdict`, named in
the round summary, and filed as the same ``coverage`` event `conditions`/`detections` file, never a quiet
``resolved``. v0.1 exposed it through ``status()``; here it is an event, because a state only an
in-process caller can ask about is invisible to the operator who is not that caller. The training span
stops at the beginning of the sustain window, so the points being judged are not in the band that judges
them (v0.1's "an outlier cannot vouch for itself", and `anomaly._verdict`'s evaluated-tail exclusion).

Two honest limits, stated where they will be read:

* **Seven days.** The series is read through `local_observe/store/client.py`, whose `Window` refuses a
  span over 7 days, so a band cannot be trained on the 14 days `anomaly.DEFAULTS` uses — `anomaly`
  reads through its own reviewed SQL and is not bound. ``history_seconds`` is therefore capped at 604800
  here, and the cost is a band that sees two weeks of a weekday pattern rather than none.
* **The deque lives in the store.** v0.1 kept the trailing window in process memory; this module rebuilds
  it from one read per tick, which is what makes the verdict survive a restart and what makes the
  reconstruction bound real: a rule whose ``history_seconds`` does not exceed its own ``for_seconds``
  plus an evaluation window is refused at load, exactly as in `conditions.Rule`.
"""
import datetime as dt
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from local_observe.inventory.validation import digest, utc_text
from local_observe.store.client import MAX_ROWS
from . import anomaly, conditions, vocabulary
from .conditions import FIRING, RESOLVED, Verdict, condition_event, coverage_event
from .state import StateError, identifier, label

#: The mode string a rule document uses to ask for a learned band; `conditions.rule` dispatches here.
BAND_MODE = 'band'
#: The `state.EVENT_KINDS` word a band verdict carries — the same one event kinds's producer files under.
BAND_KIND = 'anomaly'
BAND_QUERY_TYPE = 'metric-threshold'
BAND_KEYS = frozenset({'id', 'mode', 'resource_id', 'source', 'severity_source', 'severity_tier',
                       'season', 'k', 'min_points', 'min_per_bucket', 'history_seconds',
                       'evaluation_seconds', 'for_seconds', 'resolve_seconds', 'max_age_seconds',
                       'metric'})
BAND_REQUIRED = ('id', 'resource_id', 'source', 'severity_source', 'severity_tier')
# The store facade's own ceiling (`local_observe/store/client.MAX_WINDOW_SECONDS`), restated here as a
# load-time refusal so the failure is a config sentence and not a `StoreRefused` mid-round.
MAX_HISTORY_SECONDS = 7 * 86400
BAND_LIMITS: dict[str, tuple[float, float]] = {
    'k': (1.0, 20.0), 'min_points': (4, MAX_ROWS), 'min_per_bucket': (1, 64),
    'history_seconds': (3600, MAX_HISTORY_SECONDS), 'evaluation_seconds': (60, 3600),
    'for_seconds': (0, 86400), 'resolve_seconds': (0, 86400), 'max_age_seconds': (60, 86400)}


@dataclass(frozen=True)
class Band:
    """One learned band: which series it watches, how it trains, and how long a crossing must hold.

    Satisfies `conditions.Judged` structurally, which is why a band's events are built by the same two
    functions a static threshold uses. Loudness is a config field resolved through
    `platform/vocabulary.severity`, so this file names no severity: `anomaly.severity_for` is the merged
    alternative that would scale loudness by how far a point sits beyond its band edge, and the card
    that wants that should call it rather than invent a second measure here.

    Raises:
        StateError: Any knob is outside :data:`BAND_LIMITS` or `anomaly.SEASONS`, the document carries a
            key this mode does not read, or the timings cannot be satisfied by the read span. A
            `vocabulary.VocabularyError` from an unresolvable tier word propagates unchanged.
    """
    id: str
    resource_id: str
    source: str
    severity_source: str
    severity_tier: str
    mode: str = BAND_MODE
    season: str = 'hour_of_day'
    k: float = 3.0
    min_points: int = 48
    min_per_bucket: int = 3
    history_seconds: int = 86400
    evaluation_seconds: int = 300
    for_seconds: int = 900
    resolve_seconds: int | None = None
    max_age_seconds: int = 3600
    metric: str | None = None

    def __post_init__(self) -> None:
        """Check every knob against the bound it belongs to, and the timing chain against itself."""
        label(self.id)
        label(self.source)
        identifier(self.resource_id)
        if self.mode != BAND_MODE:
            raise StateError('Unsupported band mode')
        if self.season not in anomaly.SEASONS:
            raise StateError('Band season must be one of: ' + ', '.join(sorted(anomaly.SEASONS)))
        for name in ('k', 'min_points', 'min_per_bucket', 'history_seconds', 'evaluation_seconds',
                     'for_seconds', 'max_age_seconds'):
            _band_bounded(name, getattr(self, name))
        if self.resolve_seconds is not None:
            _band_bounded('resolve_seconds', self.resolve_seconds)
        if isinstance(self.min_points, bool) or not isinstance(self.min_points, int) \
                or isinstance(self.min_per_bucket, bool) or not isinstance(self.min_per_bucket, int) \
                or isinstance(self.evaluation_seconds, bool) \
                or not isinstance(self.evaluation_seconds, int):
            raise StateError('Band point and window counts must be whole numbers')
        if self.min_points < self.min_per_bucket:
            raise StateError('Band min_points must cover at least one full bucket')
        # The reconstruction bound, same shape as `conditions.Rule` and one term wider: the span the
        # machine walks must fit inside the read span with training points left over, and it has to hold
        # a full open-then-clear cycle (`for` + `clear` + one evaluation window) or a condition that fired
        # in an earlier round would be reconstructed as never having fired at all.
        if self.history_seconds <= self.sustain_seconds:
            raise StateError('Band history must outlast its own open/clear/evaluation windows')
        vocabulary.severity(self.severity_source, self.severity_tier)

    @property
    def kind(self) -> str:
        """The `state.EVENT_KINDS` word a band verdict carries."""
        return BAND_KIND

    @property
    def query_type(self) -> str:
        """The evidence reference kind a band verdict cites."""
        return BAND_QUERY_TYPE

    @property
    def clear_seconds(self) -> int:
        """How long an in-band run must last before the band condition reports `resolved`."""
        return self.for_seconds if self.resolve_seconds is None else self.resolve_seconds

    @property
    def sustain_seconds(self) -> int:
        """How far back the machine must look to reconstruct this band's state at *now*.

        It is the whole span a verdict can be dated within, so it is wider than v0.1's
        ``for_duration_s`` alone: the clear side needs its own room, or a condition that fired and then
        started clearing is rebuilt from a window too short to contain the firing, and the flap returns.
        The cost of the reconstruction — stated in the module docstring and bounded by the load-time
        refusal above — is that a run older than this span is dated at its start, which can only ever
        make a verdict arrive late, never early.
        """
        return self.for_seconds + self.clear_seconds + self.evaluation_seconds

    @property
    def version(self) -> str:
        """The `rule_version` a verdict from this band carries: the knobs it was judged with.

        Same recipe as `anomaly._rule_version` and `conditions.Rule.version` for the same reason: a
        different estimator is a different condition, and severity stays out of the binding so
        retuning loudness cannot orphan an open incident.
        """
        return digest([BAND_MODE, self.season, self.k, self.min_points, self.min_per_bucket,
                       self.history_seconds, self.evaluation_seconds, self.for_seconds,
                       self.clear_seconds, self.max_age_seconds])[:16]

    def severity(self) -> str:
        """Return this band's firing loudness, resolved from its own config through the crosswalk."""
        return vocabulary.severity(self.severity_source, self.severity_tier)

    def judge(self, points: Sequence[tuple[float, Any]], *,
              now: dt.datetime) -> conditions.Verdict:
        """Return this band's verdict over *points* at *now*, so `conditions.tick` can drive both modes."""
        return verdict(self, points, now=now)

    def train(self, points: Sequence[tuple[float, float]], *, sustain_start_s: float) -> anomaly.Baseline:
        """Train the estimator on the points older than the span being judged.

        The exclusion is the whole method: a band that trained on the excursion it is judging would
        widen around a sustained shift and call it normal, which is `anomaly._verdict`'s stated reason
        for cutting its own evaluated tail.
        """
        training = [point for point in points if point[0] < sustain_start_s]
        return anomaly.train(training, season=self.season, min_per_bucket=self.min_per_bucket, k=self.k)


def _band_bounded(name: str, value: Any) -> float:
    """Return *value* inside :data:`BAND_LIMITS` for `name`, refusing anything else."""
    low, high = BAND_LIMITS[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
            or not low <= value <= high:
        raise StateError(f'Band {name} must be a finite number in {low:g}..{high:g}')
    return float(value)


def band_rule(document: Mapping[str, Any]) -> Band:
    """Build one validated `Band` from a rule document; an unknown key is a refusal, not ignored."""
    if not isinstance(document, Mapping):
        raise StateError('Band rule must be an object')
    missing = [name for name in BAND_REQUIRED if not isinstance(document.get(name), str) or not document[name]]
    for name in ('min_points', 'min_per_bucket', 'history_seconds', 'evaluation_seconds', 'for_seconds',
                 'resolve_seconds', 'max_age_seconds'):
        if name in document and (isinstance(document[name], bool) or not isinstance(document[name], int)):
            raise StateError(f'Band {name} must be a whole number')
    if set(document) - BAND_KEYS or missing:
        raise StateError('Band rule fields are unknown or missing: '
                         + ', '.join(sorted(set(document) - BAND_KEYS) + missing))
    if 'metric' in document and (not isinstance(document['metric'], str) or not document['metric']
                                 or len(document['metric']) > 256):
        raise StateError('Band metric must be a short name')
    return Band(**dict(document))


def _bucketed(points: Sequence[tuple[float, float]], *, seconds: int,
              limit_s: float) -> list[tuple[dt.datetime, list[tuple[float, float]]]]:
    """Group points into evaluation buckets and name each one by its own end instant.

    Each bucket is one tick's worth of evidence, which is what makes ``for_seconds`` measurable from a
    series alone: the machine is stepped once per bucket, in time order, and the run it dates is a run of
    buckets and not a run of samples.
    """
    buckets: dict[int, list[tuple[float, float]]] = {}
    for epoch_s, value in points:
        buckets.setdefault(int(epoch_s // seconds), []).append((epoch_s, value))
    ordered: list[tuple[dt.datetime, list[tuple[float, float]]]] = []
    for index, chunk in sorted(buckets.items()):
        end_s = min((index + 1) * seconds, limit_s)
        ordered.append((dt.datetime.fromtimestamp(end_s, dt.timezone.utc), chunk))
    return ordered


def verdict(rule: Band, points: Sequence[tuple[float, Any]], *,
            now: dt.datetime) -> conditions.Verdict:
    """Judge one band over one series at one instant, reconstructing its sustained state.

    Returns a `conditions.Verdict`, the same shape a static condition returns, so a caller reads one
    outcome vocabulary for both: ``firing``/``resolved`` are verdicts, and ``insufficient``,
    ``unjudgeable`` and ``stale`` are the tick saying it could not judge — each of which files a
    ``coverage`` event and **nothing** about the condition, so a blind tick can never close an incident
    an earlier one opened.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise StateError('Band evaluation needs an aware clock')
    ordered = conditions.ordered_points(points)
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // rule.evaluation_seconds
                                    * rule.evaluation_seconds, dt.timezone.utc)
    window = {'start': utc_text(end - dt.timedelta(seconds=rule.evaluation_seconds)),
              'end': utc_text(end)}
    newest_s = ordered[-1][0] if ordered else None
    age = (end.timestamp() - newest_s) if newest_s is not None else None
    detail: dict[str, Any] = {'points': len(ordered), 'min_points': int(rule.min_points)}
    if age is None or not 0 <= age <= rule.max_age_seconds:
        detail['age_seconds'] = None if age is None else int(age)
        detail['max_age_seconds'] = rule.max_age_seconds
        return Verdict('stale', 'unjudged', None, detail, [coverage_event(rule, window, False)])

    sustain_start_s = end.timestamp() - rule.sustain_seconds
    training = [point for point in ordered if point[0] < sustain_start_s]
    current = [point for point in ordered if point[0] >= sustain_start_s]
    detail.update({'training_points': len(training), 'current_points': len(current)})
    if len(training) < rule.min_points:
        # v0.1's `insufficient_baseline`, visible: named in the summary and filed as coverage, never read
        # as a healthy band and never as a recovery of one.
        detail['reason'] = 'band trained on fewer points than min_points'
        return Verdict('insufficient', 'unjudged', None, detail, [coverage_event(rule, window, False)])

    baseline = rule.train(ordered, sustain_start_s=sustain_start_s)
    machine = conditions.SustainedStateMachine(for_seconds=rule.for_seconds,
                                               clear_seconds=rule.clear_seconds)
    steps = _bucketed(current, seconds=rule.evaluation_seconds, limit_s=end.timestamp())
    judgeable = 0
    last_breaching = False
    deviations = 0
    skipped = 0
    for bucket_end, chunk in steps:
        outcome = anomaly.detect(baseline, chunk)
        skipped += len(outcome.skipped)
        if len(outcome.skipped) == len(chunk):
            continue                     # nothing judgeable in this bucket: no step, and never a resolve
        judgeable += 1
        deviations += len(outcome.deviations)
        last_breaching = bool(outcome.deviations)
        machine.step(rule.id, true=last_breaching, now=bucket_end)
    detail.update({'buckets_judgeable': judgeable, 'deviations': deviations, 'skipped': skipped,
                   'buckets_insufficient': len(baseline.insufficient)})
    if not judgeable:
        detail['reason'] = 'every current point sits in a bucket too thin to judge'
        return Verdict('unjudgeable', 'unjudged', None, detail, [coverage_event(rule, window, False)])

    # The tick itself, one last step: a crossing that is still true has to be able to reach its `for:`
    # deadline at an instant the series does not contain, exactly as in `conditions.verdict`.
    machine.step(rule.id, true=last_breaching, now=end)
    state = machine.state_of(rule.id)
    status = FIRING if state in conditions.HOLDING else RESOLVED
    detail.update({'state': state, 'value': current[-1][1], 'age_seconds': int(age)})
    outcome = 'firing' if status == FIRING else ('pending' if state == 'pending' else 'resolved')
    return Verdict(outcome, state, status, detail,
                   [coverage_event(rule, window, True),
                    condition_event(rule, status, window, current[-1][0])])


def evaluate(rule: Band, points: Sequence[tuple[float, Any]], *,
             now: dt.datetime) -> list[dict[str, Any]]:
    """Return the canonical events this band owes at *now*."""
    return verdict(rule, points, now=now).events

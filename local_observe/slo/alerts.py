"""The burn as a condition: the objective document, the store read, the ``for:`` machine, the events.

This is where the port crosses contracts, and everything platform-specific happens in one place so the
arithmetic in :mod:`.budget` stays pure and :mod:`.objectives` stays import-free.

**Configuration is one file, named by** ``LO_SLO_CONFIG``. Absent or blank is the off switch and logs
one `INFO` line naming the variable (`anomaly`/`configdrift`/`pathcheck` all mean "off" this way, and a
producer that meant something different would be the one an operator misreads). Two more variables
belong to the worker: ``LO_SLO_CURSOR`` — the absolute path of this producer's own JSON cursor, **required
when a configuration is named**, because a verdict with nowhere to record what it owes is a verdict that
can be lost (`conditions.tick`'s rule, adopted whole) — and ``LO_SLO_SOURCE``, the producer identity that
must match its intake token, since the platform records *who* said it. ``LO_INDEX_PATH`` names the built
inventory index every objective's `resource_id` must resolve in, and the store read comes from the three
``LO_CLICKHOUSE_*`` variables `platform/cli.py::store_reader` already refuses to guess about. The
document's own fields, all of them required unless marked, are `objective_id`, `resource_id`, `signal`,
`target`, `window_days`, `long_window`, `short_window`, `burn_threshold`, and optionally `metric`
(defaulted from the objective id only where that is unambiguous — see `rule`), `threshold_s` (required for
``signal: latency``, refused otherwise), `min_samples`, `severity_source`, `severity_tier`,
`evaluation_seconds`, `for_seconds`, `resolve_seconds`, `max_age_seconds`. An unknown key is a refusal, not
an ignored field: a typo in a burn window that silently did nothing is a rule that pages at the wrong
rate, which is the one thing this file exists to get right.

**The read is store facade's and only store facade's**: one ``metric-threshold`` read per objective per round through
`local_observe/store/client.py`, narrowed by the store's own `metric_name` selector and scoped to the
declared `resource_id`, under a window the facade itself bounds (7 days, 2 000 rows). No SQL, no second
HTTP client, no fallback read. The bound is load-bearing and stated rather than discovered at runtime:
`history_seconds` is derived from the objective's own windows (:attr:`BurnCondition.history_seconds`) and
must fit inside the store's 7-day ceiling, so **a compliance window of 28 or 30 days — v0.1's own default
shape — cannot be evaluated through this facade and is refused at load**, with the reason in the
refusal's own sentence. What would change that is an aggregate read kind in the store's closed table
(`describe-*` answers a row count, never a good/bad split), which is store facade's vocabulary to widen and not
this package's to route around; the same row bound is why the read tolerates a sample cadence no finer
than `history_seconds / 2000` (a 1-day window ⇒ ≈44 s resolution or coarser), and a read that came back
`truncated` is reported as such and judged as nothing — the facade returns the oldest rows of a full
page, so a truncated read does not even contain the instant being judged.

**The two-window rule is enforced by the same code that enforces every other** ``for:`` **duration.** The
predicate fed to `conditions.SustainedStateMachine` is :data:`budget.FIRING` — which is `long >= threshold
AND short >= threshold`, computed by `budget.check_fast_burn` and nowhere else — replayed once per
evaluation bucket over the span the machine needs, exactly the way `dynamic_bands.verdict` replays a band
crossing. Two consequences, both wanted: a burn that flickers across the threshold inside `for_seconds`
never opens (the machine's silent ``pending → ok``, shared with every other condition here), and a burn
that clears must stay clear for `resolve_seconds` before the condition resolves, so one sustained burn is
one incident and one page instead of two per flap. A bucket whose windows hold no samples earns **no
step** — never a step toward resolved, because a tick that could not judge may not close what a tick that
could once opened.

**``INSUFFICIENT_DATA`` is a visible state, on the pattern `detections.py` already uses.** Too few
samples for an attainment, no samples in either burn window, a read the store could not answer and a
series whose newest point is older than `max_age_seconds` all file a ``coverage`` event
(`kind='coverage'`, `status='firing'`, condition ``<objective_id>.coverage``) and **nothing** about the
budget: never a `resolved` that closes a burn incident on the strength of missing data, and never an
attainment of 1.0. A thin compliance window beside a *measurable* burn pair files both — the coverage
event says the attainment is not computable, the `threshold` event says the budget is burning.

**How a burn page coexists with notification budget's precision budget.** This package contains no sending code. Both
are events, so
both walk one path:
`platform/detections.event` builds it → ``POST /v1/events`` → `state.Store.intake`, which books an outbox
row **only on an `opened` or `resolved` transition** — a firing event that arrives while the incident is
already open books nothing — and the delivery rail (`notifications.deliver_one`) claims that row and
calls `notification_safety.reserve`, which counts that channel's `notification_reservations` inside
`window_seconds` since the last human reset, refuses at `max_attempts`, latches that channel's flood
breaker open until a human resets it, and records the refusal in `notification_suppressions`. An
escalation rung and an error-budget page therefore spend **the same per-channel budget object through the
same outbox row**, and neither has a second door: this package posts no send, holds no
channel credential, reads no `LO_NOTIFICATION_MODE` and imports no delivery transport — its one
network call is ``POST /v1/events``, which books nothing by itself; `tests/test_slo_burn.py`'s `SurfaceTests`
pins that as syntax, because a paragraph that has to name the rail cannot be the proof that nothing
else reaches it. And because `intake`'s condition key digests `(source, rule_id, rule_version, resource_id,
condition)` with **no timestamp in it**, one objective is one condition, so notification budget's per-rule precision
metric (≤2 security pings/week median) counts a burn as it counts any other rule: a sustained burn books
one delivery, a burn that flap-pages twice per hour is an over-tuned `burn_threshold`, and the metric sees
that instead of being routed around by it.
"""
from __future__ import annotations

import datetime as dt
import math
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from local_observe.inventory import index
from local_observe.inventory.validation import digest, read_document, timestamp, utc_text
from local_observe.log import get_logger
from local_observe.platform import conditions, vocabulary
from local_observe.platform.state import StateError, identifier, label
from local_observe.store.client import MAX_WINDOW_SECONDS, Window

from . import budget
from .objectives import AvailabilityObjective, LatencyObjective, Objective

log = get_logger(__name__)

#: The one environment variable that turns this producer on, and the only off switch it has.
CONFIG_ENVIRONMENT = 'LO_SLO_CONFIG'
#: Where this producer remembers what it judged and what it still owes. Required with a configuration.
CURSOR_ENVIRONMENT = 'LO_SLO_CURSOR'
#: The producer identity, which must match the intake token the platform authenticates.
SOURCE_ENVIRONMENT = 'LO_SLO_SOURCE'

#: The two signals this build can evaluate, in the order `docs` states them (`slo/objectives.py`).
SIGNALS = ('availability', 'latency')
#: The `mode` word this subject contributes to the cursor binding. It is deliberately not in
#: `conditions.MODES`, exactly as `dynamic_bands.BAND_MODE` is not: a mode listed there would claim a
#: machine `conditions.Rule` cannot run, while the cursor only needs the word to *change* when the
#: judgment changes.
SLO_MODE = 'slo'
#: The verdict's `kind`: `vocabulary.TYPE_CROSSWALK` gives v0.1's `slo.fast_burn` the pair
#: ``('threshold', 'slo.fast_burn')``, and the port table's §6 `alerting` row calls that mapping "lossy
#: and must be decided per rule". The decision here is `threshold` — a budget is a number past a limit,
#: not a test that failed (`availability`) and not a signal that stopped arriving (`coverage`, which this
#: package reserves for exactly that) — so no new kind arrives and `tests/test_event_kinds.py` stands.
BURN_KIND = 'threshold'
#: The read kind, and the evidence reference both halves of a verdict cite: the samples behind a number.
BURN_QUERY_TYPE = 'metric-threshold'

DEFAULT_EVALUATION_SECONDS = 300
DEFAULT_MAX_AGE_SECONDS = 3600
DEFAULT_TICK_SECONDS = 300
TICK_LIMITS = (5, 3600)
MAX_OBJECTIVES = 16
MAX_CONFIG_BYTES = 262_144
#: The store facade's own window ceiling (`store.client.MAX_WINDOW_SECONDS`), restated as a load-time
#: refusal so a too-long compliance window is a config sentence and not a `StoreRefused` mid-round.
MAX_HISTORY_SECONDS = MAX_WINDOW_SECONDS
#: Every bound is a refusal at load and never a runtime surprise, in the shape `conditions.LIMITS` uses.
#: `target` and `threshold_s` are absent on purpose: their bounds belong to the objective classes that
#: judge samples with them, and a second copy here is a second place to be wrong.
LIMITS: dict[str, tuple[float, float]] = {
    'window_days': (1, 7), 'long_window': (60, 86_400), 'short_window': (60, 86_400),
    'burn_threshold': (0.1, 100.0), 'min_samples': (1, budget.MAX_SAMPLES),
    'evaluation_seconds': (60, 3600), 'for_seconds': (0, 86_400), 'resolve_seconds': (0, 86_400),
    'max_age_seconds': (60, 86_400)}
#: The outcome words one objective can report for one round. `truncated` and `insufficient` are additions
#: this producer owns (`conditions.OUTCOMES` has no word for "the read could not state the denominator"),
#: and none of the words except `firing`/`resolved`/`pending` is allowed to resolve anything.
OUTCOMES = conditions.OUTCOMES + ('insufficient', 'truncated')

CONFIG_KEYS = frozenset({'interval_seconds', 'objectives'})
OBJECTIVE_KEYS = frozenset({'objective_id', 'resource_id', 'signal', 'target', 'window_days',
                           'long_window', 'short_window', 'burn_threshold', 'metric', 'threshold_s',
                           'min_samples', 'severity_source', 'severity_tier', 'evaluation_seconds',
                           'for_seconds', 'resolve_seconds', 'max_age_seconds'})
#: The eight fields the port brief names, and the two the crosswalk needs: loudness has to be cited from
#: somewhere, and this module spells no severity word of its own (see `severity`).
OBJECTIVE_REQUIRED = ('objective_id', 'resource_id', 'signal', 'target', 'window_days', 'long_window',
                      'short_window', 'burn_threshold', 'severity_source', 'severity_tier')
_WHOLE_SECONDS = ('window_days', 'long_window', 'short_window', 'evaluation_seconds', 'for_seconds',
                  'resolve_seconds', 'max_age_seconds', 'min_samples')


@dataclass(frozen=True)
class BurnCondition:
    """One objective, its burn pair, and the durations that decide when the pair is loud enough to file.

    It satisfies `conditions.Judged` structurally — the same protocol `dynamic_bands.Band` satisfies — so
    the two event builders in `conditions` (`coverage_event`, `condition_event`) write this subject's
    events too, and a learned band, a static tier and an error budget cannot grow three event shapes.
    Loudness is a config field resolved through `platform/vocabulary.severity`, so this file names no
    severity: v0.1's `FastBurnPolicy.severity` had no legal encoding here (its module docstring says why).

    Raises:
        StateError: A field is outside :data:`LIMITS`, the signal is unknown, a latency objective omits
            its threshold, or the derived read span does not fit the store's own window ceiling. A
            `vocabulary.VocabularyError` from an unresolvable severity word propagates unchanged: it is a
            `ValueError`, and the worker's start-up handler already answers one line for one.
    """

    objective_id: str
    resource_id: str
    source: str
    signal: str
    target: float
    window_days: float
    long_window: int
    short_window: int
    burn_threshold: float
    metric: str
    severity_source: str
    severity_tier: str
    min_samples: int = 1
    threshold_s: float | None = None
    evaluation_seconds: int = DEFAULT_EVALUATION_SECONDS
    for_seconds: int = 0
    resolve_seconds: int | None = None
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS

    def __post_init__(self) -> None:
        """Check every field against its bound, and this objective's timings against the read they need."""
        label(self.objective_id)
        label(self.source)
        label(self.metric)
        identifier(self.resource_id)
        if self.signal not in SIGNALS:
            raise StateError('SLO signal must be one of: ' + ', '.join(SIGNALS))
        for name in ('window_days', 'long_window', 'short_window', 'burn_threshold', 'min_samples',
                     'evaluation_seconds', 'for_seconds', 'max_age_seconds'):
            _bounded(name, getattr(self, name))
        if self.resolve_seconds is not None:
            _bounded('resolve_seconds', self.resolve_seconds)
        if self.short_window >= self.long_window:
            raise StateError('SLO short burn window must be shorter than the long one')
        if self.signal == 'latency' and self.threshold_s is None:
            raise StateError('A latency objective needs the threshold its samples are good up to')
        if self.signal == 'availability' and self.threshold_s is not None:
            raise StateError('An availability objective judges a boolean, not a comparison')
        # Resolve the loudness **now**, at load, and not at the first firing tick: the difference between a
        # bad config discovered on the operator's desk and one discovered during the incident the objective
        # existed to report (`conditions.Rule.__post_init__`'s reason for the same line).
        self.severity()
        # Constructing the objective here is what bounds `target` and `threshold_s`: the classes that
        # judge samples with those numbers own their bounds, and a copy of them here would be a second
        # place to be wrong. The name is discarded; the ValueError it may raise is not.
        _ = self.objective  # construction is the bound check; the object itself is not used here
        # The reconstruction bound, in this module's shape: the machine can only date a run from the
        # first point it can see, the long window has to be *behind* the earliest instant it replays, and
        # the compliance window has to be wholly *inside* the read or the attainment denominator is a
        # guess. Refusing the objective is the only honest answer available at load.
        if self.history_seconds > MAX_HISTORY_SECONDS:
            raise StateError(f'SLO read span would be {self.history_seconds}s; the store facade refuses '
                             f'over {MAX_HISTORY_SECONDS}s, so shorten window_days, long_window or the '
                             'sustain windows')

    @property
    def id(self) -> str:
        """The `rule_id` this objective's events carry — the port table's `rule_id`-carries-the-objective."""
        return self.objective_id

    @property
    def mode(self) -> str:
        """The mode word the cursor binding digests, so an edit to the judgment refuses to resume."""
        return SLO_MODE

    @property
    def kind(self) -> str:
        """The `state.EVENT_KINDS` word a burn verdict is filed under."""
        return BURN_KIND

    @property
    def query_type(self) -> str:
        """The evidence reference kind this objective's events cite, and the read it came from."""
        return BURN_QUERY_TYPE

    @property
    def compliance_seconds(self) -> float:
        """The rolling window attainment and remaining budget are measured over, in seconds."""
        return float(self.window_days) * 86_400

    @property
    def clear_seconds(self) -> int:
        """How long a non-burning run must last before the condition reports `resolved`."""
        return self.for_seconds if self.resolve_seconds is None else self.resolve_seconds

    @property
    def sustain_seconds(self) -> int:
        """The span the machine must walk to reconstruct this burn's state at *now* (`Band`'s recipe)."""
        return self.for_seconds + self.clear_seconds + self.evaluation_seconds

    @property
    def history_seconds(self) -> int:
        """The one read span that holds everything this verdict depends on: compliance and burn together.

        It is the greater of the compliance window and the span the machine replays *plus* the long burn
        window behind it, with two evaluation windows of slack so a run can be dated and the tick itself
        can reach its deadline. Deriving it instead of configuring it is deliberate: a configured
        `history_seconds` shorter than the objective's own windows produces an attainment over less than
        the window it claims, which is the failure mode `budget.INSUFFICIENT_DATA` exists to refuse.
        """
        return int(max(self.compliance_seconds, self.sustain_seconds + self.long_window)
                   + 2 * self.evaluation_seconds)

    @property
    def version(self) -> str:
        """The `rule_version` a verdict carries: a digest of everything the judgment depends on.

        `conditions.Rule.version` and `anomaly._rule_version` set the recipe (16 hex, severity excluded).
        Severity is not an input, so retuning how loud a burn is must not orphan the incident it opened;
        changing a window or the threshold genuinely is a different condition and moves it.
        """
        return digest([SLO_MODE, self.signal, self.target, self.compliance_seconds, self.long_window,
                       self.short_window, self.burn_threshold, self.min_samples, self.threshold_s,
                       self.evaluation_seconds, self.for_seconds, self.clear_seconds,
                       self.max_age_seconds])[:16]

    @property
    def objective(self) -> Objective:
        """The classifier this objective's samples are judged by, built from this subject's own fields."""
        if self.signal == 'availability':
            return AvailabilityObjective(name=self.objective_id, target=float(self.target),
                                         window_s=self.compliance_seconds, min_samples=self.min_samples)
        return LatencyObjective(name=self.objective_id, threshold_s=float(self.threshold_s or 0.0),
                                target=float(self.target), window_s=self.compliance_seconds,
                                min_samples=self.min_samples)

    @property
    def policy(self) -> budget.FastBurnPolicy:
        """The burn pair, as the pure function that judges it takes it."""
        return budget.FastBurnPolicy(objective=self.objective, long_window_s=float(self.long_window),
                                     short_window_s=float(self.short_window),
                                     threshold=float(self.burn_threshold))

    def window(self, end: dt.datetime) -> dict[str, str]:
        """The evaluation window this objective is judged over at *end* (aligned, bounded, half-open)."""
        return {'start': utc_text(end - dt.timedelta(seconds=self.evaluation_seconds)),
                'end': utc_text(end)}

    def severity(self) -> str:
        """Return this objective's firing loudness, resolved from its own config through the crosswalk."""
        return vocabulary.severity(self.severity_source, self.severity_tier)

    def judge(self, points: Sequence[tuple[float, Any]], *,
              now: dt.datetime) -> conditions.Verdict:
        """Return this objective's verdict over *points* at *now* — the entry point `tick` drives."""
        return verdict(self, points, now=now)


def _bounded(name: str, value: Any) -> float:
    """Return *value* inside :data:`LIMITS` for `name`, refusing anything else."""
    low, high = LIMITS[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
            or not low <= value <= high:
        raise StateError(f'SLO {name} must be a finite number in {low:g}..{high:g}')
    return float(value)


def rule(document: Mapping[str, Any], *, source: str) -> BurnCondition:
    """Build one validated `BurnCondition` from an operator document; an unknown key is a refusal.

    `source` is the producer identity, not a document field: it must match the token that posts the
    event (`configdrift`/`pathcheck` take it the same way), so an objective document cannot name a
    different author than the one the platform will authenticate.
    """
    if not isinstance(document, Mapping):
        raise StateError('SLO objective must be an object')
    missing = [name for name in OBJECTIVE_REQUIRED if not document.get(name)]
    for name in _WHOLE_SECONDS:
        if name in document and (isinstance(document[name], bool) or not isinstance(document[name], int)):
            raise StateError(f'SLO {name} must be a whole number')
    if set(document) - OBJECTIVE_KEYS or missing:
        raise StateError('SLO objective fields are unknown or missing: '
                         + ', '.join(sorted(set(document) - OBJECTIVE_KEYS) + missing))
    fields = dict(document)
    fields['source'] = source
    if not isinstance(fields.get('metric'), str) or not fields['metric']:
        # `metric` names the series the read narrows to, so it is not optional in practice even though it
        # is optional in the document: a missing one would silently widen the denominator to every series
        # the resource has, which is an attainment computed over a different question than was asked.
        raise StateError('SLO objective needs metric: the store series its samples are read from')
    if 'threshold_s' in fields and (isinstance(fields['threshold_s'], bool)
                                    or not isinstance(fields['threshold_s'], (int, float))
                                    or not math.isfinite(float(fields['threshold_s']))):
        raise StateError('SLO threshold_s must be a finite number')
    return BurnCondition(**fields)


def load_config(path: Path | str, *, source: str) -> dict[str, Any]:
    """Read and validate one objective document; the off switch is the absence of the file.

    The bounds are `conditions.load_config`'s, because the returned mapping is the shape that module's
    cursor helpers read: ``{'rules': [...], 'interval_seconds': n, 'cursor': None}``. The document spells
    its list `objectives` — that is the operator's word, and the in-memory key is the cursor's word — and
    `interval_seconds` is the grid every window in this round is aligned to. `cursor` is not a document
    field: it is ``LO_SLO_CURSOR``, because the cursor is not a tuning knob.
    """
    candidate = Path(path)
    if len(candidate.read_bytes()) > MAX_CONFIG_BYTES:
        raise StateError('SLO configuration exceeds its byte bound')
    document = read_document(candidate)
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS:
        raise StateError('Unknown SLO configuration keys')
    entries = document.get('objectives')
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_OBJECTIVES:
        raise StateError('SLO objectives must be 1-16 entries')
    parsed = [rule(entry, source=source) for entry in entries]
    if len({item.objective_id for item in parsed}) != len(parsed):
        raise StateError('SLO objective ids must be unique')
    interval = document.get('interval_seconds', DEFAULT_TICK_SECONDS)
    if isinstance(interval, bool) or not isinstance(interval, int) \
            or not TICK_LIMITS[0] <= interval <= TICK_LIMITS[1]:
        raise StateError(f'SLO interval must be {TICK_LIMITS[0]}..{TICK_LIMITS[1]} seconds')
    return {'rules': parsed, 'interval_seconds': interval, 'cursor': None}


def producer_config(environment: Mapping[str, str] | None = None) -> dict[str, Any] | None:
    """Return the validated objectives, or None when this producer is not configured at all.

    An unset or blank ``LO_SLO_CONFIG`` is the documented off switch and answers one `INFO` line naming
    the variable. A file that is named and cannot be read or parsed is **not** off: it raises, and the
    worker exits 1, because a producer that survived a broken objective document would be reporting
    "nothing is burning" about budgets it never opened.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CONFIG_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('SLO producer is off; no configuration named', extra={'variable': CONFIG_ENVIRONMENT})
        return None
    source = (environ.get(SOURCE_ENVIRONMENT) or '').strip()
    if not source:
        raise StateError(f'SLO producer needs {SOURCE_ENVIRONMENT}: the platform records who said it')
    return load_config(raw, source=source)


def read_series(reader: Any, subject: BurnCondition, *,
                end: dt.datetime) -> conditions.SeriesRead:
    """Read one objective's samples through the store facade, and say how complete the answer is.

    One read, one span, one selector: `conditions.SeriesRead` is reused as the report shape so a round
    summary says the same words for a band rule and a budget. The read is refused (``answered='refused'``)
    when the store could not answer or a row names no instant — a blind tick, which files a `coverage`
    event and never a verdict — and reported `truncated` when it hit the row bound, which `tick` treats
    as blindness for the same reason: the facade keeps the *oldest* rows of a full page, so a truncated
    read may not contain the instant being judged at all.
    """
    window = Window(start=utc_text(end - dt.timedelta(seconds=subject.history_seconds)), end=utc_text(end))
    outcome = reader.read(subject.query_type, window=window,
                          parameters={'resource_id': subject.resource_id, 'rule_id': subject.id},
                          selectors={'metric_name': subject.metric})
    if outcome.status not in ('available', 'unavailable'):
        return conditions.SeriesRead([], 'refused', False, 1, 0.0)
    points: list[tuple[float, Any]] = []
    for row in outcome.samples:
        stamp = getattr(row, 'timestamp', None)
        value = getattr(row, 'value', None)
        if stamp is None or value is None:
            return conditions.SeriesRead([], 'refused', False, 1, 0.0)
        try:
            instant = timestamp(stamp)
        except (TypeError, ValueError) as exc:
            # A row that names no instant is a store answer this round cannot use, and refusing the read
            # says so; dropping the point quietly would shorten the window the attainment claims to span.
            raise StateError('SLO read returned a row whose timestamp this build cannot parse') from exc
        points.append((float(instant.timestamp()), value))
    points.sort(key=lambda item: item[0])
    return conditions.SeriesRead(points, 'ok' if points else 'empty', outcome.receipt.truncated, 1,
                                 float(subject.history_seconds))


def _burn_steps(subject: BurnCondition, points: Sequence[budget.Sample], *,
                end: dt.datetime) -> list[tuple[dt.datetime, budget.BurnCheck]]:
    """One check per evaluation bucket inside the sustain span, in time order, each stamped at its end.

    Bucketing is what makes ``for_seconds`` measurable from a series alone: the machine is stepped once
    per bucket and not once per sample, so a run is a run of evaluation windows — `dynamic_bands`'s
    precedent, and the reason a 1-second cadence and a 1-hour one age the same condition identically.
    """
    span_start = end.timestamp() - subject.sustain_seconds
    buckets = {int(epoch_s // subject.evaluation_seconds) for epoch_s, _ in points if epoch_s >= span_start}
    steps: list[tuple[dt.datetime, budget.BurnCheck]] = []
    for bucket in sorted(buckets):
        at_s = min((bucket + 1) * subject.evaluation_seconds, end.timestamp())
        steps.append((dt.datetime.fromtimestamp(at_s, dt.timezone.utc),
                      subject.policy.check(points, at_s)))
    return steps


def verdict(subject: BurnCondition, points: Sequence[tuple[float, Any]], *,
            now: dt.datetime) -> conditions.Verdict:
    """Judge one objective over one series at one instant, reconstructing its sustained burn state.

    Returns a `conditions.Verdict` — the shape every other condition here produces — so one caller reads
    one outcome vocabulary for a static tier, a learned band and an error budget. The attainment half and
    the burn half are judged apart and reported together: a burn pair that measures is worth filing even
    when the compliance window is too thin to print an attainment, and the `coverage` event beside it says
    which half could not be computed rather than leaving the reader to guess from a number that is absent.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise StateError('SLO evaluation needs an aware clock')
    ordered = conditions.ordered_points(points)
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // subject.evaluation_seconds
                                    * subject.evaluation_seconds, dt.timezone.utc)
    window = subject.window(end)
    report = budget.evaluate(subject.objective, ordered, end.timestamp())
    detail: dict[str, Any] = {'points': len(ordered), 'window': window, 'total': report.total,
                              'good': report.good, 'bad': report.bad,
                              'attainment': report.attainment, 'budget_status': report.status,
                              'burn': report.burn_rate, 'min_samples': int(subject.min_samples),
                              'compliance_window': budget.window_span(subject.compliance_seconds)}
    newest_s = ordered[-1][0] if ordered else None
    age = (end.timestamp() - newest_s) if newest_s is not None else None
    detail['age_seconds'] = None if age is None else int(age)
    detail['max_age_seconds'] = subject.max_age_seconds
    if age is None or not 0 <= age <= subject.max_age_seconds:
        # The rule `detections.evaluate` states and every producer here keeps: this tick says one thing,
        # about the signal, and nothing about the condition — so the incident keeps whatever the last
        # judged tick gave it, and a blind tick cannot close a burn it never saw.
        detail['reason'] = 'no point in the read window' if age is None else 'newest point is stale'
        return conditions.Verdict('stale', 'unjudged', None, detail,
                                  [conditions.coverage_event(subject, window, False)])

    steps = _burn_steps(subject, ordered, end=end)
    at_tick = subject.policy.check(ordered, end.timestamp())
    detail.update({'long_burn': at_tick.long_burn_rate, 'short_burn': at_tick.short_burn_rate,
                   'threshold': at_tick.threshold, 'buckets': len(steps)})
    if report.status == budget.INSUFFICIENT_DATA:
        detail['reason'] = 'compliance window holds fewer samples than min_samples'
    if at_tick.status == budget.INSUFFICIENT_DATA:
        # Neither window being measurable is "no data at all in the span"; one empty window is a series
        # that went quiet inside the short one. Both are named, both are coverage, and neither is a pass.
        detail['reason'] = ('neither burn window holds a sample' if at_tick.long_burn_rate is None
                            and at_tick.short_burn_rate is None else 'one burn window holds no sample')
        return conditions.Verdict('insufficient', 'unjudged', None, detail,
                                  [conditions.coverage_event(subject, window, False)])

    machine = conditions.SustainedStateMachine(for_seconds=subject.for_seconds,
                                               clear_seconds=subject.clear_seconds)
    judged = 0
    for at, check in steps:
        if check.status == budget.INSUFFICIENT_DATA:
            continue                       # nothing judgeable in this bucket: no step, never a resolve
        judged += 1
        machine.step(subject.id, true=check.burning, now=at)
    detail['buckets_judged'] = judged
    # The tick itself, one last step: a burn that is still true has to be able to reach its `for:`
    # deadline at an instant the series does not contain, exactly as in `conditions.verdict`.
    machine.step(subject.id, true=at_tick.burning, now=end)
    state = machine.state_of(subject.id)
    status = conditions.FIRING if state in conditions.HOLDING else conditions.RESOLVED
    observed_s = ordered[-1][0]
    detail.update({'state': state, 'value': ordered[-1][1],
                   'long_burn_window': budget.window_span(subject.long_window),
                   'short_burn_window': budget.window_span(subject.short_window)})
    outcome = 'firing' if status == conditions.FIRING else (
        'pending' if state == 'pending' else 'resolved')
    return conditions.Verdict(outcome, state, status, detail,
                              [conditions.coverage_event(subject, window,
                                                         report.status != budget.INSUFFICIENT_DATA),
                               conditions.condition_event(subject, status, window, observed_s)])


def evaluate(subject: BurnCondition, points: Sequence[tuple[float, Any]], *,
             now: dt.datetime) -> list[dict[str, Any]]:
    """Return the canonical events one objective owes at *now* — the caller-facing shape of `verdict`."""
    return verdict(subject, points, now=now).events


def tick(index_path: Path | str, config: Mapping[str, Any], cursor_path: Path, reader: Any,
         deliver: Callable[[dict[str, Any]], None], *, now: dt.datetime,
         state: Mapping[str, Any]) -> dict[str, Any]:
    """Judge every objective at one instant, deliver the batch, and advance the cursor only on success.

    The ordering discipline is `conditions.tick`'s, adopted rather than re-derived because the cursor it
    writes is the same shape and the same helpers read and validate it (`cursor_binding`, `load_cursor`,
    `detection_worker.save`): every event of the round is accepted before the window moves, a refused
    round keeps its bytes pending and replays them before judging anything new, and a window already
    delivered at this grid position answers `idle` instead of offering a second opinion about it. Storing
    the undelivered bytes instead of re-deriving them is the point — `detections.event` stamps
    ``expires_at`` from the window it was handed, so re-judging a window after a crash is a *different*
    event with a shorter life, and the platform would read that as a new verdict rather than a retry.

    The cursor follows the document schedule; reads and verdicts share each objective's
    evaluation cutoff. Truncated reads use the same cutoff for their coverage event.

    Args:
        index_path: The declared inventory index; every objective's resource must resolve in it, so a typo
            in a UUID refuses the round before any store read runs (`detections.evaluate`'s rule).
        config: The validated document from :func:`load_config`.
        cursor_path: Where this producer's own JSON cursor lives.
        reader: A `store.client.StoreClient` to read series through — the production facade or the
            in-memory backend a test seeds, and the only read surface in this package.
        deliver: Called once per event; must raise when the event was not accepted.
        now: The injected clock.
        state: The cursor document from `conditions.load_cursor`, required for the same reason the cursor
            file is: a verdict that cannot record what it owes is a verdict that can be lost.

    Returns:
        The round summary: ``result``, the per-objective outcome words, their judgment details, the event
        count and the objectives whose read came back short. Every word in ``objectives`` is one of
        :data:`OUTCOMES`; a round that judged nothing is not reported as a healthy one.
    """
    binding = conditions.cursor_binding(config)
    pending = state.get('pending') if state.get('binding') == binding else None
    summary: dict[str, Any] = {'result': 'delivered', 'objectives': {}, 'detail': {}, 'events': 0,
                               'refusals': 0, 'insufficient': 0, 'truncated': []}
    if pending:
        for item in pending['events']:
            deliver(item)
            summary['events'] += 1
        _save(cursor_path, {'schema_version': conditions.CURSOR_VERSION, 'binding': binding,
                            'pending': None, 'last_end': pending['end'],
                            'previous_end': state.get('last_end')})
        return {**summary, 'result': 'replayed'}
    with index.readonly(index_path) as connection:
        for entry in config['rules']:
            if index.resolve(connection, resource_id=entry.resource_id)['status'] != 'resolved':
                raise StateError('SLO objective resource is not declared')
    end = conditions.grid_end(now, seconds=config['interval_seconds'])
    if state.get('last_end') == utc_text(end):
        return {**summary, 'result': 'idle'}
    batch: list[dict[str, Any]] = []
    for entry in config['rules']:
        cutoff = conditions.grid_end(end, seconds=entry.evaluation_seconds)
        reading = read_series(reader, entry, end=cutoff)
        if reading.truncated:
            summary['truncated'].append(entry.objective_id)
        if reading.answered == 'refused':
            summary['objectives'][entry.objective_id] = 'unreadable'
            summary['refusals'] += 1
            continue
        # A truncated read reports coverage at the same evaluation watermark.
        result = _blind(entry, cutoff) if reading.truncated else entry.judge(reading.points, now=cutoff)
        summary['objectives'][entry.objective_id] = result.outcome
        if result.outcome == 'insufficient':
            summary['insufficient'] += 1
        summary['detail'][entry.objective_id] = dict(result.detail, read={
            'answered': reading.answered, 'truncated': reading.truncated, 'reads': reading.reads,
            'covered_seconds': reading.covered_s, 'points': len(reading.points)})
        batch.extend(result.events)
    if batch:
        _save(cursor_path, {'schema_version': conditions.CURSOR_VERSION, 'binding': binding,
                            'pending': {'binding': binding, 'end': utc_text(end), 'events': batch},
                            'last_end': state.get('last_end')})
        for item in batch:
            deliver(item)
            summary['events'] += 1
        _save(cursor_path, {'schema_version': conditions.CURSOR_VERSION, 'binding': binding,
                            'pending': None, 'last_end': utc_text(end),
                            'previous_end': state.get('last_end')})
    else:
        summary['result'] = 'idle'
    return summary


def _blind(subject: BurnCondition, end: dt.datetime) -> conditions.Verdict:
    """The one round-shape answer a truncated read earns: coverage, and no claim about the budget.

    Not a `verdict` over the rows that did arrive, because the store keeps the oldest rows of a full page:
    the tail the burn windows need is precisely what is missing, and judging the head of a series as if it
    were the whole span would print an attainment whose denominator is a truncation. The reason is named
    in the detail so the round line says *why* nothing was said about the budget.
    """
    window = subject.window(end)
    return conditions.Verdict('truncated', 'unjudged', None,
                              {'points': 0, 'window': window,
                               'reason': 'read hit the store row bound; the newest samples are not in it'},
                              [conditions.coverage_event(subject, window, False)])


def _save(cursor_path: Path, value: Mapping[str, Any]) -> None:
    """Write the cursor atomically, reusing `detection_worker.save` and its fsync discipline."""
    from local_observe.platform.detection_worker import save
    save(Path(cursor_path), dict(value))


def summary_line(summary: Mapping[str, Any]) -> dict[str, Any]:
    """Reduce one round summary to the fields its log line is built from — one place, both entry points.

    `__main__.py` logs it every round and the tests read it, so the pair cannot drift into a log line
    that names keys the round stopped producing (the defect `configdrift`'s pinned key-set test exists for).
    """
    return {'result': summary['result'], 'events': summary['events'],
            'objectives': summary['objectives'], 'refusals': summary['refusals'],
            'insufficient': summary['insufficient'], 'truncated': summary['truncated']}


def cursor_document(path: Path, config: Mapping[str, Any]) -> dict[str, Any]:
    """Load this producer's cursor through the platform's own loader, so refusals are shared not restated."""
    return conditions.load_cursor(path, config)

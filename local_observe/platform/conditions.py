"""Sustained alert conditions: the ``for:`` state machine, absence, and coverage-first inputs.

**What this adds to** `platform/detections.py` **is time.** `detections.evaluate` judges one sample in
one window and its answer flips with the sample, so a value oscillating on a threshold files firing,
resolved, firing — and intake books a delivery for **both** edges (`state.Store.intake` writes an outbox
row on ``opened`` *and* on ``resolved``), so each flap pages twice and opens a fresh incident, because
resolving an incident clears `conditions.incident_id` and the next firing mints a new one. A condition
here is a machine whose reported status only changes once a crossing has held, so an oscillation is one
condition with one page instead of two per flap.

**Hysteresis was a choice between two mechanisms, and the duration won.** The alternative was a
deadband (``fire_above``/``clear_below`` — two numbers per rule). ``for_seconds`` was picked because:

* a learned band (platform/dynamic_bands.py) has no natural *width* to build a deadband from — its width
  is the thing it just learned — while "held for N seconds" means the same thing for a static threshold,
  an availability probe and a band, so one field covers every rule here and in forecast/error budget;
* it is the mechanism v0.1 shipped (`legacy:alerting/conditions.SustainedStateMachine`, ``for_duration_s``)
  and the one the downstream port rows already assume: alert conditions's brief hands a predicted crossing to "the
  rule's ``for:`` duration" and error budget wants burn windows enforced by "the same code that enforces every
  other ``for:`` duration";
* a deadband hides only a flap that stays between its two lines, while a duration hides a flap of any
  shape shorter than the duration, which is the case that pages twice per hour in practice.

The cost is stated rather than hidden: a crossing that resolves inside ``for_seconds`` never fires at
all, so a spike that matters briefly *is* invisible, by design; and this module can only see the points
it was handed, so a rule whose ``history_seconds`` does not exceed its own ``for_seconds`` plus its
``evaluation_seconds`` is refused at load rather than silently never firing. **One deliberate deviation
from v0.1:** its machine resolves on the first non-breaching tick, which re-pages on the next flap —
the exact defect this card exists to remove — so the clear side is symmetric here: a run of
non-crossing must last ``resolve_seconds`` (default: ``for_seconds``) before the condition reports
resolved.

**Absence is the odd rule out and carries no machine.** A no-data condition is judged by the clock
against the deadline the rule names (``within_seconds``), and a second duration stacked behind a
deadline is two numbers answering one question; v0.1 made the same choice (`AbsenceCondition.window_s`).
A rule that sets ``for_seconds`` on an absence mode is refused, not ignored.

Two rules from `detections.evaluate` are kept exactly as they were, because they are the reason that
function's docstring exists: **a None/failed/stale input opens coverage and never recovers the
underlying condition** — when the newest point is absent or older than ``max_age_seconds`` this module
emits *only* the coverage event, so the stored condition stays as it was and a blind tick cannot close
an incident; and **blindness is never silence** — a rule that cannot judge the series it was handed (no
points at all, a band too thin to learn, a read that arrived incomplete for this evaluator) files a
``coverage`` event and names its own reason in the tick summary, never a quiet ``resolved``. A read the
store could not answer at all is the one exception, and it is the round's oldest: it is named in the
summary, spends one refusal, files nothing about the condition, and moves the cursor only if some other
rule's events owed a delivery this round (`tick`).

The clock is always injected and there are no threads and no wall-clock reads: `verdict`/`evaluate` take
``now`` and a series of ``(epoch seconds, value)`` points — the same point shape
`platform/anomaly.series_points` produces, so a read from store facade's facade, a cursor replay and a test
fixture are interchangeable. Nothing here notifies, delivers or reads a delivery mode: the only output is
canonical events through `detections.event`, and the page-or-not decision belongs to the platform service
(`docs/CONTRACTS.md` §5). Loudness comes from the rule's own config field resolved by
`platform/vocabulary.severity`, so this file names no severity at all.
"""
import datetime as dt
import math
import operator
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple, Protocol

from local_observe.inventory import index
from local_observe.inventory.validation import digest, read_document, timestamp, utc_text
from local_observe.store.client import MAX_ROWS, MAX_WINDOW_SECONDS, Window
from . import vocabulary
from .detections import event
from .state import StateError, identifier, label

# The four comparisons a typed rule can mean, ported from `legacy:alerting/conditions.OPS`: an operator
# table and never an expression evaluator, so a rule document cannot carry code.
OPS: dict[str, Callable[[float, float], bool]] = {'>': operator.gt, '>=': operator.ge,
                                                  '<': operator.lt, '<=': operator.le}
#: The three things a rule of *this* module can watch: `absence` is judged by the clock, the others by
#: value. A fourth mode, ``band`` (platform/dynamic_bands.py), arrives in the same documents and is
#: dispatched by :func:`rule` to its own estimator, so one configuration file and one round can hold both.
#: It is deliberately absent from this tuple: a `Rule` carrying it would own a machine it cannot run.
MODES = ('threshold', 'availability', 'absence')
# Which `state.EVENT_KINDS` word each mode's verdict is filed under. Absence is `coverage` and not
# `availability` for the reason the crosswalk states (docs/CONTRACTS.md §4.1, the boundary that decides
# availability against coverage): a test that RAN and failed is availability; a signal that stopped
# arriving says nothing about the thing it came from, only about the signal.
KIND_BY_MODE: dict[str, str] = {'threshold': 'threshold', 'availability': 'availability',
                                'absence': 'coverage'}
# Which evidence reference `state.validate_event` admits for each mode — the same three
# `detections.evaluate` and `anomaly` already use, so no new query vocabulary arrives here.
QUERY_BY_MODE: dict[str, str] = {'threshold': 'metric-threshold', 'availability': 'gatus-result',
                                 'absence': 'source-heartbeat'}
FIRING, RESOLVED = 'firing', 'resolved'
#: Machine states. `pending` is a crossing too short to fire and `clearing` a non-crossing too short to
#: resolve: neither is a verdict the platform has not already been told, which is what the flap costs.
STATES = ('ok', 'pending', 'firing', 'clearing')
#: The two states whose verdict is `firing`: a run that is clearing has not cleared yet.
HOLDING = ('firing', 'clearing')

DEFAULT_EVALUATION_SECONDS = 60
DEFAULT_MAX_AGE_SECONDS = 120
DEFAULT_HISTORY_SECONDS = 3600
# A series longer than the store's own row bound cannot be honest about its start, and the point list is
# a caller-supplied argument: the bound is applied to the argument too, not only to the read — and to the
# composition of several reads, checked while they compose and not after (see `SeriesRead`: a composition
# that would break this bound is stopped with nothing retained and reported incomplete, never trimmed
# into a verdict).
MAX_POINTS = MAX_ROWS
# The instants a point may name. A series is `(epoch seconds, value)`, and an unvalidated float here
# would reach `datetime.fromtimestamp` and raise the driver's own OSError (a 500-shaped answer to a
# config typo) or roll the epoch backwards past the platform's own stamps, where a comparison against
# `utc_text(now)` stops meaning anything. 2001 and 2100 bound the range a real point can sit in.
EPOCH_MIN = 978_307_200
EPOCH_MAX = 4_102_444_800
MAX_RULES = 16
MAX_CONFIG_BYTES = 262_144
# How many reads one rule may spend per round to get past the facade's 2 000-row cap (see `SeriesRead`):
# one read of the whole span, and one retry at this many slices. Four is the whole budget — a producer
# that needed more would be doing a backfill, which is a reviewed operation and not a tick.
MAX_READ_SPANS = 3
MAX_CURSOR_BYTES = 1_048_576
CURSOR_VERSION = 1
CURSOR_KEYS = frozenset({'schema_version', 'binding', 'pending', 'last_end', 'previous_end'})
CONFIG_KEYS = frozenset({'rules', 'interval_seconds'})
RULE_KEYS = frozenset({'id', 'mode', 'resource_id', 'source', 'severity_source', 'severity_tier',
                       'evaluation_seconds', 'max_age_seconds', 'history_seconds', 'for_seconds',
                       'resolve_seconds', 'within_seconds', 'op', 'threshold', 'metric'})
RULE_REQUIRED = ('id', 'mode', 'resource_id', 'source', 'severity_source', 'severity_tier')
DEFAULT_TICK_SECONDS = 300
TICK_LIMITS = (5, 3600)
# Every bound is a refusal at load and not a runtime surprise, in the `anomaly.LIMITS` shape.
LIMITS: dict[str, tuple[float, float]] = {
    'for_seconds': (0, 86400), 'resolve_seconds': (0, 86400), 'evaluation_seconds': (5, 3600),
    'max_age_seconds': (1, 86400), 'within_seconds': (60, 86400), 'history_seconds': (60, 604800),
    'threshold': (-1e15, 1e15)}
# The outcome words one rule can report for one tick. `insufficient` belongs to
# platform/dynamic_bands.py and never appears here, and every word except `firing`/`resolved`/`pending`
# describes a tick that could not judge — which is why none of them is allowed to resolve anything.
OUTCOMES = ('firing', 'resolved', 'pending', 'stale', 'unseen', 'unreadable')


@dataclass(frozen=True)
class Rule:
    """One alertable condition: its identity, its timing, and where its loudness comes from.

    `severity_source` is a *declared source vocabulary* name (`vocabulary.SOURCE_VOCABULARIES`) and
    `severity_tier` one of that source's own words: the loudness is a config field resolved through the
    crosswalk, never a word this module knows. That is deliberate and it is why no severity appears
    below — a rule that wants the loudest rung names the word in the ladder it cites, and an unmapped
    word refuses at load (`vocabulary.VocabularyError`) instead of shipping a guess about volume.

    Raises:
        StateError: Any field is outside its bound, the mode's required fields are absent, or the
            timings cannot be satisfied by the history the rule will be judged over. A
            `vocabulary.VocabularyError` from the loudness lookup propagates unchanged: it is a
            ValueError, and `cli.py` already answers one JSON line for it.
    """
    id: str
    mode: str
    resource_id: str
    source: str
    severity_source: str
    severity_tier: str
    evaluation_seconds: int = DEFAULT_EVALUATION_SECONDS
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    history_seconds: int = DEFAULT_HISTORY_SECONDS
    for_seconds: int = 0
    resolve_seconds: int | None = None
    within_seconds: int = 600
    op: str = '>'
    threshold: float | None = None
    metric: str | None = None

    def __post_init__(self) -> None:
        """Check every field against its bound, and the rule's timings against each other."""
        label(self.id)
        label(self.source)
        identifier(self.resource_id)
        if self.mode not in MODES:
            raise StateError('Unsupported condition mode')
        for name in ('evaluation_seconds', 'max_age_seconds', 'history_seconds', 'for_seconds',
                     'within_seconds'):
            _bounded(name, getattr(self, name))
        if self.resolve_seconds is not None:
            _bounded('resolve_seconds', self.resolve_seconds)
        if self.mode == 'absence':
            if self.for_seconds or self.resolve_seconds is not None:
                raise StateError('An absence rule has one deadline: within_seconds')
            if self.threshold is not None or self.op != '>':
                raise StateError('An absence rule judges no value')
            if self.history_seconds <= self.within_seconds:
                raise StateError('Absence history must outlast its own deadline')
            return
        if self.mode == 'threshold':
            if self.op not in OPS:
                raise StateError('Unsupported condition comparison')
            if self.threshold is None or isinstance(self.threshold, bool) \
                    or not isinstance(self.threshold, (int, float)) or not math.isfinite(self.threshold):
                raise StateError('A threshold rule needs a finite numeric threshold')
            _bounded('threshold', float(self.threshold))
        elif self.threshold is not None or self.op != '>':
            raise StateError('An availability rule judges a boolean, not a comparison')
        # The reconstruction bound: the machine can only date a run from the first point it can see, so a
        # history no longer than the durations it must measure could never reach either edge. Refusing
        # the rule is the only honest answer available at load.
        if self.history_seconds <= self.for_seconds + self.evaluation_seconds:
            raise StateError('Condition history must outlast its own for/evaluation windows')
        # Refuse a loudness the crosswalk cannot resolve *now*, at load, rather than at the first firing
        # tick — which is the difference between a bad config discovered on the operator's desk and one
        # discovered during the incident the rule existed to report.
        vocabulary.severity(self.severity_source, self.severity_tier)

    @property
    def clear_seconds(self) -> int:
        """How long non-crossing must last before the condition reports `resolved`."""
        return self.for_seconds if self.resolve_seconds is None else self.resolve_seconds

    @property
    def kind(self) -> str:
        """The `state.EVENT_KINDS` word this rule's verdict is filed under."""
        return KIND_BY_MODE[self.mode]

    @property
    def query_type(self) -> str:
        """The evidence reference kind this rule's events cite."""
        return QUERY_BY_MODE[self.mode]

    @property
    def version(self) -> str:
        """The `rule_version` this rule's events carry: a digest of everything a verdict depends on.

        `anomaly._rule_version` is the precedent (16 hex of the knob binding, so the identity of a
        condition moves when the judgment moves). Severity is deliberately **not** an input: retuning
        how loud a rule is must not orphan the incident it already opened, while changing how long a
        crossing must hold genuinely produces a different condition — and, as in `anomaly`, leaves the
        previous rule's incident open for an operator to reconcile by hand.
        """
        return digest([self.mode, self.op, self.threshold, self.for_seconds, self.clear_seconds,
                       self.evaluation_seconds, self.max_age_seconds, self.history_seconds,
                       self.within_seconds])[:16]

    def crosses(self, value: Any) -> bool:
        """Return whether one point breaches this rule; a bad value is a refusal, never a quiet False."""
        if self.mode == 'availability':
            if not isinstance(value, bool):
                raise StateError('Availability condition requires a boolean verdict')
            return not value
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise StateError('Threshold condition requires finite numeric values')
        if self.threshold is None:
            raise StateError('Threshold condition has no threshold')
        return OPS[self.op](float(value), float(self.threshold))

    def severity(self) -> str:
        """Return this rule's firing loudness, resolved from its own config through the crosswalk."""
        return vocabulary.severity(self.severity_source, self.severity_tier)

    def judge(self, points: Sequence[tuple[float, Any]], *,
              now: dt.datetime) -> 'Verdict':
        """Return this rule's verdict over *points* at *now*: :func:`verdict` with the arguments swapped."""
        return verdict(self, points, now=now)


class Verdict(NamedTuple):
    """One rule's answer at one instant: the words, and the events that answer earned.

    `outcome` is the acknowledgement word a tick logs (`OUTCOMES`), `state` is the machine state after
    this tick (`STATES`, or ``unjudged``/``present``/``absent`` for what no machine decided), `status` is the event
    status this tick files (`firing`/`resolved`, or None when the tick could not judge the condition at
    all and files only coverage), and `detail` counts what the judgment saw. The words are separate
    because they answer different questions: ``stale`` says *why nothing was filed about the condition*,
    while the stored incident keeps the status the last judged tick gave it.
    """

    outcome: str
    state: str
    status: str | None
    detail: dict[str, Any]
    events: list[dict[str, Any]]


def _bounded(name: str, value: Any) -> float:
    """Return *value* as a float inside the bound `LIMITS` names for it, refusing anything else."""
    low, high = LIMITS[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) \
            or not low <= value <= high:
        raise StateError(f'Condition {name} must be a finite number in {low:g}..{high:g}')
    return float(value)


def rule(document: Mapping[str, Any]) -> Rule:
    """Build one validated `Rule` from an operator document; an unknown key is a refusal, not ignored.

    A typo in a rule document that silently did nothing is the failure mode this repository keeps
    refusing (`notifications.build_channels` is the precedent): every key here must be one the rule
    reads, and every mode must carry the fields that mode judges.
    """
    if not isinstance(document, Mapping):
        raise StateError('Condition rule must be an object')
    if document.get('mode') == 'band':
        # A late import, decided by the cycle: platform/dynamic_bands.py imports this module for the
        # state machine and the event builders, so an arrow the other way at module level would fail at
        # service start. `state.py`'s `notification_safety` import is the precedent in this package.
        from .dynamic_bands import band_rule
        return band_rule(document)
    missing = [name for name in RULE_REQUIRED if not isinstance(document.get(name), str)
               or not document[name]]
    if set(document) - RULE_KEYS or missing:
        raise StateError('Condition rule fields are unknown or missing: '
                         + ', '.join(sorted(set(document) - RULE_KEYS) + missing))
    for name in ('evaluation_seconds', 'max_age_seconds', 'history_seconds', 'for_seconds',
                 'resolve_seconds', 'within_seconds'):
        if name in document and (isinstance(document[name], bool)
                                 or not isinstance(document[name], int)):
            raise StateError(f'Condition {name} must be a whole number of seconds')
    if 'metric' in document and (not isinstance(document['metric'], str) or not document['metric']
                                 or len(document['metric']) > 256):
        raise StateError('Condition metric must be a short name')
    return Rule(**{'threshold': None, 'within_seconds': 600, 'history_seconds': DEFAULT_HISTORY_SECONDS,
                   'metric': None, **dict(document)})


def load_config(path: Path | str) -> dict[str, Any]:
    """Read and validate one conditions document; the off switch is the absence of the file.

    Bounds on the file itself are `anomaly.load_config`'s: a size cap applied to the bytes before the
    parse, a closed key set, 1..16 rules with unique ids, and an `interval_seconds` inside
    :data:`TICK_LIMITS` — the alignment of the evaluation window every rule in this document shares.
    """
    candidate = Path(path)
    if len(candidate.read_bytes()) > MAX_CONFIG_BYTES:
        raise StateError('Condition configuration exceeds its byte bound')
    document = read_document(candidate)
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS:
        raise StateError('Unknown condition configuration keys')
    entries = document.get('rules')
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_RULES:
        raise StateError('Condition rules must be 1-16 entries')
    parsed = [rule(entry) for entry in entries]
    if len({item.id for item in parsed}) != len(parsed):
        raise StateError('Condition rule ids must be unique')
    interval = document.get('interval_seconds', DEFAULT_TICK_SECONDS)
    if isinstance(interval, bool) or not isinstance(interval, int) or not TICK_LIMITS[0] <= interval \
            <= TICK_LIMITS[1]:
        raise StateError(f'Condition interval must be {TICK_LIMITS[0]}..{TICK_LIMITS[1]} seconds')
    return {'rules': parsed, 'interval_seconds': interval, 'cursor': document.get('cursor')}


class SustainedStateMachine:
    """Per-key ``ok -> pending -> firing -> clearing -> ok`` tracker. Pure, clock-injected, no threads.

    Ported from `legacy:alerting/conditions.SustainedStateMachine` with one change and one addition. The
    change is the clear side: v0.1 resolved on the first non-breaching tick, so a value that touched
    back through the threshold closed the incident and the next breach opened a *new* one — two pages
    per flap, which is what this card was written to stop. The addition is the optional `since`, which
    lets a caller that knows when its predicate became true say so instead of letting the machine date
    the run at the first tick it happened to be asked (a learned band can report the crossing instant; a
    plain tick cannot).

    One machine serves many keys (``(rule id, resource id)`` pairs, or one key per rule) because v0.1
    keyed the same way and because the reconstruction in :func:`verdict` replays one series at a time.
    """

    def __init__(self, *, for_seconds: int, clear_seconds: int) -> None:
        """Fix the two durations; both are seconds and 0 means "the edge is this tick"."""
        if not 0 <= for_seconds <= 86400 or not 0 <= clear_seconds <= 86400:
            raise StateError('Sustained durations must be 0..86400 seconds')
        self.for_seconds = for_seconds
        self.clear_seconds = clear_seconds
        self._state: dict[str, tuple[str, dt.datetime | None]] = {}

    def state_of(self, key: str) -> str:
        """Return the machine's state for one key: `ok` for a key it has never seen."""
        return self._state.get(key, ('ok', None))[0]

    def step(self, key: str, *, true: bool, now: dt.datetime,
             since: dt.datetime | None = None) -> str | None:
        """Advance one key to *now*; return `FIRING`/`RESOLVED` on an edge and None on every other tick.

        `since` is the instant the caller believes the current run began, used only when the machine is
        entering a run. A value in the future of `now` is pulled back to `now`: a caller that mis-dates
        a crossing must be able to delay an edge, never invent one that already happened.

        A crossing that never reaches ``for_seconds`` returns the key to ``ok`` **silently**, exactly as
        v0.1 does: a sub-duration spike is not an incident and filing it as one would be the flap this
        machine exists to prevent.
        """
        if not isinstance(now, dt.datetime) or now.tzinfo is None:
            raise StateError('Sustained step needs an aware clock')
        if since is not None and since.tzinfo is None:
            raise StateError('Sustained step needs an aware crossing instant')
        state, run_start = self._state.get(key, ('ok', None))
        if since is not None and now is not None and since > now:
            since = now
        if true:
            if state == 'firing':
                return None                      # already fired: no second edge, that is the whole point
            if state == 'clearing':
                # The hysteresis, in one line: a crossing that arrives while the clear run is still too
                # short does NOT go back to `pending`. The condition was never cleared, so from the
                # platform's side there is no new condition to earn — re-entering `pending` here is
                # exactly the flip that pages twice per flap. Opening needs evidence; reopening something
                # that never closed does not.
                self._state[key] = ('firing', run_start)
                return None
            if state != 'pending':
                state, run_start = 'pending', (since or now)
            self._state[key] = (state, run_start)
            if (now - run_start).total_seconds() >= self.for_seconds:
                self._state[key] = ('firing', run_start)
                return FIRING
            return None
        if state == 'pending':
            self._state[key] = ('ok', None)        # a spike too short to fire: silent, as in v0.1
            return None
        if state == 'firing':
            self._state[key] = ('clearing', since or now)
            return None
        if state == 'clearing':
            start = run_start or now
            self._state[key] = ('clearing', start)
            if (now - start).total_seconds() >= self.clear_seconds:
                self._state[key] = ('ok', None)
                return RESOLVED
            return None
        self._state[key] = ('ok', None)
        return None


class Judged(Protocol):
    """What the event builders and the series read below need from anything that can be judged.

    `Rule` here and `dynamic_bands.Band` both satisfy it without declaring it (as do
    `forecast.timetothreshold.ForecastRule` and `slo.alerts.BurnCondition`): identity, the vocabulary
    words the event must carry, the loudness, and the fields a store read and an event window name. One
    pair of event builders is what keeps a static threshold and a learned band from drifting into two
    event shapes — the defect `platform/vocabulary.py` exists to prevent, applied to the producer side.
    """

    id: str
    source: str
    resource_id: str
    kind: str
    query_type: str
    version: str
    history_seconds: int
    # The width of the window a verdict is filed under, and the grid :func:`_aligned_window` floors `now`
    # onto. An attribute and not a method because every subject already carries it as one, and because a
    # round that could not judge still owes a coverage event naming the same window the verdict it
    # withheld would have named.
    evaluation_seconds: int
    metric: str | None

    def severity(self) -> str:
        """Return the firing loudness a verdict from this subject carries, resolved through the crosswalk.

        Only a `firing` event ever asks: a recovery names no loudness and lets `detections.event` derive
        the quiet default.
        """
        ...

    def judge(self, points: Sequence[tuple[float, Any]], *,
              now: dt.datetime) -> 'Verdict':
        """Return this subject's verdict over *points* at *now* — the entry point :func:`tick` drives.

        The one method a round needs to treat a static tier and a learned band as the same kind of rule
        without branching on a mode string: each subject knows how it judges itself.
        """
        ...


def ordered_points(points: Sequence[tuple[float, Any]]) -> list[tuple[float, Any]]:
    """Bound, sort and return the series a rule is judged over; a malformed point is a refusal."""
    if not isinstance(points, Sequence) or isinstance(points, (str, bytes)):
        raise StateError('Condition series must be a sequence of (epoch seconds, value) points')
    if len(points) > MAX_POINTS:
        raise StateError('Condition series exceeds its point bound')
    ordered = sorted(points, key=lambda item: item[0])
    for epoch_s, value in ordered:
        if isinstance(epoch_s, bool) or not isinstance(epoch_s, (int, float)) \
                or not math.isfinite(epoch_s) or not EPOCH_MIN <= epoch_s <= EPOCH_MAX:
            raise StateError('Condition series point is outside the supported epoch range')
        if not isinstance(value, (bool, int, float)):
            raise StateError('Condition series values must be numeric or boolean')
    return ordered


def _aligned_window(rule: Judged, now: dt.datetime) -> tuple[dt.datetime, dict[str, str]]:
    """Return one rule's grid instant for *now*, and the event window that instant names.

    The alignment is the rule's own ``evaluation_seconds`` and nobody else's, which is what lets a rule
    judging a five-minute window sit in the same round as one judging an hour. :func:`verdict` files its
    verdict over this pair and :func:`_incomplete_read` files its coverage over the same one, so a round
    that could not judge cannot end up describing a different window than the verdict it withheld.
    """
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // rule.evaluation_seconds
                                    * rule.evaluation_seconds, dt.timezone.utc)
    return end, {'start': utc_text(end - dt.timedelta(seconds=rule.evaluation_seconds)),
                 'end': utc_text(end)}


def verdict(rule: Rule, points: Sequence[tuple[float, Any]], *, now: dt.datetime) -> Verdict:
    """Judge one rule over one series at one instant, reconstructing its state from the points.

    No state lives in a process here: the machine is replayed over the whole series on every call, so a
    restarted worker that reads the same window reaches the same verdict, and the only thing a producer
    has to remember durably is which window it already delivered. What reconstruction cannot do is date a
    run from before the first point it can see, which is why `load_config` refuses a history shorter
    than the durations it must measure.

    Returns:
        A `Verdict` whose `events` are the canonical events this tick should file: only the coverage
        event when the input is stale or absent (so the stored condition is left exactly as it was), and
        coverage-plus-condition when the rule could judge anything.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise StateError('Condition evaluation needs an aware clock')
    ordered = ordered_points(points)
    window_end, window = _aligned_window(rule, now)
    detail: dict[str, Any] = {'points': len(ordered), 'window': window}
    newest_s = ordered[-1][0] if ordered else None
    age = (window_end.timestamp() - newest_s) if newest_s is not None else None

    if rule.mode == 'absence':
        return _absence_verdict(rule, window, newest_s, age, detail)

    fresh = age is not None and 0 <= age <= rule.max_age_seconds
    detail['fresh'] = fresh
    if not fresh:
        # The `detections.evaluate` rule, kept whole: this tick says one thing, about the signal, and it
        # says nothing about the condition, so the incident keeps the status the last judged tick gave it.
        detail['age_seconds'] = None if age is None else int(age)
        return Verdict('stale', 'unjudged', None, detail, [coverage_event(rule, window, False)])

    machine = SustainedStateMachine(for_seconds=rule.for_seconds, clear_seconds=rule.clear_seconds)
    key = rule.id
    for epoch_s, value in ordered:
        machine.step(key, true=rule.crosses(value),
                     now=dt.datetime.fromtimestamp(epoch_s, dt.timezone.utc))
    # Then the tick itself: a value that stopped moving still has to be able to reach its `for:`
    # deadline, and it can only be reached at an instant the series does not contain.
    machine.step(key, true=rule.crosses(ordered[-1][1]), now=window_end)
    state = machine.state_of(key)
    status = FIRING if state in HOLDING else RESOLVED
    detail.update({'state': state, 'value': ordered[-1][1],
                   'age_seconds': int(age) if age is not None else None})
    outcome = 'firing' if status == FIRING else ('pending' if state == 'pending' else 'resolved')
    return Verdict(outcome, state, status, detail,
                   [coverage_event(rule, window, True),
                    condition_event(rule, status, window, ordered[-1][0])])


def _absence_verdict(rule: Rule, window: dict[str, str], newest_s: float | None,
                     age: float | None, detail: dict[str, Any]) -> Verdict:
    """Judge one no-data rule: the deadline is the clock's, and the reason is always named.

    A resource this rule has never seen and one that went quiet both arrive as a firing coverage-kind
    event, because both mean "the signal I need is not arriving" and neither may read as health; the
    `outcome` word separates them (``unseen`` for a rule that has nothing to measure) so the tick line
    and the portal can say which, and an absence rule never invents a verdict about the thing it watches.
    """
    if newest_s is None:
        detail.update({'reason': 'no point in the read window', 'within_seconds': rule.within_seconds})
        return Verdict('unseen', 'absent', FIRING, detail, [absence_event(rule, window, FIRING)])
    late = age > rule.within_seconds
    detail.update({'age_seconds': int(age), 'within_seconds': rule.within_seconds, 'late': late})
    status = FIRING if late else RESOLVED
    return Verdict(status, 'present' if not late else 'absent', status, detail,
                   [absence_event(rule, window, status)])


def coverage_event(rule: Judged, window: dict[str, str], fresh: bool) -> dict[str, Any]:
    """The companion coverage verdict: is this rule's signal arriving at all.

    Shaped exactly like `detections.evaluate`'s coverage event — same condition suffix, same parameters,
    same ``source-heartbeat`` reference — so one operator view reads a baseline detector, a sustained
    condition and a learned band without a special case, and the rule id it cites is the rule's own. It
    is filed on every judged tick (`resolved` when the input is fresh) rather than only on an edge,
    because its state is a function of the clock and not of the series: a verdict filed only when it
    changed could never close. Shared with platform/dynamic_bands.py for exactly that reason.
    """
    return event(rule.source, rule.resource_id, rule.id + '.coverage', 'coverage',
                 'resolved' if fresh else 'firing', window, {'rule_id': rule.id},
                 query_type='source-heartbeat')


def absence_event(rule: Judged, window: dict[str, str], status: str) -> dict[str, Any]:
    """The single event an absence rule files: the condition *is* the coverage verdict, so no companion."""
    return event(rule.source, rule.resource_id, rule.id, rule.kind, status, window,
                 {'rule_id': rule.id}, query_type=rule.query_type, version=rule.version,
                 severity=rule.severity() if status == FIRING else None)


def condition_event(rule: Judged, status: str, window: dict[str, str],
                    observed_s: float) -> dict[str, Any]:
    """File one judged verdict, with the loudness its rule names and the point that earned it.

    A recovery names no loudness and lets `detections.event` derive one, which is what keeps a resolved
    event from carrying the volume of the failure it ended (`vocabulary.severity`'s own rule). Shared
    with platform/dynamic_bands.py, so a static tier and a learned band cannot grow two event shapes.
    """
    observed = utc_text(dt.datetime.fromtimestamp(observed_s, dt.timezone.utc))
    parameters = {'rule_id': rule.id,
                  'sample_id': digest([rule.version, window['start'], window['end'], observed_s])}
    return event(rule.source, rule.resource_id, rule.id, rule.kind, status, window, parameters,
                 query_type=rule.query_type, version=rule.version, observed_at=observed,
                 severity=rule.severity() if status == FIRING else None)


def evaluate(rule: Rule, points: Sequence[tuple[float, Any]], *,
             now: dt.datetime) -> list[dict[str, Any]]:
    """Return the canonical events one rule owes at *now* — the caller-facing shape of `verdict`."""
    return verdict(rule, points, now=now).events


class SeriesRead(NamedTuple):
    """What one rule's series read produced: the points, and the three ways the answer can be thin.

    `answered` is ``ok`` (points arrived), ``empty`` (the store honestly held nothing in the window — an
    *answer*, and an absence rule reads it as absence) or ``refused`` (the store could not answer, its
    receipt no longer outlived the window, or one answer carried more rows than a page may: a blind tick
    and never a verdict). An unknown metric and a silent one arrive identically through
    ``source-heartbeat``, which is why a rule that has never been seen is named `unseen` by the absence
    verdict and not read as a down resource.

    `truncated` is the load-bearing field, and it means **inability to judge**, never "a shorter memory to
    grade anyway". Two shapes produce it: the bounded reads could not answer the whole span, and the span
    is denser than this module may judge — :data:`MAX_POINTS` is the *evaluator's* bound, applied while
    the slices compose, so such a read carries no points at all and spends no further reads hunting for
    them. Either way a read that says it is short is not a series. The store keeps the oldest rows of a
    full page, so the newest samples — the ones a verdict is dated from — are exactly what is missing, and
    a span cut by nothing but where a page ended can hide a firing period outright as easily as it can
    delay one. :func:`tick` therefore files the rule's own ``coverage`` event with the reason named and
    builds no verdict from it, the way `slo.alerts._blind` and `dynamic_bands`' `insufficient` already
    mean. Reported, never absorbed.
    """

    points: list[tuple[float, Any]]
    answered: str
    truncated: bool
    reads: int
    covered_s: float


def read_points(reader: Any, rule: Judged, *, end: dt.datetime) -> SeriesRead:
    """Read one rule's trailing series through the store facade, and say how complete the answer is.

    `reader` is any `local_observe.store.client.StoreClient` — the production facade or the in-memory
    backend a test seeds — and this module never builds SQL, never names a table and never opens a second
    HTTP client: the two named reads are ``metric-threshold`` (samples for a judged value) and
    ``source-heartbeat`` (whether the source produced anything at all, which answers with one presence
    record rather than rows).

    One read covers the whole span. When it comes back `truncated` the span is read again in
    :data:`MAX_READ_SPANS` equal slices and nothing else: a bounded retry, not a descent. Deeper history
    than that would be a backfill, which is a reviewed operation and not a tick, and a round that needed
    it would be spending reads in proportion to how badly the store is behaving.

    Returns:
        A `SeriesRead` holding at most :data:`MAX_POINTS` points and spending at most
        ``1 + MAX_READ_SPANS`` reads. The bound is applied **while the slices compose** — each slice is
        measured against what is already held before anything is appended, so a dense span stops the
        retry where it is discovered, reports itself `truncated` with no points, and keeps the reads it
        really spent and the span it was asked for. A store that refused, or one whose single answer
        carried more rows than a page may, answers ``refused`` instead, and `tick` treats that as the
        blind tick with no event that it always was. Neither shape is graded; the rules that do fit are.
    """
    wanted = max(float(rule.history_seconds), 1.0)
    first = _read_span(reader, rule, end=end, back=wanted, forward=0.0)
    if first.answered == 'refused':
        return first
    points, truncated, reads = list(first.points), first.truncated, first.reads
    if truncated and reads < MAX_READ_SPANS:
        retry: list[tuple[float, Any]] = []
        retry_truncated, retry_reads = False, 0
        for position in range(MAX_READ_SPANS):
            back = wanted * (MAX_READ_SPANS - position) / MAX_READ_SPANS
            forward = wanted * (MAX_READ_SPANS - position - 1) / MAX_READ_SPANS
            again = _read_span(reader, rule, end=end, back=back, forward=forward)
            if again.answered == 'refused':
                return again
            if len(retry) + len(again.points) > MAX_POINTS:
                # Composition is the case no page bound can see: every slice can sit inside the row bound
                # and the span can still hold more points than a `verdict` may be built over. It is
                # answered here, before the extend — allocating and sorting 3 600 points only to throw
                # them away would make the bound a cleanup step rather than the reason for the answer —
                # and it is answered as *incomplete*, not as a trimmed series graded complete: a tail
                # chosen by nothing but its length measures less history than the rule's own `for_seconds`
                # presumes. `tick` names the rule and files its coverage; the rules that fit go on.
                return SeriesRead([], 'ok', True, reads + retry_reads + again.reads, wanted)
            retry.extend(again.points)
            retry_truncated = retry_truncated or again.truncated
            retry_reads += again.reads
        points, truncated, reads = retry, retry_truncated, reads + retry_reads
    points.sort(key=lambda item: item[0])
    # An empty composition is an *answer* (nothing in the span) unless something said it was short, in
    # which case `tick` treats it as incomplete and not as absence either way.
    return SeriesRead(points, 'ok' if points else 'empty', truncated, reads, wanted)


def _read_span(reader: Any, rule: Judged, *, end: dt.datetime, back: float,
               forward: float) -> SeriesRead:
    """One bounded read of one sub-span, in the same shape `read_points` reports (so refusal travels)."""
    window = Window(start=utc_text(end - dt.timedelta(seconds=back)),
                    end=utc_text(end - dt.timedelta(seconds=forward)))
    outcome = reader.read(rule.query_type, window=window,
                          parameters={'resource_id': rule.resource_id, 'rule_id': rule.id},
                          selectors=_selectors(rule))
    if outcome.status not in ('available', 'unavailable'):
        return SeriesRead([], 'refused', False, 1, 0.0)
    if len(outcome.samples) > MAX_POINTS:
        # The facade caps a page at :data:`MAX_ROWS` (the same number), so an answer fatter than that is a
        # broken or substituted reader rather than a dense span. Nothing is kept: trimming the page to the
        # bound here would be the silent shortening `SeriesRead` exists to refuse, and the rows behind it
        # are not a series this module was ever allowed to hold.
        return SeriesRead([], 'refused', True, 1, 0.0)
    points: list[tuple[float, Any]] = []
    for row in outcome.samples:
        stamp = getattr(row, 'last_seen', None) or getattr(row, 'timestamp', None)
        if stamp is None:
            return SeriesRead([], 'refused', False, 1, 0.0)
        # A heartbeat row is one presence record with no value of its own: the fact is that it exists, so
        # the point carries a presence marker and only its instant is ever read.
        points.append((float(timestamp(stamp).timestamp()),
                       getattr(row, 'value', True) if hasattr(row, 'value') else True))
    return SeriesRead(points, 'ok' if outcome.status == 'available' else 'empty',
                      outcome.receipt.truncated, 1, back - forward)


def _selectors(rule: Judged) -> dict[str, str] | None:
    """Name the kind's own narrowing for one rule, or none.

    ``metric-threshold`` narrows by ``metric_name``; ``source-heartbeat`` narrows by ``dataset``, and a
    band/threshold rule's `metric` field is the only selector text either kind accepts here.
    """
    if rule.metric is None:
        return None
    return {'metric_name': rule.metric} if rule.query_type == 'metric-threshold' else {'dataset': rule.metric}


def grid_end(instant: dt.datetime, *, seconds: int) -> dt.datetime:
    """Floor an aware clock onto a UTC grid shared by reads and evaluation."""
    if not isinstance(instant, dt.datetime) or instant.tzinfo is None:
        raise StateError('Condition evaluation needs an aware clock')
    if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 1:
        raise StateError('Condition grid must be a whole number of seconds of at least one')
    return dt.datetime.fromtimestamp(int(instant.timestamp()) // seconds * seconds, dt.timezone.utc)


def cursor_binding(config: Mapping[str, Any]) -> str:
    """Digest everything the delivered verdicts of this document depend on, for the cursor to check."""
    return digest([[rule.mode, rule.id, rule.resource_id, rule.source, rule.version,
                    rule.query_type] for rule in config['rules']] + [config['interval_seconds']])


def load_cursor(path: Path | str, config: Mapping[str, Any]) -> dict[str, Any]:
    """Read this producer's cursor, refusing anything it cannot trust to deliver from.

    The refusals are the ones the sibling cursors already enforce (`configdrift.load_cursor`,
    `anomaly_cursor.load`): a document over the size bound, a foreign `schema_version`, a binding that
    is not the current configuration's (a rule was edited under a batch still owed — re-baselining
    silently would drop the verdict owed for the *old* rule), and a pending batch whose stored events
    are not canonical events any more. The last check reuses `state.validate_event` rather than
    restating the event schema, so a cursor cannot smuggle a hand-edited verdict into the platform.

    A file that does not exist yet is an empty document, not a refusal: the first round has nothing owed.
    """
    from .state import validate_event
    candidate = Path(path)
    if not candidate.exists():
        return {'schema_version': 1, 'binding': cursor_binding(config), 'pending': None, 'last_end': None}
    if candidate.stat().st_size > MAX_CURSOR_BYTES:
        raise StateError(f'Condition cursor exceeds {MAX_CURSOR_BYTES} bytes')
    document = read_document(candidate)
    if not isinstance(document, dict) or document.get('schema_version') != CURSOR_VERSION:
        raise StateError('Condition cursor schema version is unsupported')
    if set(document) - CURSOR_KEYS:
        raise StateError('Condition cursor holds unknown keys')
    if document.get('binding') != cursor_binding(config):
        raise StateError('Condition cursor belongs to a different rule set; reconcile it, never re-baseline')
    pending = document.get('pending')
    if pending is not None:
        if set(pending) != {'binding', 'end', 'events'} or pending['binding'] != document['binding']:
            raise StateError('Condition cursor pending batch is malformed')
        events = pending['events']
        if not isinstance(events, list) or not 1 <= len(events) <= MAX_RULES * 2:
            raise StateError('Condition cursor pending batch is not a bounded event list')
        for item in events:
            validate_event(item, timestamp(pending['end']))
    return document


def tick(index_path: Path | str, config: Mapping[str, Any], cursor_path: Path, reader: Any,
         deliver: Callable[[dict[str, Any]], None], *, now: dt.datetime,
         state: Mapping[str, Any]) -> dict[str, Any]:
    """Judge every rule of one document at one instant, deliver the batch, and advance only on success.

    The durability rule is `detection_worker.tick`'s and `configdrift.tick`'s: the window advances only
    after **every** event of the round was accepted, and a round that was refused keeps its events in the
    cursor and retries them before anything new is judged. A retry is safe because the platform's own
    identity folds it — identical bytes answer ``duplicate``, and a re-filed event for a condition whose
    incident is already open books no second delivery (`state.Store.intake`).

    Undelivered bytes are stored rather than re-derived: `detections.event` stamps ``expires_at`` from the
    window it was given, and a retry of a *re-judged* window is a different event with a shorter life.

    The cursor follows the document schedule; each rule reads and evaluates at its own
    cutoff, floored from that schedule. This excludes samples newer than the verdict.

    Args:
        index_path: The declared inventory index; every rule's resource must resolve in it, so a typo in
            a UUID refuses the round before any store read runs (`detections.evaluate`'s rule).
        config: The validated document from :func:`load_config`.
        cursor_path: Where this producer's own JSON cursor lives.
        reader: A `StoreClient` to read series through.
        deliver: Called once per event; must raise when the event was not accepted.
        now: The injected clock.
        state: The cursor document from :func:`load_cursor`. Required, because a verdict with nowhere to
            record what it owes is a verdict that can be lost: a configured producer with no cursor is
            refused upstream (`configdrift.main`'s rule), not run best-effort.

    One rule whose read is not a series it may judge is reported and not retried, not trimmed and not
    judged from a tail. There are two ways to get there and they are told apart. A read the store could
    not answer (or answered with a page no caller may hold) is ``refused``: the rule is named in ``rules``
    and ``refusals``, files nothing at all, and is the round's existing no-verdict policy unchanged. A read
    that arrived **incomplete** — the bounded reads did not cover the span, or the span was denser than
    this module may judge (see :func:`read_points`) — files one thing, and it is the rule's own `coverage`
    event, dated at that rule's cutoff like the verdict it withheld, naming the reason: "this round
    could not look" is a statement about the signal, and blindness is
    never silence. Neither shape files a verdict about the condition, so neither can recover one; an
    absence rule with an incomplete read does not assert absence. Either way the rest of the document is
    judged, delivered and acknowledged, and the cursor keeps the position it reached.

    Returns:
        The round summary: ``result``, the per-rule outcome words, and the counts. Every word in
        ``rules`` is one of `OUTCOMES` — `unreadable` covers both a read that was refused and a read that
        arrived incomplete, and the `detail` reason says which of the two it was — and a round that judged
        nothing is not reported as a healthy one.
    """
    binding = cursor_binding(config)
    pending = state.get('pending') if state.get('binding') == binding else None
    summary: dict[str, Any] = {'result': 'delivered', 'rules': {}, 'detail': {}, 'events': 0,
                              'refusals': 0, 'truncated': []}
    if pending:
        for item in pending['events']:
            deliver(item)
            summary['events'] += 1
        _save(cursor_path, {'schema_version': CURSOR_VERSION, 'binding': binding, 'pending': None,
                            'last_end': pending['end'], 'previous_end': state.get('last_end')})
        return {**summary, 'result': 'replayed'}
    with index.readonly(index_path) as connection:
        for entry in config['rules']:
            if index.resolve(connection, resource_id=entry.resource_id)['status'] != 'resolved':
                raise StateError('Condition resource is not declared')
    end = grid_end(now, seconds=config['interval_seconds'])
    if state.get('last_end') == utc_text(end):
        # Already delivered at this grid position: re-judging it would be a second opinion about the
        # same window, which is what the cursor exists to prevent (and what a lost cursor is honest about
        # losing — see platform/README.md).
        return {**summary, 'result': 'idle'}
    batch: list[dict[str, Any]] = []
    for entry in config['rules']:
        # Reads must stop at the evaluator's cutoff, which may precede the schedule.
        cutoff = grid_end(end, seconds=entry.evaluation_seconds)
        reading = read_points(reader, entry, end=cutoff)
        if reading.truncated:
            summary['truncated'].append(entry.id)   # named: this round is not looking at the whole span
        if reading.answered == 'refused':
            # The store could not answer, or answered with a page no caller may hold: a blind tick, named,
            # and every other rule in the document is judged, delivered and acknowledged as it was.
            summary['rules'][entry.id] = 'unreadable'
            summary['refusals'] += 1
            continue
        if reading.truncated:
            # Data arrived, but not the whole span, so there is no series here to judge — and no verdict,
            # only the coverage event that says so. Not for a threshold, not for a band, and not the
            # assertion of absence for an absence rule either. The instant it names is this rule's own
            # cutoff and not the document's schedule end: it is the window the withheld verdict would
            # have carried, so a round that could not look describes the same round it failed to judge.
            result = _incomplete_read(entry, cutoff, reading)
            summary['refusals'] += 1
        else:
            result = entry.judge(reading.points, now=cutoff)
            if isinstance(entry, Rule) and entry.mode == 'absence':
                # Complete input clears reader coverage independently of the signal's absence verdict.
                # Otherwise an incomplete absence read opens a companion incident that can never close.
                # The companion is aligned like every other event of this rule's round, at its cutoff.
                batch.append(coverage_event(entry, _aligned_window(entry, cutoff)[1], True))
        summary['rules'][entry.id] = result.outcome
        summary['detail'][entry.id] = dict(result.detail, read={
            'answered': reading.answered, 'truncated': reading.truncated, 'reads': reading.reads,
            'covered_seconds': reading.covered_s, 'points': len(reading.points)})
        batch.extend(result.events)
    if batch:
        _save(cursor_path, {'schema_version': CURSOR_VERSION, 'binding': binding,
                            'pending': {'binding': binding, 'end': utc_text(end), 'events': batch},
                            'last_end': state.get('last_end')})
        for item in batch:
            deliver(item)
            summary['events'] += 1
        _save(cursor_path, {'schema_version': CURSOR_VERSION, 'binding': binding, 'pending': None,
                            'last_end': utc_text(end), 'previous_end': state.get('last_end')})
    else:
        summary['result'] = 'idle'
    return summary


def _incomplete_read(rule: Judged, now: dt.datetime, reading: SeriesRead) -> Verdict:
    """The one answer an incomplete read earns: its coverage event, its reason, and nothing about the condition.

    Not `rule.judge(reading.points)`, and not for any of the three reasons a read can be short. The store
    keeps the **oldest** rows of a full page, so the tail a `for:` run and a freshness check are dated
    from is precisely what such a read is missing; grading it would print a verdict over a span chosen by
    nothing but where the page ended, which can hide a firing period outright and not merely delay one.
    A composition that overflowed :data:`MAX_POINTS` retained nothing on purpose. And for an absence rule
    the shortcut is worse than wrong: `judge([])` answers "no point in the read window" and files the
    absence the read was never able to state, so an incomplete round would open a condition whose own
    deadline nothing measured. The event filed is the companion ``<rule>.coverage`` one, so the rule's
    absence condition keeps whatever the last complete round said about it. Complete absence rounds
    also file a resolved companion coverage event, independently of whether the signal is absent.

    `slo.alerts._blind` and `dynamic_bands`' `insufficient` are the same decision with the same shape:
    inability to judge is named, is filed as coverage, and never reads as health. `unreadable` is the
    existing `OUTCOMES` word for it — no new verdict word arrives, and the detail names which of the three
    shortnesses this was so the round line says more than "no". The window is the one the withheld verdict
    would have carried (:func:`_aligned_window`), so an operator reads one window per rule per round
    either way.
    """
    window = _aligned_window(rule, now)[1]
    if not reading.points and reading.answered == 'ok':
        cause = (f'the {reading.covered_s:g}s span answered more points than this evaluator may judge '
                 f'({MAX_POINTS}), so none of it was retained')
    elif not reading.points:
        cause = f'the {reading.covered_s:g}s span came back short across {reading.reads} reads'
    else:
        cause = (f'only {len(reading.points)} points of the {reading.covered_s:g}s span arrived across '
                 f'{reading.reads} reads')
    return Verdict('unreadable', 'unjudged', None,
                   {'reason': f'incomplete read: {cause}, so nothing is judged',
                    'window': window, 'points': len(reading.points)},
                   [coverage_event(rule, window, False)])


def _save(cursor_path: Path, value: Mapping[str, Any]) -> None:
    """Write the cursor atomically, reusing `detection_worker.save` and its fsync discipline."""
    from .detection_worker import save
    save(Path(cursor_path), dict(value))

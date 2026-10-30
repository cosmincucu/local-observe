"""Planned maintenance: recurring schedules, the outcomes of windows, and what a report may claim.

`platform/suppression.py` owns the *window* — one bounded, attested, human-declared silence over one
resource or one rule, read on the delivery path. This module owns the three things a platform that plans
work in advance needs on top of it, and deliberately owns none of the enforcement:

* **schedules** — a recurring plan (`14:55 Europe/London on Tuesdays, 114 minutes, until 2026-12-22`) that
  materializes into ordinary windows. Each occurrence becomes its own `maintenance:<id>` control document
  through `suppression.declare_window`, so every bound ever argued about a window still holds: one day
  maximum, thirty-two live maximum, one human author, one append-only attestation each. A schedule is a
  *plan to declare*, not a timer that declares without a human; the human signed the rule, the occurrences
  inherit that signature, and the schedule version is attested the same way a window is.
* **condition classes** — what a window accounts for. `suppression.CONDITION_CLASSES` is the vocabulary and
  `suppression.condition_class` derives a finding's class from the canonical event alone; this module is
  where the operator chooses the list, which defaults to `EXPLAINED_BY_DEFAULT` (availability, restart,
  silence, freshness). Security findings, backup-integrity findings and the application's own failures are
  **not** explained by that default and page inside a planned outage. Naming one of them in a declaration
  is possible and is written into the attested text, so a reviewer can see a silence being widened.
* **outcomes and intervals** — what became of a window (`planned`, `active`, `completed`, `cancelled`,
  `unused`, `overrun`, or `unknown` where the evidence is not there) and the spans a report should show as
  quiet, with the declared span and the span the platform actually held quiet side by side and the window
  that produced each named.

Two roles sign planned work, and they are the two `state.OPERATOR_ROLES` names: the person on call
behind a `human` credential, and the automated operator behind an `operator-agent` one. Both may declare,
revise, cancel and roll forward a plan, and the version row stores which of them did — the effect of a
plan is not decided by who typed it, but a report that said "a human scheduled this" about an agent's act
would be a report that could not be trusted for anything else.

Two claims here are load-bearing, and both are refusals.

**Retroactive declarations are not supported** (`RETROACTIVE`). A window whose `starts_at` is already
behind the clock is refused at this door: suppression can only affect a page that has not gone out yet, so
a declaration typed afterwards cannot be what silenced anything, and a row that could be written after the
fact would let "what was planned around that outage?" be answered by editing the answer. The historical
reads (`intervals`, `window_at`) are the supported way to ask about the past: they report windows that
*were* declared in advance, and they say when they could not see far enough to answer. One narrow
exception exists and lives in `materialize_schedule`: carrying out a plan signed in advance for an
occurrence that has begun but not ended is not a new claim about the past. An occurrence that has already
ended is never materialized, because it could silence nothing.

**A search that hit its bound may not report absence.** `suppression.MAX_HISTORY_ROWS` bounds a read over
the window rows the live read never touches (expired and revoked ones), because a report question is about
exactly those rows. When the bound is hit, every window returned is real and verified, and the *absence* of
a window covering an instant means nothing: `complete` goes False and a classification answers `unknown`.
The failure mode that rule exists to block is "there were no windows, so this page was not planned work" —
an accusation against an operator, issued by a bounded query.

Why schedules are a typed table and windows are not (`state.py`'s v12 preamble carries the argument): a
window is a declaration that never changes, and a schedule is *edited*. An edit must make a new version
effective while leaving every version that was ever in force readable, and `notification_control` has no
shape for that — `control_declare` cannot express an edit and `control_write` destroys the history an
operator is entitled to ask back. So: `maintenance_schedules(schedule_id, version)` with `UPDATE` and
`DELETE` refused by triggers, and one append-only `maintenance.schedule_declared` audit row per version,
quoted byte for byte the way a window quotes its `maintenance.declared` row.
"""
import contextlib
import datetime as dt
import json
import re
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from local_observe.inventory.index import dependents, readonly as readonly_index
from local_observe.inventory.validation import InvalidInventory, canonical, timestamp, utc_text
from local_observe.log import get_logger
from . import suppression
from .state import (MAINTENANCE_ATTRIBUTION_WINDOW, MAINTENANCE_SCHEDULE_TABLE,
                    MAINTENANCE_SCHEDULE_VERSION_LIMIT, MAINTENANCE_SUPPRESSED_OPERATION, OPERATOR_ROLE_SCHEDULES,
                    OPERATOR_ROLES, Actor, StateError, Store, clock, control_write, identifier, label, require,
                    stored_role)

log = get_logger(__name__)

#: The one audit operation this module adds. Every schedule *version* takes a row — an edit and a
#: cancellation are both new versions — so the log names each version a human signed rather than the plan
#: as a whole.
SCHEDULE_OPERATION = 'maintenance.schedule_declared'
#: The roll-forward, audited as its own operation: "who asked for the next eight occurrences?" is a
#: different question from "who signed this plan?" and gets a different answer.
MATERIALIZATION_OPERATION = 'maintenance.schedule_materialized'

# --- the closed vocabularies -----------------------------------------------------------------
#: What a window or a schedule may be *about*. `resource` and `rule` map onto the two selectors
#: `suppression` can match at the delivery path; `service` cannot, and is expanded into its members when
#: the plan is signed instead (see `resolve_scope`), because consulting a built index on the path that
#: decides whether to page would make a stale graph a reason to stay quiet.
SCOPE_KINDS = ('resource', 'service', 'rule')
#: The recurrence shapes this build can say out loud. Anything richer (monthly, "last business day", a
#: cron expression) is a *calendar*, and its DST semantics are not derivable from a string.
FREQUENCIES = ('daily', 'weekly')
#: How a local wall-clock time is honoured across a transition. `wall` keeps the clock the operator typed
#: (a spring-forward 02:30 lands just after the shift); `fixed` keeps the UTC offset the first occurrence
#: established, so the local time drifts, which is what a shift that must never overlap itself wants;
#: `skip` drops an occurrence whose local time does not exist. Chosen per schedule rather than defaulted:
#: a silent choice is how a twice-yearly surprise arrives.
DST_POLICIES = ('wall', 'fixed', 'skip')
#: The two finite bounds. There is no third: an open-ended recurrence is a permanent silence wearing a
#: schedule's clothes, and `suppression.declare_window` refuses an open-ended *window* for the same reason.
BOUND_KEYS = ('first_occurrence', 'occurrences', 'until')
#: What a stored schedule version holds. An extra or missing key is not a version this build wrote.
SCHEDULE_KEYS = ('id', 'version', 'state', 'reason', 'scope', 'explains', 'recurrence', 'bounds',
                 'author', 'declared_at')
#: The fields a schedule declaration may name. `version`, `state` and `author` are this module's to decide,
#: which is why they are not in the request vocabulary at all.
REQUEST_KEYS = ('reason', 'scope', 'recurrence', 'bounds', 'explains')
#: The fields a window declaration may name, and the only ones it accepts: a key nobody reads is a promise
#: nobody keeps, so the transport refuses the request instead of tolerating the field.
WINDOW_REQUEST_KEYS = ('reason', 'scope', 'starts_at', 'ends_at', 'explains')
SCOPE_KEYS = ('kind', 'id')
RECURRENCE_KEYS = ('frequency', 'interval', 'days_of_week', 'time_of_day', 'duration_seconds',
                   'timezone', 'dst')
#: The schedule states. `cancelled` is a *version*, never a rewrite: the version that was in force while
#: the plan ran stays in the table and stays readable.
SCHEDULE_STATES = ('active', 'cancelled')

# --- the bounds ------------------------------------------------------------------------------
#: Occurrences one schedule may bound itself to. With `MAX_WINDOW_SECONDS` this makes a plan finite in
#: both directions: 400 daily occurrences is a year and a change of mind, not an indefinite silence.
MAX_OCCURRENCE_BOUND = 400
#: Occurrences one materialization pass may turn into windows. Eight is a month of weekly work and well
#: under `suppression.MAX_LIVE_WINDOWS`, so one pass cannot take the platform's whole window budget and
#: starve an emergency declaration.
MAX_MATERIALIZED_OCCURRENCES = 8
#: How far ahead of the clock materialization may reach. Past it a plan is still a plan — it simply is not
#: yet a set of silences — and a schedule nobody rolls forward stops suppressing rather than suppressing
#: forever.
MAX_HORIZON_SECONDS = 35 * 86400
#: The largest member set a service-scoped declaration may expand to. Above it the operator declares the
#: members, because the alternative is a plan that quietly consumes every live-window slot in the platform.
#: Bounded below `suppression.MAX_LIVE_WINDOWS` so one service cannot be why an unrelated emergency
#: window is refused.
MAX_SERVICE_MEMBERS = 16
#: The shortest occurrence worth planning. A silence measured in seconds suppresses nothing that takes a
#: human to notice, and a zero-length window is a way of asking for a page that arrives anyway.
MIN_OCCURRENCE_SECONDS = 60
#: How many schedule rows one read walks. Rows accumulate per *version*, so this bounds edits-and-plans
#: rather than plans alone.
MAX_SCHEDULE_ROWS = 256
#: How many attributed suppression rows one window's history may name.
MAX_EVIDENCE_ROWS = 128
#: How many interval rows one query may return, and so how many outcome reads it may cost.
MAX_INTERVAL_ROWS = 100
#: The widest span one interval query may ask about. Without a bound the honest answer would be
#: `bound_exceeded` almost always; with one, the caller can narrow the question and get a complete answer.
MAX_QUERY_SPAN_SECONDS = 92 * 86400

#: Sentence fragments meaning "this collides with state you could not see from here", which is the
#: transport's 409 rather than a 400 about the caller's body. Matched on wording rather than on exception
#: class for the same reason `api.stable_code` matches wording: the sentence is written where the fact is
#: known, and a refusal whose text says *the plan is already cancelled* is not a malformed request. An
#: identical re-declaration is not in this list at all — it answers 200 with `status: duplicate`, because
#: replaying a signed act is the idempotency boundary's job, not a conflict to be reported.
CONFLICT = ('already cancelled', 'already revoked', 'already declared and says something else',
            'cancelled maintenance schedule',
            'live maintenance windows', 'exceed the read bound')

#: One line of provenance, and the ceiling the durable window row applies to it. Read off `suppression`
#: instead of restated: a door that refused reasons at 512 characters while the row stored 200 would let a
#: declaration through the API that the control writer then refused, and a number like this drifts exactly
#: as often as nobody looks.
REASON_LIMIT = suppression.MAX_REASON_CHARS
#: The namespace every occurrence id is minted under. One constant, so an occurrence id computed today
#: equals the one recomputed after a restore.
SCHEDULE_NAMESPACE = uuid.UUID('f0c7a4a4-8d3f-5a1b-9e2c-4d6b1a7f3e05')
#: The stance every historical read publishes: this product has no retroactive door, so every window a span
#: answer lists was signed before it began. A constant rather than an omission, because "no plan was found"
#: and "no plan could have been declared here" are different claims and a reader cannot tell them apart
#: from an absent field.
RETROACTIVE = False

#: The refusal every retroactive attempt reaches, quoted so this file and `docs/api/maintenance.md` cannot
#: disagree about what the platform says.
RETROACTIVE = False
RETROACTIVE_REFUSAL = ('A maintenance window cannot begin in the past; planned work is declared in'
                       ' advance, and what was planned around a past instant is a question for'
                       ' /v1/maintenance-intervals')
#: The fixed sentence a bounded search gives when it cannot see far enough to report absence.
INCOMPLETE_SEARCH = 'The window history exceeded this build\'s read bound; absence cannot be reported'

TIME_PATTERN = re.compile(r'^([01][0-9]|2[0-3]):[0-5][0-9]$')
DATE_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}$')

#: The outcome vocabulary, in the order a reader meets it. Definitions are in `window_outcome`.
OUTCOMES = ('planned', 'active', 'completed', 'cancelled', 'unused', 'overrun', 'unknown')
#: What an event-time lookup may answer. `outside` is a *claim*, made only when the search was complete;
#: `unknown` is what a bound or missing evidence says.
CLASSIFICATIONS = ('planned', 'outside', 'unknown')


@contextmanager
def readonly(store: Store) -> Iterator[sqlite3.Connection]:
    """Open the store's file read-only, so a report costs the writer nothing.

    `platform/suppression.py`'s private helper is the precedent, and `verification_reader.py` and
    `escalation_reader.py` each hold their own for the same reason: asking a question must not take the
    ``BEGIN IMMEDIATE`` write slot. Every read in this module is a report read — outcomes, intervals,
    schedules — and none of them may queue behind a delivery.
    """
    with closing(sqlite3.connect(store.path.resolve().as_uri() + '?mode=ro', uri=True,
                                 timeout=10)) as db:
        db.row_factory = sqlite3.Row
        yield db


# --- the schedule document -------------------------------------------------------------------

def _zone(name: Any) -> ZoneInfo:
    """Return the named IANA zone, refusing anything else.

    An offset (`+01:00`) is refused rather than accepted: an offset has no transitions, so the DST policy
    the operator is being made to choose would be a no-op, and a plan that drifts an hour twice a year
    while claiming not to is worse than a refusal. `zoneinfo` is the standard library's copy of the IANA
    database — no new dependency, and the names are the host's, not this file's. On a host without
    `tzdata` every name reaches this refusal, which is the loud direction: a schedule that silently loses
    its zone would be a schedule that materializes at the wrong hour twice a year.
    """
    if not isinstance(name, str) or not 1 <= len(name) <= 64:
        raise StateError('A maintenance schedule needs an IANA timezone name')
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise StateError(f'Unknown IANA timezone: {name}') from None


def _local_date(value: Any, field: str) -> dt.date:
    """Return one calendar date from the `YYYY-MM-DD` text a schedule bound is written in."""
    if not isinstance(value, str) or not DATE_PATTERN.match(value):
        raise StateError(f'{field} must be a calendar date (YYYY-MM-DD)')
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        raise StateError(f'{field} is not a real date') from None


def _time_of_day(value: Any) -> dt.time:
    """Return one wall-clock minute, refusing anything a duty roster could not have typed."""
    if not isinstance(value, str) or not TIME_PATTERN.match(value):
        raise StateError('A maintenance schedule needs a time of day as HH:MM')
    return dt.time(int(value[:2]), int(value[3:5]))


def _weekday(value: Any) -> int:
    """Return one ISO weekday (Monday is 0), rejecting a boolean the way `suppression._bound` does."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 6:
        raise StateError('A weekly maintenance schedule names days_of_week as 0..6 (Monday is 0)')
    return value


def _instant(value: Any) -> dt.datetime:
    """Return one aware UTC instant, converting the inventory module's refusal into this one's."""
    if not isinstance(value, str):
        raise StateError('A maintenance window needs timezone-aware ISO timestamps')
    try:
        return timestamp(value)
    except InvalidInventory:
        raise StateError('A maintenance window needs timezone-aware ISO timestamps') from None


def _limit(name: str, value: Any, low: int, high: int) -> int:
    """Return `value` inside ``[low, high]`` as an int, refusing rather than clamping."""
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise StateError(f'{name} must be {low}..{high}')
    return value


def transition(naive: dt.datetime, zone: ZoneInfo) -> str:
    """Name what one local wall-clock minute is inside a zone: ``normal``, ``gap`` or ``fold``.

    The test is a round trip through UTC, not an offset comparison and not `astimezone` on the naive value:
    CPython returns a datetime whose tzinfo already *is* the target zone unchanged, so an imaginary minute
    would round-trip to itself and read as ordinary. Mapping both fold values to instants and asking what
    the zone calls those instants is the question with the right answers — a spring-forward minute maps to
    an instant the zone never shows at that wall clock (``gap``: London's 01:30 on 2026-03-29 is 02:30 BST
    when you arrive), and an autumn minute maps to two instants the zone both calls that minute (``fold``:
    London's 01:30 on 2026-10-25 comes twice). Naming them is the point of `dst`: the operator chooses
    between them per schedule, in the declaration, and a plan whose DST behaviour is unstated is a plan
    whose second occurrence is a surprise.
    """
    first = naive.replace(tzinfo=zone, fold=0).astimezone(dt.timezone.utc)
    second = naive.replace(tzinfo=zone, fold=1).astimezone(dt.timezone.utc)
    if first == second:
        return 'normal'
    return 'fold' if first.astimezone(zone).replace(tzinfo=None) == naive else 'gap'


def occurrence_start(ordinal: int, base: dt.date, moment: dt.time, zone: ZoneInfo, *, frequency: str,
                     interval: int, days_of_week: Sequence[int], dst: str,
                     anchor: dt.timedelta | None) -> tuple[dt.datetime, str] | None:
    """Return the *ordinal*-th occurrence's start instant and what the clock did to it.

    Occurrences are anchored to the wall clock on the calendar (`base + n*interval` days for daily;
    `days_of_week` inside every `interval`-th week for weekly), so a transition night yields one
    occurrence, not two and not none. Returns None when `dst` is ``skip`` and this occurrence's local time
    does not exist: that is a deliberate loss — moving it forward would put the same work next to the
    following week's, and the brief's "explicit DST handling" means the operator chose that trade, not that
    the platform invented one.
    """
    if frequency == 'weekly':
        day = _weekly_day(base, ordinal, interval, days_of_week)
    else:
        day = base + dt.timedelta(days=ordinal * interval)
    naive = dt.datetime.combine(day, moment)
    state = transition(naive, zone)
    if state == 'gap' and dst == 'skip':
        return None
    if dst == 'fixed' and anchor is not None:
        # The offset the first occurrence established, applied to the wall clock: the instant is what stays
        # a constant distance from the plan's anchor, and the local hour is allowed to move.
        return (naive.replace(tzinfo=dt.timezone.utc) - anchor).astimezone(dt.timezone.utc), \
            'offset-preserved'
    return naive.replace(tzinfo=zone, fold=0).astimezone(dt.timezone.utc), state


def _weekly_day(base: dt.date, ordinal: int, interval: int, days_of_week: Sequence[int]) -> dt.date:
    """Return the ``ordinal``-th weekly occurrence's calendar date.

    `base`'s ISO week is week 0 and `days_of_week` are the candidate days inside it, so `interval` means
    "every N weeks" rather than "every N*7 days from the last occurrence". A plan with two days a week has
    to count weeks, not gaps, or the second day of every week drifts one day per occurrence.
    """
    days = sorted(days_of_week) or [base.weekday()]
    week, position = divmod(ordinal, len(days))
    monday = base - dt.timedelta(days=base.weekday())
    return monday + dt.timedelta(weeks=week * interval, days=days[position])


def occurrences(schedule: dict[str, Any], *, now: dt.datetime,
                after: dt.datetime | None = None) -> dict[str, Any]:
    """Return this schedule's next bounded slice of occurrences, with the clock's behaviour named each.

    Occurrence identity is ``(schedule id, version, ordinal, instant)`` and the ordinal is computed from
    the calendar rather than stored: the same version always materializes the same instants with the same
    ids, which is what lets a roll-forward that died half way re-run and answer `duplicate`, and what lets
    a restored file materialize exactly what the copy would have.

    Args:
        schedule: One validated schedule document.
        now: The clock the horizon and the `started`/`past` flags are judged against.
        after: Materialization must not reach back behind this instant (the stored horizon), so a
            roll-forward asks only for what has not been declared yet.

    Returns:
        ``{'occurrences': [{'index', 'occurrence_id', 'starts_at', 'ends_at', 'dst', 'started', 'past'}],
        'generated': int, 'bounded': bool, 'skipped': int, 'dropped': [...], 'horizon': str}`` — `bounded` says the
        occurrence bound stopped the walk, `skipped` counts gap-dropped occurrences, `horizon` is the
        instant the returned slice reaches through.
    """
    recurrence, bounds = schedule['recurrence'], schedule['bounds']
    zone = _zone(recurrence['timezone'])
    moment = _time_of_day(recurrence['time_of_day'])
    base = _local_date(bounds['first_occurrence'], 'first_occurrence')
    duration = recurrence['duration_seconds']
    count = bounds.get('occurrences')
    until = _local_date(bounds['until'], 'until') if 'until' in bounds else None
    floor = after if after is not None else now
    anchor: dt.timedelta | None = None
    dropped: list[dict[str, Any]] = []
    found: list[dict[str, Any]] = []
    horizon = now
    ordinal = reached = emitted = skipped = 0
    while ordinal < MAX_OCCURRENCE_BOUND and emitted < MAX_MATERIALIZED_OCCURRENCES:
        step = occurrence_start(ordinal, base, moment, zone, frequency=recurrence['frequency'],
                                interval=recurrence['interval'], days_of_week=recurrence['days_of_week'],
                                dst=recurrence['dst'], anchor=anchor)
        ordinal += 1
        if step is None:
            # Counted, and named: an operator reading "3 occurrences, 1 skipped" is entitled to know *which*
            # minute vanished, because the answer to "why was nothing quiet on 29 March?" cannot be a number.
            # `ordinal` has already moved past this occurrence, and the calendar is walked the way
            # `occurrence_start` walks it, so the date reported is the date that was lost.
            lost = (base + dt.timedelta(days=(ordinal - 1) * recurrence['interval'])
                    if recurrence['frequency'] != 'weekly'
                    else _weekly_day(base, ordinal - 1, recurrence['interval'],
                                     recurrence['days_of_week']))
            dropped.append({'index': reached + 1, 'local': lost.isoformat(),
                            'time_of_day': recurrence['time_of_day'], 'timezone': zone.key,
                            'reason': 'the local minute does not exist in this zone, and the plan says skip'})
            skipped += 1
            continue
        start, clock_state = step
        if anchor is None:
            anchor = start.astimezone(zone).utcoffset()
        if until is not None and start.astimezone(zone).date() > until:
            break
        if start > now + dt.timedelta(seconds=MAX_HORIZON_SECONDS):
            break
        reached += 1
        if start + dt.timedelta(seconds=duration) > floor:
            emitted += 1
            horizon = max(horizon, start + dt.timedelta(seconds=duration))
            found.append({'index': reached, 'occurrence_id': occurrence_id(schedule['id'],
                                                                           schedule['version'],
                                                                           reached, start),
                          'starts_at': utc_text(start),
                          'ends_at': utc_text(start + dt.timedelta(seconds=duration)),
                          'dst': clock_state, 'started': start <= now,
                          'past': start + dt.timedelta(seconds=duration) <= now})
        if count is not None and reached >= count:
            break
    return {'occurrences': found, 'generated': reached,
            'bounded': count is not None and reached >= count, 'skipped': skipped,
            'dropped': dropped,
            'horizon': utc_text(horizon)}


def occurrence_id(schedule_id: str, version: int, index: int, start: dt.datetime) -> str:
    """Return one occurrence's stable id: `(plan, version, ordinal, instant)`, digested.

    Not random, and that is the property. Materializing the same occurrence twice is the same window id
    reaching `declare_window`, which answers `duplicate` and writes nothing — so a half-finished
    roll-forward, a second operator rolling the same plan, and a restored file all converge on one row per
    occurrence. Including the instant means an edit that moved the time cannot collide with the occurrence
    it replaced, which is what keeps the earlier window reachable and revocable.
    """
    return str(uuid.uuid5(SCHEDULE_NAMESPACE, canonical([schedule_id, version, index, utc_text(start)])))


def schedule_id(reason: str, scope: dict[str, Any], author: str, recurrence: dict[str, Any],
                bounds: dict[str, Any]) -> str:
    """Return a new schedule's id, derived from the plan rather than minted at random.

    A random id would make a retried declaration — the caller that lost the response, the client whose
    idempotency key never arrived — a *second* plan with a second set of windows. Digesting the request
    means the retry collides on the primary key and is answered `duplicate`, which is the same argument
    `suppression.window_id` makes for a window, with one difference stated in `declare_schedule`: the
    *content* stays addressable while the *versions* of one plan are numbered, because a plan is edited and
    a content address would turn every edit into a new plan.

    The digest covers the recurrence and the bound, not only the reason. `Firmware, Mondays, by operator` is
    two different plans if one says 03:30 and the other 04:30 — or, as `tests/test_maintenance_api.py`
    checks, if one says `skip` across the spring-forward gap and the other says `wall`. Iding on the reason
    alone would answer the second declaration `duplicate`, store the first document, and then declare the
    second plan's windows: a table that describes one plan and a set of silences belonging to another.
    """
    return str(uuid.uuid5(SCHEDULE_NAMESPACE, canonical(['schedule', reason, scope, author, recurrence,
                                                        bounds])))


# --- the two validators a document and a row share ----------------------------------------------

def _recurrence(value: Any) -> dict[str, Any]:
    """Return a validated recurrence block, refusing a calendar this build cannot speak.

    `daily` and `weekly` with an interval and a weekday set are the whole vocabulary here, and the reason
    for stopping there is `dst`: a cron expression or a "last business day" rule has DST semantics nobody
    can derive from a string, and a platform that guesses them would move a silence by an hour twice a
    year without anybody deciding to.

    `days_of_week` is Monday-0 and is *required* for a weekly plan and *forbidden* for a daily one. A daily
    plan carrying `[1, 4]` is one of the two meanings, and the platform does not get to pick.
    """
    if not isinstance(value, dict) or set(value) != set(RECURRENCE_KEYS):
        raise StateError('Maintenance recurrence must name ' + ', '.join(RECURRENCE_KEYS))
    frequency = value['frequency']
    if frequency not in FREQUENCIES:
        raise StateError(f'Maintenance recurrence frequency must be one of {", ".join(FREQUENCIES)}')
    interval = _limit('interval', value['interval'], 1, MAX_OCCURRENCE_BOUND)
    days = value['days_of_week']
    if not isinstance(days, (list, tuple)):
        raise StateError('Maintenance recurrence days_of_week must be a list of weekdays (Monday is 0)')
    days = sorted({_weekday(day) for day in days})
    if len(days) != len(value['days_of_week']):
        raise StateError('Maintenance recurrence days_of_week repeats a weekday')
    if frequency == 'daily' and days:
        raise StateError('A daily maintenance recurrence names no days_of_week; every day is every day')
    if frequency == 'weekly' and not days:
        raise StateError('A weekly maintenance recurrence names at least one day_of_week')
    duration = _limit('duration_seconds', value['duration_seconds'], MIN_OCCURRENCE_SECONDS,
                      suppression.MAX_WINDOW_SECONDS)
    return {'frequency': frequency, 'interval': interval, 'days_of_week': days,
            # Normalized back to the two-figure text: `occurrences` and `_first_instant` re-read this
            # field through `_time_of_day`, and a document that stored a `datetime.time` would fail its own
            # next read. Canonical text is also what the audit digest is taken over.
            'time_of_day': _time_of_day(value['time_of_day']).strftime('%H:%M'),
            'duration_seconds': duration, 'timezone': _zone(value['timezone']).key, 'dst': _dst(value['dst'])}


def _dst(value: Any) -> str:
    """Return one DST policy, refusing a plan that left the transition to chance."""
    if value not in DST_POLICIES:
        raise StateError(f'Maintenance dst must be one of {", ".join(DST_POLICIES)};'
                         ' an unstated transition is a silence that moves twice a year')
    return str(value)


def _bounds(value: Any) -> dict[str, Any]:
    """Return a finite occurrence bound, refusing an open-ended plan.

    `first_occurrence` plus exactly one of `occurrences` or `until`. "Exactly one" is the whole point: a
    plan bounded both ways is a contradiction waiting for the shorter of the two, and a plan bounded
    neither way is a permanent silence with a start date. `suppression.declare_window` refuses an
    open-ended *window* for the same reason; this is that rule applied to the thing that generates windows,
    where it matters more, because one bad line here is a hundred silences.

    `until` is inclusive: the last occurrence that *starts* on that local date is still in the plan. An
    exclusive end would make "until Friday" mean "not on Friday", which is not what anyone means.
    """
    if not isinstance(value, dict):
        raise StateError('Maintenance bounds must name first_occurrence and one of occurrences or until')
    unknown = set(value) - set(BOUND_KEYS)
    if unknown:
        raise StateError('Unknown maintenance bound: ' + ', '.join(sorted(unknown)))
    first = _local_date(value.get('first_occurrence'), 'first_occurrence')
    rest = set(value) - {'first_occurrence'}
    if rest != {'occurrences'} and rest != {'until'}:
        raise StateError('A maintenance schedule bound is occurrences or until, never both and never'
                         ' neither: open-ended silence is not maintenance')
    bounds: dict[str, Any] = {'first_occurrence': first.isoformat()}
    if 'occurrences' in value:
        bounds['occurrences'] = _limit('occurrences', value['occurrences'], 1, MAX_OCCURRENCE_BOUND)
    else:
        until = _local_date(value['until'], 'until')
        if until < first:
            raise StateError('A maintenance schedule until must be its first_occurrence or later')
        bounds['until'] = until.isoformat()
    return bounds


def _document(document: Any, *, stored: bool = False) -> dict[str, Any] | None:
    """Return a validated schedule version, or None on the read path when a row cannot be validated.

    One function answers both questions on purpose. The write path must refuse a request that names
    something this build cannot store; the read path must refuse to *apply* a row it cannot re-validate
    while still reporting that the row exists — a schedule that vanishes from a list because its document
    grew a field is a schedule nobody cancelled. Same rules, two verbs: raise, or answer None.

    A validated document is exactly `SCHEDULE_KEYS`, with the recurrence and bounds normalized. That
    canonical form is what gets digested into the duplicate key and what the audit row quotes, so two
    spellings of one plan cannot become two plans with two sets of windows.
    """
    def refuse(message: str) -> dict[str, Any] | None:
        if stored:
            return None
        raise StateError(message)
    if not isinstance(document, dict) or set(document) != set(SCHEDULE_KEYS):
        missing = set(SCHEDULE_KEYS) - set(document or {})
        return refuse('Maintenance schedule version must name '
                      + (', '.join(sorted(missing)) if stored or missing else 'exactly '
                         + ', '.join(SCHEDULE_KEYS)))
    try:
        identifier(document['id'])
        version = _limit('version', document['version'], 1, MAINTENANCE_SCHEDULE_VERSION_LIMIT)
        if document['state'] not in SCHEDULE_STATES:
            raise StateError(f'Maintenance schedule state must be one of {", ".join(SCHEDULE_STATES)}')
        reason = _text(document['reason'], 'reason', REASON_LIMIT)
        scope = _scope_shape(document['scope'])
        explains = explain_list(document['explains'])
        author = _text(document['author'], 'author', 200)
        declared_at = _instant(document['declared_at'])
        recurrence = _recurrence(document['recurrence'])
        bounds = _bounds(document['bounds'])
    except (StateError, InvalidInventory, ValueError, TypeError):
        if not stored:
            raise
        return None
    return {'id': document['id'], 'version': version, 'state': document['state'], 'reason': reason,
            'scope': scope, 'explains': explains, 'recurrence': recurrence, 'bounds': bounds,
            'author': author, 'declared_at': utc_text(declared_at)}


def _read_row(row: Any) -> dict[str, Any] | None:
    """Return one stored schedule version, with the row's own columns winning over the document.

    `version`, `state` and `horizon` exist twice — inside the signed document and as columns the reads
    filter and sort on — and they cannot disagree while this module writes them. On the read path the
    columns are the answer, because they are what the query that found this row was actually asking about;
    the document is what the human signed. A row whose document cannot be re-validated answers None, which
    every caller reports as `unreadable` rather than skipping.
    """
    try:
        document = json.loads(row['document'])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    validated = _document(document, stored=True)
    if validated is None:
        return None
    return dict(validated, id=row['schedule_id'], version=int(row['version']), state=row['state'],
                horizon=str(row['horizon']), declared_at=row['declared_at'],
                declared_by=row['declared_by'],
                # The column, read through `state.stored_role` so a version written before schema v15 — when
                # `human` was the only role that could sign a plan — reads as that role and not as an absence.
                declared_by_role=stored_role(row, OPERATOR_ROLE_SCHEDULES), attest=int(row['attest']))


def _attested(connection: sqlite3.Connection, document: dict[str, Any], attest: int) -> bool:
    """Whether the audit row this version points at exists, names this version, and says a human signed it.

    The same test `suppression._attested` applies to a window, over the same table, including the
    comparison against the whole signed document: `audit` carries the append-only UPDATE and DELETE
    triggers, so a version that cannot point at its own log entry — naming its id, its author and its
    exact fields — is a version nobody signed. A document whose reason or bound moved after the fact is not
    the document that was approved, and this lookup says so rather than a reader's opinion.
    """
    if attest <= 0:
        return False
    signed = {field: document[field] for field in SCHEDULE_KEYS}
    return connection.execute(f'SELECT 1 FROM audit WHERE sequence=?'
                              f" AND operation='{SCHEDULE_OPERATION}' AND subject=? AND detail=?",
                              (attest, document['id'], canonical(signed))).fetchone() is not None


# --- scope -----------------------------------------------------------------------------------
def _scope_shape(scope: Any) -> dict[str, Any]:
    """Return a validated ``{kind, id}`` scope, refusing a selector that could reach past its kind."""
    if not isinstance(scope, dict) or not set(SCOPE_KEYS) <= set(scope) \
            or not set(scope) <= set(SCOPE_KEYS):
        raise StateError('Maintenance scope must be a kind and an id')
    kind = scope['kind']
    if kind not in SCOPE_KINDS:
        raise StateError(f'Maintenance scope kind must be one of {", ".join(SCOPE_KINDS)}')
    target = _text(scope['id'], 'scope id', REASON_LIMIT)
    if kind == 'rule':
        label(target)
    else:
        identifier(target)
    return {'kind': kind, 'id': target}


def resolve_scope(store: Store, scope: dict[str, Any], *,
                  index_path: Path | str | None = None) -> dict[str, Any]:
    """Return the resources and rules a scope actually covers, refusing to guess a member set.

    `resource` and `rule` are what they say and need nothing. `service` cannot be matched at the delivery
    path — a canonical event names a resource and a rule, never a service — so a service plan is expanded
    *here*, against the built inventory index, into the members `index.dependents` walks (everything the
    shipped relation vocabulary says runs on or depends on the service, plus the service itself). That is a
    snapshot taken when the plan was signed, and it is the honest shape: the alternative is a silence whose
    extent changes whenever somebody re-runs a discovery job, which is a window nobody declared.

    Refusals, all of them loud: no built index configured; an unknown service id; a walk the index itself
    reports as truncated (a partial member set would page half the estate and call it covered); and more
    members than `MAX_SERVICE_MEMBERS`, which is a plan for the operator to split.
    """
    if not isinstance(scope, dict) or set(scope) != set(SCOPE_KEYS):
        raise StateError('A maintenance scope names one kind and one id')
    kind, target = scope['kind'], _scope_shape(scope)['id']
    if kind not in SCOPE_KINDS:
        raise StateError(f'Unknown maintenance scope: {kind}')
    if kind == 'rule':
        label(target)
        return {'kind': kind, 'id': target, 'selectors': [{'resource_id': None, 'rule_id': target}],
                'members': [], 'resolved_from': 'declaration', 'bound_exceeded': False}
    identifier(target)
    if kind == 'resource':
        return {'kind': kind, 'id': target, 'selectors': [{'resource_id': target, 'rule_id': None}],
                'members': [target], 'resolved_from': 'declaration', 'bound_exceeded': False}
    if index_path is None:
        raise StateError('A service-scoped maintenance plan needs a built inventory index;'
                         ' its members are a fact about the estate and are never guessed')
    with readonly_index(index_path) as connection:
        if not connection.execute('SELECT 1 FROM resources WHERE id=?', (target,)).fetchone():
            raise StateError('Maintenance scope names a resource this inventory does not hold')
        # Ask the index for one less than the bound and check the total here, so an oversized plan is
        # refused with *this* module's sentence (which names the bound and the remedy) instead of the
        # index's `limit must be 1..1000`. The clamp is what keeps a small bound honest rather than illegal.
        walk = dependents(connection, target, limit=max(1, min(MAX_SERVICE_MEMBERS - 1, 999)))
    members = [target] + [row['id'] for row in walk['resources']]
    if walk['truncated'] or len(members) > MAX_SERVICE_MEMBERS:
        raise StateError(f'A service maintenance scope covers at most {MAX_SERVICE_MEMBERS} resources;'
                         ' declare the members or narrow the service')
    return {'kind': kind, 'id': target,
            'selectors': [{'resource_id': member, 'rule_id': None} for member in members],
            'members': members, 'resolved_from': 'inventory-index',
            'bound_exceeded': bool(getattr(index_path, 'truncated', False))}


def explain_list(value: Any) -> list[str]:
    """Return the condition classes one declaration covers, defaulting to the explained four.

    An absent `explains` is the default, not a wildcard: a window declared over a resource says
    "planned work is happening here", and the four classes planned work does cause are what it gets. To
    also silence `security` or `backup-integrity` a caller must write that down, in the declaration, where
    a reviewer can see a human widened a silence. `unclassified` is nameable for the same reason — a rule
    nobody has labelled yet is a rule somebody is about to write a window around.

    A window that names nothing at all is a v1 window and is class-blind; this function is not how a new
    row gets there.
    """
    if value is None:
        return list(suppression.EXPLAINED_BY_DEFAULT)
    if not isinstance(value, (list, tuple)) or not value:
        raise StateError('Maintenance explains must be a non-empty list of condition classes')
    unknown = sorted({item for item in value if item not in suppression.CONDITION_CLASSES})
    if unknown:
        raise StateError(f'Unknown maintenance condition class: {", ".join(unknown)}')
    duplicated = sorted({item for item in value if list(value).count(item) > 1})
    if duplicated:
        raise StateError(f'Maintenance explains repeats a condition class: {", ".join(duplicated)}')
    return sorted(value)


def _text(value: Any, field: str, maximum: int, *, required: bool = True) -> str | None:
    """Return one bounded single-line field, or refuse it: the rules the durable window applies.

    `required=False` answers None for an absent field, which is how an optional field stays optional
    through a PATCH body that names only what it changes.
    """
    if value is None:
        if required:
            raise StateError(f'Maintenance {field} is required')
        return None
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > maximum:
        raise StateError(f'Maintenance {field} must be trimmed text of at most {maximum} characters')
    if not suppression.REASON_PATTERN.match(value):
        raise StateError(f'Maintenance {field} must be one line of printable text')
    return value


def cancel_window(store: Store, window: str, actor: Actor, *,
                  now: dt.datetime | None = None) -> dict[str, Any]:
    """Cancel one named window, and answer with what stopped being suppressed.

    A cancellation is an act, not a note: the durable revoke adds `revoked_by` and `revoked_at`, has no
    free-text field, and this door accepts an empty body rather than inventing a `reason` that would be
    parsed, checked and then thrown away. Who cancelled and when is already in the audit row beside it;
    the window's own `reason` stays where its author put it.

    A sibling window that overlaps this one is *not* touched, and the answer says so by naming only this
    id. That is not a convenience: the overlap test on the delivery path asks whether *any* live window
    covers a finding, so a cancellation that quietly took the second window with it would end a silence
    somebody else declared and never asked to end. See the acceptance test for the pair.
    """
    suppression.revoke_window(store, window, actor, now=now)
    # Read the row back rather than trusting the revoke's own three-field answer: the caller asked about
    # *this* window and deserves its selector, its classes and who cancelled it, and the durable word for
    # what happened is `revoked` while the outcome vocabulary the API publishes says `cancelled`. Both are
    # said — `status` is the outcome word, `revoked_at` is the durable one.
    stored = suppression.window_by_id(store, window)
    return {'window_id': window, 'status': 'cancelled', 'resource_id': stored['resource_id'],
            'rule_id': stored['rule_id'], 'starts_at': stored['starts_at'], 'ends_at': stored['ends_at'],
            'reason': stored['reason'], 'explains': stored.get('explains'),
            'cancelled_by': stored['revoked_by'], 'cancelled_at': stored['revoked_at'],
            'cancelled_by_role': stored['revoked_by_role']}


def declare_window(store: Store, request: dict[str, Any], actor: Actor, *,
                   index_path: Path | str | None = None,
                   now: dt.datetime | None = None) -> dict[str, Any]:
    """Declare one planned window over a scope, and answer with every window it produced.

    This is the door the CLI does not have. `suppression.declare_window` takes a resource and two
    instants, which is the right shape for a host operator standing in front of one host; the API
    promises three scope kinds, so the expansion happens here and the durable shape stays the one the
    delivery path already reads. Two things follow, and both are stated in the answer:

    * a `service` scope declares **one window per member**, each with its own id, each revocable on
      its own. The answer lists them instead of hiding them behind one aggregate id, because the
      aggregate is exactly what a caller must not assume: a member added tomorrow is not covered by a
      window declared today.
    * a window that has already ended cannot be declared here (see `RETROACTIVE`), and one longer than
      `suppression.MAX_WINDOW_SECONDS` cannot be declared at all. A silence that long is a different
      product, and the CLI's refusal was not the only way to reach this table once this door opened.

    `explains` defaults to `EXPLAINED_BY_DEFAULT`, deliberately not to "everything": through this door an
    omission has blast radius, and the classes whose pages must survive a maintenance window are the ones
    a plan tends to forget. A caller who wants a wider silence names it.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if not isinstance(request, dict):
        raise StateError('Maintenance declaration must be an object')
    reason = _text(request.get('reason'), 'reason', REASON_LIMIT)
    scope = _scope_shape(request.get('scope'))
    start, end = _query_instant(request.get('starts_at'), 'starts_at'), \
        _query_instant(request.get('ends_at'), 'ends_at')
    if end <= start:
        raise StateError('Maintenance window ends_at must be after starts_at')
    if end - start > dt.timedelta(seconds=suppression.MAX_WINDOW_SECONDS):
        raise StateError(f'Maintenance window may not be longer than {suppression.MAX_WINDOW_SECONDS} seconds')
    if end <= now:
        raise StateError(RETROACTIVE_REFUSAL)
    unknown = sorted(set(request) - set(WINDOW_REQUEST_KEYS))
    if unknown:
        raise StateError('Unknown maintenance window field: ' + ','.join(unknown))
    klass = explain_list(request.get('explains'))
    resolved = resolve_scope(store, scope, index_path=index_path)
    answers: list[dict[str, Any]] = []
    duplicates = 0
    for member in resolved['selectors']:
        # A rule-scoped window carries no resource selector and covers the rule wherever it reports; every
        # other window is anchored to one member. One window per member is what makes cancelling one
        # silence one decision, and what keeps a member added tomorrow out of a window signed today.
        answer = suppression.declare_window(
            store, {'resource_id': member['resource_id'], 'rule_id': member['rule_id'],
                    'starts_at': utc_text(start), 'ends_at': utc_text(end), 'reason': reason,
                    'explains': klass}, actor, now=now)
        duplicates += answer['status'] == 'duplicate'
        answers.append(_window_answer(answer))
    return {'status': 'duplicate' if answers and duplicates == len(answers) else 'declared',
            'windows': answers, 'count': len(answers), 'declared': len(answers) - duplicates,
            'duplicates': duplicates, 'members': resolved['members'], 'scope': scope,
            'explains': klass, 'now': utc_text(now),
            'bound_exceeded': resolved['bound_exceeded'] or len(answers) > suppression.MAX_LIVE_WINDOWS,
            'max_windows': suppression.MAX_LIVE_WINDOWS}


def _window_answer(window: dict[str, Any]) -> dict[str, Any]:
    """Report one stored declaration with its classes, in the shape an HTTP answer uses."""
    stored = window['window']
    return {'window_id': stored['id'], 'status': window['status'], 'resource_id': stored['resource_id'],
            'starts_at': stored['starts_at'], 'ends_at': stored['ends_at'], 'reason': stored['reason'],
            'declared_by': stored['author'], 'declared_by_role': stored[suppression.AUTHOR_ROLE],
            'explains': stored.get('explains')}


def declare_schedule(store: Store, request: dict[str, Any], actor: Actor, *,
                     index_path: Path | str | None = None,
                     now: dt.datetime | None = None) -> dict[str, Any]:
    """Record a recurring plan, and declare the first bounded slice of its windows.

    The version row is booked first and the windows declared after it, in their own transactions rather
    than inside it: `suppression.declare_window` opens its own write transaction, and a nested one on this
    file would sit on the same lock. What makes the split safe is that both halves are content-addressed —
    the schedule id is `schedule_id(reason, scope, author, recurrence, bounds)` and each window's id is
    `occurrence_id` plus
    `suppression.window_id` — so a process that died between them is finished by the next attempt, which
    answers `duplicate` on what already exists and writes the rest. Nothing is left half-declared in a way
    a reader cannot tell: `GET /v1/maintenance-schedules/{id}` recomputes the whole occurrence list from
    the document and reports `materialized_through` beside it.

    Args:
        request: `reason`, `scope`, `recurrence`, `bounds`, and optionally `explains`.
        actor: Must carry role ``human``, as every window declaration requires.
        index_path: The built inventory index, required for a service scope and unused otherwise.
        now: The aware clock the plan is checked and materialized against.

    Returns:
        ``{'status': 'declared' | 'duplicate', 'id', 'version', 'schedule', 'occurrences', 'windows',
        'horizon', 'members', 'skipped_occurrences', 'dropped_occurrences', 'bound_exceeded'}``.

    Raises:
        StateError: The role is not ``human``; the shape is not a schedule; the bound is missing, open or
            oversized; the first occurrence has already ended (`RETROACTIVE`); or a scope this build cannot
            resolve. A window this plan would need may still be refused by `suppression.declare_window`'s
            own bounds (thirty-two live, the candidate bound) and that refusal propagates — a plan that
            quietly materialized some of its occurrences is a plan that lies about what is quiet.
    """
    require(actor, *OPERATOR_ROLES)
    now = clock(now)
    document, scope = _request(request, actor, store=store, index_path=index_path, now=now)
    document = dict(document, version=1, state='active')
    status = _insert_version(store, document, actor, now=now)
    return _materialize(store, document, scope, actor, status=status, now=now)


def revise_schedule(store: Store, id: str, request: dict[str, Any], actor: Actor, *,
                    expected_version: Any = None, index_path: Path | str | None = None,
                    now: dt.datetime | None = None) -> dict[str, Any]:
    """Make a new version of a plan effective, leaving every window already running exactly as it was.

    An edit appends. The version that was in force is still in `maintenance_schedules`, still readable by
    number, which is the only way "what did the plan say in October?" has an answer in November — and the
    windows the old version declared are *not* rewritten, because their spans, authors and attestations are
    facts about silences that already happened.

    What an edit does touch: the unstarted windows the plan's earlier versions declared. Those are revoked,
    because a plan whose time moved must not leave the old silence in place, and a revocation (unlike an
    edit) is an audited act that keeps its row. A window already *running* is left alone: cutting short a
    silence an operator is standing inside is not what "the recurrence changed" means, and the new version
    starts governing at the next occurrence. Overlapping windows are allowed and each keeps its own
    attribution, so the overlap this can briefly leave is visible in a report rather than hidden.

    `expected_version` — the `If-Match` the transport hands over, or the body's `expected_revision` — makes
    this a conditional write: a plan that moved under the caller is refused rather than silently replacing
    somebody else's edit.

    Raises:
        StateError: The role is not ``human``; no such schedule; the current version is cancelled (a
            cancelled plan is not edited, the new plan is declared); the expectation does not match; or the
            request is not a schedule.
    """
    require(actor, *OPERATOR_ROLES)
    now = clock(now)
    identifier(id)
    with readonly(store) as db:
        current = _current_version(db, id)
    if current is None:
        raise StateError('No such maintenance schedule')
    if current.get('unreadable'):
        raise StateError('Maintenance schedule version is unreadable; reconcile it, never re-declare it')
    check_revision(current['version'], expected_version)
    if current['state'] == 'cancelled':
        raise StateError('A cancelled maintenance schedule is not edited; declare the new plan')
    document, scope = _request(request, actor, store=store, index_path=index_path, now=now, id=id)
    document = dict(document, version=current['version'] + 1, state='active')
    status = _insert_version(store, document, actor, now=now)
    # Supersede first, materialize second. The other order revokes the windows this version has just
    # declared — a plan edited at 09:00 would arrive at 09:01 with its own future cut out from under it —
    # and `not_version` is the belt to that brace: a retried edit that answered `duplicate` must not
    # re-revoke what it is keeping.
    supersede = _revoke_superseded(store, id, actor, now=now, not_version=document['version'])
    outcome = _materialize(store, document, scope, actor, status=status, now=now)
    outcome['windows_revoked'] = supersede['count']
    outcome['windows_superseded'] = supersede['windows']
    outcome['bound_exceeded'] = outcome['bound_exceeded'] or supersede['bound_exceeded']
    return outcome


def cancel_schedule(store: Store, id: str, actor: Actor, *,
                    now: dt.datetime | None = None) -> dict[str, Any]:
    """Stop a plan going forward: a new version says `cancelled`, and the windows nobody has started end.

    Cancelled windows are revoked, not deleted, and the ones already running keep running to their declared
    ends: a revocation is what a human can be held to, and a row that changed its span would be a silence
    nobody signed. Past windows stay exactly as they were — they are the evidence the outcomes are computed
    from.

    Raises:
        StateError: The role is not ``human``, no such schedule, or the current version already cancelled.
    """
    require(actor, *OPERATOR_ROLES)
    now = clock(now)
    identifier(id)
    with readonly(store) as db:
        current = _current_version(db, id)
    if current is None:
        raise StateError('No such maintenance schedule')
    if current.get('unreadable'):
        raise StateError('Maintenance schedule version is unreadable; reconcile it, never re-declare it')
    if current['state'] == 'cancelled':
        raise StateError('Maintenance schedule is already cancelled')
    document = {key: current[key] for key in SCHEDULE_KEYS}
    document = dict(document, version=current['version'] + 1, state='cancelled')
    _insert_version(store, document, actor, now=now)
    revoked = _revoke_superseded(store, id, actor, now=now)
    return {'status': 'cancelled', 'id': id, 'version': document['version'],
            'windows_revoked': revoked['count'], 'windows_superseded': revoked['windows'],
            'bound_exceeded': revoked['bound_exceeded'], 'schedule': document}


def materialize_schedule(store: Store, id: str, actor: Actor, *,
                         index_path: Path | str | None = None,
                         now: dt.datetime | None = None) -> dict[str, Any]:
    """Declare the next bounded slice of a plan's windows, and say where that slice stops.

    A roll-forward is a human act, not a timer: it needs the credential declaring a window needs, it is
    bounded to `MAX_MATERIALIZED_OCCURRENCES` occurrences inside `MAX_HORIZON_SECONDS`, and it is idempotent
    because both ids involved are computed from the plan rather than minted. Running it twice is one answer,
    twice — which is also why the horizon is written *after* the windows rather than before.

    The narrow exception to `RETROACTIVE` lives here and nowhere else: an occurrence that has begun but not
    ended is still declared, because the plan covering it was signed in advance and the remaining silence is
    what the plan promised. An occurrence that has already ended is not declared at all.
    """
    require(actor, *OPERATOR_ROLES)
    now = clock(now)
    identifier(id)
    with readonly(store) as db:
        current = _current_version(db, id)
    if current is None:
        raise StateError('No such maintenance schedule')
    if current.get('unreadable'):
        raise StateError('Maintenance schedule version is unreadable; reconcile it, never re-declare it')
    if current['state'] == 'cancelled':
        raise StateError('A cancelled maintenance schedule materializes nothing; declare the new plan')
    scope = resolve_scope(store, current['scope'], index_path=index_path)
    outcome = _materialize(store, {key: current[key] for key in SCHEDULE_KEYS}, scope, actor,
                           status='rolled_forward', now=now, horizon_after=current['horizon'])
    with store.transaction() as connection:
        store.audit(connection, now, actor.identity, MATERIALIZATION_OPERATION, id,
                    {'version': current['version'], 'declared': outcome['declared'],
                     'duplicates': outcome['duplicates'], 'horizon': outcome['horizon']})
    return dict(outcome, id=id, version=current['version'])


def _request(request: dict[str, Any], actor: Actor, *, store: Store,
             index_path: Path | str | None, now: dt.datetime,
             id: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the (document, scope) pair one validated declaration request describes.

    Shared by declare and revise so the two doors cannot drift: the same shape test, the same bounds, the
    same retroactive refusal, the same scope resolution. `id` is the caller's for a revision and derived
    from the content for a new plan (see `schedule_id`).
    """
    if not isinstance(request, dict):
        raise StateError('A maintenance schedule declaration is a JSON object')
    unknown = set(request) - set(REQUEST_KEYS)
    if unknown:
        raise StateError('Unknown maintenance schedule field: ' + ','.join(sorted(unknown)))
    missing = set(REQUEST_KEYS) - {'explains'} - set(request)
    if missing:
        raise StateError('A maintenance schedule needs reason, scope, recurrence and bounds; missing '
                         + ','.join(sorted(missing)))
    scope = resolve_scope(store, request['scope'], index_path=index_path)
    recurrence = _recurrence(request['recurrence'])
    bounds = _bounds(request['bounds'])
    first = _local_date(bounds['first_occurrence'], 'first_occurrence')
    zone = _zone(recurrence['timezone'])
    start = _first_instant(first, recurrence, zone)
    if start + dt.timedelta(seconds=recurrence['duration_seconds']) <= now:
        raise StateError(RETROACTIVE_REFUSAL)
    return {'id': id or schedule_id(request['reason'], request['scope'], actor.identity,
                                    request['recurrence'], request['bounds']),
            'version': None, 'state': None, 'reason': request['reason'], 'scope': request['scope'],
            'explains': explain_list(request.get('explains')), 'recurrence': recurrence,
            'bounds': bounds, 'author': actor.identity, 'declared_at': utc_text(now)}, scope


def _first_instant(day: dt.date, recurrence: dict[str, Any], zone: ZoneInfo) -> dt.datetime:
    """Return the first occurrence's start, in the plan's own zone, honouring its DST policy.

    ``skip`` on the *first* occurrence is answered by the next real instant rather than by an empty plan: a
    schedule that could never start would bind a version, take an audit row, and materialize nothing, ever.
    """
    naive = dt.datetime.combine(day, _time_of_day(recurrence['time_of_day']))
    instant = naive.replace(tzinfo=zone, fold=0).astimezone(dt.timezone.utc)
    if transition(naive, zone) == 'gap' and recurrence['dst'] == 'skip':
        return instant + dt.timedelta(hours=1)
    return instant


def _materialize(store: Store, document: dict[str, Any], scope: dict[str, Any], actor: Actor, *,
                 status: str, now: dt.datetime,
                 horizon_after: str | None = None) -> dict[str, Any]:
    """Turn the next bounded slice of one version's occurrences into windows."""
    floor = _instant(horizon_after) if horizon_after else now
    plan = occurrences(document, now=now, after=floor)
    windows: list[dict[str, Any]] = []
    declared = duplicates = 0
    for occurrence in plan['occurrences']:
        if occurrence['past']:
            continue                       # an ended occurrence could silence nothing; declare nothing
        for selector in scope['selectors']:
            answer = suppression.declare_window(store, dict(
                selector, starts_at=occurrence['starts_at'], ends_at=occurrence['ends_at'],
                reason=document['reason'], explains=document['explains'],
                schedule_id=document['id'], schedule_version=document['version'],
                occurrence_id=occurrence['occurrence_id']), actor, now=now)
            declared += answer['status'] == 'declared'
            duplicates += answer['status'] == 'duplicate'
            windows.append(dict(answer['window'], occurrence_id=occurrence['occurrence_id'],
                                dst=occurrence['dst'], status=answer['status']))
    with store.transaction() as connection:
        _write_horizon(connection, document['id'], document['version'], plan['horizon'], now)
    return {'status': status, 'id': document['id'], 'version': document['version'],
            'schedule': document, 'occurrences': plan['occurrences'], 'windows': windows,
            'declared': declared, 'duplicates': duplicates, 'horizon': plan['horizon'],
            'skipped_occurrences': plan['skipped'], 'dropped_occurrences': plan['dropped'],
            'members': scope['members'],
            'bound_exceeded': plan['bounded'] or len(windows) > suppression.MAX_LIVE_WINDOWS}


# --- durable rows ----------------------------------------------------------------------------

def _insert_version(store: Store, document: dict[str, Any], actor: Actor, *, now: dt.datetime) -> str:
    """Audit and insert one schedule version in one transaction, and report declared or duplicate.

    The audit row goes in *first* and its sequence is stored beside the document, exactly as a window
    stores the sequence of its `maintenance.declared` row: `audit` carries the UPDATE and DELETE triggers
    this table copies, so the version a row points at cannot be quietly rewritten afterwards. A duplicate
    (the same id and version already present) writes nothing and answers `duplicate`, which is what makes a
    retried declaration cheap rather than dangerous.
    """
    document = _document(document)
    key = canonical({field: document[field] for field in SCHEDULE_KEYS})
    with store.transaction() as connection:
        exists = connection.execute(f'SELECT document FROM {MAINTENANCE_SCHEDULE_TABLE}'
                                    ' WHERE schedule_id=? AND version=?',
                                    (document['id'], document['version'])).fetchone()
        if exists is not None:
            # `duplicate` is a claim, not a shrug: it says the row already present *is* this declaration.
            # Anything else is a collision between two plans that reached one id, and answering it quietly
            # would leave the table describing one plan while the windows belong to another.
            if exists[0] != key:
                raise StateError(f'A maintenance schedule {document["id"]} version {document["version"]}'
                                 ' is already declared and says something else; revise it or declare the'
                                 ' other plan under its own reason')
            return 'duplicate'
        store.audit(connection, now, actor.identity, SCHEDULE_OPERATION, document['id'],
                    {field: document[field] for field in SCHEDULE_KEYS})
        # The role goes in a column and never into the signed document. `document` is the text the audit
        # row quotes byte for byte (`_attested`), and widening it after the fact would split one plan into
        # two digests — a schedule declared by a human before this role existed would stop matching its own
        # version on a re-declaration, and the answer would be a false "already declared and says something
        # else". Who signed is therefore stored *beside* the signature, in the one place a read can ask.
        connection.execute(
            f'INSERT INTO {MAINTENANCE_SCHEDULE_TABLE}(schedule_id,version,document,state,horizon,'
            f' declared_at,declared_by,{OPERATOR_ROLE_SCHEDULES},attest) VALUES (?,?,?,?,?,?,?,?,?)',
            (document['id'], document['version'], key, document['state'], utc_text(now),
             document['declared_at'], actor.identity, actor.role,
             int(connection.execute('SELECT last_insert_rowid()').fetchone()[0])))
    return 'declared'


def _write_horizon(connection: sqlite3.Connection, id: str, version: int, horizon: str,
                   now: dt.datetime) -> None:
    """Move one plan's materialization horizon forward, in control state and not in the version row.

    The horizon is bookkeeping — where the roll-forward reached — and the append-only triggers on
    `maintenance_schedules` deliberately forbid the UPDATE that would move it as a column. Bending an
    append-only guarantee to hold a cursor is how the guarantee gets lost, so the cursor lives under its own
    control key and carries the version it was written for: a reader that finds a horizon written by an
    older version ignores it, and the version rows go on saying exactly what they said when signed. One key
    per plan, overwritten by that plan's own next roll-forward, so the cursor cannot grow the file.
    """
    control_write(connection, horizon_key(id),
                  canonical({'version': version, 'horizon': horizon}), now)


#: The prefix the materialization cursor lives under, one key per plan. Deliberately *not* under
#: `state.MAINTENANCE_PREFIX`: that range is what `suppression._scan` and schema v5's index read as
#: windows, and a bookkeeping key inside it would be scanned as a declaration and counted against the live
#: window bound. `-` sorts before `:`, so these keys sit outside the window range on both sides.
HORIZON_PREFIX = 'maintenance-horizon:'


def horizon_key(id: str) -> str:
    """Return the control key holding where one plan's materialization reached."""
    return HORIZON_PREFIX + id


def _revoke_superseded(store: Store, id: str, actor: Actor, *, now: dt.datetime,
                       not_version: int | None = None) -> dict[str, Any]:
    """Revoke this plan's unstarted windows, and report what was left running.

    A window whose start is behind the clock is left alone — see `revise_schedule` for why cutting a live
    silence is not what an edit means. `bound_exceeded` propagates rather than being swallowed: if this
    read could not see the whole future set, the caller is told the cancellation may be incomplete instead
    of being told it was.
    """
    horizon = now + dt.timedelta(seconds=MAX_HORIZON_SECONDS + suppression.MAX_WINDOW_SECONDS)
    found = suppression.windows_spanning(store, span_from=now, span_to=horizon)
    revoked = []
    for window in found['windows']:
        if window['schedule_id'] != id or window['revoked_at'] is not None:
            continue
        if not_version is not None and window['schedule_version'] == not_version:
            continue
        if _instant(window['starts_at']) <= now:
            continue
        suppression.revoke_window(store, window['id'], actor, now=now)
        revoked.append(window['id'])
    return {'count': len(revoked), 'windows': revoked, 'bound_exceeded': found['bound_exceeded']}


def _current_version(connection: sqlite3.Connection, id: str) -> dict[str, Any] | None:
    """Return the newest version of one schedule with its horizon merged in, or None when it has none.

    The primary key is ``(schedule_id, version)``, so "newest" is a seek and not a walk. A version whose
    document cannot be re-validated is reported under `unreadable` rather than skipped — skipping it would
    make a corrupt newest version invisible and hand the caller an older plan to edit, which is a silent
    rewind dressed up as a read.
    """
    row = connection.execute(f'SELECT * FROM {MAINTENANCE_SCHEDULE_TABLE} WHERE schedule_id=?'
                             ' ORDER BY version DESC LIMIT 1', (id,)).fetchone()
    if row is None:
        return None
    document = _read_row(row)
    if document is None:
        return {'unreadable': True, 'version': int(row['version']), 'id': id}
    stored = connection.execute('SELECT value FROM notification_control WHERE key=?',
                                (horizon_key(id),)).fetchone()
    if stored is not None:
        try:
            payload = json.loads(stored['value'])
            if int(payload['version']) >= int(document['version']):
                document['horizon'] = str(payload['horizon'])
        except (ValueError, TypeError, KeyError):
            pass                     # an unreadable cursor is no cursor: the version row's own stamp wins
    return document


def check_revision(actual: Any, expected: Any) -> None:
    """Refuse a conditional write whose expectation no longer holds.

    The transport owns the `412` shape and the header parsing; this module only says whether the
    expectation matched, in one place, so a revise and a cancel cannot disagree about what a stale
    `If-Match` means.
    """
    if expected is None:
        return
    if str(actual) != str(expected):
        raise StateError('Maintenance schedule revision does not match')


# --- reading schedules -----------------------------------------------------------------------

def schedule(store: Store, id: str, *, index_path: Path | str | None = None,
             now: dt.datetime | None = None) -> dict[str, Any]:
    """One schedule: its current version, its version history, and what it has materialized.

    The occurrence list is recomputed from the document on every read, which is why a plan answers for a
    host that has not run a roll-forward in a month — the plan is the fact, the windows are its
    consequence — and why `materialized_through` is stated beside `occurrences` rather than instead of it.

    Raises:
        StateError: The id is not canonical, no version of that schedule is stored, or the newest version
            cannot be re-validated.
    """
    identifier(id)
    now = clock(now)
    with readonly(store) as db:
        current = _current_version(db, id)
        if current is None:
            raise StateError('No such maintenance schedule')
        if current.get('unreadable'):
            raise StateError('Maintenance schedule version is unreadable; reconcile it, never re-declare it')
        rows = db.execute(f'SELECT * FROM {MAINTENANCE_SCHEDULE_TABLE} WHERE schedule_id=?'
                          ' ORDER BY version LIMIT ?', (id, MAX_SCHEDULE_ROWS + 1)).fetchall()
        history = []
        for row in rows:
            document = _read_row(row)
            history.append({'version': int(row['version']), 'declared_at': row['declared_at'],
                            'declared_by': row['declared_by'],
                            'declared_by_role': stored_role(row, OPERATOR_ROLE_SCHEDULES),
                            'state': row['state'],
                            'horizon': row['horizon'], 'unreadable': document is None,
                            'attested': _attested(db, document, int(row['attest']))
                            if document is not None else False})
        members = None
        if current['scope']['kind'] == 'service':
            with contextlib.suppress(StateError):
                members = resolve_scope(store, current['scope'], index_path=index_path)['members']
        plan = occurrences(current, now=now)
    return {'schedule': dict(current, attested=_attested_current(store, current)),
            'history': history, 'versions': len(history), 'occurrences': plan['occurrences'],
            'materialized_through': current['horizon'], 'occurrence_bound': plan['bounded'],
            'skipped_occurrences': plan['skipped'], 'dropped_occurrences': plan['dropped'],
            'scope_members': members, 'now': utc_text(now),
            'bound_exceeded': len(rows) > MAX_SCHEDULE_ROWS}


def _attested_current(store: Store, document: dict[str, Any]) -> bool:
    """Whether the current version's own audit row exists, on a read-only connection."""
    with readonly(store) as db:
        return _attested(db, document, int(document['attest']))


def schedule_history(store: Store, id: str) -> dict[str, Any]:
    """Every version of one schedule, oldest first, each with whether a human signed it.

    Version history is the whole reason schedules are a table: "what was planned for the third Tuesday, and
    who said so?" is answered by rows that cannot have been overwritten. An answer that could be rewritten
    after the fact is not evidence, which is also why the documents are returned as stored rather than
    re-narrated.
    """
    identifier(id)
    with readonly(store) as db:
        rows = db.execute(f'SELECT * FROM {MAINTENANCE_SCHEDULE_TABLE} WHERE schedule_id=?'
                          ' ORDER BY version LIMIT ?', (id, MAX_SCHEDULE_ROWS + 1)).fetchall()
        versions = []
        for row in rows:
            document = _read_row(row)
            versions.append({'version': int(row['version']), 'declared_at': row['declared_at'],
                             'declared_by': row['declared_by'],
                             'declared_by_role': stored_role(row, OPERATOR_ROLE_SCHEDULES),
                             'state': row['state'],
                             'horizon': row['horizon'], 'unreadable': document is None,
                             'attested': _attested(db, document, int(row['attest']))
                             if document is not None else False,
                             'document': document})
    return {'id': id, 'versions': versions, 'count': len(versions),
            'attested': sum(1 for row in versions if row['attested']),
            'bound_exceeded': len(rows) > MAX_SCHEDULE_ROWS}


def schedules(store: Store, *, wanted: str = 'active',
              now: dt.datetime | None = None) -> dict[str, Any]:
    """Every schedule's current version, and every way this build would refuse to trust one.

    `wanted` filters on the *current* version, not on any version: a cancelled plan whose last word was
    `cancelled` belongs to the cancelled list even though its history is full of active versions. Rows are
    counted rather than dropped when their document cannot be re-validated or their attestation is missing,
    for the reason `live_windows` gives: a store this build cannot read to the end is a fact the operator is
    owed, not a row to hide.
    """
    if wanted not in SCHEDULE_STATES:
        raise StateError(f'Unknown maintenance schedule state: {wanted}')
    now = clock(now)
    with readonly(store) as db:
        rows = db.execute(f'SELECT * FROM {MAINTENANCE_SCHEDULE_TABLE} ORDER BY schedule_id, version'
                          ' LIMIT ?', (MAX_SCHEDULE_ROWS + 1,)).fetchall()
        newest: dict[str, dict[str, Any]] = {}
        unreadable = 0
        for row in rows:
            document = _read_row(row)
            if document is None:
                unreadable += 1
                continue
            newest[document['id']] = document
        answer = []
        unattested = 0
        for document in newest.values():
            if document['state'] != wanted:
                continue
            attested = _attested(db, document, int(document['attest']))
            unattested += not attested
            answer.append(dict(document, attested=attested))
        answer.sort(key=lambda item: (item['bounds']['first_occurrence'], item['id']))
    return {'schedules': answer, 'count': len(answer), 'scanned': len(rows), 'unreadable': unreadable,
            'unattested': unattested, 'state': wanted, 'bound_exceeded': len(rows) > MAX_SCHEDULE_ROWS,
            'max_rows': MAX_SCHEDULE_ROWS, 'now': utc_text(now)}


# --- outcomes --------------------------------------------------------------------------------

def attributed(store: Store, window: str, *,
               limit: int = MAX_EVIDENCE_ROWS) -> dict[str, Any]:
    """Which pages this window folded, read back off the append-only decisions that named it.

    The decision writes `window_id` into its own audit detail (`suppression._decide`) and schema v12 cut a
    partial index over exactly that key for exactly this question, so the read is a seek rather than a walk
    of a table that grows for the life of the file. Those rows are the evidence the brief asks for:
    attribution survives a restart because it is in the log, not in a process.

    `truncated` says the bound was reached, which weakens only a claim of *absence* — every row named here
    happened.
    """
    identifier(window)
    bound = _limit('limit', limit, 1, MAX_EVIDENCE_ROWS)
    with readonly(store) as db:
        rows = db.execute(
            'SELECT sequence, at, subject,'
            ' CASE WHEN json_valid(detail) THEN json_extract(detail,'
            "'$.condition_class') END AS condition_class"
            ' FROM audit'
            f" WHERE operation='{MAINTENANCE_SUPPRESSED_OPERATION}'"
            f' AND {MAINTENANCE_ATTRIBUTION_WINDOW} = ? ORDER BY sequence LIMIT ?',
            (window, bound + 1)).fetchall()
    return {'attributions': [{'sequence': row[0], 'at': row[1], 'delivery': row[2],
                              'condition_class': row[3]} for row in rows[:bound]],
            'count': min(len(rows), bound), 'truncated': len(rows) > bound, 'max_rows': bound}


def overlapping_incidents(store: Store, resource_id: str, *, start: dt.datetime, end: dt.datetime,
                          limit: int = MAX_EVIDENCE_ROWS) -> dict[str, Any]:
    """The incidents about one resource whose own span touches ``[start, end)``, and whether all were seen.

    This is the evidence that separates `unused` from `unknown` and the instant an `overrun` is claimed
    from: an open incident is the durable form of "this resource is still firing", so a row still open at
    the declared end says the work outlived its window. `resource_id` is required because a *rule*-scoped
    window has no resource to ask about, and its overrun check is reported unavailable rather than guessed
    from the absence of pages.
    """
    identifier(resource_id)
    bound = _limit('limit', limit, 1, MAX_EVIDENCE_ROWS)
    with readonly(store) as db:
        rows = db.execute("SELECT id, status, opened_at, updated_at FROM incidents WHERE resource_id=?"
                          " AND opened_at<? AND (status='open' OR updated_at>=?)"
                          ' ORDER BY opened_at, id LIMIT ?',
                          (resource_id, utc_text(end), utc_text(start), bound + 1)).fetchall()
    return {'incidents': [dict(row) for row in rows[:bound]], 'count': min(len(rows), bound),
            'truncated': len(rows) > bound, 'max_rows': bound}


def window_outcome(store: Store, window: dict[str, Any], *,
                   now: dt.datetime | None = None) -> dict[str, Any]:
    """What became of one window, from the rows that say, with the evidence named.

    The definitions are stated here because a report that invents its own adjectives is not checkable:

    ``planned``
        Not started and not revoked. Nothing has been silenced on its strength yet.
    ``active``
        Running. Its findings are being folded *now*, which is the state most likely to be forgotten.
    ``cancelled``
        Revoked. `cancelled_before_start` separates the work that never happened from work that ended
        early, and the evidence line names who signed it and when the covering stopped.
    ``overrun``
        Past its end, **and** an incident about the window's own resource that opened at or before `ends_at`
        is still open when this is read: the condition outlived the declared silence. Suppression stopped
        at the declared end regardless — that is not a judgement, it is how `suppression._covering_window`
        works — so what this outcome records is that the findings after the end paged, which is the loud
        direction the whole module prefers. A *resolved* incident is not evidence of an overrun, because
        `updated_at` moves when a fact is received and a recovery report that arrives late would convict its
        own window.
    ``completed``
        Past its end, and at least one page it explains was folded inside it.
    ``unused``
        Past its end, its scope was observed inside it, and nothing needed explaining.
    ``unknown``
        Past its end and the evidence does not reach: no observation, an unattested or unreadable window, a
        truncated read, or a rule-scoped window whose overrun cannot be checked from incident rows.

    Nothing is inferred from the *absence* of a row unless the read that found the absence was complete.
    """
    now = clock(now)
    if window.get('attested') is False:
        return {'outcome': 'unknown', 'observed': None, 'complete': False, 'attributions': [],
                'evidence': ['no human declaration attests this window: it silenced nothing, and what'
                             ' nobody signed has no recorded end']}
    start, end = _instant(window['starts_at']), _instant(window['ends_at'])
    revoked_at = _instant(window['revoked_at']) if window.get('revoked_at') else None
    if revoked_at is not None:
        # The pages a window folded *before* it was cancelled stay in the answer. `cancelled` describes
        # what the window is now, not what it did: a caller reading this is usually asking "what went
        # quiet, and who lost a page?", and reporting an empty attribution list would be a comfortable
        # untruth about work that already happened.
        fold = attributed(store, window['id'])
        return {'outcome': 'cancelled', 'observed': bool(fold['count']), 'complete': not fold['truncated'],
                'cancelled_before_start': revoked_at <= start, 'attributions': fold['attributions'],
                'evidence': [f'revoked by {window["revoked_by"]} at {window["revoked_at"]}',
                             f'{"never started" if revoked_at <= start else "started before it was revoked"};'
                             ' a revoked window covers nothing from that instant',
                             f'{fold["count"]} page(s) folded before it was revoked']}
    if start > now:
        return {'outcome': 'planned', 'observed': None, 'complete': True, 'attributions': [],
                'evidence': [f'starts at {window["starts_at"]}']}
    if end > now:
        return {'outcome': 'active', 'observed': None, 'complete': True, 'attributions': [],
                'evidence': [f'covering until {window["ends_at"]}']}
    fold = attributed(store, window['id'])
    resource = window.get('resource_id')
    overlap = None if resource is None else overlapping_incidents(store, resource, start=start, end=end)
    # An incident that opened at or before the declared end and is *still open* when this is read is the
    # durable form of "the condition outlived the window". A resolved incident is not evidence either way:
    # `incidents.updated_at` moves when a fact is *received*, and a boot report about 15:30 that arrives at
    # 17:30 would otherwise make a window that ended at 15:49 look overrun by its own recovery. Claiming an
    # overrun from arrival order is the kind of inference this module refuses in both directions.
    firing = bool(overlap and [row for row in overlap['incidents'] if row['status'] == 'open'])
    evidence = [f'{fold["count"]} page(s) folded by this window'] if fold['count'] else \
        ['no page was folded by this window']
    if overlap is not None:
        evidence.append(f'{overlap["count"]} incident(s) about this resource overlapped the window')
    else:
        evidence.append('a rule-scoped window has no resource whose incidents could show an overrun')
    complete = not fold['truncated'] and not (overlap or {}).get('truncated', False)
    if firing:
        evidence.append('an incident about this resource was open at the declared end and is still open;'
                        ' suppression stopped at the end, so those pages went out')
        outcome = 'overrun'
    elif fold['count']:
        outcome = 'completed'
    elif overlap and overlap['count']:
        outcome = 'unused'
    else:
        outcome = 'unknown'
        evidence.append('nothing observable about this scope was recorded inside the window; absence of'
                        ' findings cannot be claimed from an unread interval')
    return {'outcome': outcome, 'observed': bool(fold['count'] or (overlap and overlap['count'])),
            'evidence': evidence, 'complete': complete and outcome != 'unknown',
            'attributions': fold['attributions']}


def window_history(store: Store, window: str, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """One window's whole story: the declaration, the revocation, and every page it folded.

    Composed from three reads that each name their own evidence — the stored document (what was signed,
    including the envelope version that signed it), the window's outcome (which is computed from the log
    rather than stored beside it), and the attributed deliveries. Nothing is cached between them, so
    `tests/test_maintenance_api.py` can assert that a restart answers the same question with the same rows.
    """
    stored = suppression.window_by_id(store, window)
    outcome = window_outcome(store, stored, now=now)
    return {'window': stored, 'outcome': outcome, 'schedule': stored['schedule_id'],
            'occurrence_id': stored['occurrence_id'], 'events': [
                {'at': stored['declared_at'], 'what': 'declared', 'by': stored['author'],
                 'by_role': stored[suppression.AUTHOR_ROLE], 'attested': stored['attested']}]
            + ([{'at': stored['revoked_at'], 'what': 'revoked', 'by': stored['revoked_by'],
                 'by_role': stored['revoked_by_role'], 'attested': True}] if stored['revoked_at'] else [])
            + [{'at': row['at'], 'what': 'folded', 'by': 'suppression-worker',
                'attested': True, 'delivery': row['delivery'],
                'condition_class': row['condition_class']}
               for row in outcome['attributions']]}


# --- intervals and event-time lookup ---------------------------------------------------------

def intervals(store: Store, *, scope: dict[str, Any], span_from: dt.datetime, span_to: dt.datetime,
              index_path: Path | str | None = None, limit: int | None = None,
              now: dt.datetime | None = None) -> dict[str, Any]:
    """What a report should show as quiet between two instants, and which window says so.

    Two spans are reported for every window and they are not the same claim:

    * **raw** is what was declared — the span a human signed, quoted by the audit row. It never moves, so
      "the window was 14:55 to 16:49" stays true after somebody cancels it at 15:20.
    * **adjusted** is what the platform actually held quiet: truncated at a revocation, and absent for a
      window this build refuses to apply (unattested, unreadable). A report printing only the raw span
      would claim a silence nobody observed.

    `effective` is the union of the adjusted spans with every contributing window named — that is what
    "overlapping windows keep attribution" means in an answer: cancelling one of two overlapping windows
    shrinks the effective set and still shows the other's raw span beside its own author.
    """
    now = clock(now)
    found = suppression.windows_spanning(store, span_from=span_from, span_to=span_to)
    resolved = resolve_scope(store, scope, index_path=index_path) if scope['kind'] == 'service' else scope
    in_scope = [window for window in found['windows'] if _in_scope(window, resolved)]
    rows = in_scope[:_limit('limit', limit or MAX_INTERVAL_ROWS, 1, MAX_INTERVAL_ROWS)]
    covered = []
    for window in rows:
        outcome = window_outcome(store, window, now=now)
        applied = bool(window['attested'])
        end = window['revoked_at'] or window['ends_at']
        covered.append({'window_id': window['id'], 'scope': _window_scope(window),
                        'raw': {'starts_at': window['starts_at'], 'ends_at': window['ends_at']},
                        'adjusted': ({'starts_at': window['starts_at'], 'ends_at': end} if applied
                                     else None),
                        'applied': bool(applied),
                        'adjustment': 'revoked early' if window['revoked_at'] else None,
                        'explains': window['explains'], 'author': window['author'],
                        'declared_at': window['declared_at'], 'schedule_id': window['schedule_id'],
                        'schedule_version': window['schedule_version'],
                        'occurrence_id': window['occurrence_id'], 'outcome': outcome['outcome']})
    return {'intervals': covered, 'count': len(covered), 'returned_of': len(in_scope),
            'effective': _effective_spans(covered),
            'span': {'from': utc_text(span_from), 'to': utc_text(span_to)},
            'scope': scope, 'scope_members': resolved.get('members'),
            'truncated': len(in_scope) > len(rows),
            'complete': not found['bound_exceeded'],
            'bounds': {'scanned': found['scanned'], 'bound_exceeded': found['bound_exceeded'],
                       'unusable': found['unusable'], 'unattested': found['unattested'],
                       'max_rows': found['max_rows']},
            'retroactive': RETROACTIVE}


def window_at(store: Store, *, scope: dict[str, Any], at: dt.datetime, klass: str | None = None,
              index_path: Path | str | None = None) -> dict[str, Any]:
    """Classify one instant against the windows planned around it, without guessing.

    This is how a *late* fact reaches its classification: a boot report about 15:30 that arrives at 17:30 is
    long past the window that planned it, and `live_windows` will never see that window again. Asking the
    history answers what a report needs — was this outage planned? — with `planned`, `outside` or
    `unknown`, where `unknown` is what a bound says and never a default.

    `klass` asks the sharper question: given a finding of this class, does the planned work explain it? A
    window covering the instant that does not explain the class answers `outside`, which is the honest
    answer for an application failure inside an outage window — and the same answer the delivery path
    reached at the time, because it paged.
    """
    if klass is not None and klass not in suppression.CONDITION_CLASSES:
        raise StateError(f'Unknown condition class: {klass}')
    found = suppression.windows_spanning(store, span_from=at, span_to=at + dt.timedelta(seconds=1))
    resolved = resolve_scope(store, scope, index_path=index_path) if scope['kind'] == 'service' else scope
    covering = [window for window in found['windows'] if _in_scope(window, resolved)]
    explained = [window for window in covering
                 if klass is None or suppression.explains(window, klass)]
    primary = min(explained, key=lambda window: (window['starts_at'], window['id'])) if explained else None
    return {'at': utc_text(at), 'scope': scope,
            'classification': ('unknown' if found['bound_exceeded']
                               else 'planned' if primary is not None else 'outside'),
            'incomplete_reason': INCOMPLETE_SEARCH if found['bound_exceeded'] else None,
            'explained_by': [window['id'] for window in explained],
            'covers_instant': [window['id'] for window in covering],
            'primary': None if primary is None else {
                'window_id': primary['id'], 'schedule_id': primary['schedule_id'],
                'schedule_version': primary['schedule_version'],
                'occurrence_id': primary['occurrence_id'], 'starts_at': primary['starts_at'],
                'ends_at': primary['ends_at'], 'explains': primary['explains'],
                'author': primary['author']},
            'complete': not found['bound_exceeded'],
            'bounds': {'scanned': found['scanned'], 'bound_exceeded': found['bound_exceeded'],
                       'max_rows': found['max_rows']},
            'retroactive': RETROACTIVE}


def _window_scope(window: dict[str, Any]) -> dict[str, Any]:
    """The scope one stored window speaks for, in the words a request would use."""
    if window['resource_id'] is not None:
        return {'kind': 'resource', 'id': window['resource_id']}
    return {'kind': 'rule', 'id': window['rule_id']}


def _in_scope(window: dict[str, Any], scope: dict[str, Any]) -> bool:
    """Whether one window belongs to the scope a query asked about.

    Exact, and per-resource: a service query lists the members its snapshot resolved to, and a window on one
    of them is in scope. Nothing matches on a label prefix or a name — the same rule
    `suppression._covering_window` follows, for the same reason.
    """
    if scope['kind'] == 'rule':
        return window['rule_id'] == scope['id']
    members = scope.get('members') or [scope['id']]
    return window['resource_id'] is not None and window['resource_id'] in members


def _effective_spans(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge the adjusted spans into the smallest set covering them, naming every window per span.

    Overlaps are not collapsed into an anonymous union: each merged span carries the ids that produced it,
    so a reader can see that two windows said the same half-hour, and that cancelling one left the other.
    """
    spans = sorted((row for row in rows if row['adjusted']),
                   key=lambda row: (row['adjusted']['starts_at'], row['adjusted']['ends_at']))
    merged: list[dict[str, Any]] = []
    for row in spans:
        start, end = row['adjusted']['starts_at'], row['adjusted']['ends_at']
        if merged and start <= merged[-1]['ends_at']:
            last = merged[-1]
            last['ends_at'] = max(last['ends_at'], end)
            last['explained_by'].append(row['window_id'])
            continue
        merged.append({'starts_at': start, 'ends_at': end, 'explained_by': [row['window_id']]})
    return merged


# --- the query boundary ----------------------------------------------------------------------

def parse_query(query: bytes) -> dict[str, Any]:
    """Return one validated interval query, refusing anything this read cannot answer bounded.

    The rules are `platform/audit_reader.py`'s, for the same reason: the query is caller bytes, and a read
    that ignores an unknown parameter is a read whose answer silently depends on a spelling mistake.
    Exactly one scope (`resource`, `service` or `rule`), and exactly one of a span (`from` *and* `to`) or
    an instant (`at`); optional `class` with an instant, optional `limit` with a span. A bare date names a
    day in UTC — `from=2026-10-25` is that day's start and `to=2026-10-25` its end, exclusive — so asking
    about "the Tuesday the clocks changed" does not require spelling midnight twice.
    """
    try:
        text = query.decode('utf-8')
    except UnicodeDecodeError:
        raise StateError('An interval query must be UTF-8 text') from None
    parameters: dict[str, list[str]] = {}
    for pair in text.split('&'):
        if not pair:
            continue
        name, _, value = pair.partition('=')
        parameters.setdefault(name, []).append(value)
    if any(len(values) != 1 for values in parameters.values()):
        raise StateError('An interval query takes each parameter once')
    unknown = set(parameters) - {'resource', 'service', 'rule', 'from', 'to', 'at', 'class', 'limit'}
    if unknown:
        raise StateError('Unknown interval query parameter: ' + ','.join(sorted(unknown)))
    scopes = [key for key in ('resource', 'service', 'rule') if key in parameters]
    if len(scopes) != 1:
        raise StateError('An interval query names exactly one of resource, service or rule')
    instant = 'at' in parameters
    if instant == ('from' in parameters or 'to' in parameters):
        raise StateError('An interval query names either at, or both from and to')
    if 'class' in parameters and not instant:
        raise StateError('A condition class is asked for with at, not with a span')
    answer: dict[str, Any] = {'scope': {'kind': scopes[0], 'id': parameters[scopes[0]][0]},
                              'limit': _limit('limit', _number(parameters['limit'][0]), 1,
                                              MAX_INTERVAL_ROWS) if 'limit' in parameters else None,
                              'klass': parameters.get('class', [None])[0], 'at': None, 'span': None}
    if instant:
        answer['at'] = _query_instant(parameters['at'][0], 'at')
        return answer
    start, finish = _query_instant(parameters['from'][0], 'from'), _query_end(parameters['to'][0])
    if not start < finish:
        raise StateError('An interval query needs a to after its from')
    if (finish - start) > dt.timedelta(seconds=MAX_QUERY_SPAN_SECONDS):
        raise StateError(f'An interval query spans at most {MAX_QUERY_SPAN_SECONDS // 86400} days')
    answer['span'] = (start, finish)
    return answer


def _number(value: str) -> int:
    """Return one query integer, refusing instead of letting `int()` name the caller's text.

    `platform/api.py` answers an unparsed number with a fixed sentence everywhere else for this reason: a
    `ValueError` out of a handler reaches the transport's `500` branch, and a bad `limit` is the caller's
    mistake, not the service's.
    """
    try:
        return int(value)
    except ValueError:
        raise StateError('limit must be a positive integer') from None


def _query_instant(value: str, field: str) -> dt.datetime:
    """Return one query instant, reading a bare UTC day as its start."""
    if DATE_PATTERN.match(value):
        return dt.datetime.combine(_local_date(value, field), dt.time(), tzinfo=dt.timezone.utc)
    return _instant(value)


def _query_end(value: str) -> dt.datetime:
    """Return the end of a query span: a bare date means the *end* of that day, exclusively."""
    if DATE_PATTERN.match(value):
        return (dt.datetime.combine(_local_date(value, 'to'), dt.time(), tzinfo=dt.timezone.utc)
                + dt.timedelta(days=1))
    return _instant(value)

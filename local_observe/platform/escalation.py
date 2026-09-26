"""Escalation as a scheduler over the outbox: a stage enqueues a verdict, it never pages.

v0.1's `legacy:alerting/escalation.py` held an ordered list of `Stage(recipients, interval_s)` per alert,
advanced one stage per tick while the alert was unacknowledged, audited every transition, and handed the
recipients to `alerting/dispatch.py`, which sent them. **The engine is ported; the dispatcher is not, and
that is the whole adaptation.** `docs/CONTRACTS.md` §5 makes a delivery a leased, budgeted outbox row and
`platform/notification_safety.py` is the only thing allowed to decide whether a row may reach a human — a
second path that pages would be a second budget, which is the class of defect control state exists to prevent. So a
stage here does not notify anyone: **it files one canonical event**, and `state.Store.intake` is the only
code in this repository that writes an outbox row. What escalation owns is *when* a new verdict is filed,
never *whether it is sent*.

The mechanism, and the two things it buys:

* **A stage is a condition of its own.** Stage *k* of rule ``r`` is filed under ``r.stage<k>``, so it has
  its own `conditions.key`, its own incident, and therefore its own ``opened`` transition — which is what
  books the delivery. The base incident (stage 0) already booked its own when the detector's firing event
  opened it, so the chain in the configuration file lists the escalations *after* that page, not a
  duplicate of it.
* **Re-filing a stage cannot page it twice**, whatever the cursor does. A retry of a stage whose incident
  is already open produces a `firing` event for an open condition, and `Store.intake` books a delivery
  only on an ``opened``/``resolved`` **transition**. The durability argument therefore rests on the
  platform's incident identity rather than on this file's bookkeeping, which is the same posture
  `platform/anomaly.py` takes ("a re-send is a duplicate and not a second incident").
* **The clock arithmetic is derived, not remembered.** `due_at(k) = opened_at + Σ interval(1..k)`, read
  off the incident row, so a restart recomputes the same deadlines; the only thing the cursor must keep is
  the highest stage already enqueued, which is exactly what a restart must not repeat.

What is **not** done here, with the reason, because both are paths a later reader might reach for:

* `Store.retry_notification` is never called. It requires an `Actor` of role ``human`` (that is what it
  means: a person asked for a replay) and it only resurrects a ``dead`` row; a scheduler that minted a
  human actor to page again would be claiming an identity, not escalating. If a re-arm of an exhausted
  row turns out to be what an operator needs, it needs a state.py change and a decision, not a cast.
* `Store.claim_notification` / `finish_notification` are never called either. They are the delivery
  rail's lease; a second claimer would race `notifications.deliver_one` and consume a send slot.

What escalation *does* read from the delivery rail is its posture, through the existing
`Store.notification_safety_status`: **while every configured channel's flood breaker is latched, or the
store's mode is off, a stage is not enqueued at all** — it is audited as `escalation.suppressed` with the
reason, the stage is held (not advanced), and the next round retries. Enqueueing into a queue that will
suppress it would create an incident nobody can be paged about and a resolution nobody has to give; the
refusal is the honest artifact. The decision to suppress a *send* stays in `reserve_route`, unchanged.

**History is read through `platform/escalation_reader.py`, and this file touches no table of its own.**
That boundary is the bounded escalation history, and it exists because the first version of this unit asked the past a
question
a bounded window cannot answer. It judged liveness and acknowledgement from `Store.records` — the newest
100 rows of `events`, `incidents`, `actions` and `audit` — so the platform's 101st event silently ended
escalation everywhere (every read came back full, and a full window is one that might be hiding an
acknowledgement), and a tracked incident that had merely aged out of the newest-100 incidents looked like a
resolved one and was **closed**. No window size fixes that: the tables grow for the life of the file and a
round must not cost what the tables have accumulated. What the round reads now, and what it may conclude:

* **Tracked incidents, by primary key.** At most `MAX_TRACKED` exact reads, whatever else is happening in
  the file. A ladder ends on one positive fact: that incident's own `status` column, read from its own row,
  saying `resolved`. An absent incident row, an absent verdict row or a payload that is not a JSON object is
  *held* — the entry stays, the rung stays owed, nothing is closed. A ladder that holds is a pager still
  armed.
* **New work, by rowid walk.** `status='open'` in rowid order, one bounded page per round, the position
  durable in the cursor. Chains are matched in Python *after* the page is in hand, because a SQL predicate
  on the rule would have to read every open incident the platform ever opened. Old irrelevant history
  therefore delays discovery by a bounded number of pages instead of holding it forever, and it never
  delays an incident that is already tracked. The position is a ROWID and never a timestamp: `opened_at` is
  not monotonic, and a discovery key that can go backwards loses incidents or repeats them.
* **Acknowledgement, as two booleans per incident.** A human decision (an `actions` row bound to that
  incident whose status is past decision) and an approval intent (an `action.approval_intent` audit row for
  one of that incident's actions) — the same two durable facts as before, each proved by a row that stays in
  the database forever, so a last month's decision stops the ladder over a hundred thousand unrelated later
  rows. An incident whose *own* history is large enough to run out of its read budget is reported incomplete
  by name and held; the other incidents in the round are judged normally.

Like every other unit here: the clock is injected, there are no threads and no wall-clock reads, and every
transition — enroll, escalate, acknowledge, suppress, close — is an append-only audit row written through
the same `Store.audit` path intake uses. Absent configuration means off, and off is one INFO line.
"""
import datetime as dt
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import digest, timestamp, utc_text
from local_observe.log import get_logger
from .detections import event
from .state import Actor, StateError, Store, identifier, label, validate_event
from . import escalation_reader, vocabulary

log = get_logger(__name__)

# The stage event's own evaluation window. Sixty seconds because a stage is a statement about this tick,
# and `validate_event` bounds the window it must fit inside.
STAGE_WINDOW_SECONDS = 60
MAX_CHAINS = 8
MAX_STAGES = 5
MAX_CONFIG_BYTES = 65_536
#: How many incidents one scheduler may hold a durable stage counter for. The bounded escalation history keeps this
#: bound
#: exactly as it was — it bounds the memory of *this file*, and was never a bound on what the platform has
#: incidents about — and pairs it with an explicit `capacity` count, so reaching it is a reported
#: limitation rather than an incident that quietly never escalates.
MAX_TRACKED = 64
MAX_CURSOR_BYTES = 1_048_576
#: v2 adds the durable discovery position (`scan_after`). A v1 file is still read and is migrated in memory
#: rather than refused: the facts a stage counter is trusted for — the entries, the producer identity, the
#: chain binding — carry over untouched, and a walk that starts at the beginning of the table loses nothing
#: that v1 could see.
CURSOR_VERSION = 2
CONFIG_KEYS = frozenset({'chains'})
CHAIN_KEYS = frozenset({'id', 'rule_id', 'resource_id', 'stages'})
STAGE_KEYS = frozenset({'interval_seconds', 'severity_source', 'severity_tier'})
STAGE_LIMITS = (60, 86400)
CURSOR_KEYS = frozenset({'schema_version', 'source', 'binding', 'incidents', 'scan_after'})
CURSOR_KEYS_V1 = frozenset({'schema_version', 'source', 'binding', 'incidents'})
ENTRY_KEYS = frozenset({'chain', 'stage', 'status', 'condition', 'resource_id', 'opened_at', 'suppressed'})
#: SQLite's signed-64 ceiling, which is also the largest rowid a discovery position may name.
ROWID_MAXIMUM = escalation_reader.ROWID_MAXIMUM
#: The prefix `notification_safety.NotificationPolicy.is_synthetic` reserves for non-production
#: producers. A stage filed under such a source would be booked, claimed and delivered into a recording
#: sink — an audit trail of a page that never paged anyone — so `tick` refuses it at the door.
SYNTHETIC_PREFIX = 'stage-'
#: The two ack kinds, and the post-decision `actions.status` values each one implies. `pending` is absent
#: on purpose: a proposal is not an acknowledgement, and an expired action decided by nobody is not either.
ACK_STATUSES = ('approved', 'denied', 'executing', 'succeeded', 'failed', 'unknown')
ACK_DECISION = 'action-decided'
ACK_INTENT = 'approval-intent'
#: Audit operations this module adds. Named as a tuple so the report, the README row and a grep agree.
OPERATIONS = ('escalation.enrolled', 'escalation.stage', 'escalation.acknowledged',
              'escalation.suppressed', 'escalation.closed')
#: The one word a round that never got a read snapshot reports. Fixed, because the reason a snapshot failed
#: can name a file path, and nothing this module returns may carry one.
READ_REFUSAL = 'history-unreadable'


@dataclass(frozen=True)
class Stage:
    """One escalation rung: how long to wait, and how loud the resulting verdict is.

    `severity_source` names a declared source vocabulary and `severity_tier` one of its words, resolved by
    `platform/vocabulary.severity` — so this module spells no severity, and a chain cannot invent a fourth
    rung intake would refuse. The recipients v0.1 carried here are deliberately gone: who is paged is
    the notification channel's configuration, chosen by `notification_safety.reserve_route` at claim time,
    and a stage that named a channel would be a second routing table.
    """
    interval_seconds: int
    severity_source: str
    severity_tier: str

    def __post_init__(self) -> None:
        """Check the wait and resolve the loudness, once, at load."""
        if isinstance(self.interval_seconds, bool) or not isinstance(self.interval_seconds, int) \
                or not STAGE_LIMITS[0] <= self.interval_seconds <= STAGE_LIMITS[1]:
            raise StateError('Escalation interval must be 60..86400 seconds')
        vocabulary.severity(self.severity_source, self.severity_tier)

    def severity(self) -> str:
        """Return the firing loudness this rung files at."""
        return vocabulary.severity(self.severity_source, self.severity_tier)


@dataclass(frozen=True)
class Chain:
    """One rule's ordered rungs, and the arithmetic that says which are due.

    Stage numbering starts at **1**: stage 0 is the base incident's own delivery, filed by the detector
    that opened it. So `stages` holds the escalations only, and `stages[0]` is the first rung after that.
    """
    id: str
    rule_id: str
    resource_id: str | None
    stages: tuple[Stage, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Check the identity fields and the shape of the ladder."""
        label(self.id)
        label(self.rule_id)
        if self.resource_id is not None:
            identifier(self.resource_id)
        if not 1 <= len(self.stages) <= MAX_STAGES:
            raise StateError('Escalation chain must hold 1-5 stages')
        for stage in self.stages:
            if not isinstance(stage, Stage):
                raise StateError('Escalation chain stages must be stages')

    def matches(self, rule_id: str, resource_id: str | None) -> bool:
        """Say whether this chain owns one condition, optionally narrowed to one resource."""
        return rule_id == self.rule_id and (self.resource_id is None or resource_id == self.resource_id)

    def due_at(self, stage: int, *, opened_at: dt.datetime) -> dt.datetime:
        """Return the instant rung *stage* becomes due: the sum of the waits before it.

        Derived from the incident's own `opened_at` and never from "now minus a stored deadline", so a
        worker that was down for an hour knows exactly which rungs it owes on the way back — and cannot
        invent a new deadline by restarting the clock.
        """
        if not 1 <= stage <= len(self.stages):
            raise StateError('Escalation stage is outside the chain')
        waiting = sum(item.interval_seconds for item in self.stages[:stage])
        return opened_at + dt.timedelta(seconds=waiting)

    def stage_for(self, *, opened_at: dt.datetime, now: dt.datetime, last: int = 0) -> int | None:
        """Return the lowest rung due at *now* above `last`, or None when nothing is owed.

        One rung per round, as v0.1 made it: an hour of downtime must not turn into a burst of pages when
        the worker returns. What `last` (the highest rung already enqueued, read from the durable cursor)
        buys is the restart promise — a second process recomputes the same due times and still cannot
        re-page the rung the first one already filed.
        """
        for stage in range(max(last, 0) + 1, len(self.stages) + 1):
            if self.due_at(stage, opened_at=opened_at) <= now:
                return stage
        return None


def config(path: Path | str) -> dict[str, Any]:
    """Read and validate one escalation document; the off switch is the absence of the file.

    Raises:
        StateError: The document is oversized, keyed beyond `CONFIG_KEYS`, holds 0 or >8 chains, gives a
            chain no stages, or repeats a chain id. A `vocabulary.VocabularyError` from an unresolvable
            tier word propagates unchanged: it is already a ValueError, and `cli.py` answers one JSON line
            for those.
    """
    candidate = Path(path)
    if len(candidate.read_bytes()) > MAX_CONFIG_BYTES:
        raise StateError('Escalation configuration exceeds its byte bound')
    document = json.loads(candidate.read_text(encoding='utf-8'))
    if not isinstance(document, dict) or set(document) - CONFIG_KEYS:
        raise StateError('Unknown escalation configuration keys')
    entries = document.get('chains')
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_CHAINS:
        raise StateError('Escalation chains must be 1-8 entries')
    chains: list[Chain] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) - CHAIN_KEYS or 'id' not in entry or 'rule_id' not in entry:
            raise StateError('Escalation chain fields are unknown or missing')
        stages = entry.get('stages')
        if not isinstance(stages, list) or not stages:
            raise StateError('Escalation chain needs at least one stage')
        built = []
        for stage in stages:
            if not isinstance(stage, Mapping) or set(stage) - STAGE_KEYS or set(stage) != STAGE_KEYS:
                raise StateError('Escalation stage fields are unknown or missing')
            built.append(Stage(**dict(stage)))
        chains.append(Chain(id=entry['id'], rule_id=entry['rule_id'],
                            resource_id=entry.get('resource_id'), stages=tuple(built)))
    if len({chain.id for chain in chains}) != len(chains):
        raise StateError('Escalation chain ids must be unique')
    return {'chains': chains}


def binding(chains: Sequence[Chain]) -> str:
    """Digest the chain set a cursor was written against, so an edit cannot silently re-baseline it."""
    return digest([[chain.id, chain.rule_id, chain.resource_id,
                    [stage.interval_seconds for stage in chain.stages]] for chain in chains])


def _position(value: Any) -> int:
    """Return a stored discovery position, refusing one this build could not have written.

    The bound is SQLite's own rowid ceiling rather than an invented one: a position above it could not name
    a row, so a cursor claiming it is a document this round must not resume from. A float, a string of
    digits, a bool and a negative number are all refusals — the walk either has an honest integer position
    or it starts over, and "starts over" is a coverage cost, never a lost stage.
    """
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= ROWID_MAXIMUM:
        raise StateError('Escalation cursor scan position is unsupported')
    return value


def load_cursor(path: Path | str, *, source: str, chains: Sequence[Chain]) -> dict[str, Any]:
    """Read this scheduler's durable stage state, refusing anything it cannot be trusted to resume from.

    A missing file is not a refusal: the first round has escalated nothing. What is refused is a document
    that claims to be about something else — another version, another producer identity, another chain
    set — because resuming from that is how stage 1 gets paged a second time, the exact failure the cursor
    exists to prevent.

    A v1 document is the one exception, and the migration is in memory only: `schema_version` and
    `scan_after` are this load's answer, while `incidents`, `source` and `binding` are copied out of the
    file unchanged, because those are the entries a stage counter is trusted for. `scan_after` starts at 0,
    which means "walk the table from its beginning", and the first such walk can only re-examine incidents
    this round either already tracks or will enroll.

    Returns:
        The v2-shaped document, plus ``migrated`` — a fact about *this load* (`True` when the file on disk
        was v1) that `save_cursor` deliberately does not accept, so the version bump is written by a round
        that completed and not by a read.

    Raises:
        StateError: The file is oversized, keyed beyond `CURSOR_KEYS`/`CURSOR_KEYS_V1`, of a version neither
            v1 nor this build's, written by another producer, bound to another chain set, holding more than
            `MAX_TRACKED` incidents, carrying an entry this build cannot describe, or naming a scan position
            that is not a rowid.
    """
    candidate = Path(path)
    if not candidate.exists():
        return {'schema_version': CURSOR_VERSION, 'source': source, 'binding': binding(chains),
                'incidents': {}, 'scan_after': 0, 'migrated': False}
    try:
        with candidate.open('rb') as cursor:
            raw = cursor.read(MAX_CURSOR_BYTES + 1)
        if len(raw) > MAX_CURSOR_BYTES:
            raise StateError('Escalation cursor exceeds its byte bound')
        document = json.loads(raw)
    except StateError:
        raise
    except (OSError, ValueError, RecursionError):
        raise StateError('Escalation cursor could not be read') from None
    if not isinstance(document, dict) or set(document) not in (CURSOR_KEYS, CURSOR_KEYS_V1):
        raise StateError('Escalation cursor fields are unknown')
    version = document['schema_version']
    if type(version) is not int:
        raise StateError('Escalation cursor schema version is unsupported')
    if version == CURSOR_VERSION and set(document) == CURSOR_KEYS:
        scan_after, migrated = _position(document['scan_after']), False
    elif version == 1 and set(document) == CURSOR_KEYS_V1:
        scan_after, migrated = 0, True
    else:
        raise StateError('Escalation cursor schema version or producer identity is unsupported')
    if document['source'] != source:
        raise StateError('Escalation cursor schema version or producer identity is unsupported')
    if document['binding'] != binding(chains):
        raise StateError('Escalation cursor belongs to a different chain set; reconcile it, never re-baseline')
    incidents = document['incidents']
    if not isinstance(incidents, dict) or len(incidents) > MAX_TRACKED:
        raise StateError('Escalation cursor tracks too many incidents')
    for incident_id, entry in incidents.items():
        identifier(incident_id)
        if not isinstance(entry, Mapping) or set(entry) != ENTRY_KEYS:
            raise StateError('Escalation cursor entry is malformed')
        chain = next((chain for chain in chains if chain.id == entry['chain']), None)
        if chain is None or entry['condition'] != chain.rule_id:
            raise StateError('Escalation cursor entry belongs to an unknown chain')
        if type(entry['stage']) is not int or not 0 <= entry['stage'] <= len(chain.stages) \
                or entry['status'] not in ('escalating', 'acked', 'suppressed'):
            raise StateError('Escalation cursor entry state is unsupported')
        if entry['suppressed'] is not None and (type(entry['suppressed']) is not int
                                                or not 1 <= entry['suppressed'] <= len(chain.stages)):
            raise StateError('Escalation cursor suppression stage is unsupported')
        if entry['resource_id'] is not None:
            identifier(entry['resource_id'])
        try:
            timestamp(entry['opened_at'])
        except (TypeError, ValueError):
            raise StateError('Escalation cursor opening time is unsupported') from None
    return {'schema_version': CURSOR_VERSION, 'source': document['source'], 'binding': document['binding'],
            'incidents': incidents, 'scan_after': scan_after, 'migrated': migrated}


def save_cursor(path: Path | str, document: Mapping[str, Any]) -> None:
    """Write the cursor atomically, reusing `detection_worker.save` and its fsync discipline.

    The key check is not ceremony: `load_cursor` adds a `migrated` flag to what it returns, and a document
    carrying it into the file would be one this build itself could not read back.
    """
    from .detection_worker import save
    if not isinstance(document, Mapping) or set(document) != CURSOR_KEYS:
        raise StateError('Escalation cursor fields are unknown')
    if type(document['schema_version']) is not int or document['schema_version'] != CURSOR_VERSION:
        raise StateError('Escalation cursor schema version is unsupported')
    _position(document['scan_after'])
    save(Path(path), dict(document))


def _base(payload: Any, *, now: dt.datetime) -> Mapping[str, Any] | None:
    """Return a canonical verdict, holding malformed stored evidence instead of guessing."""
    try:
        validate_event(payload, now)
    except (StateError, ValueError, TypeError, KeyError, RecursionError):
        return None
    return payload


def _chain_for(chains: Sequence[Chain], payload: Mapping[str, Any]) -> Chain | None:
    """Match one verdict to the chain that owns it, in configuration order — in Python, off the page."""
    return next((item for item in chains if item.matches(payload['rule_id'], payload['resource_id'])),
                None)


def _acknowledgement(ack: escalation_reader.Ack | None) -> str | None:
    """Turn the reader's two booleans into the kind of ack this unit counts, or None.

    A decision outranks an intent, as it always did: a person who answered the page *and* decided has
    decided. An incomplete read answers None — which the caller reads as "hold", never as "nobody has
    answered", because the second would send a page over an acknowledgement this round could not see.
    """
    if ack is None or not ack.complete:
        return None
    return ACK_DECISION if ack.decided else (ACK_INTENT if ack.intent else None)


def stage_event(chain: Chain, stage: int, base: Mapping[str, Any], *, source: str,
                now: dt.datetime) -> dict[str, Any]:
    """Build the one canonical event a stage advances to.

    It is a *statement about now* — "this condition is still unacknowledged" — so its window and
    `observed_at` are the current tick, not the incident's: an event stamped with an opening three hours
    ago would be suppressed by `notification_safety` as `event-too-old` and the escalation would die
    quietly, which is the worst possible failure for a pager. The evidence it cites is the base rule and a
    digest binding of incident, stage and the event that opened it; the sample id is a **pointer and not a
    stored evidence row**, so `Store.get_evidence` answers `unavailable` for it (the same honesty
    `platform/configdrift.py` states about its own references).
    """
    rung = chain.stages[stage - 1]
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // STAGE_WINDOW_SECONDS * STAGE_WINDOW_SECONDS,
                                    dt.timezone.utc)
    window = {'start': utc_text(end - dt.timedelta(seconds=STAGE_WINDOW_SECONDS)), 'end': utc_text(end)}
    rule_id = chain.rule_id + '.stage' + str(stage)
    parameters = {'rule_id': chain.rule_id,
                  'sample_id': digest([base.get('resource_id'), base.get('rule_id'), stage,
                                       base.get('source_event_id')])}
    return event(source, base.get('resource_id'), rule_id, base['kind'], 'firing', window, parameters,
                 query_type=base['evidence'][0]['query_type'], version=base['rule_version'],
                 severity=rung.severity())


def posture(store: Store) -> tuple[bool, str | None]:
    """Ask the delivery rail whether a page could arrive at all, through the read it already publishes.

    Returns ``(blocked, reason)``. Blocked means every configured channel's flood breaker is latched, or
    the store's mode is ``off``. `recording` and `live` are both unblocked: a recording sink still books
    the row and still leaves the audit trail, which is how this unit is tested without a channel.
    """
    status = store.notification_safety_status()
    if status['delivery_mode'] == 'off':
        return True, 'notifications-disabled'
    channels = status.get('channels') or {status['channel']: {'circuit_open': status['circuit_open']}}
    if channels and all(row['circuit_open'] for row in channels.values()):
        return True, 'flood-circuit-open'
    return False, None


def record_audit(store: Store, *, now: dt.datetime, actor: str, operation: str, subject: str,
                 detail: Mapping[str, Any] | None = None) -> None:
    """Write one append-only transition row, on the same `Store.audit` path intake uses.

    Its own transaction, deliberately. The cursor this module writes is a JSON file that no database
    rollback can undo, so a transition row that shared a transaction with it could either be lost with a
    failed `os.replace` or claim a stage the cursor never recorded. One row per transition, committed
    before the file that agrees with it, is the ordering that keeps the two auditable independently.

    `operation` is always one of :data:`OPERATIONS`; the five names are what the report, the README row
    and `docs/COMPONENTS.md` agree on, and the audit table is append-only with triggers to enforce it.
    """
    with store.transaction() as connection:
        store.audit(connection, now, actor, operation, subject, dict(detail or {}))


def _discover(page: escalation_reader.Discovery, *, chains: Sequence[Chain],
              tracked: Mapping[str, Any], closing: Sequence[str], summary: dict[str, int],
              start: int, now: dt.datetime) -> tuple[list[tuple[str, Chain, Mapping[str, Any], dt.datetime]], int]:
    """Decide which discovered incidents this round enrolls, and where the walk stops.

    Two rules do all the work, and both are about the position:

    * A row the round examined and settled on — enrolled, already tracked, owned by no chain, or whose
      verdict could not be read — is **behind** the position. The walk advances past it, and a page that
      settled everything it fetched either continues at the last row it saw or, if the table ran out, is
      answered with 0 so the candidates earlier in the table get looked at again.
    * A row the round wanted and could **not** take, because `MAX_TRACKED` is full, is *not* settled: the
      position stays below it and stops moving for the rest of the page, so the next round reaches it again
      as soon as a tracked incident closes. The bound is a capacity limit and must not become a silent drop
      of the work past it — quietly losing the incidents behind a full window is exactly the defect this
      replaced. The count of them is reported in ``capacity``, which is what "we are at the bound and here
      is how much is waiting" looks like from the outside.

    Restarting at 0 on an exhausted page is what keeps the walk fair rather than stuck: old irrelevant open
    incidents ahead of a candidate cost a bounded number of pages per cycle, never a permanent blackout, and
    a candidate that could not be enrolled this cycle is in front of the position again next one.

    Returns the enrollments in rowid order and the position to persist.
    """
    # The incidents closing this round are already paid for: their entries are popped in the same round
    # their rungs ended, so the room they free is real room and refusing to use it would delay a fresh
    # incident by one round for no safety at all. `len(tracked) > MAX_TRACKED` below is the pin that says so.
    room = MAX_TRACKED - (len(tracked) - len(set(closing)))
    settled = start
    accepted: list[tuple[str, Chain, Mapping[str, Any], dt.datetime]] = []
    full = False
    for candidate in page.rows:
        if candidate.incident_id in tracked:
            if candidate.event is None:
                summary['unknown'] -= 1  # Its exact read already counted this missing verdict.
            if not full:
                settled = candidate.rowid          # judged by its exact read already; examined, so settled
            continue
        payload = _base(candidate.event, now=now)
        chain = _chain_for(chains, payload) if payload is not None else None
        if chain is None:
            if payload is None and candidate.event is not None:
                summary['unknown'] += 1
            if not full:
                settled = candidate.rowid          # not ours, or not readable: examined and settled
            continue
        if room <= 0:
            summary['capacity'] += 1
            full = True                            # wanted, not taken: the position stays below it
            continue
        room -= 1
        accepted.append((candidate.incident_id, chain, payload, candidate.opened_at))
        settled = candidate.rowid
    if not full:
        if page.exhausted:
            settled = 0
        elif page.last_rowid is not None:
            # The page ends at a row this round could not describe at all; it was still examined, and the
            # walk has no reason to look at it a second time.
            settled = max(settled, page.last_rowid)
    summary['unknown'] += page.unreadable
    return accepted, settled


def _summary() -> dict[str, int]:
    """The counters one round reports, all of them zero to start with.

    ``enrolled`` newly tracked, ``escalated`` a rung enqueued, ``suppressed`` a due rung the delivery
    posture refused, ``acked``, ``closed`` a ladder ended on a positively read resolution, ``held`` a
    tracked entry this round could not finish judging, ``unknown`` the part of that which is a missing or
    unusable row, ``incomplete`` the part which is an unfinished or refused read, ``capacity`` an
    open incident left untracked because `MAX_TRACKED` was reached, and ``refusals`` the read failures that
    stopped work altogether.
    """
    return dict.fromkeys(('enrolled', 'escalated', 'held', 'suppressed', 'acked', 'closed', 'unknown',
                          'incomplete', 'capacity', 'refusals'), 0)


def tick(store: Store, cursor_path: Path | str, *, chains: Sequence[Chain], source: str,
         now: dt.datetime) -> dict[str, Any]:
    """Advance every tracked incident whose rung is due, and record what the round did.

    The round is three steps and boring: read (one snapshot, tracked incidents by primary key plus one
    bounded discovery page), decide (chains matched in Python, one rung per incident, capacity honoured),
    then write (audits, intakes, and the cursor exactly once). Every branch reports a word; nothing here
    fails quietly, and nothing here sends a notification.

    The read is deliberately *entirely* before the write, including the delivery posture: a round that
    could not read the database holds its rungs and closes nothing, where asking the posture first would
    have had it open a write transaction over a file it could not even read.

    Returns:
        A summary: ``result`` (`idle` | `advanced` | `held` | `refused`), the counters from `_summary`,
        ``tracked``/``max_tracked``, the round's discovery position ``scan_after``, ``unreadable_rows`` for
        the rows the page examined and could not describe, ``incomplete_incidents`` naming every incident
        whose own read did not finish, and the chain ids the round judged. ``capped`` remains a
        diagnostic for a full discovery page, capacity limit or incomplete incident read; it does
        not prevent other incidents with complete evidence from advancing.

    Raises:
        StateError: The cursor cannot be trusted (`load_cursor`) or the source identity is not a bounded
            label. A refused round writes nothing at all, including no cursor. A write that fails mid-round
            propagates as it always did: the cursor is the last thing written, so a round that died half
            way through files no stage the operator cannot see in the audit log.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise StateError('Escalation needs an aware clock')
    label(source)
    if source.startswith(SYNTHETIC_PREFIX):
        raise StateError(f'Escalation source may not start with {SYNTHETIC_PREFIX!r}: the delivery policy '
                         'routes such sources to a recording sink, so a ladder filed under one would '
                         'escalate into nowhere')
    actor = Actor(source, 'producer')
    document = load_cursor(cursor_path, source=source, chains=chains)
    tracked: dict[str, Any] = dict(document['incidents'])
    scan_start = document['scan_after']
    summary = _summary()
    incomplete: list[str] = []
    states: dict[str, Any] = {}
    page: escalation_reader.Discovery | None = None
    enrolled: list[tuple[str, Chain, Mapping[str, Any], dt.datetime]] = []
    acks: dict[str, escalation_reader.Ack] = {}
    live: dict[str, dict[str, Any]] = {}
    closing: list[str] = []
    scan_next = scan_start

    # Read delivery posture first, then establish one snapshot for incident/event/ack reads.
    try:
        with escalation_reader.EscalationReader(store.path, ack_statuses=ACK_STATUSES) as reader:
            blocked, reason = posture(store)
            states = reader.read_incidents(sorted(tracked))
            page = reader.discover(scan_start)
            for incident_id in sorted(tracked):
                entry, state = tracked[incident_id], states[incident_id]
                if state.status == escalation_reader.RESOLVED:
                    closing.append(incident_id)                              # the one fact that ends a ladder
                    continue
                if state.status in (escalation_reader.INCOMPLETE, escalation_reader.REFUSED) \
                        or (state.status == escalation_reader.OPEN
                            and (state.ack is None or not state.ack.complete)):
                    # This incident's own history outgrew its read budget, or the read was refused. Either
                    # way nobody knows whether it was acknowledged, so nobody pages and nothing closes.
                    summary['incomplete'] += 1
                    summary['held'] += 1
                    incomplete.append(incident_id)
                    continue
                payload = _base(state.event, now=now) if state.status == escalation_reader.OPEN else None
                if payload is None:
                    # No such row, a row this build cannot describe, or no readable verdict behind it. All
                    # three are the absence of an answer, and an entry retained costs one rung of patience.
                    summary['unknown'] += 1
                    summary['held'] += 1
                    continue
                chain = _chain_for(chains, payload)
                if chain is None:
                    # No ladder owns this verdict any more. Still not a resolution: held, and the operator
                    # reads `unknown` rather than finding a closed ladder in the audit log.
                    summary['unknown'] += 1
                    summary['held'] += 1
                    continue
                if chain.id != entry['chain']:
                    # The verdict now matches a different ladder than the one this entry was enrolled on.
                    # `binding` refuses a cursor whose chain set changed, so this is a changed database
                    # under a cursor that did not: hold, and let an operator reconcile the two.
                    summary['unknown'] += 1
                    summary['held'] += 1
                    log.warning('Escalation entry no longer matches the chain it was enrolled on',
                                extra={'incident': incident_id, 'enrolled': entry['chain'],
                                       'matched': chain.id})
                    continue
                live[incident_id] = {'chain': chain, 'opened_at': state.opened_at, 'event': payload,
                                     'resource_id': payload['resource_id'],
                                     'ack': _acknowledgement(state.ack)}
            if page.complete:
                enrolled, scan_next = _discover(page, chains=chains, tracked=tracked, closing=closing,
                                                summary=summary, start=scan_start, now=now)
                acks = reader.read_ack([item[0] for item in enrolled])
                for incident_id, *_ in enrolled:
                    ack = acks.get(incident_id)
                    if ack is None or not ack.complete:
                        summary['incomplete'] += 1
                        summary['held'] += 1
                        incomplete.append(incident_id)
            else:
                # The walk could not run. The position is left exactly where it was: a discovery page that
                # failed is not evidence that there is nothing to find, and advancing past it would lose
                # every incident behind it.
                summary['refusals'] += 1
    except StateError:
        # No snapshot, so no verdicts: nothing enrolled, nothing held differently, nothing closed, nothing
        # filed, and the cursor left byte-for-byte as it was. This is the direction in which a pager keeps
        # working and a human who already answered is not paged twice — the round simply does not judge.
        summary['refusals'] += 1
        log.warning('Escalation round refused: history could not be read',
                    extra={'cursor_scan_after': scan_start, 'tracked': len(tracked)})
        return {'result': 'refused', 'chains': [chain.id for chain in chains], 'tracked': len(tracked),
                'max_tracked': MAX_TRACKED, 'scan_after': scan_start, 'incomplete_incidents': [],
                'refused': READ_REFUSAL, 'capped': False, **summary}

    # --- decide: what the round is about to write, said before it writes anything --------------
    if summary['held'] or summary['capacity']:
        # One line per round that could not finish, naming what is outstanding rather than pretending the
        # round judged everything: this is where an operator who wonders why nobody was paged will look.
        log.warning('Escalation round held work it could not finish reading',
                    extra={'held': summary['held'], 'incomplete': summary['incomplete'],
                           'unknown': summary['unknown'], 'capacity': summary['capacity'],
                           'scan_after': scan_next, 'incomplete_incidents': incomplete[:MAX_TRACKED]})

    # --- write -------------------------------------------------------------------------------
    changed = bool(document['migrated'])
    for incident_id in sorted(closing):
        entry = tracked.pop(incident_id)
        record_audit(store, now=now, actor=source, operation='escalation.closed', subject=incident_id,
                     detail={'stage': entry['stage'], 'chain': entry['chain']})
        summary['closed'] += 1
        changed = True
    for incident_id, chain, payload, opened_at in enrolled:
        entry = {'chain': chain.id, 'stage': 0, 'status': 'escalating', 'condition': chain.rule_id,
                 'resource_id': payload['resource_id'], 'opened_at': utc_text(opened_at),
                 'suppressed': None}
        tracked[incident_id] = entry
        record_audit(store, now=now, actor=source, operation='escalation.enrolled', subject=incident_id,
                     detail={'chain': chain.id, 'condition': chain.rule_id,
                             'resource_id': payload['resource_id']})
        if incident_id not in incomplete:
            live[incident_id] = {'chain': chain, 'opened_at': opened_at, 'event': payload,
                                 'resource_id': payload['resource_id'],
                                 'ack': _acknowledgement(acks.get(incident_id))}
        summary['enrolled'] += 1
        changed = True

    for incident_id in sorted(live):
        entry = tracked[incident_id]
        current = live[incident_id]
        chain: Chain = current['chain']
        kind = current['ack']
        if kind and entry['status'] != 'acked':
            entry['status'] = 'acked'
            record_audit(store, now=now, actor=source, operation='escalation.acknowledged',
                         subject=incident_id, detail={'stage': entry['stage'], 'chain': chain.id,
                                                      'evidence': kind})
            summary['acked'] += 1
            changed = True
        if entry['status'] == 'acked':
            continue
        due = chain.stage_for(opened_at=current['opened_at'], now=now, last=entry['stage'])
        if due is None:
            continue
        if blocked:
            if entry['suppressed'] != due:
                entry['suppressed'] = due
                record_audit(store, now=now, actor=source, operation='escalation.suppressed',
                             subject=incident_id, detail={'stage': due, 'chain': chain.id, 'reason': reason})
                summary['suppressed'] += 1
                changed = True
            continue
        rung_event = stage_event(chain, due, current['event'], source=source, now=now)
        outcome = store.intake(rung_event, actor, now=now)
        entry['stage'] = due
        entry['suppressed'] = None
        record_audit(store, now=now, actor=source, operation='escalation.stage', subject=incident_id,
                     detail={'stage': due, 'chain': chain.id, 'condition': rung_event['rule_id'],
                             'event_id': outcome['event_id'], 'transition': outcome['transition']})
        summary['escalated'] += 1
        changed = True

    if len(tracked) > MAX_TRACKED:
        raise StateError('Escalation would track more incidents than its bound')
    # Scan progress is written even when no tracked incident changed: it is the only thing that remembers
    # how far into a large open-incident set this scheduler has looked, and a round that recomputed it from
    # zero every time would never cross the noise to reach the incident behind it.
    if changed or scan_next != scan_start:
        save_cursor(cursor_path, {'schema_version': CURSOR_VERSION, 'source': source,
                                  'binding': binding(chains), 'incidents': tracked,
                                  'scan_after': scan_next})
    result = 'idle'
    if summary['escalated'] or summary['enrolled'] or summary['acked'] or summary['closed'] \
            or summary['suppressed']:
        result = 'advanced'
    elif summary['held'] or summary['incomplete'] or summary['refusals']:
        result = 'held'
    return {'result': result, 'chains': [chain.id for chain in chains], 'tracked': len(tracked),
            'max_tracked': MAX_TRACKED, 'scan_after': scan_next,
            'incomplete_incidents': sorted(incomplete),
            'capped': bool(summary['capacity'] or summary['incomplete']
                           or (page is not None and page.complete and not page.exhausted)),
            'unreadable_rows': (page.unreadable if page is not None and page.complete else 0),
            **summary}

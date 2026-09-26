"""Flap folding and maintenance windows: a suppression is a state, never a silence.

v0.1's ``aiops/dedup`` did two jobs this repository had only done half of. ``dedup.py`` collapsed
repeats and counted state transitions so one oscillating resource surfaced once instead of forty;
``suppression.py`` wrapped an event in ``suppressed=True`` plus a sentence saying what silenced it (a
parent that is down, a dependency path, a maintenance window) instead of dropping it, and reported the
noise reduction so the claim was measured. **The state is ported; the in-memory key cache is not** —
port-table §6 names that as the whole delta: a cache that forgets on restart re-pages, which is the
defect this row exists to remove. Every input to a decision here is a row this database already holds,
so a fresh process recomputes the same answer, and nothing in this module keeps a dict between calls.

What was already right, and what was missing (measured on ``main``): ``Store.intake`` files a condition
under ``digest([source, rule_id, rule_version, resource_id, condition])`` — the field carrying
fire/resolve, ``status``, is *not* in that key, so a fire/resolve/fire flap already lands in **one**
``conditions`` row. What intake did not do is *notice* the flap: each transition still booked its own
outbox row, so one oscillating rule paged once per edge (page, recovery, page, recovery) and could
out-pager an incident. ``condition_key`` below is that same formula, spelled once, and
``tests/test_flap_folding.py`` asserts it against a ``conditions`` row that a real ``intake`` wrote —
that pin is what keeps a second identity from growing here the way v0.1's
``core/events.py`` grew one (``derive_dedup_key``): two keys for one finding were possible there,
and are not here.

The three causes, in the order they are consulted, because precedence is a claim:

* **a maintenance window** — a human said this resource or this rule is under work until ``ends_at``;
* **a dependency** — an upstream resource of this one holds an *open incident*, so this finding is a
  symptom of something already paged (`local_observe/topology.py`, declared plane only);
* **flap folding** — this condition has flipped ``flap_threshold`` or more times inside
  ``window_seconds``, counting the transition being decided right now.

The first cause that applies writes the reason and the others are not consulted for the sentence: two
reasons for one silence are two stories to check and one of them is redundant. A human declaration
outranks a structural inference, which outranks a statistic.

**Nothing is dropped, and that is checkable three ways.** The event is filed first, by
`Store.intake` — the only method in this repository that writes `events`, `conditions` and the outbox —
so a suppressed finding is still a finding an operator can list, and still the row that opened or
resolved the incident. The delivery that transition booked is refused — in that same commit — the way
every other refusal is: `status='dead'` plus a `notification_suppressions` row plus a
`notification.suppressed` audit row, the trio `Store.claim_notification` itself writes for a budget
refusal, so the durable refusal list stays one table with one meaning. And `platform/presentation.py`
already renders that row as ``… (suppressed: <reason>)`` in the outbox view — which is why this module
writes a *sentence* and not a code, and why it needed no change to the presentation layer to be visible.

Two consequences of reusing that table are stated where they bite. A folded page is unreplayable,
because `Store.retry_notification` refuses any delivery holding a suppression row (the same posture it
takes towards a discarded backlog); the finding is not gone, the page is. And
`claim_notification`'s head-of-queue clause already steps over suppressed rows, which is what stops a
folded page from holding up the one behind it.

**Where a window is stored, and what stands in for its CHECK.** A declaration is one key in control state's
`notification_control` table (`state.maintenance_key`), not a table of its own, and the reasoning is
recorded in `state.py` above `MIGRATIONS`: what that choice gives up is a constraint in the file, so the
same two bounds are refused twice in this module instead (at declaration,
and again at every read, which is the only door through which a window can reach a pager), and every
window carries the `audit` sequence of the `maintenance.declared` row that created it: a control row that
no append-only audit row attests is counted `unattested` and silences nothing, and one whose declared text
has moved since does not match its attestation either. Rows are never deleted, so the read is schema v5's
bounded indexed query — declared, unrevoked, not yet expired, at most `MAX_WINDOW_ROWS` candidates — and
past that nothing is applied: the loud direction, because a suppression mechanism that cannot see is one
that pages. An expired or revoked declaration spends no candidate slot; only a live one does.

v0.1 wrapped the *event* in `suppressed=True`, and this module deliberately does not: the canonical event
is the intake path's idempotency fingerprint (`events.fingerprint`, and `Store.intake` refuses a retry
whose contents moved with "Event retry changed contents"), so stamping a verdict into the payload would
make the same finding two different events depending on what the delivery rail was doing at the moment it
arrived. The suppression therefore lives beside the event, on the delivery — which is also the honest
place for it, because what is being suppressed is a page and not a finding. The consequence for a reader
is that `records('events')` shows no suppression column and the outbox view shows the sentence.

Ordering is the whole defect, and it has two halves that pull opposite ways: the event must be filed
**before** it is decided (the flap count has to include the transition being decided, or a rule with
``threshold=2`` pages twice for its first pair of edges), and the fold must **commit with the filing** (or
the page sits ``pending`` in the gap between two transactions, where a notifier can lease it). So
`file_event` hands `Store.intake` an admission callback, called **on intake's own connection after its
audit row and before the commit**: every read the decision makes sees the rows this admission wrote, a
competing `claim_notification` waits on that write lock and is handed a row already ``dead``, and a
callback that raises rolls the whole admission back rather than leave a finding filed beside an
undecided send.

The count is therefore "including this one", and the default threshold of 4 lets the first three pages of
an episode through and folds everything after
them while the episode stays inside the window. Once the window ages out, folding stops and a *new*
episode pages again: folding is a bound on noise, never a way to stop reporting a condition that came
back.

**A grouped condition has no `incidents` rows for the part of its life it spent inside a group**, and the
count reads that part where it survives: `incident_members` (correlation's rationale table) holds one row per
member-and-group, and each one names an opening whose incident row `Store._join_group` deleted. Those
edges are reported as `absorbed`, added to `transitions`, and — because a group also swallows the
member's *recoveries*, which leave no dateable row anywhere in this schema — any non-zero `absorbed`
makes the answer a stated **floor** (`complete: False`, so the reason reads "at least"). Before correlation followups
the
member's edges were simply missing and the number looked exact, which is the difference between a fold
that under-pages and one that silently lies.

Fail-closed means fail-*loud* here, and every unknown goes the loud way: a window this build cannot
parse or that breaks its own bound is not applied, a dependency walk that reports truncation suppresses
nothing, a graph that is not configured suppresses nothing, an outbox row that has left ``pending`` is
never rewritten, and a condition scan that hit its read bound says so instead of quoting an exact
number it does not have. The failure mode of a pager is the page that did not go out.
"""
from contextlib import closing, contextmanager
from dataclasses import dataclass
import datetime as dt
import json
import math
from pathlib import Path
import re
import sqlite3
from typing import Any
from collections.abc import Iterator
import uuid

from local_observe import topology
from local_observe.inventory.validation import InvalidInventory, canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from .state import (Actor, GROUPING_TABLE, MAINTENANCE_WINDOW_END, MAINTENANCE_WINDOW_INDEX,
                    MAINTENANCE_WINDOW_KEYS, MAINTENANCE_WINDOW_LIVE, StateError, Store, clock,
                    control_declare, control_write, identifier, label, maintenance_key, notification_id,
                    record_suppression, require, validate_event)

log = get_logger(__name__)

#: The audit vocabulary this module adds. `notification.suppressed` is shared with
#: `state.Store.claim_notification` on purpose: it is the same fact (this delivery may never be sent)
#: decided for a different reason, and the reason lives in the row's `detail`.
OPERATIONS = ('maintenance.declared', 'maintenance.revoked', 'notification.suppressed')
#: The bounded cause words, and the first token of every reason sentence this module writes. The
#: bucketing in `stats()` reads that first token, so a new cause is a word here and nothing else.
CAUSES = ('maintenance-window', 'dependency', 'flapping')
#: Whose name the audit row carries when a fold or a window kills a send. Not the producer that filed
#: the event — the producer silenced nothing — and not a human either, unless one opened a window, in
#: which case `author` in the window row names them. `state.MIGRATE_ACTOR` is the precedent for a
#: decision this module makes about a row rather than a person making a decision.
WORKER_ACTOR = 'suppression-worker'

# --- flap folding ---------------------------------------------------------------------------
#: How far back a flap episode is counted, and the bounds an operator may move it within. 300 s and 4
#: transitions are v0.1's `flap_window_s`/`flap_threshold` defaults. A window shorter than a rule's own
#: `resolve_seconds` cannot see a flap at all, because hysteresis (`platform/conditions.py`) already
#: stopped the transitions: folding and hysteresis are two different answers to one oscillation, and a
#: rule that is already damped has nothing here left to fold.
FLAP_WINDOW_SECONDS = 300
FLAP_WINDOW_BOUNDS = (60, 86400)
#: A threshold below 2 would fold the *first* page of an episode, i.e. silence an incident nobody has
#: been told about. The floor is what makes "never fold the first page" true by construction rather than
#: by a caller remembering to pass a sane number.
FLAP_THRESHOLD = 4
FLAP_THRESHOLD_BOUNDS = (2, 100)
#: Rows read per side of one condition's transition count. Above the highest threshold this module
#: accepts, so a scan that hits the bound has already earned the verdict it reports; what it loses is
#: the exact number, which is why the reason then reads "at least".
MAX_TRANSITION_ROWS = 200
#: How many distinct conditions `stats()` walks. A sample, named as one: `conditions_observed` says
#: what was scanned, `conditions_total` says what exists.
MAX_SCANNED_CONDITIONS = 64

# --- windows as control state ---------------------------------------------------------------
#: The longest window this build will store. There is no CHECK carrying it (see the choice recorded above
#: `state.MIGRATIONS`), so it is refused twice in this module instead: once at declaration and once at
#: every use, by `live_windows`, which is the only door through which a window can reach a pager. 24 h is
#: also longer than the planned work a pager is expected to sleep through; a job needing more renews by
#: declaring the next window, which is what makes a forgotten window visible instead of permanent.
MAX_WINDOW_SECONDS = 86400
#: How many unexpired, unrevoked windows may exist at once. Past this the live set is not read at all
#: (see `live_windows`): the module no longer knows it saw the window covering this event, and picking
#: one of a hundred declarations to blame for a silence is not a decision worth a missed page.
MAX_LIVE_WINDOWS = 32
#: How many *candidates* one read walks — declared, unrevoked windows whose stored end is still ahead of
#: the instant being read. Schema v5's index answers exactly that set, so a lifetime of expired or revoked
#: declarations costs this bound nothing (it used to spend it, which is how old history silenced every new
#: window). The bound is what makes the scan finite rather than merely fast: past it this module cannot
#: claim it saw the window covering this finding, so it applies none and says `bound_exceeded` — which
#: pages. Rows are never deleted, so this is a budget of *live* declarations and not a history limit.
MAX_WINDOW_ROWS = 512
#: The reason an operator types is what the portal prints after "suppressed: ", so it is one printable
#: line, bounded, stored verbatim rather than reflowed by this module.
REASON_PATTERN = re.compile(r'^[^\x00-\x1f\x7f]+$')
MAX_REASON_CHARS = 200
#: The bound on a whole composed sentence. A column width, not a judgement.
MAX_SUPPRESSION_CHARS = 400
#: The two selector shapes, and the whole key set a declaration may name. A window covers one resource
#: *or* one rule and nothing else: v0.1's selector was an expression language over inventory attributes
#: (`key=value AND …`) and its own docstring recorded the failure mode as "degraded visibly by simply
#: not suppressing — never guessed". Exact match on a canonical UUID or a `label()` has no such mode: it
#: either matches the event or it does not, and a rule id that matches nothing simply pages as usual.
SELECTOR_KEYS = ('resource_id', 'rule_id')
WINDOW_KEYS = ('resource_id', 'rule_id', 'starts_at', 'ends_at', 'reason')
#: The envelope one stored window occupies under its key, and the version of that envelope. `declared` is
#: the block a human authored and the audit row attests byte for byte; `revoked` is the only thing this
#: module ever adds to a stored window; `attest` is the `audit` sequence of the `maintenance.declared`
#: row. That third field is what stands in for the CHECK the typed table would have had: a control row
#: that no append-only audit row names is never applied, whatever else it claims, so "a window exists"
#: means "a human's declaration of it survives in the one table that cannot be rewritten". Checking it
#: costs one primary-key lookup per candidate window, on the read path, and nothing at all on the write.
WINDOW_DOCUMENT_VERSION = 1
WINDOW_DOCUMENT_KEYS = ('schema_version', 'declared', 'revoked', 'attest')
#: The declared block's whole field set, in the shape the audit detail stores it. A stored window with an
#: extra or a missing field is not a window this build declared, and is not applied.
DECLARED_KEYS = ('id', 'resource_id', 'rule_id', 'starts_at', 'ends_at', 'reason', 'author',
                 'declared_at')
#: The two fields a revocation adds. Stored window rows carry them as null until then, so the shape a
#: reader sees is the shape the typed table had and no caller has to branch on where the state lives.
REVOKE_KEYS = ('revoked_at', 'revoked_by')

# --- dependency suppression -----------------------------------------------------------------
#: One hop by default — the same bound `platform/presentation.py` labels its incident view with. Deeper
#: walking is allowed and bounded, but how far a symptom travels is a claim, so it is asked for.
DEPENDENCY_DEPTH = 1
MAX_DEPENDENCY_DEPTH = 4
#: The row bound of one upstream walk (`topology.Topology.max_rows`).
MAX_DEPENDENCY_NODES = 20
#: How many open incidents the read of "what is down right now" may walk before it stops answering. A
#: store holding more than this is in an outage, and suppressing child findings against a *sample* of
#: the down set could blame the wrong parent, so it suppresses nothing and says `truncated`.
MAX_FIRING_RESOURCES = 200
#: How many resource ids one reason sentence may print. The path itself is bounded by
#: `MAX_DEPENDENCY_DEPTH`; this bounds the *label*.
PATH_NODES = 4


@dataclass(frozen=True)
class Decision:
    """What one event's delivery was told, and why — the record of a suppression, not a filter.

    `suppressed` is the only field a caller acts on. Everything else is what an operator or a later
    reader needs in order to disbelieve it: which condition was looked at, which cause won, the sentence
    that goes into `notification_suppressions`, and the numbers that cause was computed from.
    """

    condition: str
    suppressed: bool
    cause: str | None = None
    reason: str | None = None
    transitions: int = 0
    detail: dict | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the decision in the shape the CLI prints and a log line carries."""
        return {'condition': self.condition, 'suppressed': self.suppressed, 'cause': self.cause,
                'reason': self.reason, 'transitions': self.transitions, 'detail': self.detail or {}}


def condition_key(event: dict[str, Any]) -> str:
    """Return the `conditions.key` one canonical event belongs to — the key `Store.intake` writes.

    The state marker is *already* folded out here, and that is the interesting fact about this port: the
    field carrying fire/resolve is ``status``, and ``status`` is not an input to this digest, so a whole
    flap episode shares one `conditions` row. What the key holds is the identity of the *judgement*: who
    filed it, which rule and which version of it, on which resource, and which condition of that rule
    (``condition``, which every producer here sets to its own ``rule_id`` — the ``.stage<N>`` and
    ``.coverage`` suffixes in `platform/escalation.py` and `platform/conditions.py` are how one producer
    keeps a companion verdict off another's incident).

    This expression matches `Store.intake`. `tests/test_flap_folding.py` compares it
    with a row written by real intake so an identity change cannot silently split a
    condition into separate incidents.

    Raises:
        StateError: A canonical event field is missing. The `KeyError` is converted so this module has
            one refusal sentence, the way `state.identifier` converts `uuid`'s.
    """
    try:
        return digest([event['source'], event['rule_id'], event['rule_version'],
                       event['resource_id'], event['condition']])
    except KeyError as exc:
        raise StateError(f'Event is missing {exc.args[0]}') from None


def transitions(store: Store, condition: str, *, window_seconds: int = FLAP_WINDOW_SECONDS,
                now: dt.datetime | None = None) -> dict[str, Any]:
    """Count this condition's fire/resolve transitions inside the flap window, from durable rows only.

    The read-only form of `_transitions`, for a caller that is not inside the transaction whose rows it
    is counting. Same answer, same bounds, same refusals; `file_event` is the caller that cannot use it.
    Includes the openings a group absorbed (`absorbed`), and says `complete: False` when it did.
    """
    with _readonly(store) as db:
        return _transitions(db, condition, window_seconds=window_seconds, now=now)


def _transitions(connection: sqlite3.Connection, condition: str, *,
                 window_seconds: int = FLAP_WINDOW_SECONDS,
                 now: dt.datetime | None = None) -> dict[str, Any]:
    """`transitions` against a connection the caller owns — the shape a decision inside a write needs.

    A transition is an `incidents` row appearing — `Store.intake` writes one per firing event that finds
    no open incident — or an existing row flipping to ``resolved``, which happens once, per resolved
    event that found one. That is the whole mechanism, and it is why the count survives a restart with
    no state of its own: `intake` writes `events`, `conditions` and `incidents` in one transaction, so
    the rows that *make* a condition are the same rows that count its edges. The instant of a resolve is
    that row's `updated_at`, which is write-once for a resolved incident: `intake` sets the condition's
    `incident_id` to NULL on the resolve, so nothing attaches to that row again and moves the stamp.

    **A grouped condition leaves `incidents` for part of its history, and the third component counts
    what that first read cannot see** — see `_count_transitions` for the absorbed openings and why the
    count then stops being exact.

    Two bounds, both stated in the answer. `window_seconds` is the horizon, refused outside
    `FLAP_WINDOW_BOUNDS` rather than clamped. `complete` is False when either side hit
    `MAX_TRANSITION_ROWS`, or when any opening was absorbed by a group, which makes `transitions` a
    **floor**: the verdict is still earned (the cap sits above every threshold this module accepts), the
    number is not exact. A row this build cannot date is not counted at all — `julianday()` answers
    NULL, the comparison answers NULL, the row drops out — which is the direction that pages rather than
    the one that folds.

    Rows this connection wrote and has not yet committed are counted, which is the only reason
    `file_event` can fold an episode correctly: the transition being decided is one of the edges.
    """
    seconds = _bound('window_seconds', window_seconds, *FLAP_WINDOW_BOUNDS)
    finish = clock(now)
    return _count_transitions(connection, condition, utc_text(finish - dt.timedelta(seconds=seconds)),
                              utc_text(finish), seconds)


def flapping(store: Store, event: dict[str, Any], *, window_seconds: int = FLAP_WINDOW_SECONDS,
             threshold: int = FLAP_THRESHOLD, now: dt.datetime | None = None) -> dict[str, Any]:
    """Return this event's condition key, its transition count, and whether the count reached the bound.

    The read-only form of `_flapping`; see `transitions` for why the two exist.
    """
    with _readonly(store) as db:
        return _flapping(db, event, window_seconds=window_seconds, threshold=threshold, now=now)


def _flapping(connection: sqlite3.Connection, event: dict[str, Any], *,
              window_seconds: int = FLAP_WINDOW_SECONDS, threshold: int = FLAP_THRESHOLD,
              now: dt.datetime | None = None) -> dict[str, Any]:
    """`flapping` against a connection the caller owns, counting whatever that connection has written.

    The count is taken over the condition key and not over the event, because an episode is a property
    of the condition: a fire and the resolve that follows are two edges of one thing, not two rules.
    `transitions` includes the transition this event represents, which is what makes the first page of an
    episode always go out — `FLAP_THRESHOLD_BOUNDS` refuses anything that would fold it.

    The absorbed openings of a grouped member are read here too (`_count_transitions`), which is what
    makes a member of a group reach its threshold on the edges it actually made instead of the subset
    that still has an `incidents` row named for it.
    """
    condition = condition_key(event)
    counted = _transitions(connection, condition, window_seconds=window_seconds, now=now)
    counted['threshold'] = _bound('flap_threshold', threshold, *FLAP_THRESHOLD_BOUNDS)
    counted['flapping'] = counted['transitions'] >= counted['threshold']
    counted['condition'] = condition
    return counted


# --- windows as control state ---------------------------------------------------------------

def window_id(declaration: dict[str, Any]) -> str:
    """Return the identity of one window: a digest of everything the declaration asserts.

    Content-addressed, so the same declaration typed twice is one row (`declare_window` answers the
    second as a duplicate instead of adding a second silence over the same work) and any edit — a later
    end, a different reason — is a different window with its own row and its own audit entry. The author
    is deliberately not an input: who declared it is recorded in the row and in the audit log, and a
    window is not a different promise because a second person entered it.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
                          canonical([[key, declaration[key]] for key in WINDOW_KEYS
                                     if declaration.get(key) is not None])))


def declare_window(store: Store, declaration: dict[str, Any], actor: Actor, *,
                   now: dt.datetime | None = None) -> dict[str, Any]:
    """Record a human's maintenance window, and refuse everything about it that is not bounded.

    Only role ``human`` may open one. A ``producer`` credential asking for a window is refused the way
    `Store.decide` and `Store.retry_notification` refuse it: a detector able to declare the window
    covering its own findings is a detector able to silence its own pager, and the point of the role gate
    is that the thing being suppressed cannot suppress itself.

    Args:
        store: The platform database the window is recorded in.
        declaration: Exactly one of `resource_id` / `rule_id` (both or neither is a refusal), plus
            `starts_at`, `ends_at` and a one-line `reason` of at most `MAX_REASON_CHARS`.
        actor: Must carry role ``human``; its identity is stored as `author`.
        now: The aware clock the declaration is checked against.

    Returns:
        ``{'status': 'declared' | 'duplicate', 'id': ..., 'window': {...}}``. A duplicate writes nothing
        — no row, no audit line — because the declaration it repeats is already the durable fact, and it
        reports the window as stored, including who first declared it.

    Raises:
        StateError: The role is not ``human``; the selector is not exactly one of the two shapes; a
            timestamp is unparseable, unordered, empty-spanned or longer than `MAX_WINDOW_SECONDS`; the
            window is already over at the moment it is declared; the reason is not one printable bounded
            line; an unknown key is present; `MAX_LIVE_WINDOWS` windows are already live; or the candidate
            read is already past `MAX_WINDOW_ROWS`, which is a silence this build cannot promise to apply.
    """
    require(actor, 'human')
    now = clock(now)
    unknown = set(declaration) - set(WINDOW_KEYS)
    if unknown:
        raise StateError('Unknown maintenance window field: ' + ','.join(sorted(unknown)))
    if sum(1 for key in SELECTOR_KEYS if declaration.get(key) is not None) != 1:
        raise StateError('A maintenance window names exactly one resource_id or one rule_id')
    start, end = _instant(declaration.get('starts_at')), _instant(declaration.get('ends_at'))
    span = (end - start).total_seconds()
    if not 0 < span <= MAX_WINDOW_SECONDS:
        raise StateError(f'A maintenance window must last between one second and {MAX_WINDOW_SECONDS} s;'
                         ' an open-ended window is refused')
    if end <= now:
        raise StateError('A maintenance window that is already over cannot be declared; declare the work')
    reason = declaration.get('reason')
    if (not isinstance(reason, str) or not 1 <= len(reason) <= MAX_REASON_CHARS
            or reason != ' '.join(reason.split()) or not REASON_PATTERN.match(reason)):
        raise StateError('A maintenance window needs a one-line printable reason'
                         f' of at most {MAX_REASON_CHARS} characters')
    resource_id, rule_id = declaration.get('resource_id'), declaration.get('rule_id')
    if resource_id is not None:
        identifier(resource_id)
    if rule_id is not None:
        label(rule_id)
    declared = {'id': window_id(declaration), 'resource_id': resource_id, 'rule_id': rule_id,
                'starts_at': utc_text(start), 'ends_at': utc_text(end), 'reason': reason,
                'author': actor.identity, 'declared_at': utc_text(now)}
    key = maintenance_key(declared['id'])
    with store.transaction() as connection:
        stored = connection.execute('SELECT value FROM notification_control WHERE key=?', (key,)).fetchone()
        if stored is not None:
            # The identical declaration is already stored; hand back what the file holds, including the
            # author who got there first, rather than a record of the attempt that wrote nothing. The
            # order matters: asking after the duplicate *first* is what keeps a re-typed declaration from
            # leaving a second audit row for a fact the log already holds.
            return {'status': 'duplicate', 'id': declared['id'], 'window': _readable_window(stored['value'])}
        candidates = _scan(connection, now)
        if candidates['bound_exceeded'] or candidates['scanned'] >= MAX_WINDOW_ROWS:
            # Reserve a candidate slot for the declaration being inserted in this transaction.
            raise StateError('Maintenance window candidates exceed the read bound of this build;'
                             ' reconcile them before declaring a window it cannot promise to apply')
        if candidates['count'] >= MAX_LIVE_WINDOWS:
            raise StateError(f'A platform may hold at most {MAX_LIVE_WINDOWS} live maintenance windows;'
                             ' revoke one or wait it out before declaring another')
        # The declaration is audited *before* it is stored, in this same transaction, and the row's
        # sequence is written into what gets stored: `audit` is the one table here with append-only
        # UPDATE and DELETE triggers, so the audit entry is not a record of a decision but the evidence
        # of one. A control row with no matching audit row silences nothing (`_attested`), which is how
        # a bound that lives in this module rather than in a CHECK still cannot be forged by editing a
        # file, only by writing the log — and writing the log honestly is what this method just did.
        store.audit(connection, now, actor.identity, 'maintenance.declared', declared['id'], declared)
        document = {'schema_version': WINDOW_DOCUMENT_VERSION, 'declared': declared, 'revoked': None,
                    'attest': int(connection.execute('SELECT last_insert_rowid()').fetchone()[0])}
        control_declare(connection, key, canonical(document), now)
    return {'status': 'declared', 'id': declared['id'],
            'window': dict(declared, revoked_at=None, revoked_by=None)}


def revoke_window(store: Store, window: str, actor: Actor, *,
                  now: dt.datetime | None = None) -> dict[str, Any]:
    """Close a declared window early — once, by a human, audited.

    A window swallows pages until its `ends_at`, so work that was cancelled or finished early would
    leave the pager asleep for the rest of a period nobody is causing findings in, and refusing to revoke
    would make `MAX_WINDOW_SECONDS` the length of the silence regardless of what the work did. There is no
    *edit* path on purpose: `control_declare` inserts and never updates, so the declared block a human
    authored cannot be widened after the fact, and the one write this method makes adds the revoke pair to
    the envelope. Revoking is not deleting: the stored document keeps its selector, its times and its
    author, and the audit log holds both ends.

    The two directions are not symmetric, and that is deliberate. Reading a declaration is what silences a
    pager, so anything this build cannot fully verify is never applied; *revoking* can silence nothing, so
    it is accepted on a document whose bounds or attestation have failed — a row nobody can prove was
    declared still gets a human's signature on its cancellation rather than being stuck in the table
    forever. It is not applied either way, so nothing here is trusting it.

    Raises:
        StateError: The role is not ``human``, the id is not a canonical UUID naming a stored window, the
            stored document is not readable enough to be signed for what it is, or that window is already
            revoked.
    """
    require(actor, 'human')
    now = clock(now)
    identifier(window)
    key = maintenance_key(window)
    with store.transaction() as connection:
        row = connection.execute('SELECT value FROM notification_control WHERE key=?', (key,)).fetchone()
        if row is None:
            raise StateError('No such maintenance window')
        document = _envelope(row['value'])
        if document is None:
            raise StateError('Maintenance window declaration is unreadable; it applies to nothing and'
                             ' needs a human to reconcile it')
        if document['revoked'] is not None:
            raise StateError('Maintenance window is already revoked')
        document['revoked'] = {'revoked_at': utc_text(now), 'revoked_by': actor.identity}
        control_write(connection, key, canonical(document), now)
        store.audit(connection, now, actor.identity, 'maintenance.revoked', window,
                    {'ends_at': document['declared']['ends_at'], 'revoked_at': utc_text(now)})
    return {'status': 'revoked', 'id': window, 'revoked_at': utc_text(now)}


def live_windows(store: Store, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Every window that is neither revoked nor expired, and every way this build would refuse to trust one.

    Reads are refused rather than guessed. A document this build cannot read to the end — not the envelope
    it writes, not the version it knows, a timestamp it cannot parse, a span over `MAX_WINDOW_SECONDS`, a
    selector that is both or neither — is counted in `unusable` and left out. So is one whose
    `maintenance.declared` audit row is missing or says something else (`unattested`): the typed-table
    version of this state had CHECKs in the file, and the attestation is what this shape has instead,
    checked on every read because a control row can be copied into a file while the log it points at
    cannot be rewritten. `bound_exceeded` is the third way the answer stops being safe — more candidates
    than `MAX_WINDOW_ROWS`, or more live ones than `MAX_LIVE_WINDOWS` — and it means this module can no
    longer claim it saw the window covering an event, so `covering_window` applies none of them. Expired
    and revoked rows are never read at all (schema v5's index over the stored documents), so `scanned`,
    `revoked` and `expired` describe the candidates this bounded query looked at and never the lifetime of
    declarations the file holds.

    Returns:
        ``{'windows': [...], 'count': int, 'scanned': int, 'bound_exceeded': bool, 'unusable': int,
        'unattested': int, 'revoked': int, 'expired': int, 'max_live_windows': int,
        'max_seconds': int, 'max_rows': int}``, ordered by (starts_at, id) so a replay of the read is
        deterministic, and each window carries `covers_now` plus the two null revoke fields until one is
        revoked. Every count is of candidates, not of history.
    """
    now = clock(now)
    with _readonly(store) as db:
        return _scan(db, now)


def covering_window(store: Store, event: dict[str, Any], *,
                    now: dt.datetime | None = None) -> dict[str, Any] | None:
    """The live window covering this event's resource or rule, or None when nothing does.

    The read-only form of `_covering_window`, on the store's file rather than on a caller's connection.
    """
    with _readonly(store) as db:
        return _covering_window(db, event, now=now)


def _covering_window(connection: sqlite3.Connection, event: dict[str, Any], *,
                     now: dt.datetime | None = None) -> dict[str, Any] | None:
    """`covering_window` against a connection the caller owns.

    Matching is exact and per-event: a window on a resource covers every finding about that resource, a
    window on a rule covers that rule wherever it files. `_scan` has already refused the four ways the
    answer could be wrong (an unreadable row, an unattested one, a set past its bound, a scan past its
    row limit), so None here means "no window applies" and never "no window could be read".
    """
    answer = _scan(connection, clock(now))
    if answer['bound_exceeded']:
        return None
    for window in answer['windows']:
        if not window['covers_now']:
            continue
        if window['resource_id'] is not None and window['resource_id'] == event['resource_id']:
            return window
        if window['rule_id'] is not None and window['rule_id'] == event['rule_id']:
            return window
    return None


# --- dependency suppression -----------------------------------------------------------------

def firing_resources(store: Store) -> dict[str, Any]:
    """Which resources hold an open incident right now, and whether that answer is whole.

    ``status='open'`` on `incidents` is the durable form of "this condition is firing": `Store.intake`
    opens the row on a firing transition and closes it on a resolved one, so no second down-state map is
    kept here. v0.1 kept exactly such a dict in `DependencySuppressor._down`, and it is the thing that
    came back empty after a restart. The rule id printed in a reason comes from the event that incident
    last saw, read with `json_extract` rather than re-derived into a second identity.

    The read-only form of `_firing_resources`, on the store's file rather than on a caller's connection.

    Returns:
        ``{'resources': {resource_id: {'rule_id': ..., 'incident_id': ...}}, 'truncated': bool}`` —
        truncated when more rows existed than `MAX_FIRING_RESOURCES`, which is read as "do not suppress"
        by every caller.
    """
    with _readonly(store) as db:
        return _firing_resources(db)


def _firing_resources(connection: sqlite3.Connection) -> dict[str, Any]:
    """`firing_resources` against a connection the caller owns.

    An incident this connection opened and has not committed yet is in the answer, which is what lets one
    admission see a parent it just filed as the reason to fold a child's page.
    """
    rows = connection.execute('SELECT i.resource_id AS resource_id, i.id AS incident_id,'
                              " json_extract(e.payload,'$.rule_id') AS rule_id"
                              ' FROM incidents i JOIN events e ON e.id=i.last_event_id'
                              " WHERE i.status='open' AND i.resource_id IS NOT NULL"
                              ' ORDER BY i.rowid DESC LIMIT ?', (MAX_FIRING_RESOURCES + 1,)).fetchall()
    truncated = len(rows) > MAX_FIRING_RESOURCES
    resources: dict[str, Any] = {}
    for row in rows[:MAX_FIRING_RESOURCES]:
        resources.setdefault(row['resource_id'], {'rule_id': row['rule_id'], 'incident_id': row['incident_id']})
    return {'resources': resources, 'truncated': truncated}


def dependency(store: Store, event: dict[str, Any], *, index_path: Path | str | None = None,
               graph: Any = None, depth: int = DEPENDENCY_DEPTH) -> dict[str, Any] | None:
    """Why this finding is a symptom of something already paged, or None when it stands on its own.

    Direction follows `local_observe/topology.py`: an edge means *src depends on dst*, so `upstream()` is
    everything this event's resource rests on, and a child's finding is a symptom when one of those rests
    on a resource holding an open incident. The **nearest** such parent is blamed (fewest hops, then
    resource id, as v0.1 did) so the reason names one thing an operator can go and look at, and the path
    that reaches it is printed beside it: an explanation nobody can walk is a guess.

    Every way the answer can be incomplete ends in *no suppression* — no index configured, the resource
    not declared, the index unreadable, a hop that ran out of rows, the open-incident read truncated, a
    chain the walk never showed. A fold that was not earned is the failure this module is built to avoid;
    a page that went out during an outage is noise by comparison. One truncation is tolerated and it is
    named in the answer rather than hidden: a walk cut at its *depth* bound can only have missed nodes
    further out than every node it returned, and this blames the nearest down parent it did see, so the
    cut cannot have chosen a worse blame (`graph_cut_at_depth_bound` says the graph reaches further).

    Args:
        store: The platform database holding the open incidents.
        event: The canonical event being decided.
        index_path: The built inventory index. ``None`` leaves dependency suppression off, which is the
            honest state of an installation that has declared no graph.
        graph: A prepared `topology.Topology`, for a caller deciding many events over one index. It wins
            over `index_path`, and its own `depth`/`max_rows` are still asked per call.
        depth: Hops to walk, refused above `MAX_DEPENDENCY_DEPTH` rather than clamped.
    """
    if event['resource_id'] is None or (index_path is None and graph is None):
        # Nothing to ask and nowhere to ask it: answering this costs no read of the database, which is
        # the state of an installation that has declared no graph rather than a judgement about it.
        return None
    with _readonly(store) as db:
        return _dependency(db, event, index_path=index_path, graph=graph, depth=depth)


def _dependency(connection: sqlite3.Connection, event: dict[str, Any], *,
                index_path: Path | str | None = None, graph: Any = None,
                depth: int = DEPENDENCY_DEPTH) -> dict[str, Any] | None:
    """`dependency` against a connection the caller owns.

    Same refusal set, and one difference that is the whole reason it exists: the open incidents this
    connection has written but not committed are part of the down set, so an admission that files a
    parent and a child in one round of work cannot be decided against a graph of yesterday.
    """
    resource_id = event['resource_id']
    if resource_id is None or (index_path is None and graph is None):
        return None
    hops = _bound('depth', depth, 1, MAX_DEPENDENCY_DEPTH)
    down = _firing_resources(connection)
    if down['truncated'] or not down['resources']:
        return None
    graph = graph or topology.Topology(index_path, depth=hops, max_rows=MAX_DEPENDENCY_NODES)
    try:
        walk = graph.upstream(resource_id, hops, max_rows=MAX_DEPENDENCY_NODES)
    except topology.UndeclaredResource:
        return None
    except (OSError, sqlite3.Error, ValueError) as exc:      # a TopologyRefusal is an inventory refusal
        log.warning('Dependency suppression unavailable; the finding stands on its own',
                    extra={'error_class': type(exc).__name__})
        return None
    if walk['truncated_by'] and any(reason != 'depth' for reason in walk['truncated_by']):
        # A *row* cut means a hop ran out of rows: the neighbour set is incomplete, and the missing
        # neighbours are exactly the nearer ones, so the nearest down parent this call found may not be
        # the nearest one that exists. A *depth* cut is different and is tolerated below: it can only
        # hide nodes further out than everything it returned, and this call blames the nearest down
        # parent, so no node beyond the bound could have been a better blame.
        return None
    by_id = {node['resource_id']: node for node in walk['nodes']}
    blamed = sorted((node for node in walk['nodes'] if node['resource_id'] in down['resources']),
                    key=lambda node: (node['depth'], node['resource_id']))
    if not blamed:
        return None
    parent = blamed[0]
    path = _path_to(resource_id, parent, by_id)
    if path is None:
        return None
    cause = down['resources'][parent['resource_id']]
    return {'parent': parent['resource_id'], 'depth': parent['depth'], 'path': path,
            'rule_id': cause['rule_id'], 'incident_id': cause['incident_id'], 'relation': parent['relation'],
            'depth_truncated': 'depth' in walk['truncated_by']}


def _path_to(origin: str, node: dict[str, Any], by_id: dict[str, Any]) -> list[str] | None:
    """Rebuild the declared path from an `upstream()` walk, using only the hops that walk reported.

    Each node carries the `via` it was reached from, so the chain needs no second search — and
    specifically no `topology.shortest_path()` call, whose `incomplete`/`depth_exceeded` answers would
    have to be handled all over again for a path the walk already shows. A chain that never closes back
    on the origin is refused rather than printed as `[child, parent]`: the walk is the evidence, and a
    path it did not actually reach is not something to blame a silence on.
    """
    path = [node['resource_id']]
    seen = {node['resource_id']}
    hop = node
    while hop.get('via') is not None and hop['via'] != origin:
        parent = by_id.get(hop['via'])
        if parent is None or parent['resource_id'] in seen:
            return None
        seen.add(parent['resource_id'])
        path.append(parent['resource_id'])
        hop = parent
    if hop.get('via') != origin:
        return None
    path.append(origin)
    return list(reversed(path))


# --- the decision ---------------------------------------------------------------------------

def decide(store: Store, event: dict[str, Any], *, now: dt.datetime | None = None,
           index_path: Path | str | None = None, graph: Any = None,
           window_seconds: int = FLAP_WINDOW_SECONDS, threshold: int = FLAP_THRESHOLD,
           depth: int = DEPENDENCY_DEPTH) -> Decision:
    """Ask the three questions in order and return the one answer, with the sentence to print.

    Read-only: nothing here writes, and nothing here needs to. A caller that only wants to know — the
    CLI's `inspect`, an operator wondering whether a page is coming — gets the same object without
    spending a write. `file_event` is the caller that acts, and it cannot use this one: it decides inside
    the transaction whose rows the decision is about, through `_decide`.

    The transition count is carried on every decision, suppressed or not, because "why was this one not
    folded?" is asked as often as "why was it?". `depth` is the dependency walk's bound, passed through
    and refused above `MAX_DEPENDENCY_DEPTH` rather than clamped: how far a symptom travels is the
    caller's claim to make, not this module's default dressed up as an answer.

    Raises:
        StateError: `event` is not a canonical event as `state.validate_event` defines one.
    """
    with _readonly(store) as db:
        return _decide(db, event, now=now, index_path=index_path, graph=graph,
                       window_seconds=window_seconds, threshold=threshold, depth=depth)


def _decide(connection: sqlite3.Connection, event: dict[str, Any], *, now: dt.datetime | None = None,
            index_path: Path | str | None = None, graph: Any = None,
            window_seconds: int = FLAP_WINDOW_SECONDS, threshold: int = FLAP_THRESHOLD,
            depth: int = DEPENDENCY_DEPTH) -> Decision:
    """The three questions, asked on one connection the caller owns — the whole judgement, once.

    Every read here goes through a `_`-prefixed helper on that connection, so a decision made inside
    `Store.intake`'s transaction counts the transition that transaction just filed and sees the incident
    rows it wrote; a second, read-only connection would decide against the database as it stood before
    this event, and a nested transaction on this file is not available anyway.
    """
    now = clock(now)
    validate_event(event, now)
    flap = _flapping(connection, event, window_seconds=window_seconds, threshold=threshold, now=now)
    window = _covering_window(connection, event, now=now)
    if window is not None:
        reason = _limit(f'maintenance-window {window["id"]} for {_selector(window)} covers this finding'
                        f' until {window["ends_at"]}; declared by {window["author"]}: {window["reason"]}')
        return Decision(condition=flap['condition'], suppressed=True, cause='maintenance-window',
                        reason=reason, transitions=flap['transitions'],
                        detail={'window_id': window['id'], 'starts_at': window['starts_at'],
                                'ends_at': window['ends_at'], 'declared_by': window['author'],
                                'declared_at': window['declared_at']})
    cause = _dependency(connection, event, index_path=index_path, graph=graph, depth=depth)
    if cause is not None:
        reason = _limit(f'dependency {cause["parent"]} is firing under rule {cause["rule_id"]}'
                        f' ({_path_text(cause["path"])})')
        return Decision(condition=flap['condition'], suppressed=True, cause='dependency', reason=reason,
                        transitions=flap['transitions'],
                        detail={'parent': cause['parent'], 'path': cause['path'], 'hops': cause['depth'],
                                'relation': cause['relation'], 'parent_incident': cause['incident_id'],
                                'graph_cut_at_depth_bound': cause['depth_truncated']})
    if flap['flapping']:
        counted = f'at least {flap["transitions"]}' if not flap['complete'] else str(flap['transitions'])
        # Which rows the count leaned on, named in the sentence an operator reads: `absorbed` openings are
        # the ones a group swallowed (`Store._join_group` deleted the incident row they opened), and they
        # come from a different table than `opened`/`resolved`. A fold that quoted only the incident-visible
        # edges would say "4 transitions" about the six-edge episode
        # `tests/test_correlation.py::GroupingResolutionTests` measures.
        grouped = (f'; {flap["absorbed"]} of them absorbed by a group'
                   if flap['absorbed'] else '')
        reason = _limit(f'flapping {counted} transitions of one condition within'
                        f' {flap["window_seconds"]} s (threshold {flap["threshold"]}){grouped}')
        return Decision(condition=flap['condition'], suppressed=True, cause='flapping', reason=reason,
                        transitions=flap['transitions'],
                        detail={'window_seconds': flap['window_seconds'], 'threshold': flap['threshold'],
                                'opened': flap['opened'], 'resolved': flap['resolved'],
                                'absorbed': flap['absorbed'], 'complete': flap['complete']})
    return Decision(condition=flap['condition'], suppressed=False, transitions=flap['transitions'],
                    detail={'window_seconds': flap['window_seconds'], 'threshold': flap['threshold']})


def file_event(store: Store, event: dict[str, Any], actor: Actor, *, now: dt.datetime | None = None,
               index_path: Path | str | None = None, graph: Any = None,
               window_seconds: int = FLAP_WINDOW_SECONDS,
               threshold: int = FLAP_THRESHOLD, depth: int = DEPENDENCY_DEPTH) -> dict[str, Any]:
    """File one canonical event through `Store.intake` and fold the page it booked, in one commit.

    The event is filed first, always, by the one method here that writes `events`, `conditions` and the
    outbox, and the delivery that transition booked is folded **inside that same transaction** — through
    intake's `admission` callback, on intake's own connection, after its audit row and before its commit.
    `intake` is never skipped or imitated, so a suppressed finding is still a finding an operator can
    list, the decision counts the transition it is deciding, and no committed ``pending`` row is ever
    offered to `claim_notification`.

    A fold lands only on a row still ``pending``; a fold that cannot be written — a refusal from this
    module's own bounds, a database that answers — raises out of `intake` having rolled the whole
    admission back, event included, rather than leave a finding filed beside an undecided send.

    Returns:
        ``{'intake': <Store.intake's result>, 'decision': <Decision or None>, 'delivery': ...,
        'suppressed': bool}``. `decision` is None when the event was a duplicate or filed no transition,
        because then nothing was booked and there is nothing to fold; `delivery` is the outbox row the
        transition booked (suppressed or not), and `delivery_missing` says a transition booked no
        readable row, which is a bug somewhere else and is never treated as a fold.
    """
    now = clock(now)
    folded: dict[str, Any] = {}

    def admit(connection: sqlite3.Connection, outcome: dict[str, Any]) -> None:
        """Decide and fold on intake's connection, before that transaction becomes visible to anybody."""
        if outcome['transition'] is None:
            return                       # nothing was booked, so there is nothing to decide about
        decision = _decide(connection, event, now=now, index_path=index_path, graph=graph,
                           window_seconds=window_seconds, threshold=threshold, depth=depth)
        folded['decision'] = decision
        delivery = _delivery_row(connection, outcome['event_id'])
        if delivery is None:
            folded['delivery_missing'] = True
            return
        folded['delivery'] = delivery
        if not decision.suppressed or decision.cause is None:
            return
        folded['suppressed'] = _suppress_delivery(
            store, connection, delivery, decision.reason or '', cause=decision.cause, now=now,
            detail={'condition': decision.condition, 'event_id': outcome['event_id'],
                    'transition': outcome['transition'], 'producer': actor.identity})

    outcome = store.intake(event, actor, now=now, admission=admit)
    result: dict[str, Any] = {'intake': outcome, 'decision': folded.get('decision'),
                              'delivery': folded.get('delivery'),
                              'suppressed': bool(folded.get('suppressed', False))}
    if folded.get('delivery_missing'):
        result['delivery_missing'] = True
    return result


def _refusal_words(cause: Any, reason: Any, delivery: Any) -> None:
    """Refuse a fold that cannot be said in the two vocabularies a refusal is made of.

    Run before a standalone caller opens a transaction it would only have to roll back, and again inside
    `_suppress_delivery`, which is also reached from an admission holding a sentence it composed itself.
    """
    if cause not in CAUSES:
        raise StateError('Unknown suppression cause')
    if (not isinstance(reason, str) or not 1 <= len(reason) <= MAX_SUPPRESSION_CHARS
            or not REASON_PATTERN.match(reason)):
        raise StateError('A suppression reason must be one printable bounded line')
    identifier(delivery)


def suppress_delivery(store: Store, delivery: str, reason: str, *, cause: str,
                      detail: dict[str, Any] | None = None,
                      now: dt.datetime | None = None) -> bool:
    """Mark one queued delivery never-sendable, in the three places a refusal belongs.

    The trio is `Store.claim_notification`'s own, reused rather than re-invented: the row goes ``dead``
    so the claim query never hands it out, `state.record_suppression` writes the durable refusal list
    (which is what `presentation.delivery_route` renders as ``suppressed: <reason>`` and what
    `Store.retry_notification` reads when it refuses a replay), and the audit row is the history of the
    decision. Writing *only* the refusal row would not stop the send: `claim_notification` selects on
    ``status='pending'``, and the suppression table only ever *unblocks* its head-of-queue clause.

    This is the standalone shape of the call: a delivery id the caller already holds, decided beside the
    filing, so it takes its own transaction. `file_event`'s fold is the same three writes through
    `_suppress_delivery` on intake's connection, before that transaction commits. Neither rewrites a row
    that has left ``pending``.

    Returns False, having written nothing, when the delivery is unknown or has left ``pending``.

    Raises:
        StateError: `cause` is not one of `CAUSES`, `reason` is not a bounded printable one-line
            sentence, or `delivery` is not a canonical UUID.
    """
    _refusal_words(cause, reason, delivery)
    with store.transaction() as connection:
        return _suppress_delivery(store, connection, delivery, reason, cause=cause, detail=detail, now=now)


def _suppress_delivery(store: Store, connection: sqlite3.Connection, delivery: str, reason: str, *,
                       cause: str, detail: dict[str, Any] | None = None,
                       now: dt.datetime | None = None) -> bool:
    """The three writes on a connection the caller owns — a fold that needs no commit of its own.

    `notification_safety.reserve` is the precedent for the shape: the caller supplies the lock and this
    supplies the statements, so an admission cannot be raced by the delivery rail and a refusal here
    unwinds it. Returns False, having written nothing, when the row is unknown or has left ``pending`` on
    this connection.
    """
    now = clock(now)
    _refusal_words(cause, reason, delivery)
    row = connection.execute('SELECT status FROM outbox WHERE id=?', (delivery,)).fetchone()
    if row is None or row['status'] != 'pending':
        return False
    connection.execute("UPDATE outbox SET status='dead',claim_token=NULL,lease_until=NULL WHERE id=?",
                       (delivery,))
    record_suppression(connection, delivery, reason, now)
    store.audit(connection, now, WORKER_ACTOR, 'notification.suppressed', delivery,
                dict(detail or {}, reason=reason, cause=cause))
    return True


# --- noise, measured ------------------------------------------------------------------------

def stats(store: Store, *, now: dt.datetime | None = None, window_seconds: int = FLAP_WINDOW_SECONDS,
          threshold: int = FLAP_THRESHOLD) -> dict[str, Any]:
    """Report what suppression did, as numbers off the database, because a claim is not a measurement.

    v0.1's `stats()` reported a noise ratio so an operator could see the collapse working; here every
    input is a stored row, which is also what makes the number honest across a restart. The counts are
    deliberately not merged into one: `booked_deliveries` is what the transitions asked for,
    `suppressed_deliveries` is what was refused — by **any** cause, including the send budget's own
    reasons, which is why `suppressed_by_cause` exists and why `other` is a bucket rather than an error —
    and `noise_reduction` is the fraction between them, `None` rather than a division by zero on a
    database that has never booked a send.

    `conditions_observed` names the newest `MAX_SCANNED_CONDITIONS` conditions by watermark and
    `conditions_total` names how many exist, so a sample never reads as a census.
    """
    now = clock(now)
    seconds = _bound('window_seconds', window_seconds, *FLAP_WINDOW_BOUNDS)
    limit = _bound('flap_threshold', threshold, *FLAP_THRESHOLD_BOUNDS)
    start = utc_text(now - dt.timedelta(seconds=seconds))
    with _readonly(store) as db:
        total = db.execute('SELECT count(*) FROM conditions').fetchone()[0]
        keys = [row[0] for row in db.execute('SELECT key FROM conditions ORDER BY watermark DESC LIMIT ?',
                                             (MAX_SCANNED_CONDITIONS,)).fetchall()]
        counted = {'opened': 0, 'resolved': 0, 'absorbed': 0, 'transitions': 0, 'flapping': 0}
        swallowed = _absorbed_counts(db, start, utc_text(now))
        for key in keys:
            one = _count_transitions(db, key, start, utc_text(now), seconds, absorbed=swallowed)
            counted['opened'] += one['opened']
            counted['resolved'] += one['resolved']
            counted['absorbed'] += one['absorbed']
            counted['transitions'] += one['transitions']
            counted['flapping'] += 1 if one['transitions'] >= limit else 0
        causes = dict.fromkeys((*CAUSES, 'other'), 0)
        suppressed = 0
        for cause, count in db.execute('SELECT substr(reason,1,instr(reason,\' \')) AS cause,'
                                       ' count(*) FROM notification_suppressions GROUP BY cause'):
            causes[reason_cause(cause)] += count
            suppressed += count
        booked = db.execute('SELECT count(*) FROM outbox').fetchone()[0]
        stored = _scan(db, now)
    return {'schema_version': 1, 'generated_at': utc_text(now),
            'scope': 'durable rows in this database; nothing here is remembered between calls',
            'conditions_observed': len(keys), 'conditions_total': total,
            'max_scanned_conditions': MAX_SCANNED_CONDITIONS,
            'conditions_flapping': counted['flapping'],
            'flap': {'window_seconds': seconds, 'threshold': limit,
                     'transitions_in_window': counted['transitions'],
                     'opened_in_window': counted['opened'], 'resolved_in_window': counted['resolved'],
                     'absorbed_in_window': counted['absorbed']},
            'booked_deliveries': booked, 'suppressed_deliveries': suppressed,
            'suppressed_by_cause': causes,
            'noise_reduction': (round(suppressed / booked, 4) if booked else None),
            'windows': {'declared': stored['scanned'], 'live': stored['count'],
                        'revoked': stored['revoked'], 'expired': stored['expired'],
                        'unusable': stored['unusable'], 'unattested': stored['unattested'],
                        'bound_exceeded': stored['bound_exceeded'],
                        'max_seconds': MAX_WINDOW_SECONDS, 'max_live_windows': MAX_LIVE_WINDOWS,
                        'max_rows': MAX_WINDOW_ROWS}}


def suppressed_deliveries(store: Store) -> int | None:
    """How many deliveries this platform has ever refused to send, or None when that cannot be read.

    The overview's one number from this module. It is the whole `notification_suppressions` table rather
    than this module's share of it — that table *is* the platform's refusal list, and the honest headline
    is "how many pages did not fire", which includes the send budget's `event-too-old` and
    `flood-circuit-open`. The per-cause split lives in `stats()`.

    None means the read was not possible: no file behind this store, or a database this process cannot
    open. A missing number on an operator surface is a fact and
    a zero is a claim, which is the same line `platform/overview.py` draws for every other signal.
    """
    if getattr(store, 'path', None) is None:
        return None
    try:
        with _readonly(store) as db:
            return db.execute('SELECT count(*) FROM notification_suppressions').fetchone()[0]
    except (OSError, sqlite3.Error):
        return None


def reason_cause(reason: Any) -> str:
    """Which of `CAUSES` wrote a suppression sentence, or `other` when the answer is not this module.

    Bucketing is by the first token, because the column holds one sentence and the sentence is what the
    portal shows. Reasons written by `platform/notification_safety.py` (`event-too-old`,
    `flood-circuit-open`, …) are single tokens matching none of `CAUSES` and land in `other`, which is the
    honest answer: this module did not make them.
    """
    if not isinstance(reason, str):
        return 'other'
    first = reason.split(' ', 1)[0].strip()
    return first if first in CAUSES else 'other'


# --- internals ------------------------------------------------------------------------------

def _count_transitions(db: sqlite3.Connection, condition: str, start: str, finish: str,
                       seconds: int, *, absorbed: dict[str, int] | None = None) -> dict[str, Any]:
    """The one transition count both `transitions` and `stats` ask, against a connection the caller owns.

    The window is closed on both ends: a row stamped *ahead* of the caller's `now` (a producer is
    allowed 60 seconds of skew by `validate_event`, and an injected `now` can name any instant) is not
    counted, because a transition that has not happened by the instant being decided cannot be evidence
    that one already has. Two bounds, both stated in the answer — see `transitions`.

    **The third component: openings a group swallowed (correlation, repaired by correlation followups).** `incidents`
    alone
    under-counts a condition that has been grouped, because `Store._join_group` deletes the incident row
    the member's own firing event opened and leaves exactly one `incident_members` row in its place. So
    each link row naming this condition, dated inside the same window by the link's own `at`, is counted
    as one more `opened` edge, and the total is reported under its own key (`absorbed`) rather than
    folded silently into `opened`: the two come from different tables and a reader is entitled to see
    which one the number leaned on.

    `absorbed` openings are the reason the old count was *quietly* wrong rather than loudly wrong: the
    edges were simply missing and the answer still claimed to be exact. `complete: False` whenever any
    opening was absorbed is what closes that, and it is honest rather than a hedge — a group also swallows
    the member's *recoveries* (a member that resolves while the group stays open stamps nothing on any row
    keyed by its own condition), and no row in this schema dates those. `transitions` is therefore a floor
    for a grouped member, and the reason sentence reads "at least" — the same shape the row cap already
    produces, which is why that machinery is reused instead of a new one.

    `absorbed` is the pre-counted map `stats()` passes so that one surface reads the link table once for
    its whole sample instead of once per condition; `None` (the flap decision's shape) reads this one
    condition here. **Cost, stated because it was the remaining debt of this repair until schema v9:** the
    link table's primary key is `(incident_id, condition_key)`, whose autoindex answers reads *by incident*,
    so the read by condition used to be a scan of `incident_members` stopped by `MAX_TRANSITION_ROWS`
    matches rather than a lookup. `state.MEMBERS_CONDITION_INDEX`  added
    `incident_members(condition_key)`, and the read is a seek on it as of that step; the measured scan
    figures it replaced — 0.1 ms with 500 links stored, 2.2 ms with 10 000, 9.3 ms with 50 000 on one
    machine, worst case (a condition with no link row), one such read per page booked and none per overview
    read — stay here as the reason the index exists, and a file restored from a pre-v9 copy still pays
    them until `lo-platform migrate` runs. What this card does **not** move is the floor: a group swallows
    the member's *recoveries* as well as its openings and no row anywhere in this schema dates those, so
    `complete` is False whenever anything was absorbed and that undated half is the debt that remains.

    Split out so `stats()` can walk sixty conditions over a single read-only connection instead of
    opening sixty of them: a per-condition connection would put sixty WAL readers behind one overview
    read, and the count itself would be unchanged.
    """
    opened = db.execute('SELECT opened_at FROM incidents WHERE condition_key=?'
                        ' AND julianday(opened_at)>julianday(?) AND julianday(opened_at)<=julianday(?)'
                        ' ORDER BY opened_at DESC LIMIT ?',
                        (condition, start, finish, MAX_TRANSITION_ROWS + 1)).fetchall()
    resolved = db.execute("SELECT updated_at FROM incidents WHERE condition_key=?"
                          " AND status='resolved' AND julianday(updated_at)>julianday(?)"
                          ' AND julianday(updated_at)<=julianday(?) ORDER BY updated_at DESC LIMIT ?',
                          (condition, start, finish, MAX_TRANSITION_ROWS + 1)).fetchall()
    if absorbed is None:
        absorbed_count = _absorbed_openings(db, condition, start, finish)
    else:
        absorbed_count = min(absorbed.get(condition, 0), MAX_TRANSITION_ROWS)
    opened_count, resolved_count = min(len(opened), MAX_TRANSITION_ROWS), min(len(resolved), MAX_TRANSITION_ROWS)
    return {'window_seconds': seconds, 'since': start, 'until': finish, 'opened': opened_count,
            'resolved': resolved_count, 'absorbed': absorbed_count,
            'transitions': opened_count + resolved_count + absorbed_count,
            'complete': (opened_count < MAX_TRANSITION_ROWS and resolved_count < MAX_TRANSITION_ROWS
                         and absorbed_count < MAX_TRANSITION_ROWS and absorbed_count == 0)}


def _grouping_present(db: sqlite3.Connection) -> bool:
    """Whether this file has ever had the grouping table, which is whether grouping can have happened.

    A database below schema v7 (`state.MIGRATIONS`) has no `incident_members` at all, and the honest
    answer about absorbed openings there is zero rather than a crash: nothing ever joined a group in a
    file that has no table to record a join in. Without this pre-check the count would raise out of a
    flap decision on an un-migrated store and roll back the finding it was only trying to price — the
    one failure mode this module's whole posture forbids.
    """
    return db.execute('SELECT 1 FROM sqlite_master WHERE type=? AND name=?',
                      ('table', GROUPING_TABLE)).fetchone() is not None


def _absorbed_openings(db: sqlite3.Connection, condition: str, start: str, finish: str) -> int:
    """How many of this one condition's openings a group swallowed inside the window.

    One row per *group* it joined, not one per opening: `state.GROUPING_SCHEMA`'s primary key is
    `(incident_id, condition_key)` and `Store._join_group` writes it `INSERT OR REPLACE`, so a member
    that leaves a group and rejoins the same one leaves one row restamped with the newest link. That is
    the under-count that remains after this repair, and it is why the caller reports the total as a
    floor. The `at` bound is the link's own instant, which `grouping_admission` stamps with intake's
    `now`, so it lands in the same window the incident read uses.

    This is a lookup, not a scan, as of schema v9: `state.MEMBERS_CONDITION_INDEX` indexes
    `condition_key`, the half of that primary key the autoindex could not reach (the table's key leads
    with `incident_id`, so a read by condition had no index to take). It deliberately does not name the
    index with `INDEXED BY`, for the reason step 8 gave for the member read: a file that predates the
    step must still answer this question — with the scan it always paid — rather than raise an SQLite
    error the caller cannot tell apart from a database that will not open, inside a transaction whose
    whole contract is that a grouping decision costs no finding.
    """
    if not _grouping_present(db):
        return 0
    return db.execute(f'SELECT count(*) FROM (SELECT 1 FROM {GROUPING_TABLE} WHERE condition_key=?'
                      ' AND julianday(at)>julianday(?) AND julianday(at)<=julianday(?) LIMIT ?)',
                      (condition, start, finish, MAX_TRANSITION_ROWS + 1)).fetchone()[0]


def _absorbed_counts(db: sqlite3.Connection, start: str, finish: str) -> dict[str, int]:
    """Every condition's absorbed openings in one window, read once for the whole `stats()` sample.

    The bulk form of `_absorbed_openings` for a caller that asks about sixty conditions: one walk of the
    link table per overview read instead of sixty, bucketed by condition in SQLite rather than in Python
    so the rows never land in this process. Conditions nobody grouped are absent from the map, which is
    the same zero the per-condition read would have answered.
    """
    if not _grouping_present(db):
        return {}
    return {row[0]: row[1] for row in db.execute(
        f'SELECT condition_key, count(*) FROM {GROUPING_TABLE}'
        " WHERE julianday(at)>julianday(?) AND julianday(at)<=julianday(?) GROUP BY condition_key",
        (start, finish)).fetchall()}


@contextmanager
def _readonly(store: Store) -> Iterator[sqlite3.Connection]:
    """Open the store's own file read-only, so asking a question does not cost the writer its lock.

    `platform/presentation.py` is the precedent. The alternative — `Store.transaction()` — opens
    ``BEGIN IMMEDIATE``, which is the write lock: a flap check on every intake would serialise intake
    behind itself, and a read that decides nothing on its own has no business taking the writer's slot.
    """
    with closing(sqlite3.connect(store.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)) as db:
        db.row_factory = sqlite3.Row
        yield db


# --- the stored window document -------------------------------------------------------------

def _envelope(value: Any) -> dict[str, Any] | None:
    """Return one stored window envelope as a mutable dict, or None when it is not one at all.

    This is the shallow read `revoke_window` and the duplicate answer need: it checks that the text is
    JSON of the shape this module writes — the envelope, its version, a complete `declared` block, a
    well-formed `revoked` pair or nothing, a positive integer attestation — and judges none of the
    *contents*. Judgement belongs to `_scan`, on the path that applies a window, because a row whose span
    or attestation has failed must still be revocable by the human who can see it in `windows`.
    """
    if not isinstance(value, str):
        return None
    try:
        document = json.loads(value)
    except ValueError:
        return None
    if (not isinstance(document, dict) or set(document) != set(WINDOW_DOCUMENT_KEYS)
            or document['schema_version'] != WINDOW_DOCUMENT_VERSION
            or not isinstance(document['declared'], dict)
            or set(document['declared']) != set(DECLARED_KEYS)
            or not (document['revoked'] is None
                    or (isinstance(document['revoked'], dict)
                        and set(document['revoked']) == set(REVOKE_KEYS)))
            or isinstance(document['attest'], bool) or not isinstance(document['attest'], int)
            or document['attest'] <= 0):
        return None
    return document


def _declared(block: Any) -> dict[str, Any] | None:
    """Return one declared block this build would have written, or None.

    The refusals are `declare_window`'s, re-applied here rather than trusted from there, because the row
    being read may have arrived by a restore or a copy from a build with different bounds: the selector
    must be exactly one of the two shapes and well-formed in itself, the author a bounded identity, the
    reason one printable bounded line, and every stamp parseable, ordered, and inside
    `MAX_WINDOW_SECONDS`. None of that is a judgement about the *work*; it is the shape a window must
    have before anything may be silenced on its strength, so a failure here is a row that is counted and
    never applied — the direction that pages.
    """
    if not isinstance(block, dict) or set(block) != set(DECLARED_KEYS):
        return None
    try:
        identifier(block['id'])
        resource_id, rule_id = block['resource_id'], block['rule_id']
        if (resource_id is None) == (rule_id is None):
            return None
        if resource_id is None:
            label(rule_id)
        else:
            identifier(resource_id)
        label(block['author'])
        reason = block['reason']
        if (not isinstance(reason, str) or not 1 <= len(reason) <= MAX_REASON_CHARS
                or reason != ' '.join(reason.split()) or not REASON_PATTERN.match(reason)):
            return None
        start, end = _instant(block['starts_at']), _instant(block['ends_at'])
        _instant(block['declared_at'])
        if not 0 < (end - start).total_seconds() <= MAX_WINDOW_SECONDS:
            return None
    except (StateError, InvalidInventory, TypeError, ValueError):
        return None
    return dict(block)


def _attested(connection: sqlite3.Connection, declared: dict[str, Any], attest: int) -> bool:
    """Whether one append-only audit row says a human declared exactly this window.

    The probe is by primary key (`sequence`), which is why the sequence is stored in the document instead
    of being re-found by `operation`/`subject`: control state exists because control state that asked the audit log
    a question on every claim made the log the source of truth for behaviour, and a read the log must be
    scanned for is a cost an outage pays. One indexed lookup per candidate window is a different thing —
    and its answer is decisive, because `audit` carries the UPDATE and DELETE triggers
    `notification_control` does not, so the declaration a window points at cannot be quietly rewritten
    or removed.

    The comparison is against the whole declared block, canonicalised by the one function that wrote both
    sides: a stored window whose end, reason or author has moved since it was declared is not the window
    anybody approved, and it is the *lookup* that says so rather than a reader's opinion.
    """
    return connection.execute("SELECT 1 FROM audit WHERE sequence=? AND operation='maintenance.declared'"
                              ' AND subject=? AND detail=?',
                              (attest, declared['id'], canonical(declared))).fetchone() is not None


#: The candidate read, phrased off `state.py`'s fragments so index and query cannot drift: the v5 index,
#: its own partial key range, the live end as both filter and ordering (which the index delivers), and the
#: bound on how many candidates one read may look at. `INDEXED BY` is deliberate: a plan that fell back to
#: scanning the table would reintroduce the defect as a performance bug, and the history test below reads
#: the EXPLAIN QUERY PLAN of this statement.
_CANDIDATE_SQL = ('SELECT key,value FROM notification_control'
                  f' INDEXED BY {MAINTENANCE_WINDOW_INDEX}'
                  f' WHERE {MAINTENANCE_WINDOW_KEYS} AND {MAINTENANCE_WINDOW_LIVE}'
                  f' ORDER BY ({MAINTENANCE_WINDOW_END}), key LIMIT ?')


def _scan(connection: sqlite3.Connection, now: dt.datetime) -> dict[str, Any]:
    """Validate a bounded indexed set of unrevoked candidates whose stored end is after now.

    Malformed JSON and missing ends index as NULL and are excluded, as are expired or revoked rows.
    Counters describe fetched candidates only. An indexed end grants no authority: every candidate
    still needs a valid declaration and matching append-only attestation before it can suppress.
    """
    rows = connection.execute(_CANDIDATE_SQL, (utc_text(now), MAX_WINDOW_ROWS + 1)).fetchall()
    live: list[dict[str, Any]] = []
    unusable = unattested = revoked = expired = 0
    for row in rows:
        document = _envelope(row['value'])
        if document is None:
            unusable += 1
            continue
        declared = _declared(document['declared'])
        if declared is None:
            unusable += 1
            continue
        if document['revoked'] is not None:
            revoked += 1
            continue
        if not _attested(connection, declared, document['attest']):
            unattested += 1
            continue
        start, end = _instant(declared['starts_at']), _instant(declared['ends_at'])
        if end <= now:
            expired += 1
            continue
        live.append(dict(declared, revoked_at=None, revoked_by=None, covers_now=start <= now))
    live.sort(key=lambda window: (window['starts_at'], window['id']))
    return {'windows': live, 'count': len(live), 'scanned': len(rows),
            'bound_exceeded': len(rows) > MAX_WINDOW_ROWS or len(live) > MAX_LIVE_WINDOWS,
            'unusable': unusable, 'unattested': unattested, 'revoked': revoked, 'expired': expired,
            'max_live_windows': MAX_LIVE_WINDOWS, 'max_seconds': MAX_WINDOW_SECONDS,
            'max_rows': MAX_WINDOW_ROWS}


def _readable_window(value: Any) -> dict[str, Any]:
    """Return the stored window a duplicate declaration repeats, refusing a row that cannot be read.

    A duplicate is answered with the fact the file already holds — including the author who got there
    first — so a row this build cannot read is not an answer, and filling the gap from the caller's own
    declaration would be inventing a stored fact. Reconciling it is a human act, and the sentence says so.
    """
    document = _envelope(value)
    declared = _declared(document['declared']) if document is not None else None
    if declared is None:
        raise StateError('Maintenance window declaration is unreadable; reconcile it, never re-declare it')
    revoke = document['revoked'] or {}
    return dict(declared, revoked_at=revoke.get('revoked_at'), revoked_by=revoke.get('revoked_by'))


def _delivery_row(connection: sqlite3.Connection, event_id: str) -> str | None:
    """Return the outbox row one accepted event booked, read on the connection that booked it.

    A primary-key lookup, because the row's id *is* the event's: `state.notification_id` is the one mint
    `Store.intake` books with and the one this read asks with, so no scan of the incident's rows is
    needed and no second copy of the formula can drift from the first. Only a transition books a row, and
    only a booking reaches this call. The caller's connection is the point: the booking is invisible
    anywhere else until that transaction commits.
    """
    row = connection.execute('SELECT id FROM outbox WHERE id=?', (notification_id(event_id),)).fetchone()
    return row['id'] if row else None


def _bound(name: str, value: Any, low: int, high: int) -> int:
    """Return `value` as an int inside ``[low, high]``, or refuse; a clamp would be a silent edit.

    Booleans are refused rather than counted as 1: `True` is not an operator's choice of window, and a
    config file that reaches `1` through a YAML `yes` would fold every second page in the estate.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise StateError(f'Invalid {name}')
    number = int(value)
    if number != value or not low <= number <= high:
        raise StateError(f'{name} must be {low}..{high}')
    return number


def _instant(value: Any) -> dt.datetime:
    """Return one aware UTC datetime for a stored or declared instant, refusing anything else.

    `inventory.validation.timestamp` answers `InvalidInventory` for text it cannot parse; that is a
    different module's exception and this module's callers catch `StateError`, so it is converted here
    the way `state.identifier` converts `uuid`'s.
    """
    if not isinstance(value, str):
        raise StateError('A maintenance window needs timezone-aware ISO timestamps')
    try:
        return timestamp(value)
    except InvalidInventory:
        raise StateError('A maintenance window needs timezone-aware ISO timestamps') from None


def _selector(window: dict[str, Any]) -> str:
    """The one clause saying what a window covers, in the words its author declared it in."""
    return (f'resource {window["resource_id"]}' if window['resource_id'] is not None
            else f'rule {window["rule_id"]}')


def _path_text(path: list[str]) -> str:
    """Print a dependency path inside the length budget of one reason sentence."""
    if len(path) <= PATH_NODES:
        return ' -> '.join(path)
    return f'{path[0]} -> ... -> {path[-1]} ({len(path) - 2} hops hidden)'


def _limit(reason: str) -> str:
    """Cut a composed sentence at its bound, so a column width is never what decides the text."""
    if len(reason) <= MAX_SUPPRESSION_CHARS:
        return reason
    return reason[:MAX_SUPPRESSION_CHARS - 3].rstrip() + '...'


def main() -> int:
    """Run one read-only suppression command: `stats`, `windows` or `inspect`.

    Nothing here writes, and nothing here may. Opening a window is a human act behind a human credential,
    and `platform/api.py` — not this module — is where a credential exists: a command line that minted
    `Actor(identity, 'human')` from a bare flag would be *claiming* a role the caller never proved, which
    is the same reason `lo-platform` has no approval subcommand today. `lo-platform suppress` and the
    API route are follow-up cards, and until one lands a window is declared by a caller that holds a
    real human actor (`declare_window` above).

    Returns the process exit code: 0 on an answer, 1 on a refusal, always one JSON object on stdout.
    """
    import argparse

    from local_observe.inventory.validation import timestamp as parse_timestamp
    parser = argparse.ArgumentParser(prog='python -m local_observe.platform.suppression',
                                     description='read-only suppression and maintenance-window state')
    parser.add_argument('--database', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    counters = sub.add_parser('stats', help='what suppression did, measured off this database')
    counters.add_argument('--flap-window-seconds', type=int, default=FLAP_WINDOW_SECONDS)
    counters.add_argument('--flap-threshold', type=int, default=FLAP_THRESHOLD)
    listed = sub.add_parser('windows', help='the live maintenance windows, and whether to trust them')
    listed.add_argument('--now', type=parse_timestamp)
    looked = sub.add_parser('inspect', help='answer "would this finding page?" and file nothing')
    looked.add_argument('--event', type=Path, required=True)
    looked.add_argument('--index', type=Path,
                        help='declared inventory index; omitting it leaves dependency suppression off,'
                             ' which is the honest state of an installation with no graph declared')
    looked.add_argument('--depth', type=int, default=DEPENDENCY_DEPTH,
                        help=f'hops of the declared graph to consult (1..{MAX_DEPENDENCY_DEPTH}); one'
                             ' is what the incident view labels too')
    looked.add_argument('--now', type=parse_timestamp)
    args = parser.parse_args()
    try:
        store = Store(args.database)
        if args.command == 'stats':
            result: Any = stats(store, window_seconds=args.flap_window_seconds,
                                threshold=args.flap_threshold)
        elif args.command == 'windows':
            result = live_windows(store, now=args.now)
        else:
            event = json.loads(args.event.read_text())
            result = decide(store, event, now=args.now, index_path=args.index,
                            depth=args.depth).as_dict()
        print(json.dumps(result, indent=2, default=str))
        return 0
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as exc:
        # stdout keeps the machine-readable JSON contract `lo-platform` established; the diagnosis goes to
        # the log stream, and the sentence itself never rides out to a caller that did not earn it.
        log.warning('Suppression command failed', extra={'command': args.command,
                                                         'error_class': type(exc).__name__})
        log.debug('Suppression command details', exc_info=True)
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

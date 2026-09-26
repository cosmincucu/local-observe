"""What the refusal audit may say, and how often it may say it .

A refusal is the platform telling a caller it will not do something. The response carries a sentence;
the durable record carries one of these fixed words, and never the sentence. That is the whole design:
an operator reading `GET /v1/records/audit` must be able to see *that* someone kept trying, and nothing
someone tried to smuggle into a field may ride along to make that record unreadable or false.

Two things live here, with two different state stories:

* **Classification** — a closed map from the platform's own refusal sentences to one bounded word
  (`reason_for`, `refusal_row`). Matching is on the *whole* sentence, exact, so caller-influenced text
  cannot steer the classification by embedding a marker inside it; a sentence this module has never
  seen becomes `unclassified`, which is loud in the log-free sense (one row, one word) and is what the
  totality test in `tests/test_refusal_audit.py` exists to prevent.
* **The write budget** — `RefusalAudit`, one per `Store`: a token bucket over a real monotonic clock
  plus four counters. It bounds the *rate* of refusal rows, nothing else. Unlike the classifier this one
  is **stateful and locked** — a mutable token level, four counters and one `threading.Lock` — and it is
  the only part of the module that reads a clock. Its state is process memory: nothing here survives a
  restart, nothing here is read back from the database, and nothing here is shared between `Store`
  objects.

This module never touches the database, never reads a clock of its own beyond the bucket's injected
monotonic one, and never imports `Store` — `state.py` is the only SQL writer, and the dependency runs
this way only (`refusals.py` imports `state`, `state.py` imports this module inside its own functions)
so neither import cycle exists at load time.

The validators reused below are `state.py`'s own (`label`, `identifier`) rather than private copies:
the audit's bounds must be the *same* bounds the rest of the module enforces, and a second regex that
drifted by one character would be a silent widening of what may be written about a denial.
"""
import threading
import time
from collections.abc import Callable
from typing import Any

from .state import Actor, StateError, identifier, label

# `state.py` imports this module from inside its own functions, never at module level (the
# `notification_safety` precedent in that file), so the one module-level arrow below cannot become a
# load-time cycle. `test_refusal_audit.py` pins that, because the day `state.py` imports this at the
# top the failure is an `ImportError` at service start, not a test failure.

#: The audit operation word. Every refusal at the action boundary writes this operation and nothing
#: else, so a reader can filter on it, and no existing consumer of another word changes meaning.
OPERATION = 'action.refused'
#: The attempt stage the refusal happened on, in the caller's vocabulary. `attempt` + `reason` is the
#: pair an operator reads: one sentence ("Action is not pending") is reachable from two stages, so the
#: reason alone is not enough to tell the two stories apart.
ATTEMPTS = ('propose', 'decide', 'claim', 'outcome')
#: The roles the platform knows. `api.create_app` accepts exactly this list for a credential, and
#: `test_the_role_vocabulary_is_the_one_the_api_accepts` pins the two spellings together: a seventh
#: role would otherwise become an audit value nobody reviewed.
ROLES = ('reader', 'producer', 'proposer', 'human', 'executor', 'summary')
#: Stored instead of a subject that is not a canonical UUID. A refusal often has no durable row to
#: point at (a bad identifier, a missing action), and "we do not know which one" is the honest value.
UNBOUND = 'unbound'
#: The one word for a refusal sentence this map does not carry. Reachable only from a
#: deployment-supplied policy closure that raises its own text; a sentence inside the platform that
#: lands here is a taxonomy gap, and the totality test is what turns that gap into a failing test.
UNCLASSIFIED = 'unclassified'
#: The transport's own early refusal: a `summary`-role credential is turned away from a write route
#: before any state is read, so no `Store` method was entered and no state-layer row would exist.
SUMMARY_ONLY = 'summary-only'

# One word per platform refusal sentence reachable from the four audited lifecycle methods
# (`propose_action`, `decide`, `claim_action`, `execution_outcome`) including the shared gates those
# methods call first (`require`, `label`, `identifier`, `timestamp`) and the sentences the injected
# action policy in `policy.py` raises. Keys are whole sentences; `SENTENCES.get(str(exc), ...)` is the
# only lookup, so no substring of a caller-controlled value can match a key here.
SENTENCES = {
    # The role gate, shared by every audited method.
    'Actor is not authorised for this operation': 'actor-not-authorised',
    # `state.label` / `state.identifier` / the inventory timestamp parser, reached before any
    # transaction opens.
    'Invalid bounded identifier': 'bad-label',
    'Expected canonical UUID': 'bad-identifier',
    'Expected timezone-aware ISO timestamp': 'bad-timestamp',
    # `propose_action`.
    'Invalid action request fields': 'request-fields',
    'Action expiry must be in the next 24 hours': 'expiry-out-of-range',
    'Action retry changed contents': 'retry-changed-contents',
    'Action requires an open incident': 'incident-not-open',
    'Action requires bounded incident event evidence': 'evidence-unbounded',
    'Action evidence must belong to incident': 'evidence-off-incident',
    # `decide`.
    'Invalid decision': 'decision-word',
    'Action is not pending': 'action-not-pending',
    # `claim_action`.
    'Action is not available for dispatch': 'action-not-dispatchable',
    'Incident recovered; propose again only if needed': 'incident-recovered',
    # `execution_outcome`.
    'Invalid execution outcome': 'outcome-word',
    'Execution already terminal or absent': 'execution-not-reportable',
    'Runner identity/token mismatch': 'runner-credential-mismatch',
    'Human reconciliation requires unknown outcome': 'reconciliation-state',
    # `policy.py`, reached through `propose_action` and `claim_action`.
    'Expected distinct bounded targets': 'policy-targets-shape',
    'Action/version not allowlisted': 'policy-not-allowlisted',
    'Action parameters exceed limit': 'policy-parameters-size',
    'Action parameters do not match allowlisted schema': 'policy-parameters-schema',
    'Target is not opted into remediation': 'policy-target-opt-in',
}

#: Words the state layer can produce. Every value of `SENTENCES`, plus `unclassified`.
REASONS = frozenset(SENTENCES.values()) | {UNCLASSIFIED}
#: Words only the transport produces. Deliberately disjoint from `REASONS` (asserted both ways: by the
#: literal below and by `set(SENTENCES.values()) & TRANSPORT_REASONS == set()` in the test), which is
#: what makes "no duplicate row for one refusal" a property of the vocabulary rather than a runtime
#: flag that a future handler can forget to check.
TRANSPORT_REASONS = frozenset({SUMMARY_ONLY})
#: Everything `refusal_row` will accept as a reason, in one closed set.
ALL_REASONS = REASONS | TRANSPORT_REASONS

# The write budget, fixed by this module and not operator-configurable: a knob nobody reviewed is a
# second, undocumented policy. 64 tokens with 1 token/second means a burst of 64 refusals is written
# in full (the invariant file's nine attempts fit three times over) and a sustained flood is written
# at 1 row/second after that burst, so the audit table cannot be grown faster than one bounded row per
# second by refusal traffic alone. The counters saturate at signed-63 (`COUNTER_LIMIT`, 2**63-1 — a
# different number about a different thing: the 64 bounds a rate, the ceiling bounds a total) rather
# than wrapping, so a process that has been refusing for centuries reports 9223372036854775807 and
# names itself in `saturated` instead of a small wrong number.
CAPACITY = 64
REFILL_TOKENS_PER_SECOND = 1
COUNTERS = ('written', 'dropped', 'failed', 'unauditable')
COUNTER_LIMIT = 2 ** 63 - 1
#: What the counters describe, and what does *not* survive them. Both words are load-bearing: the
#: ceiling bounds the rate of writes in this process, and a restart resets them while the rows already
#: committed stay in the database. `docs/units/refusal-audit.md` states the same limit in prose.
SCOPE = 'process-local'
RESETS_ON_RESTART = True
#: Pinned by test: the whole stored text of the widest legal row. The columns are bounded above
#: (`label` 128, canonical UUID 36, `OPERATION` 14, the detail below) precisely so this number cannot
#: drift upward without a test noticing.
ROW_TEXT_LIMIT = 512
#: The one instant an audit-write failure is logged per, in seconds of *actual elapsed* monotonic time
#: since the line that was actually printed. A locked or full database that keeps failing costs one
#: line a minute, not one line per refusal — and not two lines 0.1 s apart because they straddled a
#: minute boundary.
FAILURE_LOG_INTERVAL_SECONDS = 60


def reason_for(exc: BaseException) -> str:
    """Return the one fixed word for a platform refusal, or `unclassified` for a sentence nobody mapped.

    Exact whole-sentence match, never a substring: `api.stable_code` tolerates imprecision because an
    error body is transient, and a durable record must not be steerable by text the caller can affect.
    """
    return SENTENCES.get(str(exc), UNCLASSIFIED)


def attribution(actor: Any) -> tuple[str, str] | None:
    """Return ``(identity, role)`` for an `Actor` this module can honestly name, else `None`.

    `None` is the answer that matters: a caller that hands the state layer something which is not an
    `Actor`, or one whose identity is not a bounded label, or whose role is not one of the six words,
    gets **no row at all** rather than a row naming a fabricated or hashed actor. Counting the refusal
    as unauditable is the honest record; inventing an identity for it would put words in a reader's
    mouth about who was refused.
    """
    if not isinstance(actor, Actor) or actor.role not in ROLES:
        return None
    identity = bounded_label(actor.identity)
    return None if identity is None else (identity, actor.role)


def bounded_label(value: Any) -> str | None:
    """Return `value` when `state.label` accepts it, else `None`.

    `None` rather than a raise, because the caller is the refusal path itself: a second exception
    here would replace the denial the client is supposed to receive.
    """
    try:
        return label(value)
    except StateError:
        return None


def subject_field(value: Any) -> str:
    """Return the canonical UUID `value`, or the `unbound` sentinel for anything else.

    A subject is a pointer to a durable row, not a description of the request: raw caller text of any
    length is refused by `identifier()` and lands on the sentinel, which is also why a flood of random
    UUIDs costs nothing extra in memory (nothing here is keyed by subject).
    """
    if not isinstance(value, str) or len(value) > 64:
        return UNBOUND
    try:
        return identifier(value)
    except StateError:
        return UNBOUND


def detail_fields(attempt: str, reason: str, role: str | None = None) -> dict[str, str]:
    """Return the audit `detail` payload: three fixed words, all from closed sets, no free text.

    `role` is written only when it is one of `ROLES` (which `attribution` already guarantees), so the
    field can never hold a role string the platform did not configure. It names *which* credential
    class was refused, which is the question an operator asks first; the identity column answers who.
    """
    fields = {'attempt': attempt, 'reason': reason}
    if role is not None:
        fields['role'] = role
    return fields


def refusal_row(attempt: Any, reason: Any, actor: Any, subject: Any = None) -> tuple[str, str, dict] | None:
    """Return the ``(actor, subject, detail)`` of one honest refusal row, or `None` when there is none.

    Every input passes a closed vocabulary or a bounded validator here, and for the inputs this helper
    is written for — a `str` attempt/reason, an `Actor`-shaped or not actor, any subject — it answers
    `None` instead of raising. It is called from the path that is already refusing, and nothing in the
    audit may turn a denial into an error, into a different denial, or into a row that says something
    that is not true. That is a promise about *these* shapes, not about arbitrary objects: an input
    whose own `__eq__` or `__hash__` raises, or a broken `Actor` subclass, can still propagate, and the
    caller re-raises the denial it already had rather than pretending this helper is total.

    The `isinstance(reason, str)` test runs before the `ALL_REASONS` lookup for that reason too:
    `reason in frozenset(...)` hashes its argument, so an unhashable `[]` or `{}` would raise `TypeError`
    out of a *classification* helper — the one place a stray caller object must not reach the wire. A
    non-string reason is simply not in the vocabulary, which is what `None` means.
    """
    if (not isinstance(attempt, str) or not isinstance(reason, str) or attempt not in ATTEMPTS
            or reason not in ALL_REASONS):
        return None
    named = attribution(actor)
    if named is None:
        return None
    identity, role = named
    return identity, subject_field(subject), detail_fields(attempt, reason, role)


def row_text_width(row: dict[str, Any]) -> int:
    """Return the stored text width of one audit row: the five columns, UTF-8, no framing or JSON of the
    row itself. This is the measurement the `<= ROW_TEXT_LIMIT` test pins, stated in one place so the
    test cannot be satisfied by a different definition than the document's.
    """
    return sum(len(str(row[name]).encode()) for name in ('at', 'actor', 'operation', 'subject', 'detail'))


class RefusalAudit:
    """The token bucket and the four counters behind `Store.refusal_audit_status()`.

    One instance per `Store` object, which means one per process in practice (`api.create_app` and
    every CLI open a single store). What it bounds is the *rate* of refusal rows: capacity 64 tokens,
    initially full, refilled at 1 token/second from a real monotonic clock — never from the
    caller-supplied `now=` a `Store` method accepts, because a rate limit an attacker sets is not a
    limit.

    Thread-safety: one lock guards the token level and the counters, and it is never held across the
    SQLite write. `reserve()` and `count()` are separate calls precisely so the transaction runs
    between them: holding an accounting lock over database I/O would turn a locked database into a
    stalled one. Two concurrent refusals can therefore both reserve, and both write — that is the
    design (a burst of 64 is allowed to produce 64 rows), and what the lock guarantees is that no
    burst spends more tokens than the bucket holds.

    `clock` is injectable for tests only, so a refill can be observed without sleeping; production
    passes nothing and gets `time.monotonic`.
    """

    def __init__(self, *, capacity: int = CAPACITY,
                 refill_per_second: int = REFILL_TOKENS_PER_SECOND,
                 clock: Callable[[], float] | None = None) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._clock = clock if clock is not None else time.monotonic
        self._lock = threading.Lock()
        self._tokens = float(capacity)
        self._last_refill = self._clock()
        self._counters = dict.fromkeys(COUNTERS, 0)
        # The single instant an audit-write failure was last logged at. One instant, not a per-minute
        # bucket: see `should_log_failure`.
        self._last_failure_logged_at: float | None = None

    def _refill_locked(self, now: float) -> None:
        """Move the token level up to what the clock has earned. Caller holds the lock."""
        elapsed = now - self._last_refill
        if elapsed > 0:
            self._tokens = min(float(self.capacity), self._tokens + elapsed * self.refill_per_second)
        # A clock that went backwards refills nothing; the accounting just moves on from wherever it is.
        self._last_refill = now

    def reserve(self) -> bool:
        """Spend one write token if the bucket has one; the spend is not refunded if the write fails.

        A failed write costs quota on purpose. A database that is refusing writes is exactly the
        situation where retrying every refusal would be a second failure mode, and the `failed`
        counter is the record of what was lost — not a licence to keep hammering the file.
        """
        with self._lock:
            self._refill_locked(self._clock())
            if self._tokens < 1:
                return False
            self._tokens -= 1
            return True

    def count(self, name: str) -> None:
        """Add one to a named counter, saturating at `COUNTER_LIMIT` instead of wrapping or raising."""
        with self._lock:
            current = self._counters[name]
            if current < COUNTER_LIMIT:
                self._counters[name] = current + 1

    def should_log_failure(self) -> bool:
        """Return True for the first audit-write failure and then only 60 s of monotonic time later.

        The failure path is a locked, full or corrupt database, and the refusal that triggered it is
        still refused at the client's own rate. One line per `FAILURE_LOG_INTERVAL_SECONDS` of *actual
        elapsed* time, naming nothing but an exception class, is the whole signal; the counter behind it
        is the count.

        The clock is read **inside** the lock and compared against the last instant that was actually
        logged, not against an aligned minute bucket. Both details are the property: aligned buckets let
        two failures 0.1 s apart straddle a minute boundary and print two lines (59.9, then 60.0), and a
        clock read taken before the lock can be re-ordered against another thread's grant, so two
        threads each see a fresh bucket and both log. One lock, one stored instant, one line per
        interval — and the stored instant only ever moves forward, so the wait stays bounded even if a
        monotonic source misbehaves.
        """
        with self._lock:
            now = self._clock()
            last = self._last_failure_logged_at
            if last is not None and now - last < FAILURE_LOG_INTERVAL_SECONDS:
                return False
            self._last_failure_logged_at = now
            return True

    @property
    def counters(self) -> dict[str, Any]:
        """The four counters as a snapshot, with the saturated names marked rather than implied."""
        with self._lock:
            counters = dict(self._counters)
        return {**counters, 'saturated': sorted(name for name in COUNTERS
                                                if counters[name] >= COUNTER_LIMIT)}

    @property
    def tokens_available(self) -> int:
        """Whole tokens writable right now. A floor, not a promise: another thread may take the one you saw.

        The refill is applied on a read too, so `/v1/runtime` reports the level the next refusal will
        meet rather than the level the last refusal left. No I/O happens under this lock.
        """
        with self._lock:
            self._refill_locked(self._clock())
            return int(self._tokens)

    def status(self) -> dict[str, Any]:
        """The operator-facing body: counters, the budget's shape, and how far it can be trusted."""
        return {**self.counters, 'capacity': self.capacity,
                'refill_tokens_per_second': self.refill_per_second,
                'tokens_available': self.tokens_available,
                'scope': SCOPE, 'resets_on_restart': RESETS_ON_RESTART}

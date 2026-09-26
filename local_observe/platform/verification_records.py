"""Durable verification bindings and submitted observations .

`docs/CONTRACTS.md` §5 says verification after execution determines incident recovery, and
`platform/verification.py` computes that verdict — but until now the only durable thing it could file
was one four-field `evidence` row, from which the threshold, the rule, the window and the *reason* are
not readable back. This module is the record behind that verdict: two append-only tables, the policy
that decides which detector revision a signal *means*, and the server-side judgement of one submitted
observation. It is storage and judgement only — no scheduler, no queue, no HTTP route, no producer
enablement, and no incident resolution. Three questions it answers and one it refuses:

* **what was this action about?** `Store.get_verification_binding` reads the binding captured *inside
  the proposal's own transaction*, from the immutable events that action cited. A bound answer is the
  complete reviewed mapping plus the chosen `event_id` and `action_targets`, digested. An unbound
  answer is an explicit captured reason (`unsupported-targets`, `origin-unmatched`,
  `origin-ambiguous`), and an action this build never captured reads as `unbound`/`not-captured`. The
  binding is never re-derived later: a policy change, a restart or a retry cannot move it, and nothing
  backfills history.
* **who says what?** `Store.put_verification` accepts a *submitted observation* from one identity the
  CURRENT policy names as a verifier and nothing else — not a runner, not a human, not a random
  producer, and never a caller-supplied verdict. The server derives `cleared`/`not_cleared`/`unknown`
  from the captured mapping, the execution's own state and the real clock.
* **can I read it back?** `Store.get_verification` returns the stored document verbatim, forever.
  Nothing here prunes, expires or overwrites a record: an expired receipt still reads, and a replay of
  identical bytes returns `created: false` with the original row untouched, even after the evidence has
  aged out or the execution was reconciled to `unknown`.
* **did a remote read actually happen?** Not provable here, and this module does not claim it. The
  verifiers it accepts are *trusted for actual observation and completeness*: every check below is a
  consistency check against a reviewed definition, and a complete set of bounded, mutually consistent
  claimed samples is still a claim. `unknown` means this server could not derive an answer from what it
  was given — it never means a verifier lied, and `cleared` never means the platform itself measured it.

Two designs are load-bearing and both are refusals. **Scope before verdict:** a receipt whose query,
approved parameters or window is not the captured read, and samples that are not the captured
resource/metric inside the submitted window, are refusals for *every* outcome — never a conveniently
`unknown` answer about something else. A window that is not exactly the captured `window_seconds` long,
or that is not over yet, or that lies in the future, is refused rather than graded. **The verdict is
derived, in a fixed precedence** (see `_grade`), from state the caller does not control: an
`unknown` execution, a window that opens before the terminal stamp, an unanswered store, an expired or
truncated receipt, an excerpt shorter than the claimed row count, an empty window and a newest sample
from before the boundary each name themselves; only a newest instant after the boundary, complete and
unexpired, is allowed to speak about recovery.

Cycle-safety follows the package's existing rule (`refusals`, `notification_safety`, `audit_reader`):
`state.py` imports this module from *inside* its own methods, and this module imports `state` at module
level, so the dependency runs one way only and no load-time cycle exists at service start.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import json
import math
from typing import Any

from local_observe.inventory.validation import InvalidInventory, canonical, digest, timestamp, utc_text
from .state import Actor, StateError, identifier, label, require
from .verification import CLEARED, COMPARISONS, NOT_CLEARED, UNKNOWN, VERDICTS

#: The one policy document version this build admits, spelled strictly: `1.0`, `True` and `"1"` are
#: all refusals, because a policy that quietly meant another version is a different review.
SCHEMA_VERSION = 1
#: The only query kind a mapping may name: the one signal this repo can re-read as a number. A log,
#: trace or alert-rule origin has no numeric read behind the facade's named read, so it cannot be
#: reviewed into a policy at all rather than being mounted and answering `unknown` forever.
QUERY_TYPE = 'metric-threshold'
#: The policy document's key set, exact.
POLICY_KEYS = ('schema_version', 'verifiers', 'mappings')
#: One mapping's key set, exact: the whole reviewed numeric meaning of one detector revision, with
#: nothing optional to guess about.
MAPPING_KEYS = ('source', 'rule_id', 'rule_version', 'condition', 'resource_id', 'query_type',
                'parameters', 'metric_name', 'threshold', 'comparison', 'window_seconds',
                'artifact_sha256')
#: The identity of a reviewed meaning. Two mappings that differ only in threshold are two meanings for
#: one detector revision, which is exactly the ambiguity the selector check refuses.
SELECTOR_KEYS = ('source', 'rule_id', 'rule_version', 'condition', 'resource_id')
#: The approved parameters of the one read a mapping describes, and no others: an artifact pin is
#: required, so the optional-pin form `verification.Origin` allows is not admitted here.
READ_PARAMETERS = ('artifact_sha256', 'resource_id', 'rule_id')
#: Verifier identities are who may attest: at least one, or a policy would authorize nobody while
#: looking configured; at most 32, so the allowlist stays a reviewed list and not a growable one.
VERIFIER_LIMITS = (1, 32)
MAPPING_LIMITS = (0, 64)
MAX_POLICY_BYTES = 65_536
#: The same evaluation span `verification.WINDOW_SECONDS_LIMITS` gives a re-check: minutes to a day.
#: A binding's numeric meaning includes how long a window it was evaluated over, so a record read back
#: months later still says what length of evidence could have answered it.
WINDOW_SECONDS_LIMITS = (60, 86_400)
#: Rows one submission may carry, and rows one receipt may claim. The excerpt bound is the platform's
#: existing evidence bound (20); the claimed bound is the store facade's 2 000-row page rounded up to
#: a reviewed number, because a receipt claiming more rows than an excerpt can carry is the honest
#: `evidence-incomplete` case and must stay expressible instead of unrepresentable.
SAMPLE_LIMIT = 20
SAMPLE_COUNT_LIMIT = 10_000
#: First-write verification records per execution. Exact retries stay admissible at the cap; the 65th
#: *new* window is refused. It bounds what one execution can make readable back, not the number of
#: checks a caller may attempt.
RECORDS_PER_EXECUTION = 64
MAX_RECORD_BYTES = 32_768
MAX_STORED_BYTES = 65_536
#: The submitted record's key set, exact. There is no verdict, no reason, no threshold, no actor and no
#: free-text note in it, so a producer cannot file its own conclusion or describe its own scope.
RECORD_KEYS = ('execution_id', 'binding_id', 'window', 'outcome', 'receipt', 'samples')
#: Read-outcome words (`store.client.ReadOutcome.status`), NOT fields of a receipt.
OUTCOMES = ('available', 'unavailable', 'expired')
#: `store.client.ReadReceipt.as_dict()`'s six fields, exact and no seventh.
RECEIPT_KEYS = ('expires_at', 'parameters', 'query_type', 'sample_count', 'truncated', 'window')
#: One claimed row, exact. A metric name is a selector and never an evidence parameter
#: (`docs/CONTRACTS.md` §4), so it is a field of a row rather than of the receipt that scoped the read.
SAMPLE_KEYS = ('metric_name', 'observed_at', 'resource_id', 'value')
#: The 15 keys of the stored document: the whole readable record, and exactly the shape
#: `Store.get_verification` answers with (no more, and never a caller-supplied field among them).
RECORD_DOCUMENT_KEYS = ('verification_id', 'execution_id', 'action_id', 'binding_id', 'origin',
                        'window', 'outcome', 'receipt', 'samples', 'verdict', 'reason', 'value',
                        'sampled_at', 'recorded_by', 'recorded_at')

STATUS_BOUND, STATUS_UNBOUND = 'bound', 'unbound'
#: The one reason a bound row may carry: it matched one reviewed mapping to one cited event.
BOUND_REASON = 'matched'
#: The captured refusals — written down, because "we never looked" and "we looked and this is why
#: nothing binds" are different answers to an operator, and only one of them is checkable later.
UNBOUND_REASONS = ('unsupported-targets', 'origin-unmatched', 'origin-ambiguous')
#: The synthetic answer for an action with no stored row: an action proposed before this table existed,
#: or by a build with no policy mounted. Not a stored value (the `CHECK` in migration 4 refuses it).
NOT_CAPTURED = 'not-captured'
#: The one audit row a *first* accepted write leaves. No lifecycle refusal word is added or reused
#: here: these methods sit outside the four audited action attempts by design, and a duplicate replay
#: or a conflict writes nothing at all.
AUDIT_OPERATION = 'verification.recorded'
#: Roles that may read a record or a binding. `producer` is admissible only while the current policy
#: names that identity (see `_reader`), and `summary` never is.
READ_ROLES = ('reader', 'human', 'proposer', 'executor')

#: Every reason the server may derive. `comparison-*`, `store-unanswered` and `window-empty` are the
#: words `verification.py` already answers with; the rest are this record's own boundaries. A reason
#: outside this set is a bug, and `_grade` is the only place any of them is produced.
REASONS = frozenset({'comparison-satisfied', 'comparison-failed', 'execution-boundary-unknown',
                     'pre-execution-window', 'store-unanswered', 'evidence-expired',
                     'evidence-truncated', 'evidence-incomplete', 'window-empty',
                     'pre-execution-sample'})
#: The one answer a bug in the precedence below may not produce: `_derive` refuses a word outside the
#: two vocabularies rather than storing a verdict no reader has ever been told how to read. It is the
#: same guard `verification._unknown` gives that unit's reasons.
BAD_DERIVATION = 'Verification verdict is not derivable'

# Fixed sentences. Each names a field, a bound owned by this module or a piece of platform state the
# caller cannot see from here — never the offending value, which is `api.py`'s rule for a 400 body and
# is cheaper to keep here than to reconstruct at the edge.
BAD_ACTOR = 'Actor is not authorised for this operation'
NO_POLICY = 'Verification policy is not configured; verification records cannot be written'
BAD_POLICY_VERSION = 'Verification policy schema_version is unsupported'
BAD_POLICY_FIELDS = 'Invalid verification policy fields'
BAD_POLICY_DOCUMENT = 'Verification policy is not bounded JSON data'
BAD_POLICY_SIZE = 'Verification policy exceeds 64 KiB'
BAD_POLICY_VERIFIERS = 'Verification policy verifier list is unbounded or duplicated'
BAD_POLICY_MAPPINGS = 'Verification policy mapping list is unbounded'
BAD_MAPPING_FIELDS = 'Invalid verification mapping fields'
BAD_MAPPING_QUERY = 'Verification mapping query_type is unsupported'
BAD_MAPPING_PARAMETERS = 'Verification mapping parameters do not match its own scope'
BAD_MAPPING_COMPARISON = 'Verification mapping comparison is unsupported'
BAD_MAPPING_THRESHOLD = 'Verification mapping threshold must be a finite number'
BAD_MAPPING_WINDOW = 'Verification mapping window_seconds must be 60..86400 seconds'
BAD_DUPLICATE_MAPPING = 'Verification mapping duplicates a detector revision with another meaning'
BAD_CLOCK = 'Verification needs an aware UTC clock'
BAD_RECORD = 'Invalid verification record fields'
BAD_RECORD_SIZE = 'Verification record exceeds 32 KiB before any write'
BAD_OUTCOME = 'Invalid verification read outcome'
BAD_BINDING_ID = 'Expected lowercase SHA256 binding id'
BAD_VERIFICATION_ID = 'Expected lowercase SHA256 verification id'
BAD_WINDOW = 'Invalid bounded verification window'
WINDOW_NOT_CAPTURED = 'Verification window is not the captured evaluation window'
WINDOW_IN_FUTURE = 'Verification window is in the future'
BAD_RECEIPT = 'Invalid verification receipt fields'
RECEIPT_EXPIRY = 'Verification receipt expires before its window end'
RECEIPT_SCOPE = 'Verification receipt is not the captured read'
RECEIPT_REQUIRED = 'Verification record needs a receipt for this read outcome'
BAD_SAMPLES = 'Invalid bounded verification samples'
SAMPLE_SCOPE = 'Verification samples are not the captured resource and metric'
ROWS_WITHOUT_ANSWER = 'A verification read that did not answer carries no rows'
ROWS_OVER_COUNT = 'Verification samples exceed the claimed row count'
UNKNOWN_EXECUTION = 'Execution already terminal or absent'
EXECUTING_EXECUTION = 'An executing execution cannot be verified yet'
BAD_BINDING = 'Action binding does not match this verification record'
UNKNOWN_ACTION = 'Action is not known to this platform'
BAD_STORED_BINDING = 'Stored action binding is unreadable'
BAD_STORED_EXECUTION = 'Stored execution state is unreadable'
RETRY_CHANGED = 'Verification retry changed contents'
RECORD_LIMIT = 'Execution already carries every verification record it may have'
NEEDS_MIGRATION = 'Verification tables are unavailable; verify the schema and restore or migrate a validated copy'
RECORD_TOO_LARGE = 'Stored verification record exceeds 64 KiB'

_HEX = frozenset('0123456789abcdef')
#: What `_plain` will walk: a documented ceiling, not a tuning knob. Every shape this module admits is
#: flat or two levels deep, so a document that reaches this depth is not a policy or a record, and
#: refusing it is what keeps `canonical()`'s recursion from ever being the thing that fails.
MAX_DEPTH = 8
MAX_CONTAINER_ITEMS = 64
MAX_JSON_NODES = 4096
INTEGER_LIMIT = 2 ** 63 - 1
STRING_LIMIT = 4_096


def _plain(value: Any, *, sentence: str, depth: int = 0,
           budget: list[int] | None = None) -> None:
    """Refuse anything that is not bounded JSON-compatible data, before it is hashed, digested or sent.

    Runs *ahead* of the field checks so a value can never reach `canonical()` or a `digest()` while
    carrying a float that JSON cannot express (NaN, an infinity), an integer whose text is unbounded,
    an object with a `__str__` nobody reviewed, a cycle, or a nesting depth that would raise
    `RecursionError` from inside a serializer. Those are the ways a "fixed safe sentence" refusal turns
    into a 500, and a refusal is the whole contract here.

    A `bool` is admissible data at this layer (it is JSON) and is refused by the field validators,
    which is where "a boolean is not a number, and not a clock, and not a row count" is decided.
    """
    if budget is None:
        budget = [MAX_JSON_NODES]
    budget[0] -= 1
    if depth > MAX_DEPTH or budget[0] < 0:
        raise StateError(sentence)
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if len(value) > STRING_LIMIT:
            raise StateError(sentence)
        return
    if isinstance(value, int):
        if abs(value) > INTEGER_LIMIT:
            raise StateError(sentence)
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise StateError(sentence)
        return
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise StateError(sentence)
        for key, item in value.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 64:
                raise StateError(sentence)
            _plain(item, sentence=sentence, depth=depth + 1, budget=budget)
        return
    if isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise StateError(sentence)
        for item in value:
            _plain(item, sentence=sentence, depth=depth + 1, budget=budget)
        return
    raise StateError(sentence)


def _number(value: Any, sentence: str) -> float:
    """Return *value* as one canonical finite float, refusing a bool, a string and an unusable number.

    The float normalisation is not a convenience: a threshold reviewed as `90` and a value submitted as
    `90.0` must be comparable, and a binding digest must not fork on how a number happened to be
    spelled in a file (the same rule `verification.Origin` applies to its own threshold).
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StateError(sentence)
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise StateError(sentence) from None
    if not math.isfinite(result):
        raise StateError(sentence)
    return result


def _whole(value: Any, bounds: tuple[int, int], sentence: str) -> int:
    """Return *value* as an int inside *bounds*, refusing a bool and every non-whole number."""
    if isinstance(value, bool) or not isinstance(value, int) or not bounds[0] <= value <= bounds[1]:
        raise StateError(sentence)
    return value


def _sha256(value: Any, sentence: str) -> str:
    """Return *value* when it is one lowercase SHA-256 hex digest, and refuse every other spelling.

    Uppercase is refused rather than folded: a digest is an identifier here (a binding id and a logical
    record id), and a second casing of one identifier is how one check becomes two records.
    """
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in _HEX for character in value)):
        raise StateError(sentence)
    return value


def _instant(value: Any, sentence: str) -> dt.datetime:
    """Return *value* as an aware UTC instant, converting a parse failure into the refusal it belongs to.

    `inventory.timestamp` raises `InvalidInventory` for text it cannot read. Every other failure this
    module raises is a `StateError`, and a caller that has to catch two classes to read one surface
    safely is a caller that will eventually catch neither — so the two are the same sentence here.
    """
    if not isinstance(value, str):
        raise StateError(sentence)
    try:
        return timestamp(value)
    except (InvalidInventory, ValueError, TypeError, AttributeError, OverflowError):
        raise StateError(sentence) from None


def _clock(now: Any) -> dt.datetime:
    """Return the server instant to judge at: *now*, or this call's real aware UTC clock.

    A naive datetime is refused and never read as local time or as UTC: which instant a record is
    graded at is the server's decision, and one that silently moved by hours would move
    `evidence-expired` and the execution boundary with it.
    """
    if now is None:
        return dt.datetime.now(dt.timezone.utc)
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise StateError(BAD_CLOCK)
    try:
        if now.utcoffset() is None:
            raise StateError(BAD_CLOCK)
        return now.astimezone(dt.timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise StateError(BAD_CLOCK) from None


def _label(value: Any, sentence: str) -> str:
    """Return `state.label(value)`, with *sentence* for anything the bounded alphabet refuses."""
    try:
        return label(value)
    except StateError:
        raise StateError(sentence) from None


def _identifier(value: Any, sentence: str) -> str:
    """Return `state.identifier(value)` (canonical UUID text), refusing with *sentence*."""
    try:
        return identifier(value)
    except StateError:
        raise StateError(sentence) from None


def _mapping(document: Any) -> dict[str, Any]:
    """Return one validated, normalised mapping: every field required, none guessed.

    This is deliberately stricter than `verification.Origin`, which is a pure re-grader and so may be
    built without a `metric_name` and without an artifact pin. A policy entry is neither: an unpinned
    historical detector is *not* guessed a pin (the pin is what makes the reviewed SQL that produced the
    alert the same SQL a later reader reauthorises), and an entry that could mean two queries is one
    entry too many to review.
    """
    _plain(document, sentence=BAD_POLICY_DOCUMENT)
    if not isinstance(document, dict) or set(document) != set(MAPPING_KEYS):
        raise StateError(BAD_MAPPING_FIELDS)
    query_type = _label(document['query_type'], BAD_MAPPING_FIELDS)
    if query_type != QUERY_TYPE:
        raise StateError(BAD_MAPPING_QUERY)
    comparison = document['comparison']
    if not isinstance(comparison, str) or comparison not in COMPARISONS:
        raise StateError(BAD_MAPPING_COMPARISON)
    parameters = document['parameters']
    _plain(parameters, sentence=BAD_MAPPING_PARAMETERS)
    if not isinstance(parameters, dict) or set(parameters) != set(READ_PARAMETERS):
        raise StateError(BAD_MAPPING_PARAMETERS)
    resource_id = _identifier(document['resource_id'], BAD_MAPPING_FIELDS)
    rule_id = _label(document['rule_id'], BAD_MAPPING_FIELDS)
    artifact = _sha256(document['artifact_sha256'], BAD_MAPPING_FIELDS)
    scoped = {'resource_id': _identifier(parameters['resource_id'], BAD_MAPPING_PARAMETERS),
              'rule_id': _label(parameters['rule_id'], BAD_MAPPING_PARAMETERS),
              'artifact_sha256': _sha256(parameters['artifact_sha256'], BAD_MAPPING_PARAMETERS)}
    # The scope is stated twice on purpose (once as mapping fields, once as the read's approved
    # parameters, exactly as the receipt carries them) and the two must agree: a mapping whose
    # parameters name another rule or artifact would scope the read somewhere other than the signal it
    # reviewed, and would bind a numeric meaning to a read that cannot be reauthorised.
    if scoped != {'resource_id': resource_id, 'rule_id': rule_id, 'artifact_sha256': artifact}:
        raise StateError(BAD_MAPPING_PARAMETERS)
    return {'source': _label(document['source'], BAD_MAPPING_FIELDS), 'rule_id': rule_id,
            'rule_version': _label(document['rule_version'], BAD_MAPPING_FIELDS),
            'condition': _label(document['condition'], BAD_MAPPING_FIELDS),
            'resource_id': resource_id, 'query_type': query_type, 'parameters': scoped,
            'metric_name': _label(document['metric_name'], BAD_MAPPING_FIELDS),
            'threshold': _number(document['threshold'], BAD_MAPPING_THRESHOLD),
            'comparison': comparison,
            'window_seconds': _whole(document['window_seconds'], WINDOW_SECONDS_LIMITS,
                                     BAD_MAPPING_WINDOW),
            'artifact_sha256': artifact}


class VerificationPolicy:
    """The reviewed verifier allowlist and detector-meaning table, validated and snapshotted.

    Construction takes a plain parsed document (a later API startup reads the named
    `LO_VERIFICATION_POLICY` service file; this slice deliberately ships no loader, so no path, environment
    value or default is read here) and holds a private, normalised deep copy of it. Nothing shares
    memory with the caller's document, and every accessor builds a fresh copy, so mutating the caller's
    dict or list, or an accessor's result, cannot change what this policy means — a binding digested
    against one mapping table has to keep meaning that table's numbers.

    Two things are NOT in scope by construction and stay out: any `Origin`-shaped permissiveness
    (optional artifact pin, default comparison/window, absent metric name), and any statement that a
    verifier's readings are true. `verifiers` bounds *who may file*; it attests nobody.
    """

    __slots__ = ('_mappings', '_verifiers')

    def __init__(self, document: Any) -> None:
        _plain(document, sentence=BAD_POLICY_DOCUMENT)
        if not isinstance(document, dict) or set(document) != set(POLICY_KEYS):
            raise StateError(BAD_POLICY_FIELDS)
        # Sized on the caller's own bytes, before anything is normalised: the bound is on the document
        # an operator reviewed, and normalisation must not be able to sneak under it.
        if len(canonical(document).encode()) > MAX_POLICY_BYTES:
            raise StateError(BAD_POLICY_SIZE)
        version = document['schema_version']
        if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
            raise StateError(BAD_POLICY_VERSION)
        if not isinstance(document['verifiers'], list):
            raise StateError(BAD_POLICY_VERIFIERS)
        if not VERIFIER_LIMITS[0] <= len(document['verifiers']) <= VERIFIER_LIMITS[1]:
            raise StateError(BAD_POLICY_VERIFIERS)
        verifiers = tuple(_label(item, BAD_POLICY_VERIFIERS) for item in document['verifiers'])
        if len(set(verifiers)) != len(verifiers):
            raise StateError(BAD_POLICY_VERIFIERS)
        if not isinstance(document['mappings'], list):
            raise StateError(BAD_POLICY_MAPPINGS)
        if not MAPPING_LIMITS[0] <= len(document['mappings']) <= MAPPING_LIMITS[1]:
            raise StateError(BAD_POLICY_MAPPINGS)
        mappings = tuple(_mapping(item) for item in document['mappings'])
        selectors = [tuple(item[key] for key in SELECTOR_KEYS) for item in mappings]
        # Two entries for one detector revision is not a wider policy but an unreviewed one: only one
        # numeric meaning may exist for an exact source/rule/version/condition/resource, however the
        # thresholds differ, because a binding has to name one of them and cannot choose.
        if len(set(selectors)) != len(selectors):
            raise StateError(BAD_DUPLICATE_MAPPING)
        self._verifiers = verifiers
        self._mappings = mappings

    def __repr__(self) -> str:
        """Report the shape of the policy and none of its content."""
        return (f'{type(self).__name__}(verifiers={len(self._verifiers)}, '
                f'mappings={len(self._mappings)})')

    @property
    def verifiers(self) -> tuple[str, ...]:
        """The identities the current policy admits as attestors, as an immutable tuple."""
        return self._verifiers

    @property
    def mappings(self) -> tuple[dict[str, Any], ...]:
        """Fresh copies of every normalised mapping, in the document's own order."""
        return deepcopy(self._mappings)

    def allows(self, identity: Any) -> bool:
        """Return whether *identity* is an allowlisted verifier right now, without raising."""
        try:
            return isinstance(identity, str) and label(identity) in self._verifiers
        except StateError:
            return False


def _reader(policy: VerificationPolicy | None, actor: Any) -> None:
    """Refuse every actor a read is not for, before any database is opened.

    `summary` is refused because it is the transport's memory-only role and a record is not memory-only
    reading of it; a producer is admitted only while the current policy names it, which is the same
    allowlist that decides write authority, so a reader cannot be a party the policy has never heard of.
    Every refusal is the one sentence `require` already raises for every other gate in this package.
    """
    if not isinstance(actor, Actor):
        raise StateError(BAD_ACTOR)
    _label(actor.identity, BAD_ACTOR)
    if (actor.role == 'producer' and policy is not None
            and policy.allows(actor.identity)):
        return
    require(actor, *READ_ROLES)


def _writer(policy: VerificationPolicy | None, actor: Any) -> None:
    """Refuse every actor that is not a currently allowlisted verifier, before any database is opened.

    Order is the point: a `human`, an executor/runner or a malformed actor is refused on authority,
    and only a genuine producer is then told whether a policy is mounted at all. A random producer with
    a valid credential is not an attestor — the credential says which service called, the allowlist says
    whether that service may speak about this signal.
    """
    require(actor, 'producer')
    if policy is None:
        raise StateError(NO_POLICY)
    if not policy.allows(actor.identity):
        raise StateError(BAD_ACTOR)


def _ready(connection: Any) -> bool:
    """Return whether this connection's file has both verification tables.

    A missing table is a schema failure, not an absent record. A v4 header alone cannot prove that
    both tables survived: reads and writes refuse an incomplete schema. Default-off proposals still
    skip this helper entirely, preserving the old-schema lifecycle fixtures without hiding corruption
    from the new read surface.
    """
    return connection.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN "
        "('verification_bindings','verification_records')").fetchone()[0] == 2


def _unbound(reason: str) -> dict[str, Any]:
    """Return one captured non-binding: explicit, with no id and no origin to read as a partial match."""
    if reason not in UNBOUND_REASONS:
        raise StateError(BAD_DERIVATION)
    return {'status': STATUS_UNBOUND, 'reason': reason, 'binding_id': None, 'origin': None}


def _derive(state: str, reason: str, value: float | None = None,
            sampled_at: str | None = None) -> tuple[str, str, float | None, str | None]:
    """Return one verdict, refusing a word either closed vocabulary does not carry."""
    if state not in VERDICTS or reason not in REASONS:
        raise StateError(BAD_DERIVATION)
    return state, reason, value, sampled_at


def _event_matches(event: Any, mapping: dict[str, Any], target: str) -> bool:
    """Return whether one cited event is the signal this mapping reviewed, read only, guessing never.

    Five identity fields must equal the event's own (`source`, `rule_id`, `rule_version`, `condition`,
    `resource_id`) and the resource must be the action's single target; the event must be `firing` (a
    resolved event's numbers say the condition stopped, which is not the signal an action was proposed
    for); and the event must carry a reference whose source is the event's own source, whose query kind
    is the mapping's, and whose approved parameters equal the mapping's — including the artifact pin,
    where "the pin is missing" is not "the pin matches".
    """
    if not isinstance(event, dict) or event.get('status') != 'firing':
        return False
    if any(event.get(key) != mapping[key] for key in SELECTOR_KEYS) or mapping['resource_id'] != target:
        return False
    references = event.get('evidence')
    if not isinstance(references, list):
        return False
    return any(isinstance(item, dict) and item.get('source') == event.get('source')
               and item.get('query_type') == mapping['query_type']
               and item.get('parameters') == mapping['parameters'] for item in references)


def match_origin(policy: VerificationPolicy, targets: Any,
                 events: Any) -> dict[str, Any]:
    """Return the binding one proposal earns: exactly one event/mapping pair, or an explicit refusal.

    Zero pairs is `origin-unmatched` and two or more is `origin-ambiguous`, and both are durable
    non-bindings rather than a rejected action: an operator must be able to see that a proposal was
    not verifiable and why, and a partial or guessed binding would be a numeric claim about a signal
    this action cannot be shown to be about. Distinctness is over `(event, mapping)` pairs, so two
    references of one event matching one mapping is still the one meaning, while one event matching two
    reviewed mappings — or two events matching anything — is not.
    """
    if not isinstance(targets, list) or len(targets) != 1 or not _is_identifier(targets[0]):
        return _unbound('unsupported-targets')
    target = targets[0]
    mappings = policy.mappings
    pairs = {(event_id, index) for event_id, event in events
             for index, mapping in enumerate(mappings) if _event_matches(event, mapping, target)}
    if len(pairs) != 1:
        return _unbound('origin-unmatched' if not pairs else 'origin-ambiguous')
    event_id, index = next(iter(pairs))
    # The whole reviewed mapping is captured, not a pointer to it: a later reader must be able to see the
    # numeric meaning this action was proposed under even after the policy that produced it is gone,
    # changed or unmounted. `policy.mappings` is already a fresh copy, so the digested origin below can
    # never be taken over live policy state or share a nested dict with one.
    origin = {**mappings[index], 'event_id': event_id, 'action_targets': [target]}
    return {'status': STATUS_BOUND, 'reason': BOUND_REASON, 'binding_id': digest(origin),
            'origin': origin}


def _is_identifier(value: Any) -> bool:
    """Return whether *value* is canonical UUID text, without raising (`match_origin` decides shape)."""
    try:
        identifier(value)
    except StateError:
        return False
    return True


def capture_binding(connection: Any, policy: VerificationPolicy, action_id: str,
                    request: dict[str, Any], now: dt.datetime) -> dict[str, Any]:
    """Capture this proposal's binding inside the caller's own transaction, and store it.

    Called by `Store.propose_action` only when a policy is mounted, after the existing action/evidence
    validation (which already proved every cited event belongs to this incident's open incident) and
    before the `action.proposed` audit row commits, so a proposal and its binding commit together or not
    at all. Only events this action explicitly cited are read — never "the latest event for this
    resource", which would let a signal that arrived afterwards decide what the proposal meant. The
    request's stored payload and fingerprint are untouched: a binding is a statement about the origin,
    not a new field of a client's action.

    This function raises nothing for a signal it cannot bind — `unbound` is a result — and the only
    refusal it can produce is that the file in front of it has no table to write to.
    """
    if not _ready(connection):
        raise StateError(NEEDS_MIGRATION)
    evidence = request.get('evidence')
    cited = []
    for event_id in (evidence if isinstance(evidence, list) else []):
        if not isinstance(event_id, str):
            continue
        row = connection.execute('SELECT payload FROM events WHERE id=?', (event_id,)).fetchone()
        if row is None:
            continue
        try:
            cited.append((event_id, json.loads(row['payload'])))
        except ValueError:
            # An event row this build cannot parse is not evidence about anything: citing it was
            # already refused or accepted elsewhere, and here it simply binds nothing rather than being
            # guessed at.
            continue
    result = match_origin(policy, request.get('targets'), cited)
    origin = result['origin']
    connection.execute('INSERT INTO verification_bindings VALUES (?,?,?,?,?,?)',
                       (action_id, result['status'], result['reason'], result['binding_id'],
                        None if origin is None else canonical(origin), utc_text(now)))
    result['action_id'] = action_id
    return result


def _stored_binding(row: Any) -> dict[str, Any]:
    """Return one stored binding row as the readable document, defensively parsed.

    The origin is re-read from its canonical text on every call, so a caller mutates its own copy and
    can never reach another reader's — or the table's — view of what was reviewed.
    """
    try:
        origin = None if row['origin'] is None else json.loads(row['origin'])
    except ValueError:
        raise StateError(BAD_STORED_BINDING) from None
    if row['status'] == STATUS_BOUND and not isinstance(origin, dict):
        raise StateError(BAD_STORED_BINDING)
    return {'action_id': row['action_id'], 'status': row['status'], 'reason': row['reason'],
            'binding_id': row['binding_id'], 'origin': origin}


def read_binding(store: Any, action_id: Any, actor: Any) -> dict[str, Any]:
    """Return the durable binding of one action: `bound`/`matched`, or an explicit `unbound`.

    An action with no stored row answers `unbound`/`not-captured` rather than `None`: "this build never
    captured a meaning for it" is the fact a caller needs, and the absence of a row is not evidence that
    a signal did not mean something. An action that does not exist is a refusal, because "not captured"
    and "no such action" are different statements and only one of them is about verification.
    """
    _reader(store.verification_policy, actor)
    wanted = identifier(action_id)
    with store.transaction() as connection:
        if connection.execute('SELECT 1 FROM actions WHERE id=?', (wanted,)).fetchone() is None:
            raise StateError(UNKNOWN_ACTION)
        if not _ready(connection):
            raise StateError(NEEDS_MIGRATION)
        row = connection.execute('SELECT * FROM verification_bindings WHERE action_id=?',
                                 (wanted,)).fetchone()
    if row is None:
        return {'action_id': wanted, 'status': STATUS_UNBOUND, 'reason': NOT_CAPTURED,
                'binding_id': None, 'origin': None}
    return _stored_binding(row)


def _window(value: Any, sentence: str) -> dict[str, str]:
    """Return one normalised `{start,end}` half-open window as UTC microsecond text."""
    _plain(value, sentence=sentence)
    if not isinstance(value, dict) or set(value) != {'start', 'end'}:
        raise StateError(sentence)
    start, end = _instant(value['start'], sentence), _instant(value['end'], sentence)
    if not start < end:
        raise StateError(sentence)
    return {'start': utc_text(start), 'end': utc_text(end)}


def _receipt(value: Any) -> dict[str, Any]:
    """Return one submitted receipt, normalised, or refuse: the six fields and nothing else.

    `evidence_query_type`, `detail` and the rows themselves are not receipt fields and are refused as
    such: this is the shape a `store.client.ReadReceipt` printed, and a free-form `detail` string or a
    URL would turn a bounded record into a place to park whatever a transport said.
    """
    _plain(value, sentence=BAD_RECEIPT)
    if not isinstance(value, dict) or set(value) != set(RECEIPT_KEYS):
        raise StateError(BAD_RECEIPT)
    parameters = value['parameters']
    _plain(parameters, sentence=BAD_RECEIPT)
    if not isinstance(parameters, dict) or not 1 <= len(parameters) <= 10:
        raise StateError(BAD_RECEIPT)
    # Bounded labels in both directions, exactly as `store.client.ReadReceipt` bounds them: the scope
    # equality a receipt must then survive against the captured origin is decided by `_check_scope`,
    # so what is settled here is only "this names parameters, not prose".
    scoped = {_label(key, BAD_RECEIPT): _label(item, BAD_RECEIPT) for key, item in parameters.items()}
    truncated = value['truncated']
    if not isinstance(truncated, bool):
        # Strictly a boolean: `1` is a claim about a page in a store that records one, and reading it as
        # `True` (or `0` as `False`) would let a caller choose how much of the truth it filed.
        raise StateError(BAD_RECEIPT)
    window = _window(value['window'], BAD_RECEIPT)
    expiry = _instant(value['expires_at'], BAD_RECEIPT)
    if expiry <= _instant(window['end'], BAD_RECEIPT):
        # Dead evidence is refused rather than graded: an answer that could not be reauthorised when it
        # was written is not a store answer about this window at all (`store.client` refuses to build
        # such a receipt, so a verifier could not have received one).
        raise StateError(RECEIPT_EXPIRY)
    return {'query_type': _label(value['query_type'], BAD_RECEIPT), 'parameters': scoped,
            'window': window, 'expires_at': utc_text(expiry),
            'sample_count': _whole(value['sample_count'], (0, SAMPLE_COUNT_LIMIT), BAD_RECEIPT),
            'truncated': truncated}


def _samples(value: Any, window: dict[str, str]) -> list[dict[str, Any]]:
    """Return the claimed rows, normalised, bounded and inside the window that was submitted."""
    _plain(value, sentence=BAD_SAMPLES)
    if not isinstance(value, list) or len(value) > SAMPLE_LIMIT:
        raise StateError(BAD_SAMPLES)
    start, end = _instant(window['start'], BAD_WINDOW), _instant(window['end'], BAD_WINDOW)
    rows = []
    for item in value:
        _plain(item, sentence=BAD_SAMPLES)
        if not isinstance(item, dict) or set(item) != set(SAMPLE_KEYS):
            raise StateError(BAD_SAMPLES)
        instant = _instant(item['observed_at'], BAD_SAMPLES)
        # Half-open, like every window in this repository: a row at `end` belongs to the next window,
        # and a row outside the claimed window cannot be evidence about this one. Inside `[start, end)`
        # with `end <= now` is also what makes a future sample unreachable.
        if not start <= instant < end:
            raise StateError(BAD_SAMPLES)
        rows.append({'resource_id': _identifier(item['resource_id'], BAD_SAMPLES),
                     'metric_name': _label(item['metric_name'], BAD_SAMPLES),
                     'observed_at': utc_text(instant),
                     'value': _number(item['value'], BAD_SAMPLES)})
    return rows


def _incoming(record: Any) -> dict[str, Any]:
    """Return the normalised submitted statement, or refuse it whole.

    Normalised means: every stamp in this module's own UTC microsecond text, every numeric value as a
    float, and the key sets pinned. The fingerprint is taken over *this* document, so a retry that
    reformats `90` as `90.0` or `2026-…T00:00:00Z` as `+00:00` is one statement, and a retry that
    changes an outcome, a receipt field or a sample value is a conflict and not a re-run.

    The 32 KiB bound is on the caller's canonical bytes *before* any write, and the shape checks run
    before anything is serialised: `canonical()` may only ever be asked about data this module already
    knows it can express.
    """
    _plain(record, sentence=BAD_RECORD)
    if not isinstance(record, dict) or set(record) != set(RECORD_KEYS):
        raise StateError(BAD_RECORD)
    if len(canonical(record).encode()) > MAX_RECORD_BYTES:
        raise StateError(BAD_RECORD_SIZE)
    outcome = record['outcome']
    if not isinstance(outcome, str) or outcome not in OUTCOMES:
        raise StateError(BAD_OUTCOME)
    window = _window(record['window'], BAD_WINDOW)
    receipt = None if record['receipt'] is None else _receipt(record['receipt'])
    samples = _samples(record['samples'], window)
    if receipt is None:
        # The one shape a null receipt may take: the store said "no answer" and offered nothing. An
        # `expired` read still has a receipt (it is a fact about a read that happened), and an
        # `available` read without one is an unsourced claim of rows.
        if outcome != 'unavailable' or samples:
            raise StateError(RECEIPT_REQUIRED)
    elif outcome != 'available' and samples:
        raise StateError(ROWS_WITHOUT_ANSWER)
    elif outcome == 'available' and len(samples) > receipt['sample_count']:
        # More rows than the read claims exist is not a partial excerpt but an impossible statement, so
        # it is refused here instead of being graded; fewer rows is the ordinary truncated-excerpt case
        # and is answered `evidence-incomplete` below, never as if the excerpt proved completeness.
        raise StateError(ROWS_OVER_COUNT)
    # `identifier`'s own sentence is the refusal for a bad execution id on purpose: it is the one text
    # every other platform surface already classifies as a bad identifier.
    return {'execution_id': identifier(record['execution_id']),
            'binding_id': _sha256(record['binding_id'], BAD_BINDING_ID), 'window': window,
            'outcome': outcome, 'receipt': receipt, 'samples': samples}


def _check_scope(statement: dict[str, Any], origin: dict[str, Any], now: dt.datetime) -> dt.datetime:
    """Refuse every statement that is not about the captured signal, and return the window's start.

    Scope is checked before any verdict is derived, in both directions of the two refusals that matter:
    a receipt naming another read (or another window) is somebody else's evidence, and samples of
    another resource or metric are somebody else's numbers. Both are refusals for every outcome,
    including `unavailable`, because filing an `unknown` about a scoped-elsewhere read would let an
    unrelated page become the durable answer about this execution.

    The window must be *exactly* the captured evaluation length: a submitted `[start,end)` is the
    interval the verdict is about, and the mapping's `window_seconds` is the only length the reviewed
    detector ever evaluated, so a wider or narrower ask is a different check wearing this binding's
    name. `end <= now` is the server's clock and nobody else's — a receipt, or a shifted `now`, may not
    certify its own freshness.
    """
    start, end = (_instant(statement['window']['start'], BAD_WINDOW),
                  _instant(statement['window']['end'], BAD_WINDOW))
    if end > now:
        raise StateError(WINDOW_IN_FUTURE)
    if end - start != dt.timedelta(seconds=origin['window_seconds']):
        raise StateError(WINDOW_NOT_CAPTURED)
    receipt = statement['receipt']
    if (receipt is not None and (receipt['query_type'] != origin['query_type']
                                 or receipt['parameters'] != origin['parameters']
                                 or receipt['window'] != statement['window'])):
        raise StateError(RECEIPT_SCOPE)
    if any(row['resource_id'] != origin['resource_id'] or row['metric_name'] != origin['metric_name']
           for row in statement['samples']):
        raise StateError(SAMPLE_SCOPE)
    return start


def _deciding(values: list[float], comparison: str, threshold: float) -> float:
    """Return the value least favourable to `cleared`, which is the one the record files.

    The same rule `verification.check` applies to a newest instant carrying several points: no average
    and no majority vote, because a high reading must not be able to hide behind a low one. `lt`/`le`
    are decided by the largest, `gt`/`ge` by the smallest, `eq` by the point furthest from the line.
    """
    if comparison in ('gt', 'ge'):
        return min(values)
    if comparison == 'eq':
        return max(values, key=lambda value: (abs(value - threshold), value))
    return max(values)


def _grade(statement: dict[str, Any], origin: dict[str, Any], execution: Any,
           now: dt.datetime, start: dt.datetime) -> tuple[str, str, float | None, str | None]:
    """Return `(verdict, reason, value, sampled_at)` for one accepted statement, in this precedence.

    Everything after scope is a *verdict*, never a refusal, and `unknown` is always a named boundary:

    1. the execution is `unknown` — it may still be running, so nothing after it is knowable;
    2. the window opens before the execution's terminal stamp — it describes the state before the run
       ended (equal is allowed: the boundary instant is not itself a sample from before it);
    3. the store did not answer, in word or in receipt;
    4. the evidence was already expired at the server's own instant;
    5. the page was truncated — an excerpt cannot prove a condition stopped;
    6. fewer rows arrived than the receipt claims — an excerpt is never read as a complete answer;
    7. the window carried no rows;
    8. the newest row is from at or before the terminal boundary — the deciding samples must be strictly
       after the run finished, whatever the window's own start was;
    9. only now does a value speak, and it speaks for every row at the newest instant.

    Earlier samples never override a later one, and a `not_cleared` here is a real verdict about a
    signal still firing, not a failure of this module. For every `unknown` the record stores no value
    and no instant: an unanswered question must not leave behind a number that reads like an answer.
    """
    if execution['status'] == 'unknown':
        return _derive(UNKNOWN, 'execution-boundary-unknown')
    boundary = _instant(execution['updated_at'], BAD_STORED_EXECUTION)
    if start < boundary:
        return _derive(UNKNOWN, 'pre-execution-window')
    receipt = statement['receipt']
    if receipt is None or statement['outcome'] != 'available':
        return _derive(UNKNOWN, 'store-unanswered')
    if _instant(receipt['expires_at'], BAD_RECEIPT) <= now:
        return _derive(UNKNOWN, 'evidence-expired')
    if receipt['truncated']:
        return _derive(UNKNOWN, 'evidence-truncated')
    if receipt['sample_count'] > len(statement['samples']):
        return _derive(UNKNOWN, 'evidence-incomplete')
    if not statement['samples']:
        return _derive(UNKNOWN, 'window-empty')
    newest = max(_instant(row['observed_at'], BAD_SAMPLES) for row in statement['samples'])
    if newest <= boundary:
        return _derive(UNKNOWN, 'pre-execution-sample')
    values = [row['value'] for row in statement['samples']
              if row['observed_at'] == utc_text(newest)]
    threshold, comparison = origin['threshold'], origin['comparison']
    satisfied = all(bool(COMPARISONS[comparison](value, threshold)) for value in values)
    return _derive(CLEARED if satisfied else NOT_CLEARED,
                   'comparison-satisfied' if satisfied else 'comparison-failed',
                   _deciding(values, comparison, threshold), utc_text(newest))


def write_record(store: Any, record: Any, actor: Any, *,
                 now: dt.datetime | None = None) -> dict[str, Any]:
    """Accept one submitted observation, judge it, and append it. Returns `{verification_id, created}`.

    The whole of one submission lives in a single `BEGIN IMMEDIATE`, which is what makes the retry rule
    true rather than aspirational: the execution lookup, its stored action binding, the duplicate check
    and the insert are serialised against every other writer, so two producers racing identical bytes
    get one row and one `created` answer between them.

    What is checked in which order, and why:

    * **authority, clock, shape, size** — before the file is opened, so a refusal costs no write lock;
    * **execution, binding, `executing`** — inside the transaction: the binding must be `bound` and
      equal the id the statement names, because a statement about an unbound action has no numeric
      meaning to be judged against, and an in-flight execution has no terminal boundary yet;
    * **scope** — the captured read, the captured window length, the captured resource and metric;
    * **identity, then the cap** — a replay of the identical statement is admissible at the cap
      (returns `created: false`, changes nothing, writes no audit row) while a 65th *new* window is not;
    * **grading last** — an already accepted statement is never re-graded by a later clock or a later
      execution status, which is why the duplicate answer comes back before `_grade` is reached.

    Nothing here overwrites or re-decides an execution, an action or an incident: a `not_cleared` record
    leaves a `succeeded` execution exactly as its runner reported it, and the incident stays open because
    closing it remains intake's decision about a `resolved` event.
    """
    policy = store.verification_policy
    _writer(policy, actor)
    moment = _clock(now)
    statement = _incoming(record)
    with store.transaction() as connection:
        if not _ready(connection):
            raise StateError(NEEDS_MIGRATION)
        execution = connection.execute('SELECT * FROM executions WHERE id=?',
                                       (statement['execution_id'],)).fetchone()
        if execution is None:
            raise StateError(UNKNOWN_EXECUTION)
        if execution['status'] == 'executing':
            raise StateError(EXECUTING_EXECUTION)
        if execution['status'] not in ('succeeded', 'failed', 'unknown'):
            raise StateError(BAD_STORED_EXECUTION)
        row = connection.execute('SELECT * FROM verification_bindings WHERE action_id=?',
                                 (execution['action_id'],)).fetchone()
        if row is None:
            raise StateError(BAD_BINDING)
        binding = _stored_binding(row)
        if (binding['status'] != STATUS_BOUND or binding['binding_id'] != statement['binding_id']
                or not isinstance(binding['origin'], dict)):
            raise StateError(BAD_BINDING)
        origin = binding['origin']
        start = _check_scope(statement, origin, moment)
        verification_id = digest([statement['execution_id'], statement['binding_id'],
                                 statement['window']])
        fingerprint = digest(statement)
        seen = connection.execute('SELECT fingerprint FROM verification_records WHERE verification_id=?',
                                  (verification_id,)).fetchone()
        if seen is not None:
            if seen['fingerprint'] != fingerprint:
                raise StateError(RETRY_CHANGED)
            return {'verification_id': verification_id, 'created': False}
        if connection.execute('SELECT count(*) FROM verification_records WHERE execution_id=?',
                              (execution['id'],)).fetchone()[0] >= RECORDS_PER_EXECUTION:
            raise StateError(RECORD_LIMIT)
        verdict, reason, value, sampled_at = _grade(statement, origin, execution, moment, start)
        document = dict(zip(RECORD_DOCUMENT_KEYS, (
            verification_id, statement['execution_id'], execution['action_id'],
            statement['binding_id'], origin, statement['window'], statement['outcome'],
            statement['receipt'], statement['samples'], verdict, reason, value, sampled_at,
            actor.identity, utc_text(moment))))
        stored = canonical(document)
        if len(stored.encode()) > MAX_STORED_BYTES:
            # Measured on the bytes about to be stored, so the bound the reader is promised is a fact
            # about this row and not an expectation about the caller's input bound.
            raise StateError(RECORD_TOO_LARGE)
        connection.execute('INSERT INTO verification_records VALUES (?,?,?,?,?,?,?,?)',
                           (verification_id, execution['id'], fingerprint, stored, verdict, reason,
                            actor.identity, utc_text(moment)))
        store.audit(connection, moment, actor.identity, AUDIT_OPERATION, verification_id,
                    {'verdict': verdict, 'reason': reason})
        return {'verification_id': verification_id, 'created': True}


def read_record(store: Any, verification_id: Any, actor: Any) -> dict[str, Any] | None:
    """Return one stored verification document, or `None` when that id was never recorded.

    A well-formed id that is absent answers `None` — this is a lookup of one immutable document, not a
    list, and "no such record" is a fact about the id rather than a malformed request. A malformed id is
    a refusal, so a caller cannot pass a prefix, a wildcard or a stray body field as an id. The document
    is re-parsed from its stored text on every call: no two readers share an object, and nothing a
    caller does to a returned document can reach the file.
    """
    _reader(store.verification_policy, actor)
    wanted = _sha256(verification_id, BAD_VERIFICATION_ID)
    with store.transaction() as connection:
        if not _ready(connection):
            raise StateError(NEEDS_MIGRATION)
        row = connection.execute('SELECT payload FROM verification_records WHERE verification_id=?',
                                 (wanted,)).fetchone()
    return None if row is None else json.loads(row['payload'])

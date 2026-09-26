"""Post-action verification: did the signal that paged actually clear? remediation invariants.

One sentence of contract, from ``docs/CONTRACTS.md`` §5: *"Verification after execution determines
incident recovery; process exit zero alone does not."* A runner reporting ``succeeded`` says a process
finished; it does not say the condition that opened the incident stopped firing. This module answers
the second question, and refuses to answer it optimistically.

Remediation invariants this unit exists to keep honest. Each one is enforced by a named test in
``tests/test_action_invariants.py`` (the lifecycle ones) or ``tests/test_verification.py`` (the verdict
ones); the statement lives here as well as in the tests because an invariant nobody can read is not a
rule.

1. **Only a credential whose authenticated role is ``human`` decides an action, and an agent credential
   approves nothing — including the action it proposed.** Identity comes from the bearer token, never
   from a payload field, and read/summary credentials cannot approve, execute or report an outcome
   (``docs/CONTRACTS.md`` §5). Enforced at both boundaries here:
   ``test_agent_principal_cannot_approve_any_action`` (``Store.decide`` and the ASGI edge with the
   proposer's own token), ``test_no_actor_that_is_not_an_authenticated_human_role_decides`` (the state
   layer's own gate, including actors that are not ``Actor`` objects at all),
   ``test_body_field_cannot_claim_a_human_role``, ``test_read_credentials_cannot_approve_or_execute``,
   ``test_an_unlisted_or_missing_credential_chooses_no_route``.
   §5 asks for an authenticated **human** identity, not for two distinct humans, and v0.1's rule
   rejected *agent* approvers for the same reason; the control §5 does require is attribution, so
   ``test_a_human_who_proposed_may_approve_and_both_sides_are_durable`` pins what is durable about it
   (``actions.requester`` and ``decided_by`` both survive, and the audit row names the approver) without
   asserting an identity-level separation no contract asks for.
2. **Approval expiry blocks a new dispatch and never interrupts a running execution**
   (``test_expired_approval_blocks_a_new_dispatch``,
   ``test_approved_action_that_expires_before_it_is_claimed_cannot_dispatch``,
   ``test_expiry_never_interrupts_a_running_execution``).
3. **One action, one claim** (``test_second_claim_of_one_action_is_refused``,
   ``test_dispatch_rechecks_the_policy_gate_and_an_open_incident``).
4. **A runner proves itself with its token and its identity** (``test_wrong_runner_token_is_refused``,
   ``test_an_outcome_is_never_granted_by_repetition``).
5. **An interrupted execution is reconciled, never re-dispatched**
   (``test_interrupted_execution_is_reconciled_not_redispatched``,
   ``test_recovery_does_not_invent_a_failure``).
6. **Exit zero is not recovery** (``test_succeeded_outcome_alone_never_resolves_the_incident``).
7. **Dagu is an executor, not a source of approval**
   (``test_dagu_never_dispatches_without_an_approved_claim``,
   ``test_dagu_polls_a_lost_acknowledgement_instead_of_redispatching``).
8. **A mechanical success whose signal is still firing is ``not_cleared``, and anything unverifiable
   is ``unknown`` — never ``cleared``** (``test_still_firing_signal_is_not_cleared_after_a_mechanical_success``,
   and every test in ``tests/test_verification.py``).
9. **A refused bad action leaves no durable trace today**, and this unit does not claim otherwise:
   ``test_a_refused_attempt_leaves_a_durable_audit_row`` is kept as a measured gap (tracked as the refusal audit), not
   as a passing invariant. The verdicts computed here are equally undurable beyond one
   four-field evidence row until the verification workflow gives them a real record.

Two halves, deliberately not merged into one call: **sampling** (:func:`read_sample`, the only function
in this module that touches the store, and only through the named-query facade of
``local_observe/store``) and **judging** (:func:`check`, pure arithmetic over the sample that came back
— no I/O, no clock, no store). :func:`verify` composes the two and says so at the call site.

Port delta from ``legacy:aiops/remediation/verify.py`` (which read a ``query_range`` transport this repo
does not have): the sample arrives from ``local_observe.store.client``'s ``metric-threshold`` read,
whose receipt names the query kind, the approved parameters, the window, the row count and whether the
answer was cut off. That receipt is what makes a verdict checkable later, so **this module distrusts
it as hard as it distrusts a missing sample**: rows that are not the declared series, rows that are not
the declared resource, rows outside the window the receipt claims, a receipt whose approved parameters
are not exactly this origin's (a pinned ``artifact_sha256`` that the read never carried is a different
read, not a matching one), a receipt of a different query kind, and a truncated page all answer
``unknown``, never ``cleared``. The reason truncation alone is fatal is concrete — the store's metric
statement returns oldest-first inside a bounded page, so a cut-off page of a still-rising series has
the *low* points on it and the firing ones missing.

Freshness belongs to :func:`verify`, and it is measured against the **real** clock: with no ``now``
argument, *now* is this call's aware UTC instant, never the reused receipt's own window end. A receipt
allowed to name the instant it is judged at certifies its own freshness, and last quarter's healthy
page would read as this minute's recovery. Replaying history is still possible and is stated as such —
pass the historical ``now``, or grade the rows with the pure :func:`check`.

What survives is stated exactly, because an evidence row is the only durable thing this unit writes:
``Store.put_evidence`` keeps four fields, so what a reader can recover later is the **verdict word and
the sampled value** (``verify.<verdict>.<digest>`` and ``value``), the instant the window ended, and
whether the store answered at all. The threshold, comparison, rule and window behind the verdict are
*not* readable back — they are folded into a digest that only re-derives if somebody already knows
them. The digest is a check, not a recovery: hand it the same origin and the same read and it matches,
invert it and there is nothing, so re-deriving a verdict from the stored value plus the operator's own
configured check is not the same act as re-reading the store. That is a limit of the existing evidence
API, not a choice made here; the follow-up that would make a verdict durable as a record is **the verification
workflow**, and until it lands this module must not be advertised as integrated post-action recovery (see
``docs/units/verification.md``, "Evidence truth").

**Off is the default, and this unit is not integrated recovery.** ``python -m
local_observe.platform.verification`` with no ``LO_VERIFY_CONFIG`` names nothing, logs one INFO line
and exits 0 without opening a connection or writing anything. It resolves no incident, attaches nothing
to an execution, and has no ``lo-platform`` subcommand yet. ``docs/units/verification.md`` carries every
knob, every ``unknown`` reason, and the two integrations still missing (cards 122 and 123).
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import datetime as dt
import json
import math
import os
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import digest, timestamp, utc_text
from local_observe.log import get_logger
from local_observe.store.client import MetricSample, ReadOutcome, Window
from .state import identifier, label

log = get_logger(__name__)

#: The whole vocabulary a verdict may take. Nothing else is ever returned.
VERDICTS = ('cleared', 'not_cleared', 'unknown')
CLEARED, NOT_CLEARED, UNKNOWN = VERDICTS

#: The comparisons a metric threshold may be expressed with. Anything else is unverifiable.
COMPARISONS: dict[str, Any] = {'lt': lambda value, limit: value < limit,
                               'le': lambda value, limit: value <= limit,
                               'gt': lambda value, limit: value > limit,
                               'ge': lambda value, limit: value >= limit,
                               'eq': lambda value, limit: value == limit}

#: The only origin kind this unit can re-check. A log, trace or alert-rule origin has no numeric
#: sample behind the facade's metric read, so the worker cannot be configured for one at all:
#: :class:`Origin` refuses it at construction rather than reporting ``unknown`` forever about a signal
#: it can never read.
VERIFIABLE_KIND = 'metric-threshold'

#: Every reason :func:`check` or :func:`verify` may answer ``unknown``, spelled once. ``unknown`` is
#: only ever produced by naming one of these, and a reason outside this set is a bug rather than a
#: verdict (:func:`_unknown` raises). ``tests/test_verification.py`` asserts this set in both
#: directions: every ``unknown`` names one, and every one is reachable by a listed input.
UNVERIFIABLE_REASONS = frozenset({
    'selector-missing',      # the origin does not name the series to re-check; anything else is guesswork
    'threshold-unusable',    # no threshold, or one that is not a finite number
    'comparison-unsupported',  # a comparison outside COMPARISONS
    'sample-missing',        # nothing was sampled at all (sample is None)
    'store-unanswered',      # the read itself refused: unavailable or expired
    'window-empty',          # the read answered and carried no rows
    'sample-off-origin',     # rows exist, but none is the declared series of the declared resource
    'sample-not-numeric',    # the newest value is a log/trace row, missing, a bool, a string
    'sample-not-finite',     # the newest value is NaN, an infinity, or too large to be a number
    'row-outside-window',    # a row has no usable instant, or one outside the receipt's half-open window
    'receipt-unusable',      # the read is not this origin's read, or its page was truncated
    'window-mismatch',       # a reused ReadOutcome is not the read this origin would have asked for
})

CONFIG_ENVIRONMENT = 'LO_VERIFY_CONFIG'
CONFIG_KEYS = frozenset({'rule_id', 'resource_id', 'metric_name', 'threshold', 'comparison',
                         'window_seconds', 'artifact_sha256'})
# `metric_name` is required here although :class:`Origin` can be built without it: a worker that did
# not name the series would be verifying whatever metric happened to be in the answer. The pure
# evaluator keeps the honest `selector-missing` unknown for callers that hand-build an origin.
REQUIRED_CONFIG_KEYS = frozenset({'rule_id', 'resource_id', 'metric_name', 'threshold', 'comparison',
                                  'window_seconds'})
MAX_CONFIG_BYTES = 65_536
# The read window. `store.client.MAX_WINDOW_SECONDS` caps any receipt at 7 days; a verification that
# asked for more would be refused by the facade, so the bound is tightened to what a post-action
# re-check actually means: minutes to a day.
WINDOW_SECONDS_LIMITS = (60, 86_400)


class ConfigError(ValueError):
    """A verification configuration this unit will not run; the message names the field, never a value."""


def _usable_number(value: Any) -> bool:
    """Return True for a real finite number, and False for a bool, a string, NaN or an infinity."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _now() -> dt.datetime:
    """Return the real aware UTC clock, behind one name so a test can hold time still."""
    return dt.datetime.now(dt.timezone.utc)


def _clock(now: Any = None) -> dt.datetime:
    """Return the instant to judge at: *now* when one is named, the real UTC clock otherwise.

    :func:`verify` is the clock-aware entry point, so "no clock named" means *now*, in the ordinary
    sense of the word — never "borrow the instant the sample happens to describe", which is a receipt
    certifying its own freshness. A caller that means a historical instant passes that instant
    explicitly; a caller that has no clock at all re-grades history with the pure :func:`check`.

    A naive datetime, a string or a number is a :class:`ConfigError` and not an ``unknown``: a clock is
    the caller's configuration, not source data, and the two fail differently by design (bad data
    degrades to a named ``unknown``, bad configuration refuses loudly before any read is asked for).
    """
    if now is None:
        return _now()
    if not isinstance(now, dt.datetime) or now.tzinfo is None:
        raise ConfigError('Verification needs an aware UTC datetime as its clock; pass None to judge '
                          'against the real one, or re-grade a historical window with check()')
    return now


@dataclass(frozen=True)
class Origin:
    """A recheckable description of the signal that fired, bounded at construction.

    ``metric_name`` names the series the verdict is about. :class:`Origin` allows it to be absent
    because :func:`check` is also a pure re-grader of a sample somebody already holds, but a worker
    must configure it (:data:`REQUIRED_CONFIG_KEYS`), and without it the verdict is
    ``selector-missing``: verifying "whatever this resource reported" would let an unrelated low point
    stand in for the metric that paged.

    Construction is the gate: a bad UUID, a non-finite threshold, an unsupported comparison, a window
    outside its bounds or an unbounded name is a :class:`ConfigError`, not an ``unknown``. A worker
    that cannot state what it is checking must refuse at startup, not report "cannot tell" forever.
    """

    rule_id: str
    resource_id: str
    threshold: float
    comparison: str = 'lt'
    window_seconds: int = 300
    metric_name: str | None = None
    artifact_sha256: str | None = None
    kind: str = VERIFIABLE_KIND

    def __post_init__(self) -> None:
        """Refuse anything this unit would have to guess about later."""
        label(self.rule_id)
        identifier(self.resource_id)
        if self.kind != VERIFIABLE_KIND:
            raise ConfigError(f'Only {VERIFIABLE_KIND} origins are verifiable; {self.kind!r} is not')
        if self.comparison not in COMPARISONS:
            raise ConfigError(f'Unsupported comparison {self.comparison!r}; expected one of '
                              f'{", ".join(sorted(COMPARISONS))}')
        if not _usable_number(self.threshold):
            raise ConfigError('Verification threshold must be a finite number')
        # One canonical numeric form, so a threshold written `90` in a file and one re-graded at `90.0`
        # produce the same binding: a digest that changed on a type spelling would silently fork the
        # evidence rows of one check.
        object.__setattr__(self, 'threshold', float(self.threshold))
        if isinstance(self.window_seconds, bool) or not isinstance(self.window_seconds, int) \
                or not WINDOW_SECONDS_LIMITS[0] <= self.window_seconds <= WINDOW_SECONDS_LIMITS[1]:
            raise ConfigError(f'window_seconds must be a whole number of seconds from '
                              f'{WINDOW_SECONDS_LIMITS[0]} to {WINDOW_SECONDS_LIMITS[1]}')
        if self.metric_name is not None:
            label(self.metric_name)
        if self.artifact_sha256 is not None and (
                not isinstance(self.artifact_sha256, str) or len(self.artifact_sha256) != 64
                or any(char not in '0123456789abcdef' for char in self.artifact_sha256.lower())):
            raise ConfigError('artifact_sha256 must be 64 hexadecimal characters')

    @property
    def binding(self) -> str:
        """Return the digest of the reviewed definition, so a changed check is a different evidence id."""
        return digest([self.kind, self.rule_id, self.resource_id, self.metric_name, self.threshold,
                       self.comparison, self.window_seconds, self.artifact_sha256])

    def window(self, now: dt.datetime) -> Window:
        """Return the half-open ``[now - window_seconds, now)`` the read is asked for."""
        if not isinstance(now, dt.datetime) or now.tzinfo is None:
            raise ConfigError('Verification needs an aware UTC clock')
        end = timestamp(utc_text(now))
        return Window(start=utc_text(end - dt.timedelta(seconds=self.window_seconds)),
                      end=utc_text(end))

    def read_request(self, now: dt.datetime) -> tuple[str, dict[str, str], dict[str, str], Window]:
        """Return the named read this origin asks for: kind, approved parameters, selectors, window.

        Pure data — building the request touches nothing. The parameter names are the ones
        ``state.validate_event`` admits, which is why the metric name is a *selector* (bound
        server-side, never filed as proof) and not a parameter.
        """
        parameters = self.read_parameters
        selectors = {'metric_name': self.metric_name} if self.metric_name else {}
        return VERIFIABLE_KIND, parameters, selectors, self.window(now)

    @property
    def read_parameters(self) -> dict[str, str]:
        """Return the approved evidence parameters exactly one read of this origin must carry.

        This is the scope :func:`_receipt_problem` compares a receipt against, so it is the same object
        the request is built from and not a second spelling that could drift: ``resource_id`` +
        ``rule_id``, plus ``artifact_sha256`` when — and only when — the origin pins a reviewed artifact.
        """
        parameters = {'resource_id': self.resource_id, 'rule_id': self.rule_id}
        if self.artifact_sha256 is not None:
            parameters['artifact_sha256'] = self.artifact_sha256
        return parameters

    @classmethod
    def from_document(cls, document: Any) -> Origin:
        """Build one origin from a parsed configuration document, refusing anything extra or absent.

        Unknown keys are a refusal and not a clamp: a typo in an operator file must not silently run a
        different check than the one the operator meant to configure.
        """
        if not isinstance(document, dict):
            raise ConfigError('Verification configuration must be one JSON object')
        extra = sorted(set(document) - CONFIG_KEYS)
        if extra:
            raise ConfigError(f'Verification configuration holds unknown key(s): {", ".join(extra)}; '
                              f'this check reads {", ".join(sorted(REQUIRED_CONFIG_KEYS))}'
                              ' plus artifact_sha256')
        missing = sorted(REQUIRED_CONFIG_KEYS - set(document))
        if missing:
            raise ConfigError(f'Verification configuration is missing key(s): {", ".join(missing)}')
        window_seconds = document['window_seconds']
        if isinstance(window_seconds, float) and window_seconds.is_integer():
            window_seconds = int(window_seconds)
        return cls(rule_id=document['rule_id'], resource_id=document['resource_id'],
                   metric_name=document['metric_name'], threshold=document['threshold'],
                   comparison=document['comparison'], window_seconds=window_seconds,
                   artifact_sha256=document.get('artifact_sha256'))


@dataclass(frozen=True)
class Verdict:
    """One answer, with the provenance that makes it checkable later — and the limits of that.

    ``state`` is one of :data:`VERDICTS`; ``reason`` is a fixed code (``comparison-satisfied``,
    ``comparison-failed``, or one of :data:`UNVERIFIABLE_REASONS`). ``threshold``, ``comparison`` and
    ``metric_name`` are the **effective** condition the answer was made against — the origin's own, or
    the caller's override once it had been validated — so ``origin_binding`` always names the check that
    was actually run and never a stale definition. ``window``, ``parameters`` and ``query_type`` come
    from the store's receipt when there was a read, which is what lets the answer be reauthorised; a
    verdict judged from rows handed over without one has no window and cannot be filed.

    ``value`` is the sample the verdict was made on — the one least favourable to ``cleared`` — and
    ``answered`` records whether the store replied, which is *not* the same fact as the verdict.
    """

    state: str
    reason: str
    rule_id: str | None = None
    resource_id: str | None = None
    metric_name: str | None = None
    threshold: float | None = None
    comparison: str | None = None
    origin_binding: str | None = None
    query_type: str | None = None
    parameters: Mapping[str, str] | None = None
    window: Mapping[str, str] | None = None
    value: float | None = None
    sampled_at: str | None = None
    samples: int = 0
    answered: bool = False

    def __str__(self) -> str:
        """Return the verdict word, so a log line and an assertion read the same way."""
        return self.state

    @property
    def cleared(self) -> bool:
        """True only for the one state that says the originating signal stopped firing."""
        return self.state == CLEARED

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe statement of this verdict, for a log line or a portal field."""
        return {'verdict': self.state, 'reason': self.reason, 'rule_id': self.rule_id,
                'resource_id': self.resource_id, 'metric_name': self.metric_name,
                'threshold': self.threshold, 'comparison': self.comparison,
                'origin_binding': self.origin_binding, 'query_type': self.query_type,
                'parameters': dict(self.parameters or {}), 'window': dict(self.window or {}),
                'value': self.value, 'sampled_at': self.sampled_at, 'samples': self.samples,
                'answered': self.answered}


def _unknown(reason: str, origin: Origin | None = None, *, provenance: Verdict | None = None) -> Verdict:
    """Build an ``unknown`` that names its reason; the only way this state is ever reached.

    ``unknown`` is a claim about *us* — this signal could not be evaluated — and it is never a softer
    synonym for ``cleared``. Every call site is a reason in :data:`UNVERIFIABLE_REASONS`, and the
    provenance the read supplied (window, parameters, row count) is carried through even on a refusal,
    so a log line says what was looked at and found unusable.
    """
    if reason not in UNVERIFIABLE_REASONS:
        raise ConfigError(f'unknown verdicts name a documented reason; {reason!r} is not one')
    carried = provenance or Verdict(state=UNKNOWN, reason=reason)
    return Verdict(state=UNKNOWN, reason=reason, rule_id=origin.rule_id if origin else None,
                   resource_id=origin.resource_id if origin else None,
                   metric_name=origin.metric_name if origin else None,
                   threshold=origin.threshold if origin else None,
                   comparison=origin.comparison if origin else None,
                   origin_binding=origin.binding if origin else carried.origin_binding,
                   query_type=carried.query_type, parameters=carried.parameters, window=carried.window,
                   value=carried.value, sampled_at=carried.sampled_at, samples=carried.samples,
                   answered=carried.answered)


def _rows(sample: Any) -> Sequence[Any] | None:
    """Return the rows of one read, or None when the input is not a set of metric readings.

    None means "this is not evidence": a number, a string, a dict, or log/trace rows from a read of a
    different kind. The caller answers ``unknown``/``sample-not-numeric`` rather than guessing at a
    shape — a value whose series, resource and instant are unknown cannot be reauthorised by anyone
    later, and an attribute error out of a verdict function is a crash where a refusal belongs.
    """
    rows = sample.samples if isinstance(sample, ReadOutcome) else (
        (sample,) if isinstance(sample, MetricSample) else sample)
    if isinstance(rows, Sequence) and not isinstance(rows, (str, bytes)) \
            and all(isinstance(row, MetricSample) for row in rows):
        return tuple(rows)
    return None


def _instant(row: Any) -> dt.datetime | None:
    """Return one row's instant, or None when it carries nothing parseable — never an exception.

    Bad *data* degrades to ``unknown`` here; bad *configuration* is what raises. A store row stamped
    with prose, a naive time or no time at all cannot be placed in the window the verdict is about.
    """
    value = getattr(row, 'timestamp', None)
    if not isinstance(value, str):
        return None
    try:
        return timestamp(value)
    except Exception:
        # `inventory.timestamp` raises InvalidInventory for a naive or malformed stamp; a row we
        # cannot date is unusable evidence, not a crash in the middle of a verdict.
        return None


def _series(row: Any) -> str | None:
    """Return the metric name a row reports, or None when the row does not say."""
    return row.name if isinstance(getattr(row, 'name', None), str) else None


def _resource(row: Any) -> str | None:
    """Return the declared resource a row is attributed to, from either place the backends put it."""
    value = getattr(row, 'resource_id', None)
    if not isinstance(value, str) and isinstance(getattr(row, 'labels', None), dict):
        value = row.labels.get('resource_id')
    return value if isinstance(value, str) else None


def _provenance(origin: Origin, sample: Any) -> Verdict:
    """Return what the sample attests to, before anyone judges it; no verdict is decided here.

    A `ReadOutcome` is the only object that can say where a sample came from, because its receipt names
    the query kind, the approved parameters, the window the store served and whether the page was cut.
    Rows handed over without one carry the origin's declared scope and **no window**, so the verdict
    made from them cannot be filed as evidence — :func:`evidence_sample` refuses that.
    """
    rows = _rows(sample)
    if isinstance(sample, ReadOutcome):
        receipt = sample.receipt
        return Verdict(state='', reason='', rule_id=origin.rule_id, resource_id=origin.resource_id,
                       metric_name=origin.metric_name, threshold=origin.threshold,
                       comparison=origin.comparison, origin_binding=origin.binding,
                       query_type=receipt.query_type, parameters=dict(receipt.parameters),
                       window=receipt.window.as_dict(), samples=len(sample.samples),
                       answered=sample.status == 'available')
    return Verdict(state='', reason='', rule_id=origin.rule_id, resource_id=origin.resource_id,
                   metric_name=origin.metric_name, threshold=origin.threshold,
                   comparison=origin.comparison, origin_binding=origin.binding,
                   query_type=origin.kind if rows is not None else None,
                   parameters={'resource_id': origin.resource_id, 'rule_id': origin.rule_id}
                   if rows is not None else None, samples=len(rows or ()), answered=bool(rows))


def _receipt_problem(origin: Origin, outcome: ReadOutcome) -> str | None:
    """Return why this read cannot support a verdict about *origin*, or None when it can.

    Four concrete failures, each of which would otherwise let an unrelated number clear an alert:

    * **the wrong read** — a receipt of another query kind is somebody else's answer, and a receipt
      whose approved parameters are not *exactly* this origin's is somebody else's evidence; the
      ``available`` flag alone proves nothing about what was asked for;
    * **an unpinned read cited for a pinned rule** — when the origin pins ``artifact_sha256``, a receipt
      that carries no hash (or a different one) is not a read of the reviewed artifact the verdict
      claims to be about. "Hash missing" is not "hash matches";
    * **a truncated page** — ``store.client`` bounds a read at ``MAX_ROWS`` and the metric statement
      orders oldest-first, so a cut page of a rising series holds the low points and is missing the
      firing ones. A partial history cannot prove a condition stopped;
    * **dead evidence** — a receipt whose expiry is not later than its own window end (defended against
      by the facade, checked again here) could not be reauthorised when the verdict is read back.
    """
    receipt = outcome.receipt
    if receipt.query_type != origin.kind:
        return 'receipt-unusable'
    # Exact equality, in both directions: a missing parameter is not a matching one, and a hash this
    # origin never asked for means this read was scoped to a different reviewed artifact.
    if dict(receipt.parameters) != origin.read_parameters:
        return 'receipt-unusable'
    if receipt.truncated:
        return 'receipt-unusable'
    try:
        if timestamp(receipt.expires_at) <= receipt.window.instant('end'):
            return 'receipt-unusable'
    except Exception:
        return 'receipt-unusable'
    return None


def _worst(values: Sequence[float], comparison: str, threshold: float) -> float:
    """Return the value least favourable to ``cleared`` — the one the verdict is filed against.

    A newest instant carrying several points of one series is not averaged: averaging would let a high
    sample hide behind a low one. ``lt``/``le`` are decided by the largest, ``gt``/``ge`` by the
    smallest, and ``eq`` by the point furthest from the threshold.
    """
    if comparison in ('gt', 'ge'):
        return min(values)
    if comparison == 'eq':
        return max(values, key=lambda value: (abs(value - threshold), value))
    return max(values)


def check(origin: Origin, sample: Any, threshold: Any = None, comparison: str | None = None) -> Verdict:
    """Judge an already-sampled signal: ``cleared`` | ``not_cleared`` | ``unknown``. remediation invariants.

    **Pure**: no store, no network and **no clock**. *origin* says what fired and what would count as
    having stopped, *sample* is what a read answered, and *threshold*/*comparison* re-grade that same
    sample against a different condition — validated first, and the :attr:`Verdict.origin_binding`
    reports the **effective** check that was run, never the definition that was superseded.

    Two limits of that purity, both deliberate:

    * **no clock.** `check` cannot tell a fresh read from a three-week-old one, because freshness is a
      fact about the instant of asking, not about the sample. :func:`verify` owns it: a read that is not
      exactly the one this origin would have asked for at the moment being judged — which is the real
      UTC clock unless the caller named another — is refused as ``window-mismatch``, and
      :func:`read_sample` builds its window from the clock it is given. A caller that calls `check`
      directly on a stored ReadOutcome gets a verdict about that window, and nothing here pretends the
      window is current.
    * **no attestation.** A `ReadOutcome` is trusted for what it says it read (and is audited against
      *origin* — see :func:`_receipt_problem`); a bare sequence of rows says nothing about where it came
      from, so a verdict made from it has no window and :func:`evidence_sample` refuses to file it.

    The two refusals that carry the design:

    * a signal we cannot evaluate is ``unknown``, never ``cleared`` — no named series, a store that did
      not answer, an empty or truncated window, a read of something else, rows that are not this
      series/resource/window, a bool/missing/non-finite/undated value;
    * a signal that mechanically succeeded but is still outside its threshold is ``not_cleared``,
      whatever the runner said. ``not_cleared`` is a real verdict, not a failure of this module.

    Nothing here raises for bad *data*: an unjudgeable input is ``unknown`` with a named reason. Bad
    *configuration* is a :class:`ConfigError`, raised by :class:`Origin` before any read is asked for.
    """
    if not isinstance(origin, Origin):
        raise ConfigError('check() needs an Origin built from validated configuration; '
                          'an unvalidated origin is how an unsupported comparison reaches a verdict')
    provenance = _provenance(origin, sample)
    limit = origin.threshold if threshold is None else threshold
    name = origin.comparison if comparison is None else comparison
    # An override that will not build a valid condition is an unverifiable signal, not a crash and not
    # a clearance — and the working origin below is what the verdict and its binding describe.
    if name not in COMPARISONS:
        return _unknown('comparison-unsupported', origin, provenance=provenance)
    if not _usable_number(limit):
        return _unknown('threshold-unusable', origin, provenance=provenance)
    working = origin if (limit, name) == (origin.threshold, origin.comparison) \
        else replace(origin, threshold=float(limit), comparison=name)
    if working.metric_name is None:
        # Without the series name the read is unscoped, and "some number this resource reports is low"
        # is not evidence that the metric which paged has recovered.
        return _unknown('selector-missing', working, provenance=provenance)
    if sample is None:
        return _unknown('sample-missing', working, provenance=provenance)
    rows = _rows(sample)
    if rows is None:
        return _unknown('sample-not-numeric', working, provenance=provenance)
    if isinstance(sample, ReadOutcome):
        if sample.status != 'available':
            return _unknown('store-unanswered', working, provenance=provenance)
        problem = _receipt_problem(working, sample)
        if problem:
            return _unknown(problem, working, provenance=provenance)
        bounds = (sample.receipt.window.instant('start'), sample.receipt.window.instant('end'))
    else:
        bounds = None
    if not rows:
        return _unknown('window-empty', working, provenance=provenance)

    stamped: list[tuple[dt.datetime, Any]] = []
    for row in rows:
        instant = _instant(row)
        if instant is None or (bounds is not None and not bounds[0] <= instant < bounds[1]):
            # A row we cannot place inside the window the receipt claims is not evidence about that
            # window: trusting it would let a stale or out-of-band point decide recovery.
            return _unknown('row-outside-window', working, provenance=provenance)
        stamped.append((instant, row))
    mine = [(instant, row) for instant, row in stamped
            if _series(row) == working.metric_name and _resource(row) == working.resource_id]
    if not mine:
        # Rows arrived, and none of them is the signal that fired. That is not a clearance, and it is
        # not the same statement as "the window was empty": somebody read the wrong series.
        return _unknown('sample-off-origin', working, provenance=provenance)
    newest = max(instant for instant, _ in mine)
    latest = [row for instant, row in mine if instant == newest]
    # A newest sample that cannot be read is never skipped in favour of an older one: dropping the
    # freshest point of the originating series to reach a comfortable one is how a live alert reads as
    # recovered.
    values: list[float] = []
    for row in latest:
        if not _usable_number(row.value):
            # A number too large to be a float is not the same defect as a string in the value column:
            # the first is unrepresentable data, the second is not a reading at all.
            numeric = isinstance(row.value, (int, float)) and not isinstance(row.value, bool)
            return _unknown('sample-not-finite' if numeric else 'sample-not-numeric',
                            working, provenance=provenance)
        values.append(float(row.value))
    outcomes = [bool(COMPARISONS[name](value, float(limit))) for value in values]
    satisfied = all(outcomes)
    return Verdict(state=CLEARED if satisfied else NOT_CLEARED,
                   reason='comparison-satisfied' if satisfied else 'comparison-failed',
                   rule_id=working.rule_id, resource_id=working.resource_id,
                   metric_name=working.metric_name, threshold=float(limit), comparison=name,
                   origin_binding=working.binding, query_type=provenance.query_type,
                   parameters=provenance.parameters, window=provenance.window,
                   value=_worst(values, name, float(limit)), sampled_at=utc_text(newest),
                   samples=len(rows), answered=True)


def read_sample(store: Any, origin: Origin, *, now: dt.datetime | None = None) -> ReadOutcome:
    """Ask the store for the samples this origin was judged from — the only I/O in this module.

    *store* is any ``local_observe.store.client.StoreClient`` (the ClickHouse facade in production, the
    in-memory backend in tests): the read is named ``metric-threshold`` and narrowed to one declared
    resource and one series. No second transport, no SQL, no caller-written filter — and no verdict:
    whatever the store answers is returned untouched, including an ``unavailable`` outcome, which is the
    store's word and not this module's opinion.

    A facade refusal (`StoreRefused`) propagates: a read that was not performed yields no verdict and
    no evidence, which is different from a read that answered "nothing".

    ``now`` names the end of the window asked for; left alone it is the real aware UTC clock
    (:func:`_clock`), so a scheduled worker reads "the last N seconds" without being handed a clock, and
    a test that must not drift passes its own instant.
    """
    query_type, parameters, selectors, window = origin.read_request(_clock(now))
    return store.read(query_type, window=window, parameters=parameters, selectors=selectors)


def verify(store: Any, origin: Origin, *, now: dt.datetime | None = None,
           outcome: ReadOutcome | None = None) -> Verdict:
    """Sample, then judge — the two steps kept visible, in this order.

    ``outcome`` lets a caller that already holds a read grade the same rows without asking twice, and
    this is where the clock is enforced rather than assumed: the reused read must be **exactly** the
    read this origin would have asked for at the instant being judged, or the answer is
    ``window-mismatch``. A verdict about a stale window is how a recovery that happened last Tuesday
    gets reported as a recovery now.

    **The clock defaults to the real one.** With no ``now``, *now* is this call's own aware UTC instant
    (:func:`_now`), never the reused receipt's window end: a receipt allowed to name the instant it is
    judged at certifies its own freshness, and a nine-month-old page of low samples would read as a
    recovery every time it was re-submitted. A caller verifying history says so — pass that historical
    ``now``, or call :func:`check` on the rows and let the verdict be about that window, which is what
    its ``window`` field already says it is. A ``now`` that is not an aware :class:`datetime.datetime`
    is a :class:`ConfigError`, because a clock is caller configuration, not source data.
    """
    reference = _clock(now)
    if outcome is None:
        return check(origin, read_sample(store, origin, now=reference))
    if not isinstance(outcome, ReadOutcome):
        return _unknown('receipt-unusable', origin)
    expected = origin.window(reference)
    if expected != outcome.receipt.window:
        # One comparison of the two normalised bounds covers the whole rule: same start and same end
        # means the reused read is the read this origin would have asked for at the instant being
        # judged, of the same length and ending now. It also settles freshness — `_receipt_problem`
        # (and the facade's own receipt guard) require `expires_at > window.end`, so a read that is
        # still live at the instant it is judged about could not have been judged at any other.
        # Anything else and the caller is grading an arbitrary interval and calling it recovery.
        return _unknown('window-mismatch', origin, provenance=_provenance(origin, outcome))
    return check(origin, outcome)


def evidence_sample(verdict: Verdict, *, subject: str | None = None) -> dict[str, Any]:
    """Return the one sample ``Store.put_evidence`` accepts, for a verdict that carries its own proof.

    Takes the verdict alone and nothing else: the condition, the series and the window are the ones
    :func:`check` actually used, so no caller can file a verdict against a different origin than the one
    it was made from. What that leaves is the platform's minimal sample contract —
    ``{sample_id, observed_at, ok, value}`` — with nothing invented around it.

    Read the durability claim narrowly. ``Store.put_evidence`` keeps four fields, so what a reader can
    recover later is the **verdict word** (in ``sample_id``), the **value** the verdict was made on, the
    **window end** (as ``observed_at``) and whether the store answered (``ok``). The threshold,
    comparison, rule, series and window behind it survive only inside the digest — checkable against a
    known origin, never readable back from the row. The follow-up that would make them durable is in
    ``docs/units/verification.md``; nothing here pretends otherwise.

    ``ok`` is the store's answer to the read (did it answer at all), **not** the verdict: a
    ``not_cleared`` verdict on a read that answered carries ``ok=True``, and a reader who mistook the
    two would file a still-firing alert as a clean sample.

    ``sample_id`` is ``verify.<verdict>.<digest>``, the digest covering the effective origin binding, the
    query kind, its approved parameters, the window, the sampled instant, the value, the verdict word
    and (when the caller names one) the action or execution it verifies. Two different verdicts about one
    window get two ids, a re-run of one read gets the same id — which is what makes ``put_evidence``'s
    "Evidence retry changed contents" guard meaningful — and one window verified for two actions leaves
    two rows instead of overwriting.

    Filing is refused for a verdict that carries no window or no binding: an undated sample cannot be
    reauthorised, and a bare value is not proof of anything.
    """
    if not isinstance(verdict, Verdict):
        raise ConfigError('evidence_sample files a Verdict and nothing else; an Origin is not a verdict, '
                          'and a verdict carries the condition it was actually made against')
    if verdict.state not in VERDICTS:
        raise ConfigError('Cannot file a verdict outside the vocabulary')
    if not verdict.origin_binding or not verdict.window or not verdict.window.get('end'):
        raise ConfigError('Cannot file evidence for a verdict that carries no origin binding and no '
                          'query window; grade a store ReadOutcome, not a bare value')
    if verdict.state == UNKNOWN and verdict.reason not in UNVERIFIABLE_REASONS:  # pragma: no cover
        raise ConfigError('Cannot file an unknown verdict with an undocumented reason')
    identity = digest([verdict.origin_binding, verdict.query_type, dict(verdict.parameters or {}),
                       dict(verdict.window), verdict.sampled_at, verdict.value, verdict.state,
                       verdict.reason, subject])
    return {'sample_id': f'verify.{verdict.state}.{identity[:32]}',
            'observed_at': verdict.window['end'], 'ok': verdict.answered, 'value': verdict.value}


def record_evidence(store: Any, sample: dict[str, Any], actor: Any, *,
                    now: dt.datetime | None = None) -> str:
    """File one verdict sample through ``Store.put_evidence`` — the platform's own evidence path.

    No new table, no new column, no lifecycle: the sample is the same four-field artifact every other
    producer files, and ``put_evidence`` keeps its own rules (bounded sample id, numeric-or-null value,
    2 KiB cap, 15-day expiry from ``observed_at``, first-writer-wins on a changed retry). ``now`` is
    passed straight through for the reason it is everywhere else in this package — a test pins the
    clock, a service uses its own.
    """
    return store.put_evidence(sample, actor, now=now)


def post_evidence(platform: Any, sample: dict[str, Any]) -> bool:
    """File one verdict sample with the platform service over ``POST /v1/evidence``.

    The worker's path: the platform service is the single writer of the state database (it holds the
    exclusive owner lock in its lifespan), so a worker files proof through the same authenticated
    producer surface the detector and the anomaly worker already use, and never opens the database
    itself. Returns False when the platform refused, which the caller must not report as a verdict that
    was recorded.
    """
    status, _ = platform.request('POST', '/v1/evidence', sample)
    return status == 200


def load_config(path: Path | str) -> Origin:
    """Read and validate ``LO_VERIFY_CONFIG``; every refusal names a field, never a value."""
    candidate = Path(path)
    try:
        with candidate.open('rb') as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        # A named-but-unreadable file is a refusal, not the off switch: a worker that fell back to
        # defaults would be reporting on a signal nobody pointed it at.
        raise ConfigError(f'{CONFIG_ENVIRONMENT} names a file that cannot be read') from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f'{CONFIG_ENVIRONMENT} document exceeds {MAX_CONFIG_BYTES} bytes')
    try:
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ConfigError(f'{CONFIG_ENVIRONMENT} is not JSON') from None
    return Origin.from_document(document)


def producer_config(environment: Mapping[str, str] | None = None) -> Origin | None:
    """Return the configured check, or None when the worker is not configured at all.

    An unset or blank ``LO_VERIFY_CONFIG`` is the documented off switch: one INFO line naming the
    variable, and no connection, no read and no write follows. A file that is named but unreadable is
    the opposite case and raises — a check that quietly ran a different query would report "cleared"
    for a signal it never read.
    """
    environ = os.environ if environment is None else environment
    raw = (environ.get(CONFIG_ENVIRONMENT) or '').strip()
    if not raw:
        log.info('Post-action verification is off; no configuration named',
                 extra={'variable': CONFIG_ENVIRONMENT})
        return None
    return load_config(raw)


def tick(store: Any, platform: Any, origin: Origin, *,
         now: dt.datetime | None = None) -> tuple[Verdict, bool]:
    """Run one verification round: read, judge, file the sample, log one line.

    Returns the verdict and whether the platform accepted its evidence. A refused evidence post is
    reported, never hidden: the verdict exists but is not durable, and `main` exits 1 on it for the same
    reason the anomaly worker does. The reason is logged even for ``cleared``, because the number, the
    row count and the window behind a clearance are what a reader needs to distrust it later.
    """
    verdict = verify(store, origin, now=now)
    delivered = post_evidence(platform, evidence_sample(verdict))
    log.info('Post-action verification finished', extra={
        'rule_id': origin.rule_id, 'resource_id': origin.resource_id, 'metric_name': origin.metric_name,
        'verdict': verdict.state, 'reason': verdict.reason, 'samples': verdict.samples,
        'value': verdict.value, 'window_end': (verdict.window or {}).get('end'),
        'evidence_delivered': delivered})
    return verdict, delivered


def main() -> int:
    """Verify once and exit; the loop belongs to whoever schedules it (see the reported follow-up).

    Exit codes: ``0`` when a verdict was reached and filed — including an honest ``unknown`` from a read
    that answered "nothing here" — and ``1`` when the check could not be performed at all (unreadable
    configuration, no store credential, a transport failure, or evidence the platform refused). ``1`` is
    never a ``not_cleared``: a still-firing signal is an answer, not a failure.

    With ``LO_VERIFY_CONFIG`` unset this logs one INFO line and returns 0 without constructing a client,
    opening the store or touching the state database.
    """
    try:
        origin = producer_config()
        if origin is None:
            return 0
    except (ConfigError, OSError, ValueError) as exc:
        log.warning('Post-action verification cannot start; configuration is unreadable',
                    extra={'error_class': type(exc).__name__})
        return 1
    try:
        from local_observe.credentials import read_credential
        from local_observe.http import JsonClient, TransportError
        from local_observe.store.backends.clickhouse import store_from_environment

        allow_http = os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
        store = store_from_environment()
        platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                              allow_http=allow_http)
    except (ConfigError, OSError, KeyError, ValueError, TypeError, TransportError) as exc:
        log.warning('Post-action verification cannot run; store or platform is unavailable',
                    extra={'error_class': type(exc).__name__})
        return 1
    try:
        _, delivered = tick(store, platform, origin)
    except (ConfigError, OSError, KeyError, ValueError, TypeError, TransportError) as exc:
        # No verdict and no evidence: the read was not performed. Saying "unknown" here would be a guess
        # about a store we never reached, so the worker fails loudly instead.
        log.warning('Post-action verification unavailable; no verdict filed for this window',
                    extra={'rule_id': origin.rule_id, 'error_class': type(exc).__name__})
        log.debug('Post-action verification failed', exc_info=True)
        return 1
    return 0 if delivered else 1


if __name__ == '__main__':
    raise SystemExit(main())

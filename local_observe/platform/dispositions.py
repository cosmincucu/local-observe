"""What a named operator decided about one alert occurrence, and what that stops.

An **occurrence** is one episode of one alert condition, and its id is the incident id: `Store.intake`
opens an incident on a firing verdict that found no open incident for its condition and closes it when the
last condition pointing at it reports `resolved`, so one incident row already *is* one episode — durable
across an API restart, a notifier restart and a replay of the verdicts that produced it. This module adds
the one of an occurrence's three states that no table could carry before it: **the operator's disposition**.
The measurement stays in `incidents`/`conditions`, the delivery stays in `outbox`, and nothing here writes
either. `docs/api/occurrences.md` is the contract; this file is its implementation, and the paragraphs below
record the mechanisms a reviewer cannot check from that document.

The two dispositions, and what each one buys:

* **acknowledge** — "a human has this". Every delivery of the episode still `pending` (never leased) is
  folded in the same transaction, and later escalation rungs of the *same* episode are held by
  `platform/escalation.py`, which now asks this table through `platform/escalation_reader.py`. The condition
  stays open until a genuine `resolved` verdict arrives, and that verdict is still delivered: someone who
  took the page wants to hear it ended. There is no expiry, because the episode has an end of its own — a
  clear followed by a re-fire is a new incident with a new id, which arrives unacknowledged.
* **dismiss** — "this episode is not actionable". Everything acknowledge does, plus a tombstone per
  (episode, condition) pair, which is what makes the answer durable: `platform/notification_safety` asks
  `state.episode_dismissed` before it takes a send slot, so a verdict that books a *new* delivery for a
  covered pair after this process died still does not page. A re-fire after a genuine clear, or the next
  discrete occurrence of a producer that carries its own identity in `condition`, is a different pair on a
  different incident and pages. Dismissal never resolves the condition, so the measurement of a fault nobody
  fixed is allowed to keep reading `open`.

Four rules hold both of those honest, and each is a decision rather than a convenience:

1. **The pair, never the condition, is the tombstone key.** A tombstone on a condition alone would silence
   the next boot and the next real failure forever, which is the opposite of what an operator asked for and
   the one failure mode a pager may not have. See `state.OCCURRENCE_DISPOSITION_SCHEMA`.
2. **A disposition covers the group members that existed when it was recorded.** The member set is read
   inside the same transaction, so a condition that joins the incident afterwards — the case
   `platform/correlation.py` exists to create — is not covered and its own page still goes out. Silence that
   grows by inheritance is how a dismissed group swallows an unrelated fault.
3. **A leased or dispatched message is never recalled**, because the delivery rail has no recall verb and a
   second one would be a claim about a provider this platform cannot make. The uncertainty is reported
   instead (`delivery.in_flight`, `delivery.uncertain`), so nobody has to infer it from an absence.
4. **The actor is the credential, and the reason is required.** `docs/CONTRACTS.md` §5 says a payload field
   cannot claim that an agent is a human, and `api_contract.assert_no_actor_claim` refuses one before this
   module is reached. An empty reason is refused for the reason the durable history exists at all: a
   disposition nobody can explain next month is the artifact this feature replaces, not an improvement on it.
   The two roles this module hears are `state.OPERATOR_ROLES`, and which of them spoke is stored with the
   decision rather than inferred from the name that spoke.

Two durable facts ride the same transaction and one more does not. The audit row (`occurrence.disposed`) and
the append-only history are inside it, so an operator can always reconstruct who said what in which order.
The two **projection** records — the telemetry metric and the rule card a wider installation expects to learn
from — are rows, not calls: a downstream that is down must not be able to undo a decision, so `drain`
attempts them later, records what it saw, and the read surface reports the status. Absent configuration is a
reported state (`pending` with `last_error: not-configured`), never a silence.

Like every other unit here: the clock is injected, there are no threads, no network, and no second SQL
writer — every statement runs on a connection `Store.transaction()` opened.
"""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

from local_observe.inventory.validation import canonical, utc_text
from local_observe.log import get_logger
from . import api_contract, correlation, escalation, escalation_reader
from .state import (OCCURRENCE_DISMISSAL_ACK_CAUSE, OCCURRENCE_DISMISSAL_CAUSE, OCCURRENCE_DISMISSAL_TABLE,
                   OCCURRENCE_DISPOSITION_HISTORY_TABLE, OCCURRENCE_DISPOSITION_KINDS,
                   OCCURRENCE_DISPOSITION_OPERATION, OCCURRENCE_DISPOSITION_TABLE, OCCURRENCE_PROJECTION_KINDS,
                   OCCURRENCE_PROJECTION_LIMIT, OCCURRENCE_PROJECTION_TABLE, OCCURRENCE_REASON_LIMIT,
                   OPERATOR_ROLE_DISPOSITIONS, OPERATOR_ROLES, StateError, Store, clock, identifier, label,
                   record_suppression, stored_role)
from .suppression import condition_key as event_condition_key

log = get_logger(__name__)

#: The two kinds, re-exported under the names this module's callers use. The vocabulary itself lives in
#: `state.py`, beside the CHECK that enforces it, so a third kind is a schema decision and not a string.
ACKNOWLEDGED, DISMISSED = OCCURRENCE_DISPOSITION_KINDS
#: The states a read may report. The first three name the operator's act; the last is the source having ended
#: the episode, which outranks the act — which is why `state` is derived here and never stored as a fourth
#: kind: a stored `source-resolved` would be one more row that a replay could leave disagreeing with the
#: verdict that actually ended the episode.
UNACKNOWLEDGED, SOURCE_RESOLVED = 'unacknowledged', 'source-resolved'
STATES = (UNACKNOWLEDGED, ACKNOWLEDGED, DISMISSED, SOURCE_RESOLVED)
#: Characters one reason may hold — the column's own bound, imported rather than repeated (the
#: `api_contract.MAX_STORED_REPLY_BYTES` precedent), so the refusal and the CHECK cannot disagree.
MAX_REASON_CHARS = OCCURRENCE_REASON_LIMIT
#: Characters a folded delivery's suppression sentence may reach: the cause word, `: `, and the reason. Named
#: so the composition below is a stated width and not an unbounded concatenation.
MAX_SUPPRESSION_CHARS = len(OCCURRENCE_DISMISSAL_CAUSE) + 2 + MAX_REASON_CHARS
#: Rows one page of the occurrence list or of one occurrence's history may carry. `api_contract` bounds the
#: caller's `limit`; this is the same ceiling, named here so a reader of this file sees the bound.
MAX_PAGE_ROWS = api_contract.PAGE_LIMIT_MAX
#: Projections one drain call may attempt. Bounded work per call, so a downstream that refuses everything
#: cannot make this the statement holding the write lock; what is left is attempted next call.
DRAIN_LIMIT = 50
#: The ceiling on a failed projection's wait before its next attempt, in seconds. The shape is
#: `Store.finish_notification`'s own (exponential, capped) and the cap is the same 300 s, because a
#: projection that has failed for five minutes is not going to succeed sooner than that.
DRAIN_BACKOFF_CEILING = 300
#: The word a projection record carries when no sink is mounted for its target. It occupies the error slot on
#: purpose: leaving it empty reads as "nobody tried", and the truth is "there is nothing here to send to".
NOT_CONFIGURED = 'not-configured'
#: The audit operations a disposition writes. The fold reuses `notification.suppressed`, the operation every
#: other fold in the product already writes, so `presentation.delivery_route` and the suppression statistics
#: see one vocabulary rather than two.
OPERATIONS = (OCCURRENCE_DISPOSITION_OPERATION, 'notification.suppressed')
#: The cause words a folded delivery carries. Distinct from `suppression.CAUSES` because a disposition is a
#: human judgement and those three are measurements; `suppression.reason_cause` answers `other` for both of
#: these, which is that module's honest verdict about a refusal it did not make.
CAUSES = (OCCURRENCE_DISMISSAL_CAUSE, OCCURRENCE_DISMISSAL_ACK_CAUSE)
#: The fixed sentences this module refuses with, named here because the transport maps *statuses* from this
#: module rather than matching English wording the way `stable_code` does for the routes that predate the
#: boundary — a sentence that exists only at its raise site cannot be pinned by a test.
UNKNOWN_OCCURRENCE = 'No occurrence carries this identifier'
DISMISSAL_IS_FINAL = 'A dismissed occurrence cannot be acknowledged; the next episode will page again'
#: The other half of the same rule: the write that reaches this refusal is a dismissal restated with a
#: different reason, and the sentence must not accuse its caller of asking for an acknowledgement. Refused
#: because a second dismissal would silently widen the silence — a condition that joined the episode since the
#: first dismissal would be covered by a statement the operator made about an episode that did not yet hold it
#: (`docs/api/occurrences.md` §4), which is the one thing a tombstone may not do.
DISMISSAL_ALREADY_RECORDED = ('This episode is already dismissed; a dismissal is final, and its silence does '
                              'not widen to a condition that joined since')
REASON_REQUIRED = 'A disposition must carry a reason a later reader can act on'
REASON_SHAPE = f'A disposition reason must be one printable line of at most {MAX_REASON_CHARS} characters'
#: The two roles this module hears, in one sentence that names why the other five are turned away: the
#: operator on call, and the automated operator that acts under its own credential. Neither may name the
#: other in a body — `api_contract.assert_no_actor_claim` refuses a `role` field before this module is
#: reached — so the role in an answer is always the one the server authenticated.
ROLE_REFUSAL = 'Only a ' + ' or '.join(OPERATOR_ROLES) + ' credential may record a disposition'
KIND_REFUSAL = 'Unknown disposition kind'

# ------------------------------------------------------------------------------------------- reads


def revision_of(disposition_revision: int, measured_status: str, opened_at: str) -> str:
    """Return the tag one occurrence presents for a conditional write.

    Composed from three stored facts and nothing else, and deliberately *not* an opaque digest: a caller who
    cannot read a `412` is a caller who cannot debug one. Each part moves for one reason and only one reason —
    `disposition_revision` when an operator records a disposition, `measured_status` when the source ends the
    episode, `opened_at` never (it *is* the episode's identity) — which is what makes the rule above testable:
    a repeat verdict, which moves only `incidents.updated_at`, must not invalidate the acknowledgement
    somebody is in the middle of writing, while a genuine clear must.

    The spelling is `If-Match`-safe by construction: the separator is `.`, and `utc_text` emits only characters
    `api_contract.REVISION_PATTERN` admits.
    """
    return f'{disposition_revision}.{measured_status}.{opened_at}'


def disposition_kind(store: Store, occurrence_id: str) -> str | None:
    """Return the effective kind an operator recorded for one occurrence, or None when nobody has.

    The scheduler's question and nothing more: `platform/escalation_reader.py` asks it about the *base*
    incident it tracks and needs one word rather than a reason and an identity it has no business reading. A
    file this build has not migrated answers None rather than raising, which is what lets escalation on an
    unmigrated database behave exactly as it did before schema v12.
    """
    _occurrence_id(occurrence_id)
    with store.transaction() as connection:
        return _kind(connection, occurrence_id)


def occurrence(store: Store, occurrence_id: str) -> dict[str, Any]:
    """Return one occurrence: the measurement, the disposition, the delivery roll-up.

    Three blocks, three sources, and a refusal rather than a guess when the episode named is not in the file.
    `legacy_evidence` names what the pre-existing acknowledgement reads saw (a decided action, a tapped page
    link) without letting either stand for a disposition: they are not one, and a read that quietly promoted
    them would invent an actor and a reason nobody gave.

    Raises:
        api_contract.ContractError: 404 `not_found` for an id that is not a canonical UUID or names no episode
            this platform opened. One answer for both, so the route is not an oracle for id shape.
    """
    _occurrence_id(occurrence_id)
    with store.transaction() as connection:
        incident = _incident(connection, occurrence_id)
        if incident is None:
            raise api_contract.ContractError(404, 'not_found', UNKNOWN_OCCURRENCE)
        return _document(connection, incident)


def history(store: Store, occurrence_id: str, *, limit: int = api_contract.PAGE_LIMIT_DEFAULT,
            cursor: str | None = None) -> dict[str, Any]:
    """Return one bounded page of one occurrence's disposition history, oldest first.

    Every row the append-only table holds, including the kinds the effective state has moved past — which is
    the point of a history: "who else touched this, and what did they say?" is not answerable from the current
    row. A no-op restatement added no row, so the history is a record of decisions and not of retries.

    Raises:
        api_contract.ContractError: 404 `not_found` for an unknown occurrence, 400 `invalid_pagination` for a
            cursor that is not a history position this service issued.
    """
    _occurrence_id(occurrence_id)
    position = _position(cursor, 'history position')
    with store.transaction() as connection:
        if _incident(connection, occurrence_id) is None:
            raise api_contract.ContractError(404, 'not_found', UNKNOWN_OCCURRENCE)
        rows = connection.execute(
            f'SELECT sequence, kind, actor, {OPERATOR_ROLE_DISPOSITIONS}, reason, at, revision'
            f' FROM {OCCURRENCE_DISPOSITION_HISTORY_TABLE}'
            ' WHERE occurrence_id=? AND sequence>? ORDER BY sequence LIMIT ?',
            (occurrence_id, position, limit)).fetchall()
        return api_contract.page_payload([dict(row, actor_role=stored_role(row, OPERATOR_ROLE_DISPOSITIONS))
                                          for row in rows], limit=limit,
                                         cursor_for=lambda row: row['sequence'])


def page(store: Store, *, limit: int = api_contract.PAGE_LIMIT_DEFAULT,
         cursor: str | None = None) -> dict[str, Any]:
    """Return one bounded page of occurrences, oldest episode first.

    The walk is by `incidents.rowid`, the same honest indexed monotonic position
    `platform/escalation_reader.py` uses for discovery: an incident's `opened_at` is not monotonic (clock
    adjustments, backfills, two episodes opening in one second) and a page key that can go backwards loses
    episodes or repeats them forever. Nothing else is accepted, because `api_contract.page_params` admits only
    `limit` and `cursor` — so an operator narrows the answer by paging through it, and `limit` is refused
    rather than clamped.

    Raises:
        api_contract.ContractError: 400 `invalid_pagination` for a cursor that is not a position.
    """
    position = _position(cursor, 'occurrence position')
    with store.transaction() as connection:
        rows = connection.execute(
            'SELECT rowid AS position, id FROM incidents WHERE rowid>? ORDER BY rowid LIMIT ?',
            (position, limit)).fetchall()
        documents, positions = [], {}
        for row in rows:
            incident = _incident(connection, row['id'])
            if incident is None:                    # gone since the page query: absent, never guessed at
                continue
            documents.append(_document(connection, incident))
            positions[incident['id']] = row['position']
        return api_contract.page_payload(documents, limit=limit,
                                         cursor_for=lambda row: positions[row['occurrence_id']])


# ------------------------------------------------------------------------------------------ writes


def acknowledge(store: Store, occurrence_id: str, reason: str, context: api_contract.ActorContext, *,
                expected_revision: str | None = None,
                now: dt.datetime | None = None) -> dict[str, Any]:
    """Record that the human behind `context` has this, and stop the episode's repeats.

    Raises:
        api_contract.ContractError: the refusals named by :func:`record`.
    """
    return record(store, occurrence_id, ACKNOWLEDGED, reason, context,
                  expected_revision=expected_revision, now=now)


def dismiss(store: Store, occurrence_id: str, reason: str, context: api_contract.ActorContext, *,
            expected_revision: str | None = None,
            now: dt.datetime | None = None) -> dict[str, Any]:
    """Record that the human behind `context` closes this episode, and tombstone its members.

    Raises:
        api_contract.ContractError: the refusals named by :func:`record`.
    """
    return record(store, occurrence_id, DISMISSED, reason, context,
                  expected_revision=expected_revision, now=now)


def record(store: Store, occurrence_id: str, kind: str, reason: str, context: api_contract.ActorContext, *,
           expected_revision: str | None = None,
           now: dt.datetime | None = None) -> dict[str, Any]:
    """Commit one disposition, its history, its fold, its audit row and its projections — or none of them.

    `context` is the only place an identity enters this function, and it is the value the transport built from
    the bearer credential (`api_contract.actor_context`): no parameter accepts an actor, a role or a name, so a
    caller cannot record a disposition as somebody it did not authenticate.

    One `Store.transaction()` (`BEGIN IMMEDIATE`) holds every write, in this order: the effective row, the
    history row, the dismissal tombstones, the fold of the episode's still-`pending` deliveries, the audit row,
    the projection records. A fold that cannot be written rolls the disposition back with it, because an
    operator who believes they silenced a pager must not be reading a database that did not do it. What is
    deliberately *outside* the transaction is any downstream call (§5 of the unit document): the projections
    are rows here, attempted later by :func:`drain`.

    Returns the occurrence document plus ``created`` (False for the identical statement replayed, which changed
    nothing and bumped no revision) and ``folded`` (deliveries this call moved out of ``pending``).

    Raises:
        api_contract.ContractError: 400 `invalid_request` for a kind outside the two or a reason that is
            missing, unprintable or over-long; 403 `not_authorised` for any role other than the two named by
            `state.OPERATOR_ROLES`; 404
            `not_found` for an unknown occurrence; 409 `conflict` for an acknowledgement offered to a dismissed
            episode; 412 `stale_revision` when `expected_revision` no longer describes this occurrence. Nothing
            is written for any of them, and no idempotency key is completed by a refusal (the gate releases it).
    """
    if kind not in OCCURRENCE_DISPOSITION_KINDS:
        raise api_contract.ContractError(400, 'invalid_request', KIND_REFUSAL)
    reason = _reason(reason)
    actor, actor_role = _operator(context)
    _occurrence_id(occurrence_id)
    moment = clock(now)
    with store.transaction() as connection:
        incident = _incident(connection, occurrence_id)
        if incident is None:
            raise api_contract.ContractError(404, 'not_found', UNKNOWN_OCCURRENCE)
        current = _disposition(connection, occurrence_id)
        api_contract.check_revision(_revision(incident, current), expected_revision)
        if current is not None and current['kind'] == kind and current['actor'] == actor \
                and stored_role(current, OPERATOR_ROLE_DISPOSITIONS) == actor_role \
                and current['reason'] == reason:
            # The identical statement, restated. The stored row keeps the *first* actor, role, reason and
            # instant — durable who/when/why means one of each — and no revision moves, so a caller that
            # retried without an `Idempotency-Key` gets the same outcome a replay would have given rather
            # than a second decision on one question and a history full of one operator's network. The role
            # is part of the statement because a role is part of who spoke: the same identity mounted twice
            # (a human token and an agent token) has said two different things.
            return {**_document(connection, incident), 'created': False, 'folded': 0}
        if current is not None and current['kind'] == DISMISSED:
            # Forward only. An acknowledgement after a dismissal would claim a human owns an episode a human
            # just closed, and what that case wants is the next episode — which pages by itself. A restated
            # dismissal is refused by the same rule and a different sentence: it is not asking to acknowledge,
            # it is asking for a wider silence than the one that was granted.
            raise api_contract.ContractError(409, 'conflict',
                                             DISMISSAL_IS_FINAL if kind == ACKNOWLEDGED
                                             else DISMISSAL_ALREADY_RECORDED)
        revision = 0 if current is None else int(current['revision'])
        members = _keys(connection, occurrence_id, incident['condition_key'])
        folded, in_flight = _fold(connection, store, incident, members, moment, kind)
        connection.execute(
            f'INSERT INTO {OCCURRENCE_DISPOSITION_TABLE}(occurrence_id,kind,actor,{OPERATOR_ROLE_DISPOSITIONS},'
            'reason,at,revision)'
            f' VALUES (?,?,?,?,?,?,?) ON CONFLICT(occurrence_id) DO UPDATE SET kind=excluded.kind,'
            f' actor=excluded.actor, {OPERATOR_ROLE_DISPOSITIONS}=excluded.{OPERATOR_ROLE_DISPOSITIONS},'
            ' reason=excluded.reason, at=excluded.at, revision=excluded.revision',
            (occurrence_id, kind, actor, actor_role, reason, utc_text(moment), revision + 1))
        connection.execute(
            f'INSERT INTO {OCCURRENCE_DISPOSITION_HISTORY_TABLE}(occurrence_id,kind,actor,'
            f'{OPERATOR_ROLE_DISPOSITIONS},reason,at,revision)'
            ' VALUES (?,?,?,?,?,?,?)',
            (occurrence_id, kind, actor, actor_role, reason, utc_text(moment), revision + 1))
        tombstoned = _tombstone(connection, occurrence_id, members, actor, moment) if kind == DISMISSED else 0
        store.audit(connection, moment, actor, OCCURRENCE_DISPOSITION_OPERATION, occurrence_id,
                    {'kind': kind, 'actor_role': actor_role, 'revision': revision + 1, 'folded': folded,
                     'in_flight': in_flight, 'tombstoned': tombstoned, 'members': len(members)})
        _project(connection, incident, kind, actor, actor_role, reason, moment)
        updated = _incident(connection, occurrence_id)
        if updated is None:                                 # unreachable: this transaction wrote the row
            raise api_contract.ContractError(500, 'internal_error', 'The committed occurrence vanished')
        return {**_document(connection, updated), 'created': True, 'folded': folded}


def drain(store: Store, sinks: Mapping[str, Callable[[dict[str, Any]], Any]] | None = None, *,
          now: dt.datetime | None = None,
          limit: int = DRAIN_LIMIT) -> dict[str, Any]:
    """Attempt the due projection records `sinks` can serve, and record what each one said.

    A projection is *not* the disposition: this function may fail entirely, many times, and the acknowledgement
    an operator made stays committed, still stopping pages, still readable. That asymmetry is the whole reason
    the projections are rows. Nothing here raises for a downstream fault — a sink that throws, a sink that
    returns a refusal, or no sink mounted for a target — and each leaves the record `pending` with its attempt
    counted, the exception *class* in `last_error` (never a response body, a URL or a credential, per the
    logging contract), and a bounded backoff before the next attempt.

    Args:
        sinks: ``{target: callable}``, where the callable is handed the stored statement document and raises,
            or returns a falsy value, to say it did not land. Optional: with nothing mounted, every due record
            reports `not-configured` and stays retryable.
        now: The instant the attempts are stamped at; defaults to the clock.
        limit: Records one call may attempt, so a refusing downstream is bounded work and not a loop.

    Returns:
        ``{attempted, sent, pending, failed, unconfigured, backoff_seconds}`` — counters, never payloads.
    """
    mounted = dict(sinks or {})
    for target in mounted:
        label(target)
    moment = clock(now)
    report = dict.fromkeys(('attempted', 'sent', 'pending', 'unconfigured', 'failed'), 0)
    with store.transaction() as connection:
        rows = connection.execute(
            f'SELECT occurrence_id, kind, payload, attempts FROM {OCCURRENCE_PROJECTION_TABLE}'
            " WHERE status='pending' AND available_at<=? ORDER BY available_at LIMIT ?",
            (utc_text(moment), max(1, min(int(limit), DRAIN_LIMIT)))).fetchall()
        for row in rows:
            report['attempted'] += 1
            sink = mounted.get(row['kind'])
            if sink is None:
                report['unconfigured'] += 1
                _reproject(connection, row, moment, NOT_CONFIGURED)
                continue
            try:
                accepted = bool(sink(json.loads(row['payload'])))
            except Exception as exc:                     # a downstream fault is a fact about that downstream
                report['failed'] += 1
                _reproject(connection, row, moment, type(exc).__name__)
                continue
            if not accepted:
                report['failed'] += 1
                _reproject(connection, row, moment, 'refused')
                continue
            report['sent'] += 1
            connection.execute(
                f'UPDATE {OCCURRENCE_PROJECTION_TABLE} SET status=?,updated_at=?,last_error=?'
                ' WHERE occurrence_id=? AND kind=?',
                ('sent', utc_text(moment), '', row['occurrence_id'], row['kind']))
    report['pending'] = report['attempted'] - report['sent']
    report['backoff_seconds'] = DRAIN_BACKOFF_CEILING
    return report


# --------------------------------------------------------------------------------------- internals


def _operator(context: Any) -> tuple[str, str]:
    """Return the ``(identity, role)`` behind an authenticated context, refusing every other role.

    The role test sits here rather than in the transport on purpose: `docs/CONTRACTS.md` §5's claim is about
    *who may acknowledge*, and a rule that lives in one handler is a rule the next handler can forget. The
    refusal is a 403 in the machine envelope because this route family has spoken the envelope since its first
    answer; `Store`'s flat `not_authorised` body belongs to the routes that have always given it.

    The role travels with the identity because a decision is only evidence if it says who made it, and "a
    named human took this episode" and "an automated operator took this episode" are two different sentences
    about the same effect. Both roles are admitted — an `operator-agent` dismissal silences exactly the
    deliveries a `human` dismissal silences — and which one spoke is what gets stored.
    """
    if not isinstance(context, api_contract.ActorContext) or context.role not in OPERATOR_ROLES:
        raise api_contract.ContractError(403, 'not_authorised', ROLE_REFUSAL)
    if not context.identity:
        raise api_contract.ContractError(401, 'authentication_required', ROLE_REFUSAL)
    return context.identity, context.role


def _reason(value: Any) -> str:
    """Return a disposition reason, refusing one that could not be read back usefully.

    Required, printable, bounded, and not blank after trimming: the operator on call at 04:00 is allowed to be
    terse and is not allowed to leave the next shift a field that says nothing. The refusal quotes none of the
    caller's text, which is the rule every other refusal in this package holds.
    """
    if not isinstance(value, str) or not value.strip():
        raise api_contract.ContractError(400, 'invalid_request', REASON_REQUIRED)
    if len(value) > MAX_REASON_CHARS or any(character in value for character in '\r\n\x00'):
        raise api_contract.ContractError(400, 'invalid_request', REASON_SHAPE)
    return value.strip()


def _occurrence_id(value: Any) -> str:
    """Return a validated occurrence id. Malformed text and unknown ids answer identically (404)."""
    try:
        return identifier(value)
    except StateError:
        raise api_contract.ContractError(404, 'not_found', UNKNOWN_OCCURRENCE) from None


def _position(value: Any, kind: str) -> int:
    """Return a page position, refusing one this service never issued.

    A cursor is an `incidents.rowid` or a history `sequence` and nothing else. A caller that invented one, or
    mangled one in transit, is refused here rather than reading "no more rows" out of a query that could not
    run — the difference between absence and stopping, which is what `docs/api/COVERAGE.md` makes illegal.
    """
    if value is None:
        return 0
    text = str(value)
    if not text.isascii() or not text.isdecimal():
        raise api_contract.ContractError(400, 'invalid_pagination',
                                         f'A {kind} must be a decimal position this service issued')
    return int(text)


def _incident(connection: sqlite3.Connection, occurrence_id: str) -> sqlite3.Row | None:
    """Return one incident with its anchor condition's verdict and its group size beside it, or None."""
    return connection.execute(
        'SELECT i.id AS id, i.condition_key AS condition_key, i.resource_id AS resource_id,'
        ' i.status AS status, i.opened_at AS opened_at, i.updated_at AS updated_at,'
        ' i.last_event_id AS last_event_id, c.status AS condition_status,'
        ' (SELECT count(*) FROM conditions m WHERE m.incident_id=i.id) AS members'
        ' FROM incidents i LEFT JOIN conditions c ON c.key=i.condition_key WHERE i.id=?',
        (occurrence_id,)).fetchone()


def _disposition(connection: sqlite3.Connection, occurrence_id: str) -> sqlite3.Row | None:
    """Return the effective disposition row, or None when no operator has spoken for this episode.

    `actor_role` is named in the select because it is part of the answer, and read through
    `state.stored_role` because a row this build did not write may predate the column (schema v15): a
    disposition recorded before an automated operator could exist was necessarily a human's, and that is
    the value a read reports for it rather than an absence a caller has to interpret.
    """
    return connection.execute(
        f'SELECT kind, actor, reason, at, revision, {OPERATOR_ROLE_DISPOSITIONS}'
        f' FROM {OCCURRENCE_DISPOSITION_TABLE}'
        ' WHERE occurrence_id=?',
        (occurrence_id,)).fetchone()


def _kind(connection: sqlite3.Connection, occurrence_id: str) -> str | None:
    row = _disposition(connection, occurrence_id)
    return None if row is None else row['kind']


def _keys(connection: sqlite3.Connection, occurrence_id: str, anchor: str) -> set[str]:
    """Every condition key pointing at this incident, plus the anchor even if its row has aged out.

    The anchor is added unconditionally so a group whose member rows this build cannot read still gets
    covered: a tombstone set that silently came back empty would be a dismissal that dismissed nothing, and
    the loud direction for a disposition is the one that says more than less.
    """
    keys = {row['condition_key'] for row in connection.execute(
        'SELECT key AS condition_key FROM conditions WHERE incident_id=?', (occurrence_id,))}
    keys.add(anchor)
    return keys


def _revision(incident: sqlite3.Row, current: sqlite3.Row | None) -> str:
    """Return the tag a caller's expectation is compared against, read from the state and never the body."""
    return revision_of(0 if current is None else int(current['revision']),
                       incident['status'], incident['opened_at'])


def _document(connection: sqlite3.Connection, incident: sqlite3.Row) -> dict[str, Any]:
    """Compose the one document the three sources are read from: measurement, disposition, delivery."""
    occurrence_id = incident['id']
    disposition = _disposition(connection, occurrence_id)
    verdict = connection.execute('SELECT payload FROM events WHERE id=?', (incident['last_event_id'],)).fetchone()
    event = None if verdict is None else _event(verdict['payload'])
    return {'occurrence_id': occurrence_id,
            'episode': _episode(incident, event),
            'measured': {'status': incident['status'], 'condition_status': incident['condition_status'],
                         'opened_at': incident['opened_at'], 'updated_at': incident['updated_at']},
            'disposition': None if disposition is None else {
                'kind': disposition['kind'], 'actor': disposition['actor'], 'reason': disposition['reason'],
                'actor_role': stored_role(disposition, OPERATOR_ROLE_DISPOSITIONS),
                'at': disposition['at'], 'revision': disposition['revision']},
            'state': SOURCE_RESOLVED if incident['status'] == 'resolved' else (
                disposition['kind'] if disposition is not None else UNACKNOWLEDGED),
            'revision': _revision(incident, disposition),
            'delivery': _delivery(connection, occurrence_id),
            'projections': _projections(connection, occurrence_id),
            'legacy_evidence': _legacy_evidence(connection, occurrence_id)}


def _episode(incident: sqlite3.Row, event: Mapping[str, Any] | None) -> dict[str, Any]:
    """Say what this occurrence *is*, from the stored verdict that opened it.

    `identity_basis` is the field that answers an operator's question without their reading this file:
    `incident` names an episode delimited by its own recovery/re-fire boundary, `discrete` names a producer
    carrying its own occurrence identity in `condition` (a boot, a session, a run — the case where the
    *condition* moves so the next occurrence is a new episode), and `verdict-unreadable` names an event row
    this build could not decode. `discrete` is reported only from stored fields, never guessed: an unreadable
    verdict yields `verdict-unreadable` and null names rather than an invented source or rule.
    """
    if event is None:
        basis, names = 'verdict-unreadable', {}
    else:
        condition, rule = event.get('condition'), event.get('rule_id')
        basis = 'discrete' if condition and condition != rule else 'incident'
        names = {'source': event.get('source'), 'rule_id': rule, 'rule_version': event.get('rule_version'),
                 'condition': condition}
    return {'identity_basis': basis, 'condition_key': incident['condition_key'],
            'resource_id': incident['resource_id'], 'members': int(incident['members']),
            'rung': bool(rule and correlation.is_escalation_rung(rule)) if event is not None else False,
            'source': names.get('source'), 'rule_id': names.get('rule_id'),
            'rule_version': names.get('rule_version'), 'condition': names.get('condition')}


def _delivery(connection: sqlite3.Connection, occurrence_id: str) -> dict[str, Any]:
    """Roll the episode's deliveries up into the questions an operator actually asks of them.

    `in_flight` counts rows on a lease and `dispatched` rows whose attempt ended with no acknowledgement
    obtained; both are why `uncertain` is true and `recalled` is false. A disposition folded the `queued` rows it
    found and nothing else, so those numbers beside it are the honest sentence "these may still reach you"
    rather than a promise this platform cannot keep.
    """
    counts = {row['status']: row['total'] for row in connection.execute(
        'SELECT status, count(*) AS total FROM outbox WHERE incident_id=? GROUP BY status',
        (occurrence_id,))}
    suppressed = connection.execute(
        'SELECT count(*) FROM notification_suppressions s JOIN outbox o ON o.id=s.outbox_id'
        ' WHERE o.incident_id=?', (occurrence_id,)).fetchone()[0]
    dispatched = connection.execute(
        "SELECT count(*) FROM notification_attempts a JOIN outbox o ON o.id=a.outbox_id"
        " WHERE o.incident_id=? AND a.result='unknown'", (occurrence_id,)).fetchone()[0]
    in_flight = counts.get('sending', 0)
    return {'queued': counts.get('pending', 0), 'in_flight': in_flight, 'dispatched': dispatched,
            'sent': counts.get('sent', 0), 'suppressed': suppressed,
            'exhausted': max(0, counts.get('dead', 0) - suppressed),
            'recalled': False, 'uncertain': bool(in_flight or dispatched)}


def _projections(connection: sqlite3.Connection, occurrence_id: str) -> dict[str, Any]:
    """The two downstream statements this disposition owes, and where each one stands.

    A target with no row reads `unconfigured` rather than `pending`: the two are different sentences about the
    world — "this build never wrote a record for it" and "a record waits to be attempted" — and a caller that
    conflated them could not tell a missing integration from a stuck one. Every target in the closed
    vocabulary is present in the answer whatever the table holds, so a client's branch is on a status and not
    on a key.
    """
    rows = connection.execute(
        f'SELECT kind, status, attempts, available_at, last_error FROM {OCCURRENCE_PROJECTION_TABLE}'
        ' WHERE occurrence_id=?', (occurrence_id,)).fetchall()
    answer = {kind: {'status': 'unconfigured', 'attempts': 0, 'available_at': None, 'last_error': ''}
              for kind in OCCURRENCE_PROJECTION_KINDS}
    answer.update({row['kind']: {'status': row['status'], 'attempts': row['attempts'],
                                 'available_at': row['available_at'], 'last_error': row['last_error']}
                   for row in rows})
    return answer


def _legacy_evidence(connection: sqlite3.Connection, occurrence_id: str) -> list[str]:
    """Name what the pre-existing acknowledgement reads saw about this incident, as words and nothing more.

    Two `EXISTS` questions over durable rows, deliberately not answered as a disposition: a decided action and
    a tapped page link are facts about a human surface, not an authenticated statement carrying a reason. The
    words are `escalation`'s own, so the scheduler's audit row and this read cannot name one thing two ways,
    and the statements are `escalation_reader`'s expressions so the two reads cannot disagree about which
    action belongs to which incident.
    """
    evidence = []
    placeholders = ','.join('?' * len(escalation.ACK_STATUSES))
    if connection.execute('SELECT EXISTS(SELECT 1 FROM actions WHERE '
                          + escalation_reader.ESCALATION_ACTIONS_EXPRESSION + '=? AND status IN ('
                          + placeholders + '))', (occurrence_id, *escalation.ACK_STATUSES)).fetchone()[0]:
        evidence.append(escalation.ACK_DECISION)
    if connection.execute("SELECT EXISTS(SELECT 1 FROM audit WHERE operation='"
                          + escalation_reader.ESCALATION_INTENT_OPERATION + "' AND subject IN (SELECT id"
                          ' FROM actions WHERE ' + escalation_reader.ESCALATION_ACTIONS_EXPRESSION
                          + '=?))', (occurrence_id,)).fetchone()[0]:
        evidence.append(escalation.ACK_INTENT)
    return evidence


def _event(text: Any) -> Mapping[str, Any] | None:
    """Decode one stored document, or None: an unreadable one is reported, never repaired."""
    try:
        document = json.loads(text)
    except (TypeError, ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def _fold(connection: sqlite3.Connection, store: Store, incident: sqlite3.Row, members: set[str],
          now: dt.datetime, kind: str) -> tuple[int, int]:
    """Move this episode's still-`pending` deliveries out of the queue, and count what had already gone.

    The three writes are the ones `Store.claim_notification` and `suppression` make for every fold in the
    product — `dead`, the durable suppression row, one audit row — reused rather than re-invented, because a
    fold that wrote only the suppression list would leave the row `pending` and leasable
    (`claim_notification` selects on ``status='pending'``). The audit detail's `cause` is what lets a reader
    tell a disposition's fold from a window's or a flap's.

    An **acknowledgement leaves a queued clear alone**: the transition the incident's own verdict booked last.
    A human who said "I have this" still wants to hear when it ended — that page is the end of their shift on
    the incident — while every alert of the episode that has not left the queue is silenced. A **dismissal
    folds it too**, because the statement there is "this episode needs nobody", and a recovery page for an
    episode its operator closed is a page about a fault nobody is tracking. The distinction is read from the
    booked `transition` and not from a message body, which is the only reason it survives a notifier that
    renders text differently next month.

    Rows on a lease and rows already `sent` are counted and left alone: rule 3 of this module's docstring.
    Returns ``(folded, in_flight)``.
    """
    cause = OCCURRENCE_DISMISSAL_CAUSE if kind == DISMISSED else OCCURRENCE_DISMISSAL_ACK_CAUSE
    folded = 0
    for row in connection.execute("SELECT id, payload FROM outbox WHERE incident_id=? AND status='pending'"
                                  ' ORDER BY sequence', (incident['id'],)).fetchall():
        booked = _event(row['payload']) or {}
        if kind != DISMISSED and booked.get('transition') == 'resolved':
            continue
        reason = f'{cause}: {_member_of(booked.get("event"), members, incident["condition_key"])}'
        connection.execute("UPDATE outbox SET status='dead',claim_token=NULL,lease_until=NULL WHERE id=?",
                           (row['id'],))
        record_suppression(connection, row['id'], reason, now)
        store.audit(connection, now, 'suppression-worker', 'notification.suppressed', row['id'],
                    {'reason': reason, 'cause': cause, 'occurrence_id': incident['id'],
                     'transition': booked.get('transition')})
        folded += 1
    in_flight = connection.execute("SELECT count(*) FROM outbox WHERE incident_id=? AND status='sending'",
                                   (incident['id'],)).fetchone()[0]
    return folded, in_flight


def _member_of(event: Any, members: set[str], anchor: str) -> str:
    """Name the condition a folded delivery belonged to, for the sentence in the suppression row.

    `suppression.condition_key` is the one definition of that identity and is reused, so the text in
    `notification_suppressions` names a key `conditions.key` really holds. A delivery whose payload this build
    cannot read is attributed to the episode's anchor condition and stays folded: the fold must not depend on
    parsing a document, because a fold that could not be written would undo an operator's disposition.
    """
    if isinstance(event, Mapping):
        try:
            key = event_condition_key(dict(event))
        except StateError:
            key = None
        if key is not None and key in members:
            return key
    return anchor


def _tombstone(connection: sqlite3.Connection, occurrence_id: str, members: set[str], actor: str,
               now: dt.datetime) -> int:
    """Write one row per (episode, condition) pair, and report how many pairs the dismissal covers.

    `INSERT OR IGNORE` is a guard and not the mechanism: at most one dismissal transaction ever reaches this
    function for one episode, because a dismissal is final — the changed reason that would mean a second
    dismissal is refused with `409` ahead of it (`docs/api/occurrences.md` §2), and the identical restatement
    returns before anything is written. What the pair key is *for* is the width: every condition the group held
    at this instant and only those, so a member that joined afterwards is covered by nothing and its own page
    still goes (§4). The count is reported in the audit row so a reader of the log can see how wide a given
    dismissal was.
    """
    moment = utc_text(now)
    for key in sorted(members):
        connection.execute(f'INSERT OR IGNORE INTO {OCCURRENCE_DISMISSAL_TABLE}(occurrence_id,condition_key,'
                           'actor,at) VALUES (?,?,?,?)', (occurrence_id, key, actor, moment))
    return len(members)


def _project(connection: sqlite3.Connection, incident: sqlite3.Row, kind: str, actor: str, actor_role: str,
             reason: str,
             now: dt.datetime) -> None:
    """Book the two downstream statements as `pending` rows, in the disposition's own transaction.

    The document is the decision and the identifiers that locate it — never an event payload, an evidence
    parameter or a value copied out of a verdict — and its width is `OCCURRENCE_PROJECTION_LIMIT`, the bound the
    column's CHECK carries. `actor_role` travels with `actor` because a downstream told only "an operator named
    X dismissed this" would print a human's sentence about an automated operator's act: the effect it should
    act on is identical, the words it should say are not. Re-dispositioning an occurrence replaces the stored
    statement and resets its
    attempt count: `attempts` counts failures of *what is pending now*, so an operator reading `attempts: 3`
    knows a downstream refused this statement three times and not some older one it no longer holds.
    """
    moment = utc_text(now)
    for target in OCCURRENCE_PROJECTION_KINDS:
        statement = canonical({'occurrence_id': incident['id'], 'projection': target, 'kind': kind,
                               'actor': actor, 'actor_role': actor_role, 'reason': reason, 'at': moment,
                               'condition_key': incident['condition_key'],
                               'resource_id': incident['resource_id']})
        if len(statement.encode()) > OCCURRENCE_PROJECTION_LIMIT:      # the reason bound is the width bound
            raise api_contract.ContractError(400, 'invalid_request', REASON_SHAPE)
        connection.execute(
            f'INSERT INTO {OCCURRENCE_PROJECTION_TABLE}(occurrence_id,kind,payload,status,attempts,'
            'available_at,updated_at,last_error) VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(occurrence_id,kind)'
            ' DO UPDATE SET payload=excluded.payload, status=excluded.status, attempts=0,'
            ' available_at=excluded.available_at, updated_at=excluded.updated_at, last_error=?',
            (incident['id'], target, statement, 'pending', 0, moment, moment, '', ''))


def _reproject(connection: sqlite3.Connection, row: sqlite3.Row, now: dt.datetime, error: str) -> None:
    """Record a failed or unconfigured projection attempt, with a bounded wait before the next one.

    The row stays `pending` and its attempt count rises. Nothing here sets a terminal status or deletes a row:
    a downstream that was unreachable for a week is not a reason to forget an operator's decision, and a
    disposition whose metric never landed is still a disposition.
    """
    attempts = int(row['attempts']) + 1
    wait = min(DRAIN_BACKOFF_CEILING, 2 ** min(attempts, 9))
    connection.execute(
        f'UPDATE {OCCURRENCE_PROJECTION_TABLE} SET attempts=?,available_at=?,updated_at=?,last_error=?'
        ' WHERE occurrence_id=? AND kind=?',
        (attempts, utc_text(now + dt.timedelta(seconds=wait)), utc_text(now), error[:64],
         row['occurrence_id'], row['kind']))


__all__ = ['CAUSES', 'DISMISSED', 'ACKNOWLEDGED', 'STATES', 'UNACKNOWLEDGED', 'SOURCE_RESOLVED', 'OPERATIONS',
           'MAX_REASON_CHARS', 'MAX_SUPPRESSION_CHARS', 'DRAIN_LIMIT', 'NOT_CONFIGURED', 'DISMISSAL_IS_FINAL',
           'DISMISSAL_ALREADY_RECORDED', 'UNKNOWN_OCCURRENCE', 'ROLE_REFUSAL', 'REASON_REQUIRED',
           'REASON_SHAPE', 'KIND_REFUSAL', 'acknowledge', 'dismiss', 'disposition_kind', 'drain', 'history',
           'occurrence', 'page', 'record', 'revision_of']

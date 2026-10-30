"""The shared HTTP boundary: error envelope, request id, idempotency, revision, paging, actor.

`local_observe/platform/api.py` is a hand-written ASGI app with six server-assigned roles and a
decade of response bodies that installed clients and this repository's own tests assert byte for byte
(`tests/test_api_errors.py` pins `{'error': 'conflict', 'detail': 'Action is not pending'}`). A second
route family — alert-occurrence acknowledgement, maintenance windows — must not invent its own answer
shape while doing that. This module is the boundary those routes use, and it is deliberately the *only*
place the following five decisions are made:

* **The machine error envelope.** `{"error": {"code", "message", "request_id"}}`, one code per failure
  class, a sentence chosen by this module, and the id of the request that produced it. Legacy bodies
  stay exactly as they were — see `legacy_error` — so compatibility is a fact about which constructor a
  response used, not a promise nobody can check.
* **Request identity.** One `x-request-id` per served request, reused when the caller sent a
  well-formed one and minted otherwise, echoed on every answer and carried into the log line that
  records a server-side fault.
* **Idempotency.** `Idempotency-Key` on a POST whose durable answer must survive a lost
  acknowledgement. Same key plus same body replays the stored answer; same key plus a different body
  is a `409 idempotency_conflict`, never a second side effect.
* **Expected revision.** `If-Match` compared against the state the caller could not see, answered
  `412 stale_revision` (or `409` where a write had already begun).
* **Actor identity.** An `ActorContext` built *only* from the credential the transport authenticated.
  `assert_no_actor_claim` refuses a body that names an identity, because `docs/CONTRACTS.md` §5 says a
  payload field cannot claim that an agent is a human — and a route that read one would make that
  sentence false.

What this module deliberately is not: a framework, a validator generator, a schema language, or a
second authentication path. It imports no third-party package and no sibling transport module, so it
can be imported by `api.py` at module scope without putting another unit's import failure in front of
every request this process serves.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field, replace
import datetime as dt
import hashlib
import json
import re
import urllib.parse
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from local_observe.inventory.validation import canonical
from .state import (API_IDEMPOTENCY_REPLY_LIMIT, IDEMPOTENCY_IN_FLIGHT_SECONDS, IDEMPOTENCY_PRUNE_ROWS,
                    IDEMPOTENCY_TTL_SECONDS, Actor)

# -------------------------------------------------------------------------------------- header names

#: The request/response header that names one served request. Inbound values are *offered*, never
#: trusted: a value this module cannot echo into a log line safely is replaced by a fresh one.
REQUEST_ID_HEADER = b'x-request-id'
#: The inbound opt-in for "run this write once, and let me read the same answer if I lose the reply".
IDEMPOTENCY_HEADER = b'idempotency-key'
#: The conditional-write header carrying the revision the caller last saw. Deliberately standard
#: (`If-Match`) rather than invented: a client already knows how to send it, and the comparison below is
#: the only interpretation it ever gets here.
REVISION_HEADER = b'if-match'
#: Set on an answer that came out of the idempotency store instead of a second execution. A caller that
#: sees it knows its first attempt landed; a caller that ignores it loses nothing.
REPLAYED_HEADER = b'x-idempotency-replayed'

#: Characters one request id may hold. Chosen so the value survives a header, a log line and a URL
#: query without escaping, and so a caller cannot smuggle a separator into a structured log field.
REQUEST_ID_PATTERN = re.compile(r'[A-Za-z0-9_.:-]{1,64}')
#: Idempotency keys are `state.label` shaped: bounded, no spaces, no separators that would collide with a
#: composite key. Same vocabulary as every other durable name in the platform.
LABEL_PATTERN = re.compile(r'[A-Za-z0-9_.:-]{1,128}')
#: A revision tag additionally admits `+`, because every revision this platform can hold carries a UTC
#: offset (`2026-01-02T03:04:05.123456+00:00`), and `state.label`'s vocabulary would refuse it. The space
#: conversion in `_tag_text` below is the other half: `str(datetime)` renders that same instant with a
#: space, a header may not carry one unquoted and a query string may not carry one at all.
REVISION_PATTERN = re.compile(r'[A-Za-z0-9_.:+-]{1,128}')
#: An `If-Match` value may arrive quoted, or weakly tagged, by clients that copied it from an `ETag`.
TAG_PATTERN = re.compile(r'(?:W/)?"?([A-Za-z0-9_.:+-]{1,128})"?')

# -------------------------------------------------------------------------------------- fixed bounds

#: Raw bytes of a key or an id accepted before any parsing. Both shapes are bounded above, so this is
#: headroom rather than a limit a well-built client can reach.
MAX_HEADER_VALUE_BYTES = 256
#: Stored replies only. The routes this gate serves answer with identifiers and a status, and every one
#: of them is already bounded by its own body ceiling (64 KiB inbound); the ceiling itself is the schema
#: CHECK in `state.py`, so a record cannot be written wider than the file will admit and a larger answer
#: is released rather than truncated — see `IdempotencyGate.complete`.
MAX_STORED_REPLY_BYTES = API_IDEMPOTENCY_REPLY_LIMIT
# How long a completed answer may be replayed, how long an in-flight claim may survive its own process,
# and how many rows one reserve call may reap: all three are imported from `state.py` above, beside the
# table they bound (the same arrangement as `CALLBACK_TTL_SECONDS`), so no number here can drift from the
# CHECK that enforces it.

#: Default and ceiling for the bounded page the next routes expose. `limit` is a *ceiling on the
#: answer*, and `cursor` is opaque to the caller by design: it names a position in this store, not a
#: field a client may filter on.
PAGE_LIMIT_DEFAULT = 50
PAGE_LIMIT_MAX = 200
#: Characters one raw cursor may carry once decoded. A cursor is a position, so anything near this is a
#: caller copying a whole document into a query string.
MAX_CURSOR_CHARS = 256
#: Raw query bytes admitted before parsing, for the same reason `verification_api.MAX_QUERY_BYTES`
#: exists: refuse the oversized input before traversing it.
MAX_QUERY_BYTES = 512

#: The fixed refusal sentences this module may answer with. One spelling each, so a client that switches
#: on the code and a human who reads the message are looking at the same words every time; none is ever
#: formatted with caller bytes, which is the rule `api.py` already holds for a 500.
CURSOR_REJECTED = 'cursor is not a continuation token this service issued'
QUERY_SHAPE_REJECTED = 'A page query takes only limit and cursor, each once'
LIMIT_REJECTED = 'limit must be a positive integer'

# --------------------------------------------------------------------------------------- error codes

#: Every code this boundary can name, with the status it answers under. `x-required-role`, the OpenAPI
#: document and the tests all read this one table, so a code cannot appear in a contract that no code
#: path can produce — and the reverse (a produced code nobody documented) fails the conformance test.
ERROR_CATALOGUE: dict[str, tuple[int, ...]] = {
    'authentication_required': (401,),
    'callback_unauthorised': (401,),
    'not_authorised': (400, 403),
    'summary_only': (403,),
    'invalid_request': (400,),
    'invalid_idempotency_key': (400,),
    'actor_claim_refused': (400,),
    'invalid_pagination': (400,),
    'invalid_revision': (400,),
    'body_too_large': (413,),
    'not_found': (404,),
    'method_not_allowed': (405,),
    'conflict': (409,),
    'idempotency_conflict': (409,),
    'request_in_progress': (409,),
    'stale_revision': (409, 412),
    'internal_error': (500,),
    'observer_state_unavailable': (503,),
    'observer_review_busy': (503,),
    'operator_login_busy': (503,),
    'verification_unavailable': (503,),
    'verification_busy': (503,),
    'verification_storage_error': (500,),
}
#: Codes the pre-existing routes already answer with. Listed to make the split visible: everything else
#: in the catalogue is only reachable through a boundary this module owns.
LEGACY_CODES = frozenset({
    'authentication_required', 'callback_unauthorised', 'not_authorised', 'summary_only',
    'invalid_request', 'body_too_large', 'not_found', 'method_not_allowed', 'conflict',
    'internal_error', 'observer_state_unavailable', 'observer_review_busy', 'operator_login_busy',
    'verification_unavailable', 'verification_busy', 'verification_storage_error',
})

# Fields a body may never use. A route that read `role` out of a payload would let any credential pick
# its own authority, and `Store` already refuses an actor whose role does not fit — so the useful answer
# is not "ignored", it is "refused, loudly, before anything is written".
ACTOR_CLAIM_FIELDS = frozenset({'actor', 'actor_id', 'identity', 'requester', 'requested_by', 'role',
                                'roles', 'credential', 'token', 'operator', 'operator_id',
                                'decided_by', 'on_behalf_of', 'impersonate', 'impersonated_by'})

#: The one body field a conditional write may name. Read only when a route passes `body=` to
#: `expected_revision`, and only as a value compared against stored state — never as an identity.
REVISION_FIELD = 'expected_revision'


# ------------------------------------------------------------------------------------- error surface

class ContractError(Exception):
    """One refusal this boundary chose, as the status and the envelope it must be answered with.

    Deliberately *not* a `StateError`: `api.py` maps a `StateError` by matching fixed English wording
    (`stable_code`), and a boundary refusal already carries its own code. Deriving from `Exception`
    keeps that matcher out of the path entirely, and keeps `docs/CONTRACTS.md` §5's rule that a refusal
    `Store` audited is audited once — a `ContractError` is raised before any `Store` write is entered.
    """

    def __init__(self, status: int, code: str, message: str, *,
                 headers: Sequence[tuple[bytes, bytes]] = ()) -> None:
        super().__init__(message)
        if code not in ERROR_CATALOGUE:
            # A code outside the catalogue is a bug in this module, not a client error: fail at the
            # raise site where the typo is visible rather than shipping an undocumented answer.
            raise KeyError(f'Unknown API error code: {code}')
        self.status = status
        self.code = code
        self.message = message
        self.headers = tuple(headers)


def error_envelope(code: str, message: str, request_id: str) -> dict[str, Any]:
    """Return the machine-readable envelope for one refusal.

    Three fields and no fourth: a code a client can switch on, one sentence a human can read, and the
    id that ties the answer to the log line. Never a request value, a path, a token or an exception
    string — the reason `api.py` already answers a 500 with only an exception class name applies here.
    """
    return {'error': {'code': code, 'message': message, 'request_id': request_id}}


def legacy_error(code: str, detail: str | None = None) -> dict[str, Any]:
    """Return the flat body the routes that existed before this module always answered with.

    `{'error': <code>}`, plus `{'detail': <sentence>}` where the route has always sent one. Kept here,
    next to the envelope, so "which shape does this response use?" is answerable from one file instead
    of from archaeology in `api.py`. Nothing new should use it.
    """
    return {'error': code} if detail is None else {'error': code, 'detail': detail}


# --------------------------------------------------------------------------------------- request ids

def new_request_id() -> str:
    """Return one fresh request id: a canonical UUID, which needs no escaping anywhere it can travel."""
    return str(uuid.uuid4())


def request_id_from(scope: Mapping[str, Any]) -> str:
    """Return the id this request is answered under, reusing only a well-formed, unambiguous inbound one.

    Two `x-request-id` headers are not "the first one wins": an ambiguous identity is replaced, so a
    front end cannot make this process attribute two requests' logs to one id by sending both. A value
    with a character outside `REQUEST_ID_PATTERN` is replaced for the same reason it is not echoed — it
    would land in a structured log field and in a response header.
    """
    offered = [value.decode('utf-8', 'replace') for name, value in _headers(scope)
               if name == REQUEST_ID_HEADER]
    if len(offered) == 1 and REQUEST_ID_PATTERN.fullmatch(offered[0]):
        return offered[0]
    return new_request_id()


# ------------------------------------------------------------------------------- actor and body shape

@dataclass(frozen=True)
class ActorContext:
    """Who this request is, as a value that cannot be edited by the request.

    `identity` and `role` come from the bearer credential the transport matched with
    `secrets.compare_digest`; `authentication` records *that fact* so a downstream route can assert it
    rather than re-derive it. There is no constructor that takes a body: an actor this object does not
    describe cannot be built by a caller.
    """

    identity: str
    role: str
    request_id: str
    authentication: str = 'bearer'
    idempotency_key: str | None = None
    #: The digest of the body this write was admitted with, when a body was read. Held so an
    #: idempotency completion can assert it is finishing the request it reserved for.
    request_sha256: str | None = field(default=None, compare=False)


def actor_context(actor: Actor, request_id: str, *,
                  idempotency_key: str | None = None, request_sha256: str | None = None) -> ActorContext:
    """Return the context for an authenticated `Actor` and nothing else.

    Raises:
        ContractError: The actor is not a `state.Actor` with a non-empty identity and a role, i.e. the
            transport asked this module to describe an anonymous request.
    """
    if not isinstance(actor, Actor) or not actor.identity or not actor.role:
        raise ContractError(401, 'authentication_required', 'A credential is required for this operation')
    return ActorContext(identity=actor.identity, role=actor.role, request_id=request_id,
                        idempotency_key=idempotency_key, request_sha256=request_sha256)


def assert_no_actor_claim(body: Any) -> None:
    """Refuse a body that names an identity, a role or a credential.

    Only top-level keys are examined, and only against `ACTOR_CLAIM_FIELDS`: the point is to make
    "the payload decided who acted" unrepresentable on a guarded route, not to police document content.
    Nothing from the body is echoed back — the refusal names how many fields were wrong, never what
    they were called, so the answer cannot be used to probe which spellings this module knows.
    """
    if isinstance(body, Mapping):
        claims = sorted(field for field in ACTOR_CLAIM_FIELDS if field in body)
        if claims:
            raise ContractError(400, 'actor_claim_refused',
                                f'A body may not name an identity or a role ({len(claims)} such '
                                'field(s) present); actor identity comes from the credential')


def body_digest(body: Any) -> str:
    """Return the digest of one parsed body in its canonical form.

    Canonical JSON, not the raw bytes: a client that reformats key order or whitespace retried the same
    request, and the contract must answer "same body" about the *statement*, the way `actions.retry_key`
    and the verification record fingerprint already do.
    """
    return hashlib.sha256(canonical(body).encode()).hexdigest()


def idempotency_key_from(scope: Mapping[str, Any]) -> str | None:
    """Return the key this request opts in with, or `None` when it does not opt in at all.

    Raises:
        ContractError: The header appears twice, or once with a value outside `LABEL_PATTERN`. A
            malformed key is refused rather than normalised: silently rewriting a key is how two
            different intents end up sharing one stored answer.
    """
    offered = [value.decode('utf-8', 'replace') for name, value in _headers(scope)
               if name == IDEMPOTENCY_HEADER]
    if not offered:
        return None
    if len(offered) != 1 or len(offered[0].encode()) > MAX_HEADER_VALUE_BYTES:
        raise ContractError(400, 'invalid_idempotency_key', 'Exactly one well-formed Idempotency-Key is required')
    key = offered[0]
    if LABEL_PATTERN.fullmatch(key) is None:
        raise ContractError(400, 'invalid_idempotency_key', 'Exactly one well-formed Idempotency-Key is required')
    return key


# --------------------------------------------------------------------------------- expected revision

def _tag_text(value: Any) -> str:
    """Return the one header-safe spelling of a revision or a page position.

    A revision is usually a UTC timestamp, which renders two ways in Python — `isoformat()` with a `T` and
    `str()` with a space — and only one of those may travel in a header or a query string. The conversion is
    applied to the issued tag and to the caller's expectation by the same function, which is the only reason
    both sides can compare strings and be sure they mean the same instant.
    """
    text = value.isoformat() if isinstance(value, dt.datetime) else str(value)
    return text.replace(' ', 'T')


def expected_revision(scope: Mapping[str, Any], body: Any = None) -> str | None:
    """Return the revision this request claims to have read, or `None` for an unconditional write.

    Read from `If-Match` first and, only when a route explicitly passes `body`, from one named body
    field. A quoted or weakly tagged etag is normalised to its tag, because that is the value the
    helper that issued it returned. An `If-Match: *` (any revision) is answered as "no expectation",
    which is what it means: the caller asked to overwrite whatever is there.

    Raises:
        ContractError: The header appears twice or carries a value no tag can be read out of.
    """
    offered = [value.decode('utf-8', 'replace') for name, value in _headers(scope) if name == REVISION_HEADER]
    raw: str | None = None
    if offered:
        if len(offered) != 1:
            raise ContractError(400, 'invalid_revision', 'At most one If-Match value is understood')
        raw = offered[0]
    if raw is None and isinstance(body, Mapping) and REVISION_FIELD in body:
        raw = body[REVISION_FIELD]
    if raw is None:
        return None
    if len(raw.encode()) > MAX_HEADER_VALUE_BYTES or raw.strip() == '*':
        return None
    matched = TAG_PATTERN.fullmatch(_tag_text(raw.strip()))
    if matched is None:
        raise ContractError(400, 'invalid_revision', 'At most one If-Match value is understood')
    return matched.group(1)


def revision_tag(value: Any) -> str:
    """Return the tag text one state value presents for a conditional write.

    A revision is any bounded value the owning module can compare (`updated_at` text, a stored version
    integer, a document digest). It is rendered as text here so the header, the body field and the
    comparison never disagree about spelling.
    """
    tag = _tag_text(value)
    if REVISION_PATTERN.fullmatch(tag) is None:
        # A revision the transport could not name is a defect in the owning module; say so rather than
        # hand a client a tag it can never send back.
        raise ContractError(500, 'internal_error', 'Server state does not expose a comparable revision')
    return tag


def check_revision(actual: Any, expected: str | None, *, status: int = 412) -> str:
    """Return the current revision tag, refusing a caller whose expectation no longer matches.

    The caller's problem with this helper is that it must be given the value it read *from the state*,
    not from the request. No expectation is a no-op, which is what lets a route call it unconditionally.

    Raises:
        ContractError: 404 `not_found` when the resource has no revision at all (nothing to write
            against), or `status` (412 by default, 409 for a write already under way) with code
            `stale_revision` when it disagrees with the caller's.
    """
    current = revision_tag(actual) if actual is not None else None
    if expected is None:
        return current if current is not None else ''
    if current is None:
        raise ContractError(404, 'not_found', 'The resource this write names no longer has state to update')
    if current != expected:
        raise ContractError(status, 'stale_revision',
                            'The resource changed since the revision this request expects; read it again')
    return current


# ---------------------------------------------------------------------------------------- bounded pages

def page_params(scope: Mapping[str, Any], *, default_limit: int = PAGE_LIMIT_DEFAULT,
                maximum: int = PAGE_LIMIT_MAX) -> dict[str, Any]:
    """Return the validated ``{limit, cursor}`` of one list request.

    Strict, and run before any read: an unknown field, a repeated field, a blank value, a non-decimal
    limit, a limit over the ceiling or a cursor that does not decode is a refusal that opens no
    connection. `limit` is refused rather than clamped — a client that asked for 500 rows and quietly
    got 50 would build a wrong idea of completeness, which is the failure `docs/CONTRACTS.md` §2 makes
    illegal for a query adapter.

    Raises:
        ContractError: 400 `invalid_pagination`, naming the bound that failed and never the caller's text.
    """
    raw = scope.get('query_string', b'') or b''
    if len(raw) > MAX_QUERY_BYTES:
        raise ContractError(400, 'invalid_pagination', f'A page query may not exceed {MAX_QUERY_BYTES} bytes')
    fields: dict[str, str] = {}
    for item in raw.split(b'&') if raw else ():
        name, separator, value = item.partition(b'=')
        try:
            name = urllib.parse.unquote(name.decode('ascii'), errors='strict')
            value = urllib.parse.unquote(value.decode('ascii'), errors='strict')
        except (UnicodeDecodeError, UnicodeEncodeError):
            raise ContractError(400, 'invalid_pagination', 'A page query must be ASCII percent-encoded text') from None
        if not separator or not name or not value or name not in ('limit', 'cursor') or name in fields:
            raise ContractError(400, 'invalid_pagination', QUERY_SHAPE_REJECTED)
        fields[name] = value
    limit_text = fields.get('limit', str(default_limit))
    if not limit_text.isascii() or not limit_text.isdecimal() or str(int(limit_text)) != limit_text:
        raise ContractError(400, 'invalid_pagination', LIMIT_REJECTED)
    limit = int(limit_text)
    if not 1 <= limit <= maximum:
        raise ContractError(400, 'invalid_pagination', f'limit must be between 1 and {maximum}')
    return {'limit': limit, 'cursor': decode_cursor(fields['cursor']) if 'cursor' in fields else None}


def encode_cursor(position: Any) -> str:
    """Return the opaque continuation token for one position, or `''` when the page is the last one.

    Base64url without padding: the value goes into a query string, so this is the smallest encoding that
    needs no escaping. It is opaque to a caller and *not* a security boundary — nothing is hidden from
    the client that it did not already see in the rows it was given.
    """
    if position is None:
        return ''
    text = _tag_text(position)
    if len(text) > MAX_CURSOR_CHARS:
        raise ContractError(500, 'internal_error', 'Server state produced an unusable continuation token')
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip('=')


def decode_cursor(token: str) -> str:
    """Return the position one continuation token carries.

    Raises:
        ContractError: 400 `invalid_pagination`. A cursor the caller invented (or mangled in transit) is
            refused here rather than reaching a query, so a typo never reads as "no more rows".
    """
    if len(token) > 4 * ((MAX_CURSOR_CHARS + 2) // 3) + 4:
        raise ContractError(400, 'invalid_pagination', CURSOR_REJECTED)
    try:
        padded = token + '=' * (-len(token) % 4)
        text = base64.urlsafe_b64decode(padded.encode('ascii')).decode('utf-8')
    except (ValueError, UnicodeDecodeError, UnicodeEncodeError):
        raise ContractError(400, 'invalid_pagination', CURSOR_REJECTED) from None
    if not text or len(text) > MAX_CURSOR_CHARS or REVISION_PATTERN.fullmatch(text) is None:
        raise ContractError(400, 'invalid_pagination', CURSOR_REJECTED)
    return text


def page_payload(rows: Sequence[Any], *, limit: int, cursor_for: Any = None) -> dict[str, Any]:
    """Return one page document, plus the cursor that continues it when a full page came back.

    `cursor_for` is called with the last row to produce that row's position. A short page means the end
    and yields no cursor — the difference between "there is no more" and "I stopped looking", which is
    the same honesty rule `docs/CONTRACTS.md` §2 gives a truncated query answer.
    """
    document: dict[str, Any] = {'rows': list(rows), 'limit': limit, 'returned': len(rows)}
    if len(rows) == limit and rows and cursor_for is not None:
        document['next_cursor'] = encode_cursor(cursor_for(rows[-1]))
    return document


# --------------------------------------------------------------------------------------- idempotency

@dataclass(frozen=True)
class Reservation:
    """One key this process holds, or the stored answer that replaces holding it.

    Exactly one of the two is populated: `replay` carries the earlier answer when the key already
    completed, and `held` names a key this request reserved and must therefore finish or release.
    """

    context: ActorContext
    held: bool
    replay: tuple[int, Any] | None = None


class IdempotencyGate:
    """The `Idempotency-Key` protocol over one `Store`, with no queue and no in-process memory.

    Durable state is the point: a process that only remembered keys in a dict would answer "run it
    again" to the exact caller it had just answered — the lost acknowledgement `docs/CONTRACTS.md` §5 is
    written around. `Store` stays the only SQL writer, so this class holds the *rules* (what a replay
    means, how long an in-flight claim lives, what is storable) and every read or write goes to a
    `Store` method.

    Args:
        store: The operational store whose `api_idempotency` table (schema v11) holds the records.
    """

    def __init__(self, store: Any) -> None:
        self.store = store

    def reserve(self, context: ActorContext, body: Any, *, now: dt.datetime | None = None) -> Reservation:
        """Claim the key this context carries, or hand back the answer already stored under it.

        Same key plus the same canonical body replays the stored answer unchanged, so a client that lost
        a response learns its side effect happened exactly once. Same key plus a *different* body is
        `409 idempotency_conflict` and nothing runs: two different intentions under one key is a client
        bug, and executing either one would make the key a lie.

        A key still in flight is `409 request_in_progress` rather than a wait — a second caller cannot
        help the first along, and a queue here would be a backlog of duplicate side effects waiting to
        happen. An in-flight claim older than `IDEMPOTENCY_IN_FLIGHT_SECONDS` belongs to a process that
        died, and the key is handed to the new caller instead.

        Raises:
            ContractError: `idempotency_conflict` or `request_in_progress`.
        """
        if context.idempotency_key is None:
            raise ContractError(400, 'invalid_idempotency_key', 'No idempotency key was carried for this write')
        digest = body_digest(body)
        # Bound the key to this body for the rest of its life: every later call this request makes
        # (complete or abandon) names the same digest it reserved with, so a completion can never land
        # on a row another request wrote under the same key.
        context = replace(context, request_sha256=digest)
        outcome = self.store.idempotency_reserve(context.identity, context.idempotency_key, digest,
                                                 now=now, ttl_seconds=IDEMPOTENCY_TTL_SECONDS,
                                                 stale_seconds=IDEMPOTENCY_IN_FLIGHT_SECONDS,
                                                 prune_rows=IDEMPOTENCY_PRUNE_ROWS)
        state = outcome['state']
        if state == 'replay':
            return Reservation(context=context, held=False,
                               replay=(outcome['status'], json.loads(outcome['payload'])))
        if state == 'conflict':
            raise ContractError(409, 'idempotency_conflict',
                                'This Idempotency-Key was already used for a different request body')
        if state == 'in_progress':
            raise ContractError(409, 'request_in_progress',
                                'This Idempotency-Key is being served by another request right now')
        return Reservation(context=context, held=True)

    def complete(self, reservation: Reservation, status: int, payload: Any) -> None:
        """Store this reservation's answer so a lost response can be replayed.

        Only a 2xx is stored. A 4xx or 5xx is released instead (`abandon`), because a refusal is a fact
        about a state this platform may not have reached, and freezing it under a key would turn a
        retry into a replay of a "no" that is no longer true. An answer larger than
        `MAX_STORED_REPLY_BYTES` is released too: it is served unchanged to this caller, and the next
        replay re-executes the write rather than being answered from a truncated record.
        """
        if not reservation.held:
            return
        if not 200 <= status < 300:
            self.abandon(reservation)
            return
        text = canonical(payload)
        if len(text.encode()) > MAX_STORED_REPLY_BYTES:
            self.abandon(reservation)
            return
        self.store.idempotency_complete(reservation.context.identity, reservation.context.idempotency_key,
                                        reservation.context.request_sha256 or '', status, text)

    def abandon(self, reservation: Reservation) -> None:
        """Let go of a key whose answer was refused, oversized, or never produced.

        Idempotent by construction: the delete names this request's own digest and only ever matches a
        row that has not completed, so racing with a completion cannot discard a stored answer.
        """
        if not reservation.held:
            return
        self.store.idempotency_release(reservation.context.identity, reservation.context.idempotency_key,
                                       reservation.context.request_sha256 or '')


# ------------------------------------------------------------------------------------ request helpers

def header_values(scope: Mapping[str, Any], name: bytes) -> list[str]:
    """Return every value of one header, lower-cased name matched, as decoded text.

    Exported for the routes that need to ask a header question through this boundary rather than
    reading `scope` themselves, so header folding and case rules stay decided in one place.
    """
    return [value.decode('utf-8', 'replace') for key, value in _headers(scope) if key == name]


def _headers(scope: Mapping[str, Any]) -> list[tuple[bytes, bytes]]:
    """Return the request headers as lower-cased-name/byte-value pairs.

    The ASGI spec says a server may hand headers in any casing; a comparison that forgot it would make
    `Idempotency-Key` and `IDEMPOTENCY-KEY` two different questions. Text values are encoded rather than
    refused: a scope built by a test harness or a hand-written client is not a reason for this process to
    raise a `TypeError` on a request it would otherwise answer.
    """
    return [(_as_bytes(name).lower(), _as_bytes(value)) for name, value in scope.get('headers', [])]


def _as_bytes(value: Any) -> bytes:
    """Return *value* as bytes, encoding text rather than failing on it."""
    return value if isinstance(value, bytes) else str(value).encode('utf-8', 'replace')


def request_context(scope: Mapping[str, Any], actor: Actor) -> ActorContext:
    """Return the id, key and actor one request is served under, before any body is read.

    A key is bound to a body, and the body may not have been read at this point in the request: the
    digest is filled in by :meth:`IdempotencyGate.reserve`, which is the only place that pairs them.
    """
    return ActorContext(identity=actor.identity, role=actor.role, request_id=request_id_from(scope),
                        authentication='bearer', idempotency_key=idempotency_key_from(scope))


__all__ = ['ActorContext', 'ContractError', 'ERROR_CATALOGUE', 'IdempotencyGate', 'LEGACY_CODES',
           'Reservation', 'actor_context', 'body_digest', 'check_revision', 'decode_cursor',
           'encode_cursor', 'error_envelope', 'expected_revision', 'header_values', 'idempotency_key_from',
           'legacy_error', 'new_request_id', 'page_params', 'page_payload', 'request_context',
           'request_id_from', 'assert_no_actor_claim', 'revision_tag']

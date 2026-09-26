"""The verification HTTP seam: five exact routes, one owned path set, one off-loop Store slot.

`verification_records.py` and `verification_reader.py` own the durable judgement, the bounds and every
refusal sentence; `api.py` owns bearer authentication and the routes it already has. This module is only
the edge between them, and its surface is deliberately narrow: `owns(path)` answers "is this mine?" for
exactly four literal paths, `handle(scope, receive, actor)` answers with `(status, body)` or with `None`
for "not mine / nobody is listening any more", and `close()`/`wait_idle()` are the two lifecycle hooks a
serving lifespan needs. Nothing here opens a database, runs SQL, derives a verdict, mints a role or reads
an environment value: synchronous work calls `Store` or its read-only candidate helper; authority is the storage
module's own `_reader`/`_writer`, so this file holds no second copy of either vocabulary.

The invariants, each stated with the reason it is shaped this way:

1. **Path ownership is a set test.** `/v1/verification/records` serves both a GET and a POST.
   One additional path discovers bounded verification candidates. Prefix matching would hand this parser
   a query string it was never reviewed
   against, so an unlisted path under `/v1/verification/` stays the main API's to answer.
2. **A refusal costs no I/O.** Method, authority, query syntax, identifier shape, body size and JSON
   shape are all decided before the slot is claimed and before any `Store` method is entered. A summary
   credential is turned away before `receive()`, so a body is never read to decide an authority question
   — and a syntax refusal never reaches the parser-vs-database boundary at all.
3. **Errors are mapped on exact constants, not substrings.** `api.stable_code` matches fixed English
   wording, which is fine for the routes it already serves and wrong here: this surface must distinguish
   "nobody has mounted a policy" (503) from "this producer is not an attestor" (403) and from "the stored
   state is unreadable" (500), and all three of those sentences come out of the same module. So every
   branch compares `str(exc)` against an imported constant from `verification_records`/
   `verification_reader`. A `detail` is echoed only when the sentence is one of those known constants, so
   a message this build has never seen cannot carry a path or a payload into a body; a 500 body is fixed.
4. **One actual synchronous call at a time, and no queue.** Capacity is one per instance: a second
   concurrent verification request is answered `503 verification_busy` rather than made to wait, because
   a queue here is an unbounded buffer of callers whose database is busy, in front of a file whose own
   busy timeout already bounds a real wait. `submit` happens under the same `threading.Lock` as the
   availability test, with no `await` between them: that gap is the entire race, and a slot two requests
   both believed they held would be a second writer on one locked file.
5. **The completion authority is the `concurrent.futures.Future`, and cancellation cannot reach it.**
   The slot is free when that future reports `done()` — a fact about the callable's own thread, not about
   any await that was watching it. `close()` is `shutdown(wait=False)` and never `cancel_futures`: a
   queued item still runs. `wait_idle` polls the future's own state, so it never joins a thread on the
   loop and never mistakes a cancellation for the end of a write. This is the lesson
   `refusal_dispatch.py` documents — a *cancelled wrapper* says nothing about a thread — applied to the
   one future that does: `concurrent.futures.Future.cancel()` is refused the moment the callable started,
   so `cancelled()` here means the callable provably never ran.
6. **`close()`/`wait_idle()` belong to one event loop** — the app's own, matching `create_app`'s ASGI
   lifetime. `asyncio.wrap_future` binds a future to the loop that awaits it, and no cross-thread use of
   one app is promised or supported.

A disconnect mid-body returns `None` and produces no response and no write: a caller who hung up did not
submit a record. Beyond that, cancellation is a lost answer and nothing more.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
import concurrent.futures
from functools import partial
import json
import math
import sqlite3
import threading
from typing import Any

from local_observe.log import get_logger
from .state import StateError
from . import verification_candidates
from .verification_reader import READ_FAILED, BAD_EXECUTION_ID
from .verification_records import (BAD_ACTOR, BAD_BINDING, BAD_BINDING_ID, BAD_CLOCK, BAD_DERIVATION,
                                   BAD_OUTCOME, BAD_RECORD, BAD_RECORD_SIZE, BAD_RECEIPT,
                                   BAD_SAMPLES, BAD_STORED_BINDING, BAD_STORED_EXECUTION,
                                   BAD_VERIFICATION_ID, BAD_WINDOW, EXECUTING_EXECUTION, NEEDS_MIGRATION,
                                   NO_POLICY, RECEIPT_EXPIRY, RECEIPT_REQUIRED, RECEIPT_SCOPE,
                                   RECORD_LIMIT, RECORD_TOO_LARGE, RETRY_CHANGED, ROWS_OVER_COUNT,
                                   ROWS_WITHOUT_ANSWER, SAMPLE_SCOPE, UNKNOWN_ACTION,
                                   UNKNOWN_EXECUTION, WINDOW_IN_FUTURE, WINDOW_NOT_CAPTURED,
                                   INTEGER_LIMIT, MAX_RECORD_BYTES,
                                   _identifier, _reader, _sha256, _writer)

log = get_logger(__name__)

#: The four literal paths this seam owns. `owns` is membership in this set and nothing else: no prefix,
#: no pattern, no trailing-slash folding — the main API keeps every other path, including every other
#: path under `/v1/verification/`.
BINDING_ROUTE = '/v1/verification/binding'
RECORDS_ROUTE = '/v1/verification/records'
RECORD_ROUTE = '/v1/verification/record'
CANDIDATES_ROUTE = '/v1/verification/candidates'
ROUTES = frozenset({BINDING_ROUTE, RECORDS_ROUTE, RECORD_ROUTE, CANDIDATES_ROUTE})
#: The one named query parameter each GET route admits, and the identifier shape it must carry. The write
#: route admits no query string at all: a submitted observation is a body, never a URL.
READ_PARAMETERS = {BINDING_ROUTE: 'action_id', RECORDS_ROUTE: 'execution_id',
                   RECORD_ROUTE: 'verification_id'}
#: Raw query bytes admitted before any parsing. Every legal value here is 36 or 64 ASCII characters plus
#: its parameter name, so 256 is already two orders of magnitude of headroom for one pair.
MAX_QUERY_BYTES = 256
#: Raw body bytes admitted before concatenation. `verification_records.MAX_RECORD_BYTES` bounds the
#: canonical form of the record; this bounds what a caller may make this process hold in memory to ask.
MAX_BODY_BYTES = MAX_RECORD_BYTES
#: How often a drain re-reads the in-flight future when nothing can wake it. A sampling interval, not a
#: deadline: it bounds nothing about how long the callable may take, and the loop stays free throughout.
SLOT_POLL_SECONDS = 0.01
#: The role the transport turns away before anything else, with the body every other write route gives it.
SUMMARY = 'summary'
#: The one 500 body. Fixed, because a driver message carries a path and this surface's fault detail is
#: nobody's to read: "verification storage is failing" is the whole answer an untrusted caller gets.
STORAGE_ERROR = 'verification_storage_error'
#: This module's own sentences. Each names a rule of this edge, never a value: they join
#: `KNOWN_SENTENCES` below, so they are the only non-storage text that may appear in a `detail`.
BAD_QUERY = 'Verification query is malformed'
QUERY_LIMIT = f'Verification query exceeds {MAX_QUERY_BYTES} bytes'
QUERY_PARAMETER = 'Exactly one named verification query parameter is required'
QUERY_ON_WRITE = 'Verification record writes take no query parameters'
BAD_BODY = 'Verification record body is not a bounded JSON object'
#: `state.identifier`'s own sentence, the one `verification_reader.BAD_EXECUTION_ID` restates rather than
#: invents (the reason that module gives for restating it at all): a malformed UUID reads the same here as
#: it does on every other platform surface. One name, imported, so the two cannot drift apart.
BAD_IDENTIFIER_TEXT = BAD_EXECUTION_ID

# The status mapping, keyed on whole sentences imported from their owners rather than on substrings.
NOT_FOUND_SENTENCES = (UNKNOWN_ACTION, UNKNOWN_EXECUTION)
CONFLICT_SENTENCES = (RETRY_CHANGED, EXECUTING_EXECUTION, RECORD_LIMIT)
STORAGE_SENTENCES = (NEEDS_MIGRATION, BAD_STORED_BINDING, BAD_STORED_EXECUTION, BAD_DERIVATION,
                     BAD_CLOCK, RECORD_TOO_LARGE, READ_FAILED)
#: Every sentence a `detail` may carry: the storage module's own refusals (which name a field or a bound
#: and never a value) plus this edge's five. Anything a `Store` raised that is not in here is answered
#: with the fixed 500 body instead — an unreviewed message is exactly the one that could carry a path.
KNOWN_SENTENCES = frozenset(
    (BAD_ACTOR, NO_POLICY, BAD_RECORD, BAD_RECORD_SIZE, BAD_OUTCOME, BAD_BINDING_ID, BAD_VERIFICATION_ID,
     BAD_WINDOW, WINDOW_NOT_CAPTURED, WINDOW_IN_FUTURE, BAD_RECEIPT, RECEIPT_EXPIRY, RECEIPT_SCOPE,
     RECEIPT_REQUIRED, BAD_SAMPLES, SAMPLE_SCOPE, ROWS_WITHOUT_ANSWER, ROWS_OVER_COUNT, BAD_BINDING,
     UNKNOWN_ACTION, UNKNOWN_EXECUTION, RETRY_CHANGED, EXECUTING_EXECUTION, RECORD_LIMIT,
     NEEDS_MIGRATION, BAD_STORED_BINDING, BAD_STORED_EXECUTION, BAD_DERIVATION, BAD_CLOCK,
     RECORD_TOO_LARGE, READ_FAILED, BAD_IDENTIFIER_TEXT, BAD_QUERY, QUERY_LIMIT,
     QUERY_PARAMETER, QUERY_ON_WRITE, BAD_BODY))


class _Refusal(Exception):
    """One answer the parser or the authority gate already chose, raised out of the helper that chose it.

    Private and never logged: it exists so the shape checks can be functions that return a value instead
    of functions that return `dict | None` and make every caller re-test it. Nothing request-derived rides
    in it beyond the fixed body it carries.
    """

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(body['error'])
        self.status = status
        self.body = body


def owns(path: Any) -> bool:
    """Return whether one of the four verification paths is named exactly by *path*."""
    return isinstance(path, str) and path in ROUTES


def _consume(outcome: Any) -> None:
    """Read one finished future's outcome, so nothing is ever logged as "never retrieved".

    Attached as a done-callback to both futures that exist (the asyncio wrapper a request awaited, and the
    concurrent future `wait_idle` polls). A detached exception has no caller left to receive it: it is
    consumed here and, for a parked request, never becomes a client-visible answer either.
    """
    if not outcome.cancelled():
        outcome.exception()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Return one decoded object's dict, refusing a key stated twice at this or any shallower level."""
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError('duplicate object key')
    return dict(pairs)


def _finite(text: str) -> float:
    """Return a JSON float literal, refusing the ones a verification record cannot carry an answer in."""
    value = float(text)
    if not math.isfinite(value):
        # `1e400` is a float literal, not the `Infinity` constant, so `json` hands it over happily and
        # `parse_constant` never sees it. A non-finite value has no place in a window, a count or a value.
        raise ValueError('non-finite number')
    return value


def _whole(text: str) -> int:
    """Return a JSON integer literal inside the signed-64 bound every stored field obeys."""
    value = int(text)
    if abs(value) > INTEGER_LIMIT:
        raise ValueError('unbounded integer')
    return value


def _reject_constant(_name: str) -> Any:
    """Refuse `NaN`/`Infinity`/`-Infinity` instead of letting them arrive as floats."""
    raise ValueError('non-finite constant')


def _strict_object(raw: bytes) -> dict[str, Any]:
    """Return the submitted record as a parsed object, refusing every other spelling of bytes.

    The UTF-8 decode happens before `json.loads` on purpose: `json` would sniff a UTF-16/32 BOM and
    happily read an encoding this platform never accepts, so a two-byte-per-character body could double
    the record bound and stay admissible. Nothing is re-encoded to check that. Duplicate keys,
    non-finite numbers, unbounded integers and structures deep enough to threaten the recursion limit are
    all the same answer — one `400 invalid_request` with this module's fixed sentence, no `line 1 column
    4000` of caller text and no second record schema here.
    """
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_BODY}) from None
    try:
        document = json.loads(text, object_pairs_hook=_unique, parse_constant=_reject_constant,
                              parse_float=_finite, parse_int=_whole)
    except (ValueError, RecursionError, OverflowError):
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_BODY}) from None
    if not isinstance(document, dict):
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_BODY})
    return document


async def _body(receive: Callable[..., Any]) -> bytes | None:
    """Collect the request body under `MAX_BODY_BYTES`, or return `None` on a disconnect.

    The size test is against `len(raw) + len(chunk)` *before* concatenation, so an oversized body is
    refused by the chunk that would have overflowed the buffer rather than by the buffer. A disconnect
    returns `None`, which `handle` propagates: no response is owed to a caller that hung up, and nothing
    of theirs is written on its behalf.
    """
    collected = bytearray()
    while True:
        chunk = await receive()
        if chunk['type'] == 'http.disconnect':
            return None
        pending = chunk.get('body', b'')
        if len(collected) + len(pending) > MAX_BODY_BYTES:
            raise _Refusal(413, {'error': 'body_too_large'})
        collected += pending
        if not chunk.get('more_body'):
            return bytes(collected)


def _percent(text: str) -> str:
    """Return *text* with strict percent-decoding: one escape, three characters, valid UTF-8.

    A stray or short `%`, an escape that is not two hex digits, and bytes that do not form a UTF-8
    sequence are all refusals. `urllib.parse` is not used: it replaces undecodable bytes, keeps `+` as a
    space, and accepts separators a bounded identifier never needs, and every one of those defaults would
    be a second, undocumented answer to "what did the caller name?".
    """
    out = bytearray()
    index = 0
    while index < len(text):
        character = text[index]
        if character != '%':
            out += character.encode('ascii')
            index += 1
            continue
        digits = text[index + 1:index + 3]
        if len(digits) != 2 or any(digit not in '0123456789abcdefABCDEF' for digit in digits):
            raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_QUERY})
        out.append(int(digits, 16))
        index += 3
    try:
        return out.decode('utf-8')
    except UnicodeDecodeError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_QUERY}) from None


def _query_value(route: str, raw: bytes) -> str:
    """Return the one identifier *route* names, refusing every other query spelling.

    Exactly one `name=value` pair, the name this route expects, no duplicate, no blank, no extra, no
    bare `&`, and the whole string bounded first — so the parser never traverses an unbounded input. The
    bytes are ASCII-decoded strictly (a non-ASCII byte is a refusal here, not a replacement character),
    then percent-decoded strictly, then and only then handed to an identifier parser.
    """
    if len(raw) > MAX_QUERY_BYTES:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': QUERY_LIMIT})
    wanted = READ_PARAMETERS[route]
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_QUERY}) from None
    if not text:
        # No query bytes at all is "the parameter is missing", which is a different sentence from "the
        # bytes that arrived are not decodable", and the caller can only act on the right one.
        raise _Refusal(400, {'error': 'invalid_request', 'detail': QUERY_PARAMETER})
    found: str | None = None
    named: set[str] = set()
    for segment in text.split('&'):
        name, separator, value = segment.partition('=')
        if not separator or not name or not value:
            raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_QUERY})
        name = _percent(name)
        if name in named or name != wanted:
            # `name in named` covers a repeated parameter; `name != wanted` covers an extra one and an
            # unknown one. Both are the same sentence, because both say "this is not one named read".
            raise _Refusal(400, {'error': 'invalid_request', 'detail': QUERY_PARAMETER})
        named.add(name)
        found = _percent(value)
    if found is None:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': QUERY_PARAMETER})
    return found


def _bounded_uuid(value: str) -> str:
    """Return canonical UUID text, refusing on type/length before any parser sees the caller's string."""
    if not isinstance(value, str) or len(value) != 36:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_IDENTIFIER_TEXT})
    try:
        return _identifier(value, BAD_IDENTIFIER_TEXT)
    except StateError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_IDENTIFIER_TEXT}) from None


def _candidate_page(raw: bytes) -> tuple[str | None, int]:
    """Parse optional after/limit once; refuse duplicates and aliases before the slot."""
    if len(raw) > MAX_QUERY_BYTES:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': QUERY_LIMIT})
    try:
        text = raw.decode('ascii')
        values = {}
        for segment in text.split('&') if text else ():
            name, separator, value = segment.partition('=')
            if not separator or not name or not value:
                raise ValueError()
            name, value = _percent(name), _percent(value)
            if name not in ('after', 'limit') or name in values:
                raise ValueError()
            values[name] = value
        limit_text = values.get('limit', str(verification_candidates.DEFAULT_LIMIT))
        if not limit_text.isascii() or not limit_text.isdecimal() or str(int(limit_text)) != limit_text:
            raise ValueError()
        return verification_candidates.validate_page(values.get('after'), int(limit_text))
    except (ValueError, UnicodeDecodeError, StateError):
        raise _Refusal(400, {'error': 'invalid_request',
                             'detail': verification_candidates.BAD_QUERY}) from None


def _bounded_digest(value: str) -> str:
    """Return one lowercase SHA-256 digest, refusing a wrong-length string before digest validation."""
    if not isinstance(value, str) or len(value) != 64:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_VERIFICATION_ID})
    try:
        return _sha256(value, BAD_VERIFICATION_ID)
    except StateError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': BAD_VERIFICATION_ID}) from None


def _state_error(exc: StateError, method: str) -> tuple[int, dict[str, Any]]:
    """Return the answer a `Store` refusal entitles this caller to, matched on exact sentences.

    `RECORD_LIMIT` and `BAD_STORED_EXECUTION` are deliberately method-aware and sentence-aware: the same
    words mean "you asked for a 65th check" on a submission (409, the caller's) and "the file disagrees
    with the writer" on a discovery read (500, ours). A 500 never carries the sentence.
    """
    sentence = str(exc)
    if sentence in NOT_FOUND_SENTENCES:
        return 404, {'error': 'not_found'}
    if sentence == BAD_ACTOR:
        return 403, {'error': 'not_authorised', 'detail': BAD_ACTOR}
    if sentence == NO_POLICY:
        return 503, {'error': 'verification_unavailable', 'detail': NO_POLICY}
    if method == 'POST' and sentence in CONFLICT_SENTENCES:
        return 409, {'error': 'conflict', 'detail': sentence}
    if method == 'GET' or sentence in STORAGE_SENTENCES:
        # After the parser accepted an identifier, a GET `StateError` is about stored state: a missing
        # table, a corrupt stored id or cap, an unreadable binding. Those are ours, not the caller's.
        return 500, {'error': STORAGE_ERROR}
    return 400, {'error': 'invalid_request',
                 'detail': sentence if sentence in KNOWN_SENTENCES else BAD_RECORD}


def _unexpected(exc: BaseException) -> tuple[int, dict[str, Any]]:
    """Book a fault that was not a `StateError`, or refuse to book it and let the bug travel.

    A driver error and a JSON/Unicode failure while re-parsing a stored document are storage failures:
    one fixed body for either method, no driver text, and the class logged once. Anything else is a defect
    in this build or in `Store`, and turning it into a client error would be a false accusation — so it
    propagates to `api.py`'s existing 500 handling, which is where an unchosen exception belongs.
    """
    if isinstance(exc, (sqlite3.Error, json.JSONDecodeError, UnicodeDecodeError)):
        log.warning('Verification storage request failed', extra={'error_class': type(exc).__name__})
        return 500, {'error': STORAGE_ERROR}
    raise exc


class VerificationAPI:
    """The verification routes over one `Store`, with one off-loop callable and no queue.

    Construction takes the store and nothing else: no event loop, no policy document, no environment
    value, no thread. The executor exists only once a request needed a thread, so an app that is built,
    inspected and discarded costs no thread and a test that exercises only the parser starts no pool.
    The store handle is held, never used on this thread: every `Store` call below runs inside `_admit`.
    """

    def __init__(self, store: Any) -> None:
        self.store = store
        self._lock = threading.Lock()
        self._executor: concurrent.futures.ThreadPoolExecutor | None = None
        self._running: Any = None
        self._closed = False

    # ----------------------------------------------------------------------- ownership

    @property
    def closed(self) -> bool:
        """Whether admission is shut; `close()` is permanent for this instance."""
        with self._lock:
            return self._closed

    @property
    def slot_busy(self) -> bool:
        """Whether the one callable this instance admitted is still not `done()`.

        Read off the future rather than a counter, so the answer cannot drift from the fact: a callable
        this instance submitted five requests ago and that already finished reports free, and one whose
        request was cancelled mid-flight reports busy for as long as its thread is inside SQLite.
        """
        with self._lock:
            return self._occupied_locked() is not None

    # -------------------------------------------------------------------------- ASGI

    async def handle(self, scope: dict, receive: Callable[..., Any],
                     actor: Any) -> tuple[int, dict[str, Any]] | None:
        """Answer one verification request, or return `None` for "not mine" / "caller hung up".

        `api.py` calls this only for a path `owns` accepted and only with an authenticated `Actor` (the
        bearer never reaches this module), so the `None` it can see here means a disconnected body: there
        is nobody left to answer. Everything before the slot — method, authority, query, size, JSON — is
        decided on this thread, on the caller's bytes alone.
        """
        route = scope.get('path')
        if not owns(route):
            return None
        method = scope.get('method')
        try:
            if getattr(actor, 'role', None) == SUMMARY:
                # The transport's own early answer, before `receive` and before the storage authority is
                # consulted: a summary credential may not read a record or file one, and no role test
                # inside `Store` (which refuses it too) is reached to decide these bytes.
                return 403, {'error': 'summary_only'}
            if method == 'POST':
                if route != RECORDS_ROUTE:
                    # A recognized path with an unsupported method: no body is read, no `Store` is asked,
                    # and no slot is taken. `/v1/verification/binding` and `/v1/verification/record` are
                    # reads, and a POST to them is not a "write with an empty body".
                    return 405, {'error': 'method_not_allowed'}
                return await self._record_write(scope, receive, actor)
            if method != 'GET':
                return 405, {'error': 'method_not_allowed'}
            if route == CANDIDATES_ROUTE:
                _writer(self.store.verification_policy, actor)
                after, limit = _candidate_page(scope.get('query_string', b''))
                return await self._offload(partial(self._read_candidates, after, limit, actor))
            return await self._record_read(route, scope, actor)
        except _Refusal as refusal:
            return refusal.status, refusal.body
        except StateError as exc:
            # The authority gates are `Store`'s own sentences raised from this thread rather than from an
            # executor one: same map, same statuses. Classifying them here is what keeps "no policy is
            # mounted" a 503 and "this producer is not an attestor" a 403 instead of letting
            # `api.stable_code`'s substring reading answer both with a 400.
            return _state_error(exc, method)

    async def _record_read(self, route: str, scope: dict,
                           actor: Any) -> tuple[int, dict[str, Any]]:
        """One bounded read: authority, then identifier shape, then the off-loop `Store` call.

        `_reader` runs against the store's *current* policy before the query is even parsed, so a caller
        who may not read learns nothing about how this parser spells a parameter, and a refusal costs no
        connection, no thread and no slot. The identifier is validated here rather than left to `Store`
        because after the slot is claimed every refusal has to come from a thread.
        """
        _reader(self.store.verification_policy, actor)
        value = _query_value(route, scope.get('query_string', b''))
        if route == RECORD_ROUTE:
            wanted, work = _bounded_digest(value), self._read_record
        elif route == BINDING_ROUTE:
            wanted, work = _bounded_uuid(value), self._read_binding
        else:
            wanted, work = _bounded_uuid(value), self._read_ids
        return await self._offload(partial(work, wanted, actor))

    async def _record_write(self, scope: dict, receive: Callable[..., Any],
                            actor: Any) -> tuple[int, dict[str, Any]] | None:
        """One submitted observation: authority, bytes, shape, then the off-loop write.

        `_writer` is the storage module's own gate, so "reader/human/proposer/executor are refused, a
        producer is admitted only while the current policy names it, and with no policy mounted nothing
        may be written" is one rule with one owner — and it runs before a single body chunk is read, the
        way `api.py`'s summary gate runs before the body. A first acceptance and an exact replay both
        answer 200 with the storage layer's own `{verification_id, created}`, unwrapped.
        """
        _writer(self.store.verification_policy, actor)
        if scope.get('query_string', b''):
            raise _Refusal(400, {'error': 'invalid_request', 'detail': QUERY_ON_WRITE})
        raw = await _body(receive)
        if raw is None:
            return None
        record = _strict_object(raw)
        return await self._offload(lambda: self._write(record, actor))

    async def _offload(self, call: Callable[[], tuple[int, dict[str, Any]]]) -> tuple[int, dict[str, Any]]:
        """Run one synchronous `Store` call on this instance's only thread, and await its outcome.

        `submit` or shed — never queue, never wait for a slot. The await is shielded over a wrapper of
        the *concurrent* future: cancelling this coroutine cannot cancel the callable, cannot take the
        slot back, and cannot decide when this instance's next request may run. The wrapper is never
        cancelled by anything here, which is the only reason `wrap_future`'s cancellation propagation is
        inert; the future that actually describes the work stays the authority in `self._running`.
        """
        admitted = self._admit(call)
        if admitted is None:
            return 503, {'error': 'verification_busy'}
        wrapper = asyncio.wrap_future(admitted)
        wrapper.add_done_callback(_consume)
        try:
            return await asyncio.shield(wrapper)
        except asyncio.CancelledError:
            # The requester went away. The callable did not: it keeps the slot until its own thread
            # returns, and `wait_idle` is what says when that happened.
            raise
        except BaseException as exc:  # carried off the executor thread by the future
            return _unexpected(exc)

    # ---------------------------------------------------------------------- store work

    def _read_candidates(self, after: str | None, limit: int, actor: Any) -> tuple[int, dict[str, Any]]:
        """Reuse the service slot, current producer authority and a read-only helper."""
        try:
            return 200, verification_candidates.list_candidates(self.store, actor, after=after, limit=limit)
        except StateError as exc:
            return _state_error(exc, 'GET')

    def _read_binding(self, action_id: str, actor: Any) -> tuple[int, dict[str, Any]]:
        """The synchronous half of `GET /v1/verification/binding`."""
        try:
            return 200, self.store.get_verification_binding(action_id, actor)
        except StateError as exc:
            return _state_error(exc, 'GET')

    def _read_ids(self, execution_id: str, actor: Any) -> tuple[int, dict[str, Any]]:
        """The synchronous half of `GET /v1/verification/records` — ids only, never documents."""
        try:
            return 200, {'verification_ids': self.store.list_verifications(execution_id, actor)}
        except StateError as exc:
            return _state_error(exc, 'GET')

    def _read_record(self, verification_id: str, actor: Any) -> tuple[int, dict[str, Any]]:
        """The synchronous half of `GET /v1/verification/record`; an id never recorded is a 404."""
        try:
            document = self.store.get_verification(verification_id, actor)
        except StateError as exc:
            return _state_error(exc, 'GET')
        return (404, {'error': 'not_found'}) if document is None else (200, document)

    def _write(self, record: dict[str, Any], actor: Any) -> tuple[int, dict[str, Any]]:
        """The synchronous half of `POST /v1/verification/records`."""
        try:
            return 200, self.store.put_verification(record, actor)
        except StateError as exc:
            return _state_error(exc, 'POST')

    # --------------------------------------------------------------------- slot control

    def _occupied_locked(self) -> Any:
        """Return the future still holding the slot, or `None`. Caller holds `self._lock`."""
        running = self._running
        return None if running is None or running.done() else running

    def _admit(self, call: Callable[[], tuple[int, dict[str, Any]]]) -> Any:
        """Claim the slot and submit *call* inside one locked span, or shed and return `None`.

        The availability test and the `submit` share the lock and there is no `await` — indeed no lock
        release — between them, because two requests that both read "free" would put two verification
        callables on one SQLite file, which is the exact condition this slot exists to bound.
        `ThreadPoolExecutor.submit` only takes the item (the pool is private and single-worker, so its
        internal queue cannot grow past the one call) and never calls back into this object.
        """
        with self._lock:
            if self._closed or self._occupied_locked() is not None:
                # Busy and closed are one answer to this caller, and the same body: nothing of theirs ran.
                return None
            if self._executor is None:
                # Lazy, and named: `max_workers=1` is the capacity, so the pool itself cannot become the
                # queue this design refuses, and no other app's work shares this thread.
                self._executor = concurrent.futures.ThreadPoolExecutor(
                    max_workers=1, thread_name_prefix='verification')
            self._running = self._executor.submit(call)
            return self._running

    def close(self) -> None:
        """Shut admission, synchronously, waiting for nothing and cancelling nothing.

        `shutdown(wait=False)` is the whole promise: this thread may not join the worker (that join would
        happen on the serving loop), and `cancel_futures` is never passed, because a verification write
        this app already admitted either finishes or fails on its own terms and `wait_idle` is how the
        lifespan learns which. Idempotent, and a submission after this is a shed, never a `RuntimeError`
        from a shut-down pool: the closed flag is read before the pool is ever touched.
        """
        with self._lock:
            self._closed = True
            executor = self._executor
        if executor is not None:
            executor.shutdown(wait=False)

    async def wait_idle(self) -> None:
        """Wait until this instance's synchronous work has really ended. No join, no deadline.

        `api.py` awaits this in its drain, after `close()` and before the owner lock is handed back, so a
        verification `INSERT` cannot outlive the process that admitted it. A `CancelledError` that lands
        while the callable runs is *remembered and re-raised afterwards*: a drain that stops waiting is
        not a drain that saw the work end, and releasing the owner lock around a live write is the one
        thing this wait exists to prevent. Nothing awaited here is a thread, and nothing here decides how
        long the callable may take.
        """
        interrupted = False
        while True:
            with self._lock:
                running = self._running
            if running is None:
                break
            while not running.done():
                # `concurrent.futures.Future.done()` is a fact about the callable: it is set after the
                # callable returned or raised, and a started item can never be cancelled into it.
                try:
                    await asyncio.sleep(SLOT_POLL_SECONDS)
                except asyncio.CancelledError:
                    interrupted = True
            _consume(running)  # covers an item dropped before it ran, and consumes its outcome
            with self._lock:
                if self._running is running:
                    self._running = None
        if interrupted:
            raise asyncio.CancelledError()


__all__ = ['BINDING_ROUTE', 'RECORDS_ROUTE', 'RECORD_ROUTE', 'VerificationAPI', 'owns']

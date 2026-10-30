"""The maintenance route family: windows, schedules, outcomes and intervals.

`platform/api.py` owns the request boundary — credential to actor, one request per connection, body
limits, the idempotency claim, the answer envelope. This module owns the paths that answer "what work is
planned, over what, and what became of it", and nothing else: it opens no database, mints no identity, and
refuses nothing that `local_observe.platform.maintenance` has not already refused. The split is deliberate.
The durable rules (who may sign a silence, what a window covers, when a plan materializes) belong to
`maintenance.py` and `suppression.py`, where the CLI, the worker and the tests reach them too; a route is
those same rules seen from one URL.

Three things are true of every route here, and each is worth saying once:

* **A write is signed by the credential, never by the body.** `api.py` refuses an identity field in the
  payload before this module is reached, so `author`, `declared_by` and `cancelled_by` in an answer are
  always the actor the server authenticated — a value this file could not have been handed.
* **A read reports its bound.** Every collection here answers `bound_exceeded` beside its rows, because
  "nothing is planned" and "this build stopped counting" are different claims about the estate, and the
  second must never be printable as the first.
* **Nothing is invented on the way out.** `None` in an answer means the stored row says nothing: a v1
  window with no condition classes, a window with no schedule behind it, a plan that has not materialized
  yet. The vocabulary and the bounds live in `maintenance.py`; this file only chooses a status code for a
  sentence that module already wrote.
"""

from __future__ import annotations

import datetime as dt
import urllib.parse
from pathlib import Path
from typing import Any

from . import maintenance, suppression
from .api_contract import ContractError
from .state import Actor, StateError, Store, require

#: The collection routes, spelled exactly as documented: `tests/test_api_openapi_conformance.py` reads
#: these literals out of this file and fails a documented path that no transport names.
WINDOW_ROUTE = '/v1/maintenance-windows'
SCHEDULE_ROUTE = '/v1/maintenance-schedules'
INTERVAL_ROUTE = '/v1/maintenance-intervals'

#: Sub-resource prefixes. The trailing slash is what makes each literal match the templated documented
#: path (`/v1/maintenance-windows/{id}/history`) as well as the collection, which is the direction the
#: coverage check runs; the id after it is validated by `state.identifier` before it is used for anything.
WINDOW_PREFIX = '/v1/maintenance-windows/'
SCHEDULE_PREFIX = '/v1/maintenance-schedules/'

READ_PREFIXES = (WINDOW_ROUTE, SCHEDULE_ROUTE, INTERVAL_ROUTE)
#: The writes the idempotency boundary guards: a retried declaration must not buy a second silence, and a
#: retried materialization must not spend an occurrence twice. Two shapes, because the collection routes are
#: addressed by their body and the sub-resources by their path, and a single prefix over the collection
#: name would also match a route that does not exist (`/v1/maintenance-windows-x`), spending an
#: idempotency key on the way to a 404.
WRITE_ROUTES = (WINDOW_ROUTE, SCHEDULE_ROUTE)
WRITE_PREFIXES = (WINDOW_PREFIX, SCHEDULE_PREFIX)

#: Sentences from `maintenance.py`/`suppression.py` that mean "no such row", which is a 404 and not a 400.
#: Matched on fixed wording the way `api.py`'s `stable_code` matches its own: "you asked for something
#: that is not here" is a different fact from "what you sent is malformed", and an operator who typed a
#: valid uuid they have never seen deserves to learn which one happened.
NOT_FOUND = frozenset({'No such maintenance window', 'No such maintenance schedule'})

#: Sub-resources, matched as whole segments so a typo answers 404 rather than reaching a handler that
#: read a different route's meaning out of the same bytes.
WINDOW_SUBROUTES = ('history', 'cancellations')
SCHEDULE_SUBROUTES = ('history', 'cancellations', 'materializations')

READ_ROLES = ('reader', 'proposer', 'human', 'executor')
WRITE_ROLES = ('human',)


def writes(path: str) -> bool:
    """Whether one path is a maintenance write, and so is owed the idempotency boundary."""
    return path in WRITE_ROUTES or path.startswith(WRITE_PREFIXES)


def edits(path: str) -> bool:
    """True only for the one path `PATCH` is a verb of: a bare schedule address.

    `api.py` gates verbs before it gates routes, so widening `PATCH` for the schedule edit would widen it
    for every write path in the API — and a `PATCH /v1/audit` that fell through to the end of the chain would
    answer `404 not_found` instead of the `405` every other path gives for a verb it does not carry. Narrowing
    the allowance to the path that means it keeps one answer per question, and keeps the widening honest: one
    route, one verb, no new shape anywhere else.
    """
    tail = path[len(SCHEDULE_PREFIX):] if path.startswith(SCHEDULE_PREFIX) else ''
    return bool(tail) and '/' not in tail


def owns(path: str) -> bool:
    """Whether this route family answers ``path`` — asked before any credential is consulted."""
    return path.startswith(READ_PREFIXES)


def read(store: Store, path: str, query: bytes, actor: Actor, *,
         index_path: Path | str | None = None,
         now: dt.datetime | None = None) -> tuple[int, dict[str, Any]]:
    """Answer one maintenance read, or raise the refusal the transport will render.

    `query` stays raw bytes on purpose: `maintenance.parse_query` is the thing that refuses a repeated or
    unknown parameter, and re-encoding a parsed dict would quietly decide the rules for it.

    `index_path` is passed through rather than resolved here. A service-scoped question can only be
    answered against a built inventory index, and a deployment that has not built one should get the loud
    refusal `maintenance.resolve_scope` already writes, not an empty list dressed up as a plan.
    """
    try:
        _require(actor, READ_ROLES)
        if path == INTERVAL_ROUTE:
            return 200, _intervals(store, query, index_path=index_path, now=now)
        if path == WINDOW_ROUTE:
            return 200, suppression.live_windows(store, now=maintenance.clock(now))
        if path == SCHEDULE_ROUTE:
            return 200, _schedules(store, query, now=now)
        if path.startswith(WINDOW_PREFIX):
            window, sub = _segments(path[len(WINDOW_PREFIX):], WINDOW_SUBROUTES, path)
            history = maintenance.window_history(store, window, now=now)
            if sub is None:
                # The record and its outcome, without the timeline: a duty screen that shows one window
                # does not want to pay for the audit walk, and `outcome` is already the answer to "did
                # this happen as planned".
                return 200, {key: history[key] for key in
                             ('window', 'outcome', 'schedule', 'occurrence_id')}
            return 200, {'window_id': window, 'outcome': history['outcome']['outcome'],
                         'events': history['events'], 'count': len(history['events']),
                         'max_events': maintenance.MAX_EVIDENCE_ROWS}
        if path.startswith(SCHEDULE_PREFIX):
            ident, sub = _segments(path[len(SCHEDULE_PREFIX):], SCHEDULE_SUBROUTES, path)
            if sub is None:
                return 200, maintenance.schedule(store, ident, index_path=index_path, now=now)
            return 200, maintenance.schedule_history(store, ident)
        raise _not_found(path)
    except _LegacyAnswer as refusal:
        return refusal.answer
    except StateError as exc:
        raise _translate(exc) or exc from exc


def write(store: Store, path: str, body: dict[str, Any], actor: Actor, *,
          method: str = 'POST', index_path: Path | str | None = None,
          now: dt.datetime | None = None) -> tuple[int, dict[str, Any]]:
    """Apply one maintenance write and report what *this* request changed.

    No branch answers with a count of other windows: a caller reading a cancellation needs to know what
    the cancellation did, and an answer that also listed the windows it left running would invite the
    inference that an overlapping sibling was part of the deal. It was not — see the acceptance pair.
    """
    try:
        _require(actor, WRITE_ROLES)
        if path == WINDOW_ROUTE:
            _verb(method, path, ('POST',))
            _reject(body, maintenance.WINDOW_REQUEST_KEYS)
            return 200, maintenance.declare_window(store, body, actor, index_path=index_path, now=now)
        if path == SCHEDULE_ROUTE:
            _verb(method, path, ('POST',))
            _reject(body, maintenance.REQUEST_KEYS)
            return 200, maintenance.declare_schedule(store, body, actor, index_path=index_path, now=now)
        if path.startswith(WINDOW_PREFIX):
            window, sub = _segments(path[len(WINDOW_PREFIX):], WINDOW_SUBROUTES, path)
            if sub != 'cancellations':
                raise _not_found(path)
            _verb(method, path, ('POST',))
            # An empty body, deliberately. The durable revoke records who and when and keeps no free-text
            # field, so accepting a `reason` here would mean parsing a promise nobody keeps; the audit row
            # beside it already names the actor and the instant.
            if body:
                raise StateError('A maintenance cancellation takes no body fields')
            return 200, maintenance.cancel_window(store, window, actor, now=now)
        if path.startswith(SCHEDULE_PREFIX):
            ident, sub = _segments(path[len(SCHEDULE_PREFIX):], SCHEDULE_SUBROUTES, path)
            if sub is None:
                _verb(method, path, ('PATCH',))
                # A schedule edit is conditional or it is nothing. Without an expectation a second editor
                # silently replaces the first, and the durable record — which is an append-only version
                # list — would show two active-looking versions with no sign that one overwrote the other.
                # `expected_version` is therefore required, and a mismatch answers 412.
                if 'expected_version' not in body:
                    raise StateError('A maintenance schedule edit names expected_version')
                # `expected_version` is the conditional-write field, not part of the version document: it
                # says which revision the editor read, and is consumed here rather than stored.
                _reject(body, maintenance.REQUEST_KEYS + ('expected_version',))
                document = {key: value for key, value in body.items() if key != 'expected_version'}
                return 200, maintenance.revise_schedule(store, ident, document, actor,
                                                        expected_version=body['expected_version'],
                                                        index_path=index_path, now=now)
            if sub == 'cancellations':
                _verb(method, path, ('POST',))
                if body:
                    raise StateError('A maintenance schedule cancellation takes no body fields')
                return 200, maintenance.cancel_schedule(store, ident, actor, now=now)
            _verb(method, path, ('POST',))
            if body:
                raise StateError('A maintenance materialization takes no body fields')
            return 200, maintenance.materialize_schedule(store, ident, actor,
                                                         index_path=index_path, now=now)
        raise _not_found(path)
    except _LegacyAnswer as refusal:
        return refusal.answer
    except StateError as exc:
        raise _translate(exc) or exc from exc


def _reject(body: dict[str, Any], allowed: tuple[str, ...]) -> None:
    """Refuse a write body that names a field this door does not read.

    An unhandled key is how a contract dies quietly: the caller believes they asked for something — an
    author, a `dry_run`, a class list spelled another way — and the platform did nothing with it, and the
    outage later discovers what the window was never covering. Two refusals: an author claim, which is §5
    (the actor is the credential that signed the request, never a field in the payload), and an unknown
    field. Both are said with the field named, so the caller learns now.
    """
    claimed = sorted(field for field in body if field.lower() in ('author', 'actor', 'declared_by',
                                                                  'identity', 'role'))
    if claimed:
        raise ContractError(400, 'actor_claim_refused',
                            f'{claimed[0]} is refused: the actor is the credential that signed this request')
    extra = sorted(field for field in body if field not in allowed)
    if extra:
        raise ContractError(400, 'invalid_request',
                            'this request accepts ' + ', '.join(allowed) + ' only')


class _LegacyAnswer(Exception):
    """A refusal whose documented body is the transport's legacy `{"error": "..."}` shape.

    The error contract has two bodies: the structured `Error` for a refusal with a code, a message and a
    detail, and the legacy single-word form the transport predates it with. `method_not_allowed` is legacy,
    and the OpenAPI document describes `MethodNotAllowed` as `{"error": "method_not_allowed"}` for every
    route — so this seam raises this exception instead of inventing a second, nearly identical body for the
    same status. `read` and `write` turn it back into the pair of values the transport answers with.
    """

    def __init__(self, status: int, payload: dict[str, Any]) -> None:
        super().__init__(str(payload.get('error')))
        self.answer = (status, payload)


def _require(actor: Actor, roles: tuple[str, ...]) -> None:
    """Gate a route on the credential's role, and answer 403 rather than the state layer's 400.

    `state.require` raises the platform's own sentence, which `api.py` maps to `not_authorised` at 400 —
    the answer every pre-existing route gives. A brand-new route family gets to choose, and the choice
    here is the one an HTTP client can act on: 403 says "a different token would work here", 400 says
    "you sent me something wrong", and only the first is true.
    """
    try:
        require(actor, *roles)
    except StateError as exc:
        raise ContractError(403, 'not_authorised', str(exc)) from exc


def _segments(tail: str, subroutes: tuple[str, ...], path: str) -> tuple[str, str | None]:
    """Return ``(id, subroute)``, refusing an empty id or an unnamed sub-resource.

    The id is not validated here — `state.identifier` does that, in the read, and says why — but the
    *shape* is decided here, so `/v1/maintenance-windows/a/b/c` is a routing miss (404) and never a
    window named `a/b/c`, and never a silent truncation to `a`.
    """
    parts = tail.split('/')
    if not parts[0]:
        raise _not_found(path)
    if len(parts) == 1:
        return parts[0], None
    if len(parts) == 2 and parts[1] in subroutes:
        return parts[0], parts[1]
    raise _not_found(path)


def _intervals(store: Store, query: bytes, *, index_path: Path | str | None,
               now: dt.datetime | None) -> dict[str, Any]:
    """Answer a scope with either a bounded span or the classification of one instant."""
    if not query:
        raise StateError('An interval query names a scope and a span or an instant')
    ask = maintenance.parse_query(query)
    if ask['at'] is not None:
        return maintenance.window_at(store, scope=ask['scope'], at=ask['at'], klass=ask['klass'],
                                     index_path=index_path)
    return maintenance.intervals(store, scope=ask['scope'], span_from=ask['span'][0],
                                 span_to=ask['span'][1], index_path=index_path,
                                 limit=ask['limit'], now=now)


def _schedules(store: Store, query: bytes, *, now: dt.datetime | None) -> dict[str, Any]:
    """List schedules by state, refusing an unknown parameter or a repeated one."""
    try:
        text = query.decode('utf-8')
    except UnicodeDecodeError:
        raise StateError('A schedule query must be UTF-8 text') from None
    parameters = urllib.parse.parse_qs(text)
    if any(len(values) != 1 for values in parameters.values()):
        raise StateError('The schedule state parameter takes one value')
    if set(parameters) - {'state'}:
        raise StateError('Unknown schedule list parameter: '
                         + ','.join(sorted(set(parameters) - {'state'})))
    return maintenance.schedules(store, wanted=parameters.get('state', ['active'])[0], now=now)


def _not_found(path: str) -> ContractError:
    return ContractError(404, 'not_found', f'No such maintenance route: {path}')


def _verb(method: str, path: str, allowed: tuple[str, ...]) -> None:
    """Refuse a verb this route does not carry, naming the verbs it does.

    `PATCH` is the schedule-edit verb and no other route in this transport answers it. An edit has to be
    a distinct verb: a `POST` to the collection mints a second plan instead of appending a version to the
    one the operator is standing on, and `POST .../revisions` would work but leaves the caller to guess
    which id the new version got. `expected_version` in the body is what makes the difference between
    those two answers safe to read.
    """
    if method not in allowed:
        raise _LegacyAnswer(405, {'error': 'method_not_allowed'})


def _translate(exc: StateError) -> ContractError | None:
    """Return the chosen answer for one platform sentence, or None to leave `api.py`'s mapping alone.

    Three sentences are chosen here: a missing row (404), an expectation that stopped being true (412),
    and a collision with state the caller could not see (409). Everything else is left to `api.py`'s
    `stable_code`, because a second translation table would be a second opinion about the same refusal,
    and the one thing a client must not have to reconcile is two statuses for one sentence.
    """
    message = str(exc)
    if message in NOT_FOUND:
        return ContractError(404, 'not_found', message)
    if 'revision does not match' in message:
        # 412 and not 409: the caller named the version they had read, and the server is saying that
        # premise stopped being true. Nothing about the request body is wrong, and a client that retries
        # the same bytes will hear the same sentence until it reads the current version.
        return ContractError(412, 'stale_revision', message)
    lowered = message.lower()
    if any(fragment in lowered for fragment in maintenance.CONFLICT):
        return ContractError(409, 'conflict', message)
    return None


__all__ = ['INTERVAL_ROUTE', 'SCHEDULE_PREFIX', 'SCHEDULE_ROUTE', 'WINDOW_PREFIX', 'WINDOW_ROUTE',
           'edits', 'owns', 'read', 'writes', 'write']

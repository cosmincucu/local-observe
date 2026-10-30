"""The administration route family: what this installation is, who may call it, and the copies it has made.

`platform/api.py` owns the request boundary — credential to actor, body limits, the idempotency claim, the
answer envelope. This module owns the paths that answer "is this installation wired the way I think, who can
reach it, and what did I ask it to do with its own database", and nothing else: it opens no database outside
the `Store` it is handed, mints no identity, and refuses nothing that `administration.py` or `state.py` has
not already refused. The split is the one `maintenance_api.py` documents: the durable rules live where the
CLI, the worker and the tests reach them too, and a route is those same rules seen from one URL.

Twelve paths, twelve operations, and one reason each is here rather than in another family:

* **`/v1/health` and `/v1/boundary`** are the two reads an installer or an agent asks before it does
  anything: *is this thing wired correctly*, and *is the thing I cannot find a decision or a gap*. Neither is
  a record, so neither belongs on `/v1/records/{table}`; neither is a finding, so neither belongs under
  `/v1/alert-occurrences`.
* **`/v1/credentials`** and one write under it are the operator's view of the door. The read is a projection
  of the mounted role list beside the durable revocations; the write adds a revocation and cannot remove one.
* **`/v1/state`**, `/v1/state/backup-plan` and the two job requests are the state lifecycle: read what the
  copy would be, approve that exact digest, get a job id back, and read what became of it.
* **`/v1/jobs`** is the ledger those requests wrote. It is one family rather than a route per kind because
  the answer to "what happened to my request?" must not depend on which kind of request it was.

Three rules hold every route here, and none of them is invented by this file.

* **A write is signed by the credential, never by the body.** `api.py` refuses an identity field in the
  payload before this module is reached, so `approved_by` and `revoked_by` in an answer are always the actor
  the server authenticated. A role check is a 403 here rather than the state layer's 400, because "a different
  token would work here" is the truth and "you sent me something wrong" is not.
* **Nothing secret leaves a credential read.** Token values are used by `api.py` for one constant-time
  comparison and are never carried into an answer, a job row, an audit detail or a log line by this module —
  see the refusal this file raises rather than echoing a value, and `tests/test_api_credentials.py`, which
  asserts the absence rather than trusting the intent.
* **A long job is a booking, not a receipt.** The two requests that start work answer 202 with a job id and
  nothing else, because the copy has not happened yet; the state of the promise is `GET /v1/jobs/{id}`.

What this module is NOT. Not an authorization store: `GET /v1/credentials` reads the mounted list this process
was handed and the deny-list it was told to write, and no route here can add, widen, rename or restore a
grant. Not a file server: no route accepts or returns a path, and the artifact a job writes is named by a rule
the plan publishes, beside the state file, so that a caller who wants the bytes reaches them the way an
operator reaches a file — through the host, not through the transport.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from . import administration, api_contract
from .administration import APPROVAL_FIELD, BACKUP_BODY_KEYS, VERIFICATION_BODY_KEYS
from .api_contract import ContractError
from .state import CREDENTIAL_REVOKED_STATE, Actor, StateError, Store, require

#: The collection routes, spelled exactly as documented: `tests/test_api_openapi_conformance.py` reads these
#: literals out of this file and fails a documented path that no transport names.
HEALTH_ROUTE = '/v1/health'
BOUNDARY_ROUTE = '/v1/boundary'
CREDENTIAL_ROUTE = '/v1/credentials'
STATE_ROUTE = '/v1/state'
BACKUP_PLAN_ROUTE = '/v1/state/backup-plan'
BACKUP_ROUTE = '/v1/state/backups'
VERIFICATION_ROUTE = '/v1/state/verifications'
JOB_ROUTE = '/v1/jobs'

#: Sub-resource prefixes. The trailing slash is what makes each literal match the templated documented path
#: (`/v1/jobs/{job_id}/cancellations`) as well as the collection, which is the direction the coverage check
#: runs; the id after it is judged by `administration`, which refuses a non-canonical id and an unknown one
#: with the same 404.
CREDENTIAL_PREFIX = '/v1/credentials/'
JOB_PREFIX = '/v1/jobs/'

READ_ROUTES = (HEALTH_ROUTE, BOUNDARY_ROUTE, CREDENTIAL_ROUTE, STATE_ROUTE, BACKUP_PLAN_ROUTE, JOB_ROUTE)
READ_PREFIXES = (CREDENTIAL_PREFIX, JOB_PREFIX)
#: The writes the idempotency boundary guards. A retried approval must not book a second copy of the same
#: state, and a retroked revocation must not buy a second audit row — and a retried cancellation, addressed by
#: the id in its own path, must not answer a different question the second time.
WRITE_ROUTES = (BACKUP_ROUTE, VERIFICATION_ROUTE)
WRITE_PREFIXES = (CREDENTIAL_PREFIX, JOB_PREFIX)

#: The two reads any credentialed role may make; the rest of the family is `human` only. `producer` is not
#: here for the reason `maintenance_api` gives: under `api.py` a producer credential is refused by the GET
#: branch's own role test before this gate runs, and the gate is the second line for a caller that uses the
#: module directly.
READ_ROLES = ('reader', 'proposer', 'human', 'executor')
WRITE_ROLES = ('human',)
STATE_ROLES = ('human',)

#: Sub-resources, matched as whole segments, so `/v1/jobs/a/b/c` is a routing miss rather than a job named
#: `a/b/c` and never a silent truncation to `a`.
JOB_SUBROUTES = ('cancellations',)
CREDENTIAL_SUBROUTES = ('revocations',)

#: The status a request that started work answers with, named once: the route, its OpenAPI entry and the
#: tests that assert the body has no receipt in it all read this value.
ACCEPTED = 202

#: Where the volatile numbers live. `GET /v1/health` deliberately does not duplicate them, because two
#: answers to "how many open incidents" is two chances to disagree, and `/v1/runtime` is where a
#: process-local counter already lives.
SEE_ALSO = {'counts': '/v1/status', 'process_counters': '/v1/runtime'}

#: One capability this installation can or cannot serve, and what made it so. `supported` means wired and
#: reachable, `disabled` means this deployment chose not to, `unavailable` means the thing it needs is absent
#: and no choice of this process could add it. Three words, because "off" and "cannot" are different answers
#: to an installer's question and one word would force a guess.
CAPABILITY_STATES = ('supported', 'disabled', 'unavailable')


def owns(path: str) -> bool:
    """Whether this route family answers ``path`` — asked before any credential is consulted."""
    return path in READ_ROUTES or path.startswith(READ_PREFIXES)


def writes(path: str) -> bool:
    """Whether one path is an administration write, and so is owed the idempotency boundary."""
    return path in WRITE_ROUTES or path.startswith(WRITE_PREFIXES)


def read(store: Store, path: str, query: bytes, actor: Actor, *, credentials: list[dict[str, str]],
         seams: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    """Answer one administration read, or raise the refusal the transport will render.

    `query` stays raw bytes on purpose, as `maintenance_api.read` keeps them: `api_contract.page_params`
    judges the bytes a caller actually sent and refuses a repeated or unknown parameter, and re-encoding a
    parsed dict would quietly decide those rules for it.

    `credentials` is the same list `api.py` authenticated this request against — passed in rather than
    re-read, because this module must not be a second place that opens a mounted secret file, and `seams` is
    what this process was handed at startup, which is the only honest source for "is delivery configured".
    """
    try:
        if path in (HEALTH_ROUTE, BOUNDARY_ROUTE):
            _require(actor, READ_ROLES)
            return 200, (_health(store, seams or {}) if path == HEALTH_ROUTE else _boundary())
        _require(actor, STATE_ROLES)
        if path == CREDENTIAL_ROUTE:
            return 200, _credentials(store, credentials)
        if path == STATE_ROUTE:
            return 200, {**administration.state_summary(store), 'see_also': SEE_ALSO}
        if path == BACKUP_PLAN_ROUTE:
            return 200, administration.backup_plan(store)
        if path == JOB_ROUTE:
            return 200, administration.page(store, **api_contract.page_params({'query_string': query}))
        if path.startswith(JOB_PREFIX):
            job_id, sub = _segments(path[len(JOB_PREFIX):], JOB_SUBROUTES, path)
            if sub is not None:
                raise _not_found(path)
            return 200, administration.job(store, job_id)
        if path.startswith(CREDENTIAL_PREFIX):
            identity, sub = _segments(path[len(CREDENTIAL_PREFIX):], CREDENTIAL_SUBROUTES, path)
            if sub is not None:
                raise _not_found(path)
            return 200, _credential(store, credentials, identity)
        raise _not_found(path)
    except StateError as exc:
        # The state layer's own sentences keep `api.py`'s mapping (400 with a stable code): this family has no
        # second opinion about them, and a route that re-labelled a platform refusal would be a second
        # vocabulary for one fact. `_translate` exists for the two sentences that *are* this family's.
        raise _translate(exc) or exc from exc


def write(store: Store, path: str, body: dict[str, Any], actor: Actor, *,
          credentials: list[dict[str, str]],
          now: dt.datetime | None = None) -> tuple[int, dict[str, Any]]:
    """Apply one administration write and report what *this* request booked.

    A request that starts work answers 202 with the job document and no receipt: the copy has not happened,
    and an answer that carried a digest of a file that does not exist yet would be a claim about the future
    wearing the shape of a fact.
    """
    try:
        _require(actor, WRITE_ROLES)
        if path == BACKUP_ROUTE:
            _reject(body, BACKUP_BODY_KEYS)
            return ACCEPTED, administration.request_backup(store, body, actor, now=now)
        if path == VERIFICATION_ROUTE:
            _reject(body, VERIFICATION_BODY_KEYS)
            return ACCEPTED, administration.request_verification(store, body, actor, now=now)
        if path.startswith(JOB_PREFIX):
            job_id, sub = _segments(path[len(JOB_PREFIX):], JOB_SUBROUTES, path)
            if sub != 'cancellations':
                raise _not_found(path)
            # An empty body, deliberately. A cancellation of a booking that has not started withdraws it;
            # there is no decision in it to explain, and accepting a `reason` here would mean parsing a
            # promise nobody keeps. The audit row beside it already names the actor and the instant.
            if body:
                raise ContractError(400, 'invalid_request', 'A job cancellation takes no body fields')
            return 200, administration.cancel(store, job_id, actor, now=now)
        if path.startswith(CREDENTIAL_PREFIX):
            identity, sub = _segments(path[len(CREDENTIAL_PREFIX):], CREDENTIAL_SUBROUTES, path)
            if sub != 'revocations':
                raise _not_found(path)
            _reject(body, frozenset({'reason'}))
            return 200, administration.revoke(store, identity, body.get('reason'), actor,
                                              mounted=[row['identity'] for row in credentials], now=now)
        raise _not_found(path)
    except StateError as exc:
        raise _translate(exc) or exc from exc


# ----------------------------------------------------------------------------------------- the answers


def _health(store: Store, seams: dict[str, Any]) -> dict[str, Any]:
    """Answer what this process can judge from where it stands, and say which of the three it cannot.

    The one judgment here is the schema: ``Store`` refuses to open a file whose version this build does not
    understand, so a served answer always means the file and the code agree. Everything else is reported as
    the configuration fact it is, without a verdict, because "the delivery loop has failed 40 times" is a
    signal and "unhealthy" would be an opinion nobody defined. Two absences are stated rather than left to
    inference: this endpoint cannot see the *other* process (an inventory service, a runner host) and cannot
    know whether the operator's own backup schedule ran — both are named in `not_measured`, because an
    installer who reads `supported` everywhere and has no backup is the failure this file exists to avoid.
    """
    mode = str(seams.get('delivery_mode', 'off'))
    capabilities = {
        'state': {'state': 'supported', 'schema_version': store.status()['schema_version'],
                  'evidence': 'this process holds the store open; a version it cannot read refused to start'},
        'delivery': {'state': ('disabled' if mode == 'off'
                               else 'supported' if seams.get('sender_configured') or mode == 'recording'
                               else 'unavailable'),
                     'evidence': {'mode': mode, 'channels': len(store.channel_policies),
                                  'sender_configured': bool(seams.get('sender_configured'))}},
        'inventory': {'state': 'supported' if seams.get('inventory_index') else 'disabled',
                      'evidence': 'a built index is mounted on this process'
                      if seams.get('inventory_index') else 'no index path was mounted'},
        'verification': {'state': 'supported' if seams.get('verification_policy') else 'disabled',
                         'evidence': 'a reviewed verifier policy is mounted'
                         if seams.get('verification_policy') else 'no policy file was mounted'},
        'runner_handoff': {'state': 'supported' if seams.get('runner_handoff') else 'disabled',
                           'evidence': 'at least one trusted runner is configured'
                           if seams.get('runner_handoff') else 'claims answer directly, no queue'},
        'guided_setup': {'state': 'supported' if seams.get('guided_setup') else 'disabled',
                         'evidence': 'the setup routes are served' if seams.get('guided_setup')
                         else 'the /v1/setup paths answer 404'},
        'observer_review': {'state': 'supported' if seams.get('observer_review') else 'disabled',
                            'evidence': 'an observer journal is mounted' if seams.get('observer_review')
                            else 'the /v1/observer paths answer 404'},
        'state_jobs': {'state': 'supported',
                       'evidence': {'kinds': list(administration.KINDS),
                                    'runner': 'the delivery loop of this process',
                                    'artifact_rule': administration.ARTIFACT_RULE}},
    }
    return {'status': 'serving', 'schema_version': store.status()['schema_version'],
            'capabilities': capabilities, 'not_measured': ['another process on this host',
                                                           'an operator backup schedule outside this service',
                                                           'the reachability of a notification channel'],
            'see_also': SEE_ALSO}


def _boundary() -> dict[str, Any]:
    """Return the declared-boundary document, from the same map the MCP tool answers with.

    One source, two transports: `platform/tools.py` owns `COMPONENT_BOUNDARY` and the shape of the answer, so
    an agent that asked the tool and an agent that asks this route cannot be handed two different lists of
    what this product refuses to do.
    """
    from .tools import boundary_document
    return boundary_document()


def _credentials(store: Store, credentials: list[dict[str, str]]) -> dict[str, Any]:
    """Return who may call this installation, and who it now refuses. Never a token.

    The role list is a projection of the file `api.py` authenticated against, joined to the durable
    revocations; a `revoked` row is one the transport refuses at the door on the next request. The mounted
    file is enrollment and stays read-only here: nothing in this answer implies a route that could add a row
    to it, and `docs/api/COVERAGE.md` records why enrollment is not an HTTP operation.
    """
    ledger = administration.revocations(store)
    by_identity = {row['identity']: row for row in ledger['rows']}
    rows = [{'identity': row['identity'], 'role': row['role'],
             'state': CREDENTIAL_REVOKED_STATE if row['identity'] in by_identity else 'active',
             'revoked_at': by_identity[row['identity']]['revoked_at'] if row['identity'] in by_identity else None,
             'revoked_by': by_identity[row['identity']]['revoked_by'] if row['identity'] in by_identity else None,
             'source': 'mounted role file'} for row in credentials]
    return {'rows': rows, 'count': len(rows), 'revocations': {'count': ledger['count'],
                                                              'limit': ledger['limit'],
                                                              'bound_exceeded': ledger['bound_exceeded']},
            'secrets': 'no token material is returned by any route in this family'}


def _credential(store: Store, credentials: list[dict[str, str]], identity: str) -> dict[str, Any]:
    """Return one identity's answer, refusing to say whether an id this installation never mounted exists.

    `404` for an unmounted identity is not an oracle: the mounted list is the whole population, and the same
    bytes come back for an identity that was never a thing as for a typo of one that is. A revoked identity
    answers 200, because its row is the point of the read.
    """
    answer = _credentials(store, credentials)
    matches = [row for row in answer['rows'] if row['identity'] == identity]
    if not matches:
        raise ContractError(404, 'not_found', administration.IDENTITY_UNKNOWN)
    return matches[0]


# ------------------------------------------------------------------------------------------ the guards


def _reject(body: dict[str, Any], allowed: frozenset[str]) -> None:
    """Refuse a write body that names a field this door does not read.

    An unhandled key is how a contract dies quietly: the caller believes it asked for something — a
    destination path, a `dry_run`, a retention period spelled another way — and the platform did nothing with
    it. Two refusals, both naming the field: an actor claim, which is §5 (the actor is the credential that
    signed the request, never a payload field), and an unknown field. The allowed list is the answer's whole
    vocabulary, so the sentence a caller reads is the sentence the route enforces.
    """
    claimed = sorted(field for field in body if field.lower() in ('actor', 'actor_id', 'identity', 'role',
                                                                  'requested_by', 'approved_by', 'revoked_by'))
    if claimed:
        raise ContractError(400, 'actor_claim_refused',
                            f'{claimed[0]} is refused: the actor is the credential that signed this request')
    extra = sorted(field for field in body if field not in allowed)
    if extra:
        raise ContractError(400, 'invalid_request',
                            'this request accepts ' + ', '.join(sorted(allowed)) + ' only')


def _require(actor: Actor, roles: tuple[str, ...]) -> None:
    """Gate a route on the credential's role, and answer 403 rather than the state layer's 400."""
    try:
        require(actor, *roles)
    except StateError as exc:
        raise ContractError(403, 'not_authorised', str(exc)) from exc


def _segments(tail: str, subroutes: tuple[str, ...], path: str) -> tuple[str, str | None]:
    """Return ``(id, subroute)``, refusing an empty id or an unnamed sub-resource."""
    parts = tail.split('/')
    if not parts[0]:
        raise _not_found(path)
    if len(parts) == 1:
        return parts[0], None
    if len(parts) == 2 and parts[1] in subroutes:
        return parts[0], parts[1]
    raise _not_found(path)


def _not_found(path: str) -> ContractError:
    return ContractError(404, 'not_found', f'No such administration route: {path}')


def _translate(exc: StateError) -> ContractError | None:
    """Return the chosen answer for one platform sentence, or None to leave `api.py`'s mapping alone.

    Two sentences are chosen because they are this family's own, and everything else is left to `api.py`'s
    `stable_code`: a second translation table would be a second opinion about the same refusal, and the one
    thing a client must not have to reconcile is two statuses for one sentence.
    """
    message = str(exc)
    if message in NOT_FOUND_SENTENCES:
        return ContractError(404, 'not_found', message)
    if message in CONFLICT_SENTENCES:
        return ContractError(409, 'conflict', message)
    return None


#: The sentences this family means as "no such row", which is a 404 and not a 400. Matched on fixed wording
#: the way `api.py`'s `stable_code` matches its own: an operator who pasted a plausible id deserves to learn
#: whether the id was unreadable or simply empty of rows.
NOT_FOUND_SENTENCES = frozenset({administration.NO_SUCH_JOB})
#: The sentences that mean "the state you read has moved", which a client can only act on by reading again.
CONFLICT_SENTENCES = frozenset({administration.NOT_VERIFIABLE, administration.RUNNING_IS_NOT_INTERRUPTIBLE,
                                administration.ALREADY_SETTLED, administration.ALREADY_REVOKED,
                                administration.IDENTITY_UNKNOWN})


__all__ = ['BACKUP_PLAN_ROUTE', 'BACKUP_ROUTE', 'BOUNDARY_ROUTE', 'CAPABILITY_STATES', 'CREDENTIAL_PREFIX',
           'CREDENTIAL_ROUTE', 'HEALTH_ROUTE', 'JOB_PREFIX', 'JOB_ROUTE', 'READ_ROLES', 'SEE_ALSO',
           'STATE_ROUTE', 'STATE_ROLES', 'VERIFICATION_ROUTE', 'WRITE_ROLES', 'owns', 'read', 'write',
           'writes']

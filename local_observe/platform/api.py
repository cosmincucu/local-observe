"""Small authenticated JSON surface. Actor identity comes only from server configuration.

Errors are classified at the edge: a refusal the platform raised on purpose (`state.py`,
`policy.py`, the inventory validators, a configured transport) becomes a 400 carrying a stable
machine code plus that fixed sentence, and any exception nobody chose — a `KeyError` from a
handler bug, a corrupt database, a broken driver — becomes a 500 carrying only the exception
class name, with the traceback logged at DEBUG. Request values never reach an error body.
"""
import contextvars
import json
import asyncio
import datetime as dt
import os
from pathlib import Path
import secrets
import threading
from collections.abc import Awaitable, Callable, Mapping
import urllib.parse
from typing import Any

from local_observe.credentials import read_credential
from local_observe.http import TransportError
from local_observe.inventory.validation import InvalidInventory, canonical
from local_observe.log import get_logger
from . import api_contract, dispositions, intake
from .policy import action_policy
from .refusal_dispatch import RefusalAuditDispatcher
from .refusals import SUMMARY_ONLY
from .state import Actor, StateError, Store, clock, identifier, require, validate_event
from .notifications import deliver_one
from .owner import exclusive_owner

log = get_logger(__name__)

# How long the delivery loop waits before its next iteration, clean versus just-failed.
DELIVERY_TICK_SECONDS = 1
DELIVERY_BACKOFF_SECONDS = 5
#: How often a cancelled delivery task re-reads whether its blocking call has really ended, in seconds.
#: A sampling interval, not a deadline: nothing about it bounds how long that call may take, and the
#: serving loop is free the whole time. Not operator-configurable, for the reason `refusals.CAPACITY`
#: gives for the budget next to it.
DELIVERY_COMPLETION_POLL_SECONDS = 0.01

#: The environment value security manifests retired. Its presence means the deployment still hands the role list
#: to the container as an environment value, which `docker inspect` and /proc/<pid>/environ expose.
RETIRED_CREDENTIALS_ENVIRONMENT = 'LO_PLATFORM_CREDENTIALS_JSON'

#: The environment variable that names the *file* the role list is mounted at.
CREDENTIALS_PATH_ENVIRONMENT = 'LO_PLATFORM_CREDENTIALS'

#: The one inbound route a notification channel can reach, with its channel name appended. The
#: single-use approval code travels in the request body — never in this path, and never in a query
#: string, because both get logged by everything between the phone and this process (ledger notifications,
#: `docs/CONTRACTS.md` §5).
CALLBACK_PREFIX = '/v1/callbacks/'

#: The one inbound webhook prefix, with the source name appended: `POST /v1/intake/<source>`. A
#: source's raw envelope (Alertmanager's `{"alerts": [...]}`, and later Gatus/CrowdSec/Healthchecks)
#: is not a canonical event and cannot go to `/v1/events`, so it gets its own path — and the path
#: carries only the source name, never a token, a rule name or anything else that belongs in a body.
#: The role posture is `/v1/events`' unchanged: `summary` is turned away before the body is read and
#: `reader` is refused by the state layer's producer check, so no role that could not post an event
#: before can post one now.
INTAKE_PREFIX = '/v1/intake/'

#: The alert-occurrence surface (`docs/api/occurrences.md`): one episode of one condition, read three ways
#: and written two. The prefix is one constant because five routes share it, and a literal spelled five ways is
#: five chances for `openapi.yaml`, the census and this dispatcher to disagree about an address. An occurrence
#: id **is** an incident id — the episode identity `Store.intake` already mints — and nothing below accepts a
#: second name for it.
OCCURRENCE_PREFIX = '/v1/alert-occurrences'
#: The same family one level down, spelled as its own literal rather than computed from the constant above.
#: `tests/test_api_openapi_conformance.py` proves a documented templated path is served by matching it
#: against a literal the transport names (`match()` reads the source, not the running dispatcher), and
#: `OCCURRENCE_PREFIX + '/'` is an expression: true at runtime, invisible to the census, and the three
#: `{id}` routes would read as documented-but-unreachable. `INTAKE_PREFIX` and `CALLBACK_PREFIX` are the
#: two precedents for naming the trailing-slash form directly.
OCCURRENCE_CHILD_PREFIX = '/v1/alert-occurrences/'
#: The two dispositions a caller may post, and the command each names. A path segment and not a body field,
#: because the two write different durable facts (a dismissal tombstones, an acknowledgement does not) and a
#: caller must be able to tell which one they called from the URL they sent.
OCCURRENCE_COMMANDS = {'acknowledgements': 'acknowledge', 'dismissals': 'dismiss'}
#: The whole body a disposition write may carry. `reason` is required; `expected_revision` is the
#: conditional-write opt-in `api_contract.expected_revision` reads when no `If-Match` arrived. Anything else is
#: refused rather than ignored — `docs/api/COVERAGE.md` records the 404-instead-of-400 fall-through this
#: product already dislikes, and a new route must not widen it. An identity field is refused further upstream
#: by `api_contract.assert_no_actor_claim`, which every disposition write opts into.
OCCURRENCE_BODY_KEYS = frozenset({'reason', 'expected_revision'})
#: The sentence one path under the prefix gets when it names neither an episode nor its history. Named here
#: because `occurrence_target` raises it before the dispatcher reaches the module that owns the rest of the
#: vocabulary, and a refusal that exists only at its raise site cannot be pinned by a test.
OCCURRENCE_SHAPE_REFUSAL = 'This path names no occurrence and no occurrence history'


def occurrence_write(path: str) -> tuple[str, str] | None:
    """Return the ``(command, occurrence id)`` one POST path names, or None when it names neither.

    The id is validated by `dispositions`, not here: this function decides only *which command* a path is, so a
    malformed id keeps travelling to the one place that knows the difference between "not this route" and "no
    such occurrence" — and that place answers both with the same 404, so no caller learns which of the two the
    store holds.
    """
    if not path.startswith(OCCURRENCE_CHILD_PREFIX):
        return None
    segments = path.removeprefix(OCCURRENCE_CHILD_PREFIX).split('/')
    if len(segments) != 2 or not segments[0] or segments[1] not in OCCURRENCE_COMMANDS:
        return None
    return OCCURRENCE_COMMANDS[segments[1]], segments[0]


def occurrence_target(path: str) -> tuple[str, bool]:
    """Return the occurrence id one GET path names, and whether its history was asked for.

    Two shapes exist under the prefix — an episode and its history — and a third is a refusal rather than a
    best-effort guess, for the reason every other unrecognised path here gets a 404: an unexpected segment must
    not silently read something the caller did not ask for.

    An empty id is not refused as a shape problem. It is the same question as an id that names no episode
    (`/v1/alert-occurrences//history` has always reached `dispositions` and answered 404 there), and
    `docs/api/occurrences.md` §7 makes that answer deliberately identical so the route is not an oracle for
    id shape — a path with no id in it names no occurrence either.

    Raises:
        api_contract.ContractError: 404 `not_found` when the path carries no id, 400 `invalid_request` for a
            trailing segment that is not `history`. Both in the machine envelope, because this whole route
            family has spoken the envelope since its first answer; a StateError here would have been answered
            in the flat shape the routes that predate the boundary use, which is two error shapes behind one
            address.
    """
    remainder = path.removeprefix(OCCURRENCE_CHILD_PREFIX).strip('/')
    segments = remainder.split('/') if remainder else ['']
    if len(segments) > 2 or (len(segments) == 2 and segments[1] != 'history'):
        raise api_contract.ContractError(400, 'invalid_request', OCCURRENCE_SHAPE_REFUSAL)
    if not segments[0]:
        raise api_contract.ContractError(404, 'not_found', dispositions.UNKNOWN_OCCURRENCE)
    return segments[0], len(segments) == 2

#: The four write routes a `summary` credential is turned away from *before* any `Store` method is
#: entered . The path names the attempt word the durable refusal row carries, and nothing
#: else: no route string, body or token is written. This is the only refusal the transport audits —
#: every other answer here either reaches a `Store` method (which owns the row, and auditing it again
#: here would double-count one refusal) or is rejected by the parser, size or shape gates, or is
#: unauthenticated or on an unknown route, and those stay write-free so an unauthenticated request can
#: never become a database writer. "Write-free" belongs to those gates alone: the `summary` role gate
#: runs *before* the body is read, so a summary credential posting malformed or oversized bytes gets
#: the same audited 403 as one posting valid JSON — the row is audited without body inspection, which
#: is why no branch here parses a body to decide whether the summary audit happens.
REFUSAL_POST_ROUTES = {'/v1/actions': 'propose', '/v1/actions/decision': 'decide',
                       '/v1/actions/claim': 'claim', '/v1/executions/outcome': 'outcome'}

#: The POST routes that honour `Idempotency-Key` (api boundary foundation). Membership is the whole
#: opt-in: a route not named here ignores the header, which is what keeps every client that exists today
#: answering exactly as it always did — no client sends the header yet.
#:
#: The list is a judgement about *which writes a lost response makes dangerous*, not a general
#: allowance. In: event and evidence filing, a claim, a delivery retry, a safety reset, an execution
#: outcome, and the intake front door — each of them performs state the caller cannot re-derive, and a
#: client that lost the answer cannot tell "never ran" from "ran and I never heard".
#:
#: Out, with the reason for each, because a missing entry here reads as an oversight:
#: * `/v1/actions` already has a durable retry identity of its own — `actions UNIQUE(requester,
#:   retry_key)` — and a second key in front of it would make "which name deduplicates this proposal?"
#:   a question with two answers.
#: * `/v1/actions/decision`, `/v1/actions/execute` and the writes under `/v1/setup/` bind their own
#:   receipt (`runner_requests` is keyed by action, and a setup plan carries its own status), so replaying
#:   an answer would be a second opinion on a decision whose authority is the row.
#: * `/v1/callbacks/<channel>` is single-use by contract: a stored success replayed after the token was
#:   spent would report an intent that this route is defined to refuse.
#: * The verification and observer-review seams own their own body parsing, size gates and replay rules
#:   (`verification_api` refuses a changed re-post, `observer_review` refuses a re-graded cycle), so a
#:   gate in front of them would be a second copy of a rule that already exists and is already tested.
#: * The pre-existing acknowledgement surfaces (`/v1/actions/decision`, `/v1/callbacks/<channel>`) bind a
#:   decision or an intent of their own and stay out for the reasons above; they are not dispositions, and
#:   `docs/api/occurrences.md` §6 says what the difference is.
IDEMPOTENT_POST_ROUTES = frozenset({'/v1/events', '/v1/evidence', '/v1/actions/claim',
                                    '/v1/notifications/retry', '/v1/notifications/reset-safety',
                                    '/v1/executions/outcome', '/v1/runner/claim'})


def idempotency_enabled(path: str) -> bool:
    """Whether one write route honours `Idempotency-Key`, as the lists above and the two seams decided.

    The disposition writes are in **by shape** (`occurrence_write`, the same test the dispatcher routes
    by) and the maintenance family through `maintenance_api.writes`, matched by prefix, because both
    families address their writes with an identifier that is caller data, which a list of exact paths
    cannot name. A GET under those prefixes also reads as guarded, and never claims a key, because the
    claim lives in the write branch.
    """
    from . import maintenance_api  # the seam owns its prefixes; see the import note in `create_app`
    return (path in IDEMPOTENT_POST_ROUTES or path.startswith(INTAKE_PREFIX)
            or occurrence_write(path) is not None or maintenance_api.writes(path))


def _retrieve_execution(future: Any) -> None:
    """Read one delivery execution future's outcome so asyncio cannot log it as never-retrieved.

    Private for the same reason `refusal_dispatch._settle` is: it belongs to the scheduling, not to the
    product surface. Nothing awaits or cancels that future — it is deliberately the handle nobody may pull
    a running call out by — so this is the only reading it ever gets, and it is not a completion signal
    either: the completion signal is the event the callable's own thread sets. `exception()` raises on an
    item an executor dropped from a queue it shut down, hence the check.
    """
    if not future.cancelled():
        future.exception()


def refuse_retired_credentials_environment(environ: Mapping[str, str] = os.environ) -> None:
    """Refuse to start when role credentials are offered as an environment value.

    The role list arrives only as the file named by ``LO_PLATFORM_CREDENTIALS`` (card security manifests): the
    component manifest (security manifests), the packaging gate (secret files) and the staging drivers (scripts
    leftovers) all reject
    the environment form, and a product branch that preferred it would be the one place a leaked
    environment value still beat the mounted file. It is therefore a refusal, never a fallback.

    Only the key is named in the message; the value is never read, logged or echoed.

    Args:
        environ: The environment to inspect; defaults to this process's.

    Raises:
        ValueError: ``LO_PLATFORM_CREDENTIALS_JSON`` is present, whatever else is configured.
    """
    if RETIRED_CREDENTIALS_ENVIRONMENT in environ:
        raise ValueError(f'{RETIRED_CREDENTIALS_ENVIRONMENT} is retired: mount the role list and '
                         f'name its path in {CREDENTIALS_PATH_ENVIRONMENT}')


def role_credentials(environ: Mapping[str, str] = os.environ) -> list[dict]:
    """Return the platform's role rows from the mounted file, never from the environment.

    Args:
        environ: The environment to read the path from; defaults to this process's.

    Returns:
        The ``{identity, role, token}`` rows the service was started with.

    Raises:
        ValueError: The retired environment value is present (see
            :func:`refuse_retired_credentials_environment`).
        KeyError: ``LO_PLATFORM_CREDENTIALS`` names nothing.
        OSError: The named path is not a readable file.
    """
    refuse_retired_credentials_environment(environ)
    return json.loads(Path(environ[CREDENTIALS_PATH_ENVIRONMENT]).read_text())


# Fixed sentences in state.py/policy.py describing an identity or token that is not permitted.
NOT_AUTHORISED_MESSAGES = frozenset({'actor is not authorised', 'runner identity/token mismatch',
                                     'source identity differs'})

# Fixed sentences describing a collision with state the caller could not see, not a bad body.
CONFLICT_MESSAGES = frozenset({
    'retry changed contents', 'changed its contents', 'conflicting', 'already terminal',
    'is not pending', 'is not available for dispatch', 'claim is no longer valid',
    'cannot be replayed', 'can be manually retried', 'reconcile outstanding claims',
    'live activation refused', 'requires an open incident', 'incident recovered',
    'requires unknown outcome',
    # Notification callbacks (ledger notifications): a token that is genuine but spent, stale, or pointing at an
    # action this delivery could not have been about. All three are facts about state the caller cannot
    # see from here, which is the definition of a conflict rather than of a malformed request.
    'already been consumed', 'callback has expired', 'not part of the notified incident',
})


def stable_code(message: str) -> str:
    """Return the machine-readable code for a sentence the platform raised about itself.

    Matching is on the fixed wording used in `state.py`/`policy.py`, lower-cased substring, so
    those sentences stay readable where they are raised and are not pinned line by line here.
    Anything unrecognised is `invalid_request`, the honest default for a rejected request.
    """
    text = message.lower()
    if any(marker in text for marker in NOT_AUTHORISED_MESSAGES):
        return 'not_authorised'
    if any(marker in text for marker in CONFLICT_MESSAGES):
        return 'conflict'
    return 'invalid_request'


def query_params(scope: dict) -> dict[str, list[str]]:
    """Parse the request query string; undecodable bytes are replaced, never echoed back."""
    return urllib.parse.parse_qs(scope.get('query_string', b'').decode('utf-8', 'replace'))


def intake_target(path: str, identity: str) -> str:
    """The source one `/v1/intake/<source>` path names, checked against the identity that posted it.

    The check is not decoration. `Store.intake` refuses an event whose `source` differs from the
    authenticated producer, so a path could not smuggle another source's events into the store — but
    it could reach `intake.prepare`, which opens the inventory index and evaluates that source's
    rules. Requiring the path to name the caller's own identity is what makes `"which source posted
    this?"` one answer for the route, the normaliser and the stored row, and it is why the refusal
    reuses `state.py`'s fixed sentence: the client then gets `not_authorised`, the same code the state
    layer would have given, and no new error word appears.

    Raises:
        StateError: The path carries no source segment or more than one, or it names a source other
            than this credential's identity.
    """
    source = path.removeprefix(INTAKE_PREFIX).strip('/')
    if not source or '/' in source:
        raise StateError('Intake path must name exactly one source')
    if source != identity:
        raise StateError('Source identity differs from authenticated producer')
    return source


def sender_configured(client: Any) -> bool:
    """Return whether this process can send at all, for one client or for a whole channel mapping.

    A lone client object answers as it always did. The multi-channel form (schema v3) is a mapping, and
    an empty one configures nothing: reporting it as a sender would be the `sender_configured: true`
    answer that api errors exists to make trustworthy.
    """
    if client is None:
        return False
    return bool(client) if isinstance(client, Mapping) else True


def validate_credentials(credentials: list[dict[str, str]]) -> None:
    """Refuse a role list this process must not serve, in the words `create_app` has always used.

    Moved out of `create_app`'s first lines verbatim, not rewritten: the same two sentences, the same
    uniqueness/length/role tests and the same six roles. Token values are used for uniqueness and
    length checks, never logged. The reason it is a function is one ordering fact: `app_factory` must
    reject unusable credentials *before* it opens (or creates) the state file, so a
    deployment whose role list is short, duplicated or role-sick no longer leaves a half-booted database
    behind on the way out. `create_app` still calls it first, so a caller that builds an app directly is
    validated exactly as it always was — the check is in both entry points, and neither one is a copy of
    the other's rules.

    Args:
        credentials: The `{identity, role, token}` rows as mounted, never re-read from disk here.

    Raises:
        ValueError: The list is empty or repeats a token, or a token is shorter than 24 characters or
            names a role outside the six this transport authenticates. Never a message carrying a value.
    """
    if not credentials or len({item['token'] for item in credentials}) != len(credentials):
        raise ValueError('Missing or duplicate platform credentials')
    if any(len(item['token']) < 24 or
           item['role'] not in ('reader', 'producer', 'proposer', 'human', 'executor', 'summary')
           for item in credentials):
        raise ValueError('Invalid platform credential configuration')


def create_app(store: Store, credentials: list[dict[str, str]],
               policy: Callable[[dict[str, Any]], None], notification_client: Any | None = None,
               index_path: Path | str | None = None, display_config: dict[str, Any] | None = None,
               overview_path: Path | str | None = None,
               intake_rules: Mapping[str, Any] | None = None, *,
               runner_handoff: Any | None = None,
               guided_setup: Any | None = None,
               observer_review: Path | str | None = None) -> Callable[..., Awaitable[None]]:
    validate_credentials(credentials)
    runner_ids = set(runner_handoff.runners) if runner_handoff is not None else set()
    if guided_setup is not None:
        runner_ids.add(guided_setup.runner)
    for identity in runner_ids:
        rows = [row for row in credentials if row['identity'] == identity]
        if len(rows) != 1 or rows[0]['role'] != 'executor':
            raise ValueError('A trusted runner requires its own executor credential')
    from .runtime import observe_startup
    mode = store.notification_policy.delivery_mode
    if mode == 'off':
        notification_client = None
    elif mode == 'recording':
        from .notification_safety import RecordingSink
        notification_client = RecordingSink()
    runtime = observe_startup(mode, sender_configured(notification_client))
    # observe_startup takes one immutable snapshot of the filesystem; the delivery loop publishes
    # its own health into this small mutable dict, which GET /v1/runtime merges over the snapshot.
    # Only the serving event loop writes it, so the two keys need no lock.
    runtime_state: dict[str, object] = {'delivery_loop_failures': 0, 'delivery_loop_last_failure_at': None}

    # The asynchronous audit writer: the one place this transport writes to the database on its own account runs off the
    # serving loop, behind a dispatcher that owns no thread until a request needs one and no slot to
    # queue in. One per `create_app` instance, and nothing is shared between instances: two apps over
    # one `Store` have two slots and two tallies (`scope: 'app-local'`). Construction takes no loop, so
    # an app that is built and never served — or served only through direct ASGI calls, with or without
    # a lifespan — costs nothing and leaks nothing.
    refusal_dispatch = RefusalAuditDispatcher()

    # The idempotency boundary: one gate per `create_app`, over the same `Store` this app already writes
    # through. It owns no thread, no queue and no in-process memory — every read and write is a `Store`
    # call against the `api_idempotency` table (schema v11), so a key this process reserved is still
    # reserved after a restart, which is the whole reason the record is durable rather than a dict. The
    # gate holds rules, not rows: `state.py` stays the only SQL writer.
    idempotency = api_contract.IdempotencyGate(store)

    # The verification workflow: the verification routes are their own module and their own admission slot, and this is
    # the only place either is built. One `VerificationAPI` per `create_app`, over the same `Store` this
    # app already writes through and nothing else — the bearer text stays here (so the actor it answers
    # about is still decided by `secrets.compare_digest` alone), it reads no policy or other environment
    # value, and it takes no thread until a request needs one. Imported here rather than at module scope
    # for the same reason `runtime` and `audit_reader` are: a sibling transport module would otherwise
    # join the package's import graph at service start, and nothing may be able to fail an `api` import
    # on its account. Its path census is the module's own `owns`, so no prefix in this file decides.
    from . import verification_api as verification_service
    verification = verification_service.VerificationAPI(store)
    # The maintenance route family: ten paths and thirteen operations over `maintenance.py` and
    # `suppression.py`. Imported here for the reason `verification_api`, `runtime` and `audit_reader` are — a
    # sibling transport must not be
    # able to fail an `api` import on its own account — and its path census is the module's `owns`, so no
    # prefix in this file decides which routes exist. What stays here is the boundary: this app's `Store`,
    # this app's index path, and the actor the credential named, handed over after the body was read and
    # claimed, so a replayed declaration never reaches the state layer twice.
    from . import maintenance_api as maintenance_routes

    # The optional observer review seam: three routes over the observer's own private journal, built only
    # when this installation names one (`observer_review.py` owns the rules, the bounds and the refusals).
    # `None` is the off switch and costs nothing — no import, no path touched, and the three paths keep
    # their old `404 not_found`. A named directory with no journal is a boot refusal raised here rather
    # than a review surface that opens an empty database, so a caller that builds an app directly is
    # refused exactly as a deployment that set the environment variable is.
    review_api = None
    if observer_review is not None:
        from .observer_review import ObserverReview
        review_api = ObserverReview(observer_review)

    def note_delivery_failure() -> int:
        """Count one failed delivery-loop iteration, stamp when it happened, return the tally."""
        runtime_state['delivery_loop_failures'] = runtime_state['delivery_loop_failures'] + 1
        runtime_state['delivery_loop_last_failure_at'] = dt.datetime.now(dt.timezone.utc).isoformat()
        return int(runtime_state['delivery_loop_failures'])

    def admit_intake(source: str, payload: dict[str, Any], actor: Actor) -> dict[str, Any]:
        """Normalise one source envelope and admit it, evidence first, as `store` requires.

        Two passes over the prepared events, and the split is the whole design: `state.validate_event`
        judges **every** event before anything is written, so a malformed envelope costs nothing and
        one unreadable alert cannot leave nine of its siblings committed behind a 400. After that the
        events go in payload order — each `put_evidence` immediately before the event that cites it,
        which is the order `detection_worker.tick` already uses over HTTP — and a state conflict at
        that point (`Event retry changed contents`, two transitions of one condition agreeing on one
        watermark) is a fact about rows that really arrived, not a shape error, so the earlier rows
        stay. Nothing is rolled back from a transport, and nothing is truncated to make an envelope fit.

        The answer names the source and one entry per event, each carrying the event/incident ids,
        `Store`'s status (`accepted`/`duplicate`) and the `resource_link` verdict. That last field is
        why this route has a response body of its own: an unresolved event is admissible, so
        "the instance named here matched no declaration" has to be said somewhere, and the canonical
        event must not gain a field for it (`docs/CONTRACTS.md` §4).

        The two writes are not one transaction, and neither needs to be: an evidence row committed
        before its event died is re-named by the retry (same identity, same contents, `INSERT OR
        IGNORE`) and expires on its own, while the event is simply absent until the sender repeats. The
        reverse order would be the dangerous one — an event whose sample was never stored is a dead
        link, and §4 says a dead link is not proof.
        """
        now = clock()
        prepared = intake.prepare(source, payload, now=now, index_path=index_path, rules=intake_rules)
        for item in prepared:
            validate_event(item.event, now)
        results = []
        for item in prepared:
            if item.sample is not None:
                store.put_evidence(item.sample, actor, now=now)
            # correlation: the grouping callback is built per event because it carries this request's actor and
            # instant, and `index_path` is the only graph it knows. With no index configured the factory
            # answers None and intake behaves exactly as it did before this line existed.
            results.append({**store.intake(item.event, actor, now=now,
                                          admission=store.grouping_admission(index_path, actor, now=now)),
                            'resource_link': item.link})
        return {'source': source, 'events': results}

    async def audit_summary_refusal(attempt: str, refused: Actor) -> None:
        """Audit one `summary`-role write denial off the loop, and wait for the attempt this request owns.

        The awaited work is exactly one `Store.record_refusal` call, closed over nothing but the fixed
        attempt word from `REFUSAL_POST_ROUTES`, the `Actor` this process authenticated from a bearer
        credential, and the fixed `summary-only` reason: no body, token, path, subject or exception text
        is handed over or retained (`Store` remains the only SQL writer and the only budget owner).

        Three answers, and the caller cannot tell them apart, which is the point:

        * **admitted** — this request awaits its own callable to completion before the 403 goes out, so
          a response that completed has its one audit *attempt* behind it. What that attempt produced is
          `Store`'s business: a row, or a counted `dropped`/`failed`/`unauditable` with no row. The write
          runs on an executor thread, so this one write cannot hold the loop while somebody else holds
          the database lock; routes that do their own synchronous database work on the loop are unchanged
          and can still block it .
        * **shed** — the single slot was busy (or this app is closing), so nothing ran, no token of the
          `Store`'s 64/+1s bucket was spent, `overloaded` moved, and the 403 is sent immediately.
          A concurrent flood therefore loses rows; a 403 is never proof of a durable record.
        * **failed** — a dispatcher fault is counted and logged once an interval by class only. It never
          reaches this handler: the status, the body and the early exit are the ones this route always
          had.

        Cancellation of the request while its callable is in flight unwinds this `await` and changes
        neither the write nor the slot: only the callable's own thread releases capacity.
        """
        job = refusal_dispatch.submit(lambda: store.record_refusal(attempt, refused, SUMMARY_ONLY))
        if job is None:
            return
        await refusal_dispatch.wait(job)

    async def app(scope, receive, send):
        if scope['type'] == 'lifespan':
            ownership = None
            worker: asyncio.Task | None = None
            stop = asyncio.Event()
            cleanup_task: asyncio.Task | None = None
            def release_ownership() -> None:
                """Let go of the exclusive owner lock, once, and only when nothing of ours is left running.

                There is no thread to join here: taking an `flock`/byte-range record back is a syscall
                this loop may make directly, and it is the last thing this process does with the file.
                `ownership` is named only after `__enter__` actually took the lock, so a boot that failed
                on the lock itself cannot unlock a file this process never held.
                """
                nonlocal ownership
                if ownership is None:
                    return
                held, ownership = ownership, None
                held.__exit__(None, None, None)

            async def delivery_loop():
                # The asynchronous audit writer: a cancelled delivery call may not end this task. `asyncio.to_thread`
                # cannot
                # carry these two calls: cancelling the task unwinds that `await` as soon as the executor
                # refuses to cancel an item that already started, so the task reports itself finished while
                # its thread is still inside SQLite — and `drain` below awaits this task as the proof that
                # nothing of ours is left running, so it would hand the state file to the next owner around
                # a live write. What the waits here watch is the callable, not the future that scheduled it,
                # which keeps this task's completion a fact about its calls. A cancellation this loop
                # survives is remembered rather than raised where it arrived: the task ends cancelled as soon
                # as the in-flight call has really ended, and starts no further call.
                pending_cancellation = False

                async def run_to_completion(call: Callable[[], Any]) -> None:
                    """Run one blocking delivery call on an executor thread and return only once it ended.

                    The execution future is never awaited, never shielded and never cancelled, because
                    `await future` is exactly the path along which `Task.cancel()` reaches the item. The end
                    is read instead from an event the callable's own thread sets in a `finally`, polled with
                    cooperative yields; a `CancelledError` landing while the call is in flight sets
                    `pending_cancellation` and the wait goes on, so repeated cancellations change nothing.
                    A future that is itself cancelled is treated the same way, never as proof the callable
                    was dropped before it ran. Then both facts are kept, in this order:

                    * the call's own exception travels first, so the loop below counts it, logs its class
                      and backs off exactly as it always did;
                    * a remembered cancellation is raised next — after that accounting, and instead of the
                      next call or another iteration.

                    A call that both failed and was cancelled is therefore counted *and* ends the task
                    cancelled. Nothing here times out: the wait is as long as the call is.
                    """
                    nonlocal pending_cancellation
                    loop = asyncio.get_running_loop()
                    ended = threading.Event()
                    fault: list[BaseException] = []

                    def invoke() -> None:
                        try:
                            call()
                        except BaseException as exc:  # carried to the loop, which owns the accounting
                            fault.append(exc)
                        finally:
                            ended.set()

                    # This loop's own default executor — the one `to_thread` used, so no extra thread, pool
                    # or queue appears here — and at most one item from this loop is ever outstanding. The
                    # context is copied the way `to_thread` copied it, so a call reading a context variable
                    # still sees the one it was served with.
                    submitted = loop.run_in_executor(None, contextvars.copy_context().run, invoke)
                    submitted.add_done_callback(_retrieve_execution)
                    while not ended.is_set():
                        # Only a *non-cancelled* execution future reaching its end says the callable is no
                        # longer running. A cancelled one says the item is no longer wanted, which is true
                        # of a queued item nobody picked up and of a call mid-flight on its thread alike,
                        # so cancellation is never read as "dropped" and this wait goes on. The event is
                        # re-read beside the future because the thread can set it, or the future resolve,
                        # between the `while` test and this one. A finished future with no event is the
                        # one case where the callable never reached a thread — an executor shut down around
                        # its queue looks like that. It is booked as a failed iteration, the loop's own
                        # accounting, because waiting on a thread that does not exist would make this wait,
                        # and this shutdown, unbounded.
                        if submitted.done() and not submitted.cancelled() and not ended.is_set():
                            raise RuntimeError('Delivery call never reached an executor thread')
                        try:
                            await asyncio.sleep(DELIVERY_COMPLETION_POLL_SECONDS)
                        except asyncio.CancelledError:
                            # A lost turn, not a finished call: keep waiting for the thread, and remember
                            # that this task is owed its cancellation.
                            pending_cancellation = True
                    if fault:
                        raise fault[0]
                    if pending_cancellation:
                        raise asyncio.CancelledError()

                while not stop.is_set():
                    failed = False
                    try:
                        await run_to_completion(store.expire_actions)
                        if notification_client is not None:
                            await run_to_completion(lambda: deliver_one(store, notification_client))
                    except Exception as exc:
                        # Failed transport/state remains in the outbox; never invent acknowledgement.
                        # The loop survives, but a swallowed failure is a silent one: count it, say
                        # which class raised, and let /v1/runtime show the tally.
                        failed = True
                        failures = note_delivery_failure()
                        log.warning('Delivery loop iteration failed',
                                    extra={'error_class': type(exc).__name__, 'delivery_loop_failures': failures})
                        log.debug('Delivery loop iteration details', exc_info=True)
                    if pending_cancellation:
                        # Reached only when a call faulted *and* was cancelled: the failure is accounted
                        # above, so the cancellation is what this task answers with — no backoff sleep, no
                        # second call, no next iteration.
                        raise asyncio.CancelledError()
                    try:
                        await asyncio.wait_for(stop.wait(),
                                               timeout=DELIVERY_BACKOFF_SECONDS if failed else DELIVERY_TICK_SECONDS)
                    except TimeoutError:
                        pass

            async def drain() -> tuple[bool, list[BaseException]]:
                """Wait for the real end of the work this lifespan owns, then hand the file back.

                The asynchronous audit writer, and this order is the whole point: the one callable that holds the
                audit slot
                finishes its `INSERT` (or fails and is counted), the verification service's own one
                callable has left the `Store`, and the delivery loop has left its last blocking call, and
                only then does this process drop the owner lock. A shutdown that
                released ownership around a write still in flight would hand the file to the next owner
                with a refusal row mid-transaction. No deadline substitutes for that wait: SQLite's
                `busy_timeout` bounds the driver's own retry loop, not an fsync or a thread, so a fixed
                number here would be a durability claim nobody measured. Both waits are `await`s, never a
                thread join, so the loop keeps serving while this runs.

                It answers two questions rather than raising, because a cleanup that *failed* must not be
                reported as a completed shutdown: `interrupted` says a wait ended in a cancellation — which
                says this drain did not see the work end, not that the work is still running — and `faults`
                are the exceptions owned work actually raised, logged by class and handed back so the caller
                can propagate them. The owner lock goes back in every case, including when the release
                itself is what faulted (a lock suppressed forever is the other failure mode, and no
                caller is left to hand it back), and it goes back exactly once, because
                `release_ownership` clears the name before it calls.

                The delivery loop is awaited, not cancelled, and shielded while it is awaited. Its being
                done is the proof this drain needs, whether it ended by returning or by cancellation: both
                blocking calls it makes go through `run_to_completion`, which will not let that task finish
                while either is still on its executor thread. No release of ownership here can outrun a live
                delivery call. A worker that somebody else's teardown cancelled is still reported as an
                interruption and `shutdown.complete` is still withheld from it: a shutdown cut short is not
                one that finished, even though handing the file back is sound.
                """
                # The verification service's slot is drained beside the audit slot, in the same gather and
                # for the same reason: its Store callable may still be inside SQLite, and handing the owner
                # lock back around a live write is the one thing this wait exists to prevent.
                waits: list[Any] = [refusal_dispatch.wait_idle(), verification.wait_idle()]
                if worker is not None:
                    # `shield`, because a cancelled gather cancels every child it is still waiting on,
                    # and the delivery task is not this drain's to cancel.
                    waits.append(asyncio.shield(worker))
                interrupted = False
                faults: list[BaseException] = []
                for ended in await asyncio.gather(*waits, return_exceptions=True):
                    if not isinstance(ended, BaseException):
                        continue
                    if isinstance(ended, asyncio.CancelledError):
                        interrupted = True
                        continue
                    faults.append(ended)
                    log.warning('Lifespan cleanup failed', extra={'error_class': type(ended).__name__})
                release_ownership()
                return interrupted, faults

            async def cleanup() -> tuple[bool, list[BaseException]]:
                """Run `drain` to the end; return whether we were interrupted and everything that faulted.

                Admission closes and the delivery loop is told to stop synchronously, here, before any
                await. The drain is one task of ours, created once, and re-awaited through a fresh
                `asyncio.shield` for every incoming `asyncio.CancelledError`: a server that gives up on
                the lifespan (its own shutdown deadline, a process teardown) may stop *waiting* for this,
                but it may not make this stop waiting for the write it admitted.

                Nothing is swallowed on the way out. An earlier draft logged a failed wait and walked on
                to `shutdown.complete`, which is a completion claim about work this process had not seen
                end; both the interruption and the fault now travel to the one caller that knows whether
                the server ever asked for a normal shutdown.
                """
                nonlocal cleanup_task
                refusal_dispatch.close()
                # Verification admission closes in the same synchronous breath: no *new* Store callable may
                # be claimed once shutdown has begun, and the one already running is waited for by `drain`
                # rather than cancelled (its work is the platform's write, not this lifespan's to abort).
                verification.close()
                stop.set()
                if cleanup_task is None:
                    cleanup_task = asyncio.ensure_future(drain())
                interrupted = False
                while True:
                    try:
                        drained, faults = await asyncio.shield(cleanup_task)
                        # Our own interruptions count even when a later shield finally came back clean:
                        # a shutdown that was cut short and then finished is still one that was cut short.
                        return interrupted or drained, faults
                    except asyncio.CancelledError:
                        interrupted = True
                        if cleanup_task.cancelled():
                            # A drain that was itself cancelled — a teardown sweeping every pending task,
                            # since nothing of ours cancels this one — cannot be awaited again, and
                            # re-awaiting its corpse would spin here forever. Own a fresh one: `drain`
                            # re-reads the slot and the worker, so nothing already finished is redone.
                            cleanup_task = asyncio.ensure_future(drain())
                    except Exception as exc:
                        # `drain` reports the outcomes of its own waits rather than raising them, so the
                        # only thing that can raise through here is the owner release. Named like any
                        # other fault: the lock going back is not a drain that finished.
                        log.warning('Lifespan cleanup failed',
                                    extra={'error_class': type(exc).__name__})
                        return interrupted, [exc]

            error: BaseException | None = None
            outcome: BaseException | None = None
            normal_shutdown = False
            try:
                while True:
                    message = await receive()
                    if message['type'] == 'lifespan.startup':
                        holder = exclusive_owner(store.path)
                        holder.__enter__()
                        # Only now is this process the owner, and only now may cleanup unlock it.
                        ownership = holder
                        store.start_notification_mode()
                        store.recover_executions()
                        worker = asyncio.create_task(delivery_loop())
                        await send({'type': 'lifespan.startup.complete'})
                    elif message['type'] == 'lifespan.shutdown':
                        normal_shutdown = True
                        break
            except (Exception, asyncio.CancelledError) as exc:
                # Startup, `receive` and `send` all fail here, and none of them gets to skip the drain.
                # A startup that failed after taking ownership is the case that matters: this app may
                # already have admitted audit work (an app served without a lifespan does), so the owner
                # lock goes back only once that callable really finished. The error keeps travelling
                # afterwards, so a failed boot stays the error the server reported — not a 403, and not a
                # `shutdown.complete` for a drain nobody finished.
                error = exc
            finally:
                interrupted, faults = await cleanup()
                outcome = error if error is not None else (faults[0] if faults else None)
                if outcome is None and normal_shutdown and not interrupted:
                    # The lifespan's word that the admitted work is over and the file is not ours. Sent
                    # after `release_ownership`, never around it, and never for a drain that was cut
                    # short, that faulted, or that ended by cancellation: that would be a false
                    # completion, which is the one answer a lifespan may not give.
                    await send({'type': 'lifespan.shutdown.complete'})
            if outcome is not None:
                raise outcome
            if interrupted:
                raise asyncio.CancelledError()
            return
        if scope['type'] != 'http':
            await send({'type': 'websocket.close', 'code': 1008})
            return
        # The identity this request is answered under, decided before any handler runs: reused when the
        # caller sent one well-formed `x-request-id`, minted otherwise. It rides every answer as a header
        # and every server-side log line, so an operator reading a report can find the trace of one
        # request. Legacy bodies are unchanged (several are pinned byte for byte), which is why the id is
        # a header on those and a field of the envelope only where `api_contract` produced the answer.
        request_id = api_contract.request_id_from(scope)
        # The one idempotency claim this request holds, if it made one. A list used as a mutable cell so
        # `respond` — which every answer this handler sends passes through — can see and clear it: one
        # place where a key is finished or released, so no answer can leave a key claimed.
        settling: list = []

        async def respond(status, body, extra=()):
            """Send one answer, its request id, and settle the idempotency claim this request may hold.

            A 2xx is stored so a caller that lost the response can replay it; every other status releases
            the key, because a refusal is a fact about a state this platform may not have reached and
            freezing it under a key would replay a "no" that is no longer true. The write happens before
            the first response message goes out, which is the §5 rule that a completed answer is durable
            rather than scheduled — and it is one more synchronous `Store` transaction on the loop, the
            same shape every route here already has.
            """
            if settling:
                reservation, settling[:] = settling[0], []
                if 200 <= status < 300:
                    idempotency.complete(reservation, status, body)
                else:
                    idempotency.abandon(reservation)
            await send({'type': 'http.response.start', 'status': status,
                        'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store'),
                                    (api_contract.REQUEST_ID_HEADER, request_id.encode()), *extra]})
            await send({'type': 'http.response.body', 'body': canonical(body).encode()})
        values = [value for name, value in scope.get('headers', []) if name.lower() == b'authorization']
        actor = None
        if len(values) == 1:
            for item in credentials:
                if secrets.compare_digest(values[0], ('Bearer ' + item['token']).encode()):
                    actor = Actor(item['identity'], item['role'])
        if actor is None:
            return await respond(401, {'error': 'authentication_required'})
        path, method = scope['path'], scope['method']
        try:
            if verification_service.owns(path):
                # The verification paths are handed over whole, after authentication and before every
                # gate this handler already had. The role test a verification read answers to is
                # `verification_records._reader`'s (a `producer` is admissible only while the current
                # policy names it, and `summary` never is), so the `method == 'GET'` role and summary
                # gate below cannot run first without turning a verifier's own read into a 400; and a
                # POST body may not be read here either, because size, duplicate-key and UTF-8 judgement
                # belongs to the service, ahead of its first `Store` call. `None` is the one answer that
                # is not a status: the caller disconnected mid-body, so nothing is owed and nothing is
                # invented. No owned path reaches an old branch and no old path reaches this one.
                handled = await verification.handle(scope, receive, actor)
                if handled is None:
                    return
                status, payload = handled
                return await respond(status, payload)
            if review_api is not None and review_api.owns(path):
                # The observer review paths are handed over whole, for the reasons `verification_api`
                # gives: the role test these three routes answer to is `human` alone (`reader` may read
                # records elsewhere and still must not see a grade), and a POST body here is judged by
                # the service — size, duplicate keys and UTF-8 belong ahead of its first journal call,
                # not to the transport's generic parser, which keeps the last of two repeated keys.
                # `None` is the one answer that is not a status: the caller disconnected mid-body, so
                # nothing is owed and no review is written. No review path reaches an old branch, and a
                # deployment without a configured journal never reaches this one.
                handled = await review_api.handle(scope, receive, actor)
                if handled is None:
                    return
                status, payload = handled
                return await respond(status, payload)
            if method == 'GET':
                require(actor, 'reader', 'human', 'proposer', 'executor', 'summary')
                if actor.role == 'summary' and path not in ('/v1/me', '/v1/overview'):
                    return await respond(403, {'error': 'summary_only'})
                if path == '/v1/runner/requests' and runner_handoff is not None:
                    return await respond(200, runner_handoff.pending(actor))
                if path == '/v1/setup/pending' and guided_setup is not None:
                    return await respond(200, guided_setup.pending(actor))
                if path == '/v1/actions/review':
                    require(actor, 'human')
                    parameters = query_params(scope)
                    if set(parameters) != {'action_id'} or len(parameters['action_id']) != 1:
                        raise StateError('Action review requires one action identifier')
                    action_id = parameters['action_id'][0]
                    if runner_handoff is not None:
                        return await respond(200, runner_handoff.review(action_id, actor))
                    identifier(action_id)
                    with store.transaction() as connection:
                        row = connection.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
                        if not row:
                            raise StateError('Action is not available for review')
                        # Explicit successful manual review, never an interpretation of a failed
                        # runner review. The immutable action ID binds the stored request. A later
                        # decision routed to a configured handoff still requires its binding hash.
                        review = {'mode': 'manual', 'action_id': action_id,
                                  'request': json.loads(row['payload']), 'request_sha256': row['fingerprint']}
                    return await respond(200, review)
                if path == '/v1/me':
                    return await respond(200, {'identity': actor.identity, 'role': actor.role})
                if path == '/v1/inventory' and index_path:
                    from local_observe.inventory.index import readonly
                    with readonly(index_path) as connection:
                        rows = [dict(row) for row in connection.execute(
                            'SELECT id,kind,name FROM resources ORDER BY name LIMIT 100')]
                    from .presentation import resource_info
                    for row in rows:
                        row['display'] = resource_info(index_path, row['id'], display_config)
                    return await respond(200, {'rows': rows})
                if path == '/v1/status':
                    return await respond(200, store.status())
                if path == '/v1/runtime':
                    # `refusal_audit` is a pure in-memory read of this process's counters (no commit, no
                    # query); `delivery_loop_failures` is the precedent for a counter of something that
                    # used to be invisible. `refusal_audit_dispatch` is the same kind of read for this
                    # app instance's one off-loop audit slot: app-local, volatile, and the reason it is
                    # beside `refusal_audit` rather than inside it is that the two count different
                    # things — `Store`'s bucket bounds rows, this bounds callables, and a row this app
                    # shed never reached the bucket at all. `Store.status()` is not widened either way:
                    # its exact shape is pinned.
                    return await respond(200, {**runtime, 'refusal_audit': store.refusal_audit_status(),
                                               'refusal_audit_dispatch': refusal_dispatch.status(),
                                               **runtime_state})
                if path == '/v1/notifications/safety':
                    return await respond(200, store.notification_safety_status())
                if path == '/v1/overview':
                    from .overview import overview
                    return await respond(200, overview(store, overview_path))
                if path == '/v1/audit':
                    # One new GET route inside the role gate this branch already applied (`summary` is
                    # answered above, a producer never reached it), and it is the *parser* that runs
                    # first: `audit_reader.parse_query` judges the raw query bytes and refuses before
                    # `Store` is asked for anything, so an invalid paging request opens no connection and
                    # no SQLite file. Its refusals are the platform's own fixed sentences, so they reach
                    # the 400 branch below as `invalid_request` naming a field and never the caller's
                    # text; and no page field touches `/v1/records/audit`, which keeps its own limit
                    # behaviour untouched. See `docs/units/audit-reader.md`.
                    from .audit_reader import parse_query
                    page = parse_query(scope.get('query_string', b''))
                    return await respond(200, store.audit_page(
                        limit=page['limit'], category=page['category'],
                        snapshot=page['snapshot'], before=page['before']))
                if path == OCCURRENCE_PREFIX or path.startswith(OCCURRENCE_CHILD_PREFIX):
                    # The alert-occurrence reads (`docs/api/occurrences.md` §7): three routes, one module, and
                    # the boundary's own parser ahead of two of them. `page_params` judges the raw query bytes
                    # and refuses before any connection is opened, and because it admits only `limit` and
                    # `cursor` there is no filter on these routes to forget — an operator narrows the answer by
                    # paging through it, and `returned`/`next_cursor` say which of "there is no more" and "I
                    # stopped looking" the page means. `ETag` rides the single-episode read so the write that
                    # follows it can name the revision it read; the list and the history carry a cursor instead.
                    if path == OCCURRENCE_PREFIX:
                        return await respond(200, dispositions.page(store, **api_contract.page_params(scope)))
                    target, wants_history = occurrence_target(path)
                    if wants_history:
                        return await respond(200, dispositions.history(store, target,
                                                                       **api_contract.page_params(scope)))
                    document = dispositions.occurrence(store, target)
                    return await respond(200, document,
                                         [(b'etag', api_contract.revision_tag(document['revision']))])
                if path.startswith('/v1/records/'):
                    params = query_params(scope)
                    try:
                        limit = int(params.get('limit', ['100'])[0])
                    except ValueError:
                        # int() would name the offending text; a bad query value gets a fixed sentence.
                        return await respond(400, {'error': 'invalid_request', 'detail': 'limit must be an integer'})
                    from .presentation import records
                    table = path.removeprefix('/v1/records/')
                    return await respond(200, {'rows': records(
                        store, table, store.records(table, limit), index_path, display_config)})
                if path == '/v1/evidence':
                    params = query_params(scope)
                    if not {'source', 'sample_id'} <= set(params):
                        return await respond(400, {'error': 'invalid_request',
                                                   'detail': 'source and sample_id query parameters are required'})
                    return await respond(200, store.get_evidence(params['source'][0], params['sample_id'][0]))
                if maintenance_routes.owns(path):
                    # Inside the branch, after the `summary` refusal above and after `/v1/me`: the family
                    # answers `summary` with 403 like every other read. The family's own read gate names
                    # `reader`, `proposer`, `human` and `executor` and not `producer` — a choice, documented in
                    # `docs/api/maintenance.md` — but under this app a `producer` never reaches it: the GET
                    # branch's own role test refuses that credential first, with the state layer's 400. The
                    # seam's gate is therefore the second line, for a caller that uses the module directly.
                    # Raw query bytes go over
                    # whole: `maintenance.parse_query` is the thing that refuses a repeated or unknown
                    # parameter, and re-encoding a parsed dict would silently write its rules.
                    return await respond(*maintenance_routes.read(store, path,
                                                                  scope.get('query_string', b''), actor,
                                                                  index_path=index_path))
                return await respond(404, {'error': 'not_found'})
            if method not in ('POST', 'PATCH') or (method == 'PATCH'
                                                   and not maintenance_routes.edits(path)):
                # `PATCH` is admitted for exactly one path — `/v1/maintenance-schedules/{id}`, which
                # `maintenance_routes.edits` recognises — and every other path reaches the 405 it always
                # gave. The verb is a deliberate exception for one route, not a widening of the write
                # surface, and `tests/test_api_openapi_conformance.py` pins which verbs a documented
                # operation may claim.
                return await respond(405, {'error': 'method_not_allowed'})
            if actor.role == 'summary':
                # A summary credential never reaches the state layer on a write route, so the state
                # layer cannot have audited this: the transport records the one row, with the identity
                # the bearer decided and no subject. Every other POST refusal below answers the caller
                # with the same status and body it always did; only this branch is new, and the asynchronous audit
                # writer
                # changed only *where* its write runs. The gate still answers before the first
                # `receive()`, so the bytes are never read to decide this: the row is a summary-role
                # write denial, not a parser or size verdict wearing a 403 — and the off-loop audit
                # awaits nothing but its own one attempt, never a body.
                #
                # What an admitted request waits for: its own single `Store.record_refusal`, off the
                # serving loop, so this write cannot hold the loop while the database is locked elsewhere,
                # and the attempt is over before the response completes. What it does not wait for: a
                # slot. One callable per app instance is admitted and every other concurrent
                # denial is shed with these same bytes and a counter, because a queue here is a backlog
                # of already-refused callers; a 403 is therefore never proof of a durable row under
                # concurrency. See `refusal_dispatch.py`.
                if path in REFUSAL_POST_ROUTES:
                    await audit_summary_refusal(REFUSAL_POST_ROUTES[path], actor)
                return await respond(403, {'error': 'summary_only'})
            raw = b''
            while True:
                chunk = await receive()
                if chunk['type'] == 'http.disconnect':
                    return
                raw += chunk.get('body', b'')
                if len(raw) > 65536:
                    return await respond(413, {'error': 'body_too_large'})
                if not chunk.get('more_body'):
                    break
            if (path.startswith(('/v1/setup/', '/v1/runner/')) or path == '/v1/actions/execute'
                    or (runner_handoff is not None and path == '/v1/actions/decision')):
                from .runner_handoff import strict_request
                body = strict_request(raw)
            else:
                body = json.loads(raw)
            if not isinstance(body, dict):
                # Every POST branch reads named fields; a JSON array/scalar body is a client error,
                # not the TypeError the field test would otherwise raise out of the handler.
                return await respond(400, {'error': 'invalid_request', 'detail': 'Expected a JSON object body'})
            if idempotency_enabled(path):
                # The only two things the boundary adds to a route that opted in, and both happen before
                # the first `Store` method this route would call. (1) A body may not name an identity: the
                # actor is the credential, and §5 says a payload field cannot claim that an agent is a
                # human, so a guarded route refuses the claim rather than ignoring it. (2) A key is
                # claimed, replayed or refused here — never later — so a caller that retried a write it
                # already performed reads its first answer instead of performing it twice.
                #
                # A route not named in `IDEMPOTENT_POST_ROUTES` never reaches here: its clients send no
                # key, and an ignored header on such a route must not become a second answer to "what did
                # this request cost?". This is also why the claim is made after the body was read and
                # judged: the key is bound to a *valid* body, and a malformed retry must not spend one.
                api_contract.assert_no_actor_claim(body)
                key = api_contract.idempotency_key_from(scope)
                if key is not None:
                    reservation = idempotency.reserve(api_contract.actor_context(actor, request_id,
                                                                                idempotency_key=key), body,
                                                      target=(method, path))
                    if reservation.replay is not None:
                        status, payload = reservation.replay
                        return await respond(status, payload, [(api_contract.REPLAYED_HEADER, b'true')])
                    settling.append(reservation)
            if path == '/v1/events':
                # Grouping is wired here as well as on `/v1/intake/<source>`, and only there: the two
                # `Store.intake` call sites in this file are the transport's whole write path for events,
                # and a producer that posts a canonical event directly must not be the one producer whose
                # findings never join anything. `index_path` absent means the factory hands back None.
                result = store.intake(body, actor,
                                      admission=store.grouping_admission(index_path, actor))
            elif path.startswith(INTAKE_PREFIX):
                # The producer role is checked before a single byte of the envelope is normalised:
                # `prepare` opens the inventory index and evaluates rules, and a caller who can never
                # post an event should not cost that work or learn what the rules resolved to.
                require(actor, 'producer')
                result = admit_intake(intake_target(path, actor.identity), body, actor)
            elif path == '/v1/evidence':
                result = {'evidence_id': store.put_evidence(body, actor)}
            elif path == '/v1/actions':
                result = store.propose_action(body, actor, policy)
            elif (path == '/v1/actions/decision' and {'action_id', 'decision'} <= set(body)
                  <= {'action_id', 'decision', 'binding_sha256'}):
                if runner_handoff is not None:
                    result = runner_handoff.decide(body['action_id'], body['decision'],
                                                    body.get('binding_sha256'), actor)
                elif set(body) == {'action_id', 'decision'}:
                    result = store.decide(body['action_id'], body['decision'], actor)
                else:
                    raise StateError('No runner binding configured')
            elif path == '/v1/actions/claim' and set(body) == {'action_id'}:
                if runner_handoff is not None:
                    # Configured handoffs must claim through the queue, including trusted runners.
                    with store.refusal('claim', actor, body['action_id']):
                        raise StateError('Direct claims disabled; use the trusted runner handoff')
                result = store.claim_action(body['action_id'], actor, policy)
            elif path == '/v1/actions/execute' and set(body) == {'action_id'}:
                if runner_handoff is None:
                    raise StateError('Execution unavailable: no trusted runner configured')
                result = runner_handoff.enqueue(body['action_id'], actor)
            elif path == '/v1/runner/claim' and set(body) == {'action_id', 'binding_sha256', 'runner_token'}:
                if runner_handoff is None:
                    raise StateError('Execution unavailable: no trusted runner configured')
                result = runner_handoff.claim(body['action_id'], body['binding_sha256'], body['runner_token'], actor)
            elif path.startswith('/v1/setup/') and guided_setup is not None:
                result = guided_setup.request(path, body, actor)
            elif path == '/v1/notifications/retry' and set(body) == {'delivery_id'}:
                result = store.retry_notification(body['delivery_id'], actor)
            elif occurrence_write(path) is not None:
                # The two dispositions (`docs/api/occurrences.md`). The role test, the reason bound and the
                # revision comparison all live in `dispositions`, so this branch adds exactly one thing the
                # routes above do not have: a stated body shape, refused before the state layer is asked.
                # Every refusal it raises is already a `ContractError` carrying its status, so the flat
                # sentence-matching classifier in `stable_code` never sees a disposition refusal — which is the
                # difference between an envelope a client can switch on and a guess about English wording.
                command, target = occurrence_write(path)
                if set(body) - OCCURRENCE_BODY_KEYS:
                    raise api_contract.ContractError(
                        400, 'invalid_request',
                        f'A disposition takes a reason and an optional {api_contract.REVISION_FIELD}')
                expect = api_contract.expected_revision(scope, body)
                context = api_contract.request_context(scope, actor)
                if command == 'acknowledge':
                    result = dispositions.acknowledge(store, target, body.get('reason'), context,
                                                      expected_revision=expect)
                else:
                    result = dispositions.dismiss(store, target, body.get('reason'), context,
                                                  expected_revision=expect)
            elif path == '/v1/notifications/reset-safety' and not body:
                result = store.reset_notification_guard(actor)
            elif path.startswith(CALLBACK_PREFIX) and set(body) == {'token', 'action_id'}:
                # The identity this records is `actor`, from the bearer credential that reached the
                # route: no body field names an identity, and a `reader` or `summary` token is refused
                # by the role gate inside `Store.record_callback` before the code is even looked up.
                result = store.record_callback(path.removeprefix(CALLBACK_PREFIX),
                                               body['token'], body['action_id'], actor)
                if result is None:
                    # One sentence for a wrong code, an unknown channel and a code minted for a channel
                    # other than this one. Which of the three it was is not the client's to learn, and
                    # an attacker probing for a live channel gets the same bytes every time.
                    return await respond(401, {'error': 'callback_unauthorised'})
            elif path == '/v1/executions/outcome' and set(body) <= {'execution_id', 'outcome', 'runner_token'}:
                result = store.execution_outcome(body['execution_id'], body['outcome'], actor, body.get('runner_token'))
            elif maintenance_routes.owns(path):
                # After the idempotency claim, so a replayed write returns its first answer with
                # `Idempotency-Replayed: true` and never reaches this line a second time; after
                # `assert_no_actor_claim`, so an author in the body is refused before the state layer ever
                # sees it and every `author`/`declared_by` in the answer came from the credential.
                return await respond(*maintenance_routes.write(store, path, body, actor, method=method,
                                                              index_path=index_path))
            else:
                return await respond(404, {'error': 'not_found'})
            return await respond(200, result)
        except json.JSONDecodeError as exc:
            # The decoder's message is a fixed sentence plus a position; it never carries the body.
            return await respond(400, {'error': 'invalid_request', 'detail': str(exc)})
        except UnicodeDecodeError:
            return await respond(400, {'error': 'invalid_request', 'detail': 'Body is not valid UTF-8'})
        except api_contract.ContractError as exc:
            # A refusal this boundary chose, and the one answer shape `api_contract` owns. It is written
            # before the state layer is reached (a key is claimed and a claim refused ahead of any `Store`
            # write), so it is not a refusal §5 says `Store` already audited, and it audits nothing here.
            # Legacy branches above keep their flat bodies untouched; these codes did not exist before
            # this file did.
            return await respond(exc.status, api_contract.error_envelope(exc.code, exc.message, request_id),
                                 exc.headers)
        except (StateError, InvalidInventory, TransportError) as exc:
            # Messages raised here are the platform's own sentences: fixed wording, no request data.
            # This branch writes nothing, deliberately: a refusal that came out of `state.py` was
            # already audited by `Store.refusal` on the way out, so an audit call here would put two
            # rows behind one refusal. Keep it that way.
            return await respond(400, {'error': stable_code(str(exc)), 'detail': str(exc)})
        except Exception as exc:
            # Nobody chose this exception. Say only its class to the client and put the traceback in
            # the log (DEBUG only, per the logging contract) instead of blaming the caller.
            log.error('Platform request failed', extra={'method': method, 'path': path, 'request_id': request_id,
                                                        'error_class': type(exc).__name__})
            log.debug('Platform request details', exc_info=True)
            return await respond(500, {'error': 'internal_error', 'detail': type(exc).__name__})
    # Named on the returned callable so a caller that already holds an app instance can see which
    # instance-owned slot it is driving. Nothing in the transport reads it back; it is not part of the
    # ASGI surface, and it is never a way in: the dispatcher accepts no caller-supplied job.
    app.refusal_audit_dispatch = refusal_dispatch
    # The same reasoning for the verification service: a lifecycle test holds one app instance and needs
    # to see which service instance its lifespan closed and drained. Not part of the HTTP surface;
    # it accepts no caller-supplied callable or policy.
    app.verification_api = verification
    # The same reasoning for the idempotency boundary: it is app-local, it is built over this app's
    # `Store`, and a caller holding an app instance can see which gate its writes were booked against.
    # Not part of the HTTP surface, and it accepts nothing a caller supplies.
    app.idempotency_gate = idempotency
    return app


def app_factory() -> Callable[..., Awaitable[None]]:
    from . import verification_policy
    from .notification_safety import NotificationPolicy
    from .runtime import observe_startup
    # Named before anything is opened: a deployment still carrying the retired environment value is
    # one that must be redeployed, and it must not get as far as migrating state on the way out.
    refuse_retired_credentials_environment()
    safety = (json.loads(Path(os.environ['LO_NOTIFICATION_POLICY']).read_text())
              if os.environ.get('LO_NOTIFICATION_POLICY') else {})
    declared = os.environ.get('LO_NOTIFICATION_MODE')
    if declared is not None and not declared.strip():
        # Blank is a refusal, never an unset value (ledger notification and state leftovers, from the test tooling
        # review). A line
        # reading `LO_NOTIFICATION_MODE=` in a generated environment file says the operator wrote
        # it; treating it as unset would boot this entry point on the default while the CLI refused
        # the same file. Both entry points now refuse it, and neither one names a mode.
        raise ValueError('LO_NOTIFICATION_MODE is set but blank; name off, recording or live, or unset it')
    mode = declared if declared is not None else safety.get('delivery_mode', 'recording')
    if 'delivery_mode' in safety and safety['delivery_mode'] != mode:
        raise ValueError('Conflicting notification mode declarations')
    notification_policy = NotificationPolicy(**dict(safety, delivery_mode=mode))
    # Reject a wrong code pin before opening or migrating operational state.
    observe_startup(mode, False)
    credentials = role_credentials()
    # The two judgements the mounted role list makes possible, ahead of anything that could touch the
    # state file: is this credential set one this transport may serve at all, and does it carry the
    # producer rows the mounted verification policy names as verifiers. Credential validation used to
    # run only inside `create_app`, after Store and notification-client construction. Policy loading
    # is new here. The loader checks row keys and identities without reading token values;
    # `validate_credentials` reads tokens for length and uniqueness and checks each role.
    #
    # The order is deliberately not flat. Everything above (the retired environment value, the mode
    # declarations, the code pin) keeps refusing first, exactly as it did, and the action-policy,
    # channel, store and intake-rules reads keep their places below: an unreadable rules document still
    # stops the service after the store is open, because this is a preflight for these two refusals and
    # not a promise that every startup failure was ever IO-free. An unset `LO_VERIFICATION_POLICY` is the
    # off switch and costs nothing — `None`, no file opened, no second policy vocabulary.
    validate_credentials(credentials)
    # The observer's review surface is opt-in and checked here, ahead of the state file: unset is the
    # documented off switch, and a value that is blank, relative or pointed at a directory with no
    # journal is a deployment that must be fixed, not a platform that boots with a review API over an
    # empty database it just created. Only the variable's name appears in the refusal.
    from .observer_review import state_path_from_environment
    observer_state = state_path_from_environment()
    mounted_policy = verification_policy.policy_from_environment(credentials)
    definitions = json.loads(Path(os.environ['LO_ACTION_POLICY']).read_text())
    clients: dict[str, Any] = {}
    display = (json.loads(Path(os.environ['LO_DISPLAY_CONFIG']).read_text())
               if os.environ.get('LO_DISPLAY_CONFIG') else {})
    # The two variables this entry point has always honoured become one entry in the same table the
    # registry fills: a deployment configured the old way is a one-channel deployment, and the channel
    # it sends on is the one its `LO_NOTIFICATION_POLICY` names (default `primary`). Keeping them in
    # `clients` rather than in a separate variable is what stops the running process having a private
    # notion of "the" channel while its database books sends against a named one.
    if mode == 'live' and os.environ.get('LO_TELEGRAM_CONFIG'):
        if os.environ.get('LO_NOTIFY_URL'):
            raise ValueError('Configure exactly one notification channel')
        from .telegram import TelegramClient
        config = json.loads(Path(os.environ['LO_TELEGRAM_CONFIG']).read_text())
        clients[notification_policy.channel] = TelegramClient(
            config['token'], config['chat_id'],
            index_path=os.environ['LO_INDEX_PATH'], display_config=display)
    elif mode == 'live' and os.environ.get('LO_NOTIFY_URL'):
        from local_observe.http import JsonClient
        # The webhook credential is mounted (LO_NOTIFY_TOKEN_FILE); the environment value is still
        # accepted so a staging script can export one. Either way a live channel with no credential
        # raises here and the service never starts, rather than starting and silently not delivering.
        clients[notification_policy.channel] = JsonClient(
            os.environ['LO_NOTIFY_URL'], read_credential('LO_NOTIFY_TOKEN'),
            allow_http=os.environ.get('LO_NOTIFY_ALLOW_HTTP') == '1')
    # Additional channels arrive from one mounted document, in the operator's preference order. Read
    # only in live mode: `recording` and `off` must not open a channel credential (this package's
    # README), so the file stays closed and the store runs on its single primary policy.
    channel_policies: dict[str, Any] = {}
    if mode == 'live' and os.environ.get('LO_NOTIFY_CHANNELS'):
        from .notifications import build_channels
        extra_clients, channel_policies = build_channels(
            json.loads(Path(os.environ['LO_NOTIFY_CHANNELS']).read_text()), mode=mode,
            index_path=os.environ['LO_INDEX_PATH'], display_config=display)
        clashing = sorted(set(clients) & set(extra_clients))
        if clashing:
            # One channel name sent by two clients would make "which channel delivered this?" a question
            # with no durable answer, so the collision is a boot failure rather than a precedence rule.
            raise ValueError(f'Notification channel configured twice: {", ".join(clashing)}')
        clients.update(extra_clients)
    store = Store(os.environ['LO_STATE_PATH'], notification_policy, verification_policy=mounted_policy)
    # Recorded after opening and before any claim: the store routes across exactly the channels this
    # process can send on, and a channel with no client could only ever refuse.
    store.add_channels({name: channel_policies[name] for name in channel_policies if name in clients})
    # Read last, after every other boot refusal has had its chance: an unreadable or invalid rules
    # document stops the service (a webhook whose rules could not be read would answer every sender
    # with a refusal naming nothing useful), and an unset `LO_INTAKE_RULES` is the documented off
    # switch — one INFO line, `{}` rules, and every `/v1/intake/<source>` POST refused with the reason.
    #
    # This import is crowdsec's and it is the only line this card adds to this file: `crowdsec.py`
    # registers its intake adapter at import, the way `intake.py` registers its own Alertmanager
    # adapter, and without an importer `/v1/intake/crowdsec` would answer "no adapter is registered"
    # while the component, its rules document and its tests all claimed the source exists. It sits here
    # rather than at module scope for the reason `verification_api` and `runtime` sit here: nothing may
    # be able to fail an `api` import on a sibling's account. It changes no ordering — it reads no file,
    # no socket and no environment, and every refusal above it still happens first.
    from . import crowdsec  # noqa: F401  (imported for the adapter registration, which is its whole effect)
    intake_rules = intake.rules_from_environment()
    policy = action_policy(os.environ['LO_INDEX_PATH'], definitions)
    from local_observe.deployment.setup_service import configured_services
    handoff, setup = configured_services(store, policy, os.environ)
    return create_app(store, credentials,
                      policy, clients or None,
                      os.environ['LO_INDEX_PATH'], display, os.environ.get('LO_OVERVIEW_PATH'),
                      intake_rules, runner_handoff=handoff, guided_setup=setup,
                      observer_review=observer_state)

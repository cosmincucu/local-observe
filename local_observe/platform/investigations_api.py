"""The investigation, delivery and explanation routes over the state their owner already keeps.

`local_observe/platform/observer_review.py` opened the observer's journal to a human at a browser: two
reads and one append. This module finishes what the same journal may be asked, and adds the store-side
operation that belongs to this area rather than to the journal:

* **investigation reads** — the freshness answer the `lo-observer check` command gives, the corrected
  cases the `retrieve` command prints, the delivery session's state, and this installation's posture;
* **investigation writes** — ask for a cycle, ask for an export, withdraw a job that has not started,
  reconcile or disarm a delivery session;
* **jobs** — the admitted-and-not-yet-finished answer, which is the only honest response to "run an
  investigation" inside a request that must return in milliseconds (`local_observe/platform/job_queue.py`);
* **explanations** — one bounded round of the rule floor, which is what `lo-platform rca` runs and which
  needs nothing the platform service does not already hold.

What makes each of these a route rather than a second implementation:

* **One writer per fact.** `journal.check`, `journal.examples`, `journal.create_file`,
  `delivery.session_status`, `delivery.disarm`, `delivery.reconcile` and `rca.tick` are the functions the
  CLI commands call, imported from the same modules. Nothing here writes a cycle, a delivery row, an
  acceptance receipt or an explanation record by hand.
* **The credential is the authority, and it is never a field.** Writes are `human`-only, as are the reads
  of review-adjacent data; `reader` additionally reaches the two operational facts a poller needs
  (freshness, posture). No body field names an identity, an actor, a reviewer or an attestation — the last
  of those is why `POST /v1/observer/delivery/reconciliations` can exist at all: the `human` credential
  *is* the attestation, exactly as it is for `POST /v1/actions/decision`, so the route asks for a session
  identifier and nothing else.
* **A model's own claim is never a human's.** No route here writes a grade, and no answer reproduces a
  `decision`, `confidence` or `rationale` as a `correct`/`incorrect` label. The one human grade in this
  journal remains the append `observer_review.py` owns.
* **Off is off, and off is not broken.** With no journal configured, every `/v1/observer/*` path here
  answers `404 not_found` exactly as it did before this module existed. A missing AI provider is not an
  error either: the explanation round answers `{"status": "off", "configured": false, "analyzed": 0}`, the
  posture `lo-platform rca` already takes without `--config`, and it never constructs a model client.
* **A destination is not a readout.** The delivery read reports the channel *kind*, its daily budget and
  the digest that binds it, and never a chat or user identifier: those are the destination's own, and
  `channel_sha256` answers "is this the channel I configured?" without publishing them.

Nothing in this module's import list reaches the `observer` package: the journal, the delivery driver and
the observer's own JSON contract are imported inside the calls that need them, for the reason
`observer_review.py` gives — a platform process that serves no observer request must not be able to fail
its own import on the observer's account.
"""
from __future__ import annotations

import asyncio
import os
import re
import secrets
import threading
import uuid
from collections.abc import Callable
from typing import Any

from . import job_queue
from .api_contract import ContractError, page_params
from .state import Actor, StateError, Store, clock, require

# ---------------------------------------------------------------------------------------- route table

#: The literal routes this module answers, and the one prefix whose tail is an identifier. Membership is
#: exact-or-shaped, so no other path — including the three `observer_review.py` owns alone — is reachable
#: from here, and a sub-resource this family does not have is a `404` rather than a handler reading a
#: meaning out of an identifier.
HEALTH_ROUTE = '/v1/observer/health'
CASES_ROUTE = '/v1/observer/cases'
CAPABILITIES_ROUTE = '/v1/observer/capabilities'
RUNS_ROUTE = '/v1/observer/runs'
EXPORTS_ROUTE = '/v1/observer/exports'
JOBS_ROUTE = '/v1/observer/jobs'
DELIVERY_ROUTE = '/v1/observer/delivery'
DISARM_ROUTE = '/v1/observer/delivery/disarm'
RECONCILE_ROUTE = '/v1/observer/delivery/reconciliations'
EXPLANATION_ROUTE = '/v1/explanations/rounds'
JOBS_PREFIX = '/v1/observer/jobs/'
EXACT_ROUTES = frozenset({HEALTH_ROUTE, CASES_ROUTE, CAPABILITIES_ROUTE, RUNS_ROUTE, EXPORTS_ROUTE,
                          JOBS_ROUTE, DELIVERY_ROUTE, DISARM_ROUTE, RECONCILE_ROUTE, EXPLANATION_ROUTE})

#: The job kinds this area admits, and who can run each. `observer.run` names the observer process on
#: purpose: a cycle needs the main thread, the kernel lock and the protected model route, none of which a
#: request handler has (`observer/runtime.py::deadline` refuses any other thread outright).
RUN_KIND = job_queue.KIND_RUN
EXPORT_KIND = job_queue.KIND_EXPORT

#: The three delivery-channel fields an answer may carry. `chat_id` and `user_id` are deliberately absent:
#: see the module header.
CHANNEL_FIELDS = ('channel', 'daily_limit', 'channel_sha256')

#: Raw query bytes admitted before parsing — the review seam's bound, kept identical so one rule covers
#: every `/v1/observer/` read.
MAX_QUERY_BYTES = 256
#: Newest-first page cap, shared with the review seam and `job_queue.MAX_PAGE`.
MAX_PAGE = job_queue.MAX_PAGE
#: `lo-observer check --max-age-seconds`'s default, so the route answers the question the command asks.
DEFAULT_MAX_AGE_SECONDS = 7200
MAX_AGE_SECONDS_LIMIT = 604800
#: The review seam's cap on retained reviews; an export's `--limit` is the same 100 the CLI caps at.
MAX_EXAMPLES = 100

_IDENTIFIER = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z')

# ---------------------------------------------------------------------------------------- refusals

#: What a journal route answers on an installation that configured none. `api.py` cannot answer it itself,
#: because the path *is* known to the transport as soon as this module is mounted, so the family returns
#: the transport's own flat `404` body byte for byte: an unconfigured installation must not be able to
#: tell a journal route from a path that never existed, and no caller learns a new error shape for free.
ABSENT = (404, {'error': 'not_found'})

#: The journal/delivery codes that judge the request rather than the state behind it, and those that say
#: the request was well-formed and the state moved. Everything else is state this process may not use, and
#: is answered `503` naming nothing (`observer_review.py`'s rule, reused by importing its lists).
_REQUEST_CODES = frozenset({'invalid_identifier', 'invalid_retrieval_bound', 'invalid_reconciled_spend'})
_CONFLICT_CODES = frozenset({'observer_busy', 'fresh_process_challenge_required', 'reconciliation_expired',
                             'fresh_delivery_epoch_required', 'unknown_cycle', 'cycle_not_reviewable',
                             'delivery_session_superseded', 'acceptance_changed', 'acceptance_revoked',
                             'acceptance_expired', 'external_effect_reconciliation_required'})
#: The codes whose honest answer is not about the caller at all, said once instead of echoing journal code.
_SENTENCES = {
    'observer_busy': 'The observer holds its own lock, so no other process may change delivery state now',
    'fresh_process_challenge_required': 'That delivery session is not waiting for a reconciliation',
    'reconciliation_expired': 'That reconciliation window has closed; start a new delivery session',
    'fresh_delivery_epoch_required': 'A fresh delivery epoch is required, and this platform mints it',
    'external_effect_reconciliation_required': 'The reconciliation attestation this route carries was not '
                                               'accepted, so nothing was re-armed',
    'delivery_session_superseded': 'Another observer instance holds the send authority now',
    'acceptance_changed': 'The accepted quality record no longer matches the one this session bound',
    'acceptance_revoked': 'The acceptance this session bound has been revoked',
    'acceptance_expired': 'The acceptance this session bound has expired',
    'unknown_cycle': 'No such cycle is retained',
    'invalid_reconciled_spend': 'The reconciled send floor must be a whole number of sends',
    'invalid_retrieval_bound': 'The retrieval bound is not one this surface accepts',
}


def owns(path: Any) -> bool:
    """Whether one path belongs to this module. Asked before any credential is consulted."""
    if not isinstance(path, str):
        return False
    if path in EXACT_ROUTES:
        return True
    if not path.startswith(JOBS_PREFIX):
        return False
    parts = path[len(JOBS_PREFIX):].split('/')
    return bool(parts[0]) and (len(parts) == 1 or (len(parts) == 2 and parts[1] == 'cancellations'))


def writes(path: Any) -> bool:
    """Whether one path is an investigation write, and so is owed the idempotency boundary.

    `api.py` names the four collection-shaped writes in its own list and asks this function about the one
    family member it cannot name there: a withdrawal addresses its job by path, and the identifier is
    caller data (`docs/api/COVERAGE.md` "Adding an operation", step 3, and `maintenance_api.writes`).
    """
    return isinstance(path, str) and owns(path) and path.endswith('/cancellations')


class Investigations:
    """The route family over one observer journal, plus the store-side explanation round."""

    def __init__(self, store: Store, *, state: str | None = None, index_path: Any = None,
                 explanation_config_path: str | None = None,
                 explanation_source: str | None = None) -> None:
        """Bind the family to this app's store, and to a journal only when this installation named one.

        Args:
            store: The operational store an explanation round reads and writes.
            state: The observer state directory, or ``None`` for "no journal here". The path is validated
                by `observer_review.existing_state` when the family is built, so a deployment that names a
                directory with no journal in it refuses to start rather than serving an empty review page.
            index_path: The inventory index an explanation round may read declared boundaries from.
            explanation_config_path: The rule-floor configuration file, or ``None`` for "no rule floor is
                installed". It is read and validated here, at construction, so a named file that cannot be
                parsed refuses to start the service rather than serving a round that explains nothing — and
                read through a function-body import, so an installation without this optional component can
                still build the app and answer every other route. Never from a request.
            explanation_source: The label an explanation round files its records under, required beside a
                configuration path exactly as `lo-platform rca` requires `--source` beside `--config`.
            explanation_source: The source label an explanation round files its records under.

        Raises:
            ValueError: ``state`` is not a directory holding an existing journal.
        """
        self.store = store
        self.state = state
        self.index_path = index_path
        self.explanation_source = explanation_source
        self.explanation_config = None
        if explanation_config_path is not None:
            if not explanation_source:
                raise ValueError('An explanation source label is required with a rule-floor configuration')
            from . import rca  # a body, not a module header: see the class docstring and D15's neighbour
            self.explanation_config = rca.load_config(explanation_config_path)
        if state is not None:
            from .observer_review import existing_state
            self.state = str(existing_state(state))
        # One worker identity per app instance: only this process may close a job this process claimed,
        # which is what leaves a dead service's work `unknown` rather than falsely `succeeded`.
        self.worker = 'platform-' + secrets.token_hex(8)
        self._capacity = threading.BoundedSemaphore(4)
        self._tasks: set = set()

    # ---------------------------------------------------------------------------------- transport entry

    async def read(self, path: str, scope: dict[str, Any], actor: Actor) -> tuple[int, dict[str, Any]]:
        """Answer one investigation read. Every journal call here runs off the serving loop."""
        if self.state is None and path != EXPLANATION_ROUTE:
            return ABSENT
        if path == HEALTH_ROUTE:
            _require(actor, READ_ROLES)
            asked = _query(scope.get('query_string', b''), {'max_age_seconds'})
            age = _bounded(asked['max_age_seconds'], MAX_AGE_SECONDS_LIMIT) if 'max_age_seconds' in asked \
                else DEFAULT_MAX_AGE_SECONDS
            return 200, await self._offloop(self._health, age)
        if path == CASES_ROUTE:
            _require(actor, ('human',))
            return 200, await self._offloop(self._cases, _query(scope.get('query_string', b''),
                                                                {'query', 'limit'}))
        if path == CAPABILITIES_ROUTE:
            _require(actor, READ_ROLES)
            return 200, await self._offloop(self._capabilities)
        if path == DELIVERY_ROUTE:
            _require(actor, ('human',))
            return 200, await self._offloop(self._delivery)
        if path == JOBS_ROUTE:
            _require(actor, ('human',))
            page = page_params(scope, default_limit=MAX_PAGE, maximum=MAX_PAGE)
            return 200, await self._offloop(self._jobs_page, page['limit'], page['cursor'])
        if path.startswith(JOBS_PREFIX) and '/' not in path[len(JOBS_PREFIX):]:
            _require(actor, ('human',))
            return 200, await self._offloop(self._job_read, path[len(JOBS_PREFIX):])
        raise _not_found(path)

    async def write(self, path: str, body: dict[str, Any], actor: Actor) -> tuple[int, dict[str, Any]]:
        """Apply one investigation write, or answer `202` with the job that stands for the work."""
        if self.state is None and path != EXPLANATION_ROUTE:
            return ABSENT
        if path == RUNS_ROUTE:
            return await self._run(body, actor)
        if path == EXPORTS_ROUTE:
            return await self._export(body, actor)
        if path == DISARM_ROUTE:
            _require(actor, ('human',))
            _reject(body, ())
            return 200, await self._offloop(self._disarm)
        if path == RECONCILE_ROUTE:
            return await self._reconcile(body, actor)
        if path == EXPLANATION_ROUTE:
            _require(actor, ('human',))
            _reject(body, ())
            return 200, await self._offloop(self._explanation)
        if owns(path) and path.endswith('/cancellations'):
            _require(actor, ('human',))
            _reject(body, ())
            return 200, await self._offloop(self._job_cancel, path[len(JOBS_PREFIX):], actor)
        raise _not_found(path)

    # ---------------------------------------------------------------------------------------- the reads

    def _health(self, max_age_seconds: int) -> dict[str, Any]:
        """Freshness of the newest finished cycle — the record `lo-observer check` prints, plus its bound.

        The bound travels with the verdict. `healthy: false` judged against an hour and against a week are
        two different facts, and a poller that asked for one should not have to remember which it asked;
        the verdict itself comes from `Journal.check` and is not re-derived here.
        """
        verdict = self._journal_call(lambda journal: journal.check(now=clock(),
                                                                   max_age_seconds=max_age_seconds))
        return {**verdict, 'max_age_seconds': max_age_seconds}

    def _cases(self, asked: dict[str, str]) -> dict[str, Any]:
        """The retained corrected cases `lo-observer retrieve` prints, newest first."""
        query = asked.get('query', '')
        if len(query) > 200:
            raise ContractError(400, 'invalid_request', 'A retrieval query may not exceed 200 characters')
        limit = _bounded(asked['limit'], MAX_EXAMPLES) if 'limit' in asked else 10
        examples = self._journal_call(lambda journal: journal.examples(query=query, limit=limit))
        return {'schema_version': 1, 'examples': examples, 'returned': len(examples),
                'trust': 'untrusted_reference_only', 'bound': 'latest_independent_correction_per_cycle'}

    def _capabilities(self) -> dict[str, Any]:
        """What this installation may do, as posture: no host, path, model version, channel identifier or
        secret is named, because a capability read is answered to every credential that may poll it."""
        session = 'no_journal' if self.state is None else self._safe_session_state()
        return {'schema_version': 1,
                'journal': 'mounted' if self.state is not None else 'absent',
                'delivery': {'session': session,
                             'disarm': 'available' if self.state is not None else 'absent'},
                'explanation': {'configured': self.explanation_config is not None
                                and self.explanation_source is not None,
                                'model_used': False,
                                'reason': None if self.explanation_config is not None
                                else 'no-rule-floor-configuration'},
                'notification_mode': self.store.notification_safety_status()['delivery_mode'],
                'meaning': 'posture_only; no host, path, model, channel identifier or secret is named'}

    def _safe_session_state(self) -> str:
        """The delivery session's state, or `unreadable`: a capability read never carries a journal error."""
        try:
            return str(self._journal_call(lambda journal: _delivery_status(journal).get('state',
                                                                                       'unknown')))
        except ContractError:
            return 'unreadable'

    def _delivery(self) -> dict[str, Any]:
        """One delivery session's state, with the destination's own identifiers left out."""
        return {'schema_version': 1, 'delivery': self._journal_call(lambda journal: _delivery_status(journal))}

    def _jobs_page(self, limit: int, cursor: str | None) -> dict[str, Any]:
        document = self._journal_call(lambda journal: job_queue.page(journal.db, limit=limit, cursor=cursor,
                                                                now=clock()))
        return {'schema_version': 1, **document}

    def _job_read(self, job_id: str) -> dict[str, Any]:
        return {'schema_version': 1,
                'job': self._journal_call(lambda journal: job_queue.read(journal.db, _identifier(job_id),
                                                                    now=clock()))}

    # --------------------------------------------------------------------------------------- the writes

    async def _run(self, body: dict[str, Any], actor: Actor) -> tuple[int, dict[str, Any]]:
        """Admit one investigation cycle; the observer process runs it, this route records the ask."""
        _require(actor, ('human',))
        _reject(body, ('cycle_id',))
        cycle_id = _identifier(body['cycle_id'])
        job, created = await self._offloop(self._admit, 'run-' + secrets.token_hex(8), RUN_KIND,
                                           job_queue.RUNNER_OBSERVER, actor.identity, {'cycle_id': cycle_id})
        return 202, {'schema_version': 1, 'job': job, 'reused': not created,
                     'runner': job_queue.RUNNER_OBSERVER,
                     'note': 'admitted; the observer process claims admitted cycles under its own lock'}

    async def _export(self, body: dict[str, Any], actor: Actor) -> tuple[int, dict[str, Any]]:
        """Admit one export, start it in this process, and answer with the job rather than the file."""
        _require(actor, ('human',))
        _reject(body, ('limit',))
        if 'limit' in body and type(body['limit']) is not int:
            # `type is int`, not `isinstance`: `True` is an `int` in Python and is not a page size.
            raise ContractError(400, 'invalid_request', f'An export limit is an integer from 1 to '
                                                        f'{MAX_EXAMPLES}')
        limit = _bounded(body['limit'], MAX_EXAMPLES) if 'limit' in body else MAX_EXAMPLES
        job_id = 'export-' + secrets.token_hex(8)
        # No durable dedupe key here: an export is a *fresh* view of the retained cases, and a unique key
        # on `{"limit": 100}` would mean the second export of next month is answered with this month's
        # file. `Idempotency-Key` is what covers a lost acknowledgement of this one request.
        job, _created = await self._offloop(self._admit, job_id, EXPORT_KIND, job_queue.RUNNER_PLATFORM,
                                            actor.identity, {'limit': limit},
                                            dedupe=digest_of({'job_id': job_id}))
        self._spawn(lambda: self._execute_export(job_id, limit))
        return 202, {'schema_version': 1, 'job': job, 'reused': False, 'runner': job_queue.RUNNER_PLATFORM,
                     'note': 'started-in-this-process'}

    def _job_cancel(self, tail: str, actor: Actor) -> dict[str, Any]:
        job_id = _identifier(tail.split('/')[0])
        document = self._journal_call(lambda journal: job_queue.cancel(journal.db, job_id=job_id,
                                                                  actor=actor.identity, now=clock()))
        return {'schema_version': 1, 'job': document}

    def _disarm(self) -> dict[str, Any]:
        """Pull the send authority for this journal, whatever session currently holds it."""
        from local_observe.observer import delivery

        # `delivery.disarm` takes the journal's own exclusive lock and refuses `observer_busy` when the
        # observer is inside a cycle; taking a second lock here would only make that refusal permanent,
        # because an flock on a second descriptor of the same file is refused by the kernel.
        return self._journal_call(lambda journal: {
            'schema_version': 1,
            'delivery': _delivery_status(journal, delivery.disarm(journal, now=clock()))})

    async def _reconcile(self, body: dict[str, Any], actor: Actor) -> tuple[int, dict[str, Any]]:
        """Attest that a waiting session's earlier external effects were reconciled.

        The CLI asks a human at a terminal to type the session id back; this route takes the attestation
        from the `human` credential that signed the request — the same authority `POST
        /v1/actions/decision` takes for an approval — and mints the epoch itself, because `reconcile`
        refuses one the journal has already seen and a caller-supplied epoch would put the freshness rule
        in the wrong hands. A body field named `attested`, `epoch` or `actor` is refused: the first two
        are this route's to decide and the third is `docs/CONTRACTS.md` §5.
        """
        _require(actor, ('human',))
        _reject(body, ('session_id', 'used_today_floor'))
        session_id = _identifier(body['session_id'])
        floor = body.get('used_today_floor')
        if floor is not None and (type(floor) is not int or not 0 <= floor <= 2):
            raise ContractError(400, 'invalid_request',
                                'The reconciled send floor is a whole number of sends from 0 to 2')
        epoch = str(uuid.UUID(hex=secrets.token_hex(16)))
        from local_observe.observer import delivery

        # `delivery.reconcile` takes the journal lock itself, for the reason `disarm` above gives.
        def call(journal: Any) -> dict[str, Any]:
            current = delivery.reconcile(journal, session_id=session_id, epoch=epoch, attested=True,
                                         now=clock(), used_today_floor=floor)
            return {'schema_version': 1, 'delivery': _delivery_status(journal, current)}

        return 200, await self._offloop(self._journal_call, call)

    # ---------------------------------------------------------------------------------- the explanation

    def _explanation(self) -> dict[str, Any]:
        """One bounded round of the rule floor, exactly as `lo-platform rca` runs it.

        `generate` stays ``None``, which is what the CLI does and what keeps the optional `ai` package out
        of this process: the rule floor answers on its own, and a model that is not configured cannot make
        this route fail. The round is bounded by the installed configuration's own `max_incidents` and
        `max_model_calls`, which is why it is a bounded write here and not a job.
        """
        if self.explanation_config is None or self.explanation_source is None:
            return {'status': 'off', 'configured': False, 'analyzed': 0,
                    'reason': 'no-rule-floor-configuration'}
        from . import rca  # the round's own module, imported by the code that runs the round
        return rca.tick(self.store, self.index_path, config=self.explanation_config,
                        source=self.explanation_source, now=clock())

    # ------------------------------------------------------------------------------------ the plumbing

    def _admit(self, job_id: str, kind: str, runner: str, actor: str, argument: dict[str, Any],
               *, dedupe: str | None = None) -> tuple[dict[str, Any], bool]:
        def call(journal: Any) -> tuple[dict[str, Any], bool]:
            return job_queue.admit(journal.db, job_id=job_id, kind=kind, runner=runner, actor=actor,
                              argument=argument, now=clock(), dedupe=dedupe)

        return self._journal_call(call)

    def _execute_export(self, job_id: str, limit: int) -> None:
        """Run one admitted export under the journal's own lock, and record how it ended."""
        from local_observe.observer.contract import encoded

        def build() -> dict[str, Any]:
            journal = self._open()
            try:
                # The same projection the CLI writes — one canonical example per line, exclusively
                # created inside the private state directory, never a caller-named path. The name is the
                # job's own, so a re-run cannot overwrite the file an earlier answer pointed at.
                target = f'{job_id}.jsonl'
                descriptor = journal.create_file(journal.directory / target)
                written = 0
                with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                    for example in journal.examples(limit=limit):
                        stream.write(encoded(example) + '\n')
                        written += 1
                    stream.flush()
                    os.fsync(stream.fileno())
                return {'schema_version': 1, 'exported': written, 'file': target}
            finally:
                journal.close()

        journal = self._open()
        try:
            job_queue.run_now(journal.db, job_id=job_id, worker=self.worker, work=build, now=clock())
        finally:
            journal.close()

    def _spawn(self, work: Callable[[], None]) -> None:
        """Start one admitted platform-side job in this process without making the caller wait for it.

        A failure inside the job is the job's own record (`job_queue.run_now` writes it), so the only thing
        worth logging here is a task that died outside that path.
        """
        loop = asyncio.get_running_loop()
        task = loop.create_task(asyncio.to_thread(work))
        self._tasks.add(task)

        def finished(failed: asyncio.Future) -> None:
            self._tasks.discard(failed)
            if not failed.cancelled() and failed.exception() is not None:
                from local_observe.log import get_logger
                get_logger(__name__).warning('Investigation job task failed',
                                             extra={'error_class': type(failed.exception()).__name__})

        task.add_done_callback(finished)

    def _open(self) -> Any:
        """Open the configured journal for one operation. It is closed before the answer travels."""
        if self.state is None:
            # Unreachable through `read`/`write`, which answer `ABSENT` first; a 503 rather than a 404
            # because reaching here means the configuration this object was built with has gone.
            raise _unavailable()
        from local_observe.observer.journal import Journal
        return Journal(self.state, create=False)

    def _journal_call(self, work: Callable[[Any], Any]) -> Any:
        """Run one bounded journal operation, mapping its codes onto this family's refusals."""
        from local_observe.observer.contract import ObserverError
        from .observer_review import FEEDBACK_CONFLICT_CODES, FEEDBACK_REQUEST_CODES
        journal = None
        try:
            journal = self._open()
            return work(journal)
        except ContractError:
            raise
        except ObserverError as exc:
            code = str(exc)
            if code in FEEDBACK_CONFLICT_CODES or code in _CONFLICT_CODES:
                raise ContractError(409, 'conflict', _SENTENCES.get(
                    code, 'The retained state no longer agrees with this request')) from None
            if code in FEEDBACK_REQUEST_CODES or code in _REQUEST_CODES:
                raise ContractError(400, 'invalid_request', _SENTENCES.get(
                    code, 'This request is not in the shape that route accepts')) from None
            raise _unavailable() from None
        except Exception:  # noqa: BLE001 - what broke inside another owner's state is not the caller's
            raise _unavailable() from None
        finally:
            if journal is not None:
                journal.close()

    async def _offloop(self, operation: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run one journal call in a worker thread, with at most four admitted and no queue.

        The reason is `observer_review.py`'s: the journal is another process's file, and a request waiting
        on it would hold the serving loop, and so hold up authentication and health. A refusal here is
        `503`, never a queue — a queue of journal waits is the same backlog with worse latency.
        """
        if not self._capacity.acquire(blocking=False):
            raise ContractError(503, 'observer_review_busy',
                                'Too many investigation requests are in flight; try again shortly')

        def run() -> Any:
            try:
                return operation(*args, **kwargs)
            finally:
                self._capacity.release()

        try:
            task = asyncio.create_task(asyncio.to_thread(run))
        except BaseException:
            self._capacity.release()
            raise
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return await asyncio.shield(task)


# ------------------------------------------------------------------------------------ small helpers

def _delivery_status(journal: Any, current: dict[str, Any] | None = None) -> dict[str, Any]:
    """Report one delivery session without publishing the destination it sends to."""
    from local_observe.observer import delivery
    document = dict(current if current is not None else delivery.session_status(journal))
    channel = document.get('channel')
    if isinstance(channel, dict):
        document['channel'] = {key: channel[key] for key in CHANNEL_FIELDS if key in channel}
    return document


def digest_of(value: Any) -> str:
    """The canonical SHA-256 of one document, from the same helper the state layer uses."""
    from local_observe.inventory.validation import digest
    return digest(value)


#: The two investigation reads a credential may make without being the person on call: the journal's
#: freshness and its capability list. `operator-agent` is in the pair because an automated operator
#: reads what a `reader` reads. Everything else in this family — cases, jobs, runs, exports, reviews —
#: stays `human`, because those are the surfaces where a person grades an investigation.
READ_ROLES = ('reader', 'human', 'operator-agent')


def _require(actor: Actor, roles: tuple[str, ...]) -> None:
    """Gate on the credential's role, and answer 403 rather than the state layer's 400.

    `state.require` raises the platform's own sentence, which `api.py` maps to a `400`. A new route family
    gets to choose, and the choice is the one a client can act on: `403` says "a different credential
    would work here", and only that is true.
    """
    try:
        require(actor, *roles)
    except StateError as exc:
        raise ContractError(403, 'not_authorised', str(exc)) from None


def _reject(body: dict[str, Any], allowed: tuple[str, ...]) -> None:
    """Refuse a write body that names a field this door does not read."""
    extra = sorted(field for field in body if field not in allowed)
    if extra:
        raise ContractError(400, 'invalid_request',
                            'This route accepts ' + (', '.join(allowed) or 'an empty JSON object') + ' only')


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ContractError(400, 'invalid_request', 'An identifier is not one this surface accepts')
    return value


def _bounded(value: Any, maximum: int) -> int:
    text = value if isinstance(value, str) else str(value)
    if not text.isascii() or not text.isdecimal() or str(int(text)) != text or not 1 <= int(text) <= maximum:
        raise ContractError(400, 'invalid_request', f'A numeric value is outside the range 1..{maximum}')
    return int(text)


def _query(raw: Any, allowed: set[str]) -> dict[str, str]:
    """Return the named query parameters, refusing every other spelling of a query string."""
    body = raw if isinstance(raw, bytes) else b''
    if len(body) > MAX_QUERY_BYTES:
        raise ContractError(400, 'invalid_request', f'A query may not exceed {MAX_QUERY_BYTES} bytes')
    try:
        text = body.decode('ascii')
    except UnicodeDecodeError:
        raise ContractError(400, 'invalid_request', 'A query must be ASCII text') from None
    found: dict[str, str] = {}
    for segment in text.split('&') if text else ():
        key, separator, value = segment.partition('=')
        if not separator or not key or not value or key not in allowed or key in found:
            raise ContractError(400, 'invalid_request', 'That query parameter is not accepted here')
        found[key] = value
    return found


def _not_found(path: str) -> ContractError:
    return ContractError(404, 'not_found', f'No such investigation route: {path}')


def _unavailable() -> ContractError:
    """State this process may not use. Which of the reasons it was is logged by the caller's log line."""
    return ContractError(503, 'observer_state_unavailable',
                         'The observer state this route reads is not usable by this process')


__all__ = ['CAPABILITIES_ROUTE', 'CASES_ROUTE', 'DELIVERY_ROUTE', 'DISARM_ROUTE', 'EXPLANATION_ROUTE',
           'EXPORTS_ROUTE', 'HEALTH_ROUTE', 'JOBS_ROUTE', 'RECONCILE_ROUTE', 'RUNS_ROUTE',
           'Investigations', 'owns', 'writes']

"""The optional authenticated review seam over the observer's own journal: three routes, no new state.

The observer already records every cycle it admits and every human correction it is given, in a private
SQLite journal owned by the OS account that runs it (`local_observe/observer/journal.py`). This module is
the only way a human at a browser reaches that journal: two bounded reads and one append, behind the
bearer credential `api.py` already authenticates. It adds no database, no scheduler, no notification and
no second copy of any review rule.

The invariants, each with the reason it is shaped this way:

1. **Off is off.** With no configured path this module is never imported by `create_app`, and the three
   paths answer `404 not_found` exactly as they did before it existed. A configured path must name an
   *existing* journal: the observer's `Journal` creates a database and a private directory when opened on
   a directory that has none, so this seam looks for the file and refuses instead of opening. A typo in a
   deployment variable must never produce an empty state directory that looks reviewable.
2. **Authority is the credential, never the body.** Every route requires the `human` role, and the
   reviewer retained in the journal is `platform-human:<authenticated identity>`. No request field names
   an identity, a role or a reviewer, so a `reader`, `producer`, `proposer`, `executor` or `summary`
   token can neither read review data nor become a reviewer.
3. **The journal is opened per call and closed before the answer is sent.** Nothing here keeps a
   connection open across requests. Journal operations run off the serving loop with at most four
   admitted operations and no waiting queue; database contention cannot block authentication or health.
4. **Malformed input is refused before journal access.** Method, authority, query bytes,
   identifier shape, body size, JSON shape and exact field names are decided before the journal opens.
   Every refusal body is a fixed vocabulary: `api.py`'s existing shapes plus `journal.py`'s own payload-free
   codes. An unopenable journal, an unexpected exception or a stored record this build cannot project is
   one 503 body that names nothing; the reason goes to the log alone. No path, exception text, credential
   or request value is echoed in a refusal.
5. **Nothing here writes a cycle.** The seam appends to the append-only `feedback` table and never
   modifies `cycles`, delivery, acceptance or expiry. A `quiet`, unanswered, failed or in-flight cycle is
   reported as `review: unknown` and `reviewable` only when the journal would accept a grade for it —
   being unreviewed is never evidence of being correct.
6. **Concurrency is the journal's decision, taken inside its own write transaction.** A caller echoes the
   cycle digest and the newest review ID it was shown; `Journal.feedback` refuses a changed digest
   (`cycle_digest_changed`) or a review that is no longer newest (`stale_review`) while holding the write
   lock, and returns the original receipt for a byte-identical retry of an ID it already holds.

The cycle list's `queue_reason` reuses the two reasons `local_observe/evaluation/feedback.py` puts in its
review queue, per row. The workload report's every-nth-quiet sampling is a property of a measured window,
so it is not applied here and no row claims a queue position.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from local_observe.log import get_logger
from local_observe.observer.contract import ObserverError, digest, name, strict_json

from .state import Actor, StateError, label, require

log = get_logger(__name__)

#: The environment variable naming the observer's private state directory. Unset is the documented off
#: switch; a set-but-blank value is a refusal, the way `LO_NOTIFICATION_MODE` treats a blank line.
ENVIRONMENT = 'LO_OBSERVER_REVIEW_STATE'

#: The journal file `Journal` owns inside that directory. Its absence means "no observer state here",
#: which is a refusal, never an empty page of results.
JOURNAL_FILE = 'observer.sqlite3'

#: The three literal paths this seam owns. Membership is an exact test with no prefix and no
#: trailing-slash folding, so every other path — including anything else under `/v1/observer/` — stays
#: the main API's to answer.
CYCLES_ROUTE = '/v1/observer/cycles'
CYCLE_ROUTE = '/v1/observer/cycle'
FEEDBACK_ROUTE = '/v1/observer/feedback'
ROUTES = frozenset({CYCLES_ROUTE, CYCLE_ROUTE, FEEDBACK_ROUTE})

#: The reviewer prefix the platform's authenticated human identities are recorded under. The OS-derived
#: `os-uid:` reviewer remains the CLI's, and nothing here can name it from a request body.
REVIEWER_PREFIX = 'platform-human:'

#: Newest-first page cap. The observer's own retrieval bound (`examples(limit=10..100)`) and the
#: platform's `/v1/records` default are both 100; a review surface with a larger cap is a page nobody
#: reads and a query that holds the journal's read lock longer than a human can wait.
MAX_PAGE = 100
#: Raw query bytes admitted before parsing. One canonical cycle ID plus a `limit` fits in far less, and
#: every legal value here is ASCII, so the bound costs nothing and stops an unbounded scan.
MAX_QUERY_BYTES = 256
#: Raw body bytes admitted before concatenation — the same ceiling `api.py` already applies to its own
#: POST bodies, so no route here accepts a larger request than the transport it hangs off.
MAX_BODY_BYTES = 65536
#: Nesting an observer review can legitimately reach: body, `values`, `outcome_refs`. Anything deeper is
#: a shape this surface does not accept, and refusing it is cheaper than bounding it later.
MAX_BODY_DEPTH = 8

#: The statuses a review can be recorded against. This is `observer.journal.REVIEWABLE_STATUSES`, kept
#: as a local literal because the journal is imported only on the enabled path (see `_open`);
#: `test_observer_review_api` asserts the two never drift apart, and the journal repeats this judgement
#: inside its own write transaction, so this copy only decides which honest status to answer with.
REVIEWABLE = ('completed', 'partial', 'failed')
#: The two review-queue reasons `evaluation/feedback.py` uses, and `None` for "this row needs nothing".
QUIET_SAMPLE = 'quiet-sample'
FINDING_OR_GAP = 'finding-or-coverage-gap'
#: The journal's own vocabulary for "no human has graded this". Never `correct`, never a default grade.
UNREVIEWED = 'unknown'
REVIEWED = 'reviewed'

# Fixed bodies. None is ever formatted with caller bytes, a path or an exception message.
NOT_FOUND = {'error': 'not_found'}
METHOD_NOT_ALLOWED = {'error': 'method_not_allowed'}
SUMMARY_UNAUTHORISED = {'error': 'summary_only'}
NOT_AUTHORISED = {'error': 'not_authorised', 'detail': 'Actor is not authorised for this operation'}
BODY_TOO_LARGE = {'error': 'body_too_large'}
#: The one answer for "this process may not read the observer's state, for a reason the caller cannot
#: act on": ownership, an unreadable or unversioned journal, a record that will not project, a driver
#: fault. Which of them it was is logged by class or by journal code and never returned.
STATE_UNAVAILABLE = {'error': 'observer_state_unavailable'}

#: `journal.py`'s verdicts on the review document a caller supplied. These are the caller's own error and
#: the codes are payload-free by that module's contract, so they may be named back.
FEEDBACK_REQUEST_CODES = frozenset({'invalid_fields', 'invalid_usefulness', 'invalid_correctness',
                                    'invalid_corrected_answer', 'invalid_outcome_refs',
                                    'invalid_review_seconds', 'invalid_export_approval',
                                    'unknown_outcome_reference', 'corrected_evidence_required_for_export'})
#: Codes that say the request was well-formed but the retained state no longer agrees with it.
FEEDBACK_CONFLICT_CODES = frozenset({'cycle_not_reviewable', 'feedback_id_reused', 'stale_review',
                                     'cycle_digest_changed'})
#: Every code a body-parse refusal may name; an unlisted one is answered with a plain `invalid_request`.
BODY_CODES = frozenset({'json_too_large', 'duplicate_json_key', 'invalid_json', 'structure_too_deep',
                        'invalid_object', 'too_many_items', 'string_too_long', 'nonfinite_number',
                        'nonfinite_json', 'invalid_value'})

_DIGEST = re.compile(r'\A[0-9a-f]{64}\Z')

# One page of the newest cycles, with the two facts a reviewer needs beside each record: whether the
# journal holds any feedback for it, and which review ID is newest. Correlated subqueries over a primary
# key and a `cycle_id` lookup, bounded by the same `limit` the outer query carries.
_PAGE_SQL = ('SELECT c.cycle_id, c.document, '
             'EXISTS(SELECT 1 FROM feedback f WHERE f.cycle_id = c.cycle_id) AS reviewed, '
             '(SELECT f.feedback_id FROM feedback f WHERE f.cycle_id = c.cycle_id '
             'ORDER BY f.rowid DESC LIMIT 1) AS latest_feedback_id '
             'FROM cycles c{where} ORDER BY c.rowid DESC LIMIT ?')
_CURSOR_SQL = 'SELECT c.rowid FROM cycles c WHERE c.cycle_id = ? LIMIT 1'
_COUNT_SQL = 'SELECT count(*) FROM cycles'


def state_path_from_environment(environ: dict[str, str] | None = None) -> Path | None:
    """Return the observer state directory this process may review, or ``None`` when disabled.

    Called by `api.app_factory` before any state file is opened, so a deployment that names a missing
    journal refuses to start instead of booting a platform with a review surface pointed at nothing.

    Args:
        environ: The environment to read; defaults to this process's.

    Returns:
        The absolute directory holding an existing `observer.sqlite3`, or ``None`` when
        ``LO_OBSERVER_REVIEW_STATE`` is unset.

    Raises:
        ValueError: The variable is set but blank, names a relative path, or names a directory with no
            existing journal. Only the variable's name appears in any of these messages.
    """
    values = os.environ if environ is None else environ
    declared = values.get(ENVIRONMENT)
    if declared is None:
        return None
    if not declared.strip():
        raise ValueError(f'{ENVIRONMENT} is set but blank; unset it or name an existing observer state '
                         f'directory')
    return existing_state(declared)


def existing_state(value: Path | str) -> Path:
    """Return ``value`` as an absolute directory that already holds a journal, refusing every else.

    Raises:
        ValueError: A blank or relative path, or a directory with no `observer.sqlite3` regular file. A
            directory this process cannot stat is refused with the same words as one that does not exist:
            the caller cannot fix either by reading a permission detail.
    """
    path = Path(value) if isinstance(value, (str, Path)) else Path(str(value))
    if not str(value).strip():
        raise ValueError(f'{ENVIRONMENT} names no state directory')
    if not path.is_absolute():
        raise ValueError(f'{ENVIRONMENT} must name an absolute state directory')
    try:
        journal = path / JOURNAL_FILE
        if not journal.is_file():
            raise ValueError(f'{ENVIRONMENT} must name an existing observer journal; no {JOURNAL_FILE} '
                             f'was found to review')
    except OSError:
        raise ValueError(f'{ENVIRONMENT} must name an existing observer journal; no {JOURNAL_FILE} '
                         f'was found to review') from None
    return path


def owns(path: Any) -> bool:
    """Return whether one of the three review paths is named exactly by *path*."""
    return isinstance(path, str) and path in ROUTES


class _Refusal(Exception):
    """One answer this edge already chose, raised out of the helper that chose it.

    Private, never logged, and carries only a fixed body: it exists so the checks below can return a
    value instead of every caller re-testing one.
    """

    def __init__(self, status: int, body: dict[str, Any]) -> None:
        super().__init__(body['error'])
        self.status = status
        self.body = body


def _identifier(value: Any) -> str:
    """Return a bounded identifier, refusing anything else before the journal sees it."""
    try:
        return name(value)
    except ObserverError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_identifier'}) from None


def _digest(value: Any) -> str:
    """Return a lowercase SHA-256 digest, refusing anything else before it is compared to anything."""
    if not isinstance(value, str) or _DIGEST.match(value) is None:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_cycle_digest'})
    return value


def _query(raw: Any, allowed: set[str]) -> dict[str, str]:
    """Return the named query parameters, refusing every other spelling of a query string.

    Exactly `name=value` pairs, names from *allowed*, no repeat, no blank, no bare `&`, ASCII only and
    bounded first — so nothing unbounded is ever traversed. Percent-decoding is deliberately absent:
    every legal identifier here is already URL-safe, and a decoder that replaces undecodable bytes
    would answer "what did the caller name?" with a guess.
    """
    body = raw if isinstance(raw, bytes) else b''
    if len(body) > MAX_QUERY_BYTES:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': 'query_too_large'})
    try:
        text = body.decode('ascii')
    except UnicodeDecodeError:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_query'}) from None
    found: dict[str, str] = {}
    for segment in text.split('&') if text else ():
        key, separator, value = segment.partition('=')
        if not separator or not key or not value or key not in allowed or key in found:
            raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_query'})
        found[key] = value
    return found


def _page(raw: Any) -> tuple[int, str | None]:
    """Return the ``(limit, after)`` a cycle page asks for, with the defaults spelled out."""
    values = _query(raw, {'limit', 'after'})
    limit = MAX_PAGE
    if 'limit' in values:
        text = values['limit']
        if not text.isascii() or not text.isdecimal() or str(int(text)) != text or not 1 <= int(text) <= MAX_PAGE:
            raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_limit'})
        limit = int(text)
    return limit, (_identifier(values['after']) if 'after' in values else None)


def _cycle_id(raw: Any) -> str:
    """Return the one cycle identifier a detail read names."""
    values = _query(raw, {'cycle_id'})
    if set(values) != {'cycle_id'}:
        raise _Refusal(400, {'error': 'invalid_request', 'detail': 'cycle_id_required'})
    return _identifier(values['cycle_id'])


def _summary(cycle_id: str, document: Any, reviewed: bool, latest_feedback_id: Any) -> dict[str, Any]:
    """Project one stored cycle into a review summary — no evidence, no answer, no grade.

    The projection is total or it refuses: a record that lacks a field, or carries a type this surface
    cannot name, is state this build cannot read, and answering with a partial row would be a claim about
    a cycle nobody has read.
    """
    if not isinstance(document, dict):
        raise _Refusal(503, STATE_UNAVAILABLE)
    try:
        status = document['status']
        coverage = document['coverage']
        decision = document['decision']
        mode = document['mode']
        delivery_status = document['delivery']['status']
        answer = document['answer']
        started_at, ended_at = document['started_at'], document['ended_at']
    except (KeyError, TypeError) as exc:
        log.warning('Observer cycle cannot be projected', extra={'error_class': type(exc).__name__})
        raise _Refusal(503, STATE_UNAVAILABLE) from None
    findings: Any
    if answer is None:
        findings = []
    elif isinstance(answer, dict):
        findings = answer.get('findings') or []
    else:
        raise _Refusal(503, STATE_UNAVAILABLE)
    if (not isinstance(status, str) or not isinstance(coverage, str) or not isinstance(mode, str)
            or not isinstance(delivery_status, str) or decision not in (None, 'quiet', 'watch', 'tell')
            or not isinstance(findings, list)
            or not (ended_at is None or isinstance(ended_at, str))):
        raise _Refusal(503, STATE_UNAVAILABLE)
    # The same per-row rule the workload report applies, without its window-based quiet sampling: a
    # complete quiet result with no grade is a sample, anything that spoke or fell short is a gap. A
    # cycle that cannot be graded yet (still `running`, or `skipped`) gets no reason at all: the report
    # counts a still-open coverage gap inside a measured window, while a review surface that queues work
    # nobody can review yet is a form that fails the moment it is opened.
    gap = coverage != 'complete' or bool(findings) or decision == 'tell'
    quiet = decision == 'quiet' and coverage == 'complete'
    reviewable = status in REVIEWABLE
    reason: str | None = None
    if reviewable and not reviewed:
        reason = FINDING_OR_GAP if gap else (QUIET_SAMPLE if quiet else None)
    return {'cycle_id': cycle_id, 'started_at': started_at, 'ended_at': ended_at, 'status': status,
            'coverage': coverage, 'decision': decision, 'mode': mode, 'delivery_status': delivery_status,
            'review': REVIEWED if reviewed else UNREVIEWED, 'reviewable': reviewable,
            'findings': len(findings), 'queue_reason': reason,
            'latest_feedback_id': latest_feedback_id}


class ObserverReview:
    """The three review routes over one existing observer journal directory."""

    def __init__(self, state: Path | str) -> None:
        """Bind this service to an existing journal, refusing any other configuration.

        Raises:
            ValueError: ``state`` is blank, relative, or a directory with no journal to review — the
                same refusals `state_path_from_environment` makes, so a caller that builds an app
                directly is refused exactly as a deployment through the environment is.
        """
        self.state = existing_state(state)
        self._capacity = threading.BoundedSemaphore(4)
        self._jobs: set[asyncio.Future] = set()
        try:
            journal = _open(self.state)
            journal.close()
        except (OSError, sqlite3.Error, ObserverError, _Refusal):
            raise ValueError('LO_OBSERVER_REVIEW_STATE requires an owned existing observer journal') from None

    def owns(self, path: Any) -> bool:
        """Return whether *path* is one of this service's three routes."""
        return owns(path)

    async def handle(self, scope: dict[str, Any], receive: Any, actor: Actor | None
                     ) -> tuple[int, dict[str, Any]] | None:
        """Answer one review route, or return ``None`` when the caller disconnected mid-body.

        Called by `api.py` after bearer authentication and before its own GET/POST gates, so the role
        test below is the only authority decision these paths get. `api.py` classifies anything raised
        out of here exactly as it classifies its own handlers.
        """
        path, method = scope.get('path'), scope.get('method')
        try:
            self._authorise(actor)
            if method == 'GET' and path == CYCLES_ROUTE:
                return 200, await self._offloop(self._cycles, scope.get('query_string', b''))
            if method == 'GET' and path == CYCLE_ROUTE:
                return 200, await self._offloop(self._cycle, scope.get('query_string', b''))
            if method == 'POST' and path == FEEDBACK_ROUTE:
                if scope.get('query_string'):
                    # A review submission is a body. A query parameter on this route could only ever be
                    # ignored, and an ignored field on a form that decides a human grade is a defect the
                    # caller should meet at once rather than a silent difference in what was recorded.
                    raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_query'})
                raw = await _body(receive)
                if raw is None:
                    return None
                return 200, await self._offloop(self._append, raw, actor)
            if method in ('GET', 'POST'):
                # An owned path with the other method: the path is ours, the verb is not.
                return 405, METHOD_NOT_ALLOWED
        except _Refusal as refusal:
            return refusal.status, refusal.body
        return 405, METHOD_NOT_ALLOWED

    async def _offloop(self, operation, *args):
        if not self._capacity.acquire(blocking=False):
            raise _Refusal(503, {'error': 'observer_review_busy'})

        def run():
            try:
                return operation(*args)
            finally:
                # Cancellation is not completion: only the actual operation returns capacity.
                self._capacity.release()

        try:
            job = asyncio.get_running_loop().run_in_executor(None, run)
        except BaseException:
            self._capacity.release()
            raise
        self._jobs.add(job)

        def finished(future):
            self._jobs.discard(future)
            if not future.cancelled():
                future.exception()

        job.add_done_callback(finished)
        return await asyncio.shield(job)

    def _authorise(self, actor: Actor | None) -> None:
        """Refuse every credential that is not an authenticated human, before any journal is opened."""
        if actor is not None and actor.role == 'summary':
            # The transport's own word for this role, kept identical to every other route's answer so a
            # summary credential cannot tell this surface from any other by probing a status.
            raise _Refusal(403, SUMMARY_UNAUTHORISED)
        try:
            require(actor, 'human')
        except StateError:
            raise _Refusal(403, NOT_AUTHORISED) from None

    def _journal(self, work: Any, *, request_codes: frozenset[str] = frozenset()) -> Any:
        """Open the existing journal, run one bounded call, and close it before the answer travels.

        *request_codes* names the journal codes that judge the caller's own submission on this call site;
        a code outside them is treated as state this process cannot use, because the only codes the
        journal raises for its own reasons (`private_owned_directory_required`, `unsupported_journal_version`,
        `duplicate_json_key` on a *stored* document) are exactly the ones a caller did not cause.
        """
        journal = None
        try:
            journal = _open(self.state)
            return work(journal)
        except _Refusal:
            raise
        except ObserverError as exc:
            code = str(exc)
            if code in FEEDBACK_CONFLICT_CODES:
                raise _Refusal(409, {'error': 'conflict', 'detail': code}) from None
            if code in request_codes:
                raise _Refusal(400, {'error': 'invalid_request', 'detail': code}) from None
            log.warning('Observer review state refused', extra={'refusal_code': code})
            raise _Refusal(503, STATE_UNAVAILABLE) from None
        except (OSError, sqlite3.Error) as exc:
            log.warning('Observer review state failed', extra={'error_class': type(exc).__name__})
            raise _Refusal(503, STATE_UNAVAILABLE) from None
        finally:
            if journal is not None:
                try:
                    journal.close()
                except (OSError, sqlite3.Error, ObserverError) as exc:
                    # The answer this call computed is already final; a descriptor we could not hand back
                    # is logged, never charged to the caller.
                    log.warning('Observer review journal close failed',
                                extra={'error_class': type(exc).__name__})

    def _cycles(self, raw_query: bytes) -> dict[str, Any]:
        """Return the newest cycle summaries, with truncation stated rather than inferred."""
        limit, after = _page(raw_query)

        def work(journal: Any) -> dict[str, Any]:
            if after is None:
                where, arguments = '', [limit + 1]
            else:
                cursor = journal.db.execute(_CURSOR_SQL, (after,)).fetchone()
                if cursor is None:
                    # The cursor names no retained cycle. That is a fact about the request, and it cannot
                    # be answered with an empty page that would also be the answer for a short journal.
                    raise _Refusal(404, NOT_FOUND)
                where, arguments = ' WHERE c.rowid < ?', [cursor[0], limit + 1]
            rows = journal.db.execute(_PAGE_SQL.format(where=where), tuple(arguments))
            # One row more than the page was asked for, so "there is a newer-or-older side you have not
            # seen" is a measurement and not a guess: `truncated` is true only when a row really was cut,
            # and `next_after` names the cursor that returns the next page.
            page, truncated = [], False
            for row in rows:
                if len(page) == limit:
                    truncated = True
                    break
                # Retain summaries only: a page of 100 maximum-size cycle documents is 50 MiB.
                page.append(_summary(row[0], strict_json(row[1], 524288, max_depth=20), bool(row[2]), row[3]))
            total = journal.db.execute(_COUNT_SQL).fetchone()[0]
            return {'schema_version': 1,
                    'cycles': page,
                    'limit': limit, 'returned': len(page), 'total_cycles': total,
                    'truncated': truncated,
                    'next_after': page[-1]['cycle_id'] if truncated and page else None}

        return self._journal(work)

    def _cycle(self, raw_query: bytes) -> dict[str, Any]:
        """Return one retained replay, the digest a review form must echo, and the newest review ID."""
        cycle_id = _cycle_id(raw_query)

        def work(journal: Any) -> dict[str, Any]:
            cycle = journal.get(cycle_id)
            if cycle is None:
                raise _Refusal(404, NOT_FOUND)
            total = journal.db.execute('SELECT count(*) FROM feedback WHERE cycle_id=?', (cycle_id,)).fetchone()[0]
            rows = journal.db.execute('SELECT document FROM feedback WHERE cycle_id=? ORDER BY rowid DESC LIMIT 100',
                                      (cycle_id,)).fetchall()
            feedback = [strict_json(row[0]) for row in reversed(rows)]
            for record in feedback:
                record.setdefault('review_seconds', None)
            replay = {**cycle, 'review': 'reviewed' if feedback else 'unknown', 'feedback': feedback}
            return {'schema_version': 1, 'cycle_sha256': digest(cycle),
                    'reviewable': cycle['status'] in REVIEWABLE,
                    'latest_feedback_id': feedback[-1]['feedback_id'] if feedback else None,
                    'feedback_total': total, 'feedback_truncated': total > len(feedback),
                    'replay': replay}

        return self._journal(work)

    def _append(self, raw: bytes, actor: Actor) -> dict[str, Any]:
        """Validate one review submission exactly, then let the journal decide it under its write lock."""
        document = _object(raw)
        if set(document) != {'cycle_id', 'feedback_id', 'cycle_sha256', 'previous_feedback_id', 'values'}:
            # Exact, not a subset: a body carrying `reviewer`, `identity` or `role` is an attempt to
            # supply the authority this process decides, and a missing field is an unfinished form.
            raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_fields'})
        cycle_id = _identifier(document['cycle_id'])
        feedback_id = _identifier(document['feedback_id'])
        cycle_sha256 = _digest(document['cycle_sha256'])
        previous = document['previous_feedback_id']
        previous_id = None if previous is None else _identifier(previous)
        values = document['values']
        identity = actor.identity
        try:
            label(identity)
        except StateError:
            # The mounted credential set named an identity this journal cannot retain. That is a
            # deployment fact, not something the caller can correct.
            log.warning('Observer reviewer identity is unusable', extra={'refusal_code': 'invalid_identifier'})
            raise _Refusal(503, STATE_UNAVAILABLE) from None

        def submit(journal: Any) -> dict[str, Any]:
            # One journal open, one write transaction. A cycle that is not retained is answered here (404),
            # because "no such cycle" is not a state collision; whether a retained cycle can be graded at
            # all is the journal's decision (`cycle_not_reviewable`), taken while it holds the write lock.
            if journal.get(cycle_id) is None:
                raise _Refusal(404, NOT_FOUND)
            record = journal.feedback(cycle_id, feedback_id, values,
                                      reviewer=REVIEWER_PREFIX + identity, cycle_sha256=cycle_sha256,
                                      previous_feedback_id=previous_id)
            return {'schema_version': 1, 'feedback': record}

        return self._journal(submit, request_codes=FEEDBACK_REQUEST_CODES)


def _open(state: Path) -> Any:
    """Open the existing journal, refusing a state directory whose journal has disappeared since startup.

    Raises:
        _Refusal: `observer_state_unavailable` when the file is not there. The observer's `Journal`
            creates a database it is pointed at, so this check is what keeps a deleted or never-created
            state directory from becoming a reviewable empty one.
    """
    try:
        if not (state / JOURNAL_FILE).is_file():
            raise _Refusal(503, STATE_UNAVAILABLE)
    except OSError:
        raise _Refusal(503, STATE_UNAVAILABLE) from None
    # Imported here, and only on the enabled path: the journal module pulls the observer's contract and
    # an app that serves no review request must not pay for either, and nothing in the observer package
    # may be able to fail a platform import on its account.
    from local_observe.observer.journal import Journal
    return Journal(state, create=False)


async def _body(receive: Any) -> bytes | None:
    """Collect the request body under `MAX_BODY_BYTES`, or return ``None`` on a disconnect.

    The size test is against `len(collected) + len(pending)` before concatenation, so an oversized body
    is refused by the chunk that would have overflowed the buffer rather than by the buffer — the same
    shape `api.py` and `verification_api.py` use.
    """
    collected = bytearray()
    while True:
        chunk = await receive()
        if chunk['type'] == 'http.disconnect':
            return None
        pending = chunk.get('body', b'')
        if len(collected) + len(pending) > MAX_BODY_BYTES:
            raise _Refusal(413, BODY_TOO_LARGE)
        collected += pending
        if not chunk.get('more_body'):
            return bytes(collected)


def _object(raw: bytes) -> dict[str, Any]:
    """Return the submitted review as a parsed object, refusing every other spelling of bytes.

    Duplicate keys, non-finite numbers, oversized or over-deep documents and undecodable UTF-8 are all
    refused here with a journal code or one fixed sentence — never with a decoder message quoting the
    caller's text, and never by letting `json.loads` silently keep the last of two repeated keys.
    """
    try:
        document = strict_json(raw, MAX_BODY_BYTES, max_depth=MAX_BODY_DEPTH)
    except ObserverError as exc:
        code = str(exc)
        raise _Refusal(400, {'error': 'invalid_request',
                             'detail': code if code in BODY_CODES else 'invalid_request'}) from None
    if not isinstance(document, dict):
        raise _Refusal(400, {'error': 'invalid_request', 'detail': 'invalid_object'})
    return document

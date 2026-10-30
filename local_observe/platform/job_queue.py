"""Durable job records for work a caller asks for now and some owner's process performs later.

An HTTP caller may ask for work this platform cannot finish inside a request: one investigation cycle
runs for minutes under a kernel lock, an export walks and writes a bounded batch of retained records.
Those requests are admitted, not performed inline, and the answer is a *job*: an identifier, a state, and
a place to read what came of it. The states are the six a caller can act on —
`accepted` / `running` / `succeeded` / `failed` / `cancelled` / `unknown` — and one row per admitted
request, never a queue of retries.

**Why the row lives in the observer journal and not in the operational store.** Every job this module
admits today does its work against the observer's journal under the observer's own exclusive lock, and the
process that can run it is the process that owns that file. A queue in the operational store would be an
admission the runner cannot read without reaching across an account boundary it has no business crossing,
which is how a queue ends up holding jobs nobody can claim. The journal is where the work, the lock and
the state already live, so it is where the request joins them; `local_observe/observer/delivery.py`
and `acceptance.py` already add their own tables to that file the same way. See `docs/api/DECISIONS.md`
D12 for the cost. The functions below therefore take an open SQLite connection rather than a `Store`, and
any later area with a store-side queue can reuse this module against a `Store.transaction()` connection.

Four rules this module does not bend:

* **The state is what happened, not what was asked.** `unknown` exists and is used: a `running` row whose
  runner has not been seen within `JOB_STALE_SECONDS` describes work whose process may have died, and the
  honest answer about a job nobody can report on is `unknown`, never `running` and never `failed`.
* **Nothing is cancelled that cannot be stopped.** A job still `accepted` has started no work and may be
  withdrawn. A `running` investigation cycle cannot be stopped by a request — its own wall-clock deadline
  is the only thing that ends it (`observer/runtime.py::deadline`) — so the withdrawal is a `409` that says
  so. An idempotent replay of a withdrawal returns the same answer, not a second one.
* **Admission is deduplicated, so a lost answer costs nothing.** `POST` twice with the same identity for
  the same work and the second call reads back the first job (`reused`), because the alternative is a
  queue of duplicate cycles and a model bill to match.
* **No secret, path or provider message travels in a job row.** `argument` is the caller's own bounded
  document re-encoded canonically, `result` is whatever the runner chose to report, and `error` is a
  public refusal code from the module that raised it — never exception prose, which is the observer's
  logging rule applied to a durable record.
"""
from __future__ import annotations

import datetime as dt
import re
import sqlite3
from collections.abc import Callable
from typing import Any

from local_observe.inventory.validation import canonical, digest

from .api_contract import ContractError, page_payload

#: The one table this module owns, created on first use inside the journal the same way
#: `observer/delivery.py` creates its session table: an added table is not a new journal version, and a
#: journal this build can read is a journal this build may add to.
JOBS_TABLE = 'platform_jobs'

#: The closed state vocabulary. `accepted` is admitted and not started; `running` is claimed by a runner;
#: `succeeded`/`failed` are a runner's own report; `cancelled` is a withdrawal that reached the job before
#: any runner took it; `unknown` is this module's judgement about a `running` row nobody reported on.
STATUSES = ('accepted', 'running', 'succeeded', 'failed', 'cancelled', 'unknown')

#: How long a `running` row may go unreported before it is no longer evidence of a live process. It is
#: deliberately wider than the longest cycle this product can configure (the observer's own
#: `max_cycle_seconds` is the inner bound) plus room for the lock wait in front of it: reclaiming a job
#: that is merely slow would turn a live investigation into a false `unknown`, and a false `unknown` is
#: the one answer a caller cannot un-see.
JOB_STALE_SECONDS = 7200
#: Newest-first page cap, shared with the observer review seam: a job list nobody reads is not a queue.
MAX_PAGE = 100
#: Bytes of caller-supplied `argument` admitted into one row. Enough for one cycle identifier and a
#: limit; not enough for a document, which is what a job argument must never become.
MAX_ARGUMENT_BYTES = 4096

_IDENTIFIER = re.compile(r'\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z')
_PUBLIC_CODES = re.compile(r'\A[a-z][a-z0-9_]{0,63}\Z')

#: The status list as SQL text, generated from `STATUSES` so the CHECK and the vocabulary cannot drift.
_STATUS_CHECK = ', '.join(f"'{item}'" for item in STATUSES)

_ENSURE = f'''CREATE TABLE IF NOT EXISTS {JOBS_TABLE} (
    job_id TEXT PRIMARY KEY, kind TEXT NOT NULL, runner TEXT NOT NULL, actor TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ({_STATUS_CHECK})),
    dedupe TEXT NOT NULL CHECK (length(dedupe) = 64),
    argument TEXT NOT NULL, result TEXT, error TEXT,
    created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, claimed_by TEXT,
    -- A job that was withdrawn before any runner took it never started, so `cancelled` is the one
    -- terminal state that may carry a null `started_at`; the other four terminal states are a runner's
    -- report and a runner must have claimed the row first (`finish` refuses one that did not).
    CHECK (started_at IS NOT NULL OR status IN ('accepted', 'cancelled')),
    CHECK (finished_at IS NOT NULL OR status IN ('accepted', 'running')));
-- One admitted request per (kind, argument): the durable half of "run it once", which the transport's
-- `Idempotency-Key` only covers for as long as a key is kept.
CREATE UNIQUE INDEX IF NOT EXISTS {JOBS_TABLE}_dedupe ON {JOBS_TABLE}(kind, dedupe);
CREATE INDEX IF NOT EXISTS {JOBS_TABLE}_recency ON {JOBS_TABLE}(job_id);'''

#: What `runner` says about a job, and who is able to move it out of `accepted`.
RUNNER_OBSERVER = 'observer'
RUNNER_PLATFORM = 'platform'
RUNNERS = (RUNNER_OBSERVER, RUNNER_PLATFORM)

#: The job kinds this platform can run, each with the process that runs it. A kind outside this tuple is
#: refused at admission rather than queued: a row no claimer will ever name is a job that sits in a queue
#: until `reclaim` calls it `unknown`, which reads as a failure the platform caused.
KIND_RUN = 'observer.run'
KIND_EXPORT = 'observer.export'
KINDS = (KIND_RUN, KIND_EXPORT)


class JobError(ContractError):
    """One refusal about a job, already carrying the status and the catalogue code to answer it with."""


def ensure(db: sqlite3.Connection) -> None:
    """Create the job table inside an open journal connection when this is the first use."""
    db.executescript(_ENSURE)


def identifier(value: Any) -> str:
    """Return a bounded job identifier, refusing every other spelling of one.

    Raises:
        JobError: 400 `invalid_request`. The same reason `state.identifier` exists: this string is
            retained and echoed back, and an unbounded value in a primary key is a log line waiting to
            happen.
    """
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise JobError(400, 'invalid_request', 'A job identifier must be a bounded identifier')
    return value


def admit(db: sqlite3.Connection, *, job_id: str, kind: str, runner: str, actor: str,
          argument: dict[str, Any], now: dt.datetime, dedupe: str | None = None
          ) -> tuple[dict[str, Any], bool]:
    """Record one admitted request, or return the job that already carries the same request.

    `runner` names the process able to take the job (`platform` for work this service can do itself,
    `observer` for a cycle), and it is chosen by the route, never by the caller: a body that named its own
    runner would be a request to decide which process the platform runs.

    Returns:
        ``(job, created)`` — `created` is ``False`` when an earlier admission carried the same `kind` and
        the same `dedupe`, in which case the earlier row is returned unchanged.

    Raises:
        JobError: 400 for an unusable identifier, kind, runner or argument size.
    """
    ensure(db)
    job_id = identifier(job_id)
    if kind not in KINDS:
        # Shape is checked by the caller's route; membership is checked here so the queue cannot hold work
        # that no `claim(kind=...)` in this build will ever name.
        raise JobError(400, 'invalid_request', 'An unknown job kind was requested')
    if runner not in RUNNERS:
        raise JobError(400, 'invalid_request', 'This platform cannot run that kind of job')
    text = canonical(argument)
    if len(text.encode()) > MAX_ARGUMENT_BYTES:
        raise JobError(400, 'invalid_request', 'The requested job arguments are too large')
    stamp = _text(now)
    key = digest({'kind': kind, 'argument': argument}) if dedupe is None else dedupe
    with db:
        db.execute(f'INSERT OR IGNORE INTO {JOBS_TABLE}'
                   ' (job_id, kind, runner, actor, status, dedupe, argument, created_at)'
                   ' VALUES (?,?,?,?,?,?,?,?)',
                   (job_id, kind, runner, actor, 'accepted', key, text, stamp))
    row = _fetch(db, job_id)
    if row is None:
        # The unique index took the earlier row and this `job_id` is new, so the same request is already
        # in the queue under another identifier. Reading it back is the only honest answer.
        row = db.execute(f'SELECT * FROM {JOBS_TABLE} WHERE kind = ? AND dedupe = ?', (kind, key)).fetchone()
        assert row is not None
        return record(row), False
    return record(row), True


def claim(db: sqlite3.Connection, *, kind: str, worker: str, now: dt.datetime) -> dict[str, Any] | None:
    """Take the oldest admitted job of one kind, or return ``None`` when nothing waits.

    Called by the process that can do the work — never by the network. One claimer at a time is the
    journal's own exclusive lock (`observer/journal.py::Journal.lock`), which the caller holds for the
    duration; this statement is what makes "was this job already taken?" and "it is mine" one fact.
    """
    ensure(db)
    with db:
        row = db.execute(f'SELECT job_id FROM {JOBS_TABLE} WHERE kind = ? AND status = ?'
                         ' ORDER BY rowid LIMIT 1', (kind, 'accepted')).fetchone()
        if row is None:
            return None
        db.execute(f"UPDATE {JOBS_TABLE} SET status = 'running', started_at = ?, claimed_by = ?"
                   ' WHERE job_id = ? AND status = ?', (_text(now), worker, row[0], 'accepted'))
    return record(_fetch(db, row[0]))


def finish(db: sqlite3.Connection, *, job_id: str, worker: str, status: str,
           result: dict[str, Any] | None = None, error: str | None = None,
           now: dt.datetime) -> dict[str, Any]:
    """Close out one running job with the report its claimer produced.

    Only the process holding the claim may report on it: a second runner finishing a job it never claimed
    would overwrite the first one's answer, which is the same defect `Store.claim_action` refuses for an
    action execution.

    Raises:
        JobError: 400 for a status outside the vocabulary or a refusal code that is not public;
            409 when the job is not this worker's to report on.
    """
    ensure(db)
    if status not in ('succeeded', 'failed', 'cancelled', 'unknown'):
        raise JobError(400, 'invalid_request', 'A job may only be closed with a terminal state')
    if error is not None and (not isinstance(error, str) or _PUBLIC_CODES.fullmatch(error) is None):
        # Exception prose is never durable state: a transport message can carry a payload, a path or a
        # token, and a job row is readable. The class of refusal is the whole diagnosis.
        raise JobError(400, 'invalid_request', 'A job error must be a public refusal code')
    row = _fetch(db, job_id)
    if row is None:
        raise JobError(404, 'not_found', 'No such job')
    if row['status'] != 'running' or row['claimed_by'] != worker:
        raise JobError(409, 'conflict', 'Only the process running a job may report its outcome')
    payload = None if result is None else canonical(result)
    with db:
        db.execute(f'UPDATE {JOBS_TABLE} SET status = ?, result = ?, error = ?, finished_at = ?'
                   ' WHERE job_id = ?', (status, payload, error, _text(now), job_id))
    return record(_fetch(db, job_id))


def run_now(db: sqlite3.Connection, *, job_id: str, worker: str, work: Callable[[], dict[str, Any]],
            now: dt.datetime) -> dict[str, Any]:
    """Claim one named job, do its work, and record the outcome whatever happened.

    Used for the work this service can perform itself (`platform` jobs). `work` raising is a job outcome,
    not a failed request: the caller has already been answered `202`, so the only place the refusal can go
    is the row. A public code from the raising module is stored; anything else is `job_failed`.
    """
    ensure(db)
    with db:
        changed = db.execute(f"UPDATE {JOBS_TABLE} SET status = 'running', started_at = ?, claimed_by = ?"
                             ' WHERE job_id = ? AND status = ?', (_text(now), worker, job_id, 'accepted'))
        if not changed.rowcount:
            raise JobError(409, 'conflict', 'This job is already running or finished')
    try:
        result = work()
        return finish(db, job_id=job_id, worker=worker, status='succeeded', result=result, now=now)
    except Exception as exc:  # noqa: BLE001 - a job's failure is data, and every exception is one
        code = str(exc) if _PUBLIC_CODES.fullmatch(str(exc)) else 'job_failed'
        return finish(db, job_id=job_id, worker=worker, status='failed', error=code, now=now)


def cancel(db: sqlite3.Connection, *, job_id: str, actor: str, now: dt.datetime) -> dict[str, Any]:
    """Withdraw a job that has not started, and say plainly why one that has cannot be withdrawn.

    Returns:
        The job record — `cancelled`, with `finished_at` set — or the unchanged `succeeded`/`failed`/
        `cancelled` record of a job that already finished (a withdrawal of a finished job is a read of it,
        and an idempotent caller must not be punished for asking twice).

    Raises:
        JobError: 404 for a job this queue never admitted; 409 for a running job, naming what does end it.
    """
    ensure(db)
    row = _fetch(db, job_id)
    if row is None:
        raise JobError(404, 'not_found', 'No such job')
    if row['status'] == 'running':
        raise JobError(409, 'conflict',
                       'A running job is ended by its own deadline, not by this request; read the job again')
    if row['status'] == 'accepted':
        with db:
            db.execute(f"UPDATE {JOBS_TABLE} SET status = 'cancelled', finished_at = ?,"
                       " error = NULL, claimed_by = ? WHERE job_id = ? AND status = 'accepted'",
                       (_text(now), f'withdrawn-by:{actor}', job_id))
        return record(_fetch(db, job_id))
    return record(row)


def read(db: sqlite3.Connection, job_id: str, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Return one job, after judging whether a `running` row still describes live work.

    Raises:
        JobError: 404 `not_found` — which covers both "this queue never admitted that id" and "the job
            belongs to another installation", because neither answer is useful to a caller and the second
            one is a fact about this process's state.
    """
    ensure(db)
    reclaim(db, now=now or dt.datetime.now(dt.timezone.utc))
    row = _fetch(db, job_id) if isinstance(job_id, str) and _IDENTIFIER.fullmatch(job_id) else None
    if row is None:
        raise JobError(404, 'not_found', 'No such job')
    return record(row)


def page(db: sqlite3.Connection, *, limit: int = MAX_PAGE, cursor: str | None = None,
         now: dt.datetime | None = None) -> dict[str, Any]:
    """Return the newest jobs, newest first, with the cursor that continues the page.

    `cursor` carries the `job_id` of the last row of the previous page; a token this service never issued
    is refused by `api_contract.decode_cursor` before a query is written, and a job id that is no longer
    retained answers an empty page rather than an error — the caller has seen everything still there.
    The bound is repeated here rather than trusted to the route, so a later caller cannot ask for more
    rows than this surface has ever promised by naming its own limit.
    """
    ensure(db)
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise JobError(400, 'invalid_request', f'A job page is between 1 and {MAX_PAGE} rows')
    reclaim(db, now=now or dt.datetime.now(dt.timezone.utc))
    if cursor is None:
        rows = db.execute(f'SELECT * FROM {JOBS_TABLE} ORDER BY rowid DESC LIMIT ?', (limit,)).fetchall()
    else:
        position = db.execute(f'SELECT rowid FROM {JOBS_TABLE} WHERE job_id = ?', (cursor,)).fetchone()
        rows = db.execute(f'SELECT * FROM {JOBS_TABLE} WHERE rowid < ? ORDER BY rowid DESC LIMIT ?',
                          (position[0] if position else 0, limit)).fetchall()
    document = page_payload([record(row) for row in rows], limit=limit,
                            cursor_for=lambda item: item['job_id'])
    document['statuses'] = list(STATUSES)
    return document


def reclaim(db: sqlite3.Connection, *, now: dt.datetime, after_seconds: int = JOB_STALE_SECONDS) -> int:
    """Turn a `running` row nobody reported on into `unknown`, and return how many there were.

    Bounded work per call and no new scheduler, the way `api_idempotency`'s expiry sweep is: this runs at
    the head of a read, so the queue cannot accrete a phantom `running` job for the life of the file.

    `finished_at` is the instant this process stopped believing the row described live work, not the
    instant the work ended — which is exactly what `unknown` means, and the one thing a later reader must
    not infer from that column is that somebody saw the job stop.
    """
    ensure(db)
    with db:
        return db.execute("UPDATE platform_jobs SET status = 'unknown', finished_at = ?"
                          " WHERE status = 'running' AND started_at IS NOT NULL AND started_at < ?",
                          (_text(now), _text(now - dt.timedelta(seconds=after_seconds)))).rowcount


def record(row: sqlite3.Row) -> dict[str, Any]:
    """Project one stored row into the document a caller reads.

    `argument` is re-parsed rather than echoed as text so a caller sees the object it sent, and `result`
    is ``None`` until a runner reported one — an absent result is not a failure, and a `running` job with
    no result is the truth.
    """
    return {'job_id': row['job_id'], 'kind': row['kind'], 'runner': row['runner'],
            'actor': row['actor'], 'status': row['status'],
            'argument': _loads(row['argument']),
            'result': None if row['result'] is None else _loads(row['result']),
            'error': row['error'], 'created_at': row['created_at'], 'started_at': row['started_at'],
            'finished_at': row['finished_at'], 'claimed_by': row['claimed_by']}


def _fetch(db: sqlite3.Connection, job_id: str) -> sqlite3.Row | None:
    return db.execute(f'SELECT * FROM {JOBS_TABLE} WHERE job_id = ?', (job_id,)).fetchone()


def _loads(text: str) -> Any:
    import json
    return json.loads(text)


def _text(now: dt.datetime) -> str:
    from local_observe.inventory.validation import utc_text
    return utc_text(now)


__all__ = ['JOBS_TABLE', 'JOB_STALE_SECONDS', 'MAX_PAGE', 'RUNNERS', 'RUNNER_OBSERVER', 'RUNNER_PLATFORM',
           'STATUSES', 'JobError', 'admit', 'cancel', 'claim', 'ensure', 'finish', 'identifier', 'page',
           'read', 'record', 'reclaim', 'run_now']

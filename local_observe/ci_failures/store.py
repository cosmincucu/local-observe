"""Durable ingestion state: the cursor, the occurrence window, the delivery journal, the heartbeat.

Four kinds of row, and the distinction between them is the whole design:

* **Facts** (`runs`, `occurrences`, `open_runs`) -- what the Actions API said. Written in the same
  transaction that advances the cursor, so a fact is durable before the pipeline ever claims to have
  passed it. Replay is idempotent by primary key (`event_key`, `(fingerprint, run_id)`), which is what
  makes "re-read the page after a crash" safe instead of expensive.
* **Intent** (`deliveries`) -- what this pipeline decided to write to the board, recorded *before* the
  write and updated after it. Its primary key is a digest of the decision (`create` per fingerprint,
  `comment` per fingerprint-and-batch), so a replayed tick cannot produce a second intent, and a row
  left `pending` is a delivery that still has to happen.
* **Receipt** (`filings`) -- the board issue number this fingerprint is filed against, plus the highest
  run already acknowledged. A receipt is *evidence of a write*, not an incident: incident state is
  `platform/state.py`'s and this table never pretends otherwise.
* **Liveness** (`heartbeat`, `lapses`) -- the last successful tick, and every gap that was judged. The
  lapse rows are written *before* the heartbeat row moves, so returning from a long silence cannot
  erase the lapse it came back from -- see `record_success`.

Everything is one small SQLite file with `synchronous=FULL` and `BEGIN IMMEDIATE`: this database sees
a handful of writes per poll, so the cost of full fsync is irrelevant next to what it buys -- a commit
that either happened or did not, which is the only foundation a "did I already file this card?" answer
can sit on. The journal mode is deliberately the rollback journal, not WAL: an ingestion process that
may be killed between pages must not depend on a `-wal` sidecar surviving to be replayed.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import json
import sqlite3
from pathlib import Path
from typing import Any
from collections.abc import Iterator, Mapping, Sequence

from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from .facts import CoverageNote, RunFact, card_identity, event_identity
from .transports import CiFailureError

log = get_logger(__name__)

__all__ = ['CiFailureStore', 'Delivery', 'DeliveryBlocked', 'FAILING_OUTCOMES', 'HeartbeatVerdict',
           'StoreError', 'WindowStats', 'DEFAULT_RETENTION_DAYS', 'DEFAULT_WINDOW_DAYS',
           'DELIVERY_STATES', 'STATE_ADOPTED', 'STATE_DELIVERED', 'STATE_PENDING', 'STATE_SUPERSEDED']

SCHEMA_VERSION = 1
MAX_REASON_CHARS = 300
MAX_DETAIL_BYTES = 32768
#: The seven-day recurrence window the card's threshold is written against, and the retention floor for
#: a row that is no longer inside any window. Retention is a bound, not a tidy-up: an unbounded table
#: of every CI run forever is a memory leak with a nice story.
DEFAULT_WINDOW_DAYS = 7
DEFAULT_RETENTION_DAYS = 35
#: How late a gap may be judged. `lapses` older than this are still answerable but no longer created --
#: a process resurrected after a month reports the outage it survived, once.
MAX_LAPSE_HOURS = 168

STATE_PENDING = 'pending'
STATE_DELIVERED = 'delivered'
STATE_ADOPTED = 'adopted'
STATE_SUPERSEDED = 'superseded'
DELIVERY_STATES = (STATE_PENDING, STATE_DELIVERED, STATE_ADOPTED, STATE_SUPERSEDED)

#: The outcomes that belong in a fingerprint window. One list, here, because `record_facts` decides
#: which occurrence rows exist and `pipeline` decides which facts to hand it -- two copies of that
#: list is how a card silently stops counting one class of failure.
FAILING_OUTCOMES = ('failure', 'cancelled', 'timed_out', 'action_required', 'stuck')

SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (event_key TEXT PRIMARY KEY, repository TEXT NOT NULL,
    run_id INTEGER NOT NULL, fingerprint TEXT NOT NULL, plane TEXT NOT NULL, head_sha TEXT NOT NULL,
    status TEXT NOT NULL, conclusion TEXT NOT NULL, outcome TEXT NOT NULL,
    recorded_at TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS refusals (id TEXT PRIMARY KEY, repository TEXT NOT NULL, run_id INTEGER,
    reason TEXT NOT NULL, detail TEXT NOT NULL, recorded_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS coverage (id TEXT PRIMARY KEY, source TEXT NOT NULL, reason TEXT NOT NULL,
    detail TEXT NOT NULL, observed_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS occurrences (fingerprint TEXT NOT NULL, run_id INTEGER NOT NULL,
    repository TEXT NOT NULL, event_key TEXT NOT NULL, head_sha TEXT NOT NULL, plane TEXT NOT NULL,
    outcome TEXT NOT NULL, observed_at TEXT NOT NULL, PRIMARY KEY (fingerprint, run_id));
CREATE TABLE IF NOT EXISTS open_runs (run_id INTEGER NOT NULL, repository TEXT NOT NULL,
    head_sha TEXT NOT NULL, status TEXT NOT NULL, first_seen_at TEXT NOT NULL,
    waiting_since TEXT, stuck_reported INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (repository, run_id));
CREATE TABLE IF NOT EXISTS filings (fingerprint TEXT PRIMARY KEY, repository TEXT NOT NULL,
    issue_number INTEGER NOT NULL, title TEXT NOT NULL, filed_at TEXT NOT NULL,
    last_ack_run INTEGER NOT NULL, occurrences_filed INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
    repository TEXT NOT NULL, action TEXT NOT NULL CHECK (action IN ('create','comment')),
    state TEXT NOT NULL CHECK (state IN ('pending','delivered','adopted','superseded')),
    attempts INTEGER NOT NULL DEFAULT 0, issue_number INTEGER, run_ids TEXT NOT NULL,
    detail TEXT NOT NULL, reason TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS heartbeat (key TEXT PRIMARY KEY, last_success_at TEXT NOT NULL,
    outcome TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lapses (id TEXT PRIMARY KEY, started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL, gap_seconds REAL NOT NULL, source TEXT NOT NULL,
    judged_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS occurrences_time ON occurrences(observed_at);
CREATE INDEX IF NOT EXISTS deliveries_state ON deliveries(state, created_at);
CREATE INDEX IF NOT EXISTS coverage_time ON coverage(observed_at);
'''


class StoreError(CiFailureError):
    """The state file cannot be used: unreadable, wrong version, or asked to do something unbounded."""


class DeliveryBlocked(StoreError):
    """A delivery row moved to a state that requires a receipt the caller did not supply."""


class WindowStats:
    """What the occurrence window says about one fingerprint at one instant.

    `count` is a number of failing *runs* and `distinct_shas` the SHAs they landed on; both are needed
    because a count alone would let one SHA's twin builds look like recurrence. The run ids travel with
    them because a card has to link something a human can open.
    """

    __slots__ = ('count', 'distinct_shas', 'first_seen', 'last_seen', 'run_ids', 'shas', 'planes')

    def __init__(self, count: int, distinct_shas: int, first_seen: dt.datetime | None,
                 last_seen: dt.datetime | None, run_ids: Sequence[int], shas: Sequence[str],
                 planes: Sequence[str]):
        self.count = count
        self.distinct_shas = distinct_shas
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.run_ids = tuple(run_ids)
        self.shas = tuple(shas)
        self.planes = tuple(planes)

    def brief(self) -> str:
        return (f'{self.count} occurrence(s) across {self.distinct_shas} sha(s), '
                f'{len(self.planes)} plane(s)')

    def as_dict(self) -> dict[str, Any]:
        return {'count': self.count, 'distinct_shas': self.distinct_shas,
                'first_seen': None if self.first_seen is None else utc_text(self.first_seen),
                'last_seen': None if self.last_seen is None else utc_text(self.last_seen),
                'run_ids': list(self.run_ids), 'shas': list(self.shas), 'planes': sorted(self.planes)}


class HeartbeatVerdict:
    """The answer to "has this poller checked in lately?", judged without writing anything.

    `state` is `ok`, `lapsed`, or `cold-start` (no successful tick has ever been recorded -- which is
    *not* `ok`: a process that has never worked and a process that stopped working look identical to a
    monitor that defaults its answer).
    """

    __slots__ = ('state', 'last_success_at', 'age_seconds', 'deadline_seconds', 'outcome')

    def __init__(self, state: str, last_success_at: dt.datetime | None, age_seconds: float | None,
                 deadline_seconds: float, outcome: str | None):
        self.state = state
        self.last_success_at = last_success_at
        self.age_seconds = age_seconds
        self.deadline_seconds = deadline_seconds
        self.outcome = outcome

    @property
    def lapsed(self) -> bool:
        return self.state != 'ok'

    def as_dict(self) -> dict[str, Any]:
        return {'state': self.state,
                'last_success_at': None if self.last_success_at is None else utc_text(self.last_success_at),
                'age_seconds': self.age_seconds, 'deadline_seconds': self.deadline_seconds,
                'outcome': self.outcome, 'lapsed': self.lapsed}


class Delivery:
    """One row of the delivery journal, as the outlet sees it."""

    __slots__ = ('id', 'fingerprint', 'repository', 'action', 'state', 'attempts', 'issue_number',
                 'run_ids', 'detail', 'reason', 'created_at', 'updated_at')

    def __init__(self, row: sqlite3.Row):
        self.id = row['id']
        self.fingerprint = row['fingerprint']
        self.repository = row['repository']
        self.action = row['action']
        self.state = row['state']
        self.attempts = row['attempts']
        self.issue_number = row['issue_number']
        self.run_ids = tuple(json.loads(row['run_ids']))
        self.detail = json.loads(row['detail'])
        self.reason = row['reason']
        self.created_at = timestamp(row['created_at'])
        self.updated_at = timestamp(row['updated_at'])

    @property
    def blocked(self) -> bool:
        """Pending *and* a previous attempt failed: observable, not a silent queue."""
        return self.state == STATE_PENDING and bool(self.reason)

    def as_dict(self) -> dict[str, Any]:
        return {'id': self.id, 'fingerprint': self.fingerprint, 'action': self.action,
                'state': self.state, 'attempts': self.attempts, 'issue_number': self.issue_number,
                'run_ids': list(self.run_ids), 'reason': self.reason, 'blocked': self.blocked}


class CiFailureStore:
    """One file, one writer, four kinds of row. Every mutation is a single transaction."""

    def __init__(self, path: Path | str, *, window_days: int = DEFAULT_WINDOW_DAYS,
                 retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
        if not 1 <= int(window_days) <= 7 or not int(retention_days) >= int(window_days):
            raise StoreError('Invalid occurrence window/retention')
        self.path = Path(path)
        if self.path.is_symlink():
            raise StoreError('Refusing a symlinked state path')
        self.window_days = int(window_days)
        self.retention_days = int(retention_days)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=5.0, isolation_level=None,
                                          check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA journal_mode=DELETE')
        self.connection.execute('PRAGMA synchronous=FULL')
        self.connection.execute('PRAGMA foreign_keys=ON')
        self._open_or_create()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> CiFailureStore:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.connection.execute('BEGIN IMMEDIATE')
        try:
            yield self.connection
        except BaseException:
            self.connection.execute('ROLLBACK')
            raise
        self.connection.execute('COMMIT')

    def _open_or_create(self) -> None:
        fresh = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'").fetchone() is None
        with self.transaction() as connection:
            for statement in SCHEMA.split(';'):
                if statement.strip():
                    connection.execute(statement)
            version = connection.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            if version is None:
                connection.execute("INSERT INTO meta(key, value) VALUES('schema_version', ?)",
                                   (str(SCHEMA_VERSION),))
            elif version['value'] != str(SCHEMA_VERSION):
                raise StoreError(f'State schema version {version["value"]} is not {SCHEMA_VERSION}')
            if fresh:
                connection.execute("INSERT INTO meta(key, value) VALUES('run_cursor', '0')")

    # ---- cursor -------------------------------------------------------------

    def cursor(self) -> int:
        row = self.connection.execute("SELECT value FROM meta WHERE key='run_cursor'").fetchone()
        if row is None:
            raise StoreError('Run cursor is missing from the state file')
        return int(row['value'])

    def set_cursor(self, value: int, now: dt.datetime) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise StoreError('Invalid cursor value')
        with self.transaction() as connection:
            connection.execute("INSERT INTO meta(key, value) VALUES('run_cursor', ?) "
                               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(value),))
            connection.execute("INSERT INTO meta(key, value) VALUES('cursor_at', ?) "
                               "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                               (utc_text(now),))

    # ---- facts --------------------------------------------------------------

    def record_facts(self, facts: Sequence[RunFact], *, cursor: int, now: dt.datetime,
                     outcomes: Sequence[str] | None = None) -> list[tuple[RunFact, str]]:
        """Store facts (and optionally move the cursor) in one commit; return `[(fact, outcome)]` that
        were new -- a *list of pairs*, never a count, and the caller iterates it.

        Returning the new pairs rather than a count is what makes the send path run on novelty instead of
        on the caller's memory: a fact re-read after a restart is stored without complaint and comes back
        absent from this list, so it is never admitted twice and never planned as a new occurrence twice.

        Two identity layers, deliberately different :

        * `runs.event_key` -- the *event*: `(repository, workflow, head_sha, plane-class, verdict)`. The
          push and PR twin builds of one SHA land on one row, so the incident the platform opens is one
          incident, which is the collapse the card asks for.
        * `occurrences (fingerprint, run_id)` -- one row per failing *run* in a fingerprint's window, so
          the card threshold counts recurrences. Twins therefore contribute two occurrences and one
          event, and that is why the threshold also demands two distinct SHAs rather than trusting a
          count alone.
        """
        if cursor < 0:
            raise StoreError('Cursor may not move backwards')
        labels = tuple(outcomes) if outcomes is not None else None
        fresh: list[tuple[RunFact, str]] = []
        with self.transaction() as connection:
            for position, fact in enumerate(facts):
                outcome = fact.failure_class() if labels is None else labels[position]
                identity = card_identity(fact)
                event_key = event_identity(fact)
                observed = utc_text(fact.observed_at or now)
                detail = canonical({'signature': identity.signature, 'coarse': identity.coarse,
                                    'reasons': list(identity.reasons), 'workflow': fact.workflow_name,
                                    'coverage': [note.line() for note in fact.coverage],
                                    'excerpt': fact.excerpt, 'jobs': [job.name for job in fact.jobs]})
                already = connection.execute('SELECT 1 FROM runs WHERE event_key=?',
                                             (event_key,)).fetchone() is not None
                connection.execute(
                    'INSERT INTO runs(event_key, repository, run_id, fingerprint, plane, head_sha,'
                    ' status, conclusion, outcome, recorded_at, detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)'
                    ' ON CONFLICT(event_key) DO UPDATE SET run_id=excluded.run_id,'
                    ' outcome=excluded.outcome, recorded_at=excluded.recorded_at,'
                    ' detail=excluded.detail',
                    (event_key, fact.repository, fact.run_id, identity.fingerprint, fact.plane,
                     fact.head_sha, fact.status, fact.conclusion, outcome, utc_text(now),
                     detail[:MAX_DETAIL_BYTES]))
                novelty = not already
                if fact.status == 'completed':
                    # A run that settles replaces its own starvation placeholder. The `stuck` row was a
                    # *status transition* counted while the run was still waiting, and it can sit under a
                    # coarser fingerprint (no log, no failing step) than the verdict now arriving. Left in
                    # place it would make one starved-then-failed run two occurrences of "something is
                    # wrong with this build", and two cards -- so the run keeps exactly one counted row.
                    connection.execute("DELETE FROM occurrences WHERE repository=? AND run_id=?"
                                       " AND outcome='stuck'", (fact.repository, fact.run_id))
                if outcome in FAILING_OUTCOMES:
                    occurrence = connection.execute(
                        'INSERT INTO occurrences(fingerprint, run_id, repository, event_key, head_sha,'
                        ' plane, outcome, observed_at) VALUES(?,?,?,?,?,?,?,?)'
                        ' ON CONFLICT(fingerprint, run_id) DO NOTHING',
                        (identity.fingerprint, fact.run_id, fact.repository, event_key, fact.head_sha,
                         fact.plane, outcome, observed))
                    novelty = novelty or bool(occurrence.rowcount)
                if novelty:
                    fresh.append((fact, outcome))
            connection.execute("INSERT INTO meta(key, value) VALUES('last_fact_at', ?) ON CONFLICT(key)"
                               ' DO UPDATE SET value=excluded.value', (utc_text(now),))
            connection.execute("INSERT INTO meta(key, value) VALUES('run_cursor', ?) ON CONFLICT(key)"
                               ' DO UPDATE SET value=excluded.value', (str(cursor),))
        return fresh

    def mark_stuck_reported(self, repository: str, run_id: int, now: dt.datetime) -> None:
        with self.transaction() as connection:
            connection.execute('UPDATE open_runs SET stuck_reported=1 WHERE repository=? AND run_id=?',
                               (repository, int(run_id)))

    def stuck_reported(self, repository: str, run_id: int) -> bool:
        """Whether this run's starvation has already been told -- the flag that folds a storm.

        Read from the row rather than from process memory: a poller that restarts every five minutes
        would otherwise re-report the same starved runner on every boot and call each report a new
        occurrence.
        """
        row = self.connection.execute('SELECT stuck_reported FROM open_runs WHERE repository=?'
                                      ' AND run_id=?', (repository, int(run_id))).fetchone()
        return row is not None and int(row['stuck_reported']) == 1

    def track_open_run(self, fact: RunFact, now: dt.datetime) -> dt.datetime | None:
        """Remember a non-terminal run; return the instant it started waiting, or None if it is new.

        The starved-runner class (`waiting` past a deadline) needs a *first-seen* time that outlives a
        restart, and one row per `(repository, run_id)` is that. Re-admitting the same waiting run after
        a restart keeps the original `waiting_since`, so a restart cannot reset the 20-minute clock --
        which is the difference between reporting a starvation once and never reporting it.
        """
        waiting = fact.started_waiting_at or fact.created_at or now
        with self.transaction() as connection:
            row = connection.execute('SELECT waiting_since FROM open_runs WHERE repository=? AND run_id=?',
                                     (fact.repository, fact.run_id)).fetchone()
            if row is None:
                connection.execute(
                    'INSERT INTO open_runs(run_id, repository, head_sha, status, first_seen_at,'
                    ' waiting_since, stuck_reported) VALUES(?,?,?,?,?,?,0)',
                    (fact.run_id, fact.repository, fact.head_sha, fact.status, utc_text(now),
                     utc_text(waiting)))
                return None
            connection.execute('UPDATE open_runs SET status=?, head_sha=? WHERE repository=? AND run_id=?',
                               (fact.status, fact.head_sha, fact.repository, fact.run_id))
            return timestamp(row['waiting_since']) if row['waiting_since'] else waiting

    def drop_open_run(self, repository: str, run_id: int) -> None:
        with self.transaction() as connection:
            connection.execute('DELETE FROM open_runs WHERE repository=? AND run_id=?',
                               (repository, int(run_id)))

    def open_run_ids(self, repository: str) -> list[int]:
        rows = self.connection.execute('SELECT run_id FROM open_runs WHERE repository=?',
                                       (repository,)).fetchall()
        return sorted(int(row['run_id']) for row in rows)

    def recorded_runs(self, repository: str) -> set[int]:
        rows = self.connection.execute('SELECT run_id FROM runs WHERE repository=?', (repository,)).fetchall()
        return {int(row['run_id']) for row in rows}

    def refusal(self, repository: str, reason: str, detail: str, *, run_id: int | None = None,
                now: dt.datetime | None = None) -> None:
        """Record a payload this parser refused. Durable and deduped, because a silent skip is a lie."""
        moment = now or dt.datetime.now(dt.timezone.utc)
        record_id = digest(['refusal', repository, run_id, reason, detail[:MAX_REASON_CHARS]])
        with self.transaction() as connection:
            connection.execute('INSERT INTO refusals(id, repository, run_id, reason, detail,'
                               ' recorded_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                               (record_id, repository, run_id, reason[:MAX_REASON_CHARS],
                                detail[:MAX_REASON_CHARS], utc_text(moment)))

    def coverage(self, source: str, note: CoverageNote, *, observed_at: dt.datetime | None = None,
                 now: dt.datetime | None = None) -> None:
        """Record one coverage gap about a source, idempotent by (source, reason, minute).

        Idempotency is per-minute on purpose: a source that stays broken for an hour should say so
        repeatedly to a monitor that only reads the newest row, and should not add 3,600 identical
        rows while it does.
        """
        moment = now or dt.datetime.now(dt.timezone.utc)
        seen = observed_at or moment
        bucket = seen.replace(second=0, microsecond=0)
        record_id = digest(['coverage', source, note.reason, note.detail, utc_text(bucket)])
        with self.transaction() as connection:
            connection.execute('INSERT INTO coverage(id, source, reason, detail, observed_at)'
                               ' VALUES(?,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                               (record_id, source, note.reason[:MAX_REASON_CHARS],
                                note.detail[:MAX_REASON_CHARS], utc_text(seen)))

    def coverage_rows(self, *, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.connection.execute('SELECT source, reason, detail, observed_at FROM coverage'
                                       ' ORDER BY observed_at DESC, id LIMIT ?', (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    def refusal_rows(self, *, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.connection.execute('SELECT repository, run_id, reason, detail, recorded_at'
                                       ' FROM refusals ORDER BY recorded_at DESC, id LIMIT ?',
                                       (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    # ---- window / folding ---------------------------------------------------

    def window(self, fingerprint: str, *, now: dt.datetime,
               days: int | None = None) -> WindowStats:
        """The occurrences of one fingerprint inside the recurrence window, oldest first.

        `run_ids` come back **ascending** rather than in observed order: they are the set of runs this
        incident has touched, they are stored on the delivery row, and a comment batch token is derived
        from them. A sequence whose order depends on which row happened to be written last is a fingerprint
        that can move under a replay, so the summary is sorted at the seam that produces it.
        """
        span = self.window_days if days is None else int(days)
        if not 1 <= span <= 7:
            raise StoreError('Invalid occurrence window')
        cutoff = utc_text(now - dt.timedelta(days=span))
        rows = self.connection.execute(
            'SELECT run_id, head_sha, plane, observed_at FROM occurrences WHERE fingerprint=?'
            ' AND observed_at>=? ORDER BY observed_at, run_id', (fingerprint, cutoff)).fetchall()
        if not rows:
            return WindowStats(0, 0, None, None, (), (), ())
        shas = tuple(dict.fromkeys(row['head_sha'] for row in rows))
        return WindowStats(len(rows), len(shas), timestamp(rows[0]['observed_at']),
                           timestamp(rows[-1]['observed_at']),
                           tuple(sorted(int(row['run_id']) for row in rows)), shas,
                           tuple(dict.fromkeys(row['plane'] for row in rows)))

    def occurrences_of(self, fingerprint: str, *, days: int | None = None,
                       now: dt.datetime | None = None) -> list[dict[str, Any]]:
        cutoff = None if now is None else utc_text(
            now - dt.timedelta(days=self.window_days if days is None else int(days)))
        statement = ('SELECT run_id, repository, head_sha, plane, outcome, observed_at FROM occurrences'
                     ' WHERE fingerprint=?')
        params: list[Any] = [fingerprint]
        if cutoff is not None:
            statement += ' AND observed_at>=?'
            params.append(cutoff)
        rows = self.connection.execute(statement + ' ORDER BY observed_at, run_id', params).fetchall()
        return [dict(row) for row in rows]

    def run_detail(self, repository: str, run_id: int) -> dict[str, Any] | None:
        """What the store knows about one run -- its **latest** recorded event.

        One run can own two `runs` rows: the unfinished event (while it was queued or running) and the
        finished one (once its verdict arrives), because `event_key` deliberately carries a
        finished/stuck class. An unordered lookup therefore answered "waiting" for a run whose failure had
        already been ingested -- for a `--run`-style reader, and for any operator asking what the poller
        knows, that reads as a lost incident. Newest-recorded, with the event key as a tie-break so the
        answer does not depend on insert order.
        """
        row = self.connection.execute('SELECT run_id, detail, fingerprint, head_sha, plane, outcome FROM runs'
                                      ' WHERE repository=? AND run_id=? ORDER BY recorded_at DESC, event_key'
                                      ' LIMIT 1',
                                      (repository, int(run_id))).fetchone()
        if row is None:
            return None
        detail = json.loads(row['detail'])
        detail.update({'fingerprint': row['fingerprint'], 'head_sha': row['head_sha'],
                       'plane': row['plane'], 'outcome': row['outcome'], 'run_id': int(row['run_id'])})
        return detail

    # ---- receipts -----------------------------------------------------------

    def filing(self, fingerprint: str) -> dict[str, Any] | None:
        row = self.connection.execute('SELECT * FROM filings WHERE fingerprint=?', (fingerprint,)).fetchone()
        return dict(row) if row is not None else None

    def remember_filing(self, fingerprint: str, repository: str, issue_number: int, title: str,
                        *, occurrences_filed: int, last_ack_run: int, now: dt.datetime) -> None:
        if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number <= 0:
            raise StoreError('Filing receipt needs a positive issue number')
        with self.transaction() as connection:
            connection.execute(
                'INSERT INTO filings(fingerprint, repository, issue_number, title, filed_at,'
                ' last_ack_run, occurrences_filed) VALUES(?,?,?,?,?,?,?) ON CONFLICT(fingerprint)'
                ' DO UPDATE SET issue_number=excluded.issue_number, title=excluded.title,'
                ' occurrences_filed=excluded.occurrences_filed, last_ack_run=excluded.last_ack_run',
                (fingerprint, repository, issue_number, title[:MAX_REASON_CHARS], utc_text(now),
                 int(last_ack_run), int(occurrences_filed)))

    def forget_filing(self, fingerprint: str) -> None:
        with self.transaction() as connection:
            connection.execute('DELETE FROM filings WHERE fingerprint=?', (fingerprint,))

    def acknowledged_runs(self, fingerprint: str) -> set[int]:
        """Every run id this outlet has already reported for the fingerprint, in any delivery state that
        means "the board has it".

        Comments *and* creates count: the card body lists the runs that met the threshold, so a later
        comment is about the runs that arrived since. This is the anti-duplicate rule for the comment
        path -- the journal, not the caller's memory, decides whether an occurrence has been announced,
        so a process that restarts mid-batch resumes the batch instead of re-announcing the runs already
        on the card.
        """
        rows = self.connection.execute('SELECT run_ids FROM deliveries WHERE fingerprint=?'
                                       " AND state IN ('delivered','adopted')",
                                       (fingerprint,)).fetchall()
        acknowledged: set[int] = set()
        for row in rows:
            acknowledged.update(int(value) for value in json.loads(row['run_ids']))
        return acknowledged

    # ---- delivery journal ---------------------------------------------------

    def plan_delivery(self, *, fingerprint: str, repository: str, action: str, run_ids: Sequence[int],
                      detail: Mapping[str, Any], now: dt.datetime) -> tuple[str, bool]:
        """Record the intent to write, before the write. Returns `(id, newly_recorded)`.

        The id is a digest of the decision, so the same decision computed twice -- after a restart, or
        by a replayed tick -- lands on the same row. `newly_recorded` is False in that case, and the
        caller must treat that as "there is already a pending delivery for this", never as "nothing to
        do": the existing row may still be waiting to be attempted.
        """
        if action not in ('create', 'comment'):
            raise StoreError('Unknown delivery action')
        ids = tuple(sorted(int(value) for value in run_ids))
        if not ids:
            raise StoreError('A delivery must name the run it speaks for')
        record_id = digest(['delivery', action, fingerprint, max(ids)])
        payload = canonical(dict(detail))[:MAX_DETAIL_BYTES]
        with self.transaction() as connection:
            existing = connection.execute('SELECT state, attempts FROM deliveries WHERE id=?',
                                          (record_id,)).fetchone()
            connection.execute(
                'INSERT INTO deliveries(id, fingerprint, repository, action, state, attempts,'
                ' run_ids, detail, created_at, updated_at) VALUES(?,?,?,?,?,?,?, ?,?,?)'
                ' ON CONFLICT(id) DO NOTHING',
                (record_id, fingerprint, repository, action, STATE_PENDING,
                 0 if existing is None else int(existing['attempts']), json.dumps(list(ids)), payload,
                 utc_text(now), utc_text(now)))
        return record_id, existing is None

    def pending_deliveries(self) -> list[Delivery]:
        rows = self.connection.execute(
            "SELECT * FROM deliveries WHERE state='pending' ORDER BY created_at, id").fetchall()
        return [Delivery(row) for row in rows]

    def delivery(self, delivery_id: str) -> Delivery | None:
        row = self.connection.execute('SELECT * FROM deliveries WHERE id=?', (delivery_id,)).fetchone()
        return Delivery(row) if row is not None else None

    def deliveries_for(self, fingerprint: str, action: str | None = None) -> list[Delivery]:
        statement, params = 'SELECT * FROM deliveries WHERE fingerprint=?', [fingerprint]
        if action is not None:
            statement += ' AND action=?'
            params.append(action)
        rows = self.connection.execute(statement + ' ORDER BY created_at, id', params).fetchall()
        return [Delivery(row) for row in rows]

    def mark_delivered(self, delivery_id: str, *, issue_number: int | None, now: dt.datetime) -> None:
        """Close a delivery with its receipt. `create` must carry the issue number it wrote."""
        row = self.connection.execute('SELECT action FROM deliveries WHERE id=?', (delivery_id,)).fetchone()
        if row is None:
            raise StoreError('Unknown delivery id')
        if row['action'] == 'create' and not issue_number:
            raise DeliveryBlocked('A create delivery needs the issue number it created')
        with self.transaction() as connection:
            connection.execute(
                "UPDATE deliveries SET state='delivered', issue_number=COALESCE(?, issue_number),"
                " reason=NULL, updated_at=? WHERE id=?",
                (issue_number, utc_text(now), delivery_id))

    def mark_adopted(self, delivery_id: str, *, issue_number: int, now: dt.datetime) -> None:
        """Close a delivery because the effect was already on the board.

        Adoption is the answer to the only genuinely undecidable case here: the write succeeded and the
        acknowledgement was lost. Reconcile finds the card by its fingerprint line, records the number,
        and the intent is finished -- filing a second copy would be the pipeline doubting its own eyes.
        """
        if isinstance(issue_number, bool) or not isinstance(issue_number, int) or issue_number <= 0:
            raise DeliveryBlocked('Adoption needs the issue number that was found')
        with self.transaction() as connection:
            connection.execute("UPDATE deliveries SET state='adopted', issue_number=?, reason=NULL,"
                               ' updated_at=? WHERE id=?', (issue_number, utc_text(now), delivery_id))

    def mark_blocked(self, delivery_id: str, reason: str, now: dt.datetime) -> None:
        """Keep the intent, add one attempt, and say why it is still pending.

        The state stays `pending`: `blocked` is a property of a pending row (`Delivery.blocked`), not a
        terminal state. Turning a failure into a terminal state is how a board outage silently deletes
        a delivery.
        """
        with self.transaction() as connection:
            connection.execute("UPDATE deliveries SET attempts=attempts+1, reason=?, updated_at=?"
                               " WHERE id=? AND state='pending'",
                               (reason[:MAX_REASON_CHARS], utc_text(now), delivery_id))

    def supersede(self, delivery_id: str, reason: str, now: dt.datetime) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE deliveries SET state='superseded', reason=?, updated_at=?"
                               " WHERE id=?", (reason[:MAX_REASON_CHARS], utc_text(now), delivery_id))

    # ---- liveness -----------------------------------------------------------

    def last_success(self) -> tuple[dt.datetime, str, dict[str, Any]] | None:
        row = self.connection.execute('SELECT * FROM heartbeat WHERE key=?', ('poller',)).fetchone()
        if row is None:
            return None
        return timestamp(row['last_success_at']), row['outcome'], json.loads(row['detail'])

    def check_heartbeat(self, *, now: dt.datetime, deadline_seconds: float) -> HeartbeatVerdict:
        """Judge liveness. Reads only -- the monitor must not be able to repair what it reports.

        This is the function a *separate* process (`--check-heartbeat`, its own scheduler entry) calls.
        It never writes: a monitor that could clear a lapse would also be able to hide one, and the
        card's D4 requirement is that a stopped poller alerts from somewhere else.
        """
        if not 1 <= float(deadline_seconds) <= 86400:
            raise StoreError('Invalid heartbeat deadline')
        seen = self.last_success()
        if seen is None:
            return HeartbeatVerdict('cold-start', None, None, float(deadline_seconds), None)
        last, outcome, _ = seen
        age = (now - last).total_seconds()
        return HeartbeatVerdict('ok' if age <= float(deadline_seconds) else 'lapsed', last, age,
                                float(deadline_seconds), outcome)

    def judge_lapse(self, *, now: dt.datetime, deadline_seconds: float,
                    source: str = 'independent-monitor') -> tuple[HeartbeatVerdict, dict[str, Any] | None]:
        """Record a gap if one is open, from a process that is not the poller. Returns verdict + lapse.

        This is what `--check-heartbeat` calls on its own schedule. Two properties matter:

        * It runs *before* the poller's next `record_success`, so a lapse is on the books even if the
          poller wakes up, succeeds, and would otherwise have moved the timestamp past the gap.
        * The row id digests only the *start* of the gap (`last_success_at`), not the instant it was
          noticed. If this monitor records the gap and the poller later records the same gap on
          recovery, the second insert does nothing -- one outage, one row, whoever saw it first.
        """
        verdict = self.check_heartbeat(now=now, deadline_seconds=deadline_seconds)
        if verdict.state != 'lapsed':
            return verdict, None
        started = verdict.last_success_at
        gap = verdict.age_seconds or 0.0
        if not 0 < gap <= MAX_LAPSE_HOURS * 3600:
            return verdict, None
        lapse_id = digest(['lapse', utc_text(started)])
        with self.transaction() as connection:
            connection.execute('INSERT INTO lapses(id, started_at, ended_at, gap_seconds, source,'
                               ' judged_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                               (lapse_id, utc_text(started), utc_text(now), gap,
                                source[:MAX_REASON_CHARS], utc_text(now)))
        return verdict, {'id': lapse_id, 'started_at': utc_text(started), 'ended_at': utc_text(now),
                         'gap_seconds': gap, 'judged_by': source}

    def record_success(self, *, now: dt.datetime, outcome: str, detail: Mapping[str, Any],
                       deadline_seconds: float, source: str = 'ci-failures-poller') -> dict[str, Any] | None:
        """Judge the gap, write the lapse, *then* move the heartbeat -- in that order, one commit.

        Order is the point. If the timestamp moved first, a poller that came back after three hours
        would overwrite the evidence of its own three-hour silence and every monitor that reads
        `lapses` afterwards would report a healthy pipeline. Because the lapse row is inserted from the
        *old* value in the same transaction that updates it, the recovery proves the outage instead of
        erasing it, and the digest key makes the insert idempotent against a replayed tick.
        """
        if not 1 <= float(deadline_seconds) <= 86400:
            raise StoreError('Invalid heartbeat deadline')
        lapse: dict[str, Any] | None = None
        with self.transaction() as connection:
            row = connection.execute('SELECT last_success_at FROM heartbeat WHERE key=?',
                                     ('poller',)).fetchone()
            if row is not None:
                started = timestamp(row['last_success_at'])
                gap = (now - started).total_seconds()
                if gap > float(deadline_seconds) and 0 < gap <= MAX_LAPSE_HOURS * 3600:
                    lapse_id = digest(['lapse', utc_text(started)])
                    written = connection.execute(
                        'INSERT INTO lapses(id, started_at, ended_at, gap_seconds, source,'
                        ' judged_at) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING',
                        (lapse_id, utc_text(started), utc_text(now), gap,
                         source[:MAX_REASON_CHARS], utc_text(now)))
                    # The id digests only the *start* of the gap, so a lapse an independent monitor already
                    # judged collides here and the insert does nothing. Reporting it anyway would turn one
                    # outage into two alerts -- the monitor's, then this recovery's -- and the second one
                    # would claim a gap nobody had to discover. Only the process that created the row
                    # tells anybody.
                    if written.rowcount:
                        lapse = {'id': lapse_id, 'started_at': utc_text(started),
                                 'ended_at': utc_text(now), 'gap_seconds': gap,
                                 'judged_by': 'poller-recovery'}
            connection.execute(
                'INSERT INTO heartbeat(key, last_success_at, outcome, detail) VALUES(?,?,?,?)'
                ' ON CONFLICT(key) DO UPDATE SET last_success_at=excluded.last_success_at,'
                ' outcome=excluded.outcome, detail=excluded.detail',
                ('poller', utc_text(now), outcome[:64], canonical(dict(detail))[:MAX_DETAIL_BYTES]))
        if lapse is not None:
            log.warning('CI poller recovered from a check-in gap', extra={'gap_seconds': lapse['gap_seconds']})
        return lapse

    def lapses(self, *, limit: int = 20) -> list[dict[str, Any]]:
        rows = self.connection.execute('SELECT * FROM lapses ORDER BY ended_at DESC LIMIT ?',
                                       (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    def unreported_lapses(self, *, watermark: dt.datetime | None = None) -> list[dict[str, Any]]:
        """Lapses newer than a monitor's own watermark -- so each gap is told exactly once.

        The watermark lives with the caller (a monitor's own state), never here: whatever can reset the
        record of what was already reported can also hide a gap.
        """
        statement = 'SELECT * FROM lapses'
        params: list[Any] = []
        if watermark is not None:
            statement += ' WHERE ended_at>?'
            params.append(utc_text(watermark))
        return [dict(row) for row in self.connection.execute(statement + ' ORDER BY ended_at', params)]

    def last_success_row_at(self) -> dt.datetime | None:
        """The raw check-in time, for a monitor that keeps its own watermark. Read-only."""
        row = self.connection.execute("SELECT last_success_at FROM heartbeat WHERE key='poller'").fetchone()
        return timestamp(row['last_success_at']) if row is not None else None

    # ---- retention ----------------------------------------------------------

    def prune(self, *, now: dt.datetime) -> dict[str, int]:
        """Drop rows older than the retention floor. Receipts and the journal are never pruned.

        `deliveries` and `filings` are excluded on purpose: they are the answer to "have I already
        filed this?", and a retention job that deletes the answer turns tomorrow's restart into a
        duplicate card. What gets pruned is history nobody re-reads: old facts, their occurrences, and
        coverage that has since been overtaken.
        """
        floor = utc_text(now - dt.timedelta(days=self.retention_days))
        counts: dict[str, int] = {}
        with self.transaction() as connection:
            for table, column in (('coverage', 'observed_at'), ('refusals', 'recorded_at'),
                                  ('runs', 'recorded_at')):
                counts[table] = connection.execute(f'DELETE FROM {table} WHERE {column}<?',
                                                  (floor,)).rowcount
            counts['occurrences'] = connection.execute(
                'DELETE FROM occurrences WHERE observed_at<? AND fingerprint NOT IN'
                ' (SELECT fingerprint FROM filings)', (floor,)).rowcount
        return counts

    def status(self, *, now: dt.datetime, deadline_seconds: float = 3600) -> dict[str, Any]:
        """One report-shaped dict: cursor, counts, heartbeat verdict, newest coverage and refusals."""
        counts = {table: int(self.connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0])
                  for table in ('runs', 'occurrences', 'deliveries', 'filings', 'coverage', 'refusals',
                                'lapses')}
        pending = self.pending_deliveries()
        return {'schema_version': SCHEMA_VERSION, 'cursor': self.cursor(),
                'counts': counts, 'heartbeat': self.check_heartbeat(now=now,
                                                                    deadline_seconds=deadline_seconds).as_dict(),
                'pending_deliveries': [delivery.as_dict() for delivery in pending],
                'blocked_deliveries': [delivery.as_dict() for delivery in pending if delivery.blocked],
                'latest_coverage': self.coverage_rows(limit=5),
                'latest_refusals': self.refusal_rows(limit=5)}

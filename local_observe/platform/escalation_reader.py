"""Every history read the escalation scheduler decides from: read-only, index-bound, one snapshot .

The scheduler used to judge acknowledgement and liveness from `Store.records` — the capped, newest-first
window the human read surface exposes. That window is 100 rows and it never grows, so the day a platform
had written its 101st event, escalation stopped escalating: every read came back full, `capped` said "an
acknowledgement may exist that I could not see", and the round held — forever. Worse, a *tracked* incident
that aged out of the window looked exactly like one that had been resolved, so ladders were closed by
history having happened. The fix is not a bigger window: no fixed window survives an unbounded table, and a
round whose cost grows with lifetime history is a round that eventually cannot run.

What is said once here, and why each part has to be this shape:

* **One read snapshot per round.** One `mode=ro` connection, one deferred `BEGIN` (never
  `Store.transaction`, which takes the write lock), closed before the scheduler writes anything. The
  discovery page, the tracked incidents and the acknowledgement evidence all come from the same read mark,
  so a row cannot move underneath a decision made about it. Nothing here creates, writes, audits or
  migrates: pointed at a file that does not exist, this module refuses rather than building one.
* **Indexes are named, never hoped for.** Three of the four statements carry `INDEXED BY` with one of the
  names `state.MIGRATIONS[6]` creates. `INDEXED BY` is a refusal and not a hint — a file that has lost an
  index answers "no query solution", which the caller reports as held work. That is what makes these reads
  safe against a table with millions of rows: an accidental full scan is impossible by construction rather
  than by the planner's mood. No index is ever created at runtime; the migration is the only place they
  exist. The fourth statement is an equality on `incidents.id`, whose UNIQUE index the planner cannot
  sensibly decline, and `plans()` below lets a test require that it did not.
* **Discovery is a rowid walk, not a filter.** `status='open' AND rowid>scan_after ORDER BY rowid LIMIT`
  one fixed page. The rule chains are matched in Python, *after* the page: a SQL `WHERE` carrying the rule
  filter would have to read every nonmatching open row of a platform that has had thousands of them, which
  is the unbounded cost this whole file exists to avoid. Progress is a ROWID and never a timestamp —
  `opened_at` is not monotonic (clock adjustments, backfills, two incidents opened in the same second), and
  a discovery key that can go backwards loses rows or repeats them forever.
* **Tracked incidents are read by primary key, independently of the page.** A tracked incident cannot be
  missed because it aged out of a window, and cannot be judged from a page that never reached it. Its
  status column is read from its own row, which is the only positive evidence that may end a ladder.
* **Ack is two EXISTS questions answered in booleans.** Whether a human decided, and whether a page was
  tapped. Both are proved by rows that stay in the table forever, whatever their age, and neither returns a
  payload: an incident with ten thousand historical actions costs the scheduler two integers.
* **Per-incident work is budgeted, and an unfinished read is a named result.** Each incident's own queries
  run inside a fixed SQLite VM-instruction budget. Exceptional per-incident history therefore produces
  *that incident's* `incomplete` answer — which the scheduler holds — instead of a global stop, and instead
  of a guess. Unrelated history cannot spend the budget at all, because it is never scanned: it is stepped
  over by an index seek.

Holding is the safe direction for everything in here. A rung not filed this round is due again next round;
a rung filed over an acknowledgement nobody could read is a page sent to a human who already answered, and
a ladder closed on absent evidence is an incident nobody will be paged about any more.
"""
from __future__ import annotations

from contextlib import closing, suppress
from dataclasses import dataclass
import datetime as dt
import json
from pathlib import Path
import sqlite3
from collections.abc import Mapping, Sequence
from typing import Any

from local_observe.inventory.validation import timestamp
from .state import (ESCALATION_ACTIONS_EXPRESSION, ESCALATION_ACTIONS_INDEX, ESCALATION_AUDIT_INDEX,
                   ESCALATION_INCIDENTS_INDEX, ESCALATION_INTENT_OPERATION, StateError, identifier,
                   label)

#: Rows one discovery page may carry. The fixed cap the scheduler has always cost per round, now spent on
#: *examined* rows instead of on *newest* ones: it bounds one round's work, and a large open-incident set is
#: crossed in a bounded number of rounds instead of never being reached.
DISCOVERY_LIMIT = 100
ROWID_MAXIMUM = 2 ** 63 - 1
#: Virtual machine instructions one incident's reads may cost before that incident is reported incomplete.
#: This bounds excessive work on one incident without charging it for unrelated history.
PROGRESS_INSTRUCTIONS = 128_000
#: How often the progress handler runs. 100 instructions is resolution enough to catch a runaway read and
#: cheap enough to leave installed all round.
PROGRESS_CHECK_INSTRUCTIONS = 100
#: Widest event payload a read will transfer. `state.validate_event` refuses an event over 64 KiB, so this
#: is the bound every row this build wrote obeys; a stored payload above it is never transferred into
#: Python, and the incident it belongs to is reported unreadable rather than guessed about.
PAYLOAD_MAXIMUM_BYTES = 65_536
#: How many acknowledgement status words one read may ask about. The list arrives from the caller and
#: becomes a fixed count of bound placeholders, so no caller text reaches a statement.
STATUS_MAXIMUM = 16

#: The incident read qualities. `open`/`resolved` are the stored status column, read positively; every
#: other word is the absence of an answer, and must never be read as one.
OPEN = 'open'
RESOLVED = 'resolved'
#: No `incidents` row with that id: the incident was never here, which is not the statement "it is over".
MISSING = 'missing'
#: A row exists but this build cannot describe it — a status outside the two its CHECK admits, an
#: unparseable `opened_at`, an id that is not a canonical UUID.
CORRUPT = 'corrupt'
#: This incident's own budget was spent mid-read. Whether anyone acknowledged it is unknown.
INCOMPLETE = 'incomplete'
#: The read was refused: a missing index, a locked or unreadable file, a schema this build did not write.
#: Held work, never absent work.
REFUSED = 'refused'

#: One sentence for every driver failure, raised `from None` so no message carrying a file path rides along,
#: and one for a cursor position that is not a position. Neither of them ever means "no acknowledgement".
READ_FAILED = 'Escalation history could not be read'
SYMLINKED = 'Refusing symlink state database'
SCAN_POSITION_INVALID = 'Escalation scan position must be a non-negative integer'
STATUSES_INVALID = 'Escalation acknowledgement status list is empty or too long'

#: A canonical UUID used only as a bind value by :meth:`EscalationReader.plans`. It names no incident, and
#: an `EXPLAIN` reads no row.
PROBE_ID = '00000000-0000-0000-0000-000000000000'
#: Canonical UUID text is always this long; checked before a parser is reached, so an arbitrary stored value
#: cannot turn a read into somebody else's exception.
_UUID_TEXT = 36

# Static SQL. Every value reaches it as a bound parameter, and the only literals are this module's own words
# and the fixed page cap. `_EVENT_TEXT` is the one event-payload read: the byte bound and `json_valid` are
# decided *inside* SQLite, so a payload this build may not have written is never transferred.
_EVENT_TEXT = ('CASE WHEN e.id IS NOT NULL AND length(CAST(e.payload AS BLOB))<=? AND'
               ' json_valid(e.payload)=1 THEN CAST(e.payload AS BLOB) END')

#: The discovery page. `status` alone is enough to reach the open rows, because inside one status value the
#: index entries are already in rowid order: the walk resumes where it stopped instead of sorting.
DISCOVERY_SQL = (f'SELECT i.rowid, i.id, i.opened_at, {_EVENT_TEXT}'
                 f' FROM incidents AS i INDEXED BY {ESCALATION_INCIDENTS_INDEX}'
                 ' LEFT JOIN events AS e ON e.id=i.last_event_id'
                 " WHERE i.status='open' AND i.rowid>?"
                 f' ORDER BY i.rowid LIMIT {DISCOVERY_LIMIT}')

#: One tracked incident, by primary key. The verdict is read in the same statement as the status, so a
#: tracked incident is never judged from two different moments.
INCIDENT_SQL = (f'SELECT i.status, i.opened_at, {_EVENT_TEXT}'
                ' FROM incidents AS i LEFT JOIN events AS e ON e.id=i.last_event_id'
                ' WHERE i.id=?')

#: An approval intent, found through the partial index on the one operation this question is about, joined
#: to the incident's own actions through the expression index that carries their ids. Age is irrelevant:
#: both halves are seeks, and the answer is one bit.
INTENT_SQL = ('SELECT EXISTS(SELECT 1 FROM audit AS a INDEXED BY ' + ESCALATION_AUDIT_INDEX
              + " WHERE a.operation='" + ESCALATION_INTENT_OPERATION + "'"
              + ' AND a.subject IN (SELECT id FROM actions INDEXED BY ' + ESCALATION_ACTIONS_INDEX
              + ' WHERE ' + ESCALATION_ACTIONS_EXPRESSION + '=?))')

#: The busy timeout every other connection in this package waits, as `sqlite3.connect`'s argument. A read
#: transaction takes no write lock, but a `-wal` still has to be read by somebody.
_BUSY_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class Ack:
    """Whether a human has already acted on one incident, and whether that question got answered.

    `decided` is an `actions` row bound to the incident whose status is past a human decision; `intent` is
    an `action.approval_intent` audit row for one of that incident's actions. Both are EXISTS answers over
    the whole table, so their cost and their truth do not depend on how much has happened since.
    `complete=False` means the question was *not* answered — this incident's budget ran out, or the read was
    refused — and then the two booleans say nothing at all. Which kind of evidence counts as an
    acknowledgement, and what it does to a ladder, is the scheduler's decision and not this module's.
    """
    decided: bool = False
    intent: bool = False
    complete: bool = True
    reason: str | None = None


@dataclass(frozen=True)
class Incident:
    """One tracked incident read by primary key: its own status, its current verdict, its ack evidence.

    `steps` is the VM instructions this incident's reads accounted for — the same ledger the budget is drawn
    from, reported so a caller can say *which* incident cost what rather than calling a round slow.
    """
    incident_id: str
    status: str
    opened_at: dt.datetime | None = None
    event: Mapping[str, Any] | None = None
    ack: Ack | None = None
    steps: int = 0


@dataclass(frozen=True)
class Candidate:
    """One open incident a discovery page carried, with the verdict that opened it.

    `event` is None when the verdict row is absent, too wide to transfer, or not a JSON object: the row was
    examined and could not be judged, which is reported and never repaired.
    """
    incident_id: str
    rowid: int
    opened_at: dt.datetime
    event: Mapping[str, Any] | None


@dataclass(frozen=True)
class Discovery:
    """One page of the rowid walk, and what may honestly be concluded from it.

    `last_rowid` is the highest rowid the page *examined*, including a trailing row whose verdict could not
    be read: an examined row is settled, and the walk advances over it. `exhausted` says the page came back
    short, so the walk reached the end of the table and may restart — a statement about the table, not about
    the caller's own capacity. `complete=False` (with `reason`) means the page never happened.
    """
    rows: tuple[Candidate, ...] = ()
    last_rowid: int | None = None
    exhausted: bool = False
    complete: bool = True
    reason: str | None = None
    unreadable: int = 0
    steps: int = 0


class EscalationReader:
    """One read snapshot of the operational database, held open for exactly one scheduler round.

    Usage is one `with` block: the connect and the deferred `BEGIN` happen on entry, every read in the body
    sees those rows, and the transaction is ended and the connection closed on exit — before the caller
    writes, and whatever the body raised. Progress accounting is reset by each incident's read, so one
    incident's exceptional history is not paid for by the next one.

    One limit of the mechanism is stated rather than glossed: the budget is spent by interrupting a
    statement, and SQLite may end the read transaction when its statement is interrupted. The reads after
    it are then separate consistent reads rather than part of the same snapshot, which is what a scheduler
    that writes nothing while reading can live with — and the round still cannot *write*, because it does
    that only after the snapshot is closed. Nothing about that changes a verdict: a read that was cut short
    is reported incomplete, never reported as an absence of evidence.

    Raises:
        StateError: The status list is empty, oversized or holds a word that is not a bounded label; the
            path is a symlink; or the file cannot be opened and reading cannot start. All of them refuse
            before a row is read, and none of them is ever answered with "there is no acknowledgement".
    """

    def __init__(self, path: Path | str, *, ack_statuses: Sequence[str],
                 progress: int | None = None) -> None:
        words = tuple(ack_statuses)
        if not 1 <= len(words) <= STATUS_MAXIMUM:
            raise StateError(STATUSES_INVALID)
        for word in words:
            label(word)
        self._statuses = words
        # The status count is the only thing a caller influences, and it becomes that many `?`s.
        self._decision_sql = ('SELECT EXISTS(SELECT 1 FROM actions INDEXED BY ' + ESCALATION_ACTIONS_INDEX
                              + ' WHERE ' + ESCALATION_ACTIONS_EXPRESSION + '=? AND status IN ('
                              + ','.join('?' * len(words)) + '))')
        self._budget = PROGRESS_INSTRUCTIONS if progress is None else progress
        self._spent = 0
        self._limit: int | None = None
        self._interrupted = False
        self._armed = False
        self._connection: sqlite3.Connection | None = None
        candidate = Path(path)
        if candidate.is_symlink():
            raise StateError(SYMLINKED)
        self._connection = _connect(candidate)
        try:
            # A deferred read transaction: this snapshot costs no write lock, and it is over before the
            # round that took it writes anything.
            self._connection.execute('BEGIN')
        except sqlite3.Error:
            self.close()
            raise StateError(READ_FAILED) from None

    def __enter__(self) -> EscalationReader:
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.close()
        return False

    def close(self) -> None:
        """End the snapshot. A read transaction is discarded and never committed: nothing here writes."""
        connection, self._connection = self._connection, None
        if connection is None:
            return
        with suppress(sqlite3.Error):
            connection.set_progress_handler(None, 0)
            connection.execute('ROLLBACK')
        with suppress(sqlite3.Error), closing(connection):
            pass

    # --- the reads --------------------------------------------------------------------------

    def discover(self, scan_after: int) -> Discovery:
        """Return the next page of open incidents by rowid, after `scan_after`.

        No rule, resource, stage or ack predicate appears in this statement: the page is every open incident
        in the next slice of the table, and the caller decides which of them its chains own. That is what
        keeps the cost proportional to the *page* rather than to the history, and what lets a candidate the
        caller has no capacity for be revisited later.

        Raises:
            StateError: `scan_after` is not a non-negative integer. A page the database could not answer is
                not an exception: it comes back `complete=False` with a fixed reason, because "I could not
                read" and "there is nothing open" are different statements.
        """
        if type(scan_after) is not int or not 0 <= scan_after <= ROWID_MAXIMUM:
            raise StateError(SCAN_POSITION_INVALID)
        self._arm(None)
        connection = self._connection
        if connection is None:
            return Discovery(complete=False, reason=REFUSED)
        try:
            rows = connection.execute(DISCOVERY_SQL, (PAYLOAD_MAXIMUM_BYTES, scan_after)).fetchall()
        except sqlite3.Error:
            return Discovery(complete=False, reason=self._classify(), steps=_units(self._spent))
        found: list[Candidate] = []
        unreadable = 0
        for rowid, incident_id, opened_at, payload in rows:
            event = _payload(payload)
            moment = _moment(opened_at)
            if moment is None or not _is_uuid(incident_id):
                unreadable += 1                      # examined and unusable: settled, but enrollable by nobody
                continue
            if event is None:
                unreadable += 1
            found.append(Candidate(incident_id=incident_id, rowid=rowid, opened_at=moment, event=event))
        return Discovery(rows=tuple(found), last_rowid=rows[-1][0] if rows else None,
                         exhausted=len(rows) < DISCOVERY_LIMIT,
                         unreadable=unreadable, steps=_units(self._spent))

    def read_incidents(self, incident_ids: Sequence[str]) -> dict[str, Incident]:
        """Read each tracked incident by primary key, with its current verdict and its ack evidence.

        Independent of the discovery page, in the caller's order, one entry per id. An id that is not a
        canonical UUID is reported `corrupt` rather than raised, because a tracked entry that cannot be read
        is held by the caller and must not take the rest of the round down with it.
        """
        return {incident_id: self._incident(incident_id) for incident_id in incident_ids}

    def read_ack(self, incident_ids: Sequence[str]) -> dict[str, Ack]:
        """Ask the two acknowledgement questions of incidents whose rows the caller already holds."""
        out: dict[str, Ack] = {}
        for incident_id in incident_ids:
            self._arm(self._budget)
            out[incident_id] = self._ack(incident_id)
        return out

    def plans(self) -> dict[str, tuple[str, ...]]:
        """Return `EXPLAIN QUERY PLAN` for each of the four statements, by name.

        A diagnostic read of the *plan* and not of any row: it exists so the bound these reads claim — no
        scan of `incidents`, `events`, `actions` or `audit` — is checkable from outside instead of being a
        claim in a comment. It runs inside the same snapshot and binds a probe id that names nothing.
        """
        connection = self._connection
        if connection is None:
            raise StateError(READ_FAILED)
        statements = (('discover', DISCOVERY_SQL, (PAYLOAD_MAXIMUM_BYTES, 0)),
                      ('incident', INCIDENT_SQL, (PAYLOAD_MAXIMUM_BYTES, PROBE_ID)),
                      ('decision', self._decision_sql, (PROBE_ID, *self._statuses)),
                      ('intent', INTENT_SQL, (PROBE_ID,)))
        try:
            return {name: tuple(row[-1] for row in connection.execute(
                'EXPLAIN QUERY PLAN ' + sql, parameters).fetchall()) for name, sql, parameters in statements}
        except sqlite3.Error:
            raise StateError(READ_FAILED) from None

    # --- internals ---------------------------------------------------------------------------

    def _incident(self, incident_id: str) -> Incident:
        self._arm(self._budget)
        if not _is_uuid(incident_id):
            return Incident(incident_id=str(incident_id), status=CORRUPT)
        connection = self._connection
        if connection is None:
            return Incident(incident_id=incident_id, status=REFUSED)
        try:
            row = connection.execute(INCIDENT_SQL, (PAYLOAD_MAXIMUM_BYTES, incident_id)).fetchone()
        except sqlite3.Error:
            return Incident(incident_id=incident_id, status=self._classify(), steps=_units(self._spent))
        if row is None:
            return Incident(incident_id=incident_id, status=MISSING, steps=_units(self._spent))
        status, opened_at, payload = row
        moment = _moment(opened_at)
        event = _payload(payload)
        if moment is None or status not in (OPEN, RESOLVED):
            return Incident(incident_id=incident_id, status=CORRUPT, steps=_units(self._spent))
        if status == RESOLVED:
            # The stored status column is the positive fact that ends a ladder. The verdict row that opened
            # it says nothing about whether the incident is over, so an unreadable one changes nothing here.
            return Incident(incident_id=incident_id, status=RESOLVED, opened_at=moment, event=event,
                            steps=_units(self._spent))
        return Incident(incident_id=incident_id, status=OPEN, opened_at=moment, event=event,
                        ack=self._ack(incident_id), steps=_units(self._spent))

    def _ack(self, incident_id: str) -> Ack:
        connection = self._connection
        if connection is None:
            return Ack(complete=False, reason=REFUSED)
        try:
            decided = bool(connection.execute(self._decision_sql, (incident_id, *self._statuses))
                           .fetchone()[0])
            intent = bool(connection.execute(INTENT_SQL, (incident_id,)).fetchone()[0])
        except sqlite3.Error:
            return Ack(complete=False, reason=self._classify())
        return Ack(decided=decided, intent=intent)

    def _arm(self, limit: int | None) -> None:
        """Start charging the per-incident budget, or read without one.

        The handler is installed once, on this connection, and reads the current limit: arming with `None`
        means "measure, never stop", which is what a `LIMIT`-bounded page needs in order to still report the
        cost it had.
        """
        self._limit = limit
        self._spent = 0
        self._interrupted = False
        if self._armed or self._connection is None:
            return
        self._connection.set_progress_handler(self._charge, PROGRESS_CHECK_INSTRUCTIONS)
        self._armed = True

    def _charge(self) -> int:
        """Account for the instructions just run, and interrupt the incident that ran out of budget."""
        self._spent += PROGRESS_CHECK_INSTRUCTIONS
        if self._limit is not None and self._spent > self._limit:
            self._interrupted = True
            return 1
        return 0

    def _classify(self) -> str:
        """Say *why* a read stopped: this incident's own budget, or a refusal this build cannot answer."""
        return INCOMPLETE if self._interrupted else REFUSED


def _connect(path: Path) -> sqlite3.Connection:
    """Open `path` as it lies on disk: read-only, autocommit except where this module says BEGIN."""
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, isolation_level=None,
                                     timeout=_BUSY_TIMEOUT_SECONDS)
    except sqlite3.Error:
        raise StateError(READ_FAILED) from None
    try:
        # Belt and braces beside `mode=ro`: this module has one statement per question and no write in any
        # of them, and a connection that could not write even by accident is one fewer thing to argue about.
        connection.execute('PRAGMA query_only=ON')
    except sqlite3.Error:
        with suppress(sqlite3.Error), closing(connection):
            pass
        raise StateError(READ_FAILED) from None
    return connection


def _is_uuid(value: Any) -> bool:
    """Whether `value` may be a cursor key, refusing a stored value that is not one."""
    if not isinstance(value, str) or len(value) != _UUID_TEXT:
        return False
    try:
        identifier(value)
    except (StateError, ValueError):
        return False
    return True


def _moment(value: Any) -> dt.datetime | None:
    """Parse a stored `opened_at`, or report that this row cannot be reasoned about."""
    try:
        return timestamp(value)
    except (ValueError, TypeError):
        return None


def _payload(value: Any) -> Mapping[str, Any] | None:
    """Decode one event payload, or `None`.

    `None` is the statement "this verdict could not be read", and it covers the row SQLite refused to
    transfer (too wide, or not JSON), bytes that are not UTF-8, and JSON that is not an object. Nothing is
    repaired: an escalation filed from a guessed payload would page on a rule name this build invented.
    """
    if not isinstance(value, bytes):
        return None
    try:
        document = json.loads(value.decode('utf-8'))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def _units(spent: int) -> int:
    """Round an instruction count to the granularity the progress handler can actually see."""
    return spent // PROGRESS_CHECK_INSTRUCTIONS * PROGRESS_CHECK_INSTRUCTIONS

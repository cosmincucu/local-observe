"""Bounded, paged, read-only access to the append-only audit history .

`GET /v1/records/audit` stays exactly what it was: one newest-first window of at most 100 stored rows
with no way back, which is the surface the refusal-audit documents describe. That cap is not a bug to
fix here — it is the reason an operator reading the audit after a refusal burst can only see the last
100 positions, and this module is the second door: an explicit `GET /v1/audit` route that walks the
same table backwards in bounded pages. Nothing in the legacy read changes shape, limit behaviour or
bytes, and no page field reaches it.

Three bounds, each owned here and nowhere else:

* **Positions per request** — `SCAN_BUDGET`. A page consumes at most 500 audit positions, matching or
  not, and `scanned` reports what it spent. A filtered category that finds nothing inside the budget
  returns an *empty* page with a non-null `next_before`: "keep going", not "there is nothing".
* **Bytes per response** — `PAGE_MAXIMUM_BYTES`. The whole canonical body, metadata included, is
  measured before a row is taken, so the answer is never truncated and never over the cap.
* **Stored bytes per row** — `ROW_STORED_TEXT_MAXIMUM`. Historical row size is not assumed safe.
  A row above this bound is never read whole into Python. Its width is decided by `length()`
  *inside SQLite*, which transfers an integer rather than
  the value: that bounds this process's allocation, not the disk IO or latency of a hostile historical
  blob, and this module claims nothing stronger.

A row too wide to show, or one whose canonical escaping would not fit even on a page of its own, is
reported as `{"sequence": N, "omitted": "row_exceeds_page_budget"}` in place of its columns. That
placeholder consumes the position and counts toward the limit like any other entry, so the walk keeps
moving and history is never silently dropped. The sequence identifies the omitted position;
this API does not provide a separate arbitrary-row retrieval endpoint.

**Cursors are positions, not authority.** `snapshot` fixes the maximum sequence this traversal may
show, captured inside the same read transaction as its first page; appends above it can neither
duplicate nor displace the walk. A client that preserves `snapshot` and `category` continues the same
traversal; changing either starts a new one. Nothing here signs, seals or remembers a cursor, and a
restored or replaced database is a different table, not a resumable position.

The connection is a dedicated read-only URI (`mode=ro`), opened per page, holding a *deferred* read
transaction (`BEGIN`, never `BEGIN IMMEDIATE`, never `Store.transaction`, which takes the write lock),
and closed before the page is returned. Every value is a bound parameter against static SQL, so the
only text reaching SQLite is written in this file.
"""
from contextlib import closing
from pathlib import Path
import re
import sqlite3
from typing import Any

from local_observe.inventory.validation import canonical
from .state import StateError

# `state.py` imports this module from inside `Store.audit_page`, never at module level (the
# `refusals`/`notification_safety` precedent), so this module-level arrow cannot become a load-time
# cycle at service start.

#: The four fields the route accepts, and the only fields it accepts.
FIELDS = frozenset({'limit', 'category', 'snapshot', 'before'})
#: The page size nobody asks for: the same 100 the legacy record read caps at, so the default reads as
#: "the window I already know", and a caller who wants less says so.
DEFAULT_LIMIT = 100
LIMIT_BOUNDS = (1, 100)
CATEGORY_ALL = 'all'
CATEGORY_ACTION_TRANSITIONS = 'action-transitions'
CATEGORIES = (CATEGORY_ALL, CATEGORY_ACTION_TRANSITIONS)
#: The completed lifecycle transitions. An approval *intent* (`action.approval_intent`) and a refused
#: attempt (`action.refused`) are deliberately absent: CONTRACTS §5 says a callback receipt is not
#: action completion, and the refusal audit says a refusal is a denial rather than a transition. An operator who
#: wants either reads them under `all`.
ACTION_TRANSITIONS = frozenset({
    'action.proposed', 'action.approved', 'action.denied', 'action.expired',
    'execution.claimed', 'execution.succeeded', 'execution.failed', 'execution.unknown',
})
#: Audit positions one request may consume, matching or not. A floor for the filtered walk, never a
#: promise that a page is complete: `next_before` says what remains.
SCAN_BUDGET = 500
#: What the route will read out of the ASGI scope before refusing to interpret it.
QUERY_MAXIMUM_BYTES = 2048
#: Hard ceiling on the whole canonical response body, metadata included. Measured before a row joins
#: the page, so the answer sent is always inside it.
PAGE_MAXIMUM_BYTES = 65536
#: Widest combined stored text a single audit row may carry into Python.
ROW_STORED_TEXT_MAXIMUM = 49152
#: How much of `operation` the metadata read transfers. The clip cannot change a match: every word in
#: `ACTION_TRANSITIONS` is 19 bytes or shorter, so a value long enough to be clipped is not one of them.
OPERATION_METADATA_BYTES = 64
#: SQLite's signed-64 ceiling, which is also what `sequence` can never exceed.
INTEGER_MAXIMUM = 2 ** 63 - 1
#: The one word naming a position this page could not show. Fixed, so a reader can count it.
OMISSION = 'row_exceeds_page_budget'
#: The six stored audit columns, in the order both reads return them. `audit` holds no token, claim or
#: callback field, so the legacy reader's secret-stripping is not a rule this reader has to copy — there
#: is nothing here to strip.
ROW_COLUMNS = ('sequence', 'at', 'actor', 'operation', 'subject', 'detail')
#: The whole response body: these keys and no others.
RESPONSE_KEYS = ('rows', 'snapshot', 'next_before', 'scanned')

# The busy timeout inherited from the rest of the package's connections. A read transaction needs no
# write lock, but a `-wal` index still has to be recovered or read by somebody, and 10 s is what
# `state.py`'s own connections wait. Passed as sqlite3.connect's timeout argument.
_BUSY_TIMEOUT_MILLISECONDS = 10000

# A query string is printable ASCII other than `%`, or a well-formed percent escape, and nothing else:
# raw control bytes and raw non-ASCII are refusals rather than something to guess about, and every `%`
# must carry exactly two hex digits (`%2`, `%zz` and a trailing `%` are refusals, never literal text —
# which is why `%` is outside the literal class below). One path through the alternation per byte, so a
# hostile string costs a linear scan.
_QUERY_BYTES = re.compile(rb'(?:[\x20-\x24\x26-\x7e]|%[0-9A-Fa-f]{2})*\Z')
# Canonical decimal only: no sign, no surrounding space, no underscore, no leading zero. `0` is
# canonical; `+0`, `-0`, `00`, `01`, `1.0` and `1e0` are not.
_DECIMAL = re.compile(r'(?:0|[1-9][0-9]*)\Z')
_ESCAPE = re.compile(b'%[0-9A-Fa-f]{2}')

# Fixed sentences: they name a field or a bound owned by this module and never the offending text, so
# a refusal cannot be made to repeat what its caller sent (`api.py`'s own rule for this surface).
TOO_LARGE = f'Audit query exceeds {QUERY_MAXIMUM_BYTES} bytes'
MALFORMED_QUERY = 'Audit query is not canonical percent-encoded UTF-8'
UNKNOWN_FIELD = 'Audit query names an unknown field'
DUPLICATE_FIELD = 'Audit query repeats a field'
BLANK_FIELD = 'Audit query field is blank or has no value'
INVALID_INTEGER = f'Audit cursor value must be a canonical integer from 0 to {INTEGER_MAXIMUM}'
INVALID_LIMIT = f'Audit limit must be a canonical integer from {LIMIT_BOUNDS[0]} to {LIMIT_BOUNDS[1]}'
INVALID_CATEGORY = f'Audit category must be {CATEGORY_ALL} or {CATEGORY_ACTION_TRANSITIONS}'
CURSOR_INCOMPLETE = 'Audit cursor requires both snapshot and before'
CURSOR_AHEAD = 'Audit cursor before must not exceed snapshot'

# Static, trusted SQL. Every value below arrives as a bound parameter.
MAXIMUM_SQL = 'SELECT MAX(sequence) FROM audit'
POSITIONS_SQL = ('SELECT sequence, substr(CAST(operation AS BLOB), 1, ?),'
                 ' length(CAST(at AS BLOB)) + length(CAST(actor AS BLOB))'
                 ' + length(CAST(operation AS BLOB))'
                 ' + length(CAST(subject AS BLOB)) + length(CAST(detail AS BLOB)),'
                 " CAST(typeof(at)='text' AND typeof(actor)='text' AND typeof(operation)='text'"
                 " AND typeof(subject)='text' AND typeof(detail)='text' AS INTEGER)"
                 ' FROM audit WHERE sequence <= ?'
                 ' ORDER BY sequence DESC LIMIT ?')
ROW_SQL = ('SELECT sequence, CAST(at AS BLOB), CAST(actor AS BLOB), CAST(operation AS BLOB),'
           ' CAST(subject AS BLOB), CAST(detail AS BLOB) FROM audit WHERE sequence = ?')


def parse_query(query_string: bytes) -> dict[str, Any]:
    """Return the validated ``{limit, category, snapshot, before}`` of one raw query string.

    Strict on purpose, and run by the transport *before* `Store` is asked for anything: an over-long,
    non-UTF-8, badly-escaped, duplicated, blank or unknown-field query is a refusal that opens no
    connection, reads no body and echoes nothing back. Duplicate fields are refused rather than
    last-wins, because two values for one bound is a question this module does not answer.

    `+` is a literal plus and never a space: no value this route accepts contains either.
    """
    return _validated(_fields(query_string))


def audit_page(path: Path | str, *, limit: Any = None, category: Any = None,
               snapshot: Any = None, before: Any = None) -> dict[str, Any]:
    """Return one bounded page of the audit history from `path`, opening it read-only.

    `limit=None` and `category=None` take `DEFAULT_LIMIT` and `CATEGORY_ALL`; every argument is
    revalidated here so the direct-call surface (`Store.audit_page`, a CLI, a worker, a test) gets the
    same refusals as the HTTP one. `snapshot`/`before` are `None` for an initial request and a pair for
    a continuation. A `bool` is not an integer here, whatever Python's subclass says.

    Raises:
        StateError: A field is unknown, duplicated, blank, non-canonical, oversized, out of range, a
            half cursor or a `before` ahead of its `snapshot`. Always a fixed sentence naming a field,
            never the value; always raised before the file is opened.
    """
    request = _validated({'limit': DEFAULT_LIMIT if limit is None else limit,
                          'category': CATEGORY_ALL if category is None else category,
                          **({'snapshot': snapshot} if snapshot is not None else {}),
                          **({'before': before} if before is not None else {})})
    return _page(Path(path), request['limit'], request['category'], request['snapshot'], request['before'])


def _validated(fields: dict[str, Any]) -> dict[str, Any]:
    """Judge the four accepted fields from their values, whichever surface supplied them.

    Returns the four keys always, with `snapshot` and `before` `None` for an initial request, so the
    caller never has to know which defaults were spelled.
    """
    unknown = sorted(set(fields) - set(FIELDS))
    if unknown:
        raise StateError(UNKNOWN_FIELD)
    limit, category = _limit(fields.get('limit')), _category(fields.get('category'))
    snapshot, before = _cursor(fields.get('snapshot'), fields.get('before'))
    return {'limit': limit, 'category': category, 'snapshot': snapshot, 'before': before}


def _fields(query_string: bytes) -> dict[str, str]:
    """Return the decoded ``{field: text}`` pairs of one bounded query string, refusing the rest."""
    if not isinstance(query_string, bytes):
        raise StateError(MALFORMED_QUERY)
    if len(query_string) > QUERY_MAXIMUM_BYTES:
        raise StateError(TOO_LARGE)
    if not query_string:
        return {}                                  # no query at all is the initial request
    if _QUERY_BYTES.fullmatch(query_string) is None:
        raise StateError(MALFORMED_QUERY)          # raw control/non-ASCII bytes or a broken escape
    fields: dict[str, str] = {}
    for item in query_string.split(b'&'):
        encoded_key, separator, encoded_value = item.partition(b'=')
        if not encoded_key or not encoded_value or not separator:
            raise StateError(BLANK_FIELD)
        key, value = _decoded(encoded_key), _decoded(encoded_value)
        if key not in FIELDS:
            raise StateError(UNKNOWN_FIELD)
        if key in fields:
            raise StateError(DUPLICATE_FIELD)
        fields[key] = value
    return fields


def _decoded(raw: bytes) -> str:
    """Percent-decode one bounded token and require valid UTF-8, refusing either."""
    parts, index = [], 0
    while True:
        match = _ESCAPE.search(raw, index)
        if match is None:
            parts.append(raw[index:])
            break
        parts.append(raw[index:match.start()])
        parts.append(bytes.fromhex(match.group()[1:].decode('ascii')))
        index = match.end()
    try:
        return b''.join(parts).decode('utf-8')
    except UnicodeDecodeError as exc:
        raise StateError(MALFORMED_QUERY) from exc


def _limit(value: Any) -> int:
    if value is None:
        return DEFAULT_LIMIT
    number = _integer(value, INVALID_LIMIT)
    if not LIMIT_BOUNDS[0] <= number <= LIMIT_BOUNDS[1]:
        raise StateError(INVALID_LIMIT)
    return number


def _category(value: Any) -> str:
    if value is None:
        return CATEGORY_ALL
    if not isinstance(value, str) or value not in CATEGORIES:
        raise StateError(INVALID_CATEGORY)
    return value


def _integer(value: Any, sentence: str) -> int:
    """Return `value` as a usable integer, refusing anything that is not one.

    A `bool` is refused although Python files it under `int`: a page of 100 audits is not "True".
    Text is checked against the canonical grammar before `int()` ever sees it, which is also what stops
    a 5 000-digit string reaching CPython's conversion limit as an exception nobody chose.
    """
    if isinstance(value, bool):
        raise StateError(sentence)
    if isinstance(value, str):
        if len(value) > len(str(INTEGER_MAXIMUM)) or _DECIMAL.fullmatch(value) is None:
            raise StateError(sentence)
        value = int(value)
    if not isinstance(value, int):
        raise StateError(sentence)
    if not 0 <= value <= INTEGER_MAXIMUM:
        raise StateError(sentence)
    return value


def _cursor(snapshot: Any, before: Any) -> tuple[int | None, int | None]:
    """Return the ``(snapshot, before)`` pair a traversal was asked for, refusing half of one.

    Both bounds are non-negative integers and `0` is legal and meaningful: it is the snapshot of an
    empty database, and a traversal of it answers empty with the end known. A cursor is a position a
    client may choose freely — it is not a proof about what that client really saw.
    """
    if snapshot is None and before is None:
        return None, None
    if snapshot is None or before is None:
        raise StateError(CURSOR_INCOMPLETE)
    fixed = _integer(snapshot, INVALID_INTEGER)
    floor = _integer(before, INVALID_INTEGER)
    if floor > fixed:
        raise StateError(CURSOR_AHEAD)
    return fixed, floor


def _page(path: Path, limit: int, category: str, snapshot: int | None, before: int | None) -> dict[str, Any]:
    """Read one page on a dedicated read-only connection, closed before this returns."""
    with closing(_connect(path)) as connection:
        connection.execute('BEGIN')
        page = _positions(connection, limit, category, snapshot, before)
        # The read transaction ends with the page: its snapshot is a fact about these rows and no
        # other, and nothing here holds the file (or a WAL read mark) between requests. If the read
        # raises, `closing` discards the transaction instead.
        connection.execute('COMMIT')
        return page


def _connect(path: Path) -> sqlite3.Connection:
    """Open `path` as it lies on disk: read-only, autocommit off only where this module says BEGIN."""
    return sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, isolation_level=None,
                           timeout=_BUSY_TIMEOUT_MILLISECONDS / 1000)


def _positions(connection: sqlite3.Connection, limit: int, category: str,
               snapshot: int | None, before: int | None) -> dict[str, Any]:
    """Walk at most `SCAN_BUDGET` positions newest-first and build the bounded page from them."""
    if snapshot is None:
        # Captured inside this transaction, so the page and its snapshot come from one read mark. An
        # empty database has no maximum and answers zero, which is a legal snapshot with nothing in it.
        snapshot = connection.execute(MAXIMUM_SQL).fetchone()[0] or 0
    # A single upper key lets SQLite seek directly to the continuation. An OR-wrapped
    # optional before predicate would scan all newer positions again on every deep page.
    upper = snapshot if before is None else min(snapshot, before - 1)
    positions = connection.execute(
        POSITIONS_SQL,
        (OPERATION_METADATA_BYTES, upper, SCAN_BUDGET)).fetchall()
    rows: list[dict[str, Any]] = []
    next_before: int | None = None
    scanned = 0
    for sequence, operation, stored_bytes, text_only in positions:
        scanned += 1
        # The clipped `operation` arrives as bytes and is decoded leniently: it is never returned, only
        # compared with words that are pure ASCII, so a hostile stored value cannot reach a response and
        # cannot match. A value long enough to have been clipped is not one of them.
        matches = category == CATEGORY_ALL or operation.decode('utf-8', 'replace') in ACTION_TRANSITIONS
        if matches and len(rows) < limit:
            item = _settled(connection, sequence, stored_bytes, text_only, rows, snapshot)
            if item is None:
                # Whole, wanted, and this page has no room left for it. The cursor sits one position
                # above so the next page starts at this row: advancing over it would lose history.
                next_before = sequence + 1
                break
            rows.append(item)
            continue
        if len(rows) >= limit:
            # The page holds everything the caller asked for, so stop spending the scan budget. Where the
            # cursor goes depends on what this position is: a matching row this page could not show stays
            # eligible one page away (+1), while a consumed non-match has nothing to show on any page and
            # is left behind by the exclusive bound. Either way the walk moved: `sequence` is below every
            # position this page settled.
            next_before = sequence + 1 if matches else sequence
            break
    if next_before is None and len(positions) >= SCAN_BUDGET:
        # Every position came back matching or not and the budget is spent; there may be more below.
        next_before = positions[-1][0]
    return _body(rows, snapshot, next_before, scanned)


def _body(rows: list[dict[str, Any]], snapshot: int, next_before: int | None,
          scanned: int) -> dict[str, Any]:
    """Assemble the one shape this read may answer: `RESPONSE_KEYS` and nothing else."""
    return dict(zip(RESPONSE_KEYS, (rows, snapshot, next_before, scanned)))


def _settled(connection: sqlite3.Connection, sequence: int, stored_bytes: int, text_only: int,
             rows: list[dict[str, Any]], snapshot: int) -> dict[str, Any] | None:
    """Return the entry this position contributes, or `None` to defer it to the next page.

    `None` is only ever "this page is full": a row is never skipped because it was inconvenient, and an
    oversized one is named in place instead.
    """
    row = None if stored_bytes > ROW_STORED_TEXT_MAXIMUM else _complete(connection, sequence, text_only)
    if row is not None and _page_bytes(rows + [row], snapshot) > PAGE_MAXIMUM_BYTES:
        if _page_bytes([row], snapshot) > PAGE_MAXIMUM_BYTES:
            # It would not have fitted on a page of its own either, so it is an omission wherever it is
            # read — and that is the only reason a complete row ever stops being one here.
            row = None
        else:
            return None  # A valid row belongs on the next page, not beyond this page's byte cap.
    if row is None:
        # `row` is None because the stored text is too wide to carry, or is not text that can be shown
        # as stored. Both get the same honest answer: the position is named and its bytes are not.
        row = {'sequence': sequence, 'omitted': OMISSION}
        if _page_bytes(rows + [row], snapshot) > PAGE_MAXIMUM_BYTES:
            # Even a placeholder will not fit behind what this page already holds, so nothing about this
            # position can be said on it: defer, and let the next page — which starts empty — say so.
            return None
    return row


def _complete(connection: sqlite3.Connection, sequence: int, text_only: int) -> dict[str, Any] | None:
    """Return one position's six stored columns, or `None` when they cannot be shown as stored.

    The text columns are read as `BLOB` and decoded strictly, because a value this build did not write
    may hold bytes that are not UTF-8 (or may not be text at all, which the `typeof` check answers) and
    SQLite's own text decoder would raise over it. Repairing such a value with replacement characters
    would be rewriting the audit; `None` makes it a visible omission instead. A position that the
    metadata read saw and this read cannot find is treated the same way: inside one read transaction it
    cannot happen, and if the file were replaced underneath us the honest answer is "not shown", never a
    silent hole in the walk.
    """
    if not text_only:
        return None
    fetched = connection.execute(ROW_SQL, (sequence,)).fetchone()
    if fetched is None:
        return None
    try:
        values = [fetched[0]] + [column.decode('utf-8') for column in fetched[1:]]
    except UnicodeDecodeError:
        return None
    return dict(zip(ROW_COLUMNS, values))


def _page_bytes(rows: list[dict[str, Any]], snapshot: int) -> int:
    """Wire bytes of this body, with the metadata sized at the widest it can legally be.

    Reserve the largest legal integer cursor, which also covers the four-byte JSON null. `scanned`
    never passes `SCAN_BUDGET`. That is what makes `PAGE_MAXIMUM_BYTES` a
    statement about the bytes actually sent rather than about the values this request happened to have
    settled on: a row only ever joins a page when the widest body it could sit inside still fits.
    """
    return len(canonical(_body(rows, snapshot, INTEGER_MAXIMUM, SCAN_BUDGET)).encode())

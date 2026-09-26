"""Bounded discovery of the verification ids one execution carries .

`Store.get_verification` reads one stored document by its exact id, and that id is a digest of execution,
binding and normalised window — so a caller holding only an execution had no way to ask "which
verifications does this run carry?". This module answers that question and nothing else:
`Store.list_verifications(execution_id, actor)` returns id strings. IDs only, never a payload, metadata,
verdict, timestamp, claim, token, sample or action record; `get_verification` stays the way to read any of
those, one document at a time. Nothing here re-reads or re-grades an accepted result, and an `executing`
execution is listable (usually empty) — this read infers no terminal outcome.

What lives here: a dedicated read-only connection and one bounded statement. What stays owned by
`verification_records.py`, the single authorization/schema vocabulary owner: `_reader` (which roles may
read, and when a `producer` may), `_ready` (both tables or a schema failure), `_sha256` with
`BAD_VERIFICATION_ID` (what a stored id is), `_identifier`, and the words `RECORDS_PER_EXECUTION`,
`RECORD_LIMIT`, `UNKNOWN_EXECUTION`, `NEEDS_MIGRATION`. Those are same-package private helpers, imported
rather than copied: a second copy of the role or schema test is a second thing that can drift open.

Two bounds are deliberate. **Lexical ascending, not chronology:** `recorded_at` is never read and no
`ORDER BY` over a stored column runs before the `LIMIT`, avoiding a sort of unbounded corrupt history.
**Refuse rather than truncate:** the writer caps an execution at 64 records, this read fetches
one row more and refuses anything past the cap — as it refuses an id that is not exactly 64 lowercase hex
bytes. No repair, no omission, no partial list.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
from typing import Any

from .state import StateError
from .verification_records import (BAD_VERIFICATION_ID, NEEDS_MIGRATION, RECORD_LIMIT,
                                   RECORDS_PER_EXECUTION, UNKNOWN_EXECUTION, _identifier, _reader,
                                   _ready, _sha256)

#: Row count and digest width are separate bounds, even though both currently equal 64.
_PROBE = RECORDS_PER_EXECUTION + 1
_DIGEST_BYTES = 64
READ_FAILED = 'Verification records could not be read'
#: Canonical UUID text is always this long. Checking it before `uuid.UUID` is reached keeps arbitrary-length
#: caller text out of an identifier parser, and keeps the refusal this module's own.
_UUID_TEXT = 36
#: The busy timeout every other connection in this package waits, passed as `sqlite3.connect`'s argument
#: and never as a URI parameter. A read transaction takes no write lock, but a `-wal` still has to be read.
_BUSY_TIMEOUT_SECONDS = 10
#: The platform's one bad-identifier sentence (`state.identifier`, the key `refusals.SENTENCES` calls
#: `bad-identifier`) restated as a name rather than invented: a malformed execution id reads the same here
#: as it does on every other surface.
BAD_EXECUTION_ID = 'Expected canonical UUID'
#: The index `MIGRATIONS[4]` creates for this exact lookup. `INDEXED BY` is a refusal and not a hint: a
#: file that lost the index fails closed here instead of costing a full-table scan nobody budgeted.
EXECUTION_INDEX = 'verification_records_execution'
EXISTS_SQL = 'SELECT 1 FROM executions WHERE id=?'
# Static SQL, one bound value. `payload` is never named: the widest thing transferred is 65 bytes of id.
IDS_SQL = (f'SELECT typeof(verification_id), substr(CAST(verification_id AS BLOB), 1, {_DIGEST_BYTES + 1})'
           f' FROM verification_records INDEXED BY {EXECUTION_INDEX}'
           f' WHERE execution_id=? LIMIT {_PROBE}')


def _connect(path: Path) -> sqlite3.Connection:
    """Open `path` as it lies on disk: read-only, autocommit except where this module says BEGIN."""
    return sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, isolation_level=None,
                           timeout=_BUSY_TIMEOUT_SECONDS)


def _canonical(value: Any) -> str:
    """Return *value* as canonical UUID text, refusing a non-string or a wrong length without parsing it."""
    if not isinstance(value, str) or len(value) != _UUID_TEXT:
        raise StateError(BAD_EXECUTION_ID)
    return _identifier(value, BAD_EXECUTION_ID)


def _verification_id(kind: Any, raw: Any) -> str:
    """Return one stored id, refusing every row this read cannot vouch for.

    `kind` is SQLite's own `typeof`, so a row whose id is not text says so before Python decodes it; `raw`
    is the first 65 bytes of the value as stored, which is how an over-length id is *seen* rather than
    silently clipped. Bytes that are not UTF-8 are refused, never replaced: this list names ids, and a
    repaired id would name a document that does not exist.
    """
    if kind != 'text' or not isinstance(raw, bytes) or len(raw) != _DIGEST_BYTES:
        raise StateError(BAD_VERIFICATION_ID)
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise StateError(BAD_VERIFICATION_ID) from None
    return _sha256(text, BAD_VERIFICATION_ID)


def _digests(rows: list[tuple[Any, Any]]) -> list[str]:
    """Return the validated ids in lexical ascending order, refusing an over-cap or corrupt history."""
    if len(rows) > RECORDS_PER_EXECUTION:
        # The cap is the writer's rule; more rows than it means the file disagrees, and answering with the
        # first 64 would present a partial list as the whole answer.
        raise StateError(RECORD_LIMIT)
    return sorted(_verification_id(*row) for row in rows)


def list_records(store: Any, execution_id: Any, actor: Any) -> list[str]:
    """Return every verification id `execution_id` carries, as a fresh sorted list of id strings.

    Authority and the execution identifier are settled before the file is opened, so a refusal costs no
    connection and no policy is required of an ordinary reader. A known execution with no records answers
    `[]`; an unknown one is a refusal, because "nothing recorded yet" and "no such execution" are different
    statements. The transaction is a deferred `BEGIN`, never `BEGIN IMMEDIATE`/`Store.transaction`, and the
    connection is closed before this returns: nothing is created, written, migrated or audited, and a path
    with no database on it stays a refusal rather than a new file.

    Raises:
        StateError: An unauthorised or malformed actor, a non-canonical execution id, an unreadable or
            absent database, an incomplete verification schema, a missing execution index, an unknown
            execution, more than `RECORDS_PER_EXECUTION` stored rows, or any id that is not exactly 64
            lowercase hex bytes. One fixed sentence each, never input, path or driver text.
    """
    _reader(store.verification_policy, actor)
    wanted = _canonical(execution_id)
    try:
        with closing(_connect(store.path)) as connection:
            connection.execute('BEGIN')
            if not _ready(connection):
                raise StateError(NEEDS_MIGRATION)
            if connection.execute(EXISTS_SQL, (wanted,)).fetchone() is None:
                raise StateError(UNKNOWN_EXECUTION)
            rows = connection.execute(IDS_SQL, (wanted,)).fetchall()
            connection.execute('COMMIT')
    except sqlite3.Error:
        # One sentence for every driver failure — absent file, not-a-database, locked, lost index — raised
        # `from None`, so no driver text (which carries paths) rides along. A programming error is not a
        # `sqlite3.Error` and stays the traceback it is.
        raise StateError(READ_FAILED) from None
    return _digests(rows)

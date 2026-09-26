"""Bounded, producer-only discovery for one automatic verification per execution.

A page scans executions before filtering. Its cursor advances over ineligible rows
too; end-of-sweep is null, so a later sweep finds new UUIDs behind the old cursor
and executions that have since finished. No claims, queue or operational writes.
"""
from contextlib import closing
import json
import sqlite3

from local_observe.inventory.validation import canonical, digest, utc_text
from .state import StateError
from .verification_records import (MAPPING_KEYS, MAX_POLICY_BYTES, NEEDS_MIGRATION,
                                   _identifier, _instant, _mapping, _ready, _sha256, _writer)

DEFAULT_LIMIT = 16
MAX_LIMIT = 32
BAD_QUERY = 'Invalid verification candidate page'
BAD_STORED = 'Verification candidate state is invalid'
READ_FAILED = 'Verification candidates could not be read'
EXECUTION_INDEX = 'sqlite_autoindex_executions_1'
BINDING_INDEX = 'sqlite_autoindex_verification_bindings_1'
RECORD_INDEX = 'verification_records_execution'


def _fields(bounds):
    return ','.join(f'typeof({name}),substr(CAST({name} AS BLOB),1,{size + 1})'
                    for name, size in bounds)


EXECUTION_FIELDS = (('id', 36), ('action_id', 36), ('status', 9), ('updated_at', 64))
PAGE_PREFIX = ('SELECT ' + _fields(EXECUTION_FIELDS)
               + f' FROM executions INDEXED BY {EXECUTION_INDEX}')
FIRST_SQL = PAGE_PREFIX + ' ORDER BY id LIMIT ?'
NEXT_SQL = PAGE_PREFIX + ' WHERE id>? ORDER BY id LIMIT ?'
BINDING_FIELDS = (('status', 7), ('reason', 19), ('binding_id', 64),
                  ('origin', MAX_POLICY_BYTES), ('captured_at', 64))
BINDING_SQL = ('SELECT ' + _fields(BINDING_FIELDS)
               + f' FROM verification_bindings INDEXED BY {BINDING_INDEX} WHERE action_id=? LIMIT 1')
RECORD_SQL = ('SELECT ' + _fields((('verification_id', 64),))
              + f' FROM verification_records INDEXED BY {RECORD_INDEX} WHERE execution_id=? LIMIT 1')


def validate_page(after=None, limit=DEFAULT_LIMIT):
    """Validate user values before authority-approved callers may open SQLite."""
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise StateError(BAD_QUERY)
    if after is not None:
        if not isinstance(after, str) or len(after) != 36:
            raise StateError(BAD_QUERY)
        _identifier(after, BAD_QUERY)
    return after, limit


def _connect(path):
    return sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True,
                           isolation_level=None, timeout=10)


def _text(kind, value, bound, *, nullable=False):
    if nullable and kind == 'null' and value is None:
        return None
    if kind != 'text' or not isinstance(value, bytes) or len(value) > bound:
        raise StateError(BAD_STORED)
    try:
        return value.decode('utf-8')
    except UnicodeDecodeError:
        raise StateError(BAD_STORED) from None


def _binding(row):
    if row is None:
        return False  # Pre-policy action: no captured binding.
    values = [_text(*row[i * 2:i * 2 + 2], bound, nullable=name in ('binding_id', 'origin'))
              for i, (name, bound) in enumerate(BINDING_FIELDS)]
    status, reason, binding_id, raw, captured_at = values
    _instant(captured_at, BAD_STORED)
    if status == 'unbound':
        if (reason not in ('unsupported-targets', 'origin-unmatched', 'origin-ambiguous')
                or binding_id is not None or raw is not None):
            raise StateError(BAD_STORED)
        return False
    if status != 'bound' or reason != 'matched' or raw is None:
        raise StateError(BAD_STORED)
    _sha256(binding_id, BAD_STORED)
    try:
        origin = json.loads(raw)
        if not isinstance(origin, dict) or set(origin) != set(MAPPING_KEYS) | {'event_id', 'action_targets'}:
            raise StateError(BAD_STORED)
        _mapping({k: origin[k] for k in MAPPING_KEYS})
        _identifier(origin['event_id'], BAD_STORED)
        if origin['action_targets'] != [origin['resource_id']]:
            raise StateError(BAD_STORED)
        if canonical(origin) != raw or digest(origin) != binding_id:
            raise StateError(BAD_STORED)
    except (ValueError, TypeError, RecursionError, OverflowError, StateError):
        raise StateError(BAD_STORED) from None
    return True


def list_candidates(store, actor, *, after=None, limit=DEFAULT_LIMIT):
    """Return exactly ``{items, next_after}``; rows contain only two IDs and a stamp.

The existing writer authority is required even though this is read-only. SQL
transfers bounded field bytes, never execution tokens or verification payloads.
One existence probe skips an already-recorded execution; it does not reread or
regrade its accepted document. A missing named index refuses rather than scans.
"""
    _writer(store.verification_policy, actor)
    after, limit = validate_page(after, limit)
    try:
        with closing(_connect(store.path)) as db:
            db.execute('BEGIN')
            if not _ready(db):
                raise StateError(NEEDS_MIGRATION)
            # Prepare both probes even for an empty page: missing indexes are not empty state.
            db.execute('EXPLAIN QUERY PLAN ' + BINDING_SQL, ('',)).fetchall()
            db.execute('EXPLAIN QUERY PLAN ' + RECORD_SQL, ('',)).fetchall()
            rows = db.execute(FIRST_SQL if after is None else NEXT_SQL,
                              (limit + 1,) if after is None else (after, limit + 1)).fetchall()
            if len(rows) > limit:
                _identifier(_text(*rows[-1][:2], 36), BAD_STORED)
            items, last = [], None
            for row in rows[:limit]:
                execution, action, status, finished = [_text(*row[i * 2:i * 2 + 2], bound)
                                                       for i, (_, bound) in enumerate(EXECUTION_FIELDS)]
                _identifier(execution, BAD_STORED)
                _identifier(action, BAD_STORED)
                finished = utc_text(_instant(finished, BAD_STORED))
                if status not in ('executing', 'succeeded', 'failed', 'unknown'):
                    raise StateError(BAD_STORED)
                last = execution
                bound = _binding(db.execute(BINDING_SQL, (action,)).fetchone())
                record = db.execute(RECORD_SQL, (execution,)).fetchone()
                if record is not None:
                    _sha256(_text(*record, 64), BAD_STORED)
                if status != 'executing' and bound and record is None:
                    items.append({'execution_id': execution, 'action_id': action, 'finished_at': finished})
            db.execute('COMMIT')
            return {'items': items, 'next_after': last if len(rows) > limit else None}
    except sqlite3.Error:
        raise StateError(READ_FAILED) from None

"""One source's durable, bounded rotation over open incidents; no operational database writes.

The cursor stores a fixed cycle high-water rowid and the last examined rowid. New incidents wait for
the next cycle, so a busy newest edge cannot starve older incidents. See docs/units/rca-progress.md
for local-filesystem ownership, crash replay and restore limits.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from typing import Any

from local_observe.inventory.validation import canonical, digest
from .owner import exclusive_owner
from .state import ESCALATION_INCIDENTS_INDEX, label

VERSION = 1
MAX_CURSOR_BYTES = 2_048
MAX_PAGE = 25
ROWID_MAXIMUM = 2 ** 63 - 1
READ_INSTRUCTIONS = 16_000
CHECK_INSTRUCTIONS = 100
KEYS = frozenset({'schema_version', 'source', 'binding', 'high_water', 'after'})
HIGH_WATER_SQL = (f'SELECT rowid FROM incidents INDEXED BY {ESCALATION_INCIDENTS_INDEX}'
                  " WHERE status='open' ORDER BY rowid DESC LIMIT 1")
# Only the two identities bundle() needs cross this boundary. Corrupt oversized text never enters
# Python; its incident is still examined and will report a per-incident refusal.
PAGE_SQL = (
    'SELECT rowid, CASE WHEN length(CAST(id AS BLOB))=36 THEN id END AS id,'
    ' CASE WHEN resource_id IS NULL OR length(CAST(resource_id AS BLOB))=36'
    " THEN resource_id ELSE '' END AS resource_id"
    f' FROM incidents INDEXED BY {ESCALATION_INCIDENTS_INDEX}'
    " WHERE status='open' AND rowid>? AND rowid<=? ORDER BY rowid LIMIT ?")


class ProgressError(ValueError):
    """Untrusted progress or unreadable discovery; never reset silently."""


def _safe_path(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise ProgressError('Refusing linked RCA progress or database path')
    if path.exists() and not stat.S_ISREG(path.stat().st_mode):
        raise ProgressError('RCA progress and database paths must be regular files')


def location(database: Path | str, source: str) -> Path:
    """A deterministic sidecar beside the database, with no caller-controlled path fragment."""
    label(source)
    path = Path(database).absolute()
    _safe_path(path)
    return path.with_name(path.name + '.rca.' + digest(source) + '.cursor.json')


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for key, value in pairs:
        if key in out:
            raise ProgressError('RCA progress repeats a field')
        out[key] = value
    return out


class Progress:
    """Exclusive cursor ownership for one tick; read snapshots end before the caller analyzes."""

    def __init__(self, database: Path | str, source: str):
        self.path = location(database, source)
        self.database = Path(database).absolute()
        self.source = source
        self.binding = digest(os.path.normcase(str(self.database.resolve())))
        self.document: dict[str, Any] = {}
        self._owner = exclusive_owner(self.path)

    def __enter__(self) -> Progress:
        _safe_path(self.path)
        _safe_path(Path(str(self.path) + '.owner.lock'))
        self._owner.__enter__()
        try:
            self.document = self._load()
        except BaseException:
            self._owner.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self._owner.__exit__(exc_type, exc_value, traceback)

    def _load(self) -> dict[str, Any]:
        _safe_path(self.path)
        try:
            with self.path.open('rb') as stream:
                raw = stream.read(MAX_CURSOR_BYTES + 1)
        except FileNotFoundError:
            return {'schema_version': VERSION, 'source': self.source, 'binding': self.binding,
                    'high_water': 0, 'after': 0}
        if len(raw) > MAX_CURSOR_BYTES:
            raise ProgressError('RCA progress exceeds its byte bound')
        try:
            value = json.loads(raw.decode('utf-8'), object_pairs_hook=_object)
        except (UnicodeDecodeError, ValueError):
            raise ProgressError('RCA progress is not a valid JSON document') from None
        if (not isinstance(value, dict) or set(value) != KEYS
                or type(value['schema_version']) is not int or value['schema_version'] != VERSION
                or value['source'] != self.source or value['binding'] != self.binding):
            raise ProgressError('RCA progress schema, source or database binding is unsupported')
        if any(type(value[key]) is not int or not 0 <= value[key] <= ROWID_MAXIMUM
               for key in ('after', 'high_water')) or value['after'] > value['high_water']:
            raise ProgressError('RCA progress position is unsupported')
        return value

    def _save(self) -> None:
        _safe_path(self.path)
        raw = canonical(self.document).encode('utf-8')
        if len(raw) > MAX_CURSOR_BYTES:
            raise ProgressError('RCA progress exceeds its byte bound')
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='wb', dir=self.path.parent,
                                             prefix=self.path.name + '.', delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _safe_path(self.path)
            os.replace(temporary, self.path)
            if os.name != 'nt':
                descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def page(self, limit: int) -> tuple[list[dict[str, Any]], bool]:
        """At most limit incidents plus one lookahead, under a fixed SQL instruction budget."""
        if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
            raise ProgressError('RCA incident budget must be an integer 1..25')
        _safe_path(self.database)
        steps = 0

        def budget() -> int:
            nonlocal steps
            steps += CHECK_INSTRUCTIONS
            return int(steps > READ_INSTRUCTIONS)

        reset = self.document['after'] == self.document['high_water']
        try:
            with closing(sqlite3.connect(self.database.resolve().as_uri() + '?mode=ro',
                                         uri=True, timeout=10)) as connection:
                connection.row_factory = sqlite3.Row
                connection.set_progress_handler(budget, CHECK_INSTRUCTIONS)
                connection.execute('BEGIN')
                high_water = self.document['high_water']
                after = self.document['after']
                if reset:
                    latest = connection.execute(HIGH_WATER_SQL).fetchone()
                    high_water, after = (latest[0] if latest else 0), 0
                rows = [dict(row) for row in connection.execute(PAGE_SQL,
                                                                (after, high_water, limit + 1))]
        except sqlite3.Error:
            raise ProgressError('RCA incident page could not be read') from None
        if reset:
            self.document.update(high_water=high_water, after=after)
            self._save()  # Fix the cycle before its first attempt, including a crash after that attempt.
        return rows[:limit], len(rows) > limit

    def advance(self, rowid: int) -> None:
        """Persist an examined incident; replay after a failed save remains content-idempotent."""
        if type(rowid) is not int or not self.document['after'] < rowid <= self.document['high_water']:
            raise ProgressError('RCA progress cannot advance outside its cycle')
        self.document['after'] = rowid
        self._save()

    def finish(self, more: bool) -> None:
        """A short page completes this fixed cycle, including rows that closed since it began."""
        if not more and self.document['after'] != self.document['high_water']:
            self.document['after'] = self.document['high_water']
            self._save()

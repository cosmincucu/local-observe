"""Build atomic derived SQLite snapshots and expose bounded read-only lookups.

A built index is derived data: every byte of it comes from the declaration, so a schema step here is never
migrated in place. ``SCHEMA_VERSION`` is the version this build reads; an index built at any other version
is refused with the command that rebuilds it, because rebuilding from the declaration is cheaper and safer
than carrying a migration path for a file the operator never edits.
"""
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from typing import Any

from .validation import InvalidInventory, alias_key, canonical, declared, digest, utc_text

APPLICATION_ID = 0x4C4F4901
#: The `resources` table layout this build reads. Version 2 (typed inventory records) added the typed `owner` column; a
#: version-1 index holds no owner column, so reading it would answer "No owner declared" for a resource
#: whose operator did declare one — the refusal below is what stops that silent lie.
SCHEMA_VERSION = 2


@contextmanager
def readonly(path: Path | str) -> Iterator[sqlite3.Connection]:
    """Open a built index read-only, refusing a file this build cannot answer from.

    Both refusals name what the operator does next: a file that is not an inventory index at all, and an
    index built by another schema version, which is rebuilt from the declaration rather than migrated.
    """
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA query_only=ON')
        if connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID:
            raise InvalidInventory('Not a declared inventory index')
        version = connection.execute('PRAGMA user_version').fetchone()[0]
        if version != SCHEMA_VERSION:
            raise InvalidInventory(f'Unsupported inventory index schema (built at version {version}, '
                                   f'this build reads {SCHEMA_VERSION}): rebuild it from the declaration '
                                   'with lo-inventory build')
        yield connection
    finally:
        connection.close()


def _require_own_index(path: Path) -> None:
    """Refuse to overwrite a file that is not this product's index; an older schema version is replaced.

    The rebuild that `readonly()` names must be able to land on the stale file's own path, so this guard
    checks only `application_id`: a foreign file is never overwritten, and an index built at any schema
    version of this product is derived data whose replacement is the point of building (typed inventory records).
    """
    connection = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
    try:
        if connection.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID:
            raise InvalidInventory('Not a declared inventory index')
    finally:
        connection.close()


def normalized(document: dict[str, Any]) -> dict[str, Any]:
    result = {'schema_version': 1, 'resources': []}
    for resource in sorted(document['resources'], key=lambda item: item['id']):
        item = dict(resource)
        item['aliases'] = [{'scope': scope, 'type': kind, 'value': value}
                           for scope, kind, value in sorted(alias_key(alias) for alias in item['aliases'])]
        item['relations'] = sorted(item['relations'], key=lambda relation: (relation['type'], relation['target']))
        item['credential_refs'] = item.get('credential_refs', {})
        result['resources'].append(item)
    return result


def build(document: dict[str, Any], output: Path | str, revision: str, *,
          now: dt.datetime | None = None) -> dict[str, str]:
    declared(document)
    if not isinstance(revision, str) or not revision.strip() or len(revision) > 256:
        raise InvalidInventory('A bounded declaration revision label is required')
    document = normalized(document)
    output = Path(output)
    if output.is_symlink():
        raise InvalidInventory('Refusing symlink output')
    if output.exists():
        _require_own_index(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    metadata = {'schema_version': '1', 'declaration_revision': revision,
                'declaration_sha256': digest(document),
                'built_at': utc_text(now or dt.datetime.now(dt.timezone.utc))}
    fd, name = tempfile.mkstemp(prefix='.inventory-', suffix='.db', dir=output.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        connection = sqlite3.connect(temporary)
        try:
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute(f'PRAGMA application_id={APPLICATION_ID}')
            connection.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
            connection.executescript('''
                CREATE TABLE build_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE resources (id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL,
                    attributes TEXT NOT NULL, credential_refs TEXT NOT NULL, owner TEXT);
                CREATE TABLE aliases (scope TEXT NOT NULL, type TEXT NOT NULL, value TEXT NOT NULL,
                    resource_id TEXT NOT NULL REFERENCES resources(id), PRIMARY KEY(scope,type,value));
                CREATE INDEX aliases_resource ON aliases(resource_id);
                CREATE TABLE relations (source_id TEXT NOT NULL REFERENCES resources(id), type TEXT NOT NULL,
                    target_id TEXT NOT NULL REFERENCES resources(id), PRIMARY KEY(source_id,type,target_id));
                CREATE INDEX relations_target ON relations(target_id,type);
            ''')
            with connection:
                connection.executemany('INSERT INTO build_metadata VALUES (?,?)', sorted(metadata.items()))
                for item in document['resources']:
                    connection.execute('INSERT INTO resources VALUES (?,?,?,?,?,?)',
                        (item['id'], item['kind'], item['name'], canonical(item['attributes']),
                         canonical(item['credential_refs']), item.get('owner')))
                for item in document['resources']:
                    connection.executemany('INSERT INTO aliases VALUES (?,?,?,?)',
                        [(*alias_key(alias), item['id']) for alias in item['aliases']])
                    connection.executemany('INSERT INTO relations VALUES (?,?,?)',
                        [(item['id'], relation['type'], relation['target']) for relation in item['relations']])
            if connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise InvalidInventory('Built index failed integrity check')
        finally:
            connection.close()
        with temporary.open('r+b') as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        if os.name != 'nt':
            directory_fd = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary.exists():
            temporary.unlink()
    return metadata


def resolve(connection: sqlite3.Connection, *, resource_id: str | None = None,
            aliases: Sequence[dict[str, Any]] = ()) -> dict[str, Any]:
    matches = set()
    for alias in aliases:
        row = connection.execute(
            'SELECT resource_id FROM aliases WHERE scope=? AND type=? AND value=?',
            alias_key(alias)).fetchone()
        if row:
            matches.add(row[0])
    if resource_id:
        known = connection.execute('SELECT 1 FROM resources WHERE id=?', (resource_id,)).fetchone()
        if not known:
            return {'status': 'unknown_uuid', 'resource_id': None, 'candidates': sorted(matches)}
        matches.add(resource_id)
    if len(matches) > 1:
        return {'status': 'conflict', 'resource_id': None, 'candidates': sorted(matches)}
    if not matches:
        return {'status': 'unknown', 'resource_id': None, 'candidates': []}
    return {'status': 'resolved', 'resource_id': next(iter(matches)), 'candidates': sorted(matches)}


def dependents(connection: sqlite3.Connection, resource_id: str, limit: int = 100) -> dict[str, Any]:
    if not 1 <= limit <= 1000:
        raise InvalidInventory('limit must be 1..1000')
    if not connection.execute('SELECT 1 FROM resources WHERE id=?', (resource_id,)).fetchone():
        raise InvalidInventory('Unknown resource UUID')
    # UNION deduplicates nodes so dependency cycles cannot recurse indefinitely.
    steps = 0
    def bound():
        nonlocal steps
        steps += 1
        return int(steps > 1000)
    connection.set_progress_handler(bound, 1000)
    try:
        rows = connection.execute('''WITH RECURSIVE impact(id) AS (
            SELECT ? UNION SELECT relations.source_id FROM relations JOIN impact ON relations.target_id=impact.id
            WHERE relations.type IN ('runs-on','depends-on')
        ) SELECT resources.id,kind,name FROM resources JOIN impact USING(id)
        WHERE resources.id != ? ORDER BY resources.id LIMIT ?''', (resource_id, resource_id, limit + 1)).fetchall()
        return {'resources': [dict(row) for row in rows[:limit]], 'truncated': len(rows) > limit}
    finally:
        connection.set_progress_handler(None, 0)

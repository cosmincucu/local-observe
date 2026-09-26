"""Bounded state copies with logical SQLite readback; caller owns writer exclusion."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any

from .content import Conflict
from local_observe.inventory.validation import digest


def _regular(path, root):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path or not path.is_relative_to(root) or not path.is_file():
        raise Conflict('Expected a regular non-symlink file within approved root')
    return path


def _wal_bytes(path):
    """Return how many bytes `<path>-wal` holds, or 0 when the sidecar is absent.

    A SQLite database in WAL mode keeps committed pages in that sidecar until something folds them
    back into the `.db`. A read-only connection can only read past the `.db` when the matching `-shm`
    exists and is writable; without it SQLite answers from the older file alone and reports no problem
    at all. The size is taken with the default stat (a symlinked sidecar reports its target), which is
    the fail-closed direction: an unusual sidecar refuses the copy rather than being trusted with it.
    """
    try:
        return path.with_name(path.name+'-wal').stat().st_size
    except OSError:
        return 0


def _checkpoint(path, timeout, deadline):
    """Fold a live `-wal` into its database, only because the caller asked for this by name.

    This writes to the source, so the caller owns writer exclusion over the file exactly as it owns it
    over the copy. `TRUNCATE` rather than the default `PASSIVE`: it returns only once the log is folded
    in and emptied, so the read-only connection below cannot be left reading a `.db` whose newest
    commit is still in a sidecar this run then refuses to copy. A busy source (another writer holds the
    lock), a sidecar that survived the attempt and a past deadline all refuse the copy; nothing here
    falls back to copying the sidecar as bytes, which is what turns a truncated snapshot into a silent
    one.
    """
    try:
        with closing(sqlite3.connect(path, timeout=timeout)) as writer:
            writer.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    except sqlite3.Error as exc:
        raise Conflict('SQLite source could not be checkpointed for copying: '+type(exc).__name__) from exc
    if _wal_bytes(path):
        raise Conflict('Checkpoint left a non-empty WAL on the source; take writer exclusion or restore a copy')
    if time.monotonic() > deadline:
        raise Conflict('SQLite checkpoint exceeded the copy deadline')


def _logical(db):
    if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise Conflict('SQLite integrity check failed')
    schema = db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name').fetchall()
    tables, total = {}, 0
    for kind, name, _, _ in schema:
        if kind != 'table':
            continue
        hashes = []
        for row in db.execute('SELECT * FROM "'+name.replace('"', '""')+'"'):
            total += 1
            if total > 500000:
                raise Conflict('Logical verification row budget exceeded')
            hashes.append(hashlib.sha256(repr(row).encode()).hexdigest())
        tables[name] = {'rows': len(hashes), 'content_sha256': digest(sorted(hashes))}
    return {'schema_sha256': digest(schema), 'tables_sha256': digest(tables),
            'row_count': total, 'table_count': len(tables)}


def copy_state(sources: dict[str, tuple[Path | str, str]], allowed_root: Path | str, output: Path | str, *,
               max_bytes: int = 64*1024**2, timeout: float = 30,
               allow_checkpoint: bool = False) -> dict[str, Any]:
    """Copy explicit logical-name -> (path, json/sqlite) inputs into a NEW directory.

    Does not acquire application locks, restore live paths, or claim cross-file
    consistency. Caller must hold writer exclusion across all related inputs.
    Partial output is retained on failure. Reports contain hashes, never values.

    A SQLite source whose `-wal` sidecar still holds pages is refused, because the copy is made over a
    read-only connection that cannot always read that sidecar and would produce an intact-looking
    snapshot with the newest commits missing. `allow_checkpoint=True` says the caller holds the source
    alone and accepts that folding the WAL back in writes to it; a `-wal`/`-shm` file is never itself
    an input, since copying a sidecar as bytes is how a truncated snapshot gets made.
    """
    root, output = Path(allowed_root).absolute(), Path(output).absolute()
    if root.resolve(strict=True) != root or not root.is_dir():
        raise Conflict('Approved root must be an existing non-symlink directory')
    if (output.parent.resolve(strict=True) != output.parent or not output.is_relative_to(root)
            or not sources or type(max_bytes) is not int or max_bytes <= 0 or timeout <= 0
            or type(allow_checkpoint) is not bool):
        raise Conflict('Invalid bounded copy scope')
    selected = {}
    for name, (path, kind) in sources.items():
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,79}', name) or kind not in ('json', 'sqlite'):
            raise Conflict('Invalid logical state input')
        path = _regular(path, root)
        if path.name.endswith(('-wal', '-shm')):
            raise Conflict('A SQLite sidecar is never copied as bytes; copy the database it belongs to')
        if output.is_relative_to(path.parent):
            raise Conflict('Output overlaps a source directory')
        selected[name] = (path, kind)
    if sum(path.stat().st_size for path, _ in selected.values()) > max_bytes:
        raise Conflict('State inputs exceed copy budget')
    output.mkdir(mode=0o700)
    report, used = {}, 0
    deadline = time.monotonic() + timeout
    for name, (path, kind) in sorted(selected.items()):
        _regular(path, root)
        if kind == 'sqlite' and _wal_bytes(path):
            if not allow_checkpoint:
                raise Conflict('source has a live WAL; checkpoint it or pass allow_checkpoint')
            _checkpoint(path, timeout, deadline)
        target = output/(name+('.db' if kind == 'sqlite' else '.json'))
        with target.open('xb'):
            pass
        target.chmod(0o600)
        logical = None
        if kind == 'json':
            with path.open('rb') as stream:
                data = stream.read(max_bytes-used+1)
            if len(data) > max_bytes-used:
                raise Conflict('JSON copy exceeds remaining budget')
            json.loads(data)
            target.write_bytes(data)
            with path.open('rb') as stream:
                unchanged = stream.read(len(data)+1) == data
            if target.read_bytes() != data or not unchanged:
                raise Conflict('JSON changed during copy or readback differs')
        else:
            with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as source:
                source.execute('BEGIN')
                page_size = source.execute('PRAGMA page_size').fetchone()[0]
                if source.execute('PRAGMA page_count').fetchone()[0]*page_size > max_bytes-used:
                    raise Conflict('SQLite snapshot exceeds remaining byte budget')
                source.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                logical = _logical(source)
                # B023: `page_size` and the remaining budget are rebound by this very loop, so the
                # callback binds them at definition time instead of reading them at call time. Today
                # `source.backup()` calls it synchronously inside one iteration and nothing can rebind
                # them mid-backup; the defaults make that the contract rather than a happy accident.
                def progress(status, remaining, total, *, deadline=deadline, page_size=page_size,
                             budget=max_bytes-used):
                    if time.monotonic() > deadline or total*page_size > budget:
                        raise Conflict('SQLite backup exceeds time or byte budget')
                with closing(sqlite3.connect(target)) as destination:
                    source.backup(destination, pages=128, progress=progress, sleep=0.01)
            with closing(sqlite3.connect(target.as_uri()+'?mode=ro', uri=True)) as restored:
                restored.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
                if _logical(restored) != logical:
                    raise Conflict('Restored SQLite content differs')
        data = target.read_bytes()
        used += len(data)
        if used > max_bytes or time.monotonic() > deadline:
            raise Conflict('State copy budget exceeded')
        report[name] = {'kind': kind, 'bytes': len(data),
                        'sha256': hashlib.sha256(data).hexdigest(), 'logical': logical}
    return {'files': report, 'total_bytes': used, 'copy_verified': True,
            'application_recovery_proven': False, 'cross_file_consistency_proven': False}

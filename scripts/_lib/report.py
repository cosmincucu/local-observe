"""Atomic evidence writes with required scope or limitation declarations.

Readers see complete JSON, and an unscoped pass cannot be published as a report.
"""
from __future__ import annotations

import collections.abc
import json
import os
from pathlib import Path
import typing
import uuid

from _lib.require import require

#: A report must say, in one of these top-level keys, what it actually covered.
SCOPE_KEYS = ('scope', 'limitations')


def _states_scope(value: typing.Mapping[str, typing.Any]) -> None:
    """Refuse a report that never says what it covered.

    Args:
        value: The report mapping about to be written.

    Raises:
        ValueError: No top-level ``scope`` or ``limitations`` key holds real text.
    """
    for key in SCOPE_KEYS:
        stated = value.get(key)
        if isinstance(stated, str) and stated.strip():
            return
        if isinstance(stated, (list, tuple)) and stated and all(
                isinstance(item, str) and item.strip() for item in stated):
            return
    raise ValueError('Refusing an unscoped report: a top-level ' + ' or '.join(f"'{key}'" for key in SCOPE_KEYS)
                     + ' key must state what this run actually covered')


def _write(path: Path, value: typing.Any, *, replace: bool, indent: int) -> Path:
    """Serialise ``value`` durably to ``path`` and prove the file says the same thing.

    The bytes are flushed and ``fsync``ed before the file appears at ``path`` (exclusive create, or
    an atomic rename when ``replace`` is set), so a reader either sees the whole document or none
    of it. The mode is forced to ``0o600``: these files have carried bearer tokens.

    Args:
        path: Destination file.
        value: Any JSON-serialisable object.
        replace: Overwrite an existing file atomically instead of refusing.
        indent: Passed to :func:`json.dumps`.

    Returns:
        ``path``, so callers can chain a hash or a print.

    Raises:
        FileExistsError: ``path`` exists and ``replace`` is false.
        ValueError: The bytes read back differ from the bytes intended, or serialisation failed.
    """
    path = Path(path)
    text = json.dumps(value, indent=indent) + '\n'
    if replace:
        temporary = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex[:8])
        with temporary.open('x', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, path)
    else:
        with path.open('x', encoding='utf-8') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    require(json.loads(path.read_text(encoding='utf-8')) == json.loads(text),
            'Report readback differs from the value written: ' + path.name)
    return path


def write_json(path: Path, value: typing.Any, *, replace: bool = False, indent: int = 2) -> Path:
    """Write a non-report JSON artefact durably: a compose model, a plan, a mounted credential.

    Evidence reports go through :func:`write_report`, which additionally refuses an unscoped
    mapping. This function exists so the atomic write is not duplicated, not as a way to avoid the
    scope rule: a file that records what a run measured is a report.

    Args:
        path: Destination file.
        value: Any JSON-serialisable object.
        replace: Overwrite atomically instead of refusing an existing file.
        indent: Passed to :func:`json.dumps`.

    Returns:
        ``path``.
    """
    return _write(Path(path), value, replace=replace, indent=indent)


def write_report(path: Path, mapping: typing.Mapping[str, typing.Any], *, replace: bool = False,
                 indent: int = 2) -> Path:
    """Write an evidence report, refusing one that does not state its own scope.

    Args:
        path: Destination file.
        mapping: The report. Must be a mapping carrying a non-empty ``scope`` (or a non-empty
            ``limitations``) naming what the run covered - the field that would have made the
            unscoped verification counts impossible to publish.
        replace: Overwrite an existing report atomically; use for a report checkpointed while the
            run is still progressing, never to clobber a finished one.
        indent: Passed to :func:`json.dumps`.

    Returns:
        ``path``.

    Raises:
        ValueError: ``mapping`` is not a mapping, or states no scope.
        FileExistsError: ``path`` exists and ``replace`` is false.
    """
    require(isinstance(mapping, collections.abc.Mapping), 'A report must be a mapping, not ' + type(mapping).__name__)
    _states_scope(mapping)
    return _write(Path(path), dict(mapping), replace=replace, indent=indent)

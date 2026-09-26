"""The reviewed offline migration from an anomaly cursor's schema 1 to its schema 2 .

Enabling per-series coverage alerts on a deployment that already has a cursor is the one state change
the producer refuses to make on its own: ``anomaly_cursor.load`` rejects a schema-1 file read with
coverage on, and says *retain the existing cursor* rather than offering a conversion. This module is
that conversion, and nothing else. It is deliberately **not** reachable from the producer — no
environment variable, no start-time branch, no automatic call — because a service restart after a bad
configuration edit must never be able to decide that a monitor's memory changed shape.

Behaviour, and the reason for each:

* **dry-run is the default.** Everything is checked, nothing is written and no lock is taken; the exit
  code says whether a migration *would* be possible. ``--apply`` is the only mode that writes.
* **the output is a new file, never the input.** ``--output`` must not exist when ``--apply`` runs and
  is created with ``O_EXCL``, so a second apply refuses instead of replacing a file. The operator
  inspects the new file and swaps it into place themselves, with the producer stopped.
* **the source is never modified.** Nothing here truncates, renames, deletes or chmods the input.
* **``--expected-sha256`` is required in both modes.** A digest of the exact bytes the run was shown,
  re-checked after the cursor has been loaded, so a file that moved underneath the run is refused.

The checks are the producer's own, reused rather than restated: the cursor is loaded under the *old*
configuration with coverage off (every structural, digest and symlink rule in ``anomaly_cursor.load``),
every configured entry is replay-preflighted against the old configuration and then the new one, and
the result is validated as a schema-2 document before a byte of it is written. So this command cannot
produce a cursor its own consumer would refuse to open.

**Backups are the operator's precondition, not this tool's promise** — it copies nothing and claims no
restore. The deployment's procedure (``docs/units/anomaly-cursor.md``, "Backup and restore")
runs *before* ``--apply``. What is provable from this code is narrower: on success the source is
untouched and one new file exists; on refusal the source is untouched, **though a run that died partway
through the write leaves its own incomplete destination behind** rather than deleting a path it may not
have created. Stdlib only; no network, no store, no index.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import canonical
from local_observe.log import get_logger
from local_observe.platform import anomaly, anomaly_cursor
from local_observe.platform.owner import exclusive_owner

log = get_logger(__name__)
OUTPUT_MODE = 0o600


class Refusal(ValueError):
    """A refusal this command chose, carrying the one fixed code an operator greps for.

    Anything the cursor or the configuration loader raises is *not* a ``Refusal`` — it keeps its own
    class, which is how an operator tells "this command said no" from "the state file is damaged".
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _private_parent(path: Path, name: str) -> Path:
    """Return *path*'s parent, refusing a symlink or a group-readable directory at any level."""
    try:
        return anomaly_cursor.private_parent(path)
    except anomaly_cursor.CursorRefusal as exc:
        raise Refusal(f'{name}_parent_unsafe', str(exc)) from None


def _ancestry(path: Path, name: str) -> None:
    """Refuse a path reachable through a symlink, and (on Windows) an explicit UNC or device form."""
    try:
        anomaly_cursor._refuse_symlinked_ancestry(path)   # noqa: SLF001 — the module's own predicate
    except anomaly_cursor.CursorRefusal as exc:
        raise Refusal(f'{name}_parent_unsafe', str(exc)) from None


def _input_shape(path: Path) -> None:
    """Refuse a source that is absent, linked, a directory or reachable through a link."""
    _ancestry(path, 'input')
    if not path.exists():
        raise Refusal('input_absent', 'The named anomaly cursor does not exist; migration never '
                                      'creates one — a first start is what writes a schema-2 file')
    if path.is_symlink():
        raise Refusal('input_symlink', 'Refusing a symlinked anomaly cursor; migrate the real file')
    if path.is_dir():
        raise Refusal('input_is_directory', 'The named anomaly cursor is a directory')
    if not stat.S_ISREG(path.stat().st_mode):
        raise Refusal('input_not_regular', 'The input must be a regular cursor file')


def _read_source(path: Path, *, expected_sha256: str) -> tuple[bytes, Any]:
    """Return the cursor's exact bytes and parsed document, refusing other bytes than *expected*."""
    _input_shape(path)
    try:
        with path.open('rb') as stream:
            raw = stream.read(anomaly_cursor.MAX_CURSOR_BYTES + 1)
    except OSError as exc:
        raise Refusal('input_unreadable', 'The named anomaly cursor could not be read '
                                        f'({type(exc).__name__})') from None
    if len(raw) > anomaly_cursor.MAX_CURSOR_BYTES:
        raise Refusal('input_too_large', f'The anomaly cursor exceeds {anomaly_cursor.MAX_CURSOR_BYTES} '
                                        'bytes and is damage, not a migration candidate')
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise Refusal('input_digest_mismatch', 'The bytes at --input are not the bytes named by '
                                              '--expected-sha256; nothing was written')
    return raw, json.loads(raw, object_pairs_hook=anomaly_cursor._no_duplicates)   # noqa: SLF001


def build(*, cursor_path: Path | str, config_path: Path | str, source: str,
          expected_sha256: str, now: dt.datetime) -> dict[str, Any]:
    """Return the migrated document for the cursor at *cursor_path*, or raise without touching it.

    Read-only, and the order is the safety property: the source is hashed, the file must be schema 1,
    the *old* configuration is what the cursor is loaded and replay-checked against, and only then is
    the target configuration allowed to re-bind anything. A ``CursorRefusal`` means the file is damaged
    or belongs to another producer identity, and is reported as that — never repaired.

    :func:`anomaly_cursor.load` opens the path again, so the bytes it read are not the bytes that were
    hashed. The file is therefore re-read and re-checked against *expected_sha256* once the load is
    back, and a difference is refused (``source_changed``) rather than carried into the result. That
    narrows the window in which a third party could swap the file — it does not close it, and no
    statement here should be read as a guarantee about a writer that does not hold the owner lock.

    Raises:
        Refusal: a refusal of this command (``input_absent``, ``input_digest_mismatch``, …).
        anomaly_cursor.CursorRefusal: the cursor, its payloads or the migration refuse.
        ValueError: the configuration named does not parse.
    """
    path = Path(cursor_path)
    # Reuses the cursor's own digest-text validator rather than restating "64 hex, lowercase".
    if not isinstance(expected_sha256, str) or not anomaly_cursor.SHA256_TEXT.fullmatch(expected_sha256):
        raise Refusal('digest_malformed', '--expected-sha256 names 64 lowercase hex characters of the '
                                          'cursor file')
    _private_parent(path, 'input')
    raw, parsed = _read_source(path, expected_sha256=expected_sha256)
    version = parsed.get('schema_version') if isinstance(parsed, dict) else None
    # `type(...) is int`, not an equality test: `True == 1` and `1.0 == 1`, and a document whose version
    # field merely *equals* 1 is not one this producer wrote (`_schema_version` refuses it too — this
    # just makes sure such a file is reported as an unsupported input rather than as anything else).
    if type(version) is not int or version != anomaly_cursor.SCHEMA_VERSION:
        raise Refusal('input_not_schema_one', 'Only a schema-1 anomaly cursor can be migrated here; a '
                                             'schema-2 file is already the target shape, and any other '
                                             'version is damage. The input is untouched')
    target = anomaly.load_config(config_path)
    series = list(target['series'])
    if not any(anomaly_cursor.coverage_threshold(entry) for entry in series):
        raise Refusal('target_coverage_disabled', 'The target configuration enables no coverage '
                                                 'threshold, so a migration would change nothing and '
                                                 'the cursor stays schema 1')
    # The cursor is loaded, and its stored verdicts replay-checked, against the configuration that
    # actually wrote it: the target file's knobs minus the coverage threshold, which is the only thing
    # this migration is authorised to change.
    legacy = {**target, 'series': [{key: value for key, value in entry.items()
                                    if key != 'coverage_unjudgeable_windows'} for entry in series]}
    document = anomaly_cursor.load(path, source=source, coverage=False)
    if (canonical(document) != canonical(parsed)
            or _read_source(path, expected_sha256=expected_sha256)[0] != raw):
        raise Refusal('source_changed', 'The anomaly cursor changed while it was being read, so the '
                                        'verdicts checked here are not the bytes on disk; nothing was '
                                        'written from them')
    anomaly._require_bindings(legacy['series'], document, source=source, now=now)
    migrated = anomaly_cursor.migrate_document(
        document, legacy=legacy['series'], target=series,
        rule_versions={entry['id']: anomaly._rule_version(entry) for entry in series},
        source=source, now=now)
    if len(canonical(migrated).encode()) > anomaly_cursor.MAX_CURSOR_BYTES:
        raise Refusal('output_too_large', 'The migrated document exceeds the cursor byte limit')
    return {'document': migrated, 'input_sha256': hashlib.sha256(raw).hexdigest(),
            'pending': sum(1 for entry in document['series'].values() if entry['pending'] is not None)}


def _output_candidate(output: Path) -> None:
    """Refuse an output that is not a new file under a private parent."""
    if output.exists() or output.is_symlink():
        raise Refusal('output_exists', 'Refusing to overwrite an existing anomaly cursor file; name a '
                                       'new --output, or remove the file you made earlier yourself')
    _ancestry(output, 'output')
    _private_parent(output, 'output')


def _same_file(left: Path, right: Path) -> bool:
    """Return whether two paths name one file, or would resolve to one once created."""
    if os.path.normcase(os.path.abspath(str(left))) == os.path.normcase(os.path.abspath(str(right))):
        return True
    try:
        return left.exists() and right.exists() and os.path.samefile(left, right)
    except OSError:
        return False


def write_output(output: Path, document: Any) -> tuple[bytes, str]:
    """Create *output* exclusively with the canonical bytes of *document*; return them and their digest.

    ``O_EXCL`` is the whole promise: two simultaneous applies cannot both win, and a leftover file from
    a previous attempt is never replaced. The bytes are written, flushed and ``fsync``ed, the mode is
    set explicitly (``os.open``'s mode is filtered by umask), then the file is read back and compared.

    A failure here leaves an **incomplete file nobody asked for**, deliberately: deleting it would be
    this command destroying a path it may not have created. If the ``fsync`` fails the bytes may be
    visible to a running process and may not survive a crash, which is a different statement from "the
    write failed harmlessly" and is reported as its own code.
    """
    payload = canonical(document).encode()
    if len(payload) > anomaly_cursor.MAX_CURSOR_BYTES:
        raise Refusal('output_too_large', f'The migrated cursor would exceed '
                                          f'{anomaly_cursor.MAX_CURSOR_BYTES} bytes')
    descriptor: int | None = None
    try:
        descriptor = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, OUTPUT_MODE)
        with os.fdopen(descriptor, 'wb') as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            try:
                os.fsync(stream.fileno())
            except OSError as exc:
                raise Refusal('output_write_unsynced', f'The migrated cursor was written but not '
                                                       f'flushed ({type(exc).__name__}); the input is '
                                                       'unchanged and the output may not survive a '
                                                       'crash') from None
        output.chmod(OUTPUT_MODE)
    except FileExistsError:
        raise Refusal('output_exists', 'Refusing to overwrite an existing anomaly cursor file; name a '
                                       'new --output, or remove the file you made earlier yourself') from None
    except OSError as exc:
        raise Refusal('output_write_failed', f'The migrated cursor could not be written '
                                             f'({type(exc).__name__}); the input is unchanged and the '
                                             'output is unverified') from None
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    try:
        written = output.read_bytes()
    except OSError as exc:
        raise Refusal('output_readback_unreadable', f'The written cursor could not be read back '
                                                    f'({type(exc).__name__}); the input is unchanged '
                                                    'and the output is unverified') from None
    if written != payload:
        raise Refusal('output_readback_mismatch', 'The written cursor does not read back as the bytes '
                                                  'this command produced; the input is unchanged and '
                                                  'the output is unverified')
    return written, hashlib.sha256(written).hexdigest()


@contextlib.contextmanager
def _source_idle(cursor: Path) -> Iterator[None]:
    """Hold the cursor's own owner lock, refusing a producer that already holds it.

    Only the lock's *acquisition* is translated to ``source_locked``: an ``OSError`` from anything else
    in the body is a different problem and must keep its own class, or a readback failure would be
    reported as a busy producer.

    What the lock buys is exactly what the producer does with it — it holds ``exclusive_owner`` on this
    file for its whole life, so a running producer and an apply cannot both write it. It does **not**
    prove no other process touched the file: a writer that never asks for this lock can still rewrite
    it, which is why the digest is re-checked inside the lock and why stopping the producer stays part
    of the operator's procedure rather than something this function can observe.
    """
    holder = exclusive_owner(cursor)
    try:
        holder.__enter__()
    except OSError as exc:
        raise Refusal('source_locked', f'The anomaly cursor is owned by another process '
                                       f'({type(exc).__name__}); stop the producer before migrating') from None
    try:
        yield
    finally:
        holder.__exit__(None, None, None)


def migrate(*, cursor_path: Path | str, output_path: Path | str, config_path: Path | str,
            source: str, expected_sha256: str, apply: bool = False,
            now: dt.datetime | None = None) -> dict[str, Any]:
    """Dry-run or apply the schema-1 → schema-2 migration; return the report, never the payloads.

    ``--apply`` takes the cursor's ``exclusive_owner`` lock, exactly as the producer does for its whole
    life, and re-checks the source digest inside it, because the bytes were verified before the lock
    was won and could have moved since (:func:`_source_idle` for what the lock does and does not
    establish).

    Dry-run takes **no lock and writes nothing** — no lock file, no destination, no temp file. That is
    the difference between *checked* and *reserved*: a dry run that touched the directory would make an
    operator's ``ls`` an action with side effects.
    """
    moment = now or dt.datetime.now(dt.timezone.utc)
    cursor, output = Path(cursor_path), Path(output_path)
    if _same_file(cursor, output):
        raise Refusal('output_same_as_input', 'The output is the input; this command never rewrites a '
                                              'cursor in place')
    if not apply:
        prepared = build(cursor_path=cursor, config_path=config_path, source=source,
                         expected_sha256=expected_sha256, now=moment)
        _output_candidate(output)
        return {'status': 'dry_run', 'input': str(cursor), 'output': str(output),
                'input_sha256': prepared['input_sha256'],
                'output_sha256': hashlib.sha256(canonical(prepared['document']).encode()).hexdigest(),
                'series': len(prepared['document']['series']), 'pending': prepared['pending'],
                'would_write': True}
    _output_candidate(output)
    _input_shape(cursor)          # before the lock: a refusal must not leave a lock file behind
    _private_parent(cursor, 'input')
    with _source_idle(cursor):
        prepared = build(cursor_path=cursor, config_path=config_path, source=source,
                         expected_sha256=expected_sha256, now=moment)
        # Recheck immediately before exclusive creation; unrelated writers need not use our lock.
        _output_candidate(output)
        written, written_digest = write_output(output, prepared['document'])
    return {'status': 'migrated', 'input': str(cursor), 'output': str(output),
            'input_sha256': prepared['input_sha256'], 'output_sha256': written_digest,
            'bytes': len(written), 'series': len(prepared['document']['series']),
            'pending': prepared['pending']}


def main(argv: list[str] | None = None) -> int:
    """Run one migration from the command line; stdout keeps the platform CLI's JSON contract.

    ``python -m local_observe.platform.anomaly_migrate --input <cursor.json> --output <new.json>
    --config <anomaly.json> --source <producer-id> --expected-sha256 <64 hex> [--apply]``

    ``--config`` is the configuration the producer runs with **after** the migration: its thresholds are
    what the migrated cursor will be loaded under, and the old configuration the stored verdicts are
    checked against is that same file with the coverage thresholds removed. A refusal prints
    ``{"status": "error", "error_type": …}`` and exits 1. The report names the two digests, the file
    size and the pending count — never a payload, because this command's stdout lands in a shell
    history and a terminal scrollback.
    """
    parser = argparse.ArgumentParser(prog='python -m local_observe.platform.anomaly_migrate',
                                     description='Migrate an anomaly cursor from schema 1 to schema 2 '
                                                 'without touching the source file.')
    parser.add_argument('--input', type=Path, required=True,
                        help='the existing schema-1 cursor named by LO_ANOMALY_CURSOR')
    parser.add_argument('--output', type=Path, required=True,
                        help='the new schema-2 cursor; it must not exist yet')
    parser.add_argument('--config', type=Path, required=True,
                        help=f'the same document ${anomaly.CONFIG_ENVIRONMENT} names, with the '
                             'coverage thresholds enabled')
    parser.add_argument('--source', required=True,
                        help=f'the producer identity in ${anomaly.SOURCE_ENVIRONMENT}; it must match '
                             'the cursor')
    parser.add_argument('--expected-sha256', required=True,
                        help='sha256 of the input file right now; required in both modes')
    parser.add_argument('--apply', action='store_true',
                        help='write --output; without it nothing is written and no lock is taken')
    args = parser.parse_args(argv)
    try:
        report = migrate(cursor_path=args.input, output_path=args.output, config_path=args.config,
                         source=args.source, expected_sha256=args.expected_sha256, apply=args.apply)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        # Class and this module's code only: an OSError message can echo the path it failed on, and a
        # cursor path is topology. The full sentence reaches a reader at DEBUG, as everywhere else.
        extra: dict[str, Any] = {'error_class': type(exc).__name__}
        if isinstance(exc, Refusal):
            extra['refusal'] = exc.code
        elif isinstance(exc, anomaly_cursor.CursorRefusal):
            extra['refusal'] = 'cursor_refused'
        log.warning('Anomaly cursor migration refused', extra=extra)
        log.debug('Anomaly cursor migration details', exc_info=True)
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__}))
        return 1
    log.info('Anomaly cursor migration finished',
             extra={'status': report['status'], 'pending': report['pending']})
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

"""Acknowledge one configuration change, so the drift incident it opened can close (drift resolution).

The producer in `configdrift.py` reports that an artifact's bytes moved and never claims the change was
harmless — so it can open an incident and, on its own, never close one. Closing takes a ``resolved``
event on the same condition key, and `state.Store.intake` is the only writer that incident table has.
This module is the human half of that loop: an operator who has *seen* the change, checked it and
accepted it files a small durable record here, and a **later** round of the producer turns that record
into the ordinary `drift`/`resolved` event that closes the incident. Nothing is deleted, no rule is
disabled and no finding is suppressed — an acknowledgement closes one incident and silences nothing.

**Who may ack, and what that claim is worth.** A human operator with write access to the acknowledgement
directory and to the platform database — the same trust level `cli.py` already assumes ("Trusted local
operator CLI", no role token, no HTTP). `--actor` is recorded, in the record and in the audit row, and
it is **not authenticated**: there is no local authentication path outside the API (whose routes are not
this card's file), so anyone who can run this command can attach any bounded name to `actor`. That is a
stated limit of the shipped tool, not a bug to fix by editing a string, and closing it needs a
`state.py` change plus an API route (see the unit document).

**Why the audit row is written before the file.** `Store.audit` lands in the append-only table the
platform's readers walk; the file is what the producer acts on. An audit row with no file is an
acknowledgement that did not take effect — the change stays open, and re-running the command files it
properly. A file with no audit row is an acknowledgement nobody owns: the producer would close an
incident on an instruction with no recorded author. The first is a lost click, the second is a forged
paper trail, so the row goes first and the loss on a crash between them is the harmless one.

**Why this never touches the cursor and never takes the owner lock.** `configdrift.main` holds
`owner.exclusive_owner` on the producer's cursor for its whole life; a tool that waited on that lock
would hang forever, and a tool that wrote the cursor would be a second writer of a single-writer file.
So this module writes the record and the audit row and lets the producer notice them on its next round
— which is also why an acknowledgement is **eventually** applied rather than immediately: the resolve
lands on the round after the one that saw the record.

Stdlib only, like the producer. The record format and every refusal of it live in `configdrift`, because
the reader and the writer must not grow two opinions: this tool writes nothing its own reader refuses.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import digest, utc_text
from local_observe.log import get_logger
from . import configdrift
from .state import Store, clock, identifier

log = get_logger(__name__)

# The audit operation this tool writes. No new audit category is needed for it:
# `audit_reader.CATEGORIES` is ('all', 'action-transitions'), and an operation the reader does not know
# simply appears under 'all', which is where an operator looks for "who told this producer what".
OPERATION = 'drift.acknowledged'
# The record's mode, deliberately NOT the cursor's 0600. The cursor holds each artifact's retained text
# and so holds configuration content; an acknowledgement holds a digest, a rule id, an actor name and a
# one-sentence reason — and the process that must read it is the producer, which usually runs as another
# account. A private acknowledgement is an acknowledgement that never takes effect.
ACK_MODE = 0o644


class Refusal(ValueError):
    """A refusal this module chose, carrying the one fixed code an operator greps for.

    It exists because the CLI's contract on stdout is `{'status': 'error', 'error_type': …}` and nothing
    else — a refusal that names no reason is a mystery on a terminal. Anything the platform's own readers
    raise (a `ValueError` from `validate_acknowledgement`, an `OSError` from the tree) is **not** a
    `Refusal`, logs only its class name, and keeps its class in `error_type`: this class claims a code
    only for the sentences this file wrote. Never the message text on the WARNING line: an `OSError`
    message can echo the path it failed on, and this tool runs against trees that hold configuration.
    """

    def __init__(self, code: str, message: str) -> None:
        """Remember *code* as the machine-readable half of the refusal, *message* as the human half."""
        super().__init__(message)
        self.code = code


def write_acknowledgement(root: Path | str, document: dict[str, Any]) -> Path:
    """Install one validated record at its artifact's path, atomically, and return that path.

    Temporary file in the same directory, fsync, then one `os.replace`: the producer reads this tree
    while it runs, so a half-written record is a record it refuses, and a torn write that reads as
    valid JSON would be an instruction the operator never finished typing. The parent directory is
    created when absent — the operator named the root, and one missing `<resource_id>/` directory must
    not be a reason an acknowledgement cannot be filed.

    Callers pass a document that has already been through `configdrift.validate_acknowledgement`, which
    is what keeps the promise this module lives by: the writer can never install what the reader would
    refuse. The bytes are the canonical form (`sort_keys`), so the record digest the producer computes is
    the same digest this function returned for the file it just wrote.
    """
    destination = configdrift.acknowledgement_path(root, document['resource_id'], document['name'])
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + '.tmp')
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, ACK_MODE)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        json.dump(document, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        # `os.open`'s mode is filtered by the creating process' umask, and `os.replace` keeps the mode of
        # a file it overwrites: setting it here is what makes the second acknowledgement of an artifact
        # as readable as the first, whoever filed the one before it.
        temporary.chmod(ACK_MODE)
    except OSError:
        pass
    os.replace(temporary, destination)
    return destination


def acknowledge(*, config_path: Path | str, database_path: Path | str, resource_id: str, name: str,
                artifact_sha256: str, actor: str, reason: str,
                now: dt.datetime | None = None) -> dict[str, Any]:
    """File one acknowledgement of one digest of one artifact, or refuse and write nothing.

    The order is the design, and every step is a refusal that leaves the previous steps' state intact:

    1. `configdrift.load_config` — and refuse when the document names no ``acknowledgements``
       directory. The resolve path is off until an operator puts one in the configuration, and this tool
       does not guess where it would have gone.
    2. The artifact must be **configured**: a record for something the configuration does not watch
       would sit unread in the tree forever, which is worse than a refusal.
    3. ``--database`` must exist. `Store(path)` **creates** an empty database, and an acknowledgement
       audited into a file nobody reads records nothing: the producer's own intakes go to the platform's
       database, not to a new one beside it.
    4. The digest must be the one **on disk right now**: `read_snapshot` is called again here, through
       the same reader the producer uses. An operator can only acknowledge the change they were shown,
       and a tool that wrote an acknowledgement for bytes it could not see would let one record close
       every future revision of an artifact. Its *shape* is checked first (64 lowercase hex), so a typo
       in the flag is reported as a malformed digest rather than as a disagreement with the tree.
    5. The record is built and passed through `configdrift.validate_acknowledgement` — the writer must
       never write what the reader refuses.
    6. The audit row, inside `store.transaction()`, **before** the file: see the module docstring.
    7. The file, atomically (`write_acknowledgement`).

    Raises:
        Refusal: A refusal this module chose — `no_acknowledgements_directory`, `artifact_not_configured`,
            `database_absent`, `digest_malformed`, `digest_not_on_disk` — each naming what to fix.
        ValueError: Anything the reader refuses about the record itself (an unbounded actor, a reason
            too long), reported by class because the sentence behind it came from `configdrift`.
    """
    config = configdrift.load_config(config_path)
    root = config['acknowledgements']
    if root is None:
        raise Refusal('no_acknowledgements_directory', 'Drift configuration names no "acknowledgements" '
                                                       'directory; the resolve path is off until it does')
    declared_id = identifier(resource_id)
    entry = next((item for item in config['resources']
                  if item['resource_id'] == declared_id and item['name'] == name), None)
    if entry is None:
        raise Refusal('artifact_not_configured', 'That artifact is not configured for drift; nothing '
                                                 'would ever read this acknowledgement')
    database = Path(database_path)
    if not database.is_file():
        raise Refusal('database_absent', 'Refusing to audit an acknowledgement into a database that does '
                                         'not exist; name the platform database')
    if not isinstance(artifact_sha256, str) or not configdrift.SHA256_TEXT.fullmatch(artifact_sha256):
        raise Refusal('digest_malformed', 'An acknowledgement names 64 lowercase hex characters')
    current = configdrift.read_snapshot(config['root'], declared_id, name)
    if current.sha256 != artifact_sha256:
        raise Refusal('digest_not_on_disk', 'Refusing an acknowledgement for bytes that are not on disk; '
                                            'run `lo-platform drift` to read the current digest')
    moment = clock(now)
    document = configdrift.validate_acknowledgement({
        'schema_version': 1, 'resource_id': declared_id, 'name': entry['name'],
        'rule_id': entry['rule_id'], 'artifact_sha256': artifact_sha256, 'actor': actor,
        'reason': reason, 'at': utc_text(moment)})
    record_digest = digest(document)
    store = Store(database)
    with store.transaction() as connection:
        store.audit(connection, moment, document['actor'], OPERATION, document['rule_id'], document)
    path = write_acknowledgement(root, document)
    log.info('Drift acknowledgement filed',
             extra={'artifact': configdrift.entry_key(entry), 'rule_id': document['rule_id'],
                    'acknowledgement': record_digest})
    return {'status': 'acknowledged', 'artifact': configdrift.entry_key(entry),
            'rule_id': document['rule_id'], 'artifact_sha256': document['artifact_sha256'],
            'acknowledgement_sha256': record_digest, 'path': str(path)}


def main(argv: list[str] | None = None) -> int:
    """Run one acknowledgement from the command line; stdout keeps the platform CLI's JSON contract.

    ``python -m local_observe.platform.drift_ack --config <drift.json> --database <state.db>
    --resource-id <uuid> --name <artifact> --sha256 <64 hex> --actor <label> --reason "<text>"``

    A refusal prints ``{"status": "error", "error_type": <class>}`` and exits 1, exactly as
    `lo-platform` does: the diagnosis goes to the log stream as an exception **class**, never as
    exception text, because a message raised by `os` can echo a path. This is the operator's door, not a
    second producer: it opens no cursor, takes no owner lock and emits no event — the producer's next
    round is what turns this record into the event that closes the incident.
    """
    parser = argparse.ArgumentParser(prog='python -m local_observe.platform.drift_ack',
                                     description=__doc__)
    parser.add_argument('--config', type=Path, required=True,
                        help=f'the same drift document ${configdrift.CONFIG_ENVIRONMENT} names; the '
                             f'acknowledgement root is read from it, never from here')
    parser.add_argument('--database', type=Path, required=True,
                        help='the platform database to audit into; it must already exist')
    parser.add_argument('--resource-id', required=True, help='the declared inventory UUID of the artifact')
    parser.add_argument('--name', required=True, help='the artifact name as the configuration spells it')
    parser.add_argument('--sha256', required=True,
                        help='the digest being accepted; it must equal the bytes on disk right now')
    parser.add_argument('--actor', required=True,
                        help='the named human this acknowledgement belongs to; recorded, not verified')
    parser.add_argument('--reason', required=True,
                        help='one sentence on why the change is accepted (1..256 characters)')
    args = parser.parse_args(argv)
    try:
        result = acknowledge(config_path=args.config, database_path=args.database,
                             resource_id=args.resource_id, name=args.name, artifact_sha256=args.sha256,
                             actor=args.actor, reason=args.reason)
    except (ValueError, OSError, KeyError, TypeError, sqlite3.Error) as exc:
        # Only the class is logged, plus this module's own fixed code when there is one: an OSError
        # message can carry the path it failed on, and this tool runs against trees holding
        # configuration. The full sentence reaches a reader at DEBUG, as everywhere else in the CLI.
        extra: dict[str, Any] = {'error_class': type(exc).__name__}
        if isinstance(exc, Refusal):
            extra['refusal'] = exc.code
        log.warning('Drift acknowledgement refused', extra=extra)
        log.debug('Drift acknowledgement details', exc_info=True)
        print(json.dumps({'status': 'error', 'error_type': type(exc).__name__}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

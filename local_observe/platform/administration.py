"""The durable half of the administration surface: the jobs an operator approved, and the bearers an operator cut.

Two capabilities live here, and they share a file because they share a reason. Both answer the question an
operator standing away from the host actually asks: *"what may I make this platform do, and what did it
do?"* Before schema v14 the honest answer to the first half was "nothing, without a shell on the machine",
because every administration capability in ``docs/api/coverage.yaml`` was a ``cli`` row. What this module
adds is the narrow set of acts a serving process can perform **with its own privileges on its own file** and
no new authority: a verified copy of the operational database, and the verification of a copy it made
earlier. What it deliberately does not add is any act needing a container runtime, a staging host, a second
store's administrator credentials, or secret material — those exclusions and their reasons are in
``docs/api/COVERAGE.md``.

Three rules hold everything here together, and each is a rule this repository already had:

* **A job exists only as the result of an approval that named an exact plan.** The plan is *derived* from
  the state of the database — its version, the naming rule of the artifact it would write, the digest of the
  artifact under test — rather than stored, so there is no plan row to expire, adopt or race. The server
  recomputes the same binding when the write arrives and refuses (412) if the caller approved something
  else. An approval that does not bind the bytes about to be copied is a rubber stamp with extra steps.
* **Nothing runs on the serving loop.** :func:`drain` is called by ``api.py``'s delivery loop through
  ``run_to_completion``, the same machinery that keeps ``expire_actions`` and a delivery attempt off the
  loop and outlasts shutdown. A state copy is a SQLite call bounded by the size of the database, so the
  claim is one short transaction, the copy is no transaction at all, and the outcome is a second short one.
  Holding ``BEGIN IMMEDIATE`` across a copy would stall every other write in the platform for the length of
  the backup — the opposite of what an on-call operator asked for.
* **A refusal writes no row, and a failure names no path.** A job that faulted is stored with the
  *class* of its exception, not its message: SQLite and OS messages name files, and an answer repeating one
  has told a caller the deployment layout it was never handed. The traceback goes to the log, where somebody
  with the host can read it.

What this module is NOT. Not an executor of arbitrary work: no callable, command, query, path or URL enters
from a request, and the two kinds below are the whole vocabulary (``state.PLATFORM_JOB_KINDS`` is the
schema's CHECK as well as this file's). Not a queue: no lease, no retry count, no worker pool — two copies
of one database running at once is corruption rather than throughput, and a retried backup is a new backup
with its own row. Not a credential authority: ``credential_revocations`` is a deny-list consulted on the way
in, while the mounted role file stays the only statement of who may call at all.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import re
import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from local_observe.inventory.validation import canonical, digest, utc_text
from local_observe.log import get_logger
from . import api_contract
from .state import (APPLICATION_ID, CREDENTIAL_REVOCATION_OPERATION, CREDENTIAL_REVOCATION_REASON_LIMIT,
                    CREDENTIAL_REVOCATION_TABLE, CREDENTIAL_REVOKED_STATE, PLATFORM_JOB_KINDS,
                    PLATFORM_JOB_OPERATION, PLATFORM_JOB_RECEIPT_LIMIT, PLATFORM_JOB_STATES,
                    PLATFORM_JOB_TABLE,
                    PLATFORM_JOB_TERMINAL_STATES, VERSION, Actor, StateError, Store, clock, label)

log = get_logger(__name__)

#: The closed job vocabulary this build can run, and the states one row passes through — the schema's own
#: CHECK values, named here so the routes, the OpenAPI enums and the plan derivation read one list.
KINDS = PLATFORM_JOB_KINDS
STATES = PLATFORM_JOB_STATES
TERMINAL_STATES = PLATFORM_JOB_TERMINAL_STATES
BACKUP = 'state.backup'
VERIFICATION = 'state.backup_verification'

#: The actor the delivery loop runs a job as. It is not a credential: no bearer names it, it cannot be
#: assumed by a request, and it is the same kind of internal actor ``state.MIGRATE_ACTOR`` is for a
#: migration. The human whose approval put the job here is recorded separately, in `approved_by`.
JOB_ACTOR = 'platform-jobs'

#: How many succeeded backups one revocation or artifact read names before it says it stopped counting.
#: Both lists are rare-and-permanent rather than high-volume, so this is a ceiling on an answer, stated in
#: the answer, for the reason `maintenance_api` gives for its own bounds.
REVOCATION_LIST_LIMIT = 200

#: The artifact naming rule, published inside every backup plan. It is a *rule*, not a path: the plan digest
#: covers this string, and the state file's own name never appears in a plan, a digest or an answer.
ARTIFACT_RULE = '<database>.api-backup-<utc-stamp>-<job>.db'
#: Where a copy lands, in the words the plan uses. Deliberately unflattering, because it is true: a copy
#: beside the state file is protection against a bad migration, not against a lost disk, and the CLI form
#: that names its own destination remains the one that survives a dead volume.
DESTINATION_RULE = 'beside the operational database file'
#: The stamp inside a generated name — the shape ``Store._snapshot`` already uses, so two files an operator
#: finds beside the database read the same way.
_STAMP = '%Y%m%dT%H%M%SZ'
#: One generated artifact name, and nothing else. `/` is outside the class, so a name read back out of a
#: stored receipt can neither leave the state directory nor have been a path in the first place.
ARTIFACT_NAME = re.compile(r'[A-Za-z0-9_.:@+-]{1,128}\.api-(?:backup|verify)-\d{8}T\d{6}Z-[0-9a-f]{8}\.db\Z')
#: One lowercase sha256, as stored in a receipt or demanded in an approval.
HEX64 = re.compile(r'[0-9a-f]{64}\Z')

# --------------------------------------------------------------------------------------------- refusals

#: The field that carries an approved plan digest. Named once: the route, its refusal, the OpenAPI body and
#: the tests cannot disagree about what a caller must send.
APPROVAL_FIELD = 'approval'
#: The body fields one state job request accepts, spelled once for `administration_api`'s refusal.
BACKUP_BODY_KEYS = frozenset({APPROVAL_FIELD})
VERIFICATION_BODY_KEYS = frozenset({'backup_job', APPROVAL_FIELD})

PLAN_KIND_UNKNOWN = 'A state job kind must be state.backup or state.backup_verification'
APPROVAL_REQUIRED = f'A state job must carry the 64-character plan digest it was read as, in `{APPROVAL_FIELD}`'
BACKUP_JOB_REQUIRED = 'A backup verification names the backup_job whose artifact it restores'
PLAN_APPROVAL_MISMATCH = 'This approval does not name the plan this request would run; read the plan again'
NO_SUCH_JOB = 'No such administration job'
NOT_VERIFIABLE = 'Only a succeeded state.backup job has an artifact to verify'
RUNNING_IS_NOT_INTERRUPTIBLE = ('A state copy already running is not interruptible; it reports its own '
                                'outcome, and a cancellation pretending otherwise would leave the file and '
                                'the row disagreeing about what happened')
ALREADY_SETTLED = 'This job already reported its outcome; a cancellation would rewrite history'
ARTIFACT_MISSING = 'The artifact named by that backup job is not in the state directory'
ARTIFACT_UNREADABLE = 'The artifact named by that backup job is not a name this service issues'
INTEGRITY_FAILURE = 'Backup integrity failure'
WAL_SIDECAR = ('That artifact has an un-recovered -wal sidecar, so the database is two files and this job '
               'verifies one; retake the copy or recover the sidecar offline')
DIGEST_MISMATCH = 'The artifact no longer hashes to what that backup reported'
#: The failure sentences a job receipt may carry. Each is fixed wording written in this file or in
#: ``state.Store.backup``, so a receipt can explain *why* a copy failed without reproducing an SQLite or
#: operating-system message that names a file. Anything else is reported by exception class: the difference
#: between an explanation and a leak, stated as a set.
SAFE_FAILURES = frozenset({ARTIFACT_MISSING, ARTIFACT_UNREADABLE, WAL_SIDECAR, DIGEST_MISMATCH,
                           NOT_VERIFIABLE, INTEGRITY_FAILURE})
IDENTITY_UNKNOWN = ('No credential in this installation mounts that identity, so there is nothing to revoke:'
                    ' the mounted role file is enrollment, and revocation only refuses a bearer that exists')
ALREADY_REVOKED = 'That identity is already revoked'

#: Why these jobs answer 202 rather than a receipt in the response: the work is bounded by the size of the
#: database, not by the request that asked for it. Quoted in the OpenAPI description and in the coverage
#: page, so the promise is stated where a caller reads it before sending the bytes.
ASYNC_REASON = 'The work is bounded by the size of the database, not by the request'


# ------------------------------------------------------------------------------------------ the plans


def backup_plan(store: Store) -> dict[str, Any]:
    """Return the reviewable plan one state backup would carry, with its digest.

    Nothing is read from a plan table, because there is none: the plan *is* the state of this database at
    the instant it was read. Deriving it is what makes an approval mean something — the server recomputes
    the same binding when the write arrives, so a caller cannot approve a plan read against one build and
    then have a job run against another. An upgrade moves `target_version`, and every approval minted before
    it stops being honoured with 412 instead of being quietly reinterpreted.

    The state file's own name appears nowhere here: the naming *rule* does, which is all an operator needs
    in order to recognise the file afterwards.
    """
    binding: dict[str, Any] = {'application_id': APPLICATION_ID, 'kind': BACKUP,
                               'schema_version': store.status()['schema_version'], 'target_version': VERSION,
                               'artifact_rule': ARTIFACT_RULE, 'destination': DESTINATION_RULE,
                               'replaces_existing': False,
                               'verified_by': 'sqlite integrity_check on the copy, then this build opening it'}
    return {**binding, 'digest': digest(binding)}


def verification_plan(store: Store, backup_job: str) -> dict[str, Any]:
    """Return the plan that would verify the artifact one succeeded backup wrote, with its digest.

    `backup_job` is a job id and never a path: the artifact is resolved from the receipt this service wrote
    for that job, which is what makes an arbitrary file on the host unreachable through this route. The
    digest binds the recorded sha256 and size, so an approval to verify *this* copy cannot be replayed
    against a different one, and a copy that has since changed fails its own job rather than silently
    proving something else.

    Raises:
        api_contract.ContractError: 404 `not_found` for a job that does not exist; 409 `conflict` for a job
            that is not a succeeded backup (there is no artifact yet, and promising one is the invention
            this refuses), or for a receipt whose artifact name this build would not have issued.
    """
    row = _job_row(store, backup_job)
    if row['kind'] != BACKUP or row['state'] != 'succeeded':
        # Said here rather than discovered as "the receipt has no artifact in it": a booked-but-unrun backup
        # and a receipt that lost its artifact name are different facts, and the first is the ordinary case
        # for a caller who pressed verify a second too early.
        raise api_contract.ContractError(409, 'conflict', NOT_VERIFIABLE)
    return _verification_binding(row)


def _verification_binding(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return one backup row's verification binding and digest, from the row already in hand.

    Split out because the ledger page builds many documents at once: a page of twenty succeeded backups
    would otherwise open twenty transactions to re-derive twenty digests, each from rows this same
    transaction already holds. Same binding, same digest, no second read.
    """
    receipt = _receipt(row)
    for key in ('artifact', 'sha256'):
        value = receipt.get(key)
        if not isinstance(value, str):
            raise api_contract.ContractError(409, 'conflict', ARTIFACT_UNREADABLE)
    if not ARTIFACT_NAME.fullmatch(receipt['artifact']) or not HEX64.fullmatch(receipt['sha256']):
        raise api_contract.ContractError(409, 'conflict', ARTIFACT_UNREADABLE)
    binding: dict[str, Any] = {'application_id': APPLICATION_ID, 'kind': VERIFICATION,
                               'backup_job': row['id'], 'artifact_sha256': receipt['sha256'],
                               'bytes': receipt.get('bytes'),
                               'restore': 'a copy of the artifact into a scratch file this job then deletes',
                               'opens_with': 'this build only; an older copy needs lo-platform migrate on it',
                               'scratch_removed': True}
    return {**binding, 'backup_job': row['id'], 'digest': digest(binding)}


# ------------------------------------------------------------------------------------------- the ledger


def request_backup(store: Store, body: Mapping[str, Any], actor: Actor, *,
                   now: dt.datetime | None = None) -> dict[str, Any]:
    """Book one state backup, and only if the body's approval still names the plan this database would copy.

    The row is written `accepted`: nothing has run yet, and this function does not run it either. That is
    the honest meaning of the 202 the transport answers with — the platform has promised the work and has
    written down that it promised, which survives a restart. Whether it finished is a question :func:`job`
    answers.

    Raises:
        api_contract.ContractError: 400 `invalid_request` for a malformed approval; 412 `stale_revision`
            when the plan this database would run no longer matches the digest offered. Neither writes.
    """
    offered = _approval(body.get(APPROVAL_FIELD))
    if offered != backup_plan(store)['digest']:
        raise api_contract.ContractError(412, 'stale_revision', PLAN_APPROVAL_MISMATCH)
    return _admit(store, kind=BACKUP, plan_sha256=offered, subject='state', actor=actor, now=now)


def request_verification(store: Store, body: Mapping[str, Any], actor: Actor, *,
                         now: dt.datetime | None = None) -> dict[str, Any]:
    """Book the verification of one backup's artifact, approved against the plan that names its digest.

    Raises:
        api_contract.ContractError: 400 `invalid_request` for a missing or malformed `backup_job` or
            approval; the refusals of :func:`verification_plan`; 412 `stale_revision` when the artifact's
            recorded digest changed between the read and this write.
    """
    offered = _approval(body.get(APPROVAL_FIELD))
    source = body.get('backup_job')
    if not isinstance(source, str) or not _is_uuid(source):
        raise api_contract.ContractError(400, 'invalid_request', BACKUP_JOB_REQUIRED)
    if offered != verification_plan(store, source)['digest']:
        raise api_contract.ContractError(412, 'stale_revision', PLAN_APPROVAL_MISMATCH)
    return _admit(store, kind=VERIFICATION, plan_sha256=offered, subject=source, actor=actor, now=now)


def job(store: Store, job_id: str) -> dict[str, Any]:
    """Return one job document: its row, its receipt, and for a backup what verifying it found.

    A succeeded backup carries a `verification` block rather than making the caller walk the ledger to learn
    whether anyone has ever read its artifact back. Its `state` is `unverified` when no verification job
    exists for it and otherwise the state of the most recent one — including an `accepted` or `running`
    verification, because "someone is checking it now" is a different fact from "nobody has".

    Raises:
        api_contract.ContractError: 404 `not_found` for an id that is not canonical or names nothing.
    """
    with store.transaction() as connection:
        return _document(connection, _known_row(connection, job_id))


def page(store: Store, *, limit: int = api_contract.PAGE_LIMIT_DEFAULT,
         cursor: str | None = None) -> dict[str, Any]:
    """Return one bounded page of the job ledger, newest first.

    No filters, and deliberately so: this is `api_contract.page_params`'s rule ("a page query takes only
    `limit` and `cursor`") applied to a second family, and the reason `dispositions.page` gives for it — an
    operator narrows the answer by paging through it, and a filter nobody has to parse is a filter nobody can
    forget to enforce. The walk is by `rowid`, the same honest monotonic position every other list in this
    package uses: `admitted_at` is not unique (two approvals inside one microsecond are available to a fast
    operator) and a page key that can repeat loses or repeats rows.

    Raises:
        api_contract.ContractError: 400 `invalid_pagination` for a cursor that is not a position.
    """
    position = _position(cursor)
    with store.transaction() as connection:
        rows = connection.execute(
            f'SELECT rowid AS position, * FROM {PLATFORM_JOB_TABLE} WHERE rowid<? ORDER BY rowid DESC LIMIT ?',
            (position, limit)).fetchall()
        documents = [_document(connection, row) for row in rows]
        positions = {row['id']: row['position'] for row in rows}
        return api_contract.page_payload(documents, limit=limit,
                                         cursor_for=lambda row: positions[row['job_id']])


def cancel(store: Store, job_id: str, actor: Actor, *,
           now: dt.datetime | None = None) -> dict[str, Any]:
    """Withdraw a job this process has not started, and say plainly why a running one stays.

    `accepted` is the only cancellable state, and the reason is physical: the copy is a SQLite call holding
    an open file, and this build has no way to stop one mid-flight and still claim to know what its output
    contains. A cancellation of a `running` job therefore refuses (409) rather than setting a flag some
    later code might honour — the flag would be a promise about work already happening.
    """
    moment = clock(now)
    with store.transaction() as connection:
        current = _known_row(connection, job_id)
        if current['state'] == 'running':
            raise api_contract.ContractError(409, 'conflict', RUNNING_IS_NOT_INTERRUPTIBLE)
        if current['state'] in TERMINAL_STATES:
            raise api_contract.ContractError(409, 'conflict', ALREADY_SETTLED)
        connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=?, finished_at=? WHERE id=?',
                           ('cancelled', utc_text(moment), current['id']))
        store.audit(connection, moment, actor.identity, PLATFORM_JOB_OPERATION, current['id'],
                    {'kind': current['kind'], 'action': 'cancelled', 'plan_sha256': current['plan_sha256']})
        return _document(connection, _known_row(connection, current['id']))


# ------------------------------------------------------------------------------------------ the runner


def drain(store: Store, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Claim the oldest booked job, run it, and report what this call saw.

    One job per call, and the caller is ``api.py``'s delivery loop: a second concurrent copy of one database
    is not throughput but a race over the same pages, and a queue that allowed it would be a feature nobody
    could use. Zero is a normal answer — it says nothing was booked.

    Raises nothing on a job failure: a job that faulted is stored `failed` with its exception's class name,
    logged with its traceback, and this function answers the counts it moved. A `Store` that cannot be
    opened at all is left to raise, because that is a fact about the process rather than about the job.
    """
    moment = clock(now)
    with store.transaction() as connection:
        row = connection.execute(
            f'SELECT * FROM {PLATFORM_JOB_TABLE} WHERE state=? ORDER BY rowid LIMIT 1',
            ('accepted',)).fetchone()
        if row is None:
            return {'claimed': 0, 'job_id': None, 'outcome': None}
        connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=?, started_at=? WHERE id=? AND state=?',
                           ('running', utc_text(moment), row['id'], 'accepted'))
        if connection.execute('SELECT changes()').fetchone()[0] != 1:
            # Another writer took it between the SELECT and the UPDATE. Nothing ran, and this answer says so
            # rather than claiming a job this call never held.
            return {'claimed': 0, 'job_id': None, 'outcome': None}
        store.audit(connection, moment, JOB_ACTOR, PLATFORM_JOB_OPERATION, row['id'],
                    {'kind': row['kind'], 'action': 'started', 'plan_sha256': row['plan_sha256']})
        claimed = dict(row)
    outcome, receipt = _execute(store, claimed)
    return {'claimed': 1, 'job_id': claimed['id'], 'outcome': outcome,
            'settled': _settle(store, claimed['id'], outcome, receipt, clock(None))}


def recover(store: Store, *, now: dt.datetime | None = None) -> int:
    """Mark every `running` job `unknown`, and return how many this process could not have run.

    The startup sibling of ``Store.recover_executions``, for the same reason: a row left `running` was
    claimed by a process that is gone, and the one thing the platform must not do at boot is *assume* its
    outcome. `succeeded` would be a durability claim nobody observed; `failed` would discard a backup that
    may well have completed. `unknown` is the honest word, and it is terminal — the operator reconciles it
    by reading the state directory or booking a fresh backup, which is an act with its own row rather than a
    guess made here.
    """
    moment = clock(now)
    with store.transaction() as connection:
        rows = connection.execute(f'SELECT id, kind, plan_sha256 FROM {PLATFORM_JOB_TABLE} WHERE state=?',
                                  ('running',)).fetchall()
        for row in rows:
            connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=?, finished_at=? WHERE id=?',
                               ('unknown', utc_text(moment), row['id']))
            store.audit(connection, moment, JOB_ACTOR, PLATFORM_JOB_OPERATION, row['id'],
                        {'kind': row['kind'], 'action': 'recovered', 'plan_sha256': row['plan_sha256']})
        return len(rows)


def _execute(store: Store, row: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    """Run one claimed job and return its outcome and receipt, without raising through the loop."""
    try:
        receipt = _run_backup(store, row) if row['kind'] == BACKUP else _run_verification(store, row)
        return 'succeeded', receipt
    except StateError as exc:
        # A sentence this module wrote is safe to store; a sentence from SQLite or the operating system is
        # not, because it names a file. The membership test below is the whole difference between the two, and
        # it is closed: an unrecognised `StateError` from a deeper layer is reported by class, exactly like any
        # other fault, so a new sentence cannot become a leak by accident.
        return _failed(row, str(exc) if str(exc) in SAFE_FAILURES else type(exc).__name__)
    except Exception as exc:
        # Class only, for the same reason: an answer that repeated the message would have handed the
        # deployment layout to whoever holds a human token, which is not the same thing as being allowed to
        # read the state directory.
        return _failed(row, type(exc).__name__)


def _failed(row: Mapping[str, Any], reason: str) -> tuple[str, dict[str, Any]]:
    """Report one faulted job, and put its traceback where somebody with the host can read it."""
    log.error('Administration job failed', extra={'job_id': row['id'], 'job_kind': row['kind'],
                                                  'error_reason': reason})
    log.debug('Administration job details', exc_info=True)
    return 'failed', {'error': reason}


def _settle(store: Store, job_id: str, outcome: str, receipt: Mapping[str, Any],
            moment: dt.datetime) -> bool:
    """Write one terminal state, its receipt and its audit row together; report whether the row moved."""
    payload = canonical(dict(receipt))
    if len(payload.encode()) > PLATFORM_JOB_RECEIPT_LIMIT:
        # Unreachable by construction (both receipts hold ids, digests and counts), and still checked: the
        # column bound is the schema's promise, and a transport that could not write its own answer would
        # leave a finished job looking `running` forever.
        payload = canonical({'receipt_too_large': True})
    with store.transaction() as connection:
        connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=?, finished_at=?, receipt=? WHERE id=?',
                           (outcome, utc_text(moment), payload, job_id))
        moved = connection.execute('SELECT changes()').fetchone()[0] == 1
        store.audit(connection, moment, JOB_ACTOR, PLATFORM_JOB_OPERATION, job_id,
                    {'action': outcome, 'receipt_sha256': digest(receipt)})
        return moved


def _run_backup(store: Store, row: Mapping[str, Any]) -> dict[str, Any]:
    """Copy the live database, then prove the copy by reading it back rather than by hoping.

    Three checks, each catching a different failure: ``Store.backup`` refuses an existing destination
    (`open('xb')`) and integrity-checks the copy; *this build opening* the copy proves it is a platform
    database this code understands and not merely a readable file; and the sha256 plus the byte count give
    the operator something to compare after the file leaves the host. A copy that is never read back is the
    failure mode this estate's operating notes are written around — a file that exists is not a file that
    restores.
    """
    stamp = dt.datetime.now(dt.timezone.utc).strftime(_STAMP)
    name = f'{store.path.name}.api-backup-{stamp}-{row["id"][:8]}.db'
    destination = store.path.with_name(name)
    store.backup(destination)
    read_back = Store(destination).status()
    return {'artifact': name, 'bytes': destination.stat().st_size, 'sha256': _sha256(destination),
            'integrity': 'ok', 'schema_version': read_back['schema_version'],
            'records': {key: value for key, value in read_back.items() if key != 'schema_version'}}


def _run_verification(store: Store, row: Mapping[str, Any]) -> dict[str, Any]:
    """Restore one recorded artifact into scratch, prove it opens and reads, and remove the scratch.

    This is the check that turns "a file was written" into "a file that restores", which is what an operator's
    backup question actually is. It is not the offline conformance script's job:
    ``scripts/conformance_recovery.py`` measures a *declared state manifest* and needs a scratch tree and
    host access; this answers one question about one artifact this service wrote.

    The copy is made page-for-page over SQLite's backup API on a **read-only** connection to the artifact,
    and ``Store.backup`` is deliberately not reused for it: a ``Store`` pointed at an empty or truncated
    artifact would *create* the schema inside it, which is exactly the damage a verification must be
    incapable of doing. The scratch file is the only thing this job writes, and it is removed — together with
    the pre-migration copy ``Store`` took of it, whose path the migrator hands back rather than this function
    guessing at.
    """
    source = _job_row(store, row['subject'])
    if source['kind'] != BACKUP or source['state'] != 'succeeded':
        raise StateError(NOT_VERIFIABLE)
    receipt = _receipt(source)
    for key in ('artifact', 'sha256', 'bytes'):
        if receipt.get(key) in (None, ''):
            raise StateError(ARTIFACT_UNREADABLE)
    artifact = store.path.with_name(str(receipt['artifact']))
    if not ARTIFACT_NAME.fullmatch(artifact.name):
        raise StateError(ARTIFACT_UNREADABLE)
    if not artifact.is_file():
        raise StateError(ARTIFACT_MISSING)
    size, sha256 = _fingerprint(artifact)
    if sha256 != receipt['sha256'] or size != receipt['bytes']:
        raise StateError(DIGEST_MISMATCH)
    if _unrecovered_wal(artifact):
        raise StateError(WAL_SIDECAR)
    stamp = dt.datetime.now(dt.timezone.utc).strftime(_STAMP)
    scratch = store.path.with_name(f'{store.path.name}.api-verify-{stamp}-{row["id"][:8]}.db')
    _copy_read_only(artifact, scratch)
    opened: dict[str, Any] = {}
    try:
        # `migrate=True` on the *scratch* copy is what a real restore does: an artifact taken before a schema
        # change is brought forward and must still open and read. It never reaches the artifact, which this
        # function only ever opens read-only.
        moved = Store(scratch, migrate=True)
        restored = moved.status()
        opened = {'migrated_from': moved.migrated_from, 'pre_migration_copy': moved.migration_backup}
    finally:
        _remove(scratch)
        if opened.get('pre_migration_copy') is not None:
            _remove(Path(opened['pre_migration_copy']))
    return {'backup_job': source['id'], 'artifact': artifact.name, 'bytes': size, 'sha256': sha256,
            'digest_matches': True, 'integrity': 'ok', 'migrated_from': opened['migrated_from'],
            'restored_schema_version': restored['schema_version'],
            'restored_records': {key: value for key, value in restored.items() if key != 'schema_version'},
            'scratch_removed': not scratch.exists()}


def _remove(path: Path) -> None:
    """Delete one file this job created, and the WAL sidecars a connection may have left beside it.

    Exact names only: a `scratch*` pattern in a deployment's state directory is a way to delete somebody's
    pre-migration copy, which is the one file the recovery story cannot do without.
    """
    for stale in (path, path.with_name(path.name + '-wal'), path.with_name(path.name + '-shm')):
        with contextlib.suppress(FileNotFoundError):
            stale.unlink()


def _copy_read_only(source: Path, destination: Path) -> None:
    """Copy `source` into a new `destination` without any possibility of writing `source`.

    `open('xb')` and the integrity check follow ``Store.backup``'s discipline. The write refusal is
    ``PRAGMA query_only`` rather than SQLite's `mode=ro` URI, and the difference matters: a `mode=ro`
    connection over a WAL database can recover the WAL index but cannot remove the `-wal`/`-shm` sidecars it
    needed to do so, which would leave an operator's artifact wearing files it did not have before the check
    that was only supposed to look at it. `query_only` forbids the same writes and closes cleanly.
    """
    with destination.open('xb'):
        pass
    with contextlib.closing(sqlite3.connect(source)) as origin, \
            contextlib.closing(sqlite3.connect(destination)) as target:
        origin.execute('PRAGMA query_only=ON')
        origin.backup(target)
        if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise StateError(INTEGRITY_FAILURE)
        if origin.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise StateError(INTEGRITY_FAILURE)


def _unrecovered_wal(path: Path) -> bool:
    """Whether one artifact has a `-wal` sidecar carrying bytes the main file does not.

    The same worry ``Store._refuse_orphaned_wal`` raises for the live file, applied to an artifact: with a
    non-empty sidecar present the *database* is two files, and a job that hashed one of them and called the
    result a verified backup would be reporting on half a database. Refusing is also the safer answer to the
    question nobody asked — whether the sidecar should be trusted — because the operator can recover it or
    retake the copy, and either is a decision rather than a guess.
    """
    sidecar = path.with_name(path.name + '-wal')
    return sidecar.is_file() and sidecar.stat().st_size > 0


# ------------------------------------------------------------------------------------ revocation ledger


def revoke(store: Store, identity: Any, reason: Any, actor: Actor, *,
           mounted: Sequence[str] = (), now: dt.datetime | None = None) -> dict[str, Any]:
    """Refuse one identity's bearer from now on, durably, and audit the decision.

    The row is a deny-list entry, not an enrollment: the mounted role file stays the only statement of who
    may call. That is why `identity` must already appear in `mounted` (:data:`IDENTITY_UNKNOWN`) and why
    nothing here can mint, widen or rename a grant. An identity with two mounted rows — two bearers, one
    name — is revoked as one unit, because the mount names no finer reference; a deployment needing
    per-token control edits the file, which is the offline act it already is.

    One transaction holds the row and its audit row, so a revocation and the record of it cannot disagree.
    The transport consults :func:`revoked` on every authenticated request, so this bites on the next call
    rather than on the next restart.

    Raises:
        api_contract.ContractError: 400 `invalid_request` for an identity outside `state.label`'s alphabet or
            a reason that is missing, multiline or over-long; 404 `not_found` for an identity this
            installation never mounted; 409 `conflict` for one already revoked. A `summary` credential never
            reaches here: the transport refuses its writes first.
    """
    ident = _identity(identity)
    text = _reason(reason)
    if ident not in set(mounted):
        raise api_contract.ContractError(404, 'not_found', IDENTITY_UNKNOWN)
    moment = clock(now)
    with store.transaction() as connection:
        if connection.execute(f'SELECT 1 FROM {CREDENTIAL_REVOCATION_TABLE} WHERE identity=?',
                              (ident,)).fetchone() is not None:
            raise api_contract.ContractError(409, 'conflict', ALREADY_REVOKED)
        connection.execute(
            f'INSERT INTO {CREDENTIAL_REVOCATION_TABLE}(identity,revoked_by,revoked_at,reason) VALUES (?,?,?,?)',
            (ident, actor.identity, utc_text(moment), text))
        store.audit(connection, moment, actor.identity, CREDENTIAL_REVOCATION_OPERATION, ident,
                    {'reason': text})
        return {'identity': ident, 'state': CREDENTIAL_REVOKED_STATE, 'revoked_by': actor.identity,
                'revoked_at': utc_text(moment), 'reason': text}


def revocations(store: Store) -> dict[str, Any]:
    """Return every revocation this database holds, oldest first, beside the bound that stopped the walk.

    Reported with `bound_exceeded` for the reason `maintenance_api` gives for its reads: an empty list and
    "this build stopped counting" are different claims about who can still call, and the second must never be
    printed as the first.
    """
    with store.transaction() as connection:
        rows = connection.execute(
            f'SELECT identity, revoked_by, revoked_at, reason FROM {CREDENTIAL_REVOCATION_TABLE}'
            ' ORDER BY revoked_at, identity LIMIT ?', (REVOCATION_LIST_LIMIT + 1,)).fetchall()
    over = len(rows) > REVOCATION_LIST_LIMIT
    return {'rows': [dict(row) for row in rows[:REVOCATION_LIST_LIMIT]],
            'count': min(len(rows), REVOCATION_LIST_LIMIT), 'limit': REVOCATION_LIST_LIMIT,
            'bound_exceeded': over}


def revoked(path: Path | str, identity: str) -> bool:
    """Whether one identity is refused, answered from a read-only connection to `path`.

    The one store read that runs ahead of routing, on every authenticated request — and read-only on
    purpose. ``Store.transaction`` issues ``BEGIN IMMEDIATE``, which takes the *write* lock; a transport
    claiming that per request would serialise its own readers behind a bookkeeping lookup. So this mirrors
    ``platform/audit_reader.py``'s connection instead: a deferred read transaction, closed before the answer,
    holding no WAL mark between requests.

    Raises whatever SQLite raises rather than answering `False`. Falling open would make a locked or damaged
    database a way to use a revoked bearer, and the row exists precisely so that a token outlives its
    bearer's access. ``api.py`` renders the raise as its usual 500: no action is taken, nothing is pretended.
    """
    uri = Path(path).resolve().as_uri() + '?mode=ro'
    with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=10)) as connection:
        return connection.execute(f'SELECT 1 FROM {CREDENTIAL_REVOCATION_TABLE} WHERE identity=?',
                                  (identity,)).fetchone() is not None


# --------------------------------------------------------------------------------------------- internals


def state_summary(store: Store) -> dict[str, Any]:
    """Return the administration view of one operational database: its version, its work, its refusals.

    Three tallies and one plan, on purpose. `docs/CONTRACTS.md` §5's rule about an answer is that it states
    its own bound and its own scope rather than implying them, so `jobs` names every state including the ones
    at zero (`unknown` at zero is a fact an operator is entitled to have said out loud), `revocations` carries
    the bound that stopped its walk, and `plan` is the digest a write will demand — the number an operator
    reads *is* the number they approve, from the same derivation, in the same read.

    `GET /v1/status` counts incidents, actions and deliveries. This counts the operator surface: what schema
    the file is at, what work has been booked against it, and which bearers this installation has refused.
    """
    with store.transaction() as connection:
        tallies = {row['state']: row['count'] for row in connection.execute(
            f'SELECT state, count(*) AS count FROM {PLATFORM_JOB_TABLE} GROUP BY state')}
        latest = connection.execute(
            f'SELECT id FROM {PLATFORM_JOB_TABLE} WHERE kind=? ORDER BY rowid DESC LIMIT 1', (BACKUP,)).fetchone()
        revoked = connection.execute(f'SELECT count(*) AS count FROM {CREDENTIAL_REVOCATION_TABLE}').fetchone()
    ledger = revocations(store)
    return {'schema_version': store.status()['schema_version'], 'supported_kinds': list(KINDS),
            'plan': backup_plan(store),
            'jobs': {state: tallies.get(state, 0) for state in STATES},
            'last_backup': None if latest is None else job(store, latest['id']),
            'revocations': {'count': revoked['count'], 'listed': ledger['count'],
                            'limit': ledger['limit'], 'bound_exceeded': ledger['bound_exceeded']}}


def _admit(store: Store, *, kind: str, plan_sha256: str, subject: str, actor: Actor,
           now: dt.datetime | None) -> dict[str, Any]:
    """Insert one booked job and its audit row, and return the document its caller is answered with."""
    if kind not in KINDS:
        raise api_contract.ContractError(400, 'invalid_request', PLAN_KIND_UNKNOWN)
    moment = clock(now)
    job_id = str(uuid.uuid4())
    with store.transaction() as connection:
        connection.execute(
            f'INSERT INTO {PLATFORM_JOB_TABLE}(id,kind,state,plan_sha256,subject,approved_by,admitted_at)'
            " VALUES (?,?,'accepted',?,?,?,?)",
            (job_id, kind, plan_sha256, subject, actor.identity, utc_text(moment)))
        store.audit(connection, moment, actor.identity, PLATFORM_JOB_OPERATION, job_id,
                    {'kind': kind, 'action': 'approved', 'plan_sha256': plan_sha256, 'subject': subject})
        return _document(connection, _known_row(connection, job_id))


def _document(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Return one job as the answer `docs/api/administration.md` describes."""
    document = {'job_id': row['id'], 'kind': row['kind'], 'state': row['state'],
                'plan_sha256': row['plan_sha256'], 'subject': row['subject'],
                'approved_by': row['approved_by'], 'admitted_at': row['admitted_at'],
                'started_at': row['started_at'], 'finished_at': row['finished_at'],
                'terminal': row['state'] in TERMINAL_STATES}
    stored = _receipt(row)
    if stored:
        document['receipt'] = stored
    if row['kind'] == BACKUP:
        document['verification'] = _verification_block(connection, row)
    return document


def _verification_block(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    """Return what has been done to prove this backup's artifact, or that nothing has."""
    latest = connection.execute(
        f'SELECT id, state FROM {PLATFORM_JOB_TABLE} WHERE kind=? AND subject=?'
        ' ORDER BY rowid DESC LIMIT 1', (VERIFICATION, row['id'])).fetchone()
    block: dict[str, Any] = {'state': 'unverified' if latest is None else latest['state'],
                             'last_job': None if latest is None else latest['id'], 'plan': None}
    if row['state'] == 'succeeded':
        try:
            block['plan'] = _verification_binding(row)
        except api_contract.ContractError:
            block['plan'] = None            # no artifact to promise: the receipt will say what happened
    return block


def _receipt(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return one stored receipt as a document, or the empty dict when none was written."""
    stored = row['receipt']
    if not stored:
        return {}
    try:
        parsed = json.loads(stored)
    except (TypeError, ValueError):
        return {'receipt_unreadable': True}
    return parsed if isinstance(parsed, dict) else {'receipt_unreadable': True}


def _job_row(store: Store, job_id: Any) -> sqlite3.Row:
    """Return one job row, refusing a non-canonical id and an unknown one with the same 404.

    A malformed id and an absent id answer alike, for the reason `dispositions` gives for its own reads: the
    route is not an oracle for whether a uuid is well-formed, and an operator who pasted a truncated id is
    no better served by that distinction than somebody probing the id space.
    """
    if not isinstance(job_id, str) or not _is_uuid(job_id):
        raise api_contract.ContractError(404, 'not_found', NO_SUCH_JOB)
    with store.transaction() as connection:
        return _known_row(connection, job_id)


def _known_row(connection: sqlite3.Connection, job_id: str) -> sqlite3.Row:
    row = connection.execute(f'SELECT * FROM {PLATFORM_JOB_TABLE} WHERE id=?', (job_id,)).fetchone()
    if row is None:
        raise api_contract.ContractError(404, 'not_found', NO_SUCH_JOB)
    return row


def _is_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def _approval(value: Any) -> str:
    """Return an approved plan digest, refusing anything that is not one.

    The field is required rather than optional-with-a-default: a job that ran whatever the current plan
    happened to be is a job nobody approved, and §5's rule about a human decision is that it names the thing
    it agreed to.
    """
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise api_contract.ContractError(400, 'invalid_request', APPROVAL_REQUIRED)
    return value


def _identity(value: Any) -> str:
    if not isinstance(value, str):
        raise api_contract.ContractError(400, 'invalid_request', IDENTITY_UNKNOWN)
    try:
        return label(value)
    except StateError as exc:
        raise api_contract.ContractError(400, 'invalid_request', str(exc)) from exc


def _reason(value: Any) -> str:
    """Return a revocation reason: required, one printable line, bounded by the column's own width."""
    if not isinstance(value, str) or not value.strip():
        raise api_contract.ContractError(400, 'invalid_request',
                                         'A revocation must carry a reason a later reader can act on')
    if len(value) > CREDENTIAL_REVOCATION_REASON_LIMIT or any(c in value for c in '\r\n\x00'):
        raise api_contract.ContractError(
            400, 'invalid_request', f'A revocation reason must be one printable line of at most '
                                    f'{CREDENTIAL_REVOCATION_REASON_LIMIT} characters')
    return value.strip()


def _position(value: Any) -> int:
    """Return the rowid one page continues from, refusing anything that is not one."""
    if value is None:
        return 2**63 - 1                                  # the newest end of the ledger
    if not isinstance(value, str) or not value.isdigit():
        raise api_contract.ContractError(400, 'invalid_pagination', api_contract.CURSOR_REJECTED)
    return int(value)


def _fingerprint(path: Path) -> tuple[int, str]:
    """Return one file's byte count and sha256, read in 1 MiB blocks."""
    size = 0
    context = hashlib.sha256()
    with path.open('rb') as handle:
        while block := handle.read(1024 * 1024):
            size += len(block)
            context.update(block)
    return size, context.hexdigest()


def _sha256(path: Path) -> str:
    return _fingerprint(path)[1]


__all__ = ['APPROVAL_FIELD', 'ASYNC_REASON', 'ARTIFACT_RULE', 'BACKUP', 'BACKUP_BODY_KEYS', 'JOB_ACTOR',
           'KINDS', 'REVOCATION_LIST_LIMIT', 'STATES', 'TERMINAL_STATES', 'VERIFICATION',
           'VERIFICATION_BODY_KEYS', 'backup_plan', 'cancel', 'drain', 'job', 'page', 'recover',
           'request_backup', 'request_verification', 'revocations', 'revoke', 'revoked', 'state_summary',
           'verification_plan']

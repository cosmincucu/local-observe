"""Explicit copied-state rehearsal, separate from the production release transition.

The caller stops its isolated writers and owns the copy before calling ``prepare``.
Only that copy is mounted in the candidate image. Original/rollback files are never
mounted. Docker is injected; importing this module performs no I/O. Snapshots hold
private rows in memory; public receipts contain hashes and pins only.
"""
from contextlib import closing
from copy import deepcopy
import datetime as dt
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3

from local_observe.deployment.content import Conflict
from local_observe.deployment.release import inspect_sqlite, transition
from local_observe.inventory.validation import digest


RUNTIME_CONTRACT = '''import json
from local_observe.platform import state
print(json.dumps({'version':state.VERSION,'application_id':state.APPLICATION_ID,
 'actor':state.MIGRATE_ACTOR,
 'scripts':{str(k):state.digest(v) for k,v in state.MIGRATIONS.items()}}))
'''


def require(value, message):
    if not value:
        raise Conflict(message)


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def snapshot(path, columns=None):
    """Read every durable table and every column in one read-only transaction.

An original projection can be supplied after migration; missing tables/columns
    refuse. SQLite's sequence bookkeeping is checked separately from application
    rows. No per-table allowlist can silently omit a new table.
"""
    inspect_sqlite(path)
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('BEGIN')
        require(not db.execute('PRAGMA foreign_key_check').fetchall(), 'State has broken foreign keys')
        actual = {name: [r[1] for r in db.execute('PRAGMA table_info(' + _quote(name) + ')')]
                  for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'"
                                           " AND name NOT LIKE 'sqlite_%' ORDER BY name")}
        chosen = actual if columns is None else columns
        sequences = {}
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").fetchone():
            for table, sequence in db.execute('SELECT name,seq FROM sqlite_sequence'):
                require(table in actual and type(sequence) is int and sequence >= 0,
                        'Invalid SQLite sequence bookkeeping')
                primary = [row[1] for row in db.execute('PRAGMA table_info(' + _quote(table) + ')')
                           if row[5]]
                require(len(primary) == 1, 'Unknown SQLite sequence primary key')
                maximum = db.execute('SELECT max(' + _quote(primary[0]) + ') FROM ' + _quote(table)).fetchone()[0]
                require(maximum is None or sequence >= maximum, 'SQLite sequence trails durable rows')
                sequences[table] = sequence
        result = {'columns': chosen, 'rows': {}, 'sequences': sequences}
        for table, names in chosen.items():
            require(table in actual and set(names) <= set(actual[table]), 'Historical table or column missing')
            selection = ','.join(_quote(n) for n in names)
            result['rows'][table] = db.execute('SELECT ' + selection + ' FROM ' + _quote(table)
                                              + ' ORDER BY ' + selection).fetchall()
        return result


def fingerprint(value):
    """Hash private row content, preserving SQLite byte values without printing them."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    default=lambda b: {'sqlite_blob_hex': b.hex()}).encode()).hexdigest()


def _command(image, *args, state_dir=None):
    require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image),
            'Rehearsal requires a resolved image ID')
    command = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=ALL',
               '--security-opt=no-new-privileges:true', '--pids-limit=128', '--memory=384m',
               '--cpus=0.5', '--tmpfs=/tmp:rw,size=32m,mode=1777']
    if state_dir is not None:
        command += ['--mount', 'type=bind,source=' + str(state_dir) + ',target=/data']
    return command + ['--entrypoint', 'python', image, '-B', *args]


def runtime_contract(run, image):
    """Read version and audit script hashes from the actual candidate image."""
    value = json.loads(run(*_command(image, '-c', RUNTIME_CONTRACT), timeout=60))
    require(isinstance(value, dict) and set(value) == {'version', 'application_id', 'actor', 'scripts'},
            'Candidate migration contract is malformed')
    version = value['version']
    require(type(version) is int and 1 <= version <= 1000 and type(value['application_id']) is int
            and isinstance(value['actor'], str) and bool(value['actor'])
            and isinstance(value['scripts'], dict)
            and set(value['scripts']) == {str(k) for k in range(1, version + 1)}
            and all(isinstance(v, str) and re.fullmatch(r'[0-9a-f]{64}', v)
                    for v in value['scripts'].values()), 'Candidate migration contract is malformed')
    return value


def _preserved(path, before, source_version, contract):
    after = snapshot(path, before['columns'])
    for table, old_rows in before['rows'].items():
        new_rows = after['rows'][table]
        if table != 'audit':
            require(new_rows == old_rows, 'Historical durable rows changed')
            continue
        require(before['columns']['audit'] == ['sequence', 'at', 'actor', 'operation', 'subject', 'detail'],
                'Unknown historical audit columns')
        require(new_rows[:len(old_rows)] == old_rows, 'Historical audit prefix changed')
        extra = new_rows[len(old_rows):]
        steps = range(source_version + 1, contract['version'] + 1)
        require(len(extra) == len(steps), 'Unexpected migration audit row count')
        last = before['sequences'].get('audit', old_rows[-1][0] if old_rows else 0)
        for row, target in zip(extra, steps):
            sequence, at, actor, operation, subject, detail = row
            require(sequence == last + 1 and actor == contract['actor'] and operation == 'schema.migrated'
                    and subject == str(target), 'Unexpected migration audit row')
            require(dt.datetime.fromisoformat(at.replace('Z', '+00:00')).utcoffset() == dt.timedelta(0),
                    'Invalid migration audit timestamp')
            require(json.loads(detail) == {'from': source_version, 'to': target,
                                          'script_sha256': contract['scripts'][str(target)]},
                    'Migration audit does not match candidate scripts')
            last = sequence
    for table, sequence in before['sequences'].items():
        expected = sequence + (contract['version'] - source_version if table == 'audit' else 0)
        require(after['sequences'].get(table) == expected, 'Historical SQLite sequence changed')


def prepare(run, image, state_dir, original_pin):
    """Migrate only the stopped isolated copy, verify backup/pin/all historical rows.

Raises on any failure, before the driver can start a candidate or advance a receipt.
The CLI exclusively creates its own timestamped backup; a naming collision refuses
and retains both files. A same-schema run invokes no migration and creates no backup.
"""
    directory = Path(state_dir)
    path = directory / 'platform.db'
    require(directory.is_dir() and not directory.is_symlink() and not path.is_symlink(),
            'Expected isolated regular state directory')
    wal = path.with_name(path.name + '-wal')
    require(not wal.exists() or wal.stat().st_size == 0,
            'Stop isolated writers before migration')
    require(inspect_sqlite(path) == original_pin, 'Original copy does not match its state pin')
    before = snapshot(path)
    contract = runtime_contract(run, image)
    source = original_pin['user_version']
    require(contract['application_id'] == original_pin['application_id']
            and source <= contract['version'], 'Candidate cannot migrate this original state')
    backup = None
    if source < contract['version']:
        existing = set(directory.iterdir())
        result = json.loads(run(*_command(image, '-m', 'local_observe.platform.cli',
                                         '--database', '/data/platform.db', 'migrate',
                                         state_dir=directory), timeout=120))
        require(isinstance(result, dict) and set(result) == {'status', 'from', 'to', 'backup'}
                and result['status'] == 'migrated' and result['from'] == source
                and result['to'] == contract['version'] and isinstance(result['backup'], str),
                'Candidate migration receipt disagrees with its runtime contract')
        reported = PurePosixPath(result['backup'])
        require(reported.parent == PurePosixPath('/data')
                and re.fullmatch(r'platform\.db\.pre-v' + str(source) + r'-[0-9]{8}T[0-9]{6}Z\.db', reported.name),
                'Migration backup is outside the isolated state directory')
        saved = directory / reported.name
        require(saved not in existing and not saved.is_symlink() and saved.is_file(),
                'Migration did not create a new regular rollback copy')
        require(inspect_sqlite(saved) == original_pin and snapshot(saved) == before,
                'Migration rollback copy differs from original state')
        backup = {'name': saved.name, 'bytes': saved.stat().st_size,
                  'sha256': hashlib.sha256(saved.read_bytes()).hexdigest(),
                  'state': original_pin}
    pin = inspect_sqlite(path)
    require(pin['application_id'] == contract['application_id']
            and pin['user_version'] == contract['version'], 'Candidate state version does not match its image')
    if source == contract['version']:
        require(pin == original_pin, 'Same-schema candidate changed the state pin')
    full = snapshot(path)
    require(contract['version'] < 4 or {'verification_bindings', 'verification_records'} <= set(full['columns']),
            'Candidate lacks verification storage')
    _preserved(path, before, source, contract)
    return {'original_state': original_pin, 'candidate_state': pin, 'migration_backup': backup,
            'durable_sha256': fingerprint(full), 'runtime_contract': contract,
            'status': 'verified-copy', 'deploy_authorized': False}


def rehearsal_transition(previous, candidate, original_pin, candidate_pin):
    """Check other release contracts without granting a production schema transition."""
    require(previous['state']['platform'] == original_pin and candidate['state']['platform'] == candidate_pin,
            'Rehearsal release state pins disagree with verified copies')
    if original_pin == candidate_pin:
        return transition(previous, candidate, original_pin)
    aligned = deepcopy(candidate)
    aligned['state']['platform'] = original_pin
    transition(previous, aligned, original_pin)
    return {'status': 'review-required', 'deploy_authorized': False,
            'previous_sha256': digest(previous), 'candidate_sha256': digest(candidate),
            'original_state': original_pin, 'candidate_state': candidate_pin,
            'scope': 'explicit isolated copied-state migration only'}


def restore_copy(checkpoint, output, receipt):
    """Restore into a new directory; retain the failed candidate and every backup."""
    checkpoint, output = Path(checkpoint), Path(output)
    require(not checkpoint.is_symlink() and checkpoint.is_file(), 'Expected regular rollback checkpoint')
    require(hashlib.sha256(checkpoint.read_bytes()).hexdigest() == receipt['sha256']
            and inspect_sqlite(checkpoint) == receipt['state'], 'Rollback checkpoint changed')
    output.mkdir(mode=0o777)
    output.chmod(0o777)
    target = output / 'platform.db'
    with checkpoint.open('rb') as source, target.open('xb') as destination:
        shutil.copyfileobj(source, destination)
    target.chmod(0o666)
    require(hashlib.sha256(target.read_bytes()).hexdigest() == receipt['sha256']
            and inspect_sqlite(target) == receipt['state'], 'Restored state differs from checkpoint')
    return target

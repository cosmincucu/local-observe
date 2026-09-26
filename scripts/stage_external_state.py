"""Preflight or copy discovery/overview state; no service restart, replay or witness access."""
from contextlib import contextmanager
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import time

@contextmanager
def discovery_lock(path):
    """Use the worker's existing lock; never create a lock or wait for a writer."""
    import fcntl
    with path.open('rb') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def capture_external_state(root, work, run, *, capture=False, lock=discovery_lock,
                           monotonic=time.monotonic):
    """Default is read-only planning; explicit capture may checkpoint discovery WAL.

    The command and lock seams allow fixture execution without host services.
    Production callers must retain the nonblocking OS lock and rootless guard.
    """
    from local_observe.deployment.state_copy import copy_state
    from local_observe.deployment.runtime_bundle import artifact_hash
    root, work = Path(root).absolute(), Path(work).absolute()
    if (root.resolve(strict=True) != root or work.resolve(strict=True) != work
            or root.parent != work or not root.name.startswith('external-state-')):
        raise ValueError('Expected a fresh external-state task')
    if type(capture) is not bool:
        raise ValueError('Capture must be explicit boolean')
    for name in ('index-backup', 'backup', 'restore', 'report.json'):
        if (root/name).exists() or (root/name).is_symlink():
            raise ValueError('Capture output already exists; inspect previous evidence')
    before = sorted(run('docker', 'ps', '-q', '--no-trunc').split())
    def document(path):
        path = Path(path)
        if path.resolve(strict=True) != path or not path.is_relative_to(work):
            raise ValueError('Ledger/config path outside approved work tree')
        return json.loads(path.read_text())
    discovery = document(work/'active-discovery.json')
    home = document(work/'active-homepage.json')
    dpath = Path(discovery['deployment'])/'discovery.json'
    def configured_path(service, key):
        # Extract only the allowlisted path; never retain or report environment values.
        try:
            rows = shlex.split(run('systemctl', '--user', 'show', service,
                                   '--value', '-p', 'Environment'))
            values = [row.split('=', 1)[1] for row in rows if row.startswith(key+'=')]
        except ValueError:
            raise ValueError('Malformed service configuration environment') from None
        if len(values) != 1 or not values[0]:
            raise ValueError('Missing or duplicate service configuration path')
        return Path(values[0])
    def verify_discovery_binding():
        actual = configured_path('local-observe-discovery.service', 'LO_DISCOVERY_CONFIG')
        if actual != dpath:
            raise ValueError('Discovery service configuration differs from ledger')
    verify_discovery_binding()
    dconfig = document(dpath)
    discovery_state = Path(dconfig['state'])
    opath = configured_path('local-observe-overview.service', 'LO_OVERVIEW_CONFIG')
    oconfig = document(opath)
    # Avoid contending with the next scheduled discovery run while holding its lock.
    timer_path = shlex.split(run('busctl', '--user', 'call', 'org.freedesktop.systemd1',
        '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager', 'GetUnit',
        's', 'local-observe-discovery.timer'))[1]
    next_value = run('busctl', '--user', 'get-property', 'org.freedesktop.systemd1', timer_path,
                     'org.freedesktop.systemd1.Timer', 'NextElapseUSecMonotonic').split()
    if len(next_value) != 2 or next_value[0] != 't':
        raise ValueError('Unexpected timer property type')
    next_run = int(next_value[1])/1000000
    if next_run-monotonic() < 90:
        raise ValueError('Discovery run is imminent; defer snapshot, do not change timer')
    units = {}
    for name in ('discovery', 'overview'):
        service = 'local-observe-'+name+'.service'
        units[name] = {field: run('systemctl', '--user', 'show', service, '--value', '-p', field)
                       for field in ('ActiveState', 'SubState', 'FragmentPath', 'WorkingDirectory')}
    if units['discovery']['ActiveState'] != 'inactive':
        raise ValueError('Discovery writer is active; defer capture')
    lock_path = discovery_state/'worker.lock.owner.lock'
    if (lock_path.resolve(strict=True) != lock_path or not lock_path.is_relative_to(work)
            or not lock_path.is_file()):
        raise ValueError('Unexpected ownership lock')
    with lock(lock_path):
        verify_discovery_binding()
        if document(dpath) != dconfig:
            raise ValueError('Discovery configuration changed before capture')
        sources = {'discovery-config': (dpath, 'json'),
            'discovery-cursor': (discovery_state/'cursor.json', 'json'),
            'discovery-drift': (discovery_state/'drift.json', 'json'),
            'discovery-index': (Path(dconfig['index']), 'sqlite'),
            'overview-config': (opath, 'json'), 'overview-state': (Path(oconfig['output']), 'json')}
        for path in sorted(discovery_state.glob('observations-*.db')):
            sources[path.stem] = (path, 'sqlite')
        for index, path in enumerate(sorted((discovery_state/'proposals').glob('*.json'))):
            if index >= 1000:
                raise ValueError('Proposal count exceeds bounded capture')
            sources['proposal-'+str(index)] = (path, 'json')
        # Validate the same declared source set even for preflight, without opening SQLite.
        for path, _ in sources.values():
            if (path.resolve(strict=True) != path or not path.is_relative_to(work)
                    or not path.is_file() or root.is_relative_to(path.parent)):
                raise ValueError('State source outside capture scope')
        source_bytes = sum(path.stat().st_size for path, _ in sources.values())
        if source_bytes > 64*1024**2:
            raise ValueError('State inputs exceed copy budget')
        pins = {name: artifact_hash(Path(directory)/'local_observe', work)
                for name, directory in [('discovery', discovery['deployment']),
                                        ('overview', home['overview_code'])]}
        index_wal = Path(str(sources['discovery-index'][0])+'-wal')
        if index_wal.is_symlink() or (index_wal.exists() and index_wal.stat().st_size):
            raise ValueError('Inventory index has live WAL; its writer is not owned by discovery')
        if not capture:
            return {'status': 'preflight', 'files': len(sources), 'source_bytes': source_bytes,
                    'declared_source_sha256': pins, 'application_recovery_proven': False}
        # Discovery only READS the inventory index; its lock does not own that writer.
        # Snapshot it separately with checkpointing forbidden, then use that owned copy.
        copy_state({'discovery-index': sources['discovery-index']}, work,
                   root/'index-backup', allow_checkpoint=False)
        sources['discovery-index'] = (root/'index-backup'/'discovery-index.db', 'sqlite')
        # Discovery's nonblocking owner lock excludes its real writer across WAL checkpoint
        # and copy. Overview is a separate atomically replaced derived document, not a
        # consistent snapshot of the discovery/API inputs that produced it.
        report = copy_state(sources, work, root/'backup', allow_checkpoint=True)
        report['writer_exclusion'] = 'discovery lock held; overview is a separately read atomic derived document'
    # Re-open every backup into a separate restore tree; never point workers at it.
    restored = copy_state({name: (root/'backup'/(name+('.db' if entry['kind'] == 'sqlite' else '.json')),
                                   entry['kind']) for name, entry in report['files'].items()},
                           work, root/'restore')
    for name, entry in report['files'].items():
        other = restored['files'][name]
        if entry['logical'] != other['logical'] or (entry['kind'] == 'json' and entry['sha256'] != other['sha256']):
            raise ValueError('Independent restore readback differs')
    report.update(status='partial', restored_readback=True, unit_observations=units,
                  declared_source_sha256=pins, actual_loaded_code_proven=False,
                  witness='not-accessed; separate scoped host access required',
                  running_containers_unchanged=before == sorted(run('docker', 'ps', '-q', '--no-trunc').split()))
    path = root/'report.json'
    with path.open('x') as stream:
        json.dump(report, stream, indent=2)
    path.chmod(0o600)
    if json.loads(path.read_text()) != report:
        raise ValueError('Evidence readback failed')
    if not report['running_containers_unchanged']:
        raise RuntimeError('Running container identities changed during capture')
    return {'status': report['status'], 'files': len(report['files']),
        'backup_bytes': report['total_bytes'], 'restored_readback': True,
        'report_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
        'application_recovery_proven': False, 'running_containers_unchanged': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True, help='approved rootless Docker data boundary')
    parser.add_argument('--uid', type=int, required=True, help='approved non-root account UID')
    parser.add_argument('--work', type=Path, required=True, help='directory containing the active ledgers')
    parser.add_argument('--output', type=Path, required=True, help='existing empty external-state-* directory under work')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--preflight', action='store_true', help='inspect only (the default)')
    mode.add_argument('--capture', action='store_true', help='explicitly create backup and restore copies')
    args = parser.parse_args()
    if args.uid <= 0:
        parser.error('--uid must identify a non-root account')
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from scripts._lib.guards import rootless_docker_guard
    from scripts._lib.run import run
    rootless_docker_guard(args.base, args.uid, user_name=None, adopt_environment=False)
    print(json.dumps(capture_external_state(args.output, args.work, run, capture=args.capture)))



if __name__ == '__main__':
    main()

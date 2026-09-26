"""Cold backup and separate-project restore of the guarded synthetic NAS demo."""
import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from conformance_recovery import Demo, add_scope_arguments, command

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.report import write_json

VOLUMES = {'clickhouse-data', 'signoz-sqlite', 'zookeeper-data', 'ch-user-scripts',
           'front-door-queue', 'agent-state'}


def sha(path):
    """Return the SHA-256 of a file, read in 1 MiB blocks so a volume archive never loads into RAM."""
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def helper(image, volume, directory, filename, restore=False):
    if not volume.startswith('local-observe-demo_') and not volume.startswith('local-observe-demo-restore-'):
        raise ValueError('Unscoped volume')
    operation = ('test -z "$(ls -A /volume)"; tar --numeric-owner -xpf /backup/' + filename + ' -C /volume'
                 if restore else 'tar --numeric-owner -cpf /backup/' + filename + ' -C /volume .')
    command(['docker', 'run', '--rm', '--network', 'none', '--memory', '256m', '--cpus', '1',
             '--pids-limit', '128', '--entrypoint', '/bin/sh', '--user', '0',
             '--mount', f'type=volume,source={volume},target=/volume' + ('' if restore else ',readonly'),
             '--mount', f'type=bind,source={directory},target=/backup' + (',readonly' if restore else ''),
             image, '-ec', operation], timeout=600)


def stopped(demo):
    for cid in demo.compose('ps', '-aq').split():
        if command(['docker', 'inspect', '--format', '{{.State.Running}}', cid]).strip() != 'false':
            raise ValueError('Refusing backup of a running source container')


def restore_model(model, directory, project):
    result = copy.deepcopy(model)
    result['name'] = project
    for name, network in result.get('networks', {}).items():
        if network.get('external'):
            raise ValueError('External restore network')
        network['name'] = project + '_' + name
    for name, volume in result['volumes'].items():
        if name not in VOLUMES or volume.get('external'):
            raise ValueError('Unexpected volume')
        volume['name'] = project + '_' + name
    port_map = {8080: 28081, 4317: 34317, 4318: 34318, 13133: 33133}
    configs = directory / 'configs'
    configs.mkdir()
    for name, config in result.get('configs', {}).items():
        if 'file' in config:
            target = configs / name
            shutil.copy2(config['file'], target)
            config['file'] = str(target)
    for name, service in result['services'].items():
        if 'container_name' in service:
            raise ValueError('Fixed container name')
        for port in service.get('ports', []):
            port['published'] = str(port_map[int(port['target'])])
        for index, mount in enumerate(service.get('volumes', [])):
            if mount['type'] != 'bind':
                continue
            source = Path(mount['source'])
            if name == 'agent-linux' and mount['target'] == '/input':
                mount['source'] = str(directory / 'logs')
            elif source == Path('/') and mount.get('read_only') and name == 'agent-linux':
                continue
            elif source.is_file() and mount.get('read_only'):
                target = configs / f'{name}-{index}-{source.name}'
                shutil.copy2(source, target)
                mount['source'] = str(target)
            else:
                raise ValueError('Unexpected writable or directory bind')
    return result


def backup_restore(demo):
    """Archive every demo volume cold, then prove the archives restore into a separate project."""
    queries, _posts = demo.inject()
    demo.wait_counts(queries)
    demo.report['retained_queries'] = queries
    project = 'local-observe-demo-restore-' + demo.run[:12]
    directory = demo.directory
    image = demo.model['services']['clickhouse']['image']
    restore_prefix = ['docker', 'compose', '--project-name', project, '-f', str(directory / 'restore.json')]
    restore_started = False
    start = time.monotonic()
    try:
        demo.compose('stop', '-t', '30', 'agent-linux', 'lo-front-door')
        # Stop consumers gracefully before stopping their durable dependencies.
        demo.compose('stop', '-t', '60', 'signoz-otel-collector', 'signoz')
        demo.compose('stop', '-t', '90', 'clickhouse')
        demo.compose('stop', '-t', '30', 'zookeeper-1')
        stopped(demo)
        if shutil.disk_usage(directory).free < 20 * 1024**3:
            raise ValueError('Less than 20 GiB headroom; refusing copy rehearsal')
        shutil.copytree(demo.base / 'logs', directory / 'logs')
        archives = {}
        if set(demo.model['volumes']) != VOLUMES:
            raise ValueError('Unexpected volume set')
        for name in sorted(VOLUMES):
            volume = demo.model['volumes'][name]['name']
            if volume != 'local-observe-demo_' + name:
                raise ValueError('Unexpected source volume name')
            labels = json.loads(command(['docker', 'volume', 'inspect', volume]))[0]['Labels']
            if labels.get('com.docker.compose.project') != 'local-observe-demo':
                raise ValueError('Unexpected source volume ownership')
            filename = name + '.tar'
            helper(image, volume, directory, filename)
            path = directory / filename
            archives[name] = {'source': volume, 'sha256': sha(path), 'bytes': path.stat().st_size}
        restored = restore_model(demo.model, directory, project)
        write_json(directory / 'restore.json', restored)
        demo.record('cold_backup', {'archives': archives, 'seconds': round(time.monotonic() - start, 2),
                                   'all_source_containers_stopped': True})
        for name, archive in archives.items():
            path = directory / (name + '.tar')
            if sha(path) != archive['sha256']:
                raise ValueError('Archive checksum changed')
            target = project + '_' + name
            # Unique project names and explicit inspect prevent reusing an old target.
            if subprocess.run(['docker', 'volume', 'inspect', target], capture_output=True).returncode == 0:
                raise ValueError('Restore target already exists')
            command(['docker', 'volume', 'create', '--label', 'com.docker.compose.project=' + project,
                     '--label', 'com.docker.compose.volume=' + name, target])
            helper(image, target, directory, name + '.tar', restore=True)
        restore_started = True
        command([*restore_prefix, 'up', '-d'], timeout=360)
        original_prefix = demo.prefix
        demo.prefix = restore_prefix
        try:
            counts = demo.wait_counts(queries)
            demo.record('restored_old_telemetry', counts)
            original_url = demo.url
            demo.url = 'http://127.0.0.1:34318'
            try:
                fresh, _fresh_posts = demo.inject()
                demo.wait_counts(fresh)
            finally:
                demo.url = original_url
            demo.record('restored_new_telemetry', 'pass')
        finally:
            demo.prefix = original_prefix
        demo.report['restore_project'] = project
        demo.record('restore_duration_seconds', round(time.monotonic() - start, 2))
    finally:
        if restore_started:
            command([*restore_prefix, 'stop', '-t', '60'], timeout=180)
        demo.compose('start', 'zookeeper-1', 'clickhouse', 'signoz', 'signoz-otel-collector', 'lo-front-door', 'agent-linux')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    add_scope_arguments(parser)
    args = parser.parse_args()
    demo = Demo(args.env_file, base=args.base, uid=args.uid, docker_root=args.docker_root)
    try:
        backup_restore(demo)
        demo.report['status'] = 'pass'
    except Exception as exc:
        demo.report['status'] = 'fail'
        demo.report['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        demo.save()
        print(json.dumps({'checkpoint': str(demo.directory), 'status': demo.report['status']}), flush=True)


if __name__ == '__main__':
    main()

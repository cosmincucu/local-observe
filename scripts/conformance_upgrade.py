"""Restore, upgrade selected images, and roll back from cold archives into fresh volumes."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

from conformance_backup import VOLUMES, helper, restore_model, sha
from conformance_recovery import Demo, add_scope_arguments, command
from conformance_smoke import DIGEST
from conformance_coverage import grpc_checks, redaction

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.report import write_json


def clone(demo, checkpoint, phase):
    """Restore one cold checkpoint into a fresh, separately named project and return its prefix."""
    directory = demo.directory / phase
    directory.mkdir(mode=0o700)
    source_report = json.loads((checkpoint / 'report.json').read_text())
    archives = source_report['checks']['cold_backup']['archives']
    baseline = json.loads((checkpoint / 'restore.json').read_text())
    project = 'local-observe-demo-restore-' + demo.run[:10] + '-' + phase
    model = restore_model(baseline, directory, project)
    shutil.copytree(checkpoint / 'logs', directory / 'logs')
    # Carry the signal-forwarding fix into the rehearsal configuration.
    collector = model['services']['signoz-otel-collector']
    collector['command'] = [part.replace('\n/signoz-otel-collector --config=', '\nexec /signoz-otel-collector --config=')
                            for part in collector['command']]
    path = directory / 'compose.json'
    write_json(path, model)
    for name in sorted(VOLUMES):
        if sha(checkpoint / (name + '.tar')) != archives[name]['sha256']:
            raise ValueError('Cold archive hash mismatch')
        volume = project + '_' + name
        if subprocess.run(['docker', 'volume', 'inspect', volume], capture_output=True).returncode == 0:
            raise ValueError('Clone volume already exists')
        command(['docker', 'volume', 'create', '--label', 'com.docker.compose.project=' + project,
                 '--label', 'com.docker.compose.volume=' + name, volume])
        helper(model['services']['clickhouse']['image'], volume, checkpoint, name + '.tar', restore=True)
    return model, path, ['docker', 'compose', '--project-name', project, '-f', str(path)]


def write_model(path, model):
    """Replace a rehearsal compose model in place, atomically, readable only by the staging user."""
    write_json(path, model, replace=True)


def healthy_signoz(demo):
    """Wait for the upgraded SigNoz container to report a healthy status."""
    for _ in range(60):
        cid = demo.compose('ps', '-aq', 'signoz').strip()
        state = json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', cid]))
        if state.get('Health', {}).get('Status') == 'healthy':
            return
        time.sleep(2)
    raise ValueError('SigNoz did not become healthy after upgrade')


def rehearse(demo, checkpoint):
    """Upgrade the restored project in place and roll back to the same cold archives afterwards."""
    if (checkpoint.parent != demo.base / 'backups'
            or not re.fullmatch(r'conformance-[a-f0-9]{32}', checkpoint.name)):
        raise ValueError('Unscoped backup checkpoint')
    candidates = json.loads((demo.base / 'artifacts/upgrade-candidates.json').read_text())
    for candidate in candidates.values():
        if not DIGEST.fullmatch(candidate['image']):
            raise ValueError('Unpinned candidate')
        command(['docker', 'pull', '--quiet', candidate['image']], timeout=360)
    queries = json.loads((checkpoint / 'report.json').read_text())['retained_queries']
    source_prefix, source_url = demo.prefix, demo.url
    active = None
    try:
        demo.compose('stop', '-t', '60')
        model, path, active = clone(demo, checkpoint, 'upgrade')
        command([*active, 'up', '-d'], timeout=360)
        demo.prefix, demo.url = active, 'http://127.0.0.1:34318'
        demo.wait_counts(queries)
        demo.record('separate_restore', {'old_signals': 'pass', 'network': model['networks']['default']['name'],
                                       'project': model['name']})
        demo.compose('stop', '-t', '30', 'signoz-otel-collector')
        pending, pending_posts = demo.inject(4)
        demo.compose('stop', '-t', '30', 'lo-front-door')
        marker = 'lo-upgrade-agent-' + demo.run
        (path.parent / 'logs' / 'upgrade.log').write_text(marker + '\n')
        time.sleep(12)
        demo.compose('stop', '-t', '30', 'agent-linux', 'signoz')
        previous = {name: model['services'][name]['image'] for name in ('signoz', 'lo-front-door', 'agent-linux')}
        for name in ('lo-front-door', 'agent-linux'):
            model['services'][name]['image'] = candidates['otel']['image']
        model['services']['signoz']['image'] = candidates['signoz']['image']
        write_model(path, model)
        for name in ('lo-front-door', 'agent-linux'):
            demo.compose('run', '--rm', '--no-deps', name, 'validate', '--config=/etc/otelcol-contrib/config.yaml')
        command([*active, 'up', '-d', '--no-deps', 'signoz', 'lo-front-door', 'agent-linux', 'signoz-otel-collector'], timeout=180)
        demo.wait_counts(pending)
        agent_query = {'agent': "SELECT count() FROM signoz_logs.distributed_logs_v2 WHERE body = '" + marker + "'"}
        agent_log = demo.wait_counts(agent_query)
        demo.wait_counts(queries)
        fresh, _fresh_posts = demo.inject()
        demo.wait_counts(fresh)
        healthy_signoz(demo)
        grpc_checks(demo, port=34317)
        redaction(demo)
        demo.record('upgrade', {'old_images': previous, 'candidates': candidates, 'old_and_new_signals': 'pass',
                               'signoz_health': 'pass',
                               'pending_front_door_posts': pending_posts,
                               'pending_front_door_records': len(pending), 'pending_agent_log': agent_log['agent'],
                               'unchanged_companions': ['clickhouse', 'zookeeper-1', 'signoz-otel-collector']})
        # A failing migration must block dependent startup on this copied project.
        demo.compose('stop', '-t', '30', 'signoz', 'signoz-otel-collector')
        demo.compose('rm', '-f', 'signoz', 'signoz-otel-collector', 'signoz-telemetrystore-migrator')
        failed_model = json.loads(json.dumps(model))
        failed_model['services']['signoz-telemetrystore-migrator']['command'] = ['-c', 'exit 42']
        write_model(path, failed_model)
        result = subprocess.run([*active, 'up', '-d', 'signoz', 'signoz-otel-collector'], capture_output=True, timeout=120)
        if result.returncode == 0:
            raise ValueError('Failed migration did not block Compose startup')
        for name in ('signoz', 'signoz-otel-collector'):
            for cid in demo.compose('ps', '-aq', name).split():
                if command(['docker', 'inspect', '--format', '{{.State.Running}}', cid]).strip() != 'false':
                    raise ValueError('Dependent ran despite failed migration')
        demo.record('failed_migration_gate', {'injected_exit': 42, 'dependents_running': False})
        command([*active, 'stop', '-t', '30'], timeout=180)
        model, path, active = clone(demo, checkpoint, 'rollback')
        command([*active, 'up', '-d'], timeout=360)
        demo.prefix = active
        demo.wait_counts(queries)
        rolled_back, _rolled_back_posts = demo.inject()
        demo.wait_counts(rolled_back)
        demo.record('cold_rollback', {'project': model['name'], 'fresh_volumes': True,
                                     'old_and_new_signals': 'pass', 'upgraded_data_reused': False})
    finally:
        if active:
            command([*active, 'stop', '-t', '30'], timeout=180)
        demo.prefix, demo.url = source_prefix, source_url
        demo.compose('start', 'zookeeper-1', 'clickhouse', 'signoz', 'signoz-otel-collector', 'lo-front-door', 'agent-linux')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    parser.add_argument('--checkpoint', type=Path, required=True)
    add_scope_arguments(parser)
    args = parser.parse_args()
    demo = Demo(args.env_file, base=args.base, uid=args.uid, docker_root=args.docker_root)
    try:
        rehearse(demo, args.checkpoint)
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

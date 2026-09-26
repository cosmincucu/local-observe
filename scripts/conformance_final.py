"""Verify the pinned P1 project without rejecting independently deployed P2 components."""
import argparse
import json
from pathlib import Path
import shutil

from conformance_recovery import Demo, add_scope_arguments, command


def check_baseline(demo):
    ids = command(['docker', 'ps', '-q', '--filter', 'label=com.docker.compose.project=local-observe-demo']).split()
    states = json.loads(command(['docker', 'inspect', *ids])) if ids else []
    expected = {'agent-linux', 'lo-front-door', 'signoz', 'clickhouse', 'zookeeper-1', 'signoz-otel-collector'}
    found = set()
    summary = []
    for state in states:
        labels = state['Config']['Labels']
        service = labels.get('com.docker.compose.service')
        if labels.get('com.docker.compose.project') != 'local-observe-demo' or service not in expected:
            raise ValueError('Unexpected running rehearsal container')
        found.add(service)
        if state['Config']['Image'] != demo.model['services'][service]['image']:
            raise ValueError('Baseline image changed')
        health = state['State'].get('Health', {}).get('Status')
        if health and health != 'healthy':
            raise ValueError('Baseline health not ready: ' + service)
        for bindings in state['NetworkSettings']['Ports'].values():
            if bindings and any(port['HostIp'] != '127.0.0.1' for port in bindings):
                raise ValueError('Non-loopback publication')
        summary.append({'service': service, 'health': health or 'running',
                        'image': state['Config']['Image'], 'oom_killed': state['State']['OOMKilled']})
    if found != expected or len(states) != len(expected):
        raise ValueError('Incomplete baseline')
    demo.record('final_baseline', summary)
    disk = shutil.disk_usage(demo.base)
    demo.record('staging_disk', {'total_bytes': disk.total, 'used_bytes': disk.used, 'free_bytes': disk.free})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    add_scope_arguments(parser)
    args = parser.parse_args()
    demo = Demo(args.env_file, base=args.base, uid=args.uid, docker_root=args.docker_root)
    try:
        check_baseline(demo)
        demo.report['status'] = 'pass'
    except Exception as exc:
        demo.report['status'] = 'fail'
        demo.report['error'] = type(exc).__name__ + ': ' + str(exc)
        raise
    finally:
        demo.save()
        print(json.dumps({'checkpoint': str(demo.directory), 'status': demo.report['status']}))


if __name__ == '__main__':
    main()

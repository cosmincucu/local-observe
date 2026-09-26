"""Bound queue and disk-failure experiments inside disposable collector projects."""
import argparse
import copy
import json
from pathlib import Path
import sys
import time
import urllib.error
import yaml

from conformance_recovery import Demo, add_scope_arguments, command
from conformance_smoke import ROOT, payloads, post

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.report import write_json


def pressure(demo, disk=False):
    """Run one bounded queue/disk-failure experiment in a disposable collector project, then stop it."""
    name = 'disk' if disk else 'queue'
    directory = demo.directory / name
    directory.mkdir(mode=0o700)
    project = 'local-observe-demo-pressure-' + demo.run[:10] + '-' + name
    config = yaml.safe_load((ROOT / 'components/data/front-door/collector.yaml').read_text())
    config['exporters']['otlp']['sending_queue']['queue_size'] = 3000 if disk else 4
    config['exporters']['otlp']['sending_queue']['num_consumers'] = 1
    config_path = directory / 'collector.json'
    write_json(config_path, config)
    service = copy.deepcopy(demo.model['services']['lo-front-door'])
    service['restart'] = 'no'
    service['environment']['LO_STORE_OTLP_ENDPOINT'] = '127.0.0.1:9'
    service['ports'] = [{'target': 4318, 'published': '44318', 'host_ip': '127.0.0.1', 'protocol': 'tcp'}]
    service['volumes'] = [{'type': 'bind', 'source': str(config_path),
                           'target': '/etc/otelcol-contrib/config.yaml', 'read_only': True}]
    model = {'name': project, 'services': {'lo-front-door': service}}
    if disk:
        service['tmpfs'] = ['/var/lib/otelcol:rw,size=2097152']
    else:
        service['volumes'].append({'type': 'volume', 'source': 'queue', 'target': '/var/lib/otelcol'})
        model['volumes'] = {'queue': {'name': project + '_queue'}}
    path = directory / 'compose.json'
    write_json(path, model)
    prefix = ['docker', 'compose', '--project-name', project, '-f', str(path)]
    statuses = []
    try:
        command([*prefix, 'up', '-d'])
        time.sleep(3)
        sample = payloads(demo.run)[0]['logs']
        if disk:
            sample['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]['body']['stringValue'] = 'synthetic:' + 'x' * 500000
        for _ in range(20):
            try:
                status, _ = post('http://127.0.0.1:44318/v1/logs', sample, demo.token)
                statuses.append(status)
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                statuses.append('connection-failed')
                break
        if not any(status == 200 for status in statuses) or all(status == 200 for status in statuses):
            raise ValueError('Did not observe both acceptance and bounded failure')
        if not disk and any(status not in (200, 429, 503) for status in statuses):
            raise ValueError('Unexpected queue-full response')
        logs = command([*prefix, 'logs', '--no-color', '--tail', '100', 'lo-front-door'])
        # Keep collector diagnostics private; only expose classification in shared evidence.
        (directory / 'collector.log').write_text(logs)
        evidence = {'http_statuses': statuses, 'queue_capacity_requests': 3000 if disk else 4,
                    'tmpfs_byte_limit': 2097152 if disk else None,
                    'enospc_observed': 'no space left on device' in logs.lower(),
                    'scope': 'disposable collector only; no host/dataset pressure'}
        if disk and not evidence['enospc_observed']:
            raise ValueError('Disk test failed without ENOSPC evidence')
        demo.record(name + '_pressure', evidence)
    finally:
        command([*prefix, 'stop', '-t', '10'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    add_scope_arguments(parser)
    args = parser.parse_args()
    demo = Demo(args.env_file, base=args.base, uid=args.uid, docker_root=args.docker_root)
    try:
        pressure(demo)
        pressure(demo, disk=True)
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

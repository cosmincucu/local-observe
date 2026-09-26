"""Exercise recovery in an explicitly selected, guarded demo installation."""
import argparse
import json
from pathlib import Path
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.guards import rootless_docker_guard
from _lib.report import write_report
from _lib.require import require
from _lib.run import run as command

from conformance_smoke import ROOT, compose_output, payloads, post, require_accepted, validate_runtime

PROJECT = 'local-observe-demo'


def add_scope_arguments(parser):
    """Require the operator to select the scratch boundary and rootless daemon."""
    parser.add_argument('--base', type=Path, required=True, help='existing demo scratch directory')
    parser.add_argument('--uid', type=int, required=True, help='non-root account running the demo')
    parser.add_argument('--docker-root', type=Path, required=True, help='expected rootless Docker data directory under base')


class Demo:
    """The isolated demo stack, its front door and the private evidence directory of one run."""

    def __init__(self, env, *, base, uid, docker_root):
        base, docker_root = Path(base), Path(docker_root)
        require(base.is_absolute() and base.is_dir() and base.resolve() == base,
                'Demo base must be an existing absolute directory without symlink components')
        require(type(uid) is int and uid > 0, 'Demo uid must be non-root')
        require(docker_root.is_absolute() and docker_root.is_dir()
                and docker_root.resolve() == docker_root and docker_root.is_relative_to(base)
                and docker_root != base, 'Docker data directory must be inside the selected demo base')
        self.base = base
        rootless_docker_guard(base, uid, adopt_environment=False, user_name=None,
                              expected_root_dir=str(docker_root))
        info = json.loads(command(['docker', 'info', '--format', '{{json .}}']))
        require(any('rootless' in option for option in info['SecurityOptions']), 'Unexpected daemon')
        self.prefix = ['docker', 'compose', '--env-file', str(env.resolve()), '--project-name', PROJECT,
                       '-f', str(ROOT / 'examples/demo/compose.yaml')]
        self.model = json.loads(compose_output(self.prefix, 'config', '--format', 'json'))
        self.url, self.token = validate_runtime(self.model)
        self.run = uuid.uuid4().hex
        self.report = {'run_id': self.run, 'checks': {}, 'status': 'running', 'scope': ('isolated project '+PROJECT+' under '+str(base)+'; synthetic markers only')}
        self.directory = base / 'backups' / ('conformance-' + self.run)
        self.directory.mkdir(mode=0o700)
        self.save()

    def save(self):
        """Checkpoint the report durably, so a crash mid-run still leaves a readable one."""
        write_report(self.directory / 'report.json', self.report, replace=True)

    def compose(self, *args):
        """Run one compose command against this project only."""
        return command([*self.prefix, *args])

    def query(self, sql):
        """Return the single scalar a ClickHouse query produced."""
        return self.compose('exec', '-T', 'clickhouse', 'clickhouse-client', '--query',
                            sql + ' SETTINGS max_execution_time=10 FORMAT TabSeparated').strip()

    def counts(self, queries):
        """Return one integer per named marker query."""
        return {name: int(self.query(sql)) for name, sql in queries.items()}

    def wait_counts(self, queries, expected=1, timeout=180):
        """Wait until every marker reads exactly ``expected``, and return the observed counts.

        Raises if a marker never arrives or arrives twice, so a count that comes back from here is
        an observation and never a promise about what the caller intended to send.
        """
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            counts = self.counts(queries)
            if all(n >= expected for n in counts.values()):
                # Allow delayed duplicates to arrive before recording reconciliation.
                time.sleep(8)
                counts = self.counts(queries)
                if any(n != expected for n in counts.values()):
                    raise ValueError('Unexpected duplicate counts: ' + str(counts))
                return counts
            time.sleep(2)
        raise ValueError('Timed out awaiting markers: ' + str(counts))

    def inject(self, count=1):
        """Send ``count`` synthetic samples; return their marker queries and the accepted posts.

        Every accepted POST contributes exactly one marker query, so the two numbers are checked
        against each other here rather than one of them being written into the report by hand.
        """
        queries, accepted = {}, 0
        for index in range(count):
            samples, sql = payloads(uuid.uuid4().hex)
            for signal, sample in samples.items():
                require_accepted(*post(self.url + '/v1/' + signal, sample, self.token))
                accepted += 1
                queries[f'{index}_{signal}'] = sql[signal]
        require(accepted == len(queries), f'sent {accepted} accepted posts but tracked {len(queries)} markers')
        return queries, accepted

    def record(self, name, value):
        """Add one check to the report, persist it, and echo it as a JSON line."""
        self.report['checks'][name] = value
        self.save()
        print(json.dumps({name: value}), flush=True)


def recovery(demo):
    """Kill the collector and the front door around in-flight traffic; prove nothing is lost."""
    retained, retained_posts = demo.inject()
    demo.wait_counts(retained)
    try:
        demo.compose('stop', '-t', '30', 'signoz-otel-collector')
        queued, queued_posts = demo.inject(12)
        if any(demo.counts(queued).values()):
            raise ValueError('Outage markers unexpectedly reached the stopped downstream')
        demo.compose('kill', '-s', 'SIGKILL', 'lo-front-door')
        demo.compose('start', 'lo-front-door')
        time.sleep(5)
        demo.compose('start', 'signoz-otel-collector')
        started = time.monotonic()
        counts = demo.wait_counts(queued)
        demo.record('front_door_crash_queue', {'accepted': queued_posts, 'stored': sum(counts.values()),
                    'missing': sum(max(0, 1 - count) for count in counts.values()),
                    'duplicates': sum(max(0, count - 1) for count in counts.values()),
                    'recovery_seconds': round(time.monotonic() - started, 2)})

        demo.compose('stop', '-t', '30', 'lo-front-door')
        marker = 'lo-agent-recovery-' + demo.run
        source = demo.base / 'logs' / ('recovery-' + demo.run + '.log')
        source.write_text(marker + '\n')
        time.sleep(12)
        demo.compose('kill', '-s', 'SIGKILL', 'agent-linux')
        demo.compose('start', 'agent-linux')
        time.sleep(5)
        demo.compose('start', 'lo-front-door')
        query = {'agent': "SELECT count() FROM signoz_logs.distributed_logs_v2 WHERE body = '" + marker + "'"}
        agent = demo.wait_counts(query)
        demo.record('agent_crash_queue', {'markers': len(agent), 'stored': agent['agent'],
                    'missing': max(0, 1 - agent['agent']), 'duplicates': max(0, agent['agent'] - 1)})
        source.rename(source.with_suffix('.log.1'))
        source.write_text(marker + '-rotated\n')
        rotated = demo.wait_counts({'rotated': query['agent'].replace(marker, marker + '-rotated')})
        demo.record('file_rotation', {'old': int(demo.query(query['agent'])), 'new': rotated['rotated']})

        demo.compose('stop', '-t', '30', 'agent-linux', 'lo-front-door', 'signoz-otel-collector', 'signoz')
        demo.compose('stop', '-t', '60', 'clickhouse')
        demo.compose('start', 'clickhouse')
        for _ in range(60):
            try:
                if demo.query('SELECT 1') == '1':
                    break
            except RuntimeError:
                pass
            time.sleep(2)
        retained_after = demo.wait_counts(retained)
        demo.record('store_restart', {'accepted_before_outage': retained_posts, 'markers': len(retained),
                                      'stored': sum(retained_after.values()),
                                      'old_metric_log_trace': 'pass'})
        demo.report['retained_queries'] = retained
    finally:
        demo.compose('start', 'clickhouse', 'signoz', 'signoz-otel-collector', 'lo-front-door', 'agent-linux')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', type=Path, required=True)
    add_scope_arguments(parser)
    args = parser.parse_args()
    demo = Demo(args.env_file, base=args.base, uid=args.uid, docker_root=args.docker_root)
    try:
        recovery(demo)
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

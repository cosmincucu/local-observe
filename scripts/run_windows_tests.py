"""Bound one stock tier run, including interpreter shutdown, without changing asyncio."""
from __future__ import annotations

import argparse
import faulthandler
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import secrets
import subprocess
import sys
import time

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[1]
MAX_BYTES = 32 * 1024 * 1024


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_new(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)


def read_json(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError('Invalid report file')
    return json.loads(path.read_text(encoding='utf-8'))


def identity():
    return {'executable': str(Path(sys.executable).resolve()),
            'base_executable': str(Path(getattr(sys, '_base_executable', sys.executable)).resolve()),
            'prefix': str(Path(sys.prefix).resolve()), 'base_prefix': str(Path(sys.base_prefix).resolve()),
            'python': sys.version, 'mcp': importlib.util.find_spec('mcp') is not None}


def child_command(worker_script, config):
    """Use CPython's own venv redirector contract, but retain the interpreter handle."""
    environment = os.environ.copy()
    executable = sys.executable
    if os.name == 'nt':
        if sys.implementation.name != 'cpython' or not getattr(sys, '_base_executable', None):
            raise ValueError('Direct Windows supervision requires CPython')
        executable = str(Path(sys._base_executable).resolve())
        environment['__PYVENV_LAUNCHER__'] = sys.executable
    # POSIX venv executables are commonly symlinks: resolving argv[0] loses pyvenv.cfg.
    return [str(Path(executable).absolute()), '-I', '-B', str(worker_script), '--_worker', str(config)], environment


def worker(config_path):
    config = read_json(config_path)
    output, root = Path(config_path).resolve().parent, Path(config['root'])
    runner = root / 'tests/tiers.py'
    if digest(runner) != config['runner_sha256']:
        raise ValueError('Tier runner input changed')
    # The C-level timer remains armed during atexit and interpreter shutdown.
    stacks = (output / 'stacks.log').open('xb')
    faulthandler.enable(file=stacks, all_threads=True)
    faulthandler.dump_traceback_later(config['stack_interval'], repeat=True, file=stacks)
    write_new(output / 'started.json', {'run_id': config['run_id'], 'pid': os.getpid(),
                                       'identity': identity()})
    os.chdir(root)
    sys.argv = [str(runner), '--start-dir', str(root / config['start_dir']),
                '--json', str(output / 'tier-report.json'), '--verbose']
    if config['only_tier']:
        sys.argv += ['--only-tier', config['only_tier']]
    code = 0
    try:
        runpy.run_path(str(runner), run_name='__main__')
    except SystemExit as error:
        code = error.code if type(error.code) is int else (0 if error.code is None else 1)
    report = output / 'tier-report.json'
    write_new(output / 'completed.json', {'run_id': config['run_id'], 'pid': os.getpid(),
                                         'returncode': code,
                                         'report_sha256': digest(report) if report.is_file() else None})
    # Keep the file object alive; closing it here would lose teardown evidence.
    globals()['_stacks_through_exit'] = stacks
    return code


def report_clean(report, config):
    """Reject stale selections and inconsistent counters, not just a claimed pass flag."""
    try:
        if (type(report['schema_version']) is not int or report['schema_version'] != 1
                or report['generated_by'] != 'tests/tiers.py'
                or report.get('only_tier') != config['only_tier'] or len(report['tiers']) != 1):
            return False
        tier = report['tiers'][0]
        if tier['start_dir'] != str(Path(config['root']) / config['start_dir']):
            return False
        for name in ('collected', 'ran', 'skipped'):
            if type(tier[name]) is not int or tier[name] < 0:
                return False
        if tier['collected'] == 0 or tier['ran'] != tier['collected'] or tier['skipped'] > tier['ran']:
            return False
        for name in ('failures', 'errors', 'collection_errors', 'unexpected_successes'):
            if tier[name] != []:
                return False
        if (not isinstance(tier['expected_failures'], list) or not isinstance(tier['skips'], list)
                or len(tier['skips']) != tier['skipped']):
            return False
        expected = {'collected': tier['collected'], 'ran': tier['ran'], 'skipped': tier['skipped'],
                    'failures': 0, 'errors': 0, 'collection_errors': 0}
        return (report['totals'] == expected and all(type(v) is int for v in report['totals'].values())
                and report['environment']['optional_modules']['mcp'] is config['identity']['mcp'])
    except (KeyError, TypeError, ValueError):
        return False


def supervise(output, timeout=900, start_dir='tests', only_tier=None, *, root=ROOT,
              launcher=subprocess.Popen, worker_script=SCRIPT, stack_interval=5):
    if (type(timeout) not in (int, float) or not 1 <= timeout <= 3600
            or start_dir not in ('tests', 'tests/compiler') or only_tier not in (None, 'mcp')
            or (only_tier and start_dir != 'tests') or not 0.05 <= stack_interval <= 10):
        raise ValueError('Invalid bounded tier selection')
    output, root = Path(output).resolve(), Path(root).resolve()
    if output == root or output.is_relative_to(root / 'tests'):
        raise ValueError('Output must be outside test discovery')
    output.mkdir()  # No report from an earlier attempt can be reused.
    before = {'supervisor': digest(worker_script), 'runner': digest(root / 'tests/tiers.py')}
    config = {'run_id': secrets.token_hex(16), 'root': str(root), 'start_dir': start_dir,
              'only_tier': only_tier, 'identity': identity(), 'runner_sha256': before['runner'],
              'stack_interval': min(stack_interval, timeout / 4)}
    write_new(output / 'run.json', config)
    command, environment = child_command(worker_script, output / 'run.json')
    result = {'schema_version': 1, 'run_id': config['run_id'], 'command': command,
              'executable_sha256': digest(command[0]), 'input_before': before,
              'identity_scope': 'supervisor and tier reporter bytes and interpreter; not a full checkout manifest',
              'timeout_seconds': timeout, 'suite_clean': False, 'work_complete': False,
              'exit_observed': False, 'timed_out': False, 'interrupted': False,
              'cleanup_failed': False, 'output_limit': False, 'success': False}
    began = time.monotonic()
    process = None
    with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
        try:
            process = launcher(command, env=environment, cwd=root, stdout=stdout, stderr=stderr, shell=False)
            result['pid'] = process.pid
            write_new(output / 'owned.json', {'pid': process.pid, 'command': command,
                                              'executable_sha256': result['executable_sha256'],
                                              'started_epoch_seconds': time.time()})
            while True:
                remaining = timeout - (time.monotonic() - began)
                if remaining <= 0:
                    result['timed_out'] = True
                    break
                if any(p.stat().st_size > MAX_BYTES for p in output.iterdir() if p.is_file()):
                    result['output_limit'] = True
                    break
                try:
                    result['returncode'] = process.wait(timeout=min(0.2, remaining))
                    result['exit_observed'] = True
                    break
                except subprocess.TimeoutExpired:
                    continue
        except KeyboardInterrupt:
            result['interrupted'] = True
        except OSError as error:
            result['launch_or_wait_error'] = type(error).__name__
        finally:
            if process is not None and not result['exit_observed']:
                try:
                    if process.poll() is None:
                        process.kill()  # Only the retained direct-child handle, never a numeric PID lookup.
                        result['kill_requested'] = True
                    result['returncode'] = process.wait(timeout=5)
                    result['exit_observed'] = True
                except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                    result['cleanup_failed'] = True
                    result['cleanup_error'] = type(error).__name__
    result['elapsed_seconds'] = time.monotonic() - began
    # A child can exceed the limit and exit during wait(), before the next poll.
    try:
        if any(path.stat().st_size > MAX_BYTES for path in output.iterdir() if path.is_file()):
            result['output_limit'] = True
    except OSError as error:
        result['file_read_error'] = type(error).__name__
    try:
        started = read_json(output / 'started.json')
        result['identity_matches'] = (started == {'run_id': config['run_id'], 'pid': result['pid'],
                                                'identity': config['identity']})
        completed = read_json(output / 'completed.json')
        result['work_complete'] = (completed['run_id'] == config['run_id'] and completed['pid'] == result['pid'])
        report = read_json(output / 'tier-report.json')
        result['suite_clean'] = (completed['returncode'] == 0
                                 and completed['report_sha256'] == digest(output / 'tier-report.json')
                                 and report_clean(report, config))
    except (OSError, ValueError, KeyError, TypeError):
        result['report_refused'] = True
    try:
        result['input_unchanged'] = before == {'supervisor': digest(worker_script),
                                             'runner': digest(root / 'tests/tiers.py')}
    except OSError as error:
        result['input_unchanged'] = False
        result['input_error'] = type(error).__name__
    result['success'] = bool(result['suite_clean'] and result['work_complete'] and result.get('identity_matches')
                             and result['exit_observed'] and result.get('returncode') == 0
                             and result['input_unchanged'] and not any(result[k] for k in
                                 ('timed_out', 'interrupted', 'cleanup_failed', 'output_limit'))
                             and 'launch_or_wait_error' not in result and 'file_read_error' not in result)
    result['logs_final'] = result['exit_observed'] or process is None
    result['files'] = {}
    for path in output.iterdir():
        try:
            if path.is_file() and path.stat().st_size <= MAX_BYTES:
                result['files'][path.name] = {'bytes': path.stat().st_size, 'sha256': digest(path)}
        except OSError as error:
            result['success'] = False
            result['file_read_error'] = type(error).__name__
    write_new(output / 'supervisor-report.json', result)
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == '--_worker':
        return worker(argv[1])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--start-dir', choices=('tests', 'tests/compiler'), default='tests')
    parser.add_argument('--only-tier', choices=('mcp',))
    args = parser.parse_args(argv)
    result = supervise(args.output, args.timeout, args.start_dir, args.only_tier)
    print(json.dumps({'success': result['success'], 'report': str(args.output / 'supervisor-report.json')}))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    sys.exit(main())

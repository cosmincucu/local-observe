"""Opt-in stdlib probes for socketpair and default asyncio loop construction."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import threading
import time
import traceback

CASES = ('socketpair', 'runner-per-iteration', 'shared-runner-control')
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_STACK_BYTES = 1024 * 1024
SCRIPT = Path(__file__).resolve()


def file_identity(path):
    path = Path(path).resolve()
    return {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def identity():
    sources = {}
    for module in (socket, asyncio.runners, asyncio.events):
        sources[module.__name__] = file_identity(module.__file__)
    return {'python': sys.version, 'implementation': platform.python_implementation(),
            'platform': platform.platform(), 'architecture': platform.machine(),
            'executable': file_identity(sys.executable), 'pid': os.getpid(), 'ppid': os.getppid(),
            'cwd': str(Path.cwd()), 'script': file_identity(SCRIPT), 'stdlib': sources,
            'default_policy': type(asyncio.get_event_loop_policy()).__name__}


def worker(case, iterations, directory):
    """Only fixed stdlib operations; never launch another process or change policy."""
    phase = {'name': 'CHILD_START', 'iteration': 0}
    began = time.monotonic()
    sequence = 0

    def emit(name, iteration=0, **extra):
        nonlocal sequence
        phase.update(name=name, iteration=iteration)
        print(json.dumps({'sequence': sequence, 'phase': name, 'case': case,
                          'iteration': iteration, 'pid': os.getpid(),
                          'elapsed': time.monotonic() - began, 'epoch_seconds': time.time(), **extra}), flush=True)
        sequence += 1

    emit('CHILD_START', identity=identity())
    stack_path = directory / 'stacks.log'
    stack_path.touch(exist_ok=False)

    def observe():
        while True:
            time.sleep(5)
            output = io.StringIO()
            output.write(json.dumps({'pid': os.getpid(), 'phase': dict(phase),
                                     'elapsed': time.monotonic() - began}) + '\n')
            for ident, frame in list(sys._current_frames().items())[:16]:
                output.write('THREAD ' + str(ident) + '\n')
                traceback.print_stack(frame, limit=25, file=output)
            data = output.getvalue().encode('utf-8', errors='replace')[:65536]
            remaining = MAX_STACK_BYTES - stack_path.stat().st_size
            if remaining <= 0:
                return
            with stack_path.open('ab') as stream:
                stream.write(data[:remaining])

    threading.Thread(target=observe, daemon=True, name='diagnostic-observer').start()

    async def noop(iteration):
        emit('COROUTINE_ENTERED', iteration)
        return 'diagnostic-sentinel'

    def run(runner, iteration):
        if runner.run(noop(iteration)) != 'diagnostic-sentinel':
            raise RuntimeError('Unexpected coroutine result')
        emit('RUN_RETURNED', iteration)

    def entered(runner, iteration):
        loop = runner.get_loop()
        emit('RUNNER_ENTERED', iteration, loop_class=type(loop).__name__,
             loop_source=file_identity(sys.modules[type(loop).__module__].__file__))

    if case == 'socketpair':
        for iteration in range(iterations):
            emit('SOCKETPAIR_BEGIN', iteration)
            left, right = socket.socketpair()
            try:
                emit('SOCKETPAIR_READY', iteration)
            finally:
                left.close()
                right.close()
            emit('SOCKETPAIR_CLOSED', iteration)
    elif case == 'runner-per-iteration':
        for iteration in range(iterations):
            emit('RUNNER_ENTER_BEGIN', iteration)
            with asyncio.Runner() as runner:
                entered(runner, iteration)
                run(runner, iteration)
                emit('RUNNER_CLOSE_BEGIN', iteration)
            emit('RUNNER_CLOSED', iteration)
    else:
        emit('RUNNER_ENTER_BEGIN')
        with asyncio.Runner() as runner:
            entered(runner, 0)
            for iteration in range(iterations):
                run(runner, iteration)
            emit('RUNNER_CLOSE_BEGIN', iterations - 1)
        emit('RUNNER_CLOSED', iterations - 1)
    emit('WORK_COMPLETE', iterations=iterations)
    # Fatal faulthandler and stderr remain enabled through interpreter teardown.


def expected_markers(case, iterations):
    expected = [('CHILD_START', 0)]
    if case == 'socketpair':
        for index in range(iterations):
            expected.extend((phase, index) for phase in ('SOCKETPAIR_BEGIN', 'SOCKETPAIR_READY', 'SOCKETPAIR_CLOSED'))
    elif case == 'runner-per-iteration':
        for index in range(iterations):
            expected.extend((phase, index) for phase in ('RUNNER_ENTER_BEGIN', 'RUNNER_ENTERED',
                            'COROUTINE_ENTERED', 'RUN_RETURNED', 'RUNNER_CLOSE_BEGIN', 'RUNNER_CLOSED'))
    else:
        expected.extend([('RUNNER_ENTER_BEGIN', 0), ('RUNNER_ENTERED', 0)])
        for index in range(iterations):
            expected.extend([('COROUTINE_ENTERED', index), ('RUN_RETURNED', index)])
        expected.extend([('RUNNER_CLOSE_BEGIN', iterations - 1), ('RUNNER_CLOSED', iterations - 1)])
    return expected + [('WORK_COMPLETE', 0)]


def run_case(case, iterations, timeout, directory, *, launcher=subprocess.Popen, worker_script=SCRIPT):
    """Retain the exact Popen object; no numeric-PID lookup or descendant cleanup."""
    directory.mkdir()
    executable = Path(getattr(sys, '_base_executable', sys.executable)).resolve()
    command = [str(executable), '-I', '-B', '-X', 'faulthandler', str(worker_script),
               '--_worker', case, str(iterations), str(directory.resolve())]
    before = file_identity(worker_script)
    result = {'schema_version': 1, 'case': case, 'iterations': iterations, 'timeout_seconds': timeout,
              'command': command, 'executable': file_identity(executable), 'input_before': before,
              'work_complete': False, 'exit_observed': False, 'timed_out': False,
              'cleanup_failed': False, 'interrupted': False, 'success': False,
              'started_epoch_seconds': time.time()}
    began = time.monotonic()
    # File handles stay open until the child has exited, including atexit/fatal output.
    with (directory / 'markers.jsonl').open('xb') as stdout, (directory / 'stderr.log').open('xb') as stderr:
        process = None
        try:
            process = launcher(command, stdout=stdout, stderr=stderr, shell=False)
        except OSError as error:
            result['launch_error'] = type(error).__name__
        if process is not None:
            result['launcher_pid'] = process.pid
            try:
                result['returncode'] = process.wait(timeout=timeout)
                result['exit_observed'] = True
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as interruption:
                result['timed_out'] = isinstance(interruption, subprocess.TimeoutExpired)
                result['interrupted'] = isinstance(interruption, KeyboardInterrupt)
                try:
                    if process.poll() is None:
                        process.kill()
                        result['kill_requested'] = True
                    result['returncode'] = process.wait(timeout=5)
                    result['exit_observed'] = True
                except (OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
                    result['cleanup_failed'] = True
                    result['cleanup_error'] = type(error).__name__
    result['elapsed_seconds'] = time.monotonic() - began
    marker_path = directory / 'markers.jsonl'
    rows = []
    try:
        if marker_path.stat().st_size > MAX_LOG_BYTES:
            raise ValueError('Marker log exceeds limit')
        rows = [json.loads(line) for line in marker_path.read_text(encoding='utf-8').splitlines()]
        result['work_complete'] = any(row.get('phase') == 'WORK_COMPLETE' for row in rows)
        result['pid_matches'] = bool(rows) and process is not None and all(row['pid'] == process.pid for row in rows)
        result['markers_valid'] = ([(row['phase'], row['iteration']) for row in rows] == expected_markers(case, iterations)
                                   and [row['sequence'] for row in rows] == list(range(len(rows)))
                                   and all(row['case'] == case for row in rows)
                                   and rows[-1]['iterations'] == iterations)
    except (ValueError, KeyError, TypeError, AttributeError):
        result['markers_valid'] = False
    result['last_phase'] = rows[-1].get('phase') if rows and isinstance(rows[-1], dict) else None
    result['input_unchanged'] = before == file_identity(worker_script)
    result['success'] = (result['exit_observed'] and result.get('returncode') == 0
                         and not result['timed_out'] and not result['cleanup_failed'] and not result['interrupted']
                         and result.get('pid_matches', False) and result['markers_valid']
                         and result['input_unchanged'])
    result['logs'] = {name: file_identity(directory / name) for name in ('markers.jsonl', 'stderr.log')}
    if (directory / 'stacks.log').exists():
        result['logs']['stacks.log'] = file_identity(directory / 'stacks.log')
    result['logs_final'] = result['exit_observed'] or process is None
    (directory / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def bounded_integer(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError('Expected an integer') from error
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f'Expected {low}..{high}')
        return number
    return parse


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == '--_worker':
        if len(argv) != 4 or argv[1] not in CASES:
            raise ValueError('Invalid internal worker arguments')
        worker(argv[1], bounded_integer(1, 1000)(argv[2]), Path(argv[3]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--iterations', type=bounded_integer(1, 1000), default=250)
    parser.add_argument('--timeout', type=bounded_integer(1, 120), default=60)
    args = parser.parse_args(argv)
    args.output.mkdir()  # Exclusive creation; never reuse or overwrite prior evidence.
    before = identity()
    results = []
    for case in CASES:
        results.append(run_case(case, args.iterations, args.timeout, args.output / case))
        if results[-1]['cleanup_failed'] or results[-1].get('interrupted', False):
            break
    report = {'schema_version': 1, 'identity': before, 'cases': results,
              'input_unchanged': before['script'] == file_identity(SCRIPT)}
    report['success'] = len(results) == len(CASES) and all(row['success'] for row in results) and report['input_unchanged']
    (args.output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'success': report['success'], 'report': str(args.output / 'report.json')}))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

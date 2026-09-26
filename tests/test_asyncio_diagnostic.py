"""Own-child diagnostics distinguish completed work from actual interpreter exit."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'asyncio_diagnostic', Path(__file__).resolve().parents[1] / 'scripts/diagnose_windows_asyncio.py')
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, ending='', *, missing=False, wrong_pid=False):
        rows = diagnostic.expected_markers('socketpair', 1)
        script = self.root / 'child.py'
        script.write_text('import atexit,json,os,sys,time\n'
                          "atexit.register(lambda: print('AFTER_WORK_AT_EXIT',file=sys.stderr,flush=True))\n"
                          + ('rows=[]\n' if missing else 'rows=' + repr(rows) + '\n')
                          + 'for seq,(phase,iteration) in enumerate(rows):\n'
                          + " print(json.dumps(dict(sequence=seq,phase=phase,iteration=iteration,case='socketpair',"
                          + ('pid=-1,' if wrong_pid else 'pid=os.getpid(),')
                          + 'iterations=1)),flush=True)\n' + ending, encoding='utf-8')
        return script

    def run_fixture(self, **kwargs):
        script = self.fixture(**kwargs)
        return diagnostic.run_case('socketpair', 1, 1, self.root / 'case', worker_script=script)

    def test_three_real_tiny_stdlib_probes_complete_and_exit(self):
        for case in diagnostic.CASES:
            with self.subTest(case=case):
                result = diagnostic.run_case(case, 2, 10, self.root / case)
                self.assertTrue(result['success'], result)
                self.assertTrue(result['work_complete'])
                self.assertTrue(result['exit_observed'])
                self.assertTrue(result['pid_matches'])
                self.assertEqual(result['returncode'], 0)
                self.assertIn('faulthandler', result['command'])
                rows = [json.loads(line) for line in (self.root / case / 'markers.jsonl').read_text().splitlines()]
                self.assertEqual(rows[0]['identity']['pid'], result['launcher_pid'])

    def test_completed_work_with_live_thread_times_out_and_is_not_success(self):
        result = self.run_fixture(ending='import threading\nthreading.Thread(target=lambda: time.sleep(30)).start()\n')
        self.assertTrue(result['work_complete'])
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['kill_requested'])
        self.assertTrue(result['exit_observed'])
        self.assertFalse(result['cleanup_failed'])
        self.assertFalse(result['success'])

    def test_stall_before_first_marker_still_cleans_up_owned_handle(self):
        result = self.run_fixture(missing=True, ending='time.sleep(30)\n')
        self.assertFalse(result['work_complete'])
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['exit_observed'])
        self.assertTrue(result['kill_requested'])
        self.assertFalse(result['success'])

    def test_complete_marker_cannot_mask_nonzero_exit(self):
        result = self.run_fixture(ending='sys.exit(7)\n')
        self.assertTrue(result['work_complete'])
        self.assertEqual(result['returncode'], 7)
        self.assertFalse(result['success'])

    def test_zero_exit_without_markers_is_not_success(self):
        result = self.run_fixture(missing=True)
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['success'])

    def test_wrong_child_pid_refuses_success(self):
        result = self.run_fixture(wrong_pid=True)
        self.assertFalse(result['pid_matches'])
        self.assertFalse(result['success'])

    def test_stderr_is_retained_through_atexit_after_complete(self):
        result = self.run_fixture()
        self.assertTrue(result['success'])
        self.assertIn('AFTER_WORK_AT_EXIT', (self.root / 'case/stderr.log').read_text())
        self.assertEqual(result['logs']['stderr.log'], diagnostic.file_identity(self.root / 'case/stderr.log'))

    def test_kill_denied_has_no_alternate_cleanup(self):
        process = mock.Mock(pid=123)
        process.wait.side_effect = subprocess.TimeoutExpired('owned-fixture', 1)
        process.poll.return_value = None
        process.kill.side_effect = PermissionError('denied')
        launcher = mock.Mock(return_value=process)
        result = diagnostic.run_case('socketpair', 1, 1, self.root / 'case', launcher=launcher)
        self.assertTrue(result['cleanup_failed'])
        self.assertEqual(result['cleanup_error'], 'PermissionError')
        self.assertFalse(result['exit_observed'])
        self.assertEqual(process.method_calls, [mock.call.wait(timeout=1), mock.call.poll(), mock.call.kill()])
        self.assertFalse(launcher.call_args.kwargs['shell'])

    def test_exit_race_does_not_kill_completed_process(self):
        process = mock.Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired('owned-fixture', 1), 0]
        process.poll.return_value = 0
        result = diagnostic.run_case('socketpair', 1, 1, self.root / 'case', launcher=mock.Mock(return_value=process))
        process.kill.assert_not_called()
        self.assertTrue(result['exit_observed'])
        self.assertTrue(result['timed_out'])
        self.assertFalse(result['success'])

    def test_launch_error_is_a_retained_failed_receipt(self):
        launcher = mock.Mock(side_effect=PermissionError('not executable'))
        result = diagnostic.run_case('socketpair', 1, 1, self.root / 'case', launcher=launcher)
        self.assertEqual(result['launch_error'], 'PermissionError')
        self.assertFalse(result['success'])
        self.assertFalse(result['exit_observed'])
        self.assertTrue(result['logs_final'])
        self.assertEqual(json.loads((self.root / 'case/result.json').read_text()), result)

    def test_keyboard_interrupt_cleans_only_owned_handle(self):
        process = mock.Mock(pid=123)
        process.wait.side_effect = [KeyboardInterrupt(), -9]
        process.poll.return_value = None
        result = diagnostic.run_case('socketpair', 1, 1, self.root / 'case', launcher=mock.Mock(return_value=process))
        self.assertTrue(result['interrupted'])
        self.assertTrue(result['exit_observed'])
        self.assertFalse(result['success'])
        self.assertEqual(process.method_calls, [mock.call.wait(timeout=1), mock.call.poll(),
                                               mock.call.kill(), mock.call.wait(timeout=5)])

    def test_interrupt_stops_further_cases(self):
        failed = {'interrupted': True, 'cleanup_failed': False, 'success': False}
        with mock.patch.object(diagnostic, 'run_case', return_value=failed) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.main(['--output', str(self.root / 'output')]), 1)
        self.assertEqual(run.call_count, 1)

    def test_cleanup_failure_stops_further_cases(self):
        output = self.root / 'output'
        with mock.patch.object(diagnostic, 'run_case', return_value={'cleanup_failed': True, 'success': False}) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.main(['--output', str(output)]), 1)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(json.loads((output / 'report.json').read_text())['success'])

    def test_existing_output_and_invalid_limits_launch_nothing(self):
        with mock.patch.object(diagnostic, 'run_case') as run:
            with self.assertRaises(FileExistsError):
                diagnostic.main(['--output', str(self.root)])
            with contextlib.redirect_stderr(io.StringIO()):
                for options in (['--iterations', '0'], ['--iterations', '1001'],
                                ['--timeout', '0'], ['--timeout', '121'], ['--timeout', 'nan']):
                    with self.assertRaises(SystemExit):
                        diagnostic.main(['--output', str(self.root / 'new'), *options])
            run.assert_not_called()
        self.assertFalse((self.root / 'new').exists())

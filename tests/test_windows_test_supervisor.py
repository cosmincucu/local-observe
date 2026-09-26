"""Real owned subprocesses distinguish stock test completion from interpreter exit."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest import mock
import venv

from scripts import run_windows_tests as supervisor


class WindowsSupervisorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'tests').mkdir()
        shutil.copyfile(supervisor.ROOT / 'tests/tiers.py', self.root / 'tests/tiers.py')
        self.test_file = self.root / 'tests/test_one.py'
        self.test_file.write_text('import unittest\nclass One(unittest.TestCase):\n'
                                  ' def test_one(self): self.assertEqual(2+2,4)\n')
        self.output = self.root / 'receipt'

    def run_supervised(self, **kwargs):
        return supervisor.supervise(self.output, timeout=2, root=self.root,
                                     stack_interval=0.1, **kwargs)

    def test_real_stock_tier_pass_requires_identity_report_and_process_exit(self):
        result = self.run_supervised()
        self.assertTrue(result['success'], result)
        self.assertTrue(result['suite_clean'])
        self.assertTrue(result['work_complete'])
        self.assertTrue(result['exit_observed'])
        self.assertTrue(result['identity_matches'])
        self.assertEqual(result['returncode'], 0)
        started = supervisor.read_json(self.output / 'started.json')
        self.assertEqual(started['pid'], result['pid'])
        self.assertEqual(started['identity'], supervisor.identity())
        report = supervisor.read_json(self.output / 'tier-report.json')
        self.assertEqual(report['totals']['ran'], 1)

    def test_ordinary_failure_is_retained_without_retry(self):
        self.test_file.write_text('import unittest\nclass One(unittest.TestCase):\n'
                                  ' def test_one(self): self.fail("controlled failure")\n')
        launched = []
        def launch(*args, **kwargs):
            launched.append(1)
            return subprocess.Popen(*args, **kwargs)
        result = self.run_supervised(launcher=launch)
        self.assertFalse(result['success'])
        self.assertFalse(result['suite_clean'])
        self.assertTrue(result['work_complete'])
        self.assertEqual(result['returncode'], 1)
        self.assertEqual(launched, [1])
        self.assertEqual(supervisor.read_json(self.output / 'tier-report.json')['totals']['failures'], 1)

    @unittest.skipUnless(os.name == 'posix', 'POSIX venv symlink launch contract')
    def test_real_symlinked_posix_venv_preserves_child_prefix_and_identity(self):
        environment = self.root / 'venv'
        venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
        executable = environment / 'bin/python'
        self.assertTrue(executable.is_symlink(), 'fixture must exercise a real venv symlink')
        probe = ('import json,sys\n'
                 f'sys.path.insert(0,{str(supervisor.ROOT)!r})\n'
                 'from scripts import run_windows_tests as s\n'
                 f'result=s.supervise({str(self.output)!r},timeout=5,root={str(self.root)!r})\n'
                 'print(json.dumps(result))\n')
        completed = subprocess.run([str(executable), '-I', '-B', '-c', probe],
                                   capture_output=True, text=True, timeout=15, check=True)
        result = json.loads(completed.stdout)
        self.assertTrue(result['success'], result)
        self.assertTrue(result['identity_matches'], result)
        self.assertTrue(result['exit_observed'], result)
        started = supervisor.read_json(self.output / 'started.json')
        self.assertEqual(started['identity']['prefix'], str(environment.resolve()))
        self.assertNotEqual(started['identity']['prefix'], started['identity']['base_prefix'])

    def teardown_fixture(self):
        with self.test_file.open('a') as stream:
            stream.write('\nimport atexit,time\natexit.register(time.sleep,30)\n')

    def test_baseline_stock_report_can_pass_without_process_exit(self):
        self.teardown_fixture()
        script = self.root / 'baseline.py'
        script.write_text('import runpy,sys\n'
                          f'sys.argv=["tiers.py","--start-dir",{str(self.root / "tests")!r},'
                          f'"--json",{str(self.root / "baseline.json")!r}]\n'
                          f'runpy.run_path({str(self.root / "tests/tiers.py")!r},run_name="__main__")\n')
        command, env = supervisor.child_command(script, self.root / 'unused')
        with (self.root / 'baseline.log').open('wb') as log:
            process = subprocess.Popen(command[:4], env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 3
                while not (self.root / 'baseline.json').exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                report = supervisor.read_json(self.root / 'baseline.json')
                self.assertEqual(report['totals']['ran'], 1)
                self.assertEqual(report['totals']['failures'], 0)
                with self.assertRaises(subprocess.TimeoutExpired):
                    process.wait(timeout=0.1)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            self.assertIsNotNone(process.returncode)

    def test_completed_tier_then_teardown_block_is_failed_and_exact_child_exits(self):
        self.teardown_fixture()
        result = self.run_supervised()
        self.assertTrue(result['suite_clean'], result)
        self.assertTrue(result['work_complete'])
        self.assertFalse(result['success'])
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['kill_requested'])
        self.assertTrue(result['exit_observed'])
        self.assertTrue(result['identity_matches'])
        self.assertNotEqual(result['returncode'], 0)
        self.assertIn('Timeout', (self.output / 'stacks.log').read_text())

    def test_block_inside_test_retains_stack_and_never_claims_suite_completion(self):
        self.test_file.write_text('import unittest,time\nclass One(unittest.TestCase):\n'
                                  ' def test_one(self): time.sleep(30)\n')
        result = self.run_supervised()
        self.assertFalse(result['success'])
        self.assertFalse(result['work_complete'])
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['exit_observed'])
        self.assertIn('test_one', (self.output / 'stacks.log').read_text())

    def test_pre_marker_block_is_cleaned_without_requiring_a_child_handshake(self):
        script = self.root / 'pre_marker.py'
        script.write_text('import time\ntime.sleep(30)\n')
        result = self.run_supervised(worker_script=script)
        self.assertTrue(result['timed_out'])
        self.assertTrue(result['exit_observed'])
        self.assertTrue(result['kill_requested'])
        self.assertFalse(result['work_complete'])
        self.assertFalse(result['success'])

    def test_keyboard_interrupt_wait_cleans_the_real_owned_child(self):
        children = []
        class InterruptedWait:
            def __init__(self, *args, **kwargs):
                self.child = subprocess.Popen(*args, **kwargs)
                self.pid = self.child.pid
                self.interrupted = False
                children.append(self.child)
            def wait(self, timeout):
                if not self.interrupted:
                    self.interrupted = True
                    raise KeyboardInterrupt
                return self.child.wait(timeout=timeout)
            def poll(self):
                return self.child.poll()
            def kill(self):
                self.child.kill()
        result = self.run_supervised(launcher=InterruptedWait)
        self.assertTrue(result['interrupted'])
        self.assertTrue(result['exit_observed'])
        self.assertFalse(result['success'])
        self.assertIsNotNone(children[0].returncode)

    def test_cleanup_denial_has_no_alternative_or_later_launch(self):
        calls = []
        class Denied:
            pid = 123
            def __init__(self, *args, **kwargs):
                calls.append('launch')
            def wait(self, timeout):
                raise KeyboardInterrupt
            def poll(self):
                return None
            def kill(self):
                calls.append('kill')
                raise PermissionError('controlled denial; no actual child')
        result = self.run_supervised(launcher=Denied)
        self.assertTrue(result['cleanup_failed'])
        self.assertFalse(result['exit_observed'])
        self.assertFalse(result['logs_final'])
        self.assertFalse(result['success'])
        self.assertEqual(calls, ['launch', 'kill'])

    def test_existing_output_is_never_reused(self):
        self.output.mkdir()
        prior = self.output / 'tier-report.json'
        prior.write_text('prior receipt')
        with self.assertRaises(FileExistsError):
            self.run_supervised()
        self.assertEqual(prior.read_text(), 'prior receipt')

    def corrupting_worker(self, code):
        path = self.root / 'fixture_worker.py'
        path.write_text('import json,runpy,sys\nfrom pathlib import Path\n'
                        f'm=runpy.run_path({str(supervisor.SCRIPT)!r})\n'
                        'config=Path(sys.argv[-1]);p=config.parent\n'
                        'm["worker"](str(config))\n' + code)
        return path

    def test_stale_completion_and_changed_report_cannot_pass(self):
        for name, code in (
            ('nonce', 'q=p/"completed.json"\nr=json.loads(q.read_text());r["run_id"]="stale";q.write_text(json.dumps(r))\n'),
            ('report', '(p/"tier-report.json").write_text("{}")\n'),
        ):
            with self.subTest(name=name):
                self.output = self.root / name
                result = self.run_supervised(worker_script=self.corrupting_worker(code))
                self.assertEqual(result['returncode'], 0)
                self.assertFalse(result['success'])

    def test_disappearing_runner_still_produces_a_failed_final_receipt(self):
        worker = self.corrupting_worker('(Path(json.loads(config.read_text())["root"])/"tests/tiers.py").unlink()\n')
        result = self.run_supervised(worker_script=worker)
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['success'])
        self.assertFalse(result['input_unchanged'])
        self.assertEqual(result['input_error'], 'FileNotFoundError')
        self.assertTrue((self.output / 'supervisor-report.json').is_file())

    def test_consistently_rehashed_false_report_is_still_refused(self):
        code = ('import hashlib\nq=p/"tier-report.json"\nr=json.loads(q.read_text())\n'
                'r["tiers"][0]["collected"]=0;r["tiers"][0]["ran"]=0\n'
                'r["totals"]["collected"]=0;r["totals"]["ran"]=0\nq.write_text(json.dumps(r))\n'
                'q2=p/"completed.json";c=json.loads(q2.read_text())\n'
                'c["report_sha256"]=hashlib.sha256(q.read_bytes()).hexdigest();q2.write_text(json.dumps(c))\n')
        result = self.run_supervised(worker_script=self.corrupting_worker(code))
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['suite_clean'])
        self.assertFalse(result['success'])

    def test_fast_exit_after_large_output_is_not_a_success(self):
        script = self.corrupting_worker('import time\n'
                                       'while not (p/"go").exists(): time.sleep(0.01)\n'
                                       'print("x"*32768)\n')
        output = self.output
        class FinishDuringWait:
            def __init__(self, *args, **kwargs):
                self.child = subprocess.Popen(*args, **kwargs)
                self.pid = self.child.pid
            def wait(self, timeout):
                (output / 'go').touch()
                return self.child.wait(timeout=2)
            def poll(self):
                return self.child.poll()
            def kill(self):
                self.child.kill()
        with mock.patch.object(supervisor, 'MAX_BYTES', 16384):
            result = self.run_supervised(worker_script=script, launcher=FinishDuringWait)
        self.assertEqual(result['returncode'], 0)
        self.assertFalse(result['timed_out'])
        self.assertTrue(result['output_limit'])
        self.assertFalse(result['success'])
        self.assertGreater((self.output / 'stdout.log').stat().st_size, 16384)

    def test_launch_failure_produces_a_failed_receipt(self):
        with mock.patch.object(supervisor.subprocess, 'Popen', side_effect=OSError):
            result = self.run_supervised(launcher=supervisor.subprocess.Popen)
        self.assertFalse(result['success'])
        self.assertEqual(result['launch_or_wait_error'], 'OSError')
        self.assertTrue(result['logs_final'])

    def test_invalid_deadlines_and_selections_refuse_before_output(self):
        for timeout in (0, 3601, True, float('nan')):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                supervisor.supervise(self.output, timeout, root=self.root)
        self.assertFalse(self.output.exists())
        with self.assertRaises(ValueError):
            supervisor.supervise(self.output, start_dir='tests/compiler', only_tier='mcp', root=self.root)

    def test_cli_returns_failure_for_a_failed_supervised_run(self):
        with mock.patch.object(supervisor, 'supervise', return_value={'success': False}):
            self.assertEqual(supervisor.main(['--output', str(self.output)]), 1)


if __name__ == '__main__':
    unittest.main()

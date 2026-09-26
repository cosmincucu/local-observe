"""Rehearsal tools require an explicit installation and refuse it before host access."""
import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import conformance_recovery as recovery

SPEC = importlib.util.spec_from_file_location('external_capture_cli', SCRIPTS / 'stage_external_state.py')
capture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capture)


class RehearsalScopeTests(unittest.TestCase):
    def test_demo_scope_has_no_installation_defaults(self):
        parser = argparse.ArgumentParser()
        recovery.add_scope_arguments(parser)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            parser.parse_args([])
        self.assertEqual(raised.exception.code, 2)

    def test_invalid_scope_cannot_contact_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            daemon = base / 'daemon'
            daemon.mkdir()
            for uid, selected in ((0, daemon), (1000, base), (1000, base.parent)):
                with self.subTest(uid=uid, selected=selected), patch.object(recovery, 'command') as command, \
                        patch.object(recovery, 'rootless_docker_guard') as guard:
                    with self.assertRaises(ValueError):
                        recovery.Demo(base / 'demo.env', base=base, uid=uid, docker_root=selected)
                    guard.assert_not_called()
                    command.assert_not_called()

    def test_selected_scope_reaches_guard_before_any_demo_command(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            daemon = base / 'daemon'
            daemon.mkdir()
            with patch.object(recovery, 'rootless_docker_guard', side_effect=ValueError('guard refusal')) as guard, \
                    patch.object(recovery, 'command') as command:
                with self.assertRaisesRegex(ValueError, 'guard refusal'):
                    recovery.Demo(base / 'demo.env', base=base, uid=1000, docker_root=daemon)
                guard.assert_called_once_with(base, 1000, adopt_environment=False,
                                              user_name=None, expected_root_dir=str(daemon))
                command.assert_not_called()

    def test_external_capture_is_read_only_unless_explicitly_selected(self):
        for flags, expected in (([], False), (['--preflight'], False), (['--capture'], True)):
            argv = ['capture', '--base', '/fixture', '--uid', '1000', '--work', '/fixture/work',
                    '--output', '/fixture/work/external-state-test', *flags]
            with self.subTest(flags=flags), patch.object(sys, 'argv', argv), \
                    patch('scripts._lib.guards.rootless_docker_guard') as guard, \
                    patch('scripts._lib.run.run') as command, \
                    patch.object(capture, 'capture_external_state', return_value={'status': 'fixture'}) as perform, \
                    contextlib.redirect_stdout(io.StringIO()):
                capture.main()
                guard.assert_called_once_with(Path('/fixture'), 1000, user_name=None, adopt_environment=False)
                perform.assert_called_once_with(Path('/fixture/work/external-state-test'),
                                                Path('/fixture/work'), command, capture=expected)
                command.assert_not_called()

    def test_root_uid_and_conflicting_modes_are_refused_before_host_access(self):
        for flags in (['--uid', '0'], ['--preflight', '--capture']):
            argv = ['capture', '--base', '/fixture', '--uid', '1000', '--work', '/fixture/work',
                    '--output', '/fixture/work/external-state-test', *flags]
            with self.subTest(flags=flags), patch.object(sys, 'argv', argv), \
                    patch('scripts._lib.guards.rootless_docker_guard') as guard, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                capture.main()
            self.assertEqual(raised.exception.code, 2)
            guard.assert_not_called()

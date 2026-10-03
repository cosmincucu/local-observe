"""Tests for ``scripts/_lib``: the shared command wrapper, guard, un-strippable require, report writer.

These helpers replace per-script copies, so what is pinned here is the behaviour the copies were
not free to vary: stderr stays out of the raised message, an evidence report that states no scope
is refused, a guard cannot be stripped by ``-O``, a report is only claimed after it is read back,
and - since card scripts leftovers - a script that is shipped *by itself* into another tree still gets the whole
``_lib`` directory and can still import it. Two scripts that consume a mounted credential - the
platform stage driver and the notification sink - are pinned here too (card platform stage files).
"""
from __future__ import annotations

import ast
from email.message import Message
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
sys.path.insert(0, str(SCRIPTS))

from _lib import credentials as credentials_module
from _lib import guards as guards_module
from _lib import report as report_module
from _lib import require as require_module
from _lib import run as run_module
# scripts/ is on sys.path above, and the sink adds /app itself for its local_observe import; the
# module has no import-time side effect beyond that path line, so importing it is how these tests
# reach Handler.authorised() and main().
import notification_sink


class _SubstitutedFlags:
    """Stand-in for ``sys.flags``: overrides the named fields, delegates every other read."""

    def __init__(self, **overrides: object) -> None:
        self.__dict__['overrides'] = overrides

    def __getattr__(self, name: str) -> object:
        overrides = self.__dict__.get('overrides', {})
        if name in overrides:
            return overrides[name]
        return getattr(sys.flags, name)


def flags_with(optimize: int) -> _SubstitutedFlags:
    """A ``sys.flags`` look-alike with ``optimize`` overridden and every other field real."""
    return _SubstitutedFlags(optimize=optimize)


class LoaderContract(unittest.TestCase):
    """Scripts reach ``_lib`` with only ``scripts/`` on the path; a bare interpreter proves it."""

    def test_package_is_importable_with_only_scripts_on_path(self) -> None:
        probe = ('import _lib, _lib.guards as g, _lib.report as r, _lib.require as q, _lib.run as u,'
                 ' _lib.credentials as c;'
                 'print(all(callable(f) for f in (u.run, q.require, q.refuse_optimized, q.optimized,'
                 'r.write_report, r.write_json, g.rootless_docker_guard, c.role_credentials, c.token_for)))')
        result = subprocess.run([sys.executable, '-B', '-P', '-c', probe], capture_output=True, text=True,
                                timeout=60, env=dict(os.environ, PYTHONPATH=str(SCRIPTS)),
                                cwd=str(tempfile.gettempdir()))
        self.assertEqual(result.returncode, 0, result.stderr[-400:])
        self.assertEqual(result.stdout.strip(), 'True')

    def test_product_package_does_not_import_the_scripts_library(self) -> None:
        """``_lib`` is tooling: local_observe must not depend on it in either direction."""
        hits = [path.relative_to(ROOT).as_posix() for path in (ROOT / 'local_observe').rglob('*.py')
                if '_lib' in path.read_text(encoding='utf-8')]
        self.assertEqual(hits, [])


class RequireTests(unittest.TestCase):
    """``assert`` is what this replaces; ``python -O`` must not be able to remove the check."""

    def test_true_conditions_return_none(self) -> None:
        for condition in (True, 1, 'text', [0], {'a': 0}, object()):
            with self.subTest(condition=repr(condition)):
                self.assertIsNone(require_module.require(condition, 'must not raise'))

    def test_false_conditions_raise_valueerror_with_the_message(self) -> None:
        for condition in (False, 0, '', [], None):
            with self.subTest(condition=repr(condition)):
                with self.assertRaisesRegex(ValueError, 'guard text'):
                    require_module.require(condition, 'guard text')

    def test_optimized_reads_sys_flags_optimize_at_call_time(self) -> None:
        for value, expected in ((0, False), (1, True), (2, True)):
            with self.subTest(optimize=value), mock.patch.object(sys, 'flags', flags_with(value)):
                self.assertEqual(require_module.optimized(), expected)

    def test_refuse_optimized_raises_under_dash_o_and_is_silent_otherwise(self) -> None:
        with mock.patch.object(sys, 'flags', flags_with(1)):
            with self.assertRaisesRegex(ValueError, 'optimized'):
                require_module.refuse_optimized()
        with mock.patch.object(sys, 'flags', flags_with(0)):
            self.assertIsNone(require_module.refuse_optimized())


class RunTests(unittest.TestCase):
    """The wrapper is bounded, list-argv only, and its failure message carries no stderr."""

    @staticmethod
    def child(exit_code: int, stderr: str = '') -> list[str]:
        write = f'sys.stderr.write({stderr!r});' if stderr else ''
        return [sys.executable, '-B', '-c', f'import sys;{write}sys.stdout.write("out\\n");sys.exit({exit_code})']

    def test_returns_stdout_stripped_for_both_call_forms(self) -> None:
        self.assertEqual(run_module.run(self.child(0), timeout=60), 'out')
        self.assertEqual(run_module.run(*self.child(0), timeout=60), 'out')

    def test_empty_argv_a_missing_program_and_non_string_parts_are_refused(self) -> None:
        for argv in ([], [''], ['echo', Path('/tmp/x')], [b'echo'], [None]):
            with self.subTest(argv=repr(argv)):
                with self.assertRaises(ValueError):
                    run_module.run(*argv, timeout=5)

    def test_an_empty_argument_is_allowed_because_commands_pass_them(self) -> None:
        # ssh-keygen -N '' is a legitimate empty argv element; only the program must be named.
        self.assertEqual(run_module.run(self.child(0, 'quiet'), timeout=60), 'out')

    def test_failure_names_the_program_and_never_repeats_stderr(self) -> None:
        secret = 'LO_TOKEN=super-private-value'
        with self.assertRaises(RuntimeError) as caught:
            run_module.run(self.child(3, secret), timeout=60)
        message = str(caught.exception)
        self.assertNotIn('super-private', message, 'stderr leaked into a shared exception string')
        self.assertIn(sys.executable, message)
        self.assertIn('exit 3', message)

    def test_stderr_included_on_request_is_scrubbed_of_named_secrets(self) -> None:
        secret = 'LO_TOKEN=super-private-value'
        with self.assertRaises(RuntimeError) as caught:
            run_module.run(self.child(4, secret), timeout=60, redact_stderr=False, scrub=[secret])
        message = str(caught.exception)
        self.assertIn('[REDACTED]', message)
        self.assertNotIn('super-private', message)

    def test_stderr_tail_is_bounded_when_not_redacted(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            run_module.run(self.child(5, 'q' * (run_module.STDERR_TAIL + 500)), timeout=60, redact_stderr=False)
        # Count only stderr; the interpreter path can also contain the chosen character.
        detail = str(caught.exception).split('\n', 1)[1]
        self.assertEqual(detail, 'q' * run_module.STDERR_TAIL)

    def test_stdin_is_written_and_the_timeout_bounds_the_child(self) -> None:
        echo = [sys.executable, '-B', '-c', 'import sys; sys.stdout.write(sys.stdin.read().strip())']
        self.assertEqual(run_module.run(echo, timeout=60, data='piped\n'), 'piped')
        with self.assertRaises(subprocess.TimeoutExpired):
            run_module.run([sys.executable, '-B', '-c', 'import time; time.sleep(30)'], timeout=1)

    def test_env_override_applies_to_the_child_only(self) -> None:
        read = [sys.executable, '-B', '-c', 'import os; print(os.environ.get("LO_TEST_VAR","unset"))']
        self.assertEqual(run_module.run(read, timeout=60, env=dict(os.environ, LO_TEST_VAR='set')), 'set')
        self.assertEqual(run_module.run(read, timeout=60), 'unset')
        self.assertNotIn('LO_TEST_VAR', os.environ)


class ReportTests(unittest.TestCase):
    """A report is evidence only if the bytes on disk are the bytes intended, and it says its scope."""

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp())

    def test_refuses_a_report_without_a_useful_scope(self) -> None:
        for body in ({'status': 'pass'}, {'status': 'pass', 'checks': {'a': 'pass'}},
                     {'status': 'pass', 'scope': ''}, {'status': 'pass', 'scope': '   '},
                     {'status': 'pass', 'scope': None}, {'status': 'pass', 'limitations': []},
                     {'status': 'pass', 'limitations': ['burst test', '']}):
            with self.subTest(body=sorted(map(str, body))):
                with self.assertRaisesRegex(ValueError, 'unscoped'):
                    report_module.write_report(self.directory / 'report.json', body)
        self.assertFalse(list(self.directory.iterdir()), 'a refused report left a file behind')

    def test_accepts_a_non_empty_scope_or_list_of_limitations(self) -> None:
        for key, value in (('scope', 'staging platform API only'), ('limitations', ['burst test only'])):
            path = self.directory / (key + '.json')
            with self.subTest(key=key):
                self.assertEqual(report_module.write_report(path, {'status': 'pass', key: value}), path)
                self.assertEqual(json.loads(path.read_text())['status'], 'pass')

    def test_refuses_a_non_mapping_report(self) -> None:
        for body in ([{'status': 'pass'}], 'pass', 7, None):
            with self.subTest(body=type(body).__name__):
                with self.assertRaisesRegex(ValueError, 'mapping'):
                    report_module.write_report(self.directory / 'list.json', body)

    def test_second_write_refuses_to_clobber_a_finished_report(self) -> None:
        path = self.directory / 'report.json'
        report_module.write_report(path, {'scope': 'first', 'status': 'pass'})
        with self.assertRaises(FileExistsError):
            report_module.write_report(path, {'scope': 'second', 'status': 'pass'})
        self.assertEqual(json.loads(path.read_text())['scope'], 'first')

    def test_replace_checkpoints_atomically_and_leaves_no_temporary(self) -> None:
        path = self.directory / 'report.json'
        report_module.write_report(path, {'scope': 'first', 'status': 'running'})
        for round_number in range(3):
            report_module.write_report(path, {'scope': 'first', 'status': 'pass', 'round': round_number},
                                       replace=True)
            self.assertEqual(json.loads(path.read_text())['round'], round_number)
        self.assertFalse(list(self.directory.glob('*.tmp-*')))

    def test_write_json_is_the_unscoped_variant_for_non_report_artefacts(self) -> None:
        path = self.directory / 'plan.json'
        report_module.write_json(path, {'port': 1, 'files': ['a']})
        self.assertEqual(json.loads(path.read_text()), {'port': 1, 'files': ['a']})
        with self.assertRaises(FileExistsError):
            report_module.write_json(path, {'port': 2})
        report_module.write_json(path, {'port': 2}, replace=True)
        self.assertEqual(json.loads(path.read_text())['port'], 2)

    def test_a_file_that_does_not_say_what_was_written_is_not_claimed(self) -> None:
        # The guarantee is the read-back: whatever lands on disk must parse to the intended value.
        path = self.directory / 'report.json'

        def tampered(*args, **kwargs):
            return json.dumps({'scope': 'tampered-with', 'status': 'pass'})

        with mock.patch.object(Path, 'read_text', tampered):
            with self.assertRaisesRegex(ValueError, 'readback'):
                report_module.write_report(path, {'scope': 's', 'status': 'pass'})
        self.assertEqual(json.loads(path.open(encoding='utf-8').read())['status'], 'pass')

    @unittest.skipUnless(os.name == 'posix', 'the private-file mode is what is being asserted')
    def test_reports_are_never_world_readable(self) -> None:
        written = [report_module.write_report(self.directory / 'a.json', {'scope': 's', 'token': 'x'}),
                   report_module.write_json(self.directory / 'b.json', {'token': 'x'}),
                   report_module.write_report(self.directory / 'c.json', {'scope': 's'}, replace=True)]
        for path in written:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path.name)


class GuardTests(unittest.TestCase):
    """The preamble: only the rootless staging daemon, only as the staging account, never stripped."""

    def setUp(self) -> None:
        self.base = Path('/srv/stage/scratch')

    def test_refuses_a_non_linux_host_before_touching_docker(self) -> None:
        with mock.patch.object(sys, 'platform', 'win32'):
            with self.assertRaisesRegex(ValueError, 'Linux'):
                guards_module.rootless_docker_guard(self.base, 1001)

    def test_refuses_optimized_python_first(self) -> None:
        with mock.patch.object(sys, 'flags', flags_with(1)), mock.patch.object(sys, 'platform', 'linux'):
            with self.assertRaisesRegex(ValueError, 'optimized'):
                guards_module.rootless_docker_guard(self.base, 1001)

    @unittest.skipUnless(os.name == 'posix', 'the guard checks POSIX account and socket state')
    def test_refuses_wrong_uid_and_a_writable_rootful_socket(self) -> None:
        cases = [('wrong uid', mock.patch.object(os, 'getuid', return_value=0)),
                 ('rootful socket writable', mock.patch.object(os, 'access', return_value=True))]
        for name, patcher in cases:
            with self.subTest(case=name), patcher:
                with self.assertRaises(ValueError):
                    guards_module.rootless_docker_guard(self.base, 1001)

    @unittest.skipUnless(os.name == 'posix', 'the guard checks POSIX account and socket state')
    def test_refuses_a_daemon_whose_data_root_is_elsewhere(self) -> None:
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(os, 'getuid', return_value=1001), \
                mock.patch.object(os, 'access', return_value=False), \
                mock.patch('pwd.getpwuid', return_value=types.SimpleNamespace(pw_name='lo-stage')), \
                mock.patch.object(guards_module, 'run', return_value='/var/lib/docker') as info:
            with self.assertRaisesRegex(ValueError, 'scratch'):
                guards_module.rootless_docker_guard(self.base, 1001)
            self.assertEqual(info.call_args.args, ('docker', 'info', '--format', '{{.DockerRootDir}}'))

    @unittest.skipUnless(os.name == 'posix', 'the guard adopts POSIX environment and account state')
    def test_adopts_the_socket_clears_the_context_and_returns_the_data_root(self) -> None:
        root_dir = str(self.base) + '/home/.local/share/docker'
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(os, 'getuid', return_value=1001), \
                mock.patch.object(os, 'access', return_value=False), \
                mock.patch('pwd.getpwuid', return_value=types.SimpleNamespace(pw_name='lo-stage')), \
                mock.patch.object(guards_module, 'run', return_value=root_dir), \
                mock.patch.dict(os.environ, {'DOCKER_CONTEXT': 'leftover'}, clear=True):
            self.assertEqual(guards_module.rootless_docker_guard(self.base, 1001, set_runtime_dir=True),
                             root_dir)
            self.assertEqual(os.environ['DOCKER_HOST'], 'unix:///run/user/1001/docker.sock')
            self.assertEqual(os.environ['XDG_RUNTIME_DIR'], '/run/user/1001')
            self.assertNotIn('DOCKER_CONTEXT', os.environ)

    @unittest.skipUnless(os.name == 'posix', 'the strict form reads POSIX DOCKER_HOST')
    def test_strict_form_requires_the_socket_to_be_set_already(self) -> None:
        root_dir = str(self.base) + '/home/.local/share/docker'
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(os, 'getuid', return_value=1001), \
                mock.patch.object(os, 'access', return_value=False), \
                mock.patch('pwd.getpwuid', return_value=types.SimpleNamespace(pw_name='lo-stage')), \
                mock.patch.object(guards_module, 'run', return_value=root_dir):
            with mock.patch.dict(os.environ, {}, clear=True):
                with self.assertRaisesRegex(ValueError, 'DOCKER_HOST'):
                    guards_module.rootless_docker_guard(self.base, 1001, adopt_environment=False)
            with mock.patch.dict(os.environ, {'DOCKER_HOST': 'unix:///run/user/1001/docker.sock'}, clear=True):
                self.assertEqual(guards_module.rootless_docker_guard(
                    self.base, 1001, expected_root_dir=root_dir, user_name=None), root_dir)
                with self.assertRaisesRegex(ValueError, 'data root'):
                    guards_module.rootless_docker_guard(self.base, 1001, expected_root_dir='/nope',
                                                        user_name=None)

    @unittest.skipUnless(os.name == 'posix', 'the guard resolves the account name through POSIX pwd')
    def test_refuses_an_account_name_that_is_not_the_staging_one(self) -> None:
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(os, 'getuid', return_value=1001), \
                mock.patch.object(os, 'access', return_value=False), \
                mock.patch('pwd.getpwuid', return_value=types.SimpleNamespace(pw_name='root')):
            with self.assertRaisesRegex(ValueError, 'account'):
                guards_module.rootless_docker_guard(self.base, 1001)

    @unittest.skipUnless(os.name == 'posix', 'the guard resolves the account name through POSIX pwd')
    def test_a_uid_without_a_passwd_entry_is_refused_not_crashed(self) -> None:
        # CI containers and deleted accounts have a uid that pwd cannot name. That is "not the
        # staging account", a ValueError like every other refusal, not a KeyError from the guard.
        with mock.patch.object(sys, 'platform', 'linux'), \
                mock.patch.object(os, 'getuid', return_value=1001), \
                mock.patch('pwd.getpwuid', side_effect=KeyError('getpwuid(): uid not found: 1001')):
            with self.assertRaisesRegex(ValueError, 'account'):
                guards_module.rootless_docker_guard(self.base, 1001)


class FakeDocker:
    """Stand-in for :func:`_lib.run.run` answering only the reads :func:`role_credentials` makes.

    Answers are the real shapes: ``docker inspect --format '{{json .X}}'`` on one container prints
    *that field's* JSON - an array of ``K=V`` strings for ``.Config.Env``, an array of mount objects
    for ``.Mounts`` - and the two ``docker exec`` reads are told apart by the code they pass.
    """

    def __init__(self, env: list[str], mounts: list[dict], shape: str = 'file', body: str = '') -> None:
        self.env, self.mounts, self.shape, self.body = env, mounts, shape, body
        self.calls: list[list[str]] = []

    def __call__(self, *args: str, **kwargs: object) -> str:
        argv = list(args)
        self.calls.append(argv)
        if '--format' in argv:
            template = argv[argv.index('--format') + 1]
            if '.Config.Env' in template:
                return json.dumps(self.env)
            if '.Mounts' in template:
                return json.dumps(self.mounts)
        if argv[:2] == ['docker', 'exec']:
            # The shape probe is the call whose script begins with the os/sys import; the other
            # one streams the file. Coupling to the script text is deliberate: it pins which is.
            return self.shape if argv[-2].startswith('import os,sys') else self.body
        raise AssertionError('unexpected command: ' + repr(argv))

    def commands(self) -> list[list[str]]:
        """Every command this stand-in was asked to run, in order."""
        return self.calls


class CredentialTests(unittest.TestCase):
    """scripts leftovers: the role list is read from the mount the container actually has, never from its env."""

    ROWS = [{'identity': 'stage-reader', 'role': 'reader', 'token': 'synthetic-reader-token'},
            {'identity': 'stage-detector', 'role': 'producer', 'token': 'synthetic-producer-token'}]
    MOUNT = credentials_module.CREDENTIALS_MOUNT

    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp())

    def env(self, *extra: str) -> list[str]:
        return ['PATH=/usr/local/bin:/usr/bin:/bin', 'LO_PLATFORM_CREDENTIALS=' + self.MOUNT, *extra]

    def mounts(self, destination: str = MOUNT) -> list[dict]:
        return [{'Type': 'bind', 'Source': '/srv/stage/work/x/private/platform-credentials',
                 'Destination': destination}]

    def serve(self, docker: FakeDocker) -> None:
        mock.patch.object(credentials_module, 'run', docker).start()
        self.addCleanup(mock.patch.stopall)

    def test_reads_the_role_list_from_inside_the_container(self) -> None:
        docker = FakeDocker(self.env(), self.mounts(), body=json.dumps(self.ROWS))
        self.serve(docker)
        self.assertEqual(credentials_module.role_credentials('stage-platform-1'), self.ROWS)
        self.assertTrue(all(call[0] == 'docker' for call in docker.commands()),
                        'a host-side read was attempted when the container was available')

    def test_the_format_templates_print_arrays_not_inspect_objects(self) -> None:
        # docker inspect --format '{{json .Config.Env}}' prints the array itself. Indexing [0] -
        # what the copy this helper replaced did - turns the env rows into one string and the mount
        # rows into that string's characters, so the call died before it read anything.
        docker = FakeDocker(self.env(), self.mounts(), body=json.dumps(self.ROWS))
        self.serve(docker)
        self.assertEqual(credentials_module.role_credentials('stage-platform-1'), self.ROWS)
        templates = [call[call.index('--format') + 1] for call in docker.commands() if '--format' in call]
        self.assertEqual(templates, ['{{json .Config.Env}}', '{{json .Mounts}}'])

    def test_refuses_a_container_still_carrying_the_environment_form(self) -> None:
        docker = FakeDocker(self.env('LO_PLATFORM_CREDENTIALS_JSON=[]'), self.mounts())
        self.serve(docker)
        with self.assertRaisesRegex(ValueError, 'redeploy it first'):
            credentials_module.role_credentials('stage-platform-1')
        self.assertEqual(len(docker.commands()), 1, 'the refusal should not go on reading credentials')

    def test_refuses_a_container_that_does_not_name_the_mount(self) -> None:
        docker = FakeDocker(['PATH=/usr/bin'], self.mounts())
        self.serve(docker)
        with self.assertRaisesRegex(ValueError, 'does not read role credentials'):
            credentials_module.role_credentials('stage-platform-1')

    def test_refuses_a_container_that_mounts_nothing_at_that_path(self) -> None:
        docker = FakeDocker(self.env(), self.mounts('/run/secrets/somewhere-else'))
        self.serve(docker)
        with self.assertRaisesRegex(ValueError, 'mounts nothing at'):
            credentials_module.role_credentials('stage-platform-1')

    def test_refuses_anything_in_the_container_that_is_not_a_regular_file(self) -> None:
        for shape in ('symlink', 'absent'):
            docker = FakeDocker(self.env(), self.mounts(), shape=shape, body=json.dumps(self.ROWS))
            self.serve(docker)
            with self.subTest(shape=shape), self.assertRaisesRegex(ValueError, 'not a regular file'):
                credentials_module.role_credentials('stage-platform-1')

    def test_refuses_rows_that_are_not_complete_identity_role_token(self) -> None:
        for body in (json.dumps([]), json.dumps([{'identity': 'x', 'role': 'reader'}]),
                     json.dumps([{'identity': 'x', 'role': 'reader', 'token': ''}]),
                     json.dumps({'identity': 'x'})):
            docker = FakeDocker(self.env(), self.mounts(), body=body)
            self.serve(docker)
            with self.subTest(body=body[:34]), self.assertRaisesRegex(ValueError, 'identity/role/token'):
                credentials_module.role_credentials('stage-platform-1')

    def test_a_file_that_is_not_json_names_the_file_it_could_not_read(self) -> None:
        docker = FakeDocker(self.env(), self.mounts(), body='not json at all')
        self.serve(docker)
        with self.assertRaisesRegex(ValueError, 'stage-platform-1:/run/secrets'):
            credentials_module.role_credentials('stage-platform-1')

    def test_an_explicit_host_path_is_read_when_the_caller_names_one(self) -> None:
        file = self.directory / 'platform-credentials.json'
        file.write_text(json.dumps(self.ROWS), encoding='utf-8')
        docker = FakeDocker(self.env(), [])
        self.serve(docker)
        self.assertEqual(credentials_module.role_credentials('stage-platform-1', host_path=file), self.ROWS)
        self.assertFalse([call for call in docker.commands() if call[:2] == ['docker', 'exec']],
                         'the container was read even though the caller named a host file')

    @unittest.skipIf(os.name != 'posix', 'a symlink to a regular file is the case being refused')
    def test_a_symlinked_host_path_is_refused(self) -> None:
        real = self.directory / 'real.json'
        real.write_text(json.dumps(self.ROWS), encoding='utf-8')
        link = self.directory / 'platform-credentials.json'
        link.symlink_to(real)
        self.serve(FakeDocker(self.env(), []))
        with self.assertRaisesRegex(ValueError, 'not a regular file'):
            credentials_module.role_credentials('stage-platform-1', host_path=link)

    def test_token_for_selects_by_identity_or_role_and_refuses_ambiguity(self) -> None:
        self.assertEqual(credentials_module.token_for(self.ROWS, role='reader'), 'synthetic-reader-token')
        self.assertEqual(credentials_module.token_for(self.ROWS, identity='stage-detector'),
                         'synthetic-producer-token')
        for kwargs in ({'identity': 'nobody'}, {'role': 'human'},
                       {'identity': 'stage-reader', 'role': 'producer'}):
            with self.subTest(selectors=kwargs), self.assertRaisesRegex(ValueError, 'Exactly one'):
                credentials_module.token_for(self.ROWS, **kwargs)

    def test_token_for_refuses_to_choose_between_two_matching_rows(self) -> None:
        rows = self.ROWS + [{'identity': 'another-reader', 'role': 'reader', 'token': 'a-second-one'}]
        with self.assertRaisesRegex(ValueError, 'found 2'):
            credentials_module.token_for(rows, role='reader')

    def test_token_for_refuses_to_select_without_a_selector(self) -> None:
        with self.assertRaisesRegex(ValueError, 'needs an identity or a role'):
            credentials_module.token_for(self.ROWS)









class NotificationSinkTokenFileTests(unittest.TestCase):
    """platform stage files: the sink authenticates against one token read once, from ``LO_NOTIFY_TOKEN_FILE``."""

    TOKEN = 'synthetic-sink-bearer-token-aaaaaaaaaaaaaaaa'

    def authorised(self, header: str | None, token: str) -> bool:
        """Run :meth:`notification_sink.Handler.authorised` on a stand-in carrying one header."""
        headers = Message()
        if header is not None:
            headers['Authorization'] = header
        return notification_sink.Handler.authorised(types.SimpleNamespace(headers=headers, token=token))

    def test_the_bearer_read_from_a_token_file_is_accepted_and_a_wrong_one_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / 'notify-token'
            path.write_bytes(self.TOKEN.encode('utf-8'))  # exactly the bytes: no trailing newline
            with mock.patch.dict(os.environ, {'LO_NOTIFY_TOKEN_FILE': str(path)}, clear=True):
                loaded = notification_sink.read_credential('LO_NOTIFY_TOKEN')  # what main() does, once
        self.assertEqual(loaded, self.TOKEN)
        self.assertTrue(self.authorised('Bearer ' + loaded, loaded))
        self.assertFalse(self.authorised('Bearer ' + loaded + 'x', loaded), 'a near-miss bearer token was accepted')
        self.assertFalse(self.authorised(loaded, loaded), 'the bare token with no scheme was accepted')
        self.assertFalse(self.authorised('Bearer ' + loaded, ''), 'a sink that loaded no credential served a request')
        # The guard is what makes an unloaded credential refuse *this* request too: compare_digest
        # would otherwise match the empty token against the 'Bearer ' prefix it builds itself.
        self.assertFalse(self.authorised('Bearer ', ''), 'an empty bearer value authenticates to an unloaded sink')

    def test_a_missing_token_file_stops_the_sink_before_it_opens_a_database_or_a_port(self) -> None:
        """Fail at boot, not per request: the alternative is a sink up and answering 401 forever."""
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch.dict(os.environ, {'LO_NOTIFY_TOKEN_FILE': str(Path(raw) / 'absent')}, clear=True), \
                    mock.patch.object(notification_sink, 'sqlite3') as database, \
                    mock.patch.object(notification_sink, 'HTTPServer') as server:
                with self.assertRaises(OSError):
                    notification_sink.main()
        database.connect.assert_not_called()
        server.assert_not_called()


if __name__ == '__main__':
    unittest.main()

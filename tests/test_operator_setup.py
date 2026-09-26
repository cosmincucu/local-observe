"""Generated-only first-install setup checks; no services or real credentials."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
import warnings
from unittest.mock import patch

import yaml

from local_observe.deployment import operator_setup as setup
from local_observe.platform.api import validate_credentials
from local_observe.platform.operator_account import verify_password


URLS = {name: 'https://' + name + '.example.test' for name in
        ('home', 'operations', 'overview', 'jobs', 'signoz', 'healthchecks')}
HASH = '$2a$14$' + 'a' * 53


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'new'

    def generate(self, password='test-only: # "quotes" \\ $ value', **kw):
        with patch.object(setup.shutil, 'which', return_value='/fake/caddy'), patch.object(
                setup.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=HASH.encode())):
            return setup.generate(self.output, 'alice', password, URLS, caddy_binary='caddy',
                                  windows_acl_protected=True, **kw)

    def test_independent_credentials_valid_roles_and_exact_password(self):
        password = 'test-only: # "quotes" \\ $ value'
        result = self.generate(password)
        account = json.loads((self.output / 'operator-account.json').read_text())
        self.assertTrue(verify_password(account, 'alice', password))
        dagu = yaml.safe_load((self.output / 'dagu-config.yaml').read_text())
        self.assertEqual(dagu['auth']['basic'], {'username': 'alice', 'password': password})
        roles = json.loads((self.output / 'platform-credentials.json').read_text())
        validate_credentials(roles)
        tokens = [row['token'] for row in roles]
        tokens += [(self.output / name).read_text() for name in
                   ('ingest-token', 'store-token', 'inventory-token', 'healthchecks-secret')]
        self.assertEqual(len(tokens), len(set(tokens)))
        self.assertNotIn(password, tokens)
        self.assertEqual(account['identity'], next(row['identity'] for row in roles if row['role'] == 'human'))
        summary = next(row['token'] for row in roles if row['role'] == 'summary')
        self.assertEqual((self.output / 'homepage-overview-token').read_text(), summary)
        self.assertEqual(result['main_page'], URLS['home'])
        for name in ('ACCESS.md', 'access.json', 'homepage-links.yaml', 'credential-paths.json'):
            text = (self.output / name).read_text()
            for secret in [password, HASH, account['password_hash'], *tokens]:
                self.assertNotIn(secret, text)
        self.assertEqual(result['components']['signoz']['status'], 'pending-native-registration')
        self.assertEqual(result['components']['healthchecks']['status'], 'pending-native-registration')
        paths = json.loads((self.output / 'credential-paths.json').read_text())
        self.assertEqual(paths['LO_OPERATOR_ACCOUNT_FILE'], '/config/operator-account.json')
        self.assertEqual(paths['LO_DAGU_USERNAME'], 'alice')
        self.assertEqual(len(yaml.safe_load((self.output / 'homepage-links.yaml').read_text())[0]['Services']), 6)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
            self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in self.output.iterdir()))

    def test_existing_directory_refused_unchanged(self):
        self.output.mkdir()
        keep = self.output / 'existing'
        keep.write_bytes(b'owned')
        with self.assertRaises(setup.SetupError):
            self.generate()
        self.assertEqual(list(self.output.iterdir()), [keep])
        self.assertEqual(keep.read_bytes(), b'owned')

    def test_caddy_stdin_only_and_no_inherited_secret_argument(self):
        password = 'test-only-pw'
        with patch.object(setup.shutil, 'which', return_value='/fake/caddy'), patch.object(
                setup.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=HASH.encode())) as run:
            self.assertEqual(setup.homepage_hash(password, 'caddy'), HASH)
        args, kwargs = run.call_args
        self.assertNotIn(password, args[0])
        self.assertEqual(kwargs['input'], password.encode() + b'\n')
        self.assertEqual(args[0], ['/fake/caddy', 'hash-password', '--algorithm', 'bcrypt'])
        self.assertNotIn('env', kwargs)

    def test_missing_caddy_and_incompatible_passwords_refused_before_writes(self):
        with patch.object(setup.shutil, 'which', return_value=None), self.assertRaises(setup.SetupError):
            setup.generate(self.output, 'alice', 'pw', URLS, windows_acl_protected=True)
        self.assertFalse(self.output.exists())
        for password in (' leading', 'trailing ', 'a' * 73, 'é' * 37):
            with self.subTest(password_length=len(password)), self.assertRaises(setup.SetupError):
                self.generate(password)
            self.assertFalse(self.output.exists())

    def test_skipping_homepage_leaves_explicit_pending_status(self):
        result = self.generate(skip_homepage_auth=True)
        self.assertEqual(result['components']['home']['status'], 'pending-authentication')
        self.assertEqual(result['components']['overview']['status'], 'pending-authentication')
        self.assertFalse((self.output / 'homepage-auth.caddy').exists())

    def test_bad_urls_and_username_refused(self):
        for url in ('http://portal.example', 'https://a:pw@portal.example', 'https://portal.example?token=pw',
                    'https://portal.example/#pw', 'https://portal.example:invalid', 'https://portal.example/|broken',
                    'https://portal.example/`broken', 'https://portal.example/<tag>'):
            with self.subTest(url=url), self.assertRaises(setup.SetupError):
                setup.checked_url(url)
        with self.assertRaises(setup.SetupError):
            setup.generate(self.output, 'bad name', 'pw', URLS, skip_homepage_auth=True,
                           windows_acl_protected=True)
        self.assertFalse(self.output.exists())

    def test_password_file_exact_bounded_and_private(self):
        path = self.root / 'input'
        path.write_bytes('value é'.encode())
        path.chmod(0o600)
        self.assertEqual(setup.private_password(path, True), 'value é')
        for data in (b'pw\n', b'pw\r', b'pw\0', b'x' * 1025, b'', b'\xff'):
            path.write_bytes(data)
            with self.assertRaises(setup.SetupError):
                setup.private_password(path, True)
        if os.name == 'posix':
            path.write_bytes(b'pw')
            path.chmod(0o644)
            with self.assertRaises(setup.SetupError):
                setup.private_password(path)
            fifo = self.root / 'fifo'
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(setup.SetupError):
                setup.private_password(fifo)

    def test_cli_password_prompts_twice_and_never_prints_secrets(self):
        argv = ['--output', str(self.output), '--username', 'alice', '--skip-homepage-auth',
                '--windows-acl-protected']
        for name, url in URLS.items():
            argv.extend(['--' + name + '-url', url])
        output = io.StringIO()
        with (patch.object(setup.getpass, 'getpass', side_effect=['fixture-pw', 'fixture-pw']) as prompt,
              contextlib.redirect_stdout(output), contextlib.redirect_stderr(output)):
            code = setup.main(argv)
        self.assertEqual(code, 0)
        self.assertEqual(prompt.call_count, 2)
        self.assertNotIn('fixture-pw', output.getvalue())

    def test_failure_keeps_partial_files_and_sanitizes_message(self):
        with patch.object(setup.os, 'fsync', side_effect=OSError('SECRET-OUTPUT')), self.assertRaises(
                setup.SetupError) as raised:
            self.generate()
        self.assertNotIn('SECRET-OUTPUT', str(raised.exception))
        self.assertTrue(self.output.is_dir())
        self.assertTrue(any(self.output.iterdir()))

    def test_insecure_prompt_refused_without_echo_or_files(self):
        argv = ['--output', str(self.output), '--username', 'alice', '--skip-homepage-auth']
        for name, url in URLS.items():
            argv.extend(['--' + name + '-url', url])
        def unsafe_prompt(prompt):
            warnings.warn('Cannot control echo', setup.getpass.GetPassWarning, stacklevel=2)
            raise AssertionError('must not reach echo fallback')
        output = io.StringIO()
        with (patch.object(setup.getpass, 'getpass', side_effect=unsafe_prompt),
              contextlib.redirect_stderr(output)):
            self.assertEqual(setup.main(argv), 2)
        self.assertIn('--password-file', output.getvalue())
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()

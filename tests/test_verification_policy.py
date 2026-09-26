"""Smoke tests for the verification-policy loader , written against its contract alone.

What is covered is the loader's own surface: what it refuses before opening anything, what it refuses
after opening, the fixed and redacted shape of every failure, and the credential crosscheck. Document
*schema* validation belongs to `tests/test_verification_records.py`. No network, no live state and no
service enablement is claimed or tested here.
"""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

from local_observe.platform.state import Store
from local_observe.platform.verification_policy import (CONFIG_ENVIRONMENT, PolicyLoadError,
                                                       load_policy, policy_from_environment)
from local_observe.platform.verification_records import MAX_POLICY_BYTES, VerificationPolicy

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = json.loads((ROOT / 'examples/platform/verification-policy.json').read_text())
VERIFIER = DOCUMENT['verifiers'][0]
CREDENTIALS = [{'identity': VERIFIER, 'role': 'producer', 'token': 'x' * 24}]


class Watch(list):
    """A credential list that reports whether anything looked inside it."""

    looked = 0

    def __iter__(self):
        self.looked += 1
        return list.__iter__(self)


class NoToken:
    """A token value whose representation must never be inspected."""

    def __str__(self):
        raise AssertionError('the loader inspected a token value')

    __repr__ = __str__


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, text, name='policy.json') -> Path:
        path = self.root / name
        path.write_bytes(text if isinstance(text, bytes) else str(text).encode())
        return path

    def policy(self, **top) -> str:
        return json.dumps({**DOCUMENT, **top}, separators=(',', ':'))

    def sentence(self, thunk, *values) -> str:
        """Assert one fixed, short, redacted refusal that chains nothing, and return its wording."""
        with self.assertRaises(PolicyLoadError) as caught:
            thunk()
        text = str(caught.exception)
        self.assertTrue(text and '\n' not in text and len(text) < 200)
        self.assertIsNone(caught.exception.__cause__)
        self.assertFalse(any(char in text for char in '{}"\''))
        for value in values:
            self.assertNotIn(str(value), text)
        return text

    def test_an_absent_variable_is_off_without_a_file_or_a_credential_read(self):
        seen = Watch(CREDENTIALS)
        self.assertIsNone(policy_from_environment(seen, environ={}))
        self.assertEqual(seen.looked, 0)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_the_environment_is_read_at_call_time_and_defaults_to_this_process(self):
        environ = {}
        self.assertIsNone(policy_from_environment(CREDENTIALS, environ=environ))
        path = str(self.file(self.policy()))
        environ[CONFIG_ENVIRONMENT] = path
        self.assertIsInstance(policy_from_environment(CREDENTIALS, environ=environ),
                              VerificationPolicy)
        with mock.patch.dict(os.environ, {CONFIG_ENVIRONMENT: path}):
            self.assertTrue(policy_from_environment(CREDENTIALS))
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(policy_from_environment(CREDENTIALS))

    def test_a_named_but_unusable_path_refuses_rather_than_turning_the_policy_off(self):
        environ = {}
        for value in ('', '   ', '\t\n', None, True, 1, [], {}, Path(''), 'policy'):
            environ[CONFIG_ENVIRONMENT] = value
            self.sentence(lambda: policy_from_environment(CREDENTIALS, environ=environ))
        self.sentence(lambda: policy_from_environment(CREDENTIALS, environ='not-an-environment'))

    def test_the_named_file_becomes_the_policy_a_store_accepts(self):
        policy = load_policy(self.file(self.policy()), CREDENTIALS)
        self.assertIs(type(policy), VerificationPolicy)
        self.assertEqual(policy.verifiers, (VERIFIER,))
        self.assertEqual(policy.mappings[0], VerificationPolicy(DOCUMENT).mappings[0])
        self.assertTrue(Store(self.root / 'mounted.db', verification_policy=policy).path.exists())

    def test_a_directory_an_absent_path_or_a_fifo_is_refused_without_hanging(self):
        self.sentence(lambda: load_policy(self.root, CREDENTIALS))
        self.sentence(lambda: load_policy(self.root / 'absent.json', CREDENTIALS))
        if not hasattr(os, 'mkfifo'):  # pragma: no cover - Windows has no FIFOs
            return
        path = self.root / 'policy.fifo'
        os.mkfifo(path)
        self.assertTrue(stat.S_ISFIFO(path.stat().st_mode))
        self.sentence(lambda: load_policy(path, CREDENTIALS))

    def test_the_byte_bound_counts_whitespace_and_not_just_nodes(self):
        padded = self.file(' ' * (MAX_POLICY_BYTES + 1) + self.policy())
        self.sentence(lambda: load_policy(padded, CREDENTIALS))
        self.assertTrue(load_policy(self.file(' ' * 64 + self.policy()), CREDENTIALS))

    def test_a_document_that_is_not_one_json_object_is_refused(self):
        base = self.policy()
        for text in ('', '[]', 'null', '1', '"policy"', base + ' {}', base + ' //note',
                     '{"schema_version": 1,}', base.replace('"', "'")):
            self.sentence(lambda text=text: load_policy(self.file(text), CREDENTIALS))

    def test_duplicate_keys_are_refused_at_every_depth(self):
        nested = self.policy().replace('"artifact_sha256"', '"rule_id":"other","artifact_sha256"', 1)
        self.sentence(lambda: load_policy(self.file(nested), CREDENTIALS))
        top = self.policy().replace('"schema_version"', '"verifiers":[],"schema_version"', 1)
        self.sentence(lambda: load_policy(self.file(top), CREDENTIALS))

    def test_numbers_json_cannot_express_are_refused(self):
        for literal in ('NaN', 'Infinity', '-Infinity', '1e400'):
            broken = self.policy().replace('"threshold":90.0', '"threshold":' + literal)
            self.sentence(lambda broken=broken: load_policy(self.file(broken), CREDENTIALS), literal)

    def test_deeply_nested_input_refuses_instead_of_recursing(self):
        self.sentence(lambda: load_policy(self.file('[' * 4000 + ']' * 4000), CREDENTIALS))

    def test_invalid_utf8_and_a_byte_order_mark_are_refused(self):
        self.sentence(lambda: load_policy(self.file(b'\xff\xfe\x00policy'), CREDENTIALS))
        self.sentence(lambda: load_policy(self.file('\ufeff' + self.policy()), CREDENTIALS))

    def test_a_refusal_never_names_the_path_or_a_value_from_the_document(self):
        path = self.file('{"schema_version": 1, "verifiers": ["private-worker"]')
        self.sentence(lambda: load_policy(path, CREDENTIALS), str(path), 'private-worker', 'mappings')

    def test_credentials_are_crosschecked_only_after_the_document_parsed(self):
        unparsed = self.sentence(lambda: load_policy(self.file('not json'), CREDENTIALS))
        self.assertEqual(unparsed, self.sentence(lambda: load_policy(self.file('not json'), [])))
        seen = Watch(CREDENTIALS)
        self.sentence(lambda: load_policy(self.file('not json'), seen))
        self.assertEqual(seen.looked, 0)

    def test_every_verifier_needs_one_producer_row_and_no_row_of_another_role(self):
        reader = {'identity': VERIFIER, 'role': 'reader', 'token': 'y' * 24}
        self.sentence(lambda: load_policy(self.file(self.policy()), []))
        self.sentence(lambda: load_policy(self.file(self.policy()), [reader]))
        self.sentence(lambda: load_policy(self.file(self.policy()), [reader] + CREDENTIALS))
        self.sentence(lambda: load_policy(self.file(self.policy(verifiers=['nope'])), CREDENTIALS))
        self.assertTrue(load_policy(self.file(self.policy()), CREDENTIALS + [
            {'identity': VERIFIER, 'role': 'producer', 'token': 'z' * 24},
            {'identity': 'other-worker', 'role': 'summary', 'token': 'w' * 24}]))

    def test_malformed_rows_and_an_unbounded_credential_list_are_refused(self):
        one, two = CREDENTIALS[0], {**CREDENTIALS[0], 'scope': 'all'}
        rows = ({'identity': VERIFIER, 'role': 'producer'}, two, {**one, 'role': 'verifier'},
                {**one, 'identity': 'bad worker'}, {**one, 'identity': 1},
                [VERIFIER, 'producer', 'x' * 24], None, VERIFIER)
        for junk in rows:
            self.sentence(lambda junk=junk: load_policy(self.file(self.policy()),
                                                       [junk] + CREDENTIALS), VERIFIER)
        for container in (None, 'credentials', {'identity': VERIFIER}, (), CREDENTIALS * 257):
            self.sentence(lambda container=container: load_policy(self.file(self.policy()), container))

    def test_the_token_value_is_never_read_and_the_row_shape_is_all_that_is_checked(self):
        rows = [{'identity': VERIFIER, 'role': 'producer', 'token': NoToken()}]
        self.assertTrue(load_policy(self.file(self.policy()), rows))

    def test_binary_read_counts_crlf_and_refuses_control_z_suffix(self):
        document = self.policy().encode()
        padding = MAX_POLICY_BYTES - len(document)
        exact = document + b'\r\n' * (padding // 2) + b' ' * (padding % 2)
        self.assertEqual(len(exact), MAX_POLICY_BYTES)
        self.assertTrue(load_policy(self.file(exact), CREDENTIALS))
        for raw in (exact + b'\r\n', document + b'\x1a'):
            with self.subTest(size=len(raw)):
                self.sentence(lambda: load_policy(self.file(raw), CREDENTIALS))

    def test_environment_paths_are_strings_and_credential_rows_are_plain_dicts(self):
        path = self.file(self.policy())
        self.sentence(lambda: policy_from_environment(CREDENTIALS,
                                                     environ={CONFIG_ENVIRONMENT: path}))
        row_type = type('CustomRow', (dict,), {})
        self.sentence(lambda: load_policy(path, [row_type(CREDENTIALS[0])]))

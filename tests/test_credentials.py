"""Credential resolution: a mounted file wins, the environment value stays supported, no leaks."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch
import tempfile
import unittest

from local_observe.credentials import MAX_CREDENTIAL_BYTES, read_credential
from local_observe.http import JsonClient


SECRET = 'a-very-deliberate-canary-value-0123456789'


class CredentialReaderTests(unittest.TestCase):
    """`read_credential` and the order it resolves in; every case fixes one delivered behaviour."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, name: str, body: str | bytes) -> str:
        """Write one credential file and return its path as text."""
        path = self.root / name
        path.write_bytes(body.encode() if isinstance(body, str) else body)
        return str(path)

    def render(self, records: list[logging.LogRecord]) -> str:
        """Everything a log call could have said, including any formatting it would have done."""
        return ''.join(record.getMessage() + repr(record.__dict__) for record in records)

    def test_file_is_read_when_only_the_file_is_configured(self):
        path = self.file('token', SECRET)
        self.assertEqual(read_credential('LO_X', environ={'LO_X_FILE': path}), SECRET)

    def test_environment_value_is_still_accepted(self):
        """The staging scripts under scripts/ export values; a worker must not break them."""
        self.assertEqual(read_credential('LO_X', environ={'LO_X': SECRET}), SECRET)

    def test_file_wins_and_one_warning_names_the_variable_not_the_value(self):
        path = self.file('token', 'from-the-file')
        environ = {'LO_X_FILE': path, 'LO_X': SECRET}
        with self.assertLogs('local_observe.credentials', 'WARNING') as captured:
            self.assertEqual(read_credential('LO_X', environ=environ), 'from-the-file')
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(captured.records[0].variable, 'LO_X')
        self.assertNotIn(SECRET, self.render(captured.records))

    def test_missing_configuration_names_both_accepted_forms(self):
        with self.assertRaises(KeyError) as raised:
            read_credential('LO_STORE_TOKEN', environ={})
        message = str(raised.exception)
        self.assertIn('LO_STORE_TOKEN_FILE', message)
        self.assertIn('LO_STORE_TOKEN', message)

    def test_one_trailing_newline_is_stripped_and_a_second_is_refused(self):
        """`echo` leaves a newline behind; every consumer compares the value byte for byte.

        A second newline is not a credential: it is a two-line file. `http.JsonClient` refuses a
        token containing `\\n`, so returning one here would only move the failure to the first
        request. The expectation changed from "keeps the extra newline" when `read_credential`
        began refusing control characters (credential file leftovers).
        """
        with_newline = self.file('a', SECRET + '\n')
        self.assertEqual(read_credential('LO_A', environ={'LO_A_FILE': with_newline}), SECRET)
        two = self.file('b', SECRET + '\n\n')
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_B', environ={'LO_B_FILE': two})
        self.assertIn('LO_B_FILE', str(raised.exception))
        self.assertIn('U+000A', str(raised.exception))
        self.assertNotIn(SECRET, str(raised.exception))

    def test_a_crlf_line_ending_is_refused_at_the_read(self):
        """A file authored on Windows used to yield a token ending in `\\r`, refused far from here.

        The old expectation was that the carriage return survived so `http.JsonClient` could
        reject it; credential file leftovers moved the refusal to the read, where the message can name the variable and
        the code point instead of a transport error naming an endpoint.
        """
        path = self.file('crlf', SECRET + '\r\n')
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_X', environ={'LO_X_FILE': path})
        self.assertIn('LO_X_FILE', str(raised.exception))
        self.assertIn('U+000D', str(raised.exception))
        self.assertNotIn(SECRET, str(raised.exception))

    def test_an_embedded_nul_is_refused_without_the_value_being_echoed(self):
        """A truncated or binary-damaged file must not be presented as a short credential.

        The fixture is not named `nul`: on Windows that is a reserved device name and writing to it
        discards the bytes, so the reader would see an empty file instead of a NUL.
        """
        path = self.file('nul-byte', SECRET + '\x00' + 'tail')
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_X', environ={'LO_X_FILE': path})
        self.assertIn('LO_X_FILE', str(raised.exception))
        self.assertIn('U+0000', str(raised.exception))
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertNotIn('tail', str(raised.exception))

    def test_a_control_character_in_an_environment_value_is_refused_too(self):
        """Both forms arrive at the same rule, so neither can smuggle a line break into a header."""
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_X', environ={'LO_X': SECRET + '\r'})
        self.assertIn('LO_X', str(raised.exception))
        self.assertNotIn(SECRET, str(raised.exception))

    def test_the_transport_guard_still_refuses_a_carriage_return_from_any_other_caller(self):
        """`read_credential` is not the only way in: `JsonClient` keeps its own line-break guard."""
        with self.assertRaises(ValueError):
            JsonClient('https://endpoint.example', SECRET + '\r')

    def test_empty_or_blank_file_is_refused(self):
        for index, body in enumerate(('', '\n', '   \n')):
            path = self.file('blank-%d' % index, body)
            with self.subTest(body=body), self.assertRaises(ValueError) as raised:
                read_credential('LO_X', environ={'LO_X_FILE': path})
            self.assertNotIn(SECRET, str(raised.exception))

    def test_a_directory_is_refused_rather_than_raising_isadirectoryerror_from_open(self):
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_X', environ={'LO_X_FILE': str(self.root)})
        self.assertIn('LO_X_FILE', str(raised.exception))

    def test_oversized_file_is_refused_and_a_full_bound_is_accepted(self):
        over = self.file('over', 'x' * (MAX_CREDENTIAL_BYTES + 1))
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_X', environ={'LO_X_FILE': over})
        self.assertIn(str(MAX_CREDENTIAL_BYTES), str(raised.exception))
        exact = self.file('exact', 'y' * MAX_CREDENTIAL_BYTES)
        self.assertEqual(len(read_credential('LO_Y', environ={'LO_Y_FILE': exact})),
                         MAX_CREDENTIAL_BYTES)

    def test_non_utf8_bytes_are_refused_without_being_echoed(self):
        path = self.file('bytes', b'\xff\xfe\x00credential bytes not text')
        with self.assertRaises(ValueError) as raised:
            read_credential('LO_X', environ={'LO_X_FILE': path})
        self.assertNotIn('credential', str(raised.exception))

    def test_a_missing_file_raises_its_own_error_rather_than_falling_back_to_the_environment(self):
        """Falling through would silently serve a stale value the operator thought was deleted."""
        environ = {'LO_X_FILE': str(self.root / 'absent'), 'LO_X': SECRET}
        with self.assertRaises(OSError):
            read_credential('LO_X', environ=environ)

    def test_an_empty_file_variable_is_treated_as_unset_so_the_value_is_used(self):
        """Compose renders `${VAR:-}` as an empty string; a blank path is not a path."""
        self.assertEqual(read_credential('LO_X', environ={'LO_X_FILE': '', 'LO_X': SECRET}), SECRET)

    def test_empty_environment_value_does_not_count_as_a_credential(self):
        with self.assertRaises(KeyError):
            read_credential('LO_X', environ={'LO_X': ''})

    def test_the_default_environment_is_the_process_environment(self):
        path = self.file('token', SECRET)
        os.environ['LO_WORKER_CANARY_FILE'] = path
        self.addCleanup(os.environ.pop, 'LO_WORKER_CANARY_FILE', None)
        self.assertEqual(read_credential('LO_WORKER_CANARY'), SECRET)

    def test_no_exception_or_log_line_ever_carries_the_credential(self):
        """The whole point of the module: the value leaves only as the return value."""
        for environ in ({}, {'LO_X_FILE': str(self.root / 'absent')},
                        {'LO_X_FILE': str(self.root)}, {'LO_X': ''}):
            with self.subTest(environ=sorted(environ)):
                try:
                    read_credential('LO_X', environ=environ)
                except (KeyError, OSError, ValueError) as exc:
                    self.assertNotIn(SECRET, str(exc))
                else:
                    self.fail('expected a refusal')


class ConsumerWiringTests(unittest.TestCase):
    """The shipped compose shape must be the shape the code actually accepts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_detection_worker_builds_both_clients_from_mounted_files_alone(self):
        """No LO_GATUS_TOKEN / LO_PRODUCER_TOKEN in the environment, as the manifests now set it."""
        from local_observe.platform import detection_worker

        class StoppedLoop(Exception):
            pass

        gatus_file = self.root / 'gatus-token'
        gatus_file.write_bytes((SECRET + '\n').encode())
        producer_file = self.root / 'producer-token'
        producer_file.write_bytes(b'p' * 32)
        rule = self.root / 'rule.yaml'
        rule.write_text('source: fixture\n', encoding='utf-8')
        environment = {'LO_DETECTION_RULE': str(rule),
                       'LO_DETECTION_CURSOR': str(self.root / 'cursor.json'),
                       'LO_GATUS_URL': 'http://gatus.example.invalid',
                       'LO_GATUS_TOKEN_FILE': str(gatus_file),
                       'LO_PLATFORM_URL': 'http://platform.example.invalid',
                       'LO_PRODUCER_TOKEN_FILE': str(producer_file),
                       'LO_INTERNAL_ALLOW_HTTP': '1', 'LO_INDEX_PATH': str(self.root / 'index.db')}
        seen: list[tuple[str, str]] = []

        def fake_client(url, token, **_kwargs):
            seen.append((url, token))
            return object()

        def stopped(*_args, **_kwargs):
            raise StoppedLoop

        from contextlib import nullcontext
        with patch.object(detection_worker, 'JsonClient', fake_client), \
                patch.object(detection_worker, 'exclusive_owner', lambda _path: nullcontext()), \
                patch.object(detection_worker, 'tick', lambda *_a, **_k: 'idle'), \
                patch.object(detection_worker.time, 'sleep', stopped), \
                patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(StoppedLoop):
                detection_worker.main()
        self.assertEqual(seen, [('http://gatus.example.invalid', SECRET),
                                ('http://platform.example.invalid', 'p' * 32)])


if __name__ == '__main__':
    unittest.main()

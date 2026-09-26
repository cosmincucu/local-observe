"""Wave 11 : the frozen public shape of `lo-platform verification`.

Only `cli.main()` and the `verification_cli.JsonClient` patch seam are touched: every case is one argv
list, one exit status, one stdout document, and the requests a transport replacement recorded. No private
helper of the new module is named; the storage bounds the contract says are reused (`MAX_RECORD_BYTES`,
`RECORD_KEYS`, `_incoming`) are imported, not restated. Two cases build the *real* `JsonClient` and
intercept `OpenerDirector.open` — the last step before a socket — and none opens one.

Pinned, because each is a way this client could be wrong while still printing something: **one request per
invocation**, including failures and lost acknowledgements (an unanswered POST may be stored, so a retry is
a duplicate write); **nothing local** (`Store`, `NotificationPolicy`, the mode environment and any database
file are tripwired); **two fixed error objects** and nothing else — never a token, path, document, driver
message, traceback or an invented `busy`/`unavailable` distinction; and **validation before I/O**, so a bad
id or statement spends no request and reads no credential. Files are real temporary regular files (oversize
included, plus a FIFO where the platform has one).
"""
from __future__ import annotations

import contextlib
import copy
import datetime as dt
from inspect import Parameter, signature
import http.client
import io
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import urllib.request
from typing import Any, NamedTuple

from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import canonical, utc_text
from local_observe.platform import cli, verification_cli, verification_records
from local_observe.platform.verification_records import MAX_RECORD_BYTES, RECORD_KEYS

# Proves the credential never leaks, and stands in for server-side text this client must not repeat.
TOKEN = 'OPERATOR-SECRET-TOKEN-0123456789'
SERVER_SENTINEL = 'server-detail-should-not-travel-91f3'
_UNSET = object()
ACTION_ID = '6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4a5b'
EXECUTION_ID = '1a1b1c1d-1e1f-4a2b-8c3d-4e5f6a7b8c9d'
VERIFICATION_ID = 'ab' * 32
RESOURCE = '7b2f9d31-5c4e-4a6f-9d8e-1f2a3b4c5d6e'
BINDING, PIN = 'c' * 64, 'a' * 64
START = dt.datetime(2026, 9, 8, 12, tzinfo=dt.timezone.utc)
END = START + dt.timedelta(minutes=5)
WINDOW = {'start': utc_text(START), 'end': utc_text(END)}
ANSWER = {'verification_id': VERIFICATION_ID, 'verdict': 'cleared',
          'reason': 'comparison-satisfied', 'value': 70.0, 'window': WINDOW}
BASE = 'https://verify.invalid/base'
BIND_PATH = f'/v1/verification/binding?action_id={ACTION_ID}'
RECORDS_PATH = f'/v1/verification/records?execution_id={EXECUTION_ID}'
RECORD_PATH = f'/v1/verification/record?verification_id={VERIFICATION_ID}'
SUBMIT_PATH = '/v1/verification/records'
# Spellings that are neither one canonical UUID nor one 64-character lowercase digest, so no reading of the
# id rule can call them acceptable — the injection, traversal and fragment shapes included.
BAD_ANY_ID = ('', ' ', 'x', 'null', '0' * 36, 'a' * 35, 'a' * 37, 'a' * 63, 'a' * 65, 'g' * 64,
              ACTION_ID.upper(), '{' + ACTION_ID + '}', 'urn:uuid:' + ACTION_ID,
              ACTION_ID.replace('-', ''), ACTION_ID + '-', ' ' + ACTION_ID, ACTION_ID + ' ',
              VERIFICATION_ID.upper(), '../etc/passwd', '../../etc/passwd', 'verification/record',
              '%66' + ACTION_ID[3:], ACTION_ID + '?execution_id=' + EXECUTION_ID,
              ACTION_ID + '#fragment', ACTION_ID + '\n', ACTION_ID + '%20')
GET_CASES = (('binding', '--action-id', (EXECUTION_ID + '0',)),
             ('records', '--execution-id', (EXECUTION_ID.upper(),)),
             ('record', '--verification-id', ('D4' + VERIFICATION_ID[2:], 'ab' * 31)))
# The real transport's parameters and defaults, read off its signature: this file never restates them, it
# only asks what the command ended up configuring.
POSITIONAL = list(signature(JsonClient.__init__).parameters)[1:]
DEFAULTS = {name: item.default for name, item in signature(JsonClient.__init__).parameters.items()
            if item.default is not Parameter.empty}


def statement() -> dict:
    """One complete submitted observation that storage's own `_incoming` accepts, altered by nobody here.

    Normalised already (UTC microsecond stamps, float value, pure ASCII), so "the payload is the validated
    statement" holds for the raw file and for the document storage would normalise to.
    """
    window = copy.deepcopy(WINDOW)
    return {'execution_id': EXECUTION_ID, 'binding_id': BINDING, 'window': window,
            'outcome': 'available',
            'receipt': {'query_type': 'metric-threshold',
                        'parameters': {'artifact_sha256': PIN, 'resource_id': RESOURCE,
                                       'rule_id': 'inspect.cpu'}, 'window': copy.deepcopy(window),
                        'expires_at': utc_text(END + dt.timedelta(minutes=15)),
                        'sample_count': 1, 'truncated': False},
            'samples': [{'metric_name': 'lo_cpu', 'observed_at': utc_text(START + dt.timedelta(minutes=1)),
                         'resource_id': RESOURCE, 'value': 70.0}]}


def carried(document: Any, key: str) -> Any:
    """The first value *key* carries anywhere inside *document*."""
    if isinstance(document, dict):
        if key in document:
            return document[key]
        values: Any = list(document.values())
    else:
        values = document if isinstance(document, list) else []
    for item in values:
        if (found := carried(item, key)) is not _UNSET:
            return found
    return _UNSET


def rewritten(document: dict, key: str, spelling: str | None = None, again: bool = False,
              twice: Any = _UNSET) -> str:
    """Rewrite *key*'s first pair as raw JSON *spelling*, or repeat it (*again*, or once as *twice*).

    Edited into the live document text, so each refusal below is about the duplicated or impossible value
    alone: with the guard removed, the rest of the statement still passes every other rule.
    """
    text = json.dumps(document)
    needle = json.dumps({key: carried(document, key)})[1:-1]
    found = text.find(needle)
    if found < 0:
        raise AssertionError(f'the fixture carries no {key} pair to touch')
    end = found + len(needle)
    if again or twice is not _UNSET:
        return text[:end] + f', {needle if again else json.dumps({key: twice})[1:-1]}' + text[end:]
    return text[:found] + f'{json.dumps(key)}: {spelling}' + text[end:]


def tripwire(name: str):
    """Return a callable that refuses to be used: the verification group reaches none of these."""
    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f'{name} must not be touched by `verification`')
    return refuse


class FakeClient:
    """`verification_cli.JsonClient`'s replacement: it records, answers on command, opens nothing.

    Constructor arguments are kept as handed over, positional or keyword, and read back through the real
    `JsonClient`'s signature, so assertions are about effective configuration, never a call convention.
    """

    instances: list[FakeClient] = []
    answer: Any = (200, ANSWER)
    failure: BaseException | None = None
    build_failure: BaseException | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        if FakeClient.build_failure is not None:
            raise FakeClient.build_failure
        self.args, self.kwargs, self.calls = args, kwargs, []
        self.answer, self.failure = FakeClient.answer, FakeClient.failure
        FakeClient.instances.append(self)

    def request(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append({'args': args, 'kwargs': kwargs})
        if self.failure is not None:
            raise self.failure
        return self.answer

    def option(self, name: str) -> Any:
        """What this client is configured with: as given, else the real transport's own default."""
        index = POSITIONAL.index(name)
        if index < len(self.args):
            return self.args[index]
        return self.kwargs[name] if name in self.kwargs else DEFAULTS.get(name, _UNSET)

    @classmethod
    def programme(cls, answer=_UNSET, failure=None, build_failure=None, keep=False) -> None:
        if not keep:
            cls.instances = []
        cls.answer = (200, ANSWER) if answer is _UNSET else answer
        cls.failure, cls.build_failure = failure, build_failure


class Run(NamedTuple):
    code: int
    out: str
    err: str


class VerificationFixture(unittest.TestCase):
    """One argv-wide `cli.main()` call, a real token file, and a transport that cannot lie.

    The harness is `invoke`: `TestCase.run` belongs to the runner and is left entirely alone.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / 'platform.db'
        self.token = self.root / 'operator-token'
        self.token.write_text(TOKEN, encoding='utf-8')
        self.url = 'https://verify.invalid'
        FakeClient.programme()
        self.addCleanup(FakeClient.programme)
        self.enterContext(mock.patch.dict(os.environ))
        for name in (cli.MODE_ENVIRONMENT, 'LO_VERIFICATION_TOKEN', 'LO_VERIFICATION_URL'):
            os.environ.pop(name, None)

    def invoke(self, *argv: str, answer: Any = _UNSET, failure: BaseException | None = None,
               build_failure: BaseException | None = None, keep: bool = False, client: bool = True,
               local: bool = False) -> Run:
        """Run `cli.main()`: transport replaced, local machinery tripwired, stdout and logs captured.

        `client=False` leaves `verification_cli.JsonClient` real for the wiring cases; `local=True` leaves
        the store machinery real for the legacy control. Logs are captured at DEBUG, so "no traceback for a
        remote failure" is asserted where one would otherwise have been emitted.
        """
        if answer is not _UNSET or failure is not None or build_failure is not None:
            FakeClient.programme(answer=answer, failure=failure, build_failure=build_failure, keep=keep)
        elif not keep:
            FakeClient.instances = []
        out, logged = io.StringIO(), io.StringIO()
        handler, code = logging.StreamHandler(logged), None
        root, previous = logging.getLogger(), logging.getLogger().level
        blocked = [] if local else ['Store', 'NotificationPolicy', 'notification_mode', 'Actor']
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, 'argv', ['lo-platform', *argv]))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(logged))
            if client:
                stack.enter_context(mock.patch.object(verification_cli, 'JsonClient', FakeClient))
            for name in [*blocked, 'JsonClient']:
                stack.enter_context(mock.patch.object(cli, name, tripwire(name)))
            root.addHandler(handler)
            stack.callback(root.removeHandler, handler)
            root.setLevel(logging.DEBUG)
            stack.callback(root.setLevel, previous)
            try:
                code = cli.main()
            except SystemExit as refused:
                code = refused.code if isinstance(refused.code, int) else 2
        return Run(code, out.getvalue(), logged.getvalue())

    def via_real_transport(self, *argv: str, body: bytes = b'{}') -> tuple[Run, list]:
        """Run with the real `JsonClient`, intercepting `OpenerDirector.open` and counting its calls."""
        opened: list[Any] = []
        answer = mock.MagicMock(status=200)
        answer.read.side_effect = lambda limit=-1: body[:limit] if limit >= 0 else body
        answer.__enter__.return_value = answer

        def fake_open(handler_, request, timeout=None):
            opened.append((request, timeout))
            return answer

        with mock.patch.object(urllib.request.OpenerDirector, 'open', fake_open):
            return self.invoke(*argv, client=False), opened

    def verify(self, *argv: str, url: str | None = None, token: Any = _UNSET) -> list[str]:
        """The frozen public command, spelled once: `verification --url .. --token-file .. OPERATION`."""
        return ['verification', '--url', self.url if url is None else url, '--token-file',
                str(self.token if token is _UNSET else token), *argv]

    def write(self, name: str, payload: Any) -> Path:
        """Write real bytes (text as UTF-8) into one regular file and hand back its path."""
        path = self.root / name
        path.write_bytes(payload if isinstance(payload, bytes) else payload.encode('utf-8'))
        return path

    def document(self, result: Run) -> Any:
        """The single JSON document stdout must hold, whatever the outcome was."""
        self.assertNotEqual('', result.out.strip(), 'a run answers with one document or nothing')
        return json.loads(result.out)

    def requests(self) -> list[dict]:
        """Every recorded request across every client, in order, flattened to method/path/payload."""
        seen = []
        for client in FakeClient.instances:
            for call in client.calls:
                args, kwargs = call['args'], call['kwargs']
                seen.append({'method': args[0] if args else kwargs.get('method'),
                             'path': args[1] if len(args) > 1 else kwargs.get('path', ''),
                             'payload': args[2] if len(args) > 2 else kwargs.get('payload')})
        return seen

    def one_client(self) -> FakeClient:
        self.assertEqual(1, len(FakeClient.instances), 'exactly one transport per invocation')
        return FakeClient.instances[0]

    def assert_one_request(self, method: str, path: str | None, payload: Any = _UNSET) -> dict:
        """Exactly one request, with this method, this path and (for submit) this payload."""
        seen = self.requests()
        self.assertEqual(1, len(seen), f'one request was allowed, {len(seen)} were made: {seen}')
        self.assertEqual(method, seen[0]['method'])
        if path is not None:
            self.assertEqual(path, seen[0]['path'])
        if payload is not _UNSET:
            self.assertEqual(payload, seen[0]['payload'])
        return seen[0]

    def assert_no_request(self) -> None:
        """No request left this process, whether or not a client object was ever built."""
        self.assertEqual([], self.requests(), 'a refused invocation must spend no request')

    def assert_no_client(self) -> None:
        """Not even a transport was constructed: invalid input never reaches the endpoint."""
        self.assertEqual([], FakeClient.instances, 'invalid input must not build the transport')

    def assert_cli_error(self, result: Run) -> None:
        """The one local-failure answer: two fields, exit 1, nothing else on stdout."""
        self.assertEqual(1, result.code, f'stdout was {result.out!r}')
        self.assertEqual({'status': 'error', 'error_type': 'VerificationCLIError'}, self.document(result))

    def assert_http_error(self, result: Run, status: int) -> None:
        """The one remote-failure answer: three fields, exit 1, and no invented diagnosis."""
        self.assertEqual(1, result.code, f'stdout was {result.out!r}')
        self.assertEqual({'status': 'error', 'error_type': 'VerificationHTTPError',
                          'http_status': status}, self.document(result))

    def assert_syntax_refused(self, *argv: str) -> None:
        """argparse answers with exit 2 on stderr, before a credential, a file or a socket is touched."""
        result = self.invoke(*argv)
        self.assertEqual(2, result.code, f'stdout was {result.out!r}')
        self.assertEqual('', result.out, 'a usage error is not a JSON answer')
        self.assert_no_client()
        self.assert_no_local_state()

    def assert_refused_input(self, *argv: str) -> Run:
        """One invocation whose input is refused while no transport exists and no request is spent."""
        FakeClient.programme()
        result = self.invoke(*argv)
        self.assert_cli_error(result)
        self.assert_no_client()
        self.assert_no_request()
        self.assert_quiet(result)
        return result

    def assert_bad_statement(self, text: str, name: str = 'bad') -> Run:
        """One statement file the command must refuse out of hand."""
        return self.assert_refused_input(*self.verify('submit', '--statement',
                                                      str(self.write(f'{name}.json', text))))

    def awkward_files(self, role: str) -> list[tuple[str, Path]]:
        """The files one bounded regular read must refuse: absent, a directory, oversized, a FIFO."""
        cases = [('missing', self.root / f'no-{role}'), ('directory', self.root),
                 ('oversize', self.write(f'long-{role}', 'k' * (MAX_RECORD_BYTES + 256)))]
        if hasattr(os, 'mkfifo'):
            fifo = self.root / f'{role}-fifo'
            os.mkfifo(fifo)
            cases.append(('fifo', fifo))
        return cases

    def assert_quiet(self, result: Run) -> None:
        """No credential, path, submitted document, server text or traceback in either stream."""
        for text in (result.out, result.err):
            for secret in (TOKEN, SERVER_SENTINEL, str(self.root), 'lo_cpu', str(self.database)):
                self.assertNotIn(secret, text, 'a fixed answer names a class, never a value')
            self.assertNotIn('Traceback', text)

    def assert_no_local_state(self) -> None:
        """Verification opened no database and created nothing that looks like one."""
        self.assertFalse(self.database.exists(), 'the verification group never resolves --database')
        self.assertEqual([], sorted(path.name for path in self.root.glob('*.db*')),
                         'a verification run created no database file')


class TransportTests(VerificationFixture):
    """The four operations, the one transport, and everything an answer may and may not look like."""

    def test_every_operation_makes_its_one_exact_request(self) -> None:
        """GET/GET/GET/POST on the four frozen paths: one request, exit 0, answer and credential intact."""
        path = self.write('statement.json', json.dumps(statement()))
        for operation, option, value, method, endpoint, payload in (
                ('binding', '--action-id', ACTION_ID, 'GET', BIND_PATH, _UNSET),
                ('records', '--execution-id', EXECUTION_ID, 'GET', RECORDS_PATH, _UNSET),
                ('record', '--verification-id', VERIFICATION_ID, 'GET', RECORD_PATH, _UNSET),
                ('submit', '--statement', str(path), 'POST', SUBMIT_PATH, statement())):
            with self.subTest(operation=operation):
                FakeClient.programme()
                result = self.invoke(*self.verify(operation, option, value, url=BASE))
                self.assertEqual(0, result.code, f'stdout was {result.out!r}')
                self.assertEqual(BASE, self.one_client().option('base'), 'the base path is kept')
                self.assertEqual(TOKEN, self.one_client().option('token'))
                seen = self.assert_one_request(method, endpoint, payload)
                self.assertNotIn('%', seen['path'], 'a validated id is written, never percent-encoded')
                self.assertNotIn('//', seen['path'])
                self.assertEqual(ANSWER, self.document(result))
                self.assert_quiet(result)

    def test_the_transport_is_configured_with_only_what_the_operator_named(self) -> None:
        """Bearer over HTTPS, no relaxation flags, the named timeout, the named CA file, nothing else."""
        ca = self.write('operator-ca.pem', b'-----BEGIN CERTIFICATE-----\nnot-a-certificate\n')
        for extra, wanted in (((), {'timeout': 10, 'ca_file': None}), (('--timeout', '3'), {'timeout': 3}),
                              (('--ca-file', str(ca)), {'ca_file': str(ca)}),
                              (('--timeout', '20', '--ca-file', str(ca)), {'timeout': 20})):
            with self.subTest(extra=' '.join(extra) or 'defaults'):
                FakeClient.programme()
                self.invoke(*self.verify(*extra, 'binding', '--action-id', ACTION_ID))
                client = self.one_client()
                self.assertEqual('Bearer', client.option('scheme'))
                self.assertIs(False, client.option('allow_http'))
                self.assertIs(False, client.option('accept_non_json'))
                for name, value in wanted.items():
                    found = client.option(name)
                    self.assertEqual(value, str(found) if isinstance(found, Path) else found,
                                     f'{name} reached the transport as {found!r}')

    def test_the_real_transport_is_the_one_constructed_and_refuses_a_bad_configuration(self) -> None:
        """Wiring, and the bounds it owns: plain HTTP, embedded credentials, a bad timeout, no request.

        These need the real `JsonClient`, which is the module that owns the scheme and the 1..20 s rule;
        the accepted case is asserted beside them, on the joined URL and the header it really sends.
        """
        good, opened = self.via_real_transport(*self.verify('binding', '--action-id', ACTION_ID,
                                                           url=BASE),
                                               body=b'{"verdict":"cleared","value":70.0}')
        self.assertEqual(0, good.code, f'stdout was {good.out!r}')
        self.assertEqual(1, len(opened), 'exactly one request on the real transport')
        request, timeout = opened[0]
        self.assertEqual(BASE + BIND_PATH, request.full_url)
        self.assertEqual('GET', request.method)
        self.assertIsNone(request.data, 'a GET carries no body')
        self.assertEqual('Bearer ' + TOKEN, request.get_header('Authorization'))
        self.assertEqual(10, timeout, 'the default request bound is the transport\'s own')
        self.assertEqual({'verdict': 'cleared', 'value': 70.0}, self.document(good))
        missing = str(self.root / 'no-such-ca.pem')
        for label, url, extra in (('http url', 'http://verify.invalid', ()),
                                  ('plain host', 'verify.invalid', ()), ('empty url', '', ()),
                                  ('credentials', 'https://u:p@verify.invalid', ()),
                                  ('query in url', self.url + '?a=1', ()),
                                  ('fragment', self.url + '#f', ()),
                                  ('malformed IPv6', 'https://[broken', ()),
                                  ('zero timeout', self.url, ('--timeout', '0')),
                                  ('over-long timeout', self.url, ('--timeout', '21')),
                                  ('missing ca file', self.url, ('--ca-file', missing))):
            with self.subTest(case=label):
                result, opened = self.via_real_transport('verification', '--url', url, '--token-file',
                                                        str(self.token), *extra, 'binding',
                                                        '--action-id', ACTION_ID)
                self.assert_cli_error(result)
                self.assertEqual([], opened, 'a refused configuration spends no request')

    def test_a_successful_answer_is_printed_unchanged(self) -> None:
        """The server's fields, order and all: no `status`, no synthesized success, no renaming."""
        stored = {'verification_id': VERIFICATION_ID, 'verdict': 'unknown',
                  'reason': 'pre-execution-window', 'value': None, 'samples': [],
                  'recorded_by': 'verify-worker', 'nested': {'window': {'start': 'x', 'end': 'y'}}}
        FakeClient.programme(answer=(200, stored))
        result = self.invoke(*self.verify('record', '--verification-id', VERIFICATION_ID))
        self.assertEqual(0, result.code, f'stdout was {result.out!r}')
        self.assertEqual(json.dumps(stored, indent=2, allow_nan=False), result.out.strip())
        self.assertEqual(stored, self.document(result))

    def test_every_non_200_answer_is_one_fixed_error_line(self) -> None:
        """Polarity and diagnosis: only 200 succeeds, the status is reported, the server's prose stays
        behind, and two 503s whose bodies name different reasons answer identically.
        """
        answers = []
        for status, body in ((201, {'error': SERVER_SENTINEL}), (202, None), (204, None), (299, None),
                             (301, None), (400, None), (401, None), (403, None), (404, None),
                             (409, None), (429, None), (500, None), (502, None),
                             (503, {'reason': 'verification_busy'}),
                             (503, {'reason': 'verification_unavailable'})):
            with self.subTest(status=status, body=str(body)):
                FakeClient.programme(answer=(status, body))
                result = self.invoke(*self.verify('records', '--execution-id', EXECUTION_ID))
                self.assert_http_error(result, status)
                self.assert_one_request('GET', RECORDS_PATH)
                self.assert_quiet(result)
                if status == 503:
                    answers.append(result.out)
        self.assertEqual(2, len(answers))
        self.assertEqual(answers[0], answers[1], 'no reason word may be invented')

    def test_a_lost_or_unreachable_endpoint_is_a_client_error_with_no_status(self) -> None:
        """A timeout, a refused connection and a refused construction are one line with no http_status."""
        for label, programme in (('unreachable', {'failure': TransportError('Endpoint unavailable')}),
                                 ('reset', {'failure': ConnectionResetError('connection reset')}),
                                 ('refused build',
                                  {'build_failure': TransportError('Invalid HTTP timeout')})):
            with self.subTest(case=label):
                FakeClient.programme(answer=(503, None), **programme)
                self.assert_cli_error(self.invoke(*self.verify('record', '--verification-id',
                                                               VERIFICATION_ID)))

    def test_a_non_object_or_non_finite_success_answer_is_a_fixed_local_error(self) -> None:
        """A 200 that is not a JSON object, or holds a number JSON cannot express, is refused."""
        for label, body in (('list', []), ('rows', ['row']), ('text', 'text'), ('number', 70.0),
                            ('null', None), ('boolean', True), ('nan', {'value': float('nan')}),
                            ('infinity', {'value': float('inf')}), ('nested -inf', [float('-inf')]),
                            ('nan in answer', {'window': WINDOW, 'value': float('nan')})):
            with self.subTest(body=label):
                FakeClient.programme(answer=(200, body))
                result = self.invoke(*self.verify('binding', '--action-id', ACTION_ID))
                self.assert_cli_error(result)
                self.assert_one_request('GET', BIND_PATH)
                for word in ('NaN', 'Infinity', 'Traceback'):
                    self.assertNotIn(word, result.out)

    def test_a_programmer_error_is_not_swallowed_into_a_fixed_line(self) -> None:
        """Only expected failures become fixed answers; a bug escapes instead of being hushed."""
        for bug in (RuntimeError('unexpected'), AttributeError('no such attribute'),
                    TypeError('bad call'), ValueError('bad internal value'), KeyboardInterrupt()):
            with self.subTest(bug=type(bug).__name__):
                FakeClient.programme(failure=bug)
                with self.assertRaises(type(bug)):
                    self.invoke(*self.verify('binding', '--action-id', ACTION_ID))


class CredentialFileTests(VerificationFixture):
    """The token file: one bounded read of one regular file, and the only credential this command knows."""

    def test_the_token_file_is_the_only_credential_source(self) -> None:
        """An environment variable and a raw-token flag are both nothing: no fallback, no request."""
        os.environ['LO_VERIFICATION_TOKEN'] = TOKEN
        os.environ[cli.MODE_ENVIRONMENT] = 'live'
        for extra in ([], ['--token', TOKEN], ['--token', TOKEN, '--url', self.url], ['--url', self.url]):
            with self.subTest(supplied=' '.join(extra) or 'neither option'):
                self.assert_syntax_refused('verification', *extra, 'binding', '--action-id', ACTION_ID)

    def test_the_token_is_stripped_and_then_24_to_4096_printable_ascii_bytes(self) -> None:
        """Outer whitespace is formatting; a space inside, a control byte or a non-ASCII byte is not."""
        for payload, accepted in ((TOKEN, True), ('\n' + TOKEN + '\r\n', True),
                                  ('\t ' + TOKEN + ' \n', True), ('k' * 24, True), ('k' * 4096, True),
                                  ('~!@#$%^&*()_+' * 4, True), ('', False), ('   ', False),
                                  ('k' * 23, False), ('k' * 4097, False), ('k' * 5000, False),
                                  ('k' * 30 + ' k', False), ('k' * 30 + '\tk', False),
                                  ('k' * 20 + '\x7f', False), ('k' * 20 + '\x00', False),
                                  ('k' * 30 + 'é', False), (('k' * 30).encode('utf-16'), False),
                                  (b'k' * 30 + b'\xff\xfe', False), ('\ufeff' + 'k' * 30, False)):
            with self.subTest(token=repr(payload)[:30], accepted=accepted):
                self.token.write_bytes(payload if isinstance(payload, bytes)
                                       else payload.encode('utf-8'))
                FakeClient.programme()
                result = self.invoke(*self.verify('binding', '--action-id', ACTION_ID))
                if accepted:
                    self.assertEqual(0, result.code, f'stdout was {result.out!r}')
                    self.assertEqual(payload.strip(), self.one_client().option('token'))
                else:
                    self.assert_cli_error(result)
                    self.assert_no_client()

    def test_a_secret_or_statement_file_must_be_a_readable_regular_file(self) -> None:
        """Absent, a directory, oversized and a FIFO are fixed errors that spend nothing, either file."""
        for role in ('token', 'statement'):
            for label, path in self.awkward_files(role):
                with self.subTest(file=f'{role}/{label}'):
                    self.assert_refused_input(*(self.verify('binding', '--action-id', ACTION_ID,
                                                            token=path) if role == 'token'
                                                else self.verify('submit', '--statement', str(path))))

    def test_a_symlink_to_a_regular_file_is_still_a_regular_file(self) -> None:
        """No permission or symlink policy is invented here: the operator's own regular file is read."""
        linked = self.root / 'linked-token'
        try:
            linked.symlink_to(self.token)
        except (OSError, NotImplementedError):
            self.skipTest('this platform creates no unprivileged symlinks')
        FakeClient.programme()
        result = self.invoke(*self.verify('binding', '--action-id', ACTION_ID, token=linked))
        self.assertEqual(0, result.code, f'stdout was {result.out!r}')
        self.assertEqual(TOKEN, self.one_client().option('token'))


class StatementTests(VerificationFixture):
    """The submitted statement: storage's own rules on one bounded file read, before any I/O."""

    def test_the_statement_fixture_is_a_real_accepted_statement(self) -> None:
        """Control: storage accepts the fixture unchanged, so every acceptance below means something."""
        document = statement()
        self.assertEqual(sorted(RECORD_KEYS), sorted(document))
        self.assertEqual(document, verification_records._incoming(copy.deepcopy(document)),
                         'the fixture is not already in storage\'s normal form')
        self.assertLess(len(canonical(document).encode()), MAX_RECORD_BYTES,
                        'the padding cases below must be about the raw cap and nothing else')

    def test_submit_posts_the_validated_statement_and_adds_nothing(self) -> None:
        """No verdict, no reason, no actor, no clock: the six record keys are the whole payload."""
        path = self.write('statement.json', json.dumps(statement()))
        FakeClient.programme()
        result = self.invoke(*self.verify('submit', '--statement', str(path)))
        self.assertEqual(0, result.code, f'stdout was {result.out!r}')
        payload = self.assert_one_request('POST', SUBMIT_PATH, statement())['payload']
        self.assertEqual(sorted(RECORD_KEYS), sorted(payload))
        for invented in ('verdict', 'reason', 'actor', 'now', 'value', 'verification_id'):
            self.assertNotIn(invented, payload)
        self.assertEqual(ANSWER, self.document(result))

    def test_a_statement_file_is_accepted_up_to_the_storage_byte_cap(self) -> None:
        """Exactly `MAX_RECORD_BYTES` of padded JSON is admissible; one byte more is refused."""
        text = json.dumps(statement())
        for extra, accepted in ((0, True), (1, False)):
            with self.subTest(size=MAX_RECORD_BYTES + extra):
                path = self.write('padded.json', text + ' ' * (MAX_RECORD_BYTES + extra - len(text)))
                self.assertEqual(MAX_RECORD_BYTES + extra, len(path.read_bytes()))
                FakeClient.programme()
                result = self.invoke(*self.verify('submit', '--statement', str(path)))
                if accepted:
                    self.assertEqual(0, result.code, f'stdout was {result.out!r}')
                    self.assert_one_request('POST', SUBMIT_PATH, statement())
                else:
                    self.assert_cli_error(result)
                    self.assert_no_client()

    def test_a_statement_that_is_not_one_json_object_is_refused(self) -> None:
        """Empty, prose, a non-object document, trailing junk and undecodable bytes cost nothing."""
        text = json.dumps(statement())
        for label, payload in (('empty', ''), ('blank', '   '), ('array', '[]'), ('string', '"text"'),
                               ('null', 'null'), ('number', '70'), ('truncated', '{'),
                               ('two documents', '{} {}'), ('trailing junk', text + ' extra'),
                               ('prose', '# not json'), ('utf-16', text.encode('utf-16')),
                               ('invalid utf-8', b'{"outcome": "\xff\xfe"}'),
                               ('bom', ('\ufeff' + text).encode('utf-8')),
                               ('trailing non-utf8', text.encode('utf-8') + b'\n\x80')):
            with self.subTest(statement=label):
                self.assert_bad_statement(payload, 'broken')

    def test_duplicate_object_keys_are_refused_at_every_depth(self) -> None:
        """One repeated name anywhere is a refusal, even where both copies agree and the shape is legal."""
        document = statement()
        for key in ('outcome', 'binding_id', 'window', 'query_type', 'sample_count', 'truncated',
                    'artifact_sha256', 'resource_id', 'metric_name', 'observed_at', 'value', 'start'):
            with self.subTest(key=key):
                self.assert_bad_statement(rewritten(document, key, again=True), f'duplicate-{key}')
        # A second `sample_count` of 2 over one row is the conflicting case every other rule still
        # accepts, so a dropped duplicate-key guard cannot hide behind a shape refusal here.
        self.assert_bad_statement(rewritten(document, 'sample_count', twice=2), 'duplicate-changed')

    def test_numbers_storage_will_not_hold_and_nesting_it_will_not_walk_are_refused(self) -> None:
        """Non-finite constants, an overflowing float, signed64 edges and a recursion bomb: exit 1."""
        for key, spelling in (('outcome', 'NaN'), ('window', '"Infinity"'),
                              ('sample_count', '-Infinity'), ('value', '1e400'),
                              ('expires_at', '1e309'), ('binding_id', str(2 ** 63)),
                              ('resource_id', str(2 ** 63 - 1)), ('metric_name', '1e400'),
                              ('observed_at', '-9223372036854775809')):
            with self.subTest(key=key, spelling=spelling):
                self.assert_bad_statement(rewritten(statement(), key, spelling), f'edge-{key}')
        for depth in (9, 40, 2000):
            with self.subTest(depth=depth):
                result = self.assert_bad_statement('[' * depth + ']' * depth, 'deep')
                self.assertNotIn('Recursion', result.out + result.err)

    def test_a_statement_storage_shape_rules_refuse_is_a_client_error(self) -> None:
        """The reused `_incoming` refusals surface as `VerificationCLIError`, with no transport at all."""
        document, receipt, row = statement(), statement()['receipt'], statement()['samples'][0]
        broken = [({'extra': 1}, 'an unaccepted field'), ({'execution_id': 'not-a-uuid'}, 'a bad id'),
                  ({'execution_id': EXECUTION_ID.upper()}, 'an uppercase execution id'),
                  ({'binding_id': BINDING.upper()}, 'an uppercase binding digest'),
                  ({'outcome': 'cleared'}, 'a verdict where an outcome belongs'),
                  ({'receipt': None}, 'an available read with no receipt'),
                  ({'samples': None}, 'samples must be a list'),
                  ({'window': {'start': WINDOW['end'], 'end': WINDOW['start']}}, 'a reversed window'),
                  ({'window': {'start': WINDOW['start']}}, 'a half window'),
                  ({'samples': [{**row, 'observed_at': WINDOW['end']}]}, 'a row at the window end'),
                  ({'samples': [{**row, 'value': float('nan')}]}, 'a nan sample'),
                  ({'samples': [{**row, 'metric_name': 'has space'}]}, 'an unbounded metric name'),
                  ({'receipt': {**receipt, 'detail': SERVER_SENTINEL}}, 'a receipt carrying prose'),
                  ({'receipt': {**receipt, 'truncated': 1}}, 'a non-boolean truncation'),
                  ({'receipt': {**receipt, 'expires_at': WINDOW['end']}},
                   'a receipt dead at its window end')]
        for changes, label in broken:
            with self.subTest(statement=label):
                self.assert_bad_statement(json.dumps({**copy.deepcopy(document), **changes}), 'shape')


class DispatchTests(VerificationFixture):
    """The dispatch itself: syntax before I/O, no database, and no knob this slice does not offer."""

    def test_missing_unknown_or_conflicting_syntax_is_refused_before_any_io(self) -> None:
        """Exit 2 on stderr for every shape the frozen command does not spell, database included."""
        good = ['--url', self.url, '--token-file', str(self.token), 'binding', '--action-id', ACTION_ID]
        cases = [['verification'], ['verification', 'binding'], ['verification', 'binding', '--action-id'],
                 ['verification', 'records'], ['verification', 'submit'], ['verification', 'unknown'],
                 ['verification', 'status'], ['--database', str(self.database)],
                 ['verification', *good[:2], 'binding', '--action-id', ACTION_ID],
                 ['verification', *good[2:], 'binding', '--action-id', ACTION_ID],
                 ['verification', 'binding', '--action_id', ACTION_ID], ['verification', *good, 'extra'],
                 ['--database', str(self.database), 'verification', *good],
                 ['verification', '--database', str(self.database), *good],
                 ['verification', *good[:4], '--database', str(self.database), *good[4:]]]
        for argv in cases:
            with self.subTest(argv=' '.join(argv[1:]) or 'bare'):
                self.assert_syntax_refused(*argv)

    def test_no_insecure_retry_local_or_credential_option_is_offered(self) -> None:
        """Every withheld knob is unknown syntax, including the ones that would have looked safe."""
        for option in (['--allow-http'], ['--insecure'], ['--no-verify'], ['--http'], ['--retry'],
                       ['--retries', '3'], ['--output', 'answer.json'], ['--actor', 'operator'],
                       ['--role', 'human'], ['--now', '2026-09-08T12:00:00Z'], ['--token', TOKEN],
                       ['--timeout', '3.5'], ['--timeout', 'abc']):
            with self.subTest(option=' '.join(option)):
                self.assert_syntax_refused(*self.verify(*option, 'binding', '--action-id', ACTION_ID))

    def test_verification_never_opens_a_store_a_policy_or_a_database_file(self) -> None:
        """The tripwires stay silent and the directory stays clean, on success and on refusal."""
        path = self.write('statement.json', json.dumps(statement()))
        for argv, code in ((('binding', '--action-id', ACTION_ID), 0),
                           (('submit', '--statement', str(path)), 0),
                           (('record', '--verification-id', 'nope'), 1)):
            with self.subTest(operation=argv[0], code=code):
                FakeClient.programme()
                result = self.invoke(*self.verify(*argv))
                self.assertEqual(code, result.code, f'stdout was {result.out!r}')
                self.assert_no_local_state()
                self.assert_quiet(result)

    def test_legacy_commands_still_require_and_still_use_a_database(self) -> None:
        """The global flag became optional without becoming optional for anything that needs it."""
        refused = self.invoke('status')
        self.assertEqual(2, refused.code)
        self.assertEqual('', refused.out)
        self.assert_no_local_state()
        result = self.invoke('--database', str(self.database), 'status', local=True)
        self.assertEqual(0, result.code, f'stdout was {result.out!r}')
        self.assertIsInstance(self.document(result), dict)
        self.assertTrue(self.database.exists(), 'the legacy path really did open its database')
        self.assertEqual([], FakeClient.instances, 'a legacy run built no verification transport')

    def test_an_invalid_identifier_spends_no_request_and_reads_no_token(self) -> None:
        """Every GET id is exactly one UUID or one lowercase digest, decided before anything else."""
        for operation, option, extra in GET_CASES:
            for spelling in (*BAD_ANY_ID, *extra):
                with self.subTest(operation=operation, value=spelling[:22] or 'empty'):
                    self.assert_refused_input(*self.verify(operation, option, spelling))


class AmbiguityTests(VerificationFixture):
    """The one rule a client cannot be trusted to improvise: an unanswered submit is not a retry."""

    def test_an_ambiguous_submit_failure_never_retries_inside_one_invocation(self) -> None:
        """Lost acknowledgement, 409, 500, 503, 504 and a timeout each cost exactly one POST."""
        path = self.write('statement.json', json.dumps(statement()))
        argv = self.verify('submit', '--statement', str(path))
        before = path.read_bytes()
        for status in (202, 400, 409, 500, 503, 504):
            with self.subTest(status=status):
                FakeClient.programme(answer=(status, {'reason': SERVER_SENTINEL}))
                self.assert_http_error(self.invoke(*argv), status)
                self.assert_one_request('POST', SUBMIT_PATH)
        for failure in (TransportError('Endpoint unavailable or invalid JSON response'),
                        TimeoutError('the request bound expired')):
            with self.subTest(failure=type(failure).__name__):
                FakeClient.programme(failure=failure)
                self.assert_cli_error(self.invoke(*argv))
                self.assert_one_request('POST', SUBMIT_PATH)
        self.assertEqual(before, path.read_bytes(), 'the operator\'s statement file is never rewritten')

    def test_an_explicit_resubmit_of_an_unchanged_statement_is_two_invocations(self) -> None:
        """Replay is the operator's decision: two runs, two identical payloads, two clients."""
        path = self.write('statement.json', json.dumps(statement()))
        argv = self.verify('submit', '--statement', str(path))
        first = self.invoke(*argv, answer=(503, None))
        second = self.invoke(*argv, answer=(200, ANSWER), keep=True)
        self.assert_http_error(first, 503)
        self.assertEqual(0, second.code, f'stdout was {second.out!r}')
        seen = self.requests()
        self.assertEqual(2, len(seen), 'two explicit invocations, never a retry inside one')
        self.assertEqual(2, len(FakeClient.instances), 'each invocation builds its own client')
        self.assertEqual(canonical(seen[0]['payload']), canonical(seen[1]['payload']),
                         'the resubmitted statement is the same statement')
        self.assertEqual(statement(), seen[1]['payload'])


class MainReviewTests(VerificationFixture):
    """Regression controls from main's review of the independently drafted implementation/tests."""

    def test_http_protocol_failures_are_sanitized_without_retry(self) -> None:
        path = self.write('statement.json', json.dumps(statement()))
        for failure in (http.client.IncompleteRead(SERVER_SENTINEL.encode()),
                        http.client.BadStatusLine(SERVER_SENTINEL),
                        http.client.LineTooLong(SERVER_SENTINEL),
                        http.client.InvalidURL(SERVER_SENTINEL)):
            with self.subTest(exception=type(failure).__name__):
                result = self.invoke(*self.verify('submit', '--statement', str(path)), failure=failure)
                self.assert_cli_error(result)
                self.assert_one_request('POST', SUBMIT_PATH, statement())
                self.assert_quiet(result)

    def test_a_bad_port_is_refused_by_real_http_without_connecting(self) -> None:
        with mock.patch.object(http.client.HTTPSConnection, 'connect',
                               side_effect=AssertionError('unexpected network')) as connect:
            result = self.invoke(*self.verify('binding', '--action-id', ACTION_ID,
                                              url='https://verify.invalid:notaport'), client=False)
        self.assert_cli_error(result)
        self.assert_quiet(result)
        connect.assert_not_called()

    def test_raw_file_limits_are_not_windows_text_mode_limits(self) -> None:
        raw = json.dumps(statement()).encode('utf-8')
        cases = [('token-ctrl-z', self.verify('binding', '--action-id', ACTION_ID), self.token,
                  TOKEN.encode() + b'\x1a' + b'x' * 4096),
                 ('token-crlf', self.verify('binding', '--action-id', ACTION_ID), self.token,
                  b'v' * 4095 + b'\r\n'),
                 ('statement-ctrl-z', None, self.root / 'statement.json', raw + b'\x1aextra'),
                 ('statement-crlf', None, self.root / 'statement.json',
                  raw + b' ' * (MAX_RECORD_BYTES - len(raw) - 1) + b'\r\n')]
        for label, argv, path, payload in cases:
            with self.subTest(case=label):
                self.token.write_bytes(TOKEN.encode())
                path.write_bytes(payload)
                self.assert_refused_input(*(argv or self.verify('submit', '--statement', str(path))))

    def test_validated_document_is_sent_without_storage_normalization(self) -> None:
        document = statement()
        document['window']['start'] = '2026-09-08T12:00:00Z'
        document['receipt']['window']['start'] = document['window']['start']
        normalized = verification_records._incoming(document)
        self.assertNotEqual(document, normalized, 'fixture must distinguish validation from rewriting')
        path = self.write('original.json', json.dumps(document))
        result = self.invoke(*self.verify('submit', '--statement', str(path)))
        self.assertEqual(0, result.code)
        self.assert_one_request('POST', SUBMIT_PATH, document)

    def test_empty_available_samples_are_for_the_server_to_judge(self) -> None:
        document = statement()
        document['samples'] = []
        verification_records._incoming(document)
        path = self.write('empty.json', json.dumps(document))
        result = self.invoke(*self.verify('submit', '--statement', str(path)))
        self.assertEqual(0, result.code)
        self.assert_one_request('POST', SUBMIT_PATH, document)

    def test_invalid_ids_are_refused_before_opening_any_file(self) -> None:
        with mock.patch.object(verification_cli.os, 'open', side_effect=AssertionError('file opened')):
            for operation, option, value in (('binding', '--action-id', 'a' * 100000),
                                             ('records', '--execution-id', EXECUTION_ID.upper()),
                                             ('record', '--verification-id', 'z' * 64)):
                with self.subTest(operation=operation):
                    self.assert_refused_input(*self.verify(operation, option, value))


if __name__ == '__main__':
    unittest.main()

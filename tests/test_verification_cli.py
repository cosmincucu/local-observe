"""Wave 11 : the HTTPS-only `verification` group of `lo-platform`.

`verification_cli.py` (`add_parser`, `run`) and the dispatch seam in `cli.main()` are tested here as the
wave-11 contract froze them. The group is a *client*: validate what the operator typed, read one
credential and one statement from named files, make **one** request through the existing `JsonClient`,
print the server's answer. It judges nothing — no policy, no verdict, no clock, no database — so the
interesting inputs are the ones that would otherwise be *interpreted*: a second spelling of an id, a
duplicate key, a number JSON cannot mean, a credential file that is a FIFO, a statement one byte over.

Every claim is read from the transport seam: each `request` is counted, and an unscripted second call
raises `AssertionError`, which `run` deliberately does not catch, so a hidden retry fails the test rather
than looking like an exit status. Bad input spends nothing: no client is constructed before the ids and
the statement validate, and the credential waits for those. Both fixed error objects are compared
exactly, so no token, path, traceback, cause or server body can ride out in them. `Store`,
`NotificationPolicy` and `notification_mode` are poisoned, while `status` and `pathcheck` run for real --
the tests the dispatch would break by swallowing them. `JsonClient` is patched at the *new module's*
binding by a subclass keeping the real constructor's bounds; `cli`'s binding refuses to be built, so the
wrong binding fails instead of dialling out.
"""
from __future__ import annotations

import contextlib
import io
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import uuid
from typing import Any

from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import canonical
from local_observe.platform import cli, verification_cli
from local_observe.platform.verification_records import INTEGER_LIMIT, MAX_RECORD_BYTES

TOKEN = 'vErifier-Token-0123456789abcdef'
BASE = 'https://platform.example/lo'
ACTION = str(uuid.uuid4())
EXECUTION = str(uuid.uuid4())
RESOURCE = str(uuid.uuid4())
BINDING = 'a' * 64
VERIFICATION = 'b' * 64
LOCAL_REFUSAL = {'status': 'error', 'error_type': 'VerificationCLIError'}
HTTP_REFUSAL = 'VerificationHTTPError'
WINDOW = {'start': '2026-09-08T12:00:00+00:00', 'end': '2026-09-08T12:05:00+00:00'}
#: Each operation's identity flag, spelled the way the frozen contract spells it.
FLAGS = {'binding': 'action-id', 'records': 'execution-id', 'record': 'verification-id',
         'submit': 'statement'}


def statement(**changes) -> dict:
    """One complete submitted observation: the six record keys, nothing else, changed only as asked.

    Shape-valid for `verification_records._incoming`, with no store, policy or clock involved.
    """
    document = {'execution_id': EXECUTION, 'binding_id': BINDING, 'window': WINDOW,
                'outcome': 'available',
                'receipt': {'expires_at': '2026-09-08T13:00:00+00:00',
                            'parameters': {'artifact_sha256': BINDING, 'resource_id': RESOURCE,
                                           'rule_id': 'inspect.cpu'},
                            'query_type': 'metric-threshold', 'sample_count': 1, 'truncated': False,
                            'window': WINDOW},
                'samples': [{'metric_name': 'lo_cpu', 'observed_at': '2026-09-08T12:04:00+00:00',
                             'resource_id': RESOURCE, 'value': 70.0}]}
    document.update(changes)
    return document


def nested(depth: int) -> Any:
    """One value nested *depth* levels deep, for a document no bounds walk may walk to the bottom."""
    value: Any = 1
    for _ in range(depth):
        value = [value]
    return value


class ScriptedClient(JsonClient):
    """The real constructor's bounds, a scripted answer, and no socket anywhere near it.

    Subclassing rather than replacing `__init__` is the point: `https://`, the 1..20 s timeout and the CA
    file are refused by `JsonClient` itself, so "bad config spends no request" proves the real bounds ran.
    """

    constructions: list = []
    instances: list = []
    script: list = []

    @classmethod
    def reset(cls) -> None:
        cls.constructions, cls.instances, cls.script = [], [], []

    def __init__(self, *args, **kwargs) -> None:
        ScriptedClient.constructions.append((args, kwargs))
        super().__init__(*args, **kwargs)
        self.calls: list = []
        ScriptedClient.instances.append(self)

    def request(self, method, path='', payload=None, *, headers=None, timeout=None):
        self.calls.append((method, path, payload))
        if not ScriptedClient.script:
            raise AssertionError('a second request was made inside one invocation')
        outcome = ScriptedClient.script.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class ForbiddenClient:
    """`cli`'s transport binding: constructing it here would be both a bug and a real outbound call."""

    def __init__(self, *args, **kwargs) -> None:
        raise AssertionError('the verification group must build its client at its own module binding')


def forbidden(name: str):
    """A local-only seam `main` reaches after the dispatch point; calling it fails the test."""

    def reached(*args, **kwargs):
        raise AssertionError(f'{name} was reached by a verification run')

    return reached


class VerificationCliFixture(unittest.TestCase):
    """A credential file, a statement file, both transport bindings patched, a clean notification mode."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.token_file = self.root / 'verifier.token'
        self.statement_file = self.root / 'statement.json'
        self.database = self.root / 'absent.db'
        self.write_token(TOKEN + '\n')
        ScriptedClient.reset()
        for target in (verification_cli, cli):
            patcher = mock.patch.object(
                target, 'JsonClient', ScriptedClient if target is verification_cli else ForbiddenClient)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.enterContext(mock.patch.dict(os.environ))
        os.environ.pop(cli.MODE_ENVIRONMENT, None)

    # ------------------------------------------------------------------ fixtures

    def write_token(self, content) -> Path:
        self.token_file.write_bytes(content if isinstance(content, bytes) else content.encode())
        return self.token_file

    def write_statement(self, content) -> Path:
        self.statement_file.write_bytes(content if isinstance(content, bytes) else content.encode())
        return self.statement_file

    def rewrite(self, document: dict, pair: str, replacement: str) -> str:
        """Replace one printed pair of *document*, so each edge case stays about this statement."""
        text = json.dumps(document)
        self.assertEqual(1, text.count(pair), f'the statement fixture must name {pair} exactly once')
        return text.replace(pair, replacement)

    # ------------------------------------------------------------------ running

    def cli(self, *argv: str, real_store: bool = False) -> tuple[int, str, str]:
        """Run `lo-platform` in-process over *argv*; return `(exit status, stdout, stderr)`.

        The seams `main` touches after the verification dispatch are poisoned, unless `real_store` names
        the legacy controls that genuinely have to open a database.
        """
        guards = [mock.patch.object(cli, name, forbidden(name))
                  for name in ('NotificationPolicy', 'notification_mode')]
        if not real_store:
            guards.append(mock.patch.object(cli, 'Store', forbidden('Store')))
        printed, logged = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', ['lo-platform', *argv]), contextlib.ExitStack() as stack:
            for guard in guards:
                stack.enter_context(guard)
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                try:
                    code = cli.main()
                except SystemExit as caught:
                    code = caught.code
        return code, printed.getvalue(), logged.getvalue()

    # ------------------------------------------------------------------ assertions

    def sent(self) -> list:
        """Every `request` the patched transport saw, across every client that was actually built."""
        return [call for client in ScriptedClient.instances for call in client.calls]

    def answer(self, *outcomes) -> None:
        """Clear the seam and script the answers this invocation's single request may give."""
        ScriptedClient.reset()
        ScriptedClient.script = list(outcomes)

    def assert_refused(self, *argv: str, constructions: int = 0, requests: int = 0) -> None:
        """One fixed local refusal and exit 1, having spent exactly the builds and calls it should.

        The two counts separate this group's three refusal distances: bad input (neither), bad transport
        configuration (a build that faulted before any call), an unusable *answer* (one call spent).
        """
        code, printed, logged = self.cli(*argv)
        self.assertEqual(1, code, f'{argv} must be refused with status 1; stdout was {printed!r}')
        self.assertEqual(LOCAL_REFUSAL, json.loads(printed))
        self.assertNotIn(TOKEN, printed + logged, 'a credential never reaches stdout or the log stream')
        self.assertNotIn(str(self.root), printed + logged, 'a refusal names no local path')
        self.assertNotIn('Traceback', printed + logged)
        self.assertEqual(requests, len(self.sent()), 'a refused invocation spends no request of its own')
        self.assertEqual(constructions, len(ScriptedClient.constructions),
                         'the transport is built only after the input and the credential are admitted')

    def assert_syntax_refused(self, *argv: str) -> None:
        """argparse exits 2 and prints nothing on stdout, before any file, credential or transport."""
        code, printed, _ = self.cli(*argv)
        self.assertEqual(2, code, f'{argv} is a syntax refusal: exit 2, not {code}')
        self.assertEqual('', printed, 'a syntax refusal prints no JSON object at all')
        self.assertEqual([], self.sent())
        self.assertEqual([], ScriptedClient.constructions)

    def group(self, operation: str, *argv: str) -> list:
        """The `verification` argv every case shares: base, credential file, then the operation."""
        return ['verification', '--url', BASE, '--token-file', str(self.token_file), operation, *argv]


class TransportTests(VerificationCliFixture):
    """The four requests, the credential's only source, and the two answers an operator can act on."""

    def test_binding_read_makes_the_frozen_request_exactly_once(self) -> None:
        """One GET of the captured binding, addressed by canonical action id, nothing else sent."""
        returned = {'action_id': ACTION, 'status': 'bound', 'reason': 'matched', 'binding_id': BINDING,
                    'origin': {'threshold': 90.0, 'metric_name': 'lo_cpu', 'window_seconds': 300},
                    'value': None, 'samples': [], 'note': 'ok \u00e9'}
        self.answer((200, returned))
        code, printed, _ = self.cli(*self.group('binding', '--action-id', ACTION))
        self.assertEqual(0, code)
        self.assertEqual([('GET', f'/v1/verification/binding?action_id={ACTION}', None)], self.sent())
        self.assertEqual((BASE, TOKEN), ScriptedClient.constructions[0][0])
        self.assertEqual({'timeout': 10, 'ca_file': None}, ScriptedClient.constructions[0][1],
                         'the documented default timeout, and no CA override asked for')
        self.assertEqual(json.dumps(returned, indent=2) + '\n', printed,
                         'the server object is printed verbatim: nested fields, nulls, floats and text, '
                         'with nothing synthesised into it or renamed on the way out')
        self.assertEqual(returned, json.loads(printed))

    def test_the_other_two_reads_name_their_own_query_parameter(self) -> None:
        """`records` addresses an execution and `record` one verification id; the paths stay distinct."""
        cases = {'records': (EXECUTION, f'/v1/verification/records?execution_id={EXECUTION}'),
                 'record': (VERIFICATION, f'/v1/verification/record?verification_id={VERIFICATION}')}
        for operation, (value, expected) in cases.items():
            with self.subTest(operation=operation):
                self.answer((200, {'status': 'ok'}))
                code, printed, _ = self.cli(*self.group(operation, '--' + FLAGS[operation], value))
                self.assertEqual(0, code)
                self.assertEqual([('GET', expected, None)], self.sent())
                self.assertEqual({'status': 'ok'}, json.loads(printed))

    def test_submit_posts_the_validated_statement_once(self) -> None:
        """The payload is the operator's own document, key for key: no normalising, no grading."""
        submitted = statement()
        self.write_statement(json.dumps(submitted))
        self.answer((200, {'verification_id': VERIFICATION, 'created': True}))
        code, printed, _ = self.cli(*self.group('submit', '--statement', str(self.statement_file)))
        self.assertEqual(0, code)
        self.assertEqual([('POST', '/v1/verification/records', submitted)], self.sent())
        self.assertEqual({'verification_id': VERIFICATION, 'created': True}, json.loads(printed))
        payload = self.sent()[0][2]
        self.assertEqual(WINDOW, payload['window'], 'no timestamp rewriting on the way out')
        self.assertEqual(70.0, payload['samples'][0]['value'], 'no grading, no verdict invented')
        canonical(payload)

    def test_a_configured_base_path_reaches_the_transport_untouched(self) -> None:
        """An endpoint behind a base path is the operator's to configure, as `JsonClient` supports."""
        self.answer((200, {}))
        code, _, _ = self.cli('verification', '--url', BASE + '/api/', '--token-file',
                              str(self.token_file), 'binding', '--action-id', ACTION)
        self.assertEqual(0, code)
        self.assertEqual(BASE + '/api', ScriptedClient.instances[0].base)
        self.assertEqual([('GET', f'/v1/verification/binding?action_id={ACTION}', None)], self.sent())

    def test_the_credential_comes_from_the_token_file_alone(self) -> None:
        """Outer whitespace stripped, and no other source admitted: the flag names a file or nothing runs."""
        self.write_token(' \n\t' + TOKEN + '\r\n')
        self.answer((200, {}))
        code, printed, _ = self.cli(*self.group('binding', '--action-id', ACTION))
        self.assertEqual(0, code)
        self.assertEqual(TOKEN, ScriptedClient.instances[0].token)
        self.assertEqual('Bearer', ScriptedClient.instances[0].scheme)
        self.assertFalse(ScriptedClient.instances[0].accept_non_json,
                         'a verification answer is a JSON object or this run is refused')
        self.assertNotIn(TOKEN, printed)
        self.answer()
        self.assert_syntax_refused('verification', '--url', BASE, 'binding', '--action-id', ACTION)

    def test_only_timeout_and_ca_file_reach_the_transport(self) -> None:
        """What is pinned is the *handover*: `--ca-file` arrives at the constructor, the default timeout is
        10, and no insecure option is ever offered. The refusal below is `JsonClient`'s own bound.
        """
        self.write_statement(json.dumps(statement()))
        self.answer((200, {}))
        code, _, _ = self.cli('verification', '--url', BASE, '--token-file', str(self.token_file),
                              '--timeout', '7', 'submit', '--statement', str(self.statement_file))
        self.assertEqual(0, code)
        self.assertEqual((BASE, TOKEN), ScriptedClient.constructions[0][0])
        self.assertEqual({'timeout': 7, 'ca_file': None}, ScriptedClient.constructions[0][1])
        self.answer((200, {}))
        self.assert_refused('verification', '--url', BASE, '--token-file', str(self.token_file),
                            '--ca-file', str(self.token_file), 'binding', '--action-id', ACTION,
                            constructions=1)
        self.assertEqual({'timeout': 10, 'ca_file': self.token_file},
                         ScriptedClient.constructions[0][1],
                         'the default timeout, and the named authority handed to the transport')
        for _, kwargs in ScriptedClient.constructions:
            self.assertNotIn('allow_http', kwargs, 'no insecure escape hatch exists on this group')

    def test_every_error_status_answers_one_fixed_object(self) -> None:
        """No body, no reason phrase, no driver message: the status is the whole diagnosis, 503 twice."""
        for status in (301, 400, 401, 403, 404, 409, 429, 500, 502, 503):
            with self.subTest(status=status):
                self.answer((status, None))
                code, printed, _ = self.cli(*self.group('binding', '--action-id', ACTION))
                self.assertEqual(1, code)
                self.assertEqual({'status': 'error', 'error_type': HTTP_REFUSAL, 'http_status': status},
                                 json.loads(printed))
                self.assertEqual(1, len(self.sent()))

    def test_one_attempt_is_all_a_failure_ever_gets(self) -> None:
        """A timeout, a refused connection and a lost submit acknowledgement: one attempt each, once.

        The submit case is the load-bearing one. Whether the server accepted that statement is unknowable
        from here, so a fixed object and exit 1 are the only honest answers, and no word like `rollback`
        may claim a rewind of an append-only record.
        """
        self.write_statement(json.dumps(statement()))
        faults = (TransportError('Endpoint unavailable or invalid JSON response'), OSError('reset'))
        for index, argv in enumerate((self.group('records', '--execution-id', EXECUTION),
                                      self.group('submit', '--statement', str(self.statement_file)))):
            with self.subTest(operation=argv[-3]):
                self.answer(faults[index])
                code, printed, logged = self.cli(*argv)
                self.assertEqual(1, code)
                self.assertEqual(LOCAL_REFUSAL, json.loads(printed))
                self.assertEqual(1, len(self.sent()), 'the statement may already be stored; send it once')
                self.assertNotIn('Traceback', printed + logged)
                for word in ('retry', 'retried', 'rollback', 'rolled back'):
                    self.assertNotIn(word, (printed + logged).lower())

    def test_an_unusable_success_answer_is_a_local_error(self) -> None:
        """A 200 that is not an object, or that carries a number JSON cannot express, is refused.

        `JsonClient` decodes with permissive defaults, so `NaN` really can arrive in a valid response; it
        must never be printed as if it were an answer about a verification record.
        """
        for document in (None, [], [{'verification_id': VERIFICATION}], VERIFICATION, 200, True,
                         {'value': float('nan')}, {'value': float('inf')},
                         {'nested': [{'value': -math.inf}]}):
            with self.subTest(document=document):
                self.answer((200, document))
                self.assert_refused(*self.group('record', '--verification-id', VERIFICATION),
                                    constructions=1, requests=1)


class DispatchTests(VerificationCliFixture):
    """Where the group sits in `main`, and everything it must therefore never touch."""

    def test_verification_refuses_a_database_as_a_syntax_error(self) -> None:
        """`--database` is global, so it is offered both in its global position (where the parse succeeds
        and only the conflict refusal can answer) and after the command word: both exit 2, neither opens.
        """
        self.assert_syntax_refused('--database', str(self.database), 'verification', '--url', BASE,
                                   '--token-file', str(self.token_file), 'binding', '--action-id', ACTION)
        self.assert_syntax_refused('--database', str(self.database), 'verification', '--url', BASE,
                                   '--token-file', str(self.token_file), 'submit',
                                   '--statement', str(self.statement_file))
        self.assertFalse(self.database.exists(), 'the refused path is never opened, let alone created')

    def test_verification_never_creates_a_local_database(self) -> None:
        """A successful read and a successful submit leave the scratch tree as they found it."""
        self.write_statement(json.dumps(statement()))
        for operation, argv in (('binding', ('--action-id', ACTION)),
                                ('submit', ('--statement', str(self.statement_file)))):
            with self.subTest(operation=operation):
                self.answer((200, {'status': 'ok'}))
                code, printed, _ = self.cli(*self.group(operation, *argv))
                self.assertEqual(0, code)
                self.assertIn('"status": "ok"', printed, 'the server answer is what was printed')
                self.assertEqual(1, len(self.sent()))
                self.assertEqual([], [path.name for path in self.root.iterdir()
                                      if path.suffix in ('.db', '.db-wal', '.db-shm')])

    def test_missing_conflicting_and_unknown_syntax_exits_two(self) -> None:
        """Every syntax problem is argparse's, and none of them reaches a file, a credential or a socket."""
        full = ['verification', '--url', BASE, '--token-file', str(self.token_file)]
        notoken = ['verification', '--url', BASE]
        nofile = ['verification', '--token-file', str(self.token_file)]
        cases = {
            'no operation': list(full),
            'unknown operation': [*full, 'digest'],
            'missing --url': [*notoken, 'binding', '--action-id', ACTION],
            'missing --token-file': [*nofile, 'binding', '--action-id', ACTION],
            'missing --action-id': [*full, 'binding'],
            'conflicting identities': [*full, 'binding', '--action-id', ACTION, '--execution-id',
                                        EXECUTION],
            'an option after the operation': [*full, 'binding', '--url', BASE, '--action-id', ACTION],
            'a non-integer timeout': [*full, '--timeout', 'soon', 'binding', '--action-id', ACTION],
            'a statement on stdin': [*full, 'submit'],
            'an output file': [*full, 'binding', '--action-id', ACTION, '--output', 'out.json'],
            'an insecure flag': [*full, '--allow-http', 'binding', '--action-id', ACTION],
            'a raw token': [*full, '--token', TOKEN, 'binding', '--action-id', ACTION],
            'a clock override': [*full, 'binding', '--action-id', ACTION, '--now', '2026-09-08T12:00:00Z'],
        }
        for label, argv in cases.items():
            with self.subTest(case=label):
                self.assert_syntax_refused(*argv)

    def test_transport_configuration_refusals_come_from_the_real_client(self) -> None:
        """HTTPS, 1..20 s and a usable CA file are `JsonClient`'s own bounds, enforced before any request."""
        cases = {'plain HTTP endpoint': ['--url', 'http://platform.example'],
                 'an endpoint with credentials': ['--url', 'https://user:pass@platform.example'],
                 'a query on the base': ['--url', BASE + '?next=/elsewhere'],
                 'no timeout': ['--timeout', '0'],
                 'a timeout past the bound': ['--timeout', '21'],
                 'a missing CA file': ['--ca-file', str(self.root / 'absent.pem')],
                 'a CA file that is not a certificate': ['--ca-file', str(self.token_file)]}
        for label, options in cases.items():
            with self.subTest(case=label):
                self.answer()
                # A well-formed `--url` always precedes the case's options, so a refused base cannot mask
                # a refused timeout or authority file.
                self.assert_refused('verification', '--token-file', str(self.token_file), '--url', BASE,
                                    *options, 'binding', '--action-id', ACTION, constructions=1)

    def test_local_commands_still_refuse_a_missing_database(self) -> None:
        """The global flag became syntactically optional and semantically required: still exit 2."""
        commands = dict.fromkeys(('status', 'migrate', 'notify', 'escalate', 'conditions',
                                 'pathcheck'), [])
        commands.update({'backup': ['--output', str(self.root / 'copy.db')],
                         'intake': ['--source', 'x', '--event', str(self.root / 'event.json')],
                         'evaluate': ['--index', str(self.root / 'index.db'), '--rule',
                                      str(self.root / 'rule.json')]})
        for command, argv in commands.items():
            with self.subTest(command=command):
                self.assert_syntax_refused(command, *argv)

    def test_local_commands_still_run_with_a_database(self) -> None:
        """The negative controls that matter: `main` still opens the store and still runs its commands."""
        code, printed, _ = self.cli('--database', str(self.database), 'status', real_store=True)
        self.assertEqual(0, code)
        self.assertEqual({}, json.loads(printed)['incidents'], 'a fresh database has nothing to count')
        self.assertTrue(self.database.exists())
        code, printed, _ = self.cli('--database', str(self.database), 'pathcheck', real_store=True)
        self.assertEqual(0, code)
        self.assertEqual({'status': 'off', 'configured': False}, json.loads(printed),
                         'a peer command and its off switch, untouched by this dispatch edit')

    def test_no_operational_configuration_is_consulted(self) -> None:
        """A mode `notify` would refuse cannot touch a verification run, because it is never read."""
        for value in ('', 'not-a-mode', 'live'):
            with self.subTest(mode=value):
                os.environ[cli.MODE_ENVIRONMENT] = value
                self.answer((200, {'status': 'ok'}))
                code, printed, _ = self.cli(*self.group('binding', '--action-id', ACTION))
                self.assertEqual(0, code, f'{value!r} in the environment must not be read here')
                self.assertIn('"status": "ok"', printed)

    def test_bad_input_is_refused_before_the_credential_is_opened(self) -> None:
        """Ordering, probed directly: `_token` is raised to `AssertionError`, a class `run` deliberately
        does not catch, so a credential opened before validation errors instead of quietly passing.
        """
        self.write_statement('{"execution_id": "not-a-uuid"}')
        cases = [('binding', ('--action-id', 'not-a-uuid')),
                 ('record', ('--verification-id', 'c' * 63)),
                 ('submit', ('--statement', str(self.statement_file)))]
        for operation, argv in cases:
            with self.subTest(operation=operation), mock.patch.object(
                    verification_cli, '_token', side_effect=AssertionError('credential opened too early')):
                self.answer()
                code, printed, _ = self.cli(*self.group(operation, *argv))
                self.assertEqual(1, code)
                self.assertEqual(LOCAL_REFUSAL, json.loads(printed))
                self.assertEqual([], self.sent())


class InputTests(VerificationCliFixture):
    """The inputs the group refuses, and the two bounds it admits."""

    def test_invalid_identities_spend_no_request(self) -> None:
        """Canonical UUID text and lowercase hex only: nothing is quoted, escaped, folded or trimmed."""
        bad_uuids = ['', ' ', ACTION.upper(), ACTION.replace('-', ''), ACTION[:-1], ACTION + ' ',
                     ' ' + ACTION, '{' + ACTION + '}', 'urn:uuid:' + ACTION,
                     ACTION.replace('-', '%2d'), '../../etc/passwd', 'a&b', 'x' * 36, BINDING, '0' * 36,
                     f'{ACTION}?execution_id={EXECUTION}', f'{ACTION}#fragment']
        bad_digests = ['', BINDING.upper(), BINDING[:-1], BINDING + 'a', 'g' * 64, ACTION,
                       ' ' + BINDING, BINDING.replace('a', '%61'), '../../', 'sha256:' + BINDING,
                       'a&b', '0' * 65]
        for value in bad_uuids:
            with self.subTest(action_id=repr(value)):
                self.assert_refused(*self.group('binding', '--action-id', value))
                self.assert_refused(*self.group('records', '--execution-id', value))
        for value in bad_digests:
            with self.subTest(verification_id=repr(value)):
                self.assert_refused(*self.group('record', '--verification-id', value))

    def test_the_input_files_must_be_regular_bounded_files(self) -> None:
        """Missing, a directory, empty, one byte over the bound — credential and statement alike."""
        for name, path, limit, argv in (
                ('credential', self.token_file, 4_096, self.group('binding', '--action-id', ACTION)),
                ('statement', self.statement_file, MAX_RECORD_BYTES,
                 self.group('submit', '--statement', str(self.statement_file)))):
            with self.subTest(file=name):
                path.unlink(missing_ok=True)
                self.assert_refused(*argv)
                path.mkdir()
                self.assert_refused(*argv)
                path.rmdir()
                path.write_bytes(b'')
                self.assert_refused(*argv)
                path.write_bytes(b'v' * (limit + 1))
                self.assert_refused(*argv)

    @unittest.skipUnless(hasattr(os, 'mkfifo') and os.name == 'posix', 'POSIX offers mkfifo')
    def test_a_fifo_credential_never_blocks_the_read(self) -> None:
        """`O_NONBLOCK` plus `fstat`: a writerless FIFO is refused, not waited on forever."""
        fifo = self.root / 'pipe.token'
        os.mkfifo(fifo)
        self.assert_refused('verification', '--url', BASE, '--token-file', str(fifo), 'binding',
                            '--action-id', ACTION)

    def test_credential_content_must_be_bounded_printable_ascii(self) -> None:
        """24..4096 bytes inside 0x21..0x7e once outer whitespace is gone, and nothing is ever echoed."""
        for content in ('v' * 23, 'vvv\n' + 'v' * 30, 'verb 0123456789abcdef0123456789',
                        'verb\t0123456789abcdef0123456789', 'v\u00e9rif-0123456789abcdef0123456789',
                        ('v' * 30).encode('utf-16'), b'\xff\xfe' + b'v' * 30, b'{"t": \xc3}'):
            with self.subTest(rejected=repr(content)[:24]):
                self.write_token(content)
                self.assert_refused(*self.group('binding', '--action-id', ACTION))
        for index, content in enumerate(('v' * 24, TOKEN + '\r\n', 'v' * 4_096, 'v' * 4_095 + '\n')):
            with self.subTest(accepted=index):
                self.write_token(content)
                self.answer((200, {}))
                code, _, _ = self.cli(*self.group('binding', '--action-id', ACTION))
                self.assertEqual(0, code)
                self.assertEqual(content.strip(), ScriptedClient.instances[0].token)

    def test_a_symlinked_credential_is_not_refused_for_being_a_symlink(self) -> None:
        """No symlink policy is invented here, so this keeps working and keeps reading its target."""
        target, link = self.root / 'real.token', self.root / 'linked.token'
        target.write_text(TOKEN + '\n')
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest('this filesystem offers no symlinks')
        self.answer((200, {}))
        code, _, _ = self.cli('verification', '--url', BASE, '--token-file', str(link), 'binding',
                              '--action-id', ACTION)
        self.assertEqual((0, TOKEN), (code, ScriptedClient.instances[0].token))

    def test_a_statement_up_to_the_raw_bound_is_accepted(self) -> None:
        """The bound is inclusive and measured on the file as read, so padding costs no request."""
        plain = json.dumps(statement())
        cases = (('bare', plain), ('at the raw bound', plain + ' ' * (MAX_RECORD_BYTES - len(plain))))
        for label, text in cases:
            with self.subTest(case=label):
                self.write_statement(text)
                self.answer((200, {'verification_id': VERIFICATION, 'created': True}))
                argv = self.group('submit', '--statement', str(self.statement_file))
                code, printed, _ = self.cli(*argv)
                self.assertEqual(0, code)
                self.assertEqual(1, len(self.sent()))
                self.assertEqual(statement(), self.sent()[0][2])
                self.assertEqual({'verification_id': VERIFICATION, 'created': True}, json.loads(printed))

    def test_statement_json_edges_are_refused(self) -> None:
        """Everything `json.loads` admits by default and this product must not: see each case's label."""
        edges = {
            'a duplicated top-level key': self.rewrite(statement(), '"outcome": "available"',
                                                       '"outcome": "available", "outcome": "unavailable"'),
            'a duplicated nested key': self.rewrite(statement(), '"truncated": false',
                                                    '"truncated": false, "truncated": true'),
            'deeper than the storage bounds': json.dumps(statement(samples=nested(40))),
            'deeper than the parser survives': self.rewrite(statement(samples=[]), '"samples": []',
                                                            '"samples": ' + '[' * 400 + ']' * 400),
            'an array at the top level': '[1, 2]',
            'the statement as an array of its keys': json.dumps(list(statement())),
            'not JSON at all': '{',
            'UTF-16 bytes': json.dumps(statement()).encode('utf-16'),
            'invalid UTF-8': b'{"execution_id": "' + ACTION.encode() + b'", \xc3}',
        }
        numbers = {'a NaN constant': 'NaN', 'an Infinity constant': 'Infinity',
                   'a negative Infinity constant': '-Infinity', 'a float overflowing to inf': '1e999',
                   'an integer over signed 64': str(INTEGER_LIMIT + 1)}
        for label, spelling in numbers.items():
            edges[label] = self.rewrite(statement(), '"value": 70.0', f'"value": {spelling}')
        for label, content in edges.items():
            with self.subTest(case=label):
                self.write_statement(content)
                self.assert_refused(*self.group('submit', '--statement', str(self.statement_file)))

    def test_an_integer_at_the_platform_bound_is_accepted(self) -> None:
        """`INTEGER_LIMIT` is storage's own number, so the edge is inclusive and not a second policy."""
        self.write_statement(self.rewrite(statement(), '"value": 70.0', f'"value": {INTEGER_LIMIT}'))
        self.answer((200, {'created': True}))
        code, _, _ = self.cli(*self.group('submit', '--statement', str(self.statement_file)))
        self.assertEqual(0, code)
        payload = self.sent()[0][2]
        self.assertEqual(INTEGER_LIMIT, payload['samples'][0]['value'],
                         'the submitted spelling travels; the server normalises and grades')

    def test_statement_shape_is_refused_by_the_storage_layer_itself(self) -> None:
        """No verdict, no note, no extra key, no missing key, and no id this layer would guess at."""
        shapes = {
            'a verdict of its own': statement(verdict='cleared'),
            'a free-text note': statement(note='it recovered'),
            'no sample list': {key: value for key, value in statement().items() if key != 'samples'},
            'an invented read outcome': statement(outcome='recovered'),
            'an unanswered read still claiming rows': statement(outcome='unavailable'),
            'a non-canonical execution id': statement(execution_id=EXECUTION.upper()),
            'an uppercase binding id': statement(binding_id=BINDING.upper()),
            'a window that does not run forward': statement(
                window={'start': WINDOW['end'], 'end': WINDOW['start']}),
            'more rows than the read claims': statement(receipt=dict(statement()['receipt'],
                                                                     sample_count=0)),
        }
        for label, document in shapes.items():
            with self.subTest(case=label):
                self.write_statement(json.dumps(document))
                self.assert_refused(*self.group('submit', '--statement', str(self.statement_file)))

    def test_resubmitting_a_statement_is_two_explicit_invocations(self) -> None:
        """An immutable replay is two operator decisions; one invocation never contains a retry."""
        self.write_statement(json.dumps(statement()))
        argv = self.group('submit', '--statement', str(self.statement_file))
        seen = []
        for invocation in (1, 2):
            with self.subTest(invocation=invocation):
                self.answer((200, {'verification_id': VERIFICATION, 'created': invocation == 1}))
                code, printed, _ = self.cli(*argv)
                self.assertEqual(0, code)
                self.assertEqual(1, len(ScriptedClient.instances), 'one client built per invocation')
                self.assertEqual(1, len(self.sent()), 'and exactly one request inside it')
                self.assertEqual(statement(), self.sent()[0][2], 'the unchanged statement again')
                self.assertEqual(invocation == 1, json.loads(printed)['created'])
                seen.append(self.sent()[0][2])
        self.assertEqual(seen[0], seen[1])


if __name__ == '__main__':
    unittest.main()

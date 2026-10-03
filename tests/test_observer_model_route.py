"""Optional gateway deployment guard: transport matching, provenance binding and refusals.

Every response here comes from a fake opener, so the checks are about which single response header
reaches which call -- no host is contacted and no gateway is configured. Synthetic names only:
``example-model`` is the alias in the envelope, ``backend-a``/``backend-b`` are expected deployment IDs.
"""
from __future__ import annotations

import datetime as dt
import email.message
import hashlib
import json
import logging
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch

from local_observe.ai.budget import DEFAULTS as BUDGET
from local_observe.ai.client import AiClient
from local_observe.http import JsonClient, ResponseHeader, TransportError
from local_observe.observer import Config, Journal, Observer, ObserverError, Source
from local_observe.observer.adapters import Model
from local_observe.observer.contract import encoded, snapshot, utc
from local_observe.observer.environment import load_environment, validate_environment
from local_observe.observer.model_route import (DEPLOYMENT_HEADER, DEPLOYMENT_VARIABLE, DeploymentGuard,
                                                declared_deployment, deployment_id, expected_deployment,
                                                guard_client, route_label)
from local_observe.observer.provenance import build_provenance, label, validate_provenance
import urllib.error

NOW = dt.datetime(2026, 1, 1, 12, tzinfo=dt.timezone.utc)
RESOURCE = '00000000-0000-4000-8000-000000000001'
SOURCE = Source('cpu', 'metric-threshold', RESOURCE, metric_name='cpu.utilization')
CONFIG = Config((SOURCE,))
WINDOW = {'start': '2026-01-01T11:00:00Z', 'end': '2026-01-01T12:00:00Z'}
ALIAS = 'example-model'
TOKEN = 'example-token-' + 'x' * 32

ENVELOPE = {'schema_version': 1, 'source': SOURCE.id, 'query_type': SOURCE.query_type,
            'resource_id': SOURCE.resource_id, 'window': WINDOW, 'observed_at': utc(NOW),
            'rows': [{'timestamp': '2026-01-01T11:59:00Z', 'value': 0.8, 'labels': {}}]}
EVIDENCE = [snapshot(SOURCE, ENVELOPE, WINDOW, CONFIG, NOW)]


def reply_text():
    item = EVIDENCE[0]
    return encoded({'schema_version': 1, 'decision': 'watch', 'rationale': 'The retained sample warrants review.',
                    'citations': [{'evidence_id': item['evidence_id'], 'row_index': 0, 'field': 'value',
                                   'value': item['rows'][0]['value']}], 'follow_up': []})


def completion_body(*, model=ALIAS, extra=None):
    body = {'id': 'resp-1', 'model': model, 'usage': {'prompt_tokens': 11, 'completion_tokens': 7},
            'choices': [{'message': {'content': reply_text()}, 'finish_reason': 'stop'}]}
    return {**body, **(extra or {})}


class FakeResponse:
    """The three attributes `JsonClient` reads off a opened response: status, bytes, headers."""

    def __init__(self, body=None, headers=(), status=200):
        self.status = status
        self.body = encoded(body).encode() if body is not None else b''
        self.headers = email.message.Message()
        for pair in headers:
            self.headers[pair[0]] = pair[1]

    def duplicate(self, name, values):
        for value in values:
            self.headers.add_header(name, value)
        return self

    def read(self, limit=-1):
        return self.body if limit is None or limit < 0 else self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """One queued answer per attempt, in order; an exception answer fails that attempt instead."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, timeout))
        if not self.responses:
            raise AssertionError('the fake opener received more requests than the test queued')
        answer = self.responses.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def matching(status=200, extra=None):
    return FakeResponse(completion_body(extra=extra), [(DEPLOYMENT_HEADER, 'backend-a')], status=status)


def answered_as(status):
    """An opener that fails the attempt with one HTTP error status, as `urllib` does."""
    return urllib.error.HTTPError('https://model.invalid/v1/chat/completions', status, 'unavailable',
                                  email.message.Message(), None)


def refused_by_transport():
    """An opener that fails before an answer exists: the same OSError path a timeout takes."""
    return socket.timeout('no answer')


class GuardTestCase(unittest.TestCase):
    """Shared protected fixture files plus a Model whose client answers from queued fakes."""

    def setUp(self):
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        private = self.temp / 'private'
        private.mkdir(mode=0o700)
        key = private / 'ai.key'
        key.write_text(TOKEN, encoding='utf-8')
        key.chmod(0o600)
        policy = {'schema_version': 1, 'classes': {c: {'generate': True, 'remote': False,
                    'redact': ['secret_keys'], 'label': ''} for c in ('public', 'internal', 'restricted')}}
        capability = {'schema_version': 1, 'context_tokens': 8192, 'tools': False, 'json_mode': True,
                      'streaming': False, 'vision': False, 'parallel': 1, 'quant': 'example',
                      'measured_tok_per_s': 1}
        paths = {}
        for name, document in (('policy', policy), ('capability', capability)):
            path = private / (name + '.json')
            path.write_text(encoded(document), encoding='utf-8')
            path.chmod(0o600)
            paths['LO_AI_' + name.upper()] = str(path)
        self.environ = {'LO_AI_BASE_URL': 'https://model.invalid', 'LO_AI_MODEL': ALIAS,
                        'LO_AI_API_KEY_FILE': str(key), 'LO_AI_CAPTURE': '0', 'LO_AI_OUT_OF_LAN': '0',
                        'LO_OBSERVER_MODEL_PROVIDER': 'example-provider',
                        'LO_OBSERVER_MODEL_VERSION': 'weights-v1', **paths}
        blocked = patch.object(socket, 'create_connection', side_effect=AssertionError('real network forbidden'))
        blocked.start()
        self.addCleanup(blocked.stop)

    def model(self, *responses, deployment='backend-a', environ=None):
        """A Model on a real AiClient whose real JsonClient reads from the queued fake opener."""
        values = {**(environ or self.environ)}
        if deployment is not None:
            values.setdefault(DEPLOYMENT_VARIABLE, deployment)
        model = Model(environ=values)
        client = AiClient.from_environment(values)
        self.json = client.transport
        self.assertIsInstance(self.json, JsonClient)
        self.json.opener = FakeOpener(*responses)
        model.client = client
        return model

    def call(self, model):
        return model.complete(EVIDENCE, set(), CONFIG, NOW)

    def expect(self, model, code):
        with self.assertRaises(ObserverError) as caught:
            self.call(model)
        self.assertEqual(str(caught.exception), code)
        return caught.exception


class DerivationTests(unittest.TestCase):
    def test_label_is_a_bounded_digest_holding_neither_input(self):
        value = route_label('weights-v1', 'backend-a')
        self.assertRegex(value, r'^route-sha256:[0-9a-f]{64}$')
        self.assertNotIn('weights-v1', value)
        self.assertNotIn('backend-a', value)
        self.assertEqual(len(value), 77)
        self.assertEqual(label(value), value, 'the version-1 label grammar must admit it')

    def test_digest_recomputes_independently_from_the_two_inputs(self):
        canonical = json.dumps(['weights-v1', 'backend-a'], sort_keys=True, separators=(',', ':'))
        self.assertEqual(route_label('weights-v1', 'backend-a'),
                         'route-sha256:' + hashlib.sha256(canonical.encode()).hexdigest())

    def test_each_change_of_expectation_moves_the_label(self):
        base = route_label('weights-v1', 'backend-a')
        self.assertNotEqual(base, route_label('weights-v2', 'backend-a'))
        self.assertNotEqual(base, route_label('weights-v1', 'backend-b'))
        self.assertNotEqual(base, route_label('weights-v1', '550e8400-e29b-41d4-a716-446655440000'))
        self.assertNotEqual(route_label('a:', 'b'), route_label('a', ':b'), 'the two fields cannot be re-split')

    def test_unknown_version_is_never_turned_into_a_digest(self):
        for version in (None, '', 'unknown', 'Unknown', 'none', 'null', 'unset', 'unmeasured',
                        'a b', 'a\r\nb', 'x' * 200, 1, True, {'v': 1}):
            self.assertIsNone(route_label(version, 'backend-a'), repr(version))

    def test_deployment_id_shape_is_single_bounded_and_credential_free(self):
        for good in ('backend-a', 'gw01', '550e8400-e29b-41d4-a716-446655440000', 'a:b.c_-1'):
            self.assertEqual(deployment_id(good), good)
        for bad in ('', ' ', 'backend b', 'https://gw.invalid/backend-a', '//backend', 'route/backend',
                    'backend+alt', 'backend\r\nX-Other: 1', 'backend\n', 'unknown', 'none',
                    'Bearer ' + 'A' * 40, 'x' * 200, None, 7):
            self.assertIsNone(deployment_id(bad), repr(bad))
        # A credential-shaped string is not refused for its shape: it is refused because it is not the
        # declared deployment ID, and it is never copied anywhere -- only hashed into the derived label.
        self.assertEqual(deployment_id('sk-' + 'A' * 60), 'sk-' + 'A' * 60)

    def test_configuration_is_read_without_ever_being_rewritten(self):
        self.assertIsNone(declared_deployment({}))
        self.assertIsNone(declared_deployment({DEPLOYMENT_VARIABLE: '  '}))
        self.assertEqual(declared_deployment({DEPLOYMENT_VARIABLE: 'backend-a'}), 'backend-a')
        self.assertIsNone(declared_deployment({DEPLOYMENT_VARIABLE: 'backend b'}))
        self.assertEqual(expected_deployment({DEPLOYMENT_VARIABLE: 'backend-a'}), 'backend-a')
        with self.assertRaises(ObserverError) as caught:
            expected_deployment({DEPLOYMENT_VARIABLE: 'backend b'})
        self.assertEqual(str(caught.exception), 'invalid_model_deployment')
        self.assertIsNone(expected_deployment({}), 'unset is unselected, not a refusal')


class EnvironmentTests(unittest.TestCase):
    def test_the_deployment_label_is_allowlisted_and_validated(self):
        base = {'LO_OBSERVER_MODEL_PROVIDER': 'example-provider', 'LO_OBSERVER_MODEL_VERSION': 'weights-v1'}
        self.assertEqual(validate_environment({**base, DEPLOYMENT_VARIABLE: 'backend-a'})[DEPLOYMENT_VARIABLE],
                         'backend-a')
        self.assertEqual(validate_environment({**base, DEPLOYMENT_VARIABLE: '550e8400-e29b-41d4-a716-446655440000'})
                         [DEPLOYMENT_VARIABLE], '550e8400-e29b-41d4-a716-446655440000')
        for value in ('', ' ', 'backend b', 'https://gw.invalid/backend-a', 'backend\r\nx', 'unknown',
                      'Bearer ' + 'A' * 40, 'x' * 200):
            with self.assertRaises(ObserverError, msg=repr(value)):
                validate_environment({**base, DEPLOYMENT_VARIABLE: value})

    def test_ambient_selection_and_absence_survive_the_reader(self):
        ambient = {DEPLOYMENT_VARIABLE: 'backend-a', 'LO_OBSERVER_MODEL_VERSION': 'weights-v1',
                   'LO_SOMETHING_PRIVATE': 'ignored'}
        self.assertEqual(load_environment(None, ambient=ambient)[DEPLOYMENT_VARIABLE], 'backend-a')
        self.assertNotIn('LO_SOMETHING_PRIVATE', load_environment(None, ambient=ambient))
        self.assertNotIn(DEPLOYMENT_VARIABLE, load_environment(None, ambient={'LO_AI_CAPTURE': '0'}))


class ProvenanceTests(GuardTestCase):
    def provenance(self, model):
        return build_provenance(CONFIG, model, response_model=ALIAS)

    def test_unconfigured_keeps_the_explicit_operator_version(self):
        model = self.model(matching(), deployment=None)
        value = self.provenance(model)
        self.assertEqual(value['model_version'], 'weights-v1')
        self.assertEqual(value['provider'], 'example-provider')
        self.assertTrue(validate_provenance(value, require_complete=True)['complete'])
        self.assertIs(model.client.transport, self.json, 'no wrapper is attached when unselected')

    def test_selection_binds_the_expected_deployment_without_naming_it(self):
        value = self.provenance(self.model(matching()))
        self.assertEqual(value['model_version'], route_label('weights-v1', 'backend-a'))
        self.assertTrue(validate_provenance(value, require_complete=True)['complete'])
        self.assertNotIn('backend-a', encoded(value))
        self.assertNotIn('weights-v1', encoded(value))
        self.assertNotIn(TOKEN, encoded(value))

    def test_changing_deployment_or_version_invalidates_accepted_provenance(self):
        accepted = self.provenance(self.model(matching()))
        validate_provenance(accepted, require_complete=True)
        for environ in ({**self.environ, DEPLOYMENT_VARIABLE: 'backend-b'},
                        {**self.environ, 'LO_OBSERVER_MODEL_VERSION': 'weights-v2'},
                        {k: v for k, v in self.environ.items() if k != 'LO_OBSERVER_MODEL_VERSION'},
                        {k: v for k, v in self.environ.items() if k != DEPLOYMENT_VARIABLE}):
            changed = self.provenance(self.model(matching(), deployment=None, environ=environ))
            self.assertNotEqual(changed['sha256'], accepted['sha256'], encoded(sorted(environ)))
            self.assertNotEqual(validate_provenance(changed)['model_version'], accepted['model_version'])

    def test_static_provenance_reflects_the_expectation_before_any_call(self):
        static = build_provenance(CONFIG, self.model(matching()))
        self.assertEqual(static['model_version'], route_label('weights-v1', 'backend-a'))
        self.assertFalse(static['complete'])
        self.assertIsNone(static['response_model'])
        with self.assertRaises(ObserverError):
            validate_provenance(static, require_complete=True)

    def test_unknown_version_stays_unknown_under_the_guard(self):
        environ = {k: v for k, v in self.environ.items() if k != 'LO_OBSERVER_MODEL_VERSION'}
        value = self.provenance(self.model(matching(), environ=environ))
        self.assertIsNone(value['model_version'])
        self.assertFalse(value['complete'])
        model = self.model(matching(), deployment='backend b')
        self.assertIs(model.client.transport, self.json, 'nothing is wrapped before the call')
        self.expect(model, 'invalid_model_deployment')
        self.assertIs(model.client.transport, self.json, 'a malformed expectation is never applied loosely')
        self.assertEqual(model.client.transport.opener.requests, [], 'and it is refused before any request')


class TransportTests(GuardTestCase):
    def test_changed_expectation_rechecks_the_same_client_transport(self):
        model = self.model(matching(), matching())
        self.assertEqual(self.call(model)['status'], 'ok')
        model.environ[DEPLOYMENT_VARIABLE] = 'backend-b'
        self.expect(model, 'model_deployment_mismatch')
        self.assertEqual(model.client.transport.expected, 'backend-b')
        self.assertNotIsInstance(model.client.transport.transport, DeploymentGuard)

    def test_non_text_expectation_cannot_disable_the_guard(self):
        for invalid in (False, 17, [], {}):
            with self.subTest(value=invalid), self.assertRaises(ObserverError):
                expected_deployment({DEPLOYMENT_VARIABLE: invalid})

    def test_matching_deployment_completes_and_wraps_once(self):
        model = self.model(matching(), matching(), matching())
        for _ in range(3):
            result = self.call(model)
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(result['response_model'], ALIAS)
        self.assertIsInstance(model.client.transport, DeploymentGuard)
        self.assertNotIsInstance(model.client.transport.transport, DeploymentGuard, 'the guard did not nest')
        self.assertEqual(len(model.client.transport.transport.opener.requests), 3, 'exactly one attempt per call')

    def test_the_existing_alias_check_is_untouched_by_the_guard(self):
        # A right deployment answering as the wrong alias still refuses, and by the existing alias rule.
        self.expect(self.model(FakeResponse(completion_body(model='other-model'),
                                            [(DEPLOYMENT_HEADER, 'backend-a')])), 'model_model_mismatch')

    def test_the_client_the_adapter_builds_is_guarded_too(self):
        """The production construction path, not only an injected client, gets the wrapper."""
        real = AiClient.from_environment
        seen = []

        def build(values):
            client = real(values)
            client.transport.opener = FakeOpener(matching(),
                                                 FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-b')]))
            seen.append(client)
            return client
        model = Model(environ={**self.environ, DEPLOYMENT_VARIABLE: 'backend-a'})
        with patch.object(AiClient, 'from_environment', side_effect=build):
            self.assertEqual(self.call(model)['status'], 'ok')
            self.expect(model, 'model_deployment_mismatch')
        client = seen[0]
        self.assertIsInstance(client.transport, DeploymentGuard)
        self.assertEqual(len(client.transport.transport.opener.requests), 2,
                         'one attempt per call, wrapped by the adapter', )
        self.assertIsInstance(client.transport.transport, JsonClient)

    def test_the_client_the_adapter_builds_is_untouched_when_unselected(self):
        real = AiClient.from_environment
        built = []

        def build(values):
            client = real(values)
            client.transport.opener = FakeOpener(matching())
            built.append(client)
            return client
        model = Model(environ=self.environ)
        with patch.object(AiClient, 'from_environment', side_effect=build):
            self.assertEqual(model.complete(EVIDENCE, set(), CONFIG, NOW)['status'], 'ok')
        self.assertIs(type(built[0].transport), JsonClient, 'no wrapper, no header read')
        self.assertEqual(model.provenance()['model_version'], 'weights-v1')

    def test_any_other_deployment_refuses(self):
        self.expect(self.model(FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-b')])),
                    'model_deployment_mismatch')
        self.expect(self.model(FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-a-2')])),
                    'model_deployment_mismatch')

    def test_absent_malformed_duplicate_or_body_only_claim_refuses(self):
        cases = {
            'absent': FakeResponse(completion_body()),
            'url': FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'https://gw.invalid/backend-a')]),
            'crlf': FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-a\r\nX-Other: 1')]),
            'credential-like': FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'sk-' + 'A' * 40)]),
            'empty': FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, '')]),
            'body-claim': FakeResponse(completion_body(extra={'deployment': 'backend-a',
                                                             DEPLOYMENT_HEADER: 'backend-a'})),
        }
        for name, response in cases.items():
            self.expect(self.model(response), 'model_deployment_mismatch')
        duplicated = FakeResponse(completion_body()).duplicate(DEPLOYMENT_HEADER, ['backend-a', 'backend-a'])
        self.expect(self.model(duplicated), 'model_deployment_mismatch')

    def test_refusal_never_carries_the_header_or_the_body(self):
        for value in ('backend-b', 'sk-' + 'A' * 40, 'https://gw.invalid/backend-a'):
            error = self.expect(self.model(FakeResponse(completion_body(extra={'secret': TOKEN}),
                                                       [(DEPLOYMENT_HEADER, value)])),
                                'model_deployment_mismatch')
            self.assertNotIn(value, str(error))
            self.assertNotIn(TOKEN, str(error))

    def test_a_match_does_not_certify_the_next_call(self):
        model = self.model(matching(), FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-b')]))
        self.assertEqual(self.call(model)['status'], 'ok')
        self.expect(model, 'model_deployment_mismatch')
        self.assertEqual(len(model.client.transport.transport.opener.requests), 2)
        self.assertEqual(model.client.transport.expected, 'backend-a', 'the expectation is configuration only')

    def test_timeout_then_match_then_miss_refuses_only_where_unverified(self):
        model = self.model(matching(), refused_by_transport(), matching(),
                           FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-b')]))
        self.assertEqual(self.call(model)['status'], 'ok')
        self.expect(model, 'model_endpoint_unavailable')
        self.assertEqual(self.call(model)['status'], 'ok', 'the timed-out call is not certified by the earlier match')
        self.expect(model, 'model_deployment_mismatch')
        self.assertEqual(len(model.client.transport.transport.opener.requests), 4)

    def test_error_status_keeps_the_existing_status_refusal(self):
        model = self.model(answered_as(503), matching())
        self.expect(model, 'model_endpoint_status')
        self.assertEqual(self.call(model)['status'], 'ok',
                         'an error answer is refused by the status gate, not re-labelled as a deployment miss')
        self.assertEqual(len(model.client.transport.transport.opener.requests), 2)

    def test_a_transport_that_cannot_carry_the_header_is_refused(self):
        class StandIn:
            def request(self, method, path='', payload=None, **kwargs):
                return 200, completion_body()

        client = AiClient(base_url='https://model.invalid', api_key=TOKEN, model=ALIAS,
                          capability={'schema_version': 1, 'context_tokens': 8192, 'tools': False,
                                      'json_mode': True, 'streaming': False, 'vision': False, 'parallel': 1,
                                      'quant': 'example', 'measured_tok_per_s': 1},
                          policy={'schema_version': 1, 'classes': {c: {'generate': True, 'remote': False,
                                  'redact': ['secret_keys'], 'label': ''} for c in ('public', 'internal',
                                  'restricted')}},
                          budget=dict(BUDGET), out_of_lan=False, transport=StandIn())
        model = Model(environ={**self.environ, DEPLOYMENT_VARIABLE: 'backend-a'})
        model.client = client
        self.expect(model, 'model_deployment_unsupported')
        self.assertIsInstance(client.transport, StandIn)
        self.assertIs(guard_client(client, {}), client, 'unselected configuration leaves any client alone')

    def test_response_header_slot_collects_one_name_and_forgets_it(self):
        slot = ResponseHeader(DEPLOYMENT_HEADER)
        client = JsonClient('https://model.invalid', TOKEN)
        client.opener = FakeOpener(FakeResponse({'ok': True}, [(DEPLOYMENT_HEADER, 'backend-a'),
                                                              ('X-Other', 'unrelated')]),
                                   FakeResponse({'ok': True}, [(DEPLOYMENT_HEADER, 'backend-a')]),
                                   FakeResponse({'ok': True}),
                                   FakeResponse({'ok': True}, [(DEPLOYMENT_HEADER, 'backend-b')]))
        self.assertEqual(client.request('GET', '/v1/thing'), (200, {'ok': True}))
        self.assertEqual(slot.values, [], 'an unset slot is never filled by an unrelated request')
        self.assertEqual(client.request('GET', '/v1/thing', response_header=slot), (200, {'ok': True}))
        self.assertEqual(slot.values, ['backend-a'], 'and only the one requested name is kept')
        self.assertEqual(client.request('GET', '/v1/thing', response_header=slot), (200, {'ok': True}))
        self.assertEqual(slot.values, [], 'a later answer without that header empties the slot')
        self.assertEqual(client.request('GET', '/v1/thing', response_header=slot), (200, {'ok': True}))
        self.assertEqual(slot.values, ['backend-b'])
        with self.assertRaises(TransportError):
            client.request('GET', '/v1/thing', response_header='x-litellm-model-id')
        self.assertEqual(slot.values, ['backend-b'], 'a refused call leaves the slot as it was')
        for name in ('X Bad Name', '', 'x' * 200, None, 7):
            with self.assertRaises(TransportError, msg=repr(name)):
                ResponseHeader(name)


class JournalTests(GuardTestCase):
    def setUp(self):
        super().setUp()
        self.state = self.temp / 'state'
        self.state.mkdir(mode=0o700)
        self.journal = Journal(self.state)
        self.addCleanup(self.journal.close)

    def sources(self):
        class Fixed:
            secrets = ()

            def read(self, source, window, now):
                return {**ENVELOPE, 'window': window}
        return Fixed()

    def records(self):
        collected = []

        class Collect(logging.Handler):
            def emit(self, record):
                collected.append(record.getMessage() + ' ' + ' '.join(str(v) for v in record.__dict__.values()))

        handler, root = Collect(), logging.getLogger()
        previous = root.level
        root.setLevel(logging.DEBUG)
        root.addHandler(handler)

        def restore():
            root.setLevel(previous)
            root.removeHandler(handler)
        self.addCleanup(restore)
        return collected

    def run_cycle(self, model, cycle_id):
        return Observer(CONFIG, self.journal, sources=self.sources(), model=model,
                        clock=lambda: NOW).run(cycle_id)

    def test_a_guarded_call_completes_and_stores_only_the_derived_label(self):
        result = self.run_cycle(self.model(matching()), 'guarded')
        self.assertEqual((result['status'], result['coverage'], result['decision']),
                         ('completed', 'complete', 'watch'))
        self.assertEqual(result['provenance']['model_version'], route_label('weights-v1', 'backend-a'))
        self.assertEqual(result['model_calls'][0]['provenance'], result['provenance'])
        self.assertEqual(result['model_calls'][0]['response_model'], ALIAS)
        persisted = encoded(result) + encoded(self.journal.replay('guarded'))
        for secret in ('backend-a', 'weights-v1', TOKEN, DEPLOYMENT_HEADER):
            self.assertNotIn(secret, persisted)

    def test_a_mismatch_fails_the_cycle_without_persisting_the_header(self):
        logs = self.records()
        result = self.run_cycle(self.model(FakeResponse(completion_body(), [(DEPLOYMENT_HEADER, 'backend-b')])),
                                'refused')
        self.assertEqual((result['status'], result['coverage'], result['decision']),
                         ('failed', 'failed', None))
        self.assertEqual(result['error'], 'model_deployment_mismatch')
        self.assertEqual([call['status'] for call in result['model_calls']], ['failed'])
        self.assertIsNone(result['provenance']['response_model'])
        self.assertFalse(result['provenance']['complete'], 'a refused call cannot complete provenance')
        for leak in ('backend-b', 'backend-a', TOKEN, DEPLOYMENT_HEADER, reply_text()):
            self.assertNotIn(leak, encoded(result) + encoded(self.journal.replay('refused')) + ' '.join(logs))


if __name__ == '__main__':
    unittest.main()


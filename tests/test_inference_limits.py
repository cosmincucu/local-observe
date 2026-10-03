"""Independent boundary checks for explicit local-inference budgets."""
from contextlib import closing
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_observe.ai import budget
from local_observe.ai.client import AiClient, AiError, AiNotConfigured
from local_observe.http import JsonClient, ResultTooLarge, TransportError
from local_observe.observer import Config, Journal, Observer
from local_observe.observer.adapters import Model, Sources
from local_observe.observer.contract import ObserverError, digest
from local_observe.platform.query import open_reader
from local_observe.store.backends import clickhouse as ch
from tests.test_ai_client import (BUDGET_EXHAUSTED, FakeTransport, MEASURED, NOW as AI_NOW, POLICY,
                                  REASONING_CANARY, reference)
from tests.test_observer_runtime import FixtureModel, FixtureSources, NOW, SOURCE, WINDOW, envelope
from tests.test_store_facade import RecordingOpener, recorded, RESOURCE, WINDOW as STORE_WINDOW


def client(**overrides):
    values = {'base_url': 'https://model.example.test', 'api_key': 't' * 32,
              'model': 'qwen3-30b', 'capability': {**MEASURED, 'context_tokens': 32768},
              'policy': POLICY, 'budget': dict(budget.DEFAULTS), 'out_of_lan': False}
    return AiClient(**{**values, **overrides})


class BudgetLimits(unittest.TestCase):
    def test_optional_timeout_preserves_existing_validated_budget(self):
        legacy = {'max_evidence_items': 20, 'max_evidence_bytes': 16384,
                  'max_prompt_bytes': 24576, 'max_completion_tokens': 512}
        self.assertEqual(budget.validate({}), legacy)
        self.assertEqual(budget.validate(legacy), legacy)
        configured = budget.validate({'request_timeout_seconds': 90, 'max_completion_tokens': 8192})
        self.assertEqual(configured, {**legacy, 'request_timeout_seconds': 90, 'max_completion_tokens': 8192})

    def test_optional_timeout_and_completion_hard_boundaries(self):
        for value in (1, 120):
            self.assertEqual(budget.validate({'request_timeout_seconds': value})['request_timeout_seconds'], value)
        for value in (0, 121, True, '90', None, 90.0):
            with self.subTest(value=value), self.assertRaises(budget.BudgetError):
                budget.validate({'request_timeout_seconds': value})
        for value in (1, 512, 8192, 16384):
            with self.subTest(value=value):
                self.assertEqual(budget.validate({'max_completion_tokens': value})['max_completion_tokens'], value)
        for value in (0, -1, 16385, True, '16384', None, 16384.0):
            with self.subTest(value=value), self.assertRaises(budget.BudgetError):
                budget.validate({'max_completion_tokens': value})

    def test_an_oversized_completion_allowance_refuses_before_any_request(self):
        transport = FakeTransport()
        with self.assertRaises(AiError):
            client(transport=transport, budget={'max_completion_tokens': 16385})
        self.assertEqual(transport.calls, [])

    def test_configured_timeout_reaches_transport_without_expanding_overrides(self):
        self.assertEqual(client().transport.timeout, 10)
        self.assertEqual(client().transport.max_timeout, 20)
        self.assertEqual(client(timeout=20).transport.timeout, 20)
        with self.assertRaises(AiNotConfigured):
            client(timeout=21)
        limits = {**budget.DEFAULTS, 'request_timeout_seconds': 90}
        transport = client(budget=limits).transport
        self.assertEqual((transport.timeout, transport.max_timeout), (90, 90))
        self.assertEqual(transport._attempt_timeout('POST', '/v1/chat/completions', 120), 90)
        self.assertEqual(client(budget=limits, timeout=7).transport.timeout, 7)
        for value in (91, True, 0, '90'):
            with self.subTest(value=value), self.assertRaises(AiNotConfigured):
                client(budget=limits, timeout=value)

    def test_model_request_uses_explicit_completion_allowance(self):
        for allowance in (512, 8192, 16384):
            transport = FakeTransport()
            instance = client(transport=transport, budget={'max_completion_tokens': allowance})
            instance.complete(instruction='Review these samples.', data_class='internal',
                              evidence=[reference()], now=AI_NOW)
            with self.subTest(allowance=allowance):
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(transport.calls[0]['payload']['max_tokens'], allowance)

    def test_shared_http_callers_keep_their_shorter_default_ceiling(self):
        generic = JsonClient('https://service.example.test', 't' * 32)
        self.assertEqual((generic.timeout, generic.max_timeout), (10, 20))
        for kwargs in ({'timeout': 21}, {'timeout': True}, {'max_timeout': True},
                       {'max_timeout': 121}, {'max_timeout': '120'}, {'max_timeout': 120.0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(TransportError):
                JsonClient('https://service.example.test', 't' * 32, **kwargs)
        opted_in = JsonClient('https://model.example.test', 't' * 32, timeout=90, max_timeout=120)
        self.assertEqual(opted_in._attempt_timeout('POST', '/', 119), 90)
        self.assertEqual(opted_in._attempt_timeout('POST', '/', 3), 3)


class ReaderLimits(unittest.TestCase):
    def test_oversized_presence_probe_is_not_mistaken_for_absence(self):
        def answer(sql, limit):
            if limit == 1:
                raise ResultTooLarge('untrusted-response-text')
            return []

        with self.assertRaises(ResultTooLarge):
            recorded(answer).read('log-records', window=STORE_WINDOW, parameters={'resource_id': RESOURCE})

    def test_wire_allowance_is_explicit_and_keeps_native_query_constraints(self):
        body = json.dumps({'data': [{'value': 1}]}).encode() + b' ' * 66000
        opener = RecordingOpener([], body)
        with patch.object(ch.urllib.request, 'build_opener', return_value=opener):
            ordinary = ch.ClickHouse('https://store.example.test', 'reader', 'p' * 32)
            with self.assertRaises(ResultTooLarge):
                ordinary._rows('SELECT 1 FORMAT JSON', {}, max_result_rows=1)
            observer = ch.ClickHouse('https://store.example.test', 'reader', 'p' * 32,
                                     max_response_bytes=131072)
            self.assertEqual(observer._rows('SELECT 1 FORMAT JSON', {}, max_result_rows=1), [{'value': 1}])
            self.assertEqual(opener.requests[0][0].full_url, opener.requests[1][0].full_url)
            self.assertEqual([timeout for _, timeout in opener.requests], [10, 10])
            opener.body = b' ' * 131073
            with self.assertRaises(ResultTooLarge):
                observer._rows('SELECT 1 FORMAT JSON', {}, max_result_rows=1)
        for value in (65535, 131073, True, '131072', None, 131072.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ch.ClickHouse('https://store.example.test', 'reader', 'p' * 32, max_response_bytes=value)

    def test_only_the_observer_requests_formatting_headroom(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / 'reader'
            secret.write_text('p' * 32, encoding='utf-8')
            secret.chmod(0o600)
            environment = {'LO_CLICKHOUSE_URL': 'https://store.example.test',
                           'LO_CLICKHOUSE_READ_PASSWORD_FILE': str(secret)}
            self.assertEqual(open_reader(environ=environment).client.max_response_bytes, 65536)
            for cap, expected in ((65536, 131072), (8192, 65536)):
                config = Config((SOURCE,), max_result_bytes=cap)
                sources = Sources(config, environ=environment)
                with patch('local_observe.platform.query.open_reader', wraps=open_reader) as factory:
                    # No HTTP request: stop at the already constructed facade.
                    with patch.object(ch.ClickHouseStore, 'read', side_effect=TransportError('unavailable')):
                        with self.assertRaises(TransportError):
                            sources.read(SOURCE, WINDOW, NOW)
                    self.assertEqual(factory.call_args.kwargs['max_response_bytes'], expected)

    def test_a_larger_wire_budget_does_not_raise_the_normalized_evidence_limit(self):
        config = Config((SOURCE,), max_result_bytes=1024)
        raw = envelope()
        raw['rows'][0]['labels']['description'] = 'x' * 1500
        with tempfile.TemporaryDirectory() as directory, closing(Journal(Path(directory) / 'state')) as journal:
            model = FixtureModel()
            source = type('SourceFixture', (), {'read': lambda _self, *_args: raw})()
            result = Observer(config, journal, sources=source, model=model, clock=lambda: NOW).run('too-wide')
            self.assertEqual(result['activity'][0]['error'], 'result_too_large')
            self.assertEqual(model.calls, [])

    def test_exception_attributes_cannot_become_journal_text(self):
        canary = 'untrusted-error-attribute'
        error = ResultTooLarge(canary)
        error.code = canary
        class StoreFixture:
            def read(self, *_args, **_kwargs):
                raise error

        store = StoreFixture()
        config = Config((SOURCE,))
        with tempfile.TemporaryDirectory() as directory, closing(Journal(Path(directory) / 'state')) as journal:
            result = Observer(config, journal, sources=Sources(config, store=store),
                              model=FixtureModel(), clock=lambda: NOW).run('safe-code')
            self.assertEqual(result['activity'][0]['error'], 'source_result_too_large')
            self.assertNotIn(canary, json.dumps(result))


class ReasoningEffortProvenance(unittest.TestCase):
    """The spelling is part of the document that gets hashed, so it is part of what got reproduced.

    `budget_sha256` is how a later reader tells which request this cycle made, and the drift gate is
    how the runtime tells that the document it is about to use is the document it hashed. Both read
    the validated budget, so an optional key has to move both: an operator who edits the effort in one
    place only is refused, never quietly served a different request than the provenance describes.
    """

    def ask(self, *, client, environ):
        """One adapter-level model call, in the shape the observer hands the adapter."""
        model = Model(environ=environ, client=client)
        evidence = [{'source': SOURCE.id, 'query_type': SOURCE.query_type,
                     'resource_id': SOURCE.resource_id, 'window': dict(WINDOW)}]
        return model, model.complete(evidence, {SOURCE.id}, Config((SOURCE,)), NOW)

    def test_each_spelling_is_a_different_budget_document(self):
        digests = {'omitted': digest(budget.validate(dict(budget.DEFAULTS)))}
        for effort in budget.REASONING_EFFORTS:
            digests[effort] = digest(budget.validate(dict(budget.DEFAULTS, reasoning_effort=effort)))
        self.assertEqual(len(set(digests.values())), 5,
                         'a changed effort that no digest noticed cannot be reproduced by anyone')
        self.assertEqual(digests['omitted'], digest(budget.load(None)),
                         'the unnamed case keeps the legacy document, so legacy digests stand')

    def test_the_adapter_sends_and_hashes_the_spelling_the_file_named(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'budget.json'
            path.write_text(json.dumps({'max_completion_tokens': 8_192, 'request_timeout_seconds': 90,
                                        'reasoning_effort': 'xhigh'}), encoding='utf-8')
            transport = FakeTransport()
            instance = client(transport=transport,
                              budget={**budget.DEFAULTS, 'max_completion_tokens': 8_192,
                                      'request_timeout_seconds': 90, 'reasoning_effort': 'xhigh'})
            model, result = self.ask(client=instance, environ={'LO_AI_BUDGET': str(path)})
            self.assertEqual(transport.calls[0]['payload']['reasoning_effort'], 'xhigh')
            self.assertEqual(transport.calls[0]['payload']['max_tokens'], 8_192)
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(model.provenance()['budget_sha256'], digest(instance.budget))

            # The same client, the file edited under it: the runtime refuses rather than generating a
            # request its own provenance does not describe.
            path.write_text(json.dumps({'max_completion_tokens': 8_192, 'request_timeout_seconds': 90}),
                            encoding='utf-8')
            with self.assertRaises(ObserverError) as caught:
                self.ask(client=instance, environ={'LO_AI_BUDGET': str(path)})
            self.assertEqual(str(caught.exception), 'model_configuration_drift')
            self.assertEqual(len(transport.calls), 1, 'the drift gate ran before a second request')


class RefusalDiagnostics(unittest.TestCase):
    def test_nonfinite_model_responses_emit_one_safe_refusal(self):
        for value in (float('nan'), float('inf'), float('-inf')):
            transport = FakeTransport(reply={'untrusted': 'response-canary', 'nested': [{'value': value}]})
            with self.subTest(value=value), self.assertLogs('local_observe.ai.telemetry', 'WARNING') as logs:
                with self.assertRaises(AiError) as caught:
                    client(transport=transport).complete(instruction='Review.', data_class='internal',
                                                        evidence=[reference()], now=AI_NOW)
            self.assertEqual(caught.exception.code, 'malformed_response')
            self.assertEqual(len(logs.records), 1)
            self.assertEqual(logs.records[0].refusal, 'malformed_response')
            self.assertNotIn('response-canary', str(vars(logs.records[0])))
            self.assertEqual(len(transport.calls), 1)

    def test_model_error_codes_are_allowlisted_before_persistence(self):
        config = Config((SOURCE,))
        for code, expected in (('prompt_bytes', 'model_prompt_bytes'),
                               ('endpoint_unavailable', 'model_endpoint_unavailable'),
                               ('incomplete_response', 'model_incomplete_response'),
                               ('untrusted-code-canary', 'model_request_failed')):
            class RejectingClient:
                capture = False
                out_of_lan = False

                def complete(self, **_kwargs):
                    raise AiError('untrusted-error-text-canary', code=code)

            with self.subTest(code=code), tempfile.TemporaryDirectory() as directory:
                with closing(Journal(Path(directory) / 'state')) as journal:
                    result = Observer(config, journal, sources=FixtureSources(),
                                      model=Model(client=RejectingClient()), clock=lambda: NOW).run('refused')
                    self.assertEqual(result['error'], expected)
                    self.assertEqual(result['model_calls'][0]['status'], 'failed')
                    self.assertNotIn('canary', json.dumps(journal.get('refused')))

    def test_a_budget_exhausted_reply_is_journalled_as_incomplete_output(self):
        """The serve answered, spent every completion token and wrote no answer: the cycle says so.

        Before the parser read `finish_reason` first, this reply reached the journal as
        ``model_request_failed``, which points an operator at the endpoint while the endpoint was
        healthy and the allowance was the problem.
        """
        transport = FakeTransport(reply=BUDGET_EXHAUSTED)
        config = Config((SOURCE,))
        with tempfile.TemporaryDirectory() as directory:
            with closing(Journal(Path(directory) / 'state')) as journal:
                result = Observer(config, journal, sources=FixtureSources(),
                                  model=Model(client=client(transport=transport)),
                                  clock=lambda: NOW).run('truncated')
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['error'], 'model_incomplete_response')
                self.assertNotIn(result['error'], ('model_request_failed', 'model_endpoint_unavailable',
                                                   'model_endpoint_status', 'incomplete_model_response'))
                self.assertEqual(result['model_calls'][0]['status'], 'failed')
                # A failed call keeps unknown counts in the journal; the measured ones belong to the
                # AI telemetry record, and are not re-derived here from a reply the client refused.
                self.assertEqual(result['model_calls'][0]['usage'], {'input_tokens': None,
                                                                    'output_tokens': None})
                self.assertEqual(len(transport.calls), 1)
                persisted = json.dumps(journal.get('truncated'))
                self.assertNotIn(REASONING_CANARY, persisted)
                self.assertNotIn('reasoning', persisted)

    def test_a_partial_answer_is_still_refused_by_the_observer(self):
        """Text that stopped mid-write is a different code and an equally refused cycle."""
        transport = FakeTransport(reply={'choices': [{'finish_reason': 'length',
                                                     'message': {'content': '{"decision": ',
                                                                 'reasoning_content': REASONING_CANARY}}],
                                          'usage': {'prompt_tokens': 20933, 'completion_tokens': 512}})
        config = Config((SOURCE,))
        with tempfile.TemporaryDirectory() as directory:
            with closing(Journal(Path(directory) / 'state')) as journal:
                result = Observer(config, journal, sources=FixtureSources(),
                                  model=Model(client=client(transport=transport)),
                                  clock=lambda: NOW).run('partial')
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['error'], 'incomplete_model_response')
                persisted = json.dumps(journal.get('partial'))
                self.assertNotIn(REASONING_CANARY, persisted)
                self.assertIsNone(result['answer'], 'a half-written answer is not recorded as a finding')
                self.assertNotIn('answer', result['model_calls'][0])

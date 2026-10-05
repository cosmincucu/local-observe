"""Route-pool recording and independent refusal of single-model quality certification."""
from contextlib import closing
from dataclasses import asdict, replace
from pathlib import Path
import tempfile
import unittest

from local_observe.evaluation.report import evaluate
from local_observe.observer import Config, Journal, Observer, ObserverError, Source
from local_observe.observer.acceptance import validate_report
from local_observe.observer.contract import digest, encoded, snapshot
from local_observe.observer.environment import validate_environment
from local_observe.observer.provenance import build_provenance, validate_provenance, validate_route_receipt
from test_observer_acceptance_integration import FixtureModel, RESOURCE, fixture_corpus
from test_observer_model_route import (ALIAS, CONFIG, DEPLOYMENT_HEADER, ENVELOPE, NOW, SOURCE,
                                       WINDOW, FakeResponse, GuardTestCase, completion_body)


class PoolIntegrationTests(GuardTestCase):
    def setUp(self):
        super().setUp()
        self.routes = {'schema_version': 1, 'routes': {
            'backend-a': {'provider': 'engine-a', 'model_version': 'weights-a'},
            'backend-b': {'provider': 'engine-b', 'model_version': 'weights-b'}}}
        self.route_file = Path(self.environ['LO_AI_API_KEY_FILE']).parent / 'routes.json'
        self.route_file.write_text(encoded(self.routes), encoding='utf-8')
        self.route_file.chmod(0o600)
        self.environ.pop('LO_OBSERVER_MODEL_PROVIDER')
        self.environ.pop('LO_OBSERVER_MODEL_VERSION')
        self.environ['LO_OBSERVER_MODEL_ROUTES'] = str(self.route_file)

    def response(self, member, *, content=None):
        body = completion_body()
        if content is not None:
            body['choices'][0]['message']['content'] = encoded(content)
        return FakeResponse(body, [(DEPLOYMENT_HEADER, member)])

    def test_environment_checks_path_and_ambiguous_declarations(self):
        self.assertEqual(validate_environment(self.environ), self.environ)
        for key in ('LO_OBSERVER_MODEL_DEPLOYMENT', 'LO_OBSERVER_MODEL_PROVIDER', 'LO_OBSERVER_MODEL_VERSION'):
            with self.subTest(key=key), self.assertRaisesRegex(ObserverError, 'model_route_pool_ambiguous'):
                validate_environment({**self.environ, key: 'example'})
        with self.assertRaisesRegex(ObserverError, 'absolute_setting_path_required'):
            validate_environment({'LO_OBSERVER_MODEL_ROUTES': 'relative.json'})

    def test_followup_can_change_member_without_claiming_single_model_identity(self):
        second = Source('cpu-two', 'metric-threshold', SOURCE.resource_id,
                        metric_name='cpu.utilization', initial=False)
        config = replace(CONFIG, sources=(SOURCE, second))
        envelopes = {SOURCE.id: ENVELOPE, second.id: {**ENVELOPE, 'source': second.id}}
        answers = []
        for source, following in ((SOURCE, [second.id]), (second, [])):
            evidence = snapshot(source, envelopes[source.id], WINDOW, config, NOW)
            answers.append({'schema_version': 1, 'decision': 'watch', 'rationale': 'Synthetic sample.',
                            'citations': [{'evidence_id': evidence['evidence_id'], 'row_index': 0,
                                           'field': 'value', 'value': 0.8}], 'follow_up': following})
        model = self.model(self.response('backend-a', content=answers[0]),
                           self.response('backend-b', content=answers[1]), deployment=None)

        class Sources:
            def read(self, source, window, now):
                return envelopes[source.id]

        with closing(Journal(self.temp / 'journal')) as journal:
            observer = Observer(config, journal, sources=Sources(), model=model, clock=lambda: NOW)
            cycle = observer.run('pool-followup')
            self.assertEqual((cycle['status'], cycle['coverage']), ('completed', 'complete'))
            self.assertFalse(cycle['delivery']['external_send'])
            self.assertEqual(len(cycle['model_calls']), 2)
            receipts = [call['model_route'] for call in cycle['model_calls']]
            expected_pool = digest(self.routes)
            self.assertEqual({r['pool_sha256'] for r in receipts}, {expected_pool})
            self.assertEqual([r['member_sha256'] for r in receipts],
                             [digest(['backend-a', 'engine-a', 'weights-a']),
                              digest(['backend-b', 'engine-b', 'weights-b'])])
            self.assertTrue(all(r['complete'] for r in receipts))
            self.assertTrue(cycle['provenance']['complete'])
            self.assertEqual(cycle['provenance']['provider'], 'declared-route-pool')
            self.assertEqual(cycle['provenance']['model_version'], 'route-pool-sha256:' + expected_pool)
            self.assertTrue(all(c['provenance'] == cycle['provenance'] for c in cycle['model_calls']))
            for forbidden in ('backend-a', 'backend-b', 'engine-a', 'weights-a', DEPLOYMENT_HEADER):
                self.assertNotIn(forbidden, encoded(cycle))
            before = encoded(cycle)
            self.assertEqual(encoded(observer.run('pool-followup')), before)

    def test_missing_member_version_keeps_overall_provenance_incomplete(self):
        self.routes['routes']['backend-b']['model_version'] = None
        self.route_file.write_text(encoded(self.routes), encoding='utf-8')
        model = self.model(self.response('backend-a'), deployment=None)
        self.call(model)
        provenance = build_provenance(CONFIG, model, response_model=ALIAS)
        self.assertFalse(provenance['complete'])
        self.assertIsNone(provenance['model_version'])

    def test_malformed_answer_then_good_call_does_not_inherit_route(self):
        malformed = completion_body()
        malformed['choices'] = []
        model = self.model(FakeResponse(malformed, [(DEPLOYMENT_HEADER, 'backend-a')]),
                           self.response('backend-b'), deployment=None)
        with self.assertRaises(ObserverError):
            self.call(model)
        self.assertIsNone(model.client.transport.take_receipt())
        result = self.call(model)
        self.assertEqual(result['model_route']['member_sha256'], digest(['backend-b', 'engine-b', 'weights-b']))
        self.assertIsNone(model.client.transport.take_receipt())

    def test_declaration_changed_during_request_refuses_same_call(self):
        model = self.model(self.response('backend-a'), deployment=None)
        original = self.json.opener.open

        def changing(request, timeout=None):
            response = original(request, timeout=timeout)
            self.routes['routes']['backend-b']['model_version'] = 'weights-changed'
            self.route_file.write_text(encoded(self.routes), encoding='utf-8')
            return response

        self.json.opener.open = changing
        with self.assertRaisesRegex(ObserverError, 'model_configuration_drift'):
            self.call(model)
        self.assertIsNone(model.client.transport.take_receipt())

    def test_unknown_header_never_reaches_the_journal(self):
        marker = 'credential-like-unlisted-' + 'z' * 24
        model = self.model(self.response(marker), deployment=None)

        class Sources:
            def read(self, source, window, now):
                return ENVELOPE

        with closing(Journal(self.temp / 'journal')) as journal:
            cycle = Observer(CONFIG, journal, sources=Sources(), model=model, clock=lambda: NOW).run('refusal')
            self.assertEqual(cycle['error'], 'model_deployment_mismatch')
            self.assertNotIn(marker, encoded(cycle))
            self.assertNotIn('model_route', cycle['model_calls'][0])

    def test_incomplete_declaration_changed_after_response_cannot_relabel_it(self):
        self.routes['routes']['backend-b']['model_version'] = None
        self.route_file.write_text(encoded(self.routes), encoding='utf-8')
        model = self.model(self.response('backend-a'), deployment=None)
        result = self.call(model)
        self.routes['routes']['backend-a']['provider'] = 'changed-engine'
        self.route_file.write_text(encoded(self.routes), encoding='utf-8')
        with self.assertRaisesRegex(ObserverError, 'model_configuration_drift'):
            build_provenance(CONFIG, model, response_model=ALIAS, route_receipt=result['model_route'])

    def test_unaccepted_success_status_keeps_the_ai_status_refusal(self):
        for status in (202, 204, 206):
            with self.subTest(status=status):
                model = self.model(FakeResponse(completion_body(), status=status), deployment=None)
                with self.assertRaisesRegex(ObserverError, 'model_endpoint_status'):
                    self.call(model)
                self.assertIsNone(model.client.transport.take_receipt())


class PoolFixtureModel(FixtureModel):
    def provenance_for_route(self, receipt):
        return self.provenance()

    def complete(self, evidence, allowed, config, now):
        return {**super().complete(evidence, allowed, config, now), 'model_route': {
            'schema_version': 1, 'pool_sha256': 'a' * 64, 'member_sha256': 'b' * 64, 'complete': True}}

    def provenance(self):
        return {**super().provenance(), 'provider': 'declared-route-pool',
                'model_version': 'route-pool-sha256:' + 'a' * 64}


class PoolQualityTests(unittest.TestCase):
    def test_real_comparison_is_unjudgeable_and_acceptance_refuses_pool(self):
        config = Config(sources=(Source('disk', 'metric-threshold', RESOURCE,
                                        metric_name='filesystem_used_bytes'),), mode='shadow')
        corpus = fixture_corpus()
        # Synthetic contract fixture, never live quality evidence.
        corpus['origin'] = 'anonymized-example'
        baseline = {'schema_version': 1, 'thresholds': [
            {'resource_id': RESOURCE, 'metric': 'filesystem_used_bytes', 'threshold': 30e9}]}
        with tempfile.TemporaryDirectory() as directory:
            report = evaluate(corpus, revision='a' * 40, observer_directory=Path(directory) / 'evaluation',
                              observer_model_factory=PoolFixtureModel, observer_config=config,
                              baseline_config=baseline)
        self.assertNotEqual(report['quality']['verdict'], 'measured-pass')
        self.assertIsNone(report['manifest']['observer']['provenance'])
        calls = report['runs'][0]['llm-rca']['detail']['cycles'][0]['model_calls']
        self.assertEqual(calls[0]['model_route']['member_sha256'], 'b' * 64)
        self.assertEqual(calls[0]['status'], 'completed')
        provenance = build_provenance(config, PoolFixtureModel(), response_model='fixture-backend-v1')
        self.assertTrue(validate_provenance(provenance)['complete'])
        with self.assertRaisesRegex(ObserverError, 'pooled_model_quality_unaccepted'):
            validate_report(report, config_sha256=digest(asdict(config)), provenance=provenance, config=config)

    def test_version_prefix_alone_cannot_bypass_acceptance(self):
        provenance = build_provenance(CONFIG, PoolFixtureModel(), response_model=ALIAS)
        provenance['provider'] = 'example-provider'
        provenance['sha256'] = digest({k: v for k, v in provenance.items() if k != 'sha256'})
        with self.assertRaisesRegex(ObserverError, 'pooled_model_quality_unaccepted'):
            validate_report({}, config_sha256=digest(asdict(CONFIG)), provenance=provenance, config=CONFIG)

    def test_receipt_schema_refuses_payloads_and_a_different_pool(self):
        provenance = build_provenance(CONFIG, PoolFixtureModel(), response_model=ALIAS)
        receipt = {'schema_version': 1, 'pool_sha256': 'a' * 64, 'member_sha256': 'b' * 64, 'complete': True}
        self.assertEqual(validate_route_receipt(receipt, provenance), receipt)
        for wrong in ({**receipt, 'header': 'sensitive-untrusted-payload'},
                      {**receipt, 'member_sha256': 'sensitive-untrusted-payload'},
                      {**receipt, 'pool_sha256': 'c' * 64},
                      {**receipt, 'schema_version': True}, {**receipt, 'complete': False},
                      {**receipt, 'complete': 1}, None, []):
            with self.subTest(value=wrong), self.assertRaises(ObserverError):
                validate_route_receipt(wrong, provenance)

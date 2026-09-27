"""Independent checks for unknown labels and the observer quality acceptance boundary."""
import copy
import datetime as dt
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from local_observe.evaluation.arms import finding
from local_observe.evaluation.eval import score
from local_observe.evaluation.fault_inject import RESOURCE, START, synthetic
from local_observe.evaluation.model import CorpusError
from local_observe.evaluation.quality import assess
from local_observe.evaluation.report import evaluate
from local_observe.inventory.validation import utc_text


class ObserverQualityTests(unittest.TestCase):
    def runs(self):
        from test_eval_corrections import quality_fixture
        return quality_fixture()

    def test_measurements_never_arm_delivery_including_generated_pass(self):
        corpus, runs = self.runs()
        report = assess(corpus, runs, observer_flip_rate=0)
        self.assertEqual(report['verdict'], 'measured-pass')
        self.assertFalse(report['authorizes_delivery'])
        self.assertEqual(report['novel_classes'], ['coverage'])

    def test_every_run_must_meet_precision_volume_and_known_label_requirements(self):
        for field, value in [('precision', .69), ('precision', None), ('precision', float('nan')),
                             ('findings_per_day', 2.01), ('findings_per_day', True),
                             ('unlabelled_findings', 1)]:
            corpus, runs = self.runs()
            runs[2]['llm-rca']['score'][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(CorpusError):
                assess(corpus, runs, observer_flip_rate=0)

    def test_unwired_partial_and_known_baseline_class_cannot_pass(self):
        for status in ('unwired', 'failed', 'partial'):
            corpus, runs = self.runs()
            runs[1]['llm-rca']['execution'] = status
            self.assertEqual(assess(corpus, runs, observer_flip_rate=0)['verdict'], 'fail')
        corpus, runs = self.runs()
        runs[0]['seasonal']['score'] = copy.deepcopy(runs[0]['llm-rca']['score'])
        self.assertEqual(assess(corpus, runs, observer_flip_rate=0)['verdict'], 'fail')

    def test_strict_flip_ceiling_and_forged_truth(self):
        corpus, runs = self.runs()
        self.assertEqual(assess(corpus, runs, observer_flip_rate=.1)['verdict'], 'fail')
        runs[0]['llm-rca']['score']['matched'] = ['invented']
        with self.assertRaises(CorpusError):
            assess(corpus, runs, observer_flip_rate=0)

    def test_unlabelled_window_is_unknown_but_still_counts_toward_fatigue(self):
        corpus = synthetic()
        corpus['quiet'] = []
        corpus['labelled'] = []
        event = finding(RESOURCE, 'anomaly', (START + dt.timedelta(hours=3)).timestamp(), arm='control')
        report = score(corpus, [event])
        self.assertIsNone(report['precision'])
        self.assertEqual(report['false_positives'], 0)
        self.assertEqual(report['unlabelled_findings'], 1)
        self.assertEqual(report['findings_per_day'], 6)


@unittest.skipUnless(sys.platform == 'linux', 'Linux observer storage and process deadline')
class ObserverComparisonTests(unittest.TestCase):
    def fixture(self):
        corpus = synthetic()
        corpus['incidents'] = [{'id': 'first-hour', 'resource_id': RESOURCE, 'expected_class': 'anomaly',
                               'window': {'start': utc_text(START),
                                          'end': utc_text(START + dt.timedelta(hours=1))}}]
        corpus['quiet'] = [{'start': utc_text(START + dt.timedelta(hours=1)),
                            'end': utc_text(START + dt.timedelta(hours=4))}]
        corpus['series'] = [{'resource_id': RESOURCE, 'metric': 'cpu', 'rows': [
            {'ts': (START + dt.timedelta(hours=hour, minutes=59)).timestamp(),
             'v': 200 if hour == 0 else 10} for hour in range(4)]}]
        return corpus

    def test_cli_loads_exact_operator_config_and_uses_fresh_private_namespace(self):
        from local_observe.evaluation.__main__ import main
        from local_observe.observer.contract import Config, Source
        config = Config(sources=(Source(id='operator-cpu', query_type='metric-threshold', resource_id=RESOURCE,
                                        metric_name='cpu'),), mode='shadow')
        received = []

        def offline_evaluate(corpus, **kwargs):
            received.append(kwargs['observer_config'])
            # Exercise the shared evaluator and private output flow without credentials or model calls.
            return evaluate(corpus, **kwargs, observer_model_factory=lambda: object())

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'config.json'
            source.write_text(json.dumps(asdict(config)), encoding='utf-8')
            corpus_path = root / 'corpus.json'
            corpus_path.write_text(json.dumps(self.fixture()), encoding='utf-8')
            output = root / 'new'
            with patch('local_observe.evaluation.__main__.evaluate', side_effect=offline_evaluate):
                self.assertEqual(main(['--revision', 'a' * 40, '--corpus', str(corpus_path),
                                       '--observer-config', str(source),
                                       '--observer-directory', str(output), '--output', str(output / 'report.json')]), 0)
            report = json.loads((output / 'report.json').read_text(encoding='utf-8'))
            self.assertEqual(received, [config])
            self.assertEqual(report['manifest']['observer']['configuration_authority'], 'operator-supplied')
            self.assertEqual((output / 'report.json').stat().st_mode & 0o777, 0o600)

    def test_operator_config_is_injected_without_rewriting_hash_or_reading_credentials(self):
        from local_observe.observer.contract import Config, Source, digest
        config = Config(sources=(Source(id='operator-cpu', query_type='metric-threshold', resource_id=RESOURCE,
                                        metric_name='cpu', adapter='file', path='/example/source.json'),),
                        max_sources=1, max_rows=7, max_age_seconds=120, mode='shadow')
        configurations, source_ids = [], []

        class FixtureModel:
            def complete(self, evidence, allowed, supplied, now):
                configurations.append(asdict(supplied))
                source_ids.append(evidence[0]['source'])
                row = evidence[0]['rows'][0]
                return {'model': 'example', 'response_model': 'example', 'content': json.dumps({
                    'schema_version': 1, 'decision': 'quiet', 'rationale': 'Fixture only', 'follow_up': [],
                    'citations': [{'evidence_id': evidence[0]['evidence_id'], 'row_index': 0,
                                   'field': 'value', 'value': row['value']}], 'findings': []})}

        with tempfile.TemporaryDirectory() as directory:
            report = evaluate(self.fixture(), revision='a' * 40, observer_directory=Path(directory) / 'new',
                              observer_model_factory=FixtureModel, observer_config=config)
        self.assertEqual(len(configurations), 12)
        self.assertTrue(all(value == asdict(config) for value in configurations))
        self.assertEqual(set(source_ids), {'operator-cpu'})
        identity = report['manifest']['observer']
        self.assertEqual(identity['config_sha256'], digest(asdict(config)))
        self.assertEqual(identity['configuration_authority'], 'operator-supplied')
        self.assertNotIn('/example/source.json', json.dumps(report))
        for run in report['runs']:
            self.assertTrue(all(c['config_sha256'] == identity['config_sha256']
                                for c in run['llm-rca']['detail']['cycles']))

    def test_missing_ambiguous_or_nonmetric_configured_series_refuse(self):
        from local_observe.evaluation.observer import judge
        from local_observe.observer.contract import Config, Source
        corpus = self.fixture()
        context = {'series': corpus['series'], 'evaluation': corpus['evaluation']}
        sources = [(Source(id='missing', query_type='metric-threshold', resource_id=RESOURCE, metric_name='other'),),
                   tuple(Source(id=name, query_type='metric-threshold', resource_id=RESOURCE, metric_name='cpu')
                         for name in ('first', 'second')),
                   (Source(id='logs', query_type='log-records', resource_id=RESOURCE),)]
        for selected in sources:
            with tempfile.TemporaryDirectory() as directory:
                with self.subTest(sources=selected), self.assertRaises(CorpusError):
                    judge(context, directory=Path(directory) / 'new', config=Config(sources=selected),
                          model_factory=lambda: self.fail('invalid mapping must refuse before model construction'))

    def test_actual_cycles_three_runs_keep_truth_out_and_persist_replay(self):
        calls = []
        class MeasuredFixtureModel:
            def complete(inner, evidence, allowed, config, now):
                calls.append(copy.deepcopy(evidence))
                item, row = evidence[0], evidence[0]['rows'][0]
                tell = row['value'] > 100
                answer = {'schema_version': 1, 'decision': 'tell' if tell else 'quiet',
                          'rationale': 'Fixture comparison only', 'follow_up': [],
                          'citations': [{'evidence_id': item['evidence_id'], 'row_index': 0,
                                         'field': 'value', 'value': row['value']}],
                          'findings': [{'resource_id': RESOURCE, 'kind': 'anomaly',
                                        'observed_at': row['timestamp'], 'evidence_ids': [item['evidence_id']]}]
                                      if tell else []}
                return {'content': json.dumps(answer), 'model': 'fixture', 'response_model': 'fixture-v1',
                        'usage': {'input_tokens': 40, 'output_tokens': 20}}

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evaluation'
            report = evaluate(self.fixture(), revision='a' * 40, observer_directory=output,
                              observer_model_factory=MeasuredFixtureModel)
            actual = report['arms']['llm-rca']
            self.assertEqual(actual['execution'], 'unjudgeable', 'fixture supplies no runtime provenance')
            self.assertEqual(actual['score']['true_positives'], 1)
            self.assertEqual(actual['score']['false_positives'], 0)
            self.assertEqual(report['flip_rate']['per_arm']['llm-rca'], 0)
            self.assertFalse(report['quality']['authorizes_delivery'])
            self.assertEqual(len(calls), 12)
            self.assertNotIn('first-hour', json.dumps(calls))
            self.assertNotIn('expected_class', json.dumps(calls))
            from local_observe.observer.journal import Journal
            restored = Journal(output / 'run-1')
            try:
                cycle = restored.replay('evaluation-' + str(int((START + dt.timedelta(hours=1)).timestamp())))
                self.assertEqual(cycle['evidence'][0]['rows'][0]['value'], 200)
                self.assertEqual(cycle['review'], 'unknown')
                self.assertFalse(cycle['delivery']['external_send'])
                self.assertEqual(os.stat(restored.path).st_mode & 0o777, 0o600)
            finally:
                restored.close()
            changed = self.fixture()
            changed['series'][0]['rows'][0]['v'] += 10
            with self.assertRaisesRegex(CorpusError, 'fresh'):
                evaluate(changed, revision='a' * 40, observer_directory=output,
                         observer_model_factory=MeasuredFixtureModel)
            self.assertEqual(len(calls), 12)

    def test_model_outage_cannot_be_scored_as_a_successful_quiet_cycle(self):
        class UnavailableModel:
            def complete(self, *args):
                raise TimeoutError('synthetic timeout')
        with tempfile.TemporaryDirectory() as directory:
            report = evaluate(self.fixture(), revision='b' * 40, observer_directory=Path(directory) / 'evaluation',
                              observer_model_factory=UnavailableModel)
        self.assertEqual(report['arms']['llm-rca']['execution'], 'unjudgeable')
        self.assertEqual(report['quality']['verdict'], 'fail')
        for cycle in report['arms']['llm-rca']['detail']['cycles']:
            self.assertEqual(cycle['status'], 'failed')
            self.assertIsNone(cycle['decision'])

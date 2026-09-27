"""Independent counterexamples for scoring, coverage, replay and runtime identity."""
import copy
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from local_observe.evaluation import arms
from local_observe.evaluation.decisions import baseline
from local_observe.evaluation.eval import flip_rate, score
from local_observe.evaluation.fault_inject import RESOURCE, START, synthetic
from local_observe.evaluation.manifest import build_manifest, verify_manifest
from local_observe.evaluation.model import CorpusError, ROOT, validate
from local_observe.evaluation.provenance import digest, validate_provenance
from local_observe.evaluation.quality import assess
from local_observe.evaluation.report import evaluate
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, utc_text


def provenance(config='a' * 64, **changes):
    value = {'schema_version': 1, 'implementation_sha256': 'b' * 64, 'prompt_sha256': 'c' * 64,
             'config_sha256': config, 'policy_sha256': 'd' * 64, 'capability_sha256': 'e' * 64,
             'budget_sha256': 'f' * 64, 'configured_model': 'example-alias', 'provider': 'example-provider',
             'model_version': 'example-v1', 'response_model': 'example-backend-v1', 'complete': True}
    value.update(changes)
    value['sha256'] = digest(value)
    return value


def observer_detail(value=None):
    value = value or provenance()
    cycle = {'status': 'completed', 'coverage': 'complete', 'config_sha256': value['config_sha256'],
             'provenance': value, 'model_calls': [{'status': 'completed', 'model': value['configured_model'],
                 'response_model': value['response_model'], 'provenance': value}]}
    return {'coverage_complete': True, 'config_sha256': value['config_sha256'],
            'provenance': value, 'cycles': [cycle]}


def quality_fixture():
    corpus = synthetic()
    corpus['evaluation']['end'] = utc_text(START + dt.timedelta(days=1))
    corpus['incidents'] = [{'id': 'novel-coverage', 'resource_id': RESOURCE, 'expected_class': 'coverage',
                           'window': {'start': utc_text(START), 'end': utc_text(START + dt.timedelta(hours=1))}}]
    corpus['quiet'] = []
    corpus['labelled'] = [{'resource_id': RESOURCE, 'window': dict(corpus['evaluation'])}]
    corpus = validate(corpus)
    finding = arms.finding(RESOURCE, 'coverage', (START + dt.timedelta(minutes=15)).timestamp(), arm='llm-rca')
    measured = {'execution': 'measured', 'score': score(corpus, [finding]), 'detail': observer_detail()}
    control = {'execution': 'measured', 'score': score(corpus, []),
               'detail': {'coverage_complete': True, 'unjudgeable_points': 0, 'unconfigured_series': 0}}
    return corpus, [{'llm-rca': copy.deepcopy(measured), 'static-threshold': copy.deepcopy(control),
                     'seasonal': copy.deepcopy(control)} for _ in range(3)]


class ScoringCorrectionsTests(unittest.TestCase):
    def test_distinct_classes_count_but_identical_retries_do_not(self):
        corpus, runs = quality_fixture()
        good = arms.finding(RESOURCE, 'coverage', (START + dt.timedelta(minutes=15)).timestamp(), arm='llm-rca')
        bad = arms.finding(RESOURCE, 'security', (START + dt.timedelta(minutes=30)).timestamp(), arm='llm-rca')
        self.assertNotEqual(good['source_event_id'], bad['source_event_id'])
        measured = score(corpus, [good, copy.deepcopy(good), bad])
        self.assertEqual((measured['true_positives'], measured['false_positives'], measured['duplicates']), (1, 1, 1))
        self.assertEqual(measured['precision'], .5)
        self.assertEqual(measured['findings_per_day'], 2)
        for run in runs:
            run['llm-rca']['score'] = measured
        self.assertEqual(assess(corpus, runs, observer_flip_rate=0)['verdict'], 'fail')
        bad['source_event_id'] = good['source_event_id']
        with self.assertRaisesRegex(CorpusError, 'Contradictory'):
            score(corpus, [good, bad])
        resolved = {**good, 'status': 'resolved'}
        for events in ([good, resolved], [resolved, good]):
            with self.assertRaisesRegex(CorpusError, 'Contradictory'):
                score(corpus, events)

    def test_unknown_resource_and_time_require_explicit_annotation(self):
        corpus, _ = quality_fixture()
        other = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
        event = arms.finding(other, 'security', (START + dt.timedelta(minutes=15)).timestamp(), arm='test')
        unknown = score(corpus, [event])
        self.assertEqual((unknown['false_positives'], unknown['unlabelled_findings']), (0, 1))
        self.assertIsNone(unknown['precision'])
        corpus['labelled'].append({'resource_id': other, 'window': dict(corpus['evaluation'])})
        self.assertEqual(score(corpus, [event])['false_positives'], 1)
        corpus['labelled'] = []
        event = arms.finding(RESOURCE, 'anomaly', (START + dt.timedelta(hours=3)).timestamp(), arm='test')
        self.assertEqual(score(corpus, [event])['unlabelled_findings'], 1)
        self.assertEqual(score(corpus, [event])['findings_per_day'], 1)

    def test_missing_malformed_and_inconsistent_scores_refuse(self):
        corpus, valid = quality_fixture()
        for name in valid[0]['llm-rca']['score']:
            runs = copy.deepcopy(valid)
            del runs[1]['llm-rca']['score'][name]
            with self.subTest(missing=name), self.assertRaises(CorpusError):
                assess(corpus, runs, observer_flip_rate=0)
        for value in (None, [], 7):
            runs = copy.deepcopy(valid)
            runs[1]['seasonal'] = value
            with self.subTest(arm=value), self.assertRaises(CorpusError):
                assess(corpus, runs, observer_flip_rate=0)
        for key, value in [('true_positives', True), ('precision', .75), ('findings_per_day', .5),
                           ('matched', ['novel-coverage', 'novel-coverage']), ('unlabelled_findings', -1)]:
            runs = copy.deepcopy(valid)
            runs[1]['llm-rca']['score'][key] = value
            with self.subTest(field=key), self.assertRaises(CorpusError):
                assess(corpus, runs, observer_flip_rate=0)

    def test_one_unstable_decision_is_one_disagreement_among_300(self):
        stable = {'llm-rca': {str(i): 'quiet' for i in range(100)}}
        runs = [copy.deepcopy(stable) for _ in range(3)]
        runs[2]['llm-rca']['50'] = 'watch'
        result = flip_rate(runs)
        self.assertEqual(result['measurements']['llm-rca']['disagreements'], 1)
        self.assertEqual(result['measurements']['llm-rca']['comparisons'], 300)
        self.assertAlmostEqual(result['per_arm']['llm-rca'], 1 / 300)
        del runs[1]['llm-rca']['50']
        result = flip_rate(runs)
        self.assertIsNone(result['per_arm']['llm-rca'])
        self.assertEqual(result['measurements']['llm-rca']['missing_decisions'], 1)

    def test_provenance_requires_complete_stable_alias_and_backend(self):
        corpus, runs = quality_fixture()
        self.assertTrue(validate_provenance(provenance(), require_complete=True)['complete'])
        self.assertEqual(assess(corpus, runs, observer_flip_rate=0)['verdict'], 'measured-pass')
        for detail in (observer_detail(provenance(response_model='different-backend')), {'coverage_complete': True},
                       observer_detail(provenance(model_version=None, complete=False))):
            changed = copy.deepcopy(runs)
            changed[1]['llm-rca']['detail'] = detail
            self.assertEqual(assess(corpus, changed, observer_flip_rate=0)['verdict'], 'fail')
        changed = copy.deepcopy(runs)
        changed[1]['llm-rca']['detail']['cycles'][0]['model_calls'][0]['provenance']['sha256'] = '0' * 64
        self.assertEqual(assess(corpus, changed, observer_flip_rate=0)['verdict'], 'fail')

    def test_provenance_rejects_placeholder_labels_but_accepts_version_identifiers(self):
        for value in ('unknown', 'UNSET', 'unmeasured', 'none', 'null', 'https://example.invalid/model'):
            with self.subTest(value=value), self.assertRaises(CorpusError):
                validate_provenance(provenance(model_version=value), require_complete=True)
        self.assertTrue(validate_provenance(provenance(model_version='example/model@version:1'),
                                            require_complete=True)['complete'])

    def test_manifest_contains_identity_and_ai_implementation(self):
        corpus, _ = quality_fixture()
        identity = {'schema_version': 1, 'config_sha256': 'a' * 64,
                    'configuration_authority': 'operator-supplied', 'provenance': provenance()}
        manifest = build_manifest(corpus, revision='a' * 40, arms=arms.NAMES, exclusions=[], observer=identity)
        self.assertEqual(manifest['observer'], identity)
        self.assertIn('local_observe/ai/client.py', manifest['implementation_sha256'])
        self.assertTrue(verify_manifest(manifest, corpus))
        manifest['observer']['config_sha256'] = '0' * 64
        with self.assertRaises(CorpusError):
            verify_manifest(manifest, corpus)

    def test_missing_or_mixed_baseline_coverage_cannot_earn_novelty(self):
        corpus, runs = quality_fixture()
        for value in (None, 1, True):
            changed = copy.deepcopy(runs)
            changed[0]['seasonal']['detail']['unjudgeable_points'] = value
            self.assertEqual(assess(corpus, changed, observer_flip_rate=0)['verdict'], 'fail')


class ComparisonCorrectionsTests(unittest.TestCase):
    def test_partly_configured_and_trained_baselines_are_incomplete(self):
        corpus = synthetic()
        unknown = copy.deepcopy(corpus['series'][0])
        unknown['metric'] = 'unconfigured-example'
        context = {'series': corpus['series'] + [unknown], 'evaluation': corpus['evaluation']}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.db'
            index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), path, 'test')
            result = arms.judge('static-threshold', context, index_path=path)
        self.assertTrue(result['findings'])
        self.assertEqual(result['unconfigured_series'], 1)
        self.assertEqual(result['status'], 'unjudgeable')
        context['series'] = copy.deepcopy(corpus['series'])
        context['series'][0]['rows'] = [row for row in context['series'][0]['rows']
            if row['ts'] >= START.timestamp() or dt.datetime.fromtimestamp(row['ts'], dt.timezone.utc).hour == 0]
        result = arms.judge('seasonal', context, index_path=None)
        self.assertTrue(result['findings'])
        self.assertEqual(result['unjudgeable_points'], 10)
        self.assertEqual(result['status'], 'unjudgeable')
        self.assertTrue(all(value is None for value in baseline(context, result).values()))

    def test_existing_directory_refuses_before_model_or_source_work(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('local_observe.evaluation.report.injected_read') as read:
                with self.assertRaisesRegex(CorpusError, 'fresh'):
                    evaluate(synthetic(), revision='a' * 40, observer_directory=directory)
                read.assert_not_called()

    def test_symlink_namespace_never_overwrites_existing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(CorpusError):
                evaluate(synthetic(), revision='a' * 40, observer_directory=root / 'link')
            self.assertTrue((root / 'link').is_symlink())

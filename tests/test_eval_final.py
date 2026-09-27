"""Acceptance counterexamples and real producer/baseline paths with synthetic adapters."""
import copy
from contextlib import redirect_stderr
from dataclasses import asdict
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_observe.evaluation.__main__ import main
from local_observe.evaluation.baseline_config import prepare, validate_config
from local_observe.evaluation.eval import flip_rate, score
from local_observe.evaluation.manifest import verify_manifest
from local_observe.evaluation.model import CorpusError, validate
from local_observe.evaluation.provenance import digest
from local_observe.evaluation.quality import assess
from local_observe.evaluation.report import evaluate
from local_observe.inventory.validation import utc_text
from local_observe.observer.contract import Config, Source

A = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc3'
B = 'dddddddd-dddd-4ddd-8ddd-ddddddddddd4'
START = dt.datetime(2025, 2, 1, tzinfo=dt.timezone.utc)


def inputs(two=False, optional=False):
    end = START + dt.timedelta(days=1)
    window = {'start': utc_text(START), 'end': utc_text(end)}
    resources = (A, B) if two else (A,)
    rows = [{'ts': (START + dt.timedelta(days=day, hours=hour, minutes=minute)).timestamp(), 'v': 1}
            for day in (-3, -2, -1, 0) for hour in range(24) for minute in (10, 40)]
    corpus = validate({'schema_version': 1, 'id': 'held-out-canary', 'origin': 'anonymized-example',
        'evaluation': window, 'incidents': [{'id': 'truth-canary', 'resource_id': A, 'expected_class': 'coverage',
            'window': {'start': utc_text(START), 'end': utc_text(START + dt.timedelta(minutes=20))}}],
        'quiet': [], 'labelled': [{'resource_id': resource, 'window': window} for resource in resources],
        'series': [{'resource_id': resource, 'metric': 'metric', 'rows': copy.deepcopy(rows)} for resource in resources]})
    config = Config(sources=tuple(Source('source-' + str(i), 'metric-threshold', resource, metric_name='metric',
                                       initial=not (optional and resource == B)) for i, resource in enumerate(resources)),
                    max_rows=2000, max_age_seconds=3600, mode='recording')
    baseline = {'schema_version': 1, 'thresholds': [{'resource_id': r, 'metric': 'metric', 'threshold': 10}
                                                  for r in resources]}
    return corpus, config, baseline


class SyntheticModel:
    """Uses real producer provenance and answer validation, without any transport."""
    def __init__(self, *, multiple=False, reverse=False, duplicate=False, watch=False):
        self.multiple, self.reverse, self.duplicate, self.watch = multiple, reverse, duplicate, watch
        self.calls = []

    def provenance(self):
        return {'configured_model': 'synthetic-alias', 'response_model': 'synthetic-backend',
                'provider': 'synthetic-provider', 'model_version': 'synthetic@1',
                'policy_sha256': '1' * 64, 'capability_sha256': '2' * 64, 'budget_sha256': '3' * 64}

    def complete(self, evidence, allowed, config, now):
        self.calls.append({'evidence': copy.deepcopy(evidence), 'allowed': sorted(allowed), 'config': asdict(config)})
        item = next(row for row in evidence if row['resource_id'] == A)
        rows = list(enumerate(item['rows']))
        first = item['window']['start'].startswith('2025-02-01T00:00:00')
        selected = rows[:2 if self.multiple else 1] if first else rows[:1]
        findings = [{'resource_id': A, 'kind': 'coverage', 'observed_at': row['timestamp'],
                     'evidence_ids': [item['evidence_id']]} for _, row in selected] if first else []
        if self.duplicate and findings:
            findings.append(copy.deepcopy(findings[0]))
        if self.reverse:
            findings.reverse()
        answer = {'schema_version': 1, 'decision': 'tell' if findings else
                  'watch' if self.watch and now.hour == 4 else 'quiet',
                  'rationale': 'Synthetic grounded observation', 'follow_up': [], 'findings': findings,
                  'citations': [{'evidence_id': item['evidence_id'], 'row_index': i, 'field': 'value',
                                 'value': row['value']} for i, row in selected]}
        return {'content': json.dumps(answer), 'model': 'synthetic-alias', 'response_model': 'synthetic-backend',
                'usage': {'input_tokens': 10, 'output_tokens': 10}}


class FinalEvaluatorTests(unittest.TestCase):
    def evaluate(self, corpus, config, baseline, factory=SyntheticModel):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return evaluate(corpus, revision='a' * 40, observer_directory=Path(directory.name) / 'evaluation',
                        observer_config=config, baseline_config=baseline, observer_model_factory=factory)

    def test_same_class_distinct_observations_cannot_hide_false_positive_in_either_order(self):
        corpus, config, baseline = inputs()
        for reverse in (False, True):
            result = self.evaluate(corpus, config, baseline,
                                   lambda: SyntheticModel(multiple=True, reverse=reverse))
            score = result['arms']['llm-rca']['score']
            self.assertEqual((score['true_positives'], score['false_positives'], score['precision'],
                              score['findings_per_day']), (1, 1, .5, 2))
            self.assertEqual(result['quality']['verdict'], 'fail')
            self.assertFalse(result['quality']['authorizes_delivery'])
            events = result['measurement']['runs'][0]['llm-rca']['findings']
            self.assertEqual(len(events), 2)
            self.assertEqual(len({event['source_event_id'] for event in events}), 2)

    def test_real_producer_exact_retry_and_operator_sources_pass_without_truth_leakage(self):
        corpus, config, baseline = inputs(two=True)
        models = []
        def factory():
            models.append(SyntheticModel(duplicate=True))
            return models[-1]
        result = self.evaluate(corpus, config, baseline, factory)
        self.assertEqual(result['quality']['verdict'], 'measured-pass')
        self.assertFalse(result['quality']['authorizes_delivery'])
        self.assertEqual(result['arms']['llm-rca']['score']['duplicates'], 1)
        self.assertEqual(result['arms']['llm-rca']['score']['total_findings'], 1)
        self.assertEqual(result['manifest']['observer']['config_sha256'], digest(asdict(config)))
        self.assertTrue(result['manifest']['observer']['provenance']['complete'])
        self.assertEqual(result['manifest']['baseline']['configuration_authority'], 'operator-supplied')
        self.assertTrue(verify_manifest(result['manifest'], corpus, baseline_config=baseline))
        with self.assertRaises(CorpusError):
            verify_manifest(result['manifest'], corpus)
        changed = copy.deepcopy(baseline)
        changed['thresholds'][0]['threshold'] = 11
        with self.assertRaises(CorpusError):
            verify_manifest(result['manifest'], corpus, baseline_config=changed)
        self.assertEqual([len(model.calls) for model in models], [24, 24, 24])
        for marker in ('truth-canary', 'held-out-canary', 'labelled', 'incidents'):
            self.assertNotIn(marker, json.dumps([model.calls for model in models]))

    def test_unread_optional_resource_is_unknown_and_cannot_dilute_cycle_flips(self):
        corpus, config, baseline = inputs(two=True, optional=True)
        result = self.evaluate(corpus, config, baseline)
        arm = result['arms']['llm-rca']
        self.assertEqual(arm['execution'], 'unjudgeable')
        self.assertFalse(arm['detail']['coverage_complete'])
        self.assertTrue(all(value is None for key, value in arm['detail']['resource_findings'].items() if B in key))
        measurement = result['flip_rate']['measurements']['llm-rca']
        self.assertEqual((measurement['unit'], measurement['units'], measurement['comparisons'],
                          measurement['missing_decisions']), ('cycle-window', 24, 72, 72))
        self.assertIsNone(result['flip_rate']['per_arm']['llm-rca'])
        self.assertEqual(result['quality']['verdict'], 'fail')

    def test_one_actual_cycle_verdict_change_uses_one_cycle_denominator(self):
        corpus, config, baseline = inputs(two=True)
        models = []
        def factory():
            models.append(SyntheticModel(watch=len(models) == 2))
            return models[-1]
        result = self.evaluate(corpus, config, baseline, factory)
        measured = result['flip_rate']['measurements']['llm-rca']
        self.assertEqual((measured['units'], measured['disagreements'], measured['comparisons']), (24, 1, 72))
        self.assertEqual(result['flip_rate']['per_arm']['llm-rca'], 1/72)
        values = result['arms']['llm-rca']['detail']['resource_findings'].values()
        self.assertTrue(all('decision' not in value for value in values))

    def test_nested_unknown_or_inconsistent_cycles_cannot_pass_assessment(self):
        corpus, config, baseline = inputs()
        result = self.evaluate(corpus, config, baseline)
        for field, value in [('decision', None), ('decision', []), ('structured_findings', False),
                             ('structured_findings', 1), ('evaluation_complete', False), ('error', 'failed')]:
            runs = copy.deepcopy(result['runs'])
            runs[1]['llm-rca']['detail']['cycles'][0][field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(assess(corpus, runs, observer_flip_rate=0)['verdict'], 'fail')

    def test_retained_measurements_recompute_scores_novelty_and_flip_summaries(self):
        corpus, config, baseline = inputs(two=True)
        result = self.evaluate(corpus, config, baseline)
        measured = result['measurement']
        self.assertEqual(set(measured), {'schema_version', 'corpus', 'baseline_config', 'runs'})
        self.assertEqual(measured['schema_version'], 1)
        self.assertEqual(measured['corpus'], validate(corpus))
        self.assertEqual(measured['baseline_config'], validate_config(baseline))
        self.assertEqual(len(measured['runs']), 3)
        recomputed = copy.deepcopy(result['runs'])
        maps = []
        for number, run in enumerate(measured['runs']):
            self.assertEqual(set(run), {'static-threshold', 'seasonal', 'shaping', 'llm-rca'})
            maps.append({name: arm['decisions'] for name, arm in run.items()})
            for name, arm in run.items():
                self.assertEqual(set(arm), {'findings', 'decisions'})
                recomputed[number][name]['score'] = score(measured['corpus'], arm['findings'])
            cycles = result['runs'][number]['llm-rca']['detail']['cycles']
            self.assertTrue(all(cycle['covered_sources'] == ['source-0', 'source-1'] for cycle in cycles))
            self.assertTrue(all(cycle['evaluation_complete'] for cycle in cycles))
        flips = flip_rate(maps)
        self.assertEqual(recomputed, result['runs'])
        self.assertEqual(flips['per_arm'], result['flip_rate']['per_arm'])
        self.assertEqual(assess(measured['corpus'], recomputed, observer_flip_rate=flips['per_arm']['llm-rca']),
                         result['quality'])

    def test_arbitrary_resource_runs_actual_static_detector_with_explicit_threshold(self):
        corpus, _, baseline = inputs()
        corpus['incidents'][0]['expected_class'] = 'threshold'
        next(row for row in corpus['series'][0]['rows'] if row['ts'] >= START.timestamp())['v'] = 15
        result = evaluate(corpus, revision='a' * 40, baseline_config=baseline)
        arm = result['arms']['static-threshold']
        self.assertEqual(arm['execution'], 'measured')
        self.assertEqual((arm['score']['true_positives'], arm['score']['false_positives']), (1, 0))
        self.assertEqual(result['read_receipts'][0]['resource_id'], A)
        self.assertEqual(result['read_receipts'][0]['rows'], 192)

    def test_missing_malformed_or_ambiguous_operator_settings_refuse(self):
        corpus, config, baseline = inputs()
        for value in (None, [], {}, {'schema_version': True, 'thresholds': baseline['thresholds']},
                      {'schema_version': 1, 'thresholds': []},
                      {**baseline, 'thresholds': baseline['thresholds'] * 2}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_config(value)
        for number in (True, None, float('nan'), float('inf'), '10'):
            invalid = copy.deepcopy(baseline)
            invalid['thresholds'][0]['threshold'] = number
            with self.subTest(number=number), self.assertRaises(ValueError):
                prepare(corpus, invalid)
        for changed in ('resource_id', 'metric'):
            invalid = copy.deepcopy(baseline)
            invalid['thresholds'][0][changed] = B if changed == 'resource_id' else 'other'
            with self.assertRaises(CorpusError):
                self.evaluate(corpus, config, invalid, lambda: self.fail('must refuse before model'))
        with self.assertRaises(CorpusError):
            self.evaluate(corpus, config, None, lambda: self.fail('must refuse before model'))

    def test_cli_accepts_exact_operator_and_baseline_configs_and_refuses_duplicate_json(self):
        corpus, config, baseline = inputs()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, value in [('corpus.json', corpus), ('observer.json', asdict(config)), ('baseline.json', baseline)]:
                (root / filename).write_text(json.dumps(value), encoding='utf-8')
            args = ['--revision', 'a' * 40, '--corpus', str(root / 'corpus.json'),
                    '--observer-config', str(root / 'observer.json'), '--baseline-config', str(root / 'baseline.json'),
                    '--observer-directory', str(root / 'run'), '--output', str(root / 'run/report.json')]
            with patch('local_observe.evaluation.observer.CurrentModel', SyntheticModel):
                self.assertEqual(main(args), 0)
            result = json.loads((root / 'run/report.json').read_text(encoding='utf-8'))
            self.assertEqual(result['quality']['verdict'], 'measured-pass')
            self.assertEqual((root / 'run/report.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(result['measurement']['baseline_config'], validate_config(baseline))
            (root / 'baseline.json').write_text('{"schema_version":1,"schema_version":1}', encoding='utf-8')
            with redirect_stderr(io.StringIO()), patch('local_observe.evaluation.observer.CurrentModel') as factory:
                self.assertEqual(main(args), 2)
                factory.assert_not_called()

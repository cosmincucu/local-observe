"""Independent scoring truth, negative controls, bounds and report provenance."""
import copy
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from local_observe.evaluation import arms
from local_observe.evaluation.__main__ import main
from local_observe.evaluation.eval import flip_rate, score
from local_observe.evaluation.fault_inject import RESOURCE, START, synthetic
from local_observe.evaluation.manifest import build_manifest, verify_manifest
from local_observe.evaluation.model import CorpusError, load, validate
from local_observe.evaluation.report import evaluate
from local_observe.inventory.validation import utc_text
from local_observe.platform.state import Actor, Store

REVISION = 'a' * 40


class EvaluationGateTests(unittest.TestCase):
    def corpus(self):
        corpus = synthetic()
        for truth in corpus['incidents']:
            truth['expected_class'] = 'anomaly'
        return corpus

    def event(self, hour, *, arm='control', resource=RESOURCE, kind='anomaly'):
        return arms.finding(resource, kind, (START + dt.timedelta(hours=hour)).timestamp(), arm=arm)

    def test_three_truth_two_hits_one_quiet_is_two_thirds_not_point_adjusted(self):
        measured = score(self.corpus(), [self.event(0), self.event(1), self.event(3)])
        self.assertEqual([measured[k] for k in ('true_positives', 'false_positives', 'false_negatives')], [2, 1, 1])
        self.assertAlmostEqual(measured['precision'], 2 / 3)
        self.assertAlmostEqual(measured['recall'], 2 / 3)
        self.assertEqual(measured['findings_per_day'], 18)
        with self.assertRaises(CorpusError):
            score(self.corpus(), [], point_adjust=True)

    def test_duplicates_cannot_credit_another_incident_and_extra_findings_cost_precision(self):
        event = self.event(0)
        result = score(self.corpus(), [event, copy.deepcopy(event), self.event(.5, arm='other')])
        self.assertEqual((result['true_positives'], result['false_positives'], result['duplicates']), (1, 1, 1))

    def test_half_open_end_and_wrong_resource_or_class_cannot_match(self):
        corpus = self.corpus()
        corpus['incidents'] = corpus['incidents'][:1]
        corpus['labelled'] = [{'resource_id': RESOURCE, 'window': dict(corpus['incidents'][0]['window'])}]
        inputs = [self.event(1), self.event(0, resource='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'),
                  self.event(0, kind='threshold')]
        result = score(corpus, inputs)
        self.assertEqual((result['true_positives'], result['false_positives']), (0, 1))
        self.assertEqual(result['unlabelled_findings'], 2)
        self.assertEqual(score(corpus, [self.event(0)])['true_positives'], 1)

    def test_fires_everywhere_fails_explicit_test_policy_unwired_never_passes(self):
        findings = [self.event(hour) for hour in range(4)]
        result = score(self.corpus(), findings, min_precision=.9)
        self.assertEqual(result['precision'], .75)
        self.assertEqual(result['verdict'], 'fail')
        unwired = arms.judge('llm-rca', {'series': [], 'evaluation': {}}, index_path=None)
        self.assertEqual(unwired['status'], 'unwired')
        self.assertEqual(unwired['findings'], [])
        self.assertEqual(score(self.corpus(), [], min_precision=.9)['verdict'], 'fail')

    def test_nested_arrays_missing_boolean_nonfinite_and_huge_inputs_refuse(self):
        for row in ([1, 2], {'ts': 1}, {'ts': True, 'v': 1}, {'ts': 1767571200, 'v': float('nan')},
                    {'ts': 1767571200, 'v': float('inf')}, {'ts': 1767571200, 'v': [1]}):
            corpus = self.corpus()
            corpus['series'][0]['rows'] = [row]
            with self.subTest(row=row), self.assertRaises(CorpusError):
                validate(corpus)
        corpus = self.corpus()
        corpus['series'][0]['rows'] *= 2001
        with self.assertRaises(CorpusError):
            validate(corpus)
        with self.assertRaises(CorpusError):
            score(self.corpus(), [self.event(0)] * 4097)

    def test_unknown_fields_ambiguous_truth_quiet_truth_and_duplicate_json_refuse(self):
        mutations = []
        corpus = self.corpus(); corpus['incidents'][0]['unexpected'] = 1; mutations.append(corpus)
        corpus = self.corpus(); corpus['incidents'].append(copy.deepcopy(corpus['incidents'][0])); mutations.append(corpus)
        corpus = self.corpus(); corpus['quiet'].append(corpus['incidents'][0]['window']); mutations.append(corpus)
        corpus = self.corpus(); corpus['schema_version'] = True; mutations.append(corpus)
        for corpus in mutations:
            with self.assertRaises(CorpusError):
                validate(corpus)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            path.write_text('{"x":1,"x":2}', encoding='utf-8')
            with self.assertRaises(CorpusError):
                load(path)
            path.write_bytes(b' ' * 1048577)
            with self.assertRaises(CorpusError):
                load(path)

    def test_cross_arm_disagreement_is_not_a_flip_but_one_arm_change_is(self):
        stable = {'a': {'unit': 'quiet'}, 'b': {'unit': 'tell'}}
        self.assertEqual(flip_rate([stable.copy() for _ in range(3)])['rate'], 0)
        changed = flip_rate([stable, stable, {'a': {'unit': 'watch'}, 'b': {'unit': 'tell'}}])
        self.assertAlmostEqual(changed['per_arm']['a'], 1 / 3)
        self.assertAlmostEqual(changed['rate'], 1 / 6)
        with self.assertRaises(CorpusError):
            flip_rate([stable, stable])

    def test_manifest_detects_telemetry_and_implementation_tampering(self):
        corpus = self.corpus()
        manifest = build_manifest(corpus, revision=REVISION, arms=arms.NAMES, exclusions=['private'])
        self.assertTrue(verify_manifest(manifest, corpus))
        changed = copy.deepcopy(corpus); changed['series'][0]['rows'][0]['v'] += 1
        with self.assertRaises(CorpusError):
            verify_manifest(manifest, changed)
        manifest['implementation_sha256']['local_observe/platform/anomaly.py'] = '0' * 64
        with self.assertRaises(CorpusError):
            verify_manifest(manifest, corpus)

    def test_canonical_findings_really_enter_platform_store(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'state.db')
            event = self.event(0)
            answer = store.intake(event, Actor(event['source'], 'producer'), now=START + dt.timedelta(hours=4))
            self.assertIsInstance(answer, dict)

    def test_three_run_report_and_exclusive_cli_artifact(self):
        report = evaluate(synthetic(), revision=REVISION)
        self.assertIsNone(report['flip_rate']['rate'], 'unwired and missing decisions are unknown')
        self.assertEqual(report['arms']['llm-rca']['execution'], 'unwired')
        self.assertIsNone(report['arms']['llm-rca']['score'])
        self.assertEqual(report['uncovered_truth_classes'], ['coverage'])
        print(json.dumps({'evaluation': report['arms'], 'flip_rate': report['flip_rate']}))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            self.assertEqual(main(['--revision', REVISION, '--output', str(path)]), 0)
            before = path.read_bytes()
            self.assertEqual(main(['--revision', REVISION, '--output', str(path)]), 2)
            self.assertEqual(path.read_bytes(), before)

    def test_evaluation_selector_and_base_union_have_no_extra_execution(self):
        from tests import tiers

        selectors = tiers.tier_selectors('evaluation')
        owned = ('test_eval_gate.EvaluationGateTests.test_one',
                 'test_eval_arms.ArmTests.test_one', 'test_fault_injection.FaultInjectionTests.test_one')
        unowned = ('test_eval_gate_extra.Case.test_one', 'test_anomaly.Case.test_one')
        all_ids = set(owned + unowned)
        evaluation = {item for item in all_ids if tiers.id_selected(item, selectors)}
        remainder = all_ids - evaluation
        self.assertEqual(evaluation, set(owned))
        self.assertFalse(evaluation & remainder)
        self.assertEqual(evaluation | remainder, all_ids)
        # CI reports quality separately but invokes unittest for this subgroup only in base.
        import yaml

        from local_observe.evaluation.model import ROOT

        workflow = yaml.safe_load((ROOT / '.gitea/workflows/ci.yml').read_text(encoding='utf-8'))
        commands = '\n'.join(step.get('run', '') for step in workflow['jobs']['deterministic-tests']['steps'])
        self.assertNotIn('--only-tier evaluation', commands)
        self.assertEqual(commands.count('-m local_observe.evaluation'), 1)
        self.assertIn('--fail-under=76', commands)

"""Full producer/consumer contract using synthetic transport and independent fixture truth."""
import copy
import datetime as dt
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from local_observe.evaluation.fault_inject import RESOURCE, START
from local_observe.evaluation.report import evaluate
from local_observe.inventory.validation import utc_text
from local_observe.observer.acceptance import AcceptedQuality, accept_quality, validate_report
from local_observe.observer.contract import Config, ObserverError, Source, digest, encoded
from local_observe.observer.journal import Journal
from local_observe.observer.provenance import build_provenance
from local_observe.observer.telegram import TelegramConfig


class FixtureModel:
    calls = []

    def provenance(self):
        return {'configured_model': 'fixture-alias', 'provider': 'fixture-provider',
                'model_version': 'fixture-v1', 'policy_sha256': digest({'policy': 'fixture'}),
                'capability_sha256': digest({'capability': 'fixture'}),
                'budget_sha256': digest({'budget': 'fixture'})}

    def complete(self, evidence, allowed, config, now):
        self.calls.append(copy.deepcopy(evidence))
        item = evidence[0]
        row = item['rows'][0]
        tell = row['value'] == 21e9
        return {'model': 'fixture-alias', 'response_model': 'fixture-backend-v1',
                'content': encoded({'schema_version': 1, 'decision': 'tell' if tell else 'quiet',
                    'rationale': 'Synthetic contract fixture only.', 'follow_up': [],
                    'citations': [{'evidence_id': item['evidence_id'], 'row_index': 0,
                                  'field': 'value', 'value': row['value']}],
                    'findings': [{'resource_id': RESOURCE, 'kind': 'security',
                                  'observed_at': row['timestamp'], 'evidence_ids': [item['evidence_id']]}]
                                if tell else []})}


def fixture_corpus():
    end = START + dt.timedelta(days=1)
    points = [{'ts': (START - dt.timedelta(days=days) + dt.timedelta(hours=hour, minutes=59)).timestamp(),
               'v': level} for days, level in ((3, 18e9), (2, 20e9), (1, 22e9)) for hour in range(24)]
    points += [{'ts': (START + dt.timedelta(hours=hour, minutes=59)).timestamp(),
                'v': 21e9 if hour == 0 else 20e9} for hour in range(24)]
    return {'schema_version': 1, 'id': 'contract-fixture-only', 'origin': 'generated-demo',
            'evaluation': {'start': utc_text(START), 'end': utc_text(end)},
            'incidents': [{'id': 'independent-truth-marker', 'resource_id': RESOURCE, 'expected_class': 'security',
                           'window': {'start': utc_text(START), 'end': utc_text(START + dt.timedelta(hours=1))}}],
            'quiet': [], 'labelled': [{'resource_id': RESOURCE,
                                      'window': {'start': utc_text(START), 'end': utc_text(end)}}],
            'series': [{'resource_id': RESOURCE, 'metric': 'filesystem_used_bytes',
                        'rows': sorted(points, key=lambda row: row['ts'])}]}


class ProducerAcceptanceTests(unittest.TestCase):
    def test_real_producer_report_round_trip_and_generated_gate(self):
        config = Config(sources=(Source('disk', 'metric-threshold', RESOURCE,
                                        metric_name='filesystem_used_bytes'),), mode='shadow')
        FixtureModel.calls = []
        model = FixtureModel()
        corpus = fixture_corpus()
        provenance = build_provenance(config, model, response_model='fixture-backend-v1')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = evaluate(corpus, revision='a' * 40, observer_directory=root / 'evaluation',
                              observer_model_factory=FixtureModel, observer_config=config)
            self.assertEqual(len(FixtureModel.calls), 72)
            self.assertNotIn('independent-truth-marker', encoded(FixtureModel.calls))
            self.assertNotIn('expected_class', encoded(FixtureModel.calls))
            self.assertEqual(report['quality']['verdict'], 'measured-pass')
            self.assertEqual(report['quality']['novel_classes'], ['security'])
            self.assertEqual(report['manifest']['observer']['provenance'], provenance)
            self.assertFalse(report['quality']['authorizes_delivery'])
            with self.assertRaisesRegex(ObserverError, 'independent_corpus_required'):
                validate_report(report, config_sha256=digest(asdict(config)), provenance=provenance)
            # Contract-only attested-origin fixture. This edit is NOT measured independent model quality.
            corpus['origin'] = 'anonymized-example'
            measured = evaluate(corpus, revision='a' * 40, observer_directory=root / 'attested-fixture',
                                observer_model_factory=FixtureModel, observer_config=config)
            validate_report(measured, config_sha256=digest(asdict(config)), provenance=provenance)
            report_path = root / 'report.json'
            report_path.write_text(encoded(measured), encoding='utf-8')
            report_path.chmod(0o600)
            journal = Journal(root / 'runtime')
            self.addCleanup(journal.close)
            channel = TelegramConfig(str(root / 'unused-token'), 42, 73)
            acceptance = journal.directory / 'acceptance.json'
            now = dt.datetime.now(dt.timezone.utc)
            receipt = accept_quality(journal, report_path=report_path, config=config, model=model, channel=channel,
                output=acceptance, expires_at=utc_text(now + dt.timedelta(hours=1)),
                independent_held_out_labels=True, now=now)
            verifier = AcceptedQuality(acceptance, report_path, journal=journal, config=config,
                                       model=model, channel=channel)
            self.assertEqual(verifier.verify(now), receipt)
            report_path.write_text(encoded(measured) + '\n', encoding='utf-8')
            with self.assertRaisesRegex(ObserverError, 'accepted_report_changed'):
                verifier.verify(now)

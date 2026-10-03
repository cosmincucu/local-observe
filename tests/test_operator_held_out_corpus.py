"""Synthetic contract checks; no fixture here establishes independent model quality."""
import copy
import datetime as dt
import json
from dataclasses import asdict
from pathlib import Path
import unittest

import jsonschema

from local_observe.evaluation.manifest import build_manifest
from local_observe.evaluation.model import CorpusError, validate
from local_observe.observer import Config, ObserverError, Source
from local_observe.observer.acceptance import accept_quality, validate_report
from local_observe.observer.contract import digest
from local_observe.observer.provenance import build_provenance
from test_observer_completion import ModelFixture, NOW, RESOURCE, measured_report


class HeldOutCorpusTests(unittest.TestCase):
    def setUp(self):
        self.config = Config((Source('cpu', 'metric-threshold', RESOURCE, metric_name='cpu'),))
        self.model = ModelFixture()
        self.provenance = build_provenance(self.config, self.model, response_model='backend-v1')
        self.report = measured_report(self.config, self.provenance)
        self.schema = json.loads((Path(__file__).resolve().parents[1] /
                                  'examples/corpus/schema.json').read_text(encoding='utf-8'))

    def report_for(self, origin):
        report = copy.deepcopy(self.report)
        report['measurement']['corpus']['origin'] = origin
        report['quality']['corpus_origin'] = origin
        old = report['manifest']
        report['manifest'] = build_manifest(report['measurement']['corpus'], revision=old['revision'],
            arms=old['arms'], exclusions=old['exclusions'], observer=old['observer'],
            baseline_config=report['measurement']['baseline_config'])
        return report

    def check_report(self, report):
        return validate_report(report, config_sha256=digest(asdict(self.config)),
                               provenance=self.provenance, config=self.config)

    def test_schema_and_runtime_accept_the_same_three_origins(self):
        for origin in ('generated-demo', 'anonymized-example', 'operator-held-out'):
            with self.subTest(origin=origin):
                corpus = self.report_for(origin)['measurement']['corpus']
                jsonschema.validate(corpus, self.schema)
                self.assertEqual(validate(corpus)['origin'], origin)
        for origin in ('private', '', None, [], {}):
            with self.subTest(origin=origin):
                corpus = {**self.report['measurement']['corpus'], 'origin': origin}
                with self.assertRaises(CorpusError):
                    validate(corpus)
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(corpus, self.schema)

    def test_private_and_legacy_reports_recompute_but_never_authorize_delivery(self):
        for origin in ('operator-held-out', 'anonymized-example'):
            with self.subTest(origin=origin):
                result = self.check_report(self.report_for(origin))
                self.assertFalse(result['quality']['authorizes_delivery'])

    def test_generated_origin_refuses_even_with_valid_measurements(self):
        with self.assertRaisesRegex(ObserverError, 'independent_corpus_required'):
            self.check_report(self.report_for('generated-demo'))

    def test_origin_does_not_mask_modified_measurements_or_incomplete_provenance(self):
        report = self.report_for('operator-held-out')
        report['measurement']['corpus']['series'][0]['rows'][0]['v'] = 0.0
        with self.assertRaises(ObserverError):
            self.check_report(report)
        self.provenance = build_provenance(self.config, self.model)
        with self.assertRaises(ObserverError):
            self.check_report(self.report_for('operator-held-out'))

    def test_explicit_independent_label_attestation_is_still_required(self):
        with self.assertRaisesRegex(ObserverError, 'independent_held_out_attestation_required'):
            accept_quality(None, report_path=None, config=self.config, model=self.model, channel=None,
                output=None, expires_at=(NOW + dt.timedelta(days=1)).isoformat(),
                independent_held_out_labels=False, now=NOW)

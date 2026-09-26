"""Executable faults round-trip actual store types, declared inventory and bounded reads."""
import copy
import datetime as dt
import unittest

from local_observe.evaluation.fault_inject import RESOURCE, START, injected_read, seed_store, synthetic
from local_observe.evaluation.model import CorpusError
from local_observe.inventory.validation import utc_text
from local_observe.store.client import Window


class FaultInjectionTests(unittest.TestCase):
    def test_public_schema_example_and_same_privacy_token_list(self):
        import json

        from jsonschema import Draft202012Validator, FormatChecker

        from local_observe.evaluation.model import ROOT, load
        from scripts.check_foundation import BANNED_TOKENS

        directory = ROOT / 'examples/corpus'
        schema = json.loads((directory / 'schema.json').read_text(encoding='utf-8'))
        example = load(directory / 'worked-example.json')
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(example)
        expected = synthetic(); expected['id'] = 'worked-anonymized-shape'; expected['origin'] = 'anonymized-example'
        self.assertEqual(example, expected)
        hits = [(path.name, token) for path in directory.iterdir() if path.is_file()
                for token in BANNED_TOKENS if token in path.read_text(encoding='utf-8').lower()]
        self.assertEqual(hits, [])

    def test_injection_is_repeatable_and_actual_store_roundtrip_keeps_every_row(self):
        corpus = synthetic()
        self.assertEqual(corpus, synthetic())
        loaded, receipts = injected_read(corpus)
        self.assertEqual(loaded, corpus)
        self.assertEqual(receipts[0]['rows'], 75)
        self.assertEqual(receipts[0]['status'], 'available')

    def test_store_half_open_boundary_excludes_next_hour(self):
        corpus = synthetic(); store = seed_store(corpus)
        outcome = store.read_metrics('metric-threshold',
            window=Window(utc_text(START), utc_text(START + dt.timedelta(hours=1))),
            parameters={'resource_id': RESOURCE, 'rule_id': 'eval.read'},
            selectors={'metric_name': 'filesystem_used_bytes'})
        self.assertEqual(len(outcome.samples), 5)
        self.assertEqual({row.value for row in outcome.samples}, {96e9})

    def test_unrecognised_resource_rejected_before_fixture_is_scored(self):
        corpus = synthetic()
        corpus['series'][0]['resource_id'] = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd'
        with self.assertRaises(CorpusError):
            seed_store(corpus)

    def test_missing_interval_has_truth_but_no_fabricated_zero_rows(self):
        corpus = synthetic()
        current = [row for row in corpus['series'][0]['rows']
                   if (START + dt.timedelta(hours=2)).timestamp() <= row['ts']
                   < (START + dt.timedelta(hours=3)).timestamp()]
        self.assertEqual(current, [])
        self.assertEqual(corpus['incidents'][2]['expected_class'], 'coverage')
        self.assertEqual(len(corpus['quiet']), 1)

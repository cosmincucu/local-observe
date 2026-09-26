"""Tests for the evidence budget: whole-bundle refusal, and expired evidence reported as expired."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.ai import budget
from local_observe.ai.budget import BudgetError

NOW = dt.datetime(2026, 9, 8, 10, 30, tzinfo=dt.timezone.utc)
WINDOW = {'start': '2026-09-08T10:00:00+00:00', 'end': '2026-09-08T10:05:00+00:00'}


def reference(**changes):
    """One canonical evidence reference, fresh unless *changes* say otherwise."""
    item = {'source': 'sigma-example', 'query_type': 'sigma-count',
            'parameters': {'rule_id': 'disk-full'}, 'window': dict(WINDOW), 'schema_version': 1,
            'expires_at': '2026-09-08T11:00:00+00:00'}
    item.update(changes)
    return item


class BudgetFileTests(unittest.TestCase):
    def test_no_file_means_the_shipped_defaults(self):
        self.assertEqual(budget.load(None), budget.DEFAULTS)
        self.assertEqual(budget.load(''), budget.DEFAULTS)
        self.assertEqual(budget.load('   '), budget.DEFAULTS)

    def test_a_file_may_only_make_a_call_smaller(self):
        self.assertEqual(budget.validate({'max_completion_tokens': 64})['max_completion_tokens'], 64)
        self.assertEqual(budget.validate({'max_completion_tokens': 64})['max_evidence_items'],
                         budget.DEFAULTS['max_evidence_items'])
        with self.assertRaises(BudgetError):
            budget.validate({'max_evidence_items': 21})
        with self.assertRaises(BudgetError):
            budget.validate({'max_evidence_bytes': 131_072})
        for bad in ({'max_prompt_bytes': 'lots'}, {'max_prompt_bytes': True}, {'max_evidence_items': 0},
                    {'context': 100}, {'max_prompt_bytes': 1024, 'max_evidence_bytes': 4096}):
            with self.subTest(bad=bad):
                with self.assertRaises(BudgetError):
                    budget.validate(bad)

    def test_a_budget_file_is_bounded_and_must_be_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'budget.json').write_text(json.dumps({'max_evidence_bytes': 4_096,
                                                          'max_prompt_bytes': 8_192}), encoding='utf-8')
            loaded = budget.load(root / 'budget.json')
            self.assertEqual(loaded['max_prompt_bytes'], 8_192)
            self.assertEqual(loaded['max_evidence_bytes'], 4_096)
            self.assertEqual(loaded['max_completion_tokens'], budget.DEFAULTS['max_completion_tokens'])
            (root / 'big.json').write_text(json.dumps({'pad': 'x' * 5000}), encoding='utf-8')
            with self.assertRaises(BudgetError):
                budget.load(root / 'big.json')
            (root / 'broken.json').write_text('nope', encoding='utf-8')
            with self.assertRaises(BudgetError):
                budget.load(root / 'broken.json')


class BudgetPlanTests(unittest.TestCase):
    def plan(self, items, *, prompt_bytes=40, **changes):
        limits = dict(budget.DEFAULTS, **changes)
        return budget.plan(budget.validate(limits), items, prompt_bytes=prompt_bytes, now=NOW)

    def test_a_fresh_bounded_bundle_is_admitted_with_its_size_recorded(self):
        result = self.plan([reference()])
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['evidence_bytes'], budget.payload_bytes([reference()]))
        self.assertEqual(len(result['items']), 1)
        self.assertEqual(result['max_completion_tokens'], budget.DEFAULTS['max_completion_tokens'])

    def test_an_empty_bundle_is_refused_rather_than_explained_from_thin_air(self):
        with self.assertRaises(BudgetError) as caught:
            self.plan([])
        self.assertEqual(caught.exception.code, 'no_evidence')
        with self.assertRaises(BudgetError):
            self.plan('not a list')

    def test_too_many_references_and_too_many_bytes_are_refused_whole(self):
        with self.assertRaises(BudgetError) as too_many:
            self.plan([reference() for _ in range(3)], max_evidence_items=2)
        self.assertEqual(too_many.exception.code, 'too_many_references')
        heavy = [reference(parameters={'blob': 'x' * 3000})]
        with self.assertRaises(BudgetError) as big:
            self.plan(heavy, max_evidence_bytes=512)
        self.assertEqual(big.exception.code, 'evidence_bytes')
        self.assertIn('refused whole', str(big.exception))
        with self.assertRaises(BudgetError) as body:
            self.plan(heavy, max_evidence_bytes=4_096, max_prompt_bytes=4_096, prompt_bytes=2_048)
        self.assertEqual(body.exception.code, 'prompt_bytes')
        # A refusal admits nothing: there is no partial plan to fall through to.
        self.assertNotIsInstance(big.exception, dict)

    def test_expired_evidence_is_reported_as_expired_and_says_nothing_was_requeried(self):
        for item, expected in ((reference(expires_at='2026-09-08T10:29:00+00:00'), 'expired_evidence'),
                              (reference(status='expired'), 'expired_evidence'),
                              (reference(status='unavailable'), 'unavailable_evidence')):
            with self.subTest(expected=expected):
                with self.assertRaises(BudgetError) as caught:
                    self.plan([item])
                self.assertEqual(caught.exception.code, expected)
        with self.assertRaises(BudgetError) as caught:
            self.plan([reference(expires_at='2026-09-08T10:29:00+00:00')])
        self.assertIn('reported as expired', str(caught.exception))
        self.assertIn('re-queries nothing', str(caught.exception))

    def test_an_available_status_does_not_outvote_a_stale_expiry(self):
        """The store said `available` a moment ago; the clock says otherwise, and the clock wins."""
        with self.assertRaises(BudgetError) as caught:
            self.plan([reference(status='available', expires_at='2026-09-08T10:10:00+00:00')])
        self.assertEqual(caught.exception.code, 'expired_evidence')

    def test_reference_shape_is_the_canonical_one_and_nothing_else(self):
        broken = [
            {key: value for key, value in reference().items() if key != 'query_type'},
            reference(extra='x'),
            reference(schema_version=2),
            reference(window={'start': WINDOW['start']}),
            reference(window={'start': WINDOW['end'], 'end': WINDOW['start']}),
            reference(expires_at='yesterday'),
            reference(expires_at=WINDOW['end']),
            reference(status='maybe'),
            'not an object',
        ]
        for item in broken:
            with self.subTest(item=repr(item)[:48]):
                with self.assertRaises(BudgetError) as caught:
                    self.plan([item])
                self.assertEqual(caught.exception.code, 'invalid_reference')

    def test_the_sample_a_store_returned_may_travel_with_the_reference(self):
        result = self.plan([reference(status='available',
                                     sample={'sample_id': 's-1', 'observed_at': WINDOW['start'],
                                             'ok': True, 'value': 91.4})])
        self.assertEqual(result['status'], 'ok')

    def test_payload_bytes_uses_the_canonical_form(self):
        self.assertEqual(budget.payload_bytes({'b': 1, 'a': 2}),
                         len(budget.canonical({'a': 2, 'b': 1}).encode()))


if __name__ == '__main__':
    unittest.main()

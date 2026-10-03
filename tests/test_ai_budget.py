"""Tests for the evidence budget: whole-bundle refusal, expired evidence reported as expired, and
the optional reasoning spelling that has no default.
"""
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

    def test_explicit_completion_boundaries_preserve_defaults(self):
        self.assertEqual(budget.DEFAULTS['max_completion_tokens'], 512)
        self.assertEqual(budget.CEILINGS['max_completion_tokens'], (1, 16_384))
        for value in (1, 512, 8_192, 16_384):
            with self.subTest(value=value):
                validated = budget.validate({'max_completion_tokens': value})
                self.assertEqual(validated['max_completion_tokens'], value,
                                 'an accepted figure is returned unchanged, never clamped')
                self.assertEqual({key: limit for key, limit in validated.items()
                                  if key != 'max_completion_tokens'},
                                 {key: limit for key, limit in budget.DEFAULTS.items()
                                  if key != 'max_completion_tokens'},
                                 'a longer allowance moves no other limit')
        for value in (0, -1, 16_385, 100_000, True, False, '16384', 16384.0, None):
            with self.subTest(value=repr(value)):
                with self.assertRaises(BudgetError) as caught:
                    budget.validate({'max_completion_tokens': value})
                self.assertIn('max_completion_tokens', str(caught.exception))
                self.assertIn('1..16384', str(caught.exception), 'the refusal names the bound it applied')

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


class ReasoningEffortFileTests(unittest.TestCase):
    """The one budget key that is not a limit: an optional request spelling, and nothing else.

    The three things these tests hold apart are the states an operator can actually be in. Not
    naming the key is the legacy configuration and must stay byte-for-byte the legacy document.
    Naming `xhigh` is a measured request to ask for it, so the value must survive unchanged. Naming
    anything else is a typo, and a typo has to die here rather than arrive at the endpoint as a
    second, unmeasured question.
    """

    LEGACY = {'max_evidence_items': 20, 'max_evidence_bytes': 16_384,
              'max_prompt_bytes': 24_576, 'max_completion_tokens': 512}

    def test_an_absent_key_leaves_the_validated_document_exactly_as_it_was(self):
        self.assertNotIn('reasoning_effort', budget.DEFAULTS, 'no effort is shipped as a default')
        self.assertEqual(budget.validate({}), self.LEGACY)
        self.assertEqual(budget.validate(self.LEGACY), self.LEGACY)
        self.assertEqual(budget.load(None), self.LEGACY)
        self.assertEqual(budget.validate({'max_completion_tokens': 8_192}),
                         dict(self.LEGACY, max_completion_tokens=8_192))

    def test_every_accepted_spelling_is_returned_unchanged(self):
        self.assertEqual(budget.REASONING_EFFORTS, ('low', 'medium', 'high', 'xhigh'))
        for effort in budget.REASONING_EFFORTS:
            with self.subTest(effort=effort):
                validated = budget.validate({'reasoning_effort': effort})
                self.assertEqual(validated['reasoning_effort'], effort)
                # Adding it is the only change: no limit moves, and nothing else is inferred.
                self.assertEqual({key: value for key, value in validated.items()
                                  if key != 'reasoning_effort'}, self.LEGACY)

    def test_anything_else_refuses_the_document(self):
        for value in (None, True, False, 1, 8192, 90.0, ['xhigh'], [], {'spelling': 'xhigh'}, {},
                      'XHIGH', 'XHigh', 'xhigh ', ' xhigh', 'x-high', 'highest', 'none', 'null', ''):
            with self.subTest(value=repr(value)):
                with self.assertRaises(BudgetError) as caught:
                    budget.validate({'reasoning_effort': value})
                self.assertEqual(caught.exception.code, 'budget_exceeded')
                self.assertIn('reasoning_effort', str(caught.exception))
        # A rejected value is never quoted back: it is arbitrary JSON on its way into a log line.
        with self.assertRaises(BudgetError) as caught:
            budget.validate({'reasoning_effort': 'untrusted-operator-prose-do-not-echo'})
        self.assertNotIn('untrusted-operator-prose', str(caught.exception))

    def test_a_budget_file_is_read_with_the_effort_and_refused_without_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'measured.json').write_text(json.dumps({'max_completion_tokens': 8_192,
                                                           'request_timeout_seconds': 90,
                                                           'reasoning_effort': 'xhigh'}),
                                                encoding='utf-8')
            loaded = budget.load(root / 'measured.json')
            self.assertEqual(loaded['reasoning_effort'], 'xhigh')
            self.assertEqual(loaded['max_completion_tokens'], 8_192)
            (root / 'typo.json').write_text('{"reasoning_effort": "extreme"}', encoding='utf-8')
            with self.assertRaises(BudgetError):
                budget.load(root / 'typo.json')


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

    def test_larger_completion_allowance_preserves_evidence_bounds(self):
        roomier = self.plan([reference()], max_completion_tokens=16_384)
        self.assertEqual(roomier['max_completion_tokens'], 16_384,
                         'the figure the operator named is the figure the client is told to send')
        self.assertEqual({key: value for key, value in roomier.items() if key != 'max_completion_tokens'},
                         {key: value for key, value in self.plan([reference()]).items()
                          if key != 'max_completion_tokens'},
                         'the same bundle fits, whatever the completion ceiling allows')
        with self.assertRaises(BudgetError) as caught:
            self.plan([reference()], max_completion_tokens=16_384, max_evidence_bytes=1_024,
                      max_prompt_bytes=1_024, prompt_bytes=600)
        self.assertEqual(caught.exception.code, 'prompt_bytes',
                         'the byte ceiling still refuses the body this call would have written')

    def test_payload_bytes_uses_the_canonical_form(self):
        self.assertEqual(budget.payload_bytes({'b': 1, 'a': 2}),
                         len(budget.canonical({'a': 2, 'b': 1}).encode()))

    def test_an_effort_changes_the_spelling_asked_not_the_bundle_admitted(self):
        """`plan` answers "does this fit", and a reasoning mode does not make evidence smaller."""
        without = self.plan([reference()])
        with self.assertRaises(BudgetError) as caught:
            self.plan([reference(), reference()], max_evidence_items=1, reasoning_effort='xhigh')
        self.assertEqual(caught.exception.code, 'too_many_references',
                         'asking harder does not buy a bigger bundle')
        for effort in budget.REASONING_EFFORTS:
            with self.subTest(effort=effort):
                self.assertEqual(self.plan([reference()], reasoning_effort=effort), without)


if __name__ == '__main__':
    unittest.main()

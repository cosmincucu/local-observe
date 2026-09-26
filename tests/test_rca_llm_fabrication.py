"""The lying-model regression: the test that justifies the whole component, per rca task 4.

Everything else in `platform/rca.py` is plumbing until this file is true. The model is handed a real
bundle and lies about it — a metric name that is nowhere in the bundle, a number that is nowhere in it,
a resource uuid that is nowhere in it — and the assertions are the two halves of the promise:

* the **ranked cause set is byte-identical** to the one the rule floor produced on its own, in the
  same order, with the same citations; and
* the **prose is what changes**: the sentences that cited nothing are discarded, by name, before an
  operator reads them.

`test_a_lying_model_changes_the_prose_and_never_the_ranked_cause_set` is the one to open in a review.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp
from local_observe.platform import rca
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-09T12:00:00Z')
SERVICE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
HOST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
WINDOW = {'start': '2026-09-09T11:58:00Z', 'end': '2026-09-09T11:59:00Z'}
# Inventions, chosen to be absent rather than merely unlikely: a dotted metric name, a number with a
# fraction, and a uuid no producer in this file ever wrote. Each one is asserted absent from the bundle
# text below, so the test cannot pass by accident of a fixture that happened not to contain them.
INVENTED_METRIC = 'nvme_disk_used_bytes'
INVENTED_NUMBER = '97.4'
INVENTED_UUID = '11111111-2222-4333-8444-555555555555'


class _Model:
    """A generator seam that records what it was asked and answers with whatever it is told to say."""

    def __init__(self, reply=None, error: Exception | None = None) -> None:
        self.reply = reply
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, **kwargs) -> dict:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.reply if self.reply is not None else {}


class LyingModelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.index = self.root / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture',
                    now=NOW)
        producer = Actor('fabrication-detector', 'producer')
        self.store.put_evidence({'sample_id': 'live-sample', 'observed_at': '2026-09-09T11:59:00Z',
                                 'ok': True, 'value': 4}, producer, now=NOW)
        self.store.intake(event('fabrication-detector', SERVICE, 'api.down', 'availability', 'firing',
                                WINDOW, {'sample_id': 'live-sample'}, query_type='gatus-result'),
                          producer, now=NOW)
        self.store.intake(event('analyzer', HOST, 'anomaly.cpu', 'anomaly', 'firing',
                                {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:55:00Z'},
                                {'sample_id': 'live-sample'}, query_type='metric-threshold'),
                          Actor('analyzer', 'producer'), now=NOW)
        self.incident = next(row for row in self.store.records('incidents')
                             if row['resource_id'] == SERVICE)

    def bundle(self) -> dict:
        return rca.bundle(self.store, self.incident, self.index, now=NOW)

    def lying_reply(self) -> str:
        return (f'The finding {INVENTED_METRIC} reached {INVENTED_NUMBER} percent on the affected node. '
                f'Resource {INVENTED_UUID} is the origin of the fault and should be treated as the '
                f'cause. The anomaly verdict anomaly.cpu is consistent with the availability finding '
                f'api.down.')

    def test_a_lying_model_changes_the_prose_and_never_the_ranked_cause_set(self) -> None:
        body = self.bundle()
        floor = rca.candidates(body)
        self.assertTrue(floor, 'the fixture must produce a real rule floor, or this proves nothing')
        for invention in (INVENTED_METRIC, INVENTED_NUMBER, INVENTED_UUID):
            self.assertNotIn(invention, body['text'], f'{invention} leaked into the bundle itself')

        model = _Model({'display_text': self.lying_reply()})
        outcome = rca.explain(body, generate=model)

        # Half one: the cause set, identical to the floor's, in the floor's order, citations included.
        self.assertEqual(outcome['candidates'], [item.as_dict() for item in floor])
        self.assertEqual([item['rule'] for item in outcome['candidates']],
                         [item.rule for item in floor])
        self.assertEqual(outcome['citations'], sorted({citation for item in floor
                                                       for citation in item.citations}))
        # Half two: the prose, with every invented sentence gone and named.
        self.assertTrue(outcome['llm_used'])
        self.assertIsNone(outcome['degraded_reason'])
        explanation = outcome['explanation']
        self.assertEqual(explanation['source'], 'rules+model')
        self.assertNotIn(INVENTED_METRIC, explanation['text'])
        self.assertNotIn(INVENTED_NUMBER, explanation['text'])
        self.assertNotIn(INVENTED_UUID, explanation['text'])
        self.assertIn('anomaly.cpu', explanation['text'])
        self.assertIn('api.down', explanation['text'])
        discarded = [entry['claims'] for entry in explanation['discarded']]
        self.assertEqual(len(explanation['discarded']), 2, discarded)
        self.assertIn(INVENTED_METRIC, discarded[0] + discarded[1])
        self.assertIn(INVENTED_UUID, discarded[0] + discarded[1])
        for entry in explanation['discarded']:
            self.assertEqual(entry['code'], rca.FABRICATION)
        self.assertEqual(len(model.calls), 1)

    def test_a_model_may_not_reorder_the_cause_set_even_when_it_is_telling_the_truth(self) -> None:
        """Rerank is the other permitted operation, and this build applies none: stated, not implied."""
        outcome = rca.explain(self.bundle(), generate=_Model({'display_text': 'One cause: anomaly.cpu.'}))
        rerank = outcome['explanation']['rerank']
        self.assertTrue(rerank['requested'])
        self.assertFalse(rerank['applied'])
        self.assertIn('json_mode', rerank['reason'])
        self.assertIn('capability', rerank['reason'])

    def test_a_model_that_raises_leaves_the_floor_and_never_raises_out_of_here(self) -> None:
        """`analyze`/`explain` never raise, whatever the optional half does (v0.1's `LlmUnavailable`)."""
        floor = rca.candidates(self.bundle())
        model = _Model(error=RuntimeError('the endpoint refused'))
        outcome = rca.explain(self.bundle(), generate=model)
        self.assertFalse(outcome['llm_used'])
        self.assertEqual(outcome['degraded_reason'], 'model_unavailable')
        self.assertEqual(outcome['candidates'], [item.as_dict() for item in floor])
        self.assertEqual(outcome['confidence'], 'supported')
        # The floor's own prose is still an answer an operator can read.
        self.assertIn('anomaly.cpu', outcome['explanation']['text'])

    def test_a_model_that_answers_with_no_text_is_malformed_and_not_an_empty_explanation(self) -> None:
        for reply in ({}, {'content': '   '}, {'content': 12}, [], 'plain text'):
            with self.subTest(reply=reply):
                outcome = rca.explain(self.bundle(), generate=_Model(reply))
                self.assertFalse(outcome['llm_used'])
                self.assertEqual(outcome['degraded_reason'], 'model_malformed')
                self.assertTrue(outcome['candidates'])

    def test_the_remote_label_travels_with_the_text_it_labels(self) -> None:
        """remote inference policy: `display_text` is read before `content`, or the indication quietly disappears."""
        outcome = rca.explain(self.bundle(), generate=_Model(
            {'content': 'anomaly.cpu is the leading cause.',
             'display_text': '[generated off-LAN]\nanomaly.cpu is the leading cause.'}))
        self.assertTrue(outcome['explanation']['text'].startswith('[generated off-LAN]'))

    def test_the_instruction_is_this_modules_and_not_the_callers(self) -> None:
        """The only variable part of a prompt is the bundle and the floor's own answer."""
        model = _Model({'display_text': 'anomaly.cpu is the cause.'})
        rca.explain(self.bundle(), generate=model)
        instruction = model.calls[0]['instruction']
        self.assertTrue(instruction.startswith(rca.INSTRUCTION))
        self.assertIn('Rule output:', instruction)
        self.assertNotIn('ignore', instruction.lower())

    def test_an_unclassified_bundle_is_refused_before_any_prompt_is_built(self) -> None:
        for data_class in ('', 'secret', 'PUBLIC', None):
            with self.subTest(data_class=data_class):
                with self.assertRaises(rca.RcaError):
                    rca.explain(self.bundle(), generate=_Model({}), data_class=str(data_class))

    def test_no_model_prose_is_written_to_the_durable_record(self) -> None:
        """The record is the redacted minimum context: verdict words and citations, never the sentences.

        Free prose from a model that the platform re-publishes later reads as a fact, and it is also
        the one channel by which a discarded fabrication could come back after this file threw it away.
        """
        body = self.bundle()
        outcome = rca.explain(body, generate=_Model({'display_text': 'anomaly.cpu is the cause.'}))
        detail = rca.explanation_record('rca-test', body, outcome)
        self.assertEqual(set(detail), set(rca.EXPLANATION_KEYS))
        self.assertNotIn('is the cause', json.dumps(detail))
        self.assertNotIn('explanation', detail)
        rca.record(self.store, body['incident_id'], detail, Actor('rca-test', 'producer'), now=NOW)
        stored = rca.read_latest(self.store, body['incident_id'])
        self.assertEqual(stored, detail)
        self.assertNotIn('is the cause', json.dumps(stored))


class PostValidationTests(unittest.TestCase):
    """The guard on its own, including the limitation it has and the report names."""

    def test_only_the_sentences_the_bundle_can_back_survive(self) -> None:
        allowed = 'incident with anomaly.cpu and api.down, value 4, at 2026-09-09T11:59:00Z'
        reply = ('anomaly.cpu fired beside api.down. disk temperature hit 71 degrees. '
                 'The pool nvme_pool_used exhausted at 4.')
        checked = rca.post_validate(reply, allowed)
        self.assertEqual(checked['text'], 'anomaly.cpu fired beside api.down.')
        self.assertEqual(checked['discarded_count'], 2)
        self.assertEqual([entry['code'] for entry in checked['discarded']],
                         [rca.FABRICATION, rca.FABRICATION])
        self.assertIn('71', checked['discarded'][0]['claims'])
        self.assertIn('nvme_pool_used', checked['discarded'][1]['claims'])

    def test_a_number_is_only_checkable_if_it_is_not_already_a_digit_in_the_bundle(self) -> None:
        """The honest weakness of containment, pinned as a test so nobody rediscover it as a guarantee.

        `unknown_claims` is a substring check, so `4` is "found" inside a timestamp or a digest. The
        guard catches invented names, uuids and non-trivial numbers; it is not arithmetic, and a claim
        of arithmetic would be the sort of quality statement `corpus eval`'s corpus gate exists to refuse.
        """
        allowed = 'value 4 at 2026-09-09T11:59:00Z'
        self.assertEqual(rca.unknown_claims('the count was 4.', allowed), [])
        self.assertEqual(rca.unknown_claims('the count was 41.', allowed), ['41'])

    def test_a_uuid_is_always_a_claim(self) -> None:
        self.assertEqual(rca.unknown_claims('see bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',
                                            'nothing here'),
                         ['bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'])
        self.assertEqual(rca.unknown_claims('see bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2',
                                            'mentions bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'), [])

    def test_hyphenated_prose_is_english_and_not_a_resource_name(self) -> None:
        """Otherwise every honest sentence about the `rule-floor` costs itself its own sentence."""
        self.assertEqual(rca.unknown_claims('the rule-floor ranked this first.', 'nothing'), [])


if __name__ == '__main__':
    unittest.main()

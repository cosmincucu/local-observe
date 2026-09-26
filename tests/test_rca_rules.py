"""The rule floor: four heuristics, each pinned by the test that proves it runs and why it is quiet.

Task 4's third named test lives here — `test_an_empty_rule_floor_sends_nothing_to_the_model` — beside
the four rules it exists to protect. The floor is the component's whole claim ("Rule-based RCA",
`docs/COMPONENTS.md`), so every rule is pinned in both directions: the case that makes it speak and the
case that must keep it silent. A rule that only has a positive test is a rule that can grow into a
pager.
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
SERVICE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'      # demo-api
HOST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'         # probe-1, the host demo-api declares runs-on
WINDOW = {'start': '2026-09-09T11:58:00Z', 'end': '2026-09-09T11:59:00Z'}


class _CountingModel:
    """A stand-in generator that records every call, so "no model was asked" is a count and a word."""

    def __init__(self, reply: str = 'The rule fired as recorded.') -> None:
        self.reply = reply
        self.calls: list[dict] = []

    def __call__(self, **kwargs) -> dict:
        self.calls.append(kwargs)
        return {'display_text': self.reply}


class RuleFloorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.index = self.root / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture',
                    now=NOW)
        self.put = 0

    def file(self, payload) -> Path:
        self.put += 1
        path = self.root / f'config-{self.put}.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def report(self, source: str, resource: str | None, rule: str, kind: str, status: str,
               window: dict[str, str], *, sample: str | None = None,
               observed: str | None = None) -> None:
        """File one canonical event through intake, the only door that opens an incident."""
        actor = Actor(source, 'producer')
        if sample is not None:
            self.store.put_evidence({'sample_id': sample, 'observed_at': window['end'], 'ok': True,
                                     'value': 4}, actor, now=NOW)
        body = event(source, resource, rule, kind, status, window,
                     {'sample_id': sample} if sample else {'rule_id': rule},
                     query_type='metric-threshold', observed_at=observed)
        self.store.intake(body, actor, now=NOW)

    def incident_for(self, resource: str | None, rule: str) -> dict:
        """The open incident whose newest event is the rule this test filed.

        Matched through the last event's payload and not by resource alone: several of these tests
        open two conditions on one resource, and `records('incidents')` is newest-first, so a lookup
        by resource would silently pick the wrong incident and the assertion below would be about a
        different one.
        """
        for row in self.store.records('incidents'):
            if row['resource_id'] != resource or row['status'] != 'open':
                continue
            linked = [event for event in self.store.records('events', rca.RECORDS_LIMIT)
                      if event['id'] == row['last_event_id']]
            if linked and json.loads(linked[0]['payload'])['rule_id'] == rule:
                return row
        raise AssertionError(f'no open incident on {resource} / {rule}')

    def bundle(self, resource: str | None = SERVICE, rule: str = 'api.down', **kwargs) -> dict:
        return rca.bundle(self.store, self.incident_for(resource, rule), self.index, now=NOW, **kwargs)

    # -- the discipline itself ------------------------------------------------------------------

    def test_the_floor_is_four_rules_and_every_one_states_why_it_exists(self) -> None:
        """The `why:` line is the point of the tuple, so it is asserted and not admired in a comment.

        Task "Verification you must report" asks for a count and for the proof each rule carries its
        reason: a rule that cannot say why it is tuned the way it is gets deleted, not defended.
        """
        self.assertEqual(len(rca.RULES), 4)
        self.assertEqual([rule.id for rule in rca.RULES],
                         ['change-before-finding', 'baseline-break', 'earliest-upstream-finding',
                          'source-coverage-blind'])
        for rule in rca.RULES:
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.why.startswith('why:'), rule.why[:40])
                self.assertGreaterEqual(len(rule.why), 120, 'a one-line why is a label, not a reason')
        with self.assertRaises(rca.RcaError):
            rca.Rule('unjustified', '', lambda body: [])

    def test_candidates_are_ranked_in_rule_order_and_capped(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-base')
        self.report('drifter', SERVICE, 'config.drift', 'drift', 'firing',
                    {'start': '2026-09-09T11:30:00Z', 'end': '2026-09-09T11:40:00Z'})
        self.report('analyzer', HOST, 'anomaly.cpu', 'anomaly', 'firing',
                    {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:55:00Z'})
        rules = [item.rule for item in rca.candidates(self.bundle())]
        self.assertEqual(rules, ['change-before-finding', 'baseline-break'])
        self.assertEqual(rules, [rule.id for rule in rca.RULES if rule.id in rules],
                         'the emitted order must be rule order, always')

    def test_maximum_valid_labels_fit_every_candidate_before_the_round_records_them(self) -> None:
        document = read_document(ROOT / 'examples/inventory/declared.yaml')
        name = 'n' * 256
        document['resources'][0]['name'] = name
        self.index = self.root / 'long-names.db'
        index.build(document, self.index, 'fixture', now=NOW)
        rules = {kind: kind + '.' + 'x' * (127 - len(kind))
                 for kind in ('coverage', 'drift', 'anomaly', 'availability')}
        for kind, rule in rules.items():
            self.assertEqual(len(rule), 128)
            self.report('detect', SERVICE if kind == 'coverage' else HOST,
                        rule, kind, 'firing', WINDOW)
        self.report('detect', None, 'unrelated.down', 'availability', 'firing', WINDOW)
        body = self.bundle(SERVICE, rules['coverage'])
        found = rca.candidates(body)
        self.assertEqual([one.rule for one in found], [rule.id for rule in rca.RULES])
        self.assertTrue(any(item['name'] == name for item in body['channels']['topology']['items']))
        for candidate in found:
            self.assertEqual(len(candidate.cause), rca.MAX_CAUSE_CHARS)
            self.assertTrue(candidate.cause.endswith('\u2026'))
            for citation in candidate.citations:
                channel, _ = citation.split(':')
                self.assertTrue(any(item['id'] == citation
                                    for item in body['channels'][channel]['items']))
        for channel, kind in [('members', 'coverage'), ('changes', 'drift'),
                              ('baselines', 'anomaly'), ('neighbours', 'availability')]:
            self.assertEqual(body['channels'][channel]['items'][0]['rule_id'], rules[kind])
        # Public execution and durable readback: another incident still receives an explanation.
        result = rca.tick(self.store, self.index, config={'max_incidents': 5}, source='rca-long', now=NOW)
        self.assertEqual(result['analyzed'], 5)
        self.assertEqual(result['written'], 5)
        for row in self.store.records('incidents'):
            detail = rca.read_latest(self.store, row['id'])
            self.assertIsNotNone(detail)
            self.assertTrue(all(len(cause) <= rca.MAX_CAUSE_CHARS for cause in detail['causes']))

    def test_candidate_validation_still_refuses_oversized_external_prose(self) -> None:
        with self.assertRaises(rca.RcaError):
            rca.Candidate('baseline-break', 'x' * (rca.MAX_CAUSE_CHARS + 1),
                          'supported', ('baselines:0',), HOST)

    # -- rule 1: the change that came first ------------------------------------------------------

    def test_change_before_finding_names_the_drift_and_cites_it(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-one')
        self.report('drifter', SERVICE, 'config.drift', 'drift', 'firing',
                    {'start': '2026-09-09T11:20:00Z', 'end': '2026-09-09T11:30:00Z'})
        found = [item for item in rca.candidates(self.bundle()) if item.rule == 'change-before-finding']
        self.assertEqual(len(found), 1)
        self.assertIn('config.drift', found[0].cause)
        self.assertEqual(found[0].confidence, 'indicated', 'co-occurrence is not causation')
        self.assertIn('changes:0', found[0].citations)

    def test_a_change_reported_after_the_first_finding_is_not_a_cause(self) -> None:
        """The one word that separates this rule from a symptom pager: *before*."""
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-two')
        self.report('drifter', SERVICE, 'config.drift', 'drift', 'firing',
                    {'start': '2026-09-09T11:59:30Z', 'end': '2026-09-09T11:59:40Z'})
        rules = [item.rule for item in rca.candidates(self.bundle())]
        self.assertNotIn('change-before-finding', rules)

    def test_a_signal_older_than_the_lookback_is_not_in_the_bundle_at_all(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-three')
        self.report('drifter', SERVICE, 'config.drift', 'drift', 'firing',
                    {'start': '2026-09-09T05:00:00Z', 'end': '2026-09-09T06:00:00Z'})
        self.assertEqual(len(self.bundle(lookback_seconds=600)['channels']['changes']['items']), 0)
        self.assertEqual(len(self.bundle(lookback_seconds=86_400)['channels']['changes']['items']), 1)

    # -- rule 2: the band the series learned -----------------------------------------------------

    def test_baseline_break_is_the_only_candidate_this_product_may_call_supported(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-four')
        self.report('analyzer', HOST, 'anomaly.cpu', 'anomaly', 'firing',
                    {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:55:00Z'})
        found = [item for item in rca.candidates(self.bundle()) if item.rule == 'baseline-break']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].confidence, 'supported')
        self.assertIn('anomaly.cpu', found[0].cause)
        # event kinds's shape, read as it is and not as the brief hoped: the event carries the evaluation
        # window, and no claim is made about the training span.
        channel = self.bundle()['channels']['baselines']
        self.assertIn('evaluation span', channel['note'])

    def test_a_resolved_anomaly_is_not_a_candidate(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-five')
        self.report('analyzer', HOST, 'anomaly.cpu', 'anomaly', 'resolved',
                    {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:55:00Z'})
        self.assertNotIn('baseline-break', [item.rule for item in rca.candidates(self.bundle())])

    # -- rule 3: the declared graph, one hop ----------------------------------------------------

    def test_earliest_upstream_member_needs_the_declared_graph_to_say_anything(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-five')
        self.report('detect', HOST, 'host.down', 'availability', 'firing',
                    {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:52:00Z'})
        with_graph = rca.bundle(self.store, self.incident_for(SERVICE, 'api.down'), self.index,
                                now=NOW)
        found = [item for item in rca.candidates(with_graph)
                 if item.rule == 'earliest-upstream-finding']
        self.assertEqual(len(found), 1, 'probe-1 is declared above demo-api and fired first')
        self.assertIn('probe-1', found[0].cause)
        self.assertEqual(found[0].confidence, 'indicated')
        self.assertEqual(found[0].resource_id, HOST)
        without = rca.bundle(self.store, self.incident_for(SERVICE, 'api.down'), None, now=NOW)
        self.assertNotIn('earliest-upstream-finding', [item.rule for item in rca.candidates(without)],
                         'no index, no declared edge, no claim about position')

    def test_a_resource_is_never_its_own_upstream_cause(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-six')
        self.report('detect', SERVICE, 'api.slow', 'threshold', 'firing',
                    {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:52:00Z'})
        rules = [item.rule for item in rca.candidates(self.bundle())]
        self.assertNotIn('earliest-upstream-finding', rules)

    def test_later_upstream_finding_stays_context_without_becoming_a_cause(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW)
        self.report('detect', HOST, 'host.down', 'availability', 'firing', WINDOW,
                    observed='2026-09-09T11:59:50Z')
        body = self.bundle()
        self.assertEqual(body['channels']['neighbours']['items'][0]['direction'], 'upstream')
        self.assertNotIn('earliest-upstream-finding', [item.rule for item in rca.candidates(body)])

    def test_downstream_only_finding_stays_context_without_becoming_a_cause(self) -> None:
        self.report('detect', HOST, 'host.down', 'availability', 'firing', WINDOW)
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW,
                    observed='2026-09-09T11:58:50Z')
        body = self.bundle(HOST, 'host.down')
        self.assertEqual(body['channels']['neighbours']['items'][0]['direction'], 'downstream')
        self.assertNotIn('earliest-upstream-finding', [item.rule for item in rca.candidates(body)])

    def test_equal_time_upstream_is_indicated_and_identifies_the_neighbour(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW)
        self.report('detect', HOST, 'host.down', 'availability', 'firing', WINDOW)
        found = rca.candidates(self.bundle())
        self.assertEqual([(one.rule, one.confidence, one.resource_id) for one in found],
                         [('earliest-upstream-finding', 'indicated', HOST)])

    def test_missing_anchor_or_undated_neighbour_cannot_support_an_upstream_cause(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW)
        self.report('detect', HOST, 'host.down', 'availability', 'firing', WINDOW)
        body = self.bundle()
        body['span'] = {'first': '', 'last': ''}
        self.assertTrue(body['channels']['neighbours']['items'])
        self.assertEqual(rca.candidates(body), [])
        body = self.bundle()
        body['channels']['neighbours']['items'][0]['observed_at'] = ''
        self.assertEqual(rca.candidates(body), [])

    # -- rule 4: the blindness is the finding ---------------------------------------------------

    def test_a_coverage_member_makes_the_blindness_the_candidate(self) -> None:
        self.report('detect', SERVICE, 'api.down.coverage', 'coverage', 'firing', WINDOW,
                    sample='s-seven')
        found = [item for item in rca.candidates(self.incident_bundle('api.down.coverage'))
                 if item.rule == 'source-coverage-blind']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].confidence, 'supported')
        self.assertIn('cannot be told from outage', found[0].cause)

    def incident_bundle(self, rule: str) -> dict:
        return rca.bundle(self.store, self.incident_for(SERVICE, rule), self.index, now=NOW)

    def test_an_availability_member_is_not_reported_as_blindness(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-eight')
        self.assertNotIn('source-coverage-blind', [item.rule for item in rca.candidates(self.bundle())])

    # -- the floor with nothing to say ----------------------------------------------------------

    def test_no_rule_matched_and_the_answer_says_so_instead_of_guessing(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-nine')
        body = self.bundle()
        self.assertEqual(rca.candidates(body), [])
        self.assertEqual(rca.confidence_of([]), 'unknown')
        self.assertIn('No candidate cause', rca.floor_text(body, []))
        self.assertIn('none was asked', rca.floor_text(body, []))

    def test_an_empty_rule_floor_sends_nothing_to_the_model(self) -> None:
        """Task 4's third named test: the floor's emptiness is what keeps a model from inventing a cause.

        The model is configured, willing, and handed a reply — and is still never called, because there
        is no rule output to rerank or explain. The mutation that proves this test bites is deleting the
        `if not found: return` guard in `explain`; the report names it.
        """
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-ten')
        model = _CountingModel(reply='The cause was the database pool exhaustion at 97.4 percent.')
        outcome = rca.explain(self.bundle(), generate=model)
        self.assertEqual(model.calls, [], 'a model was asked with no rule output to explain')
        self.assertFalse(outcome['llm_used'])
        self.assertEqual(outcome['degraded_reason'], 'no_rule_floor')
        self.assertEqual(outcome['confidence'], 'unknown')
        self.assertEqual(outcome['candidates'], [])
        self.assertIn('none was asked', outcome['explanation']['text'])

    def test_the_budget_exhausts_before_the_model_is_asked_again(self) -> None:
        self.report('detect', SERVICE, 'api.down', 'availability', 'firing', WINDOW, sample='s-eleven')
        self.report('analyzer', HOST, 'anomaly.cpu', 'anomaly', 'firing',
                    {'start': '2026-09-09T11:50:00Z', 'end': '2026-09-09T11:55:00Z'})
        model = _CountingModel()
        outcome = rca.explain(self.bundle(), generate=model, max_model_calls=0)
        self.assertEqual(model.calls, [])
        self.assertEqual(outcome['degraded_reason'], 'budget_exhausted')
        self.assertEqual([item['rule'] for item in outcome['candidates']], ['baseline-break'],
                         'the floor answered, and its answer survives the model being unavailable')


class ConfigurationTests(unittest.TestCase):
    """The round's own document: bounded, closed, and unable to ask for the half that is not built."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, payload) -> Path:
        path = self.root / 'rca.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def test_defaults_apply_and_every_bound_is_named(self) -> None:
        config = rca.load_config(self.file({}))
        self.assertEqual(set(config), set(rca.CONFIG_KEYS))
        self.assertEqual(config['max_incidents'], rca.DEFAULTS['max_incidents'])
        self.assertIsNone(config['executor'])

    def test_every_out_of_range_or_unknown_field_is_a_refusal(self) -> None:
        for payload in ({'max_incidents': 0}, {'max_incidents': 26}, {'max_model_calls': -1},
                        {'lookback_seconds': 59}, {'max_incidents': True}, {'nope': 1},
                        {'data_class': 'secret'}, {'executor': {'enabled': True}}):
            with self.subTest(payload=payload):
                with self.assertRaises(rca.RcaError):
                    rca.load_config(self.file(payload))

    def test_an_enabled_executor_refuses_and_names_the_document_that_holds_the_shapes(self) -> None:
        """holmesgpt's open half, enforced by code: the manifest may not promise an executor no one built."""
        with self.assertRaises(rca.RcaError) as caught:
            rca.load_config(self.file({'executor': {'enabled': True}}))
        self.assertIn('components/control/rca/CONTRACT.md', str(caught.exception))
        rca.load_config(self.file({'executor': {'enabled': False, 'note': 'not built'}}))

    def test_a_document_that_is_not_json_or_is_too_big_refuses_without_echoing(self) -> None:
        broken = self.root / 'broken.json'
        broken.write_text('{not json', encoding='utf-8')
        with self.assertRaises(rca.RcaError):
            rca.load_config(broken)
        big = self.root / 'big.json'
        big.write_bytes(b'{"max_incidents": 1}' + b' ' * (rca.MAX_CONFIG_BYTES + 1))
        with self.assertRaises(rca.RcaError):
            rca.load_config(big)


if __name__ == '__main__':
    unittest.main()

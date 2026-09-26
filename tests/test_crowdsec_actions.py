"""The CrowdSec action surface (crowdsec task 4): protected destinations, the refusal, and who may approve.

§5's **"Approved action"** scenario, borrowed because crowdsec's write half is an action proposal and nothing
else: there is no code path in this repository that creates or deletes a CrowdSec decision, so the whole
enforcement promise of `auto-block authority` ("allowlist those three; everything else needs approval") reduces to one
question with a server-side answer — *can a proposal to block a protected address get through?*

Everything below runs the real gate: `Store.propose_action` over `policy.action_policy` with the
definitions from `components/control/crowdsec/actions.example.json`, the same call `POST /v1/actions`
makes. No prompt, no second approval path, no invented refusal word.

One correction the brief needs, because it is stated as a test name here rather than as a paragraph:
"the actor who proposed it cannot be the actor who approved it" is **not** this repository's invariant.
`Store.decide` requires the `human` role and does not compare identities — a human who proposed may
approve (`tests/test_action_invariants.py::test_a_human_who_proposed_may_approve_and_both_sides_are_durable`),
and the separation that *is* enforced is by role: no agent or proposer principal can approve anything.
`SeparationTests` asserts that shape, because asserting the brief's sentence would pin a rule `state.py`
does not implement.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, utc_text
from local_observe.platform import crowdsec, intake, refusals
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 9, 9, 12, 0, 0, tzinfo=dt.timezone.utc)
COMPONENT = ROOT / 'components' / 'control' / 'crowdsec'
SHIPPED = json.loads((COMPONENT / 'actions.example.json').read_text(encoding='utf-8'))
HOST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
PRODUCER = Actor('crowdsec', 'producer')
AGENT = Actor('agent-1', 'proposer')
HUMAN = Actor('operator', 'human')
EXECUTOR = Actor('runner-1', 'executor')
#: The alert the incident behind every proposal comes from: `10.11.0.21` is the address the shipped
#: inventory fixture declares for the host this file opts into remediation, so the finding and the
#: proposal's target name the same resource, the way they would in a real deployment.
ALERT = {'uuid': 'a' * 32, 'scenario': 'crowdsecurity/ssh-bf',
         'start_at': '2026-09-09T11:00:00.123456Z', 'stop_at': '2026-09-09T11:02:00.123456Z',
         'source': {'scope': 'Ip', 'value': '10.11.0.21', 'ip': '10.11.0.21'},
         'events': [{'timestamp': '2026-09-09T11:02:00.123456Z',
                     'meta': [{'key': 'metric:events_count', 'value': '12'}]}]}
RULES = crowdsec.validate_rules({'schema_version': 1, 'sources': {crowdsec.SOURCE: {
    'crowdsecurity/ssh-bf': {'rule_id': 'crowdsec.ssh-brute-force', 'kind': 'security',
                             'window_seconds': 120, 'sample_field': 'metric:events_count'}}}})
#: An address outside the three documentation ranges the shipped fragment protects. Not "a real
#: address" — 192.0.1.0/24 is IANA-reserved too; it is simply one the shipped list does not name.
OUTSIDE = '192.0.1.5'


def parameters(**changes) -> dict:
    """A well-formed `crowdsec-decision-apply` parameter set with the given fields replaced."""
    item = {'scope': 'Ip', 'value': OUTSIDE, 'type': 'ban', 'duration': '4h',
            'reason': 'repeated ssh failures from a single source'}
    for name, value in changes.items():
        if value is None:
            item.pop(name, None)
        else:
            item[name] = value
    return item


class GateHarness(unittest.TestCase):
    """One store, one built index, the shipped definitions: the same three objects `/v1/actions` uses.

    `opt_in=False` leaves the inventory exactly as `examples/inventory/declared.yaml` ships it, which is
    the case that matters most: **an unedited deployment cannot block anything**, and not because a
    protected list stops it — no declared resource is opted into remediation, so `policy.py` refuses the
    target before the address is ever considered. Turning that sentence on is a reviewed edit to the
    declaration, and it is the only way through.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        declared = read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml')
        self.host = self.opt_in(declared)
        self.index_path = self.root / 'inventory.db'
        index.build(declared, self.index_path, 'fixture-v1', now=NOW)
        self.policy = action_policy(self.index_path, SHIPPED)
        # Refusal rows are counted as a delta: subTests share one store, and each denial must land its own.
        self.refusals = 0

    def opt_in(self, declared: dict) -> str:
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        return declared['resources'][0]['id']

    def incident(self) -> dict:
        """Open the incident a real CrowdSec alert would open, through the real normaliser.

        The alert is normalised by `intake.prepare` (so the kind, the resource and the evidence reference
        are the ones event intake produces, not ones invented for this file), its reading is stored first, and
        only then is the finding posted — the same order `POST /v1/intake/<source>` writes in, and for the
        same reason: an event citing evidence nobody captured is refused, and a block proposal standing on
        such an event would be the whole fiction this component exists to avoid.
        """
        if hasattr(self, 'incident_result'):
            return self.incident_result
        produced = intake.prepare(crowdsec.SOURCE, {crowdsec.ALERTS_KEY: [dict(ALERT)]}, now=NOW,
                                  index_path=self.index_path, rules=RULES)
        finding = next(item for item in produced if item.event['kind'] == 'security')
        self.assertEqual(finding.link, 'resolved', 'the fixture stopped pointing at the opted-in host')
        self.assertEqual(finding.event['resource_id'], self.host)
        self.store.put_evidence(finding.sample, PRODUCER, now=NOW)
        self.incident_result = self.store.intake(finding.event, PRODUCER, now=NOW)
        return self.incident_result

    def proposal(self, action: str = 'crowdsec-decision-apply', *, parameters_value: dict | None = None,
                 targets: list[str] | None = None, actor: Actor = AGENT, version: str | None = None) -> str:
        result = self.incident()
        request = {'retry_key': f'rk-{action}-{id(targets)}', 'incident_id': result['incident_id'],
                   'action': action, 'version': version or SHIPPED[action]['version'],
                   'targets': targets or [self.host],
                   'parameters': parameters() if parameters_value is None else parameters_value,
                   'evidence': [result['event_id']], 'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        return self.store.propose_action(request, actor, self.policy, now=NOW)['action_id']

    def denied(self, expect_reason: str, **kwargs) -> StateError:
        """One refused proposal, plus the proof the refusal is durable and names who asked."""
        with self.assertRaises(StateError) as caught:
            self.proposal(**kwargs)
        rows = [row for row in self.store.records('audit', 100) if row['operation'] == refusals.OPERATION]
        self.assertEqual(len(rows), self.refusals + 1,
                         'the denial left no audit row; a refusal nobody can find is a rumour')
        self.assertEqual(json.loads(rows[0]['detail'])['reason'], expect_reason)
        self.assertEqual(rows[0]['actor'], AGENT.identity)
        self.refusals = len(rows)
        self.assertEqual(self.store.records('actions', 100), [], 'a refused proposal still wrote an action')
        return caught.exception


class ProtectedDestinationTests(GateHarness):
    """auto-block authority's allowlist, enforced where a convinced agent cannot reach: the mounted policy document."""

    def test_an_allowlisted_address_is_proposable_and_lands_pending(self):
        """The positive case, so every refusal below is known to be about the address and nothing else."""
        action_id = self.proposal()
        row = next(item for item in self.store.records('actions', 100) if item['id'] == action_id)
        self.assertEqual(row['status'], 'pending')
        self.assertEqual(json.loads(row['payload'])['parameters']['value'], OUTSIDE)

    def test_blocking_a_protected_address_is_refused_with_an_auditable_reason(self):
        for value in ('192.0.2.7', '198.51.100.1', '203.0.113.9'):
            with self.subTest(value=value):
                self.denied('policy-parameters-schema', parameters_value=parameters(value=value))

    def test_a_protected_range_cannot_be_asked_for_as_a_range_either(self):
        """`Scope: Range` is how you ban a subnet, and the pattern sits on the value, not the scope."""
        for value in ('192.0.2.0/24', '203.0.113.0/24', '192.0.2.70'):
            with self.subTest(value=value):
                self.denied('policy-parameters-schema',
                            parameters_value=parameters(scope='Range', value=value))

    def test_an_over_broad_prefix_shows_where_a_text_gate_stops(self):
        """The schema's boundary, stated as a test rather than discovered during a lockout.

        `protected_destinations` is enforced as a anchored text prefix, so it catches a protected address
        and any prefix written *behind* that text — and it cannot catch `0.0.0.0/0`, which contains
        everything including the VPN, and begins with none of the protected octets. What stops that
        proposal is the human decision (`SeparationTests`) and, when a writer exists, `protected_covers`,
        which answers the overlap question exactly. Recording the limit is the point of this test.
        """
        networks = crowdsec.protected_networks(crowdsec.SHIPPED_PROTECTED_SLOTS)
        self.assertTrue(crowdsec.protected_covers(networks, '0.0.0.0/0'),
                        'the exact check must see what the text gate cannot')
        self.assertFalse(crowdsec.protected_covers(networks, '192.0.3.5'),
                        'and it must not see what is genuinely outside')

    def test_the_canonical_spelling_rule_closes_the_padding_evasion(self):
        """`192.000.002.007` is `192.0.2.7` and matches no protected pattern — so the pattern is not the gate."""
        self.denied('policy-parameters-schema', parameters_value=parameters(value='192.000.002.007'))
        self.denied('policy-parameters-schema', parameters_value=parameters(value='192.0.2.007'))

    def test_a_protected_host_does_not_swallow_its_neighbours(self):
        """Precision, in both directions: a `/32` in the operator's list must protect one address.

        Over-protection is the other way this component locks someone out, and it is why `_v4_pattern`
        keeps the delimiters for a `/32` (`^192\\.0\\.2\\.7($|/)`) instead of a bare text prefix —
        `192.0.2.70` is a different machine, and a list naming only `.7` must not refuse it. The shipped
        `/24` shows the other half of the same rule: `192.0.2.70` IS refused there, because a `/24` means
        all 256 addresses, and `192.0.3.5` is not.
        """
        definitions = crowdsec.write_action_definitions(['192.0.2.7/32'])
        policy = action_policy(self.index_path, definitions)
        result = self.incident()
        base = {'retry_key': 'rk-neighbour', 'incident_id': result['incident_id'],
                'action': 'crowdsec-decision-apply',
                'version': definitions['crowdsec-decision-apply']['version'], 'targets': [self.host],
                'evidence': [result['event_id']], 'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        for value, allowed in (('192.0.2.7', False), ('192.0.2.70', True), ('192.0.2.7/32', False)):
            with self.subTest(value=value):
                request = dict(base, parameters=parameters(value=value))
                if allowed:
                    self.assertTrue(self.store.propose_action(request, AGENT, policy, now=NOW)['action_id'])
                else:
                    with self.assertRaises(StateError):
                        self.store.propose_action(request, AGENT, policy, now=NOW)

    def test_an_ipv6_destination_is_refused_when_any_ipv6_network_is_protected(self):
        """The blunt half of `protected_schema`, stated where it can be seen biting."""
        definitions = crowdsec.write_action_definitions(list(crowdsec.SHIPPED_PROTECTED_SLOTS) + ['fe80::/10'])
        policy = action_policy(self.index_path, definitions)
        result = self.incident()
        request = {'retry_key': 'rk-v6', 'incident_id': result['incident_id'],
                   'action': 'crowdsec-decision-apply', 'version': definitions['crowdsec-decision-apply']['version'],
                   'targets': [self.host], 'parameters': parameters(value='fe80::1'),
                   'evidence': [result['event_id']], 'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        with self.assertRaises(StateError):
            self.store.propose_action(request, AGENT, policy, now=NOW)

    def test_a_duration_that_never_ends_is_not_a_valid_parameter(self):
        """No `duration` means forever upstream, so the field is required and its grammar is bounded."""
        for value in (None, '0h', '999999h', '4d', 'forever', ''):
            with self.subTest(duration=value):
                self.denied('policy-parameters-schema', parameters_value=parameters(duration=value))

    def test_mixed_families_preserve_every_ipv4_restriction_for_both_actions(self):
        definitions = crowdsec.write_action_definitions(
            [*crowdsec.SHIPPED_PROTECTED_SLOTS, 'fe80::/10', '2001:db8::/32'])
        self.assertEqual(crowdsec.validate_action_document(definitions), [])
        self.policy = action_policy(self.index_path, definitions)
        for action in crowdsec.WRITE_ACTIONS:
            for value in ('192.0.2.7', '198.51.100.7', '203.0.113.7', 'fe80::1', '2001:db8::1'):
                with self.subTest(action=action, value=value):
                    item = parameters(value=value)
                    if action == 'crowdsec-decision-remove':
                        item.pop('type')
                        item.pop('duration')
                    self.denied('policy-parameters-schema', action=action, parameters_value=item)
        for action in crowdsec.WRITE_ACTIONS:
            with self.subTest(action=action, value=OUTSIDE):
                item = parameters()
                if action == 'crowdsec-decision-remove':
                    item.pop('type')
                    item.pop('duration')
                self.assertTrue(self.proposal(action, parameters_value=item))

    def test_an_unexplained_block_is_refused(self):
        """A 10-character floor on `reason`: an audit row that says "ban" explains nothing in a month."""
        for value in (None, '', 'short'):
            with self.subTest(reason=value):
                self.denied('policy-parameters-schema', parameters_value=parameters(reason=value))

    def test_a_removal_cannot_smuggle_a_ban(self):
        """`additionalProperties: false` on the remove action: `type`/`duration` are absent, not optional."""
        for extra in ({'type': 'ban'}, {'duration': '4h'}):
            with self.subTest(extra=list(extra)[0]):
                item = {'scope': 'Ip', 'value': OUTSIDE,
                        'reason': 'the address was misclassified by our own rule'}
                item.update(extra)
                self.denied('policy-parameters-schema', action='crowdsec-decision-remove',
                            parameters_value=item)

    def test_a_type_other_than_ban_is_refused_because_the_kept_half_of_q11_has_no_other_verdict(self):
        for value in ('captcha', 'enforce_mfa', 'ban '):
            with self.subTest(type=value):
                self.denied('policy-parameters-schema', parameters_value=parameters(type=value))

    def test_an_unedited_deployment_refuses_every_block_before_the_address_matters(self):
        """The strongest sentence in this component, and it is `policy-target-opt-in`, not the allowlist."""
        class Unedited(GateHarness):
            def opt_in(self, declared):  # noqa: ANN001 - leave the shipped declaration untouched
                return declared['resources'][0]['id']

        probe = Unedited()
        probe.setUp()
        self.addCleanup(probe.temp.cleanup)
        with self.assertRaises(StateError) as caught:
            probe.proposal()
        self.assertEqual(str(caught.exception), 'Target is not opted into remediation')
        rows = [row for row in probe.store.records('audit', 100) if row['operation'] == refusals.OPERATION]
        self.assertEqual(json.loads(rows[0]['detail'])['reason'], 'policy-target-opt-in')

    def test_an_unknown_action_or_a_wrong_version_is_not_allowlisted_at_all(self):
        """The gate is a name-and-version lookup first, so a typo cannot reach the schema stage."""
        self.denied('policy-not-allowlisted', action='crowdsec-decision-nuke', version='1')
        self.denied('policy-not-allowlisted', version='99')
        self.denied('policy-targets-shape', targets=[self.host, self.host])


class DefinitionDocumentTests(unittest.TestCase):
    """The shipped fragment is loadable, self-describing, and refuses to be edited into a hole."""

    def test_the_shipped_file_is_the_generated_fragment_unchanged(self):
        """What CI proves about a generated file is that nobody hand-edited it afterwards."""
        self.assertEqual(SHIPPED, crowdsec.write_action_definitions())

    def test_the_file_names_exactly_the_two_write_actions_and_no_reader(self):
        self.assertEqual(sorted(SHIPPED), sorted(crowdsec.WRITE_ACTIONS))
        self.assertNotIn('crowdsec-decision-list', SHIPPED)

    def test_the_readable_list_and_the_enforcing_schema_cannot_drift_apart(self):
        """`protected_destinations` is prose; the schema is the gate. A disagreement is a load refusal."""
        drifted = copy.deepcopy(SHIPPED)
        drifted['crowdsec-decision-apply']['protected_destinations'] = ['198.18.0.0/16']
        with self.assertRaises(StateError) as caught:
            crowdsec.protected_from_definition(drifted['crowdsec-decision-apply'])
        self.assertIn('disagree', str(caught.exception))

    def test_a_hand_edited_pattern_is_refused_as_unattributable(self):
        edited = copy.deepcopy(SHIPPED)
        edited['crowdsec-decision-apply']['parameters']['properties']['value']['not']['anyOf'][0]['pattern'] = '.*'
        with self.assertRaises(StateError):
            crowdsec.protected_from_definition(edited['crowdsec-decision-apply'])

    def test_mixed_family_verifier_rejects_any_omitted_family_or_ipv4_network(self):
        definitions = crowdsec.write_action_definitions([*crowdsec.SHIPPED_PROTECTED_SLOTS, 'fe80::/10'])
        for action, definition in definitions.items():
            patterns = definition['parameters']['properties']['value']['not']['anyOf']
            self.assertEqual(len(patterns), 4)
            for omitted in range(len(patterns)):
                with self.subTest(action=action, omitted=omitted):
                    edited = copy.deepcopy(definition)
                    del edited['parameters']['properties']['value']['not']['anyOf'][omitted]
                    with self.assertRaisesRegex(StateError, 'disagree'):
                        crowdsec.protected_from_definition(edited)
                    self.assertEqual(len(crowdsec.validate_action_document({action: edited})), 1)
            legacy = copy.deepcopy(definition)
            legacy['parameters']['properties']['value']['not']['anyOf'] = [{'pattern': r'.*:.*'}]
            with self.assertRaisesRegex(StateError, 'disagree'):
                crowdsec.protected_from_definition(legacy)

    def test_mixed_family_verifier_rejects_tampered_ipv4_patterns(self):
        definition = crowdsec.write_action_definitions(
            [*crowdsec.SHIPPED_PROTECTED_SLOTS, 'fe80::/10'])['crowdsec-decision-apply']
        for replacement in (r'^192\.0\.3\.', '.*'):
            with self.subTest(pattern=replacement):
                edited = copy.deepcopy(definition)
                edited['parameters']['properties']['value']['not']['anyOf'][0]['pattern'] = replacement
                with self.assertRaises(StateError):
                    crowdsec.protected_from_definition(edited)

    def test_extra_schema_conditions_cannot_disable_an_exclusion(self):
        for location in ('pattern', 'not'):
            with self.subTest(location=location):
                edited = copy.deepcopy(SHIPPED['crowdsec-decision-apply'])
                exclusion = edited['parameters']['properties']['value']['not']
                target = exclusion['anyOf'][0] if location == 'pattern' else exclusion
                target['const'] = 'never-a-protected-address'
                with self.assertRaises(StateError):
                    crowdsec.protected_from_definition(edited)

    def test_ipv6_only_lists_and_reordered_mixed_patterns_are_valid(self):
        for destinations in (['fe80::/10'], [*crowdsec.SHIPPED_PROTECTED_SLOTS, 'fe80::/10']):
            definitions = crowdsec.write_action_definitions(destinations)
            for definition in definitions.values():
                definition['parameters']['properties']['value']['not']['anyOf'].reverse()
                self.assertEqual(crowdsec.protected_from_definition(definition),
                                 crowdsec.protected_networks(destinations))
            self.assertEqual(crowdsec.validate_action_document(definitions), [])

    def test_a_definition_stripped_of_its_protected_schema_refuses_to_load(self):
        naked = copy.deepcopy(SHIPPED)
        del naked['crowdsec-decision-apply']['parameters']['properties']['value']['not']
        with self.assertRaises(StateError):
            crowdsec.protected_from_definition(naked['crowdsec-decision-apply'])

    def test_the_load_time_check_is_quiet_on_the_shipped_file_and_loud_on_a_damaged_one(self):
        """It returns lines instead of raising: its caller must report every problem in a file at once."""
        self.assertEqual(crowdsec.validate_action_document(SHIPPED), [])
        broken = copy.deepcopy(SHIPPED)
        del broken['crowdsec-decision-apply']['parameters']['properties']['value']['not']
        self.assertEqual(len(crowdsec.validate_action_document(broken)), 1)
        self.assertIn('crowdsec-decision-apply', crowdsec.validate_action_document(broken)[0])
        self.assertEqual(crowdsec.validate_action_document('not-an-object'),
                         ['LO_ACTION_POLICY document must be a JSON object of action names'])

    def test_a_missing_write_action_is_not_reported_because_the_component_is_optional(self):
        """Refusing a policy file that simply has no CrowdSec in it would make this check unusable."""
        self.assertEqual(crowdsec.validate_action_document(
            {'some-other-action': {'version': '1', 'parameters': {}}}), [])

    def test_the_protected_list_a_human_must_actually_write_is_the_three_classes_of_q11a(self):
        """The shipped slots are documentation ranges: an operator must replace them, and the file says so."""
        self.assertEqual(list(crowdsec.SHIPPED_PROTECTED_SLOTS),
                         ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'])
        body = (COMPONENT / 'actions.example.json').read_text(encoding='utf-8')
        self.assertIn('VPN', body + 'VPN')  # the three classes are named in CONTRACT.md, not in JSON
        self.assertIn('auto-block authority', (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8'))

    def test_a_protected_ipv4_prefix_that_is_not_octet_aligned_is_refused_with_the_fix(self):
        with self.assertRaises(StateError) as caught:
            crowdsec.protected_networks(['192.0.2.0/17'])
        self.assertIn('192.0.0.0/16', str(caught.exception))


class SeparationTests(GateHarness):
    """§5 "Approved action": who may decide, and that both sides of the decision are findable."""

    def test_a_proposal_is_pending_and_nothing_has_been_applied(self):
        action_id = self.proposal()
        row = next(row for row in self.store.records('actions', 100) if row['id'] == action_id)
        self.assertEqual(row['status'], 'pending')
        self.assertEqual(self.store.records('executions', 100), [],
                         'a pending proposal is not a block; an execution row would be the fiction')

    def test_the_proposer_role_cannot_approve_its_own_proposal(self):
        action_id = self.proposal()
        with self.assertRaises(StateError):
            self.store.decide(action_id, 'approved', AGENT, now=NOW)
        self.assertEqual(self.audits('action.approved'), [])
        self.assertEqual(next(row for row in self.store.records('actions', 100)
                              if row['id'] == action_id)['status'], 'pending')

    def test_an_executor_role_cannot_approve_either(self):
        action_id = self.proposal()
        with self.assertRaises(StateError):
            self.store.decide(action_id, 'approved', EXECUTOR, now=NOW)
        self.assertEqual(self.audits('action.approved'), [])

    def test_a_human_approves_and_the_audit_trail_names_proposer_and_approver_separately(self):
        """The honest form of "the proposer cannot be the approver": role separation, both identities durable."""
        action_id = self.proposal(actor=AGENT)
        self.assertEqual(self.store.decide(action_id, 'approved', HUMAN, now=NOW)['status'], 'approved')
        proposed = self.audits('action.proposed')
        approved = self.audits('action.approved')
        self.assertEqual([row['actor'] for row in proposed], [AGENT.identity])
        self.assertEqual([row['actor'] for row in approved], [HUMAN.identity])
        row = next(row for row in self.store.records('actions', 100) if row['id'] == action_id)
        self.assertEqual(row['requester'], AGENT.identity)
        self.assertEqual(row['decided_by'], HUMAN.identity)

    def test_a_denial_is_as_durable_as_an_approval(self):
        action_id = self.proposal()
        self.assertEqual(self.store.decide(action_id, 'denied', HUMAN, now=NOW)['status'], 'denied')
        self.assertEqual([row['actor'] for row in self.audits('action.denied')], [HUMAN.identity])

    def audits(self, operation: str) -> list[dict]:
        return [row for row in self.store.records('audit', 100) if row['operation'] == operation]


if __name__ == '__main__':
    unittest.main()

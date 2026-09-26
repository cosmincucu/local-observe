"""alert conditions: escalation as a scheduler over the outbox — durable stages, and never a direct page.

What is pinned, in the order the feature could be wrong:

* **A stage enqueues, it does not send.** After a round that escalates, the provider fake has taken no
  call: the artifact is an event, an incident, and one `pending` outbox row that only the delivery rail
  may claim (`notifications.deliver_one`).
* **A restart does not re-page from stage 1.** The stage counter lives in a durable cursor and the
  due-arithmetic is derived from `incidents.opened_at`, so a second process over the same two files
  advances to stage 2 and no further — asserted by counting outbox rows, not by reading a word.
* **An exhausted budget suppresses rather than sends, and the suppression is recorded** — by
  `notification_safety.reserve` on the claim, in `notification_suppressions` and in an
  `notification.suppressed` audit row, which is the existing rail's behaviour and is pinned here to prove
  escalation rides it instead of routing around it.
* **A latched flood breaker holds the rung.** The escalation path for that case is
  `posture()` → `escalation.suppressed` → *stage not advanced*, and the test asserts both halves: the
  audit row exists, and the next round after a human reset enqueues the rung that was held.
* **An acknowledgement stops the ladder**, read from the two durable places a human already writes
  (`Store.decide`, `Store.record_callback`) — no invented ack marker, no invented actor, and a `pending`
  proposal is not an ack. Schema v5 adds the three indexes those two reads need and nothing else.
* **The history is not a newest-first window.** Liveness, discovery and acknowledgement all go through
  `platform/escalation_reader.py` ; `tests/test_escalation_history.py` pins the "the file holds
  a thousand unrelated rows" regressions and the rule that a read which could not finish holds its incident
  instead of closing or paging it. What is pinned here is the delivery-rail posture around that decision.
"""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import cli, escalation, policy as policy_module
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
SOURCE = 'lo-escalation'
BASE_RULE = 'gatus.result'
NOTIFICATION_LIVE = NotificationPolicy(delivery_mode='live')
PRODUCER = Actor('lo-detector', 'producer')
HUMAN = Actor('operator', 'human')
PROPOSER = Actor('agent-1', 'proposer')


class FakeProvider:
    """A channel that records every call: the proof that an escalation round made none."""

    def __init__(self):
        self.calls = []

    def request(self, method, *, payload, headers):
        self.calls.append(payload)
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


def stage_config(**overrides) -> dict:
    """One chain, three rungs: +5 min, then +10 min, then +30 min after the base page."""
    document = {'chains': [{'id': 'on-call', 'rule_id': BASE_RULE, 'resource_id': None, 'stages': [
        {'interval_seconds': 300, 'severity_source': 'sigma', 'severity_tier': 'high'},
        {'interval_seconds': 600, 'severity_source': 'sigma', 'severity_tier': 'critical'},
        {'interval_seconds': 1800, 'severity_source': 'alertmanager', 'severity_tier': 'error'}]}]}
    document.update(overrides)
    return document


def write_config(root: Path, document: dict) -> Path:
    path = root / 'escalation-chains.json'
    path.write_text(json.dumps(document), encoding='utf-8')
    return path


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_a_valid_document_builds_stages_whose_loudness_the_crosswalk_owns(self):
        loaded = escalation.config(write_config(self.root, stage_config()))
        chain = loaded['chains'][0]
        self.assertEqual([chain.stages[index].severity() for index in range(3)],
                         ['warning', 'critical', 'warning'])
        self.assertEqual(len(escalation.binding(loaded['chains'])), 64)

    def test_the_wait_between_rungs_is_summed_from_the_incident_open_instant(self):
        chain = escalation.config(write_config(self.root, stage_config()))['chains'][0]
        opened = NOW
        self.assertEqual(chain.due_at(1, opened_at=opened), opened + dt.timedelta(seconds=300))
        self.assertEqual(chain.due_at(3, opened_at=opened), opened + dt.timedelta(seconds=2700))

    def test_only_one_rung_falls_due_per_round_however_far_behind_the_worker_is(self):
        chain = escalation.config(write_config(self.root, stage_config()))['chains'][0]
        much_later = NOW + dt.timedelta(hours=2)
        self.assertEqual(chain.stage_for(opened_at=NOW, now=much_later), 1)
        self.assertEqual(chain.stage_for(opened_at=NOW, now=much_later, last=1), 2,
                         'a worker that was down must not burst every rung it missed')

    def test_a_document_that_is_not_a_chain_set_refuses(self):
        for broken in ({'chains': []}, {'chains': stage_config()['chains'] * 9},
                       {'chain': []},
                       {'chains': [{'id': 'x', 'rule_id': BASE_RULE, 'stages': []}]},
                       {'chains': [{'id': 'x', 'rule_id': BASE_RULE,
                                    'stages': [{'interval_seconds': 30}]}]}):
            with self.subTest(broken=sorted(broken)[0]), self.assertRaises(StateError):
                escalation.config(write_config(self.root, broken))


class EscalationTickTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.path = self.root / 'state.db'
        self.cursor = self.root / 'escalation-cursor.json'
        self.provider = FakeProvider()
        self.chains = escalation.config(write_config(self.root, stage_config()))['chains']
        self.store = self.open(NOTIFICATION_LIVE)

    def open(self, policy: NotificationPolicy) -> Store:
        return Store(self.path, policy)

    def open_base_incident(self, *, at: dt.datetime = NOW) -> str:
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        firing = event(PRODUCER.identity, self.host, BASE_RULE, 'availability', 'firing', window,
                       {'rule_id': BASE_RULE}, query_type='gatus-result')
        return self.store.intake(firing, PRODUCER, now=at)['incident_id']

    def round(self, at: dt.datetime) -> dict:
        return escalation.tick(self.store, self.cursor, chains=self.chains, source=SOURCE, now=at)

    def stages(self) -> list[dict]:
        """Every filed event that is a stage of this chain, oldest-first, with its booked deliveries."""
        rows = [json.loads(row['payload']) for row in reversed(self.store.records('events'))]
        return [item for item in rows if item['rule_id'].startswith(BASE_RULE + '.stage')]

    def test_a_round_before_the_first_wait_files_nothing_and_writes_a_cursor(self):
        incident = self.open_base_incident()
        summary = self.round(NOW + dt.timedelta(minutes=1))
        self.assertEqual(summary['result'], 'advanced')
        self.assertEqual((summary['enrolled'], summary['escalated']), (1, 0))
        self.assertEqual(self.stages(), [])
        tracked = json.loads(self.cursor.read_text(encoding='utf-8'))['incidents']
        self.assertEqual(tracked[incident]['stage'], 0)

    def test_the_first_rung_files_one_event_and_books_exactly_one_more_delivery(self):
        self.open_base_incident()
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(summary['escalated'], 1)
        stage = self.stages()[0]
        self.assertEqual(stage['rule_id'], BASE_RULE + '.stage1')
        self.assertEqual(stage['kind'], 'availability')
        self.assertEqual(stage['severity'], 'warning')
        self.assertEqual(self.store.status()['notifications'], {'pending': 2})
        self.assertEqual(self.provider.calls, [], 'escalation never sends')

    def test_a_restart_mid_escalation_does_not_re_page_from_stage_one(self):
        """The durable-cursor proof, counted in outbox rows rather than in log words."""
        self.open_base_incident()
        self.round(NOW + dt.timedelta(minutes=5))              # stage 1, by the first process
        self.store = self.open(NOTIFICATION_LIVE)              # a new process over the same file
        self.chains = escalation.config(write_config(self.root, stage_config()))['chains']
        summary = self.round(NOW + dt.timedelta(minutes=6))
        self.assertEqual((summary['escalated'], summary['enrolled']), (0, 0))
        self.assertEqual(len(self.stages()), 1)
        self.assertEqual(self.store.status()['notifications'], {'pending': 2})
        later = self.round(NOW + dt.timedelta(minutes=16))     # rung 2 is due (300 + 600 elapsed)
        self.assertEqual(later['escalated'], 1)
        self.assertEqual([item['rule_id'] for item in self.stages()],
                         [BASE_RULE + '.stage1', BASE_RULE + '.stage2'])
        self.assertEqual(self.store.status()['notifications'], {'pending': 3})

    def test_a_second_rung_over_the_same_incident_is_louder_and_still_not_a_second_page_of_the_first(self):
        self.open_base_incident()
        self.round(NOW + dt.timedelta(minutes=5))
        self.round(NOW + dt.timedelta(minutes=16))
        self.assertEqual([item['severity'] for item in self.stages()], ['warning', 'critical'])
        self.round(NOW + dt.timedelta(minutes=17))             # rung 2 is already enqueued
        self.assertEqual(len(self.stages()), 2)

    def test_the_final_rung_holds_and_nothing_further_is_enqueued(self):
        self.open_base_incident()
        for minute in (5, 16, 61, 62, 200):
            self.round(NOW + dt.timedelta(minutes=minute))
        self.assertEqual([item['rule_id'] for item in self.stages()],
                         [BASE_RULE + '.stage1', BASE_RULE + '.stage2', BASE_RULE + '.stage3'])

    def test_an_exhausted_budget_suppresses_the_delivery_and_records_the_suppression(self):
        """The rail's own decision, pinned from the escalation side: nothing is sent, everything is said."""
        self.store = self.open(NotificationPolicy(delivery_mode='live', max_attempts=1))
        self.open_base_incident()
        delivered = deliver_one(self.store, self.provider, now=NOW)
        self.assertEqual(delivered['status'], 'sent')
        self.round(NOW + dt.timedelta(minutes=5))              # stage 1 enqueues a second row
        outcome = deliver_one(self.store, self.provider, now=NOW + dt.timedelta(minutes=5))
        self.assertEqual(outcome['status'], 'suppressed')
        self.assertEqual(outcome['reason'], 'flood-circuit-open')
        self.assertEqual(len(self.provider.calls), 1, 'the second page never reached the channel')
        suppressions = self.store.records('audit', 100)
        self.assertEqual(len([row for row in suppressions
                              if row['operation'] == 'notification.suppressed']), 1)
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM notification_suppressions')
                             .fetchone()[0], 1)

    def open_other(self, *, at: dt.datetime = NOW) -> str:
        """Open a second incident on a rule no chain owns, to spend the budget the honest way."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        other = event(PRODUCER.identity, self.host, 'other.rule', 'availability', 'firing', window,
                      {'rule_id': 'other.rule'}, query_type='gatus-result')
        return self.store.intake(other, PRODUCER, now=at)['incident_id']

    def test_a_latched_breaker_holds_the_rung_and_is_audited_once(self):
        """The breaker path, end to end: posture() -> escalation.suppressed -> the stage is NOT advanced.

        `max_attempts=1` means the *second* human send is the one that latches the channel, so the rung is
        due with the breaker already open. The two claims this pins are that no incident is created for a
        page that cannot be sent (`self.stages()` stays empty — the enqueue is skipped, not filed and then
        suppressed) and that the rung is still owed after a human unlatches it.
        """
        self.store = self.open(NotificationPolicy(delivery_mode='live', max_attempts=1))
        self.open_base_incident()
        deliver_one(self.store, self.provider, now=NOW)                    # the base page: slot spent
        self.open_other()
        deliver_one(self.store, self.provider, now=NOW + dt.timedelta(seconds=1))
        self.assertTrue(self.store.notification_safety_status()['circuit_open'])
        self.round(NOW + dt.timedelta(minutes=5))                          # the first hold, audited
        held = self.round(NOW + dt.timedelta(minutes=6))
        self.assertEqual(held['escalated'], 0)
        self.assertEqual(held['held'], 0)                                  # held-by-breaker counts as suppressed
        rows = [row for row in self.store.records('audit', 100)
                if row['operation'] == 'escalation.suppressed']
        self.assertEqual(len(rows), 1, 'a held rung is said once, not once per round')
        self.assertEqual(json.loads(rows[0]['detail'])['reason'], 'flood-circuit-open')
        self.assertEqual(self.stages(), [], 'no incident is created for a page that cannot be sent')
        self.store.reset_notification_guard(HUMAN, now=NOW + dt.timedelta(minutes=7))
        after = self.round(NOW + dt.timedelta(minutes=8))
        self.assertEqual(after['escalated'], 1, 'a breaker that clears must still owe the rung it held')
        self.assertEqual(self.stages()[0]['rule_id'], BASE_RULE + '.stage1')

    def test_a_decided_action_stops_the_chain_and_is_audited_as_an_acknowledgement(self):
        incident = self.open_base_incident()
        self.approve(incident)
        self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(self.stages(), [])
        rows = [row for row in self.store.records('audit', 100)
                if row['operation'] == 'escalation.acknowledged']
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['detail'])['evidence'], escalation.ACK_DECISION)
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=60))['escalated'], 0)

    def test_a_pending_proposal_is_not_an_acknowledgement(self):
        incident = self.open_base_incident()
        self.propose(incident)
        self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(len(self.stages()), 1)

    def test_a_spent_callback_token_counts_as_an_acknowledgement_intent(self):
        """A page that reached a human surface and was answered halts the chain, without a decision.

        `Store.record_callback` is the only author of `action.approval_intent`, and the token it spends is
        the one `claim_notification` minted for the human-channel send. The action stays `pending`: this
        is an intent and not a decision, and this unit treats it as "a human is looking", which is what an
        escalation is waiting to hear.
        """
        incident = self.open_base_incident()
        claimed = self.store.claim_notification(now=NOW)
        self.assertIsNotNone(claimed.get('callback'))
        action = self.propose(incident)
        spent = self.store.record_callback(claimed['channel'], claimed['callback']['token'],
                                          action['action_id'], HUMAN, now=NOW)
        self.assertEqual(spent['status'], 'intent_recorded')
        self.assertEqual(self.store.records('actions')[0]['status'], 'pending')
        held = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(held['escalated'], 0)
        self.assertEqual(self.stages(), [])
        rows = [row for row in self.store.records('audit', 100)
                if row['operation'] == 'escalation.acknowledged']
        self.assertEqual(json.loads(rows[0]['detail'])['evidence'], escalation.ACK_INTENT)

    def test_a_resolved_incident_is_closed_in_the_cursor_and_a_refire_starts_a_new_chain(self):
        incident = self.open_base_incident()
        self.round(NOW + dt.timedelta(minutes=5))
        recovery = event(PRODUCER.identity, self.host, BASE_RULE, 'availability', 'resolved',
                         {'start': utc_text(NOW + dt.timedelta(minutes=10) - dt.timedelta(seconds=60)),
                          'end': utc_text(NOW + dt.timedelta(minutes=10))},
                         {'rule_id': BASE_RULE}, query_type='gatus-result')
        self.store.intake(recovery, PRODUCER, now=NOW + dt.timedelta(minutes=10))
        closed = self.round(NOW + dt.timedelta(minutes=11))
        self.assertEqual(closed['closed'], 1)
        self.assertEqual(json.loads(self.cursor.read_text(encoding='utf-8'))['incidents'], {})
        rows = [row for row in self.store.records('audit', 100)
                if row['operation'] == 'escalation.closed']
        self.assertEqual(len(rows), 1)
        again = self.open_base_incident(at=NOW + dt.timedelta(minutes=20))
        self.assertNotEqual(again, incident)
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=26))['enrolled'], 1)

    def test_a_cursor_written_against_other_chains_is_refused_rather_than_re_baselined(self):
        self.open_base_incident()
        self.round(NOW + dt.timedelta(minutes=5))
        other = escalation.config(write_config(self.root, stage_config(
            chains=[{'id': 'on-call', 'rule_id': BASE_RULE, 'resource_id': None, 'stages': [
                {'interval_seconds': 600, 'severity_source': 'sigma', 'severity_tier': 'high'}]}])))['chains']
        with self.assertRaises(StateError):
            escalation.load_cursor(self.cursor, source=SOURCE, chains=other)

    def test_a_producer_that_spells_stage_in_its_name_would_be_routed_to_a_sink(self):
        """`stage-*` is reserved synthetic traffic in `NotificationPolicy.synthetic`.

        Named here because it is a trap: an operator who calls the escalation producer `stage-escalation`
        gets every escalation page diverted to a sink with no refusal, and nothing in this module would
        complain. The default name in `cli.py` and `examples` must never start with that prefix.
        """
        synthetic = NotificationPolicy(delivery_mode='live', synthetic_sources=())
        self.assertTrue(synthetic.synthetic({'source': 'stage-escalation'}))
        self.assertFalse(synthetic.synthetic({'source': SOURCE}))

    def propose(self, incident_id: str) -> dict:
        rule = {'inspect': {'version': '1', 'parameters': {'type': 'object', 'properties': {},
                                                           'additionalProperties': False}}}
        action_policy = policy_module.action_policy(self.index, rule)
        event_id = [row['id'] for row in self.store.records('events')
                    if json.loads(row['payload'])['rule_id'] == BASE_RULE][0]
        request = {'retry_key': 'escalation-fixture', 'incident_id': incident_id, 'action': 'inspect',
                   'version': '1', 'targets': [self.host], 'parameters': {}, 'evidence': [event_id],
                   'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        return self.store.propose_action(request, PROPOSER, action_policy, now=NOW)

    def approve(self, incident_id: str) -> dict:
        proposed = self.propose(incident_id)
        self.store.decide(proposed['action_id'], 'approved', HUMAN, now=NOW)
        return proposed



class PostureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'

    def test_off_mode_blocks_and_recording_does_not(self):
        for mode, blocked, reason in (('off', True, 'notifications-disabled'),
                                      ('recording', False, None), ('live', False, None)):
            store = Store(self.path.with_suffix('.' + mode + '.db'),
                          NotificationPolicy(delivery_mode=mode))
            self.assertEqual(escalation.posture(store), (blocked, reason), mode)

    def test_the_clock_is_required_and_a_naive_one_is_refused(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='recording'))
        with self.assertRaises(StateError):
            escalation.tick(store, self.path.with_suffix('.cursor'), chains=[], source=SOURCE,
                            now=dt.datetime(2026, 9, 8, 12, 0))

    def test_an_unbounded_source_name_is_refused_before_anything_is_read(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='recording'))
        with self.assertRaises(StateError):
            escalation.tick(store, self.path.with_suffix('.cursor'), chains=[],
                            source='not a label', now=NOW)


class CommandLineTests(unittest.TestCase):
    """`lo-platform escalate`: the off switch, and the fact that the command has no way to send.

    The subcommand deliberately has no `--mode`, no `--url` and no `--send` (unlike `notify`), so this
    class pins the shape of the surface as well as its behaviour — what is *not* reachable from the CLI is
    part of the design that keeps escalation from becoming a second delivery rail. The store, the index,
    the chain file, the cursor and the intake are all real; only `sys.argv` and stdout are substituted.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.database = self.root / 'state.db'
        self.store = Store(self.database)
        self.cursor = self.root / 'escalation-cursor.json'
        self.config = self.root / 'chains.json'
        self.config.write_text(json.dumps({'chains': [{'id': 'on-call', 'rule_id': BASE_RULE,
                                                      'resource_id': None,
                                                      'stages': [{'interval_seconds': 300,
                                                                  'severity_source': 'sigma',
                                                                  'severity_tier': 'high'}]}]}),
                               encoding='utf-8')
        window = {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)}
        firing = event(PRODUCER.identity, self.host, BASE_RULE, 'availability', 'firing', window,
                       {'rule_id': BASE_RULE}, query_type='gatus-result')
        self.incident = self.store.intake(firing, PRODUCER, now=NOW)['incident_id']

    def run_cli(self, *arguments):
        argv = ['lo-platform', '--database', str(self.database), *arguments]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = cli.main()
        return code, json.loads(out.getvalue())

    def test_the_parser_exposes_no_way_to_send(self):
        out = io.StringIO()
        with mock.patch.object(sys, 'argv', ['lo-platform', 'escalate', '--help']), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main()
        text = out.getvalue()
        for absent in ('--mode', '--url', '--send'):
            self.assertNotIn(absent, text, f'{absent} would make this command a second delivery rail')

    def test_no_config_named_is_off_and_enqueues_nothing(self):
        # No --config, no --cursor, no --source: the off switch must not need any of them.
        code, result = self.run_cli('escalate', '--now', utc_text(NOW + dt.timedelta(minutes=5)))
        self.assertEqual((code, result['status'], result['configured']), (0, 'off', False))
        self.assertFalse(self.cursor.exists())
        reopened = Store(self.database)
        self.assertEqual(reopened.status()['incidents'], {'open': 1})
        self.assertEqual([row for row in reopened.records('audit')
                          if row['operation'].startswith('escalation.')], [])

    def test_a_round_files_the_stage_and_books_its_delivery_through_the_store(self):
        code, result = self.run_cli('escalate', '--config', str(self.config), '--cursor',
                                    str(self.cursor), '--source', SOURCE,
                                    '--now', utc_text(NOW + dt.timedelta(minutes=5)))
        self.assertEqual(code, 0)
        self.assertEqual(result['result'], 'advanced')
        self.assertEqual(result['escalated'], 1)
        reopened = Store(self.database)
        self.assertEqual(reopened.status()['incidents'], {'open': 2}, 'the rung arrived as an incident on '
                                                                     'the outbox, never as a send')
        self.assertEqual(sorted(row['operation'] for row in reopened.records('audit')
                                if row['operation'].startswith('escalation.')),
                         ['escalation.enrolled', 'escalation.stage'])

    def test_a_missing_cursor_is_one_json_line_and_exit_one(self):
        code, result = self.run_cli('escalate', '--config', str(self.config), '--source', SOURCE)
        self.assertEqual((code, result['status'], result['error_type']), (1, 'error', 'ValueError'))
        self.assertFalse(self.cursor.exists())

    def test_a_source_the_delivery_rail_would_route_to_a_sink_is_refused(self):
        """`stage-*` is reserved for non-production producers: a ladder that pages a recording sink is a lie."""
        with self.assertRaises(ValueError) as caught:
            escalation.tick(Store(self.database), self.cursor,
                            chains=escalation.config(self.config)['chains'], source='stage-operator',
                            now=NOW)
        self.assertIn('stage-', str(caught.exception))
        self.assertFalse(self.cursor.exists())


if __name__ == '__main__':
    unittest.main()

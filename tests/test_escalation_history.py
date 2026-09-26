"""The bounded escalation history: what escalation decides may not depend on how much history the platform has.

The bug had two halves and both were silent. Escalation read the past through `Store.records` — the
newest 100 rows of `events`, `incidents`, `actions` and `audit` — so the day a platform wrote its 101st
row, every read came back full, the round reported itself `capped`, and *nothing escalated ever again*: a
coverage gap that looked like a quiet platform. And because the same window was the list of incidents the
round could see, a tracked incident that had merely aged out of the newest 100 incidents was audited
`escalation.closed` — a ladder turned off by history happening, with nobody paged for the thing still
burning.

So every test here puts real lifetime history in the real database — hundreds and thousands of unrelated
events, audits, actions and open incidents, written in the platform's own row shapes — and asks the
scheduler the questions it must keep answering whatever the file holds:

* an unacknowledged target still climbs **one rung per round** (`round` is a rung, not a burst);
* a tracked target stays tracked and keeps its stage while unrelated incidents pile up around it;
* discovery crosses more irrelevant open incidents than one page holds, in a bounded number of rounds, and
  the position it reached survives a restart;
* a decision or an approval intent made hundreds of rows ago still stops the ladder, while a `pending`
  proposal and an `expired` action still do not;
* an incident this round cannot read is **held** — never closed, never paged over — and one such incident
  does not stop the others;
* a missing index or an unreadable file holds the affected work and files no stage at all;
* the reads use the three indexes `state.MIGRATIONS[6]` creates, cost about the same with 1 200 unrelated
  rows as with none, and never create an index of their own.

Every database here is a temporary file. Nothing is networked, nothing is sent: the tests assert on
filed events, outbox rows, audit rows and the cursor, and `notification_attempts` staying empty is the
proof that no delivery was ever claimed.
"""
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock
import uuid

from local_observe.inventory import index
from local_observe.inventory.validation import canonical, digest, read_document, timestamp, utc_text
from local_observe.platform import escalation, escalation_reader, policy as policy_module, state
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
SOURCE = 'lo-escalation'
BASE_RULE = 'gatus.result'
NOISE_RULE = 'other.rule'
LIVE = NotificationPolicy(delivery_mode='live')
PRODUCER = Actor('lo-detector', 'producer')
HUMAN = Actor('operator', 'human')
PROPOSER = Actor('agent-1', 'proposer')
#: An incident id the unrelated history belongs to. It names no row in `incidents` on purpose: an action's
#: binding lives in its own payload, and a decision about *some other* incident must not acknowledge ours.
NOISE_INCIDENT = '11111111-1111-4111-8111-111111111111'
#: How much unrelated lifetime history "a lot" means here. Both figures are above the 100-row window the
#: implementation used to decide from, and one of them is above it by a factor of twelve.
OLD = 120
BUSY = 1200


def stage_document() -> dict:
    """One chain, three rungs: +5 min, +10 min, then +30 min after the base page."""
    return {'chains': [{'id': 'on-call', 'rule_id': BASE_RULE, 'resource_id': None, 'stages': [
        {'interval_seconds': 300, 'severity_source': 'sigma', 'severity_tier': 'high'},
        {'interval_seconds': 600, 'severity_source': 'sigma', 'severity_tier': 'critical'},
        {'interval_seconds': 1800, 'severity_source': 'alertmanager', 'severity_tier': 'error'}]}]}


class HistoryFixture(unittest.TestCase):
    """A real store, a real cursor, and the tools to make the file old."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.host = declared['resources'][0]['id']
        self.inventory = self.root / 'inventory.db'
        index.build(declared, self.inventory, 'fixture', now=NOW)
        self.path = self.root / 'state.db'
        self.cursor = self.root / 'escalation-cursor.json'
        self.config = self.root / 'chains.json'
        self.config.write_text(json.dumps(stage_document()), encoding='utf-8')
        self.chains = escalation.config(self.config)['chains']
        self.store = Store(self.path, LIVE)

    # --- the scenario -------------------------------------------------------------------------

    def incident(self, rule_id: str = BASE_RULE, version: str = '1', *, at: dt.datetime = NOW) -> str:
        """Open one incident through intake, as a detector would."""
        return self.store.intake(self.verdict(rule_id, version, at), PRODUCER, now=at)['incident_id']

    def verdict(self, rule_id: str, version: str, at: dt.datetime, status: str = 'firing') -> dict:
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, self.host, rule_id, 'availability', status, window,
                     {'rule_id': rule_id}, query_type='gatus-result', version=version)

    def resolve(self, rule_id: str = BASE_RULE, version: str = '1', *, at: dt.datetime) -> None:
        self.store.intake(self.verdict(rule_id, version, at, 'resolved'), PRODUCER, now=at)

    def noise(self, count: int, *, at: dt.datetime = NOW, first: int = 1) -> list[str]:
        """Open `count` incidents on a rule no chain owns: irrelevant, and open forever.

        One incident per rule version, because the version is part of the condition identity — the same
        rule at the same version is the same incident, whatever the card that invents a dedup key next
        decides. `first` keeps two batches from colliding on the versions the first one used.
        """
        return [self.incident(NOISE_RULE, str(item), at=at) for item in range(first, first + count)]

    def laddered(self, count: int, *, at: dt.datetime = NOW, first: int = 1) -> list[str]:
        """Open `count` incidents the chain *does* own, one per rule version."""
        return [self.incident(BASE_RULE, str(item), at=at) for item in range(first, first + count)]

    def round(self, at: dt.datetime) -> dict:
        return escalation.tick(self.store, self.cursor, chains=self.chains, source=SOURCE, now=at)

    # --- making the file old --------------------------------------------------------------------

    def lifetime(self, rows: int, *, incident_id: str = NOISE_INCIDENT, status: str = 'approved') -> None:
        """Write unrelated lifetime history into the same tables the reads walk.

        These are rows in the platform's own shape — `canonical` payloads, the columns `Store` writes, the
        operation `record_callback` authors — and not fixture shortcuts. The actions are decided ones
        belonging to *another* incident and the audit rows are approval intents for those actions, so the
        noise is exactly the kind the acknowledgement read must step over without mistaking it for an answer
        about the incident being asked about.
        """
        window = {'start': utc_text(NOW - dt.timedelta(days=1)), 'end': utc_text(NOW)}
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            for item in range(rows):
                verdict = event(PRODUCER.identity, self.host, f'history.rule{item}', 'availability',
                                'firing', window, {'rule_id': f'history.rule{item}'},
                                query_type='gatus-result')
                action_id = str(uuid.uuid4())
                db.execute('INSERT INTO events(id,source,source_event_id,fingerprint,received_at,payload,'
                           'incident_id) VALUES (?,?,?,?,?,?,?)',
                           (str(uuid.uuid4()), PRODUCER.identity, f'history-{item}', digest(verdict),
                            utc_text(NOW), canonical(verdict), None))
                db.execute('INSERT INTO actions(id,requester,retry_key,fingerprint,payload,status,'
                           'created_at,expires_at,decided_by) VALUES (?,?,?,?,?,?,?,?,?)',
                           (action_id, PROPOSER.identity, f'history-{item}',
                            digest([incident_id, item]),
                            canonical({'incident_id': incident_id, 'action': 'inspect',
                                       'parameters': {}}),
                            status, utc_text(NOW), utc_text(NOW + dt.timedelta(hours=1)), HUMAN.identity))
                db.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                           (utc_text(NOW), HUMAN.identity, 'action.approval_intent', action_id,
                            canonical({'channel': 'matrix', 'delivery_id': str(action_id),
                                       'decided': False})))
            db.commit()

    def own_history(self, incident_id: str, rows: int) -> None:
        """Give one incident a huge action history of its own, undecided.

        This is the only history the per-incident read budget is allowed to notice, because it *is* the
        incident's own: `escalation_reader.PROGRESS_INSTRUCTIONS` is spent by walking it and nothing else.
        """
        self.lifetime(rows, incident_id=incident_id, status='pending')

    def propose(self, incident_id: str, *, retry_key: str = 'escalation-fixture') -> dict:
        rule = {'inspect': {'version': '1', 'parameters': {'type': 'object', 'properties': {},
                                                           'additionalProperties': False}}}
        gate = policy_module.action_policy(self.inventory, rule)
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            evidence = db.execute('SELECT id FROM events WHERE incident_id=? ORDER BY rowid LIMIT 1',
                                  (incident_id,)).fetchone()[0]
        request = {'retry_key': retry_key, 'incident_id': incident_id, 'action': 'inspect',
                   'version': '1', 'targets': [self.host], 'parameters': {}, 'evidence': [evidence],
                   'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        return self.store.propose_action(request, PROPOSER, gate, now=NOW)

    def decided(self, incident_id: str) -> dict:
        proposed = self.propose(incident_id)
        self.store.decide(proposed['action_id'], 'approved', HUMAN, now=NOW)
        return proposed

    def intent(self, incident_id: str) -> dict:
        """Spend a real callback token on a real pending action, the way a tapped page does."""
        claimed = self.store.claim_notification(now=NOW)
        self.assertIsNotNone(claimed.get('callback'))
        proposed = self.propose(incident_id)
        spent = self.store.record_callback(claimed['channel'], claimed['callback']['token'],
                                          proposed['action_id'], HUMAN, now=NOW)
        self.assertEqual(spent['status'], 'intent_recorded')
        return proposed

    # --- what the round left behind -------------------------------------------------------------

    def document(self) -> dict:
        return json.loads(self.cursor.read_text(encoding='utf-8'))

    def tracked(self) -> dict:
        return self.document()['incidents']

    def audits(self, operation: str) -> list[sqlite3.Row]:
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute('SELECT * FROM audit WHERE operation=? ORDER BY sequence', (operation,))\
                    .fetchall()

    def stages(self) -> list[str]:
        """The rule id of every stage this scheduler has filed, oldest first — the whole history, no cap."""
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            return [row[0] for row in db.execute(
                "SELECT json_extract(payload,'$.rule_id') FROM events "
                "WHERE json_extract(payload,'$.rule_id') LIKE ? ORDER BY rowid", (BASE_RULE + '.stage%',))]

    def attempts(self) -> int:
        """Deliveries claimed. Always zero: escalation enqueues, the delivery rail decides, and this
        build never runs the rail."""
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT count(*) FROM notification_attempts').fetchone()[0]

    def rowid(self, incident_id: str) -> int:
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT rowid FROM incidents WHERE id=?', (incident_id,)).fetchone()[0]

    def indexes(self) -> list[str]:
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            return sorted(row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'escalation_%'"))

    def action_status(self, action_id: str) -> str:
        """One action's own status, read by its id — never from a newest-first window."""
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            return db.execute('SELECT status FROM actions WHERE id=?', (action_id,)).fetchone()[0]

    def break_the_index(self, name: str) -> None:
        """Drop one migration-created index, as a restored or hand-edited file would have it missing."""
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute(f'DROP INDEX {name}')
            db.commit()


class AdvancementTests(HistoryFixture):
    """The ladder still climbs, and nothing else in the file can be what decides that."""

    def test_an_unacknowledged_target_still_climbs_one_rung_per_round_when_the_file_is_old(self):
        self.incident()
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=1))['enrolled'], 1)
        self.lifetime(BUSY)                       # 1200 unrelated events, decided actions and intents
        first = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((first['escalated'], first['held'], first['incomplete'], first['refusals']),
                         (1, 0, 0, 0), 'unrelated history is not a reason to hold')
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1'])
        self.assertFalse(first['capped'], 'unrelated lifetime history is not a read limit')
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=6))['escalated'], 0,
                         'a round files one rung, however many are overdue')
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=16))['escalated'], 1)
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1', BASE_RULE + '.stage2'])
        self.assertEqual(self.attempts(), 0, 'escalation enqueues; it never claims a delivery')

    def test_a_tracked_target_stays_tracked_while_unrelated_incidents_pile_up(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        self.noise(OLD + 50)                      # far more open incidents than the old window could hold
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(summary['escalated'], 1)
        self.assertEqual(summary['closed'], 0, 'aging out of a window is not a resolution')
        self.assertEqual(self.audits('escalation.closed'), [])
        self.assertEqual(list(self.tracked()), [target])
        self.assertEqual(self.tracked()[target]['stage'], 1)
        self.assertEqual(self.attempts(), 0)

    def test_an_incident_aged_out_of_the_newest_window_is_still_judged_by_its_own_row(self):
        """The exact defect: hundreds of incidents opened after the target, and it keeps climbing."""
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        self.noise(150)
        self.round(NOW + dt.timedelta(minutes=5))
        self.noise(150, at=NOW + dt.timedelta(minutes=6), first=151)
        later = self.round(NOW + dt.timedelta(minutes=16))
        self.assertEqual(later['escalated'], 1)
        self.assertEqual(self.tracked()[target]['stage'], 2)
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1', BASE_RULE + '.stage2'])

    def test_a_resolution_read_from_the_incident_row_is_the_only_thing_that_closes_a_ladder(self):
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        self.noise(OLD + 50)
        self.resolve(at=NOW + dt.timedelta(minutes=2))
        summary = self.round(NOW + dt.timedelta(minutes=3))
        self.assertEqual(summary['closed'], 1)
        self.assertEqual(self.tracked(), {})
        rows = self.audits('escalation.closed')
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['detail'])['chain'], 'on-call')

    def test_the_ladder_never_tracks_more_than_its_bound_and_says_what_it_left_behind(self):
        incidents = self.laddered(escalation.MAX_TRACKED + 6)
        summary = self.round(NOW + dt.timedelta(minutes=1))
        self.assertEqual(summary['enrolled'], escalation.MAX_TRACKED)
        self.assertEqual(summary['capacity'], 6, 'the incidents behind the bound are reported, not lost')
        self.assertTrue(summary['capped'])
        self.assertEqual(len(self.tracked()), escalation.MAX_TRACKED)
        self.assertEqual(self.attempts(), 0)
        # The bound must not silently advance the walk past the work it could not take.
        self.assertEqual(self.document()['scan_after'], self.rowid(incidents[escalation.MAX_TRACKED - 1]))
        self.assertNotIn(incidents[escalation.MAX_TRACKED], self.tracked())
        for item in range(6):
            self.resolve(BASE_RULE, str(item + 1), at=NOW + dt.timedelta(minutes=2))
        following = self.round(NOW + dt.timedelta(minutes=3))
        self.assertEqual((following['closed'], following['enrolled'], following['capacity']), (6, 6, 0),
                         'the freed capacity is filled by the incidents that were waiting, in order')
        self.assertIn(incidents[escalation.MAX_TRACKED], self.tracked())
        self.assertEqual(self.document()['scan_after'], 0, 'the walk reached the end of the table and began '
                                                          'again, so nothing behind it is stranded')


class DiscoveryTests(HistoryFixture):
    """The rowid walk: bounded per round, fair over rounds, durable across processes."""

    def test_discovery_crosses_more_irrelevant_open_incidents_than_one_page_holds(self):
        self.noise(OLD + 50)
        target = self.incident()
        first = self.round(NOW + dt.timedelta(minutes=1))
        self.assertEqual(first['enrolled'], 0, 'one bounded page per round is the round cost')
        self.assertEqual(first['result'], 'idle')
        self.assertTrue(first['capped'], 'the discovery page limit is diagnostic')
        self.assertEqual(self.tracked(), {}, 'and no incident is tracked from a page it was not on')
        self.assertGreater(self.document()['scan_after'], 0, 'the position is durable even when nothing '
                                                             'else happened')
        second = self.round(NOW + dt.timedelta(minutes=2))
        self.assertEqual(second['enrolled'], 1)
        self.assertEqual(list(self.tracked()), [target])
        self.assertEqual(second['escalated'], 0, 'the rung is not due yet')
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=5))['escalated'], 1)

    def test_a_restart_resumes_the_walk_where_the_other_process_left_it(self):
        self.noise(OLD + 50)
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        position = self.document()['scan_after']
        self.store = Store(self.path, LIVE)                     # a new process over the same file
        self.chains = escalation.config(self.config)['chains']
        summary = self.round(NOW + dt.timedelta(minutes=2))
        self.assertEqual(summary['enrolled'], 1, 'the walk resumed instead of restarting behind the noise')
        self.assertEqual(list(self.tracked()), [target])
        self.assertGreater(position, 0)

    def test_the_reads_never_create_an_index_to_fall_back_on(self):
        """`INDEXED BY` is a refusal, so a runtime `CREATE INDEX` would be the fallback this forbids."""
        before = self.indexes()
        self.assertEqual(before, sorted([state.ESCALATION_INCIDENTS_INDEX, state.ESCALATION_ACTIONS_INDEX,
                                        state.ESCALATION_AUDIT_INDEX]))
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        self.round(NOW + dt.timedelta(minutes=5))
        self.round(NOW + dt.timedelta(minutes=16))
        self.assertEqual(self.indexes(), before)


class AcknowledgementTests(HistoryFixture):
    """A human's answer is durable, and so is the read that has to find it."""

    def test_a_decision_taken_before_the_file_filled_up_still_stops_the_ladder(self):
        target = self.incident()
        self.decided(target)
        self.lifetime(BUSY)
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['acked'], summary['escalated']), (1, 0))
        self.assertEqual(self.stages(), [])
        rows = self.audits('escalation.acknowledged')
        self.assertEqual(len(rows), 1, 'said once, not once per round')
        self.assertEqual(json.loads(rows[0]['detail'])['evidence'], escalation.ACK_DECISION)
        self.assertEqual(len(self.store.records('actions', 100)), 100,
                         'the newest-first window this used to decide from is full of somebody else')
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=60))['escalated'], 0)

    def test_an_approval_intent_taken_before_the_file_filled_up_still_stops_the_ladder(self):
        target = self.incident()
        proposed = self.intent(target)
        self.lifetime(BUSY)
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['acked'], summary['escalated']), (1, 0))
        self.assertEqual(self.stages(), [])
        self.assertEqual(json.loads(self.audits('escalation.acknowledged')[0]['detail'])['evidence'],
                         escalation.ACK_INTENT)
        self.assertEqual(self.action_status(proposed['action_id']), 'pending',
                         'an intent is not a decision, and it is still an acknowledgement')

    def test_a_pending_proposal_is_not_an_acknowledgement_however_the_window_looks(self):
        target = self.incident()
        self.propose(target)
        self.lifetime(BUSY)
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=5))['escalated'], 1)
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1'])

    def test_an_expired_action_is_not_an_acknowledgement(self):
        target = self.incident()
        self.propose(target)
        self.lifetime(BUSY)
        self.store.expire_actions(now=NOW + dt.timedelta(hours=2))
        summary = self.round(NOW + dt.timedelta(hours=3))
        self.assertEqual(summary['escalated'], 1, 'an action nobody decided is not somebody answering')
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1'])

    def test_another_incidents_decision_does_not_acknowledge_this_one(self):
        """The noise is decided actions on a different incident: the read is per incident, not per platform."""
        self.incident()
        self.lifetime(BUSY)
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=5))['escalated'], 1)
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=5))['acked'], 0)

    def test_a_malformed_action_payload_is_not_evidence_and_does_not_break_the_read(self):
        """The `CASE WHEN json_valid(payload)` guard, from the reader's side.

        The row exists, is `approved`, and belongs to this incident — and it proves nothing, because its
        payload cannot be read. The ladder keeps climbing and the round reports no ack rather than guessing
        at an incident id it could not parse.
        """
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute('INSERT INTO actions(id,requester,retry_key,fingerprint,payload,status,created_at,'
                       'expires_at,decided_by) VALUES (?,?,?,?,?,?,?,?,?)',
                       (str(uuid.uuid4()), PROPOSER.identity, 'broken', digest([1]),
                        'not json at all', 'approved', utc_text(NOW), utc_text(NOW + dt.timedelta(hours=1)),
                        HUMAN.identity))
            db.commit()
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['acked'], summary['escalated'], summary['incomplete']), (0, 1, 0))
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1'])


class HeldWorkTests(HistoryFixture):
    """What a round may not conclude from not having been able to look."""

    def test_new_incident_with_incomplete_ack_is_held_while_another_advances(self):
        busy = self.incident(BASE_RULE, '1')
        quiet = self.incident(BASE_RULE, '2')
        self.own_history(busy, 800)
        with mock.patch.object(escalation_reader, 'PROGRESS_INSTRUCTIONS', 2_000):
            summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['enrolled'], summary['held'], summary['escalated']), (2, 1, 1))
        self.assertEqual(summary['incomplete_incidents'], [busy])
        self.assertTrue(summary['capped'])
        self.assertEqual(self.tracked()[busy]['stage'], 0)
        self.assertEqual(self.tracked()[quiet]['stage'], 1)
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1'])
        # The interrupted read hid real approval intents. A complete retry finds them.
        retry = self.round(NOW + dt.timedelta(minutes=6))
        self.assertEqual((retry['acked'], retry['escalated']), (1, 0))
        self.assertEqual(self.tracked()[busy]['status'], 'acked')

    def test_new_incident_with_missing_ack_index_cannot_file_a_stage(self):
        target = self.incident()
        self.break_the_index(state.ESCALATION_ACTIONS_INDEX)
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['enrolled'], summary['held'], summary['escalated']), (1, 1, 0))
        self.assertEqual(summary['incomplete_incidents'], [target])
        self.assertEqual(self.tracked()[target]['stage'], 0)
        self.assertEqual(self.stages(), [])

    def test_missing_new_ack_result_does_not_mean_no_acknowledgement(self):
        target = self.incident(BASE_RULE, '1')
        healthy = self.incident(BASE_RULE, '2')
        read_ack = escalation_reader.EscalationReader.read_ack

        def omit_one(reader, incident_ids):
            result = read_ack(reader, incident_ids)
            result.pop(target)
            return result

        with mock.patch.object(escalation_reader.EscalationReader, 'read_ack', omit_one):
            summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['held'], summary['escalated']), (1, 1))
        self.assertEqual(summary['incomplete_incidents'], [target])
        self.assertEqual(self.tracked()[target]['stage'], 0)
        self.assertEqual(self.tracked()[healthy]['stage'], 1)

    def test_malformed_typed_verdict_holds_only_its_incident(self):
        target = self.incident(BASE_RULE, '1')
        healthy = self.incident(BASE_RULE, '2')
        self.round(NOW + dt.timedelta(minutes=1))
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT last_event_id FROM incidents WHERE id=?', (target,)).fetchone()
            payload = json.loads(db.execute('SELECT payload FROM events WHERE id=?', row).fetchone()[0])
            payload['kind'] = ['availability']
            db.execute('UPDATE events SET payload=? WHERE id=?', (canonical(payload), row[0]))
            db.commit()
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['held'], summary['escalated'], summary['closed']), (1, 1, 0))
        self.assertEqual(self.tracked()[target]['stage'], 0)
        self.assertEqual(self.tracked()[healthy]['stage'], 1)

    def test_a_tracked_incident_whose_verdict_row_is_gone_is_held_and_never_closed(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute('DELETE FROM events WHERE id=(SELECT last_event_id FROM incidents WHERE id=?)',
                       (target,))
            db.commit()
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['escalated'], summary['closed']), (0, 0))
        self.assertEqual((summary['held'], summary['unknown'], summary['incomplete']), (1, 1, 0))
        self.assertEqual(summary['result'], 'held')
        self.assertEqual(self.tracked()[target]['stage'], 0)
        self.assertEqual(self.audits('escalation.closed'), [])
        self.assertEqual(self.stages(), [])

    def test_a_tracked_incident_whose_verdict_payload_is_malformed_is_held(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE events SET payload=? WHERE id=(SELECT last_event_id FROM incidents WHERE id=?)',
                       ('{"rule_id": "gatus.result"}', target))
            db.commit()
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['held'], summary['closed'], summary['escalated']), (1, 0, 0))
        self.assertIn(target, self.tracked())

    def test_a_tracked_incident_whose_row_is_gone_is_held_rather_than_closed(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            db.execute('DELETE FROM incidents WHERE id=?', (target,))
            db.commit()
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['held'], summary['unknown'], summary['closed']), (1, 1, 0))
        self.assertEqual(self.audits('escalation.closed'), [], 'absent evidence may not turn a pager off')
        self.assertIn(target, self.tracked())

    def test_a_missing_index_holds_the_incidents_that_needed_it_and_files_no_stage(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        self.break_the_index(state.ESCALATION_ACTIONS_INDEX)
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(summary['escalated'], 0)
        self.assertEqual(self.stages(), [], 'a read that was refused may not reach a human')
        self.assertEqual(summary['incomplete_incidents'], [target])
        self.assertEqual((summary['incomplete'], summary['closed'], summary['held']), (1, 0, 1))
        self.assertEqual(summary['result'], 'held')
        self.assertEqual(self.tracked()[target]['stage'], 0)
        self.assertEqual(self.attempts(), 0)

    def test_a_missing_discovery_index_stops_the_walk_and_leaves_the_position_alone(self):
        target = self.incident()
        self.noise(5)
        self.round(NOW + dt.timedelta(minutes=1))                # the cursor exists; the walk already wrapped
        self.break_the_index(state.ESCALATION_INCIDENTS_INDEX)
        summary = self.round(NOW + dt.timedelta(minutes=2))
        self.assertEqual(summary['enrolled'], 0, 'nothing on the page could be looked at')
        self.assertEqual(summary['refusals'], 1)
        self.assertEqual(summary['result'], 'held')
        self.assertEqual(self.document()['scan_after'], 0, 'a page that never ran is not a page examined')
        self.assertEqual(self.tracked()[target]['stage'], 0)
        self.assertEqual(self.store.status()['incidents'], {'open': 6})

    def test_an_unreadable_database_refuses_the_round_and_writes_nothing(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        cursor_before = self.cursor.read_bytes()
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        os.replace(self.path, self.path.with_name('absent.db'))
        summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual((summary['result'], summary['refusals'], summary['escalated']), ('refused', 1, 0))
        self.assertEqual(summary['incomplete_incidents'], [])
        self.assertEqual(summary['scan_after'], self.document()['scan_after'])
        self.assertEqual(summary['tracked'], len(self.tracked()))
        self.assertEqual(self.cursor.read_bytes(), cursor_before,
                         'a round that could not read decides nothing, and writes nothing')
        self.assertTrue(target)

    def test_one_incidents_oversized_history_is_that_ones_problem_alone(self):
        """The per-incident budget, and the reason it is per incident.

        `busy` owns 800 actions; `quiet` owns none. With the budget pulled down to a fraction of what an
        ordinary read costs, `busy` is reported incomplete by name and held, and `quiet` still files the rung
        it is owed: a single unbounded history may stop its own escalation and nobody else's.
        """
        busy = self.incident(BASE_RULE, '1')
        quiet = self.incident(BASE_RULE, '2')
        self.round(NOW + dt.timedelta(minutes=1))
        self.own_history(busy, 800)
        with mock.patch.object(escalation_reader, 'PROGRESS_INSTRUCTIONS', 2_000):
            summary = self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(summary['incomplete_incidents'], [busy])
        self.assertEqual((summary['incomplete'], summary['held'], summary['escalated']), (1, 1, 1))
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1'])
        self.assertEqual(self.tracked()[busy]['stage'], 0)
        self.assertEqual(self.tracked()[quiet]['stage'], 1)


class ReadShapeTests(HistoryFixture):
    """The two claims the whole design rests on: the indexes are used, and unrelated rows are free."""

    def reader(self) -> escalation_reader.EscalationReader:
        return escalation_reader.EscalationReader(self.path, ack_statuses=escalation.ACK_STATUSES)

    def test_discovery_refuses_positions_that_sqlite_cannot_bind(self):
        with self.reader() as reader:
            for position in (-1, True, '0', 1.5, 2 ** 63):
                with self.subTest(position=position), self.assertRaises(StateError):
                    reader.discover(position)
            self.assertTrue(reader.discover(2 ** 63 - 1).exhausted)

    def measure(self) -> tuple[int, int]:
        """Cost of one discovery page and one tracked read, in VM instructions the handler accounted.

        The page is deliberately a *full* one by the time history has been added: its cost may be a
        function of the fixed page, and not of how many rows the tables have accumulated.
        """
        with self.reader() as reader:
            page = reader.discover(0)
            incident = reader.read_incidents([self.target])[self.target]
            self.assertEqual(incident.status, escalation_reader.OPEN)
            return page.steps, incident.steps

    def test_the_reads_use_the_indexes_the_migration_creates(self):
        self.target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        self.lifetime(BUSY)
        with self.reader() as reader:
            plans = reader.plans()
        for name in ('discover', 'incident', 'decision', 'intent'):
            self.assertTrue(plans[name], f'{name} answered no plan')
            text = ' '.join(plans[name])
            scans = [step for step in plans[name] if step.startswith('SCAN ')
                     and step != 'SCAN CONSTANT ROW']
            self.assertEqual(scans, [], f'{name} scans stored rows: {text}')
        self.assertIn(state.ESCALATION_INCIDENTS_INDEX, ' '.join(plans['discover']))
        self.assertNotIn('TEMP B-TREE', ' '.join(plans['discover']),
                         'the walk must seek to the next rowid, not sort the open incidents it skipped')
        self.assertIn('id=?', ' '.join(plans['incident']))
        self.assertIn(state.ESCALATION_ACTIONS_INDEX, ' '.join(plans['decision']))
        self.assertIn(state.ESCALATION_ACTIONS_INDEX, ' '.join(plans['intent']))
        self.assertIn(state.ESCALATION_AUDIT_INDEX, ' '.join(plans['intent']))

    def test_unrelated_history_cost_nothing_per_incident_read(self):
        self.target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        discovery_few, incident_few = self.measure()
        self.lifetime(BUSY)
        self.noise(120)                       # the second page is a full one, over a far larger file
        discovery_many, incident_many = self.measure()
        self.assertLess(incident_many, escalation_reader.PROGRESS_INSTRUCTIONS // 4,
                        'a per-incident read must not come close to its budget because of other people')
        self.assertLess(discovery_many, escalation_reader.PROGRESS_INSTRUCTIONS,
                        'one bounded page must fit inside the budget a single incident is given')
        self.assertLessEqual(incident_many, incident_few + 500,
                             'the cost tracks the incident, not the lifetime of the platform')
        self.assertLessEqual(discovery_many, discovery_few + 20_000)


class CursorMigrationTests(HistoryFixture):
    """v1 wrote stages and no position; that history is the reason the position is trusted."""

    def v1(self, document: dict) -> dict:
        return {'schema_version': 1, 'source': document['source'], 'binding': document['binding'],
                'incidents': document['incidents']}

    def test_cursor_version_and_fields_must_describe_the_same_schema(self):
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        document = self.document()
        malformed = [{**self.v1(document), 'schema_version': 2},
                     {**document, 'schema_version': 1}]
        malformed.extend({**document, 'schema_version': version} for version in (True, False, 2.0, '2'))
        for broken in malformed:
            with self.subTest(document=broken):
                self.cursor.write_text(json.dumps(broken), encoding='utf-8')
                with self.assertRaises(StateError):
                    self.round(NOW + dt.timedelta(minutes=5))
                self.assertEqual(self.document(), broken)
        self.assertEqual(self.stages(), [])

    def test_cursor_entry_requires_complete_fields_and_integer_stage(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        document = self.document()
        entry = document['incidents'][target]
        malformed = [{key: value for key, value in entry.items() if key != missing}
                     for missing in ('chain', 'status', 'suppressed')]
        malformed.extend({**entry, 'stage': stage} for stage in (True, 1.0, []))
        malformed.extend({**entry, field: value} for field, value in (
            ('chain', []), ('condition', {}), ('resource_id', 'not-a-uuid'),
            ('opened_at', []), ('status', None), ('suppressed', True), ('suppressed', 999)))
        for broken in malformed:
            with self.subTest(entry=broken):
                payload = {**document, 'incidents': {target: broken}}
                self.cursor.write_text(json.dumps(payload), encoding='utf-8')
                with self.assertRaises(StateError):
                    self.round(NOW + dt.timedelta(minutes=5))
                self.assertEqual(self.document(), payload)
        self.assertEqual(self.stages(), [])

    def test_oversized_unparseable_and_deep_cursors_refuse_without_mutation(self):
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        malformed = (b' ' * (escalation.MAX_CURSOR_BYTES + 1), b'\xff', b'{',
                     b'[' * 2000 + b'0' + b']' * 2000)
        for raw in malformed:
            with self.subTest(size=len(raw)):
                self.cursor.write_bytes(raw)
                with self.assertRaises(StateError):
                    self.round(NOW + dt.timedelta(minutes=5))
                self.assertEqual(self.cursor.read_bytes(), raw)
        self.assertEqual(self.stages(), [])

    def test_a_v1_cursor_keeps_its_stages_and_binding_and_is_not_repaged(self):
        target = self.incident()
        self.round(NOW + dt.timedelta(minutes=5))                # rung 1 filed by the v1-era build
        self.cursor.write_text(json.dumps(self.v1(self.document())), encoding='utf-8')
        loaded = escalation.load_cursor(self.cursor, source=SOURCE, chains=self.chains)
        self.assertEqual((loaded['schema_version'], loaded['scan_after'], loaded['migrated']), (2, 0, True))
        self.assertEqual(loaded['incidents'], {target: {'chain': 'on-call', 'stage': 1,
                                                       'status': 'escalating', 'condition': BASE_RULE,
                                                       'resource_id': self.host, 'opened_at': utc_text(NOW),
                                                       'suppressed': None}})
        self.assertEqual(loaded['binding'], escalation.binding(self.chains))
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=6))['escalated'], 0,
                         'the rung the other build filed is not filed twice')
        self.assertEqual(self.round(NOW + dt.timedelta(minutes=16))['escalated'], 1)
        saved = self.document()
        self.assertEqual((saved['schema_version'], saved['incidents'][target]['stage']), (2, 2))
        self.assertEqual(saved['binding'], escalation.binding(self.chains))
        self.assertEqual(self.stages(), [BASE_RULE + '.stage1', BASE_RULE + '.stage2'])

    def test_a_v1_cursor_is_refused_for_another_producer_or_chain_set(self):
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        document = self.v1(self.document())
        for broken in ({**document, 'source': 'lo-somebody-else'},
                       {**document, 'binding': escalation.binding([])},
                       {**document, 'scan_after': 0}):
            with self.subTest(keys=sorted(broken)):
                self.cursor.write_text(json.dumps(broken), encoding='utf-8')
                with self.assertRaises(StateError):
                    escalation.load_cursor(self.cursor, source=SOURCE, chains=self.chains)

    def test_a_position_that_is_not_a_rowid_is_refused_rather_than_guessed(self):
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        for broken in (-1, '12', True, 1.5, 2 ** 63):
            with self.subTest(position=broken):
                document = {**self.document(), 'scan_after': broken}
                self.cursor.write_text(json.dumps(document), encoding='utf-8')
                with self.assertRaises(StateError):
                    escalation.load_cursor(self.cursor, source=SOURCE, chains=self.chains)

    def test_a_cursor_that_cannot_be_trusted_refuses_the_round_and_writes_nothing(self):
        """`load_cursor` refuses before the file is opened for reading, so nothing is judged at all."""
        self.incident()
        self.round(NOW + dt.timedelta(minutes=1))
        broken = {**self.document(), 'incidents': {'not-an-uuid': {}}}
        self.cursor.write_text(json.dumps(broken), encoding='utf-8')
        with self.assertRaises(StateError):
            self.round(NOW + dt.timedelta(minutes=5))
        self.assertEqual(self.stages(), [], 'a refused round filed no rung')
        self.assertEqual(self.document(), broken, 'and left its own cursor exactly as it was')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})


class IndexMigrationTests(HistoryFixture):
    """The index step, evaluated as the release that shipped it: schema 6 is this build's top step."""

    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(state, 'MIGRATIONS',
                                             {step: state.MIGRATIONS[step] for step in range(1, 7)}))
        stack.enter_context(mock.patch.object(state, 'VERSION', 6))
        super().setUp()

    def test_explicit_index_step_preserves_rows_and_records_exactly_one_migration(self):
        target = next(version for version, script in state.MIGRATIONS.items()
                      if script == state.ESCALATION_INDEX_SCHEMA)
        incident = self.incident()
        self.decided(incident)
        names = (state.ESCALATION_INCIDENTS_INDEX, state.ESCALATION_ACTIONS_INDEX,
                 state.ESCALATION_AUDIT_INDEX)
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            for name in names:
                db.execute(f'DROP INDEX {name}')
            db.execute(f'PRAGMA user_version={target - 1}')
            db.commit()
            tables = [row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            before = {table: db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                      for table in tables}
        with self.assertRaises(StateError):
            Store(self.path, LIVE)
        self.assertEqual(self.indexes(), [])
        Store(self.path, LIVE, migrate=True)
        self.assertEqual(self.indexes(), sorted(names))
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], target)
            for table in tables:
                after = db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                if table == 'audit':
                    self.assertEqual(after[:-1], before[table])
                    self.assertEqual(len(after), len(before[table]) + 1)
                else:
                    self.assertEqual(after, before[table], table)
            migration = db.execute(
                "SELECT actor,subject,detail FROM audit WHERE operation='schema.migrated'"
            ).fetchall()
        self.assertEqual(len(migration), 1)
        self.assertEqual(migration[0][:2], ('platform-migrate', str(target)))
        self.assertEqual(json.loads(migration[0][2]),
                         {'from': target - 1, 'to': target,
                          'script_sha256': digest(state.ESCALATION_INDEX_SCHEMA)})
        Store(self.path, LIVE, migrate=True)
        self.assertEqual(len(self.audits('schema.migrated')), 1)


if __name__ == '__main__':
    unittest.main()

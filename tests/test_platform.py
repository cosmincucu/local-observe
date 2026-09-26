import asyncio
import copy
from contextlib import closing
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import detections
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
PRODUCER = Actor('test-detector', 'producer')
HUMAN = Actor('operator', 'human')
AGENT = Actor('agent-1', 'proposer')
RUNNER = Actor('runner-1', 'executor')


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})

    def event(self, status='firing', minute=0):
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        return detections.event(PRODUCER.identity, self.host, 'availability', 'availability', status,
                                window, {'sample_id': 'fixture'}, query_type='gatus-result')

    def intake(self, event=None, now=None):
        return self.store.intake(event or self.event(), PRODUCER, now=now or NOW)

    def action(self):
        result = self.intake()
        request = {'retry_key': 'once', 'incident_id': result['incident_id'], 'action': 'inspect', 'version': '1',
                   'targets': [self.host], 'parameters': {}, 'evidence': [result['event_id']],
                   'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        return self.store.propose_action(request, AGENT, self.policy, now=NOW), request

    def approved(self):
        action, _ = self.action()
        self.store.decide(action['action_id'], 'approved', HUMAN, now=NOW)
        return action['action_id']

    def test_atomic_event_incident_outbox_and_retry(self):
        first = self.intake()
        self.assertEqual(self.intake()['status'], 'duplicate')
        self.assertEqual(len(self.store.records('events')), 1)
        self.assertEqual(self.store.status()['notifications'], {'pending': 1})
        altered = self.event()
        altered['severity'] = 'critical'
        with self.assertRaises(StateError):
            self.intake(altered)
        self.assertEqual(self.store.records('incidents')[0]['id'], first['incident_id'])

    def test_restart_preserves_state(self):
        self.intake()
        restarted = Store(self.root / 'state.db')
        self.assertEqual(restarted.status(), self.store.status())

    def test_failure_recovery_and_recurrence(self):
        first = self.intake()
        recovery = self.intake(self.event('resolved', 1), NOW + dt.timedelta(minutes=1))
        self.assertEqual(first['incident_id'], recovery['incident_id'])
        again = self.intake(self.event('firing', 2), NOW + dt.timedelta(minutes=2))
        self.assertNotEqual(first['incident_id'], again['incident_id'])
        self.assertEqual(self.store.status()['incidents'], {'open': 1, 'resolved': 1})

    def test_late_recovery_and_unknown_do_not_close(self):
        self.intake(self.event('firing', 1), NOW + dt.timedelta(minutes=1))
        self.intake(self.event('resolved'), NOW + dt.timedelta(minutes=1))
        self.intake(self.event('unknown', 2), NOW + dt.timedelta(minutes=2))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_watermark_conflict_rejected(self):
        self.intake()
        event = self.event('resolved')
        event['source_event_id'] = 'different'
        with self.assertRaises(StateError):
            self.intake(event)
        self.assertEqual(len(self.store.records('events')), 1)

    def test_identity_and_invalid_evidence_refused(self):
        with self.assertRaises(StateError):
            self.store.intake(self.event(), Actor('impostor', 'producer'), now=NOW)
        bad = self.event()
        bad['evidence'][0]['parameters'] = {'sql': 'select something'}
        with self.assertRaises(StateError):
            self.intake(bad)

    def test_future_event_refused(self):
        with self.assertRaises(StateError):
            self.intake(self.event('firing', 3))

    def test_outbox_lease_ordering_and_stale_ack(self):
        self.intake()
        self.intake(self.event('resolved', 1), NOW + dt.timedelta(minutes=1))
        first = self.store.claim_notification(now=NOW)
        self.assertIsNone(self.store.claim_notification(now=NOW + dt.timedelta(seconds=1)))
        replacement = self.store.claim_notification(now=NOW + dt.timedelta(seconds=31))
        self.assertEqual(first['id'], replacement['id'])
        with self.assertRaises(StateError):
            self.store.finish_notification(first['id'], first['claim_token'], True, now=NOW + dt.timedelta(seconds=32))
        self.store.finish_notification(replacement['id'], replacement['claim_token'], True, now=NOW + dt.timedelta(seconds=32))
        self.assertEqual(self.store.claim_notification(now=NOW + dt.timedelta(minutes=1))['payload']['transition'], 'resolved')

    def test_outbox_failures_bounded(self):
        self.intake()
        for attempt in range(5):
            now = NOW + dt.timedelta(minutes=attempt)
            item = self.store.claim_notification(now=now)
            self.store.finish_notification(item['id'], item['claim_token'], False, now=now)
        self.assertEqual(self.store.status()['notifications'], {'dead': 1})
        self.assertIsNone(self.store.claim_notification(now=NOW + dt.timedelta(days=1)))

    def test_delivery_requires_matching_receipt(self):
        self.intake()
        class Receiver:
            def request(self, *args, **kwargs):
                return 202, {'accepted': True, 'delivery_id': 'wrong'}
        # A receipt is only worth checking against a route that has a human channel to check it on:
        # the delivery default is `recording` (ledger test tooling), which answers from the local sink.
        store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode='live'))
        self.assertEqual(deliver_one(store, Receiver(), now=NOW)['status'], 'pending')

    def test_successful_delivery(self):
        self.intake()
        class Receiver:
            def request(self, *args, **kwargs):
                return 202, {'accepted': True, 'delivery_id': kwargs['payload']['delivery_id']}
        store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode='live'))
        self.assertEqual(deliver_one(store, Receiver(), now=NOW)['status'], 'sent')

    def test_action_retry_and_change_refused(self):
        action, request = self.action()
        self.assertEqual(self.store.propose_action(request, AGENT, self.policy, now=NOW), action)
        request['expires_at'] = utc_text(NOW + dt.timedelta(hours=2))
        with self.assertRaises(StateError):
            self.store.propose_action(request, AGENT, self.policy, now=NOW)

    def test_agent_cannot_approve_and_callback_once(self):
        action, _ = self.action()
        for actor in (AGENT, RUNNER, Actor('reader', 'reader')):
            with self.assertRaises(StateError):
                self.store.decide(action['action_id'], 'approved', actor, now=NOW)
        self.store.decide(action['action_id'], 'denied', HUMAN, now=NOW)
        with self.assertRaises(StateError):
            self.store.decide(action['action_id'], 'approved', HUMAN, now=NOW)

    def test_expired_approval_never_dispatches(self):
        action, _ = self.action()
        self.assertEqual(self.store.decide(action['action_id'], 'approved', HUMAN, now=NOW + dt.timedelta(hours=2))['status'], 'expired')
        with self.assertRaises(StateError):
            self.store.claim_action(action['action_id'], RUNNER, self.policy, now=NOW)

    def test_approved_action_expires_before_claim(self):
        action = self.approved()
        self.assertEqual(self.store.claim_action(action, RUNNER, self.policy, now=NOW + dt.timedelta(hours=2)), {'status': 'expired'})

    def test_claim_only_once_and_interruption_unknown(self):
        action = self.approved()
        execution = self.store.claim_action(action, RUNNER, self.policy, now=NOW)
        with self.assertRaises(StateError):
            self.store.claim_action(action, RUNNER, self.policy, now=NOW)
        self.assertEqual(self.store.recover_executions(now=NOW), 1)
        with self.assertRaises(StateError):
            self.store.claim_action(action, RUNNER, self.policy, now=NOW)
        self.store.execution_outcome(execution['execution_id'], 'succeeded', HUMAN, now=NOW)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_runner_identity_and_token(self):
        execution = self.store.claim_action(self.approved(), RUNNER, self.policy, now=NOW)
        with self.assertRaises(StateError):
            self.store.execution_outcome(execution['execution_id'], 'succeeded', RUNNER, 'wrong', now=NOW)
        self.store.execution_outcome(execution['execution_id'], 'succeeded', RUNNER, execution['runner_token'], now=NOW)
        self.assertEqual(self.store.status()['actions'], {'succeeded': 1})

    def test_opt_in_rechecked_at_claim(self):
        action = self.approved()
        self.declared['resources'][0]['attributes']['remediation_enabled'] = False
        index.build(self.declared, self.index, 'changed', now=NOW)
        with self.assertRaises(StateError):
            self.store.claim_action(action, RUNNER, self.policy, now=NOW)

    def test_recovered_incident_blocks_dispatch(self):
        action = self.approved()
        self.intake(self.event('resolved', 1), NOW + dt.timedelta(minutes=1))
        with self.assertRaises(StateError):
            self.store.claim_action(action, RUNNER, self.policy, now=NOW + dt.timedelta(minutes=1))

    def test_backup_and_unrelated_database(self):
        self.action()
        self.store.backup(self.root / 'backup.db')
        self.assertEqual(Store(self.root / 'backup.db').status(), self.store.status())
        with self.assertRaises(StateError):
            Store(self.index)
        with self.assertRaises(FileExistsError):
            self.store.backup(self.index)

    def test_audit_append_only(self):
        self.intake()
        with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
            connection.execute('DELETE FROM audit')

    def test_detection_absence_and_threshold(self):
        rule = {'id': 'cpu', 'kind': 'threshold', 'resource_id': self.host, 'source': PRODUCER.identity, 'threshold': 90}
        sample = {'sample_id': 'sample-1', 'observed_at': utc_text(NOW), 'ok': True, 'value': 95}
        values = detections.evaluate(self.index, rule, sample, now=NOW)
        self.assertEqual([item['status'] for item in values], ['resolved', 'firing'])
        self.assertEqual(len(detections.evaluate(self.index, rule, None, now=NOW)), 1)
        sample['observed_at'] = utc_text(NOW - dt.timedelta(hours=1))
        self.assertEqual(detections.evaluate(self.index, rule, sample, now=NOW)[0]['kind'], 'coverage')

    def test_gatus_chooses_latest_completed_sample(self):
        sample = detections.gatus_sample({'results': [
            {'timestamp': utc_text(NOW), 'success': False},
            {'timestamp': utc_text(NOW + dt.timedelta(minutes=1)), 'success': True}]}, before=NOW)
        self.assertFalse(sample['value'])

    def test_api_auth_and_actor_spoof(self):
        async def exercise():
            import httpx
            token = 'dedicated-reader-token-for-tests'
            app = create_app(self.store, [{'token': token, 'role': 'reader', 'identity': 'reader'}], self.policy)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
                self.assertEqual((await client.get('/v1/status')).status_code, 401)
                headers = {'Authorization': 'Bearer ' + token}
                self.assertEqual((await client.get('/v1/status', headers=headers)).status_code, 200)
                self.assertEqual((await client.post('/v1/actions/decision', headers=headers,
                    json={'action_id': 'anything', 'decision': 'approved', 'role': 'human'})).status_code, 404)
                self.assertEqual((await client.post('/v1/events', headers=headers, json=self.event())).status_code, 400)
        asyncio.run(exercise())

    def test_evidence_retry_expiry_and_no_credentials(self):
        sample = {'sample_id': 'minimal', 'observed_at': utc_text(NOW), 'ok': True, 'value': False}
        first = self.store.put_evidence(sample, PRODUCER, now=NOW)
        self.assertEqual(first, self.store.put_evidence(sample, PRODUCER, now=NOW))
        self.assertEqual(self.store.get_evidence(PRODUCER.identity, 'minimal', now=NOW)['status'], 'available')
        self.assertEqual(self.store.get_evidence(PRODUCER.identity, 'minimal', now=NOW + dt.timedelta(days=16))['status'], 'expired')
        sample['value'] = 'password'
        with self.assertRaises(StateError):
            self.store.put_evidence(sample, PRODUCER, now=NOW)

    def test_expiry_sweep_does_not_expire_executing(self):
        action = self.approved()
        self.store.claim_action(action, RUNNER, self.policy, now=NOW)
        self.assertEqual(self.store.expire_actions(now=NOW + dt.timedelta(days=2)), 0)
        self.assertEqual(self.store.status()['actions'], {'executing': 1})

    def test_second_service_owner_refused(self):
        from local_observe.platform.owner import exclusive_owner
        with exclusive_owner(self.store.path):
            with self.assertRaises(OSError), exclusive_owner(self.store.path):
                pass

    def test_detection_pending_batch_survives_partial_send(self):
        from local_observe.platform.detection_worker import tick
        from local_observe.http import TransportError
        rule = {'id': 'http', 'kind': 'availability', 'resource_id': self.host, 'source': PRODUCER.identity}
        class Gatus:
            def request(self, *args):
                return 200, {'results': [{'timestamp': utc_text(NOW), 'success': False}]}
        outer = self
        class Intake:
            fail = True
            def request(self, method, path, payload):
                if path == '/v1/evidence':
                    return 200, {'evidence_id': outer.store.put_evidence(payload, PRODUCER, now=NOW)}
                result = outer.store.intake(payload, PRODUCER, now=NOW)
                if self.fail and payload['kind'] == 'availability':
                    raise TransportError('lost ack')
                return 200, result
        intake = Intake()
        cursor = self.root / 'cursor.json'
        with self.assertRaises(TransportError):
            tick(self.index, rule, cursor, Gatus(), intake, now=NOW)
        intake.fail = False
        self.assertEqual(tick(self.index, rule, cursor, Gatus(), intake, now=NOW), 'delivered')
        self.assertEqual(len(self.store.records('events')), 2)
        self.assertEqual(tick(self.index, rule, cursor, Gatus(), intake, now=NOW - dt.timedelta(minutes=1)), 'idle')

    def test_concurrent_claims_are_single_use(self):
        from concurrent.futures import ThreadPoolExecutor
        action = self.approved()
        def claim():
            try:
                return self.store.claim_action(action, RUNNER, self.policy, now=NOW)['status']
            except StateError:
                return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(lambda _: claim(), range(2))), ['executing', 'refused'])

    def test_manual_delivery_retry_requires_human(self):
        self.intake()
        item = self.store.claim_notification(now=NOW)
        self.store.finish_notification(item['id'], item['claim_token'], False, now=NOW, max_attempts=1)
        with self.assertRaises(StateError):
            self.store.retry_notification(item['id'], AGENT, now=NOW)
        self.assertEqual(self.store.retry_notification(item['id'], HUMAN, now=NOW), {'status': 'pending'})

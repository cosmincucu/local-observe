"""Notification safety: budgets, routing, circuit and test windows.

Every policy here names its `delivery_mode`. The platform default is `recording` (ledger test tooling), so a
policy built without one never reaches a human channel; the tests that exercise the human route say
`delivery_mode='live'` rather than inheriting a default that no longer exists.
"""
import datetime as dt
from pathlib import Path
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-07T09:00:00Z')


class FakeProvider:
    def __init__(self, accepted=True):
        self.calls = []
        self.accepted = accepted

    def request(self, method, *, payload, headers):
        self.calls.append(payload)
        return 202, {'accepted': self.accepted, 'delivery_id': payload['delivery_id']}


class NotificationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'platform.db'
        self.client = FakeProvider()

    def intake(self, store, second, source='real-detector', status=None, restricted=False):
        now = NOW + dt.timedelta(seconds=second)
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        item = event(source, None, 'fixture', 'availability',
                     status or ('firing' if second % 2 == 0 else 'resolved'), window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')
        if restricted:
            item['data_class'] = 'restricted'
        store.intake(item, Actor(source, 'producer'), now=now)
        return now

    def test_534_flaps_record_locally_without_calling_human_provider(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='live'))
        for i in range(534):
            now = self.intake(store, i, 'stage-jobs')
            result = deliver_one(store, self.client, now=now)
            self.assertEqual(result['destination'], 'synthetic-sink')
        self.assertEqual(self.client.calls, [])
        self.assertEqual(store.status()['notifications'], {'sent': 534})
        self.assertFalse(store.notification_safety_status()['circuit_open'])

    def test_human_flap_budget_covers_both_transitions_and_survives_restart(self):
        policy = NotificationPolicy(delivery_mode='live', max_attempts=4)
        for i in range(20):
            store = Store(self.path, policy)
            now = self.intake(store, i)
            result = deliver_one(store, self.client, now=now)
            self.assertEqual(result['status'], 'sent' if i < 4 else 'suppressed')
        self.assertEqual([p['transition'] for p in self.client.calls], ['opened', 'resolved'] * 2)
        self.assertEqual(store.notification_safety_status()['suppressed'], 16)
        self.assertTrue(Store(self.path).notification_safety_status()['circuit_open'])
        # Time alone does not unlatch the circuit.
        now = self.intake(store, 3600)
        self.assertEqual(deliver_one(store, self.client, now=now)['status'], 'suppressed')

    def test_crash_and_transport_failure_consume_slots(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='live', max_attempts=2))
        self.intake(store, 0)
        store.claim_notification(now=NOW)
        restarted = Store(self.path, NotificationPolicy(delivery_mode='live', max_attempts=2))
        self.client.accepted = False
        self.assertEqual(deliver_one(restarted, self.client, now=NOW + dt.timedelta(seconds=31))['status'], 'pending')
        self.assertEqual(deliver_one(restarted, self.client, now=NOW + dt.timedelta(seconds=40))['status'], 'suppressed')
        self.assertEqual(len(self.client.calls), 1)

    def test_test_window_expires_and_has_immutable_total_budget(self):
        window = {'id': 'approved-test', 'starts_at': utc_text(NOW),
                  'expires_at': utc_text(NOW + dt.timedelta(seconds=120)), 'max_attempts': 2}
        for i in range(4):
            store = Store(self.path, NotificationPolicy(delivery_mode='live', test_window=window))
            now = self.intake(store, i, 'stage-jobs')
            self.assertEqual(deliver_one(store, self.client, now=now)['status'], 'sent' if i < 2 else 'suppressed')
        changed = Store(self.path, NotificationPolicy(delivery_mode='live',
                                                     test_window={**window, 'max_attempts': 10}))
        now = self.intake(changed, 4, 'stage-jobs')
        self.assertEqual(deliver_one(changed, self.client, now=now)['reason'], 'test-window-definition-changed')
        now = self.intake(store, 121, 'stage-jobs')
        self.assertEqual(deliver_one(store, self.client, now=now)['reason'], 'test-window-inactive-or-old-event')
        self.assertEqual(len(self.client.calls), 2)

    def test_old_events_and_restricted_payloads_never_consume_send_slots(self):
        store = Store(self.path)
        self.intake(store, 0, restricted=True)
        self.assertEqual(deliver_one(store, self.client, now=NOW)['reason'], 'restricted-channel-policy-required')
        self.intake(store, 1)
        self.assertEqual(deliver_one(store, self.client, now=NOW + dt.timedelta(days=1))['reason'], 'event-too-old')
        self.assertEqual(self.client.calls, [])
        self.assertFalse(any(r['operation'] == 'notification.reserved' for r in store.records('audit')))

    def test_reset_cannot_replay_backlog_or_bypass_human_role(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='live', max_attempts=1))
        for i in range(4):
            self.intake(store, i)
        deliver_one(store, self.client, now=NOW + dt.timedelta(seconds=4))
        deliver_one(store, self.client, now=NOW + dt.timedelta(seconds=5))
        with self.assertRaises(StateError):
            store.reset_notification_guard(Actor('agent', 'proposer'), now=NOW)
        store.reset_notification_guard(Actor('owner', 'human'), now=NOW + dt.timedelta(minutes=11))
        self.assertEqual(deliver_one(store, self.client, now=NOW + dt.timedelta(minutes=11))['status'], 'idle')
        for row in store.records('outbox'):
            if row['status'] == 'dead':
                with self.assertRaises(StateError):
                    store.retry_notification(row['id'], Actor('owner', 'human'), now=NOW)
        self.assertEqual(len(self.client.calls), 1)
        self.assertFalse(store.notification_safety_status()['circuit_open'])

    def test_two_claimants_cannot_overbook(self):
        policy = NotificationPolicy(delivery_mode='live', max_attempts=1)
        store = Store(self.path, policy)
        self.intake(store, 0, 'one')
        self.intake(store, 0, 'two')
        def claim(_):
            return Store(self.path, policy).claim_notification(now=NOW)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, range(2)))
        self.assertEqual(sum('claim_token' in r for r in results), 1)
        self.assertEqual(sum('suppressed' in r for r in results), 1)

    def test_invalid_windows_and_bounds_fail_closed(self):
        for fields in ({'max_attempts': True}, {'max_attempts': 0}, {'window_seconds': 0},
                       {'test_window': {}}, {'max_event_age_seconds': -1}):
            with self.assertRaises((StateError, ValueError)):
                # live is named so each dict below is refused for the field it breaks, not for pairing
                # a human-channel test window with a mode that forbids it.
                NotificationPolicy(delivery_mode='live', **fields)

    def test_verified_backup_restores_circuit_and_suppression(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='live', max_attempts=1))
        for i in range(2):
            now = self.intake(store, i)
            deliver_one(store, self.client, now=now)
        backup = self.path.with_name('backup.db')
        store.backup(backup)
        restored = Store(backup, NotificationPolicy(delivery_mode='live', max_attempts=1))
        self.assertEqual(restored.notification_safety_status(), store.notification_safety_status())
        now = self.intake(restored, 3600)
        self.assertEqual(deliver_one(restored, self.client, now=now)['status'], 'suppressed')
        self.assertEqual(len(self.client.calls), 1)

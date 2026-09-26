"""Actual outbox envelopes render human context, without changing durable identities."""
import copy
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.channels import NtfyChannel
from local_observe.platform.detections import event
from local_observe.platform.notification_text import notification_lines, operations_url
from local_observe.platform.state import Actor, Store
from local_observe.platform.telegram import TelegramClient

NOW = timestamp('2026-09-13T12:00:00Z')
RESOURCE = 'f6408e88-b83f-4807-9b3a-c96257e7809c'


class Opener:
    def __init__(self):
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        response = io.BytesIO(json.dumps({'ok': True, 'result': {
            'message_id': 42, 'chat': {'id': 123}}}).encode())
        response.status = 200
        return response


class HumanNotificationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.store = Store(Path(tmp.name) / 'platform.db')
        window = {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)}
        item = event('probe', RESOURCE, 'storage-free', 'threshold', 'firing', window,
                     {'sample_id': 'DO-NOT-EXPORT'}, query_type='gatus-result')
        self.store.intake(item, Actor('probe', 'producer'), now=NOW)
        self.payload = json.loads(self.store.records('outbox')[0]['payload'])

    def telegram(self, config=None, payload=None):
        payload = payload or self.payload
        opener = Opener()
        client = TelegramClient('123:synthetic', '123', opener=opener, display_config=config)
        status, receipt = client.request('POST', payload=payload,
                                        headers={'Idempotency-Key': payload['delivery_id']})
        self.assertEqual(status, 200)
        self.assertEqual(receipt['delivery_id'], payload['delivery_id'])
        return json.loads(opener.requests[0].data)['text']

    def assert_no_identity_or_evidence(self, message):
        for value in (self.payload['incident_id'], self.payload['delivery_id'],
                      self.payload['event_id'], RESOURCE, 'DO-NOT-EXPORT'):
            self.assertNotIn(value, message)

    def test_real_outbox_missing_labels_has_condition_and_next_action(self):
        before = copy.deepcopy(self.payload)
        message = self.telegram()
        self.assertIn('Incident: Detection threshold exceeded', message)
        self.assertIn('Condition: Active', message)
        self.assertIn('Next: Open Operations; inspect the incident and recent checks', message)
        self.assert_no_identity_or_evidence(message)
        self.assertEqual(self.payload, before)
        # No adapter writes labels back into state or replaces durable IDs.
        self.assertEqual(json.loads(self.store.records('outbox')[0]['payload']), before)

    def test_shared_renderer_retains_known_labels_and_refuses_uuid_labels(self):
        display = {'description': 'Storage free space is low',
                   'resource_name': 'Archive volume', 'host_name': 'Declared storage host'}
        message = '\n'.join(notification_lines(self.payload, display, {'channel_name': 'On-call'}))
        for label in display.values():
            self.assertIn(label, message)
        for key in display:
            with self.subTest(key=key):
                bad = {**display, key: RESOURCE}
                rendered = '\n'.join(notification_lines(self.payload, bad))
                self.assert_no_identity_or_evidence(rendered)
        self.assertIn('Delivery: On-call', message)

    def test_nested_event_rule_selects_configured_label_not_raw_payload_text(self):
        self.payload['event']['title'] = 'DO-NOT-EXPORT'
        self.payload['incident'] = {'display': {'description': 'DO-NOT-EXPORT'}}
        config = {'rule_names': {'storage-free': 'Archive free space is low'},
                  'operations_url': 'https://ops.example.org/console'}
        message = self.telegram(config)
        self.assertIn('Incident: Archive free space is low', message)
        self.assertIn('Next: Inspect the incident in Operations: https://ops.example.org/console', message)
        self.assert_no_identity_or_evidence(message)

    def test_other_channels_share_actionable_text(self):
        channel = NtfyChannel('https://ntfy.example.org', 'alerts',
                              display_config={'rule_names': {'storage-free': 'Archive free space is low'}})
        title, body = channel.message(self.payload, self.payload['event'])
        self.assertEqual(title, '[local-observe] ALERT — resource label missing @ host label missing')
        self.assertIn('Incident: Archive free space is low', body)
        self.assertIn('Condition: Active', body)
        self.assertIn('Next: Open Operations', body)
        self.assert_no_identity_or_evidence(title + body)

    def test_resource_less_witness_does_not_invent_a_host_and_recovery_is_clear(self):
        payload = copy.deepcopy(self.payload)
        payload['event']['resource_id'] = None
        payload['transition'] = 'resolved'
        message = self.telegram(payload=payload)
        self.assertIn('Resource: local-observe platform', message)
        self.assertIn('Host: Host not configured', message)
        self.assertIn('Condition: Recovered', message)
        self.assertIn('Next: Confirm platform availability; review witness logs if the alert repeats.', message)
        linked = self.telegram({'operations_url': 'https://ops.example.org'}, payload)
        self.assertIn('Next: Confirm Operations is reachable: https://ops.example.org', linked)
        self.assertNotIn('incident in Operations', linked)
        payload['transition'] = 'opened'
        linked = self.telegram({'operations_url': 'https://ops.example.org'}, payload)
        self.assertIn('Next: Check Operations availability: https://ops.example.org', linked)

    def test_console_links_reject_credentials_queries_and_control_characters(self):
        for value in ('http://ops.example.org', 'https://user:secret@ops.example.org',
                      'https://ops.example.org?token=secret', 'https://ops.example.org/#secret',
                      'https://ops.example.org/\nsecret', 'https://ops.example.org:0',
                      'https://ops.example.org:bad'):
            with self.subTest(value=value):
                self.assertIsNone(operations_url(value))
        self.assertEqual(operations_url('https://ops.example.org'), 'https://ops.example.org')


class HeadlineLabelTests(unittest.TestCase):
    def test_malformed_nested_kind_keeps_explicit_missing_headline(self):
        for value in [{}, [], 12, None]:
            with self.subTest(value=value):
                lines = notification_lines({'event': {'kind': value}}, {}, {})
                self.assertEqual(lines[0], '[local-observe] ALERT — resource label missing @ host label missing')

    """The example issue: the first line names the monitored resource and host, alert and recovery.

    Direct-render fixtures only: every label below is synthetic, and the durable IDs are the
    ones this file already uses, so a UUID can never be mistaken for an accepted label.
    """

    INCIDENT_ID = '2b1c9a10-5d0e-4d1f-8f77-3a6f3f0a9c11'
    DELIVERY_ID = '7f0d3c2b-1e9a-4f6b-9d55-2c4b8a1e0f33'
    CONSOLE = 'https://ops.example.org/console'

    def payload(self, transition='opened', resource_id=RESOURCE):
        return {'incident_id': self.INCIDENT_ID, 'delivery_id': self.DELIVERY_ID,
                'transition': transition,
                'event': {'resource_id': resource_id, 'kind': 'threshold',
                          'evidence': 'DO-NOT-EXPORT'}}

    def witness(self, transition, config):
        """Render the way an independent witness calls the shared formatter: no resource in event."""
        return notification_lines(self.payload(transition, None), {},
                                  dict(config, channel_name='Telegram'))

    def assert_no_ids(self, lines):
        joined = '\n'.join(lines)
        for value in (self.INCIDENT_ID, self.DELIVERY_ID, RESOURCE, 'DO-NOT-EXPORT'):
            self.assertNotIn(value, joined)

    def test_outage_headline_names_witness_resource_and_host(self):
        config = {'witness_resource': 'Monitor', 'witness_host': 'probe-host',
                  'operations_url': self.CONSOLE}
        lines = self.witness('opened', config)
        self.assertTrue(lines[0].startswith('[local-observe] ALERT'), lines[0])
        self.assertIn('Monitor', lines[0])
        self.assertIn('probe-host', lines[0])
        self.assertIn('Resource: Monitor', lines)
        self.assertIn('Host: probe-host', lines)
        self.assertIn('Next: Check Operations availability: ' + self.CONSOLE, lines)
        self.assert_no_ids(lines)

    def test_recovery_headline_names_the_same_labels_and_keeps_its_link(self):
        config = {'witness_resource': 'Monitor', 'witness_host': 'probe-host',
                  'operations_url': self.CONSOLE}
        lines = self.witness('resolved', config)
        self.assertTrue(lines[0].startswith('[local-observe] RECOVERED'), lines[0])
        self.assertIn('Monitor', lines[0])
        self.assertIn('probe-host', lines[0])
        self.assertIn('Condition: Recovered', lines)
        self.assertIn('Next: Confirm Operations is reachable: ' + self.CONSOLE, lines)
        self.assertEqual(len(self.witness('opened', config)), len(lines))
        self.assert_no_ids(lines)

    def test_inventory_labels_name_the_headline_for_a_monitored_resource(self):
        display = {'description': 'Free space is low', 'resource_name': 'Archive volume',
                   'host_name': 'Declared storage host'}
        lines = notification_lines(self.payload(), display, {'operations_url': self.CONSOLE})
        self.assertEqual(lines[0], '[local-observe] ALERT — Archive volume @ Declared storage host')
        self.assertIn('Next: Inspect the incident in Operations: ' + self.CONSOLE, lines)
        self.assert_no_ids(lines)

    def test_absent_and_uuid_labels_stay_explicit_gaps(self):
        for label in ({}, {'resource_name': RESOURCE, 'host_name': RESOURCE},
                      {'resource_name': '   ', 'host_name': None},
                      {'resource_name': 'Inventory unavailable', 'host_name': 'Unknown'}):
            with self.subTest(label=sorted(label)):
                lines = notification_lines(self.payload(), label, {})
                self.assertEqual(lines[0], '[local-observe] ALERT — resource label missing @ host label missing')
                self.assertTrue(lines[2].startswith('Resource: Resource not')
                                or lines[2].startswith('Resource: Inventory unavailable'), lines[2])
                self.assertIn(lines[2].removeprefix('Resource: '), ('Resource not identified',
                                                                   'Inventory unavailable'))
                self.assertIn(lines[3], ('Host: Host not identified',))
                self.assertNotIn(RESOURCE, '\n'.join(lines))
        exact = notification_lines(self.payload(), {'resource_name': RESOURCE,
                                                   'host_name': 'Not declared'}, {})
        self.assertIn('Resource: Resource not identified', exact)
        self.assertIn('Host: Host not identified', exact)

    def test_partial_metadata_names_the_known_side_and_marks_the_other(self):
        lines = notification_lines(self.payload(), {'resource_name': 'Archive volume',
                                                   'host_name': 'Not declared'}, {})
        self.assertEqual(lines[0], '[local-observe] ALERT — Archive volume @ host label missing')
        self.assertIn('Host: Host not identified', lines)
        lines = notification_lines(self.payload(transition='resolved'),
                                   {'resource_name': 'Undeclared resource',
                                    'host_name': 'Declared storage host'}, {})
        self.assertEqual(lines[0], '[local-observe] RECOVERED — resource label missing @ Declared storage host')
        self.assertIn('Resource: Resource label unavailable', lines)
        self.assert_no_ids(lines)

    def test_long_and_unicode_labels_stay_bounded_on_one_headline(self):
        config = {'witness_resource': 'Ünïcøde Monitor — Ñuñoa ' + 'z' * 300,
                  'witness_host': 'проверка-хост ' + 'q' * 300, 'operations_url': self.CONSOLE}
        lines = self.witness('opened', config)
        self.assertEqual(len(lines), 7)
        self.assertNotIn('\n', lines[0])
        self.assertIn('Ünïcøde Monitor', lines[0])
        self.assertIn('проверка-хост', lines[0])
        self.assertNotIn('z' * 200, lines[0])
        self.assertLessEqual(len(lines[0]), 3 * 160 + 32)
        self.assertLess(len('\n'.join(lines)), 4096)
        self.assertIn('Next: Check Operations availability: ' + self.CONSOLE, lines)

    def test_label_whitespace_and_control_spacing_cannot_add_a_second_line(self):
        config = {'witness_resource': 'Broken\nline\t label', 'witness_host': 'probe-host'}
        lines = self.witness('opened', config)
        self.assertEqual(len(lines), 7)
        self.assertIn('Broken line label', lines[0])
        self.assertNotIn('\n', lines[0])

    def test_malformed_inputs_fail_closed_to_explicit_gaps(self):
        for bad in (None, 7, 'text', [], {'resource_name': {'nested': 1}}):
            with self.subTest(bad=repr(bad)):
                lines = notification_lines(self.payload(), bad, bad)
                self.assertEqual(len(lines), 7)
                self.assertEqual(lines[0], '[local-observe] ALERT — resource label missing @ host label missing')
                self.assertIn('Resource: Resource not identified', lines)
        for broken in ('text', 7, {'event': 'text'}, {'event': None}):
            with self.subTest(payload=repr(broken)):
                lines = notification_lines(broken, {}, {'witness_resource': 'Monitor',
                                                        'witness_host': 'probe-host'})
                self.assertEqual(len(lines), 7)
                self.assertEqual(lines[0], '[local-observe] ALERT — Monitor @ probe-host')


if __name__ == '__main__':
    unittest.main()

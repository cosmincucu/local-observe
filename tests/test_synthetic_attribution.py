"""Offline Gatus wire fixtures -> durable worker -> real recoverable Store evidence."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.http import TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp
from local_observe.platform.detection_worker import tick
from local_observe.platform.detections import gatus_sample
from local_observe.platform.state import Actor, StateError, Store, validate_event

NOW = timestamp('2026-09-10T12:00:00Z')
ROOT = Path(__file__).resolve().parents[1]
EXPRESSION = '[HEADERS].X-Ready == yes'


class Engine:
    def __init__(self, conditions):
        self.calls = 0
        self.payload = {'results': [{'timestamp': NOW.isoformat(), 'success': True,
                                     'conditionResults': conditions, 'errors': ['private-error']} ]}

    def request(self, *args):
        self.calls += 1
        return 200, self.payload


class Intake:
    def __init__(self, store, source):
        self.store = store
        self.actor = Actor(source, 'producer')
        self.calls = []
        self.refuse = False
        self.lose_evidence_ack = False

    def request(self, method, path, payload):
        self.calls.append((path, payload))
        if self.refuse and path == '/v1/events':
            raise TransportError('lost acknowledgement')
        if path == '/v1/evidence':
            self.store.put_evidence(payload, self.actor, now=NOW)
            if self.lose_evidence_ack and len(self.calls) == 2:
                raise TransportError('lost evidence acknowledgement')
        else:
            validate_event(payload, NOW)
            self.store.intake(payload, self.actor, now=NOW)
        return 200, {}


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.index = self.root / 'index.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.rule = {'id': 'web', 'source': 'synthetics', 'kind': 'availability',
                     'resource_id': declared['resources'][0]['id'],
                     'assertions': {EXPRESSION: 'ready-header'}}
        self.store = Store(self.root / 'state.db')
        self.intake = Intake(self.store, self.rule['source'])
        self.cursor = self.root / 'cursor.json'

    def run_tick(self, engine, now=NOW):
        return tick(self.index, self.rule, self.cursor, engine, self.intake, now=now)

    def test_header_failure_named_and_recoverable_without_raw_data(self):
        self.run_tick(Engine([{'condition': EXPRESSION, 'success': False}]))
        event = next(payload for path, payload in self.intake.calls
                     if path == '/v1/events' and payload['kind'] == 'availability')
        self.assertEqual(event['status'], 'firing')
        reference = event['evidence'][1]
        self.assertEqual(reference['parameters']['rule_id'], 'ready-header')
        sample = self.store.get_evidence(reference['source'], reference['parameters']['sample_id'],
                                         now=NOW)['sample']
        self.assertEqual(set(sample), {'sample_id', 'observed_at', 'ok', 'value'})
        self.assertTrue(sample['ok'])
        self.assertFalse(sample['value'])
        self.assertNotIn(EXPRESSION, self.cursor.read_text())
        self.assertNotIn('private-error', json.dumps(self.intake.calls))
        paths = [path for path, _ in self.intake.calls]
        self.assertEqual(paths, ['/v1/evidence', '/v1/evidence', '/v1/events', '/v1/events'])

    def test_missing_named_measurement_is_failed_with_unmeasured_evidence(self):
        self.run_tick(Engine([]))
        sample = self.intake.calls[1][1]
        self.assertFalse(sample['ok'])
        self.assertIsNone(sample['value'])
        self.assertEqual(self.intake.calls[-1][1]['status'], 'firing')

    def test_pending_replay_does_not_fetch_or_rebuild_with_changed_config(self):
        engine = Engine([{'condition': EXPRESSION, 'success': False}])
        self.intake.refuse = True
        with self.assertRaises(TransportError):
            self.run_tick(engine)
        pending = json.loads(self.cursor.read_text())['pending']
        self.rule['assertions'] = {'new expression': 'new-name'}
        engine.payload = None
        self.intake.calls.clear()
        self.intake.refuse = False
        self.run_tick(engine, NOW + dt.timedelta(minutes=1))
        self.assertEqual(engine.calls, 1)
        self.assertEqual([payload for path, payload in self.intake.calls if path == '/v1/events'],
                         pending['events'])
        self.assertEqual(self.intake.calls[1][1], pending['assertion_samples'][0])

    def test_legacy_sample_and_cursor_shape_unchanged(self):
        self.rule.pop('assertions')
        engine = Engine([])
        expected = gatus_sample(engine.payload, before=NOW)
        self.intake.refuse = True
        with self.assertRaises(TransportError):
            self.run_tick(engine)
        pending = json.loads(self.cursor.read_text())['pending']
        self.assertEqual(set(pending), {'sample', 'events', 'end'})
        self.assertEqual(pending['sample'], expected)
        self.intake.refuse = False
        self.run_tick(engine)
        self.assertEqual(engine.calls, 1)

    def test_lost_named_evidence_ack_replays_identical_samples_before_events(self):
        engine = Engine([{'condition': EXPRESSION, 'success': False}])
        self.intake.lose_evidence_ack = True
        with self.assertRaises(TransportError):
            self.run_tick(engine)
        text = self.cursor.read_text()
        self.assertNotIn(EXPRESSION, text)
        self.assertNotIn('private-error', text)
        pending = json.loads(text)['pending']
        accepted = self.store.get_evidence('synthetics', pending['assertion_samples'][0]['sample_id'],
                                           now=NOW)['sample']
        engine.payload = None
        self.intake.calls.clear()
        self.intake.lose_evidence_ack = False
        self.run_tick(engine)
        self.assertEqual(engine.calls, 1)
        self.assertEqual(self.intake.calls[1], ('/v1/evidence', accepted))
        self.assertEqual([path for path, _ in self.intake.calls],
                         ['/v1/evidence', '/v1/evidence', '/v1/events', '/v1/events'])

    def test_excess_measurements_fail_coverage_and_configuration_is_refused(self):
        self.run_tick(Engine([{'condition': str(i), 'success': True} for i in range(17)]))
        self.assertEqual([payload['kind'] for path, payload in self.intake.calls if path == '/v1/events'],
                         ['coverage'])
        self.assertEqual(self.intake.calls[-1][1]['status'], 'firing')
        self.rule['assertions'] = {}
        with self.assertRaises(StateError):
            self.run_tick(Engine([]), NOW + dt.timedelta(seconds=10))

    def test_maximum_mapping_stays_inside_canonical_reference_bound(self):
        self.rule['assertions'] = {str(i): 'assertion-' + str(i) for i in range(16)}
        self.run_tick(Engine([{'condition': str(i), 'success': True} for i in range(16)]))
        self.assertEqual(len(self.intake.calls[-1][1]['evidence']), 17)
        self.assertEqual(self.intake.calls[-1][1]['status'], 'resolved')

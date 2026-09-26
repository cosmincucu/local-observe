"""The event-kind vocabulary after event vocabulary: `anomaly` and `security` are admitted, nothing else is.

Three claims are pinned here and nowhere else in the suite:

* the two new kinds survive intake, open and resolve incidents, and come back through the records
  view with a label an operator can read (a kind nobody can name on screen is a kind that does not
  exist);
* widening the vocabulary did not soften the check — any other value is still refused, including a
  near-miss spelling and a capitalised one;
* Sigma findings are written as `security`, which is the whole point of adding it: before event kinds a
  matched security rule was indistinguishable from a CPU threshold in every view.
"""
import copy
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import detections, presentation
from local_observe.platform.sigma_runner import artifact, tick
from local_observe.platform.state import EVENT_KINDS, Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
PRODUCER = Actor('event-kinds-test', 'producer')
SIGMA_PRODUCER = Actor('sigma-stage', 'producer')
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
# The labels presentation.py owes each kind, spelled here so a silent rename fails a test.
LABELS = {'availability': 'Availability check failed', 'coverage': 'Monitoring data missing',
          'threshold': 'Detection threshold exceeded', 'drift': 'Inventory drift detected',
          'anomaly': 'Value outside its seasonal baseline', 'security': 'Security rule matched'}


def canonical(kind: str, *, status: str = 'firing', resource: str | None = None,
              minute: int = 0, rule: str | None = None) -> dict:
    """Build one event of *kind* through the factory the producers use."""
    rule = rule or 'rule.' + str(kind)
    end = NOW + dt.timedelta(minutes=minute)
    window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
    return detections.event(PRODUCER.identity, resource, rule, kind, status, window,
                            {'rule_id': rule}, query_type='metric-threshold')


class Query:
    """One aggregate answer in the shape sigma_runner expects, with no transport underneath."""

    def __init__(self, match: int = 1, total: int = 2, usable: int = 2) -> None:
        self.row = {'source_count': total, 'usable_count': usable, 'match_count': match}

    def query(self, sql: str, parameters: dict) -> dict:
        return self.row


class Intake:
    """The platform HTTP surface replaced by the real store, so intake is really validated."""

    def __init__(self, store: Store, actor: Actor) -> None:
        self.store, self.actor, self.events = store, actor, []
        self.now = NOW

    def request(self, method: str, path: str, payload: dict) -> tuple[int, dict]:
        if path == '/v1/events':
            self.events.append(copy.deepcopy(payload))
            return 200, self.store.intake(payload, self.actor, now=self.now)
        return 200, self.store.put_evidence(payload, self.actor, now=self.now)


class VocabularyTests(unittest.TestCase):
    def test_anomaly_and_security_are_admitted(self):
        self.assertIn('anomaly', EVENT_KINDS)
        self.assertIn('security', EVENT_KINDS)
        for kind in ('availability', 'coverage', 'threshold', 'drift'):
            self.assertIn(kind, EVENT_KINDS)

    def test_every_admitted_kind_round_trips_through_intake(self):
        store = Store(self.root / 'state.db')
        for kind in EVENT_KINDS:
            result = store.intake(canonical(kind, resource=RESOURCE), PRODUCER, now=NOW)
            self.assertEqual(result['status'], 'accepted', kind)
            self.assertEqual(result['transition'], 'opened', kind)

    def test_a_kind_outside_the_vocabulary_is_refused(self):
        store = Store(self.root / 'state.db')
        for position, kind in enumerate(('anomalie', 'Anomaly', 'security-event', 'SECURITY', '',
                                        'thresholds', 'unknown', 'info', None, 1, ['anomaly'])):
            with self.subTest(kind=kind), self.assertRaises(StateError):
                store.intake(canonical(kind, resource=RESOURCE, rule=f'rule.refused.{position}'),
                             PRODUCER, now=NOW)
        self.assertEqual(store.records('events'), [])

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)


class RecordViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)

    def displays(self, table: str) -> list[dict]:
        rows = self.store.records(table)
        return [row['display'] for row in presentation.records(self.store, table, rows, self.index)]

    def test_anomaly_event_reaches_the_records_view_with_its_label(self):
        opened = self.store.intake(canonical('anomaly', resource=RESOURCE), PRODUCER, now=NOW)
        self.assertEqual(opened['transition'], 'opened')
        self.assertEqual(json.loads(self.store.records('events')[0]['payload'])['kind'], 'anomaly')
        self.assertEqual(self.displays('events')[0]['description'], LABELS['anomaly'])
        self.assertEqual(self.displays('incidents')[0]['description'], LABELS['anomaly'])
        self.assertEqual(self.displays('incidents')[0]['resource_name'], 'probe-1')
        self.assertEqual(self.displays('outbox')[0]['delivery_name'], 'Incident alert')
        resolved = self.store.intake(canonical('anomaly', status='resolved', resource=RESOURCE,
                                              minute=5), PRODUCER, now=NOW + dt.timedelta(minutes=5))
        self.assertEqual(resolved['transition'], 'resolved')
        self.assertEqual(self.store.records('incidents')[0]['status'], 'resolved')

    def test_the_severity_a_producer_named_survives_intake(self):
        event = canonical('anomaly', resource=RESOURCE)
        event['severity'] = 'critical'
        self.store.intake(event, PRODUCER, now=NOW)
        self.assertEqual(json.loads(self.store.records('events')[0]['payload'])['severity'], 'critical')


class SigmaKindTests(unittest.TestCase):
    """A matched Sigma rule is a security finding, not a threshold breach."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture')
        self.compiled = artifact(ROOT / 'examples/sigma/compiled/process-marker.json')
        self.cursor = self.root / 'cursor.json'
        self.store = Store(self.root / 'state.db')
        self.intake = Intake(self.store, SIGMA_PRODUCER)

    def kinds(self) -> list[str]:
        return [json.loads(row['payload'])['kind'] for row in self.store.records('events')]

    def findings(self) -> list[dict]:
        return [item for item in self.intake.events if item['kind'] == 'security']

    def run_tick(self, query: Query) -> str:
        return tick(self.index, self.compiled, RESOURCE, self.cursor, query, self.intake, now=self.intake.now)

    def test_finding_and_coverage_carry_their_own_kinds(self):
        self.assertEqual(self.run_tick(Query()), 'delivered')
        self.assertEqual(sorted(self.kinds()), ['coverage', 'security'])
        self.assertEqual([event['kind'] for event in self.intake.events], ['coverage', 'security'])
        self.assertEqual(self.findings()[0]['rule_id'], 'sigma.' + self.compiled['rule_id'])

    def test_a_matched_rule_opens_an_incident_the_operator_can_read(self):
        self.run_tick(Query())
        display = [row['display'] for row in presentation.records(self.store, 'incidents',
                                                                 self.store.records('incidents'),
                                                                 self.index)][0]
        self.assertEqual(display['description'], LABELS['security'])
        self.assertEqual(display['resource_name'], 'probe-1')

    def test_no_match_resolves_the_finding_without_touching_coverage(self):
        self.run_tick(Query())
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.intake.now = NOW + dt.timedelta(minutes=1)
        self.run_tick(Query(match=0))
        self.assertEqual(sorted(set(self.kinds())), ['coverage', 'security'])
        self.assertEqual([item['status'] for item in self.findings()], ['firing', 'resolved'])
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})

    def test_an_unusable_source_emits_coverage_only(self):
        self.run_tick(Query(match=0, total=2, usable=1))
        self.assertEqual(self.kinds(), ['coverage'])


if __name__ == '__main__':
    unittest.main()

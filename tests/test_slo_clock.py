"""SLO reads, burn verdicts and coverage use one evaluation cutoff (#202)."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform.state import Actor, Store
from local_observe.slo import alerts
from local_observe.store.backends.memory import InMemoryStore, MetricSample, series

ROOT = Path(__file__).resolve().parents[1]


def at(hour, minute):
    return dt.datetime(2026, 9, 8, hour, minute, tzinfo=dt.timezone.utc)


NOW, SCHEDULE_END, CUTOFF = at(12, 24), at(12, 15), at(12, 10)


class RecordingStore(InMemoryStore):
    def __init__(self, rows):
        super().__init__(rows)
        self.reads = []

    def read(self, query_type, *, window, parameters, **kwargs):
        result = super().read(query_type, window=window, parameters=parameters, **kwargs)
        self.reads.append((parameters['rule_id'], window, result.samples))
        return result


class SloClockTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.store = Store(self.root / 'state.db')
        self.actor = Actor('lo-slo', 'producer')
        self.cursor = self.root / 'cursor.json'
        self.sent = []

    def rule(self, **overrides):
        document = {'objective_id': 'api.availability', 'resource_id': self.host,
                    'signal': 'availability', 'target': 0.9, 'window_days': 1,
                    'long_window': 900, 'short_window': 300, 'burn_threshold': 5.0,
                    'metric': 'availability', 'min_samples': 1, 'severity_source': 'core-events-v1',
                    'severity_tier': 'warning', 'evaluation_seconds': 600, 'for_seconds': 300,
                    'max_age_seconds': 900}
        document.update(overrides)
        return alerts.rule(document, source='lo-slo')

    def rows(self, stop, *, bad_from=None, bad_to=None):
        rows = []
        instant = at(11, 0)
        bad_from = bad_from or at(11, 30)
        bad_to = bad_to or stop
        while instant <= stop:
            value = 0.0 if bad_from <= instant <= bad_to else 1.0
            rows.append(MetricSample(name='availability', value=value, resource_id=self.host,
                                     labels={'resource_id': self.host}, timestamp=utc_text(instant)))
            instant += dt.timedelta(seconds=60)
        return rows

    def tick(self, reader, *rules, now=NOW, interval=900, deliver=None):
        config = {'rules': list(rules), 'interval_seconds': interval}

        def file_event(item):
            self.store.intake(item, self.actor, now=now)
            self.sent.append(item)

        return alerts.tick(self.index, config, self.cursor, reader, deliver or file_event,
                           now=now, state=alerts.cursor_document(self.cursor, config))

    def test_900_600_reads_only_samples_before_the_burn_verdict_cutoff(self):
        reader = RecordingStore(self.rows(at(12, 14)))
        result = self.tick(reader, self.rule())
        self.assertEqual(result['objectives'], {'api.availability': 'firing'})
        self.assertEqual(len(reader.reads), 1)
        _, window, samples = reader.reads[0]
        self.assertEqual(window.end, utc_text(CUTOFF))
        self.assertEqual(max(timestamp(row.timestamp) for row in samples), at(12, 9))
        detail = result['detail']['api.availability']
        self.assertEqual(detail['window']['end'], window.end)
        self.assertEqual(detail['age_seconds'], 60)
        self.assertAlmostEqual(detail['long_burn'], 10.0)
        self.assertAlmostEqual(detail['short_burn'], 10.0)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual({item['window']['end'] for item in self.sent}, {utc_text(CUTOFF)})
        self.assertEqual(json.loads(self.cursor.read_text())['last_end'], utc_text(SCHEDULE_END))
        self.assertEqual(self.tick(reader, self.rule(), now=at(12, 26))['result'], 'idle')
        self.assertEqual(len(reader.reads), 1)

    def test_each_objective_uses_its_own_grid_including_an_aligned_objective(self):
        reader = RecordingStore(self.rows(at(12, 14)))
        result = self.tick(reader, self.rule(),
                           self.rule(objective_id='api.slow', evaluation_seconds=900))
        expected = {'api.availability': utc_text(CUTOFF), 'api.slow': utc_text(SCHEDULE_END)}
        self.assertEqual({name: window.end for name, window, _ in reader.reads}, expected)
        self.assertEqual({name: detail['window']['end'] for name, detail in result['detail'].items()},
                         expected)
        self.assertEqual(set(result['objectives'].values()), {'firing'})

    def test_true_staleness_opens_coverage_without_resolving_the_burn(self):
        entry = self.rule()
        self.tick(RecordingStore(self.rows(at(12, 14))), entry)
        self.sent.clear()
        result = self.tick(RecordingStore(self.rows(at(11, 20))), entry, now=at(13, 9))
        self.assertEqual(result['objectives'], {'api.availability': 'stale'})
        self.assertEqual(result['detail']['api.availability']['age_seconds'], 6000)
        self.assertEqual([(item['kind'], item['status']) for item in self.sent], [('coverage', 'firing')])
        self.assertEqual(self.store.status()['incidents'], {'open': 2})

    def test_truncated_read_emits_coverage_at_the_evaluation_cutoff(self):
        reader = RecordingStore(series(2000, name='availability', resource_id=self.host,
                                        step_seconds=30, value=0.0,
                                        start=utc_text(CUTOFF - dt.timedelta(seconds=87000))))
        result = self.tick(reader, self.rule())
        self.assertEqual(result['objectives'], {'api.availability': 'truncated'})
        self.assertEqual(result['truncated'], ['api.availability'])
        self.assertEqual(reader.reads[0][1].end, utc_text(CUTOFF))
        self.assertEqual([(item['kind'], item['status']) for item in self.sent], [('coverage', 'firing')])
        self.assertEqual(self.sent[0]['window'], {'start': utc_text(at(12, 0)), 'end': utc_text(CUTOFF)})

    def test_pending_batch_replays_identical_events_without_reading(self):
        attempts = []

        def refuse(item):
            attempts.append(item)
            raise OSError('intake unreachable')

        entry = self.rule()
        with self.assertRaises(OSError):
            self.tick(RecordingStore(self.rows(at(12, 14))), entry, deliver=refuse)
        stored = json.loads(self.cursor.read_text())
        self.assertIsNone(stored['last_end'])
        self.assertEqual(stored['pending']['end'], utc_text(SCHEDULE_END))
        self.assertEqual({item['window']['end'] for item in stored['pending']['events']},
                         {utc_text(CUTOFF)})
        result = self.tick(None, entry, now=at(13, 30))
        self.assertEqual((result['result'], result['events']), ('replayed', 2))
        self.assertEqual(attempts, stored['pending']['events'][:1])
        self.assertEqual(self.sent, stored['pending']['events'])
        finished = json.loads(self.cursor.read_text())
        self.assertIsNone(finished['pending'])
        self.assertEqual(finished['last_end'], utc_text(SCHEDULE_END))

    def test_sustained_burn_and_recovery_keep_incident_transitions(self):
        entry = self.rule()
        reader = RecordingStore(self.rows(at(12, 59), bad_from=at(11, 30), bad_to=at(12, 29)))
        first = self.tick(reader, entry, now=at(12, 34))
        self.assertEqual(first['objectives'], {'api.availability': 'firing'})
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        second = self.tick(reader, entry, now=at(13, 4))
        self.assertEqual(second['objectives'], {'api.availability': 'resolved'})
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})
        self.assertEqual(self.store.status()['notifications'], {'pending': 2})

    def test_faster_schedule_reuses_the_same_burn_window_without_conflicting_events(self):
        entry = self.rule()
        reader = RecordingStore(self.rows(at(12, 6)))
        self.tick(reader, entry, interval=300, now=at(12, 4))
        first = self.sent.copy()
        result = self.tick(reader, entry, interval=300, now=at(12, 7))
        self.assertEqual(result['result'], 'delivered')
        self.assertEqual([window.end for _, window, _ in reader.reads], [utc_text(at(12, 0))] * 2)
        self.assertEqual(self.sent[len(first):], first)
        self.assertEqual(len(self.store.records('events')), len(first))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

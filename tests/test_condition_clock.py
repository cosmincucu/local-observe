"""Condition reads and verdicts share each rule's evaluation cutoff (#202).

The two `test_a_dense_rule_...`/`test_a_truncated_absence_round_...` cases carry the same rule into
#211's shapes: a read that came back short is inability to judge and files only its own
``<rule>.coverage`` event, and a complete absence round clears that reader warning beside its own absence
verdict. Both events name the rule's own window, never the document's schedule position — which is the
whole of the two cards' intersection, and the shape neither card's own tests could see alone.
"""
import datetime as dt
import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import conditions
from local_observe.platform.state import Actor, StateError, Store
from local_observe.store.backends.memory import InMemoryStore, MetricSample
from local_observe.store.client import ReadOutcome

ROOT = Path(__file__).resolve().parents[1]


def at(hour, minute, *, day=8):
    return dt.datetime(2026, 9, day, hour, minute, tzinfo=dt.timezone.utc)


NOW, SCHEDULE_END, CUTOFF = at(12, 24), at(12, 15), at(12, 10)


class RecordingStore(InMemoryStore):
    def __init__(self, rows):
        super().__init__(rows)
        self.reads = []

    def read(self, query_type, *, window, parameters, **kwargs):
        result = super().read(query_type, window=window, parameters=parameters, **kwargs)
        self.reads.append((parameters['rule_id'], window, result.samples))
        return result


class ShortReader:
    """A facade double that calls its answer short: the same rows, with `truncated` set on the receipt.

    The shape of a read the bounded pages could not cover. A heartbeat read never falls into it by itself
    (its answer is one presence record, and a one-row page is never a cut-off one), so the absence path
    can only be asserted against a reader that says so — `tests/test_conditions.py`'s `TruncatingReader`
    is the same double, and this file needs it to put #211's shape on #202's clock.
    """

    def __init__(self, inner):
        self.inner = inner

    def read(self, *args, **kwargs):
        outcome = self.inner.read(*args, **kwargs)
        return ReadOutcome(status=outcome.status, receipt=replace(outcome.receipt, truncated=True),
                           samples=outcome.samples, detail=outcome.detail)


class ConditionClockTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.store = Store(self.root / 'state.db')
        self.actor = Actor('lo-conditions', 'producer')
        self.cursor = self.root / 'cursor.json'
        self.sent = []

    def rule(self, **overrides):
        document = {'id': 'cpu.high', 'mode': 'threshold', 'resource_id': self.host,
                    'source': 'lo-conditions', 'severity_source': 'sigma', 'severity_tier': 'high',
                    'metric': 'cpu', 'threshold': 90, 'for_seconds': 600,
                    'evaluation_seconds': 600, 'max_age_seconds': 300, 'history_seconds': 3600}
        document.update(overrides)
        return conditions.rule(document)

    def rows(self, start, stop, *, step=60, breach_start=None, breach_end=None, name='cpu'):
        rows = []
        instant = start
        while instant <= stop:
            breach = ((breach_start is None or instant >= breach_start)
                      and (breach_end is None or instant <= breach_end))
            rows.append(MetricSample(name=name, value=95.0 if breach else 10.0,
                                     resource_id=self.host, labels={'resource_id': self.host},
                                     timestamp=utc_text(instant)))
            instant += dt.timedelta(seconds=step)
        return rows

    def tick(self, reader, *rules, now=NOW, interval=900, deliver=None):
        config = {'rules': list(rules), 'interval_seconds': interval}

        def file_event(item):
            self.store.intake(item, self.actor, now=now)
            self.sent.append(item)

        return conditions.tick(self.index, config, self.cursor, reader, deliver or file_event,
                               now=now, state=conditions.load_cursor(self.cursor, config))

    def test_900_600_reads_only_samples_before_the_verdict_cutoff(self):
        reader = RecordingStore(self.rows(at(11, 0), at(12, 14)))
        result = self.tick(reader, self.rule())
        self.assertEqual(result['rules'], {'cpu.high': 'firing'})
        self.assertEqual(len(reader.reads), 1)
        _, window, samples = reader.reads[0]
        self.assertEqual((window.start, window.end), (utc_text(at(11, 10)), utc_text(CUTOFF)))
        self.assertEqual(max(timestamp(row.timestamp) for row in samples), at(12, 9))
        detail = result['detail']['cpu.high']
        self.assertEqual(detail['window']['end'], window.end)
        self.assertEqual(detail['age_seconds'], 60)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual({item['window']['end'] for item in self.sent}, {utc_text(CUTOFF)})
        self.assertEqual(json.loads(self.cursor.read_text())['last_end'], utc_text(SCHEDULE_END))
        self.assertEqual(self.tick(reader, self.rule(), now=at(12, 26))['result'], 'idle')
        self.assertEqual(len(reader.reads), 1)

    def test_each_rule_uses_its_own_grid_including_an_aligned_rule(self):
        reader = RecordingStore(self.rows(at(11, 0), at(12, 14)))
        result = self.tick(reader, self.rule(), self.rule(id='cpu.slow', evaluation_seconds=900))
        expected = {'cpu.high': utc_text(CUTOFF), 'cpu.slow': utc_text(SCHEDULE_END)}
        self.assertEqual({name: window.end for name, window, _ in reader.reads}, expected)
        self.assertEqual({name: detail['window']['end'] for name, detail in result['detail'].items()},
                         expected)
        self.assertEqual(set(result['rules'].values()), {'firing'})

    def test_band_rule_uses_the_same_per_rule_cutoff(self):
        entry = conditions.rule({'id': 'load.band', 'mode': 'band', 'resource_id': self.host,
                                 'source': 'lo-conditions', 'severity_source': 'sigma',
                                 'severity_tier': 'high', 'metric': 'cpu', 'evaluation_seconds': 600,
                                 'history_seconds': 86400, 'for_seconds': 900, 'max_age_seconds': 3600,
                                 'min_points': 48, 'min_per_bucket': 3})
        reader = RecordingStore(self.rows(at(12, 14, day=7), at(12, 14), step=300))
        result = self.tick(reader, entry)
        self.assertEqual(reader.reads[0][1].end, utc_text(CUTOFF))
        self.assertGreaterEqual(result['detail']['load.band']['age_seconds'], 0)
        self.assertNotEqual(result['rules']['load.band'], 'stale')
        self.assertEqual({item['window']['end'] for item in self.sent}, {utc_text(CUTOFF)})

    def test_true_staleness_opens_coverage_without_resolving_an_open_condition(self):
        entry = self.rule(history_seconds=7200)
        self.tick(RecordingStore(self.rows(at(11, 0), at(12, 14))), entry)
        self.sent.clear()
        result = self.tick(RecordingStore(self.rows(at(11, 0), at(11, 59))), entry, now=at(13, 9))
        self.assertEqual(result['rules'], {'cpu.high': 'stale'})
        self.assertEqual(result['detail']['cpu.high']['age_seconds'], 3660)
        self.assertEqual([(item['kind'], item['status']) for item in self.sent], [('coverage', 'firing')])
        self.assertEqual(self.store.status()['incidents'], {'open': 2})

    def test_pending_batch_replays_identical_events_without_reading(self):
        attempts = []

        def refuse(item):
            attempts.append(item)
            raise OSError('intake unreachable')

        entry = self.rule()
        with self.assertRaises(OSError):
            self.tick(RecordingStore(self.rows(at(11, 0), at(12, 14))), entry, deliver=refuse)
        stored = json.loads(self.cursor.read_text())
        self.assertIsNone(stored['last_end'])
        self.assertEqual(stored['pending']['end'], utc_text(SCHEDULE_END))
        self.assertEqual({item['window']['end'] for item in stored['pending']['events']},
                         {utc_text(CUTOFF)})
        # None is deliberately not a reader: replay must use only the persisted batch.
        result = self.tick(None, entry, now=at(13, 30))
        self.assertEqual((result['result'], result['events']), ('replayed', 2))
        self.assertEqual(attempts, stored['pending']['events'][:1])
        self.assertEqual(self.sent, stored['pending']['events'])
        finished = json.loads(self.cursor.read_text())
        self.assertIsNone(finished['pending'])
        self.assertEqual(finished['last_end'], utc_text(SCHEDULE_END))

    def test_sustained_breach_and_recovery_keep_incident_transitions(self):
        entry = self.rule(for_seconds=900, resolve_seconds=900, history_seconds=7200)
        reader = RecordingStore(self.rows(at(11, 0), at(12, 59),
                                          breach_start=at(11, 30), breach_end=at(12, 29)))
        self.assertEqual(self.tick(reader, entry, now=at(12, 34))['rules'], {'cpu.high': 'firing'})
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual(self.tick(reader, entry, now=at(13, 4))['rules'], {'cpu.high': 'resolved'})
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})
        self.assertEqual(self.store.status()['notifications'], {'pending': 2})

    def test_faster_schedule_reuses_the_same_evaluation_window_without_conflicting_events(self):
        reader = RecordingStore(self.rows(at(11, 0), at(12, 6)))
        entry = self.rule()
        self.tick(reader, entry, interval=300, now=at(12, 4))
        first = self.sent.copy()
        result = self.tick(reader, entry, interval=300, now=at(12, 7))
        self.assertEqual(result['result'], 'delivered')
        self.assertEqual([window.end for _, window, _ in reader.reads], [utc_text(at(12, 0))] * 2)
        self.assertEqual(self.sent[len(first):], first)
        self.assertEqual(len(self.store.records('events')), len(first))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_a_dense_rule_and_a_different_cadence_sibling_name_their_own_cutoffs(self):
        """#211's incomplete read inside #202's round: coverage is dated where the verdict would have been.

        One round, two rules, two grids: the dense `cpu` hour overflows :data:`MAX_POINTS` as the bounded
        slices compose, so it is reported and never graded, and the event it files is its own
        ``cpu.dense.coverage`` at 12:00–12:10 — the rule's own evaluation window, not the 12:05–12:15 the
        document's schedule position would have written. The `disk` rule on a 900-second grid is judged,
        delivered and acknowledged at 12:00–12:15 in the same round, and the cursor records the schedule.
        """
        dense = self.rule(id='cpu.dense', metric='cpu', history_seconds=3600, evaluation_seconds=600)
        sparse = self.rule(id='disk.sparse', metric='disk', history_seconds=3600, evaluation_seconds=900)
        reader = RecordingStore(self.rows(at(11, 10), at(12, 9), step=1)
                                + self.rows(at(12, 0), at(12, 14), name='disk'))
        result = self.tick(reader, dense, sparse)
        self.assertEqual(result['rules'], {'cpu.dense': 'unreadable', 'disk.sparse': 'firing'})
        self.assertEqual((result['refusals'], result['truncated']), (1, ['cpu.dense']))
        reading = result['detail']['cpu.dense']['read']
        self.assertEqual({key: value for key, value in reading.items() if key != 'reads'},
                         {'answered': 'ok', 'truncated': True, 'covered_seconds': 3600.0, 'points': 0})
        self.assertLessEqual(reading['reads'], 1 + conditions.MAX_READ_SPANS,
                             'the dense span stops the retry where it is discovered, inside the bound')
        self.assertIn('so nothing is judged', result['detail']['cpu.dense']['reason'])
        self.assertEqual(result['detail']['cpu.dense']['window'],
                         {'start': utc_text(at(12, 0)), 'end': utc_text(CUTOFF)})
        # No read of either rule crosses its own cutoff: the dense rule's slices all sit inside 12:10 and
        # the 900-second rule's single read stops at the 12:15 schedule position it is aligned to.
        self.assertEqual({name: max(window.end for rule_name, window, _ in reader.reads
                                    if rule_name == name)
                          for name in ('cpu.dense', 'disk.sparse')},
                         {'cpu.dense': utc_text(CUTOFF), 'disk.sparse': utc_text(SCHEDULE_END)})
        self.assertEqual(sorted((item['rule_id'], item['status']) for item in self.sent),
                         [('cpu.dense.coverage', 'firing'), ('disk.sparse', 'firing'),
                          ('disk.sparse.coverage', 'resolved')])
        self.assertEqual({(item['window']['start'], item['window']['end']) for item in self.sent
                          if item['rule_id'] == 'cpu.dense.coverage'},
                         {(utc_text(at(12, 0)), utc_text(CUTOFF))},
                         'the coverage event of an incomplete read names the grid of its own rule, not '
                         'the document end it was taken before')
        self.assertEqual({(item['window']['start'], item['window']['end']) for item in self.sent
                          if item['rule_id'].startswith('disk.sparse')},
                         {(utc_text(at(12, 0)), utc_text(SCHEDULE_END))})
        self.assertEqual(json.loads(self.cursor.read_text())['last_end'], utc_text(SCHEDULE_END))
        self.assertEqual(self.store.status()['incidents'], {'open': 2},
                         'the blind warning of the dense rule and the sparse verdict, and no cursor lost')

    def test_a_truncated_absence_round_and_its_recovery_share_the_rule_cutoff(self):
        """Reader recovery is independent of absence, and both rounds speak one rule's window.

        Round one's heartbeat read comes back short, so the rule files nothing about absence — only
        ``beat.absent.coverage`` firing at 12:00–12:10, the window the withheld verdict would have
        carried, and the round is still acknowledged at the 12:15 schedule position. Round two reads the
        same (empty) heartbeat honestly: the absence verdict it earns and the companion that clears the
        reader warning are both dated at that rule's 12:30–12:40 cutoff (a 12:45 schedule position floored
        onto the 600-second grid), while the cursor still moves on the document's own 12:45. Using the
        schedule grid for either event would leave the warning open beside a condition nobody measured,
        and one rule's round would name two windows.
        """
        quiet = conditions.rule({'id': 'beat.absent', 'mode': 'absence', 'resource_id': self.host,
                                 'source': 'lo-conditions', 'severity_source': 'sigma',
                                 'severity_tier': 'high', 'metric': 'host.checkins',
                                 'evaluation_seconds': 600, 'history_seconds': 3600,
                                 'within_seconds': 300})
        blind = ShortReader(RecordingStore([]))
        result = self.tick(blind, quiet)
        self.assertEqual((result['rules'], result['refusals'], result['truncated'], result['events']),
                         ({'beat.absent': 'unreadable'}, 1, ['beat.absent'], 1))
        self.assertEqual(result['detail']['beat.absent']['read'],
                         {'answered': 'empty', 'truncated': True, 'reads': 1 + conditions.MAX_READ_SPANS,
                          'covered_seconds': 3600.0, 'points': 0})
        self.assertEqual(max(window.end for _, window, _ in blind.inner.reads), utc_text(CUTOFF),
                         'even the retried slices stay inside the cutoff of this rule')
        self.assertEqual([(item['rule_id'], item['status'], item['window']) for item in self.sent],
                         [('beat.absent.coverage', 'firing',
                           {'start': utc_text(at(12, 0)), 'end': utc_text(CUTOFF)})])
        self.assertEqual(json.loads(self.cursor.read_text())['last_end'], utc_text(SCHEDULE_END))
        self.assertEqual(self.store.status()['incidents'], {'open': 1},
                         'the reader warning only: no absence incident from a read that could not state it')

        self.sent.clear()
        recovered = self.tick(RecordingStore([]), quiet, now=at(12, 54))
        self.assertEqual(recovered['rules'], {'beat.absent': 'unseen'})
        self.assertEqual((recovered['truncated'], recovered['refusals']), ([], 0))
        self.assertEqual(sorted((item['rule_id'], item['status']) for item in self.sent),
                         [('beat.absent', 'firing'), ('beat.absent.coverage', 'resolved')])
        self.assertEqual({(item['window']['start'], item['window']['end']) for item in self.sent},
                         {(utc_text(at(12, 30)), utc_text(at(12, 40)))},
                         'absence and its companion are one round of one rule and name one window each')
        self.assertEqual(json.loads(self.cursor.read_text())['last_end'], utc_text(at(12, 45)))
        self.assertEqual(self.store.status()['incidents'], {'open': 1, 'resolved': 1},
                         'the recovery closed the reader warning and left the absence it measured open')

    def test_grid_rejects_invalid_clocks_and_intervals(self):
        for instant, seconds in ((NOW.replace(tzinfo=None), 600), (NOW, 0), (NOW, True), (NOW, 1.5)):
            with self.subTest(instant=instant, seconds=seconds), self.assertRaises(StateError):
                conditions.grid_end(instant, seconds=seconds)

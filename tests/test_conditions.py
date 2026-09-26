"""alert conditions: sustained conditions — the ``for:`` machine, absence, and the coverage-first rule.

Four claims are pinned here, and each is a way the feature could be quietly wrong:

* **A flap is one condition.** `FlapTests` states its input series and the numbers it produces: the
  same twelve samples driven through `detections.evaluate` tick by tick open **3** incidents and book
  **6** deliveries, while `conditions.evaluate` on the same samples opens **1** and books **1**. The
  difference is not dedup of identical bytes — every tick carries a different window — it is the state
  machine refusing to call a flap a recovery.
* **Blindness is never silence, and never a recovery.** A stale or absent input files one `coverage`
  event and nothing about the condition, so an incident opened by real data cannot be closed by the
  absence of data: the rule `detections.evaluate` states in its docstring, kept here verbatim.
* **Nothing is invented.** Too few points, an unreadable store, a rule with no threshold, an unmapped
  severity word and a foreign cursor are refusals or named outcome words, and every event this module
  emits passes `state.validate_event` — the platform's own gate, not a copy of it.
* **A dense series costs its own rule a verdict, and nothing else.** Four bounded reads of one hour can
  answer 3 600 points, and that is more than `MAX_POINTS` may be judged over. `read_points` composes
  *under* that bound — each slice is measured against what is already held, before anything is appended —
  so the dense hour answers empty, `truncated`, and with the reads it really spent; `tick` then files that
  rule's own ``coverage`` event naming the reason and grades nothing, the way `slo.alerts._blind` and
  `dynamic_bands`' `insufficient` already mean inability to judge. The *other* rules' events are still
  delivered and their cursor still moves. Two earlier builds are pinned as broken: the one that
  concatenated 3 600 points and let `ordered_points` refuse them inside `judge`, which aborted every rule
  in the document and never moved the cursor at all; and the one that graded a truncated 2 000-row page,
  a span cut by nothing but where the store's page ended, whose missing rows are the newest ones — the
  part a `for:` run is dated from (`DenseSeriesTests`, `DenseRoundTests`).

Fixture style follows `tests/test_platform.py` (a real inventory index built from
`examples/inventory/declared.yaml`) and `tests/test_notification_safety.py` (a real `Store`, with the
durable delivery facts read back out of its own tables).
"""
import contextlib
import datetime as dt
from dataclasses import replace
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import cli, conditions, detections
from local_observe.platform.state import Actor, StateError, Store, validate_event
from local_observe.store.client import ReadOutcome
from local_observe.store.backends.memory import InMemoryStore, MetricSample, series

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
SOURCE = 'lo-conditions'
STEP = 60
MAX_HISTORY = 7 * 86400
# The headline series: a crossing that holds long enough to fire, then a flap around the threshold.
FLAP = [10, 10, 95, 95, 95, 95, 95, 85, 95, 85, 95, 85]


def points(values, *, end: dt.datetime = NOW, step: int = STEP):
    """Lay a list of values on a fixed 60-second grid whose newest point sits exactly at *end*."""
    return [(end.timestamp() - step * (len(values) - 1 - i), float(value))
            for i, value in enumerate(values)]


def threshold_rule(resource: str, **overrides) -> conditions.Rule:
    document = {'id': 'cpu.high', 'mode': 'threshold', 'resource_id': resource, 'source': SOURCE,
                'severity_source': 'sigma', 'severity_tier': 'high', 'threshold': 90,
                'for_seconds': 180, 'evaluation_seconds': 60, 'history_seconds': 3600}
    document.update(overrides)
    return conditions.rule(document)


def absence_rule(resource: str, **overrides) -> conditions.Rule:
    document = {'id': 'beat.absent', 'mode': 'absence', 'resource_id': resource, 'source': SOURCE,
                'severity_source': 'sigma', 'severity_tier': 'high', 'within_seconds': 300,
                'evaluation_seconds': 60, 'history_seconds': 3600}
    document.update(overrides)
    return conditions.rule(document)


def dense_rows(count: int, *, name: str, resource_id: str, end: dt.datetime,
               step: int = 1, value: float = 95.0) -> list[MetricSample]:
    """Lay `count` rows `step` seconds apart, the newest one `step` inside *end* (the window is half-open).

    `store.backends.memory.series` caps itself at the facade's 2 000-row page, so the dense fixtures that
    overflow it are seeded row by row: a fixture that could not write 3 600 one-second samples could not
    state the bound this file pins, and a fixture one second too long would lose its newest point to the
    half-open window and quietly test a denser series than its name says.
    """
    return [MetricSample(name=name, value=value, resource_id=resource_id,
                         labels={'resource_id': resource_id},
                         timestamp=utc_text(end - dt.timedelta(seconds=step * (count - position))))
            for position in range(count)]


def events_for(rule, values, *, at: dt.datetime = NOW):
    """Every event one tick owes, each one passed through the platform's own event gate first."""
    emitted = conditions.evaluate(rule, points(values), now=at)
    for item in emitted:
        validate_event(item, at)
    return emitted


def findings(emitted):
    """The condition events of a tick, with the companion coverage verdict removed."""
    return [item['status'] for item in emitted if item['kind'] != 'coverage']


class RuleConfigTests(unittest.TestCase):
    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def test_a_valid_rule_resolves_its_loudness_from_the_crosswalk_and_not_from_here(self):
        rule = threshold_rule(self.host)
        self.assertEqual(rule.severity(), 'warning')          # sigma `high` is the crosswalk's answer
        self.assertEqual((rule.kind, rule.query_type), ('threshold', 'metric-threshold'))
        self.assertEqual(len(rule.version), 16)

    def test_a_quieter_tier_word_is_a_different_loudness_and_not_a_different_condition(self):
        loud = threshold_rule(self.host, severity_tier='critical')
        quiet = threshold_rule(self.host, severity_tier='informational')
        self.assertEqual(loud.severity(), 'critical')
        self.assertEqual(quiet.severity(), 'info')
        self.assertEqual(loud.version, quiet.version,
                         'retuning loudness must not orphan the incident a rule already opened')

    def test_a_severity_word_the_crosswalk_cannot_resolve_refuses_the_rule_at_load(self):
        with self.assertRaises(Exception) as caught:
            threshold_rule(self.host, severity_tier='catastrophic')
        self.assertIn('catastrophic', str(caught.exception))

    def test_unknown_keys_and_missing_fields_refuse_rather_than_being_ignored(self):
        base = {'id': 'cpu.high', 'mode': 'threshold', 'resource_id': self.host, 'source': SOURCE,
                'severity_source': 'sigma', 'severity_tier': 'high', 'threshold': 90}
        extra = dict(base, threshhold=90)
        with self.assertRaises(StateError):
            conditions.rule(extra)
        for name in conditions.RULE_REQUIRED:
            absent = dict(base)
            del absent[name]
            with self.subTest(missing=name), self.assertRaises(StateError):
                conditions.rule(absent)

    def test_a_history_shorter_than_its_own_durations_refuses_instead_of_never_firing(self):
        """The reconstruction bound: a machine that cannot see back cannot date a run."""
        with self.assertRaises(StateError):
            threshold_rule(self.host, for_seconds=600, history_seconds=600)

    def test_absence_refuses_a_second_duration_behind_its_deadline(self):
        with self.assertRaises(StateError):
            absence_rule(self.host, for_seconds=60)

    def test_a_threshold_rule_needs_a_finite_number_and_a_boolean_rule_no_comparison(self):
        with self.assertRaises(StateError):
            threshold_rule(self.host, threshold=float('nan'))
        with self.assertRaises(StateError):
            threshold_rule(self.host, mode='availability', threshold=90)

    def test_load_config_bounds_the_document_and_the_rule_set(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / 'conditions.json'
        good = {'rules': [{'id': 'cpu.high', 'mode': 'availability', 'resource_id': self.host,
                           'source': SOURCE, 'severity_source': 'sigma', 'severity_tier': 'high'}]}
        path.write_text(json.dumps(good), encoding='utf-8')
        loaded = conditions.load_config(path)
        self.assertEqual([entry.id for entry in loaded['rules']], ['cpu.high'])
        self.assertEqual(loaded['interval_seconds'], conditions.DEFAULT_TICK_SECONDS)
        for broken in ({'rules': [], 'interval_seconds': 4}, {'rule': []},
                       {'rules': [good['rules'][0], good['rules'][0]]}):
            path.write_text(json.dumps(broken), encoding='utf-8')
            with self.subTest(broken=sorted(broken)), self.assertRaises(StateError):
                conditions.load_config(path)


class MachineTests(unittest.TestCase):
    """The state machine on its own, with the clock supplied by the test and never read."""

    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def test_a_sub_duration_crossing_never_fires_and_leaves_nothing_to_audit(self):
        self.assertEqual(findings(events_for(threshold_rule(self.host, for_seconds=600),
                                             [10, 95, 95, 10])), ['resolved'])

    def test_a_crossing_that_holds_fires_once_and_reports_firing_on_every_later_tick(self):
        rule = threshold_rule(self.host, for_seconds=180)
        values = [10, 95, 95, 95, 95, 95]
        statuses = []
        for position in range(2, len(values) + 1):
            at = NOW + dt.timedelta(seconds=STEP * (position - len(values)))
            emitted = conditions.evaluate(rule, points(values[:position], end=at), now=at)
            for item in emitted:
                validate_event(item, at)
            statuses.append(findings(emitted)[0])
        self.assertEqual(statuses, ['resolved', 'resolved', 'resolved', 'firing', 'firing'])

    def test_the_clear_side_holds_too_and_a_recrossing_while_clearing_does_not_re_fire(self):
        rule = threshold_rule(self.host)
        self.assertEqual(findings(events_for(rule, FLAP)), ['firing'])
        # A clear that does last `resolve_seconds` is allowed to close.
        self.assertEqual(findings(events_for(rule, [10, 10, 95, 95, 95, 95, 95] + [85] * 5)),
                         ['resolved'])

    def test_an_explicit_resolve_seconds_overrides_the_symmetric_default(self):
        rule = threshold_rule(self.host, resolve_seconds=0)
        self.assertEqual(findings(events_for(rule, [10, 95, 95, 95, 95, 85])), ['resolved'])

    def test_the_step_refuses_a_clock_it_cannot_order(self):
        machine = conditions.SustainedStateMachine(for_seconds=60, clear_seconds=60)
        with self.assertRaises(StateError):
            machine.step('key', true=True, now=dt.datetime(2026, 9, 8, 12, 0))
        self.assertEqual(machine.state_of('key'), 'ok')

    def test_a_mis_dated_crossing_is_pulled_back_to_this_tick(self):
        """A `since` after `now` can neither fire on a negative interval nor park the run forever."""
        machine = conditions.SustainedStateMachine(for_seconds=600, clear_seconds=600)
        self.assertIsNone(machine.step('k', true=True, now=NOW, since=NOW + dt.timedelta(hours=1)))
        self.assertEqual(machine.state_of('k'), 'pending')
        self.assertEqual(machine.step('k', true=True, now=NOW + dt.timedelta(minutes=10)), 'firing')

    def test_a_series_of_foreign_shapes_is_refused_before_anything_is_judged(self):
        rule = threshold_rule(self.host)
        for broken in ([('now', 1.0)], [(NOW.timestamp(), 'hot')],
                       [(NOW.timestamp() - 10, 1.0)] * (conditions.MAX_POINTS + 1)):
            with self.subTest(broken=type(broken[0][0]).__name__), self.assertRaises(StateError):
                conditions.evaluate(rule, broken, now=NOW)


class FlapTests(unittest.TestCase):
    """The claim the card was written for, counted in the platform's own currency: incidents and pages."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.store = Store(self.root / 'state.db')
        self.actor = Actor(SOURCE, 'producer')

    def tick_at(self, position: int) -> dt.datetime:
        """The instant the ``position``-th sample of :data:`FLAP` is judged at."""
        return NOW + dt.timedelta(seconds=STEP * (position - len(FLAP)))

    def drive_baseline(self, rule) -> int:
        """The current product: one `detections.evaluate` call per tick, as `detection_worker` does."""
        booked = 0
        for position in range(1, len(FLAP) + 1):
            at = self.tick_at(position)
            sample = {'sample_id': 'tick-%d' % position, 'observed_at': utc_text(at),
                      'ok': True, 'value': FLAP[position - 1]}
            baseline = {'id': rule.id, 'kind': 'threshold', 'resource_id': rule.resource_id,
                        'source': SOURCE, 'threshold': rule.threshold}
            for item in detections.evaluate(self.index, baseline, sample, now=at):
                booked += 1 if self.store.intake(item, self.actor, now=at).get('transition') else 0
        return booked

    def drive_sustained(self, rule) -> int:
        booked = 0
        for position in range(1, len(FLAP) + 1):
            at = self.tick_at(position)
            for item in conditions.evaluate(rule, points(FLAP[:position], end=at), now=at):
                booked += 1 if self.store.intake(item, self.actor, now=at).get('transition') else 0
        return booked

    def test_the_same_twelve_samples_open_one_condition_and_book_one_delivery(self):
        booked = self.drive_sustained(threshold_rule(self.host))
        self.assertEqual(booked, 1)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual(self.store.status()['notifications'], {'pending': 1})
        newest: dict[str, str] = {}
        for row in self.store.records('events'):        # newest first, so the first sighting per kind wins
            item = json.loads(row['payload'])
            newest.setdefault(item['kind'], item['status'])
        self.assertEqual(newest, {'coverage': 'resolved', 'threshold': 'firing'})
        # 12 ticks × 2 verdicts: the events are not folded away, and that is fine — filing a verdict the
        # platform already holds is one row and no page, which is what makes emitting every tick safe.
        self.assertEqual(len(self.store.records('events')), 24)

    def test_the_baseline_detector_on_the_same_series_opens_three_incidents_and_books_six(self):
        """Measured against `detections.evaluate` on the same twelve samples, in the same store.

        Three incidents opened, three of them closed again, six deliveries booked — and the condition
        is reported *recovered* on the last tick of the run while the value is still oscillating around
        the threshold. Those are the numbers this card removes; they are the product's current
        behaviour, not a strawman built for the assertion.
        """
        booked = self.drive_baseline(threshold_rule(self.host))
        self.assertEqual(booked, 6)
        self.assertEqual(self.store.status()['incidents'], {'resolved': 3})
        self.assertEqual(self.store.status()['notifications'], {'pending': 6})

    def test_a_stale_input_opens_coverage_and_leaves_the_firing_incident_open(self):
        self.drive_sustained(threshold_rule(self.host))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        later = NOW + dt.timedelta(minutes=1)
        emitted = conditions.evaluate(threshold_rule(self.host),
                                      [(NOW.timestamp() - 7200, 10.0)], now=later)
        self.assertEqual([(item['kind'], item['status']) for item in emitted], [('coverage', 'firing')])
        for item in emitted:
            self.store.intake(item, self.actor, now=later)
        # Two open incidents and nothing resolved: the second is the coverage condition the blind tick
        # opened about the signal, and the threshold incident the earlier ticks opened is still open —
        # which is the whole point of filing nothing about the condition on a tick that could not judge.
        self.assertEqual(self.store.status()['incidents'], {'open': 2})

    def test_a_firing_verdict_carries_the_rule_tier_and_its_recovery_carries_none(self):
        loud = findings(events_for(threshold_rule(self.host, severity_tier='critical'),
                                   [10, 95, 95, 95, 95, 95]))
        self.assertEqual(loud, ['firing'])
        quiet = [item for item in events_for(threshold_rule(self.host), FLAP)
                 if item['kind'] != 'coverage']
        self.assertEqual([item['severity'] for item in quiet], ['warning'])
        self.assertEqual([item['severity'] for item in
                          events_for(threshold_rule(self.host), FLAP[:7] + [10] * 6)
                          if item['kind'] != 'coverage'], ['info'])


class AbsenceTests(unittest.TestCase):
    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def test_a_source_that_stops_reporting_fires_the_coverage_kind(self):
        quiet = conditions.verdict(absence_rule(self.host),
                                   points([10] * 4, end=NOW - dt.timedelta(seconds=900)), now=NOW)
        self.assertEqual(quiet.outcome, 'firing')
        self.assertEqual([(item['kind'], item['status']) for item in quiet.events],
                         [('coverage', 'firing')])
        validate_event(quiet.events[0], NOW)

    def test_a_report_that_arrives_resolves_it_again(self):
        result = conditions.verdict(absence_rule(self.host), points([10] * 4), now=NOW)
        self.assertEqual((result.outcome, result.state), ('resolved', 'present'))
        self.assertEqual(result.events[0]['status'], 'resolved')

    def test_a_resource_never_seen_is_named_unseen_and_still_files_something(self):
        result = conditions.verdict(absence_rule(self.host), [], now=NOW)
        self.assertEqual(result.outcome, 'unseen')
        self.assertEqual(result.detail['reason'], 'no point in the read window')
        self.assertEqual([item['status'] for item in result.events], ['firing'])

    def test_absence_files_one_event_because_the_condition_is_itself_the_coverage_verdict(self):
        self.assertEqual(len(conditions.verdict(absence_rule(self.host), points([10] * 3),
                                                now=NOW).events), 1)

    def test_an_availability_rule_judges_a_boolean_and_refuses_a_number(self):
        rule = conditions.rule({'id': 'probe.down', 'mode': 'availability', 'resource_id': self.host,
                                'source': SOURCE, 'severity_source': 'sigma', 'severity_tier': 'high',
                                'for_seconds': 120, 'evaluation_seconds': 60,
                                'history_seconds': 3600})
        down = [(NOW.timestamp() - STEP * i, False) for i in range(4, -1, -1)]
        self.assertEqual(findings(conditions.evaluate(rule, down, now=NOW)), ['firing'])
        with self.assertRaises(StateError):
            conditions.evaluate(rule, points([1, 1, 1, 1, 1]), now=NOW)


class ReadTests(unittest.TestCase):
    """The store seam: two named reads, no SQL, and an empty answer that is not a refusal."""

    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def reader(self, count=20, value=95.0, name='cpu'):
        return InMemoryStore(series(count, name=name, resource_id=self.host,
                                    start=utc_text(NOW - dt.timedelta(seconds=STEP * count)),
                                    step_seconds=STEP, value=value))

    def test_metric_threshold_points_arrive_oldest_first(self):
        reading = conditions.read_points(self.reader(), threshold_rule(self.host, metric='cpu'), end=NOW)
        self.assertEqual(reading.answered, 'ok')
        self.assertFalse(reading.truncated)
        self.assertEqual([value for _, value in reading.points], [95.0] * 20)
        self.assertLess(reading.points[0][0], reading.points[-1][0])
        self.assertLess(reading.points[-1][0], NOW.timestamp(), 'the read window is half-open at the top')

    def test_a_metric_the_store_has_never_seen_is_empty_and_not_a_verdict(self):
        reading = conditions.read_points(InMemoryStore(), threshold_rule(self.host, metric='cpu'), end=NOW)
        self.assertEqual((reading.points, reading.answered), ([], 'empty'))

    def test_a_receipt_that_no_longer_outlives_its_window_is_refused_and_not_read_as_absence(self):
        reading = conditions.read_points(ExpiredReader(self.reader()),
                                        threshold_rule(self.host, metric='cpu'), end=NOW)
        self.assertEqual((reading.points, reading.answered), ([], 'refused'))

    def test_a_span_too_long_for_one_read_is_split_and_says_so(self):
        """2 000 rows is the facade's cap; a 7-day rule can be over it, and the reader must not shrink quietly."""
        rows = series(2000, name='cpu', resource_id=self.host,
                      start=utc_text(NOW - dt.timedelta(seconds=MAX_HISTORY)), step_seconds=302)
        reading = conditions.read_points(InMemoryStore(rows),
                                        threshold_rule(self.host, metric='cpu',
                                                       history_seconds=MAX_HISTORY), end=NOW)
        self.assertEqual(reading.reads, 1 + conditions.MAX_READ_SPANS,
                         'one read cannot return a whole 7-day history at this rate, and the retry is '
                         'bounded: the first span plus this many slices, never a descent')
        self.assertFalse(reading.truncated, 'the split is what the extra reads are for')
        self.assertEqual((reading.answered, len(reading.points)), ('ok', 2000))

    def test_a_read_that_still_does_not_fit_reports_itself_truncated_and_finishes_anyway(self):
        """Four reads is the whole budget: a short memory is stated, not hidden, and not extended.

        What `tick` does with this answer is `DenseRoundTests` business — it is an incomplete read and
        not a series to judge — and this test is only about the reader keeping its budget and its word.
        """
        rows = series(2000, name='cpu', resource_id=self.host,
                      start=utc_text(NOW - dt.timedelta(seconds=STEP * 2000)), step_seconds=STEP)
        reading = conditions.read_points(InMemoryStore(rows),
                                        threshold_rule(self.host, metric='cpu',
                                                       history_seconds=MAX_HISTORY), end=NOW)
        self.assertEqual(reading.reads, 1 + conditions.MAX_READ_SPANS, 'the budget is spent, not grown')
        self.assertTrue(reading.truncated)
        self.assertEqual(reading.answered, 'ok')

    def test_a_heartbeat_read_reports_the_presence_record_it_really_returns(self):
        seeded = InMemoryStore(series(3, name='cpu', resource_id=self.host,
                                      start=utc_text(NOW - dt.timedelta(minutes=3)),
                                      step_seconds=STEP))
        reading = conditions.read_points(seeded, absence_rule(self.host, metric='host.checkins'), end=NOW)
        self.assertEqual((reading.points, reading.answered), ([], 'empty'),
                         'no log rows were seeded, and that is the answer')


class DenseSeriesTests(unittest.TestCase):
    """The bound composition can cross: 2 000 rows per read *and* 2 000 points to judge are one number.

    The card's reproduction is the third test below — 3 600 one-second points over one hour, which four
    honest reads answer as 3 600 complete points with no `truncated` anywhere near them. The reader
    composes *under* the judgment bound instead of over it and then discarding: it weighs each slice
    against what it already holds, so a dense span stops where it is found, empty, `truncated`, and with
    the reads it really spent — never a newest tail trimmed into a verdict. The bound moves nowhere: a
    caller that hand-builds a longer series is still refused outright, which the last test pins, and a
    reader fatter than a page is refused on the spot rather than cut down to fit.
    """

    def setUp(self):
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']

    def rule(self, **overrides):
        document = {'metric': 'cpu', 'history_seconds': 3600, 'evaluation_seconds': 60,
                    'max_age_seconds': 120, 'for_seconds': 180}
        document.update(overrides)
        return threshold_rule(self.host, **document)

    def reading(self, count: int, *, end: dt.datetime = NOW):
        return conditions.read_points(self.store(count, end=end), self.rule(), end=end)

    def store(self, count: int, *, name: str = 'cpu', value: float = 95.0,
              end: dt.datetime = NOW) -> InMemoryStore:
        return InMemoryStore(dense_rows(count, name=name, resource_id=self.host, end=end, value=value))

    def test_the_span_that_fits_the_bound_is_read_completely_and_judged(self):
        """The healthy half of the boundary, stated as numbers: exactly the bound is a verdict."""
        reading = self.reading(conditions.MAX_POINTS)
        self.assertEqual((reading.answered, reading.truncated), ('ok', False),
                         'the slices answered the whole span, so nothing about this read is short')
        self.assertEqual(len(reading.points), conditions.MAX_POINTS)
        self.assertEqual(reading.reads, 1 + conditions.MAX_READ_SPANS,
                         'the retry stays bounded whatever the density: one span plus this many slices')
        self.assertEqual(conditions.verdict(self.rule(), reading.points, now=NOW).outcome, 'firing')

    def test_one_point_over_the_bound_comes_back_empty_and_says_it_is_incomplete(self):
        reading = self.reading(conditions.MAX_POINTS + 1)
        self.assertEqual((reading.answered, reading.points), ('ok', []),
                         'data arrived, so this is not a refusal; it is not judgeable either, and no '
                         'tail chosen by nothing but its length is handed back to be graded')
        self.assertTrue(reading.truncated, 'and the round still gets to name the rule as incomplete')
        self.assertLessEqual(reading.reads, 1 + conditions.MAX_READ_SPANS,
                             'the retry stops at the bound instead of spending the rest of the budget')
        self.assertEqual(reading.covered_s, 3600.0, 'the span asked for is the span it could not hold')

    def test_the_dense_hour_the_card_reproduced_is_bounded_in_points_and_in_reads(self):
        rows = dense_rows(3600, name='cpu', resource_id=self.host, end=NOW)
        self.assertGreater(len(rows), conditions.MAX_POINTS, 'the span really is denser than the bound')
        self.assertEqual(rows[0].timestamp, utc_text(NOW - dt.timedelta(seconds=3600)))
        self.assertEqual(rows[-1].timestamp, utc_text(NOW - dt.timedelta(seconds=1)),
                         'every row sits inside the half-open window the read asks for')
        counting = CountingReader(InMemoryStore(rows))
        reading = conditions.read_points(counting, self.rule(), end=NOW)
        self.assertLessEqual(counting.reads, 1 + conditions.MAX_READ_SPANS,
                             'the query count is bounded across the composition, not per request')
        self.assertEqual(counting.reads, reading.reads, 'every read spent is a read the answer reports')
        self.assertLessEqual(reading.reads, 1 + conditions.MAX_READ_SPANS)
        self.assertLessEqual(len(reading.points), conditions.MAX_POINTS,
                             'and so is the point count of the answer it reports')
        self.assertEqual((reading.answered, reading.truncated), ('ok', True),
                         'incomplete for this evaluator, which is a different answer from "the store '
                         'could not answer" and is reported as the round line either way')

    def test_a_page_fatter_than_the_facade_s_own_is_refused_and_never_trimmed_to_fit(self):
        """An over-full answer is the one input that must not be made judgeable by dropping rows."""
        reading = conditions.read_points(OverFullReader(), self.rule(), end=NOW)
        self.assertEqual((reading.answered, reading.points), ('refused', []),
                         'refused, not ``ok`` with a newest 2 000: nothing this big was ever judgeable, '
                         'and keeping part of it would be the silent shortening this file refuses')
        self.assertTrue(reading.truncated, 'named as an over-full page, not as a clean empty answer')
        self.assertEqual(reading.reads, 1, 'and it is refused on the spot, never re-read in slices')

    def test_the_point_bound_is_still_a_refusal_for_a_series_built_by_hand(self):
        """Nothing was raised, trimmed or downsampled into a verdict: the bound is the same one, and it bites."""
        over = [(NOW.timestamp() - position, 95.0) for position in range(conditions.MAX_POINTS + 1)]
        with self.assertRaises(StateError):
            conditions.evaluate(self.rule(), over, now=NOW)


class ExpiredReader:
    """A facade double that answers the one legal status that is not proof: `expired`."""

    def __init__(self, inner):
        self.inner = inner

    def read(self, *args, **kwargs):
        outcome = self.inner.read(*args, **kwargs)
        return ReadOutcome(status='expired', receipt=outcome.receipt, samples=(),
                           detail='receipt expired')


class TruncatingReader:
    """A facade double that calls its answer short: the same rows, with `truncated` set on the receipt.

    This is the shape of a read the store could not cover whole — a full page of the *oldest* rows, the
    newest ones missing — and a heartbeat rule can never fall into it on its own, because its answer is
    one presence record and no page bound ever marks that truncated. It exists so the incomplete path can
    be asserted for a rule whose honest empty answer would otherwise be a verdict about absence.
    """

    def __init__(self, inner):
        self.inner = inner

    def read(self, *args, **kwargs):
        outcome = self.inner.read(*args, **kwargs)
        return ReadOutcome(status=outcome.status, receipt=replace(outcome.receipt, truncated=True),
                           samples=outcome.samples, detail=outcome.detail)


class OverFullReader:
    """A facade double answering one span with more rows than a page may hold.

    `store.client.build_outcome` refuses such an answer on the way out, so it can only arrive through a
    broken or substituted reader — exactly the reader `read_points` must refuse outright rather than cut
    down to a judgeable size and hand back as a complete series.
    """

    def __init__(self, rows: int = conditions.MAX_POINTS + 1):
        self.rows = rows

    def read(self, query_type, *, window, parameters, selectors=None, **kwargs):
        end = timestamp(window.end)
        samples = [MetricSample(name='cpu', value=95.0, resource_id=parameters['resource_id'],
                                labels={'resource_id': parameters['resource_id']},
                                timestamp=utc_text(end - dt.timedelta(seconds=position + 1)))
                   for position in range(self.rows)]
        return SimpleNamespace(status='available', samples=tuple(samples),
                               receipt=SimpleNamespace(truncated=False))


class TransportReader:
    """A facade double that raises: a store outage must travel, not become an outcome word."""

    def read(self, *args, **kwargs):
        raise RuntimeError('store unreachable')


class TickTests(unittest.TestCase):
    """The durable-cursor round: a refused delivery keeps the verdict, and a window is judged once."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.cursor = self.root / 'conditions.json'
        self.store = Store(self.root / 'state.db')
        self.actor = Actor(SOURCE, 'producer')
        self.now = NOW
        self.config = {'rules': [threshold_rule(self.host, metric='cpu')], 'interval_seconds': 300}

    def reader(self, value=95.0, count=12):
        return InMemoryStore(series(count, name='cpu', resource_id=self.host,
                                    start=utc_text(NOW - dt.timedelta(seconds=STEP * count)),
                                    step_seconds=STEP, value=value))

    def deliver(self, item):
        self.store.intake(item, self.actor, now=self.now)

    def run_tick(self, reader=None, now=NOW):
        self.now = now
        state = conditions.load_cursor(self.cursor, self.config)
        return conditions.tick(self.index, self.config, self.cursor, reader or self.reader(),
                              self.deliver, now=now, state=state)

    def test_a_firing_round_files_both_events_and_leaves_nothing_owed_after_delivery(self):
        summary = self.run_tick()
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(summary['events'], 2)
        self.assertEqual(summary['rules'], {'cpu.high': 'firing'})
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual(json.loads(self.cursor.read_text(encoding='utf-8'))['pending'], None)

    def test_the_same_window_is_never_judged_twice(self):
        self.run_tick()
        self.assertEqual(self.run_tick()['result'], 'idle')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_a_refused_delivery_retains_the_exact_bytes_and_a_restart_replays_them(self):
        """The restart proof: the second round re-sends what the first stored, and judges nothing again."""
        attempts = []

        def refusing(item):
            attempts.append(item)
            raise OSError('intake unreachable')

        with self.assertRaises(OSError):
            conditions.tick(self.index, self.config, self.cursor, self.reader(), refusing,
                            now=NOW, state=conditions.load_cursor(self.cursor, self.config))
        self.assertEqual(len(attempts), 1)
        stored = json.loads(self.cursor.read_text(encoding='utf-8'))
        self.assertEqual(len(stored['pending']['events']), 2)
        replayed = conditions.tick(self.index, self.config, self.cursor, TransportReader(),
                                   self.deliver, now=NOW + dt.timedelta(minutes=30),
                                   state=conditions.load_cursor(self.cursor, self.config))
        self.assertEqual(replayed['result'], 'replayed')
        self.assertEqual(replayed['events'], 2)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual(self.store.status()['notifications'], {'pending': 1})

    def test_a_store_that_cannot_answer_is_a_refusal_and_files_nothing(self):
        summary = self.run_tick(reader=ExpiredReader(InMemoryStore()))
        self.assertEqual(summary['rules'], {'cpu.high': 'unreadable'})
        self.assertEqual(summary['refusals'], 1)
        self.assertEqual(self.store.records('events'), [])

    def test_a_transport_failure_travels_and_the_window_stays_owed(self):
        with self.assertRaises(RuntimeError):
            self.run_tick(reader=TransportReader())
        self.assertFalse(self.cursor.exists())
        self.assertEqual(self.store.records('events'), [])

    def test_an_undeclared_resource_refuses_the_round_before_any_read_happens(self):
        broken = threshold_rule('11111111-1111-4111-8111-111111111111', metric='cpu')
        config = {'rules': [broken], 'interval_seconds': 300}
        counting = CountingReader(self.reader())
        with self.assertRaises(StateError):
            conditions.tick(self.index, config, self.cursor, counting, self.deliver, now=NOW,
                            state=conditions.load_cursor(self.cursor, config))
        self.assertEqual(counting.reads, 0)

    def test_a_cursor_written_by_other_rules_is_refused_rather_than_re_baselined(self):
        self.run_tick()
        other = {'rules': [threshold_rule(self.host, metric='cpu', for_seconds=600)],
                 'interval_seconds': 300}
        with self.assertRaises(StateError):
            conditions.load_cursor(self.cursor, other)

    def test_a_cursor_whose_pending_events_are_not_canonical_is_refused(self):
        def tampering(item):
            self.deliver(item)
            raise OSError('after intake')

        with self.assertRaises(OSError):
            conditions.tick(self.index, self.config, self.cursor, self.reader(), tampering,
                            now=NOW, state=conditions.load_cursor(self.cursor, self.config))
        document = json.loads(self.cursor.read_text(encoding='utf-8'))
        self.assertTrue(document['pending'])
        conditions.load_cursor(self.cursor, self.config)          # coherent: the batch is deliverable
        document['pending']['events'][0]['severity'] = 'catastrophic'
        self.cursor.write_text(json.dumps(document), encoding='utf-8')
        with self.assertRaises(StateError):
            conditions.load_cursor(self.cursor, self.config)


class DenseRoundTests(unittest.TestCase):
    """The end-to-end claim: one dense rule cannot abort a batch, hold back a cursor or page twice.

    Everything here is the product's own path — `conditions.tick` over a built inventory index, a real
    cursor file, the real `read_points` and the in-memory store backend — and the durable facts are read
    back out of a real `Store`. Only `deliver` is a test double, and where a round must not read at all a
    `TransportReader` stands in for the store so a re-judgement would be loud rather than plausible.

    What an incomplete read owes is stated once, here, in four places: it files its own `<rule>.coverage`
    event with the reason, never a verdict about its condition, never a trimmed-down series graded as
    complete, and never the absence an absence rule would have inferred from an empty read.
    """

    def setUp(self):
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.dense = threshold_rule(self.host, id='cpu.dense', metric='cpu', history_seconds=3600,
                                    evaluation_seconds=60, max_age_seconds=120, for_seconds=180)
        self.sparse = threshold_rule(self.host, id='disk.sparse', metric='disk', history_seconds=3600,
                                     evaluation_seconds=60, max_age_seconds=120, for_seconds=180)
        self._fresh_root()

    def _fresh_root(self) -> None:
        """A new index, cursor and state database: one round must not inherit another round's memory."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.cursor = self.root / 'conditions.json'
        self.store = Store(self.root / 'state.db')
        self.actor = Actor(SOURCE, 'producer')
        self.now = NOW

    def reader(self, *, end: dt.datetime = NOW, dense_count: int = 3600) -> InMemoryStore:
        """A dense one-hour `cpu` series beside a sparse one-minute `disk` one — the two rules, one store."""
        rows = dense_rows(dense_count, name='cpu', resource_id=self.host, end=end)
        rows += series(12, name='disk', resource_id=self.host, step_seconds=STEP,
                       start=utc_text(end - dt.timedelta(seconds=STEP * 12)), value=95.0)
        return InMemoryStore(rows)

    def deliver(self, item):
        self.store.intake(item, self.actor, now=self.now)

    def run_round(self, rules, *, reader=None, deliver=None, now: dt.datetime = NOW):
        self.now = now
        self.config = {'rules': list(rules), 'interval_seconds': 300}
        return conditions.tick(self.index, self.config, self.cursor, reader or self.reader(),
                               deliver or self.deliver, now=now,
                               state=conditions.load_cursor(self.cursor, self.config))

    def filed(self) -> list[tuple[str, str]]:
        """Every ``(rule_id, status)`` booked, newest first, read back out of the platform's own table."""
        return [(json.loads(row['payload'])['rule_id'], json.loads(row['payload'])['status'])
                for row in self.store.records('events')]

    def test_a_dense_rule_loses_no_sparse_verdict_and_no_cursor_position_in_either_order(self):
        for order in ([self.dense, self.sparse], [self.sparse, self.dense]):
            with self.subTest(order=[entry.id for entry in order]):
                self._fresh_root()
                summary = self.run_round(order)
                self.assertEqual(summary['result'], 'delivered',
                                 'the round the first build never finished: no batch, no cursor, no verdict')
                self.assertEqual(summary['rules'], {'cpu.dense': 'unreadable', 'disk.sparse': 'firing'})
                self.assertEqual((summary['refusals'], summary['truncated']), (1, ['cpu.dense']),
                                 'the dense rule is named twice — as an incomplete read and in the '
                                 'truncated list — and is not silently given a shorter span to judge')
                self.assertEqual(summary['events'], 3,
                                 'the sparse pair, plus the dense rule saying out loud that it could not '
                                 'be looked at this round')
                self.assertEqual(sorted(summary['detail']), ['cpu.dense', 'disk.sparse'])
                self.assertEqual(set(summary['detail']['cpu.dense']),
                                 {'points', 'reason', 'read', 'window'},
                                 'reported as an incomplete read and nothing more: no value, no state, no '
                                 'detail that reads as a tick which judged something')
                self.assertEqual(summary['detail']['cpu.dense']['points'], 0)
                self.assertIn('more points than this evaluator may judge',
                              summary['detail']['cpu.dense']['reason'])
                self.assertEqual(summary['detail']['disk.sparse']['read'],
                                 {'answered': 'ok', 'truncated': False, 'reads': 1,
                                  'covered_seconds': 3600.0, 'points': 12})
                self.assertEqual(sorted(self.filed()), [('cpu.dense.coverage', 'firing'),
                                                        ('disk.sparse', 'firing'),
                                                        ('disk.sparse.coverage', 'resolved')])
                self.assertEqual(self.store.status()['incidents'], {'open': 2})
                self.assertEqual(self.store.status()['notifications'], {'pending': 2})
                stored = json.loads(self.cursor.read_text(encoding='utf-8'))
                self.assertIsNone(stored['pending'])
                self.assertEqual(stored['last_end'], utc_text(NOW))
                self.assertEqual(self.run_round(order)['result'], 'idle',
                                 'and the window it did deliver is not judged twice')

    def test_a_refused_delivery_owes_the_exact_batch_and_no_invented_dense_condition(self):
        attempts = []

        def refusing(item):
            attempts.append(item)
            raise OSError('intake unreachable')

        with self.assertRaises(OSError):
            self.run_round([self.dense, self.sparse], deliver=refusing)
        self.assertEqual(len(attempts), 1, 'the first event was refused, so the round is owed whole')
        stored = json.loads(self.cursor.read_text(encoding='utf-8'))
        self.assertEqual({item['rule_id'] for item in stored['pending']['events']},
                         {'cpu.dense.coverage', 'disk.sparse', 'disk.sparse.coverage'},
                         'the incomplete rule contributes its own coverage event to the owed batch and no '
                         'verdict about its condition')
        self.assertEqual([item for item in stored['pending']['events']
                          if item['rule_id'] == 'cpu.dense'], [],
                         'there is no dense condition event in the batch to lose, and none to invent')
        self.assertIsNone(stored['last_end'])
        sent = []

        def replayed_by_a_restart(item):
            sent.append(item)
            self.deliver(item)

        replayed = conditions.tick(self.index, self.config, self.cursor, TransportReader(),
                                   replayed_by_a_restart, now=NOW + dt.timedelta(minutes=30),
                                   state=conditions.load_cursor(self.cursor, self.config))
        self.assertEqual((replayed['result'], replayed['events']), ('replayed', 3))
        self.assertEqual([json.dumps(item, sort_keys=True) for item in sent],
                         [json.dumps(item, sort_keys=True) for item in stored['pending']['events']],
                         'the stored bytes go out unchanged, and a reader that would raise proves nothing '
                         'was re-judged on the way')
        self.assertEqual(self.store.status()['incidents'], {'open': 2})
        self.assertEqual(self.store.status()['notifications'], {'pending': 2})
        self.assertEqual(json.loads(self.cursor.read_text(encoding='utf-8'))['last_end'], utc_text(NOW))

    def test_a_round_that_cannot_see_a_condition_it_had_opened_files_nothing_about_it(self):
        """The no-recovery rule, applied to an incomplete read: the coverage moves, the condition does not.

        An incomplete round is not silent and so is not held owed forever — it files its coverage event,
        that event is accepted, and the window is acknowledged. What it may not do is touch the threshold
        condition a judged round opened; and the condition verdict it could not make is not lost in the
        accounting sense either, because every `verdict` here is reconstructed from the trailing history
        the *next* complete read walks.
        """
        self.run_round([self.dense], reader=self.reader(dense_count=2000))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        later = NOW + dt.timedelta(minutes=5)
        summary = self.run_round([self.dense], reader=self.reader(dense_count=3600, end=later), now=later)
        self.assertEqual(summary['rules'], {'cpu.dense': 'unreadable'})
        self.assertEqual(summary['truncated'], ['cpu.dense'])
        self.assertEqual((summary['result'], summary['events']), ('delivered', 1),
                         'blindness is never silence: the round files its own coverage event for it')
        self.assertEqual([status for rule_id, status in self.filed() if rule_id == 'cpu.dense'],
                         ['firing'], 'a read this module could not judge never closes what a read it '
                                     'could judge opened')
        self.assertEqual(self.store.status()['incidents'], {'open': 2},
                         'the coverage incident the blind round opened beside the firing one it left open')
        self.assertEqual(json.loads(self.cursor.read_text(encoding='utf-8'))['last_end'], utc_text(later),
                         'what it did say was delivered, so the window is acknowledged and does not hold '
                         'the round behind it owed forever')

    def test_a_short_read_that_still_fits_the_bound_is_reported_and_never_graded(self):
        """The defect this revision refuses to preserve: 2 000 rows of a 7-day history is not a series.

        The retained points sit exactly on the judgment bound, so nothing about the *composition* was
        over-full — the earlier build judged them and filed a `firing` verdict over a span no wider than
        the store's page. That page is the OLDEST rows, so the fresh tail a `for:` run and a freshness
        check are dated from is the part that is missing, and a missing tail can hide a firing period
        outright rather than merely arrive at it late. Incomplete is the answer, and it is a coverage
        event and no verdict.
        """
        rows = series(2000, name='cpu', resource_id=self.host, step_seconds=STEP,
                      start=utc_text(NOW - dt.timedelta(seconds=STEP * 2000)), value=95.0)
        long_back = threshold_rule(self.host, id='cpu.dense', metric='cpu', history_seconds=MAX_HISTORY,
                                   evaluation_seconds=60, max_age_seconds=120, for_seconds=180)
        summary = self.run_round([long_back], reader=InMemoryStore(rows))
        self.assertEqual(summary['rules'], {'cpu.dense': 'unreadable'})
        self.assertEqual((summary['refusals'], summary['truncated']), (1, ['cpu.dense']))
        self.assertEqual(summary['events'], 1, 'one coverage event, and no verdict about the condition')
        self.assertEqual(summary['detail']['cpu.dense']['read'],
                         {'answered': 'ok', 'truncated': True, 'reads': 1 + conditions.MAX_READ_SPANS,
                          'covered_seconds': float(MAX_HISTORY), 'points': conditions.MAX_POINTS})
        self.assertIn('so nothing is judged', summary['detail']['cpu.dense']['reason'])
        self.assertEqual(self.filed(), [('cpu.dense.coverage', 'firing')])
        self.assertEqual(self.store.status()['incidents'], {'open': 1},
                         'the coverage condition the short read opened, and nothing else')

    def test_the_judged_boundary_is_the_point_bound_itself_and_it_bites_both_ways(self):
        """2 000 complete points are a verdict; 2 001 are an incomplete read. The bound moved nowhere."""
        self.run_round([self.dense], reader=self.reader(dense_count=conditions.MAX_POINTS))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        later = NOW + dt.timedelta(minutes=5)
        summary = self.run_round([self.dense], reader=self.reader(dense_count=conditions.MAX_POINTS + 1,
                                                                 end=later), now=later)
        self.assertEqual((summary['rules'], summary['truncated'], summary['events']),
                         ({'cpu.dense': 'unreadable'}, ['cpu.dense'], 1))
        self.assertEqual([status for rule_id, status in self.filed() if rule_id == 'cpu.dense'],
                         ['firing'], 'the verdict the complete round earned is not moved by the '
                                     'incomplete one that followed it')

    def test_a_complete_read_resolves_the_coverage_an_incomplete_one_opened(self):
        """`unreadable` is not a one-way door: the fix is the data arriving, and it resolves as coverage.

        The same rule, the same store and one point short of the refusal is enough — no bound was raised
        and nothing was downsampled to get from the incomplete round to the judged one.
        """
        first = self.run_round([self.dense], reader=self.reader(dense_count=3600))
        self.assertEqual((first['rules'], first['events'], first['truncated']),
                         ({'cpu.dense': 'unreadable'}, 1, ['cpu.dense']))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        later = NOW + dt.timedelta(minutes=5)
        second = self.run_round([self.dense], reader=self.reader(dense_count=conditions.MAX_POINTS,
                                                                end=later), now=later)
        self.assertEqual(second['rules'], {'cpu.dense': 'firing'})
        self.assertEqual((second['truncated'], second['refusals']), ([], 0))
        self.assertEqual(second['detail']['cpu.dense']['read'],
                         {'answered': 'ok', 'truncated': False, 'reads': 1 + conditions.MAX_READ_SPANS,
                          'covered_seconds': 3600.0, 'points': conditions.MAX_POINTS})
        self.assertEqual(sorted(self.filed()), [('cpu.dense', 'firing'),
                                                ('cpu.dense.coverage', 'firing'),
                                                ('cpu.dense.coverage', 'resolved')])
        self.assertEqual(self.store.status()['incidents'], {'open': 1, 'resolved': 1},
                         'the coverage condition the incomplete round opened is the one the complete '
                         'round closed, and the real verdict is now open in its place')

    def test_a_complete_absence_read_clears_incomplete_coverage_without_hiding_absence(self):
        """Reader recovery and an actually absent signal are independent conditions."""
        quiet = absence_rule(self.host, id='beat.absent', metric='host.checkins',
                             history_seconds=3600, within_seconds=300)
        self.run_round([quiet], reader=TruncatingReader(InMemoryStore()))
        later = NOW + dt.timedelta(minutes=5)
        summary = self.run_round([quiet], reader=InMemoryStore(), now=later)
        self.assertEqual(summary['rules'], {'beat.absent': 'unseen'})
        self.assertEqual(sorted(self.filed()), [('beat.absent', 'firing'),
                                                ('beat.absent.coverage', 'firing'),
                                                ('beat.absent.coverage', 'resolved')])
        self.assertEqual(self.store.status()['incidents'], {'open': 1, 'resolved': 1})
        self.assertEqual(json.loads(self.cursor.read_text(encoding='utf-8'))['last_end'], utc_text(later))

    def test_an_absence_rule_keeps_its_own_verdict_beside_a_dense_sibling(self):
        """The coverage-first rule keeps its teeth, and a dense sibling cannot borrow its condition.

        The absence rule's heartbeat read arrived complete, so its verdict is exactly what it was before
        this card: `unseen`, filed on its own condition id. The dense rule's incomplete round speaks only
        through `<rule>.coverage`, which is a different condition to `Store.intake`.
        """
        quiet = absence_rule(self.host, id='beat.absent', metric='host.checkins',
                             history_seconds=3600, within_seconds=300)
        summary = self.run_round([self.dense, quiet], reader=self.reader(dense_count=3600))
        self.assertEqual(summary['rules'], {'cpu.dense': 'unreadable', 'beat.absent': 'unseen'})
        self.assertEqual(sorted(rule_id for rule_id, _ in self.filed()),
                         ['beat.absent', 'beat.absent.coverage', 'cpu.dense.coverage'])
        self.assertEqual(self.store.status()['incidents'], {'open': 2})

    def test_an_absence_rule_with_an_incomplete_read_never_asserts_the_absence_it_could_not_see(self):
        """The worst shape of the defect: `judge([])` answering on behalf of a read that came back short.

        Nothing is seeded, so the honest heartbeat answer is `empty` — read whole, that is the rule's
        "this resource has never been seen" and it files absence. Reported *short* instead, the read
        cannot say even that: `tick` must not reach `judge` at all, and the only event is the companion
        `<rule>.coverage` one, so no absence incident opens on the strength of a read that could not tell
        whether the signal was arriving.
        """
        quiet = absence_rule(self.host, id='beat.absent', metric='host.checkins',
                             history_seconds=3600, within_seconds=300)
        with mock.patch.object(conditions.Rule, 'judge',
                               side_effect=AssertionError('an incomplete read was judged')) as judged:
            summary = self.run_round([quiet], reader=TruncatingReader(InMemoryStore()))
        self.assertEqual(judged.call_count, 0, 'a read that says it is short is never judged at all')
        self.assertEqual(summary['rules'], {'beat.absent': 'unreadable'})
        self.assertEqual((summary['refusals'], summary['truncated']), (1, ['beat.absent']))
        self.assertEqual([rule_id for rule_id, _ in self.filed()], ['beat.absent.coverage'],
                         'the companion condition only; the absence rule files nothing this round')
        self.assertEqual(summary['detail']['beat.absent']['read'],
                         {'answered': 'empty', 'truncated': True, 'reads': 1 + conditions.MAX_READ_SPANS,
                          'covered_seconds': 3600.0, 'points': 0})
        self.assertIn('so nothing is judged', summary['detail']['beat.absent']['reason'])
        self.assertNotIn('more points', summary['detail']['beat.absent']['reason'],
                         'the reason names a short read, not a span the evaluator could not hold')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})   # coverage, never the absence


class CommandLineTests(unittest.TestCase):
    """`lo-platform conditions`: one round in front of the operator, and off when nothing names a config.

    In-process, following `tests/test_platform_cli.py`: `sys.argv` is swapped, stdout is captured, and the
    store read facade is substituted (`cli.store_reader`) because the product's only series transport is a
    ClickHouse the suite must not reach. Everything else — the index, the database, the cursor file, the
    intake — is real.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.database = self.root / 'state.db'
        self.cursor = self.root / 'conditions-cursor.json'
        self.config = self.root / 'conditions.json'
        self.config.write_text(json.dumps({'interval_seconds': 300, 'rules': [
            {'id': 'cpu.high', 'mode': 'threshold', 'resource_id': self.host, 'source': SOURCE,
             'severity_source': 'sigma', 'severity_tier': 'high', 'threshold': 90, 'metric': 'cpu',
             'for_seconds': 180, 'evaluation_seconds': 60, 'max_age_seconds': 900,
             'history_seconds': 86400}]}), encoding='utf-8')
        self.reader = InMemoryStore(series(20, name='cpu', resource_id=self.host,
                                          start=utc_text(NOW - dt.timedelta(seconds=STEP * 20)),
                                          step_seconds=STEP, value=95.0))

    def run_cli(self, *arguments):
        argv = ['lo-platform', '--database', str(self.database), *arguments]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(cli, 'store_reader',
                                                                    return_value=self.reader), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main()
        return code, json.loads(out.getvalue())

    def test_no_config_named_is_off_and_touches_nothing(self):
        code, result = self.run_cli('conditions')
        self.assertEqual(code, 0)
        self.assertEqual(result, {'status': 'off', 'configured': False})
        self.assertFalse(self.cursor.exists())
        opened = Store(self.database)
        self.assertEqual(opened.records('events'), [])
        self.assertEqual(opened.status()['incidents'], {})

    def test_a_round_files_its_events_and_reports_the_outcome_words(self):
        code, result = self.run_cli('conditions', '--config', str(self.config), '--cursor',
                                    str(self.cursor), '--index', str(self.index),
                                    '--now', utc_text(NOW))
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'delivered')
        self.assertEqual(result['rules'], {'cpu.high': 'firing'})
        self.assertEqual(result['events'], 2)
        self.assertEqual(len(result['intake']), 2)
        self.assertEqual(Store(self.database).status()['incidents'], {'open': 1})

    def test_a_missing_cursor_or_index_is_one_json_line_and_exit_one(self):
        code, result = self.run_cli('conditions', '--config', str(self.config),
                                    '--index', str(self.index))
        self.assertEqual((code, result['status'], result['error_type']), (1, 'error', 'ValueError'))
        code, result = self.run_cli('conditions', '--config', str(self.config),
                                    '--cursor', str(self.cursor))
        self.assertEqual((code, result['status']), (1, 'error'))

    def test_a_cursor_directory_that_does_not_exist_is_refused_before_anything_is_read(self):
        code, result = self.run_cli('conditions', '--config', str(self.config), '--index',
                                    str(self.index), '--cursor', str(self.root / 'nope' / 'c.json'))
        self.assertEqual((code, result['status']), (1, 'error'))
        self.assertEqual(Store(self.database).records('events'), [])


class CountingReader:
    """A store facade double that only counts: used to prove a refusal read nothing."""

    def __init__(self, inner):
        self.inner = inner
        self.reads = 0

    def read(self, *args, **kwargs):
        self.reads += 1
        return self.inner.read(*args, **kwargs)


if __name__ == '__main__':
    unittest.main()

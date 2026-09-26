"""error budget (part 2): the burn as a condition — the truth table, the machine, the event, the rail.

Five claims, each one a way an error-budget alert could be wrong on an operator's desk:

* **The pair is an AND, and the four corners of it are tested.** Long-only burns stay quiet (a burn that
  stopped is not a page), short-only stays quiet (a blip is not a page), both fires, neither stays quiet —
  and an unmeasurable window is a fifth state that is never read as "under threshold". Numbers are
  asserted, not the shape: on the fixture below the long burn is 15.0 and the short is 20.0 against a
  threshold of 14.4.
* **The both-windows rule is held by alert conditions's machine, not by a second one.** A burn that first breaches at
  11:35 is `pending` at 11:35 and `firing` at 11:40 (`for_seconds: 300`), and a burn that clears is held
  firing until the clear run reaches `resolve_seconds`. Eight rounds of one sustained burn open **one**
  incident and book **two** deliveries — one for opening, one for closing — because the three firing
  rounds in the middle share one condition.
* **Re-fire shares one condition key, and that is tested at the store.** The three firing events have
  three different `source_event_id`s (they are three different windows) and one `condition`; intake
  therefore books one delivery, not three. No timestamp enters that key.
* **``INSUFFICIENT_DATA`` reaches the operator as an event.** `kind='coverage'`, `status='firing'`,
  condition ``<objective_id>.coverage`` — the pattern `detections.evaluate` already files — and nothing
  about the budget condition, so a thin window can neither print an attainment nor close a burn.
* **A burn page spends the platform's budget.** With one send per window configured, the first burn page
  goes out and the second is suppressed `flood-circuit-open` with a durable suppression row, because this
  package's only output is an event and the delivery rail is the same one every other alert pays at
  (`notification_safety.reserve`).

Fixture style follows `tests/test_conditions.py` (a real inventory index built from
`examples/inventory/declared.yaml`, the in-memory store backend) and `tests/test_escalation.py` (a real
`Store`, with the delivery facts read back out of its own tables).
"""
import ast
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, utc_text
from local_observe.log import get_logger
from local_observe.slo import alerts, budget
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store, validate_event
from local_observe.store.backends.memory import InMemoryStore, MetricSample, series
from local_observe.store.client import ReadOutcome

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 9, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
SOURCE = 'lo-slo'
RESOURCE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
METRIC = 'demo-availability'
STEP = 60
# The burn fixture's own clock: an outage from 11:25 to 11:50, sampled every minute, on a 300-second grid.
BURN_FROM = NOW - dt.timedelta(seconds=2100)
BURN_TO = NOW - dt.timedelta(seconds=900)


def series_points(count: int = 181, *, step: int = STEP, end: dt.datetime = NOW,
                  bad_from: dt.datetime | None = BURN_FROM,
                  bad_to: dt.datetime | None = BURN_TO) -> list[tuple[float, float]]:
    """A 0/1 availability series on a fixed grid whose newest point sits exactly at *end*.

    A sample is a failed check (0.0) when its instant falls inside ``[bad_from, bad_to]`` and a passing
    one (1.0) otherwise, so a test states when the outage was and nothing else; the default is the
    11:25→11:50 outage the module docstring describes, and `bad_from=None` is a healthy window.
    """
    points = []
    for offset in reversed(range(count)):
        at = end - dt.timedelta(seconds=step * offset)
        bad = bad_from is not None and bad_from <= at <= (bad_to or bad_from)
        points.append((at.timestamp(), 0.0 if bad else 1.0))
    return points


def until(points, at: dt.datetime) -> list[tuple[float, float]]:
    """The points that existed at *at*, which is what a round at that instant could have read."""
    return [point for point in points if point[0] <= at.timestamp()]


def condition(objective_id: str = 'api.availability', **overrides) -> alerts.BurnCondition:
    """One objective: 90 % availability over a day, the 15-minute/5-minute pair at 5x, held for 5 minutes.

    `burn_threshold: 5.0` and `target: 0.9` are chosen so the breach boundary is a whole number of failed
    samples in both windows (8 of 15 in the long one, 3 of 5 in the short one), which is what lets the
    truth table below state its numbers instead of approximating them.
    """
    document = {'objective_id': objective_id, 'resource_id': RESOURCE, 'signal': 'availability',
                'target': 0.9, 'window_days': 1, 'long_window': 900, 'short_window': 300,
                'burn_threshold': 5.0, 'metric': METRIC, 'min_samples': 1,
                'severity_source': 'core-events-v1', 'severity_tier': 'warning',
                'evaluation_seconds': 300, 'for_seconds': 300, 'max_age_seconds': 900}
    document.update(overrides)
    return alerts.rule(document, source=SOURCE)


def policy_for(subject: alerts.BurnCondition) -> budget.FastBurnPolicy:
    """The pure pair for a subject, with the defaults this module's fixture is sized against."""
    return subject.policy


def burn_check(subject: alerts.BurnCondition, points, at: dt.datetime = NOW) -> budget.BurnCheck:
    """The AND, evaluated by the pure function and by nothing else in this repository."""
    return budget.check_fast_burn(subject.policy, points, at.timestamp())


class TruthTableTests(unittest.TestCase):
    """The four corners of the both-windows rule, plus the fifth state that is not a pass."""

    def setUp(self):
        self.subject = condition()

    def check(self, bad_from: dt.datetime | None, bad_to: dt.datetime | None, *,
              count: int = 181, at: dt.datetime = NOW) -> budget.BurnCheck:
        points = series_points(count, bad_from=bad_from, bad_to=bad_to)
        return burn_check(self.subject, points, at)

    def test_neither_window_burning_is_quiet_and_names_two_zero_rates(self):
        check = self.check(None, None)                             # a healthy day, start to finish
        self.assertEqual(check.status, budget.QUIET)
        self.assertAlmostEqual(check.long_burn_rate, 0.0, places=9)
        self.assertAlmostEqual(check.short_burn_rate, 0.0, places=9)

    def test_the_long_window_burning_alone_stays_quiet(self):
        """A burn that started and finished inside the long window is a real burn and not a page."""
        check = self.check(NOW - dt.timedelta(seconds=840), NOW - dt.timedelta(seconds=360))
        self.assertEqual(check.status, budget.QUIET)
        self.assertAlmostEqual(check.long_burn_rate, 6.0, places=6)     # 9 failed of 15 in 900 s, at 0.9
        self.assertAlmostEqual(check.short_burn_rate, 0.0, places=9)    # ... and none in the last 300 s

    def test_the_short_window_burning_alone_stays_quiet(self):
        """Two bad minutes inside an otherwise healthy quarter-hour is the blip the pair exists to hide."""
        check = self.check(NOW - dt.timedelta(seconds=120), NOW)
        self.assertEqual(check.status, budget.QUIET)
        self.assertAlmostEqual(check.short_burn_rate, 6.0, places=6)    # 3 failed of 5
        self.assertAlmostEqual(check.long_burn_rate, 2.0, places=6)     # the same 3 of 15 over the quarter

    def test_both_windows_burning_is_the_firing_case(self):
        """The same objective at the same threshold, one minute after the outage began to reach both."""
        check = self.check(BURN_FROM, BURN_TO, at=NOW - dt.timedelta(minutes=15))
        self.assertEqual(check.status, budget.FIRING)
        self.assertAlmostEqual(check.long_burn_rate, 10.0, places=6)    # 15 of 15 in the long window
        self.assertAlmostEqual(check.short_burn_rate, 10.0, places=6)   # 5 of 5 in the short one
        self.assertEqual(check.threshold, 5.0)
        # And the burn the pair exists to hide: this one ended 15 minutes before the next evaluation.
        self.assertEqual(self.check(BURN_FROM, BURN_TO).status, budget.QUIET)

    def test_a_window_with_no_samples_is_insufficient_rather_than_under_threshold(self):
        """The order of the branches: no data is answered before the AND, or absence would read as health."""
        quiet_before = series_points(31, end=NOW - dt.timedelta(seconds=600))
        check = budget.check_fast_burn(self.subject.policy, quiet_before, NOW.timestamp())
        self.assertEqual(check.status, budget.INSUFFICIENT_DATA)
        self.assertIsNone(check.short_burn_rate)
        self.assertIsNotNone(check.long_burn_rate)
        self.assertEqual(budget.check_fast_burn(self.subject.policy, [], NOW.timestamp()).status,
                         budget.INSUFFICIENT_DATA)

    def test_the_pair_is_the_only_place_the_and_lives(self):
        """`alerts` asks `check.burning` and never compares a rate to a threshold itself."""
        text = (ROOT / 'local_observe' / 'slo' / 'alerts.py').read_text(encoding='utf-8')
        self.assertNotIn('long_burn >', text)
        self.assertNotIn('>= subject.burn_threshold', text)
        self.assertIn('check.burning', text)


class SustainedBurnTests(unittest.TestCase):
    """The predicate is fed to alert conditions's machine, so "held long enough" means here what it means everywhere."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.subject = condition()

    def verdict_at(self, at: dt.datetime, points=None):
        return alerts.verdict(self.subject, until(points or series_points(), at), now=at)

    def test_a_burn_that_just_started_is_pending_and_files_no_firing_condition(self):
        result = self.verdict_at(NOW - dt.timedelta(minutes=25))            # first breaching bucket end
        self.assertEqual(result.outcome, 'pending')
        self.assertEqual(result.state, 'pending')
        self.assertEqual([(item['kind'], item['status']) for item in result.events
                          if item['kind'] != 'coverage'], [('threshold', 'resolved')])

    def test_the_burn_files_once_its_for_duration_has_been_met(self):
        self.assertEqual(self.verdict_at(NOW - dt.timedelta(minutes=20)).outcome, 'firing')
        self.assertEqual(self.verdict_at(NOW - dt.timedelta(minutes=15)).state, 'firing')

    def test_a_burn_that_stopped_is_still_held_until_the_clear_run_completes(self):
        """The symmetric clear side: 11:50 is inside `resolve_seconds` of the last breaching tick."""
        held = self.verdict_at(NOW - dt.timedelta(minutes=10))
        self.assertEqual(held.state, 'clearing')
        self.assertEqual(held.status, 'firing')
        cleared = self.verdict_at(NOW - dt.timedelta(minutes=5))
        self.assertEqual((cleared.state, cleared.status), ('ok', 'resolved'))

    def test_one_burn_is_one_incident_and_two_booked_deliveries_across_eight_rounds(self):
        """Counted in the platform's own currency, over the rounds 11:25 → 12:00 in five-minute steps."""
        root = Path(self.temp.name)
        store_path = root / 'state.db'
        store = Store(store_path)
        actor = Actor(SOURCE, 'producer')
        points = series_points()
        booked = 0
        for minutes in (35, 30, 25, 20, 15, 10, 5, 0):
            at = NOW - dt.timedelta(minutes=minutes)
            for item in alerts.evaluate(self.subject, until(points, at), now=at):
                validate_event(item, at)
                booked += 1 if store.intake(item, actor, now=at).get('transition') else 0
        self.assertEqual(booked, 2, 'one page for opening the burn and one for closing it')
        self.assertEqual(store.status()['incidents'], {'resolved': 1})
        self.assertEqual(store.status()['notifications'], {'pending': 2})

    def test_three_firing_rounds_share_one_condition_and_still_have_three_event_ids(self):
        """The property the brief calls load-bearing, read from the events themselves."""
        points = series_points()
        firing = []
        for minutes in (20, 15, 10):
            at = NOW - dt.timedelta(minutes=minutes)
            firing += [item for item in alerts.evaluate(self.subject, until(points, at), now=at)
                       if item['kind'] != 'coverage' and item['status'] == 'firing']
        self.assertEqual(len(firing), 3)
        self.assertEqual({item['condition'] for item in firing}, {'api.availability'})
        self.assertEqual({item['rule_id'] for item in firing}, {'api.availability'})
        self.assertEqual(len({item['source_event_id'] for item in firing}), 3,
                         'they are three verdicts about three windows; it is the condition that folds them')

    def test_a_zero_for_duration_reproduces_v01_instant_burning(self):
        """The parity case: with no sustain asked for, the first breaching tick is the firing tick."""
        instant = condition(for_seconds=0)
        result = alerts.verdict(instant, until(series_points(), NOW - dt.timedelta(minutes=25)),
                                now=NOW - dt.timedelta(minutes=25))
        self.assertEqual((result.outcome, result.state), ('firing', 'firing'))


class InsufficientDataTests(unittest.TestCase):
    """"We cannot compute this" is a state, and it arrives as the coverage event `detections` files."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.host = declared['resources'][0]['id']
        self.store = Store(self.root / 'state.db')
        self.actor = Actor(SOURCE, 'producer')

    def coverage(self, subject, points, *, at: dt.datetime = NOW):
        emitted = alerts.evaluate(subject, points, now=at)
        for item in emitted:
            validate_event(item, at)
        return emitted

    def test_a_thin_compliance_window_files_coverage_and_still_answers_the_burn_pair(self):
        """Two conditions, two statements: the attainment is not computable, and the budget is not burning.

        Suppressing the burn verdict because the *day* is unreadable would hide a real fast burn behind an
        unrelated thinness, so the coverage event says which half could not be computed. The coverage
        condition is `<objective_id>.coverage`, `kind='coverage'`, `status='firing'` — the words
        `state.validate_event` admits — and never a `resolved` about the budget.
        """
        subject = condition(min_samples=500)                 # the compliance floor is never reached
        emitted = self.coverage(subject, series_points(61))
        self.assertEqual([(item['kind'], item['status']) for item in emitted],
                         [('coverage', 'firing'), ('threshold', 'resolved')])
        self.assertEqual(emitted[0]['condition'], 'api.availability.coverage')
        self.assertEqual(emitted[0]['rule_id'], 'api.availability.coverage')
        self.assertEqual(emitted[0]['evidence'][0]['query_type'], 'source-heartbeat')
        self.assertEqual(emitted[1]['rule_id'], 'api.availability')

    def test_the_verdict_a_real_store_read_of_a_quiet_series_produces_arrives_as_coverage(self):
        """The same `INSUFFICIENT_DATA` through `tick`, with the series seeded in the in-memory backend.

        Three samples 10 minutes ago: fresh enough to judge (inside `max_age_seconds`), empty inside the
        5-minute burn window, and 3 samples against a 1-sample floor — so the pair cannot be measured and
        the round says so with one firing coverage event and no budget verdict at all.
        """
        reader = InMemoryStore(series(3, name=METRIC, resource_id=self.host,
                                      start=utc_text(NOW - dt.timedelta(seconds=600)),
                                      step_seconds=60, value=1.0))
        sent: list = []
        summary = alerts.tick(self.index, {'rules': [condition(resource_id=self.host)],
                                           'interval_seconds': 300, 'cursor': None},
                              self.root / 'cursor.json', reader, sent.append, now=NOW,
                              state={'schema_version': 1, 'binding': None, 'pending': None,
                                     'last_end': None})
        self.assertEqual(summary['objectives']['api.availability'], 'insufficient')
        self.assertEqual(summary['insufficient'], 1)
        self.assertEqual([(item['kind'], item['status']) for item in sent], [('coverage', 'firing')])

    def test_a_stale_series_opens_coverage_and_leaves_an_open_burn_open(self):
        subject = condition(resource_id=self.host)
        points = series_points(bad_from=BURN_FROM, bad_to=BURN_TO)
        firing = [item for item in alerts.evaluate(subject, until(points, NOW - dt.timedelta(minutes=15)),
                                                   now=NOW - dt.timedelta(minutes=15))
                  if item['kind'] != 'coverage']
        for item in firing:
            self.store.intake(item, self.actor, now=NOW - dt.timedelta(minutes=15))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        later = NOW + dt.timedelta(minutes=30)               # nothing new has arrived for half an hour
        blind = self.coverage(subject, until(points, later), at=later)
        self.assertEqual([(item['kind'], item['status']) for item in blind], [('coverage', 'firing')])
        for item in blind:
            self.store.intake(item, self.actor, now=later)
        self.assertEqual(self.store.status()['incidents'], {'open': 2},
                         'the burn is still open beside the coverage condition the blind tick opened')

    def test_every_event_the_package_can_file_passes_the_platform_gate(self):
        subject = condition()
        seen = set()
        for minutes in (35, 25, 20, 15, 10, 0):
            at = NOW - dt.timedelta(minutes=minutes)
            for item in alerts.evaluate(subject, until(series_points(), at), now=at):
                validate_event(item, at)
                seen.add((item['kind'], item['status']))
        self.assertIn(('threshold', 'firing'), seen)
        self.assertIn(('threshold', 'resolved'), seen)
        self.assertIn(('coverage', 'resolved'), seen)
        self.assertTrue({'availability', 'drift', 'anomaly', 'security'} & seen == set(),
                        'this package files threshold and coverage only')


class ConfigTests(unittest.TestCase):
    """The document: what it must name, what it refuses, and what "off" means."""

    def write(self, document) -> Path:
        path = Path(self.temp.name) / 'slo.yaml'
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.objective = {'objective_id': 'api.availability', 'resource_id': RESOURCE,
                          'signal': 'availability', 'target': 0.995, 'window_days': 1,
                          'long_window': 3600, 'short_window': 300, 'burn_threshold': 6.0,
                          'metric': METRIC, 'severity_source': 'core-events-v1',
                          'severity_tier': 'warning'}

    def config(self, *objectives, **top) -> dict:
        document = {'objectives': list(objectives) or [self.objective]}
        document.update(top)
        return alerts.load_config(self.write(document), source=SOURCE)

    def test_the_document_names_the_eight_fields_the_port_carries_and_becomes_one_subject(self):
        parsed = self.config()[ 'rules'][0]
        self.assertEqual(parsed.id, 'api.availability')
        self.assertEqual(parsed.kind, 'threshold')
        self.assertEqual(parsed.query_type, 'metric-threshold')
        self.assertEqual(parsed.severity(), 'warning')
        self.assertEqual(parsed.compliance_seconds, 86_400)
        self.assertEqual(parsed.history_seconds, 87_000)

    def test_the_shipped_example_is_a_document_this_module_accepts(self):
        parsed = alerts.load_config(ROOT / 'examples' / 'platform' / 'slo.yaml', source=SOURCE)
        self.assertEqual([item.objective_id for item in parsed['rules']],
                         ['demo-api.availability', 'demo-api.latency'])
        self.assertEqual([item.severity() for item in parsed['rules']], ['critical', 'warning'])

    def test_a_thirty_day_compliance_window_is_refused_with_the_reason_the_store_gives(self):
        """v0.1's usual window cannot be read here, and saying so at load beats a blind producer."""
        with self.assertRaises(StateError) as refused:
            self.config(dict(self.objective, window_days=7))
        self.assertIn('store facade refuses', str(refused.exception))

    def test_the_window_bound_is_stated_as_a_number_and_not_a_clamp(self):
        for days in (0, 8, 30, True):
            with self.assertRaises(StateError, msg=str(days)):
                self.config(dict(self.objective, window_days=days))

    def test_every_unknown_or_missing_field_is_a_refusal(self):
        for broken in (dict(self.objective, burn_windows=3600),
                       {key: value for key, value in self.objective.items() if key != 'target'},
                       {key: value for key, value in self.objective.items() if key != 'metric'},
                       {key: value for key, value in self.objective.items() if key != 'signal'},
                       dict(self.objective, metric='two words'),
                       dict(self.objective, signal='rum'),
                       dict(self.objective, short_window=3600),
                       dict(self.objective, severity_tier='panic'),
                       dict(self.objective, burn_threshold=0),
                       dict(self.objective, resource_id='api')):
            with self.assertRaises(ValueError, msg=str(sorted(broken))):
                self.config(broken)

    def test_a_latency_objective_needs_the_threshold_and_an_availability_one_refuses_it(self):
        with self.assertRaises(StateError):
            self.config(dict(self.objective, signal='latency'))
        with self.assertRaises(StateError):
            self.config(dict(self.objective, threshold_s=0.3))
        latency = self.config(dict(self.objective, signal='latency', threshold_s=0.3))['rules'][0]
        self.assertEqual(latency.objective.threshold_s, 0.3)

    def test_one_objective_per_id_and_a_bounded_count(self):
        with self.assertRaises(StateError):
            self.config(self.objective, dict(self.objective))
        with self.assertRaises(StateError):
            alerts.load_config(self.write({'objectives': []}), source=SOURCE)
        with self.assertRaises(StateError):
            alerts.load_config(self.write({'objectives': [self.objective] * 17}), source=SOURCE)
        with self.assertRaises(StateError):
            alerts.load_config(self.write({'objectives': [self.objective], 'interval_seconds': 3}),
                               source=SOURCE)
        with self.assertRaises(StateError):
            alerts.load_config(self.write({'objectives': [self.objective], 'rules': []}), source=SOURCE)

    def test_absent_configuration_is_off_and_names_the_variable_once(self):
        with mock.patch.dict('os.environ', {}, clear=True), \
                self.assertLogs('local_observe.slo.alerts', 'INFO') as captured:
            self.assertIsNone(alerts.producer_config())
        self.assertEqual([record.levelname for record in captured.records], ['INFO'],
                         'off is one line, and it is not a warning: nothing is wrong')
        self.assertEqual(captured.records[0].variable, alerts.CONFIG_ENVIRONMENT)

    def test_a_named_but_unreadable_document_is_not_off(self):
        with mock.patch.dict('os.environ', {alerts.CONFIG_ENVIRONMENT: str(Path(self.temp.name) / 'nope'),
                                            alerts.SOURCE_ENVIRONMENT: SOURCE}, clear=True):
            with self.assertRaises((OSError, StateError)):
                alerts.producer_config()
        with mock.patch.dict('os.environ', {alerts.CONFIG_ENVIRONMENT: str(self.write(
                {'objectives': [self.objective]}))}, clear=True):
            with self.assertRaises(StateError):
                alerts.producer_config()          # no producer identity: the platform records who said it


class ReadTests(unittest.TestCase):
    """The series comes from store facade's facade: one named read, scoped, narrowed, and honest when thin."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']
        self.subject = condition(resource_id=self.host)

    def seeded(self, count: int = 60, *, value: float = 1.0, name: str = METRIC, minutes: int = 60,
               step: int = 60):
        return InMemoryStore(series(count, name=name, resource_id=self.host, step_seconds=step,
                                    start=utc_text(NOW - dt.timedelta(minutes=minutes)), value=value))

    def test_one_read_names_the_series_and_the_declared_resource_and_no_second_transport(self):
        reading = alerts.read_series(self.seeded(), self.subject, end=NOW)
        self.assertEqual(reading.answered, 'ok')
        self.assertEqual(len(reading.points), 60)
        self.assertEqual(reading.points[-1][1], 1.0)
        self.assertEqual(reading.reads, 1)
        self.assertEqual(reading.covered_s, self.subject.history_seconds)

    def test_the_request_the_package_makes_is_the_request_the_facade_approves(self):
        seen: dict = {}

        class Spy(InMemoryStore):
            def read(self, query_type, *, window, parameters, selectors=None, **kwargs):
                seen.update(query_type=query_type, window=window, parameters=parameters,
                            selectors=selectors)
                return super().read(query_type, window=window, parameters=parameters,
                                    selectors=selectors, **kwargs)

        alerts.read_series(Spy(series(2, name=METRIC, resource_id=self.host,
                                      start=utc_text(NOW - dt.timedelta(minutes=5)))),
                           self.subject, end=NOW)
        self.assertEqual(seen['query_type'], 'metric-threshold')
        self.assertEqual(seen['parameters'], {'resource_id': self.host, 'rule_id': 'api.availability'})
        self.assertEqual(seen['selectors'], {'metric_name': METRIC})
        self.assertLessEqual((seen['window'].instant('end') - seen['window'].instant('start')).total_seconds(),
                             alerts.MAX_HISTORY_SECONDS)

    def test_a_series_the_store_has_never_seen_is_an_answer_about_absence_not_an_empty_list(self):
        reading = alerts.read_series(InMemoryStore(), self.subject, end=NOW)
        self.assertEqual(reading.answered, 'empty')
        self.assertEqual(reading.points, [])

    def test_a_store_that_cannot_answer_fails_the_round_rather_than_answering_absence(self):
        class Refused(InMemoryStore):
            def read(self, *args, **kwargs):
                raise RuntimeError('transport down')

        with self.assertRaises(RuntimeError):
            alerts.read_series(Refused(), self.subject, end=NOW)

    def test_a_full_page_is_reported_truncated_because_it_is_the_oldest_rows_that_arrived(self):
        """The facade returns the head of a rising series; the burn windows need its tail."""
        # 2 000 samples at 30 s fills the facade's page and stops 27 030 s short of the judged instant.
        reading = alerts.read_series(self.seeded(count=2000, minutes=87000 // 60, step=30), self.subject,
                                     end=NOW)
        self.assertTrue(reading.truncated)
        self.assertEqual(len(reading.points), budget.MAX_SAMPLES)
        # The page stops where the row bound stops it: the newest sample that arrived is 27 030 seconds
        # (7 h 30 m) before the instant being judged, and the samples that would answer the burn windows
        # are the ones the facade dropped.
        self.assertAlmostEqual(NOW.timestamp() - reading.points[-1][0], 27_030, delta=1)

    def test_a_row_that_names_no_instant_fails_the_round_rather_than_dropping_a_point(self):
        """A point dropped quietly shortens the window an attainment claims to span, so it is a refusal."""
        class Broken(InMemoryStore):
            def read(self, query_type, **kwargs):
                outcome = super().read(query_type, **kwargs)
                return ReadOutcome(status='available', receipt=outcome.receipt,
                                   samples=(MetricSample(name=METRIC, value=1.0, timestamp='',
                                                         resource_id=RESOURCE),))

        with self.assertRaises(StateError):
            alerts.read_series(Broken(series(1, name=METRIC, resource_id=self.host,
                                            start=utc_text(NOW - dt.timedelta(minutes=5)))),
                               self.subject, end=NOW)


class TickTests(unittest.TestCase):
    """One round: the index decides first, the cursor decides last, and a refused delivery is retried."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.cursor = self.root / 'slo-cursor.json'
        self.subject = condition(resource_id=self.host)
        self.config = {'rules': [self.subject], 'interval_seconds': 300, 'cursor': None}
        self.reader = InMemoryStore(series(60, name=METRIC, resource_id=self.host,
                                           start=utc_text(NOW - dt.timedelta(minutes=60)),
                                           step_seconds=60, value=0.0))

    def run_tick(self, *, at: dt.datetime = NOW, reader=None, deliver=None):
        sent: list = []
        sink = deliver or sent.append
        state = alerts.cursor_document(self.cursor, self.config)
        summary = alerts.tick(self.index, self.config, self.cursor, reader or self.reader, sink,
                              now=at, state=state)
        summary['sent'] = sent
        return summary

    def test_a_burning_store_delivers_two_events_and_moves_the_cursor_only_after_both(self):
        summary = self.run_tick()
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(summary['events'], len(summary['sent']))
        self.assertEqual(summary['objectives']['api.availability'], 'firing')
        stored = json.loads(self.cursor.read_text(encoding='utf-8'))
        self.assertEqual(stored['pending'], None)
        self.assertEqual(stored['last_end'], utc_text(NOW))

    def test_a_round_that_is_refused_keeps_its_bytes_and_replays_them_before_judging_anything(self):
        """The delivery decision is not the producer's, and neither is the right to forget a verdict."""
        attempts: list = []

        def refusing(item):
            attempts.append(item)
            raise RuntimeError('intake down')

        with self.assertRaises(RuntimeError):
            self.run_tick(deliver=refusing)
        pending = json.loads(self.cursor.read_text(encoding='utf-8'))
        self.assertIsNotNone(pending['pending'], 'the batch is on disk, not in a terminal buffer')
        self.assertEqual(len(pending['pending']['events']), 2)
        self.assertIsNone(pending['last_end'])
        replayed = self.run_tick()
        self.assertEqual(replayed['result'], 'replayed')
        self.assertEqual((len(attempts), replayed['events']), (1, 2),
                         'the stored bytes are offered again, unchanged, before anything new is judged')
        self.assertEqual(json.loads(self.cursor.read_text(encoding='utf-8'))['last_end'], utc_text(NOW))

    def test_the_same_grid_position_is_judged_once(self):
        self.run_tick()
        again = self.run_tick()
        self.assertEqual(again['result'], 'idle')
        self.assertEqual(again['events'], 0)

    def test_an_undeclared_resource_refuses_the_round_before_any_read_runs(self):
        self.config['rules'] = [condition(resource_id='11111111-1111-4111-8111-111111111111')]
        with self.assertRaises(StateError):
            self.run_tick()

    def test_a_truncated_read_files_coverage_and_prints_no_attainment(self):
        dense = InMemoryStore(series(2000, name=METRIC, resource_id=self.host, step_seconds=30,
                                     start=utc_text(NOW - dt.timedelta(seconds=87_000)), value=0.0))
        summary = self.run_tick(reader=dense)
        self.assertEqual(summary['objectives']['api.availability'], 'truncated')
        self.assertEqual(summary['truncated'], ['api.availability'])
        self.assertEqual(summary['detail']['api.availability']['reason'],
                         'read hit the store row bound; the newest samples are not in it')
        self.assertNotIn('attainment', summary['detail']['api.availability'])
        self.assertEqual(len(summary['sent']), 1)
        self.assertEqual((summary['sent'][0]['kind'], summary['sent'][0]['status']),
                         ('coverage', 'firing'))

    def test_a_read_the_store_cannot_answer_fails_the_round_and_leaves_the_cursor_where_it_was(self):
        class Refusing:
            def read(self, *args, **kwargs):
                raise KeyError('no store')

        with self.assertRaises(KeyError):
            self.run_tick(reader=Refusing())
        self.assertFalse(self.cursor.exists(), 'a round that never judged owes nothing')

    def test_the_round_summary_carries_every_field_the_worker_log_line_is_built_from(self):
        summary = self.run_tick()
        line = alerts.summary_line(summary)
        self.assertEqual(sorted(line), ['events', 'insufficient', 'objectives', 'refusals', 'result',
                                        'truncated'])


class DeliveryRailTests(unittest.TestCase):
    """Task 5's proof, read from the path rather than asserted about it: a burn page spends the budget."""

    # The burn is measured at 11:45 (5 minutes of headroom against the policy's own event-age bound);
    # the rail is driven at 11:50, inside `max_event_age_seconds` of the verdict it is delivering.
    PAGE_AT = NOW - dt.timedelta(minutes=15)
    SEND_AT = NOW - dt.timedelta(minutes=10)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db',
                           NotificationPolicy(delivery_mode='live', max_attempts=1))
        self.actor = Actor(SOURCE, 'producer')
        self.provider = _Sink()

    def page(self, objective_id: str) -> list[dict]:
        """Intake one firing burn verdict for `objective_id`, through the events this package emits."""
        points = series_points(bad_from=BURN_FROM, bad_to=BURN_TO)
        events = alerts.evaluate(condition(objective_id=objective_id), until(points, self.PAGE_AT),
                                 now=self.PAGE_AT)
        firing = [item for item in events if item['kind'] != 'coverage']
        self.assertEqual([(item['status']) for item in firing], ['firing'], 'the fixture must really burn')
        for item in events:
            self.store.intake(item, self.actor, now=self.PAGE_AT)
        return firing

    def test_the_second_burn_page_is_suppressed_by_the_latched_breaker_and_recorded(self):
        self.page('api.availability')
        first = _deliver(self.store, self.provider, at=self.SEND_AT)
        self.assertEqual(first['status'], 'sent')
        self.page('search.availability')
        second = _deliver(self.store, self.provider, at=self.SEND_AT)
        self.assertEqual((second['status'], second['reason']), ('suppressed', 'flood-circuit-open'))
        self.assertEqual(len(self.provider.calls), 1, 'the second page never reached the channel')
        self.assertTrue(self.store.notification_safety_status()['circuit_open'])
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute(
                'SELECT count(*) FROM notification_suppressions').fetchone()[0], 1)

    def test_a_burn_that_keeps_burning_books_no_second_page_at_all(self):
        """The other half of the same budget: intake, not the breaker, is what stays quiet here."""
        points = series_points(bad_from=BURN_FROM, bad_to=BURN_TO)
        booked = 0
        for minutes in (20, 15, 10):
            at = NOW - dt.timedelta(minutes=minutes)
            for item in alerts.evaluate(condition(), until(points, at), now=at):
                booked += 1 if self.store.intake(item, self.actor, now=at).get('transition') else 0
        self.assertEqual(booked, 1)
        self.assertEqual(self.store.status()['notifications'], {'pending': 1})
        self.assertEqual(self.store.status()['incidents'], {'open': 1})


class SurfaceTests(unittest.TestCase):
    """What the package does not contain, pinned as a test rather than as a claim in a report.

    Read as syntax, not as text: these files' docstrings discuss the delivery rail in prose (task 5 asks
    for that paragraph), so the check that matters is what the package *imports and calls*. The AST
    technique is `tests/test_intake.py::SurfaceTests`'s, for the same reason: a grep would fire on the
    sentence that explains the rule.
    """

    #: Modules this package may never reach: the delivery rail and everything mounted on it.
    #: `platform.state` is deliberately absent: importing `StateError`/`label` from it is the same thing
    #: every producer here does, and `state.py`'s own send path is reached only by the notify worker.
    FORBIDDEN_IMPORTS = ('local_observe.platform.notifications', 'local_observe.platform.telegram',
                         'local_observe.platform.channels', 'local_observe.platform.notification_safety',
                         'local_observe.platform.escalation', 'local_observe.platform.telegram')
    #: Names that, called, would mean this package sent or suppressed something itself.
    FORBIDDEN_CALLS = ('claim_notification', 'finish_notification', 'retry_notification', 'deliver_one',
                       'reserve', 'reserve_route', 'latch_circuit', 'send')

    def setUp(self):
        self.trees = {path.name: ast.parse(path.read_text(encoding='utf-8'))
                      for path in sorted((ROOT / 'local_observe' / 'slo').glob('*.py'))}
        self.assertTrue(self.trees)

    def imports(self) -> list[tuple[str, str]]:
        """Every (file, dotted module) pair the package imports, late imports inside functions included."""
        found: list[tuple[str, str]] = []
        for name, tree in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found += [(name, item.name) for item in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    found += [(name, node.module)] + [(name, node.module + '.' + item.name)
                                                      for item in node.names]
        return found

    def string_constants(self) -> list[tuple[str, str]]:
        """Every string literal in the package, with the file it sits in (docstrings are not literals)."""
        found: list[tuple[str, str]] = []
        for name, tree in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    found.append((name, node.value))
        return found

    def test_no_delivery_module_is_imported_anywhere_in_the_package(self):
        hits = sorted({where + ': ' + target for where, target in self.imports()
                       if target in self.FORBIDDEN_IMPORTS
                       or any(target.startswith(prefix + '.') for prefix in self.FORBIDDEN_IMPORTS)})
        self.assertEqual(hits, [], 'a second door to a human channel would bypass the per-channel budget')

    def test_no_delivery_function_is_called(self):
        called = set()
        for name, tree in self.trees.items():
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    label = getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)
                    if label in self.FORBIDDEN_CALLS:
                        called.add(name + ': ' + str(label))
        self.assertEqual(sorted(called), [])

    def test_no_severity_literal_is_spelled_in_the_package(self):
        hits = sorted({where + ': ' + value for where, value in self.string_constants()
                       if value in ('critical', 'warning', 'error', 'info')})
        self.assertEqual(hits, [],
                         'cite platform/vocabulary.severity and let detections.event derive the rest')

    def test_the_only_event_kind_this_package_names_is_the_one_the_crosswalk_row_gives_it(self):
        """`threshold` is named once, and no event is built here except through `conditions`' builders."""
        self.assertEqual(alerts.BURN_KIND, 'threshold')
        self.assertEqual(alerts.BURN_QUERY_TYPE, 'metric-threshold')
        kinds: list[str] = []
        for name, tree in self.trees.items():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
                    continue
                named = any(getattr(target, 'id', '').endswith('KIND') for target in node.targets)
                if named and node.value.value in ('availability', 'coverage', 'threshold', 'drift',
                                                   'anomaly', 'security'):
                    kinds.append(name + ': ' + str(node.value.value))
        self.assertEqual(sorted(kinds), ['alerts.py: threshold'])
        # And the package never calls the event factory itself: `conditions`' two builders are the door.
        built = sorted(name for name, tree in self.trees.items()
                       for node in ast.walk(tree)
                       if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'event')
        self.assertEqual(built, [])

    def test_the_package_writes_no_sql_and_opens_no_second_transport(self):
        for forbidden in ('SELECT ', 'INSERT ', 'CREATE TABLE'):
            with self.subTest(token=forbidden):
                hits = sorted(name for name, tree in self.trees.items() if forbidden in ast.unparse(tree))
                self.assertEqual(hits, [])
        # `sqlite3` is absent from this list on purpose: `__main__.py` imports it to *catch* the index's
        # OperationalError, exactly as `configdrift` and `pathcheck` do, and writes no statement.
        for module in ('urllib', 'requests', 'http.client', 'socket', 'subprocess'):
            with self.subTest(module=module):
                hits = sorted(name for name, target in self.imports()
                              if target == module or target.startswith(module + '.'))
                self.assertEqual(hits, [])
        # The one network call in the package is the platform's own event door, and it lives in the worker.
        intake = sorted(name for name, target in self.imports() if target == 'local_observe.http')
        self.assertEqual(intake, ['__main__.py'])
        self.assertEqual(ast.unparse(self.trees['__main__.py']).count("request('POST', '/v1/events'"), 1)


def _deliver(store, provider, *, at: dt.datetime) -> dict:
    """One turn of the delivery rail, imported lazily so this module does not import it at all."""
    from local_observe.platform.notifications import deliver_one
    return deliver_one(store, provider, now=at)


class _Sink:
    """A channel that records every call it was given; the count is the proof nothing else went out."""

    def __init__(self):
        self.calls: list = []

    def request(self, method, *, payload, headers):
        self.calls.append(payload)
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


class WorkerTests(unittest.TestCase):
    """The off switch and the start-up refusals, in the shape every other producer here uses."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_main_reports_off_and_writes_nothing(self):
        from local_observe.slo import __main__ as worker
        with mock.patch.dict('os.environ', {}, clear=True), \
                self.assertLogs('local_observe.slo.alerts', 'INFO') as captured:
            self.assertEqual(worker.main(), 0)
        self.assertEqual(captured.records[0].variable, alerts.CONFIG_ENVIRONMENT)
        self.assertEqual(list(self.root.iterdir()), [], 'off opens no file')

    def test_a_configured_producer_without_a_cursor_refuses_to_start(self):
        from local_observe.slo import __main__ as worker
        document = self.root / 'slo.yaml'
        document.write_text(json.dumps({'objectives': [{
            'objective_id': 'api.availability', 'resource_id': RESOURCE, 'signal': 'availability',
            'target': 0.99, 'window_days': 1, 'long_window': 3600, 'short_window': 300,
            'burn_threshold': 6.0, 'metric': METRIC, 'severity_source': 'core-events-v1',
            'severity_tier': 'warning'}]}), encoding='utf-8')
        base = {alerts.CONFIG_ENVIRONMENT: str(document), alerts.SOURCE_ENVIRONMENT: SOURCE}
        cursor = self.root / 'cursor.json'
        refusals = [({}, 'StateError', 'no LO_SLO_CURSOR named'),
                    ({alerts.CURSOR_ENVIRONMENT: 'relative.json'}, 'StateError',
                     'a relative path is not a durable location'),
                    ({alerts.CURSOR_ENVIRONMENT: str(self.root / 'missing' / 'cursor.json')},
                     'StateError', 'the operator creates the parent'),
                    ({alerts.CURSOR_ENVIRONMENT: str(cursor)}, 'KeyError',
                     'no platform url or token: a refusal, never a send')]
        for extra, raised, why in refusals:
            with self.subTest(reason=why), \
                    mock.patch.dict('os.environ', dict(base, **extra), clear=True), \
                    self.assertLogs('local_observe.slo.__main__', 'WARNING') as captured:
                self.assertEqual(worker.main(), 1)
            self.assertEqual(captured.records[0].error_class, raised,
                             'the start-up line names the exception class and nothing else')
        self.assertFalse(cursor.exists(), 'a refused start writes no cursor')


if __name__ == '__main__':
    unittest.main()

"""forecast: a forecast is an ordinary event, and the only thing it adds is the word *predicted*.

This file pins the one question the brief said to stop and report if the answer was not there: **can
"will exceed" be told apart from "has exceeded" inside the vocabulary `state.EVENT_KINDS` admits?**
The answer `ForecastRule` gives is the mechanism this repository already uses twice — a condition
namespace. `detections.evaluate` files ``<rule>.coverage`` beside ``<rule>``, `escalation.stage_event`
files ``<rule>.stage2``, and this files ``<rule>.predicted``. The test that makes that more than a
claim runs a forecast rule and the base threshold rule **over one store through one intake** and
asserts the platform booked two conditions and two incidents, and that when the series actually
crosses the predicted condition is the one that closes. A page whose name does not say which of the
two it is would be worse than no forecast, so the pairing is asserted as numbers, not as prose.

The rest is the discipline the brief named:

* the sustained path is `conditions.SustainedStateMachine` — spied on, so a re-implementation fails —
  and one spiky sample does **not** open a condition;
* every event passes `state.validate_event`, and no severity literal appears in the package: loudness
  arrives from the rule's `severity_source`/`severity_tier` through the crosswalk;
* the refusals (`flat`, `receding`, `insufficient`, `already`, out of horizon) produce coverage or a
  resolved verdict, never a "will exceed";
* the producer ships off, and `vocabulary.REFUSALS` still refuses v0.1's `forecast.threshold_predicted`
  type: this port files the admitted kind and did not widen the vocabulary to fit itself.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from local_observe.forecast import __main__ as worker
from local_observe.forecast import models, timetothreshold
from local_observe.http import TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import conditions, vocabulary
from local_observe.platform.state import EVENT_KINDS, Actor, StateError, Store, validate_event
from local_observe.store.backends.memory import InMemoryStore
from local_observe.store.client import MetricSample

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'local_observe' / 'forecast'
NOW = timestamp('2026-09-08T12:00:00Z')
STEP = 300
SOURCE = 'lo-forecast'
THRESHOLD = 54.0
HOST = read_document(ROOT / 'examples/inventory/declared.yaml')['resources'][0]['id']
#: The newest sample of every default fixture sits one step inside the store's half-open read window:
#: a row stamped exactly at ``end`` belongs to the next window (`store/backends/memory.py`'s own rule),
#: and a fixture that silently lost its newest point to that rule would be testing a shorter series
#: than its name says.
EDGE = NOW - dt.timedelta(seconds=STEP)
#: The fixture's own crossing instant: 40 samples, +1 every 300 s, newest (49) at `EDGE`, so the line
#: reaches 54 at NOW + 1200 s. Every ETA assertion below reads that number.
RAMP_ETA = NOW.timestamp() + 1200


def laid(values, *, end: dt.datetime = EDGE, step: int = STEP):
    """Put values on a *step* grid whose newest point sits at *end* (one step inside the read window)."""
    return [(end.timestamp() - step * (len(values) - 1 - i), float(value))
            for i, value in enumerate(values)]


def ramp(count=40, *, start_value=10, end: dt.datetime = EDGE, step: int = STEP):
    """A clean rising series: +1 per step, newest sample one step before *end*."""
    return laid([start_value + i for i in range(count)], end=end, step=step)


def flat(value=10.0, count=40, *, end: dt.datetime = EDGE, step: int = STEP):
    """A series that goes nowhere, so the only honest forecast about it is a refusal."""
    return laid([value] * count, end=end, step=step)


def falling(count=40, *, start_value=60, end: dt.datetime = EDGE, step: int = STEP):
    """A series receding from the limit — v0.1's `receding` refusal, as data."""
    return laid([start_value - i for i in range(count)], end=end, step=step)


def rule_document(**overrides):
    """One forecast rule document, in the shape `examples/platform/forecast.yaml` uses."""
    document = {'id': 'pool-disk', 'series': 'disk_used', 'resource_id': HOST, 'source': SOURCE,
                'severity_source': 'core-events-v1', 'severity_tier': 'warning',
                'threshold': THRESHOLD, 'model': 'linear', 'horizon_seconds': 3600,
                'min_points': 4, 'evaluation_seconds': STEP, 'history_seconds': 86400,
                'max_age_seconds': 3600, 'for_seconds': 600}
    document.update(overrides)
    return document


def forecast_rule(**overrides):
    """Return one validated `ForecastRule`, built the way the loader builds it."""
    return timetothreshold.rule(rule_document(**overrides))


def rows_for(points, *, name='disk_used', resource_id=HOST):
    """Turn ``(epoch, value)`` pairs into store rows, so the fixture reads like production."""
    return [MetricSample(name=name, value=float(value), resource_id=resource_id,
                         labels={'resource_id': resource_id},
                         timestamp=utc_text(dt.datetime.fromtimestamp(epoch, dt.timezone.utc)))
            for epoch, value in points]


class RoundFixture(unittest.TestCase):
    """One round of the producer delivered into a real `Store` — the shape `conditions.tick` runs.

    Subclasses inherit `run_round` and the read-back helpers; this class itself holds no tests, so the
    names below are the assertions and this is the harness they share.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.store = Store(self.root / 'state.db')
        self.actor = Actor(SOURCE, 'producer')
        self.cursor = self.root / 'forecast.json'

    def config(self, rules, interval=STEP):
        return {'rules': list(rules), 'interval_seconds': interval}

    def run_round(self, config, points, *, now=NOW, rows=None):
        reader = InMemoryStore(rows if rows is not None else rows_for(points, resource_id=self.host))
        return conditions.tick(self.index, config, self.cursor, reader,
                               lambda item: self.store.intake(item, self.actor, now=now), now=now,
                               state=conditions.load_cursor(self.cursor, config))

    def events(self):
        return [json.loads(row['payload']) for row in self.store.records('events')]

    def condition_events(self):
        """Everything filed about a condition — the coverage companion is the platform's health signal."""
        return [item for item in self.events() if item['kind'] != 'coverage']

    def pairs(self):
        return {(item['rule_id'], item['status']) for item in self.condition_events()}

    def incidents(self, status: str = 'open') -> int:
        """How many incidents the platform holds in one state (`status()` counts open ones only)."""
        return len([row for row in self.store.records('incidents') if row['status'] == status])


class VocabularyTests(RoundFixture):
    """The event: an admitted `kind`, and the difference carried in the condition identity."""

    def test_the_rule_names_an_admitted_kind_and_never_a_new_one(self):
        rule = forecast_rule()
        self.assertIn(rule.kind, EVENT_KINDS)
        self.assertEqual((rule.kind, rule.query_type), ('threshold', 'metric-threshold'))
        self.assertEqual((rule.id, rule.rule_id, rule.mode),
                         ('pool-disk.predicted', 'pool-disk', 'forecast'))

    def test_v0_1_forecast_type_is_still_refused_because_this_port_did_not_widen_anything(self):
        """The refusal row is load-bearing: it says which decision is still open, and this package
        files the admitted word instead of quietly answering the question for the owner."""
        with self.assertRaises(vocabulary.VocabularyError) as caught:
            vocabulary.classify('core-events-v1', 'forecast.threshold_predicted')
        message = str(caught.exception)
        self.assertIn('refused by design', message)
        self.assertIn('forecast owes a decision', message)

    def test_predicted_and_exceeded_are_two_conditions_and_the_breach_closes_the_forecast(self):
        """The brief's central claim, as numbers: two rule ids, two incidents, one fact each."""
        base = conditions.rule({'id': 'pool-disk', 'mode': 'threshold', 'resource_id': self.host,
                                'source': SOURCE, 'severity_source': 'core-events-v1',
                                'severity_tier': 'warning', 'threshold': THRESHOLD, 'for_seconds': 0,
                                'evaluation_seconds': STEP, 'history_seconds': 86400,
                                'max_age_seconds': 3600, 'metric': 'disk_used'})
        config = self.config([forecast_rule(), base])
        summary = self.run_round(config, ramp())
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'firing', 'pool-disk': 'resolved'})
        self.assertEqual(self.pairs(), {('pool-disk.predicted', 'firing'), ('pool-disk', 'resolved')})
        self.assertEqual(self.incidents(), 1)
        self.assertEqual(self.incidents('resolved'), 0)

        # The ramp continues until the limit is actually crossed: the base rule's verdict is the one
        # with standing now, and the forecast's condition is the one that closes.
        later = NOW + dt.timedelta(seconds=2400)
        summary = self.run_round(config, ramp(count=48, end=later - dt.timedelta(seconds=STEP)),
                                 now=later)
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'resolved', 'pool-disk': 'firing'})
        self.assertEqual(self.incidents(), 1)
        self.assertEqual(self.incidents('resolved'), 1)
        by_rule: dict[str, list] = {}
        for item in self.condition_events():
            by_rule.setdefault(item['rule_id'], set()).add(item['status'])
        self.assertEqual(by_rule, {'pool-disk.predicted': {'firing', 'resolved'},
                                   'pool-disk': {'firing', 'resolved'}})
        self.assertEqual(len({item['rule_id'] for item in self.events()}), 4)   # two rules, two coverages

    def test_the_predicted_rule_id_survives_intake_as_its_own_condition(self):
        self.run_round(self.config([forecast_rule()]), ramp())
        event = self.condition_events()[0]
        self.assertEqual((event['rule_id'], event['condition']),
                         ('pool-disk.predicted', 'pool-disk.predicted'))
        self.assertEqual(event['evidence'][0]['parameters']['rule_id'], 'pool-disk.predicted')
        self.assertEqual(event['evidence'][0]['query_type'], 'metric-threshold')
        self.assertTrue(event['source_event_id'])


class SeverityTests(RoundFixture):
    """Nothing here spells a severity: the crosswalk answers for the rule's own two config fields."""

    def test_the_firing_severity_is_what_the_crosswalk_says_for_the_configured_word(self):
        for tier, expected in (('warning', 'warning'), ('error', 'warning'), ('critical', 'critical')):
            with self.subTest(tier=tier):
                self.assertEqual(vocabulary.severity('core-events-v1', tier), expected)
                verdict = timetothreshold.verdict(forecast_rule(severity_tier=tier), ramp(), now=NOW)
                event = verdict.events[-1]
                self.assertEqual((event['status'], event['severity']), ('firing', expected))

    def test_a_quieter_word_does_not_make_a_different_condition(self):
        """Same rule shape, different loudness: the version — and so the incident — must not move."""
        loud = forecast_rule(severity_tier='critical')
        quiet = forecast_rule(severity_tier='warning')
        self.assertEqual(loud.version, quiet.version)
        self.assertNotEqual(loud.severity(), quiet.severity())

    def test_a_recovery_never_keeps_the_loudness_of_the_failure_it_ended(self):
        rule = forecast_rule(severity_tier='critical', model='holt')
        self.run_round(self.config([rule]), ramp(count=44, start_value=6))
        self.assertEqual([(item['status'], item['severity']) for item in self.condition_events()],
                         [('firing', 'critical')])
        level_off = laid([10 + i for i in range(36)] + [49.0] * 8)
        summary = self.run_round(self.config([rule]), level_off, now=NOW + dt.timedelta(seconds=STEP))
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'resolved'})
        newest = self.condition_events()[0]          # `records()` returns newest first
        self.assertEqual((newest['status'], newest['severity']), ('resolved', 'info'))

    def test_an_unmapped_loudness_refuses_at_load_rather_than_at_the_first_firing_tick(self):
        with self.assertRaises(vocabulary.VocabularyError):
            forecast_rule(severity_tier='catastrophic')

    def test_the_package_contains_no_severity_literal(self):
        """A severity word in product code is a second vocabulary; there is one, and it is a lookup."""
        for path in sorted(PACKAGE.glob('*.py')):
            source = path.read_text(encoding='utf-8')
            for word in ("'info'", "'warning'", "'critical'", '"info"', '"warning"', '"critical"'):
                self.assertNotIn(word, source, f'{path.name} spells a severity: {word}')


class SustainedTests(RoundFixture):
    """The machine is alert conditions's, imported; and what is sustained here is the *prediction*."""

    def test_the_machine_is_the_merged_one_and_is_stepped_once_per_evaluation_bucket(self):
        rule = forecast_rule()
        calls = []
        original = conditions.SustainedStateMachine.step

        def spy(self, key, **kwargs):
            calls.append((key, kwargs['now']))
            return original(self, key, **kwargs)

        with mock.patch.object(conditions.SustainedStateMachine, 'step', spy):
            verdict = timetothreshold.verdict(rule, ramp(), now=NOW)
        self.assertEqual(verdict.outcome, 'firing')
        self.assertGreater(len(calls), 1)
        self.assertTrue(all(key == 'pool-disk.predicted' for key, _ in calls))
        self.assertEqual(calls[-1][1], NOW)

    def test_one_spiky_sample_does_not_open_a_condition_and_pages_nothing(self):
        """The failure mode `for:` exists for: one excursion that tips the fit toward a crossing."""
        spiked = laid([10.0] * 39 + [40.0])
        rule = forecast_rule(model='holt', alpha=0.5, beta=0.3)
        verdict = timetothreshold.verdict(rule, spiked, now=NOW)
        self.assertEqual((verdict.outcome, verdict.state, verdict.status),
                         ('pending', 'pending', 'resolved'))
        summary = self.run_round(self.config([rule]), spiked)
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'pending'})
        self.assertEqual(self.incidents(), 0)
        self.assertEqual([item['status'] for item in self.condition_events()], ['resolved'])
        # The same points, the same model, and no duration to earn, do fire: that gap is what `for:`
        # bought, and it is the difference between a spike and a trend.
        immediate = timetothreshold.verdict(forecast_rule(model='holt', for_seconds=0), spiked, now=NOW)
        self.assertEqual(immediate.outcome, 'firing')

    def test_only_a_prediction_inside_the_horizon_opens_anything(self):
        """The same ramp, read against a horizon shorter than its ETA, is a planning note."""
        quiet = forecast_rule(horizon_seconds=600)         # ETA is +1500 s from the newest sample
        self.assertEqual(timetothreshold.verdict(quiet, ramp(), now=NOW).outcome, 'resolved')
        self.run_round(self.config([quiet]), ramp())
        self.assertEqual(self.incidents(), 0)
        self.assertEqual(timetothreshold.verdict(forecast_rule(horizon_seconds=86400), ramp(),
                                                 now=NOW).outcome, 'firing')

    def test_a_series_that_stops_rising_clears_the_condition(self):
        """Holt's trend decays while a series sits level, so the ETA outruns the horizon.

        Eight level samples after a ramp is the point where the prediction stops being a near one: the
        condition opened on `for_seconds` of agreeing predictions and closes on the same duration of
        disagreeing ones, which is the symmetry `conditions.SustainedStateMachine` was written for.
        """
        rule = forecast_rule(model='holt')
        self.run_round(self.config([rule]), ramp(count=44, start_value=6))
        self.assertEqual(self.incidents(), 1)
        level_off = laid([10 + i for i in range(36)] + [49.0] * 8)
        summary = self.run_round(self.config([rule]), level_off, now=NOW + dt.timedelta(seconds=STEP))
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'resolved'})
        self.assertEqual(self.incidents(), 0)
        self.assertEqual(self.incidents('resolved'), 1)

    def test_an_already_crossed_series_is_named_as_a_breach_and_not_as_a_forecast(self):
        points = ramp(count=46)
        verdict = timetothreshold.verdict(forecast_rule(), points, now=NOW)
        self.assertTrue(verdict.detail['breached'])
        self.assertIn('belongs to rule pool-disk', verdict.detail['reason'])
        self.run_round(self.config([forecast_rule()]), points)
        self.assertEqual(self.incidents(), 0)


class RefusalTests(RoundFixture):
    """Every refusal is a state with a reason, and none of them may file a "will exceed"."""

    def test_a_flat_series_refuses_with_its_reason_and_files_no_condition(self):
        prediction = timetothreshold.time_to_threshold(models.fit(flat(), 'linear'), 70.0,
                                                       flat()[-1][0])
        self.assertIsNone(prediction.eta_epoch_s)
        self.assertEqual(prediction.state, 'flat')
        self.assertIn('flat series', prediction.confidence_note)
        summary = self.run_round(self.config([forecast_rule(model='linear')]), flat())
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'resolved'})
        self.assertEqual(self.pairs(), {('pool-disk.predicted', 'resolved')})
        self.assertEqual(self.incidents(), 0)

    def test_a_receding_series_refuses_with_its_reason_and_files_no_condition(self):
        points = falling()
        prediction = timetothreshold.time_to_threshold(models.fit(points, 'holt'), 70.0, points[-1][0])
        self.assertIsNone(prediction.eta_epoch_s)
        self.assertEqual(prediction.state, 'receding')
        self.assertIn('away from threshold', prediction.confidence_note)
        summary = self.run_round(self.config([forecast_rule(model='holt')]), points)
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'resolved'})
        self.assertEqual(self.pairs(), {('pool-disk.predicted', 'resolved')})
        self.assertEqual(self.incidents(), 0)

    def test_three_points_are_insufficient_and_are_never_extrapolated(self):
        rule = forecast_rule(min_points=4)
        verdict = timetothreshold.verdict(rule, ramp(count=3), now=NOW)
        self.assertEqual((verdict.outcome, verdict.status), ('insufficient', None))
        self.assertEqual([item['kind'] for item in verdict.events], ['coverage'])
        self.assertIn('no trend is fitted', verdict.detail['reason'])
        summary = self.run_round(self.config([rule]), ramp(count=3))
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'insufficient'})
        # The blindness is itself a filing: a coverage event about the series, not silence, and not a
        # verdict about the thing the forecast was watching.
        self.assertEqual(self.pairs(), set())
        self.assertEqual({item['rule_id'] for item in self.events()},
                         {'pool-disk.predicted.coverage'})
        self.assertEqual([item['status'] for item in self.events()], ['firing'])
        self.assertEqual(self.incidents(), 1)

    def test_a_stale_series_files_coverage_and_never_recovers_an_open_condition(self):
        rule = forecast_rule()
        self.run_round(self.config([rule]), ramp())
        self.assertEqual(self.incidents(), 1)
        before = self.pairs()
        verdict = timetothreshold.verdict(rule, ramp(end=NOW - dt.timedelta(seconds=7200)), now=NOW)
        self.assertEqual((verdict.outcome, verdict.status), ('stale', None))
        self.assertEqual([item['kind'] for item in verdict.events], ['coverage'])
        self.assertIn('fresh enough', verdict.detail['reason'])
        self.assertEqual(self.pairs(), before)          # nothing was filed about the condition
        self.assertEqual(self.incidents(), 1)
        latest = [item for item in self.condition_events() if item['rule_id'] == 'pool-disk.predicted']
        self.assertEqual([item['status'] for item in latest], ['firing'])

    def test_the_eta_is_reported_and_never_carried_on_the_event(self):
        """`validate_event`'s object has no summary or raw bag, so the ETA lives in the round detail."""
        verdict = timetothreshold.verdict(forecast_rule(), ramp(), now=NOW)
        self.assertEqual(verdict.detail['prediction']['state'], 'crossing')
        self.assertEqual(verdict.detail['prediction']['eta'],
                         utc_text(dt.datetime.fromtimestamp(RAMP_ETA, dt.timezone.utc)))
        self.assertIn('r2=', verdict.detail['prediction']['note'])
        for item in verdict.events:
            self.assertEqual(set(item), {'schema_version', 'source', 'source_event_id', 'resource_id',
                                         'observed_at', 'kind', 'severity', 'data_class', 'evidence',
                                         'rule_id', 'rule_version', 'window', 'condition', 'status'})


class EventValidityTests(RoundFixture):
    """Every event this producer can file is an ordinary canonical event, verified as such."""

    def test_every_event_scenario_lands_inside_validate_event(self):
        scenarios = [
            ('firing forecast', ramp()),
            ('quiet flat', flat()),
            ('receding', falling()),
            ('spiky', laid([10.0] * 39 + [40.0])),
            ('crossed already', ramp(count=46)),
            ('too few points', ramp(count=3)),
            ('stale', ramp(end=NOW - dt.timedelta(seconds=7200))),
        ]
        for name, points in scenarios:
            with self.subTest(scenario=name):
                for model in models.MODELS:
                    events = timetothreshold.evaluate(forecast_rule(model=model), points, now=NOW)
                    self.assertTrue(1 <= len(events) <= 2)
                    for item in events:
                        validate_event(item, NOW)
                        self.assertEqual(item['source'], SOURCE)
                        self.assertEqual(item['data_class'], 'internal')
                        self.assertTrue(item['rule_id'].endswith('.predicted')
                                        or item['rule_id'].endswith('.predicted.coverage'))

    def test_the_cursor_advances_only_after_a_delivered_round(self):
        config = self.config([forecast_rule()])
        self.run_round(config, ramp())
        state = conditions.load_cursor(self.cursor, config)
        self.assertIsNone(state['pending'])
        self.assertEqual(state['last_end'], utc_text(NOW))
        self.assertEqual(self.run_round(config, ramp())['result'], 'idle')

    def test_an_edited_document_refuses_to_resume_the_old_cursor(self):
        self.run_round(self.config([forecast_rule()]), ramp())
        with self.assertRaises(StateError):
            conditions.load_cursor(self.cursor, self.config([forecast_rule(for_seconds=900)]))


class RoundDriverTests(RoundFixture):
    """`__main__.round_once` is the worker's whole per-round path, minus the HTTP poster."""

    def test_round_once_loads_its_cursor_judges_the_batch_and_reports_the_round(self):
        config = self.config([forecast_rule()])
        seen: list = []
        summary = worker.round_once(self.index, config, self.cursor,
                                    InMemoryStore(rows_for(ramp(), resource_id=self.host)),
                                    seen.append, now=NOW)
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(summary['rules'], {'pool-disk.predicted': 'firing'})
        self.assertEqual(len(seen), 2)                       # coverage + condition
        self.assertEqual({item['kind'] for item in seen}, {'coverage', 'threshold'})
        after = conditions.load_cursor(self.cursor, config)
        self.assertIsNone(after['pending'])
        self.assertEqual(after['last_end'], utc_text(NOW))

    def test_a_refused_delivery_leaves_the_batch_owed_rather_than_lost(self):
        config = self.config([forecast_rule()])

        def refuse(item):
            raise TransportError('fixture: intake said no')

        with self.assertRaises(TransportError):
            worker.round_once(self.index, config, self.cursor,
                              InMemoryStore(rows_for(ramp(), resource_id=self.host)), refuse, now=NOW)
        owed = conditions.load_cursor(self.cursor, config)
        self.assertIsNotNone(owed['pending'])
        self.assertEqual(len(owed['pending']['events']), 2)
        self.assertIsNone(owed['last_end'])


class ConfigTests(unittest.TestCase):
    """The document: the brief's six series keys, the base rule's own timing fields, and refusals."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def write(self, document):
        path = Path(self.temp.name) / 'forecast.yaml'
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding='utf-8')
        return path

    def test_the_shipped_example_loads_and_the_env_var_is_named(self):
        config = timetothreshold.load_config(ROOT / 'examples/platform/forecast.yaml')
        self.assertEqual([item.id for item in config['rules']],
                         ['pool-disk-fill.predicted', 'queue-backlog-growth.predicted'])
        self.assertTrue(all(isinstance(item, timetothreshold.ForecastRule) for item in config['rules']))
        self.assertEqual(timetothreshold.CONFIG_ENVIRONMENT, 'LO_FORECAST_CONFIG')
        for wanted in ('series', 'resource_id', 'horizon_seconds', 'min_points', 'alpha', 'beta'):
            self.assertIn(wanted, timetothreshold.RULE_KEYS)

    def test_a_document_carries_the_base_rule_number_once_and_both_verdicts_read_it(self):
        for item in timetothreshold.load_config(ROOT / 'examples/platform/forecast.yaml')['rules']:
            self.assertEqual(item.threshold(), item.watch.threshold)
            self.assertEqual(item.kind, item.watch.kind)
            self.assertEqual(item.sustain_seconds, item.watch.for_seconds + item.watch.clear_seconds
                             + item.watch.evaluation_seconds)

    def test_a_forecast_document_may_not_rename_the_direction_or_the_mode(self):
        for broken in ({'op': '<'}, {'mode': 'band'}, {'within_seconds': 60}, {'metric': 'disk_used'},
                       {'window_days': 3}):
            with self.subTest(key=list(broken)[0]), self.assertRaises(StateError):
                timetothreshold.rule(rule_document(**broken))

    def test_a_horizon_shorter_than_the_duration_it_must_sustain_is_refused(self):
        """Provable, not stylistic: a prediction is true only inside its horizon, so a `for:` longer
        than the horizon is a condition that can never be earned — the same class of refusal
        `conditions.Rule` makes for `history_seconds`."""
        with self.assertRaises(StateError):
            forecast_rule(horizon_seconds=300, for_seconds=600)
        self.assertEqual(forecast_rule(horizon_seconds=600, for_seconds=600).horizon_seconds, 600)

    def test_a_sustain_window_needing_more_refits_than_the_round_budget_is_refused(self):
        with self.assertRaises(StateError):
            forecast_rule(for_seconds=86400, evaluation_seconds=600, horizon_seconds=86400,
                          history_seconds=604800)

    def test_document_bounds_are_refusals_at_load(self):
        broken = [
            {'rules': []},
            {'rules': [rule_document(extra=1)]},
            {'rules': [rule_document(), rule_document()]},
            {'rules': [rule_document()], 'interval_seconds': 4},
            {'rules': [rule_document()], 'interval_seconds': 3601},
            {'rules': [rule_document()], 'cursor': ''},
            {'rules': [rule_document()], 'cursor': 'x' * 2000},
            {'rules': [rule_document()], 'unknown': 1},
        ]
        for document in broken:
            with self.subTest(document=document), self.assertRaises(StateError):
                timetothreshold.load_config(self.write(document))

    def test_a_missing_file_is_a_refusal_and_not_an_off_switch(self):
        with self.assertRaises(OSError):
            timetothreshold.load_config(Path(self.temp.name) / 'absent.yaml')


class OffSwitchTests(unittest.TestCase):
    """Off is one INFO line and nothing touched; a named-but-broken file is exit 1."""

    def test_main_reports_off_and_touches_nothing(self):
        with mock.patch.dict('os.environ', {}, clear=True), \
                self.assertLogs(timetothreshold.__name__, 'INFO') as captured:
            self.assertEqual(worker.main(), 0)
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(captured.records[0].variable, 'LO_FORECAST_CONFIG')

    def test_a_named_file_that_cannot_be_read_is_exit_one(self):
        environment = {timetothreshold.CONFIG_ENVIRONMENT: 'no-such-directory/forecast.yaml'}
        with mock.patch.dict('os.environ', environment, clear=True), \
                self.assertLogs('local_observe.forecast', 'WARNING') as captured:
            self.assertEqual(worker.main(), 1)
        self.assertEqual(captured.records[0].error_class, 'FileNotFoundError')
        self.assertEqual(captured.records[0].variable, 'LO_FORECAST_CONFIG')

    def test_a_configured_producer_without_a_cursor_refuses_to_start(self):
        config = timetothreshold.load_config(ROOT / 'examples/platform/forecast.yaml')
        with mock.patch.dict('os.environ', {}, clear=True):
            self.assertEqual(worker.cursor_location(config).as_posix(), str(config['cursor']))
            with self.assertRaises(ValueError) as caught:
                worker.cursor_location({'cursor': None})
            self.assertIn('LO_FORECAST_CURSOR', str(caught.exception))
        with mock.patch.dict('os.environ', {timetothreshold.CURSOR_ENVIRONMENT: '/tmp/forecast.json'}):
            self.assertEqual(worker.cursor_location({'cursor': None}).as_posix(), '/tmp/forecast.json')

    def test_the_store_reader_refusal_names_the_variable_that_is_missing(self):
        with self.assertRaises(ValueError) as caught:
            worker.store_reader({})
        message = str(caught.exception)
        self.assertIn('LO_CLICKHOUSE_URL', message)
        self.assertIn('no second query transport', message)


if __name__ == '__main__':
    unittest.main()

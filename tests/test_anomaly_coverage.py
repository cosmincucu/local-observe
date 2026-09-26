"""Coverage episodes through real verdicts, cursor files and platform intake, including retry."""
import copy
import datetime as dt
import json

from local_observe.inventory.validation import canonical
from local_observe.platform import anomaly, anomaly_cursor
from test_anomaly import ConfigFixture, Intake, NOW, PRODUCER, history, latest, series_entry


class CoverageTests(ConfigFixture):
    def config_for(self, threshold=2, **values):
        return self.configuration(series_entry(coverage_unjudgeable_windows=threshold,
                                                min_points=4, window_days=14, **values))

    def step(self, config, number, outcome='judgeable', **options):
        now = NOW + dt.timedelta(hours=number)
        end = int(now.timestamp()) // 3600 * 3600
        training = [(end - 3600 - day * 86400 + 60, 10.0) for day in range(1, 5)]
        if outcome == 'unjudgeable':
            training = [(instant - 3600, value) for instant, value in training]
        rows = training + [(end - 60, 30.0 if outcome == 'anomaly' else 10.0)]
        if outcome == 'insufficient':
            rows = rows[-1:]
        elif outcome == 'idle':
            rows = training
        return self.run_round(config, rows, now=now, **options)

    def coverage(self):
        return self.cursor_entry()['coverage']

    def test_cold_start_hour_of_week_default_history_stays_silent(self):
        config = self.configuration(series_entry(coverage_unjudgeable_windows=1,
                                                  season='hour_of_week'))
        summary, platform, _ = self.run_round(config, history() + latest(30.0))
        self.assertEqual(summary['series'][0]['result'], 'unjudgeable')
        self.assertEqual(platform.calls, [])
        self.assertEqual(self.coverage(), {'previously_judgeable': False,
                                          'consecutive_unjudgeable': 0, 'coverage_open': False})

    def test_threshold_opens_once_and_judgeable_resolves_without_losing_anomaly(self):
        config = self.config_for()
        self.step(config, 0)
        self.assertTrue(self.coverage()['previously_judgeable'])
        _, first, _ = self.step(config, 1, 'unjudgeable')
        self.assertEqual(first.calls, [])
        self.assertEqual(self.coverage()['consecutive_unjudgeable'], 1)
        _, opened, _ = self.step(config, 2, 'unjudgeable')
        self.assertEqual([(e['kind'], e['status']) for e in opened.events], [('coverage', 'firing')])
        _, again, _ = self.step(config, 3, 'unjudgeable')
        self.assertEqual(again.calls, [])
        summary, recovered, _ = self.step(config, 4, 'anomaly')
        self.assertEqual(summary['posts'], 4)
        self.assertEqual([(e['kind'], e['status']) for e in recovered.events],
                         [('coverage', 'resolved'), ('anomaly', 'firing')])
        self.assertEqual(opened.events[0]['condition'], recovered.events[0]['condition'])
        self.assertEqual(opened.events[0]['rule_version'], recovered.events[0]['rule_version'])
        self.assertFalse(self.coverage()['coverage_open'])
        self.assertEqual(self.coverage()['consecutive_unjudgeable'], 0)

    def test_lost_open_response_replays_identical_bytes_and_counts_once(self):
        config = self.config_for()
        self.step(config, 0)
        self.step(config, 1, 'unjudgeable')
        _, failed, _ = self.step(config, 2, 'unjudgeable', lose=('/v1/events',))
        self.assertEqual(self.coverage()['consecutive_unjudgeable'], 1)
        pending = self.held_batch()
        self.assertTrue(pending['coverage_after']['coverage_open'])
        summary, replay, query = self.step(config, 2, 'insufficient')
        self.assertEqual(summary['queries'], 0)
        self.assertEqual(query.calls, 0)
        self.assertEqual(failed.bodies(), replay.bodies())
        self.assertEqual(self.coverage()['consecutive_unjudgeable'], 2)
        self.assertIsNone(self.held_batch())

    def test_mixed_recovery_retry_keeps_both_deliveries_and_reserves_four_posts(self):
        config = self.config_for(1)
        self.step(config, 0)
        self.step(config, 1, 'unjudgeable')
        before = self.cursor.read_bytes()
        summary, deferred, _ = self.step(config, 2, 'anomaly', budget=anomaly.RoundBudget(posts=3))
        self.assertEqual(summary['posts'], 0)
        self.assertEqual(deferred.calls, [])
        self.assertEqual(before, self.cursor.read_bytes())
        _, failed, _ = self.step(config, 2, 'anomaly', lose=('/v1/events',))
        self.assertEqual(len(self.held_batch()['deliveries']), 2)
        self.assertTrue(self.coverage()['coverage_open'])
        summary, replay, _ = self.step(config, 2, 'insufficient')
        self.assertEqual(summary['posts'], 4)
        self.assertEqual(summary['queries'], 0)
        self.assertEqual(failed.bodies(), replay.bodies()[:2])
        self.assertEqual([(e['kind'], e['status']) for e in replay.events],
                         [('coverage', 'resolved'), ('anomaly', 'firing')])
        self.assertFalse(self.coverage()['coverage_open'])

    def test_response_lost_after_second_event_replays_all_four_identically(self):
        class LoseLast(Intake):
            def request(self, method, path, payload):
                answer = super().request(method, path, payload)
                return (503, None) if len(self.calls) == 4 else answer

        config = self.config_for(1)
        self.step(config, 0)
        self.step(config, 1, 'unjudgeable')
        platform = LoseLast(self.store, now=NOW + dt.timedelta(hours=2))
        self.step(config, 2, 'anomaly', intake=platform)
        self.assertEqual(len(platform.calls), 4)
        self.assertTrue(self.coverage()['coverage_open'])
        _, replay, query = self.step(config, 2, 'insufficient')
        self.assertEqual(query.calls, 0)
        self.assertEqual(platform.bodies(), replay.bodies())
        self.assertFalse(self.coverage()['coverage_open'])

    def test_silent_interruption_resets_counter_but_does_not_resolve_open_episode(self):
        config = self.config_for()
        self.step(config, 0)
        for number, outcome in enumerate(('unjudgeable', 'insufficient', 'unjudgeable', 'idle'), 1):
            self.step(config, number, outcome)
        self.assertEqual(self.coverage()['consecutive_unjudgeable'], 0)
        self.step(config, 5, 'unjudgeable')
        self.step(config, 6, 'unjudgeable')
        _, silent, _ = self.step(config, 7, 'insufficient')
        self.assertEqual(silent.calls, [])
        self.assertTrue(self.coverage()['coverage_open'])
        self.assertEqual(self.coverage()['consecutive_unjudgeable'], 0)
        _, recovered, _ = self.step(config, 8)
        self.assertEqual([(e['kind'], e['status']) for e in recovered.events],
                         [('coverage', 'resolved'), ('anomaly', 'resolved')])

    def test_schema_one_opt_in_refuses_without_reads_posts_or_rewrite(self):
        old = self.config_for(0)
        self.step(old, 0)
        before = self.cursor.read_bytes()
        self.assertEqual(json.loads(before)['schema_version'], 1)
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'migration'):
            self.step(self.config_for(), 1)
        self.assertEqual(before, self.cursor.read_bytes())

    def test_disabled_binding_and_event_bytes_match_omitted_setting(self):
        disabled = self.config_for(0)['series'][0]
        omitted = self.resolved(series_entry(min_points=4, window_days=14))
        self.assertEqual(disabled, omitted)
        self.assertEqual(anomaly_cursor.series_binding(disabled), anomaly_cursor.series_binding(omitted))
        self.assertEqual(anomaly._verdict_binding(disabled), anomaly._verdict_binding(omitted))

    def test_configuration_integer_bounds_and_coverage_state_refusals(self):
        for value in (-1, 101, 1.0, True, '2', None, [], {}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.config_for(value)
        self.config_for(100)
        config = self.config_for()
        self.step(config, 0)
        original = self.cursor_document()
        for field, value in [('consecutive_unjudgeable', 101), ('consecutive_unjudgeable', True),
                             ('previously_judgeable', 1), ('coverage_open', 'true'), ('unknown', 0)]:
            document = copy.deepcopy(original)
            document['series']['demo-load']['coverage'][field] = value
            self.cursor.write_text(canonical(document), encoding='utf-8')
            before = self.cursor.read_bytes()
            with self.subTest(field=field, value=value), self.assertRaises(anomaly_cursor.CursorRefusal):
                anomaly_cursor.load(self.cursor, source=PRODUCER.identity)
            self.assertEqual(before, self.cursor.read_bytes())

    def test_pending_transition_tampering_refuses_before_delivery(self):
        config = self.config_for(1)
        self.step(config, 0)
        self.step(config, 1, 'unjudgeable', refuse=('/v1/events',))
        document = self.cursor_document()
        document['series']['demo-load']['pending']['coverage_after']['consecutive_unjudgeable'] = 2
        self.cursor.write_text(canonical(document), encoding='utf-8')
        before = self.cursor.read_bytes()
        with self.assertRaisesRegex(anomaly_cursor.CursorRefusal, 'transition'):
            self.step(config, 1)
        self.assertEqual(before, self.cursor.read_bytes())

    def test_malformed_delivery_envelope_is_refused_read_only(self):
        config = self.config_for(1)
        self.step(config, 0)
        self.step(config, 1, 'unjudgeable', refuse=('/v1/events',))
        original = self.cursor_document()
        for fault in ('unknown', 'empty', 'three', 'missing', 'bad-outcome'):
            document = copy.deepcopy(original)
            pending = document['series']['demo-load']['pending']
            if fault == 'unknown':
                pending['extra'] = 1
            elif fault == 'empty':
                pending['deliveries'] = []
            elif fault == 'three':
                pending['deliveries'] *= 3
            elif fault == 'missing':
                del pending['deliveries'][0]['event']
            else:
                pending['outcome'] = []
            self.cursor.write_text(canonical(document), encoding='utf-8')
            before = self.cursor.read_bytes()
            with self.subTest(fault=fault), self.assertRaises(anomaly_cursor.CursorRefusal):
                anomaly_cursor.load(self.cursor, source=PRODUCER.identity)
            self.assertEqual(before, self.cursor.read_bytes())

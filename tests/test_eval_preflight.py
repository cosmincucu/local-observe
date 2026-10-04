"""Model-free feasibility preflight: what it refuses, what it predicts, what it must never touch."""
import copy
import datetime as dt
import io
import json
import os
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from local_observe.evaluation.fault_inject import RESOURCE, START, synthetic
from local_observe.evaluation.model import CorpusError, load, validate
from local_observe.evaluation.observer import judge
from local_observe.evaluation.preflight import preflight
from local_observe.inventory.validation import utc_text
from local_observe.observer.contract import Config, Source

METRIC = 'cpu'
OTHER = 'queue_depth'
SECOND = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
REVISION = 'a' * 40


def points(count=8, hour=0):
    return [(hour, minute, minute + 1) for minute in range(count)]


def series(resource=RESOURCE, metric=METRIC, rows=()):
    return {'resource_id': resource, 'metric': metric,
            'rows': [{'ts': (START + dt.timedelta(hours=hour, minutes=minute)).timestamp(), 'v': value}
                     for hour, minute, value in sorted(rows)]}


def corpus(rows, incidents=(), quiet=(), labelled=(), hours=1):
    return validate({'schema_version': 1, 'id': 'preflight-example', 'origin': 'generated-demo',
                     'evaluation': {'start': utc_text(START), 'end': utc_text(START + dt.timedelta(hours=hours))},
                     'incidents': list(incidents), 'quiet': list(quiet), 'labelled': list(labelled),
                     'series': list(rows)})


def baseline(rows, threshold=100):
    return {'schema_version': 1,
            'thresholds': [{'resource_id': row['resource_id'], 'metric': row['metric'], 'threshold': threshold}
                           for row in rows]}


def metric_source(metric, name, resource=RESOURCE, **kwargs):
    return Source(id=name, query_type='metric-threshold', resource_id=resource, metric_name=metric, **kwargs)


def config(sources=None, **overrides):
    selected = sources or (metric_source(METRIC, 'example-cpu'),)
    limits = {'max_sources': 8, 'max_rows': 2000, 'max_age_seconds': 3600, 'mode': 'recording'}
    limits.update(overrides)
    return Config(sources=tuple(selected), **limits)


def checked(held, settings, rows=None, threshold=100):
    selected = list(rows if rows is not None else held['series'])
    return preflight(held, revision=REVISION, observer_config=settings,
                     baseline_config=baseline(selected, threshold))


def codes(report):
    return {gap['code'] for gap in report['gaps']}


class QuietModel:
    """Cites one real row, asks for no follow-up: isolates input feasibility from model behavior."""

    def complete(self, evidence, allowed, supplied, now):
        item, row = evidence[-1], evidence[-1]['rows'][0]
        return {'content': json.dumps({'schema_version': 1, 'decision': 'quiet',
                                       'rationale': 'Fixture comparison only', 'follow_up': [],
                                       'citations': [{'evidence_id': item['evidence_id'], 'row_index': 0,
                                                      'field': 'value', 'value': row['value']}],
                                       'findings': []})}


def actual_cycles(held, settings):
    with tempfile.TemporaryDirectory() as directory:
        result = judge({'series': held['series'], 'evaluation': held['evaluation']},
                       directory=Path(directory) / 'new', model_factory=QuietModel, config=settings)
    return result


class PreflightInputTests(unittest.TestCase):
    def test_malformed_and_missing_corpus_refuse_before_any_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'corpus.json'
            for text in ('{', '{"schema_version": 1,}', '[]', '{"id": "a", "id": "b"}', '{"schema_version": 1.5}'):
                path.write_text(text, encoding='utf-8')
                with self.subTest(text=text), self.assertRaises(CorpusError):
                    load(path)
        held = corpus([series(rows=points(2))])
        for missing in ('schema_version', 'id', 'origin', 'incidents', 'series', 'evaluation'):
            broken = copy.deepcopy(held)
            del broken[missing]
            with self.subTest(field=missing), self.assertRaises(CorpusError):
                checked(broken, config(), rows=[series(rows=points(2))])
        optional = copy.deepcopy(held)
        del optional['labelled']
        self.assertEqual(checked(optional, config())['labels']['unknown_seconds'], 3600)

    def test_exact_multi_resource_mapping_and_baseline_source_matching(self):
        rows = [series(rows=points(2)), series(resource=SECOND, metric=OTHER, rows=points(2))]
        settings = config(sources=[metric_source(METRIC, 'first'), metric_source(OTHER, 'second', resource=SECOND)])
        self.assertTrue(checked(corpus(rows), settings)['inputs_feasible'])
        wrong_sources = [
            config(sources=[metric_source(METRIC, 'first')]),
            config(sources=[metric_source(METRIC, 'first'), metric_source(METRIC, 'second')]),
            config(sources=[metric_source(METRIC, 'first'), metric_source(OTHER, 'extra')]),
            config(sources=[metric_source(METRIC, 'first'),
                            Source(id='logs', query_type='log-records', resource_id=SECOND)])]
        for selected in wrong_sources:
            with self.subTest(sources=[row.id for row in selected.sources]), self.assertRaises(CorpusError):
                checked(corpus(rows), selected)
        for number, wrong in enumerate((baseline(rows[:-1]), {'schema_version': 1, 'thresholds': []},
                                        baseline(rows, threshold='100'),
                                        {'schema_version': 2, 'thresholds': baseline(rows)['thresholds']})):
            with self.subTest(case=number), self.assertRaises(CorpusError):
                preflight(corpus(rows), revision=REVISION, observer_config=settings, baseline_config=wrong)

    def test_cadence_must_cover_every_configured_window(self):
        held = corpus([series(rows=[(0, 30, 10), (1, 30, 10)])], hours=2)
        for overrides in ({'window_seconds': 5400}, {'cadence_seconds': 4500}, {'window_seconds': 1800}):
            with self.subTest(**overrides), self.assertRaises(CorpusError):
                checked(held, config(**overrides))
        report = checked(held, config())
        self.assertEqual((report['cycles']['count'], report['cycles']['source_reads']), (2, 2))
        self.assertTrue(report['inputs_feasible'])

    def test_invalid_revision_config_or_a_study_larger_than_a_preflight_refuse(self):
        held = corpus([series(rows=points(2))])
        with self.assertRaises(CorpusError):
            corpus([series(rows=points(2))],
                   incidents=[{'id': 'late', 'resource_id': RESOURCE, 'expected_class': 'not-a-class',
                               'window': {'start': utc_text(START),
                                          'end': utc_text(START + dt.timedelta(minutes=5))}}])
        with self.assertRaises(CorpusError):
            preflight(held, revision='not-a-commit-id', observer_config=config(),
                      baseline_config=baseline(held['series']))
        with self.assertRaises(CorpusError):
            preflight(held, revision=REVISION, observer_config={'schema_version': 1, 'sources': []},
                      baseline_config=baseline(held['series']))
        with self.assertRaises(CorpusError):
            preflight(held, revision=REVISION, observer_config=config(), baseline_config=None)
        long = corpus([series(rows=points(2))], hours=168)
        with self.assertRaises(CorpusError):
            preflight(long, revision=REVISION, observer_config=config(cadence_seconds=60, window_seconds=60),
                      baseline_config=baseline(long['series']))


class PreflightPredictionTests(unittest.TestCase):
    def test_labels_never_cover_other_resources_or_double_count_metrics(self):
        rows = [series(rows=points(2)), series(metric=OTHER, rows=points(2)),
                series(resource=SECOND, rows=points(2))]
        settings = config(sources=[metric_source(METRIC, 'first'), metric_source(OTHER, 'second'),
                                   metric_source(METRIC, 'third', resource=SECOND)])
        held = corpus(rows, labelled=[{'resource_id': RESOURCE,
                                      'window': {'start': utc_text(START),
                                                 'end': utc_text(START + dt.timedelta(hours=1))}}])
        labels = checked(held, settings)['labels']
        self.assertEqual(labels['duration_seconds'], 7200)
        self.assertEqual(labels['exhaustive_seconds'], 3600)
        self.assertEqual(labels['unknown_seconds'], 3600)
        self.assertEqual(labels['resources'], [
            {'resource_index': 0, 'exhaustive_seconds': 3600, 'unknown_seconds': 0},
            {'resource_index': 1, 'exhaustive_seconds': 0, 'unknown_seconds': 3600}])
        # The same label outside the corpus cannot supply coverage at all.
        held['series'] = [rows[-1]]
        labels = checked(held, config(sources=[settings.sources[-1]]))['labels']
        self.assertEqual(labels['unknown_seconds'], 3600)
        self.assertEqual(labels['exhaustive_seconds'], 0)

    def test_every_follow_up_source_is_checked_for_samples_and_total_capacity(self):
        rows = [series(rows=points(8)), series(metric=OTHER, rows=points(8))]
        settings = config(sources=[metric_source(METRIC, 'first'),
                                   metric_source(OTHER, 'second', initial=False)])
        held = corpus(rows)
        tight = checked(held, replace(settings, max_result_bytes=1300))
        self.assertIn('cycle_evidence_budget', codes(tight))
        for changed, code in (([(-1, 30, 1)], 'empty_sample'), ([(0, 0, 1)], 'stale_samples'),
                              (points(8), 'invalid_rows')):
            held['series'][1] = series(metric=OTHER, rows=changed)
            limits = replace(settings, max_age_seconds=300, max_rows=3) if code == 'invalid_rows' else (
                replace(settings, max_age_seconds=300) if code == 'stale_samples' else settings)
            report = checked(held, limits)
            self.assertFalse(report['inputs_feasible'])
            self.assertIn({'code': code, 'window_index': 0, 'source_index': 1}, report['gaps'])
        # One remaining slot cannot cover two conditional sources.
        rows.append(series(resource=SECOND, rows=points(2)))
        settings = replace(settings, max_sources=2, sources=(*settings.sources,
                           metric_source(METRIC, 'third', resource=SECOND, initial=False)))
        report = checked(corpus(rows), settings)
        self.assertIn('configured_sources_exceed_max_sources', codes(report))
        self.assertEqual(report['follow_up']['capacity'], 'insufficient')
        self.assertEqual(report['cycles']['source_reads'], 3)
        self.assertEqual(report['cycles']['inputs_ready'], 0)

    def test_usable_follow_up_cannot_bootstrap_an_empty_initial_pass(self):
        rows = [series(rows=[(-1, 30, 1)]), series(metric=OTHER, rows=points(2))]
        settings = config(sources=[metric_source(METRIC, 'first'),
                                   metric_source(OTHER, 'second', initial=False)])
        report = checked(corpus(rows), settings)
        self.assertIn('no_usable_evidence', codes(report))
        self.assertEqual(report['cycles']['usable_initial_evidence'], 0)

    def test_incidents_for_resources_outside_the_corpus_are_reported_separately(self):
        held = corpus([series(rows=points(2))], incidents=[{
            'id': 'outside', 'resource_id': SECOND, 'expected_class': 'anomaly',
            'window': {'start': utc_text(START), 'end': utc_text(START + dt.timedelta(hours=1))}}])
        report = checked(held, config())
        self.assertEqual(report['labels']['incident_labels'], 0)
        self.assertEqual(report['labels']['out_of_scope_incident_labels'], 1)
        self.assertEqual(report['labels']['unknown_seconds'], 3600)
        self.assertIn('out_of_scope_incident_labels', report['caveats'])
        self.assertTrue(report['inputs_feasible'])

    def test_fully_labelled_span_can_still_have_gaps_between_observations(self):
        span = {'start': utc_text(START), 'end': utc_text(START + dt.timedelta(hours=3))}
        held = corpus([series(rows=[(0, 30, 1), (2, 30, 1)])], quiet=[span], hours=3)
        report = checked(held, config(cadence_seconds=7200, window_seconds=3600))
        self.assertEqual(report['labels']['evaluation_seconds'], 10800)
        self.assertEqual(report['labels']['unknown_seconds'], 0)
        self.assertEqual(report['cycles']['observation_seconds'], 7200)
        self.assertEqual(report['cycles']['unobserved_seconds'], 3600)
        self.assertIn('unobserved_evaluation_intervals', report['caveats'])
        self.assertTrue(report['inputs_feasible'])
        # Overlapping cycles contribute their union, not twice their covered time.
        report = checked(held, config(cadence_seconds=1800, window_seconds=3600))
        self.assertEqual(report['cycles']['observation_seconds'], 10800)
        self.assertEqual(report['cycles']['unobserved_seconds'], 0)

    def test_partial_window_staleness_and_empty_samples_are_located(self):
        rows = [series(rows=[(0, 30, 10), (1, 5, 10)]), series(metric=OTHER, rows=[(0, 30, 10)])]
        settings = config(sources=[metric_source(METRIC, 'first'), metric_source(OTHER, 'second')],
                          max_age_seconds=1800)
        report = checked(corpus(rows, hours=2), settings)
        self.assertFalse(report['inputs_feasible'])
        self.assertEqual([(row['code'], row['window_index'], row['source_index']) for row in report['gaps']],
                         [('stale_samples', 1, 0), ('empty_sample', 1, 1), ('no_usable_evidence', 1, None)])
        self.assertEqual(report['counts'], {'stale_samples': 1, 'empty_sample': 1, 'no_usable_evidence': 1})
        self.assertEqual({key: report['cycles'][key] for key in
                          ('count', 'inputs_ready', 'inputs_incomplete', 'usable_initial_evidence', 'source_reads',
                           'model_calls_required_per_run')},
                         {'count': 2, 'inputs_ready': 1, 'inputs_incomplete': 1, 'usable_initial_evidence': 1,
                          'source_reads': 4, 'model_calls_required_per_run': 2})
        self.assertGreater(report['cycles']['peak_evidence_bytes'], 0)

    def test_per_source_fit_cannot_hide_total_cycle_overflow(self):
        rows = [series(rows=points()), series(metric=OTHER, rows=points())]
        held = corpus(rows)
        settings = config(sources=[metric_source(METRIC, 'first'), metric_source(OTHER, 'second')],
                          max_result_bytes=1300)
        report = checked(held, settings)
        self.assertEqual(codes(report), {'cycle_evidence_budget'})
        self.assertEqual([(row['window_index'], row['source_index']) for row in report['gaps']], [(0, 1)])
        self.assertEqual(report['cycles']['inputs_incomplete'], 1)
        self.assertLessEqual(report['cycles']['peak_evidence_bytes'], settings.max_result_bytes)
        for position, single in enumerate(settings.sources):
            alone = checked(corpus([rows[position]]), config(sources=[single], max_result_bytes=1300))
            self.assertTrue(alone['inputs_feasible'], single.id + ' fits the cycle budget on its own')

    def test_budget_limits_apply_across_the_cycle(self):
        rows = [series(rows=points(2)), series(metric=OTHER, rows=points(2))]
        both = [metric_source(METRIC, 'first'), metric_source(OTHER, 'second')]
        held = corpus(rows)
        cases = {
            'initial_sources_exceed_max_sources': (held, config(sources=both, max_sources=1)),
            'model_budget_exhausted': (corpus([rows[0]]), config(sources=[both[0]], max_model_calls=0)),
            'follow_up_capacity_insufficient': (held, config(sources=[both[0], metric_source(OTHER, 'second',
                                                                                             initial=False)],
                                                             max_sources=2, max_model_calls=1))}
        for expected, (subject, settings) in cases.items():
            report = checked(subject, settings)
            with self.subTest(gap=expected):
                self.assertFalse(report['inputs_feasible'])
                self.assertEqual(codes(report), {expected})
                self.assertEqual(report['counts'], {expected: 1})
                self.assertEqual(report['gaps'][0], {'code': expected, 'window_index': None, 'source_index': None})
                self.assertEqual(report['cycles']['inputs_ready'], 0)
        conditional = checked(held, config(sources=[both[0], metric_source(OTHER, 'second', initial=False)]))
        self.assertTrue(conditional['inputs_feasible'], 'a reachable follow-up is conditional, never a guarantee')
        self.assertEqual(conditional['follow_up'], {'sources': 1, 'model_calls': 2, 'required_model_calls': 2,
                                                   'capacity': 'conditional'})
        self.assertIn('conditional_sources_require_model_follow_up', conditional['caveats'])
        self.assertNotIn('conditional_sources_require_model_follow_up', checked(held, config(sources=both))['caveats'])
        self.assertEqual(conditional['cycles']['source_reads'], 2)
        self.assertEqual(conditional['cycles']['model_calls_required_per_run'], 2)

    def test_label_union_is_half_open_and_incidents_are_not_negatives(self):
        def interval(hour, minutes=0):
            return {'start': utc_text(START + dt.timedelta(hours=hour, minutes=minutes)),
                    'end': utc_text(START + dt.timedelta(hours=hour + 1, minutes=minutes))}
        rows = [series(rows=[(hour, 30, 10) for hour in range(4)])]
        held = corpus(rows, hours=4,
                      incidents=[{'id': 'late', 'resource_id': RESOURCE, 'expected_class': 'anomaly',
                                  'window': interval(3)}],
                      quiet=[interval(0)],
                      labelled=[{'resource_id': RESOURCE, 'window': interval(0, 30)},
                                {'resource_id': RESOURCE, 'window': interval(1)},
                                {'resource_id': SECOND, 'window': interval(2)}])
        report = checked(held, config())
        self.assertEqual(report['labels'], {
            'unit': 'resource_seconds', 'evaluation_seconds': 14400, 'duration_seconds': 14400,
            'exhaustive_seconds': 7200, 'unknown_seconds': 7200,
            'resources': [{'resource_index': 0, 'exhaustive_seconds': 7200, 'unknown_seconds': 7200}],
            'quiet_windows': 1, 'labelled_windows': 3, 'labelled_resources': 1,
            'out_of_scope_labelled_windows': 1, 'incident_labels': 1, 'out_of_scope_incident_labels': 0,
            'incidents_are_exhaustive_negatives': False})
        self.assertTrue(report['inputs_feasible'], 'unknown labels warn; they do not invalidate runnable inputs')
        self.assertIn('unknown_label_intervals', report['caveats'])
        self.assertFalse(report['authorizes_delivery'])
        self.assertFalse(report['substitute_for_quality_report'])
        bare = checked(corpus(rows, hours=4), config())
        self.assertEqual((bare['labels']['exhaustive_seconds'], bare['labels']['unknown_seconds']), (0, 14400))
        self.assertTrue(bare['inputs_feasible'])
        self.assertNotIn('arms', bare)
        self.assertNotIn('quality', bare)
        self.assertNotIn('measurement', bare)

    def test_prediction_matches_production_cycles_for_tight_and_loose_budgets(self):
        rows = [series(rows=[(hour, minute, 200 if hour == 0 else 10)
                             for hour in range(4) for minute in range(5)])]
        held = corpus(rows, hours=4)
        loose = config(max_rows=2000)
        report = checked(held, loose)
        self.assertTrue(report['inputs_feasible'])
        self.assertEqual(report['cycles']['inputs_ready'], 4)
        cycles = actual_cycles(held, loose)['cycles']
        self.assertEqual([row['status'] for row in cycles], ['completed'] * 4)
        self.assertTrue(all(row['coverage'] == 'complete' for row in cycles))
        tight = config(max_rows=3)
        report = checked(held, tight)
        self.assertFalse(report['inputs_feasible'])
        self.assertEqual(codes(report), {'invalid_rows', 'no_usable_evidence'})
        self.assertEqual(report['cycles']['inputs_ready'], 0)
        cycles = actual_cycles(held, tight)['cycles']
        self.assertEqual([row['error'] for row in cycles], ['no_usable_evidence'] * 4)
        self.assertEqual([row['status'] for row in cycles], ['failed'] * 4)

    def test_generated_demo_gap_is_a_real_cycle_failure_not_a_preflight_invention(self):
        held = synthetic()
        settings = Config(sources=(metric_source('filesystem_used_bytes', 'demo'),), max_sources=1, max_rows=2000,
                          max_age_seconds=3600, mode='recording')
        report = preflight(held, revision=REVISION, observer_config=settings,
                           baseline_config=baseline(held['series'], threshold=50e9))
        self.assertEqual(report['counts'], {'empty_sample': 1, 'no_usable_evidence': 1})
        self.assertEqual(report['cycles']['inputs_incomplete'], 1)
        result = actual_cycles(held, settings)
        self.assertEqual([row['error'] for row in result['cycles']].count('no_usable_evidence'), 1)
        self.assertEqual(result['status'], 'unjudgeable')


class PreflightBoundaryTests(unittest.TestCase):
    def bombs(self):
        def explode(label):
            def fail(*args, **kwargs):
                raise AssertionError(label + ' must not be reached')
            return fail

        return [patch('local_observe.evaluation.report.reserve_namespace', side_effect=explode('reserve_namespace')),
                patch('local_observe.evaluation.__main__.evaluate', side_effect=explode('evaluate')),
                patch('local_observe.observer.runtime.Observer.run', side_effect=explode('Observer.run')),
                patch('local_observe.observer.journal.Journal.__init__', side_effect=explode('Journal')),
                patch('local_observe.observer.adapters.Sources.__init__', side_effect=explode('source adapter')),
                patch('local_observe.observer.adapters.Model.__init__', side_effect=explode('model credential')),
                patch('local_observe.observer.adapters.credential', side_effect=explode('credential read')),
                patch.object(socket, 'socket', side_effect=explode('network'))]

    def api(self, *, held=None, settings=None):
        held = held or corpus([series(rows=points(2))])
        settings = settings or config()
        states = self.bombs()
        for state in states:
            state.start()
        try:
            return checked(held, settings)
        finally:
            for state in states:
                state.stop()

    def cli(self, argv, arrange=None):
        """Run the CLI under bombs and return what the protected directory holds afterwards."""
        from local_observe.evaluation.__main__ import main
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = [series(rows=points(2))]
            paths = {'root': root, 'corpus': root / 'corpus.json', 'config': root / 'config.json',
                     'baseline': root / 'baseline.json', 'private': root / 'private',
                     'output': root / 'private' / 'preflight.json', 'elsewhere': root / 'elsewhere.json'}
            paths['corpus'].write_text(json.dumps(corpus(rows)), encoding='utf-8')
            paths['config'].write_text(json.dumps({'schema_version': 1, 'sources': [
                {'id': 'example-cpu', 'query_type': 'metric-threshold', 'resource_id': RESOURCE,
                 'metric_name': METRIC}], 'max_sources': 8, 'max_rows': 2000, 'max_age_seconds': 3600,
                'mode': 'recording'}), encoding='utf-8')
            paths['baseline'].write_text(json.dumps(baseline(rows)), encoding='utf-8')
            paths['private'].mkdir()
            paths['private'].chmod(0o700)
            if arrange is not None:
                arrange(paths)
            requested = [str(paths[item[1:-1]]) if isinstance(item, str) and item.startswith('{') else item
                         for item in argv]
            states = self.bombs()
            for state in states:
                state.start()
            captured = io.StringIO()
            try:
                with redirect_stdout(captured):
                    status = main(requested)
            except SystemExit as exc:  # argparse refuses an absent --revision the same way: status 2
                status = exc.code
            finally:
                for state in states:
                    state.stop()

            def contents(path):
                return path.read_text(encoding='utf-8') if path.is_file() else None

            return {'status': status, 'stdout': captured.getvalue(),
                    'listing': sorted(name for name in os.listdir(paths['private']))
                            if paths['private'].exists() else None,
                    'output': contents(paths['output']), 'elsewhere': contents(paths['elsewhere']),
                    'mode': os.stat(paths['output']).st_mode & 0o777 if paths['output'].exists() else None}

    def request(self, **changes):
        """Build a complete preflight command line, dropping a flag (None) or replacing its pair."""
        parts = {'revision': ['--revision', REVISION], 'mode': ['--preflight'], 'corpus': ['--corpus', '{corpus}'],
                 'observer config': ['--observer-config', '{config}'],
                 'baseline config': ['--baseline-config', '{baseline}'], 'output': ['--output', '{output}']}
        for key, value in changes.items():
            parts.pop(key) if value is None else parts.update({key: value})
        return [value for group in parts.values() for value in group]

    def test_api_preflight_touches_no_model_journal_or_namespace(self):
        with patch.dict(os.environ, {}, clear=True):  # an emptied environment changes nothing
            self.assertTrue(self.api()['inputs_feasible'])

    def test_cli_writes_only_its_report_and_prints_nothing(self):
        planted = {'LO_AI_API_KEY': 'sentinel-model-key', 'LO_AI_MODEL': 'sentinel-alias',
                   'LO_CLICKHOUSE_READ_PASSWORD_FILE': '/sentinel/credential',
                   'LO_OBSERVER_CREDENTIAL_FILE': '/sentinel/observer-credential'}
        with patch.dict(os.environ, planted):
            result = self.cli(self.request())
        self.assertEqual((result['status'], result['stdout'], result['listing']), (0, '', ['preflight.json']))
        self.assertEqual(result['mode'], 0o600)
        report = json.loads(result['output'])
        self.assertTrue(report['inputs_feasible'])
        text = json.dumps(report)
        for leaked in (RESOURCE, SECOND, METRIC, 'cpu', 'threshold', '/example', 'private',
                       '/sentinel', *planted.values()):
            self.assertNotIn(leaked, text)
        self.assertEqual([len(report['binding'][key]) for key in ('corpus_sha256', 'config_sha256',
                                                                  'baseline_sha256', 'inventory_sha256')],
                         [64, 64, 64, 64])

    def test_cli_refuses_insecure_pre_existing_linked_and_repository_outputs(self):
        def existing(paths):
            paths['output'].write_text('pre-existing', encoding='utf-8')

        def insecure(paths):
            paths['private'].chmod(0o755)

        def linked(paths):
            paths['elsewhere'].write_text('pre-existing', encoding='utf-8')
            paths['output'].symlink_to(paths['elsewhere'])

        def repository(paths):
            (paths['root'] / '.git').mkdir()

        for arrange in (existing, insecure, linked, repository):
            with self.subTest(case=arrange.__name__):
                result = self.cli(self.request(), arrange)
                self.assertEqual((result['status'], result['stdout']), (2, ''))
                self.assertEqual(result['output'], 'pre-existing' if arrange in (existing, linked) else None)
                self.assertEqual(result['elsewhere'], 'pre-existing' if arrange is linked else None)

    def test_cli_writes_infeasible_diagnostics_and_returns_failure(self):
        def no_model_budget(paths):
            value = json.loads(paths['config'].read_text(encoding='utf-8'))
            value['max_model_calls'] = 0
            paths['config'].write_text(json.dumps(value), encoding='utf-8')

        result = self.cli(self.request(), no_model_budget)
        self.assertEqual((result['status'], result['stdout'], result['mode']), (2, '', 0o600))
        report = json.loads(result['output'])
        self.assertFalse(report['inputs_feasible'])
        self.assertEqual(report['cycles']['inputs_ready'], 0)
        self.assertIn('model_budget_exhausted', codes(report))

    def test_cli_refuses_incomplete_or_journal_requesting_calls(self):
        cases = [(name, self.request(**{name: None})) for name in
                 ('corpus', 'observer config', 'baseline config', 'output', 'revision')]
        cases.append(('relative output', self.request(output=['--output', 'preflight.json'])))
        cases.append(('journal request', self.request(directory=['--observer-directory', '{private}'])))
        for name, argv in cases:
            with self.subTest(case=name):
                result = self.cli(argv)
                self.assertEqual((result['status'], result['stdout']), (2, ''))
                self.assertNotIn('preflight.json', result['listing'] or [])


if __name__ == '__main__':
    unittest.main()

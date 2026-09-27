"""Execute the metric SQL over synthetic hourly metadata and exact sample timestamps.

SQLite runs the relational part of the production statement, with adapters for bound parameter
syntax, FORMAT JSON and three ClickHouse functions. These tests check row semantics and metadata
aggregation inputs; ClickHouse parsing, distributed execution and read cost need separate acceptance.
"""
import datetime as dt
import json
import re
import sqlite3
import unittest

from local_observe.store import client as facade
from local_observe.store.backends import clickhouse as ch

RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
METRIC = 'fixture.load'
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def millis(text):
    delta = facade.parse_ts(text) - EPOCH
    return delta // dt.timedelta(milliseconds=1)


class MetricWindows(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.execute("ATTACH DATABASE ':memory:' AS signoz_metrics")
        identity = 'env TEXT, temporality TEXT, metric_name TEXT, fingerprint INTEGER'
        self.db.execute(f'CREATE TABLE {ch.METRICS_SAMPLES} '
                        f'({identity}, unix_milli INTEGER, value REAL)')
        self.db.execute(f'CREATE TABLE {ch.METRICS_SERIES} '
                        f'({identity}, unix_milli INTEGER, labels TEXT)')
        self.db.create_function('intDiv', 2, lambda a, b: a // b)
        self.db.create_function('JSONExtractString', 2, lambda text, key: json.loads(text).get(key, ''))
        self.metadata_seen = []
        seen = self.metadata_seen

        class ArgMax:
            def __init__(self):
                self.latest = None
                self.value = None

            def step(self, value, timestamp):
                seen.append(timestamp)
                if self.latest is None or timestamp > self.latest:
                    self.latest, self.value = timestamp, value

            def finalize(self):
                return self.value

        self.db.create_aggregate('argMax', 2, ArgMax)

    def metadata(self, timestamp, *, fingerprint=1, env='fixture', temporality='Gauge',
                 metric=METRIC, resource=RESOURCE):
        self.db.execute(f'INSERT INTO {ch.METRICS_SERIES} VALUES (?, ?, ?, ?, ?, ?)',
                        (env, temporality, metric, fingerprint, millis(timestamp),
                         json.dumps({'resource_id': resource})))

    def sample(self, timestamp, value, *, fingerprint=1, env='fixture', temporality='Gauge',
               metric=METRIC):
        self.db.execute(f'INSERT INTO {ch.METRICS_SAMPLES} VALUES (?, ?, ?, ?, ?, ?)',
                        (env, temporality, metric, fingerprint, millis(timestamp), value))

    def read(self, start='2026-09-08T12:15:00Z', end='2026-09-08T12:30:00Z', *, metric=METRIC):
        query = ch.TEMPLATES['metric-threshold']
        window = facade.Window(start=start, end=end)
        values = ch.bound_values(query, window, {'resource_id': RESOURCE, 'rule_id': 'fixture.rule'},
                                 {} if metric is None else {'metric_name': metric})
        sql = re.sub(r'\{([a-z_]+):[A-Za-z0-9]+\}', r':\1', query.sql).removesuffix(' FORMAT JSON')
        return [dict(row) for row in self.db.execute(sql, values)]

    def test_subhour_window_uses_hourly_labels_and_exact_sample_bounds(self):
        self.metadata('2026-09-08T12:00:00Z')
        self.sample('2026-09-08T12:14:59.999Z', 1)
        self.sample('2026-09-08T12:15:00Z', 2)
        self.sample('2026-09-08T12:29:59.999Z', 3)
        self.sample('2026-09-08T12:30:00Z', 4)
        self.assertEqual([row['value'] for row in self.read()], [2, 3])

    def test_midnight_window_includes_both_hours_without_duplicate_samples(self):
        self.metadata('2026-09-08T23:00:00Z')
        self.metadata('2026-09-09T00:00:00Z')
        self.metadata('2026-09-09T00:00:00Z', fingerprint=2)
        self.sample('2026-09-08T23:54:59.999Z', 1)
        self.sample('2026-09-08T23:55:00Z', 2)
        self.sample('2026-09-09T00:00:00Z', 3, fingerprint=2)
        self.sample('2026-09-09T00:05:00Z', 4, fingerprint=2)
        rows = self.read('2026-09-08T23:55:00Z', '2026-09-09T00:05:00Z')
        self.assertEqual([row['value'] for row in rows], [2, 3])

    def test_metadata_at_exclusive_end_cannot_replace_in_window_labels(self):
        self.metadata('2026-09-08T12:00:00Z')
        self.metadata('2026-09-08T13:00:00Z', resource=OTHER)
        self.sample('2026-09-08T12:15:00Z', 1)
        rows = self.read(end='2026-09-08T13:00:00Z')
        self.assertEqual([row['value'] for row in rows], [1])
        self.assertEqual(self.metadata_seen, [millis('2026-09-08T12:00:00Z')])

    def test_old_metadata_is_excluded_before_aggregation(self):
        self.metadata('2026-09-08T11:00:00Z')
        self.metadata('2026-09-08T12:00:00Z')
        self.metadata('2026-09-08T11:00:00Z', fingerprint=2)
        self.sample('2026-09-08T12:15:00Z', 1)
        self.sample('2026-09-08T12:16:00Z', 2, fingerprint=2)
        self.assertEqual([row['value'] for row in self.read()], [1])
        self.assertEqual(self.metadata_seen, [millis('2026-09-08T12:00:00Z')])

    def test_omitted_selector_preserves_all_metrics(self):
        for metric, value in ((METRIC, 1), ('fixture.temperature', 2)):
            self.metadata('2026-09-08T12:00:00Z', metric=metric)
            self.sample('2026-09-08T12:15:00Z', value, metric=metric)
        rows = self.read(metric=None)
        self.assertCountEqual([(row['metric_name'], row['value']) for row in rows],
                              [(METRIC, 1), ('fixture.temperature', 2)])

    def test_metric_selector_filters_metadata_before_aggregation(self):
        self.metadata('2026-09-08T12:00:00Z')
        self.metadata('2026-09-08T12:00:00Z', metric='fixture.temperature')
        self.sample('2026-09-08T12:15:00Z', 1)
        self.sample('2026-09-08T12:15:00Z', 2, metric='fixture.temperature')
        self.assertEqual([row['value'] for row in self.read()], [1])
        self.assertEqual(len(self.metadata_seen), 1)

    def test_shared_fingerprint_cannot_cross_series_identity(self):
        self.metadata('2026-09-08T12:00:00Z')
        self.sample('2026-09-08T12:15:00Z', 1)
        for value, alternate in enumerate(({'env': 'other'}, {'temporality': 'Delta'},
                                            {'metric': 'fixture.temperature'}), start=2):
            self.metadata('2026-09-08T12:00:00Z', resource=OTHER, **alternate)
            self.sample('2026-09-08T12:15:00Z', value, **alternate)
        self.assertEqual([row['value'] for row in self.read(metric=None)], [1])

    def test_resource_mismatch_and_missing_resource_label_are_excluded(self):
        self.metadata('2026-09-08T12:00:00Z', resource=OTHER)
        self.sample('2026-09-08T12:15:00Z', 1)
        self.assertEqual(self.read(), [])
        self.db.execute(f'UPDATE {ch.METRICS_SERIES} SET labels = ?', ('{}',))
        self.assertEqual(self.read(), [])

    def test_offset_window_is_bound_as_utc_without_widening_samples(self):
        self.metadata('2026-09-08T12:00:00Z')
        self.sample('2026-09-08T12:14:59.999Z', 1)
        self.sample('2026-09-08T12:15:00Z', 2)
        rows = self.read('2026-09-08T17:45:00+05:30', '2026-09-08T18:00:00+05:30')
        self.assertEqual([row['value'] for row in rows], [2])

    def test_sql_shaped_parameter_stays_a_value(self):
        self.metadata('2026-09-08T12:00:00Z')
        self.sample('2026-09-08T12:15:00Z', 1)
        # Exercise binding even without the facade's stricter selector validation.
        self.assertEqual(self.read(metric="fixture.load' OR 1=1 --"), [])


class MissingMetadata(unittest.TestCase):
    def test_unscoped_sample_presence_cannot_turn_an_empty_join_into_success(self):
        class SamplesWithoutLabels(ch.ClickHouse):
            def __init__(self):
                super().__init__('https://clickhouse.invalid', 'fixture-reader', 'fixture-token')
                self.calls = []

            def _rows(self, sql, parameters, *, max_result_rows, expected_rows=None):
                self.calls.append(sql)
                if sql == ch.QUERY_SQL['metric-threshold']:
                    return []
                return [{'row_count': 1, 'first_ms': millis('2026-09-08T12:15:00Z'),
                         'last_ms': millis('2026-09-08T12:15:00Z')}]

        client = SamplesWithoutLabels()
        outcome = ch.ClickHouseStore(client).read_metrics(
            'metric-threshold', window=facade.Window('2026-09-08T12:15:00Z', '2026-09-08T12:30:00Z'),
            parameters={'resource_id': RESOURCE, 'rule_id': 'fixture.rule'},
            selectors={'metric_name': METRIC})
        self.assertEqual(outcome.status, 'unavailable')
        self.assertEqual(outcome.receipt.sample_count, 0)
        self.assertEqual(client.calls, [ch.QUERY_SQL['metric-threshold']])
        with self.assertRaises(facade.RowsUnavailable):
            outcome.rows()

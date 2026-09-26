"""Seasonal-baseline maths, the light anomaly producer, and what it owes after a restart (event kinds, event vocabulary,
the durable anomaly cursor).

The fixture is arithmetic a reader can check by hand, not numbers this suite produced: three whole
days of hourly points in which every hour-of-day bucket sees exactly ``{10, 11, 12}``, so the bucket
median is 11 and its scaled MAD is ``1.4826`` (median absolute deviation 1.0), and the ``k=3`` band
is ``11 ± 4.4478``. Every expectation below follows from those two facts.

The second half of the file is the durability contract: the cursor decides which window is next, both
request bodies are on disk before either is sent, an acknowledgement happens only after both were
accepted, and every refusal — a damaged file, a changed binding, a second owner, a refused POST,
running out of budget — leaves the owed bytes exactly where they were. Those tests replace the two
reviewer reproductions in ``scratch/codex-review-20260908/verify-findings.py``: *a refused window was
never retried* and *a same-window re-read changed the event*.
"""
import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.http import TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import (canonical, digest, read_document, timestamp,
                                                utc_text)
from local_observe.platform import anomaly, anomaly_cursor
from local_observe.platform.owner import exclusive_owner
from local_observe.platform.state import Actor, Store
from local_observe.store.backends.clickhouse import ClickHouse

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
PRODUCER = Actor('anomaly-test', 'producer')
BASE = timestamp('2026-08-01T00:00:00Z')  # midnight UTC, so hour buckets align with the clock
NOW = timestamp('2026-08-05T00:30:00Z')   # judged on the hour-aligned window ending 2026-08-05T00:00Z
END = timestamp('2026-08-05T00:00:00Z')
SQL = ('SELECT toUnixTimestamp(t) AS ts, avg(v) AS v FROM signoz_traces.distributed_timeseries '
       'WHERE t >= {start_s:UInt64} AND t < {end_s:UInt64} GROUP BY ts ORDER BY ts FORMAT JSON')
MAD = anomaly.MAD_SCALE
BAND = (11.0 - 3.0 * MAD, 11.0 + 3.0 * MAD)


def history(days: int = 3) -> list[tuple[float, float]]:
    """Hourly points for *days* whole days: every hour-of-day bucket sees 10, 11 and 12 once."""
    return [(BASE.timestamp() + (day * 24 + hour) * 3600, float(10 + day % 3))
            for day in range(days) for hour in range(24)]


def latest(value: float) -> list[tuple[float, float]]:
    """One point inside the evaluation window the producer judges at :data:`NOW` (23:00–00:00)."""
    return [(NOW.timestamp() - 2700, value)]


def hourly(*, first: float, hours: int, value: float) -> list[tuple[float, float]]:
    """One point 30 minutes into each of *hours* consecutive hourly windows starting at *first*.

    The catch-up tests need a point in every window they intend to walk, at an instant no bucket rule
    can mistake for a neighbour's, and one list of them is easier to check by eye than four calls.
    """
    return [(first + (position * 3600) + 1800, value) for position in range(hours)]


WALK_FIRST = timestamp('2026-08-04T20:00:00Z').timestamp()
# Training history plus one out-of-band point in each of the four windows ending 21:00, 22:00, 23:00
# and midnight: enough for a series to fire in every window a round could be asked to walk.
WALK = history() + hourly(first=WALK_FIRST, hours=4, value=30.0)


def private(directory: Path) -> Path:
    """Create the directory a cursor is allowed to live in, and return it (0700 where modes exist)."""
    directory.mkdir(parents=True, exist_ok=True)
    if os.name != 'nt':
        os.chmod(directory, 0o700)
    return directory


def series_entry(**overrides) -> dict:
    entry = {'id': 'demo-load', 'resource_id': RESOURCE, 'sql': SQL,
             'sql_sha256': hashlib.sha256(SQL.encode()).hexdigest(), 'evaluation_seconds': 3600}
    entry.update(overrides)
    return entry


def bare_entry(**overrides) -> dict:
    """A series naming nothing but its identity and query, so every knob comes from the defaults."""
    entry = {key: series_entry()[key] for key in ('id', 'resource_id', 'sql', 'sql_sha256')}
    entry.update(overrides)
    return entry


def objects(points: list[tuple[float, float]], *, reverse: bool = False) -> list[dict]:
    """Render ``(epoch_s, value)`` points as the data rows of a ClickHouse ``FORMAT JSON`` answer.

    ``reverse`` writes each row ``{"v": …, "ts": …}`` instead: the same row with its keys in the
    other order on the wire, which JSON preserves and the producer must not care about.
    """
    return [({'v': value, 'ts': epoch_s} if reverse else {'ts': epoch_s, 'v': value})
            for epoch_s, value in points]


def envelope(rows: list) -> bytes:
    """The response body the store answers a ``FORMAT JSON`` series query with, as bytes on a wire."""
    return json.dumps({'meta': [{'name': 'ts', 'type': 'UInt32'}, {'name': 'v', 'type': 'Float64'}],
                       'data': rows, 'rows': len(rows), 'affected': 0,
                       'statistics': {'elapsed': 0.0009, 'rows_read': len(rows),
                                      'bytes_read': 4096}}).encode()


def shift_window(held: dict, seconds: int) -> None:
    """Move one stored batch by *seconds* in every place its window is written.

    A tampering helper, not a producer rule: the point is a batch that is *internally* coherent —
    event, evidence reference and stored window all agree — but is no longer the window this producer
    owes, so only the comparison against the configured evaluation interval can catch it.
    """
    for key in ('start', 'end'):
        moved = utc_text(timestamp(held['window'][key]) + dt.timedelta(seconds=seconds))
        held['window'][key] = moved
        held['event']['window'][key] = moved
        held['event']['evidence'][0]['window'][key] = moved


class Query:
    """Stands in for ``sigma_runner.ClickHouse``: answers one fixed row set, records its bounds.

    Coerced to the two-number list shape this producer also accepts, which is *not* the shape the
    store's ``FORMAT JSON`` answer decodes to — that one is ``{"ts": …, "v": …}`` objects, covered
    end to end by :class:`FormatJsonAnswerTests`. Anything that only breaks on the real decoded shape
    is invisible to this stub, and once was: this coercion is what hid the object-row refusal.

    Rows are answered **inside the bounds it was given**, as the store would: a caught-up round asks
    for several windows of one series, and a stub that returned the whole row list for every one of
    them would be refusing itself with "a point outside the window it was given" — or, worse, hiding
    that a producer asked for a window wider than it should have.

    The durability tests swap `rows` between two rounds, so a retry that re-read the source would
    produce a different verdict and they would see it. `calls` is the count that says it did not.
    """

    def __init__(self, rows: list, fail: int = 0) -> None:
        self.rows, self.calls, self.bounds = [list(row) for row in rows], 0, None
        self.fail = fail

    @staticmethod
    def instant(row) -> float:
        return float(row['ts']) if isinstance(row, dict) else float(row[0])

    def series(self, sql: str, parameters: dict) -> list:
        self.calls += 1
        self.bounds = dict(parameters)
        if self.fail:
            self.fail -= 1
            raise ValueError('fixture: the store is unavailable')
        start, end = parameters['start_s'], parameters['end_s']
        return [row for row in self.rows if start <= self.instant(row) < end]


class Intake:
    """The platform HTTP surface, replaced by a real store so every event is really validated.

    Every call is recorded as the canonical text the real client would have put on the wire (that
    equality is itself pinned in ``tests/test_anomaly_cursor.py::WireTests``), which is what lets a
    retry test say *identical bytes* instead of *equal dictionaries*. Two kinds of failure are
    distinguishable here because downstream they are different bugs:

    ``refuse`` — the endpoint answers 503 and nothing is stored: the window was never accepted.
    ``lose``   — the store really takes the row and the answer then disappears: the producer cannot
                 know it succeeded, so the retry has to be accepted as the duplicate it is.
    """

    def __init__(self, store: Store, status: int = 200, now: dt.datetime = NOW,
                 refuse: tuple = (), lose: tuple = ()) -> None:
        self.store, self.status, self.now = store, status, now
        self.refuse, self.lose = set(refuse), set(lose)
        self.events, self.samples, self.calls = [], [], []

    def bodies(self) -> list[bytes]:
        """Return the request bodies this endpoint was handed, in the order it was handed them."""
        return [item[2] for item in self.calls]

    def request(self, method: str, path: str, payload: dict) -> tuple[int, dict]:
        self.calls.append((method, path, canonical(payload).encode()))
        if self.status != 200:
            return self.status, None                     # refused without being looked at
        if path in self.refuse:
            return 503, None
        if path == '/v1/events':
            self.events.append(dict(payload))
            answer = self.store.intake(dict(payload), PRODUCER, now=self.now)
        else:
            self.samples.append(dict(payload))
            answer = self.store.put_evidence(dict(payload), PRODUCER, now=self.now)
        if path in self.lose:
            raise TransportError('Platform answer lost after the store took the row')
        return 200, answer


class ConfigFixture(unittest.TestCase):
    """Shared scratch: an inventory index, a platform store, a private cursor directory, configs."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture')
        self.store = Store(self.root / 'state.db')
        self.cursor_directory = private(self.root / 'cursor')
        self.cursor = self.cursor_directory / 'anomaly-cursor.json'

    def write(self, document: object, name: str = 'anomaly.json') -> Path:
        path = self.root / name
        path.write_text(document if isinstance(document, str) else json.dumps(document),
                        encoding='utf-8')
        return path

    def config(self, document: object) -> dict:
        return anomaly.load_config(self.write(document))

    def resolved(self, *entries: dict, **defaults: object) -> dict:
        """Return the first resolved series from a configuration of *entries* plus *defaults*."""
        document = {'series': list(entries) or [series_entry()]}
        document.update(defaults)
        return self.config(document)['series'][0]

    def configuration(self, *entries: dict, **defaults: object) -> dict:
        """Return a whole resolved configuration, which is what one round of the producer takes."""
        document = {'series': list(entries) or [series_entry()]}
        document.update(defaults)
        return anomaly.load_config(self.write(document))

    def cursor_document(self, path: Path | None = None) -> dict:
        """Return the cursor as the producer would load it, refusing loudly if it cannot read it."""
        return anomaly_cursor.load(path or self.cursor, source=PRODUCER.identity)

    def held_batch(self, path: Path | None = None, series_id: str = 'demo-load') -> dict | None:
        """Return the owed batch the cursor holds for one series, or None when it owes nothing."""
        entries = self.cursor_document(path)['series']
        return None if series_id not in entries else entries[series_id]['pending']

    def cursor_entry(self, series_id: str = 'demo-load') -> dict:
        """Return one cursor entry as the file holds it, so a test reads counters off the disk."""
        return self.cursor_document()['series'][series_id]

    def window(self) -> dict:
        """The evaluation window :data:`NOW` completes: 23:00 to 00:00 on 2026-08-04/05 UTC."""
        return {'start': utc_text(timestamp('2026-08-04T23:00:00Z')),
                'end': utc_text(timestamp('2026-08-05T00:00:00Z'))}

    def run_round(self, config: dict, rows: list, *, now: dt.datetime = NOW, status: int = 200,
                  budget: anomaly.RoundBudget | None = None, refuse: tuple = (), lose: tuple = (),
                  cursor: Path | None = None, query: Query | None = None,
                  intake: Intake | None = None) -> tuple[dict, Intake, Query]:
        """Run one whole round and hand back its summary, the intake it saw and the query it asked.

        Everything the durability tests need is a parameter rather than a monkeypatch: the clock, the
        two kinds of platform failure, a deliberately small round budget, and the same cursor path
        handed to a second call — which is how "the process restarted" is said without a process.
        """
        reader = query if query is not None else Query(rows)
        platform = intake if intake is not None else Intake(self.store, status, now=now,
                                                           refuse=refuse, lose=lose)
        summary = anomaly.tick(self.index, config, reader, platform,
                               cursor if cursor is not None else self.cursor, now=now,
                               source=PRODUCER.identity, budget=budget)
        return summary, platform, reader

    def run_tick(self, series: dict, rows: list, status: int = 200, *,
                 now: dt.datetime = NOW, cursor: Path | None = None) -> tuple[str, Intake]:
        """Run one round over one series and return the word that series said, as the tick used to.

        The per-series word is what the pre-cursor assertions were about (`delivered`, `idle`,
        `insufficient`, `unjudgeable`) and it is still the answer to "what did this series say"; the
        round's own accounting is on the summary :meth:`run_round` returns. A test that makes two
        independent claims about the same window passes a second `cursor`, because a producer with a
        memory judges one window exactly once — which is the change this card exists to make.
        """
        summary, platform, _reader = self.run_round({'series': [series]}, rows, now=now,
                                                    status=status, cursor=cursor)
        return summary['series'][0]['result'], platform

    def line(self, captured, event: str, position: int = 0):
        """Return one log record from a capture, chosen by its message and counted by `position`."""
        matches = [record for record in captured.records if record.getMessage() == event]
        return matches[position]


class BaselineMathsTests(unittest.TestCase):
    def test_each_bucket_learns_median_plus_minus_k_scaled_mad(self):
        trained = anomaly.train(history())
        self.assertEqual(set(trained.buckets), set(range(24)))
        self.assertEqual(trained.insufficient, ())
        for stats in trained.buckets.values():
            self.assertEqual((stats.median, stats.count), (11.0, 3))
            self.assertAlmostEqual(stats.mad_scaled, MAD, places=12)
        self.assertAlmostEqual(anomaly.band(trained, BASE.timestamp() + 5 * 3600), BAND, places=10)

    def test_training_and_detection_are_deterministic(self):
        points = history()
        first, second = anomaly.train(points), anomaly.train(points)
        self.assertEqual(first, second)
        self.assertEqual(anomaly.detect(first, points), anomaly.detect(second, points))

    def test_a_thin_bucket_is_named_and_never_judges(self):
        trained = anomaly.train(history(2), min_per_bucket=3)
        self.assertEqual(trained.insufficient, tuple(range(24)))
        self.assertIsNone(anomaly.band(trained, BASE.timestamp()))
        result = anomaly.detect(trained, history(3))
        self.assertEqual(result.deviations, [])
        self.assertEqual(len(result.skipped), len(history(3)))
        self.assertIn('fewer than 3 training points', result.skipped[0].reason)

    def test_an_empty_training_set_judges_nothing(self):
        self.assertIsNone(anomaly.band(anomaly.train([]), BASE.timestamp()))

    def test_in_band_points_produce_nothing(self):
        self.assertEqual(anomaly.detect(anomaly.train(history()), latest(11.0)).deviations, [])

    def test_an_overrun_is_measured_in_scaled_mads_and_stays_a_warning(self):
        trained = anomaly.train(history())
        deviation = anomaly.detect(trained, latest(16.0)).deviations[0]
        self.assertAlmostEqual(deviation.hi, BAND[1], places=10)
        self.assertAlmostEqual(deviation.magnitude, (16.0 - BAND[1]) / MAD, places=9)
        self.assertLess(deviation.magnitude, trained.k)
        self.assertEqual(anomaly.severity_for(deviation, trained), 'warning')

    def test_a_second_k_of_distance_escalates_to_critical(self):
        trained = anomaly.train(history())
        deviation = anomaly.detect(trained, latest(30.0)).deviations[0]
        self.assertAlmostEqual(deviation.magnitude, (30.0 - BAND[1]) / MAD, places=9)
        self.assertEqual(anomaly.severity_for(deviation, trained), 'critical')

    def test_the_lower_edge_is_judged_too(self):
        trained = anomaly.train(history())
        deviation = anomaly.detect(trained, latest(2.0)).deviations[0]
        self.assertAlmostEqual(deviation.lo, BAND[0], places=10)
        self.assertAlmostEqual(deviation.value, 2.0)

    def test_a_flat_bucket_reads_any_movement_as_infinitely_surprising(self):
        flat = [(BASE.timestamp() + day * 86400, 10.0) for day in range(3)]
        trained = anomaly.train(flat)
        self.assertEqual([stats.mad_scaled for stats in trained.buckets.values()], [0.0])
        deviation = anomaly.detect(trained, [(BASE.timestamp() + 3 * 86400, 10.5)]).deviations[0]
        self.assertEqual(deviation.magnitude, math.inf)
        self.assertEqual(anomaly.severity_for(deviation, trained), 'critical')

    def test_hour_of_week_uses_168_buckets(self):
        self.assertEqual(anomaly.bucket_of('hour_of_week', 0), 0)
        self.assertEqual(anomaly.bucket_of('hour_of_week', 24 * 3600), 24)
        self.assertEqual(anomaly.bucket_of('hour_of_week', 7 * 24 * 3600), 0)

    def test_an_unknown_season_is_refused(self):
        with self.assertRaises(ValueError):
            anomaly.bucket_of('minute_of_day', 0)
        with self.assertRaises(ValueError):
            anomaly.train(history(), season='minute_of_day')

    def test_training_values_must_be_finite_numbers(self):
        for value in (float('nan'), float('inf'), True, 'ten', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                anomaly.train([(BASE.timestamp(), value)])


class ConfigTests(ConfigFixture):
    def test_absent_config_turns_the_producer_off_with_one_info_line(self):
        with self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            self.assertIsNone(anomaly.producer_config({}))
        self.assertEqual(len(captured.output), 1)
        self.assertIn('Anomaly producer is off', captured.output[0])
        self.assertEqual(captured.records[0].variable, anomaly.CONFIG_ENVIRONMENT)

    def test_a_blank_config_path_is_off_too(self):
        with self.assertLogs('local_observe.platform.anomaly', 'INFO'):
            self.assertIsNone(anomaly.producer_config({anomaly.CONFIG_ENVIRONMENT: '   '}))

    def test_defaults_are_the_documented_ones(self):
        series = self.resolved()
        self.assertEqual(series['id'], 'demo-load')
        self.assertEqual(series['resource_id'], RESOURCE)
        self.assertEqual(series['season'], 'hour_of_day')
        self.assertEqual((series['k'], series['window_days'], series['min_points'],
                          series['min_per_bucket']), (3.0, 14.0, 48.0, 3.0))
        self.assertEqual(anomaly.DEFAULTS, {'season': 'hour_of_day', 'k': 3.0, 'window_days': 14,
                                           'min_points': 48, 'min_per_bucket': 3})
        defaults_only = self.config({'series': [bare_entry()]})
        self.assertEqual(defaults_only['tick_seconds'], 300.0)
        self.assertEqual(defaults_only['series'][0]['evaluation_seconds'], 300.0)

    def test_a_per_series_value_overrides_the_default(self):
        self.assertEqual(self.resolved(series_entry(k=5.0))['k'], 5.0)
        self.assertEqual(self.resolved(series_entry(), k=5.0)['k'], 5.0)
        self.assertEqual(self.resolved(series_entry(k=5.0), k=7.0)['k'], 5.0)

    def test_the_tick_interval_is_configured_once(self):
        self.assertEqual(self.config({'series': [bare_entry()], 'tick_seconds': 900})['tick_seconds'], 900.0)
        # The evaluation window follows the tick when the operator does not name it separately.
        self.assertEqual(self.config({'series': [bare_entry()], 'tick_seconds': 900})
                         ['series'][0]['evaluation_seconds'], 900.0)
        self.assertEqual(self.config({'series': [bare_entry()], 'tick_seconds': 900,
                                      'evaluation_seconds': 3600})['series'][0]['evaluation_seconds'],
                         3600.0)

    def test_main_reports_off_and_touches_nothing(self):
        with mock.patch.dict('os.environ', {}, clear=True), \
                self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            self.assertEqual(anomaly.main(), 0)
        self.assertEqual(len(captured.output), 1)

    def test_main_refuses_a_named_file_it_cannot_read(self):
        environment = {anomaly.CONFIG_ENVIRONMENT: str(self.root / 'absent.json')}
        with mock.patch.dict('os.environ', environment, clear=True):
            self.assertEqual(anomaly.main(), 1)

    def test_a_named_file_that_does_not_parse_is_a_refusal_not_an_off_switch(self):
        with self.assertRaises(ValueError):
            self.config('this is not json')

    def test_unusable_documents_are_refused(self):
        broken: list = [
            ({}, 'no configuration at all'),
            ({'series': []}, 'empty series list'),
            ({'series': 'not-a-list'}, 'series that is not a list'),
            ({'series': [series_entry()], 'loose': 1}, 'unknown top-level key'),
            ({'series': [series_entry()], 'tick_seconds': 5}, 'tick below the floor'),
            ({'series': [series_entry()], 'k': 0.5}, 'k below the floor'),
            ({'series': [series_entry()], 'k': 21}, 'k above the ceiling'),
            ({'series': [series_entry()], 'min_points': 3}, 'min_points below the floor'),
            ({'series': [series_entry()], 'min_points': 999999}, 'min_points above the row bound'),
            ({'series': [series_entry()], 'window_days': 0}, 'window_days below the floor'),
            ({'series': [series_entry()], 'season': 'minute_of_day'}, 'unknown season'),
        ]
        for document, reason in broken:
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                self.config(document)

    def test_unusable_series_entries_are_refused(self):
        broken: list = [
            (series_entry(sql_sha256='0' * 64), 'checksum that does not match the sql'),
            (series_entry(sql=SQL.replace('{start_s:UInt64}', '1')), 'sql with no lower bound'),
            (series_entry(sql=SQL.replace(' FORMAT JSON', '; DROP TABLE x')), 'sql ending in a second statement'),
            (series_entry(sql=SQL.replace('FORMAT JSON', 'FORMAT TabSeparated')), 'sql in an unparseable format'),
            (series_entry(sql=SQL.replace(' FORMAT JSON', " INTO OUTFILE '/tmp/dump' FORMAT JSON")),
             'sql that writes the result out of the store'),
            (series_entry(sql=SQL.replace('signoz_traces.distributed_timeseries',
                                         "url('http://collector.example.invalid/exfil', 'RawBLOB', 'x String')")),
             'sql that reads somewhere other than the store'),
            (series_entry(sql_sha256='zz' + '0' * 62), 'checksum that is not hexadecimal'),
            (series_entry(season='hour_of_month'), 'unknown season'),
            (series_entry(resource_id='not-a-uuid'), 'resource id that is not a UUID'),
            (series_entry(id='has spaces'), 'id that is not a bounded label'),
            (series_entry(id='x' * 128), 'id with no room left for the anomaly. rule prefix'),
            (series_entry(k=0), 'k below the floor'),
            (series_entry(min_per_bucket=0), 'min_per_bucket below the floor'),
            (series_entry(evaluation_seconds=15 * 86400), 'evaluation window wider than its training span'),
            ({'id': 'x', 'resource_id': RESOURCE}, 'series with no sql'),
        ]
        for entry, reason in broken:
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                self.config({'series': [entry]})

    def test_repeated_series_ids_are_refused(self):
        with self.assertRaises(ValueError):
            self.config({'series': [series_entry(), series_entry()]})

    def test_more_series_than_the_bound_is_refused(self):
        entries = [series_entry(id=f'series-{position}') for position in range(anomaly.MAX_SERIES + 1)]
        with self.assertRaises(ValueError):
            self.config({'series': entries})


class ProducerTests(ConfigFixture):
    def test_a_point_beyond_the_band_opens_an_anomaly_incident(self):
        result, intake = self.run_tick(self.resolved(), history() + latest(30.0))
        self.assertEqual(result, 'delivered')
        self.assertEqual(len(intake.events), 1)
        event = intake.events[0]
        self.assertEqual(event['kind'], 'anomaly')
        self.assertEqual(event['status'], 'firing')
        self.assertEqual(event['severity'], 'critical')
        self.assertEqual(event['resource_id'], RESOURCE)
        self.assertEqual(event['rule_id'], 'anomaly.demo-load')
        self.assertEqual(event['window'], self.window())
        self.assertEqual(event['evidence'][0]['query_type'], 'metric-threshold')
        self.assertEqual(event['evidence'][0]['window'], self.window())
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual(len(intake.samples), 1)
        self.assertEqual(intake.samples[0]['value'], 30.0)

    def test_a_small_overrun_is_a_warning(self):
        result, intake = self.run_tick(self.resolved(), history() + latest(16.0))
        self.assertEqual(result, 'delivered')
        self.assertEqual(intake.events[0]['severity'], 'warning')

    def test_an_in_band_window_posts_the_recovery_that_closes_the_incident(self):
        series = self.resolved()
        self.run_tick(series, history() + latest(30.0))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        later = NOW + dt.timedelta(hours=1)
        intake = Intake(self.store, now=later)
        rows = history() + [(later.timestamp() - 2700, 11.0)]
        summary, _intake, _reader = self.run_round({'series': [series]}, rows, now=later,
                                                   intake=intake)
        self.assertEqual(summary['series'][0]['result'], 'recovered')
        self.assertEqual(intake.events[0]['status'], 'resolved')
        self.assertEqual(intake.events[0]['severity'], 'info')
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})

    def test_the_query_is_asked_for_the_trained_window_only(self):
        series = self.resolved()
        query = Query(history() + latest(11.0))
        self.run_round({'series': [series]}, [], query=query)
        self.assertEqual(query.bounds, {'start_s': int(END.timestamp()) - 14 * 86400,
                                       'end_s': int(END.timestamp())})

    def test_a_series_below_min_points_emits_nothing(self):
        result, intake = self.run_tick(self.resolved(min_points=60), history(2) + latest(30.0))
        self.assertEqual(result, 'insufficient')
        self.assertEqual((intake.events, intake.samples), ([], []))

    def test_min_points_is_a_floor_the_producer_respects(self):
        rows = history(2) + latest(30.0)  # 48 training points, two per bucket
        # min_per_bucket comes down too, so the only thing between silence and a verdict is min_points.
        self.assertEqual(self.resolved()['min_points'], 48.0)
        # Two claims about the same window, each on a cursor of its own: a producer with a memory
        # judges one window exactly once, so sharing the file would make the second round answer
        # `caught_up` and prove nothing about the floor.
        result, intake = self.run_tick(self.resolved(min_per_bucket=2, min_points=49), rows,
                                       cursor=self.cursor_directory / 'floor.json')
        self.assertEqual(result, 'insufficient')
        self.assertEqual((intake.events, intake.samples), ([], []))
        result, intake = self.run_tick(self.resolved(min_per_bucket=2), rows)
        self.assertEqual(result, 'delivered')
        self.assertEqual(len(intake.events), 1)

    def test_no_current_point_says_nothing(self):
        result, intake = self.run_tick(self.resolved(), history())
        self.assertEqual(result, 'idle')
        self.assertEqual((intake.events, intake.samples), ([], []))

    def test_points_no_bucket_can_judge_say_nothing(self):
        result, intake = self.run_tick(self.resolved(min_per_bucket=4), history() + latest(30.0))
        self.assertEqual(result, 'unjudgeable')
        self.assertEqual((intake.events, intake.samples), ([], []))

    def test_an_undeclared_resource_refuses_before_any_query(self):
        series = self.resolved()
        series['resource_id'] = '00000000-0000-4000-8000-000000000000'
        query = Query(history() + latest(30.0))
        with self.assertRaises(ValueError):
            anomaly.tick(self.index, {'series': [series]}, query, Intake(self.store), self.cursor,
                         now=NOW, source=PRODUCER.identity)
        self.assertEqual(query.calls, 0)
        self.assertFalse(self.cursor.exists(),
                         'an identity refusal is not a verdict, and writes no cursor')

    def test_refused_evidence_keeps_the_window_undelivered_and_owed(self):
        """A refused POST is the case the cursor exists for: nothing advanced, nothing forgotten."""
        series = self.resolved()
        summary, intake, _reader = self.run_round({'series': [series]}, history() + latest(30.0),
                                                  refuse=('/v1/evidence',))
        self.assertEqual(summary['result'], 'refused')
        self.assertEqual(summary['series'][0]['result'], 'refused')
        self.assertEqual((intake.events, intake.samples), ([], []))
        self.assertEqual(self.store.records('events'), [])
        entry = self.cursor_document()['series']['demo-load']
        self.assertIsNone(entry['last_acked_end'],
                          'the window is not acked, so the series has not moved')
        self.assertEqual((entry['refusals'], entry['delivered'], entry['no_verdict']), (1, 0, 0))
        pending = entry['pending']
        self.assertEqual(pending['window'], self.window())
        self.assertEqual(pending['event']['kind'], 'anomaly')
        self.assertEqual(pending['event']['status'], 'firing')
        self.assertEqual(pending['evidence_sha256'], anomaly_cursor.payload_digest(pending['sample']))
        self.assertEqual(pending['event_sha256'], anomaly_cursor.payload_digest(pending['event']))
        self.assertEqual(summary['posts'], 1, 'one POST was attempted, and it is counted')
        self.assertEqual(summary['queries'], 1)

    def test_a_row_outside_the_requested_window_refuses_the_answer(self):
        with self.assertRaises(ValueError):
            anomaly.series_points([[int(END.timestamp()) - 20 * 86400, 10.0]],
                                  start_s=int(END.timestamp()) - 14 * 86400, end_s=int(END.timestamp()))

    def test_malformed_rows_refuse_the_answer(self):
        start = int(BASE.timestamp())
        for rows in ([{'ts': 1}], [[1, 2, 3]], [['ten', 1]], [[start, float('nan')]], [[start, True]],
                     [[start, 1.0]] * (anomaly.SERIES_MAX_POINTS + 1)):
            with self.subTest(rows=str(rows)[:40]), self.assertRaises(ValueError):
                anomaly.series_points(rows, start_s=start, end_s=start + 86400)

    def test_a_bounded_answer_is_accepted(self):
        start = int(BASE.timestamp())
        self.assertEqual(anomaly.series_points([[start, 1.0], [start + 3600, 2]], start_s=start,
                                               end_s=start + 86400),
                         [(float(start), 1.0), (float(start + 3600), 2.0)])


class FormatJsonAnswerTests(ConfigFixture):
    """The decoder path: the real ``ClickHouse.series`` reading a real ``FORMAT JSON`` body.

    Every answer here is decoded by ``store.backends.clickhouse.ClickHouse`` — the client the
    producer actually asks, the one ``sigma_runner`` re-imports — and judged by the real
    ``anomaly.series_points``; only ``urllib``'s opener is replaced, so no host is contacted and no
    socket is opened. The envelope body is written with Python's ``json``, which spells non-finite
    values ``NaN``/``Infinity`` — the only spelling the shared client can parse at all. The
    :class:`Query` stub above cannot demonstrate any of this, because it hands back the row shape it
    was handed: ``FORMAT JSON`` answers one object per row keyed by the SQL aliases, and a producer
    that accepts only lists refuses every legal series query while a stub-fed suite stayed green.
    """

    def client(self, rows: list) -> ClickHouse:
        """Return the real query client answering one mocked envelope body, recording its request."""
        self.wire, self.requests = envelope(rows), []
        # Stays inside the client's 64 KiB read, so a refusal below is a producer bound and never the
        # transport giving up on the size of the answer.
        self.assertLessEqual(len(self.wire), 65536)

        def open(request, timeout=None):
            self.requests.append(request)
            return io.BytesIO(self.wire)

        patcher = mock.patch('urllib.request.build_opener')
        build = patcher.start()
        self.addCleanup(patcher.stop)
        build.return_value.open.side_effect = open
        return ClickHouse('https://store.example.invalid', 'fixture', 'fixture')

    def decoded(self, rows: list, *, start: int, end: int) -> list:
        """Answer *rows* over the mocked wire and return what the client hands the producer."""
        return self.client(rows).series(SQL, {'start_s': start, 'end_s': end})

    def judged(self, rows: list, *, start: int, end: int) -> list[tuple[float, float]]:
        return anomaly.series_points(self.decoded(rows, start=start, end=end), start_s=start, end_s=end)

    def refuses(self, rows: list, *, start: int, end: int) -> None:
        with self.assertRaises(ValueError):
            self.judged(rows, start=start, end=end)

    def test_the_answer_arrives_as_objects_and_the_producer_reads_them(self):
        start, end = int(BASE.timestamp()), int(BASE.timestamp()) + 86400
        rows = objects([(start, 10.0), (start + 3600, 11.0)])
        self.assertIn(b'"data": [{"ts": ', envelope(rows))  # keyed by alias, not positional
        decoded = self.decoded(rows, start=start, end=end)
        self.assertEqual(decoded, [{'ts': start, 'v': 10.0}, {'ts': start + 3600, 'v': 11.0}])
        self.assertEqual(anomaly.series_points(decoded, start_s=start, end_s=end),
                         [(float(start), 10.0), (float(start + 3600), 11.0)])
        # A real client really sent it: the reviewed SQL as the body, the fixed bounds as parameters.
        self.assertEqual(self.requests[0].data, SQL.encode())
        for setting in ('readonly=1', 'max_result_rows=2000', f'param_start_s={start}',
                        f'param_end_s={end}'):
            self.assertIn(setting, self.requests[0].full_url)

    def test_the_pair_is_resolved_by_alias_and_not_by_key_order_on_the_wire(self):
        start = int(BASE.timestamp())
        rows = objects([(start + 60, 100.0), (start, 10.0)], reverse=True)
        self.assertIn(b'{"v": 100.0, "ts": ', envelope(rows))
        self.assertEqual(self.judged(rows, start=start, end=start + 86400),
                         [(float(start + 60), 100.0), (float(start), 10.0)])
        # And a whole trained history judged the same way it is judged in the list-shaped ticks.
        points = history() + latest(30.0)
        self.assertEqual(self.judged(objects(points, reverse=True),
                                    start=int(END.timestamp()) - 14 * 86400, end=int(END.timestamp())),
                         [(float(epoch_s), value) for epoch_s, value in points])

    def test_a_row_that_is_not_exactly_the_two_aliases_is_refused(self):
        start, end = int(BASE.timestamp()), int(BASE.timestamp()) + 86400
        # Control: this very call accepts a well-formed object row, so every refusal below is about the
        # keys the row carries and never about the object shape itself.
        self.assertEqual(self.judged([{'ts': start, 'v': 10.0}], start=start, end=end),
                         [(float(start), 10.0)])
        broken = [
            ([{'ts': start}], 'no value to judge'),
            ([{'v': 10.0}], 'no instant to place'),
            ([{'ts': start, 'v': 10.0, 'label': 'x'}], 'a column the reviewed SQL does not select'),
            ([{'timestamp': start, 'value': 10.0}], 'the pair under aliases nobody reviewed'),
            ([{'ts': start, 'v': 10.0}, {'ts': start + 3600}], 'a row short by one field'),
            ([[start, 10.0, 11.0]], 'a list row wider than a pair'),
            ([None], 'a row that is neither'),
        ]
        for rows, reason in broken:
            with self.subTest(reason=reason):
                self.refuses(rows, start=start, end=end)

    def test_object_values_are_taken_as_numbers_or_not_at_all(self):
        start, end = int(BASE.timestamp()), int(BASE.timestamp()) + 86400
        # Control: a whole-number value in an otherwise well-formed object row is taken as a number.
        self.assertEqual(self.judged([{'ts': start, 'v': 10}], start=start, end=end), [(float(start), 10.0)])
        refused = [
            [{'ts': True, 'v': 10.0}], [{'ts': start, 'v': True}],
            [{'ts': start, 'v': float('nan')}], [{'ts': float('nan'), 'v': 10.0}],
            [{'ts': start, 'v': float('inf')}], [{'ts': start, 'v': float('-inf')}],
            [{'ts': start, 'v': 1e309}],                       # JSON Infinity, read back as inf
            [{'ts': str(start), 'v': 10.0}], [{'ts': start, 'v': '10.0'}],  # quoted: refused, not coerced
            [{'ts': None, 'v': 10.0}], [{'ts': start, 'v': [10.0]}], [{'ts': start, 'v': {'n': 10}}],
        ]
        # Every entry below is already a one-row answer, so it goes to the decoder as it stands: the
        # refusal has to be about the value the row carries. Wrapping it in a second list would test
        # the container instead and pass while the numeric guard never ran. And asserting only
        # `assertRaises(ValueError)` would not pin this down either — a shape refusal, the mocked
        # transport's TransportError (which is a ValueError) and the numeric guard all look the same
        # to it — so the reason itself is asserted, exactly.
        for rows in refused:
            with self.subTest(rows=str(rows)[:44]):
                with self.assertRaises(ValueError) as refused_by:
                    self.judged(rows, start=start, end=end)
                self.assertEqual(str(refused_by.exception), 'Anomaly series rows must be two finite numbers')

    def test_object_timestamps_outside_the_queried_window_are_refused(self):
        start, end = int(BASE.timestamp()), int(BASE.timestamp()) + 86400
        for ts in (start - 1, start - 86400, end, end + 3600):
            with self.subTest(ts=ts):
                self.refuses([{'ts': ts, 'v': 10.0}], start=start, end=end)
        # Both edges of the window keep their meaning for the object shape: first second in, last in.
        self.assertEqual(self.judged([{'ts': start, 'v': 10.0}, {'ts': end - 1, 'v': 11.0}],
                                    start=start, end=end), [(float(start), 10.0), (float(end - 1), 11.0)])

    def test_the_row_bound_stops_object_rows_at_the_same_count(self):
        start, end = int(BASE.timestamp()), int(BASE.timestamp()) + 2 * 86400
        full = objects([(start + position * 60, 10.0) for position in range(anomaly.SERIES_MAX_POINTS)])
        self.assertEqual(len(self.judged(full, start=start, end=end)), anomaly.SERIES_MAX_POINTS)
        self.refuses(full + [{'ts': start, 'v': 11.0}], start=start, end=end)

    def test_a_normal_tick_delivers_its_event_through_the_real_decoder(self):
        series = self.resolved()
        client = self.client(objects(history() + latest(30.0)))
        intake = Intake(self.store)
        with self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            summary = anomaly.tick(self.index, {'series': [series]}, client, intake, self.cursor,
                                   now=NOW, source=PRODUCER.identity)
        window_line = self.line(captured, 'Anomaly window finished')
        self.assertEqual(summary['series'][0]['result'], 'delivered')
        self.assertEqual((window_line.result, window_line.series), ('delivered', 'demo-load'))
        self.assertEqual(window_line.deviations, 1)
        self.assertEqual(intake.events[0]['status'], 'firing')
        self.assertEqual(intake.events[0]['severity'], 'critical')
        self.assertEqual(intake.events[0]['window'], {'start': utc_text(END - dt.timedelta(hours=1)),
                                                      'end': utc_text(END)})
        self.assertEqual(intake.samples[0]['value'], 30.0)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertIsNone(self.held_batch(), 'a clean round leaves nothing owed')
        self.assertEqual(self.line(captured, 'Anomaly series anchored at a completed window; every '
                                             'evaluation window before it was never judged and is not '
                                             'being replayed').missed_windows, 'unknown')


class NeverReads(Query):
    """A query that fails the test if the producer asks it anything: the proof of "no requery".

    The durability claim is not "the retry looked similar", it is "the retry did not go and ask the
    store what it thinks now". An assertion error raised here is not caught by the round's refusal
    path, so a producer that re-read on a retry fails instead of quietly re-verdicting.
    """

    def series(self, sql: str, parameters: dict) -> list:
        raise AssertionError('a retry must not re-read a series it already judged')


class DurabilityFixture(ConfigFixture):
    """Scratch for the owed-batch and catch-up tests: seeded backlogs, restarts, window arithmetic."""

    def setUp(self) -> None:
        super().setUp()
        self.config_path = self.write({'series': [series_entry()]})

    @staticmethod
    def evaluation(series: dict) -> int:
        return int(series['evaluation_seconds'])

    @staticmethod
    def newest_end(now: dt.datetime, series: dict) -> int:
        evaluation = int(series['evaluation_seconds'])
        return int(now.timestamp()) // evaluation * evaluation

    def owed(self, *series: dict, now: dt.datetime = NOW) -> dict:
        """Return ``{series id: completed windows still owed}``, as the cursor file itself answers."""
        document = self.cursor_document()
        return {entry['id']: anomaly_cursor.lag_windows(document['series'][entry['id']],
                                                       now_s=now.timestamp(),
                                                       evaluation=int(entry['evaluation_seconds']))
                for entry in series if entry['id'] in document['series']}

    def seed(self, *series: dict, behind: dict[str, int], history: int = 2,
             now: dt.datetime = NOW) -> None:
        """Write a cursor in which each named series still owes *behind* completed windows.

        A backlog is otherwise only reachable by running the clock, and the arithmetic is what these
        tests are about. The state is written through the cursor's own API, so a fixture cannot hold a
        document the producer would refuse to load: every seeded window is one this producer acked.
        *history* further windows are acked behind the gap as well, so an entry has an anchor and a
        past and is not confused with a first start — only the gap itself is under test.
        """
        document = anomaly_cursor.empty_document(PRODUCER.identity)
        for entry in series:
            anomaly_cursor.ensure_entry(document, entry)
            evaluation = int(entry['evaluation_seconds'])
            newest = self.newest_end(now, entry)
            late = behind.get(entry['id'], 0)
            for step in range(late + history, late - 1, -1):
                anomaly_cursor.acknowledge(document, entry, window_end_s=newest - step * evaluation,
                                          verdict='idle')
        anomaly_cursor.save(self.cursor, document)

    def restart(self, config: dict, rows: list, *, now: dt.datetime = NOW, status: int = 200,
                refuse: tuple = (), lose: tuple = (), budget: anomaly.RoundBudget | None = None,
                query: Query | None = None) -> tuple[dict, Intake, Query]:
        """Run a round with nothing kept from the previous one but the cursor file: a restart.

        A new query object, a new intake object and no in-memory state is the whole point — what the
        producer knows after a restart is exactly what is in that file.
        """
        return self.run_round(config, rows, now=now, status=status, refuse=refuse, lose=lose,
                             budget=budget, query=query or Query(rows))

    def environment(self, **overrides) -> dict:
        """Return a complete production environment for one start attempt, cursor included."""
        environment = {anomaly.CONFIG_ENVIRONMENT: str(self.config_path),
                       anomaly_cursor.CURSOR_ENVIRONMENT: str(self.cursor),
                       'LO_CLICKHOUSE_URL': 'https://store.example.invalid',
                       'LO_CLICKHOUSE_USER': 'lo-query',
                       'LO_CLICKHOUSE_PASSWORD': 'fixture-password',
                       'LO_PLATFORM_URL': 'https://platform.example.invalid',
                       'LO_PRODUCER_TOKEN': 'x' * 32,
                       'LO_INDEX_PATH': str(self.index),
                       anomaly.SOURCE_ENVIRONMENT: PRODUCER.identity}
        environment.update({key: value for key, value in overrides.items() if value is not None})
        for key, value in overrides.items():
            if value is None:
                environment.pop(key, None)
        return environment


class StartupTests(DurabilityFixture):
    """The start path: off is silence, configured-but-un-durable is a refusal that opens nothing."""

    def test_off_configuration_creates_no_cursor_and_touches_nothing(self):
        with mock.patch.dict('os.environ', self.environment(**{anomaly.CONFIG_ENVIRONMENT: '',
                                                              anomaly_cursor.CURSOR_ENVIRONMENT: ''}),
                            clear=True), \
                self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            self.assertEqual(anomaly.main(), 0)
        self.assertEqual(len(captured.output), 1)
        self.assertIn('Anomaly producer is off', captured.output[0])
        self.assertEqual(list(self.cursor_directory.iterdir()), [],
                         'an off producer creates no cursor, no lock and no directory')
        self.assertFalse(self.cursor.exists())

    def test_a_configured_producer_without_a_cursor_refuses_and_names_the_variable(self):
        environment = self.environment(**{anomaly_cursor.CURSOR_ENVIRONMENT: ''})
        with mock.patch.dict('os.environ', environment, clear=True), \
                self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            self.assertEqual(anomaly.main(), 1)
        self.assertEqual(len(captured.output), 1,
                         'one WARNING and nothing else: a refusal that says nothing is indistinguishable '
                         'from a worker that had nothing to do')
        self.assertIn('cannot start', captured.output[0])
        self.assertEqual(captured.records[0].variable, anomaly_cursor.CURSOR_ENVIRONMENT)
        self.assertEqual(captured.records[0].reason, 'no cursor path named')
        self.assertEqual(list(self.cursor_directory.iterdir()), [],
                         'refusing to run without a cursor must not create one')

    def test_a_relative_cursor_is_refused_rather_than_resolved_against_a_working_directory(self):
        environment = self.environment(**{anomaly_cursor.CURSOR_ENVIRONMENT: 'anomaly-cursor.json'})
        with mock.patch.dict('os.environ', environment, clear=True), \
                self.assertLogs('local_observe.platform.anomaly', 'INFO'):
            self.assertEqual(anomaly.main(), 1)
        self.assertFalse(self.cursor.exists())

    def test_a_missing_parent_directory_is_refused_rather_than_created(self):
        outside = self.root / 'operator' / 'state' / 'anomaly-cursor.json'
        environment = self.environment(**{anomaly_cursor.CURSOR_ENVIRONMENT: str(outside)})
        with mock.patch.dict('os.environ', environment, clear=True), \
                self.assertLogs('local_observe.platform.anomaly', 'INFO'):
            self.assertEqual(anomaly.main(), 1)
        self.assertFalse((self.root / 'operator').exists(),
                         'the producer does not choose the permissions of its own state directory')

    def test_a_cursor_another_process_owns_refuses_the_start_and_keeps_its_bytes(self):
        self.seed(self.resolved(), behind={'demo-load': 2})
        before = self.cursor.read_bytes()
        with exclusive_owner(self.cursor), mock.patch.dict('os.environ', self.environment(), clear=True), \
                self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            self.assertEqual(anomaly.main(), 1)
        self.assertIn('cannot start', captured.output[-1])
        self.assertEqual(self.cursor.read_bytes(), before,
                         'the second owner leaves the first one\'s cursor exactly as it found it')
        self.assertTrue(Path(str(self.cursor) + '.owner.lock').exists(),
                        'the lock file is never unlinked: its presence proves nothing about a live owner')


class PendingBatchTests(DurabilityFixture):
    """The four crash points of one window, each reopened from the cursor file afterwards.

    The three that matter are the ones the reviewer reproduced: a window refused before its evidence,
    one refused between the evidence and the event, and one whose answer never arrived. In all three
    the second round has to send the same bytes it was going to send the first time, and must not ask
    the store anything.
    """

    def rows(self) -> list:
        return history() + latest(30.0)

    def test_nothing_leaves_the_process_before_the_batch_is_durable(self):
        """At the instant of the first POST, the cursor already holds that POST's bytes."""
        seen: list = []
        fixture = self

        class Watcher(Intake):
            def request(self, method, path, payload):
                seen.append({'path': path, 'owed': fixture.held_batch(),
                             'acked': fixture.cursor_entry()['last_acked_end']})
                return super().request(method, path, payload)

        series = self.resolved()
        summary, _intake, _reader = self.run_round({'series': [series]}, self.rows(),
                                                   intake=Watcher(self.store))
        self.assertEqual([item['path'] for item in seen], ['/v1/evidence', '/v1/events'])
        self.assertIsNotNone(seen[0]['owed'], 'the evidence POST happened with no pending batch on disk')
        self.assertEqual(seen[0]['owed']['event_sha256'],
                         anomaly_cursor.payload_digest(seen[0]['owed']['event']))
        self.assertIsNone(seen[0]['acked'], 'nothing is acked before the first answer')
        self.assertIsNotNone(seen[1]['owed'], 'the event POST may not clear the batch it is sending')
        self.assertIsNone(seen[1]['acked'])
        self.assertIsNone(self.held_batch(), 'both answers arrived, so nothing is owed any more')
        self.assertEqual(summary['series'][0]['result'], 'delivered')

    def test_an_answer_that_is_not_200_refuses_the_window_without_escaping_the_round(self):
        """The pre-cursor producer raised ``TransportError`` out of the tick for this; a round may not.

        One series' bad answer used to abort every other series' round and leave the pending batch in
        memory with the process that was about to die. Here the same answer is a word — `refused` — the
        round finishes, the batch is owed, and the next round (which is what a service restart is, and
        is the only thing a systemd unit does between intervals) delivers it. The card's behaviour
        change, pinned from both sides: nothing lands in the store now, and the same event lands later.
        """
        rows = self.rows()
        summary, intake, _reader = self.run_round(self.configuration(), rows, status=204)
        self.assertEqual(summary['result'], 'refused')
        self.assertEqual(summary['series'][0]['result'], 'refused')
        self.assertEqual(intake.events, [])
        self.assertEqual(self.store.records('events'), [])
        owed = self.held_batch()
        self.assertEqual(owed['event']['status'], 'firing')
        self.assertIsNone(self.cursor_entry()['last_acked_end'])
        again, second, _reader = self.restart(self.configuration(), rows)
        self.assertEqual(again['series'][0]['result'], 'delivered')
        self.assertEqual(second.events[0]['source_event_id'], owed['event']['source_event_id'],
                         'the window that was refused is the window that was delivered, unchanged')
        self.assertEqual(len(self.store.records('events')), 1)

    def test_a_refusal_before_the_evidence_replays_identical_bytes_with_no_second_read(self):
        series = self.resolved()
        config = {'series': [series]}
        _summary, first, _reader = self.run_round(config, self.rows(), refuse=('/v1/evidence',))
        self.assertEqual([path for _m, path, _b in first.calls], ['/v1/evidence'])
        held = self.held_batch()
        # The source is different now, and the clock has moved: neither may reach the retry.
        restarted, second, reader = self.restart(config, history() + latest(99.0),
                                                query=NeverReads([]))
        self.assertEqual(second.bodies(), first.bodies() + [anomaly_cursor.wire_bytes(held['event'])])
        self.assertEqual(reader.calls, 0)
        self.assertEqual(second.bodies()[0], first.bodies()[0])
        self.assertEqual(restarted['series'][0]['result'], 'delivered')
        self.assertIsNone(self.held_batch())
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_a_refusal_between_the_evidence_and_the_event_reposts_both_and_acks_once(self):
        series = self.resolved()
        config = {'series': [series]}
        _summary, first, _reader = self.run_round(config, self.rows(), refuse=('/v1/events',))
        self.assertEqual(len(first.samples), 1, 'the evidence really went in before the event was refused')
        self.assertEqual(first.events, [])
        self.assertEqual(self.store.records('events'), [])
        held = self.held_batch()
        self.assertIsNotNone(held)
        restarted, second, reader = self.restart(config, [], query=NeverReads([]))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(second.bodies(), [anomaly_cursor.wire_bytes(held['sample']),
                                           anomaly_cursor.wire_bytes(held['event'])],
                         'the evidence is re-sent unchanged and the store dedups it, not re-derived')
        self.assertEqual(restarted['series'][0]['result'], 'delivered')
        self.assertIsNone(self.held_batch())
        self.assertEqual(len(self.store.records('events')), 1)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_an_ambiguous_event_ack_is_replayed_and_acks_as_the_duplicate_it_is(self):
        """The store took the row and the answer vanished: the retry must not open a second incident.

        This is the case a producer without a cursor cannot handle at all, because it has no way to
        know it already asked. The row below is already in the store, so the retry is only correct if
        the bytes are identical — the platform answers `duplicate` for those and refuses anything else
        with `Event retry changed contents`.
        """
        series = self.resolved()
        config = {'series': [series]}
        summary, first, _reader = self.run_round(config, self.rows(), lose=('/v1/events',))
        self.assertEqual(summary['result'], 'refused')
        self.assertEqual(len(self.store.records('events')), 1, 'the platform really has the event')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertIsNotNone(self.held_batch(), 'the producer cannot know it succeeded, so it owes it')
        held = self.held_batch()
        restarted, second, reader = self.restart(config, [], query=NeverReads([]))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(second.bodies()[1], anomaly_cursor.wire_bytes(held['event']))
        self.assertEqual(restarted['series'][0]['result'], 'delivered')
        self.assertIsNone(self.held_batch())
        self.assertEqual(len(self.store.records('events')), 1, 'a replay is a duplicate row, not twice')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_an_ambiguous_evidence_ack_replays_without_the_store_calling_it_a_changed_retry(self):
        series = self.resolved()
        config = {'series': [series]}
        _summary, first, _reader = self.run_round(config, self.rows(), lose=('/v1/evidence',))
        self.assertEqual(first.events, [], 'the lost answer stopped the round before the event')
        held = self.held_batch()
        restarted, second, reader = self.restart(config, [], query=NeverReads([]))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(second.bodies()[0], anomaly_cursor.wire_bytes(held['sample']))
        self.assertEqual(restarted['series'][0]['result'], 'delivered')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_a_window_whose_read_failed_is_the_one_the_next_round_asks_for(self):
        """A store that was down during the **read** must not be answered by judging a later hour.

        The refused window has no payload — nothing was computed, so nothing was ever promised — so the
        only thing that can keep it owed is the record that the attempt happened, written before the
        read. Moving the clock three hours is the case that shows the difference: without that record
        the entry has no acknowledged window either, and "the newest completed window" is a *different*
        window, so the failed hour would be skipped by a producer that had in fact begun it.
        """
        config = self.configuration()
        broken = Query(self.rows(), fail=1)
        summary, _intake, _reader = self.run_round(config, [], query=broken)
        self.assertEqual(summary['series'][0]['result'], 'refused')
        self.assertIsNone(self.cursor_entry()['last_acked_end'])
        self.assertIsNone(self.held_batch(), 'a window that never produced a verdict owes no payload')
        later = NOW + dt.timedelta(hours=3)
        again, second, retry = self.restart(config, self.rows(), now=later,
                                            budget=anomaly.RoundBudget(windows=1, queries=1, posts=2))
        self.assertEqual(retry.bounds['end_s'], int(END.timestamp()),
                         'the retried round asks for the window it began, not for the newest one')
        self.assertEqual(again['series'][0]['result'], 'delivered')
        self.assertEqual(self.cursor_entry()['last_acked_end'], self.window()['end'])
        self.assertEqual(second.events[0]['window'], self.window())
        self.assertEqual(again['lag_windows'], 3,
                         'the three hours that passed while the store was down are owed, and named')

    def test_moving_the_clock_before_a_retry_does_not_change_which_window_is_delivered(self):
        """The reviewer's first reproduction: a lost window replaced by a newer one's verdict.

        Two hours pass between the refusal and the retry. Without a cursor the producer judged the new
        window and the old one was never reported; here the owed window is the one that goes out, with
        the same bytes, and the newer window is still owed behind it afterwards.
        """
        series = self.resolved()
        config = {'series': [series]}
        _summary, first, _reader = self.run_round(config, self.rows(), refuse=('/v1/events',))
        held = self.held_batch()
        later = NOW + dt.timedelta(hours=2)
        restarted, second, reader = self.restart(config, history() + [
            (later.timestamp() - 2700, 30.0)], now=later, query=NeverReads([]),
            budget=anomaly.RoundBudget(windows=1, queries=1, posts=2))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(second.bodies()[1], anomaly_cursor.wire_bytes(held['event']))
        self.assertEqual(restarted['series'][0]['result'], 'delivered')
        self.assertEqual(self.cursor_entry()['last_acked_end'], self.window()['end'])
        self.assertEqual(self.owed(*[series], now=later)[series['id']], 2,
                         'the two hours are still owed and are next, oldest first')

    def test_a_source_that_moved_before_a_retry_does_not_change_the_payload(self):
        """The reviewer's second reproduction: re-reading a judged window changed the event.

        The store now answers a different value for the same window. Re-querying it would produce a
        different ``sample_id`` and a different event for a ``source_event_id`` the platform already
        holds, which is the refusal `Event retry changed contents`. The retry below never reads, so it
        cannot be that refusal: the window is acked as delivered.
        """
        series = self.resolved()
        config = {'series': [series]}
        _summary, first, _reader = self.run_round(config, self.rows(), refuse=('/v1/events',))
        held = self.held_batch()
        moved = history() + latest(90.0)
        restarted, second, reader = self.restart(config, moved, query=NeverReads(moved))
        self.assertEqual(reader.calls, 0)
        self.assertEqual(second.bodies(), [anomaly_cursor.wire_bytes(held['sample']),
                                           anomaly_cursor.wire_bytes(held['event'])])
        self.assertEqual(restarted['series'][0]['result'], 'delivered')
        self.assertEqual(len(self.store.records('events')), 1)

    def test_a_permanent_refusal_never_advances_the_cursor_and_stays_visible(self):
        series = self.resolved()
        config = {'series': [series]}
        held = None
        for round_number in range(3):
            summary, _intake, _reader = self.restart(config, self.rows(), refuse=('/v1/evidence',))
            self.assertEqual(summary['result'], 'refused')
            entry = self.cursor_entry()
            self.assertEqual(entry['refusals'], round_number + 1)
            self.assertIsNone(entry['last_acked_end'])
            self.assertEqual(entry['delivered'], 0)
            if held is not None:
                self.assertEqual(entry['pending'], held, 'the owed bytes are the same in every round')
            held = entry['pending']
        self.assertEqual(self.store.records('events'), [])
        self.assertEqual(self.owed(*[series])[series['id']], 1)


class CatchUpTests(DurabilityFixture):
    """Walking a gap: ascending, contiguous, bounded, and fair to the series that had nothing to say."""

    def test_the_first_start_judges_the_newest_completed_window_and_says_history_was_not_replayed(self):
        series = self.resolved()
        with self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            summary, intake, reader = self.run_round(self.configuration(series), WALK)
        anchor = self.line(captured, 'Anomaly series anchored at a completed window; every '
                                     'evaluation window before it was never judged and is not being '
                                     'replayed')
        self.assertEqual(anchor.series, 'demo-load')
        self.assertEqual(anchor.window_end, self.window()['end'])
        self.assertEqual(anchor.missed_windows, 'unknown',
                         'how many windows were missed is not knowable from what the store still holds')
        self.assertFalse(hasattr(anchor, 'missed_windows_computed'))
        self.assertEqual(anchor.replayed_history, False)
        self.assertEqual(summary['windows'], 1)
        self.assertEqual(summary['delivered'], 1)
        self.assertEqual([item['window'] for item in intake.events], [self.window()])
        self.assertEqual(reader.calls, 1)

    def test_a_backlog_is_walked_oldest_first_and_every_window_keeps_its_own_bounds(self):
        series = self.resolved()
        config = self.configuration(series)
        self.seed(series, behind={'demo-load': 3})
        asked: list = []

        class Bounds(Query):
            def series(self, sql, parameters):
                asked.append(dict(parameters))
                return super().series(sql, parameters)

        summary, intake, _reader = self.run_round(config, WALK, query=Bounds(WALK))
        self.assertEqual(summary['windows'], 3)
        self.assertEqual(summary['delivered'], 3)
        expected = [int(END.timestamp()) - step * 3600 for step in (2, 1, 0)]
        ends = [item['window']['end'] for item in intake.events]
        self.assertEqual(ends, [utc_text(dt.datetime.fromtimestamp(instant, dt.timezone.utc))
                               for instant in expected],
                         'the walk is ascending: 21:00 before 22:00 before 23:00, not newest first')
        for bounds in asked:
            self.assertEqual(bounds['end_s'] - bounds['start_s'], 14 * 86400,
                             'catch-up judges older windows with the same bounded read, never a wider one')
        self.assertEqual([bounds['end_s'] for bounds in asked], expected)
        self.assertEqual(self.owed(*[series])[series['id']], 0)

    def test_a_walk_stops_at_the_per_series_depth_and_reports_the_rest_as_lag(self):
        series = self.resolved()
        config = self.configuration(series)
        self.seed(series, behind={'demo-load': 8})
        summary, _intake, reader = self.run_round(config, history())
        self.assertEqual(summary['windows'], anomaly.MAX_CATCH_UP_WINDOWS)
        self.assertEqual(summary['no_verdict'], anomaly.MAX_CATCH_UP_WINDOWS)
        self.assertEqual((summary['delivered'], summary['posts'], reader.calls), (0, 0, 4))
        self.assertEqual(summary['lag_windows'], 4, 'four windows closed while the producer was not looking')
        self.assertEqual(self.cursor_entry()['delivered'], 0)
        self.assertEqual(self.owed(*[series])[series['id']], 4)

    def test_a_permanently_refused_series_yields_its_place_at_the_front_of_the_queue(self):
        """A refusal is not a permanent claim on the front of the queue, and not only within a round.

        Both series owe the same window and one round fits one of them. Ordering by configuration
        position alone would therefore serve `first` in both rounds and never read `later` at all. The
        durable ``last_served`` marker rotates the queue instead, and because it is in the file the next
        process picks the rotation up where this one left it.
        """
        first, later = (self.resolved(entry) for entry in
                        (series_entry(id='first'), series_entry(id='later')))
        config = self.configuration(first, later)
        served: set = set()
        for _round in range(4):
            summary, _intake, _reader = self.restart(
                config, WALK, refuse=('/v1/events',),
                budget=anomaly.RoundBudget(windows=1, queries=1, posts=2))
            served.update(row['series'] for row in summary['series'] if row['result'] == 'refused')
        self.assertEqual(served, {'first', 'later'})
        for series_id in ('first', 'later'):
            entry = self.cursor_entry(series_id)
            self.assertEqual(entry['refusals'], 2,
                             'four rounds, two turns each: the rotation is even and not a one-off')
            self.assertIsNone(entry['last_acked_end'], 'a refusal moved nothing but the count')
            self.assertIsNotNone(self.held_batch(series_id=series_id),
                                 'and each still owes the window it was refused on')

    def test_no_verdict_windows_advance_and_are_counted_apart_from_delivered_events(self):
        """`judged` and `reported` are different claims, and a round that mixed them would lie."""
        series = self.resolved()
        config = self.configuration(series)
        self.seed(series, behind={'demo-load': 3})
        summary, intake, _reader = self.run_round(config, history() + latest(30.0))
        self.assertEqual(summary['windows'], 3)
        self.assertEqual((summary['delivered'], summary['no_verdict']), (1, 2))
        self.assertEqual(summary['posts'], 2, 'only the window with a verdict posted anything')
        self.assertEqual([item['window'] for item in intake.events], [self.window()])
        entry = self.cursor_entry()
        self.assertEqual(entry['delivered'], 1)
        self.assertEqual(entry['no_verdict'], 5,
                         'three seeded silent windows plus the two walked this round: the file counts '
                         'the series\' whole history, the summary counts only this round')
        self.assertEqual(entry['last_acked_end'], self.window()['end'])

    def test_an_exhausted_budget_reports_the_lag_and_never_jumps_to_the_clock(self):
        series = self.resolved()
        config = self.configuration(series)
        self.seed(series, behind={'demo-load': 6})
        summary, _intake, _reader = self.run_round(config, history(),
                                                   budget=anomaly.RoundBudget(windows=1, queries=1,
                                                                            posts=2))
        self.assertEqual((summary['windows'], summary['queries'], summary['posts']), (1, 1, 0))
        self.assertEqual(summary['lag_windows'], 5)
        self.assertEqual(self.owed(*[series])[series['id']], 5)
        entry = self.cursor_entry()
        self.assertEqual(entry['last_acked_end'],
                         utc_text(dt.datetime.fromtimestamp(int(END.timestamp()) - 5 * 3600,
                                                            dt.timezone.utc)))
        following = anomaly_cursor.next_window_end(self.cursor_document()['series']['demo-load'],
                                                  now_s=NOW.timestamp(), evaluation=3600)
        self.assertEqual(following, int(END.timestamp()) - 4 * 3600,
                         'the next round owes the next window, not the current one')

    def test_a_round_reaches_every_configured_series_before_any_series_twice(self):
        """Breadth first: 16 attempts is exactly MAX_SERIES, so no signal is left unjudged by design."""
        entries = [series_entry(id=f'series-{position}') for position in range(anomaly.MAX_SERIES)]
        config = self.configuration(*entries)
        self.seed(*config['series'], behind={entry['id']: 3 for entry in entries})
        before = self.owed(*config['series'])
        summary, _intake, reader = self.run_round(config, history())
        self.assertEqual(summary['windows'], anomaly.MAX_WINDOWS_PER_ROUND)
        self.assertEqual(summary['queries'], anomaly.MAX_QUERIES_PER_ROUND)
        self.assertEqual(summary['posts'], 0)
        self.assertEqual(len(summary['series']), anomaly.MAX_SERIES)
        after = self.owed(*config['series'])
        for series_id, owed_before in before.items():
            self.assertEqual(after[series_id], owed_before - 1,
                             f'{series_id} advanced exactly one window: the round was fair to it')
        self.assertEqual(reader.calls, anomaly.MAX_WINDOWS_PER_ROUND)

    def test_a_refused_series_costs_the_round_one_attempt_and_does_not_stop_the_others(self):
        """A persistent refusal is one window attempt per round per series, not a spinning round.

        Both series are refused here, because the platform is down for everyone; what is being pinned
        is the shape of the failure — one POST attempted for each, nothing advanced, the owed bytes
        kept — and that the next healthy round delivers what both of them owe.
        """
        stuck, other = (self.resolved(entry) for entry in
                        (series_entry(id='stuck'), series_entry(id='other')))
        config = self.configuration(stuck, other)
        summary, intake, reader = self.run_round(config, WALK, refuse=('/v1/evidence',))
        self.assertEqual({row['series']: row['result'] for row in summary['series']},
                         {'stuck': 'refused', 'other': 'refused'})
        self.assertEqual(summary['windows'], 2)
        self.assertEqual(summary['posts'], 2, 'one refused POST each: the round did not spin on the failure')
        self.assertEqual((intake.events, intake.samples), ([], []))
        self.assertEqual(self.store.records('events'), [])
        for series_id in ('stuck', 'other'):
            entry = self.cursor_document()['series'][series_id]
            self.assertIsNotNone(entry['pending'])
            self.assertEqual(entry['refusals'], 1)
            self.assertIsNone(entry['last_acked_end'])
        again, second, _reader = self.restart(config, WALK)
        self.assertEqual(again['delivered'], 2)
        self.assertEqual(again['refusals'], 0)
        self.assertEqual([event['window']['end'] for event in second.events],
                         [self.window()['end'], self.window()['end']],
                         'both owed windows were replayed, in configuration order, and accepted')
        for series_id in ('stuck', 'other'):
            self.assertIsNone(self.held_batch(series_id=series_id))

    def test_the_turn_is_the_cursor_s_and_an_older_debt_does_not_outrank_it(self):
        """Fairness across *different* owed windows, which is where counting ties cannot help.

        `lagging` owes four windows, `leading` owes one, and the round budget fits exactly one series.
        Ordering by owed window puts `lagging` at the front of every round forever — the same
        starvation as a permanent refusal, only quieter, because here the series being skipped is one
        that could have advanced; and two series owing *different* windows never tie, so no amount of
        count-sorting at equal times reaches this case. The durable ``last_served`` marker does: the
        head of the configuration takes the first round, the other takes the next, and each of these
        four rounds is a fresh process with nothing but the file behind it. What the rotation may not
        do is reorder a series' own windows: each read is at that series' next window, ascending, and
        never at the clock's.
        """
        leading, lagging = (self.resolved(entry) for entry in
                            (series_entry(id='leading'), series_entry(id='lagging')))
        config = self.configuration(leading, lagging)
        self.seed(leading, lagging, behind={'leading': 1, 'lagging': 4})
        turns: list = []
        for _process in range(4):
            summary, _intake, reader = self.restart(
                config, history(), budget=anomaly.RoundBudget(windows=1, queries=1, posts=2))
            self.assertEqual(summary['windows'], 1, 'one window per round, whatever the backlog says')
            served = [(row['series'], row['result']) for row in summary['series']
                      if row['result'] not in ('deferred', 'caught_up')]
            self.assertEqual(len(served), 1, 'and the round spent it on exactly one series')
            turns.append((served[0][0], reader.bounds['end_s']))
        self.assertEqual([series_id for series_id, _end in turns][:2], ['leading', 'lagging'],
                         'the shallower debt was read first: owed time ranks nothing across series')
        newest = int(END.timestamp())
        self.assertEqual([end for _series_id, end in turns],
                         [newest, newest - 3 * 3600, newest - 2 * 3600, newest - 3600],
                         'each series was read at its own next window, ascending, never at the clock')
        self.assertEqual(self.cursor_entry('leading')['last_acked_end'], utc_text(
            dt.datetime.fromtimestamp(newest, dt.timezone.utc)))
        self.assertEqual(self.owed(*[leading, lagging])[lagging['id']], 1,
                         'the backlog drained one window per turn instead of owning the round')

    def test_a_series_added_while_another_is_refused_is_still_served_round_by_round(self):
        """The reviewer's fifth probe, as a collected test: unequal owed windows, budget of one.

        One series has been refused on its window since an hour ago and is refused on every attempt;
        a second joins the configuration an hour later, and the clock moves an hour per round. Six
        rounds, six processes, one window each: the older series always owes the older window, so a
        queue ordered by time serves the same refusal six times and the new series is never read. The
        claim being pinned is the one the reviewer asked for — every eligible series gets a turn — and a
        turn is **an evaluation**, not only a failed POST: the newcomer's own window can hold a current
        point and come back idle, which is a series that was judged, not one that was starved.
        """
        first, later = (self.resolved(entry) for entry in
                        (series_entry(id='first'), series_entry(id='later')))
        rows = history() + latest(30.0)
        turns: list = []
        for offset in range(6):
            configured = [first] if offset == 0 else [first, later]
            summary, _intake, reader = self.restart(
                self.configuration(*configured), rows,
                now=NOW + dt.timedelta(hours=offset), refuse=('/v1/evidence', '/v1/events'),
                budget=anomaly.RoundBudget(windows=1, queries=1, posts=2))
            self.assertEqual(summary['windows'], 1)
            turns += [row['series'] for row in summary['series'] if row['result'] != 'deferred']
            self.assertLessEqual(reader.calls, 1, 'a refused round read at most one window')
        self.assertEqual(set(turns), {'first', 'later'},
                         'different owed windows must not defeat durable fairness')
        self.assertEqual(turns[0], 'first', 'the series that was already refused kept the turn it had')
        self.assertIn('later', turns[:3], 'the newcomer was reached within two rounds of joining')
        self.assertGreaterEqual(turns.count('later'), 2,
                                'a turn is a rotation, not a one-off concession')
        self.assertEqual(self.cursor_entry('first')['refusals'], turns.count('first'),
                         'one attempt per turn for the series the platform will not take')
        self.assertIsNotNone(self.held_batch(series_id='first'),
                             'and it still owes what the platform would not take')
        self.assertEqual(self.cursor_entry('later')['no_verdict'], turns.count('later'),
                         'the newcomer was judged, on its own window, every time it was reached')
        self.assertEqual(self.cursor_document()['last_served'], turns[-1],
                         'the position the next process reads, written before this one posted anything')

    def test_a_new_series_anchors_at_its_own_newest_completed_window(self):
        """The durable anomaly cursor's first-start rule, kept away from a sibling's history (reviewer probe, ported).

        A series added to a cursor that already holds an older sibling owes what the clock says at its
        own first turn, and nothing deeper: there is no shared-horizon, backfill or join-depth policy
        here, because a producer configured to watch from now is not configured to replay the week its
        neighbour has been walking, and the durable anomaly cursor refuses the unbounded version of that too.
        """
        first, later = (self.resolved(entry) for entry in
                        (series_entry(id='first'), series_entry(id='later')))
        self.restart(self.configuration(first), history() + latest(30.0))
        later_now = NOW + dt.timedelta(hours=2)
        summary, _intake, reader = self.restart(self.configuration(first, later),
                                                history() + latest(30.0), now=later_now,
                                                budget=anomaly.RoundBudget(windows=1, queries=1,
                                                                           posts=2))
        served = [row['series'] for row in summary['series']
                  if row['result'] not in ('deferred', 'caught_up')]
        self.assertEqual(served, ['later'], 'the turn was the newcomer\'s, and it took it')
        self.assertEqual(reader.bounds['end_s'], anomaly_cursor.align_end(
            now_s=later_now.timestamp(), evaluation=3600),
            'its own newest completed window, not the window a sibling stands in')
        self.assertEqual(self.cursor_entry('later')['last_acked_end'],
                         anomaly_cursor.window_text(
                             anomaly_cursor.align_end(now_s=later_now.timestamp(), evaluation=3600),
                             3600)['end'])
        self.assertEqual(self.owed(*[first, later], now=later_now)[first['id']], 2,
                         'and the sibling still owes its own older windows, drained one per turn')

    def test_unequal_evaluation_intervals_take_turns_too(self):
        """Three series, three evaluation intervals, one window a round: nobody is left unjudged.

        A backlog measured in *windows* is not comparable across series that evaluate hourly, every six
        hours and daily, which is the other way a time-ordered queue can put the same series at the
        front forever. The marker rotates over the configured list whatever each series owes.
        """
        entries = [series_entry(id='hourly', evaluation_seconds=3600),
                   series_entry(id='six-hourly', evaluation_seconds=21_600),
                   series_entry(id='daily', evaluation_seconds=86_400)]
        config = self.configuration(*(self.resolved(entry) for entry in entries))
        for _round in range(3):
            summary, _intake, _reader = self.restart(
                config, history(), budget=anomaly.RoundBudget(windows=1, queries=1, posts=2))
            self.assertEqual(summary['windows'], 1)
        for series_id in ('hourly', 'six-hourly', 'daily'):
            self.assertIsNotNone(self.cursor_entry(series_id)['last_acked_end'],
                                 f'{series_id} was never given a turn')

    def test_saturated_counters_neither_stop_the_cursor_nor_the_rotation(self):
        """A lifetime count that reaches its ceiling must not become a stopped producer.

        The ceiling is also what `load` refuses past, so a counter that walked past it would make every
        later save fail — a cursor that cannot record its own refusals while still holding undelivered
        batches. Clamping is what keeps that unreachable, and because no scheduling decision reads a
        count, a saturated series still takes its turn.
        """
        first, later = (self.resolved(entry) for entry in
                        (series_entry(id='first'), series_entry(id='later')))
        config = self.configuration(first, later)
        self.seed(first, later, behind={'first': 0, 'later': 0})
        document = self.cursor_document()
        for state in document['series'].values():
            for field in ('delivered', 'no_verdict', 'refusals'):
                state[field] = anomaly_cursor.MAX_COUNT
        anomaly_cursor.save(self.cursor, document)
        for _round in range(2):
            summary, _intake, _reader = self.restart(config, history())
            self.assertEqual(summary['refusals'], 0)
        for series_id in ('first', 'later'):
            entry = self.cursor_entry(series_id)
            self.assertEqual(entry['refusals'], anomaly_cursor.MAX_COUNT,
                             'the count stays at its ceiling instead of making the file unreadable')
            self.assertIsNotNone(entry['last_acked_end'], 'and the series was served')

    def test_a_cursor_that_cannot_be_written_posts_nothing_and_owes_the_same_window(self):
        """The fail-closed rule is about ordering, not about files: no write, no request.

        Neither half of ``save``'s failure semantics can promise that the *old* bytes survived — see
        its docstring — so the producer does not reason from them. It simply never POSTs on the
        strength of a write that did not succeed, which leaves the window owed and the next round able
        to deliver it once the write works again.
        """
        series = self.resolved()
        config = self.configuration(series)
        rows = history() + latest(30.0)
        with mock.patch('os.replace', side_effect=OSError('disk says no')):
            summary, intake, reader = self.run_round(config, rows)
        self.assertEqual(summary['result'], 'refused')
        self.assertEqual(intake.calls, [], 'nothing left the process on the strength of a failed write')
        self.assertEqual(reader.calls, 0, 'nor did it even ask the store, once the turn write failed')
        self.assertEqual(self.store.records('events'), [])
        self.assertFalse(self.cursor.exists(), 'a failed first write creates nothing')
        summary, intake, _reader = self.restart(config, rows)
        self.assertEqual(summary['delivered'], 1, 'the next round that can write, writes and delivers')
        self.assertEqual([item['window']['end'] for item in intake.events], [self.window()['end']])

    def test_a_round_with_no_budget_left_is_deferred_and_never_reported_as_caught_up(self):
        """A legal budget of zero over a standing backlog is *behind*, not *current*.

        `RoundBudget(0, 0, 0)` is the tightest round there is — no window, no read, no POST — and
        reporting it as `caught_up` inverts the one claim the round line exists to make: the number the
        operator watches (`lag_windows`) is positive and the word has to agree with it. Nothing is
        acked and nothing is delivered, and because no attempt was made the file is not even touched.
        """
        series = self.resolved()
        config = self.configuration(series)
        self.seed(series, behind={'demo-load': 3})
        before = self.cursor.read_bytes()
        empty = anomaly.RoundBudget(windows=0, queries=0, posts=0)
        summary, intake, reader = self.restart(config, history(), budget=empty)
        self.assertEqual((summary['windows'], summary['queries'], summary['posts']), (0, 0, 0))
        self.assertEqual(summary['result'], 'deferred')
        self.assertEqual([row['result'] for row in summary['series']], ['deferred'])
        self.assertEqual(summary['lag_windows'], 3)
        self.assertEqual((reader.calls, intake.calls), (0, []))
        self.assertEqual(self.store.records('events'), [])
        self.assertEqual(self.cursor.read_bytes(), before,
                         'a round that attempted nothing wrote nothing, not even a turn marker')

    def test_a_budget_that_cannot_afford_a_batch_reads_nothing_and_creates_no_cursor(self):
        """Two posts are one batch: a round that cannot pay for both does not open the window.

        Taking the window and then finding the event unaffordable is the half-delivery the reservation
        exists to prevent, so the attempt declines before it spends a read or a byte — and on a first
        start that means no file at all, which is the proof that nothing was attempted rather than the
        assertion that nothing was acked.
        """
        series = self.resolved()
        summary, intake, reader = self.restart(
            self.configuration(series), history() + latest(30.0),
            budget=anomaly.RoundBudget(windows=1, queries=1, posts=0))
        self.assertEqual(summary['result'], 'deferred')
        self.assertEqual([row['result'] for row in summary['series']], ['deferred'])
        self.assertEqual(summary['lag_windows'], 1)
        self.assertEqual((reader.calls, intake.calls, summary['windows']), (0, [], 0))
        self.assertFalse(self.cursor.exists(), 'no attempt, so no cursor to show for it')

    def test_silent_progress_keeps_the_word_idle_beside_its_remaining_lag(self):
        """Work done outranks work deferred, and the leftover backlog rides beside the word.

        A round that advanced one silent window and then ran out of budget is not a round that did
        nothing: calling it `deferred` would hide a window the cursor really acknowledged. What it did
        not reach stays where it always was — in `lag_windows`, next to the word, not instead of it.
        """
        series = self.resolved()
        config = self.configuration(series)
        self.seed(series, behind={'demo-load': 6})
        summary, _intake, reader = self.run_round(config, history(),
                                                  budget=anomaly.RoundBudget(windows=1, queries=1,
                                                                            posts=2))
        self.assertEqual(summary['no_verdict'], 1, 'one window really was judged this round')
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual([row['result'] for row in summary['series']], ['idle'])
        self.assertEqual((summary['lag_windows'], reader.calls), (5, 1))
        self.assertEqual(self.cursor_entry()['last_acked_end'],
                         utc_text(dt.datetime.fromtimestamp(int(END.timestamp()) - 5 * 3600,
                                                            dt.timezone.utc)))

    def test_a_series_with_nothing_left_to_owe_says_caught_up_in_its_own_row(self):
        """The other half of the same defect: an up-to-date series must not default to `deferred`.

        Both halves of the report have to say it — the round's summary word *and* that series' row.
        A row left sitting on `deferred` beside a `lag_windows` of zero reads as "the round never got
        to it", which is the opposite story from the one the cursor tells.
        """
        series = self.resolved()
        config = self.configuration(series)
        self.restart(config, WALK)
        with self.assertLogs('local_observe.platform.anomaly', 'INFO') as captured:
            summary, intake, reader = self.restart(config, WALK)
        self.assertEqual(summary['result'], 'caught_up')
        self.assertEqual([row['result'] for row in summary['series']], ['caught_up'])
        self.assertEqual((summary['windows'], summary['lag_windows']), (0, 0))
        self.assertEqual((summary['delivered'], summary['no_verdict'], summary['refusals']), (0, 0, 0))
        self.assertEqual((reader.calls, intake.calls), (0, []))
        self.assertEqual(self.line(captured, 'Anomaly window finished').result, 'caught_up')

    def test_a_caught_up_series_keeps_its_word_when_the_round_defers_its_neighbour(self):
        """The two words in one round, and the summary is the one that is behind.

        `current` has nothing left to owe and `behind` has two windows left; the budget fits neither.
        The summary describes the round (`deferred`) while each row describes its own series, which is
        the division the round line is written for — a single word for the whole round cannot say both.
        """
        current, behind = (self.resolved(entry) for entry in
                           (series_entry(id='current'), series_entry(id='behind')))
        config = self.configuration(current, behind)
        # `current` ends up acked at the newest completed window and `behind` two windows back: the
        # seed walks each series up to its own gap, so neither word here is set up by hand.
        self.seed(current, behind, behind={'current': 0, 'behind': 2})
        empty = anomaly.RoundBudget(windows=0, queries=0, posts=0)
        summary, _intake, reader = self.restart(config, history(), budget=empty)
        self.assertEqual(summary['result'], 'deferred')
        self.assertEqual({row['series']: row['result'] for row in summary['series']},
                         {'current': 'caught_up', 'behind': 'deferred'})
        self.assertEqual({row['series']: row['lag_windows'] for row in summary['series']},
                         {'current': 0, 'behind': 2})
        self.assertEqual(reader.calls, 0)


class CursorRefusalTests(DurabilityFixture):
    """What a round does when the cursor is the thing that is wrong: refuse, and change nothing."""

    def series(self) -> dict:
        return self.resolved()

    def acked_cursor(self, name: str = 'positions.json', *, rows: list | None = None,
                     config: dict | None = None) -> Path:
        """Return a cursor one clean round wrote (newest completed window acked, nothing owed).

        Written through the producer itself rather than assembled, so the file is exactly what this
        writer emits and every position in it is one the configuration produced. That is what makes
        the rewrites below about the **one** field they move.
        """
        path = self.cursor_directory / name
        self.run_round(config or self.configuration(self.series()),
                       [] if rows is None else rows, cursor=path)
        return path

    def rewritten(self, path: Path, **positions: str) -> bytes:
        """Rewrite *positions* on one loaded entry, write the file back, and return its new bytes.

        Re-canonicalised through the loaded document, so the result is a file `load` accepts: the text
        is the form this writer emits and the ordering inside the entry still runs forwards. Only the
        resolved configuration can say the position is one this producer could never have reached —
        which is the difference these tests are about, and the reason each case asserts the load first.
        """
        document = json.loads(canonical(anomaly_cursor.load(path, source=PRODUCER.identity)))
        document['series']['demo-load'].update(positions)
        path.write_text(canonical(document), encoding='utf-8')
        return path.read_bytes()

    def test_a_cursor_that_does_not_parse_refuses_the_round_and_keeps_its_bytes(self):
        series = self.series()
        self.seed(series, behind={'demo-load': 2})
        before = self.cursor.read_bytes()
        self.cursor.write_text('{"schema_version": 1, "source": "anomaly-test"', encoding='utf-8')
        torn = self.cursor.read_bytes()
        with self.assertRaises(anomaly_cursor.CursorRefusal):
            self.run_round(self.configuration(series), WALK)
        self.assertEqual(self.cursor.read_bytes(), torn)
        self.assertNotEqual(self.cursor.read_bytes(), before)
        self.assertEqual(self.store.records('events'), [])

    def test_a_cursor_written_by_another_producer_identity_is_not_this_one_to_read(self):
        """Restoring the wrong file is a refusal, not a re-baseline: the events would be lies."""
        series = self.series()
        self.seed(series, behind={'demo-load': 2})
        foreign = json.loads(canonical(self.cursor_document()))
        foreign['source'] = 'the-other-producer'
        self.cursor.write_text(canonical(foreign), encoding='utf-8')
        with self.assertRaises(anomaly_cursor.CursorRefusal) as refused:
            anomaly.tick(self.index, self.configuration(series), Query(WALK), Intake(self.store),
                         self.cursor, now=NOW, source=PRODUCER.identity)
        self.assertIn('producer identity', str(refused.exception))
        self.assertEqual(self.cursor.read_bytes(), canonical(foreign).encode())

    def test_a_symlinked_cursor_refuses_before_anything_is_read_or_written(self):
        series = self.series()
        real = self.cursor_directory / 'somewhere-else.json'
        real.write_text(canonical(anomaly_cursor.empty_document(PRODUCER.identity)), encoding='utf-8')
        try:
            self.cursor.symlink_to(real)
        except OSError as exc:
            if not (os.name == 'nt' and getattr(exc, 'winerror', None) == 1314):
                raise
            self.skipTest('Windows withholds SeCreateSymbolicLinkPrivilege from this test run')
        except NotImplementedError:
            raise
        with self.assertRaises(anomaly_cursor.CursorRefusal):
            self.run_round(self.configuration(series), WALK)
        self.assertEqual(real.read_bytes(),
                         canonical(anomaly_cursor.empty_document(PRODUCER.identity)).encode())

    def test_a_symlinked_ancestor_refuses_the_round_before_the_file_is_opened(self):
        """The predicate, not the platform: a link anywhere above the cursor is the same traversal.

        This runs on every OS because the check is driven by a deterministic stand-in for "is this
        directory a link" — the real-link cases stay integration tests (``make_link`` in
        ``tests/test_anomaly_cursor.py`` skips only where Windows withholds the privilege). What is
        pinned is that the refusal happens before the cursor is opened, so a link planted between two
        rounds cannot make the producer read (or write) somebody else's file.
        """
        series = self.series()
        config = self.configuration(series)
        self.run_round(config, history() + latest(30.0))
        before = self.cursor.read_bytes()
        reached = self.cursor.parent

        def pretend_linked(candidate):
            return candidate == reached

        query, intake = NeverReads([]), Intake(self.store)
        with mock.patch.object(anomaly_cursor, 'symlink_present', pretend_linked):
            with self.assertRaises(anomaly_cursor.CursorRefusal) as refused:
                anomaly.tick(self.index, config, query, intake, self.cursor, now=NOW,
                             source=PRODUCER.identity)
        self.assertIn('symlink', str(refused.exception))
        self.assertEqual(self.cursor.read_bytes(), before)
        self.assertEqual(intake.calls, [])

    def test_a_stored_batch_that_the_configuration_no_longer_authorises_refuses_the_round(self):
        """Replay is only safe while the stored verdict is still *this* series' verdict.

        Each case below re-tallies the digests after mutating the payload, so the refusal cannot be
        the checksum guard firing by accident: the batch is internally consistent, self-verifying and
        still belongs to a configuration that no longer exists. Every one of them is refused before the
        round's first query, first POST and first byte — the alternative is a producer that POSTs an
        old opinion under an id the new configuration owns, which is exactly the failure the platform
        cannot undo.
        """
        series = self.series()
        config = self.configuration(series)
        window = self.window()
        moved_k = self.resolved(series_entry(k=9.0))
        mutations = [
            ('an event for a resource the configuration does not name',
             lambda pending, document: pending['event'].__setitem__(
                 'resource_id', '00000000-0000-4000-8000-000000000000')),
            ('an event with no resource at all',
             lambda pending, document: pending['event'].__setitem__('resource_id', None)),
            ('an event whose rule belongs to another series',
             lambda pending, document: pending['event'].update(
                 {'rule_id': 'anomaly.somebody-else', 'condition': 'anomaly.somebody-else'})),
            ('an event whose rule_version is not what the current knobs produce',
             lambda pending, document: pending['event'].__setitem__(
                 'rule_version', anomaly._rule_version(moved_k))),
            ('an event quoted against a different kind of evidence query',
             lambda pending, document: pending['event']['evidence'][0].__setitem__(
                 'query_type', 'observed-snapshot')),
            ('an event whose evidence parameters name another rule',
             lambda pending, document: pending['event']['evidence'][0]['parameters'].__setitem__(
                 'rule_id', 'anomaly.somebody-else')),
            ('an event paired with a sample the batch does not hold',
             lambda pending, document: pending['event']['evidence'][0]['parameters'].__setitem__(
                 'sample_id', 'not-the-stored-sample')),
            ('an event with no evidence sample stored beside it',
             lambda pending, document: (pending.__setitem__('sample', None),
                                        pending.__setitem__('evidence_sha256', digest(None)))),
            ('a batch whose window is not aligned to the configured evaluation',
             lambda pending, document: (shift_window(pending, 60), document['series']['demo-load']
                                        .__setitem__('owed_end', pending['window']['end']))),
            ('a batch that is two evaluations past the last acknowledged window',
             lambda pending, document: document['series']['demo-load'].__setitem__(
                 'last_acked_end',
                 utc_text(timestamp(window['start']) - dt.timedelta(seconds=3600)))),
        ]
        for position, (reason, mutate) in enumerate(mutations):
            with self.subTest(refusal=reason):
                cursor = self.cursor_directory / f'tampered-{position}.json'
                self.run_round(config, history() + latest(30.0), cursor=cursor,
                               refuse=('/v1/events',))
                document = json.loads(canonical(anomaly_cursor.load(cursor, source=PRODUCER.identity)))
                mutate(document['series']['demo-load']['pending'], document)
                pending = document['series']['demo-load']['pending']
                pending['event_sha256'] = digest(pending['event'])
                if pending['sample'] is not None:
                    pending['evidence_sha256'] = digest(pending['sample'])
                torn = canonical(document)
                cursor.write_text(torn, encoding='utf-8')
                query, intake = NeverReads([]), Intake(self.store)
                with self.assertRaises(anomaly_cursor.CursorRefusal):
                    anomaly.tick(self.index, config, query, intake, cursor, now=NOW,
                                 source=PRODUCER.identity)
                self.assertEqual(cursor.read_bytes(), torn.encode(),
                                 'the refused batch keeps its exact bytes for the operator to read')
                self.assertEqual(intake.calls, [], 'the refusal did not reach the platform')
                self.assertEqual(self.store.records('events'), [])

    def test_a_saved_owed_attempt_cannot_skip_a_window_after_the_last_ack(self):
        """An owed *attempt* is preflighted with no payload in the file to replay (reviewer probe).

        Nothing here is damage ``load`` can see: the text is the form this writer emits and the owed
        window is strictly ahead of the ack, so the entry agrees with itself. What it disagrees with is
        the configured evaluation interval — an ack at midnight and an attempt at two in the morning
        are **two** windows apart — and the round that answered that attempt would acknowledge 02:00,
        clear the debt, and never mention the hour in between. It is the silent skip this card exists
        to close, arriving from the other side: the owed marker itself, moved.
        """
        path = self.acked_cursor()
        later = END + dt.timedelta(hours=2)
        before = self.rewritten(path, owed_end=utc_text(later))
        query, intake = Query([]), Intake(self.store)
        with self.assertRaises(anomaly_cursor.CursorRefusal) as refused:
            anomaly.tick(self.index, self.configuration(self.series()), query, intake, path,
                         now=later, source=PRODUCER.identity)
        self.assertIn('not one configured evaluation', str(refused.exception))
        self.assertEqual(query.calls, 0, 'the refusal spent no read on the later window')
        self.assertEqual(intake.calls, [], 'and reached no endpoint')
        self.assertEqual(path.read_bytes(), before, 'the damaged position stays for the operator')
        self.assertEqual(self.store.records('events'), [])

    def test_a_window_position_that_is_not_a_window_boundary_refuses_the_round(self):
        """Fractional and off-grid positions are refused, and never read down until they look aligned.

        Each case below is a file ``load`` accepts — the load call is asserted, not assumed, because
        the structural pass is the point: only the resolved configuration can refuse these, which is
        why the check is a preflight and not a loader rule. The half-second case is the one that must
        not be run through ``int()``: truncating it lands exactly on the next legal window end, so a
        reader that rounded would call the damaged position contiguous and the refusal would never
        happen while the skipped hour quietly was.
        """
        cases = [
            ('an owed attempt half a second off any window edge', 'owed_end',
             utc_text(END + dt.timedelta(seconds=3600.5)), 'fraction of a second'),
            ('an owed attempt begun mid-hour on an hourly series', 'owed_end',
             utc_text(END + dt.timedelta(minutes=30)), 'whole number of configured'),
            ('an acknowledged window off the evaluation grid', 'last_acked_end',
             utc_text(END + dt.timedelta(minutes=30)), 'whole number of configured'),
            ('an anchor off the grid, behind a sound acknowledgement', 'anchored_at',
             utc_text(END - dt.timedelta(minutes=30)), 'whole number of configured'),
        ]
        for position, (reason, field, value, refusal) in enumerate(cases):
            with self.subTest(position=reason):
                path = self.acked_cursor(name=f'grid-{position}.json')
                before = self.rewritten(path, **{field: value})
                self.assertEqual(anomaly_cursor.load(path, source=PRODUCER.identity)
                                 ['series']['demo-load'][field], value,
                                 'the file itself is structurally sound: this is a config refusal')
                query, intake = Query([]), Intake(self.store)
                with self.assertRaises(anomaly_cursor.CursorRefusal) as refused:
                    anomaly.tick(self.index, self.configuration(self.series()), query, intake, path,
                                 now=END + dt.timedelta(hours=1), source=PRODUCER.identity)
                self.assertIn(refusal, str(refused.exception))
                self.assertEqual(query.calls, 0)
                self.assertEqual(intake.calls, [])
                self.assertEqual(path.read_bytes(), before)

    def test_an_owed_attempt_on_the_next_window_is_retried_however_far_the_clock_moved(self):
        """The positive control for both refusals above: a contiguous owed hour is work, not damage.

        The same shape as the skipped-window cursor — an owed position and no payload — differing only
        in the one thing the check is about: the owed window is exactly the next one after the ack.
        Three hours may close on the clock, and the round still reads the hour the file names,
        delivers it, and reports the hours behind it as lag rather than jumping to the newest one.
        """
        path = self.acked_cursor(name='contiguous.json')
        owed = END + dt.timedelta(hours=1)
        self.rewritten(path, owed_end=utc_text(owed))
        rows = history() + [(owed.timestamp() - 1800, 30.0)]
        summary, intake, reader = self.run_round(self.configuration(self.series()), rows,
                                                 now=END + dt.timedelta(hours=3), cursor=path,
                                                 budget=anomaly.RoundBudget(windows=1, queries=1,
                                                                            posts=2))
        self.assertEqual(summary['series'][0]['result'], 'delivered')
        self.assertEqual(reader.bounds['end_s'], int(owed.timestamp()),
                         'the window the cursor named, not the one the clock is standing in')
        self.assertEqual([item['window']['end'] for item in intake.events], [utc_text(owed)])
        entry = self.cursor_document(path)['series']['demo-load']
        self.assertEqual(entry['last_acked_end'], utc_text(owed))
        self.assertIsNone(entry['owed_end'], 'the attempt was answered, not skipped')
        self.assertEqual(summary['lag_windows'], 2,
                         'the two hours that closed behind it are owed, and named')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_an_impossible_position_on_a_later_series_refuses_before_the_earlier_one_is_read(self):
        """Configuration order is no defence, and a refusal never partly runs.

        `first` is sound and owes real work; `later`, configured second, holds an owed attempt two
        evaluations past its ack. The preflight walks **every** configured entry before the round
        starts, so `first` is not judged either: the round that cannot trust the file does no work, the
        message names `later`, and neither entry moved. Same shape as the binding and
        undeclared-resource refusals, and the same reason — an operator can fix it and rerun without
        wondering what the rejected round already told the platform.
        """
        first, later = (self.resolved(entry) for entry in
                        (series_entry(id='first'), series_entry(id='later')))
        config = self.configuration(first, later)
        self.run_round(config, [])
        held = {series_id: self.cursor_entry(series_id)['last_acked_end']
                for series_id in ('first', 'later')}
        document = json.loads(canonical(self.cursor_document()))
        document['series']['later']['owed_end'] = utc_text(END + dt.timedelta(hours=2))
        torn = canonical(document)
        self.cursor.write_text(torn, encoding='utf-8')
        query, intake = Query([]), Intake(self.store)
        with self.assertRaises(anomaly_cursor.CursorRefusal) as refused:
            anomaly.tick(self.index, config, query, intake, self.cursor,
                         now=END + dt.timedelta(hours=2), source=PRODUCER.identity)
        self.assertIn('later', str(refused.exception), 'the refusal names the series it is about')
        self.assertEqual(query.calls, 0, 'the sound series was not judged either')
        self.assertEqual(intake.calls, [])
        self.assertEqual(self.cursor.read_bytes(), torn.encode())
        for series_id in ('first', 'later'):
            self.assertEqual(self.cursor_entry(series_id)['last_acked_end'], held[series_id],
                             f'{series_id} is exactly where it was')
            self.assertEqual(self.cursor_entry(series_id)['refusals'], 0,
                             'a round that never started keeps no score')

    def test_a_series_whose_knobs_moved_refuses_the_whole_round_and_touches_nothing(self):
        """A binding mismatch is refused before the round can do anything it would have to undo.

        One series' knob moved, so every stored verdict in the file belongs to a configuration that no
        longer exists. The round does not judge the other series anyway: the refusal is a statement
        about what the *file* is, and a round that partly ran would leave an operator fixing a
        configuration while wondering what the rejected round already told the platform. This is the
        same shape as the undeclared-resource refusal, and it is what makes "fix it and rerun" safe:
        the rejected round performed no read, no POST and no byte of cursor. Deleting or rewriting the
        mismatching entry stays an operator decision (`docs/units/anomaly-cursor.md`).
        """
        moved, steady = (self.resolved(entry) for entry in
                         (series_entry(id='moved'), series_entry(id='steady')))
        config = self.configuration(moved, steady)
        self.seed(moved, steady, behind={'moved': 1, 'steady': 1})
        held = {series_id: self.cursor_entry(series_id) for series_id in ('moved', 'steady')}
        before = self.cursor.read_bytes()
        moved_again = self.resolved(series_entry(id='moved', k=9.0))
        with self.assertRaises(anomaly_cursor.CursorRefusal) as refused:
            self.run_round({'series': [moved_again, config['series'][1]]}, WALK,
                           query=NeverReads([]))
        self.assertIn('moved', str(refused.exception), 'the refusal names the series it is about')
        self.assertEqual(self.cursor.read_bytes(), before, 'the rejected round wrote nothing')
        for series_id in ('moved', 'steady'):
            entry = self.cursor_entry(series_id)
            self.assertEqual(entry['last_acked_end'], held[series_id]['last_acked_end'],
                             f'{series_id} is exactly where it was')
            self.assertEqual(entry['refusals'], held[series_id]['refusals'],
                             'not even a counter moves: a round that never started keeps no score')
        self.assertEqual(self.cursor_entry('moved')['binding'], held['moved']['binding'],
                         'the cursor keeps the binding it was written with, not the new one')
        self.assertEqual(self.store.records('events'), [], 'and nothing reached the platform')

    def test_a_series_that_left_the_configuration_keeps_its_owed_batch_and_is_named(self):
        """A pending batch is never silently acked or deleted because its series stopped being named."""
        left = self.resolved(series_entry(id='left-behind'))
        kept = self.resolved(series_entry(id='kept'))
        _summary, _intake, _reader = self.run_round(self.configuration(left, kept), WALK,
                                                   refuse=('/v1/events',))
        owed = self.held_batch(series_id='left-behind')
        self.assertIsNotNone(owed)
        held = self.cursor_entry('left-behind')
        summary, _intake, _reader = self.restart(self.configuration(kept), WALK)
        self.assertEqual(summary['stale_entries'], ['left-behind'])
        self.assertEqual(summary['unresolved_pending'], ['left-behind'])
        self.assertEqual(self.held_batch(series_id='left-behind'), owed,
                         'the stranded batch is byte-for-byte the one it was left holding')
        self.assertEqual(self.cursor_entry('left-behind'), held,
                         'a retained entry is not rewritten, not counted and not deleted')
        self.assertEqual(summary['series'], [{'series': 'kept', 'result': 'delivered',
                                             'delivered': 1, 'no_verdict': 0, 'refusals': 1,
                                             'lag_windows': 0, 'pending': False}],
                         'only the series still named is reported — and its refusals counter carries '
                         'the refusal it earned before the other one was removed')


if __name__ == '__main__':
    unittest.main()

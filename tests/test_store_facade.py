"""store facade: the store facade's bounded reads, its evidence seam, and the ClickHouse client behind it.

The rules under test decide whether an incident can still be proved next week: a read answers with a
reference intake accepts, an absent series says so out loud, a window whose evidence would already be
expired is refused before it can become a dead link, and the only SQL the platform can run is the
table this repository reviewed. Half of these tests replace the transport, never the rules — the fake
client below records the bounds it was asked to honour instead of skipping them.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse
import urllib.request

from local_observe.http import ResultTooLarge, TransportError
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, Store, StateError
from local_observe.platform.sigma_runner import ClickHouse, SERIES_MAX_POINTS
from local_observe.store import client as facade
from local_observe.store import retention
from local_observe.store.backends import clickhouse as ch
from local_observe.store.backends import memory as memory_backend

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
OTHER = '9f1b2c3a-0d4e-4f5a-8b6c-7d8e9f0a1b2c'
NOW = dt.datetime(2026, 9, 8, 10, 5, tzinfo=dt.timezone.utc)
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
WINDOW = facade.Window(start='2026-09-08T10:00:00Z', end='2026-09-08T10:05:00Z')
FIRST, LAST = '2026-09-08T10:01:00Z', '2026-09-08T10:03:00Z'


def nano(text: str) -> int:
    """Whole-nanosecond epoch reading of an ISO instant, as the log and trace tables stamp a row."""
    return int((facade.parse_ts(text) - EPOCH).total_seconds()) * 1_000_000_000


def millis(text: str) -> int:
    """Whole-millisecond epoch reading of an ISO instant, as the metric tables stamp a row."""
    return int((facade.parse_ts(text) - EPOCH).total_seconds()) * 1_000


MILLIS = millis(FIRST)
METRIC_ROW = {'metric_name': 'lo_process_running', 'unix_milli': str(MILLIS), 'value': '3',
              'labels': json.dumps({'resource_id': RESOURCE, 'host.name': 'host-a'})}
LOG_ROW = {'timestamp_ns': str(nano(FIRST)), 'body': 'process lo-fixture started',
           'severity_text': 'INFO', 'attributes': json.dumps({'event.dataset': 'linux.process'}),
           'resources': json.dumps({'resource_id': RESOURCE})}
SPAN_ROW = {'trace_id': 'a' * 32, 'span_id': 'b' * 16, 'name': 'GET /api', 'service': 'front-door',
            'duration_ns': '15000000', 'ts_ms': str(MILLIS), 'status_code': '200'}


def aggregate(count: int, *, unit: str = 'ns') -> list[dict]:
    """One describe or heartbeat answer, in the shape ``FORMAT JSON`` produces for it.

    Empty bounds come back as JSON ``null`` rather than as a zero, which is what a real aggregate of
    no rows does — a reader that confused the two would report the oldest sample as the epoch.
    """
    stamps = ({'first_ms': str(millis(FIRST)), 'last_ms': str(millis(LAST))} if unit == 'ms'
              else {'first_seen': str(nano(FIRST)), 'last_seen': str(nano(LAST))})
    empty = {key: None for key in stamps}
    return [{'row_count': str(count), **(stamps if count else empty)}]


class Recorder(ch.ClickHouse):
    """The bounded client with its transport replaced: it records what it was asked and answers.

    ``handler`` sees the statement text and the row bound, so a test can assert on the two together —
    they are exactly the things a caller must not be able to choose.
    """

    def __init__(self, handler=None) -> None:
        self.url, self.user, self.password = 'https://clickhouse.invalid:8123', 'lo-query', 'x' * 32
        self.handler = handler or (lambda sql, limit: [])
        self.calls: list[tuple[str, dict, int]] = []

    def _rows(self, sql, parameters, *, max_result_rows, expected_rows=None):
        self.calls.append((sql, dict(parameters), max_result_rows))
        rows = self.handler(sql, max_result_rows)
        if expected_rows is not None and len(rows) != expected_rows:
            raise TransportError('Unexpected aggregate result')
        return rows


def recorded(handler=None) -> ch.ClickHouseStore:
    """One facade over a recorded transport."""
    return ch.ClickHouseStore(Recorder(handler))

class FakeResponse:
    """A ClickHouse HTTP body that honours the read bound the client asks for."""

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


class RecordingOpener:
    """An opener that records its handlers and every request, and answers with one fixed body."""

    def __init__(self, handlers: list, body: bytes) -> None:
        self.handlers, self.body, self.requests = handlers, body, []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        return FakeResponse(self.body)


def padded_body(size: int, *, canary: str = '') -> bytes:
    """One ``FORMAT JSON`` answer padded to exactly *size* bytes, so a bound is tested at cap and cap+1."""
    prefix, suffix = '{"data":[{"note":"', '"}]}'
    filler = max(0, size - len(prefix) - len(suffix) - len(canary))
    body = (prefix + canary + 'p' * filler + suffix).encode()
    if len(body) != size:
        raise AssertionError(f'no {size}-byte answer fits this shape')
    return body


class TimestampContract(unittest.TestCase):
    """``parse_ts``: one string means one instant, whatever the host's zone is."""

    def test_naive_text_is_utc_and_an_offset_is_converted(self):
        expected = dt.datetime(2026, 9, 8, 10, 0, tzinfo=dt.timezone.utc)
        for text in ('2026-09-08T10:00:00', '2026-09-08T10:00:00Z', '2026-09-08T10:00:00+00:00',
                     '2026-09-08T11:00:00+01:00'):
            with self.subTest(text=text):
                parsed = facade.parse_ts(text)
                self.assertEqual(parsed, expected)
                self.assertEqual(parsed.tzinfo, dt.timezone.utc)

    def test_text_that_is_not_a_timestamp_is_refused(self):
        for value in ('', 'yesterday', '1756461660', None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    facade.parse_ts(value)


class WindowRules(unittest.TestCase):
    """The half-open window docs/CONTRACTS.md §2 promises, normalised once at the door."""

    def test_bounds_are_normalised_to_utc_microseconds(self):
        window = facade.Window(start='2026-09-08T11:00:00+01:00', end='2026-09-08T10:05:00')
        self.assertEqual(window.as_dict(), {'start': '2026-09-08T10:00:00.000000+00:00',
                                            'end': '2026-09-08T10:05:00.000000+00:00'})

    def test_an_empty_reversed_or_giant_window_is_refused(self):
        for start, end in (('2026-09-08T10:05:00Z', '2026-09-08T10:05:00Z'),
                           ('2026-09-08T10:05:00Z', '2026-09-08T10:00:00Z'),
                           ('2026-01-01T00:00:00Z', '2026-09-08T10:00:00Z')):
            with self.subTest(start=start, end=end):
                with self.assertRaises(facade.StoreRefused):
                    facade.Window(start=start, end=end)

    def test_a_bound_that_is_not_a_bound_is_refused(self):
        with self.assertRaises(facade.StoreRefused):
            WINDOW.instant('middle')


class QueryTable(unittest.TestCase):
    """The closed table: what may be run, what may be said, and where the SQL lives."""

    def test_every_kind_has_exactly_one_statement(self):
        self.assertEqual(set(ch.QUERY_SQL), set(facade.QUERY_KINDS))
        self.assertEqual(set(ch.TEMPLATES), set(facade.QUERY_KINDS))
        self.assertEqual(set(ch.PROBES), {name for name, kind in facade.QUERY_KINDS.items()
                                          if kind.purpose == 'read' and kind.max_rows > 1})

    def test_every_placeholder_is_bound_from_the_window_or_an_approved_name(self):
        for name, query in ch.TEMPLATES.items():
            with self.subTest(query=name):
                allowed = ch.WINDOW_UNITS | query.kind.parameters | set(query.kind.selectors)
                self.assertTrue(set(query.placeholders()) <= allowed,
                                f'{name} binds a name the facade cannot supply')

    def test_no_statement_carries_a_write_or_a_credential(self):
        for name, sql in ch.QUERY_SQL.items():
            with self.subTest(query=name):
                upper = sql.upper()
                self.assertTrue(upper.startswith('SELECT'), f'{name} is not a SELECT')
                for forbidden in ('INSERT', 'ALTER', 'DROP', 'TRUNCATE', 'OPTIMIZE', 'CREATE',
                                  'PASSWORD', 'KEY'):
                    self.assertNotIn(forbidden, upper)

    def test_the_reads_bind_the_signal_tables_and_no_resource_table(self):
        joined = ' '.join(ch.QUERY_SQL.values())
        for table in (ch.METRICS_SAMPLES, ch.METRICS_SERIES, ch.LOGS, ch.TRACES):
            self.assertIn(table, joined)
        self.assertNotIn('distributed_logs_v2_resource', joined)

    def test_an_unknown_query_kind_is_refused_with_the_list_of_names(self):
        with self.assertRaises(facade.StoreRefused) as caught:
            facade.describe_query('select-everything')
        self.assertIn('metric-threshold', str(caught.exception))

    def test_only_the_two_approved_kinds_may_be_named_as_evidence(self):
        self.assertEqual(facade.ADMISSIBLE_QUERY_TYPES, {'metric-threshold', 'source-heartbeat'})
        self.assertTrue(facade.ADMISSIBLE_QUERY_TYPES <= facade.EVIDENCE_QUERY_TYPES)

    def test_the_runner_still_imports_the_client_it_always_had(self):
        """The class moved out of the runner; its name at the old address did not."""
        self.assertIs(ClickHouse, ch.ClickHouse)
        self.assertEqual(SERIES_MAX_POINTS, 2000)
        self.assertEqual(facade.MAX_ROWS, SERIES_MAX_POINTS)


class ClickHouseReads(unittest.TestCase):
    """The facade over the client: bounds, bindings, rows, and what a verdict may claim."""

    def test_a_metric_read_posts_its_window_as_bounds_and_its_names_as_bindings(self):
        recorder = Recorder(lambda sql, limit: [METRIC_ROW])
        outcome = ch.ClickHouseStore(recorder).read_metrics(
            'metric-threshold', window=WINDOW, parameters={'resource_id': RESOURCE, 'rule_id': 'anomaly.marker'},
            selectors={'metric_name': 'lo_process_running'})
        sql, parameters, limit = recorder.calls[0]
        self.assertEqual(limit, facade.QUERY_KINDS['metric-threshold'].max_rows + 1)
        self.assertIn(ch.METRICS_SAMPLES, sql)
        self.assertIn(ch.METRICS_SERIES, sql)
        self.assertEqual(parameters['resource_id'], RESOURCE)
        self.assertEqual(parameters['metric_name'], 'lo_process_running')
        self.assertEqual(parameters['start_ms'], millis(WINDOW.start))
        self.assertEqual(parameters['end_ms'], millis(WINDOW.end))
        self.assertEqual(outcome.status, 'available')
        sample = outcome.rows()[0]
        self.assertEqual((sample.name, sample.value, sample.resource_id), ('lo_process_running', 3.0, RESOURCE))
        self.assertEqual(sample.labels['host.name'], 'host-a')

    def test_quoted_integers_and_both_map_shapes_are_read_as_the_same_row(self):
        """ClickHouse's JSON format quotes 64-bit integers and renders a Map two ways."""
        variant = dict(METRIC_ROW, labels={'resource_id': RESOURCE, 'host.name': 'host-b'})
        outcome = recorded(lambda sql, limit: [variant]).read_metrics(
            'metric-threshold', window=WINDOW, parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'})
        self.assertEqual(outcome.rows()[0].labels['host.name'], 'host-b')
        self.assertEqual(outcome.rows()[0].value, 3.0)

    def test_log_and_span_rows_map_to_their_record_types(self):
        logs = recorded(lambda sql, limit: [LOG_ROW] if ch.LOGS in sql and 'positionCaseInsensitive' in sql
                        else aggregate(1))
        record = logs.read_logs('log-records', window=WINDOW,
                               parameters={'resource_id': RESOURCE}).rows()[0]
        self.assertEqual((type(record).__name__, record.severity, record.resource_id),
                         ('LogRecord', 'info', RESOURCE))
        span = recorded(lambda sql, limit: [SPAN_ROW]).read_traces(
            'trace-spans', window=WINDOW, parameters={'rule_id': 'rca.1'},
            selectors={'service': 'front-door'}).rows()[0]
        self.assertEqual((span.service, span.duration_ns, span.status), ('front-door', 15_000_000, '200'))

    def test_a_full_page_is_reported_as_truncated(self):
        kind = facade.QUERY_KINDS['log-records']
        rows = [dict(LOG_ROW, body=f'line {index}') for index in range(kind.max_rows + 1)]
        outcome = recorded(lambda sql, limit: rows).read_logs('log-records', window=WINDOW,
                                                             parameters={'resource_id': RESOURCE})
        self.assertEqual(len(outcome.rows()), kind.max_rows)
        self.assertTrue(outcome.receipt.truncated)
        self.assertEqual(outcome.receipt.sample_count, kind.max_rows)

    def test_an_aggregate_is_never_reported_as_a_cut_off_page(self):
        outcome = recorded(lambda sql, limit: aggregate(4)).read_logs(
            'source-heartbeat', window=WINDOW, parameters={'resource_id': RESOURCE})
        self.assertFalse(outcome.receipt.truncated)
        self.assertEqual(outcome.rows()[0].row_count, 4)

    def test_a_silent_resource_is_unavailable_and_never_an_empty_success(self):
        outcome = recorded(lambda sql, limit: aggregate(0)).read_logs(
            'source-heartbeat', window=WINDOW, parameters={'resource_id': RESOURCE})
        self.assertEqual(outcome.status, 'unavailable')
        self.assertEqual(outcome.receipt.sample_count, 0)
        with self.assertRaises(facade.RowsUnavailable):
            outcome.rows()

    def test_an_empty_window_on_a_known_series_is_an_honest_empty_answer(self):
        """The read found nothing because the needle missed; the resource did produce logs."""
        outcome = recorded(lambda sql, limit: [] if 'positionCaseInsensitive' in sql else aggregate(2)) \
            .read_logs('log-records', window=WINDOW, parameters={'resource_id': RESOURCE},
                       selectors={'needle': 'absent'})
        self.assertEqual((outcome.status, outcome.receipt.sample_count), ('available', 0))
        self.assertIn('no rows', outcome.detail)

    def test_a_series_the_store_has_never_seen_is_unavailable(self):
        outcome = recorded(lambda sql, limit: []).read_metrics(
            'metric-threshold', window=WINDOW, parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'},
            selectors={'metric_name': 'lo_process_running'})
        self.assertEqual(outcome.status, 'unavailable')
        self.assertEqual(sorted(outcome.receipt.parameters), ['resource_id', 'rule_id'])

    def test_a_probe_that_cannot_be_read_is_absence_and_not_data(self):
        """The read came back empty and the existence question came back malformed."""
        outcome = recorded(lambda sql, limit: [] if 'positionCaseInsensitive' in sql
                           else [{'unexpected': 'shape'}]).read_logs(
            'log-records', window=WINDOW, parameters={'resource_id': RESOURCE})
        self.assertEqual(outcome.status, 'unavailable')

    def test_describe_answers_in_the_store_shape(self):
        presence = recorded(lambda sql, limit: aggregate(4, unit='ms')).describe(
            'describe-metrics', window=WINDOW, selectors={'metric_name': 'lo_process_running'})
        self.assertEqual((presence.signal, presence.row_count), ('metrics', 4))
        self.assertEqual(presence.first_seen, '2026-09-08T10:01:00.000000+00:00')
        self.assertEqual(presence.as_dict()['last_seen'], '2026-09-08T10:03:00.000000+00:00')

    def test_a_transport_failure_stays_one_error_and_carries_no_secret(self):
        class Failing(Recorder):
            def _rows(self, sql, parameters, *, max_result_rows, expected_rows=None):
                raise TransportError('Bounded ClickHouse query failed')

        with self.assertRaises(TransportError) as caught:
            ch.ClickHouseStore(Failing()).read_logs('log-records', window=WINDOW,
                                                    parameters={'resource_id': RESOURCE})
        self.assertNotIn('x' * 32, str(caught.exception))
        self.assertNotIn(RESOURCE, str(caught.exception))

    def test_a_store_that_answers_in_an_unknown_shape_is_unavailable(self):
        with self.assertRaises(TransportError):
            recorded(lambda sql, limit: [{'unexpected': 'row'}]).read_logs(
                'log-records', window=WINDOW, parameters={'resource_id': RESOURCE})

    def test_the_signal_named_by_the_method_must_match_the_query(self):
        with self.assertRaises(ValueError):
            recorded().read_logs('metric-threshold', window=WINDOW,
                                 parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'})

    def test_describe_and_read_cannot_be_confused(self):
        for call in (lambda s: s.read_logs('describe-logs', window=WINDOW, parameters={'resource_id': RESOURCE}),
                     lambda s: s.describe('log-records', window=WINDOW)):
            with self.assertRaises(facade.StoreRefused):
                call(recorded())


class Transport(unittest.TestCase):
    """The one POST. Nothing the runner depended on moved, and the facade asks for nothing wider."""

    def setUp(self):
        self.original = urllib.request.build_opener

    def patch(self, body: bytes) -> None:
        def build_opener(*handlers):
            opener = RecordingOpener(list(handlers), body)
            Transport.openers.append(opener)
            return opener

        Transport.openers = []
        urllib.request.build_opener = build_opener
        self.addCleanup(setattr, urllib.request, 'build_opener', self.original)

    def client(self) -> ClickHouse:
        return ClickHouse('https://clickhouse.invalid:8123', 'lo-query', 'secret-credential-value')

    def settings(self, index: int = -1) -> dict[str, list[str]]:
        request, _timeout = Transport.openers[0].requests[index]
        return urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)

    def test_every_bound_travels_with_the_query(self):
        self.patch(json.dumps({'data': [{'source_count': 1, 'usable_count': 1, 'match_count': 0}]}).encode())
        row = self.client().query('SELECT 1 FORMAT JSON', {'resource_id': RESOURCE})
        settings = self.settings()
        self.assertEqual(row['match_count'], 0)
        self.assertEqual(settings['readonly'], ['1'])
        self.assertEqual(settings['max_execution_time'], ['5'])
        self.assertEqual(settings['max_rows_to_read'], ['1000000'])
        self.assertEqual(settings['max_bytes_to_read'], ['67108864'])
        self.assertEqual(settings['max_memory_usage'], ['134217728'])
        self.assertEqual(settings['max_result_rows'], ['1'])
        self.assertEqual(settings['result_overflow_mode'], ['throw'])
        self.assertEqual(settings['read_overflow_mode'], ['throw'])
        self.assertEqual(settings['param_resource_id'], [RESOURCE])

    def test_the_credential_is_a_header_and_the_body_is_the_statement(self):
        self.patch(json.dumps({'data': [{'n': 1}]}).encode())
        self.client().query('SELECT 1 FORMAT JSON', {})
        request, timeout = Transport.openers[0].requests[0]
        self.assertEqual(request.get_header('X-clickhouse-user'), 'lo-query')
        self.assertEqual(request.get_header('X-clickhouse-key'), 'secret-credential-value')
        self.assertEqual(request.method, 'POST')
        self.assertEqual(request.data, b'SELECT 1 FORMAT JSON')
        self.assertEqual(timeout, 10)

    def test_no_proxy_and_no_redirect_are_installed_on_every_request(self):
        self.patch(json.dumps({'data': [{'n': 1}]}).encode())
        self.client().query('SELECT 1 FORMAT JSON', {})
        handlers = Transport.openers[0].handlers
        names = [type(handler).__name__ for handler in handlers]
        self.assertIn('NoRedirect', names)
        proxies = [handler for handler in handlers if type(handler).__name__ == 'ProxyHandler']
        self.assertEqual([handler.proxies for handler in proxies], [{}])
        redirector = next(handler for handler in handlers if type(handler).__name__ == 'NoRedirect')
        self.assertIsNone(redirector.redirect_request(None, None, 302, '', {}, 'https://elsewhere/'))

    def test_the_facade_asks_for_its_kind_bound_and_binds_only_named_values(self):
        self.patch(json.dumps({'data': [METRIC_ROW]}).encode())
        outcome = ch.ClickHouseStore(self.client()).read_metrics(
            'metric-threshold', window=WINDOW, parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'},
            selectors={'metric_name': 'lo_process_running'})
        settings = self.settings()
        self.assertEqual(settings['max_result_rows'], [str(facade.QUERY_KINDS['metric-threshold'].max_rows + 1)])
        self.assertEqual(settings['param_metric_name'], ['lo_process_running'])
        self.assertEqual(settings['param_start_ms'], [str(millis(WINDOW.start))])
        self.assertNotIn('param_rule_id', settings, 'a parameter with no placeholder must not be sent')
        self.assertEqual(outcome.status, 'available')

    def test_metric_window_and_selector_remain_bound_in_the_http_request(self):
        self.patch(json.dumps({'data': [METRIC_ROW]}).encode())
        window = facade.Window('2026-09-08T12:15:00Z', '2026-09-08T12:30:00Z')
        ch.ClickHouseStore(self.client()).read_metrics(
            'metric-threshold', window=window, parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'},
            selectors={'metric_name': 'fixture.load'})
        request, _timeout = Transport.openers[0].requests[0]
        self.assertEqual(request.data.decode('utf-8'), ch.QUERY_SQL['metric-threshold'])
        self.assertNotIn(RESOURCE, request.data.decode('utf-8'))
        self.assertNotIn('fixture.load', request.data.decode('utf-8'))
        settings = self.settings()
        self.assertEqual(settings['param_start_ms'], [str(millis(window.start))])
        self.assertEqual(settings['param_end_ms'], [str(millis(window.end))])
        self.assertEqual(settings['param_metric_name'], ['fixture.load'])
        self.assertEqual(settings['param_resource_id'], [RESOURCE])
        self.assertEqual(settings['max_rows_to_read'], ['1000000'])
        self.assertEqual(settings['max_bytes_to_read'], ['67108864'])

    def test_an_oversized_answer_is_refused_rather_than_cut(self):
        self.patch(b'{"data": ["' + b'y' * 70_000 + b'"]}')
        with self.assertRaises(TransportError):
            self.client().series('SELECT 1 FORMAT JSON', {})

    def test_the_read_bound_is_the_byte_that_separates_an_answer_from_an_overflow(self):
        """Exactly 64 KiB is an answer; one byte more is `ResultTooLarge`, never a truncated result."""
        self.patch(padded_body(65_536, canary='ANSWER-CANARY'))
        self.assertEqual(len(self.client().series('SELECT 1 FORMAT JSON', {})), 1)
        self.patch(padded_body(65_537, canary='ANSWER-CANARY'))
        with self.assertRaises(ResultTooLarge) as caught:
            self.client().series('SELECT 1 FORMAT JSON', {})
        self.assertEqual(caught.exception.code, 'source_result_too_large')
        self.assertIsInstance(caught.exception, TransportError)
        self.assertEqual([type(opener).__name__ for opener in Transport.openers], ['RecordingOpener'])
        self.assertEqual(len(Transport.openers[0].requests), 1, 'an overflow is not retried')

    def test_an_overflow_names_its_own_failure_and_a_broken_answer_keeps_the_sanitised_one(self):
        """The two bounded failures stay tellable apart, and neither carries the answer or the key."""
        def store():
            return ch.ClickHouseStore(self.client())

        for overflow in (lambda: store().read_logs('log-records', window=WINDOW,
                                                   parameters={'resource_id': RESOURCE}),
                         lambda: store().describe('describe-metrics', window=WINDOW,
                                                  selectors={'metric_name': 'lo_process_running'})):
            self.patch(padded_body(65_537, canary='ANSWER-CANARY'))
            with self.assertRaises(ResultTooLarge) as caught:
                overflow()
            self.assertNotIn('ANSWER-CANARY', str(caught.exception))
            self.assertNotIn('secret-credential-value', str(caught.exception))
            self.assertNotIn('SELECT', str(caught.exception))
        self.patch(b'{"data": [not json ANSWER-CANARY')
        with self.assertRaises(TransportError) as unknown:
            store().read_logs('log-records', window=WINDOW, parameters={'resource_id': RESOURCE})
        self.assertNotIsInstance(unknown.exception, ResultTooLarge)
        self.assertNotIn('ANSWER-CANARY', str(unknown.exception))
        self.assertNotIn('secret-credential-value', str(unknown.exception))

    def test_http_is_refused_until_the_operator_asks_for_it(self):
        for url in ('http://clickhouse:8123', 'https://clickhouse:8123?param_readonly=0',
                    'https://user:pw@clickhouse:8123', 'https://clickhouse:8123#/x', 'not-a-url'):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    ClickHouse(url, 'lo-query', 'x' * 32)
        self.assertEqual(ClickHouse('http://clickhouse:8123', 'lo-query', 'x' * 32,
                                    allow_http=True).url, 'http://clickhouse:8123')

    def test_the_facade_refuses_anything_that_is_not_the_bounded_client(self):
        for wrong in ('SELECT 1', {'url': 'https://x'}, None):
            with self.subTest(wrong=wrong):
                with self.assertRaises(TypeError):
                    ch.ClickHouseStore(wrong)


class EvidenceSeam(unittest.TestCase):
    """A read's answer must survive intake, storage and reauthorisation, or it must refuse."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'state.db')
        self.actor = Actor('store-facade', 'producer')

    def metric_read(self, **kwargs):
        return recorded(lambda sql, limit: [METRIC_ROW]).read_metrics(
            'metric-threshold', window=WINDOW, parameters={'resource_id': RESOURCE, 'rule_id': 'anomaly.marker'},
            selectors={'metric_name': 'lo_process_running'}, **kwargs)

    def intake(self, outcome):
        """Put the read's own reference on an event from the platform factory and intake it."""
        payload = event('store-facade', RESOURCE, 'rule.facade', 'threshold', 'firing', WINDOW.as_dict(),
                        dict(outcome.receipt.parameters), query_type='metric-threshold')
        payload['evidence'] = [outcome.as_evidence('store-facade')]
        return self.store.intake(payload, self.actor, now=NOW)

    def test_the_receipt_names_the_query_and_carries_no_rows(self):
        reported = self.metric_read().receipt.as_dict()
        self.assertEqual(set(reported), {'query_type', 'parameters', 'window', 'expires_at',
                                         'sample_count', 'truncated'})
        self.assertNotIn('lo_process_running', json.dumps(reported))

    def test_intake_accepts_the_reference_the_read_returned(self):
        self.assertIn('incident_id', self.intake(self.metric_read()))
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    def test_the_sample_a_read_offers_is_storable_and_reauthorisable(self):
        outcome = self.metric_read()
        self.store.put_evidence(outcome.as_sample('facade-sample-1', 3), self.actor, now=NOW)
        fetched = self.store.get_evidence('store-facade', 'facade-sample-1', now=NOW)
        self.assertEqual(fetched['status'], 'available')
        self.assertEqual(fetched['sample']['observed_at'], WINDOW.end)
        self.assertTrue(fetched['sample']['ok'])

    def test_a_read_that_refused_still_reports_not_ok(self):
        outcome = recorded(lambda sql, limit: aggregate(0)).read_logs(
            'source-heartbeat', window=WINDOW, parameters={'resource_id': OTHER})
        self.assertFalse(outcome.as_sample('facade-sample-2')['ok'])

    def test_a_window_whose_evidence_would_be_expired_never_returns_rows(self):
        for expiry in (WINDOW.end, '2026-09-08T10:04:59Z'):
            with self.subTest(expiry=expiry):
                with self.assertRaises(facade.StoreRefused):
                    self.metric_read(expires_at=expiry)

    def test_intake_applies_the_same_expiry_rule_the_facade_enforces(self):
        payload = event('store-facade', RESOURCE, 'rule.facade', 'threshold', 'firing', WINDOW.as_dict(),
                        {'resource_id': RESOURCE}, query_type='metric-threshold')
        payload['evidence'][0]['expires_at'] = WINDOW.end
        with self.assertRaises(StateError):
            self.store.intake(payload, self.actor, now=NOW)

    def test_evidence_may_not_be_promised_past_the_retention_the_store_applies(self):
        for hours in (24, 14 * 24):
            with self.subTest(hours=hours):
                with self.assertRaises(facade.StoreRefused):
                    self.metric_read(store_ttl_hours=hours)
        self.assertEqual(self.metric_read(store_ttl_hours=15 * 24).status, 'available')

    def test_a_read_intake_would_not_name_refuses_instead_of_filing_a_dead_reference(self):
        outcome = recorded(lambda sql, limit: [LOG_ROW]).read_logs('log-records', window=WINDOW,
                                                                  parameters={'resource_id': RESOURCE})
        with self.assertRaises(facade.EvidenceNotApproved) as caught:
            outcome.as_evidence('store-facade')
        self.assertIn('metric-threshold', str(caught.exception))
        payload = event('store-facade', RESOURCE, 'rule.facade', 'threshold', 'firing', WINDOW.as_dict(),
                        {'resource_id': RESOURCE}, query_type='log-records')
        with self.assertRaises(StateError):
            self.store.intake(payload, self.actor, now=NOW)

    def test_a_metric_reference_carries_only_approved_parameter_names(self):
        self.assertTrue(set(self.metric_read().receipt.parameters) <= facade.APPROVED_PARAMETERS)


class FacadeRules(unittest.TestCase):
    """Every refusal is the facade's, so no backend can be the one that quietly loosens it."""

    def refusals(self):
        return (('unknown query kind', lambda store: store.read_logs(
            'not-a-query', window=WINDOW, parameters={'resource_id': RESOURCE})),
                ('unapproved parameter name', lambda store: store.read_logs(
                    'log-records', window=WINDOW, parameters={'resource_id': RESOURCE, 'body_ilike': 'x'})),
                ('parameter that is not a bounded label', lambda store: store.read_logs(
                    'log-records', window=WINDOW, parameters={'resource_id': '*/** OR 1=1'})),
                ('selector the kind does not take', lambda store: store.read_logs(
                    'log-records', window=WINDOW, parameters={'resource_id': RESOURCE},
                    selectors={'metric_name': 'x'})),
                ('selector carrying quote characters', lambda store: store.read_logs(
                    'log-records', window=WINDOW, parameters={'resource_id': RESOURCE},
                    selectors={'needle': "a' OR '1'='1"})),
                ('missing required parameter', lambda store: store.read_metrics(
                    'metric-threshold', window=WINDOW, parameters={'resource_id': RESOURCE})),
                ('describe named as a read', lambda store: store.read_logs(
                    'describe-logs', window=WINDOW, parameters={'resource_id': RESOURCE})),
                ('window wider than the platform allows', lambda store: store.read_logs(
                    'log-records',
                    window=facade.Window(start='2026-01-01T00:00:00Z', end='2026-09-08T00:00:00Z'),
                    parameters={'resource_id': RESOURCE})))

    def test_both_backends_refuse_the_same_requests(self):
        for label, call in self.refusals():
            for name, backend in (('clickhouse', recorded()), ('memory', memory_backend.InMemoryStore())):
                with self.subTest(refusal=label, backend=name):
                    with self.assertRaises(ValueError):
                        call(backend)

    def test_a_seeded_row_must_be_a_row(self):
        seeded = memory_backend.InMemoryStore()
        with self.assertRaises(ValueError):
            seeded.load([{'body': 'a dict is not a log record'}])
        self.assertEqual(seeded.load([]), 0)


class MemoryReads(unittest.TestCase):
    """The test/demo backend answers with the same verdicts, or a test proves the wrong thing."""

    def setUp(self):
        self.metrics = memory_backend.series(3, name='lo_process_running', resource_id=RESOURCE,
                                             start='2026-09-08T10:01:00Z', step_seconds=60)
        self.store = memory_backend.InMemoryStore(self.metrics + [
            facade.LogRecord(body='process lo-fixture started', timestamp='2026-09-08T10:02:00Z',
                             fields={'event.dataset': 'linux.process'}, resource_id=RESOURCE),
            facade.TraceSpan(trace_id='a' * 32, span_id='b' * 16, name='GET /api', service='front-door',
                             duration_ns=15_000_000, timestamp='2026-09-08T10:02:30Z', status='200')])

    def test_a_window_is_half_open(self):
        wide = facade.Window(start='2026-09-08T10:01:00Z', end='2026-09-08T10:03:00Z')
        outcome = self.store.read_metrics('metric-threshold', window=wide,
                                          parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'},
                                          selectors={'metric_name': 'lo_process_running'})
        self.assertEqual([row.timestamp for row in outcome.rows()],
                         ['2026-09-08T10:01:00.000000+00:00', '2026-09-08T10:02:00.000000+00:00'])

    def test_absence_emptiness_and_presence_are_three_different_answers(self):
        missing = self.store.read_logs('source-heartbeat', window=WINDOW, parameters={'resource_id': OTHER})
        narrowed = self.store.read_logs('log-records', window=WINDOW, parameters={'resource_id': RESOURCE},
                                        selectors={'needle': 'a needle nobody wrote'})
        present = self.store.read_logs('source-heartbeat', window=WINDOW, parameters={'resource_id': RESOURCE})
        self.assertEqual(missing.status, 'unavailable')
        self.assertEqual((narrowed.status, narrowed.receipt.sample_count), ('available', 0))
        self.assertEqual((present.status, present.rows()[0].row_count), ('available', 1))

    def test_every_signal_answers_and_describe_counts_the_same_rows(self):
        metrics = self.store.read_metrics('metric-threshold', window=WINDOW,
                                          parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'})
        traces = self.store.read_traces('trace-spans', window=WINDOW, parameters={'rule_id': 'rca.1'},
                                        selectors={'service': 'front-door'})
        self.assertEqual((metrics.status, traces.status), ('available', 'available'))
        self.assertEqual(traces.receipt.query_type, 'trace-spans')
        self.assertEqual(self.store.describe('describe-metrics', window=WINDOW,
                                             selectors={'metric_name': 'lo_process_running'}).row_count, 3)

    def test_a_seeded_series_is_deterministic_and_bounded(self):
        again = memory_backend.series(3, name='lo_process_running', resource_id=RESOURCE,
                                      start='2026-09-08T10:01:00Z')
        self.assertEqual([row.timestamp for row in again], [row.timestamp for row in self.metrics])
        for count, step in ((0, 60), (2001, 60), (10, 0)):
            with self.subTest(count=count, step=step):
                with self.assertRaises(ValueError):
                    memory_backend.series(count, name='x', resource_id=RESOURCE,
                                          start='2026-09-08T10:01:00Z', step_seconds=step)


class PackagePosture(unittest.TestCase):
    """The seams the port promised: one network path, no second TTL reader, no estate left behind."""

    def source(self, relative: str) -> str:
        return (ROOT / 'local_observe/store' / relative).read_text(encoding='utf-8')

    def test_the_package_has_exactly_one_network_seam(self):
        transport = [line for line in self.source('backends/clickhouse.py').splitlines() if 'urllib.request' in line]
        self.assertIn('urllib.request.build_opener', ' '.join(transport))
        self.assertIn('urllib.request.Request', ' '.join(transport))
        for module in ('__init__.py', 'client.py', 'retention.py', 'backends/__init__.py', 'backends/memory.py'):
            with self.subTest(module=module):
                self.assertNotIn('urllib.request', self.source(module), f'{module} grew a transport')
                self.assertNotIn('JsonClient', self.source(module), f'{module} grew a second client')

    def test_the_retention_reader_is_the_r15_tool_imported_not_a_copy(self):
        text = self.source('retention.py')
        self.assertIn('store-signoz', text)
        for forbidden in ('settings/ttl', 'urlopen', 'build_opener', 'http.client'):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, text, 'a second TTL reader appeared in store/retention.py')

    def test_the_openobserve_backend_was_not_ported(self):
        self.assertFalse((ROOT / 'local_observe/store/backends/openobserve.py').exists())
        self.assertIn('OpenObserve', self.source('__init__.py'))
        self.assertIn('store boundaries', self.source('__init__.py'))

    def test_the_package_names_no_host_and_no_private_path(self):
        blob = ' '.join(self.source(name) for name in ('__init__.py', 'client.py', 'retention.py',
                                                       'backends/__init__.py', 'backends/clickhouse.py',
                                                       'backends/memory.py'))
        for forbidden in ('private-address-marker', 'storage-host', 'worker-host', 'example-site', 'openbao', 'deployment-config', 'example-operator',
                          'C:/Users', '/srv/observe', 'notification-bot', 'admin-host'):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, blob)

    def test_the_retention_module_shares_the_facade_signal_list(self):
        self.assertEqual(retention.SIGNALS, facade.SIGNALS)


if __name__ == '__main__':
    unittest.main()

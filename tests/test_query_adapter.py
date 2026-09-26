"""query adapter: the platform query envelope, its refusals, and the evidence link it must not fake.

`local_observe/store` (store facade) owns the query kinds, the SQL and the transport; this file tests only
what `local_observe/platform/query.py` adds on top of it: the eight-field `docs/CONTRACTS.md` §2
envelope a producer posts, the rule that a read which could not happen is never shaped like a read
that found nothing, the row bound that makes `truncated` provable, the refusal of caller-supplied
SQL and of a plaintext endpoint, and the reauthorisation of a stored reference — which must report an
expired link as expired instead of fetching fresh rows to dress it up.

Where a rule belongs to the store seam rather than to this module it is not restated here:
`tests/test_store_facade.py` asserts the bounds that travel with a query, the credential headers, the
no-redirect opener, the 64 KiB read cap and the endpoint refusals on the client itself.
"""
import datetime as dt
import inspect
import json
from pathlib import Path
import re
import tempfile
import unittest
import urllib.request
import xml.etree.ElementTree as ET

from local_observe.http import TransportError
from local_observe.platform import query
from local_observe.platform.detections import event
from local_observe.platform.sigma_runner import ClickHouse, SERIES_MAX_POINTS
from local_observe.store.backends import clickhouse as ch
from local_observe.platform.state import Actor, Store
from local_observe.store import client as facade
from local_observe.store.backends import memory as memory_backend
import yaml

RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
SOURCE = 'query-adapter'
NOW = dt.datetime(2026, 9, 8, 10, 5, tzinfo=dt.timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
WINDOW = {'start': '2026-09-08T10:00:00Z', 'end': '2026-09-08T10:05:00Z'}
#: What `Window` normalises those bounds to: `utc_text` keeps microseconds, which is what makes an
#: envelope's window compare equal to the one `detections.event()` recorded on the event.
PAIR = {'start': '2026-09-08T10:00:00.000000+00:00', 'end': '2026-09-08T10:05:00.000000+00:00'}
FIRST = '2026-09-08T10:01:00Z'
CREDENTIAL = 'k' * 32


def counting(rows=()):
    """A real store backend that also counts the reads it was asked for."""
    return CountingStore(rows)


class CountingStore(memory_backend.InMemoryStore):
    """The in-memory backend with a call log: it answers under the facade's real rules."""

    def __init__(self, rows=()) -> None:
        super().__init__(rows)
        self.calls: list[str] = []

    def read_metrics(self, query_type, **kwargs):
        self.calls.append('read_metrics')
        return super().read_metrics(query_type, **kwargs)

    def read_logs(self, query_type, **kwargs):
        self.calls.append('read_logs')
        return super().read_logs(query_type, **kwargs)

    def read_traces(self, query_type, **kwargs):
        self.calls.append('read_traces')
        return super().read_traces(query_type, **kwargs)


class FailingStore:
    """A facade stand-in that raises the way the transport does, once, with a chosen error."""

    def __init__(self, error: Exception) -> None:
        self.error = error
        self.calls: list[str] = []

    def read_metrics(self, query_type, **kwargs):
        self.calls.append('read_metrics')
        raise self.error

    def read_logs(self, query_type, **kwargs):
        self.calls.append('read_logs')
        raise self.error

    def read_traces(self, query_type, **kwargs):
        self.calls.append('read_traces')
        raise self.error


def metric_store(count: int = 3) -> CountingStore:
    """A store holding *count* samples for `RESOURCE`, all inside `WINDOW`."""
    return counting(memory_backend.series(count, name='lo_process_running', resource_id=RESOURCE,
                                          start=FIRST, step_seconds=30))


def log_store(count: int) -> CountingStore:
    """A store holding *count* log records for `RESOURCE`, one per second inside `WINDOW`."""
    origin = facade.parse_ts(FIRST)
    return counting([facade.LogRecord(body=f'lo-fixture line {index}', severity='info',
                                      resource_id=RESOURCE, fields={'event.dataset': 'linux.process'},
                                      timestamp=facade.utc_text(origin + dt.timedelta(seconds=index)))
                     for index in range(count)])


def read(store, kind='metric-threshold', **kwargs):
    """One metrics envelope, with the parameters every metrics kind requires."""
    parameters = {'resource_id': RESOURCE, 'rule_id': 'anomaly.baseline'}
    return query.metrics(store, SOURCE, kind, window=WINDOW, parameters=parameters, **kwargs)


class EnvelopeShape(unittest.TestCase):
    """§2 names the fields; a producer may not have to open the store package to read an answer."""

    def test_a_read_returns_exactly_the_eight_named_fields(self):
        envelope = read(metric_store())
        self.assertEqual(list(envelope), list(query.ENVELOPE_FIELDS))
        self.assertEqual(envelope['query_type'], 'metric-threshold')
        self.assertEqual(envelope['parameters'], {'resource_id': RESOURCE, 'rule_id': 'anomaly.baseline'})
        self.assertEqual(envelope['window'], PAIR)
        self.assertEqual(len(envelope['rows']), 3)
        self.assertEqual(envelope['row_limit'], facade.QUERY_KINDS['metric-threshold'].max_rows)
        self.assertIs(envelope['truncated'], False)
        self.assertIsNone(envelope['error'])

    def test_rows_are_json_safe_so_a_bundle_can_carry_them(self):
        envelope = read(metric_store())
        decoded = json.loads(json.dumps(envelope))
        self.assertEqual(sorted(decoded['rows'][0]), ['labels', 'name', 'resource_id', 'timestamp', 'value'])
        self.assertEqual(decoded['rows'][0]['name'], 'lo_process_running')

    def test_the_window_is_the_pair_the_event_factory_records(self):
        """One time format, restated as a test: the envelope's window must equal the event's."""
        pair = facade.Window(WINDOW['start'], WINDOW['end']).as_dict()
        built = event(SOURCE, RESOURCE, 'rule.query', 'threshold', 'firing', dict(pair),
                      {'rule_id': 'rule.query'}, query_type='metric-threshold')
        envelope = read(metric_store())
        self.assertEqual(envelope['window'], built['window'])
        self.assertEqual(envelope['window'], built['evidence'][0]['window'])

    def test_an_absent_store_is_a_refusal_and_never_an_exception(self):
        envelope = read(None)
        self.assertEqual(list(envelope), list(query.ENVELOPE_FIELDS))
        self.assertEqual(envelope['rows'], ())
        self.assertIsNone(envelope['parameters'].get('sample_id'))
        self.assertTrue(envelope['error'].startswith('unavailable:'))
        self.assertEqual(envelope['row_limit'], facade.QUERY_KINDS['metric-threshold'].max_rows)


class WindowRules(unittest.TestCase):
    """`[start, end)` in UTC, validated before the store is asked anything."""

    def test_a_naive_bound_means_utc(self):
        envelope = query.logs(counting(), SOURCE, 'source-heartbeat',
                              window={'start': '2026-09-08T10:00:00', 'end': '2026-09-08T10:05:00'},
                              parameters={'resource_id': RESOURCE})
        self.assertEqual(envelope['window']['start'], PAIR['start'])

    def test_a_reversed_or_empty_window_is_refused_before_the_store_is_asked(self):
        store = counting()
        for window in ({'start': WINDOW['end'], 'end': WINDOW['start']},
                       {'start': WINDOW['start'], 'end': WINDOW['start']},
                       {'start': 'yesterday', 'end': 'today'},
                       {'start': WINDOW['start']},
                       {'start': None, 'end': WINDOW['end']}):
            with self.subTest(window=window):
                envelope = query.metrics(store, SOURCE, 'metric-threshold', window=window,
                                         parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'})
                self.assertEqual(envelope['rows'], ())
                self.assertIsNotNone(envelope['error'])
        self.assertEqual(store.calls, [], 'a refused window never reached the store')

    def test_a_window_wider_than_intake_allows_is_refused(self):
        wide = {'start': '2026-09-01T10:00:00Z', 'end': '2026-09-09T10:00:00Z'}   # 8 days
        envelope = query.metrics(counting(), SOURCE, 'metric-threshold', window=wide,
                                 parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'})
        self.assertIn('7 days', envelope['error'])


class FailureIsNotEmptySuccess(unittest.TestCase):
    """The sentence in §2 that is a test, not a style note."""

    def outcome(self, *, series_exists: bool):
        kind = facade.QUERY_KINDS['log-records']
        return facade.build_outcome(kind, {'resource_id': RESOURCE},
                                    facade.Window(**WINDOW), [], series_exists=series_exists)

    def test_an_empty_window_on_a_known_series_is_a_success_with_no_error(self):
        envelope = query.envelope_of(self.outcome(series_exists=True), SOURCE)
        self.assertEqual(envelope['rows'], ())
        self.assertIsNone(envelope['error'])
        self.assertIs(envelope['truncated'], False)

    def test_a_series_the_store_has_never_seen_is_reported_as_an_error(self):
        envelope = query.envelope_of(self.outcome(series_exists=False), SOURCE)
        self.assertEqual(envelope['rows'], ())
        self.assertIsNotNone(envelope['error'])
        self.assertTrue(envelope['error'].startswith('unavailable:'))
        self.assertNotEqual(envelope, query.envelope_of(self.outcome(series_exists=True), SOURCE))

    def test_a_refused_query_carries_the_reason_and_no_rows(self):
        for error in (TransportError('Bounded store read refused or unavailable'),
                      facade.StoreRefused('metric-threshold requires parameter(s): resource_id')):
            with self.subTest(error=type(error).__name__):
                envelope = read(FailingStore(error))
                self.assertEqual(envelope['rows'], ())
                self.assertTrue(envelope['error'].startswith('refused:'), envelope['error'])

    def test_an_unexpected_failure_names_its_class_and_nothing_else(self):
        envelope = read(FailingStore(KeyError('LO_CLICKHOUSE_PASSWORD')))
        self.assertEqual(envelope['error'], 'failed: KeyError')
        self.assertNotIn('CLICKHOUSE_PASSWORD', json.dumps(envelope))

    def test_a_programming_error_is_not_masked_as_a_store_answer(self):
        """The envelope catches refusals and transport failures, not every exception in the process.

        Swallowing `NameError`/`RuntimeError` here would turn a defect in this repository into a
        coverage event saying the store did not answer, which is the wrong thing to be honest about.
        """
        for error in (NameError('typo'), RuntimeError('bug')):
            with self.subTest(error=type(error).__name__), self.assertRaises(type(error)):
                read(FailingStore(error))
        for error in (TransportError('x'), ValueError('x'), TypeError('x'), KeyError('x'),
                      facade.StoreRefused('x')):
            with self.subTest(handled=type(error).__name__):
                self.assertIsNotNone(read(FailingStore(error))['error'])
        self.assertIsNotNone(read(None)['error'])


class Truncation(unittest.TestCase):
    """A page that filled its bound says so; a page the server refused is an error, not a short read."""

    def test_a_full_page_is_reported_as_cut_off_and_still_answered(self):
        bound = facade.QUERY_KINDS['log-records'].max_rows
        envelope = query.logs(log_store(bound), SOURCE, 'log-records', window=WINDOW,
                              parameters={'resource_id': RESOURCE})
        self.assertEqual(len(envelope['rows']), bound)
        self.assertEqual(envelope['row_limit'], bound)
        self.assertIs(envelope['truncated'], True)
        self.assertIsNone(envelope['error'])

    def test_a_short_page_is_not_truncated(self):
        envelope = query.logs(log_store(3), SOURCE, 'log-records', window=WINDOW,
                              parameters={'resource_id': RESOURCE})
        self.assertIs(envelope['truncated'], False)

    def test_an_overflow_is_the_store_s_error_rather_than_a_silently_short_page(self):
        """`result_overflow_mode = throw` is what makes this true; `lo-read.xml` states the cap."""
        failing = FailingStore(TransportError('Bounded store read refused or unavailable'))
        envelope = query.logs(failing, SOURCE, 'log-records', window=WINDOW,
                              parameters={'resource_id': RESOURCE})
        self.assertEqual((envelope['rows'], envelope['truncated']), ((), False))
        self.assertIsNotNone(envelope['error'])
        self.assertEqual(envelope['row_limit'], facade.QUERY_KINDS['log-records'].max_rows)


class ArbitrarySqlIsRefused(unittest.TestCase):
    """Design item 2: a request that cannot be named in the kind table is refused, not compiled."""

    def test_a_statement_shaped_query_type_never_reaches_the_store(self):
        store = counting()
        for name in ('SELECT count() FROM signoz_logs.distributed_logs_v2',
                     'metric-threshold; DROP TABLE signoz_logs.distributed_logs_v2',
                     'log-records --', 'create table x as select 1'):
            with self.subTest(query_type=name):
                envelope = query.metrics(store, SOURCE, name, window=WINDOW,
                                         parameters={'resource_id': RESOURCE, 'rule_id': 'r.1'})
                self.assertEqual(envelope['rows'], ())
                self.assertEqual(envelope['row_limit'], 0, 'no approved kind answered this name')
                self.assertIn('SQL', envelope['error'])
        self.assertEqual(store.calls, [])

    def test_an_unknown_kind_is_refused_by_the_table_and_becomes_an_error(self):
        envelope = read(counting(), kind='metric-everything')
        self.assertIn('closed table', envelope['error'])
        self.assertEqual(envelope['row_limit'], 0)

    def test_the_statement_argument_does_not_exist_on_the_read_functions(self):
        """The public surface takes a query kind, so there is nowhere to put SQL."""
        for function in (query.metrics, query.logs, query.traces):
            with self.subTest(function=function.__name__):
                names = set(inspect.signature(function).parameters)
                self.assertTrue({'store', 'source', 'query_type', 'window', 'parameters'} <= names)
                self.assertFalse([name for name in names if 'sql' in name.lower() or 'statement' in name])

    def test_a_rejected_parameter_value_is_never_echoed_into_the_envelope(self):
        bad = {'resource_id': RESOURCE, 'rule_id': 'anomaly.marker\r\nX-ClickHouse-User: default'}
        envelope = query.metrics(counting(), SOURCE, 'metric-threshold', window=WINDOW, parameters=bad)
        self.assertEqual(envelope['parameters']['rule_id'], query.ECHO_REFUSAL)
        self.assertNotIn('X-ClickHouse-User', json.dumps(envelope))
        self.assertIsNotNone(envelope['error'])


class ReaderConstruction(unittest.TestCase):
    """Design item 7: unconfigured means stated-off, never a traceback in a producer's loop."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.credential = Path(self.temp.name) / 'read-password'
        # write_bytes, not write_text: on Windows a text-mode write turns the one \n into \r\n, and
        # read_credential refuses the \r — the refusal its own message tells the operator to fix with
        # printf. The test must not depend on that difference one way or the other.
        self.credential.write_bytes((CREDENTIAL + '\n').encode())

    def environ(self, **extra):
        values = {'LO_CLICKHOUSE_URL': 'https://clickhouse:8123',
                  'LO_CLICKHOUSE_READ_PASSWORD_FILE': str(self.credential)}
        values.update(extra)
        return values

    def assert_off(self, environ, *, fragment):
        with self.assertLogs('local_observe.platform.query', level='INFO') as captured:
            self.assertIsNone(query.open_reader(environ=environ))
        self.assertEqual(len(captured.output), 1, captured.output)
        self.assertIn(fragment, captured.output[0])
        self.assertNotIn(CREDENTIAL, captured.output[0])

    def test_no_endpoint_names_the_variable_in_one_log_line(self):
        self.assert_off({'LO_CLICKHOUSE_READ_PASSWORD_FILE': str(self.credential)},
                        fragment='LO_CLICKHOUSE_URL')

    def test_a_blank_endpoint_is_the_same_refusal(self):
        self.assert_off(self.environ(**{'LO_CLICKHOUSE_URL': '   '}), fragment='LO_CLICKHOUSE_URL')

    def test_a_missing_credential_names_its_variable_and_not_its_value(self):
        self.assert_off({'LO_CLICKHOUSE_URL': 'https://clickhouse:8123'},
                        fragment='LO_CLICKHOUSE_READ_PASSWORD')

    def test_a_blank_credential_refuses_rather_than_authenticating_as_empty(self):
        """Three blank shapes, one line each: spaces in the value, a whitespace file, a missing file."""
        blank = Path(self.temp.name) / 'blank'
        blank.write_bytes(b'   ')
        for environ in ({'LO_CLICKHOUSE_URL': 'https://clickhouse:8123',
                         'LO_CLICKHOUSE_READ_PASSWORD': '   '},
                        {'LO_CLICKHOUSE_URL': 'https://clickhouse:8123',
                         'LO_CLICKHOUSE_READ_PASSWORD_FILE': str(blank)},
                        {'LO_CLICKHOUSE_URL': 'https://clickhouse:8123',
                         'LO_CLICKHOUSE_READ_PASSWORD_FILE': str(Path(self.temp.name) / 'nope')}):
            with self.subTest(variable=sorted(environ)):
                self.assert_off(environ, fragment='LO_CLICKHOUSE_READ_PASSWORD')

    def test_the_runner_credential_is_never_borrowed_for_analysis_reads(self):
        """The Sigma user's profile pins one row per query; using it here would be a silent ceiling raise."""
        self.assert_off({'LO_CLICKHOUSE_URL': 'https://clickhouse:8123',
                         'LO_CLICKHOUSE_PASSWORD': CREDENTIAL},
                        fragment='LO_CLICKHOUSE_READ_PASSWORD')

    def test_plaintext_http_is_refused_until_the_operator_asks_for_it(self):
        """The refusal the runner's client carried, now on this module's own construction path."""
        self.assert_off(self.environ(**{'LO_CLICKHOUSE_URL': 'http://clickhouse:8123'}),
                        fragment='LO_CLICKHOUSE_URL')
        reader = query.open_reader(environ=self.environ(**{'LO_CLICKHOUSE_URL': 'http://clickhouse:8123',
                                                           'LO_INTERNAL_ALLOW_HTTP': '1'}))
        self.assertIsNotNone(reader)
        self.assertEqual(reader.client.url, 'http://clickhouse:8123')

    def test_an_endpoint_with_embedded_credentials_is_refused(self):
        self.assert_off(self.environ(**{'LO_CLICKHOUSE_URL': 'https://default@clickhouse:8123'}),
                        fragment='LO_CLICKHOUSE_URL')

    def test_a_user_name_outside_the_bounded_shape_is_refused(self):
        self.assert_off(self.environ(**{'LO_CLICKHOUSE_READ_USER': 'lo read'}),
                        fragment='LO_CLICKHOUSE_READ_USER')

    def test_a_configured_reader_is_built_on_the_analysis_user(self):
        """No request is made here: what is under test is which identity the client would present."""
        reader = query.open_reader(environ=self.environ())
        self.assertEqual(reader.client.user, query.ANALYSIS_USER_DEFAULT)
        self.assertEqual(reader.client.user, 'lo-read')
        self.assertEqual(reader.client.url, 'https://clickhouse:8123')

    def test_a_reader_named_by_the_environment_uses_that_name(self):
        reader = query.open_reader(environ=self.environ(**{'LO_CLICKHOUSE_READ_USER': SOURCE}))
        self.assertEqual(reader.client.user, SOURCE)


class RefusalEnvelope(unittest.TestCase):
    """The shape a producer emits when the query path is off, so coverage replaces silence."""

    def test_a_refusal_names_its_reason_and_carries_the_window(self):
        envelope = query.refusal(SOURCE, 'source-heartbeat', window=WINDOW,
                                 parameters={'resource_id': RESOURCE},
                                 error='unavailable: reads are disabled on this install')
        self.assertEqual(list(envelope), list(query.ENVELOPE_FIELDS))
        self.assertEqual(envelope['rows'], ())
        self.assertIs(envelope['truncated'], False)
        self.assertEqual(envelope['window'], PAIR)

    def test_a_refusal_with_no_reason_is_refused(self):
        for empty in ('', '   ', None):
            with self.subTest(error=empty), self.assertRaises(ValueError):
                query.refusal(SOURCE, 'log-records', window=WINDOW, parameters={}, error=empty)

    def test_a_refusal_cannot_carry_an_impossible_window(self):
        with self.assertRaises(ValueError):
            query.refusal(SOURCE, 'log-records', window={'start': WINDOW['end'], 'end': WINDOW['start']},
                          parameters={}, error='unavailable: no reader')


class EvidenceLink(unittest.TestCase):
    """Design item 3: a result is cited as a reference, and an aged-out link stays aged out."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Store(Path(self.temp.name) / 'state.db')
        self.actor = Actor(SOURCE, 'producer')

    def stored_read(self):
        """One metrics read, its sample retained, and the reference a producer would post."""
        store = metric_store()
        outcome = store.read_metrics('metric-threshold',
                                     window=facade.Window(**WINDOW),
                                     parameters={'resource_id': RESOURCE, 'rule_id': 'anomaly.marker'},
                                     selectors={'metric_name': 'lo_process_running'})
        sample_id = 'sample-query-adapter-1'
        self.state.put_evidence(outcome.as_sample(sample_id, value=len(outcome.samples)), self.actor,
                                now=NOW)
        reference = dict(outcome.as_evidence(SOURCE))
        return store, reference, sample_id, outcome

    def test_a_retained_sample_is_available_now(self):
        store, reference, sample_id, _ = self.stored_read()
        verdict = query.reauthorise(self.state, reference, sample_id=sample_id, now=NOW)
        self.assertEqual(verdict['status'], 'available')
        self.assertTrue(verdict['sample']['ok'])
        self.assertIsNotNone(verdict['expires_at'])

    def test_an_expired_reference_is_reported_expired_and_never_back_filled(self):
        store, reference, sample_id, _ = self.stored_read()
        later = NOW + dt.timedelta(days=16)          # past the 15 days put_evidence stamps
        asked_before = len(store.calls)
        verdict = query.reauthorise(self.state, reference, sample_id=sample_id, now=later)
        self.assertEqual(verdict['status'], 'expired')
        self.assertIsNone(verdict['sample'])
        self.assertIsNone(verdict['expires_at'])
        self.assertIn('back-fill', verdict['detail'])
        self.assertEqual(len(store.calls), asked_before, 'the adapter must not re-query for a dead link')

    def test_reauthorise_cannot_be_handed_a_store_client_at_all(self):
        """The no-back-fill rule is structural: there is no parameter to pass a reader through."""
        names = set(inspect.signature(query.reauthorise).parameters)
        self.assertEqual(names, {'state', 'reference', 'sample_id', 'now'})
        self.assertFalse([name for name in names if 'store' in name.lower() and name != 'state'])

    def test_a_reference_naming_no_sample_id_is_unavailable_not_a_lookup_under_an_empty_key(self):
        calls = []

        class Watching(Store):
            def get_evidence(self, source, sample_id, **kwargs):
                calls.append((source, sample_id))
                return super().get_evidence(source, sample_id, **kwargs)

        reference = {'source': SOURCE, 'query_type': 'sigma-count',
                     'parameters': {'rule_id': 'sigma.6b2', 'artifact_sha256': 'a' * 64},
                     'window': dict(WINDOW), 'schema_version': 1, 'expires_at': '2026-09-23T10:05:00+00:00'}
        verdict = query.reauthorise(Watching(Path(self.temp.name) / 'state.db'), reference, now=NOW)
        self.assertEqual(verdict['status'], 'unavailable')
        self.assertIn('sample_id', verdict['detail'])
        self.assertEqual(calls, [])

    def test_a_reference_from_another_producer_is_not_this_producer_s_sample(self):
        store, reference, sample_id, _ = self.stored_read()
        reference['source'] = 'someone-else'
        verdict = query.reauthorise(self.state, reference, sample_id=sample_id, now=NOW)
        self.assertEqual(verdict['status'], 'unavailable')

    def test_a_state_that_cannot_answer_is_unavailable_rather_than_available(self):
        broken = object()
        verdict = query.reauthorise(broken, {'source': SOURCE, 'parameters': {'sample_id': 's.1'}})
        self.assertEqual(verdict['status'], 'unavailable')
        self.assertIn('could not answer', verdict['detail'])

    def test_an_envelope_of_a_failed_read_still_offers_a_storable_verdict(self):
        outcome = facade.build_outcome(facade.QUERY_KINDS['source-heartbeat'], {'resource_id': RESOURCE},
                                       facade.Window(**WINDOW), [], series_exists=False)
        sample = outcome.as_sample('heartbeat.1')
        self.assertIs(sample['ok'], False)
        key = self.state.put_evidence(sample, self.actor, now=NOW)
        self.assertTrue(key)


class AnalysisProfile(unittest.TestCase):
    """The second ClickHouse user, checked against the first one rather than against prose.

    `lo-read.xml` is a privilege claim in XML, and the only claim that makes it safe to add is that
    it is `lo-query`'s privileges with a bigger row number and nothing else. The comparison is
    therefore structural: same settings keys and values except the one named difference, same
    constraints, same three grants. A future edit that quietly adds `system.*` to the new user, or
    drops `allow_ddl`, fails here without anyone having to re-read the file.
    """

    USERS = Path('components/data/store-signoz/clickhouse-users.d')
    BOUNDS = ('max_execution_time', 'max_rows_to_read', 'max_bytes_to_read', 'max_memory_usage',
              'max_result_rows', 'result_overflow_mode', 'read_overflow_mode')

    def setUp(self):
        self.query_user = ET.parse(ROOT / self.USERS / 'lo-query.xml').getroot()
        self.read_user = ET.parse(ROOT / self.USERS / 'lo-read.xml').getroot()

    def profile(self, root: ET.Element, name: str) -> dict[str, str]:
        return {child.tag: (child.text or '').strip()
                for child in root.find('profiles').find(name) if child.tag != 'constraints'}

    def test_the_two_users_differ_in_one_setting_and_in_their_identity(self):
        left = self.profile(self.query_user, 'lo-readonly')
        right = self.profile(self.read_user, 'lo-analysis')
        self.assertEqual(sorted(left), sorted(right))
        self.assertEqual([name for name in self.BOUNDS if left[name] != right[name]], ['max_result_rows'])
        self.assertEqual((left['readonly'], left['allow_ddl']), ('1', '0'))
        self.assertEqual((right['readonly'], right['allow_ddl']), ('1', '0'))
        self.assertEqual((left['result_overflow_mode'], left['read_overflow_mode']), ('throw', 'throw'))
        self.assertEqual((right['result_overflow_mode'], right['read_overflow_mode']), ('throw', 'throw'))

    def test_the_row_ceiling_is_the_transport_bound_not_a_number_invented_here(self):
        analysis = self.profile(self.read_user, 'lo-analysis')
        self.assertEqual(int(analysis['max_result_rows']), facade.MAX_ROWS)
        self.assertEqual(int(analysis['max_result_rows']), SERIES_MAX_POINTS)

    def test_the_grants_are_identical_and_name_nothing_outside_the_three_signal_databases(self):
        def grants(root):
            return sorted(item.text for item in root.find('users').findall('.//grant'))
        self.assertEqual(grants(self.query_user), grants(self.read_user))
        # Pinned ClickHouse parses each entry as a GRANT/REVOKE statement. Bare
        # "SELECT ON" matched our previous fixture expectation but prevented startup.
        self.assertEqual(sorted(f'GRANT SELECT ON signoz_{name}.*' for name in ('traces', 'metrics', 'logs')),
                         grants(self.read_user))

    def test_the_constraints_blocks_match_setting_for_setting(self):
        def constrained(root, profile):
            return sorted(item.tag for item in root.find('profiles').find(profile).find('constraints'))
        self.assertEqual(constrained(self.query_user, 'lo-readonly'),
                         constrained(self.read_user, 'lo-analysis'))
        self.assertEqual(sorted(self.BOUNDS), constrained(self.read_user, 'lo-analysis'))

    def test_the_password_is_a_substitution_from_its_own_file_not_the_other_user_s(self):
        def substitution(root):
            return (root.findtext('include_from'), root.find('users').findall('.//password')[0].get('incl'))
        self.assertEqual(substitution(self.read_user),
                         ('/run/secrets/clickhouse-read-credentials', 'lo_read_password'))
        self.assertNotEqual(substitution(self.query_user), substitution(self.read_user))
        body = (ROOT / self.USERS / 'lo-read.xml').read_text(encoding='utf-8')
        self.assertNotIn('<password>', body, 'no literal password in a shipped fragment')

    def test_the_user_name_this_module_builds_is_the_one_the_fragment_creates(self):
        self.assertEqual(query.ANALYSIS_USER_DEFAULT,
                         self.read_user.find('users')[0].tag)
        self.assertEqual(1, len(self.read_user.find('users')))

    def test_the_delta_that_would_mount_it_is_read_only_and_ships_no_default(self):
        body = (ROOT / self.USERS / 'lo-read.compose.yaml').read_text(encoding='utf-8')
        mount = [line.strip().removeprefix('- ') for line in body.splitlines()
                 if line.lstrip().startswith('- ./')][0]
        self.assertEqual('./clickhouse-users.d/lo-read.xml:/etc/clickhouse-server/users.d/lo-read.xml:ro',
                         mount)
        secret = yaml.safe_load(body)['secrets']
        # Exactly one secret, and its only two keys: a `file:` pointing at a REQUIRED variable. An
        # `optional: true` or a `:-` default here is the fail-open path lo-read.xml argues about.
        self.assertEqual(['clickhouse-read-credentials'], sorted(secret))
        self.assertEqual(['file'], sorted(secret['clickhouse-read-credentials']))
        self.assertIn('LO_CLICKHOUSE_READ_CREDENTIALS_FILE:?', secret['clickhouse-read-credentials']['file'])
        self.assertEqual([], re.findall(r'\$\{[A-Z0-9_]+:-', ''.join(
            line for line in body.splitlines() if not line.lstrip().startswith('#'))),
                         'a required secret keeps no default')


class Posture(unittest.TestCase):
    """This module is a projection, not a second store seam."""

    SOURCE_PATH = Path(__file__).resolve().parents[1] / 'local_observe' / 'platform' / 'query.py'

    def test_it_opens_no_socket_and_names_no_header(self):
        body = self.SOURCE_PATH.read_text(encoding='utf-8')
        for forbidden in ('urllib', 'X-ClickHouse', 'http.client', 'socket'):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, body)

    def test_it_names_no_host_and_no_private_path(self):
        body = self.SOURCE_PATH.read_text(encoding='utf-8')
        for token in ('private-address-marker', 'storage-host', 'worker-host', 'deployment-config', 'openbao', '/home/example-operator', '/srv/observe',
                      'example-site', 'example-operator'):
            with self.subTest(token=token):
                self.assertNotIn(token, body)

    def test_every_envelope_key_the_contract_names_is_produced_by_one_function(self):
        body = self.SOURCE_PATH.read_text(encoding='utf-8')
        for field in query.ENVELOPE_FIELDS:
            with self.subTest(field=field):
                self.assertIn(f"'{field}'", body)

    def test_the_envelope_never_grows_a_ninth_field(self):
        for envelope in (read(counting()), read(None),
                         query.refusal(SOURCE, 'log-records', window=WINDOW, parameters={},
                                       error='unavailable: no reader')):
            with self.subTest(envelope=type(envelope).__name__):
                self.assertEqual(len(envelope), 8)
                self.assertEqual(set(envelope), set(query.ENVELOPE_FIELDS))


class ComponentDirectory(unittest.TestCase):
    """`components/data/query-adapter/` — the five quality bar artefacts, and the claims inside them.

    The row in `docs/COMPONENTS.md` says "Bounded queries and evidence links". quality bar says the word
    *validated* means contract + pinned manifest + conformance + backup/restore + upgrade, so this
    class checks the five documents exist, that the machine-readable one does not drift from the code
    it describes, and that the prose one keeps saying `not-run` where nothing ran. A document that
    restates a number the code owns is worse than a pointer, so every restated number here is pinned
    against its source; the ones that could not be pinned are not restated at all.
    """

    COMPONENT = ROOT / 'components/data/query-adapter'
    ARTEFACTS = ('CONTRACT.md', 'conformance.md', 'backup.md', 'upgrade.md', 'versions.json')

    def setUp(self):
        self.pins = json.loads((self.COMPONENT / 'versions.json').read_text(encoding='utf-8'))
        self.store = json.loads((ROOT / 'components/data/store-signoz/versions.json').read_text(encoding='utf-8'))

    def test_the_five_artefacts_are_here_and_no_compose_model_is(self):
        for name in self.ARTEFACTS:
            with self.subTest(artefact=name):
                self.assertTrue((self.COMPONENT / name).is_file(), name)
        self.assertFalse((self.COMPONENT / 'compose.yaml').exists(),
                         'a second owner of the clickhouse service cannot be merged across includes')

    def test_the_store_image_pins_are_referenced_and_never_copied(self):
        named = self.pins['compatible_tuple']['image_pin_keys']
        self.assertTrue(set(named) <= set(self.store['images']), named)
        body = (self.COMPONENT / 'versions.json').read_text(encoding='utf-8')
        for key in named:
            with self.subTest(pin=key):
                self.assertNotIn(self.store['images'][key], body, 'a copied pin is a second truth')
        self.assertIsNone(self.pins['verified_on'], 'nothing here has been verified on a host')
        self.assertEqual('experimental', self.pins['status'])

    def test_the_tables_named_are_the_tables_the_code_builds_statements_from(self):
        """Two directions, because a table can drift either way: documented and unread, or read and undocumented."""
        documented = {name for name in self.pins['tables_and_layouts'] if name != 'note'}
        from local_observe.store.backends.clickhouse import QUERY_SQL
        built = set()
        for statement in QUERY_SQL.values():
            built.update(part.strip() for part in re.findall(r'FROM ([a-z_]+\.[a-z_0-9]+)', statement))
        self.assertEqual(documented, built, 'versions.json and QUERY_SQL name different tables')

    def test_the_row_caps_are_the_ones_the_kinds_declare(self):
        for query_type, bound in self.pins['row_caps'].items():
            if not isinstance(bound, int) or isinstance(bound, bool):
                continue        # the note, the aggregate list and the provenance line
            with self.subTest(query_type=query_type):
                expected = facade.MAX_ROWS if query_type == 'MAX_ROWS' else facade.QUERY_KINDS[query_type].max_rows
                self.assertEqual(bound, expected)
        for aggregate in self.pins['row_caps']['aggregates_max_rows_1']:
            with self.subTest(aggregate=aggregate):
                self.assertEqual(1, facade.QUERY_KINDS[aggregate].max_rows)

    def test_the_bounds_are_the_ones_the_client_actually_sends(self):
        body = (ROOT / 'local_observe/store/backends/clickhouse.py').read_text(encoding='utf-8')
        for key, value in self.pins['server_side_bounds']['sent_on_every_request'].items():
            with self.subTest(setting=key):
                self.assertRegex(body, rf"'{key}'\s*:\s*'{value}'")

    def test_every_document_says_not_run_where_nothing_ran(self):
        for name in self.ARTEFACTS:
            with self.subTest(document=name):
                self.assertIn('not-run', (self.COMPONENT / name).read_text(encoding='utf-8'),
                              'a component document that never says not-run claims a pass')

    def test_the_contract_names_the_owner_of_every_piece_it_points_at(self):
        body = (self.COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        for piece in ('local_observe/platform/query.py', 'local_observe/store/client.py',
                      'local_observe/store/backends/clickhouse.py', 'clickhouse-users.d',
                      'components/control/sigma/compose.yaml'):
            with self.subTest(piece=piece):
                self.assertIn(piece, body)


class TransportRefusalsCarriedOver(unittest.TestCase):
    """The runner's transport moved to `store/backends/clickhouse.py` (store facade); its refusals did not move.

    Each test here names one refusal the pre-move `sigma_runner.ClickHouse` had and asserts it through
    the name `sigma_runner` re-exports, so the move cannot be undone quietly and so the aggregate
    path's own bound is still checked on the **real** client rather than only on a fake. The rest of
    them (the seven bounds, the header, the no-redirect opener, the 64 KiB read cap) are asserted in
    `tests/test_store_facade.py::Transport`, which is cited per refusal in the query adapter report.
    """

    def setUp(self):
        self.original = urllib.request.build_opener

    def tearDown(self):
        urllib.request.build_opener = self.original

    def answer_with(self, payload: dict) -> None:
        body = json.dumps(payload).encode()

        class Body:
            def read(self, _limit):
                return body

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

        class Opener:
            def open(self, _request, timeout=None):
                return Body()

        urllib.request.build_opener = lambda *handlers: Opener()

    def client(self):
        return ClickHouse('https://clickhouse.invalid:8123', 'lo-read', CREDENTIAL)

    def test_the_runner_still_imports_the_client_by_the_name_it_always_used(self):
        self.assertIs(ClickHouse, ch.ClickHouse)

    def test_an_aggregate_answer_of_two_rows_is_refused_rather_than_the_first_one_returned(self):
        """`query()` promises exactly one row; a wider answer is a refusal, not a convenience."""
        self.answer_with({'data': [{'match_count': 1}, {'match_count': 2}]})
        with self.assertRaises(TransportError):
            self.client().query('SELECT count() AS match_count FROM x FORMAT JSON', {})

    def test_an_aggregate_answer_of_one_row_is_returned_whole(self):
        self.answer_with({'data': [{'source_count': 3, 'usable_count': 3, 'match_count': 0}]})
        self.assertEqual(self.client().query('SELECT 1 FORMAT JSON', {})['match_count'], 0)

    def test_the_series_path_is_where_a_wider_page_is_asked_for(self):
        self.answer_with({'data': [{'ts': 1, 'value': 2}]})
        self.assertEqual(len(self.client().series('SELECT 1 FORMAT JSON', {})), 1)

    def test_a_malformed_answer_is_one_transport_error_and_names_nothing_from_the_body(self):
        self.answer_with({'nope': 'not the JSON shape FORMAT JSON produces'})
        with self.assertRaises(TransportError) as caught:
            self.client().query('SELECT 1 FORMAT JSON', {})
        self.assertNotIn('not the JSON shape', str(caught.exception))

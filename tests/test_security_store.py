"""The owned ``security_events`` store: schema application, the write bounds, and both transports.

Three things are proven here that a reviewer cannot check by reading the code alone:

* applying the DDL twice lands nothing, and applying a *different* policy over an existing table is
  reported as **drift** rather than as success — the case that a `CREATE TABLE IF NOT EXISTS` hides
  from every other tool in this repository;
* the row is a bounded object: a `kind` that is not a security finding, a severity outside intake's
  three, a payload over the 64 KiB ceiling, or a control character in a field are refusals *before*
  any byte goes out;
* neither transport leaks: a failing write raises one fixed sentence that carries neither the
  credential nor the statement, and the read side refuses a wrong-shaped answer instead of guessing.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.http import TransportError
from local_observe.security import schema
from local_observe.security.memory import InMemorySecurityStore
from local_observe.security.store import (ClickHouseSecurityReader, ClickHouseSecurityWriter,
                                         MAX_RAW_BYTES, MAX_ROWS_PER_STATEMENT, SecurityEvent,
                                         SecurityEventStore, SecurityStoreRefused,
                                         SecurityStoreUnavailable, cutoffs, epoch_text, insert_statement,
                                         nanos, sensitive_in)
from local_observe.security.ttl import (DEFAULT_POLICY, RetentionPolicy, TIER_CRITICAL, TIER_ROUTINE,
                                       parse_ttl_expression)
from local_observe.store.retention import SIGNALS

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'local_observe' / 'security'
USERS_DIR = ROOT / 'components' / 'data' / 'store-signoz' / 'clickhouse-users.d'
STAMP = '2026-09-09T12:00:00+00:00'


def row(**overrides) -> SecurityEvent:
    """One valid analytical row, with *overrides* replacing the defaults."""
    base = {'ts': STAMP, 'source': 'sigma-stage', 'event_id': 'a' * 64, 'rule_id': 'sigma.5d2cb39c',
            'rule_version': '65ff3516', 'kind': 'security', 'status': 'firing', 'severity': 'warning',
            'window_start': '2026-09-09T11:59:00+00:00', 'window_end': STAMP,
            'observed_at': STAMP, 'resource_id': 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'}
    base.update(overrides)
    return SecurityEvent(**base)


class FakeStore:
    """A `ClickHouse` stand-in that answers one reviewed aggregate per statement, and counts calls."""

    def __init__(self, answers=None, fail=False):
        self.answers = answers or {}
        self.fail = fail
        self.calls = []

    def query(self, sql, parameters):
        self.calls.append((sql, parameters))
        if self.fail:
            raise TransportError('Bounded ClickHouse query failed')
        for key, answer in self.answers.items():
            if key in sql:
                return answer if isinstance(answer, dict) else {'row_count': answer}
        raise AssertionError(f'unexpected statement: {sql[:60]}')


class EnsureSchemaTests(unittest.TestCase):
    """The idempotent apply, and the drift an idempotent apply would otherwise swallow."""

    def setUp(self):
        self.backend = InMemorySecurityStore()
        self.store = SecurityEventStore(writer=self.backend, reader=self.backend)

    def test_applying_twice_sends_both_statements_and_changes_nothing(self):
        first = self.store.ensure_schema()
        self.assertEqual(len(first.statements), 2)
        self.assertEqual(self.backend.statements[:2], list(first.statements))
        self.assertEqual(self.store.ensure_schema().comparison.status, 'match')
        self.assertEqual(self.backend.reapplied, 1)
        self.assertEqual(len(self.backend.statements), 4)

    def test_a_fresh_store_reports_agreement_with_the_policy(self):
        verdict = self.store.ensure_schema()
        self.assertTrue(verdict.comparison.matches)
        self.assertEqual(verdict.comparison.live, DEFAULT_POLICY)

    def test_applying_a_different_policy_over_an_existing_table_reports_drift_not_success(self):
        """``IF NOT EXISTS`` keeps the old TTL; a checker that printed "applied" would be lying."""
        self.store.ensure_schema()
        narrowed = SecurityEventStore(writer=self.backend, reader=self.backend,
                                      policy=RetentionPolicy(critical_days=400, routine_days=30))
        verdict = narrowed.ensure_schema()
        self.assertEqual(verdict.comparison.status, 'drift')
        self.assertIn('declared 400d but the live table keeps 1825d', verdict.comparison.detail)

    def test_a_table_that_was_never_created_reads_as_no_ttl(self):
        self.assertEqual(self.store.verify_ttl().status, 'no-ttl')

    def test_a_write_before_the_schema_is_refused_rather_than_dropped(self):
        with self.assertRaises(SecurityStoreRefused):
            self.store.write([row()])

    def test_the_in_memory_backend_refuses_a_statement_it_does_not_model(self):
        """The backend that proves these rules must not silently accept a new kind of write."""
        with self.assertRaises(SecurityStoreRefused):
            self.backend.execute('DROP TABLE security_events.events')


class RowBoundsTests(unittest.TestCase):
    """What a row refuses, and why each refusal is the shape of a real defect."""

    def test_a_coverage_verdict_is_not_a_security_event(self):
        """§4 keeps the records distinct: a missing log source must not enter a security table."""
        for kind in ('coverage', 'threshold', 'anomaly', 'availability', 'drift', ''):
            with self.subTest(kind=kind):
                with self.assertRaises(SecurityStoreRefused):
                    row(kind=kind)

    def test_only_the_words_intake_admits_survive_into_a_row(self):
        for status in ('cleared', 'OK', ''):
            with self.subTest(status=status):
                with self.assertRaises(SecurityStoreRefused):
                    row(status=status)
        for severity in ('error', 'unknown', ''):
            with self.subTest(severity=severity):
                with self.assertRaises(SecurityStoreRefused):
                    row(severity=severity)

    def test_the_payload_is_bounded_by_the_ceiling_an_event_itself_may_not_pass(self):
        with self.assertRaises(SecurityStoreRefused):
            row(raw='x' * (MAX_RAW_BYTES + 1))
        row(raw='x' * MAX_RAW_BYTES)

    def test_a_control_character_in_a_text_field_is_refused_not_stripped(self):
        for name, value in (('raw', 'line\nbreak'), ('principal', 'tab\there'), ('raw', 'nul\x00')):
            with self.subTest(field=name):
                with self.assertRaises(SecurityStoreRefused):
                    row(**{name: value})

    def test_an_unbounded_or_unsafe_label_is_refused(self):
        for name in ('source', 'event_id', 'rule_id', 'rule_version'):
            with self.subTest(field=name):
                with self.assertRaises(SecurityStoreRefused):
                    row(**{name: 'has a space'})
                with self.assertRaises(SecurityStoreRefused):
                    row(**{name: 'x' * 129})

    def test_window_bounds_must_be_ordered_and_parsable(self):
        with self.assertRaises(SecurityStoreRefused):
            row(window_start=STAMP, window_end='2026-09-09T11:59:00+00:00')
        with self.assertRaises(SecurityStoreRefused):
            row(observed_at='whenever')

    def test_labels_are_bounded_in_count_and_shape(self):
        with self.assertRaises(SecurityStoreRefused):
            row(labels={f'k{i}': 'v' for i in range(20)})
        with self.assertRaises(SecurityStoreRefused):
            row(labels={'ok': 'value with\na newline'})
        self.assertEqual(len(row(labels={'sample_id': 'b' * 64}).labels), 1)

    def test_the_tier_is_derived_and_cannot_be_supplied(self):
        self.assertEqual(row(severity='critical').retention_tier, TIER_CRITICAL)
        self.assertEqual(row(severity='warning').retention_tier, TIER_ROUTINE)
        with self.assertRaises(TypeError):
            row(retention_tier='critical')

    def test_a_row_carries_exactly_the_columns_the_ddl_declares(self):
        columns = [line.strip().split(' ')[0] for line in schema.create_table_sql().splitlines()
                   if line.startswith('    ')]
        self.assertEqual(list(row().as_row(received_at=STAMP)), columns)


class InsertStatementTests(unittest.TestCase):
    """One bounded statement, and the JSON that keeps a payload inside its own field."""

    def test_a_payload_that_holds_sql_or_quotes_stays_inside_its_column(self):
        nasty = "'; DROP TABLE security_events.events; SELECT 'x"
        statement = insert_statement([row(raw=nasty).as_row(received_at=STAMP)])
        self.assertEqual(statement.count('INSERT INTO'), 1)
        payload = json.loads(statement.split('\n', 1)[1])
        self.assertEqual(payload['raw'], nasty)

    def test_an_empty_batch_is_a_refusal_not_a_no_op(self):
        with self.assertRaises(SecurityStoreRefused):
            insert_statement([])

    def test_one_write_is_capped_in_rows(self):
        rows = [row(event_id=f'e{i}').as_row(received_at=STAMP) for i in range(MAX_ROWS_PER_STATEMENT + 1)]
        with self.assertRaises(SecurityStoreRefused):
            insert_statement(rows)

    def test_a_repeated_identity_inside_one_batch_is_refused(self):
        """The table keeps one row for a repeated key, so counting two would be a false claim."""
        backend = InMemorySecurityStore()
        store = SecurityEventStore(writer=backend, reader=backend)
        store.ensure_schema()
        with self.assertRaises(SecurityStoreRefused):
            store.write([row(), row()])
        self.assertEqual(len(backend.statements), 2)  # the bad INSERT never reached the transport

    def test_the_writer_counts_rows_sent_and_a_replay_stores_one_row(self):
        backend = InMemorySecurityStore()
        store = SecurityEventStore(writer=backend, reader=backend)
        store.ensure_schema()
        self.assertEqual(store.write([row()]), 1)
        self.assertEqual(store.write([row()]), 1)
        self.assertEqual(store.count(), 1)
        self.assertEqual(len(backend.statements[2:]), 2)


class ReaderTests(unittest.TestCase):
    """The three named reads: what they ask, and what they refuse to make of a bad answer."""

    LIVE = ("(toDateTime(ts) + toIntervalDay(1825)) DELETE WHERE retention_tier = 'critical', "
            "(toDateTime(ts) + toIntervalDay(90)) DELETE WHERE retention_tier = 'routine'")
    METADATA = {'table_count': '1', 'create_table_query': schema.create_table_sql()}

    def test_the_ttl_read_names_the_owned_table_and_passes_only_its_bound_parameters(self):
        client = FakeStore({'system.tables': self.METADATA})
        reader = ClickHouseSecurityReader(client)
        self.assertEqual(parse_ttl_expression(reader.live_ttl_expression()), DEFAULT_POLICY)
        sql, parameters = client.calls[0]
        self.assertEqual(parameters, {'database': 'security_events', 'table': 'events'})
        self.assertIn('system.tables', sql)
        self.assertIn('any(create_table_query)', sql)
        self.assertIn('count()', sql)
        self.assertNotIn('ttl_expression', sql)
        self.assertNotIn('security_events.events', sql)

    def test_an_absent_ttl_is_empty_text_and_not_an_error(self):
        metadata = {'table_count': '1', 'create_table_query':
                    'CREATE TABLE security_events.events (ts DateTime) ENGINE = MergeTree ORDER BY ts'}
        reader = ClickHouseSecurityReader(FakeStore({'system.tables': metadata}))
        self.assertEqual(reader.live_ttl_expression(), '')

    def test_the_count_is_over_the_identity_pair_because_a_merge_has_not_necessarily_run(self):
        client = FakeStore({'uniqExact': '7'})
        self.assertEqual(ClickHouseSecurityReader(client).count(), 7)
        self.assertIn('uniqExact(source, event_id)', client.calls[0][0])

    def test_a_quoted_64_bit_number_is_read_as_a_number(self):
        reader = ClickHouseSecurityReader(FakeStore({'uniqExact': '12'}))
        self.assertEqual(reader.count(), 12)

    def test_a_wrong_shaped_or_unreachable_answer_is_one_error_type(self):
        for client in (FakeStore(fail=True), FakeStore({'uniqExact': 'seven'}),
                       FakeStore({'uniqExact': -1}), FakeStore({'uniqExact': {'nested': 1}})):
            with self.subTest(client=client):
                with self.assertRaises(SecurityStoreUnavailable):
                    ClickHouseSecurityReader(client).count()

    def test_expired_counts_against_the_shared_cutoff_arithmetic(self):
        backend = InMemorySecurityStore()
        store = SecurityEventStore(writer=backend, reader=backend)
        store.ensure_schema()
        old = '2019-01-01T00:00:00+00:00'
        store.write([row(event_id='oldroutine', severity='warning', ts=old, observed_at=old,
                         window_start='2018-12-31T23:59:00+00:00', window_end=old),
                     row(event_id='oldcritical', severity='critical', ts=old, observed_at=old,
                         window_start='2018-12-31T23:59:00+00:00', window_end=old)])
        now = dt.datetime(2026, 9, 9, tzinfo=dt.timezone.utc)
        verdict = store.verify_ttl(now=now)
        self.assertEqual(verdict.status, 'match')
        self.assertEqual(verdict.expired, 2)  # both are older than even the 90-day tier
        recent = store.verify_ttl(now=dt.datetime(2019, 1, 2, tzinfo=dt.timezone.utc))
        self.assertEqual(recent.expired, 0)

    def test_an_unreadable_expired_count_is_minus_one_and_not_zero(self):
        """Zero would say "nothing is due"; the truth is that the number could not be read."""
        class HalfBlind(ClickHouseSecurityReader):
            def expired(self, cutoff):
                raise SecurityStoreUnavailable('the expired count is unavailable')

        client = FakeStore({'system.tables': self.METADATA})
        store = SecurityEventStore(writer=InMemorySecurityStore(), reader=HalfBlind(client))
        verdict = store.verify_ttl()
        self.assertEqual(verdict.expired, -1)
        self.assertEqual(verdict.status, 'match')
        self.assertIn('as declared', verdict.as_dict()['detail'])

    def test_the_reads_are_three_named_statements_and_no_caller_text_reaches_them(self):
        sqls = [ClickHouseSecurityReader.TTL_SQL, ClickHouseSecurityReader.EVENTS_SQL,
                ClickHouseSecurityReader.EXPIRED_SQL]
        for sql in sqls:
            self.assertTrue(sql.endswith('FORMAT JSON'))
            self.assertNotIn('%s', sql)
        joined = ' '.join(sqls)
        for forbidden in ('DROP', 'ALTER', 'INSERT'):
            self.assertNotIn(forbidden, joined)


class WriterTests(unittest.TestCase):
    """The write transport: what it refuses to be pointed at, and what it refuses to say."""

    URL = 'https://clickhouse.internal:8443/'

    class Response:
        def __init__(self, body=b'Ok.\n'):
            self.body = body

        def read(self, limit):
            return self.body[:limit]

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class Opener:
        def __init__(self, response=None, error=None):
            self.response, self.error, self.requests = response or WriterTests.Response(), error, []

        def open(self, request, timeout=None):
            self.requests.append((request, timeout))
            if self.error is not None:
                raise self.error
            return self.response

    def patch(self, opener):
        """Route the transport's opener construction at *opener* and undo it on cleanup."""
        import urllib.request
        original = urllib.request.build_opener
        urllib.request.build_opener = lambda *a, **k: opener
        self.addCleanup(setattr, urllib.request, 'build_opener', original)
        return opener

    def test_a_plaintext_endpoint_is_refused_unless_the_operator_says_otherwise(self):
        with self.assertRaises(SecurityStoreRefused):
            ClickHouseSecurityWriter('http://clickhouse:8123', 'lo-security', 'secret')
        self.assertTrue(ClickHouseSecurityWriter('http://clickhouse:8123', 'lo-security', 'secret',
                                                 allow_http=True).url.endswith('8123'))

    def test_a_url_carrying_credentials_a_query_or_a_fragment_is_refused(self):
        for url in ('https://u:p@host/', 'https://host/?x=1', 'https://host/#f', 'host', 'https:///'):
            with self.subTest(url=url):
                with self.assertRaises(SecurityStoreRefused):
                    ClickHouseSecurityWriter(url, 'lo-security', 'secret')

    def test_an_empty_credential_or_an_unsafe_user_name_is_refused(self):
        with self.assertRaises(SecurityStoreRefused):
            ClickHouseSecurityWriter(self.URL, 'lo-security', '')
        with self.assertRaises(SecurityStoreRefused):
            ClickHouseSecurityWriter(self.URL, 'lo security; DROP', 'secret')

    def test_a_failing_write_reports_one_sentence_with_no_credential_and_no_payload(self):
        secret, payload = 'correct horse battery staple', "raw text with 'quotes' inside"
        opener = self.patch(WriterTests.Opener(error=OSError('connection refused')))
        with self.assertRaises(SecurityStoreUnavailable) as context:
            ClickHouseSecurityWriter(self.URL, 'lo-security', secret).execute(payload)
        self.assertNotIn(secret, str(context.exception))
        self.assertNotIn(payload, str(context.exception))
        self.assertEqual(len(opener.requests), 1)

    def test_the_statement_is_sent_as_the_body_with_the_user_pair_in_headers(self):
        opener = self.patch(WriterTests.Opener())
        writer = ClickHouseSecurityWriter(self.URL, 'lo-security', 'hunter2')
        self.assertEqual(writer.execute('SELECT 1'), 'Ok.\n')
        request, timeout = opener.requests[0]
        self.assertEqual(request.data, b'SELECT 1')
        self.assertEqual(request.get_header('X-clickhouse-user'), 'lo-security')
        self.assertEqual(request.get_header('X-clickhouse-key'), 'hunter2')
        self.assertEqual(timeout, 10)

    def test_an_oversized_acknowledgement_is_refused(self):
        self.patch(WriterTests.Opener(response=WriterTests.Response(b'x' * 8192)))
        with self.assertRaises(SecurityStoreUnavailable):
            ClickHouseSecurityWriter(self.URL, 'lo-security', 'hunter2').execute('SELECT 1')

    def test_an_empty_statement_is_refused_before_anything_is_opened(self):
        with self.assertRaises(SecurityStoreRefused):
            ClickHouseSecurityWriter(self.URL, 'lo-security', 'hunter2').execute('')


class StampTests(unittest.TestCase):
    """The one timestamp contract: a stamp means the same instant whatever the host's zone is."""

    def test_a_naive_stamp_means_utc_and_a_local_offset_is_converted(self):
        self.assertEqual(nanos('2026-09-09T12:00:00', 'ts'), nanos('2026-09-09T12:00:00+00:00', 'ts'))
        self.assertEqual(nanos('2026-09-09T12:00:00+00:00', 'ts'),
                         nanos('2026-09-09T13:00:00+01:00', 'ts'))

    def test_the_round_trip_through_nanoseconds_is_exact_to_the_microsecond(self):
        text = '2026-09-09T12:00:00.123456+00:00'
        self.assertEqual(epoch_text(nanos(text, 'ts')), text)

    def test_the_cutoff_is_one_instant_per_tier_and_uses_the_declared_days(self):
        now = dt.datetime(2026, 9, 9, tzinfo=dt.timezone.utc)
        found = cutoffs(DEFAULT_POLICY, now=now)
        self.assertEqual(set(found), {f'{tier}_cutoff_ns' for tier in (TIER_CRITICAL, TIER_ROUTINE)})
        self.assertEqual(nanos(epoch_text(found[f'{TIER_CRITICAL}_cutoff_ns']), 'x'),
                         nanos('2021-09-10T00:00:00+00:00', 'x'))

    def test_a_negative_or_non_integer_stored_stamp_is_refused(self):
        for value in (-1, 'x', None, True, 1.0):
            with self.subTest(value=value):
                with self.assertRaises(SecurityStoreRefused):
                    epoch_text(value)


class PostureTests(unittest.TestCase):
    """The package's own walls: no estate identity, no host path, no DDL beyond the owned schema."""

    def test_the_package_names_no_host_and_no_private_path(self):
        for name in sorted(p.name for p in PACKAGE.glob('*.py')):
            text = (PACKAGE / name).read_text(encoding='utf-8')
            with self.subTest(module=name):
                for forbidden in ('private-address-marker', 'storage-host', 'worker-host', 'example-site', 'openbao', 'deployment-config',
                                  'example-operator', '/srv/observe', 'notification-bot', 'admin-host'):
                    self.assertNotIn(forbidden, text)

    def test_the_store_ships_no_default_data_directory(self):
        """v0.1 defaulted this to one estate host's dataset path; a check with that default passes nowhere else."""
        backup = (PACKAGE / 'backup.py').read_text(encoding='utf-8')
        self.assertIn('LO_SECURITY_EVENTS_DATA_ROOT', backup)
        self.assertNotIn('clickhouse-data', backup)

    def test_the_writer_sends_no_query_string_settings_of_its_own(self):
        """The reader's bounds are the server profile's; a writer that restates them is a second policy."""
        text = (PACKAGE / 'store.py').read_text(encoding='utf-8')
        self.assertNotIn('urlencode', text, 'the write transport must not carry a settings query string')
        self.assertNotIn('max_memory_usage', text)

    def test_the_sensitive_columns_are_the_two_the_package_claims(self):
        self.assertEqual(schema.SENSITIVE_COLUMNS, {'principal', 'raw'})
        self.assertEqual(sensitive_in({'principal': 'someone', 'raw': '', 'event_id': 'x'}), {'principal'})

    def test_the_owned_table_is_not_one_of_the_three_signal_databases(self):
        """clickstack / hyperdx's boundary: this store is owned, so it is not inside anything SigNoz rewrites."""
        self.assertNotIn(schema.DATABASE, [f'signoz_{signal}' for signal in SIGNALS])
        self.assertTrue(schema.FQ_TABLE.startswith(schema.DATABASE + '.'))

    def test_no_shipped_credential_names_the_owned_database(self):
        """Task 2 stays a proposal: the grant is a reviewer decision, so a shipped fragment must not have it.

        `tests/test_query_adapter.py` (`AnalysisProfile`) already pins what `lo-query.xml` and
        `lo-read.xml` DO grant; this is the other side, stated for the store this package adds. It is
        deliberately over every fragment in the directory rather than over the two known users, because
        the way this becomes true by accident is someone adding a third file that quietly has the grant.
        """
        fragments = sorted(USERS_DIR.glob('*.xml'))
        self.assertTrue(fragments, 'the users.d directory vanished from under this test')
        for fragment in fragments:
            with self.subTest(fragment=fragment.name):
                self.assertNotIn(schema.DATABASE, fragment.read_text(encoding='utf-8'),
                                 f'{fragment.name} names the owned database: the security store grant was applied '
                                 f'without the reviewer decision its contract paragraph asks for')
        # The same claim one level up, where it would also silently become true: an example delta that
        # mounts a fragment carrying it.
        for delta in sorted((ROOT / 'components').rglob('*.compose.yaml')):
            with self.subTest(delta=str(delta.relative_to(ROOT))):
                self.assertNotIn(schema.DATABASE, delta.read_text(encoding='utf-8'))


class TempFileTests(unittest.TestCase):
    """The CLI's `print-schema` needs no credential, and its DDL is what the store applies."""

    def test_the_printed_schema_is_the_statement_the_store_sends(self):
        import io
        import contextlib
        from local_observe.security import cli
        buffer, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(errors):
            status = cli.main(['print-schema'])
        self.assertEqual(status, 0)
        self.assertEqual([block.strip() for block in buffer.getvalue().split('\n\n') if block.strip()],
                         [statement.strip() for statement in schema.ddl_statements()])
        self.assertIn('operator', errors.getvalue())

    def test_verify_backup_without_a_root_names_the_variable_and_exits_two(self):
        import io
        import contextlib
        from local_observe.security import cli
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            status = cli.main(['verify-backup'], environ={})
        self.assertEqual(status, 2)
        self.assertIn('LO_SECURITY_EVENTS_DATA_ROOT', buffer.getvalue())

    def test_verify_backup_reports_a_table_that_is_not_there(self):
        import io
        import contextlib
        from local_observe.security import cli, backup
        with tempfile.TemporaryDirectory() as directory:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = cli.main(['verify-backup'], environ={backup.ENV_DATA_ROOT: directory})
            self.assertEqual(status, 1)
            self.assertIn('never applied', buffer.getvalue())
            (Path(directory) / 'data' / 'security_events' / 'events').mkdir(parents=True)
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                status = cli.main(['verify-backup'], environ={backup.ENV_DATA_ROOT: directory})
            self.assertEqual(status, 0)
            self.assertIn('inside', buffer.getvalue())

    def test_a_named_data_root_that_does_not_exist_is_a_state_and_not_an_exception(self):
        from local_observe.security import backup
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / 'nope'
            self.addCleanup(lambda: missing.exists() and missing.rmdir())
            verdict = backup.coverage(missing)
            self.assertFalse(verdict.covered)
            self.assertEqual(verdict.state, 'missing')
            self.assertIn(str(missing), verdict.detail)


if __name__ == '__main__':
    unittest.main()

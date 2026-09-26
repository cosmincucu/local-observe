"""Offline harness checks; no ClickHouse server or runtime conformance is implied."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.http import TransportError
from local_observe.security.schema import create_table_sql
from local_observe.security.ttl import RetentionPolicy, build_ttl_clause

SPEC = importlib.util.spec_from_file_location('retention_conformance',
    Path(__file__).resolve().parents[1] / 'scripts/security_retention_conformance.py')
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
SECRET = 'sentinel-private-password-do-not-print'
FIXTURE = '909e5c73-0d69-4bfb-a30e-8b031f440ca0'


def ddl(case):
    statement = create_table_sql(RetentionPolicy(routine_days=91) if case == 'drift' else None)
    if case == 'no-ttl':
        statement = statement.replace(build_ttl_clause(), '')
    if case == 'extra-delete':
        statement = statement.replace('\nSETTINGS', ', toDateTime(ts) + toIntervalDay(1) DELETE\nSETTINGS')
    if case == 'unsupported-ttl':
        statement = statement.replace('INTERVAL 90 DAY', 'toIntervalMonth(1)')
    return statement


class Client:
    def __init__(self, case, config, user=probe.READER, *, failure=None, rows=0, hidden=False):
        self.case, self.config, self.user = case, config, user
        self.failure, self.rows, self.hidden = failure, rows, hidden
        self.calls = []

    def query(self, sql, parameters):
        self.calls.append((sql, parameters))
        if self.failure:
            raise self.failure
        if sql == probe.IDENTITY_SQL:
            return {'version': '25.12.5.44', 'user': self.user}
        if sql == probe.MARKER_SQL:
            return {'fixture_id': FIXTURE, 'case_name': self.case, 'image_digest': probe.IMAGE}
        denied = self.user == probe.DENIED
        if sql == probe.ClickHouseSecurityReader.TTL_SQL:
            if denied and not self.hidden:
                raise TransportError(SECRET)
            missing = self.case == 'absent' or denied
            return {'table_count': '0' if missing else '1',
                    'create_table_query': '' if missing else ddl(self.case)}
        if sql in (probe.ClickHouseSecurityReader.EXPIRED_SQL, probe.ClickHouseSecurityReader.EVENTS_SQL):
            if denied or self.case == 'absent':
                raise TransportError(SECRET)
            return {'row_count': self.rows}
        raise AssertionError('Unexpected SQL')


class ConformanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, value in (('reader', SECRET), ('denied', 'different-private-password')):
            path = self.root / name
            path.write_text(value)
            path.chmod(0o600)
        self.config = {'schema_version': 1, 'fixture_id': FIXTURE, 'url': 'http://127.0.0.1:18991',
                       'reader_password_file': str(self.root / 'reader'),
                       'denied_password_file': str(self.root / 'denied')}

    def test_real_server_canonical_delete_omission_for_every_fixture_case(self):
        original = ddl
        def canonical(case):
            # SHOW CREATE normalizes INTERVAL and omits the default DELETE action.
            import re
            text = re.sub(r'INTERVAL (\d+) DAY', r'toIntervalDay(\1)', original(case))
            return text.replace(' DELETE', '')
        with mock.patch(__name__ + '.ddl', side_effect=canonical):
            for case in probe.CASES:
                with self.subTest(case=case):
                    self.observe(case)

    def observe(self, case, **options):
        clients = []

        def factory(url, user, password, *, allow_http):
            self.assertEqual(url, self.config['url'])
            self.assertTrue(allow_http)
            if case == 'bad-credential' and password != SECRET:
                client = Client(case, self.config, user, failure=TransportError(password))
                clients.append(client)
                return client
            self.assertIn(password, (SECRET, 'different-private-password'))
            client = Client(case, self.config, user, **options)
            clients.append(client)
            return client
        result = probe.observe(self.config, case, client_factory=factory)
        self.assertTrue(all(sql.startswith('SELECT ') for client in clients for sql, _ in client.calls))
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertNotIn('create_table_query', result)
        self.assertEqual(len(result['source_sha256']), 5)
        return result

    def test_all_fixed_cases_use_real_reader_and_parser(self):
        for case, expected in probe.CASES.items():
            with self.subTest(case=case):
                result = self.observe(case)
                self.assertTrue(result['success'])
                self.assertEqual(result['status'], expected)
                self.assertEqual(result['metadata_table_count'], 0 if case == 'absent' else 1)
                self.assertEqual(result['declared_days'], {'critical': 1825, 'routine': 90})
                if case in ('match', 'drift'):
                    self.assertEqual(result['live_days'], {'critical': 1825, 'routine': 91 if case == 'drift' else 90})

    def test_probe_pin_matches_shipped_linux_amd64_lock(self):
        root = Path(__file__).resolve().parents[1]
        lock = json.loads((root / 'components/data/store-signoz/image-lock.json').read_text())
        entry = lock['images']['LO_CLICKHOUSE_IMAGE']
        self.assertEqual(entry['platform'], 'linux/amd64')
        self.assertEqual(entry['candidate'], 'clickhouse/clickhouse-server:25.12.5')
        self.assertEqual(entry['image'].split('@')[1], probe.IMAGE)

    def test_generated_invalid_password_differs_even_on_random_collision(self):
        seen = []

        def factory(url, user, password, **kwargs):
            seen.append(password)
            return Client('bad-credential', self.config, user,
                          failure=TransportError(SECRET) if password != SECRET else None)
        with mock.patch.object(probe.secrets, 'token_urlsafe', return_value=SECRET):
            result = probe.observe(self.config, 'bad-credential', client_factory=factory)
        self.assertEqual(seen, [SECRET, SECRET + 'x'])
        self.assertTrue(result['success'])
        self.assertNotIn(SECRET, json.dumps(result))

    def test_hidden_metadata_is_unknown_not_no_ttl(self):
        result = self.observe('permission', hidden=True)
        self.assertEqual(result['status'], 'unreadable')
        self.assertEqual(result['expired_rows'], -1)

    def test_nonempty_fixture_refuses_before_subject_verdict(self):
        with self.assertRaisesRegex(probe.Refused, 'fixture_not_empty'):
            self.observe('match', rows=1)

    def test_wrong_marker_stops_before_metadata(self):
        client = mock.Mock()
        client.query.side_effect = [{'version': '25.12.5.44', 'user': probe.READER}, {}]
        with self.assertRaisesRegex(probe.Refused, 'fixture_marker'):
            probe.observe(self.config, 'match', client_factory=lambda *a, **k: client)
        self.assertEqual(client.query.call_count, 2)

    def test_marker_case_or_identity_mismatch_is_setup_failure(self):
        for row in ({'fixture_id': FIXTURE, 'case_name': 'drift', 'image_digest': probe.IMAGE},
                    {'fixture_id': 'another', 'case_name': 'match', 'image_digest': probe.IMAGE}):
            client = Client('match', self.config)
            original = client.query
            with mock.patch.object(client, 'query', side_effect=lambda sql, params:
                                   row if sql == probe.MARKER_SQL else original(sql, params)):
                with self.assertRaisesRegex(probe.Refused, 'fixture_marker'):
                    probe.observe(self.config, 'match', client_factory=lambda *a, **k: client)

    def test_mismatching_ddl_is_not_a_successful_negative_case(self):
        client = Client('match', self.config)
        original = client.query
        with mock.patch.object(client, 'query', side_effect=lambda sql, params:
                               {'fixture_id': FIXTURE, 'case_name': 'extra-delete', 'image_digest': probe.IMAGE}
                               if sql == probe.MARKER_SQL else original(sql, params)):
            with self.assertRaisesRegex(probe.Refused, 'fixture_ttl_setup'):
                probe.observe(self.config, 'extra-delete', client_factory=lambda *a, **k: client)

    def test_extra_rule_does_not_hide_wrong_base_policy(self):
        original_ddl = ddl
        with mock.patch(__name__ + '.ddl', side_effect=lambda case:
                        original_ddl(case).replace('INTERVAL 1825 DAY', 'INTERVAL 1826 DAY')):
            with self.assertRaisesRegex(probe.Refused, 'fixture_extra_delete_setup'):
                self.observe('extra-delete')

    def test_invalid_cli_contract_never_constructs_client(self):
        config = self.root / 'invalid.json'
        config.write_text(json.dumps(dict(self.config, url='http://production:8123')))
        output = self.root / 'refused.json'
        with mock.patch.object(probe, 'observe') as observe, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(probe.main(['--contract', str(config), '--case', 'match',
                                         '--output', str(output)]), 1)
            observe.assert_not_called()
        self.assertFalse(json.loads(output.read_text())['success'])

    def test_marker_is_rechecked_after_subject_read(self):
        client = Client('match', self.config)
        original = client.query
        markers = 0

        def changed(sql, params):
            nonlocal markers
            result = original(sql, params)
            if sql == probe.MARKER_SQL:
                markers += 1
                if markers == 2:
                    result['case_name'] = 'no-ttl'
            return result
        with mock.patch.object(client, 'query', side_effect=changed):
            with self.assertRaises(probe.Refused):
                probe.observe(self.config, 'match', client_factory=lambda *a, **k: client)

    def test_wrong_release_or_admin_user_refused(self):
        for row in ({'version': '25.12.6.1', 'user': probe.READER},
                    {'version': '25.12.5.44', 'user': 'default'}):
            client = mock.Mock()
            client.query.return_value = row
            with self.assertRaisesRegex(probe.Refused, 'server_identity'):
                probe.observe(self.config, 'match', client_factory=lambda *a, **k: client)
            self.assertEqual(client.query.call_count, 1)

    def test_strict_contract_refuses_hostile_or_ambiguous_inputs(self):
        good = self.root / 'contract.json'
        good.write_text(json.dumps(self.config))
        self.assertEqual(probe.contract(good), self.config)
        variants = [dict(self.config, schema_version=True), dict(self.config, surprise=1),
                    dict(self.config, url='http://store.internal:8123'),
                    dict(self.config, url='http://127.0.0.1:18991/?password=secret'),
                    dict(self.config, url='https://127.0.0.1:18991'),
                    dict(self.config, reader_password_file='relative')]
        for value in variants:
            good.write_text(json.dumps(value))
            with self.assertRaises((ValueError, probe.Refused)):
                probe.contract(good)
        for text in ('{"a":1,"a":2}', 'x' * (probe.MAX_CONTRACT_BYTES + 1)):
            good.write_text(text)
            with self.assertRaises(probe.Refused):
                probe.contract(good)

    def test_cli_retains_only_sanitized_failure_and_no_success(self):
        config = self.root / 'contract.json'
        config.write_text(json.dumps(self.config))
        output = self.root / 'result.json'
        with mock.patch.object(probe, 'observe', side_effect=TransportError(SECRET)):
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(probe.main(['--contract', str(config), '--case', 'match',
                                             '--output', str(output)]), 1)
        result = json.loads(output.read_text())
        self.assertFalse(result['success'])
        self.assertEqual(result['failure'], 'configuration_or_read_failed')
        self.assertNotIn(SECRET, output.read_text() + stdout.getvalue())

    def test_existing_output_launches_nothing(self):
        output = self.root / 'existing'
        output.write_text('retained')
        with mock.patch.object(probe, 'observe') as observe:
            with self.assertRaises(FileExistsError):
                probe.main(['--contract', str(self.root / 'absent'), '--case', 'match', '--output', str(output)])
            observe.assert_not_called()
        self.assertEqual(output.read_text(), 'retained')

    def test_no_writer_cannot_be_used_to_provision_fixture(self):
        with self.assertRaisesRegex(probe.Refused, 'unexpected_write'):
            probe.NoWriter().execute('CREATE DATABASE anything')


if __name__ == '__main__':
    unittest.main()

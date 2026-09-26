"""Focused regressions for the staged fixture's narrow INSERT contract."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from local_observe.http import JsonClient, TransportError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sigma_fixture', ROOT / 'scripts/sigma_fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureTests(unittest.TestCase):
    def test_explicit_columns_match_the_insert_grant(self):
        row = {'timestamp': 1, 'id': 'fixture', 'body': 'label', 'resources_string': {}, 'attributes_string': {}}
        query, data = fixture.insert_query(row).split('\n', 1)
        self.assertEqual(query, 'INSERT INTO signoz_logs.logs_v2 (timestamp, id, body, resources_string, attributes_string) FORMAT JSONEachRow')
        self.assertEqual(json.loads(data), row)

    def test_unreviewed_columns_are_refused(self):
        row = {'timestamp': 1, 'id': 'fixture', 'body': 'label', 'resources_string': {}, 'attributes_string': {}, 'trace_id': 'unexpected'}
        with self.assertRaises(ValueError):
            fixture.insert_query(row)


class ScopedTrustTests(unittest.TestCase):
    def test_custom_trust_is_explicit_and_https_only(self):
        with self.assertRaises(TransportError):
            JsonClient('http://fixture', 'x' * 32, allow_http=True, ca_file='fixture.pem')

    def test_certificate_file_only_configures_this_client(self):
        with patch('local_observe.http.ssl.create_default_context') as context:
            JsonClient('https://fixture', 'x' * 32, ca_file='fixture.pem')
            context.assert_called_once_with(cafile='fixture.pem')
            JsonClient('https://another-fixture', 'x' * 32)
            context.assert_called_once()


if __name__ == '__main__':
    unittest.main()

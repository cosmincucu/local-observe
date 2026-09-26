"""Independent witness health survives changes in platform storage schema."""
from pathlib import Path
import tempfile
import unittest

from local_observe.platform.deadman import platform_healthy
from local_observe.platform.state import Store, VERSION


class PlatformHealthTests(unittest.TestCase):
    def test_actual_current_store_status_is_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            body = Store(Path(directory) / 'platform.db').status()
            self.assertEqual(body['schema_version'], VERSION)
            self.assertTrue(platform_healthy(200, body))

    def test_legacy_and_future_storage_versions_remain_healthy(self):
        self.assertTrue(platform_healthy(200, {'schema_version': 1}))
        self.assertTrue(platform_healthy(200, {'schema_version': VERSION + 1}))

    def test_missing_and_malformed_schema_are_not_healthy(self):
        for body in (None, [], [{'schema_version': 1}], 'text', {},
                     {'schema_version': True}, {'schema_version': False},
                     {'schema_version': 0}, {'schema_version': -1},
                     {'schema_version': '9'}, {'schema_version': 9.0}):
            with self.subTest(body=body):
                self.assertFalse(platform_healthy(200, body))

    def test_non_success_response_never_reports_healthy(self):
        for code in (201, 204, 301, 401, 403, 404, 500):
            self.assertFalse(platform_healthy(code, {'schema_version': VERSION}))

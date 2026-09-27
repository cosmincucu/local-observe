"""Public setup entrypoints retain explicit configuration and remote role authority."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_observe.deployment.guided_cli import main
from local_observe.deployment.setup_service import configured_services


class GuidedEntrypointTests(unittest.TestCase):
    def test_optional_services_do_not_touch_state_when_unselected(self):
        self.assertEqual(configured_services(None, None, {}), (None, None))

    def test_partial_or_blank_selection_is_refused(self):
        for values in ({'LO_GUIDED_SETUP_ROOT': '/configured'}, {'LO_GUIDED_SETUP_RUNNER': 'runner'},
                       {'LO_GUIDED_SETUP_ROOT': '', 'LO_GUIDED_SETUP_RUNNER': 'runner'},
                       {'LO_TRUSTED_RUNNERS_FILE': ''}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                configured_services(None, None, values)

    def test_runner_config_unknown_version_and_duplicate_keys_fail_before_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'runners.json'
            for raw in ('{"schema_version":true,"runners":{}}',
                        '{"schema_version":1,"schema_version":1,"runners":{}}',
                        '{"schema_version":2,"runners":{}}'):
                path.write_text(raw, encoding='utf-8')
                with self.assertRaises(ValueError):
                    configured_services(None, None, {'LO_TRUSTED_RUNNERS_FILE': str(path)})

    def test_human_decision_is_one_authenticated_request_and_never_a_retry(self):
        with patch('local_observe.deployment.guided_cli.read_credential', return_value='x' * 32), \
                patch('local_observe.deployment.guided_cli.JsonClient') as client, \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            client.return_value.request.return_value = (200, {'plan_id': 'a' * 64, 'status': 'approved'})
            result = main(['--url', 'https://platform.example.test', '--token-file', '/run/secrets/human',
                           'decision', 'a' * 64, '--decision', 'approved', '--expires-at', '2026-01-01T12:00:00Z'])
        self.assertEqual(result, 0)
        client.return_value.request.assert_called_once_with('POST', '/v1/setup/decision', {
            'plan_id': 'a' * 64, 'decision': 'approved', 'expires_at': '2026-01-01T12:00:00Z'})
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'approved')
        self.assertNotIn('x' * 32, stdout.getvalue())

    def test_refusal_and_unexpected_capability_are_never_printed_as_success(self):
        for response in ((403, None), (200, {'runner_token': 'synthetic-secret-canary'})):
            with patch('local_observe.deployment.guided_cli.read_credential', return_value='x' * 32), \
                    patch('local_observe.deployment.guided_cli.JsonClient') as client, \
                    contextlib.redirect_stdout(io.StringIO()) as stdout, \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                client.return_value.request.return_value = response
                result = main(['--url', 'https://platform.example.test', '--token-file', '/run/secrets/proposer',
                               'apply', 'b' * 64])
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertNotIn('synthetic-secret-canary', stderr.getvalue())
            self.assertEqual(client.return_value.request.call_count, 1)

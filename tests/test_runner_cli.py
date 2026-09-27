"""Trusted command acceptance through a real authenticated platform and synthetic engine."""
from contextlib import nullcontext, redirect_stderr, redirect_stdout
import io
import json
import os
import stat
import unittest
from unittest.mock import patch

from local_observe.http import TransportError
from local_observe.inventory.validation import digest
from local_observe.platform import runner_cli
from local_observe.platform.runner_handoff import RunnerHandoff
from local_observe.platform.state import Store
from test_action_invariants import FakeDagu, reviewed_binding
from test_platform_tools import ApiBridge, HOST, HUMAN_TOKEN, Platform
from test_runner_handoff import configured, RUNNER_TOKEN


class Engine(FakeDagu):
    def __init__(self, dag, **kwargs):
        super().__init__(**kwargs)
        self.dag = dag

    def request(self, method, path, payload=None):
        code, result = super().request(method, path, payload)
        if 'dagRunDetails' in result:
            result['dagRunDetails']['name'] = self.dag
        return code, result


@unittest.skipUnless(os.name == 'posix', 'trusted runner requires POSIX protected storage')
class RunnerCommandTests(unittest.TestCase):
    def setUp(self):
        self.platform = Platform()
        self.addCleanup(self.platform.close)
        self.platform.store.path.chmod(0o600)
        self.root = self.platform.store.path.parent
        self.journals = self.root / 'journals'
        self.journals.mkdir(mode=0o700)
        self.specs = self.root / 'dags'
        self.specs.mkdir(mode=0o700)
        self.binding = reviewed_binding([HOST])
        self.binding['dag'] += '-' + self.binding['sha256'][:16]
        (self.specs / (self.binding['dag'] + '.yaml')).write_text('fixture', encoding='utf-8')
        self.handoff = RunnerHandoff(self.platform.store, self.platform.policy,
                                     {'trusted-runner': [self.binding]})
        self.client = configured(self.platform, handoff=self.handoff)
        self.engine = Engine(self.binding['dag'], result='succeeded')
        self.engine_token = 'synthetic-engine-independent-credential-0001'
        self.platform_file = self.write_private('platform-token', RUNNER_TOKEN)
        self.engine_file = self.write_private('engine-token', self.engine_token)
        self.config = {'schema_version': 1, 'identity': 'trusted-runner',
                       'platform': {'url': 'https://platform.example.test',
                                    'credential_file': str(self.platform_file)},
                       'engine': {'url': 'https://engine.example.test',
                                  'credential_file': str(self.engine_file), 'scheme': 'Basic'},
                       'journal_root': str(self.journals), 'immutable_dag_root': str(self.specs),
                       'bindings': [self.binding], 'poll_seconds': 1, 'timeout_seconds': 2}
        self.config_file = self.write_private('runner.json', json.dumps(self.config))

    def write_private(self, name, value):
        path = self.root / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(value)
        return path

    def queued(self):
        action = self.platform.proposal(retry_key=self.platform.next_key())['action_id']
        human = ApiBridge(self.platform.app, HUMAN_TOKEN)
        code, review = human.request('GET', '/v1/actions/review?action_id=' + action)
        self.assertEqual(code, 200)
        self.assertEqual(human.request('POST', '/v1/actions/decision', {'action_id': action,
                         'decision': 'approved', 'binding_sha256': review['binding_sha256']})[0], 200)
        self.assertEqual(self.platform.bridge('executor').request('POST', '/v1/actions/execute',
                                                                 {'action_id': action})[0], 200)
        return action

    def command(self, *, client=None, argv=(), immutable=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        # Queue/journal tests use a deterministic in-memory engine. Deployment must
        # independently prove the read-only source mapping; a real writable mount is
        # refused separately below, without replacing that safety check.
        with patch.object(runner_cli, 'JsonClient', side_effect=[client or self.client, self.engine]) as factory, \
                patch.object(runner_cli, 'immutable_dag', return_value=nullcontext()) if immutable else nullcontext(), \
                patch('local_observe.platform.runner_handoff.immutable_dag', return_value=nullcontext()) \
                    if immutable else nullcontext(), redirect_stdout(stdout), redirect_stderr(stderr):
            status = runner_cli.main(['--config', str(self.config_file), *argv])
        for secret in (RUNNER_TOKEN, self.engine_token):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        return status, stdout.getvalue(), stderr.getvalue(), factory

    def test_once_uses_separate_credentials_and_exact_binding_then_repeats_without_dispatch(self):
        action = self.queued()
        code, output, errors, factory = self.command()
        self.assertEqual((code, errors), (0, ''))
        result = json.loads(output)
        self.assertEqual(result['results'][0]['action_id'], action)
        self.assertEqual(result['results'][0]['status'], 'succeeded')
        self.assertEqual(factory.call_args_list[0].args, ('https://platform.example.test', RUNNER_TOKEN))
        self.assertEqual(factory.call_args_list[1].args, ('https://engine.example.test', self.engine_token))
        self.assertEqual(factory.call_args_list[1].kwargs, {'timeout': 2, 'scheme': 'Basic'})
        self.assertEqual(self.command()[0], 0)
        self.assertEqual(self.engine.starts, 1)
        for journal in self.journals.glob('*.json'):
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)

    def test_unconfigured_route_identity_mismatch_and_malformed_queue_do_not_dispatch(self):
        self.queued()
        original = self.client.request
        fixtures = [('identity', (200, {'identity': 'another-runner', 'role': 'executor'})),
                    ('identity', (200, {'identity': 'trusted-runner', 'role': 'human'})),
                    ('queue', (404, None)), ('queue', (200, {'requests': [None]})),
                    ('queue', (200, {'requests': [], 'runner_token': self.engine_token})),
                    ('queue', (200, {'requests': [{'action_id': HOST, 'binding_sha256': '0' * 64}]})),
                    ('queue', (200, {'requests': [{}] * 21}))]
        for kind, response in fixtures:
            with self.subTest(kind=kind, response=response):
                def read(method, route, body=None):
                    if route == ('/v1/me' if kind == 'identity' else '/v1/runner/requests'):
                        return response
                    return original(method, route, body)
                with patch.object(self.client, 'request', side_effect=read):
                    self.assertEqual(self.command()[0], 2)
        self.assertEqual(self.engine.starts, 0)
        self.assertEqual(self.platform.executions(), [])

    def test_entire_queue_validated_before_first_dispatch(self):
        action = self.queued()
        original = self.client.request
        def read(method, route, body=None):
            if route == '/v1/runner/requests':
                return 200, {'requests': [{'action_id': action, 'binding_sha256': digest(self.binding)},
                                         {'action_id': action, 'binding_sha256': digest(self.binding)}]}
            return original(method, route, body)
        with patch.object(self.client, 'request', side_effect=read):
            code, _, error, _ = self.command()
        self.assertEqual(code, 2)
        self.assertIn('duplicate_queued_action', error)
        self.assertEqual(self.engine.starts, 0)

    def test_writable_spec_mount_refuses_before_credentials_or_network(self):
        self.queued()
        code, _, error, factory = self.command(immutable=False)
        self.assertEqual(code, 2)
        self.assertIn('immutable_dag_unavailable', error)
        factory.assert_not_called()
        self.assertEqual(self.platform.executions(), [])

    def test_one_process_lock_prevents_second_command(self):
        with runner_cli.ownership(self.config):
            code, _, error, factory = self.command()
        self.assertEqual(code, 2)
        self.assertIn('runner_storage_unavailable_or_busy', error)
        factory.assert_not_called()

    def test_poll_keeps_process_lock_and_stops_cleanly_on_interrupt(self):
        self.queued()
        def stop(_):
            with self.assertRaises(runner_cli.RunnerError), runner_cli.ownership(self.config):
                pass
            raise KeyboardInterrupt
        with patch.object(runner_cli.time, 'sleep', side_effect=stop):
            code, output, _, _ = self.command(argv=('--poll',))
        self.assertEqual(code, 130)
        self.assertEqual(json.loads(output)['results'][0]['status'], 'succeeded')
        with runner_cli.ownership(self.config):
            pass

    def test_lost_claim_response_restarts_with_same_capability_and_no_dispatch(self):
        action = self.queued()
        original = self.client.request
        def lost(method, route, body=None):
            answer = original(method, route, body)
            if route == '/v1/runner/claim':
                raise TransportError('synthetic-engine-independent-credential-0001')
            return answer
        with patch.object(self.client, 'request', side_effect=lost):
            self.assertEqual(self.command()[0], 2)
        intent = self.journals / (action + '.intent.json')
        before = intent.read_bytes()
        self.platform.store = Store(self.platform.store.path)
        self.platform.store.recover_executions()
        self.handoff = RunnerHandoff(self.platform.store, self.platform.policy, {'trusted-runner': [self.binding]})
        self.client = configured(self.platform, handoff=self.handoff)
        code, output, _, _ = self.command()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)['results'][0]['status'], 'unknown')
        self.assertEqual(intent.read_bytes(), before)
        self.assertEqual(self.engine.starts, 0)
        self.assertEqual(len(self.platform.executions()), 1)
        self.assertNotIn(json.loads(before)['token'], output)

    def test_crash_after_start_is_observed_on_restart_without_redispatch(self):
        self.queued()
        original = self.engine.request
        def crash(method, route, body=None):
            answer = original(method, route, body)
            if route.endswith('/start'):
                raise KeyboardInterrupt
            return answer
        with patch.object(self.engine, 'request', side_effect=crash):
            self.assertEqual(self.command()[0], 130)
        self.assertEqual(self.command()[0], 0)
        self.assertEqual(self.engine.starts, 1)

    def test_lost_start_and_outcome_acknowledgements_never_repeat_start(self):
        self.queued()
        self.engine.lost_ack = True
        original = self.client.request
        def lost(method, route, body=None):
            answer = original(method, route, body)
            if route == '/v1/executions/outcome':
                raise TransportError('synthetic lost response')
            return answer
        with patch.object(self.client, 'request', side_effect=lost):
            self.assertEqual(self.command()[0], 2)
        self.assertEqual(self.command()[0], 0)
        self.assertEqual(self.engine.starts, 1)
        self.assertEqual(self.platform.executions()[0]['status'], 'succeeded')

    def test_unknown_and_failed_results_stop_polling_for_reconciliation(self):
        self.queued()
        self.engine.result = 'unexpected'
        with patch.object(runner_cli.time, 'sleep') as sleep:
            code, output, _, _ = self.command(argv=('--poll',))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)['status'], 'attention')
        sleep.assert_not_called()

    def test_strict_config_duplicate_keys_nested_shapes_and_bounds(self):
        for changes in ({'schema_version': True}, {'identity': []}, {'bindings': [None]},
                        {'timeout_seconds': 21}, {'poll_seconds': 0}, {'journal_root': '../escape'},
                        {'engine': {'url': 'http://engine.example.test', 'credential_file': str(self.engine_file)}},
                        {'platform': {**self.config['platform'], 'token': 'inline-token'}}, {'hook': 'execute'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner_cli.configuration({**self.config, **changes})
        self.config_file.write_text('{"schema_version":1,"schema_version":1}', encoding='utf-8')
        self.assertEqual(self.command()[0], 2)

    def test_credentials_are_private_regular_independent_and_have_no_environment_fallback(self):
        self.engine_file.write_text(RUNNER_TOKEN, encoding='utf-8')
        self.assertEqual(self.command()[0], 2)
        self.engine_file.write_text(self.engine_token, encoding='utf-8')
        self.engine_file.chmod(0o644)
        self.assertEqual(self.command()[0], 2)
        self.engine_file.chmod(0o400)
        self.assertEqual(self.command()[0], 0)
        self.engine_file.unlink()
        with patch.dict(os.environ, {'LO_RUNNER_ENGINE_TOKEN': self.engine_token}):
            self.assertEqual(self.command()[0], 2)
        self.engine_file.symlink_to(self.platform_file)
        self.assertEqual(self.command()[0], 2)
        self.engine_file.unlink()
        os.mkfifo(self.engine_file, 0o600)
        self.assertEqual(self.command()[0], 2)

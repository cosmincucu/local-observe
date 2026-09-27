"""Real authenticated API, SQLite restart and journal recovery acceptance."""
import concurrent.futures
from contextlib import nullcontext
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_observe.http import TransportError
from local_observe.inventory.validation import digest
from local_observe.platform import state, tools
from local_observe.platform.api import create_app
from local_observe.platform.runner_handoff import RunnerHandoff, run_request
from local_observe.platform.state import Actor, StateError, Store
from test_action_invariants import FakeDagu, reviewed_binding
from test_platform_tools import ApiBridge, HOST, HUMAN_TOKEN, Platform

RUNNER_TOKEN = 'independent-trusted-runner-credential-0001'


def configured(platform, *, handoff=None, setup=None):
    credentials = [{'identity': 'agent-' + {'reader': 'read', 'proposer': 'ask', 'executor': 'run'}[role],
                    'role': role, 'token': token} for role, token in platform.tokens.items()]
    credentials += [{'identity': 'operator', 'role': 'human', 'token': HUMAN_TOKEN},
                    {'identity': 'trusted-runner', 'role': 'executor', 'token': RUNNER_TOKEN}]
    platform.app = create_app(platform.store, credentials, platform.policy, runner_handoff=handoff,
                              guided_setup=setup)
    return ApiBridge(platform.app, RUNNER_TOKEN)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.platform = Platform()
        self.platform.store.path.chmod(0o600)
        self.addCleanup(self.platform.close)
        self.binding = reviewed_binding([HOST])
        self.handoff = RunnerHandoff(self.platform.store, self.platform.policy,
                                     {'trusted-runner': [self.binding]})
        self.runner = configured(self.platform, handoff=self.handoff)
        self.journals = self.platform.store.path.parent / 'journals'
        self.journals.mkdir(mode=0o700)
        # These tests prove queue/journal behavior using a deterministic in-memory
        # engine. Real immutable-mount deployment acceptance is a separate gate.
        self.mount_guard = patch('local_observe.platform.runner_handoff.immutable_dag', return_value=nullcontext())
        self.mount_guard.start()
        self.addCleanup(self.mount_guard.stop)

    def approved(self):
        action = self.platform.proposal(retry_key=self.platform.next_key())['action_id']
        self.assertEqual(self.approve(action)[0], 200)
        return action

    def approve(self, action):
        human = ApiBridge(self.platform.app, HUMAN_TOKEN)
        code, review = human.request('GET', '/v1/actions/review?action_id=' + action)
        self.assertEqual(code, 200)
        return human.request('POST', '/v1/actions/decision', {'action_id': action, 'decision': 'approved',
                                                            'binding_sha256': review['binding_sha256']})

    def queued(self):
        action = self.platform.proposal(retry_key=self.platform.next_key())['action_id']
        self.assertEqual(self.approve(action), (200, {'status': 'approved'}))
        result = self.platform.registry().invoke('execute_action', self.platform.agent('executor'),
                                                 {'action_id': action})
        self.assertTrue(result.data['queued'])
        self.assertNotIn('runner_token', json.dumps(result.data))
        code, body = self.runner.request('GET', '/v1/runner/requests')
        self.assertEqual(code, 200)
        return next(item for item in body['requests'] if item['action_id'] == action)

    def test_human_approval_agent_queue_separate_runner_and_restart(self):
        request = self.queued()
        engine = FakeDagu(lost_ack=True)
        self.assertEqual(run_request(self.runner, engine, request, self.binding, self.journals)['status'], 'executing')
        self.platform.store = Store(self.platform.store.path)
        self.platform.store.recover_executions()
        handoff = RunnerHandoff(self.platform.store, self.platform.policy, {'trusted-runner': [self.binding]})
        runner = configured(self.platform, handoff=handoff)
        engine.result = 'succeeded'
        result = run_request(runner, engine, request, self.binding, self.journals)
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(run_request(runner, engine, request, self.binding, self.journals), result)
        self.assertEqual(engine.starts, 1)
        self.assertEqual(self.platform.executions()[0]['runner'], 'trusted-runner')
        requested = self.platform.operations('runner.requested')[0]
        self.assertEqual(requested['actor'], 'agent-run')
        detail = json.loads(requested['detail'])
        self.assertEqual((detail['approver'], detail['runner'], detail['targets']),
                         ('operator', 'trusted-runner', [HOST]))
        token = json.loads(next(self.journals.glob('*.intent.json')).read_text(encoding='utf-8'))['token']
        self.assertNotIn(token, json.dumps(self.platform.store.records('audit')))
        self.assertNotIn(token, json.dumps(self.platform.executions()))

    def test_roles_arbitrary_ids_and_nested_payloads_cannot_escalate(self):
        action = self.platform.proposal()['action_id']
        for role in ('reader', 'proposer', 'executor'):
            client = self.platform.bridge(role)
            self.assertEqual(client.request('POST', '/v1/actions/decision',
                                            {'action_id': action, 'decision': 'approved'})[0], 400)
            self.assertEqual(client.request('POST', '/v1/actions/claim', {'action_id': action})[0], 400)
            self.assertEqual(client.request('GET', '/v1/runner/requests')[0], 400)
            self.assertEqual(client.request('POST', '/v1/runner/claim', {'action_id': action,
                             'binding_sha256': digest(self.binding), 'runner_token': 'a' * 43})[0], 400)
        for invalid in (HOST, {'id': action}, [action], '../../runner'):
            self.assertEqual(self.platform.bridge('executor').request('POST', '/v1/actions/execute',
                                                                     {'action_id': invalid})[0], 400)
        self.assertEqual(self.platform.executions(), [])

    def test_pending_denied_expired_and_unsupported_actions_never_start(self):
        action = self.platform.proposal()['action_id']
        client = self.platform.bridge('executor')
        self.assertEqual(client.request('POST', '/v1/actions/execute', {'action_id': action})[0], 400)
        self.platform.call('POST', '/v1/actions/decision', {'action_id': action, 'decision': 'denied'}, HUMAN_TOKEN)
        self.assertEqual(client.request('POST', '/v1/actions/execute', {'action_id': action})[0], 400)
        expired = self.platform.approved(expires_claim=True)
        self.assertEqual(client.request('POST', '/v1/actions/execute', {'action_id': expired})[0], 400)
        action = self.approved()
        self.handoff.runners['trusted-runner'][0]['action'] = 'unsupported'
        self.assertEqual(client.request('POST', '/v1/actions/execute', {'action_id': action})[0], 400)
        self.assertEqual(self.platform.executions(), [])

    def test_withdrawal_expiry_policy_and_binding_drift_rechecked_at_claim(self):
        for reason in ('withdrawn', 'expired', 'policy', 'binding', 'spec'):
            with self.subTest(reason=reason):
                request = self.queued()
                engine = FakeDagu()
                if reason == 'withdrawn':
                    self.assertEqual(self.platform.call('POST', '/v1/actions/decision',
                        {'action_id': request['action_id'], 'decision': 'denied'}, HUMAN_TOKEN)[0], 200)
                if reason == 'binding':
                    self.handoff.runners['trusted-runner'][0]['sha256'] = '0' * 64
                if reason == 'spec':
                    engine.spec = 'changed'
                with patch('local_observe.platform.runner_handoff.clock', return_value=
                           dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)) if reason == 'expired' else \
                        patch.object(self.handoff, 'policy', side_effect=StateError('Policy refused')) if reason == 'policy' else \
                        patch('local_observe.platform.runner_handoff.label', wraps=state.label):
                    with self.assertRaises((ValueError, TransportError)):
                        run_request(self.runner, engine, request, self.binding, self.journals)
                self.assertEqual(engine.starts, 0)
                self.handoff.runners['trusted-runner'][0] = dict(self.binding)

    def test_concurrent_enqueue_is_one_durable_request(self):
        action = self.approved()
        def enqueue(_):
            return self.handoff.enqueue(action, Actor('agent-run', 'executor'))
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            answers = list(pool.map(enqueue, range(2)))
        self.assertEqual(answers[0], answers[1])
        self.assertEqual(len(self.platform.operations('runner.requested')), 1)

    def test_lost_claim_reply_recovers_without_dispatch(self):
        request = self.queued()
        engine = FakeDagu()
        original = self.runner.request
        def lost(method, path, payload=None):
            result = original(method, path, payload)
            if path == '/v1/runner/claim':
                raise TransportError('Lost response after durable claim')
            return result
        with patch.object(self.runner, 'request', side_effect=lost), self.assertRaises(TransportError):
            run_request(self.runner, engine, request, self.binding, self.journals)
        result = run_request(self.runner, engine, request, self.binding, self.journals)
        self.assertEqual(result['status'], 'unknown')
        self.assertEqual(engine.starts, 0)
        self.assertEqual(len(self.platform.executions()), 1)

    def test_crash_before_claim_can_retry_but_after_claim_cannot_dispatch(self):
        request = self.queued()
        engine = FakeDagu(result='succeeded')
        with patch.object(self.runner, 'request', side_effect=TransportError('Before claim')):
            with self.assertRaises(TransportError):
                run_request(self.runner, engine, request, self.binding, self.journals)
        self.assertEqual(self.platform.executions(), [])
        self.assertEqual(run_request(self.runner, engine, request, self.binding, self.journals)['status'], 'succeeded')
        self.assertEqual(engine.starts, 1)
        request = self.queued()
        engine = FakeDagu()
        with patch('local_observe.platform.dagu.save', side_effect=OSError('Crash after claim')):
            with self.assertRaises(OSError):
                run_request(self.runner, engine, request, self.binding, self.journals)
        self.assertEqual(run_request(self.runner, engine, request, self.binding, self.journals)['status'], 'unknown')
        self.assertEqual(engine.starts, 0)

    def test_concurrent_claim_requires_same_journaled_token(self):
        request = self.queued()
        actor = Actor('trusted-runner', 'executor')
        def claim(token):
            try:
                return self.handoff.claim(request['action_id'], request['binding_sha256'], token, actor)['status']
            except StateError:
                return 'refused'
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            answers = list(pool.map(claim, ('a' * 43, 'b' * 43)))
        self.assertEqual(sorted(answers), ['executing', 'refused'])
        self.assertEqual(len(self.platform.executions()), 1)

    def test_current_schema_upgrade_requires_explicit_migration_and_retains_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'old.db'
            with patch.object(state, 'VERSION', 9), patch.object(state, 'MIGRATIONS',
                       {key: value for key, value in state.MIGRATIONS.items() if key <= 9}):
                old = Store(path)
                with old.transaction() as db:
                    old.audit(db, dt.datetime.now(dt.timezone.utc), 'fixture', 'fixture.kept', 'fixture')
            with self.assertRaisesRegex(StateError, 'migrate'):
                Store(path)
            updated = Store(path, migrate=True)
            self.assertTrue(updated.migration_backup.is_file())
            self.assertTrue(any(row['operation'] == 'fixture.kept' for row in updated.records('audit')))
            with Store(path).transaction() as db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 10)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM runner_requests').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM setup_plans').fetchone()[0], 0)

    def test_binding_change_after_human_approval_before_enqueue_is_refused(self):
        action = self.approved()
        self.handoff.runners['trusted-runner'][0]['sha256'] = '0' * 64
        self.assertEqual(self.platform.bridge('executor').request('POST', '/v1/actions/execute',
                                                                 {'action_id': action})[0], 400)
        self.assertEqual(self.platform.executions(), [])

    def test_missing_or_writable_immutable_mount_fails_before_claim(self):
        self.mount_guard.stop()
        request = self.queued()
        engine = FakeDagu()
        with self.assertRaisesRegex(StateError, 'immutable'):
            run_request(self.runner, engine, request, self.binding, self.journals)
        from local_observe.platform.runner_handoff import immutable_dag
        binding = {**self.binding, 'dag': 'inspect-' + self.binding['sha256'][:16]}
        (self.journals / (binding['dag'] + '.yaml')).write_text('fixture', encoding='utf-8')
        with self.assertRaisesRegex(StateError, 'read-only'), immutable_dag(self.journals, binding):
            pass
        self.assertEqual(engine.starts, 0)
        self.assertEqual(self.platform.executions(), [])

    def test_token_journals_created_private_with_permissive_umask(self):
        request = self.queued()
        old = os.umask(0o022)
        try:
            run_request(self.runner, FakeDagu(result='succeeded'), request, self.binding, self.journals)
        finally:
            os.umask(old)
        for path in self.journals.glob('*.json'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_journal_symlink_and_temporary_symlink_do_not_touch_sentinel(self):
        request = self.queued()
        sentinel = self.journals.parent / 'sentinel'
        sentinel.write_bytes(b'untouched')
        temporary = self.journals / (request['action_id'] + '.tmp')
        temporary.symlink_to(sentinel)
        with self.assertRaises(StateError):
            run_request(self.runner, FakeDagu(), request, self.binding, self.journals)
        self.assertEqual(sentinel.read_bytes(), b'untouched')
        self.assertEqual(self.platform.executions(), [])

    def test_reviewed_digest_cannot_approve_a_rebound_action(self):
        action = self.platform.proposal()['action_id']
        human = ApiBridge(self.platform.app, HUMAN_TOKEN)
        _, review = human.request('GET', '/v1/actions/review?action_id=' + action)
        self.handoff.runners['trusted-runner'][0]['sha256'] = '0' * 64
        code, _ = human.request('POST', '/v1/actions/decision', {'action_id': action, 'decision': 'approved',
                                                               'binding_sha256': review['binding_sha256']})
        self.assertEqual(code, 400)
        self.assertEqual(self.platform.action_row(action)['status'], 'pending')

    def test_crash_after_dispatch_intent_observes_without_start(self):
        request = self.queued()
        from local_observe.platform import dagu
        original = dagu.save
        def crash(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError('Crash after intent journal is durable')
        engine = FakeDagu()
        with patch.object(dagu, 'save', side_effect=crash), self.assertRaises(OSError):
            run_request(self.runner, engine, request, self.binding, self.journals)
        self.assertEqual(run_request(self.runner, engine, request, self.binding, self.journals)['status'], 'unknown')
        self.assertEqual(engine.starts, 0)

    def test_crash_after_external_start_and_lost_outcome_response_never_repeat_start(self):
        request = self.queued()
        engine = FakeDagu(result='succeeded')
        original = engine.request
        def crash(method, path, payload=None):
            result = original(method, path, payload)
            if path.endswith('/start'):
                raise KeyboardInterrupt
            return result
        with patch.object(engine, 'request', side_effect=crash), self.assertRaises(KeyboardInterrupt):
            run_request(self.runner, engine, request, self.binding, self.journals)
        original_platform = self.runner.request
        def lost(method, path, payload=None):
            result = original_platform(method, path, payload)
            if path == '/v1/executions/outcome':
                raise TransportError('Outcome response lost after commit')
            return result
        with patch.object(self.runner, 'request', side_effect=lost), self.assertRaises(TransportError):
            run_request(self.runner, engine, request, self.binding, self.journals)
        self.assertEqual(run_request(self.runner, engine, request, self.binding, self.journals)['status'], 'succeeded')
        self.assertEqual(engine.starts, 1)

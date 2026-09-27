"""Approval, filesystem drift and recovery through the authenticated setup API."""
import asyncio
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch

import httpx

from local_observe.ai import capability, policy
from local_observe.deployment import guided, guided_files
from local_observe.platform.state import Actor, StateError, Store
from test_platform_tools import ApiBridge, HOST, HUMAN_TOKEN, Platform
from test_runner_handoff import configured

# Optional read-only package overlay for independently developed observer integration.
# This is test-process configuration, never a production import or setup profile field.
if os.environ.get('LO_TEST_OBSERVER_PACKAGE'):
    import local_observe
    package = Path(os.environ['LO_TEST_OBSERVER_PACKAGE']).resolve(strict=True)
    if not (package / 'observer' / 'contract.py').is_file():
        raise ValueError('Expected an observer package for integration acceptance')
    local_observe.__path__.append(str(package))


def example_profile():
    return {'schema_version': 1, 'name': 'example', 'interval_seconds': 3600,
            'telemetry': {'url': 'https://telemetry.example.test', 'token_file': '/run/secrets/store-reader',
                          'resource_id': HOST, 'metric_name': 'system.cpu.utilization'},
            'model': {'url': 'https://model.example.test', 'token_file': '/run/secrets/model-reader',
                      'model': 'observer-model', 'local': True,
                      'capability': {'schema_version': 1, 'context_tokens': 8192, 'tools': False,
                                     'json_mode': True, 'streaming': False, 'vision': False,
                                     'parallel': 1, 'quant': 'unknown', 'measured_tok_per_s': 'unknown'}},
            'channel': {'type': 'recording'}}


@unittest.skipUnless(os.name == 'posix', 'guided setup requires descriptor-relative POSIX operations')
class GuidedTests(unittest.TestCase):
    def setUp(self):
        self.platform = Platform()
        self.platform.store.path.chmod(0o600)
        self.addCleanup(self.platform.close)
        self.root = self.platform.store.path.parent / 'configuration'
        self.root.mkdir(mode=0o700)
        self.setup = guided.GuidedSetup(self.platform.store, self.root, 'trusted-runner')
        self.runner = configured(self.platform, setup=self.setup)
        self.agent = self.platform.bridge('proposer')
        self.human = ApiBridge(self.platform.app, HUMAN_TOKEN)
        self.profile = example_profile()
        self.expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat()

    def post(self, client, name, body):
        return client.request('POST', '/v1/setup/' + name, body)

    def prepare(self):
        code, result = self.post(self.agent, 'plan', {'profile': self.profile})
        self.assertEqual(code, 200, result)
        return result

    def queue(self):
        plan = self.prepare()
        key = plan['plan_id']
        self.assertEqual(self.post(self.human, 'decision',
            {'plan_id': key, 'decision': 'approved', 'expires_at': self.expiry})[0], 200)
        self.assertEqual(self.post(self.agent, 'request', {'plan_id': key})[0], 200)
        return plan

    def test_fresh_directory_reviewed_hashes_real_configuration_restart_and_repeat(self):
        prepared = self.prepare()
        self.assertEqual(prepared, self.prepare())
        self.assertEqual(list(self.root.iterdir()), [])
        plan = self.queue()
        code, receipt = self.post(self.runner, 'apply', {'plan_id': plan['plan_id']})
        self.assertEqual(code, 200, receipt)
        target = self.root / 'example'
        expected = {item['path']: item['sha256'] for item in plan['plan']['operations']}
        actual = {name: hashlib.sha256((target / name).read_bytes()).hexdigest() for name in expected}
        self.assertEqual(actual, expected)
        self.assertEqual(receipt['files'], expected)
        timestamps = {name: (target / name).stat().st_mtime_ns for name in expected}
        for path in target.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.platform.store = Store(self.platform.store.path)
        setup = guided.GuidedSetup(self.platform.store, self.root, 'trusted-runner')
        runner = configured(self.platform, setup=setup)
        self.assertEqual(self.post(runner, 'apply', {'plan_id': plan['plan_id']}), (200, receipt))
        self.assertEqual({name: (target / name).stat().st_mtime_ns for name in expected}, timestamps)
        self.assertEqual(self.post(self.platform.bridge('reader'), 'verify', {'plan_id': plan['plan_id']}),
                         (200, receipt))
        policy.validate(json.loads((target / 'ai-policy.json').read_text(encoding='utf-8')))
        capability.validate(json.loads((target / 'ai-capability.json').read_text(encoding='utf-8')))
        config = json.loads((target / 'observer.json').read_text(encoding='utf-8'))
        self.assertEqual(config['sources'][0]['resource_id'], HOST)
        self.assertEqual(config['mode'], 'recording')
        environment = json.loads((target / 'observer-environment.json').read_text(encoding='utf-8'))
        self.assertEqual(environment['LO_CLICKHOUSE_READ_PASSWORD_FILE'], '/run/secrets/store-reader')
        self.assertEqual(environment['LO_AI_CAPTURE'], '0')
        from local_observe.ai.client import AiClient
        from local_observe.platform.query import open_reader
        with patch('local_observe.ai.client.read_credential', return_value='synthetic-model-credential-0001'), \
                patch('local_observe.platform.query.read_credential', return_value='synthetic-store-credential-0001'):
            AiClient.from_environment(environment)
            self.assertIsNotNone(open_reader(environ=environment))

    @unittest.skipUnless(importlib.util.find_spec('local_observe.observer') is not None,
                         'observer contract is an integration check after package assembly')
    def test_generated_config_validates_with_observer_contract(self):
        from local_observe.observer.contract import Config
        Config.from_dict(guided.observer_inputs(self.profile))

    def test_agent_and_reader_cannot_approve_apply_or_fabricate_identity(self):
        plan = self.prepare()['plan_id']
        for role in ('reader', 'proposer', 'executor'):
            client = self.platform.bridge(role)
            self.assertEqual(self.post(client, 'decision',
                {'plan_id': plan, 'decision': 'approved', 'expires_at': self.expiry})[0], 400)
            self.assertEqual(self.post(client, 'apply', {'plan_id': plan})[0], 400)
        self.assertEqual(self.post(self.human, 'decision', {'plan_id': plan, 'decision': 'approved',
            'expires_at': self.expiry, 'approved_by': 'operator'})[0], 400)
        self.assertEqual(self.post(self.agent, 'request', {'plan_id': plan})[0], 400)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_withdrawn_expired_and_modified_plan_do_not_write(self):
        for reason in ('withdrawn', 'expired', 'source', 'profile', 'destination'):
            with self.subTest(reason=reason):
                self.profile['name'] = reason
                plan = self.queue()['plan_id']
                if reason == 'withdrawn':
                    self.assertEqual(self.post(self.human, 'decision', {'plan_id': plan,
                        'decision': 'denied', 'expires_at': self.expiry})[0], 200)
                    self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
                elif reason == 'expired':
                    with patch('local_observe.deployment.guided.clock',
                               return_value=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)):
                        self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
                elif reason == 'source':
                    with patch.object(self.setup, '_source', return_value={'changed.py': '0' * 64}):
                        self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
                else:
                    # Even a direct persisted-content mutation cannot preserve the approved hash.
                    with self.platform.store.transaction() as db:
                        payload = json.loads(db.execute('SELECT payload FROM setup_plans WHERE id=?',
                                                        (plan,)).fetchone()[0])
                        if reason == 'profile':
                            payload['profile']['interval_seconds'] = 60
                        else:
                            payload['destination'] = str(self.root / 'another')
                        db.execute('UPDATE setup_plans SET payload=? WHERE id=?', (json.dumps(payload), plan))
                    self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_strict_nested_profile_and_approval_shapes(self):
        invalid = []
        for value in ([], 'value', {'type': 'recording', 'hook': 'run'}, {'type': ['recording']}):
            document = copy.deepcopy(self.profile)
            document['channel'] = value
            invalid.append(document)
        for name in ('../outside', '/outside', 'x/child', '.', '..'):
            invalid.append({**self.profile, 'name': name})
        invalid.append({**self.profile, 'schema_version': True})
        invalid.append({**self.profile, 'hook': 'arbitrary'})
        invalid.append({**self.profile, 'model': {**self.profile['model'], 'api_key': 'inline-secret'}})
        invalid.append({**self.profile, 'telemetry': {**self.profile['telemetry'], 'token_file': '../../secret'}})
        invalid.append({**self.profile, 'model': {**self.profile['model'], 'url': 'https://model.example.test/v1'}})
        invalid.append({**self.profile, 'model': {**self.profile['model'],
            'capability': {**self.profile['model']['capability'], 'schema_version': True}}})
        for document in invalid:
            self.assertEqual(self.post(self.agent, 'plan', {'profile': document})[0], 400)
        plan = self.prepare()['plan_id']
        for decision, expiry in (({}, self.expiry), (['approved'], self.expiry), ('approved', {})):
            self.assertEqual(self.post(self.human, 'decision',
                {'plan_id': plan, 'decision': decision, 'expires_at': expiry})[0], 400)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_duplicate_json_keys_and_deep_objects_rejected_at_transport(self):
        async def request(raw):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.platform.app),
                                         base_url='http://platform.invalid') as client:
                return await client.post('/v1/setup/plan', content=raw,
                    headers={'Authorization': 'Bearer ' + self.platform.tokens['proposer']})
        raw = '{"profile":' + json.dumps(self.profile) + ',"profile":' + json.dumps(self.profile) + '}'
        self.assertEqual(asyncio.run(request(raw)).status_code, 400)
        self.assertEqual(asyncio.run(request('{"profile":' + '[' * 40 + '0' + ']' * 40 + '}')).status_code, 400)

    def test_existing_symlinked_and_unmanaged_destinations_preserve_sentinels(self):
        sentinel = self.root.parent / 'sentinel'
        sentinel.write_bytes(b'untouched')
        for kind in ('file', 'directory', 'symlink'):
            self.profile['name'] = kind
            plan = self.queue()['plan_id']
            target = self.root / kind
            if kind == 'file':
                target.write_bytes(b'untouched')
            elif kind == 'directory':
                target.mkdir(mode=0o700)
            else:
                target.symlink_to(sentinel)
            self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
        self.assertEqual(sentinel.read_bytes(), b'untouched')
        link = self.root.parent / 'linked-root'
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(StateError):
            guided.GuidedSetup(self.platform.store, link, 'trusted-runner')

    def test_partial_apply_resumes_exact_files_and_refuses_corruption(self):
        plan = self.queue()['plan_id']
        original = guided_files.create_file
        def fail(fd, name, data):
            if name == 'observer.json':
                raise OSError('Interrupted after first configuration file')
            return original(fd, name, data)
        with patch.object(guided_files, 'create_file', side_effect=fail):
            self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
        target = self.root / 'example'
        first = (target / 'profile.json').stat().st_mtime_ns
        self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 200)
        self.assertEqual((target / 'profile.json').stat().st_mtime_ns, first)
        (target / 'observer.json').write_bytes(b'changed')
        self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)
        self.assertEqual((target / 'observer.json').read_bytes(), b'changed')

    def test_permissive_root_and_fifo_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(StateError):
            guided.GuidedSetup(self.platform.store, self.root, 'trusted-runner')
        self.root.chmod(0o700)
        plan = self.queue()['plan_id']
        self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 200)
        target = self.root / 'example' / 'observer.json'
        target.unlink()
        os.mkfifo(target, 0o600)
        self.assertEqual(self.post(self.runner, 'apply', {'plan_id': plan})[0], 400)


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    unittest.main()

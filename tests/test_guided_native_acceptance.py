"""First-time setup using native password approval and an independent runner.

Imports only the installed product and test dependencies, so the same check can run outside a checkout
against a built wheel. Telemetry/model endpoints and every credential are synthetic; no network calls.
"""
import asyncio
import base64
import datetime as dt
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from local_observe.deployment.guided import GuidedSetup
from local_observe.observer.contract import Config
from local_observe.observer.environment import validate_environment
from local_observe.platform.api import create_app
from local_observe.platform.operator import with_ui
from local_observe.platform.operator_account import make_account
from local_observe.platform.state import Store


class NativeSetupAcceptanceTests(unittest.TestCase):
    def test_password_approval_exact_six_files_runner_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configuration = root / 'configuration'
            configuration.mkdir(mode=0o700)
            state = root / 'platform.sqlite3'
            Store(state)
            state.chmod(0o600)
            credentials = [
                {'identity': 'setup-proposer', 'role': 'proposer', 'token': 'p' * 40},
                {'identity': 'setup-operator', 'role': 'human', 'token': 'h' * 40},
                {'identity': 'setup-runner', 'role': 'executor', 'token': 'r' * 40},
                {'identity': 'setup-reader', 'role': 'reader', 'token': 'v' * 40}]
            account = make_account('operator', 'synthetic-password-for-acceptance')

            def application():
                fresh = Store(state)
                setup = GuidedSetup(fresh, configuration, 'setup-runner')
                return with_ui(create_app(fresh, credentials, {}, guided_setup=setup), account, 'h' * 40)

            profile = {'schema_version': 1, 'name': 'first-install', 'interval_seconds': 3600,
                'telemetry': {'url': 'https://telemetry.example.test',
                    'token_file': '/run/secrets/store-reader', 'metric_name': 'cpu',
                    'resource_id': '00000000-0000-4000-8000-000000000001'},
                'model': {'url': 'https://model.example.test', 'token_file': '/run/secrets/model-reader',
                    'model': 'example-model', 'local': True, 'capability': {'schema_version': 1,
                        'context_tokens': 8192, 'tools': False, 'json_mode': True, 'streaming': False,
                        'vision': False, 'parallel': 1, 'quant': 'unknown', 'measured_tok_per_s': 'unknown'}},
                'channel': {'type': 'recording'}}
            human = 'Basic ' + base64.b64encode(b'operator:synthetic-password-for-acceptance').decode()

            async def workflow():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application()),
                                             base_url='https://platform.example.test') as client:
                    async def post(action, body, auth):
                        return await client.post('/v1/setup/' + action, json=body,
                                                 headers={'Authorization': auth})
                    response = await post('plan', {'profile': profile}, 'Bearer ' + 'p' * 40)
                    self.assertEqual(response.status_code, 200, response.text)
                    plan = response.json()
                    key = {'plan_id': plan['plan_id']}
                    decision = {**key, 'decision': 'approved', 'expires_at':
                        (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=10)).isoformat()}
                    self.assertEqual(list(configuration.iterdir()), [])
                    self.assertEqual((await post('decision', decision, 'Bearer ' + 'p' * 40)).status_code, 400)
                    self.assertEqual((await post('apply', key, 'Bearer ' + 'r' * 40)).status_code, 400)
                    self.assertEqual((await post('decision', {**decision, 'approved_by': 'operator'},
                                                 human)).status_code, 400)
                    approved = await post('decision', decision, human)
                    self.assertEqual(approved.status_code, 200, approved.text)
                    self.assertEqual((await post('request', key, 'Bearer ' + 'p' * 40)).status_code, 200)
                    applied = await post('apply', key, 'Bearer ' + 'r' * 40)
                    self.assertEqual(applied.status_code, 200, applied.text)
                    receipt = applied.json()
                    self.assertNotIn('h' * 40, json.dumps([plan, approved.json(), receipt]))
                destination = configuration / 'first-install'
                expected = {item['path']: item['sha256'] for item in plan['plan']['operations']}
                self.assertEqual(len(expected), 6)
                self.assertEqual(receipt['files'], expected)
                times = {}
                for name, sha in expected.items():
                    path = destination / name
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), sha)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    times[name] = path.stat().st_mtime_ns
                self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
                config = Config.from_dict(json.loads((destination / 'observer.json').read_text(encoding='utf-8')))
                self.assertEqual(config.mode, 'recording')
                validate_environment(json.loads((destination / 'observer-environment.json').read_text(encoding='utf-8')))
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=application()),
                                             base_url='https://platform.example.test') as client:
                    repeated = await client.post('/v1/setup/apply', json=key,
                                                  headers={'Authorization': 'Bearer ' + 'r' * 40})
                    verified = await client.post('/v1/setup/verify', json=key,
                                                  headers={'Authorization': 'Bearer ' + 'v' * 40})
                    self.assertEqual(repeated.status_code, 200)
                    self.assertEqual(repeated.json(), receipt)
                    self.assertEqual(verified.status_code, 200)
                    self.assertEqual(verified.json(), receipt)
                self.assertEqual({name: (destination / name).stat().st_mtime_ns for name in expected}, times)
                audit = Store(state).records('audit', limit=100)
                approved = [row for row in audit if row['operation'] == 'setup.approved']
                applied = [row for row in audit if row['operation'] == 'setup.applied']
                self.assertEqual([row['actor'] for row in approved], ['setup-operator'])
                self.assertEqual([row['actor'] for row in applied], ['setup-runner'])

            asyncio.run(workflow())

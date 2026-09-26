import asyncio
import importlib.util
import json
from pathlib import Path
import unittest

import httpx

import test_platform as fixtures
from local_observe.platform.api import create_app
from local_observe.platform.operator import with_ui


class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PlatformTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_terminal_execution_retry_requires_same_runner_and_outcome(self):
        from local_observe.platform.state import Actor, StateError
        fixture = self.fixture
        claim = fixture.store.claim_action(fixture.approved(), fixtures.RUNNER, fixture.policy, now=fixtures.NOW)
        args = (claim['execution_id'], 'succeeded', fixtures.RUNNER, claim['runner_token'])
        self.assertEqual(fixture.store.execution_outcome(*args, now=fixtures.NOW), {'status': 'succeeded'})
        before = len(fixture.store.records('audit'))
        self.assertEqual(fixture.store.execution_outcome(*args, now=fixtures.NOW), {'status': 'succeeded'})
        self.assertEqual(before, len(fixture.store.records('audit')))
        with self.assertRaises(StateError):
            fixture.store.execution_outcome(claim['execution_id'], 'failed', fixtures.RUNNER, claim['runner_token'], now=fixtures.NOW)
        with self.assertRaises(StateError):
            fixture.store.execution_outcome(claim['execution_id'], 'succeeded', Actor('other-runner', 'executor'), claim['runner_token'], now=fixtures.NOW)

    def test_operator_assets_and_role_enforcement(self):
        action_id = self.fixture.action()[0]['action_id']
        async def check():
            app = with_ui(create_app(self.fixture.store, [
                {'identity': 'operator', 'role': 'human', 'token': 'human-test-token-' * 3},
                {'identity': 'reader', 'role': 'reader', 'token': 'reader-test-token-' * 3}], self.fixture.policy, index_path=self.fixture.index))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
                response = await client.get('/')
                self.assertEqual(response.status_code, 200)
                self.assertIn('frame-ancestors', response.headers['content-security-policy'])
                self.assertEqual((await client.get('/v1/status')).status_code, 401)
                reader = {'Authorization': 'Bearer ' + 'reader-test-token-' * 3}
                self.assertEqual((await client.get('/v1/me', headers=reader)).json()['role'], 'reader')
                self.assertEqual(len((await client.get('/v1/inventory', headers=reader)).json()['rows']), 2)
                action = (await client.get('/v1/records/actions', headers=reader)).json()['rows'][0]
                self.assertNotIn(action_id, action['display']['description'])
                self.assertEqual(action['display']['host_name'], 'probe-1')
                self.assertEqual(action['display']['resource_name'], 'probe-1')
                self.assertEqual((await client.post('/v1/actions/decision', headers=reader, json={'action_id': action_id, 'decision': 'approved'})).status_code, 400)
                self.assertEqual((await client.get('/v1/records/events?limit=100000', headers=reader)).status_code, 400)
        asyncio.run(check())

    def test_environment_badge_reports_the_serving_delivery_mode(self):
        """The shell ships no fixed environment label; the badge reads the runtime observation."""
        async def check():
            app = with_ui(create_app(self.fixture.store, [
                {'identity': 'operator', 'role': 'human', 'token': 'human-test-token-' * 3}], self.fixture.policy, index_path=self.fixture.index))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
                page = await client.get('/')
                self.assertNotIn('STAGING', page.text)
                self.assertIn('id="environment">UNKNOWN<', page.text)
                # script-src 'self' is only satisfiable while the shell carries no inline script.
                self.assertNotIn('<script>', page.text)
                self.assertIn('/v1/runtime', (await client.get('/ui.js')).text)
                human = {'Authorization': 'Bearer ' + 'human-test-token-' * 3}
                mode = (await client.get('/v1/runtime', headers=human)).json()['notification_mode']
                self.assertEqual(mode, self.fixture.store.notification_policy.delivery_mode)
                self.assertIn(mode, ('off', 'recording', 'live'))
                self.assertEqual((await client.get('/v1/runtime')).status_code, 401)
        asyncio.run(check())


@unittest.skipUnless(importlib.util.find_spec('mcp'), 'Optional MCP extra not installed; run the MCP test tier separately')
class MCPTests(unittest.TestCase):
    def test_authenticated_protocol_and_read_only_tools(self):
        from local_observe.platform.mcp import create_server
        class Client:
            def request(self, method, path):
                if method != 'GET':
                    raise AssertionError('MCP attempted a mutation')
                return 200, {'schema_version': 1}
        async def check():
            app, server = create_server(Client(), 'mcp-read-only-test-token-' * 2)
            async with server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost:8000') as client:
                    body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list', 'params': {}}
                    self.assertEqual((await client.post('/mcp', json=body)).status_code, 401)
                    headers = {'Authorization': 'Bearer ' + 'mcp-read-only-test-token-' * 2, 'Accept': 'application/json, text/event-stream'}
                    response = await client.post('/mcp', json=body, headers=headers)
                    self.assertEqual(response.status_code, 200, response.text)
                    tools = response.json()['result']['tools']
                    self.assertEqual({tool['name'] for tool in tools}, {'platform_status', 'platform_overview', 'records', 'inventory'})
                    self.assertTrue(all(tool['annotations']['readOnlyHint'] for tool in tools))
                    call = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'platform_status', 'arguments': {}}}
                    self.assertFalse((await client.post('/mcp', json=call, headers=headers)).json()['result']['isError'])
                    call['params']['name'] = 'approve'
                    self.assertTrue((await client.post('/mcp', json=call, headers=headers)).json()['result']['isError'])
        asyncio.run(check())

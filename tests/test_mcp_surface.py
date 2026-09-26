"""mcp tool surface: the MCP transport itself — the bearer gate, the two content blocks, the tool list a client sees.

Every test here needs the optional ``mcp`` extra and skips without it, which is the arrangement
``docs/testing-standards.md`` describes and ``.gitea/workflows/ci.yml`` runs as two jobs. The refusals that
do *not* need the SDK — the registry, the identity map, the five action behaviours, the absent-extra
refusal itself — live in ``tests/test_platform_tools.py`` and run in the base tier.

What is only provable from the wire:

* the **exposed set is exactly the registered set**, in both directions: a client's ``tools/list`` equals
  ``ToolRegistry.descriptors()`` for each of the two surfaces, and an unmounted capability is absent;
* an answer is **two content blocks**, the platform document first and its provenance second, so the
  document an agent reads is byte-comparable with the route it came from;
* a **credential that is not in the map** gets one 401 and nothing else — not a tool list, not a hint of
  which agents exist;
* an oversized request body is refused **before the SDK sees it**;
* a tool that refuses by role refuses *over the wire*, as ``isError`` with the refusal's own sentence.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as dt
import importlib.util
import json
import unittest
from typing import Any

import httpx

from local_observe.platform import tools
from test_platform_tools import (MOUNTED, READ_ARGUMENTS, HOST, Platform, seeded_store)  # noqa: E402

MCP_TOKEN = 'a-dedicated-mcp-reader-token-0000'
BEARERS = {'reader': 'bearer-read-0123456789abcdef012345678',
           'proposer': 'bearer-ask-0123456789abcdef012345678',
           'executor': 'bearer-run-0123456789abcdef012345678'}
ACCEPT = {'Accept': 'application/json, text/event-stream'}


def thread_bridge(app: Any, token: str) -> Any:
    """A `JsonClient`-shaped client that runs one in-process request per call, off the serving loop.

    The SDK calls a synchronous tool function *inside* its own event loop, and ``httpx.ASGITransport``
    needs a loop of its own to run on, so each call gets one on a worker thread. That is the same shape
    ``tests/test_homepage_surfaces.py`` uses for the same reason: blocking from the tool's point of view,
    one credential, no retries, and only the network replaced.
    """
    class Bridge:
        def request(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
            async def go() -> tuple[int, Any]:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url='http://platform.invalid') as client:
                    response = await client.request(method, path, json=payload,
                                                    headers={'Authorization': 'Bearer ' + token})
                    return response.status_code, response.json()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, go()).result()
    return Bridge()


@unittest.skipUnless(importlib.util.find_spec('mcp'),
                     'Optional MCP extra not installed; run the MCP test tier separately')
class TransportTests(unittest.TestCase):
    """One server instance per test: the SDK allows one `session_manager.run()` per instance."""

    def setUp(self) -> None:
        """The platform, the agents a map would mount, and nothing built until a test asks for it."""
        self.platform = Platform(reader=seeded_store())
        self.addCleanup(self.platform.close)

    def agent(self, role: str) -> tools.Agent:
        return tools.Agent(identity=MOUNTED[role], role=role,
                           client=thread_bridge(self.platform.app, self.platform.tokens[role]))

    def serve(self, *, roles: tuple[str, ...] = ('reader', 'proposer', 'executor'), reader: Any = 'default',
              index: bool = True) -> Any:
        """Build one transport and hand it to the caller inside its session lifetime."""
        from local_observe.platform import mcp
        table = [(BEARERS[role], self.agent(role)) for role in roles]
        app, server = mcp.create_agent_server(
            table, reader=self.platform.reader if reader == 'default' else reader,
            index_path=self.platform.index_path if index else None)

        class Serving:
            def __init__(self: Any) -> None:
                self.app, self.server = app, server

            async def __aenter__(self: Any) -> Any:
                self.context = server.session_manager.run()
                await self.context.__aenter__()
                return self

            async def __aexit__(self: Any, *exc: Any) -> None:
                await self.context.__aexit__(*exc)
        return Serving()

    async def tools_list(self, client: Any, token: str) -> list[str]:
        """The tool names one bearer is offered."""
        response = await client.post('/mcp', headers={**ACCEPT, 'Authorization': 'Bearer ' + token},
                                     json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list',
                                           'params': {}})
        self.assertEqual(response.status_code, 200, response.text)
        return sorted(item['name'] for item in response.json()['result']['tools'])

    async def call(self, client: Any, token: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """One ``tools/call`` and its decoded result, without asserting whether it worked."""
        response = await client.post('/mcp', headers={**ACCEPT, 'Authorization': 'Bearer ' + token},
                                     json={'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                                           'params': {'name': name, 'arguments': arguments}})
        return response.json()['result']

    def drive(self, exercise: Any) -> Any:
        """Run one async exchange, holding a built server across it."""
        async def go() -> Any:
            async with self.serve() as serving:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(serving.app),
                                             base_url='http://localhost:8000') as client:
                    return await exercise(client)
        return asyncio.run(go())

    # --------------------------------------------------------------------- the exposed tool set

    def test_the_exposed_set_is_exactly_the_registered_set(self) -> None:
        """Both directions of the claim, on the bytes a client receives."""
        registry = tools.agent_registry(reader=self.platform.reader, index_path=self.platform.index_path)
        expected = sorted(item['name'] for item in registry.descriptors())

        async def exercise(client: Any) -> None:
            self.assertEqual(await self.tools_list(client, BEARERS['reader']), expected)
        self.drive(exercise)

    def test_an_unmounted_capability_is_absent_from_the_list(self) -> None:
        """No store reader means no `signal_series`: the tool is not offered, not failing."""
        async def exercise(client: Any) -> None:
            names = await self.tools_list(client, BEARERS['reader'])
            self.assertNotIn('signal_series', names)
            self.assertNotIn('topology_neighbourhood', names)
            self.assertIn('records', names)
            self.assertIn('execute_action', names, 'visibility is not the gate; the role is')
        async def go() -> None:
            from local_observe.platform import mcp
            table = [(BEARERS['reader'], self.agent('reader'))]
            app, server = mcp.create_agent_server(table, reader=None, index_path=None)
            async with server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app),
                                             base_url='http://localhost:8000') as client:
                    names = await self.tools_list(client, BEARERS['reader'])
            self.assertNotIn('signal_series', names)
            self.assertNotIn('topology_neighbourhood', names)
            self.assertIn('evidence_window', names)
        asyncio.run(go())

    def test_a_single_token_deployment_still_sees_exactly_the_four_v0_1_reads(self) -> None:
        """``LO_MCP_TOKEN_FILE`` is not a legacy in name only: its surface is unchanged, tools included."""
        from local_observe.platform import mcp
        client = thread_bridge(self.platform.app, self.platform.tokens['reader'])
        app, server = mcp.create_server(client, MCP_TOKEN)

        async def go() -> None:
            async with server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app),
                                             base_url='http://localhost:8000') as http:
                    names = await self.tools_list(http, MCP_TOKEN)
            self.assertEqual(names, sorted(['platform_status', 'platform_overview', 'records',
                                            'inventory']))
        asyncio.run(go())

    def test_the_single_token_surface_refuses_a_short_credential(self) -> None:
        from local_observe.platform import mcp
        with self.assertRaisesRegex(ValueError, 'dedicated MCP reader token'):
            mcp.create_server(thread_bridge(self.platform.app, self.platform.tokens['reader']), 'short')

    # --------------------------------------------------------------------------- the answer shape

    def test_an_answer_is_the_document_then_its_provenance(self) -> None:
        """Block one is what the route returned; block two is the envelope, and nothing else."""

        async def exercise(client: Any) -> None:
            result = await self.call(client, BEARERS['reader'], 'platform_status', {})
            self.assertFalse(result['isError'], result)
            self.assertEqual(len(result['content']), 2)
            document = json.loads(result['content'][0]['text'])
            envelope = json.loads(result['content'][1]['text'])
            self.assertEqual(set(document), {'schema_version', 'incidents', 'actions', 'notifications'})
            self.assertEqual(set(envelope), {'provenance'})
            self.assertEqual(set(envelope['provenance']), set(tools.PROVENANCE_KEYS))
            self.assertEqual(envelope['provenance']['source'], 'agent-read')
            self.assertEqual(envelope['provenance']['query_type'], 'platform-status')
            self.assertNotIn('structuredContent', result,
                             'the change this item makes to the wire shape is pinned, not assumed')
        self.drive(exercise)

    def test_the_tool_and_the_route_return_one_document(self) -> None:
        """Two consumers, one datum: the v0.1 agreement still holds across the new envelope."""
        async def exercise(client: Any) -> None:
            tool = json.loads((await self.call(client, BEARERS['reader'], 'platform_overview',
                                                {}))['content'][0]['text'])
            async with httpx.AsyncClient(transport=httpx.ASGITransport(self.platform.app),
                                         base_url='http://platform.invalid') as api:
                response = await api.get('/v1/overview', headers={'Authorization': 'Bearer '
                                                                  + self.platform.tokens['reader']})
            portal = response.json()
            tool.pop('generated_at', None)
            portal.pop('generated_at', None)
            self.assertEqual(tool, portal)
        self.drive(exercise)

    def test_every_read_the_registry_names_returns_a_provenance_block_over_the_wire(self) -> None:
        """The same table as the base tier's, once more through the protocol that ships it."""
        async def exercise(client: Any) -> None:
            for name, arguments in READ_ARGUMENTS.items():
                with self.subTest(tool=name):
                    result = await self.call(client, BEARERS['reader'], name, arguments)
                    self.assertFalse(result['isError'], result)
                    envelope = json.loads(result['content'][1]['text'])['provenance']
                    self.assertEqual(set(envelope), set(tools.PROVENANCE_KEYS))
                    self.assertIn(envelope['query_type'], tools.PROVENANCE_QUERY_TYPES)
        self.drive(exercise)

    # ------------------------------------------------------------------------- the bearer gate

    def test_a_credential_that_is_not_mounted_gets_one_answer_and_no_tool_list(self) -> None:
        token, wrong = BEARERS['reader'], 'bearer-not-in-the-map-0123456789abcdef00'

        async def exercise(client: Any) -> None:
            for bad in (wrong, '', token + 'x'):
                response = await client.post('/mcp', headers={**ACCEPT, 'Authorization': 'Bearer ' + bad},
                                             json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list',
                                                   'params': {}})
                self.assertEqual(response.status_code, 401, response.text)
                self.assertEqual(response.json().get('error'), 'authentication_required')
                self.assertNotIn('tools', response.json().get('result', {}))
            without = await client.post('/mcp', headers=ACCEPT,
                                        json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list',
                                              'params': {}})
            self.assertEqual(without.status_code, 401)
            extra = await client.post('/mcp', headers={**ACCEPT, 'Authorization': 'Bearer ' + token,
                                                       'x-other': 'Bearer ' + token},
                                      json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list',
                                            'params': {}})
            self.assertEqual(extra.status_code, 200, 'a header that is not the one is not a credential')
        self.drive(exercise)

    def test_two_credentials_on_one_request_decide_nothing(self) -> None:
        """Exactly one ``Authorization`` is a credential; two are an ambiguous request, refused.

        Driven with raw ASGI scopes because httpx will not send a repeated header, and a header list is
        exactly the shape an attacker can send. The answer must be the same 401 an absent credential gets.
        """
        from local_observe.platform import mcp
        table = [(BEARERS['reader'], self.agent('reader'))]
        app, _server = mcp.create_agent_server(table, reader=self.platform.reader,
                                               index_path=self.platform.index_path)

        async def go(statuses: list[int]) -> None:
            async def one(headers: list[tuple[bytes, bytes]]) -> int:
                sent: list[dict[str, Any]] = []

                async def receive() -> dict[str, Any]:
                    return {'type': 'http.request', 'body': b'{}', 'more_body': False}

                async def send(message: dict[str, Any]) -> None:
                    sent.append(message)
                await app({'type': 'http', 'method': 'POST', 'path': '/mcp', 'query_string': b'',
                           'headers': headers}, receive, send)
                return sent[0]['status']
            bearer = ('Bearer ' + BEARERS['reader']).encode()
            statuses.append(await one([(b'authorization', bearer), (b'authorization', bearer)]))
            statuses.append(await one([(b'authorization', bearer), (b'authorization', b'Bearer other')]))
            statuses.append(await one([]))
        outcomes: list[int] = []
        asyncio.run(go(outcomes))
        self.assertEqual(outcomes, [401, 401, 401])

    def test_a_non_http_scope_is_handed_to_the_underlying_app(self) -> None:
        """A lifespan scope belongs to the SDK, and the gate must not swallow it.

        This is how the served process starts the session manager: uvicorn drives the lifespan through
        this callable, so the pass-through is not a formality — and no bearer is asked for, because a
        lifespan message carries no caller and no tool.
        """
        from local_observe.platform import mcp

        async def go() -> None:
            app, _server = mcp.create_server(thread_bridge(self.platform.app,
                                                           self.platform.tokens['reader']), MCP_TOKEN)
            sent: list[dict[str, Any]] = []
            startup = iter([{'type': 'lifespan.startup'}, {'type': 'lifespan.shutdown'}])

            async def receive() -> dict[str, Any]:
                return next(startup)

            async def send(message: dict[str, Any]) -> None:
                sent.append(message)
            await app({'type': 'lifespan'}, receive, send)
            self.assertIn('lifespan.startup.complete', [item['type'] for item in sent], sent)
            self.assertIn('lifespan.shutdown.complete', [item['type'] for item in sent], sent)
        asyncio.run(go())

    def test_a_body_beyond_the_request_budget_is_refused_before_the_sdk_sees_it(self) -> None:
        """413, and the SDK never parses the bytes: the ceiling is the transport's, not the tool's."""
        from local_observe.platform import mcp
        app, server = mcp.create_server(thread_bridge(self.platform.app, self.platform.tokens['reader']),
                                        MCP_TOKEN)

        async def go() -> None:
            sent: list[dict[str, Any]] = []
            messages = iter([{'type': 'http.request', 'body': b'x' * (mcp.MAX_REQUEST_BYTES + 1),
                              'more_body': False}])

            async def receive() -> dict[str, Any]:
                return next(messages)

            async def send(message: dict[str, Any]) -> None:
                sent.append(message)
            async with server.session_manager.run():
                await app({'type': 'http', 'method': 'POST', 'path': '/mcp', 'query_string': b'',
                           'headers': [(b'authorization', b'Bearer ' + MCP_TOKEN.encode())]},
                          receive, send)
            self.assertEqual(sent[0]['status'], 413)
        asyncio.run(go())

    # ------------------------------------------------------------------- the action pair, over the wire

    def test_a_reader_that_calls_the_action_tool_hears_the_role_refusal(self) -> None:
        """The gate travels to the client as a tool error naming the role it wanted."""
        async def exercise(client: Any) -> None:
            result = await self.call(client, BEARERS['reader'], 'execute_action',
                                     {'action_id': HOST})
            self.assertTrue(result['isError'])
            self.assertIn('needs role executor', result['content'][0]['text'])
            self.assertEqual(self.platform.executions(), [],
                             'a refusal over the wire opened no execution either')
        self.drive(exercise)

    def test_executor_refusal_preserves_approval_over_the_wire_for_the_runner(self) -> None:
        action_id = self.platform.approved()
        tables = ('actions', 'executions', 'audit')
        before = {table: self.platform.store.records(table, 100) for table in tables}

        async def exercise(client: Any) -> None:
            for _ in range(2):
                result = await self.call(client, BEARERS['executor'], 'execute_action',
                                         {'action_id': action_id})
                self.assertTrue(result['isError'], result)
                self.assertEqual(len(result['content']), 1, 'a refusal carries no claimed result')
                self.assertIn('no trusted runner handoff', result['content'][0]['text'])
                text = json.dumps(result)
                self.assertNotIn('execution_id', text)
                for secret in (*BEARERS.values(), *self.platform.tokens.values()):
                    self.assertNotIn(secret, text)
                self.assertEqual({table: self.platform.store.records(table, 100) for table in tables}, before)

        self.drive(exercise)
        self.assertEqual(self.platform.action_row(action_id)['status'], 'approved')
        code, claim = self.platform.bridge('executor').request('POST', '/v1/actions/claim',
                                                              {'action_id': action_id})
        self.assertEqual((code, claim['status']), (200, 'executing'))
        self.assertIn('runner_token', claim, 'the trusted runner still receives its credential directly')
        self.assertEqual(len(self.platform.executions()), 1)

    def test_a_proposal_filed_over_the_wire_is_pending_and_names_its_agent(self) -> None:
        incident = self.platform.open_incident()
        arguments = {'retry_key': 'over-the-wire', 'incident_id': incident['incident_id'],
                     'action': 'inspect', 'version': '1', 'targets': [HOST], 'parameters': {},
                     'evidence': [incident['event_id']],
                     'expires_at': (dt.datetime.now(dt.timezone.utc)
                                    + dt.timedelta(hours=2)).isoformat()}

        async def exercise(client: Any) -> None:
            result = await self.call(client, BEARERS['proposer'], 'propose_action', arguments)
            self.assertFalse(result['isError'], result)
            data = json.loads(result['content'][0]['text'])
            self.assertEqual(data['outcome'], 'filed, pending human decision')
            self.assertEqual(data['filed_by'], 'agent-ask')
            self.assertEqual(self.platform.action_row(data['action_id'])['requester'], 'agent-ask')
            envelope = json.loads(result['content'][1]['text'])['provenance']
            self.assertEqual(envelope['query_type'], 'action-propose')
            self.assertIsNone(envelope['window'], 'a filing is not about a window, and says so')
        self.drive(exercise)

    def test_a_refused_proposal_reaches_the_client_as_an_error_not_an_empty_success(self) -> None:
        """The refusal is loud, and it names the platform's code rather than the body that caused it."""
        arguments = {'retry_key': 'unknown-action', 'incident_id': HOST, 'action': 'inspect',
                     'version': '1', 'targets': [HOST], 'parameters': {}, 'evidence': [HOST],
                     'expires_at': dt.datetime.now(dt.timezone.utc).isoformat()}

        async def exercise(client: Any) -> None:
            result = await self.call(client, BEARERS['proposer'], 'propose_action', arguments)
            self.assertTrue(result['isError'])
            self.assertIn('Proposal refused by the platform', result['content'][0]['text'])
            self.assertNotIn(arguments['retry_key'], result['content'][0]['text'])
        self.drive(exercise)

    # ------------------------------------------------------------------------ table refusals kept here

    def test_the_per_agent_surface_refuses_an_empty_or_duplicated_table(self) -> None:
        """No agent, or two on one bearer: both are a boot refusal, never a server with a guess in it."""
        from local_observe.platform import mcp
        with self.assertRaisesRegex(tools.ToolRefusal, 'at least one mounted agent'):
            mcp.create_agent_server([])
        agent = self.agent('reader')
        with self.assertRaisesRegex(tools.ToolRefusal, 'share a bearer token'):
            mcp.create_agent_server([(BEARERS['reader'], agent), (BEARERS['reader'], agent)])


@unittest.skipUnless(importlib.util.find_spec('mcp'),
                     'Optional MCP extra not installed; run the MCP test tier separately')
class LegacySurfaceUnchangedTests(unittest.TestCase):
    """What v0.1's readers rely on, kept: one token, four reads, the same sentences on refusal."""

    def setUp(self) -> None:
        self.platform = Platform()
        self.addCleanup(self.platform.close)

    def test_a_read_the_platform_refuses_is_the_old_sentence(self) -> None:
        """``Platform read unavailable`` survives the rewrite, word for word."""
        from local_observe.platform import mcp

        class Dead:
            """A platform that answers every read with a status and no document."""

            def request(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
                return 503, {'error': 'unavailable'}
        app, server = mcp.create_server(Dead(), MCP_TOKEN)

        async def go() -> dict[str, Any]:
            async with server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app),
                                             base_url='http://localhost:8000') as client:
                    result = await client.post('/mcp',
                                               headers={**ACCEPT, 'Authorization': 'Bearer ' + MCP_TOKEN},
                                               json={'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                                                     'params': {'name': 'platform_status',
                                                                'arguments': {}}})
                    return result.json()['result']
        answer = asyncio.run(go())
        self.assertTrue(answer['isError'])
        self.assertIn('Platform read unavailable', answer['content'][0]['text'])

    def test_the_records_limit_and_table_are_still_bounded_at_the_schema(self) -> None:
        """The 1..20 window and the six table names are what the input schema says they are."""
        from local_observe.platform import mcp
        _app, server = mcp.create_server(thread_bridge(self.platform.app,
                                                       self.platform.tokens['reader']), MCP_TOKEN)

        async def go() -> dict[str, Any]:
            return {item.name: item for item in await server.list_tools()}
        listed = asyncio.run(go())
        self.assertEqual(sorted(listed), ['inventory', 'platform_overview', 'platform_status', 'records'])
        table = json.dumps(listed['records'].inputSchema)
        for name in tools.RECORD_TABLES:
            self.assertIn(name, table, 'the closed table list is in the schema the client validates')
        self.assertNotIn('notification_attempts', table)


if __name__ == '__main__':
    unittest.main()

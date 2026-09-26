"""Optional SDK-backed, authenticated MCP facade over the tool registry in `tools.py`.

Two shapes, and the difference between them is identity rather than features. ``create_server`` keeps the
v0.1 deployment: one shared bearer from ``LO_MCP_TOKEN_FILE``, the four read tools it always answered
with, and no action pair — a shared credential has no answer to "who asked?", which is the question a
proposal is filed under. ``create_agent_server`` is the chat integration shape: a mounted per-agent map
(``LO_MCP_IDENTITIES``, the secret files/credential file leftovers file credential) where each agent's own platform
credential is what
the platform sees, so a proposal names an agent and a refusal is attributable. ``credential_source``
refuses a process configured with both, and refuses ``LO_MCP_TOKEN`` outright: an MCP credential arrives
as a file, and only as a file (ledger notification and state leftovers recorded that this file's bare read was left
out of credential file leftovers's
cleanup; :func:`local_observe.platform.tools.read_credential_file` is the bounded read that owed it). The
credential this service uses to reach the platform on a legacy deployment is unchanged and still arrives
through :func:`local_observe.credentials.read_credential` — the operator's staging driver exports that
value, and mcp tool surface changes the agent-facing credential rather than that one.

Everything that decides *what an agent may ask for* lives in ``tools.py``, which imports no SDK and is
tested in the base-dependency tier. This module is the transport: the bearer gate, the 64 KiB request-body
bound, the two content blocks one answer travels in, and the loud refusal when the extra is not installed
— never a silent server that answers with no tools.

The result shape is the one thing a client of the v0.1 surface has to re-read. Each answer arrives as two
``TextContent`` blocks: the first is the platform document itself, byte-for-byte what the corresponding
``GET``/``POST`` route returned, and the second is ``{"provenance": {...}}`` — the query, the bounded
parameters, the window (or ``null``, when the read has none), whose read it was, and when it happened.
``structuredContent`` is no longer sent: an answer with two halves needs one schema for both, and the data
half is the platform's document rather than this module's to re-describe. A client that read
``structuredContent`` reads ``content[0]`` now.

The action pair is role-gated, but execution is unavailable: ``propose_action`` files a proposal a
human must decide, and ``execute_action`` refuses before any platform request until a trusted runner
handoff exists. It preserves approved actions for the Dagu runner and never obtains a runner secret.
``tests/test_platform_tools.py`` and ``tests/test_mcp_surface.py`` verify that boundary.
"""
from __future__ import annotations

import contextvars
import json
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, Literal

from local_observe.credentials import read_credential
from local_observe.http import JsonClient

from . import tools
from .tools import (RECORD_TABLES, SERIES_SIGNALS, TOPOLOGY_DIRECTIONS, Agent, Identity, ToolRegistry,
                    ToolResult, authorize, agent_table, credential_source, mcp_extra_refusal,
                    read_credential_file, read_identity_rows)

try:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import TextContent, ToolAnnotations
except ModuleNotFoundError as exc:  # pragma: no cover - taken on any interpreter without the extra
    raise mcp_extra_refusal(exc) from exc

#: The request-body ceiling this transport accepted before, kept: an MCP message is a JSON-RPC envelope,
#: not a channel for a document, and 64 KiB is what the platform's own POST gate holds too. It is a
#: *separate* number from `tools.MAX_RESULT_BYTES`, which bounds the answer: two bounds that happen to
#: agree are not one bound, and the request one is checked before the SDK parses anything.
MAX_REQUEST_BYTES = 65536

#: The three closed vocabularies, spelled as protocol-level enums so a client refuses a bad value before
#: it asks. Each one is the same tuple `tools` registers, and `tests/test_mcp_surface.py` compares the
#: schema a client receives against `descriptors()` — the enums and the registry may not disagree.
#: `Literal[tuple]` is how the typing module spells a membership list from data.
RecordTable = Literal[RECORD_TABLES]
SignalKind = Literal[tuple(SERIES_SIGNALS)]
Direction = Literal[TOPOLOGY_DIRECTIONS]

#: The agent that reached this process, set by the transport for the duration of one JSON-RPC message and
#: read by the tool wrapper. It is a `contextvars.ContextVar` rather than an argument because the SDK
#: builds the tool's arguments from its own signature and offers no place to pass server-side state; the
#: per-request isolation that makes it safe is the transport's, and it is stated under `_serve`.
_CALLING_AGENT: contextvars.ContextVar[Agent | None] = contextvars.ContextVar('lo_mcp_agent', default=None)


def _blocks(result: ToolResult) -> list[TextContent]:
    """Return one answer as the two content blocks it travels in: the document, then its provenance.

    Ordered deliberately: ``content[0]`` is what a client that has not heard of the envelope still reads,
    and the second block is additive. Both are compact JSON with sorted keys, so a reviewer diffing two
    answers is diffing the data and not the serialiser.
    """
    return [TextContent(type='text', text=json.dumps(result.data, sort_keys=True, separators=(',', ':'),
                                                     default=str)),
            TextContent(type='text', text=json.dumps({'provenance': result.provenance.as_dict()},
                                                     sort_keys=True, separators=(',', ':')))]


async def _unauthorised(send: Callable[..., Awaitable[None]]) -> None:
    """Send the one 401 this transport ever gives, with no hint about which credentials exist.

    Both messages are awaited: an ``http.response.start`` that is constructed and dropped is a request
    that never gets an answer at all, and the ASGI client in front of it notices (``assert status_code is
    not None``) before anybody reading this file does.
    """
    await send({'type': 'http.response.start', 'status': 401,
                'headers': [(b'content-type', b'application/json'), (b'cache-control', b'no-store')]})
    await send({'type': 'http.response.body', 'body': b'{"error":"authentication_required"}'})


def _serve(table: Sequence[tuple[str, Agent]], registry: ToolRegistry) -> tuple[Callable[..., Awaitable[None]],
                                                                                FastMCP]:
    """Build the FastMCP app for `registry` and wrap it in the bearer gate that selects an agent.

    Three properties this depends on, each one a reason not to copy this wrapper into another transport:

    * ``stateless_http=True`` and ``json_response=True``. Every JSON-RPC message is one HTTP request, and
      the agent is bound to the request that carried the credential. On a session-based transport the
      identity of a later message would be inherited from an earlier one, which is exactly the confusion
      this variable must never be allowed to create.
    * One :class:`contextvars.ContextVar` set around the call into the SDK and reset after it. The SDK
      runs a synchronous tool function inside this task, so the value the handler reads is the one this
      request authenticated and not the one the request before it did.
    * The body is read to the same 64 KiB ceiling as the platform API, and 413 is answered before the
      SDK sees a byte of it.
    """
    server = FastMCP('local-observe', stateless_http=True, json_response=True, log_level='ERROR')
    transport = server.streamable_http_app()
    exposed: set[str] = set()

    def expose(name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Return the decorator that registers this function as *name*, or one that registers nothing.

        The registry decides what the surface has; a function below that no registry names stays an
        ordinary local function. That is what makes the legacy four and the map surface two readings of
        one file rather than two files that can drift apart.
        """
        if not registry.describes(name):
            return lambda function: function
        exposed.add(name)
        return server.tool(name=name, description=registry.description(name),
                           annotations=ToolAnnotations(**registry.annotations(name)))

    def call(name: str, **arguments: Any) -> list[TextContent]:
        """Run one registered tool as the agent this request authenticated."""
        agent = _CALLING_AGENT.get()
        if agent is None:
            # Unreachable through the app below: the gate answers 401 before the SDK runs a tool. It is
            # here because the alternative is a `None` reaching `registry.invoke`, which would read as a
            # bug in the registry rather than as a transport that was wired wrongly.
            raise tools.ToolRefusal('No authenticated agent is bound to this request')
        return _blocks(registry.invoke(name, agent, arguments))

    @expose('platform_status')
    def platform_status() -> list:
        """Read incident, action and delivery counts."""
        return call('platform_status')

    @expose('platform_overview')
    def platform_overview() -> list:
        """Read the portal summary."""
        return call('platform_overview')

    @expose('records')
    def records(table: RecordTable, limit: int = 10) -> list:
        """Read recent records from one named table."""
        return call('records', table=table, limit=limit)

    @expose('inventory')
    def inventory() -> list:
        """Read the declared inventory."""
        return call('inventory')

    @expose('evidence_window')
    def evidence_window(source: str, sample_id: str) -> list:
        """Read whether one evidence sample is available, expired or unavailable."""
        return call('evidence_window', source=source, sample_id=sample_id)

    @expose('signal_series')
    def signal_series(signal: SignalKind, resource_id: str = '', rule_id: str = '',
                      metric_name: str = '', service: str = '', artifact_sha256: str = '',
                      minutes: int = 60) -> list:
        """Read one bounded series through the store facade."""
        arguments: dict[str, Any] = {'signal': signal, 'minutes': minutes}
        # An optional argument the client left at its default is *not sent*: the registry validates what
        # arrives, and an empty string is not a bounded label — it is the absence of the argument, wearing
        # a quote.
        for name, value in (('resource_id', resource_id), ('rule_id', rule_id),
                            ('metric_name', metric_name), ('service', service),
                            ('artifact_sha256', artifact_sha256)):
            if value:
                arguments[name] = value
        return call('signal_series', **arguments)

    @expose('topology_neighbourhood')
    def topology_neighbourhood(resource_id: str, direction: Direction, depth: int = 2) -> list:
        """Read the declared neighbourhood of one resource."""
        return call('topology_neighbourhood', resource_id=resource_id, direction=direction, depth=depth)

    @expose('component_boundary')
    def component_boundary() -> list:
        """Read which capabilities this surface deliberately does not have."""
        return call('component_boundary')

    @expose('propose_action')
    def propose_action(retry_key: str, incident_id: str, action: str, version: str, targets: list,
                       parameters: dict, evidence: list, expires_at: str) -> list:
        """File one approval request as the authenticated agent."""
        return call('propose_action', retry_key=retry_key, incident_id=incident_id, action=action,
                    version=version, targets=targets, parameters=parameters, evidence=evidence,
                    expires_at=expires_at)

    @expose('execute_action')
    def execute_action(action_id: str) -> list:
        """Refuse execution until a trusted runner handoff exists, preserving approval."""
        return call('execute_action', action_id=action_id)

    # The registry is the source of truth, and this module spells each tool out because the SDK builds a
    # tool's input schema from a real signature and will not take a generated one. The cost of spelling
    # it twice is drift, so one direction is refused here — a registered tool with no wrapper is a boot
    # failure, never a silent gap — and the other direction (a wrapper the registry never named, which
    # `expose` above leaves unregistered) is pinned by name in `tests/test_mcp_surface.py`.
    unexposed = sorted(set(registry.names()) - exposed)
    if unexposed:
        raise tools.ToolRefusal(f'This transport exposes no wrapper for: {", ".join(unexposed)}')

    async def app(scope: dict, receive: Callable[..., Awaitable[Any]],
                  send: Callable[..., Awaitable[None]]) -> None:
        """Gate one request on its bearer credential, bind the agent it names, and hand the message over."""
        if scope['type'] != 'http':
            await transport(scope, receive, send)
            return
        values = [value for key, value in scope.get('headers', []) if key.lower() == b'authorization']
        agent = authorize(table, values[0] if len(values) == 1 else None)
        if agent is None:
            await _unauthorised(send)
            return
        body = b''
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            body += message.get('body', b'')
            if len(body) > MAX_REQUEST_BYTES:
                await send({'type': 'http.response.start', 'status': 413, 'headers': []})
                await send({'type': 'http.response.body', 'body': b''})
                return
            if not message.get('more_body'):
                break
        bound = _CALLING_AGENT.set(agent)

        async def bounded_receive() -> dict:
            """Hand the SDK the whole body once, then stay out of the way."""
            if not consumed[0]:
                consumed[0] = True
                return {'type': 'http.request', 'body': body, 'more_body': False}
            return await receive()

        consumed = [False]
        try:
            await transport(scope, bounded_receive, send)
        finally:
            # Reset, never leave set: a worker that reuses this task's context for a later request must
            # not find the previous caller's credential still bound to it.
            _CALLING_AGENT.reset(bound)

    return app, server


def create_server(client: JsonClient, token: str) -> tuple[Callable[..., Awaitable[None]], FastMCP]:
    """Build the v0.1 single-token reader surface: one shared bearer, four reads, no action pair.

    Args:
        client: The platform API client this facade reads through — a reader-role credential, and the
            only credential this process holds.
        token: The bearer an agent presents here. At least 24 characters, never the platform credential:
            the two serve different edges.

    Returns:
        The ASGI app and its FastMCP server, as v0.1's callers already unpack them.

    Raises:
        ValueError: `token` is shorter than the estate-wide credential floor. A short shared token is
            this surface's whole trust boundary, so it is refused rather than logged about.
    """
    if len(token) < tools.MIN_TOKEN_LENGTH:
        raise ValueError('A dedicated MCP reader token is required')
    agent = Agent(identity='platform-reader', role='reader', client=client)
    return _serve([(token, agent)], tools.reader_registry())


def create_agent_server(table: Sequence[tuple[str, Agent]], *, reader: Any = None,
                        index_path: Any = None) -> tuple[Callable[..., Awaitable[None]], FastMCP]:
    """Build the per-agent surface: one agent, one credential, one identity the platform can name.

    Args:
        table: ``(bearer_token, Agent)`` pairs from :func:`local_observe.platform.tools.agent_table`.
            Empty or repeated is refused below rather than served.
        reader: A store reader to expose the bounded series read through, or ``None`` to leave that tool
            off the surface entirely.
        index_path: A built inventory index to walk for the topology read, or ``None`` to leave it off.

    Returns:
        The ASGI app and its FastMCP server.

    Raises:
        ToolRefusal: No agent is mounted, or two agents share a bearer (one credential naming two
            identities would make every audit row this surface writes a guess).
    """
    if not table:
        raise tools.ToolRefusal('The per-agent MCP surface needs at least one mounted agent')
    bearers = [bearer for bearer, _ in table]
    if len(set(bearers)) != len(bearers):
        raise tools.ToolRefusal('Two MCP agents share a bearer token')
    return _serve(table, tools.agent_registry(reader=reader, index_path=index_path))


def identities_with_clients(rows: Sequence[Identity], *, environ: Mapping[str, str]
                            ) -> list[tuple[str, Agent]]:
    """Build the transport table for mounted identity rows, one API client per identity.

    ``LO_PLATFORM_URL`` and ``LO_INTERNAL_ALLOW_HTTP`` mean exactly what they mean in the platform's own
    entry point: one endpoint, and cleartext only on an isolated network that says so. One client per
    identity is the point — the credential the platform sees is the agent's, which is what makes
    ``action.proposed`` name the agent that filed it.

    Args:
        rows: Validated rows from :func:`local_observe.platform.tools.read_identity_rows`.
        environ: The environment the endpoint is read from; a parameter for the same reason
            :func:`credential_source` takes one.

    Returns:
        The pairs for :func:`create_agent_server`.

    Raises:
        KeyError: ``LO_PLATFORM_URL`` is unset.
        TransportError: An endpoint or credential is one the bounded client will not accept — including
            a platform URL that is cleartext without ``LO_INTERNAL_ALLOW_HTTP=1``.
    """
    url = environ['LO_PLATFORM_URL']
    allow_http = environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
    return agent_table(rows, {row.identity: JsonClient(url, row.platform_token, allow_http=allow_http)
                              for row in rows})


def app_factory() -> Callable[..., Awaitable[None]]:
    """Return the ASGI app this process was configured to serve, or refuse loudly at boot.

    Read in this order, because the order is the set of boot refusals: the credential source (a process
    configured two ways, or with a value in the environment instead of a file, is not started), then the
    endpoint, then the credentials themselves, and only then the optional capabilities. A store reader is
    detected rather than assumed — :func:`local_observe.platform.query.open_reader` answers ``None`` with
    one log line and no exception, and the series read is then *absent from the surface* rather than
    present and answering "unconfigured".

    Returns:
        The app to serve under ``uvicorn --factory``.

    Raises:
        ToolRefusal: The credential source is ambiguous, blank, unreadable or malformed.
        KeyError: ``LO_PLATFORM_URL`` is unset.
        OSError: A mounted credential file is missing.
    """
    kind, path = credential_source(os.environ)
    if kind == 'legacy':
        client = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_READER_TOKEN'),
                            allow_http=os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1')
        return create_server(client, read_credential_file(path, what='MCP reader token'))[0]
    rows = read_identity_rows(path)
    table = identities_with_clients(rows, environ=os.environ)
    from local_observe.platform import query as platform_query
    return create_agent_server(table, reader=platform_query.open_reader(),
                               index_path=os.environ.get('LO_INDEX_PATH') or None)[0]

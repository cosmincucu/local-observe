"""mcp tool surface: the tool registry, the per-agent map and the one gated action pair — no SDK needed.

Everything here runs in the base-dependency tier (``.gitea/workflows/ci.yml`` asserts
``importlib.util.find_spec('mcp') is None`` for it), because ``local_observe/platform/tools.py``
deliberately imports no SDK: what an agent may ask for, what it gets back and which role may file what is
decided in that module, so it is provable without the transport. The transport's own shape — the bearer
gate, the two content blocks, the tool list a client actually sees — is ``tests/test_mcp_surface.py``.

The action lifecycle rules are not re-derived here. ``tests/test_action_invariants.py`` owns them at the
state layer and at the HTTP edge: ``test_agent_principal_cannot_approve_any_action``,
``test_read_credentials_cannot_approve_or_execute``, ``test_expired_approval_blocks_a_new_dispatch``,
``test_second_claim_of_one_action_is_refused``. This file verifies the tool role gates, and that execution
refuses without consuming approval while no trusted runner handoff exists.

The fixture is honest on purpose: a real ``Store``, a real inventory index, a real ``create_app`` and the
platform's own role list. ``ApiBridge`` replaces the network and nothing else; local execution refusals
are also checked to make no request to that service.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import httpx

from local_observe.inventory import index as inventory_index
from local_observe.inventory.validation import read_document
from local_observe.platform import tools
from local_observe.platform.api import create_app
from local_observe.platform.detections import event as detection_event
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, Store
from local_observe.store.backends.memory import InMemoryStore, series

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime.now(dt.timezone.utc)
PAST = NOW - dt.timedelta(hours=3)
PRODUCER = Actor('gatus', 'producer')
HUMAN_TOKEN = 'human-credential-for-these-tests-00001'
#: The mounted identity of each agent role, spelled as a deployment would spell it in its map: the
#: provenance `source` and the durable audit actor are these names, not the role.
MOUNTED = {'reader': 'agent-read', 'proposer': 'agent-ask', 'executor': 'agent-run'}
# A credential-shaped string planted in every fake answer below: the scan at the end of this file fails
# if one ever reaches a tool result.
PLANTED = 'runner-secret-abcdef0123456789ABCDEF'

DECLARED = read_document(ROOT / 'examples/inventory/declared.yaml')
HOST = DECLARED['resources'][0]['id']

#: The minimal argument set each read tool needs, so the provenance table drives *every* registered read
#: and not the subset that happens to take no arguments. A new read with no row here fails that test.
READ_ARGUMENTS: dict[str, dict[str, Any]] = {
    'platform_status': {},
    'platform_overview': {},
    'records': {'table': 'incidents'},
    'inventory': {},
    'evidence_window': {'source': 'gatus', 'sample_id': 'fixture-0'},
    'signal_series': {'signal': 'metrics', 'resource_id': HOST, 'rule_id': 'availability'},
    'topology_neighbourhood': {'resource_id': HOST, 'direction': 'impact'},
    'component_boundary': {},
}


class ApiBridge:
    """A `JsonClient`-shaped reader and writer of the real application, for a synchronous tool handler."""

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    def request(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
        """Perform one in-process request and return ``(status_code, decoded body)``."""
        async def go() -> tuple[int, Any]:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                         base_url='http://platform.invalid') as client:
                response = await client.request(method, path, json=payload,
                                                headers={'Authorization': 'Bearer ' + self.token})
                return response.status_code, response.json()
        return asyncio.run(go())


class Platform:
    """One disposable platform, its inventory index, and the role list a deployment would mount."""

    def __init__(self, *, reader: Any = None) -> None:
        """Build the state database, a built index and the authenticated app over them."""
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index_path = root / 'inventory.db'
        inventory_index.build(declared, self.index_path, 'fixture', now=PAST)
        self.store = Store(root / 'state.db')
        self.policy = action_policy(self.index_path, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        self.tokens = {'reader': 'reader-credential-for-these-tests-00',
                       'proposer': 'proposer-credential-for-these-tests-0',
                       'executor': 'executor-credential-for-these-tests-00'}
        self.app = create_app(self.store, [
            {'identity': 'gatus', 'role': 'producer', 'token': 'producer-credential-for-tests-0000001'},
            {'identity': 'portal', 'role': 'summary', 'token': 'summary-credential-for-tests-00000001'},
            {'identity': 'agent-read', 'role': 'reader', 'token': self.tokens['reader']},
            {'identity': 'agent-ask', 'role': 'proposer', 'token': self.tokens['proposer']},
            {'identity': 'agent-run', 'role': 'executor', 'token': self.tokens['executor']},
            {'identity': 'operator', 'role': 'human', 'token': HUMAN_TOKEN}], self.policy,
            index_path=self.index_path)
        self.reader = reader
        self.sequence = 0

    def next_key(self) -> str:
        """Return a fresh ``retry_key``: every fixture action must be its own request, not a retry.

        ``retry_key`` is unique per requester by design, so two fixtures that happened to share one key
        would silently collapse into one action and the test that read "approved" would be reading a row
        another test filed.
        """
        self.sequence += 1
        return f'fixture-{self.sequence}'

    def close(self) -> None:
        """Remove the state file and the index behind one fixture."""
        self.temp.cleanup()

    def bridge(self, role: str) -> ApiBridge:
        """One client, holding exactly one mounted agent role's credential."""
        return ApiBridge(self.app, self.tokens[role])

    def agent(self, role: str) -> tools.Agent:
        """The registry's view of that agent, under the name its map mounts it as."""
        return tools.Agent(identity=MOUNTED[role], role=role, client=self.bridge(role))

    def registry(self) -> tools.ToolRegistry:
        """The full per-agent surface, with the capabilities this deployment mounted."""
        return tools.agent_registry(reader=self.reader, index_path=self.index_path)

    def open_incident(self, minute: int = 0) -> dict[str, Any]:
        """File one firing event at the fixture's past clock and return what the store accepted."""
        return self.store.intake(self.firing(minute), PRODUCER, now=PAST + dt.timedelta(minutes=minute))

    def firing(self, minute: int = 0, status: str = 'firing') -> dict[str, Any]:
        """Build one availability event for the example host, stamped in the fixture's past."""
        end = PAST + dt.timedelta(minutes=minute)
        window = {'start': (end - dt.timedelta(minutes=1)).isoformat(), 'end': end.isoformat()}
        return detection_event(PRODUCER.identity, HOST, 'availability', 'availability', status, window,
                               {'sample_id': f'fixture-{minute}'}, query_type='gatus-result')

    def proposal(self, *, role: str = 'proposer', minute: int = 0, retry_key: str = 'once',
                 expires: dt.timedelta = dt.timedelta(hours=10)) -> dict[str, Any]:
        """File one tool proposal as `role` and return the tool's own answer."""
        incident = self.open_incident(minute=minute)
        result = self.registry().invoke('propose_action', self.agent(role), {
            'retry_key': retry_key, 'incident_id': incident['incident_id'], 'action': 'inspect',
            'version': '1', 'targets': [HOST], 'parameters': {}, 'evidence': [incident['event_id']],
            'expires_at': (PAST + expires).isoformat()})
        return {**result.data, '_incident': incident['incident_id'], '_event': incident['event_id']}

    def approved(self, *, expires: dt.timedelta = dt.timedelta(hours=15),
                 expires_claim: bool = False) -> str:
        """Put one approved action on record and return its id, filed at the fixture's own clock.

        Why the filing goes straight to ``Store`` here rather than through the tool: the lifecycle routes
        call ``state.clock()`` and so judge expiry against the wall clock, and an approval that has
        *already* aged out cannot be arranged against a real clock without sleeping through it. Filing and
        deciding at ``PAST`` (the same move ``tests/test_action_invariants.py``'s fixture makes) leaves a
        row durably ``approved`` with an expiry in the past, which is the state under test — and the claim
        is subsequently judged by the runner's direct platform claim on the real clock.

        Args:
            expires: How long after ``PAST`` the offer lapses; ignored when ``expires_claim`` is set.
            expires_claim: ``True`` puts the lapse in the past, so a claim must answer ``expired``.
        """
        incident = self.open_incident()
        lapse = PAST + (dt.timedelta(minutes=30) if expires_claim else expires)
        retry_key = f'{"aged" if expires_claim else "live"}-{self.next_key()}'
        action_id = self.store.propose_action(
            {'retry_key': retry_key, 'incident_id': incident['incident_id'], 'action': 'inspect',
             'version': '1', 'targets': [HOST], 'parameters': {}, 'evidence': [incident['event_id']],
             'expires_at': lapse.isoformat()},
            Actor('agent-ask', 'proposer'), self.policy, now=PAST)['action_id']
        self.store.decide(action_id, 'approved', Actor('operator', 'human'), now=PAST)
        if self.action_row(action_id)['status'] != 'approved':
            raise AssertionError('the fixture did not produce an approved action to claim')
        return action_id

    def approve(self, action_id: str) -> tuple[int, Any]:
        """Decide with the human credential, over the same edge an agent reaches."""
        return self.call('POST', '/v1/actions/decision', {'action_id': action_id,
                                                         'decision': 'approved'}, HUMAN_TOKEN)

    def call(self, method: str, path: str, body: Any, token: str) -> tuple[int, Any]:
        """One raw request, for the cases the surface has no tool for."""
        return ApiBridge(self.app, token).request(method, path, body)

    def action_row(self, action_id: str) -> dict[str, Any]:
        """The durable action row behind one id."""
        return next(row for row in self.store.records('actions', 100) if row['id'] == action_id)

    def executions(self) -> list[dict[str, Any]]:
        """Every execution row this platform holds."""
        return self.store.records('executions', 100)

    def operations(self, operation: str) -> list[dict[str, Any]]:
        """Every audit row carrying one operation."""
        return [row for row in self.store.records('audit', 100) if row['operation'] == operation]


class PlatformTestCase(unittest.TestCase):
    """One platform per test, cleaned up through the TestCase rather than left behind."""

    def fixture(self, *, reader: Any = None) -> Platform:
        platform = Platform(reader=reader)
        self.addCleanup(platform.close)
        return platform


# ------------------------------------------------------------------ the registry's own refusals


class RegistryDeclarationTests(PlatformTestCase):
    """A tool that cannot describe its bounds is not registered, and nothing else is either."""

    def test_the_reader_surface_is_the_four_reads_v0_1_shipped(self) -> None:
        """The single-token surface is pinned to four names, in order, and to nothing else."""
        self.assertEqual(tools.reader_registry().names(),
                         ('platform_status', 'platform_overview', 'records', 'inventory'))

    def test_the_agent_surface_adds_the_two_new_reads_the_boundary_and_one_action_pair(self) -> None:
        """Ten tools, and the set is the whole claim of what this surface can do."""
        names = tools.agent_registry(reader=object(), index_path='index.db').names()
        self.assertEqual(set(names), {'platform_status', 'platform_overview', 'records', 'inventory',
                                      'evidence_window', 'signal_series', 'topology_neighbourhood',
                                      'component_boundary', 'propose_action', 'execute_action'})
        self.assertEqual([name for name in names if name.endswith('_action')],
                         ['propose_action', 'execute_action'],
                         'exactly one pair, in lifecycle order (chat integration)')

    def test_a_capability_that_is_not_mounted_is_not_advertised(self) -> None:
        """An unmounted store reader or index leaves its tool off the surface entirely.

        This is the difference between "no data" and "no path to data": a registered tool that answers the
        second as the first is the false-completeness defect this repository has already been bitten by,
        and an agent cannot tell the two apart from the outside.
        """
        bare = tools.agent_registry().names()
        self.assertNotIn('signal_series', bare)
        self.assertNotIn('topology_neighbourhood', bare)
        self.assertIn('evidence_window', bare, 'the platform API is the facade itself, always mounted')

    def test_a_tool_cannot_be_registered_twice_or_under_an_impossible_declaration(self) -> None:
        registry = tools.ToolRegistry()
        hints = tools.ToolHints('read', ('reader',))
        registry.register('one', lambda agent: tools.ToolResult(
            {}, tools.Provenance('platform-status', {'shape': 'counts'}, None, agent.identity)),
            hints, description='one')
        with self.assertRaisesRegex(tools.ToolRefusal, 'registered twice'):
            registry.register('one', lambda agent: None, hints, description='again')
        with self.assertRaisesRegex(tools.ToolRefusal, 'no handler'):
            registry.register('two', None, hints, description='two')  # type: ignore[arg-type]
        with self.assertRaisesRegex(tools.ToolRefusal, 'Unknown tool capability'):
            tools.ToolHints('write', ('reader',))
        with self.assertRaisesRegex(tools.ToolRefusal, 'subset'):
            tools.ToolHints('read', ('human',))
        with self.assertRaisesRegex(tools.ToolRefusal, 'read-only'):
            tools.ToolHints('propose', ('proposer',), read_only=True)
        with self.assertRaisesRegex(tools.ToolRefusal, 'is destructive'):
            tools.ToolHints('execute', ('executor',), read_only=False, destructive=True)
        with self.assertRaisesRegex(tools.ToolRefusal, 'must describe itself'):
            tools.Tool('three', '', hints, lambda agent: None)
        with self.assertRaisesRegex(tools.ToolRefusal, 'declares an argument twice'):
            tools.Tool('four', 'four', hints, lambda agent: None,
                       (tools.Argument('x', 'label', 'one'), tools.Argument('x', 'label', 'two')))

    def test_invoking_an_unnamed_or_misshapen_request_is_refused_before_anything_runs(self) -> None:
        """Unknown tool, unknown argument, missing argument, wrong shape: four refusals, no request made."""
        platform = self.fixture()
        registry = platform.registry()
        counting = CountingDouble()
        agent = tools.Agent(identity='agent-read', role='reader', client=counting)
        for name, arguments, message in (
                ('do_anything', {}, 'Unknown tool'),
                ('platform_status', {'sql': 'select 1'}, 'accepts no argument'),
                ('evidence_window', {'source': 'gatus'}, 'requires argument'),
                ('platform_status', ['not an object'], 'must be a JSON object'),
                ('records', {'table': 'users'}, 'must be one of'),
                ('records', {'table': 'events', 'limit': 5000}, 'must be 1..20'),
                ('records', {'table': 'events', 'limit': True}, 'must be an integer'),
                ('topology_neighbourhood', {'resource_id': 'not-a-uuid', 'direction': 'upstream'},
                 'not a valid bounded value'),
                ('evidence_window', {'source': 'gatus', 'sample_id': 'two words'},
                 'not a valid bounded value')):
            with self.subTest(tool=name, arguments=arguments):
                with self.assertRaisesRegex(tools.ToolRefusal, message):
                    registry.invoke(name, agent, arguments)
        self.assertEqual(counting.calls, [], 'a refusal that cost a request is not a refusal')

    def test_the_action_arguments_are_bounded_where_the_state_layer_bounds_them(self) -> None:
        """20 targets, 20 evidence rows, 8 KiB of parameters, an aware timestamp: none invented here."""
        platform = self.fixture()
        registry = platform.registry()
        agent = platform.agent('proposer')
        incident = platform.open_incident()
        base = {'incident_id': incident['incident_id'], 'action': 'inspect', 'version': '1',
                'parameters': {}, 'retry_key': 'bounded', 'evidence': [incident['event_id']],
                'targets': [HOST], 'expires_at': (PAST + dt.timedelta(hours=2)).isoformat()}

        def refuse(**extra: Any) -> str:
            arguments = {**base, **extra}
            with self.assertRaises(tools.ToolRefusal) as caught:
                registry.invoke('propose_action', agent, arguments)
            return str(caught.exception)

        self.assertIn('1..20', refuse(targets=[HOST] * 21))
        self.assertIn('1..20', refuse(evidence=[incident['event_id']] * 21))
        self.assertIn('8 KiB', refuse(parameters={'blob': 'x' * 9000}))
        self.assertIn('timezone-aware', refuse(expires_at='2026-09-09T12:00:00'))
        self.assertIn('list of 1..20', refuse(targets=HOST))
        self.assertIn('not a valid bounded value', refuse(targets=[HOST, 'later']))

    def test_no_argument_of_any_tool_is_free_text(self) -> None:
        """Every declared string is a canonical UUID or a `state.label`: no query, no URL, no clause."""
        for descriptor in tools.agent_registry(reader=object(), index_path='index.db').descriptors():
            for argument in descriptor['arguments']:
                with self.subTest(tool=descriptor['name'], argument=argument['name']):
                    self.assertIn(argument['kind'], tools.ARGUMENT_KINDS)
                    self.assertNotIn(argument['name'], {'query', 'sql', 'statement', 'where', 'url',
                                                        'uri', 'expr', 'fragment', 'path', 'expression'})
                    if argument['kind'] == 'enumeration':
                        self.assertTrue(argument['values'])
        # The label alphabet is what makes that a property of the type rather than a list of banned words:
        # no `/`, no space and no quote, so a URL and a clause are both unrepresentable.
        for rejected in ('http://example.invalid/x', 'a b', "events' OR 1=1 --", '/etc/passwd'):
            self.assertIsNone(tools.LABEL_PATTERN.fullmatch(rejected), rejected)

    def test_records_names_only_the_tables_the_store_already_admits(self) -> None:
        """The table vocabulary is ``state.Store.records``' own, minus one widening this item did not ask for."""
        declared = next(item for item in tools.reader_registry().descriptors()
                        if item['name'] == 'records')['arguments'][0]
        self.assertEqual(declared['values'], list(tools.RECORD_TABLES))
        self.assertEqual(set(tools.RECORD_TABLES),
                         {'incidents', 'events', 'actions', 'executions', 'outbox', 'audit'})
        self.assertNotIn('notification_attempts', tools.RECORD_TABLES,
                         'v0.1 never let an agent name it, and widening a read is its own review')


class ProvenanceTests(PlatformTestCase):
    """Every answer says where it came from, or it is not a tool result."""

    def test_every_read_tool_answers_with_a_reauthorisable_provenance(self) -> None:
        """Table-driven over `descriptors()`: a new read with no row above fails here, not in review."""
        platform = self.fixture(reader=seeded_store())
        registry = platform.registry()
        reads = [item['name'] for item in registry.descriptors() if item['capability'] == 'read']
        self.assertEqual(set(reads), set(READ_ARGUMENTS),
                         'every read tool needs a minimal argument set in READ_ARGUMENTS')
        for name in reads:
            with self.subTest(tool=name):
                result = registry.invoke(name, platform.agent('reader'), READ_ARGUMENTS[name])
                provenance = result.provenance.as_dict()
                self.assertEqual(set(provenance), set(tools.PROVENANCE_KEYS))
                self.assertIn(provenance['query_type'], tools.PROVENANCE_QUERY_TYPES)
                self.assertEqual(provenance['source'], 'agent-read',
                                 'whose read it was belongs to the evidence, not to the answer')
                self.assertTrue(provenance['parameters'])
                for key, value in provenance['parameters'].items():
                    self.assertIsNotNone(tools.LABEL_PATTERN.fullmatch(key), key)
                    self.assertIsNotNone(tools.LABEL_PATTERN.fullmatch(value),
                                         f'{key}={value}: never a path, a URL or a statement')
                self.assertTrue(tools.timestamp(provenance['read_at']).tzinfo)
                if name == 'signal_series':
                    self.assertEqual(set(provenance['window'] or {}), {'start', 'end'})
                    self.assertTrue(result.data['rows'], 'the seeded series should have answered')
                    self.assertIsNone(result.data['error'])
                elif name != 'signal_series':
                    self.assertIsNone(provenance['window'],
                                      'a count, an index or a walk has no window, and says so')

    def test_an_explicit_empty_is_the_answer_a_read_gives_when_there_is_nothing(self) -> None:
        """An empty table and an absent evidence row are both answered, in shape, not omitted.

        The series read is deliberately *not* in this test: an empty window there is a measured absence
        (``unavailable`` plus the store's own reason), which is the opposite of an empty success and is
        pinned in :meth:`SeriesReadTests.test_a_window_with_no_samples_is_a_measured_absence`.
        """
        platform = self.fixture()
        records = platform.registry().invoke('records', platform.agent('reader'), {'table': 'incidents'})
        self.assertEqual(records.data['rows'], [])
        evidence = platform.registry().invoke('evidence_window', platform.agent('reader'),
                                              {'source': 'gatus', 'sample_id': 'fixture-absent'})
        self.assertEqual(evidence.data, {'status': 'unavailable'})
        status = platform.registry().invoke('platform_status', platform.agent('reader'), {})
        self.assertEqual(status.data['incidents'], {}, 'a count of nothing is an empty mapping, not a gap')

    def test_the_action_pair_carries_provenance_too(self) -> None:
        platform = self.fixture()
        result = platform.registry().invoke('propose_action', platform.agent('proposer'), proposal_arguments(
            platform, platform.open_incident()))
        self.assertEqual(set(result.provenance.as_dict()), set(tools.PROVENANCE_KEYS))
        self.assertEqual(result.provenance.query_type, 'action-propose')

    def test_a_provenance_that_could_not_be_reauthorised_is_refused(self) -> None:
        cases = (
            (lambda: tools.Provenance('select * from events', {'shape': 'counts'}, None, 'agent'),
             'not one this surface names'),
            (lambda: tools.Provenance('platform-status', {'route': '/v1/status'}, None, 'agent'),
             'bounded label'),
            (lambda: tools.Provenance('platform-status', {}, None, 'agent'), '1..10 bounded values'),
            (lambda: tools.Provenance('platform-status', {'shape': 'counts'},
                                      {'start': '2026-09-09T12:00:00+00:00'}, 'agent'), 'start and end'),
            (lambda: tools.Provenance('platform-status', {'shape': 'counts'},
                                      {'start': '2026-09-09T12:01:00+00:00',
                                       'end': '2026-09-09T12:00:00+00:00'}, 'agent'), 'start < end'),
            (lambda: tools.Provenance('platform-status', {'shape': 'counts'}, None, 'not a label!'),
             'source'),
            (lambda: tools.Provenance('platform-status', {'shape': 'counts'}, None, 'agent',
                                      read_at='yesterday'), 'stamp'),
        )
        for build, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(tools.ToolRefusal, message):
                    build()

    def test_a_result_without_provenance_is_not_representable(self) -> None:
        with self.assertRaisesRegex(tools.ToolRefusal, 'carries provenance'):
            tools.ToolResult({'rows': []}, None)  # type: ignore[arg-type]

    def test_the_evidence_budget_refusal_is_the_one_v0_1_already_sent(self) -> None:
        """64 KiB stays the ceiling, and the sentence a reader already knows is unchanged."""
        self.assertEqual(tools.EVIDENCE_BUDGET_REFUSAL,
                         'Read exceeds evidence budget; use a smaller result limit')
        platform = self.fixture()
        agent = tools.Agent(identity='agent-read', role='reader',
                            client=StatusDouble(200, {'blob': 'x' * (tools.MAX_RESULT_BYTES + 1)}))
        with self.assertRaisesRegex(tools.ToolRefusal, 'Read exceeds evidence budget'):
            platform.registry().invoke('platform_status', agent, {})

    def test_a_read_that_did_not_answer_is_never_reported_as_an_empty_document(self) -> None:
        """"The platform did not answer" and "the platform answered with nothing" stay two answers."""
        platform = self.fixture()
        for code in (503, 403, 404):
            with self.subTest(code=code):
                agent = tools.Agent(identity='agent-read', role='reader',
                                    client=StatusDouble(code, {'error': 'unavailable'}))
                for tool in ('inventory', 'platform_status', 'platform_overview'):
                    with self.assertRaisesRegex(tools.ToolRefusal, 'Platform read unavailable'):
                        platform.registry().invoke(tool, agent, {})

    def test_an_evidence_row_that_is_not_there_is_answered_as_unavailable(self) -> None:
        """``state.Store.get_evidence``'s own word, carried through the tool rather than invented."""
        platform = self.fixture()
        self.assertEqual(platform.call('GET', '/v1/evidence?source=gatus&sample_id=missing-0', None,
                                       platform.tokens['reader'])[1]['status'], 'unavailable')
        result = platform.registry().invoke('evidence_window', platform.agent('reader'),
                                            {'source': 'gatus', 'sample_id': 'missing-0'})
        self.assertEqual(result.data['status'], 'unavailable')


class SeriesReadTests(PlatformTestCase):
    """The bounded series read store facade makes possible, and the refusals that keep it bounded."""

    def test_the_read_goes_through_the_facade_envelope_and_names_its_window(self) -> None:
        platform = self.fixture(reader=seeded_store())
        result = platform.registry().invoke('signal_series', platform.agent('reader'),
                                            READ_ARGUMENTS['signal_series'])
        self.assertEqual(list(result.data), ['source', 'query_type', 'parameters', 'window', 'rows',
                                             'row_limit', 'truncated', 'error'])
        self.assertEqual(result.data['query_type'], 'metric-threshold')
        self.assertEqual(len(result.data['rows']), 4)
        self.assertEqual(result.data['source'], 'agent-read')
    def test_a_request_the_facade_refuses_is_reported_and_not_answered_away(self) -> None:
        """A metric read with no rule is a refusal inside the envelope, never an empty window."""
        platform = self.fixture(reader=seeded_store())
        arguments = {key: value for key, value in READ_ARGUMENTS['signal_series'].items()
                     if key != 'rule_id'}
        result = platform.registry().invoke('signal_series', platform.agent('reader'), arguments)
        self.assertEqual(list(result.data['rows']), [])
        self.assertIsNotNone(result.data['error'])
        self.assertIn('rule_id', str(result.data['error']))

    def test_the_unmounted_reader_is_refused_even_if_a_handler_is_called_directly(self) -> None:
        """The registration gate is the brace; this is the belt beside it."""
        platform = self.fixture()
        with self.assertRaisesRegex(tools.ToolRefusal, 'No read-only store client'):
            tools.series_tool(platform.agent('reader'), reader=None, signal='metrics',
                              resource_id=HOST, rule_id='availability')

    def test_a_window_with_no_samples_is_a_measured_absence(self) -> None:
        """Empty rows plus the store's own reason: never silence, and never an empty success.

        ``store.client`` answers "this series produced nothing in the window" by asking the matching
        describe read, so the tool carries the verdict it was given. The distinction is the whole
        anti-fabrication rule of the port: an agent that reads ``rows: []`` with no ``error`` would
        conclude the metric was flat, and one that reads this knows the store never saw the series.
        """
        platform = self.fixture(reader=seeded_store())
        registry = platform.registry()
        with self.assertRaisesRegex(tools.ToolRefusal, 'must be 1..10080'):
            registry.invoke('signal_series', platform.agent('reader'),
                            {**READ_ARGUMENTS['signal_series'], 'minutes': 99999})
        result = registry.invoke('signal_series', platform.agent('reader'),
                                 {**READ_ARGUMENTS['signal_series'], 'minutes': 5})
        self.assertEqual(list(result.data['rows']), [], 'the seeded stamps sit outside five minutes')
        self.assertIsNotNone(result.data['error'])
        self.assertIn('unavailable', str(result.data['error']))


class TopologyReadTests(PlatformTestCase):
    """The upstream/impact read topology read model makes possible, with its completeness bounds intact."""

    def test_the_walk_reports_the_bound_that_cut_it_off(self) -> None:
        platform = self.fixture()
        result = platform.registry().invoke('topology_neighbourhood', platform.agent('reader'),
                                            READ_ARGUMENTS['topology_neighbourhood'])
        self.assertIn('truncated_by', result.data)
        self.assertIn('direction', result.data)
        self.assertEqual(result.provenance.parameters['direction'], 'impact')

    def test_an_undeclared_resource_is_refused_rather_than_answered_as_a_bare_neighbourhood(self) -> None:
        """The one difference between "nothing depends on this" and "this is not a resource"."""
        platform = self.fixture()
        with self.assertRaisesRegex(tools.ToolRefusal, 'Topology read refused'):
            platform.registry().invoke('topology_neighbourhood', platform.agent('reader'),
                                       {'resource_id': '00000000-0000-4000-8000-000000000000',
                                        'direction': 'upstream'})

    def test_no_index_mounted_means_no_walk(self) -> None:
        with self.assertRaisesRegex(tools.ToolRefusal, 'No inventory index'):
            tools.topology_tool(tools.Agent(identity='agent-read', role='reader',
                                            client=StatusDouble(200, {})), index_path=None,
                                resource_id=HOST, direction='upstream')


class BoundaryTests(PlatformTestCase):
    """The documented passthrough: what this surface declines, and where the work belongs."""

    def test_the_boundary_names_the_adopted_components_and_the_private_overlay(self) -> None:
        platform = self.fixture()
        answer = platform.registry().invoke('component_boundary', platform.agent('reader'), {}).data
        self.assertEqual(answer['schema_version'], 1)
        self.assertEqual(set(answer['capabilities']), set(tools.COMPONENT_BOUNDARY))
        for name, entry in answer['capabilities'].items():
            with self.subTest(capability=name):
                self.assertEqual(set(entry), {'owner', 'this_surface', 'declines'})
                self.assertTrue(entry['declines'].strip(), 'a decline with no reason is a gap')

    def test_the_boundary_carries_no_estate_identifier_and_no_url(self) -> None:
        """agent delivery pipeline, checked on the bytes an agent receives rather than on a comment."""
        platform = self.fixture()
        text = json.dumps(platform.registry().invoke('component_boundary',
                                                    platform.agent('reader'), {}).data)
        for token in ('example-site', 'private-address-marker', 'storage-host', 'worker-host', 'notification-bot', 'openbao', 'deployment-config',
                      'admin-host', '/srv/observe', 'example-operator', 'spark'):
            self.assertNotIn(token, text)
        self.assertNotIn('http://', text)
        self.assertNotIn('https://', text)


class PerAgentCredentialTests(unittest.TestCase):
    """Static per-agent bearer tokens (chat integration), refused loudly when the map is anything but exact."""

    @staticmethod
    def row(index: int = 0, **changes: Any) -> dict[str, Any]:
        base = {'identity': f'agent{index}', 'role': 'reader',
                'bearer_token': f'bearer{index}-0123456789abcdef0123456789',
                'platform_token': f'platform{index}-0123456789abcdef0123456789'}
        base.update(changes)
        return base

    def test_a_well_formed_map_yields_one_row_per_agent(self) -> None:
        rows = tools.identity_rows([self.row(), self.row(1, role='proposer'), self.row(2, role='executor')])
        self.assertEqual([row.identity for row in rows], ['agent0', 'agent1', 'agent2'])
        self.assertEqual([row.role for row in rows], ['reader', 'proposer', 'executor'])

    def test_a_described_row_names_the_agent_and_never_a_credential(self) -> None:
        row = tools.identity_rows([self.row()])[0]
        self.assertEqual(row.described(), {'identity': 'agent0', 'role': 'reader'})
        self.assertNotIn('bearer', json.dumps(row.described()))

    def test_a_human_producer_or_summary_row_is_refused_with_its_own_reason(self) -> None:
        for role, marker in (('human', 'human-role credential may not be handed'),
                             ('producer', 'event producer'), ('summary', 'may not write')):
            with self.subTest(role=role):
                with self.assertRaisesRegex(tools.ToolRefusal, marker):
                    tools.identity_rows([self.row(role=role)])

    def test_an_unknown_role_is_refused_as_an_unknown_role(self) -> None:
        with self.assertRaisesRegex(tools.ToolRefusal, 'unknown role'):
            tools.identity_rows([self.row(role='owner')])

    def test_a_malformed_map_is_refused_without_repeating_anything_in_it(self) -> None:
        cases = {
            'not a list': {'identity': 'agent0'},
            'empty': [],
            'too many rows': [self.row(index) for index in range(tools.MAX_IDENTITIES + 1)],
            'row is not an object': ['bearer0'],
            'extra key': [self.row(extra='x')],
            'missing key': [{'identity': 'agent0', 'role': 'reader', 'bearer_token': 'y' * 26}],
            'short bearer': [self.row(bearer_token='too-short')],
            'control character': [self.row(platform_token='p' * 25 + '\r')],
            'unbounded identity': [self.row(identity='agent 0')],
            'repeated identity': [self.row(), self.row(1, identity='agent0')],
            'repeated bearer': [self.row(), self.row(1, bearer_token=self.row()['bearer_token'])],
            'bearer that is also a platform credential':
                [self.row(), self.row(1, platform_token=self.row()['bearer_token'])],
            'credential is not a string': [self.row(bearer_token=7)],
        }
        for name, document in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(tools.ToolRefusal) as caught:
                    tools.identity_rows(document)
                for secret in ('too-short', 'y' * 26, 'bearer0-0123456789abcdef0123456789'):
                    self.assertNotIn(secret, str(caught.exception))

    def test_authorize_matches_one_bearer_and_nothing_else(self) -> None:
        rows = tools.identity_rows([self.row(), self.row(1, role='proposer')])
        table = tools.agent_table(rows, {'agent0': object(), 'agent1': object()})
        self.assertEqual(tools.authorize(table, b'Bearer ' + rows[0].bearer_token.encode()).identity,
                         'agent0')
        self.assertEqual(tools.authorize(table, b'Bearer ' + rows[1].bearer_token.encode()).identity,
                         'agent1')
        for header in (None, b'', b'Bearer ', b'bearer ' + rows[0].bearer_token.encode(),
                       b'Bearer ' + rows[0].bearer_token.encode() + b' ',
                       b'Bearer ' + rows[0].bearer_token.encode()[:20],
                       b'Bearer ' + rows[1].bearer_token.encode()[:20],
                       'Bearer beärer0-x'.encode()):
            with self.subTest(header=header):
                self.assertIsNone(tools.authorize(table, header))

    def test_a_missing_client_for_a_mounted_row_is_refused(self) -> None:
        rows = tools.identity_rows([self.row()])
        with self.assertRaisesRegex(tools.ToolRefusal, 'No platform client'):
            tools.agent_table(rows, {})

    def test_the_credential_source_refuses_ambiguity_and_the_value_form(self) -> None:
        """One source, named by a path. Blank means "not configured", because the manifest says so."""
        mounted = {'LO_MCP_IDENTITIES': '/run/mcp/identities.json'}
        self.assertEqual(tools.credential_source(mounted), ('identities', '/run/mcp/identities.json'))
        legacy = {'LO_MCP_TOKEN_FILE': '/run/secrets/mcp-token'}
        self.assertEqual(tools.credential_source(legacy), ('legacy', '/run/secrets/mcp-token'))
        # The shipped manifest passes `${LO_MCP_IDENTITIES:-}`, so a blank value is the unset value: it
        # must not stop the deployment that has only a single token, and must not invent a map.
        self.assertEqual(tools.credential_source({'LO_MCP_IDENTITIES': '', **legacy}),
                         ('legacy', '/run/secrets/mcp-token'))
        for name, environ, message in (('both', {**mounted, **legacy}, 'exactly one MCP credential'),
                                       ('neither', {}, 'No MCP credential source'),
                                       ('blank both', {'LO_MCP_IDENTITIES': ' ', 'LO_MCP_TOKEN_FILE': ''},
                                        'No MCP credential source'),
                                       ('value form', {'LO_MCP_TOKEN': 'x' * 30}, 'LO_MCP_TOKEN is not read'),
                                       ('blank value form', {'LO_MCP_TOKEN': '', **legacy},
                                        'LO_MCP_TOKEN is not read')):
            with self.subTest(case=name):
                with self.assertRaisesRegex(tools.ToolRefusal, message):
                    tools.credential_source(environ)

    def test_read_credential_file_refuses_every_shape_that_is_a_mistake(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        big = root / 'big'
        big.write_bytes(b'x' * (tools.MAX_CREDENTIAL_BYTES + 1))
        empty = root / 'empty'
        empty.write_text('\n', encoding='utf-8')
        control = root / 'control'
        control.write_text('abc\rdef', encoding='utf-8')
        not_text = root / 'bytes'
        not_text.write_bytes(b'\xff\xfe\x00\x01')
        good = root / 'good'
        good.write_bytes(b'a-token-with-a-trailing-newline-0000\n')
        self.assertEqual(tools.read_credential_file(str(good)),
                         'a-token-with-a-trailing-newline-0000')
        for path, message in ((str(root), 'directory'), (str(big), 'exceeds'),
                              (str(empty), 'holds nothing'), (str(control), 'control character'),
                              (str(not_text), 'not UTF-8')):
            with self.subTest(path=path):
                with self.assertRaisesRegex(tools.ToolRefusal, message):
                    tools.read_credential_file(path)
        with self.assertRaises(OSError):
            tools.read_credential_file(str(root / 'absent'))

    def test_a_malformed_identity_file_is_refused_by_position_and_never_by_contents(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        broken = root / 'identities.json'
        secret = 'do-not-echo-this-credential-012345678'
        broken.write_text('[{"identity": "agent0", "bearer_token": "%s"}' % secret, encoding='utf-8')
        with self.assertRaises(tools.ToolRefusal) as caught:
            tools.read_identity_rows(str(broken))
        self.assertIn('line', str(caught.exception))
        self.assertNotIn(secret, str(caught.exception))
        folder = root / 'folder.json'
        folder.mkdir()
        with self.assertRaisesRegex(tools.ToolRefusal, 'directory'):
            tools.read_identity_rows(str(folder))
        wrong = root / 'wrong.json'
        wrong.write_text('[{"identity": "agent0", "role": "human", "bearer_token": "%s", '
                         '"platform_token": "%s"}]' % ('b' * 26, 'p' * 26), encoding='utf-8')
        with self.assertRaisesRegex(tools.ToolRefusal, 'human-role'):
            tools.read_identity_rows(str(wrong))

    def test_the_identity_map_binds_one_identity_to_one_credential(self) -> None:
        """A name used twice is a guess about who acted, so the map refuses it here.

        The transport's own two refusals (an empty table, two agents on one bearer) need the SDK to build
        and are held to in ``tests/test_mcp_surface.py``; this is the half that is provable in the base tier.
        """
        with self.assertRaisesRegex(tools.ToolRefusal, 'twice'):
            tools.identity_rows([self.row(), self.row(1, identity='agent0')])
        rows = tools.identity_rows([self.row(), self.row(1)])
        self.assertEqual([row.bearer_token for row in rows],
                         ['bearer0-0123456789abcdef0123456789',
                          'bearer1-0123456789abcdef0123456789'])


class ActionPairTests(PlatformTestCase):
    """Proposal and role gates, plus approval preservation when MCP cannot hand off execution."""

    def test_a_proposal_is_filed_as_the_agent_and_says_it_is_pending_a_human(self) -> None:
        """Behaviour 5: the answer names what happened, and what did not."""
        platform = self.fixture()
        answer = platform.proposal()
        self.assertEqual(answer['status'], 'pending')
        self.assertEqual(answer['outcome'], 'filed, pending human decision')
        self.assertEqual(answer['performed'], ['proposal recorded against the incident'])
        self.assertEqual(answer['not_performed'], ['approved', 'executed'])
        self.assertEqual(answer['filed_by'], 'agent-ask')
        self.assertEqual(answer['filed_by_role'], 'proposer')
        self.assertEqual(platform.action_row(answer['action_id'])['requester'], 'agent-ask',
                         'the durable requester is the bearer identity, never a payload field')
        self.assertEqual([row['actor'] for row in platform.operations('action.proposed')],
                         ['agent-ask'])

    def test_the_filing_is_idempotent_on_the_retry_key(self) -> None:
        """A retry may not become a second offer to approve."""
        platform = self.fixture()
        first = platform.proposal(retry_key='twice', minute=0)
        second = platform.proposal(retry_key='twice', minute=0)
        self.assertEqual(first['action_id'], second['action_id'])
        self.assertEqual(len([row for row in platform.store.records('actions', 100)
                              if row['id'] == first['action_id']]), 1)

    def test_an_agent_cannot_approve_its_own_proposal(self) -> None:
        """Behaviour 1, the surface's half.

        The state-layer and HTTP-edge halves are
        ``test_action_invariants.ActionInvariantTests.test_agent_principal_cannot_approve_any_action``
        and ``test_read_credentials_cannot_approve_or_execute``; nothing here re-implements them. What is
        ours is that the surface cannot even be *configured* with a credential that could decide: there is
        no decide tool, and `identity_rows` refuses the role that would have one.
        """
        platform = self.fixture()
        answer = platform.proposal()
        self.assertEqual(platform.action_row(answer['action_id'])['status'], 'pending')
        self.assertNotIn('decide_action', platform.registry().names())
        self.assertNotIn('approve_action', platform.registry().names())
        self.assertEqual(platform.call('POST', '/v1/actions/decision',
                                       {'action_id': answer['action_id'], 'decision': 'approved'},
                                       platform.tokens['proposer'])[0], 400)
        self.assertEqual(platform.action_row(answer['action_id'])['status'], 'pending')
        with self.assertRaisesRegex(tools.ToolRefusal, 'human-role credential may not be handed'):
            tools.identity_rows([PerAgentCredentialTests.row(role='human')])
        self.assertEqual(platform.approve(answer['action_id'])[0], 200,
                         'the gate is a role, not a refusal of everything')
        self.assertEqual(platform.action_row(answer['action_id'])['status'], 'approved')
        self.assertEqual([row['actor'] for row in platform.operations('action.approved')], ['operator'])

    def test_a_read_credential_cannot_propose_or_execute(self) -> None:
        """Behaviour 2: the refusal is a gate, not an absent tool, and it costs no request."""
        platform = self.fixture()
        registry = platform.registry()
        self.assertIn('propose_action', registry.names())
        self.assertIn('execute_action', registry.names())
        counting = CountingDouble()
        reader = tools.Agent(identity='agent-read', role='reader', client=counting)
        with self.assertRaisesRegex(tools.ToolRefusal, 'needs role proposer'):
            registry.invoke('propose_action', reader, proposal_arguments(platform,
                                                                         platform.open_incident()))
        with self.assertRaisesRegex(tools.ToolRefusal, 'needs role executor'):
            registry.invoke('execute_action', reader, {'action_id': HOST})
        self.assertEqual(counting.calls, [], 'a refusal that reached the platform would be a mutation')
        # And a proposer cannot use the executor's tool either: one role per tool of the pair.
        with self.assertRaisesRegex(tools.ToolRefusal, 'needs role executor'):
            registry.invoke('execute_action', platform.agent('proposer'), {'action_id': HOST})

    def test_an_expired_approval_is_left_for_the_runner_to_judge(self) -> None:
        platform = self.fixture()
        action_id = platform.approved(expires_claim=True)
        before = platform.action_row(action_id)
        with self.assertRaisesRegex(tools.ToolRefusal, 'no trusted runner handoff'):
            platform.registry().invoke('execute_action', platform.agent('executor'),
                                       {'action_id': action_id})
        self.assertEqual(platform.action_row(action_id), before)
        self.assertEqual(platform.executions(), [])
        code, result = platform.bridge('executor').request('POST', '/v1/actions/claim',
                                                          {'action_id': action_id})
        self.assertEqual((code, result['status']), (200, 'expired'))
        self.assertEqual(platform.executions(), [])

    def test_repeated_refusal_preserves_approval_and_existing_execution_rows(self) -> None:
        platform = self.fixture()
        existing = platform.approved()
        self.assertEqual(platform.bridge('executor').request('POST', '/v1/actions/claim',
                                                            {'action_id': existing})[0], 200)
        action_id = platform.approved()
        tables = ('actions', 'executions', 'audit')
        before = {table: platform.store.records(table, 100) for table in tables}
        for _ in range(3):
            with self.assertRaisesRegex(tools.ToolRefusal, 'no trusted runner handoff'):
                platform.registry().invoke('execute_action', platform.agent('executor'),
                                           {'action_id': action_id})
            self.assertEqual({table: platform.store.records(table, 100) for table in tables}, before)
        self.assertEqual(platform.action_row(action_id)['status'], 'approved')

    def test_execution_refuses_before_any_platform_request(self) -> None:
        counting = CountingDouble()
        agent = tools.Agent(identity='agent-run', role='executor', client=counting)
        with self.assertRaisesRegex(tools.ToolRefusal, 'no trusted runner handoff'):
            tools.agent_registry().invoke('execute_action', agent, {'action_id': HOST})
        with self.assertRaisesRegex(tools.ToolRefusal, 'no trusted runner handoff'):
            tools.execute_tool(agent, action_id=HOST)
        self.assertEqual(counting.calls, [])

    def test_dagu_can_complete_an_action_after_mcp_refuses_and_recover_without_redispatch(self) -> None:
        from local_observe.platform import dagu
        from test_action_invariants import FakeDagu, reviewed_binding

        platform = self.fixture()
        action_id = platform.approved()
        with self.assertRaises(tools.ToolRefusal):
            platform.registry().invoke('execute_action', platform.agent('executor'),
                                       {'action_id': action_id})
        engine = FakeDagu(lost_ack=True)
        binding = reviewed_binding([HOST])
        journal = platform.store.path.parent / 'runner.json'
        first = dagu.execute(platform.bridge('executor'), engine, action_id, binding, journal)
        self.assertEqual(first['status'], 'executing')
        engine.result = 'succeeded'
        # Recreated clients read the durable journal rather than trying a second claim or dispatch.
        result = dagu.execute(platform.bridge('executor'), engine, action_id, binding, journal)
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(dagu.execute(platform.bridge('executor'), engine, action_id, binding, journal), result)
        self.assertEqual(engine.starts, 1)
        self.assertEqual(len(platform.executions()), 1)
        self.assertEqual(platform.executions()[0]['status'], 'succeeded')
        self.assertTrue(json.loads(journal.read_text())['finished'])
        self.assertEqual(platform.call('POST', '/v1/actions/claim', {'action_id': action_id},
                                       platform.tokens['executor'])[0], 400)

    def test_execution_of_a_pending_action_is_refused_locally(self) -> None:
        platform = self.fixture()
        answer = platform.proposal()
        with self.assertRaisesRegex(tools.ToolRefusal, 'no trusted runner handoff'):
            platform.registry().invoke('execute_action', platform.agent('executor'),
                                       {'action_id': answer['action_id']})
        self.assertEqual(platform.action_row(answer['action_id'])['status'], 'pending')
        self.assertEqual(platform.executions(), [])

    def test_a_proposal_the_allowlist_refuses_reaches_the_agent_as_a_refusal(self) -> None:
        """An action nobody allowlisted is refused by the platform, and the refusal is not swallowed."""
        platform = self.fixture()
        incident = platform.open_incident()
        arguments = proposal_arguments(platform, incident)
        arguments['action'] = 'reboot-everything'
        with self.assertRaisesRegex(tools.ToolRefusal, 'Proposal refused by the platform'):
            platform.registry().invoke('propose_action', platform.agent('proposer'), arguments)
        self.assertEqual(platform.operations('action.proposed'), [])

    def test_a_proposal_against_a_resolved_incident_is_refused(self) -> None:
        platform = self.fixture()
        incident = platform.open_incident()
        platform.store.intake(platform.firing(600, status='resolved'), PRODUCER,
                              now=PAST + dt.timedelta(minutes=600))
        arguments = proposal_arguments(platform, incident)
        arguments['incident_id'] = incident['incident_id']
        with self.assertRaisesRegex(tools.ToolRefusal, 'Proposal refused by the platform'):
            platform.registry().invoke('propose_action', platform.agent('proposer'), arguments)

    def test_a_body_that_claims_an_identity_never_reaches_the_platform_as_one(self) -> None:
        """§5 at the tool boundary: the tool has no identity argument, and the route has no such field."""
        platform = self.fixture()
        incident = platform.open_incident()
        arguments = proposal_arguments(platform, incident)
        with self.assertRaisesRegex(tools.ToolRefusal, 'accepts no argument'):
            platform.registry().invoke('propose_action', platform.agent('proposer'),
                                       {**arguments, 'actor': {'identity': 'operator', 'role': 'human'}})
        code, body = platform.call('POST', '/v1/actions', {**arguments, 'actor': 'operator'},
                                   platform.tokens['proposer'])
        self.assertEqual((code, body.get('error')), (400, 'invalid_request'),
                         'the extra field is a shape error, never a claim of identity')

    def test_local_execution_refusal_adds_no_platform_audit_or_lifecycle_move(self) -> None:
        platform = self.fixture()
        answer = platform.proposal()
        with self.assertRaises(tools.ToolRefusal):
            platform.registry().invoke('execute_action', platform.agent('executor'),
                                       {'action_id': answer['action_id']})
        refusals = platform.operations('action.refused')
        self.assertEqual(refusals, [])
        self.assertEqual(platform.action_row(answer['action_id'])['status'], 'pending')
        self.assertEqual(platform.executions(), [])

    def test_no_tool_result_carries_a_credential_shaped_string(self) -> None:
        """Every tool and every answer it can give: no secret field, and no planted secret.

        The secret is planted rather than hoped for: ``state.claim_action`` mints its runner credential
        with ``secrets.token_urlsafe``, so for the duration of these calls every minted credential is
        :data:`PLANTED`. A claim through the raw route proves the plant landed; tool reads and the local
        execution refusal must not expose it. Same reasoning for the agent credentials: the reader's own
        token must not come back inside the document it read.
        """
        from unittest import mock
        platform = self.fixture(reader=seeded_store())
        registry = platform.registry()
        with mock.patch('local_observe.platform.state.secrets.token_urlsafe', return_value=PLANTED):
            lapsed = platform.call('POST', '/v1/actions/claim',
                                   {'action_id': platform.approved(expires_claim=True)},
                                   platform.tokens['executor'])
            # A lapse is a recorded transition, not an error, so it answers 200 — and it mints no runner
            # credential, which is why the live claim below is the one the plant has to land on.
            self.assertEqual((lapsed[0], lapsed[1].get('status')), (200, 'expired'), lapsed)
            self.assertNotIn('runner_token', lapsed[1], lapsed)
            live = platform.approved()
            raw = platform.call('POST', '/v1/actions/claim', {'action_id': live},
                                platform.tokens['executor'])
            self.assertEqual(raw[0], 200)
            self.assertEqual(raw[1].get('runner_token'), PLANTED,
                             'the plant failed, so the scan below would prove nothing')
            with self.assertRaises(tools.ToolRefusal) as refused:
                registry.invoke('execute_action', platform.agent('executor'),
                                {'action_id': platform.approved()})
            answers: list[tuple[str, Any]] = [('execute_action', str(refused.exception))]
            for name in READ_ARGUMENTS:
                answers.append((name, registry.invoke(name, platform.agent('reader'),
                                                      READ_ARGUMENTS[name]).data))
            answers.append(('propose_action', registry.invoke(
                'propose_action', platform.agent('proposer'),
                proposal_arguments(platform, platform.open_incident(minute=1))).data))
        for name, data in answers:
            text = json.dumps(data, default=str)
            with self.subTest(tool=name):
                self.assertNotIn(PLANTED, text)
                for field in tools.SECRET_FIELDS:
                    self.assertNotIn(f'"{field}"', text)
                for token in platform.tokens.values():
                    self.assertNotIn(token, text)
        self.assertNotIn('execution_id', answers[0][1], 'the refused tool opened no execution')


class ExtraRefusalTests(unittest.TestCase):
    """The absent-SDK refusal, proven in the tier where the SDK is genuinely absent."""

    def test_the_refusal_names_the_install_line_and_keeps_the_cause_text(self) -> None:
        refusal = tools.mcp_extra_refusal(ModuleNotFoundError("No module named 'mcp'"))
        self.assertIsInstance(refusal, ModuleNotFoundError)
        self.assertIsInstance(refusal, tools.McpExtraNotInstalled)
        self.assertIn("No module named 'mcp'", str(refusal))
        self.assertIn('local-observe[mcp]', str(refusal))
        self.assertIn('mcp==1.29.1', str(refusal))
        self.assertIn('local-observe[mcp]', str(tools.mcp_extra_refusal()))

    @unittest.skipIf(importlib.util.find_spec('mcp'),
                     'the mcp extra is installed here; this refusal belongs to the base-dependency tier')
    def test_importing_the_transport_without_the_extra_refuses_loudly(self) -> None:
        """The base tier is the one that proves this: no silent server, and no zero-tool answer.

        ``.gitea/workflows/ci.yml`` runs ``python -c "import importlib.util; assert
        importlib.util.find_spec('mcp') is None"`` before that tier's suite, so when this test runs it ran
        with the extra genuinely absent. It is a subprocess because the refusal happens at import, and the
        rest of this suite must not be poisoned by a half-imported module.
        """
        program = ('import importlib.util, sys\n'
                   'assert importlib.util.find_spec("mcp") is None\n'
                   'sys.path.insert(0, ".")\n'
                   'try:\n'
                   '    import local_observe.platform.mcp\n'
                   'except ModuleNotFoundError as error:\n'
                   '    text = str(error)\n'
                   '    assert "local-observe[mcp]" in text, text\n'
                   '    assert type(error).__name__ == "McpExtraNotInstalled", text\n'
                   'else:\n'
                   '    raise AssertionError("the transport imported without the extra")\n')
        result = subprocess.run([sys.executable, '-B', '-c', program], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)


# ------------------------------------------------------------------ fakes and small helpers


def seeded_store() -> InMemoryStore:
    """Four metric samples for the example host, stamped inside the last hour."""
    start = NOW - dt.timedelta(minutes=30)
    return InMemoryStore(series(4, name='cpu_usage', resource_id=HOST, start=start.isoformat(),
                                step_seconds=120))


def proposal_arguments(platform: Platform, incident: dict[str, Any],
                       expires: dt.timedelta = dt.timedelta(hours=10)) -> dict[str, Any]:
    """One well-formed proposal against one freshly opened incident."""
    return {'retry_key': platform.next_key(), 'incident_id': incident['incident_id'],
            'action': 'inspect', 'version': '1', 'targets': [HOST], 'parameters': {},
            'evidence': [incident['event_id']], 'expires_at': (PAST + expires).isoformat()}


class StatusDouble:
    """A client that answers every request with one status and one document."""

    def __init__(self, code: int = 200, body: Any = None) -> None:
        self.code, self.body = code, body if body is not None else {'rows': []}

    def request(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
        return self.code, self.body


class CountingDouble:
    """A client that records every attempt, so "refused before the write" is a count and not a feeling."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
        self.calls.append((method, path))
        return 403, {'error': 'not_authorised'}


if __name__ == '__main__':
    unittest.main()

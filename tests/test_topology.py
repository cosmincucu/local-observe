"""The declared read model: direction, bounds, refusals and the cycle finding (topology read model).

Fixture shape note: the resources are synthetic names (`probe-host`, `demo-api`, …) with UUIDs
derived from those names, and the relation words come from the declared vocabulary
(`runs-on`, `depends-on`). Nothing here is an estate identifier.
"""
import copy
import datetime as dt
import hashlib
import sqlite3
import tempfile
import unittest
import uuid
from unittest import mock
from pathlib import Path
from typing import Any

from local_observe import topology
from local_observe.inventory import index
from local_observe.inventory.validation import (InvalidInventory, canonical, read_document, timestamp,
                                                utc_text)
from local_observe.platform import detections, presentation, state
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
REVISION = 'fixture-rev-1'
PRODUCER = Actor('topology-fixture', 'producer')


def identifier(name: str) -> str:
    """A stable synthetic UUID for a name (uuid5 of the name, never a real estate id)."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'topology-fixture/' + name))


def resource(name: str, kind: str = 'service', relations: tuple[tuple[str, str], ...] = ()) -> dict[str, Any]:
    return {'id': identifier(name), 'kind': kind, 'name': name,
            'aliases': [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
            'attributes': {'environment': 'fixture'},
            'relations': [{'type': relation, 'target': identifier(target)} for relation, target in relations]}


def document(resources: list[dict[str, Any]]) -> dict[str, Any]:
    return {'schema_version': 1, 'resources': resources}


def edge_identities(edges: list[topology.DeclaredEdge]) -> set[tuple[str, str, str]]:
    return {(edge.source_id, edge.relation, edge.target_id) for edge in edges}


class TopologyFixture(unittest.TestCase):
    """Builds one index and hands each test a Topology over it."""

    resources: list[dict[str, Any]] = []

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'inventory.db'
        self.document = document(copy.deepcopy(self.resources))
        index.build(self.document, self.path, REVISION, now=NOW)
        self.graph = topology.Topology(self.path)


class DirectionTests(TopologyFixture):
    resources = [
        resource('probe-host', 'host'),
        resource('demo-api', 'service', (('runs-on', 'probe-host'),)),
        resource('demo-worker', 'service', (('depends-on', 'demo-api'),)),
    ]

    def test_runs_on_makes_the_host_upstream_of_the_service(self):
        """v0.1's pinned example, restated here: `container --runs-on--> host` means the container
        depends on the host, so the host is UPSTREAM of the container and the container is in
        impact(host). A reversed reading passes no other assertion in this file."""
        upstream = self.graph.upstream(identifier('demo-api'), 3)
        self.assertEqual([node['resource_id'] for node in upstream['nodes']], [identifier('probe-host')])
        self.assertEqual(upstream['nodes'][0]['relation'], 'runs-on')
        self.assertEqual(upstream['nodes'][0]['depth'], 1)
        self.assertEqual(upstream['direction'], 'depends-on')
        # The host itself depends on nothing: here an empty answer is the whole answer, and the
        # scan says so — the undeclared case is a refusal, tested separately below.
        empty = self.graph.upstream(identifier('probe-host'), 3)
        self.assertEqual(empty['nodes'], [])
        self.assertFalse(empty['truncated'])
        self.assertEqual(empty['depth_reached'], 0)

    def test_impact_of_a_two_level_chain(self):
        impact = self.graph.impact(identifier('probe-host'), 3)
        self.assertEqual([(node['name'], node['depth'], node['relation']) for node in impact['nodes']],
                         [('demo-api', 1, 'runs-on'), ('demo-worker', 2, 'depends-on')])
        self.assertEqual(impact['direction'], 'depended-on-by')
        self.assertEqual(impact['depth_reached'], 2)
        # Depth 1 asks for direct dependents only; it is not the same answer as depth 3.
        self.assertEqual([node['name'] for node in self.graph.impact(identifier('probe-host'), 1)['nodes']],
                         ['demo-api'])
        # Nothing breaks if the leaf breaks, except nothing.
        self.assertEqual(self.graph.impact(identifier('demo-worker'), 3)['nodes'], [])

    def test_relation_type_and_declaration_revision_travel_with_the_edges(self):
        expected = index.digest(index.normalized(copy.deepcopy(self.document)))
        for method in (self.graph.upstream, self.graph.impact):
            for node in method(identifier('demo-worker'), 3)['nodes']:
                self.assertEqual(node['declaration_revision'], REVISION)
                self.assertIsInstance(node['relation'], str)
        answer = self.graph.declared_edges()
        self.assertEqual(answer['plane'], 'declared')
        self.assertFalse(answer['truncated'])
        self.assertEqual(answer['revision']['declaration_sha256'], expected)
        self.assertEqual({(edge.source_id, edge.relation, edge.target_id) for edge in answer['edges']},
                         {(identifier('demo-api'), 'runs-on', identifier('probe-host')),
                          (identifier('demo-worker'), 'depends-on', identifier('demo-api'))})
        for edge in answer['edges']:
            self.assertEqual(edge.plane, 'declared')
            self.assertEqual(edge.declaration_revision, REVISION)
            self.assertEqual(edge.declaration_sha256, expected)
        for edge in self.graph.edges_for(identifier('demo-api'))['depends_on']:
            self.assertEqual(edge.declaration_revision, REVISION)
        for hop in self.graph.shortest_path(identifier('demo-worker'), identifier('probe-host'))['edges']:
            self.assertEqual(hop.declaration_revision, REVISION)

    def test_a_rebuilt_index_reports_its_own_revision(self):
        self.document['resources'][1]['relations'] = []
        index.build(self.document, self.path, 'fixture-rev-2', now=NOW)
        graph = topology.Topology(self.path)
        self.assertEqual(graph.revision()['declaration_revision'], 'fixture-rev-2')
        self.assertEqual([edge.relation for edge in graph.declared_edges()['edges']], ['depends-on'])
        self.assertEqual(graph.upstream(identifier('demo-api'), 3)['nodes'], [])
        self.assertNotEqual(graph.revision()['declaration_sha256'],
                            index.digest(index.normalized(document(DirectionTests.resources))))
        self.assertEqual(graph.revision()['built_at'], utc_text(NOW))

    def test_edges_for_returns_both_directions_in_one_call(self):
        middle = self.graph.edges_for(identifier('demo-api'))
        self.assertEqual(middle['plane'], 'declared')
        self.assertEqual([(edge.source_id, edge.target_id) for edge in middle['depends_on']],
                         [(identifier('demo-api'), identifier('probe-host'))])
        self.assertEqual([(edge.source_id, edge.target_id) for edge in middle['depended_on_by']],
                         [(identifier('demo-worker'), identifier('demo-api'))])
        # Every reported edge keeps its declared orientation (source depends on target) whichever
        # side asked for it, so a caller can never read an incoming edge as an outgoing one.
        for edge in middle['depended_on_by']:
            self.assertEqual((edge.source_id, edge.target_id, edge.relation),
                             (identifier('demo-worker'), identifier('demo-api'), 'depends-on'))
        self.assertEqual(self.graph.edges_for(identifier('probe-host'))['depends_on'], [])
        self.assertFalse(middle['truncated'])

    def test_declared_edges_can_be_filtered_by_resource_and_relation(self):
        self.assertEqual([edge.relation for edge in
                          self.graph.declared_edges(resource_id=identifier('probe-host'))['edges']], ['runs-on'])
        self.assertEqual(self.graph.declared_edges(relation='depends-on')['edges'][0].source_id,
                         identifier('demo-worker'))
        self.assertEqual(self.graph.declared_edges(relation='connects-to')['edges'], [])
        self.assertEqual([edge.relation for edge in
                          self.graph.declared_edges(resource_id=identifier('demo-api'),
                                                    relation='runs-on')['edges']], ['runs-on'])

    def test_shortest_path_walks_the_depends_on_direction(self):
        found = self.graph.shortest_path(identifier('demo-worker'), identifier('probe-host'))
        self.assertEqual(found['status'], 'found')
        self.assertEqual(found['path'], [identifier('demo-worker'), identifier('demo-api'),
                                         identifier('probe-host')])
        self.assertEqual([edge.relation for edge in found['edges']], ['depends-on', 'runs-on'])
        self.assertEqual({edge.declaration_revision for edge in found['edges']}, {REVISION})
        # The reverse direction has no path: the host does not depend on the worker.
        reverse = self.graph.shortest_path(identifier('probe-host'), identifier('demo-worker'))
        self.assertEqual(reverse['status'], 'absent')
        self.assertTrue(reverse['complete'])

    def test_shortest_path_from_a_node_to_itself_makes_no_edge_claim(self):
        result = self.graph.shortest_path(identifier('probe-host'), identifier('probe-host'))
        self.assertEqual(result['status'], 'found')
        self.assertEqual(result['path'], [identifier('probe-host')])
        self.assertEqual(result['edges'], [])

    def test_undeclared_resource_id_refuses_rather_than_answering_empty(self):
        stranger = identifier('never-declared')
        for name, call in (
            ('upstream', lambda: self.graph.upstream(stranger, 2)),
            ('impact', lambda: self.graph.impact(stranger, 2)),
            ('edges_for', lambda: self.graph.edges_for(stranger)),
            ('declared_edges', lambda: self.graph.declared_edges(resource_id=stranger)),
            ('shortest_path target', lambda: self.graph.shortest_path(identifier('demo-api'), stranger)),
            ('shortest_path source', lambda: self.graph.shortest_path(stranger, identifier('demo-api'))),
        ):
            with self.subTest(call=name):
                with self.assertRaises(topology.UndeclaredResource) as refused:
                    call()
                self.assertIsInstance(refused.exception, InvalidInventory)
                self.assertIn(stranger, str(refused.exception))

    def test_a_malformed_resource_id_refuses_before_any_query(self):
        for value in ('probe-host', 'urn:uuid:00000000-0000-0000-0000-000000000000',
                      '00000000-0000-0000-0000-000000000000'.upper(), None, 7):
            with self.subTest(value=value):
                with self.assertRaises(topology.TopologyRefusal):
                    self.graph.upstream(value, 2)


class DeepGraphTests(unittest.TestCase):
    """A 200-node chain plus a wide fan-out: every answer is bounded and says so."""

    LENGTH = 200
    LEAVES = 40

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'inventory.db'
        chain = [resource(f'node-{step:03d}', 'service',
                          (() if step == self.LENGTH - 1 else (('depends-on', f'node-{step + 1:03d}'),)))
                 for step in range(self.LENGTH)]
        fan = [resource('hub', 'service'), resource('collector', 'service')]
        fan += [resource(f'leaf-{leaf:03d}', 'service', (('runs-on', 'hub'),)) for leaf in range(self.LEAVES)]
        self.resources = chain + fan
        self.edges = sum(len(item['relations']) for item in self.resources)
        index.build(document(self.resources), self.path, REVISION, now=NOW)
        self.graph = topology.Topology(self.path)

    def test_traversal_depth_bound_stops_a_deep_chain(self):
        """A walk the depth bound cut says so.

        The first draft asserted `truncated: False` on this call, which was the finding: node-003
        depends on node-004 and is not in the answer, so "not truncated" would have told a caller
        the neighbourhood was complete. It is a *depth* cut, not a row cut, and `truncated_by`
        says which.
        """
        three = self.graph.upstream(identifier('node-000'), 3)
        self.assertEqual([node['name'] for node in three['nodes']], ['node-001', 'node-002', 'node-003'])
        self.assertTrue(three['truncated'])
        self.assertEqual(three['truncated_by'], ['depth'])
        self.assertEqual(three['depth_reached'], 3)
        self.assertEqual(three['depth_limit'], 3)
        # Raising the row bound cannot un-cut it: the bound that bit was the depth.
        self.assertEqual(self.graph.upstream(identifier('node-000'), 3,
                                             max_rows=topology.ROW_CEILING)['truncated_by'], ['depth'])
        # One more hop reaches one more node, so the cut answer really is missing the rest.
        deeper = self.graph.upstream(identifier('node-000'), 4)
        self.assertEqual([node['name'] for node in deeper['nodes']][-1:], ['node-004'])
        bounded = self.graph.upstream(identifier('node-000'), topology.MAX_DEPTH)
        self.assertEqual(bounded['depth_limit'], topology.MAX_DEPTH)
        self.assertEqual(len(bounded['nodes']), topology.MAX_DEPTH)
        self.assertEqual(bounded['depth_reached'], topology.MAX_DEPTH)
        self.assertTrue(bounded['truncated'])
        self.assertEqual(bounded['truncated_by'], ['depth'])
        # The same chain walked to its real end is complete: the last hop had nothing left.
        tail = self.graph.upstream(identifier(f'node-{self.LENGTH - 4:03d}'), 4)
        self.assertEqual([node['name'] for node in tail['nodes']],
                         ['node-197', 'node-198', 'node-199'])
        self.assertFalse(tail['truncated'])
        self.assertEqual(tail['truncated_by'], [])

    def test_row_bound_reports_truncation_instead_of_a_short_answer(self):
        answer = self.graph.impact(identifier('hub'), 3, max_rows=10)
        self.assertEqual(len(answer['nodes']), 10)
        self.assertTrue(answer['truncated'])
        whole = self.graph.impact(identifier('hub'), 3, max_rows=self.LEAVES)
        self.assertEqual(len(whole['nodes']), self.LEAVES)
        self.assertFalse(whole['truncated'])

    def test_edge_row_bound_reports_truncation(self):
        answer = self.graph.declared_edges(max_rows=5)
        self.assertEqual(len(answer['edges']), 5)
        self.assertTrue(answer['truncated'])
        # The default row bound is smaller than this fixture, so the default call says so.
        self.assertEqual(len(self.graph.declared_edges()['edges']), topology.MAX_ROWS)
        self.assertTrue(self.graph.declared_edges()['truncated'])
        whole = self.graph.declared_edges(max_rows=self.edges)
        self.assertEqual(len(whole['edges']), self.edges)
        self.assertFalse(whole['truncated'])
        hub = self.graph.edges_for(identifier('hub'), max_rows=3)
        self.assertEqual(len(hub['depended_on_by']), 3)
        self.assertEqual(hub['depends_on'], [])
        self.assertTrue(hub['truncated'])
        scoped = self.graph.declared_edges(resource_id=identifier('hub'), max_rows=3)
        self.assertEqual(len(scoped['edges']), 3)
        self.assertTrue(scoped['truncated'])

    def test_deep_chain_terminates_and_is_proved_acyclic(self):
        endpoints = set()
        for item in self.resources:
            for relation in item['relations']:
                endpoints.add(item['id'])
                endpoints.add(relation['target'])
        self.assertNotIn(identifier('collector'), endpoints)      # no edge at either end: not a node
        scan = self.graph.detect_cycles()
        self.assertEqual(scan['cycles'], [])
        self.assertTrue(scan['complete'])
        self.assertFalse(scan['truncated'])
        self.assertEqual(scan['edges_scanned'], self.edges)
        self.assertEqual(scan['nodes_scanned'], len(endpoints))

    def test_traversal_of_a_deep_chain_is_bounded_by_default(self):
        answer = self.graph.upstream(identifier('node-000'), topology.DEFAULT_DEPTH)
        self.assertEqual(len(answer['nodes']), topology.DEFAULT_DEPTH)
        self.assertEqual(answer['depth_limit'], topology.DEFAULT_DEPTH)
        # The default bound is shorter than this chain, so the default answer is a cut answer.
        self.assertTrue(answer['truncated'])
        self.assertEqual(answer['truncated_by'], ['depth'])
        self.assertFalse(self.graph.upstream(identifier(f'node-{self.LENGTH - 11:03d}'),
                                            topology.DEFAULT_DEPTH)['truncated'])

    def test_shortest_path_refuses_to_call_a_bound_search_an_absence(self):
        direct = self.graph.shortest_path(identifier('node-000'), identifier('node-002'))
        self.assertEqual(direct['status'], 'found')
        self.assertEqual(direct['depth'], 2)
        capped = self.graph.shortest_path(identifier('node-000'), identifier('node-002'), 1)
        self.assertEqual(capped['status'], 'depth_exceeded')
        self.assertEqual(capped['path'], [])
        self.assertFalse(capped['complete'])
        # A leaf that depends on nothing, asked about something unrelated, is a real absence:
        # the search exhausted inside the bound rather than running out of hops.
        last = f'node-{self.LENGTH - 1:03d}'
        absent = self.graph.shortest_path(identifier(last), identifier('collector'))
        self.assertEqual(absent['status'], 'absent')
        self.assertTrue(absent['complete'])

    def test_argument_bounds_are_refused_not_clamped(self):
        for depth in (0, -1, topology.MAX_DEPTH + 1, True, '2', type(None)):
            with self.subTest(depth=depth):
                with self.assertRaises(topology.TopologyRefusal):
                    self.graph.upstream(identifier('node-000'), depth)
        for rows in (0, topology.ROW_CEILING + 1, 1.5):
            with self.subTest(rows=rows):
                with self.assertRaises(topology.TopologyRefusal):
                    self.graph.impact(identifier('hub'), 2, max_rows=rows)
        with self.assertRaises(topology.TopologyRefusal):
            topology.Topology(self.path, max_rows=0)
        with self.assertRaises(topology.TopologyRefusal):
            topology.Topology(self.path, depth=topology.MAX_DEPTH + 1)
        with self.assertRaises(topology.TopologyRefusal):
            self.graph.detect_cycles(limit=topology.MAX_CYCLES + 1)

    def test_relation_filter_accepts_only_the_declared_vocabulary(self):
        with self.assertRaises(topology.TopologyRefusal):
            self.graph.declared_edges(relation='RUNS_ON')
        with self.assertRaises(topology.TopologyRefusal):
            self.graph.declared_edges(relation='runs_on')


class DepthCutTests(TopologyFixture):
    """The difference between a walk that finished and a walk the depth bound cut (finding 1).

    `chain-a -> chain-b -> chain-c` is the reviewer's own shape, built through `index.build` and
    never hand-fed to the read model: at depth 1 the answer is `chain-b` and `chain-c` is missing,
    so the answer must be marked cut. `revisit-*` is the opposite case — the boundary frontier's
    only edge leads back to a node already reported, so nothing is missing and the walk says so.
    """

    resources = [
        resource('chain-a', 'service', (('depends-on', 'chain-b'),)),
        resource('chain-b', 'service', (('depends-on', 'chain-c'),)),
        resource('chain-c', 'service'),
        resource('revisit-top', 'service', (('depends-on', 'revisit-middle'),)),
        resource('revisit-middle', 'service', (('depends-on', 'revisit-leaf'),)),
        resource('revisit-leaf', 'service', (('depends-on', 'revisit-middle'),)),
        resource('fan-top', 'service', tuple(('depends-on', f'fan-leaf-{step}') for step in range(6))),
        resource('lonely', 'service'),
    ] + [resource(f'fan-leaf-{step}', 'service', (('depends-on', f'fan-tail-{step}'),))
         for step in range(6)] + [resource(f'fan-tail-{step}', 'service') for step in range(6)]

    def test_a_cut_chain_is_reported_as_cut_in_both_directions(self):
        up = self.graph.upstream(identifier('chain-a'), 1)
        self.assertEqual([node['name'] for node in up['nodes']], ['chain-b'])
        self.assertTrue(up['truncated'])
        self.assertEqual(up['truncated_by'], ['depth'])
        self.assertEqual(up['depth_reached'], 1)
        self.assertEqual(up['depth_limit'], 1)
        down = self.graph.impact(identifier('chain-c'), 1)
        self.assertEqual([node['name'] for node in down['nodes']], ['chain-b'])
        self.assertTrue(down['truncated'])
        self.assertEqual(down['truncated_by'], ['depth'])
        # The same questions one hop deeper are complete, and that is what the flag was promising.
        self.assertEqual([node['name'] for node in self.graph.upstream(identifier('chain-a'), 2)['nodes']],
                         ['chain-b', 'chain-c'])
        self.assertFalse(self.graph.upstream(identifier('chain-a'), 2)['truncated'])
        self.assertEqual(sorted(node['name'] for node in
                                self.graph.impact(identifier('chain-c'), 2)['nodes']),
                         ['chain-a', 'chain-b'])
        self.assertFalse(self.graph.impact(identifier('chain-c'), 2)['truncated'])

    def test_a_leaf_exactly_on_the_depth_boundary_is_not_reported_as_work_remaining(self):
        """The other half of finding 1: the bound stopping a walk is not the same as the cut.

        `chain-b` depends on `chain-c`, which depends on nothing. At depth 1 the frontier is that
        leaf, so the next hop would have found nothing and inventing a truncation here would be
        its own lie. One bounded existence check (a `SELECT 1 ... LIMIT 1`, not a walk) decides it.
        """
        for name, answer in (
            ('upstream chain-b', self.graph.upstream(identifier('chain-b'), 1)),
            ('impact chain-b', self.graph.impact(identifier('chain-b'), 1)),
        ):
            with self.subTest(answer=name):
                self.assertEqual(len(answer['nodes']), 1)
                self.assertFalse(answer['truncated'])
                self.assertEqual(answer['truncated_by'], [])
                self.assertEqual(answer['depth_reached'], 1)
        # A frontier of visited nodes only: the bound stopped the walk, and the walk was over.
        revisit = self.graph.upstream(identifier('revisit-top'), 2)
        self.assertEqual([node['name'] for node in revisit['nodes']], ['revisit-middle', 'revisit-leaf'])
        self.assertFalse(revisit['truncated'])
        self.assertEqual(revisit['truncated_by'], [])
        self.assertEqual(revisit['depth_reached'], 2)
        self.assertFalse(self.graph.upstream(identifier('revisit-top'), 5)['truncated'])
        # A resource with no edge at all: the frontier never opens, so nothing is claimed missing.
        alone = self.graph.upstream(identifier('lonely'), 1)
        self.assertEqual(alone['nodes'], [])
        self.assertFalse(alone['truncated'])
        self.assertEqual(alone['truncated_by'], [])

    def test_a_row_cut_and_a_depth_cut_are_named_separately_and_together(self):
        whole = self.graph.upstream(identifier('fan-top'), 2, max_rows=12)
        self.assertEqual(len(whole['nodes']), 12)                     # 6 leaves + 6 tails, all of them
        self.assertFalse(whole['truncated'])
        rows = self.graph.upstream(identifier('fan-top'), 2, max_rows=3)
        self.assertEqual(len(rows['nodes']), 3)
        self.assertEqual(rows['truncated_by'], ['rows'])              # the walk continued to hop 2
        both = self.graph.upstream(identifier('fan-top'), 1, max_rows=3)
        self.assertEqual(len(both['nodes']), 3)
        self.assertEqual(both['truncated_by'], ['depth', 'rows'])     # every kept leaf goes deeper
        self.assertTrue(both['truncated'])

    def test_an_existence_check_that_cannot_run_says_work_may_remain(self):
        """The completeness of a depth answer rests on one bounded query; degrade it safely.

        `_has_unexplored` passes the already-reported ids back as parameters, and SQLite caps how
        many it may bind. If that ceiling were ever the reason the check could not run, claiming
        "nothing was left" would be a guess, so the read model says the opposite instead and the
        answer comes back marked truncated.
        """
        complete = self.graph.upstream(identifier('chain-b'), 1)
        self.assertEqual(complete['truncated_by'], [])
        with mock.patch.object(topology, 'SQL_PARAMETER_BOUND', 1):
            degraded = self.graph.upstream(identifier('chain-b'), 1)
        self.assertTrue(degraded['truncated'])
        self.assertEqual(degraded['truncated_by'], ['depth'])
        self.assertEqual([node['name'] for node in degraded['nodes']],
                         [node['name'] for node in complete['nodes']])   # same nodes, honest flag


class PathBoundTests(unittest.TestCase):
    """`shortest_path` remembers a cut it made one hop ago (finding 2).

    The fixture names are chosen so their UUIDs sort in a known order, because the row bound cuts
    the first ``ROW_CEILING`` rows of a hop in that order: `wide` has three leaf dependencies and
    the target is the last one, so a row bound of two drops the very edge being asked about while
    leaving a frontier of nodes that go nowhere. The other index gives the dropped edge a longer
    replacement, which must not be reported as the shortest path.
    """

    @staticmethod
    def ascending_names(count: int, seed: str) -> list[str]:
        """Synthetic names whose UUIDs are already in ascending order (a deterministic search)."""
        chosen: list[str] = []
        step = 0
        while len(chosen) < count:
            name = f'{seed}-{step}'
            step += 1
            if all(identifier(old) < identifier(name) for old in chosen):
                chosen.append(name)
        return chosen

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.wide = self.ascending_names(3, 'wide')                 # [0] first, [2] last by UUID
        self.deep = self.ascending_names(3, 'deep')
        self.path = Path(self.temp.name) / 'inventory.db'
        index.build(document([
            resource('wide-root', 'service', tuple(('depends-on', name) for name in self.wide)),
            *[resource(name, 'service') for name in self.wide],
            resource('deep-root', 'service', tuple(('depends-on', name) for name in self.deep)),
            resource(self.deep[0], 'service', (('depends-on', self.deep[2]),)),   # the longer route
            *[resource(name, 'service') for name in self.deep[1:]],
        ]), self.path, REVISION, now=NOW)
        self.graph = topology.Topology(self.path)

    def test_a_row_cut_in_one_hop_is_not_an_absence_when_the_next_frontier_closes(self):
        """The reviewer's reproduction, as a fixture: three dependencies, row bound of two.

        Today this answers `absent` with `complete: True` at depth 2 — the hop that lost the direct
        edge is forgotten the moment the next frontier turns out to have no outgoing edges.
        """
        target = identifier(self.wide[2])
        self.assertEqual(self.graph.shortest_path(identifier('wide-root'), target)['status'], 'found')
        with mock.patch.object(topology, 'ROW_CEILING', 2):
            answer = self.graph.shortest_path(identifier('wide-root'), target)
        self.assertEqual(answer['status'], 'incomplete')
        self.assertFalse(answer['complete'])
        self.assertEqual(answer['path'], [])
        self.assertEqual(answer['edges'], [])
        self.assertTrue(answer['truncated'])
        self.assertEqual(answer['truncated_by'], ['rows'])
        self.assertNotEqual(answer['status'], 'absent')

    def test_a_row_cut_may_not_be_answered_by_a_longer_path_found_later(self):
        """A hop that was cut might have held the shorter route, so no length is quotable."""
        target = identifier(self.deep[2])
        found = self.graph.shortest_path(identifier('deep-root'), target)
        self.assertEqual(found['status'], 'found')
        self.assertEqual(found['depth'], 1)                            # the direct edge
        with mock.patch.object(topology, 'ROW_CEILING', 2):
            answer = self.graph.shortest_path(identifier('deep-root'), target)
        self.assertEqual(answer['status'], 'incomplete')
        self.assertFalse(answer['complete'])
        self.assertEqual(answer['path'], [])                           # the length-2 route is not an answer
        self.assertEqual(answer['truncated_by'], ['rows'])

    def test_a_cut_at_the_level_that_reached_the_target_still_proves_shortest(self):
        """`found` is only refused when an *earlier* level was cut.

        Every path of length 1 is a direct edge, and this one was read: cutting the rest of that
        same hop can hide other length-1 paths, never a shorter one, because the levels before it
        were read whole. The cut is still reported, so a caller can see it happened.
        """
        target = identifier(self.wide[0])                              # the first by UUID: kept
        with mock.patch.object(topology, 'ROW_CEILING', 2):
            answer = self.graph.shortest_path(identifier('wide-root'), target)
        self.assertEqual(answer['status'], 'found')
        self.assertEqual(answer['depth'], 1)
        self.assertEqual(answer['path'], [identifier('wide-root'), target])
        self.assertTrue(answer['complete'])
        self.assertTrue(answer['truncated'])
        self.assertEqual(answer['truncated_by'], ['rows'])

    def test_the_total_work_of_a_search_is_bounded_not_only_its_hops(self):
        """Per-hop rows are the old bound; discovered nodes are the new one (finding 2)."""
        target = identifier(self.wide[2])
        with mock.patch.object(topology, 'MAX_SEARCH_NODES', 1):
            answer = self.graph.shortest_path(identifier('wide-root'), target)
        self.assertEqual(answer['status'], 'incomplete')
        self.assertFalse(answer['complete'])
        self.assertEqual(answer['truncated_by'], ['nodes'])
        with mock.patch.object(topology, 'MAX_SEARCH_ROWS', 2):
            answer = self.graph.shortest_path(identifier('wide-root'), target)
        self.assertEqual(answer['status'], 'incomplete')
        self.assertEqual(answer['truncated_by'], ['rows'])
        self.assertLessEqual(topology.MAX_SEARCH_NODES, topology.ROW_CEILING * 10)
        self.assertLessEqual(topology.MAX_SEARCH_ROWS, topology.MAX_EDGES)

    def test_a_depth_bound_with_nothing_left_to_see_is_a_real_absence(self):
        """Depth exhaustion and row exhaustion stay different, and both stay honest."""
        capped = self.graph.shortest_path(identifier('deep-root'), identifier(self.deep[2]), 1)
        self.assertEqual(capped['status'], 'found')                    # the direct edge is at hop 1
        away = self.graph.shortest_path(identifier(self.wide[0]), identifier('wide-root'))
        self.assertEqual(away['status'], 'absent')                     # a leaf: nothing to walk
        self.assertTrue(away['complete'])
        self.assertEqual(away['truncated_by'], [])
        # A cycle closes the search on its own, so an unreachable target is still an answer.
        loop = Path(self.temp.name) / 'loop.db'
        index.build(document([resource('loop-a', 'service', (('depends-on', 'loop-b'),)),
                              resource('loop-b', 'service', (('runs-on', 'loop-a'),)),
                              resource('loop-out', 'service', (('depends-on', 'loop-a'),))]),
                    loop, REVISION, now=NOW)
        answer = topology.Topology(loop).shortest_path(identifier('loop-a'), identifier('loop-out'), 1)
        self.assertEqual(answer['status'], 'absent')
        self.assertTrue(answer['complete'])
        self.assertEqual(answer['truncated_by'], [])
        # And a hop bound that really was too short says depth, not rows: hop-c is one edge past
        # the frontier the bound stopped, and the search knows the difference between the two.
        hops = Path(self.temp.name) / 'hops.db'
        index.build(document([resource('hop-a', 'service', (('depends-on', 'hop-b'),)),
                              resource('hop-b', 'service', (('depends-on', 'hop-c'),)),
                              resource('hop-c', 'service')]), hops, REVISION, now=NOW)
        capped = topology.Topology(hops).shortest_path(identifier('hop-a'), identifier('hop-c'), 1)
        self.assertEqual(capped['status'], 'depth_exceeded')
        self.assertFalse(capped['complete'])
        self.assertEqual(capped['truncated_by'], ['depth'])
        self.assertEqual(topology.Topology(hops).shortest_path(identifier('hop-a'),
                                                              identifier('hop-c'), 2)['status'], 'found')


class CycleTests(TopologyFixture):
    """The builder admits a declared cycle, so the read model has to report it (measured)."""

    resources = [
        resource('loop-a', 'service', (('depends-on', 'loop-b'),)),
        resource('loop-b', 'service', (('runs-on', 'loop-a'),)),
        resource('loop-c', 'service', (('depends-on', 'loop-c'),)),
        resource('outside', 'service', (('depends-on', 'loop-a'),)),
    ]

    def test_the_builder_admits_a_declared_cycle(self):
        """Measured 2026-09-08 against this repo's own builder: `validation.declared` refuses a
        relation whose *target* is not declared and says nothing about cycles, so a cyclic
        declaration builds. That refusal is the gatekeeper the brief names, and it does not
        cover cycles — which is why `detect_cycles` and `cycle_findings` exist."""
        rebuilt = Path(self.temp.name) / 'rebuilt.db'
        metadata = index.build(self.document, rebuilt, 'cycle-fixture', now=NOW)
        self.assertEqual(metadata['declaration_revision'], 'cycle-fixture')
        scan = topology.Topology(rebuilt).detect_cycles()
        self.assertEqual(scan['count'], 2)
        self.assertTrue(scan['complete'])

    def test_detect_cycles_reports_each_cycle_once_rotated_to_its_smallest_id(self):
        scan = self.graph.detect_cycles()
        self.assertTrue(scan['complete'])
        self.assertEqual(scan['mode'], 'dfs-witness')
        self.assertEqual(scan['count'], 2)
        self.assertEqual(sorted(scan['cycles']), sorted([[identifier('loop-a'), identifier('loop-b')],
                                                         [identifier('loop-c')]]))
        for cycle in scan['cycles']:
            self.assertEqual(cycle[0], min(cycle))
            self.assertEqual(len(cycle), len(set(cycle)))
        self.assertEqual(scan['nodes_scanned'], 4)
        self.assertEqual(scan['edges_scanned'], 4)

    def test_a_declared_cycle_terminates_every_traversal_and_excludes_the_origin(self):
        up_a = self.graph.upstream(identifier('loop-a'), 8)
        self.assertEqual([node['resource_id'] for node in up_a['nodes']], [identifier('loop-b')])
        self.assertEqual(self.graph.upstream(identifier('loop-b'), 8)['nodes'][0]['resource_id'],
                         identifier('loop-a'))
        impact_a = self.graph.impact(identifier('loop-a'), 8)
        self.assertEqual(sorted(node['name'] for node in impact_a['nodes']), ['loop-b', 'outside'])
        self.assertEqual([node['name'] for node in self.graph.impact(identifier('loop-b'), 8)['nodes']],
                         ['loop-a', 'outside'])
        for node in impact_a['nodes']:
            self.assertNotEqual(node['resource_id'], identifier('loop-a'))
        self.assertFalse(impact_a['truncated'])
        # A loop is not "work remaining": the frontier's only edge led back to a node this call had
        # already reported (or to the origin), so depth 8 asking more than exists still says complete.
        for name, answer in (('upstream loop-a', self.graph.upstream(identifier('loop-a'), 8)),
                             ('upstream loop-b', self.graph.upstream(identifier('loop-b'), 8)),
                             ('impact loop-a', impact_a), ('impact outside',
                                                           self.graph.impact(identifier('outside'), 8))):
            with self.subTest(answer=name):
                self.assertFalse(answer['truncated'])
                self.assertEqual(answer['truncated_by'], [])

    def test_cycle_findings_emit_coverage_events_naming_the_rule_id(self):
        findings = self.graph.cycle_findings(now=NOW)
        self.assertEqual(findings['status'], 'finding')
        self.assertEqual(len(findings['events']), 2)
        by_resource = {event['resource_id']: event for event in findings['events']}
        self.assertEqual(set(by_resource), {identifier('loop-a'), identifier('loop-c')})
        event = by_resource[identifier('loop-a')]
        self.assertEqual(event['kind'], 'coverage')
        self.assertEqual(event['status'], 'firing')
        self.assertTrue(event['rule_id'].startswith(topology.CYCLE_RULE_PREFIX + '.'))
        self.assertEqual(event['resource_id'], identifier('loop-a'))
        self.assertEqual(event['evidence'][0]['query_type'], topology.CYCLE_EVIDENCE_QUERY_TYPE)
        self.assertEqual(event['evidence'][0]['parameters'],
                         {'resource_id': identifier('loop-a'),
                          'artifact_sha256': findings['revision']['declaration_sha256']})
        for finding in findings['events']:
            state.validate_event(finding, NOW)      # still a canonical event, not a near-miss
        self.assertEqual(len({finding['rule_id'] for finding in findings['events']}), 2)
        # Re-running the same declaration produces the same rule ids, so intake folds them.
        self.assertEqual({finding['rule_id'] for finding in findings['events']},
                         {finding['rule_id'] for finding in self.graph.cycle_findings(now=NOW)['events']})
        # A different cycle is a different condition, and the cycle digest is its own.
        loop_c = by_resource[identifier('loop-c')]
        expected = hashlib.sha256(canonical([identifier('loop-c')]).encode()).hexdigest()[:16]
        self.assertEqual(loop_c['rule_id'], f'{topology.CYCLE_RULE_PREFIX}.{expected}')

    def test_report_limit_makes_the_scan_say_it_is_incomplete(self):
        scan = self.graph.detect_cycles(limit=1)
        self.assertEqual(scan['count'], 1)
        self.assertTrue(scan['truncated'])
        self.assertFalse(scan['complete'])
        findings = self.graph.cycle_findings(now=NOW, limit=1)
        self.assertEqual(len(findings['events']), 1)
        self.assertTrue(findings['truncated'])
        with self.assertRaises(topology.TopologyRefusal):
            self.graph.detect_cycles(limit=0)

    def test_a_clean_graph_reports_clean_from_a_complete_scan(self):
        path = Path(self.temp.name) / 'clean.db'
        index.build(document([resource('solo', 'service')]), path, 'clean', now=NOW)
        findings = topology.Topology(path).cycle_findings(now=NOW)
        self.assertEqual(findings['status'], 'clean')
        self.assertEqual(findings['events'], [])
        self.assertTrue(findings['complete'])
        self.assertFalse(findings['truncated'])
        self.assertEqual(findings['edges_scanned'], 0)


class CycleWitnessTests(TopologyFixture):
    """What `detect_cycles` may claim: an acyclicity verdict and a witness list, not an enumeration.

    Two nodes with edges both ways is the smallest case where the distinction bites: the graph
    holds two elementary cycles (`a -> c -> a` and `a -> b -> c -> a`), the DFS tree can only make
    one of them a back-edge, and a complete bounded edge scan does not change that. Documenting it
    as "all cycles" would be a false promise to suppression/correlation, which read this module.
    """

    resources = [
        resource('w-a', 'service', (('depends-on', 'w-b'), ('runs-on', 'w-c'))),
        resource('w-b', 'service', (('depends-on', 'w-c'),)),
        resource('w-c', 'service', (('depends-on', 'w-a'),)),
    ]

    def test_a_dfs_witness_list_is_not_an_enumeration_of_every_cycle(self):
        declared = {(edge.source_id, edge.target_id) for edge in self.graph.declared_edges()['edges']}
        self.assertIn((identifier('w-a'), identifier('w-c')), declared)
        self.assertIn((identifier('w-c'), identifier('w-a')), declared)
        scan = self.graph.detect_cycles()
        self.assertTrue(scan['complete'])                             # every edge and node was seen
        self.assertFalse(scan['truncated'])
        self.assertEqual(scan['edges_scanned'], 4)
        # w-a and w-c depend on each other, which is a cycle of two, and no witness names it:
        # one of those two edges became a tree edge on the way in. The scan is honest about the
        # graph it walked and silent about no list being a census.
        self.assertNotIn(sorted([identifier('w-a'), identifier('w-c')]),
                         sorted([sorted(cycle) for cycle in scan['cycles']]))
        self.assertTrue(scan['cycles'])
        for cycle in scan['cycles']:
            self.assertEqual(len(cycle), len(set(cycle)))
            self.assertEqual(cycle[0], min(cycle))
        findings = self.graph.cycle_findings(now=NOW)
        self.assertEqual(findings['status'], 'finding')
        self.assertTrue(findings['complete'])                         # "a loop exists", not "all loops"

    def test_an_empty_complete_scan_is_a_proof_of_acyclicity_not_a_shrug(self):
        """The other half of the same sentence: absence is proved, presence is only witnessed."""
        path = Path(self.temp.name) / 'diamond.db'
        index.build(document([
            resource('d-top', 'service', (('depends-on', 'd-left'), ('runs-on', 'd-right'))),
            resource('d-left', 'service', (('depends-on', 'd-bottom'),)),
            resource('d-right', 'service', (('depends-on', 'd-bottom'),)),
            resource('d-bottom', 'service'),
        ]), path, 'diamond', now=NOW)
        scan = topology.Topology(path).detect_cycles()
        self.assertEqual(scan['cycles'], [])
        self.assertTrue(scan['complete'])
        self.assertEqual(scan['edges_scanned'], 4)
        self.assertEqual(scan['nodes_scanned'], 4)
        # Removing the closing edge of the witness cycle leaves a graph the scan calls acyclic.
        broken = Path(self.temp.name) / 'broken.db'
        index.build(document([
            resource('w-a', 'service', (('depends-on', 'w-b'), ('runs-on', 'w-c'))),
            resource('w-b', 'service', (('depends-on', 'w-c'),)),
            resource('w-c', 'service'),
        ]), broken, 'broken', now=NOW)
        clean = topology.Topology(broken).detect_cycles()
        self.assertEqual(clean['cycles'], [])
        self.assertTrue(clean['complete'])
        self.assertEqual(topology.Topology(broken).cycle_findings(now=NOW)['status'], 'clean')


class IndexBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_a_file_that_is_not_an_inventory_index_is_refused(self):
        """`index.readonly` re-validates the application id on every open, so a file that is not an
        inventory index fails there — the read model inherits that refusal and adds none."""
        path = Path(self.temp.name) / 'other.db'
        path.write_text('not an index')
        with self.assertRaises(sqlite3.Error):
            topology.Topology(path).declared_edges()

    def test_a_missing_index_is_refused_rather_than_reading_as_empty(self):
        with self.assertRaises(sqlite3.Error):
            topology.Topology(Path(self.temp.name) / 'gone.db').declared_edges()

    def test_an_index_with_no_recorded_revision_is_refused(self):
        # `build()` refuses a blank revision itself, so the read model's own check is exercised
        # against a hand-stripped metadata table: an index that cannot name its declaration must
        # not answer at all rather than answer with a null revision on every edge.
        path = Path(self.temp.name) / 'norev.db'
        index.build(document([resource('probe-host', 'host')]), path, REVISION, now=NOW)
        connection = sqlite3.connect(path)
        with connection:
            connection.execute("DELETE FROM build_metadata WHERE key = 'declaration_revision'")
        connection.close()
        for name, call in (('declared_edges', lambda: topology.Topology(path).declared_edges()),
                           ('upstream', lambda: topology.Topology(path).upstream(identifier('probe-host'), 2)),
                           ('detect_cycles', lambda: topology.Topology(path).detect_cycles()),
                           ('revision', lambda: topology.Topology(path).revision())):
            with self.subTest(name=name):
                with self.assertRaises(topology.TopologyRefusal):
                    call()

    def test_the_example_declaration_is_readable_as_a_graph(self):
        built = Path(self.temp.name) / 'example.db'
        example = read_document(ROOT / 'examples/inventory/declared.yaml')
        index.build(example, built, 'example', now=NOW)
        graph = topology.Topology(built)
        host, service = example['resources'][0]['id'], example['resources'][1]['id']
        self.assertEqual([node['resource_id'] for node in graph.upstream(service, 2)['nodes']], [host])
        self.assertEqual([node['name'] for node in graph.impact(host, 2)['nodes']], ['demo-api'])
        self.assertEqual(graph.detect_cycles()['cycles'], [])


class PresentationTests(unittest.TestCase):
    """The one labelled topology section the incident view gained (brief task 5).

    The delivery path is asserted too: `describe` is what the notifier calls per message and it
    must stay exactly as it was — a labelled section on the incident view is not a licence to
    start opening the graph inside a delivery.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        resources = [resource('probe-host', 'host'),
                     resource('demo-api', 'service', (('runs-on', 'probe-host'),)),
                     resource('demo-worker', 'service', (('depends-on', 'demo-api'),))]
        for step in range(presentation.TOPOLOGY_NAMES + 2):
            resources.append(resource(f'rack-{step:02d}', 'host'))
        resources.append(resource('many-hosts', 'service',
                                  tuple(('runs-on', f'rack-{step:02d}')
                                        for step in range(presentation.TOPOLOGY_NAMES + 2))))
        for step in range(presentation.TOPOLOGY_NAMES + 2):
            resources.append(resource('tenant-' + str(step), 'service', (('runs-on', 'shared-host'),)))
        resources.append(resource('shared-host', 'host'))
        resources.append(resource('lonely', 'service'))
        self.index = self.root / 'inventory.db'
        index.build(document(resources), self.index, REVISION, now=NOW)

    def open_incident(self, name: str | None) -> dict[str, str]:
        rule = 'topology.test.' + (name or 'platform')
        window = {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)}
        event = detections.event(PRODUCER.identity, identifier(name) if name else None, rule,
                                 'availability', 'firing', window, {'rule_id': rule},
                                 query_type='metric-threshold')
        self.store.intake(event, PRODUCER, now=NOW)
        rows = self.store.records('incidents')
        return presentation.records(self.store, 'incidents', rows, self.index)[0]['display']

    def test_the_incident_row_labels_upstream_and_downstream(self):
        display = self.open_incident('demo-worker')
        self.assertEqual(display['upstream_name'], 'demo-api')
        self.assertEqual(display['downstream_name'], 'Nothing declared below it')
        self.assertEqual(display['resource_name'], 'demo-worker')
        # The host two hops below: its direct dependents only, at the depth the view asks for.
        host = self.open_incident('probe-host')
        self.assertEqual(host['upstream_name'], 'Nothing declared above it')
        self.assertEqual(host['downstream_name'], 'demo-api')
        self.assertEqual(self.open_incident('demo-api')['upstream_name'], 'probe-host')

    def test_an_incident_with_no_resource_says_so_rather_than_blaming_the_index(self):
        display = self.open_incident(None)
        self.assertEqual(display['upstream_name'], 'No resource on this incident')
        self.assertEqual(display['downstream_name'], 'No resource on this incident')

    def test_the_labels_distinguish_the_five_ways_the_answer_can_be_empty(self):
        blank = presentation.dependency_info(self.index, identifier('lonely'))
        self.assertEqual(blank, {'upstream_name': 'Nothing declared above it',
                                'downstream_name': 'Nothing declared below it'})
        self.assertEqual(presentation.dependency_info(self.index, identifier('nobody')),
                         {'upstream_name': 'Not declared', 'downstream_name': 'Not declared'})
        unreadable = self.root / 'other.db'
        unreadable.write_text('not an index')
        self.assertEqual(presentation.dependency_info(unreadable, identifier('demo-api')),
                         {'upstream_name': 'Topology unavailable',
                          'downstream_name': 'Topology unavailable'})
        self.assertEqual(presentation.dependency_info(self.root / 'gone.db', identifier('demo-api')),
                         {'upstream_name': 'Topology unavailable',
                          'downstream_name': 'Topology unavailable'})
        self.assertEqual(presentation.dependency_info(None, None),
                         {'upstream_name': 'Topology not configured',
                          'downstream_name': 'Topology not configured'})

    def test_the_bounded_name_list_says_it_was_cut(self):
        many = presentation.dependency_info(self.index, identifier('many-hosts'))
        self.assertEqual(many['upstream_name'].count(','), presentation.TOPOLOGY_NAMES - 1)
        self.assertTrue(many['upstream_name'].endswith('(more; this list is bounded)'))
        crowded = presentation.dependency_info(self.index, identifier('shared-host'))
        self.assertTrue(crowded['downstream_name'].endswith('(more; this list is bounded)'))

    def test_operators_keep_the_last_word_on_a_name(self):
        display = presentation.dependency_info(self.index, identifier('demo-worker'),
                                               {'resource_names': {identifier('demo-api'): 'Checkout API'}})
        self.assertEqual(display['upstream_name'], 'Checkout API')

    def test_only_a_row_cut_marks_the_name_list_as_bounded(self):
        """More graph *below* the hop is not a shorter list: the two bounds say different things.

        `demo-worker` depends on `demo-api`, which depends on a host. The label asks for one hop,
        so the walk is depth-cut and the five-name row bound was never reached — and the cell must
        not tell the operator its list of direct neighbours was truncated when it was not.
        """
        deeper = presentation.dependency_info(self.index, identifier('demo-worker'))
        self.assertEqual(deeper['upstream_name'], 'demo-api')
        self.assertNotIn('more', deeper['upstream_name'])
        self.assertIn('demo-api', presentation.dependency_info(self.index,
                                                               identifier('probe-host'))['downstream_name'])

    def test_only_the_incident_view_carries_the_section(self):
        rule = 'topology.test.other-tables'
        window = {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)}
        event = detections.event(PRODUCER.identity, identifier('demo-api'), rule, 'availability',
                                 'firing', window, {'rule_id': rule}, query_type='metric-threshold')
        self.store.intake(event, PRODUCER, now=NOW)
        for table in ('events', 'outbox', 'actions', 'executions'):
            rows = presentation.records(self.store, table, self.store.records(table), self.index)
            for row in rows:
                with self.subTest(table=table):
                    self.assertNotIn('upstream_name', row['display'])
                    self.assertNotIn('downstream_name', row['display'])

    def test_the_delivery_label_still_carries_no_topology(self):
        """`describe` is what a notification message is built from; it must not start a graph read."""
        display = presentation.describe({'rule_id': 'x', 'kind': 'availability',
                                        'resource_id': identifier('demo-api')}, self.index)
        self.assertEqual(set(display), {'description', 'resource_name', 'host_name'})

    def test_the_example_declaration_labels_the_same_way(self):
        built = self.root / 'example.db'
        example = read_document(ROOT / 'examples/inventory/declared.yaml')
        index.build(example, built, 'example', now=NOW)
        host, service = example['resources'][0]['id'], example['resources'][1]['id']
        self.assertEqual(presentation.dependency_info(built, service)['upstream_name'], 'probe-1')
        self.assertEqual(presentation.dependency_info(built, host)['downstream_name'], 'demo-api')


class RelationShapeTests(unittest.TestCase):
    """The relation vocabulary restated in topology.py must stay the schema's, not drift from it."""

    def test_the_pattern_matches_the_shipped_declaration_schema(self):
        schema = (ROOT / 'local_observe/inventory/schemas/declared.json').read_text()
        self.assertIn('"pattern": "^[a-z][a-z0-9-]{0,63}$"', schema)   # this file is not topology read model's to edit
        for accepted in ('runs-on', 'depends-on', 'connects-to', 'a'):
            self.assertTrue(topology.RELATION_SHAPE.fullmatch(accepted), accepted)
        for rejected in ('runs_on', 'RUNS-ON', '-runs-on', 'runs.on', '', 'x' * 65):
            with self.subTest(rejected=rejected):
                self.assertIsNone(topology.RELATION_SHAPE.fullmatch(rejected))
                with self.assertRaises(topology.TopologyRefusal):
                    topology._relation(rejected)

    def test_the_direction_convention_is_written_in_the_module_docstring(self):
        """The pinned sentences: a later brief reads this docstring and not the code."""
        self.assertIn('An edge ``src --relation--> dst`` means **src DEPENDS ON dst**.',
                      topology.__doc__)
        self.assertIn('``container --runs-on--> host``', topology.__doc__)
        self.assertIn('``upstream(id)`` follows OUTGOING', topology.__doc__)
        self.assertIn('``impact(id)`` follows INCOMING', topology.__doc__)
        self.assertIn('``shortest_path(a, b)`` walks the same depends-on direction', topology.__doc__)


class CoverageWindowTests(unittest.TestCase):
    def test_coverage_window_is_aligned_bounded_and_aware(self):
        path = Path(tempfile.mkdtemp()) / 'loop.db'
        index.build(document([resource('loop-a', 'service', (('depends-on', 'loop-a'),))]),
                    path, REVISION, now=NOW)
        graph = topology.Topology(path)
        findings = graph.cycle_findings(now=NOW, window_seconds=60)
        self.assertEqual(findings['events'][0]['window'],
                         {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)})
        self.assertEqual(findings['events'][0]['observed_at'], utc_text(NOW))
        with self.assertRaises(topology.TopologyRefusal):
            graph.cycle_findings(now=NOW, window_seconds=0)
        with self.assertRaises(topology.TopologyRefusal):
            graph.cycle_findings(now=NOW, window_seconds=3601)
        with self.assertRaises(topology.TopologyRefusal):
            graph.cycle_findings(now=dt.datetime(2026, 9, 6, 12, 1))     # naive time


if __name__ == '__main__':
    unittest.main()

"""Declared and observed edges are separate planes; an inference never reaches the graph (topology read model).

v0.1 wrote span- and network-inferred edges straight into its own graph store. The port keeps the
*idea* (an inference is a timestamped claim with evidence) and drops the graph writer: an inferred
relation goes through `discovery.Observation` → `discovery.snapshot` → `discovery.ingest`, and the
read model exposes the two planes through different calls returning different types. This file is
the proof that they do not mix.

All ids are synthetic uuid5 values derived from synthetic names; no estate identifier appears here.
"""
import datetime as dt
import hashlib
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any

from local_observe import topology
from local_observe.inventory import discovery, index
from local_observe.inventory.validation import InvalidInventory, timestamp, utc_text

NOW = timestamp('2026-09-06T12:01:00Z')
LATER = timestamp('2026-09-06T12:06:00Z')
REVISION = 'fixture-rev-1'
SOURCE = 'fixture-spans'


def identifier(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'topology-observed/' + name))


def resource(name: str, kind: str = 'service', relations: tuple[tuple[str, str], ...] = ()) -> dict[str, Any]:
    return {'id': identifier(name), 'kind': kind, 'name': name,
            'aliases': [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
            'attributes': {'environment': 'fixture'},
            'relations': [{'type': relation, 'target': identifier(target)} for relation, target in relations]}


class ObservedPlaneTests(unittest.TestCase):
    """One built index (host ← api ← worker) plus the observed database beside it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.index_path = Path(self.temp.name) / 'inventory.db'
        self.observations_path = Path(self.temp.name) / 'observed.db'
        self.declaration = {'schema_version': 1, 'resources': [
            resource('probe-host', 'host'),
            resource('demo-api', 'service', (('runs-on', 'probe-host'),)),
            resource('demo-worker', 'service', (('depends-on', 'demo-api'),))]}
        index.build(self.declaration, self.index_path, REVISION, now=NOW)
        self.graph = topology.Topology(self.index_path)

    # -- helpers ----------------------------------------------------------

    def infer(self, subject: str, target: str, relation: str = 'connects-to', *,
              at: dt.datetime = NOW, evidence: tuple[str, ...] = ('span:abc123',),
              source: str = SOURCE, observation_id: str | None = None) -> discovery.Observation:
        return topology.inferred_relation_observation(
            source, observed_at=at, subject_id=identifier(subject), target_id=identifier(target),
            relation=relation, evidence=list(evidence), observation_id=observation_id)

    def ingest(self, *observations: discovery.Observation, at: dt.datetime = NOW,
               snapshot_id: str | None = None) -> dict[str, Any]:
        document = discovery.snapshot(observations[0].source, list(observations), now=at)
        if snapshot_id:
            document['snapshot_id'] = snapshot_id
        return discovery.ingest(self.observations_path, document, now=at)

    def hand_built(self, observations: list[dict[str, Any]], *, at: dt.datetime = NOW,
                   snapshot_id: str = 'snapshot-a', source: str = SOURCE) -> dict[str, Any]:
        document = {'schema_version': 1, 'source': source,
                    'snapshot_id': str(uuid.uuid5(uuid.NAMESPACE_DNS, snapshot_id)),
                    'observed_at': utc_text(at), 'status': 'ok', 'complete': False, 'scope': [],
                    'observations': observations}
        return discovery.ingest(self.observations_path, document, now=at)   # ingest validates it

    def edges(self, **kwargs: Any) -> list[topology.ObservedEdge]:
        return topology.observed_edges(self.observations_path, SOURCE, **kwargs)['edges']

    # -- the inferred relation is an observation --------------------------------

    def test_an_inferred_relation_lands_in_the_observed_plane_with_its_evidence(self):
        self.ingest(self.infer('demo-api', 'demo-worker'))
        answer = topology.observed_edges(self.observations_path, SOURCE, history_limit=2)
        self.assertEqual(answer['plane'], 'observed')
        self.assertEqual(len(answer['edges']), 1)
        edge = answer['edges'][0]
        self.assertEqual((edge.source_id, edge.relation, edge.target_id),
                         (identifier('demo-api'), 'connects-to', identifier('demo-worker')))
        self.assertEqual(edge.observed_at, utc_text(NOW))
        self.assertEqual(edge.observation_source, SOURCE)
        self.assertEqual(edge.evidence, ('span:abc123',))
        self.assertTrue(edge.snapshot_id)
        self.assertEqual(answer['newest_observed_at'], utc_text(NOW))
        self.assertEqual(answer['snapshots_read'], 1)
        self.assertTrue(answer['history_complete'])
        self.assertNotIn('revision', answer)         # there is no declaration behind an inference

    def test_the_observed_record_is_the_shape_the_discovery_plane_already_accepts(self):
        """The helper adds no column and no schema: it emits a plain `Observation`."""
        observation = self.infer('demo-api', 'demo-worker')
        self.assertIsInstance(observation, discovery.Observation)
        self.assertEqual(observation.as_dict()['attributes'],
                         {topology.INFERRED_RELATION: 'connects-to',
                          topology.INFERRED_TARGET: identifier('demo-worker')})
        self.assertEqual(observation.resource_id, identifier('demo-api'))
        document = discovery.snapshot(SOURCE, [observation], now=NOW)
        self.assertEqual(document['observations'][0], observation.as_dict())
        self.assertEqual(discovery.ingest(self.observations_path, document, now=NOW)['status'], 'inserted')

    def test_a_stamped_source_can_seal_and_store_it_without_any_topology_write(self):
        """No method on this module opens a database for writing: `ingest` is what persists."""
        observation = self.infer('demo-worker', 'probe-host', relation='runs-on')
        document = discovery.snapshot(SOURCE, [observation], now=NOW)        # a provider seals it
        discovery.ingest(self.observations_path, document, now=NOW)          # a writer stores it
        self.assertEqual(self.edges()[0].relation, 'runs-on')

    # -- the two planes never mix ------------------------------------------

    def test_declared_and_observed_edges_are_never_mixed(self):
        """The brief's headline: a consumer that asks for one and gets the other is a bug.

        An inference is ingested between two resources that already have a declared edge, using
        a *different* relation word, so any leak is visible rather than plausible.
        """
        before = self.graph.declared_edges()
        self.ingest(self.infer('demo-api', 'demo-worker', relation='connects-to'))
        declared = {(edge.source_id, edge.relation, edge.target_id)
                    for edge in self.graph.declared_edges()['edges']}
        observed = {(edge.source_id, edge.relation, edge.target_id) for edge in self.edges()}
        self.assertEqual(declared, {(edge.source_id, edge.relation, edge.target_id)
                                    for edge in before['edges']})
        self.assertEqual(observed, {(identifier('demo-api'), 'connects-to', identifier('demo-worker'))})
        self.assertFalse(declared & observed)
        # Nothing the declared read model answers changes because of the inference.
        self.assertEqual([edge.relation for edge in
                          self.graph.edges_for(identifier('demo-api'))['depended_on_by']], ['depends-on'])
        self.assertNotIn('connects-to', [edge.relation for edge in self.graph.declared_edges()['edges']])
        self.assertEqual([node['name'] for node in self.graph.upstream(identifier('demo-api'), 3)['nodes']],
                         ['probe-host'])
        self.assertEqual([node['name'] for node in self.graph.impact(identifier('demo-api'), 3)['nodes']],
                         ['demo-worker'])
        self.assertEqual([node['relation'] for node in self.graph.impact(identifier('demo-api'), 3)['nodes']],
                         ['depends-on'])
        self.assertEqual(self.graph.shortest_path(identifier('demo-api'), identifier('demo-worker'))['status'],
                         'absent')
        self.assertEqual(self.graph.detect_cycles()['cycles'], [])
        # ...and the observed read never answers with a declared edge.
        self.assertNotIn((identifier('demo-api'), 'runs-on', identifier('probe-host')), observed)

    def test_each_plane_carries_its_own_provenance_and_never_the_others(self):
        self.ingest(self.infer('demo-api', 'demo-worker'))
        declared = self.graph.declared_edges()['edges'][0]
        observed = self.edges()[0]
        self.assertEqual(declared.plane, 'declared')
        self.assertEqual(observed.plane, 'observed')
        self.assertEqual(declared.declaration_revision, REVISION)
        self.assertFalse(hasattr(declared, 'observed_at'))
        self.assertFalse(hasattr(declared, 'snapshot_id'))
        self.assertFalse(hasattr(observed, 'declaration_revision'))
        self.assertFalse(hasattr(observed, 'declaration_sha256'))
        def read_revision() -> Any:                     # a consumer that expects a revision on edges
            return observed.declaration_revision

        with self.assertRaises(AttributeError):
            read_revision()                             # fails loudly, never reads None as unversioned
        self.assertNotEqual(set(declared.as_dict()), set(observed.as_dict()))
        self.assertEqual(set(declared.as_dict()),
                         {'plane', 'source_id', 'target_id', 'relation', 'declaration_revision',
                          'declaration_sha256'})
        self.assertEqual(set(observed.as_dict()),
                         {'plane', 'source_id', 'target_id', 'relation', 'observation_source',
                          'observed_at', 'snapshot_id', 'evidence'})

    def test_the_declared_graph_ignores_an_inferred_cycle(self):
        """An inference that would close a declared loop does not: `detect_cycles` reads declarations."""
        self.ingest(self.infer('probe-host', 'demo-api', relation='connects-to'))
        self.assertEqual(self.graph.detect_cycles()['cycles'], [])
        self.assertEqual(self.graph.cycle_findings(now=NOW)['status'], 'clean')
        self.assertEqual(self.graph.upstream(identifier('probe-host'), 5)['nodes'], [])
        self.assertEqual({edge.relation for edge in self.edges()}, {'connects-to'})

    def test_a_declared_only_resource_and_an_observed_only_resource_are_distinguishable(self):
        """The observed plane does not resolve identity — that is `index.resolve`'s job, and this
        is why the two planes are separate calls: an inference may name something the operator has
        not declared yet, and that must never read as a declared node."""
        stranger = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'topology-observed/not-declared'))
        observation = topology.inferred_relation_observation(
            SOURCE, observed_at=NOW, subject_id=identifier('demo-api'), target_id=stranger,
            relation='connects-to', evidence=['span:unmatched'])
        self.ingest(observation)
        self.assertEqual([edge.target_id for edge in self.edges()], [stranger])
        with self.assertRaises(topology.UndeclaredResource):
            self.graph.edges_for(stranger)
        self.assertEqual([node['resource_id'] for node in self.graph.upstream(identifier('demo-api'), 3)['nodes']],
                         [identifier('probe-host')])

    # -- reading the observed plane back ----------------------------------

    def test_the_newest_claim_wins_and_history_bounds_are_reported(self):
        self.ingest(self.infer('demo-api', 'demo-worker', evidence=('span:first',)), at=NOW,
                    snapshot_id='6f6c6174-0000-0000-0000-000000000001')
        second = self.infer('demo-api', 'demo-worker', evidence=('span:second',), at=LATER,
                            observation_id='second-claim')
        document = discovery.snapshot(SOURCE, [second], now=LATER)
        document['snapshot_id'] = '6f6c6174-0000-0000-0000-000000000002'
        discovery.ingest(self.observations_path, document, now=LATER)
        answer = topology.observed_edges(self.observations_path, SOURCE, history_limit=2)
        self.assertEqual(len(answer['edges']), 1)
        self.assertEqual(answer['edges'][0].evidence, ('span:second',))
        self.assertEqual(answer['edges'][0].observed_at, utc_text(LATER))
        self.assertEqual(answer['snapshots_read'], 2)
        # Two snapshots read out of a bound of two: the reader cannot claim there were no more.
        self.assertFalse(answer['history_complete'])
        wide = topology.observed_edges(self.observations_path, SOURCE, history_limit=5)
        self.assertEqual(wide['snapshots_read'], 2)
        self.assertTrue(wide['history_complete'])

    def test_more_claims_than_the_row_bound_are_reported_as_truncated(self):
        many = [self.infer('demo-api', f'peer-{step}', observation_id=f'claim-{step}')
                for step in range(12)]
        self.ingest(*many)
        answer = topology.observed_edges(self.observations_path, SOURCE, max_rows=5)
        self.assertEqual(len(answer['edges']), 5)
        self.assertTrue(answer['truncated'])
        self.assertFalse(answer['skipped'])
        whole = topology.observed_edges(self.observations_path, SOURCE, max_rows=12)
        self.assertEqual(len(whole['edges']), 12)
        self.assertFalse(whole['truncated'])
        # Deterministic: the same index and the same bound answer in the same order twice.
        self.assertEqual([edge.target_id for edge in whole['edges']],
                         [edge.target_id for edge in topology.observed_edges(
                             self.observations_path, SOURCE, max_rows=12)['edges']])

    def test_an_unreadable_claim_is_skipped_visibly_rather_than_dropped(self):
        """v0.1 reported a skip instead of silently dropping it; that survives as `skipped`."""
        self.hand_built([
            {'observation_id': 'good', 'aliases': [{'type': 'service.name', 'value': 'demo-api'}],
             'resource_id': identifier('demo-api'),
             'attributes': {topology.INFERRED_RELATION: 'connects-to',
                            topology.INFERRED_TARGET: identifier('demo-worker')},
             'evidence': ['span:good']},
            {'observation_id': 'target-not-a-uuid', 'resource_id': identifier('demo-api'),
             'aliases': [], 'attributes': {topology.INFERRED_RELATION: 'connects-to',
                                           topology.INFERRED_TARGET: 'switch-01'},
             'evidence': ['span:bad-target']},
            {'observation_id': 'relation-not-declared-shaped', 'resource_id': identifier('demo-api'),
             'aliases': [], 'attributes': {topology.INFERRED_RELATION: 'CONNECTS_TO',
                                           topology.INFERRED_TARGET: identifier('demo-worker')},
             'evidence': ['span:bad-relation']},
            {'observation_id': 'no-subject', 'aliases': [{'type': 'service.name', 'value': 'x'}],
             'attributes': {topology.INFERRED_RELATION: 'connects-to',
                            topology.INFERRED_TARGET: identifier('demo-worker')},
             'evidence': ['span:no-subject']},
            {'observation_id': 'not-a-relation-at-all', 'resource_id': identifier('demo-api'),
             'aliases': [], 'attributes': {'environment': 'fixture'}, 'evidence': ['span:unrelated']},
        ])
        answer = topology.observed_edges(self.observations_path, SOURCE)
        self.assertEqual(len(answer['edges']), 1)
        self.assertEqual(answer['edges'][0].source_id, identifier('demo-api'))
        self.assertEqual(answer['skipped_count'], 3)
        self.assertEqual(len(answer['skipped']), 3)
        self.assertTrue(any('not a canonical UUID' in reason for reason in answer['skipped']))
        self.assertTrue(any('relation vocabulary' in reason for reason in answer['skipped']))
        self.assertTrue(any('no resource identity' in reason for reason in answer['skipped']))
        self.assertEqual(len(self.edges(max_rows=1)), 1)

    def test_the_skip_list_itself_is_bounded(self):
        noisy = []
        for step in range(30):
            noisy.append({'observation_id': f'bad-{step}', 'resource_id': identifier('demo-api'),
                          'aliases': [], 'attributes': {topology.INFERRED_RELATION: 'connects-to',
                                                        topology.INFERRED_TARGET: f'not-a-uuid-{step}'},
                          'evidence': [f'span:{step}']})
        self.hand_built(noisy)
        answer = topology.observed_edges(self.observations_path, SOURCE, skip_limit=4)
        self.assertEqual(len(answer['skipped']), 4)
        self.assertEqual(answer['skipped_count'], 30)
        self.assertEqual(answer['edges'], [])
        with self.assertRaises(topology.TopologyRefusal):
            topology.observed_edges(self.observations_path, SOURCE, skip_limit=1000)

    def test_a_different_source_is_a_different_answer(self):
        """Two producers may claim the same word; the reader keeps the planes per source."""
        self.ingest(self.infer('demo-api', 'demo-worker'))
        other = self.infer('demo-worker', 'probe-host', relation='runs-on', source='fixture-docker')
        discovery.ingest(self.observations_path, discovery.snapshot('fixture-docker', [other], now=NOW),
                         now=NOW)
        self.assertEqual([edge.observation_source for edge in self.edges()], [SOURCE])
        self.assertEqual(len(topology.observed_edges(self.observations_path, 'fixture-docker')['edges']), 1)
        self.assertEqual(topology.observed_edges(self.observations_path, 'never-reported')['edges'], [])

    # -- evidence is required on both sides of the boundary -------------------

    def test_an_evidence_free_inference_is_refused_on_the_read_boundary_too(self):
        """The helper is not the boundary; the read has to hold without it.

        ``observed.json`` gives ``evidence`` no ``minItems``, ``discovery.snapshot`` is the only
        thing that refuses an empty list, and ``discovery.ingest`` validates a hand-built document
        against the schema — so a snapshot that never passed through a provider can hold an
        evidence-free inferred relation. This walks that whole path for real (ingest, then the
        store, then ``history``) and shows the read refuses the edge rather than returning it.
        """
        with self.assertRaises(InvalidInventory):        # the provider path never lets it through
            discovery.snapshot(SOURCE, [discovery.Observation(
                source=SOURCE, observed_at=NOW, observation_id='no-evidence', aliases=[],
                attributes={topology.INFERRED_RELATION: 'connects-to',
                            topology.INFERRED_TARGET: identifier('demo-worker')},
                evidence=[], resource_id=identifier('demo-api'))], now=NOW)
        accepted = self.hand_built([{
            'observation_id': 'no-evidence', 'resource_id': identifier('demo-api'), 'aliases': [],
            'attributes': {topology.INFERRED_RELATION: 'connects-to',
                           topology.INFERRED_TARGET: identifier('demo-worker')},
            'evidence': []}])
        self.assertEqual(accepted['status'], 'inserted')          # the store took it
        stored = discovery.history(self.observations_path, SOURCE, limit=2)[0]
        self.assertEqual(stored['observations'][0]['evidence'], [])  # it is really in there
        answer = topology.observed_edges(self.observations_path, SOURCE)
        self.assertEqual(answer['edges'], [])
        self.assertEqual(answer['skipped_count'], 1)
        self.assertEqual(answer['skipped'], ['no-evidence: carries an inferred relation with no '
                                            'usable evidence reference behind it'])
        self.assertIsNone(answer['newest_observed_at'])
        # An explicit list of blanks is the same claim in a different shape.
        self.hand_built([{'observation_id': 'blank-evidence', 'resource_id': identifier('demo-api'),
                          'aliases': [],
                          'attributes': {topology.INFERRED_RELATION: 'connects-to',
                                         topology.INFERRED_TARGET: identifier('demo-worker')},
                          'evidence': ['   ']}], at=LATER, snapshot_id='snapshot-b')
        wide = topology.observed_edges(self.observations_path, SOURCE)
        self.assertEqual(wide['edges'], [])
        self.assertEqual(wide['skipped_count'], 2)
        self.assertTrue(all(len(reason) < 120 for reason in wide['skipped']))   # bounded sentences
        self.assertNotIn('   ', ' '.join(wide['skipped']))                      # never quotes the record

    def test_a_useless_evidence_reference_is_skipped_with_a_bounded_reason(self):
        """Read and write honour the same per-reference bounds as ``observed.json``."""
        self.hand_built([{'observation_id': 'long-evidence', 'resource_id': identifier('demo-api'),
                          'aliases': [],
                          'attributes': {topology.INFERRED_RELATION: 'connects-to',
                                         topology.INFERRED_TARGET: identifier('demo-worker')},
                          'evidence': ['x' * topology.MAX_EVIDENCE_CHARS]}])
        answer = topology.observed_edges(self.observations_path, SOURCE)
        self.assertEqual(len(answer['edges']), 1)               # the schema's own maximum is legal
        self.assertEqual(answer['edges'][0].evidence, ('x' * topology.MAX_EVIDENCE_CHARS,))
        self.assertEqual(answer['skipped'], [])
        # One reference past the schema's own cap cannot even be ingested, so the read bound
        # (MAX_EVIDENCE_REFS) can never be the thing that hides a real claim.
        with self.assertRaises(InvalidInventory):
            self.hand_built([{'observation_id': 'too-many', 'resource_id': identifier('demo-api'),
                              'aliases': [],
                              'attributes': {topology.INFERRED_RELATION: 'connects-to',
                                             topology.INFERRED_TARGET: identifier('demo-worker')},
                              'evidence': [f'span:{step}' for step in range(topology.MAX_EVIDENCE_REFS + 1)]}])

    def test_a_plain_observation_without_evidence_is_not_judged_as_an_inference(self):
        """The filter is on inferred relations, not on the whole observed plane."""
        self.hand_built([{'observation_id': 'plain', 'resource_id': identifier('demo-api'),
                          'aliases': [], 'attributes': {'environment': 'fixture'}, 'evidence': []},
                         {'observation_id': 'half-an-inference', 'resource_id': identifier('demo-api'),
                          'aliases': [], 'attributes': {topology.INFERRED_TARGET: identifier('demo-worker')},
                          'evidence': ['span:target-only']}])
        answer = topology.observed_edges(self.observations_path, SOURCE)
        self.assertEqual(answer['edges'], [])
        self.assertEqual(answer['skipped_count'], 1)            # only the half claim is a skip
        self.assertIn('half-an-inference', answer['skipped'][0])
        self.assertIn('has no inferred_relation attribute', answer['skipped'][0])

    def test_the_helper_refuses_evidence_that_is_not_a_list_of_references(self):
        """``evidence='span:abc'`` is one value; iterating it would have stored its characters."""
        base: dict[str, Any] = {'observed_at': NOW, 'subject_id': identifier('demo-api'),
                                'target_id': identifier('demo-worker'), 'relation': 'connects-to'}
        for name, evidence in (
            ('string', 'span:abc'),
            ('bytes', b'span:abc'),
            ('none', None),
            ('empty', []),
            ('blank-item', ['   ']),
            ('non-string-item', [7]),
            ('too-many', [f'span:{step}' for step in range(topology.MAX_EVIDENCE_REFS + 1)]),
            ('too-long', ['x' * (topology.MAX_EVIDENCE_CHARS + 1)]),
        ):
            with self.subTest(evidence=name):
                with self.assertRaises(topology.TopologyRefusal):
                    topology.inferred_relation_observation(SOURCE, evidence=evidence, **base)
        accepted = topology.inferred_relation_observation(
            SOURCE, evidence=['x' * topology.MAX_EVIDENCE_CHARS] * topology.MAX_EVIDENCE_REFS, **base)
        self.assertEqual(len(accepted.evidence), topology.MAX_EVIDENCE_REFS)

    def test_the_evidence_bounds_are_the_ones_the_observed_schema_ships(self):
        """Pinned against the file, because ``observed.json`` is not topology read model's to edit."""
        schema = (Path(__file__).resolve().parents[1]
                  / 'local_observe/inventory/schemas/observed.json').read_text()
        self.assertIn('"maxItems": 20', schema)
        self.assertIn('"minLength": 1, "maxLength": 1024', schema)
        self.assertEqual(topology.MAX_EVIDENCE_REFS, 20)
        self.assertEqual(topology.MAX_EVIDENCE_CHARS, 1024)

    # -- refusals ---------------------------------------------------------

    def test_the_helper_refuses_every_shape_that_would_make_a_fake_edge(self):
        base: dict[str, Any] = {'observed_at': NOW, 'subject_id': identifier('demo-api'),
                                'target_id': identifier('demo-worker'), 'relation': 'connects-to',
                                'evidence': ['span:abc']}
        for name, change in (
            ('subject', {'subject_id': 'demo-api'}),
            ('target', {'target_id': 'switch-01'}),
            ('target-case', {'target_id': identifier('demo-worker').upper()}),
            ('relation-underscore', {'relation': 'connects_to'}),
            ('relation-empty', {'relation': ''}),
            ('evidence-none', {'evidence': []}),
            ('evidence-blank', {'evidence': ['   ']}),
            ('source', {}),
            ('observed-at-naive', {'observed_at': dt.datetime(2026, 9, 6, 12, 1)}),
        ):
            with self.subTest(case=name):
                arguments = dict(base)
                arguments.update(change)
                source = 'Fixture Spans' if name == 'source' else SOURCE
                with self.assertRaises(topology.TopologyRefusal):
                    topology.inferred_relation_observation(source, **arguments)

    def test_a_refusal_is_an_inventory_refusal_so_an_http_edge_classifies_it(self):
        with self.assertRaises(InvalidInventory):
            topology.inferred_relation_observation(SOURCE, observed_at=NOW, subject_id='nope',
                                                   target_id=identifier('demo-worker'),
                                                   relation='connects-to', evidence=['span:x'])

    def test_reading_an_observations_file_that_is_not_one_is_refused(self):
        wrong = Path(self.temp.name) / 'wrong.db'
        wrong.write_bytes(b'not the observed plane')
        with self.assertRaises(sqlite3.Error):
            topology.observed_edges(wrong, SOURCE)
        with self.assertRaises(InvalidInventory):
            topology.observed_edges(self.index_path, SOURCE)         # the declared index is not observations
        for change in ({'history_limit': 1}, {'history_limit': 1001}, {'max_rows': 0},
                       {'max_rows': topology.ROW_CEILING + 1}, {'skip_limit': 1000}):
            with self.subTest(change=change):
                with self.assertRaises(topology.TopologyRefusal):
                    topology.observed_edges(self.observations_path, SOURCE, **change)
        for source in ('Bad Source', 'Fixture Spans', 'a' * 200, None):
            with self.subTest(source=source):
                with self.assertRaises(topology.TopologyRefusal):
                    topology.observed_edges(self.observations_path, source)

    def test_topology_never_writes_either_database(self):
        """A read model that created its own store would be the drift this brief exists to stop."""
        self.ingest(self.infer('demo-api', 'demo-worker'))

        def fingerprint(path: Path) -> str:
            return hashlib.sha256(path.read_bytes()).hexdigest()

        before = (fingerprint(self.index_path), fingerprint(self.observations_path))
        topology.observed_edges(self.observations_path, SOURCE)
        self.graph.upstream(identifier('demo-worker'), 5)
        self.graph.detect_cycles()
        self.graph.cycle_findings(now=NOW)
        self.assertEqual((fingerprint(self.index_path), fingerprint(self.observations_path)), before)


if __name__ == '__main__':
    unittest.main()

"""correlation: several conditions become one incident only on a corroborated link, and the why is stored.

`local_observe/platform/correlation.py` holds the rule; `Store.grouping_admission` holds the durable half.
This file is the argument that the two hold together, and it is organised around the one failure the port
table names as the thing to avoid: **one mush-incident per busy hour**. Two unrelated things failing in the
same minute is coincidence, and a platform that groups on coincidence has replaced N symptoms with one
symptom that lies about all of them.

The properties under test, in the order a reviewer should read them:

* **temporal proximity alone never groups** — asserted as a pure property over a grid of gaps and pairs
  (`link()` answers None whenever the instant is far or nothing structural corroborates it), and again
  through `Store.intake`, where the answer is an incident count rather than a return value;
* **a declared edge does group, and the stored rationale names that edge** — read back off the file with
  raw sqlite, not from the object that wrote it;
* **a graph that cannot answer is not an answer** — `absent` groups nothing, `depth_exceeded` groups
  nothing, an undeclared resource groups nothing, and a graph that raises does not fail the intake;
* **the group is the file** — a restart loses nothing, a re-fired member stays with its group through the
  condition pointer, and the group-size bound fails toward *two pages*, never toward one wide incident;
* **every entry point groups** — the two HTTP routes and the six producer rounds of `lo-platform` that
  name an inventory index all pass the admission, so a CLI-filed condition is not the one condition that
  never joins anything (`CliGroupingTests`); `lo-platform intake` groups when `--index` names a graph
  (correlation followups 2), and files the pre-grouping way when it does not — both halves pinned there;
* **an escalation rung never joins a group, in either direction** (`escalation.py`'s ladder counts rungs
  per incident, so a joined rung is a rung the cursor believes it already filed);
* **one writer** — two threads filing the two halves of one group produce one incident, because grouping
  runs inside `Store.intake`'s own transaction and the second transaction waits behind the first;
* **the rationale is minimum redacted context** — a secret-shaped value anywhere in the event reaches the
  stored line in exactly one shape: not at all;
* **resolution belongs to the last open member**, and the resolution of an ordinary single-condition
  incident is byte-for-byte the behaviour that predates this card.

Fixtures are synthetic names with `uuid5`-derived ids (`tests/test_topology.py`'s convention) and one built
inventory index. No network, host or telemetry store is touched anywhere in this file, and no delivery
client is constructed: the tests never call `claim_notification`.
"""
import ast
import asyncio
import concurrent.futures
import contextlib
import datetime as dt
import io
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from typing import Any
import uuid
from unittest import mock

from local_observe import topology
from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import cli, correlation, presentation, suppression
from local_observe.platform.api import create_app
from local_observe.platform.detections import event as build_event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, GROUPING_TABLE, StateError, Store
from local_observe.store.backends.memory import InMemoryStore, series

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-10T09:00:00Z')
REVISION = 'correlation-fixture-rev-1'
PRODUCER = Actor('correlation-fixture', 'producer')
TOKEN = 'a' * 32
#: "the caller did not name a resource": `None` has a meaning in these fixtures (an unresolved event), so
#: the default cannot be the same value.
UNSET = object()


def identifier(name: str) -> str:
    """A stable synthetic UUID for a synthetic name, never a real estate id."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'correlation-fixture/' + name))


def resource(name: str, kind: str = 'service', relations: tuple[tuple[str, str], ...] = (),
             attributes: dict | None = None) -> dict:
    """One declaration: a name, optional outgoing relations, and the attributes routing reads."""
    return {'id': identifier(name), 'kind': kind, 'name': name,
            'aliases': [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
            'attributes': attributes if attributes is not None else {'environment': 'fixture'},
            'relations': [{'type': relation, 'target': identifier(target)} for relation, target in relations]}


def declaration() -> dict:
    """The fixture graph.

    `demo-worker --depends-on--> demo-api --runs-on--> demo-host` is one connected group two hops wide;
    `far-away` is declared and related to nothing, which is the honest negative for a temporal match;
    `loop-a`/`loop-b` are a real cycle, walked but never trusted further than their own two edges; and
    `long-a -> long-b -> long-c` exists so that a `max_hops` of 1 cannot reach `long-c` and must say so
    rather than guess, and so two incidents can be candidates for one joining event at once.
    """
    return {'schema_version': 1, 'resources': [
        resource('demo-host', 'host', attributes={'owner': 'team-platform'}),
        resource('demo-api', relations=(('runs-on', 'demo-host'),), attributes={'owner': 'team-api'}),
        resource('demo-worker', relations=(('depends-on', 'demo-api'),)),
        resource('far-away'),
        resource('loop-a', relations=(('depends-on', 'loop-b'),)),
        resource('loop-b', relations=(('depends-on', 'loop-a'),)),
        resource('long-a', relations=(('depends-on', 'long-b'),)),
        resource('long-b', relations=(('depends-on', 'long-c'),)),
        resource('long-c'),
    ]}


class BrokenGraph:
    """A `Topology` stand-in that raises whatever it is handed, on the only call grouping makes."""

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def shortest_path(self, a: str, b: str, depth=None) -> dict:
        raise self.error


class StubGraph:
    """A `Topology` stand-in returning one canned answer, for the shapes this build must not trust."""

    def __init__(self, answer: dict) -> None:
        self.answer = answer

    def shortest_path(self, a: str, b: str, depth=None) -> dict:
        return {'from': a, 'to': b, 'path': [], 'edges': [], 'revision': {}, **self.answer}


class WideEdge:
    """A declared edge long enough that a path of them cannot fit the rationale bound."""

    relation = 'x' * 64
    declaration_sha256 = 'ab' * 32
    source_id = identifier('demo-api')
    target_id = identifier('demo-host')


def wide_graph() -> StubGraph:
    """A `found` answer whose path cannot be written inside `MAX_RATIONALE_CHARS`."""
    return StubGraph({'status': 'found', 'from': identifier('demo-api'), 'to': identifier('demo-host'),
                     'path': [identifier('demo-api')] * 300 + [identifier('demo-host')],
                     'edges': [WideEdge() for _ in range(300)]})


def called_names(function: ast.FunctionDef) -> set[str]:
    """Every attribute-or-name a function calls, spelled as it appears in the source."""
    return {getattr(node.func, 'attr', None) or getattr(node.func, 'id', None)
            for node in ast.walk(function) if isinstance(node, ast.Call)}


class GraphFixture(unittest.TestCase):
    """Builds one inventory index per test and hands subclasses the store over it."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = self.root / 'inventory.db'
        index.build(declaration(), self.index_path, REVISION, now=NOW)

    def store(self, name: str = 'state.db') -> Store:
        """One platform database, created by this build (schema v7)."""
        return Store(self.root / name)

    def verdict(self, name: str, rule: str, *, at: dt.datetime = NOW, status: str = 'firing',
               severity: str | None = None, resource_id: Any = UNSET,
               parameters: dict | None = None) -> dict:
        """One canonical event about the resource called `name`, at `at`.

        `resource_id=` overrides the name — and passing `None` files an event that names no resource at
        all, which is how §4.2's unresolved case is reached; `parameters=` replaces the evidence parameters,
        which is where the redaction tests hide a sentinel: the one place a canonical event can carry a
        value this module did not compose.
        """
        window = {'start': utc_text(at - dt.timedelta(minutes=1)), 'end': utc_text(at)}
        return build_event(PRODUCER.identity, identifier(name) if resource_id is UNSET else resource_id,
                          rule, 'availability', status, window,
                          parameters or {'rule_id': rule}, query_type='gatus-result', severity=severity)

    def file(self, store: Store, verdict: dict, *, at: dt.datetime | None = None,
             grouping: bool = True, bounds: correlation.Grouping | None = None) -> dict:
        """File one event through `Store.intake`, with or without the grouping admission installed.

        `at` defaults to the instant the verdict itself carries (its window end), which is deliberate: a
        test that moves an event and forgets to move the intake clock is refused by `validate_event` for
        evaluating a window in the future, and that refusal reads like a defect in the code under test.

        `grouping=False` is the caller that never wires the feature — since correlation followups 2 that is a choice
        rather
        than a missing flag: `lo-platform intake` groups when it is given `--index` and files the old way
        when it is not — and the tests use it to pin that the new rule's no-member case is the old
        behaviour.
        """
        moment = at or timestamp(verdict['window']['end'])
        if not grouping:
            return store.intake(verdict, PRODUCER, now=moment)
        admit = store.grouping_admission(self.index_path, PRODUCER, now=moment, grouping=bounds)
        return store.intake(verdict, PRODUCER, now=moment, admission=admit)

    def raw(self, store: Store, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite, so no answer below comes from the code under test."""
        with closing(sqlite3.connect(store.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    def write(self, store: Store, sql: str, parameters: tuple = ()) -> None:
        """Write to the store's file the way a foreign caller would, and commit it.

        Only used to prove a constraint holds against somebody else's `INSERT`: a row inserted through
        this helper is committed or the assertion below it is measuring a rollback, not a CHECK.
        """
        with closing(sqlite3.connect(store.path)) as db:
            db.execute(sql, parameters)
            db.commit()

    def count(self, store: Store, table: str) -> int:
        """How many rows `table` holds, read off the file."""
        return self.raw(store, 'SELECT count(*) AS n FROM ' + table)[0]['n']


# --- the pure signals ------------------------------------------------------------------------


class TemporalSignalTests(GraphFixture):
    """`temporal` is the necessary half of the rule, and only that half."""

    def test_the_gap_inside_the_window_scores_downward_from_one(self):
        first = self.verdict('demo-api', 'api.down')
        for seconds, expected in ((0, 1.0), (150, 0.5), (300, 0.0)):
            later = self.verdict('demo-api', 'api.down', at=NOW + dt.timedelta(seconds=seconds))
            rationale = correlation.temporal(first, later, window_seconds=300)
            with self.subTest(seconds=seconds):
                self.assertIsNotNone(rationale)
                self.assertEqual(rationale.kind, 'temporal')
                self.assertAlmostEqual(rationale.score, expected, places=3)
                self.assertIn(f'{seconds} s apart', rationale.detail)

    def test_a_gap_wider_than_the_window_is_not_proximity(self):
        first = self.verdict('demo-api', 'api.down')
        later = self.verdict('demo-api', 'api.down', at=NOW + dt.timedelta(seconds=301))
        self.assertIsNone(correlation.temporal(first, later, window_seconds=300))

    def test_an_unreadable_instant_claims_nothing_rather_than_guessing_one(self):
        """v0.1 fell back to the wall clock here; that fallback is a proximity nobody measured."""
        broken = self.verdict('demo-api', 'api.down')
        broken['observed_at'] = 'not-a-time'
        self.assertIsNone(correlation.temporal(broken, self.verdict('demo-api', 'api.down')))

    def test_a_window_outside_its_bound_is_refused_not_clamped(self):
        pair = (self.verdict('demo-api', 'api.down'), self.verdict('demo-host', 'host.down'))
        for seconds in (0, -1, correlation.MAX_WINDOW_SECONDS + 1, '300', True):
            with self.subTest(seconds=seconds), self.assertRaises(correlation.CorrelationError):
                correlation.temporal(*pair, window_seconds=seconds)


class TopologicalSignalTests(GraphFixture):
    """`topological` reads the declared plane and nothing else: no path, no claim."""

    def setUp(self):
        super().setUp()
        self.graph = topology.Topology(self.index_path, depth=4)

    def test_a_declared_edge_names_itself_and_scores_the_hops(self):
        rationale = correlation.topological(self.verdict('demo-api', 'api.down'),
                                           self.verdict('demo-host', 'host.down'), self.graph)
        self.assertIsNotNone(rationale)
        self.assertEqual(rationale.kind, 'topological')
        self.assertEqual(rationale.references['hops'], 1)
        self.assertEqual(rationale.references['relations'], ['runs-on'])
        self.assertEqual(rationale.references['direction'], 'depends-on')
        self.assertEqual(rationale.references['declaration_sha256'],
                         self.graph.revision()['declaration_sha256'])
        self.assertIn('runs-on', rationale.detail)

    def test_the_second_direction_counts_when_the_first_is_negative(self):
        """`shortest_path` follows depends-on in one direction only, and a dependency is still a link
        when the event order puts the parent first."""
        child = self.verdict('demo-worker', 'worker.down')
        parent = self.verdict('demo-api', 'api.down')
        self.assertEqual(correlation.topological(child, parent, self.graph).references['hops'], 1)
        self.assertEqual(correlation.topological(parent, child, self.graph).references['hops'], 1)

    def test_two_hops_score_lower_than_one(self):
        near = correlation.topological(self.verdict('demo-worker', 'w'), self.verdict('demo-api', 'a'),
                                      self.graph)
        far = correlation.topological(self.verdict('demo-worker', 'w'), self.verdict('demo-host', 'h'),
                                     self.graph)
        self.assertGreater(near.score, far.score)
        self.assertEqual(far.references['hops'], 2)

    def test_the_same_resource_is_not_an_edge(self):
        """Grouping on identity would fold `detections.evaluate`'s coverage event into the finding filed
        beside it, which §4.2 forbids: coverage says the probe could not run, never that the condition
        recovered. `topology.shortest_path(x, x)` says plainly that its one-node path claims no edge."""
        self.assertIsNone(correlation.topological(self.verdict('demo-api', 'api.down'),
                                                self.verdict('demo-api', 'api.coverage'), self.graph))

    def test_no_declared_path_groups_nothing(self):
        self.assertIsNone(correlation.topological(self.verdict('demo-api', 'a'),
                                                self.verdict('far-away', 'f'), self.graph))

    def test_a_walk_cut_by_its_depth_bound_groups_nothing(self):
        """`depth_exceeded` means the search stopped before it could answer. v0.1's `shortest_path` could
        not tell that apart from a real negative; this one can, and the difference is the whole refusal."""
        far, near = self.verdict('long-c', 'c.down'), self.verdict('long-a', 'a.down')
        self.assertIsNone(correlation.topological(near, far, self.graph, max_hops=1))
        self.assertEqual(correlation.topological(near, far, self.graph, max_hops=2).references['hops'], 2)

    def test_a_resource_nobody_declared_groups_with_nothing(self):
        undeclared = self.verdict('unused', 'x.down', resource_id=str(uuid.uuid4()))
        self.assertIsNone(correlation.topological(undeclared, self.verdict('demo-api', 'a'), self.graph))

    def test_an_unreadable_graph_is_silence_and_not_a_failure(self):
        """A broken graph must not cost the event its finding: `intake` has already filed it, and the only
        way to leave it filed is to group nothing rather than to raise."""
        for error in (sqlite3.OperationalError('no such table'), OSError('index gone'),
                      topology.TopologyRefusal('refused'), ValueError('shape')):
            with self.subTest(error=type(error).__name__):
                self.assertIsNone(correlation.topological(
                    self.verdict('demo-api', 'a'), self.verdict('demo-host', 'h'), BrokenGraph(error)))

    def test_an_answer_shape_this_build_does_not_know_groups_nothing(self):
        for status in ('incomplete', 'depth_exceeded', 'nonsense', 'absent'):
            with self.subTest(status=status):
                self.assertIsNone(correlation.topological(
                    self.verdict('demo-api', 'a'), self.verdict('demo-host', 'h'),
                    StubGraph({'status': status, 'path': [identifier('demo-api')], 'edges': []})))

    def test_a_found_answer_without_a_traversable_path_groups_nothing(self):
        for path, edges in (([], []), ([identifier('demo-api'), identifier('demo-host')], [])):
            with self.subTest(path=len(path)):
                self.assertIsNone(correlation.topological(
                    self.verdict('demo-api', 'a'), self.verdict('demo-host', 'h'),
                    StubGraph({'status': 'found', 'path': path, 'edges': edges})))

    def test_a_cycle_is_walked_and_not_followed_round_and_round(self):
        """A declared cycle answers `found` in both directions. The bound that stops the walk is
        `topology`'s; what is asserted here is that grouping finishes with a hop count and the two real
        resources, inventing no third one and never recursing into the loop."""
        rationale = correlation.topological(self.verdict('loop-a', 'a.down'),
                                           self.verdict('loop-b', 'b.down'), self.graph)
        self.assertEqual(rationale.references['hops'], 1)
        self.assertEqual(rationale.references['path'], [identifier('loop-a'), identifier('loop-b')])

    def test_no_graph_object_claims_nothing(self):
        self.assertIsNone(correlation.topological(self.verdict('demo-api', 'a'),
                                                self.verdict('demo-host', 'h'), None))

    def test_an_event_that_names_no_resource_claims_nothing(self):
        self.assertIsNone(correlation.topological(self.verdict('demo-api', 'a', resource_id=None),
                                                self.verdict('demo-host', 'h'), self.graph))
        self.assertIsNone(correlation.topological(self.verdict('demo-api', 'a'),
                                                self.verdict('demo-host', 'h', resource_id=None),
                                                self.graph))
        self.assertIsNone(correlation.topological('not-an-event', self.verdict('demo-host', 'h'),
                                                self.graph))


class LinkInvariantTests(GraphFixture):
    """The rule itself: temporal AND structural, and no composition order that loosens it."""

    def graph(self) -> topology.Topology:
        return topology.Topology(self.index_path, depth=4)

    def test_the_same_minute_alone_is_not_a_link(self):
        pair = (self.verdict('demo-api', 'api.down'), self.verdict('far-away', 'far.down'))
        self.assertIsNotNone(correlation.temporal(*pair, window_seconds=300))
        self.assertIsNone(correlation.link(*pair, self.graph()))

    def test_a_link_always_carries_the_temporal_half_and_a_structural_one(self):
        """The assertible form of the invariant, over a grid of pairs and gaps.

        Two claims, checked on every cell: a link returned is never temporal-only, and a link is absent
        whenever the instant alone rules it out. A `link()` that ever grew an `or` into its temporal clause
        fails this on the first cell.
        """
        pairs = [('demo-api', 'demo-host'), ('demo-worker', 'demo-api'), ('demo-api', 'far-away'),
                 ('loop-a', 'loop-b'), ('long-a', 'long-c'), ('demo-host', 'far-away'),
                 ('demo-api', 'demo-api'), ('long-a', 'far-away')]
        for first, second in pairs:
            for seconds in (0, 299, 301, 1200):
                a = self.verdict(first, f'{first}.down')
                b = self.verdict(second, f'{second}.down', at=NOW + dt.timedelta(seconds=seconds))
                link = correlation.link(a, b, self.graph(), window_seconds=300, max_hops=2)
                with self.subTest(pair=(first, second), seconds=seconds):
                    if seconds > 300:
                        self.assertIsNone(link, 'a distant pair grouped anyway')
                        continue
                    kinds = [signal.kind for signal in link or []]
                    if 'topological' in kinds:
                        self.assertIsNotNone(correlation.temporal(a, b, window_seconds=300),
                                             'a structural signal without the temporal half')
                    else:
                        self.assertIsNone(link, f'a temporal-only link for {first}/{second}: {kinds}')

    def test_an_inexpressible_rationale_is_no_link_at_all(self):
        """Refusing to group is the failure direction. The alternative is a stored line the column's CHECK
        would reject inside the transaction that filed the finding, which costs an event."""
        link = correlation.link(self.verdict('demo-api', 'a'), self.verdict('demo-host', 'h'),
                               wide_graph(), max_hops=4)
        self.assertIsNone(link)

    def test_the_grouping_object_applies_its_own_bounds_to_the_same_composition(self):
        rules = correlation.Grouping(window_seconds=60)
        pair = (self.verdict('demo-api', 'a'), self.verdict('demo-host', 'h',
                                                           at=NOW + dt.timedelta(seconds=90)))
        self.assertIsNone(rules.link(*pair, self.graph()))
        self.assertIsNotNone(correlation.Grouping().link(*pair, self.graph()))


class RationaleDocumentTests(GraphFixture):
    """What a stored rationale is, and what `parse_rationale` refuses to render."""

    def stored(self) -> str:
        graph = topology.Topology(self.index_path, depth=4)
        lines = correlation.link(self.verdict('demo-api', 'api.down'),
                                self.verdict('demo-host', 'host.down'), graph)
        return correlation.rationale_document(lines)

    def test_the_document_is_canonical_json_inside_the_bound(self):
        document = self.stored()
        self.assertLessEqual(len(document), correlation.MAX_RATIONALE_CHARS)
        self.assertEqual(document, json.dumps(json.loads(document), separators=(',', ':'),
                                             sort_keys=True))
        self.assertEqual([line['kind'] for line in correlation.parse_rationale(document)],
                        ['temporal', 'topological'], 'match order is the stored order')

    def test_the_same_link_composed_twice_is_the_same_bytes(self):
        self.assertEqual(self.stored(), self.stored())

    def test_a_parsed_line_keeps_the_sentence_that_was_stored(self):
        document = self.stored()
        lines = correlation.parse_rationale(document)
        again = correlation.rationale_document([correlation.Rationale(line['kind'], line['detail'],
                                                                    line['score']) for line in lines])
        self.assertEqual([row['detail'] for row in json.loads(again)],
                        [row['detail'] for row in json.loads(document)])
        self.assertEqual([row['kind'] for row in json.loads(again)],
                        [row['kind'] for row in json.loads(document)])

    def test_a_short_line_is_readable_and_an_empty_array_is_no_lines(self):
        self.assertEqual(correlation.parse_rationale('[{"kind":"temporal","detail":"0 s apart",'
                                                    '"score":1.0}]'),
                        [{'kind': 'temporal', 'detail': '0 s apart', 'score': 1.0}])
        self.assertEqual(correlation.parse_rationale('[]'), [])

    def test_an_unreadable_line_names_nothing_rather_than_half_a_thing(self):
        for stored in ('', 'not json', '{}', '[1]', '[{"kind":"label"}]',
                       '[{"kind":"temporal","detail":"","score":0.5}]',
                       '[{"kind":"temporal","detail":"x","score":2.0}]',
                       '[{"kind":"temporal","detail":"x"}]', '"a string"', None, 7,
                       [{'kind': 'temporal', 'detail': 'x', 'score': True}],
                       '[' + '{"kind":"temporal","detail":"x","score":0.5},' * 40 +
                       '{"kind":"temporal","detail":"x","score":0.5}]'):
            with self.subTest(stored=repr(stored)[:24]):
                self.assertEqual(correlation.parse_rationale(stored), [])

    def test_a_detail_longer_than_a_sentence_is_refused(self):
        stored = json.dumps([{'kind': 'temporal', 'detail': 'x' * 300, 'score': 0.5}])
        self.assertEqual(correlation.parse_rationale(stored), [])

    def test_references_are_stored_beside_the_sentence_and_not_inside_it(self):
        rationale = correlation.Rationale('temporal', 'x', 1.0, {'hops': 2})
        self.assertEqual(rationale.as_dict()['references'], {'hops': 2})
        self.assertEqual(rationale.as_dict()['detail'], 'x')


class GroupingBoundsTests(unittest.TestCase):
    """A bound is a refusal at wiring time, because the alternative is losing a filed finding."""

    def test_every_bound_is_checked_where_it_is_configured(self):
        for changes in ({'window_seconds': 0}, {'window_seconds': correlation.MAX_WINDOW_SECONDS + 1},
                       {'max_hops': 0}, {'max_hops': correlation.MAX_SEARCH_HOPS + 1},
                       {'promotion_threshold': 0}, {'promotion_threshold': 0},
                       {'max_members': 0}, {'max_members': correlation.MAX_GROUP_MEMBERS + 1},
                       {'window_seconds': '300'}):
            with self.subTest(changes=changes), self.assertRaises(correlation.CorrelationError):
                correlation.Grouping(**changes)

    def test_the_defaults_are_the_ported_values(self):
        rules = correlation.Grouping()
        self.assertEqual((rules.window_seconds, rules.max_hops, rules.promotion_threshold,
                         rules.max_members), (300, 2, 3, correlation.MAX_GROUP_MEMBERS))


class SeverityPromotionTests(unittest.TestCase):
    """Max member severity, one rank toward critical on wide impact, capped — in three words, not six."""

    def test_the_rank_moves_toward_critical_and_never_away_from_it(self):
        """The ported arithmetic is inverted on arrival: `vocabulary.ADMITTED_SEVERITIES` is
        `('info','warning','critical')`, quietest first, so +1 is louder. v0.1's `idx -= 1` ran a
        loudest-first ladder, and copied unchanged it would make every wide incident quieter than its own
        loudest member — the silent direction this card must not ship."""
        self.assertEqual(correlation.promote(['warning', 'info'], 1), 'warning')
        self.assertEqual(correlation.promote(['warning', 'warning', 'warning'], 3), 'critical')
        self.assertEqual(correlation.promote(['info', 'info', 'info'], 3), 'warning')

    def test_the_boundary_is_distinct_resources_and_nothing_else(self):
        for resources, expected in ((1, 'warning'), (2, 'warning'), (3, 'critical'), (9, 'critical')):
            with self.subTest(resources=resources):
                self.assertEqual(correlation.promote(['warning'] * resources, resources), expected)

    def test_critical_is_the_ceiling(self):
        self.assertEqual(correlation.promote(['critical', 'critical', 'critical'], 5), 'critical')

    def test_a_quiet_group_stays_quiet_below_the_threshold(self):
        self.assertEqual(correlation.promote(['info', 'info'], 2), 'info')

    def test_the_loudest_member_decides_whatever_the_order(self):
        self.assertEqual(correlation.promote(['info', 'critical', 'warning'], 1), 'critical')
        self.assertEqual(correlation.promote(['warning', 'info'], 1), 'warning')

    def test_an_unadmitted_severity_is_refused_rather_than_read_as_info(self):
        for words in (['severe'], ['warning', ''], []):
            with self.subTest(words=words), self.assertRaises(correlation.CorrelationError):
                correlation.promote(words, 3)

    def test_a_threshold_outside_its_bound_is_refused(self):
        for threshold in (0, -1, correlation.MAX_PROMOTION_THRESHOLD + 1):
            with self.subTest(threshold=threshold), self.assertRaises(correlation.CorrelationError):
                correlation.promote(['warning'], 3, promotion_threshold=threshold)

    def test_the_member_shape_the_view_hands_over(self):
        members = [{'severity': 'warning', 'resource_id': 'a'}, {'severity': 'warning', 'resource_id': 'b'},
                  {'severity': 'warning', 'resource_id': 'c'}]
        self.assertEqual(correlation.group_severity(members), 'critical')

    def test_an_unresolved_member_adds_its_loudness_and_no_resource(self):
        """A null resource is a symptom whose cause is not linked yet (§4.2), so it counts toward the
        group's severity and not toward the impact that promotes it."""
        members = [{'severity': 'warning', 'resource_id': 'a'},
                  {'severity': 'warning', 'resource_id': None},
                  {'severity': 'warning', 'resource_id': None}]
        self.assertEqual(correlation.group_severity(members), 'warning')

    def test_an_empty_group_is_refused_rather_than_reported_as_info(self):
        for members in ([], [{}], None):
            with self.subTest(members=members), self.assertRaises(correlation.CorrelationError):
                correlation.group_severity(members)


class RungShapeTests(unittest.TestCase):
    """`*.stage<N>` is a rung of a ladder, and a ladder counts rungs per incident."""

    def test_the_rung_shape_is_the_one_escalation_composes(self):
        source = (ROOT / 'local_observe' / 'platform' / 'escalation.py').read_text(encoding='utf-8')
        self.assertIn("chain.rule_id + '.stage' + str(stage)", source,
                     'the rule this exemption matches is composed there; if that line moves, so does this')
        for rule in ('api-down.stage1', 'api-down.stage12', 'core.probe.stage3'):
            self.assertTrue(correlation.is_escalation_rung(rule), rule)

    def test_ordinary_rules_and_lookalikes_are_not_rungs(self):
        for rule in ('api-down', 'api-down.stage0', 'api-down.stage', 'api-down.stage-1', 'stage1',
                     'api-down.stage1x', None, 7, ['api-down.stage1']):
            with self.subTest(rule=rule):
                self.assertFalse(correlation.is_escalation_rung(rule))


# --- grouping through the one writer ---------------------------------------------------------


class GroupingIntakeTests(GraphFixture):
    """What `Store.intake` plus the admission callback does to the file, read back with raw sqlite."""

    def test_the_same_minute_on_unrelated_resources_stays_two_incidents(self):
        store = self.store()
        first = self.file(store, self.verdict('demo-api', 'api.down'))
        second = self.file(store, self.verdict('far-away', 'far.down'))
        self.assertNotEqual(first['incident_id'], second['incident_id'])
        self.assertEqual(self.count(store, 'incidents'), 2)
        self.assertEqual(self.count(store, GROUPING_TABLE), 0)

    def test_a_declared_edge_makes_one_incident_and_the_line_names_that_edge(self):
        store = self.store()
        first = self.file(store, self.verdict('demo-api', 'api.down'))
        second = self.file(store, self.verdict('demo-host', 'host.down'))
        self.assertEqual(first['incident_id'], second['incident_id'], 'the host joined the api incident')
        self.assertEqual(self.count(store, 'incidents'), 1, 'the incident the second event opened is gone')
        rows = self.raw(store, f'SELECT * FROM {GROUPING_TABLE}')
        self.assertEqual(len(rows), 1)
        lines = correlation.parse_rationale(rows[0]['rationale'])
        self.assertEqual([line['kind'] for line in lines], ['temporal', 'topological'])
        self.assertIn('runs-on', lines[1]['detail'])
        self.assertEqual(json.loads(rows[0]['rationale'])[1]['references']['hops'], 1)
        self.assertEqual(rows[0]['incident_id'], first['incident_id'])

    def test_the_link_is_recorded_as_one_audit_row_naming_its_signals(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        joined = self.file(store, self.verdict('demo-host', 'host.down'))
        rows = self.raw(store, "SELECT * FROM audit WHERE operation='incident.grouped'")
        self.assertEqual(len(rows), 1)
        detail = json.loads(rows[0]['detail'])
        self.assertEqual(detail['incident_id'], joined['incident_id'])
        self.assertEqual(detail['via'], ['temporal', 'topological'])
        self.assertEqual(detail['members'], 2)
        self.assertEqual(rows[0]['actor'], PRODUCER.identity,
                        'the same transaction audited the intake one row earlier, under the same identity')

    def test_a_two_hop_neighbour_joins_through_the_resource_already_in_the_group(self):
        store = self.store()
        opened = self.file(store, self.verdict('demo-api', 'api.down'))
        host = self.file(store, self.verdict('demo-host', 'host.down'))
        worker = self.file(store, self.verdict('demo-worker', 'worker.down'))
        self.assertEqual(len({opened['incident_id'], host['incident_id'], worker['incident_id']}), 1)
        self.assertEqual(self.count(store, 'incidents'), 1)
        self.assertEqual(self.count(store, GROUPING_TABLE), 2)

    def test_the_oldest_matching_incident_wins_whatever_the_order_they_were_opened(self):
        """`long-b` is one hop from both `long-a` and `long-c`, and both incidents are open and inside it.

        The join must be decided by creation order and not by hop count, score or row luck, and the second
        half of this test reverses that order to prove the answer moves with it. A rule whose answer did not
        depend on file order would be a different rule, and v0.1's engine documented this one: first member
        of the first incident, fully deterministic.

        The two anchors are ten minutes apart, so they never grouped with each other; `long-b` lands five
        minutes after the first and five before the second, which is what makes both of them candidates.
        """
        for order in (('long-a', 'long-c'), ('long-c', 'long-a')):
            with self.subTest(order=order):
                store = self.store(f'{order[0]}-{order[1]}.db')
                first = self.file(store, self.verdict(order[0], f'{order[0]}.down'))
                self.file(store, self.verdict(order[1], f'{order[1]}.down',
                                            at=NOW + dt.timedelta(minutes=10)))
                joined = self.file(store, self.verdict('long-b', 'long-b.down',
                                                     at=NOW + dt.timedelta(minutes=5)))
                self.assertEqual(joined['incident_id'], first['incident_id'],
                                'the incident that opened first is the one the neighbour joined')
                self.assertEqual(self.count(store, 'incidents'), 2, 'two candidates, one group')

    def test_an_older_candidate_that_does_not_match_does_not_shield_a_newer_one(self):
        """Every candidate inside the bound is examined, in creation order, until one corroborates.

        `long-b` is one hop from `long-c` and one hop from `long-a`, but ten and a half minutes from
        `long-a`'s subject event — outside the window, so that pair is not a group. If the search stopped
        at the oldest open incident the arriving condition would file a third one and the bound on
        candidates would be decoration. This is the test that makes `GROUP_CANDIDATES` a real limit.
        """
        store = self.store('shield.db')
        first = self.file(store, self.verdict('long-a', 'long-a.down'))
        later = NOW + dt.timedelta(minutes=10)
        second = self.file(store, self.verdict('long-c', 'long-c.down', at=later))
        arrival = later + dt.timedelta(seconds=30)
        joined = self.file(store, self.verdict('long-b', 'long-b.down', at=arrival))
        self.assertEqual(joined['incident_id'], second['incident_id'])
        self.assertNotEqual(first['incident_id'], joined['incident_id'],
                            'the older incident is untouched, not wrongly grown')
        self.assertEqual(self.count(store, 'incidents'), 2)

    def test_a_flapping_member_stays_with_its_group_through_the_pointer(self):
        """A re-firing member is not a new incident: `conditions.incident_id` is the pointer, and the
        admission never runs on a transition that opened nothing."""
        store = self.store()
        api = self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        again = self.file(store, self.verdict('demo-host', 'host.down', at=NOW + dt.timedelta(minutes=20)))
        self.assertEqual(again['incident_id'], api['incident_id'])
        self.assertIsNone(again['transition'], 'the incident was already open; nothing new was booked')

    def test_the_delivery_the_join_booked_follows_the_group(self):
        """`outbox.incident_id` moves with the condition, so the head-of-line rule `claim_notification`
        already applies keeps one incident's pages in order — and each row's own payload still says what
        was decided when it was booked."""
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        joined = self.file(store, self.verdict('demo-host', 'host.down'))
        rows = self.raw(store, 'SELECT incident_id, payload FROM outbox')
        self.assertEqual(len(rows), 2)
        self.assertEqual({row['incident_id'] for row in rows}, {joined['incident_id']})
        for row in rows:
            self.assertEqual(json.loads(row['payload'])['transition'], 'opened',
                            'pages stay per condition: the member keeps its own alert')

    def test_the_group_keeps_describing_the_condition_that_opened_it(self):
        """A symptom must not overwrite the cause in the pointer escalation and dependency suppression
        read as "this incident's subject event"."""
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        incident = self.raw(store, 'SELECT last_event_id, resource_id, condition_key FROM incidents')[0]
        payload = json.loads(self.raw(store, 'SELECT payload FROM events WHERE id=?',
                                     (incident['last_event_id'],))[0]['payload'])
        self.assertEqual(payload['rule_id'], 'api.down')
        self.assertEqual(incident['resource_id'], identifier('demo-api'))
        # and a member's *recovery* does not move it either, which is what keeps a re-firing member
        # arriving at the group it left rather than at whichever condition last spoke
        self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                    at=NOW + dt.timedelta(minutes=1)))
        again = self.raw(store, 'SELECT last_event_id FROM incidents')[0]['last_event_id']
        self.assertEqual(again, incident['last_event_id'])

    def test_no_row_points_at_an_incident_that_was_deleted(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        self.assertEqual(self.raw(store, 'SELECT id FROM events WHERE incident_id IS NULL'), [])
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_member_updates_preserve_subject_for_suppression_and_escalation(self):
        from local_observe.platform.escalation_reader import EscalationReader
        from local_observe.platform.suppression import firing_resources, condition_key
        store = self.store()
        subject = self.verdict('demo-api', 'api.down')
        opened = self.file(store, subject)
        self.file(store, self.verdict('demo-host', 'host.down'))
        for minute, status in enumerate(('firing', 'unknown', 'resolved', 'firing'), 1):
            member = self.file(store, self.verdict('demo-host', 'host.down', status=status,
                                                  at=NOW + dt.timedelta(minutes=minute)))
            self.assertEqual(member['incident_id'], opened['incident_id'])
            incident = self.raw(store, 'SELECT * FROM incidents')[0]
            self.assertEqual(incident['condition_key'], condition_key(subject))
            self.assertEqual(incident['resource_id'], subject['resource_id'])
            self.assertEqual(incident['last_event_id'], opened['event_id'])
            self.assertEqual(firing_resources(store)['resources'][subject['resource_id']]['rule_id'], 'api.down')
            with EscalationReader(store.path, ack_statuses=('approved',)) as reader:
                discovery = reader.discover(0)
                self.assertTrue(discovery.complete)
                self.assertEqual(discovery.rows[0].event['rule_id'], 'api.down')
                current = reader.read_incidents([opened['incident_id']])[opened['incident_id']]
                self.assertEqual(current.event['resource_id'], subject['resource_id'])
                self.assertEqual(current.event['rule_id'], 'api.down')
        refreshed = self.file(store, self.verdict('demo-api', 'api.down',
                                                  at=NOW + dt.timedelta(minutes=5)))
        self.assertEqual(self.raw(store, 'SELECT last_event_id FROM incidents')[0]['last_event_id'],
                         refreshed['event_id'])
        # Recovery of the anchor holds the group open; the final member closes it without
        # changing its subject. Each delivery still carries its own condition's event.
        self.file(store, self.verdict('demo-api', 'api.down', status='resolved',
                                     at=NOW + dt.timedelta(minutes=6)))
        closed = self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                              at=NOW + dt.timedelta(minutes=7)))
        self.assertEqual(closed['transition'], 'resolved')
        incident = self.raw(store, 'SELECT * FROM incidents')[0]
        self.assertEqual(incident['last_event_id'], refreshed['event_id'])
        self.assertEqual(incident['status'], 'resolved')
        delivery = self.raw(store, 'SELECT payload FROM outbox ORDER BY rowid DESC LIMIT 1')[0]
        self.assertEqual(json.loads(delivery['payload'])['event']['rule_id'], 'host.down')

    def test_no_index_configured_means_no_grouping_at_all(self):
        """An installation that declared no topology is not making a claim about what is related."""
        store = self.store()
        first = self.file(store, self.verdict('demo-api', 'api.down'), grouping=False)
        second = self.file(store, self.verdict('demo-host', 'host.down'), grouping=False)
        self.assertNotEqual(first['incident_id'], second['incident_id'])
        self.assertEqual(self.count(store, GROUPING_TABLE), 0)
        self.assertEqual(self.count(store, 'incidents'), 2)

    def test_a_graph_that_cannot_answer_leaves_the_event_its_own_incident(self):
        store = self.store('broken.db')
        admit = store.grouping_admission(self.index_path, PRODUCER, now=NOW,
                                       graph=BrokenGraph(sqlite3.OperationalError('locked')))
        first = store.intake(self.verdict('demo-api', 'api.down'), PRODUCER, now=NOW, admission=admit)
        second = store.intake(self.verdict('demo-host', 'host.down'), PRODUCER, now=NOW, admission=admit)
        self.assertNotEqual(first['incident_id'], second['incident_id'])
        self.assertEqual(self.count(store, 'events'), 2, 'the findings landed whatever the graph did')

    def test_the_group_size_bound_opens_a_second_incident_rather_than_a_wide_one(self):
        store = self.store()
        opened = self.file(store, self.verdict('demo-api', 'api.down'))
        host = self.file(store, self.verdict('demo-host', 'host.down'),
                        bounds=correlation.Grouping(max_members=2))
        self.assertEqual(opened['incident_id'], host['incident_id'])
        worker = self.file(store, self.verdict('demo-worker', 'worker.down'),
                          bounds=correlation.Grouping(max_members=2))
        self.assertNotEqual(worker['incident_id'], opened['incident_id'])
        self.assertEqual(self.count(store, 'incidents'), 2)

    def test_a_group_survives_a_restart_because_the_group_is_the_file(self):
        store = self.store()
        api = self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        reopened = Store(store.path)
        worker = self.file(reopened, self.verdict('demo-worker', 'worker.down',
                                                at=NOW + dt.timedelta(minutes=1)))
        self.assertEqual(worker['incident_id'], api['incident_id'])
        self.assertEqual(self.count(reopened, 'incidents'), 1)
        self.assertEqual(self.count(reopened, GROUPING_TABLE), 2)

    def test_a_resolved_member_rejoins_the_group_it_left(self):
        """Inside the window, the group it belongs to is still the group it finds.

        The window is measured against the incident's subject event, which a still-firing producer keeps
        fresh by re-evaluating it; that limit is stated in `docs/CONTRACTS.md` §4 rather than hidden, and
        the minute-scale gaps here are what it looks like from the outside.
        """
        store = self.store()
        api = self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                    at=NOW + dt.timedelta(minutes=1)))
        again = self.file(store, self.verdict('demo-host', 'host.down',
                                            at=NOW + dt.timedelta(minutes=2)))
        self.assertEqual(again['incident_id'], api['incident_id'])
        self.assertEqual(self.count(store, 'incidents'), 1)
        self.assertEqual(self.count(store, GROUPING_TABLE), 1,
                        'the re-join restates the one link this pair has, it does not accumulate a second')

    def test_a_duplicate_event_is_returned_before_the_admission_is_reached(self):
        store = self.store()
        verdict = self.verdict('demo-api', 'api.down')
        first = self.file(store, verdict)
        again = self.file(store, verdict)
        self.assertEqual(again['status'], 'duplicate')
        self.assertEqual(again['incident_id'], first['incident_id'])
        self.assertEqual(self.count(store, GROUPING_TABLE), 0)

    def test_the_factory_refuses_a_producer_it_would_not_let_write(self):
        """Order matters here: the same `StateError` sentence `intake` itself raises for a non-producer."""
        store = self.store()
        with self.assertRaisesRegex(StateError, 'not authorised'):
            store.grouping_admission(self.index_path, Actor('watcher', 'reader'))

    def test_the_factory_is_absent_without_a_graph_and_present_with_one(self):
        store = self.store()
        self.assertIsNone(store.grouping_admission(None, PRODUCER))
        self.assertIsNone(store.grouping_admission('', PRODUCER))
        self.assertIsNotNone(store.grouping_admission(self.index_path, PRODUCER))
        self.assertIsNotNone(store.grouping_admission(None, PRODUCER,
                                                    graph=topology.Topology(self.index_path)))


class GroupingResolutionTests(GraphFixture):
    """Correction 6(a): an incident resolves with its last open member, not with the first one home."""

    def statuses(self, store: Store) -> list[str]:
        return [row['status'] for row in self.raw(store, 'SELECT status FROM incidents')]

    def test_the_first_recovery_is_not_the_incident_s(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        resolved = self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                              at=NOW + dt.timedelta(minutes=2)))
        self.assertIsNone(resolved['transition'], 'no recovery page while the group is still open')
        self.assertEqual(self.statuses(store), ['open'])
        self.assertEqual(self.count(store, 'outbox'), 2, 'two openings, no recovery booked')

    def test_the_last_recovery_resolves_it_once(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                    at=NOW + dt.timedelta(minutes=2)))
        last = self.file(store, self.verdict('demo-api', 'api.down', status='resolved',
                                           at=NOW + dt.timedelta(minutes=3)))
        self.assertEqual(last['transition'], 'resolved')
        self.assertEqual(self.statuses(store), ['resolved'])
        self.assertEqual(self.count(store, 'outbox'), 3, 'exactly one recovery notice')

    def test_the_detached_member_is_not_counted_twice(self):
        """The count that decides is over *attached* conditions, and the member that resolved has already
        handed back its pointer — which is why a group of two needs two resolutions and not three."""
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                    at=NOW + dt.timedelta(minutes=2)))
        self.assertEqual(self.raw(store, "SELECT count(*) AS n FROM conditions WHERE incident_id IS NULL")
                        [0]['n'], 1)
        self.file(store, self.verdict('demo-api', 'api.down', status='resolved',
                                    at=NOW + dt.timedelta(minutes=3)))
        self.assertEqual(self.statuses(store), ['resolved'])

    def test_an_ordinary_incident_behaves_exactly_as_it_did_before_grouping(self):
        """The no-members case of the new rule *is* the old behaviour, asserted for a caller that never
        installs the admission — which is `lo-platform intake`'s shape (no index named, so no graph) and
        every producer round pointed at an index that declares nothing related.
        """
        store = self.store()
        opened = store.intake(self.verdict('far-away', 'far.down'), PRODUCER, now=NOW)
        closed = store.intake(self.verdict('far-away', 'far.down', status='resolved',
                                        at=NOW + dt.timedelta(minutes=2)),
                            PRODUCER, now=NOW + dt.timedelta(minutes=2))
        self.assertEqual(opened['transition'], 'opened')
        self.assertEqual(closed['transition'], 'resolved')
        self.assertEqual(self.statuses(store), ['resolved'])
        self.assertEqual(self.count(store, 'outbox'), 2)

    def test_a_condition_whose_last_verdict_is_unknown_keeps_the_incident_open(self):
        """`unknown` is not a recovery, so it is counted as open: the loud direction, deliberately."""
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        self.file(store, self.verdict('demo-host', 'host.down', status='unknown',
                                    at=NOW + dt.timedelta(minutes=2)))
        resolved = self.file(store, self.verdict('demo-api', 'api.down', status='resolved',
                                              at=NOW + dt.timedelta(minutes=3)))
        self.assertIsNone(resolved['transition'])
        self.assertEqual(self.statuses(store), ['open'])

    def test_a_grouped_member_keeps_the_openings_its_group_absorbed(self):
        """correlation followups closes the one interaction with suppression that correlation had to leave open, and says what is left.

        Flap folding counted edges in `incidents` keyed by the condition (`suppression._transitions`), and
        a join deletes the member's own incident row — so the re-openings a group absorbed were never
        counted, and the number still read as exact. They are counted now, from `incident_members` (one row
        per member-and-group, dated by the link's own `at`), and reported under their own word
        (`absorbed`) instead of being merged into `opened`: the two halves come from different tables and a
        reader is entitled to see which one the number leaned on.

        The measured numbers are the assertion. Three fire/resolve cycles of a grouped member reach
        `opened=2, resolved=2, absorbed=1` against the same producer ungrouped at `3, 3, 0`. The one edge
        still missing is a **recovery** the group swallowed: a member that resolves while the group stays
        open stamps nothing on any row keyed by its own condition, and no row in this schema dates those,
        so the grouped answer says `complete: False` and the fold sentence reads "at least". The direction
        of the remaining error is the one this module always chose — an under-count folds **less**, so it
        can only ever cost a page, never take one that was earned. Where the repair changes an answer, the
        numbers are below: at suppression's default threshold of 4 both members fold either way (four
        incident-visible edges were already enough), and at threshold 5 the grouped member folds **only**
        because the absorbed opening is counted — the edges still holding an `incidents` row are 4 there.
        """
        def episode(grouping: bool) -> tuple[Store, dict]:
            store = self.store(f'flap-{grouping}.db')
            self.file(store, self.verdict('demo-api', 'api.down'), grouping=True)
            minute = 2
            for _ in range(3):
                for status in ('firing', 'resolved'):
                    moment = NOW + dt.timedelta(minutes=minute)
                    minute += 2
                    if status == 'firing':
                        self.file(store, self.verdict('demo-host', 'host.down', at=moment), grouping=grouping)
                    else:
                        self.file(store, self.verdict('demo-host', 'host.down', status=status, at=moment),
                                  grouping=grouping)
            key = self.raw(store, "SELECT c.key FROM conditions c JOIN events e ON e.id=c.event_id"
                           " WHERE json_extract(e.payload,'$.rule_id')='host.down'")
            with closing(sqlite3.connect(store.path)) as db:
                counted = suppression._transitions(db, key[0]['key'], window_seconds=86400,
                                                  now=NOW + dt.timedelta(hours=1))
            return store, counted

        store, grouped = episode(True)
        _plain_store, plain = episode(False)
        self.assertEqual((plain['opened'], plain['resolved'], plain['absorbed'], plain['transitions']),
                         (3, 3, 0, 6), 'ungrouped, three fire/resolve cycles are six edges, as suppression documents')
        self.assertTrue(plain['complete'], 'and that number is exact: nothing was absorbed')
        self.assertEqual((grouped['opened'], grouped['resolved'], grouped['absorbed']), (2, 2, 1),
                         'the opening the group deleted is counted again, as itself and not as an incident')
        self.assertEqual(grouped['transitions'], plain['transitions'] - 1,
                         'the only edge still missing is the recovery the group absorbed and nothing dates')
        self.assertFalse(grouped['complete'], 'so the count is a stated floor, never an exact-looking number')
        visible = grouped['opened'] + grouped['resolved']
        self.assertEqual(visible, 4, 'four edges still have an `incidents` row of their own')
        verdict = self.verdict('demo-host', 'host.down', status='resolved',
                              at=NOW + dt.timedelta(minutes=12))
        with closing(sqlite3.connect(store.path)) as db:
            self.assertTrue(suppression._flapping(db, verdict, window_seconds=86400,
                                                 now=NOW + dt.timedelta(hours=1))['flapping'],
                           'at the default threshold of 4 the episode folds, as it always did')
            self.assertTrue(suppression._flapping(db, verdict, window_seconds=86400, threshold=visible + 1,
                                                 now=NOW + dt.timedelta(hours=1))['flapping'],
                           'and at threshold 5 it folds only because the absorbed opening is counted now'
                           ' — the incident-visible edges stop at 4')
        self.assertEqual(suppression.stats(store, now=NOW + dt.timedelta(hours=1), window_seconds=86400)
                        ['flap']['absorbed_in_window'], 1,
                        'the overview reads the same edges through its one bulk read, not a smaller answer')


class RungGroupingTests(GraphFixture):
    """Correction 7: escalation rungs are outside groups, on both sides of the link."""

    def test_a_rung_never_joins_the_incident_it_escalates(self):
        store = self.store()
        base = self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        rung = self.file(store, self.verdict('demo-api', 'api.down.stage2'))
        self.assertNotEqual(rung['incident_id'], base['incident_id'],
                          'the ladder files one rung per incident; a joined rung is a rung never counted')
        self.assertEqual(self.count(store, GROUPING_TABLE), 1, 'the host joined; the rung did not')

    def test_nothing_joins_an_incident_a_rung_opened(self):
        store = self.store()
        rung = self.file(store, self.verdict('demo-api', 'api.down.stage1'))
        neighbour = self.file(store, self.verdict('demo-host', 'host.down'))
        self.assertNotEqual(rung['incident_id'], neighbour['incident_id'])
        self.assertEqual(self.count(store, 'incidents'), 2)
        self.assertEqual(self.count(store, GROUPING_TABLE), 0)

    def test_the_rung_of_a_different_rule_still_opens_its_own_incident(self):
        store = self.store()
        base = self.file(store, self.verdict('demo-api', 'api.down'))
        rung = self.file(store, self.verdict('demo-api', 'api.down.stage1'))
        self.assertEqual(self.count(store, 'incidents'), 2)
        self.assertNotEqual(base['incident_id'], rung['incident_id'])
        self.assertEqual(rung['transition'], 'opened', 'a rung is a condition of its own, as designed')


class GroupingRaceTests(GraphFixture):
    """Two intakes, one group, one incident: proved with threads on one file, not with a sentence."""

    def test_two_concurrent_intakes_cannot_open_two_incidents_for_one_group(self):
        store = self.store()

        def admit(name: str, rule: str) -> dict:
            verdict = self.verdict(name, rule)
            return store.intake(verdict, PRODUCER, now=NOW,
                               admission=store.grouping_admission(self.index_path, PRODUCER, now=NOW))

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda item: admit(*item),
                                    [('demo-api', 'api.down'), ('demo-host', 'host.down')]))
        self.assertEqual(len({outcome['incident_id'] for outcome in outcomes}), 1,
                        'both producers were told the same incident')
        self.assertEqual(self.count(store, 'incidents'), 1)
        self.assertEqual(self.count(store, GROUPING_TABLE), 1, 'exactly one of the two was the joiner')
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_the_group_is_the_same_whatever_the_number_of_callers(self):
        """The same pair filed strictly one after another (the shape of a second process that never
        existed) leaves one incident too: nothing about grouping depends on racing."""
        store = self.store()
        for name, rule in (('demo-api', 'api.down'), ('demo-host', 'host.down'),
                          ('demo-worker', 'worker.down')):
            self.file(store, self.verdict(name, rule))
        self.assertEqual(self.count(store, 'incidents'), 1)


class OneWriterShapeTests(GraphFixture):
    """The AST form of "grouping is a call site of intake, inside intake's transaction".

    Behavioural tests cannot pin a *shape*: they can show that two threads agreed, but not that the next
    change does not move the decision into its own transaction, which is the change that would quietly
    reintroduce a window in which a group is half-filed. `tests/test_suppression_admission.py` pins the
    same three properties for the fold; these are the group's.
    """

    def setUp(self):
        super().setUp()
        self.tree = ast.parse((ROOT / 'local_observe' / 'platform' / 'state.py').read_text(encoding='utf-8'))

    def function(self, name: str) -> ast.FunctionDef:
        return next(node for node in ast.walk(self.tree)
                   if isinstance(node, ast.FunctionDef) and node.name == name)

    def test_intake_opens_exactly_one_transaction_and_calls_the_admission_inside_it(self):
        intake = self.function('intake')
        transactions = [node for node in ast.walk(intake)
                       if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'transaction']
        self.assertEqual(len(transactions), 1, 'a second transaction would mean a second writer')
        admitted = [node for node in ast.walk(intake)
                   if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == 'admission']
        self.assertEqual(len(admitted), 1)
        audited = [node for node in ast.walk(intake)
                  if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'audit']
        self.assertLess(audited[0].lineno, admitted[0].lineno,
                       'the callback must run after intake\'s own audit row, as its docstring promises')

    def test_grouping_opens_no_transaction_and_no_connection_of_its_own(self):
        for name in ('grouping_admission', '_join_group'):
            with self.subTest(function=name):
                names = called_names(self.function(name))
                self.assertNotIn('transaction', names)
                self.assertNotIn('connect', names)
                self.assertNotIn('exclusive_owner', names)

    def test_the_only_grouping_hook_is_intake_s_admission_argument(self):
        """Nothing else in the product may call `_join_group`: it takes a connection from `intake`."""
        callers = [node.lineno for node in ast.walk(self.tree)
                  if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == '_join_group']
        self.assertEqual(len(callers), 1, 'exactly one call site, inside `grouping_admission`')


# --- the stored rationale, as redacted context -----------------------------------------------


class GroupingRedactionTests(GraphFixture):
    """§4's promise, tested the only way it can be: put something secret-shaped in, look for it after."""

    SENTINELS = ('hunter2secretvalue', 'sk-liveabcdefghijklmnop', '198-51-100-77', 'bearerabc123def456')

    def test_a_rationale_carries_none_of_what_the_event_carried(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down',
                                    parameters={'sample_id': self.SENTINELS[0],
                                                'endpoint': self.SENTINELS[2]}))
        self.file(store, self.verdict('demo-host', 'host.down'))
        stored = self.raw(store, f'SELECT rationale FROM {GROUPING_TABLE}')[0]['rationale']
        for sentinel in self.SENTINELS:
            self.assertNotIn(sentinel, stored)
        self.assertNotIn('sample_id', stored)
        self.assertNotIn('endpoint', stored)
        self.assertNotIn('window_start', stored)
        self.assertIn('runs-on', stored, 'and it still says the one thing that makes it worth storing')

    def test_a_producer_or_rule_named_like_a_secret_does_not_reach_the_line(self):
        secret_producer = Actor('tokenrotator9f2c', 'producer')
        store = self.store()
        for name, rule in (('demo-api', 'apibearerabc123down'), ('demo-host', 'hostbearerxyz789down')):  # gitleaks:allow
            verdict = build_event(secret_producer.identity, identifier(name), rule, 'availability',
                                 'firing', {'start': utc_text(NOW - dt.timedelta(minutes=1)),
                                            'end': utc_text(NOW)}, {'rule_id': rule},
                                 query_type='gatus-result')
            store.intake(verdict, secret_producer, now=NOW,
                        admission=store.grouping_admission(self.index_path, secret_producer, now=NOW))
        stored = self.raw(store, f'SELECT rationale FROM {GROUPING_TABLE}')[0]['rationale']
        self.assertNotIn(secret_producer.identity, stored)
        self.assertNotIn('bearerabc123', stored)
        self.assertIn('topological', stored)

    def test_the_graph_edge_is_stored_as_a_reference_and_not_a_copy(self):
        store = self.store()
        self.file(store, self.verdict('demo-worker', 'worker.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        lines = json.loads(self.raw(store, f'SELECT rationale FROM {GROUPING_TABLE}')[0]['rationale'])
        references = lines[1]['references']
        self.assertEqual(references['path'],
                        [identifier('demo-worker'), identifier('demo-api'), identifier('demo-host')])
        self.assertEqual(len(references['declaration_sha256']), 64)
        self.assertNotIn('nodes', references, 'no resource names, kinds or aliases are copied in')
        self.assertNotIn('truncated', references)

    def test_the_stored_line_obeys_the_bound_the_column_advertises(self):
        graph = topology.Topology(self.index_path, depth=4)
        lines = correlation.link(self.verdict('demo-api', 'api.down'),
                                self.verdict('demo-worker', 'worker.down'), graph)
        document = correlation.rationale_document(lines)
        self.assertLessEqual(len(document), correlation.MAX_RATIONALE_CHARS)
        schema = self.raw(self.store(), 'SELECT sql FROM sqlite_master WHERE name=?',
                         (GROUPING_TABLE,))[0]['sql']
        self.assertIn(f'BETWEEN 1 AND {correlation.MAX_RATIONALE_CHARS}', schema)

    def test_the_column_refuses_an_over_wide_rationale_written_by_anybody(self):
        """The bound belongs to the file: an INSERT from outside this build hits the CHECK, not a view."""
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        incident = self.raw(store, 'SELECT id FROM incidents')[0]['id']
        for rationale, label in (('x' * 2000, 'too wide'), ('', 'empty')):
            with self.subTest(rationale=label), self.assertRaises(sqlite3.IntegrityError):
                self.write(store, f'INSERT INTO {GROUPING_TABLE}(incident_id,condition_key,rationale,at)'
                                 ' VALUES (?,?,?,?)', (incident, 'k-' + label, rationale, utc_text(NOW)))
        self.write(store, f'INSERT INTO {GROUPING_TABLE}(incident_id,condition_key,rationale,at)'
                         ' VALUES (?,?,?,?)', (incident, 'k3', '{"kind":"temporal"}', utc_text(NOW)))
        self.assertEqual(self.count(store, GROUPING_TABLE), 1,
                        'the column is width-bounded and not JSON-bounded: `parse_rationale` is the reader\'s guard')

    def test_one_row_per_pair_and_the_newest_link_wins(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        condition = self.raw(store, "SELECT c.key AS key FROM conditions c JOIN events e ON e.id=c.event_id"
                                   " WHERE json_extract(e.payload,'$.rule_id')=?", ('host.down',))[0]['key']
        incident = self.raw(store, 'SELECT id FROM incidents')[0]['id']
        self.write(store, f'INSERT OR REPLACE INTO {GROUPING_TABLE}(incident_id,condition_key,rationale,at)'
                        ' VALUES (?,?,?,?)', (incident, condition, '[]', '2027-01-01T00:00:00+00:00'))
        self.assertEqual([row['at'] for row in self.raw(store, f'SELECT at FROM {GROUPING_TABLE}')],
                        ['2027-01-01T00:00:00+00:00'],
                        'a re-join restates the link rather than accumulating a second explanation')


class GroupingViewTests(GraphFixture):
    """The operator's half: members and the per-link rationale, on the incident row and nowhere else."""

    def rows(self, store: Store, table: str = 'incidents'):
        return presentation.records(store, table, store.records(table), self.index_path)

    def test_an_incident_with_a_group_names_its_members_and_the_reason(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        row = next(item for item in self.rows(store) if 'grouping' in item)
        self.assertIn('Grouped: 2 conditions', row['display']['member_name'])
        self.assertEqual(row['grouping']['links'], 1)
        self.assertEqual([member['role'] for member in row['grouping']['members']], ['opened', 'member'])
        joined = row['grouping']['members'][1]
        self.assertEqual(joined['rule_id'], 'host.down')
        self.assertTrue(joined['attached'])
        self.assertEqual([line['kind'] for line in joined['rationale']], ['temporal', 'topological'])

    def test_an_ordinary_incident_says_so_instead_of_saying_nothing(self):
        store = self.store()
        self.file(store, self.verdict('far-away', 'far.down'), grouping=False)
        row = self.rows(store)[0]
        self.assertEqual(row['display']['member_name'], 'One condition on this incident')
        self.assertNotIn('grouping', row)

    def test_the_derived_severity_rides_the_group_and_no_column_was_added(self):
        store = self.store()
        for name in ('demo-api', 'demo-host', 'demo-worker'):
            self.file(store, self.verdict(name, f'{name}.down'))
        row = next(item for item in self.rows(store) if 'grouping' in item)
        self.assertEqual(row['grouping']['total'], 3)
        self.assertEqual(row['grouping']['severity'], 'critical',
                        'three warnings across three resources read one rank louder')
        self.assertIn('shown as critical', row['display']['member_name'])
        self.assertNotIn('severity', dict(self.raw(store, 'SELECT * FROM incidents')[0]))

    def test_a_resolved_group_still_names_the_cause_it_grouped(self):
        """A member that recovered detaches its `conditions` row; the rationale row still names it."""
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        self.file(store, self.verdict('demo-host', 'host.down', status='resolved',
                                    at=NOW + dt.timedelta(minutes=2)))
        row = next(item for item in self.rows(store) if 'grouping' in item)
        self.assertEqual(row['grouping']['total'], 2)
        self.assertEqual([member['attached'] for member in row['grouping']['members']], [True, False])
        self.assertEqual(row['grouping']['members'][1]['status'], 'resolved')

    def test_only_the_incident_view_carries_grouping(self):
        store = self.store()
        self.file(store, self.verdict('demo-api', 'api.down'))
        self.file(store, self.verdict('demo-host', 'host.down'))
        for table in ('events', 'outbox', 'actions', 'executions', 'audit'):
            for row in self.rows(store, table):
                with self.subTest(table=table):
                    self.assertNotIn('member_name', row['display'])
                    self.assertNotIn('owner_name', row['display'])
                    self.assertNotIn('grouping', row)

    def test_the_view_read_is_one_per_page_and_not_one_per_row(self):
        """The `cause_info` lesson, kept: a page of incidents must not rescan for each row.

        Counted with a wrapper around `presentation.grouping_info` rather than an `EXPLAIN`, because what
        is being pinned is the *number of calls for a page*, which is the shape that regressed in RCA.
        """
        store = self.store()
        for name in ('demo-api', 'demo-host', 'far-away'):
            self.file(store, self.verdict(name, f'{name}.down'))
        calls = []
        real = presentation.grouping_info

        def spy(db, incident_ids):
            calls.append(list(incident_ids))
            return real(db, incident_ids)

        with mock.patch.object(presentation, 'grouping_info', spy):
            rows = presentation.records(store, 'incidents', store.records('incidents'), self.index_path)
        self.assertEqual(len(rows), 2, 'one group of three, and the unrelated condition')
        self.assertEqual(len(calls), 1, 'one grouping read for the whole page')
        self.assertEqual(sorted(calls[0]), sorted(row['id'] for row in rows))


class ApiGroupingTests(GraphFixture):
    """Correction 8: HTTP intake groups. Two `Store.intake` call sites, no new route, nothing else."""

    def app_for(self, store: Store, index_path) -> None:
        self.store_object = store
        return create_app(store, [{'identity': PRODUCER.identity, 'role': 'producer', 'token': TOKEN}],
                         {}, None, index_path)

    def post(self, app, path: str, body: dict) -> tuple[int, dict]:
        output = []

        async def receive():
            return {'type': 'http.request', 'body': json.dumps(body).encode(), 'more_body': False}

        async def send(message):
            output.append(message)

        async def drive():
            await app({'type': 'http', 'method': 'POST', 'path': path, 'query_string': b'',
                      'headers': [(b'authorization', ('Bearer ' + TOKEN).encode())]}, receive, send)
        asyncio.run(drive())
        return output[0]['status'], json.loads(output[1]['body'])

    def test_post_v1_events_groups_the_way_intake_does(self):
        app = self.app_for(Store(self.root / 'api.db', NotificationPolicy(delivery_mode='off')),
                          self.index_path)
        first = self.post(app, '/v1/events', self.verdict('demo-api', 'api.down'))
        second = self.post(app, '/v1/events', self.verdict('demo-host', 'host.down'))
        self.assertEqual(first[0], 200)
        self.assertEqual(first[1]['incident_id'], second[1]['incident_id'])
        self.assertEqual(self.count(self.store_object, 'incidents'), 1)
        self.assertEqual(self.count(self.store_object, GROUPING_TABLE), 1)

    def test_the_answer_kept_exactly_the_keys_it_had(self):
        app = self.app_for(Store(self.root / 'api-keys.db', NotificationPolicy(delivery_mode='off')),
                          self.index_path)
        body = self.post(app, '/v1/events', self.verdict('far-away', 'far.down'))[1]
        self.assertEqual(sorted(body), ['event_id', 'incident_id', 'status', 'transition'])

    def test_without_an_index_the_route_behaves_exactly_as_before(self):
        app = self.app_for(Store(self.root / 'api-noindex.db', NotificationPolicy(delivery_mode='off')),
                          None)
        first = self.post(app, '/v1/events', self.verdict('demo-api', 'api.down'))
        second = self.post(app, '/v1/events', self.verdict('demo-host', 'host.down'))
        self.assertNotEqual(first[1]['incident_id'], second[1]['incident_id'])
        self.assertEqual(self.count(self.store_object, 'incidents'), 2)
        self.assertEqual(self.count(self.store_object, GROUPING_TABLE), 0)


class CliGroupingTests(GraphFixture):
    """correlation followups: a CLI producer round groups exactly like HTTP intake does — six rounds, one index each.

    Before this card the grouping callback was wired on the two HTTP routes only, so a condition filed by
    `lo-platform conditions` at a declared neighbour of a condition already open on the platform was the
    one condition in the estate that could never join anything — two entry points, two answers about what
    one incident is. `tests/test_conditions.py::CommandLineTests` is the pattern below: `sys.argv` swapped,
    stdout captured, `cli.store_reader` substituted (the product's only series transport is a ClickHouse
    this suite must not reach) — and the index, the database, the cursor file and the intake are the real
    ones, so what is asserted is the group the file holds, not the group a mock reported.

    correlation followups 2 added the seventh: `lo-platform intake --index <built index>` groups the same way, and plain
    `intake` (no index named, so no graph to consult) is pinned as filing the behaviour that predates
    grouping. Both halves are here because the flag is optional, and an optional flag is only a contract
    when the absence is asserted too.
    """

    def rule(self, rule_id: str, name: str) -> dict:
        """One sustained-condition rule about `name`, filed under this fixture's own producer identity."""
        return {'id': rule_id, 'mode': 'threshold', 'resource_id': identifier(name),
                'source': PRODUCER.identity, 'severity_source': 'sigma', 'severity_tier': 'high',
                'threshold': 90, 'metric': 'cpu', 'for_seconds': 180, 'evaluation_seconds': 60,
                'history_seconds': 86400, 'max_age_seconds': 900}

    def drive_cli(self, *arguments: str) -> tuple[int, dict]:
        """One `cli.main()` call against this fixture's index, with both resources breaching."""
        rows = [point for name in ('demo-api', 'demo-host')
                for point in series(20, name='cpu', resource_id=identifier(name),
                                    start=utc_text(NOW - dt.timedelta(seconds=60 * 20)),
                                    step_seconds=60, value=95.0)]
        argv = ['lo-platform', '--database', str(self.root / 'cli.db'), *arguments]
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli, 'store_reader', return_value=InMemoryStore(rows)), \
                mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            code = cli.main()
        return code, json.loads(out.getvalue())

    def test_a_cli_round_groups_two_related_conditions_into_one_incident(self):
        """Two rules, two declared neighbours, one round: one incident and one rationale row."""
        document = self.root / 'conditions.json'
        document.write_text(json.dumps({'interval_seconds': 300, 'rules': [
            self.rule('api.high', 'demo-api'), self.rule('host.high', 'demo-host')]}), encoding='utf-8')
        code, result = self.drive_cli('conditions', '--config', str(document), '--cursor',
                               str(self.root / 'cursor.json'), '--index', str(self.index_path),
                               '--now', utc_text(NOW))
        self.assertEqual(code, 0)
        opened = [one for one in result['intake'] if one['transition'] == 'opened']
        self.assertEqual(len(opened), 2, 'both conditions opened, and one of them then joined')
        self.assertEqual(len({one['incident_id'] for one in opened}), 1,
                         'the outcome each condition reports names the same incident')
        store = Store(self.root / 'cli.db')
        self.assertEqual(self.count(store, 'incidents'), 1, 'the group, read back off the file')
        self.assertEqual(self.count(store, GROUPING_TABLE), 1, 'with the reason it is one incident stored')
        signals = correlation.parse_rationale(self.raw(store, f'SELECT rationale FROM {GROUPING_TABLE}')[0][0])
        self.assertEqual(sorted(signal['kind'] for signal in signals), ['temporal', 'topological'],
                         'the stored line is the same composition the HTTP route writes, not a CLI-only shape')

    def test_the_intake_subcommand_without_index_opens_two_incidents(self):
        """The one CLI intake shape that still cannot group, pinned as the choice it is.

        `intake --source --event` with no `--index` names no inventory index, so `Store.grouping_admission`
        is never called and nothing is installed — the behaviour that predates grouping, unchanged. The
        flag is optional on purpose (an installation that declared no topology, and an operator filing one
        event against it, both want this), and an optional flag whose absence nobody asserts is a flag that
        silently became required.
        """
        for name, rule in (('demo-api', 'api.down'), ('demo-host', 'host.down')):
            path = self.root / f'{rule}.json'
            path.write_text(json.dumps(self.verdict(name, rule)), encoding='utf-8')
            code, result = self.drive_cli('intake', '--source', PRODUCER.identity, '--event', str(path))
            self.assertEqual((code, result['status']), (0, 'accepted'), rule)
        store = Store(self.root / 'cli.db')
        self.assertEqual(self.count(store, 'incidents'), 2, 'two incidents, because no graph was named')
        self.assertEqual(self.count(store, GROUPING_TABLE), 0, 'and no rationale row was composed')

    def test_the_intake_subcommand_with_index_groups_the_two_conditions_into_one_incident(self):
        """correlation followups 2: the same two events, the same fixture, one extra flag — and one incident.

        Everything but `--index` is the test above: two hand-filed verdicts about declared neighbours,
        through the real `cli.main()` over the real database. The assertions are the ones the positive
        producer round above makes, because after this flag there is no second CLI grouping shape — one
        incident, one rationale row, and a stored line composed by `correlation.link` like any other.
        """
        for name, rule in (('demo-api', 'api.down'), ('demo-host', 'host.down')):
            path = self.root / f'{rule}.json'
            path.write_text(json.dumps(self.verdict(name, rule)), encoding='utf-8')
            code, result = self.drive_cli('intake', '--source', PRODUCER.identity, '--event', str(path),
                                         '--index', str(self.index_path))
            self.assertEqual((code, result['status']), (0, 'accepted'), rule)
        store = Store(self.root / 'cli.db')
        self.assertEqual(self.count(store, 'incidents'), 1,
                        'the second condition joined the incident the first opened')
        self.assertEqual(self.count(store, GROUPING_TABLE), 1, 'with the reason it is one incident stored')
        signals = correlation.parse_rationale(self.raw(store, f'SELECT rationale FROM {GROUPING_TABLE}')[0][0])
        self.assertEqual(sorted(signal['kind'] for signal in signals), ['temporal', 'topological'],
                         'the stored line is the same composition the HTTP route and the producer rounds write')
        self.assertEqual(self.raw(store, 'SELECT incident_id FROM conditions')[0][0],
                        self.raw(store, 'SELECT id FROM incidents')[0][0],
                        'the member condition points at the group, not at an incident of its own')


class FaultGuardTests(GraphFixture):
    """A grouping that cannot be expressed must cost a page, never a finding."""

    def test_a_callback_that_raises_rolls_the_finding_back_so_none_of_them_may_raise_on_data(self):
        """Documented `intake` behaviour, asserted at the grouping call site: the seam is *inside* the
        transaction, so a raising callback leaves no event. That is why `link()` answers None where a
        value is merely unusable, and why the two refusals in this class cost a second incident."""
        store = self.store()
        real = store.grouping_admission(self.index_path, PRODUCER, now=NOW)

        def exploding(connection, outcome):
            real(connection, outcome)
            raise RuntimeError('a callback that raises')

        with self.assertRaises(RuntimeError):
            store.intake(self.verdict('demo-api', 'api.down'), PRODUCER, now=NOW, admission=exploding)
        self.assertEqual(self.count(store, 'events'), 0)

    def test_an_over_wide_declared_path_costs_a_second_incident_rather_than_the_event(self):
        store = self.store()
        admit = store.grouping_admission(self.index_path, PRODUCER, now=NOW, graph=wide_graph())
        first = store.intake(self.verdict('demo-api', 'api.down'), PRODUCER, now=NOW, admission=admit)
        second = store.intake(self.verdict('demo-host', 'host.down'), PRODUCER, now=NOW, admission=admit)
        self.assertEqual(self.count(store, 'events'), 2)
        self.assertEqual(self.count(store, 'incidents'), 2)
        self.assertEqual(self.count(store, GROUPING_TABLE), 0)
        self.assertNotEqual(first['incident_id'], second['incident_id'])

    def test_a_candidate_list_cut_by_its_bound_groups_nothing_and_filing_continues(self):
        """`GROUP_CANDIDATES` is a search bound, and the honest answer past it is "no group", not "the
        first group I happened to see before I stopped looking"."""
        store = self.store()
        first = self.file(store, self.verdict('demo-api', 'api.down'))
        with mock.patch('local_observe.platform.state.GROUP_CANDIDATES', 0):
            joined = self.file(store, self.verdict('demo-host', 'host.down'))
        self.assertNotEqual(first['incident_id'], joined['incident_id'])
        self.assertEqual(self.count(store, 'events'), 2)


if __name__ == '__main__':
    unittest.main()

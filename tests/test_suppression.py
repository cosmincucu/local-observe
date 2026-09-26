"""suppression: the suppression interface itself — three causes, one answer, and a send that is refused loudly.

`local_observe/platform/suppression.py` is one question ("is this finding allowed to page?") with three
answers (a human window, a dependency that is already paged, a flap that has flipped too often) and one
way to act (refuse the delivery and record it). This file is the seams: the order the causes are
consulted in, what happens on every incomplete answer, and what the durable footprint of a decision is.

The dependency half reads `local_observe/topology.py`, which landed in PW2 (topology read model), so its direction
convention is inherited rather than restated: an edge ``src --depends-on--> dst`` means *src depends on
dst*, `upstream()` is everything a resource rests on, and a child's finding is a symptom when one of
those rests on a resource holding an open incident. The fixtures below are synthetic names
(`probe-host`, `demo-api`, `demo-worker`) with uuid5-derived ids, in the shape
`tests/test_topology.py` established: nothing here is an estate resource.
"""
import copy
import datetime as dt
import json
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from local_observe import topology
from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import suppression
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-09T12:00:00Z')
REVISION = 'fixture-rev-1'
PRODUCER = Actor('suppression-fixture', 'producer')
HUMAN = Actor('operator', 'human')


def identifier(name: str) -> str:
    """A stable synthetic UUID for a name, never a real estate id."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'suppression-fixture/' + name))


def resource(name: str, kind: str = 'service', relations: tuple[tuple[str, str], ...] = ()) -> dict:
    """One declared resource, with optional outgoing depends-on relations."""
    return {'id': identifier(name), 'kind': kind, 'name': name,
            'aliases': [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
            'attributes': {'environment': 'fixture'},
            'relations': [{'type': relation, 'target': identifier(target)} for relation, target in relations]}


def chain(names: list[str]) -> list[dict]:
    """A depends-on chain: `names[0]` rests on `names[1]`, which rests on `names[2]`, and so on."""
    return [resource(name, 'service', (('depends-on', names[position + 1]),) if position + 1 < len(names)
                     else ())
            for position, name in enumerate(names)]


class SuppressionFixture(unittest.TestCase):
    """One store, one index builder, and the canonical events the tests file."""

    resources: list[dict[str, Any]] = []

    def setUp(self):
        """Open a scratch directory, build the class's index, and open one store over it."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = self.root / 'inventory.db'
        index.build({'schema_version': 1, 'resources': copy.deepcopy(self.resources)},
                    self.index_path, REVISION, now=NOW)
        self.store = Store(self.root / 'suppression.db')

    def verdict(self, status: str, at: dt.datetime, *, name: str, rule: str | None = None) -> dict:
        """One canonical event about the resource called `name`, at `at`."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, identifier(name), rule or f'{name}-down', 'availability', status,
                     window, {'sample_id': 'fixture'}, query_type='gatus-result')

    def file(self, status: str, at: dt.datetime, *, name: str, rule: str | None = None,
             graph: bool = True) -> dict:
        """File one event through the suppression path, with the declared graph when asked for."""
        return suppression.file_event(self.store, self.verdict(status, at, name=name, rule=rule), PRODUCER,
                                      now=at, index_path=self.index_path if graph else None)

    def raw(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite, so no answer comes from the code under test."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    def suppressions(self) -> list[sqlite3.Row]:
        """Every durable refusal, oldest first."""
        return self.raw('SELECT outbox_id, reason, at FROM notification_suppressions ORDER BY at')


class DependencyTests(SuppressionFixture):
    """A child's finding is a symptom when something upstream of it is already paged."""

    resources = chain(['demo-worker', 'demo-api', 'probe-host'])

    def test_an_upstream_incident_makes_the_childs_finding_a_symptom(self):
        """The brief's task 5: the parent's rule id and the path are both named in the reason.

        The parent pages and the child does not — and the child's *finding* is still filed, which is the
        half the next assertion makes. An operator reading the incident list sees the symptom with the
        cause beside it instead of seeing nothing.
        """
        parent = self.file('firing', NOW, name='demo-api')
        self.assertFalse(parent['suppressed'], 'the parent itself always pages')
        child = self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')
        self.assertTrue(child['suppressed'])
        decision = child['decision']
        self.assertEqual(decision.cause, 'dependency')
        self.assertEqual(decision.detail['parent'], identifier('demo-api'))
        self.assertEqual(decision.detail['path'], [identifier('demo-worker'), identifier('demo-api')])
        self.assertEqual(decision.detail['hops'], 1)
        self.assertEqual(decision.detail['relation'], 'depends-on')
        self.assertIn(identifier('demo-api'), decision.reason)
        self.assertIn('demo-api-down', decision.reason, 'the reason names the rule that is firing upstream')
        self.assertEqual(self.raw('SELECT id FROM events WHERE id=?',
                                  (child['intake']['event_id'],))[0]['id'], child['intake']['event_id'])

    def test_a_resource_is_never_downstream_of_itself(self):
        """`probe-host` is upstream of `demo-api`; nothing is upstream of itself, so both findings page."""
        self.file('firing', NOW, name='probe-host')
        second = self.file('firing', NOW + dt.timedelta(seconds=30), name='probe-host', rule='host-full')
        self.assertFalse(second['suppressed'], 'a second rule on a resource is not a symptom of the first')

    def test_the_finding_stands_when_the_parent_has_recovered(self):
        """The dependency map is the `incidents` table, so closing the parent's incident ends the fold."""
        self.file('firing', NOW, name='demo-api')
        self.assertTrue(self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')['suppressed'])
        self.file('resolved', NOW + dt.timedelta(seconds=60), name='demo-api')
        later = self.file('firing', NOW + dt.timedelta(seconds=90), name='demo-worker', rule='worker-late')
        self.assertFalse(later['suppressed'])

    def test_a_two_hop_graph_blames_the_nearest_down_parent_and_prints_the_path(self):
        """`worker -> api -> host`, host down: the blame is the host and the path shows the hop through api.

        Depth is asked for, never assumed (`DEPENDENCY_DEPTH` is one hop), because how far a symptom
        travels is a claim about the graph.
        """
        self.file('firing', NOW, name='probe-host')
        decision = suppression.decide(self.store, self.verdict('firing', NOW + dt.timedelta(seconds=30),
                                                              name='demo-worker', rule='worker-two-hop'),
                                      now=NOW + dt.timedelta(seconds=30), index_path=self.index_path,
                                      depth=2)
        self.assertTrue(decision.suppressed)
        self.assertEqual(decision.detail['parent'], identifier('probe-host'))
        self.assertEqual(decision.detail['path'], [identifier('demo-worker'), identifier('demo-api'),
                                                   identifier('probe-host')])
        self.assertEqual(decision.detail['hops'], 2)
        self.assertIn(' -> ', decision.reason)

    def test_the_nearest_down_parent_wins_when_more_than_one_is_down(self):
        """Two down ancestors, one hop and two: the one-hop one is blamed (v0.1's nearest, id tie-break)."""
        self.file('firing', NOW, name='probe-host')
        self.file('firing', NOW + dt.timedelta(seconds=10), name='demo-api')
        decision = suppression.decide(self.store, self.verdict('firing', NOW + dt.timedelta(seconds=40),
                                                              name='demo-worker'),
                                      now=NOW + dt.timedelta(seconds=40), index_path=self.index_path,
                                      depth=3)
        self.assertEqual(decision.detail['parent'], identifier('demo-api'))

    def test_an_undeclared_resource_and_a_missing_graph_both_page(self):
        """The two ways dependency suppression is simply off, and both are the loud direction."""
        self.file('firing', NOW, name='demo-api')
        outside = Store(self.root / 'undeclared.db')
        undeclared = suppression.decide(outside, event(
            PRODUCER.identity, identifier('nowhere'), 'ghost-down', 'availability', 'firing',
            {'start': utc_text(NOW), 'end': utc_text(NOW + dt.timedelta(seconds=60))},
            {'sample_id': 'fixture'}, query_type='gatus-result'), now=NOW + dt.timedelta(seconds=60),
            index_path=self.index_path)
        self.assertFalse(undeclared.suppressed)
        without_graph = suppression.decide(self.store, self.verdict('firing', NOW + dt.timedelta(seconds=30),
                                                                   name='demo-worker'),
                                           now=NOW + dt.timedelta(seconds=30))
        self.assertFalse(without_graph.suppressed)

    def test_a_walk_cut_by_its_row_bound_suppresses_nothing_and_says_why(self):
        """A *row* cut can hide the nearest down parent, so the finding stands and no blame is printed.

        The fixture is built deliberately wide (25 declared dependencies, the down one last) and the
        truncation is confirmed against `topology` before the suppression answer is asserted — otherwise
        the test would pass on a graph that was never cut.
        """
        wide = [resource('wide-service', 'service',
                         tuple(('depends-on', f'wide-dependency-{step}') for step in range(25)))]
        wide += [resource(f'wide-dependency-{step}', 'service') for step in range(25)]
        path = self.root / 'wide.db'
        index.build({'schema_version': 1, 'resources': wide}, path, REVISION, now=NOW)
        graph = topology.Topology(path, depth=1, max_rows=suppression.MAX_DEPENDENCY_NODES)
        self.assertIn('rows', graph.upstream(identifier('wide-service'), 1,
                                            max_rows=suppression.MAX_DEPENDENCY_NODES)['truncated_by'],
                      'the fixture must actually run the bound out')
        store = Store(self.root / 'wide-store.db')
        store.intake(event(PRODUCER.identity, identifier('wide-dependency-24'), 'wide-down', 'availability',
                           'firing', {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)},
                           {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=NOW)
        decision = suppression.decide(store, event(
            PRODUCER.identity, identifier('wide-service'), 'service-down', 'availability', 'firing',
            {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)},
            {'sample_id': 'fixture'}, query_type='gatus-result'), now=NOW, index_path=path)
        self.assertFalse(decision.suppressed)

    def test_the_nearest_parent_and_the_path_survive_a_restart(self):
        """Nothing about a dependency decision is remembered in a process: it is the `incidents` rows."""
        self.file('firing', NOW, name='demo-api')
        child = self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')
        self.assertTrue(child['suppressed'])
        reopened = Store(self.root / 'suppression.db')
        again = suppression.decide(reopened, self.verdict('firing', NOW + dt.timedelta(seconds=30),
                                                         name='demo-worker'),
                                   now=NOW + dt.timedelta(seconds=30), index_path=self.index_path)
        self.assertEqual(again.reason, child['decision'].reason)
        self.assertEqual(again.detail['parent'], child['decision'].detail['parent'])

    def test_firing_resources_reads_the_open_incidents_and_says_whole_or_truncated(self):
        """The down-map is a query, not a cache: two open incidents, one resource each, `truncated` False."""
        self.assertFalse(suppression.firing_resources(self.store)['resources'])
        self.file('firing', NOW, name='demo-api')
        answer = suppression.firing_resources(self.store)
        self.assertEqual(list(answer['resources']), [identifier('demo-api')])
        self.assertEqual(answer['resources'][identifier('demo-api')]['rule_id'], 'demo-api-down')
        self.assertFalse(answer['truncated'])

    def test_a_resource_with_no_open_incident_is_never_blamed(self):
        """`status='open'` is the whole down-state: a resolved incident does not suppress anything."""
        self.file('firing', NOW, name='demo-api')
        self.file('resolved', NOW + dt.timedelta(seconds=30), name='demo-api')
        self.assertFalse(suppression.firing_resources(self.store)['resources'])
        self.assertFalse(self.file('firing', NOW + dt.timedelta(seconds=60), name='demo-worker',
                                  rule='worker-after')['suppressed'])


class PrecedenceTests(SuppressionFixture):
    """Which reason wins, because precedence is a claim and not an accident of code order."""

    resources = chain(['demo-worker', 'demo-api'])

    def setUp(self):
        """Build the shared fixture, then a flap, a down parent and a window over all of it."""
        super().setUp()
        self.file('firing', NOW, name='demo-api')
        for step in range(6):
            at = NOW + dt.timedelta(seconds=10 * step)
            self.file('resolved' if step % 2 else 'firing', at, name='demo-worker', rule='worker-flap')

    def declare(self, **overrides) -> dict:
        """Open a window over the child resource, as a human would."""
        document = {'resource_id': identifier('demo-worker'), 'starts_at': utc_text(NOW),
                    'ends_at': utc_text(NOW + dt.timedelta(hours=4)), 'reason': 'planned work'}
        document.update(overrides)
        return suppression.declare_window(self.store, document, HUMAN, now=NOW)

    def test_a_human_window_outranks_a_down_parent_which_outranks_a_flap(self):
        """One reason per silence: the declaration, then the graph, then the statistic.

        The same event is decided three times with the same shape and a different winner each time, so
        the order is asserted and not inferred from whichever branch happened to answer first.
        """
        at = NOW + dt.timedelta(seconds=70)
        verdict = self.verdict('firing', at, name='demo-worker', rule='worker-flap')
        flapping_only = suppression.decide(self.store, verdict, now=at)
        self.assertEqual(flapping_only.cause, 'flapping', 'the window and the parent are not in place yet')
        with_dependency = suppression.decide(self.store, verdict, now=at, index_path=self.index_path)
        self.assertEqual(with_dependency.cause, 'dependency')
        self.declare()
        with_window = suppression.decide(self.store, verdict, now=at, index_path=self.index_path)
        self.assertEqual(with_window.cause, 'maintenance-window')
        self.assertIn('planned work', with_window.reason)

    def test_a_decision_that_suppresses_nothing_still_carries_its_count(self):
        """The count is on every answer: "why was this one NOT folded?" is asked as often as the reverse."""
        at = NOW + dt.timedelta(seconds=70)
        answer = suppression.decide(self.store, self.verdict('firing', at, name='demo-api'),
                                    now=at).as_dict()
        self.assertFalse(answer['suppressed'])
        self.assertIsNone(answer['cause'])
        self.assertEqual(answer['transitions'], 1, 'this condition opened one incident, at `now`')
        self.assertEqual(sorted(answer['detail']), ['threshold', 'window_seconds'])
        self.assertEqual(len(answer), 6)

    def test_a_non_canonical_event_is_refused_before_anything_is_read(self):
        """`decide` validates through `state.validate_event`, so a malformed event is a refusal."""
        at = NOW + dt.timedelta(seconds=70)
        broken = self.verdict('firing', at, name='demo-api') | {'severity': 'very-bad'}
        with self.assertRaisesRegex(StateError, 'severity'):
            suppression.decide(self.store, broken, now=at)
        with self.assertRaises(StateError):
            suppression.decide(self.store, {'source': 'x'}, now=at)


class ApplyTests(SuppressionFixture):
    """What a decision costs: one dead outbox row, one refusal row, one audit line — or nothing."""

    resources = chain(['demo-worker', 'demo-api'])

    def test_a_decision_writes_the_same_trio_the_delivery_rail_writes_for_a_budget(self):
        """`status='dead'`, `notification_suppressions`, `notification.suppressed`: all three, once."""
        self.file('firing', NOW, name='demo-api')
        child = self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')
        rows = self.raw('SELECT status FROM outbox WHERE id=?', (child['delivery'],))
        self.assertEqual(rows[0]['status'], 'dead')
        self.assertEqual(len(self.suppressions()), 1)
        self.assertEqual(self.suppressions()[0]['outbox_id'], child['delivery'])
        audit = self.raw("SELECT actor, detail FROM audit WHERE operation='notification.suppressed'")
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]['actor'], suppression.WORKER_ACTOR)
        self.assertEqual(json.loads(audit[0]['detail'])['cause'], 'dependency')

    def test_the_event_and_the_incident_are_untouched_by_the_refusal(self):
        """The two rows this module may never write are the two rows it never writes.

        `intake` runs unchanged and first, so a suppressed finding keeps its `events` row, its incident
        and its `event.intake` audit line; what this module adds is the delivery refusal and nothing else.
        """
        self.file('firing', NOW, name='demo-api')
        child = self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')
        intake = self.raw("SELECT operation, count(*) AS n FROM audit WHERE operation='event.intake'"
                          ' GROUP BY operation')
        self.assertEqual(intake[0]['n'], 2)
        self.assertEqual(len(self.raw('SELECT id FROM events')), 2)
        self.assertEqual(len(self.raw('SELECT id FROM incidents WHERE status=\'open\'')), 2,
                         'the child incident is open, it simply was not paged')
        self.assertTrue(child['intake']['incident_id'])

    def test_two_suppression_asks_about_one_delivery_write_one_refusal(self):
        """A second ask about a row that is already refused writes nothing at all.

        Reached by calling the two entry points in the order a retry could: the fold is already recorded,
        so the later ask cannot edit the explanation an operator already read, and it must not spend a
        second audit line on a decision that changed nothing.
        """
        self.file('firing', NOW, name='demo-api')
        child = self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')
        again = suppression.suppress_delivery(self.store, child['delivery'],
                                              'maintenance-window x for resource y covers this finding',
                                              cause='maintenance-window', now=NOW + dt.timedelta(seconds=40))
        self.assertFalse(again, 'the row is already dead, so a second refusal writes nothing')
        self.assertEqual(len(self.suppressions()), 1)
        self.assertIn('dependency', self.suppressions()[0]['reason'])
        self.assertEqual(len(self.raw("SELECT sequence FROM audit WHERE operation='notification.suppressed'")),
                         1)

    def test_stats_split_the_three_causes_and_count_the_budgets_reasons_as_other(self):
        """One number per cause, read off one table.

        The order of the filings *is* the test: the flap runs while nothing upstream is down (otherwise
        every child event answers `dependency` by precedence and the flap branch is never exercised),
        then the parent opens, then a window covers a third rule.
        """
        for step in range(5):
            at = NOW + dt.timedelta(seconds=10 * step)
            self.file('resolved' if step % 2 else 'firing', at, name='demo-worker', rule='worker-flap')
        self.file('firing', NOW + dt.timedelta(seconds=100), name='demo-api')
        self.assertTrue(self.file('firing', NOW + dt.timedelta(seconds=110), name='demo-worker',
                                 rule='worker-symptom')['suppressed'])
        suppression.declare_window(self.store, {'rule_id': 'worker-windowed', 'starts_at': utc_text(NOW),
                                               'ends_at': utc_text(NOW + dt.timedelta(hours=2)),
                                               'reason': 'planned work'}, HUMAN, now=NOW)
        self.assertTrue(self.file('firing', NOW + dt.timedelta(seconds=120), name='demo-worker',
                                 rule='worker-windowed')['suppressed'])
        stats = suppression.stats(self.store, now=NOW + dt.timedelta(seconds=120))
        self.assertEqual(stats['suppressed_by_cause']['flapping'], 2)
        self.assertEqual(stats['suppressed_by_cause']['maintenance-window'], 1)
        self.assertEqual(stats['suppressed_by_cause']['dependency'], 1)
        self.assertEqual(stats['suppressed_by_cause']['other'], 0)
        self.assertEqual(stats['suppressed_deliveries'], sum(stats['suppressed_by_cause'].values()))
        self.assertEqual(stats['windows']['live'], 1)
        self.assertEqual(stats['conditions_total'], 4)

    def test_a_budget_suppression_and_a_fold_share_the_table_and_stay_separate_in_the_count(self):
        """`other` is a bucket and not an error: the send budget's reasons are not this module's doing."""
        delivery = self.file('firing', NOW, name='demo-api')['delivery']
        from local_observe.platform.state import record_suppression
        with self.store.transaction() as connection:
            record_suppression(connection, delivery, 'flood-circuit-open', NOW)
        stats = suppression.stats(self.store, now=NOW + dt.timedelta(seconds=1))
        self.assertEqual(stats['suppressed_by_cause']['other'], 1)
        self.assertEqual(stats['suppressed_by_cause']['flapping'], 0)
        self.assertEqual(suppression.suppressed_deliveries(self.store), 1)

    def test_suppress_delivery_refuses_a_malformed_reason_and_an_unknown_cause(self):
        """The cause vocabulary and the sentence bound are the two things that keep `stats` honest."""
        delivery = self.file('firing', NOW, name='demo-api')['delivery']
        for cause in ('other', 'BUDGET', '', None):
            with self.subTest(cause=cause), self.assertRaisesRegex(StateError, 'Unknown suppression cause'):
                suppression.suppress_delivery(self.store, delivery, 'dependency x is down', cause=cause,
                                              now=NOW)
        for reason in ('', 'multi\nline', 'x' * 401, None):
            with self.subTest(reason=reason), self.assertRaisesRegex(StateError, 'printable bounded line'):
                suppression.suppress_delivery(self.store, delivery, reason, cause='dependency', now=NOW)
        with self.assertRaisesRegex(StateError, 'Expected canonical UUID'):
            suppression.suppress_delivery(self.store, 'not-a-uuid', 'dependency x is down',
                                          cause='dependency', now=NOW)
        self.assertEqual(self.suppressions(), [])


class OverviewFieldTests(SuppressionFixture):
    """The one number this module puts on the operator's front page, and what it refuses to say."""

    resources = chain(['demo-worker', 'demo-api'])

    def test_the_overview_counts_the_refusal_list_and_answers_none_rather_than_zero_without_a_file(self):
        """`dead_deliveries` says a send stopped; this says a decision stopped it, and by how many.

        None is the answer when the read is impossible — an object with no file behind it, a database this
        process cannot open — because a missing number is a fact and a zero would be a claim that nothing
        was suppressed. That is the same line `overview.py` draws for every signal tile above it.
        """
        from local_observe.platform.overview import overview
        self.assertEqual(overview(self.store, now=NOW)['suppressed_deliveries'], 0)
        self.file('firing', NOW, name='demo-api')
        self.assertEqual(overview(self.store, now=NOW)['suppressed_deliveries'], 0)
        self.assertTrue(self.file('firing', NOW + dt.timedelta(seconds=30), name='demo-worker')['suppressed'])
        self.assertEqual(overview(self.store, now=NOW)['suppressed_deliveries'], 1)
        self.assertEqual(overview(self.store, now=NOW)['dead_deliveries'], 1,
                         'the folded row is the same row the failure tile already counts')

        class NoFile:
            """The shape `tests/test_overview.py`'s partial `Store` double has: no path, no read."""

            def status(self):
                return {'incidents': {}, 'actions': {}, 'notifications': {}}

        self.assertIsNone(suppression.suppressed_deliveries(NoFile()))
        self.assertIsNone(overview(NoFile(), now=NOW)['suppressed_deliveries'])


class InterfaceShapeTests(unittest.TestCase):
    """The module's own vocabulary, pinned so a rename is a reviewed change and not a quiet one."""

    def test_the_cause_words_are_the_first_word_of_every_reason_this_module_writes(self):
        """`stats` buckets on that token, so the two lists cannot disagree without failing here."""
        self.assertEqual(suppression.CAUSES, ('maintenance-window', 'dependency', 'flapping'))
        self.assertEqual(suppression.OPERATIONS, ('maintenance.declared', 'maintenance.revoked',
                                                 'notification.suppressed'))
        self.assertEqual(suppression.WORKER_ACTOR, 'suppression-worker')

    def test_the_bounds_are_named_numbers_and_not_magic(self):
        """Every bound a test or an operator quotes is written once, here, in this shape."""
        self.assertEqual(suppression.FLAP_WINDOW_SECONDS, 300)
        self.assertEqual(suppression.FLAP_THRESHOLD, 4)
        self.assertEqual(suppression.FLAP_THRESHOLD_BOUNDS[0], 2, 'never fold the first page')
        self.assertEqual(suppression.MAX_WINDOW_SECONDS, 86400, 'a day, and the schema agrees')
        self.assertEqual(suppression.DEPENDENCY_DEPTH, 1)
        self.assertGreater(suppression.MAX_TRANSITION_ROWS, suppression.FLAP_THRESHOLD_BOUNDS[1],
                           'a scan that hits the cap has already earned the verdict it reports')

    def test_a_bound_is_refused_and_never_clamped(self):
        """`_bound` is the one door: out of range or not a number is the same refusal shape."""
        for value in (True, '300', None, 3.5, float('nan'), float('inf'), -1, 0, 101):
            with self.subTest(value=value):
                self.assertRaises(StateError, suppression._bound, 'flap_threshold', value, 2, 100)
        self.assertEqual(suppression._bound('flap_threshold', 4, 2, 100), 4)


if __name__ == '__main__':
    unittest.main()

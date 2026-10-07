"""Path-change detection (path monitoring): the condition's lifecycle, and the event this product cannot file.

`local_observe/platform/pathcheck.py` tracks one route signature per
`(vantage_resource_id, target, protocol)` in its own cursor. These tests walk **one transition per
test**, in the order an operator would meet them: a first sighting, a route that moves, a route that
moves again, a route that comes home, and a route that sits still.

Two behaviours are deliberate and both are argued in the module docstring; they are pinned here so a
later reader cannot "fix" them by accident:

* **A never-seen path is baselined, not reported.** v0.1's rule. A producer that fired on its own
  first round would page for whatever route it happened to boot onto, and a restart would page again.
* **A bare route change files no event.** `vocabulary.REFUSALS` — merged as event vocabulary, aimed at this card
  by name — says `netpath.path_change` is neither `drift` nor `availability` and needs a new `kind`
  by decision. So the transition is durable state, a round summary and a CLI field, and the reviewer
  decision is whether it should also become an incident (:class:`NoEventForARouteTests` states what
  is owed and what is not). The *consequence* of a route change that costs reachability is filed
  anyway, by the verdict channel, which is what makes waiting honest rather than silent.

Times and fixtures follow `test_pathcheck.py`: :data:`NOW` is five seconds inside a 300-second round
whose watermark is ``12:00:00Z``.
"""
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import utc_text
from local_observe.platform import pathcheck
from local_observe.platform import pathcheck_parsers as parsers
from local_observe.platform.state import Actor, Store, validate_event

VANTAGE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
SIBLING = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
SOURCE = 'pathchange-test'
INTERVAL = dt.timedelta(seconds=300)
WATERMARK = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.timezone.utc)
LATER = WATERMARK + INTERVAL
NOW = WATERMARK + dt.timedelta(seconds=5)
DECLARATION = {'schema_version': 1, 'resources': [
    {'id': VANTAGE, 'kind': 'host', 'name': 'probe-1',
     'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'}],
     'attributes': {'environment': 'demo'}, 'relations': []},
    {'id': SIBLING, 'kind': 'host', 'name': 'probe-2',
     'aliases': [{'type': 'hostname', 'value': 'probe-2.example.test'}],
     'attributes': {'environment': 'demo'}, 'relations': []}]}


def trace(*hops: tuple, target: str = 'demo-api', vantage: str = VANTAGE,
          protocol: str = 'icmp') -> parsers.TraceReport:
    """Build a :class:`TraceReport` from `(ttl, address, rtts)` triples, as a probe runner would."""
    records = [{'ttl': ttl, 'address': address, 'rtts_ms': list(rtts)} for ttl, address, rtts in hops]
    return parsers.parse_traceroute(records, vantage_resource_id=vantage, target=target,
                                    protocol=protocol)


def one_hop(address: str = '10.11.0.1') -> tuple:
    """The shortest trace that means anything: one replying hop, as a hop set."""
    return ((1, address, [1.0]),)


def two_hops(near: str = '10.11.0.1', far: str = '198.51.100.9') -> tuple:
    """Two hops, for the case where a route grows a router rather than changing one."""
    return ((1, near, [1.0]), (2, far, [2.0]))


class RouteStateTests(unittest.TestCase):
    """The state machine on its own, with a dictionary standing in for the cursor."""

    def setUp(self) -> None:
        self.state: dict[str, dict[str, str]] = {}

    def observe(self, *traces: parsers.TraceReport, at: str = '2026-08-05T12:00:00Z') -> list:
        return pathcheck.observe_routes(self.state, traces, observed_at=at)

    def test_a_route_this_producer_has_never_seen_is_baselined_and_says_nothing(self):
        findings = self.observe(trace(*one_hop()))
        self.assertEqual(findings, [])
        stored = self.state[pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]
        self.assertEqual(stored['open'], 'no')
        self.assertEqual(len(stored['baseline']), 64)

    def test_the_first_signature_change_opens_the_condition(self):
        self.observe(trace(*one_hop()))
        findings = self.observe(trace(*two_hops()))
        self.assertEqual([item.transition for item in findings], ['opened'])
        opened = findings[0]
        self.assertEqual((opened.target, opened.protocol, opened.vantage_resource_id),
                         ('demo-api', 'icmp', VANTAGE))
        self.assertEqual(opened.hop_count, 2)
        self.assertNotEqual(opened.previous_signature, opened.current_signature)
        self.assertEqual(opened.baseline_signature, opened.previous_signature,
                         'the baseline moved, so "off baseline" no longer means what the name says')
        self.assertEqual(self.state[pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]['open'], 'yes')

    def test_a_second_change_holds_the_condition_open_rather_than_claiming_recovery(self):
        """The one departure from the brief's literal wording, and the reason for it.

        A -> B opens. B -> C under "any later change resolves it" would tell the operator the route
        came home when all that happened is that it moved again. Under this rule the condition means
        what its name says — the route in use is not the route that was baselined — and it closes only
        on the route actually coming back.
        """
        self.observe(trace(*one_hop()))
        self.observe(trace(*two_hops()))
        findings = self.observe(trace(*two_hops(near='10.11.0.2')))
        self.assertEqual([item.transition for item in findings], ['held'])
        self.assertEqual(self.state[pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]['open'], 'yes')

    def test_the_route_coming_home_resolves_the_condition(self):
        baseline = trace(*one_hop())
        self.observe(baseline)
        self.observe(trace(*two_hops()))
        findings = self.observe(baseline)
        self.assertEqual([item.transition for item in findings], ['resolved'])
        self.assertEqual(self.state[pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]['open'], 'no')
        self.assertEqual(findings[0].current_signature, baseline.path_signature)

    def test_a_round_on_the_baseline_after_a_resolution_is_silence(self):
        """Quiet means the route is the expected one; it must never be confused with `held`."""
        baseline = trace(*one_hop())
        self.observe(baseline)
        self.observe(trace(*two_hops()))
        self.observe(baseline)
        self.assertEqual(self.observe(baseline), [])

    def test_a_hop_going_quiet_is_a_path_change_and_not_a_silent_router(self):
        """The `*` rule, end to end: an unresponsive hop participates in the signature."""
        self.observe(trace((1, '10.11.0.1', [1.0]), (2, '198.51.100.9', [2.0])))
        findings = self.observe(trace((1, '10.11.0.1', [1.0]), (2, None, [None])))
        self.assertEqual([item.transition for item in findings], ['opened'])
        self.assertEqual(findings[0].hop_count, 2)

    def test_each_triple_keeps_its_own_baseline_so_two_targets_cannot_share_one_verdict(self):
        self.observe(trace(*one_hop(), target='demo-api'), trace(*one_hop(), target='cache-01'))
        findings = self.observe(trace(*two_hops(), target='demo-api'))
        self.assertEqual([(item.target, item.transition) for item in findings],
                         [('demo-api', 'opened')])
        self.assertEqual(len(self.state), 2)

    def test_the_same_route_over_a_different_protocol_is_a_different_condition(self):
        key = pathcheck.route_key(VANTAGE, 'demo-api', 'tcp')
        self.observe(trace(*one_hop()))
        self.assertNotIn(key, self.state)
        self.observe(trace(*one_hop(), protocol='tcp'))
        self.assertIn(key, self.state)
        self.assertEqual(self.observe(trace(*two_hops(), protocol='tcp'))[0].transition, 'opened')

    def test_a_different_vantage_point_never_shares_the_route_it_is_compared_against(self):
        self.observe(trace(*one_hop()))
        findings = self.observe(trace(*one_hop(), vantage=SIBLING))
        self.assertEqual(findings, [], "a sibling's first sighting read as a change on my route")
        self.assertEqual(len(self.state), 2)
        self.assertEqual({item.vantage_resource_id for item in self.observe(
            trace(*two_hops(), vantage=SIBLING))}, {SIBLING})

    def test_the_key_is_unambiguous_because_no_component_can_contain_the_separator(self):
        key = pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')
        self.assertEqual(key.count('|'), 2)
        self.assertEqual(key.split('|'), [VANTAGE, 'demo-api', 'icmp'])
        for value in ('probe-1', VANTAGE.upper(), 'a/b', 'x' * 129, ''):
            with self.subTest(value=str(value)[:16]):
                with self.assertRaises(ValueError):
                    pathcheck.route_key(value, 'demo-api', 'icmp')
        with self.assertRaises(ValueError):
            pathcheck.route_key(VANTAGE, 'not/a/label', 'icmp')

    def test_the_bounded_number_of_route_keys_is_a_refusal_and_not_an_eviction(self):
        """Silently dropping the oldest route would turn an over-capacity cursor into a false baseline."""
        self.state.update({f'{VANTAGE}|t{index}|icmp': {'baseline': 'a' * 64, 'signature': 'a' * 64,
                                                        'open': 'no'}
                           for index in range(pathcheck.MAX_ROUTES)})
        with self.assertRaises(pathcheck.PathCheckError) as raised:
            self.observe(trace(*one_hop()))
        self.assertIn('maximum', str(raised.exception))
        self.assertEqual(len(self.state), pathcheck.MAX_ROUTES, 'the bound replaced a route')

    def test_a_finding_carries_digests_and_counts_and_never_a_hop_list(self):
        self.observe(trace(*one_hop()))
        finding = self.observe(trace(*two_hops('198.51.100.7', '198.51.100.8')))[0].as_dict()
        self.assertEqual(finding['transition'], 'opened')
        self.assertNotIn('198.51.100.7', json.dumps(finding))
        self.assertNotIn('hops', finding)


class RoundTests(unittest.TestCase):
    """The route state through one real round: the cursor, the index, and what a restart remembers."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'inventory.db'
        index.build(DECLARATION, self.index, 'fixture')
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        self.state_dir = self.root / 'state'
        self.state_dir.mkdir()
        self.cursor = self.state_dir / 'pathcheck.json'
        self.config = pathcheck.load_config(self.write(self.document()))

    def document(self) -> dict:
        return {'vantage_resource_id': VANTAGE, 'targets': ['demo-api'], 'protocols': ['icmp'],
                'interval_seconds': 300, 'sources': {'reports_dir': str(self.reports)},
                'cursor': str(self.cursor)}

    def write(self, document: object, name: str = 'pathcheck.json') -> Path:
        path = self.root / name
        path.write_text(document if isinstance(document, str) else json.dumps(document),
                        encoding='utf-8')
        return path

    def write_report(self, hops: tuple, *, observed_at: dt.datetime = WATERMARK,
                     ok: bool = True) -> None:
        """Drop this vantage's report: one probe of the target, and the trace under test."""
        payload = {'schema_version': 1, 'vantage_resource_id': VANTAGE,
                   'observed_at': utc_text(observed_at),
                   'probes': [{'target': 'demo-api', 'ok': ok}],
                   'traces': [{'target': 'demo-api', 'protocol': 'icmp',
                               'hops': [{'ttl': ttl, 'address': address, 'rtts_ms': list(rtts)}
                                        for ttl, address, rtts in hops]}]}
        (self.reports / f'{VANTAGE[:8]}.json').write_text(json.dumps(payload), encoding='utf-8')

    def round(self, *, now: dt.datetime = NOW) -> tuple[dict, list[dict]]:
        events: list[dict] = []
        summary = pathcheck.tick(self.index, self.config, self.cursor, events.append, now=now,
                                 source=SOURCE)
        return summary, events

    def cursor_text(self) -> dict:
        return json.loads(self.cursor.read_text(encoding='utf-8'))

    def test_a_baselined_route_then_a_change_reports_the_transition_and_reaches_the_cursor(self):
        self.write_report(one_hop())
        first, events = self.round()
        self.assertEqual(first['route_findings'], [])
        self.assertEqual(first['verdict'], 'ok')
        self.write_report(two_hops(), observed_at=LATER)
        second, events = self.round(now=NOW + INTERVAL)
        self.assertEqual([item['transition'] for item in second['route_findings']], ['opened'])
        self.assertEqual(second['transitions'], 1)
        stored = self.cursor_text()['routes'][pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]
        self.assertEqual(stored['open'], 'yes')
        self.assertEqual(len(stored['baseline']), 64)

    def test_a_restart_reads_the_same_baseline_from_the_cursor_and_does_not_re_page(self):
        """v0.1's `PathTracker` held this in a dict, so every restart re-baselined and re-fired."""
        self.write_report(one_hop())
        self.round()
        self.write_report(two_hops(), observed_at=LATER)
        self.round(now=NOW + INTERVAL)
        # A new process, same cursor: the alternate route is still the open fact, not a new one.
        self.write_report(two_hops(), observed_at=LATER + INTERVAL)
        third, _ = self.round(now=NOW + 2 * INTERVAL)
        self.assertEqual([item['transition'] for item in third['route_findings']], ['held'])

    def test_refused_delivery_retains_acknowledged_routes_and_the_intended_transition(self):
        self.write_report(one_hop())
        self.round()
        self.write_report(two_hops(), observed_at=LATER, ok=False)
        before = self.cursor_text()

        def refuse(item: dict) -> None:
            raise RuntimeError('intake refused')

        with self.assertRaises(RuntimeError):
            pathcheck.tick(self.index, self.config, self.cursor, refuse, now=NOW + INTERVAL,
                           source=SOURCE)
        pending = self.cursor_text()['pending']
        self.assertEqual(self.cursor_text()['routes'], before['routes'])
        self.assertEqual(self.cursor_text()['open'], before['open'])
        self.assertIsNotNone(pending, 'the refused transition must remain available for replay')
        self.assertEqual(before['routes'][pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]['open'],
                         'no', 'the refused transition was written anyway')
        self.assertIsNone(before['open'])
        summary, events = self.round(now=NOW + INTERVAL)
        self.assertEqual(summary['result'], 'replayed')
        self.assertEqual(events, pending['events'])
        self.assertEqual(self.cursor_text()['routes'], pending['routes'])
        self.assertEqual(self.cursor_text()['open'], pending['open'])

    def test_a_route_change_alone_files_no_event_and_the_ok_verdict_says_nothing_either(self):
        """event vocabulary's refusal, pinned: a bare route change has no `kind`, so nothing reaches intake.

        The route finding is not a log line either — it is durable cursor state and a named field of
        the round result — but the reviewer decision the card owes is whether it should open an
        incident. This test is the line in the sand: if a `kind` is ever decided for it, this test is
        the one that must change, together with `vocabulary.REFUSALS` and docs/CONTRACTS.md §4.
        """
        self.write_report(one_hop())
        self.round()
        self.write_report(two_hops(), observed_at=LATER)
        summary, events = self.round(now=NOW + INTERVAL)
        self.assertEqual(summary['verdict'], 'ok')
        self.assertEqual(events, [])
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual([item['transition'] for item in summary['route_findings']], ['opened'])

    def test_a_route_change_that_costs_reachability_is_still_filed_by_the_verdict_channel(self):
        """The consequence is what gets an event, which is what makes waiting on the kind honest."""
        self.write_report(one_hop())
        self.round()
        self.write_report(two_hops(), observed_at=LATER, ok=False)
        summary, events = self.round(now=NOW + INTERVAL)
        self.assertEqual(summary['verdict'], 'target')
        self.assertEqual([(item['kind'], item['status'], item['rule_id']) for item in events],
                         [('availability', 'firing', 'pathcheck.target')])
        validate_event(events[0], NOW + INTERVAL)
        self.assertEqual([item['transition'] for item in summary['route_findings']], ['opened'])

    def test_removing_the_cursor_re_baselines_and_reports_nothing_until_the_route_moves_again(self):
        self.write_report(one_hop())
        self.round()
        self.write_report(two_hops(), observed_at=LATER)
        self.round(now=NOW + INTERVAL)
        self.cursor.unlink()
        self.write_report(two_hops(), observed_at=LATER + INTERVAL)
        summary, events = self.round(now=NOW + 2 * INTERVAL)
        self.assertEqual(summary['route_findings'], [])
        self.assertEqual(events, [])
        self.assertEqual(self.cursor_text()['routes'][
            pathcheck.route_key(VANTAGE, 'demo-api', 'icmp')]['open'], 'no')

    def test_a_trace_record_that_is_malformed_refuses_its_report_not_the_round(self):
        """A trace is a `target`, a `protocol` and a hop set; each half missing is its own refusal.

        The hop-set shapes are the ones a probe runner writes when it is unhappy: no hops at all (the
        run died), a hop with a ttl of 0 (not a TTL), and a hop with no RTT list (nothing to analyze).
        All of them refuse the *report* — a trace this producer cannot read is not a trace that did not
        happen — and none of them touches another vantage's file.
        """
        refused = [
            [{'protocol': 'icmp', 'hops': [{'ttl': 1, 'rtts_ms': [1.0]}]}],
            [{'target': 'demo-api', 'protocol': 'icmp'}],
            [{'target': 'demo-api', 'protocol': 'icmp', 'hops': []}],
            [{'target': 'demo-api', 'protocol': 'icmp', 'hops': [{'ttl': 0, 'rtts_ms': [1.0]}]}],
            [{'target': 'demo-api', 'protocol': 'icmp', 'hops': [{'ttl': 1}]}],
            [{'target': 'demo-api', 'protocol': 'icmp', 'hops': [{'ttl': 1, 'rtts_ms': [1.0],
                                                                  'extra': 1}]}],
        ]
        for position, bad in enumerate(refused):
            with self.subTest(traces=str(bad)):
                self.cursor = self.root / f'trace-hygiene-{position}.json'
                payload = {'schema_version': 1, 'vantage_resource_id': VANTAGE,
                           'observed_at': utc_text(WATERMARK),
                           'probes': [{'target': 'demo-api', 'ok': True}], 'traces': bad}
                (self.reports / f'{VANTAGE[:8]}.json').write_text(json.dumps(payload), encoding='utf-8')
                summary, _ = self.round()
                self.assertEqual(summary['unparseable_reports'], 1, bad)
                self.assertEqual(summary['traces'], 0)

    def test_a_trace_on_a_protocol_nobody_asked_for_is_skipped_rather_than_refused(self):
        """A probe report may carry more than this configuration reads; that is not a broken report.

        Refusing the file would punish the vantage for the operator's narrower `protocols` list, and a
        baseline for a route nobody compares would be a lie about having observed it. So it is skipped
        and counted, the same way an out-of-scope probe record is.
        """
        payload = {'schema_version': 1, 'vantage_resource_id': VANTAGE,
                   'observed_at': utc_text(WATERMARK), 'probes': [{'target': 'demo-api', 'ok': True}],
                   'traces': [{'target': 'demo-api', 'protocol': 'udp',
                               'hops': [{'ttl': 1, 'address': '10.11.0.1', 'rtts_ms': [1.0]}]}]}
        (self.reports / f'{VANTAGE[:8]}.json').write_text(json.dumps(payload), encoding='utf-8')
        summary, _ = self.round()
        self.assertEqual(summary['unparseable_reports'], 0)
        self.assertEqual(summary['traces'], 0)
        self.assertEqual(summary['out_of_scope_probes'], 1)
        self.assertEqual(summary['verdict'], 'ok')

    def test_a_route_finding_never_reaches_an_event_body_where_a_hop_address_could_live(self):
        address = '203.0.113.77'
        self.write_report(one_hop(address))
        self.round()
        self.write_report(two_hops('10.11.0.1', '198.51.100.9'), observed_at=LATER, ok=False)
        _, events = self.round(now=NOW + INTERVAL)
        self.assertNotIn(address, json.dumps(events))
        self.assertNotIn(address, self.cursor.read_text(encoding='utf-8'))

    def test_the_store_accepts_a_verdict_round_end_to_end_with_a_route_change_beside_it(self):
        """The one place a real `Store` sees this producer: the event is legal, the route is not one."""
        store = Store(self.root / 'state.db')
        producer = Actor(SOURCE, 'producer')
        self.write_report(one_hop())
        pathcheck.tick(self.index, self.config, self.cursor,
                       lambda item: store.intake(item, producer, now=NOW), now=NOW, source=SOURCE)
        self.write_report(two_hops(), observed_at=LATER)
        received: list[dict] = []

        def deliver(item: dict) -> None:
            received.append(store.intake(item, producer, now=NOW + INTERVAL))

        summary = pathcheck.tick(self.index, self.config, self.cursor, deliver, now=NOW + INTERVAL,
                                 source=SOURCE)
        self.assertEqual(received, [], 'a route change wrote into the platform as an event')
        self.assertEqual(summary['transitions'], 1)


class CursorRoundTripTests(unittest.TestCase):
    """What the route state looks like on disk, and the shapes it refuses to be read back as."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cursor = self.root / 'pathcheck.json'
        self.config = pathcheck.load_config(self.write(
            {'vantage_resource_id': VANTAGE, 'targets': ['demo-api'], 'protocols': ['icmp'],
             'sources': {'reports_dir': str(self.root)}, 'cursor': str(self.cursor)}, 'config.json'))

    def write(self, document: dict, name: str) -> Path:
        path = self.root / name
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def test_a_saved_route_state_reads_back_identically(self):
        state = {pathcheck.route_key(VANTAGE, 'demo-api', 'icmp'):
                 {'baseline': 'a' * 64, 'signature': 'b' * 64, 'open': 'yes'}}
        pathcheck.save_cursor(self.cursor, {'schema_version': pathcheck.CURSOR_VERSION,
                                            'binding': pathcheck.cursor_binding(self.config),
                                            'open': {'kind': 'availability',
                                                     'rule_id': 'pathcheck.local'},
                                            'routes': state})
        self.assertEqual(pathcheck.load_cursor(self.cursor, self.config)['routes'], state)

    def test_the_cursor_file_is_private_and_a_second_write_keeps_it_so(self):
        if os.name == 'nt':
            self.skipTest('this asserts POSIX mode bits, which Windows does not store')
        pathcheck.save_cursor(self.cursor, {'schema_version': pathcheck.CURSOR_VERSION,
                                            'binding': pathcheck.cursor_binding(self.config),
                                            'open': None, 'routes': {}})
        pathcheck.save_cursor(self.cursor, {'schema_version': pathcheck.CURSOR_VERSION,
                                            'binding': pathcheck.cursor_binding(self.config),
                                            'open': None, 'routes': {}})
        mode = self.cursor.stat().st_mode
        self.assertFalse(mode & 0o077, f'cursor mode is {oct(mode)}; group or other can read it')

    def test_a_target_set_change_refuses_the_cursor_because_the_baselines_are_about_those_targets(self):
        pathcheck.save_cursor(self.cursor, {'schema_version': pathcheck.CURSOR_VERSION,
                                            'binding': pathcheck.cursor_binding(self.config),
                                            'open': None, 'routes': {}})
        moved = pathcheck.load_config(self.write(
            {**self.document(), 'targets': ['other-api']}, 'moved.json'))
        with self.assertRaises(ValueError) as raised:
            pathcheck.load_cursor(self.cursor, moved)
        self.assertIn('target set', str(raised.exception))

    def document(self) -> dict:
        return {'vantage_resource_id': VANTAGE, 'targets': ['demo-api'], 'protocols': ['icmp'],
                'interval_seconds': 300, 'sources': {'reports_dir': str(self.root)},
                'cursor': str(self.cursor)}

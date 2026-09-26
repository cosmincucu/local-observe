"""The "is it me or them" verdict (path monitoring): the matrix, the events it files, and the identity it needs.

Two ideas carry this file.

**A verdict is only as firm as the coverage it was computed from.** Every case below names the
vantage points that *reported*; the ones that were expected and did not are what turn a would-be
`ok` into `indeterminate`. v0.1 could not express that, because it had no expected set — it classified
whatever arrived, so a probe host that died silently produced a healthy network. That single
behaviour is the difference between this card and a straight port, and it is pinned by
:class:`CoverageGapTests`.

**A vantage point with no declared identity has no right to a verdict.** The fixture index below is
built from an inline declaration of three `probe-N.example.test` hosts (synthetic naming's placeholder naming, so the
file is copyable), and every assertion about identity is a real `index.resolve` against a real SQLite
snapshot — not a mock of one. An undeclared *configured* vantage refuses the whole round; an
undeclared vantage in someone else's report file is excluded and counted, and the hole it leaves is
what makes the round `indeterminate`.

Times are fixed and window-aligned throughout, in the `test_config_drift.py` idiom: :data:`NOW` sits
five seconds inside a 300-second round whose watermark is ``12:00:00Z``. Every emitted event is
checked with the real `state.validate_event` and filed with the real `Store.intake`, because an event
this producer is pleased with and intake refuses is the failure this card exists to prevent.
"""
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import cli, pathcheck
from local_observe.platform.state import Actor, StateError, Store, validate_event

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_DECLARATION = ROOT / 'examples/inventory/declared.yaml'
# Three declared vantage points, synthetic naming's placeholder scheme: example.test hostnames, 10.11.0.0/16 addresses.
VANTAGE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
SIBLING = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
THIRD = '9b1dede5-2f4c-4cb1-9dd3-9f2a1d3f5a11'
UNDECLARED = '00000000-4000-4000-8000-000000000000'
SOURCE = 'pathcheck-test'
PRODUCER = Actor(SOURCE, 'producer')
INTERVAL = dt.timedelta(seconds=300)
WATERMARK = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.timezone.utc)
LATER = WATERMARK + INTERVAL
NOW = WATERMARK + dt.timedelta(seconds=5)
LATER_NOW = LATER + dt.timedelta(seconds=5)
API, ROUTER, CACHE = 'demo-api', 'router-01', 'cache-01'
# The matrix rows below name their vantage points V1/V2/V3 so the table reads as a table; these are the
# canonical UUIDs the classifier actually demands, and the labels below are the only aliases for them.
V1, V2, V3 = VANTAGE, SIBLING, THIRD
T1, T2, T3 = 't-1', 't-2', 't-3'

DECLARATION = {'schema_version': 1, 'resources': [
    {'id': VANTAGE, 'kind': 'host', 'name': 'probe-1',
     'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'},
                 {'type': 'ip', 'value': '10.11.0.21'}],
     'attributes': {'environment': 'demo'}, 'relations': []},
    {'id': SIBLING, 'kind': 'host', 'name': 'probe-2',
     'aliases': [{'type': 'hostname', 'value': 'probe-2.example.test'},
                 {'type': 'ip', 'value': '10.11.0.22'}],
     'attributes': {'environment': 'demo'}, 'relations': []},
    {'id': THIRD, 'kind': 'host', 'name': 'probe-3',
     'aliases': [{'type': 'hostname', 'value': 'probe-3.example.test'},
                 {'type': 'ip', 'value': '10.11.0.23'}],
     'attributes': {'environment': 'demo'}, 'relations': []}]}


def observed(target: str, vantage: str, ok: bool, *, asn: str | None = None,
             protocol: str = 'icmp') -> pathcheck.ProbeObservation:
    """One probe result, in the shape the classifier reads."""
    return pathcheck.ProbeObservation(target=target, vantage_resource_id=vantage, ok=ok, asn=asn,
                                       protocol=protocol)


def window(end: dt.datetime = WATERMARK) -> dict[str, str]:
    """The aligned `(end - interval, end]` window a round judged at *end* carries on its events."""
    return {'start': utc_text(end - INTERVAL), 'end': utc_text(end)}


class Deliverer:
    """The delivery seam: validate each event for real, file it, and remember both answers."""

    def __init__(self, store: Store, *, now: dt.datetime) -> None:
        self.store, self.now = store, now
        self.events: list[dict] = []
        self.receipts: list[dict] = []

    def __call__(self, item: dict) -> None:
        validate_event(item, self.now)
        self.events.append(dict(item))
        self.receipts.append(self.store.intake(item, PRODUCER, now=self.now))


class Fixture(unittest.TestCase):
    """Shared scratch: a declared index of three probes, a store, a reports directory, a config."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'inventory.db'
        index.build(DECLARATION, self.index, 'fixture')
        self.store = Store(self.root / 'state.db')
        self.reports = self.root / 'reports'
        self.reports.mkdir()
        self.cursor = self.root / 'state' / 'pathcheck.json'
        self.cursor.parent.mkdir()

    def document(self, **overrides) -> dict:
        """One valid configuration document, with *overrides* merged (`None` removes a key)."""
        document: dict = {'vantage_resource_id': VANTAGE, 'targets': [API, ROUTER],
                          'protocols': ['icmp', 'tcp'], 'interval_seconds': 300,
                          'sources': {'reports_dir': str(self.reports)}, 'cursor': str(self.cursor)}
        for key, value in overrides.items():
            if value is None:
                document.pop(key, None)
            else:
                document[key] = value
        return document

    def write_json(self, document: object, name: str = 'pathcheck.json') -> Path:
        """Write *document* where the producer will be pointed, and return the path."""
        path = self.root / name
        path.write_text(document if isinstance(document, str) else json.dumps(document),
                        encoding='utf-8')
        return path

    def config(self, **overrides) -> dict:
        """Return the validated form of :meth:`document`, written to disk and read back."""
        return pathcheck.load_config(self.write_json(self.document(**overrides)))

    def write_report(self, probes: list[dict], *, vantage: str = VANTAGE,
                     observed_at: dt.datetime = WATERMARK, traces: list[dict] | None = None,
                     name: str | None = None) -> Path:
        """Drop one vantage point's report where the producer reads them."""
        payload = {'schema_version': 1, 'vantage_resource_id': vantage,
                   'observed_at': utc_text(observed_at), 'probes': probes}
        if traces is not None:
            payload['traces'] = traces
        path = self.reports / (name or f'{vantage[:8]}.json')
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def write_raw_report(self, document: object, name: str) -> Path:
        """Drop *document* in the reports tree exactly as given: a broken, huge or extra-keyed file."""
        path = self.reports / name
        path.write_text(document if isinstance(document, str) else json.dumps(document),
                        encoding='utf-8')
        return path

    def probe(self, target: str, ok: bool, **extra: object) -> dict:
        """One probe record inside a report."""
        record: dict = {'target': target, 'ok': ok}
        record.update(extra)
        return record

    def round(self, *, now: dt.datetime = NOW, config: dict | None = None,
            deliverer: Deliverer | None = None) -> tuple[dict, Deliverer]:
        """One round against the shared index and reports; returns the summary and what was filed."""
        deliverer = deliverer or Deliverer(self.store, now=now)
        return pathcheck.tick(self.index, config or self.config(), self.cursor, deliverer, now=now,
                              source=SOURCE), deliverer


class VerdictMatrixTests(unittest.TestCase):
    """The five verdicts from a fixture matrix: vantages x targets x outcomes -> verdict.

    `V1/V2/V3` are the declared probes above, `T1/T2/T3` are targets. `✓` = the probe answered,
    `x` = it did not, `-` = that vantage probed that target at all. `E` names the expected set handed
    to the classifier. Read the rows with :meth:`Fixture`'s defaults in mind: two expected targets.
    """

    MATRIX = [
        # label, observations, expected vantages, expected targets, verdict
        ('every target reachable from every vantage', [
            observed(T1, V1, True), observed(T1, V2, True)], [V1, V2], [T1], 'ok'),
        ('one target dead everywhere it was probed, a second alive', [
            observed(T1, V1, False), observed(T1, V2, False),
            observed(T2, V1, True), observed(T2, V2, True)], [V1, V2], [T1, T2],
            'target'),
        ('one target dead, probed by one vantage only', [
            observed(T1, V1, False), observed(T2, V1, True)], [V1], [T1, T2],
            'target'),
        ('two targets dead from V1 only, both alive from V2', [
            observed(T1, V1, False), observed(T2, V1, False),
            observed(T1, V2, True), observed(T2, V2, True)], [V1, V2], [T1, T2],
            'local'),
        ('two targets sharing an AS, dead everywhere', [
            observed(T1, V1, False, asn='AS64500'), observed(T1, V2, False, asn='AS64500'),
            observed(T2, V1, False, asn='AS64500'), observed(T2, V2, False, asn='AS64500'),
            observed(T3, V1, True), observed(T3, V2, True)], [V1, V2], [T1, T2, T3],
            'upstream/route'),
        ('dead targets in different ASes are a target fault, not a route one', [
            observed(T1, V1, False, asn='AS64500'), observed(T1, V2, False, asn='AS64500'),
            observed(T2, V1, False, asn='AS64501'), observed(T2, V2, False, asn='AS64501')],
            [V1, V2], [T1, T2], 'target'),
        ('one dead target with an ASN never clusters (CLUSTER_MIN_TARGETS is 2)', [
            observed(T1, V1, False, asn='AS64500'), observed(T1, V2, False, asn='AS64500'),
            observed(T2, V1, True), observed(T2, V2, True)], [V1, V2], [T1, T2],
            'target'),
        ('one target down from one vantage only, and V1 probed too few targets to be local', [
            observed(T1, V1, False), observed(T1, V2, True)], [V1], [T1],
            'indeterminate'),
        ('V1 loses everything it probed but V2 never reported to exonerate the targets', [
            observed(T1, V1, False), observed(T2, V1, False)], [V1], [T1, T2],
            'target'),
        ('mixed partial failures with no blast-radius pattern', [
            observed(T1, V1, False), observed(T1, V2, True),
            observed(T2, V1, True), observed(T2, V2, False),
            observed(T3, V1, True), observed(T3, V2, True)], [V1, V2], [T1, T2, T3],
            'indeterminate'),
    ]

    def setUp(self) -> None:
        self.classified = {row[0]: self.classify(row) for row in VerdictMatrixTests.MATRIX}

    @staticmethod
    def classify(row) -> pathcheck.ReachabilityVerdict:
        _label, observations, expected_vantages, expected_targets, _verdict = row
        return pathcheck.classify(observations, expected_vantage_points=expected_vantages,
                                  expected_targets=expected_targets)

    def test_every_row_of_the_matrix_lands_where_the_table_says(self):
        for row in VerdictMatrixTests.MATRIX:
            label, _observations, _expected_vantages, _expected_targets, verdict = row
            with self.subTest(case=label):
                self.assertEqual(self.classified[label].verdict, verdict)

    def test_the_five_verdict_values_are_v01s_and_are_all_reachable_here(self):
        self.assertEqual(pathcheck.VERDICTS, ('ok', 'target', 'local', 'upstream/route',
                                              'indeterminate'))
        self.assertEqual({row[4] for row in VerdictMatrixTests.MATRIX}, set(pathcheck.VERDICTS))

    def test_the_matrix_is_a_table_of_the_cases_and_not_only_of_the_funny_ones(self):
        self.assertEqual(len(self.classified), len(VerdictMatrixTests.MATRIX))

    def test_affected_names_the_targets_or_for_local_the_vantage_point(self):
        dead = self.classified['one target dead everywhere it was probed, a second alive']
        self.assertEqual(dead.affected, (T1,))
        local = self.classified['two targets dead from V1 only, both alive from V2']
        self.assertEqual(local.affected, (V1,))
        self.assertEqual(self.classified['every target reachable from every vantage'].affected, ())

    def test_failing_pairs_name_the_target_and_the_vantage_that_could_not_reach_it(self):
        verdict = self.classified['one target dead everywhere it was probed, a second alive']
        self.assertEqual(verdict.failing, ((T1, V1), (T1, V2)))
        self.assertEqual(self.classified['every target reachable from every vantage'].failing, ())

    def test_every_verdict_explains_itself_in_notes_a_log_line_can_carry(self):
        for label, verdict in self.classified.items():
            with self.subTest(case=label):
                self.assertTrue(verdict.notes, f'{label} reached {verdict.verdict} with no reasoning')
                self.assertTrue(all(isinstance(line, str) and line for line in verdict.notes))

    def test_the_last_probe_for_a_triple_wins_so_a_corrected_reread_is_not_history(self):
        verdict = pathcheck.classify([observed(T1, V1, False), observed(T1, V1, True)],
                                     expected_targets=[T1])
        self.assertEqual(verdict.verdict, 'ok')
        self.assertEqual(pathcheck.classify([observed(T1, V1, True), observed(T1, V1, False)],
                                            expected_targets=[T1]).verdict, 'target')

    def test_a_pair_fails_when_any_probed_protocol_failed_so_tcp_is_not_excused_by_icmp(self):
        verdict = pathcheck.classify([observed(T1, V1, True),
                                      observed(T1, V1, False, protocol='tcp'),
                                      observed(T1, V2, True),
                                      observed(T1, V2, False, protocol='tcp')],
                                     expected_targets=[T1])
        self.assertEqual(verdict.verdict, 'target')

    def test_nothing_is_fabricated_from_an_empty_set(self):
        with self.assertRaises(pathcheck.PathCheckError) as raised:
            pathcheck.classify([])
        self.assertIn('refusing to fabricate a verdict', str(raised.exception))

    def test_a_malformed_observation_refuses_rather_than_becoming_a_verdict(self):
        cases = [
            ('not a record', [object()]),
            ('ok must be a boolean', [pathcheck.ProbeObservation('T1', VANTAGE, 'yes')]),
            ('vantage must be a UUID', [observed('T1', 'probe-1', True)]),
            ('target must be a label', [observed('a/b', VANTAGE, True)]),
            ('protocol must be admitted', [observed('T1', VANTAGE, True, protocol='http')]),
            ('asn must look like an ASN', [observed('T1', VANTAGE, True, asn='64500')]),
        ]
        for label, observations in cases:
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    pathcheck.classify(observations)

    def test_a_misshapen_expected_set_refuses_to_silently_widen_or_narrow_coverage(self):
        with self.assertRaises(ValueError):
            pathcheck.classify([observed('T1', VANTAGE, True)], expected_vantage_points=['probe-1'])
        with self.assertRaises(ValueError):
            pathcheck.classify([observed('T1', VANTAGE, True)], expected_targets=['../../etc/passwd'])


class CoverageGapTests(Fixture):
    """Silence is not health: an expected reporter that said nothing degrades the verdict."""

    def classify(self, observations, **kwargs) -> pathcheck.ReachabilityVerdict:
        arguments: dict = {'expected_vantage_points': [VANTAGE, SIBLING], 'expected_targets': [API]}
        arguments.update(kwargs)
        return pathcheck.classify(observations, **arguments)

    def test_a_vantage_point_that_probed_nothing_makes_the_round_indeterminate_not_ok(self):
        """The task-8 case, and the one behaviour v0.1 could not express at all."""
        reachable = self.classify([observed(API, VANTAGE, True)])
        self.assertEqual(reachable.verdict, 'indeterminate')
        self.assertTrue(any(SIBLING in line and 'reported no probe' in line for line in reachable.notes),
                        f'the notes never name who went quiet: {reachable.notes}')

    def test_a_configured_target_that_nobody_probed_is_indeterminate_too(self):
        verdict = self.classify([observed(API, VANTAGE, True), observed(API, SIBLING, True)],
                                expected_targets=[API, ROUTER])
        self.assertEqual(verdict.verdict, 'indeterminate')
        self.assertTrue(any(ROUTER in line and 'not probed' in line for line in verdict.notes))

    def test_the_pattern_the_data_would_have_supported_survives_in_the_notes(self):
        """`indeterminate` is the verdict; the operator still gets to read what it looked like."""
        verdict = self.classify([observed(API, VANTAGE, False), observed(ROUTER, VANTAGE, False)],
                                expected_targets=[API, ROUTER])
        self.assertEqual(verdict.verdict, 'indeterminate')
        self.assertEqual(verdict.affected, (), 'a degraded verdict kept an implication it did not earn')
        self.assertTrue(any('"target"' in line for line in verdict.notes), verdict.notes)

    def test_every_expected_reporter_reporting_clears_the_degradation(self):
        verdict = self.classify([observed(API, VANTAGE, True), observed(API, SIBLING, True)])
        self.assertEqual(verdict.verdict, 'ok')

    def test_a_blind_round_is_indeterminate_coverage_about_the_source_and_never_ok(self):
        self.reports.rmdir()  # the mount is not there at all
        summary, delivered = self.round()
        self.assertEqual(summary['verdict'], 'indeterminate')
        self.assertEqual(summary['blind_reason'], 'reports_directory_absent')
        self.assertEqual([(item['kind'], item['status']) for item in delivered.events],
                         [('coverage', 'firing')])
        self.assertEqual(delivered.events[0]['rule_id'], 'pathcheck.coverage')
        self.assertEqual(summary['open_finding'], {'kind': 'coverage', 'rule_id': 'pathcheck.coverage'})

    def test_the_round_the_producer_itself_never_reported_is_a_gap_and_not_an_ok(self):
        """A sibling's healthy report may not answer for a vantage point that is on fire."""
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], vantage=SIBLING,
                          name='sibling.json')
        summary, delivered = self.round()
        self.assertEqual(summary['verdict'], 'indeterminate')
        self.assertEqual(delivered.events[0]['kind'], 'coverage')
        self.assertTrue(any(VANTAGE in line for line in summary['notes']), summary['notes'])


class BgpSeamTests(unittest.TestCase):
    """The culled feed: `upstream/route` arrives without it, and its absence is a note, not a crash."""

    CLUSTER = [observed(T1, VANTAGE, False, asn='AS64500'), observed(T2, VANTAGE, False,
                                                                     asn='AS64500')]

    def test_upstream_route_is_reached_with_no_bgp_feed_at_all(self):
        """Task 6's proof: dropping the feed cost corroboration, never the verdict.

        v0.1 reached the same conclusion the same way — the ASN rides the observation, and the feed
        only ever corroborated it — which is why dead code's cull removes a note-taker and not a decider.
        """
        verdict = pathcheck.classify(self.CLUSTER + [observed(T3, VANTAGE, True)],
                                     expected_targets=[T1, T2, T3])
        self.assertEqual(verdict.verdict, 'upstream/route')
        self.assertEqual(verdict.affected, (T1, T2))
        self.assertTrue(any('AS64500' in line for line in verdict.notes))

    def test_an_absent_feed_says_so_on_every_verdict_that_consulted_the_seam(self):
        verdict = pathcheck.classify(self.CLUSTER, expected_targets=[T1, T2])
        self.assertTrue(any(line.startswith('bgp feed absent') for line in verdict.notes), verdict.notes)
        self.assertTrue(any('degraded' in line for line in verdict.notes))

    def test_a_feed_that_raises_cannot_end_the_round_or_change_the_verdict(self):
        def broken(asn: str) -> list[str]:
            raise RuntimeError('the bgpalerter socket is gone')

        verdict = pathcheck.classify(self.CLUSTER, expected_targets=[T1, T2], bgp_feed=broken)
        self.assertEqual(verdict.verdict, 'upstream/route')
        self.assertTrue(any('bgp feed errored for AS64500' in line for line in verdict.notes),
                        verdict.notes)

    def test_a_working_feed_only_corroborates_and_never_overrules(self):
        corroborating = pathcheck.classify(self.CLUSTER, expected_targets=[T1, T2],
                                           bgp_feed=lambda asn: [f'{asn} withdrawn'])
        silent = pathcheck.classify(self.CLUSTER, expected_targets=[T1, T2],
                                    bgp_feed=lambda asn: [])
        self.assertEqual(corroborating.verdict, silent.verdict)
        self.assertTrue(any('corroborates' in line for line in corroborating.notes))
        self.assertTrue(any('no anomalies' in line for line in silent.notes))

    def test_the_feed_is_not_consulted_when_no_route_is_suspected(self):
        calls: list[str] = []
        pathcheck.classify([observed(T1, VANTAGE, True)], expected_targets=[T1],
                           bgp_feed=lambda asn: calls.append(asn) or [])
        self.assertEqual(calls, [])

    def test_the_bgp_module_was_culled_by_name_and_nothing_here_imports_it(self):
        """dead code named the feed; this is the assertion that keeps that honest rather than silent."""
        source = (ROOT / 'local_observe/platform/pathcheck.py').read_text(encoding='utf-8')
        self.assertIn('dead code', source)
        self.assertIn('bgpalerter', source)
        for token in ('import bgp', 'from .bgp', 'from local_observe.platform.bgp',
                      'bgp_feed=load', 'bgpalerter('):
            self.assertNotIn(token, source)
        self.assertFalse((ROOT / 'local_observe/platform/bgp.py').exists())
        self.assertFalse((ROOT / 'local_observe/bgp.py').exists())


class VerdictEventTests(Fixture):
    """What a verdict costs the platform: one channel, one condition, transitions only."""

    def both_up(self) -> None:
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)])
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], vantage=SIBLING,
                          name='sibling.json')

    def test_a_target_verdict_files_one_availability_event_the_platform_accepts(self):
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)], vantage=SIBLING,
                          name='sibling.json')
        summary, delivered = self.round()
        self.assertEqual(summary['verdict'], 'target')
        self.assertEqual(len(delivered.events), 1)
        finding = delivered.events[0]
        self.assertEqual(finding['kind'], 'availability')
        self.assertEqual(finding['status'], 'firing')
        self.assertEqual(finding['rule_id'], 'pathcheck.target')
        self.assertEqual(finding['condition'], 'pathcheck.target')
        self.assertEqual(finding['severity'], 'warning')
        self.assertEqual(finding['resource_id'], VANTAGE)
        self.assertEqual(finding['source'], SOURCE)
        self.assertEqual(delivered.receipts[0]['transition'], 'opened')
        validate_event(finding, NOW)

    def test_the_evidence_is_an_observed_snapshot_naming_the_observation_set(self):
        """`observed-snapshot` + `observation_id`, and never `gatus-result`: see the module docstring.

        The two names come from the closed lists in `state.validate_event` (query types at
        ``state.py:1318``, approved parameters at ``state.py:1328``); `gatus-result` would name one
        Gatus result while the verdict read every probe of every vantage, and `detections.event`
        attaches exactly one evidence reference.
        """
        self.both_up()
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        _, delivered = self.round()
        evidence = delivered.events[0]['evidence'][0]
        self.assertEqual(evidence['query_type'], 'observed-snapshot')
        self.assertNotEqual(evidence['query_type'], 'gatus-result')
        self.assertEqual(set(evidence['parameters']), {'observation_id', 'rule_id'})
        self.assertRegex(evidence['parameters']['observation_id'], r'[0-9a-f]{64}')
        self.assertEqual(evidence['window'], delivered.events[0]['window'])
        self.assertGreater(timestamp(evidence['expires_at']),
                           timestamp(delivered.events[0]['window']['end']))

    def test_the_observation_id_names_the_window_and_the_set_and_moves_when_either_does(self):
        first = [observed(API, VANTAGE, False), observed(ROUTER, VANTAGE, True)]
        second = [observed(API, VANTAGE, False), observed(ROUTER, VANTAGE, False)]
        base = pathcheck.observation_digest(first, window())
        self.assertEqual(base, pathcheck.observation_digest(list(reversed(first)), window()))
        self.assertNotEqual(base, pathcheck.observation_digest(second, window()))
        self.assertNotEqual(base, pathcheck.observation_digest(first, window(LATER)))

    def test_the_window_is_the_probe_window_aligned_and_bounded_by_the_seven_day_ceiling(self):
        self.both_up()
        summary, _ = self.round()
        self.assertEqual(summary['window'], {'start': utc_text(WATERMARK - INTERVAL),
                                             'end': utc_text(WATERMARK)})
        self.assertLessEqual(timestamp(summary['window']['end'])
                             - timestamp(summary['window']['start']), dt.timedelta(days=7))

    def test_an_unchanged_bad_verdict_files_nothing_because_it_is_already_open(self):
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        self.round()
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)], observed_at=LATER)
        summary, second = self.round(now=NOW + INTERVAL, deliverer=Deliverer(self.store,
                                                                           now=NOW + INTERVAL))
        self.assertEqual(second.events, [], 'an unchanged verdict paged a second time')
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual(summary['verdict'], 'target')

    def test_recovery_resolves_the_condition_it_opened_and_opens_nothing(self):
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        self.round()
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], observed_at=LATER)
        summary, delivered = self.round(now=NOW + INTERVAL, deliverer=Deliverer(self.store,
                                                                             now=NOW + INTERVAL))
        self.assertEqual([(item['status'], item['rule_id']) for item in delivered.events],
                         [('resolved', 'pathcheck.target')])
        self.assertEqual(delivered.events[0]['kind'], 'availability')
        self.assertIsNone(summary['open_finding'])
        self.assertEqual(delivered.receipts[0]['transition'], 'resolved')

    def test_an_ok_round_with_nothing_open_is_silence_and_not_a_resolved_event(self):
        self.both_up()
        summary, delivered = self.round()
        self.assertEqual(summary['verdict'], 'ok')
        self.assertEqual(delivered.events, [])
        self.assertIsNone(summary['open_finding'])

    def test_a_verdict_that_moves_closes_the_old_attribution_before_opening_the_new(self):
        """An operator holding `target` and `local` open at once is holding a contradiction."""
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)], vantage=SIBLING,
                          name='sibling.json')
        self.round()  # API dead from both vantages, ROUTER alive: target
        self.write_report([self.probe(API, False), self.probe(ROUTER, False)])
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], vantage=SIBLING,
                          observed_at=LATER, name='sibling.json')
        summary, delivered = self.round(now=NOW + INTERVAL, deliverer=Deliverer(self.store,
                                                                             now=NOW + INTERVAL))
        self.assertEqual(summary['verdict'], 'local')
        self.assertEqual([(item['status'], item['rule_id'], item['kind']) for item in delivered.events],
                         [('resolved', 'pathcheck.target', 'availability'),
                          ('firing', 'pathcheck.local', 'availability')])
        for receipt in delivered.receipts:
            self.assertIn(receipt['transition'], ('resolved', 'opened'))

    def test_an_indeterminate_verdict_files_coverage_and_never_a_fabricated_outage(self):
        """`availability` would page "something is down" on the strength of missing data."""
        summary, delivered = self.round()  # no reports at all
        self.assertEqual(summary['verdict'], 'indeterminate')
        finding = delivered.events[0]
        self.assertEqual(finding['kind'], 'coverage')
        self.assertNotEqual(finding['kind'], 'availability')
        self.assertEqual(finding['rule_id'], 'pathcheck.coverage')

    def test_coverage_closes_when_the_verdict_becomes_a_real_one_and_vice_versa(self):
        self.round()  # blind -> coverage firing
        self.write_report([self.probe(API, False), self.probe(ROUTER, False)], observed_at=LATER)
        summary, delivered = self.round(now=NOW + INTERVAL, deliverer=Deliverer(self.store,
                                                                             now=NOW + INTERVAL))
        self.assertEqual([(item['status'], item['rule_id']) for item in delivered.events],
                         [('resolved', 'pathcheck.coverage'), ('firing', 'pathcheck.target')])
        self.assertEqual(summary['open_finding'], {'kind': 'availability', 'rule_id': 'pathcheck.target'})

    def test_the_verdict_names_no_severity_beyond_the_factory_default(self):
        """This producer measures reachability, not size: `critical` would be an invented loudness."""
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        _, delivered = self.round()
        self.assertEqual(delivered.events[0]['severity'], 'warning')

    def test_five_verdicts_and_their_conditions_are_the_whole_channel(self):
        self.assertEqual(pathcheck.CONDITION_BY_VERDICT, {
            'target': ('availability', 'pathcheck.target'),
            'local': ('availability', 'pathcheck.local'),
            'upstream/route': ('availability', 'pathcheck.upstream-route'),
            'indeterminate': ('coverage', 'pathcheck.coverage')})
        self.assertNotIn('ok', pathcheck.CONDITION_BY_VERDICT)
        for kind, rule in pathcheck.CONDITION_BY_VERDICT.values():
            self.assertIn(kind, ('availability', 'coverage'))
            self.assertRegex(rule, r'[A-Za-z0-9_.:-]{1,128}')


class VantageIdentityTests(Fixture):
    """Task 5: the verdict has an identity to attribute, and refuses to invent one."""

    def test_a_vantage_point_that_is_not_declared_refuses_the_whole_round(self):
        config = self.config(vantage_resource_id=UNDECLARED)
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], vantage=UNDECLARED)
        with self.assertRaises(ValueError) as raised:
            self.round(config=config)
        self.assertIn('Vantage point is not declared', str(raised.exception))

    def test_the_refusal_happens_before_a_single_report_is_read(self):
        """No probe, no verdict, no event, no cursor write: identity is checked first, not last."""
        config = self.config(vantage_resource_id=UNDECLARED)
        before = sorted(path.name for path in self.cursor.parent.iterdir())
        with self.assertRaises(ValueError):
            self.round(config=config)
        self.assertEqual(sorted(path.name for path in self.cursor.parent.iterdir()), before)

    def test_a_report_from_an_undeclared_vantage_is_excluded_and_counted_not_believed(self):
        self.write_report([self.probe(API, False), self.probe(ROUTER, False)])
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], vantage=UNDECLARED,
                          name='ghost.json')
        summary, delivered = self.round()
        self.assertEqual(summary['excluded_undeclared_vantage'], [UNDECLARED])
        self.assertEqual(summary['verdict'], 'target', 'the ghost report was read after all')
        self.assertEqual([item['resource_id'] for item in delivered.events], [VANTAGE])

    def test_an_excluded_report_neither_widens_the_expected_set_nor_the_verdict(self):
        """Excluding a ghost is not a coverage gap: the expected set is who *this* process is."""
        config = self.config(targets=[API, ROUTER])
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)])
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], vantage=UNDECLARED,
                          name='ghost.json')
        summary, delivered = self.round(config=config)
        self.assertEqual(summary['excluded_undeclared_vantage'], [UNDECLARED])
        self.assertEqual(summary['verdict'], 'ok')
        self.assertEqual(delivered.events, [])

    def test_a_vantage_declared_in_the_shipped_example_is_accepted(self):
        """The example file is the contract an operator copies, so the producer must read it as-is."""
        index.build(read_document(SHIPPED_DECLARATION), self.root / 'shipped.db', 'example')
        config = pathcheck.load_config(self.write_json(
            {'vantage_resource_id': VANTAGE, 'targets': ['demo-api'], 'protocols': ['icmp'],
             'sources': {'reports_dir': str(self.reports)}, 'cursor': str(self.root / 'shipped.json')},
            'shipped-config.json'))
        self.write_report([self.probe('demo-api', True)])
        deliverer = Deliverer(Store(self.root / 'shipped-state.db'), now=NOW)
        summary = pathcheck.tick(self.root / 'shipped.db', config, config['cursor'], deliverer,
                                 now=NOW, source=SOURCE)
        self.assertEqual(summary['verdict'], 'ok')
        self.assertEqual(summary['observations'], 1)


class ConfigurationTests(Fixture):
    """The document, its refusals, and the off switch that must not touch a network."""

    def test_no_configuration_named_is_off_exit_zero_and_not_one_byte_written(self):
        before = sorted(path.name for path in self.root.iterdir())
        with mock.patch.dict('os.environ', {}, clear=True), \
                self.assertLogs('local_observe.platform.pathcheck', 'INFO') as captured:
            self.assertEqual(pathcheck.main(), 0)
        self.assertEqual(len(captured.output), 1)
        self.assertIn('off', captured.output[0])
        self.assertEqual(captured.records[0].variable, pathcheck.CONFIG_ENVIRONMENT)
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), before)

    def test_a_configuration_named_and_unreadable_refuses_startup_with_exit_one(self):
        environment = {pathcheck.CONFIG_ENVIRONMENT: str(self.root / 'absent.json')}
        with mock.patch.dict('os.environ', environment, clear=True), \
                self.assertLogs('local_observe.platform.pathcheck', 'INFO'):
            self.assertEqual(pathcheck.main(), 1)

    def test_the_worker_needs_its_identity_its_index_and_a_cursor_parent_it_did_not_create(self):
        """A producer that mkdirs its own state directory can create it in the wrong place and believe it."""
        config = self.document(cursor=str(self.root / 'nowhere' / 'pathcheck.json'))
        environment = {pathcheck.CONFIG_ENVIRONMENT: str(self.write_json(config, 'worker.json')),
                       pathcheck.SOURCE_ENVIRONMENT: SOURCE, 'LO_INDEX_PATH': str(self.index),
                       'LO_PLATFORM_URL': 'https://platform.invalid', 'LO_PRODUCER_TOKEN': 'token'}
        with mock.patch.dict('os.environ', environment, clear=True), \
                self.assertLogs('local_observe.platform.pathcheck', 'INFO'):
            self.assertEqual(pathcheck.main(), 1)

    def test_a_cursor_parent_that_does_not_exist_refuses_the_round_before_anything_is_delivered(self):
        config = self.config(cursor=str(self.root / 'nowhere' / 'pathcheck.json'))
        self.write_report([self.probe(API, False), self.probe(ROUTER, False)])
        deliverer = Deliverer(self.store, now=NOW)
        with self.assertRaises(ValueError) as raised:
            pathcheck.tick(self.index, config, config['cursor'], deliverer, now=NOW, source=SOURCE)
        self.assertIn('cursor parent', str(raised.exception))
        self.assertEqual(deliverer.events, [])

    def test_every_refusal_names_the_field_and_none_of_them_defaults_silently(self):
        cases = [
            (self.document(unknown_key=1), 'unknown keys'),
            (self.document(vantage_resource_id='probe-1'), 'canonical declared UUID'),
            (self.document(vantage_resource_id=VANTAGE.upper()), 'canonical declared UUID'),
            (self.document(targets=[]), 'targets'),
            (self.document(targets=['a/b']), 'bounded label'),
            (self.document(targets=['x' * 129]), 'bounded label'),
            (self.document(protocols=['http']), 'protocols'),
            (self.document(protocols=[]), 'protocols'),
            (self.document(interval_seconds=30), 'interval_seconds'),
            (self.document(interval_seconds=604_800), 'interval_seconds'),
            (self.document(interval_seconds='300'), 'interval_seconds'),
            (self.document(sources={}), 'sources'),
            (self.document(sources={'reports_dir': 'relative/path'}), 'absolute path'),
            (self.document(sources={'reports_dir': 5}), 'must name a path'),
            (self.document(cursor='state/pathcheck.json'), 'absolute path'),
            ({'vantage_resource_id': VANTAGE}, 'missing'),
            ('not json at all', 'is not JSON'),
            (self.document(**{'cursor': str(self.cursor), 'extra': 1}), 'unknown keys'),
        ]
        for document, fragment in cases:
            with self.subTest(fragment=fragment):
                path = self.write_json(document, 'refusal.json')
                with self.assertRaises(ValueError) as raised:
                    pathcheck.load_config(path)
                self.assertIn(fragment, str(raised.exception))

    def test_the_interval_is_the_only_thing_defaulted_and_the_cursor_is_required(self):
        config = pathcheck.load_config(self.write_json(self.document(interval_seconds=None), 'd.json'))
        self.assertEqual(config['interval_seconds'], pathcheck.DEFAULT_TICK_SECONDS)
        self.assertGreaterEqual(config['interval_seconds'], pathcheck.TICK_LIMITS[0])
        self.assertLessEqual(config['interval_seconds'], pathcheck.TICK_LIMITS[1])

    def test_targets_and_protocols_are_normalised_sorted_and_deduplicated(self):
        config = pathcheck.load_config(self.write_json(
            self.document(targets=['b', 'a', 'a'], protocols=['tcp', 'icmp', 'icmp']), 'n.json'))
        self.assertEqual(config['targets'], ['a', 'b'])
        self.assertEqual(config['protocols'], ['icmp', 'tcp'])

    def test_a_cursor_from_another_configuration_is_refused_rather_than_re_baselined(self):
        """A stored route signature from another vantage would manufacture a path change out of a typo."""
        config = self.config()
        pathcheck.save_cursor(config['cursor'], {'schema_version': pathcheck.CURSOR_VERSION,
                                                'binding': 'x' * 64, 'open': None, 'routes': {}})
        with self.assertRaises(ValueError) as raised:
            pathcheck.load_cursor(config['cursor'], config)
        self.assertIn('different vantage point', str(raised.exception))

    def test_a_cursor_document_that_is_half_one_is_refused_field_by_field(self):
        config = self.config()
        binding = pathcheck.cursor_binding(config)
        good = {'schema_version': pathcheck.CURSOR_VERSION, 'binding': binding}
        cases = [
            ('not json', '{'),
            ('unknown keys', {**good, 'routes': {}, 'open': None, 'extra': 1}),
            ('a foreign schema version', {**good, 'schema_version': 2, 'open': None, 'routes': {}}),
            ('an open finding with no kind', {**good, 'open': {'rule_id': 'pathcheck.target'},
                                              'routes': {}}),
            ('an open finding of a kind never filed',
             {**good, 'open': {'kind': 'drift', 'rule_id': 'pathcheck.target'}, 'routes': {}}),
            ('an open finding whose rule is not a label',
             {**good, 'open': {'kind': 'availability', 'rule_id': 'a/b'}, 'routes': {}}),
            ('a route record with no baseline',
             {**good, 'open': None, 'routes': {'k': {'signature': 'x' * 64, 'open': 'no'}}}),
            ('a route signature that is not a digest',
             {**good, 'open': None, 'routes': {'k': {'baseline': 'short', 'signature': 'x' * 64,
                                                     'open': 'no'}}}),
            ('a route open flag that is neither yes nor no',
             {**good, 'open': None, 'routes': {'k': {'baseline': 'x' * 64, 'signature': 'y' * 64,
                                                     'open': 'maybe'}}}),
        ]
        for label, document in cases:
            with self.subTest(case=label):
                path = self.root / 'cursor-refusal.json'
                path.write_text(document if isinstance(document, str) else json.dumps(document),
                                encoding='utf-8')
                with self.assertRaises(ValueError):
                    pathcheck.load_cursor(path, config)

    def test_a_missing_cursor_is_an_empty_one_for_this_binding_and_not_an_error(self):
        config = self.config()
        cursor = pathcheck.load_cursor(self.cursor, config)
        self.assertEqual(cursor['open'], None)
        self.assertEqual(cursor['routes'], {})
        self.assertEqual(cursor['binding'], pathcheck.cursor_binding(config))

    def test_the_binding_ignores_the_tick_rate_and_moves_with_what_is_watched(self):
        config = self.config()
        self.assertEqual(pathcheck.cursor_binding(config),
                         pathcheck.cursor_binding({**config, 'interval_seconds': 900}))
        for field, value in (('targets', ['other']), ('protocols', ['udp']),
                             ('vantage_resource_id', SIBLING)):
            with self.subTest(field=field):
                self.assertNotEqual(pathcheck.cursor_binding(config),
                                    pathcheck.cursor_binding({**config, field: value}))


class ReportHygieneTests(Fixture):
    """The reports tree is written by somebody else, so every bound here is a refusal with a count."""

    def protocols(self, config: dict | None = None):
        return (config or self.config())['protocols']

    def stale_report_is_dropped_and_counted_rather_than_read_as_health(self):
        old = WATERMARK - dt.timedelta(seconds=pathcheck.MAX_OBSERVATION_AGE_SECONDS + 60)
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)], observed_at=old)
        summary, delivered = self.round()
        self.assertEqual(summary['stale_reports'], 1)
        self.assertEqual(summary['observations'], 0)
        self.assertEqual(summary['verdict'], 'indeterminate')
        self.assertEqual(delivered.events[0]['kind'], 'coverage')

    def test_a_report_from_the_future_is_refused_not_clamped(self):
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)],
                          observed_at=WATERMARK + dt.timedelta(seconds=3600))
        summary, _ = self.round()
        self.assertEqual(summary['unparseable_reports'], 1)
        self.assertTrue(summary['blind'])

    def test_one_unparseable_vantage_does_not_silence_the_others(self):
        self.write_raw_report('{"probes": [', 'broken.json')
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)])
        summary, _ = self.round()
        self.assertEqual(summary['unparseable_reports'], 1)
        self.assertEqual(summary['verdict'], 'ok')

    def test_a_report_beyond_the_byte_ceiling_is_refused_rather_than_truncated(self):
        padding = '{"probes": [{"target": "' + API + '", "ok": true}, ' + ' ' * pathcheck.MAX_REPORT_BYTES
        self.write_raw_report(padding + ']}', 'huge.json')
        summary, _ = self.round()
        self.assertEqual(summary['oversize_reports'], 1)

    def test_a_symlinked_report_is_refused_rather_than_followed_out_of_the_tree(self):
        """The refusal predicate is patched, not a real symlink: rule 11 and the anomaly_cursor precedent.

        A mocked predicate runs on every host, which is the answer `docs/testing-standards.md` records
        for this case — a skipped test on the developer's own machine proves nothing about the mount
        the operator is about to hit.
        """
        outside = self.root / 'outside.json'
        outside.write_text(json.dumps({'schema_version': 1, 'vantage_resource_id': VANTAGE,
                                       'observed_at': utc_text(WATERMARK),
                                       'probes': [self.probe(API, True), self.probe(ROUTER, True)]}),
                           encoding='utf-8')
        (self.reports / 'link.json').write_text('{}', encoding='utf-8')
        original = Path.is_symlink
        with mock.patch.object(Path, 'is_symlink', lambda self: original(self) or self.name == 'link.json'):
            summary, _ = self.round()
        self.assertEqual(summary['unparseable_reports'], 1)
        self.assertTrue(summary['blind'])

    def test_only_the_first_reports_are_read_and_the_rest_are_counted_not_ignored(self):
        for index_number in range(pathcheck.MAX_REPORTS + 2):
            self.write_report([self.probe(API, True), self.probe(ROUTER, True)],
                              name=f'report-{index_number:02d}.json')
        summary, _ = self.round()
        self.assertEqual(summary['excess_reports'], 2)
        self.assertEqual(summary['observations'], pathcheck.MAX_REPORTS * 2)

    def test_a_probe_on_a_protocol_nobody_asked_for_is_excluded_and_counted(self):
        self.write_report([self.probe(API, True, protocol='udp'), self.probe(ROUTER, True)])
        summary, _ = self.round()
        self.assertEqual(summary['out_of_scope_probes'], 1)
        self.assertEqual(summary['observations'], 1)

    def test_a_report_whose_probes_are_all_out_of_scope_is_refused_as_a_mismatch(self):
        """An empty report from a live vantage would read as a coverage gap; the truth is a mismatch."""
        self.write_report([self.probe(API, True, protocol='udp'),
                           self.probe(ROUTER, True, protocol='udp')])
        summary, _ = self.round()
        self.assertEqual(summary['unparseable_reports'], 1)
        self.assertTrue(summary['blind'])

    def test_a_report_missing_a_required_field_or_naming_an_extra_one_is_refused(self):
        cases = [
            {'schema_version': 2, 'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [self.probe(API, True)]},
            {'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [self.probe(API, True)]},
            {'schema_version': 1, 'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [self.probe(API, True)], 'operator_note': 'nothing'},
            {'schema_version': 1, 'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [{'target': API}]},
            {'schema_version': 1, 'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [{'target': API, 'ok': 'yes'}]},
            {'schema_version': 1, 'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [{'target': API, 'ok': True, 'asn': '64500'}]},
            {'schema_version': 1, 'vantage_resource_id': VANTAGE, 'observed_at': utc_text(WATERMARK),
             'probes': [], 'traces': []},
        ]
        for document in cases:
            with self.subTest(keys=sorted(document)):
                self.write_raw_report(document, 'bad.json')
                summary, _ = self.round()
                self.assertEqual(summary['unparseable_reports'], 1, document)

    def test_an_empty_reports_directory_is_blind_and_not_a_clean_network(self):
        summary, delivered = self.round()
        self.assertTrue(summary['blind'])
        self.assertEqual(summary['blind_reason'], 'reports_directory_empty')
        self.assertEqual(delivered.events[0]['kind'], 'coverage')


class LatencySummaryTests(Fixture):
    """The ping parser inside the producer: a round says *how badly*, not only *whether*.

    `pathcheck_parsers.analyze_ping` is not a library the operator may call; the producer calls it on
    every probe record that carries an RTT series and puts the result in the round summary. These are
    the tests that make that true rather than available, and the reason the verdict still reads only
    the boolean: a series can be 100 % loss on replies and the probe still says `ok: true`, and which
    of the two opens a condition is a decision, not an arithmetic.
    """

    def test_a_series_with_a_loss_reports_its_numbers_beside_the_verdict(self):
        self.write_report([self.probe(API, True, rtts_ms=[10.0, None, 30.0]),
                           self.probe(ROUTER, True)])
        summary, _ = self.round()
        self.assertEqual(summary['latency_rows'], 1)
        row = summary['latency'][0]
        self.assertEqual(row['target'], API)
        self.assertEqual((row['sent'], row['received']), (3, 2))
        self.assertEqual(row['latency_avg_ms'], 20.0)
        self.assertEqual(row['jitter_ms'], 20.0)
        self.assertAlmostEqual(row['loss_pct'], 33.333, places=3)
        self.assertEqual(row['vantage_resource_id'], VANTAGE)

    def test_an_all_lost_series_reports_unmeasured_and_never_zero(self):
        self.write_report([self.probe(API, False, rtts_ms=[None, None]),
                           self.probe(ROUTER, True)])
        summary, delivered = self.round()
        row = summary['latency'][0]
        self.assertIsNone(row['latency_avg_ms'])
        self.assertIsNone(row['jitter_ms'])
        self.assertEqual(row['loss_pct'], 100.0)
        self.assertIn('unmeasured', row['note'])
        finding = delivered.events[0]
        self.assertEqual((finding['kind'], finding['status']), ('availability', 'firing'))
        self.assertNotIn('loss_pct', json.dumps(finding),
                         'a measured loss reached the event, not only the summary')

    def test_a_probe_without_a_series_earns_no_row_and_no_invented_one(self):
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)])
        summary, _ = self.round()
        self.assertEqual(summary['latency'], [])
        self.assertEqual(summary['latency_rows'], 0)
        self.assertFalse(summary['latency_truncated'])

    def test_a_malformed_series_refuses_its_report_rather_than_losing_the_measurement(self):
        self.write_report([self.probe(API, True, rtts_ms=['fast']), self.probe(ROUTER, True)])
        summary, _ = self.round()
        self.assertEqual(summary['unparseable_reports'], 1)
        self.assertTrue(summary['blind'])

    def test_more_series_than_the_ceiling_are_counted_and_say_so(self):
        targets = [f'target-{number}' for number in range(pathcheck.MAX_TARGETS)]
        config = self.config(targets=targets)
        for vantage in (VANTAGE, SIBLING, THIRD):
            self.write_report([self.probe(target, True, rtts_ms=[1.0, 2.0]) for target in targets],
                              vantage=vantage, name=f'{vantage[:8]}.json',
                              observed_at=LATER - dt.timedelta(seconds=1))
        summary, _ = self.round(now=LATER + dt.timedelta(seconds=5), config=config)
        self.assertEqual(summary['latency_rows'], 3 * pathcheck.MAX_TARGETS)
        self.assertEqual(len(summary['latency']), pathcheck.MAX_LATENCY_ROWS)
        self.assertTrue(summary['latency_truncated'])
        self.assertEqual(summary['verdict'], 'ok')


class CommandLineTests(Fixture):
    """`lo-platform pathcheck` is the same round with a database on the other side of the seam."""

    def run_cli(self, *argv: str) -> tuple[int, dict, str]:
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.root / 'cli-state.db'), *argv]
        printed, logged = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                code = cli.main()
        finally:
            sys.argv = original
        return code, json.loads(printed.getvalue()), logged.getvalue()

    def pathcheck_round(self, *extra: str, now: dt.datetime = NOW,
                        name: str = 'cli-pathcheck.json') -> tuple[int, dict, str]:
        config = self.write_json(self.document(), name)
        return self.run_cli('pathcheck', '--config', str(config), '--index', str(self.index),
                            '--source', SOURCE, '--now', utc_text(now), *extra)

    def test_the_subcommand_files_the_verdict_into_the_database_in_front_of_the_operator(self):
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        code, result, _ = self.pathcheck_round()
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'delivered')
        self.assertEqual(result['verdict'], 'target')
        self.assertEqual(result['intake'][0]['transition'], 'opened')
        stored = Store(self.root / 'cli-state.db').records('events')[0]
        self.assertEqual(json.loads(stored['payload'])['rule_id'], 'pathcheck.target')

    def test_a_second_round_with_the_same_verdict_files_nothing_new(self):
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)])
        self.pathcheck_round()
        self.write_report([self.probe(API, False), self.probe(ROUTER, True)], observed_at=LATER)
        code, result, _ = self.pathcheck_round(now=NOW + INTERVAL)
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'idle')
        self.assertEqual(result['intake'], [])

    def test_no_config_named_is_off_and_opens_nothing(self):
        code, result, _ = self.run_cli('pathcheck')
        self.assertEqual(code, 0)
        self.assertEqual(result, {'status': 'off', 'configured': False})

    def test_config_without_an_identity_refuses_rather_than_guessing_a_source(self):
        """The event's `source` is what intake compares to the token's identity; nothing defaults it."""
        code, result, logged = self.run_cli('pathcheck', '--config',
                                            str(self.write_json(self.document())), '--index',
                                            str(self.index))
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'error')
        # This CLI's contract is one JSON line plus a log record naming the error *class*, never the
        # sentence (an exception message can echo input, so `api.py` and this CLI both refuse it).
        # The requirement itself is pinned by the happy path passing --source and by the store row.
        self.assertNotIn('Traceback', json.dumps(result))
        self.assertEqual(Store(self.root / 'cli-state.db').records('events'), [],
                         'a refusal still wrote an event into the database')

    def test_an_undeclared_vantage_reports_the_json_error_line_and_no_traceback(self):
        config = self.write_json(self.document(vantage_resource_id=UNDECLARED), 'bad-vantage.json')
        sys.argv = ['lo-platform', '--database', str(self.root / 'cli-state.db'), 'pathcheck',
                    '--config', str(config), '--index', str(self.index), '--source', SOURCE]
        printed, logged = io.StringIO(), io.StringIO()
        original = list(sys.argv)
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                code = cli.main()
        finally:
            sys.argv = original
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(printed.getvalue())['status'], 'error')
        self.assertNotIn('Traceback', printed.getvalue())

    def test_a_cursor_parent_that_is_absent_refuses_before_the_store_is_written_to(self):
        config = self.write_json(self.document(cursor=str(self.root / 'nope' / 'c.json')), 'c.json')
        code, result, _ = self.run_cli('pathcheck', '--config', str(config), '--index',
                                       str(self.index), '--source', SOURCE)
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'error')

    def expect_argparse_error(self, *argv: str) -> tuple[int, str]:
        """Run one knowingly-incomplete command line; return argparse's code and its complaint."""
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.root / 'cli-state.db'), *argv]
        logged = io.StringIO()
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(logged):
                with self.assertRaises(SystemExit) as raised:
                    cli.main()
        finally:
            sys.argv = original
        return raised.exception.code, logged.getvalue()


class DeclarationExampleTests(unittest.TestCase):
    """The shipped example names a vantage point, because an operator cannot declare what they cannot see."""

    def test_declared_yaml_shows_a_commented_probe_vantage(self):
        text = SHIPPED_DECLARATION.read_text(encoding='utf-8')
        commented = [line for line in text.splitlines() if line.lstrip().startswith('#')]
        body = '\n'.join(line for line in text.splitlines() if not line.lstrip().startswith('#'))
        self.assertIn('pathcheck', body + '\n'.join(commented))
        self.assertTrue(any('vantage' in line for line in commented),
                        'no comment explains that a probe is a vantage point')
        self.assertIn('probe-2', '\n'.join(commented))
        self.assertNotIn('probe-2:', body, 'the example vantage must stay commented: it is an example')

    def test_the_example_uses_q5_placeholders_and_no_estate_identifier(self):
        text = SHIPPED_DECLARATION.read_text(encoding='utf-8')
        for banned in ('private-address-marker', 'example-site', 'storage-host', 'worker-host', 'admin-host', 'openbao', 'example-operator'):
            self.assertNotIn(banned, text)
        self.assertIn('example.test', text)
        self.assertIn('10.11.0.', text)


class SummaryHygieneTests(Fixture):
    """A hop address is operator topology: it reaches the cursor as a digest and goes no further."""

    def test_neither_the_summary_nor_a_filed_event_nor_the_cursor_holds_a_hop_address(self):
        address = '198.51.100.7'
        self.write_report([self.probe(API, True), self.probe(ROUTER, True)],
                          traces=[{'target': API, 'protocol': 'icmp',
                                   'hops': [{'ttl': 1, 'address': address, 'rtts_ms': [1.0]}]}])
        summary, delivered = self.round()
        # The cursor is written with the same json.dump the summary would use; read it back as text.
        cursor_text = self.cursor.read_text(encoding='utf-8')
        for label, text in (('summary', json.dumps(summary, sort_keys=True)),
                            ('events', json.dumps(delivered.events, sort_keys=True)),
                            ('cursor', cursor_text)):
            with self.subTest(part=label):
                self.assertNotIn(address, text)
        self.assertEqual(len(summary['route_findings']), 0, 'a first path is baselined, not reported')
        self.assertGreater(len(cursor_text), 0)

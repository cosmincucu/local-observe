"""The injected probe parsers (path monitoring): what they report, what they refuse, and what they never run.

Every expectation here is about a *series somebody handed in*. `mtr`, `fping` and `traceroute` are
adopted external engines that this product never spawns (port table §6, `netpath` row), so there is
nothing to mock and nothing to skip: the input is a list, and the tests below are the reason the list
is enough to compute loss, jitter, availability and a path signature from.

The refusals are the other half of the file. These parsers sit on the far side of a JSON report some
operator's job writes, so a malformed series must refuse loudly rather than return a plausible number:
`None` here means *unmeasured* and always arrives with a reason in `note`, never a zero that a
threshold rule would later read as a fast network.

The last class, :class:`NoProcessTests`, is the grep the brief asks for, written as a test so it cannot
rot: the engine names may appear in prose and nowhere a token of executable code could read them.
"""
from pathlib import Path
import io
import re
import tokenize
import unittest

from local_observe.platform import pathcheck_parsers as parsers

ROOT = Path(__file__).resolve().parents[1] / 'local_observe' / 'platform'
VANTAGE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
TARGET = 'demo-api'


def hops(*entries: tuple) -> list[dict]:
    """Build a hop set from `(ttl, address, rtts)` triples, the shape a probe runner writes."""
    return [{'ttl': ttl, 'address': address, 'rtts_ms': list(rtts)} for ttl, address, rtts in entries]


class PingTests(unittest.TestCase):
    """Latency, jitter, loss and availability out of an injected RTT series."""

    def report(self, series, **overrides) -> parsers.PingReport:
        arguments: dict = {'vantage_resource_id': VANTAGE, 'target': TARGET}
        arguments.update(overrides)
        return parsers.analyze_ping(series, **arguments)

    def test_a_clean_series_reports_min_avg_max_and_jitter(self):
        result = self.report([10.0, 20.0, 30.0])
        self.assertEqual((result.sent, result.received), (3, 3))
        self.assertEqual((result.latency_min_ms, result.latency_avg_ms, result.latency_max_ms),
                         (10.0, 20.0, 30.0))
        self.assertEqual(result.jitter_ms, 10.0)
        self.assertEqual((result.loss_pct, result.availability_pct), (0.0, 100.0))
        self.assertEqual(result.note, '')
        self.assertEqual((result.vantage_resource_id, result.target, result.protocol),
                         (VANTAGE, TARGET, 'icmp'))

    def test_jitter_skips_losses_instead_of_reading_a_gap_as_zero(self):
        """v0.1's definition, kept: consecutive *replied* RTTs, so a lost probe is not a queueing event."""
        result = self.report([10.0, None, 20.0])
        self.assertEqual(result.jitter_ms, 10.0)
        self.assertEqual(result.received, 2)
        self.assertAlmostEqual(result.loss_pct, 100.0 / 3)
        self.assertAlmostEqual(result.availability_pct, 200.0 / 3)

    def test_one_reply_reports_latency_but_refuses_to_invent_a_jitter(self):
        result = self.report([None, 12.0, None])
        self.assertEqual(result.latency_avg_ms, 12.0)
        self.assertIsNone(result.jitter_ms)
        self.assertIn('jitter', result.note)
        self.assertNotIn('latency', result.note, 'the note claims latency is unmeasured when it is not')

    def test_an_all_lost_series_is_unmeasured_with_a_reason_and_never_zero(self):
        result = self.report([None, None, None])
        for field in ('latency_min_ms', 'latency_avg_ms', 'latency_max_ms', 'jitter_ms'):
            self.assertIsNone(getattr(result, field), f'{field} was fabricated out of an all-lost series')
        self.assertEqual(result.received, 0)
        self.assertEqual((result.loss_pct, result.availability_pct), (100.0, 0.0))
        self.assertIn('unmeasured', result.note)

    def test_the_three_protocols_produce_the_same_shape_so_runs_are_comparable(self):
        reports = [vars(self.report([1.0, 2.0], protocol=name)) for name in parsers.PROTOCOLS]
        self.assertEqual({tuple(sorted(item)) for item in reports}, {tuple(sorted(reports[0]))})
        self.assertEqual([item['protocol'] for item in reports], list(parsers.PROTOCOLS))
        self.assertEqual({item['jitter_ms'] for item in reports}, {1.0})
        self.assertEqual(parsers.PROTOCOLS, ('icmp', 'tcp', 'udp'))

    def test_every_refusal_names_the_field_and_none_of_them_is_a_quiet_default(self):
        cases = [
            ([], '1-256 samples'),
            ([-0.5], 'outside 0-'),
            ([1e309], 'outside'),
            ([float('nan')], 'outside'),
            ([float('inf')], 'outside'),
            ([True], 'number of milliseconds'),
            (['12'], 'number of milliseconds'),
            ('012', 'list'),
            ([1.0] * (parsers.MAX_SERIES + 1), 'samples'),
        ]
        for series, fragment in cases:
            with self.subTest(series=str(series)[:24]):
                with self.assertRaises(parsers.PathParseError) as raised:
                    self.report(series)
                self.assertIn(fragment, str(raised.exception))

    def test_a_vantage_point_with_no_declared_identity_has_no_ping_report(self):
        for value in ('probe-1', VANTAGE.upper(), '', None, VANTAGE.replace('-', ''), 7):
            with self.subTest(value=str(value)):
                with self.assertRaises(parsers.PathParseError):
                    self.report([1.0], vantage_resource_id=value)

    def test_a_target_is_a_bounded_label_and_not_a_path_or_a_log_line(self):
        for value in ('a/b', 'a b', '../etc/passwd', '', 'x' * 129, 'a\nb', None, 3):
            with self.subTest(value=str(value)[:20]):
                with self.assertRaises(parsers.PathParseError):
                    self.report([1.0], target=value)

    def require(self, value):
        return parsers.require_protocol(value)

    def test_an_unadmitted_protocol_refuses_rather_than_defaulting_to_icmp(self):
        for value in ('http', 'ICMP', '', None):
            with self.subTest(value=str(value)):
                with self.assertRaises(parsers.PathParseError):
                    self.require(value)
        self.assertEqual(self.require('udp'), 'udp')


class TracerouteTests(unittest.TestCase):
    """Hop sets in, per-hop series and a path signature out."""

    def parse(self, records, **overrides) -> parsers.TraceReport:
        arguments: dict = {'vantage_resource_id': VANTAGE, 'target': TARGET}
        arguments.update(overrides)
        return parsers.parse_traceroute(records, **arguments)

    def test_hops_are_ordered_by_ttl_and_not_by_the_order_they_arrived_in(self):
        result = self.parse(hops((3, '203.0.113.9', [30.0]), (1, '10.11.0.1', [1.0]),
                                 (2, None, [None])))
        self.assertEqual([hop.ttl for hop in result.hops], [1, 2, 3])
        self.assertEqual(result.path, ('10.11.0.1', parsers.UNRESPONSIVE_HOP, '203.0.113.9'))
        self.assertEqual(result.hop_count, 3)

    def test_a_hop_that_never_replied_is_recorded_and_its_latency_stays_unmeasured(self):
        quiet = self.parse(hops((1, None, [None, None]))).hops[0]
        self.assertEqual(quiet.address, parsers.UNRESPONSIVE_HOP)
        self.assertEqual((quiet.sent, quiet.received, quiet.loss_pct), (2, 0, 100.0))
        for field in ('rtt_min_ms', 'rtt_avg_ms', 'rtt_max_ms'):
            self.assertIsNone(getattr(quiet, field))

    def test_an_unresponsive_hop_moving_into_the_path_is_a_change_and_not_a_quiet_router(self):
        """The signature's whole purpose: `*` participates, so flapping silence is visible."""
        before = self.parse(hops((1, '10.11.0.1', [1.0]), (2, '10.11.0.2', [2.0])))
        after = self.parse(hops((1, '10.11.0.1', [1.0]), (2, None, [None])))
        self.assertEqual(after.path[1], parsers.UNRESPONSIVE_HOP)
        self.assertNotEqual(before.path_signature, after.path_signature)
        self.assertEqual(after.path_signature, parsers.path_signature(after.path))

    def test_the_signature_is_a_stable_digest_of_order_including_the_unresponsive_mark(self):
        path = ('10.11.0.1', parsers.UNRESPONSIVE_HOP, '203.0.113.9')
        self.assertEqual(parsers.path_signature(path), parsers.path_signature(list(path)))
        self.assertRegex(parsers.path_signature(path), r'[0-9a-f]{64}\Z')
        self.assertNotEqual(parsers.path_signature(path),
                            parsers.path_signature(tuple(reversed(path))))

    def test_a_malformed_run_refuses_rather_than_choosing_one_of_two_hops_at_the_same_ttl(self):
        cases = [
            ([], '1-64'),
            (hops((0, '10.11.0.1', [1.0])), 'ttl'),
            (hops((1, '10.11.0.1', [1.0]), (1, '10.11.0.2', [2.0])), 'duplicate hop ttl 1'),
            (hops((True, '10.11.0.1', [1.0])), 'ttl'),
            ([{'ttl': 1, 'rtts_ms': [1.0], 'unexpected': 1}], 'ttl, rtts_ms'),
            ([{'ttl': 1}], 'ttl, rtts_ms'),
            (hops((1, 'not an address!', [1.0])), 'address'),
            (hops((1, 'a' * 65, [1.0])), 'address'),
            (hops((1, '10.11.0.1', [])), '1-256'),
            (hops((1, '10.11.0.1', [None, 'x'])), 'number of milliseconds'),
            (hops(*((index + 1, '10.11.0.1', [1.0]) for index in range(parsers.MAX_HOPS + 1))), '1-64'),
        ]
        for records, fragment in cases:
            with self.subTest(fragment=fragment, count=len(records)):
                with self.assertRaises(parsers.PathParseError) as raised:
                    self.parse(records)
                self.assertIn(fragment, str(raised.exception))

    def test_a_signature_argument_that_is_not_a_path_refuses(self):
        for value in ('10.11.0.1', 5, ['a b'], ['x' * 65], []):
            with self.subTest(value=str(value)[:16]):
                with self.assertRaises(parsers.PathParseError):
                    parsers.path_signature(value)

    def test_two_vantage_points_never_share_a_report_identity(self):
        first = self.parse(hops((1, '10.11.0.1', [1.0])), vantage_resource_id=VANTAGE)
        second = self.parse(hops((1, '10.11.0.1', [1.0])), vantage_resource_id=OTHER)
        self.assertEqual(first.path, second.path)
        self.assertNotEqual(first.vantage_resource_id, second.vantage_resource_id)


class NoProcessTests(unittest.TestCase):
    """The grep this card must report, pinned: no engine is ever a child of this process."""

    ENGINES = re.compile(r'\b(subprocess|Popen|mtr|fping)\b')
    FORBIDDEN_CALLS = ('.system(', '.popen(', '.exec', '.spawn', '.fork(', 'os.posix_spawn')

    def prose_spans(self, source: str) -> list[tuple[int, int]]:
        """Return the byte ranges that are module docstrings, other string literals or comments."""
        spans: list[tuple[int, int]] = []
        handle = io.StringIO(source)
        for token in tokenize.generate_tokens(handle.readline):
            if token.type in (tokenize.STRING, tokenize.COMMENT):
                spans.append((token.start[0], token.end[0]))
        return spans

    def test_engine_names_appear_only_in_prose(self):
        for name in ('pathcheck.py', 'pathcheck_parsers.py'):
            path = ROOT / name
            source = path.read_text(encoding='utf-8')
            lines = source.splitlines()
            prose = {number for start, end in self.prose_spans(source)
                     for number in range(start, end + 1)}
            for match in self.ENGINES.finditer(source):
                offset = match.start()
                line = source.count('\n', 0, offset) + 1
                with self.subTest(name=name, word=match.group(1), line=line):
                    self.assertIn(line, prose, f'{match.group(1)} appears in code at {name}:{line}')
                    self.assertIn(match.group(1), lines[line - 1])

    def test_no_process_or_shell_entry_point_is_reachable_from_these_modules(self):
        for name in ('pathcheck.py', 'pathcheck_parsers.py'):
            source = (ROOT / name).read_text(encoding='utf-8')
            code = '\n'.join(line for index, line in enumerate(source.splitlines(), 1)
                             if not line.lstrip().startswith('#'))
            for token in ('import subprocess', 'import os as _os', 'Popen('):
                self.assertNotIn(token, code, f'{name} mentions {token}')
            for call in self.FORBIDDEN_CALLS:
                self.assertNotIn(call, code, f'{name} can reach {call}')

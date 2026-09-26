"""The CIDR sweep source: what it may be pointed at, and what a sweep is allowed to say."""
import copy
import datetime as dt
import ipaddress
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from local_observe.inventory import discovery, sweep_provider
from local_observe.inventory.sweep_provider import SweepProvider
from local_observe.inventory.validation import InvalidInventory, digest, observed, timestamp, utc_text

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
ALLOW = ['10.11.0.0/24']
# Not sweep_provider.CIDR_SHAPE: that one is anchored to a whole line, which is what a config
# scanner needs and the opposite of what a search for a leaked range needs.
LOOSE_CIDR = re.compile(r'\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}')
Q5 = ipaddress.ip_network('10.11.0.0/16')


class RecordingProber:
    """A prober with a record: it proves both what answered and what was never asked."""

    def __init__(self, responsive=(), named=None, raises=()):
        self.responsive = set(responsive)
        self.named = named or {}
        self.raises = set(raises)
        self.seen = []

    def __call__(self, address):
        self.seen.append(address)
        if address in self.raises:
            raise OSError('probe failed for ' + address)
        return address in self.responsive

    def system(self, address):
        """Stand in for an SNMP-ish read: the caller decides which keys mean anything."""
        return self.named.get(address)


def build(cidrs=('10.11.0.0/29',), *, prober, allowlist=ALLOW, **kwargs):
    """Construct a sweep provider with the fixture defaults every case below overrides as needed."""
    return SweepProvider(source=kwargs.pop('source', 'sweep-demo'), cidrs=list(cidrs),
                         sweep_allowlist=list(allowlist), prober=prober, now=kwargs.pop('now', NOW), **kwargs)


class SweepConfigurationTests(unittest.TestCase):
    """A sweep plan is refused before one address is probed, and the refusal costs nothing."""

    def setUp(self):
        self.prober = RecordingProber()

    def refused(self, *, cidrs=('10.11.0.0/29',), allowlist=ALLOW, **kwargs):
        with self.assertRaises(InvalidInventory) as caught:
            build(cidrs=cidrs, prober=self.prober, allowlist=allowlist, **kwargs)
        self.assertEqual(self.prober.seen, [], 'a refused plan must not have probed anything')
        return str(caught.exception)

    def test_routable_range_refused_as_outside_rfc1918(self):
        self.assertIn('RFC 1918', self.refused(cidrs=['8.8.8.0/29']))

    def test_documentation_range_refused_even_though_it_is_not_routable(self):
        # TEST-NET looks safe and is not: synthetic naming reserves RFC 1918 for anything a reader may copy.
        self.assertIn('RFC 1918', self.refused(cidrs=['192.0.2.0/29']))

    def test_loopback_and_link_local_refused(self):
        for cidrs in (['127.0.0.0/29'], ['169.254.1.0/29']):
            with self.subTest(cidrs=cidrs):
                self.assertIn('RFC 1918', self.refused(cidrs=cidrs))

    def test_range_outside_the_declared_allowlist_refused(self):
        self.assertIn('allowlist', self.refused(cidrs=['10.30.0.0/29'], allowlist=['10.11.0.0/24']))

    def test_allowlist_wider_than_rfc1918_refused(self):
        # Otherwise `0.0.0.0/0` would be an allowlist that allows the internet.
        self.assertIn('RFC 1918', self.refused(allowlist=['0.0.0.0/0']))

    def test_empty_allowlist_refused_rather_than_defaulted(self):
        self.assertIn('allowlist', self.refused(allowlist=[]))

    def test_bare_address_refused_because_it_is_not_a_range(self):
        self.assertIn('CIDR notation', self.refused(cidrs=['10.11.0.7']))

    def test_host_bits_set_refused_rather_than_silently_normalized(self):
        self.assertIn('host bits', self.refused(cidrs=['10.11.0.5/29']))

    def test_ipv6_refused_because_unique_local_is_not_rfc1918(self):
        self.assertIn('CIDR notation', self.refused(cidrs=['fd00::/120']))

    def test_plan_over_the_probe_bound_refused(self):
        # A /16 inside a legal allowlist is 65,534 probes; the bound bites the plan, not one range.
        self.assertIn('bound', self.refused(cidrs=['10.11.0.0/16'], allowlist=['10.11.0.0/16']))

    def test_an_impossibly_large_plan_is_bounded_before_it_is_enumerated(self):
        """The count that refuses a /8 is arithmetic, not a 16-million-entry list built first."""
        message = self.refused(cidrs=['10.0.0.0/8'], allowlist=['10.0.0.0/8'])
        self.assertIn('16777214', message)
        self.assertIn('up to', message, 'the summed upper bound is what the refusal quotes')

    def test_host_count_matches_the_addresses_a_network_will_probe(self):
        for cidr in ('10.11.0.0/29', '10.11.0.8/30', '10.11.0.12/31', '10.11.0.14/32'):
            network = ipaddress.ip_network(cidr)
            with self.subTest(cidr=cidr):
                self.assertEqual(sweep_provider.host_count(network), len(list(network.hosts())))

    def test_bound_may_be_tightened_and_never_loosened(self):
        self.assertIn('bound', self.refused(cidrs=['10.11.0.0/29'], max_addresses=2))
        self.assertIn('bound', self.refused(cidrs=['10.11.0.0/29'], max_addresses=0))
        self.assertIn('bound', self.refused(cidrs=['10.11.0.0/29'],
                                           max_addresses=sweep_provider.MAX_ADDRESSES + 1))

    def test_too_many_ranges_refused(self):
        cidrs = ['10.11.0.' + str(row) + '/32' for row in range(1, 70)]
        self.assertIn('networks', self.refused(cidrs=cidrs))

    def test_missing_prober_refused_because_no_default_prober_ships(self):
        for bad in (None, '10.11.0.1', 4):
            with self.subTest(prober=bad):
                with self.assertRaises(InvalidInventory):
                    SweepProvider(source='sweep-demo', cidrs=['10.11.0.0/29'], sweep_allowlist=ALLOW,
                                  prober=bad, now=NOW)

    def test_bad_source_name_refused(self):
        with self.assertRaises(InvalidInventory):
            build(prober=self.prober, source='10-11-0-0')


class SweepObservationTests(unittest.TestCase):
    def test_two_responsive_of_six_produce_two_host_observations(self):
        prober = RecordingProber(responsive=['10.11.0.1', '10.11.0.4'])
        result = build(prober=prober).snapshot()
        observed(result, NOW)
        self.assertTrue(result['complete'], 'a sweep enumerates its whole plan or raises')
        self.assertEqual([item['name'] for item in result['observations']], ['10.11.0.1', '10.11.0.4'])
        first = result['observations'][0]
        self.assertEqual(first['kind'], 'host')
        self.assertEqual(first['aliases'], [{'type': 'ip', 'value': '10.11.0.1'}])
        self.assertEqual(first['attributes'], {'discovered_by': 'network-sweep'})
        self.assertEqual(first['evidence'], ['sweep:10.11.0.0/29'])
        self.assertNotIn('resource_id', first, 'a sweep may not name a UUID')
        self.assertEqual(result['scope'], [], 'scope is declared UUIDs, and this sweep claimed none')

    def test_every_planned_address_is_probed_once_even_when_ranges_overlap(self):
        prober = RecordingProber()
        build(cidrs=['10.11.0.0/29', '10.11.0.0/30', '10.11.0.3/32'], prober=prober).observe()
        self.assertEqual(sorted(set(prober.seen)), sorted(prober.seen), 'an overlap must not double-probe')
        self.assertEqual(len(prober.seen), 6, 'a /29 has 6 host addresses')
        self.assertNotIn('10.11.0.0', prober.seen, 'the network address is not a host')
        self.assertNotIn('10.11.0.7', prober.seen, 'the broadcast address is not a host')

    def test_a_single_address_network_is_sweepable_and_bounded(self):
        prober = RecordingProber(responsive=['10.11.0.9'])
        result = build(cidrs=['10.11.0.9/32'], prober=prober).snapshot()
        self.assertEqual([item['name'] for item in result['observations']], ['10.11.0.9'])
        self.assertEqual(prober.seen, ['10.11.0.9'])

    def test_system_name_becomes_the_name_and_a_hostname_alias_when_usable(self):
        answer = {'sysName': 'probe-2.example.test', 'sysDescr': 'secret-of-the-day'}
        prober = RecordingProber(responsive=['10.11.0.2'], named={'10.11.0.2': answer})
        result = build(prober=prober, name_prober=prober.system).snapshot()
        observed(result, NOW)
        item = result['observations'][0]
        self.assertEqual(item['name'], 'probe-2.example.test')
        self.assertEqual(item['aliases'], [{'type': 'ip', 'value': '10.11.0.2'},
                                          {'type': 'hostname', 'value': 'probe-2.example.test'}])
        self.assertNotIn('secret-of-the-day', json.dumps(result), 'only sysName is read from an agent')

    def test_an_unusable_system_name_becomes_neither_alias_nor_name(self):
        for answer in ({'sysName': 'two words'}, {'sysName': 'x' * 300}, {'sysName': 17}, {}, None):
            with self.subTest(answer=answer):
                prober = RecordingProber(responsive=['10.11.0.2'], named={'10.11.0.2': answer})
                item = build(prober=prober, name_prober=prober.system).observe()[0]
                self.assertEqual(item.name, '10.11.0.2')
                self.assertEqual([alias['type'] for alias in item.aliases], ['ip'])

    def test_observation_identity_is_the_address_so_ticks_age_rather_than_duplicate(self):
        prober = RecordingProber(responsive=['10.11.0.1'])
        first = build(prober=prober, now=NOW).observe()[0]
        later = build(prober=prober, now=NOW + dt.timedelta(minutes=15)).observe()[0]
        self.assertEqual(first.observation_id, later.observation_id)
        self.assertEqual(first.observation_id, digest(['network-sweep', '10.11.0.1']))

    def test_a_snapshot_with_no_responder_is_complete_and_empty_not_absent(self):
        result = build(prober=RecordingProber()).snapshot()
        observed(result, NOW)
        self.assertEqual((result['status'], result['complete'], result['observations']), ('ok', True, []))


class SweepFailureIsNotAbsenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name)/'observations.db'

    def test_a_raising_prober_becomes_an_error_snapshot_never_a_shorter_list(self):
        prober = RecordingProber(responsive=['10.11.0.1'], raises=['10.11.0.2'])
        result = build(prober=prober).snapshot()
        observed(result, NOW)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['error_code'], 'prober_unavailable')
        self.assertFalse(result['complete'])
        self.assertEqual(result['observations'], [])
        self.assertNotIn('10.11.0', json.dumps(result), 'the cause is not carried: it names an address')

    def test_observe_raises_a_named_prober_failure_that_keeps_its_cause_off_the_record(self):
        prober = RecordingProber(raises=['10.11.0.1'])
        with self.assertRaises(sweep_provider.ProbeUnavailable) as caught:
            build(prober=prober).observe()
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertNotIn('10.11.0.1', str(caught.exception), 'the refusal names no address')

    def test_a_bug_in_this_module_is_not_filed_as_a_network_outcome(self):
        """Only a raised prober becomes `prober_unavailable`; anything else must be seen as a bug."""
        prober = RecordingProber(responsive=['10.11.0.1'])
        with patch('local_observe.inventory.sweep_provider.discovery.Observation', side_effect=TypeError):
            with self.assertRaises(TypeError):
                build(prober=prober).snapshot()

    def test_a_broken_sweep_ages_nothing_and_says_why(self):
        good = RecordingProber(responsive=['10.11.0.1', '10.11.0.2'])
        discovery.ingest(self.db, build(prober=good).snapshot(), now=NOW)
        later = NOW + dt.timedelta(minutes=30)
        broken = RecordingProber(raises=['10.11.0.1'])
        discovery.ingest(self.db, build(prober=broken, now=later).snapshot(), now=later)
        report = discovery.ageing(self.db, 'sweep-demo', now=later)
        self.assertEqual(report['status'], 'source_unavailable')
        self.assertEqual(report['reason'], 'prober_unavailable')
        self.assertEqual(report['aged_out'], [])

    def test_an_all_quiet_sweep_is_indistinguishable_from_a_dead_prober_so_the_round_refuses(self):
        """discovery guards: this read used to age the whole plan, and nothing could tell it from a dead prober.

        The prober below is a working prober answering `False` for both addresses — byte-identical
        input to one that has quietly died — so the snapshot is fresh, successful and `complete`
        with zero observations. The default round therefore concludes nothing; the uncapped read is
        still available, but only to an operator who asks for it by name.
        """
        good = RecordingProber(responsive=['10.11.0.1', '10.11.0.2'])
        discovery.ingest(self.db, build(prober=good).snapshot(), now=NOW)
        quiet = copy.deepcopy(good)
        quiet.responsive = set()
        later = NOW + dt.timedelta(hours=2)
        discovery.ingest(self.db, build(prober=quiet, now=later).snapshot(), now=later)
        report = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('ageing_capped', 'mass_silence_above_cap', []))
        self.assertEqual((report['known_observations'], report['aged_candidates'], report['allowed_aged']),
                         (2, 2, 1))
        uncapped = discovery.ageing(self.db, 'sweep-demo', now=later, grace_seconds=900, max_aged_percent=100)
        self.assertEqual(uncapped['status'], 'evaluated')
        self.assertEqual([item['last_seen_observed_at'] for item in uncapped['aged_out']],
                         [utc_text(NOW)] * 2)
        self.assertTrue(all(item['removed'] is False for item in uncapped['aged_out']))


class SweepRangeCommitmentTests(unittest.TestCase):
    """A committed address range is an identifier: only placeholders and protocol constants ship."""

    def test_only_rfc1918_boundary_constants_appear_in_the_module(self):
        text = (ROOT/'local_observe/inventory/sweep_provider.py').read_text(encoding='utf-8')
        found = set(LOOSE_CIDR.findall(text))
        self.assertEqual(found - {str(network) for network in sweep_provider.RFC1918}, set(),
                         'a real sweep range belongs in operator config, not product code')

    def test_committed_examples_name_only_the_q5_placeholder_range(self):
        for name in ('observed.yaml', 'declared.yaml'):
            body = (ROOT/'examples/inventory'/name).read_text(encoding='utf-8')
            for line in body.splitlines():
                for cidr in LOOSE_CIDR.findall(line):
                    with self.subTest(file=name, cidr=cidr):
                        self.assertTrue(line.lstrip().startswith('#'),
                                        f'{cidr} must sit in a comment, not in served data')
                        self.assertTrue(ipaddress.ip_network(cidr).subnet_of(Q5),
                                        f'{cidr} is outside the synthetic naming placeholder range 10.11.0.0/16')

    def test_the_example_plan_probes_254_addresses_within_its_own_allowlist(self):
        body = (ROOT/'examples/inventory/observed.yaml').read_text(encoding='utf-8')
        self.assertIn('10.11.0.0/24', body, 'the committed example must name the synthetic naming range')
        plan = SweepProvider(source='sweep-demo', cidrs=['10.11.0.0/24'], sweep_allowlist=['10.11.0.0/16'],
                            prober=RecordingProber(), now=NOW)
        self.assertEqual(len(plan.addresses), 254)


if __name__ == '__main__':
    unittest.main()

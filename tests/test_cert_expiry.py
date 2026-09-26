"""Injected certificate facts exercise real canonical intake; no TLS connection is made."""
import datetime as dt
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.certcheck import CertFacts, hostname_matches, run_cert_check
from local_observe.platform.state import Actor, StateError, Store, validate_event

NOW = timestamp('2026-09-10T12:00:00Z')
RESOURCE = '00000000-0000-4000-8000-000000000001'


class CertificateTests(unittest.TestCase):
    def run_check(self, days=40, *, now=NOW, chain=True, sans=None, fetcher=None, **kwargs):
        facts = CertFacts(utc_text(now + dt.timedelta(days=days)), chain,
                          ['service.example.com'] if sans is None else sans)
        return run_cert_check('certificate', RESOURCE, 'service.example.com',
                              fetcher or (lambda host, port: facts), clock=lambda: now, **kwargs)

    def test_three_stages_have_distinct_incidents_and_repeats_do_not_duplicate(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'state.db')
            actor = Actor('synthetics.tls', 'producer')
            conditions = []
            incidents = []
            for days in (30, 14, 3):
                result = self.run_check(days)
                for sample in result.samples:
                    store.put_evidence(sample, actor, now=NOW)
                event = next(item for item in result.events if '.expiry-' in item['condition'])
                validate_event(event, NOW)
                conditions.append(event['condition'])
                first = store.intake(event, actor, now=NOW)
                incidents.append(first['incident_id'])
                self.assertEqual(store.intake(event, actor, now=NOW)['status'], 'duplicate')
                later = self.run_check(days, now=NOW + dt.timedelta(minutes=1))
                repeated = next(item for item in later.events if '.expiry-' in item['condition'])
                outcome = store.intake(repeated, actor, now=NOW + dt.timedelta(minutes=1))
                self.assertEqual(outcome['incident_id'], first['incident_id'])
            self.assertEqual(conditions, ['certificate.expiry-30d', 'certificate.expiry-14d',
                                           'certificate.expiry-3d'])
            self.assertEqual(len(set(incidents)), 3)

    def test_fetch_failure_and_malformed_metadata_never_invent_a_gauge_or_recovery(self):
        def raising(host, port):
            raise RuntimeError('private-fetch-details')
        cases = [raising, lambda h, p: None,
                 lambda h, p: CertFacts('invalid', True, []),
                 lambda h, p: CertFacts('2026-10-01T00:00:00', True, []),
                 lambda h, p: CertFacts(utc_text(NOW), 1, []),
                 lambda h, p: CertFacts(utc_text(NOW), True, ['*.*.example.com'])]
        for fetcher in cases:
            result = self.run_check(fetcher=fetcher)
            self.assertFalse(result.ok)
            self.assertIsNone(result.days_to_expiry)
            self.assertEqual(result.samples, [])
            self.assertEqual([(event['kind'], event['status']) for event in result.events],
                             [('coverage', 'firing')])
            self.assertNotIn('private-fetch-details', repr(result))
            validate_event(result.events[0], NOW)

    def test_chain_and_hostname_failures_named_and_no_expiry_recovery(self):
        result = self.run_check(chain=False, sans=['other.example.com'])
        self.assertFalse(result.ok)
        self.assertEqual([event['condition'] for event in result.events if event['status'] == 'firing'],
                         ['certificate.chain-valid', 'certificate.hostname-matches-san'])
        self.assertFalse(any('.expiry-' in event['condition'] for event in result.events))
        self.assertEqual(result.days_to_expiry, 40)

    def test_healthy_renewal_resolves_all_stages_and_evidence_is_recoverable(self):
        result = self.run_check()
        self.assertTrue(result.ok)
        self.assertEqual(len(result.events), 6)
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'state.db')
            actor = Actor('synthetics.tls', 'producer')
            for sample in result.samples:
                self.assertEqual(set(sample), {'sample_id', 'observed_at', 'ok', 'value'})
                store.put_evidence(sample, actor, now=NOW)
            for event in result.events:
                validate_event(event, NOW)
                self.assertEqual(event['status'], 'resolved')
                ref = event['evidence'][0]
                self.assertEqual(store.get_evidence(ref['source'], ref['parameters']['sample_id'],
                                                     now=NOW)['status'], 'available')

    def test_thresholds_clock_and_configuration_are_strict(self):
        for thresholds in ((), (30, 30), (3, 14), (True,), (1.0,), (0,), (float('inf'),),
                           (36501,), tuple(range(17, 0, -1))):
            with self.assertRaises(StateError):
                self.run_check(thresholds=thresholds)
        with self.assertRaises(StateError):
            self.run_check(now=NOW.replace(tzinfo=None))
        for port in (True, 0, 65536, '443'):
            with self.assertRaises(StateError):
                self.run_check(port=port)
        result = self.run_check(7, thresholds=(20, 10, 2))
        self.assertEqual(result.events[-1]['condition'], 'certificate.expiry-10d')
        self.assertEqual(self.run_check(-1).events[-1]['condition'], 'certificate.expiry-3d')

    def test_hostname_matching_has_no_multilabel_or_ip_wildcard(self):
        self.assertTrue(hostname_matches('SERVICE.example.com', ['*.example.com']))
        self.assertFalse(hostname_matches('a.b.example.com', ['*.example.com']))
        self.assertFalse(hostname_matches('example.com', ['*.example.com']))
        self.assertFalse(hostname_matches('192.0.2.1', ['*.0.2.1']))
        self.assertTrue(hostname_matches('2001:db8::1', ['2001:0db8::1']))

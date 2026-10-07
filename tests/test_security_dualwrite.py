"""The dual-write: one identity, no sensitive payload outside the owned store, and a visible gap.

Four properties, each of which is a defect class the brief named:

* the analytical copy carries the **operational event's own** ``(source, source_event_id)`` pair, so
  the replay of a lost acknowledgement lands on the row it already wrote (`docs/CONTRACTS.md` §4's
  reason for stable event ids, implemented rather than cited);
* the short-TTL projection carries **no** ``raw`` and **no** principal — proven by markers, because a
  claim about what a copy omits is worthless as a comment;
* a `coverage` event is never copied into a security-events table (§4 keeps the three record kinds
  distinct: a missing log source is not a finding);
* an absent, unreachable or drifting store reaches the platform as a **firing `coverage` event about
  the store**, from the runner's own batch — which is the whole reason the write hook lives in
  `sigma_runner.tick` and not in a background thread nobody schedules.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.http import TransportError
from local_observe.inventory.index import build
from local_observe.inventory.validation import read_document
from local_observe.platform.detections import event
from local_observe.platform.sigma_runner import artifact, tick
from local_observe.platform.state import Actor, Store
from local_observe.security.dualwrite import (PROJECTION_FIELDS, PROJECTION_PREFIX, SecuritySink,
                                            DualWriteResult, analytical_row, dual_write,
                                            short_ttl_projection)
from local_observe.security.memory import InMemorySecurityStore
from local_observe.security.store import (SecurityEventStore, SecurityStoreRefused,
                                         SecurityStoreUnavailable)
from local_observe.security.ttl import DEFAULT_POLICY, TIER_CRITICAL, TIER_ROUTINE

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
RAW_MARKER = 'RAW-PAYLOAD-MUST-NOT-LEAVE'
PRINCIPAL_MARKER = 'principal-must-not-leave'


def finding(kind: str = 'security', severity: str = 'warning', status: str = 'firing',
            source: str = 'sigma-stage', rule: str = 'sigma.5d2cb39c') -> dict:
    """One canonical event from the repository's only factory, in the last completed minute."""
    end = dt.datetime.fromtimestamp(int(dt.datetime.now(dt.timezone.utc).timestamp()) // 60 * 60,
                                    dt.timezone.utc) - dt.timedelta(minutes=2)
    window = {'start': end - dt.timedelta(minutes=1), 'end': end}
    from local_observe.store.client import utc_text
    return event(source, RESOURCE, rule, kind, status,
                 {'start': utc_text(window['start']), 'end': utc_text(window['end'])},
                 {'rule_id': rule, 'artifact_sha256': 'a' * 64}, query_type='sigma-count',
                 version='65ff3516', severity=severity)


def owned(policy=DEFAULT_POLICY):
    """A real store over the in-memory backend, with the owned schema applied."""
    backend = InMemorySecurityStore()
    store = SecurityEventStore(writer=backend, reader=backend, policy=policy)
    store.ensure_schema()
    return backend, store


class IdentityTests(unittest.TestCase):
    """The copy is keyed by the event's identity, which is the whole retry argument."""

    def test_the_analytical_row_carries_the_events_own_identity_verbatim(self):
        event = finding()
        row = analytical_row(event, artifact_sha256='b' * 64)
        self.assertEqual(row.event_id, event['source_event_id'])
        self.assertEqual(row.source, event['source'])
        self.assertEqual(row.rule_id, event['rule_id'])
        self.assertEqual(row.rule_version, event['rule_version'])
        self.assertEqual((row.window_start, row.window_end),
                         (event['window']['start'], event['window']['end']))
        self.assertEqual(row.ts, event['observed_at'])
        self.assertEqual(row.resource_id, RESOURCE)
        self.assertEqual(row.artifact_sha256, 'b' * 64)

    def test_a_second_evaluation_of_the_same_window_is_the_same_identity(self):
        """A replay recomputes the same digest from (rule, version, resource, window): one row follows."""
        self.assertEqual(analytical_row(finding()).event_id, analytical_row(finding()).event_id)
        self.assertNotEqual(analytical_row(finding()).event_id,
                            analytical_row(finding(rule='sigma.other-rule')).event_id)

    def test_the_evidence_sample_rides_as_a_label_and_the_payload_defaults_to_the_event(self):
        event = finding()
        self.assertEqual(analytical_row(event).labels, {})
        with_sample = event.copy()
        with_sample['evidence'] = [dict(event['evidence'][0],
                                        parameters={'rule_id': event['rule_id'], 'sample_id': 'b' * 64})]
        row = analytical_row(with_sample)
        self.assertEqual(row.labels, {'sample_id': 'b' * 64})
        self.assertEqual(row.raw, json.dumps(with_sample, sort_keys=True, separators=(',', ':'),
                                             ensure_ascii=True))

    def test_a_payload_that_is_not_a_canonical_event_is_refused(self):
        """The copy path reuses `state.validate_event` rather than trusting its own narrower reading."""
        for broken in ({}, {'source': 'x'}, {**finding(), 'kind': 'nonsense'},
                       {**finding(), 'evidence': []}, {**finding(), 'window': {'start': 'x', 'end': 'y'}}):
            with self.subTest(event=str(sorted(broken))[:40]):
                with self.assertRaises(SecurityStoreRefused):
                    analytical_row(broken)

    def test_the_tier_follows_the_severity_and_no_caller_can_choose_it(self):
        self.assertEqual(analytical_row(finding(severity='critical')).retention_tier, TIER_CRITICAL)
        self.assertEqual(analytical_row(finding(severity='warning')).retention_tier, TIER_ROUTINE)


class ProjectionTests(unittest.TestCase):
    """What the short-TTL copy may say, and the markers that prove what it may not."""

    def project(self, **kwargs):
        """One canonical event, the analytical row copied from it, and that row's projection."""
        event = finding(**kwargs)
        row = analytical_row(event)
        return event, row, short_ttl_projection(row)

    def test_the_projection_carries_exactly_the_six_namespaced_attributes(self):
        _, _, record = self.project()
        self.assertEqual(sorted(record.fields), sorted(PROJECTION_PREFIX + name for name in PROJECTION_FIELDS))
        self.assertEqual(record.fields[PROJECTION_PREFIX + 'rule_id'], 'sigma.5d2cb39c')
        self.assertEqual(record.resource_id, RESOURCE)
        self.assertEqual(record.severity, 'warning')

    def test_neither_sensitive_column_nor_its_content_appears_in_the_projection(self):
        """The owned row holds `principal` and `raw`; the short copy may name neither."""
        from local_observe.security.store import sensitive_in
        event = finding()
        row = analytical_row(event, principal=PRINCIPAL_MARKER, raw=RAW_MARKER)
        self.assertEqual(sensitive_in(row.as_row(received_at=row.observed_at)), {'principal', 'raw'})
        record = short_ttl_projection(row)
        text = json.dumps(record.__dict__, default=str)
        for marker in (RAW_MARKER, PRINCIPAL_MARKER):
            self.assertIn(marker, row.raw + row.principal)   # the marker really was in the row
            self.assertNotIn(marker, text)
        self.assertEqual(sensitive_in(record.fields), set())

    def test_the_projection_also_drops_the_artifact_digest_and_the_labels(self):
        """Whatever a later producer puts in `labels` stays off the dashboard surface by default."""
        row = analytical_row(finding(), artifact_sha256='c' * 64)
        record = short_ttl_projection(row)
        self.assertNotIn('c' * 64, json.dumps(record.__dict__, default=str))
        self.assertEqual(record.fields[PROJECTION_PREFIX + 'event_id'], row.event_id)

    def test_the_projection_names_the_verdict_and_nothing_that_identifies_a_principal(self):
        event, row, record = self.project(status='resolved', severity='info')
        self.assertEqual(record.body, 'security finding sigma.5d2cb39c is resolved')
        self.assertEqual(record.fields[PROJECTION_PREFIX + 'tier'], TIER_ROUTINE)
        self.assertEqual(record.timestamp, event['observed_at'])
        self.assertEqual(record.timestamp, row.observed_at)

    def test_the_projection_is_a_store_record_and_not_a_private_shape(self):
        from local_observe.store.client import LogRecord
        _, _, record = self.project()
        self.assertIsInstance(record, LogRecord)


class DualWriteTests(unittest.TestCase):
    """What one write of a batch does, reported in its two halves."""

    def test_only_findings_are_copied(self):
        """§4: a coverage event says a signal was missing, which is not a security record."""
        backend, store = owned()
        result = dual_write(store, [finding(kind='coverage'), finding(kind='coverage')])
        self.assertEqual((result.owned_written, result.projection_rows, result.projection), (0, 0, 'none'))
        self.assertEqual(backend.count(), 0)

    def test_a_mixed_batch_copies_the_finding_alone(self):
        backend, store = owned()
        result = dual_write(store, [finding(kind='coverage'), finding(kind='security')])
        self.assertEqual(result.owned_written, 1)
        self.assertEqual(backend.count(), 1)
        self.assertEqual(backend.rows[0]['kind'], 'security')

    def test_the_short_ttl_copy_is_reported_as_unwritten_without_an_exporter(self):
        """The gap is asserted, not decorated: this tree ships no exporter for the projection."""
        _, store = owned()
        result = dual_write(store, [finding()])
        self.assertEqual(result.projection, 'unwritten')
        self.assertEqual(result.projection_rows, 0)
        self.assertIn('no log exporter', result.detail)

    def test_an_exporter_sees_the_projection_and_nothing_else(self):
        """The seam a later card wires: what crosses it is the projection, and not the payload."""
        _, store = owned()
        seen: list = []

        def take(records):
            seen.extend(records)
            return len(records)

        result = dual_write(store, [finding(), finding(rule='sigma.second-rule')],
                            principal=PRINCIPAL_MARKER, log_writer=take)
        self.assertEqual((result.projection, result.projection_rows), ('written', 2))
        self.assertEqual([record.fields[PROJECTION_PREFIX + 'rule_id'] for record in seen],
                         ['sigma.5d2cb39c', 'sigma.second-rule'])
        self.assertNotIn(PRINCIPAL_MARKER, json.dumps([record.__dict__ for record in seen], default=str))

    def test_the_result_refuses_the_ways_a_half_write_can_read_as_whole(self):
        for owned_written, projection_rows, projection in ((1, 1, 'unwritten'), (1, 0, 'written'),
                                                           (1, 0, 'none'), (0, 0, 'maybe')):
            with self.subTest(case=(owned_written, projection_rows, projection)):
                with self.assertRaises(SecurityStoreRefused):
                    DualWriteResult(owned_written=owned_written, projection_rows=projection_rows,
                                    projection=projection, detail='x')

    def test_an_exporter_that_cannot_count_its_own_records_is_refused(self):
        _, store = owned()
        for answer in (True, -1, 'two', 5):
            with self.subTest(answer=answer):
                with self.assertRaises(SecurityStoreRefused):
                    dual_write(store, [finding()], log_writer=lambda records: answer)

    def test_a_retried_batch_stores_one_analytical_row(self):
        backend, store = owned()
        batch = [finding()]
        first = dual_write(store, batch, received_at='2026-09-09T00:00:00+00:00')
        replay = dual_write(store, batch, received_at='2026-09-09T00:01:00+00:00')
        self.assertEqual((first.owned_written, replay.owned_written), (1, 1))
        self.assertEqual(backend.count(), 1)


class DeadStore:
    """A store that cannot be reached: every answer is the same refusal."""

    policy = DEFAULT_POLICY

    def write(self, events, *, received_at=None):
        raise SecurityStoreUnavailable('The security_events store refused or did not answer the write')

    def verify_ttl(self, *, now=None):
        raise SecurityStoreUnavailable('The security_events TTL expression could not be read')


class SinkTests(unittest.TestCase):
    """The runner's hook: verdict words, the report flag, and one TTL read per hour."""

    def setUp(self):
        self.now = dt.datetime(2026, 9, 9, 12, 0, tzinfo=dt.timezone.utc)

    def test_a_write_that_lands_is_reported_once_and_the_copy_is_keyed_on_the_event(self):
        backend, store = owned()
        sink = SecuritySink(store)
        verdict = sink.record([finding()], now=self.now)
        self.assertEqual((verdict.store, verdict.rows, verdict.report, verdict.healthy),
                         ('written', 1, True, True))
        self.assertEqual(verdict.ttl.status, 'match')
        self.assertEqual(backend.rows[0]['event_id'], finding()['source_event_id'])

    def test_an_absent_store_is_a_verdict_and_not_a_silence(self):
        verdict = SecuritySink(DeadStore()).record([finding()], now=self.now)
        self.assertEqual(verdict.store, 'unavailable')
        self.assertEqual(verdict.ttl.status, 'unreadable')
        self.assertFalse(verdict.healthy)
        self.assertTrue(verdict.report)
        self.assertIn('refused or did not answer', verdict.detail)

    def test_a_refused_row_is_a_different_word_from_an_unreachable_store(self):
        class Refusing(DeadStore):
            def write(self, events, *, received_at=None):
                raise SecurityStoreRefused('one batch carries a repeated identity')

        verdict = SecuritySink(Refusing()).record([finding()], now=self.now)
        self.assertEqual(verdict.store, 'refused')
        self.assertFalse(verdict.healthy)

    def test_a_window_with_no_finding_still_asks_on_its_cadence_and_then_stays_quiet(self):
        backend, store = owned()
        sink = SecuritySink(store)
        quiet = sink.record([finding(kind='coverage')], now=self.now)
        self.assertEqual(quiet.store, 'idle')
        self.assertTrue(quiet.report)          # the first batch reads the TTL: the store is watched
        self.assertEqual(quiet.rows, 0)
        self.assertEqual(backend.count(), 0)   # and nothing was written to prove it
        read_after_first = backend.reads
        later = sink.record([finding(kind='coverage')], now=self.now + dt.timedelta(minutes=2))
        self.assertFalse(later.report)         # no write, no re-read inside the interval
        self.assertEqual(backend.reads, read_after_first)
        hourly = sink.record([finding(kind='coverage')], now=self.now + dt.timedelta(hours=1))
        self.assertTrue(hourly.report)
        self.assertGreater(backend.reads, read_after_first)

    def test_a_clock_that_moves_backwards_does_not_trigger_a_second_read(self):
        _, store = owned()
        sink = SecuritySink(store)
        sink.record([finding()], now=self.now)
        verdict = sink.record([finding()], now=self.now - dt.timedelta(minutes=30))
        self.assertEqual(verdict.ttl.status, 'match')
        self.assertEqual(sink.last_check, self.now)

    def test_drift_and_unreadable_checks_stay_unhealthy_until_a_fresh_match(self):
        for unavailable in (False, True):
            with self.subTest(unavailable=unavailable):
                backend, store = owned()
                if unavailable:
                    from unittest.mock import patch
                    check = patch.object(store, 'verify_ttl', side_effect=SecurityStoreUnavailable('offline'))
                    check.start()
                else:
                    store = SecurityEventStore(writer=backend, reader=backend, policy=narrow_policy())
                sink = SecuritySink(store)
                first = sink.record([finding()], now=self.now)
                if unavailable:
                    check.stop()
                self.assertFalse(first.healthy)
                reads = backend.reads
                for seconds in (-60, 60, 3599):
                    for events in ([], [finding()]):
                        cached = sink.record(events, now=self.now + dt.timedelta(seconds=seconds))
                        self.assertFalse(cached.healthy)
                        self.assertEqual(cached.ttl, first.ttl)
                        self.assertEqual(sink.last_check, self.now)
                self.assertEqual(backend.reads, reads)
                if not unavailable:
                    corrected, _ = owned(narrow_policy())
                    backend.ttl_expression = corrected.ttl_expression
                recovered = sink.record([], now=self.now + dt.timedelta(hours=1))
                self.assertTrue(recovered.healthy)
                self.assertTrue(recovered.report)
                self.assertEqual(sink.last_check, self.now + dt.timedelta(hours=1))

    def test_a_ttl_drift_is_visible_without_claiming_the_write_failed(self):
        """The two answers are different: the copy landed, the table's retention is somebody else's fix."""
        backend, _ = owned()
        narrowed = SecurityEventStore(writer=backend, reader=backend, policy=narrow_policy())
        verdict = SecuritySink(narrowed).record([finding()], now=self.now)
        self.assertEqual(verdict.store, 'written')
        self.assertEqual(verdict.ttl.status, 'drift')
        self.assertIn('declared 400d', verdict.ttl.detail)
        self.assertFalse(verdict.healthy)
        self.assertEqual(backend.count(), 1)

    def test_the_verdict_words_are_a_closed_set(self):
        with self.assertRaises(SecurityStoreRefused):
            from local_observe.security.dualwrite import SinkVerdict
            SinkVerdict(store='fine', rows=0, ttl=None, report=False, detail='x')

    def test_a_sink_needs_a_store_and_a_sane_interval(self):
        with self.assertRaises(SecurityStoreRefused):
            SecuritySink(object())
        _, store = owned()
        for interval in (0, 30, 90000):
            with self.subTest(interval=interval):
                with self.assertRaises(SecurityStoreRefused):
                    SecuritySink(store, check_interval_seconds=interval)


def narrow_policy():
    from local_observe.security.ttl import RetentionPolicy
    return RetentionPolicy(critical_days=400, routine_days=30)


class Query:
    """The store's compiled-artifact answer: one aggregate row, with no rows behind it."""

    def __init__(self, match=1, total=2, usable=2):
        self.row = {'source_count': total, 'usable_count': usable, 'match_count': match}
        self.calls = 0

    def query(self, sql, parameters):
        self.calls += 1
        return self.row


class Intake:
    """The platform's two intake routes, driven straight against the real SQLite store."""

    def __init__(self, store, now):
        self.store, self.now, self.fail = store, now, False

    def request(self, method, path, payload):
        actor = Actor('sigma-stage', 'producer')
        if self.fail and path == '/v1/events':
            self.fail = False
            raise TransportError('Lost acknowledgement')
        result = (self.store.intake(payload, actor, now=self.now) if path == '/v1/events'
                  else self.store.put_evidence(payload, actor, now=self.now))
        return 200, result


class RunnerHookTests(unittest.TestCase):
    """The hook as the runner uses it: with no sink nothing changes, and a dead store is visible.

    These run against the real `sigma_runner.tick` and the real platform `Store` because the
    property under test is the *event the runner files* — a unit test of the sink alone would pass
    even if `tick` forgot to call it. `tests/test_sigma_runner.py` owns the runner's cursor and
    replay behaviour; this file owns only the third event.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'index.db'
        build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture')
        self.compiled = artifact(ROOT / 'examples/sigma/compiled/process-marker.json')
        self.now = dt.datetime(2026, 9, 6, 15, 0, tzinfo=dt.timezone.utc)

    def run_tick(self, name, sink=None, store=None, query=None):
        store = store or Store(self.root / f'{name}.db')
        intake = Intake(store, self.now)
        result = tick(self.index, self.compiled, RESOURCE, self.root / f'{name}.json',
                      query or Query(), intake, now=self.now, security=sink)
        return store, intake, result

    def payloads(self, store):
        return [json.loads(row['payload']) for row in store.records('events')]

    def test_no_sink_means_the_two_events_it_always_filed(self):
        store, _, result = self.run_tick('plain')
        kinds = sorted(item['rule_id'] for item in self.payloads(store))
        self.assertEqual(result, 'delivered')
        self.assertEqual(len(kinds), 2)
        self.assertNotIn('sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09.store-coverage', kinds)

    def test_a_healthy_store_adds_one_resolved_coverage_event_and_one_analytical_row(self):
        backend, store = owned()
        platform, _, _ = self.run_tick('healthy', sink=SecuritySink(store))
        events = {item['rule_id']: item for item in self.payloads(platform)}
        coverage = events['sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09.store-coverage']
        self.assertEqual(coverage['kind'], 'coverage')
        self.assertEqual(coverage['status'], 'resolved')
        self.assertEqual(coverage['severity'], 'info')
        self.assertEqual(coverage['evidence'][0]['query_type'], 'source-heartbeat')
        self.assertEqual(backend.count(), 1)
        finding_event = events['sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09']
        self.assertEqual(backend.rows[0]['event_id'], finding_event['source_event_id'],
                         'the analytical row must be keyed on the operational event identity')

    def test_an_absent_store_files_a_firing_coverage_event_about_the_store_and_still_delivers(self):
        platform, _, result = self.run_tick('dead', sink=SecuritySink(DeadStore()))
        events = {item['rule_id']: item for item in self.payloads(platform)}
        coverage = events['sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09.store-coverage']
        self.assertEqual((coverage['kind'], coverage['status'], coverage['severity']),
                         ('coverage', 'firing', 'warning'))
        self.assertEqual(result, 'delivered')
        self.assertEqual(events['sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09']['status'], 'firing')
        self.assertEqual(platform.status()['incidents']['open'], 2)

    def test_a_lost_acknowledgement_replays_the_copy_onto_the_same_row(self):
        backend, store = owned()
        sink = SecuritySink(store)
        platform = Store(self.root / 'replay.db')
        first = Intake(platform, self.now)
        first.fail = True
        with self.assertRaises(TransportError):
            tick(self.index, self.compiled, RESOURCE, self.root / 'replay.json', Query(), first,
                 now=self.now, security=sink)
        cursor = json.loads((self.root / 'replay.json').read_text())
        self.assertEqual(cursor['pending']['store'], 'written')
        self.assertEqual(backend.count(), 1)
        # The copy landed while the operational batch is still owed: the replay re-sends the same
        # identity onto the same row, and the store is not re-asked because the batch already says it
        # landed.
        second = Intake(platform, self.now + dt.timedelta(minutes=1))
        tick(self.index, self.compiled, RESOURCE, self.root / 'replay.json', Query(), second,
             now=self.now + dt.timedelta(minutes=1), security=sink)
        self.assertEqual(backend.count(), 1)
        self.assertEqual(len([s for s in backend.statements if s.startswith('INSERT')]), 1)

    def test_a_resolved_finding_is_copied_too_because_the_store_is_an_account_not_an_alert(self):
        backend, store = owned()
        platform, _, _ = self.run_tick('quiet', sink=SecuritySink(store), query=Query(match=0))
        events = {item['rule_id']: item for item in self.payloads(platform)}
        self.assertEqual(events['sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09']['status'], 'resolved')
        self.assertEqual(backend.count(), 1, 'the absence of a match is still a verdict worth keeping')
        self.assertEqual(events['sigma.5d2cb39c-5f2a-4b40-b346-a2a00e0a8d09.store-coverage']['status'],
                         'resolved')

    def test_successful_writes_do_not_resolve_retention_coverage_before_recheck(self):
        backend, _ = owned()
        store = SecurityEventStore(writer=backend, reader=backend, policy=narrow_policy())
        sink = SecuritySink(store)
        platform, _, _ = self.run_tick('ttl-cadence', sink=sink)
        self.now += dt.timedelta(minutes=1)
        self.run_tick('ttl-cadence', sink=sink, store=platform)
        coverage = sorted((e for e in self.payloads(platform) if e['rule_id'].endswith('.store-coverage')),
                          key=lambda e: e['window']['end'])
        self.assertEqual([e['status'] for e in coverage], ['firing', 'firing'])
        corrected, _ = owned(narrow_policy())
        backend.ttl_expression = corrected.ttl_expression
        self.now += dt.timedelta(hours=1)
        self.run_tick('ttl-cadence', sink=sink, store=platform)
        coverage = sorted((e for e in self.payloads(platform) if e['rule_id'].endswith('.store-coverage')),
                          key=lambda e: e['window']['end'])
        self.assertEqual([e['status'] for e in coverage], ['firing', 'firing', 'resolved'])


if __name__ == '__main__':
    unittest.main()

"""The round that was owed and never got away: a lost ack, a crash, a refused second event.

`pathcheck.tick` files one or two events per round through a `deliver` call that can fail in three
different places, and only one of them is benign:

* it raises **before** the platform saw the bytes — nothing was written, and the next round may judge
  afresh;
* it raises **after** the platform committed the event and before the answer arrived — the producer
  cannot tell this from the first case, and guessing wrong costs a `resolved` event that never gets
  filed, which leaves an incident open over a network the operator can watch being healthy;
* the process dies between the first event and the second — half a transition is durable and the
  condition state that would have completed it is gone.

So the batch is written to the cursor *before* the first send, together with the condition and route
state the round intends to leave behind, and the cursor adopts that state only once every byte has been
accepted. The round that finds a pending batch replays it and returns without reading a report or
opening the inventory index: a fresh probe cannot un-owe a conclusion the previous round already
reached, and re-judging instead of replaying is the bug this file exists to keep fixed.
`conditions.tick` holds the same rule for the same reason; what is added here is the route baselines,
because a transition computed from a trace that has since moved is not the transition the failed round
saw.

The refusal half matters as much as the retry half. A failure that never got an answer keeps the batch;
a failure that says "the platform answered and did not take it" drops it, because bytes intake named as
bad will not be improved by being sent again every round forever, and a producer that only ever replays
them reports nothing about the network at all.

Everything here runs the real producer: a built inventory index, the real `Store.intake` behind
`deliver`, a real cursor file read back from disk. Times follow `test_pathcheck.py` — :data:`NOW` sits
five seconds inside a 300-second round whose watermark is ``12:00:00Z``.
"""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.http import TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import pathcheck
from local_observe.platform.state import Actor, StateError, Store, validate_event

VANTAGE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
SOURCE = 'pathcheck-replay-test'
PRODUCER = Actor(SOURCE, 'producer')
INTERVAL = dt.timedelta(seconds=300)
WATERMARK = dt.datetime(2026, 8, 5, 12, 0, 0, tzinfo=dt.timezone.utc)
NOW = WATERMARK + dt.timedelta(seconds=5)
LATER = WATERMARK + INTERVAL
LATER_NOW = LATER + dt.timedelta(seconds=5)
API, ROUTER = 'demo-api', 'router-01'

DECLARATION = {'schema_version': 1, 'resources': [
    {'id': VANTAGE, 'kind': 'host', 'name': 'probe-1',
     'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'},
                 {'type': 'ip', 'value': '10.11.0.21'}],
     'attributes': {'environment': 'demo'}, 'relations': []}]}


def written(events: list[dict]) -> list[str]:
    """The canonical text of a batch, so "the same bytes" is an assertion and not an intention."""
    return [json.dumps(item, sort_keys=True) for item in events]


class Deliverer:
    """The delivery seam: validate and file every event for real, and fail at a chosen position.

    :attr:`interrupt_at` is the 1-based count of delivered events at which the raise happens, and
    :attr:`commit_interrupted` decides which side of `Store.intake` it lands on: True reproduces the
    lost acknowledgement (the row is committed and the answer never arrives, so the producer holds an
    event the platform already has), False reproduces a refusal (the platform answered and wrote
    nothing).
    """

    def __init__(self, store: Store, *, now: dt.datetime, interrupt_at: int | None = None,
                 commit_interrupted: bool = True, error: type[Exception] = TransportError) -> None:
        self.store, self.now = store, now
        self.interrupt_at, self.commit_interrupted, self.error = (interrupt_at, commit_interrupted,
                                                                  error)
        self.events: list[dict] = []
        self.receipts: list[dict] = []
        self.calls = 0

    def __call__(self, item: dict) -> None:
        self.calls += 1
        validate_event(item, self.now)
        if (self.interrupt_at is not None and not self.commit_interrupted
                and self.calls == self.interrupt_at):
            raise self.error('Synthetic intake refusal before the event was filed')
        self.receipts.append(self.store.intake(item, PRODUCER, now=self.now))
        self.events.append(dict(item))
        if (self.interrupt_at is not None and self.commit_interrupted
                and self.calls == self.interrupt_at):
            raise self.error('Synthetic lost acknowledgement after committed intake')


class ReplayFixture(unittest.TestCase):
    """Scratch for the durable half: an index, a store, a reports tree, a cursor, a 300 s round."""

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
        self._config: dict | None = None

    @property
    def config(self) -> dict:
        """The validated configuration: this vantage, both targets, ICMP, a 300 s tick."""
        if self._config is None:
            document = {'vantage_resource_id': VANTAGE, 'targets': [API, ROUTER],
                        'protocols': ['icmp'], 'interval_seconds': 300,
                        'sources': {'reports_dir': str(self.reports)}, 'cursor': str(self.cursor)}
            path = self.root / 'config.json'
            path.write_text(json.dumps(document), encoding='utf-8')
            self._config = pathcheck.load_config(path)
        return self._config

    def write_report(self, probes: list[dict], *, observed_at: dt.datetime = WATERMARK,
                     traces: list[dict] | None = None) -> Path:
        """Drop this vantage point's report where the producer reads them."""
        payload = {'schema_version': 1, 'vantage_resource_id': VANTAGE,
                   'observed_at': utc_text(observed_at), 'probes': probes}
        if traces is not None:
            payload['traces'] = traces
        path = self.reports / f'{VANTAGE[:8]}.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def both(self, api: bool = True, router: bool = True) -> list[dict]:
        """Both configured targets as one report's probe list."""
        return [{'target': API, 'ok': api}, {'target': ROUTER, 'ok': router}]

    def round(self, *, now: dt.datetime = NOW, deliverer: Deliverer | None = None,
              config: dict | None = None) -> dict:
        """One round against the shared index, reports and cursor file."""
        return pathcheck.tick(self.index, config or self.config, self.cursor,
                              deliverer or Deliverer(self.store, now=now), now=now, source=SOURCE)

    def stored(self) -> dict:
        """The cursor exactly as the next process will read it."""
        return json.loads(self.cursor.read_text(encoding='utf-8'))

    def open_incidents(self) -> int:
        return self.store.status()['incidents'].get('open', 0)


class LostAcknowledgementTests(ReplayFixture):
    """The failure an operator feels: the platform took the verdict and the producer never heard."""

    def test_a_lost_acknowledgement_stores_the_exact_bytes_before_the_first_send(self):
        """Nothing about an owed round may live only in memory once a send has been attempted."""
        self.write_report(self.both())
        self.round()  # healthy: nothing owed, nothing filed
        self.write_report(self.both(api=False), observed_at=LATER)
        deliverer = Deliverer(self.store, now=LATER_NOW, interrupt_at=1)
        with self.assertRaises(TransportError):
            self.round(now=LATER_NOW, deliverer=deliverer)
        stored = self.stored()
        self.assertEqual(written(stored['pending']['events']), written(deliverer.events),
                         'the owed batch is not the byte-identical batch that was sent')
        self.assertEqual(stored['pending']['end'], utc_text(LATER))
        self.assertEqual(stored['pending']['binding'], stored['binding'])
        self.assertEqual(stored['pending']['open'], {'kind': 'availability',
                                                     'rule_id': 'pathcheck.target'},
                         'the batch did not carry the condition state it would have left behind')
        self.assertIsNone(stored['open'], 'the cursor advanced over a round that was not acknowledged')

    def test_the_round_after_a_lost_ack_replays_it_and_reads_no_report_at_all(self):
        """A fresh healthy probe is not evidence about the round that already concluded."""
        self.write_report(self.both())
        self.round()
        self.write_report(self.both(api=False), observed_at=LATER)
        with self.assertRaises(TransportError):
            self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW, interrupt_at=1))
        self.write_report(self.both(), observed_at=LATER)  # the source "recovered" under the batch
        with mock.patch.object(pathcheck, 'load_reports') as reader, \
                mock.patch.object(pathcheck.index, 'readonly') as opener:
            summary = self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW))
        reader.assert_not_called()
        opener.assert_not_called()
        self.assertEqual(summary['result'], 'replayed')
        self.assertIsNone(summary['verdict'], 'a replay round invented a verdict from reports it never '
                                              'read')
        self.assertEqual(summary['blind_reason'], 'pending_batch')
        self.assertEqual([item['status'] for item in summary['events']], ['firing'])
        self.assertEqual(summary['window'], {'start': utc_text(LATER - INTERVAL), 'end': utc_text(LATER)},
                         'a replay round reported a window its events do not carry')

    def test_the_incident_a_lost_ack_opened_is_closed_one_replay_later(self):
        """The whole sequence an operator would run, end to end, against the real store."""
        self.write_report(self.both())
        self.round()
        self.write_report(self.both(api=False), observed_at=LATER)
        with self.assertRaises(TransportError):
            self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW, interrupt_at=1))
        self.assertEqual(self.open_incidents(), 1, 'the committed event did not reach the platform')
        self.write_report(self.both(), observed_at=LATER)
        replay = self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW))
        self.assertEqual(replay['result'], 'replayed')
        self.assertEqual(self.stored()['pending'], None)
        self.assertEqual(self.stored()['open'], {'kind': 'availability', 'rule_id': 'pathcheck.target'},
                         'the replay adopted the wrong condition state')
        self.write_report(self.both(), observed_at=LATER + INTERVAL)
        recovery = self.round(now=LATER_NOW + INTERVAL,
                              deliverer=Deliverer(self.store, now=LATER_NOW + INTERVAL))
        self.assertEqual(recovery['verdict'], 'ok')
        self.assertEqual([(item['status'], item['rule_id']) for item in recovery['events']],
                         [('resolved', 'pathcheck.target')])
        self.assertEqual(self.open_incidents(), 0, 'the incident outlived the network it was about')
        self.assertIsNone(self.stored()['open'])

    def test_a_restart_replays_the_stored_bytes_and_the_platform_folds_the_retry(self):
        """A new process reads the cursor from disk and re-sends its event ids, not new ones."""
        self.write_report(self.both(api=False))
        with self.assertRaises(TransportError):
            self.round(deliverer=Deliverer(self.store, now=NOW, interrupt_at=1))
        owed = self.stored()['pending']['events']
        replay = Deliverer(self.store, now=LATER_NOW)
        summary = self.round(now=LATER_NOW, deliverer=replay)
        self.assertEqual(written(owed), written(summary['events']))
        self.assertEqual([receipt['status'] for receipt in replay.receipts], ['duplicate'],
                         'the replay opened a second incident for an event already committed')
        self.assertEqual(self.open_incidents(), 1)
        self.assertEqual(self.stored()['pending'], None)

    def test_a_platform_that_stays_down_never_makes_the_producer_look_at_the_network(self):
        """Repeated failure keeps the batch, keeps it unchanged, and keeps the round from judging."""
        self.write_report(self.both(api=False))
        with self.assertRaises(TransportError):
            self.round(deliverer=Deliverer(self.store, now=NOW, interrupt_at=1))
        before = self.cursor.read_text(encoding='utf-8')
        for moment in (LATER_NOW, LATER_NOW + INTERVAL, LATER_NOW + 2 * INTERVAL):
            with mock.patch.object(pathcheck, 'load_reports') as reader:
                with self.assertRaises(TransportError):
                    self.round(now=moment, deliverer=Deliverer(self.store, now=moment,
                                                               interrupt_at=1))
                reader.assert_not_called()
        self.assertEqual(self.cursor.read_text(encoding='utf-8'), before,
                         'a round that delivered nothing rewrote what it owed')

    def test_a_refused_batch_is_retained_until_delivery_succeeds(self):
        """A refusal cannot erase the transition this round owes."""
        self.write_report(self.both(api=False))
        with self.assertRaises(StateError):
            self.round(deliverer=Deliverer(self.store, now=NOW, interrupt_at=1,
                                          commit_interrupted=False, error=StateError))
        self.assertIsNotNone(self.stored()['pending'], 'a refused batch must remain owed')
        self.assertIsNone(self.stored()['open'], 'the cursor adopted a verdict it never delivered')
        self.assertEqual(self.store.records('events'), [])
        self.write_report(self.both(), observed_at=LATER)
        summary = self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW))
        self.assertEqual(summary['result'], 'replayed')
        summary = self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW))
        self.assertEqual((summary['result'], summary['verdict']), ('delivered', 'ok'))
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})


class PendingBatchShapeTests(ReplayFixture):
    """What travels with the batch, and what a round that owes nothing leaves behind."""

    def test_the_second_event_of_a_transition_rides_along_with_the_first(self):
        """A coverage round that becomes a target round owes two events and may be cut in half."""
        self.round()  # blind: coverage fires, and the round is acknowledged
        self.assertIsNone(self.stored()['pending'], 'a delivered round left a batch behind')
        self.write_report(self.both(api=False), observed_at=LATER)
        with self.assertRaises(TransportError):
            # resolves coverage, then fails before the target finding is ever filed
            self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW, interrupt_at=2,
                                                         commit_interrupted=False))
        stored = self.stored()
        self.assertEqual([(item['status'], item['rule_id']) for item in stored['pending']['events']],
                         [('resolved', 'pathcheck.coverage'), ('firing', 'pathcheck.target')])
        self.assertEqual(stored['pending']['open'], {'kind': 'availability',
                                                     'rule_id': 'pathcheck.target'})
        self.assertEqual(stored['open'], {'kind': 'coverage', 'rule_id': 'pathcheck.coverage'},
                         'the cursor claimed a transition it had only half delivered')
        replay = Deliverer(self.store, now=LATER_NOW + INTERVAL)
        summary = self.round(now=LATER_NOW + INTERVAL, deliverer=replay)
        self.assertEqual((summary['result'], summary['replayed_events']), ('replayed', 2))
        self.assertEqual([(receipt['status'], receipt.get('transition'))
                          for receipt in replay.receipts],
                         [('duplicate', None), ('accepted', 'opened')],
                         'the replay re-sent a committed event as a new one')
        self.assertEqual(self.open_incidents(), 1, 'a half-delivered transition opened twice')

    def test_a_lost_ack_on_the_second_event_replays_both_without_paging_twice(self):
        """The same batch when both bytes landed: the replay is two duplicates and no new incident."""
        self.round()  # blind, acknowledged
        self.write_report(self.both(api=False), observed_at=LATER)
        with self.assertRaises(TransportError):
            self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW, interrupt_at=2))
        replay = Deliverer(self.store, now=LATER_NOW + INTERVAL)
        summary = self.round(now=LATER_NOW + INTERVAL, deliverer=replay)
        self.assertEqual(summary['result'], 'replayed')
        self.assertEqual([(receipt['status'], receipt.get('transition'))
                          for receipt in replay.receipts],
                         [('duplicate', None), ('duplicate', None)],
                         'a committed event was filed a second time')
        self.assertEqual(self.open_incidents(), 1)

    def test_a_route_transition_computed_by_a_lost_round_is_the_one_the_cursor_keeps(self):
        """The intended final state is durable too: a replay must not re-derive a route from new traces."""
        direct = [{'target': API, 'protocol': 'icmp',
                   'hops': [{'ttl': 1, 'address': '10.11.0.1', 'rtts_ms': [1.0]}]}]
        self.write_report(self.both(), traces=direct)
        self.round()
        moved = [{'target': API, 'protocol': 'icmp',
                  'hops': [{'ttl': 1, 'address': '10.11.0.9', 'rtts_ms': [1.0]},
                           {'ttl': 2, 'address': '10.11.0.1', 'rtts_ms': [2.0]}]}]
        self.write_report(self.both(api=False), observed_at=LATER, traces=moved)
        with self.assertRaises(TransportError):
            self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW, interrupt_at=1))
        stored = self.stored()
        key = pathcheck.route_key(VANTAGE, API, 'icmp')
        self.assertEqual(stored['routes'][key]['open'], 'no',
                         'a refused round advanced the route state it never got to file')
        self.assertEqual(stored['pending']['routes'][key]['open'], 'yes',
                         'the batch did not carry the route state the round computed')
        self.round(now=LATER_NOW + INTERVAL,
                   deliverer=Deliverer(self.store, now=LATER_NOW + INTERVAL))
        self.assertEqual(self.stored()['routes'][key]['open'], 'yes',
                         'the replay never adopted the route state it owed')

    def test_a_round_that_owed_nothing_leaves_no_batch_behind(self):
        self.write_report(self.both())
        summary = self.round()
        self.assertEqual((summary['result'], summary['replayed_events']), ('idle', 0))
        self.assertIsNone(self.stored()['pending'])

    def test_a_retuned_interval_does_not_invalidate_the_owed_batch(self):
        """`cursor_binding` ignores the tick rate, and an owed batch survives a retune the same way."""
        self.write_report(self.both(api=False))
        with self.assertRaises(TransportError):
            self.round(deliverer=Deliverer(self.store, now=NOW, interrupt_at=1))
        slower = {**self.config, 'interval_seconds': 900}
        pathcheck.load_cursor(self.cursor, slower)
        summary = self.round(now=LATER_NOW, deliverer=Deliverer(self.store, now=LATER_NOW),
                             config=slower)
        self.assertEqual(summary['result'], 'replayed')


class PendingCursorValidationTests(ReplayFixture):
    """A cursor may be owed only in the shape this module wrote it in."""

    def owed(self) -> dict:
        """A cursor holding one coherent batch, straight out of a real round."""
        self.write_report(self.both(api=False))
        with self.assertRaises(TransportError):
            self.round(deliverer=Deliverer(self.store, now=NOW, interrupt_at=1))
        return self.stored()

    def test_a_batch_that_needs_no_repair_round_trips_and_is_deliverable(self):
        document = self.owed()
        pathcheck.save_cursor(self.cursor, document)
        self.assertTrue(pathcheck.load_cursor(self.cursor, self.config)['pending'])

    def test_a_cursor_written_before_a_batch_was_kept_is_read_as_owing_nothing(self):
        """Legacy in both directions: four keys load, and the open finding they carry is honoured."""
        legacy = {'schema_version': pathcheck.CURSOR_VERSION,
                  'binding': pathcheck.cursor_binding(self.config),
                  'open': {'kind': 'coverage', 'rule_id': 'pathcheck.coverage'}, 'routes': {}}
        self.cursor.write_text(json.dumps(legacy), encoding='utf-8')
        self.assertIsNone(pathcheck.load_cursor(self.cursor, self.config)['pending'])
        self.write_report(self.both())
        deliverer = Deliverer(self.store, now=NOW)
        summary = self.round(deliverer=deliverer)
        self.assertEqual([(item['status'], item['rule_id']) for item in deliverer.events],
                         [('resolved', 'pathcheck.coverage')],
                         'a legacy open condition was dropped instead of closed')
        self.assertEqual(summary['result'], 'delivered')
        self.assertIsNone(self.stored()['open'])

    def test_a_tampered_batch_is_refused_field_by_field(self):
        document = self.owed()
        broken_event = json.loads(json.dumps(document['pending']['events'][0]))
        broken_event['severity'] = 'catastrophic'
        cases: list[tuple[str, object]] = [
            ('not a document', 'owed'),
            ('an unknown key', {**document, 'pending': {**document['pending'], 'tries': 3}}),
            ('a missing key', {**document, 'pending': {key: value for key, value
                                                       in document['pending'].items()
                                                       if key != 'open'}}),
            ('another configuration', {**document, 'pending': {**document['pending'],
                                                              'binding': 'f' * 64}}),
            ('no events at all', {**document, 'pending': {**document['pending'], 'events': []}}),
            ('more events than one round files',
             {**document, 'pending': {**document['pending'],
                                      'events': document['pending']['events']
                                      * (pathcheck.MAX_PENDING_EVENTS + 1)}}),
            ('an event that is not canonical',
             {**document, 'pending': {**document['pending'], 'events': [broken_event]}}),
            ('a batch that names no window', {**document, 'pending': {**document['pending'],
                                                                     'end': 'yesterday'}}),
            ('an open condition of a kind never filed',
             {**document, 'pending': {**document['pending'],
                                      'open': {'kind': 'drift', 'rule_id': 'pathcheck.target'}}}),
            ('a route signature that is not a digest',
             {**document, 'pending': {**document['pending'],
                                      'routes': {'k': {'baseline': 'short', 'signature': 'x' * 64,
                                                       'open': 'no'}}}}),
            ('an unknown cursor key beside a batch', {**document, 'retry_at': utc_text(LATER)}),
        ]
        for label, case in cases:
            with self.subTest(case=label):
                self.cursor.write_text(case if isinstance(case, str) else json.dumps(case),
                                       encoding='utf-8')
                with self.assertRaises(ValueError):
                    pathcheck.load_cursor(self.cursor, self.config)

    def test_a_pending_batch_is_bounded_by_the_two_events_one_round_can_owe(self):
        self.assertEqual(pathcheck.MAX_PENDING_EVENTS, 2)
        document = self.owed()
        self.assertLessEqual(len(document['pending']['events']), pathcheck.MAX_PENDING_EVENTS)

    def test_a_refused_pending_batch_refuses_the_round_without_filing_or_rewriting_anything(self):
        document = self.owed()
        document['pending']['events'][0]['severity'] = 'catastrophic'
        self.cursor.write_text(json.dumps(document), encoding='utf-8')
        tampered = self.cursor.read_text(encoding='utf-8')
        deliverer = Deliverer(self.store, now=NOW)
        with self.assertRaises(ValueError):
            self.round(deliverer=deliverer)
        self.assertEqual(deliverer.events, [])
        self.assertEqual(self.cursor.read_text(encoding='utf-8'), tampered)

    def test_the_pending_window_is_the_clock_the_batch_is_checked_against(self):
        """Ageing an owed round out of its own cursor would lose the verdict, not protect anyone."""
        document = self.owed()
        far = timestamp(document['pending']['end']) + dt.timedelta(days=14)
        for item in document['pending']['events']:
            item['window'] = {'start': utc_text(far - INTERVAL), 'end': utc_text(far)}
            for reference in item['evidence']:
                reference['window'] = dict(item['window'])
        document['pending']['end'] = utc_text(far)
        self.cursor.write_text(json.dumps(document), encoding='utf-8')
        pathcheck.load_cursor(self.cursor, self.config)  # judged against the round it was written for
        stale = json.loads(json.dumps(document))
        stale['pending']['end'] = utc_text(WATERMARK - INTERVAL)
        self.cursor.write_text(json.dumps(stale), encoding='utf-8')
        with self.assertRaises(ValueError):
            pathcheck.load_cursor(self.cursor, self.config)

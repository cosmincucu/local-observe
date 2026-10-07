"""The owed batch: what the drift producer does when intake accepted an event and the answer was lost.

`tick` can only deliver after it has judged, and `Store.intake` commits before it answers. Those two
facts overlap in one hole: the platform can be holding an event — its condition, its incident, its
queued delivery — while the cursor still describes the round that happened **before** it. If the
producer then re-judges from that stale cursor, the event is not "retried", it is *recomputed*, and a
recomputed round is a different verdict: a source that became readable again compares clean against the
old healthy baseline, files nothing, and leaves the coverage incident open forever. A restart makes that
permanent, because the recomputed round is the only thing the new process knows.

So the round writes what it owes **before** it sends it: the exact event bytes, the window they were
judged inside, and the cursor this producer intended to install once they were accepted. A retry
delivers those bytes first, in that order, before a single fresh source read — the source is allowed to
have moved under the retry, and the bytes the platform was promised are not re-derived from it.

Every failure here is raised at the delivery seam with the **real** `Store` behind it, because the
defect is "intake committed, the response never arrived". A mocked intake cannot express that, and a
mocked one would accept anything the producer invented. The assertions read the platform back: incident
rows, the outbox order an operator's channel actually received, and the receipt statuses that say
whether the platform took a retry as `duplicate` or as a new incident.

Times, artifacts and configuration come from :mod:`test_config_drift`, including its aligned windows:
``LATER`` → ``12:00–12:05``, ``THIRD`` → ``12:05–12:10``, ``FOURTH`` → ``12:10–12:15``.
"""
import contextlib
import datetime as dt
import json
from pathlib import Path
import sqlite3
from unittest import mock

from local_observe.http import TransportError
from local_observe.platform import configdrift
from local_observe.platform.state import Store

from test_config_drift import (EDITED, FOURTH, LATER, ORIGINAL, PRODUCER, REPLACED, RESOURCE, RULE,
                               SOURCE, THIRD, Deliverer, Fixture, sha256, window)

SECOND_RULE = 'drift.router-startup'
SECOND_ARTIFACT = 'startup-config'
INTERVAL = 300


def aligned(instant: dt.datetime) -> dt.datetime:
    """Floor an injected round time onto the 300-second grid the producer aligns its windows to."""
    return dt.datetime.fromtimestamp(int(instant.timestamp()) // INTERVAL * INTERVAL, dt.timezone.utc)


class ReplayFixture(Fixture):
    """The shared scratch, plus the seams that lose an answer and the trace that shows what ran when."""

    def setUp(self) -> None:
        super().setUp()
        self.trace: list[str] = []
        self.original_read = configdrift.read_snapshot
        self.addCleanup(setattr, configdrift, 'read_snapshot', self.original_read)

    def patch_read(self, replacement) -> None:
        """Install *replacement* over the module's reader; the real one comes back on cleanup."""
        configdrift.read_snapshot = replacement

    def restore_reads(self) -> None:
        self.patch_read(self.original_read)

    def blind_source(self, *, reason: str = 'Synthetic mount failure') -> None:
        """Fail every source read, and trace the attempt: this is the round that opens a coverage event."""
        def read(root, resource_id, name):
            self.trace.append(f'read {resource_id}/{name}')
            raise OSError(reason)

        self.patch_read(read)

    def follow_reads(self) -> None:
        """Let the reader work, and trace every read so delivery order can be asserted."""
        real = self.original_read

        def read(root, resource_id, name):
            self.trace.append(f'read {resource_id}/{name}')
            return real(root, resource_id, name)

        self.patch_read(read)

    def restart(self) -> Store:
        """Open the platform database again: all a restart carries is what is on disk."""
        return Store(self.root / 'state.db')

    def reloaded_config(self, **overrides) -> dict:
        """Read the configuration document off disk again, the way a new process starts it."""
        return configdrift.load_config(self.write_json(self.document(**overrides)))

    def cursor_document(self) -> dict:
        """Read the raw cursor JSON, bypassing the reader under test."""
        return json.loads(Path(self.cursor).read_text(encoding='utf-8'))

    def write_cursor_document(self, document: dict) -> None:
        self.cursor.parent.mkdir(parents=True, exist_ok=True)
        self.cursor.write_text(json.dumps(document, sort_keys=True), encoding='utf-8', newline='')

    def deliveries(self) -> list[tuple[str, str]]:
        """Every queued notification, oldest first, as `(transition, incident_id)`.

        This is what an operator's channel received, and the read-back that matters: an incident that
        stayed open books no `resolved`, and a retry that speaks twice books two.
        """
        with contextlib.closing(sqlite3.connect(self.root / 'state.db')) as connection:
            rows = connection.execute('SELECT payload FROM outbox ORDER BY sequence').fetchall()
        return [(json.loads(row[0])['transition'], json.loads(row[0])['incident_id']) for row in rows]

    def incident_status(self, incident_id: str) -> str:
        with contextlib.closing(sqlite3.connect(self.root / 'state.db')) as connection:
            row = connection.execute('SELECT status FROM incidents WHERE id=?', (incident_id,)).fetchone()
        self.assertIsNotNone(row, 'the incident row the round opened is gone')
        return row[0]

    def owed(self) -> dict:
        """Return the pending batch of the current cursor, as the producer wrote it."""
        document = self.cursor_document()
        self.assertIn('pending', document, 'the round owed nothing after a failed delivery')
        return document['pending']


class Delivery:
    """The delivery seam `tick` is given, with the real intake and an acknowledgement that goes missing.

    ``fail_at`` is the 0-based index of the delivery that raises; ``commit`` says whether the platform
    saw the event first. ``commit=True`` is the lost acknowledgement — intake returned its receipt, the
    row is durable, and the producer was told nothing. ``commit=False`` is the ordinary refusal.
    """

    def __init__(self, store: Store, *, now: dt.datetime, trace: list[str] | None = None,
                 fail_at: int | None = None, commit: bool = True) -> None:
        self.store, self.now, self.trace = store, now, trace
        self.fail_at, self.commit = fail_at, commit
        self.events: list[dict] = []
        self.receipts: list[dict] = []

    def __call__(self, item: dict) -> None:
        if self.fail_at is not None and len(self.events) == self.fail_at:
            if self.commit:
                self.send(item)
            raise TransportError('Synthetic acknowledgement loss after committed intake' if self.commit
                                 else 'Synthetic intake refusal')
        self.send(item)

    def send(self, item: dict) -> None:
        self.events.append(dict(item))
        self.receipts.append(self.store.intake(item, PRODUCER, now=self.now))
        if self.trace is not None:
            self.trace.append(f'deliver {item["rule_id"]}/{item["status"]}')

    @property
    def statuses(self) -> list[str]:
        return [receipt['status'] for receipt in self.receipts]


class ReplayTests(ReplayFixture):
    """A lost acknowledgement is a retry with remembered bytes, never a round recomputed from disk."""

    def test_a_lost_acknowledgement_after_committed_intake_is_replayed_and_closes_the_incident(self):
        """The reproduction: blind round, lost ack, source back — and the coverage incident still closes.

        Checked in three parts, because all three have to hold: the batch and the intended next cursor
        are durably written before the send, the retry delivers **those bytes** before it reads the
        source again, and the recovery `resolved` event then reaches the real platform — whose incident
        row and outbox are read back afterwards.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()                                                   # baselined, healthy
        self.blind_source()
        lost = Delivery(self.store, now=LATER, trace=self.trace, fail_at=0, commit=True)
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.config(), self.cursor, lost, now=LATER, source=SOURCE)

        batch = self.owed()
        self.assertEqual(batch['events'], lost.events, 'the bytes owed are not the bytes it sent')
        self.assertEqual([(item['kind'], item['status']) for item in batch['events']],
                         [('coverage', 'firing')])
        self.assertEqual(batch['window'], window(aligned(LATER)))
        self.assertEqual(self.cursor_document()['seen'][f'{RESOURCE}/running-config'],
                         {'sha256': sha256(ORIGINAL), 'text': ORIGINAL, 'unreadable': False},
                         'the acknowledged baseline moved forward over a lost answer')
        self.assertEqual(batch['next']['seen'][f'{RESOURCE}/running-config'],
                         {'sha256': sha256(ORIGINAL), 'text': ORIGINAL, 'unreadable': True},
                         'the intended next cursor forgot the round could not see the artifact')
        incident_id = lost.receipts[0]['incident_id']
        self.assertEqual(self.deliveries(), [('opened', incident_id)])

        self.trace.clear()                                              # only the retry's order matters
        self.follow_reads()                                               # the mount is back
        summary, retry = self.run_tick(now=THIRD, deliverer=Delivery(self.restart(), now=THIRD,
                                                                     trace=self.trace))
        self.assertEqual(self.trace[:1], [f'deliver {RULE}.coverage/firing'],
                         'it read the source before replaying what it owed')
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(retry.statuses, ['duplicate', 'accepted'])
        self.assertEqual([(item['kind'], item['status']) for item in retry.events],
                         [('coverage', 'firing'), ('coverage', 'resolved')])
        self.assertEqual(retry.events[1]['window'], window(aligned(THIRD)))
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(self.incident_status(incident_id), 'resolved')
        self.assertEqual(self.deliveries(), [('opened', incident_id), ('resolved', incident_id)])
        self.assertEqual(self.restart().status()['incidents'], {'resolved': 1})
        self.assertNotIn('pending', self.cursor_document())
        self.assertEqual(self.remembered(), {'sha256': sha256(ORIGINAL), 'text': ORIGINAL,
                                             'unreadable': False})

    def test_pending_bytes_survive_a_source_that_moves_before_the_retry(self):
        """The pending event names the digest the producer actually saw, not the one on disk now.

        Rebuilding the batch from the retried round would report the *newest* bytes as if they had been
        judged in the old window, and the platform's condition watermark would be told a time at which
        nobody looked. Both events belong at the end: the promised one, then the new one on its own
        window with the promised digest as its previous.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        lost = Delivery(self.store, now=LATER, fail_at=0, commit=True)
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.config(), self.cursor, lost, now=LATER, source=SOURCE)
        promised = self.owed()['events'][0]
        self.assertEqual(promised['evidence'][0]['parameters']['artifact_sha256'], sha256(EDITED))

        self.write_artifact(REPLACED)                                     # someone else edited it
        summary, retry = self.run_tick(now=THIRD, deliverer=Delivery(self.restart(), now=THIRD))
        self.assertEqual(retry.events[0], promised, 'the owed bytes were reconstructed from the source')
        self.assertEqual(retry.statuses[0], 'duplicate')
        self.assertEqual([(item['evidence'][0]['parameters']['artifact_sha256'], item['window'])
                          for item in retry.events[1:]],
                         [(sha256(REPLACED), summary['window'])])
        self.assertEqual(summary['evaluations'][0]['previous_sha256'], sha256(EDITED),
                         'the retry lost the diff base the batch was judged against')
        self.assertEqual(summary['changed'], 1)
        self.assertEqual(self.remembered(), {'sha256': sha256(REPLACED), 'text': REPLACED,
                                             'unreadable': False})

    def test_a_retry_inside_the_window_it_owes_files_nothing_of_its_own(self):
        """One window, one verdict per condition: a second event with the same id is a refused round.

        `detections.event` derives ``source_event_id`` from rule, version, resource and window, so a retry
        that runs before the grid moves cannot also report the source that moved under it — intake would
        refuse that second event as `Event retry changed contents`, on every round, forever. Such a round
        replays and stops; the new bytes are judged in the next window like any other change.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.config(), self.cursor,
                             Delivery(self.store, now=LATER, fail_at=0, commit=True), now=LATER,
                             source=SOURCE)
        self.write_artifact(REPLACED)                                     # moved inside the same window
        summary, quiet = self.run_tick(now=LATER, deliverer=Delivery(self.restart(), now=LATER))
        self.assertEqual(quiet.statuses, ['duplicate'])
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(summary['events'], quiet.events)
        self.assertEqual(summary['evaluations'], [], 'it re-judged the tree inside the window it owed')
        self.assertNotIn('pending', self.cursor_document())
        self.assertEqual(self.remembered()['sha256'], sha256(EDITED), 'the replayed baseline was not set')

        summary, later = self.run_tick(now=THIRD, deliverer=Delivery(self.restart(), now=THIRD))
        self.assertEqual([item['evidence'][0]['parameters']['artifact_sha256'] for item in later.events],
                         [sha256(REPLACED)])
        self.assertEqual(summary['evaluations'][0]['previous_sha256'], sha256(EDITED))
        self.assertEqual(summary['window'], window(aligned(THIRD)))
        self.assertEqual(summary['result'], 'delivered')

    def test_a_failure_on_the_second_event_keeps_the_whole_batch(self):
        """A half-delivered round is not half-remembered: the accepted event is owed too.

        Keeping only the refused event would be the cheaper design and wrong twice over. The cursor
        cannot advance to the accepted one without also claiming the refused one, and re-sending the
        accepted one is what proves the platform folds it — `duplicate`, one incident, one delivery.
        """
        config = self.config(resources=[{'resource_id': RESOURCE, 'name': 'running-config',
                                         'rule_id': RULE},
                                        {'resource_id': RESOURCE, 'name': SECOND_ARTIFACT,
                                         'rule_id': SECOND_RULE}])
        self.write_artifact(ORIGINAL)
        self.write_artifact(ORIGINAL, name=SECOND_ARTIFACT)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        self.write_artifact(EDITED, name=SECOND_ARTIFACT)
        partial = Delivery(self.store, now=LATER, fail_at=1, commit=False)
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, config, self.cursor, partial, now=LATER, source=SOURCE)

        batch = self.owed()
        self.assertEqual([item['rule_id'] for item in batch['events']], [RULE, SECOND_RULE])
        self.assertEqual([item['evidence'][0]['parameters']['artifact_sha256']
                          for item in batch['events']], [sha256(EDITED), sha256(EDITED)])
        for key in (f'{RESOURCE}/running-config', f'{RESOURCE}/{SECOND_ARTIFACT}'):
            self.assertEqual(self.cursor_document()['seen'][key]['sha256'], sha256(ORIGINAL),
                             'the refused half of the round advanced the baseline it never delivered')
            self.assertFalse(self.cursor_document()['seen'][key]['unreadable'])

        summary, retry = self.run_tick(now=THIRD, config=config,
                                       deliverer=Delivery(self.restart(), now=THIRD))
        self.assertEqual(retry.statuses, ['duplicate', 'accepted'])
        self.assertEqual(summary['replayed'], 2)
        self.assertEqual([receipt.get('transition') for receipt in retry.receipts], [None, 'opened'])
        # Two artifacts, two conditions, two incidents: the accepted half of the failed round opened its
        # own and the replay booked no second delivery for it.
        opened, second = retry.receipts[0]['incident_id'], retry.receipts[1]['incident_id']
        self.assertEqual(self.deliveries(), [('opened', opened), ('opened', second)])
        self.assertNotEqual(opened, second)
        self.assertEqual({key: entry['sha256'] for key, entry in self.cursor_document()['seen'].items()},
                         {f'{RESOURCE}/running-config': sha256(EDITED),
                          f'{RESOURCE}/{SECOND_ARTIFACT}': sha256(EDITED)})

    def test_a_failure_writing_the_final_cursor_leaves_the_batch_owed_for_the_next_round(self):
        """Durability has two ends: an accepted batch is only spent once the cursor says it was.

        If the write that clears the batch fails after the platform accepted everything, the producer
        must still believe it owes the batch. The next round re-sends it, the platform answers
        `duplicate`, and the cursor is written again — the only way this ends with both sides agreeing.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        writes: list[dict] = []

        def flaky(path, value):
            writes.append(dict(value))
            if 'pending' in value:
                real(path, value)
            else:
                raise OSError('Synthetic failure clearing the batch')

        real = configdrift.save_cursor
        with mock.patch.object(configdrift, 'save_cursor', flaky):
            with self.assertRaises(OSError):
                self.run_tick(now=LATER, deliverer=Delivery(self.store, now=LATER))
        self.assertEqual(len(writes), 2, 'the batch was not written before the send')
        self.assertIn('pending', self.cursor_document(), 'the batch did not survive the failed round')
        self.assertEqual(len(self.owed()['events']), 1)

        summary, retry = self.run_tick(now=THIRD, deliverer=Delivery(self.restart(), now=THIRD))
        self.assertEqual(retry.statuses, ['duplicate'])
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(summary['events'], retry.events, 'a replay is not counted as a delivery')
        self.assertEqual(summary['result'], 'delivered')
        self.assertNotIn('pending', self.cursor_document())
        self.assertEqual(self.remembered()['sha256'], sha256(EDITED))
        self.assertEqual([transition for transition, _ in self.deliveries()], ['opened'])

    def test_a_new_process_replays_the_owed_batch_before_it_looks_at_the_source(self):
        """One round loses the answer, the next process delivers it: nothing survived in memory.

        `tick` holds no state between rounds — `main`'s loop hands it the same paths every time — so a
        restart is exactly this: the configuration re-read off disk, the platform database reopened,
        and the cursor file as the only thing the new round can work from. The source is readable
        again, which is the case that used to file nothing at all.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.blind_source()
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.reloaded_config(), self.cursor,
                             Delivery(self.store, now=LATER, fail_at=0, commit=True), now=LATER,
                             source=SOURCE)
        owed_bytes = self.owed()['events'][0]

        self.trace.clear()
        self.follow_reads()
        reopened = self.restart()
        deliverer = Delivery(reopened, now=THIRD, trace=self.trace)
        summary = configdrift.tick(self.index, self.reloaded_config(), self.cursor, deliverer,
                                   now=THIRD, source=SOURCE)
        self.assertEqual(self.trace[:1], [f'deliver {RULE}.coverage/firing'])
        self.assertEqual(deliverer.events[0], owed_bytes)
        self.assertEqual(deliverer.statuses, ['duplicate', 'accepted'])
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(summary['result'], 'delivered')
        self.assertEqual(reopened.status()['incidents'], {'resolved': 1})

    def test_a_round_that_owes_and_is_still_blind_reports_unreadable_and_loses_nothing(self):
        """Recovering a batch does not spend the round's own blindness, and blindness does not drop it."""
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.blind_source()
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.config(), self.cursor,
                             Delivery(self.store, now=LATER, fail_at=0, commit=True), now=LATER,
                             source=SOURCE)
        self.blind_source(reason='Synthetic mount still absent')
        summary, retry = self.run_tick(now=THIRD, deliverer=Delivery(self.restart(), now=THIRD))
        self.assertEqual(summary['result'], 'unreadable')
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(summary['unreadable'], 1)
        self.assertEqual(retry.statuses, ['duplicate'], 'the replay was not counted as a delivery')
        self.assertNotIn('pending', self.cursor_document())
        self.assertTrue(self.remembered()['unreadable'])

        self.restore_reads()                                              # the mount is back for good
        summary, closed = self.run_tick(now=FOURTH, deliverer=Delivery(self.restart(), now=FOURTH))
        self.assertEqual([(item['kind'], item['status']) for item in closed.events],
                         [('coverage', 'resolved')])
        self.assertEqual(closed.receipts[0]['transition'], 'resolved')
        self.assertEqual(summary['result'], 'delivered')

    def test_a_lost_acknowledgement_of_a_resolve_does_not_speak_twice_after_the_replay(self):
        """The spent-acknowledgement marker rides in the intended next cursor, or the close repeats.

        A replayed resolve is a `duplicate`; a *recomputed* one is a fresh event on a fresh window, and
        the platform is left holding a second statement about an incident it already closed.
        """
        ack_root = self.root / 'acks'
        config = self.config(acknowledgements=str(ack_root))
        self.write_artifact(ORIGINAL)
        self.run_tick(config=config)
        self.write_artifact(EDITED)
        opened = Delivery(self.store, now=LATER)
        configdrift.tick(self.index, config, self.cursor, opened, now=LATER, source=SOURCE)
        incident_id = opened.receipts[0]['incident_id']
        record = configdrift.validate_acknowledgement({
            'schema_version': 1, 'resource_id': RESOURCE, 'name': 'running-config', 'rule_id': RULE,
            'artifact_sha256': sha256(EDITED), 'actor': 'operator-one',
            'reason': 'checked against the change ticket', 'at': '2026-08-05T12:07:00.000000+00:00'})
        path = configdrift.acknowledgement_path(ack_root, RESOURCE, 'running-config')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record, sort_keys=True), encoding='utf-8', newline='')

        with self.assertRaises(TransportError):
            configdrift.tick(self.index, config, self.cursor,
                             Delivery(self.store, now=THIRD, fail_at=0, commit=True), now=THIRD,
                             source=SOURCE)
        self.assertEqual(self.owed()['next']['seen'][f'{RESOURCE}/running-config']['ack_applied'],
                         configdrift.digest(record))

        summary, quiet = self.run_tick(now=FOURTH, config=config,
                                       deliverer=Delivery(self.restart(), now=FOURTH))
        self.assertEqual(quiet.statuses, ['duplicate'])
        self.assertEqual(len(quiet.events), 1, 'a spent acknowledgement resolved the condition again')
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(summary['acknowledged'], 0)
        self.assertEqual(summary['evaluations'][0]['ack'], 'already')
        self.assertEqual(self.deliveries(), [('opened', incident_id), ('resolved', incident_id)])
        self.assertEqual(self.incident_status(incident_id), 'resolved')

    def test_the_worker_loop_replays_the_batch_the_failed_round_left_behind(self):
        """`main` treats a lost acknowledgement as a round to retry, and the retry is the same bytes.

        The clock is the real one, because `main` owns it. What is pinned is the part that does not
        depend on the clock: the second process sends the batch it owes — and only that, because the
        source never moved — and the platform still holds one event row and one open incident.
        """
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_artifact(EDITED)
        posted: list[dict] = []
        stores: list[Store] = []
        trace = self.trace
        database = self.root / 'state.db'

        class Platform:
            """A fresh store per process, so a committed row is only visible through the database."""

            def __init__(self, base: str, token: str, *, allow_http: bool = False) -> None:
                stores.append(Store(database))

            def request(self, method: str, path: str, payload: dict) -> tuple[int, dict]:
                posted.append(dict(payload))
                trace.append(f'deliver {payload["kind"]}')
                if len(stores) == 1:
                    stores[-1].intake(payload, PRODUCER)
                    raise TransportError('Synthetic acknowledgement loss after committed intake')
                return 200, stores[-1].intake(payload, PRODUCER)

        environment = {configdrift.CONFIG_ENVIRONMENT: str(self.write_json(self.document())),
                       configdrift.SOURCE_ENVIRONMENT: SOURCE, 'LO_INDEX_PATH': str(self.index),
                       'LO_PLATFORM_URL': 'https://platform.invalid',
                       'LO_PRODUCER_TOKEN': 'a-producer-token-of-at-least-twenty-four-characters'}
        with mock.patch.dict('os.environ', environment, clear=True), \
                mock.patch.object(configdrift, 'JsonClient', Platform), \
                mock.patch.object(configdrift.time, 'sleep', side_effect=StopIteration), \
                self.assertLogs('local_observe.platform.configdrift', 'WARNING') as failed:
            with self.assertRaises(StopIteration):
                configdrift.main()                                        # process one
        self.assertEqual([item['kind'] for item in posted], ['drift'])
        self.assertEqual(len(self.owed()['events']), 1)
        self.assertIn('cursor not advanced', ' '.join(record.getMessage()
                                                     for record in failed.records).lower())

        posted.clear()
        self.trace.clear()
        self.follow_reads()
        with mock.patch.dict('os.environ', environment, clear=True), \
                mock.patch.object(configdrift, 'JsonClient', Platform), \
                mock.patch.object(configdrift.time, 'sleep', side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                configdrift.main()                                        # process two
        self.assertEqual(self.trace[:1], ['deliver drift'], 'it looked at the tree before it retried')
        self.assertEqual(len(posted), 1, 'the replay also filed a fresh verdict')
        self.assertEqual(posted[0]['evidence'][0]['parameters']['artifact_sha256'], sha256(EDITED))
        self.assertEqual(len(self.stored_events(self.root / 'state.db')), 1,
                         'the retry opened a second event row instead of folding into the first')
        self.assertEqual(stores[1].status()['incidents'], {'open': 1})
        self.assertNotIn('pending', self.cursor_document())


class PendingValidationTests(ReplayFixture):
    """A hand-edited or half-written batch is refused on the way in, before anything is sent."""

    def setUp(self) -> None:
        super().setUp()
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.blind_source()
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.config(), self.cursor,
                             Delivery(self.store, now=LATER, fail_at=0, commit=True), now=LATER,
                             source=SOURCE)
        self.restore_reads()
        self.valid = self.cursor_document()

    def edit(self, **changes) -> dict:
        """Return the real cursor with *changes* applied to its pending batch (``_REMOVE`` drops a key)."""
        document = json.loads(json.dumps(self.valid))
        for key, value in changes.items():
            if value is _REMOVE:
                document['pending'].pop(key)
            else:
                document['pending'][key] = value
        return document

    def refuse(self, document: dict) -> None:
        """A cursor this producer cannot trust must raise out of the reader and out of the round."""
        self.write_cursor_document(document)
        with self.assertRaises(ValueError):
            configdrift.load_cursor(self.cursor, self.config())
        self.trace.clear()
        self.blind_source(reason='the source must not be opened for a batch that cannot be trusted')
        deliverer = Deliverer(self.store, now=THIRD)
        with self.assertRaises(ValueError):
            configdrift.tick(self.index, self.config(), self.cursor, deliverer, now=THIRD,
                             source=SOURCE)
        self.assertEqual(deliverer.events, [], 'it sent an event out of a batch it could not trust')
        self.assertEqual(self.trace, [], 'it read the tree before it trusted the batch')

    def test_a_batch_that_is_not_a_batch_is_refused(self) -> None:
        """Every refusal is checked twice: the reader will not return it, and the round will not send it."""
        events = self.valid['pending']['events']
        batch_window = self.valid['pending']['window']
        next_cursor = self.valid['pending']['next']
        key = f'{RESOURCE}/running-config'
        other_window = {'start': '2030-01-01T00:00:00.000000+00:00',
                        'end': '2030-01-02T00:00:00.000000+00:00'}

        def event_with(**changes) -> dict:
            return dict(events[0], **changes)

        def next_with(seen: object = next_cursor['seen'], **changes) -> dict:
            document = dict(next_cursor, seen=seen)
            document.update(changes)
            return self.edit(next=document)

        broken: list = [
            ('a batch with no window', self.edit(window=_REMOVE)),
            ('a batch with a key nobody gave it', self.edit(extra=1)),
            ('a batch with no events', self.edit(events=_REMOVE)),
            ('a batch with no next cursor', self.edit(next=_REMOVE)),
            ('a batch belonging to another configuration', self.edit(binding='f' * 64)),
            ('a batch holding no events at all', self.edit(events=[])),
            ('a batch whose events are not a list', self.edit(events='not-a-list')),
            ('a batch larger than one round could ever owe',
             self.edit(events=events * (configdrift.MAX_PENDING_EVENTS + 1))),
            ('a batch whose window is not a window', self.edit(window={'start': 'nope'})),
            ('a batch whose window ends before it starts',
             self.edit(window={'start': batch_window['end'], 'end': batch_window['start']})),
            ('a batch holding an event judged in another window',
             self.edit(events=[event_with(window=other_window)])),
            ('a batch holding an event that is not canonical',
             self.edit(events=[{name: value for name, value in events[0].items()
                                if name != 'severity'}])),
            ('a batch holding a kind the platform does not admit',
             self.edit(events=[event_with(kind='config')])),
            ('a batch holding an event with an unapproved evidence parameter',
             self.edit(events=[event_with(evidence=[dict(events[0]['evidence'][0],
                                                         parameters={'diff': 'hostname router-01'})])])),
            ('a batch holding an event whose identity was not derived from its own contents',
             self.edit(events=[event_with(source_event_id='0' * 64)])),
            ('a batch whose next cursor came from another producer', next_with(schema_version=2)),
            ('a batch whose next cursor belongs to another tree', next_with(binding='e' * 64)),
            ('a batch whose next cursor holds an unknown key', next_with(extra=1)),
            ('a batch whose next cursor holds no seen map', next_with(seen=None)),
            ('a batch whose next cursor holds a digest that is not a digest',
             next_with(seen={key: {'sha256': 'nope', 'text': ORIGINAL, 'unreadable': False}})),
            ('a batch whose next cursor holds a readable entry with no digest behind it',
             next_with(seen={key: {'sha256': None, 'text': ORIGINAL, 'unreadable': False}})),
            ('a batch whose next cursor holds more text than the read ceiling allows',
             next_with(seen={key: {'sha256': sha256(ORIGINAL), 'text': 'x' * 100_000,
                                   'unreadable': False}})),
        ]
        for reason, document in broken:
            with self.subTest(reason=reason):
                self.refuse(document)

    def test_a_batch_key_that_is_null_is_nothing_owed_and_not_a_refusal(self):
        """``pending: null`` answers the same as an absent key, the way `conditions` reads its cursor.

        An operator who nulled the key threw the retry away: the batch the platform had already accepted
        is not re-derived from the source, so the round says nothing and the coverage incident it opened
        stays open. That is the honest consequence of deleting the retry, and the producer states it by
        behaving exactly like the round that never owed anything.
        """
        document = json.loads(json.dumps(self.valid))
        document['pending'] = None
        self.write_cursor_document(document)
        self.assertEqual(configdrift.load_cursor(self.cursor, self.config()), document)

        summary, deliverer = self.run_tick(now=THIRD)
        self.assertEqual(summary['replayed'], 0)
        self.assertEqual(deliverer.events, [])
        self.assertEqual(summary['result'], 'idle')
        self.assertEqual(self.restart().status()['incidents'], {'open': 1})

    def test_a_batch_that_is_legitimate_is_accepted_and_replayed(self):
        self.blind_source()                                               # still owed, still blind
        summary, deliverer = self.run_tick(now=THIRD, deliverer=Delivery(self.restart(), now=THIRD))
        self.assertEqual(summary['replayed'], 1)
        self.assertEqual(deliverer.events, self.valid['pending']['events'])


class CursorCompatibilityTests(ReplayFixture):
    """The batch is an added key, so an existing cursor loads unchanged and a healthy one is stable."""

    def test_a_cursor_written_before_the_batch_loads_unchanged(self) -> None:
        """The pre-batch three-key document — with or without an acknowledgement marker — is still a cursor.

        `load_cursor` answers the document it read, key for key: no `pending` is invented on the way
        out, so a producer that never owed anything sees exactly what it saw before this key existed.
        """
        binding = configdrift.cursor_binding(self.config())
        baseline = {'schema_version': 1, 'binding': binding, 'seen': {
            f'{RESOURCE}/running-config': {'sha256': sha256(ORIGINAL), 'text': ORIGINAL,
                                           'unreadable': False}}}
        legacy = [
            ('a plain baseline', baseline),
            ('a spent acknowledgement', {'schema_version': 1, 'binding': binding, 'seen': {
                f'{RESOURCE}/running-config': {'sha256': sha256(ORIGINAL), 'text': ORIGINAL,
                                               'unreadable': False, 'ack_applied': 'a' * 64}}}),
            ('an artifact it could not read', {'schema_version': 1, 'binding': binding, 'seen': {
                f'{RESOURCE}/running-config': {'sha256': None, 'text': None, 'unreadable': True}}}),
            ('a tree it has never seen', {'schema_version': 1, 'binding': binding, 'seen': {}}),
        ]
        for reason, document in legacy:
            with self.subTest(reason=reason):
                self.write_cursor_document(document)
                self.assertEqual(configdrift.load_cursor(self.cursor, self.config()), document)
                self.assertNotIn('pending', configdrift.load_cursor(self.cursor, self.config()))

        self.write_artifact(ORIGINAL)                                     # the tree the cursor describes
        self.write_cursor_document(baseline)
        summary, deliverer = self.run_tick(now=LATER)
        self.assertEqual(deliverer.events, [])
        self.assertEqual(summary['replayed'], 0)
        self.assertEqual(summary['result'], 'idle')

    def test_a_healthy_round_writes_no_batch_key_at_all(self):
        """A completed round owes no batch, but retains its watermark across restarts."""
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.assertEqual(set(self.cursor_document()), {'schema_version', 'binding', 'seen', 'settled_end'})
        self.write_artifact(EDITED)
        self.run_tick(now=LATER)
        self.assertEqual(set(self.cursor_document()), {'schema_version', 'binding', 'seen', 'settled_end'})

    def test_a_word_the_producer_never_wrote_is_still_refused(self):
        """The document stays closed: `pending` is the only addition, and unknown keys still refuse."""
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.write_cursor_document(dict(self.cursor_document(), owed_forever='everything'))
        with self.assertRaises(ValueError):
            configdrift.load_cursor(self.cursor, self.config())

    def test_a_binding_change_refuses_the_round_rather_than_dropping_an_owed_batch(self):
        """Re-baselining away a batch is how a drift monitor quietly forgets an open incident."""
        self.write_artifact(ORIGINAL)
        self.run_tick()
        self.blind_source()
        with self.assertRaises(TransportError):
            configdrift.tick(self.index, self.config(), self.cursor,
                             Delivery(self.store, now=LATER, fail_at=0, commit=True), now=LATER,
                             source=SOURCE)
        other = self.config(root=str(self.root / 'second-tree'))
        deliverer = Deliverer(self.store, now=THIRD)
        with self.assertRaises(ValueError):
            configdrift.tick(self.index, other, self.cursor, deliverer, now=THIRD, source=SOURCE)
        self.assertEqual(deliverer.events, [])
        self.assertIn('pending', self.cursor_document(), 'the owed batch was rewritten for a new tree')


_REMOVE = object()

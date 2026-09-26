"""The inventory observer: the SLO worker loop replays the saved batch instead of grading a fresh one over it.

`local_observe/slo/__main__.py` loops, and `alerts.tick` writes a round's undelivered events to the
producer's cursor **before** it POSTs any of them. The loop used to load that cursor once, at start-up,
and hand the same document to every round: after a refused delivery the file held the batch while the
in-memory `state` still said `pending: None`, so the next round found nothing owed, queried the store
again, re-graded the window and saved its freshly-derived events over the bytes still owed. A re-graded
window is not a duplicate — another `source_event_id`, another `sample_id`, a shorter `expires_at` — so
the platform's dedup cannot fold what the overwrite cost, and the window the platform never accepted is
gone. `tests/test_slo_burn.py::TickTests` reloads the cursor through `alerts.cursor_document` every
round and so cannot see that loop at all; this file drives `main()` itself.

Every claim here is about real worker iterations:

* **HTTP 503 then success.** Round one POSTs one event, is refused, and leaves its whole batch in the
  cursor with the window unmoved; round two replays those bytes and only then advances.
* **Nothing is read or graded while a batch is owed.** The store is even seeded with a *healthy* series
  during the outage: the replayed events are still the burning ones round one wrote, and the store was
  never asked again. That is the defect's own shape — an overwritten batch would carry a recovery.
* **An accepted POST whose acknowledgement was lost** goes out again byte-for-byte, which is what makes
  `events UNIQUE (source, source_event_id)` fold the retry into the row it already has.
* **A multi-event batch that failed partway** is replayed whole, the already-accepted prefix included.
* **Idle, success, restart**: a window delivered at one grid position is not judged twice at it — in
  this process or after a restart of it — and the next window is still judged afterwards, so the
  durability is not a producer that simply stopped talking.
* **A cursor that is unreadable, of a foreign version, holding a hand-edited batch, or bound to another
  rule set** is refused read-only: one `WARNING` naming the exception class, no POST, no store read, and
  the bytes exactly as found — mid-run for the first three, across a restart for the last.

Only two boundaries are mocked: the platform's `POST /v1/events` client and the start-up reads
(`read_credential`, `store_reader`). The round is the real `alerts.tick` over a real built inventory
index, the real in-memory store backend, `exclusive_owner` and a real cursor file in a temporary
directory. The clock and the sleep are the worker module's own two names, replaced on that module only:
`main` has no `now` argument, so an injected `dt`/`time` pair is what lets two iterations land on two
different 300-second windows without wall time, and the loop is ended by a `StopLoop` raised from the
injected sleep — a `RuntimeError`, which no handler in `main` catches, so it unwinds the ownership lock
instead of being swallowed as a failed round. Nothing here sends anything, opens a socket, names a host
or runs a suite; every result below is a claim for the reviewer's `OK`, not a claim of one.
"""
import contextlib
import copy
import datetime as dt
import json
import logging
from pathlib import Path
import tempfile
import types
import unittest
from collections.abc import Callable, Iterable, Sequence
from typing import Any
from unittest import mock

from local_observe.http import TransportError
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, utc_text
from local_observe.slo import __main__ as worker
from local_observe.slo import alerts
from local_observe.store.backends.memory import InMemoryStore, series
from local_observe.store.client import ReadOutcome, Window

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 9, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
SOURCE = 'lo-slo'
METRIC = 'demo-availability'
INTERVAL = 300
OBJECTIVE_IDS = ('api.availability', 'search.availability')
#: One round over this rule set spends one store read and two events (coverage + condition) per objective.
READS_PER_ROUND = len(OBJECTIVE_IDS)
EVENTS_PER_ROUND = 2 * READS_PER_ROUND


class StopLoop(RuntimeError):
    """Raised by the injected sleep to end `main`'s `while True`.

    Deliberately a `RuntimeError`: `main` catches `OSError`/`ValueError`/`KeyError`/`TypeError`/
    `sqlite3.Error` every round, and a sentinel one of those could swallow would end the test with a
    silently shorter run instead of a stopped loop.
    """


def wire(value: Any) -> str:
    """The one canonical JSON text a payload is: what it is on the wire and what it is saved as."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def objective(objective_id: str) -> dict:
    """One burning objective: 90 % over a day, the 15-minute/5-minute pair at 5x, held for 5 minutes.

    The shape `tests/test_slo_burn.py`'s `condition()` fixture carries, spelled as an operator document
    so the worker parses it the way the service does. Two of these exist in every round, which is what
    makes a pending batch a **multi-event** batch: a failure partway through it is the case the replay
    has to survive.
    """
    return {'objective_id': objective_id, 'resource_id': None, 'signal': 'availability', 'target': 0.9,
            'window_days': 1, 'long_window': 900, 'short_window': 300, 'burn_threshold': 5.0,
            'metric': METRIC, 'min_samples': 1, 'severity_source': 'core-events-v1',
            'severity_tier': 'warning', 'evaluation_seconds': 300, 'for_seconds': 300,
            'max_age_seconds': 900}


class Clock:
    """The `dt` and `time` names the worker sees, so rounds advance on the test's grid and then stop.

    `main` reads the clock once per round and sleeps once between rounds; replacing those two attributes
    on the worker module is the smallest seam that drives two or more real iterations without wall time.
    Each sleep runs the test's hook (which is how a test inspects the durable cursor **between** rounds,
    the only moment it can), moves the injected instant by one interval unless told to hold it (the idle
    case), and raises `StopLoop` when the requested number of rounds has been driven.
    """

    def __init__(self, *, start: dt.datetime = NOW, rounds: int = 2, advance: bool = True,
                 hook: Callable[[int], None] | None = None) -> None:
        """Fix the instant the first round is driven at, how many rounds to drive, and what to do between."""
        self.instant = start
        self.rounds = rounds
        self.advance = advance
        self.hook = hook
        self.sleeps = 0
        self.datetime = types.SimpleNamespace(datetime=types.SimpleNamespace(now=self.now), timezone=dt.timezone)
        self.time = types.SimpleNamespace(sleep=self.sleep)

    def now(self, tz: dt.tzinfo | None = None) -> dt.datetime:
        """Answer the injected instant; `main` passes a timezone and the instant is already UTC."""
        return self.instant

    def sleep(self, seconds: int) -> None:
        """End one round: observe, step the grid, and stop the loop when the rounds are spent."""
        self.sleeps += 1
        if self.hook is not None:
            self.hook(self.sleeps)
        if self.advance:
            self.instant = self.instant + dt.timedelta(seconds=INTERVAL)
        if self.sleeps >= self.rounds:
            raise StopLoop(f'SLO worker loop driven for {self.sleeps} rounds')


class Intake:
    """The mocked ``POST /v1/events`` door: it keeps every body it was handed and answers from a script.

    Each scripted answer is an HTTP status or an exception to raise, because to this producer a refusal
    and a lost acknowledgement are the same thing — the batch stays pending — and only this recorder can
    tell them apart. Once the script is spent the door accepts, so a test scripts only what it refuses.
    `JsonClient` itself is what gets replaced, so no request here can reach a transport.
    """

    def __init__(self, answers: Sequence[Any] = ()) -> None:
        """Take the per-request script (statuses and exceptions, in order)."""
        self.bodies: list[dict] = []
        self.script: list = list(answers)

    def request(self, method: str, path: str, payload: dict) -> tuple[int, dict]:
        """Record one canonical event verbatim and answer it with the scripted status or failure."""
        if (method, path) != ('POST', '/v1/events'):
            raise AssertionError(f'the SLO worker asked for a route it does not post: {method} {path}')
        self.bodies.append(copy.deepcopy(payload))
        if self.script:
            answer = self.script.pop(0)
            if isinstance(answer, BaseException):
                raise answer
            return answer, {'status': 'unavailable'}
        return 200, {'accepted': True}


class CountingStore(InMemoryStore):
    """The real in-memory backend with one extra number: how many reads a round spent.

    "No metric re-query while a batch is pending" is a statement about the store being asked, so the
    counter lives on the store and every assertion below reads it. Nothing is faked about what an answer
    contains: the facade, its window rules and its truncation are `InMemoryStore`'s own.
    """

    def __init__(self, rows: Iterable[Any]) -> None:
        """Seed the backend and start the read counter at zero."""
        super().__init__(rows)
        self.reads = 0

    def read(self, query_type: str, *, window: Window, parameters: dict[str, str],
             selectors: dict[str, str] | None = None, **kwargs: Any) -> ReadOutcome:
        """Count the read, then answer it exactly as the backend would."""
        self.reads += 1
        return super().read(query_type, window=window, parameters=parameters, selectors=selectors,
                            **kwargs)


class WorkerReplayTests(unittest.TestCase):
    """`main()` driven round by round, with a real cursor file and a real ownership lock."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml')
        self.host = declared['resources'][0]['id']
        self.index_path = self.root / 'inventory.db'
        index.build(declared, self.index_path, 'fixture', now=NOW)
        self.cursor_path = self.root / 'slo-cursor.json'
        self.config_path = self.root / 'slo.yaml'
        document = {'objectives': [dict(objective(name), resource_id=self.host)
                                   for name in OBJECTIVE_IDS], 'interval_seconds': INTERVAL}
        self.config_path.write_text(json.dumps(document), encoding='utf-8')
        # Failed availability checks from an hour before `NOW` to half an hour after it, so every round
        # this file drives is a burning objective at its own instant and `max_age_seconds` is satisfied:
        # the newest sample behind a judged window is always 60 seconds old, never a stale one.
        self.reader = CountingStore(series(90, name=METRIC, resource_id=self.host,
                                           start=utc_text(NOW - dt.timedelta(seconds=3600)),
                                           step_seconds=60, value=0.0))
        self.intake = Intake()
        self.observations: list[dict] = []

    def environment(self) -> dict:
        """The worker's own environment: a named document, an identity, a cursor path, an index."""
        return {alerts.CONFIG_ENVIRONMENT: str(self.config_path), alerts.SOURCE_ENVIRONMENT: SOURCE,
                alerts.CURSOR_ENVIRONMENT: str(self.cursor_path), 'LO_INDEX_PATH': str(self.index_path),
                'LO_PLATFORM_URL': 'https://platform.invalid'}

    def run_worker(self, *, clock: Clock, answers: Sequence[Any] = ()) -> int | None:
        """Drive the real loop, replacing only the platform client and the two start-up reads.

        Returns `main()`'s exit code, or None when the injected sleep ended the loop. The cursor file,
        the index, the store, `alerts.tick` and `exclusive_owner` are the production objects; the clock
        and the sleep are attributes of the worker module and are restored on the way out.
        """
        self.intake = Intake(answers)
        with contextlib.ExitStack() as stack:
            for target, value in (('JsonClient', lambda *args, **kwargs: self.intake),
                                  ('read_credential', lambda *args, **kwargs: 'a-producer-token'),
                                  ('store_reader', lambda *args, **kwargs: self.reader),
                                  ('dt', clock.datetime), ('time', clock.time)):
                stack.enter_context(mock.patch.object(worker, target, value))
            stack.enter_context(mock.patch.dict('os.environ', self.environment(), clear=True))
            try:
                return worker.main()
            except StopLoop:
                return None

    def observe(self, round_number: int) -> None:
        """Snapshot what one round left on disk, taken from inside the sleep between rounds."""
        raw = self.cursor_path.read_bytes() if self.cursor_path.exists() else b''
        try:
            document = json.loads(raw) if raw else None
        except ValueError:
            document = None      # a deliberately broken cursor: the raw bytes are the assertion
        self.observations.append({'round': round_number, 'raw': raw, 'cursor': document,
                                  'posts': len(self.intake.bodies), 'reads': self.reader.reads})

    def results(self, records: list[logging.LogRecord]) -> list[str]:
        """The per-round `INFO` words, in order — the round line's own `result` field."""
        return [record.result for record in records if record.getMessage() == 'SLO tick finished']

    def warnings(self, records: list[logging.LogRecord]) -> list[str]:
        """The exception classes the worker's `WARNING` lines named, in order."""
        return [record.error_class for record in records if record.levelname == 'WARNING']

    def test_a_refused_intake_replays_the_saved_batch_before_the_store_is_asked_again(self):
        """503 then success: the owed bytes go out first, and only then does the window move."""
        clock = Clock(rounds=3, hook=self.observe)
        with self.assertLogs('local_observe.slo.__main__', 'INFO') as captured:
            self.run_worker(clock=clock, answers=[503])
        refused, replayed, fresh = self.observations

        self.assertEqual(refused['posts'], 1, 'the round died on its first refused POST')
        self.assertEqual(refused['reads'], READS_PER_ROUND)
        self.assertEqual(refused['cursor']['pending']['end'], utc_text(NOW))
        self.assertEqual(len(refused['cursor']['pending']['events']), EVENTS_PER_ROUND)
        self.assertIsNone(refused['cursor']['last_end'], 'a refused round does not advance the window')

        owed = refused['cursor']['pending']['events']
        self.assertEqual([wire(item) for item in self.intake.bodies[1:1 + EVENTS_PER_ROUND]],
                         [wire(item) for item in owed],
                         'the exact saved bytes go out again, in the order they were saved')
        self.assertEqual(wire(self.intake.bodies[0]), wire(owed[0]),
                         'the refused attempt and the replayed event are one and the same event')
        self.assertEqual(len({item['source_event_id'] for item in self.intake.bodies[:1 + EVENTS_PER_ROUND]}),
                         EVENTS_PER_ROUND, 'four events, four identities; nothing was duplicated by replay')
        self.assertEqual(replayed['reads'], READS_PER_ROUND,
                         'the replay asked the store for nothing: no fresh read, so nothing to re-grade')
        self.assertEqual(replayed['posts'], 1 + EVENTS_PER_ROUND)
        self.assertIsNone(replayed['cursor']['pending'])
        self.assertEqual(replayed['cursor']['last_end'], utc_text(NOW),
                         'the window advances only once every saved byte was accepted')

        # The positive control: durability is not a producer that stopped talking. One grid step later a
        # fresh window is read, judged and delivered on its own bytes.
        self.assertEqual(fresh['reads'], 2 * READS_PER_ROUND)
        self.assertEqual(fresh['cursor']['last_end'], utc_text(NOW + dt.timedelta(seconds=2 * INTERVAL)))
        next_window = self.intake.bodies[1 + EVENTS_PER_ROUND]
        self.assertEqual(next_window['window']['end'],
                         utc_text(NOW + dt.timedelta(seconds=2 * INTERVAL)))
        self.assertNotIn(next_window['source_event_id'], {item['source_event_id'] for item in owed})
        self.assertEqual(self.results(captured.records), ['replayed', 'delivered'])
        self.assertEqual(self.warnings(captured.records), ['TransportError'])

    def test_an_accepted_event_whose_acknowledgement_was_lost_goes_out_again_byte_identically(self):
        """Four bytes owed, two accepted, the third never answered: the replay sends all four again.

        The accepted prefix is re-sent unchanged and that is the whole point — the platform folds the
        identical re-send into the row it already took, where a re-graded window would have arrived as a
        second verdict about a window it had already answered.
        """
        clock = Clock(rounds=2, hook=self.observe)
        self.run_worker(clock=clock, answers=[200, 200, TransportError('intake answered nothing')])
        partial, replayed = self.observations
        owed = partial['cursor']['pending']['events']

        self.assertEqual(len(owed), EVENTS_PER_ROUND)
        self.assertEqual(partial['posts'], 3, 'the round died partway through the batch')
        self.assertIsNone(partial['cursor']['last_end'], 'a part-delivered batch is a wholly unacked one')
        self.assertEqual(replayed['reads'], READS_PER_ROUND)
        self.assertEqual(replayed['posts'], 3 + EVENTS_PER_ROUND)
        self.assertEqual([wire(item) for item in self.intake.bodies[3:3 + EVENTS_PER_ROUND]],
                         [wire(item) for item in owed], 'byte-identical replay of the whole saved batch')
        self.assertEqual([wire(item) for item in self.intake.bodies[:3]], [wire(item) for item in owed[:3]],
                         'the events the platform already accepted are re-sent and not regenerated')
        self.assertIsNone(replayed['cursor']['pending'])
        self.assertEqual(replayed['cursor']['last_end'], utc_text(NOW))

    def test_a_store_answer_that_changed_during_the_outage_is_not_regraded_while_bytes_are_owed(self):
        """The defect in one round: healthy samples arrive while a burn is owed, and nothing is re-judged.

        Under the stale-state loop the second round sees no pending batch, so it reads this new series,
        grades the later window and saves a **recovery** over the firing batch — a verdict rewritten into
        different bytes, for a window the platform never answered. The fix cannot reach that path: the
        batch is on disk, so the round replays it and never asks the store anything.
        """
        def recover(round_number: int) -> None:
            self.observe(round_number)
            if round_number == 1:
                self.reader.load(series(6, name=METRIC, resource_id=self.host, value=1.0,
                                        start=utc_text(NOW + dt.timedelta(seconds=60)),
                                        step_seconds=60))

        clock = Clock(rounds=2, hook=recover)
        with self.assertLogs('local_observe.slo.__main__', 'INFO') as captured:
            self.run_worker(clock=clock, answers=[TransportError('intake refused')])
        owed = self.observations[0]['cursor']['pending']['events']
        self.assertEqual({(item['kind'], item['status']) for item in owed},
                         {('coverage', 'resolved'), ('threshold', 'firing')},
                         'the saved batch is the burn this fixture earned')
        self.assertEqual(self.observations[1]['reads'], READS_PER_ROUND, 'the store was never asked again')
        replayed = self.intake.bodies[1:]
        self.assertEqual([wire(item) for item in replayed], [wire(item) for item in owed])
        self.assertEqual({(item['kind'], item['status']) for item in replayed},
                         {('coverage', 'resolved'), ('threshold', 'firing')},
                         'what goes out is the burn it saved, not a recovery graded from the new samples')
        self.assertEqual(self.observations[1]['cursor']['last_end'], utc_text(NOW),
                         'the owed window is the one acknowledged; the later window is still ahead')
        self.assertEqual(self.results(captured.records), ['replayed'])

    def test_a_delivered_window_is_judged_once_in_this_process_and_once_after_a_restart(self):
        """Idle, success and restart: the cursor holds the position, and the next window still arrives."""
        self.run_worker(clock=Clock(rounds=2, advance=False, hook=self.observe))
        delivered, idle = self.observations
        self.assertEqual(delivered['posts'], EVENTS_PER_ROUND)
        self.assertEqual(delivered['cursor']['last_end'], utc_text(NOW))
        self.assertIsNone(delivered['cursor']['pending'])
        self.assertEqual(idle['posts'], EVENTS_PER_ROUND, 'the same grid position is not offered twice')
        self.assertEqual(idle['reads'], READS_PER_ROUND, 'and an idle round reads nothing')

        # A new `main()` over the same file, pointed at the same instant: the durable cursor is what
        # tells it this window was delivered, and the one after it is still judged on its own read.
        self.run_worker(clock=Clock(rounds=2, start=NOW, hook=self.observe))
        boot_idle, next_window = self.observations[2], self.observations[3]
        self.assertEqual(boot_idle['posts'], 0, 'a restart does not offer a delivered window again')
        self.assertEqual(boot_idle['reads'], READS_PER_ROUND)
        self.assertEqual(next_window['reads'], 2 * READS_PER_ROUND)
        self.assertEqual(next_window['posts'], EVENTS_PER_ROUND)
        self.assertEqual(next_window['cursor']['last_end'],
                         utc_text(NOW + dt.timedelta(seconds=INTERVAL)))
        self.assertEqual(self.intake.bodies[0]['window']['end'],
                         utc_text(NOW + dt.timedelta(seconds=INTERVAL)))

    def test_a_cursor_that_turns_unreadable_mid_run_is_refused_every_round_without_losing_its_bytes(self):
        """Duplicated keys are a refusal forever, not a reason to forget what the producer owes.

        The file is left exactly as found: this loop has no repair, no re-baseline and no reset, and the
        round performs no store read and no POST, so a refusal costs a quiet round and nothing else.
        """
        broken = (b'{"schema_version": 1, "binding": null, "binding": null, "pending": null,'
                  b' "last_end": null, "previous_end": null}\n')

        def break_the_cursor(round_number: int) -> None:
            self.observe(round_number)
            if round_number == 1:
                self.cursor_path.write_bytes(broken)

        clock = Clock(rounds=3, hook=break_the_cursor)
        with self.assertLogs('local_observe.slo.__main__', 'INFO') as captured:
            self.run_worker(clock=clock, answers=[503])
        self.assertTrue(self.observations[0]['cursor']['pending'] is not None,
                        'the refused round really did save a batch before the file was broken')
        self.assertEqual(self.cursor_path.read_bytes(), broken,
                         'a cursor this module cannot trust is never rewritten, truncated or reset')
        self.assertEqual(self.observations[2]['posts'], 1, 'nothing is POSTed from a cursor it cannot read')
        self.assertEqual(self.observations[2]['reads'], READS_PER_ROUND, 'and nothing is re-queried')
        self.assertEqual(self.results(captured.records), [], 'a refused reload is not a finished round')
        self.assertEqual(self.warnings(captured.records),
                         ['TransportError', 'InvalidInventory', 'InvalidInventory'],
                         'every later round refuses again, visibly, naming only the exception class')

    def test_a_cursor_of_another_schema_version_is_refused_mid_run_and_never_migrated(self):
        """An incompatible version is a refusal the operator answers, not a file this build rewrites."""
        def bump_the_version(round_number: int) -> None:
            self.observe(round_number)
            if round_number == 1:
                document = json.loads(self.cursor_path.read_text(encoding='utf-8'))
                document['schema_version'] = 99
                self.cursor_path.write_text(json.dumps(document, sort_keys=True), encoding='utf-8')

        clock = Clock(rounds=2, hook=bump_the_version)
        with self.assertLogs('local_observe.slo.__main__', 'INFO') as captured:
            self.run_worker(clock=clock, answers=[503])
        self.assertEqual(json.loads(self.observations[1]['raw'].decode('utf-8'))['schema_version'], 99,
                         'the foreign bytes are still the file: no migration, no reset')
        self.assertEqual(self.observations[1]['posts'], 1)
        self.assertEqual(self.observations[1]['reads'], READS_PER_ROUND)
        self.assertEqual(self.warnings(captured.records), ['TransportError', 'StateError'])

    def test_a_hand_edited_pending_batch_is_refused_mid_rather_than_delivered_as_a_verdict(self):
        """`conditions.load_cursor` re-validates every stored event, and the loop honours that refusal."""
        def break_the_batch(round_number: int) -> None:
            self.observe(round_number)
            if round_number == 1:
                document = json.loads(self.cursor_path.read_text(encoding='utf-8'))
                document['pending']['events'] = [{'kind': 'threshold'}]
                self.cursor_path.write_text(json.dumps(document, sort_keys=True), encoding='utf-8')

        clock = Clock(rounds=2, hook=break_the_batch)
        with self.assertLogs('local_observe.slo.__main__', 'INFO') as captured:
            self.run_worker(clock=clock, answers=[503])
        self.assertEqual(json.loads(self.observations[1]['raw'].decode('utf-8'))['pending']['events'],
                         [{'kind': 'threshold'}], 'the edited bytes are refused as found, not repaired')
        self.assertEqual(self.observations[1]['posts'], 1, 'a batch that will not validate is never POSTed')
        self.assertEqual(self.observations[1]['reads'], READS_PER_ROUND, 'and no fresh verdict replaces it')
        self.assertEqual(self.warnings(captured.records), ['TransportError', 'StateError'])

    def test_an_edited_objective_document_over_a_pending_batch_refuses_the_restart_not_re_baselines_it(self):
        """The binding refusal is start-up validation this card must not have moved, and it still refuses.

        Re-tuning an objective under a batch the old rules owed is an operator reconciliation and not a
        re-baseline: the restart exits 1 and changes no byte, so the owed events survive. The
        per-round reload cannot weaken that rule either — the same `conditions.load_cursor` refusal runs
        on every later round, and nothing in the loop writes to a cursor it refused to read.
        """
        self.run_worker(clock=Clock(rounds=1, hook=self.observe), answers=[503])
        owed = self.observations[0]['raw']
        document = json.loads(self.config_path.read_text(encoding='utf-8'))
        document['objectives'][0]['burn_threshold'] = 14.4
        self.config_path.write_text(json.dumps(document), encoding='utf-8')

        with self.assertLogs('local_observe.slo.__main__', 'WARNING') as captured:
            self.assertEqual(1, self.run_worker(clock=Clock(rounds=2)))
        self.assertEqual([record.levelname for record in captured.records], ['WARNING'])
        self.assertEqual(captured.records[0].error_class, 'StateError')
        self.assertEqual(self.cursor_path.read_bytes(), owed, 'what the old rules owed is untouched')
        self.assertEqual(self.intake.bodies, [], 'a refused start opens no request')
        self.assertEqual(self.reader.reads, READS_PER_ROUND, 'and issues no query')


if __name__ == '__main__':
    unittest.main()

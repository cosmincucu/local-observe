"""The asynchronous audit writer, at the dispatcher's own surface: what frees the one slot, and what may never free it.

`tests/test_refusal_audit_offloop.py` drives this contract from outside — through the ASGI app, a real
`Store` and a real write lock — and deliberately never imports the dispatcher. This file is the other
half: the completion signal itself, on real threads, with no HTTP and no database in the way. The defect
it exists to prevent was measured on the second draft, where cancelling the future a request awaited
while its callable was *still running* reported the slot as free, because a cancelled asyncio future was
read as if it were a fact about a thread. It is not one: `asyncio` propagates a wrapper's cancellation
into the executor item, the executor refuses to cancel an item that already started, and the wrapper the
caller was handed reports `cancelled()` all the same. So every test here watches a real callable's real
start and real return, and asks the dispatcher what it believes — never what its source says.

What is pinned:

* **A cancelled completion signal is not completion.** Cancelling `DispatchJob.future` while the callable
  runs keeps `in_flight: 1`, keeps the next denial shed, and gives the capacity back only when the
  callable's own thread returns from it.
* **Cancellation has no path to the work.** Callable queued, its signal cancelled before a worker freed
  up: the work still runs, exactly once, and reports its own completion.
* **A cancelled *request* still propagates.** The awaiting caller gets its `CancelledError` back, and the
  slot does not move.
* **A submission that never reached a thread** is counted as a dispatcher failure and holds nothing; the
  callable it wrapped never runs. A submission an executor *dropped out of its queue* is counted too and
  keeps its slot occupied, because that state says nothing about a thread either — the same lesson, taken
  the fail-closed way.
* **`failed` counts every fault and logs one class-only line per interval** of real elapsed clock: no
  payload, no traceback, no line for a success and none for a shed.
* **The three counters are integers that saturate** at `refusals.COUNTER_LIMIT` — the same ceiling the
  refusal budget uses — and name themselves in `saturated`; `capacity`, `in_flight` and `closed` are
  state, never saturation subjects. The names come from this dispatcher, not from `refusals.COUNTERS`
  (which are `Store`'s four row tallies: `written`, `dropped`, `failed`, `unauditable`).
* **A job whose submitting loop is gone** is settled by the next loop on the thread's own event, and the
  lost wake-up costs nothing but the wake-up.

Two deliberate limits, stated rather than papered over. Reaching the ceiling needs seeded state, because
2**63-1 requests is not a test: `overloaded` is seeded *at* the ceiling (no test can lose that many
denials), `admitted` one step below it and `failed` three steps below, so every number traffic can move is
moved by a real admission or a real dispatcher fault and only the unreachable distance to the ceiling is
written. The log throttle is driven through the dispatcher's injectable monotonic `clock`, the same seam
`RefusalAudit` uses, so "one line per 60 seconds of actual elapsed time" is tested as an interval measured
from the line that was actually printed instead of as a sleep nobody here may take.

No skip lives in this file. Nothing sleeps to synchronise: every hand-off is a `threading.Event` this
file owns, every wait is a bounded *failure* deadline that names what it was owed, and the only `sleep`
calls are the cooperative yields inside those polls. All data is synthetic; the planted word in
`SENTINEL` rides inside an injected exception message to prove it reaches no log line. No claim here that
any of it passed: main runs the tiers and owns that verdict.
"""
import asyncio
import concurrent.futures
import contextlib
import json
import logging
import threading
import time
import unittest
from collections.abc import Callable
from typing import Any

from local_observe.platform.refusal_dispatch import CAPACITY, COUNTERS, RefusalAuditDispatcher
from local_observe.platform.refusals import COUNTER_LIMIT, FAILURE_LOG_INTERVAL_SECONDS

#: Every finite bound in this file is a failure deadline, never a way to let something finish.
SAFETY = 10.0
#: How often a cooperative poll looks. A sampling interval; nothing here is bounded by it.
POLL_SECONDS = 0.005
#: Rides inside an injected exception's message. It may reach no log line, no status body, no counter.
SENTINEL = 'never-in-a-row-a-log-line-or-a-job'
#: The published `status()` body, pinned from this side too: one slot, three counters, one flag.
STATUS_KEYS = frozenset({'capacity', 'in_flight', 'admitted', 'overloaded', 'failed', 'closed',
                         'scope', 'resets_on_restart', 'saturated'})


def noop() -> None:
    """A callable that does nothing, for the admissions a test needs without a database."""


async def until(predicate: Callable[[], bool], *, what: str, timeout: float = SAFETY) -> None:
    """Cooperatively wait for `predicate`, failing with the sentence that says what was owed."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() >= deadline:
            raise AssertionError(f'{what}: not true within {timeout}s')
        await asyncio.sleep(POLL_SECONDS)


def until_here(predicate: Callable[[], bool], *, what: str, timeout: float = SAFETY) -> None:
    """The same claim from a thread that owns no event loop, for facts only a thread can report."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f'{what}: not true within {timeout}s')
        time.sleep(POLL_SECONDS)


async def bounded(awaitable: Any, *, what: str, timeout: float = SAFETY) -> Any:
    """Await with a finite safety deadline, turning a hang into a sentence rather than a CI timeout."""
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    except TimeoutError:
        raise AssertionError(f'timed out after {timeout}s waiting for {what}') from None


class Runs:
    """What the submitted callables really did: entered on a thread, left it, how many times, where."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.started = 0
        self.finished = 0
        self.threads: list[str] = []
        self.on_main_thread: list[bool] = []
        self.loops: list[Any] = []
        self.starved: list[float] = []

    def note_start(self) -> None:
        thread = threading.current_thread()
        try:
            running_loop: Any = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        with self._lock:
            self.started += 1
            self.threads.append(thread.name)
            self.on_main_thread.append(thread is threading.main_thread())
            self.loops.append(running_loop)

    def note_finish(self) -> None:
        with self._lock:
            self.finished += 1

    @property
    def counts(self) -> tuple[int, int]:
        with self._lock:
            return self.started, self.finished


def parked(runs: Runs, entered: threading.Event, release: threading.Event, *,
           before: Callable[[], None] | None = None, fault: BaseException | None = None
           ) -> Callable[[], None]:
    """One audit callable whose end this file, not a timeout, decides.

    It announces its own start from the executor thread, waits on an event only this file sets, and then
    returns normally or raises `fault`. A callable that is never released records that in `starved` and
    returns rather than raising, so the failure a test reports is the assertion it was about, not a
    dispatcher that booked a stuck test as an audit failure. An already-set `release` makes it a call
    that simply completes.
    """

    def work() -> None:
        runs.note_start()
        if before is not None:
            before()
        entered.set()
        try:
            if not release.wait(SAFETY):
                runs.starved.append(SAFETY)
                return
            if fault is not None:
                raise fault
        finally:
            runs.note_finish()

    return work


def completed(release: threading.Event) -> threading.Event:
    """Return the same event, set: a callable that has nothing to wait for is a callable that finishes."""
    release.set()
    return release


class ProductLogs(logging.Handler):
    """Every record this package emits, whatever logger name the dispatcher used, at any level."""

    def __init__(self) -> None:
        super().__init__(level=0)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    @property
    def warnings(self) -> list[logging.LogRecord]:
        return [record for record in self.records
                if (record.name == 'local_observe' or record.name.startswith('local_observe.'))
                and record.levelno >= logging.WARNING]

    @contextlib.contextmanager
    def captured(self):
        root = logging.getLogger()
        root.addHandler(self)
        try:
            yield self
        finally:
            root.removeHandler(self)
            self.close()


class SteppingClock:
    """The dispatcher's log throttle, read from a clock this file moves. Never a real sleep."""

    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class RefusalDispatchTests(unittest.TestCase):
    """The slot, its completion signal, and the arithmetic that describes them."""

    def test_cancelling_the_completion_signal_of_running_work_keeps_its_slot(self):
        """The measured defect: a cancelled future is not a finished callable.

        The callable is inside its own body when the notification is cancelled. Three things are all true
        in that moment: the callable has not finished, `in_flight` is still 1, and the next denial is
        still shed. The capacity then has to come back from the callable's own return and nowhere earlier
        — including not from the drain that runs afterwards.
        """
        gate = RefusalAuditDispatcher()
        runs = Runs()
        entered, released = threading.Event(), threading.Event()
        finished = threading.Event()

        def work() -> None:
            runs.note_start()
            entered.set()
            try:
                if not released.wait(SAFETY):
                    runs.starved.append(SAFETY)
                    return
            finally:
                runs.note_finish()
                finished.set()

        async def scenario() -> dict[str, Any]:
            job = gate.submit(work)
            self.assertIsNotNone(job, 'the first denial was not admitted')
            try:
                await until(entered.is_set, what='the callable to start on an executor thread')
                self.assertTrue(job.future.cancel(), 'the job offered no completion signal to cancel')
                await asyncio.sleep(0)
                await asyncio.sleep(0)  # any callback keyed on that cancel has now had its turn
                self.assertFalse(finished.is_set(),
                                 'the callable reported itself finished while still inside its own wait')
                self.assertFalse(job.completed, 'a cancelled signal wrote the completion event')
                self.assertEqual(gate.status()['in_flight'], 1,
                                 'a cancelled asyncio future freed a slot whose work was still running')
                self.assertIsNone(gate.submit(noop), 'the freed slot admitted a second callable')
                self.assertIs(gate.current_job(), job, 'the running job was replaced by a cancelled future')
            finally:
                released.set()
                await until(finished.is_set, what='the callable to return from its own body')
            gate.close()
            await bounded(gate.wait_idle(), what='the drain to find the finished callable')
            return gate.status()

        status = asyncio.run(scenario())
        self.assertEqual(runs.counts, (1, 1), 'the cancelled-signal callable did not run exactly once')
        self.assertEqual(runs.starved, [], 'the callable hit its own safety timeout')
        self.assertEqual(runs.on_main_thread, [False], 'the audit ran on the loop thread')
        self.assertEqual(runs.loops, [None], 'the audit ran on a thread that owns an event loop')
        self.assertEqual((status['in_flight'], status['admitted'], status['overloaded'],
                          status['failed']), (0, 1, 1, 0), f'accounting of a cancelled signal: {status}')
        self.assertIs(status['closed'], True)

    def test_work_queued_behind_an_occupied_worker_still_runs_after_its_signal_is_cancelled(self):
        """The other half of the same inference: cancellation before the start must not skip the work.

        One worker, deliberately occupied, so the audit callable is provably still in the queue when its
        notification is cancelled — and the callable reads that notification on its very first line, the
        only moment that can prove the order. If cancelling a notification reached the submission, this
        callable would never run at all, and `admitted` would name a job that never happened.
        """
        gate = RefusalAuditDispatcher()
        runs = Runs()
        entered, released = threading.Event(), threading.Event()
        worker_busy, worker_free = threading.Event(), threading.Event()
        holder: dict[str, Any] = {}

        def occupy_worker() -> None:
            worker_busy.set()
            worker_free.wait(SAFETY)

        work = parked(runs, entered, released, before=lambda: holder.update(
            signal=holder['job'].future.cancelled(), completed=holder['job'].completed))

        async def scenario() -> dict[str, Any]:
            loop = asyncio.get_running_loop()
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='one-worker')
            loop.set_default_executor(pool)
            try:
                occupying = asyncio.ensure_future(loop.run_in_executor(None, occupy_worker))
                await until(worker_busy.is_set, what='the only executor worker to be occupied')
                holder['job'] = gate.submit(work)
                self.assertIsNotNone(holder['job'], 'a queued audit was refused')
                self.assertTrue(holder['job'].future.cancel())
                self.assertEqual(gate.status()['in_flight'], 1,
                                 'a queued callable with a cancelled signal left the slot')
                self.assertFalse(entered.is_set(), 'the callable ran while the only worker was occupied')
                worker_free.set()
                await bounded(occupying, what='the occupying call to give its worker back')
                await until(entered.is_set, what='the queued callable to start once a worker freed up')
                self.assertTrue(holder['signal'],
                                'the cancellation did not come first, so this run proved nothing')
                self.assertFalse(holder['completed'], 'a queued job reported completion before its work')
                self.assertEqual(gate.status()['in_flight'], 1,
                                 'the slot went while the queued callable was only now running')
                self.assertIsNone(gate.submit(noop), 'a second callable was admitted beside the queued one')
                released.set()
                await until(lambda: runs.counts == (1, 1), what='the queued callable to finish')
                gate.close()
                await bounded(gate.wait_idle(), what='the drain to see the real completion')
                return gate.status()
            finally:
                worker_free.set()
                released.set()
                pool.shutdown(wait=False)

        status = asyncio.run(scenario())
        self.assertEqual(runs.counts, (1, 1), 'the queued callable did not run exactly once')
        self.assertEqual(runs.starved, [])
        self.assertEqual((status['in_flight'], status['admitted'], status['overloaded'],
                          status['failed']), (0, 1, 1, 0), f'accounting of a queued call: {status}')

    def test_cancelling_the_awaiting_request_propagates_and_leaves_the_slot_occupied(self):
        """The caller's cancellation is the caller's business; the slot is not.

        `wait` must hand back the `CancelledError` its own task earned — a refusal path that swallowed a
        cancellation is a request nobody can cancel — while the running callable keeps the slot, the next
        denial keeps shedding, and the cancelled attempt still finishes its own work.
        """
        gate = RefusalAuditDispatcher()
        runs, entered, released = Runs(), threading.Event(), threading.Event()

        async def scenario() -> dict[str, Any]:
            job = gate.submit(parked(runs, entered, released))
            self.assertIsNotNone(job)
            waiter = asyncio.ensure_future(gate.wait(job))
            await until(entered.is_set, what='the callable to start')
            waiter.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await waiter
            self.assertFalse(job.future.cancelled(),
                             'cancelling the waiter cancelled the notification the next waiter needs')
            self.assertEqual(gate.status()['in_flight'], 1,
                             'the awaiting request was taken for the running callable')
            self.assertIsNone(gate.submit(noop), 'a cancelled request handed its slot to the next denial')
            released.set()
            await until(lambda: runs.counts == (1, 1), what='the cancelled request\'s callable to finish')
            gate.close()
            await bounded(gate.wait_idle(), what='the drain to finish what the request did not wait for')
            return gate.status()

        status = asyncio.run(scenario())
        self.assertEqual(runs.starved, [])
        self.assertEqual((status['in_flight'], status['admitted'], status['overloaded'],
                          status['failed']), (0, 1, 1, 0), f'accounting of a cancelled request: {status}')

    def test_a_submission_no_thread_ever_took_is_counted_and_holds_no_capacity(self):
        """The one release that is not the callable's own: the schedule itself faulted.

        `submit` answers `None` like any shed, but books itself in `failed` rather than `overloaded` —
        those are answers to different questions — takes nothing, admits nothing, and leaves the slot
        free for the next denial over a working executor. The callable it was handed never runs, which is
        exactly what makes this release a fact rather than a guess about somebody else's thread.
        """
        gate = RefusalAuditDispatcher()
        runs, entered, released = Runs(), threading.Event(), threading.Event()

        async def scenario() -> dict[str, Any]:
            loop = asyncio.get_running_loop()
            dead = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='shut-down')
            dead.shutdown(wait=True)
            loop.set_default_executor(dead)
            before = gate.status()
            self.assertIsNone(gate.submit(parked(runs, entered, released)),
                              'a submission that could not be scheduled was reported as admitted')
            released.set()  # nothing was running; this only guarantees the test cannot park on it
            after = gate.status()
            self.assertEqual(after['failed'], before['failed'] + 1,
                             'a submission that never reached a thread went uncounted')
            self.assertEqual((after['admitted'], after['in_flight']), (0, 0),
                             'a submission nobody scheduled took capacity or counted as admitted')
            self.assertEqual(after['overloaded'], before['overloaded'],
                             'a faulted schedule was booked as an overload, which it is not')
            self.assertFalse(after['closed'])
            self.assertEqual(runs.counts, (0, 0), 'the callable of a refused submission ran anyway')

            live = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='restored')
            loop.set_default_executor(live)
            try:
                job = gate.submit(parked(runs, entered, completed(threading.Event())))
                self.assertIsNotNone(job, 'capacity did not survive the refused submission')
                await bounded(gate.wait(job), what='the retry to complete')
                gate.close()
                await bounded(gate.wait_idle(), what='the drain after the refused submission')
                return gate.status()
            finally:
                live.shutdown(wait=True)

        status = asyncio.run(scenario())
        self.assertEqual(runs.counts, (1, 1), 'the retry after a refused submission did not run once')
        self.assertEqual(runs.starved, [])
        self.assertEqual((status['in_flight'], status['admitted'], status['overloaded'],
                          status['failed']), (0, 1, 0, 1), f'accounting of a refused submission: {status}')

    def test_a_submission_dropped_from_its_queue_never_frees_a_slot_it_might_still_run_in(self):
        """The fail-closed half: a cancelled *executor item* is not knowledge about a thread.

        A loop tearing its default executor down around a queued item produces precisely the state the
        first two drafts mistook for completion. Counting it costs nothing; releasing capacity on it does
        not, because an item that started and a wrapper that was cancelled look identical from here. So
        the slot stays taken — the only leak left in this design, and the one that cannot put a second
        writer on a locked database.
        """
        gate = RefusalAuditDispatcher()
        runs, entered, released = Runs(), threading.Event(), threading.Event()
        worker_busy, worker_free = threading.Event(), threading.Event()

        def occupy_worker() -> None:
            worker_busy.set()
            worker_free.wait(SAFETY)

        async def scenario() -> dict[str, Any]:
            loop = asyncio.get_running_loop()
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix='dropped')
            loop.set_default_executor(pool)
            try:
                occupying = asyncio.ensure_future(loop.run_in_executor(None, occupy_worker))
                await until(worker_busy.is_set, what='the only executor worker to be occupied')
                self.assertIsNotNone(gate.submit(parked(runs, entered, released)))
                pool.shutdown(wait=False, cancel_futures=True)
                worker_free.set()
                await bounded(occupying, what='the occupied worker to be released')
                await until(lambda: gate.status()['failed'] == 1,
                            what='the dropped submission to count itself')
                status = gate.status()
                self.assertEqual(status['in_flight'], 1,
                                 'a cancelled executor item was taken for a callable that had finished')
                self.assertEqual(status['admitted'], 1)
                self.assertEqual(runs.counts, (0, 0), 'the dropped submission ran anyway')
                self.assertIsNone(gate.submit(noop), 'a dropped submission handed its slot away')
                return gate.status()
            finally:
                worker_free.set()
                released.set()
                pool.shutdown(wait=False)

        status = asyncio.run(scenario())
        self.assertEqual((status['in_flight'], status['admitted'], status['overloaded'],
                          status['failed']), (1, 1, 1, 1), f'accounting of a dropped submission: {status}')
        self.assertEqual(runs.starved, [])

    def test_a_failing_callable_counts_every_time_and_costs_one_class_only_line_an_interval(self):
        """`failed` is the count and the log line is the signal; the two are out of step on purpose.

        Three faults at 0 s, half an interval, and just past a full interval of the dispatcher's own
        monotonic clock produce three counters and two lines: the interval is measured from the instant a
        line was *actually printed*, so the two failures that straddle the 60-second mark cost one line
        rather than two. A normal return costs nothing, and only the exception class may leave the
        process — the planted word rides in the message and must appear nowhere.
        """
        clock = SteppingClock()
        gate = RefusalAuditDispatcher(clock=clock)
        runs, logs = Runs(), ProductLogs()
        half = FAILURE_LOG_INTERVAL_SECONDS / 2

        async def scenario() -> dict[str, Any]:
            with logs.captured():
                for step, advance in ((1, 0.0), (2, half), (3, half + 0.1)):
                    clock.advance(advance)
                    job = gate.submit(parked(runs, threading.Event(), completed(threading.Event()),
                                             fault=RuntimeError(f'{SENTINEL}: injected call failure')))
                    self.assertIsNotNone(job, f'failure {step} was not admitted')
                    await bounded(gate.wait(job), what=f'failure {step} to be reported done')
                    await until(lambda: gate.status()['failed'] == step,
                                what=f'failure {step} to be counted')
                    self.assertEqual(len(logs.warnings), 1 if step < 3 else 2,
                                     f'the throttle printed the wrong number of lines at step {step}')
                    self.assertEqual(gate.status()['in_flight'], 0,
                                     'a failing callable did not give the slot back')
                good = gate.submit(parked(runs, threading.Event(), completed(threading.Event())))
                self.assertIsNotNone(good, 'a dispatcher that had been failing stopped admitting')
                await bounded(gate.wait(good), what='the successful call to finish')
                await until(lambda: gate.status()['admitted'] == 4, what='the success to be admitted')
                gate.close()
                await bounded(gate.wait_idle(), what='the drain after the failures')
                return gate.status()

        status = asyncio.run(scenario())
        self.assertEqual(runs.counts, (4, 4), 'a failing callable was retried, or a success was skipped')
        self.assertEqual(runs.starved, [])
        self.assertEqual((status['admitted'], status['failed'], status['overloaded'],
                          status['in_flight']), (4, 3, 0, 0), f'accounting of three faults: {status}')
        lines = logs.warnings
        self.assertEqual(len(lines), 2, f'three faults cost {len(lines)} lines')
        for record in lines:
            self.assertIsNone(record.exc_info, 'a traceback rode on the failure line')
            self.assertEqual(record.error_class, 'RuntimeError')
            rendered = ' '.join(sorted(str(value) for value in vars(record).values()))
            self.assertNotIn(SENTINEL, rendered, 'the failure line carried caller text')
            self.assertNotIn(SENTINEL, record.getMessage(), 'the failure message carried caller text')

    def test_the_three_counters_saturate_at_the_ceiling_and_only_counters_are_named_saturated(self):
        """2**63-1 is reported as itself, the next request changes nothing, and `saturated` says which.

        Only the unreachable distance to the ceiling is written: `overloaded` is seeded at it, because no
        test can flood a busy slot 2**63-1 times, while `admitted` and `failed` are seeded below it and the
        last steps are real traffic — one admission that tips the first, and four real dispatcher faults
        that lift the second to the ceiling and then try to push past it. Asserting the value after *every*
        fault is what makes this a proof of capping rather than a proof of reporting: three of the four
        steps land under the ceiling, where one fault must move the counter by exactly one. The clock is
        the real one, because nothing about the throttle is at issue here. What is observed is the
        published body: integers, never booleans, never above the ceiling, and with `capacity`,
        `in_flight` and `closed` excluded from the saturation list by being state rather than totals.
        """
        gate = RefusalAuditDispatcher()
        runs, entered, released = Runs(), threading.Event(), threading.Event()
        faults_seeded = COUNTER_LIMIT - 3
        gate._counters['overloaded'] = COUNTER_LIMIT
        gate._counters['admitted'] = COUNTER_LIMIT - 1
        gate._counters['failed'] = faults_seeded

        async def scenario() -> dict[str, Any]:
            job = gate.submit(parked(runs, entered, released))
            self.assertIsNotNone(job, 'a dispatcher at its ceiling stopped admitting altogether')
            await until(entered.is_set, what='the parked callable to start')
            self.assertIsNone(gate.submit(noop), 'a busy dispatcher admitted a second callable')
            self.assertEqual(gate.status()['overloaded'], COUNTER_LIMIT,
                             'a shed past the ceiling changed a counter that had no room left')
            released.set()
            await bounded(gate.wait(job), what='the parked callable to hand its slot back')
            for step in (1, 2, 3, 4):
                failing = gate.submit(parked(runs, threading.Event(), completed(threading.Event()),
                                             fault=RuntimeError(f'{SENTINEL}: injected call at the ceiling')))
                self.assertIsNotNone(failing, f'the dispatcher stopped admitting at fault {step}')
                await bounded(gate.wait(failing), what=f'fault {step} to be reported done')
                self.assertEqual(gate.status()['failed'], min(COUNTER_LIMIT, faults_seeded + step),
                                 f'fault {step} was not counted as exactly one, or moved a full counter')
            gate.close()
            await bounded(gate.wait_idle(), what='the drain at the ceiling')
            return gate.status()

        status = asyncio.run(scenario())
        self.assertEqual(set(status), set(STATUS_KEYS), f'the published block moved: {sorted(status)}')
        self.assertEqual((status['admitted'], status['overloaded'], status['failed']),
                         (COUNTER_LIMIT, COUNTER_LIMIT, COUNTER_LIMIT),
                         'a counter wrapped past the ceiling or was allowed to grow above it')
        self.assertEqual(status['saturated'], sorted(COUNTERS),
                         'saturation named the wrong names, or the ceiling went unreported')
        for name in COUNTERS:
            self.assertIsInstance(status[name], int, f'{name} stopped being an integer')
            self.assertNotIsInstance(status[name], bool, f'{name} became a flag')
            self.assertLessEqual(status[name], COUNTER_LIMIT)
        for state in ('capacity', 'in_flight', 'closed', 'scope', 'resets_on_restart', 'saturated'):
            self.assertNotIn(state, status['saturated'], f'{state} is state, not a saturating counter')
        self.assertEqual(status['capacity'], CAPACITY)
        self.assertEqual(status['in_flight'], 0)
        self.assertIs(status['closed'], True)
        self.assertTrue(json.dumps(status), 'the dispatch block stopped being reportable')
        self.assertEqual(runs.counts, (5, 5), 'an admission or a fault at the ceiling did not run once')
        self.assertEqual(runs.starved, [])

    def test_a_job_whose_submitting_loop_closed_is_settled_on_the_threads_own_event(self):
        """The completion fact belongs to the thread that did the work, not to the loop that asked.

        The callable is still running when the loop that submitted it is stopped and closed, and its
        notification is cancelled on that loop first, so neither can ever deliver a wake-up to anybody.
        Two claims follow: the capacity came back the instant the callable returned, visible from a thread
        that owns no loop at all, and a second loop can settle the same job without awaiting a foreign
        future — and without inventing a dispatcher failure out of a lost wake-up.
        """
        gate = RefusalAuditDispatcher()
        runs, entered, released = Runs(), threading.Event(), threading.Event()
        submitting = asyncio.new_event_loop()
        driver = threading.Thread(target=submitting.run_forever, name='submitting-loop', daemon=True)
        driver.start()
        try:
            async def admit() -> Any:
                return gate.submit(parked(runs, entered, released))

            job = asyncio.run_coroutine_threadsafe(admit(), submitting).result(SAFETY)
            self.assertIsNotNone(job, 'the submitting loop refused the audit')
            until_here(entered.is_set, what='the callable to start on the submitting loop')
            self.assertEqual(gate.status()['in_flight'], 1)

            submitting.call_soon_threadsafe(job.future.cancel)
            until_here(lambda: job.future.cancelled(), what='the notification to be cancelled')
            submitting.call_soon_threadsafe(submitting.stop)
            driver.join(SAFETY)
            submitting.close()

            self.assertEqual(gate.status()['in_flight'], 1,
                             'closing the submitting loop was taken for the callable finishing')
            self.assertFalse(job.completed, 'a closed loop wrote the job\'s completion event')
            released.set()
            until_here(lambda: runs.counts == (1, 1),
                       what='the callable to finish with nobody left on its submitting loop')
            until_here(lambda: gate.status()['in_flight'] == 0,
                       what='the callable\'s own thread to hand the slot back')

            async def settle_from_a_new_loop() -> dict[str, Any]:
                await bounded(gate.wait(job), what='the new loop to wait on the thread\'s own event')
                gate.close()
                await bounded(gate.wait_idle(), what='the drain across the loop change')
                return gate.status()

            final = asyncio.run(settle_from_a_new_loop())
        finally:
            released.set()
            with contextlib.suppress(Exception):
                # Already stopped and closed on the happy path: a closed loop refuses to be scheduled on.
                submitting.call_soon_threadsafe(submitting.stop)
            driver.join(SAFETY)
            with contextlib.suppress(Exception):
                submitting.close()

        self.assertEqual(runs.counts, (1, 1), 'the job across two loops did not run exactly once')
        self.assertEqual(runs.starved, [])
        self.assertEqual(runs.loops, [None], 'the audit ran on a thread that owns an event loop')
        self.assertEqual((final['in_flight'], final['admitted'], final['overloaded'], final['failed']),
                         (0, 1, 0, 0), f'a lost wake-up was counted as a dispatcher failure: {final}')

    def test_two_sequential_denials_over_one_dispatcher_each_get_their_own_attempt(self):
        """The positive control every cancellation test above depends on: the capacity really comes back.

        Two ordinary admissions, one after the other, each awaited to its own completion, each on an
        executor thread rather than the loop's, with nothing failed and the slot empty between them. One
        shed is expected and it is the last one: `close()` must answer with a shed, not an error and not a
        queue.
        """
        gate = RefusalAuditDispatcher()
        runs = Runs()

        async def scenario() -> dict[str, Any]:
            for _ in range(2):
                entered = threading.Event()
                job = gate.submit(parked(runs, entered, completed(threading.Event())))
                self.assertIsNotNone(job, 'an idle dispatcher refused a denial')
                await bounded(gate.wait(job), what='the admitted callable to finish')
                self.assertEqual(gate.status()['in_flight'], 0, 'the slot stayed taken after its work')
            gate.close()
            await bounded(gate.wait_idle(), what='the idle drain to return')
            self.assertIsNone(gate.submit(noop), 'a closed dispatcher admitted work')
            return gate.status()

        status = asyncio.run(scenario())
        self.assertEqual(runs.counts, (2, 2))
        self.assertEqual(runs.starved, [])
        self.assertEqual(set(runs.on_main_thread), {False}, 'an audit ran on the loop thread')
        self.assertEqual((status['in_flight'], status['admitted'], status['overloaded'],
                          status['failed'], status['closed']), (0, 2, 1, 0, True),
                         f'ordinary denials were accounted wrongly: {status}')


if __name__ == '__main__':
    unittest.main()

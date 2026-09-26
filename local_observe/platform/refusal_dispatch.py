"""One off-loop refusal-audit write per app instance, with one slot and no queue .

Why this exists. The `summary`-role write denial answered at the transport edge used to call
`Store.record_refusal` *inline, on the serving event loop*: one `INSERT` behind a `BEGIN IMMEDIATE`,
with `sqlite3`'s own 10-second busy timeout, run as part of the request's own coroutine. A real write
lock held by another thread therefore stalled every other request in the process — including a
memory-only `GET /v1/runtime`, which reads no database at all, waited for somebody else's fsync. The
refusal had to become durable before it could become off-loop; this module makes it both, without
moving the SQL anywhere except behind `Store`.

The observable shape is narrow on purpose: **one** callable may be in flight per `create_app`
instance, and a request that cannot get the slot is not queued and not made to wait for it — it is
answered with the same 403 it always got, plus a counter that says the audit did not run.

The invariants, each of which is the way it is for a stated reason:

1. **Capacity is one, and there is no queue.** A waiting queue of denied requests is a second,
   unbounded buffer wearing the same 64-token budget underneath it, and its head is a caller who is
   already refused. Admission is a nonblocking test-and-set under one `threading.Lock`.
2. **Capacity is released by the callable's own thread, and by nothing else.** `_finish` runs in a
   `finally` inside the executor thread, after the SQL returned. Cancelling a request, a shield or a
   notification therefore cannot hand back a slot whose write is still in flight, and cannot cancel the
   write itself. The future a caller awaits (`DispatchJob.future`) is a *notification*: made with
   `loop.create_future()`, never chained to the submitted work, and carrying no value anybody reads.
   The submitted future that `run_in_executor` returns is kept private to this module, which is what
   makes "no cancellation path reaches the work" a property rather than a convention.

   The reason for that split is that cancellation is not evidence about a thread. `asyncio`'s
   `wrap_future` propagates a wrapper's cancellation into the executor item, where
   `concurrent.futures.Future.cancel()` is refused the moment the item has started — and the wrapper
   still reports `cancelled()` while the write is inside SQL. A capacity release keyed on a future's
   cancelled state is therefore keyed on nothing, which is what the first two drafts of this file did.
   What a waiter does instead: a cancelled notification is a lost wake-up, so it keeps waiting on the
   job's own `finished` event; and a submission that faulted while being scheduled releases through
   `_abandon`, because in that one case no thread ever took the callable and nobody is left to report.
3. **Nothing here is bound to one event loop.** The state that matters (`_active`, the counters, each
   job's `finished` event) is thread state. A submission goes to the *serving* loop's default
   executor — bounded by invariant 1, so at most one task is ever queued — and a caller waiting on a
   loop other than the submitting one polls the job's own completion event instead of awaiting a
   foreign future (which is what makes one app driven from several loops safe). A notification that
   cannot be delivered — a closed loop, a cancelled future — costs a wake-up, never the completion fact,
   because the only thing the wake-up carries is "come and look".
4. **No thread exists until a request needs one.** The dispatcher starts nothing at construction time:
   no per-app worker, no idle queue, so an app that is built, served through a few direct-ASGI
   requests and thrown away leaks no thread and never needed a lifespan. That is why the executor is
   the loop's own rather than a private one.
5. **`close()` is permanent and drainable.** Lifespan shutdown closes admission, then waits for the
   callable it already admitted — with no timeout, because a timeout here would be a promise that the
   row landed when nobody made it. The wait never blocks the loop and never joins a thread directly,
   and `api.create_app` keeps running that wait even when its own lifespan task is cancelled, so
   abandoning a drain is not something another party can cause.
6. **Failure is counted, logged once an interval, and never an answer.** A dispatcher failure (a
   submission that could not be scheduled, an exception escaping the callable, or a queued submission
   an executor dropped while its loop was being torn down) moves `failed`, logs at most one class-only
   line per `refusals.FAILURE_LOG_INTERVAL_SECONDS` of real monotonic time, and leaves the response
   exactly as it was. A `Store` failure that `record_refusal` already handles stays in `Store`'s own
   counters and never reaches these — the two surfaces count different things. A dropped submission is
   counted and *left* occupying its slot, for the reason invariant 2 gives: releasing capacity because a
   future says `cancelled` is the inference this module exists to refuse, and a slot lost to a loop that
   is already dying is the fail-closed side of that refusal.

The job itself carries no request data: `api.audit_summary_refusal` hands over a callable closed over
nothing but the fixed attempt word, the `Actor` this process authenticated from a bearer token, and
the fixed `summary-only` reason. No body, token, subject, URL, path or exception text is retained here,
and this module never imports `Store`, never opens a connection and never reads a database.

`GET /v1/runtime` reports `status()` under `refusal_audit_dispatch`: volatile app-local memory, reset
by a restart, `scope: 'app-local'` — and, like the budget under it, proof of nothing durable. A 403
whose audit was shed is still a 403; only the row is missing, and `overloaded` is where that shows. An
admitted job that *completed* is a completed attempt, not a row: `Store.record_refusal` owns that
choice, and it may have written the row, spent nothing on a `dropped` refusal, found the attribution
`unauditable`, or counted its own `failed` — none of which this module may claim or re-count.
"""
import asyncio
import threading
import time
from collections.abc import Callable
from typing import Any

from local_observe.log import get_logger
from .refusals import COUNTER_LIMIT, FAILURE_LOG_INTERVAL_SECONDS

log = get_logger(__name__)

#: How many audit callables one app instance may have submitted-or-running at once. One is the whole
#: design: this path's answer to "no room" is to shed now with a counter, never to hold the caller, and
#: a second slot would only put a second writer on one locked file while the request that lost the race
#: is refused either way. (A queue is a separate thing, and forbidden for the reason invariant 1 gives.)
#: Not operator-configurable, for the reason `refusals.CAPACITY` gives: a knob nobody reviewed is a
#: second, undocumented policy.
CAPACITY = 1
#: What the counters describe and what does not survive them. `app-local` is narrower than the write
#: budget's `process-local`: two apps over one `Store` in one process have two slots and two tallies,
#: and neither number is a sum of the other.
SCOPE = 'app-local'
RESETS_ON_RESTART = True
#: The three numbers, in report order. `admitted` is submissions that reached an executor,
#: `overloaded` is every request refused the slot — busy *or* closing, the same 403 either way — and
#: `failed` is dispatcher faults only (see the module docstring's invariant 6). Counters saturate at
#: the same signed-63 ceiling the refusal budget uses, and name themselves in `saturated`.
COUNTERS = ('admitted', 'overloaded', 'failed')
#: How often a wait re-reads job state when no notification wake-up can reach it, in seconds. A
#: sampling interval, not a deadline: nothing about it bounds how long a wait may last, and the loop is
#: free the whole time.
DRAIN_POLL_SECONDS = 0.01


class SubmissionDropped(RuntimeError):
    """Names the class of a submission an executor dropped before running it. Never raised.

    `failed` and its one line per interval are keyed on an exception class, and the one dispatcher fault
    that arrives as a *future's state* rather than as an exception would otherwise have to borrow
    `CancelledError` — the word asyncio reserves for a caller giving up. Nobody gave up on a queued
    audit write; the loop underneath it was being torn down. The name is the difference, and nothing
    outside this module can catch it.
    """


def _settle(notification: Any) -> None:
    """Resolve one job's notification, on the loop that owns it. The re-check here is the authority.

    Reached only through `call_soon_threadsafe`, so `done()` is read by the thread allowed to read it.
    A cancelled or already-settled notification has nobody waiting on it: the completion fact lives in
    the job's `finished` event, not in this object.
    """
    if not notification.done():
        notification.set_result(None)


class DispatchJob:
    """One admitted audit call: the loop that may be woken when it ends, and the thread's own signal.

    `finished` is set by the callable's thread and is the only completion fact that means anything
    across loops, shields or cancellations. `future` is a notification for the submitting loop and
    nothing else — created here, before the work exists, so the thread can never finish into a job with
    no future to wake; never chained to the submitted task, so cancelling it cannot reach the work; and
    carrying no value, so nothing may be inferred from the order it resolves in. The future that *does*
    describe the executor task is held by `RefusalAuditDispatcher` alone, out of reach of any await.
    """

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.loop = loop
        self.future: Any = loop.create_future()
        self.finished = threading.Event()

    @property
    def completed(self) -> bool:
        return self.finished.is_set()


class RefusalAuditDispatcher:
    """The one-slot, nonblocking admission gate in front of the transport's single audit write.

    Thread-safety: one `threading.Lock` guards the slot and the counters, and it is never held across
    the SQLite write, an `await`, or a call into anything that could do either. `submit` is called
    from an event loop, the callable runs on an executor thread, and `wait`/`wait_idle` run
    on the loop: the lock is the only rendezvous, which is why cross-thread accounting stays exact
    while the write itself is unserialised by this module entirely (the database owns that).
    """

    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        """Build an open dispatcher. No thread, no queue, no loop, no database handle is taken."""
        self.capacity = CAPACITY
        # Injectable for tests only, and never caller-visible: production reads `time.monotonic`, and
        # the log throttle is spaced by *actual elapsed* time exactly like `RefusalAudit`'s.
        self._clock = clock if clock is not None else time.monotonic
        self._lock = threading.Lock()
        self._counters = dict.fromkeys(COUNTERS, 0)
        self._active: DispatchJob | None = None
        self._closed = False
        self._last_failure_logged_at: float | None = None

    # ----------------------------------------------------------------------- observation

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def in_flight(self) -> int:
        """0 or 1 — the only values a one-slot gate can report."""
        with self._lock:
            return 0 if self._active is None else 1

    def current_job(self) -> DispatchJob | None:
        with self._lock:
            return self._active

    def status(self) -> dict[str, Any]:
        """The operator-facing body: a pure in-memory read, no lock held longer than a dict copy.

        Keys and their spelling are the contract (`docs/units/refusal-audit.md`): `capacity` and
        `in_flight` answer "can the next refusal be audited from here?", the three counters answer
        "what happened to the ones before it?", and `scope`/`resets_on_restart`/`saturated` say how far
        to trust them. `Store.status()` is not involved and not widened.
        """
        with self._lock:
            counters = dict(self._counters)
            in_flight = 0 if self._active is None else 1
            closed = self._closed
        return {'capacity': self.capacity, 'in_flight': in_flight,
                **counters, 'closed': closed,
                'scope': SCOPE, 'resets_on_restart': RESETS_ON_RESTART,
                'saturated': sorted(name for name in COUNTERS if counters[name] >= COUNTER_LIMIT)}

    # ------------------------------------------------------------------------- admission

    def submit(self, work: Callable[[], Any]) -> DispatchJob | None:
        """Admit `work` to the one slot, or shed. Never queues, never waits, never raises at a caller.

        Returns the job when the callable reached an executor (the caller must then await it to
        completion before answering, and the slot stays occupied until it is done), or `None` when the
        slot was busy, this dispatcher is closing, or the submission itself faulted — in every one of
        those cases nothing ran, so the caller answers its ordinary 403 and `Store`'s token bucket was
        never touched. A shed is not a refusal of the request; it is the audit declining to run.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as exc:
            # Off a loop, `run_in_executor` has no home. Accounted rather than raised: the 403 is owed
            # to a caller who cannot be blamed for the shape of the process that served them.
            self._account_failure(exc)
            return None
        with self._lock:
            if self._closed or self._active is not None:
                # Busy and closing are the same answer to this caller: no slot, same 403, one counter.
                # `closed` in `status()` is what tells the two apart afterwards.
                self._count_locked('overloaded')
                return None
            # Reserved before the schedule: two requests racing here must not both reach an executor.
            # The job is built inside the reservation, and building it builds its notification on this
            # loop, so the executor thread can never finish into a job with nothing to wake.
            job = DispatchJob(loop)
            self._active = job
        try:
            # The default executor, and at most one task in it from this path ever, so the queue inside
            # it cannot become this refusal path's backlog. Creating a private executor instead would
            # be a thread that outlives every app the tests build. What it returns is kept here, local:
            # a future that can cancel this submission is a future nobody outside this method may hold.
            submitted = loop.run_in_executor(None, self._run_callable, job, work)
        except BaseException as exc:
            # Whatever the reason — a loop closing, an executor that refused the task, a signal — no
            # callable ever reached a thread, so the slot goes back exactly as it was taken: nothing
            # ran, nothing may be counted as written, and nothing may reach the caller.
            self._abandon(job)
            if isinstance(exc, Exception):
                # Accounted as a dispatcher failure and answered as a shed. An interrupt or a
                # `SystemExit` is not ours to absorb; the slot is back, and the signal keeps travelling
                # the way `Store.record_refusal` lets it.
                self._account_failure(exc)
                return None
            raise
        # The callback is on the SUBMITTED future, and it exists to read that future's *outcome*: an
        # exception is consumed so asyncio cannot log it as never-retrieved, and a submission that ended
        # cancelled is counted. Neither branch frees the slot on the strength of a cancelled state.
        submitted.add_done_callback(lambda done, job=job: self._on_submitted(job, done))
        with self._lock:
            self._count_locked('admitted')
        return job

    def close(self) -> None:
        """Shut admission. Idempotent, synchronous, and it waits for nothing.

        The callable already running is left exactly as it was found: it finishes, it commits (or its
        failure is counted), and its thread releases the slot. `wait_idle` is how a caller says it wants
        to see that happen; `close` alone only promises no *new* work starts.
        """
        with self._lock:
            self._closed = True

    # --------------------------------------------------------------------------- waiting

    async def wait(self, job: DispatchJob) -> None:
        """Await one admitted callable without ever being able to cancel it.

        Nothing this method returns to the caller is actionable, and nothing it raises replaces the
        403: an exception that escaped the callable is counted and swallowed, because the audit is not
        allowed to speak for the refusal. The single exception that leaves here is
        `asyncio.CancelledError` for the *awaiting task* having been cancelled — a fact about the
        caller, not a failure to report to it.
        """
        await self._await_job(job)

    async def wait_idle(self) -> None:
        """Wait for the admitted callable to be truly finished. No deadline, no thread join, no loop block.

        Called by lifespan shutdown, after `close()` and before the owner lock is released. With
        admission closed no new job can appear, so one pass per job is the whole drain; a job that
        appeared anyway (a dispatcher that was never closed) is simply drained again, so this cannot
        return while this app instance has a write in flight.
        """
        while True:
            job = self.current_job()
            if job is None:
                return
            await self._await_job(job)

    async def _await_job(self, job: DispatchJob) -> None:
        """Wait for one job on whichever loop is running, never holding the callable's thread.

        Nothing awaited here is the executor's future — that one is private, so no request, shield or
        drain has a path to the work. Same-loop callers get the immediate wake-up of the job's
        notification, reached through a shield so that cancelling *this* await cannot take the
        notification away from the next waiter either. A caller on a different loop cannot await that
        future at all, and polls the thread's own completion event — the case one app driven from
        several loops meets.
        """
        if job.completed:
            return
        notification = job.future
        if notification is None or job.loop is not asyncio.get_running_loop():
            await self._poll_completion(job)
            return
        try:
            await asyncio.shield(notification)
        except asyncio.CancelledError:
            if notification.cancelled():
                # The notification died and the thread may not have. It held no power over the callable
                # to begin with, so this is a lost wake-up rather than a finished write, and the only
                # witness left is the thread's own signal — bounded, because `_run_callable`'s `finally`
                # always sets it, cancellation or no cancellation.
                await self._poll_completion(job)
                return
            # The requester went away. The callable did not: it holds the slot until its own thread
            # is done with the SQL, and it is not cancelled by this await unwinding.
            raise
        except Exception as exc:
            # A notification is only ever resolved with `None`, so an exception here is a future that
            # stopped being ours. Counted, never an answer to the caller, and then waited for the way
            # every other lost wake-up is waited for. Re-awaiting it would spin and count forever.
            self._account_failure(exc)
            await self._poll_completion(job)

    async def _poll_completion(self, job: DispatchJob) -> None:
        """Yield the loop repeatedly until the callable's thread reports itself done. No deadline, no join."""
        while not job.completed:
            await asyncio.sleep(DRAIN_POLL_SECONDS)

    # --------------------------------------------------------------------- thread internals

    def _run_callable(self, job: DispatchJob, work: Callable[[], Any]) -> None:
        """Run the one admitted audit call on an executor thread, then hand the slot back.

        Nothing propagates out of here. `Store.record_refusal` already absorbs the persistence
        failures it understands and counts them in its own tallies; whatever escapes it is a dispatcher
        failure — counted as one, named by class at most once an interval, and never allowed to become
        a caller's answer, since there is nobody left on this thread to receive a traceback and the 403
        is owed either way.
        """
        try:
            work()
        except BaseException as exc:
            self._account_failure(exc)
        finally:
            # The only release that follows work, and it is reached only after the call returned or
            # raised its head. A cancelled request, a cancelled notification and a closed loop all stop
            # outside this `finally`, which is why none of them can take the slot back early. The one
            # other release is in `submit`, for a submission no thread ever took.
            self._finish(job)

    def _finish(self, job: DispatchJob) -> None:
        """Give the slot back from the callable's own thread, once the call is really over."""
        self._retire(job)

    def _abandon(self, job: DispatchJob) -> None:
        """Undo a reservation whose callable provably never reached an executor thread."""
        self._retire(job)

    def _retire(self, job: DispatchJob) -> None:
        """Move the slot and the job's completion signal together, from one code path, whoever asks.

        One release path is the point: a job is never left signalling completion while its slot is
        still held, and a slot is never freed while the job that holds it has not said it is done. Only
        after both may an attempt be made to wake the loop that asked.
        """
        with self._lock:
            if self._active is job:
                self._active = None
        job.finished.set()
        self._notify(job)

    def _notify(self, job: DispatchJob) -> None:
        """Resolve the job's notification from this thread, if that loop can still be spoken to.

        `call_soon_threadsafe` is the only cross-thread touch an asyncio future may have from here, and a
        failure of it (`RuntimeError`, a loop that is closing or closed) is allowed to cost a wake-up and
        nothing else: `finished` is already set, and every waiter that cannot see the notification polls
        it instead. It is deliberately not counted in `failed` — nothing about the callable or the slot
        faulted, and the process losing its loops is not a dispatcher's failure to run a call.
        """
        notification = job.future
        if notification is None or notification.done():
            # `done()` covers "cancelled": nobody is waiting on it and it cannot be resolved. A foreign
            # read of this flag is safe precisely because `_settle` re-checks it on the owning loop.
            return
        try:
            job.loop.call_soon_threadsafe(_settle, notification)
        except Exception:
            return

    def _on_submitted(self, job: DispatchJob, submitted: Any) -> None:
        """Read the outcome of *this module's* submission. A cancelled future never frees a slot.

        * **cancelled** — the executor dropped a queued item it never started, which is what tearing a
          loop's default executor down around a submission does. That state is not knowledge about a
          thread: a wrapper cancelled after its work started reads identically from here, and releasing
          on it is the inference that made the first two drafts wrong. Counted, and the slot stays
          occupied — fail-closed, and the only way this app can lose a slot at all is a loop that is
          already going away, whose drain is going away with it.
        * **exception** — the submitted function *returned*, and this module's own code was inside it,
          so no thread is in `work` any more. `_finish` already freed the slot unless the release itself
          is what raised, so putting it back here is bounded rather than hopeful.
        """
        if submitted.cancelled():
            self._account_failure(SubmissionDropped())
            return
        exc = submitted.exception()
        if exc is None:
            return
        self._account_failure(exc)
        if not job.finished.is_set():
            self._abandon(job)

    # ------------------------------------------------------------------------- accounting

    def _count_locked(self, name: str) -> None:
        """Add one to a named counter without wrapping it. Caller holds the lock."""
        current = self._counters[name]
        if current < COUNTER_LIMIT:
            self._counters[name] = current + 1

    def _account_failure(self, exc: BaseException) -> None:
        """Count one dispatcher failure, and log it if the interval says this one is the line.

        Class only, deliberately: a driver's message can name a path, and the text this whole path
        exists to keep out of a row has no business in a log record either. No traceback, no payload,
        no line for a success and no line per shed — the counters are the count, this is the signal.
        """
        with self._lock:
            self._count_locked('failed')
            due = self._log_due_locked()
        if due:
            log.warning('Refusal audit dispatch failed', extra={'error_class': type(exc).__name__})

    def _log_due_locked(self) -> bool:
        """True for the first failure and then only 60 s of real elapsed monotonic time later."""
        now = self._clock()
        last = self._last_failure_logged_at
        if last is not None and now - last < FAILURE_LOG_INTERVAL_SECONDS:
            return False
        # Read inside the lock and moved forward only, so a grant cannot be overtaken by a stale
        # sample and the wait to the next line stays bounded however the clock source behaves.
        self._last_failure_logged_at = now
        return True

"""The asynchronous audit writer: the summary-role audit write leaves the serving loop, and nothing about it is abandoned.

The problem this file exists to catch was reproduced on main: one real SQLite `BEGIN IMMEDIATE` held in
another thread delayed a *memory-only* `GET /v1/runtime` until a 2-second safety release, because the
`summary`-role 403 wrote its audit row synchronously on the serving event loop. Every test here observes
the contract from **outside** the dispatcher — through the ASGI app, a real `Store`, the single
`Store.record_refusal` call, and a real write lock held by this file.

What is pinned, and by which kind of observation:

* **Ordering the other way round.** An admitted request waits for its audit *attempt*: the row is in the
  file before the response body is sent, and the response is journaled after the callable returned.
* **Off the loop.** The callable runs on a thread that owns no event loop, and while this file parks that
  callable the same loop answers a concurrent `GET /v1/runtime` inside a window shorter than the 2 s the
  reproduced failure waited. An inline write expires that window: the probe is the proof, not a reading.
* **Capacity 1, shed, no queue.** A parked write admits exactly one request; the rest are 403
  immediately, are journaled as finishing *before* the parked one, spend no bucket token, and produce at
  most one `Store.record_refusal` call and one database connection.
* **Cancellation and shutdown free nothing while SQL runs.** Cancelling the awaiting request leaves
  `in_flight: 1` and the next denial shed; lifespan shutdown closes admission, drains, and only then
  releases the exclusive owner lock and sends `shutdown.complete` — asserted as an order in one shared
  journal, including when the lifespan task itself is cancelled mid-drain.
* **The 403 outranks the dispatcher.** Shed, failed-call and closed paths answer the same exact bytes,
  count themselves in their own counter, and never become a database writer.
* **The body stays unread.** Every refusal-route exchange uses a `receive()` that either counts its own
  calls or refuses to answer, admitted and shed alike; an unauthenticated request never reaches the
  dispatcher at all — and never opens a connection.

Two deliberate limits, stated rather than papered over. #135 leaves the dispatcher's own public surface to
the code worker, so this file imports no dispatcher module and calls no dispatcher method: the seams are
the ASGI scope, `GET /v1/runtime`'s `refusal_audit_dispatch`, the documented `Store.record_refusal` call,
and `api.exclusive_owner` (wrapped and delegating to the real lock, purely so its release is observable).
And counter *saturation* at `refusals.COUNTER_LIMIT` is not reachable from the outside at 2**63-1
requests, so what is pinned here is the reported `saturated` field's shape and its emptiness under real
traffic; the counter arithmetic itself belongs to `tests/test_refusal_dispatch.py`, and the store's budget
stays pinned in `tests/test_refusal_audit.py`.

No skip of any kind lives in this file. Nothing sleeps to make a guarantee: an injected
`threading.Event` parks a callable, a real SQLite write lock is taken by this file, the polls only notice
state, and every bounded window is either a failure deadline that raises or a named sample behind a
"not yet" assertion. Every SQLite connection this file opens is closed explicitly — `with connection:`
commits or rolls back, it does not close the handle.
"""
import asyncio
import contextlib
import dataclasses
import datetime as dt
import json
import logging
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import api as api_module
from local_observe.platform import detections, refusals
from local_observe.platform.api import REFUSAL_POST_ROUTES, create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')
AGENT = Actor('agent-1', 'proposer')
HUMAN = Actor('operator', 'human')
RUNNER = Actor('runner-1', 'executor')
SUMMARY = Actor('watcher', 'summary')
READER = 'reader-1'
#: Planted in bodies, headers and injected failures. It reaches no row, no log record and no job argument.
SENTINEL = 'never-in-a-row-a-log-line-or-a-job'

CREDENTIALS = [{'identity': AGENT.identity, 'role': 'proposer', 'token': 'proposer-token-for-tests-00000000'},
               {'identity': HUMAN.identity, 'role': 'human', 'token': 'human-token-for-tests-000000000000'},
               {'identity': RUNNER.identity, 'role': 'executor', 'token': 'executor-token-for-tests-00000'},
               {'identity': READER, 'role': 'reader', 'token': 'reader-token-for-tests-0000000000'},
               {'identity': SUMMARY.identity, 'role': 'summary', 'token': 'summary-token-for-tests-00000'}]
TOKENS = {row['identity']: row['token'] for row in CREDENTIALS}

#: Every finite bound in this file is a *failure* deadline, never a way to let something finish.
SAFETY_TIMEOUT = 20.0
#: The window a memory-only read gets while a real write is parked. The reproduced failure waited two
#: seconds for the lock to be released, so the probe is strictly shorter than that measurement.
MEMORY_READ_WINDOW = 1.5
#: How long an answer that must be immediate is given, and how long every "not yet" sample runs. Both are
#: samples this file chooses, never bounds on how long the product may take.
IMMEDIATE_WINDOW = 0.75
#: Two delivery ticks (1 s each) would have opened a connection if anything were still looping.
QUIESCENCE_WINDOW = 2.5

#: What `GET /v1/runtime` must answer with: the body it answered with before the asynchronous audit writer, plus
#: exactly one
#: new key. `refusal_audit_dispatch` is the whole widening, and `refusal_audit` keeps its published shape.
#: The first eleven names are `runtime.observe_startup`'s own output; the last three are the serving
#: process's mutable state and the two audit reads.
RUNTIME_KEYS = frozenset({'schema_version', 'pid', 'observed_at', 'code_root', 'startup_source_sha256',
                          'source_pin_verified', 'loaded_modules', 'notification_safety_contract',
                          'notification_mode', 'sender_configured', 'scope', 'refusal_audit',
                          'refusal_audit_dispatch', 'delivery_loop_failures',
                          'delivery_loop_last_failure_at'})
#: The dispatch block's fields, named by the contract and pinned as a closed set.
DISPATCH_KEYS = frozenset({'capacity', 'in_flight', 'admitted', 'overloaded', 'failed', 'closed',
                           'scope', 'resets_on_restart', 'saturated'})
#: The fields the contract calls counters: integers, and the only names `saturated` may hold. `closed` is
#: deliberately not one of them — it is a state, and a strict bool.
DISPATCH_COUNTERS = ('admitted', 'overloaded', 'failed')


def bearer(identity: str) -> list:
    return [(b'authorization', ('Bearer ' + TOKENS[identity]).encode())]


def running_loop() -> asyncio.AbstractEventLoop | None:
    """Return the calling thread's running loop, or `None` — which is what "off the loop" means."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


async def wait_until(predicate, *, what: str, timeout: float = SAFETY_TIMEOUT) -> None:
    """Poll `predicate()` until it is true, or fail with `what` when `timeout` expires.

    The synchronisation in every caller is deterministic: an injected callable blocked on a
    `threading.Event` this file holds, or a SQLite write lock this file acquired first. The poll only
    *notices*. There is deliberately no truth value to ignore — an expired deadline is an
    `AssertionError`, so a slow contract can never be reported as a satisfied one.
    """
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f'{what}: not observed within {timeout}s')
        await asyncio.sleep(0.005)


async def stays_false(predicate, *, what: str, window: float) -> None:
    """Fail if `predicate()` becomes true at any point during `window` seconds.

    The negative half, for the observations whose whole claim is "not yet, while this file still holds
    the gate". `window` is a sample, not a bound on the real thing: it says what was absent and for how
    long, and the corresponding positive wait is what says the thing eventually happened.
    """
    deadline = time.monotonic() + window
    while True:
        if predicate():
            raise AssertionError(f'{what}: seen within {window}s')
        if time.monotonic() >= deadline:
            return
        await asyncio.sleep(0.005)


async def bounded(awaitable, timeout: float, *, what: str):
    """Await with a finite safety deadline, failing with `what` instead of a bare `TimeoutError`."""
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    except TimeoutError:
        raise AssertionError(f'timed out after {timeout}s waiting for {what}') from None


async def quiet_within(predicate, timeout: float = SAFETY_TIMEOUT) -> bool:
    """Poll `predicate()` to `timeout` and report the answer. Raises nothing, ever.

    This is the cleanup shape: a `finally` that awaits a drain must not replace the assertion already
    travelling with a second one of its own, and must not hang either. Only the test bodies use
    `wait_until`, which does fail loudly; the cleanups below use this, after releasing their gates.
    """
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.005)
    return True


class Journal:
    """A lock-protected append-only record of what happened, in the order it happened.

    The serving loop's thread, the injected audit callable's thread and the lifespan task all write to one
    journal, so the claims this file makes take the form "the write finished before the owner lock went
    back" rather than "the write had finished by the time I looked". Comparing a monotonic stamp taken in
    one thread against an event observed in another is the weaker version of the same sentence, and a
    weaker version of an ordering property is not an ordering property.
    """

    def __init__(self) -> None:
        self._entries: list[str] = []
        self._lock = threading.Lock()

    def note(self, tag: str) -> None:
        with self._lock:
            self._entries.append(tag)

    def snapshot(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._entries)

    def seen(self, tag: str) -> bool:
        return tag in self.snapshot()

    def count(self, tag: str) -> int:
        return self.snapshot().count(tag)

    def first(self, tag: str) -> int | None:
        entries = self.snapshot()
        return entries.index(tag) if tag in entries else None

    def last(self, tag: str) -> int | None:
        entries = self.snapshot()
        return len(entries) - 1 - entries[::-1].index(tag) if tag in entries else None

    def ordered(self, *tags: str) -> bool:
        """True when every tag was noted and each first occurrence sits before the next one."""
        positions = [self.first(tag) for tag in tags]
        if any(position is None for position in positions):
            return False
        return positions == sorted(positions) and len(set(positions)) == len(positions)

    def last_before(self, earlier: str, later: str) -> bool:
        """True when the most recent `earlier` precedes the most recent `later`.

        For a sequential run, where a tag repeats once per iteration: the claim is about *this* round's
        work, and a first-occurrence comparison would be satisfied by any earlier round.
        """
        first, second = self.last(earlier), self.last(later)
        return first is not None and second is not None and first < second


@dataclasses.dataclass(frozen=True)
class Reply:
    """What one in-process ASGI exchange produced, including whether it ever asked for the body."""

    status: int | None
    payload: dict | None
    messages: tuple
    reads: int


async def exchange(app, method: str, path: str, *, body: bytes = b'', headers: list | None = None,
                   forbid_body: bool = False, journal: Journal | None = None,
                   label: str = '') -> Reply:
    """Drive one `http` scope directly: no socket, no test client, nothing between us and `app`.

    `forbid_body` hands the handler a `receive()` that refuses to give up a chunk, which is how "this
    answer is reachable from the credential and the path alone" is tested rather than asserted; the read
    count is the same claim in numbers, and it is the claim that separates "we never read it" from
    "nobody offered it". When a journal is given, the exchange notes the instant its final body message
    arrived, so a response can be ordered against real background work.
    """
    messages, reads = [], []

    async def receive():
        if forbid_body:
            raise AssertionError(f'{label or path}: this answer must not await a body chunk')
        reads.append(1)
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        messages.append(message)
        if (journal is not None and message['type'] == 'http.response.body'
                and not message.get('more_body')):
            journal.note(f'response:{label or path}')

    scope = {'type': 'http', 'method': method, 'path': path,
             'headers': headers if headers is not None else [], 'query_string': b''}
    await app(scope, receive, send)
    payload = json.loads(messages[-1]['body']) if len(messages) > 1 else None
    return Reply(status=messages[0]['status'] if messages else None, payload=payload,
                 messages=tuple(messages), reads=len(reads))


@dataclasses.dataclass(frozen=True)
class AuditCall:
    """One observed `Store.record_refusal` call, plus everything about the caller that a test may ask.

    `args`/`kwargs` are what the background callable passed on, which is the only place a
    request-derived value could ride into a job: #135 fixes the inputs to one attempt word, the trusted
    `Actor` and `summary-only`, so this is how that sentence gets tested. Keyword spelling is the
    dispatcher's choice, so each field is read positionally *or* by its documented name.
    """

    args: tuple
    kwargs: dict
    thread_name: str
    on_main_thread: bool
    running_loop: asyncio.AbstractEventLoop | None

    def value(self, position: int, *keywords: str):
        for keyword in keywords:
            if keyword in self.kwargs:
                return self.kwargs[keyword]
        return self.args[position] if len(self.args) > position else None

    @property
    def attempt(self):
        return self.value(0, 'attempt')

    @property
    def actor(self):
        return self.value(1, 'actor')

    @property
    def reason(self):
        return self.value(2, 'reason')

    @property
    def subject(self):
        return self.value(3, 'subject')

    @property
    def values(self) -> list:
        return list(self.args) + list(self.kwargs.values())

    @property
    def rendered(self) -> str:
        return repr((self.args, self.kwargs))


class AuditSeam:
    """A narrow, observable stand-in for `Store.record_refusal` — the contract's only audit/SQL owner.

    Why this seam rather than the dispatcher: #135 fixes *what* the audit call is and *when* it returns,
    and explicitly leaves the dispatcher's own surface to be chosen. So every runtime observation is taken
    at the boundary the contract does fix — the arguments handed over, the thread that handed them over,
    whether that thread owned an event loop, and when the call really started and really returned. Nothing
    here imports, reads, subclasses or reorders the dispatcher, and `Store`'s classifier is never patched:
    the reason word that lands in the row stays the product's own.

    All modes record the same facts. They differ only in what the call then does:

    * `OBSERVE`     — call straight through, so the real SQL runs.
    * `PARK_WRITE`  — block until this file sets `release`, then call through: a write parked in SQL.
    * `PARK_SILENT` — block, then return without writing: occupancy with no row, so a shed can never be
      explained away as "the parked call wrote nothing, so the counter had nothing to count".
    * `EXPLODE`     — raise: an unexpected failure *of the call*, which is what the dispatch block's
      `failed` counts and what a store-handled database failure is not.

    A parked call never blocks forever: `release.wait` is bounded by `safety_timeout`, so an
    implementation that ran the audit inline on the serving loop costs this file a failed test with a
    sentence rather than a hung CI job.
    """

    OBSERVE = 'observe'
    PARK_WRITE = 'park-write'
    PARK_SILENT = 'park-silent'
    EXPLODE = 'explode'
    PARKED = (PARK_WRITE, PARK_SILENT)

    def __init__(self, mode: str = OBSERVE, *, journal: Journal | None = None, park_first: int = 1,
                 safety_timeout: float = SAFETY_TIMEOUT) -> None:
        self.mode = mode
        self.journal = journal if journal is not None else Journal()
        self.park_first = park_first
        self.safety_timeout = safety_timeout
        self.release = threading.Event()
        self.calls: list[AuditCall] = []
        self.starved: list[float] = []
        self.starts = 0
        self.finishes = 0
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()
        self._patch: patch | None = None
        self._real = Store.record_refusal

    # ------------------------------------------------------------------- installation
    def start(self) -> 'AuditSeam':
        if self._patch is not None:
            return self

        seam = self

        def record_refusal(store, *args, **kwargs):  # unbound: `store` arrives as the first argument
            return seam.handle(store, args, kwargs)

        self._patch = patch.object(Store, 'record_refusal', new=record_refusal)
        self._patch.start()
        return self

    def stop(self) -> None:
        if self._patch is not None:
            self.release.set()  # never leave a callable parked behind a removed patch
            self._patch.stop()
            self._patch = None

    # ------------------------------------------------------------------- observations
    def handle(self, store, args: tuple, kwargs: dict):
        thread = threading.current_thread()
        call = AuditCall(args=tuple(args), kwargs=dict(kwargs), thread_name=thread.name,
                         on_main_thread=thread is threading.main_thread(), running_loop=running_loop())
        with self._lock:
            self.calls.append(call)
            self.starts += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            ordinal = self.starts
        self.journal.note('audit:start')
        try:
            parked = self.mode in self.PARKED and ordinal <= self.park_first
            if parked:
                if not self.release.wait(timeout=self.safety_timeout):
                    with self._lock:
                        self.starved.append(self.safety_timeout)
                    raise TimeoutError('the injected audit callable was never released')
                self.journal.note('audit:released')
            if self.mode == self.EXPLODE:
                raise RuntimeError(f'{SENTINEL}: injected dispatcher call failure')
            if parked and self.mode == self.PARK_SILENT:
                return None
            return self._real(store, *args, **kwargs)
        finally:
            self.journal.note('audit:finish')
            with self._lock:
                self.active -= 1
                self.finishes += 1

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.calls)

    @property
    def running(self) -> bool:
        with self._lock:
            return self.active > 0

    @property
    def quiet(self) -> bool:
        with self._lock:
            return self.active == 0 and self.finishes == self.starts

    def last(self) -> AuditCall:
        with self._lock:
            return self.calls[-1]


class OwnershipSpy:
    """Journal the exclusive owner lock around the lifespan, delegating to the real lock.

    #135's shutdown rule is an ordering over three events this file could otherwise only infer: the
    admitted write finishing, the owner lock going back, and `shutdown.complete` being sent. Wrapping
    `api.exclusive_owner` and calling straight through to the real context manager makes the middle event
    observable *while still taking and releasing a real OS lock*. Nothing is replaced, and the counter
    pair says whether the lock was handed back twice, or never. `refuse` stands in for a boot that could
    not acquire ownership at all, where `__exit__` must not be reached.
    """

    def __init__(self, journal: Journal, *, refuse: BaseException | None = None) -> None:
        self.journal = journal
        self.refuse = refuse
        self.enters = 0
        self.exits = 0
        self._lock = threading.Lock()

    def install(self):
        """Return an unstarted `patch` object: the caller starts it and registers that same instance."""
        spy = self
        real_owner = api_module.exclusive_owner

        def factory(path):
            inner = real_owner(path)

            class Handle:
                def __init__(self):
                    self.taken = False

                def __enter__(self):
                    with spy._lock:
                        spy.enters += 1
                    spy.journal.note('owner:enter')
                    if spy.refuse is not None:
                        raise spy.refuse
                    entered = inner.__enter__()
                    self.taken = True
                    return entered

                def __exit__(self, *exc_info):
                    with spy._lock:
                        spy.exits += 1
                    spy.journal.note('owner:exit')
                    # A lock this process never took has nothing to hand back: only delegate what was
                    # actually acquired, so a refused acquisition cannot be reported as a release.
                    return inner.__exit__(*exc_info) if self.taken else None

            return Handle()

        return patch.object(api_module, 'exclusive_owner', new=factory)


class Lifespan:
    """Drive `scope['type'] == 'lifespan'` by hand, journalling every message the app sends.

    The shape follows `tests/test_regression_live_delivery.py`'s `drive`. The additions exist because this
    card's questions are ordering questions: each message is noted as it arrives (so `shutdown.complete`
    can be placed after the actual write and the actual lock release), shutdown can be *requested without
    waiting* (so "not yet" is observable rather than assumed), and the task can be cancelled (so a server
    giving up on the lifespan mid-drain is a case this file runs instead of one it writes off).
    """

    def __init__(self, app, journal: Journal) -> None:
        self.app = app
        self.journal = journal
        self.messages: asyncio.Queue = asyncio.Queue()
        self.task: asyncio.Task | None = None
        self._events: dict[str, asyncio.Event] = {}

    async def receive(self):
        return await self.messages.get()

    async def send(self, message):
        kind = message['type']
        self.journal.note(kind)
        self._events.setdefault(kind, asyncio.Event()).set()

    @property
    def shutdown_completed(self) -> bool:
        return self.journal.seen('lifespan.shutdown.complete')

    @property
    def pending(self) -> bool:
        return self.task is not None and not self.task.done()

    async def start(self, timeout: float = SAFETY_TIMEOUT) -> None:
        self.task = asyncio.create_task(self.app({'type': 'lifespan'}, self.receive, self.send))
        await self.messages.put({'type': 'lifespan.startup'})
        await self._settle('lifespan.startup.complete', timeout)

    def begin_shutdown(self) -> None:
        self.messages.put_nowait({'type': 'lifespan.shutdown'})

    async def finish_shutdown(self, timeout: float = SAFETY_TIMEOUT) -> None:
        await self._settle('lifespan.shutdown.complete', timeout)

    def cancel(self) -> None:
        if self.task is not None:
            self.task.cancel()

    async def settle(self) -> None:
        """Wait for the lifespan task to finish, letting a cancellation through and nothing else."""
        if self.task is None:
            return
        with contextlib.suppress(asyncio.CancelledError):
            await self.task

    async def close(self) -> None:
        """Never leave the task pending. A failure it raised has already been asserted by the test."""
        if self.task is not None and not self.task.done():
            self.task.cancel()
        if self.task is None:
            return
        try:
            await self.task
        except (asyncio.CancelledError, Exception):
            # Cleanup only: a test that cared about this failure already saw it through `_settle`, and a
            # task destroyed while pending would otherwise poison the next test's report.
            pass

    async def _settle(self, kind: str, timeout: float) -> None:
        event = self._events.setdefault(kind, asyncio.Event())
        waiter = asyncio.ensure_future(event.wait())
        done, _ = await asyncio.wait((self.task, waiter), timeout=timeout,
                                     return_when=asyncio.FIRST_COMPLETED)
        if event.is_set():
            with contextlib.suppress(asyncio.CancelledError):
                await waiter
            return
        waiter.cancel()
        if not done:
            raise AssertionError(f'{kind} never arrived within {timeout}s')
        if self.task is not None and self.task.done() and not self.task.cancelled():
            failure = self.task.exception()
            if failure is not None:
                raise failure
        raise AssertionError(f'the lifespan task ended before {kind} arrived (within {timeout}s)')


class LogCollector(logging.Handler):
    """Capture every record that survives its logger's level, whatever logger name the product chose.

    The dispatcher's logger name is the code worker's choice, so "no line per refusal" and "class name
    only, no payload, no traceback" cannot be tested against a name this file would have to guess.
    Attaching at the root logger catches any name; `product` narrows the capture to this package's own
    loggers, so an unrelated library's line can neither fail nor satisfy these assertions. Records below a
    logger's own level are not captured, which is the shipped behaviour rather than a filter here: the
    logging contract puts a traceback at DEBUG and the level is INFO, so what this file checks — that no
    WARNING or above carries caller text or a traceback — is exactly the surface an operator reads.
    """

    def __init__(self) -> None:
        super().__init__(level=0)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    @property
    def product(self) -> list[logging.LogRecord]:
        return [record for record in self.records
                if record.name == 'local_observe' or record.name.startswith('local_observe.')]

    @contextlib.contextmanager
    def captured(self):
        root = logging.getLogger()
        root.addHandler(self)
        try:
            yield self
        finally:
            root.removeHandler(self)
            self.close()


class WriteLock:
    """A real SQLite write transaction, held by another thread, released only when this file says so.

    This is main's reproduced condition supplied on purpose rather than waited for: `BEGIN IMMEDIATE` plus
    a real INSERT (rolled back at the end) makes a second writer's own `BEGIN IMMEDIATE` wait out its
    10-second busy timeout. Because the holder is this file's thread and the release is a
    `threading.Event` this file owns, "the audit is still inside SQL" is a property of the fixture and not
    a race — and the audit's own busy timeout is never the thing that bounds the test.
    """

    def __init__(self, path: Path, *, marker: str = 'concurrent-write-holder') -> None:
        self.path = path
        self.marker = marker
        self.held = threading.Event()
        self.release = threading.Event()
        self.released = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self.run, name='sqlite-write-holder', daemon=True)

    def run(self) -> None:
        connection = sqlite3.connect(self.path, timeout=SAFETY_TIMEOUT, isolation_level=None)
        try:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                               (utc_text(NOW), self.marker, 'fixture.write.lock', self.marker, '{}'))
            self.held.set()
            if not self.release.wait(timeout=SAFETY_TIMEOUT):
                raise TimeoutError('the test never released the held write lock')
        except BaseException as exc:  # handed back to the test, never swallowed
            self.error = exc
        finally:
            with contextlib.suppress(sqlite3.Error):
                if connection.in_transaction:
                    connection.execute('ROLLBACK')
            connection.close()
            self.released.set()

    def start(self, test: unittest.TestCase | None = None) -> 'WriteLock':
        self.thread.start()
        if test is not None:
            test.addCleanup(self.tidy)
        return self

    def tidy(self) -> None:
        """No test may leave a write lock held against the database the next one opens."""
        self.release.set()
        self.thread.join(timeout=SAFETY_TIMEOUT)


def read_audit_rows(path: Path, operation: str | None = None) -> list[dict]:
    """Read the audit table straight from the file, in write order, closing the connection explicitly.

    `with sqlite3.connect(...) as db` commits or rolls back a transaction; it does not close the handle,
    and a leaked handle in a shared test process is a locked database for whoever runs next. So: no
    connection context manager, one `try/finally`, one `close()`.
    """
    columns = ('sequence', 'at', 'actor', 'operation', 'subject', 'detail')
    where = '' if operation is None else ' WHERE operation=?'
    connection = sqlite3.connect(path, timeout=SAFETY_TIMEOUT)
    try:
        found = connection.execute(f'SELECT * FROM audit{where} ORDER BY sequence',
                                   () if operation is None else (operation,)).fetchall()
    finally:
        connection.close()
    return [dict(zip(columns, row)) for row in found]


class FrozenMonotonic:
    """The store's rate clock, deliberately never advanced: refusals spend the bucket, they do not refill."""

    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value


class OffLoopFixture:
    """A real `Store`, a real action policy, the app under test, and the helpers every test shares.

    Mixed into `TestCase` subclasses; it defines no tests. The store opens with an injected monotonic
    clock that this file never advances, so the write budget spends down and never refills: every test
    stays under `refusals.CAPACITY` refusals, the bucket is never what a test is failing on, and no test
    here can be rescued by a clock moving.

    The async entry point is `drive_async`, never `run`: `TestCase.run` belongs to unittest's runner, and
    shadowing it would either break collection or be a way to route around the runner.
    """

    def build(self, *, mode: str = 'off') -> Store:
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        self.root = Path(holder.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.journal = Journal()
        self.clock = FrozenMonotonic()
        self.store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode=mode),
                           refusal_clock=self.clock)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        self.incident = self.open_incident()
        self.approved_id = self.approve('offloop-approved')
        self._apps: list = []
        return self.store

    # ----------------------------------------------------------------- the app under test
    def app(self, store: Store | None = None):
        """Build an app over this fixture's store. `create_app` re-digests the tree: build it once."""
        created = create_app(store if store is not None else self.store, CREDENTIALS, self.policy)
        self._apps.append(created)
        return created

    def shared_app(self):
        """The one app a test needs, built lazily so the first call owns the digest cost."""
        if not self._apps:
            self.app()
        return self._apps[0]

    def seam(self, mode: str = AuditSeam.OBSERVE, *, park_first: int = 1) -> AuditSeam:
        installed = AuditSeam(mode, journal=self.journal, park_first=park_first).start()
        self.addCleanup(installed.stop)
        return installed

    def spy_ownership(self, *, refuse: BaseException | None = None) -> OwnershipSpy:
        """Install the ownership wrapper for the whole test: one started patch, stopped by that instance."""
        spy = OwnershipSpy(self.journal, refuse=refuse)
        installed = spy.install()
        installed.start()
        self.addCleanup(installed.stop)
        return spy

    # ----------------------------------------------------------------- async conveniences
    async def dispatch(self, app) -> dict:
        """One memory-only read of the dispatch block, with the status checked where it is read."""
        reply = await bounded(exchange(app, 'GET', '/v1/runtime', headers=bearer(READER)),
                              SAFETY_TIMEOUT, what='GET /v1/runtime to answer')
        self.assertEqual(reply.status, 200, f'a memory-only read stopped being a 200: {reply.payload}')
        self.assertIn('refusal_audit_dispatch', reply.payload)
        return reply.payload['refusal_audit_dispatch']

    async def refuse(self, app, path: str, *, label: str, forbid_body: bool = False,
                     body: bytes | None = None) -> Reply:
        """One summary write denial, with the only answer it may get checked at the point of use."""
        reply = await exchange(app, 'POST', path, journal=self.journal, label=label,
                               forbid_body=forbid_body, headers=bearer(SUMMARY.identity),
                               body=(b'{"anything": "' + SENTINEL.encode() + b'"}'
                                     if body is None else body))
        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}),
                         f'a refusal stopped being this status with these exact bytes: {reply}')
        return reply

    def drive_async(self, coroutine):
        """Run one scenario on its own loop — the file's only entry point into `asyncio.run`."""
        return asyncio.run(coroutine)

    # ----------------------------------------------------------------- lifecycle (one test needs it)
    def event(self, minute: int = 0, status: str = 'firing') -> dict:
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        return detections.event(PRODUCER.identity, self.host, 'availability', 'availability', status,
                                window, {'sample_id': f'offloop-{minute}'}, query_type='gatus-result')

    def open_incident(self, minute: int = 0) -> dict:
        return self.store.intake(self.event(minute), PRODUCER, now=NOW + dt.timedelta(minutes=minute))

    def approve(self, retry_key: str) -> str:
        document = {'retry_key': retry_key, 'incident_id': self.incident['incident_id'],
                    'action': 'inspect', 'version': '1', 'targets': [self.host], 'parameters': {},
                    'evidence': [self.incident['event_id']],
                    'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        action_id = self.store.propose_action(document, AGENT, self.policy, now=NOW)['action_id']
        self.store.decide(action_id, 'approved', HUMAN, now=NOW)
        return action_id

    # ----------------------------------------------------------------- shared assertions
    def assert_counters(self, block: dict, *, admitted: int, overloaded: int, failed: int = 0,
                        in_flight: int = 0) -> None:
        """Compare the dispatch counters as one snapshot, with the field named on failure."""
        self.assertEqual(int(block['capacity']), 1, 'the dispatcher promised capacity 1')
        self.assertEqual(int(block['in_flight']), in_flight, f'in_flight was {block["in_flight"]}')
        self.assertEqual(int(block['admitted']), admitted, f'admitted was {block["admitted"]}')
        self.assertEqual(int(block['overloaded']), overloaded, f'overloaded was {block["overloaded"]}')
        self.assertEqual(int(block['failed']), failed, f'failed was {block["failed"]}')

    def refusal_rows(self) -> list[dict]:
        return read_audit_rows(self.store.path, refusals.OPERATION)

    def store_counters(self) -> dict:
        return self.store.refusal_audit_status()


class DispatcherObservationTests(unittest.TestCase, OffLoopFixture):
    """What an operator can read, what the loop is asked to do, and what no request may write."""

    def setUp(self):
        self.build()

    def test_runtime_adds_one_dispatch_block_and_widens_nothing_else(self):
        """The whole new surface is one key with nine fields, and `Store.status()` did not move.

        `capacity` is the bound #135 chose, `scope` names the only thing the counters can be trusted to
        count, and `saturated` is the field that says whether a number is a total or a floor. An extra
        field here is as much a contract change as a missing one: the published shape is `capacity:1,
        in_flight:0|1, admitted, overloaded, failed, closed, scope:'app-local', resets_on_restart:true,
        saturated`, and `GET /v1/runtime` was to add `refusal_audit_dispatch` **only**.
        """
        app = self.shared_app()
        reply = self.drive_async(exchange(app, 'GET', '/v1/runtime', headers=bearer(READER)))
        self.assertEqual(reply.status, 200)
        runtime = reply.payload
        self.assertEqual(set(runtime), set(RUNTIME_KEYS),
                         f'GET /v1/runtime changed shape: {sorted(set(runtime) ^ set(RUNTIME_KEYS))}')
        block = runtime['refusal_audit_dispatch']
        self.assertEqual(set(block), set(DISPATCH_KEYS),
                         f'the dispatch block changed shape: {sorted(set(block) ^ set(DISPATCH_KEYS))}')
        self.assertEqual(int(block['capacity']), 1)
        self.assertEqual(int(block['in_flight']), 0, 'an idle app claimed work it was not doing')
        self.assertLessEqual(int(block['in_flight']), int(block['capacity']))
        self.assertEqual(block['scope'], 'app-local', "one app's dispatcher cannot speak for another's")
        self.assertIs(block['resets_on_restart'], True)
        self.assertEqual(block['saturated'], [],
                         'a fresh app named a counter it had not yet reached the ceiling of')
        for name in DISPATCH_COUNTERS:
            self.assertIsInstance(block[name], int, f'{name} stopped being an integer')
            self.assertNotIsInstance(block[name], bool, f'{name} is a counter, not a flag')
            self.assertEqual(block[name], 0, f'a fresh app reported {name} traffic it never saw')
        # `closed` is a state, not a tally: strict bool, so it can never be read as a count of sheds.
        self.assertIsInstance(block['closed'], bool)
        self.assertIs(block['closed'], False, 'an app that never shut down reported itself closed')
        self.assertEqual(sorted(self.store.status()),
                         ['actions', 'incidents', 'notifications', 'schema_version'],
                         'Store.status() was widened, and its exact shape is pinned elsewhere')
        self.assertNotIn(SENTINEL, json.dumps(runtime))

    def test_the_memory_runtime_read_opens_no_database_connection(self):
        """`refusal_audit_dispatch` is a counter read, so polling it may not cost a connection.

        The control inside the same patch is what makes the zero mean anything: `/v1/status` is the
        sibling read that *is* a query. If the wrapped `connect` never counted, the first assertion would
        be measuring a broken counter rather than a database-free path.
        """
        app = self.shared_app()
        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            reply = self.drive_async(exchange(app, 'GET', '/v1/runtime', headers=bearer(READER)))
            self.assertEqual((reply.status, 'refusal_audit_dispatch' in reply.payload), (200, True))
            self.assertEqual(connect.call_count, 0, 'a memory-only runtime read opened the database')
            control = self.drive_async(exchange(app, 'GET', '/v1/status', headers=bearer(READER)))
        self.assertEqual(control.status, 200)
        self.assertGreater(connect.call_count, 0, 'the control read opened no connection either')

    def test_an_admitted_summary_refusal_is_durable_before_its_403_completes(self):
        """The 403 is a receipt, and it is only honest once the row is committed.

        Four routes, four awaited denials: the row is already in the file at the moment the response body
        is sent, the callable finished before that response was journaled, and nothing was queued or shed.
        This is the "admitted row persisted before 403" acceptance item through real ASGI over a real
        `Store`, with no seam standing between the handler and the file.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)
        routes = list(REFUSAL_POST_ROUTES.items())

        async def scenario():
            for position, (path, attempt) in enumerate(routes, start=1):
                with self.subTest(path=path):
                    before = len(self.refusal_rows())
                    reply = await self.refuse(app, path, label=path)
                    self.assertEqual(reply.reads, 0, 'a role gate awaited a body chunk')
                    written = self.refusal_rows()[before:]
                    self.assertEqual(len(written), 1, 'the 403 completed before its row was durable')
                    self.assertEqual(json.loads(written[0]['detail']),
                                     {'attempt': attempt, 'reason': refusals.SUMMARY_ONLY,
                                      'role': 'summary'})
                    self.assertEqual((written[0]['actor'], written[0]['subject']),
                                     (SUMMARY.identity, refusals.UNBOUND))
                    self.assertTrue(self.journal.last_before('audit:finish', f'response:{path}'),
                                    'the response was sent while its own audit attempt was still running')
                    self.assert_counters(await self.dispatch(app), admitted=position, overloaded=0,
                                         in_flight=0)

        self.drive_async(scenario())
        self.assertEqual(seam.max_active, 1, 'two audited writes ran at once')
        self.assertEqual(len(self.refusal_rows()), len(routes))
        counters = self.store_counters()
        self.assertEqual((counters['written'], counters['dropped'], counters['failed'],
                          counters['unauditable']), (len(routes), 0, 0, 0))

    def test_the_audit_callable_never_runs_on_the_serving_event_loop(self):
        """The write is off the loop by observation, not by a comment or a code shape.

        Two independent facts, because either alone can be faked: the callable's thread is not the thread
        the loop runs on, and that thread owns no running loop. An implementation that kept the audit
        inline — or that moved it into a second coroutine on the same loop — fails here while still
        returning the same status, the same body and the same row.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)
        reply = self.drive_async(self.refuse(app, '/v1/actions/claim', label='claim', forbid_body=True))
        self.assertEqual(reply.reads, 0, 'the answer needed the body on the way out')
        self.assertEqual(seam.count, 1)
        call = seam.last()
        self.assertFalse(call.on_main_thread,
                         f'the audit ran on the process thread that owns the loop ({call.thread_name})')
        self.assertIsNone(call.running_loop,
                          f'the audit ran on a thread that owns an event loop ({call.thread_name})')
        self.assertEqual(len(self.refusal_rows()), 1)
        self.assertEqual(self.store_counters()['written'], 1)

    def test_the_four_refusal_routes_answer_without_ever_reading_the_body(self):
        """`receive()` is never awaited on this path, for any of the four routes.

        The bytes are offered as a real chunk in the counting half and refused outright in the tripwire
        half, so "we did not read it" is distinguished from "nobody offered us a body": same route, same
        credential, two different `receive()` implementations, one answer. Unusable bytes stay a
        summary-role denial rather than becoming a parser or size verdict — the precedence #122 fixed and
        #135 kept, which is why none of these branches parses anything.
        """
        app = self.shared_app()
        unusable = (b'{"' + SENTINEL.encode() + b'": "body nobody may parse"}', b'{broken',
                    b'[' + SENTINEL.encode() + b']' + b' ' * 70_000)

        async def scenario():
            for path, attempt in REFUSAL_POST_ROUTES.items():
                for sample, raw in enumerate(unusable):
                    with self.subTest(path=path, body=sample, receive='counted'):
                        reply = await exchange(app, 'POST', path, body=raw,
                                               headers=bearer(SUMMARY.identity))
                        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
                        self.assertEqual(reply.reads, 0, 'the gate awaited a chunk it does not need')
                        self.assertEqual(json.loads(self.refusal_rows()[-1]['detail']),
                                         {'attempt': attempt, 'reason': refusals.SUMMARY_ONLY,
                                          'role': 'summary'})
                    with self.subTest(path=path, body=sample, receive='refused'):
                        tripwire = await self.refuse(app, path, label=path, forbid_body=True)
                        self.assertEqual(tripwire.reads, 0)

        self.drive_async(scenario())
        self.assertEqual(len(self.refusal_rows()), 2 * len(unusable) * len(REFUSAL_POST_ROUTES))
        self.assertNotIn(SENTINEL, json.dumps(self.refusal_rows()))

    def test_the_job_carries_only_the_fixed_word_the_trusted_actor_and_the_one_reason(self):
        """No body, header, subject or caller-controlled field is retained as a job input.

        The planted text rides in the body *and* in two headers, and the arguments the dispatcher actually
        handed over are then read back: one attempt word from the route table, an `Actor` equal to the one
        the bearer credential decided, `summary-only`, and a subject that names no durable row. Every
        value handed over is a `str`, the trusted `Actor`, or `None` — the types a request could not
        invent — and the planted word appears nowhere in them, nor in the row that came out of it.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)
        headers = bearer(SUMMARY.identity) + [(b'x-identity', SENTINEL.encode()),
                                             (b'content-type', SENTINEL.encode())]
        body = json.dumps({'action_id': SENTINEL, 'decision': SENTINEL, 'actor': SENTINEL,
                           'role': 'human', 'approver': SENTINEL, 'url': SENTINEL}).encode()
        reply = self.drive_async(exchange(app, 'POST', '/v1/actions/decision', body=body, headers=headers))
        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
        self.assertEqual(seam.count, 1)
        call = seam.last()
        self.assertEqual(call.attempt, REFUSAL_POST_ROUTES['/v1/actions/decision'])
        self.assertEqual(call.reason, refusals.SUMMARY_ONLY)
        self.assertEqual(call.actor, SUMMARY,
                         'the identity written down was not the credential that was refused')
        self.assertIsInstance(call.actor, Actor)
        self.assertIn(call.subject, (None, refusals.UNBOUND),
                      'a subject the caller typed rode along into the audit')
        for value in call.values:
            self.assertTrue(value is None or isinstance(value, (str, Actor, dt.datetime)),
                            f'a {type(value).__name__} from the request became a job input')
        self.assertNotIn(SENTINEL, call.rendered)
        rows = self.refusal_rows()
        self.assertEqual(len(rows), 1)
        self.assertNotIn(SENTINEL, json.dumps(rows))

    def test_nothing_unauthorised_or_unaudited_reaches_the_dispatcher_at_all(self):
        """A stranger is never a writer, and a route outside the four is never a job.

        The 401 batch is checked at the strongest point available — no database connection was even
        opened, and every dispatcher counter stayed exactly where it was. The non-audited summary routes
        keep their write-free 403 exactly as #122 left them: #135 moved one branch off the loop and
        changed nothing about which refusals are auditable at all.
        """
        app = self.shared_app()
        rejected = (('no authorization header', '/v1/actions/decision', [], 401),
                    ('wrong bearer', '/v1/actions',
                     [(b'authorization', b'Bearer nope-nope-nope-nope-000000')], 401),
                    ('empty bearer', '/v1/actions/claim', [(b'authorization', b'Bearer ')], 401),
                    ('scheme spelled wrong', '/v1/executions/outcome',
                     [(b'authorization', ('Token ' + TOKENS[SUMMARY.identity]).encode())], 401),
                    ('two authorization values', '/v1/actions/claim',
                     bearer(SUMMARY.identity) + bearer(HUMAN.identity), 401))

        async def scenario():
            for name, path, headers, expected in rejected:
                with self.subTest(case=name):
                    reply = await exchange(app, 'POST', path, body=b'{"anything": 1}', headers=headers)
                    self.assertEqual((reply.status, reply.payload),
                                     (expected, {'error': 'authentication_required'}))
            for path in ('/v1/events', '/v1/notifications/retry', '/v1/notifications/reset-safety',
                         '/v1/callbacks/primary'):
                with self.subTest(route=path):
                    reply = await exchange(app, 'POST', path, body=b'{"anything": 1}',
                                           headers=bearer(SUMMARY.identity))
                    self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
            reply = await exchange(app, 'GET', '/v1/status', headers=bearer(SUMMARY.identity))
            self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
            self.assert_counters(await self.dispatch(app), admitted=0, overloaded=0, in_flight=0)

        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            self.drive_async(scenario())
        self.assertEqual(connect.call_count, 0, 'a request the dispatcher must not see opened state')
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual({name: self.store_counters()[name] for name in refusals.COUNTERS},
                         dict.fromkeys(refusals.COUNTERS, 0))

    def test_a_state_layer_refusal_stays_synchronous_and_costs_no_dispatch_counter(self):
        """Only the transport's own summary branch moved; the four lifecycle methods did not.

        A wrong-role decision is a `Store` refusal, and #135 defers it explicitly. So its row is durable
        before the 400 completes, it was written on the calling thread — the same stack that raised — and
        the dispatcher never saw it. "The refactor stayed in its lane" is asserted here as a thread fact
        rather than as a code shape, so it keeps meaning the same thing after the dispatcher is renamed.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)

        async def scenario():
            reply = await exchange(app, 'POST', '/v1/actions/decision',
                                   body=json.dumps({'action_id': self.approved_id,
                                                    'decision': 'approved'}).encode(),
                                   headers=bearer(AGENT.identity))
            self.assertEqual((reply.status, reply.payload),
                             (400, {'error': 'not_authorised',
                                    'detail': 'Actor is not authorised for this operation'}))
            self.assert_counters(await self.dispatch(app), admitted=0, overloaded=0, in_flight=0)

        self.drive_async(scenario())
        self.assertEqual(seam.count, 1)
        call = seam.last()
        self.assertTrue(call.on_main_thread,
                        f'a normal action Store call was deferred off the loop ({call.thread_name})')
        self.assertIsNotNone(call.running_loop, 'the state layer stopped running inside its own caller')
        rows = self.refusal_rows()
        self.assertEqual(len(rows), 1, 'the state-layer row was not durable when its 400 completed')
        self.assertEqual(json.loads(rows[0]['detail']),
                         {'attempt': 'decide', 'reason': 'actor-not-authorised', 'role': 'proposer'})
        self.assertEqual(self.store_counters()['written'], 1)

    def test_two_apps_over_one_store_do_not_share_dispatcher_counters(self):
        """The bound is per `create_app` instance; the write budget stays per `Store`.

        A leaked `admitted`/`in_flight` would make one busy app the reason a second app sheds, and a
        *shared* bucket would be a rate limit across processes that the counters do not describe. Both
        halves in one run: one refusal each, two rows, and an untouched counter set on the app that did
        nothing.
        """
        first, second = self.app(), self.app()
        seam = self.seam(AuditSeam.OBSERVE)

        async def scenario():
            await self.refuse(first, '/v1/actions/claim', label='first-app')
            return await self.dispatch(second), await self.dispatch(first)

        untouched, busy = self.drive_async(scenario())
        self.assert_counters(untouched, admitted=0, overloaded=0, in_flight=0)
        self.assert_counters(busy, admitted=1, overloaded=0, in_flight=0)
        self.assertEqual(untouched['scope'], busy['scope'])
        self.assertEqual(len(self.refusal_rows()), 1)
        self.assertEqual(self.store_counters()['written'], 1)
        self.drive_async(self.refuse(second, '/v1/actions', label='second-app'))
        self.assert_counters(self.drive_async(self.dispatch(second)), admitted=1, overloaded=0, in_flight=0)
        self.assert_counters(self.drive_async(self.dispatch(first)), admitted=1, overloaded=0, in_flight=0)
        self.assertEqual(len(self.refusal_rows()), 2)
        self.assertEqual(seam.max_active, 1)

    def test_a_bounded_refusal_costs_no_log_line(self):
        """No line per refusal: the durable row and the counters are the record.

        Captured at the root logger so it holds whatever name the dispatcher's logger ends up with, then
        narrowed to `local_observe.*` so an unrelated library can neither fail nor satisfy it. The shed
        path is pinned in `DispatcherCapacityTests`, because a flood is where an unbounded line would
        actually cost something.
        """
        app = self.shared_app()
        self.seam(AuditSeam.OBSERVE)
        collector = LogCollector()
        with collector.captured():
            self.drive_async(self.refuse(app, '/v1/actions/decision', label='decide'))
        self.assertEqual([record.getMessage() for record in collector.product], [],
                         'a refusal cost a log line')


class DispatcherCapacityTests(unittest.TestCase, OffLoopFixture):
    """Capacity 1, shedding, cancellation and failure — with the write parked on purpose."""

    def setUp(self):
        self.build()

    def test_a_real_sqlite_write_lock_does_not_delay_a_memory_only_read(self):
        """#135's reproduction as a test: a held write lock must not reach `GET /v1/runtime`.

        The parked audit is *real SQL* waiting on *real* `BEGIN IMMEDIATE` contention, and the 403 is
        still outstanding when the probe lands, so this is the exact shape main measured at two seconds on
        the baseline. The read gets a bound shorter than that measurement, and this file releases the held
        lock only after the read has been observed — so the read cannot have been rescued by the
        contention going away on its own.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)
        holder = WriteLock(self.store.path).start(self)
        self.assertTrue(holder.held.wait(timeout=SAFETY_TIMEOUT), 'the write lock was never acquired')

        async def scenario():
            pending = asyncio.create_task(self.refuse(app, '/v1/actions', label='parked-by-lock'))
            try:
                await wait_until(lambda: seam.starts >= 1 and seam.running,
                                 what='the admitted audit to be inside its SQL')
                reply = await bounded(exchange(app, 'GET', '/v1/runtime', headers=bearer(READER)),
                                      MEMORY_READ_WINDOW,
                                      what='the memory-only GET /v1/runtime while SQL was parked')
                self.assertFalse(pending.done(),
                                 'the 403 completed while its audit was still waiting on the write lock')
                self.assertEqual(int(reply.payload['refusal_audit_dispatch']['in_flight']), 1,
                                 'the read answered, but the parked write had already been forgotten')
                # The read is observed; only now may the contention go away, so it cannot have rescued it.
                holder.release.set()
                await wait_until(holder.released.is_set, what='the write lock to go')
                outcome = await bounded(pending, SAFETY_TIMEOUT, what='the admitted 403 to complete')
                return reply, outcome
            finally:
                holder.release.set()  # the lock is this file's to give back, whatever the probe decided
                await quiet_within(holder.released.is_set)
                if not pending.done():
                    pending.cancel()

        reply, outcome = self.drive_async(scenario())
        self.assertEqual(reply.status, 200, 'the memory read did not answer at all')
        self.assertEqual(outcome.status, 403)
        self.assert_counters(self.drive_async(self.dispatch(app)), admitted=1, overloaded=0, in_flight=0)
        self.assertEqual(len(self.refusal_rows()), 1, 'the parked write never arrived')
        counters = self.store_counters()
        self.assertEqual((counters['written'], counters['failed'], counters['dropped']), (1, 0, 0))
        self.assertIsNone(holder.error, 'the fixture holding the write lock failed')

    def test_one_parked_write_admits_one_request_and_the_rest_are_shed_without_a_queue(self):
        """Eight denials arrive while one row is stuck in SQL: one admitted, eight shed, one call.

        Everything the contract says about overload, measured in the same breath:

        * the shed requests finish *before* the parked one, so not one of them queued behind it;
        * they answer the same 403 bytes without reading a body and without a `failed` count;
        * `overloaded` counted all eight, no bucket token was spent (`dropped` stays zero and the token
          level shows exactly one spend), and the eight cost no connections of their own: at most one in
          the whole window, which can only be the parked write's own;
        * the parked callable had no company — `max_active` is 1.

        Concurrency overload loses rows. The 403 those eight received is **not** evidence that their
        refusals are durable, and `overloaded` is the only thing that says so.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)
        holder = WriteLock(self.store.path).start(self)
        self.assertTrue(holder.held.wait(timeout=SAFETY_TIMEOUT), 'the write lock was never acquired')

        async def scenario():
            admitted = asyncio.create_task(self.refuse(app, '/v1/actions/claim', label='parked-write'))
            try:
                await wait_until(lambda: seam.starts >= 1, what='one admitted audit attempt')
                with patch('local_observe.platform.state.sqlite3.connect',
                           wraps=sqlite3.connect) as connect:
                    flood = [asyncio.create_task(
                        self.refuse(app, '/v1/executions/outcome', label=f'shed-{slot}',
                                    forbid_body=True)) for slot in range(8)]
                    done, pending = await asyncio.wait(flood, timeout=SAFETY_TIMEOUT)
                    connections = connect.call_count
                    for task in pending:
                        task.cancel()  # never hand a still-waiting denial to a loop that is about to close
                    for task in done:
                        task.result()  # surface an assertion raised inside a shed exchange; never lose one
                self.assertEqual(pending, set(), 'a denied request is still waiting for a dispatcher slot')
                self.assertEqual(len(done), 8)
                self.assertFalse(admitted.done(), 'the admitted request answered before its write did')
                self.assertEqual(seam.count, 1, 'a shed request became an audit call anyway')
                # Zero is the clean answer and one is the parked write's own connection, opened a moment
                # after this window began: either way, eight denials must not cost eight connections.
                self.assertLessEqual(connections, 1,
                                     'the shed denials opened database connections for work nobody admitted')
                busy = await self.dispatch(app)
                holder.release.set()
                outcome = await bounded(admitted, SAFETY_TIMEOUT, what='the admitted 403 after the release')
                return busy, outcome
            finally:
                holder.release.set()  # release the gate first, then let the drain finish quietly
                await quiet_within(holder.released.is_set)
                if not admitted.done():
                    admitted.cancel()

        busy, outcome = self.drive_async(scenario())
        self.assertEqual((outcome.status, outcome.payload), (403, {'error': 'summary_only'}))
        self.assertEqual(int(busy['overloaded']), 8, 'a shed denial went uncounted')
        self.assertEqual(int(busy['in_flight']), 1,
                         'capacity was freed while SQL still waited on the write lock')
        self.assertEqual(int(busy['failed']), 0, 'an expected overload counted as a dispatcher failure')
        self.assertTrue(self.journal.ordered('response:shed-0', 'audit:finish'),
                        'a shed denial finished after the parked one — that is a queue')
        self.assertEqual(seam.max_active, 1, 'two audit callables ran at once')
        self.assertEqual(len(self.refusal_rows()), 1, 'the overload grew rows behind the parked one')
        counters = self.store_counters()
        self.assertEqual((counters['written'], counters['dropped'], counters['failed']), (1, 0, 0),
                         'a dispatcher rejection spent the store write budget')
        self.assertEqual(counters['tokens_available'], refusals.CAPACITY - 1,
                         'the bucket was charged for refusals that never became work')
        self.assert_counters(self.drive_async(self.dispatch(app)), admitted=1, overloaded=8, in_flight=0)
        self.assertIsNone(holder.error)

    def test_capacity_is_released_by_the_callable_returning_and_not_by_the_response(self):
        """While the injected callable has not returned, the app is busy — whatever else happened.

        `in_flight` is read through a second request on the serving loop, so this also pins that the
        accounting crosses threads under a lock instead of being per-loop memory. The parked call writes
        nothing and still returns normally, so a shed here cannot be blamed on a row that had not been
        counted yet, and a plain `None` return must not be mistaken for a failure.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.PARK_SILENT)

        async def scenario():
            parked = asyncio.create_task(self.refuse(app, '/v1/actions', label='parked'))
            try:
                await wait_until(lambda: seam.starts >= 1, what='the parked audit to start')
                self.assertEqual(int((await self.dispatch(app))['in_flight']), 1)
                busy = await bounded(self.refuse(app, '/v1/actions/decision', label='while-parked'),
                                     IMMEDIATE_WINDOW, what='the second denial to be shed at once')
                self.assertEqual(busy.status, 403)
                self.assertEqual(seam.count, 1, 'the second denial was queued into an audit call')
                self.assert_counters(await self.dispatch(app), admitted=1, overloaded=1, in_flight=1)
                seam.release.set()
                await wait_until(lambda: seam.quiet, what='the parked callable to return')
                await bounded(parked, SAFETY_TIMEOUT, what='the parked 403 to complete')
                return await self.dispatch(app)
            finally:
                seam.release.set()  # the gate goes first, so the drain below can only finish, not hang
                await quiet_within(lambda: seam.quiet)
                if not parked.done():
                    parked.cancel()

        block = self.drive_async(scenario())
        self.assert_counters(block, admitted=1, overloaded=1, in_flight=0)
        self.assertEqual(seam.starved, [], 'the parked callable hit its own safety timeout')
        self.assertEqual(self.refusal_rows(), [], 'the parked call wrote a row it never attempted')
        self.assertEqual(self.store_counters()['written'], 0)
        self.assertEqual(self.store_counters()['failed'], 0,
                         'a normal return was booked as a store audit failure')
        seam.stop()
        self.drive_async(self.refuse(app, '/v1/executions/outcome', label='capacity-back'))
        self.assert_counters(self.drive_async(self.dispatch(app)), admitted=2, overloaded=1, in_flight=0)
        self.assertEqual(len(self.refusal_rows()), 1, 'capacity never came back to the dispatcher')

    def test_cancelling_an_admitted_request_frees_neither_capacity_nor_the_running_write(self):
        """The client gave up; the SQL did not, and neither may become free early.

        The awaited request is cancelled while its callable is parked. Three things must survive, in this
        order: capacity is still occupied (`in_flight: 1`, and the next denial is shed rather than
        admitted), the cancelled attempt still commits its row once released, and that row is counted as an
        ordinary write rather than some new word for "orphaned".
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.PARK_WRITE)

        async def scenario():
            admitted = asyncio.create_task(self.refuse(app, '/v1/actions', label='cancelled-client'))
            try:
                await wait_until(lambda: seam.starts >= 1 and seam.running,
                                 what='the admitted audit to start')
                admitted.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await admitted
                block = await self.dispatch(app)
                self.assertEqual(int(block['in_flight']), 1,
                                 'cancelling the awaiting request freed capacity while SQL was running')
                shed = await bounded(self.refuse(app, '/v1/actions/claim', label='after-cancel'),
                                     IMMEDIATE_WINDOW, what='the next denial to be shed')
                self.assertEqual(shed.status, 403,
                                 'a slot freed by cancellation let a second write into a busy dispatcher')
                self.assert_counters(await self.dispatch(app), admitted=1, overloaded=1, in_flight=1)
                seam.release.set()
                await wait_until(lambda: seam.quiet, what="the cancelled attempt's SQL to finish")
                return await self.dispatch(app)
            finally:
                seam.release.set()  # release the gate first, then let the released write finish
                await quiet_within(lambda: seam.quiet)

        block = self.drive_async(scenario())
        self.assertEqual(len(self.refusal_rows()), 1,
                         'a cancelled client lost the audit row that had already been admitted')
        self.assertEqual(self.store_counters()['written'], 1)
        self.assertEqual(int(block['in_flight']), 0, 'the capacity never came back after the work ended')
        self.assertEqual(int(block['admitted']), 1)
        self.assertEqual(int(block['overloaded']), 1)
        self.assertEqual(int(block['failed']), 0, 'a cancelled client was counted as a dispatcher failure')

    def test_an_unexpected_call_failure_keeps_the_403_counts_failed_once_and_frees_capacity(self):
        """A dispatcher-side failure is counted apart, retried never, and cannot eat the response.

        `Store.record_refusal` handles its own database failures and books them in its own counters; what
        the dispatch block's `failed` counts is a submission or call that blew up on the way. The injected
        failure raises *before* the store's code runs, so the separation is measured rather than argued:
        the store's four counters stay at zero, no connection is opened, no retry happens, and two
        failures cost one line — naming the exception class, no payload, no traceback.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.EXPLODE)
        collector = LogCollector()
        with collector.captured(), patch('local_observe.platform.state.sqlite3.connect',
                                         wraps=sqlite3.connect) as connect:
            first = self.drive_async(self.refuse(app, '/v1/actions/decision', label='failed-1'))
            second = self.drive_async(self.refuse(app, '/v1/actions/claim', label='failed-2'))
            block = self.drive_async(self.dispatch(app))
            connections = connect.call_count
        self.assertEqual((first.status, second.status), (403, 403))
        self.assertEqual(seam.count, 2, 'one failed attempt was retried into a second one')
        self.assertEqual(int(block['failed']), 2, 'each unexpected call failure must count itself')
        self.assertEqual(int(block['in_flight']), 0, 'a failure left the dispatcher busy forever')
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual({name: self.store_counters()[name] for name in refusals.COUNTERS},
                         dict.fromkeys(refusals.COUNTERS, 0),
                         'a dispatcher failure was booked into the store counters')
        self.assertEqual(connections, 0, 'a failed submission reached for the database')
        warnings = [record for record in collector.product if record.levelno >= logging.WARNING]
        self.assertEqual(len(warnings), 1,
                         f'two failures cost {len(warnings)} lines: '
                         f'{[record.getMessage() for record in warnings]}')
        line = warnings[0]
        rendered = ' '.join(str(value) for value in vars(line).values() if value != line.msg)
        self.assertNotIn(SENTINEL, rendered, 'the failure line carried caller text')
        self.assertIsNone(line.exc_info, 'a traceback rode on the failure log')
        self.assertIn('RuntimeError', rendered + line.getMessage(),
                      'the throttled failure line named nothing about what failed')
        seam.stop()
        self.drive_async(self.refuse(app, '/v1/actions', label='after-failures'))
        self.assertEqual(len(self.refusal_rows()), 1, 'capacity did not survive the failures')
        self.assertEqual(self.store_counters()['written'], 1)
        # Three submissions reached an executor: the two that failed inside the callable were admitted
        # too, which is what separates `failed` from `overloaded`. Only the shed path never got a slot.
        self.assert_counters(self.drive_async(self.dispatch(app)), admitted=3, overloaded=0, failed=2,
                             in_flight=0)

    def test_a_shed_flood_costs_no_log_line_either(self):
        """The overload path is silent too, and the flood is where a per-refusal line would hurt.

        Eight immediate 403s while one write is parked must not become eight lines, or one line per retry
        of anything: the shed counter is the record of the overload.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.PARK_SILENT)
        collector = LogCollector()

        async def scenario():
            parked = asyncio.create_task(self.refuse(app, '/v1/actions', label='silent-parked'))
            try:
                await wait_until(lambda: seam.starts >= 1, what='the parked audit')
                with collector.captured():
                    flood = [asyncio.create_task(self.refuse(app, route, label=f'silent-{slot}',
                                                             forbid_body=True))
                             for slot, route in enumerate(REFUSAL_POST_ROUTES) for _ in range(2)]
                    done, pending = await asyncio.wait(flood, timeout=SAFETY_TIMEOUT)
                    for task in pending:
                        task.cancel()
                    for task in done:
                        task.result()
                    self.assertEqual(pending, set(), 'a shed request waited for a dispatcher slot')
                    block = await self.dispatch(app)
                seam.release.set()
                await bounded(parked, SAFETY_TIMEOUT, what='the parked 403')
                return block
            finally:
                seam.release.set()  # the gate goes first, so the drain below cannot be the thing that hangs
                await quiet_within(lambda: seam.quiet)
                if not parked.done():
                    parked.cancel()

        block = self.drive_async(scenario())
        self.assertEqual([record.getMessage() for record in collector.product], [],
                         'a shed refusal cost a log line')
        self.assert_counters(block, admitted=1, overloaded=8, in_flight=1)

    def test_the_dispatch_block_stays_coherent_under_a_concurrent_flood(self):
        """Whatever the interleaving, every denial is counted exactly once and never twice.

        Twelve denials arrive at one app in a single loop. The interesting failure is a lost or doubled
        update in the accounting, and a conservation identity catches both without knowing how admission
        is implemented: `admitted + overloaded + failed` equals the number of denials, and the one
        admitted attempt is the only one that ever reached SQL.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.PARK_WRITE)

        async def scenario():
            parked = asyncio.create_task(self.refuse(app, '/v1/actions', label='coherent-parked'))
            try:
                await wait_until(lambda: seam.starts >= 1, what='the parked admission')
                rest = [asyncio.create_task(self.refuse(app, route, label=f'coherent-{slot}',
                                                        forbid_body=True))
                        for slot, route in enumerate(REFUSAL_POST_ROUTES) for _ in range(3)]
                done, pending = await asyncio.wait(rest, timeout=SAFETY_TIMEOUT)
                for task in pending:
                    task.cancel()
                self.assertEqual(pending, set(), 'a denial never came back from a busy dispatcher')
                block = await self.dispatch(app)
                for task in done:
                    task.result()
                seam.release.set()
                await bounded(parked, SAFETY_TIMEOUT, what='the parked 403')
                return block
            finally:
                seam.release.set()  # the gate goes first, so the drain below cannot be the thing that hangs
                await quiet_within(lambda: seam.quiet)
                if not parked.done():
                    parked.cancel()

        block = self.drive_async(scenario())
        self.assert_counters(block, admitted=1, overloaded=12, in_flight=1)
        self.assertEqual(sum(int(block[name]) for name in DISPATCH_COUNTERS), 13,
                         'a refusal was counted twice, or not at all')
        self.assertEqual(seam.count, 1, 'an overloaded denial became an audit call')
        self.assertEqual(int(self.drive_async(self.dispatch(app))['in_flight']), 0)
        self.assertEqual(self.store_counters()['dropped'], 0)


class DispatcherLifecycleTests(unittest.TestCase, OffLoopFixture):
    """Lifespan drain, no-lifespan honesty, closed admission, and one app across two loops."""

    def setUp(self):
        self.build()

    def test_shutdown_drains_the_admitted_write_before_releasing_ownership(self):
        """The owner lock goes back last, and `shutdown.complete` goes back last of all.

        Order is read from one journal written by three threads: the audit callable finishing, the
        delegated real `exclusive_owner.__exit__`, and the lifespan message arriving. The park is this
        file's to hold, so the two negative observations below are taken 0.75 s into a drain whose write
        had not been released yet: a shutdown that waited a fixed delay, gave up and released ownership
        would have noted both inside that window and fails here with the work still running. The positive
        ordering assertion at the end is what says the drain did finish, and how.

        The loop must not be the thing that blocks, either, so a memory-only read is taken during the
        drain and must report the work still in flight while it answers.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.PARK_WRITE)
        ownership = self.spy_ownership()
        lifespan = Lifespan(app, self.journal)

        async def scenario():
            try:
                await lifespan.start()
                self.assertEqual(ownership.enters, 1, 'startup took the owner lock twice')
                admitted = asyncio.create_task(self.refuse(app, '/v1/actions', label='drained'))
                await wait_until(lambda: seam.starts >= 1 and seam.running,
                                 what='the admitted audit to start')
                lifespan.begin_shutdown()
                self.assertFalse(lifespan.shutdown_completed,
                                 'shutdown.complete was sent before the drain had even begun')
                self.assertEqual(int((await self.dispatch(app))['in_flight']), 1,
                                 'shutdown let capacity go before the drain')
                await stays_false(lambda: self.journal.seen('lifespan.shutdown.complete'),
                                  window=IMMEDIATE_WINDOW,
                                  what='shutdown.complete while the audit was still in SQL')
                mid_drain = await bounded(exchange(app, 'GET', '/v1/runtime', headers=bearer(READER)),
                                          MEMORY_READ_WINDOW,
                                          what='the loop to stay responsive while shutdown drains')
                self.assertEqual(mid_drain.status, 200)
                await stays_false(lambda: self.journal.seen('owner:exit'), window=IMMEDIATE_WINDOW,
                                  what='ownership release while the admitted write was still parked')
                self.assertFalse(admitted.done(), 'the admitted request answered after shutdown began')
                seam.release.set()
                await lifespan.finish_shutdown()
                await bounded(admitted, SAFETY_TIMEOUT, what='the drained 403')
                return await exchange(app, 'GET', '/v1/runtime', headers=bearer(READER))
            finally:
                seam.release.set()  # never let a failed assertion leave the drain waiting on us
                await lifespan.close()

        after = self.drive_async(scenario())
        entries = self.journal.snapshot()
        self.assertEqual(seam.starved, [], 'the parked write hit its own safety timeout')
        self.assertIn('lifespan.shutdown.complete', entries)
        self.assertTrue(self.journal.ordered('audit:finish', 'owner:exit', 'lifespan.shutdown.complete'),
                        f'shutdown did not drain before releasing ownership: {entries}')
        self.assertEqual(ownership.enters, ownership.exits,
                         'the owner lock was not taken and released exactly once')
        self.assertEqual(len(self.refusal_rows()), 1,
                         'the drained write was abandoned: no row arrived for the admitted refusal')
        self.assertEqual(self.store_counters()['written'], 1)
        self.assertEqual(after.status, 200)
        self.assert_counters(after.payload['refusal_audit_dispatch'], admitted=1, overloaded=0,
                             in_flight=0)

    def test_a_cancelled_lifespan_still_drains_before_releasing_ownership(self):
        """A server that gives up on the lifespan must not turn the drain into an abandoned write.

        The lifespan task itself is cancelled mid-drain, which is what a shutdown deadline does to a real
        process. The drain in #135 waits for real completion rather than a timeout, so the observable
        state while this file still holds the write is the interesting one: the task is *still pending*
        and the owner lock is *still held*. Only after this file releases the callable does the drain get
        to finish, and the cancellation is what the task then ends with.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.PARK_WRITE)
        ownership = self.spy_ownership()
        lifespan = Lifespan(app, self.journal)

        async def scenario():
            admitted = None
            try:
                await lifespan.start()
                admitted = asyncio.create_task(self.refuse(app, '/v1/actions/claim',
                                                           label='cancelled-drain'))
                await wait_until(lambda: seam.starts >= 1 and seam.running,
                                 what='the admitted audit to start')
                lifespan.begin_shutdown()
                await stays_false(lambda: self.journal.seen('owner:exit'), window=IMMEDIATE_WINDOW,
                                  what='ownership release before the drain was allowed to finish')
                lifespan.cancel()
                self.assertTrue(lifespan.pending,
                                'the cancelled lifespan finished while its write was still parked')
                self.assertFalse(self.journal.seen('owner:exit'),
                                 'a cancelled lifespan released ownership with SQL still running')
                self.assertEqual(int((await self.dispatch(app))['in_flight']), 1,
                                 'cancelling the lifespan handed back capacity mid-write')
                # Only now may the drain end: the work it was waiting for is what this file was holding.
                seam.release.set()
                await wait_until(lambda: seam.quiet, what='the released write to complete')
                await wait_until(lambda: self.journal.seen('owner:exit'),
                                 what='the owner lock to go back after the drain')
                await lifespan.settle()
                self.assertFalse(lifespan.pending, 'the lifespan task never ended once its work was done')
                self.assertTrue(lifespan.task.cancelled(),
                                'a cancelled lifespan ended as a normal return instead')
                with contextlib.suppress(asyncio.CancelledError):
                    await admitted
                return ownership.enters, ownership.exits
            finally:
                seam.release.set()  # release every gate this file owns before awaiting anything
                await lifespan.close()

        enters, exits = self.drive_async(scenario())
        self.assertTrue(self.journal.ordered('audit:finish', 'owner:exit'),
                        f'a cancelled lifespan released ownership mid-write: {self.journal.snapshot()}')
        self.assertEqual((enters, exits), (1, 1), 'a cancelled lifespan leaked or double-released the lock')
        self.assertEqual(len(self.refusal_rows()), 1, 'the cancelled lifespan abandoned the admitted write')

    def test_a_closed_dispatcher_still_refuses_and_never_becomes_a_writer(self):
        """After shutdown the route still answers — and answers without a job, a read or a connection.

        Closing admission must not turn into a 500, an accepted write, or a request waiting for a slot
        nobody will free. The contract fixes the answer (the same 403, no work, one explicit counter) and
        leaves the field that carries the word "closing" to the code; `closed` is pinned as a strict bool
        by the first test in this file, so the shed itself has to be counted in the counter set.
        """
        app = self.shared_app()
        lifespan = Lifespan(app, self.journal)

        async def scenario():
            try:
                await lifespan.start()
                opened = await self.dispatch(app)
                self.assertIs(opened['closed'], False, 'an app that was up reported itself closed')
                lifespan.begin_shutdown()
                await lifespan.finish_shutdown()
                closed = await self.dispatch(app)
                with patch('local_observe.platform.state.sqlite3.connect',
                           wraps=sqlite3.connect) as connect:
                    reply = await self.refuse(app, '/v1/executions/outcome', label='after-shutdown',
                                              forbid_body=True)
                    after = await self.dispatch(app)
                    connections = connect.call_count
                return opened, closed, reply, after, connections
            finally:
                await lifespan.close()

        opened, closed, reply, after, connections = self.drive_async(scenario())
        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
        self.assertEqual(reply.reads, 0, 'a closed dispatcher read a body on the way to its refusal')
        self.assertEqual(connections, 0, 'a refusal after shutdown became a database writer')
        self.assertEqual(self.refusal_rows(), [])
        self.assert_counters(opened, admitted=0, overloaded=0, in_flight=0)
        self.assertIs(closed['closed'], True, 'a shut-down app did not say it was closing')
        self.assertIs(after['closed'], True, 'the closed state moved once the dispatcher had shut down')
        self.assertEqual(int(after['admitted']), 0, 'a closed dispatcher admitted work')
        self.assertEqual(int(after['in_flight']), 0, 'a closed dispatcher reported work running')
        self.assertEqual(int(after['capacity']), 1)
        # The one counter vocabulary the dispatch block publishes is admitted/overloaded/failed. Nothing
        # was admitted and nothing faulted, so this refusal has to show up as a shed or the operator
        # cannot tell a refused-after-shutdown request from a shed one.
        self.assertEqual(int(after['overloaded']) - int(closed['overloaded']), 1,
                         f'a refusal refused while closing counted nothing: {closed} -> {after}')
        self.assertEqual(int(after['failed']), int(closed['failed']))

    def test_an_app_that_served_without_lifespan_starts_once_shuts_down_and_leaves_nothing_running(self):
        """Direct-ASGI apps are legitimate, and a later real lifespan must neither double-start nor leak.

        Three claims in one run: the same app instance still answers its refusals off the loop with no
        lifespan ever sent (so nothing may fall back to running the audit inline); a real lifespan that
        arrives afterwards starts and shuts down exactly once each; and once it is done, no connection is
        opened across two whole delivery ticks — which is what an orphaned loop or an abandoned queue
        would cost.
        """
        app = self.shared_app()
        seam = self.seam(AuditSeam.OBSERVE)
        lifespan = Lifespan(app, self.journal)

        async def scenario():
            await self.refuse(app, '/v1/actions', label='no-lifespan')
            before_startup = self.journal.count('lifespan.startup.complete')
            try:
                await lifespan.start()
                block = await self.dispatch(app)
                lifespan.begin_shutdown()
                await lifespan.finish_shutdown()
                with patch('local_observe.platform.state.sqlite3.connect',
                           wraps=sqlite3.connect) as connect:
                    await stays_false(lambda: connect.call_count > 0, window=QUIESCENCE_WINDOW,
                                      what='a connection after shutdown.complete')
            finally:
                await lifespan.close()
            return block, before_startup, seam.last()

        block, before_startup, call = self.drive_async(scenario())
        self.assertEqual(before_startup, 0, 'the direct-ASGI requests started a lifespan of their own')
        self.assertEqual(self.journal.count('lifespan.startup.complete'), 1)
        self.assertEqual(self.journal.count('lifespan.shutdown.complete'), 1)
        self.assertFalse(call.on_main_thread, 'without a lifespan the audit went back onto the loop')
        self.assertIsNone(call.running_loop, 'the no-lifespan path ran its audit on an event loop thread')
        self.assert_counters(block, admitted=1, overloaded=0, in_flight=0)
        self.assertEqual(len(self.refusal_rows()), 1, 'the no-lifespan path lost its row')

    def test_no_thread_the_app_created_outlives_an_app_that_had_no_lifespan(self):
        """Nothing here may park a per-app thread that nobody can stop.

        Capacity is 1, so a worker thread is only needed while work exists. Threads are compared against
        the process snapshot taken before the exchange and only threads *this exchange created* count, so
        an unrelated library's thread in a shared test process can neither fail nor satisfy it either way.
        A thread that survives after `asyncio.run` has closed its loop is #135's leaked idle per-app
        thread, and this is the only place that fact is observable without touching the dispatcher.
        """
        app = self.shared_app()
        self.seam(AuditSeam.OBSERVE)
        before = {thread.ident for thread in threading.enumerate()}
        self.drive_async(self.refuse(app, '/v1/actions/decision', label='thread-hygiene'))
        created = [thread for thread in threading.enumerate() if thread.ident not in before]
        # A grace of one polling window, so a thread that is on its way out cannot fail this by a few
        # milliseconds; what is claimed is that no thread this exchange created survives it.
        self.drive_async(quiet_within(lambda: not any(thread.is_alive() for thread in created),
                                      IMMEDIATE_WINDOW))
        lingering = [thread.name for thread in created if thread.is_alive()]
        self.assertEqual(lingering, [],
                         'a thread outlived the refusal it was created for. The asynchronous audit writer item 5 admits a '
                         'strictly admission-bounded submission to the default executor and refuses a '
                         'permanently idle per-app thread: a thread that survives a closed loop is owned '
                         'by nobody, because an app that never ran a lifespan has no close() to hand it '
                         'back.')
        self.assertEqual(len(self.refusal_rows()), 1)

    def test_one_app_used_from_two_event_loops_admits_on_both(self):
        """Capacity must not be a promise made to one loop and broken by the next.

        #135 asks for this explicitly, because the suite drives the app from a fresh loop per test. A
        future, lock or semaphore bound to the first loop shows up here as lost capacity — the second
        loop's request shed forever — or as `attached to a different loop` raised inside the refusal path,
        which would turn a 403 into a 500.
        """
        app = self.app()
        seam = self.seam(AuditSeam.OBSERVE)
        first = self.drive_async(self.refuse(app, '/v1/actions', label='loop-one'))
        self.assertEqual(first.status, 403)
        second = self.drive_async(self.refuse(app, '/v1/actions/decision', label='loop-two'))
        self.assertEqual(second.status, 403)
        block = self.drive_async(self.dispatch(app))
        self.assert_counters(block, admitted=2, overloaded=0, in_flight=0)
        self.assertEqual(len(self.refusal_rows()), 2)
        self.assertEqual(self.store_counters()['written'], 2)
        self.assertEqual({call.on_main_thread for call in seam.calls}, {False},
                         'one of the two loops ran the audit inline')

    def test_a_startup_failure_after_ownership_releases_the_lock_exactly_once(self):
        """A boot that failed after taking ownership gives it back once, and still refuses.

        The failure is injected one call after the real lock is taken — `start_notification_mode`, which
        the lifespan runs under that lock — and the ownership spy delegates, so what is measured is the
        real enter/exit pair rather than a mock's bookkeeping. The app that never finished starting must
        then still answer the summary route with its ordinary 403 rather than a 500, a hang, or a slot
        somebody forgot to release.
        """
        app = self.shared_app()
        ownership = self.spy_ownership()
        lifespan = Lifespan(app, self.journal)

        async def scenario():
            try:
                with patch.object(Store, 'start_notification_mode',
                                  side_effect=RuntimeError(f'{SENTINEL}: injected startup failure')):
                    with self.assertRaises(RuntimeError):
                        await lifespan.start()
                self.assertEqual((ownership.enters, ownership.exits), (1, 1),
                                 'a failed startup leaked or double-released the owner lock')
                self.assertFalse(self.journal.seen('lifespan.startup.complete'),
                                 'a startup that failed still reported that it completed')
                block = await self.dispatch(app)
                # Cleanup ran, so admission is closed: this denial is shed, not admitted, and the row it
                # would have written never exists.
                reply = await self.refuse(app, '/v1/actions/claim', label='after-failed-startup')
                after = await self.dispatch(app)
                return block, reply, after
            finally:
                await lifespan.close()

        block, reply, after = self.drive_async(scenario())
        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
        self.assertEqual(int(block['in_flight']), 0, 'a failed startup left capacity occupied')
        self.assertEqual(int(block['admitted']), 0, 'a failed startup admitted work it never started')
        self.assertEqual(int(after['admitted']), 0, 'the post-failure denial became a writer')
        self.assertEqual(int(after['overloaded']) - int(block['overloaded']), 1,
                         'the post-failure denial counted nothing')
        self.assertEqual(self.refusal_rows(), [])

    def test_a_refused_ownership_acquisition_releases_nothing_and_still_refuses(self):
        """A lock this process never took must not be "released" on the way out, and must not hang.

        The other half of the startup-failure case: acquisition itself fails, so `__exit__` is never
        reached and `shutdown.complete` is never claimed. The refusal path does not depend on ownership at
        all — a platform that could not become the owner is still serving, still refusing, and still
        counting nothing it did not do.
        """
        app = self.shared_app()
        ownership = self.spy_ownership(refuse=OSError('another platform writer holds the state database'))
        lifespan = Lifespan(app, self.journal)

        async def scenario():
            try:
                with self.assertRaises(OSError):
                    await lifespan.start()
                self.assertEqual((ownership.enters, ownership.exits), (1, 0),
                                 'ownership that was refused was still reported as released')
                self.assertFalse(self.journal.seen('owner:exit'),
                                 'a lock this process never took was handed back')
                block = await self.dispatch(app)
                reply = await self.refuse(app, '/v1/actions', label='never-owner')
                after = await self.dispatch(app)
                return block, reply, after
            finally:
                await lifespan.close()

        block, reply, after = self.drive_async(scenario())
        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
        self.assertEqual(int(block['in_flight']), 0)
        self.assertEqual(int(block['admitted']), 0, 'a boot that never owned the file became a writer')
        self.assertEqual(int(after['admitted']), 0, 'the denial after a refused boot became a writer')
        self.assertEqual(int(after['overloaded']) - int(block['overloaded']), 1,
                         'the denial a refused boot could not audit counted nothing')
        self.assertEqual(self.refusal_rows(), [],
                         'a refused boot wrote a row for a refusal its closed dispatcher had to shed')


if __name__ == '__main__':
    unittest.main()

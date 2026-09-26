"""The asynchronous audit writer: a cancelled lifespan or delivery task may not abandon the work it already started.

The defect these tests exist for was measured, not imagined: with the app's single off-loop refusal audit
parked inside a real SQLite write lock, cancelling the *lifespan* task exited the lifespan immediately — it
handed the database to the next owner (the exclusive owner-lock file became reacquirable) while that write
was still running, and the row it was owed never arrived. Every question here is therefore an ordering
question, asked from outside the dispatcher, with no internals read: the `refusal_audit_dispatch` block this
app reports from memory, whether the real owner lock can be taken again, which rows are in the database
file afterwards, and which blocking delivery calls the loop really made, in order.

1. A cancelled request plus repeated lifespan cancellation, over a real held `BEGIN IMMEDIATE`: the write
   stays in flight, later denials shed, the owner lock is not handed back, and the memory-only
   `GET /v1/runtime` keeps answering; after this file releases the lock, exactly one row is durable, the
   cancellation propagates, and the lock is free again.
2. A startup that fails after this app admitted a write with no lifespan at all: the injected `Store`
   failure comes back only once that write is finished.
3. A `receive()` that fails after startup, or a `lifespan.startup.complete` send that fails: the same
   drain, ownership released afterwards, no message ASGI does not define, and no `shutdown.complete` for a
   shutdown nobody asked for.
4. A normal shutdown cancelled *during* its drain: repeated cancellation does not end it early, and the
   delivery worker's own return precedes the release of ownership.
5. A cancellation of the app's *internal* delivery task from outside, while that task is inside one of its
   two blocking calls — the `Store` expiry call and the notification delivery call, one subtest each. The
   worker may not finish before its call really ends, so a shutdown asked for over it keeps the real
   exclusive owner lock, keeps answering `GET /v1/runtime` from memory, and never sends
   `shutdown.complete`; once this file lets the call return the lock is free again, and the worker ends
   *cancelled* rather than having quietly absorbed the cancellation. Each of those two is run twice, once
   with the loop's own execution wrapper for the parked call cancelled as well, because a cancelled wrapper
   reports itself done while the executor thread that already picked the item up is still mid-call: it is
   never proof that the call was dropped from a queue.

Tests 2 to 4 park the audit on an event *inside* the documented `Store.record_refusal` call rather than
behind a write lock: the capacity contract is about the callable not having returned, and a write lock taken
before startup would also block the app's own startup writes — that contention would be the thing under test
instead of the drain. Test 1 keeps the real lock, which is the reproduced failure. The last scenario parks
the delivery call itself, on the thread the product put it on, with no write lock in the way: what is
claimed is that a thread has not left its call, and a second holder of the file would only be a second
thing under test. No
test is skipped, nothing sleeps to synchronise (every wait is a deadline that fails the test when it
expires), no source shape is asserted, and no bound here claims anything about how long an fsync takes.
Every thread, connection and task a scenario starts is given back in a `finally` and reported through
`problems`, so a failed assertion cannot leave a write lock held for the rest of the suite.
"""
import asyncio
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from local_observe.platform import refusals
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.owner import exclusive_owner
from local_observe.platform.state import Store

#: Every bound below is a *failure* deadline that fails the test, never a way to let work finish.
WAIT = 10.0
#: How long a memory-only read may take while real work is parked by this file.
FAST = 5.0
#: How long a "that must not have happened yet" observation runs — well inside the read bound above.
NOT_YET = 1.0
#: A fixture thread's own give-up bound, so a broken run costs a failure and not a hung job. It says
#: nothing about the product's patience, which the contract leaves unbounded on purpose.
HOLD = 30.0
POLL = 0.01
SUMMARY = 'lifecycle-summary'
#: Names the injected failures below. This file's own sentence, never caller-controlled data.
SENTINEL = 'lifecycle-injected-failure'
#: `observe_startup` refuses a half-set source pin, and another test in this process may have left one of
#: the two names behind. Neither is this file's business, so both are absent for its duration.
PIN_ENVIRONMENT = ('LO_PLATFORM_CODE_ROOT', 'LO_PLATFORM_CODE_SHA256')
CREDENTIALS = [{'identity': SUMMARY, 'role': 'summary',
                'token': 'synthetic-summary-lifecycle-fixture-token-01'},
               {'identity': 'lifecycle-reader', 'role': 'reader',
                'token': 'synthetic-reader-lifecycle-fixture-token-02'}]
BEARER = {row['identity']: [(b'authorization', ('Bearer ' + row['token']).encode())]
          for row in CREDENTIALS}
#: The only lifespan messages a server may ever see. Anything else is a fabricated protocol event.
ASGI_LIFESPAN_SENDS = frozenset({'lifespan.startup.complete', 'lifespan.startup.failed',
                                'lifespan.shutdown.complete', 'lifespan.shutdown.failed'})


async def reached(flag: threading.Event, *, within: float = WAIT) -> bool:
    """Notice a thread-side `threading.Event` from the loop; True means it arrived inside `within`."""
    return await asyncio.to_thread(flag.wait, within)


async def until(condition, *, within: float = WAIT) -> bool:
    """Poll to a deadline. False means the deadline ran out, and the caller decides what that was worth."""
    deadline = time.monotonic() + within
    while True:
        if condition():
            return True
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(POLL)


async def bounded(awaitable, *, within: float = WAIT, what: str = 'it'):
    """Await with a finite safety deadline, failing with `what` rather than a bare timeout."""
    try:
        return await asyncio.wait_for(awaitable, timeout=within)
    except TimeoutError:
        raise AssertionError(f'{what} did not happen within {within}s') from None


async def outcome(task, *, within: float = WAIT) -> tuple:
    """('running'|'cancelled'|'raised'|'returned', error) for a task — without hanging on or cancelling it."""
    done, _ = await asyncio.wait((task,), timeout=within)
    if not done:
        return 'running', None
    if task.cancelled():
        return 'cancelled', None
    error = task.exception()
    return ('raised', error) if error is not None else ('returned', None)


async def reap(tasks, problems: list, *, consumed=()) -> None:
    """Give back every task a scenario started, even while the scenario unwinds on a failed assertion.

    `consumed` names the tasks whose outcome the scenario already read and asserted: an exception there is
    the injected failure under test, not a leak, so it is not reported a second time. A task that survived
    its own cancellation, or a denial nobody explained, is a real problem and says so here.
    """
    for task in tasks:
        if task is None:
            continue
        if not task.done():
            task.cancel()
        kind, error = await outcome(task)
        known = any(task is settled for settled in consumed)
        if kind == 'running':
            problems.append('a task this file started never finished')
        elif kind == 'raised' and not known:
            problems.append(f'{type(error).__name__}: {error}')


async def owner_is_free(path) -> bool:
    """Whether this process can take the exclusive owner lock right now — the real lock, off the loop."""
    def probe() -> bool:
        try:
            with exclusive_owner(path):
                return True
        except OSError:
            return False

    return await asyncio.to_thread(probe)


def executor_submissions(recorded: list, real):
    """Wrap one loop's `run_in_executor` so a scenario can see the futures it hands out.

    The real submission happens first and untouched; the future it returned is noted in submission order.
    That future is a *wrapper*: cancelling it says the item was no longer wanted, which is true both of a
    queued item nobody picked up and of a call still running on its thread. Only a scenario that holds the
    thread can tell those apart, so recording the wrappers is what lets a test cancel one and keep asking
    whether the callable came back.
    """
    def record(executor, function, *args, **kwargs):
        future = real(executor, function, *args, **kwargs)
        recorded.append(future)
        return future

    return record


def delivery_workers() -> list:
    """The app's internal delivery-loop tasks, found the way a foreign teardown finds them.

    Nothing in the transport hands this task out, and this file will not reach for a private name to get
    it: a *server* cancelling the worker is the scenario, so the lookup is as indirect as the teardown
    that does it in production — by the coroutine's name, out of the running loop's task set.
    """
    return [task for task in asyncio.all_tasks()
            if getattr(task.get_coro(), '__name__', None) == 'delivery_loop']


async def refuse(app, path: str = '/v1/actions') -> tuple:
    """One summary-role write denial. Its `receive()` refuses to answer, which is itself part of the claim."""
    sent = []

    async def receive():
        raise AssertionError('the summary-role gate must not await a body chunk')

    async def send(message):
        sent.append(message)

    await app({'type': 'http', 'method': 'POST', 'path': path, 'query_string': b'',
               'headers': BEARER[SUMMARY]}, receive, send)
    return sent[0]['status'], json.loads(sent[-1]['body'])


async def refusal_block(app) -> dict:
    """This app's own `refusal_audit_dispatch` block over ASGI: a memory read, no database connection."""
    sent = []

    async def receive():
        raise AssertionError('a GET is never handed a body')

    async def send(message):
        sent.append(message)

    await app({'type': 'http', 'method': 'GET', 'path': '/v1/runtime', 'query_string': b'',
               'headers': BEARER['lifecycle-reader']}, receive, send)
    assert sent[0]['status'] == 200, f'GET /v1/runtime stopped answering from memory: {sent[0]}'
    return json.loads(sent[-1]['body'])['refusal_audit_dispatch']


async def slot_free(app, *, within: float = WAIT) -> dict:
    """Poll that memory read until this app's one slot reports itself free, then hand back the last block."""
    deadline = time.monotonic() + within
    block = await bounded(refusal_block(app), within=FAST, what='the runtime dispatch block')
    while int(block['in_flight']) and time.monotonic() < deadline:
        await asyncio.sleep(POLL)
        block = await bounded(refusal_block(app), within=FAST, what='the runtime dispatch block')
    return block


class WriteHolder:
    """One real `BEGIN IMMEDIATE` held by another thread, taken and released only when this file says so.

    `arrange` registers the guarantee and `take` is what actually locks the file, so a test can start the
    app first: the app's own startup writes must not queue behind this fixture. The connection is closed
    explicitly, because `with connection:` commits or rolls back and never closes the handle.
    """

    def __init__(self, path) -> None:
        self.path = path
        self.held = threading.Event()
        self.release = threading.Event()
        self.expired = threading.Event()
        self.error: str | None = None
        self.thread = threading.Thread(target=self.run, name='refusal-lifecycle-write-holder', daemon=True)

    def run(self) -> None:
        connection = sqlite3.connect(self.path, timeout=WAIT, isolation_level=None)
        try:
            connection.execute('BEGIN IMMEDIATE')
            self.held.set()
            if not self.release.wait(HOLD):
                self.expired.set()
        except BaseException as exc:
            self.error = type(exc).__name__
            self.held.set()
        finally:
            with contextlib.suppress(sqlite3.Error):
                if connection.in_transaction:
                    connection.execute('ROLLBACK')
            connection.close()
            self.release.set()

    def arrange(self, case: unittest.TestCase) -> 'WriteHolder':
        case.addCleanup(self.tidy)
        return self

    def take(self) -> 'WriteHolder':
        self.thread.start()
        return self

    def tidy(self) -> None:
        """Nothing in this file may leave a write lock, or the thread holding it, behind."""
        self.release.set()
        if self.thread.is_alive():
            self.thread.join(timeout=HOLD)


class Lifespan:
    """Drive one `scope['type'] == 'lifespan'` by hand and record every message the app sends.

    `sent` is what the app claimed to its server, so a message ASGI does not define and a
    `shutdown.complete` for a shutdown that never finished are both observations here rather than readings
    of a comment. `taken` is the other side of that record: the messages the app actually received, so a
    shutdown that has to be *asked for* before it is cancelled is an observation rather than a guess timed
    by a sleep. `FAILURE` makes the next `receive()` raise: a server whose receive died mid-conversation.
    """

    FAILURE = object()

    def __init__(self, app, *, fail_send: str | None = None) -> None:
        self.app = app
        self.queue: asyncio.Queue = asyncio.Queue()
        self.sent: list[str] = []
        self.taken: list[str] = []
        self.fail_send = fail_send
        self.task = None

    async def receive(self):
        message = await self.queue.get()
        if message is self.FAILURE:
            raise RuntimeError(SENTINEL)
        self.taken.append(message['type'])
        return message

    async def send(self, message):
        if message['type'] == self.fail_send:
            raise RuntimeError(f'{SENTINEL} at send')
        self.sent.append(message['type'])

    def begin(self) -> None:
        self.task = asyncio.create_task(self.app({'type': 'lifespan'}, self.receive, self.send))
        self.queue.put_nowait({'type': 'lifespan.startup'})

    async def start(self) -> None:
        self.begin()
        await until(lambda: 'lifespan.startup.complete' in self.sent or self.done)
        if 'lifespan.startup.complete' not in self.sent:
            raise AssertionError('the lifespan never acknowledged startup, so this scenario has no baseline')

    def shutdown(self) -> None:
        self.queue.put_nowait({'type': 'lifespan.shutdown'})

    def cancel(self) -> None:
        if self.task is not None:
            self.task.cancel()

    @property
    def done(self) -> bool:
        return self.task is not None and self.task.done()


class DeliveryCalls:
    """One app's two blocking delivery calls, with one of them parked by this file.

    Both are replaced for the length of a scenario, so the loop's real call order is readable rather than
    assumed, and so the call under test is the very callable the loop invokes — parked *inside* it is the
    whole scenario, and it is a real executor thread that sits there while the task around it is cancelled.
    The other call returns at once and is still counted, which is what turns "no next call after a
    cancellation" into an observation instead of a claim. `api.deliver_one` is patched where the delivery
    loop looks it up, and the app is built in a notification mode, so the delivery call is reachable.

    A parked call this file never released records itself in `starved` rather than hanging the run.
    """

    def __init__(self, parked: str) -> None:
        self.parked = parked
        self.order: list[str] = []
        self.entered = threading.Event()
        self.returned = threading.Event()
        self.gate = threading.Event()
        self.starved: list[str] = []

    @contextlib.contextmanager
    def fitted(self, store: Store):
        """Install these two calls over one store's expiry call and the transport's delivery call."""
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(store, 'expire_actions', self.expire))
            stack.enter_context(patch('local_observe.platform.api.deliver_one', self.deliver))
            yield self

    def expire(self) -> None:
        self.note('expire')

    def deliver(self, store, client) -> None:
        self.note('deliver')

    def note(self, name: str) -> None:
        self.order.append(name)
        if name != self.parked:
            return
        self.entered.set()
        if not self.gate.wait(HOLD):
            self.starved.append(name)
        self.returned.set()


class RefusalAuditLifecycleTests(unittest.TestCase):
    """The lifecycle claims, each over a real `Store`, a real owner lock, and one gate this file controls."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        environment = patch.dict(os.environ, {}, clear=False)
        environment.start()
        self.addCleanup(environment.stop)
        for name in PIN_ENVIRONMENT:
            os.environ.pop(name, None)
        self.store = Store(Path(scratch.name) / 'state.db', NotificationPolicy(delivery_mode='off'))
        self.app = create_app(self.store, CREDENTIALS, lambda _: None)
        # `record_refusal` is the contract's only audit write, so it is the one place this file may watch,
        # and the real method still runs: no classifier is patched, so the reason word in the row stays the
        # product's own. `expire_actions` is the delivery worker's only database call in `off` mode, so
        # gating it keeps this file's write lock free of company and gives test 4 its parked worker.
        self.entered = threading.Event()
        self.audit_gate = threading.Event()
        self.audit_gate.set()
        self.audit_returned = threading.Event()
        self.expire_gate = threading.Event()
        self.expire_gate.set()
        self.expire_log: list[str] = []
        self.expire_returned = threading.Event()
        self.starved: list[str] = []
        real_record = self.store.record_refusal

        def audited(*args, **kwargs):
            refused = args[1] if len(args) > 1 else kwargs.get('actor')
            if getattr(refused, 'identity', None) != SUMMARY:
                # Not this file's denial — the state layer audits its own refusals too, and an
                # unrelated one must never be parked, counted as entered, or delay a startup.
                return real_record(*args, **kwargs)
            self.entered.set()
            if not self.audit_gate.wait(HOLD):
                self.starved.append('audit')
            result = real_record(*args, **kwargs)
            self.audit_returned.set()
            return result

        def expire_actions():
            self.expire_log.append('expire')
            if not self.expire_gate.wait(HOLD):
                self.starved.append('expire')
            else:
                self.expire_returned.set()

        record_patch = patch.object(self.store, 'record_refusal', audited)
        expire_patch = patch.object(self.store, 'expire_actions', expire_actions)
        record_patch.start()
        expire_patch.start()
        # Cleanups run last-in-first-out: the gates open before either patch is withdrawn, so a callable
        # still waiting on one can never wake up to find the real method already unpatched.
        self.addCleanup(record_patch.stop)
        self.addCleanup(expire_patch.stop)
        self.addCleanup(self.open_gates)

    def open_gates(self) -> None:
        """The two gates hold product threads, so they are never left closed for the next test."""
        self.audit_gate.set()
        self.expire_gate.set()

    def refusal_rows(self) -> list:
        """The durable refusal rows in the file: who was refused, and the two fixed words the row names."""
        with contextlib.closing(sqlite3.connect(self.store.path, timeout=WAIT)) as db:
            return [(row[0], json.loads(row[1])['attempt'], json.loads(row[1])['reason']) for row in
                    db.execute('SELECT actor, detail FROM audit WHERE operation=? ORDER BY rowid',
                               (refusals.OPERATION,))]

    def assert_no_invented_message(self, life: Lifespan) -> None:
        """Every lifespan message this app sent must be a name the ASGI lifespan specification has."""
        invented = set(life.sent) - ASGI_LIFESPAN_SENDS
        self.assertEqual(invented, set(),
                         f'the lifespan sent messages ASGI does not define: {sorted(invented)}'
                         f' in {life.sent}')

    def test_a_cancelled_lifespan_waits_for_its_admitted_write_and_keeps_ownership(self):
        store, app = self.store, self.app
        holder = WriteHolder(store.path).arrange(self)
        life, problems = Lifespan(app), []

        async def scenario():
            denial = None
            try:
                await life.start()
                holder.take()
                self.assertTrue(await reached(holder.held), 'the fixture never took the write lock')
                denial = asyncio.create_task(refuse(app))
                self.assertTrue(await reached(self.entered), 'no audit attempt reached the parked write')
                self.assertFalse(denial.done(), 'the admitted 403 answered before its write finished')
                denial.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await denial
                for _ in range(3):
                    self.assertEqual(await refuse(app, '/v1/actions/claim'),
                                     (403, {'error': 'summary_only'}),
                                     'a busy slot admitted a second write')
                busy = await bounded(refusal_block(app), within=FAST,
                                     what='the runtime block while the write lock was held')
                self.assertEqual((int(busy['in_flight']), int(busy['admitted']), int(busy['overloaded']),
                                  int(busy['failed'])), (1, 1, 3, 0),
                                 'cancelling the request freed capacity or counted a dispatcher failure')
                for _ in range(4):
                    life.cancel()
                    await asyncio.sleep(0)
                self.assertFalse(life.done, 'a cancelled lifespan abandoned the admitted writer')
                self.assertFalse(await owner_is_free(store.path),
                                 'the owner lock came back while its admitted write was still running')
                parked = await bounded(refusal_block(app), within=FAST,
                                       what='the memory-only GET /v1/runtime during a cancelled drain')
                self.assertEqual(int(parked['in_flight']), 1, 'the cancelled drain forgot the write it owns')
                holder.release.set()
                self.assertTrue(await until(lambda: life.done),
                                'the cancelled lifespan never ended after its work was done')
                kind, error = await outcome(life.task)
                self.assertEqual(kind, 'cancelled', f'the cancelled lifespan ended by {kind}: {error}')
                self.assertTrue(await owner_is_free(store.path), 'the owner lock was never released')
            finally:
                holder.release.set()
                await reap([denial, life.task], problems, consumed=(life.task,))

        asyncio.run(scenario())
        self.assertEqual(problems, [], 'a task or thread was not given back')
        self.assertIsNone(holder.error, f'the thread holding the write lock failed: {holder.error}')
        self.assertFalse(holder.expired.is_set(), 'the write lock was held past this file\'s own bound')
        self.assertEqual(self.starved, [], 'a parked callable was left waiting for this file')
        self.assertEqual(self.refusal_rows(), [(SUMMARY, 'propose', refusals.SUMMARY_ONLY)],
                         'the admitted write lost or duplicated its one durable row')
        self.assertEqual(self.store.refusal_audit_status()['written'], 1,
                         'the row that arrived was not counted as a write by the store')

    def test_a_startup_failure_waits_for_admitted_work_before_giving_the_lock_back(self):
        store, app = self.store, self.app
        life, problems = Lifespan(app), []

        async def scenario():
            denial = None

            def failing_startup():
                raise RuntimeError(f'{SENTINEL} in start_notification_mode')

            try:
                self.audit_gate.clear()
                denial = asyncio.create_task(refuse(app, '/v1/executions/outcome'))
                self.assertTrue(await reached(self.entered),
                                'an app that served without a lifespan never reached its audit write')
                with patch.object(store, 'start_notification_mode', failing_startup):
                    life.begin()
                    self.assertFalse(await until(lambda: life.done, within=NOT_YET),
                                     'a failed startup released ownership while admitted work was pending')
                    self.assertFalse(await owner_is_free(store.path),
                                     'a failed startup handed the file to another owner mid-write')
                    parked = await bounded(refusal_block(app), within=FAST,
                                           what='the memory-only read during a failing startup')
                    self.assertEqual(int(parked['in_flight']), 1, 'the failed startup dropped the slot')
                    self.audit_gate.set()
                    kind, error = await outcome(life.task)
                self.assertEqual(kind, 'raised', f'the startup failure did not propagate ({kind})')
                self.assertIn(SENTINEL, str(error), 'something replaced the injected startup failure')
                self.assertNotIn('lifespan.startup.complete', life.sent,
                                 'a startup that failed claimed that it completed')
                self.assertTrue(await owner_is_free(store.path),
                                'ownership was never released after the admitted write finished')
                self.assertEqual(await bounded(denial, within=WAIT, what='the admitted 403'),
                                 (403, {'error': 'summary_only'}))
            finally:
                self.audit_gate.set()
                await reap([denial, life.task], problems, consumed=(life.task,))

        asyncio.run(scenario())
        self.assertEqual(problems, [], 'a task or thread was not given back')
        self.assertEqual(self.starved, [], 'a parked callable was left waiting for this file')
        self.assert_no_invented_message(life)
        self.assertEqual(self.refusal_rows(), [(SUMMARY, 'outcome', refusals.SUMMARY_ONLY)],
                         'the write a failed startup waited for is not durable exactly once')

    def test_a_receive_failure_after_startup_drains_and_sends_no_fake_shutdown(self):
        store, app = self.store, self.app
        life, problems = Lifespan(app), []

        async def scenario():
            denial = None
            try:
                await life.start()
                self.audit_gate.clear()
                denial = asyncio.create_task(refuse(app, '/v1/actions/claim'))
                self.assertTrue(await reached(self.entered), 'no audit attempt reached the parked write')
                life.queue.put_nowait(Lifespan.FAILURE)
                self.assertFalse(await until(lambda: life.done, within=NOT_YET),
                                 'a failed receive released ownership while admitted work was pending')
                self.assertFalse(await owner_is_free(store.path),
                                 'a failed receive dropped the owner lock around a running write')
                parked = await bounded(refusal_block(app), within=FAST,
                                       what='the memory-only read during a failed receive')
                self.assertEqual(int(parked['in_flight']), 1, 'the failed receive dropped the slot')
                self.audit_gate.set()
                kind, error = await outcome(life.task)
                self.assertEqual(kind, 'raised', f'the receive failure did not propagate ({kind})')
                self.assertIn(SENTINEL, str(error), 'something replaced the injected receive failure')
                self.assertTrue(await owner_is_free(store.path),
                                'the owner lock was never released after the drain')
                self.assertEqual(await bounded(denial, within=WAIT, what='the admitted 403'),
                                 (403, {'error': 'summary_only'}))
            finally:
                self.audit_gate.set()
                await reap([denial, life.task], problems, consumed=(life.task,))

        asyncio.run(scenario())
        self.assertEqual(problems, [], 'a task or thread was not given back')
        self.assertEqual(self.starved, [], 'a parked callable was left waiting for this file')
        self.assert_no_invented_message(life)
        self.assertNotIn('lifespan.shutdown.complete', life.sent,
                         f'a lifespan that never shut down answered shutdown.complete: {life.sent}')
        self.assertEqual(self.refusal_rows(), [(SUMMARY, 'claim', refusals.SUMMARY_ONLY)],
                         'the drained write was abandoned: no row arrived for the admitted refusal')

    def test_a_failed_startup_complete_send_drains_and_sends_no_fake_shutdown(self):
        store, app = self.store, self.app
        life = Lifespan(app, fail_send='lifespan.startup.complete')
        problems: list = []

        async def scenario():
            denial = None
            try:
                self.audit_gate.clear()
                denial = asyncio.create_task(refuse(app, '/v1/actions/decision'))
                self.assertTrue(await reached(self.entered),
                                'an app that served without a lifespan never reached its audit write')
                life.begin()
                self.assertFalse(await until(lambda: life.done, within=NOT_YET),
                                 'a failed send released ownership while admitted work was pending')
                self.assertFalse(await owner_is_free(store.path),
                                 'a failed send handed the file to another owner mid-write')
                parked = await bounded(refusal_block(app), within=FAST,
                                       what='the memory-only read during a failed send')
                self.assertEqual(int(parked['in_flight']), 1, 'the failed send dropped the slot')
                self.audit_gate.set()
                kind, error = await outcome(life.task)
                self.assertEqual(kind, 'raised', f'the send failure did not propagate ({kind})')
                self.assertIn(SENTINEL, str(error), 'something replaced the injected send failure')
                self.assertTrue(await owner_is_free(store.path),
                                'ownership was never released after the failed send drained')
                self.assertEqual(await bounded(denial, within=WAIT, what='the admitted 403'),
                                 (403, {'error': 'summary_only'}))
            finally:
                self.audit_gate.set()
                await reap([denial, life.task], problems, consumed=(life.task,))

        asyncio.run(scenario())
        self.assertEqual(problems, [], 'a task or thread was not given back')
        self.assertEqual(self.starved, [], 'a parked callable was left waiting for this file')
        self.assert_no_invented_message(life)
        self.assertNotIn('lifespan.startup.complete', life.sent,
                         'a send that raised was reported as a completed startup')
        self.assertNotIn('lifespan.shutdown.complete', life.sent,
                         f'a lifespan that never shut down answered shutdown.complete: {life.sent}')
        self.assertEqual(self.refusal_rows(), [(SUMMARY, 'decide', refusals.SUMMARY_ONLY)],
                         'the write pending across a failed send is not durable exactly once')

    def test_repeated_cancellation_during_the_drain_waits_for_the_delivery_worker_too(self):
        store, app = self.store, self.app
        life, problems = Lifespan(app), []

        async def scenario():
            denial = None
            try:
                self.audit_gate.clear()
                self.expire_gate.clear()
                await life.start()
                self.assertTrue(await until(lambda: self.expire_log),
                                'the delivery loop never reached its Store call')
                self.assertFalse(self.expire_returned.is_set(),
                                 'the delivery worker left its controlled call before this file allowed it')
                denial = asyncio.create_task(refuse(app))
                self.assertTrue(await reached(self.entered), 'no audit attempt reached the parked write')
                life.shutdown()
                for _ in range(6):
                    life.cancel()
                    await asyncio.sleep(0)
                self.assertFalse(life.done,
                                 'repeated cancellation ended the drain before the work was done')
                self.assertFalse(await owner_is_free(store.path),
                                 'ownership was released while the shutdown drain still had work')
                parked = await bounded(refusal_block(app), within=FAST,
                                       what='the memory-only read while a cancelled drain waited')
                self.assertEqual(int(parked['in_flight']), 1, 'the cancelled drain let its slot go early')
                self.audit_gate.set()
                drained = await slot_free(app)
                self.assertEqual(int(drained['in_flight']), 0, 'the slot never came back after the write')
                self.assertFalse(self.expire_returned.is_set(),
                                 'the delivery worker left its parked call too early')
                self.assertFalse(await owner_is_free(store.path),
                                 'ownership was released before the delivery worker finished')
                self.expire_gate.set()
                self.assertTrue(await until(lambda: self.expire_returned.is_set()),
                                'the delivery worker never returned from its controlled call')
                self.assertTrue(await until(lambda: life.done),
                                'the shutdown drain never finished once the real work was done')
                kind, error = await outcome(life.task)
                self.assertIn(kind, ('cancelled', 'returned'),
                              f'the cancelled drain ended by raising {type(error).__name__}: {error}')
                self.assertTrue(await owner_is_free(store.path),
                                'the owner lock was never released after a full drain')
                closed = await bounded(refusal_block(app), within=FAST,
                                       what='the runtime block after the drain')
                self.assertTrue(bool(closed['closed']), 'admission never closed for this shutdown')
                self.assertEqual(await bounded(denial, within=WAIT, what='the admitted 403'),
                                 (403, {'error': 'summary_only'}))
            finally:
                self.audit_gate.set()
                self.expire_gate.set()
                await reap([denial, life.task], problems, consumed=(life.task,))

        asyncio.run(scenario())
        self.assertEqual(problems, [], 'a task or thread was not given back')
        self.assertEqual(self.starved, [], 'a parked callable was left waiting for this file')
        self.assert_no_invented_message(life)
        self.assertEqual(self.refusal_rows(), [(SUMMARY, 'propose', refusals.SUMMARY_ONLY)],
                         'a shutdown cancelled to completion lost or duplicated its admitted row')

    def test_cancelling_the_delivery_task_waits_for_the_blocking_call_that_is_still_running(self):
        """The measured ownership regression, once per blocking call the delivery loop makes.

        main's probe: a server cancels the app's internal delivery task while that task's `Store` call is
        still on its executor thread. A drain that treats *the task ending* as proof that the call ended
        then releases the exclusive owner lock around a running call, and the next owner opens the file
        under it. So park the real call, ask for shutdown, and cancel both the worker and the lifespan
        repeatedly: until this file lets the call return, the worker is not done, the real owner lock
        cannot be taken again, the lifespan has not finished, and the memory-only `GET /v1/runtime` still
        answers — the loop is waiting, not blocked. Then release the call: the worker ends *cancelled*
        (surviving a cancellation is not absorbing it), the lock comes back, and a `shutdown.complete` for
        a shutdown that was cut short is never sent. Nothing is awaited to completion before the gate
        opens; that awaiting is the premature release this test exists to catch.

        The second dimension cancels the executor wrapper too. A cancelled `run_in_executor` future is
        *done* while the thread it scheduled is already inside the call, so "the future is done" is never
        evidence that the callable was dropped from a queue it could not reach — the same cancellation
        means either thing. That wrapper is therefore cancelled over a window of many completion-poll
        intervals (the bounded wait below, not a handful of loop yields, which can pass for nothing until
        the first poll fires) with the worker, the lifespan and the owner lock all required to stay put.
        """
        for name, mode in (('expire', 'off'), ('deliver', 'recording')):
            for cancel_wrapper in (False, True):
                with self.subTest(delivery_call=name, cancel_execution_wrapper=cancel_wrapper):
                    calls = DeliveryCalls(name)
                    store = Store(self.store.path.parent / f'delivery-{name}-{int(cancel_wrapper)}.db',
                                  NotificationPolicy(delivery_mode=mode))
                    app = create_app(store, CREDENTIALS, lambda _: None)
                    life, problems = Lifespan(app), []

                    async def scenario():
                        worker = None
                        # Every executor submission this loop makes from here on, in submission order,
                        # with the real submission untouched. Nothing else — no owner probe, no memory
                        # read, no fixture helper — has reached this loop by the time the call is parked,
                        # so the newest entry is that parked call's own wrapper.
                        submitted: list = []
                        running = asyncio.get_running_loop()
                        recorded = patch.object(running, 'run_in_executor',
                                                executor_submissions(submitted, running.run_in_executor))
                        try:
                            recorded.start()
                            with calls.fitted(store):
                                await life.start()
                                self.assertTrue(await until(lambda: calls.entered.is_set()),
                                                f'the delivery loop never reached its {name} call')
                                self.assertEqual(
                                    len(submitted), len(calls.order),
                                    'an executor submission other than the delivery calls reached this loop '
                                    'before the park, so its newest wrapper is not the parked call')
                                execution = submitted[-1]
                                self.assertFalse(execution.done(),
                                                 f'the {name} call resolved its wrapper before this file let it')
                                workers = delivery_workers()
                                self.assertEqual(len(workers), 1,
                                                 'one lifespan owns exactly one internal delivery task')
                                worker = workers[0]
                                self.assertFalse(calls.returned.is_set(),
                                                 f'the parked {name} call returned on its own')
                                life.shutdown()
                                self.assertTrue(await until(lambda: 'lifespan.shutdown' in life.taken),
                                                'the lifespan never took the shutdown it was asked for')
                                for _ in range(4):
                                    worker.cancel()
                                    life.cancel()
                                    await asyncio.sleep(0)
                                if cancel_wrapper:
                                    execution.cancel()
                                    self.assertTrue(execution.cancelled(),
                                                    'cancelling the wrapper left it unresolved')
                                    self.assertFalse(calls.returned.is_set(),
                                                     f'the thread left its parked {name} call when only '
                                                     'its wrapper was cancelled')
                                self.assertFalse(await until(lambda: worker.done() or life.done,
                                                             within=NOT_YET),
                                                 'a cancelled wrapper, or a cancelled task around a live '
                                                 'call, was read as the call having ended')
                                self.assertFalse(worker.done(),
                                                 f'the delivery task ended inside its own {name} call')
                                self.assertFalse(calls.returned.is_set(),
                                                 f'{name} was cut short instead of waited for')
                                self.assertFalse(life.done, 'shutdown finished while a delivery call ran')
                                self.assertNotIn('lifespan.shutdown.complete', life.sent,
                                                 'a shutdown still holding a delivery call claimed completion')
                                self.assertFalse(await owner_is_free(store.path),
                                                 f'the owner lock came back while {name} was still running')
                                parked = await bounded(
                                    refusal_block(app), within=FAST,
                                    what='the memory-only read while a cancelled shutdown waited')
                                self.assertEqual((int(parked['in_flight']), bool(parked['closed'])), (0, True),
                                                 'the drain was waiting on something but the delivery worker')
                                calls.gate.set()
                                kind, error = await outcome(life.task)
                                self.assertIn(kind, ('cancelled', 'returned'),
                                              f'the cancelled shutdown ended by raising {type(error).__name__}')
                                self.assertTrue(calls.returned.is_set(),
                                                f'{name} never returned after this file released it')
                                self.assertEqual(await outcome(worker), ('cancelled', None),
                                                 'the delivery worker absorbed the cancellation it was given')
                                self.assertTrue(await owner_is_free(store.path),
                                                'the owner lock was never handed back after the call ended')
                        finally:
                            recorded.stop()
                            calls.gate.set()
                            await reap([worker, life.task], problems, consumed=(life.task,))

                    asyncio.run(scenario())
                    self.assertEqual(problems, [], 'a task or thread was not given back')
                    self.assertEqual(calls.starved, [], 'a parked delivery call was left waiting for this file')
                    self.assertEqual(calls.order, ['expire'] if name == 'expire' else ['expire', 'deliver'],
                                     'the delivery loop started another call after it had been cancelled')
                    self.assert_no_invented_message(life)
                    self.assertNotIn('lifespan.shutdown.complete', life.sent,
                                     f'a delivery drain cancelled to completion answered shutdown.complete: '
                                     f'{life.sent}')


if __name__ == '__main__':
    unittest.main()

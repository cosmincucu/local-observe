"""Wave 10 : the verification service behind `platform/verification_api.py`.

Worker C's independent boundary file, written against the frozen seam and nothing else:
`VerificationAPI(store)`, `async handle(scope, receive, actor) -> (status, body) | None`, the module
function `owns(path)`, `close()` and `async wait_idle()`, plus `api.create_app`'s integration
(`app.verification_api`, routing only on `owns(path)`, `close()`/`wait_idle()` in the lifespan) and the
factory half (`api.validate_credentials`, `verification_policy.policy_from_environment` before any
`Store`). No implementation was read — the module does not exist in this checkout yet — so everything
below is an HTTP exchange over a real `Store`, or a fact observed about a call this file makes.

What is pinned, and why each half survives a mock:

* **The real lifecycle.** An incident is opened by `Store.intake`, an action is proposed through the real
  action policy so its binding is really captured, the run is claimed with a runner token and reported
  `succeeded`, and only then does a producer POST a statement over ASGI. Binding, record, id list, exact
  replay after the evidence aged out, a changed-content conflict, a revoked verifier, an unmounted
  policy, and a reopen onto the same file are all read back through these same four routes. A
  `succeeded` execution plus a `not_cleared` verdict leaves the incident open — asserted on rows.
* **Authority before anything else.** `summary` is answered `summary_only` and every other role by
  `verification_records._reader`/`_writer`, against a `receive()` that refuses to hand over a body and a
  connection counter that must not move. These routes grow no `action.refused` row, spend none of the
  store's refusal budget, and never hand a job to the card-135 dispatcher. A producer admitted to these
  three exact GETs is admitted to nothing else, `/v1/me` included.
* **The parser is the first gate.** Exact single-parameter queries (256 raw bytes, strict
  ASCII/percent/UTF-8, no duplicate, blank, extra or misnamed parameter, length and type bounds before
  any UUID or digest validation), and a POST body that is strict UTF-8 JSON with no duplicate key at any
  depth, no non-finite constant, no unbounded numeric, no runaway nesting, a 32 KiB bound enforced while
  the body is still arriving, and UTF-16/32 refused by decoding UTF-8 before parsing.
* **The status taxonomy.** 400/403/404/405/409/413/500/503 from the exact `verification_records`
  constants rather than `api.stable_code` substrings, with stored-state corruption (an unreadable
  binding, an unreadable execution, a non-JSON payload, an id that is not a digest, more rows than the
  writer may have written, a missing table) landing on one fixed `verification_storage_error` body that
  carries no driver text, path or payload.
* **One callable at a time, off the loop, freed only by its own thread.** A `Store` method parked behind
  a gate this file owns proves the serving loop stays responsive, proves a concurrent request is shed
  `503 verification_busy` with no second call, survives cancelling the awaiting request, and holds the
  lifespan's exclusive owner lock until that thread has really finished — including when the drain is
  cancelled over and over.

Every finite number below is a *failure* deadline or a sample this file chooses, never a promise about
how long the product may take: `offloop.wait_until` raises when a fact is not observed and
`offloop.stays_false` raises when an absence is broken. Fixture files are imported as *modules*
(`import test_verification_records as casebook`) so no foreign `TestCase` is collected twice. Every
scenario runs on a temporary database with no network and no live state, and no assertion depends on the
host clock: the server's clock is held here by `ServerClock`, and every clock-sensitive choice carries a
margin of days so it answers the same whether the patched instant or the host's is consulted.
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
import uuid
from unittest import mock

from tests import test_refusal_audit_offloop as offloop
from tests import test_verification_records as casebook
from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import api as api_module, refusals, verification_policy
from local_observe.platform import verification_records as records_module
from local_observe.platform.api import create_app
from local_observe.platform.state import Actor, Store
from local_observe.platform.verification_api import VerificationAPI, owns

NOW, PROPOSE_NOW = casebook.NOW, casebook.PROPOSE_NOW
TERMINAL, RECORD_NOW = casebook.TERMINAL, casebook.RECORD_NOW
READER, HUMAN, AGENT, RUNNER = casebook.READER, casebook.HUMAN, casebook.AGENT, casebook.RUNNER
SUMMARY, VERIFIER = casebook.SUMMARY, casebook.VERIFIER
SECOND_VERIFIER, UNLISTED = casebook.SECOND_VERIFIER, casebook.UNLISTED
SHA256, PIN, OTHER_PIN = casebook.SHA256, casebook.PIN, casebook.OTHER_PIN
WINDOW_SECONDS = casebook.WINDOW_SECONDS

#: The whole new HTTP surface: three literal reads and one literal write. `owns` is path-only, so the
#: records path is owned for both methods and the method split belongs to `handle`.
GET_BINDING = '/v1/verification/binding'
GET_RECORDS = '/v1/verification/records'
GET_RECORD = '/v1/verification/record'
POST_RECORDS = '/v1/verification/records'
OWNED = (GET_BINDING, GET_RECORDS, GET_RECORD)
PARAMETERS = {GET_BINDING: 'action_id', GET_RECORDS: 'execution_id', GET_RECORD: 'verification_id'}

#: Planted in submitted documents and in store paths. It reaches no response, no row and no log line.
SENTINEL = 'never-in-a-response-row-or-a-line'
#: A margin measured in years, so that whichever clock judged a statement — the one this file patches or
#: the host's own — a `LIVE` receipt is still live and an `EXPIRED` one died long ago. A verdict
#: assertion here is therefore never an assertion about how fast the machine was.
LIVE = dt.timedelta(days=400)
#: The two byte bounds the contract names. The query bound is also asserted of the fixtures that claim
#: to exceed it, so "one byte over" means one byte over this number and not over some other guess.
MAX_BODY_BYTES = 32_768
MAX_QUERY_BYTES = 256

SAFETY_TIMEOUT = offloop.SAFETY_TIMEOUT
MEMORY_READ_WINDOW = offloop.MEMORY_READ_WINDOW
IMMEDIATE_WINDOW = offloop.IMMEDIATE_WINDOW

TOKENS = {'verify-worker': 'verification-tests-producer-token-0000000001',
          'second-verifier': 'verification-tests-producer-token-0000000002',
          'test-detector': 'verification-tests-producer-token-0000000003',
          'operator': 'verification-tests-human-token-000000000001',
          'agent-1': 'verification-tests-proposer-token-000000001',
          'runner-1': 'verification-tests-executor-token-0000000001',
          'reader-1': 'verification-tests-reader-token-00000000001',
          'summary-1': 'verification-tests-summary-token-000000000001'}
CREDENTIALS = [{'identity': identity, 'role': role, 'token': TOKENS[identity]}
               for identity, role in (('verify-worker', 'producer'), ('second-verifier', 'producer'),
                                      ('test-detector', 'producer'), ('operator', 'human'),
                                      ('agent-1', 'proposer'), ('runner-1', 'executor'),
                                      ('reader-1', 'reader'), ('summary-1', 'summary'))]


def bearer(identity: str) -> list:
    return [(b'authorization', ('Bearer ' + TOKENS[identity]).encode())]


def query(route: str, value: str) -> bytes:
    """The one query string this route accepts, built from the parameter name it names."""
    return (PARAMETERS[route] + '=' + value).encode()


def case_key(case: dict, route: str) -> str:
    """The identifier one route is about, for the scenario at hand."""
    key = PARAMETERS[route]
    # Pre-record authorization probes still need a syntactically valid, absent digest.
    if key == 'verification_id' and key not in case:
        return '0' * 64
    return case[key]


@dataclasses.dataclass(frozen=True)
class Exchange:
    """One in-process ASGI exchange: what came back, and how much body the handler ever asked for."""

    status: int | None
    payload: dict | None
    raw: bytes
    messages: tuple
    reads: int

    @property
    def text(self) -> str:
        return self.raw.decode('utf-8', 'replace')


def _scope(method: str, path: str, query_string: bytes, headers: list) -> dict:
    return {'type': 'http', 'method': method, 'path': path, 'headers': headers,
            'query_string': query_string, 'scheme': 'http', 'client': ('127.0.0.1', 54321),
            'server': ('test', 80)}


def _receiver(reads: list, *, body: bytes, chunks: list | None, forbid_body: bool, disconnect: bool,
              label: str):
    """Build the `receive()` both drivers hand a handler: the instrument that says what was ever asked.

    `forbid_body` makes reading a body a test failure rather than a silent extra await, which is how
    "this answer is reachable from the credential, the path and the query alone" is decided. `chunks`
    delivers a body in pieces so a size gate can be caught refusing before the last piece arrived —
    `reads` is that evidence. `disconnect` answers `http.disconnect` and nothing else, forever, so a
    handler that kept asking gets no bytes and no hang.
    """
    pending = list(chunks) if chunks is not None else None

    async def receive():
        if forbid_body:
            raise AssertionError(f'{label}: this answer must not await a body chunk')
        reads.append(1)
        if disconnect:
            return {'type': 'http.disconnect'}
        if pending is not None:
            if pending:
                chunk = pending.pop(0)
                return {'type': 'http.request', 'body': chunk, 'more_body': bool(pending)}
            return {'type': 'http.request', 'body': b'', 'more_body': False}
        return {'type': 'http.request', 'body': body, 'more_body': False}

    return receive


def _exchange(messages: list, reads: list) -> Exchange:
    raw = messages[-1].get('body', b'') if len(messages) > 1 else b''
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = None
    return Exchange(status=messages[0]['status'] if messages else None, payload=payload, raw=raw,
                    messages=tuple(messages), reads=len(reads))


async def drive(app, method: str, path: str, *, query_string: bytes = b'', body: bytes = b'',
                chunks: list | None = None, identity: str | None = None, headers: list | None = None,
                forbid_body: bool = False, disconnect: bool = False,
                journal: offloop.Journal | None = None, label: str = '') -> Exchange:
    """Drive one `http` scope straight into `app`: no socket, no test client, nothing in between.

    When a journal is given, the instant this exchange's final body message arrives is noted, so a
    response can be ordered against real background work instead of against a guess about it.
    """
    messages, reads = [], []
    receive = _receiver(reads, body=body, chunks=chunks, forbid_body=forbid_body, disconnect=disconnect,
                        label=label or path)

    async def send(message):
        messages.append(message)
        if (journal is not None and message['type'] == 'http.response.body'
                and not message.get('more_body')):
            journal.note(f'response:{label or path}')

    scope = _scope(method, path, query_string,
                   headers if headers is not None else (bearer(identity) if identity else []))
    await app(scope, receive, send)
    return _exchange(messages, reads)


async def drive_handle(api, method: str, path: str, *, actor, query_string: bytes = b'',
                       body: bytes = b'', chunks: list | None = None, forbid_body: bool = False,
                       disconnect: bool = False) -> tuple[object, Exchange]:
    """Call `handle` directly and report what it *returned*, never what it wrote to a wire.

    `handle` is a function and not a transport: it answers with `(status, body)`, or `None` for a
    disconnected body, and it must never touch `send`. Any message here is therefore a finding, and
    every caller asserts `Exchange.messages` empty.
    """
    messages, reads = [], []
    receive = _receiver(reads, body=body, chunks=chunks, forbid_body=forbid_body, disconnect=disconnect,
                        label=path)

    async def send(message):
        messages.append(message)

    result = await api.handle(_scope(method, path, query_string, []), receive, actor)
    return result, Exchange(status=None, payload=None, raw=b'', messages=tuple(messages),
                            reads=len(reads))


@dataclasses.dataclass(frozen=True)
class StoreCall:
    """One synchronous `Store` call the service made, plus everything about the thread that made it."""

    method: str
    args: tuple
    kwargs: dict
    thread_name: str
    on_main_thread: bool
    running_loop: asyncio.AbstractEventLoop | None

    @property
    def rendered(self) -> str:
        return repr((self.method, self.args, self.kwargs))


class StoreSeam:
    """One real `Store` method, wrapped so its calls are countable and the first of them can be parked.

    The wrapper always delegates — nothing here replaces the product's SQL — it only observes when the
    product's own synchronous verification call was entered, from which thread, and when it came back.
    `PARK` blocks on a `threading.Event` this file owns *before* the real call, which turns "a
    verification callable is in flight" into a property of the fixture rather than a race. That wait is
    bounded, and `stop()` releases the gate before removing the patch, so an implementation that ran the
    work inline costs this file one failed sentence and never a hung suite.
    """

    OBSERVE = 'observe'
    PARK = 'park'

    def __init__(self, method: str, mode: str = OBSERVE, *, journal: offloop.Journal | None = None,
                 park_first: int = 1, safety: float = SAFETY_TIMEOUT) -> None:
        self.method = method
        self.mode = mode
        self.journal = journal if journal is not None else offloop.Journal()
        self.park_first = park_first
        self.safety = safety
        self.release = threading.Event()
        self.calls: list[StoreCall] = []
        self.starts = 0
        self.finishes = 0
        self.active = 0
        self.max_active = 0
        self.starved: list[float] = []
        self._lock = threading.Lock()
        self._patch = None
        self._real = getattr(Store, method)

    def start(self, test: unittest.TestCase | None = None) -> 'StoreSeam':
        """Install the wrapper. `test` registers the release-and-unpatch cleanup so nothing leaks."""
        if self._patch is None:
            seam = self

            def wrapper(store, *args, **kwargs):  # unbound: the store arrives as the first argument
                return seam.handle(args, kwargs, store)

            self._patch = mock.patch.object(Store, self.method, new=wrapper)
            self._patch.start()
        if test is not None:
            test.addCleanup(self.stop)
        return self

    def stop(self) -> None:
        if self._patch is not None:
            self.release.set()  # never leave a callable parked behind a removed patch
            self._patch.stop()
            self._patch = None

    def handle(self, args: tuple, kwargs: dict, store):
        thread = threading.current_thread()
        with self._lock:
            self.starts += 1
            ordinal = self.starts
            self.calls.append(StoreCall(method=self.method, args=tuple(args), kwargs=dict(kwargs),
                                        thread_name=thread.name,
                                        on_main_thread=thread is threading.main_thread(),
                                        running_loop=offloop.running_loop()))
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        self.journal.note(f'store:{self.method}:start')
        parked = self.mode == self.PARK and ordinal <= self.park_first
        try:
            if parked:
                if not self.release.wait(timeout=self.safety):
                    with self._lock:
                        self.starved.append(self.safety)
                    raise TimeoutError('the parked verification call was never released')
                self.journal.note('store:released')
            return self._real(store, *args, **kwargs)
        finally:
            self.journal.note(f'store:{self.method}:finish')
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
        """Every call this seam saw has come back. A snapshot, safe to poll from an event loop."""
        with self._lock:
            return self.active == 0 and self.finishes == self.starts

    def last(self) -> StoreCall:
        with self._lock:
            return self.calls[-1]

    def settled(self, timeout: float = SAFETY_TIMEOUT) -> bool:
        """Whether every call this seam saw has come back. Polled on this thread, never on a loop."""
        deadline = time.monotonic() + timeout
        while not self.quiet:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)
        return True


class ServerClock:
    """The server's own instant, held by this file: one value until a test says otherwise.

    `verification_records._clock` and `state.clock` are the two module-level helpers this package reads
    time from. Both are replaced with one function that answers this instant when a call names none and
    passes an explicit instant through untouched — which is how a fixture step that states its own `now`
    still lands where the fixture put it, while a submission (which carries no clock, by contract) is
    judged here. Advancing it is how "the evidence aged out between the two submissions" becomes a fact
    of the fixture rather than a wait.
    """

    def __init__(self, instant: dt.datetime) -> None:
        self.moment = instant
        self.patches: list = []

    def advance(self, delta: dt.timedelta) -> 'ServerClock':
        self.moment = self.moment + delta
        return self

    def read(self, now=None):
        return now or self.moment

    def install(self, test: unittest.TestCase) -> 'ServerClock':
        for target in ('local_observe.platform.verification_records._clock',
                       'local_observe.platform.state.clock'):
            handle = mock.patch(target, new=self.read)
            handle.start()
            self.patches.append(handle)
            test.addCleanup(handle.stop)
        return self


@contextlib.contextmanager
def counted_connections():
    """Yield a list that grows by one per `sqlite3.connect`, with every call delegated to the real one.

    `sqlite3.connect` is the single door every read and write in this package goes through — `Store`'s
    own transactions and `verification_reader`'s dedicated read-only connection alike — so this counts
    database work rather than guessing at it from timings. Callers must not open their own connections
    inside the context: the count is the claim.
    """
    calls: list = []
    real = sqlite3.connect

    def counting(*args, **kwargs):
        calls.append((args, kwargs))
        return real(*args, **kwargs)

    with mock.patch('local_observe.platform.state.sqlite3.connect', new=counting):
        yield calls


class VerificationAPIFixture(casebook.VerificationFixture):
    """The shared plumbing: an app per store, the held clock, and the exchanges every test repeats.

    Mixed into `TestCase` subclasses; it defines no tests of its own, which is what makes subclassing it
    safe to collect (the same rule `casebook.VerificationFixture` follows and `test_verification_reader`
    pins).
    """

    def hold_clock(self, instant: dt.datetime = RECORD_NOW) -> ServerClock:
        """Install (once per test) and return the clock every submission in this test is judged at."""
        if getattr(self, '_server_clock', None) is None:
            self._server_clock = ServerClock(instant).install(self)
        return self._server_clock

    def moment(self) -> dt.datetime:
        return self.hold_clock().moment

    def run_async(self, coroutine):
        """Keep setup and subsequent requests to each app on this fixture's loop."""
        return self.async_runner.run(coroutine)

    def finish_async(self):
        """Release app services before the serving loop and temporary stores disappear."""
        async def drain():
            for app in self.async_apps:
                for service in (app.verification_api, app.refusal_audit_dispatch):
                    service.close()
                    await service.wait_idle()

        try:
            self.async_runner.run(drain())
        finally:
            self.async_runner.close()

    def setUp(self) -> None:
        """One shared journal, and a stub for the startup tree digest.

        `observe_startup` hashes the whole source tree into the `GET /v1/runtime` snapshot; it has
        nothing to do with this seam, and this file builds an app per scenario, so it is replaced with a
        constant dict for these tests only. Nothing that is asserted here comes from it: the only runtime
        field this file reads is `refusal_audit_dispatch`, which `create_app` publishes itself.
        """
        super().setUp()
        self.async_runner = asyncio.Runner()
        self.async_apps = []
        self.addCleanup(self.finish_async)
        self.journal = offloop.Journal()
        startup = mock.patch('local_observe.platform.runtime.observe_startup',
                             new=lambda mode, configured: {'notification_mode': mode,
                                                           'sender_configured': bool(configured),
                                                           'stubbed_startup_snapshot': True})
        startup.start()
        self.addCleanup(startup.stop)

    def serving(self, name='api', *, outcome='succeeded', **event_fields) -> dict:
        """A real case — fired, proposed, decided, claimed, reported — plus the app that serves it.

        The policy mounted is `casebook.VerificationFixture.policy()`'s, with this file's two verifier
        identities allowlisted. The preconditions are asserted by the fixture this delegates to: `bound`
        reads the binding back through the public read, and `executed` walks decide/claim/outcome, so a
        scenario that failed to reach `succeeded` cannot silently become a test of something else. A
        test that wants a different policy says so by building its own case with `self.bound`.
        """
        case = self.bound(name, policy=self.policy(), **event_fields)
        self.executed(case, outcome)
        case['app'] = self.app(case['store'])
        return case

    def app(self, store: Store):
        """`create_app` digests the source tree, so a test builds the app it needs and reuses it."""
        created = create_app(store, CREDENTIALS, self.gate)
        self.assertIsInstance(created.verification_api, VerificationAPI)
        self.async_apps.append(created)
        return created

    def seam(self, method: str, mode: str = StoreSeam.OBSERVE, *, park_first: int = 1,
             journal: offloop.Journal | None = None) -> StoreSeam:
        return StoreSeam(method, mode, journal=journal or getattr(self, 'journal', None),
                         park_first=park_first).start(self)

    def body(self, case, **changes) -> bytes:
        """One submitted statement, as the bytes a producer would put in a POST body."""
        return json.dumps(self.statement(case, **changes)).encode()

    def statement_at(self, case, *, ends_at=None, seconds=WINDOW_SECONDS, values=(70.0,), count=1,
                     outcome='available', expires=LIVE, **receipt_changes) -> dict:
        """A statement over the captured origin whose receipt is unambiguously live, or long dead.

        `expires` is a delta from the fixture instant rather than an instant: `LIVE` is a year out and
        the narrow in-fixture expiries are written by the tests that need them, so no verdict here turns
        on which clock the server consulted.
        """
        window = self.window(case, ends_at=ends_at, seconds=seconds)
        rows = self.rows(case, window, list(values)) if values else []
        receipt = (None if outcome != 'available' and not receipt_changes else
                   self.receipt(case, window, count=count,
                                expires_at=utc_text(self.moment() + expires), **receipt_changes))
        return self.statement(case, window=window, outcome=outcome, receipt=receipt, samples=rows)

    async def get(self, case, route: str = GET_BINDING, value=None, *, identity=READER.identity,
                  forbid_body=False, app=None) -> Exchange:
        return await drive(app or case['app'], 'GET', route,
                           query_string=query(route, case_key(case, route) if value is None else value),
                           identity=identity, forbid_body=forbid_body, label=f'GET {route}')

    async def post(self, case, *, identity=VERIFIER.identity, body: bytes | None = None,
                   forbid_body=False, disconnect=False, chunks=None, app=None,
                   label='POST records') -> Exchange:
        return await drive(app or case['app'], 'POST', POST_RECORDS,
                           body=self.body(case) if body is None else body, identity=identity,
                           chunks=chunks, forbid_body=forbid_body, disconnect=disconnect, label=label)

    async def submit(self, case, *, identity=VERIFIER.identity, app=None, **changes) -> Exchange:
        """POST one statement built from the case, and hand back the exchange to assert on."""
        return await drive(app or case['app'], 'POST', POST_RECORDS, body=self.body(case, **changes),
                           identity=identity, label='POST records')

    def serving_app(self, case):
        """The app a case is served by — the same instance every request in that scenario used.

        A scenario that built its case with `bound`/`open` and its app separately hands this helper the
        case (or the store) rather than the app; in that case a fresh app over the same store is built,
        which is the weaker of the two readings of "nothing reached the dispatcher". Every scenario that
        can make the strong claim passes an app-derived case, and does so explicitly.
        """
        if isinstance(case, Store):
            return self.app(case)
        if isinstance(case, dict):
            return case['app'] if 'app' in case else self.app(case['store'])
        return case

    async def runtime(self, case, app=None) -> dict:
        """One memory-only read of the block the asynchronous audit writer published, with its status checked where read."""
        reply = await offloop.bounded(drive(self.serving_app(app) if app is not None
                                           else self.serving_app(case),
                                            'GET', '/v1/runtime', identity=READER.identity,
                                            label='runtime'),
                                      SAFETY_TIMEOUT, what='GET /v1/runtime to answer')
        self.assertEqual(reply.status, 200, f'GET /v1/runtime stopped answering: {reply.payload}')
        return reply.payload

    def stored(self, case, verification_id=None, actor=HUMAN) -> dict:
        return case['store'].get_verification(verification_id or case['verification_id'], actor)

    def listed(self, case, actor=HUMAN) -> list:
        return case['store'].list_verifications(case['execution_id'], actor)

    def operations(self, store: Store, operation: str) -> list:
        """The stored audit rows of one operation, newest first as `records` returns them."""
        rows = store.records('audit', 100)
        self.assertLess(len(rows), 100, 'the fixture audit census must not be truncated')
        return [row for row in rows if row['operation'] == operation]

    def assert_store_refusal_free(self, case) -> None:
        """A verification refusal is not an action attempt: no row, no budget token, no dispatcher job.

        Two durable surfaces here (the audit table and `Store`'s own counters); the third, this app
        instance's dispatcher tally, is checked by the async tests, which are the ones that can read it.
        """
        self.assertEqual(self.operations(case['store'], refusals.OPERATION), [],
                         'a verification refusal wrote an action-refusal row')
        counters = case['store'].refusal_audit_status()
        self.assertEqual([counters[name] for name in ('written', 'dropped', 'failed', 'unauditable')],
                         [0, 0, 0, 0], 'a verification refusal spent the action-refusal budget')

    async def assert_dispatch_idle(self, case, app=None) -> None:
        block = (await self.runtime(case, app=app))['refusal_audit_dispatch']
        self.assertEqual((int(block['admitted']), int(block['overloaded']), int(block['failed'])),
                         (0, 0, 0), 'a verification refusal reached the summary-audit dispatcher')
        self.assertIs(block['closed'], False, 'an app that never shut down reported itself closed')

    def answer_of(self, reply) -> tuple[int | None, dict | None, str]:
        """Read one answer as (status, body, text), whether it came off the wire or out of `handle`."""
        if isinstance(reply, Exchange):
            return reply.status, reply.payload, reply.text
        self.assertIsInstance(reply, tuple, f'not an answer this file understands: {reply!r}')
        self.assertEqual(len(reply), 2, 'handle answers (status, body) and nothing else')
        self.assertIsInstance(reply[0], int, 'the status handle returned was not an int')
        self.assertIsInstance(reply[1], dict, 'the body handle returned was not a dict')
        return reply[0], reply[1], json.dumps(reply[1], sort_keys=True)

    def assert_fixed(self, reply, code: str, *, sentinels=(), label='') -> None:
        """One known machine code, at most one fixed sentence beside it, and nothing that was submitted.

        The contract fixes the code and forbids payload, path and driver text; it does not hand this file
        the wording of every sentence, so wording is not asserted here. What a regression cannot walk
        away with is the closed field set, the single short line, and the absence of the caller's bytes.
        """
        status, body, text = self.answer_of(reply)
        self.assertIsNotNone(body, f'{label}: an error answer with no body at all')
        self.assertEqual(body.get('error'), code,
                         f'{label}: wanted {code} and got {status} {text[:300]}')
        self.assertLessEqual(set(body), {'error', 'detail'},
                             f'{label}: an error body grew a field: {text[:300]}')
        if 'detail' in body:
            detail = body['detail']
            self.assertIsInstance(detail, str, label)
            self.assertTrue(detail and '\n' not in detail and len(detail) < 200,
                            f'{label}: a fixed sentence is one short line, not {detail!r}')
        for value in sentinels:
            self.assertNotIn(value, text, f'{label}: the response echoed submitted input')

    def assert_storage_error(self, reply, *, sentinels=(), label='') -> None:
        """Every stored-state failure is the same body, whatever the file was hiding."""
        status, body, _ = self.answer_of(reply)
        self.assertEqual(status, 500, f'{label}: wanted 500, got {status}')
        self.assertEqual(body, {'error': 'verification_storage_error'},
                         f'{label}: a 500 body named something besides its own kind')
        rendered = json.dumps(body)
        for value in tuple(sentinels) + ('SELECT', 'sqlite', 'Traceback', '.db', SENTINEL):
            self.assertNotIn(value, rendered, f'{label}: a 500 body carried {value!r}')


class SeamSurfaceTests(VerificationAPIFixture):
    """The shape of the seam itself: which paths are owned, what construction costs, what is not read.

    `owns` is the whole routing decision `api.create_app` makes, so it is tested as a matcher over
    near-misses rather than as a truth table over the three paths it accepts: a prefix matcher, a
    case-folded one or one that trims a trailing slash would each answer the three named paths exactly
    like the real thing and widen the surface anyway.
    """

    def test_owns_names_three_literal_paths_and_not_one_shape_more(self):
        """No prefix, no suffix, no case, no slash, no query, no bytes.

        `POST /v1/verification/records` is the same *path* as the list read, which is why `owns` is
        path-only and the method split lives in `handle`; `GET /v1/verification/record` is one character
        away from the list path and is a different route, so the pair is asserted together.
        """
        self.assertEqual(sorted(OWNED), ['/v1/verification/binding', '/v1/verification/record',
                                        '/v1/verification/records'])
        self.assertEqual(POST_RECORDS, GET_RECORDS)
        for path in OWNED:
            self.assertTrue(owns(path), f'{path} is one of the three named routes')
        for near in ('', '/', '/v1', '/v1/', '/v1/verification', '/v1/verification/',
                     '/v1/verification', GET_BINDING + '/', GET_BINDING + '/extra',
                     GET_BINDING + '?action_id=x', GET_BINDING + ' ', ' ' + GET_BINDING,
                     GET_BINDING.upper(), GET_RECORDS + 'x', GET_RECORD + '?x=1',
                     GET_RECORD + '/', '/V1/verification/binding', '/v1/Verification/records',
                     '//v1/verification/record', '/v1//verification/record',
                     '/v1/verification/records/', '/v2/verification/binding',
                     '/v1/verification/binding%20', 'x' + GET_BINDING):
            self.assertFalse(owns(near), f'owns({near!r}) widened the surface')
        for not_a_path in (None, 1, b'/v1/verification/binding', ['action_id'], object()):
            try:
                claimed = bool(owns(not_a_path))
            except (TypeError, AttributeError):
                claimed = False  # a refusal to consider a non-path is as good an answer as `False`
            self.assertFalse(claimed, f'owns({not_a_path!r}) claimed a path it was never given')
        self.assertTrue(owns(GET_BINDING) and not owns(GET_BINDING[:-1] + ']'))

    def test_construction_costs_no_thread_and_a_refused_request_still_does(self):
        """No executor at construction, and none for a request that never reaches a `Store` call.

        The only thread this service may own is one running an actual synchronous call, so the
        observation is the identity set of live threads: a pool started eagerly, a worker per app, or a
        thread per request each adds a name to it, and neither is what the seam promised.
        """
        case = self.serving('thread-free')
        before = set(threading.enumerate())
        api = VerificationAPI(case['store'])
        self.assertEqual(set(threading.enumerate()), before, 'construction started a thread')

        async def scenario():
            refused = await drive_handle(api, 'POST', POST_RECORDS, actor=SUMMARY, body=self.body(case))
            self.assertEqual(refused[1].messages, ())
            self.assertEqual(refused[0], (403, {'error': 'summary_only'}))
            unreadable = await drive_handle(api, 'POST', POST_RECORDS, actor=VERIFIER, body=b'{oops')
            self.assertEqual(unreadable[0][0], 400)
            blank = await drive_handle(api, 'GET', GET_BINDING, actor=READER, query_string=b'')
            self.assertEqual(blank[0][0], 400)
            unowned = await drive_handle(api, 'GET', '/v1/status', actor=READER)
            self.assertIsNone(unowned[0])

        self.run_async(scenario())
        self.assertEqual(set(threading.enumerate()), before,
                         'a request that never reached the store still bought a thread')

    def test_handle_abstains_on_every_path_it_was_not_given(self):
        """`None` means "not mine", and it is the answer `api.py` needs to keep answering the old routes.

        Asserted on the return value *and* on `send`: an implementation that answered the wire itself
        would double-respond once `api.py` also returned, and one that read the body on the way to
        noticing the path was not its own would cost a chunk to a route that owes nothing.
        """
        case = self.serving('unowned')
        api = VerificationAPI(case['store'])

        async def scenario():
            for path, method in (('/v1/status', 'GET'), ('/v1/me', 'GET'), ('/v1/verification', 'GET'),
                                 (GET_BINDING + '/', 'GET'), ('/v1/verification/recordsx', 'GET'),
                                 ('/v1/events', 'POST')):
                with self.subTest(path=path, method=method):
                    result, seen = await drive_handle(api, method, path, actor=VERIFIER,
                                                     body=b'{"a": 1}')
                    self.assertIsNone(result, f'handle answered {path} instead of leaving it')
                    self.assertEqual(seen.messages, (), 'handle wrote to send; only api.py may')
                    self.assertEqual(seen.reads, 0, 'an unowned path still cost a body chunk')
            owned = await drive_handle(api, 'GET', GET_BINDING, actor=READER,
                                      query_string=query(GET_BINDING, case['action_id']))
            self.assertEqual(self.answer_of(owned[0])[0], 200, 'the three named paths must be owned')
            denied = await drive_handle(api, 'POST', POST_RECORDS, actor=Actor('', 'producer'),
                                       body=self.body(case))
            status, body, _ = self.answer_of(denied[0])
            self.assertEqual((status, body.get('error')),
                             (403, 'not_authorised'), 'an empty identity was admitted')
            foreign = await drive_handle(api, 'POST', POST_RECORDS, actor=SUMMARY,
                                        body=self.body(case))
            self.assertEqual(self.answer_of(foreign[0])[:2],
                             (403, {'error': 'summary_only'}), 'handle answered the write role by wire')

        asyncio.run(scenario())

    def test_close_is_immediate_idempotent_and_leaves_no_room_for_another_call(self):
        """Admission closes synchronously, twice is once, and everything after it is one fixed 503.

        Parsing still runs first (a malformed body is still a 400 after `close()`), so a closed gate is
        never mistaken for a parser; and nothing after `close()` may reach `Store`, which is what the
        counting seam proves while the response says "busy".
        """
        case = self.serving('closed')
        api = VerificationAPI(case['store'])
        seam = self.seam('put_verification')
        api.close()
        api.close()

        async def scenario():
            closed = await offloop.bounded(drive_handle(api, 'POST', POST_RECORDS, actor=VERIFIER,
                                                       body=self.body(case)),
                                          SAFETY_TIMEOUT, what='a closed-admission POST to answer')
            self.assertEqual(closed[1].messages, ())
            self.assertEqual(closed[0], (503, {'error': 'verification_busy'}))
            read = await offloop.bounded(drive_handle(api, 'GET', GET_BINDING, actor=READER,
                                                     query_string=query(GET_BINDING, case['action_id'])),
                                        SAFETY_TIMEOUT, what='a closed-admission GET to answer')
            self.assertEqual(read[0], (503, {'error': 'verification_busy'}),
                             'closing admission only spoke for writes')
            broken = await drive_handle(api, 'POST', POST_RECORDS, actor=VERIFIER, body=b'{not json')
            self.assertEqual(broken[0][0], 400, 'a closed gate became a parser verdict')
            self.assert_fixed(broken[0], 'invalid_request', label='closed POST with an unreadable body')
            summary = await drive_handle(api, 'POST', POST_RECORDS, actor=SUMMARY, body=self.body(case))
            self.assertEqual(summary[0], (403, {'error': 'summary_only'}),
                             'a closed gate outranked the role gate')
            await offloop.bounded(api.wait_idle(), SAFETY_TIMEOUT, what='an idle wait_idle to return')

        self.run_async(scenario())
        self.assertEqual(seam.count, 0, 'a closed admission still reached the store')
        self.assertEqual(self.listed(case, HUMAN), [], 'a closed admission wrote anyway')

    def test_this_service_reads_no_environment_and_opens_no_policy_file(self):
        """Mounting a policy is the factory's job, so a named file stays shut behind this class.

        A perfectly good policy document is put where `LO_VERIFICATION_POLICY` says it lives, over a
        store that was built with no policy at all: if this class consulted the environment the write
        below would be accepted, and the answer it must give instead is one that says no policy is
        mounted here.
        """
        case = self.bound('no-env', policy=None)
        self.executed(case)
        document = self.root / 'mounted-but-not-here.json'
        document.write_text(json.dumps(self.document()), 'utf-8')
        with mock.patch.dict(os.environ, {'LO_VERIFICATION_POLICY': str(document)}, clear=True):
            app = self.app(case['store'])

            async def scenario():
                refused = await drive(app, 'POST', POST_RECORDS, body=self.body(case),
                                     identity=VERIFIER.identity, label='POST records')
                self.assertEqual(refused.status, 503, f'no policy mounted here, so: {refused.text}')
                self.assert_fixed(refused, 'verification_unavailable', label='unmounted policy')

            asyncio.run(scenario())
        self.assertEqual(self.operations(case['store'], records_module.AUDIT_OPERATION), [],
                         'the environment-mounted policy was used after all')


class LifecycleTests(VerificationAPIFixture):
    """One real lifecycle, seen only through the four routes, on temporary files.

    Nothing here is staged through a stub: the incident came from `intake`, the binding from the
    proposal's own transaction over a real inventory index, the execution from a runner's claim, and the
    verdict from the server's judgement of a receipt `store.client.build_outcome` printed. What the
    transport may add is only a status line and a body, so each test reads the durable row back too.
    """

    def test_the_four_routes_walk_one_lifecycle_and_a_reopen_answers_identically(self):
        """Binding, list, submit, record, replay, reopen — the whole promise in one order.

        `created` is the only thing that distinguishes the first acceptance from an exact replay, and
        both are HTTP 200 with the same id: a transport that turned the replay into a 201, a 204 or an
        envelope would make an idempotent retry look like a new fact. The reopen is what proves the
        second half — the answers are stored, not derived per connection.
        """
        case = self.serving('lifecycle')

        async def scenario():
            binding = await self.get(case)
            self.assertEqual(binding.status, 200)
            self.assertEqual(binding.payload, case['binding'])
            self.assertEqual(sorted(binding.payload), sorted(casebook.BINDING_FIELDS))
            empty = await self.get(case, GET_RECORDS)
            self.assertEqual((empty.status, empty.payload), (200, {'verification_ids': []}))
            absent = await self.get(case, GET_RECORD, 'f' * 64)
            self.assertEqual(absent.status, 404)
            self.assert_fixed(absent, 'not_found', sentinels=('f' * 64,), label='absent record')

            answer = await self.submit(case, **self.statement_at(case))
            self.assertEqual(answer.status, 200)
            self.assertEqual(sorted(answer.payload), ['created', 'verification_id'])
            self.assertIs(answer.payload['created'], True)
            case['verification_id'] = answer.payload['verification_id']
            self.assertRegex(case['verification_id'], SHA256)

            listed = await self.get(case, GET_RECORDS)
            self.assertEqual((listed.status, listed.payload),
                             (200, {'verification_ids': [case['verification_id']]}))
            record = await self.get(case, GET_RECORD)
            self.assertEqual(record.status, 200)
            self.assertEqual(record.payload, case['store'].get_verification(
                case['verification_id'], HUMAN))
            self.assertEqual(sorted(record.payload), sorted(casebook.RECORD_FIELDS))
            self.assertEqual(record.payload['verdict'], 'cleared')

            replay = await self.submit(case, **self.statement_at(case))
            self.assertEqual(replay.payload, {**answer.payload, 'created': False})
            self.assertEqual((await self.get(case, GET_RECORD)).payload, record.payload,
                             'a replay rewrote a verdict')
            await self.assert_dispatch_idle(case)

        self.run_async(scenario())
        reopened = self.open(case['name'], policy=case['policy'])
        second = self.app(reopened)

        async def reread():
            again = await drive(second, 'GET', GET_RECORD, identity=READER.identity,
                               query_string=query(GET_RECORD, case['verification_id']))
            self.assertEqual(again.payload, reopened.get_verification(case['verification_id'], HUMAN))
            listed = await drive(second, 'GET', GET_RECORDS, identity=READER.identity,
                                query_string=query(GET_RECORDS, case['execution_id']))
            self.assertEqual(listed.payload, {'verification_ids': [case['verification_id']]})
            binding = await drive(second, 'GET', GET_BINDING, identity=READER.identity,
                                 query_string=query(GET_BINDING, case['action_id']))
            self.assertEqual(binding.payload, case['binding'])
            retry = await drive(second, 'POST', POST_RECORDS, identity=VERIFIER.identity,
                               body=json.dumps(self.statement_at(case)).encode())
            self.assertEqual((retry.status, retry.payload),
                             (200, {'verification_id': case['verification_id'], 'created': False}))

        self.run_async(reread())
        self.assertEqual(len(self.operations(reopened, records_module.AUDIT_OPERATION)), 1,
                         'a replay added a second audit row')
        self.assertEqual(self.operations(reopened, refusals.OPERATION), [])

    def test_a_binding_read_is_the_captured_document_and_a_fresh_copy_each_time(self):
        """What a reader mutates is its own parsed JSON, never the stored provenance.

        The HTTP answer is a fresh parse on every caller's side, so the claim that survives the wire is
        "a second read still says threshold 90 and one target" after the first reader rewrote every
        field it could reach — including the two nested ones.
        """
        case = self.serving('binding-copy')

        async def scenario():
            first = await self.get(case)
            self.assertEqual(first.payload, case['binding'])
            tampered = json.loads(first.text)
            tampered['status'] = 'bound'
            tampered['reason'] = SENTINEL
            tampered['binding_id'] = OTHER_PIN
            tampered['origin']['threshold'] = 0.0
            tampered['origin']['action_targets'].append(self.service)
            second = await self.get(case)
            self.assertEqual(second.payload, case['binding'], 'a binding read leaked the stored document')
            self.assertEqual(second.payload['origin']['threshold'], 90.0)
            self.assertEqual(second.payload['origin']['action_targets'], [self.host])
            self.assertNotIn(SENTINEL, json.dumps(
                case['store'].get_verification_binding(case['action_id'], HUMAN)))

        self.run_async(scenario())

    def test_exact_replay_after_the_evidence_aged_out_is_the_same_answer_and_regrades_nothing(self):
        """Idempotence is not a re-judgement, and the server clock is the only clock.

        Three things are pinned together: the submission was judged at the clock this file holds (the
        stored stamp says so, which is also the assertion that no caller-supplied instant was accepted —
        a statement carries no clock field); a replay after the receipt died returns the first answer
        with the first verdict; and a *new* window at that same later instant is still graded, which is
        what makes the unchanged verdict a fact about the replay rather than about a stopped clock.
        """
        case = self.serving('replay')
        statement = self.statement_at(case, values=(150.0,), expires=dt.timedelta(minutes=10))

        async def scenario():
            answer = await self.submit(case, **statement)
            self.assertEqual(answer.status, 200, answer.text)
            case['verification_id'] = answer.payload['verification_id']
            graded = await self.get(case, GET_RECORD)
            self.assertEqual((graded.payload['verdict'], graded.payload['reason']),
                             ('not_cleared', 'comparison-failed'))
            self.assertEqual(graded.payload['recorded_at'], utc_text(self.moment()),
                             'the statement was not judged at the server clock this file holds')
            self.hold_clock().advance(dt.timedelta(days=2))
            stale = await self.submit(case, **statement)
            self.assertEqual(stale.status, 200)
            self.assertEqual(stale.payload, {**answer.payload, 'created': False})
            after = await self.get(case, GET_RECORD)
            self.assertEqual(after.payload, graded.payload, 'an aged-out replay re-graded the verdict')
            # The control write is a *new* check, filed after this receipt died: an answer about it proves
            # the clock moved and that new writes are still judged, so the unchanged verdict above is a
            # fact about the replay and not about a server that stopped judging.
            control = self.statement_at(case, ends_at=self.moment() - dt.timedelta(minutes=6),
                                       values=(150.0,), expires=-dt.timedelta(minutes=1))
            fresh = await self.submit(case, **control)
            self.assertEqual(fresh.status, 200, fresh.text)
            moved = await self.get(case, GET_RECORD, fresh.payload['verification_id'])
            self.assertEqual((moved.payload['verdict'], moved.payload['reason']),
                             ('unknown', 'evidence-expired'),
                             'the control write proves the clock the replay was judged against moved')

        self.run_async(scenario())
        self.assertEqual(len(self.operations(case['store'], records_module.AUDIT_OPERATION)), 2,
                         'the replay wrote an audit row of its own')

    def test_a_changed_statement_under_one_identity_is_a_conflict_that_rewrites_nothing(self):
        """`RETRY_CHANGED` is a 409, and the first statement stands exactly where it was.

        The mutation is one a client could send by accident — a re-read that landed on different rows —
        and the answer must not be a second opinion, an overwrite, or a new audit row. A *different*
        window is a different check and stays admissible, which is the positive control that keeps this
        refusal about identity rather than about the caller.
        """
        case = self.serving('conflict')
        first = self.statement_at(case)

        async def scenario():
            answer = await self.submit(case, **first)
            case['verification_id'] = answer.payload['verification_id']
            before = await self.get(case, GET_RECORD)
            changed = self.statement_at(case, values=(150.0,))
            conflict = await self.submit(case, **changed)
            self.assertEqual(conflict.status, 409, conflict.text)
            self.assert_fixed(conflict, 'conflict', sentinels=('150.0', str(self.host)),
                              label='changed retry')
            after = await self.get(case, GET_RECORD)
            self.assertEqual(after.payload, before.payload, 'a conflict rewrote the first statement')
            listed = await self.get(case, GET_RECORDS)
            self.assertEqual(listed.payload, {'verification_ids': [case['verification_id']]})
            later = self.statement_at(case, ends_at=TERMINAL + dt.timedelta(minutes=9))
            another = await self.submit(case, **later)
            self.assertEqual((another.status, another.payload['created']), (200, True),
                             'a later window is a different check, not a conflict')

        self.run_async(scenario())
        self.assertEqual(len(self.operations(case['store'], records_module.AUDIT_OPERATION)), 2,
                         'the conflict was newsworthy')
        self.assert_store_refusal_free(case)

    def test_an_executing_execution_is_a_conflict_and_an_unknown_one_is_not_found(self):
        """A run that may still be in flight is not judgeable, and an id nobody issued has no document.

        `executing` is a fact about live state the caller cannot see from here (409), while an execution
        or action that does not exist is not a verification question at all (404) — and neither answer
        may be dressed up as an empty success, which is how "nothing recorded" and "no such thing" get
        confused later.
        """
        running = self.serving('executing', outcome=None)

        async def scenario():
            refused = await self.submit(running, **self.statement_at(running))
            self.assertEqual(refused.status, 409, refused.text)
            self.assert_fixed(refused, 'conflict', label='executing execution')
            self.assertEqual((await self.get(running, GET_RECORDS)).payload, {'verification_ids': []})
            lost = dict(running, execution_id=str(uuid.uuid4()), verification_id='e' * 64)
            missing = await self.submit(lost, **self.statement_at(lost))
            self.assertEqual(missing.status, 404, missing.text)
            self.assert_fixed(missing, 'not_found', label='absent execution')
            self.assertEqual((await self.get(lost, GET_RECORDS)).status, 404)
            stranger = dict(running, action_id=str(uuid.uuid4()))
            self.assertEqual((await self.get(stranger, GET_BINDING)).status, 404,
                             'an action this build never saw was answered as if it had been')
            self.assertEqual((await self.get(running, GET_BINDING)).status, 200,
                             'the control binding for the action that does exist stopped answering')
            self.assertEqual((await self.get(running, GET_RECORD, 'e' * 64)).status, 404)

        self.run_async(scenario())
        self.assert_store_refusal_free(running)
        self.assertEqual(self.operations(running['store'], records_module.AUDIT_OPERATION), [])

    def test_a_revoked_verifier_may_write_nothing_and_read_nothing_although_the_record_stands(self):
        """Authority is today's, and immutable history is a different question.

        A replay by a credential the current policy stopped naming is still refused (so "I wrote this
        yesterday" is not a capability), the record keeps reading to an ordinary reader field-for-field,
        and a verifier still on the list can add a new window to the same execution — the refusal is the
        identity, not the store.
        """
        case = self.serving('revoked')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        before = self.stored(case)
        revoked = self.open(case['name'], policy=self.policy(verifiers=[SECOND_VERIFIER.identity]))
        second = self.app(revoked)

        async def scenario():
            replay = await self.submit(case, app=second, **self.statement_at(case))
            self.assertEqual(replay.status, 403, replay.text)
            self.assert_fixed(replay, 'not_authorised', label='revoked verifier replay')
            denied = await self.get(case, GET_RECORD, app=second, identity=VERIFIER.identity)
            self.assertEqual(denied.status, 403)
            still = await self.get(case, GET_RECORD, app=second, identity=READER.identity)
            self.assertEqual(still.payload, before, 'revocation deleted history')
            again = await self.submit(case, app=second, identity=SECOND_VERIFIER.identity,
                                      **self.statement_at(case, ends_at=TERMINAL +
                                        dt.timedelta(minutes=9)))
            self.assertEqual((again.status, again.payload['created']), (200, True))

        self.run_async(scenario())
        self.assertEqual(revoked.get_verification(case['verification_id'], HUMAN), before)

    def test_with_no_policy_mounted_reads_still_read_and_writes_say_unavailable(self):
        """Default off is a read-only world: ordinary roles see history, and the policy answer precedes
        the allowlist answer, so an unlisted producer is told the same thing a listed one is.

        `verification_unavailable` is a 503 rather than a 403 because "this deployment mounted no policy"
        is not the caller's mistake to fix — and it is *not* a 500, because nothing about the file is
        broken. Reads keep working with no policy at all, which is what lets an operator roll the policy
        away and still audit what was already recorded.
        """
        case = self.serving('off')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        written = self.stored(case)
        off = self.open(case['name'], policy=None)
        app = self.app(off)

        async def scenario():
            record = await self.get(case, GET_RECORD, app=app, identity=READER.identity)
            self.assertEqual(record.payload, written)
            binding = await self.get(case, GET_BINDING, app=app, identity=HUMAN.identity)
            self.assertEqual(binding.payload, case['binding'])
            listed = await self.get(case, GET_RECORDS, app=app, identity=RUNNER.identity)
            self.assertEqual(listed.payload, {'verification_ids': [case['verification_id']]})
            for identity in (VERIFIER.identity, SECOND_VERIFIER.identity, UNLISTED.identity):
                with self.subTest(producer=identity):
                    refused = await self.submit(case, app=app, identity=identity,
                                               **self.statement_at(case,
                                                   ends_at=TERMINAL + dt.timedelta(minutes=11)))
                    self.assertEqual(refused.status, 503, refused.text)
                    self.assert_fixed(refused, 'verification_unavailable', label='no policy')
            for identity in (READER.identity, HUMAN.identity, AGENT.identity, RUNNER.identity,
                             SUMMARY.identity):
                with self.subTest(writer=identity):
                    refused = await self.submit(case, app=app, identity=identity,
                                               **self.statement_at(case))
                    self.assertEqual(refused.status, 403, refused.text)
                    code = 'summary_only' if identity == SUMMARY.identity else 'not_authorised'
                    self.assert_fixed(refused, code, label='not a producer')
            self.assertEqual((await self.get(case, GET_RECORD, app=app,
                                            identity=VERIFIER.identity)).status, 403,
                             'a producer is not a reader without a policy')

        self.run_async(scenario())
        self.assertEqual(off.get_verification(case['verification_id'], HUMAN), written,
                         'a refused write reached the record')
        self.assert_store_refusal_free(dict(case, store=off))

    def test_a_succeeded_execution_still_firing_is_not_cleared_and_closes_nothing(self):
        """The remediation invariants invariant over HTTP: a verdict is one audit row, and the incident does not move.

        A clean run, a complete read, and a metric outside its threshold: `not_cleared` is filed, and the
        incident is exactly where it was — status counts, incident and outbox rows, and the action and
        execution each still carrying the runner's own outcome. A `cleared` verdict is checked the same
        way, because the failure mode this pins is an automatic close on a good reading.
        """
        case = self.serving('still-firing')
        store = case['store']
        before = store.status()
        outbox, incidents = store.records('outbox', 10), store.records('incidents', 10)

        async def scenario():
            answer = await self.submit(case, **self.statement_at(case, values=(150.0,)))
            self.assertEqual(answer.status, 200, answer.text)
            case['verification_id'] = answer.payload['verification_id']
            graded = await self.get(case, GET_RECORD)
            self.assertEqual((graded.payload['verdict'], graded.payload['reason']),
                             ('not_cleared', 'comparison-failed'))
            self.assertEqual(graded.payload['value'], 150.0)

        self.run_async(scenario())
        self.assertEqual(store.status(), before, 'a verdict moved the platform')
        self.assertEqual(store.records('outbox', 10), outbox)
        self.assertEqual(store.records('incidents', 10), incidents)
        self.assertEqual(store.status()['incidents'], {'open': 1})
        action = next(row for row in store.records('actions', 50) if row['id'] == case['action_id'])
        execution = next(row for row in store.records('executions', 50)
                         if row['id'] == case['execution_id'])
        self.assertEqual((action['status'], execution['status']), ('succeeded', 'succeeded'),
                         "the verdict overwrote the runner's own outcome")
        rows = self.operations(store, records_module.AUDIT_OPERATION)
        self.assertEqual(len(rows), 1, 'the only durable addition is one audit row')
        self.assertEqual(json.loads(rows[0]['detail']),
                         {'verdict': 'not_cleared', 'reason': 'comparison-failed'})

        cleared = self.serving('cleared-closes-nothing')

        async def recovered():
            answer = await self.submit(cleared, **self.statement_at(cleared))
            cleared['verification_id'] = answer.payload['verification_id']

        self.run_async(recovered())
        self.assertEqual(self.stored(cleared)['verdict'], 'cleared')
        self.assertEqual(cleared['store'].status()['incidents'], {'open': 1},
                         'a clearance resolved an incident')

    def test_two_windows_are_two_checks_and_the_id_list_is_lexical(self):
        """Discovery answers "which checks does this run carry" and nothing else, in one fixed order.

        The list is ids, sorted lexically rather than by when they landed, and each id is readable back
        as its own document — which is the whole reason the list exists: a caller holding an execution has
        no other way to find a record.
        """
        case = self.serving('two-windows')

        async def scenario():
            first = await self.submit(case, **self.statement_at(
                case, ends_at=TERMINAL + dt.timedelta(minutes=7)))
            second = await self.submit(case, **self.statement_at(
                case, ends_at=TERMINAL + dt.timedelta(minutes=9)))
            wanted = sorted([first.payload['verification_id'], second.payload['verification_id']])
            listed = await self.get(case, GET_RECORDS)
            self.assertEqual(listed.payload, {'verification_ids': wanted})
            self.assertEqual(listed.payload['verification_ids'], sorted(listed.payload['verification_ids']))
            for verification_id in wanted:
                one = await self.get(case, GET_RECORD, verification_id)
                self.assertEqual(one.status, 200)
                self.assertEqual(one.payload['verification_id'], verification_id)
            self.assertEqual(set(self.listed(case, HUMAN)), set(wanted))

        self.run_async(scenario())
        self.assertEqual(len(self.operations(case['store'], records_module.AUDIT_OPERATION)), 2)


class AuthorityTests(VerificationAPIFixture):
    """Who is answered, in what order, and what no answer on this surface may cost or write.

    The precedence the contract fixes is `summary` first, then the current policy's own reader and writer
    gates, then the parser, then the one-slot admission, and only then the database. Each rung is tested by
    giving the rung below it a reason to answer differently: an unreadable body under a summary credential
    stays `summary_only`, a closed admission under an unreadable body stays a 400, and every one of them
    is answered by a handler that never once got the chance to read a body.
    """

    UNUSABLE = (b'{"a": ', b'[1,2]', b'', b'{"execution_id": "unused"}')

    def test_the_summary_role_is_answered_before_a_body_is_ever_asked_for(self):
        """Four routes, one credential, and a `receive()` that fails the test if it is awaited.

        The bytes offered are unusable JSON of every kind, because the whole claim is that no branch here
        parses anything to decide what a `summary` caller hears: the same exact body every time, and not
        one database connection.
        """
        case = self.serving('summary')

        async def scenario():
            for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                for sample, raw in enumerate(self.UNUSABLE):
                    with self.subTest(route=route, body=sample):
                        reply = await drive(case['app'], 'GET', route,
                                            query_string=query(route, case_key(case, route)), body=raw,
                                            identity=SUMMARY.identity, forbid_body=True,
                                            label=f'GET {route}')
                        self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
                        self.assertEqual(reply.reads, 0, 'the summary gate awaited a body chunk')
            for sample, raw in enumerate(self.UNUSABLE):
                with self.subTest(post=sample):
                    reply = await self.post(case, identity=SUMMARY.identity, body=raw, forbid_body=True)
                    self.assertEqual((reply.status, reply.payload), (403, {'error': 'summary_only'}))
                    self.assertEqual(reply.reads, 0, 'a summary write read the body it was refused for')
            await self.assert_dispatch_idle(case)

        self.run_async(scenario())
        self.assert_store_refusal_free(case)

    def test_a_refusal_costs_no_connection_and_an_admitted_read_costs_one(self):
        """The counting is the proof: a refused role, query or method never opens the file it names.

        The control sits inside the same patch, so a zero means the counter works and not that the read
        path was never entered: one admitted `GET /v1/verification/record` has to move it.
        """
        case = self.serving('noio')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())

        async def scenario():
            with counted_connections() as opened:
                for identity in (UNLISTED.identity, SUMMARY.identity):
                    for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                        with self.subTest(denied=identity, route=route):
                            reply = await self.get(case, route, identity=identity)
                            self.assertIn(reply.status, (403, 404), reply.text)
                for broken in (b'', b'action_id=', b'nope=1', b'action_id=' + b'x' * 400):
                    with self.subTest(query=broken[:40]):
                        reply = await drive(case['app'], 'GET', GET_BINDING, query_string=broken,
                                            identity=READER.identity)
                        self.assertEqual(reply.status, 400, reply.text)
                for method in ('PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
                    for route in (GET_BINDING, GET_RECORDS, GET_RECORD, POST_RECORDS):
                        with self.subTest(method=method, route=route):
                            reply = await drive(case['app'], method, route,
                                                query_string=b'' if route == POST_RECORDS
                                                else query(route, case_key(case, route)),
                                                identity=VERIFIER.identity, forbid_body=True,
                                                label=f'{method} {route}')
                            self.assertEqual(reply.status, 405, f'{method} {route}: {reply.text}')
                            self.assert_fixed(reply, 'method_not_allowed', label=f'{method} {route}')
                            self.assertEqual(reply.reads, 0, f'{method} {route} read a body')
                self.assertEqual(len(opened), 0,
                                 'a role, a query or a method refused here still opened the file')
                control = await self.get(case, GET_RECORD)
                self.assertEqual(control.status, 200, 'the control read stopped working')
                self.assertGreater(len(opened), 0, 'the control read opened no connection either')

        self.run_async(scenario())

    def test_the_read_roles_are_the_existing_ones_and_a_producer_needs_todays_allowlist(self):
        """Reader, human, proposer, executor and an allowlisted producer; nobody else, ever.

        These routes mint no new role: `verification_records._reader` is the only vocabulary, so the
        credential that can read platform state can read this state, and a producer the policy has never
        heard of hears `not_authorised` rather than learning whether the row exists.
        """
        case = self.serving('roles')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())

        async def scenario():
            for identity in (READER.identity, HUMAN.identity, AGENT.identity, RUNNER.identity,
                             VERIFIER.identity, SECOND_VERIFIER.identity):
                for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                    with self.subTest(reads=identity, route=route):
                        self.assertEqual((await self.get(case, route, identity=identity)).status, 200)
            for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                reply = await self.get(case, route, identity=UNLISTED.identity)
                with self.subTest(refused=UNLISTED.identity, route=route):
                    self.assertEqual(reply.status, 403, reply.text)
                    self.assert_fixed(reply, 'not_authorised',
                                      sentinels=(case['action_id'], case['execution_id'],
                                                 case['verification_id'], SENTINEL),
                                      label='an unlisted producer')

        self.run_async(scenario())
        self.assert_store_refusal_free(case)

    def test_admission_to_these_reads_widens_no_other_get_route(self):
        """A verifier is an allowlisted producer, not a reader of everything else the platform knows.

        The identity and the state must stay out of every one of these answers: this credential is in no
        read gate of the pre-existing routes, and a regression that let the producer admission leak into
        the whole GET branch would start answering `/v1/me`, `/v1/status` and the record tables to a
        detection worker.
        """
        case = self.serving('narrow')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        elsewhere = ('/v1/me', '/v1/status', '/v1/runtime', '/v1/audit', '/v1/records/audit',
                     '/v1/records/actions', '/v1/notifications/safety', '/v1/inventory', '/v1/overview')

        async def scenario():
            for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                admitted = await self.get(case, route, identity=VERIFIER.identity)
                self.assertEqual(admitted.status, 200,
                                 f'this producer is allowlisted for {route}: {admitted.text}')
            for path in elsewhere:
                with self.subTest(path=path):
                    reply = await drive(case['app'], 'GET', path, identity=VERIFIER.identity,
                                        label=f'GET {path}')
                    self.assertNotEqual(reply.status, 200,
                                        f'a verifier was answered {path} with {reply.text[:200]}')
                    self.assertNotIn(VERIFIER.identity, reply.text, f'{path} echoed the identity')
                    for field in ('rows', 'incidents', 'actions', 'identity', 'verification_ids',
                                  'payload', 'samples', 'binding_id'):
                        self.assertNotIn(field, reply.text, f'{path} carried a {field} field')
                    self.assertNotIn(case['verification_id'], reply.text, 'a record id rode along')

        self.run_async(scenario())

    def test_the_records_allowlist_still_stops_at_the_verification_tables(self):
        """No bulk read of this provenance was added on the way, through the old endpoint or a new one.

        `/v1/records/<table>` is the existing capped reader and its table list is a literal; these two
        tables stay out of it, so the three identifier-addressed reads are the whole public door. The
        sibling `/v1/records/audit` is the control that the endpoint itself still answers.
        """
        case = self.serving('allowlist')

        async def scenario():
            for table in ('verification_records', 'verification_bindings'):
                with self.subTest(table=table):
                    reply = await drive(case['app'], 'GET', '/v1/records/' + table,
                                        identity=HUMAN.identity, label='GET records')
                    self.assertNotEqual(reply.status, 200, f'{table} became a listable table')
                    self.assertNotIn('rows', reply.text)
            control = await drive(case['app'], 'GET', '/v1/records/audit', identity=HUMAN.identity,
                                  label='GET audit records')
            self.assertEqual((control.status, sorted(control.payload)), (200, ['rows']))

        self.run_async(scenario())

    def test_the_refusal_routes_and_their_audit_stay_the_lifecycles_and_not_these(self):
        """`REFUSAL_POST_ROUTES` gained no fifth entry, and nothing on this surface wrote one of its rows.

        A summary denial on the four lifecycle writes is the transport's one audited refusal; a summary
        denial on a verification write is not an action attempt. Both are asserted together, because the
        interesting failure is not the extra row but the missing one: if these routes had been quietly
        added to the audited table, the lifecycle denial below would still have its row and nobody would
        notice that the two vocabularies had merged.
        """
        case = self.serving('audit-boundary')

        async def scenario():
            for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                await self.get(case, route, identity=SUMMARY.identity)
            await self.post(case, identity=SUMMARY.identity)
            await self.submit(case, identity=UNLISTED.identity, **self.statement_at(case))
            await self.post(case, body=b'{"nope": 1}')
            await self.submit(case, **self.statement(case, window='window', outcome='unavailable',
                                                    receipt=None, samples=[]))
            await drive(case['app'], 'PUT', POST_RECORDS, identity=VERIFIER.identity, forbid_body=True)
            await self.assert_dispatch_idle(case)
            audited = await drive(case['app'], 'POST', '/v1/actions/claim', identity=SUMMARY.identity,
                                  body=b'{"action_id": "x"}', label='POST claim')
            self.assertEqual((audited.status, audited.payload), (403, {'error': 'summary_only'}))

        self.run_async(scenario())
        self.assertNotIn(POST_RECORDS, api_module.REFUSAL_POST_ROUTES)
        self.assertEqual(sorted(api_module.REFUSAL_POST_ROUTES),
                         ['/v1/actions', '/v1/actions/claim', '/v1/actions/decision',
                          '/v1/executions/outcome'])
        self.assertEqual(self.operations(case['store'], records_module.AUDIT_OPERATION), [],
                         'a refused verification write left a row of its own')
        rows = self.operations(case['store'], refusals.OPERATION)
        self.assertEqual([row['actor'] for row in rows], [SUMMARY.identity],
                         'these routes wrote refusal rows of their own')
        self.assertEqual([row['subject'] for row in rows], [refusals.UNBOUND])
        counters = case['store'].refusal_audit_status()
        self.assertEqual((counters['written'], counters['dropped'], counters['failed']), (1, 0, 0),
                         'the refusal budget moved for something other than the audited lifecycle route')


class QueryTests(VerificationAPIFixture):
    """The GET parser: one named parameter, exactly once, bounded, ASCII, and validated in that order.

    Every refusal here is asserted three ways — the status, a body that names no part of what was sent,
    and a connection count that never moved — because each half catches a different shortcut: a parser
    that normalises the value before checking its shape, a lookup that answers 404 for a malformed
    identifier (which is a way of asking the database about a value nobody validated), and a handler that
    trims or replaces undecodable bytes until something fits.
    """

    def setUp(self):
        super().setUp()
        self.case = self.serving('query')

        async def accepted():
            answer = await self.submit(self.case, **self.statement_at(self.case))
            self.case['verification_id'] = answer.payload['verification_id']

        self.run_async(accepted())

    def bad_queries(self, route: str) -> list:
        """Every query string that is not exactly one bounded canonical identifier for this one route.

        Each case is built from the route's *own* valid identifier, so the only thing wrong with it is
        query shape, parameter name, byte length, encoding or identifier syntax. Action and execution
        identifiers share UUID syntax: a different valid UUID is a lookup, not a parser refusal.
        """
        name, good = PARAMETERS[route], case_key(self.case, route)
        foreign = [PARAMETERS[other] for other in OWNED if other != route]
        over_bound = (f'{name}={good}' + '&pad=' + 'p' * 250).encode()
        self.assertGreater(len(over_bound), MAX_QUERY_BYTES,
                           'the fixture that attacks the query bound does not actually exceed it')
        shape = [
            ('no query at all', b''),
            ('blank value', (name + '=').encode()),
            ('value of spaces', (name + '=   ').encode()),
            ('bare key with no separator', name.encode()),
            ('empty name', ('=' + good).encode()),
            ('duplicate, identical', f'{name}={good}&{name}={good}'.encode()),
            ('duplicate, second one blank', f'{name}={good}&{name}='.encode()),
            ('extra parameter beside it', f'{name}={good}&role=reader'.encode()),
            ('another parameter only', b'reader=1'),
            ('semicolon separated pair', f'{name}={good};{name}={good}'.encode()),
            ('bracketed name', f'{name}[]={good}'.encode()),
            ('leading space in the name', (' ' + name + '=' + good).encode()),
            ('space inside the value', (name + '= ' + good).encode()),
            ('plus decodes to a space', (name + '=+' + good).encode()),
            ('percent-encoded space', (name + '=%20' + good).encode()),
            ('percent-encoded nul', (name + '=' + good + '%00').encode()),
            ('invalid percent escape', (name + '=%zz' + good).encode()),
            ('percent-decoded non-utf8', (name + '=%ff%fe%fd').encode()),
            ('raw non-utf8 bytes', (name + '=').encode() + b'\xff\xfe\xfd'),
            ('raw control bytes after the value', (name + '=' + good).encode() + b'\x00\x01'),
            ('one byte over the bound', over_bound),
            ('far over the bound', (name + '=' + 'p' * 5_000).encode()),
            ('enormous value', (name + '=' + 'p' * 70_000).encode()),
        ]
        for other in foreign:
            shape.append(('another route\'s parameter', (other + '=' + good).encode()))
        broken = ['', ' ', good.upper(), good[:-1], good + 'x', good + ' ', 'null', 'true', str(1)]
        if route == GET_RECORD:
            broken += ['f' * 63, 'f' * 65, 'g' * 64, '0' * 63, '0' * 65, PIN.upper(),
                       case_key(self.case, GET_BINDING), case_key(self.case, GET_RECORDS)]
        else:
            broken += [good.replace('-', ''), '{' + good + '}', 'urn:uuid:' + good, 'f' * 64, PIN,
                       good[:-1].replace('-', '') + '0', '0' * 36]
        for sample in broken:
            shape.append((f'identifier {sample!r}', (name + '=' + sample).encode()))
        return shape

    def test_every_query_that_is_not_the_one_form_is_refused_before_any_lookup(self):
        """400 `invalid_request`, one fixed sentence, no echo, no connection — for every spelling.

        The identifiers of the live scenario are the sentinels: a refusal that quoted them back would
        tell a probing caller that a value at least reached a validator that understands that shape, and
        an undecodable query that got replaced rather than refused shows up here as a 200 or a 404.
        """
        async def scenario():
            with counted_connections() as opened:
                for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                    for label, raw in self.bad_queries(route):
                        with self.subTest(route=route, case=label):
                            reply = await drive(self.case['app'], 'GET', route, query_string=raw,
                                                identity=READER.identity, label=f'GET {route}')
                            self.assertEqual(reply.status, 400,
                                             f'{route}?{raw[:70]!r} ({label}) -> {reply.status}')
                            self.assert_fixed(reply, 'invalid_request',
                                              sentinels=(case_key(self.case, GET_BINDING),
                                                         case_key(self.case, GET_RECORDS),
                                                         case_key(self.case, GET_RECORD), SENTINEL),
                                              label=f'{route} {label}')
                self.assertEqual(len(opened), 0, 'a malformed query reached the database')

        self.run_async(scenario())
        self.assert_store_refusal_free(self.case)

    def test_the_one_form_is_accepted_and_a_valid_identifier_naming_nothing_is_a_four_zero_four(self):
        """The control beside the sweep, and the line between 400 and 404.

        One says "this build has no such action, execution or id" and the other says "you sent me
        something I could not read". The 404s are asserted to have cost a read, which is exactly what the
        refusals above were asserted not to: an identifier is validated first and only then looked up.
        """
        async def scenario():
            for route in (GET_BINDING, GET_RECORDS, GET_RECORD):
                with self.subTest(route=route):
                    good = await self.get(self.case, route)
                    self.assertEqual(good.status, 200, good.text)
            with counted_connections() as opened:
                missing_action = await self.get(self.case, GET_BINDING, str(uuid.uuid4()))
                missing_execution = await self.get(self.case, GET_RECORDS, str(uuid.uuid4()))
                missing_record = await self.get(self.case, GET_RECORD, 'a' * 64)
            for reply, label in ((missing_action, 'action'), (missing_execution, 'execution'),
                                 (missing_record, 'record')):
                with self.subTest(absent=label):
                    self.assertEqual(reply.status, 404, reply.text)
                    self.assert_fixed(reply, 'not_found', sentinels=(str(self.case['store'].path),),
                                      label=label)
            self.assertGreaterEqual(len(opened), 3, 'a validated lookup was answered without a read')

        self.run_async(scenario())
        self.assertEqual(self.operations(self.case['store'], refusals.OPERATION), [])

    def test_an_action_that_was_never_captured_is_an_explicit_answer_and_not_a_four_zero_four(self):
        """`not-captured` is a fact about verification, so it travels as a 200 document.

        A real action this build never bound reads back as the explicit non-binding it is: no id, no
        origin, and the captured reason. A 404 there would say "no such action", and a caller would go
        looking for the action it is already holding. The write side is the mirror: the same action, with
        a binding the store never captured, is refused rather than judged against an invented scope.
        """
        quiet = self.bound('never-captured', policy=None)
        self.executed(quiet)
        app = self.app(quiet['store'])

        async def scenario():
            binding = await self.get(quiet, GET_BINDING, app=app)
            self.assertEqual(binding.status, 200, binding.text)
            self.assertEqual(binding.payload, {'action_id': quiet['action_id'], 'status': 'unbound',
                                              'reason': 'not-captured', 'binding_id': None,
                                              'origin': None})
            listed = await self.get(quiet, GET_RECORDS, app=app)
            self.assertEqual((listed.status, listed.payload), (200, {'verification_ids': []}))
            refused = await self.post(quiet, app=app, body=self.body(quiet, binding_id=OTHER_PIN))
            self.assertEqual(refused.status, 503, refused.text)
            self.assert_fixed(refused, 'verification_unavailable', label='this store has no policy')

        self.run_async(scenario())
        # A policy mounted *after* the fact must not reach backwards: the action still has no captured
        # meaning, so the write is refused on the binding rather than judged against a scope invented
        # from today's mapping.
        later = self.open('never-captured', policy=self.policy())
        app2 = self.app(later)
        self.assertEqual(later.get_verification_binding(quiet['action_id'], READER)['reason'],
                         'not-captured', 'the reopen backfilled a binding')

        async def mounted():
            refused = await self.post(quiet, app=app2, body=self.body(quiet, binding_id=OTHER_PIN))
            self.assertEqual(refused.status, 400, refused.text)
            self.assert_fixed(refused, 'invalid_request', sentinels=(OTHER_PIN,),
                              label='an uncaptured action has no scope to be judged against')
            missing = await self.get(quiet, GET_RECORD, 'a' * 64, app=app2)
            self.assertEqual(missing.status, 404)

        self.run_async(mounted())
        self.assertEqual(self.operations(quiet['store'], records_module.AUDIT_OPERATION), [])
        self.assertEqual(later.list_verifications(quiet['execution_id'], HUMAN), [],
                         'a refused write reached the record')

    def test_a_post_that_carries_a_query_string_is_refused_and_writes_nothing(self):
        """There is no query on the write route, and no quiet acceptance of one that was sent anyway.

        The same bytes with no query string are accepted, which is what makes the refusal about the query
        rather than about the statement in the body.
        """
        case = self.serving('post-query')
        body = self.body(case)

        async def scenario():
            stray = await drive(case['app'], 'POST', POST_RECORDS,
                               query_string=query(GET_BINDING, case['action_id']), body=body,
                               identity=VERIFIER.identity, label='POST with a query')
            self.assertEqual(stray.status, 400, stray.text)
            self.assert_fixed(stray, 'invalid_request', sentinels=(case['action_id'],),
                              label='POST carrying a query string')
            accepted = await drive(case['app'], 'POST', POST_RECORDS, body=body,
                                   identity=VERIFIER.identity, label='POST without a query')
            self.assertEqual(accepted.status, 200, accepted.text)
            case['verification_id'] = accepted.payload['verification_id']

        self.run_async(scenario())
        self.assertEqual(self.listed(case, HUMAN), [case['verification_id']],
                         'the refused POST wrote a record as well as the accepted one')


class BodyTests(VerificationAPIFixture):
    """The write body: six fields, strict UTF-8 JSON, bounded, and never re-interpreted.

    The record vocabulary is frozen at the storage layer, and the transport is supposed to reuse it
    rather than invent a second one — so the cases here are the ones a client writes by accident: a
    key stated twice, a number JSON cannot express, a document that grew past its bound while it was
    still arriving, an encoding that is legal somewhere else, and an envelope around the record. Every
    refusal is checked for the two things that make it safe rather than merely rejected: nothing was
    written, and nothing was echoed.
    """

    def tampered(self, document: dict, needle: str, replacement: str) -> bytes:
        """One textual defect in an otherwise valid body, with the fixture asserting it is the only one."""
        text = json.dumps(document)
        self.assertEqual(text.count(needle), 1,
                         f'the fixture does not isolate {needle!r}: it appears {text.count(needle)} times')
        return text.replace(needle, replacement).encode()

    def assert_rejected(self, case, raw: bytes, code: str, *, label: str, identity=VERIFIER.identity,
                        sentinels=()) -> Exchange:
        """One POST body, one expected refusal, and a store that never heard about it.

        The id list and the audit rows are snapshotted first, so "nothing was written" is a comparison
        and not a hope that this scenario happened to start empty.
        """
        listed, audit = self.listed(case, HUMAN), self.operations(case['store'],
                                                                  records_module.AUDIT_OPERATION)
        reply = self.run_async(self.post(case, body=raw, identity=identity))
        self.assertEqual(reply.status, 400, f'{label}: got {reply.status} {reply.text[:200]}')
        self.assert_fixed(reply, code, sentinels=sentinels, label=label)
        self.assertEqual(self.listed(case, HUMAN), listed, f'{label}: a refused body wrote a record')
        self.assertEqual(self.operations(case['store'], records_module.AUDIT_OPERATION), audit,
                         f'{label}: a refused body wrote an audit row')
        return reply

    def test_the_body_is_the_record_itself_and_the_six_fields_are_all_required(self):
        """No envelope, no verdict, no seventh field, no missing one — and one accepted shape to prove it.

        `{'record': {...}}` is the shape a reviewer would accept without noticing if the transport
        unwrapped anything: the accepted control is the same statement bare, and it is the only way a
        caller gets a `verification_id` back.
        """
        case = self.serving('shape')
        good = self.statement_at(case)
        accepted = self.run_async(self.post(case, body=json.dumps(good).encode()))
        self.assertEqual((accepted.status, sorted(accepted.payload)), (200, ['created', 'verification_id']))
        case['verification_id'] = accepted.payload['verification_id']
        kept = self.stored(case)

        broken = [
            ('an envelope around the record', json.dumps({'record': good})),
            ('a result wrapper beside it', json.dumps({**good, 'result': {'verdict': 'cleared'}})),
            ('a caller-supplied verdict', json.dumps({**good, 'verdict': 'cleared'})),
            ('a caller-supplied reason', json.dumps({**good, 'reason': 'comparison-satisfied'})),
            ('a caller-supplied identity', json.dumps({**good, 'recorded_by': VERIFIER.identity})),
            ('a caller-supplied clock', json.dumps({**good, 'now': utc_text(RECORD_NOW)})),
            ('a JSON array', json.dumps([good])),
            ('a bare string', json.dumps('record')),
            ('a bare number', json.dumps(1)),
            ('the literal null', 'null'),
            ('nothing at all', ''),
            ('a truncated object', '{"execution_id": "x"'),
        ]
        for field in ('execution_id', 'binding_id', 'window', 'outcome', 'receipt', 'samples'):
            broken.append((f'missing {field}', json.dumps({key: value for key, value in good.items()
                                                           if key != field})))
        for label, text in broken:
            with self.subTest(case=label):
                reply = self.run_async(self.post(case, body=text.encode()))
                self.assertIn(reply.status, (400, 413), f'{label} -> {reply.status} {reply.text[:200]}')
                self.assertEqual(reply.status, 400, f'{label} was not a client error: {reply.text[:200]}')
                self.assert_fixed(reply, 'invalid_request',
                                  sentinels=(case['execution_id'], case['binding_id'], SENTINEL),
                                  label=label)
        self.assertEqual(self.listed(case, HUMAN), [case['verification_id']],
                         'a refused body changed what the store holds')
        self.assertEqual(self.stored(case), kept, 'the accepted record moved')

    def test_a_key_stated_twice_is_refused_at_every_depth_and_the_last_spelling_never_wins(self):
        """Duplicate keys are a refusal, not a precedence — including the ones a parser resolves quietly.

        The pairs that matter are the ones where keeping the last spelling would still produce a valid
        statement: the same key and value twice at the top level, two row-count claims in one receipt,
        and one window that states its start twice. A permissive decoder accepts all three and files a
        verdict, so each case is built so that the *only* defect is the repeated key and the answer must
        be 400 rather than the 200 a lenient `json.loads` gives back.
        """
        case = self.serving('duplicates')
        good = self.statement_at(case)
        plain = self.statement_at(case, outcome='unavailable', values=())
        plain_text = json.dumps(plain)
        start = plain['window']['start']
        needle = '"start": "' + start + '"'
        self.assertEqual(plain_text.count(needle), 1, 'the fixture keeps a window that states a start twice')
        cases = [
            ('the same key and the same value twice',
             self.tampered(good, '"outcome": "available"',
                           '"outcome": "available", "outcome": "available"')),
            ('a receipt that claims two row counts',
             self.tampered(good, '"sample_count": 1', '"sample_count": 1, "sample_count": 2')),
            ('a window that states its start twice',
             plain_text.replace(needle, needle + ', ' + needle).encode()),
            ('a record key spelled twice in one object',
             self.tampered(good, '"binding_id"', '"binding_id": "' + good['binding_id'] + '", "binding_id"')),
        ]
        for label, raw in cases:
            with self.subTest(case=label):
                self.assert_rejected(case, raw, 'invalid_request', label=label,
                                     sentinels=(case['execution_id'],))
        self.assertEqual(self.listed(case, HUMAN), [], 'a duplicate-key body wrote a record')

    def test_a_number_json_cannot_express_is_refused_wherever_a_number_belongs(self):
        """`NaN`, `Infinity`, `-Infinity`, an overflowed float and a 500-digit integer are all 400.

        These are the inputs that turn a refusal into a 500 in a careless transport: a non-finite float
        reaches a digest, a canonicaliser or a SQL bind and fails there, with a message about the
        server. Nothing is written and nothing is echoed, and the accepted control is the same statement
        carrying `70.0`.
        """
        case = self.serving('numbers')
        good = self.statement_at(case)
        for label, needle in (('NaN', '"value": NaN'), ('Infinity', '"value": Infinity'),
                              ('-Infinity', '"value": -Infinity'), ('1e400', '"value": 1e400'),
                              ('a 500-digit integer', '"value": ' + '1' + '0' * 500),
                              ('a nonfinite row count', '"sample_count": NaN'),
                              ('a quoted number', '"value": "70.0"')):
            with self.subTest(case=label):
                raw = self.tampered(good, '"value": 70.0', needle)
                self.assert_rejected(case, raw, 'invalid_request', label=label,
                                     sentinels=(case['execution_id'], 'Infinity'))
        control = self.run_async(self.post(case, body=json.dumps(good).encode()))
        case['verification_id'] = control.payload['verification_id']
        self.assertEqual((control.status, control.payload['created']), (200, True))

    def test_a_runaway_nesting_depth_is_a_client_error_and_never_a_recursion_crash(self):
        """200 levels of arrays where twenty rows belong: refused, not a traceback.

        The storage layer refuses unbounded depth on purpose, and the transport has to carry that as a
        400 rather than as the `RecursionError` a serializer or a walker would raise. A 500 here is an
        unclassified crash about a caller's own document, which is the exact inversion of the edge's
        error taxonomy. The wrong-shape cases beside it (`samples` as an object, as a number, a `window`
        as a list) are the same claim one level shallower.
        """
        case = self.serving('depth')
        empty = json.dumps(self.statement_at(case, outcome='unavailable', values=()))
        self.assertEqual(empty.count('"samples": []'), 1, 'the fixture cannot address the samples field')
        for label, wrong in [('twenty levels', '[' * 20 + ']' * 20),
                             ('two hundred levels', '[' * 200 + ']' * 200),
                             ('samples as an object', '{"a": 1}'),
                             ('samples as a number', '7'),
                             ('samples as a string', '"rows"')]:
            raw = empty.replace('"samples": []', '"samples": ' + wrong)
            self.assertNotEqual(raw, empty)
            with self.subTest(case=label):
                self.assert_rejected(case, raw.encode(), 'invalid_request', label=label)
        windowed = json.dumps(self.statement_at(case, outcome='unavailable', values=()))
        broken_window = windowed.replace('"window": {', '"window": [')
        self.assertNotEqual(broken_window, windowed)
        self.assert_rejected(case, broken_window.encode(), 'invalid_request', label='window as a list')

    def test_the_body_bound_is_32768_raw_bytes_and_bites_while_the_body_is_still_arriving(self):
        """The bound is on the bytes, it is tighter than the transport\'s own, and it is not a buffer.

        Three claims, one test: 32768 bytes of an otherwise valid statement is accepted and 32769 is not
        (so the bound is the raw body and not the canonical record); a 40000-byte body is refused by this
        route rather than by `api.py`'s older 65536 gate; and a body arriving in twelve 4000-byte pieces
        is refused after roughly eight of them, which is what "checked before concatenation" means when
        the evidence is the number of `receive()` calls the handler made.
        """
        case = self.serving('size')
        good = json.dumps(self.statement_at(case)).encode()
        self.assertLess(len(good), MAX_BODY_BYTES, 'the fixture is too large to be a boundary test')
        at_bound = good + b' ' * (MAX_BODY_BYTES - len(good))
        self.assertEqual(len(at_bound), MAX_BODY_BYTES)
        accepted = self.run_async(self.post(case, body=at_bound))
        self.assertEqual((accepted.status, accepted.payload['created']), (200, True),
                         f'a body of exactly the bound must be accepted: {accepted.text[:200]}')
        case['verification_id'] = accepted.payload['verification_id']
        over = good + b' ' * (MAX_BODY_BYTES - len(good) + 1)
        self.assertEqual(len(over), MAX_BODY_BYTES + 1)
        too_big = self.run_async(self.post(case, body=over))
        self.assertEqual(too_big.status, 413, too_big.text[:200])
        self.assertEqual(too_big.payload, {'error': 'body_too_large'})
        far = self.run_async(self.post(case, body=good + b' ' * 40_000))
        self.assertEqual(far.status, 413, far.text[:200])
        pieces = [good[:200]] + [b' ' * 4_000] * 12
        streamed = self.run_async(self.post(case, chunks=pieces))
        self.assertEqual(streamed.status, 413, streamed.text[:200])
        self.assertLess(streamed.reads, len(pieces),
                        'the handler buffered the whole body before noticing its size')
        self.assertEqual(self.listed(case, HUMAN), [case['verification_id']],
                         'an oversized body wrote a record')

    def test_utf16_and_utf32_are_refused_by_decoding_utf8_before_parsing(self):
        """The same legal document, in three encodings this platform does not speak.

        A transport that let `bytes.decode()` decide would read a UTF-16 body as latin-1-ish noise and
        answer 400 for the wrong reason, or — worse, if it fell back to `errors='replace'` — might make
        something parseable out of it. The claim is narrow and checkable: it is a `400 invalid_request`,
        never an acceptance, and never a 500 out of a codec.
        """
        case = self.serving('encodings')
        good = self.statement_at(case)
        for label, raw in (('utf-16', json.dumps(good).encode('utf-16')),
                           ('utf-16-le', json.dumps(good).encode('utf-16-le')),
                           ('utf-32', json.dumps(good).encode('utf-32')),
                           ('utf-8 with a byte mark', b'\xef\xbb\xbf' + json.dumps(good).encode()),
                           ('latin-1 noise', json.dumps(good).encode() + b'\xa9\xae\xfd'),
                           ('empty utf-16', b'\xff\xfe')):
            with self.subTest(encoding=label):
                self.assert_rejected(case, raw, 'invalid_request', label=label,
                                     sentinels=(case['execution_id'],))

    def test_a_reordered_or_respaced_body_is_the_same_statement_and_a_replay_of_it(self):
        """Identity is over normalised values, so retrying does not depend on how the bytes were typed.

        Key order and whitespace are not part of a statement; re-spelling a window's offset or its
        numeric form is not either. This is the difference between an idempotent retry and a store that
        grows a second verdict for one check because a client upgraded its JSON encoder.
        """
        case = self.serving('reordering')
        good = self.statement_at(case)
        first = self.run_async(self.post(case, body=json.dumps(good).encode()))
        case['verification_id'] = first.payload['verification_id']
        reordered = json.dumps({key: good[key] for key in reversed(list(good))},
                              indent=2, separators=(',', ':')).encode()
        again = self.run_async(self.post(case, body=reordered))
        self.assertEqual((again.status, again.payload),
                         (200, {**first.payload, 'created': False}), 'a reordered retry became a new fact')
        shifted = json.loads(json.dumps(good))
        eastern = dt.timezone(dt.timedelta(minutes=120))
        shifted['window'] = {'start': timestamp(shifted['window']['start']).astimezone(eastern).isoformat(),
                            'end': timestamp(shifted['window']['end']).astimezone(eastern).isoformat()}
        third = self.run_async(self.post(case, body=json.dumps(shifted).encode()))
        self.assertEqual(third.payload, {**first.payload, 'created': False}, third.text[:200])
        self.assertEqual(len(self.operations(case['store'], records_module.AUDIT_OPERATION)), 1,
                         'a retry wrote a second audit row')

    def test_a_disconnected_body_writes_nothing_and_answers_nothing(self):
        """No response and no row: the caller went away, and neither the transport nor the store speaks.

        Asserted twice from the two sides of the seam — `handle` returns `None` (the answer `api.py`
        needs in order to return without responding), and the app itself puts nothing on the wire. A
        handler that answered 400 to a client that had already gone would be writing an error the
        platform never produced, and one that wrote first would be filing an observation nobody asked for.
        """
        case = self.serving('disconnect')
        api = case['app'].verification_api

        async def scenario():
            reply = await self.post(case, disconnect=True)
            self.assertEqual(reply.messages, (), f'a disconnected POST was answered: {reply.text[:200]}')
            self.assertIsNone(reply.status)
            result, seen = await drive_handle(api, 'POST', POST_RECORDS, actor=VERIFIER,
                                             body=self.body(case), disconnect=True)
            self.assertIsNone(result, 'handle answered a disconnected body instead of abstaining')
            self.assertEqual(seen.messages, ())

        self.run_async(scenario())
        self.assertEqual(self.listed(case, HUMAN), [])
        self.assertEqual(self.operations(case['store'], records_module.AUDIT_OPERATION), [])
        self.assert_store_refusal_free(case)


class StatusTaxonomyTests(VerificationAPIFixture):
    """Which failure answers with which status, and what every 500 is forbidden to say.

    The codes come from the exact constants `verification_records` raises, not from `api.stable_code`
    substring matching: a sentence that means "retry changed contents" must be a 409 and a sentence that
    means "the stored execution is unreadable" must be a 500, and both are `StateError`, which is why an
    implementation that reused the transport's old classifier gets one of these pairs wrong while still
    answering something plausible. Corruption is planted in the file itself — the tables' own triggers
    refuse UPDATE and DELETE, so every mutation below is an INSERT of a row the writer would never have
    written, or a UPDATE of an `executions` row, which carries no trigger.
    """

    def mutate(self, store: Store, statement: str, params: tuple = ()) -> None:
        """Apply one raw statement to the file as an outside writer would, and commit it."""
        connection = sqlite3.connect(store.path, timeout=SAFETY_TIMEOUT)
        try:
            connection.execute(statement, params)
            connection.commit()
        finally:
            connection.close()

    def corrupt_record_row(self, case, verification_id: str, payload: str) -> str:
        """Insert a record row whose payload is not the document its id promises, and return that id."""
        self.mutate(case['store'], 'INSERT INTO verification_records VALUES (?,?,?,?,?,?,?,?)',
                    (verification_id, case['execution_id'], 'f' * 64, payload, 'cleared',
                     'fixture-corruption', VERIFIER.identity, utc_text(RECORD_NOW)))
        return verification_id

    def test_an_unreadable_stored_record_is_one_fixed_body_and_nothing_else(self):
        """A row the reader cannot parse is a storage failure, and the answer says no more than that.

        `read_record` re-parses stored text on every call, so a payload that is not JSON raises the
        decoder it had been hiding — and `JSONDecodeError` is a `ValueError`, the same base class as
        every `StateError` this module raises for *client* faults. An implementation that catches the
        base class and calls it a bad request would answer 400 here, and one that lets it through would
        answer the transport's generic 500 with the exception class name beside it. Both are refused.
        """
        case = self.serving('corrupt-payload')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        broken = self.corrupt_record_row(case, 'c' * 64, '{not a document')
        reply = self.run_async(self.get(case, GET_RECORD, broken))
        self.assert_storage_error(reply, sentinels=(str(case['store'].path), broken),
                                 label='a stored payload that is not JSON')
        self.assertEqual(self.get_status(case, GET_RECORD, case['verification_id']), 200,
                         'one unreadable row made every other record unreadable')

    def get_status(self, case, route: str = GET_RECORD, value=None, identity: str = READER.identity) -> int:
        """One read of one route, for the assertions that only care that the rest still answers."""
        return self.run_async(self.get(case, route, value, identity=identity)).status

    def test_a_stored_id_the_writer_could_not_have_written_is_a_storage_error_not_a_short_list(self):
        """Discovery names ids or refuses; it never repairs one, trims one or returns a partial answer.

        The planted defect is an id that is not sixty-four lowercase hex bytes. The table refuses UPDATE
        and DELETE by trigger, so the only honest way to reach this state is to insert a row the writer
        could never have written — which is also what a restored-from-a-partial-backup file looks like.
        An answer of "every id except that one", or of that id with a character taken off it, would name
        documents that do not exist, so the whole read refuses.
        """
        case = self.serving('corrupt-ids')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        listed = self.run_async(self.get(case, GET_RECORDS))
        self.assertEqual(listed.payload, {'verification_ids': [case['verification_id']]},
                         'the control list stopped answering before anything was corrupted')
        self.corrupt_record_row(case, 'A' * 64, '{}')
        reply = self.run_async(self.get(case, GET_RECORDS))
        self.assert_storage_error(reply, sentinels=(str(case['store'].path), 'AAAAAAAA'),
                                 label='a stored id that is not a lowercase digest')
        self.assertEqual(self.get_status(case, GET_RECORD), 200,
                         'an id the reader cannot vouch for leaked onto the single-document read')

    def test_more_rows_than_the_writer_may_have_written_refuse_rather_than_truncate(self):
        """The discovery read's own cap is the writer's, and history past it means the file disagrees.

        Sixty-five rows for one execution is not a list to be trimmed to sixty-four: the sixty-fifth id
        would be missing from the answer with nothing saying it was. The row that pushed it over is a
        well-formed digest, so this refusal is the cap and nothing else — and the individual records keep
        reading, because a bounded list is not a reason to lose a document.
        """
        case = self.serving('over-cap')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        for record_number in range(1, records_module.RECORDS_PER_EXECUTION + 2):
            self.mutate(case['store'], 'INSERT INTO verification_records VALUES (?,?,?,?,?,?,?,?)',
                        ('%064x' % record_number, case['execution_id'], 'f', '{}', 'cleared', 'fixture-over-cap',
                         VERIFIER.identity, utc_text(RECORD_NOW)))
        crowded = self.run_async(self.get(case, GET_RECORDS))
        self.assert_storage_error(crowded, sentinels=(str(case['store'].path),),
                                 label='more stored rows than the writer may have written')
        self.assertEqual(self.get_status(case, GET_RECORD), 200,
                         'an over-cap history made the individual records unreadable too')

    def test_a_stored_binding_that_cannot_be_read_is_a_storage_error_on_the_binding_route(self):
        """A `bound` row whose origin is not a document is not an unbound action and not an empty one.

        The binding table refuses UPDATE, so the row is inserted by hand for a real action this build
        never captured: `status='bound'`, a digest, and an origin that is not JSON. The read has to say
        the file is unreadable rather than answer `unbound` (which would say "nothing was captured" about
        a capture that happened) or 404 (which would say "no such action" about an action that exists).
        """
        quiet = self.bound('corrupt-binding', policy=None)
        self.executed(quiet)
        app = self.app(quiet['store'])
        self.mutate(quiet['store'], 'INSERT INTO verification_bindings VALUES (?,?,?,?,?,?)',
                    (quiet['action_id'], 'bound', 'matched', 'b' * 64, 'nope-not-json',
                     utc_text(PROPOSE_NOW)))
        reply = self.run_async(self.get(quiet, GET_BINDING, app=app))
        self.assert_storage_error(reply, sentinels=(str(quiet['store'].path),),
                                 label='a stored binding whose origin is not a document')
        self.assertEqual(self.run_async(self.get(quiet, GET_RECORDS, app=app)).status, 200,
                         'the unreadable binding spilled onto a route that does not read it')

    def test_a_stored_execution_the_writer_cannot_describe_is_a_storage_error_on_the_write(self):
        """An execution whose status or stamp is not something this build wrote is nobody's client error.

        The contract names this failure outright (`BAD_STORED_EXECUTION` is one of the constants that
        must land on the fixed storage body), and it is the one failure a submission cannot be blamed
        for: the statement is well-formed and authorised, and what is wrong is the state behind it. Two
        spellings — a status word from no vocabulary, and a terminal stamp that is not an instant — land
        on the same fixed 500, write nothing, and say nothing about the row they found. The list read is
        the control beside it: it only asks whether the execution exists, so an unreadable *status* is
        not its business and its answer does not change.
        """
        for label, statement in (('an unknown status', "UPDATE executions SET status='aborted'"),
                                 ('an unreadable stamp', "UPDATE executions SET updated_at='yesterday'")):
            case = self.serving('corrupt-execution-' + label.replace(' ', '-'))
            self.mutate(case['store'], statement)
            reply = self.run_async(self.submit(case, **self.statement_at(case)))
            with self.subTest(case=label):
                self.assert_storage_error(reply, sentinels=(case['execution_id'], 'aborted', 'yesterday'),
                                         label=f'{label} is not the caller\'s fault')
                connection = sqlite3.connect(case['store'].path, timeout=SAFETY_TIMEOUT)
                try:
                    self.assertEqual(connection.execute(
                        'SELECT count(*) FROM verification_records').fetchone()[0], 0,
                        'a corrupt execution row was written past')
                finally:
                    connection.close()
                self.assertEqual(self.operations(case['store'],
                                                 records_module.AUDIT_OPERATION), [])
            self.assertEqual(self.get_status(case, GET_RECORDS), 200,
                             'the read surface agrees with the write about the same row')

    def test_a_schema_that_lost_its_tables_answers_on_every_route_and_breaks_no_other_route(self):
        """`NEEDS_MIGRATION` is a storage failure, four times over, and the platform keeps answering.

        The old routes are the control: a verification read that cannot find its tables must not become a
        reason `/v1/status` stops working, and the five verification answers must not differ from each
        other, which is what makes "verify the schema and restore" the one thing an operator has to do.
        """
        case = self.serving('lost-tables')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        self.mutate(case['store'], 'DROP TABLE verification_records')

        async def scenario():
            routes = ((GET_BINDING, query(GET_BINDING, case['action_id'])),
                      (GET_RECORDS, query(GET_RECORDS, case['execution_id'])),
                      (GET_RECORD, query(GET_RECORD, case['verification_id'])))
            for path, raw in routes:
                with self.subTest(route=path):
                    self.assert_storage_error(await drive(case['app'], 'GET', path, query_string=raw,
                                                        identity=READER.identity, label=f'GET {path}'),
                                             sentinels=(str(case['store'].path),),
                                             label='a missing verification table')
            self.assert_storage_error(await self.post(case), label='a missing verification table')
            status = await drive(case['app'], 'GET', '/v1/status', identity=READER.identity)
            self.assertEqual(status.status, 200, 'the old surface stopped answering over a missing table')
            runtime = await self.runtime(case)
            self.assertIn('refusal_audit_dispatch', runtime)

        self.run_async(scenario())
        self.assertFalse(any(name.startswith('verification_records')
                            for name in self.table_names(case['store'])))

    def table_names(self, store: Store) -> list:
        connection = sqlite3.connect(store.path, timeout=SAFETY_TIMEOUT)
        try:
            return [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")]
        finally:
            connection.close()

    def test_an_injected_driver_failure_is_a_storage_error_that_names_no_path(self):
        """A locked, missing or broken database is one fixed body, and the log stays as bounded.

        The failure is planted at the documented seam (`Store`'s own method) with a message carrying a
        private path and a plausible driver sentence, because the claim is about what the transport does
        with an exception it does not own: it may not put that text in a body, and per the logging
        contract it may not put it in a WARNING-level record either.
        """
        case = self.serving('driver-failure')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        detail = f'database is locked, path /var/lib/{SENTINEL}/state.db'
        for method in ('get_verification', 'list_verifications', 'get_verification_binding',
                       'put_verification'):
            real = getattr(Store, method)

            def exploding(store, *args, _real=real, **kwargs):
                raise sqlite3.OperationalError(detail)

            logs = offloop.LogCollector()
            with mock.patch.object(Store, method, new=exploding), logs.captured():
                if method == 'put_verification':
                    reply = self.run_async(self.post(case))
                else:
                    route = {'get_verification': GET_RECORD, 'list_verifications': GET_RECORDS,
                             'get_verification_binding': GET_BINDING}[method]
                    reply = self.run_async(self.get(case, route))
            with self.subTest(method=method):
                self.assert_storage_error(reply, sentinels=(detail, str(case['store'].path)),
                                         label=f'{method} raised a driver failure')
                for record in logs.product:
                    if record.levelno < logging.WARNING:
                        continue
                    self.assertNotIn(SENTINEL, record.getMessage(),
                                     f'{method}: a log line carried the driver text')

    def test_an_unexpected_bug_stays_a_server_error_and_never_becomes_a_client_error(self):
        """A fault nobody chose must not be answered as though the caller caused it.

        The contract allows an unexpected exception to reach `api.py`'s existing 500 handling and forbids
        converting every exception into a client error, so what is pinned is the half both readings agree
        on: a `RuntimeError` out of the store is a 500, its class is all the body may say, and its
        message (which carries planted text) reaches neither the response nor a WARNING-level log line.
        """
        case = self.serving('unexpected-bug')

        async def first_round():
            answer = await self.submit(case, **self.statement_at(case))
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(first_round())
        def exploding(store, *args, **kwargs):
            raise RuntimeError(f'injected fault carrying {SENTINEL} and a path /etc/passwd')

        with mock.patch.object(Store, 'get_verification', new=exploding):
            reply = self.run_async(self.get(case, GET_RECORD))
        self.assertEqual(reply.status, 500, f'a bug was answered as {reply.status}: {reply.text[:200]}')
        self.assertIn(reply.payload.get('error'), ('verification_storage_error', 'internal_error'),
                      reply.text[:200])
        self.assertLessEqual(set(reply.payload), {'error', 'detail'}, reply.text[:200])
        self.assertNotIn(SENTINEL, reply.text, 'the exception message reached the response')
        self.assertNotIn('/etc/passwd', reply.text, 'a path from the exception reached the response')


class OffLoopTests(VerificationAPIFixture):
    """The one-slot, off-the-loop rule, observed from outside the service.

    Everything here runs against a real app, a real `Store` and a real executor thread, with one
    injected gate: the first call to one `Store` method blocks on a `threading.Event` this file holds and
    nothing else releases it. That makes "a synchronous verification callable is in flight" a property of
    the fixture rather than a race, so every claim below is an ordering or a count — the loop answered
    while the callable ran, exactly one callable ran, the slot was still full after the request that
    owned it was cancelled, and the owner lock went back only after the thread had finished.

    No test here sleeps to make a guarantee, and none of them can hang: the gate is released in a
    `finally`, `offloop.wait_until` fails loudly when a fact never appears, and the parked wait itself is
    bounded, so an implementation that ran the work inline loses a test with a sentence instead of
    taking the suite down with it.
    """

    def life(self, app, journal: offloop.Journal) -> offloop.Lifespan:
        """Start the ASGI lifespan under test, with the owner lock wrapped so its release is visible."""
        spy = offloop.OwnershipSpy(journal)
        installed = spy.install()
        installed.start()
        self.addCleanup(installed.stop)
        driver = offloop.Lifespan(app, journal)

        def finish():
            # Cleanup only: the scenario already awaited the task it cared about, and a failure on the
            # way out must not replace the assertion that is already travelling.
            with contextlib.suppress(Exception):
                self.run_async(driver.close())

        self.addCleanup(finish)
        return driver

    def parked(self, method: str = 'put_verification') -> StoreSeam:
        return self.seam(method, StoreSeam.PARK)

    def test_a_parked_verification_call_leaves_the_serving_loop_answering(self):
        """The reproduced failure, aimed at the new routes: a parked write must not hold the loop.

        The probe is a memory-only `GET /v1/runtime`, and the window it is given is the one the asynchronous audit
        writer
        measured against — strictly shorter than the two seconds the reproduced failure waited for a lock
        held in another thread. If this callable ran inline the probe could not answer at all, and the
        two facts that make it off the loop rather than merely concurrent are read off the call itself:
        the thread that ran it is not this one, and it owns no event loop.
        """
        case = self.serving('parked')
        seam = self.parked()

        async def scenario():
            task = asyncio.ensure_future(offloop.bounded(self.submit(case, **self.statement_at(case)),
                                                        SAFETY_TIMEOUT, what='a parked submit to answer'))
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the verification call to start')
                runtime = await offloop.bounded(self.runtime(case), MEMORY_READ_WINDOW,
                                                what='a memory-only read while a write was parked')
                self.assertIn('refusal_audit_dispatch', runtime)
                self.assertTrue(seam.running, 'the read landed only after the parked call had finished')
                call = seam.last()
                self.assertFalse(call.on_main_thread,
                                 f'the store call ran on the loop thread ({call.thread_name})')
                self.assertIsNone(call.running_loop,
                                  f'the store call ran on a thread owning a loop ({call.thread_name})')
                self.assertEqual(call.method, 'put_verification')
            finally:
                seam.release.set()
            answer = await task
            self.assertEqual(answer.status, 200, answer.text)
            case['verification_id'] = answer.payload['verification_id']

        self.run_async(scenario())
        self.assertEqual(seam.starved, [], 'the parked call was never released')
        self.assertEqual(len(self.listed(case, HUMAN)), 1, 'the released call wrote nothing')

    def test_one_callable_at_a_time_and_every_other_request_is_shed_with_one_fixed_body(self):
        """Capacity is one, there is no queue, and a shed submission reaches neither store nor slot.

        The second request is a well-formed submission that would be accepted a moment later — the
        `503 verification_busy` it gets is the whole answer, with a body that says nothing else, no call
        made, no record written, and the slot still occupied by the first. Replaying it after that call
        has really finished is a 200, which is what makes the shed a refusal rather than a loss.
        """
        case = self.serving('shed')
        seam = self.parked()
        first = self.statement_at(case, ends_at=TERMINAL + dt.timedelta(minutes=6))
        second = self.statement_at(case, ends_at=TERMINAL + dt.timedelta(minutes=8))

        async def scenario():
            task = asyncio.ensure_future(offloop.bounded(self.submit(case, **first), SAFETY_TIMEOUT,
                                                        what='the admitted submit to answer'))
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the first call to start')
                busy = await offloop.bounded(self.submit(case, **second), SAFETY_TIMEOUT,
                                            what='the shed submit to answer')
                self.assertEqual((busy.status, busy.payload), (503, {'error': 'verification_busy'}))
                self.assertEqual(seam.count, 1, 'a second synchronous call was started beside the first')
                self.assertEqual(self.listed(case, HUMAN), [], 'the shed submission wrote anyway')
                await offloop.stays_false(lambda: seam.count > 1, window=IMMEDIATE_WINDOW,
                                         what='a second store call while the first held the slot')
                self.assertEqual(seam.max_active, 1, 'two callables were inside the store at once')
            finally:
                seam.release.set()
            admitted = await task
            self.assertEqual(admitted.status, 200, admitted.text)
            retry = await offloop.bounded(self.submit(case, **second), SAFETY_TIMEOUT,
                                         what='the retry of the shed submit')
            self.assertEqual((retry.status, retry.payload['created']), (200, True),
                             'the slot never came back once the callable had finished')

        self.run_async(scenario())
        self.assertEqual(len(self.listed(case, HUMAN)), 2)

    def test_the_slot_belongs_to_one_app_and_not_to_the_process(self):
        """Two apps over one store have two slots, so a busy instance cannot starve its sibling.

        This is the same scoping the asynchronous audit writer gave the refusal dispatcher (`scope: 'app-local'`), and
        it is
        what a module-level executor or a class-level lock would break: the second app's read is admitted
        and answered while the first app's write is still parked.
        """
        case = self.serving('two-apps')
        other = self.app(case['store'])
        seam = self.parked()

        async def scenario():
            task = asyncio.ensure_future(offloop.bounded(self.submit(
                case, **self.statement_at(case, ends_at=TERMINAL + dt.timedelta(minutes=6))),
                SAFETY_TIMEOUT, what='the parked submit to answer'))
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the first app call to start')
                sibling = await offloop.bounded(
                    self.submit(case, app=other,
                                **self.statement_at(case, ends_at=TERMINAL + dt.timedelta(minutes=8))),
                    SAFETY_TIMEOUT, what='the second app to answer while the first was parked')
                self.assertEqual((sibling.status, sibling.payload['created']), (200, True),
                                 f'the second app was shed by its sibling: {sibling.text[:200]}')
                self.assertEqual(seam.count, 2)
                self.assertTrue(seam.running, 'the first app\'s call finished early')
                self.assertIsNot(other.verification_api, case['app'].verification_api,
                                 'both apps share one verification instance')
            finally:
                seam.release.set()
            self.assertEqual((await task).status, 200)

        self.run_async(scenario())
        self.assertEqual(seam.max_active, 2, 'one app blocked another from reaching the store')
        self.assertEqual(len(self.listed(case, HUMAN)), 2)

    def test_eight_concurrent_submissions_admit_exactly_one_callable(self):
        """No window between the availability check and the claim, under a real race.

        Eight well-formed submissions, launched together, over one app: exactly one reaches the store and
        the other seven are told `verification_busy` while the first is still inside its own gate. An
        admission that awaits between looking and claiming lets a second call through here, and a queue
        would make all eight eventually run — both read as a count this test does not accept.
        """
        case = self.serving('race')
        seam = self.parked()
        statements = [self.statement_at(case, ends_at=TERMINAL + dt.timedelta(minutes=6 + 2 * index))
                      for index in range(8)]

        async def scenario():
            tasks = [asyncio.ensure_future(offloop.bounded(self.submit(case, **document), SAFETY_TIMEOUT,
                                                          what='a racing submit to answer'))
                     for document in statements]
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the first racing call to start')
                await offloop.stays_false(lambda: seam.count > 1, window=IMMEDIATE_WINDOW,
                                         what='a second call admitted during the race')
                settled = [task for task in tasks if task.done()]
                self.assertEqual(len(settled), len(tasks) - 1,
                                 'more than one request waited for the slot instead of being shed')
                for task in settled:
                    self.assertEqual(task.result().payload, {'error': 'verification_busy'},
                                     'a racing request was not shed with the fixed body')
                    self.assertEqual(task.result().status, 503)
                self.assertEqual(sum(1 for task in tasks if not task.done()), 1,
                                 'the admitted request had already been answered')
            finally:
                seam.release.set()
            answers = await asyncio.gather(*tasks)
            self.assertEqual(sorted(answer.status for answer in answers), [200] + [503] * 7)

        self.run_async(scenario())
        self.assertEqual(seam.max_active, 1, 'two callables ran inside the store at once')
        self.assertEqual(len(self.listed(case, HUMAN)), 1, 'the shed submissions wrote records')

    def test_cancelling_the_request_frees_nothing_and_abandons_no_work(self):
        """Cancellation is a fact about the caller, and never evidence about a thread.

        The request that owns the only slot is cancelled while its callable is parked. Three things then
        have to be simultaneously true: the callable is still running, the next request is still shed, and
        the write still lands. A cancellation that unwound the executor item, or that handed the slot back
        because a future said `cancelled`, would free the slot here and answer 200 to the second caller
        while the first call was still inside SQLite — which is the one thing this rule exists to refuse.
        """
        case = self.serving('cancelled')
        seam = self.parked()

        async def scenario():
            task = asyncio.ensure_future(offloop.bounded(self.submit(case, **self.statement_at(case)),
                                                        SAFETY_TIMEOUT, what='the submit to answer'))
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the call to start')
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                self.assertTrue(seam.running, 'cancelling the request stopped the store call')
                self.assertEqual(self.listed(case, HUMAN), [], 'the cancelled call wrote its record already')
                busy = await offloop.bounded(self.submit(case, **self.statement_at(
                    case, ends_at=TERMINAL + dt.timedelta(minutes=8))), SAFETY_TIMEOUT,
                    what='the request that arrived after the cancellation')
                self.assertEqual((busy.status, busy.payload), (503, {'error': 'verification_busy'}),
                                 'cancelling a request freed the slot it owned')
                self.assertEqual(seam.count, 1)
            finally:
                seam.release.set()
            await offloop.wait_until(lambda: seam.quiet, what='the abandoned call to finish')

        self.run_async(scenario())
        self.assertEqual(len(self.listed(case, HUMAN)), 1,
                         'a cancelled response silently discarded the write it owned')
        self.assertEqual(len(self.operations(case['store'], records_module.AUDIT_OPERATION)), 1)

    def test_wait_idle_waits_for_the_real_end_and_survives_being_cancelled(self):
        """The drain reports the callable, not the future that scheduled it.

        `wait_idle` may not come back while the store call is inside its gate, and it may not swallow the
        cancellation a server delivered while it waited: the waiter stays put until the work has really
        ended and then raises what it was asked to. Both halves are observed against the parked gate, so
        neither is a timing guess.
        """
        case = self.serving('drain')
        api = case['app'].verification_api
        seam = self.parked()

        async def scenario():
            task = asyncio.ensure_future(offloop.bounded(self.submit(case, **self.statement_at(case)),
                                                        SAFETY_TIMEOUT, what='the submit to answer'))
            waiter = asyncio.ensure_future(api.wait_idle())
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the call to start')
                await offloop.stays_false(lambda: waiter.done(), window=IMMEDIATE_WINDOW,
                                         what='wait_idle while the store call was still parked')
                waiter.cancel()
                await offloop.stays_false(lambda: waiter.done(), window=IMMEDIATE_WINDOW,
                                          what='a cancelled wait_idle to keep waiting for the callable')
                self.assertTrue(seam.running, 'the cancelled drain released the slot early')
            finally:
                seam.release.set()
            with contextlib.suppress(asyncio.CancelledError):
                await waiter
            self.assertTrue(waiter.cancelled(),
                            'a drain that was cancelled came back as though it had finished cleanly')
            self.assertEqual((await task).status, 200)

        self.run_async(scenario())

    def test_shutdown_closes_admission_and_holds_the_owner_lock_until_the_thread_finishes(self):
        """The lifespan may not hand the state file to the next owner around a live verification write.

        One journal records three events from three different places — the callable finishing, the
        exclusive owner lock going back, and `shutdown.complete` — and the claim is their order. While the
        write is parked the lock is still held and no completion is claimed; a request that arrives after
        shutdown began is refused the busy answer without starting a second call; and the record is
        really in the file before the answer that says the process is done.
        """
        case = self.serving('shutdown')
        journal = self.journal
        app = case['app']
        seam = self.parked()

        async def scenario():
            driver = self.life(app, journal)
            await driver.start()
            task = asyncio.ensure_future(offloop.bounded(self.submit(case, **self.statement_at(case)),
                                                        SAFETY_TIMEOUT, what='the submit to answer'))
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the verification call to start')
                driver.begin_shutdown()
                await offloop.stays_false(
                    lambda: journal.seen('owner:exit') or journal.seen('lifespan.shutdown.complete'),
                    window=IMMEDIATE_WINDOW,
                    what='the owner lock or a completion claim while a write was parked')
                late = await offloop.bounded(self.get(case, GET_RECORDS), SAFETY_TIMEOUT,
                                            what='a request that arrived during the drain')
                self.assertEqual((late.status, late.payload), (503, {'error': 'verification_busy'}))
                self.assertEqual(seam.count, 1, 'shutdown started a second synchronous call')
            finally:
                seam.release.set()
            self.assertEqual((await task).status, 200)
            await driver.finish_shutdown()
            self.assertTrue(journal.ordered(f'store:{seam.method}:finish', 'owner:exit',
                                            'lifespan.shutdown.complete'),
                            f'the shutdown order was wrong: {journal.snapshot()}')
            self.assertEqual(journal.count('lifespan.shutdown.complete'), 1)
            await driver.close()

        self.run_async(scenario())
        self.assertEqual(len(self.listed(case, HUMAN)), 1, 'the drained write never landed')
        self.assertEqual(spy_releases(journal), 1, 'the owner lock went back more than once')

    def test_a_drain_cancelled_again_and_again_still_holds_the_owner_lock(self):
        """A server that gives up on the lifespan may stop waiting; it may not stop the waiting.

        The drain is cancelled four times while the write is parked, and each time the answer must be the
        same: the lock is still held, no `shutdown.complete` is on offer, and the callable is still
        running. Only when this file releases the gate does the lock go back — and a drain that was cut
        short still does not claim to have completed.
        """
        case = self.serving('cancelled-shutdown')
        journal = self.journal
        app = case['app']
        seam = self.parked()

        async def scenario():
            driver = self.life(app, journal)
            await driver.start()
            task = asyncio.ensure_future(offloop.bounded(self.submit(case, **self.statement_at(case)),
                                                        SAFETY_TIMEOUT, what='the submit to answer'))
            try:
                await offloop.wait_until(lambda: seam.count >= 1, what='the verification call to start')
                driver.begin_shutdown()
                for attempt in range(4):
                    with self.subTest(cancelled=attempt):
                        driver.cancel()
                        await asyncio.sleep(0.02)
                        self.assertFalse(journal.seen('owner:exit'),
                                         'the owner lock was released while a write was parked')
                        self.assertFalse(journal.seen('lifespan.shutdown.complete'),
                                         'a cut-short drain claimed completion')
                        self.assertTrue(seam.running, 'a cancellation stopped the store call')
                        self.assertEqual(seam.count, 1)
            finally:
                seam.release.set()
            self.assertEqual((await task).status, 200)
            await offloop.wait_until(lambda: journal.seen('owner:exit'),
                                     what='the owner lock to come back after the write finished')
            self.assertTrue(journal.ordered(f'store:{seam.method}:finish', 'owner:exit'),
                            f'the lock went back before the write ended: {journal.snapshot()}')
            self.assertFalse(journal.seen('lifespan.shutdown.complete'),
                             'a drain that was cancelled reported a completed shutdown')
            await driver.settle()
            await driver.close()

        self.run_async(scenario())
        self.assertEqual(len(self.listed(case, HUMAN)), 1)


def spy_releases(journal: offloop.Journal) -> int:
    """How many times the exclusive owner lock was handed back."""
    return journal.count('owner:exit')


ACTION_DEFINITIONS = {'inspect': {'version': '1', 'parameters': {
    'type': 'object', 'properties': {}, 'additionalProperties': False}}}


def policy_document(resource_id: str, verifiers=()) -> dict:
    """One mountable policy file: the reviewed meaning of this checkout's own detector revision."""
    mapping = {'source': 'threshold-detector', 'rule_id': 'inspect.cpu', 'rule_version': '3',
               'condition': 'inspect.cpu', 'resource_id': resource_id, 'query_type': 'metric-threshold',
               'parameters': {'resource_id': resource_id, 'rule_id': 'inspect.cpu',
                              'artifact_sha256': PIN}, 'metric_name': 'lo_cpu', 'threshold': 90.0,
               'comparison': 'lt', 'window_seconds': 300, 'artifact_sha256': PIN}
    return {'schema_version': 1,
            'verifiers': [actor.identity for actor in
                          (verifiers or (VERIFIER, SECOND_VERIFIER))], 'mappings': [mapping]}


class CredentialValidationTests(unittest.TestCase):
    """`validate_credentials` is the app's own rules, extracted and not widened, on both entry points.

    The wave moves the existing token-uniqueness, token-length and role checks out of `create_app`'s body
    so the service factory can run the same ones before it opens anything. That is a refactor with one
    real risk: the two copies drifting apart, or the extraction quietly *loosening* a rule. So the
    vocabulary is pinned as it was — the same refusals, the same exception, no credential value in any
    message — and both entry points are shown to call the one function rather than keeping their own.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'state.db')
        startup = mock.patch('local_observe.platform.runtime.observe_startup',
                            new=lambda mode, configured: {'stubbed_startup_snapshot': mode})
        startup.start()
        self.addCleanup(startup.stop)

    def refused(self) -> list:
        good = CREDENTIALS[0]
        return [('no credentials at all', []),
                ('two credentials sharing one token', [dict(good), dict(good)]),
                ('a token shorter than the floor', [{**good, 'token': 'x' * 23}]),
                ('a role this transport does not speak', [{**good, 'role': 'verifier'}]),
                ('a role named by nothing', [{**good, 'role': ''}])]

    def test_the_function_is_the_rules_and_refuses_the_same_rows_the_app_did(self):
        self.assertTrue(callable(getattr(api_module, 'validate_credentials', None)),
                        'api.validate_credentials is the shared seam this wave promised')
        rows = [dict(row) for row in CREDENTIALS]
        pristine = json.dumps(rows)
        self.assertIsNone(api_module.validate_credentials(rows))
        self.assertEqual(json.dumps(rows), pristine, 'credential validation rewrote the rows it was given')
        for label, broken in self.refused():
            with self.subTest(case=label):
                with self.assertRaises(ValueError) as caught:
                    api_module.validate_credentials(broken)
                sentence = str(caught.exception)
                self.assertNotIn('\n', sentence)
                for row in broken:
                    if isinstance(row, dict) and len(str(row.get('token', ''))) > 8:
                        self.assertNotIn(str(row['token']), sentence, 'a refusal named a token value')
                with self.assertRaises(ValueError):
                    create_app(self.store, broken, lambda document: None)

    def test_create_app_delegates_instead_of_keeping_a_second_copy(self):
        """One call, one argument, and the app still builds when the rows are good."""
        seen = []
        real = api_module.validate_credentials

        def recorder(credentials):
            seen.append(credentials)
            return real(credentials)

        with mock.patch.object(api_module, 'validate_credentials', new=recorder):
            app = create_app(self.store, CREDENTIALS, lambda document: None)
        self.assertEqual(len(seen), 1, f'create_app called the shared validator {len(seen)} times')
        self.assertEqual(seen[0], CREDENTIALS, 'the rows validated are not the rows that were mounted')
        self.assertIsInstance(app.verification_api, VerificationAPI)


class ServiceWiringTests(unittest.TestCase):
    """Boot order, measured: credentials decided, policy read, and only then a database or a client.

    The factory reads the same policy file the loader was built for and hands the validated object to
    `Store` by keyword. What is asserted is the *order* — one journal of the three calls the boot makes —
    and the two refusals that must land before a file exists: bad credentials, and a policy whose
    verifier is not mounted as a producer. A boot that opened state on the way to noticing either would
    create or migrate a database for a service that was never allowed to start.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.declared = casebook.index_document()
        self.host = self.declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.state = self.root / 'state.db'

    def environment(self, *, credentials=None, document=None) -> dict:
        rows = CREDENTIALS if credentials is None else credentials
        (self.root / 'credentials.json').write_text(json.dumps(rows), 'utf-8')
        (self.root / 'actions.json').write_text(json.dumps(ACTION_DEFINITIONS), 'utf-8')
        environment = {'LO_PLATFORM_CREDENTIALS': str(self.root / 'credentials.json'),
                       'LO_ACTION_POLICY': str(self.root / 'actions.json'),
                       'LO_INDEX_PATH': str(self.index), 'LO_STATE_PATH': str(self.state),
                       'LO_NOTIFICATION_MODE': 'off'}
        if document is not None:
            (self.root / 'verification.json').write_text(json.dumps(document), 'utf-8')
            environment['LO_VERIFICATION_POLICY'] = str(self.root / 'verification.json')
        return environment

    def boot(self, environment: dict) -> tuple:
        """Run `app_factory` with the three things it may reach journaled, delegating to all of them."""
        order: list[str] = []
        built: list[tuple] = []
        real_store, real_validate = Store, api_module.validate_credentials
        real_loader = verification_policy.policy_from_environment

        def spy_store(*args, **kwargs):
            order.append('store')
            built.append((args, kwargs))
            return real_store(*args, **kwargs)

        def spy_validate(credentials):
            order.append('validate')
            return real_validate(credentials)

        def spy_loader(credentials, *, environ=None):
            order.append('policy')
            return real_loader(credentials, environ=environ)

        patches = [mock.patch.object(api_module, 'Store', new=spy_store),
                   mock.patch.object(api_module, 'validate_credentials', new=spy_validate),
                   mock.patch.object(verification_policy, 'policy_from_environment', new=spy_loader)]
        if hasattr(api_module, 'policy_from_environment'):
            patches.append(mock.patch.object(api_module, 'policy_from_environment', new=spy_loader))
        threads = set(threading.enumerate())
        with contextlib.ExitStack() as stack:
            for handle in patches:
                stack.enter_context(handle)
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            app = api_module.app_factory()
        return app, order, built, threads

    def test_the_policy_is_read_after_the_credentials_and_reaches_the_store_by_keyword(self):
        app, order, built, threads = self.boot(self.environment(document=policy_document(self.host)))
        self.assertEqual(order, ['validate', 'policy', 'store', 'validate'], f'the boot reached: {order}')
        (args, kwargs), = built
        self.assertEqual(args[0], str(self.state))
        policy = kwargs['verification_policy']
        self.assertIsInstance(policy, records_module.VerificationPolicy)
        self.assertEqual(policy.verifiers, (VERIFIER.identity, SECOND_VERIFIER.identity))
        self.assertFalse(kwargs.get('migrate', False), 'a service boot may not migrate state')
        self.assertIs(app.verification_api.__class__, VerificationAPI)
        self.assertEqual(set(threading.enumerate()), threads,
                         'a boot that served nothing started a thread')
        self.assertTrue(self.state.exists(), 'the accepted boot did not open the state file')

    def test_an_unmounted_policy_reaches_the_store_as_none_and_opens_no_file_itself(self):
        app, order, built, threads = self.boot(self.environment())
        self.assertEqual(order, ['validate', 'policy', 'store', 'validate'])
        (_, kwargs), = built
        self.assertIsNone(kwargs['verification_policy'], 'unset must mean off, not a default policy')
        self.assertIsInstance(app.verification_api, VerificationAPI)

    def test_bad_credentials_refuse_before_the_policy_the_state_file_and_any_thread(self):
        rows = [dict(row) for row in CREDENTIALS]
        rows[1] = {**rows[1], 'token': rows[0]['token']}
        order = self.refused_boot(self.environment(credentials=rows), ValueError)
        self.assertEqual(order, ['validate'], f'a refused boot reached {order}')

    def test_a_verifier_that_is_not_mounted_as_a_producer_refuses_before_the_state_file(self):
        document = policy_document(self.host, verifiers=(HUMAN,))
        order = self.refused_boot(self.environment(document=document),
                                 verification_policy.PolicyLoadError)
        self.assertEqual(order, ['validate', 'policy'], f'a refused boot reached {order}')

    def test_the_retired_credentials_environment_refuses_before_anything_else(self):
        environment = self.environment(document=policy_document(self.host))
        environment['LO_PLATFORM_CREDENTIALS_JSON'] = '[]'
        order = self.refused_boot(environment, ValueError)
        self.assertEqual(order, [], 'the retired environment value reached a later stage')

    def refused_boot(self, environment: dict, expected: type) -> list:
        """Run a boot expected to refuse, and return what it reached before it did."""
        before = set(threading.enumerate())
        with self.assertRaises(expected) as caught:
            self.boot(environment)
        sentence = str(caught.exception)
        for row in CREDENTIALS:
            self.assertNotIn(row['token'], sentence, 'a boot refusal named a credential value')
        self.assertFalse(self.state.exists(),
                         'a refused boot created the state database it was never allowed to open')
        self.assertFalse(Path(str(self.state) + '-wal').exists(), 'a refused boot left a sidecar behind')
        self.assertEqual(set(threading.enumerate()), before, 'a refused boot started a thread')
        return self.boot_order(environment)

    def boot_order(self, environment: dict) -> list:
        """The same boot, journaled again, with the refusal allowed to escape: only the order matters."""
        order: list[str] = []
        real_validate = api_module.validate_credentials
        real_loader = verification_policy.policy_from_environment

        def spy_validate(credentials):
            order.append('validate')
            return real_validate(credentials)

        def spy_loader(credentials, *, environ=None):
            order.append('policy')
            return real_loader(credentials, environ=environ)

        def spy_store(*args, **kwargs):
            order.append('store')
            raise AssertionError('the state file was opened by a boot that should have refused')

        patches = [mock.patch.object(api_module, 'Store', new=spy_store),
                   mock.patch.object(api_module, 'validate_credentials', new=spy_validate),
                   mock.patch.object(verification_policy, 'policy_from_environment', new=spy_loader)]
        if hasattr(api_module, 'policy_from_environment'):
            patches.append(mock.patch.object(api_module, 'policy_from_environment', new=spy_loader))
        with contextlib.ExitStack() as stack:
            for handle in patches:
                stack.enter_context(handle)
            stack.enter_context(mock.patch.dict(os.environ, environment, clear=True))
            with contextlib.suppress(Exception):
                api_module.app_factory()
        return order

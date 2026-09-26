"""The verification workflow's HTTP seam: `platform/verification_api.py` — the paths it owns, and what each answer costs.

`VerificationAPI(store)` is not mounted by `create_app` yet (that integration is main's), so every test
here drives the seam through the three arguments an ASGI caller will pass: a `scope` dict, a `receive` this
file controls, and an `Actor`. The bearer never reaches this module, so no credential table appears anywhere
in this file. Nothing is stubbed: the store is a real `Store` over a temporary file, the action is proposed
through the real action policy over a real inventory index, the binding is the one the proposal captured,
the execution is a real claim and a real outcome, and the receipts come from `store.client.build_outcome`,
the function both backends call. `ObservingStore` subclasses the real `Store` and delegates every call — it
replaces no behaviour, it only reports which thread ran one and when it left.

What is pinned, and why each is worth a test:

* **Ownership is three literals.** `owns` is yes to exactly `/v1/verification/binding`,
  `/v1/verification/records`, `/v1/verification/record`, and `handle` returns `None` for anything else, so
  the main API keeps its own 404s and no path is adopted under the prefix by association.
* **Authority and parsing precede every byte of I/O.** A `summary` credential and any role the storage
  layer will not admit are answered before `receive()` is spoken to (`Receive(forbid_body=True)` makes that
  a crash rather than a comment), and a query that is not exactly one named, decodable, in-range identifier
  never reaches `Store` — proven against a store whose verification methods are tripwires.
* **Statuses are mapped on exact constants.** `403 not_authorised` and `503 verification_unavailable` are
  two sentences of the *same* module; substring classification would flatten them. Bodies are asserted
  equal, field for field, against the imported constants they are named after, and `RECORD_LIMIT` is shown
  to be a 409 on a submission and a 500 on a discovery read.
* **A 500 says nothing.** Dropped verification tables and a stored document that is not JSON both answer the
  one fixed body, and a captured log handler proves no driver text, no path and no planted sentinel reaches
  a body or a log line.
* **One callable at a time, and the slot belongs to the thread.** A real SQLite write lock held by this file
  parks a real `INSERT`; the next submission is `503 verification_busy` *after* its body was parsed, the
  loop is not held, and the callable provably ran on a thread that owns no event loop.
* **Cancellation abandons an answer, never a write.** Cancelling the request that owns a parked write keeps
  the slot claimed, and once the lock is handed back the record is in the file and `wait_idle` is what says
  so. `wait_idle` itself, cancelled mid-write, unwinds only after the callable has really left `Store` —
  that wait is what stands between the write and the owner lock being released.
* **No thread until a request needs one, and none after `close()`.** Counted by thread name, so a leak is a
  number rather than a hope.

Two stated limits rather than gaps. Sixty-four accepted first writes to reach `RECORD_LIMIT` as a *409* is
storage's cost, pinned in `tests/test_verification_records.py`; the seam's half — that the same sentence is
a 500 on a read — is pinned here through an over-cap stored history. And every finite number below is a
failure deadline that raises or a named sample: nothing sleeps to make a guarantee, every hand-off is a
`threading.Event` or a real write lock this file owns, and the one elapsed-time assertion is deliberately
shorter than the SQLite busy timeout an inline write would have to wait out. The fixture instants are
derived from the real clock (an hour in the past) rather than fixed, because this seam cannot inject a
`now`: the server judges a submission at the instant it arrives, and a hard-coded date would eventually
make every accepted record a `window-in-the-future` refusal. No claim here that any of it passed.
"""
import asyncio
import contextlib
import dataclasses
import datetime as dt
import json
import logging
import sqlite3
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from typing import Any

from local_observe.inventory import index
from local_observe.inventory.validation import canonical, read_document, timestamp, utc_text
from local_observe.platform import detections, verification_api as module
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, Store
from local_observe.platform.verification_records import (BAD_ACTOR, BAD_BINDING, BAD_RECORD,
                                                        BAD_VERIFICATION_ID, EXECUTING_EXECUTION,
                                                        NO_POLICY, RECORD_LIMIT, RETRY_CHANGED,
                                                        VerificationPolicy)
from local_observe.store import client as facade
from local_observe.store.client import MetricSample, Window

ROOT = Path(__file__).resolve().parents[1]
#: One reviewed detector revision: the CPU series under one declared host, `cleared` at `lt 90`.
DETECTOR, RULE, RULE_VERSION, SERIES, PIN = ('threshold-detector', 'inspect.cpu', '3', 'lo_cpu',
                                           'a' * 64)
WINDOW_SECONDS = 300

VERIFIER = Actor('verify-worker', 'producer')
STRANGER = Actor('other-producer', 'producer')
READER = Actor('reader-1', 'reader')
HUMAN = Actor('operator', 'human')
AGENT = Actor('agent-1', 'proposer')
RUNNER = Actor('runner-1', 'executor')
SUMMARY = Actor('watcher', 'summary')

#: Every finite bound in this file is a failure deadline, never a way to let something finish.
SAFETY = 20.0
#: How often a cooperative poll looks. A sampling interval; nothing here is bounded by it.
POLL_SECONDS = 0.005
#: The window a shed answer is owed. `sqlite3`'s busy timeout is 10 s, so a seam that ran the `Store` call
#: inline could not answer inside this. A sample, and the thread identity asserted beside it is the
#: deterministic half of the same claim.
IMMEDIATE_WINDOW = 2.0
#: Rides inside a corrupt stored payload. It may reach no response body and no log record.
SENTINEL = 'never-in-a-body-a-path-or-a-log-line'

BINDING, RECORDS, RECORD = module.BINDING_ROUTE, module.RECORDS_ROUTE, module.RECORD_ROUTE

# The bodies this seam owes, spelled from the constants the contract names them by.
SUMMARY_ONLY = {'error': 'summary_only'}
NOT_FOUND = {'error': 'not_found'}
BUSY = {'error': 'verification_busy'}
STORAGE = {'error': 'verification_storage_error'}
METHOD_NOT_ALLOWED = {'error': 'method_not_allowed'}
TOO_LARGE = {'error': 'body_too_large'}
NOT_AUTHORISED = {'error': 'not_authorised', 'detail': BAD_ACTOR}
UNAVAILABLE = {'error': 'verification_unavailable', 'detail': NO_POLICY}


def policy_document(host: str) -> dict:
    """The reviewed policy this suite binds against: one mapping, one allowlisted verifier."""
    mapping = {'source': DETECTOR, 'rule_id': RULE, 'rule_version': RULE_VERSION, 'condition': RULE,
               'resource_id': host, 'query_type': 'metric-threshold',
               'parameters': {'resource_id': host, 'rule_id': RULE, 'artifact_sha256': PIN},
               'metric_name': SERIES, 'threshold': 90.0, 'comparison': 'lt',
               'window_seconds': WINDOW_SECONDS, 'artifact_sha256': PIN}
    return {'schema_version': 1, 'verifiers': [VERIFIER.identity], 'mappings': [mapping]}


def worker_threads() -> list[threading.Thread]:
    """The seam's own executor threads alive right now, counted rather than named.

    Every single-worker pool names its one thread the same way, so a *count* is the honest observation:
    one instance may own at most one, and a leak is a number that will not come back down.
    """
    return [thread for thread in threading.enumerate()
            if thread.name.startswith('verification') and thread is not threading.current_thread()]


def workers_started_since(snapshot: set) -> list[threading.Thread]:
    """The verification threads that did not exist at `snapshot` — this test's own workers, identified."""
    return [thread for thread in worker_threads() if thread not in snapshot]


async def until(predicate, *, what: str, timeout: float = SAFETY) -> None:
    """Poll `predicate()` until it is true, or fail with the sentence that says what was owed."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f'{what}: not observed within {timeout}s')
        await asyncio.sleep(POLL_SECONDS)


def scope_of(method: str, path: str, query: bytes = b'') -> dict:
    """The smallest `http` scope the seam reads: method, path and raw query bytes."""
    return {'type': 'http', 'method': method, 'path': path, 'query_string': query, 'headers': []}


def chunks(body: bytes, sizes: tuple[int | None, ...] | None = None, *,
           disconnect: bool = False) -> list:
    """One body as the chunks `receive` will hand back, optionally split and optionally left unfinished.

    A `None` entry in `sizes` means "the rest", which is how a test says "this chunk ends the stream"
    without counting bytes twice. `disconnect` replaces the final chunk with the message a caller that hung
    up produces.
    """
    if sizes is None:
        parts = [body]
    else:
        parts, offset = [], 0
        for size in sizes:
            parts.append(body[offset:] if size is None else body[offset:offset + size])
            offset += len(parts[-1])
        parts.append(b'')
    out = [{'type': 'http.request', 'body': part, 'more_body': index < len(parts) - 1}
           for index, part in enumerate(parts)]
    if disconnect:
        out[-1] = {'type': 'http.disconnect'}
    return out


class Receive:
    """A `receive()` that records how often it was spoken to, and may refuse to answer at all.

    `forbid_body` is the claim "this answer is reachable from the credential, the method, the path and the
    query alone": touching the body raises, and the `AssertionError` travels out of `handle` (which catches
    only its own refusal and the storage layer's `StateError`), so it cannot be absorbed into a status code.
    A chunk list is how a test says "the caller sent this in pieces"; an exhausted list answers
    `http.disconnect`, which is the honest end of a stream nobody is reading any more.
    """

    def __init__(self, messages: list | None = None, *, forbid_body: bool = False) -> None:
        self.messages = list(messages or [{'type': 'http.disconnect'}])
        self.forbid_body = forbid_body
        self.calls = 0

    async def __call__(self) -> dict:
        self.calls += 1
        if self.forbid_body:
            raise AssertionError('this answer must not await a body chunk')
        if not self.messages:
            return {'type': 'http.disconnect'}
        return self.messages.pop(0)


class Journal:
    """One lock-protected record of who did what first, across the loop thread and the callable's thread."""

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

    def only(self, *tags: str) -> list[str]:
        """The named tags in the order they happened, for an ordering claim that reads as one."""
        return [entry for entry in self.snapshot() if entry in tags]


class ObservingStore(Store):
    """The real store with an announcement: which thread ran one of the four seam callables, and when.

    Nothing is replaced — every method calls straight through. What it makes observable is what a claim
    about an off-loop callable needs: the moment the synchronous work really entered `Store` (a
    thread-owned `Event`, so "the write is parked" is a fixture fact and not a race) and the identity of the
    thread that was inside it (off the loop, or the seam is inline and this file says so). The journal
    entries order the callable against the lifecycle waits.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.journal = Journal()
        self.entered = threading.Event()
        self.exited = threading.Event()
        self.observations: list[tuple[str, str, bool, Any]] = []

    def observe(self, name: str) -> None:
        try:
            running: Any = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        thread = threading.current_thread()
        self.observations.append((name, thread.name, thread is threading.main_thread(), running))
        self.journal.note(f'store:start:{name}')

    def conclude(self, name: str) -> None:
        # Noted *before* the callable returns, so it necessarily precedes the future's completion: that is
        # what lets a test order `wait_idle` against the real end of the work.
        self.journal.note(f'store:exit:{name}')
        self.exited.set()

    @property
    def last(self) -> tuple[str, str, bool, Any]:
        return self.observations[-1]

    def get_verification_binding(self, action_id, actor):
        self.observe('binding')
        try:
            return super().get_verification_binding(action_id, actor)
        finally:
            self.conclude('binding')

    def list_verifications(self, execution_id, actor):
        self.observe('records')
        try:
            return super().list_verifications(execution_id, actor)
        finally:
            self.conclude('records')

    def get_verification(self, verification_id, actor):
        self.observe('record')
        try:
            return super().get_verification(verification_id, actor)
        finally:
            self.conclude('record')

    def put_verification(self, record, actor, **kwargs):
        # The claim is about *this* write, so its own end-signal starts cleared: an earlier call's `exit`
        # must never be read as proof that a parked one finished.
        self.exited.clear()
        self.observe('put')
        self.entered.set()
        try:
            return super().put_verification(record, actor, **kwargs)
        finally:
            self.conclude('put')


class UntouchedStore:
    """A store whose every verification method is a tripwire, for the refusals that must cost no I/O.

    Not a stand-in for the feature: the authority decision under test is `verification_records._reader` /
    `_writer`, run for real against a real `VerificationPolicy`. The tripwire pins only the ordering the
    contract fixes — "before body/DB" — which a real `Store` cannot report about itself.
    """

    def __init__(self, policy: VerificationPolicy | None) -> None:
        self.verification_policy = policy

    def _forbidden(self, name: str):
        raise AssertionError(f'{name} was entered before the answer was decided')

    def get_verification_binding(self, *args, **kwargs):
        self._forbidden('get_verification_binding')

    def list_verifications(self, *args, **kwargs):
        self._forbidden('list_verifications')

    def get_verification(self, *args, **kwargs):
        self._forbidden('get_verification')

    def put_verification(self, *args, **kwargs):
        self._forbidden('put_verification')


class WriteLock:
    """A real SQLite write transaction held by this file's thread, released only when this file says so.

    `BEGIN IMMEDIATE` plus one `INSERT` (rolled back at the end) is what makes a verification write's own
    `BEGIN IMMEDIATE` wait, so "the callable is still inside SQL" is a property of the fixture and not a
    race. `held` and `released` are thread events this file owns, and `tidy` guarantees no test leaves a
    lock behind. Its thread is deliberately not named after the seam's worker prefix.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.held = threading.Event()
        self.release = threading.Event()
        self.released = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self.run, name='fixture-write-holder', daemon=True)

    def run(self) -> None:
        connection = sqlite3.connect(self.path, timeout=SAFETY, isolation_level=None)
        try:
            connection.execute('BEGIN IMMEDIATE')
            connection.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                               (utc_text(dt.datetime.now(dt.timezone.utc)), 'fixture',
                                'fixture.write.lock', 'x', '{}'))
            self.held.set()
            if not self.release.wait(timeout=SAFETY):
                raise TimeoutError('the test never released the held write lock')
        except BaseException as exc:  # handed to the test, never swallowed
            self.error = exc
        finally:
            with contextlib.suppress(sqlite3.Error):
                if connection.in_transaction:
                    connection.execute('ROLLBACK')
            connection.close()
            self.released.set()

    def start(self, test: unittest.TestCase) -> 'WriteLock':
        self.thread.start()
        test.addCleanup(self.tidy)
        return self

    def tidy(self) -> None:
        self.release.set()
        self.thread.join(timeout=SAFETY)


class LogCollector(logging.Handler):
    """Every record that survives its logger's level, whatever logger name the implementation chose."""

    def __init__(self) -> None:
        super().__init__(level=0)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    @contextlib.contextmanager
    def captured(self):
        root = logging.getLogger()
        root.addHandler(self)
        try:
            yield self
        finally:
            root.removeHandler(self)
            self.close()


@dataclasses.dataclass(frozen=True)
class Reply:
    """What one `handle` call produced, plus whether it ever asked for a body."""

    status: int | None
    body: dict | None
    reads: int

    @property
    def text(self) -> str:
        return f'{self.status} {self.body} after {self.reads} body read(s)'


class Scenario:
    """The shared lifecycle: a real incident, one bound action, one execution, and the seam's own API.

    A plain mixin — it subclasses nothing, so no runner collects it as a test case with no tests in it.
    """

    def setUp(self, *, outcome: str | None = 'succeeded') -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.async_runner = asyncio.Runner()
        self.addCleanup(self.finish_async)
        self.root = Path(self.temp.name)
        # Derived from the real clock: this seam cannot inject a `now`, so the server judges the submission
        # at the instant it arrives and every fixture instant must already be behind that.
        self.now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)
        self.propose_at = self.now + dt.timedelta(minutes=3)
        self.terminal = self.now + dt.timedelta(minutes=5)
        self.expires = utc_text(self.now + dt.timedelta(hours=1))
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.inventory = self.root / 'inventory.db'
        index.build(declared, self.inventory, 'fixture', now=self.now)
        self.gate = action_policy(self.inventory, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        self.policy = VerificationPolicy(policy_document(self.host))
        self.store = ObservingStore(self.root / 'state.db', NotificationPolicy(delivery_mode='off'),
                                   verification_policy=self.policy)
        self.api = module.VerificationAPI(self.store)
        self.addCleanup(self.api.close)
        self.case: dict[str, Any] = {}
        self.ready(outcome=outcome)

    # ------------------------------------------------------------------ the lifecycle under test
    def fire(self, minute: int = 0, *, store: Store | None = None) -> dict:
        """Intake one `metric-threshold` event and assert the platform really accepted it."""
        store = store or self.store
        end = self.now + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        payload = detections.event(DETECTOR, self.host, RULE, 'threshold', 'firing', window,
                                  {'resource_id': self.host, 'rule_id': RULE, 'artifact_sha256': PIN},
                                  query_type='metric-threshold', version=RULE_VERSION)
        result = store.intake(payload, Actor(DETECTOR, 'producer'), now=end)
        assert result['status'] == 'accepted', 'the fixture event must be a fresh acceptance'
        return result

    def bind(self, minute: int = 0) -> dict:
        """One open incident and one *bound* action, read back through the storage layer's own read."""
        fired = self.fire(minute)
        request = {'retry_key': f'once-{minute}', 'incident_id': fired['incident_id'],
                   'action': 'inspect', 'version': '1', 'targets': [self.host], 'parameters': {},
                   'evidence': [fired['event_id']], 'expires_at': self.expires}
        action_id = self.store.propose_action(request, AGENT, self.gate, now=self.propose_at)['action_id']
        binding = self.store.get_verification_binding(action_id, READER)
        assert (binding['status'], binding['reason']) == ('bound', 'matched'), \
            f'the fixture action did not bind: {binding}'
        return {'action_id': action_id, 'incident_id': fired['incident_id'],
                'event_id': fired['event_id'], 'binding_id': binding['binding_id'],
                'origin': binding['origin'], 'window': self.window()}

    def execute(self, case: dict, *, outcome: str | None = 'succeeded') -> dict:
        """Decide, claim and (unless told to leave it running) report the execution's outcome."""
        self.store.decide(case['action_id'], 'approved', HUMAN, now=self.propose_at)
        claim = self.store.claim_action(case['action_id'], RUNNER, self.gate,
                                       now=self.terminal - dt.timedelta(minutes=1))
        case['execution_id'] = claim['execution_id']
        if outcome is not None:
            self.store.execution_outcome(claim['execution_id'], outcome, RUNNER, claim['runner_token'],
                                        now=self.terminal)
        return case

    def ready(self, *, outcome: str | None = 'succeeded') -> dict:
        """The default scenario every read/write test starts from: one bound action, one run."""
        if not self.case:
            self.case = self.execute(self.bind(), outcome=outcome)
        return self.case

    # ------------------------------------------------------------------ submitted statements
    def window(self, *, ends_at: dt.datetime | None = None, seconds: int = WINDOW_SECONDS) -> dict:
        """A window entirely after the terminal instant, exactly the captured length long."""
        ends_at = self.terminal + dt.timedelta(minutes=6) if ends_at is None else ends_at
        return {'start': utc_text(ends_at - dt.timedelta(seconds=seconds)), 'end': utc_text(ends_at)}

    def rows(self, case: dict, window: dict, values: list) -> list:
        origin = case['origin']
        instant = utc_text(timestamp(window['end']) - dt.timedelta(seconds=60))
        return [{'resource_id': origin['resource_id'], 'metric_name': origin['metric_name'],
                 'observed_at': instant, 'value': value} for value in values]

    def receipt(self, case: dict, window: dict, count: int) -> dict:
        """The six-field receipt one read of the captured origin would carry, built by the facade."""
        origin = case['origin']
        samples = [MetricSample(name=origin['metric_name'], value=1.0, resource_id=origin['resource_id'],
                               labels={'resource_id': origin['resource_id']}, timestamp=window['start'])
                   for _ in range(count)]
        outcome = facade.build_outcome(facade.QUERY_KINDS[origin['query_type']],
                                      dict(origin['parameters']),
                                      Window(start=window['start'], end=window['end']), samples)
        return outcome.receipt.as_dict()

    def statement(self, case: dict | None = None, *, value: float = 70.0, outcome: str = 'available',
                  **changes) -> dict:
        """One complete submitted observation: the six record keys, changed only as a test states."""
        case = self.ready() if case is None else case
        window = changes.pop('window', None) or case['window']
        samples = self.rows(case, window, [value]) if outcome == 'available' else []
        document = {'execution_id': case['execution_id'], 'binding_id': case['binding_id'],
                    'window': window, 'outcome': outcome, 'samples': samples,
                    'receipt': self.receipt(case, window, len(samples)) if samples else None}
        document.update(changes)
        return document

    def body(self, case: dict | None = None, **changes) -> bytes:
        return canonical(self.statement(case, **changes)).encode()

    # ------------------------------------------------------------------ the seam, driven directly
    async def call(self, method: str, path: str, *, query: bytes = b'', body: bytes | None = None,
                   messages: list | None = None, forbid_body: bool = False, actor: Actor = READER,
                   api: Any = None) -> Reply:
        """One `handle` exchange: no socket, no transport, nothing between this file and the seam."""
        receive = Receive(messages if messages is not None else
                          (chunks(body) if body is not None else None), forbid_body=forbid_body)
        result = await (api or self.api).handle(scope_of(method, path, query), receive, actor)
        status, payload = (None, None) if result is None else result
        return Reply(status=status, body=payload, reads=receive.calls)

    def drive(self, coroutine):
        """Keep successive requests to this fixture's services on one serving loop."""
        return self.async_runner.run(coroutine)

    def finish_async(self):
        """Drain admitted work before closing the serving loop and removing the database."""
        async def drain():
            for name in ('api', 'gated'):
                service = getattr(self, name, None)
                if service is not None:
                    service.close()
                    await service.wait_idle()

        try:
            self.async_runner.run(drain())
        finally:
            self.async_runner.close()

    def assert_store_off_loop(self) -> None:
        """The last `Store` callable really ran elsewhere: not this thread, and not on any loop.

        This is the deterministic half of "the serving loop is not held": an implementation that called
        `Store` inline would report the main thread and a running loop here, and no amount of polling or
        elapsed-time sampling is needed to see it.
        """
        name, thread_name, on_main, running = self.store.last
        detail = f'the {name} callable ran on {thread_name} (main={on_main}, loop={running})'
        self.assertFalse(on_main, f'{detail}: the seam ran its Store call on the serving thread')
        self.assertIsNone(running, f'{detail}: the Store callable ran on a thread owning an event loop')
        self.assertTrue(thread_name.startswith('verification'), detail)


class OwnershipTests(Scenario, unittest.TestCase):
    """`owns` is membership in a three-element set, and `handle` keeps its promise about everything else."""

    def test_the_three_literals_are_owned_and_nothing_else_under_the_prefix_is(self):
        for path in (BINDING, RECORDS, RECORD):
            self.assertTrue(module.owns(path), path)
        for path in ('/v1/verification', '/v1/verification/', '/v1/verification/records/',
                     '/v1/verification/records/extra', '/v1/verification/recordings',
                     '/v1/verification/BINDING', '/v1/verification/binding?action_id=x', '/v1/me',
                     '/v1/records/audit', '/v1/audit', None, 7, b'/v1/verification/records',
                     ['/v1/verification/records']):
            self.assertFalse(module.owns(path), repr(path))

    def test_an_unowned_path_is_handed_back_without_a_status(self):
        """`None` is the only answer for "not mine": a 404 here would be a second, different 404."""
        for method, path in (('GET', '/v1/verification/records/extra'), ('GET', '/v1/verification'),
                            ('POST', '/v1/verification/recordings'), ('GET', '/v1/records/audit')):
            reply = self.drive(self.call(method, path, query=b'action_id=' + b'0' * 36, body=b'{}'))
            self.assertIsNone(reply.status, f'{path} was adopted by prefix')
            self.assertEqual(reply.reads, 0, f'{path} was adopted and its body read')

    def test_the_write_route_is_owed_by_this_seam_and_the_read_routes_refuse_a_post(self):
        """A POST to `/records` reaches the authority answer (not 405, not the main API's 404); to the
        two read routes it is a 405 decided without a body, a thread or a database."""
        refused = self.drive(self.call('POST', RECORDS, body=b'{"nope": 1}', actor=STRANGER))
        self.assertEqual((refused.status, refused.body), (403, NOT_AUTHORISED), refused.text)
        for path in (BINDING, RECORD):
            reply = self.drive(self.call('POST', path, body=self.body(), actor=VERIFIER,
                                        forbid_body=True))
            self.assertEqual((reply.status, reply.body), (405, METHOD_NOT_ALLOWED))
            self.assertEqual(reply.reads, 0)

    def test_every_verb_that_is_neither_get_nor_post_is_a_405_before_anything_else(self):
        alive = set(threading.enumerate())
        for path in (BINDING, RECORDS, RECORD):
            for verb in ('PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
                reply = self.drive(self.call(verb, path, query=b'action_id=' + b'0' * 36,
                                            actor=VERIFIER, forbid_body=True))
                self.assertEqual((reply.status, reply.body), (405, METHOD_NOT_ALLOWED),
                                 f'{verb} {path}')
                self.assertEqual(reply.reads, 0)
        self.assertEqual(workers_started_since(alive), [], 'a 405 started a worker thread')
        self.assertEqual([name for name, *_ in self.store.observations][-1:], ['binding'],
                         'a 405 reached a Store method (the fixture binding read is the last one)')


class AuthorityTests(Scenario, unittest.TestCase):
    """Who may ask, in what order, and what each refusal is not allowed to cost."""

    def setUp(self) -> None:
        super().setUp()
        self.gated = module.VerificationAPI(UntouchedStore(self.policy))
        self.addCleanup(self.gated.close)

    def test_summary_is_turned_away_before_the_body_and_before_storage(self):
        for method, path in (('GET', BINDING), ('GET', RECORDS), ('GET', RECORD), ('POST', RECORDS)):
            reply = self.drive(self.call(method, path, body=b'{"execution_id": "anything"}',
                                        actor=SUMMARY, api=self.gated, forbid_body=True))
            self.assertEqual((reply.status, reply.body), (403, SUMMARY_ONLY), f'{method} {path}')
            self.assertEqual(reply.reads, 0)

    def test_every_read_role_the_storage_layer_admits_reaches_the_database(self):
        """The positive control: those four roles really are admitted, and their lookup is a real 404."""
        for actor in (READER, HUMAN, AGENT, RUNNER):
            reply = self.drive(self.call('GET', BINDING, query=f'action_id={uuid.uuid4()}'.encode(),
                                        actor=actor, forbid_body=True))
            self.assertEqual((reply.status, reply.body), (404, NOT_FOUND), actor.role)

    def test_a_named_verifier_may_read_and_an_unlisted_producer_may_not(self):
        """`producer` is admitted only while the current policy names it — the storage rule, not a copy."""
        verifier = self.drive(self.call('GET', BINDING, query=f'action_id={uuid.uuid4()}'.encode(),
                                       actor=VERIFIER, forbid_body=True))
        self.assertEqual((verifier.status, verifier.body), (404, NOT_FOUND),
                         'an allowlisted producer was refused a read the policy grants')
        stranger = self.drive(self.call('GET', BINDING, query=f'action_id={uuid.uuid4()}'.encode(),
                                       actor=STRANGER, api=self.gated, forbid_body=True))
        self.assertEqual((stranger.status, stranger.body), (403, NOT_AUTHORISED))
        self.assertEqual(stranger.reads, 0)

    def test_a_write_role_refusal_never_reads_the_body(self):
        for actor in (READER, HUMAN, AGENT, RUNNER, STRANGER):
            reply = self.drive(self.call('POST', RECORDS, body=self.body(), actor=actor,
                                        api=self.gated, forbid_body=True))
            self.assertEqual((reply.status, reply.body), (403, NOT_AUTHORISED), actor.role)
            self.assertEqual(reply.reads, 0, f'a {actor.role} POST decided its 403 by reading the body')

    def test_a_verifier_with_no_policy_mounted_is_told_the_service_answer(self):
        """`NO_POLICY` is 503 `verification_unavailable`, decided before the body and before the file."""
        off = module.VerificationAPI(UntouchedStore(None))
        self.addCleanup(off.close)
        reply = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER,
                                    api=off, forbid_body=True))
        self.assertEqual((reply.status, reply.body), (503, UNAVAILABLE))
        self.assertEqual(reply.reads, 0)

    def test_reads_still_work_when_no_policy_is_mounted_and_writes_still_are_refused(self):
        """Off is write-off, not read-off: an unmounted policy may not move a captured binding.

        The same file, reopened with no policy at all, is the deployment state this claims about: the
        binding the proposal captured under a policy still reads back complete, and the write gate is the
        only thing that changes.
        """
        case = self.case
        reopened = ObservingStore(self.root / 'state.db', NotificationPolicy(delivery_mode='off'))
        unmounted = module.VerificationAPI(reopened)
        self.addCleanup(unmounted.close)
        binding = self.drive(self.call('GET', BINDING, query=f"action_id={case['action_id']}".encode(),
                                      api=unmounted, forbid_body=True))
        self.assertEqual(binding.status, 200, binding.text)
        self.assertEqual((binding.body['status'], binding.body['binding_id']),
                         ('bound', case['binding_id']))
        reply = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER, api=unmounted))
        self.assertEqual((reply.status, reply.body), (503, UNAVAILABLE))

    def test_an_actor_that_is_not_an_actor_is_refused_and_never_parsed(self):
        query = f'execution_id={uuid.uuid4()}'.encode()
        for impostor in (None, 'reader-1', Actor('bad identity', 'reader'), Actor('', 'reader'),
                        Actor('reader-1', ''), Actor('reader-1', 'verifier')):
            reply = self.drive(self.call('GET', RECORDS, query=query, actor=impostor,
                                        api=self.gated, forbid_body=True))
            self.assertEqual((reply.status, reply.body), (403, NOT_AUTHORISED), repr(impostor))
            self.assertEqual(reply.reads, 0)


class QueryParserTests(Scenario, unittest.TestCase):
    """The raw query bytes, judged before anything else: one name, one value, decodable, in range."""

    def setUp(self) -> None:
        super().setUp()
        self.gated = module.VerificationAPI(UntouchedStore(self.policy))
        self.addCleanup(self.gated.close)

    def refused(self, query: bytes, expected: tuple[int, dict], *, path: str = BINDING) -> None:
        reply = self.drive(self.call('GET', path, query=query, api=self.gated, forbid_body=True))
        self.assertEqual((reply.status, reply.body), expected, f'{query!r} was not refused as {expected}')
        self.assertEqual(reply.reads, 0)

    def refused_query(self, query: bytes, detail: str, *, path: str = BINDING) -> None:
        self.refused(query, (400, {'error': 'invalid_request', 'detail': detail}), path=path)

    def test_exactly_one_named_parameter_is_required_and_no_other_spelling_is_accepted(self):
        wanted = str(uuid.uuid4()).encode()
        pairs = [(b'', module.QUERY_PARAMETER),
                 (b'?action_id=' + wanted, module.QUERY_PARAMETER),
                 (b'&', module.BAD_QUERY),
                 (b'action_id', module.BAD_QUERY),
                 (b'action_id=', module.BAD_QUERY),
                 (b'=x', module.BAD_QUERY),
                 (b'action_id=' + wanted + b'&', module.BAD_QUERY),
                 (b'&action_id=' + wanted, module.BAD_QUERY),
                 (b'action_id=' + wanted + b'&x=', module.BAD_QUERY),
                 (b'action_id=' + wanted + b'&action_id=' + wanted, module.QUERY_PARAMETER),
                 (b'action_id=' + wanted + b'&execution_id=' + wanted, module.QUERY_PARAMETER),
                 (b'execution_id=' + wanted, module.QUERY_PARAMETER),
                 (b'action+id=' + wanted, module.QUERY_PARAMETER),
                 (b'ACTION_ID=' + wanted, module.QUERY_PARAMETER)]
        for query, detail in pairs:
            self.refused_query(query, detail)
        # The `?` case above is the one worth naming: a caller that put the separator in the raw query
        # string has sent a *name* that is not the one this route reads, not undecodable bytes.

    def test_a_value_is_judged_on_type_and_length_before_any_identifier_parser(self):
        self.refused_query(b'action_id=' + b'0' * 35, module.BAD_IDENTIFIER_TEXT)
        self.refused_query(b'action_id=' + b'0' * 37, module.BAD_IDENTIFIER_TEXT)
        self.refused_query(b'action_id=' + str(uuid.uuid4()).upper().encode(),
                           module.BAD_IDENTIFIER_TEXT)
        self.refused_query(b'action_id=' + b'0' * 36 + b'%20', module.BAD_IDENTIFIER_TEXT)
        for digest in (b'0' * 63, b'0' * 65, PIN[:-1].encode() + b'A', b'z' * 64, b'0' * 32 + b'0' * 31):
            self.refused_query(f'verification_id={digest.decode()}'.encode(), BAD_VERIFICATION_ID,
                              path=RECORD)

    def test_a_valid_looking_identifier_reaches_the_database_and_is_a_real_404(self):
        """The parser admits it, so the answer must come from the file: 404, and no body read."""
        reply = self.drive(self.call('GET', RECORD, query=b'verification_id=' + b'0' * 64,
                                    forbid_body=True))
        self.assertEqual((reply.status, reply.body), (404, NOT_FOUND), reply.text)
        self.assertEqual([name for name, *_ in self.store.observations][-1:], ['record'])

    def test_decoding_is_strict_in_both_directions_and_never_replaces_a_byte(self):
        for query in ('action_id=é'.encode(),
                      'action_id=✔'.encode(),
                      b'action_id=%2',
                      b'action_id=%zz' + b'0' * 34,
                      b'action_id=%ff%fe%ff',
                      b'action_id=%',
                      b'action_id=%41-0000-0000-0000-000000000000'):
            reply = self.drive(self.call('GET', BINDING, query=query, api=self.gated, forbid_body=True))
            self.assertEqual(reply.status, 400, repr(query))
            self.assertEqual(reply.body['error'], 'invalid_request', repr(query))

    def test_a_percent_escape_is_decoded_and_the_decoded_value_is_what_is_judged(self):
        """Every `-` of a real UUID escaped is still that UUID: the decode happened, and the answer is 404."""
        wanted = str(uuid.uuid4())
        escaped = b'action_id=' + wanted.replace('-', '%2D').encode()
        self.assertNotIn(b'-', escaped)
        reply = self.drive(self.call('GET', BINDING, query=escaped, forbid_body=True))
        self.assertEqual((reply.status, reply.body), (404, NOT_FOUND), reply.text)
        self.refused_query(b'action_id=%30' + b'0' * 35, module.BAD_IDENTIFIER_TEXT)

    def test_query_bytes_are_bounded_before_anything_is_parsed(self):
        padding = b'0' * (module.MAX_QUERY_BYTES + 1 - len('action_id='))
        self.refused(b'action_id=' + padding,
                     (400, {'error': 'invalid_request', 'detail': module.QUERY_LIMIT}))
        exact = b'action_id=' + b'0' * (module.MAX_QUERY_BYTES - len('action_id='))
        self.refused_query(exact, module.BAD_IDENTIFIER_TEXT)

    def test_a_write_admits_no_query_string_at_all(self):
        reply = self.drive(self.call('POST', RECORDS, query=f'execution_id={uuid.uuid4()}'.encode(),
                                    body=self.body(), actor=VERIFIER, api=self.gated, forbid_body=True))
        self.assertEqual((reply.status, reply.body),
                         (400, {'error': 'invalid_request', 'detail': module.QUERY_ON_WRITE}))
        self.assertEqual(reply.reads, 0)


class BodyParserTests(Scenario, unittest.TestCase):
    """The submitted bytes: strict UTF-8, one object, no duplicate keys, no unbounded numbers, size first."""

    def refused(self, messages: list, *, status: int = 400, detail: str = module.BAD_BODY) -> None:
        reply = self.drive(self.call('POST', RECORDS, messages=messages, actor=VERIFIER))
        expected = (status, {'error': 'invalid_request', 'detail': detail} if status == 400 else TOO_LARGE)
        self.assertEqual((reply.status, reply.body), expected, f'{messages[0]} was not refused')

    def test_only_a_strict_utf8_json_object_is_considered_at_all(self):
        for raw in (b'', b'null', b'[1,2]', b'"record"', b'not json', b'{"a": 1,}',
                    b'{"a": 1, "a": 2}', b'{"a": {"b": 1, "b": 2}}',
                    b'{"execution_id": NaN}', b'{"execution_id": Infinity}',
                    b'{"execution_id": -Infinity}', b'{"value": 1e400}', b'{"value": -1e400}',
                    b'{"n": ' + b'9' * 5000 + b'}', b'[' * 2000 + b']' * 2000,
                    b'{"a": 1}\ntrailing', b'{"value": 1.0e309}'):
            self.refused(chunks(raw))

    def test_a_utf16_or_utf32_body_is_refused_rather_than_sniffed(self):
        """`json.loads` would accept the BOM and read twice or four times the bytes of a bounded record."""
        text = canonical(self.statement())
        for encoding in ('utf-16', 'utf-32', 'utf-16-le', 'utf-32-le'):
            encoded = text.encode(encoding)
            if encoding in ('utf-16', 'utf-32'):
                self.assertTrue(encoded.startswith(b'\xff\xfe'), encoding)
            self.refused(chunks(encoded))

    def test_signed64_boundary_is_not_the_interpreter_digit_limit(self):
        for value in (module.INTEGER_LIMIT, -module.INTEGER_LIMIT):
            raw = json.dumps({'n': value}).encode()
            self.assertEqual(module._strict_object(raw), {'n': value})
        for value in (module.INTEGER_LIMIT + 1, -module.INTEGER_LIMIT - 1):
            self.refused(chunks(json.dumps({'n': value}).encode()))

    def test_the_size_bound_is_on_raw_bytes_before_concatenation(self):
        too_large = b'{"a": "' + b'x' * module.MAX_BODY_BYTES + b'"}'
        self.refused(chunks(too_large), status=413)
        self.refused(chunks(too_large, (1000, 20000, 20000)), status=413)
        exact = b'{"a": "' + b'x' * (module.MAX_BODY_BYTES - 9) + b'"}'
        self.assertEqual(len(exact), module.MAX_BODY_BYTES)
        self.refused(chunks(exact), detail=BAD_RECORD)
        self.refused(chunks(exact, (1, module.MAX_BODY_BYTES - 1)), detail=BAD_RECORD)

    def test_a_disconnect_is_not_a_write_and_gets_no_answer(self):
        """`handle` returns `None` and nothing reaches the file: a caller that hung up submitted nothing."""
        before = self.store.records('audit', 100)
        self.assertFalse(any(row['operation'] == 'verification.recorded' for row in before),
                         'the fixture itself must have written no verification record')
        for messages in (chunks(self.body(), (40, None), disconnect=True),
                         [{'type': 'http.disconnect'}],
                         [{'type': 'http.request', 'body': b'{"execution_id":', 'more_body': True},
                          {'type': 'http.disconnect'}]):
            reply = self.drive(self.call('POST', RECORDS, messages=messages, actor=VERIFIER))
            self.assertEqual((reply.status, reply.body), (None, None), f'{messages} was answered')
        self.assertEqual(self.store.records('audit', 100), before)
        listed = self.drive(self.call('GET', RECORDS,
                                     query=f"execution_id={self.case['execution_id']}".encode(),
                                     forbid_body=True))
        self.assertEqual(listed.body, {'verification_ids': []})

    def test_a_valid_object_still_needs_the_storage_layer_to_accept_it(self):
        """The parser admits six-field JSON and nothing about it: the record's own bounds are the store's."""
        reply = self.drive(self.call('POST', RECORDS, body=canonical({}).encode(), actor=VERIFIER))
        self.assertEqual((reply.status, reply.body['error'], reply.body['detail']),
                         (400, 'invalid_request', BAD_RECORD))


class LifecycleTests(Scenario, unittest.TestCase):
    """Smoke over the real thing: submit, discover, read back, replay, and the refusals around them."""

    def test_a_submission_is_adjudicated_by_the_store_and_every_read_returns_it(self):
        case = self.case
        # Fixture setup read the binding directly; only HTTP-driven calls belong in this census.
        self.store.observations.clear()
        posted = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        self.assertEqual(posted.status, 200, posted.text)
        verification_id = posted.body['verification_id']
        self.assertIs(posted.body['created'], True)
        self.assertEqual(sorted(posted.body), ['created', 'verification_id'])
        self.assertRegex(verification_id, r'^[0-9a-f]{64}$')

        listed = self.drive(self.call('GET', RECORDS, query=f"execution_id={case['execution_id']}".encode(),
                                     forbid_body=True))
        self.assertEqual((listed.status, listed.body), (200, {'verification_ids': [verification_id]}))

        read = self.drive(self.call('GET', RECORD, query=f'verification_id={verification_id}'.encode(),
                                   forbid_body=True))
        self.assertEqual(read.status, 200, read.text)
        self.assertEqual(read.body, Store.get_verification(self.store, verification_id, READER),
                         'the read answered something other than the stored document')
        self.assertEqual((read.body['verdict'], read.body['reason']), ('cleared', 'comparison-satisfied'))
        self.assertEqual(read.body['recorded_by'], VERIFIER.identity)
        self.assertEqual(read.body['execution_id'], case['execution_id'])

        binding = self.drive(self.call('GET', BINDING, query=f"action_id={case['action_id']}".encode(),
                                      forbid_body=True))
        self.assertEqual((binding.status, binding.body),
                         (200, Store.get_verification_binding(self.store, case['action_id'], READER)))
        self.assertEqual(len(self.store.observations), 4)
        self.assert_store_off_loop()

    def test_an_exact_replay_is_a_200_with_created_false_and_a_changed_one_is_a_conflict(self):
        first = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        replay = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        self.assertEqual((replay.status, replay.body),
                         (200, {'verification_id': first.body['verification_id'], 'created': False}),
                         replay.text)
        changed = self.drive(self.call('POST', RECORDS, body=self.body(value=95.0), actor=VERIFIER))
        self.assertEqual((changed.status, changed.body['error'], changed.body['detail']),
                         (409, 'conflict', RETRY_CHANGED), changed.text)
        listed = self.drive(self.call('GET', RECORDS,
                                     query=f"execution_id={self.case['execution_id']}".encode(),
                                     forbid_body=True))
        self.assertEqual(listed.body, {'verification_ids': [first.body['verification_id']]},
                         'a replay or a conflict added a row')

    def test_an_unlisted_producer_may_not_file_and_a_verifier_may(self):
        stranger = self.drive(self.call('POST', RECORDS, body=self.body(), actor=STRANGER))
        self.assertEqual((stranger.status, stranger.body), (403, NOT_AUTHORISED), stranger.text)
        verifier = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        self.assertEqual(verifier.status, 200, verifier.text)

    def test_a_missing_execution_action_or_record_is_a_404(self):
        for path, query in ((RECORDS, f'execution_id={uuid.uuid4()}'),
                            (BINDING, f'action_id={uuid.uuid4()}'),
                            (RECORD, f'verification_id={"b" * 64}')):
            reply = self.drive(self.call('GET', path, query=query.encode(), forbid_body=True))
            self.assertEqual((reply.status, reply.body), (404, NOT_FOUND), f'{path}: {reply.text}')
        absent = self.drive(self.call('POST', RECORDS,
                                     body=self.body(execution_id=str(uuid.uuid4())), actor=VERIFIER))
        self.assertEqual((absent.status, absent.body), (404, NOT_FOUND), absent.text)

    def test_a_record_the_store_refuses_is_a_400_naming_its_own_field(self):
        unsourced = self.drive(self.call('POST', RECORDS,
                                        body=canonical(self.statement(outcome='available', receipt=None,
                                                                     samples=[])).encode(),
                                        actor=VERIFIER))
        self.assertEqual((unsourced.status, unsourced.body['error']), (400, 'invalid_request'),
                         unsourced.text)
        self.assertIn(unsourced.body['detail'],
                      ('Verification record needs a receipt for this read outcome', BAD_RECORD))
        mismatch = self.drive(self.call('POST', RECORDS, body=self.body(binding_id='c' * 64),
                                       actor=VERIFIER))
        self.assertEqual((mismatch.status, mismatch.body['error'], mismatch.body['detail']),
                         (400, 'invalid_request', BAD_BINDING), mismatch.text)

    def test_a_refused_submission_writes_no_audit_row(self):
        """A refused verification is not an action attempt: `Store` owns rows, and it wrote none here."""
        before = self.store.records('audit', 100)
        self.drive(self.call('POST', RECORDS, body=b'{}', actor=VERIFIER))
        self.drive(self.call('POST', RECORDS, body=self.body(execution_id=str(uuid.uuid4())),
                            actor=VERIFIER))
        self.drive(self.call('POST', RECORDS, body=self.body(), actor=STRANGER))
        self.assertEqual(self.store.records('audit', 100), before)

    def test_one_audit_row_behind_one_accepted_record_and_the_row_names_only_a_verdict(self):
        before = self.store.records('audit', 100)
        self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        added = [row for row in self.store.records('audit', 100) if row not in before]
        self.assertEqual([row['operation'] for row in added], ['verification.recorded'])
        self.assertEqual(sorted(json.loads(added[0]['detail'])), ['reason', 'verdict'])


class ExecutingTests(Scenario, unittest.TestCase):
    """One scenario whose execution is still running, because the seam must carry that 409 through."""

    def setUp(self) -> None:
        super().setUp(outcome=None)

    def test_an_executing_execution_is_a_conflict_and_writes_nothing(self):
        case = self.case
        self.assertEqual(self.store.records('executions', 10)[0]['status'], 'executing')
        before = self.store.records('audit', 100)
        reply = self.drive(self.call('POST', RECORDS,
                                    body=self.body(outcome='unavailable', receipt=None, samples=[]),
                                    actor=VERIFIER))
        self.assertEqual((reply.status, reply.body['error'], reply.body['detail']),
                         (409, 'conflict', EXECUTING_EXECUTION), reply.text)
        self.assertEqual(self.store.records('audit', 100), before)
        listed = self.drive(self.call('GET', RECORDS, query=f"execution_id={case['execution_id']}".encode(),
                                     forbid_body=True))
        self.assertEqual((listed.status, listed.body), (200, {'verification_ids': []}),
                         'an executing execution was not listable')


class SlotTests(Scenario, unittest.TestCase):
    """One actual call at a time, on the instance's own thread, and cancellation that frees nothing."""

    def test_no_thread_exists_until_a_request_needs_one_and_none_survives_close(self):
        alive = set(threading.enumerate())
        self.assertEqual(self.store.observations[-1][0], 'binding', 'the fixture read is the only history')
        self.assertFalse(self.api.slot_busy)
        self.assertFalse(self.api.closed)
        case = self.case
        reply = self.drive(self.call('GET', RECORDS, query=f"execution_id={case['execution_id']}".encode(),
                                    forbid_body=True))
        self.assertEqual((reply.status, reply.body), (200, {'verification_ids': []}), reply.text)
        started = workers_started_since(alive)
        self.assertEqual(len(started), 1, f'a request did not start exactly one worker: {started}')
        self.assert_store_off_loop()
        self.assertFalse(self.api.slot_busy, 'the slot was still claimed after its read finished')
        self.api.close()
        self.assertTrue(self.api.closed)
        asyncio.run(until(lambda: not workers_started_since(alive),
                          what='this instance\'s worker thread to end after close()'))

    def test_a_closed_instance_sheds_without_touching_storage(self):
        self.api.close()
        before = len(self.store.observations)
        reply = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        self.assertEqual((reply.status, reply.body), (503, BUSY), reply.text)
        self.assertTrue(reply.reads, 'a closed instance refused before it parsed the body')
        self.assertEqual(len(self.store.observations), before)

    def test_one_call_at_a_time_the_loop_is_not_held_and_the_slot_is_reused(self):
        outcome = self.drive(self.parked_write())
        self.assertEqual(outcome['owner'].status, 200, f'the parked write never completed: {outcome}')
        self.assertEqual((outcome['shed'].status, outcome['shed'].body), (503, BUSY), outcome['shed'].text)
        self.assertTrue(outcome['shed'].reads, 'the busy answer was reached without parsing the body')
        self.assertFalse(outcome['exited_while_busy'], 'the parked callable reported itself finished early')
        self.assertFalse(outcome['inline'], 'the callable ran on the serving loop')
        self.assertLess(outcome['elapsed'], IMMEDIATE_WINDOW,
                        'the shed answer waited out a real database lock: the write was not off the loop')
        self.assertEqual(len(outcome['workers']), 1, 'a busy instance started a second worker')
        reused = self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
        self.assertEqual((reused.status, reused.body['created']), (200, False),
                         f'the slot was not reusable by the next request: {reused.text}')

    async def parked_write(self) -> dict:
        """Hold a real write, submit one request, shed a second, and report what each one observed."""
        holder = WriteLock(self.store.path).start(self)
        await until(holder.held.is_set, what='the fixture write lock to be held')
        alive = set(threading.enumerate())
        try:
            owner = asyncio.create_task(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
            await until(self.store.entered.is_set, what='the submitted write to enter Store')
            inline = self.store.last[2] or self.store.last[3] is not None
            before = time.monotonic()
            shed = await self.call('POST', RECORDS, body=self.body(value=80.0), actor=VERIFIER)
            elapsed = time.monotonic() - before
            exited = self.store.journal.seen('store:exit:put')
            holder.release.set()
            answered = await asyncio.wait_for(owner, timeout=SAFETY)
            return {'owner': answered, 'shed': shed, 'elapsed': elapsed, 'inline': inline,
                    'exited_while_busy': exited, 'workers': workers_started_since(alive)}
        finally:
            holder.release.set()

    def test_cancelling_the_request_abandons_the_answer_but_not_the_write(self):
        outcome = asyncio.run(self.cancelled_write())
        self.assertTrue(outcome['cancelled'], 'the cancelled request did not end cancelled')
        self.assertEqual((outcome['shed'].status, outcome['shed'].body), (503, BUSY),
                         'cancellation handed the slot back')
        self.assertFalse(outcome['exited'], 'the parked callable finished when its caller left')
        self.assertEqual(outcome['read'].status, 200,
                         f'the write the cancelled request owned never landed: {outcome["read"].text}')
        self.assertEqual(outcome['read'].body['verdict'], 'cleared')

    async def cancelled_write(self) -> dict:
        holder = WriteLock(self.store.path).start(self)
        await until(holder.held.is_set, what='the fixture write lock to be held')
        try:
            owner = asyncio.create_task(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
            await until(self.store.entered.is_set, what='the submitted write to enter Store')
            owner.cancel()
            cancelled = False
            try:
                await owner
            except asyncio.CancelledError:
                cancelled = True
            else:
                self.fail('a cancelled verification request answered instead of unwinding')
            shed = await self.call('POST', RECORDS, body=self.body(value=80.0), actor=VERIFIER)
            exited = self.store.journal.seen('store:exit:put')
            holder.release.set()
            await until(self.store.exited.is_set, what='the parked write to leave Store')
            await asyncio.wait_for(self.api.wait_idle(), timeout=SAFETY)
            self.assertFalse(self.api.slot_busy, 'the slot stayed claimed after the write ended')
            listed = await self.call('GET', RECORDS,
                                    query=f"execution_id={self.case['execution_id']}".encode(),
                                    forbid_body=True)
            read = await self.call('GET', RECORD,
                                  query=f"verification_id={listed.body['verification_ids'][0]}".encode(),
                                  forbid_body=True)
            return {'cancelled': cancelled, 'shed': shed, 'exited': exited, 'read': read}
        finally:
            holder.release.set()

    def test_wait_idle_returns_only_once_the_callable_has_left_store(self):
        outcome = asyncio.run(self.drained_write())
        self.assertTrue(outcome['waited'], 'wait_idle came back while the callable was still inside SQL')
        self.assertEqual(outcome['order'], ['store:exit:put', 'wait:idle'],
                         f'wait_idle did not bracket the write: {outcome}')
        self.assertEqual(outcome['owner'].status, 200, outcome['owner'].text)
        self.assertEqual(outcome['rows'], ['verification.recorded'])

    async def drained_write(self) -> dict:
        holder = WriteLock(self.store.path).start(self)
        await until(holder.held.is_set, what='the fixture write lock to be held')
        journal = self.store.journal
        try:
            owner = asyncio.create_task(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
            await until(self.store.entered.is_set, what='the submitted write to enter Store')
            self.api.close()  # the lifespan's order: admission shut, then the drain it must not outrun
            drain = asyncio.create_task(self.api.wait_idle())
            await asyncio.sleep(POLL_SECONDS * 4)
            waited = not drain.done()
            holder.release.set()
            answered = await asyncio.wait_for(owner, timeout=SAFETY)
            await asyncio.wait_for(drain, timeout=SAFETY)
            journal.note('wait:idle')
            rows = [row['operation'] for row in self.store.records('audit', 100)
                    if row['operation'] == 'verification.recorded']
            return {'waited': waited, 'order': journal.only('store:exit:put', 'wait:idle'),
                    'owner': answered, 'rows': rows}
        finally:
            holder.release.set()

    def test_a_cancelled_drain_unwinds_only_after_the_write_is_over(self):
        outcome = asyncio.run(self.interrupted_drain())
        self.assertFalse(outcome['returned_early'],
                         'a cancelled wait_idle unwound while its callable was still inside SQL')
        self.assertTrue(outcome['cancelled'], 'a cancelled drain came back as a completed one')
        self.assertEqual(outcome['owner'].status, 200, outcome['owner'].text)

    async def interrupted_drain(self) -> dict:
        holder = WriteLock(self.store.path).start(self)
        await until(holder.held.is_set, what='the fixture write lock to be held')
        try:
            owner = asyncio.create_task(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))
            await until(self.store.entered.is_set, what='the submitted write to enter Store')
            self.api.close()
            drain = asyncio.create_task(self.api.wait_idle())
            await asyncio.sleep(POLL_SECONDS * 4)
            drain.cancel()
            # The write lock is still held here, so the callable provably cannot have left `Store`: this is
            # the deterministic half of "the drain did not treat its cancellation as the end of the write".
            await asyncio.sleep(POLL_SECONDS * 4)
            returned_early = drain.done()
            holder.release.set()
            cancelled = False
            try:
                await asyncio.wait_for(drain, timeout=SAFETY)
            except asyncio.CancelledError:
                cancelled = True
            answered = await asyncio.wait_for(owner, timeout=SAFETY)
            return {'returned_early': returned_early, 'cancelled': cancelled or drain.cancelled(),
                    'owner': answered}
        finally:
            holder.release.set()


class StorageFailureTests(Scenario, unittest.TestCase):
    """The ways a file disagrees with the build, and the one body either of them may produce."""

    def insert(self, rows: list[tuple]) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            connection.executemany('INSERT INTO verification_records VALUES (?,?,?,?,?,?,?,?)', rows)
            connection.commit()
        finally:
            connection.close()

    def drop_tables(self) -> None:
        connection = sqlite3.connect(self.store.path)
        try:
            connection.execute('DROP TABLE verification_records')
            connection.execute('DROP TABLE verification_bindings')
            connection.commit()
        finally:
            connection.close()

    def test_a_missing_verification_table_is_a_500_with_the_fixed_body_on_every_route(self):
        case = self.case
        self.drop_tables()
        logs = LogCollector()
        with logs.captured():
            replies = [self.drive(self.call('GET', BINDING, query=f"action_id={case['action_id']}".encode(),
                                           forbid_body=True)),
                       self.drive(self.call('GET', RECORDS,
                                           query=f"execution_id={case['execution_id']}".encode(),
                                           forbid_body=True)),
                       self.drive(self.call('GET', RECORD, query=f'verification_id={PIN}'.encode(),
                                           forbid_body=True)),
                       self.drive(self.call('POST', RECORDS, body=self.body(), actor=VERIFIER))]
        for reply in replies:
            self.assertEqual((reply.status, reply.body), (500, STORAGE), reply.text)
            self.assertNotIn(str(self.store.path), json.dumps(reply.body))
            self.assertNotIn('sqlite', json.dumps(reply.body))
        for record in logs.records:
            self.assertNotIn(str(self.store.path), record.getMessage(), record.getName())

    def test_a_stored_document_that_is_not_json_is_a_500_that_names_nothing(self):
        case = self.case
        corrupt = 'c' * 64
        self.insert([(corrupt, case['execution_id'], 'd' * 64, '{"' + SENTINEL, 'unknown',
                     'window-empty', READER.identity, utc_text(self.now))])
        logs = LogCollector()
        with logs.captured():
            reply = self.drive(self.call('GET', RECORD, query=f'verification_id={corrupt}'.encode(),
                                        forbid_body=True))
        self.assertEqual((reply.status, reply.body), (500, STORAGE), reply.text)
        self.assertNotIn(SENTINEL, json.dumps(reply.body))
        self.assertEqual([record.getMessage() for record in logs.records if SENTINEL in
                          record.getMessage()], [], 'a stored payload reached a log line')

    def test_an_over_cap_stored_history_is_a_500_on_a_read_and_a_409_on_a_write(self):
        """`RECORD_LIMIT` is one sentence about two faults, split by method and never by substring.

        The 65 rows are planted rather than earned: writing 64 real records is the storage layer's cost
        (pinned in `tests/test_verification_records.py`), while what this seam owes is that the same words
        mean "the file disagrees with its writer" to a reader and "this execution is full" to a submitter.
        """
        case = self.case
        self.insert([(f'{index:02}' + 'c' * 62, case['execution_id'], 'd' * 64, '{}', 'unknown',
                      'window-empty', READER.identity, utc_text(self.now)) for index in range(65)])
        listed = self.drive(self.call('GET', RECORDS, query=f"execution_id={case['execution_id']}".encode(),
                                     forbid_body=True))
        self.assertEqual((listed.status, listed.body), (500, STORAGE), listed.text)
        self.assertNotIn('64', json.dumps(listed.body))
        posted = self.drive(self.call('POST', RECORDS,
                                     body=self.body(window=self.window(seconds=WINDOW_SECONDS,
                                                                      ends_at=self.terminal
                                                                      + dt.timedelta(minutes=11))),
                                     actor=VERIFIER))
        self.assertEqual((posted.status, posted.body['error'], posted.body['detail']),
                         (409, 'conflict', RECORD_LIMIT), posted.text)

    def test_a_query_that_refuses_never_reaches_the_file(self):
        """Even a broken schema may not turn a bad identifier into a 500: the parser answers first."""
        self.drop_tables()
        reply = self.drive(self.call('GET', BINDING, query=b'action_id=nope', forbid_body=True))
        self.assertEqual((reply.status, reply.body),
                         (400, {'error': 'invalid_request', 'detail': module.BAD_IDENTIFIER_TEXT}),
                         reply.text)


class SourceHygieneTests(unittest.TestCase):
    """What the seam must not have quietly taken on: no credentials, no audit, no executor shortcuts."""

    def test_the_module_touches_no_credential_no_audit_and_no_environment_state(self):
        source = (ROOT / 'local_observe' / 'platform' / 'verification_api.py').read_text()
        for forbidden in ('os.environ', 'LO_', 'compare_digest', 'Bearer', 'authorization',
                          'stable_code(', 'from .api', 'REFUSAL_POST_ROUTES', 'record_refusal',
                          'run_in_executor', 'cancel_futures=True', 'threading.Thread(', 'to_thread',
                          'sqlite3.connect', 'SELECT ', "'reader'", "'producer'", "'proposer'",
                          "'human'", "'executor'"):
            self.assertNotIn(forbidden, source, f'the seam reached for {forbidden}')
        self.assertEqual(module.SUMMARY, 'summary')
        self.assertEqual(source.count('summary_only'), 1, 'the transport\'s word belongs to one branch')

    def test_the_owned_paths_include_the_bounded_candidate_read(self):
        self.assertEqual(sorted(module.ROUTES), sorted([BINDING, RECORDS, RECORD, module.CANDIDATES_ROUTE]))
        self.assertEqual(len(module.ROUTES), 4)
        self.assertEqual(sorted(module.READ_PARAMETERS.values()), ['action_id', 'execution_id',
                                                                  'verification_id'])


if __name__ == '__main__':
    unittest.main()

"""The paged audit reader: `GET /v1/audit` at the transport, and the legacy audit read that must not move.

`tests/test_audit_reader.py` proves the page itself at the `Store.audit_page` seam. This file proves the
surface the operator actually reaches, in-process against the real ASGI app (no socket, no server, no
uvicorn — the fixture style of `tests/test_api_errors.py` and `tests/test_refusal_audit.py`):

* **The gate.** `reader`, `human`, `proposer` and `executor` all get the same bytes for the same query;
  `summary` gets the 403 it gets on every other path, and `producer` gets the 400 the existing GET role
  gate gives it. A denial, a 401 or a parser refusal writes no audit row, and none of them opens the
  database at all — measured by counting `sqlite3.connect`, not by trusting an ordering comment.
* **The strict parser.** Exactly `limit`, `category`, `snapshot`, `before`. Unknown, duplicated, blank and
  case-changed fields, non-canonical or oversized integers (including `int()`'s pet tricks: `+5`, `007`,
  `1_0`, `' 5 '`, Arabic-Indic digits), an unpaired or inverted `snapshot`/`before`, a malformed percent
  escape, bytes that are not UTF-8, and a query string over 2048 bytes: all 400, all with one short fixed
  body, none of them echoing what was sent and none of them leaving a replacement character behind.
* **The response bytes.** Exactly `rows`/`snapshot`/`next_before`/`scanned`, canonical (sorted keys, no
  spaces, ASCII escapes), never over 65536 bytes, and `category=all` byte-identical to omitting the
  parameter. A normal row is the six stored columns, and for a row both routes can reach those six
  values are byte-identical to what `/v1/records/audit` sends — no `display`, no new field, no re-encoded
  `detail`.
* **Pagination over real authenticated calls**, including the card's headline: accepted lifecycle
  transitions, then 130 real refusals, then a traversal that returns every transition the legacy 100-row
  window can no longer see.
* **The legacy route**, pinned as the behaviour it already had: `{'rows': [...]}` only, newest first inside
  a 100-row window, its own tolerant `int()` limit rules, its `display` expansion, and no reaction at all
  to the new paging fields.

The assertions cover status, code, bounded size, fixedness and non-echo rather than exact new error prose.
Canonical numeric validation follows percent-decoding; `%31%30%30` is therefore a valid limit of 100.
"""
import asyncio
import datetime as dt
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import uuid
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from local_observe.inventory import index
from local_observe.inventory.validation import canonical, read_document, timestamp, utc_text
from local_observe.platform import detections, refusals
from local_observe.platform.api import create_app
from local_observe.platform.policy import action_policy
from local_observe.platform.presentation import records as present_records
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
AUDIT_PATH = '/v1/audit'
# Nothing about a read may be answered out of a request body, and a `receive()` that raises is how that
# is proved rather than inferred from a status code.
SENTINEL = 'never-reflected-in-an-answer'

DOCUMENTED_FIELDS = ('rows', 'snapshot', 'next_before', 'scanned')
AUDIT_COLUMNS = ('sequence', 'at', 'actor', 'operation', 'subject', 'detail')
PLACEHOLDER = 'row_exceeds_page_budget'
LIMIT_MAX = 100
SCAN_BUDGET = 500
PAGE_BUDGET_BYTES = 65536
QUERY_BUDGET_BYTES = 2048
INT64_MAX = 2 ** 63 - 1
MAX_QUERY_CASES_PER_DETAIL = 12
TRANSITIONS = frozenset(('action.proposed', 'action.approved', 'action.denied', 'action.expired',
                         'execution.claimed', 'execution.succeeded', 'execution.failed',
                         'execution.unknown'))

READER = {'identity': 'reader-1', 'role': 'reader', 'token': 'reader-token-for-tests-0000000000'}
PRODUCER = {'identity': 'test-detector', 'role': 'producer', 'token': 'producer-token-for-tests-00000000'}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'proposer-token-for-tests-00000000'}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'human-token-for-tests-000000000000'}
EXECUTOR = {'identity': 'runner-1', 'role': 'executor', 'token': 'executor-token-for-tests-00000'}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'summary-token-for-tests-000000000'}
CREDENTIALS = [READER, PRODUCER, PROPOSER, HUMAN, EXECUTOR, SUMMARY]
READING_ROLES = (READER, HUMAN, PROPOSER, EXECUTOR)


async def exchange(app, method: str, path: str, *, query: bytes = b'', credential: str | None = None,
                   headers: list | None = None, body: bytes = b'', forbid_body: bool = False):
    """One in-process ASGI exchange, answered with the raw bytes the client would actually receive."""
    output = []

    async def receive():
        if forbid_body:
            raise AssertionError('this route must answer without awaiting a body chunk')
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)

    if headers is None:
        headers = [] if credential is None else [(b'authorization', ('Bearer ' + credential).encode())]
    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers,
               'query_string': query}, receive, send)
    start = output[0]
    return (start['status'], {name.lower(): value for name, value in start.get('headers', [])},
            b''.join(message.get('body', b'') for message in output[1:]))


class SteppingClock:
    """A monotonic source that moves a second per read, so a 130-refusal flood is really 130 rows.

    The refusal audit's bucket holds 64 tokens and refills at one per second; the crowding this card must show
    needs more than a burst, and `Store`'s injected clock is the seam for that. Nothing sleeps here, and
    the clock is never the `now=` a lifecycle method takes.
    """

    def __init__(self) -> None:
        self.value = 0.0
        self._moves = threading.Lock()

    def __call__(self) -> float:
        with self._moves:
            current = self.value
            self.value += 1.0
            return current


class AuditApiFixture:
    """A real store, a real inventory index, a real app — and the HTTP helpers every assertion shares.

    Mixed into `TestCase` subclasses; it defines no tests. The app is built once per test because
    `create_app` snapshots the source tree, and every request in a test then runs over that one app and
    that one store, the way a serving process does.
    """

    def build(self) -> Store:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.clock = SteppingClock()
        self.store = Store(self.root / 'state.db', refusal_clock=self.clock)
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        self.absent = str(uuid.uuid4())
        self.app = create_app(self.store, CREDENTIALS, self.policy, index_path=self.index,
                              display_config={})
        return self.store

    # -------------------------------------------------------------------- HTTP helpers

    def fetch(self, query: bytes = b'', credential: str = READER['token'], path: str = AUDIT_PATH,
              method: str = 'GET', **kwargs):
        return asyncio.run(exchange(self.app, method, path, query=query, credential=credential,
                                    **kwargs))

    def audit(self, query: bytes = b'', credential: str = READER['token']) -> dict:
        """One `GET /v1/audit` that must succeed, answered as a decoded body after byte-level checks."""
        status, headers, raw = self.fetch(query, credential=credential)
        self.assertEqual(status, 200, raw[:200])
        self.assertEqual(headers.get(b'content-type'), b'application/json')
        self.assertEqual(headers.get(b'cache-control'), b'no-store',
                         'an audit page is not something a cache may answer later')
        self.assertLessEqual(len(raw), PAGE_BUDGET_BYTES, f'a response was {len(raw)} bytes')
        self.assertEqual(raw, canonical(json.loads(raw)).encode('utf-8'),
                         'the response is not canonical JSON bytes')
        return json.loads(raw)

    def post(self, path: str, body, credential: str) -> tuple[int, dict]:
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        status, _, payload = asyncio.run(exchange(self.app, 'POST', path, credential=credential,
                                                  body=raw))
        return status, json.loads(payload)

    # ------------------------------------------------------------- real lifecycle, over HTTP

    def live_event(self, tag: str) -> dict:
        """One valid firing event, stamped now, on a condition nobody else this test just opened.

        The condition is part of the key `intake` orders by, so two events on one condition inside the
        same second are the *same evaluation* and the second is refused as a conflicting watermark —
        which would be a fixture bug wearing a lifecycle costume. One tag per event, one incident per tag.
        """
        moment = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        window = {'start': utc_text(moment - dt.timedelta(minutes=1)), 'end': utc_text(moment)}
        return detections.event(PRODUCER['identity'], self.host, f'audit-page-{tag}', 'availability',
                                'firing', window,
                                {'sample_id': f'audit-page-api-{int(moment.timestamp())}'},
                                query_type='gatus-result')

    def http_lifecycle(self, retry_key: str) -> dict:
        """Take one action from event to succeeded outcome through authenticated POSTs, or fail loudly."""
        status, intake = self.post('/v1/events', self.live_event(retry_key), PRODUCER['token'])
        self.assertEqual(status, 200, intake)
        document = {'retry_key': retry_key, 'incident_id': intake['incident_id'], 'action': 'inspect',
                    'version': '1', 'targets': [self.host], 'parameters': {},
                    'evidence': [intake['event_id']],
                    'expires_at': utc_text(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1))}
        status, proposed = self.post('/v1/actions', document, PROPOSER['token'])
        self.assertEqual(status, 200, proposed)
        status, approved = self.post('/v1/actions/decision',
                                     {'action_id': proposed['action_id'], 'decision': 'approved'},
                                     HUMAN['token'])
        self.assertEqual(status, 200, approved)
        status, claim = self.post('/v1/actions/claim', {'action_id': proposed['action_id']},
                                  EXECUTOR['token'])
        self.assertEqual(status, 200, claim)
        status, outcome = self.post('/v1/executions/outcome',
                                    {'execution_id': claim['execution_id'], 'outcome': 'succeeded',
                                     'runner_token': claim['runner_token']}, EXECUTOR['token'])
        self.assertEqual(status, 200, outcome)
        return {'incident_id': intake['incident_id'], 'event_id': intake['event_id'],
                'action_id': proposed['action_id'], 'execution_id': claim['execution_id']}

    def refuse_through_http(self, count: int, credential: str = HUMAN['token']) -> None:
        """Provoke `count` real refusals through the transport, one durable row each."""
        written = self.store.refusal_audit_status()['written']
        for _ in range(count):
            status, payload = self.post('/v1/actions/decision',
                                        {'action_id': self.absent, 'decision': 'approved'}, credential)
            self.assertEqual((status, payload['error']), (400, 'conflict'))
        self.assertEqual(self.store.refusal_audit_status()['written'] - written, count,
                         'a transport refusal did not earn its own durable row')

    def all_transitions(self) -> None:
        """Reach all eight documented words: five over HTTP, three no credential can ask for."""
        self.http_lifecycle('audit-page-approved')
        status, intake = self.post('/v1/events', self.live_event('denied'), PRODUCER['token'])
        self.assertEqual(status, 200, intake)
        second_incident = intake['incident_id']
        document = {'retry_key': 'audit-page-denied', 'incident_id': second_incident, 'action': 'inspect',
                    'version': '1', 'targets': [self.host], 'parameters': {},
                    'evidence': [intake['event_id']],
                    'expires_at': utc_text(dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1))}
        status, proposed = self.post('/v1/actions', document, PROPOSER['token'])
        self.assertEqual(status, 200, proposed)
        status, denied = self.post('/v1/actions/decision',
                                   {'action_id': proposed['action_id'], 'decision': 'denied'},
                                   HUMAN['token'])
        self.assertEqual(status, 200, denied)
        # `action.expired` and `execution.unknown` are the platform's own clocks speaking: a decision
        # taken after the approval window, and a recovery pass over an execution nobody reported back on.
        expired_moment = NOW - dt.timedelta(hours=1)
        stale = self.store.propose_action({'retry_key': 'audit-page-stale', 'incident_id': second_incident,
                                           'action': 'inspect', 'version': '1', 'targets': [self.host],
                                           'parameters': {}, 'evidence': [intake['event_id']],
                                           'expires_at': utc_text(expired_moment + dt.timedelta(minutes=1))},
                                          Actor(PROPOSER['identity'], 'proposer'), self.policy,
                                          now=expired_moment)
        self.store.decide(stale['action_id'], 'approved', Actor(HUMAN['identity'], 'human'),
                          now=expired_moment + dt.timedelta(hours=2))
        lost = self.store.propose_action({'retry_key': 'audit-page-lost', 'incident_id': second_incident,
                                          'action': 'inspect', 'version': '1', 'targets': [self.host],
                                          'parameters': {}, 'evidence': [intake['event_id']],
                                          'expires_at': utc_text(dt.datetime.now(dt.timezone.utc)
                                                                 + dt.timedelta(hours=1))},
                                         Actor(PROPOSER['identity'], 'proposer'), self.policy)
        self.store.decide(lost['action_id'], 'approved', Actor(HUMAN['identity'], 'human'))
        claim = self.store.claim_action(lost['action_id'], Actor(EXECUTOR['identity'], 'executor'),
                                        self.policy)
        self.assertEqual(self.store.recover_executions(), 1)
        self.assertEqual(self.store.execution_outcome(
            claim['execution_id'], 'failed', Actor(EXECUTOR['identity'], 'executor'),
            claim['runner_token'])['status'], 'failed')
        operations = {row['operation'] for row in self.raw_audit()}
        self.assertTrue(TRANSITIONS <= operations, f'the fixture reached {operations & TRANSITIONS}')

    # ------------------------------------------------------------------ planted history

    def filler(self, count, *, operation='filler.page', size=0, actor='operator'):
        detail = {'pad': 'p' * size} if size else None
        return [(NOW, actor, operation, 'unbound', detail) for _ in range(count)]

    def plant(self, rows) -> list[int]:
        """Append history the lifecycle cannot produce, through `Store.audit` in one transaction."""
        first = self.max_sequence() + 1
        with self.store.transaction() as connection:
            for at, actor, operation, subject, detail in rows:
                Store.audit(connection, at, actor, operation, subject, detail)
        return list(range(first, first + len(rows)))

    def readonly(self) -> sqlite3.Connection:
        return sqlite3.connect(self.store.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)

    def raw_audit(self) -> list[dict]:
        with closing(self.readonly()) as db:
            return [dict(zip(AUDIT_COLUMNS, row)) for row in db.execute(
                'SELECT sequence, at, actor, operation, subject, detail FROM audit ORDER BY sequence')]

    def max_sequence(self) -> int:
        with closing(self.readonly()) as db:
            return db.execute('SELECT COALESCE(MAX(sequence), 0) FROM audit').fetchone()[0]

    def rendered_bytes(self, row: Mapping) -> int:
        return len(canonical({name: row[name] for name in AUDIT_COLUMNS}).encode())

    def to_rollback_journal(self) -> str:
        """Put the file in its rollback journal, so a write transaction and a read are provably different."""
        with closing(sqlite3.connect(self.store.path, timeout=10)) as db:
            return db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]

    # ------------------------------------------------------------------ paging over HTTP

    def check_page(self, body: dict, *, limit: int, before: int | None = None) -> list[int]:
        self.assertEqual(set(body), set(DOCUMENTED_FIELDS),
                         'the response gained, lost or renamed a field')
        sequences = []
        for row in body['rows']:
            self.assertIsInstance(row, Mapping)
            keys = tuple(sorted(row))
            if keys == ('omitted', 'sequence'):
                self.assertEqual(row['omitted'], PLACEHOLDER)
            else:
                self.assertEqual(keys, tuple(sorted(AUDIT_COLUMNS)),
                                 f'a row carries {keys}, not the six stored audit columns')
            sequences.append(row['sequence'])
            self.assertLessEqual(sequences[-1], body['snapshot'])
        if before is not None:
            self.assertTrue(all(sequence < before for sequence in sequences))
        self.assertEqual(sequences, sorted(sequences, reverse=True))
        self.assertLessEqual(len(sequences), limit)
        self.assertLessEqual(body['scanned'], SCAN_BUDGET)
        cursor = body['next_before']
        if cursor is not None:
            self.assertGreaterEqual(cursor, 0)
            self.assertLess(cursor, before if before is not None else body['snapshot'] + 1)
            if sequences:
                self.assertLessEqual(cursor, min(sequences))
        return sequences

    def traverse(self, *, limit: int = LIMIT_MAX, category: str = 'all', credential: str = READER['token'],
                 max_pages: int = 300, between=None) -> list[dict]:
        """Page one snapshot to its end through authenticated calls, asserting every page on the way."""
        pages: list[dict] = []
        query = f'limit={limit}&category={category}'.encode()
        before: int | None = None
        while True:
            body = self.audit(query, credential=credential)
            self.check_page(body, limit=limit, before=before)
            if pages:
                self.assertEqual(body['snapshot'], pages[0]['snapshot'], 'the snapshot moved mid-traversal')
            pages.append(body)
            if between is not None:
                between(pages)
            cursor = body['next_before']
            self.assertLess(len(pages), max_pages, f'the cursor never ended after {max_pages} pages')
            if cursor is None:
                return pages
            query = (f'limit={limit}&category={category}&snapshot={body["snapshot"]}'
                     f'&before={cursor}').encode()
            before = cursor

    def assert_complete(self, pages: list[dict], expected: list[int]) -> list[dict]:
        """Assert the pages delivered exactly `expected`, once each, newest first; return the rows."""
        rows = [row for page in pages for row in page['rows']]
        sequences = [row['sequence'] for row in rows]
        self.assertEqual(len(sequences), len(set(sequences)), 'a position arrived on two pages')
        self.assertEqual(sequences, sorted(sequences, reverse=True), 'the traversal is not newest-first')
        self.assertEqual(sequences, sorted(expected, reverse=True),
                         'the traversal duplicated or lost a committed position')
        return rows


class AuditApiAccessTests(unittest.TestCase, AuditApiFixture):
    """Who may read the page, and what the answers that are not a page still owe.

    The contract adds a route, not a permission: the role gate is the one every GET here already runs,
    so `reader`, `human`, `proposer` and `executor` must receive byte-identical answers for one query,
    and the two roles the gate turns away must receive the status and body they already received on every
    other path. A new surface is also a new way to make a stranger into a database writer, so every
    refusal here is checked for the row it did **not** write.
    """

    def setUp(self):
        self.build()
        self.sequences = self.plant(self.filler(4))

    def test_the_four_roles_the_gate_admits_receive_the_same_bytes_for_the_same_query(self):
        reference = None
        for credential in READING_ROLES:
            with self.subTest(role=credential['role']):
                status, headers, raw = self.fetch(b'limit=3', credential=credential['token'])
                self.assertEqual(status, 200)
                self.assertEqual(headers.get(b'content-type'), b'application/json')
                if reference is None:
                    reference = raw
                    continue
                self.assertEqual(raw, reference, 'a read-only page came out differently per role')
        body = json.loads(reference)
        self.assertEqual([row['sequence'] for row in body['rows']], [4, 3, 2])
        self.assertEqual(body['snapshot'], 4)

    def test_summary_and_producer_receive_the_gate_this_surface_already_had(self):
        """403 for `summary`, 400 `not_authorised` for `producer`: unchanged, un-narrated, unwriteable."""
        refused = asyncio.run(exchange(self.app, 'GET', AUDIT_PATH, credential=SUMMARY['token']))
        self.assertEqual((refused[0], json.loads(refused[2])), (403, {'error': 'summary_only'}))
        refused = asyncio.run(exchange(self.app, 'GET', AUDIT_PATH, credential=PRODUCER['token']))
        self.assertEqual((refused[0], json.loads(refused[2])),
                         (400, {'error': 'not_authorised',
                                'detail': 'Actor is not authorised for this operation'}))
        self.assertEqual(len(self.raw_audit()), 4, 'a role denial on a read route grew the audit table')
        self.assertEqual(self.store.refusal_audit_status()['written'], 0,
                         'a role denial on a read route was audited as if it were a write attempt')

    def test_no_credential_or_two_of_them_is_a_reader(self):
        cases = (('no authorization header', []),
                 ('empty bearer', [(b'authorization', b'Bearer ')]),
                 ('unknown token', [(b'authorization', b'Bearer ' + b'x' * 32)]),
                 ('two authorization values', [(b'authorization', ('Bearer ' + READER['token']).encode()),
                                               (b'authorization', ('Bearer ' + HUMAN['token']).encode())]),
                 ('wrong scheme', [(b'authorization', ('Token ' + READER['token']).encode())]))
        for name, headers in cases:
            with self.subTest(case=name):
                status, _, raw = asyncio.run(exchange(self.app, 'GET', AUDIT_PATH, headers=headers,
                                                      query=b'limit=1'))
                self.assertEqual(status, 401, raw[:200])
                self.assertEqual(json.loads(raw), {'error': 'authentication_required'})
        self.assertEqual(len(self.raw_audit()), 4, 'an unauthenticated read wrote a row')

    def test_the_route_answers_without_reading_a_body(self):
        """`GET /v1/audit` has no body: not parsed, not measured, not awaited.

        The tripwire is a `receive()` that raises, so a handler that reached for a chunk would surface as
        a 500 rather than as a passing test, and it runs on the valid query, the invalid query and both
        role denials — the three answers this route can give without one.
        """
        for query, expected in ((b'', 200), (b'limit=0', 400)):
            with self.subTest(query=query):
                status, _, raw = asyncio.run(exchange(self.app, 'GET', AUDIT_PATH,
                                                      credential=READER['token'], query=query,
                                                      forbid_body=True))
                self.assertEqual(status, expected, raw[:200])
        for credential, expected in ((SUMMARY['token'], 403), (PRODUCER['token'], 400)):
            with self.subTest(credential='refused role'):
                status, _, raw = asyncio.run(exchange(self.app, 'GET', AUDIT_PATH, credential=credential,
                                                      query=b'limit=1', forbid_body=True))
                self.assertEqual(status, expected, raw[:200])

    def test_the_audit_route_is_a_read_so_other_verbs_get_the_answers_the_surface_already_gave(self):
        """`PUT`/`DELETE` are the 405 every path here answers, and a `POST` is not a way to read.

        Which of the transport's two non-read answers a `POST` earns (the 404 of a route that does not
        serve it, or a 405 if a later review decides this path is method-known) is not contract text, so
        the assertion is the part that is: no 2xx, no row, no crash.
        """
        for method in ('PUT', 'DELETE', 'PATCH'):
            with self.subTest(method=method):
                status, _, raw = asyncio.run(exchange(self.app, method, AUDIT_PATH,
                                                      credential=READER['token'], body=b'{}'))
                self.assertEqual(status, 405, raw[:200])
                self.assertEqual(json.loads(raw), {'error': 'method_not_allowed'})
        status, _, raw = asyncio.run(exchange(self.app, 'POST', AUDIT_PATH, credential=READER['token'],
                                              body=json.dumps({'limit': 1}).encode()))
        self.assertIn(status, (404, 405), raw[:200])
        self.assertNotIn(status, (200, 201, 204))
        self.assertEqual(len(self.raw_audit()), 4, 'a verb that cannot read the page wrote to it')


# (name, query bytes, the byte string that must not come back out)
INVALID_QUERIES = (
    ('unknown field', f'category=all&limit=5&{SENTINEL}=1'.encode(), SENTINEL.encode()),
    ('field name with a case change', b'LIMIT=5&category=all', b'LIMIT'),
    ('another name spelled wrong', b'Category=all', b'Category'),
    ('duplicate limit', b'limit=5&limit=5', b''),
    ('duplicate category', b'category=all&category=action-transitions', b''),
    ('duplicate snapshot pair', b'snapshot=1&before=1&snapshot=1&before=1', b''),
    ('limit with no value', b'limit=', b''),
    ('category with no value', b'category=', b''),
    ('both positions blank', b'snapshot=&before=', b''),
    ('unknown field with no value', f'{SENTINEL}='.encode(), SENTINEL.encode()),
    ('limit above the maximum', b'limit=101', b'101'),
    ('limit at zero', b'limit=0', b''),
    ('limit negative', b'limit=-1', b'-1'),
    ('limit with a plus sign', b'limit=%2B5', b''),
    ('limit with a leading zero', b'limit=007', b'007'),
    ('limit with a digit separator', b'limit=1_0', b'1_0'),
    ('limit with surrounding space', b'limit=%205%20', b''),
    ('limit with a trailing semicolon clause', b'limit=5;category=all', b'5;category'),
    ('limit as a decimal', b'limit=5.0', b'5.0'),
    ('limit as a word', b'limit=five', b'five'),
    ('limit as arabic-indic digits', 'limit=\u0661\u0660'.encode(), 'limit=\u0661\u0660'.encode()),
    ('limit far beyond any integer', b'limit=' + b'9' * 40, b''),
    ('unknown category', b'category=refusals', b'refusals'),
    ('category in the wrong case', b'category=ALL', b'ALL'),
    ('category with an underscore', b'category=action_transitions', b'action_transitions'),
    ('category with a trailing space', b'category=action-transitions%20', b''),
    ('category that is only a prefix', b'category=action', b''),
    ('snapshot with no before', b'snapshot=4', b''),
    ('before with no snapshot', b'before=4', b''),
    ('before above snapshot', b'snapshot=1&before=2', b''),
    ('negative snapshot', b'snapshot=-1&before=0', b'-1'),
    ('negative before', b'snapshot=0&before=-1', b'-1'),
    ('snapshot past signed 63 bits', f'snapshot={INT64_MAX + 1}&before=1'.encode(), b''),
    ('before past signed 63 bits', f'snapshot={INT64_MAX}&before={INT64_MAX + 1}'.encode(), b''),
    ('position with a leading zero', b'snapshot=1&before=01', b'01'),
    ('position with a plus sign', b'snapshot=1&before=%2B1', b''),
    ('position as a word', b'snapshot=1&before=four', b'four'),
    ('malformed percent escape', b'limit=%', b''),
    ('percent escape that is not hex', b'limit=%zz', b'%zz'),
    ('percent escape cut short', b'limit=%4', b'%4'),
    ('percent escape that decodes to invalid utf-8', b'limit=%C0%80', b''),
    ('raw byte that is not utf-8 in a value', b'limit=\xff', b''),
    ('raw byte that is not utf-8 in a name', b'\xff=1', b''),
    ('truncated multi-byte character', 'category=\u00e9'.encode()[:-1], b''),
    ('query longer than the budget', b'limit=100&' + SENTINEL.encode() + b'=' + b'x' * QUERY_BUDGET_BYTES,
     SENTINEL.encode()),
    ('long position inside a long query', b'snapshot=1&before=' + b'9' * QUERY_BUDGET_BYTES, b''),
)


class AuditApiQueryTests(unittest.TestCase, AuditApiFixture):
    """The strict parser, at the edge, with the database provably asleep.

    Two of these cases are deliberately *both* too long and malformed (the last two): the contract sets a
    2048-byte ceiling so that no parser has to reason about an unbounded input, and what is proved here is
    the observable part of that ceiling — one short fixed 400, no connection, no row, nothing echoed.
    """

    def setUp(self):
        self.build()
        self.sequences = self.plant(self.filler(6))

    def assert_refused(self, query: bytes, offender: bytes = b'') -> dict:
        rows_before = len(self.raw_audit())
        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            status, _, raw = self.fetch(query)
        self.assertEqual(status, 400, f'{query!r} answered {status}: {raw[:200]!r}')
        body = json.loads(raw)
        self.assertEqual(set(body), {'error', 'detail'}, 'an error body grew a field')
        self.assertEqual(body['error'], 'invalid_request', f'{query!r} blamed the wrong side')
        self.assertIsInstance(body['detail'], str)
        self.assertLess(len(raw), 512, f'a refusal body was {len(raw)} bytes')
        self.assertLessEqual(len(body['detail']), 200)
        self.assertNotIn(SENTINEL.encode(), raw, 'the refusal echoed the request')
        self.assertNotIn(b'\xef\xbf\xbd', raw, 'a replacement character outlived a query that had one')
        if offender:
            self.assertNotIn(offender, raw, f'{query!r} was answered with its own text')
        self.assertEqual(connect.call_count, 0, f'{query!r} opened the database to say no')
        self.assertEqual(len(self.raw_audit()), rows_before, f'{query!r} wrote to the audit table')
        return body

    def test_the_documented_four_fields_are_the_only_ones_this_route_knows(self):
        for name, query, offender in INVALID_QUERIES:
            with self.subTest(case=name):
                self.assert_refused(query, offender)

    def test_the_valid_spellings_of_the_same_four_fields_are_accepted(self):
        for query in (b'', b'limit=1', b'limit=100', b'limit=%31%30%30', b'category=all', b'category=action-transitions',
                      b'limit=7&category=action-transitions', b'snapshot=6&before=6',
                      f'snapshot={INT64_MAX}&before={INT64_MAX}'.encode(), b'snapshot=6&before=0'):
            with self.subTest(query=query):
                body = self.audit(query)
                self.check_page(body, limit=100)

    def test_a_field_with_no_equals_sign_is_refused(self):
        """The explicit paging route rejects blank/valueless fields before database IO."""
        for query in (b'limit', b'category', b'?=5', b'&&', b'&'):
            with self.subTest(query=query):
                rows_before = len(self.raw_audit())
                status, _, raw = self.fetch(query)
                self.assertEqual(status, 400, raw[:200])
                self.assertEqual(len(self.raw_audit()), rows_before)

    def test_a_refusal_names_no_more_than_it_has_to(self):
        """Fixed text, not `int()`'s complaint or the decoder's: one small set of sentences.

        Four-odd dozen shapes of bad input must not produce four-odd dozen answers, because every distinct
        sentence is one more place a value can leak from. The sentences themselves are not published as
        contract text, so what is pinned is their number, their size, and the fact that the same shape of
        mistake always gets the same one.
        """
        details = set()
        for _name, query, offender in INVALID_QUERIES:
            details.add(self.assert_refused(query, offender)['detail'])
        self.assertLessEqual(len(details), MAX_QUERY_CASES_PER_DETAIL,
                             f'the parser invented {len(details)} distinct refusals for one gate')
        numeric = {query: self.assert_refused(query)['detail']
                   for query in (b'limit=0', b'limit=007', b'limit=1_0', b'limit=%2B5')}
        self.assertEqual(len(set(numeric.values())), 1,
                         f'non-canonical integers were explained several different ways: {numeric}')

    def test_a_query_the_parser_refused_is_not_a_refusal_the_platform_records(self):
        """No `action.refused` row for a bad query string, and no `GET /v1/audit`-shaped operation.

        The refusal audit drew the line at the action lifecycle, and the parser has always sat below it: a client
        that types `?limit=banana` a thousand times may not grow the audit table by a thousand rows, which
        is the same flood the write budget exists to bound, arriving through a new door.
        """
        for query in (b'limit=banana', b'category=nope', b'before=1', b'limit=%C0%80',
                      b'x' * 4000, f'limit=1&{SENTINEL}=2'.encode()):
            with self.subTest(query=query):
                self.assert_refused(query)
        self.assertEqual([row['operation'] for row in self.raw_audit()],
                         ['filler.page'] * 6, 'a refused query wrote an audit row')
        self.assertEqual(self.store.refusal_audit_status()['written'], 0)
        self.assertEqual(self.store.refusal_audit_status()['unauditable'], 0)


class AuditApiResponseTests(unittest.TestCase, AuditApiFixture):
    """The bytes of one page: four fields, canonical, inside 64 KiB, and no new meaning in a row.

    The row-level claim is the sharpest thing here: for a row both routes can reach, the six values this
    route sends must be *the same bytes* the legacy reader sends, so "the same six stored audit columns"
    is not a vibe about two similar queries. `display` is asserted absent because the legacy route adds
    one to every row it sends, and a new reader that quietly reused the presentation layer would put
    inventory labels — and another database read — behind an audit page.
    """

    def setUp(self):
        self.build()

    def test_an_empty_database_answers_zero_and_no_cursor(self):
        body = self.audit()
        self.assertEqual(body, {'rows': [], 'snapshot': 0, 'next_before': None, 'scanned': 0})
        self.assertEqual(self.fetch(b'')[2], canonical(body).encode(),
                         'the empty page is not the canonical bytes the contract names')

    def test_the_default_query_and_an_explicit_all_query_are_the_same_bytes(self):
        self.plant(self.filler(3))
        implicit = self.fetch(b'limit=2')[2]
        self.assertEqual(implicit, self.fetch(b'limit=2&category=all')[2])
        self.assertNotEqual(implicit, self.fetch(b'limit=2&category=action-transitions')[2])

    def test_a_normal_row_is_the_six_stored_columns_exactly_as_the_legacy_route_sends_them(self):
        hostile_actor = 'uni\u00f1code \U0001F980\x01'
        self.plant(self.filler(2))
        hostile = self.plant([(NOW, hostile_actor, 'filler.unicode', 'sub\tject\n\u2028',
                              {'note': 'a"b\\c\nd\u00e9'})])[0]
        self.plant(self.filler(1))
        body = self.audit(b'limit=10')
        self.assertEqual([row['sequence'] for row in body['rows']], [4, hostile, 2, 1])
        for row in body['rows']:
            self.assertEqual(set(row), set(AUDIT_COLUMNS))
            self.assertNotIn('display', row, 'the new route grew the legacy row a display field')
            self.assertTrue(all(isinstance(value, str) or name == 'sequence'
                                for name, value in row.items()),
                            'a stored column came back structured rather than as the text it stores')
        legacy = json.loads(self.fetch(b'limit=10', path='/v1/records/audit')[2])
        self.assertTrue(all('display' in row for row in legacy['rows']))
        by_sequence = {row['sequence']: row for row in legacy['rows']}
        for row in body['rows']:
            with self.subTest(sequence=row['sequence']):
                self.assertEqual({name: row[name] for name in AUDIT_COLUMNS},
                                 {name: by_sequence[row['sequence']][name] for name in AUDIT_COLUMNS})
        delivered = {row['sequence']: row for row in body['rows']}
        self.assertEqual(delivered[hostile]['actor'], hostile_actor,
                         'a hostile-but-legal actor did not survive escaping intact')
        self.assertEqual(json.loads(delivered[hostile]['detail']), {'note': 'a"b\\c\nd\u00e9'})
        raw = self.fetch(b'limit=10')[2]
        self.assertTrue(all(byte < 0x80 for byte in raw), 'a non-ASCII byte reached a canonical response')

    def test_a_continuation_echoes_the_snapshot_it_was_handed_not_a_fresh_capture(self):
        self.plant(self.filler(5))
        first = self.audit(b'limit=2')
        self.assertEqual([row['sequence'] for row in first['rows']], [5, 4])
        self.assertEqual(first['next_before'], 4, 'the cursor stepped over row 3 or promised row 4 again')
        second = self.audit(f'limit=2&snapshot={first["snapshot"]}&before={first["next_before"]}'.encode())
        self.assertEqual([row['sequence'] for row in second['rows']], [3, 2])
        self.assertEqual(second['snapshot'], 5, 'a continuation re-captured the snapshot')
        self.plant(self.filler(1))
        third = self.audit(f'limit=5&snapshot=5&before={second["next_before"]}'.encode())
        self.assertEqual([row['sequence'] for row in third['rows']], [1])
        self.assertEqual(third['snapshot'], 5)
        self.assertIsNone(third['next_before'])
        fresh = self.audit(b'limit=1')
        self.assertEqual(fresh['snapshot'], 6, 'a new traversal kept a stale snapshot')

    def test_an_oversized_row_is_a_placeholder_in_the_response_bytes(self):
        blob = self.plant([(NOW, 'operator', 'filler.blob', 'unbound',
                            {'blob': SENTINEL + 'z' * 60000})])[0]
        raw = self.fetch(b'limit=10')[2]
        body = json.loads(raw)
        self.assertEqual(set(body), set(DOCUMENTED_FIELDS))
        self.assertEqual(body['rows'], [{'sequence': blob, 'omitted': PLACEHOLDER}])
        self.assertIn(b'"omitted":"row_exceeds_page_budget"', raw)
        self.assertIn(f'"sequence":{blob}'.encode(), raw)
        self.assertNotIn(SENTINEL.encode(), raw, 'the placeholder carried the row it refused to render')
        self.assertEqual(body['scanned'], 1)


class AuditApiTraversalTests(unittest.TestCase, AuditApiFixture):
    """Whole traversals, paged over authenticated calls, with a writer still writing.

    Each test builds the history it needs rather than sharing one fixture shape, because the interesting
    cases disagree about what is above and below the snapshot: a flood that buries the transitions, a
    range that holds no matches at all, and an append that lands between two pages.
    """

    REFUSALS = 130

    def setUp(self):
        self.build()

    def test_accepted_transitions_survive_a_refusal_flood_through_authenticated_pages(self):
        self.all_transitions()
        self.refuse_through_http(self.REFUSALS)
        raw = self.raw_audit()
        self.assertEqual(len([row for row in raw if row['operation'] == refusals.OPERATION]),
                         self.REFUSALS)
        self.assertGreater(self.REFUSALS, refusals.CAPACITY,
                           'the fixture stayed inside one token burst, so it tested the wrong thing')
        legacy = json.loads(self.fetch(b'limit=100', path='/v1/records/audit')[2])
        self.assertEqual({row['operation'] for row in legacy['rows']}, {refusals.OPERATION})
        oldest_visible = min(row['sequence'] for row in legacy['rows'])
        transitions = [row for row in raw if row['operation'] in TRANSITIONS]
        self.assertTrue(transitions)
        for row in transitions:
            self.assertLess(row['sequence'], oldest_visible,
                            f"{row['operation']} is still in the legacy window, so this proved less")
        delivered = {row['sequence']: row for row in
                     self.assert_complete(self.traverse(limit=LIMIT_MAX),
                                          [row['sequence'] for row in raw])}
        self.assertEqual(set(delivered), {row['sequence'] for row in raw},
                         'the traversal did not cover every committed position')
        for row in transitions:
            with self.subTest(operation=row['operation']):
                self.assertEqual({name: delivered[row['sequence']][name] for name in AUDIT_COLUMNS},
                                 {name: row[name] for name in AUDIT_COLUMNS},
                                 'an accepted transition came back altered or as a placeholder')
        self.assertTrue(TRANSITIONS <= {row['operation'] for row in delivered.values()
                                        if 'operation' in row})

    def test_the_filtered_traversal_returns_the_eight_words_and_nothing_else(self):
        self.all_transitions()
        self.plant(self.filler(700))
        expected = [row['sequence'] for row in self.raw_audit() if row['operation'] in TRANSITIONS]
        pages = self.traverse(limit=2, category='action-transitions')
        rows = self.assert_complete(pages, expected)
        self.assertEqual({row['operation'] for row in rows}, set(TRANSITIONS))
        self.assertNotIn(refusals.OPERATION, {row['operation'] for row in rows})
        self.assertTrue(any(page['rows'] == [] and page['next_before'] is not None for page in pages),
                        'no page in this traversal was an empty-but-continue page')
        self.assertTrue(all(page['scanned'] <= SCAN_BUDGET for page in pages))

    def test_an_empty_page_with_a_cursor_is_not_the_end_and_the_last_empty_page_is(self):
        self.plant(self.filler(620))
        pages = self.traverse(category='action-transitions')
        self.assertEqual([page['rows'] for page in pages], [[], []],
                         'a filtered traversal over a history with no matches found something')
        self.assertEqual(pages[0]['scanned'], SCAN_BUDGET)
        self.assertIsNotNone(pages[0]['next_before'], 'an exhausted scan budget claimed the end')
        self.assertIsNone(pages[1]['next_before'], 'the end was never said')
        self.assertEqual(pages[1]['snapshot'], pages[0]['snapshot'])

    def test_no_page_breaks_the_limit_the_scan_budget_or_the_byte_budget(self):
        self.plant(self.filler(140, size=700))
        pages = self.traverse(limit=LIMIT_MAX)
        self.assertLess(len(pages[0]['rows']), LIMIT_MAX,
                        'the byte budget never cut a page, so this test proved nothing')
        text = canonical([[dict(row) for row in page['rows']] for page in pages])
        self.assertNotIn(PLACEHOLDER, text,
                         'a row that merely found the page full was replaced by a placeholder')
        rows = self.assert_complete(pages, list(range(1, 141)))
        self.assertEqual({tuple(sorted(row)) for row in rows}, {tuple(sorted(AUDIT_COLUMNS))})
        for earlier, later in zip(pages, pages[1:]):
            self.assertEqual(later['rows'][0]['sequence'], earlier['rows'][-1]['sequence'] - 1,
                             'the next page did not resume on the deferred row')

    def test_an_append_between_pages_cannot_duplicate_or_displace_the_traversal(self):
        self.all_transitions()
        started = threading.Event()
        appended: list[int] = []

        def write_while_reading():
            started.wait(timeout=30)
            appended.extend(self.plant(self.filler(6, operation='filler.concurrent')))

        thread = threading.Thread(target=write_while_reading)
        thread.start()
        self.addCleanup(thread.join)
        first = self.audit(b'limit=10')
        started.set()
        thread.join(timeout=30)
        snapshot = first['snapshot']
        pages = [first]
        cursor = first['next_before']
        while cursor is not None:
            body = self.audit(f'limit=10&snapshot={snapshot}&before={cursor}'.encode())
            self.check_page(body, limit=10, before=cursor)
            self.assertEqual(body['snapshot'], snapshot, 'a continuation re-captured the snapshot')
            pages.append(body)
            cursor = body['next_before']
            self.assertLess(len(pages), 300, 'the cursor never ended')
        self.assert_complete(pages, [row['sequence'] for row in self.raw_audit()
                                     if row['sequence'] <= snapshot])
        self.assertTrue(appended, 'the concurrent writer wrote nothing, so this proved less than it claims')
        self.assertGreater(self.audit(b'limit=1')['snapshot'], snapshot,
                           'a brand-new traversal did not see the committed append')

    def test_a_page_answers_while_a_writer_holds_the_write_lock_that_would_refuse_another_writer(self):
        """Real SQLite, real lock, real HTTP: a page is not asking for the write side of the file.

        The file is put in its rollback journal first, where a `BEGIN IMMEDIATE` and a deferred read are
        demonstrably different things: with the lock held by the writer below, a second writer is refused
        by SQLite itself while the page still answers. The route is proved here; `Store`'s half of the same
        property is in `tests/test_audit_reader.py`.
        """
        self.plant(self.filler(4))
        self.assertEqual(self.to_rollback_journal(), 'delete')
        writer = sqlite3.connect(self.store.path, timeout=10)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        with closing(sqlite3.connect(self.store.path, timeout=0.05)) as blocked:
            with self.assertRaises(sqlite3.OperationalError) as caught:
                blocked.execute('BEGIN IMMEDIATE')
        self.assertIn('locked', str(caught.exception), 'no write lock was actually held')
        status, _, raw = self.fetch(b'limit=2')
        self.assertEqual(status, 200, raw[:200])
        body = json.loads(raw)
        self.assertEqual([row['sequence'] for row in body['rows']], [4, 3])
        self.assertEqual(body['snapshot'], 4)
        writer.execute('COMMIT')
        writer.close()
        self.plant(self.filler(1))
        fresh = json.loads(self.fetch(b'limit=1')[2])
        self.assertEqual(fresh['snapshot'], 5, 'the next request kept a connection from the last one')


class AuditApiLegacyTests(unittest.TestCase, AuditApiFixture):
    """`GET /v1/records/audit` did not move: same window, same `display`, same limit rules, same bytes.

    This is the half of the card that is easy to get wrong by accident — a shared row builder, a new query
    field read on the wrong branch, a `limit` tightened "for consistency". Two of these assertions are
    therefore byte-equality against the composition the transport already used (`Store.records` +
    `presentation.records` + `canonical`), and several pin the *tolerant* legacy `int()` readings —
    `+5`, `1_0`, `' 5 '`, a duplicated `limit` — precisely because the new route refuses them and the old
    one must go on accepting them.
    """

    def setUp(self):
        self.build()
        self.sequences = self.plant(self.filler(120, size=5))

    def legacy(self, query: bytes = b''):
        return self.fetch(query, path='/v1/records/audit')

    def test_the_legacy_route_still_sends_only_its_own_window_rows_and_display(self):
        status, _, raw = self.legacy()
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(set(body), {'rows'}, 'the legacy response gained a paging field')
        self.assertEqual([row['sequence'] for row in body['rows']], list(range(120, 20, -1)))
        for row in body['rows']:
            self.assertEqual(set(row), set(AUDIT_COLUMNS) | {'display'})
        expected = canonical({'rows': present_records(self.store, 'audit',
                                                     self.store.records('audit', LIMIT_MAX),
                                                     self.index, {})})
        self.assertEqual(raw, expected.encode(), 'the legacy response bytes are not what they were')

    def test_the_legacy_limit_answers_are_unchanged(self):
        accepted = ((b'limit=5', 5), (b'limit=1', 1), (b'limit=100', 100), (b'limit=1_0', 10),
                    (b'limit=%2B5', 5), (b'limit=%205%20', 5), (b'limit=5&limit=6', 5),
                    ('limit=\u0661\u0660'.encode(), 10), (b'limit=', 100))
        for query, rows in accepted:
            with self.subTest(query=query):
                status, _, raw = self.legacy(query)
                self.assertEqual(status, 200, raw[:200])
                self.assertEqual(len(json.loads(raw)['rows']), rows)
        refused = {b'limit=0': 'Invalid bounded record query', b'limit=101': 'Invalid bounded record query',
                   b'limit=-1': 'Invalid bounded record query',
                   b'limit=abc': 'limit must be an integer',
                   b'limit=5.0': 'limit must be an integer'}
        for query, detail in refused.items():
            with self.subTest(query=query):
                status, _, raw = self.legacy(query)
                self.assertEqual((status, json.loads(raw)),
                                 (400, {'error': 'invalid_request', 'detail': detail}))

    def test_the_new_paging_fields_do_not_reach_the_legacy_route(self):
        plain = self.legacy(b'limit=3')
        for extra in (b'&category=action-transitions', b'&category=nope', b'&snapshot=1&before=2',
                      b'&before=' + b'9' * 40, b'&snapshot=abc', b'&limit=x', b'&snapshot=&before=',
                      b'&' + SENTINEL.encode() + b'=1'):
            with self.subTest(extra=extra):
                status, _, raw = self.legacy(b'limit=3' + extra)
                self.assertEqual((status, raw), (plain[0], plain[2]),
                                 'a paging field changed what the legacy route answers')
        self.assertNotIn(SENTINEL.encode(), plain[2])

    def test_the_legacy_route_keeps_the_authorization_and_table_answers_it_already_gave(self):
        status, _, raw = asyncio.run(exchange(self.app, 'GET', '/v1/records/audit',
                                              credential=SUMMARY['token']))
        self.assertEqual((status, json.loads(raw)), (403, {'error': 'summary_only'}))
        status, _, raw = asyncio.run(exchange(self.app, 'GET', '/v1/records/audit',
                                              credential=PRODUCER['token']))
        self.assertEqual((status, json.loads(raw)['error']), (400, 'not_authorised'))
        status, _, raw = self.fetch(b'', path='/v1/records/nothing')
        self.assertEqual((status, json.loads(raw)),
                         (400, {'error': 'invalid_request', 'detail': 'Invalid bounded record query'}))
        status, _, raw = self.fetch(b'', path='/v1/records/executions')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {'rows': []})
        self.assertEqual(len(self.raw_audit()), 120, 'a legacy read wrote audit rows')


if __name__ == '__main__':
    unittest.main()

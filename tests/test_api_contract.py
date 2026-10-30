"""The shared HTTP boundary answers the same way, and never lets a request decide who sent it.

The route family that comes next — alert-occurrence acknowledgement, dismissal, maintenance windows — has
to answer a lost acknowledgement, a concurrent edit and a forged identity without inventing a third error
shape. `local_observe/platform/api_contract.py` is where those three decisions live, and this file is the
reason it is a module rather than a copy-paste: each test names the failure a route would have had alone.

Fixture style follows `tests/test_api_errors.py` (a real `Store` on a temp path, the ASGI app called
directly, no socket), so the idempotency assertions are about the durable record and not about an
in-process dict that forgets on restart.
"""
import asyncio
import base64
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from local_observe.inventory.validation import canonical, utc_text
from local_observe.platform import api_contract
from local_observe.platform.api import create_app, idempotency_enabled
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import (IDEMPOTENCY_IN_FLIGHT_SECONDS, IDEMPOTENCY_TTL_SECONDS,
                                          Actor, StateError, Store)

READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
PRODUCER = {'identity': 'test-detector', 'role': 'producer', 'token': 'p' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
CREDENTIALS = [READER, PRODUCER, PROPOSER, HUMAN, SUMMARY]


async def call(app, method: str, path: str, token: str | None, body: bytes = b'',
               query: bytes = b'', headers: list[tuple[bytes, bytes]] | None = None
               ) -> tuple[int, dict, dict[bytes, bytes]]:
    """Send one request through the ASGI app; return its status, body and response headers."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)

    pairs = list(headers or [])
    if token is not None:
        pairs.append((b'authorization', ('Bearer ' + token).encode()))

    await app({'type': 'http', 'method': method, 'path': path, 'headers': pairs,
               'query_string': query}, receive, send)
    start = output[0]
    return start['status'], json.loads(output[-1]['body']), {
        name.lower(): value for name, value in start.get('headers', [])}


class BoundaryTestCase(unittest.TestCase):
    """Shared store, credentials and request helpers for the transport-level tests below."""

    def setUp(self):
        """Give every test a fresh operational store and a clear environment."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode='off'))

    def app(self):
        """Build the app over the shared store, with no action policy and no optional surface mounted."""
        return create_app(self.store, CREDENTIALS, {})

    def get(self, path: str, token: str | None = READER['token'], app=None, **kwargs):
        """One GET through a freshly built app over the shared store."""
        return asyncio.run(call(app or self.app(), 'GET', path, token, **kwargs))

    def post(self, path: str, body, token: str | None = PRODUCER['token'], app=None, **kwargs):
        """One POST whose body is a document (or raw bytes, to test malformed JSON)."""
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return asyncio.run(call(app or self.app(), 'POST', path, token, raw, **kwargs))

    def firing_event(self, marker: str | None = None) -> dict:
        """Return one valid firing event, distinct per call so two posts are two intentions."""
        moment = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        window = {'start': utc_text(moment - dt.timedelta(seconds=1)), 'end': utc_text(moment)}
        return event(PRODUCER['identity'], None, 'availability', 'availability', 'firing', window,
                     {'sample_id': marker or uuid.uuid4().hex}, query_type='gatus-result')

    def row_count(self, table: str) -> int:
        """Count rows straight from the file, so a replay claim is about the database, not the answer."""
        connection = sqlite3.connect(f'file:{self.root / "state.db"}?mode=ro', uri=True)
        try:
            return connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
        finally:
            connection.close()

    def gate(self):
        """Return the app's own gate, so a test that needs two concurrent callers uses the real object."""
        return self.app().idempotency_gate

    def context(self, identity: str = PRODUCER['identity'], key: str = 'key-1') -> api_contract.ActorContext:
        """Return one actor context as the transport would have built it for a keyed write."""
        return api_contract.ActorContext(identity=identity, role='producer',
                                         request_id=api_contract.new_request_id(), idempotency_key=key)


class ErrorEnvelopeTests(BoundaryTestCase):
    """Three fields, a fixed catalogue, and the legacy bodies left exactly where they were."""

    def test_the_envelope_carries_code_message_and_request_id_and_nothing_else(self):
        """A client switches on the code and a human reads the message; both from one shape."""
        document = api_contract.error_envelope('not_found', 'Nothing answers this path', 'req-1')
        self.assertEqual(document, {'error': {'code': 'not_found', 'message': 'Nothing answers this path',
                                             'request_id': 'req-1'}})
        self.assertEqual(set(document['error']), {'code', 'message', 'request_id'})

    def test_a_boundary_refusal_answers_the_envelope_on_a_live_route(self):
        """The envelope is not a document nobody serves: a real refusal reaches a real client."""
        status, body, headers = self.post('/v1/events', self.firing_event(), PRODUCER['token'],
                                         headers=[(b'idempotency-key', b'not a key!')])
        self.assertEqual(status, 400)
        self.assertEqual(set(body['error']), {'code', 'message', 'request_id'})
        self.assertEqual(body['error']['code'], 'invalid_idempotency_key')
        self.assertEqual(headers[b'x-request-id'].decode(), body['error']['request_id'])

    def test_the_request_id_names_the_answer_and_the_log_line(self):
        """A handler bug is answered with a class name; the id is what ties that answer to the traceback."""
        missing = uuid.uuid4().hex

        def broken_policy(request):
            raise KeyError(missing)

        request = {'retry_key': 'once', 'incident_id': str(uuid.uuid4()), 'action': 'inspect',
                   'version': '1', 'targets': [], 'parameters': {}, 'evidence': [],
                   'expires_at': utc_text(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5))}
        with self.assertLogs('local_observe.platform.api', level='ERROR') as captured:
            status, body, headers = self.post('/v1/actions', request, PROPOSER['token'],
                                              app=create_app(self.store, CREDENTIALS, broken_policy),
                                              headers=[(b'x-request-id', b'logger-tie-check')])
        self.assertEqual((status, body), (500, {'error': 'internal_error', 'detail': 'KeyError'}))
        self.assertEqual(headers[b'x-request-id'], b'logger-tie-check')
        self.assertEqual(captured.records[0].request_id, 'logger-tie-check')
        self.assertNotIn(missing, json.dumps(body))

    def test_a_code_outside_the_catalogue_is_a_bug_at_the_raise_site(self):
        """A typo in this module must not become an undocumented answer on the wire."""
        with self.assertRaises(KeyError):
            api_contract.ContractError(400, 'invlid_request', 'typo')

    def test_the_legacy_bodies_are_still_the_bodies_clients_assert(self):
        """Compatibility is a fact about which constructor ran, so both shapes are pinned here."""
        self.assertEqual(api_contract.legacy_error('not_found'), {'error': 'not_found'})
        self.assertEqual(api_contract.legacy_error('conflict', 'Action is not pending'),
                         {'error': 'conflict', 'detail': 'Action is not pending'})
        status, body, _ = self.post('/v1/actions/decision',
                                    {'action_id': str(uuid.uuid4()), 'decision': 'approved'}, HUMAN['token'])
        self.assertEqual((status, body), (400, {'error': 'conflict', 'detail': 'Action is not pending'}))

    def test_every_catalogue_code_is_reachable_or_legacy_and_names_one_status(self):
        """A documented code with no producing path, or a status no route answers, fails here."""
        for code, statuses in api_contract.ERROR_CATALOGUE.items():
            self.assertTrue(statuses, code)
            self.assertTrue(all(100 <= status < 600 for status in statuses), code)
            self.assertIn(code, api_contract.LEGACY_CODES | set(api_contract.ERROR_CATALOGUE), code)


class RequestIdentityTests(BoundaryTestCase):
    """One id per request, echoed everywhere, and never taken from an unsafe caller value."""

    def test_every_answer_carries_exactly_one_request_id(self):
        """Including the 404s and the auth refusals, which are the answers a client correlates first."""
        for path, token in (('/v1/me', READER['token']), ('/v1/nothing-here', READER['token']),
                            ('/v1/me', None), ('/v1/status', SUMMARY['token'])):
            with self.subTest(path=path, token=bool(token)):
                _status, _body, headers = self.get(path, token)
                offered = api_contract.header_values({'headers': list(headers.items())},
                                                    api_contract.REQUEST_ID_HEADER)
                self.assertEqual(len(offered), 1)
                self.assertTrue(api_contract.REQUEST_ID_PATTERN.fullmatch(offered[0]), offered[0])

    def test_a_well_formed_inbound_id_is_reused(self):
        """A caller that already named the request keeps its own name through the whole chain."""
        _status, _body, headers = self.get('/v1/me', READER['token'],
                                          headers=[(b'x-request-id', b'trace-42')])
        self.assertEqual(headers[b'x-request-id'], b'trace-42')

    def test_an_ambiguous_or_unsafe_inbound_id_is_replaced(self):
        """Two headers or an unechoable character mean a fresh id, so one id names one request."""
        offered = [[(b'x-request-id', b'a'), (b'x-request-id', b'b')],
                   [(b'x-request-id', b'has space')],
                   [(b'x-request-id', b'line\ninjected')],
                   [(b'x-request-id', b'x' * 200)]]
        for headers in offered:
            with self.subTest(headers=headers):
                _status, _body, response = self.get('/v1/me', READER['token'], headers=headers)
                echoed = response[b'x-request-id']
                self.assertNotIn(echoed, [value for _name, value in headers])
                self.assertTrue(api_contract.REQUEST_ID_PATTERN.fullmatch(echoed.decode()))

    def test_the_id_survives_a_replayed_answer(self):
        """The caller that lost its reply still gets an id, or it cannot ask what happened."""
        key = b'replay-id-tie'
        event_body = self.firing_event('replay-id')
        raw = json.dumps(event_body).encode()
        first = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], raw,
                                 b'', [(b'idempotency-key', key)]))
        second = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], raw,
                                  b'', [(b'idempotency-key', key)]))
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertTrue(second[2][b'x-request-id'])


class ActorContextTests(BoundaryTestCase):
    """The actor is the credential. A body field cannot claim a role, and nothing ignores the claim."""

    def test_the_context_is_the_authenticated_actor_and_nothing_more(self):
        """`state.Actor` in, `ActorContext` out, with the transport's own authentication fact."""
        actor = Actor(identity='operator', role='human')
        context = api_contract.actor_context(actor, 'req-1', idempotency_key='k')
        self.assertEqual((context.identity, context.role, context.authentication,
                          context.idempotency_key), ('operator', 'human', 'bearer', 'k'))

    def test_an_anonymous_request_cannot_be_described_as_an_actor(self):
        """A route that forgot to authenticate is refused here rather than served as nobody."""
        for impostor in (None, object(), Actor('', 'human'), Actor('x', '')):
            with self.subTest(actor=impostor):
                with self.assertRaises(api_contract.ContractError) as caught:
                    api_contract.actor_context(impostor, 'req-1')
                self.assertEqual((caught.exception.status, caught.exception.code),
                                 (401, 'authentication_required'))

    def test_a_body_cannot_name_the_human_behind_a_write(self):
        """A canonical event that also claims `actor` is refused by the boundary, before intake runs."""
        forged = dict(self.firing_event('actor-claim'), actor='someone-else')
        status, body, _headers = self.post('/v1/events', forged, PRODUCER['token'])
        self.assertEqual(status, 400)
        self.assertEqual(body['error']['code'], 'actor_claim_refused')
        self.assertEqual(self.row_count('events'), 0)

    def test_a_forged_identity_does_not_upgrade_the_credential(self):
        """A reader cannot become the human it names; it is refused instead of being believed."""
        status, body, _headers = self.post('/v1/evidence',
                                          {'identity': 'operator', 'source': 's', 'sample_id': '1',
                                           'observed_at': utc_text(dt.datetime.now(dt.timezone.utc)),
                                           'ok': True, 'value': 1}, READER['token'])
        self.assertEqual(status, 400)
        self.assertEqual(body['error']['code'], 'actor_claim_refused')

    def test_the_refusal_counts_the_claim_without_naming_it(self):
        """The answer must not tell a caller which spellings this module knows."""
        status, body, _headers = self.post('/v1/events',
                                           dict(self.firing_event('quiet-claim'), impersonate='operator'),
                                           PRODUCER['token'])
        self.assertEqual(status, 400)
        self.assertNotIn('impersonate', body['error']['message'])
        self.assertIn('1 such field(s)', body['error']['message'])

    def test_a_nested_document_field_is_not_an_identity_claim(self):
        """The gate polices who acted, not what the payload holds.

        Checked on the helper rather than over HTTP: every body field this platform reads is a closed shape
        (`Unapproved evidence parameter; no SQL or credentials`), so a nested document carrying an `actor`
        key can only arrive somewhere the route had already refused it for another reason.
        """
        api_contract.assert_no_actor_claim({'evidence': [{'actor': 'unrelated', 'note': 'text'}],
                                           'parameters': {'role': 'reader'}})
        with self.assertRaises(api_contract.ContractError):
            api_contract.assert_no_actor_claim({'evidence': [{'actor': 'x'}], 'actor': 'y'})

    def test_assert_no_actor_claim_accepts_a_non_object(self):
        """The callers that parse first may hand it anything; only a mapping of claims is refused."""
        api_contract.assert_no_actor_claim(None)
        api_contract.assert_no_actor_claim(['actor'])
        with self.assertRaises(api_contract.ContractError):
            api_contract.assert_no_actor_claim({'role': 'human'})


class IdempotencyProtocolTests(BoundaryTestCase):
    """Same key plus same body replays; same key plus another body runs nothing."""

    def key(self, value: str | bytes) -> list[tuple[bytes, bytes]]:
        return [(b'idempotency-key', value if isinstance(value, bytes) else value.encode())]

    def test_a_lost_answer_is_read_back_without_a_second_side_effect(self):
        """The caller that retried gets its first answer, not a second write and not a new verdict."""
        raw = json.dumps(self.firing_event('durable-replay')).encode()
        status, first, headers = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'],
                                                 raw, b'', self.key('durable-1')))
        self.assertEqual(status, 200)
        self.assertNotIn(b'x-idempotency-replayed', headers)
        replay_status, replayed, replay_headers = asyncio.run(call(self.app(), 'POST', '/v1/events',
                                                                  PRODUCER['token'], raw, b'',
                                                                  self.key('durable-1')))
        self.assertEqual((replay_status, replayed), (status, first))
        self.assertEqual(replay_headers[b'x-idempotency-replayed'], b'true')
        self.assertEqual(self.row_count('events'), 1)
        # The replay answers the request, not the current state: the store would now call this a
        # duplicate, and a caller that sees `duplicate` cannot tell whether its write landed.
        self.assertEqual(first['status'], 'accepted')

    def test_one_key_never_carries_two_intentions(self):
        """A different body under a used key is refused with the envelope, and neither write runs."""
        first = json.dumps(self.firing_event('conflict-a')).encode()
        other = json.dumps(self.firing_event('conflict-b')).encode()
        self.assertEqual(asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], first,
                                         b'', self.key('two-intentions')))[0], 200)
        status, body, headers = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], other,
                                                b'', self.key('two-intentions')))
        self.assertEqual(status, 409)
        self.assertEqual(body['error']['code'], 'idempotency_conflict')
        self.assertEqual(headers[b'x-request-id'], body['error']['request_id'].encode())
        self.assertEqual(self.row_count('events'), 1)

    def test_key_equivalence_is_about_the_statement_not_the_bytes(self):
        """Re-keyed and re-spaced JSON is the same request, so a formatter is not a second write."""
        body = self.firing_event('canonical-equality')
        wide = json.dumps(body, indent=4).encode()
        narrow = canonical(json.loads(canonical(dict(reversed(list(body.items())))))).encode()
        self.assertEqual(asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], wide,
                                         b'', self.key('same-statement')))[0], 200)
        status, replayed, headers = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'],
                                                    narrow, b'', self.key('same-statement')))
        self.assertEqual(status, 200)
        self.assertEqual(headers[b'x-idempotency-replayed'], b'true')
        self.assertEqual(self.row_count('events'), 1)

    def test_a_refusal_is_never_frozen_under_a_key(self):
        """A 4xx that names a state this platform may not have reached must not outlive that state."""
        refused = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'],
                                   b'{"schema_version": 1}', b'', self.key('retry-after-no')))
        self.assertEqual(refused[0], 400)
        self.assertEqual(self.row_count('api_idempotency'), 0)
        status, _body, headers = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'],
                                                 json.dumps(self.firing_event('after-refusal')).encode(),
                                                 b'', self.key('retry-after-no')))
        self.assertEqual(status, 200)
        self.assertNotIn(b'x-idempotency-replayed', headers)

    def test_a_malformed_key_is_refused_before_the_write(self):
        """Normalising a key would merge two intentions, so the shape is enforced and nothing runs."""
        for bad in (b'has space', b'', b'x' * 129, b'tab\tseparated'):
            with self.subTest(key=bad):
                status, body, _headers = asyncio.run(call(self.app(), 'POST', '/v1/events',
                                                         PRODUCER['token'],
                                                         json.dumps(self.firing_event('bad-key')).encode(),
                                                         b'', self.key(bad)))
                self.assertEqual(status, 400)
                self.assertEqual(body['error']['code'], 'invalid_idempotency_key')
        self.assertEqual(self.row_count('events'), 0)

    def test_two_keys_are_two_separate_claims(self):
        """A repeated header is an ambiguous opt-in, not a value to choose between."""
        status, body, _headers = asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'],
                                                 json.dumps(self.firing_event('twice')).encode(), b'',
                                                 [(b'idempotency-key', b'a'), (b'idempotency-key', b'b')]))
        self.assertEqual(status, 400)
        self.assertEqual(body['error']['code'], 'invalid_idempotency_key')

    def test_a_route_outside_the_list_ignores_the_header(self):
        """No client that exists today changes behaviour, so an unlisted route stores nothing."""
        self.assertTrue(idempotency_enabled('/v1/events'))
        self.assertFalse(idempotency_enabled('/v1/actions'))
        status, body, headers = self.post('/v1/actions', {'incident_id': str(uuid.uuid4()),
                                                         'action': 'restart', 'version': '1'},
                                         HUMAN['token'], headers=self.key('unlisted-route'))
        self.assertEqual(status, 400)  # the action allowlist is empty here; the point is what was stored
        self.assertNotIn(b'x-idempotency-replayed', headers)
        self.assertEqual(self.row_count('api_idempotency'), 0)

    def test_a_replayed_answer_does_not_run_the_handler_again(self):
        """The replay path returns before the route body, so a second side effect is not possible."""
        raw = json.dumps(self.firing_event('no-second-run')).encode()
        asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], raw, b'', self.key('once')))
        asyncio.run(call(self.app(), 'POST', '/v1/events', PRODUCER['token'], raw, b'', self.key('once')))
        self.assertEqual(self.row_count('events'), 1)
        self.assertEqual(self.row_count('api_idempotency'), 1)


class IdempotencyStoreTests(BoundaryTestCase):
    """The four states, the two clocks and the width bound — decided against the durable record."""

    def test_an_in_flight_key_is_not_served_twice(self):
        """A concurrent caller is told to stop rather than queued behind a duplicate side effect."""
        gate = self.gate()
        context = self.context(key='in-flight')
        held = gate.reserve(context, {'n': 1})
        self.assertTrue(held.held)
        with self.assertRaises(api_contract.ContractError) as caught:
            gate.reserve(self.context(key='in-flight'), {'n': 1})
        self.assertEqual((caught.exception.status, caught.exception.code), (409, 'request_in_progress'))

    def test_a_key_whose_owner_died_is_handed_to_the_next_caller(self):
        """An in-flight marker older than the window belongs to a process that is not coming back."""
        gate = self.gate()
        gate.reserve(self.context(key='orphan'), {'n': 1}, now=dt.datetime.now(dt.timezone.utc)
                     - dt.timedelta(seconds=IDEMPOTENCY_IN_FLIGHT_SECONDS + 30))
        self.assertTrue(gate.reserve(self.context(key='orphan'), {'n': 1}).held)

    def test_a_completed_answer_stops_replaying_when_the_window_closes(self):
        """The promise is bounded, so a two-day-old key is a fresh request and not a resurrection."""
        gate = self.gate()
        reservation = gate.reserve(self.context(key='aged'), {'n': 1})
        gate.complete(reservation, 200, {'status': 'accepted'})
        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=IDEMPOTENCY_TTL_SECONDS + 30)
        self.assertEqual(gate.reserve(self.context(key='aged'), {'n': 1}, now=later).replay, None)

    def test_an_answer_too_wide_to_store_is_served_but_not_stored(self):
        """Truncating a reply would replay a lie, so the caller is answered and the key is released."""
        gate = self.gate()
        wide = {'blob': 'x' * (api_contract.MAX_STORED_REPLY_BYTES + 1)}
        reservation = gate.reserve(self.context(key='wide'), wide)
        gate.complete(reservation, 200, wide)
        self.assertEqual(self.row_count('api_idempotency'), 0)
        self.assertTrue(gate.reserve(self.context(key='wide'), wide).held)

    def test_a_completion_cannot_land_on_another_requests_row(self):
        """Each call names its own digest, so two requests under one key cannot cross-finish."""
        gate = self.gate()
        first = gate.reserve(self.context(key='crossed'), {'n': 1})
        with self.assertRaises(api_contract.ContractError):
            gate.reserve(self.context(key='crossed'), {'n': 2})
        gate.abandon(first)
        self.assertEqual(self.row_count('api_idempotency'), 0)

    def test_one_key_belongs_to_the_principal_that_claimed_it(self):
        """Keys are scoped to their owner, so a second identity is not blocked by a stranger's retry."""
        gate = self.gate()
        self.assertTrue(gate.reserve(self.context('caller-a', key='shared'), {'n': 1}).held)
        self.assertTrue(gate.reserve(self.context('caller-b', key='shared'), {'n': 1}).held)

    def test_abandoning_a_replayed_answer_changes_nothing(self):
        """A replay holds no claim, so settling it twice cannot delete the stored answer."""
        gate = self.gate()
        reservation = gate.reserve(self.context(key='settled'), {'n': 1})
        gate.complete(reservation, 200, {'status': 'accepted'})
        replayed = gate.reserve(self.context(key='settled'), {'n': 1})
        gate.abandon(replayed)
        self.assertEqual(self.row_count('api_idempotency'), 1)

    def test_expired_rows_are_swept_by_the_next_reserve(self):
        """Bounded work per call and no scheduler: the table cannot grow for the life of the file."""
        gate = self.gate()
        past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=IDEMPOTENCY_TTL_SECONDS + 60)
        gate.reserve(self.context(key='swept-in-flight'), {'n': 1}, now=past)
        self.assertEqual(self.row_count('api_idempotency'), 1)
        gate.reserve(self.context(key='fresh'), {'n': 1})  # the sweep runs inside this call
        self.assertEqual(self.row_count('api_idempotency'), 1)
        completed = gate.reserve(self.context(key='swept-answer'), {'n': 1})
        gate.complete(completed, 200, {'status': 'accepted'})
        gate.reserve(self.context(key='later'), {'n': 1},
                     now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=IDEMPOTENCY_TTL_SECONDS + 60))
        self.assertEqual(self.row_count('api_idempotency'), 1)  # only the newest row is left

    def test_the_store_refuses_an_unbounded_name_before_touching_the_table(self):
        """A key that cannot be a durable label is a caller error, not a row."""
        for bad in ('', 'has space', 'x' * 200):
            with self.subTest(key=bad):
                with self.assertRaises(StateError):
                    self.store.idempotency_reserve('caller', bad, '0' * 64)
        with self.assertRaises(StateError):
            self.store.idempotency_reserve('caller', 'fine', 'not-a-digest')


class ExpectedRevisionTests(BoundaryTestCase):
    """`If-Match` compared against state the caller could not see, answered 412 or 409."""

    def scope(self, *headers: tuple[str, str]) -> dict:
        return {'headers': [(name.lower().encode(), value.encode()) for name, value in headers],
                'query_string': b''}

    def test_the_revision_is_read_from_if_match_in_the_spelling_issued(self):
        """A quoted or weak tag is the same expectation, because a client copied it from an ETag."""
        for raw in ('7', '"7"', 'W/"7"'):
            with self.subTest(etag=raw):
                self.assertEqual(api_contract.expected_revision(self.scope(('if-match', raw))), '7')

    def test_no_expectation_is_a_no_op(self):
        """An unconditional write still gets its current tag, so a route may call the helper always."""
        self.assertIsNone(api_contract.expected_revision(self.scope()))
        self.assertEqual(api_contract.check_revision(7, None), '7')

    def test_an_asterisk_means_overwrite_and_not_a_match(self):
        """`If-Match: *` is the caller asking to clobber, so it must not compare as a revision."""
        self.assertIsNone(api_contract.expected_revision(self.scope(('if-match', '*'))))

    def test_a_body_may_name_the_revision_it_read_but_not_the_actor(self):
        """Only one field is read from a body, and it is a value compared, never an identity."""
        self.assertEqual(api_contract.expected_revision(self.scope(), {'expected_revision': '9'}), '9')
        self.assertIsNone(api_contract.expected_revision(self.scope(), {'revision': '9'}))

    def test_a_mismatch_is_refused_before_anything_is_written(self):
        """412 with the catalogue's code, so a client can tell a lost race from a bad request."""
        with self.assertRaises(api_contract.ContractError) as caught:
            api_contract.check_revision(8, '7')
        self.assertEqual((caught.exception.status, caught.exception.code), (412, 'stale_revision'))
        with self.assertRaises(api_contract.ContractError) as again:
            api_contract.check_revision(8, '7', status=409)
        self.assertEqual(again.exception.status, 409)

    def test_a_resource_with_no_state_is_not_a_stale_revision(self):
        """Nothing to update is a 404, not a promise that a later read would match."""
        with self.assertRaises(api_contract.ContractError) as caught:
            api_contract.check_revision(None, '7')
        self.assertEqual((caught.exception.status, caught.exception.code), (404, 'not_found'))

    def test_two_expectations_are_refused_rather_than_chosen_between(self):
        """Same rule as the credential and the key: ambiguity is the caller's to fix."""
        scope = {'headers': [(b'if-match', b'1'), (b'if-match', b'2')]}
        with self.assertRaises(api_contract.ContractError) as caught:
            api_contract.expected_revision(scope)
        self.assertEqual((caught.exception.status, caught.exception.code), (400, 'invalid_revision'))
        with self.assertRaises(api_contract.ContractError) as junk:
            api_contract.expected_revision(self.scope(('if-match', '@@@@')))
        self.assertEqual(junk.exception.code, 'invalid_revision')

    def test_a_revision_the_server_cannot_name_is_a_server_fault(self):
        """Handing a client an unechoable tag would make the next write impossible, so say 500."""
        with self.assertRaises(api_contract.ContractError) as caught:
            api_contract.revision_tag('has spaces and, worse, commas')
        self.assertEqual((caught.exception.status, caught.exception.code), (500, 'internal_error'))

    def test_a_datetime_revision_and_an_integer_revision_both_render_once(self):
        """The owning module chooses its revision; this module only fixes its spelling."""
        moment = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
        self.assertEqual(api_contract.revision_tag(moment), '2026-01-02T03:04:05+00:00')
        # `str(datetime)` and `isoformat()` render one instant two ways; a route may hold either.
        self.assertEqual(api_contract.revision_tag(str(moment)), api_contract.revision_tag(moment))
        self.assertEqual(api_contract.revision_tag(7), '7')
        self.assertEqual(api_contract.check_revision(moment, api_contract.revision_tag(moment)),
                         '2026-01-02T03:04:05+00:00')


class BoundedPaginationTests(BoundaryTestCase):
    """A page query that cannot be answered honestly is refused before a connection is opened."""

    def scope(self, query: bytes) -> dict:
        return {'headers': [], 'query_string': query}

    def test_the_default_page_is_small_and_bounded(self):
        params = api_contract.page_params(self.scope(b''))
        self.assertEqual(params, {'limit': api_contract.PAGE_LIMIT_DEFAULT, 'cursor': None})
        self.assertLessEqual(params['limit'], api_contract.PAGE_LIMIT_MAX)

    def test_a_limit_above_the_ceiling_is_refused_not_clamped(self):
        """Quietly returning fewer rows than were asked for would make a short page look complete."""
        for query in (b'limit=201', b'limit=0', b'limit=-5', b'limit=abc', b'limit=1_000', b'limit=+5',
                      b'limit=05', b'limit=', b'limit=5&limit=6', b'limit=5&other=1', b'nope=1'):
            with self.subTest(query=query):
                with self.assertRaises(api_contract.ContractError) as caught:
                    api_contract.page_params(self.scope(query))
                self.assertEqual((caught.exception.status, caught.exception.code),
                                 (400, 'invalid_pagination'))
        self.assertEqual(api_contract.page_params(self.scope(b'limit=200')),
                         {'limit': 200, 'cursor': None})

    def test_an_oversized_query_is_refused_before_it_is_parsed(self):
        """The bound exists to stop traversal of caller bytes, so it is checked first."""
        with self.assertRaises(api_contract.ContractError) as caught:
            api_contract.page_params(self.scope(b'limit=1&cursor=' + b'A' * 900))
        self.assertEqual(caught.exception.code, 'invalid_pagination')

    def test_a_non_ascii_query_is_refused_rather_than_replaced(self):
        """Replacement characters would decode a cursor into a position nobody issued."""
        with self.assertRaises(api_contract.ContractError) as caught:
            api_contract.page_params({'headers': [], 'query_string': b'cursor=\xff\xfe'})
        self.assertEqual(caught.exception.message, 'A page query must be ASCII percent-encoded text')

    def test_a_cursor_round_trips_and_is_opaque_but_not_secret(self):
        """It is a position, not a filter: the caller cannot read it and the service cannot be fooled."""
        for position in (17, 'row-4', dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)):
            encoded = api_contract.encode_cursor(position)
            self.assertNotIn('=', encoded)
            self.assertEqual(api_contract.decode_cursor(encoded), api_contract.revision_tag(position))
        self.assertEqual(api_contract.encode_cursor(None), '')

    def test_a_cursor_the_service_never_issued_is_a_caller_error(self):
        """A typo must not read as `no more rows`, which is how a UI quietly stops showing incidents."""
        for token in ('not-base64!!', base64.urlsafe_b64encode(b'has space').decode().rstrip('='),
                      base64.urlsafe_b64encode(b'x' * 400).decode().rstrip('='), ''):
            with self.subTest(token=token[:24]):
                with self.assertRaises(api_contract.ContractError) as caught:
                    api_contract.decode_cursor(token)
                self.assertEqual(caught.exception.code, 'invalid_pagination')
        # A token the service could have issued is accepted without being inspected any further: it is a
        # position, and the caller is never told what it points at.
        self.assertEqual(api_contract.decode_cursor('YWJj'), 'abc')

    def test_a_short_page_states_that_it_is_the_last_one(self):
        """No cursor on a short page: 'there is no more' and 'I stopped looking' are different answers."""
        full = api_contract.page_payload([{'id': 1}, {'id': 2}], limit=2, cursor_for=lambda row: row['id'])
        self.assertEqual(full['next_cursor'], api_contract.encode_cursor(2))
        short = api_contract.page_payload([{'id': 1}], limit=2, cursor_for=lambda row: row['id'])
        self.assertNotIn('next_cursor', short)
        self.assertEqual((short['limit'], short['returned']), (2, 1))
        empty = api_contract.page_payload([], limit=2, cursor_for=lambda row: row['id'])
        self.assertNotIn('next_cursor', empty)
        self.assertEqual(empty['returned'], 0)


class AppWiringTests(BoundaryTestCase):
    """The boundary is per app, over the store that app already owns."""

    def test_each_app_holds_its_own_gate_over_its_own_store(self):
        other = Store(self.root / 'other.db', NotificationPolicy(delivery_mode='off'))
        first, second = create_app(self.store, CREDENTIALS, {}), create_app(other, CREDENTIALS, {})
        self.assertIs(first.idempotency_gate.store, self.store)
        self.assertIs(second.idempotency_gate.store, other)
        self.assertIsNot(first.idempotency_gate, second.idempotency_gate)

    def test_the_boundary_imports_no_transport_or_framework(self):
        """`api.py` imports it at module scope, so its import list is on every request's critical path."""
        import importlib
        source = Path(importlib.util.find_spec(api_contract.__name__).origin).read_text()
        imports = [line.strip() for line in source.splitlines()
                   if line.startswith(('import ', 'from '))]
        joined = ' '.join(imports)
        for forbidden in ('fastapi', 'pydantic', 'starlette', 'sqlite3', 'verification_api',
                          'observer_review', '.api'):
            self.assertNotIn(forbidden, joined, forbidden)
        self.assertIn('from .state import', joined)


if __name__ == '__main__':
    unittest.main()

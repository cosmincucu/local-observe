"""Regression: the notification callback is a single-use intent, and nothing more.

Ledger notifications, standing on `docs/CONTRACTS.md` §5: *"Notification callbacks bind the same request, actor
and expiry and are single use. Callback receipt is not action completion."* Before this file the
platform had no inbound route at all — `telegram.py` is send-only by docstring, and `api.py` had only
the two human-role platform calls (`/v1/notifications/retry`, `/v1/notifications/reset-safety`) — so
"the phone surface" (phone surface) meant *the phone can read*.

This route is the item's only new attack surface, so most of what follows is adversarial:

* a wrong code, an unknown channel and a code minted for a *different* channel answer with the same
  401 bytes, so the endpoint is not an oracle for which channels exist or which code shape is real;
* the identity written into the audit row is the one the bearer credential carries. A body field
  naming somebody else is refused outright, and a `reader` or `summary` token never reaches the lookup;
* replay answers with the durable "already consumed" sentence and records nothing a second time;
* every refused callback leaves the action `pending` — the strongest form of "not action completion" is
  that the decision route stays the only way forward, and an agent-role token cannot take it.

One fixture decision is worth naming, because it is the opposite of the habit elsewhere in this suite:
`now` is the *real* clock, stepped back ten minutes, rather than a fixed date. The routes below let the
service read its own time — `Store.record_callback` deliberately has no caller-supplied `now`, since a
callback that could be told what time it is would not have an expiry worth testing. So the incident is
opened in the recent past and the code's window straddles the difference: a `callback_seconds` value
below the ten-minute offset is genuinely expired by the time the POST lands, and the default one-hour
window is genuinely still open.

Fixtures otherwise follow `tests/test_api_errors.py`: a real `Store` on a temp path and the ASGI app
called directly, so the lifespan delivery loop never runs and nothing can reach a network.
"""
import asyncio
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import closing

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.api import create_app
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store

# How far back the scenario is set, and why: see the module docstring. The expired-code tests spend a
# code whose whole window sits inside this offset; the valid-code tests use the default hour.
SCENARIO_OFFSET = dt.timedelta(minutes=10)
PRODUCER = Actor('test-detector', 'producer')
AGENT = Actor('agent-1', 'proposer')
READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 's' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
CREDENTIALS = [READER, PROPOSER, SUMMARY, HUMAN]
POLICY = NotificationPolicy(delivery_mode='live', max_attempts=20, max_event_age_seconds=86400)


def allowlist(request: dict) -> None:
    """Stand in for the deployment action allowlist: these tests are about who may approve, not what."""


def scenario_now() -> dt.datetime:
    """Return the instant this scenario is built at: the real clock, stepped back a little."""
    return dt.datetime.now(dt.timezone.utc) - SCENARIO_OFFSET


async def _call(app, method: str, path: str, token: str, body: bytes = b'') -> tuple[int, dict]:
    """Drive the ASGI app directly: no socket, no lifespan, no delivery loop."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)
    auth = (b'authorization', ('Bearer ' + token).encode())
    await app({'type': 'http', 'method': method, 'path': path, 'headers': [auth],
               'query_string': b''}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class CallbackTests(unittest.TestCase):
    """What a tap on a phone message may, and may not, do to an approval."""

    def setUp(self):
        """Open a live-mode store and queue one delivery plus one pending action for its incident."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = scenario_now()
        self.path = Path(self.temp.name) / 'platform.db'
        self.store = Store(self.path, POLICY)
        self.app = create_app(self.store, CREDENTIALS, allowlist)
        self.incident, self.event = self.open_incident('test-detector')
        self.action = self.propose(self.incident, self.event)

    # --- fixtures -----------------------------------------------------------------------------

    def post(self, path: str, body, token: str = HUMAN['token']) -> tuple[int, dict]:
        """One POST through the app; `body` may be raw bytes to test a malformed document."""
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return asyncio.run(_call(self.app, 'POST', path, token, raw))

    def open_incident(self, source: str) -> tuple[str, str]:
        """Intake one firing event and return the incident it opened plus the event inside it."""
        window = {'start': utc_text(self.now - dt.timedelta(seconds=1)), 'end': utc_text(self.now)}
        result = self.store.intake(event(source, None, 'availability', 'availability', 'firing', window,
                                        {'sample_id': 'fixture'}, query_type='gatus-result'),
                                   Actor(source, 'producer'), now=self.now)
        return result['incident_id'], result['event_id']

    def propose(self, incident: str, event_id: str, *, retry_key: str = 'restart-1',
                parameters: dict | None = None) -> str:
        """Propose one bounded action against `incident` and return its id."""
        return self.store.propose_action(
            {'retry_key': retry_key, 'incident_id': incident, 'action': 'inspect-synthetic',
             'version': '1', 'targets': [str(uuid.uuid4())], 'parameters': parameters or {},
             'evidence': [event_id], 'expires_at': utc_text(self.now + dt.timedelta(hours=1))},
            AGENT, allowlist, now=self.now)['action_id']

    def claim(self, *, callback_seconds: int = 3600) -> dict:
        """Claim the head of the queue, acknowledge it in place, and return the claim."""
        claim = self.store.claim_notification(now=self.now, callback_seconds=callback_seconds)
        self.assertIsNotNone(claim, 'a live, eligible delivery must be claimable')
        self.assertEqual((claim['channel'], claim['destination']), ('primary', 'human'))
        self.store.finish_notification(claim['id'], claim['claim_token'], True, now=self.now)
        return claim

    def code(self, **kwargs) -> str:
        """Return the approval code the delivery claimed with `kwargs` handed to its channel."""
        return self.claim(**kwargs)['callback']['token']

    def audits(self, operation: str) -> list[dict]:
        """Return the audit rows of one operation, oldest first."""
        return [row for row in reversed(self.store.records('audit', 100)) if row['operation'] == operation]

    def action_status(self, action_id: str | None = None) -> str:
        """Read an action's status straight from the file, not from a view."""
        with closing(sqlite3.connect(self.store.path)) as db:
            return db.execute('SELECT status FROM actions WHERE id=?',
                              (action_id or self.action,)).fetchone()[0]

    # --- the happy path, and the boundary that makes it only a half-step ----------------------

    def test_a_callback_records_an_intent_and_leaves_the_action_pending(self):
        """Asserting "callback receipt is not action completion" the hard way.

        After a genuine, in-time, correctly-addressed callback the action is still `pending`, it cannot
        be claimed for execution, no execution row exists, and the only thing recorded is one audit row
        naming the *credential's* identity.
        """
        code = self.code()
        status, body = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action})
        self.assertEqual(status, 200)
        self.assertEqual(body['status'], 'intent_recorded')
        self.assertIs(body['decided'], False, 'the answer itself must not read like a decision')
        self.assertEqual(self.action_status(), 'pending')
        self.assertEqual(self.store.status()['actions'], {'pending': 1})
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM executions').fetchone()[0], 0,
                             'an intent may not create an execution claim')
            intents = db.execute('SELECT actor, subject, detail FROM audit'
                                 " WHERE operation='action.approval_intent'").fetchall()
        self.assertEqual([(row[0], row[1]) for row in intents], [('operator', self.action)])
        self.assertEqual(json.loads(intents[0][2]),
                         {'channel': 'primary', 'decided': False, 'delivery_id': body['delivery_id']})
        with self.assertRaisesRegex(StateError, 'not available for dispatch'):
            self.store.claim_action(self.action, Actor('runner', 'executor'), allowlist, now=self.now)

    def test_the_decision_still_belongs_to_a_human_credential_afterwards(self):
        """The intent is a note; `/v1/actions/decision` stays the only door, and only for `human`.

        The §5 "agent self-approval rejection" clause from the callback side: an agent-role credential
        may carry an intent (it approves nothing), and that same credential is refused the decision that
        would be needed to make the intent mean anything.
        """
        code = self.code()
        self.assertEqual(self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action},
                                   PROPOSER['token'])[0], 200)
        self.assertEqual(self.action_status(), 'pending', 'an intent is not a decision')
        refused = self.post('/v1/actions/decision', {'action_id': self.action, 'decision': 'approved'},
                            PROPOSER['token'])
        self.assertEqual((refused[0], refused[1]['error']), (400, 'not_authorised'))
        self.assertEqual(self.action_status(), 'pending')
        self.assertEqual(self.post('/v1/actions/decision',
                                   {'action_id': self.action, 'decision': 'approved'})[0], 200)
        self.assertEqual(self.action_status(), 'approved', 'the human route still works')

    def test_the_intent_lands_on_the_action_named_and_no_other(self):
        """The binding a callback can carry: one delivery, one incident, the action it names.

        Two pending actions on one incident, told apart only by their parameters: the audit row is about
        the one the document named. Then the other incident's delivery, whose code is refused for the
        first incident's action and accepted for its own — which is the binding asserted from both sides,
        and the only way to assert it, since a code is spent by its first use.
        """
        second, second_event = self.open_incident('second-detector')
        named = self.propose(self.incident, self.event, retry_key='restart-2',
                             parameters={'depth': 'shallow'})
        code = self.code()
        self.assertEqual(self.post('/v1/callbacks/primary', {'token': code, 'action_id': named})[0], 200)
        self.assertEqual([(row['subject'], row['actor']) for row in self.audits('action.approval_intent')],
                         [(named, 'operator')], 'only the action named acquired an intent')
        self.assertEqual(self.action_status(), 'pending', 'its sibling on the same incident is untouched')
        foreign = self.propose(second, second_event, retry_key='restart-3')
        second_code = self.code()
        crossed = self.post('/v1/callbacks/primary', {'token': second_code, 'action_id': self.action})
        self.assertEqual((crossed[0], crossed[1]['error']), (400, 'conflict'))
        self.assertIn('not part of the notified incident', crossed[1]['detail'])
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': second_code, 'action_id': foreign})[0], 200,
                         'the same code reaches the action its own delivery announced')
        self.assertEqual(sorted(row['subject'] for row in self.audits('action.approval_intent')),
                         sorted([named, foreign]))

    # --- replay, expiry and the shape of a refusal -------------------------------------------

    def test_a_replayed_callback_is_refused_and_records_nothing_a_second_time(self):
        """Single use, answered durably: the second tap says so and changes no state."""
        code = self.code()
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': code, 'action_id': self.action})[0], 200)
        for _ in range(3):
            replay = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action})
            self.assertEqual((replay[0], replay[1]['error']), (400, 'conflict'))
            self.assertIn('already been consumed', replay[1]['detail'])
        self.assertEqual(len(self.audits('action.approval_intent')), 1)
        self.assertEqual(self.action_status(), 'pending')
        # Consumption is durable state, not in-process memory: a fresh app over the same file refuses.
        reopened = create_app(Store(self.path, POLICY), CREDENTIALS, allowlist)
        raw = json.dumps({'token': code, 'action_id': self.action}).encode()
        status, body = asyncio.run(_call(reopened, 'POST', '/v1/callbacks/primary', HUMAN['token'], raw))
        self.assertEqual((status, body['error']), (400, 'conflict'))
        self.assertEqual(len(self.audits('action.approval_intent')), 1)

    def test_an_expired_callback_is_refused_and_the_action_waits(self):
        """A code whose window closed is refused with its own reason, and nothing else moves."""
        code = self.code(callback_seconds=60)
        late = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action})
        self.assertEqual(late[0], 400)
        self.assertEqual((late[1]['error'], late[1]['detail']),
                         ('conflict', 'Notification callback has expired'))
        self.assertEqual(self.audits('action.approval_intent'), [])
        self.assertEqual(self.action_status(), 'pending')

    def test_a_wrong_code_is_unauthorised_and_says_nothing_about_why(self):
        """One fixed answer for a wrong code, an unknown channel and a code minted elsewhere.

        The difference between those three would tell an attacker whether a channel exists and whether a
        code shape is recognised — exactly the enumeration this endpoint could become.
        """
        code = self.code()
        guesses = [('/v1/callbacks/primary', 'x' * 43),
                   ('/v1/callbacks/primary', 'short'),
                   ('/v1/callbacks/primary', 'x' * 300),
                   ('/v1/callbacks/no-such-channel', code),
                   ('/v1/callbacks/' + 'a' * 128, code)]
        for route, token in guesses:
            with self.subTest(route=route, length=len(token)):
                status, body = self.post(route, {'token': token, 'action_id': self.action})
                self.assertEqual(status, 401)
                self.assertEqual(body, {'error': 'callback_unauthorised'})
        self.assertEqual(self.audits('action.approval_intent'), [])
        self.assertEqual(self.action_status(), 'pending')
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': code, 'action_id': self.action})[0], 200,
                         'the real code is still good after every failed guess')

    def test_a_code_minted_for_one_channel_is_refused_on_another(self):
        """The channel in the route is part of the binding, not decoration."""
        self.store.add_channels({'oncall': NotificationPolicy(channel='oncall', delivery_mode='live')})
        code = self.code()
        self.assertEqual(self.post('/v1/callbacks/oncall',
                                   {'token': code, 'action_id': self.action})[0], 401)
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': code, 'action_id': self.action})[0],
                         200, 'the same code on its own channel still works')

    def test_a_retry_supersedes_the_code_of_the_attempt_before_it(self):
        """One live code per delivery: a retry mints a new one and the older stops working."""
        claim = self.store.claim_notification(now=self.now)
        self.store.finish_notification(claim['id'], claim['claim_token'], False, now=self.now,
                                      cause='transport')
        second = self.store.claim_notification(now=self.now + dt.timedelta(seconds=30))
        self.assertNotEqual(claim['callback']['token'], second['callback']['token'])
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': claim['callback']['token'], 'action_id': self.action})[0], 401,
                         'the superseded code matches nothing stored')
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': second['callback']['token'], 'action_id': self.action})[0], 200)

    # --- identity comes from the transport, never from the document --------------------------

    def test_a_reader_token_never_reaches_the_code_lookup(self):
        """The role gate runs first, and a refused callback spends nothing."""
        code = self.code()
        refused = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action},
                            READER['token'])
        self.assertEqual((refused[0], refused[1]['error']), (400, 'not_authorised'))
        self.assertEqual(self.audits('action.approval_intent'), [])
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': code, 'action_id': self.action})[0],
                         200, 'the reader could not have consumed the code')

    def test_a_summary_token_cannot_post_at_all(self):
        """The read-only portal surface stays read-only on the new route too."""
        code = self.code()
        refused = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action},
                            SUMMARY['token'])
        self.assertEqual((refused[0], refused[1]['error']), (403, 'summary_only'))

    def test_the_body_cannot_name_an_identity(self):
        """A document that adds an `identity` field is not a callback at all.

        The route accepts exactly `{token, action_id}` — the same "an extra field is refused, not
        ignored" rule every other POST branch in this module follows — and the code survives the
        refusal, so a client that guessed the shape wrong cannot even burn a token by trying.
        """
        code = self.code()
        forged = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action,
                                                    'identity': 'someone-else', 'role': 'human'})
        self.assertEqual(forged[0], 404)
        self.assertEqual(self.audits('action.approval_intent'), [])
        self.assertEqual(self.post('/v1/callbacks/primary',
                                   {'token': code, 'action_id': self.action})[0], 200)
        self.assertEqual([row['actor'] for row in self.audits('action.approval_intent')], ['operator'],
                         'the identity written down is the one that authenticated')

    # --- the transport edges around the new route --------------------------------------------

    def test_the_route_is_post_only_bounded_and_never_echoes_the_code(self):
        """Method and size edges, plus the one secret this route is handed."""
        code = self.code()
        self.assertEqual(asyncio.run(_call(self.app, 'GET', '/v1/callbacks/primary', HUMAN['token']))[0], 404)
        self.assertEqual(self.post('/v1/callbacks/primary', b'not json')[1]['error'], 'invalid_request')
        missing = self.post('/v1/callbacks/primary', {'token': code})
        self.assertEqual((missing[0], missing[1]['error']), (404, 'not_found'),
                         'a document naming only one of the two fields is not this route')
        not_an_object = self.post('/v1/callbacks/primary', b'[1, 2]')
        self.assertEqual((not_an_object[0], not_an_object[1]['error']), (400, 'invalid_request'))
        oversized = json.dumps({'token': code, 'action_id': self.action, 'pad': 'x' * 70000}).encode()
        status, body = self.post('/v1/callbacks/primary', oversized)
        self.assertEqual((status, body['error']), (413, 'body_too_large'))
        with closing(sqlite3.connect(self.store.path)) as db:
            stored = json.dumps([list(row) for row in db.execute('SELECT * FROM outbox')])
        for surface in (stored, json.dumps(self.store.records('outbox')),
                        json.dumps(self.store.records('notification_attempts')),
                        json.dumps(self.store.records('audit'))):
            self.assertNotIn(code, surface, 'the clear code is never stored or handed back')

    def test_a_decided_action_cannot_be_reached_through_a_code(self):
        """The lifecycle is the same door: an intent needs a *pending* action on the notified incident."""
        self.store.decide(self.action, 'denied', Actor('operator', 'human'), now=self.now)
        code = self.code()
        refused = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action})
        self.assertEqual((refused[1]['error'], refused[1]['detail']), ('conflict', 'Action is not pending'))
        self.assertEqual(self.audits('action.approval_intent'), [])

    def test_an_expired_action_cannot_be_approved_by_a_code_that_is_still_live(self):
        """The two clocks are separate, and the tighter one wins: a live code cannot revive an action.

        The code's window and the action's `expires_at` are set independently — CONTRACTS §5's "Approval
        expiry prevents a new dispatch but does not erase a running action" has the mirror case here:
        an approval that aged out is not re-opened by a message that is still in time.
        """
        self.store.expire_actions(now=self.now + dt.timedelta(hours=2))
        code = self.code()
        refused = self.post('/v1/callbacks/primary', {'token': code, 'action_id': self.action})
        self.assertEqual((refused[0], refused[1]['detail']), (400, 'Action is not pending'))
        self.assertEqual(self.action_status(), 'expired', 'the expiry stands')
        self.assertEqual(self.audits('action.approval_intent'), [])

    def test_an_unroutable_channel_or_action_id_is_refused_before_any_lookup(self):
        """The channel label and the action id are validated, never interpolated into a query."""
        code = self.code()
        for path, action_id in (('/v1/callbacks/has spaces', self.action),
                               ('/v1/callbacks/primary%2F..', self.action),
                               ('/v1/callbacks/', self.action),
                               ('/v1/callbacks/primary', 'not-a-uuid')):
            with self.subTest(path=path):
                status, body = self.post(path, {'token': code, 'action_id': action_id})
                self.assertIn(status, (400, 401, 404))
                self.assertNotIn(self.incident, json.dumps(body), 'a refusal echoes no identifiers')
        self.assertEqual(self.audits('action.approval_intent'), [])


class CallbackBoundsTests(unittest.TestCase):
    """The bounds a claim accepts, and which deliveries are issued a code at all."""

    def setUp(self):
        """Open a live-mode store with one queued delivery and no action at all."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = scenario_now()
        self.store = self.open('lifecycle', POLICY)

    def open(self, name: str, policy: NotificationPolicy) -> Store:
        """Create one store holding a single queued delivery for `test-detector`."""
        store = Store(self.root / (name + '.db'), policy)
        window = {'start': utc_text(self.now - dt.timedelta(seconds=1)), 'end': utc_text(self.now)}
        store.intake(event('test-detector', None, 'availability', 'availability', 'firing', window,
                          {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=self.now)
        return store

    def test_the_callback_lifetime_is_bounded_at_the_claim(self):
        """The default is the hour the README names, and the bounds are enforced at the door.

        Each assertion takes its own store: a claim holds a lease, and a second claim of the same row at
        the same instant is a refusal, not a second token — which is the point, but not the one here.
        """
        default_claim = self.open('default', POLICY).claim_notification(now=self.now)
        self.assertEqual(timestamp(default_claim['callback']['expires_at']) - self.now,
                         dt.timedelta(hours=1))
        short = self.open('short', POLICY).claim_notification(now=self.now, callback_seconds=60)
        self.assertEqual(timestamp(short['callback']['expires_at']) - self.now, dt.timedelta(seconds=60))
        for seconds in (5, 0, -1, 86401, 10 ** 9):
            with self.subTest(seconds=seconds), self.assertRaisesRegex(StateError, 'Callback lifetime'):
                self.open('bad-%s' % seconds, POLICY).claim_notification(now=self.now, callback_seconds=seconds)

    def test_a_sink_bound_delivery_is_issued_no_code_at_all(self):
        """Nothing that cannot reach a human carries an approval code.

        The code is a key to an intent. Minting one for a row that goes to a local sink would put a live
        secret on a delivery nobody received — and in `recording` mode, where nothing leaves the host,
        every row would carry one.
        """
        for name, policy in (('recording', NotificationPolicy(delivery_mode='recording')),
                             ('synthetic', NotificationPolicy(delivery_mode='live',
                                                             synthetic_sources=('test-detector',)))):
            with self.subTest(mode=name):
                store = self.open(name, policy)
                claim = store.claim_notification(now=self.now)
                self.assertNotEqual(claim['destination'], 'human')
                self.assertNotIn('callback', claim)
                with closing(sqlite3.connect(store.path)) as db:
                    stored = db.execute('SELECT callback_token_hash, callback_expires_at FROM outbox'
                                        ' WHERE id=?', (claim['id'],)).fetchone()
                self.assertEqual(stored, ('', None), 'no hash and no expiry: nothing was minted')

    def test_an_off_or_recording_store_mints_nothing_and_refuses_nothing(self):
        """`off` still queues rows; a code is only ever minted by a claim that can reach a human."""
        store = self.open('off', NotificationPolicy(delivery_mode='off'))
        self.assertEqual(store.claim_notification(now=self.now)['suppressed'], 'notifications-disabled')
        self.assertEqual(store.status()['notifications'], {'dead': 1})

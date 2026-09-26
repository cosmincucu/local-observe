"""chat integration's refusal matrix: the chat surface may propose, read and wait — and that is all it may do.

integration validation names four checks for the chat/AI plane: *"validate authentication, tool calls, approval
separation
and operation without Telegram."* Authentication and operation-without-Telegram are properties of the
transport and of the shipped tree; they are pinned in `tests/test_chat_component.py` and over the
existing transport tests. **This file is the third check, and it is the one that decides whether the
component is allowed to exist**: phone surface makes chat the phone surface for approvals, and an approval
surface that can approve its own proposals is not an approval surface.

What is tested here is the platform boundary a chat surface stands at — a per-agent credential whose
role is `proposer` and whose identity is `chat-<label>`. That boundary is real and ships today, so the
matrix below runs today. What is **not** tested here, and is not silently skipped either: the leg that
starts inside AnythingLLM and calls a tool. The tools are not the missing half — mcp tool surface landed
`platform/tools.py::agent_registry` with exactly one gated pair (`propose_action` -> `execute_action`,
role-gated, and the action execution boundary made that second half refuse before any platform request) — but no shipped
image installs the optional `mcp` extra and `components/control/mcp/` does not exist, so there is no
container for the call to arrive from. MCP component  owns that service and is unclaimed; this item's
brief says *"if the gated pair is missing, block, do not build it here"*, and the half that is missing
here stays unbuilt rather than being built sideways. Rows 6-8 of
`components/control/chat/conformance.md` carry that as `blocked-on-MCP component`.

Two words used below, because the difference is the whole subject: an **intent** is what a spent
notification callback records (`action.approval_intent`, action still `pending`); a **decision** is what
`POST /v1/actions/decision` writes, and only a `human` credential may post it.

Fixtures follow `tests/test_notification_callbacks.py`: a real `Store` on a temp path and the ASGI app
driven directly, so the lifespan delivery loop never runs and no socket is opened.
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

from local_observe.inventory.validation import utc_text
from local_observe.platform.api import create_app
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store

# The scenario clock, taken from the real wall clock rather than a fixed date — the same fixture
# decision `tests/test_notification_callbacks.py` records and for the same reason: the routes below go
# through HTTP, where `Store.decide`/`record_callback` read their own time and accept no caller
# supplied `now`. A fixed constant an hour in the past makes every one of those calls land after the
# proposal's expiry, and the suite then reports "expired" where it meant "denied".
NOW = dt.datetime.now(dt.timezone.utc)
# The credential the chat surface would hold, spelled the way it will be issued: one platform role
# credential, `proposer`, named for the surface rather than for a person. `chat-` is a convention in
# this file, not a rule in the code — the code cannot tell a chat proposer from any other, which is
# CONTRACT.md section 4's point and the reason the audit identity has to be a *label* and not a role.
CHAT = {'identity': 'chat-anythingllm', 'role': 'proposer', 'token': 'c' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
RUNNER = {'identity': 'dagu-runner', 'role': 'executor', 'token': 'e' * 32}
READER = {'identity': 'dashboard', 'role': 'reader', 'token': 'r' * 32}
SUMMARY = {'identity': 'portal', 'role': 'summary', 'token': 's' * 32}
CREDENTIALS = [CHAT, HUMAN, RUNNER, READER, SUMMARY]
CHAT_ACTOR = Actor(CHAT['identity'], 'proposer')
HUMAN_ACTOR = Actor(HUMAN['identity'], 'human')
RUNNER_ACTOR = Actor(RUNNER['identity'], 'executor')
# One target for the whole file: `propose_action` fingerprints the entire request, so a test of
# retry-key idempotence that regenerated its target uuid would be testing the fingerprint instead.
TARGET = str(uuid.UUID('2f8a1b6c-0000-4000-8000-000000000001'))
SILENT = NotificationPolicy(delivery_mode='off', max_attempts=20, max_event_age_seconds=86400)
LOUD = NotificationPolicy(delivery_mode='live', max_attempts=20, max_event_age_seconds=86400)


def allowlist(request: dict) -> None:
    """Stand in for the deployment action allowlist: this file is about who may decide, not what."""


async def _call(app, method: str, path: str, token: str | None, body: bytes = b'') -> tuple[int, dict]:
    """Drive one request through the ASGI app with no lifespan, no delivery loop and no socket."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)
    headers = [] if token is None else [(b'authorization', ('Bearer ' + token).encode())]
    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers,
               'query_string': b''}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class Scenario(unittest.TestCase):
    """One open incident and one proposal, with the helpers every subclass reads state the same way."""

    policy = SILENT

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'platform.db'
        self.store = Store(self.path, self.policy)
        self.app = create_app(self.store, CREDENTIALS, allowlist)
        self.incident, self.evidence = self.open_incident()

    # --- fixtures -----------------------------------------------------------------------------

    def post(self, path: str, body, token: str | None = CHAT['token']) -> tuple[int, dict]:
        """One POST through the app, as the chat credential unless the caller says otherwise."""
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return asyncio.run(_call(self.app, 'POST', path, token, raw))

    def get(self, path: str, token: str = READER['token']) -> tuple[int, dict]:
        """One GET through the app — the read path any client, chat included, answers from."""
        return asyncio.run(_call(self.app, 'GET', path, token))

    def open_incident(self, source: str = 'synthetics') -> tuple[str, str]:
        """Intake one firing event and return the incident it opened plus the event inside it."""
        window = {'start': utc_text(NOW - dt.timedelta(seconds=1)), 'end': utc_text(NOW)}
        result = self.store.intake(event(source, None, 'availability', 'availability', 'firing', window,
                                        {'sample_id': 'fixture'}, query_type='gatus-result'),
                                   Actor(source, 'producer'), now=NOW)
        return result['incident_id'], result['event_id']

    def propose(self, *, retry_key: str = 'restart-1', target: str = TARGET,
                expires: dt.timedelta = dt.timedelta(hours=1)) -> str:
        """Propose one bounded action as the chat credential and return its id."""
        return self.store.propose_action(
            {'retry_key': retry_key, 'incident_id': self.incident, 'action': 'restart-service',
             'version': '1', 'targets': [target], 'parameters': {},
             'evidence': [self.evidence], 'expires_at': utc_text(NOW + expires)},
            CHAT_ACTOR, allowlist, now=NOW)['action_id']

    def audits(self, operation: str) -> list[dict]:
        """The audit rows of one operation, oldest first, straight from the append-only table."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            return [dict(row) for row in db.execute(
                'SELECT at, actor, operation, subject, detail FROM audit WHERE operation=?'
                ' ORDER BY sequence', (operation,))]

    def status_of(self, action_id: str) -> str:
        """An action's status as the file has it, not as a view rendered it."""
        with closing(sqlite3.connect(self.store.path)) as db:
            return db.execute('SELECT status FROM actions WHERE id=?', (action_id,)).fetchone()[0]

    def record_rows(self, action_id: str) -> list[dict]:
        """What a reader — the chat surface included — sees when it asks for the action record."""
        status, body = self.get('/v1/records/actions')
        self.assertEqual(status, 200)
        return [row for row in body['rows'] if row.get('id') == action_id]


class IdentityTests(Scenario):
    """integration validation clause 1: authentication, and the identity an audit row is allowed to carry."""

    def test_an_unauthenticated_proposal_is_refused_and_writes_no_row(self):
        """No bearer, no writer. This is the boundary a public chat surface must never be able to cross."""
        body = {'retry_key': 'x', 'incident_id': self.incident, 'action': 'restart-service',
                'version': '1', 'targets': [TARGET], 'parameters': {},
                'evidence': [self.evidence], 'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        self.assertEqual(self.post('/v1/actions', body, token=None),
                         (401, {'error': 'authentication_required'}))
        self.assertEqual(self.audits('action.proposed'), [])

    def test_the_audit_row_names_the_credential_and_nothing_the_body_claimed(self):
        """docs/CONTRACTS.md §5: identity comes from authenticated transport.

        The body carries no identity field at all, and `docs/CONTRACTS.md` §5's sentence
        *"payload fields cannot claim that an agent is a human"* is enforced by the closed field set:
        a proposal naming an approver is a shape error, not a person.
        """
        action = self.propose()
        rows = self.audits('action.proposed')
        self.assertEqual([(row['actor'], row['subject']) for row in rows],
                         [(CHAT['identity'], action)],
                         'the audit trail says which agent asked, which is what per-agent tokens are for')
        claimed = {'retry_key': 'claimant', 'incident_id': self.incident, 'action': 'restart-service',
                   'version': '1', 'targets': [TARGET], 'parameters': {},
                   'evidence': [self.evidence], 'expires_at': utc_text(NOW + dt.timedelta(hours=1)),
                   'approver': HUMAN['identity']}
        status, refused = self.post('/v1/actions', claimed)
        self.assertEqual((status, refused['error'], refused['detail']),
                         (400, 'invalid_request', 'Invalid action request fields'),
                         'a body field naming a human must not become an identity')
        self.assertEqual(len(self.audits('action.proposed')), 1)

    def test_the_role_the_surface_thinks_it_has_is_the_one_the_credential_carries(self):
        """/v1/me is the surface's only self-knowledge, and it is the server's answer, not its own."""
        self.assertEqual(self.get('/v1/me', CHAT['token'])[1],
                         {'identity': CHAT['identity'], 'role': 'proposer'})
        self.assertEqual(self.get('/v1/me', HUMAN['token'])[1],
                         {'identity': HUMAN['identity'], 'role': 'human'})


class ChatCannotApproveTests(Scenario):
    """integration validation clause 3, spelled as the refusals. Every one of these is a live route, not a hypothetical."""

    def test_the_positive_control_a_proposer_may_propose(self):
        """Without this the refusals below could be passing because nothing works at all."""
        action = self.propose()
        self.assertEqual(self.status_of(action), 'pending')
        self.assertEqual(self.store.status()['actions'], {'pending': 1})

    def test_a_chat_credential_cannot_approve_its_own_proposal(self):
        action = self.propose()
        status, body = self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'})
        self.assertEqual((status, body['error']), (400, 'not_authorised'))
        self.assertEqual(self.status_of(action), 'pending', 'a refusal changes no lifecycle state')
        refused = self.audits('action.refused')
        self.assertEqual([(row['actor'], row['subject']) for row in refused],
                         [(CHAT['identity'], action)],
                         'the refusal is durable state naming who tried (docs/CONTRACTS.md §5)')
        self.assertEqual(json.loads(refused[0]['detail']),
                         {'attempt': 'decide', 'reason': 'actor-not-authorised', 'role': 'proposer'})

    def test_a_chat_credential_cannot_deny_one_either(self):
        """Denial is a decision too. A surface that could silence its own proposal has the same power."""
        action = self.propose()
        self.assertEqual(self.post('/v1/actions/decision',
                                   {'action_id': action, 'decision': 'denied'})[1]['error'],
                         'not_authorised')
        self.assertEqual(self.status_of(action), 'pending')

    def test_a_chat_credential_cannot_dispatch_even_an_action_a_human_approved(self):
        """The `execute_action` half of MCP component's pair, asserted at the only layer that exists today."""
        action = self.propose()
        self.assertEqual(self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'},
                                   HUMAN['token'])[0], 200)
        status, body = self.post('/v1/actions/claim', {'action_id': action})
        self.assertEqual((status, body['error']), (400, 'not_authorised'))
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM executions').fetchone()[0], 0,
                             'a proposer may not create an execution claim')
        refused = [row for row in self.audits('action.refused') if row['subject'] == action]
        self.assertEqual(json.loads(refused[-1]['detail']),
                         {'attempt': 'claim', 'reason': 'actor-not-authorised', 'role': 'proposer'},
                         'the claim refusal is as durable as the decide refusal (docs/CONTRACTS.md §5)')

    def test_the_runner_can_claim_what_the_surface_could_not(self):
        """The permission must be real somewhere, or the refusal above is just a broken platform."""
        action = self.propose()
        self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'},
                  HUMAN['token'])
        claim = self.store.claim_action(action, RUNNER_ACTOR, allowlist, now=NOW)
        self.assertEqual(claim['status'], 'executing')
        self.assertEqual(self.status_of(action), 'executing')

    def test_a_summary_credential_is_turned_away_before_its_body_is_read(self):
        """The portal's read-only role must not be able to reach the decision route at all."""
        action = self.propose()
        status, body = self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'},
                                 SUMMARY['token'])
        self.assertEqual((status, body['error']), (403, 'summary_only'))
        self.assertEqual(self.status_of(action), 'pending')
        # The transport writes one row for this denial too, with its own reason word — it is the only
        # record of a refusal that never entered `Store`. tests/test_refusal_audit_lifecycle.py owns
        # the lifecycle of that write (off the serving loop, one slot, shed when busy); this asserts
        # only that the chat surface's denial is named for what it was.
        refused = self.audits('action.refused')
        self.assertEqual([(row['actor'], json.loads(row['detail'])) for row in refused],
                         [(SUMMARY['identity'],
                           {'attempt': 'decide', 'reason': 'summary-only', 'role': 'summary'})],
                         'a summary denial and a lifecycle refusal carry different reason words')

    def test_a_callback_spent_by_the_chat_credential_is_an_intent_and_not_a_decision(self):
        """The one route a `proposer` token is admitted to, pinned from the chat surface's side.

        Same ground as `tests/test_notification_callbacks.py`, seen from the other end: the code's
        audience is the phone, so a chat token that could spend one would put a machine's name on an
        intent to approve. What keeps that survivable is that the intent decides nothing — the action
        stays `pending` and the human route stays the only door.
        """
        live = tempfile.TemporaryDirectory()
        self.addCleanup(live.cleanup)
        self.store = Store(Path(live.name) / 'platform.db', LOUD)
        self.app = create_app(self.store, CREDENTIALS, allowlist)
        self.incident, self.evidence = self.open_incident()
        action = self.propose()
        claim = self.store.claim_notification(now=NOW)
        self.assertIsNotNone(claim, 'a live, eligible delivery must be claimable for this to mean anything')
        self.store.finish_notification(claim['id'], claim['claim_token'], True, now=NOW)
        self.assertIsNotNone(claim['callback'], 'the delivery must have minted an approval code')
        code = claim['callback']['token']
        status, body = self.post('/v1/callbacks/' + claim['channel'],
                                {'token': code, 'action_id': action})
        self.assertEqual(status, 200)
        self.assertIs(body['decided'], False)
        self.assertEqual(self.status_of(action), 'pending')
        self.assertEqual(self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'},
                                   HUMAN['token'])[0], 200, 'the human decision still works afterwards')
        self.assertEqual(self.status_of(action), 'approved')


class RoundTripTests(Scenario):
    """The §5 "Approved action" scenario's shape, with the answer read back from the record.

    CONTRACT.md section 5's seven edges, minus the two that need a container and an unbuilt tool. What
    is pinned here is the clause that makes the chat answer worth reading at all: after a decision the
    only status available to any client is the recorded one.
    """

    def test_a_denied_action_reads_as_denied_to_every_reader(self):
        action = self.propose()
        self.assertEqual(self.post('/v1/actions/decision', {'action_id': action, 'decision': 'denied'},
                                   HUMAN['token'])[0], 200)
        rows = self.record_rows(action)
        self.assertEqual([row['status'] for row in rows], ['denied'],
                         'the record is the answer; a model sentence that disagrees is wrong')
        self.assertEqual(self.store.status()['actions'], {'denied': 1})

    def test_a_full_round_trip_ends_in_the_recorded_outcome(self):
        action = self.propose()
        self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'}, HUMAN['token'])
        claim = self.store.claim_action(action, RUNNER_ACTOR, allowlist, now=NOW)
        outcome = self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER_ACTOR,
                                              claim['runner_token'], now=NOW)
        self.assertEqual(outcome['status'], 'succeeded')
        self.assertEqual([row['status'] for row in self.record_rows(action)], ['succeeded'])
        self.assertEqual(self.audits('execution.succeeded')[0]['actor'], RUNNER['identity'])
        # The chat credential can read the outcome it did not cause and could not produce.
        refused = self.post('/v1/executions/outcome',
                            {'execution_id': claim['execution_id'], 'outcome': 'succeeded'})
        self.assertEqual(refused[1]['error'], 'not_authorised',
                         'a proposer may not record an outcome either')

    def test_the_proposal_carries_the_evidence_it_cited_and_refuses_one_it_did_not(self):
        """`evidence` is a bound reference list, so a proposal from chat is checkable, not narratable."""
        status, body = asyncio.run(_call(self.app, 'POST', '/v1/actions', CHAT['token'], json.dumps(
            {'retry_key': 'invented', 'incident_id': self.incident, 'action': 'restart-service',
             'version': '1', 'targets': [TARGET], 'parameters': {},
             'evidence': [str(uuid.uuid4())],
             'expires_at': utc_text(NOW + dt.timedelta(hours=1))}).encode()))
        self.assertEqual((status, body['error'], body['detail']),
                         (400, 'invalid_request', 'Action evidence must belong to incident'))

    def test_a_second_identical_proposal_is_idempotent_and_a_changed_one_is_refused(self):
        """A chat surface that retries on a timeout must not create two approvals to decide."""
        first = self.propose()
        again = self.propose()
        self.assertEqual(again, first, 'same requester + same retry_key returns the same action')
        with self.assertRaisesRegex(StateError, 'changed contents'):
            self.store.propose_action(
                {'retry_key': 'restart-1', 'incident_id': self.incident, 'action': 'restart-service',
                 'version': '2', 'targets': [TARGET], 'parameters': {},
                 'evidence': [self.evidence], 'expires_at': utc_text(NOW + dt.timedelta(hours=1))},
                CHAT_ACTOR, allowlist, now=NOW)


class ExpiryTests(Scenario):
    """chat integration's *"expire-unanswered"*, wired to the `expires_at` that already exists (task 4)."""

    def test_an_unanswered_proposal_expires_once_and_is_audited_once(self):
        action = self.propose()
        expired = self.store.expire_actions(now=NOW + dt.timedelta(hours=2))
        self.assertEqual(expired, 1)
        self.assertEqual(self.status_of(action), 'expired')
        rows = self.audits('action.expired')
        self.assertEqual([(row['actor'], row['subject']) for row in rows], [('platform', action)],
                         'the expiry is the platform speaking, not the surface')
        self.assertEqual(self.store.expire_actions(now=NOW + dt.timedelta(hours=3)), 0,
                         'an expired action does not expire a second time')

    def test_a_late_human_answer_records_expired_rather_than_the_click(self):
        """The clause that makes the phone safe to be late: no resurrection, and the name is kept."""
        action = self.propose(expires=dt.timedelta(minutes=5))
        decided = self.store.decide(action, 'approved', HUMAN_ACTOR, now=NOW + dt.timedelta(minutes=30))
        self.assertEqual(decided['status'], 'expired')
        self.assertEqual(self.status_of(action), 'expired')
        self.assertEqual(self.audits('action.expired')[0]['actor'], HUMAN['identity'],
                         'the row says whose late click was not honoured')
        self.assertEqual(self.audits('action.approved'), [], 'no approval happened, and none is claimed')

    def test_expiry_prevents_a_new_dispatch_and_cannot_erase_a_running_one(self):
        """docs/CONTRACTS.md §5: *"Approval expiry prevents a new dispatch but does not erase a
        running action."*"""
        action = self.propose(expires=dt.timedelta(minutes=5))
        self.post('/v1/actions/decision', {'action_id': action, 'decision': 'approved'}, HUMAN['token'])
        claim = self.store.claim_action(action, RUNNER_ACTOR, allowlist,
                                       now=NOW + dt.timedelta(minutes=1))
        self.assertEqual(claim['status'], 'executing')
        # The action was already claimed inside its window; a later expiry pass leaves the execution.
        self.assertEqual(self.store.expire_actions(now=NOW + dt.timedelta(hours=2)), 0)
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute('SELECT status FROM executions').fetchone()[0], 'executing',
                             'a running action is not silently expired out from under its runner')

    def test_the_window_the_platform_will_accept_is_bounded_at_24_hours(self):
        """The upper bound of expire-unanswered: nothing may be proposed that stays pending for a week."""
        with self.assertRaisesRegex(StateError, 'expiry must be in the next 24 hours'):
            self.store.propose_action(
                {'retry_key': 'long', 'incident_id': self.incident, 'action': 'restart-service',
                 'version': '1', 'targets': [TARGET], 'parameters': {},
                 'evidence': [self.evidence],
                 'expires_at': utc_text(NOW + dt.timedelta(days=8))},
                CHAT_ACTOR, allowlist, now=NOW)
        self.assertEqual(self.audits('action.proposed'), [])


class StatementTests(Scenario):
    """The two halves of chat integration's approver recommendation, separated on the page.

    *expire-unanswered* is in force (ExpiryTests). The *"tiny reversible allowlist"* is not, and this
    class exists so the absence is a named fact in the tree rather than a reader's discovery: it would
    be an action that needs no human, which is a new authority mechanism on `state.py`/`policy.py`, not
    a chat manifest, and it collides with MCP component's "exactly one pair" rule. It is filed as a card for the
    reviewer in WORKER-REPORT.md and named in CONTRACT.md section 5.
    """

    def test_no_auto_approval_path_exists_in_the_product_today(self):
        """Nothing may mark an action approved without a human credential, so nothing does.

        Three assertions, each weaker than it looks and each named: no `action.auto_approved`-shaped
        operation string appears anywhere in the store module, none appears in this scenario's audit
        table, and nothing in the scenario was approved. That is an absence in one file plus one run, not
        a proof about the product — which is exactly why the test below reads `decide`'s role gate
        directly instead of trusting this one.
        """
        from local_observe.platform import state
        source = Path(state.__file__).read_text(encoding='utf-8')
        for operation in ('action.auto_approved', 'action.allowlisted', 'action.pre_approved'):
            with self.subTest(operation=operation):
                self.assertNotIn(operation, source,
                                 'a row like this is the only trace an auto-approval could leave')
                self.assertEqual(self.audits(operation), [])
        self.assertEqual([row['operation'] for row in self.audits('action.approved')], [])

    def test_the_decision_route_admits_human_alone(self):
        """One line of code is the whole mechanism; pinned so a widening here is a deliberate act."""
        from local_observe.platform import state
        source = Path(state.__file__).read_text(encoding='utf-8')
        decide_body = source.split('def decide(')[1].split('def claim_action(')[0]
        self.assertIn("require(actor, 'human')", decide_body)
        self.assertNotIn("'proposer'", decide_body,
                         'widening decide to a proposer is the exact change this component exists to '
                         'refuse; it needs a decision, not a commit')


if __name__ == '__main__':
    unittest.main()

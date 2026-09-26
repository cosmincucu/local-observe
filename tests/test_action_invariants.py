"""remediation invariants: adversarial invariants for the action lifecycle — attempt the bad thing, assert the refusal.

Every test here is written the same way: *try* to make the platform do something it must never do,
then assert both the refusal and what the durable record says afterwards. Nothing in this file
exercises a happy path for its own sake; the happy paths are `tests/test_platform.py`'s. This is the
half that v0.1 only learned after an adversarial review found a critical issue its green suite could
not see, which is why the invariants are written down as tests rather than as prose.

Read `local_observe/platform/verification.py`'s module docstring for the invariant list in words;
each invariant is named in a test docstring here. `test_a_refused_attempt_leaves_a_durable_audit_row`
was the one test marked `@unittest.expectedFailure` — **a finding, not coverage**: it asserted a durability
property the old `state.py`/`api.py` did not provide, so a fix would turn it into an unexpected pass (which
`tests/tiers.py` fails the tier on) and nobody would have to re-derive the gap. **The refusal audit closed it**:
every refusal at the action boundary now writes one append-only `action.refused` row of its own, the marker
is gone, and the assertion is an invariant. The approval firewall asserted below is the one
`docs/CONTRACTS.md` §5 actually states — an action is decided only by a credential whose authenticated
role is `human`, and an agent credential decides nothing, including an action it proposed. §5 does not
require two distinct humans and v0.1's policy did not reject a human who proposed, so nothing here
asserts an identity-level rule that no contract asks for.

Two boundaries are attacked on purpose: `Store`'s own public methods, and the ASGI surface in
`api.create_app` (driven in-process with `httpx`, no server, no socket) — because the payload claim
("a body field cannot make an agent a human") can only be tested at the edge that reads bodies.
Nothing here writes to a live database, opens a network connection or imports an optional package.
"""
import asyncio
import datetime as dt
import hashlib
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import dagu, detections, verification
from local_observe.platform.api import create_app
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store
from local_observe.store import client as facade
from local_observe.store.client import MetricSample, Window, build_outcome, describe_query, utc_text as store_utc_text

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
LATER = NOW + dt.timedelta(hours=2)
PRODUCER = Actor('test-detector', 'producer')
AGENT = Actor('agent-1', 'proposer')
HUMAN = Actor('operator', 'human')
RUNNER = Actor('runner-1', 'executor')
READER = Actor('reader-1', 'reader')
# The series the verification half judges: still above its threshold, so a mechanical success must
# not read as a recovery.
SERIES = 'lo_cpu'


class FakePlatform:
    """The platform service as `dagu.execute` sees it: it can refuse the claim, which is the point."""

    def __init__(self, claim_code=200, claim=None):
        self.claims = 0
        self.outcomes = []
        self.claim_code = claim_code
        self.claim = claim

    def request(self, method, path, payload=None):
        if path.endswith('/v1/actions/claim'):
            self.claims += 1
            if self.claim_code != 200:
                return self.claim_code, {'error': 'conflict'}
            return 200, self.claim
        if path.endswith('/v1/executions/outcome'):
            self.outcomes.append(dict(payload))
            return 200, {'status': payload['outcome']}
        return 404, {'error': 'not_found'}


class FakeDagu:
    """The DAG engine as `dagu.execute` sees it: every dispatch is counted, and a lost ack is scripted."""

    def __init__(self, spec='fixture', result='running', lost_ack=False):
        self.starts = 0
        self.methods = []
        self.spec = spec
        self.result = result
        self.lost_ack = lost_ack
        self.run_id = None

    def request(self, method, path, payload=None):
        from local_observe.http import TransportError
        self.methods.append((method, path))
        if path.endswith('/spec'):
            return 200, {'spec': self.spec}
        if path.endswith('/start'):
            self.starts += 1
            self.run_id = payload['dagRunId']
            if self.lost_ack:
                raise TransportError('Dispatch acknowledgement lost')
            return 200, {'dagRunId': self.run_id}
        return 200, {'dagRunDetails': {'name': 'inspect', 'dagRunId': self.run_id,
                                       'statusLabel': self.result}}


def reviewed_binding(targets=None, spec='fixture'):
    return {'action': 'inspect', 'version': '1', 'targets': targets or ['fixture'], 'dag': 'inspect',
            'sha256': hashlib.sha256(spec.encode()).hexdigest()}


def reviewed_request(targets=None):
    return {'action': 'inspect', 'version': '1', 'targets': targets or ['fixture'], 'parameters': {}}


def answered_store(value, *, minutes_before_end=1):
    """A store facade double that answers the verification read with exactly one sample.

    The answer is built by `store.client.build_outcome`, the same function the real backends use, so
    the receipt this test hands to `verification.check` carries a real window, real approved
    parameters and a real row count — it is not a shape invented for the test.
    """
    class Answering:
        def __init__(self):
            self.reads = []

        def read(self, query_type, *, window, parameters, selectors=None, expires_at=None,
                 store_ttl_hours=None):
            self.reads.append((query_type, dict(parameters), dict(selectors or {}), window))
            kind = describe_query(query_type)
            stamp = facade.parse_ts(window.end) - dt.timedelta(minutes=minutes_before_end)
            row = MetricSample(name=selectors['metric_name'], value=value,
                               resource_id=parameters['resource_id'],
                               labels={'resource_id': parameters['resource_id']},
                               timestamp=store_utc_text(stamp))
            return build_outcome(kind, dict(parameters), Window(start=window.start, end=window.end), [row])

    return Answering()


class ActionInvariantTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'state.db')
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})

    # ---------------------------------------------------------------- fixtures

    def event(self, status='firing', minute=0):
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        return detections.event(PRODUCER.identity, self.host, 'availability', 'availability', status,
                                window, {'sample_id': f'fixture-{minute}'}, query_type='gatus-result')

    def open_incident(self, minute=0, status='firing'):
        return self.store.intake(self.event(status, minute), PRODUCER, now=NOW + dt.timedelta(minutes=minute))

    def proposed(self, retry_key='once', actor=AGENT, minute=0):
        result = self.open_incident(minute=minute)
        request = {'retry_key': retry_key, 'incident_id': result['incident_id'], 'action': 'inspect',
                   'version': '1', 'targets': [self.host], 'parameters': {},
                   'evidence': [result['event_id']], 'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        return self.store.propose_action(request, actor, self.policy, now=NOW)['action_id']

    def approved(self, retry_key='once'):
        action_id = self.proposed(retry_key=retry_key)
        self.store.decide(action_id, 'approved', HUMAN, now=NOW)
        return action_id

    def audits(self, operation=None):
        rows = self.store.records('audit', 100)
        return [row for row in rows if operation is None or row['operation'] == operation]

    def action_row(self, action_id):
        return next(row for row in self.store.records('actions', 100) if row['id'] == action_id)

    def execution_rows(self):
        return self.store.records('executions', 100)

    def asgi(self, credentials, exercise):
        """Drive one in-process ASGI exchange against the real app; no server, no socket, no uvicorn."""
        import httpx

        async def drive():
            app = create_app(self.store, credentials, self.policy)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                        base_url='http://platform.invalid') as client:
                await exercise(client)
        asyncio.run(drive())

    # ------------------------------------------------- invariant 1: self-approval

    def test_agent_principal_cannot_approve_any_action(self):
        """No role but `human` decides an action — including the principal that proposed it."""
        action_id = self.proposed()
        for actor in (AGENT, RUNNER, READER, Actor('summary-1', 'summary')):
            with self.assertRaises(StateError) as caught:
                self.store.decide(action_id, 'approved', actor, now=NOW)
            self.assertIn('not authorised', str(caught.exception))
        self.assertEqual(self.action_row(action_id)['status'], 'pending')
        self.assertEqual(self.audits('action.approved'), [])
        self.assertEqual([row['actor'] for row in self.audits('action.proposed')], [AGENT.identity])

        # The same attempt at the HTTP edge, with the proposer's own token and a correct body shape.
        token = 'proposer-token-for-tests-00000000'
        credentials = [{'identity': AGENT.identity, 'role': 'proposer', 'token': token}]

        async def exercise(client):
            response = await client.post('/v1/actions/decision', headers={'Authorization': 'Bearer ' + token},
                                        json={'action_id': action_id, 'decision': 'approved'})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()['error'], 'not_authorised')
        self.asgi(credentials, exercise)
        self.assertEqual(self.action_row(action_id)['status'], 'pending')

        # A human clears it, and the audit names the human — not the principal that asked.
        self.assertEqual(self.store.decide(action_id, 'approved', HUMAN, now=NOW), {'status': 'approved'})
        self.assertEqual([row['actor'] for row in self.audits('action.approved')], [HUMAN.identity])

    def test_no_actor_that_is_not_an_authenticated_human_role_decides(self):
        """The state layer's own gate, one argument at a time: role `human`, from an `Actor`, or nothing.

        This is the firewall CONTRACTS §5 states — "Human identity is obtained from authenticated
        transport; payload fields cannot claim that an agent is a human" — asserted on the side the
        payload cannot reach. Every input below names an identity and a role string that is not the
        role, or is not an actor at all: the action stays pending, no `action.approved` row is written,
        and the last line proves the gate is not simply refusing everything (which would be a broken
        test, not a secure one).
        """
        action_id = self.proposed()

        class NotAnActor:
            identity, role = 'operator', 'human'

        for actor in (None, 'human', {'identity': 'operator', 'role': 'human'}, NotAnActor(),
                      Actor('operator', 'human '), Actor('operator', 'Human'),
                      Actor('operator', 'operator'), Actor('operator', 'superhuman'),
                      Actor('operator', 'proposer'), Actor('operator', 'executor'),
                      Actor('operator', 'reader'), Actor('operator', 'summary'),
                      Actor('operator', 'producer'), Actor('operator', ''), Actor('', 'human'),
                      Actor(None, 'human')):
            with self.subTest(repr(actor)):
                with self.assertRaises(StateError) as caught:
                    self.store.decide(action_id, 'approved', actor, now=NOW)
                self.assertIn('not authorised', str(caught.exception))
        self.assertEqual(self.action_row(action_id)['status'], 'pending')
        self.assertEqual(self.audits('action.approved'), [])
        # Positive control: the one spelling the platform uses for a human clears the same action.
        self.assertEqual(self.store.decide(action_id, 'approved', HUMAN, now=NOW), {'status': 'approved'})
        self.assertEqual([row['actor'] for row in self.audits('action.approved')], [HUMAN.identity])

    def test_a_human_who_proposed_may_approve_and_both_sides_are_durable(self):
        """What §5 permits, pinned so nobody "fixes" it by inventing a rule no contract asks for.

        §5 binds the approval request to a **requester identity** and requires the deciding identity to
        come from authenticated transport as a human; it does not require a second human, and v0.1's
        policy rejected *agent* approvers for the same reason this one does. The control §5 does require
        is that the identity is durable and attributable — so it is asserted here: `actions.requester`
        and `actions.decided_by` both survive, the audit row names the approver, and the same credential
        still cannot dispatch (that is the executor role's) or decide an agent's request.
        """
        action_id = self.proposed(actor=HUMAN, retry_key='one-human-both-ends')
        self.assertEqual(self.store.decide(action_id, 'approved', HUMAN, now=NOW), {'status': 'approved'})
        row = self.action_row(action_id)
        self.assertEqual((row['requester'], row['decided_by']), (HUMAN.identity, HUMAN.identity))
        self.assertEqual([audit['actor'] for audit in self.audits('action.approved')], [HUMAN.identity])
        self.assertEqual(self.audits('action.proposed')[0]['actor'], HUMAN.identity)
        # Approving is not dispatching: the human credential that opened and cleared this action cannot
        # claim it, and cannot decide an action an agent proposed either.
        with self.assertRaises(StateError) as caught:
            self.store.claim_action(action_id, HUMAN, self.policy, now=NOW)
        self.assertIn('not authorised', str(caught.exception))
        self.assertEqual(self.execution_rows(), [])
        agent_proposed = self.proposed(actor=AGENT, retry_key='agent-proposed', minute=1)
        self.assertEqual(self.store.decide(agent_proposed, 'approved', HUMAN,
                                          now=NOW + dt.timedelta(minutes=1))['status'], 'approved')
        self.assertEqual((self.action_row(agent_proposed)['requester'],
                         self.action_row(agent_proposed)['decided_by']),
                         (AGENT.identity, HUMAN.identity))

    def test_an_unlisted_or_missing_credential_chooses_no_route(self):
        """The token table is the whole trust boundary: nobody is authorised by being absent from it.

        Three parts, all at the ASGI edge the reviewer named: no/contradictory/bogus credentials get 401
        and change nothing; an identity cannot choose which credential it is by the body it sends
        (`/v1/me` answers with the configured pair, which is the same Actor the decision route uses);
        and `create_app` refuses a credential configuration whose role is outside the six it knows — so
        a typo cannot create a seventh role that approves things.
        """
        action_id = self.proposed()
        human = 'human-token-for-tests-000000000000'
        agent = 'proposer-token-for-tests-00000000'
        credentials = [{'identity': AGENT.identity, 'role': 'proposer', 'token': agent},
                       {'identity': HUMAN.identity, 'role': 'human', 'token': human}]
        body = {'action_id': action_id, 'decision': 'approved'}

        async def exercise(client):
            attempts = ({}, {'Authorization': 'Bearer wrong-token-000000000000000000'},
                        {'Authorization': 'Bearer'}, {'Authorization': 'Bearer '},
                        {'Authorization': 'Token ' + human}, {'Authorization': human})
            for headers in attempts:
                response = await client.post('/v1/actions/decision', headers=headers, json=body)
                self.assertEqual(response.status_code, 401, headers)
                self.assertEqual(response.json()['error'], 'authentication_required')
            # A second header naming an operator does not move the identity either: the bearer token
            # still decides who is calling, and that caller is a proposer, so the refusal is the role
            # gate's 400 and not an authentication failure.
            spoofed = await client.post('/v1/actions/decision',
                                        headers={'Authorization': 'Bearer ' + agent, 'X-Identity':
                                                 HUMAN.identity}, json=body)
            self.assertEqual(spoofed.status_code, 400)
            self.assertEqual(spoofed.json()['error'], 'not_authorised')
            # Two Authorization values are not "the stronger one wins"; they are no identity at all.
            doubled = await client.post('/v1/actions/decision',
                                        headers=[('Authorization', 'Bearer ' + human),
                                                 ('Authorization', 'Bearer ' + human)], json=body)
            self.assertEqual(doubled.status_code, 401)
            self.assertEqual(self.action_row(action_id)['status'], 'pending')
            self.assertEqual(self.audits('action.approved'), [])
            who = await client.get('/v1/me', headers={'Authorization': 'Bearer ' + agent})
            self.assertEqual(who.json(), {'identity': AGENT.identity, 'role': 'proposer'})
            decided = await client.post('/v1/actions/decision', headers={'Authorization': 'Bearer ' + human},
                                        json=body)
            # The human credential is not refused as a caller: what it gets back is the platform's own
            # clock rule, because this fixture proposed at a pinned instant and `propose_action` bounds
            # `expires_at` to 24 hours past that instant. "expired" rather than 400 `not_authorised` is
            # exactly the difference between "not you" and "not now", and it is the proof that the two
            # refusals above came from the caller's role and not from the action being unapproachable.
            self.assertEqual(decided.status_code, 200)
            self.assertEqual(decided.json(), {'status': 'expired'})
        self.asgi(credentials, exercise)
        self.assertEqual(self.audits('action.approved'), [])
        self.assertEqual([row['actor'] for row in self.audits('action.expired')], [HUMAN.identity])
        for bad in ([{'identity': 'x', 'role': 'superhuman', 'token': 'x' * 30}],
                    [{'identity': 'x', 'role': 'human', 'token': 'short'}],
                    [{'identity': 'x', 'role': 'human', 'token': 'y' * 30},
                     {'identity': 'z', 'role': 'human', 'token': 'y' * 30}],
                    []):
            with self.subTest(str(bad)):
                with self.assertRaises(ValueError):
                    create_app(self.store, bad, self.policy)

    def test_body_field_cannot_claim_a_human_role(self):
        """CONTRACTS §5: identity comes from the authenticated transport, never from the payload."""
        action_id = self.proposed()
        reader_token = 'reader-token-for-tests-000000000000'
        credentials = [{'identity': READER.identity, 'role': 'reader', 'token': reader_token}]

        async def exercise(client):
            headers = {'Authorization': 'Bearer ' + reader_token}
            for body in ({'action_id': action_id, 'decision': 'approved', 'role': 'human'},
                         {'action_id': action_id, 'decision': 'approved', 'actor': HUMAN.identity},
                         {'action_id': action_id, 'decision': 'approved', 'approver': HUMAN.identity},
                         {'action_id': action_id, 'decision': 'approved', 'authenticated_as': 'operator'}):
                response = await client.post('/v1/actions/decision', headers=headers, json=body)
                # The forged field is outside the declared shape, so the route does not match at all:
                # 404, rather than a 400 that would name the field the caller should not have sent.
                self.assertEqual(response.status_code, 404, body)
            self.assertEqual(self.action_row(action_id)['status'], 'pending')
            self.assertEqual(self.audits('action.approved'), [])
            for row in self.audits():
                self.assertNotIn(HUMAN.identity, row['actor'])
        self.asgi(credentials, exercise)

    def test_read_credentials_cannot_approve_or_execute(self):
        """CONTRACTS §5: "Read tokens cannot approve or execute" — asserted at the HTTP edge."""
        action_id = self.approved()
        reader = 'reader-token-for-tests-000000000001'
        summary = 'summary-token-for-tests-00000000000'
        credentials = [{'identity': READER.identity, 'role': 'reader', 'token': reader},
                       {'identity': 'bot-1', 'role': 'summary', 'token': summary}]

        async def exercise(client):
            for token, expected in ((reader, 400), (summary, 403)):
                headers = {'Authorization': 'Bearer ' + token}
                decide = await client.post('/v1/actions/decision', headers=headers,
                                           json={'action_id': action_id, 'decision': 'approved'})
                claim = await client.post('/v1/actions/claim', headers=headers, json={'action_id': action_id})
                outcome = await client.post('/v1/executions/outcome', headers=headers,
                                            json={'execution_id': str(uuid.uuid4()), 'outcome': 'succeeded'})
                self.assertEqual(decide.status_code, expected, 'a reader/summary token must not approve')
                self.assertEqual(claim.status_code, expected, 'a reader/summary token must not execute')
                self.assertEqual(outcome.status_code, expected, 'a reader/summary token must not report')
            self.assertEqual(self.audits('execution.claimed'), [])
            self.assertEqual(self.execution_rows(), [])
        self.asgi(credentials, exercise)
        # The same action is dispatchable by the executor role at the state layer, so the refusals
        # above are about the credential and not about the action having gone stale.
        self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.assertEqual(len(self.execution_rows()), 1)

    # ------------------------------------------------------ invariant 2: expiry

    def test_expired_approval_blocks_a_new_dispatch(self):
        """An approval that aged out is never granted, and never turns into a claim."""
        action_id = self.proposed()
        self.assertEqual(self.store.decide(action_id, 'approved', HUMAN, now=LATER), {'status': 'expired'})
        self.assertEqual(self.action_row(action_id)['status'], 'expired')
        self.assertEqual(self.audits('action.approved'), [])
        self.assertEqual([row['operation'] for row in self.audits('action.expired')], ['action.expired'])
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, RUNNER, self.policy, now=LATER)
        self.assertEqual(self.execution_rows(), [])

    def test_approved_action_that_expires_before_it_is_claimed_cannot_dispatch(self):
        """Claiming an approved-but-aged action returns `expired`, writes no execution, and is final."""
        action_id = self.approved()
        self.assertEqual(self.store.claim_action(action_id, RUNNER, self.policy, now=LATER),
                         {'status': 'expired'})
        self.assertEqual(self.execution_rows(), [])
        self.assertEqual(self.action_row(action_id)['status'], 'expired')
        self.assertEqual(len(self.audits('action.expired')), 1)
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, RUNNER, self.policy, now=LATER)
        self.assertEqual(len(self.audits('action.expired')), 1)

    def test_expiry_never_interrupts_a_running_execution(self):
        """CONTRACTS §5: "Approval expiry prevents a new dispatch but does not erase a running action"."""
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.assertEqual(self.store.expire_actions(now=NOW + dt.timedelta(days=3)), 0)
        self.assertEqual(self.action_row(action_id)['status'], 'executing')
        self.assertEqual([row['status'] for row in self.execution_rows()], ['executing'])
        self.assertEqual(self.audits('action.expired'), [])
        # The runner can still close its own execution long after the approval expired.
        self.assertEqual(self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER,
                                                     claim['runner_token'], now=LATER)['status'], 'succeeded')

    # -------------------------------------------------- invariant 3: one claim

    def test_second_claim_of_one_action_is_refused(self):
        """The claim is the single-use dispatch gate: refused while running and after the outcome."""
        action_id = self.approved()
        first = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, Actor('runner-2', 'executor'), self.policy, now=NOW)
        self.assertEqual(len(self.execution_rows()), 1)
        self.assertEqual(len(self.audits('execution.claimed')), 1)
        self.assertEqual(self.execution_rows()[0]['id'], first['execution_id'])
        self.store.execution_outcome(first['execution_id'], 'succeeded', RUNNER, first['runner_token'], now=NOW)
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.assertEqual(len(self.execution_rows()), 1)

    def test_dispatch_rechecks_the_policy_gate_and_an_open_incident(self):
        """What was true when the human approved is re-checked at dispatch, and can still refuse."""
        recovering = self.approved(retry_key='recovering')
        action_id = self.approved(retry_key='withdrawn')
        self.declared['resources'][0]['attributes']['remediation_enabled'] = False
        index.build(self.declared, self.index, 'withdrawn', now=NOW)
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.declared['resources'][0]['attributes']['remediation_enabled'] = True
        index.build(self.declared, self.index, 'restored', now=NOW)
        self.store.intake(self.event('resolved', 1), PRODUCER, now=NOW + dt.timedelta(minutes=1))
        with self.assertRaises(StateError):
            self.store.claim_action(recovering, RUNNER, self.policy, now=NOW + dt.timedelta(minutes=1))
        self.assertEqual(self.execution_rows(), [])

    # ------------------------------------------------ invariant 4: runner proof

    def test_wrong_runner_token_is_refused(self):
        """Only the executor that claimed it, holding the token it was given, can report an outcome."""
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        attempts = (
            ('wrong token', lambda: self.store.execution_outcome(claim['execution_id'], 'succeeded',
                                                                 RUNNER, 'guessed', now=NOW)),
            ('no token', lambda: self.store.execution_outcome(claim['execution_id'], 'succeeded',
                                                              RUNNER, None, now=NOW)),
            ('another executor holding the real token',
             lambda: self.store.execution_outcome(claim['execution_id'], 'succeeded',
                                                  Actor('runner-2', 'executor'), claim['runner_token'], now=NOW)),
            ('a human closing a run that is still executing',
             lambda: self.store.execution_outcome(claim['execution_id'], 'succeeded', HUMAN, now=NOW)),
        )
        for label, attempt in attempts:
            with self.assertRaises(StateError, msg=label):
                attempt()
            self.assertEqual([row['status'] for row in self.execution_rows()], ['executing'], label)
        self.assertEqual(self.audits('execution.succeeded'), [])
        self.assertEqual(self.action_row(action_id)['status'], 'executing')
        # The real runner, with its own token, is accepted — once.
        self.assertEqual(self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER,
                                                     claim['runner_token'], now=NOW)['status'], 'succeeded')
        self.assertEqual(len(self.audits('execution.succeeded')), 1)

    def test_an_outcome_is_never_granted_by_repetition(self):
        """A terminal execution is not rewritten by a later report; repeating the same answer is idempotent."""
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.store.execution_outcome(claim['execution_id'], 'failed', RUNNER, claim['runner_token'], now=NOW)
        self.assertEqual(self.action_row(action_id)['status'], 'failed')
        self.assertEqual(self.store.execution_outcome(claim['execution_id'], 'failed', RUNNER,
                                                     claim['runner_token'], now=NOW)['status'], 'failed')
        with self.assertRaises(StateError):
            self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER,
                                         claim['runner_token'], now=NOW)
        self.assertEqual([row['status'] for row in self.execution_rows()], ['failed'])
        self.assertEqual(self.audits('execution.succeeded'), [])

    # -------------------------------------- invariant 5: reconcile, never re-dispatch

    def test_interrupted_execution_is_reconciled_not_redispatched(self):
        """`recover_executions` observes what was in flight; it never starts a second run."""
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.assertEqual(self.store.recover_executions(now=LATER), 1)
        self.assertEqual([row['status'] for row in self.execution_rows()], ['unknown'])
        self.assertEqual(self.action_row(action_id)['status'], 'unknown')
        self.assertEqual([row['operation'] for row in self.audits('execution.unknown')], ['execution.unknown'])
        self.assertEqual(len(self.execution_rows()), 1)
        self.assertEqual(self.execution_rows()[0]['id'], claim['execution_id'])
        with self.assertRaises(StateError):
            self.store.claim_action(action_id, RUNNER, self.policy, now=LATER)
        self.assertEqual(len(self.execution_rows()), 1)
        # Reconciliation is a human with an observed result, written on the same execution id.
        self.assertEqual(self.store.execution_outcome(claim['execution_id'], 'succeeded', HUMAN,
                                                     now=LATER + dt.timedelta(minutes=5))['status'], 'succeeded')
        self.assertEqual([row['id'] for row in self.execution_rows()], [claim['execution_id']])
        self.assertEqual(len(self.audits('execution.claimed')), 1)

    def test_recovery_does_not_invent_a_failure(self):
        """An interrupted run stays `unknown` until someone actually looks; nothing auto-marks it failed."""
        action_id = self.approved()
        self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.store.recover_executions(now=LATER)
        self.assertEqual(self.store.recover_executions(now=LATER + dt.timedelta(minutes=1)), 0)
        self.assertEqual(self.action_row(action_id)['status'], 'unknown')
        self.assertEqual(self.audits('execution.failed'), [])
        self.assertEqual(self.audits('execution.succeeded'), [])
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    # --------------------------------------- invariant 6: exit zero is not recovery

    def test_succeeded_outcome_alone_never_resolves_the_incident(self):
        """The runner's `succeeded` is a mechanical fact; the incident is a condition, and it stays open."""
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'], now=NOW)
        self.assertEqual(self.store.status()['actions'], {'succeeded': 1})
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual([row['status'] for row in self.store.records('incidents', 10)], ['open'])
        # Another firing changes nothing; only a resolved *event* closes it.
        self.open_incident(minute=1)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.store.intake(self.event('resolved', 2), PRODUCER, now=NOW + dt.timedelta(minutes=2))
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})

    def test_still_firing_signal_is_not_cleared_after_a_mechanical_success(self):
        """The brief's defect: exit zero with the originating condition still firing must read `not_cleared`."""
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'], now=NOW)
        self.assertEqual(self.store.status()['actions'], {'succeeded': 1})
        origin = verification.Origin(rule_id='inspect.load', resource_id=self.host, threshold=90,
                                     comparison='lt', window_seconds=300, metric_name=SERIES)
        verdict = verification.verify(answered_store(95.0), origin, now=NOW)
        self.assertEqual(verdict.state, 'not_cleared')
        self.assertEqual(verdict.reason, 'comparison-failed')
        self.assertFalse(verdict.cleared)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        # The same read back under the threshold is a real clearance — and the incident is *still*
        # open, because closing it is intake's decision about an event, not this module's about a number.
        self.assertEqual(verification.verify(answered_store(42.0), origin, now=NOW).state, 'cleared')
        self.assertEqual(self.store.status()['incidents'], {'open': 1})

    # ----------------------------------------------- invariant 7: dagu is an executor

    def test_dagu_never_dispatches_without_an_approved_claim(self):
        """CONTRACTS §5: "Dagu is an executor, not a separate source of remediation approval"."""
        journal = self.root / 'journal.json'
        for code in (400, 403, 409, 500):
            platform, engine = FakePlatform(claim_code=code), FakeDagu()
            with self.assertRaises(ValueError, msg=f'claim refused with {code}'):
                dagu.execute(platform, engine, str(uuid.uuid4()), reviewed_binding(), journal)
            self.assertEqual(engine.starts, 0, f'the DAG was started despite a {code} claim')
            self.assertEqual([method for method, _ in engine.methods], ['GET'], 'only the spec was read')
            self.assertEqual(platform.outcomes, [], 'no outcome was reported for a run that never existed')
            self.assertFalse(journal.exists(), 'no journal is written for a claim that was refused')

    def test_dagu_polls_a_lost_acknowledgement_instead_of_redispatching(self):
        """A dispatch whose acknowledgement was lost is polled by run id; the engine is started once, ever."""
        journal = self.root / 'journal.json'
        action_id = str(uuid.uuid4())
        platform = FakePlatform(claim=claim_for(reviewed_request()))
        engine = FakeDagu(lost_ack=True)
        first = dagu.execute(platform, engine, action_id, reviewed_binding(), journal)
        self.assertEqual(first['status'], 'executing')
        self.assertEqual(engine.starts, 1)
        engine.lost_ack = False
        engine.result = 'succeeded'
        second = dagu.execute(platform, engine, action_id, reviewed_binding(), journal)
        self.assertEqual(second['status'], 'succeeded')
        self.assertEqual(second['execution_id'], first['execution_id'])
        self.assertEqual(engine.starts, 1, 'the DAG was started once, ever')
        self.assertEqual(platform.claims, 1, 'the action was claimed once, ever')
        self.assertEqual([outcome['outcome'] for outcome in platform.outcomes], ['succeeded'])

    def test_a_claimed_request_that_differs_from_the_reviewed_binding_is_not_dispatched(self):
        """A claim for a different target set than the reviewed binding is refused before any effect."""
        journal = self.root / 'journal.json'
        platform = FakePlatform(claim=claim_for(reviewed_request(targets=['undeclared-other'])))
        engine = FakeDagu()
        result = dagu.execute(platform, engine, str(uuid.uuid4()), reviewed_binding(), journal)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(engine.starts, 0)
        self.assertEqual([outcome['outcome'] for outcome in platform.outcomes], ['failed'])

    # ---------------------------------------- what the audit trail does and does not hold

    def test_a_refused_attempt_leaves_a_durable_audit_row(self):
        """Every refused action attempt is durable: nine attempts, nine `action.refused` rows.

        This is the invariant the refusal audit closed, and it used to be the gap — the test stood here marked
        `@unittest.expectedFailure` because `state.py` raised before reaching its own `self.audit(...)`
        call on every one of these paths, and `api.create_app` answered a `StateError` with a 400 it did
        not log either, so nine attempted bad actions left no inspectable trace and an operator could
        not see that someone kept trying. It is now the minimum proof of the durable refusal audit:
        `Store.refusal` wraps the whole of `propose_action`, `decide`, `claim_action` and
        `execution_outcome` — role gate, validations and the injected policy call included — so the
        refused transaction is rolled back and closed first and one append-only `action.refused` row is
        committed by its own transaction afterwards, with the refusal's own sentence, status and state
        untouched. Read the rows with `GET /v1/records/audit`; `GET /v1/runtime`'s `refusal_audit`
        reports what this process wrote, dropped for rate, failed to write and could not attribute — and
        those four counters are per-process and reset on restart, while these rows do not.
        `tests/test_refusal_audit.py` holds the boundary cases (identity, subject, quota, an injected
        write failure, walking every field for a planted secret). The test below,
        `test_accepted_transitions_are_audited_with_stable_subjects`, states what has always been
        audited: the transitions that were granted.
        """
        action_id = self.approved()
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        before = len(self.audits())
        for _ in range(3):
            with self.assertRaises(StateError):
                self.store.decide(action_id, 'approved', AGENT, now=NOW)
            with self.assertRaises(StateError):
                self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
            with self.assertRaises(StateError):
                self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, 'wrong', now=NOW)
        self.assertEqual(len(self.audits()), before + 9,
                         'nine refused attempts must leave nine audit rows')

    def test_accepted_transitions_are_audited_with_stable_subjects(self):
        """Every granted transition is audited against the row it changed, and secrets stay out."""
        action_id = self.proposed()
        self.store.decide(action_id, 'approved', HUMAN, now=NOW)
        claim = self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)
        self.store.execution_outcome(claim['execution_id'], 'failed', RUNNER, claim['runner_token'], now=NOW)
        rows = {row['operation']: row for row in self.audits()}
        self.assertEqual(rows['action.proposed']['subject'], action_id)
        self.assertEqual(rows['action.approved']['subject'], action_id)
        self.assertEqual(rows['execution.claimed']['subject'], claim['execution_id'])
        self.assertEqual(rows['execution.failed']['subject'], claim['execution_id'])
        self.assertEqual({rows['action.proposed']['actor'], rows['action.approved']['actor']},
                         {AGENT.identity, HUMAN.identity})
        self.assertNotIn('token_hash', self.execution_rows()[0])
        self.assertNotIn(claim['runner_token'], json.dumps(self.execution_rows()))

    def test_audit_rows_cannot_be_edited_or_removed(self):
        """The trail is append-only in the database, so a refusal cannot be unwritten after the fact."""
        self.proposed()
        with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
            connection.execute("UPDATE audit SET actor = 'somebody-else' WHERE operation = 'action.proposed'")
        with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
            connection.execute('DELETE FROM audit')
        self.assertEqual(len(self.audits('action.proposed')), 1)


def claim_for(request, execution_id=None):
    """One accepted platform claim, in the shape `dagu.execute` consumes."""
    return {'status': 'executing', 'execution_id': execution_id or str(uuid.uuid4()),
            'runner_token': 'synthetic-runner-token-for-tests', 'request': request}


if __name__ == '__main__':
    unittest.main()

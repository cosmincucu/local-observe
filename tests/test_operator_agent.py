"""The `operator-agent` credential: what an automated operator may do, and what its acts look like on file.

`docs/api/DECISIONS.md` D16 is the decision and `docs/CONTRACTS.md` §5 is the rule it sits under; this file is
the evidence that the implementation matches both. Almost every assertion goes through `create_app` over a
real `Store` on a temp path, because the two claims that matter are not about a function's return value:

* **an agent's statement has a human's effect.** A dismissal by `night-bot` folds exactly the deliveries a
  dismissal by `operator` folds. Nothing downstream may treat the two differently, and the case that says so
  runs both halves against one fixture with the credential as the only difference.
* **an agent's statement is not a human's.** The role the server authenticated is stored beside the identity —
  in the effective row, in the append-only history, in the audit detail, in the projection an integration is
  told about, in a window's declared block and in a schedule's version row — so a reader can tell who answered.
  A stored `human` row and a stored `operator-agent` row are both true, and neither is inferred from the name.

Everything the role may *not* do is refused here too: approving or denying an action, claiming or executing
one, revoking a credential, booking a state job, grading an investigation, guided setup, filing an event. A
body that claims a role — `"role": "human"` typed into an acknowledgement — is refused before the state layer
is reached, which is the rule that makes the stored role worth trusting, and the refusal of a lifecycle
attempt is audited with the role that asked so that a denial of an automated operator is not read as a denial
of a person.

## The test that is not a case list

`test_every_read_a_reader_may_make_is_a_read_this_role_may_make` walks `docs/api/coverage.yaml` and, for every
HTTP read whose published roles include `reader`, serves the same request as both credentials and requires the
same answer. A hand-written list of readable routes would go stale the day a route is added; the sweep cannot,
because it reads the census the product publishes.

Fixtures are synthetic: `uuid5`-derived resource ids, reserved `fixture`/`demo-*` names, and no network, host,
credential value or real channel client anywhere.
"""
import asyncio
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

import yaml

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import (api_contract, dispositions, maintenance, refusals, suppression,
                                      verification_records)
from local_observe.platform.api import create_app
from local_observe.platform.detections import event as build_event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import HUMAN, OPERATOR_AGENT, Actor, Store

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / 'docs' / 'api' / 'coverage.yaml'
#: The instant the occurrence fixtures are filed at. Maintenance declarations are deliberately *not* dated
#: from it: the transport injects no clock, so a window or a plan is judged against the real one and a fixed
#: 2026 date would be refused as retroactive the moment the suite is run later than it was written.
NOW = timestamp('2026-09-19T09:00:00Z')
REAL_NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
RULE = 'gatus.result'
#: One credential row per role the transport authenticates. The identities are distinct so an answer naming
#: one cannot be mistaken for an answer naming another.
READER = {'identity': 'dashboard', 'role': 'reader', 'token': 'r' * 32}
PRODUCER = {'identity': 'lo-detector', 'role': 'producer', 'token': 'p' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
PERSON = {'identity': 'operator', 'role': HUMAN, 'token': 'h' * 32}
RUNNER = {'identity': 'runbook', 'role': 'executor', 'token': 'e' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
AGENT = {'identity': 'night-bot', 'role': OPERATOR_AGENT, 'token': 'a' * 32}
CREDENTIALS = [READER, PRODUCER, PROPOSER, PERSON, RUNNER, SUMMARY, AGENT]
TOKEN = {row['role']: row['token'] for row in CREDENTIALS}
DETECTOR = Actor(PRODUCER['identity'], 'producer')
#: `live`, so a fold is measured against a queue that would otherwise send; no provider is ever attached, so
#: nothing leaves the process and every count below is read off the file.
POLICY = NotificationPolicy(delivery_mode='live', max_attempts=20)
#: The reads the sweep must see served to be worth running: enough of the surface that a silent collapse to
#: 404 for every path would still leave the assertion true.
#: The census paths that answer 200 with no query string on a store this fixture builds, so the sweep holds a
#: real document in both hands. The rest (`/v1/evidence`, `/v1/observed-snapshots`, the `/v1/verification/*`
#: reads, `/v1/maintenance-intervals`, `/v1/inventory`) need a parameter or a mounted component: they are
#: still swept, but only for the claim that both roles are answered alike.
SERVED_READS = ('/v1/status', '/v1/runtime', '/v1/overview', '/v1/audit', '/v1/alert-occurrences',
                '/v1/maintenance-windows', '/v1/maintenance-schedules', '/v1/resources', '/v1/capabilities',
                '/v1/queries/topology', '/v1/notifications/safety', '/v1/health', '/v1/boundary')


def resource_id(name: str) -> str:
    """A stable synthetic UUID for a synthetic name — never a real estate id."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'operator-agent-fixture/' + name))


def census() -> list[dict]:
    """The published operation rows, from the file the conformance test also reads."""
    with COVERAGE.open(encoding='utf-8') as handle:
        return yaml.safe_load(handle)['operations']


def _text(value) -> str:
    return value.decode() if isinstance(value, bytes) else str(value)


class OperatorAgentFixture(unittest.TestCase):
    """One store, one app, and the transport helpers every case below drives."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / 'state.db'
        self.store = Store(self.path, POLICY)

    def app(self):
        """A freshly built app over the shared store, which is what an API restart is to this contract."""
        return create_app(self.store, CREDENTIALS, {})

    def at(self, minutes: int = 0) -> dt.datetime:
        return NOW + dt.timedelta(minutes=minutes)

    # --- the transport ----------------------------------------------------------------------

    def request(self, method: str, path: str, *, role: str = OPERATOR_AGENT, body=None, query: str = '',
                headers: list[tuple[bytes, bytes]] | None = None, app=None):
        """One request through the ASGI app, no socket, on its own event loop."""
        payload = b'' if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        # The bearer is chosen by the *role* the case asks for: one identity per role, so a stored row
        # naming an actor can only have come from the credential this test held out.
        scope_headers = list(headers or [])
        scope_headers.append((b'authorization', ('Bearer ' + TOKEN[role]).encode()))
        output: list[dict] = []

        async def receive():
            return {'type': 'http.request', 'body': payload, 'more_body': False}

        async def send(message):
            output.append(message)

        async def go():
            scope = {'type': 'http', 'http_version': '1.1', 'method': method, 'path': path,
                     'raw_path': path.encode(), 'scheme': 'http', 'query_string': query.encode(),
                     'headers': scope_headers, 'client': ('127.0.0.1', 50000),
                     'server': ('127.0.0.1', 8080), 'root_path': ''}
            await (app or self.app())(scope, receive, send)

        asyncio.run(go())
        start = output[0]
        answer = json.loads(output[-1]['body']) if output[-1].get('body') else None
        return (start['status'], answer,
                {_text(name).lower(): _text(value) for name, value in start.get('headers', [])})

    def read(self, path: str, *, role: str = OPERATOR_AGENT, **kwargs):
        return self.request('GET', path, role=role, **kwargs)

    def send(self, path: str, body=None, *, role: str = OPERATOR_AGENT, method: str = 'POST', **kwargs):
        return self.request(method, path, body=body if body is not None else {}, role=role, **kwargs)

    # --- the state the cases are about ------------------------------------------------------

    def episode(self, name: str = 'demo-host', rule: str = RULE, *, at: dt.datetime = None) -> dict:
        """File one firing verdict through `Store.intake`, returning its occurrence and event ids.

        Both are returned because an action's evidence must be an event belonging to the incident it cites,
        so a fixture that wants an action to lifecycle needs the pair and not just the occurrence.
        """
        moment = at or NOW
        return self.store.intake(self.verdict(name, rule, moment=moment), DETECTOR, now=moment)

    def open_episode(self, name: str = 'demo-host', rule: str = RULE, *, at: dt.datetime = None) -> str:
        return self.episode(name, rule, at=at)['incident_id']

    def verdict(self, name: str = 'demo-host', rule: str = RULE, *, moment: dt.datetime = None) -> dict:
        moment = moment or NOW
        window = {'start': utc_text(moment - dt.timedelta(seconds=60)), 'end': utc_text(moment)}
        return build_event(DETECTOR.identity, resource_id(name), rule, 'availability', 'firing', window,
                           {'rule_id': rule, 'resource_id': resource_id(name)}, query_type='gatus-result')

    def refile(self, name: str = 'demo-host', *, moment: dt.datetime) -> dict:
        """The same condition firing again: the repeat an acknowledgement exists to fold."""
        return self.store.intake(self.verdict(name, moment=moment), DETECTOR, now=moment)

    def pending_action(self) -> str:
        """One proposed action, through the state layer with a permissive policy.

        The policy is a no-op because this fixture is not about the allowlist: the cases that use it ask what
        a credential may *decide about* an action, and the answer must not depend on which action definitions
        a deployment happens to have mounted.
        """
        filed = self.episode()
        expires = NOW + dt.timedelta(hours=1)
        return self.store.propose_action(
            {'retry_key': 'operator-agent-fixture', 'incident_id': filed['incident_id'],
             'action': 'inspect', 'version': '1', 'targets': [resource_id('demo-host')], 'parameters': {},
             'evidence': [filed['event_id']], 'expires_at': utc_text(expires)},
            Actor(PROPOSER['identity'], 'proposer'), lambda request: None, now=NOW)['action_id']

    def window_request(self, *, hours_ahead: int = 2, minutes: int = 45, **overrides) -> dict:
        start = REAL_NOW + dt.timedelta(hours=hours_ahead)
        return dict({'reason': 'replace the disk',
                     'scope': {'kind': 'resource', 'id': resource_id('demo-host')},
                     'starts_at': utc_text(start.replace(microsecond=0)),
                     'ends_at': utc_text((start + dt.timedelta(minutes=minutes)).replace(microsecond=0))},
                    **overrides)

    def schedule_request(self, *, days_ahead: int = 6, **overrides) -> dict:
        first = (REAL_NOW + dt.timedelta(days=days_ahead)).date().isoformat()
        return dict({'reason': 'firmware refresh',
                     'scope': {'kind': 'resource', 'id': resource_id('demo-host')},
                     'recurrence': {'frequency': 'weekly', 'interval': 1, 'days_of_week': [1],
                                    'time_of_day': '03:30', 'duration_seconds': 1800,
                                    'timezone': 'Europe/London', 'dst': 'wall'},
                     'bounds': {'first_occurrence': first, 'occurrences': 3}}, **overrides)

    # --- assertions every class below reuses ------------------------------------------------

    def scalar(self, sql: str, args: tuple = ()) -> int:
        connection = sqlite3.connect(self.path)
        try:
            return int(connection.execute(sql, args).fetchone()[0])
        finally:
            connection.close()

    def rows(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            return list(connection.execute(sql, args))
        finally:
            connection.close()

    def assertRefused(self, answer, case: str, statuses: tuple[int, ...] = (400, 403)) -> None:
        """Assert the answer is the platform's own role refusal, and say which layer produced it.

        Two layers refuse a role and they do not answer identically, which is pre-existing `/v1` behaviour this
        file must not quietly "fix": a `StateError` from the state layer is mapped by `api.stable_code` to
        `not_authorised` at **400**, while a boundary module that raises the refusal itself
        (`api_contract.ContractError`) answers **403**. `api_contract.ERROR_CATALOGUE` admits both statuses for
        that one code, so the honest assertion is the code plus the answer this route is allowed to give.
        """
        got, body, _headers = answer
        stated = (body or {}).get('error')
        self.assertEqual(stated.get('code') if isinstance(stated, dict) else stated, 'not_authorised',
                         f'{case}: {body}')
        self.assertIn(got, statuses, f'{case}: {body}')


# ------------------------------------------------------------------ the two writes an operator makes


class DispositionTests(OperatorAgentFixture):
    """An automated operator answers an episode, with a person's effect and a different name."""

    def acknowledge(self, occurrence: str, *, role: str = OPERATOR_AGENT,
                    reason: str = 'runbook 12 running', **kwargs):
        return self.send(f'/v1/alert-occurrences/{occurrence}/acknowledgements', {'reason': reason},
                         role=role, **kwargs)

    def dismiss(self, occurrence: str, *, role: str = OPERATOR_AGENT,
                reason: str = 'not actionable: tracked elsewhere', **kwargs):
        return self.send(f'/v1/alert-occurrences/{occurrence}/dismissals', {'reason': reason}, role=role,
                         **kwargs)

    def test_an_operator_agent_may_acknowledge(self):
        occurrence = self.open_episode()
        status, body, _ = self.acknowledge(occurrence)
        self.assertEqual(status, 200, body)
        self.assertEqual(body['state'], 'acknowledged')
        self.assertEqual((body['disposition']['actor'], body['disposition']['actor_role']),
                         ('night-bot', OPERATOR_AGENT))

    def test_an_operator_agent_may_dismiss(self):
        occurrence = self.open_episode()
        status, body, _ = self.dismiss(occurrence)
        self.assertEqual(status, 200, body)
        self.assertEqual(body['state'], 'dismissed')
        self.assertEqual(body['disposition']['actor_role'], OPERATOR_AGENT)

    def test_the_two_roles_reach_the_same_state_by_the_same_route(self):
        """The only difference between these two runs is who spoke, so every other field must agree."""
        fields = ('kind', 'reason', 'revision')
        by_person = self.acknowledge(self.open_episode('host-a'), role=HUMAN)[1]['disposition']
        by_agent = self.acknowledge(self.open_episode('host-b'))[1]['disposition']
        self.assertEqual({key: by_person[key] for key in fields}, {key: by_agent[key] for key in fields})
        self.assertTrue(by_person['at'] and by_agent['at'], 'each statement carries its own instant')
        self.assertEqual((by_person['actor'], by_agent['actor']), ('operator', 'night-bot'))
        self.assertEqual((by_person['actor_role'], by_agent['actor_role']), (HUMAN, OPERATOR_AGENT))
        self.assertEqual(by_person['kind'], 'acknowledged')

    def test_an_agents_acknowledgement_folds_what_a_humans_folds(self):
        """Equal effect, measured as suppressed deliveries and not as a status code."""
        outcomes = {}
        for name, role in (('host-a', HUMAN), ('host-b', OPERATOR_AGENT)):
            episode = self.open_episode(name)
            self.refile(name, moment=self.at(10))
            self.refile(name, moment=self.at(20))
            before = self.scalar('SELECT count(*) FROM notification_suppressions')
            folded = self.acknowledge(episode, role=role)[1]['folded']
            outcomes[role] = (folded, self.scalar('SELECT count(*) FROM notification_suppressions') - before,
                              self.read(f'/v1/alert-occurrences/{episode}', role=HUMAN)[1]['state'])
        self.assertGreater(outcomes[HUMAN][0], 0, 'the fixture must leave repeats for a fold to find')
        self.assertEqual(outcomes[HUMAN][0], outcomes[OPERATOR_AGENT][0],
                         'what folds three repeats for a person folds three for an agent')
        self.assertEqual(outcomes[HUMAN][1], outcomes[OPERATOR_AGENT][1],
                         'and the rows taken out of the queue are the same number of rows')
        self.assertEqual(outcomes[HUMAN][2], 'acknowledged')
        self.assertEqual(outcomes[OPERATOR_AGENT][2], 'acknowledged', 'the episode reads the same either way')

    def test_the_history_names_both_halves_of_who_spoke(self):
        occurrence = self.open_episode()
        self.acknowledge(occurrence)
        self.dismiss(occurrence, role=HUMAN, reason='closed by the person on call')
        rows = self.read(f'/v1/alert-occurrences/{occurrence}/history', role=HUMAN)[1]['rows']
        self.assertEqual([(row['kind'], row['actor'], row['actor_role']) for row in rows],
                         [('acknowledged', 'night-bot', OPERATOR_AGENT), ('dismissed', 'operator', HUMAN)],
                         'one episode answered twice, once by each kind of operator')
        stored = self.rows('SELECT actor, actor_role FROM occurrence_disposition_history'
                           ' WHERE occurrence_id = ? ORDER BY sequence', (occurrence,))
        self.assertEqual([tuple(row) for row in stored],
                         [('night-bot', OPERATOR_AGENT), ('operator', HUMAN)],
                         'the read reports the columns and not an inference from a name')

    def test_the_audit_row_of_an_agent_disposition_names_the_agent_and_the_role(self):
        occurrence = self.open_episode()
        self.acknowledge(occurrence)
        row = self.rows('SELECT actor, detail FROM audit WHERE operation = ? AND subject = ?'
                        ' ORDER BY sequence', (dispositions.OCCURRENCE_DISPOSITION_OPERATION, occurrence))[-1]
        self.assertEqual(row['actor'], 'night-bot')
        self.assertEqual(json.loads(row['detail'])['actor_role'], OPERATOR_AGENT,
                         'the log an operator reads names the kind of credential that answered')

    def test_the_projection_an_integration_receives_names_the_role(self):
        """A downstream told "operator X dismissed this" about an agent's act would print a lie."""
        occurrence = self.open_episode()
        self.dismiss(occurrence)
        statements = [json.loads(row['payload']) for row in self.rows(
            'SELECT payload FROM occurrence_projections WHERE occurrence_id = ?', (occurrence,))]
        self.assertEqual(len(statements), 2, 'the two configured targets, and no third')
        for statement in statements:
            self.assertEqual((statement['actor'], statement['actor_role']), ('night-bot', OPERATOR_AGENT))
            self.assertEqual(statement['kind'], 'dismissed')

    def test_every_other_role_is_still_refused_the_disposition(self):
        occurrence = self.open_episode()
        for role in ('reader', 'producer', 'proposer', 'executor', 'summary'):
            with self.subTest(refused=role):
                status, body, _ = self.acknowledge(occurrence, role=role)
                expected = (403, 'summary_only') if role == 'summary' else (403, 'not_authorised')
                self.assertEqual((status, (body.get('error') or {}).get('code')
                                  if isinstance(body.get('error'), dict) else body.get('error')),
                                 expected, body)
        self.assertIsNone(self.read(f'/v1/alert-occurrences/{occurrence}', role=HUMAN)[1]['disposition'],
                          'none of those refusals wrote anything')

    def test_a_denied_lifecycle_attempt_is_audited_with_the_role_that_asked(self):
        """Why `operator-agent` had to join `refusals.ROLES` at all.

        `Store.refusal` writes the denial only for an actor whose role it can name (`refusals.attribution`
        answers None for anything else, and the refusal then counts as `unauditable`). An automated operator
        refused at the action boundary is a refusal an operator reads about, so the vocabulary had to grow
        with the credential rather than leave its denials uncounted.
        """
        action = self.pending_action()
        status, body, _ = self.send('/v1/actions/decision', {'action_id': action, 'decision': 'approved'})
        # 400 and not 403: the denial is the state layer's own sentence, which `api.stable_code` maps to
        # `not_authorised` at the status `/v1` has always used for it. The row below is the point.
        self.assertEqual(status, 400, body)
        row = self.rows("SELECT actor, detail FROM audit WHERE operation = 'action.refused'"
                        " ORDER BY sequence DESC LIMIT 1")[0]
        self.assertEqual(row['actor'], 'night-bot')
        self.assertEqual(json.loads(row['detail']),
                         {'attempt': 'decide', 'reason': 'actor-not-authorised', 'role': OPERATOR_AGENT})
        self.assertIn(OPERATOR_AGENT, refusals.ROLES)

    def test_a_body_may_not_claim_the_role_that_would_let_it_through(self):
        """`role: human` in an agent's body is refused as a claim, not compared with the credential."""
        occurrence = self.open_episode()
        for claim in (HUMAN, 'executor', OPERATOR_AGENT, 'human '):
            with self.subTest(claim=claim):
                status, body, _ = self.send(f'/v1/alert-occurrences/{occurrence}/acknowledgements',
                                            {'reason': 'typed it myself', 'role': claim})
                self.assertEqual(status, 400, body)
                self.assertEqual(body['error']['code'], 'actor_claim_refused')
                self.assertIn('role', json.dumps(body).lower())
        self.assertIsNone(self.read(f'/v1/alert-occurrences/{occurrence}', role=HUMAN)[1]['disposition'],
                          'a refused claim wrote no disposition, and left the episode pending')

    def test_no_actor_shaped_body_field_is_read_as_an_identity(self):
        occurrence = self.open_episode()
        for field in ('actor', 'actor_id', 'identity', 'decided_by', 'operator_id', 'on_behalf_of',
                      'impersonate', 'requester'):
            with self.subTest(refused=field):
                status, body, _ = self.send(f'/v1/alert-occurrences/{occurrence}/dismissals',
                                            {'reason': 'a name in the body', field: 'somebody'})
                self.assertEqual((status, body['error']['code']), (400, 'actor_claim_refused'), body)
        self.assertEqual(self.scalar('SELECT count(*) FROM occurrence_dispositions WHERE occurrence_id = ?',
                                     (occurrence,)), 0)

    def test_a_restated_disposition_keeps_the_actor_and_role_that_spoke_first(self):
        """A restatement of the identical statement is one decision, so its name does not move."""
        occurrence = self.open_episode()
        self.dismiss(occurrence)
        again = self.dismiss(occurrence)
        self.assertEqual(again[1]['disposition']['actor'], 'night-bot')
        self.assertEqual(again[1]['disposition']['actor_role'], OPERATOR_AGENT)
        self.assertEqual(self.scalar('SELECT count(*) FROM occurrence_disposition_history'
                                     ' WHERE occurrence_id = ?', (occurrence,)), 1,
                         'a restatement added no history row, so the role it names is still the first one')


# ------------------------------------------------------------------ planned work, by either operator


class MaintenanceTests(OperatorAgentFixture):
    """Windows and schedules: declared, edited, cancelled and rolled forward under an agent's own name."""

    def test_an_operator_agent_may_declare_and_cancel_a_window(self):
        status, declared, _ = self.send('/v1/maintenance-windows', self.window_request())
        self.assertEqual(status, 200, declared)
        window = declared['windows'][0]['window_id']
        self.assertEqual((declared['windows'][0]['declared_by'], declared['windows'][0]['declared_by_role']),
                         ('night-bot', OPERATOR_AGENT))
        detail = self.read(f'/v1/maintenance-windows/{window}')[1]['window']
        self.assertEqual((detail['author'], detail['author_role']), ('night-bot', OPERATOR_AGENT))
        status, cancelled, _ = self.send(f'/v1/maintenance-windows/{window}/cancellations')
        self.assertEqual((status, cancelled['status'], cancelled['cancelled_by']),
                         (200, 'cancelled', 'night-bot'))
        self.assertEqual(cancelled['cancelled_by_role'], OPERATOR_AGENT)
        stored = self.read(f'/v1/maintenance-windows/{window}')[1]['window']
        self.assertEqual(stored['revoked_by_role'], OPERATOR_AGENT)
        timeline = self.read(f'/v1/maintenance-windows/{window}/history')[1]['events']
        self.assertEqual([(row['what'], row['by'], row['by_role']) for row in timeline],
                         [('declared', 'night-bot', OPERATOR_AGENT),
                          ('revoked', 'night-bot', OPERATOR_AGENT)],
                         'the window story names the kind of operator at both ends')

    def test_a_human_may_cancel_the_window_an_agent_declared(self):
        status, declared, _ = self.send('/v1/maintenance-windows', self.window_request())
        window = declared['windows'][0]['window_id']
        status, cancelled, _ = self.send(f'/v1/maintenance-windows/{window}/cancellations', role=HUMAN)
        self.assertEqual(status, 200, cancelled)
        self.assertEqual((cancelled['cancelled_by'], cancelled['cancelled_by_role']),
                         ('operator', HUMAN), 'the person who cancelled it is named as a person')

    def test_an_agent_declared_window_silences_what_a_human_declared_one_silences(self):
        """Equal effect, measured as a suppressed finding rather than as a 200."""
        for role in (HUMAN, OPERATOR_AGENT):
            with self.subTest(role=role):
                store = Store(self.root / f'silence-{role}.db', POLICY)
                start = REAL_NOW + dt.timedelta(hours=3)
                answer = suppression.declare_window(
                    store, {'resource_id': resource_id('quiet-host'), 'starts_at': utc_text(start),
                            'ends_at': utc_text(start + dt.timedelta(hours=1)), 'reason': 'agent swap',
                            'explains': ['availability']},
                    Actor('night-bot' if role == OPERATOR_AGENT else 'operator', role), now=REAL_NOW)
                self.assertEqual(answer['window']['author_role'], role)
                filed = suppression.file_event(
                    store, self.verdict('quiet-host', moment=start + dt.timedelta(minutes=10)), DETECTOR,
                    now=start + dt.timedelta(minutes=10))
                decision = filed['decision']
                self.assertTrue(decision.suppressed, 'the window must cover the finding')
                self.assertEqual(decision.cause, 'maintenance-window')

    def test_an_operator_agent_may_declare_revise_cancel_and_roll_forward_a_schedule(self):
        status, declared, _ = self.send('/v1/maintenance-schedules', self.schedule_request())
        self.assertEqual(status, 200, declared)
        ident = declared['id']
        self.assertEqual(declared['declared'], 3)
        one = self.read(f'/v1/maintenance-schedules/{ident}')[1]
        self.assertEqual((one['schedule']['declared_by'], one['schedule']['declared_by_role']),
                         ('night-bot', OPERATOR_AGENT))
        status, edited, _ = self.request('PATCH', f'/v1/maintenance-schedules/{ident}',
                                        body=dict(self.schedule_request(days_ahead=7), expected_version=1))
        self.assertEqual((status, edited['version']), (200, 2), edited)
        self.assertEqual([row['declared_by_role'] for row in
                          self.read(f'/v1/maintenance-schedules/{ident}')[1]['history']],
                         [OPERATOR_AGENT, OPERATOR_AGENT], 'the version an agent appended names the agent')
        status, rolled, _ = self.send(f'/v1/maintenance-schedules/{ident}/materializations')
        self.assertEqual((status, rolled['status']), (200, 'rolled_forward'))
        status, cancelled, _ = self.send(f'/v1/maintenance-schedules/{ident}/cancellations')
        self.assertEqual((status, cancelled['status']), (200, 'cancelled'))
        versions = self.read(f'/v1/maintenance-schedules/{ident}/history')[1]['versions']
        self.assertEqual([row['declared_by_role'] for row in versions], [OPERATOR_AGENT] * 3,
                         'every version of this plan was signed by an automated operator')

    def test_a_human_and_an_agent_may_sign_different_versions_of_one_plan(self):
        status, declared, _ = self.send('/v1/maintenance-schedules', self.schedule_request())
        ident = declared['id']
        self.request('PATCH', f'/v1/maintenance-schedules/{ident}', role=HUMAN,
                     body=dict(self.schedule_request(days_ahead=8), expected_version=1))
        self.send(f'/v1/maintenance-schedules/{ident}/cancellations')
        versions = self.read(f'/v1/maintenance-schedules/{ident}/history')[1]['versions']
        self.assertEqual([(row['version'], row['declared_by'], row['declared_by_role']) for row in versions],
                         [(1, 'night-bot', OPERATOR_AGENT), (2, 'operator', HUMAN),
                          (3, 'night-bot', OPERATOR_AGENT)],
                         'one plan, three signatures, each named as what it was')

    def test_a_window_a_schedule_materialized_names_who_ran_the_schedule(self):
        """The plan links back to its version; the silence is signed by the credential that declared it."""
        status, declared, _ = self.send('/v1/maintenance-schedules', self.schedule_request())
        # A materialized window is answered as a stored row, whose selector is `id`; a hand-declared one is
        # answered as an act, whose selector is `window_id`. Both name the same record.
        window = declared['windows'][0]['id']
        stored = self.read(f'/v1/maintenance-schedules/{declared["id"]}')[1]['schedule']
        self.assertEqual((stored['declared_by'], stored['declared_by_role']),
                         ('night-bot', OPERATOR_AGENT))
        detail = self.read(f'/v1/maintenance-windows/{window}')[1]['window']
        self.assertEqual((detail['author'], detail['author_role'], detail['schedule_id']),
                         ('night-bot', OPERATOR_AGENT, declared['id']))

    def test_the_schedule_audit_row_stays_the_signed_document_and_the_role_is_stored_beside_it(self):
        """The digest the log quotes is the plan's text; widening it would split one plan into two digests."""
        status, declared, _ = self.send('/v1/maintenance-schedules', self.schedule_request())
        ident = declared['id']
        row = self.rows('SELECT actor, detail FROM audit WHERE operation = ? AND subject = ?'
                        ' ORDER BY sequence', (maintenance.SCHEDULE_OPERATION, ident))[0]
        self.assertEqual(row['actor'], 'night-bot')
        self.assertNotIn('declared_by_role', json.loads(row['detail']),
                         'the attested detail is the signed document, byte for byte, and stays that way')
        stored = self.rows('SELECT declared_by, declared_by_role FROM maintenance_schedules'
                           ' WHERE schedule_id = ? AND version = 1', (ident,))[0]
        self.assertEqual((stored['declared_by'], stored['declared_by_role']), ('night-bot', OPERATOR_AGENT))
        self.assertTrue(self.read(f'/v1/maintenance-schedules/{ident}')[1]['schedule']['attested'],
                        'storing the role beside the signature did not break the attestation')

    def test_a_window_document_is_envelope_v3_and_an_older_one_still_reads_as_a_human_silence(self):
        status, declared, _ = self.send('/v1/maintenance-windows', self.window_request())
        window = declared['windows'][0]['window_id']
        key = suppression.maintenance_key(window)
        document = json.loads(self.rows('SELECT value FROM notification_control WHERE key = ?',
                                       (key,))[0][0])
        self.assertEqual(suppression.WINDOW_DOCUMENT_VERSION, 3)
        self.assertEqual(document['schema_version'], 3)
        self.assertEqual(document['declared']['author_role'], OPERATOR_AGENT)
        # The same row one envelope version older: what a deployed file holds for a window declared before an
        # automated operator could exist. The audit log is append-only, so the older build's own row is
        # appended — the block quoted exactly as that build wrote it, with no role field — and the control row
        # is pointed at it. That is the state an upgraded file is really in, and the read must call the author
        # a human rather than refuse the row or invent a role for it.
        older = json.loads(json.dumps(document))
        older['schema_version'] = 2
        older['declared'].pop('author_role')
        with self.store.transaction() as connection:
            connection.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                               (utc_text(NOW), 'night-bot', 'maintenance.declared', window,
                                suppression.canonical(older['declared'])))
            older['attest'] = int(connection.execute('SELECT last_insert_rowid()').fetchone()[0])
            connection.execute('UPDATE notification_control SET value = ? WHERE key = ?',
                               (suppression.canonical(older), key))
        read = self.read(f'/v1/maintenance-windows/{window}')[1]['window']
        self.assertEqual(read['document_version'], 2)
        self.assertEqual((read['author'], read['author_role']), ('night-bot', HUMAN))
        self.assertTrue(read['attested'], 'the older envelope is still the document its own log row signed')
        self.assertIn((read['starts_at'], read['id']),
                      [(window['starts_at'], window['id'])
                       for window in suppression.live_windows(self.store)['windows']],
                      'an older row is still applied: reading it as a human act changes nothing about it')


# ------------------------------------------------------------------ the refusals, one power per case


class RefusalTests(OperatorAgentFixture):
    """Everything else is refused the way any non-permitted role is refused."""

    def setUp(self) -> None:
        super().setUp()
        self.action = self.pending_action()

    def test_an_agent_may_not_approve_or_deny_an_action(self):
        for decision in ('approved', 'denied'):
            with self.subTest(decision=decision):
                self.assertRefused(self.send('/v1/actions/decision', {'action_id': self.action,
                                                                     'decision': decision}),
                                   decision, statuses=(400,))
        self.assertEqual(self.rows('SELECT status FROM actions WHERE id = ?', (self.action,))[0]['status'],
                         'pending', 'a decision an agent attempted did not happen')

    def test_an_agent_may_not_claim_or_execute_an_action(self):
        self.assertRefused(self.send('/v1/actions/claim', {'action_id': self.action}), 'claim',
                           statuses=(400,))
        self.assertRefused(self.send('/v1/executions/outcome', {'execution_id': str(uuid.uuid4()),
                                                               'outcome': 'succeeded'}), 'outcome',
                           statuses=(400,))
        self.assertEqual(self.scalar('SELECT count(*) FROM executions'), 0)

    def test_an_agent_may_not_propose_an_action(self):
        self.assertRefused(self.send('/v1/actions', {
            'retry_key': 'agent-proposal', 'incident_id': self.open_episode(), 'action': 'inspect',
            'version': '1', 'targets': [resource_id('demo-host')], 'parameters': {},
            'evidence': [self.episode()['event_id']],
            'expires_at': utc_text(NOW + dt.timedelta(hours=1))}),
            'propose', statuses=(400,))

    def test_an_agent_may_not_revoke_a_credential(self):
        self.assertRefused(self.send('/v1/credentials/dashboard/revocations',
                                     {'reason': 'rotated out of the fleet'}), 'revoke', statuses=(403,))
        self.assertEqual(self.scalar('SELECT count(*) FROM credential_revocations'), 0)

    def test_an_agent_may_not_book_or_cancel_a_state_job(self):
        self.assertRefused(self.send('/v1/state/backups', {}), 'backup job', statuses=(403,))
        self.assertRefused(self.send('/v1/state/verifications', {}), 'verification', statuses=(403,))
        self.assertRefused(self.send(f'/v1/jobs/{uuid.uuid4()}/cancellations', {}), 'job cancellation',
                           statuses=(403,))
        self.assertEqual(self.scalar('SELECT count(*) FROM platform_jobs'), 0)

    def test_an_agent_may_not_read_or_answer_an_action_review(self):
        """The review surface is the human judgement about a runner's plan, and it stays that."""
        self.assertRefused(self.read('/v1/actions/review', query='action_id=' + self.action), 'review',
                           statuses=(400,))

    def test_an_agent_may_not_grade_or_run_an_investigation(self):
        """The observer surfaces a `reader` cannot reach stay closed to this role too.

        `/v1/observer/health` and `/v1/observer/capabilities` are the two reads a `reader` may make, and the
        sweep in `ReadTests` asserts this role makes them; everything else in the family is a person's
        judgement about an investigation, and the census says so row by row.
        """
        for path, method in (('/v1/observer/cases', 'GET'), ('/v1/observer/jobs', 'GET'),
                             ('/v1/observer/runs', 'POST'), ('/v1/observer/feedback', 'POST'),
                             ('/v1/observer/exports', 'POST'), ('/v1/observer/delivery/disarm', 'POST'),
                             ('/v1/observer/reviews', 'POST')):
            with self.subTest(path=path):
                status, body, _ = self.request(method, path, body={})
                self.assertNotEqual(status, 200, f'{path}: {body}')
                self.assertIn(status, (403, 404), f'{path}: {body}')

    def test_an_agent_may_not_run_guided_setup(self):
        """Both answers are honest: unmounted the routes are 404, mounted they refuse the role."""
        # No journal is mounted in this fixture, so the route is not served at all; the census row is the
        # published word, and the loop below checks it names no automated operator.
        self.assertEqual(self.read('/v1/setup/pending')[0], 404)
        for path in ('/v1/setup/plan', '/v1/setup/decision', '/v1/setup/resources'):
            with self.subTest(path=path):
                status, body, _ = self.send(path, {})
                self.assertIn(status, (403, 404), f'{path}: {body}')
                self.assertNotEqual(status, 200)
        for row in census():
            if row['operation_id'].startswith('administration.guided_setup'):
                self.assertNotIn(OPERATOR_AGENT, row['required_role'], row['operation_id'])

    def test_an_agent_may_not_retry_a_delivery_or_pump_the_queue(self):
        self.assertRefused(self.send('/v1/notifications/retry', {'delivery_id': str(uuid.uuid4())}), 'retry')
        self.assertRefused(self.send('/v1/notifications/deliveries', {}), 'pump')
        self.assertRefused(self.send('/v1/notifications/reset-safety', {}), 'flood-breaker reset')

    def test_an_agent_may_not_file_an_event_or_a_sample(self):
        filed = self.scalar('SELECT count(*) FROM events')
        self.assertRefused(self.send('/v1/events', self.verdict(moment=NOW)), 'events', statuses=(400,))
        self.assertRefused(self.send('/v1/evidence', {'kind': 'metrics', 'series': 'demo'}), 'sample',
                           statuses=(400,))
        self.assertEqual(self.scalar('SELECT count(*) FROM events'), filed,
                         'a refused filing left nothing in the store either')

    def test_the_mcp_surface_refuses_the_credential_with_a_sentence_and_not_a_stack(self):
        """`tools.py` names the refusal rather than calling the role unknown.

        The tool surface carries three capabilities — read, propose, execute — and an automated operator may
        use none of them: what its credential opens is the disposition and maintenance routes. A row naming it
        is a mounted configuration, so the answer has to explain the decision instead of looking like a typo.
        """
        from local_observe.platform import tools

        with self.assertRaises(tools.ToolRefusal) as caught:
            tools.identity_rows([{'identity': 'night-bot', 'role': OPERATOR_AGENT,
                                   'bearer_token': 'b' * 32, 'platform_token': AGENT['token']}])
        self.assertIn(OPERATOR_AGENT, str(caught.exception))
        self.assertIn(OPERATOR_AGENT, tools.REFUSED_ROLES)
        self.assertNotIn(OPERATOR_AGENT, tools.AGENT_ROLES)

    def test_the_census_never_promises_the_role_where_the_platform_refuses_it(self):
        """The published word and the served gate, one claim: no row may name a role the route refuses."""
        refused = ('action.decide', 'action.propose', 'action.claim', 'action.execution.outcome',
                   'administration.credential.revoke', 'administration.job.cancel',
                   'administration.state.backup_request', 'administration.state.verification_request',
                   'notification.retry', 'notification.safety.reset', 'notification.deliver.request',
                   'occurrence.acknowledge.mcp', 'investigation.review.record', 'investigation.run.request',
                   'investigation.export.request', 'investigation.delivery.disarm',
                   'administration.guided_setup.plan', 'administration.guided_setup.decide')
        named = {row['operation_id']: row for row in census()}
        for operation_id in refused:
            self.assertIn(operation_id, named, 'the row this test is about has gone away')
            self.assertNotIn(OPERATOR_AGENT, named[operation_id]['required_role'], operation_id)


# ------------------------------------------------------------------ the reads, and the sweep over the census


class ReadTests(OperatorAgentFixture):
    """It reads everything a reader may read — checked against the census, not a list in a test."""

    def setUp(self) -> None:
        super().setUp()
        # Named `occurrence`, not `episode`: the fixture's `episode()` method files one, and an attribute
        # holding an id would shadow it for every case in this class.
        self.occurrence = self.open_episode()

    def served_reads(self) -> list[dict]:
        return [row for row in census()
                if row['surface'] == 'http' and row['method'] == 'GET' and row['status'] == 'implemented'
                and 'reader' in row['required_role']]

    def concrete(self, path: str) -> str:
        """One census path as a request: a path parameter becomes a canonical uuid naming nothing."""
        if '{' not in path:
            return path
        return path[:path.index('{')].rstrip('/') + '/' + str(uuid.uuid4())

    def test_the_published_roles_that_include_reader_include_this_role(self):
        """The vocabulary claim, before the behaviour: no read may open for one and stay shut for the other."""
        gaps = [{'path': row['path'], 'roles': row['required_role']} for row in census()
                if row['surface'] == 'http' and row['method'] == 'GET' and 'reader' in row['required_role']
                and OPERATOR_AGENT not in row['required_role']]
        self.assertEqual(gaps, [], 'a read a `reader` may make is a read an automated operator may make')

    def test_every_read_a_reader_may_make_is_a_read_this_role_may_make(self):
        served, answered = 0, 0
        for row in self.served_reads():
            path = self.concrete(row['path'])
            reader, agent = self.read(path, role='reader'), self.read(path)
            answered += 1
            if row['path'] in SERVED_READS:
                self.assertEqual((reader[0], agent[0]), (200, 200),
                                 f"{row['path']}: {reader[1]} / {agent[1]}")
                self.assertEqual(sorted(reader[1]), sorted(agent[1]),
                                 f"{row['path']}: the two roles were handed different documents")
                served += 1
            self.assertEqual(reader[0], agent[0],
                             f"{row['path']}: a `reader` was answered {reader[0]} and {OPERATOR_AGENT}"
                             f" was answered {agent[0]}")
            self.assertNotEqual(reader[0], 403, f"{row['path']}: the census says a reader may read this")
        self.assertGreater(answered, 25, 'the sweep must actually reach the census')
        self.assertGreater(served, 8, 'the sweep needs real documents to compare, not only refusals')

    def test_the_sweep_would_notice_a_role_that_could_read_more_than_a_reader(self):
        """The other direction, on the reads the census gives to `human` alone."""
        for path in ('/v1/jobs', '/v1/state', '/v1/credentials/dashboard', '/v1/observer/cases'):
            with self.subTest(path=path):
                reader, agent = self.read(path, role='reader'), self.read(path)
                self.assertNotEqual(agent[0], 200, f'{path}: an agent read what a reader may not')
                self.assertEqual(reader[0], agent[0], f'{path}: the two roles were treated differently')

    def test_an_agent_reads_its_own_identity_and_role(self):
        self.assertEqual(self.read('/v1/me')[1], {'identity': 'night-bot', 'role': OPERATOR_AGENT})
        self.assertEqual(self.read('/v1/me', role=HUMAN)[1], {'identity': 'operator', 'role': HUMAN})

    def test_an_agent_reads_a_human_disposition_as_a_human_decision(self):
        occurrence = self.open_episode()
        self.assertEqual(self.acknowledge(occurrence, role=HUMAN)[0], 200)
        read = self.read(f'/v1/alert-occurrences/{occurrence}')[1]
        self.assertEqual((read['disposition']['actor'], read['disposition']['actor_role']),
                         ('operator', HUMAN), 'an agent reading a person\'s act must not be told it was an act')

    def test_an_agent_reads_the_verification_ledger_on_the_same_terms_as_a_reader(self):
        """The ledger carries its own role tuple, so it is named rather than swept."""
        target = str(uuid.uuid4())
        for path in (f'/v1/verification/binding?action_id={target}',
                     f'/v1/verification/records?execution_id={target}',
                     '/v1/verification/candidates'):
            with self.subTest(path=path):
                route, query = path.split('?', 1) if '?' in path else (path, '')
                reader = self.read(route, role='reader', query=query)
                agent = self.read(route, query=query)
                self.assertEqual(reader[0], agent[0], f'{path}: {reader[1]} / {agent[1]}')
        # With no verification policy mounted the ledger answers the same for both roles (it is not a surface
        # either credential may use on this installation). What this role adds is a name in the ledger's own
        # tuple, so a deployment that *does* mount a policy answers an automated operator as it answers a
        # dashboard: that tuple lives in `verification_records`, not here, and this pins it.
        self.assertIn(OPERATOR_AGENT, verification_records.READ_ROLES)

    def test_the_published_role_enum_admits_the_new_role(self):
        """`/v1/me` and `/v1/credentials` answer a *role*, so the published enums are part of this change.

        Both schemas name a closed set, and neither would break a test that only ever asks as a `reader`: the
        document goes wrong exactly when an automated operator reads it, and a client that validates what the
        contract publishes would then reject a true answer. So the published vocabulary and the implemented one
        are pinned to each other here, and the two routes are served as the agent to prove the words are used.
        """
        with (ROOT / 'docs' / 'api' / 'openapi.yaml').open(encoding='utf-8') as handle:
            schemas = yaml.safe_load(handle)['components']['schemas']
        from local_observe.platform import state
        for name in ('ActorIdentity', 'CredentialRow'):
            with self.subTest(schema=name):
                self.assertEqual(set(schemas[name]['properties']['role']['enum']),
                                 set(state.CREDENTIAL_ROLES),
                                 'the published role enum is the credential file vocabulary, spelled the same')
        self.assertEqual(self.read('/v1/me')[1], {'identity': 'night-bot', 'role': OPERATOR_AGENT})
        listed = self.read('/v1/credentials', role=HUMAN)[1]['rows']
        row = [item for item in listed if item['identity'] == AGENT['identity']]
        self.assertEqual([item['role'] for item in row], [OPERATOR_AGENT],
                         'the mount list says which kind of operator this identity is')

    def test_the_credential_file_that_configures_the_role_is_accepted_and_one_more_is_not(self):
        from local_observe.platform.api import validate_credentials

        self.assertIsNone(validate_credentials([dict(AGENT)]))
        self.assertIsNone(validate_credentials(CREDENTIALS))
        for role in ('operator_agent', 'Operator-Agent', 'operators', 'operator-agent ', '', 'superhuman'):
            with self.subTest(refused=role):
                with self.assertRaises(ValueError):
                    validate_credentials([{'identity': 'x', 'role': role, 'token': 'k' * 32}])

    def test_the_role_vocabulary_is_one_list_three_ways(self):
        """The transport, the refusal audit and the credential-file loader all name the same seven roles."""
        from local_observe.platform import state, verification_policy

        self.assertEqual(set(refusals.ROLES), set(state.CREDENTIAL_ROLES))
        self.assertEqual(set(verification_policy.ROLES), set(refusals.ROLES))
        self.assertEqual(len(refusals.ROLES), 7, refusals.ROLES)
        self.assertIn(OPERATOR_AGENT, state.OPERATOR_ROLES)
        self.assertEqual(state.OPERATOR_ROLES, (HUMAN, OPERATOR_AGENT))

    # Reused by the disposition cases above, and named here because the refusal tests reach for it too.
    def acknowledge(self, occurrence: str, *, role: str = HUMAN, **kwargs):
        return self.send(f'/v1/alert-occurrences/{occurrence}/acknowledgements',
                         {'reason': 'looking at it now'}, role=role, **kwargs)


if __name__ == '__main__':
    unittest.main()

"""The administration family answers an operator's three questions without ever becoming a shell.

*Is this installation wired the way I think* (`GET /v1/health`, `GET /v1/boundary`), *who may call it and who
does it now refuse* (`/v1/credentials`), and *what did I ask it to do with its own database* (`/v1/state`,
`/v1/jobs`). The routes are thin; what this file tests is the four decisions underneath them, each of which is
a failure the platform would have had without it:

1. A capability is reported as `supported` only by a process that was handed it, and the two words that are
   not `supported` mean different things to an installer (`disabled` is a choice, `unavailable` is an absence).
2. A bearer that has been revoked stops working on the next request, on every instance, and is refused with
   the same bytes as a bearer that never existed.
3. A job exists only as the result of an approval naming an exact plan digest, and the 202 that books it
   carries no receipt, because the work has not happened.
4. Nothing in this family — answer, receipt, job row or error — carries token material or a file path.

Fixture style follows `tests/test_api_contract.py`: a real `Store` on a temp path and the ASGI app called
directly, so the assertions are about durable rows and not an in-process dict. Jobs are run here by calling
`administration.drain` (the same call the delivery loop makes); `tests/test_api_only_lifecycle.py` drives a
whole scenario through the served loop instead, including the wait.
"""
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from local_observe.platform import administration, administration_api, api_contract, tools
from local_observe.platform.api import create_app, idempotency_enabled
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import PLATFORM_JOB_TABLE, Actor, Store

READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
EXECUTOR = {'identity': 'worker-1', 'role': 'executor', 'token': 'e' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
CREDENTIALS = [READER, PROPOSER, EXECUTOR, SUMMARY, HUMAN]
OPERATOR = Actor('operator', 'human')


async def call(app, method, path, token, body=b'', query=b'', headers=None):
    """Send one request through the ASGI app; return status, parsed body and lowered response headers."""
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


class AdministrationTestCase(unittest.TestCase):
    """A fresh store, an app built the way a deployment builds one, and request helpers over both."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.store = self.open_store()
        self.app = create_app(self.store, CREDENTIALS, {})

    def open_store(self, mode='off'):
        """Open a second database in the same directory, at one of the three delivery modes."""
        return Store(self.root / f'state-{mode}.db', NotificationPolicy(delivery_mode=mode))

    def get(self, path, token=READER['token'], query=b'', app=None):
        return asyncio.run(call(app or self.app, 'GET', path, token, query=query))

    def post(self, path, document=None, token=HUMAN['token'], headers=None, app=None, raw=None):
        return asyncio.run(call(app or self.app, 'POST', path, token,
                                body=raw if raw is not None else json.dumps(document or {}).encode(),
                                headers=headers))

    def audit(self, operation):
        """Return the audit rows one operation wrote, oldest first, as the durable record says them."""
        with self.store.transaction() as connection:
            return [dict(row) for row in connection.execute(
                'SELECT actor, operation, subject, detail FROM audit WHERE operation=? ORDER BY sequence',
                (operation,))]

    def plan(self):
        status, document, _ = self.get('/v1/state/backup-plan', HUMAN['token'])
        self.assertEqual(status, 200)
        return document

    def book_backup(self):
        """Approve the plan just read, and assert the only answer a booking is allowed to give: 202."""
        status, document, _ = self.post('/v1/state/backups', {'approval': self.plan()['digest']})
        self.assertEqual(status, 202)
        return document

    def run_next(self):
        """Run one booked job the way the delivery loop does, and return what that call saw."""
        return administration.drain(self.store)

    def files(self, marker):
        return sorted(path.name for path in self.root.iterdir() if marker in path.name)


class HealthAndBoundary(AdministrationTestCase):
    """`GET /v1/health` may judge the schema and nothing else; the rest it reports as configured."""

    def test_every_capability_uses_the_three_word_vocabulary_and_names_its_evidence(self):
        status, document, _ = self.get('/v1/health')
        self.assertEqual(status, 200)
        self.assertEqual(document['status'], 'serving')
        self.assertEqual(set(document['capabilities']),
                         {'state', 'delivery', 'inventory', 'verification', 'runner_handoff', 'guided_setup',
                          'observer_review', 'state_jobs'})
        for name, entry in document['capabilities'].items():
            self.assertIn(entry['state'], administration_api.CAPABILITY_STATES, name)
            self.assertTrue(entry['evidence'], name)
        # The one number this endpoint is entitled to judge, the places the volatile counters live instead of
        # a second copy here, and the absence it states rather than leaving to inference.
        self.assertEqual(document['schema_version'], self.store.status()['schema_version'])
        self.assertEqual(document['see_also'], {'counts': '/v1/status', 'process_counters': '/v1/runtime'})
        self.assertIn('an operator backup schedule outside this service', document['not_measured'])

    def test_a_capability_is_supported_only_for_the_process_that_was_handed_it(self):
        recording = create_app(self.open_store('recording'), CREDENTIALS, {})
        live_without_a_sender = create_app(self.open_store('live'), CREDENTIALS, {})
        with_index = create_app(self.store, CREDENTIALS, {}, index_path=self.root / 'inventory.db')

        delivered = self.get('/v1/health', app=recording)[1]['capabilities']
        stalled = self.get('/v1/health', app=live_without_a_sender)[1]['capabilities']
        indexed = self.get('/v1/health', app=with_index)[1]['capabilities']

        # `off` is a choice this deployment made; `live` with no sender is an absence it did not choose. An
        # installer told that both are "not working" fixes the wrong one.
        self.assertEqual(self.get('/v1/health')[1]['capabilities']['delivery']['state'], 'disabled')
        self.assertEqual(delivered['delivery']['state'], 'supported')
        self.assertEqual(stalled['delivery']['state'], 'unavailable')
        self.assertEqual(stalled['delivery']['evidence']['mode'], 'live')
        self.assertEqual(self.get('/v1/health')[1]['capabilities']['inventory']['state'], 'disabled')
        self.assertEqual(indexed['inventory']['state'], 'supported')
        # The job runner is never conditional: it is this process, and it says which kinds it can run.
        self.assertEqual(indexed['state_jobs']['evidence']['kinds'], list(administration.KINDS))

    def test_boundary_is_the_document_the_agent_tool_answers_with(self):
        """One source, two transports: an agent must not be able to get two lists of what is refused."""
        status, document, _ = self.get('/v1/boundary')
        self.assertEqual(status, 200)
        self.assertEqual(document, tools.boundary_document())
        self.assertEqual(document['schema_version'], 1)

    def test_a_summary_bearer_is_refused_the_administration_reads(self):
        """The least-privilege credential sees findings, not the shape of the installation holding them.

        The transport refuses it before routing, in the flat legacy shape every other 403 in this API uses for
        a summary bearer; the route family's own `not_authorised` gate is the second line, for a caller that
        reaches `administration_api.read` without the transport in front of it. Both are asserted, because the
        interesting fact is that neither line can be skipped by choosing the other door.
        """
        for path in ('/v1/health', '/v1/boundary', '/v1/credentials', '/v1/state', '/v1/jobs'):
            status, document, _ = self.get(path, SUMMARY['token'])
            self.assertEqual((status, document['error']), (403, 'summary_only'), path)
        for path in ('/v1/health', '/v1/credentials', '/v1/state', '/v1/jobs'):
            with self.assertRaises(api_contract.ContractError) as refused:
                administration_api.read(self.store, path, b'', Actor('watcher', 'summary'),
                                       credentials=CREDENTIALS, seams={})
            self.assertEqual((refused.exception.status, refused.exception.code), (403, 'not_authorised'), path)


class TheDoor(AdministrationTestCase):
    """`/v1/credentials`: the mounted list, the durable refusals, and no secret in either direction."""

    def test_no_answer_in_this_family_contains_token_material(self):
        _, listing, _ = self.get('/v1/credentials', HUMAN['token'])
        _, single, _ = self.get('/v1/credentials/operator', HUMAN['token'])
        _, revocation, _ = self.post('/v1/credentials/watcher/revocations', {'reason': 'rotated'})
        written = json.dumps([listing, single, revocation])
        for credential in CREDENTIALS:
            self.assertNotIn(credential['token'], written)
        self.assertEqual(listing['secrets'], 'no token material is returned by any route in this family')
        self.assertEqual([row['identity'] for row in listing['rows']],
                         [row['identity'] for row in CREDENTIALS])
        self.assertNotIn('token', single)
        self.assertEqual(single['source'], 'mounted role file')

    def test_revocation_bites_on_the_next_request_and_answers_like_an_unknown_bearer(self):
        probes = [('GET', '/v1/status', b'', b''), ('GET', '/v1/jobs', b'', b''),
                  ('POST', '/v1/state/backups', json.dumps({'approval': 'a' * 64}).encode(), b'')]
        self.post('/v1/credentials/agent-1/revocations', {'reason': 'token shared in a public channel'})

        for method, path, body, query in probes:
            status, document = asyncio.run(
                call(self.app, method, path, PROPOSER['token'], body=body, query=query))[:2]
            # Identical to a bearer this installation never issued: otherwise the ledger leaks who has been
            # cut, and a revoked agent can keep probing to find out which of its names still work.
            self.assertEqual(status, 401, path)
            self.assertEqual(document, {'error': 'authentication_required'})
        self.assertEqual(self.get('/v1/status', READER['token'])[0], 200)
        # And durably, not in one process's memory: a second app over the same file refuses the same bearer.
        reopened = create_app(Store(self.store.path), CREDENTIALS, {})
        self.assertEqual(asyncio.run(call(reopened, 'GET', '/v1/health', PROPOSER['token']))[0], 401)

    def test_the_ledger_is_read_before_a_route_and_never_for_a_bearer_that_did_not_match(self):
        """The two halves of the door's cost, pinned (decision D14).

        One read-only lookup per request whose bearer matched, ahead of routing — so a revoked identity cannot
        reach a single-tenant path, a verification read or an audit write — and no lookup at all for a caller
        who presented nothing this process recognizes, which is what keeps an unauthenticated request from
        becoming a database read (`docs/CONTRACTS.md` §5). The third half is the uncomfortable one and is
        stated rather than hidden: a ledger this process cannot read refuses the request, because falling open
        would make a locked database a way to keep using a cut token.
        """
        with patch('local_observe.platform.administration.revoked', return_value=False) as door:
            self.assertEqual(self.get('/v1/status')[0], 200)
            self.assertEqual(door.call_count, 1)
            self.assertEqual(self.get('/v1/status', 'never-issued' * 2)[0], 401)
            self.assertEqual(door.call_count, 1, 'a bearer that did not match reached the ledger')
            self.assertEqual(self.get('/v1/status', SUMMARY['token'])[:2], (403, {'error': 'summary_only'}))
            self.assertEqual(door.call_count, 2, 'the door opened after the role gate instead of before it')
            self.assertEqual(door.call_args_list[1][0], (self.store.path, 'watcher'))
        with patch('local_observe.platform.administration.revoked',
                   side_effect=sqlite3.OperationalError('database is locked')):
            status, document, _ = self.get('/v1/status')
        self.assertEqual(status, 500)
        self.assertEqual(document, {'error': 'internal_error', 'detail': 'OperationalError'})
        self.assertEqual(self.get('/v1/me', READER['token'])[0], 200)   # the fault was transient, by test

    def test_the_refusals_of_a_revocation(self):
        cases = [
            ('/v1/credentials/never-mounted/revocations', {'reason': 'gone'}, 404, 'not_found'),
            ('/v1/credentials/operator/revocations', {}, 400, 'invalid_request'),
            ('/v1/credentials/operator/revocations', {'reason': '   '}, 400, 'invalid_request'),
            ('/v1/credentials/operator/revocations', {'reason': 'two\nlines'}, 400, 'invalid_request'),
            ('/v1/credentials/operator/revocations', {'reason': 'x' * 401}, 400, 'invalid_request'),
            ('/v1/credentials/operator/revocations', {'reason': 'ok', 'destination': '/tmp'}, 400,
             'invalid_request'),
            ('/v1/credentials/operator/revocations', {'reason': 'ok', 'revoked_by': 'someone-else'}, 400,
             'actor_claim_refused'),
        ]
        for path, document, status, code in cases:
            answer = self.post(path, document, HUMAN['token'])
            self.assertEqual((answer[0], answer[1]['error']['code']), (status, code), path + str(document))
        for token in (READER['token'], PROPOSER['token'], EXECUTOR['token'], SUMMARY['token']):
            self.assertEqual(self.post('/v1/credentials/operator/revocations', {'reason': 'later'},
                                       token)[0], 403)
        # Every refusal above wrote nothing: a door that recorded a refused attempt would be a way to fill
        # the ledger without authority.
        self.assertEqual(self.get('/v1/credentials', HUMAN['token'])[1]['revocations']['count'], 0)
        self.assertEqual(self.audit('credential.revoked'), [])

    def test_a_retry_of_a_lost_revocation_response_costs_no_second_record(self):
        key = [(b'idempotency-key', b'cut-1')]
        status, document, headers = self.post('/v1/credentials/watcher/revocations',
                                             {'reason': 'device lost'}, HUMAN['token'], key)
        self.assertEqual(status, 200)
        self.assertNotIn(b'x-idempotency-replayed', headers)
        replay = self.post('/v1/credentials/watcher/revocations', {'reason': 'device lost'},
                           HUMAN['token'], key)
        self.assertEqual((replay[0], replay[1]), (status, document))
        self.assertEqual(replay[2][b'x-idempotency-replayed'], b'true')
        # A second key is a second decision, and the second one is refused rather than re-stamped: a retry
        # mechanism must not be able to rewrite `revoked_at` on a record an incident already cites.
        self.assertEqual(self.post('/v1/credentials/watcher/revocations', {'reason': 'again'},
                                   HUMAN['token'], [(b'idempotency-key', b'cut-2')])[0], 409)
        self.assertEqual([(row['actor'], json.loads(row['detail'])['reason'])
                          for row in self.audit('credential.revoked')], [('operator', 'device lost')])
        rows = self.get('/v1/credentials', HUMAN['token'])[1]['rows']
        watcher = [row for row in rows if row['identity'] == 'watcher'][0]
        self.assertEqual((watcher['state'], watcher['revoked_by']), ('revoked', 'operator'))


class StateAndJobs(AdministrationTestCase):
    """A job is an approval that named an exact plan; the 202 that books it promises only a job id."""

    def test_the_reads_that_name_the_installation_are_the_human_ones(self):
        for path in ('/v1/credentials', '/v1/state', '/v1/state/backup-plan', '/v1/jobs',
                     '/v1/credentials/operator', '/v1/jobs/' + '0' * 32):
            for token in (READER['token'], PROPOSER['token'], EXECUTOR['token']):
                self.assertEqual(self.get(path, token)[0], 403, path)
        self.assertEqual(self.get('/v1/state', HUMAN['token'])[0], 200)

    def test_the_plan_is_derived_and_carries_no_path_of_its_own(self):
        first, second = self.plan(), self.plan()
        self.assertEqual(first, second)                             # derived, not stored: nothing to expire
        self.assertNotIn(self.store.path.name, json.dumps(first))   # the rule, never the file's name
        self.assertEqual(first['destination'], administration.DESTINATION_RULE)
        self.assertFalse(first['replaces_existing'])
        self.assertEqual(first['target_version'], administration.VERSION)
        self.assertEqual(self.get('/v1/state', HUMAN['token'])[1]['plan'], first)

    def test_an_approval_that_does_not_name_the_current_plan_books_nothing(self):
        status, document, _ = self.post('/v1/state/backups', {'approval': 'f' * 64})
        self.assertEqual((status, document['error']['code']), (412, 'stale_revision'))
        self.assertEqual(self.get('/v1/state', HUMAN['token'])[1]['jobs'],
                         {state: 0 for state in administration.STATES})
        self.assertEqual(self.audit('administration.job'), [])
        for raw in (b'{}', b'{"approval": "nope"}',
                    json.dumps({'approval': 'a' * 64, 'dry_run': True}).encode()):
            self.assertEqual(self.post('/v1/state/backups', raw=raw)[1]['error']['code'], 'invalid_request',
                             raw)

    def test_a_booking_answers_202_with_a_job_id_and_no_receipt(self):
        booked = self.book_backup()
        self.assertEqual(booked['state'], 'accepted')
        self.assertFalse(booked['terminal'])
        self.assertNotIn('receipt', booked)                        # the copy has not happened
        self.assertEqual(booked['plan_sha256'], self.plan()['digest'])
        self.assertEqual((booked['subject'], booked['approved_by']), ('state', 'operator'))
        self.assertEqual(booked['verification'], {'state': 'unverified', 'last_job': None, 'plan': None})
        self.assertEqual([(row['actor'], json.loads(row['detail'])['action'])
                          for row in self.audit('administration.job')], [('operator', 'approved')])
        self.assertEqual(self.get(f"/v1/jobs/{booked['job_id']}", HUMAN['token'])[0], 200)

    def test_a_booking_withdraws_only_itself_and_never_rewrites_a_reported_outcome(self):
        accepted = self.book_backup()
        status, cancelled, _ = self.post(f"/v1/jobs/{accepted['job_id']}/cancellations", {})
        self.assertEqual((status, cancelled['state'], cancelled['terminal']), (200, 'cancelled', True))
        self.assertEqual(self.post(f"/v1/jobs/{accepted['job_id']}/cancellations", {})[1]['error']['code'],
                         'conflict')

        other = self.book_backup()
        with self.store.transaction() as connection:               # as the runner would have left it
            connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=? WHERE id=?', ('running',
                                                                                       other['job_id']))
        refusal = self.post(f"/v1/jobs/{other['job_id']}/cancellations", {})
        self.assertEqual(refusal[0], 409)
        self.assertEqual(refusal[1]['error']['message'], administration.RUNNING_IS_NOT_INTERRUPTIBLE)
        self.assertEqual(self.post(f"/v1/jobs/{other['job_id']}/cancellations",
                                  {'reason': 'please'})[1]['error']['code'], 'invalid_request')
        self.assertEqual(self.post('/v1/jobs/not-a-uuid/cancellations',
                                   {})[1]['error']['code'], 'not_found')

    def test_a_booked_copy_runs_and_is_proved_by_reading_it_back(self):
        booked = self.book_backup()
        settled = self.run_next()
        self.assertEqual((settled['claimed'], settled['outcome']), (1, 'succeeded'))

        status, document, _ = self.get(f"/v1/jobs/{booked['job_id']}", HUMAN['token'])
        receipt = document['receipt']
        self.assertEqual((status, document['state']), (200, 'succeeded'))
        self.assertEqual(receipt['integrity'], 'ok')
        self.assertTrue(administration.HEX64.fullmatch(receipt['sha256']))
        self.assertTrue(receipt['artifact'].startswith(self.store.path.name + '.api-backup-'))
        self.assertTrue(administration.ARTIFACT_NAME.fullmatch(receipt['artifact']))
        artifact = self.store.path.with_name(receipt['artifact'])
        self.assertEqual(receipt['bytes'], artifact.stat().st_size)
        # The claim is not "a file was written": this build opens the copy and reads its counts, which is
        # what a caller with no shell on the host cannot do for itself.
        self.assertEqual(Store(artifact).status()['schema_version'], administration.VERSION)
        self.assertEqual(administration.recover(self.store), 0)
        self.assertEqual(self.files('.api-backup-'), [artifact.name])   # no sidecar, no second copy
        self.assertEqual(self.get('/v1/state', HUMAN['token'])[1]['last_backup']['job_id'], booked['job_id'])

    def test_verification_is_addressed_by_job_id_and_removes_what_it_copied(self):
        booked = self.book_backup()
        refused = self.post('/v1/state/verifications', {'backup_job': booked['job_id'],
                                                       'approval': 'a' * 64})
        self.assertEqual((refused[0], refused[1]['error']['message']), (409, administration.NOT_VERIFIABLE))
        self.run_next()

        plan = administration.verification_plan(self.store, booked['job_id'])
        self.assertEqual(plan['kind'], administration.VERIFICATION)
        self.assertNotIn(self.store.path.name, json.dumps(plan))
        _, verification, _ = self.post('/v1/state/verifications',
                                       {'backup_job': booked['job_id'], 'approval': plan['digest']})
        self.assertEqual((verification['state'], verification['subject']), ('accepted', booked['job_id']))
        self.assertEqual(self.run_next()['outcome'], 'succeeded')

        _, check, _ = self.get(f"/v1/jobs/{verification['job_id']}", HUMAN['token'])
        self.assertEqual(check['receipt']['digest_matches'], True)
        self.assertEqual(check['receipt']['restored_schema_version'], administration.VERSION)
        self.assertTrue(check['receipt']['scratch_removed'])
        _, backup, _ = self.get(f"/v1/jobs/{booked['job_id']}", HUMAN['token'])
        self.assertEqual((backup['verification']['state'], backup['verification']['last_job']),
                         ('succeeded', verification['job_id']))
        # The scratch file and the pre-migration copy `Store` took of *it* are both gone, and the artifact is
        # the only new file in the state directory.
        self.assertEqual(self.files('.api-verify-'), [])
        self.assertEqual(len(self.files('.api-backup-')), 1)

    def test_verification_reports_a_broken_copy_by_reason_and_names_no_file(self):
        booked = self.book_backup()
        self.run_next()
        artifact = self.store.path.with_name(
            self.get(f"/v1/jobs/{booked['job_id']}", HUMAN['token'])[1]['receipt']['artifact'])
        for damage in (lambda: artifact.unlink(), lambda: artifact.write_bytes(b'truncated')):
            damage()
            plan = administration.verification_plan(self.store, booked['job_id'])
            _, requested, _ = self.post('/v1/state/verifications',
                                        {'backup_job': booked['job_id'], 'approval': plan['digest']})
            self.assertEqual(self.run_next()['outcome'], 'failed')
            _, failed, _ = self.get(f"/v1/jobs/{requested['job_id']}", HUMAN['token'])
            self.assertIn('error', failed['receipt'])
            self.assertNotIn('/', json.dumps(failed['receipt']))
            self.assertNotIn(str(self.root), json.dumps(failed))
        rows = [self.get(f"/v1/jobs/{job['job_id']}", HUMAN['token'])[1]['receipt']['error']
                for job in administration.page(self.store, limit=10)['rows']
                if job['kind'] == administration.VERIFICATION]
        self.assertEqual(sorted(rows), sorted([administration.ARTIFACT_MISSING, administration.DIGEST_MISMATCH]))
        self.assertEqual([job['state'] for job in administration.page(self.store, limit=10)['rows']
                          if job['kind'] == administration.VERIFICATION], ['failed', 'failed'])

    def test_the_ledger_pages_by_position_and_refuses_a_filter_it_does_not_have(self):
        ids = [self.book_backup()['job_id'] for _ in range(3)]
        first = self.get('/v1/jobs', HUMAN['token'], b'limit=1')[1]
        # Newest first, one row per page: `limit=1` proves the walk, not the count.
        self.assertEqual([row['job_id'] for row in first['rows']], [ids[-1]])
        walked, cursor = [row['job_id'] for row in first['rows']], first['next_cursor']
        while cursor:
            page = self.get('/v1/jobs', HUMAN['token'], f'limit=1&cursor={cursor}'.encode())[1]
            walked += [row['job_id'] for row in page['rows']]
            cursor = page.get('next_cursor')
        self.assertEqual(sorted(walked), sorted(ids))
        self.assertEqual([row['job_id'] for row in self.get('/v1/jobs', HUMAN['token'],
                                                    b'limit=99')[1]['rows']], ids[::-1])
        for query in (b'?kind=state.backup', b'limit=0', b'limit=500', b'cursor=not-a-position',
                      b'limit=1&limit=2'):
            status, document, _ = self.get('/v1/jobs', HUMAN['token'], query.lstrip(b'?'))
            self.assertEqual((status, document['error']['code']), (400, 'invalid_pagination'), query)
        self.assertEqual(self.get('/v1/jobs/' + '0' * 32, HUMAN['token'])[1]['error']['code'], 'not_found')
        self.assertEqual(self.get('/v1/jobs/a/b/c', HUMAN['token'])[1]['error']['code'], 'not_found')
        self.assertEqual(self.get('/v1/credentials/operator/unknown', HUMAN['token'])[1]['error']['code'],
                         'not_found')

    def test_every_write_in_the_family_honours_idempotency_key(self):
        for path in ('/v1/state/backups', '/v1/state/verifications', '/v1/jobs/' + '0' * 32 + '/cancellations',
                     '/v1/credentials/operator/revocations'):
            self.assertTrue(idempotency_enabled(path), path)
        for path in ('/v1/health', '/v1/state/backup-plan', '/v1/jobs', '/v1/credentials'):
            self.assertFalse(idempotency_enabled(path), path)

        key = [(b'idempotency-key', b'copy-1')]
        digest = self.plan()['digest']
        first = self.post('/v1/state/backups', {'approval': digest}, HUMAN['token'], key)
        replay = self.post('/v1/state/backups', {'approval': digest}, HUMAN['token'], key)
        self.assertEqual(replay[2][b'x-idempotency-replayed'], b'true')
        self.assertEqual(replay[1]['job_id'], first[1]['job_id'])         # one booking, not two copies
        self.assertEqual(self.run_next()['outcome'], 'succeeded')
        self.assertEqual(len(self.files('.api-backup-')), 1)

    def test_a_job_left_running_by_a_dead_process_becomes_unknown_and_stays_that_way(self):
        booked = self.book_backup()
        with self.store.transaction() as connection:
            connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=? WHERE id=?',
                               ('running', booked['job_id']))
        self.assertEqual(administration.recover(self.store), 1)
        _, document, _ = self.get(f"/v1/jobs/{booked['job_id']}", HUMAN['token'])
        self.assertEqual((document['state'], document['terminal']), ('unknown', True))
        self.assertNotIn('receipt', document)          # nobody observed an outcome, so none is claimed
        self.assertEqual(self.post(f"/v1/jobs/{booked['job_id']}/cancellations",
                                   {})[1]['error']['code'], 'conflict')
        self.assertEqual(self.run_next()['claimed'], 0)


class TheRunner(unittest.TestCase):
    """What `drain` claims, and the ordering the ledger's own CHECKs depend on."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.store = Store(self.root / 'clock.db', NotificationPolicy(delivery_mode='off'))

    def book(self):
        return administration.request_backup(self.store, {'approval': administration.backup_plan(
            self.store)['digest']}, OPERATOR)

    def test_an_empty_ledger_is_a_normal_answer_and_not_a_claim_about_others_work(self):
        self.assertEqual(administration.drain(self.store),
                         {'claimed': 0, 'job_id': None, 'outcome': None})
        self.assertEqual(administration.recover(self.store), 0)

    def test_the_stamps_one_run_leaves_are_ordered_and_a_backwards_clock_writes_nothing(self):
        booked = self.book()
        self.assertEqual(administration.drain(self.store)['outcome'], 'succeeded')
        document = administration.job(self.store, booked['job_id'])
        self.assertTrue(document['admitted_at'] <= document['started_at'] <= document['finished_at'])

        # A claim clock that has gone backwards is refused by the schema inside the claim transaction, so the
        # row keeps `accepted` and its original stamps instead of recording a run that never happened. The
        # ledger's ordering is a CHECK rather than a convention, and this is the case that proves it holds.
        second = self.book()
        with self.assertRaises(sqlite3.IntegrityError):
            administration.drain(self.store, now=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        again = administration.job(self.store, second['job_id'])
        self.assertEqual((again['state'], again['started_at']), ('accepted', None))
        self.assertEqual(administration.drain(self.store)['outcome'], 'succeeded')

    def test_two_processes_cannot_both_claim_one_booking(self):
        """The claim is a guarded UPDATE, so a job that lost the race runs nowhere rather than twice."""
        booked = self.book()
        with self.store.transaction() as connection:
            connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=? WHERE id=?', ('running',
                                                                                       booked['job_id']))
        self.assertEqual(administration.drain(self.store), {'claimed': 0, 'job_id': None, 'outcome': None})
        self.assertEqual(administration.job(self.store, booked['job_id'])['state'], 'running')


if __name__ == '__main__':
    unittest.main()

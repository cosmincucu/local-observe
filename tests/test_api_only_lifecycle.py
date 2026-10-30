"""An operator with a token and no shell: health, a booked copy, its proof, and a cut bearer, over HTTP only.

`tests/test_administration_api.py` tests each refusal of the administration family. This file tests the one
claim that made the family worth building, which no per-route test can state: **the sequence is possible at
all** from outside the host. Before it, the honest answer to "back up that database and prove the copy
restores" was *shell in, run the CLI*. Here nothing is executed, no path is sent, no path is returned, and no
fixture calls `Store.backup`: an HTTP client reads a plan, approves one digest, is booked a job, and reads what
became of it. The file is the census claim (`administration.state.*` as `http`) made unfakeable — a route that
202'd but never ran, or ran but never reported, fails here rather than in an incident.

Two things the scenario is sensitive to, and both are deliberate:

* **The job runs because a lifespan started the delivery loop.** An app served without one leaves the row
  `accepted` forever, which the second test asserts as the honest meaning of that word rather than letting a
  test pass by running the job by hand.
* **`accepted` survives a restart, and `running` does not.** The restart case is where a platform is tempted
  to invent: `succeeded` would be a durability claim nobody observed and `failed` would discard a copy that
  may exist. `unknown` is the third answer, and it is asserted as what the *next* process reports.

The artifact is checked on the host at the end, because that is the operator's half of the bargain: the
transport hands back a name, a size and a sha256, and the bytes are reached the way an operator reaches a file.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from local_observe.platform import administration
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import PLATFORM_JOB_TABLE, Actor, Store

READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
AGENT = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
CREDENTIALS = [READER, AGENT, HUMAN]
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


class Served:
    """One app with its lifespan running, so the delivery loop that settles jobs is really alive.

    A test that called `administration.drain` would prove the runner works and nothing about the service. This
    drives the same two messages a server sends, waits for `shutdown.complete` — which the app refuses to send
    around an unfinished drain — and so keeps the whole scenario inside the product's own lifetime rules.
    """

    def __init__(self, app):
        self.app, self.inbound, self.outbound = app, asyncio.Queue(), asyncio.Queue()
        self.task = None

    async def __aenter__(self):
        self.task = asyncio.create_task(self.app({'type': 'lifespan', 'headers': []},
                                                 self.receive, self.send))
        await self.inbound.put({'type': 'lifespan.startup'})
        await self._arrived('lifespan.startup.complete')
        return self

    async def __aexit__(self, *exc_info):
        await self.inbound.put({'type': 'lifespan.shutdown'})
        await self._arrived('lifespan.shutdown.complete')
        await self.task

    async def receive(self):
        return await self.inbound.get()

    async def send(self, message):
        await self.outbound.put(message)

    async def _arrived(self, kind, timeout=30):
        """Wait for one lifespan message, and refuse to pass a lifespan that reported a failure."""
        deadline = time.monotonic() + timeout
        while True:
            message = await asyncio.wait_for(self.outbound.get(), max(0.01, deadline - time.monotonic()))
            if message['type'] == kind:
                return
            if message['type'].endswith('.failed'):
                raise AssertionError(f'the lifespan reported {message}')


class ServedLifecycle(unittest.TestCase):
    """A store, a mounted role list and the request helpers every phase below drives."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.path = self.root / 'state.db'
        self.store = Store(self.path, NotificationPolicy(delivery_mode='off'))

    def serve(self, store=None):
        return Served(create_app(store or self.store, CREDENTIALS, {}))

    def artifacts(self):
        """The copy files in the state directory, by name — what an operator with a shell would list."""
        return sorted(name for name in os.listdir(self.root) if '.api-backup-' in name and name.endswith('.db'))

    def assert_no_layout(self, *documents):
        """No answer in this session names where the database lives, nor what a bearer is.

        An artifact *name* necessarily carries the state file's own base name — that is the handle an operator
        uses to find the copy, and it is the same shape `Store._snapshot` has always used. What never crosses
        this transport is a directory, a mount point or an absolute path: `ARTIFACT_NAME` forbids `/` in the
        one field that names a file, and the plan digest covers the naming *rule* rather than the file.
        """
        written = json.dumps(documents)
        for secret in (str(self.root), str(self.path), READER['token'], AGENT['token'], HUMAN['token']):
            self.assertNotIn(secret, written)

    async def settle(self, app, job_id, token=HUMAN['token'], timeout=30):
        """Read one job until it reports its own outcome, and fail if the served loop never reached it."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, document, _ = await call(app, 'GET', f'/v1/jobs/{job_id}', token)
            self.assertEqual(status, 200)
            if document['terminal']:
                return document
            await asyncio.sleep(0.05)
        raise AssertionError(f'the served delivery loop never settled {job_id}: {document}')


class TheOperatorSession(ServedLifecycle):
    """One session: read the plan, approve it, watch it settle, prove it, then cut a leaked bearer."""

    def test_an_operator_reaches_the_state_lifecycle_and_the_door_over_http_only(self):
        async def session():
            app = create_app(self.store, CREDENTIALS, {})
            async with self.serve():
                # 1. What is this installation, and can it even take the job? Read the answer, never assume it.
                status, health, _ = await call(app, 'GET', '/v1/health', READER['token'])
                self.assertEqual(status, 200)
                self.assertEqual(health['capabilities']['state_jobs']['state'], 'supported')
                self.assertEqual(health['capabilities']['state_jobs']['evidence']['kinds'],
                                 list(administration.KINDS))
                self.assertEqual(health['capabilities']['delivery']['state'], 'disabled')

                # 2. The plan, and the number that approves it. An approval naming anything else books nothing.
                status, surface, _ = await call(app, 'GET', '/v1/state', HUMAN['token'])
                self.assertEqual((status, surface['jobs']['accepted']), (200, 0))
                wrong = await call(app, 'POST', '/v1/state/backups', HUMAN['token'],
                                   body=json.dumps({'approval': 'e' * 64}).encode())
                self.assertEqual((wrong[0], wrong[1]['error']['code']), (412, 'stale_revision'))
                self.assertEqual((await call(app, 'GET', '/v1/state', HUMAN['token']))[1]['jobs'],
                                 {state: 0 for state in administration.STATES})

                # 3. The booking: 202, a job id, and no receipt for work that has not started.
                status, booked, _ = await call(app, 'POST', '/v1/state/backups', HUMAN['token'],
                                               body=json.dumps({'approval': surface['plan']['digest']}).encode())
                self.assertEqual((status, booked['state']), (202, 'accepted'))
                self.assertNotIn('receipt', booked)
                self.assert_no_layout(health, surface, booked)

                # 4. The outcome, from the ledger alone. Nothing on the host was touched to get here.
                settled = await self.settle(app, booked['job_id'])
                self.assertEqual(settled['state'], 'succeeded')
                receipt = settled['receipt']
                self.assertEqual(len(receipt['sha256']), 64)
                self.assert_no_layout(settled)

                # 5. What the operator is handed is a name, a size and a digest — and that is enough to check
                #    the copy with the tools of the host, which is the half this API deliberately does not do.
                artifact = self.path.with_name(receipt['artifact'])
                self.assertTrue(administration.ARTIFACT_NAME.fullmatch(artifact.name))
                self.assertEqual(artifact.stat().st_size, receipt['bytes'])
                self.assertEqual(_sha256(artifact), receipt['sha256'])
                self.assertEqual(Store(artifact).status()['schema_version'], administration.VERSION)
                self.assertEqual(self.artifacts(), [artifact.name])

                # 6. The proof that a file written is a file that restores, addressed by the job that wrote it.
                self.assertEqual(settled['verification']['state'], 'unverified')
                plan = administration.verification_plan(self.store, booked['job_id'])
                status, verification, _ = await call(app, 'POST', '/v1/state/verifications', HUMAN['token'],
                                                     body=json.dumps({'backup_job': booked['job_id'],
                                                                      'approval': plan['digest']}).encode())
                self.assertEqual(status, 202)
                checked = await self.settle(app, verification['job_id'])
                self.assertTrue(checked['receipt']['digest_matches'])
                self.assertTrue(checked['receipt']['scratch_removed'])
                _, proven, _ = await call(app, 'GET', f"/v1/jobs/{booked['job_id']}", HUMAN['token'])
                self.assertEqual(proven['verification']['state'], 'succeeded')
                self.assertEqual(self.artifacts(), [artifact.name])       # the check wrote no second copy
                self.assert_no_layout(verification, checked, proven)

                # 7. The ledger answers "what did I ask for" with no filter to forget enforcing, newest first.
                status, ledger, _ = await call(app, 'GET', '/v1/jobs', HUMAN['token'])
                self.assertEqual([row['kind'] for row in ledger['rows']],
                                 [administration.VERIFICATION, administration.BACKUP])
                self.assertEqual(ledger['returned'], 2)

                # 8. And the door: a leaked agent token is cut from the incident, and it stops working on the
                #    call after the one that cut it — here, and on any other process over the same file.
                _, door, _ = await call(app, 'GET', '/v1/credentials', HUMAN['token'])
                agent = [row for row in door['rows'] if row['identity'] == 'agent-1'][0]
                self.assertEqual(agent['state'], 'active')
                self.assertEqual((await call(app, 'GET', '/v1/status', AGENT['token']))[0], 200)
                status, revocation, _ = await call(app, 'POST', '/v1/credentials/agent-1/revocations',
                                                   HUMAN['token'],
                                                   body=json.dumps({'reason': 'shared in a public channel'}).encode())
                self.assertEqual((status, revocation['state'], revocation['revoked_by']),
                                 (200, 'revoked', 'operator'))
                self.assertEqual((await call(app, 'GET', '/v1/status', AGENT['token']))[:2],
                                 (401, {'error': 'authentication_required'}))
                _, row, _ = await call(app, 'GET', '/v1/credentials/agent-1', HUMAN['token'])
                self.assertEqual(row['state'], 'revoked')
                # An identity nobody mounted answers identically: the ledger does not leak who has been cut.
                self.assertEqual((await call(app, 'GET', '/v1/credentials', AGENT['token']))[:2],
                                 (await call(app, 'GET', '/v1/credentials', 'never-issued' * 3))[:2])
                self.assert_no_layout(revocation, door, row)

        asyncio.run(session())


class WordsThatSurviveARestart(ServedLifecycle):
    """`accepted` is a promise on the file; `running` after a death is something nobody may invent."""

    def test_a_booked_job_waits_for_a_process_and_a_forgiven_one_is_reported_not_guessed(self):
        booked = administration.request_backup(
            self.store, {'approval': administration.backup_plan(self.store)['digest']}, OPERATOR)

        # Phase one: an app served *without* a lifespan, which is what a router that forgets to run one gives
        # a caller — a booking that is durable and a job that honestly says nobody has reached it yet. Nothing
        # here runs the job by hand, so `accepted` is tested as a claim about the file rather than a step.
        orphan = create_app(self.store, CREDENTIALS, {})

        async def phase_one():
            status, document, _ = await call(orphan, 'GET', f"/v1/jobs/{booked['job_id']}", HUMAN['token'])
            self.assertEqual((status, document['state'], document['terminal']), (200, 'accepted', False))
            self.assertEqual(self.artifacts(), [])

        asyncio.run(phase_one())

        # Phase two: a new process over the same file. `recover` finds nothing to forgive — the row was never
        # claimed — and then the loop takes the booking the old process left behind and finishes it.
        reopened = Store(self.path, NotificationPolicy(delivery_mode='off'))
        app = create_app(reopened, CREDENTIALS, {})

        async def phase_two():
            async with self.serve(reopened):
                document = await self.settle(app, booked['job_id'])
                self.assertEqual(document['state'], 'succeeded')
                self.assertEqual(len(self.artifacts()), 1)

        asyncio.run(phase_two())

        # Phase three: a row left `running` by a process that died holding it. The next boot may not say what
        # the copy contained, so it says it does not know, and that answer is terminal.
        stuck = administration.request_backup(
            reopened, {'approval': administration.backup_plan(reopened)['digest']}, OPERATOR)
        with reopened.transaction() as connection:
            connection.execute(f'UPDATE {PLATFORM_JOB_TABLE} SET state=? WHERE id=?', ('running',
                                                                                       stuck['job_id']))
        after_crash = Store(self.path, NotificationPolicy(delivery_mode='off'))
        app = create_app(after_crash, CREDENTIALS, {})

        async def phase_three():
            async with self.serve(after_crash):
                status, document, _ = await call(app, 'GET', f"/v1/jobs/{stuck['job_id']}", HUMAN['token'])
                self.assertEqual((status, document['state'], document['terminal']), (200, 'unknown', True))
                self.assertNotIn('receipt', document)
                # An explicit empty object: `api.py` requires a JSON body on every POST, and a cancellation
                # takes no *fields*, which is a different sentence from taking nothing at all.
                cancellation = await call(app, 'POST', f"/v1/jobs/{stuck['job_id']}/cancellations",
                                          HUMAN['token'], body=b'{}')
                self.assertEqual(cancellation[1]['error']['code'], 'conflict')
                # The count an operator reads says how many rows are in this condition, rather than hiding
                # them in a ledger that looks finished.
                _, surface, _ = await call(app, 'GET', '/v1/state', HUMAN['token'])
                self.assertEqual(surface['jobs']['unknown'], 1)

        asyncio.run(phase_three())


def _sha256(path: Path) -> str:
    """Hash one artifact the way the job did, from the operator's side of the bargain."""
    context = hashlib.sha256()
    with path.open('rb') as handle:
        while block := handle.read(1 << 20):
            context.update(block)
    return context.hexdigest()


if __name__ == '__main__':
    unittest.main()

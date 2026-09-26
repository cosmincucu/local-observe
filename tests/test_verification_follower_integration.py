"""Follower discovery, authenticated HTTP submission and saved history on the real combined API.

HTTPX uses ASGITransport on one owned loop; no live socket or service is involved.
Telemetry is the product's seeded StoreClient backend. Fixture actions are really
proposed, approved, claimed and completed; only transport acknowledgement loss is injected.
"""
import asyncio
import copy
import datetime as dt
from pathlib import Path
from unittest import mock
import uuid

import httpx

from tests import test_verification_api_boundary as edge
from tests import test_verification_records as cases
from local_observe.http import TransportError
from local_observe.inventory.validation import utc_text
from local_observe.platform import verification_follower as follower
from local_observe.platform.api import create_app
from local_observe.store.backends.memory import InMemoryStore
from local_observe.store.client import MetricSample


class HTTPBridge:
    """Synchronous worker client backed by authenticated requests to the actual ASGI app."""
    def __init__(self, store, gate):
        self.app = create_app(store, edge.CREDENTIALS, gate)
        self.loop = asyncio.Runner()
        self.identity = cases.VERIFIER.identity
        self.calls = []
        self.responses = []
        self.lose_ack = False

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))

        async def exchange():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                         base_url='https://platform.example.com') as client:
                return await client.request(method, path, json=payload,
                                            headers={'Authorization': 'Bearer ' + edge.TOKENS[self.identity]})

        response = self.loop.run(asyncio.wait_for(exchange(), timeout=10))
        answer = response.json()
        self.responses.append((response.status_code, copy.deepcopy(answer)))
        if method == 'POST' and self.lose_ack:
            self.lose_ack = False
            if response.status_code != 200:
                raise AssertionError('The injected lost acknowledgement must follow a real acceptance')
            raise TransportError('Synthetic acknowledgement loss after accepted write')
        return response.status_code, answer

    def close(self):
        self.app.verification_api.close()
        self.loop.run(asyncio.wait_for(self.app.verification_api.wait_idle(), timeout=10))
        self.loop.close()


class MeasuredFixtureStore(InMemoryStore):
    def __init__(self, rows):
        super().__init__(rows)
        self.reads = []

    def read(self, query_type, **kwargs):
        self.reads.append((query_type, copy.deepcopy(kwargs)))
        return super().read(query_type, **kwargs)


class FollowerIntegrationTests(cases.VerificationFixture):
    def setUp(self):
        super().setUp()
        self.clock = edge.ServerClock(cases.RECORD_NOW).install(self)
        self.case = self.bound(policy=self.policy())
        with mock.patch('local_observe.platform.state.uuid.uuid4', return_value=uuid.UUID(
                '10000000-0000-4000-8000-000000000001')):
            self.executed(self.case)
        self.platform = HTTPBridge(self.case['store'], self.gate)
        self.addCleanup(self.platform.close)
        self.settings = follower.config({
            'schema_version': 1, 'platform_url': 'https://platform.example.com',
            'platform_token_file': str(self.root / 'platform-token'),
            'cursor_path': str(self.root / 'follow.json'),
            'store_url': 'https://store.example.com', 'store_user': 'readonly',
            'store_password_file': str(self.root / 'store-password'), 'page_size': 1})
        self.telemetry = MeasuredFixtureStore([self.sample(95)])

    def sample(self, value, *, at=cases.RECORD_NOW):
        return MetricSample(cases.SERIES, value, utc_text(at - dt.timedelta(seconds=1)),
                            resource_id=self.host)

    def tick(self, *, now=None):
        return follower.tick(self.settings, self.platform, lambda: self.telemetry,
                             now=self.clock.moment if now is None else now)

    def saved(self, execution=None):
        execution = execution or self.case['execution_id']
        status, listing = self.platform.request('GET', '/v1/verification/records?execution_id=' + execution)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing['verification_ids']), 1)
        status, document = self.platform.request(
            'GET', '/v1/verification/record?verification_id=' + listing['verification_ids'][0])
        self.assertEqual(status, 200)
        return document

    def test_real_discovery_to_saved_not_cleared_preserves_runner_and_incident(self):
        before = {name: self.case['store'].records(name) for name in ('executions', 'actions', 'incidents')}
        self.assertEqual(self.tick()['submitted'], 1)
        document = self.saved()
        self.assertEqual(document['verdict'], 'not_cleared')
        self.assertEqual(document['recorded_by'], cases.VERIFIER.identity)
        self.assertEqual(document['value'], 95)
        self.assertEqual(document['execution_id'], self.case['execution_id'])
        self.assertEqual(self.case['store'].status()['incidents'], {'open': 1})
        self.assertEqual(before, {name: self.case['store'].records(name) for name in before})
        self.assertEqual(before['executions'][0]['status'], 'succeeded')
        self.assertEqual(len(self.telemetry.reads), 1)
        self.assertTrue(all('/actions/' not in path and path != '/v1/events'
                            for _, path, _ in self.platform.calls))
        status, page = self.platform.request('GET', '/v1/verification/candidates')
        self.assertEqual((status, page), (200, {'items': [], 'next_after': None}))

    def test_lost_http_ack_replays_after_expiry_without_discovery_or_sampling(self):
        self.platform.lose_ack = True
        with self.assertRaises(TransportError):
            self.tick()
        pending = follower.load_cursor(self.settings)['pending']['statements'][0]
        original = self.saved()
        self.clock.advance(dt.timedelta(days=40))
        self.platform.calls.clear()
        with mock.patch.object(self.telemetry, 'read', side_effect=AssertionError('Replay must not resample')):
            self.assertEqual(self.tick()['status'], 'replayed')
        self.assertEqual(self.platform.calls, [('POST', '/v1/verification/records', pending)])
        self.assertFalse(self.platform.responses[-1][1]['created'])
        self.assertEqual(self.saved(), original)
        self.assertIsNone(follower.load_cursor(self.settings)['pending'])
        audits = [row for row in self.case['store'].records('audit') if row['operation'] == 'verification.recorded']
        self.assertEqual(len(audits), 1)

    def test_immature_first_page_does_not_starve_mature_run_and_wrap_revisits_it(self):
        proposed, _ = self.propose(self.case['store'], self.case['incident_id'], [self.case['event_id']],
                                   retry_key='second-run')
        second = {'store': self.case['store'], 'action_id': proposed['action_id']}
        with mock.patch('local_observe.platform.state.uuid.uuid4', return_value=uuid.UUID(
                '00000000-0000-4000-8000-000000000001')):
            self.executed(second, at=cases.RECORD_NOW - dt.timedelta(seconds=60))
        self.assertEqual(self.tick()['waiting'], 1)
        self.assertEqual(len(self.telemetry.reads), 0)
        self.assertEqual(follower.load_cursor(self.settings)['after'], second['execution_id'])
        self.assertEqual(self.tick()['submitted'], 1)
        self.assertIsNone(follower.load_cursor(self.settings)['after'])
        self.clock.advance(dt.timedelta(minutes=6))
        self.telemetry.load([self.sample(70, at=self.clock.moment)])
        self.assertEqual(self.tick()['submitted'], 1)
        self.assertEqual(self.saved(second['execution_id'])['verdict'], 'cleared')
        self.assertEqual(self.case['store'].status()['incidents'], {'open': 1})

    def test_large_real_store_page_cannot_be_shortened_into_clearance(self):
        self.telemetry = MeasuredFixtureStore([self.sample(1)] * 20 + [self.sample(95)])
        self.assertEqual(self.tick()['submitted'], 1)
        document = self.saved()
        self.assertEqual(document['verdict'], 'unknown')
        self.assertTrue(document['receipt']['truncated'])
        self.assertEqual(document['receipt']['sample_count'], 21)
        self.assertEqual(len(document['samples']), 20)
        self.assertIsNone(document['value'])
        self.assertEqual(self.tick()['submitted'], 0)
        self.assertEqual(len(self.telemetry.reads), 1)

    def test_candidate_authentication_refuses_unlisted_producer_and_reader_before_cursor(self):
        for identity in ('test-detector', 'reader-1'):
            with self.subTest(identity=identity):
                self.platform.identity = identity
                status, _ = self.platform.request('GET', '/v1/verification/candidates')
                self.assertEqual(status, 403)
                with self.assertRaises(follower.FollowerError):
                    self.tick()
                self.assertFalse(Path(self.settings['cursor_path']).exists())
        self.assertEqual(self.telemetry.reads, [])
        self.platform.identity = cases.VERIFIER.identity
        self.assertEqual(self.tick()['submitted'], 1)


    def test_second_lost_ack_resumes_after_durable_first_ack(self):
        self.settings['page_size'] = 2
        proposed, _ = self.propose(self.case['store'], self.case['incident_id'], [self.case['event_id']],
                                   retry_key='second-mature-run')
        second = {'store': self.case['store'], 'action_id': proposed['action_id']}
        with mock.patch('local_observe.platform.state.uuid.uuid4', return_value=uuid.UUID(
                '20000000-0000-4000-8000-000000000001')):
            self.executed(second)
        request = self.platform.request
        posts = []

        def lose_second_ack(method, path, payload=None):
            if method == 'POST':
                posts.append(copy.deepcopy(payload))
                self.platform.lose_ack = len(posts) == 2
            return request(method, path, payload)

        with mock.patch.object(self.platform, 'request', side_effect=lose_second_ack):
            with self.assertRaises(TransportError):
                self.tick()
        state = follower.load_cursor(self.settings)
        self.assertEqual(state['pending']['next_index'], 1)
        self.assertEqual(state['pending']['statements'], posts)
        self.assertEqual(len(posts), 2)
        self.assertEqual([row['execution_id'] for row in posts],
                         [self.case['execution_id'], second['execution_id']])
        before = [self.saved(), self.saved(second['execution_id'])]
        self.assertEqual(len(self.telemetry.reads), 2)
        self.clock.advance(dt.timedelta(days=40))
        self.platform.calls.clear()
        with mock.patch.object(self.telemetry, 'read', side_effect=AssertionError('Replay must not resample')):
            self.assertEqual(self.tick()['status'], 'replayed')
        self.assertEqual(self.platform.calls, [('POST', '/v1/verification/records', posts[1])])
        self.assertFalse(self.platform.responses[-1][1]['created'])
        self.assertEqual([self.saved(), self.saved(second['execution_id'])], before)
        self.assertIsNone(follower.load_cursor(self.settings)['pending'])
        audits = [row for row in self.case['store'].records('audit') if row['operation'] == 'verification.recorded']
        self.assertEqual(len(audits), 2)

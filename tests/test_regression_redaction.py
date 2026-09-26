"""Regression: runner tokens and delivery lease tokens must never reach a read path.

Ledger regression tests, from `docs/remediation/reports/REPORT_TESTS.md` §4/§5: `Store.records()`
(`local_observe/platform/state.py:414-421`) pops `token_hash` and `claim_token` from every row it
hands to a reader, and `GET /v1/records/<table>` (`local_observe/platform/api.py:109-114`) renders
exactly that list for the operator UI. Before this file, `records()` had only ever been called on
`audit`, `events`, `incidents` and `outbox` — the three tables that actually hold a live secret
(`actions` never does, but `executions.token_hash`, `outbox.claim_token` and
`notification_attempts.claim_token` all do) were unchecked, so dropping the pop from the redaction
loop would publish a bearer credential to every `reader` token on the network.
"""
import asyncio
import datetime as dt
import json
from pathlib import Path
import sqlite3
from contextlib import closing
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform.api import create_app
from local_observe.platform.detections import event
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:00:00Z')
PRODUCER = Actor('test-detector', 'producer')
AGENT = Actor('agent-1', 'proposer')
HUMAN = Actor('operator', 'human')
RUNNER = Actor('runner-1', 'executor')
READER = 'r' * 32
CREDENTIALS = [{'identity': 'reader', 'role': 'reader', 'token': READER}]
TABLES = ('actions', 'executions', 'outbox', 'notification_attempts', 'audit', 'events', 'incidents')
SECRETS = ('token_hash', 'claim_token')


def keys(value):
    """Yield every mapping key in a nested JSON structure, so a renamed leak is still caught."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from keys(child)


async def read(app, path: str) -> tuple[int, dict]:
    """Fetch one JSON document through the ASGI app as the `reader` credential; no socket."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': b''}

    async def send(message):
        output.append(message)
    auth = (b'authorization', ('Bearer ' + READER).encode())
    await app({'type': 'http', 'method': 'GET', 'path': path, 'headers': [auth]}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class RedactionTests(unittest.TestCase):
    """Every credential the store mints stays inside the store, on both read paths."""

    def setUp(self):
        """Reach the only state that holds secrets: a claimed action and a claimed delivery."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = declared['resources'][0]['id']
        declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        self.store = Store(self.root / 'state.db')

        window = {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)}
        self.store.intake(event(PRODUCER.identity, self.host, 'availability', 'availability', 'firing', window,
                                {'sample_id': 'fixture'}, query_type='gatus-result'), PRODUCER, now=NOW)
        request = {'retry_key': 'once', 'incident_id': self.store.records('incidents')[0]['id'], 'action': 'inspect',
                   'version': '1', 'targets': [self.host], 'parameters': {},
                   'evidence': [self.store.records('events')[0]['id']],
                   'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        action = self.store.propose_action(request, AGENT, self.policy, now=NOW)
        self.store.decide(action['action_id'], 'approved', HUMAN, now=NOW)
        self.runner_token = self.store.claim_action(action['action_id'], RUNNER, self.policy, now=NOW)['runner_token']
        self.delivery_claim = self.store.claim_notification(now=NOW)['claim_token']

    def raw(self, table: str, column: str) -> list:
        """Read one column with raw sqlite, bypassing the redaction under test."""
        with closing(sqlite3.connect(self.store.path)) as connection:
            return [row[0] for row in connection.execute(f'SELECT {column} FROM {table}')]

    def secrets(self) -> list[str]:
        """Every credential string currently held in the database, plus the two tokens this fixture minted."""
        digests = [value for value in self.raw('executions', 'token_hash') if value]
        leases = [value for value in self.raw('outbox', 'claim_token') if value]
        attempts = [value for value in self.raw('notification_attempts', 'claim_token') if value]
        self.assertNotIn(self.runner_token, digests, 'the store kept the runner token itself, not a hash')
        return [self.runner_token, self.delivery_claim] + digests + leases + attempts

    def assert_clean(self, document) -> None:
        """Fail if any secret column name or secret value appears anywhere in a read-path document."""
        found = set(keys(document)) & set(SECRETS)
        self.assertEqual(found, set(), 'a credential column reached a reader: %s' % sorted(found))
        body = json.dumps(document)
        for secret in self.secrets():
            self.assertNotIn(secret, body, 'a live credential value reached a reader')

    def test_every_table_holds_the_rows_the_redaction_loop_must_cover(self):
        """Guard against a vacuous pass: each table has rows, and the credentials really are stored."""
        for table in TABLES:
            with self.subTest(table=table):
                self.assertTrue(self.store.records(table), 'no rows to redact from %s' % table)
        digests = [value for value in self.raw('executions', 'token_hash') if value]
        leases = [value for value in self.raw('outbox', 'claim_token') if value]
        attempts = [value for value in self.raw('notification_attempts', 'claim_token') if value]
        self.assertEqual((len(digests), len(leases), len(attempts)), (1, 1, 1), 'nothing stored to redact')
        self.assertNotIn(self.runner_token, digests, 'the store kept the runner token itself, not a hash')
        self.assertEqual(leases, attempts, 'the live lease and its attempt row must share a token')
        self.assertEqual(len(self.secrets()), 5, 'two minted tokens plus the three stored credential columns')

    def test_records_expose_no_credential_column_or_value(self):
        """`Store.records()` returns business state only, for every table a reader may ask for."""
        for table in TABLES:
            with self.subTest(table=table):
                self.assert_clean(self.store.records(table))

    def test_http_records_expose_no_credential_column_or_value(self):
        """The same rows over `GET /v1/records/<table>` — the path an operator UI actually calls."""
        app = create_app(self.store, CREDENTIALS, self.policy)

        async def exercise():
            for table in TABLES:
                status, body = await read(app, '/v1/records/' + table)
                self.assertEqual(status, 200, table)
                self.assertTrue(body['rows'], table)
                self.assert_clean(body)
            self.assertEqual((await read(app, '/v1/records/nothing'))[0], 400)
        asyncio.run(exercise())

    def test_a_claim_is_still_usable_after_being_read(self):
        """Redaction is a read-path view: the holder of the token can still finish with it."""
        self.assert_clean(self.store.records('outbox'))
        self.assert_clean(self.store.records('notification_attempts'))
        self.assertEqual(self.store.finish_notification(self.store.records('outbox')[0]['id'], self.delivery_claim,
                                                        True, now=NOW), 'sent')
        self.assertEqual(self.store.status()['notifications'], {'sent': 1})
        outcome = self.store.execution_outcome(self.store.records('executions')[0]['id'], 'succeeded', RUNNER,
                                               self.runner_token, now=NOW)
        self.assertEqual(outcome['status'], 'succeeded')
        self.assert_clean(self.store.records('executions'))


if __name__ == '__main__':
    unittest.main()

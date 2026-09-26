"""Authentication boundaries and deployment settings without optional API dependencies."""
import asyncio
import base64
from pathlib import Path
import unittest

import yaml

from local_observe.inventory.api import authenticate, protect


class InventoryAuthTests(unittest.TestCase):
    token = 'separate-inventory-fixture-token-123'

    def test_bearer_and_basic(self):
        self.assertTrue(authenticate([(b'authorization', ('Bearer ' + self.token).encode())], self.token))
        encoded = base64.b64encode(('operator:' + self.token).encode())
        self.assertTrue(authenticate([(b'Authorization', b'Basic ' + encoded)], self.token))

    def test_ambiguous_and_malformed_headers(self):
        valid = (b'authorization', ('Bearer ' + self.token).encode())
        for headers in ([], [valid, valid], [(b'authorization', b'Basic !!!')],
                        [(b'authorization', b'Bearer wrong')],
                        [(b'authorization', b'Basic ' + base64.b64encode(('admin:' + self.token).encode()))]):
            with self.subTest(headers=len(headers)):
                self.assertFalse(authenticate(headers, self.token))

    def test_short_credential_rejected(self):
        with self.assertRaises(ValueError):
            protect(None, 'short')

    def test_write_and_websocket_never_reach_app(self):
        async def exercise():
            async def forbidden(*args):
                self.fail('Request reached upstream')
            for scope, expected in (
                ({'type': 'http', 'method': 'POST', 'headers': [(b'authorization', ('Bearer ' + self.token).encode())]}, 405),
                ({'type': 'http', 'method': 'GET', 'headers': [], 'query_string': ('token=' + self.token).encode()}, 401),
                ({'type': 'websocket'}, 1008),
            ):
                messages = []
                async def send(message):
                    messages.append(message)
                await protect(forbidden, self.token)(scope, None, send)
                self.assertEqual(messages[0].get('status', messages[0].get('code')), expected)
        asyncio.run(exercise())

    def test_compose_read_boundary(self):
        path = Path(__file__).resolve().parents[1] / 'components/knowledge/inventory/compose.yaml'
        service = yaml.safe_load(path.read_text())['services']['inventory']
        self.assertEqual(service['tmpfs'], ['/tmp:rw,noexec,nosuid,size=67108864'])
        self.assertTrue(service['read_only'])
        self.assertEqual(service['cap_drop'], ['ALL'])
        self.assertEqual(service['user'], '65532:65532')
        self.assertTrue(service['volumes'][0]['read_only'])
        self.assertTrue(service['ports'][0].startswith('127.0.0.1:'))

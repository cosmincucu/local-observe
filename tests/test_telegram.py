import io
import json
import unittest
import urllib.error
import uuid

from local_observe.http import TransportError
from local_observe.platform.state import StateError
from local_observe.platform.telegram import TelegramClient, NoRedirect


class Opener:
    def __init__(self, receipt):
        self.receipt = receipt
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if isinstance(self.receipt, Exception):
            raise self.receipt
        response = io.BytesIO(json.dumps(self.receipt).encode())
        response.status = 200
        return response


class TelegramTests(unittest.TestCase):
    def setUp(self):
        self.payload = {'delivery_id': str(uuid.uuid4()), 'incident_id': str(uuid.uuid4()),
                        'transition': 'opened', 'event': {'resource_id': str(uuid.uuid4()), 'data_class': 'internal',
                                                         'evidence': 'must-not-leave-platform'}}
        self.headers = {'Idempotency-Key': self.payload['delivery_id']}

    def test_send_only_minimal_payload(self):
        opener = Opener({'ok': True, 'result': {'message_id': 12, 'chat': {'id': 123}}})
        client = TelegramClient('123:synthetic', '123', opener=opener)
        _, receipt = client.request('POST', payload=self.payload, headers=self.headers)
        self.assertTrue(receipt['accepted'])
        request = opener.requests[0]
        self.assertTrue(request.full_url.endswith('/sendMessage'))
        self.assertNotIn('must-not-leave', request.data.decode())
        self.assertNotIn('parse_mode', request.data.decode())
        message = json.loads(request.data)['text']
        self.assertIn('Delivery: Telegram', message)
        self.assertTrue(message.startswith('[local-observe] ALERT — resource label missing @ host label missing\n'), message)
        self.assertNotIn('staging', message.lower())
        self.assertNotIn(self.payload['incident_id'], message)
        self.assertNotIn(self.payload['delivery_id'], message)

    def test_named_notification_never_exports_evidence(self):
        from unittest.mock import patch
        opener = Opener({'ok': True, 'result': {'message_id': 12, 'chat': {'id': 123}}})
        client = TelegramClient('123:synthetic', '123', opener=opener,
                                display_config={'channel_name': 'Ops alerts / Telegram'})
        with patch('local_observe.platform.presentation.describe', return_value={
                'description': 'Backup job failed', 'resource_name': 'Estate backup', 'host_name': 'probe-host-1'}):
            client.request('POST', payload=self.payload, headers=self.headers)
        message = json.loads(opener.requests[0].data)['text']
        for value in ('Incident: Backup job failed', 'Resource: Estate backup', 'Host: probe-host-1',
                      'Delivery: Ops alerts / Telegram'):
            self.assertIn(value, message)
        self.assertNotIn('must-not-leave', message)

    def test_message_prefix_is_configured_not_hardcoded(self):
        opener = Opener({'ok': True, 'result': {'message_id': 12, 'chat': {'id': 123}}})
        client = TelegramClient('123:synthetic', '123', opener=opener, display_config={'message_prefix': '[lab pilot]'})
        client.request('POST', payload=self.payload, headers=self.headers)
        self.payload['transition'] = 'resolved'
        client.request('POST', payload=self.payload, headers=self.headers)
        first = json.loads(opener.requests[0].data)['text']
        second = json.loads(opener.requests[1].data)['text']
        self.assertTrue(first.startswith('[lab pilot] ALERT — resource label missing @ host label missing\n'), first)
        self.assertTrue(second.startswith('[lab pilot] RECOVERED — resource label missing @ host label missing\n'), second)

    def test_missing_or_oversized_prefix_falls_back_to_the_default(self):
        """A prefix that is absent, empty, non-text or oversized cannot reach the message unbounded."""
        cases = (('unset', {}, '[local-observe]'),
                 ('null', {'message_prefix': None}, '[local-observe]'),
                 ('empty', {'message_prefix': ''}, '[local-observe]'),
                 ('whitespace', {'message_prefix': '   \n  '}, '[local-observe]'),
                 ('non-string', {'message_prefix': 7}, '[local-observe]'),
                 ('collapsed', {'message_prefix': '  pilot   one  '}, 'pilot one'),
                 ('bounded', {'message_prefix': 'x' * 400}, 'x' * 160))
        for label, display, expected in cases:
            with self.subTest(prefix=label):
                opener = Opener({'ok': True, 'result': {'message_id': 12, 'chat': {'id': 123}}})
                client = TelegramClient('123:synthetic', '123', opener=opener, display_config=display)
                client.request('POST', payload=self.payload, headers=self.headers)
                message = json.loads(opener.requests[0].data)['text']
                self.assertTrue(message.startswith(expected + ' ALERT — resource label missing @ host label missing\n'), message[:60])

    def test_wrong_recipient_not_acknowledged(self):
        client = TelegramClient('123:synthetic', '123', opener=Opener({'ok': True, 'result': {'message_id': 1, 'chat': {'id': 456}}}))
        self.assertFalse(client.request('POST', payload=self.payload, headers=self.headers)[1]['accepted'])

    def test_restricted_and_polling_refused(self):
        opener = Opener({})
        client = TelegramClient('123:synthetic', '123', opener=opener)
        with self.assertRaises(StateError):
            client.request('GET', '/getUpdates')
        self.payload['event']['data_class'] = 'restricted'
        with self.assertRaises(StateError):
            client.request('POST', payload=self.payload, headers=self.headers)
        self.assertEqual(opener.requests, [])

    def test_url_secret_removed_on_failure(self):
        client = TelegramClient('123:synthetic', '123', opener=Opener(urllib.error.URLError('123:synthetic')))
        with self.assertRaises(TransportError) as caught:
            client.request('POST', payload=self.payload, headers=self.headers)
        self.assertNotIn('synthetic', str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_redirect_refused(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid'))


class ApprovalLineTests(unittest.TestCase):
    """The single-use approval code a send may carry, and every reason it must not be printed.

    Ledger notifications: the phone is the approval surface (phone surface), so the alert has to say where the code
    goes.
    It may not say it in a way that puts the code in a URL, a query string or a path — those are logged
    by everything between the phone and this process — so the line names the route and shows the code
    separately. Every malformed input fails closed by omitting the line entirely: a truncated or wrong
    destination is worse than no destination, because an operator will trust whichever one they see.
    """

    BASE = 'https://edge.invalid/platform'
    CALLBACK = {'token': 'Ab3dEfGhIjKlMnOpQrStUvWx' + 'yz0123456789_-JK',  # gitleaks:allow (synthetic fixture)
                'expires_at': '2026-09-08T12:00:00+00:00', 'route': '/v1/callbacks/primary'}

    def message(self, display_config, callback=CALLBACK):
        """Send one synthetic alert through the real adapter and return the text it would post."""
        payload = {'delivery_id': str(uuid.uuid4()), 'incident_id': str(uuid.uuid4()),
                   'transition': 'opened', 'event': {'resource_id': str(uuid.uuid4()),
                                                    'data_class': 'internal'},
                   'callback': callback}
        opener = Opener({'ok': True, 'result': {'message_id': 12, 'chat': {'id': 123}}})
        TelegramClient('123:synthetic', '123', opener=opener,
                       display_config=display_config).request('POST', payload=payload,
                                                              headers={'Idempotency-Key': payload['delivery_id']})
        return json.loads(opener.requests[0].data)['text']

    def test_a_configured_destination_appends_exactly_one_line(self):
        text = self.message({'callback_base': self.BASE})
        base = self.message({})
        self.assertEqual(text.rsplit('\n', 1)[0], base)
        self.assertEqual(text.count('Approve at '), 1)
        self.assertTrue(text.endswith('Approve at ' + self.BASE + self.CALLBACK['route']
                                     + ' with code ' + self.CALLBACK['token']), text)
        self.assertNotIn('?token=', text)
        self.assertNotIn('api.telegram.org', text)

    def test_without_a_configured_destination_nothing_about_approvals_is_said(self):
        """Missing callback configuration never changes or leaks into the base alert."""
        base = self.message({})
        for display in ({}, {'callback_base': None}, {'callback_base': ''}, {'callback_base': 7}):
            with self.subTest(display=display):
                text = self.message(display)
                self.assertEqual(text, base)
                self.assertNotIn('Approve', text)
                self.assertNotIn(self.CALLBACK['token'], text)

    def test_a_destination_that_could_carry_a_secret_or_be_wrong_is_refused(self):
        """HTTP, credentials, a query, a fragment, an over-long value: all refused, silently."""
        for base in ('http://edge.invalid/platform', 'https://user@edge.invalid/platform',
                     'https://edge.invalid/platform?token=x', 'https://edge.invalid/platform#y',
                     'https://edge invalid', 'https://edge.invalid/platform/' + 'p' * 300,
                     'edge.invalid', '//edge.invalid', ''):
            with self.subTest(base=base):
                self.assertNotIn('Approve', self.message({'callback_base': base}))

    def test_a_code_that_is_not_one_this_build_minted_is_never_printed(self):
        """The payload is durable state; the line is only ever printed for a token-shaped value."""
        for callback in (None, 'not-a-dict', {}, {'route': '/v1/callbacks/primary'},
                        {'token': 'short', 'route': '/v1/callbacks/primary'},
                        {'token': 'has spaces and $(stuff)', 'route': '/v1/callbacks/primary'},
                        {'token': 'x' * 200, 'route': '/v1/callbacks/primary'},
                        {'token': self.CALLBACK['token'], 'route': 'https://edge.invalid/x'},
                        {'token': self.CALLBACK['token'], 'route': '/v1/other'}):
            with self.subTest(callback=str(callback)[:40]):
                text = self.message({'callback_base': self.BASE}, callback)
                self.assertNotIn('Approve', text)
                self.assertNotIn(self.CALLBACK['token'], text)

    def test_a_destination_with_a_port_and_a_path_is_accepted_verbatim(self):
        base = 'https://edge.invalid:8443/local-observe'
        self.assertIn('Approve at ' + base + '/v1/callbacks/primary with code',
                      self.message({'callback_base': base}))

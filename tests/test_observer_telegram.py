"""No-network acceptance for independent delivery authority and authenticated phone grades."""
from __future__ import annotations

import copy
import datetime as dt
import multiprocessing
import os
from pathlib import Path
import socket
import tempfile
import unittest
import urllib.request
from dataclasses import asdict
from unittest.mock import patch

from local_observe.observer import Config, Journal, Observer, ObserverError, Source
from local_observe.observer.contract import digest, encoded, utc
from local_observe.observer.telegram import Telegram, TelegramConfig, TelegramTransport

NOW = dt.datetime(2026, 1, 1, 12, tzinfo=dt.timezone.utc)
RESOURCE = '00000000-0000-4000-8000-000000000001'
EPOCH1 = '10000000-0000-4000-8000-000000000001'
EPOCH2 = '10000000-0000-4000-8000-000000000002'


class Telemetry:
    def read(self, source, window, now):
        return {'schema_version': 1, 'source': source.id, 'query_type': source.query_type,
                'resource_id': source.resource_id, 'window': window, 'observed_at': utc(now),
                'rows': [{'timestamp': '2026-01-01T11:59:00Z', 'value': 0.95, 'labels': {}}]}


class Finding:
    def complete(self, evidence, allowed, config, now):
        evidence_id = evidence[0]['evidence_id']
        return {'model': 'example-model', 'response_model': 'example-model', 'usage': {},
                'content': encoded({'schema_version': 1, 'decision': 'tell', 'rationale': 'Review the CPU sample.',
                    'citations': [{'evidence_id': evidence_id, 'row_index': 0, 'field': 'value', 'value': 0.95}],
                    'follow_up': [], 'findings': [{'resource_id': RESOURCE, 'kind': 'threshold',
                    'observed_at': '2026-01-01T11:59:00Z', 'evidence_ids': [evidence_id]}]})}


class FakeTelegram:
    def __init__(self, journal):
        self.journal, self.calls, self.updates = journal, [], []
        self.lose_ack = False

    def request(self, method, payload):
        self.calls.append((method, payload))
        if method == 'getUpdates':
            return self.updates
        # Independent SQLite inspection: dispatch must follow the durable budget/intent write.
        row = self.journal.db.execute("SELECT count(*) FROM observer_deliveries WHERE status='sending'").fetchone()
        if row[0] != 1:
            raise AssertionError('intent was not committed before send')
        if self.lose_ack:
            raise TimeoutError('synthetic accepted-but-lost acknowledgement')
        return {'message_id': 11, 'chat': {'id': 42}}


class TelegramTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = Journal(self.root / 'state')
        self.addCleanup(self.journal.close)
        self.observer_config = Config((Source('cpu', 'metric-threshold', RESOURCE, metric_name='cpu'),))
        self.config = TelegramConfig(str(self.root / 'telegram-token'), 42, 73)
        self.transport = FakeTelegram(self.journal)
        self.verified = []
        self.authorize = True
        self.sender = self.new_sender()
        block = patch.object(socket, 'create_connection', side_effect=AssertionError('real notification forbidden'))
        block.start()
        self.addCleanup(block.stop)
        self.cycle('cycle-1')

    def verifier(self, cycle, binding, now):
        self.verified.append(binding)
        return self.authorize and binding['model'] == 'example-model'

    def new_sender(self, journal=None, transport=None):
        return Telegram(journal or self.journal, self.config, verifier=self.verifier,
                        config_digest=digest(asdict(self.observer_config)), transport=transport or self.transport)

    def cycle(self, cycle_id):
        return Observer(self.observer_config, self.journal, sources=Telemetry(), model=Finding(),
                        clock=lambda: NOW).run(cycle_id)

    def callback(self, *, update_id=1, data=None):
        if data is None:
            data = self.transport.calls[0][1]['reply_markup']['inline_keyboard'][0][0]['callback_data']
        return {'update_id': update_id, 'callback_query': {'id': 'callback-1', 'data': data,
                 'from': {'id': 73, 'is_bot': False}, 'message': {'message_id': 11, 'chat': {'id': 42}}}}

    def test_unarmed_denied_and_changed_binding_send_nothing(self):
        with self.assertRaisesRegex(ObserverError, 'delivery_not_armed'):
            self.sender.deliver('cycle-1', now=NOW)
        self.sender.arm_after_reconciliation(EPOCH1)
        self.authorize = False
        with self.assertRaisesRegex(ObserverError, 'independent_evaluation_required'):
            self.sender.deliver('cycle-1', now=NOW)
        self.assertEqual(self.transport.calls, [])
        self.authorize = True
        self.sender.config_digest = '0' * 64
        with self.assertRaisesRegex(ObserverError, 'delivery_configuration_changed'):
            self.sender.deliver('cycle-1', now=NOW)
        self.assertEqual(self.transport.calls, [])

    def test_sends_once_minimal_message_and_separate_two_per_day_budget(self):
        self.sender.arm_after_reconciliation(EPOCH1)
        result = self.sender.deliver('cycle-1', now=NOW)
        self.assertEqual(result['status'], 'sent')
        self.assertEqual(self.sender.deliver('cycle-1', now=NOW), result)
        self.assertEqual(len(self.transport.calls), 1)
        self.assertIn('cpu=0.95 @ 2026-01-01T11:59:00Z', self.transport.calls[0][1]['text'])
        self.assertIn(RESOURCE, self.transport.calls[0][1]['text'])
        self.assertIn('coverage: complete', self.transport.calls[0][1]['text'])
        self.assertNotIn('CPU sample', encoded(self.transport.calls))
        self.cycle('cycle-2')
        self.sender.deliver('cycle-2', now=NOW)
        self.cycle('cycle-3')
        with self.assertRaisesRegex(ObserverError, 'model_delivery_budget'):
            self.sender.deliver('cycle-3', now=NOW)
        self.assertEqual(len(self.transport.calls), 2)
        self.assertEqual(self.verified[0]['config_sha256'], digest(asdict(self.observer_config)))

    def test_accepted_but_lost_ack_is_uncertain_without_any_retry_after_restart(self):
        self.sender.arm_after_reconciliation(EPOCH1)
        self.transport.lose_ack = True
        result = self.sender.deliver('cycle-1', now=NOW)
        self.assertEqual(result['status'], 'uncertain')
        reopened = Journal(self.root / 'state')
        try:
            sender = self.new_sender(reopened)
            with self.assertRaisesRegex(ObserverError, 'delivery_not_armed'):
                sender.deliver('cycle-1', now=NOW)
            sender.arm_after_reconciliation(EPOCH2)
            self.assertEqual(sender.deliver('cycle-1', now=NOW)['status'], 'uncertain')
            self.assertEqual(len(self.transport.calls), 1)
            self.assertEqual(reopened.db.execute('SELECT count(*) FROM observer_deliveries').fetchone()[0], 1)
        finally:
            reopened.close()

    def test_process_death_after_send_intent_quarantines_without_resending(self):
        def child():
            journal = Journal(self.root / 'state')
            class CrashTransport:
                def request(self, method, payload):
                    (self_root / 'accepted').write_text('one send', encoding='utf-8')
                    os._exit(19)
            self_root = self.root
            sender = self.new_sender(journal, CrashTransport())
            sender.arm_after_reconciliation(EPOCH1)
            sender.deliver('cycle-1', now=NOW)
        process = multiprocessing.get_context('fork').Process(target=child)
        process.start()
        process.join(10)
        self.assertEqual(process.exitcode, 19)
        self.assertEqual((self.root / 'accepted').read_text(encoding='utf-8'), 'one send')
        self.assertEqual(self.sender.outcome('cycle-1')['status'], 'sending')
        self.sender.arm_after_reconciliation(EPOCH2)
        self.assertEqual(self.sender.deliver('cycle-1', now=NOW)['status'], 'uncertain')
        self.assertEqual(self.transport.calls, [])

    def test_authenticated_grading_is_single_use_cursor_is_durable(self):
        self.sender.arm_after_reconciliation(EPOCH1)
        self.sender.deliver('cycle-1', now=NOW)
        self.transport.updates = [self.callback()]
        result = self.sender.poll_feedback(now=NOW)
        self.assertEqual((result['accepted'], result['cursor']), (1, 2))
        feedback = self.journal.replay('cycle-1')['feedback']
        self.assertEqual(len(feedback), 1)
        self.assertEqual((feedback[0]['reviewer'], feedback[0]['usefulness'], feedback[0]['correctness']),
                         ('telegram-user:73', 'useful', 'correct'))
        self.assertFalse(feedback[0]['export_approved'])
        self.transport.updates = [self.callback(update_id=2)]
        self.assertEqual(self.sender.poll_feedback(now=NOW)['rejected'], 1)
        self.assertEqual(len(self.journal.replay('cycle-1')['feedback']), 1)
        self.assertEqual(self.journal.examples(), [])
        reopened = Journal(self.root / 'state')
        try:
            self.assertEqual(reopened.db.execute('SELECT cursor FROM observer_delivery_control').fetchone()[0], 3)
        finally:
            reopened.close()

    def test_wrong_user_chat_message_nonce_bot_expired_and_old_epoch_are_rejected(self):
        self.sender.arm_after_reconciliation(EPOCH1)
        self.sender.deliver('cycle-1', now=NOW)
        forged = []
        for field, value in [('id', 74), ('is_bot', True)]:
            item = self.callback(update_id=len(forged) + 1)
            item['callback_query']['from'][field] = value
            forged.append(item)
        item = self.callback(update_id=3)
        item['callback_query']['message']['chat']['id'] = 43
        forged.append(item)
        item = self.callback(update_id=4)
        item['callback_query']['message']['message_id'] = 12
        forged.append(item)
        forged.append(self.callback(update_id=5, data='lo:' + 'x' * 24 + ':00'))
        self.transport.updates = forged
        self.assertEqual(self.sender.poll_feedback(now=NOW)['rejected'], 5)
        self.transport.updates = [self.callback(update_id=6)]
        self.assertEqual(self.sender.poll_feedback(now=NOW + dt.timedelta(days=1))['rejected'], 1)
        newer = self.new_sender()
        newer.arm_after_reconciliation(EPOCH2)
        self.transport.updates = [self.callback(update_id=7)]
        self.assertEqual(newer.poll_feedback(now=NOW)['rejected'], 1)
        self.assertEqual(self.journal.replay('cycle-1')['feedback'], [])

    def test_old_backup_cannot_rearm_on_open(self):
        backup = self.root / 'state' / 'before-send.sqlite3'
        self.journal.backup(backup)
        self.sender.arm_after_reconciliation(EPOCH1)
        self.sender.deliver('cycle-1', now=NOW)
        restored = self.root / 'restored'
        restored.mkdir(mode=0o700)
        import shutil
        shutil.copyfile(backup, restored / 'observer.sqlite3')
        (restored / 'observer.sqlite3').chmod(0o600)
        journal = Journal(restored)
        try:
            sender = self.new_sender(journal)
            with self.assertRaisesRegex(ObserverError, 'delivery_not_armed'):
                sender.deliver('cycle-1', now=NOW)
        finally:
            journal.close()
        self.assertEqual(len(self.transport.calls), 1)

    def test_real_transport_uses_fixed_host_and_disables_redirect_proxy(self):
        token = '12345:' + 'x' * 30
        path = self.root / 'token'
        path.write_text(token, encoding='utf-8')
        with patch.dict(os.environ, {'HTTPS_PROXY': 'https://proxy.example.invalid'}):
            transport = TelegramTransport(str(path))
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
                             for h in transport.opener.handlers))
        redirect = next(h for h in transport.opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        self.assertIsNone(redirect.redirect_request(None, None, 302, '', None, 'https://other.example.invalid'))
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b'{"ok":true,"result":[]}'
        with patch.object(transport.opener, 'open', return_value=Response()) as opened:
            self.assertEqual(transport.request('getUpdates', {'offset': 0}), [])
        self.assertEqual(opened.call_args.args[0].full_url, 'https://api.telegram.org/bot' + token + '/getUpdates')
        with self.assertRaises(ObserverError):
            transport.request('runCommand', {})


if __name__ == '__main__':
    unittest.main()

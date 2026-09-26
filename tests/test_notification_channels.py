"""Regression: the notification process has the channels its database already books sends against.

Ledger notifications. The state model was written for many channels long before the code allowed any:
`circuit_state(db, channel)` is per channel, `notification_reservations` records `channel` and
`destination`, `NotificationPolicy(channel=…)` is a constructor argument. `api.py` honoured none of
that — it picked Telegram **or** the `LO_NOTIFY_URL` webhook and refused the pair with
`Configure exactly one notification channel`. So one client served one policy while the schema kept
labels nobody could fill, which is the cheap direction to be wrong in and the reason the first half of
this item is small: a registry that maps a routed channel to a constructed client, and **two** adapters
behind it (the existing Telegram send and the existing generic webhook). ntfy/Slack/Matrix/PagerDuty
stay in the port plan (`event vocabulary`), not here.

Four properties are pinned, because each is one a later "just add a channel" change breaks silently:

* a channel's flood breaker is its own — one latched open must not silence another (task 4);
* routing prefers channels in the operator's declared order and moves on only when a channel *refuses
  to admit* the delivery; a provider that refused a message is charged for the attempt it made;
* the configuration is one mounted document and no new `*_TOKEN` environment value exists anywhere, so
  `scripts/check_foundation.py`'s credential rule keeps meaning what it means;
* the approval callback token reaches the channel in a payload *copy*, so the durable outbox row keeps
  holding no secret — which is also what makes a restored database unable to hand back a live code.

`build_channels` is called with real config files in a scratch directory; the network clients are
constructed and never contacted, and every send below goes to an in-process fake.
"""
import asyncio
import datetime as dt
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.api import app_factory
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import ChannelConfigError, build_channels, deliver_one
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-08T10:00:00Z')
BOT_TOKEN = '999:syntheticchannelcredential'
WEBHOOK_TOKEN = 'w' * 32
READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}


class Recorder:
    """An in-process channel: it records what it was sent and can be told to refuse."""

    def __init__(self, name, *, accepted=True):
        """Name the channel this recorder stands in for, and whether it will accept a send."""
        self.name = name
        self.accepted = accepted
        self.payloads = []
        self.headers = []

    def request(self, method, *, payload, headers):
        """Record one send and acknowledge it unless this channel was told to refuse."""
        self.payloads.append(payload)
        self.headers.append(headers)
        return 202, {'accepted': self.accepted, 'delivery_id': payload['delivery_id']}


async def _call(app, method: str, path: str, token: str, body: bytes = b'') -> tuple[int, dict]:
    """Drive the ASGI app directly: no socket, no lifespan, no Uvicorn."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)
    auth = (b'authorization', ('Bearer ' + token).encode())
    await app({'type': 'http', 'method': method, 'path': path, 'headers': [auth],
               'query_string': b''}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class ChannelDocumentTests(unittest.TestCase):
    """What one mounted document may say, and what it is refused for saying."""

    def setUp(self):
        """Write the two credential files a valid document points at, plus an empty one."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.telegram_config = self.root / 'telegram.json'
        self.telegram_config.write_text(json.dumps({'token': BOT_TOKEN, 'chat_id': '456'}))
        # Written as bytes on purpose: one LF, the way `printf` makes a mounted secret. A CRLF file is
        # its own refusal case below, and it is the failure an editor on Windows actually produces.
        self.token_file = self.root / 'oncall-token'
        self.token_file.write_bytes((WEBHOOK_TOKEN + '\n').encode())
        self.crlf = self.root / 'crlf-token'
        self.crlf.write_bytes((WEBHOOK_TOKEN + '\r\n').encode())
        self.empty = self.root / 'empty-token'
        self.empty.write_bytes(b'')
        self.oversized = self.root / 'big-token'
        self.oversized.write_text('x' * 8000)
        # A JSON document where Telegram's {token, chat_id} object belongs: unusable, and it must not be
        # reported as a credential problem, because it is not one.
        self.bad_config = self.root / 'telegram.bad'
        self.bad_config.write_text('[1, 2]')

    def entries(self, *extra):
        """Return the two shipped channel types, plus whatever else the test asks for."""
        return [{'channel': 'primary', 'type': 'telegram', 'config': str(self.telegram_config)},
                {'channel': 'oncall', 'type': 'webhook', 'url': 'https://hook.example/receive',
                 'token_file': str(self.token_file)}, *extra]

    def built(self, document, **kwargs):
        """Build a document under the live mode, returning ``(clients, policies)``."""
        return build_channels(document, mode=kwargs.pop('mode', 'live'), **kwargs)

    def test_two_adapters_are_constructed_in_declared_order_under_named_channels(self):
        """Telegram and the generic webhook, behind one mapping keyed by the routed channel."""
        from local_observe.http import JsonClient
        from local_observe.platform.telegram import TelegramClient
        clients, policies = self.built(self.entries())
        self.assertEqual(list(clients), ['primary', 'oncall'], 'the document order is the preference order')
        self.assertIsInstance(clients['primary'], TelegramClient)
        self.assertIsInstance(clients['oncall'], JsonClient)
        self.assertEqual([policies[name].channel for name in clients], ['primary', 'oncall'],
                         'a channel always runs under its own budget')
        self.assertEqual({policies[name].delivery_mode for name in clients}, {'live'})

    def test_each_channel_carries_its_own_budget_and_the_service_mode_alone(self):
        """`max_attempts`/`window_seconds` are per channel; `delivery_mode` is not a channel's to pick."""
        clients, policies = self.built(self.entries(
            {'channel': 'quiet', 'type': 'webhook', 'url': 'https://hook.example/quiet',
             'token_file': str(self.token_file),
             'policy': {'max_attempts': 2, 'window_seconds': 90, 'synthetic_sources': ['nightly-job']}}))
        self.assertEqual(list(clients)[-1], 'quiet')
        self.assertEqual((policies['quiet'].max_attempts, policies['quiet'].window_seconds), (2, 90))
        self.assertEqual(list(policies['quiet'].synthetic_sources), ['nightly-job'],
                         'a JSON list arrives as a sequence; `synthetic()` only ever asks `in`')
        self.assertEqual(policies['primary'].max_attempts, 10, 'an untuned channel keeps the defaults')
        with self.assertRaises(ChannelConfigError) as caught:
            self.built([{'channel': 'primary', 'type': 'webhook', 'url': 'https://hook.example/x',
                         'token_file': str(self.token_file), 'policy': {'delivery_mode': 'off'}}])
        self.assertIn('delivery mode differing from the service', str(caught.exception))
        with self.assertRaises(ChannelConfigError):
            self.built([{'channel': 'primary', 'type': 'webhook', 'url': 'https://hook.example/x',
                         'token_file': str(self.token_file), 'policy': {'channel': 'somebody-else'}}])

    def test_malformed_documents_are_refused_without_repeating_what_was_wrong(self):
        """Every malformed shape is a refusal, and no refusal echoes a credential or an endpoint path."""
        cases = {
            'not a list': {'channel': 'primary', 'type': 'webhook'},
            'empty list': [],
            'unknown key': {'channel': 'primary', 'type': 'webhook', 'url': 'https://hook.example/x',
                            'token_file': str(self.token_file), 'webook': True},
            'missing type': {'channel': 'primary', 'url': 'https://hook.example/x'},
            'unsupported type': {'channel': 'primary', 'type': 'matrix', 'url': 'https://hook.example/x'},
            'unbounded label': {'channel': 'has spaces', 'type': 'webhook', 'url': 'https://hook.example/x',
                                'token_file': str(self.token_file)},
            'reserved sink name': {'channel': 'recording-sink', 'type': 'webhook',
                                   'url': 'https://hook.example/x', 'token_file': str(self.token_file)},
            'configured twice': self.entries()[:1] + self.entries()[:1],
            'http url without the opt-in': {'channel': 'primary', 'type': 'webhook',
                                            'url': 'http://hook.example/x',
                                            'token_file': str(self.token_file)},
            'webhook naming a telegram file': {'channel': 'primary', 'type': 'webhook',
                                               'url': 'https://hook.example/x',
                                               'config': str(self.telegram_config)},
            'telegram naming a url': {'channel': 'primary', 'type': 'telegram',
                                      'config': str(self.telegram_config), 'url': 'https://hook.example/x'},
            'no credential file': {'channel': 'primary', 'type': 'webhook', 'url': 'https://hook.example/x'},
            'credential file missing': {'channel': 'primary', 'type': 'webhook',
                                        'url': 'https://hook.example/x',
                                        'token_file': str(self.root / 'gone')},
            'credential file empty': {'channel': 'primary', 'type': 'webhook',
                                      'url': 'https://hook.example/x', 'token_file': str(self.empty)},
            # The same rule `local_observe/credentials.py` applies to every mounted credential: a value
            # with an ASCII control character in it is a damaged file, refused at the read.
            'credential file written with CRLF': {'channel': 'primary', 'type': 'webhook',
                                                  'url': 'https://hook.example/x',
                                                  'token_file': str(self.crlf)},
            'credential file oversized': {'channel': 'primary', 'type': 'webhook',
                                          'url': 'https://hook.example/x',
                                          'token_file': str(self.oversized)},
            'telegram config unreadable': {'channel': 'primary', 'type': 'telegram',
                                           'config': str(self.root / 'gone')},
            'telegram config wrong shape': {'channel': 'primary', 'type': 'telegram',
                                            'config': str(self.bad_config)},
            'allow_http not boolean': {'channel': 'primary', 'type': 'webhook',
                                       'url': 'http://hook.example/x', 'token_file': str(self.token_file),
                                       'allow_http': 'yes'},
        }
        for name, document in cases.items():
            with self.subTest(case=name):
                listed = document if name in ('not a list', 'empty list', 'configured twice') else [document]
                with self.assertRaises(ChannelConfigError) as caught:
                    self.built(listed)
                for forbidden in (BOT_TOKEN, WEBHOOK_TOKEN, 'hook.example'):
                    self.assertNotIn(forbidden, str(caught.exception),
                                     '%s refused by repeating %r' % (name, forbidden))

    def test_an_isolated_network_http_channel_needs_the_explicit_opt_in(self):
        """`allow_http: true` is carried to `JsonClient`, which is what decides whether to accept it."""
        clients, _ = self.built([{'channel': 'lab', 'type': 'webhook', 'url': 'http://127.0.0.1:9/notify',
                                 'token_file': str(self.token_file), 'allow_http': True}])
        self.assertEqual(list(clients), ['lab'])
        self.assertEqual(clients['lab'].token, WEBHOOK_TOKEN, 'the credential came from the file')

    def test_the_credential_is_read_from_a_file_and_a_new_env_value_is_never_consulted(self):
        """No variable in this feature holds a secret, so `check_credential_files` has nothing new to miss."""
        environment = {'LO_NOTIFY_CHANNELS_TOKEN': 'never-export-this'}
        with patch.dict(os.environ, environment, clear=True):
            clients, _ = self.built([{'channel': 'oncall', 'type': 'webhook',
                                      'url': 'https://hook.example/receive',
                                      'token_file': str(self.token_file)}])
        self.assertEqual(clients['oncall'].token, WEBHOOK_TOKEN)

    def test_a_recording_boot_never_opens_a_channels_document(self):
        """The mode gate is the credential gate: only `live` reads channel configuration."""
        path = self.root / 'never-read.json'
        path.write_text('[not json')
        stores = []

        def opened(store_path, notification_policy, *, verification_policy):
            store = Store(store_path, notification_policy, verification_policy=verification_policy)
            stores.append(store)
            return store

        environment = {'LO_STATE_PATH': str(self.root / 'recording.db'),
                       'LO_INDEX_PATH': str(self.root / 'index.db'),
                       'LO_ACTION_POLICY': str(self.root / 'actions.json'),
                       'LO_PLATFORM_CREDENTIALS': str(self.root / 'credentials.json'),
                       'LO_NOTIFICATION_MODE': 'recording', 'LO_NOTIFY_CHANNELS': str(path)}
        (self.root / 'actions.json').write_text('{}')
        (self.root / 'credentials.json').write_text(json.dumps([READER]))
        with patch.dict(os.environ, environment, clear=True), \
                patch('local_observe.platform.api.action_policy', return_value=lambda request: None), \
                patch('local_observe.platform.api.Store', side_effect=opened):
            app_factory()
        self.assertEqual(list(stores[0].channel_policies), ['primary'],
                         'recording routes on one policy and the broken document was never parsed')


class AppFactoryChannelTests(unittest.TestCase):
    """The boot path: a document adds channels beside the legacy environment pair, twice is a refusal."""

    def setUp(self):
        """Clear the environment and write the two files every boot needs."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'credentials.json').write_text(json.dumps([READER]))
        (self.root / 'actions.json').write_text('{}')
        self.token_file = self.root / 'oncall-token'
        self.token_file.write_bytes(WEBHOOK_TOKEN.encode())
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def environment(self, **extra):
        """One live boot environment: role file, action policy file, plus the test's own keys."""
        base = {'LO_STATE_PATH': str(self.root / 'state.db'), 'LO_INDEX_PATH': str(self.root / 'index.db'),
                'LO_ACTION_POLICY': str(self.root / 'actions.json'),
                'LO_PLATFORM_CREDENTIALS': str(self.root / 'credentials.json'),
                'LO_NOTIFICATION_MODE': 'live'}
        return dict(base, **extra)

    def channels_file(self, document):
        """Write the channels document and return its path, as an operator mounts it."""
        path = self.root / 'channels.json'
        path.write_text(json.dumps(document))
        return str(path)

    def booted(self, environment):
        """Boot `app_factory` with a patched action allowlist; return the store it opened and the app."""
        stores = []

        def opened(path, notification_policy, *, verification_policy):
            store = Store(path, notification_policy, verification_policy=verification_policy)
            stores.append(store)
            return store

        with patch.dict(os.environ, environment), \
                patch('local_observe.platform.api.action_policy', return_value=lambda request: None), \
                patch('local_observe.platform.api.Store', side_effect=opened):
            app = app_factory()
        self.assertEqual(len(stores), 1)
        return stores[0], app

    def test_a_document_adds_a_second_channel_beside_the_legacy_webhook(self):
        """`LO_NOTIFY_URL` alone still boots one channel; a document names the other, in the schema."""
        document = [{'channel': 'oncall', 'type': 'webhook', 'url': 'https://hook.example/receive',
                     'token_file': str(self.token_file), 'policy': {'max_attempts': 3}}]
        environment = dict(self.environment(), LO_NOTIFY_URL='https://hook.example/primary',
                           LO_NOTIFY_TOKEN=WEBHOOK_TOKEN, LO_NOTIFY_CHANNELS=self.channels_file(document))
        store, app = self.booted(environment)
        self.assertEqual(sorted(store.channel_policies), ['oncall', 'primary'])
        self.assertEqual(store.channel_policies['oncall'].max_attempts, 3)
        status, runtime = asyncio.run(_call(app, 'GET', '/v1/runtime', READER['token']))
        self.assertEqual(status, 200)
        self.assertTrue(runtime['sender_configured'], 'two senders configured, one reported boolean')

    def test_one_channel_name_reachable_two_ways_is_a_boot_failure(self):
        """The legacy pair and the document may not both claim `primary`: no precedence rule is invented."""
        clash = [{'channel': 'primary', 'type': 'webhook', 'url': 'https://hook.example/other',
                  'token_file': str(self.token_file)}]
        environment = dict(self.environment(), LO_NOTIFY_URL='https://hook.example/primary',
                           LO_NOTIFY_TOKEN=WEBHOOK_TOKEN, LO_NOTIFY_CHANNELS=self.channels_file(clash))
        with patch.dict(os.environ, environment), \
                patch('local_observe.platform.api.action_policy', return_value=lambda request: None):
            with self.assertRaisesRegex(ValueError, 'configured twice'):
                app_factory()

    def test_the_legacy_pair_still_refuses_two_channels_of_its_own(self):
        """The refusal this entry point raised before the registry exists is unchanged by it."""
        environment = dict(self.environment(), LO_NOTIFY_URL='https://hook.example/primary',
                           LO_NOTIFY_TOKEN=WEBHOOK_TOKEN,
                           LO_TELEGRAM_CONFIG=str(self.root / 'telegram.json'))
        with patch.dict(os.environ, environment), \
                patch('local_observe.platform.api.action_policy', return_value=lambda request: None):
            with self.assertRaisesRegex(ValueError, 'exactly one notification channel'):
                app_factory()


class RoutingTests(unittest.TestCase):
    """Two channels, one queue: budget is per channel, and a refusal is not a substitution."""

    def setUp(self):
        """Open a scratch directory; each test names its own database."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def channels(self):
        """One policy per channel, both live, with the first channel's budget deliberately tight."""
        return (NotificationPolicy(channel='primary', delivery_mode='live', max_attempts=2,
                                  window_seconds=600),
                NotificationPolicy(channel='oncall', delivery_mode='live', max_attempts=5,
                                  window_seconds=600))

    def store(self, name: str, primary: NotificationPolicy, extra: NotificationPolicy) -> Store:
        """Open a store whose primary channel is `primary` and whose second channel is `extra`."""
        store = Store(self.root / (name + '.db'), primary)
        store.add_channels({extra.channel: extra})
        return store

    def fire(self, store: Store, source: str, *, offset: int = 0, restricted: bool = False) -> str:
        """Intake one firing event and return the delivery id it queued."""
        now = NOW + dt.timedelta(seconds=offset)
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        item = event(source, None, 'availability', 'availability', 'firing', window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')
        if restricted:
            item['data_class'] = 'restricted'
        before = {row['id'] for row in store.records('outbox')}
        store.intake(item, Actor(source, 'producer'), now=now)
        queued = [row['id'] for row in store.records('outbox') if row['id'] not in before]
        self.assertEqual(len(queued), 1, 'one event queues exactly one delivery')
        return queued[0]

    def booked(self, store: Store) -> dict:
        """Return ``{channel: sends booked}`` straight from the budget table."""
        with closing(sqlite3.connect(store.path)) as db:
            return dict(db.execute('SELECT channel, count(*) FROM notification_reservations'
                                   ' GROUP BY channel'))

    def test_a_channel_that_latches_stops_sending_and_the_next_channel_carries_on(self):
        """Task 4 of the brief: one circuit open, the other still sends, and neither borrows the other."""
        primary, oncall = self.channels()
        store = self.store('isolation', primary, oncall)
        first, second = Recorder('primary'), Recorder('oncall')
        providers = {'primary': first, 'oncall': second}
        reports = []
        for offset in range(5):
            self.fire(store, 'detector-%d' % offset, offset=offset)
            reports.append(deliver_one(store, providers, now=NOW + dt.timedelta(seconds=offset)))
        self.assertEqual([report['status'] for report in reports], ['sent'] * 5,
                         'a healthy second channel means the operator is still told about the incidents')
        self.assertEqual(len(first.payloads), 2, 'the latched channel got no send past its budget')
        self.assertEqual(len(second.payloads), 3, 'the healthy channel kept its own budget')
        self.assertEqual(self.booked(store), {'primary': 2, 'oncall': 3},
                         'each channel is charged for the sends it actually made')
        status = store.notification_safety_status()
        self.assertTrue(status['circuit_open'], 'the primary view still reports the primary breaker')
        self.assertEqual({name: row['circuit_open'] for name, row in status['channels'].items()},
                         {'primary': True, 'oncall': False}, 'a breaker does not leak across channels')

    def test_a_refused_send_is_charged_to_the_channel_that_carried_it(self):
        """Failover is a channel refusing to *admit*, not a provider refusing a message.

        A send the provider declined is an attempt on the channel that made it, and control state's rule stands:
        a failed request consumes a slot. So a declining provider walks its own channel to exhaustion,
        and only then does the next channel carry the row.
        """
        primary, oncall = self.channels()
        store = self.store('charged', primary, oncall)
        first, second = Recorder('primary', accepted=False), Recorder('oncall')
        providers = {'primary': first, 'oncall': second}
        self.fire(store, 'detector-declines')
        deliver_one(store, providers, now=NOW)
        deliver_one(store, providers, now=NOW + dt.timedelta(seconds=5))
        self.assertEqual(len(first.payloads), 2, 'the first channel was asked twice and declined twice')
        self.assertEqual(second.payloads, [], 'the second channel does not get asked while the first has budget')
        deliver_one(store, providers, now=NOW + dt.timedelta(seconds=10))
        self.assertEqual(len(second.payloads), 1, 'the first channel is out of budget, so the row moves')
        self.assertEqual(self.booked(store), {'primary': 2, 'oncall': 1})

    def test_a_restricted_event_is_still_refused_however_many_channels_exist(self):
        """Design item 4: more channels do not widen what may leave. No channel accepts a restricted event."""
        primary, oncall = self.channels()
        store = self.store('restricted', primary, oncall)
        providers = {'primary': Recorder('primary'), 'oncall': Recorder('oncall')}
        self.fire(store, 'detector-restricted', restricted=True)
        report = deliver_one(store, providers, now=NOW)
        self.assertEqual((report['status'], report['reason']),
                         ('suppressed', 'restricted-channel-policy-required'))
        self.assertEqual(providers['primary'].payloads, [])
        self.assertEqual(providers['oncall'].payloads, [])

    def test_the_channel_a_send_used_is_durable_and_visible_afterwards(self):
        """`delivery_route` names the channel that carried, or was charged for, the delivery."""
        from local_observe.platform.presentation import delivery_route
        primary, oncall = self.channels()
        store = self.store('route', primary, oncall)
        providers = {'primary': Recorder('primary'), 'oncall': Recorder('oncall')}
        for offset in range(3):
            self.fire(store, 'detector-%d' % offset, offset=offset)
            deliver_one(store, providers, now=NOW + dt.timedelta(seconds=offset))
        with closing(sqlite3.connect(store.path)) as db:
            # `records` hands out newest-first, and the deliveries are numbered oldest-first.
            ordered = sorted((row['sequence'], row['id']) for row in store.records('outbox'))
            routes = [delivery_route(db, delivery_id) for _, delivery_id in ordered]
        self.assertEqual([route['channel'] for route in routes], ['primary', 'primary', 'oncall'])

    def test_a_reset_clears_every_channel_whose_backlog_it_discarded(self):
        """One human decision about the platform, audited once per breaker it cleared."""
        primary, oncall = self.channels()
        store = self.store('reset', primary, oncall)
        self.fire(store, 'detector-reset')
        store.reset_notification_guard(Actor('operator', 'human'), now=NOW + dt.timedelta(minutes=1))
        cleared = sorted((row['operation'], row['subject']) for row in store.records('audit')
                         if row['operation'] == 'notification.circuit_reset')
        self.assertEqual(cleared, [('notification.circuit_reset', 'oncall'),
                                   ('notification.circuit_reset', 'primary')],
                         'the log says which breakers one click cleared')
        status = store.notification_safety_status()
        self.assertFalse(status['circuit_open'])
        self.assertEqual({name: row['circuit_open'] for name, row in status['channels'].items()},
                         {'primary': False, 'oncall': False})

    def test_an_unregistered_channel_or_a_second_budget_for_one_is_refused(self):
        """Configuration cannot drift into two answers about the same channel."""
        primary, oncall = self.channels()
        store = Store(self.root / 'refusal.db', primary)
        store.add_channels({'oncall': oncall})
        with self.assertRaisesRegex(StateError, 'two budgets'):
            store.add_channels({'oncall': NotificationPolicy(channel='oncall', delivery_mode='live',
                                                            max_attempts=9)})
        with self.assertRaisesRegex(StateError, 'wrong channel name'):
            store.add_channels({'mislabelled': oncall})
        with self.assertRaisesRegex(StateError, 'wrong channel name'):
            Store(self.root / 'refusal-2.db', primary, channel_policies={'mislabelled': oncall})
        self.assertEqual(list(store.channel_policies), ['primary', 'oncall'], 'the refusals changed nothing')
        self.assertEqual(store.notification_safety_status()['channel'], 'primary',
                         'the primary keys still describe the primary channel')

    def test_the_callback_token_reaches_the_channel_and_never_the_durable_row(self):
        """The token is handed over in a payload copy; the outbox keeps the payload it was written with."""
        store = Store(self.root / 'token.db', NotificationPolicy(delivery_mode='live'))
        provider = Recorder('primary')
        delivery = self.fire(store, 'detector-token')
        deliver_one(store, provider, now=NOW)
        sent = provider.payloads[0]
        self.assertEqual(set(sent), {'schema_version', 'delivery_id', 'incident_id', 'transition',
                                    'event_id', 'event', 'callback'})
        self.assertEqual(set(sent['callback']), {'token', 'expires_at', 'route'})
        self.assertEqual(sent['callback']['route'], '/v1/callbacks/primary')
        self.assertEqual(timestamp(sent['callback']['expires_at']) - NOW, dt.timedelta(hours=1),
                         'the default lifetime is the bounded one the README names')
        self.assertEqual(provider.headers[0], {'Idempotency-Key': delivery},
                         'the send carries the same key it always carried')
        with closing(sqlite3.connect(store.path)) as db:
            payload, token_hash = db.execute('SELECT payload, callback_token_hash FROM outbox').fetchone()
        self.assertNotIn(sent['callback']['token'], payload, 'the secret itself is never stored')
        self.assertEqual(len(token_hash), 64, 'its digest is, and that is what a replay is checked against')

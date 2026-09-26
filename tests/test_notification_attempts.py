"""Regression: a failed delivery says *which kind* of failure it was, and says nothing else.

Ledger notifications. `Store.finish_notification` recorded a boolean, so after the fifth retry the row for
"the provider was down all evening" was indistinguishable from the row for "the provider rejected
this message" — the `If disabled` promise on the notifications row ("delivery absence is visible")
held for a refusal and for a dead delivery, but not for a channel nobody could reach. Schema v3 adds
one bounded word per attempt, and this file pins the three things that make the word worth having:

* the classes are distinguished (`transport` for a channel that could not be reached, `rejected` for
  one that answered and did not accept, `policy` for a send the platform refused to attempt);
* the word is the *whole* diagnosis — no URL, no token, no response body, no exception text reaches
  the attempt row, the audit log or a log line. `telegram.py` puts the bot credential in the URL it
  requests, so a cause field that carried provider detail would be a credential leak with a docstring
  about redaction next to it; that is why `tests/test_regression_redaction.py`'s discipline is re-run
  here against a forced transport failure rather than trusted;
* an old database (schema v2, which recorded a boolean and no channel) opens under this build with
  defaults that describe what it genuinely does not know, and nothing in it is rewritten.
"""
import datetime as dt
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from local_observe.http import TransportError
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import state
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import deliver_one
from local_observe.platform.state import ATTEMPT_CAUSES, Actor, StateError, Store

NOW = timestamp('2026-09-08T09:00:00Z')
BOT_TOKEN = '1234:syntheticbotcredentialmustneverappear'
CHAT_ID = '456'
SECRET_BODY = 'provider-response-body-must-not-be-stored'


class Receiver:
    """A channel that answers with whatever the test needs, including nothing at all."""

    def __init__(self, *, accepted=True, status=202, raises=None, receipt=None):
        self.calls = []
        self._accepted = accepted
        self._status = status
        self._raises = raises
        self._receipt = receipt

    def request(self, method, *, payload, headers):
        """Record the send, then fail, refuse or acknowledge as configured."""
        self.calls.append(payload)
        if self._raises is not None:
            raise self._raises
        if self._receipt is not None:
            return self._status, self._receipt
        return self._status, {'accepted': self._accepted, 'delivery_id': payload['delivery_id']}


class SilentTelegramOpener:
    """Stand-in for the HTTPS opener that fails the way a real outage fails: with the URL in hand.

    `urllib` puts the request URL — which for Telegram *is* the bot credential — into the message of
    every error it raises. The adapter's job is to lose that message, and this class is written so a
    regression that started propagating it would fail these tests loudly.
    """

    def __init__(self, error):
        self.error = error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        raise self.error


class AttemptCauseTests(unittest.TestCase):
    """What one finished attempt knows about itself."""

    def setUp(self):
        """Open a scratch database on a live, single-channel policy that will not latch mid-test."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = NotificationPolicy(delivery_mode='live', max_attempts=20,
                                         max_event_age_seconds=86400)
        self.store = Store(self.root / 'state.db', self.policy)

    def fire(self, source: str, *, restricted: bool = False, offset: int = 0) -> str:
        """Intake one firing event and return the delivery it queued."""
        now = NOW + dt.timedelta(seconds=offset)
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        item = event(source, None, 'availability', 'availability', 'firing', window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')
        if restricted:
            item['data_class'] = 'restricted'
        self.store.intake(item, Actor(source, 'producer'), now=now)
        return self.store.records('outbox')[0]['id']

    def cause_of(self, delivery_id: str) -> tuple[str, str]:
        """Return the `(result, cause)` the newest attempt row for `delivery_id` holds."""
        rows = [row for row in self.store.records('notification_attempts') if row['outbox_id'] == delivery_id]
        self.assertEqual(len(rows), 1, 'one claim writes one attempt row')
        return rows[0]['result'], rows[0]['cause']

    def test_an_unreachable_channel_is_recorded_as_transport(self):
        """A provider that cannot be reached is a different fact from one that refused."""
        delivery = self.fire('detector-down')
        report = deliver_one(self.store, Receiver(raises=TransportError('Endpoint unavailable')),
                             now=NOW)
        self.assertEqual(report['status'], 'pending')
        self.assertEqual(self.cause_of(delivery), ('failed', 'transport'))

    def test_an_answer_that_is_not_an_acknowledgement_is_recorded_as_rejected(self):
        """2xx with a receipt that does not match is a refusal, and never a transport failure."""
        delivery = self.fire('detector-refused')
        deliver_one(self.store, Receiver(accepted=False), now=NOW)
        self.assertEqual(self.cause_of(delivery), ('failed', 'rejected'))
        other = self.fire('detector-echo', offset=1)
        deliver_one(self.store, Receiver(receipt={'accepted': True, 'delivery_id': 'not-the-same-id'}),
                    now=NOW + dt.timedelta(seconds=1))
        self.assertEqual(self.cause_of(other), ('failed', 'rejected'))

    def test_a_platform_refusal_is_recorded_as_policy_and_never_reaches_the_channel(self):
        """A restricted event never becomes an attempt at all; a route with no client becomes a refusal."""
        provider = Receiver()
        delivery = self.fire('detector-restricted', restricted=True)
        self.assertEqual(deliver_one(self.store, provider, now=NOW)['status'], 'suppressed')
        # A restricted event is refused at the budget gate, so no attempt row exists at all: the
        # suppression row is the record, and the provider was never contacted.
        self.assertEqual([row for row in self.store.records('notification_attempts')
                          if row['outbox_id'] == delivery], [])
        self.assertEqual(provider.calls, [])
        # Same word, other branch: a row routed to a channel this process has no client for. The
        # mapping form is the multi-channel one, and `oncall` is not a channel this store knows.
        queued = self.fire('detector-no-client', offset=2)
        report = deliver_one(self.store, {'oncall': provider}, now=NOW + dt.timedelta(seconds=2))
        self.assertEqual(report['status'], 'pending')
        self.assertEqual(provider.calls, [], 'a channel the row was not routed to must not be used')
        self.assertEqual(self.cause_of(queued), ('failed', 'policy'))

    def test_an_accepted_delivery_is_recorded_as_accepted(self):
        """Success has one cause word too, so `cause` never means "whatever was left over"."""
        delivery = self.fire('detector-ok')
        deliver_one(self.store, Receiver(), now=NOW)
        self.assertEqual(self.cause_of(delivery), ('accepted', 'accepted'))

    def test_causes_outside_the_bounded_vocabulary_are_refused(self):
        """No free text, no provider detail: a word outside the tuple is a programming error.

        `None` is the one value that is not a word and is not refused: it is what a caller that did not
        learn anything passes, and it lands on `rejected` — the same claim the boolean alone used to
        make, so a pre-v3 caller keeps its exact behaviour instead of being punished for its age.
        """
        self.fire('detector-bounds')
        claim = self.store.claim_notification(now=NOW)
        for bad in ('provider said 503', 'TRANSPORT', 'pending', 7, 'oops', ['transport']):
            with self.subTest(cause=bad), self.assertRaisesRegex(StateError, 'attempt cause'):
                self.store.finish_notification(claim['id'], claim['claim_token'], False, now=NOW, cause=bad)
        # A cause claimed for a delivery that was accepted contradicts itself and is refused too.
        with self.assertRaisesRegex(StateError, 'attempt cause'):
            self.store.finish_notification(claim['id'], claim['claim_token'], True, now=NOW, cause='transport')
        # An older caller with no cause at all: still recorded, still a refusal, and the field says so.
        self.assertEqual(self.store.finish_notification(claim['id'], claim['claim_token'], False, now=NOW),
                         'pending')
        self.assertEqual(self.store.records('notification_attempts')[0]['cause'], 'rejected')
        reopened = self.store.claim_notification(now=NOW + dt.timedelta(minutes=10))
        self.assertEqual(self.store.finish_notification(reopened['id'], reopened['claim_token'], True,
                                                       now=NOW + dt.timedelta(minutes=10)), 'sent')
        self.assertEqual(self.store.records('notification_attempts')[0]['cause'], 'accepted')

    def test_the_view_shows_the_cause_of_the_last_attempt(self):
        """`presentation.delivery_route` says which failure the operator is looking at."""
        from local_observe.platform.presentation import delivery_route
        delivery = self.fire('detector-view')
        deliver_one(self.store, Receiver(raises=TransportError('unreachable')), now=NOW)
        with closing(sqlite3.connect(self.store.path)) as db:
            route = delivery_route(db, delivery)
        self.assertEqual((route['channel'], route['destination']), ('primary', 'human'))
        self.assertEqual((route['attempt'], route['cause']), ('failed', 'transport'))
        self.assertEqual(Store(self.root / 'state.db').notification_safety_status()['channel'], 'primary')
    def test_an_attempt_row_never_holds_provider_detail(self):
        """Whatever a caller passes as an exception, the stored row holds one word and two times."""
        delivery = self.fire('detector-nosecrets')
        deliver_one(self.store, Receiver(raises=TransportError(BOT_TOKEN + ' https://api.telegram.org')),
                    now=NOW)
        row = [item for item in self.store.records('notification_attempts') if item['outbox_id'] == delivery][0]
        joined = json.dumps(row)
        self.assertEqual(row['cause'], 'transport')
        for forbidden in (BOT_TOKEN, 'telegram.org', 'https://'):
            self.assertNotIn(forbidden, joined)


class TelegramRedactionTests(unittest.TestCase):
    """The cause field must not become the place the Telegram credential leaks."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'telegram.db',
                           NotificationPolicy(delivery_mode='live', max_attempts=20,
                                              max_event_age_seconds=86400))

    def fire(self, source: str) -> str:
        """Intake one firing event and return the delivery id queued for it."""
        window = {'start': utc_text(NOW - dt.timedelta(seconds=1)), 'end': utc_text(NOW)}
        self.store.intake(event(source, None, 'availability', 'availability', 'firing', window,
                               {'sample_id': 'fixture'}, query_type='gatus-result'),
                          Actor(source, 'producer'), now=NOW)
        return self.store.records('outbox')[0]['id']

    def test_a_forced_transport_failure_leaves_no_credential_anywhere(self):
        """Grep every durable row and every log line the failure wrote: the credential is not in them.

        The store is a real one and the client is the real adapter, so this is the same path the
        service runs — the failure is injected at the opener, which is where an outage happens.
        """
        from local_observe.platform.telegram import TelegramClient
        delivery = self.fire('detector-telegram-outage')
        opener = SilentTelegramOpener(OSError(BOT_TOKEN + ' refused connection'))
        client = TelegramClient(BOT_TOKEN, CHAT_ID, opener=opener,
                                display_config={'channel_name': 'primary'})
        with self.assertLogs('local_observe.platform', 'DEBUG') as captured:
            report = deliver_one(self.store, client, now=NOW)
        self.assertEqual(report['status'], 'pending')
        self.assertEqual(len(opener.requests), 1, 'the adapter really tried to send')
        durable = json.dumps([self.store.status(), self.store.records('notification_attempts'),
                             self.store.records('outbox'), self.store.records('audit'),
                             self.store.records('incidents'), self.store.records('events')])
        logged = '\n'.join([record.getMessage() for record in captured.records]
                           + [json.dumps({key: str(value) for key, value in record.__dict__.items()
                                          if key not in ('args', 'exc_info', 'exc_text', 'stack_info')})
                              for record in captured.records])
        joined = durable + logged
        for forbidden in (BOT_TOKEN, 'api.telegram.org', 'refused connection', 'syntheticbotcredential',
                          'sendMessage'):
            self.assertNotIn(forbidden, joined, forbidden + ' reached a durable row or a log line')
        attempt = [row for row in self.store.records('notification_attempts') if row['outbox_id'] == delivery][0]
        self.assertEqual(attempt['cause'], 'transport', 'the diagnosis survives; the detail does not')


class SchemaV3OpenTests(unittest.TestCase):
    """A file written by the previous build opens under this one, and says what it does not know."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy = NotificationPolicy(delivery_mode='live', max_attempts=20,
                                         max_event_age_seconds=86400)

    @staticmethod
    def v2_build():
        """Act as the release whose schema is 2: the same two scripts, no v3 columns anywhere.

        The file is *created* by that build rather than carved out of a v3 one with DROP COLUMN, which
        is how state migrations makes an old file elsewhere and why it needs no SQLite feature this build might
        not have. Dropping columns from a current file would also leave rows that never existed at v2.
        """
        return (mock.patch.dict(state.MIGRATIONS, {1: state.SCHEMA, 2: state.CONTROL_SCHEMA}, clear=True),
                mock.patch.object(state, 'VERSION', 2))

    def columns(self, table: str) -> list[str]:
        """Return the column names of `table` in the file, read without any platform code."""
        with closing(sqlite3.connect(self.path)) as connection:
            return [row[1] for row in connection.execute('PRAGMA table_info(%s)' % table)]

    def test_an_older_file_is_refused_then_migrated_with_defaults_that_do_not_invent_history(self):
        """v2 rows keep their meaning: the channel is the one there was, and the cause was not recorded.

        The file is created by a build whose schema is 2 and then handed over untouched. What it must
        not do is *deliver* under that build: patching `MIGRATIONS`/`VERSION` changes which file a build
        creates, not which code runs, and it is the code that writes the new columns — a delivery here
        would be this build writing v3 fields into a v2 table, which is an error rather than history.
        The v2-shaped attempt row is therefore written the way a v2 build left it: six columns, raw.
        """
        migrations, version = self.v2_build()
        with migrations, version:
            old = Store(self.root / 'v2.db')
            window = {'start': utc_text(NOW - dt.timedelta(seconds=1)), 'end': utc_text(NOW)}
            old.intake(event('detector-v2', None, 'availability', 'availability', 'firing', window,
                             {'sample_id': 'fixture'}, query_type='gatus-result'),
                       Actor('detector-v2', 'producer'), now=NOW)
            self.path = old.path
        with closing(sqlite3.connect(self.path)) as db:
            delivery = db.execute('SELECT id FROM outbox').fetchone()[0]
            db.execute('INSERT INTO notification_attempts(id,outbox_id,started_at,finished_at,result,claim_token)'
                       " VALUES (?,?,?,?,?,?)",
                       ('attempt-written-at-v2', delivery, utc_text(NOW), utc_text(NOW), 'failed', 'spent-token'))
            db.commit()
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 2)
            self.assertNotIn('cause', [row[1] for row in db.execute('PRAGMA table_info(notification_attempts)')])
        before = self.path.read_bytes()
        with self.assertRaisesRegex(StateError, r'version 2; run lo-platform migrate'):
            Store(self.path)
        self.assertEqual(self.path.read_bytes(), before, 'refusing must not mean rewriting')

        moved = Store(self.path, self.policy, migrate=True)
        self.assertEqual(moved.migrated_from, 2)
        self.assertEqual(moved.status()['schema_version'], state.VERSION)
        self.assertIn('channel', self.columns('outbox'))
        self.assertIn('callback_token_hash', self.columns('outbox'))
        self.assertIn('cause', self.columns('notification_attempts'))
        attempt = moved.records('notification_attempts')[0]
        # The honest default: the cause carried across is the claim the old boolean actually made —
        # `failed` means "not accepted", which is `rejected`, and never a word more informative than the
        # one that was recorded.
        self.assertEqual((attempt['result'], attempt['cause']), ('failed', 'rejected'))
        self.assertEqual(attempt['outbox_id'], moved.records('outbox')[0]['id'],
                         'the attempt stayed attached to its delivery across the migration')
        self.assertEqual(moved.records('outbox')[0]['channel'], '',
                         'a row this build never routed asserts no channel')
        self.assertEqual(moved.records('outbox')[0]['status'], 'pending')
        self.assertEqual(moved.notification_safety_status()['channels'],
                         {'primary': {'circuit_open': False, 'delivery_mode': 'live',
                                      'max_attempts': 20, 'window_seconds': 600}})
        # A migrated row is a live row: it claims, it routes, and it can carry an approval code.
        claim = moved.claim_notification(now=NOW + dt.timedelta(seconds=1))
        self.assertEqual((claim['channel'], claim['destination']), ('primary', 'human'))
        self.assertEqual(len(claim['callback']['token']), 43)
        self.assertNotIn('callback', moved.records('outbox')[0], 'the secret is never readable back')
        self.assertEqual(moved.records('outbox')[0]['channel'], 'primary',
                         'routing a row is what writes its channel')

    def test_the_bounded_vocabulary_is_what_the_column_offers(self):
        """The tuple, the column and the docstring name the same words."""
        self.assertEqual(ATTEMPT_CAUSES, ('pending', 'accepted', 'rejected', 'transport', 'policy'))

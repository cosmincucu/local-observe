"""Regression: five ported transports, and each one can say *which* of two failures happened.

The port keeps the provider transports and excludes ITSM by decision itop. The channels are the cheap
half of that work; the requirement that matters is the one that says a channel
"that cannot state 'delivery failed' distinctly from 'channel unavailable' cannot be ported at all".
`docs/COMPONENTS.md`'s notifications row promises *delivery absence is visible*, and a transport that
reported one generic error for "the provider refused this message" and "the provider is unreachable"
would make `notification_attempts.cause` — the column built for exactly that question — mean one thing
again. So every test below is a taxonomy test: one provider answer per case, and the assertion is on
which word the platform recorded, never merely on "it failed".

Six properties are pinned here, one per task of the brief:

* the three outcomes crosswalk onto words `state.ATTEMPT_CAUSES` already offers (`sent`→`accepted`,
  `rejected`→`rejected`, `unavailable`→`transport`), so this is a narrowing and not a second vocabulary;
* each transport classifies a 4xx, a 5xx, a refused SMTP relay and a refused recipient *differently*;
* the outbox delivery id reaches the wire under one named field per channel and does **not** change when
  `attempts` increments or a lease expires — the receiver's dedupe depends on that, and v0.1's Matrix
  channel got it wrong (a fresh uuid4 per call meant a crash published the alert twice);
* the budget and the latched flood breaker are the transport's precondition, not its concern: a latched
  breaker means no socket is opened at all, and a refusal is bounded by the attempt count
  `finish_notification`/`retry_notification` already enforce rather than by anything a channel decides;
* one bounded timeout per attempt, no redirect followed, no proxy, and no credential in a log line, an
  exception string or the durable record — proven against a fake provider that records calls;
* configuration is the same mounted document as the two existing channels, so no new `*_TOKEN`
  environment value exists and `scripts/check_foundation.py`'s `check_credential_files` still needs no
  exception (and gets none).

No test here opens a socket: every HTTP transport is handed a fake `JsonClient`-shaped seam and the
email transport a fake session factory, which is the seam v0.1 itself used (`legacy:notifiers/email.py`,
`smtp_factory`).
"""
import datetime as dt
import json
import logging
from pathlib import Path
import smtplib
import sqlite3
import ssl
import tempfile
import unittest
from contextlib import closing
from urllib.error import URLError

from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import channels
from local_observe.platform.channels import (OUTCOME_REJECTED, OUTCOME_SENT, OUTCOME_UNAVAILABLE,
                                             ChannelConfigError, EmailChannel, MatrixChannel,
                                             NtfyChannel, PagerDutyChannel, SlackChannel,
                                             build_transport, http_outcome)
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.notifications import ChannelConfigError as DocumentConfigError
from local_observe.platform.notifications import build_channels, deliver_one
from local_observe.platform.state import ATTEMPT_CAUSES, Actor, StateError, Store

NOW = timestamp('2026-09-08T10:00:00Z')
DELIVERY = '6f1c2a44-7d3b-4e5f-9a10-2b3c4d5e6f70'
INCIDENT = '11111111-2222-3333-4444-555555555555'
NTFY_TOKEN = 'ntfytokensyntheticneverlogged'
SLACK_SECRET = 'x' * 24
MATRIX_TOKEN = 'syesyntheticmatrixaccesstokenvalue'
ROUTING_KEY = 'r' * 32
MAIL_PASSWORD = 'p' * 30
URL_SECRET = 'https://user:passworD synthetic@host.example/private-path'


def outbox_payload(delivery_id: str = DELIVERY, *, transition: str = 'opened',
                   severity: str = 'warning', data_class: str = 'internal') -> dict:
    """Return one outbox payload shaped exactly as `claim_notification` hands it to the loop."""
    return {'schema_version': 1, 'delivery_id': delivery_id, 'incident_id': INCIDENT,
            'transition': transition, 'event_id': '77777777-8888-9999-0000-111111111111',
            'event': {'source': 'detector', 'severity': severity, 'kind': 'availability',
                      'data_class': data_class, 'resource_id': None, 'status': 'firing',
                      'observed_at': utc_text(NOW), 'rule_id': 'probe', 'rule_version': 1,
                      'condition': 'availability', 'evidence': [{'id': 'e1', 'kind': 'gatus-result'}],
                      'window': {'start': utc_text(NOW - dt.timedelta(seconds=1)), 'end': utc_text(NOW)}}}


class Provider:
    """A fake `JsonClient`: it records every request and answers, refuses or vanishes."""

    def __init__(self, *, status: int = 200, body=None, raises: BaseException | None = None) -> None:
        """Set the answer this provider gives, or the exception it raises instead of answering."""
        self.calls: list[tuple] = []
        self.status = status
        self.body = body
        self.raises = raises

    def request(self, method, path='', payload=None, *, headers=None, timeout=None):
        """Record one call, then behave as this provider was told to."""
        self.calls.append({'method': method, 'path': path, 'document': payload,
                           'headers': headers, 'timeout': timeout})
        if self.raises is not None:
            raise self.raises
        return self.status, self.body


class Session:
    """A fake SMTP session: a context manager that can accept, refuse or fall over."""

    def __init__(self, *, refuses=None, error: BaseException | None = None, partial=None) -> None:
        """Choose the one answer this relay gives to `send_message`."""
        self.messages: list = []
        self.events: list[str] = []
        self.kwargs: dict = {}
        self.refuses = refuses
        self.error = error
        self.partial = partial

    def __enter__(self):
        """Hand over the session, as `smtplib.SMTP` does."""
        return self

    def __exit__(self, *exc):
        """Close without swallowing anything."""
        return False

    def ehlo(self):
        """Record the greeting."""
        self.events.append('ehlo')

    def starttls(self, *, context=None):
        """Record the upgrade and keep the (unused, fake) trust context out of the assertions."""
        self.events.append('starttls')

    def login(self, user, secret):
        """Record that a credential was offered, and never echo it back."""
        self.events.append('login')
        self.kwargs = {'user': user, 'secret': secret}

    def send_message(self, message, from_addr=None, to_addrs=None):
        """Accept the message, refuse it, or raise the scripted failure."""
        self.messages.append(message)
        if self.error is not None:
            raise self.error
        if self.refuses is not None:
            raise self.refuses
        return self.partial or {}


class TransportCase(unittest.TestCase):
    """Shared construction helpers: one transport, one fake provider, one outbox payload."""

    def transport(self, kind: str, *, provider: Provider | None = None, status: int = 200, body=None,
                  raises: BaseException | None = None, **extra):
        """Build one HTTP transport wired to a fake provider (built from `status`/`body`/`raises`)."""
        arguments = {'name': kind, 'client': provider or Provider(status=status, body=body, raises=raises)}
        arguments.update(extra)
        return {
            'ntfy': lambda: NtfyChannel('https://ntfy.example', 'ops-alerts', NTFY_TOKEN, **arguments),
            'slack': lambda: SlackChannel('https://hooks.slack.com/services/T00000/B00000/'
                                          + SLACK_SECRET, **arguments),
            'matrix': lambda: MatrixChannel('https://matrix.example', '!alerts:example.org',
                                            MATRIX_TOKEN, **arguments),
            'pagerduty': lambda: PagerDutyChannel(ROUTING_KEY, **arguments),
        }[kind]()

    def delivered(self, transport, *, delivery_id: str = DELIVERY, timeout: int | None = None,
                  **payload_kwargs):
        """Deliver one payload through `transport` and return the `Outcome`."""
        return transport.deliver(outbox_payload(delivery_id, **payload_kwargs), delivery_id=delivery_id,
                                timeout=timeout)


class OutcomeVocabularyTests(unittest.TestCase):
    """The crosswalk: three outcomes, four durable words, and no flattening of two failures."""

    def test_each_outcome_maps_to_a_word_the_outbox_column_already_offers(self):
        """Task 1's mapping, asserted against `state.ATTEMPT_CAUSES` rather than against a copy."""
        self.assertEqual(dict(channels.ATTEMPT_CAUSE), {'sent': 'accepted', 'rejected': 'rejected',
                                                        'unavailable': 'transport'})
        for outcome, cause in channels.ATTEMPT_CAUSE.items():
            self.assertIn(cause, ATTEMPT_CAUSES, outcome + ' names a word the column does not have')
            self.assertEqual(channels.attempt_cause(outcome), cause)
            self.assertEqual(channels.Outcome(outcome).cause, cause)
        self.assertNotIn('policy', channels.ATTEMPT_CAUSE.values(),
                         'a transport may not claim the platform\'s own refusal word')

    def test_the_two_failures_stay_two_words_after_the_crosswalk(self):
        """The defect this whole brief exists to prevent, pinned as a difference and not a description."""
        refusal = http_outcome(403, False)
        outage = http_outcome(503, False)
        self.assertEqual((refusal.outcome, outage.outcome), (OUTCOME_REJECTED, OUTCOME_UNAVAILABLE))
        self.assertEqual((refusal.cause, outage.cause), ('rejected', 'transport'))
        self.assertNotEqual(refusal.cause, outage.cause)

    def test_an_unanswered_request_is_never_recorded_as_a_refusal(self):
        """DNS/connect/TLS/timeout all land on `unavailable`, each with its own bounded reason word."""
        cases = {'dns': URLError('not known'), 'timeout': URLError(reason=TimeoutError()),
                 'reset': ConnectionResetError('peer closed'), 'refused': ConnectionRefusedError(),
                 'tls': ssl.SSLError('certificate verify failed')}
        for name, error in cases.items():
            with self.subTest(cause=name):
                wrapped = TransportError('Endpoint unavailable or invalid JSON response')
                wrapped.__cause__ = error
                outcome = channels.Outcome(OUTCOME_UNAVAILABLE, reason=channels.network_reason(wrapped))
                self.assertEqual(outcome.cause, 'transport')
                self.assertIn(outcome.reason, channels.OUTCOME_REASONS)
        self.assertEqual(channels.network_reason(TimeoutError()), 'timeout')

    def test_an_invented_outcome_word_is_refused_rather_than_stored(self):
        """`Outcome` cannot become a place to park a fourth failure class nobody has read about."""
        with self.assertRaises(StateError):
            channels.Outcome('maybe')
        with self.assertRaises(StateError):
            channels.Outcome(OUTCOME_SENT, reason='the provider said no')
        with self.assertRaises(StateError):
            channels.attempt_cause('maybe')
        with self.assertRaises(StateError):
            channels.Outcome(OUTCOME_SENT, status=99)


class TransportTaxonomyTests(TransportCase):
    """One test per transport, each proving all three answers, and no socket involved."""

    def test_ntfy_publishes_and_distinguishes_a_refusal_from_an_outage(self):
        """A 404 topic is `rejected`; a 5xx and a raised `TransportError` are both `unavailable`."""
        self.assertEqual(self.delivered(self.transport('ntfy', body={'id': 'abc123'})).outcome, OUTCOME_SENT)
        self.assertEqual(self.delivered(self.transport('ntfy', status=404)).outcome, OUTCOME_REJECTED)
        self.assertEqual(self.delivered(self.transport('ntfy', raises=TransportError('down'))).outcome,
                         OUTCOME_UNAVAILABLE)
        self.assertEqual(self.delivered(self.transport('ntfy', status=500)).outcome, OUTCOME_UNAVAILABLE)

    def test_ntfy_title_with_emoji_and_cjk_travels_in_the_body_not_a_header(self):
        """v0.1's measured quirk (`legacy:notifiers/ntfy.py`): a latin-1 header would crash on this title."""
        provider = Provider(body={'id': 'abc123'})
        transport = self.transport('ntfy', provider=provider,
                                  display_config={'message_prefix': '[🚨 監視] local-observe'})
        self.assertEqual(self.delivered(transport).outcome, OUTCOME_SENT)
        document = provider.calls[0]['document']
        self.assertIn('🚨', json.dumps(document, ensure_ascii=False))
        headers = provider.calls[0]['headers']
        for name, value in headers.items():
            self.assertTrue(value.isascii(), 'header %s would crash a latin-1 encode' % name)
        self.assertEqual(sorted(headers), ['Authorization', 'Idempotency-Key'],
                         'the only headers built per send are the credential and the dedupe key')
        self.assertEqual(document['priority'], 4, 'the severity ladder is in the body too')

    def test_slack_accepts_a_plain_text_ok_and_reads_a_4xx_as_a_refusal(self):
        """Slack answers ``ok`` in plain text: a 2xx is the whole proof it offers, a 400 is a refusal."""
        self.assertEqual(self.delivered(self.transport('slack', body=None)).outcome, OUTCOME_SENT)
        self.assertEqual(self.delivered(self.transport('slack', status=400)).outcome, OUTCOME_REJECTED)
        self.assertEqual(self.delivered(self.transport('slack', raises=TransportError('down'))).outcome,
                         OUTCOME_UNAVAILABLE)

    def test_matrix_treats_a_missing_event_id_as_an_unproven_delivery(self):
        """A 2xx without the room event id proved nothing, which is the refusal-prone reading."""
        self.assertEqual(self.delivered(self.transport('matrix', body={'event_id': '$abc'})).outcome,
                         OUTCOME_SENT)
        self.assertEqual(self.delivered(self.transport('matrix', body={})).outcome, OUTCOME_REJECTED)
        self.assertEqual(self.delivered(self.transport('matrix', status=403)).outcome, OUTCOME_REJECTED)
        self.assertEqual(self.delivered(self.transport('matrix', raises=TransportError('down'))).outcome,
                         OUTCOME_UNAVAILABLE)

    def test_pagerduty_reads_its_own_status_field_and_429_as_a_rainy_day(self):
        """Events v2 answers `{"status":"success"}`; a 429 is "come back later", not "no"."""
        self.assertEqual(self.delivered(self.transport('pagerduty',
                                                       body={'status': 'success'})).outcome, OUTCOME_SENT)
        self.assertEqual(self.delivered(self.transport('pagerduty', status=400)).outcome, OUTCOME_REJECTED)
        self.assertEqual(self.delivered(self.transport('pagerduty', status=429)).outcome,
                         OUTCOME_UNAVAILABLE)
        self.assertEqual(self.delivered(self.transport('pagerduty', status=503)).outcome,
                         OUTCOME_UNAVAILABLE)

    def test_the_provider_ladders_are_derived_from_the_admitted_vocabulary_and_cannot_drift(self):
        """A channel repeats the event's loudness; it never assigns one, and never escalates on a typo."""
        self.assertEqual(dict(channels.NTFY_PRIORITY), {'info': 3, 'warning': 4, 'critical': 5},
                         'the zip over `vocabulary.ADMITTED_SEVERITIES` is v0.1\'s ladder, by position')
        for severity in ('info', 'warning', 'critical'):
            with self.subTest(severity=severity):
                provider = Provider(body={'id': 'abc'})
                self.delivered(self.transport('ntfy', provider=provider), severity=severity)
                self.assertEqual(provider.calls[0]['document']['priority'],
                                 channels.NTFY_PRIORITY[severity])
                provider = Provider(body={'status': 'success'})
                self.delivered(self.transport('pagerduty', provider=provider), severity=severity)
                self.assertEqual(provider.calls[0]['document']['payload']['severity'], severity,
                                 'PagerDuty admits all three words unchanged')
        unmapped = outbox_payload()
        unmapped['event']['severity'] = 'unheard-of'
        provider = Provider(body={'status': 'success'})
        self.transport('pagerduty', provider=provider).deliver(unmapped, delivery_id=DELIVERY)
        self.assertEqual(provider.calls[0]['document']['payload']['severity'], 'warning',
                         'a word this build should never see takes the middle rung, never the loudest')

    def test_email_separates_a_refused_recipient_from_a_relay_that_said_later(self):
        """SMTP's reply code decides, where v0.1 raised one `RuntimeError` for both."""
        refused = smtplib.SMTPRecipientsRefused({'oncall@example.org': (550, b'no such user')})
        session = Session()
        transport = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'],
                                 name='mail', smtp_factory=lambda *args: session)
        self.assertEqual(self.delivered(transport).outcome, OUTCOME_SENT)
        self.assertEqual(session.events, ['ehlo', 'starttls', 'ehlo'],
                         'an unauthenticated relay still upgrades, and greets again after the upgrade')
        refused_transport = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'],
                                         name='mail', smtp_factory=lambda *args: Session(refuses=refused))
        outcome = self.delivered(refused_transport)
        self.assertEqual((outcome.outcome, outcome.status, outcome.reason),
                         (OUTCOME_REJECTED, 550, 'recipient-refused'))
        temporary = smtplib.SMTPResponseException(451, b'try again later')
        later = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], name='mail',
                             smtp_factory=lambda *args: Session(error=temporary))
        self.assertEqual(self.delivered(later).outcome, OUTCOME_UNAVAILABLE)
        gone = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], name='mail',
                            smtp_factory=lambda *args: Session(error=smtplib.SMTPServerDisconnected()))
        self.assertEqual(self.delivered(gone).reason, 'no-connection')

    def test_email_partially_refused_recipients_are_still_a_delivery(self):
        """Some mailboxes accepted it: resending would page the people who already have the alert."""
        session = Session(partial={'late@example.org': (550, b'mailbox unavailable')})
        transport = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'],
                                 name='mail', smtp_factory=lambda *args: session)
        self.assertEqual(self.delivered(transport).outcome, OUTCOME_SENT)

    def test_every_transport_refuses_to_format_a_restricted_event(self):
        """A refusal to *attempt* the send is not a delivery outcome, for any channel (`policy`, not here)."""
        for kind in ('ntfy', 'slack', 'matrix', 'pagerduty'):
            with self.subTest(kind=kind):
                transport = self.transport(kind, provider=Provider(body={'id': 'x', 'event_id': '$x',
                                                                        'status': 'success'}))
                with self.assertRaises(StateError):
                    self.delivered(transport, data_class='restricted')
                self.assertEqual(transport.client().calls, [], 'nothing was sent, not even attempted')
        session = Session()
        mail = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], name='mail',
                            smtp_factory=lambda *args: session)
        with self.assertRaises(StateError):
            self.delivered(mail, data_class='restricted')
        self.assertEqual(session.messages, [])

    def test_a_mismatched_identity_is_refused_before_any_request(self):
        """The delivery id is checked against the row rather than trusted, on every transport."""
        transport = self.transport('ntfy', provider=Provider(body={'id': 'abc'}))
        with self.assertRaises(StateError):
            transport.deliver(outbox_payload(), delivery_id='22222222-3333-4444-5555-666666666666')
        with self.assertRaises(StateError):
            self.delivered(transport, transition='escalated')


class DeliveryIdentityTests(TransportCase):
    """Task 3: the field name per channel, and the id that must survive a crash."""

    def test_the_delivery_id_field_is_named_per_channel(self):
        """The receiver's dedupe key is different in every provider's own tongue, and identical in value."""
        expected = {
            'ntfy': ('headers', 'Idempotency-Key'),
            'slack': ('headers', 'Idempotency-Key'),
            'matrix': ('path', None),
            'pagerduty': ('document', 'dedup_key'),
        }
        bodies = {'ntfy': {'id': 'abc'}, 'slack': None, 'matrix': {'event_id': '$abc'},
                  'pagerduty': {'status': 'success'}}
        for kind, (where, key) in expected.items():
            with self.subTest(channel=kind):
                provider = Provider(body=bodies[kind])
                self.delivered(self.transport(kind, provider=provider))
                call = provider.calls[0]
                if where == 'headers':
                    self.assertEqual(call['headers']['Idempotency-Key'], DELIVERY)
                elif where == 'path':
                    self.assertTrue(call['path'].endswith('/' + DELIVERY.replace('-', ''))
                                    or call['path'].endswith('/' + DELIVERY),
                                    'the txnId is the last path segment')
                    self.assertEqual(call['headers']['Idempotency-Key'], DELIVERY)
                else:
                    self.assertEqual(call['document'][key], DELIVERY)
                    self.assertEqual(call['document']['payload']['custom_details']['delivery_id'], DELIVERY)

    def test_email_carries_the_delivery_id_as_the_message_id(self):
        """The field the brief names for this channel: one id, so a re-delivery threads, not duplicates."""
        session = Session()
        mail = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], name='mail',
                            smtp_factory=lambda *args: session)
        self.delivered(mail)
        self.assertEqual(session.messages[0]['Message-ID'], '<' + DELIVERY + '@example.org>')

    def test_the_message_id_falls_back_to_a_reserved_domain_and_never_invents_one(self):
        """A sender with no domain must not make the reply address look real (`.invalid` is RFC 2606)."""
        session = Session()
        mail = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], name='mail',
                            smtp_factory=lambda *args: session)
        mail._sender = 'lo'
        self.delivered(mail)
        self.assertTrue(session.messages[0]['Message-ID'].endswith('@' + channels.MESSAGE_ID_FALLBACK + '>'))


class StoreDeliveryTests(unittest.TestCase):
    """The transports behind the real lease: budgets, breaker, retries and a stable id."""

    def setUp(self):
        """Open a scratch directory; each test names its own database."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def store(self, name: str, **policy) -> Store:
        """One live store on the primary channel, with the test's own budget."""
        policy.setdefault('delivery_mode', 'live')
        policy.setdefault('max_event_age_seconds', 86400)
        return Store(self.root / (name + '.db'), NotificationPolicy(channel='primary', **policy))

    def fire(self, store: Store, source: str, *, offset: int = 0) -> str:
        """Intake one firing event and return the delivery id it queued."""
        now = NOW + dt.timedelta(seconds=offset)
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        item = event(source, None, 'availability', 'availability', 'firing', window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')
        before = {row['id'] for row in store.records('outbox')}
        store.intake(item, Actor(source, 'producer'), now=now)
        queued = [row['id'] for row in store.records('outbox') if row['id'] not in before]
        self.assertEqual(len(queued), 1, 'one event queues exactly one delivery')
        return queued[0]

    def provider(self, *, body=None, **kwargs) -> Provider:
        """One ntfy transport pointed at a fake provider, as the loop will call it."""
        return Provider(body={'id': 'published'} if body is None else body, **kwargs)

    def client(self, provider: Provider) -> dict:
        """Wrap a fake-provider transport in the ``{channel: client}`` form the loop expects."""
        return {'primary': NtfyChannel('https://ntfy.example', 'ops-alerts', NTFY_TOKEN,
                                       name='primary', client=provider)}

    def attempts(self, store: Store) -> list[tuple[str, str]]:
        """Return ``[(result, cause), …]`` newest-first, straight from the durable record."""
        with closing(sqlite3.connect(store.path)) as db:
            return [(row[0], row[1]) for row in db.execute(
                'SELECT result, cause FROM notification_attempts ORDER BY started_at DESC, id DESC')]

    def test_a_latched_breaker_opens_no_socket_and_writes_the_suppression_row(self):
        """Task 4: the transport is called only from the claim path, and a latched breaker is not asked."""
        store = self.store('breaker', max_attempts=2, window_seconds=600)
        provider = self.provider()
        deliveries = [self.fire(store, 'detector-%d' % index, offset=index) for index in range(3)]
        reports = [deliver_one(store, self.client(provider), now=NOW + dt.timedelta(seconds=index))
                   for index in range(3)]
        self.assertEqual([report['status'] for report in reports], ['sent', 'sent', 'suppressed'])
        self.assertEqual(reports[2]['reason'], 'flood-circuit-open')
        self.assertEqual(len(provider.calls), 2, 'the third delivery never reached a socket')
        with closing(sqlite3.connect(store.path)) as db:
            suppressed = db.execute('SELECT outbox_id, reason FROM notification_suppressions').fetchall()
            booked = db.execute('SELECT count(*) FROM notification_reservations').fetchone()[0]
        self.assertEqual([(row[0], row[1]) for row in suppressed], [(deliveries[2], 'flood-circuit-open')])
        self.assertEqual(booked, 2, 'only the two sends that happened took a slot')

    def test_a_redelivery_after_an_expired_lease_carries_the_same_delivery_id(self):
        """The dedupe promise, tested against the lease rather than against a mock's memory.

        A worker claims the row, reaches the provider and dies before `finish_notification`: the attempt
        is closed as `unknown`, because the platform genuinely does not know whether the message landed.
        The next claim must therefore carry **the same** delivery id — a new one would make the receiver's
        dedupe impossible and would page the operator twice for one incident.
        """
        store = self.store('lease', max_attempts=10)
        delivery = self.fire(store, 'detector-lease')
        crashed = store.claim_notification(now=NOW, lease_seconds=5)
        self.assertEqual(crashed['id'], delivery, 'the row a worker is now holding')
        provider = self.provider()
        report = deliver_one(store, self.client(provider), now=NOW + dt.timedelta(seconds=60))
        self.assertEqual(report['status'], 'sent')
        self.assertEqual([call['headers']['Idempotency-Key'] for call in provider.calls], [delivery])
        with closing(sqlite3.connect(store.path)) as db:
            row = db.execute('SELECT attempts, status FROM outbox').fetchone()
            closed = db.execute("SELECT result FROM notification_attempts WHERE result='unknown'").fetchall()
        self.assertEqual(row, (2, 'sent'), 'the attempt count moved; the identity did not')
        self.assertEqual(len(closed), 1, 'the crashed attempt is honestly marked unknown')

    def test_an_unexpected_transport_failure_cannot_escape_and_cannot_leak_the_lease(self):
        """The one exception class no provider answer explains must still close the attempt.

        An escaping error would skip `finish_notification`, leaving the row `sending` until its lease
        ages out with no attempt row saying what happened — the shape of failure this rule exists to
        make impossible, so it is tested with a client that raises something no transport expects.
        """
        store = self.store('escape', max_attempts=10)
        self.fire(store, 'detector-escape')  # queues the outbox row; the id is not used here
        provider = self.provider(raises=RuntimeError('a bug, not an outage'))
        with self.assertLogs('local_observe', level='DEBUG') as captured:
            report = deliver_one(store, self.client(provider), now=NOW)
        self.assertEqual(report['status'], 'pending', 'the row is pending and re-claimable, not leased')
        self.assertEqual(self.attempts(store)[0], ('failed', 'transport'))
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute('SELECT status FROM outbox').fetchone()[0], 'pending')
        self.assertNotIn('a bug, not an outage', '\n'.join(r.getMessage() for r in captured.records),
                         'the class is logged; the message is not')

    def test_the_delivery_id_does_not_change_when_attempts_increment(self):
        """Three failed attempts, one identity: what a receiver must be able to collapse into one alert."""
        store = self.store('stable', max_attempts=10)
        delivery = self.fire(store, 'detector-stable')
        provider = self.provider(raises=TransportError('Endpoint unavailable'))
        for index in range(3):
            deliver_one(store, self.client(provider), now=NOW + dt.timedelta(seconds=300 * index))
        self.assertEqual([call['headers']['Idempotency-Key'] for call in provider.calls],
                         [delivery] * 3, 'the same id on every attempt, however many the row has made')
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute('SELECT attempts FROM outbox').fetchone()[0], 3)

    def test_a_refused_send_is_bounded_by_the_attempt_count_the_state_module_already_enforces(self):
        """`rejected` cannot loop forever: 5 attempts (the `finish_notification` default), then `dead`.

        The policy is `state.py`'s, not a channel's: `finish_notification` parks the row as `dead` once
        `attempts >= max_attempts`, and `retry_notification` is the only way back — it requires a `human`
        actor, refuses a row that is not yet exhausted ('Only exhausted notifications can be manually
        retried') and resets `attempts` to 0, so the next run is bounded the same way again. Nothing a
        channel decides can extend that, which is why no transport here carries a retry count.
        """
        store = self.store('refused', max_attempts=100)
        delivery = self.fire(store, 'detector-refused')
        provider = self.provider(status=403, body=None)
        clients = self.client(provider)
        early = [deliver_one(store, clients, now=NOW + dt.timedelta(seconds=300 * index))
                 for index in range(2)]
        self.assertEqual([report['status'] for report in early], ['pending', 'pending'])
        with self.assertRaisesRegex(StateError, 'Only exhausted notifications'):
            store.retry_notification(delivery, Actor('operator', 'human'), now=NOW + dt.timedelta(hours=1))
        rest = [deliver_one(store, clients, now=NOW + dt.timedelta(seconds=300 * index))
                for index in range(2, 7)]
        self.assertEqual([report['status'] for report in rest],
                         ['pending', 'pending', 'dead', 'idle', 'idle'])
        self.assertEqual(len(provider.calls), 5, 'five sends, not seven asks')
        self.assertEqual({cause for _, cause in self.attempts(store)}, {'rejected'})
        store.retry_notification(delivery, Actor('operator', 'human'), now=NOW + dt.timedelta(hours=2))
        self.assertEqual(deliver_one(store, self.client(Provider(body={'id': 'published'})),
                                     now=NOW + dt.timedelta(hours=2, seconds=1))['status'], 'sent')

    def test_a_transport_that_refuses_to_format_a_row_is_a_platform_refusal_not_a_provider_one(self):
        """`policy` vs `rejected`, decided by which side said no — the fourth cause word stays reachable.

        Reachable only through a row the platform itself should never have queued (here: a payload whose
        delivery id does not match the row's, as a restored or hand-edited database can produce). The
        provider never gets asked, so the answer cannot be "the provider refused".
        """
        store = self.store('policy', max_attempts=10)
        self.fire(store, 'detector-policy')  # queues the outbox row; the id is not used here
        with closing(sqlite3.connect(store.path)) as db:
            payload = json.loads(db.execute('SELECT payload FROM outbox').fetchone()[0])
            payload['delivery_id'] = '99999999-8888-7777-6666-555555555555'
            db.execute('UPDATE outbox SET payload=?', (json.dumps(payload),))
            db.commit()
        provider = self.provider()
        with self.assertLogs('local_observe', level='DEBUG'):
            report = deliver_one(store, self.client(provider), now=NOW)
        self.assertEqual(report['status'], 'pending')
        self.assertEqual(self.attempts(store)[0], ('failed', 'policy'))
        self.assertEqual(provider.calls, [], 'no request left the process')

    def test_a_suppressed_delivery_is_not_replayable_however_a_channel_is_configured(self):
        """The other half of the bound: a suppression is final for a human too, on this port's channels."""
        store = self.store('suppressed', max_attempts=10)
        delivery = self.fire(store, 'detector-suppressed')
        store.reset_notification_guard(Actor('operator', 'human'), now=NOW + dt.timedelta(seconds=30))
        with self.assertRaisesRegex(StateError, 'cannot be replayed'):
            store.retry_notification(delivery, Actor('operator', 'human'), now=NOW + dt.timedelta(hours=1))


class BoundTests(TransportCase):
    """Task 5: one bounded timeout, no redirect, no proxy, no second socket, no credential in a string."""

    def test_one_bounded_timeout_per_attempt_and_a_caller_may_only_shorten_it(self):
        """`deliver(timeout=)` is honoured downwards: a lease cannot be held open by a slow caller."""
        provider = Provider(body={'id': 'abc'})
        transport = self.transport('ntfy', provider=provider)
        self.delivered(transport)
        self.assertEqual(provider.calls[0]['timeout'], channels.DEFAULT_TIMEOUT_SECONDS)
        self.delivered(transport, timeout=3)
        self.assertEqual(provider.calls[-1]['timeout'], 3)
        self.delivered(transport, timeout=999)
        self.assertEqual(provider.calls[-1]['timeout'], channels.DEFAULT_TIMEOUT_SECONDS,
                         'the transport bound wins, so no caller holds a lease past it')
        with self.assertRaises(ChannelConfigError):
            self.transport('ntfy', provider=provider, timeout=300)

    def test_the_built_clients_refuse_a_redirect_and_install_no_environment_proxy(self):
        """Every HTTP transport goes through `JsonClient`, which is where `NoRedirect` lives."""
        for kind in ('ntfy', 'slack', 'matrix', 'pagerduty'):
            with self.subTest(kind=kind):
                built = self.transport(kind, provider=Provider())._build_client()
                self.assertIsInstance(built, JsonClient)
                names = [type(handler).__name__ for handler in built.opener.handlers]
                self.assertIn('NoRedirect', names)
                redirector = next(h for h in built.opener.handlers if type(h).__name__ == 'NoRedirect')
                self.assertIsNone(redirector.redirect_request(None, None, 302, '', {},
                                                              'https://elsewhere.example/'))
                for handler in built.opener.handlers:
                    if getattr(handler, 'proxies', None) is not None:
                        self.assertEqual(handler.proxies, {}, 'an environment proxy would carry the URL')

    def test_no_transport_opens_a_socket_of_its_own(self):
        """The one rule the brief states as a grep, pinned so a later channel cannot quietly drift."""
        text = (Path(__file__).resolve().parents[1] / 'local_observe' / 'platform'
                / 'channels.py').read_text(encoding='utf-8')
        self.assertNotIn('urlopen', text)
        self.assertNotIn('requests.', text)
        self.assertNotIn('import urllib.request', text)
        self.assertIn('from local_observe.http import JsonClient', text,
                      'HTTP goes through the bounded client, or it does not go')
        self.assertIn('smtplib', text, 'email is not HTTP; it is the one other transport, bounded by smtplib')

    def test_an_email_credential_never_reaches_a_relay_that_did_not_upgrade(self):
        """STARTTLS is not optional where a password exists, and the refusal is at construction."""
        with self.assertRaises(ChannelConfigError) as caught:
            EmailChannel('smtp.example', 25, 'lo@example.org', ['oncall@example.org'], 'lo',
                         MAIL_PASSWORD, starttls=False, name='mail')
        self.assertIn('STARTTLS', str(caught.exception))
        self.assertNotIn(MAIL_PASSWORD, str(caught.exception))


class CredentialRedactionTests(TransportCase):
    """Task 5's other half: the secret appears in no log line, no exception and no durable row."""

    def setUp(self):
        """A scratch directory for the one test that reads a real database back."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    @staticmethod
    def _text(records: list[logging.LogRecord]) -> str:
        """Flatten a captured log call to text, extras included, because `extra=` is where detail lands."""
        reserved = set(logging.LogRecord('', 0, '', 0, '', (), None).__dict__)
        chunks = [record.getMessage() for record in records]
        for record in records:
            chunks.extend(repr(value) for key, value in vars(record).items() if key not in reserved)
            if record.exc_info:
                chunks.append(repr(record.exc_info))
        return '\n'.join(chunks)

    def test_no_credential_appears_in_a_log_line_or_an_error_string_on_any_transport(self):
        """For each transport: force the failure that knows the credential, and read everything back."""
        cases = [
            ('ntfy', TransportError(URL_SECRET), NTFY_TOKEN),
            ('slack', URLError(URL_SECRET), SLACK_SECRET),
            ('matrix', TransportError('401 unauthorized'), MATRIX_TOKEN),
            ('pagerduty', TransportError(URL_SECRET), ROUTING_KEY),
        ]
        for kind, error, secret in cases:
            with self.subTest(channel=kind):
                provider = Provider(raises=error)
                transport = self.transport(kind, provider=provider)
                with self.assertLogs('local_observe', level='DEBUG') as captured:
                    outcome = self.delivered(transport)
                    with self.assertRaises(TransportError) as raised:
                        transport.request('POST', payload=outbox_payload(),
                                          headers={'Idempotency-Key': DELIVERY})
                emitted = self._text(captured.records) + repr(outcome) + str(raised.exception)
                self.assertEqual(outcome.outcome, OUTCOME_UNAVAILABLE)
                for forbidden in (secret, URL_SECRET, 'passworD'):
                    self.assertNotIn(forbidden, emitted, '%s leaked %s' % (kind, forbidden))

    def test_an_smtp_rejection_does_not_echo_the_password(self):
        """`smtplib` puts the account name in some of its messages; the password is ours to lose."""
        session = Session(error=smtplib.SMTPAuthenticationError(535, b'username or password invalid'))
        mail = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], 'lo',
                            MAIL_PASSWORD, name='mail', smtp_factory=lambda *args: session)
        with self.assertLogs('local_observe', level='DEBUG') as captured:
            status, receipt = mail.request('POST', payload=outbox_payload(),
                                          headers={'Idempotency-Key': DELIVERY})
        self.assertEqual((status, receipt['accepted']), (535, False))
        self.assertNotIn(MAIL_PASSWORD, self._text(captured.records) + str(status) + str(receipt))
        self.assertEqual(session.kwargs['secret'], MAIL_PASSWORD, 'it was offered, to the upgraded session')

    def test_a_transport_failure_stores_no_provider_detail_behind_it(self):
        """The attempt row and the audit log hold the cause word and nothing a provider wrote."""
        store = Store(self.root / 'redaction.db', NotificationPolicy(delivery_mode='live'))
        provider = Provider(raises=TransportError(URL_SECRET + ' ' + NTFY_TOKEN))
        clients = {'primary': NtfyChannel('https://ntfy.example', 'ops-alerts', NTFY_TOKEN,
                                          name='primary', client=provider)}
        now = NOW
        window = {'start': utc_text(now - dt.timedelta(seconds=1)), 'end': utc_text(now)}
        item = event('detector-redaction', None, 'availability', 'availability', 'firing', window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')
        store.intake(item, Actor('detector-redaction', 'producer'), now=now)
        with self.assertLogs('local_observe', level='DEBUG') as captured:
            deliver_one(store, clients, now=now)
        with closing(sqlite3.connect(store.path)) as db:
            durable = ' '.join(str(value) for row in db.execute(
                'SELECT result, cause FROM notification_attempts').fetchall() for value in row)
            audit = ' '.join(row[0] for row in db.execute('SELECT detail FROM audit').fetchall())
        for forbidden in (NTFY_TOKEN, URL_SECRET, 'passworD'):
            self.assertNotIn(forbidden, durable, 'the attempt column grew a second meaning')
            self.assertNotIn(forbidden, audit)
            self.assertNotIn(forbidden, self._text(captured.records))


class ConfigurationTests(unittest.TestCase):
    """Task 6: the five new channels are entries in the same mounted document, with file credentials."""

    def setUp(self):
        """Write one file per credential the new entries name, plus the bad ones refusals are tested on."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write('ntfy-token', NTFY_TOKEN)
        self.write('slack-url', 'https://hooks.slack.com/services/T00000/B00000/' + SLACK_SECRET)
        self.write('matrix-token', MATRIX_TOKEN)
        self.write('pagerduty-key', ROUTING_KEY)
        self.write('mail-password', MAIL_PASSWORD)
        self.write('recipients', 'oncall@example.org\nsecond@example.org\n')
        self.write('crlf-token', NTFY_TOKEN + '\r\n')
        self.write('bad-recipient', 'oncall@example.org\r\n')
        self.write('big-token', 'x' * 8000)

    def write(self, name: str, value: str) -> str:
        """Write one mounted file with `printf` semantics (one trailing LF at most) and name its path."""
        path = self.root / name
        data = value if value.endswith('\n') else value + '\n'
        path.write_bytes(data.encode())
        return str(path)

    def entries(self) -> list[dict]:
        """One entry per ported transport, in the order an operator would declare them."""
        return [{'channel': 'push', 'type': 'ntfy', 'url': 'https://ntfy.example', 'topic': 'ops-alerts',
                 'token_file': str(self.root / 'ntfy-token')},
                {'channel': 'chat', 'type': 'slack', 'url_file': str(self.root / 'slack-url')},
                {'channel': 'room', 'type': 'matrix', 'url': 'https://matrix.example',
                 'room_id': '!alerts:example.org', 'token_file': str(self.root / 'matrix-token')},
                {'channel': 'paged', 'type': 'pagerduty', 'key_file': str(self.root / 'pagerduty-key')},
                {'channel': 'mail', 'type': 'email', 'host': 'smtp.example', 'port': 587,
                 'from': 'lo@example.org', 'recipients_file': str(self.root / 'recipients'),
                 'username': 'lo', 'password_file': str(self.root / 'mail-password')}]

    def built(self, document: list[dict]):
        """Build a document in live mode, the way `app_factory` does."""
        return build_channels(document, mode='live')

    def test_all_five_transports_are_constructed_from_one_document(self):
        """A new channel is a document entry, so `api.py` and the boot path do not change for it."""
        clients, policies = self.built(self.entries())
        self.assertEqual(list(clients), ['push', 'chat', 'room', 'paged', 'mail'],
                         'document order is the preference order')
        self.assertEqual([type(client).__name__ for client in clients.values()],
                         ['NtfyChannel', 'SlackChannel', 'MatrixChannel', 'PagerDutyChannel',
                          'EmailChannel'])
        self.assertEqual({policies[name].channel for name in clients}, set(clients))
        self.assertIsInstance(clients['push'].client(), JsonClient)
        self.assertEqual(clients['mail']._recipients, ['oncall@example.org', 'second@example.org'])

    def test_a_mixed_document_of_seven_channels_still_books_budgets_per_channel(self):
        """The two adapters that predate this port and the five new ones are one preference-ordered set."""
        document = ([{'channel': 'primary', 'type': 'telegram',
                      'config': self.write('telegram.json',
                                           json.dumps({'token': '999:synthetic', 'chat_id': '456'}))}]
                    + self.entries()
                    + [{'channel': 'oncall', 'type': 'webhook', 'url': 'https://hook.example/receive',
                        'token_file': self.write('hook-token', 'w' * 32)}])
        clients, policies = self.built(document)
        self.assertEqual(len(clients), 7)
        self.assertEqual([policies[name].max_attempts for name in clients], [10] * 7,
                         'each channel keeps its own budget while they all share the service mode')

    def test_every_malformed_entry_refuses_without_repeating_a_credential_or_a_path(self):
        """Config refusals name the channel and the key; the secret and the file stay in the file."""
        cases = {
            'ntfy without a topic': {'channel': 'push', 'type': 'ntfy', 'url': 'https://ntfy.example'},
            'ntfy topic with a path separator': {'channel': 'push', 'type': 'ntfy',
                                                 'url': 'https://ntfy.example', 'topic': '../secret'},
            'slack naming a plain url field': {'channel': 'chat', 'type': 'slack',
                                               'url': 'https://hooks.slack.com/services/T0/B/' + SLACK_SECRET},
            'slack url that is not the accepted origin': {'channel': 'chat', 'type': 'slack',
                                                          'url_file': self.write('evil',
                                                                                 'https://evil.example/x')},
            'matrix without a room': {'channel': 'room', 'type': 'matrix', 'url': 'https://matrix.example',
                                      'token_file': str(self.root / 'matrix-token')},
            'matrix room id that is not bounded': {'channel': 'room', 'type': 'matrix',
                                                   'url': 'https://matrix.example', 'room_id': 'alerts',
                                                   'token_file': str(self.root / 'matrix-token')},
            'pagerduty with no routing key file': {'channel': 'paged', 'type': 'pagerduty'},
            'email with a password and no username': {'channel': 'mail', 'type': 'email',
                                                      'host': 'smtp.example', 'port': 587,
                                                      'from': 'lo@example.org',
                                                      'recipients_file': str(self.root / 'recipients'),
                                                      'password_file': str(self.root / 'mail-password')},
            'email with starttls off and a password': {'channel': 'mail', 'type': 'email',
                                                       'host': 'smtp.example', 'port': 587,
                                                       'from': 'lo@example.org',
                                                       'recipients_file': str(self.root / 'recipients'),
                                                       'username': 'lo',
                                                       'password_file': str(self.root / 'mail-password'),
                                                       'starttls': False},
            'email with a CRLF in a recipient line': {'channel': 'mail', 'type': 'email',
                                                      'host': 'smtp.example', 'port': 587,
                                                      'from': 'lo@example.org',
                                                      'recipients_file': str(self.root / 'bad-recipient')},
            'email from another channel type': {'channel': 'mail', 'type': 'email', 'room_id': '!x:y',
                                                'host': 'smtp.example', 'port': 587,
                                                'from': 'lo@example.org',
                                                'recipients_file': str(self.root / 'recipients')},
            'credential file written with CRLF': {'channel': 'push', 'type': 'ntfy',
                                                  'url': 'https://ntfy.example', 'topic': 'ops',
                                                  'token_file': str(self.root / 'crlf-token')},
            'credential file oversized': {'channel': 'push', 'type': 'ntfy', 'url': 'https://ntfy.example',
                                          'topic': 'ops', 'token_file': str(self.root / 'big-token')},
            'credential file missing': {'channel': 'push', 'type': 'ntfy', 'url': 'https://ntfy.example',
                                        'topic': 'ops', 'token_file': str(self.root / 'gone')},
            'an unsupported new type': {'channel': 'itsm', 'type': 'itsm', 'key_file': 'x'},
        }
        for name, entry in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(DocumentConfigError) as caught:
                    self.built([entry])
                for forbidden in (NTFY_TOKEN, MATRIX_TOKEN, ROUTING_KEY, MAIL_PASSWORD, SLACK_SECRET,
                                  'ntfy.example', 'evil.example', 'matrix-token', 'slack-url',
                                  'pagerduty-key', 'mail-password', 'gone', str(self.root)):
                    self.assertNotIn(forbidden, str(caught.exception),
                                     '%s refused by repeating %r' % (name, forbidden))

    def test_a_credential_is_read_by_the_product_credential_reader_and_never_from_the_environment(self):
        """`read_credential` is the only reader, and the variable name it prints is a label, not a read."""
        environment = {'CHANNEL_PUSH_TOKEN_FILE': str(self.root / 'gone'),
                       'LO_CHANNEL_PUSH_TOKEN': 'never-export-this'}
        from unittest import mock
        with mock.patch.dict('os.environ', environment, clear=True):
            clients, _ = self.built([self.entries()[0]])
        self.assertEqual(clients['push']._token, NTFY_TOKEN, 'the value came from the entry, not the env')

    def test_a_transport_that_cannot_tell_two_failures_apart_cannot_be_configured(self):
        """The port table's exclusion, checked as a property of the vocabulary rather than of a comment."""
        self.assertEqual({channel.kind for channel in
                          self.built(self.entries())[0].values()},
                         {'ntfy', 'slack', 'matrix', 'pagerduty', 'email'})
        for kind in ('itsm', 'sms', 'pager', 'unknown'):
            with self.subTest(kind=kind), self.assertRaises(DocumentConfigError):
                self.built([{'channel': 'x', 'type': kind, 'url': 'https://x.example/'}])


class SinkGuardTests(TransportCase):
    """A transport is a sender, and only a sender: it cannot read, redirect or consume anything."""

    def test_no_unexpected_error_leaves_a_transport_as_an_exception(self):
        """Both the HTTP and the SMTP shape answer `unavailable` where a client raises nonsense."""
        transport = self.transport('ntfy', raises=RuntimeError('boom'))
        with self.assertLogs('local_observe', level='DEBUG'):
            outcome = self.delivered(transport)
        self.assertEqual((outcome.outcome, outcome.reason, outcome.cause),
                         (OUTCOME_UNAVAILABLE, 'protocol-failure', 'transport'))
        broken = EmailChannel('smtp.example', 587, 'lo@example.org', ['oncall@example.org'], name='mail',
                              smtp_factory=lambda *args: (_ for _ in ()).throw(RuntimeError('boom')))
        with self.assertLogs('local_observe', level='DEBUG'):
            outcome = self.delivered(broken)
        self.assertEqual(outcome.outcome, OUTCOME_UNAVAILABLE)

    def test_a_non_post_call_is_refused_rather_than_reinterpreted(self):
        """The adapter speaks the delivery loop's protocol and nothing else."""
        transport = self.transport('ntfy', provider=Provider(body={'id': 'abc'}))
        with self.assertRaises(StateError):
            transport.request('GET', payload=outbox_payload(), headers={'Idempotency-Key': DELIVERY})
        with self.assertRaises(StateError):
            transport.request('POST', payload=outbox_payload(), headers={'Idempotency-Key': 'wrong'})

    def test_build_transport_refuses_a_type_it_was_not_asked_about(self):
        """The delegated constructor is not a general factory: `telegram` is not its decision to make."""
        with self.assertRaises(ChannelConfigError):
            build_transport({'channel': 'primary', 'type': 'telegram', 'config': 'x'}, 'primary',
                            secret=lambda path, channel, key: path)


if __name__ == '__main__':
    unittest.main()

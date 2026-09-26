"""Provider transports behind the leased outbox: one call per claim, and a named failure class.

v0.1's `legacy:notifiers` made a channel a `send()` that raised, and `base.dispatch()` turned the exception
into `DeliveryResult(channel, ok, attempts, error)` so one dead channel could not block the others.
That retry dispatch is **not** ported and must not be: here a delivery is already a leased outbox row
with an attempt count (`outbox.attempts`), a per-channel budget and a latched flood breaker
(`notification_safety.reserve`), so a second retry loop inside a channel would be a second, unbudgeted
answer to "how many times has this been sent?". What *is* ported is the other half of `base.py`: a
failure is **returned**, never raised out of a delivery, and it must say which of two different things
happened.

That last clause is the product requirement this module exists to meet. `docs/COMPONENTS.md` promises
"delivery absence is visible" and `notification_attempts.cause` (schema v3, ledger notifications) is the column
that keeps the promise, so every transport here answers with one of exactly three `Outcome`s and never
with a generic error:

* ``sent`` — the provider accepted this delivery;
* ``rejected`` — the provider answered and declined *this message* (4xx, bad topic, bad token, a
  permanently refused sender or recipient, an SMTP 5xx);
* ``unavailable`` — the provider could not be reached or could not take it now (DNS, connect, TLS,
  timeout, 5xx, 429, an SMTP 4xx).

`ATTEMPT_CAUSE` is the crosswalk onto the words `Store.finish_notification` already accepts, so these
three outcomes are a *narrowing* of `state.ATTEMPT_CAUSES` rather than a second vocabulary beside it:
`sent`→`accepted`, `rejected`→`rejected`, `unavailable`→`transport`. The fourth word a finished attempt
may hold — `policy`, "the platform refused to send" — is deliberately absent: `deliver_one` records it,
and a transport that could claim it would be deciding delivery policy from inside an HTTP call.

Two of v0.1's measured quirks are kept deliberately. ntfy's title and message ride in the JSON body and
**never** in a header, because urllib encodes header values as latin-1 and an emoji or CJK title would
crash the send (`legacy:notifiers/ntfy.py`); and every value that becomes a header, a URL segment or an SMTP
protocol argument is refused when it holds an ASCII control character — `local_observe/credentials.py`'s
rule, reused rather than re-spelled, and a deliberate *widening* of v0.1's CR/LF-only `_reject_crlf`.

ITSM sync (`legacy:notifiers/itsm.py`, 296 lines) is **not ported**: decision itop and `docs/COMPONENTS.md`
§3 exclude it. Nor is any channel that cannot tell "the provider refused" from "the provider is
unreachable" — that distinction is the reason each transport below has a taxonomy test instead of a
happy-path one.
"""
from __future__ import annotations

import abc
from collections.abc import Callable
from dataclasses import dataclass
import re
from pathlib import Path
import smtplib
import ssl
from types import MappingProxyType
import urllib.parse
import uuid
from typing import Any

from local_observe.credentials import CONTROL_CHARACTER, MAX_CREDENTIAL_BYTES
from local_observe.http import JsonClient, TransportError
from local_observe.log import get_logger

from .state import StateError, label
from .vocabulary import ADMITTED_SEVERITIES

log = get_logger(__name__)

#: The three answers a transport may give. Bounded on purpose: `Outcome` refuses a fourth word, so a
#: channel cannot invent its own failure class and quietly redefine what a red dot means.
OUTCOME_SENT = 'sent'
OUTCOME_REJECTED = 'rejected'
OUTCOME_UNAVAILABLE = 'unavailable'
OUTCOMES = (OUTCOME_SENT, OUTCOME_REJECTED, OUTCOME_UNAVAILABLE)

# The crosswalk onto the durable vocabulary. `sent` is `accepted` because that is the word
# `finish_notification(success=True)` records; `unavailable` is `transport` because that is what
# `deliver_one` already records for a client that raised `TransportError`; `rejected` needs no
# translation. `policy` is absent on purpose (module docstring).
ATTEMPT_CAUSE = MappingProxyType({OUTCOME_SENT: 'accepted', OUTCOME_REJECTED: 'rejected',
                                  OUTCOME_UNAVAILABLE: 'transport'})

#: The bounded words naming *why*, for the log line only. Nothing here is stored: the attempt row keeps
#: its one `cause` word, so a reason can never become a place to park provider output.
OUTCOME_REASONS = frozenset({'unproven-receipt', 'redirect-refused', 'http-refused', 'rate-limited',
                             'timeout', 'http-server-error', 'dns-lookup-failed', 'connection-refused',
                             'tls-handshake-failed', 'network-unreachable', 'endpoint-unreachable',
                             'protocol-failure', 'no-connection', 'auth-refused', 'sender-refused',
                             'recipient-refused', 'temporary-server-failure', 'server-failure'})
DEFAULT_TIMEOUT_SECONDS = 10
# The same bound `JsonClient.__init__` adjudicates. A transport allowed a 300-second timeout would hold
# an outbox lease (`claim_notification`'s `lease_seconds`, 5..300) open on a provider that has already
# stopped answering, which is how a crash and a slow endpoint become the same indistinguishable state.
TIMEOUT_BOUNDS = (1, 20)
MAX_BODY_LINES = 8
#: The domain an email `Message-ID` falls back to when the sender address names none. `.invalid` is
#: reserved (RFC 2606) and can never resolve, so a fallback cannot make a reply path look real.
MESSAGE_ID_FALLBACK = 'local.invalid'
ADDRESS = re.compile(r'[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.\-]{1,190}\Z')
TOPIC = re.compile(r'[A-Za-z0-9._-]{1,64}\Z')
ROOM_ID = re.compile(r'![A-Za-z0-9._\-/+=]{1,128}:[A-Za-z0-9.\-]{1,128}\Z')
#: The character set `http.JsonClient` will accept in a token, so a credential that passes here cannot
#: be refused by the client that has to carry it — and cannot hold anything a header could not.
OPAQUE_TOKEN = re.compile(r'[A-Za-z0-9 ._~+/=-]{24,1024}\Z')
#: The channel types this module builds. `notifications.CHANNEL_TYPES` adds `telegram` and `webhook`,
#: the two the delivery loop has always had, which keep their existing construction.
TRANSPORT_TYPES = ('ntfy', 'email', 'slack', 'matrix', 'pagerduty')

#: v0.1's ntfy ladder (`critical`→5, `warning`→4, `info`→3), spelled by *position* on the one severity
#: vocabulary this product admits (`vocabulary.ADMITTED_SEVERITIES`, quietest first) rather than by a
#: severity literal here: `tests/test_event_vocabulary.py` refuses a file outside its allowlist that
#: names one, because a channel that wrote its own loudness word would be a second producer. This is a
#: consumer, and the zip is the whole crosswalk — the ladder it produces is pinned by a test
#: (`TransportTaxonomyTests.test_ntfy_title_with_emoji_and_cjk_travels_in_the_body_not_a_header`).
NTFY_PRIORITY = MappingProxyType(dict(zip(ADMITTED_SEVERITIES, (3, 4, 5))))
NTFY_PRIORITY_DEFAULT = 3
PAGERDUTY_EVENTS_URL = 'https://events.pagerduty.com/v2/enqueue'
# PagerDuty's Events v2 vocabulary is a superset of this product's, so an admitted severity is already a
# valid PagerDuty one and needs no translation at all. What is worth spelling is the fallback for a value
# this build should never see: the middle rung, never the loudest, so a defect upstream cannot page.
PAGERDUTY_SEVERITIES = frozenset(ADMITTED_SEVERITIES)
PAGERDUTY_FALLBACK_SEVERITY = ADMITTED_SEVERITIES[1]


class ChannelConfigError(ValueError):
    """A channel document is wrong. The message names the channel and the key, never a credential."""


def _refuse(detail: str) -> ChannelConfigError:
    """Log one bounded configuration refusal and return it for the caller to raise.

    Every message names the channel label and the offending key; never a credential, an endpoint path, a
    response body or a file's contents. `notifications.build_channels` re-logs the sentence through its
    own `_refuse`, so one voice prints it whichever module found the problem.
    """
    log.warning('Notification transport configuration refused', extra={'reason': detail})
    return ChannelConfigError(detail)


def _field(value: Any, limit: int, what: str, channel: str) -> str:
    """Return one bounded document string that is about to become protocol, or refuse it.

    v0.1 checked CR and LF in the values it put into headers and SMTP fields (`legacy:notifiers/ntfy.py`,
    `legacy:notifiers/email.py`) because those two characters end a header line. This refuses every ASCII
    control character, using the product credential reader's own pattern: one NUL or vertical tab is
    just as much a second protocol line, and the refusal belongs at the read of the document rather than
    in a request that half-sends an alert.
    """
    if not isinstance(value, str) or not value or len(value) > limit:
        raise _refuse(f'Channel {channel} {what} is not a bounded string')
    if CONTROL_CHARACTER.search(value):
        raise _refuse(f'Channel {channel} {what} holds an ASCII control character')
    return value


def _secret_value(value: Any, what: str, channel: str) -> str:
    """Return one mounted credential about to become a header value or a body secret, or refuse it."""
    if not isinstance(value, str) or not OPAQUE_TOKEN.fullmatch(value):
        raise _refuse(f'Channel {channel} {what} is not a bounded opaque credential')
    return value


def attempt_cause(outcome: str) -> str:
    """Return the bounded `notification_attempts.cause` word one outcome maps to.

    Raises:
        StateError: *outcome* is not one of the three. A transport that invented a fourth word would
            otherwise be recorded as a failure class the column does not offer.
    """
    cause = ATTEMPT_CAUSE.get(outcome)
    if cause is None:
        raise StateError('Unknown delivery outcome')
    return cause


def _layers(error: BaseException) -> list[BaseException]:
    """Return *error* and the causes wrapped inside it, to a bounded depth.

    `urllib` wraps a socket timeout in `URLError` and `http.py` wraps that in `TransportError`, so the
    class that says *why* is two objects down; this walks `__cause__` and a `reason` attribute (which is
    where `URLError` keeps it) without ever reading a message, and stops at five layers rather than
    trusting an exception chain to be short.
    """
    seen: list[BaseException] = []
    layer: BaseException | None = error
    for _ in range(5):
        if layer is None:
            break
        seen.append(layer)
        nested = getattr(layer, 'reason', None)
        layer = nested if isinstance(nested, BaseException) else layer.__cause__
    return seen


def network_reason(error: BaseException) -> str:
    """Return one bounded word for a transport failure, chosen from exception classes and never a message.

    `http.py` already strips the URL from anything it raises — a webhook's secret lives in its path and
    Telegram's in its request URL — so the class is the whole diagnosis available this side of the
    client. It is still enough to tell an operator "the hostname does not resolve" from "the provider is
    answering 502", which is exactly the half of the promise this module exists to keep.
    """
    layers = _layers(error)
    if any(isinstance(layer, TimeoutError) for layer in layers):
        return 'timeout'
    if any(isinstance(layer, ssl.SSLError) for layer in layers):
        return 'tls-handshake-failed'
    if any(type(layer).__name__ == 'gaierror' for layer in layers):
        return 'dns-lookup-failed'
    if any(isinstance(layer, ConnectionRefusedError) for layer in layers):
        return 'connection-refused'
    if any(isinstance(layer, ConnectionResetError) for layer in layers):
        return 'no-connection'
    if any(isinstance(layer, OSError) and layer.errno in (101, 113) for layer in layers):
        return 'network-unreachable'
    if any(isinstance(layer, OSError) for layer in layers):
        return 'no-connection'
    if any(isinstance(layer, TransportError) for layer in layers):
        return 'endpoint-unreachable'
    return 'protocol-failure'


@dataclass(frozen=True)
class Outcome:
    """What one transport call achieved: one of three words, an optional status, a bounded reason.

    Deliberately absent: a response body, an exception message, a URL, a credential.
    `state.ATTEMPT_CAUSES` is a closed vocabulary and `finish_notification` accepts only the mapped
    `cause` word, so this cannot become the place a provider's own text enters the durable record.
    """

    outcome: str
    status: int | None = None
    reason: str = ''

    def __post_init__(self) -> None:
        """Refuse an outcome word, a reason word or a status this build cannot express."""
        if self.outcome not in OUTCOMES:
            raise StateError('Unknown delivery outcome')
        if self.reason and self.reason not in OUTCOME_REASONS:
            raise StateError('Unknown delivery outcome reason')
        if self.status is not None and (type(self.status) is not int or not 100 <= self.status <= 599):
            raise StateError('Delivery outcome status is out of range')

    @property
    def cause(self) -> str:
        """The word this outcome becomes in `notification_attempts.cause`."""
        return attempt_cause(self.outcome)

    @property
    def accepted(self) -> bool:
        """True only for a delivery the provider took; a refusal and an outage are both False."""
        return self.outcome == OUTCOME_SENT


def http_outcome(status: int, proven: bool | None) -> Outcome:
    """Classify one HTTP answer into an `Outcome`, taking the channel's own 2xx receipt rule into account.

    ``proven`` is what the channel said about a 2xx body: True (it proved the message landed), False (it
    answered 2xx without proving it — the refusal-prone reading, the same one the generic webhook already
    applies by demanding a receipt that repeats the delivery id) or None (this provider offers no receipt
    at all, so a 2xx is the whole proof there is).

    4xx means *this message* was declined, which is `rejected`, with two named exceptions rather than a
    hidden table: 408 and 429 say "come back later", which is an outage in miniature and not a refusal of
    anything — charging those as refusals would walk a rate-limited channel to exhaustion over a message
    the provider never read.
    """
    if 200 <= status < 300:
        if proven is False:
            return Outcome(OUTCOME_REJECTED, status, 'unproven-receipt')
        return Outcome(OUTCOME_SENT, status)
    if status in (301, 302, 303, 305, 307, 308):
        # `http.NoRedirect` refuses to follow, so nothing was delivered; the message was also never
        # declined. `rejected` is the word that stops a retry storm sooner, and an endpoint that moved is
        # a configuration the operator must change rather than a provider to wait out.
        return Outcome(OUTCOME_REJECTED, status, 'redirect-refused')
    if status in (408, 429):
        return Outcome(OUTCOME_UNAVAILABLE, status, 'rate-limited' if status == 429 else 'timeout')
    if 400 <= status < 500:
        return Outcome(OUTCOME_REJECTED, status, 'http-refused')
    return Outcome(OUTCOME_UNAVAILABLE, status, 'http-server-error')


class Channel(abc.ABC):
    """One provider transport: callable exactly once per claim, unable to raise for a delivery failure.

    Subclasses implement `deliver`. `request` is the adapter that lets the existing delivery loop
    (`notifications.deliver_one`, which speaks ``client.request('POST', payload=…, headers=…)``) call a
    transport without inventing a second protocol: an `Outcome` becomes the loop's own two signals — a
    receipt repeating the delivery id, or a `TransportError` — so the classification of an attempt stays
    in the one place it already lived.
    """

    #: The channels-document `type` word this transport is built for.
    kind = ''

    def __init__(self, *, name: str = 'primary', index_path: str | None = None,
                 display_config: dict[str, Any] | None = None,
                 timeout: int = DEFAULT_TIMEOUT_SECONDS) -> None:
        """Bind the presentation metadata and the one bounded timeout every attempt uses.

        Raises:
            ChannelConfigError: The channel label is outside `state.label`'s bound, or the timeout is
                outside `TIMEOUT_BOUNDS`.
        """
        try:
            label(name)
        except StateError as exc:
            raise _refuse(f'Channel {name} is not a bounded label') from exc
        if type(timeout) is not int or not TIMEOUT_BOUNDS[0] <= timeout <= TIMEOUT_BOUNDS[1]:
            raise _refuse(f'Channel {name} timeout must be {TIMEOUT_BOUNDS[0]}..{TIMEOUT_BOUNDS[1]} seconds')
        self.name = name
        self.kind = self.kind or type(self).__name__.lower().removesuffix('channel')
        self._index_path = index_path
        self._display_config = display_config or {}
        self._timeout = timeout

    @abc.abstractmethod
    def deliver(self, payload: dict[str, Any], *, delivery_id: str,
                timeout: int | None = None) -> Outcome:
        """Attempt one delivery and return its `Outcome`. A delivery failure is never raised.

        Args:
            payload: The outbox row's payload, exactly as `claim_notification` returned it.
            delivery_id: The durable delivery id the receiver must dedupe on. Checked against
                ``payload['delivery_id']`` rather than trusted: a re-delivery after a crash carries the
                same id, and one that did not would defeat the dedupe this whole design rests on.
            timeout: A shorter bound for this one attempt; never longer than the transport's own.

        Raises:
            StateError: Only for a payload the platform should never have queued (a restricted event, an
                unknown transition, an identity mismatch) — a refusal to attempt the send at all, which
                `deliver_one` records as `policy`, and not a delivery outcome.
        """

    def request(self, method: str, *, payload: dict[str, Any],
                headers: dict[str, str] | None) -> tuple[int, dict[str, Any]]:
        """Adapt one delivery-loop call onto `deliver`, leaving the loop's cause vocabulary intact."""
        if method != 'POST':
            raise StateError('Only notification sends are supported')
        delivery_id = str(payload.get('delivery_id'))
        if (headers or {}).get('Idempotency-Key') != payload.get('delivery_id'):
            raise StateError('Notification identity mismatch')
        outcome = self.deliver(payload, delivery_id=delivery_id)
        if outcome.outcome == OUTCOME_UNAVAILABLE:
            log.warning('Notification transport could not be reached',
                        extra={'delivery_id': delivery_id, 'channel': self.name, 'outcome': outcome.outcome,
                               'reason': outcome.reason or 'unavailable'})
            raise TransportError('Notification channel is unavailable')
        if outcome.outcome == OUTCOME_REJECTED:
            log.warning('Notification transport refused the delivery',
                        extra={'delivery_id': delivery_id, 'channel': self.name, 'outcome': outcome.outcome,
                               'reason': outcome.reason or 'refused', 'status': outcome.status})
            return outcome.status or 400, {'accepted': False, 'delivery_id': delivery_id}
        return 202, {'accepted': True, 'delivery_id': delivery_id}

    # -- shared payload discipline ---------------------------------------------------------------

    def checked(self, payload: dict[str, Any], delivery_id: str) -> dict[str, Any]:
        """Return the event a send may be built from, refusing what must never leave.

        Mirrors `TelegramClient.request`: a restricted event reaches no provider from any channel, and a
        row whose identity does not parse is a platform defect rather than a delivery failure — which is
        why it raises instead of returning an `Outcome`.
        """
        if not isinstance(payload, dict) or payload.get('event', {}).get('data_class') == 'restricted':
            raise StateError('Only unrestricted notification sends are supported')
        try:
            if str(uuid.UUID(delivery_id)) != delivery_id or payload.get('delivery_id') != delivery_id:
                raise ValueError
            uuid.UUID(str(payload['incident_id']))
        except (ValueError, TypeError, KeyError):
            raise StateError('Notification identity mismatch') from None
        if payload.get('transition') not in ('opened', 'resolved'):
            raise StateError('Unknown notification transition')
        return payload['event']

    def message(self, payload: dict[str, Any], event: dict[str, Any]) -> tuple[str, str]:
        """Return ``(title, body)`` from bounded presentation metadata, never from raw telemetry.

        The labels are the ones `presentation.describe` already gives Telegram and the same bounds apply
        (`presentation.text` collapses whitespace and cuts at 160 characters), so adding a channel does
        not widen what leaves the platform. The single-use approval code is deliberately **not** printed
        here: `telegram.approval_line` exists for the one channel whose reader is one known phone, and a
        room, a mailing list or a shared pager inbox has more than one reader — printing an approval code
        to all of them would grant it to all of them. Whether any of these channels may carry one is an
        owner decision, recorded as such in the delivery channels report.
        """
        from .presentation import describe
        from .notification_text import human_text, notification_lines
        display = describe(event, self._index_path, self._display_config)
        config = {'channel_name': self.name, **self._display_config}
        title, *lines = notification_lines(payload, display, config)
        lines.append('Severity: ' + human_text(event.get('severity'), 'unknown'))
        return title, '\n'.join(lines[:MAX_BODY_LINES])

    def _limit(self, timeout: int | None) -> int:
        """Return the bounded timeout for one attempt: this call's or the transport's, never the longer."""
        if timeout is None:
            return self._timeout
        if type(timeout) is not int or timeout < 1:
            raise StateError('Invalid delivery timeout')
        return min(timeout, self._timeout)


class _JsonChannel(Channel):
    """The HTTP shape four transports share: one request, one status, one receipt rule of their own.

    `client` is the seam the tests inject; the default is a `JsonClient` built with the bounds every
    product endpoint already gets — HTTPS unless the operator opted into HTTP for an isolated network,
    no proxy, no redirect followed, one bounded timeout, and a response body read to a ceiling and then
    handed to the channel's own receipt rule.
    """

    #: Whether a 2xx answer carries something this channel can check. False means the provider gives no
    #: receipt (Slack's `ok` text), so the status alone is the whole proof it offers.
    PROVES_RECEIPT = True

    def __init__(self, *, client: Any = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._client = client

    def client(self) -> Any:
        """Return the client, constructing it on first use so injection stays optional."""
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> Any:
        raise NotImplementedError

    def _envelope(self, payload: dict[str, Any], event: dict[str, Any], delivery_id: str,
                  title: str, body: str) -> tuple[str, str, Any, dict[str, str]]:
        """Return ``(method, path, document, headers)`` for one attempt. The loop's `Idempotency-Key`
        header is added by `deliver`, so no channel can drop the dedupe field."""
        raise NotImplementedError

    def receipt(self, answer: Any) -> bool:
        """Say whether a parsed 2xx body proves the message landed."""
        raise NotImplementedError

    def deliver(self, payload: dict[str, Any], *, delivery_id: str,
                timeout: int | None = None) -> Outcome:
        """Attempt one send and name which of the three things happened. Nothing escapes but `StateError`."""
        event = self.checked(payload, delivery_id)
        title, body = self.message(payload, event)
        try:
            method, path, document, headers = self._envelope(payload, event, delivery_id, title, body)
            status, answer = self.client().request(method, path, document,
                                                   headers={**headers, 'Idempotency-Key': delivery_id},
                                                   timeout=self._limit(timeout))
        except StateError:
            # The platform's own refusal, and the only exception a transport may raise: the identity and
            # data-class checks above run before any socket is touched.
            raise
        except (OSError, ValueError) as exc:
            # `JsonClient` returns a status for every answer it received, so anything raising here is a
            # request that never got one: DNS, connect, TLS, a timeout, or a body that was not JSON.
            return Outcome(OUTCOME_UNAVAILABLE, reason=network_reason(exc))
        except Exception as exc:
            # No exception may escape a transport: durable delivery state depends on a classified result.
            # an exception that reached `deliver_one` would skip `finish_notification` and leave the
            # outbox row leased until the lease ages out, with no attempt row saying what happened. So an
            # unexpected failure is recorded as "could not be reached" — the refusal-prone answer, which
            # never claims a delivery that did not happen — and its class is logged, never its message,
            # because a library message is where a URL or a credential would be.
            log.warning('Notification transport failed unexpectedly',
                        extra={'delivery_id': delivery_id, 'channel': self.name,
                               'error_class': type(exc).__name__})
            return Outcome(OUTCOME_UNAVAILABLE, reason='protocol-failure')
        proven = self.receipt(answer) if (self.PROVES_RECEIPT and 200 <= status < 300) else None
        return http_outcome(status, proven)


class NtfyChannel(_JsonChannel):
    """ntfy.sh-compatible publish: title and message in the JSON body, never in a header.

    v0.1's reason, kept as behaviour (`legacy:notifiers/ntfy.py`): urllib encodes header values as latin-1,
    so a `Title:` header holding an emoji or a CJK description raises inside the send. Posting the
    document to the server root with the topic in the body carries any text the presentation layer can
    produce — `http.canonical` additionally escapes to ASCII, which is the same protection seen from the
    other end. The only header built from configuration is `Authorization`, whose value is a bounded
    opaque token, refused at the read if it holds any control character.

    The delivery id rides the ``Idempotency-Key`` header. ntfy's own publish-id field is a 12-character
    base62 string, so a UUID does not fit it and a server that cannot use it would ignore it silently;
    the receiver that has to dedupe is ours or a bridge's, and it reads the header.
    """

    def __init__(self, url: str, topic: str, token: str | None = None, *,
                 allow_http: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._url = _field(url, 512, 'url', self.name)
        self._topic = _field(topic, 64, 'topic', self.name)
        if not TOPIC.fullmatch(self._topic):
            raise _refuse(f'Channel {self.name} topic is not a bounded ntfy topic')
        self._token = None if token is None else _secret_value(token, 'token', self.name)
        self._allow_http = allow_http is True

    def _build_client(self) -> JsonClient:
        return JsonClient(self._url, self._token, allow_http=self._allow_http, timeout=self._timeout)

    def _envelope(self, payload: dict[str, Any], event: dict[str, Any], delivery_id: str,
                  title: str, body: str) -> tuple[str, str, Any, dict[str, str]]:
        document = {'topic': self._topic, 'title': title, 'message': body,
                    'priority': NTFY_PRIORITY.get(str(event.get('severity')), NTFY_PRIORITY_DEFAULT)}
        headers = {} if self._token is None else {'Authorization': 'Bearer ' + self._token}
        return 'POST', '', document, headers

    def receipt(self, answer: Any) -> bool:
        """ntfy answers a published message with an id of its own; anything else proved nothing."""
        return isinstance(answer, dict) and isinstance(answer.get('id'), str) and bool(answer.get('id'))


class SlackChannel(_JsonChannel):
    """Slack incoming webhook: v0.1's Block Kit body, and a URL that *is* the credential.

    Kept from `legacy:notifiers/slack.py`: header block = title, section = body, context = severity, plus a
    top-level ``text`` for clients that ignore blocks. Changed: the endpoint arrives as a mounted file,
    because an incoming-webhook URL carries its secret in its path — which is why it is not a document
    field and never an environment value, the same reasoning `check_foundation.py`'s credential rule
    applies to a `*_TOKEN`.

    Slack answers a successful post with the plain text ``ok`` rather than JSON, so its client uses
    `JsonClient`'s documented `accept_non_json` option and `PROVES_RECEIPT` is False: a 2xx is the whole
    proof that provider offers.
    """

    PROVES_RECEIPT = False
    WEBHOOK_ORIGIN = re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{10,256}\Z')

    def __init__(self, url: str, *, allow_http: bool = False, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._url = _field(url, 512, 'url', self.name)
        if not self.WEBHOOK_ORIGIN.fullmatch(self._url) and allow_http is not True:
            raise _refuse(f'Channel {self.name} slack url is not an accepted webhook origin')
        self._allow_http = allow_http is True

    def _build_client(self) -> JsonClient:
        return JsonClient(self._url, None, allow_http=self._allow_http, timeout=self._timeout,
                          accept_non_json=True)

    def _envelope(self, payload: dict[str, Any], event: dict[str, Any], delivery_id: str,
                  title: str, body: str) -> tuple[str, str, Any, dict[str, str]]:
        severity = str(event.get('severity'))
        document = {'text': '[' + severity + '] ' + title,
                    'blocks': [{'type': 'header', 'text': {'type': 'plain_text', 'text': title,
                                                           'emoji': True}},
                               {'type': 'section', 'text': {'type': 'mrkdwn', 'text': body}},
                               {'type': 'context', 'elements': [{'type': 'mrkdwn',
                                                                  'text': 'severity: ' + severity}]}]}
        return 'POST', '', document, {}

    def receipt(self, answer: Any) -> bool:
        """Not consulted: this provider offers no receipt. Present to satisfy the base contract."""
        return True


class MatrixChannel(_JsonChannel):
    """Matrix client-server send, where the transaction id in the path *is* the receiver's dedupe key.

    `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}`, both ids percent-encoded
    (v0.1's shape, `legacy:notifiers/matrix.py`). What changed: v0.1 generated a fresh uuid4 per **call**, so
    a retry after a crash published the alert a second time. Here the transaction id is the outbox
    delivery id, so the homeserver's own idempotency rule collapses every re-delivery of one row into one
    room event — the clearest case in this port of "the delivery id goes on the wire".
    """

    def __init__(self, homeserver: str, room_id: str, token: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._homeserver = _field(homeserver, 512, 'url', self.name)
        self._room_id = _field(room_id, 256, 'room_id', self.name)
        if not ROOM_ID.fullmatch(self._room_id):
            raise _refuse(f'Channel {self.name} room_id is not a bounded Matrix room id')
        self._token = _secret_value(token, 'token', self.name)

    def _build_client(self) -> JsonClient:
        return JsonClient(self._homeserver, self._token, timeout=self._timeout)

    def _envelope(self, payload: dict[str, Any], event: dict[str, Any], delivery_id: str,
                  title: str, body: str) -> tuple[str, str, Any, dict[str, str]]:
        path = ('/_matrix/client/v3/rooms/' + urllib.parse.quote(self._room_id, safe='')
                + '/send/m.room.message/' + urllib.parse.quote(delivery_id, safe=''))
        document = {'msgtype': 'm.text',
                    'body': '[' + str(event.get('severity')) + '] ' + title + '\n' + body}
        return 'PUT', path, document, {}

    def receipt(self, answer: Any) -> bool:
        """The homeserver names the event it created; without that the send is not proven."""
        event_id = answer.get('event_id') if isinstance(answer, dict) else None
        return isinstance(event_id, str) and bool(event_id)


class PagerDutyChannel(_JsonChannel):
    """PagerDuty Events v2: the routing key is a body secret from a mounted file, never a header.

    v0.1 put `routing_key` in the body (`legacy:notifiers/pagerduty.py`) and that stays — the key is not a
    bearer token and belongs nowhere a proxy log copies. Its severity ladder is a superset of this
    product's, so an admitted severity passes through unchanged and anything else takes the middle rung
    (`PAGERDUTY_FALLBACK_SEVERITY`) rather than the loudest one.

    `dedup_key` is the delivery id. v0.1 copied a `dedup_key` *label* up to the top level; this repo's
    ruling on name-derived dedup identity is in `vocabulary.py` ("`dedup_key` has no home here,
    deliberately"), and the durable thing that groups verdicts into one incident is the condition key in
    `state.py`. So the only dedup a transport may assert is *this delivery* — which is precisely what
    must not be duplicated when a lease expires and the row is sent again.

    Every page is sent as ``event_action: trigger``, including a recovery, exactly as v0.1 does. Mapping
    ``resolved`` onto PagerDuty's own `resolve` action needs a stable incident-level key that outlives one
    delivery row; that is an incident-lifecycle decision for the owner, not a transport's choice, and it
    is named in the delivery channels report rather than invented here.
    """

    def __init__(self, routing_key: str, source: str = 'local-observe',
                 url: str = PAGERDUTY_EVENTS_URL, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._routing_key = _secret_value(routing_key, 'routing_key', self.name)
        self._source = _field(source, 128, 'source', self.name)
        self._url = _field(url, 512, 'url', self.name)

    def _build_client(self) -> JsonClient:
        parsed = urllib.parse.urlsplit(self._url)
        return JsonClient(parsed.scheme + '://' + parsed.netloc, None, timeout=self._timeout)

    def _envelope(self, payload: dict[str, Any], event: dict[str, Any], delivery_id: str,
                  title: str, body: str) -> tuple[str, str, Any, dict[str, str]]:
        path = urllib.parse.urlsplit(self._url).path or '/v2/enqueue'
        declared = str(event.get('severity'))
        severity = declared if declared in PAGERDUTY_SEVERITIES else PAGERDUTY_FALLBACK_SEVERITY
        document: dict[str, Any] = {'event_action': 'trigger', 'dedup_key': delivery_id,
                                    'payload': {'summary': title, 'source': self._source,
                                                'severity': severity,
                                                'custom_details': {'message': body,
                                                                   'delivery_id': delivery_id}}}
        return 'POST', path, document, {}

    def receipt(self, answer: Any) -> bool:
        """Events v2 answers ``{"status":"success", …}``; a rejected event arrives as a 400 instead."""
        return isinstance(answer, dict) and answer.get('status') == 'success'


class EmailChannel(Channel):
    """SMTP delivery from v0.1's channel (`legacy:notifiers/email.py`, 71 lines), with the outbox's taxonomy.

    Kept: the ``[SEVERITY] title`` subject, the injected session factory so no test opens a socket, and
    injection-proof addresses (v0.1's CR/LF refusal, widened to the product's control-character rule —
    see `_field`). Replaced: v0.1 raised one `RuntimeError` for a dead relay and a refused recipient
    alike, losing the rejection-versus-unavailability distinction this module requires. SMTP's own
    reply codes decide here: **5xx is `rejected`** (this message was declined — bad credentials, a
    refused sender or recipient) and **4xx is `unavailable`** (the server answered and said "later"), the
    same reading `http_outcome` applies to an HTTP status.

    The dedupe field is the ``Message-ID``: one delivery
    id across a crash means a client that has already filed this alert files the re-delivery in the same
    thread instead of showing a second copy.

    A credential is never offered to a relay that has not upgraded to TLS, and `starttls` cannot be
    switched off on a channel that has a password: an authenticated login in clear text is that
    credential on the wire to anything listening between here and the relay.
    """

    def __init__(self, host: str, port: int, sender: str, recipients: list[str],
                 username: str | None = None, password: str | None = None, *,
                 starttls: bool = True, smtp_factory: Callable[..., Any] | None = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._host = _field(host, 253, 'host', self.name)
        if type(port) is not int or not 1 <= port <= 65535:
            raise _refuse(f'Channel {self.name} port is not a bounded port')
        self._port = port
        self._sender = _field(sender, 254, 'from', self.name)
        if not ADDRESS.fullmatch(self._sender):
            raise _refuse(f'Channel {self.name} from is not a bounded address')
        if not isinstance(recipients, (list, tuple)) or not 1 <= len(recipients) <= 10:
            raise _refuse(f'Channel {self.name} needs 1..10 recipients')
        self._recipients = []
        for address in recipients:
            value = _field(address, 254, 'recipient', self.name)
            if not ADDRESS.fullmatch(value):
                raise _refuse(f'Channel {self.name} recipient is not a bounded address')
            self._recipients.append(value)
        if password is not None:
            self._password = _secret_value(password, 'password', self.name)
            if not username:
                raise _refuse(f'Channel {self.name} has a password and no username')
            if starttls is not True:
                raise _refuse(f'Channel {self.name} may not send a credential without STARTTLS')
        else:
            self._password = None
        self._username = None if username is None else _field(username, 256, 'username', self.name)
        self._starttls = starttls is True
        self._smtp_factory = smtp_factory or _default_smtp_factory

    def deliver(self, payload: dict[str, Any], *, delivery_id: str,
                timeout: int | None = None) -> Outcome:
        """Send one message and classify the answer by its SMTP reply code. No socket in a test."""
        from email.message import EmailMessage
        event = self.checked(payload, delivery_id)
        title, body = self.message(payload, event)
        message = EmailMessage()
        message['From'] = self._sender
        message['To'] = ', '.join(self._recipients)
        message['Subject'] = '[' + str(event.get('severity')).upper() + '] ' + title
        message['Message-ID'] = '<' + delivery_id + '@' + _message_id_domain(self._sender) + '>'
        message.set_content(body)
        refused: dict[str, tuple[int, str]] = {}
        try:
            with self._smtp_factory(self._host, self._port, self._limit(timeout)) as session:
                session.ehlo()
                if self._starttls:
                    session.starttls(context=ssl.create_default_context())
                    session.ehlo()
                if self._username is not None:
                    session.login(self._username, self._password or '')
                refused = session.send_message(message, from_addr=self._sender,
                                               to_addrs=self._recipients) or {}
        except StateError:
            raise
        except smtplib.SMTPAuthenticationError:
            # Named before `SMTPResponseException`, whose generic handler would otherwise read a 535 as an
            # unspecified 5xx: "the credentials are wrong" is the one answer an operator can act on.
            return Outcome(OUTCOME_REJECTED, 535, 'auth-refused')
        except smtplib.SMTPSenderRefused:
            return Outcome(OUTCOME_REJECTED, 553, 'sender-refused')
        except smtplib.SMTPRecipientsRefused:
            return Outcome(OUTCOME_REJECTED, 550, 'recipient-refused')
        except smtplib.SMTPResponseException as exc:
            # Only the code is read. A reply line is provider text and could carry anything.
            low = exc.smtp_code < 500
            return Outcome(OUTCOME_UNAVAILABLE if low else OUTCOME_REJECTED, exc.smtp_code,
                           'temporary-server-failure' if low else 'server-failure')
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError):
            # `smtplib`'s own "there is no server here" answers. They are not `OSError`s, so the class
            # walk in `network_reason` cannot see them and would call them a protocol failure.
            return Outcome(OUTCOME_UNAVAILABLE, reason='no-connection')
        except OSError as exc:
            # A socket timeout, a refused connect or a DNS failure reaching us through `smtplib`.
            return Outcome(OUTCOME_UNAVAILABLE, reason=network_reason(exc))
        except smtplib.SMTPException:
            # A reply this build cannot parse is not a refusal of the message; nothing proved it landed.
            return Outcome(OUTCOME_UNAVAILABLE, reason='protocol-failure')
        except Exception as exc:
            # Same rule as the HTTP transports: an escaping exception would leave the row leased and the
            # attempt unrecorded, so the class is logged and the answer is the refusal-prone one.
            log.warning('Notification transport failed unexpectedly',
                        extra={'delivery_id': delivery_id, 'channel': self.name,
                               'error_class': type(exc).__name__})
            return Outcome(OUTCOME_UNAVAILABLE, reason='protocol-failure')
        if refused:
            # Some recipients refused while others accepted: the alert reached a mailbox, so it was
            # delivered, and resending would page the people who already have it. The count goes to the
            # log (never the addresses) because a partial refusal is a configuration fact, not a failure.
            log.warning('Notification transport had some recipients refused',
                        extra={'delivery_id': delivery_id, 'channel': self.name, 'refused': len(refused)})
        return Outcome(OUTCOME_SENT)


def _message_id_domain(sender: str) -> str:
    """Return the domain half of the `Message-ID`: the sender's own, or the reserved fallback."""
    domain = sender.rsplit('@', 1)[-1] if '@' in sender else ''
    return domain if domain and not CONTROL_CHARACTER.search(domain) else MESSAGE_ID_FALLBACK


def _default_smtp_factory(host: str, port: int, timeout: int) -> smtplib.SMTP:
    """Open one bounded SMTP session. No test reaches it: every case injects a recorder."""
    return smtplib.SMTP(host, port, timeout=timeout)


#: The keys each transport type may name, so a field belonging to another channel is a refusal and not an
#: ignored typo — an entry that silently configured nothing would be a send the operator believes exists.
ENTRY_KEYS: dict[str, frozenset[str]] = {
    'ntfy': frozenset({'channel', 'type', 'url', 'topic', 'token_file', 'allow_http', 'policy'}),
    'email': frozenset({'channel', 'type', 'host', 'port', 'from', 'recipients_file', 'username',
                        'password_file', 'starttls', 'policy'}),
    'slack': frozenset({'channel', 'type', 'url_file', 'allow_http', 'policy'}),
    'matrix': frozenset({'channel', 'type', 'url', 'room_id', 'token_file', 'policy'}),
    'pagerduty': frozenset({'channel', 'type', 'key_file', 'url', 'source', 'policy'}),
}
#: The keys each transport type must name, whatever else it carries.
ENTRY_REQUIRED: dict[str, frozenset[str]] = {
    'ntfy': frozenset({'url', 'topic'}),
    'email': frozenset({'host', 'port', 'from', 'recipients_file'}),
    'slack': frozenset({'url_file'}),
    'matrix': frozenset({'url', 'room_id', 'token_file'}),
    'pagerduty': frozenset({'key_file'}),
}


def build_transport(entry: dict[str, Any], name: str, *, secret: Callable[[str, str, str], str],
                    index_path: str | None = None,
                    display_config: dict[str, Any] | None = None) -> Channel:
    """Construct one configured transport, or refuse the entry by channel name and key.

    Args:
        entry: One channels-document entry; its ``type`` names the transport.
        name: The channel label the store books this transport's budget and breaker under.
        secret: The caller's one credential reader — given a path, the channel it belongs to and the
            entry key it sits under, it returns the bounded value inside or raises
            `ChannelConfigError`. Every credential this module holds arrives through it, which is what
            keeps `local_observe/credentials.py` the only place a file is read as a secret and is why no
            new `*_TOKEN` environment value exists for a channel.
        index_path: Inventory index a message may be labelled from.
        display_config: Presentation metadata, as for the two existing channels.

    Raises:
        ChannelConfigError: The entry names an unknown type, misses a required key, names a key that type
            does not use, or holds a value that cannot become a header, a URL or an SMTP argument. No
            message quotes a credential, an endpoint path or a file's contents.
    """
    kind = entry.get('type')
    if kind not in TRANSPORT_TYPES:
        raise _refuse(f'Channel {name} names an unsupported type')
    allowed = ENTRY_KEYS[str(kind)]
    if not allowed.issuperset(entry):
        raise _refuse(f'Channel {name} of type {kind} names unknown keys: '
                      + ', '.join(sorted(set(entry) - allowed)))
    if not ENTRY_REQUIRED[str(kind)].issubset(entry):
        raise _refuse(f'Channel {name} of type {kind} is missing: '
                      + ', '.join(sorted(ENTRY_REQUIRED[str(kind)] - set(entry))))
    common = {'name': name, 'index_path': index_path, 'display_config': display_config}
    if kind == 'ntfy':
        token = None if 'token_file' not in entry else secret(str(entry['token_file']), name, 'token_file')
        return NtfyChannel(str(entry['url']), str(entry['topic']), token,
                           allow_http=_opt_in(entry, name), **common)
    if kind == 'slack':
        # The whole webhook URL is the credential, so it arrives as a file and never as a document field.
        return SlackChannel(secret(str(entry['url_file']), name, 'url_file'),
                            allow_http=_opt_in(entry, name), **common)
    if kind == 'matrix':
        return MatrixChannel(str(entry['url']), str(entry['room_id']),
                             secret(str(entry['token_file']), name, 'token_file'), **common)
    if kind == 'pagerduty':
        return PagerDutyChannel(secret(str(entry['key_file']), name, 'key_file'),
                                str(entry.get('source', 'local-observe')),
                                str(entry.get('url', PAGERDUTY_EVENTS_URL)), **common)
    password = None if 'password_file' not in entry else secret(str(entry['password_file']), name,
                                                                'password_file')
    if 'username' in entry and not isinstance(entry['username'], str):
        raise _refuse(f'Channel {name} username is not a bounded string')
    starttls = entry.get('starttls', True)
    if starttls not in (False, True):
        raise _refuse(f'Channel {name} starttls must be a boolean')
    return EmailChannel(str(entry['host']), entry['port'], str(entry['from']),
                        _addresses(str(entry['recipients_file']), name), entry.get('username'),
                        password, starttls=starttls, **common)


def _opt_in(entry: dict[str, Any], name: str) -> bool:
    """Return the isolated-network HTTP opt-in, refusing anything that is not exactly a boolean."""
    allowed = entry.get('allow_http', False)
    if allowed not in (False, True):
        raise _refuse(f'Channel {name} allow_http must be a boolean')
    return allowed is True


def _addresses(path: str, channel: str) -> list[str]:
    """Read one mounted recipient list: at most `MAX_CREDENTIAL_BYTES`, one bounded address per line.

    A recipient list is configuration rather than a secret, so it is not read *as* a credential — but it
    is read with the same byte bound and the same character rule, because each line becomes an SMTP
    protocol argument the moment it is sent, and because a silently dropped recipient is an operator who
    believes someone else was paged.
    """
    candidate = Path(path)
    if candidate.is_dir():
        raise _refuse(f'Channel {channel} recipients_file is a directory')
    try:
        with candidate.open('rb') as stream:
            raw = stream.read(MAX_CREDENTIAL_BYTES + 1)
    except OSError as exc:
        raise _refuse(f'Channel {channel} recipients_file cannot be read ({type(exc).__name__})') from exc
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise _refuse(f'Channel {channel} recipients_file exceeds {MAX_CREDENTIAL_BYTES} bytes')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise _refuse(f'Channel {channel} recipients_file is not UTF-8 text') from exc
    lines = [line.strip(' \t') for line in text.split('\n') if line.strip(' \t')]
    if not 1 <= len(lines) <= 10:
        raise _refuse(f'Channel {channel} recipients_file must name 1..10 addresses')
    for line in lines:
        # Only spaces and tabs were removed above, so a CRLF-authored file still carries its `\r` here and
        # is refused exactly as `read_credential` refuses the same file as a credential. Tolerating it on
        # one path and refusing it on the other would be two answers about one file.
        if CONTROL_CHARACTER.search(line) or not ADDRESS.fullmatch(line):
            raise _refuse(f'Channel {channel} recipients_file holds an address that is not bounded')
    return lines


__all__ = ['ATTEMPT_CAUSE', 'Channel', 'ChannelConfigError', 'EmailChannel', 'ENTRY_KEYS',
           'ENTRY_REQUIRED', 'MatrixChannel', 'NTFY_PRIORITY', 'OUTCOMES', 'OUTCOME_REJECTED',
           'OUTCOME_SENT', 'OUTCOME_UNAVAILABLE', 'Outcome', 'PAGERDUTY_SEVERITIES',
           'PagerDutyChannel', 'SlackChannel', 'NtfyChannel', 'TRANSPORT_TYPES', 'attempt_cause',
           'build_transport', 'http_outcome', 'network_reason']

"""At-least-once delivery; receiver must deduplicate the stable delivery ID.

Three things live here besides the delivery loop. `build_channels` turns one operator document into the
{channel: client} and {channel: NotificationPolicy} mappings a store routes against, so "channel
adapters" is plural in the running process and not only in the schema (ledger notifications); the seven types it
now accepts are two of its own (`telegram`, `webhook`) and the five the port plan's `notifiers` row
supplies (delivery channels), which are constructed in `channels.py` and arrive already unable to report a refusal
and an outage as one thing; and `deliver_one` classifies each attempt as `accepted`, `rejected`,
`transport` or `policy` before the state module records it, which is what lets an operator tell "the
provider was unreachable" from "the provider refused this message" after the fact. The classification is
a bounded word from `state.ATTEMPT_CAUSES` and never a response body, a URL or a credential: the
redaction rule that `telegram.py` exists to enforce stays exactly as strong as it was.
"""
import datetime as dt
from collections.abc import Mapping
import json
from pathlib import Path
import re
from typing import Any

from local_observe.credentials import FILE_SUFFIX, read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.log import get_logger
from .channels import TRANSPORT_TYPES, Channel, ChannelConfigError, build_transport
from .notification_safety import NotificationPolicy
from .state import StateError, Store, label
from .telegram import TelegramClient

log = get_logger(__name__)

#: The JSON keys one channel entry may hold. Anything else is a refusal, not an ignored field: a typo
#: in a channel definition that silently did nothing would leave the operator believing a channel was
#: configured when nothing was constructed for it. `channels.ENTRY_KEYS` narrows this set per type, so an
#: `email` entry that names a Matrix room is refused rather than quietly ignored.
CHANNEL_KEYS = frozenset({'channel', 'type', 'config', 'url', 'token_file', 'allow_http', 'policy',
                          'topic', 'url_file', 'key_file', 'source', 'host', 'port', 'from', 'room_id',
                          'recipients_file', 'username', 'password_file', 'starttls'})
CHANNEL_TYPES = ('telegram', 'webhook') + TRANSPORT_TYPES
#: The two keys every channel entry must name, whatever its type. A missing one is a refusal: there is
#: no sensible channel to guess when either the name to book the budget under or the adapter to build is
#: absent, and a channel silently skipped would be a send the operator believes is configured.
CHANNEL_KEYS_REQUIRED = frozenset({'channel', 'type'})
#: Channel labels a delivery may never be routed to, because `deliver_one` reads these two words as
#: "replace the client with a local sink". Naming a channel after a sink would be a way to make a live
#: send vanish into a receipt without declaring `recording` mode.
RESERVED_CHANNEL_LABELS = ('synthetic-sink', 'recording-sink')
# A credential file a channel names is opened under the same byte bound and the same control-character
# rule `local_observe/credentials.py` applies to every mounted credential, so an oversized, empty or
# CRLF-authored file is refused here rather than sent as a header value on the first request.


def _refuse(detail: str) -> ChannelConfigError:
    """Log one bounded configuration refusal and return it for the caller to raise.

    Built as a function rather than a bare `raise` so the warning and the exception can never disagree:
    the operator who fixes the document should find the same sentence in the log that the boot printed,
    and both name the channel and the key and neither a credential nor an endpoint path.
    """
    log.warning('Notification channel configuration refused', extra={'reason': detail})
    return ChannelConfigError(detail)


def _mounted_secret(path: Any, channel: str, key: str) -> str:
    """Read one channel credential file through `local_observe.credentials`, the product's only reader.

    The name handed to `read_credential` is a **label for the refusal**, not a variable this process
    consults: the path is passed in `environ` explicitly, so nothing here ever reads the real environment
    and no `*_TOKEN` value exists anywhere in this feature. That is one step stricter than the `*_FILE`
    rule the rest of the product follows — the path is not even in the environment — and it is why
    `scripts/check_foundation.py`'s `check_credential_files` needs no exception for a channel and must
    keep needing none.

    What the file is allowed to be is exactly what every other mounted credential is allowed to be: at
    most `MAX_CREDENTIAL_BYTES`, UTF-8, one optional trailing newline, never empty, and never holding an
    ASCII control character. The CRLF refusal is load-bearing for these transports rather than tidiness:
    a value with a newline in it is a second header line to `Authorization`, and `http.JsonClient` would
    refuse it only at the first request, far from the file that caused it.
    """
    if not isinstance(path, str) or not path:
        raise _refuse(f'Channel {channel} names no {key}')
    if Path(path).is_dir():
        # Named before the read: `read_credential` reports a directory too, and this says which entry key
        # pointed at it, which is the half the operator has to edit.
        raise _refuse(f'Channel {channel} {key} is a directory')
    variable = 'CHANNEL_' + channel.replace('.', '_').replace('-', '_').replace(':', '_').upper() + '_' \
        + key[:-len('_file')].upper()
    try:
        return read_credential(variable, environ={variable + FILE_SUFFIX: path})
    except OSError as exc:
        # `OSError`'s message is the path and the syscall; neither belongs in a refusal. The class name is
        # the whole diagnosis that is safe to print.
        raise _refuse(f'Channel {channel} {variable.lower()} cannot be read ({type(exc).__name__})') from exc
    except (ValueError, KeyError) as exc:
        # Every sentence `read_credential` raises names the variable and, for a control character, the
        # code point — never the value and never the path — so it is safe to repeat verbatim.
        raise _refuse(str(exc)) from exc


def _channel_token(entry: dict[str, Any], name: str) -> str:
    """Return the bearer token one webhook entry names, read as a bounded opaque value.

    The credential arrives as a file whose path sits in a mounted JSON document; only the byte bound and
    the control-character rule the product credential reader applies are re-applied here, and every
    message names the channel and the key.
    """
    return _mounted_secret(entry.get('token_file'), name, 'token_file')


def _channel_policy(entry: dict[str, Any], name: str, mode: str) -> NotificationPolicy:
    """Build one channel's budget policy, with the service's delivery mode and the channel's own name.

    A channel may tune `max_attempts`, `window_seconds`, `max_event_age_seconds`, `synthetic_sources`
    and `test_window`; it may not choose its own name or its own delivery mode. Mode is one decision
    for the whole service (it is what `start_notification_mode` records and what gates a live start), so
    a channel that declared a different one would be a second, quieter answer to the question the
    operator already answered.
    """
    declared = dict(entry.get('policy') or {})
    if declared.get('delivery_mode', mode) != mode:
        raise _refuse(f'Channel {name} declares a delivery mode differing from the service')
    declared.pop('delivery_mode', None)
    if 'channel' in declared:
        raise _refuse(f'Channel {name} names a channel inside its own policy')
    try:
        return NotificationPolicy(**dict(declared, channel=name, delivery_mode=mode))
    except (StateError, TypeError) as exc:
        raise _refuse(f'Channel {name} policy is invalid ({type(exc).__name__})') from exc


def build_channels(document: Any, *, mode: str, index_path: str | None = None,
                   display_config: dict[str, Any] | None = None) -> tuple[dict[str, Any],
                                                                          dict[str, NotificationPolicy]]:
    """Construct the configured notification channels from one operator document.

    Args:
        document: A list of channel entries in the operator's preference order. Each entry is
            ``{"channel": <label>, "type": <word>, ...}`` where `type` is one of `CHANNEL_TYPES`:
            `telegram` adds ``"config": <path to the {token, chat_id} file already used by
            LO_TELEGRAM_CONFIG>``, `webhook` adds ``"url"`` plus ``"token_file"``, and the five transports
            `channels.py` ports add what their own `ENTRY_KEYS` row names (`ntfy` a `url` and a `topic`,
            `slack` a `url_file` whose contents *are* the webhook URL, `matrix` a `url`, a `room_id` and a
            `token_file`, `pagerduty` a `key_file`, `email` a relay `host`/`port`, a `from`, a
            `recipients_file` and optionally a `username`/`password_file`). Every one of them is a path to
            a mounted file, never a credential value; ``"allow_http": true`` is the isolated-network
            opt-in `JsonClient` itself adjudicates. An optional ``"policy"`` object tunes that channel's
            send budget, window, event age, synthetic sources and test window.
        mode: The service's delivery mode, forced onto every channel policy.
        index_path: Inventory index the adapters may label a message with.
        display_config: Presentation metadata, as for the single-channel path.

    Returns:
        ``({channel: client}, {channel: NotificationPolicy})`` in document order. `deliver_one` picks
        the client by the channel the store routed the row to.

    Raises:
        ChannelConfigError: The document is not a non-empty list of valid, distinct, fully-named
            entries. No credential value, endpoint credential or response ever appears in a message.
    """
    if not isinstance(document, list) or not document:
        raise _refuse('Notification channels must be a non-empty list')
    clients: dict[str, Any] = {}
    policies: dict[str, NotificationPolicy] = {}
    for position, entry in enumerate(document):
        if not isinstance(entry, dict) or not CHANNEL_KEYS_REQUIRED <= set(entry) or not set(entry) <= CHANNEL_KEYS:
            raise _refuse(f'Channel entry {position} is not an object holding exactly the known keys')
        name = entry['channel']
        try:
            label(name)
        except StateError as exc:
            raise _refuse(f'Channel entry {position} names an unbounded channel') from exc
        if name in RESERVED_CHANNEL_LABELS:
            raise _refuse(f'Channel {name} is a reserved sink name')
        if name in clients:
            raise _refuse(f'Channel {name} is configured twice')
        kind = entry['type']
        if kind not in CHANNEL_TYPES:
            raise _refuse(f'Channel {name} names an unsupported type')
        if kind == 'telegram':
            config = entry.get('config')
            if not isinstance(config, str) or not config or 'url' in entry or 'token_file' in entry:
                raise _refuse(f'Channel {name} must name exactly a telegram config file')
            try:
                secret = json.loads(Path(config).read_text(encoding='utf-8'))
                client: Any = TelegramClient(secret['token'], secret['chat_id'],
                                             index_path=index_path, display_config=display_config or {})
            except (OSError, ValueError, KeyError, TypeError) as exc:
                # TelegramClient validates the token shape and raises ValueError; neither that message
                # nor the file contents is echoed, because the credential rides in the URL it builds.
                raise _refuse(f'Channel {name} telegram config is unusable ({type(exc).__name__})') from exc
        elif kind == 'webhook':
            url = entry.get('url')
            if not isinstance(url, str) or not url or 'config' in entry:
                raise _refuse(f'Channel {name} must name exactly a webhook url')
            if not re.fullmatch(r'https://[^\s]+', url) and entry.get('allow_http') is not True:
                raise _refuse(f'Channel {name} webhook url is not HTTPS')
            allow_http = entry.get('allow_http', False)
            if allow_http not in (False, True):
                raise _refuse(f'Channel {name} allow_http must be a boolean')
            try:
                client = JsonClient(url, _channel_token(entry, name), allow_http=allow_http is True)
            except TransportError as exc:
                # `http.py` names only its own fixed sentence here; nothing echoes the URL's path, which
                # is where a webhook's embedded secret would live.
                raise _refuse(f'Channel {name} webhook endpoint is refused ({type(exc).__name__})') from exc
        elif kind in TRANSPORT_TYPES:
            # The five ported transports: construction is theirs, refusal wording stays ours, so one
            # voice prints every configuration problem in this document whichever module found it.
            try:
                client = build_transport(entry, name, secret=_mounted_secret,
                                         index_path=index_path, display_config=display_config or {})
            except ChannelConfigError as exc:
                raise _refuse(str(exc)) from exc
        clients[name] = client
        policies[name] = _channel_policy(entry, name, mode)
    return clients, policies


def _sender(client: Any, channel: str) -> Any:
    """Return the client that must send one row: the channel's own, or the single configured one.

    A mapping is the multi-channel form (schema v3); anything else is one client for one channel, which
    is how every pre-v3 caller and test hands a sender to this module.
    """
    if isinstance(client, Mapping):
        return client.get(channel)
    return client


def deliver_one(store: Store, client: Any, *, now: dt.datetime | None = None) -> dict[str, Any]:
    """Attempt one queued delivery and record the outcome with its cause class.

    Only identifiers, the routed channel and statuses are logged: never a response body, a URL, a token
    or the message text. The callback token a human-channel send carries is handed to the channel in
    the payload copy this call builds, and is never logged nor stored in the clear anywhere.

    The returned report is the same three fields it always was (`status`, `delivery_id`, `destination`,
    plus `reason` on a refusal): the cause is durable state, readable on the attempt row and in
    `presentation.delivery_route`, not something a caller had to start handling.

    Args:
        store: The operational store whose queue is being drained.
        client: One channel client, or the ``{channel: client}`` mapping `build_channels` returns.
        now: The instant to claim and finish at; defaults to the clock.
    """
    item = store.claim_notification(now=now)
    if item is None:
        log.debug('Notification delivery idle')
        return {'status': 'idle'}
    if item.get('suppressed'):
        log.info('Notification suppressed', extra={'delivery_id': item['id'], 'destination': item['destination'],
                                                  'reason': item['suppressed']})
        return {'status': 'suppressed', 'delivery_id': item['id'], 'reason': item['suppressed']}
    # The claim names the channel the state model routed this row to. A caller handing an unmigrated
    # item, or a test double for one, has none: the single-client form below still sends, and a
    # mapping-form caller gets no sender, which is recorded as the refusal that it is.
    channel = item.get('channel') or ''
    if item['destination'] in ('synthetic-sink', 'recording-sink'):
        from .notification_safety import RecordingSink
        sender: Any = RecordingSink()
    else:
        sender = _sender(client, channel)
    payload = item['payload']
    if item.get('callback'):
        # A copy, so the durable outbox row keeps the payload it was written with: the token belongs to
        # this attempt only, and a retry mints a new one.
        payload = {**payload, 'callback': {'token': item['callback']['token'],
                                           'expires_at': item['callback']['expires_at'],
                                           'route': '/v1/callbacks/' + (channel or 'primary')}}
    accepted = False
    cause = 'rejected'
    refused_by_platform = False
    try:
        if payload['event']['data_class'] == 'restricted':
            cause, refused_by_platform = 'policy', True
            raise StateError('Restricted event delivery needs explicit channel policy')
        if sender is None:
            # A row routed to a channel this process cannot send on is a platform refusal, not a
            # provider problem: recording it as `policy` keeps the row visible and retried like any
            # other refusal, rather than making it look like a provider outage.
            cause, refused_by_platform = 'policy', True
            raise StateError('No channel client is configured for the routed channel')
        status, receipt = sender.request('POST', payload=payload, headers={'Idempotency-Key': item['id']})
        accepted = (status in (200, 201, 202) and isinstance(receipt, dict)
                    and receipt.get('delivery_id') == item['id'] and receipt.get('accepted') is True)
        if accepted:
            # The cause word is what a failure is *for*; a receipt that matched has one answer, and it
            # is not "no cause", which is what an unset field would otherwise have to mean.
            cause = 'accepted'
    except (TransportError, OSError) as exc:
        cause = 'transport'
        log.warning('Notification channel attempt failed', extra={'delivery_id': item['id'],
                                                                 'destination': item['destination'],
                                                                 'channel': channel,
                                                                 'error_class': type(exc).__name__})
        log.debug('Notification channel attempt details', exc_info=True)
    except StateError as exc:
        # Either the platform's own sentence or a channel adapter refusing a send it will not make.
        # A ported transport (`channels.Channel`) raises here only for what the platform should never have
        # queued — a restricted event, an identity mismatch, an unknown transition — because every answer
        # a provider gives comes back as an `Outcome`, never as an exception. So `policy` is the honest
        # word for its refusal; `rejected` stays the answer for the adapters that predate that interface,
        # whose `StateError` is provider-shaped (Telegram raises it for a payload it will not format).
        # Nothing about the refusal is stored: the class name is the whole diagnosis, as it was.
        cause = 'policy' if (refused_by_platform or isinstance(sender, Channel)) else 'rejected'
        log.warning('Notification channel attempt failed', extra={'delivery_id': item['id'],
                                                                 'destination': item['destination'],
                                                                 'channel': channel,
                                                                 'error_class': type(exc).__name__})
        log.debug('Notification channel attempt details', exc_info=True)
    status = store.finish_notification(item['id'], item['claim_token'], accepted, now=now, cause=cause)
    log.info('Notification delivery finished', extra={'delivery_id': item['id'], 'destination': item['destination'],
                                                     'channel': channel, 'status': status, 'cause': cause})
    return {'status': status, 'delivery_id': item['id'], 'destination': item['destination']}


__all__ = ['build_channels', 'deliver_one', 'CHANNEL_KEYS', 'CHANNEL_TYPES', 'ChannelConfigError',
           'RESERVED_CHANNEL_LABELS']

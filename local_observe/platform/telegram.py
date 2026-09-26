"""Send-only Telegram adapter; never consumes bot updates or changes bot configuration.

The adapter builds one short message from bounded presentation metadata and sends it. Since schema v3
it may also carry a single-use approval code that the platform minted for that send (ledger notifications):
the code is *printed* for the human, never posted by this adapter, which stays send-only and keeps
refusing to read the bot's update queue. Everything the platform does not know already — the phone
number, the bot's token, the response body — stays out of the message and out of any log line.
"""
import email.message
import http.client
import json
import re
from typing import Any
import urllib.error
import urllib.request
import uuid

from local_observe.http import TransportError
from .state import StateError


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: http.client.HTTPResponse, code: int,
                         msg: str, headers: email.message.Message,
                         newurl: str) -> urllib.request.Request | None:
        return None


# An approval code is the `secrets.token_urlsafe` value this build minted, and nothing shaped otherwise
# gets printed: a payload from anywhere else cannot smuggle text into an operator's phone message.
CALLBACK_CODE = re.compile(r'[A-Za-z0-9_-]{16,64}\Z')
# Where to send that code back to. Credentials (`@`), a query and a fragment are all refused: the token
# must travel in a body, so a link that could carry it is not one this adapter will print.
CALLBACK_BASE = re.compile(r'https://[A-Za-z0-9.\-]+(:\d{1,5})?(/[A-Za-z0-9._~!$&()*+,;=:@%-]*)*\Z')


def approval_line(display_config: dict[str, Any], callback: Any) -> str | None:
    """Return the one message line that carries an approval code, or None when it must not be printed.

    Two conditions decide it, both failing closed: the deployment has to name an HTTPS callback base
    (with no credentials, query or fragment in it), and the code has to be a token this build could have
    minted. Absent either, the alert still sends and simply says nothing about approvals — a link that
    might be wrong, or a code truncated to fit a bound, is worse than no line at all.
    """
    if not isinstance(callback, dict):
        return None
    base = display_config.get('callback_base') if isinstance(display_config, dict) else None
    code = callback.get('token')
    route = callback.get('route')
    if not isinstance(base, str) or not CALLBACK_BASE.match(base) or len(base) > 256:
        return None
    if not isinstance(code, str) or not CALLBACK_CODE.match(code):
        return None
    if not isinstance(route, str) or not route.startswith('/v1/callbacks/') or len(route) > 128:
        return None
    return 'Approve at ' + base.rstrip('/') + route + ' with code ' + code


class TelegramClient:
    def __init__(self, token, chat_id, *, opener=None, index_path=None, display_config=None):
        if not re.fullmatch(r'\d+:[A-Za-z0-9_-]+', token) or not re.fullmatch(r'-?\d+', str(chat_id)):
            raise ValueError('Invalid Telegram credential configuration')
        self._url = 'https://api.telegram.org/bot' + token + '/sendMessage'
        self._chat_id = str(chat_id)
        self._index_path = index_path
        self._display_config = display_config or {}
        self._opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method: str, path: str = '', payload: dict[str, Any] | None = None,
                headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
        if method != 'POST' or path or not payload or payload['event']['data_class'] == 'restricted':
            raise StateError('Only unrestricted notification sends are supported')
        delivery = str(uuid.UUID(payload['delivery_id']))
        if (headers or {}).get('Idempotency-Key') != delivery:
            raise StateError('Notification identity mismatch')
        # Only bounded rule/inventory labels leave the platform, never raw telemetry or evidence bodies.
        transition = payload['transition']
        if transition not in ('opened', 'resolved'):
            raise StateError('Unknown notification transition')
        uuid.UUID(payload['incident_id'])
        from .presentation import describe
        from .notification_text import notification_lines
        display = describe(payload['event'], self._index_path, self._display_config)
        config = {'channel_name': 'Telegram', **self._display_config}
        message = '\n'.join(notification_lines(payload, display, config))
        approval = approval_line(self._display_config, payload.get('callback'))
        if approval:
            message = message + '\n' + approval
        body = json.dumps({'chat_id': self._chat_id, 'text': message,
                           'link_preview_options': {'is_disabled': True}}).encode()
        request = urllib.request.Request(self._url, data=body, method='POST',
                                         headers={'Content-Type': 'application/json'})
        try:
            with self._opener.open(request, timeout=15) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError('Oversized response')
                receipt = json.loads(raw)
                result = receipt.get('result', {})
                accepted = (response.status == 200 and receipt.get('ok') is True
                            and isinstance(result.get('message_id'), int))
                accepted = accepted and str(result.get('chat', {}).get('id')) == self._chat_id
                return response.status, {'accepted': accepted, 'delivery_id': delivery}
        except (OSError, ValueError, TypeError, AttributeError):
            # Telegram puts its credential in the URL; never propagate URL-bearing exceptions.
            raise TransportError('Telegram send failed; response details withheld') from None

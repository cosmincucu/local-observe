"""Bounded JSON transport for operator-configured endpoints; no credential redirects."""
import email.message
import http.client
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from local_observe.inventory.validation import canonical
from local_observe.log import get_logger

log = get_logger(__name__)


class TransportError(ValueError):
    pass


class ResultTooLarge(TransportError):
    """The endpoint answered, but its result exceeded the bounded read."""

    code = 'source_result_too_large'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: http.client.HTTPResponse, code: int,
                         msg: str, headers: email.message.Message,
                         newurl: str) -> urllib.request.Request | None:
        return None


def _refused(method: str, path: str, error: TransportError, cause: BaseException | None = None) -> TransportError:
    """Log one bounded transport failure and return *error* so the caller raises it.

    Only the method, the credential-free path and the error class are recorded: never the
    token, the query string, the response body or the request payload. Pass ``cause`` when a
    lower-level failure is being wrapped — a timeout and a refused connection are different
    diagnoses — otherwise the class of the bounded error itself is reported.
    """
    log.warning('HTTP transport failed', extra={'method': method, 'path': path.split('?', 1)[0],
                                                'error_class': type(cause or error).__name__})
    return error


class JsonClient:
    """One bounded JSON endpoint, with two documented options a notification provider needs.

    `token` may be ``None``, which sends no `Authorization` header at all: some providers carry their
    secret in the request body (PagerDuty's routing key) or in the configured URL itself (a Slack
    incoming webhook), and putting it in a header as well would copy it into anything that logs headers.
    An absent token is not a weaker token -- when one is given, every rule below still applies to it.

    `accept_non_json` admits a 2xx answer whose body is not JSON, returned as ``(status, None)``. Slack
    answers a successful post with the plain text ``ok``; without this option the parse failure arrives
    as `TransportError`, which would tell the operator the endpoint was unreachable when it answered
    perfectly well. It is honoured for a 2xx only: an error status keeps the one answer it always had.
    """

    def __init__(self, base, token, *, scheme='Bearer', allow_http=False, timeout=10, ca_file=None,
                 accept_non_json=False, max_timeout=20):
        parsed = urllib.parse.urlsplit(base)
        if (parsed.scheme not in (('https', 'http') if allow_http else ('https',))
                or not parsed.hostname or parsed.username or parsed.password or parsed.query
                or parsed.fragment):
            raise TransportError('Expected configured HTTPS endpoint without embedded credentials')
        if token is not None and (not isinstance(token, str) or len(token) < 24
                                  or '\n' in token or '\r' in token):
            raise TransportError('A separate bounded credential is required')
        if accept_non_json not in (False, True):
            raise TransportError('accept_non_json must be a boolean')
        if type(max_timeout) is not int or not 1 <= max_timeout <= 120:
            raise TransportError('Invalid HTTP timeout ceiling')
        if type(timeout) is not int or not 1 <= timeout <= max_timeout:
            raise TransportError('Invalid HTTP timeout')
        self.base, self.token, self.scheme, self.timeout = base.rstrip('/'), token, scheme, timeout
        self.max_timeout = max_timeout
        self.accept_non_json = accept_non_json is True
        handlers = [urllib.request.ProxyHandler({}), NoRedirect()]
        if ca_file is not None:
            if parsed.scheme != 'https':
                raise TransportError('Custom certificate trust requires HTTPS')
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        self.opener = urllib.request.build_opener(*handlers)

    def _attempt_timeout(self, method: str, path: str, timeout: int | None) -> int:
        """Return the timeout for one request: the caller's shorter bound, never a longer one.

        A notification transport holds an outbox lease while it waits, so the ceiling is the client's own
        bound (20 s by default, with explicit constructor opt-in up to 120 s) whichever way a
        caller asks to move it. Per-request overrides can only shorten the configured timeout.
        """
        if timeout is None:
            return self.timeout
        if type(timeout) is not int or not 1 <= timeout:
            raise _refused(method, path, TransportError('Invalid HTTP timeout'))
        return min(timeout, self.timeout)

    def request(self, method: str, path: str = '', payload: Any = None, *,
                headers: dict[str, str] | None = None, timeout: int | None = None) -> tuple[int, Any]:
        """Perform one bounded JSON request; failures are logged without credentials."""
        if path and (not path.startswith('/') or path.startswith('//')
                     or '..' in urllib.parse.unquote(path).split('/')):
            raise _refused(method, path, TransportError('Invalid relative API path'))
        limit = self._attempt_timeout(method, path, timeout)
        request = urllib.request.Request(
            self.base + path,
            data=canonical(payload).encode() if payload is not None else None,
            method=method,
            headers={**(headers or {}), 'Content-Type': 'application/json', 'Accept': 'application/json',
                     **({'Authorization': self.scheme + ' ' + self.token} if self.token is not None else {})})
        try:
            with self.opener.open(request, timeout=limit) as response:
                raw = response.read(4 * 1024 * 1024 + 1)
                if len(raw) > 4 * 1024 * 1024:
                    raise TransportError('HTTP response exceeds bound')
                status = response.status
            try:
                return status, json.loads(raw) if raw else None
            except ValueError:
                if not self.accept_non_json or not 200 <= status < 300:
                    raise
                return status, None
        except urllib.error.HTTPError as exc:
            exc.close()
            log.debug('HTTP endpoint returned an error status', extra={'method': method, 'path': path.split('?', 1)[0],
                                                                      'status_code': exc.code})
            return exc.code, None
        except (OSError, ValueError) as exc:
            raise _refused(method, path, TransportError('Endpoint unavailable or invalid JSON response'),
                           exc) from exc

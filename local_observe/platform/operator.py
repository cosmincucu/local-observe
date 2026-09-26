"""Same-origin operator shell over the role-enforced platform API.

The shell does two things: it serves the static UI, and — when a password account is mounted — it
turns the UI's `Authorization: Basic` into the human bearer the deployment already configured. The
API underneath is untouched: every request it accepts still carries a bearer credential, machine
credentials keep working exactly as before, and the substituted bearer is never sent to a caller.

GET /v1/operator-auth is the one route answered here that needs no credential, because the UI has to
ask it *before* it knows how to sign in. It says `{mode: 'password'|'token'}` and nothing else, which
is how the legacy bearer UI stays reachable: a deployment with no mounted account gets `token`, the
form shows the token field, and the behaviour is the one this file had before passwords existed.
"""
import asyncio
import binascii
from collections.abc import Awaitable, Callable, Mapping
import json
import os
from pathlib import Path
from typing import Any

from . import operator_account

ASSETS = {'/': ('index.html', 'text/html; charset=utf-8'),
          '/ui.css': ('ui.css', 'text/css'), '/ui.js': ('ui.js', 'text/javascript'),
          '/lucide.min.js': ('lucide.min.js', 'text/javascript')}

#: The UI's one unauthenticated question: which field should the sign-in form show?
AUTH_METADATA_ROUTE = '/v1/operator-auth'

#: Password checks allowed in flight at once. A PBKDF2 at this iteration count is a few hundred
#: milliseconds of CPU, so the honest capacity of one installation process is a couple of them; beyond
#: that the answer is 503 and a retry, never a queue that outlives the operator's patience. Bounding
#: the count is also what bounds the threads: one slot, one `asyncio.to_thread` call.
MAX_CONCURRENT_PASSWORD_CHECKS = 2

# Fixed answers. None is ever formatted with caller bytes, a hash or a bearer.
AUTHENTICATION_REQUIRED = {'error': 'authentication_required'}
LOGIN_BUSY = {'error': 'operator_login_busy'}


def _canonical(body: Mapping[str, Any]) -> bytes:
    """Serialise one answer the way `api.canonical` does, without importing the API at module load."""
    return json.dumps(dict(body), separators=(',', ':'), sort_keys=True).encode()


def with_ui(api: Callable[..., Awaitable[None]], account: Mapping[str, Any] | None = None,
            human_token: str | None = None) -> Callable[..., Awaitable[None]]:
    """Wrap the API with the static shell and, optionally, the password-to-bearer substitution.

    Args:
        api: The authenticated platform ASGI app. It is the only thing that sees a request after the
            shell is done, and it always sees a bearer credential.
        account: The mounted operator document (`operator_account.load_account`), or ``None`` for the
            bearer-only shell.
        human_token: The human role's bearer, from `operator_account.human_bearer`. Required whenever
            ``account`` is given; never sent outwards.

    Returns:
        An ASGI app. Password checks run on a worker thread; nothing else leaves the loop's ordering.

    Raises:
        ValueError: An account was named without a bearer to stand behind it.
    """
    if account is not None and not human_token:
        raise ValueError(operator_account.NO_HUMAN_CREDENTIAL)
    # The substituted header, built once. Held here and never returned by any route.
    substitution = ('Bearer ' + human_token).encode() if account is not None else None
    checking = {'count': 0}
    checks = set()

    def finished(task):
        checking['count'] -= 1
        checks.discard(task)
        # A disconnected requester may no longer await this thread's result.
        if not task.cancelled():
            task.exception()

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        async def respond(status: int, body: Mapping[str, Any]) -> None:
            await send({'type': 'http.response.start', 'status': status, 'headers': [
                (b'content-type', b'application/json'), (b'cache-control', b'no-store'),
                (b'x-content-type-options', b'nosniff'), (b'referrer-policy', b'no-referrer')]})
            await send({'type': 'http.response.body', 'body': _canonical(body)})

        if scope['type'] == 'http' and scope['method'] == 'GET' and scope['path'] in ASSETS:
            name, content_type = ASSETS[scope['path']]
            raw = (Path(__file__).parent / 'static' / name).read_bytes()
            await send({'type': 'http.response.start', 'status': 200, 'headers': [
                (b'content-type', content_type.encode()), (b'cache-control', b'no-store'),
                (b'x-content-type-options', b'nosniff'), (b'referrer-policy', b'no-referrer'),
                (b'content-security-policy', b"default-src 'self'; script-src 'self'; style-src 'self'; "
                                            b"connect-src 'self'; img-src 'self' data:; frame-ancestors "
                                            b"'none'; base-uri 'none'; form-action 'none'")]})
            await send({'type': 'http.response.body', 'body': raw})
            return
        if scope['type'] == 'http' and scope['method'] == 'GET' and \
                scope['path'] == AUTH_METADATA_ROUTE:
            # Answered before any credential test, and it carries no credential hint of its own: the
            # mode is configuration, and the only other answer in this file is a fixed sentence.
            return await respond(200, {'mode': 'password' if account is not None else 'token'})
        if scope['type'] == 'http':
            values = [value for name, value in scope.get('headers', [])
                      if name.lower() == b'authorization']
            if len(values) > 1:
                return await respond(401, AUTHENTICATION_REQUIRED)
            # Two `Authorization` headers are a refusal, and `api` refuses them the same way; the
            # point of not reaching for the KDF here is that a duplicated header must never pick a
            # password to verify by ordering.
            if len(values) == 1 and values[0][:6].lower() == b'basic ' and account is not None:
                offered = _decode(values[0])
                if offered is None:
                    return await respond(401, AUTHENTICATION_REQUIRED)
                if checking['count'] >= MAX_CONCURRENT_PASSWORD_CHECKS:
                    # Rejected before the task exists: the point of the ceiling is that excess work is
                    # never started, so a burst costs a status code and no CPU.
                    return await respond(503, LOGIN_BUSY)
                checking['count'] += 1
                task = asyncio.create_task(asyncio.to_thread(operator_account.verify_password,
                                                             account, offered[0], offered[1]))
                checks.add(task)
                task.add_done_callback(finished)
                try:
                    # Cancellation must not release capacity while PBKDF2 still runs.
                    accepted = await asyncio.shield(task)
                except Exception:
                    return await respond(503, LOGIN_BUSY)
                if not accepted:
                    return await respond(401, AUTHENTICATION_REQUIRED)
                scope = {**scope, 'headers': [(name, substitution) if name.lower() == b'authorization'
                                              else (name, value)
                                              for name, value in scope['headers']]}
        await api(scope, receive, send)

    return app


def _decode(value: bytes) -> tuple[str, str] | None:
    """Return the ``(username, password)`` a raw header value carries, or ``None``.

    The transport hands headers as bytes and decodes them latin-1 for the sake of a caller that sent
    UTF-8, so the byte value is re-decoded exactly once, strictly, before `parse_basic` judges it. A
    value that is not UTF-8 is not a credential: `None`, which becomes the same 401 as a wrong
    password. Nothing here raises on caller bytes, and nothing echoes them.
    """
    try:
        return operator_account.parse_basic(value.decode('utf-8'))
    except (UnicodeDecodeError, binascii.Error, ValueError):
        return None


def operator_account_from_environment(environ: Mapping[str, str] = os.environ) -> dict[str, Any] | None:
    """Return the mounted operator account, or ``None`` when the deployment is bearer-only."""
    return operator_account.account_from_environment(environ)


def app_factory() -> Callable[..., Awaitable[None]]:
    """Build the shell over the platform, honouring ``LO_OPERATOR_ACCOUNT_FILE`` when set.

    Validate password configuration before the platform factory can open its store.
    Without a mounted account the existing platform startup path is unchanged.
    """
    from .api import app_factory as platform_factory, role_credentials
    account = operator_account_from_environment()
    human_token = operator_account.human_bearer(role_credentials(), account) if account is not None else None
    api = platform_factory()
    return with_ui(api, account=account, human_token=human_token)

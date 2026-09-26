"""Authenticated, read-only Datasette/GraphQL reference application."""
import base64
import binascii
from collections.abc import Awaitable, Callable, Iterable
import hmac
import os
from pathlib import Path
from typing import Any

from local_observe.credentials import read_credential

from .index import readonly


def authenticate(headers: Iterable[tuple[bytes, bytes]], token: str) -> bool:
    values = [value for name, value in headers if name.lower() == b'authorization']
    if len(values) != 1:
        return False
    scheme, _, value = values[0].partition(b' ')
    if scheme.lower() == b'bearer':
        candidate = value
    elif scheme.lower() == b'basic':
        try:
            username, separator, candidate = base64.b64decode(value, validate=True).partition(b':')
            if username != b'operator' or not separator:
                return False
        except (ValueError, binascii.Error):
            return False
    else:
        return False
    return hmac.compare_digest(candidate, token.encode())


def protect(app: Callable[..., Any], token: str) -> Callable[..., Awaitable[None]]:
    if len(token) < 24:
        raise ValueError('LO_INVENTORY_TOKEN must contain at least 24 characters')
    async def wrapped(scope, receive, send):
        if scope['type'] == 'websocket':
            await send({'type': 'websocket.close', 'code': 1008})
            return
        if scope['type'] == 'http':
            if not authenticate(scope.get('headers', []), token):
                await send({'type': 'http.response.start', 'status': 401,
                            'headers': [(b'www-authenticate', b'Basic realm="local-observe inventory"'),
                                        (b'cache-control', b'no-store')]})
                await send({'type': 'http.response.body', 'body': b'Authentication required'})
                return
            if scope['method'] not in ('GET', 'HEAD', 'OPTIONS'):
                await send({'type': 'http.response.start', 'status': 405,
                            'headers': [(b'allow', b'GET, HEAD, OPTIONS')]})
                await send({'type': 'http.response.body', 'body': b'Read-only service'})
                return
        await app(scope, receive, send)
    return wrapped


def create_app(path: Path | str, token: str) -> Callable[..., Awaitable[None]]:
    from datasette.app import Datasette
    with readonly(path):
        pass
    datasette = Datasette(immutables=[str(path)], settings={
        'default_allow_sql': False, 'allow_download': False, 'allow_csv_stream': False,
        'default_page_size': 50, 'max_returned_rows': 100, 'sql_time_limit_ms': 250,
        'default_cache_ttl': 0,
    }, metadata={'plugins': {'datasette-graphql': {'num_queries_limit': 25, 'time_limit_ms': 500}}})
    return protect(datasette.app(), token)


def app_factory() -> Callable[..., Awaitable[None]]:
    """Serve the read-only index; the token arrives as a mounted file, never as an environment value."""
    return create_app(os.environ['LO_INDEX_PATH'], read_credential('LO_INVENTORY_TOKEN'))

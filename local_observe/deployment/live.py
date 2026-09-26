"""Read-only, bounded live exports. Snapshots prove capture scope, not deploy authority."""
from collections.abc import Callable
import datetime as dt
import json
import re
import ssl
import urllib.request
from typing import Any
from urllib.parse import urlsplit, quote

from .content import Conflict, HASH, ID, TEXT, obj, validate
from local_observe.inventory.validation import digest

HOMEPAGE_FILES = ('services.yaml', 'settings.yaml', 'widgets.yaml', 'bookmarks.yaml',
                  'docker.yaml', 'kubernetes.yaml', 'proxmox.yaml', 'custom.css', 'custom.js')
SNAPSHOT = obj({'schema_version': {'const': 1}, 'adapter': {'enum': ['homepage-files-v1', 'signoz-v2-v6']},
    'scope': TEXT, 'captured_at': {'type': 'number'}, 'complete': {'const': True},
    'artifacts': {'type': 'object', 'additionalProperties': HASH}, 'sha256': HASH})


def capture(adapter: str, scope: str, artifacts: dict[str, str],
            now: float | None = None) -> dict[str, Any]:
    result = {'schema_version': 1, 'adapter': adapter, 'scope': scope,
              'captured_at': dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now,
              'complete': True, 'artifacts': artifacts, 'sha256': digest(artifacts)}
    validate(result, SNAPSHOT, 'live snapshot')
    return result


def compare(previous: dict[str, Any], observed: dict[str, Any], *, now: float | None = None,
            max_age: int = 60) -> dict[str, Any]:
    for snapshot in (previous, observed):
        validate(snapshot, SNAPSHOT, 'live snapshot')
        if snapshot['sha256'] != digest(snapshot['artifacts']):
            raise Conflict('Live snapshot digest differs')
    if (previous['scope'], previous['adapter']) != (observed['scope'], observed['adapter']):
        raise Conflict('Live export scope differs')
    now = dt.datetime.now(dt.timezone.utc).timestamp() if now is None else now
    if not 0 <= now-observed['captured_at'] <= max_age:
        raise Conflict('Live snapshot is stale or from the future')
    old, actual = previous['artifacts'], observed['artifacts']
    drift = sorted(k for k in old if old.get(k) != actual.get(k))
    unmanaged = sorted(set(actual)-set(old))
    return {'status': 'blocked' if drift or unmanaged else 'review-required', 'deploy_authorized': False,
            'drift': drift, 'unmanaged': unmanaged, 'observed_sha256': observed['sha256']}


def homepage_export(read_file: Callable[[str], Any], scope: str) -> dict[str, Any]:
    """read_file must read the running container's /app/config, not an authoring tree."""
    import hashlib
    artifacts = {}
    for name in HOMEPAGE_FILES:
        value = read_file(name)
        if not isinstance(value, bytes) or len(value) > 8*1024*1024:
            raise Conflict('Homepage export missing or exceeds bound')
        artifacts[name] = hashlib.sha256(value).hexdigest()
    return capture('homepage-files-v1', scope, artifacts)


def docker_homepage_export(run: Callable[..., str], container: str, expected_image: str,
                           scope: str) -> dict[str, Any]:
    """The caller selects a scoped Docker daemon; no sockets/credentials are discovered."""
    import base64
    if (not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', container)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', expected_image)):
        raise Conflict('Invalid container or pinned image identity')
    def identity():
        value = json.loads(run('docker', 'inspect', container))[0]
        if not value['State']['Running'] or value['Image'] != expected_image:
            raise Conflict('Homepage container is stopped or its image differs')
        return value['Id']
    before = identity()
    def read(name):
        value = run('docker', 'exec', container, 'node', '-e',
                    "process.stdout.write(require('node:fs').readFileSync("
                    "'/app/config/'+process.argv[1]).toString('base64'))",
                    name)
        return base64.b64decode(value, validate=True)
    # Two complete captures detect concurrent file edits across the non-transactional read.
    first = homepage_export(read, scope)
    second = homepage_export(read, scope)
    if before != identity() or first['sha256'] != second['sha256']:
        raise Conflict('Homepage changed during capture')
    return second


class SignozReader:
    """GET-only API-key client: verified TLS, no proxy, no redirects or token logging."""
    def __init__(self, url, token, *, ca_file=None):
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ('', '/')):
            raise Conflict('SigNoz export requires a plain HTTPS origin')
        if not token or '\n' in token or '\r' in token:
            raise Conflict('Missing or invalid reader credential')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.url, self.token = url.rstrip('/'), token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))

    def __call__(self, path):
        if not re.fullmatch(r'/api/v2/dashboards(?:\?limit=500&offset=\d+|/[a-zA-Z0-9_-]+)', path):
            raise Conflict('Read endpoint outside dashboard export scope')
        try:
            request = urllib.request.Request(self.url+path, headers={'SIGNOZ-API-KEY': self.token}, method='GET')
            with self.opener.open(request, timeout=15) as response:
                body = response.read(8*1024*1024+1)
            if len(body) > 8*1024*1024:
                raise ValueError()
            return json.loads(body)
        except (OSError, ValueError):
            raise Conflict('SigNoz read failed; no complete snapshot produced') from None


def dashboard_document(value: Any) -> dict[str, Any]:
    # Strip only known server envelope metadata. Preserve every field inside spec.
    if not isinstance(value, dict) or value.get('schemaVersion') != 'v6' or not isinstance(value.get('spec'), dict):
        raise Conflict('Unsupported SigNoz dashboard schema; explicit adapter required')
    if not isinstance(value.get('name'), str) or not isinstance(value.get('tags'), list):
        raise Conflict('Incomplete SigNoz dashboard document')
    return {key: value[key] for key in ('name', 'tags', 'spec', 'schemaVersion')}


def dashboard_identities(rows: Any, origin: str) -> dict[str, str]:
    """Derive candidate backend IDs from existing links, not names or guesses.

    This is a mapping proposal, not evidence that a dashboard exists on the server.
    signoz_export must subsequently verify every mapped backend ID.
    """
    base = urlsplit(origin)
    if (base.scheme != 'https' or not base.hostname or base.path not in ('', '/') or base.query
            or base.fragment or base.username):
        raise Conflict('Expected a plain HTTPS dashboard origin')
    if not isinstance(rows, list):
        raise Conflict('Expected a private identity map list')
    result = {}
    for row in rows:
        if not isinstance(row, dict) or 'id' not in row:
            raise Conflict('Invalid identity row')
        if 'legacy_source' not in row:
            continue
        validate(row['id'], ID, 'logical dashboard ID')
        link = urlsplit(row.get('href', ''))
        match = re.fullmatch(r'/dashboard/([a-zA-Z0-9_-]{1,128})', link.path)
        if (link.scheme, link.netloc) != (base.scheme, base.netloc) or link.query or link.fragment or not match:
            raise Conflict('Dashboard link outside selected origin or unsupported path')
        backend = match.group(1)
        if row.get('backend_id') not in (None, backend) or row['id'] in result or backend in result.values():
            raise Conflict('Conflicting dashboard backend identity')
        result[row['id']] = backend
    if not result:
        raise Conflict('No dashboard identities found')
    return result


def signoz_export(get: Callable[[str], Any], scope: str,
                  identities: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """identities maps persistent logical IDs to backend UUIDs; export unmanaged IDs too."""
    validate(identities, {'type': 'object', 'maxProperties': 10000, 'propertyNames': ID,
                          'additionalProperties': {'type': 'string', 'pattern': '^[a-zA-Z0-9_-]+$',
                                                   'maxLength': 128}},
               'dashboard identity map')
    if (len(set(identities.values())) != len(identities)
            or any(not re.fullmatch(r'[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+', k) for k in identities)):
        raise Conflict('Ambiguous dashboard identity mapping')
    def listing():
        found, total = {}, None
        for offset in range(0, 10000, 500):
            body = get('/api/v2/dashboards?limit=500&offset='+str(offset))
            try:
                data = body['data']
                count, rows = data['total'], data['dashboards']
                if type(count) is not int or not 0 <= count <= 10000 or not isinstance(rows, list) or len(rows) > 500:
                    raise ValueError()
                if total is not None and count != total:
                    raise ValueError()
                total = count
                for row in rows:
                    key = row['id']
                    if not isinstance(key, str) or not re.fullmatch(r'[a-zA-Z0-9_-]+', key) or key in found:
                        raise ValueError()
                    found[key] = row
                if len(found) == total:
                    return found
                if len(rows) != 500:
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise Conflict('Incomplete or changing SigNoz listing') from None
        raise Conflict('SigNoz listing exceeds export bound')
    rows = listing()
    if not set(identities.values()) <= set(rows):
        raise Conflict('Mapped dashboard missing from live server')
    inverse = {v: k for k, v in identities.items()}
    documents = {}
    for backend in sorted(rows):
        try:
            document = get('/api/v2/dashboards/'+quote(backend, safe=''))['data']
        except (KeyError, TypeError):
            raise Conflict('Incomplete SigNoz detail') from None
        documents[inverse.get(backend, 'unmanaged:'+backend)] = dashboard_document(document)
    if digest(rows) != digest(listing()):
        raise Conflict('Dashboard listing changed during capture')
    for backend in sorted(rows):
        try:
            current = dashboard_document(get('/api/v2/dashboards/'+quote(backend, safe=''))['data'])
        except (KeyError, TypeError):
            raise Conflict('Incomplete SigNoz recheck') from None
        if digest(current) != digest(documents[inverse.get(backend, 'unmanaged:'+backend)]):
            raise Conflict('Dashboard detail changed during capture')
    artifacts = {key: digest(value) for key, value in documents.items()}
    artifacts['$identity-map'] = digest(identities)
    return capture('signoz-v2-v6', scope, artifacts), documents

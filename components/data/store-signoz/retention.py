#!/usr/bin/env python3
"""Configure and verify SigNoz telemetry retention for the reference store (remediation retention).

Run with no mode flag to CHECK: the tool authenticates with the operator's credentials file, reads
the retention the store applies today to each of the three signals and exits 0 only when every
signal already equals the expected number of days. Run with --apply to SET them and then re-read to
prove the setting took effect. Nothing is written unless --apply is given.

Retention for application telemetry is a SigNoz API setting, not a mounted file: the checked-in
ClickHouse XML bounds only ClickHouse's own internal logs, which is why this program exists. The
endpoints it uses, and where they came from:

* ``POST /api/v2/sessions/email_password`` -- login, body ``{"email", "password", "orgID"}``
* ``GET  /api/v1/settings/ttl?type=<traces|metrics>`` -- read; ``data.ttl`` is a Go duration string
* ``POST /api/v1/settings/ttl?type=<signal>&duration=<hours>h`` -- write; hours is the unit it takes
* ``GET  /api/v2/settings/ttl?type=logs`` -- read; ``data.defaultTTLDays`` plus ``ttlConditions``
* ``POST /api/v2/settings/ttl`` -- write ``{"type": "logs", "defaultTTLDays": N, "ttlConditions": []}``

Those paths are the ones the retention brief names for SigNoz. They are **not yet confirmed against the
pinned build** (v0.138.0 in ``versions.json``, its digest in ``image-lock.json``): an unexpected
status, an unknown response shape or a refused login makes this tool exit 2 with a diagnosis instead
of guessing a unit or a field. A retention setting that cannot be read back is not a retention
setting.

Shortening a TTL is irreversible -- ClickHouse deletes the aged parts on the next merge -- so
--apply prints the before/after pair for every signal it changes and says so on the same line.

Exit codes: ``0`` the store already matches (or was made to match), ``1`` the store disagrees with
the expected days, ``2`` invalid input, an unreachable store, a refused login or an unreadable
response. The password is never printed, never logged and never part of an error message.

Transport: authenticated calls go through the product's ``local_observe.http.JsonClient`` when that
package is importable, so the no-proxy / no-redirect / bounded-body / no-credential-in-logs rules
are the same ones the platform already enforces. The login POST and any cookie-session call use the
equivalent in-module urllib path below, because JsonClient requires a bearer credential of its own
and returns no response headers. Both paths refuse redirects and proxies identically.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from collections.abc import Callable, Sequence
from typing import Any, NamedTuple

SIGNALS: tuple[str, ...] = ('traces', 'metrics', 'logs')
DEFAULT_DAYS = {'traces': 7, 'metrics': 30, 'logs': 14}
MAX_DAYS = 3650
TIMEOUT_SECONDS = 15
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CREDENTIALS_BYTES = 64 * 1024
MAX_COOKIES = 16
MAX_COOKIE_HEADER_BYTES = 8192
CREDENTIAL_KEYS = ('email', 'password', 'orgID', 'organizationName')
LOOPBACK_HOSTS = frozenset({'localhost', 'localhost.', 'ip6-localhost', '::1'})
EXIT_OK, EXIT_MISMATCH, EXIT_UNAVAILABLE = 0, 1, 2

DAYS_TEXT = re.compile(r'^(\d{1,4})\s*(?:d|day|days)$', re.IGNORECASE)
GO_DURATION = re.compile(r'^(?:\d+(?:\.\d+)?(?:ns|us|ms|s|m|h))+$')
GO_PART = re.compile(r'(\d+(?:\.\d+)?)(ns|us|ms|s|m|h)')
GO_SECONDS = {'ns': 1e-9, 'us': 1e-6, 'ms': 1e-3, 's': 1, 'm': 60, 'h': 3600}
# Field names and duration strings are echoed in diagnostics; anything else about a response stays
# inside this program, because a server body is untrusted text.
PRINTABLE = re.compile(r'^[A-Za-z0-9 .:_+()-]{1,64}$')
CONTROL = re.compile(r'[\x00-\x1f\x7f]')


class RetentionError(Exception):
    """A bounded failure that is safe to print: it never carries a credential or a server body."""


class Response(NamedTuple):
    """One store reply: HTTP status, decoded JSON body (or None) and any session cookies it set."""

    status: int
    body: Any = None
    cookies: dict[str, str] = {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect: a 3xx would move an administrator session to another origin."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - trivial
        return None


def safe_token(value: Any) -> str:
    """Return *value* as printable text for a diagnostic, or a placeholder when it is not plain."""
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    return text if PRINTABLE.match(text) else '<not printable>'


def parse_hours(value: Any, *, unit: str) -> int:
    """Normalise one TTL value to whole hours, refusing instead of guessing an unclear unit.

    ``unit`` says what the endpoint's field means: ``'days'`` for the logs API's
    ``defaultTTLDays``, ``'duration'`` for the traces/metrics API's ``ttl``. A duration string is
    Go-style (``336h0m0s``), a plain number is days when the field names days and otherwise is
    hours unless it is far too large to be hours, in which case it is a nanosecond duration.
    """
    if isinstance(value, bool) or value is None:
        raise RetentionError('the store returned no usable retention value')
    if isinstance(value, str):
        text = value.strip()
        match = DAYS_TEXT.match(text)
        if match:
            return _in_range(int(match.group(1)) * 24)
        if GO_DURATION.match(text):
            seconds = sum(float(amount) * GO_SECONDS[suffix] for amount, suffix in GO_PART.findall(text))
            if seconds % 3600:
                raise RetentionError(f'retention {safe_token(text)} is not a whole number of hours')
            return _in_range(int(seconds // 3600))
        raise RetentionError(f'unrecognised retention value {safe_token(text)}')
    if isinstance(value, float) and not value.is_integer():
        raise RetentionError(f'retention {safe_token(value)} is not a whole number')
    if isinstance(value, int):
        if unit == 'days':
            return _in_range(value * 24)
        if value >= 1_000_000_000:  # a duration marshalled as nanoseconds; hours never reach 1e9
            return _in_range(int(value // 3_600_000_000_000))
        return _in_range(value)
    if isinstance(value, float):
        return parse_hours(int(value), unit=unit)
    raise RetentionError(f'unrecognised retention value {safe_token(value)}')


def _in_range(hours: int) -> int:
    """Bound a read TTL to a plausible whole-day range so a misread unit cannot pass as success."""
    if not 1 <= hours <= MAX_DAYS * 24:
        raise RetentionError(f'retention of {hours}h is outside the supported range 1d..{MAX_DAYS}d')
    return hours


def format_hours(hours: int) -> str:
    """Render an observed TTL as days and hours, showing the raw hours whenever days do not divide."""
    days, remainder = divmod(hours, 24)
    return f'{days}d ({hours}h)' if not remainder else f'{hours / 24:.2f}d ({hours}h)'


def is_loopback(parsed: urllib.parse.SplitResult) -> bool:
    """True when a URL names this host only, which is how the store UI is published."""
    host = (parsed.hostname or '').strip('[]').lower()
    return host in LOOPBACK_HOSTS or host.startswith('127.')


def validate_origin(url: str, *, allow_insecure_http: bool = False) -> str:
    """Return the store origin without a trailing slash, refusing anything that could leak a session.

    Plaintext is accepted only for a loopback address -- the on-host or verified-SSH-tunnel case the
    component contract documents -- unless ``allow_insecure_http`` says the operator means it, so an
    administrator password never crosses a real network in the clear by accident.
    """
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise RetentionError('--url has an invalid port') from None
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or port is not None and not 1 <= port <= 65535:
        raise RetentionError('--url must be an http(s) origin such as http://127.0.0.1:18081')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise RetentionError('--url must be a bare origin: no credentials, path, query or fragment')
    if parsed.scheme == 'http' and not is_loopback(parsed) and not allow_insecure_http:
        raise RetentionError('--url is plaintext and not loopback; use https, a verified SSH tunnel to '
                             'the loopback UI port, or --allow-insecure-http on a network you trust')
    return f'{parsed.scheme}://{parsed.netloc}'


def _decode(raw: bytes) -> Any:
    """Decode a bounded response body as JSON, treating an empty or non-JSON body as no body."""
    if len(raw) > MAX_RESPONSE_BYTES:
        raise RetentionError('a store response exceeded the 4 MiB bound')
    if not raw.strip():
        return None
    try:
        return json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return None


def _cookies(headers: Any) -> dict[str, str]:
    """Collect ``Set-Cookie`` names and values, bounded and refusing control characters."""
    collected: dict[str, str] = {}
    for line in (headers.get_all('Set-Cookie') or [])[:MAX_COOKIES]:
        name, _, value = str(line).split(';', 1)[0].partition('=')
        name, value = name.strip(), value.strip().strip('"')
        if not name or CONTROL.search(name + value) or len(collected) >= MAX_COOKIES:
            continue
        collected[name] = value
    return collected


def cookie_header(cookies: dict[str, str]) -> str:
    """Join collected cookies into one bounded ``Cookie`` header value."""
    value = '; '.join(f'{name}={cookies[name]}' for name in sorted(cookies))
    if len(value) > MAX_COOKIE_HEADER_BYTES:
        raise RetentionError('the store set more session data than this tool will resend')
    return value


class HttpTransport:
    """The in-module urllib path: no proxy, no redirect, bounded body, nothing secret in a message."""

    def __init__(self, origin: str, *, timeout: int = TIMEOUT_SECONDS) -> None:
        self.origin, self.timeout = origin, timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None, *,
                headers: dict[str, str] | None = None) -> Response:
        """Perform one request and report its status; a 4xx/5xx is data, never an exception."""
        body = (json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
                if payload is not None else None)
        request = urllib.request.Request(self.origin + path, data=body, method=method.upper(),
                                         headers={'Content-Type': 'application/json', 'Accept': 'application/json',
                                                  **(headers or {})})
        try:
            with self.opener.open(request, timeout=self.timeout) as reply:
                return Response(int(reply.status), _decode(reply.read(MAX_RESPONSE_BYTES + 1)), _cookies(reply.headers))
        except urllib.error.HTTPError as error:
            try:
                raw = error.read(MAX_RESPONSE_BYTES + 1)
            except OSError:
                raw = b''
            error.close()
            return Response(int(error.code), _decode(raw), {})
        except OSError as error:
            raise RetentionError(f'the store is unreachable at {self.origin} ({type(error).__name__})') from None


def json_client_class() -> Any:
    """Return the product's ``JsonClient`` when the package is importable, else None (stdlib mode)."""
    try:
        from local_observe.http import JsonClient
    except ImportError:
        return None
    return JsonClient


class PackageTransport:
    """Authenticated calls through ``local_observe.http.JsonClient``, adapted to ``Response``."""

    def __init__(self, origin: str, *, timeout: int = TIMEOUT_SECONDS) -> None:
        self.client_class, self.origin, self.timeout = json_client_class(), origin, timeout
        if self.client_class is None:
            raise RetentionError('local_observe.http is not importable; nothing to delegate to')

    def usable(self, headers: dict[str, str]) -> bool:
        """JsonClient carries exactly one bearer credential and returns no response headers."""
        authorization = headers.get('Authorization', '')
        return ('Cookie' not in headers and authorization.startswith('Bearer ')
                and len(authorization) >= len('Bearer ') + 24 and not CONTROL.search(authorization))

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None, *,
                headers: dict[str, str] | None = None) -> Response:
        """Delegate one bearer-authenticated call; the product client owns the redaction rules."""
        authorization = (headers or {}).get('Authorization', '')
        if not self.usable(headers or {}):
            raise RetentionError('this session credential does not fit the package transport')
        client = self.client_class(self.origin, authorization[len('Bearer '):], scheme='Bearer',
                                   allow_http=self.origin.startswith('http://'), timeout=self.timeout)
        try:
            status, body = client.request(method, path, payload)
        except ValueError as error:
            raise RetentionError(f'the product transport refused the request ({type(error).__name__})') from None
        return Response(int(status), body, {})


def _access_token(body: Any) -> str | None:
    """Pull an access token out of a login response, if this SigNoz version returns one."""
    data = body.get('data') if isinstance(body, dict) else None
    if isinstance(data, dict):
        for key in ('accessToken', 'access_token', 'token'):
            value = data.get(key)
            if isinstance(value, str) and value and not CONTROL.search(value):
                return value
    return None


def _field(body: Any, key: str, *, signal: str) -> Any:
    """Return one named field from a TTL response envelope, naming the shapes it did find."""
    if not isinstance(body, dict):
        raise RetentionError(f'the store returned no JSON body for {signal} retention ({safe_token(body)})')
    data = body.get('data', body)
    if isinstance(data, list):
        rows = [row for row in data if isinstance(row, dict)]
        wanted = [row for row in rows if str(row.get('type', '')).lower() == signal]
        if len(wanted) != 1 and len(rows) != 1:
            raise RetentionError(f'the store returned {len(data)} retention rows for {signal}, expected one')
        data = (wanted or rows or [{}])[0]
    if not isinstance(data, dict):
        raise RetentionError(f'the {signal} retention response is not an object ({safe_token(data)})')
    if key not in data:
        names = ', '.join(sorted(name for name in data if PRINTABLE.match(str(name)))) or 'none'
        raise RetentionError(f'the {signal} retention response has no {key} field (fields: {names}); '
                             'the pinned SigNoz may name it differently -- see CONTRACT.md')
    return data[key]


class StoreSession:
    """One store API session: log in once, then read and write the three retention settings."""

    def __init__(self, transport: HttpTransport, credentials: dict[str, str], *,
                 package: PackageTransport | None = None) -> None:
        self.transport, self.credentials, self.package = transport, credentials, package
        self.candidates: list[tuple[str, dict[str, str]]] = []
        self.chosen, self.auth_label = 0, 'none'

    def login(self) -> str:
        """Authenticate once and record which session mechanism the store offered."""
        payload = {key: self.credentials[key] for key in CREDENTIAL_KEYS if key in self.credentials}
        reply = self.transport.request('POST', '/api/v2/sessions/email_password', payload)
        self.credentials = {}  # the password has one use in this process; do not carry it further
        if not 200 <= reply.status < 300:
            raise RetentionError(f'login refused (HTTP {reply.status}); check the credentials file, the '
                                 'org and whether the store UI is up')
        token = _access_token(reply.body)
        self.candidates = ([('bearer token', {'Authorization': f'Bearer {token}'})] if token else [])
        if reply.cookies:
            self.candidates.append(('session cookie', {'Cookie': cookie_header(reply.cookies)}))
        if not self.candidates:
            raise RetentionError('login succeeded but returned neither an access token nor a session cookie')
        return self.candidates[0][0]

    def _transport_for(self, headers: dict[str, str]) -> Any:
        return self.package if self.package is not None and self.package.usable(headers) else self.transport

    def call(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Response:
        """Issue one authenticated call, trying each session mechanism the login produced."""
        if not self.candidates:
            raise RetentionError('not logged in')
        refusals: list[str] = []
        for offset in range(len(self.candidates)):
            index = (self.chosen + offset) % len(self.candidates)
            label, headers = self.candidates[index]
            reply = self._transport_for(headers).request(method, path, payload, headers=headers)
            if reply.status in (401, 403):
                refusals.append(f'{label}: HTTP {reply.status}')
                continue
            if not 200 <= reply.status < 300:
                raise RetentionError(f'{method} {path.split("?", 1)[0]} failed (HTTP {reply.status})')
            self.chosen, self.auth_label = index, label
            return reply
        raise RetentionError(f'the store refused every session credential ({"; ".join(refusals)})')

    def read(self, signal: str) -> tuple[int, list[Any]]:
        """Read *signal* once: the retention it applies as whole hours, plus any TTL conditions.

        The logs document carries per-condition rules and its write replaces the whole document, so
        they are read here and handed back unchanged by :meth:`set_ttl`; a check or an apply must
        never quietly drop a rule an operator added in the UI. The absence of the field is read as
        no rules, which is what a fresh install carries.
        """
        if signal != 'logs':
            reply = self.call('GET', f'/api/v1/settings/ttl?type={signal}')
            return parse_hours(_field(reply.body, 'ttl', signal=signal), unit='duration'), []
        reply = self.call('GET', '/api/v2/settings/ttl?type=logs')
        hours = parse_hours(_field(reply.body, 'defaultTTLDays', signal=signal), unit='days')
        return hours, _optional(reply.body, 'ttlConditions')

    def set_ttl(self, signal: str, days: int, conditions: Sequence[Any] = ()) -> None:
        """Write the retention for *signal*: hours for traces/metrics, days plus conditions for logs."""
        if signal == 'logs':
            self.call('POST', '/api/v2/settings/ttl',
                      {'type': 'logs', 'defaultTTLDays': days, 'ttlConditions': list(conditions)})
            return
        self.call('POST', f'/api/v1/settings/ttl?type={signal}&duration={days * 24}h')


def _optional(body: Any, key: str) -> list[Any]:
    """Return a list-valued field from a TTL response document, or an empty list when it is absent."""
    data = body.get('data', body) if isinstance(body, dict) else body
    row = next((item for item in data if isinstance(item, dict)), {}) if isinstance(data, list) else data
    value = row.get(key) if isinstance(row, dict) else None
    return value if isinstance(value, list) else []


def file_mode(path: Path) -> int | None:
    """Return the POSIX permission bits of *path*, or None where they do not exist or cannot be read."""
    if os.name != 'posix':
        return None
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return None


def permissions_warning(mode: int | None) -> str | None:
    """Return a one-line warning when *mode* lets others read the credentials file, else None.

    Callers pass None where POSIX bits are meaningless (Windows), so this stays a real check on the
    Linux staging host and not a permanent warning elsewhere.
    """
    if mode is not None and mode & 0o077:
        return f'the credentials file is group- or world-accessible (mode {mode & 0o777:o}); keep it 0600'
    return None


def read_credentials(path: Path) -> dict[str, str]:
    """Read the JSON login material; the password leaves this function and never a message.

    The file is an operator-supplied secret: bounded, an object, and carrying ``email`` plus
    ``password`` (``orgID`` or ``organizationName`` optional). An unrecognised key is refused rather
    than ignored, because a typo in the org field produces a login failure with no explanation.
    """
    try:
        if not path.is_file():
            raise OSError('not a regular file')
        raw = path.read_bytes()
    except OSError:
        raise RetentionError(f'the credentials file {path} is missing or unreadable') from None
    if len(raw) > MAX_CREDENTIALS_BYTES:
        raise RetentionError(f'the credentials file exceeds {MAX_CREDENTIALS_BYTES} bytes')
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise RetentionError(f'the credentials file {path} is not valid JSON') from None
    if not isinstance(document, dict):
        raise RetentionError('the credentials file must hold one JSON object')
    unknown = sorted(set(document) - set(CREDENTIAL_KEYS))
    if unknown:
        raise RetentionError('the credentials file has unsupported key(s): ' + ', '.join(map(str, unknown))
                             + '; allowed: ' + ', '.join(CREDENTIAL_KEYS))
    credentials: dict[str, str] = {}
    for key in CREDENTIAL_KEYS:
        if key not in document:
            continue
        value = document[key]
        if not isinstance(value, (str, int)) or isinstance(value, bool):
            raise RetentionError(f'the credentials file field {key} must be a string or number')
        text = str(value)
        limit = 4096 if key == 'password' else 254 if key == 'email' else 128
        if not text or len(text) > limit:
            raise RetentionError(f'the credentials file field {key} must be 1..{limit} characters')
        if '\x00' in text or (key != 'password' and CONTROL.search(text)):
            raise RetentionError(f'the credentials file field {key} contains control characters')
        credentials[key] = text
    if 'email' not in credentials or 'password' not in credentials:
        raise RetentionError('the credentials file must carry "email" and "password"')
    if 'orgID' not in credentials and 'organizationName' not in credentials:
        raise RetentionError('the credentials file must carry "orgID" or "organizationName"')
    return credentials


def resolve_days(values: dict[str, int | None]) -> dict[str, int]:
    """Fill in the documented defaults and bound every requested number of days."""
    days: dict[str, int] = {}
    for signal in SIGNALS:
        value = values.get(signal)
        if value is None:
            days[signal] = DEFAULT_DAYS[signal]
            continue
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_DAYS:
            raise RetentionError(f'--{signal}-days must be a whole number of days from 1 to {MAX_DAYS}')
        days[signal] = value
    return days


def row(signal: str, expected_days: int, actual_hours: int | None, verdict: str) -> str:
    """Format one aligned status line; *actual_hours* is None when the store could not be read."""
    observed = 'unreadable' if actual_hours is None else format_hours(actual_hours)
    return (f'{signal:<8} expected {expected_days:>4}d ({expected_days * 24:>5}h)  '
            f'store {observed:>18}  {verdict}')


def check(session: StoreSession, expected: dict[str, int], out: Callable[[str], None] = print) -> int:
    """Report the retention the store applies against what is expected; 1 on any mismatch."""
    mismatches = 0
    for signal in SIGNALS:
        try:
            actual, _conditions = session.read(signal)
        except RetentionError as error:
            out(row(signal, expected[signal], None, f'UNKNOWN ({error})'))
            return EXIT_UNAVAILABLE
        if actual != expected[signal] * 24:
            mismatches += 1
        out(row(signal, expected[signal], actual, 'ok' if actual == expected[signal] * 24 else 'MISMATCH'))
    if mismatches:
        out(f'result: {mismatches} of {len(SIGNALS)} signals differ from the expected retention; '
            'run with --apply to set them')
        return EXIT_MISMATCH
    out(f'result: all {len(SIGNALS)} signals match '
        f'({", ".join(f"{signal} {expected[signal]}d" for signal in SIGNALS)})')
    return EXIT_OK


def apply(session: StoreSession, expected: dict[str, int], out: Callable[[str], None] = print) -> int:
    """Set each signal, warn on any shortening, then re-read every signal to prove the write."""
    before: dict[str, int] = {}
    conditions: dict[str, list[Any]] = {}
    for signal in SIGNALS:
        try:
            before[signal], conditions[signal] = session.read(signal)
        except RetentionError as error:
            out(row(signal, expected[signal], None, f'ABORTED, nothing written ({error})'))
            return EXIT_UNAVAILABLE
    written: list[str] = []
    for signal in SIGNALS:
        if conditions[signal]:
            out(f'{signal:<8} keeping {len(conditions[signal])} existing per-condition TTL rule(s)')
        if before[signal] > expected[signal] * 24:
            out(f'{signal:<8} shortening {format_hours(before[signal])} -> {expected[signal]}d: telemetry '
                'older than the new retention WILL BE DELETED by ClickHouse (irreversible)')
        try:
            session.set_ttl(signal, expected[signal], conditions[signal])
        except RetentionError as error:
            # The three settings are independent, so a failure here is a half-applied change. Say
            # which ones are already in force: --apply is idempotent, and guessing is not.
            unset = [item for item in SIGNALS if item not in written]
            out(f'{signal:<8} write failed ({error})')
            out(f'result: PARTIAL APPLY -- in force now: {", ".join(written) or "nothing"}; not set: '
                + ', '.join(unset) + '. Fix the cause and re-run --apply; writing the same value twice '
                'is harmless, and this tool re-reads before it reports success.')
            return EXIT_UNAVAILABLE
        written.append(signal)
    return check(session, expected, out=out)


def build_parser() -> argparse.ArgumentParser:
    """Return the command line: a store URL, a credentials file, three day counts and a mode."""
    parser = argparse.ArgumentParser(prog='retention.py', description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--url', required=True,
                        help='SigNoz UI/API origin, e.g. http://127.0.0.1:18081 (loopback or https)')
    parser.add_argument('--credentials-file', required=True,
                        help='private JSON file with email, password and orgID (mode 0600)')
    parser.add_argument('--traces-days', type=int, default=None,
                        help=f'traces retention in days (default {DEFAULT_DAYS["traces"]})')
    parser.add_argument('--metrics-days', type=int, default=None,
                        help=f'metrics retention in days (default {DEFAULT_DAYS["metrics"]})')
    parser.add_argument('--logs-days', type=int, default=None,
                        help=f'logs retention in days (default {DEFAULT_DAYS["logs"]})')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='read and compare only (the default)')
    mode.add_argument('--apply', action='store_true',
                      help='write the expected retention through the API, then read it back')
    parser.add_argument('--allow-insecure-http', action='store_true',
                        help='permit a plaintext non-loopback URL (a trusted project network only)')
    return parser


def main(argv: list[str] | None = None, *, transport: Any = None) -> int:
    """Run one check or apply pass and return an exit code.

    *transport* is the seam the tests inject; when it is absent the origin is validated and the
    product transport (or the in-module urllib path) is built from it.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        expected = resolve_days({signal: getattr(args, f'{signal}_days') for signal in SIGNALS})
        origin = validate_origin(args.url, allow_insecure_http=args.allow_insecure_http)
        path = Path(args.credentials_file)
        warning = permissions_warning(file_mode(path))
        session = StoreSession(transport or HttpTransport(origin), read_credentials(path),
                               package=None if transport is not None else _package(origin))
        offered = session.login()
        if warning:
            print(f'retention: {warning}', file=sys.stderr)
        print(f'store {origin}  auth offered {offered}')
        return apply(session, expected) if args.apply else check(session, expected)
    except RetentionError as error:
        print(f'retention: {error}', file=sys.stderr)
        return EXIT_UNAVAILABLE


def _package(origin: str) -> PackageTransport | None:
    """Build the product transport when ``local_observe.http`` is importable; stdlib mode otherwise."""
    try:
        return PackageTransport(origin)
    except RetentionError:
        return None


if __name__ == '__main__':
    sys.exit(main())

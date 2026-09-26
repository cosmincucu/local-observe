"""Bounded post-execution verification through the platform's single HTTP writer.

Disabled without LO_VERIFY_FOLLOW_CONFIG. Captured action bindings select telemetry;
neither live policy nor process success can change the meaning of verification.
One pending page is saved before any submission and replayed before discovery.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any
from urllib.parse import urlsplit

from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from local_observe.store.client import MAX_ROWS, MetricSample, ReadOutcome, StoreRefused, Window
from . import verification_cli as bounded
from . import verification_records as records
from .owner import exclusive_owner
from .state import StateError, identifier

log = get_logger(__name__)
CONFIG_ENVIRONMENT = 'LO_VERIFY_FOLLOW_CONFIG'
MAX_CONFIG_BYTES = 16384
MAX_CURSOR_BYTES = 1114112
CONFIG_REQUIRED = {'schema_version', 'platform_url', 'platform_token_file', 'cursor_path',
                   'store_url', 'store_user', 'store_password_file'}
CONFIG_OPTIONAL = {'page_size', 'timeout', 'ca_file', 'store_allow_http'}


class FollowerError(ValueError):
    """Fixed refusal without upstream data, local paths or credentials."""


def _refuse() -> None:
    raise FollowerError('Verification follower refused invalid configuration or state')


def _object(value: Any, keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        _refuse()


def _integer(value: Any, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        _refuse()
    return value


def _path(value: Any) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 4096 or '\0' in value
            or not Path(value).is_absolute()):
        _refuse()
    return value


def _url(value: Any, *, allow_http=False, prefix=False) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        _refuse()
    parsed = urlsplit(value)
    if (parsed.scheme not in (('https', 'http') if allow_http else ('https',))
            or not parsed.hostname or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or (not prefix and parsed.path not in ('', '/'))
            or any(ord(char) <= 32 or ord(char) > 126 for char in value)):
        _refuse()
    # Access validates malformed/out-of-range ports before credential or transport setup.
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        _refuse()
    return value.rstrip('/')


def config(document: Any) -> dict[str, Any]:
    """Validate configuration without opening any file or constructing any client."""
    if (not isinstance(document, dict) or not CONFIG_REQUIRED <= set(document)
            or set(document) - CONFIG_REQUIRED - CONFIG_OPTIONAL):
        _refuse()
    records._plain(document, sentence='Invalid follower configuration')
    _integer(document['schema_version'], 1, 1)
    result = dict(document)
    result['page_size'] = _integer(result.get('page_size', 16), 1, 32)
    result['timeout'] = _integer(result.get('timeout', 10), 1, 20)
    result['store_allow_http'] = result.get('store_allow_http', False)
    if type(result['store_allow_http']) is not bool:
        _refuse()
    result['platform_url'] = _url(result['platform_url'], prefix=True)
    result['store_url'] = _url(result['store_url'], allow_http=result['store_allow_http'])
    for key in ('platform_token_file', 'cursor_path', 'store_password_file'):
        _path(result[key])
    if len({os.path.normcase(os.path.abspath(result[key]))
            for key in ('platform_token_file', 'cursor_path', 'store_password_file')}) != 3:
        _refuse()
    result['ca_file'] = result.get('ca_file')
    if result['ca_file'] is not None:
        _path(result['ca_file'])
    if (not isinstance(result['store_user'], str) or not 1 <= len(result['store_user']) <= 128
            or any(ord(char) < 33 or ord(char) > 126 for char in result['store_user'])):
        _refuse()
    return result


def _read(path: Any, limit: int) -> Any:
    return bounded._document(bounded._text(bounded._read_limited(path, limit)))


def _uuid(value: Any) -> str:
    return bounded._canonical_uuid(value)


def _after(value: Any) -> str | None:
    return None if value is None else _uuid(value)


def _statement(value: Any) -> dict:
    result = records._incoming(value)
    if result != value:
        _refuse()
    return result


def load_cursor(settings: dict) -> dict:
    """Refuse corrupt/foreign cursors without rewriting or replacing their bytes."""
    path = Path(settings['cursor_path'])
    if path.is_symlink():
        _refuse()
    if not path.exists():
        return {'schema_version': 1, 'configuration': digest(settings), 'after': None, 'pending': None}
    state = _read(path, MAX_CURSOR_BYTES)
    _object(state, {'schema_version', 'configuration', 'after', 'pending'})
    _integer(state['schema_version'], 1, 1)
    if state['configuration'] != digest(settings):
        _refuse()
    _after(state['after'])
    pending = state['pending']
    if pending is not None:
        _object(pending, {'next_after', 'statements', 'fingerprint', 'next_index'})
        _after(pending['next_after'])
        statements = pending['statements']
        if not isinstance(statements, list) or not 1 <= len(statements) <= settings['page_size']:
            _refuse()
        _integer(pending['next_index'], 0, len(statements))
        seen = set()
        for statement in statements:
            normalized = _statement(statement)
            if normalized['execution_id'] in seen:
                _refuse()
            seen.add(normalized['execution_id'])
        if pending['fingerprint'] != digest(statements):
            _refuse()
    return state


def _save(settings: dict, state: dict) -> None:
    raw = canonical(state).encode()
    if len(raw) > MAX_CURSOR_BYTES:
        _refuse()
    destination = Path(settings['cursor_path'])
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=destination.parent,
                                         prefix=destination.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
        if os.name != 'nt':
            descriptor = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _get(platform: Any, path: str) -> Any:
    status, response = platform.request('GET', path)
    if status != 200:
        raise FollowerError('Verification follower platform read refused')
    return response


def candidates(response: Any, after: str | None, limit: int) -> tuple[list[dict], str | None]:
    """Validate even empty filtered pages: next_after describes scanned rows, not items."""
    _object(response, {'items', 'next_after'})
    next_after = _after(response['next_after'])
    if next_after is not None and after is not None and next_after <= after:
        _refuse()
    items = response['items']
    if not isinstance(items, list) or len(items) > limit:
        _refuse()
    previous = after
    for item in items:
        _object(item, {'execution_id', 'action_id', 'finished_at'})
        execution = _uuid(item['execution_id'])
        _uuid(item['action_id'])
        records._instant(item['finished_at'], 'Invalid terminal timestamp')
        if ((previous is not None and execution <= previous)
                or (next_after is not None and execution > next_after)):
            _refuse()
        previous = execution
    return items, next_after


def captured_binding(response: Any, action_id: str) -> tuple[str, dict]:
    _object(response, {'action_id', 'status', 'reason', 'binding_id', 'origin'})
    if response['action_id'] != action_id or response['status'] != 'bound' or response['reason'] != 'matched':
        _refuse()
    _object(response['origin'], set(records.MAPPING_KEYS) | {'event_id', 'action_targets'})
    origin = records._mapping({key: response['origin'][key] for key in records.MAPPING_KEYS})
    origin['event_id'] = _uuid(response['origin']['event_id'])
    if response['origin']['action_targets'] != [origin['resource_id']]:
        _refuse()
    origin['action_targets'] = [origin['resource_id']]
    binding_id = bounded._hex64(response['binding_id'])
    if binding_id != digest(origin):
        _refuse()
    return binding_id, origin


def observation(execution_id: str, binding_id: str, origin: dict, window: Window,
                outcome: ReadOutcome, *, now: dt.datetime) -> dict:
    """Convert actual typed rows without rewriting their identity or hiding incomplete evidence."""
    if not isinstance(outcome, ReadOutcome):
        _refuse()
    receipt = records._receipt(outcome.receipt.as_dict())
    if (receipt['query_type'] != origin['query_type'] or receipt['parameters'] != origin['parameters']
            or receipt['window'] != window.as_dict()):
        _refuse()
    if not isinstance(outcome.samples, (tuple, list)) or len(outcome.samples) > MAX_ROWS:
        _refuse()
    if outcome.status == 'available':
        if len(outcome.samples) != receipt['sample_count']:
            _refuse()
        converted = []
        for sample in outcome.samples:
            if not isinstance(sample, MetricSample):
                _refuse()
            row = {'metric_name': sample.name, 'resource_id': sample.resource_id,
                   'observed_at': sample.timestamp, 'value': sample.value}
            # Validate every row before selecting an excerpt; off-origin rows are never repaired.
            row = records._samples([row], window.as_dict())[0]
            if row['metric_name'] != origin['metric_name'] or row['resource_id'] != origin['resource_id']:
                _refuse()
            if len(converted) < records.SAMPLE_LIMIT:
                converted.append(row)
        if len(outcome.samples) > records.SAMPLE_LIMIT:
            receipt['truncated'] = True  # A client-bounded excerpt, preserving the original row count.
    else:
        if outcome.samples or outcome.status not in ('unavailable', 'expired'):
            _refuse()
        converted = []
    statement = records._incoming({'execution_id': execution_id, 'binding_id': binding_id,
                                  'window': window.as_dict(), 'outcome': outcome.status,
                                  'receipt': receipt, 'samples': converted})
    records._check_scope(statement, origin, now)
    return statement


def _deliver(settings: dict, state: dict, platform: Any) -> int:
    pending = state['pending']
    delivered = 0
    while pending['next_index'] < len(pending['statements']):
        statement = pending['statements'][pending['next_index']]
        expected = digest([statement['execution_id'], statement['binding_id'], statement['window']])
        status, answer = platform.request('POST', '/v1/verification/records', statement)
        if (status != 200 or not isinstance(answer, dict) or set(answer) != {'verification_id', 'created'}
                or answer['verification_id'] != expected or type(answer['created']) is not bool):
            raise FollowerError('Verification acknowledgement refused; exact pending batch retained')
        pending['next_index'] += 1
        _save(settings, state)
        delivered += 1
    state['after'], state['pending'] = pending['next_after'], None
    _save(settings, state)
    return delivered


def tick(settings: dict, platform: Any, store_factory: Any, *, now: dt.datetime) -> dict:
    """One owned cursor, at most one page, and no telemetry/discovery until pending replay finishes."""
    settings = config(settings)
    moment = records._clock(now)
    with exclusive_owner(settings['cursor_path']):
        state = load_cursor(settings)
        if state['pending'] is not None:
            return {'status': 'replayed', 'submitted': _deliver(settings, state, platform), 'refused': 0}
        path = '/v1/verification/candidates?limit=' + str(settings['page_size'])
        if state['after'] is not None:
            path += '&after=' + state['after']
        items, next_after = candidates(_get(platform, path), state['after'], settings['page_size'])
        statements, refused, waiting = [], 0, 0
        telemetry = None
        for item in items:
            try:
                binding_id, origin = captured_binding(_get(platform, '/v1/verification/binding?action_id='
                                                          + item['action_id']), item['action_id'])
                start = moment - dt.timedelta(seconds=origin['window_seconds'])
                if start < timestamp(item['finished_at']):
                    waiting += 1
                    continue
                window = Window(utc_text(start), utc_text(moment))
                if telemetry is None:
                    telemetry = store_factory()
                outcome = telemetry.read(origin['query_type'], window=window,
                                         parameters=dict(origin['parameters']),
                                         selectors={'metric_name': origin['metric_name']})
                statements.append(observation(item['execution_id'], binding_id, origin, window, outcome, now=moment))
            except (FollowerError, StateError, StoreRefused, TransportError, ValueError, TypeError,
                    KeyError, AttributeError, bounded._Refused) as exc:
                refused += 1
                log.warning('Verification candidate refused; no statement submitted; retry on next sweep',
                            extra={'execution_id': item['execution_id'], 'error_class': type(exc).__name__})
        if statements:
            state['pending'] = {'next_after': next_after, 'statements': statements,
                                'fingerprint': digest(statements), 'next_index': 0}
            _save(settings, state)
            submitted = _deliver(settings, state, platform)
        else:
            state['after'] = next_after
            _save(settings, state)
            submitted = 0
        return {'status': 'completed', 'submitted': submitted, 'refused': refused, 'waiting': waiting}


def _store(settings: dict):
    from local_observe.store.backends.clickhouse import store_from_environment
    return store_from_environment({'LO_CLICKHOUSE_URL': settings['store_url'],
                                   'LO_CLICKHOUSE_USER': settings['store_user'],
                                   'LO_CLICKHOUSE_PASSWORD_FILE': settings['store_password_file'],
                                   'LO_INTERNAL_ALLOW_HTTP': '1' if settings['store_allow_http'] else '0'})


def run(config_path: str | None = None, *, environ=None, now=None) -> int:
    """One-shot scheduler entry; an absent opt-in returns before all file/client/credential I/O."""
    values = os.environ if environ is None else environ
    selected = config_path if config_path is not None else values.get(CONFIG_ENVIRONMENT)
    if selected is None or (isinstance(selected, str) and not selected.strip()):
        return 0
    try:
        settings = config(_read(selected, MAX_CONFIG_BYTES))
        # Validate a pre-existing cursor before reading credentials or constructing clients.
        load_cursor(settings)
        platform = JsonClient(settings['platform_url'], bounded._token(settings['platform_token_file']),
                              timeout=settings['timeout'], ca_file=settings['ca_file'])
        result = tick(settings, platform, lambda: _store(settings),
                      now=dt.datetime.now(dt.timezone.utc) if now is None else now)
        print(json.dumps(result, sort_keys=True))
        return 1 if result['refused'] else 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, TransportError, bounded._Refused):
        print('{"status":"error","error_type":"VerificationFollowerError"}')
        return 1


def add_parser(sub):
    parser = sub.add_parser('verify-follow', allow_abbrev=False,
                           help='follow one page of terminal executions over HTTPS')
    parser.add_argument('--config', help='mounted JSON configuration; otherwise LO_VERIFY_FOLLOW_CONFIG')
    parser.add_argument('--loop', action='store_true', help='explicitly enable scheduled bounded rounds')
    parser.add_argument('--interval', type=int, default=30, help='loop interval in seconds (5..3600)')


def schedule(config_path=None, *, loop=False, interval=30, environ=None,
             stop=None, sleep=None, clock=None) -> int:
    """Opt-in scheduler: reload config/cursor each round, never carry mutable pending state in memory."""
    values = os.environ if environ is None else environ
    selected = config_path if config_path is not None else values.get(CONFIG_ENVIRONMENT)
    if selected is None or (isinstance(selected, str) and not selected.strip()):
        return 0
    if type(loop) is not bool or type(interval) is not int or not 5 <= interval <= 3600:
        print('{"status":"error","error_type":"VerificationFollowerError"}')
        return 1
    sleeper = time.sleep if sleep is None else sleep
    clock = (lambda: dt.datetime.now(dt.timezone.utc)) if clock is None else clock
    result = 0
    while stop is None or not stop():
        result = run(config_path, environ=values, now=clock())
        if not loop:
            return result
        if result:
            log.warning('Verification follower round failed; durable pending state retained')
        sleeper(interval)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--config')
    parser.add_argument('--loop', action='store_true')
    parser.add_argument('--interval', type=int, default=30)
    args = parser.parse_args()
    return schedule(args.config, loop=args.loop, interval=args.interval)


if __name__ == '__main__':
    raise SystemExit(main())

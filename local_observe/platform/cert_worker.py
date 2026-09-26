"""Default-off certificate facts delivery; one configured target and one owned cursor."""
import argparse
import datetime as dt
import json
import math
import os
from pathlib import Path
import tempfile
import time
import uuid
from urllib.parse import urlsplit

from local_observe.credentials import read_credential
from local_observe.http import JsonClient
from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from .assertions import safe_name
from .certcheck import DEFAULT_THRESHOLDS, run_cert_check
from .cert_measurement import TLSProvider, validate_target
from .owner import exclusive_owner
from .state import identifier, label, validate_event

log = get_logger(__name__)
MAX_CONFIG = 16384
MAX_CURSOR = 131072


class WorkerError(ValueError):
    """Fixed refusal without credential, target or remote response text."""


def refuse():
    raise WorkerError('Certificate worker refused configuration, cursor or acknowledgement')


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        refuse()
    return value


def path_value(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 4096 or '\0' in value or not Path(value).is_absolute():
        refuse()
    return value


def config(value):
    required = {'schema_version', 'host', 'connect_ip', 'resource_id', 'rule_id', 'source',
                'platform_url', 'platform_token_file', 'cursor_path'}
    optional = {'port', 'timeout', 'thresholds', 'interval', 'tls_ca_file', 'platform_ca_file'}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
        refuse()
    result = dict(value)
    integer(result['schema_version'], 1, 1)
    result['port'] = integer(result.get('port', 443), 1, 65535)
    result['timeout'] = integer(result.get('timeout', 10), 1, 20)
    result['interval'] = integer(result.get('interval', 60), 5, 3600)
    validate_target(result['host'], result['connect_ip'], result['port'], result['timeout'])
    safe_name(result['rule_id'])
    identifier(result['resource_id'])
    label(result['source'])
    result['thresholds'] = result.get('thresholds', list(DEFAULT_THRESHOLDS))
    stages = result['thresholds']
    if (not isinstance(stages, list) or not 1 <= len(stages) <= 16
            or any(type(s) is not int or not 1 <= s <= 36500 for s in stages)
            or stages != sorted(set(stages), reverse=True)):
        refuse()
    url = result['platform_url']
    if not isinstance(url, str) or not 1 <= len(url) <= 4096 or any(ord(c) <= 32 or ord(c) > 126 for c in url):
        refuse()
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment):
        refuse()
    if parsed.port is not None:
        integer(parsed.port, 1, 65535)
    result['platform_url'] = url.rstrip('/')
    paths = [path_value(result[k]) for k in ('cursor_path', 'platform_token_file')]
    for key in ('tls_ca_file', 'platform_ca_file'):
        result[key] = result.get(key)
        if result[key] is not None:
            paths.append(path_value(result[key]))
    # The writable cursor and its lock must never alias a mounted credential/CA.
    cursor = os.path.normcase(os.path.abspath(paths[0]))
    if any(os.path.normcase(os.path.abspath(p)) in (cursor, cursor + '.owner.lock') for p in paths[1:]):
        refuse()
    return result


def read_json(path, limit):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                refuse()
            value[key] = item
        return value
    with Path(path).open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        refuse()
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: refuse())
    except (ValueError, UnicodeError, RecursionError):
        refuse()


def validate_batch(batch, settings):
    if not isinstance(batch, dict) or set(batch) != {'observed_at', 'samples', 'events'}:
        refuse()
    moment = timestamp(batch['observed_at'])
    samples, events = batch['samples'], batch['events']
    if not isinstance(samples, list) or len(samples) not in (0, 3):
        refuse()
    if not isinstance(events, list) or not 1 <= len(events) <= 19:
        refuse()
    ids = set()
    for sample in samples:
        if (not isinstance(sample, dict) or set(sample) != {'sample_id', 'observed_at', 'ok', 'value'}
                or sample['observed_at'] != batch['observed_at'] or sample['ok'] is not True
                or type(sample['value']) not in (bool, int, float) or not math.isfinite(sample['value'])
                or not isinstance(sample['sample_id'], str) or len(sample['sample_id']) != 64
                or sample['sample_id'] in ids):
            refuse()
        ids.add(sample['sample_id'])
    conditions = {settings['rule_id'] + '.' + suffix for suffix in
                  ['fetch-error', 'chain-valid', 'hostname-matches-san'] +
                  [f'expiry-{stage}d' for stage in settings['thresholds']]}
    seen = set()
    for event in events:
        validate_event(event, moment)
        if (event['source'] != settings['source'] or event['resource_id'] != settings['resource_id']
                or event['observed_at'] != batch['observed_at'] or event['rule_id'] not in conditions
                or event['condition'] != event['rule_id'] or event['rule_id'] in seen):
            refuse()
        seen.add(event['rule_id'])
        for reference in event['evidence']:
            params = reference['parameters']
            if (reference['source'] != settings['source'] or params.get('rule_id') != event['rule_id']
                    or set(params) - {'rule_id', 'sample_id'}
                    or ('sample_id' in params and params['sample_id'] not in ids)):
                refuse()


def load_cursor(settings):
    path = Path(settings['cursor_path'])
    if path.is_symlink():
        refuse()
    if not path.exists():
        return {'schema_version': 1, 'configuration': digest(settings), 'last_at': None, 'pending': None}
    state = read_json(path, MAX_CURSOR)
    if (not isinstance(state, dict) or set(state) != {'schema_version', 'configuration', 'last_at', 'pending'}
            or type(state['schema_version']) is not int or state['schema_version'] != 1
            or state['configuration'] != digest(settings)):
        refuse()
    if state['last_at'] is not None:
        timestamp(state['last_at'])
    if state['pending'] is not None:
        pending = state['pending']
        if not isinstance(pending, dict) or set(pending) != {'batch', 'fingerprint'}:
            refuse()
        validate_batch(pending['batch'], settings)
        if pending['fingerprint'] != digest(pending['batch']):
            refuse()
        if state['last_at'] is not None and timestamp(pending['batch']['observed_at']) <= timestamp(state['last_at']):
            refuse()
    return state


def save(settings, state):
    raw = canonical(state).encode()
    if len(raw) > MAX_CURSOR:
        refuse()
    destination = Path(settings['cursor_path'])
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
        if os.name != 'nt':
            fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def tick(settings, platform, provider_factory, *, now):
    settings = config(settings)
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() is None:
        refuse()
    with exclusive_owner(settings['cursor_path']):
        state = load_cursor(settings)
        replay = state['pending'] is not None
        if not replay:
            if (state['last_at'] is not None
                    and (now - timestamp(state['last_at'])).total_seconds() < settings['interval']):
                return 'idle'
            result = run_cert_check(settings['rule_id'], settings['resource_id'], settings['host'],
                                    provider_factory(), clock=lambda: now, source=settings['source'],
                                    port=settings['port'], thresholds=settings['thresholds'])
            batch = {'observed_at': utc_text(now), 'samples': result.samples, 'events': result.events}
            validate_batch(batch, settings)
            state['pending'] = {'batch': batch, 'fingerprint': digest(batch)}
            save(settings, state)
        batch = state['pending']['batch']
        for sample in batch['samples']:
            status, response = platform.request('POST', '/v1/evidence', sample)
            if status != 200 or response != {'evidence_id': digest([settings['source'], sample['sample_id']])}:
                refuse()
        for event in batch['events']:
            status, response = platform.request('POST', '/v1/events', event)
            expected = str(uuid.uuid5(uuid.NAMESPACE_URL, canonical([event['source'], event['source_event_id']])))
            if (status != 200 or not isinstance(response, dict) or response.get('event_id') != expected
                    or response.get('status') not in ('accepted', 'duplicate')):
                refuse()
        state['last_at'], state['pending'] = batch['observed_at'], None
        save(settings, state)
        return 'replayed' if replay else 'delivered'


def run(config_path=None, *, loop=False, environ=None, sleep=time.sleep, clock=None, stop=lambda: False):
    env = os.environ if environ is None else environ
    selected = config_path if config_path is not None else env.get('LO_CERT_CONFIG', '')
    if not selected or not str(selected).strip():
        return 0
    while True:
        interval = 60
        try:
            settings = config(read_json(path_value(str(selected)), MAX_CONFIG))
            interval = settings['interval']
            # Refuse corrupt state before credentials or client construction.
            load_cursor(settings)
            token = read_credential('LO_CERT_TOKEN', environ={'LO_CERT_TOKEN_FILE': settings['platform_token_file']})
            platform = JsonClient(settings['platform_url'], token, timeout=settings['timeout'],
                                  ca_file=settings['platform_ca_file'])
            factory = lambda settings=settings: TLSProvider(settings['connect_ip'], timeout=settings['timeout'],
                                          ca_file=settings['tls_ca_file'])
            tick(settings, platform, factory, now=clock() if clock else dt.datetime.now(dt.timezone.utc))
            result = 0
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            log.warning('Certificate worker round refused; pending delivery retained')
            result = 1
        if not loop or stop():
            return result
        sleep(interval)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--config')
    parser.add_argument('--loop', action='store_true')
    args = parser.parse_args(argv)
    return run(args.config, loop=args.loop)


if __name__ == '__main__':
    raise SystemExit(main())

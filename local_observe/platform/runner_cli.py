"""Run one bounded trusted-runner pass, or poll under one process ownership lock."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from urllib.parse import urlsplit

from local_observe.deployment.guided_files import directory, private_lock, protected
from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import canonical, digest
from .runner_handoff import check_binding, immutable_dag, run_request, strict_request
from .state import StateError, identifier, label


class RunnerError(ValueError):
    """Fixed public codes; never include credential/config/transport contents."""


def path(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or not Path(value).is_absolute() or '..' in Path(value).parts):
        raise RunnerError('invalid_config_path')
    return Path(value)


def private_bytes(value, limit):
    """Read only an owned regular private file, anchoring each directory component."""
    target = path(value)
    try:
        with directory(target.parent) as parent:
            fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                        or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_size > limit):
                    raise RunnerError('unsafe_private_file')
                result = stream.read(limit + 1)
                if not result or len(result) > limit:
                    raise RunnerError('invalid_private_file_size')
                return result
    except (OSError, StateError):
        raise RunnerError('private_file_unavailable') from None


def credential(value):
    try:
        token = private_bytes(value, 4096).decode('ascii').removesuffix('\n')
    except UnicodeError:
        raise RunnerError('invalid_credential_file') from None
    if not 24 <= len(token) <= 4096 or re.search(r'[\x00-\x20\x7f]', token):
        raise RunnerError('invalid_credential_file')
    return token


def endpoint(value, *, engine=False):
    required = {'url', 'credential_file'}
    if not isinstance(value, dict) or not required <= set(value) <= required | ({'scheme'} if engine else set()):
        raise RunnerError('invalid_endpoint_config')
    url = value['url']
    try:
        if not isinstance(url, str) or len(url) > 2048 or any(char.isspace() for char in url):
            raise ValueError
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
            raise ValueError
        _ = parsed.port
    except ValueError:
        raise RunnerError('endpoint_requires_https_origin') from None
    path(value['credential_file'])
    if engine and value.get('scheme', 'Bearer') not in ('Basic', 'Bearer'):
        raise RunnerError('invalid_engine_auth_scheme')
    return dict(value)


def configuration(value):
    required = {'schema_version', 'identity', 'platform', 'engine', 'journal_root', 'immutable_dag_root', 'bindings'}
    if (not isinstance(value, dict) or not required <= set(value) <= required | {'poll_seconds', 'timeout_seconds'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        raise RunnerError('invalid_runner_config')
    try:
        label(value['identity'])
        platform = endpoint(value['platform'])
        engine = endpoint(value['engine'], engine=True)
        if path(platform['credential_file']) == path(engine['credential_file']):
            raise RunnerError('separate_credential_files_required')
        for key in ('journal_root', 'immutable_dag_root'):
            path(value[key])
        if not isinstance(value['bindings'], list) or not 1 <= len(value['bindings']) <= 32:
            raise RunnerError('invalid_runner_bindings')
        bindings = [check_binding(item) for item in value['bindings']]
        keys = [canonical([item[key] for key in ('action', 'version', 'targets')]) for item in bindings]
        if len(keys) != len(set(keys)):
            raise RunnerError('ambiguous_runner_bindings')
        for binding in bindings:
            if not binding['dag'].endswith('-' + binding['sha256'][:16]):
                raise RunnerError('versioned_dag_required')
        poll, timeout = value.get('poll_seconds', 10), value.get('timeout_seconds', 10)
        if type(poll) is not int or not 1 <= poll <= 300 or type(timeout) is not int or not 1 <= timeout <= 20:
            raise RunnerError('invalid_runner_time_bounds')
        return {**value, 'platform': platform, 'engine': engine, 'bindings': bindings,
                'poll_seconds': poll, 'timeout_seconds': timeout}
    except StateError:
        raise RunnerError('invalid_runner_binding_or_identity') from None


def load_configuration(filename):
    try:
        return configuration(strict_request(private_bytes(filename, 65536)))
    except (StateError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise RunnerError('invalid_runner_config') from None


def clients(config):
    """No environment-value fallback; two separate protected mounted credentials."""
    platform_token = credential(config['platform']['credential_file'])
    engine_token = credential(config['engine']['credential_file'])
    if secrets.compare_digest(platform_token, engine_token):
        raise RunnerError('independent_credentials_required')
    return (JsonClient(config['platform']['url'], platform_token, timeout=config['timeout_seconds']),
            JsonClient(config['engine']['url'], engine_token, timeout=config['timeout_seconds'],
                       scheme=config['engine'].get('scheme', 'Bearer')))


@contextmanager
def ownership(config):
    """One OS-held lock across all passes, released by the kernel on crash."""
    try:
        with directory(path(config['journal_root'])) as fd:
            identity = protected(fd)
            with private_lock(fd, 'trusted-runner-process'):
                yield identity
    except OSError:
        raise RunnerError('runner_storage_unavailable_or_busy') from None


def preflight(config, root_identity):
    with directory(path(config['journal_root'])) as fd:
        if protected(fd) != root_identity:
            raise RunnerError('runner_storage_changed')
    try:
        for binding in config['bindings']:
            with immutable_dag(path(config['immutable_dag_root']), binding):
                pass
    except (OSError, StateError):
        raise RunnerError('immutable_dag_unavailable') from None


def one_pass(config, platform, engine):
    """At most twenty requests from one validated queue snapshot, with no inline retry."""
    code, identity = platform.request('GET', '/v1/me')
    if code != 200 or identity != {'identity': config['identity'], 'role': 'executor'}:
        raise RunnerError('runner_identity_mismatch')
    code, body = platform.request('GET', '/v1/runner/requests')
    if code != 200:
        raise RunnerError('runner_handoff_unavailable')
    if not isinstance(body, dict) or set(body) != {'requests'}:
        raise RunnerError('invalid_runner_queue')
    requests = body['requests']
    if not isinstance(requests, list) or len(requests) > 20:
        raise RunnerError('invalid_runner_queue')
    bindings = {digest(binding): binding for binding in config['bindings']}
    ids = set()
    for request in requests:
        if not isinstance(request, dict) or set(request) != {'action_id', 'binding_sha256'}:
            raise RunnerError('invalid_runner_queue')
        try:
            identifier(request['action_id'])
        except StateError:
            raise RunnerError('invalid_runner_queue') from None
        binding_hash = request['binding_sha256']
        if not isinstance(binding_hash, str) or binding_hash not in bindings:
            raise RunnerError('queued_binding_not_configured')
        if request['action_id'] in ids:
            raise RunnerError('duplicate_queued_action')
        ids.add(request['action_id'])
    results = []
    for request in requests:
        try:
            result = run_request(platform, engine, request, bindings[request['binding_sha256']],
                                 config['journal_root'], immutable_dag_root=config['immutable_dag_root'])
            if (not isinstance(result, dict) or set(result) != {'status', 'execution_id'}
                    or result['status'] not in ('executing', 'succeeded', 'failed', 'unknown')):
                raise RunnerError('invalid_execution_receipt')
            identifier(result['execution_id'])
            results.append({'action_id': request['action_id'], 'status': result['status'],
                            'execution_id': result['execution_id']})
        except (OSError, ValueError, KeyError, TypeError):
            # The runner journal remains authoritative after any uncertain I/O. An
            # error is reported without echoing upstream data or silently requeuing.
            results.append({'action_id': request['action_id'], 'status': 'refused',
                            'reason': 'execution_unavailable_inspect_journal'})
            break
        if result['status'] in ('failed', 'unknown'):
            break
    attention = any(item['status'] in ('refused', 'failed', 'unknown') for item in results)
    return {'status': 'attention' if attention else ('processed' if results else 'idle'),
            'runner': config['identity'], 'results': results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='owned 0400/0600 JSON configuration file')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--once', action='store_true', help='one bounded pass (default)')
    mode.add_argument('--poll', action='store_true', help='repeat bounded passes under one process lock')
    args = parser.parse_args(argv)
    try:
        config = load_configuration(args.config)
        with ownership(config) as root_identity:
            preflight(config, root_identity)
            platform, engine = clients(config)
            while True:
                result = one_pass(config, platform, engine)
                print(canonical(result), flush=True)
                if result['status'] == 'attention':
                    return 2
                if not args.poll:
                    return 0
                time.sleep(config['poll_seconds'])
                preflight(config, root_identity)
    except RunnerError as exc:
        print(canonical({'status': 'refused', 'reason': str(exc)}), file=sys.stderr)
        return 2
    except TransportError:
        print(canonical({'status': 'refused', 'reason': 'runner_transport_unavailable'}), file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError):
        print(canonical({'status': 'refused', 'reason': 'runner_configuration_or_storage_unavailable'}),
              file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())

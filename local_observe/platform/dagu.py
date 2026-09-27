"""Dispatch one approved, exact allowlisted DAG; recovery only observes, never redispatches."""
import hashlib
from contextlib import nullcontext
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any
import uuid

from local_observe.http import JsonClient, TransportError
from local_observe.log import get_logger

log = get_logger(__name__)


def save(path, value, *, directory_fd=None):
    """Token-bearing journals use exclusive 0600 temporary files in a private parent."""
    from local_observe.deployment.guided_files import directory, protected
    with directory(path.parent.absolute()) if directory_fd is None else nullcontext(directory_fd) as fd:
        protected(fd)
        name = path.name + '.' + secrets.token_hex(16) + '.tmp'
        handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)


def execute(platform: JsonClient, dagu: JsonClient, action_id: str, binding: dict[str, Any],
            journal_path: Path | str, *, directory_fd=None) -> dict[str, Any]:
    """Caller credentials must be executor-only, never human approver credentials."""
    uuid.UUID(action_id)
    if not re.fullmatch('[A-Za-z0-9_-]{1,80}', binding['dag']):
        raise ValueError('Only an explicitly bound DAG name is permitted')
    journal = Path(journal_path)
    from local_observe.deployment.guided_files import directory, protected
    with directory(journal.parent.absolute()) if directory_fd is None else nullcontext(directory_fd) as fd:
        protected(fd)
        return _execute(platform, dagu, action_id, binding, journal, fd)


def _execute(platform, dagu, action_id, binding, journal, fd):
    from local_observe.deployment.guided_files import private_lock, read_file
    with private_lock(fd, journal.name):
        if journal.name in os.listdir(fd):
            state = json.loads(read_file(fd, journal.name))
            if state['action_id'] != action_id or state['binding'] != binding:
                raise ValueError('Journal action/binding mismatch')
            if state.get('finished'):
                log.info('Execution journal already closed', extra={'execution_id': state['claim']['execution_id'],
                                                                   'outcome': state['outcome']})
                return {'status': state['outcome'], 'execution_id': state['claim']['execution_id']}
        else:
            status, spec = dagu.request('GET', '/api/v1/dags/' + binding['dag'] + '/spec')
            if status != 200 or hashlib.sha256(spec['spec'].encode()).hexdigest() != binding['sha256']:
                raise ValueError('DAG specification differs from reviewed binding')
            code, claim = platform.request('POST', '/v1/actions/claim', {'action_id': action_id})
            if code != 200 or claim.get('status') not in ('executing', 'recovering'):
                raise ValueError('No approved platform claim; nothing dispatched')
            request = claim['request']
            state = {'action_id': action_id, 'binding': binding, 'claim': claim, 'outcome': None, 'finished': False}
            log.info('Execution claimed', extra={'execution_id': claim['execution_id'], 'action_id': action_id})
            if (request['action'], request['version'], request['targets'], request['parameters']) != (
                    binding['action'], binding['version'], binding['targets'], {}):
                state['outcome'] = 'failed'
                log.warning('Claimed request differs from the reviewed binding; nothing dispatched',
                            extra={'execution_id': claim['execution_id'], 'outcome': 'failed'})
                save(journal, state, directory_fd=fd)
            elif claim['status'] == 'recovering':
                # The claim response was lost before this journal was saved. A previous
                # process might have dispatched; observation is the only safe recovery.
                save(journal, state, directory_fd=fd)
            else:
                # Persist before the external effect. After a crash this path can only GET status.
                save(journal, state, directory_fd=fd)
                try:
                    code, response = dagu.request('POST', '/api/v1/dags/' + binding['dag'] + '/start',
                                                   {'dagRunId': claim['execution_id'], 'params': '{}'})
                    if code != 200 or response.get('dagRunId') != claim['execution_id']:
                        state['outcome'] = 'unknown'
                        log.warning('Dispatch outcome unknown; the run is polled, never redispatched',
                                    extra={'execution_id': claim['execution_id'], 'outcome': 'unknown'})
                    else:
                        log.info('Execution dispatched', extra={'execution_id': claim['execution_id']})
                except TransportError as exc:
                    log.warning('Dispatch transport failed; the run is polled, never redispatched',
                                extra={'execution_id': claim['execution_id'], 'error_class': type(exc).__name__})
        if state['outcome'] is None:
            try:
                code, response = dagu.request(
                    'GET', '/api/v1/dag-runs/' + binding['dag'] + '/' + state['claim']['execution_id'])
                run = response.get('dagRunDetails', {}) if isinstance(response, dict) else {}
                if (code == 200 and run.get('dagRunId') == state['claim']['execution_id']
                        and run.get('name') == binding['dag']):
                    result = run.get('statusLabel')
                    if result in ('succeeded', 'failed'):
                        state['outcome'] = result
                    elif result in ('running', 'queued', 'waiting', 'not started'):
                        log.info('Execution status polled', extra={'execution_id': state['claim']['execution_id'],
                                                                  'run_status': result})
                        return {'status': 'executing', 'execution_id': state['claim']['execution_id']}
                    else:
                        state['outcome'] = 'unknown'
                else:
                    state['outcome'] = 'unknown'
                if state['outcome'] == 'unknown':
                    log.warning('Execution status unreadable; recorded as unknown',
                                extra={'execution_id': state['claim']['execution_id'], 'status_code': code})
            except TransportError as exc:
                log.warning('Execution status poll failed; recorded as unknown',
                            extra={'execution_id': state['claim']['execution_id'], 'error_class': type(exc).__name__})
                state['outcome'] = 'unknown'
        save(journal, state, directory_fd=fd)
        payload = {key: state['claim'][key] for key in ('execution_id', 'runner_token')}
        payload['outcome'] = state['outcome']
        code, result = platform.request('POST', '/v1/executions/outcome', payload)
        if code != 200:
            log.warning('Outcome intake refused; journal retained',
                        extra={'execution_id': state['claim']['execution_id'], 'outcome': state['outcome'],
                               'status_code': code})
            raise TransportError('Outcome intake refused; journal retained')
        state['finished'] = True
        save(journal, state, directory_fd=fd)
        log.info('Outcome posted', extra={'execution_id': state['claim']['execution_id'], 'outcome': state['outcome'],
                                         'status': result['status']})
        return {'status': result['status'], 'execution_id': state['claim']['execution_id']}

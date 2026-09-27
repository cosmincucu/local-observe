"""Durable requests for explicitly configured runners; never send claims to an agent."""
from __future__ import annotations

import json
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import stat

from local_observe.inventory.validation import canonical, digest, utc_text
from . import dagu
from .state import StateError, clock, identifier, label, require


def protected_state(store):
    """New authority records require protected existing platform runtime storage."""
    from local_observe.deployment.guided_files import directory, protected
    with directory(store.path.absolute().parent) as fd:
        protected(fd)
        info = os.stat(store.path.name, dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise StateError('Runner platform database must be owned and mode 0600')


def strict_request(raw):
    """New authority-bearing endpoints reject duplicate keys, depth and nonfinite values."""
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise StateError('Duplicate request field')
            value[key] = item
        return value
    def constant(_):
        raise StateError('Nonfinite request value')
    def bounded(value, depth=0):
        if depth > 12:
            raise StateError('Request nesting exceeds bound')
        if isinstance(value, (dict, list)):
            if len(value) > 128:
                raise StateError('Request collection exceeds bound')
            for child in value.values() if isinstance(value, dict) else value:
                bounded(child, depth + 1)
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        bounded(value)
        return value
    except RecursionError:
        raise StateError('Request nesting exceeds bound') from None


@contextmanager
def immutable_dag(root, binding):
    """Require a versioned spec on a read-only mount shared with the Dagu engine.

    The operator must mount this same source at Dagu's DAG directory and disable its
    alternate mutable configuration sources. That mapping requires deployment acceptance;
    the runner refuses a missing or writable local mount. A digest check alone is insufficient.
    """
    from local_observe.deployment.guided_files import directory, sha
    if root is None or not binding['dag'].endswith('-' + binding['sha256'][:16]):
        raise StateError('Runner requires an immutable versioned DAG mount')
    with directory(Path(root)) as fd:
        if not os.fstatvfs(fd).f_flag & os.ST_RDONLY:
            raise StateError('Runner DAG mount must be read-only')
        handle = os.open(binding['dag'] + '.yaml', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(handle, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise StateError('Unsafe immutable DAG specification')
            if sha(stream.read(65537)) != binding['sha256']:
                raise StateError('Immutable DAG specification differs')
            yield


def check_binding(value):
    """Bindings are operator configuration, never supplied by a request."""
    if not isinstance(value, dict) or set(value) != {'action', 'version', 'targets', 'dag', 'sha256'}:
        raise StateError('Invalid runner binding')
    label(value['action'])
    label(value['version'])
    if (not isinstance(value['dag'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', value['dag'])
            or not isinstance(value['sha256'], str) or not re.fullmatch(r'[a-f0-9]{64}', value['sha256'])
            or not isinstance(value['targets'], list) or not 1 <= len(value['targets']) <= 20):
        raise StateError('Invalid runner binding')
    for target in value['targets']:
        identifier(target)
    if len(set(value['targets'])) != len(value['targets']):
        raise StateError('Invalid runner binding')
    return json.loads(canonical(value))


class RunnerHandoff:
    """An API-owned queue with a closed mapping of runner identity to reviewed DAGs.

    Executor identities in this mapping must have credentials separate from all agents.
    The API checks that separation when it is assembled. No request can change the map.
    """

    def __init__(self, store, policy, runners):
        protected_state(store)
        if not isinstance(runners, dict) or not runners or len(runners) > 32:
            raise StateError('Invalid runner configuration')
        self.store, self.policy = store, policy
        self.runners = {}
        seen = set()
        for identity, bindings in runners.items():
            label(identity)
            if not isinstance(bindings, list) or not 1 <= len(bindings) <= 32:
                raise StateError('Invalid runner configuration')
            self.runners[identity] = [check_binding(binding) for binding in bindings]
            for binding in self.runners[identity]:
                key = canonical([binding[k] for k in ('action', 'version', 'targets')])
                if key in seen:
                    raise StateError('Ambiguous runner configuration')
                seen.add(key)

    def require_runner(self, actor):
        require(actor, 'executor')
        if actor.identity not in self.runners:
            raise StateError('Actor is not authorised as a trusted runner')

    def _binding(self, request):
        for runner, bindings in self.runners.items():
            for binding in bindings:
                if (all(request[k] == binding[k] for k in ('action', 'version', 'targets'))
                        and request['parameters'] == {}):
                    return runner, binding
        raise StateError('Action has no allowlisted runner binding')

    def approval(self, request):
        """Capture server configuration in the human decision's SQLite transaction."""
        self.policy(request)
        runner, binding = self._binding(request)
        return runner, digest(binding)

    def review(self, action_id, actor):
        require(actor, 'human')
        identifier(action_id)
        with self.store.transaction() as db:
            row = db.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
            if not row:
                raise StateError('Action is not available for review')
            request = json.loads(row['payload'])
            runner, binding = self._binding(request)
            return {'action_id': action_id, 'request': request, 'request_sha256': row['fingerprint'],
                    'runner': runner, 'binding': binding, 'binding_sha256': digest(binding)}

    def decide(self, action_id, decision, binding_sha256, actor):
        def reviewed(request):
            runner, current = self.approval(request)
            if not isinstance(binding_sha256, str) or binding_sha256 != current:
                raise StateError('Human decision requires the exact reviewed runner binding')
            return runner, current
        return self.store.decide(action_id, decision, actor, binding_policy=reviewed)

    def _approved_binding(self, db, action_id, runner, binding):
        approved = db.execute('SELECT * FROM runner_approvals WHERE action_id=?', (action_id,)).fetchone()
        if not approved or (approved['runner'], approved['binding_sha256']) != (runner, digest(binding)):
            raise StateError('Human approval does not cover the current runner binding')

    def enqueue(self, action_id, actor, *, now=None):
        with self.store.refusal('claim', actor, action_id, now=now):
            require(actor, 'executor')
            identifier(action_id)
            if actor.identity in self.runners:
                raise StateError('A trusted runner cannot request agent execution')
            now = clock(now)
            with self.store.transaction() as db:
                row = db.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
                if not row:
                    raise StateError('Action is not available for dispatch')
                request = json.loads(row['payload'])
                runner, binding = self._binding(request)
                self._approved_binding(db, action_id, runner, binding)
                old = db.execute('SELECT * FROM runner_requests WHERE action_id=?', (action_id,)).fetchone()
                if old:
                    if (old['runner'], old['binding_sha256']) != (runner, digest(binding)):
                        raise StateError('Runner binding changed; request cannot be replayed')
                    return {'action_id': action_id, 'status': row['status'], 'queued': True}
                if row['status'] != 'approved' or row['expires_at'] <= utc_text(now):
                    raise StateError('Action is not available for dispatch')
                self.policy(request)
                db.execute('INSERT INTO runner_requests VALUES (?,?,?,?,?)',
                           (action_id, actor.identity, runner, digest(binding), utc_text(now)))
                self.store.audit(db, now, actor.identity, 'runner.requested', action_id,
                                 {'runner': runner, 'approver': row['decided_by'],
                                  'action': request['action'], 'targets': request['targets'],
                                  'source': 'execute_action', 'binding_sha256': digest(binding)})
                return {'action_id': action_id, 'status': 'approved', 'queued': True}

    def pending(self, actor):
        self.require_runner(actor)
        with self.store.transaction() as db:
            rows = db.execute('SELECT r.action_id,r.binding_sha256 FROM runner_requests r '
                              'JOIN actions a ON a.id=r.action_id WHERE r.runner=? '
                              "AND a.status IN ('approved','executing','unknown') "
                              'ORDER BY r.requested_at,r.action_id LIMIT 20', (actor.identity,)).fetchall()
            return {'requests': [dict(row) for row in rows]}

    def claim(self, action_id, binding_sha256, runner_token, actor, *, now=None):
        """Retry a lost claim response only with the runner's previously journaled token."""
        with self.store.refusal('claim', actor, action_id, now=now):
            self.require_runner(actor)
            identifier(action_id)
            if (not isinstance(runner_token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', runner_token)
                    or not isinstance(binding_sha256, str)):
                raise StateError('Invalid runner claim')
            now = clock(now)
            with self.store.transaction() as db:
                queued = db.execute('SELECT * FROM runner_requests WHERE action_id=?', (action_id,)).fetchone()
                row = db.execute('SELECT * FROM actions WHERE id=?', (action_id,)).fetchone()
                if not queued or not row or queued['runner'] != actor.identity:
                    raise StateError('Action is not available for dispatch')
                request = json.loads(row['payload'])
                runner, binding = self._binding(request)
                self._approved_binding(db, action_id, runner, binding)
                if (runner != actor.identity or digest(binding) != binding_sha256
                        or queued['binding_sha256'] != binding_sha256):
                    raise StateError('Runner binding changed; request cannot be replayed')
                previous = db.execute('SELECT * FROM executions WHERE action_id=?', (action_id,)).fetchone()
                if previous:
                    if (previous['runner'] != actor.identity or not secrets.compare_digest(
                            previous['token_hash'], digest(runner_token))):
                        raise StateError('Runner identity/token mismatch')
                    # This is recovery of an existing claim, never fresh dispatch authority.
                    return {'execution_id': previous['id'], 'runner_token': runner_token,
                            'status': 'recovering', 'request': request}
                return self.store._claim_action(db, action_id, actor, self.policy, now, token=runner_token)


class _ClaimClient:
    def __init__(self, platform, action_id, binding_hash, token):
        self.platform, self.action_id, self.binding_hash, self.token = platform, action_id, binding_hash, token

    def request(self, method, path, payload=None):
        if method == 'POST' and path == '/v1/actions/claim':
            if payload != {'action_id': self.action_id}:
                raise StateError('Journal action mismatch')
            return self.platform.request('POST', '/v1/runner/claim', {
                'action_id': self.action_id, 'binding_sha256': self.binding_hash, 'runner_token': self.token})
        return self.platform.request(method, path, payload)


def run_request(platform, engine, request, binding, journal_directory, *, immutable_dag_root=None):
    """Trusted runner entry point. The caller supplies its own authenticated clients.

    A claim intent is fsynced before the platform sees it. A crash after claim but before
    the Dagu journal is durable recovers by observing the run, never by starting it.
    """
    if not isinstance(request, dict) or set(request) != {'action_id', 'binding_sha256'}:
        raise StateError('Invalid queued request')
    identifier(request['action_id'])
    binding = check_binding(binding)
    if request['binding_sha256'] != digest(binding):
        raise StateError('Queued runner binding differs')
    from local_observe.deployment.guided_files import directory, protected
    with directory(Path(journal_directory)) as fd, immutable_dag(immutable_dag_root, binding):
        protected(fd)
        return _run_request(platform, engine, request, binding, Path(journal_directory), fd)


def _run_request(platform, engine, request, binding, directory, fd):
    from local_observe.deployment.guided_files import create_file, private_lock, read_file
    action_id = request['action_id']
    intent = action_id + '.intent.json'
    with private_lock(fd, intent):
        if intent in os.listdir(fd):
            saved = json.loads(read_file(fd, intent))
            if saved['request'] != request:
                raise StateError('Runner intent changed')
            token = saved['token']
        else:
            token = secrets.token_urlsafe(32)
            create_file(fd, intent, canonical({'request': request, 'token': token}).encode('utf-8'))
        journal = directory / (action_id + '.json')
        if journal.with_suffix('.tmp').name in os.listdir(fd):
            raise StateError('Unsafe runner journal')
        return dagu.execute(_ClaimClient(platform, action_id, digest(binding), token), engine,
                            action_id, binding, journal, directory_fd=fd)

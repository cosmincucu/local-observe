"""Review, human approval and trusted application of a bounded first-install profile.

This prepares observer inputs over existing services. It installs no service, runs no
shell, changes no account and never reads a secret value. Transport authentication owns
Actor construction; neither the profile nor an approval payload can name an approver.
"""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.platform.state import StateError, clock, identifier, label, require
from . import guided_files as files
from .operator_setup import SetupError, checked_url


def _object(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise StateError('Invalid guided setup fields')


def _secret_ref(value):
    if not isinstance(value, str) or not re.fullmatch(r'/run/secrets/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', value):
        raise StateError('Setup secrets must be mounted file references')


def profile(value):
    """Strict versioned input. Nested unknown fields, inline secrets and hooks are refused."""
    _object(value, ('schema_version', 'name', 'telemetry', 'model', 'channel', 'interval_seconds'))
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['name'], str)
            or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', value['name'])
            or type(value['interval_seconds']) is not int or not 60 <= value['interval_seconds'] <= 86400):
        raise StateError('Invalid guided setup profile')
    for key in ('telemetry', 'model'):
        _object(value[key], ('url', 'token_file', 'resource_id', 'metric_name') if key == 'telemetry'
                else ('url', 'token_file', 'model', 'local', 'capability'))
        if not isinstance(value[key]['url'], str) or len(value[key]['url']) > 2048:
            raise StateError('Invalid bounded setup endpoint')
        try:
            checked_url(value[key]['url'])
        except SetupError:
            raise StateError('Setup endpoints require HTTPS without credentials or query parameters') from None
        if urlsplit(value[key]['url']).path not in ('', '/'):
            raise StateError('Setup endpoints must be HTTPS origins without an API path')
        _secret_ref(value[key]['token_file'])
    label(value['model']['model'])
    identifier(value['telemetry']['resource_id'])
    if (not isinstance(value['telemetry']['metric_name'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', value['telemetry']['metric_name'])):
        raise StateError('Invalid setup metric name')
    if value['model']['local'] is not True:
        raise StateError('Guided setup requires an explicitly local model endpoint')
    from local_observe.ai.capability import CapabilityError, validate
    capability = value['model']['capability']
    if not isinstance(capability, dict) or type(capability.get('schema_version')) is not int:
        raise StateError('Invalid measured model capability')
    try:
        validate(capability)
    except (CapabilityError, TypeError):
        raise StateError('Invalid measured model capability') from None
    channel = value['channel']
    if not isinstance(channel, dict) or not isinstance(channel.get('type'), str):
        raise StateError('Invalid setup channel')
    if channel['type'] == 'recording':
        _object(channel, ('type',))
    elif channel['type'] == 'telegram':
        _object(channel, ('type', 'token_file', 'destination_file'))
        _secret_ref(channel['token_file'])
        _secret_ref(channel['destination_file'])
    else:
        raise StateError('Invalid setup channel')
    return json.loads(canonical(value))


def observer_inputs(value):
    """Runnable observer Config over the existing store facade, in recording mode."""
    value = profile(value)
    return {'schema_version': 1, 'sources': [{'id': 'telemetry-metric', 'adapter': 'store',
            'query_type': 'metric-threshold', 'resource_id': value['telemetry']['resource_id'],
            'metric_name': value['telemetry']['metric_name'], 'initial': True, 'data_class': 'internal'}],
            'cadence_seconds': value['interval_seconds'], 'window_seconds': value['interval_seconds'],
            'max_sources': 1, 'max_model_calls': 1, 'max_cycle_seconds': 120, 'max_result_bytes': 65536,
            'max_rows': 200, 'max_age_seconds': 900, 'data_class': 'internal', 'mode': 'recording'}


def render(value, destination):
    value = profile(value)
    policy = {'schema_version': 1, 'classes': {name: {
        'generate': name != 'restricted', 'remote': False, 'redact': ['secret_keys'],
        'label': 'Local observation'} for name in ('public', 'internal', 'restricted')}}
    environment = {'LO_CLICKHOUSE_URL': value['telemetry']['url'],
                   'LO_CLICKHOUSE_READ_PASSWORD_FILE': value['telemetry']['token_file'],
                   'LO_AI_BASE_URL': value['model']['url'], 'LO_AI_MODEL': value['model']['model'],
                   'LO_AI_API_KEY_FILE': value['model']['token_file'], 'LO_AI_OUT_OF_LAN': '0',
                   'LO_AI_CAPTURE': '0', 'LO_AI_POLICY': str(Path(destination) / 'ai-policy.json'),
                   'LO_AI_CAPABILITY': str(Path(destination) / 'ai-capability.json')}
    artifacts = {'profile.json': value, 'observer.json': observer_inputs(value),
                 'observer-environment.json': environment, 'ai-policy.json': policy,
                 'ai-capability.json': value['model']['capability'],
                 'channel.json': {'schema_version': 1, 'mode': 'recording',
                                  'requested_channel': value['channel'], 'model_delivery_enabled': False}}
    return {name: (canonical(document) + '\n').encode('utf-8') for name, document in artifacts.items()}


class GuidedSetup:
    """Server-owned configuration root and runner identity; SQLite owns all authority.

    Manual clients and assistants submit the same /v1/setup requests. Assistants may
    prepare and request; only a human credential decides and the named runner applies.
    No public method accepts a caller-supplied plan, hash manifest or filesystem path.
    """

    def __init__(self, store, root, runner):
        from local_observe.platform.runner_handoff import protected_state
        protected_state(store)
        self.store, self.root, self.runner = store, Path(root), label(runner)
        with files.directory(self.root) as fd:
            files.protected(fd)
        self.source = self._source()

    def _source(self):
        # Pin the rendering/validation engine too: code drift requires a new review.
        package = Path(__file__).absolute().parents[1]
        paths = sorted(package.rglob('*.py'))
        result = {}
        for path in paths:
            with files.directory(path.absolute().parent) as fd:
                handle = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                with os.fdopen(handle, 'rb') as stream:
                    result[path.relative_to(package).as_posix()] = files.sha(stream.read())
        return {'product_sha256': digest(result), 'file_count': len(result)}

    def _plan(self, value):
        value = profile(value)
        artifacts = render(value, self.root / value['name'])
        source = self._source()
        if source != self.source:
            raise StateError('Setup source changed; restart before preparing a plan')
        with files.directory(self.root) as fd:
            root_identity = files.protected(fd)
        return {'schema_version': 1, 'profile': value, 'source': source,
                'destination': str(self.root / value['name']), 'root_identity': root_identity,
                'operations': [{'operation': 'create-file', 'path': name, 'bytes': len(data),
                                'sha256': files.sha(data), 'mode': '0600'}
                               for name, data in sorted(artifacts.items())],
                'directory_mode': '0700', 'runner': self.runner}

    def prepare(self, value, actor, *, now=None):
        require(actor, 'human', 'proposer')
        plan = self._plan(value)
        plan_id = digest(plan)
        with files.directory(self.root) as fd:
            if plan['profile']['name'] in os.listdir(fd):
                # An exact completed/partial plan is reviewable, arbitrary pre-existing data is not.
                with self.store.transaction() as db:
                    known = db.execute('SELECT id FROM setup_plans WHERE id=?', (plan_id,)).fetchone()
                if not known:
                    raise StateError('Setup destination already exists')
        with self.store.transaction() as db:
            old = db.execute('SELECT status FROM setup_plans WHERE id=?', (plan_id,)).fetchone()
            if not old:
                db.execute('INSERT INTO setup_plans VALUES (?,?,?,?,?,?,?,?)',
                           (plan_id, canonical(plan), actor.identity, 'pending', None, None, self.runner, None))
                self.store.audit(db, clock(now), actor.identity, 'setup.prepared', plan_id,
                                 {'source': 'guided-setup', 'destination': plan['destination']})
        return {'plan_id': plan_id, 'plan': plan, 'status': old['status'] if old else 'pending',
                'preflight': {'filesystem': 'ready', 'endpoints': 'not-contacted',
                              'secret_values': 'not-read', 'services': 'operator-managed'}}

    def _row(self, db, plan_id):
        if not isinstance(plan_id, str) or not re.fullmatch(r'[a-f0-9]{64}', plan_id):
            raise StateError('Invalid setup plan identifier')
        row = db.execute('SELECT * FROM setup_plans WHERE id=?', (plan_id,)).fetchone()
        if not row or row['runner'] != self.runner:
            raise StateError('Setup plan unavailable')
        plan = json.loads(row['payload'])
        if digest(plan) != plan_id or self._plan(plan['profile']) != plan:
            raise StateError('Setup inputs changed; prepare a new plan')
        return row, plan

    def decide(self, plan_id, decision, expires_at, actor, *, now=None):
        require(actor, 'human')
        now = clock(now)
        if not isinstance(decision, str) or decision not in ('approved', 'denied'):
            raise StateError('Invalid setup decision')
        if not isinstance(expires_at, str):
            raise StateError('Invalid setup approval expiry')
        expires = timestamp(expires_at)
        if not now < expires <= now + dt.timedelta(hours=1):
            raise StateError('Setup approval expiry must be in the next hour')
        with self.store.transaction() as db:
            row, _ = self._row(db, plan_id)
            if row['status'] not in ('pending', 'approved', 'queued', 'denied'):
                raise StateError('Setup decision is no longer available')
            db.execute('UPDATE setup_plans SET status=?,decided_by=?,expires_at=? WHERE id=?',
                       (decision, actor.identity, utc_text(expires), plan_id))
            self.store.audit(db, now, actor.identity, 'setup.' + decision, plan_id,
                             {'expires_at': utc_text(expires)})
        return {'plan_id': plan_id, 'status': decision}

    def enqueue(self, plan_id, actor, *, now=None):
        require(actor, 'human', 'proposer', 'executor')
        with self.store.transaction() as db:
            row, _ = self._row(db, plan_id)
            if row['status'] not in ('approved', 'queued') or row['expires_at'] <= utc_text(clock(now)):
                raise StateError('Setup plan requires current human approval')
            if row['status'] == 'approved':
                db.execute("UPDATE setup_plans SET status='queued' WHERE id=?", (plan_id,))
                self.store.audit(db, clock(now), actor.identity, 'setup.requested', plan_id,
                                 {'runner': self.runner, 'approver': row['decided_by']})
        return {'plan_id': plan_id, 'status': 'queued'}

    def apply(self, plan_id, actor, *, now=None):
        require(actor, 'executor')
        if actor.identity != self.runner:
            raise StateError('Actor is not authorised as the setup runner')
        # Serialize decisions and writes. Files are exclusive creations; a crash rolls
        # back the transaction and an exact marker allows the same approved plan to resume.
        with self.store.transaction() as db:
            row, plan = self._row(db, plan_id)
            if row['status'] not in ('queued', 'applied'):
                raise StateError('Setup plan is not queued')
            completed = row['status'] == 'applied'
            if not completed and row['expires_at'] <= utc_text(clock(now)):
                raise StateError('Setup approval expired')
            with files.directory(self.root) as fd:
                if files.protected(fd) != plan['root_identity']:
                    raise StateError('Setup destination changed')
                hashes = files.materialize(fd, plan_id, plan['profile']['name'],
                                           render(plan['profile'], plan['destination']),
                                           verify_only=completed)
            receipt = {'plan_id': plan_id, 'status': 'verified', 'files': hashes,
                       'runner': actor.identity, 'approver': row['decided_by'],
                       'destination': plan['destination']}
            if not completed:
                db.execute("UPDATE setup_plans SET status='applied',receipt=? WHERE id=?",
                           (canonical(receipt), plan_id))
                self.store.audit(db, clock(now), actor.identity, 'setup.applied', plan_id, receipt)
            return receipt

    def verify(self, plan_id, actor):
        require(actor, 'reader', 'human', 'proposer', 'executor')
        with self.store.transaction() as db:
            row, plan = self._row(db, plan_id)
            if row['status'] != 'applied':
                raise StateError('Setup is not applied')
            with files.directory(self.root) as fd:
                files.materialize(fd, plan_id, plan['profile']['name'],
                                  render(plan['profile'], plan['destination']), verify_only=True)
            return json.loads(row['receipt'])

    def pending(self, actor):
        require(actor, 'executor')
        if actor.identity != self.runner:
            raise StateError('Actor is not authorised as the setup runner')
        with self.store.transaction() as db:
            return {'plans': [row[0] for row in db.execute(
                "SELECT id FROM setup_plans WHERE runner=? AND status='queued' ORDER BY rowid LIMIT 20",
                (self.runner,))]}

    def request(self, path, body, actor):
        """Transport adapter: exact payload shapes, identities solely from authentication."""
        attempt = 'decide' if path.endswith('/decision') else 'claim'
        with self.store.refusal(attempt, actor):
            return self._request(path, body, actor)

    def _request(self, path, body, actor):
        if path == '/v1/setup/plan':
            _object(body, ('profile',))
            return self.prepare(body['profile'], actor)
        if path == '/v1/setup/decision':
            _object(body, ('plan_id', 'decision', 'expires_at'))
            return self.decide(body['plan_id'], body['decision'], body['expires_at'], actor)
        _object(body, ('plan_id',))
        if path == '/v1/setup/request':
            return self.enqueue(body['plan_id'], actor)
        if path == '/v1/setup/apply':
            return self.apply(body['plan_id'], actor)
        if path == '/v1/setup/verify':
            return self.verify(body['plan_id'], actor)
        raise StateError('Unknown guided setup operation')

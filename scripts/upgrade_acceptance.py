"""Candidate-image acceptance on disposable synthetic state; copied real state stays read-only."""
from contextlib import closing
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import uuid

EXPIRED_ROWS = 2048
UNRELATED_ROWS = 160
INDEX_NAMES = ('maintenance_unrevoked_end', 'escalation_incidents_status',
               'escalation_actions_incident', 'escalation_audit_intent')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def copy_guard(path):
    """Refuse a copied main file that still depends on a writer's journal."""
    require(not sys.flags.optimize, 'Refusing optimized acceptance Python')
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Missing migrated copied database')
    with path.open('rb') as stream:
        header = stream.read(100)
    require(header[:16] == b'SQLite format 3\x00' and header[18:20] in (b'\x01\x01', b'\x02\x02'),
            'Unexpected SQLite journal header')
    for suffix in ('-wal', '-journal'):
        sidecar = path.with_name(path.name + suffix)
        require(not sidecar.exists() or sidecar.stat().st_size == 0,
                'Stop isolated writers before acceptance')


def indexes(path):
    with closing(sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)) as db:
        return {name: db.execute('SELECT sql FROM sqlite_master WHERE type=? AND name=?',
                                ('index', name)).fetchone() for name in INDEX_NAMES}


def exercise(copied, temporary_parent=None):
    """Execute real candidate product reads and ticks; never write the supplied copied database."""
    copy_guard(copied)
    from local_observe.inventory.validation import canonical, timestamp, utc_text
    from local_observe.platform import escalation, state, suppression
    from local_observe.platform.detections import event
    from local_observe.platform.notification_safety import NotificationPolicy

    now = timestamp('2026-09-10T12:00:00Z')
    resource = '11111111-1111-4111-8111-111111111111'
    producer = state.Actor('upgrade-detector', 'producer')
    human = state.Actor('upgrade-operator', 'human')

    def verdict(rule, at, version='1'):
        return event(producer.identity, resource, rule, 'availability', 'firing',
                     {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)},
                     {'sample_id': 'upgrade-fixture'}, query_type='gatus-result', version=version)

    with tempfile.TemporaryDirectory(prefix='upgrade-acceptance-', dir=temporary_parent) as directory:
        root = Path(directory)
        store = state.Store(root / 'fixture.db', NotificationPolicy(delivery_mode='recording'))
        expected = indexes(store.path)
        actual = indexes(copied)
        require(all(expected.values()) and actual == expected,
                'Migrated copy indexes differ from candidate schema')
        with closing(sqlite3.connect(Path(copied).resolve().as_uri() + '?mode=ro', uri=True)) as db:
            require(db.execute('PRAGMA user_version').fetchone()[0] == state.VERSION,
                    'Migrated copy version differs from candidate')

        # Bulk synthetic history has the public declaration envelope and attesting audit row.
        # One transaction avoids thousands of fsyncs; no real copied row enters this fixture.
        expired = now - dt.timedelta(days=2)
        with store.transaction() as db:
            for number in range(EXPIRED_ROWS):
                declaration = {'resource_id': resource, 'rule_id': None,
                               'starts_at': utc_text(expired),
                               'ends_at': utc_text(expired + dt.timedelta(minutes=1)),
                               'reason': 'historical work ' + str(number)}
                declared = dict(declaration, id=suppression.window_id(declaration),
                                author=human.identity, declared_at=utc_text(expired))
                store.audit(db, expired, human.identity, 'maintenance.declared', declared['id'], declared)
                document = {'schema_version': suppression.WINDOW_DOCUMENT_VERSION,
                            'declared': declared, 'revoked': None,
                            'attest': db.execute('SELECT last_insert_rowid()').fetchone()[0]}
                db.execute('INSERT INTO notification_control(key,value,updated_at) VALUES (?,?,?)',
                           (state.maintenance_key(declared['id']), canonical(document), utc_text(expired)))
        live = suppression.declare_window(store, {
            'resource_id': None, 'rule_id': 'upgrade-maintenance', 'starts_at': utc_text(now),
            'ends_at': utc_text(now + dt.timedelta(hours=1)), 'reason': 'current work'}, human, now=now)
        with store.transaction() as db:
            require(db.execute("SELECT count(*) FROM notification_control WHERE key LIKE 'maintenance:%'").fetchone()[0]
                    == EXPIRED_ROWS + 1, 'Maintenance fixture history count differs')
            require(db.execute("SELECT count(*) FROM audit WHERE operation='maintenance.declared'").fetchone()[0]
                    == EXPIRED_ROWS + 1, 'Maintenance fixture attestations differ')
        covered = suppression.covering_window(store, verdict('upgrade-maintenance', now), now=now)
        require(covered is not None and covered['id'] == live['id'],
                'Expired maintenance history hides a current window')
        require(suppression.covering_window(store, verdict('uncovered', now), now=now) is None,
                'Expired maintenance history suppresses an unrelated finding')

        target = store.intake(verdict('upgrade-escalation', now), producer, now=now)['incident_id']
        config = root / 'chains.json'
        config.write_text(json.dumps({'chains': [{'id': 'upgrade-chain',
            'rule_id': 'upgrade-escalation', 'resource_id': None, 'stages': [
                {'interval_seconds': 300, 'severity_source': 'sigma', 'severity_tier': 'high'}]}]}))
        chains = escalation.config(config)['chains']
        cursor = root / 'cursor.json'
        first = escalation.tick(store, cursor, chains=chains, source='lo-escalation',
                                now=now + dt.timedelta(minutes=1))
        require(first['enrolled'] == 1, 'Target incident was not enrolled')
        # Newer open incidents exceed the retired 100-row read window.
        for number in range(UNRELATED_ROWS):
            at = now + dt.timedelta(minutes=2)
            store.intake(verdict('unrelated', at, str(number)), producer, now=at)
        with store.transaction() as db:
            for number in range(UNRELATED_ROWS):
                action = str(uuid.uuid4())
                db.execute('INSERT INTO actions(id,requester,retry_key,fingerprint,payload,status,'
                           'created_at,expires_at,decided_by) VALUES (?,?,?,?,?,?,?,?,?)',
                           (action, human.identity, action, 'f' * 64,
                            canonical({'incident_id': str(uuid.uuid4()), 'action': 'inspect',
                                       'parameters': {}}), 'approved', utc_text(now),
                            utc_text(now + dt.timedelta(hours=1)), human.identity))
                store.audit(db, now, human.identity, 'action.approval_intent', action,
                            {'channel': 'matrix', 'delivery_id': action, 'decided': False})
            require(db.execute("SELECT count(*) FROM incidents WHERE id<>? AND status='open' AND opened_at>?",
                               (target, utc_text(now))).fetchone()[0] == UNRELATED_ROWS,
                    'Escalation fixture newer incident count differs')
            require(db.execute('SELECT count(*) FROM actions').fetchone()[0] == UNRELATED_ROWS,
                    'Escalation fixture action count differs')
            require(db.execute("SELECT count(*) FROM audit WHERE operation='action.approval_intent'").fetchone()[0]
                    == UNRELATED_ROWS, 'Escalation fixture intent count differs')
        later = escalation.tick(store, cursor, chains=chains, source='lo-escalation',
                                now=now + dt.timedelta(minutes=5))
        require(later['escalated'] == 1 and later['closed'] == 0 and later['held'] == 0,
                'Older open incident does not escalate through unrelated history')
        with store.transaction() as db:
            require(db.execute('SELECT status FROM incidents WHERE id=?', (target,)).fetchone()[0] == 'open',
                    'Target incident no longer open')
            require(db.execute('SELECT count(*) FROM notification_attempts').fetchone()[0] == 0,
                    'Acceptance attempted notification delivery')
        return {'status': 'pass', 'schema_version': state.VERSION,
                'indexes': list(INDEX_NAMES), 'expired_windows': EXPIRED_ROWS,
                'unrelated_incidents': UNRELATED_ROWS, 'escalated': 1, 'notification_attempts': 0}


def run_acceptance(run, image, state_dir):
    """One bounded network-disabled candidate container, no writable host state mount."""
    require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image),
            'Acceptance requires exact candidate image ID')
    source = Path(__file__).resolve()
    database = Path(state_dir).resolve() / 'platform.db'
    copy_guard(database)
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        version = db.execute('PRAGMA user_version').fetchone()[0]
    output = run('docker', 'run', '--rm', '--pull=never', '--network=none', '--read-only',
                 '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--pids-limit=128',
                 '--memory=384m', '--cpus=0.5', '--tmpfs=/tmp:rw,size=32m,mode=1777',
                 '--workdir=/release', '--env=PYTHONPATH=/release',
                 '--mount', f'type=bind,source={source},target=/acceptance.py,readonly',
                 '--mount', f'type=bind,source={database},target=/tmp/copied.db,readonly',
                 '--entrypoint', 'python', image, '-B', '/acceptance.py', timeout=120)
    require(hashlib.sha256(database.read_bytes()).hexdigest() == before,
            'Acceptance changed the migrated copy')
    copy_guard(database)
    receipt = json.loads(output)
    require(isinstance(receipt, dict) and all(type(receipt.get(key)) is int for key in
            ('schema_version', 'expired_windows', 'unrelated_incidents', 'escalated', 'notification_attempts')),
            'Candidate acceptance receipt refused')
    require(receipt == {'status': 'pass', 'schema_version': version, 'indexes': list(INDEX_NAMES),
                        'expired_windows': EXPIRED_ROWS, 'unrelated_incidents': UNRELATED_ROWS,
                        'escalated': 1, 'notification_attempts': 0}, 'Candidate acceptance receipt refused')
    return dict(receipt, image=image, helper_sha256=hashlib.sha256(source.read_bytes()).hexdigest())


if __name__ == '__main__':
    from local_observe.platform import state
    require(Path(state.__file__).resolve().is_relative_to('/release/local_observe'),
            'Acceptance did not import the candidate release source')
    print(json.dumps(exercise('/tmp/copied.db')))

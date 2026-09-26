"""Complete development runtime pins, separate from mutable state and release authority."""
import hashlib
import os
from pathlib import Path
from typing import Any
from .content import Conflict, HASH, TEXT, obj, validate
from .recovery import OWNER_PLAN, check_snapshot
from local_observe.inventory.validation import digest

ARTIFACT = obj({'path': TEXT, 'sha256': HASH,
                'kind': {'enum': ['compose', 'environment', 'config', 'source', 'binary', 'secret-reference']}})
BUNDLE = obj({'schema_version': {'const': 1}, 'scope': TEXT,
    'product_revision': {'type': 'string', 'pattern': '^[a-f0-9]{40}$'},
    'customisation_revision': {'type': 'string', 'pattern': '^[a-f0-9]{40}$'},
    'inventory_sha256': HASH, 'recovery_plan_sha256': HASH,
    'services': {'type': 'object', 'minProperties': 1, 'additionalProperties': obj({
        'image_id': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
        'effective_config_sha256': HASH,
        'artifacts': {'type': 'array', 'minItems': 1, 'items': ARTIFACT}})},
    'state_owners': {'type': 'object', 'minProperties': 1, 'additionalProperties': obj({
        'format': TEXT, 'recovery': TEXT, 'verification': TEXT})},
    'notification_safety_contract': {'enum': [0, 1]}})


def artifact_hash(path: Path | str, allowed_root: Path | str, *,
                  max_bytes: int = 512 * 1024**2) -> str:
    """Hash an exact file or complete regular-file tree, without exporting its bytes."""
    path, allowed_root = Path(path), Path(allowed_root).resolve()
    if path.is_symlink() or not path.resolve().is_relative_to(allowed_root):
        raise Conflict('Artifact outside approved root or symlink')
    if not path.exists():
        raise Conflict('Missing artifact')
    files = [path] if path.is_file() else []
    if path.is_dir():
        def fail(error):
            raise error
        for directory, dirs, names in os.walk(path, onerror=fail, followlinks=False):
            files.extend(Path(directory)/name for name in sorted(dirs + names))
    manifest, size = {}, 0
    for child in files:
        if child.is_symlink():
            raise Conflict('Artifact tree contains symlink')
        if child.is_dir():
            manifest[child.relative_to(path).as_posix()+'/'] = '$directory'
            continue
        if not child.is_file():
            raise Conflict('Non-regular artifact')
        size += child.stat().st_size
        if size > max_bytes:
            raise Conflict('Artifact tree exceeds bounded capture size')
        key = child.name if path.is_file() else child.relative_to(path).as_posix()
        manifest[key] = hashlib.sha256(child.read_bytes()).hexdigest()
    if not path.is_file() and not path.is_dir():
        raise Conflict('Non-regular artifact root')
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else digest(manifest)


def check_bundle(bundle: dict[str, Any], snapshot: dict[str, Any],
                 recovery_plan: dict[str, Any]) -> dict[str, Any]:
    validate(bundle, BUNDLE, 'Whole-deployment runtime pins')
    validate(recovery_plan, OWNER_PLAN, 'Stable recovery plan')
    check_snapshot(snapshot)
    if bundle['inventory_sha256'] != snapshot['sha256'] or bundle['scope'] != snapshot['scope']:
        raise Conflict('Runtime pins belong to another inventory')
    if bundle['recovery_plan_sha256'] != digest(recovery_plan):
        raise Conflict('Recovery plan changed after pinning')
    services = {}
    for row in snapshot['containers']:
        key = row['project']+'/'+row['service']
        if key in services and services[key] != row['image_id']:
            raise Conflict('Service replicas use different images')
        services[key] = row['image_id']
    if set(bundle['services']) != set(services):
        raise Conflict('Every observed service requires a runtime pin')
    for key, image in services.items():
        pin = bundle['services'][key]
        if pin['image_id'] != image:
            raise Conflict('Observed image differs from service pin')
        if any(row.get('effective_config_sha256') != pin['effective_config_sha256']
               for row in snapshot['containers'] if row['project']+'/'+row['service'] == key):
            raise Conflict('Fresh effective configuration observation differs from service pin')
        paths = [a['path'] for a in pin['artifacts']]
        if len(paths) != len(set(paths)) or not any(a['kind'] == 'compose' for a in pin['artifacts']):
            raise Conflict('Each service needs unique artifacts and its Compose input')
        retained = {(s['project'], s['service'], s['target'], s['type']) for o in recovery_plan['owners']
                    if o['recovery'] in ('retain-external', 'backup-restore') for s in o['selectors']}
        for row in (r for r in snapshot['containers'] if r['project']+'/'+r['service'] == key):
            for mount in row['mounts']:
                if (mount['type'] == 'bind'
                        and (row['project'], row['service'], mount['target'], mount['type']) not in retained):
                    if mount['source'] not in paths:
                        raise Conflict('Mounted configuration/source/credential reference is not pinned')
                if mount['type'] == 'volume' and mount['target'] == '/var/lib/clickhouse/user_scripts':
                    if 'volume:'+mount['source']+'/histogramQuantile' not in paths:
                        raise Conflict('Installed histogram executable requires an independent binary pin')
    owners = {}
    for external, rows in ((False, recovery_plan['owners']), (True, recovery_plan['external_owners'])):
        for owner in rows:
            if owner['id'] in owners:
                raise Conflict('Duplicate state owner')
            owners[owner['id']] = {
                'format': 'unobserved-external-state' if external else owner['state_format'],
                'recovery': owner['recovery'], 'verification': owner['verification']}
    if bundle['state_owners'] != owners:
        raise Conflict('State compatibility declarations differ from recovery plan')
    return {'status': 'review-required' if bundle['notification_safety_contract'] else 'blocked',
            'deploy_authorized': False, 'recovery_proven': False,
            'sha256': digest(bundle), 'limitations': ['Daemon-local image IDs are development-only',
            'Pins require independent live recapture; declarations do not prove source/image provenance',
            'Every state owner still requires consistent backup and restore acceptance']}


def compare_bundles(previous: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    for bundle in (previous, candidate):
        validate(bundle, BUNDLE, 'Whole-deployment runtime pins')
    if previous['scope'] != candidate['scope'] or previous['state_owners'] != candidate['state_owners']:
        raise Conflict('Scope or state-format change requires a separate migration contract')
    if set(previous['services']) != set(candidate['services']):
        raise Conflict('Service lifecycle change requires separate acceptance')
    if candidate['notification_safety_contract'] < previous['notification_safety_contract']:
        raise Conflict('Rollback cannot remove notification safety enforcement')
    return {'status': 'review-required', 'deploy_authorized': False,
            'previous_sha256': digest(previous), 'candidate_sha256': digest(candidate)}

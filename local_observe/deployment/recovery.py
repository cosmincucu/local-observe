"""Read-only Docker storage inventory and recovery-ownership coverage, not restore proof."""
from collections.abc import Callable, Sequence
import json
import re
import time
from typing import Any

from local_observe.inventory.validation import digest
from .content import Conflict, HASH, NAME, TEXT, obj, validate


PATH = {'type': 'string', 'minLength': 1, 'maxLength': 4096}
MOUNT = obj({'type': {'enum': ['bind', 'volume', 'tmpfs']}, 'source': PATH,
             'target': PATH, 'writable': {'type': 'boolean'}})
CONTAINER = obj({'id': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'},
                 'name': TEXT, 'project': TEXT, 'service': TEXT,
                 'image_id': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
                 'status': TEXT, 'readonly_rootfs': {'type': 'boolean'},
                 'mounts': {'type': 'array', 'items': MOUNT}, 'effective_config_sha256': HASH},
                ['id', 'name', 'project', 'service', 'image_id', 'status', 'readonly_rootfs', 'mounts'])
SNAPSHOT = obj({'schema_version': {'const': 1}, 'scope': TEXT,
                'projects': {'type': 'array', 'minItems': 1, 'uniqueItems': True, 'items': NAME},
                'captured_at': {'type': 'number'},
                'containers': {'type': 'array', 'minItems': 1, 'items': CONTAINER}, 'sha256': HASH})
OWNER = obj({'id': NAME, 'description': TEXT,
             'resources': {'type': 'array', 'minItems': 1, 'uniqueItems': True, 'items': PATH},
             'recovery': {'enum': ['backup-restore', 'rebuild', 'reissue', 'disposable', 'retain-external']},
             'procedure': TEXT})
OWNERSHIP = obj({'schema_version': {'const': 1}, 'inventory_sha256': HASH,
                 'owners': {'type': 'array', 'items': OWNER}})

SELECTOR = obj({'project': NAME, 'service': NAME, 'target': PATH,
                'type': {'enum': ['bind', 'volume', 'layer']},
                'sources': {'type': 'array', 'minItems': 1, 'uniqueItems': True, 'items': PATH}})
PLANNED_OWNER = obj({'id': NAME, 'description': TEXT,
    'recovery': OWNER['properties']['recovery'], 'procedure': TEXT,
    'state_format': TEXT, 'verification': TEXT,
    'writers': {'type': 'array', 'uniqueItems': True, 'items': TEXT},
    'selectors': {'type': 'array', 'minItems': 1, 'items': SELECTOR}})
OWNER_PLAN = obj({'schema_version': {'const': 1},
    'owners': {'type': 'array', 'minItems': 1, 'items': PLANNED_OWNER},
    'external_owners': {'type': 'array', 'items': obj({'id': NAME, 'host': TEXT,
        'path': PATH, 'recovery': OWNER['properties']['recovery'], 'procedure': TEXT,
        'verification': TEXT, 'observed': {'type': 'boolean'}})}})


def bind_owners(plan: dict[str, Any], snapshot: dict[str, Any], *,
                now: float | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
    """Bind reviewed stable selectors to a fresh capture; never auto-approve new mounts."""
    validate(plan, OWNER_PLAN, 'Stable recovery plan')
    check_snapshot(snapshot)
    available = {}
    for row in snapshot['containers']:
        for mount in row['mounts']:
            if mount['type'] != 'tmpfs':
                key = (row['project'], row['service'], mount['target'], mount['type'])
                available.setdefault(key, set()).add(mount['type']+':'+mount['source'])
        if not row['readonly_rootfs']:
            available.setdefault((row['project'], row['service'], '$writable-layer', 'layer'), set()).add(
                'layer:'+row['id'])
    ownership = {'schema_version': 1, 'inventory_sha256': snapshot['sha256'], 'owners': []}
    selectors, physical, ids = set(), {}, set()
    for owner in plan['owners']:
        if owner['id'] in ids:
            raise Conflict('Duplicate planned recovery owner')
        ids.add(owner['id'])
        claimed = set()
        for selector in owner['selectors']:
            key = tuple(selector[k] for k in ('project', 'service', 'target', 'type'))
            if key in selectors or key not in available:
                raise Conflict('Duplicate or missing recovery selector')
            if selector['type'] == 'layer':
                if selector['sources'] != ['$container-layer']:
                    raise Conflict('Writable layers require the explicit container-layer selector')
            elif available[key] != {selector['type']+':'+s for s in selector['sources']}:
                raise Conflict('Physical storage source changed behind a reviewed selector')
            selectors.add(key)
            for resource in available[key]:
                if resource in physical and physical[resource] != owner['id']:
                    raise Conflict('Shared storage has conflicting recovery owners')
                physical[resource] = owner['id']
                claimed.add(resource)
        ownership['owners'].append({k: owner[k] for k in ('id', 'description', 'recovery', 'procedure')} |
                                   {'resources': sorted(claimed)})
    external_ids = [o['id'] for o in plan['external_owners']]
    if len(set(external_ids)) != len(external_ids) or ids.intersection(external_ids):
        raise Conflict('Duplicate external recovery owner')
    report = coverage(ownership, snapshot, now=now)
    unselected = sorted(set(available) - selectors)
    report['unselected_mounts'] = [list(k) for k in unselected]
    report['unobserved_external_owners'] = [o['id'] for o in plan['external_owners'] if not o['observed']]
    if unselected or report['unobserved_external_owners']:
        report['status'] = 'blocked'
    report['plan_sha256'] = digest(plan)
    return ownership, report


def _hash(snapshot):
    return digest({key: value for key, value in snapshot.items() if key != 'sha256'})


def docker_inventory(run: Callable[..., str], projects: Sequence[str], scope: str, *,
                     now: float | None = None) -> dict[str, Any]:
    """Use only ps/inspect on the caller's daemon; never return Config.Env or labels."""
    if not projects or len(projects) != len(set(projects)) or any(
            not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', p) for p in projects):
        raise Conflict('Explicit unique Compose projects required')
    projects = sorted(projects)

    def capture():
        rows = []
        for project in projects:
            ids = run('docker', 'ps', '-aq', '--no-trunc', '--filter',
                      'label=com.docker.compose.project='+project).split()
            if not ids or len(ids) != len(set(ids)) or any(
                    not re.fullmatch(r'[a-f0-9]{64}', item) for item in ids):
                raise Conflict('Project has no containers or invalid container identities')
            documents = json.loads(run('docker', 'inspect', *sorted(ids)))
            if not isinstance(documents, list) or sorted(d['Id'] for d in documents) != sorted(ids):
                raise Conflict('Incomplete Docker inspection')
            for doc in documents:
                labels = doc['Config']['Labels']
                if labels.get('com.docker.compose.project') != project:
                    raise Conflict('Container is outside requested project')
                mounts = []
                for mount in doc['Mounts']:
                    kind = mount['Type']
                    # Volume names are portable within this daemon; internal mountpoints are not.
                    source = mount['Name'] if kind == 'volume' else ('tmpfs' if kind == 'tmpfs' else mount['Source'])
                    mounts.append({'type': kind, 'source': source, 'target': mount['Destination'],
                                   'writable': mount['RW']})
                rows.append({'id': doc['Id'], 'name': doc['Name'].lstrip('/'), 'project': project,
                             'service': labels['com.docker.compose.service'], 'image_id': doc['Image'],
                             'status': doc['State']['Status'],
                             'effective_config_sha256': digest({'config': doc['Config'], 'host': doc['HostConfig']}),
                             'readonly_rootfs': doc['HostConfig']['ReadonlyRootfs'],
                             'mounts': sorted(mounts, key=lambda m: (m['target'], m['source']))})
        return sorted(rows, key=lambda row: row['id'])

    try:
        first = capture()
        if first != capture():
            raise Conflict('Containers or mounts changed during inventory')
        result = {'schema_version': 1, 'scope': scope, 'projects': projects,
                  'captured_at': time.time() if now is None else now, 'containers': first}
        result['sha256'] = _hash(result)
        check_snapshot(result)
        return result
    except (KeyError, TypeError, ValueError) as error:
        raise Conflict('Unsupported Docker inventory; no complete snapshot produced') from error


def check_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    validate(snapshot, SNAPSHOT, 'Docker storage inventory')
    if snapshot['sha256'] != _hash(snapshot):
        raise Conflict('Storage inventory digest differs')
    rows = snapshot['containers']
    if len({row['id'] for row in rows}) != len(rows):
        raise Conflict('Duplicate container identity')
    if {row['project'] for row in rows} != set(snapshot['projects']):
        raise Conflict('Project coverage differs from inventory scope')
    for row in rows:
        if len({mount['target'] for mount in row['mounts']}) != len(row['mounts']):
            raise Conflict('Duplicate mount target')
    return snapshot


def resources(snapshot: dict[str, Any]) -> dict[str, list[str]]:
    """Include read-only binds and writable layers; neither implies state is disposable."""
    check_snapshot(snapshot)
    result = {}
    for row in snapshot['containers']:
        label = row['project']+'/'+row['service']+' ('+row['name']+')'
        if not row['readonly_rootfs']:
            result.setdefault('layer:'+row['id'], []).append(label+' writable container layer')
        for mount in row['mounts']:
            if mount['type'] != 'tmpfs':
                key = mount['type']+':'+mount['source']
                result.setdefault(key, []).append(label+' -> '+mount['target']+
                                                  (' [rw]' if mount['writable'] else ' [ro]'))
    return {key: sorted(uses) for key, uses in sorted(result.items())}


def coverage(ownership: dict[str, Any], snapshot: dict[str, Any], *,
             now: float | None = None) -> dict[str, Any]:
    validate(ownership, OWNERSHIP, 'Recovery ownership')
    actual = resources(snapshot)
    age = (time.time() if now is None else now) - snapshot['captured_at']
    if not 0 <= age <= 60:
        raise Conflict('Fresh storage inventory required (maximum age 60 seconds)')
    if ownership['inventory_sha256'] != snapshot['sha256']:
        raise Conflict('Ownership belongs to a different inventory')
    claimed, ids = {}, set()
    for owner in ownership['owners']:
        if owner['id'] in ids:
            raise Conflict('Duplicate recovery owner')
        ids.add(owner['id'])
        for resource in owner['resources']:
            if resource in claimed:
                raise Conflict('Storage resource assigned more than once')
            claimed[resource] = owner['id']
    missing = [{'resource': key, 'used_by': actual[key]} for key in sorted(actual.keys() - claimed.keys())]
    unknown = sorted(claimed.keys() - actual.keys())
    return {'status': 'blocked' if missing or unknown else 'review-required',
            'deploy_authorized': False, 'recovery_proven': False,
            'scope': snapshot['scope'], 'inventory_sha256': snapshot['sha256'],
            'ownership_sha256': digest(ownership), 'unassigned': missing, 'unknown': unknown,
            'limitations': ['Selected Docker projects only; independent hosts and external services not inventoried',
                            'Ownership is not backup, restore, state-format compatibility or query-parity evidence',
                            'Image IDs identify local images; Compose inputs, mounted bytes and external '
                            'binaries need separate pins',
                            'Double inspection is not an atomic capture; freeze writers and recheck before apply']}

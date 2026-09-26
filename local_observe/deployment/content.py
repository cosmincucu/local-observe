"""Reconcile owned content without fetching packages, resolving secrets or touching services."""
from collections.abc import Sequence
import copy
import hashlib
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
import yaml

from local_observe.inventory.validation import canonical, digest

ID = {'type': 'string', 'pattern': r'^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$', 'maxLength': 160}
NAME = {'type': 'string', 'pattern': r'^[a-z][a-z0-9_-]*$', 'maxLength': 60}
TEXT = {'type': 'string', 'minLength': 1, 'maxLength': 200}
HASH = {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}


def obj(properties: dict[str, Any], required: Sequence[str] | None = None) -> dict[str, Any]:
    return {'type': 'object', 'properties': properties, 'required': list(properties) if required is None else required,
            'additionalProperties': False}


SPECS = {
    'group': obj({'name': TEXT, 'tab': TEXT, 'order': {'type': 'integer'}, 'collapsed': {'type': 'boolean'}}),
    'tile': obj({'name': TEXT, 'group': ID, 'order': {'type': 'integer'}, 'config': {'type': 'object'}}),
    'dashboard': {'type': 'object'},
}
CONTENT = obj({'id': ID, 'kind': {'enum': list(SPECS)}, 'spec': {'type': 'object'}})
ITEMS = {'type': 'array', 'maxItems': 2000, 'items': CONTENT}
PACKAGE = obj({'schema_version': {'const': 1}, 'name': NAME, 'version': TEXT,
               'content_contract': {'const': 1}, 'content': ITEMS})
PIN = obj({'name': NAME, 'version': TEXT, 'sha256': HASH})
LOCK = obj({'schema_version': {'const': 1}, 'packages': {'type': 'array', 'minItems': 1, 'maxItems': 50, 'items': PIN}})
OVERRIDE = obj({'id': ID, 'expect_sha256': HASH, 'mode': {'enum': ['patch', 'replace', 'disable']},
                'set': {'type': 'object'}, 'spec': {'type': 'object'}}, ['id', 'expect_sha256', 'mode'])
DEPLOYMENT = obj({'schema_version': {'const': 1}, 'id': NAME, 'content': ITEMS,
    'overrides': {'type': 'array', 'maxItems': 2000, 'items': OVERRIDE},
    'homepage': obj({'title': TEXT, 'theme': {'enum': ['light', 'dark']}, 'color': TEXT})})
OWNED = obj({'id': ID, 'kind': {'enum': list(SPECS)}, 'owner': TEXT, 'spec': {'type': 'object'}})
STATE = obj({'schema_version': {'const': 1}, 'lock': LOCK, 'deployment_sha256': HASH,
             'homepage': DEPLOYMENT['properties']['homepage'],
             'content': {'type': 'array', 'maxItems': 10000, 'items': OWNED}})


class Conflict(ValueError):
    pass


def validate(value: Any, schema: dict[str, Any], label: str) -> None:
    canonical(value)
    error = next(Draft202012Validator(schema).iter_errors(value), None)
    if error:
        # Do not echo configuration values; documents can contain private inputs.
        raise Conflict('Invalid '+label+' at '+'.'.join(map(str, error.absolute_path)))


def index(rows: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result = {}
    for row in rows:
        if row['id'] in result:
            raise Conflict('Duplicate content ID: '+row['id'])
        validate(row['spec'], SPECS[row['kind']], row['id'])
        result[row['id']] = copy.deepcopy(row)
    return result


def references_only(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normal = key.lower().replace('_', '').replace('-', '')
            if normal in ('password', 'token', 'authorization', 'apikey', 'privatekey', 'clientsecret', 'secret'):
                if (not isinstance(child, str)
                        or not re.fullmatch(r'(?:Bearer )?\{\{HOMEPAGE_FILE_[A-Z0-9_]+\}\}', child)):
                    raise Conflict('Secret value must be a mounted-file reference')
            if key in ('url', 'href') and isinstance(child, str):
                parsed = urlsplit(child)
                if (parsed.scheme not in ('http', 'https', 'smb') or not parsed.netloc
                        or parsed.username or parsed.password):
                    raise Conflict('Unsupported or credential-bearing destination')
            references_only(child)
    elif isinstance(value, list):
        for child in value:
            references_only(child)


def make_lock(packages: Sequence[dict[str, Any]]) -> dict[str, Any]:
    pins = []
    names = set()
    for package in packages:
        validate(package, PACKAGE, 'content package')
        name = package['name']
        if name == 'user' or name in names:
            raise Conflict('Reserved or duplicate package name: '+name)
        names.add(name)
        index(package['content'])
        if any(not row['id'].startswith(name+'.') for row in package['content']):
            raise Conflict('Package content must use its own namespace: '+name)
        pins.append({'name': name, 'version': package['version'], 'sha256': digest(package)})
    result = {'schema_version': 1, 'packages': sorted(pins, key=lambda pin: pin['name'])}
    validate(result, LOCK, 'release lock')
    return result


def resolve(packages: Sequence[dict[str, Any]], lock: dict[str, Any],
            deployment: dict[str, Any]) -> dict[str, Any]:
    validate(lock, LOCK, 'release lock')
    if make_lock(packages) != lock:
        raise Conflict('Package set, version or digest differs from reviewed lock')
    validate(deployment, DEPLOYMENT, 'deployment')
    content = {}
    for package in packages:
        for key, row in index(package['content']).items():
            content[key] = {**row, 'owner': package['name']}
    users = index(deployment['content'])
    for key, row in users.items():
        if not key.startswith('user.'):
            raise Conflict('User additions require the user namespace: '+key)
        content[key] = {**row, 'owner': 'user'}
    overridden = set()
    for change in deployment['overrides']:
        key = change['id']
        if key in overridden or key not in content or content[key]['owner'] == 'user':
            raise Conflict('Duplicate, missing or user-owned override target: '+key)
        overridden.add(key)
        original = content[key]
        # Pin the complete upstream record: even non-overlapping upstream edits require review in v1.
        base = {k: original[k] for k in ('id', 'kind', 'spec')}
        if digest(base) != change['expect_sha256']:
            raise Conflict('Upstream content changed beneath override: '+key)
        mode = change['mode']
        allowed = {'patch': {'set'}, 'replace': {'spec'}, 'disable': set()}[mode]
        if set(change)-{'id', 'expect_sha256', 'mode'} != allowed:
            raise Conflict('Override fields do not match mode: '+key)
        if mode == 'disable':
            del content[key]
            continue
        spec = (copy.deepcopy(change['spec']) if mode == 'replace'
                else {**original['spec'], **copy.deepcopy(change['set'])})
        validate(spec, SPECS[original['kind']], key)
        content[key] = {**original, 'spec': spec}
    groups = {k: row for k, row in content.items() if row['kind'] == 'group'}
    if len({r['spec']['name'] for r in groups.values()}) != len(groups):
        raise Conflict('Homepage group names collide')
    titles = set()
    for row in content.values():
        if row['kind'] == 'tile':
            spec = row['spec']
            if spec['group'] not in groups:
                raise Conflict('Tile references missing group: '+row['id'])
            title = (spec['group'], spec['name'])
            if title in titles:
                raise Conflict('Homepage tile names collide within group: '+row['id'])
            titles.add(title)
            references_only(spec['config'])
    return {'schema_version': 1, 'lock': copy.deepcopy(lock), 'deployment_sha256': digest(deployment),
            'homepage': copy.deepcopy(deployment['homepage']),
            'content': [content[key] for key in sorted(content)]}


def render(state: dict[str, Any], deployment: dict[str, Any]) -> dict[str, str]:
    validate(state, STATE, 'resolved state')
    validate(deployment, DEPLOYMENT, 'deployment')
    if state['deployment_sha256'] != digest(deployment) or state['homepage'] != deployment['homepage']:
        raise Conflict('Resolved state belongs to a different deployment')
    content = index(state['content'])
    order = lambda row: (row['spec'].get('order', 0), row['id'])
    groups = sorted((r for r in content.values() if r['kind'] == 'group'), key=order)
    services, layout = [], {}
    for group in groups:
        spec = group['spec']
        tiles = sorted((r for r in content.values() if r['kind'] == 'tile' and r['spec']['group'] == group['id']),
                       key=order)
        services.append({spec['name']: [{r['spec']['name']: r['spec']['config']} for r in tiles]})
        layout[spec['name']] = {'tab': spec['tab'], 'style': 'row', 'columns': 3,
                                'initiallyCollapsed': spec['collapsed']}
    files = {'homepage/services.yaml': yaml.safe_dump(services, sort_keys=False),
             'homepage/settings.yaml': yaml.safe_dump({**deployment['homepage'], 'layout': layout}, sort_keys=False),
             'homepage/custom.css': '', 'homepage/custom.js': ''}
    for name, value in (('widgets', []), ('bookmarks', []), ('docker', {}), ('kubernetes', {}), ('proxmox', {})):
        files['homepage/'+name+'.yaml'] = yaml.safe_dump(value)
    for row in content.values():
        if row['kind'] == 'dashboard':
            files['dashboards/'+row['id']+'.json'] = canonical(row['spec'])+'\n'
    return files


def plan(previous: dict[str, Any], observed: dict[str, Any],
         candidate: dict[str, Any]) -> dict[str, Any]:
    for label, value in (('previous', previous), ('observed', observed), ('candidate', candidate)):
        validate(value, STATE, label)
    old, actual, new = [index(v['content']) for v in (previous, observed, candidate)]
    drift = sorted(key for key in old if key not in actual or digest(old[key]) != digest(actual[key]))
    collisions = sorted(set(new) & (set(actual)-set(old)))
    removed = sorted(set(old)-set(new))
    settings_drift = previous['homepage'] != observed['homepage']
    return {'schema_version': 1, 'status': 'blocked' if drift or collisions or settings_drift else 'review-required',
        'deploy_authorized': False, 'runtime_drift': drift, 'unmanaged_collisions': collisions,
        'homepage_settings_drift': settings_drift,
        'homepage_settings_change': previous['homepage'] != candidate['homepage'],
        'add': sorted(set(new)-set(old)), 'remove': removed,
        'change': sorted(key for key in set(old) & set(new) if digest(old[key]) != digest(new[key])),
        'retain_unmanaged': sorted(set(actual)-set(old)-set(new)), 'requires_removal_review': bool(removed),
        'previous_sha256': digest(previous), 'observed_sha256': digest(observed), 'candidate_sha256': digest(candidate),
        'scope': 'Content plan only; no database migration, secret resolution or deployment'}


def export_dashboard(state: dict[str, Any], content_id: str,
                     document: dict[str, Any]) -> dict[str, Any]:
    validate(state, STATE, 'resolved state')
    content = index(state['content'])
    if (content_id not in content or content[content_id]['kind'] != 'dashboard'
            or not isinstance(document, dict)):
        raise Conflict('Expected a known dashboard and normalized dashboard JSON')
    row = content[content_id]
    canonical(document)
    return {'schema_version': 1, 'id': content_id,
            'observed_sha256': digest({k: row[k] for k in ('id', 'kind', 'spec')}),
            'owner': row['owner'], 'spec': document,
            'next_step': ('review user definition edit' if row['owner'] == 'user'
                          else 'review pinned replacement override or create user-owned copy')}


def write_bundle(directory: Path | str, state: dict[str, Any], deployment: dict[str, Any]) -> None:
    files = render(state, deployment)
    files['resolved.json'] = canonical(state)+'\n'
    manifest = canonical({name: hashlib.sha256(value.encode()).hexdigest() for name, value
                          in sorted(files.items())})+'\n'
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    for name, value in sorted(files.items()):
        target = directory/name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('x', encoding='utf-8', newline='\n') as stream:
            stream.write(value)
    with (directory/'files.json').open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(manifest)

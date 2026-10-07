"""One-way export of declared inventory resources to a LogicMonitor portal.

The declaration is the source of truth. This module reads a built index and LogicMonitor's device list,
plans the smallest set of changes that brings LogicMonitor in line, and applies that plan only when the
operator asks. It never reads anything back into the inventory and never deletes a LogicMonitor device.

Planning is pure: `plan()` takes resources, devices and the export configuration and returns a document an
operator can review. `fetch_devices()` and `apply()` are the only functions that talk to the portal.

Matching, strongest first:

1. A device whose ``<prefix>resource_id`` property names the resource is that resource's device.
2. Otherwise a device whose display name or polling address matches the resource's name, a ``hostname``
   alias, an ``ip`` alias or its ``hostname_reported`` attribute is *adopted*, when exactly one unclaimed
   device matches and no other resource matches the same device.
3. A match on ``ip_observed`` alone (a DHCP address) is never adopted automatically: addresses move, and a
   stale device at a reused address is a different machine. It is listed for review.
4. A resource with no candidate at all is created only when creation is enabled and the resource is eligible.

A device that claims a resource the declaration no longer holds is reported as an orphan and left alone.
"""
from collections.abc import Iterable
import ipaddress
import json
import re
from typing import Any

from .validation import InvalidInventory

DEFAULT_PREFIX = 'lo.'
#: LogicMonitor's ordinary (collector-monitored) device type. Cloud accounts, websites and services are
#: never matched or changed.
REGULAR_DEVICE = 0
PAGE_SIZE = 1000
MAX_PAGES = 20


class ExportError(ValueError):
    pass


def _norm(value: str) -> str:
    return re.sub(r'[^a-z0-9]', '', value.lower())


def _ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _name_key(value: Any) -> tuple[str, str] | None:
    """A display name or address as a match key: an IP stays an IP, a host name loses its domain."""
    if not isinstance(value, str) or not value.strip():
        return None
    ip = _ip(value)
    if ip:
        return ('ip', ip)
    # Only a host name loses its domain: "Switch 2.5G" is a display name whose dot is part of the name.
    label = value.strip() if any(char.isspace() for char in value.strip()) else value.strip().split('.', 1)[0]
    key = _norm(label)
    return ('name', key) if key else None


def load_config(document: Any) -> dict[str, Any]:
    """Validate the operator's export configuration and fill documented defaults."""
    if not isinstance(document, dict) or document.get('schema_version') != 1:
        raise ExportError('Export configuration must be an object with schema_version 1')
    known = {'schema_version', 'portal', 'property_prefix', 'attributes', 'rename', 'max_changes', 'create', 'adopt'}
    unknown = set(document) - known
    if unknown:
        raise ExportError('Unknown export configuration keys: ' + ', '.join(sorted(unknown)))
    portal = document.get('portal')
    if not isinstance(portal, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', portal):
        raise ExportError('portal must be the LogicMonitor account name (the part before .logicmonitor.com)')
    prefix = document.get('property_prefix', DEFAULT_PREFIX)
    if not isinstance(prefix, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,15}\.', prefix):
        raise ExportError('property_prefix must be a short lowercase name ending in a dot')
    attributes = document.get('attributes', [])
    if not isinstance(attributes, list) or not all(
            isinstance(item, str) and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', item) for item in attributes):
        raise ExportError('attributes must list lowercase attribute names')
    rename = document.get('rename', True)
    max_changes = document.get('max_changes', 25)
    if type(rename) is not bool or type(max_changes) is not int or not 1 <= max_changes <= 1000:
        raise ExportError('rename must be a boolean and max_changes an integer from 1 to 1000')
    create = document.get('create', {'enabled': False})
    if not isinstance(create, dict) or type(create.get('enabled')) is not bool:
        raise ExportError('create must be an object with a boolean enabled')
    create_known = {'enabled', 'collector_id', 'host_group_ids', 'dns_suffix', 'when'}
    if set(create) - create_known:
        raise ExportError('Unknown create keys: ' + ', '.join(sorted(set(create) - create_known)))
    if create['enabled']:
        if type(create.get('collector_id')) is not int or create['collector_id'] < 1:
            raise ExportError('create.collector_id is required when creation is enabled')
    groups = create.get('host_group_ids', [])
    if not isinstance(groups, list) or not all(type(item) is int and item > 0 for item in groups):
        raise ExportError('create.host_group_ids must list positive integers')
    suffix = create.get('dns_suffix')
    if suffix is not None and (not isinstance(suffix, str)
                               or not re.fullmatch(r'[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+',
                                                   suffix)):
        raise ExportError('create.dns_suffix must be a DNS domain')
    when = create.get('when', {})
    if not isinstance(when, dict) or not all(
            isinstance(key, str) and isinstance(values, list) and all(isinstance(v, str) for v in values)
            for key, values in when.items()):
        raise ExportError('create.when must map attribute names to lists of allowed values')
    adopt = document.get('adopt', {})
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    if not isinstance(adopt, dict) or not all(
            isinstance(key, str) and re.fullmatch(uuid_pattern, key) and type(value) is int and value > 0
            for key, value in adopt.items()) or len(set(adopt.values())) != len(adopt):
        raise ExportError('adopt must map resource UUIDs to distinct LogicMonitor device ids')
    return {'portal': portal, 'property_prefix': prefix, 'attributes': attributes, 'rename': rename,
            'max_changes': max_changes, 'adopt': adopt,
            'create': {'enabled': create['enabled'], 'collector_id': create.get('collector_id'),
                       'host_group_ids': groups, 'dns_suffix': suffix, 'when': when}}


def read_resources(connection) -> list[dict[str, Any]]:
    """Read every declared resource with its aliases from a built index connection."""
    aliases: dict[str, list[dict[str, str]]] = {}
    for row in connection.execute(
            'SELECT resource_id, scope, type, value FROM aliases ORDER BY resource_id, type, value'):
        aliases.setdefault(row[0], []).append({'scope': row[1], 'type': row[2], 'value': row[3]})
    resources = []
    for row in connection.execute('SELECT id, kind, name, attributes, owner FROM resources ORDER BY id'):
        resources.append({'id': row[0], 'kind': row[1], 'name': row[2], 'attributes': json.loads(row[3]),
                          'owner': row[4], 'aliases': aliases.get(row[0], [])})
    return resources


def _resource_keys(resource: dict[str, Any]) -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    strong: set[tuple[str, str]] = set()
    weak: set[tuple[str, str]] = set()
    for value in (resource['name'], resource['attributes'].get('hostname_reported')):
        key = _name_key(value)
        if key:
            strong.add(key)
    for alias in resource['aliases']:
        if alias['type'] == 'hostname':
            key = _name_key(alias['value'])
        elif alias['type'] == 'ip':
            key = ('ip', _ip(alias['value'])) if _ip(alias['value']) else None
        else:
            key = None
        if key:
            strong.add(key)
    observed = _ip(resource['attributes'].get('ip_observed'))
    if observed and ('ip', observed) not in strong:
        weak.add(('ip', observed))
    return strong, weak


def _device_keys(device: dict[str, Any]) -> set[tuple[str, str]]:
    return {key for key in (_name_key(device.get('displayName')), _name_key(device.get('name'))) if key}


def _properties(device: dict[str, Any]) -> dict[str, str]:
    return {item['name']: item['value'] for item in device.get('customProperties') or []
            if isinstance(item, dict) and isinstance(item.get('name'), str)}


def desired_properties(resource: dict[str, Any], config: dict[str, Any]) -> dict[str, str]:
    """The LogicMonitor properties that carry the declaration; values are strings, as LogicMonitor stores them."""
    prefix = config['property_prefix']
    wanted = {prefix + 'resource_id': resource['id'], prefix + 'kind': resource['kind']}
    if resource.get('owner'):
        wanted[prefix + 'owner'] = resource['owner']
    for name in config['attributes']:
        value = resource['attributes'].get(name)
        if value is None:
            continue
        wanted[prefix + name] = (('true' if value else 'false') if isinstance(value, bool) else str(value))
    return wanted


def _address(resource: dict[str, Any], config: dict[str, Any]) -> str | None:
    suffix = config['create']['dns_suffix']
    hostnames = [alias['value'] for alias in resource['aliases'] if alias['type'] == 'hostname']
    if hostnames:
        name = hostnames[0]
        return name if '.' in name or not suffix else name + '.' + suffix
    ips = [alias['value'] for alias in resource['aliases'] if alias['type'] == 'ip']
    return ips[0] if ips else _ip(resource['attributes'].get('ip_observed'))


def _eligible(resource: dict[str, Any], config: dict[str, Any]) -> bool:
    return all(str(resource['attributes'].get(key)) in values for key, values in config['create']['when'].items())


def plan(resources: Iterable[dict[str, Any]], devices: Iterable[dict[str, Any]],
         config: dict[str, Any]) -> dict[str, Any]:
    """Return the reviewable change plan. Nothing here performs I/O."""
    resources = sorted(resources, key=lambda item: item['id'])
    by_id = {item['id']: item for item in resources}
    devices = [item for item in devices if item.get('deviceType', REGULAR_DEVICE) == REGULAR_DEVICE]
    claim_key = config['property_prefix'] + 'resource_id'
    claimed: dict[str, list[dict[str, Any]]] = {}
    orphans = []
    for device in devices:
        rid = _properties(device).get(claim_key)
        if rid is None:
            continue
        if rid in by_id:
            claimed.setdefault(rid, []).append(device)
        else:
            orphans.append({'device_id': device['id'], 'display_name': device.get('displayName'),
                            'resource_id': rid, 'reason': 'claims a resource the declaration does not hold'})
    claimed_ids = {device['id'] for group in claimed.values() for device in group}
    device_by_id = {device['id']: device for device in devices}
    free = {device['id'] for device in devices
            if device['id'] not in claimed_ids and claim_key not in _properties(device)}

    matched: dict[str, tuple[dict[str, Any], str]] = {}
    review, absent = [], []
    # An operator pin is an explicit adoption: it settles a match the rules below would only list for review.
    pinned = set()
    for rid, device_id in sorted(config.get('adopt', {}).items()):
        if rid not in by_id or rid in claimed:
            continue
        pinned.add(rid)
        if device_id in free:
            matched[rid] = (device_by_id[device_id], 'adopted')
            free.discard(device_id)
        else:
            review.append({'resource_id': rid, 'name': by_id[rid]['name'],
                           'reason': 'pinned device is missing, not a regular device or already claimed',
                           'candidates': [device_id]})
    pool: dict[tuple[str, str], set[int]] = {}
    for device_id in free:
        for key in _device_keys(device_by_id[device_id]):
            pool.setdefault(key, set()).add(device_id)

    strong_hits: dict[str, set[int]] = {}
    weak_hits: dict[str, set[int]] = {}
    for resource in resources:
        if resource['id'] in pinned:
            continue
        if resource['id'] in claimed:
            group = claimed[resource['id']]
            if len(group) == 1:
                matched[resource['id']] = (group[0], 'claimed')
            else:
                review.append({'resource_id': resource['id'], 'name': resource['name'],
                               'reason': 'several devices claim this resource',
                               'candidates': sorted(device['id'] for device in group)})
            continue
        strong, weak = _resource_keys(resource)
        strong_hits[resource['id']] = set().union(*(pool.get(key, set()) for key in strong)) if strong else set()
        weak_hits[resource['id']] = set().union(*(pool.get(key, set()) for key in weak)) if weak else set()
    contested: dict[int, set[str]] = {}
    for rid, hits in strong_hits.items():
        for device_id in hits:
            contested.setdefault(device_id, set()).add(rid)
    for rid, hits in strong_hits.items():
        resource = by_id[rid]
        if len(hits) == 1 and len(contested[next(iter(hits))]) == 1:
            matched[rid] = (device_by_id[next(iter(hits))], 'adopted')
        elif hits:
            others = sorted({other for device_id in hits for other in contested[device_id]} - {rid})
            also = ' (also matches ' + ', '.join(others) + ')' if others else ''
            review.append({'resource_id': rid, 'name': resource['name'], 'reason': 'ambiguous match' + also,
                           'candidates': sorted(hits)})
        elif weak_hits[rid]:
            review.append({'resource_id': rid, 'name': resource['name'],
                           'reason': 'matches only by a DHCP address; confirm before adopting',
                           'candidates': sorted(weak_hits[rid])})
        else:
            absent.append(resource)

    display_names = {device.get('displayName'): device['id'] for device in devices}
    actions, unchanged, notes = [], 0, []
    for rid, (device, how) in sorted(matched.items()):
        resource = by_id[rid]
        current = _properties(device)
        wanted = desired_properties(resource, config)
        changed = {name: value for name, value in wanted.items() if current.get(name) != value}
        rename = None
        if config['rename'] and device.get('displayName') != resource['name']:
            holder = display_names.get(resource['name'])
            if holder is None or holder == device['id']:
                rename = resource['name']
            else:
                notes.append({'resource_id': rid, 'name': resource['name'],
                              'note': f'display name already used by device {holder}; not renamed'})
        if not changed and rename is None:
            unchanged += 1
            continue
        actions.append({'op': 'adopt' if how == 'adopted' else 'update', 'device_id': device['id'],
                        'resource_id': rid, 'from_display_name': device.get('displayName'),
                        'display_name': rename, 'properties': changed})
    not_created = []
    for resource in absent:
        reason = None
        address = _address(resource, config)
        if not config['create']['enabled']:
            reason = 'creation disabled'
        elif not _eligible(resource, config):
            reason = 'not eligible under create.when'
        elif address is None:
            reason = 'no hostname or address to poll'
        elif resource['name'] in display_names:
            reason = f"display name already used by device {display_names[resource['name']]}"
        if reason:
            not_created.append({'resource_id': resource['id'], 'name': resource['name'], 'reason': reason})
            continue
        payload = {'name': address, 'displayName': resource['name'],
                   'preferredCollectorId': config['create']['collector_id'],
                   'description': 'Declared in the local-observe inventory',
                   'customProperties': [{'name': name, 'value': value}
                                        for name, value in sorted(desired_properties(resource, config).items())]}
        if config['create']['host_group_ids']:
            payload['hostGroupIds'] = ','.join(str(item) for item in config['create']['host_group_ids'])
        actions.append({'op': 'create', 'resource_id': resource['id'], 'payload': payload})
    summary = {'resources': len(resources), 'devices': len(devices), 'unchanged': unchanged,
               'adopt': sum(a['op'] == 'adopt' for a in actions), 'update': sum(a['op'] == 'update' for a in actions),
               'create': sum(a['op'] == 'create' for a in actions), 'review': len(review),
               'not_created': len(not_created), 'orphans': len(orphans)}
    return {'summary': summary, 'actions': actions, 'review': review, 'not_created': not_created,
            'orphans': orphans, 'notes': notes}


def fetch_devices(client) -> list[dict[str, Any]]:
    """Read every device with the fields matching needs, bounded by MAX_PAGES pages."""
    devices, offset = [], 0
    for _ in range(MAX_PAGES):
        status, body = client.request(
            'GET', f'/device/devices?size={PAGE_SIZE}&offset={offset}'
                   '&fields=id,displayName,name,deviceType,customProperties',
            headers={'X-Version': '3'})
        if status != 200 or not isinstance(body, dict) or not isinstance(body.get('items'), list):
            raise ExportError(f'LogicMonitor device listing failed with HTTP {status}')
        devices.extend(body['items'])
        offset += PAGE_SIZE
        if offset >= int(body.get('total', 0)):
            return devices
    raise ExportError('Device listing exceeded the page bound; refusing a partial view')


def apply(client, document: dict[str, Any], max_changes: int) -> dict[str, Any]:
    """Apply a plan's actions. Refuses a plan larger than max_changes; never deletes anything."""
    actions = document['actions']
    if len(actions) > max_changes:
        raise ExportError(f'Plan has {len(actions)} changes, above max_changes={max_changes}; '
                          'review it and raise the limit deliberately')
    results = []
    for action in actions:
        if action['op'] == 'create':
            status, body = client.request('POST', '/device/devices', action['payload'], headers={'X-Version': '3'})
            ok = status == 200 and isinstance(body, dict) and 'id' in body
            results.append({'op': 'create', 'resource_id': action['resource_id'], 'status': status,
                            'device_id': body.get('id') if ok else None, 'ok': ok})
            continue
        payload: dict[str, Any] = {}
        fields = []
        if action['properties']:
            payload['customProperties'] = [{'name': name, 'value': value}
                                           for name, value in sorted(action['properties'].items())]
            fields.append('customProperties')
        if action['display_name']:
            payload['displayName'] = action['display_name']
            fields.append('displayName')
        # opType=replace updates the named properties and leaves every other property on the device as it is.
        status, _ = client.request('PATCH', f"/device/devices/{int(action['device_id'])}?patchFields="
                                   + ','.join(fields) + '&opType=replace', payload, headers={'X-Version': '3'})
        results.append({'op': action['op'], 'resource_id': action['resource_id'], 'device_id': action['device_id'],
                        'status': status, 'ok': status == 200})
    failed = [item for item in results if not item['ok']]
    return {'status': 'applied' if not failed else 'partial', 'applied': len(results) - len(failed),
            'failed': len(failed), 'results': results}


def portal_base(config: dict[str, Any]) -> str:
    if not config.get('portal'):
        raise InvalidInventory('Export configuration names no portal')
    return f"https://{config['portal']}.logicmonitor.com/santaba/rest"

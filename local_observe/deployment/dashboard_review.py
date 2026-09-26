"""Offline structural dashboard review; no migration or deployment authority."""
import re
from typing import Any

from .content import Conflict, DEPLOYMENT, ID, index, validate
from .live import SNAPSHOT, dashboard_document
from local_observe.inventory.validation import digest


def _require(condition, message):
    if not condition:
        raise Conflict(message)


def _named(rows, field, label):
    _require(isinstance(rows, list), 'Invalid '+label+' list')
    result = {}
    for row in rows:
        _require(isinstance(row, dict), 'Invalid '+label+' object')
        name = row.get(field)
        _require(isinstance(name, str) and bool(name), 'Invalid '+label+' identity')
        _require(name not in result, 'Duplicate '+label+' identity')
        result[name] = row
    return result


def _view(document):
    if 'schemaVersion' in document:
        dashboard_document(document)
        spec = document['spec']
        panels = spec.get('panels')
        _require(isinstance(panels, dict), 'Invalid v6 panel map')
        result = {}
        for key, panel in panels.items():
            _require(isinstance(key, str) and bool(key) and isinstance(panel, dict)
                     and panel.get('kind') == 'Panel' and isinstance(panel.get('spec'), dict),
                     'Invalid v6 panel')
            body = panel['spec']
            _require(isinstance(body.get('display'), dict)
                     and isinstance(body['display'].get('name'), str)
                     and isinstance(body.get('plugin'), dict)
                     and isinstance(body['plugin'].get('kind'), str)
                     and isinstance(body['plugin'].get('spec'), dict)
                     and isinstance(body.get('queries'), list), 'Invalid v6 panel spec')
            result[key] = {'name': body['display']['name'], 'raw': panel,
                           'queries': body['queries'], 'v6': True}
        variables = spec.get('variables')
        _require(isinstance(variables, list) and all(isinstance(v, dict)
                 and isinstance(v.get('kind'), str) and isinstance(v.get('spec'), dict)
                 for v in variables), 'Invalid v6 variables')
        names = _named([v['spec'] for v in variables], 'name', 'variable')
        layouts = spec.get('layouts')
        _require(isinstance(layouts, list) and all(isinstance(v, dict)
                 and isinstance(v.get('spec'), dict) for v in layouts), 'Invalid v6 layouts')
        for layout in layouts:
            _require(layout.get('kind') == 'Grid' and isinstance(layout['spec'].get('items'), list),
                     'Unsupported v6 layout; expected Grid items')
            for item in layout['spec']['items']:
                _require(isinstance(item, dict) and isinstance(item.get('content'), dict)
                         and item['content'].get('$ref') in {'#/spec/panels/'+k for k in panels}
                         and all(type(item.get(k)) in (int, float) for k in ('x', 'y', 'width', 'height')),
                         'Invalid v6 layout item')
        rows = []
        display = spec.get('display')
        _require(isinstance(display, dict), 'Invalid v6 display')
        title = display.get('name')
    else:
        _require(isinstance(document.get('widgets'), list),
                 'Unsupported authoring dashboard format; expected legacy widgets or v6')
        widgets = _named(document['widgets'], 'id', 'widget')
        result, rows = {}, []
        for key, widget in widgets.items():
            _require(isinstance(widget.get('title'), str)
                     and isinstance(widget.get('panelTypes'), str), 'Invalid legacy widget')
            if widget['panelTypes'] == 'row':
                rows.append(widget)
            else:
                queries = widget.get('query')
                _require(queries is None or isinstance(queries, dict), 'Invalid legacy query')
                result[key] = {'name': widget['title'], 'raw': widget,
                               'queries': queries, 'v6': False}
        variables = document.get('variables', {})
        _require(isinstance(variables, dict), 'Invalid legacy variables')
        names = _named(list(variables.values()), 'name', 'variable')
        layouts = document.get('layout')
        _require(isinstance(layouts, list) and all(isinstance(v, dict) for v in layouts),
                 'Invalid legacy layout')
        for item in layouts:
            _require(isinstance(item.get('i'), str) and item['i'] in widgets
                     and all(type(item.get(k)) in (int, float) for k in ('x', 'y', 'w', 'h')),
                     'Invalid legacy layout item')
        title = document.get('title')
    _require(isinstance(title, str), 'Invalid dashboard title')
    return {'title': title, 'panels': result, 'variables': variables,
            'variable_names': names, 'layouts': layouts, 'rows': rows}


def _sql(panel):
    queries = panel['queries']
    if not panel['v6']:
        if queries is None or queries.get('queryType') != 'clickhouse_sql':
            return None
        rows = _named(queries.get('clickhouse_sql'), 'name', 'SQL query')
    else:
        specs = []
        supported = True
        for query in queries:
            _require(isinstance(query, dict) and isinstance(query.get('spec'), dict),
                     'Invalid v6 query')
            spec = query['spec']
            plugin = spec.get('plugin')
            _require(isinstance(plugin, dict) and isinstance(plugin.get('kind'), str)
                     and isinstance(plugin.get('spec'), dict), 'Invalid v6 query plugin')
            if plugin['kind'] != 'signoz/ClickHouseSQL':
                supported = False
            else:
                _require(plugin['spec'].get('name') == spec.get('name'),
                         'Conflicting v6 SQL query names')
            specs.append(spec)
        if not supported or not specs:
            return None
        named = _named(specs, 'name', 'query')
        rows = {name: spec['plugin']['spec'] for name, spec in named.items()}
    _require(bool(rows) and all(isinstance(row.get('query'), str) for row in rows.values()),
             'Invalid SQL text')
    return {name: row['query'] for name, row in rows.items()}


def _hashes(before, after):
    left, right = digest(before), digest(after)
    return {'authoring_sha256': left, 'live_sha256': right, 'raw_equal': left == right}


def _comparison(before, after):
    a, b = _view(before), _view(after)
    old, new = a['panels'], b['panels']
    shared = sorted(set(old) & set(new))
    named = lambda values, keys: [{'id': key, 'name': values[key]['name']} for key in sorted(keys)]
    panels = {'added': named(new, set(new)-set(old)),
              'removed': named(old, set(old)-set(new)), 'shared_count': len(shared),
              'shared': [], 'sql': [], 'title_changes': []}
    # Validate queries even on unpaired panels; unsupported families stay unproven.
    sql_old = {key: _sql(value) for key, value in old.items()}
    sql_new = {key: _sql(value) for key, value in new.items()}
    for key in shared:
        panels['shared'].append({'id': key, 'name': new[key]['name'],
            'document': _hashes(old[key]['raw'], new[key]['raw']),
            'sql_text_comparison': 'available' if sql_old[key] is not None and sql_new[key] is not None
                                   else 'not-applicable-or-unsupported',
            'queries': _hashes(old[key]['queries'], new[key]['queries'])})
        if old[key]['name'] != new[key]['name']:
            panels['title_changes'].append({'id': key, 'authoring': old[key]['name'],
                                            'live': new[key]['name']})
        if sql_old[key] is not None and sql_new[key] is not None:
            panels['sql'].append({'id': key, 'name': new[key]['name'],
                'text_equal': sql_old[key] == sql_new[key],
                'query_names_authoring': sorted(sql_old[key]), 'query_names_live': sorted(sql_new[key])})
    av, bv = set(a['variable_names']), set(b['variable_names'])
    return {'title': {'authoring': a['title'], 'live': b['title'], 'equal': a['title'] == b['title']},
            'panels': panels, 'variables': {'added': sorted(bv-av), 'removed': sorted(av-bv),
                **_hashes(a['variables'], b['variables'])},
            'layout': _hashes(a['layouts'], b['layouts']),
            'legacy_rows': [{'id': row['id'], 'name': row['title']} for row in a['rows']]}


def review(authoring: dict[str, Any], snapshot: dict[str, Any], documents: dict[str, Any],
           identities: dict[str, str]) -> dict[str, Any]:
    """Return structural evidence from supplied JSON; never check runtime freshness."""
    validate(authoring, DEPLOYMENT, 'deployment')
    authored = {key: row['spec'] for key, row in index(authoring['content']).items()
                if row['kind'] == 'dashboard'}
    validate(snapshot, SNAPSHOT, 'live snapshot')
    _require(snapshot['adapter'] == 'signoz-v2-v6', 'Unsupported snapshot adapter')
    validate(identities, {'type': 'object', 'maxProperties': 10000, 'propertyNames': ID,
        'additionalProperties': {'type': 'string', 'pattern': '^[a-zA-Z0-9_-]+$', 'maxLength': 128}},
        'dashboard identity map')
    _require(len(set(identities.values())) == len(identities)
             and all(re.fullmatch(r'[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+', k) for k in identities),
             'Ambiguous dashboard identity mapping')
    _require(isinstance(documents, dict) and set(identities) <= set(documents),
             'Invalid or incomplete dashboard documents')
    _require(not any(row['id'] in set(authored) | set(identities) for row in authoring['overrides']),
             'Dashboard overrides require resolved content review; raw authoring is insufficient')
    for key, document in documents.items():
        _require(isinstance(key, str) and (key in identities or
                 re.fullmatch(r'unmanaged:[a-zA-Z0-9_-]+', key)), 'Unmapped dashboard identity')
        _require(not key.startswith('unmanaged:') or key[10:] not in identities.values(),
                 'Conflicting unmanaged dashboard identity')
        dashboard_document(document)
        for panel in _view(document)['panels'].values():
            _sql(panel)
    artifacts = {key: digest(document) for key, document in documents.items()}
    artifacts['$identity-map'] = digest(identities)
    _require(snapshot['artifacts'] == artifacts and snapshot['sha256'] == digest(artifacts),
             'Live snapshot artifacts or digest differ')
    rows = []
    for key in sorted(set(authored) | set(documents)):
        before, after = authored.get(key), documents.get(key)
        if before is not None:
            for panel in _view(before)['panels'].values():
                _sql(panel)
        row = {'id': key, 'status': 'missing_authoring' if before is None else
               'missing_live' if after is None else 'compared',
               'authoring_sha256': digest(before) if before is not None else None,
               'live_sha256': digest(after) if after is not None else None}
        if before is not None and after is not None:
            row.update(_comparison(before, after))
            row['document_equal'] = digest(before) == digest(after)
        rows.append(row)
    return {'schema_version': 1, 'status': 'review-required', 'deploy_authorized': False,
            'query_equivalence_proven': False, 'freshness_checked': False,
            'scope': 'Private deployment.content dashboards only; packages are not resolved; no query execution',
            'input_hashes': {'authoring': digest(authoring), 'snapshot': digest(snapshot),
                             'documents': digest(documents), 'identities': digest(identities)},
            'dashboards': rows}

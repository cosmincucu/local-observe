"""Generate private migration baselines by reading the operator's checkout as data, never executing it."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_migration import BASELINE_ENV, SOURCE_REFUSAL, baseline_directory
from migration_layout import read_layout

ROOT = Path(__file__).resolve().parents[1]


def walk(value):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def capture(source, layout):
    """Hash and summarise the operator checkout `layout` describes, writing nothing.

    Every name this capture reports comes out of the validated layout, so the function holds no
    estate of its own: no host, no operator directory layout, no service name, no endpoint address.
    The layout is copied into the returned baseline (schema 2) so every later reader sees exactly
    which estate was read instead of re-deriving it from a literal in this file.
    """
    hashes = {}
    def read(name):
        path = (source/name).resolve()
        if not path.is_relative_to(source.resolve()) or path.is_symlink():
            raise ValueError('Source must remain in the selected checkout')
        raw = path.read_bytes()
        hashes[name] = hashlib.sha256(raw).hexdigest()
        return raw.decode('utf-8')
    homepage_name = layout['homepage_services']
    raw = read(homepage_name)
    groups = yaml.safe_load(raw)
    lines = raw.splitlines()
    nodes = yaml.compose(raw)
    services, dashboards = [], []
    for group_node, group in zip(nodes.value, groups):
        name, entries = next(iter(group.items()))
        entry_nodes = group_node.value[0][1].value
        for node, entry in zip(entry_nodes, entries):
            title, config = next(iter(entry.items()))
            row = {'name': title, 'group': name, 'href': config.get('href'), 'ping': config.get('ping'),
                'description': config.get('description'), 'source_line': node.start_mark.line+1,
                'widget': {'type': config['widget'].get('type'), 'url': config['widget'].get('url')} if config.get('widget') else None,
                'disposition': 'preserve existing endpoint', 'acceptance': 'not yet exercised against candidate'}
            if title in layout['tile_dispositions']:
                row['disposition'] = layout['tile_dispositions'][title]
            if title in layout['tile_availability']:
                row['expected_availability'] = layout['tile_availability'][title]
            services.append(row)
            if not name.startswith(layout['dashboard_group_prefix']):
                continue
            section = '\n'.join(lines[node.start_mark.line:node.end_mark.line])
            match = re.search(r'# dashboard:\s*([A-Za-z0-9_.-]+\.json)', section)
            if not match:
                raise ValueError('Dashboard tile has no source marker: '+title)
            file = layout['dashboard_directory']+'/'+match[1]
            document = json.loads(read(file))
            metrics = sorted({item['metricName'] for item in walk(document) if isinstance(item, dict) and isinstance(item.get('metricName'), str)})
            panels = []
            for widget in document.get('widgets', []):
                if widget.get('panelTypes') == 'row':
                    continue
                query = widget.get('query', {})
                panels.append({'title': widget.get('title'), 'query_type': query.get('queryType'),
                    'query_sha256': hashlib.sha256(json.dumps(query, sort_keys=True).encode()).hexdigest(),
                    'metric_names': sorted({item['metricName'] for item in walk(query) if isinstance(item, dict) and isinstance(item.get('metricName'), str)}),
                    'data_sources': sorted({item['dataSource'] for item in walk(query) if isinstance(item, dict) and isinstance(item.get('dataSource'), str)}),
                    'query_result_parity': 'pending; do not infer from HTTP 200'})
            dashboards.append({'name': title, 'href': config['href'], 'source': file, 'sha256': hashes[file],
                'variables': list(document.get('variables', {})), 'metrics': metrics, 'panels': panels,
                'producer_mapping': 'candidate mapping only; estate evidence required', 'migration': 'retain old destination until query parity passes'})
    producers = []
    for collector in layout['collector_configs']:
        file = collector['path']
        document = yaml.safe_load(read(file))
        scrapes = document.get('receivers', {}).get('prometheus', {}).get('config', {}).get('scrape_configs', [])
        producers.append({'host': collector['host'], 'source': file, 'receivers': list(document.get('receivers', {})),
            'scrape_jobs': [item['job_name'] for item in scrapes], 'pipelines': list(document.get('service', {}).get('pipelines', {})),
            'credentials': 'not exported; rebind using private secret references', 'replacement': 'not authorized'})
    for dashboard in dashboards:
        candidates = set()
        for metric in dashboard['metrics']:
            if metric.startswith(('system.', 'process.', 'node_', 'up')): candidates.add('host agents / node exporters')
            if metric.startswith(('DCGM_', 'gpu_', 'vllm', 'llm_', 'sglang')): candidates.add('GPU/model exporters and AI emitters')
            if metric.startswith(('unifi_', 'unpoller_')): candidates.add('unpoller / UniFi topology')
            if metric.startswith(('homeassistant_', 'ha_')): candidates.add('Home Assistant scrape / energy emitters')
            if metric.startswith(('lo_', 'estate_')): candidates.add('private estate collectors/self-tests/emitters')
            if metric.startswith(('blocky_', 'dns_')): candidates.add('blocky scrape / DNS logs')
            if metric.startswith(('smartctl_', 'zfs_', 'disk_')): candidates.add('SMART/ZFS/storage collectors')
        dashboard['candidate_producers'] = sorted(candidates)
    toolfile = layout['mcp_tool_surface']
    tree = ast.parse(read(toolfile))
    toolsets = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Set):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.endswith('_TOOLS'):
                    toolsets[target.id] = sorted(ast.literal_eval(node.value))
    deploy = json.loads(read(layout['deploy_map']))
    preserve = []
    preserved = set(layout['preserved_services'])
    for host, config in deploy['hosts'].items():
        for name, item in config.get('services', {}).items():
            if name in preserved:
                preserve.append({'host': host, 'service': name, 'model': item.get('model'), 'repo': item.get('repo'),
                    'backup': item.get('backup'), 'action': 'preserve; retired/undeployed entries must not be started'})
    absent = [name for name in layout['mcp_contract_sets'] if not toolsets.get(name)]
    if absent:
        raise ValueError('Declared MCP contract set absent from the tool surface: '+', '.join(absent)
                         +'; a missing contract set must not become an empty one')
    return {'schema_version': 2, 'authority': 'working-tree file hashes; not a committed product revision or live runtime capture',
        'layout': layout,
        'sources': hashes, 'services': services, 'dashboards': dashboards, 'producers': producers,
        'mcp': {'legacy_endpoint': layout['legacy_mcp_endpoint'], 'required_contract_sets': toolsets,
            'policy': 'keep existing endpoint and clients; additive product MCP is not a drop-in replacement',
            'live_tool_parity': 'pending scoped credential'}, 'deployments': preserve}


def main():
    """Write a NEW baseline into the operator's directory; never into this checkout.

    The capture is the one baseline input that does not pre-exist, so it takes the destination
    directory rather than a file: deployment separation leaves no default output path inside the product tree. privacy checks adds
    the two inputs it could not ship as defaults: `--source` (the operator checkout being described) and
    the source layout sitting beside the baselines, which is copied into the capture it makes.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=None,
                        help='the operator checkout to capture; required, because this checkout ships no '
                             'default path to one (privacy checks)')
    parser.add_argument('--baseline-dir', type=Path, default=None,
                        help='operator directory to write the new baseline into; default $' + BASELINE_ENV)
    parser.add_argument('--output', type=Path, default=None,
                        help="new baseline: a bare file name lands in the operator directory, a path is "
                             'taken as given and must sit outside this checkout (default baseline-next.json)')
    args = parser.parse_args()
    try:
        directory = baseline_directory(args.baseline_dir)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.source is None:
        print(SOURCE_REFUSAL, file=sys.stderr)
        return 2
    output = args.output or Path('baseline-next.json')
    if not output.is_absolute() and len(output.parts) == 1:
        output = directory/output   # a bare name belongs in the operator's directory
    if output.resolve().is_relative_to(ROOT.resolve()):
        print('A generated baseline must not land in the product checkout (deployment separation); write it into the '
              "operator's repository instead: " + str(output), file=sys.stderr)
        return 2
    if output.exists():
        parser.error('Use a fresh output; retain the previous baseline')
    try:
        layout = read_layout(args.baseline_dir)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    result = capture(args.source, layout)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'services': len(result['services']), 'dashboards': len(result['dashboards']),
        'panels': sum(len(d['panels']) for d in result['dashboards']),
        'source_files': len(result['sources']), 'output': str(output)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

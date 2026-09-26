"""Prepare a private, review-only downstream directory; never write into the operator's checkout or deploy it."""
import argparse
import copy
import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))          # the repository root, for local_observe
sys.path.insert(0, str(HERE))                 # scripts/, so check_migration imports when a test loads this by path
from local_observe.deployment.content import make_lock, resolve, write_bundle
from local_observe.deployment.defaults import package
from local_observe.inventory.validation import canonical, digest, read_document
from check_migration import BASELINE_ENV, BASELINE_NAME, SOURCE_REFUSAL, baseline_file, check


def prepare(source, baseline, operator_url, output):
    """Build the private candidate directory from the capture, refusing a drift or a layout it cannot read.

    The estate's own names — its deployment identity, the Homepage source path, its group prefix and the
    tiles whose widgets gate a status — are read from the layout the capture carried (privacy checks), never from
    literals here: this file ships no estate, and a candidate that wanted one needed an operator input.
    """
    report = check(baseline, source)
    if not report['preparation_valid']:
        raise ValueError('Baseline drift: refresh/review the baseline before preparing customisations')
    layout = baseline.get('layout')
    if not isinstance(layout, dict):   # check() already refuses this; the sentence names the repair
        raise ValueError('The capture predates the layout contract; regenerate it with prepare_migration.py')
    product = package()
    deployment = {'schema_version': 1, 'id': layout['deployment']['id'], 'homepage': {
        'title': layout['deployment']['title'], 'theme': layout['deployment']['theme'],
        'color': layout['deployment']['color']}, 'content': [], 'overrides': []}
    for row in product['content']:
        if row['kind'] == 'tile' and 'href' in row['spec']['config']:
            config = copy.deepcopy(row['spec']['config'])
            config['href'] = operator_url
            deployment['overrides'].append({'id': row['id'], 'mode': 'patch', 'expect_sha256': digest(row), 'set': {'config': config}})
    homepage_source = layout['homepage_services']
    sources = baseline['sources']
    def read(name):
        path = (source/name).resolve()
        if not path.is_relative_to(source.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != sources[name]:
            raise ValueError('Source changed while preparing candidate')
        return read_document(path)
    homepage = read(homepage_source)
    native = {(group, name): config for entry in homepage for group, rows in entry.items() for row in rows for name, config in row.items()}
    identities = []
    def identifier(kind, label):
        slug = re.sub('[^a-z0-9]+', '-', label.lower()).strip('-')
        return 'user.'+kind+'-'+slug
    for number, row in enumerate(baseline['services']):
        content_id = identifier('tile', row['name'])
        group = 'core.dashboards' if row['group'].startswith(layout['dashboard_group_prefix']) else 'core.consoles'
        config = copy.deepcopy(native[row['group'], row['name']])
        if config.get('widget') and row['name'] in layout['widget_status_tiles']:
            group = 'core.platform'
            for mapping in config['widget'].get('mappings', []):
                if mapping.get('field') in ('enabled', 'sealed'):
                    blocking = mapping['field'] == 'enabled'
                    mapping['remap'] = [{'value': True, 'to': 'Enabled' if blocking else 'Sealed'},
                        {'value': False, 'to': 'Paused' if blocking else 'Unsealed'}, {'any': True, 'to': 'Unknown'}]
        deployment['content'].append({'id': content_id, 'kind': 'tile', 'spec': {
            'name': row['name'], 'group': group, 'order': number+10, 'config': config}})
        identities.append({'id': content_id, 'legacy_group': row['group'], 'legacy_name': row['name'], 'href': row['href']})
    for dashboard in baseline['dashboards']:
        content_id = identifier('dashboard', Path(dashboard['source']).stem)
        document = read(dashboard['source'])
        deployment['content'].append({'id': content_id, 'kind': 'dashboard', 'spec': document})
        identities.append({'id': content_id, 'legacy_source': dashboard['source'], 'href': dashboard['href'], 'backend_id': document.get('id')})
    lock = make_lock([product])
    state = resolve([product], lock, deployment)
    # Recheck source digests before any output; do not disguise a moving checkout as a frozen release.
    if not check(baseline, source)['preparation_valid']:
        raise ValueError('Source changed while preparing candidate')
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'prepared', 'deploy_authorized': False, 'product_release': 'development content snapshot, not a public release',
        'user_tiles': len(baseline['services']), 'user_dashboards': len(baseline['dashboards']),
        'target_after_review': "the operator's own repository, after review",
        'checks': ['baseline hashes matched', 'all native dashboard definitions retained', 'existing destinations retained', 'owned content resolves'],
        'pending': ['review content/identity map', 'complete product image/source lock', 'live export and backend ID reconciliation', 'staged deployment and upgrade rehearsal']}
    for name, value in {'product-content.json': product, 'deployment.json': deployment, 'release.lock.json': lock,
                        'identity-map.json': identities, 'source-hashes.json': sources, 'report.json': report}.items():
        (output/name).write_text(canonical(value)+'\n', encoding='utf-8')
    write_bundle(output/'rendered', state, deployment)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=None,
                        help='the operator checkout the capture was taken from; required, because this '
                             'checkout ships no default path to one (privacy checks)')
    parser.add_argument('--baseline-dir', type=Path, default=None,
                        help='directory holding the baselines in the operator repository; default $' + BASELINE_ENV)
    parser.add_argument('--baseline', default=None,
                        help='baseline file name inside that directory (default ' + BASELINE_NAME + ')')
    parser.add_argument('--operator-url', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        baseline = baseline_file(args.baseline_dir, args.baseline or BASELINE_NAME)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.source is None:
        print(SOURCE_REFUSAL, file=sys.stderr)
        return 2
    print(canonical(prepare(args.source, read_document(baseline), args.operator_url, args.output)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

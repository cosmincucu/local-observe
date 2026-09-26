"""Save an offline synthetic content-upgrade rehearsal; this is not a running product upgrade."""
import argparse
import copy
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.require import refuse_optimized, require
from local_observe.deployment.content import Conflict, export_dashboard, make_lock, plan, resolve, write_bundle
from local_observe.inventory.validation import canonical, digest, read_document


def main():
    refuse_optimized()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--deployment-dir', type=Path, help='Use a prepared private candidate instead of the synthetic fixture')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    package = read_document(args.deployment_dir/'product-content.json' if args.deployment_dir else root/'examples/deployment/core-v1.yaml')
    deployment = read_document(args.deployment_dir/'deployment.json' if args.deployment_dir else root/'examples/deployment/custom.yaml')
    overridden = {r['id'] for r in deployment['overrides']}
    target = next(r for r in reversed(package['content']) if r['id'] not in overridden)
    newer = copy.deepcopy(package)
    newer['version'] = '0.2.0-demo.1'
    updated = next(r for r in newer['content'] if r['id'] == target['id'])
    if updated['kind'] == 'dashboard':
        updated['spec']['description'] = 'Upstream dashboard improvement'
    else:
        updated['spec']['name'] += ' (candidate)'
    before = resolve([package], make_lock([package]), deployment)
    after = resolve([newer], make_lock([newer]), deployment)
    clean = plan(before, before, after)
    require(clean['change'] == [target['id']] and not clean['remove'],
            'The simulated upgrade did not propose exactly the one upstream change')
    require([r for r in before['content'] if r['owner'] == 'user'] == [r for r in after['content'] if r['owner'] == 'user'],
            'An owner-owned tile or dashboard changed during the simulated upgrade')
    edited = copy.deepcopy(before)
    row = next(r for r in edited['content'] if r['owner'] == 'user' and r['kind'] == 'dashboard')
    row['spec']['title'] = 'Uncommitted dashboard edit'
    drift = plan(before, edited, after)
    require(drift['status'] == 'blocked', 'An unreviewed dashboard edit did not block the upgrade plan')
    custom = copy.deepcopy(deployment)
    upstream = target
    field = 'title' if upstream['kind'] == 'dashboard' else 'name'
    custom['overrides'].append({'id': upstream['id'], 'mode': 'patch', 'expect_sha256': digest(upstream), 'set': {field: 'Custom title'}})
    resolve([package], make_lock([package]), custom)
    try:
        resolve([newer], make_lock([newer]), custom)
        raise AssertionError('Upstream conflict was accepted')
    except Conflict:
        pass
    args.output.mkdir(parents=True, exist_ok=False)
    write_bundle(args.output/'before', before, deployment)
    write_bundle(args.output/'candidate', after, deployment)
    write_bundle(args.output/'rollback-render', before, deployment)
    require((args.output/'before/files.json').read_bytes() == (args.output/'rollback-render/files.json').read_bytes(),
            'Rendering the prior release twice did not produce the same bundle')
    report = {'status': 'pass', 'scope': 'Offline candidate content with simulated product upgrade; no database or live upgrade',
        'checks': ['user tiles and dashboards survive', 'upstream content changes visible', 'UI drift blocks',
                   'stale override blocks', 'deterministic rollback render'],
        'upgrade': clean, 'drift': drift}
    artifacts = {'package-before.json': package, 'package-candidate.json': newer, 'deployment.json': deployment,
        'lock-before.json': make_lock([package]), 'lock-candidate.json': make_lock([newer]), 'report.json': report,
        'dashboard-edit-proposal.json': export_dashboard(before, row['id'], row['spec'])}
    for name, value in artifacts.items():
        (args.output/name).write_text(canonical(value)+'\n', encoding='utf-8')
    print(canonical(report))


if __name__ == '__main__':
    main()

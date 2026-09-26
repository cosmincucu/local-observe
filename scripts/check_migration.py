"""Check baseline drift and completeness; passing preparation never authorizes cutover."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]   # this checkout: the one place a baseline must NOT be read from

# deployment separation (docs/DECISIONS.md, section H): the baselines describe one operator's estate, so they live in
# that operator's repository and never in this checkout. Two names are part of the contract: the
# variable every reader falls back to, and the capture every reader opens by default.
BASELINE_ENV = 'LO_MIGRATION_BASELINE_DIR'
BASELINE_NAME = 'baseline-02.json'
REFUSAL = ('Set --baseline-dir or the ' + BASELINE_ENV + ' environment variable to the directory that '
           "holds the baseline inputs in the operator's repository: this checkout ships none, and a "
           'default path inside it would read a file deployment separation removed.')
# privacy checks: the same argument applied to the tree the baseline *describes*. Three scripts defaulted
# --source to one person's workstation, so a stranger's run either failed later or hashed whatever
# happened to sit at that path. Shared by every reader, refused before any file is opened.
SOURCE_REFUSAL = ('Set --source to the operator checkout this baseline describes: this script ships no '
                  "default path to one, and the previous default named one person's workstation (deployment separation).")


def baseline_directory(baseline_dir: Path | None = None) -> Path:
    """Return the operator's baseline directory, refusing to guess one inside this checkout.

    The caller's argument wins over the environment variable; an empty or blank variable counts as
    unset, so a half-configured shell cannot silently point the gate at the wrong tree. A directory
    inside this checkout is refused too: deployment separation is not only about a default path but about where those
    files may exist at all, and pointing the variable back at the product tree would undo it quietly.
    """
    if baseline_dir is None:
        configured = os.environ.get(BASELINE_ENV, '').strip()
        if not configured:
            raise ValueError(REFUSAL)
        directory = Path(configured)
    else:
        directory = Path(baseline_dir)
    if directory.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError('Point --baseline-dir or ' + BASELINE_ENV + " at the baseline directory in the "
                         "operator's repository: " + str(directory) + ' lies inside this checkout, and '
                         'deployment separation removed those files from it.')
    return directory


def baseline_file(baseline_dir: Path | None = None, name: str = BASELINE_NAME) -> Path:
    """Return one baseline input file inside the operator's directory, refusing anything else.

    A directory that does not hold `name` is refused rather than reported as drift: a missing
    operator input and a source file that changed are different failures, and only the second one is
    this gate's job. `name` stays a bare file name so a caller cannot reach outside that directory.
    """
    candidate = Path(name)
    if candidate.is_absolute() or len(candidate.parts) != 1:
        raise ValueError('The baseline must be one file name inside the baseline directory, not a path: ' + name)
    path = baseline_directory(baseline_dir)/candidate.name
    if not path.is_file():
        raise ValueError('Set --baseline-dir or ' + BASELINE_ENV + " to the directory in the operator's "
                         'repository holding ' + candidate.name + '; ' + str(path.parent) + ' has no such file.')
    return path


def check(baseline, source):
    errors = []
    source = source.resolve()
    if baseline.get('schema_version') != 2 or not baseline.get('sources'):
        return {'preparation_valid': False, 'migration_ready': False, 'errors': ['Missing versioned source baseline']}
    # privacy checks: the capture carries the operator layout it was produced from, and this gate reads the
    # estate's names from that copy rather than from literals in this file or a second operator input.
    layout = baseline.get('layout')
    if not isinstance(layout, dict):
        return {'preparation_valid': False, 'migration_ready': False,
                'errors': ['Baseline carries no source layout: the capture predates the layout contract '
                           '(privacy checks), regenerate it with prepare_migration.py']}
    for name, expected in baseline['sources'].items():
        path = (source/name).resolve()
        if Path(name).is_absolute() or not path.is_relative_to(source):
            errors.append('Source path escapes checkout: '+name)
        elif not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            errors.append('Source drift or missing file: '+name)
    services, dashboards = baseline.get('services', []), baseline.get('dashboards', [])
    prefix = layout.get('dashboard_group_prefix')
    if not isinstance(prefix, str) or not prefix:
        errors.append('Baseline declares no dashboard group prefix')
        prefix = '\x00'   # names no group: an undeclared prefix must not silently mean "every group"
    tiles = {(s['name'], s['href']) for s in services if s['group'].startswith(prefix)}
    captured = {(d['name'], d['href']) for d in dashboards}
    if not tiles or tiles != captured or len(captured) != len(dashboards):
        errors.append('Dashboard destination mapping incomplete or duplicated')
    panels = 0
    for dashboard in dashboards:
        panels += len(dashboard.get('panels', []))
        if baseline['sources'].get(dashboard['source']) != dashboard['sha256']:
            errors.append('Dashboard source hash not anchored: '+dashboard['name'])
        if not dashboard.get('panels') or any(len(p.get('query_sha256', '')) != 64 for p in dashboard['panels']):
            errors.append('Dashboard query baseline incomplete: '+dashboard['name'])
    required = baseline.get('mcp', {}).get('required_contract_sets', {})
    declared = layout.get('mcp_contract_sets')
    if not isinstance(declared, list) or not declared:
        errors.append('Baseline declares no required MCP contract sets')
    elif not all(required.get(name) for name in declared):
        errors.append('Required MCP contract missing')
    return {'preparation_valid': not errors, 'migration_ready': False, 'errors': errors,
        'counts': {'services': len(services), 'dashboards': len(dashboards), 'panels': panels, 'sources': len(baseline['sources'])},
        'remaining_gates': ['Whole-stack upgrade with committed customisations and live dashboard parity (scoped platform/Homepage rehearsal passes separately)',
            'Pinned product revision and resolved private deployment/state manifest',
            'Authenticated legacy MCP names, schemas, bounded per-plane reads and error parity',
            'Dashboard query/producer/freshness parity for each destination being moved',
            'Verified estate backup and resident-model observation adapters',
            'Scoped pilot restore/rollback and observation-period acceptance',
            'Owner approval of pilot source, window and notification ownership'],
        'scope': 'Static baseline only; no live reads, writes, deployment or cutover'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=None,
                        help='the operator checkout this baseline describes; required, because this '
                             'checkout ships no default path to one (privacy checks)')
    parser.add_argument('--baseline-dir', type=Path, default=None,
                        help='directory holding the baselines in the operator repository; default $' + BASELINE_ENV)
    parser.add_argument('--baseline', default=BASELINE_NAME,
                        help='baseline file name inside that directory (default ' + BASELINE_NAME + ')')
    parser.add_argument('--baseline-only', action='store_true', help='Exit successfully for valid preparation, never declare migration ready')
    args = parser.parse_args()
    try:
        baseline = baseline_file(args.baseline_dir, args.baseline)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.source is None:
        print(SOURCE_REFUSAL, file=sys.stderr)
        return 2
    result = check(json.loads(baseline.read_text(encoding='utf-8')), args.source)
    print(json.dumps(result, indent=2))
    return 0 if args.baseline_only and result['preparation_valid'] else 2


if __name__ == '__main__':
    raise SystemExit(main())

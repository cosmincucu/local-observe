"""Offline CLI: generate drafts, render locked content, and review upgrades or dashboard exports."""
import argparse
from pathlib import Path
import subprocess

from local_observe.inventory.validation import canonical, read_document
from .content import (Conflict, DEPLOYMENT, LOCK, PACKAGE, STATE, export_dashboard, make_lock, plan, resolve,
                      write_bundle)
from .release import RELEASE, check_release, inspect_sqlite, transition, verify_inputs
from .live import SignozReader, compare, docker_homepage_export, signoz_export
from .recovery import OWNERSHIP, OWNER_PLAN, SNAPSHOT, bind_owners, coverage, docker_inventory
from .runtime_bundle import BUNDLE, check_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    schema = commands.add_parser('schema')
    schema.add_argument('name', choices=['package', 'lock', 'deployment', 'state', 'release', 'storage',
                                         'ownership', 'owner-plan', 'runtime-bundle'])
    runtime = commands.add_parser('check-runtime')
    for name in ('bundle', 'inventory', 'owners'):
        runtime.add_argument('--'+name, type=Path, required=True)
    owner_plan = commands.add_parser('check-owner-plan')
    owner_plan.add_argument('--plan', type=Path, required=True)
    owner_plan.add_argument('--inventory', type=Path, required=True)
    storage = commands.add_parser('export-storage',
                                  help='Read selected Compose projects on the configured Docker daemon')
    storage.add_argument('--project', action='append', required=True)
    storage.add_argument('--scope', required=True)
    ownership = commands.add_parser('check-ownership')
    ownership.add_argument('--ownership', type=Path, required=True)
    ownership.add_argument('--inventory', type=Path, required=True)
    release = commands.add_parser('verify-release')
    release.add_argument('--release', type=Path, required=True)
    release.add_argument('--source', type=Path, required=True)
    release.add_argument('--customisations', type=Path, required=True)
    gate = commands.add_parser('state-gate')
    for name in ('previous', 'candidate', 'database'):
        gate.add_argument('--'+name, type=Path, required=True)
    live = commands.add_parser('check-live')
    for name in ('previous', 'observed'):
        live.add_argument('--'+name, type=Path, required=True)
    dashboards = commands.add_parser(
        'review-dashboards', help='Review a saved export against private authoring; no query execution or import')
    for name in ('deployment', 'snapshot', 'documents', 'identities'):
        dashboards.add_argument('--'+name, type=Path, required=True)
    signoz = commands.add_parser('export-signoz')
    signoz.add_argument('--url', required=True)
    signoz.add_argument('--token-file', type=Path, required=True)
    signoz.add_argument('--ca-file', type=Path)
    signoz.add_argument('--identities', type=Path, required=True)
    signoz.add_argument('--output', type=Path, required=True)
    homepage = commands.add_parser('export-homepage')
    homepage.add_argument('--container', required=True)
    homepage.add_argument('--image-id', required=True)
    homepage.add_argument('--scope', required=True)
    lock = commands.add_parser('lock', help='Generate a draft content lock for review; no fetch or trust verification')
    lock.add_argument('--package', type=Path, action='append', required=True)
    build = commands.add_parser('render')
    build.add_argument('--package', type=Path, action='append', required=True)
    build.add_argument('--lock', type=Path, required=True)
    build.add_argument('--deployment', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    review = commands.add_parser('plan')
    for name in ('previous', 'observed', 'candidate'):
        review.add_argument('--'+name, type=Path, required=True)
    export = commands.add_parser('export-dashboard')
    export.add_argument('--state', type=Path, required=True)
    export.add_argument('--id', required=True)
    export.add_argument('--document', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'schema':
            result = {'$schema': 'https://json-schema.org/draft/2020-12/schema',
                      **{'package': PACKAGE, 'lock': LOCK, 'deployment': DEPLOYMENT, 'state': STATE,
                         'release': RELEASE, 'storage': SNAPSHOT, 'ownership': OWNERSHIP,
                         'owner-plan': OWNER_PLAN, 'runtime-bundle': BUNDLE}[args.name]}
        elif args.command == 'check-runtime':
            result = check_bundle(read_document(args.bundle), read_document(args.inventory), read_document(args.owners))
        elif args.command == 'check-owner-plan':
            _, result = bind_owners(read_document(args.plan), read_document(args.inventory))
        elif args.command == 'check-ownership':
            result = coverage(read_document(args.ownership), read_document(args.inventory))
        elif args.command == 'verify-release':
            release = check_release(read_document(args.release))
            verify_inputs(release, args.source, args.customisations)
            result = {'status': 'pins-verified',
                      'scope': 'source bytes only; runtime image/state inspection still required',
                      'deploy_authorized': False}
        elif args.command == 'state-gate':
            result = transition(read_document(args.previous), read_document(args.candidate),
                                inspect_sqlite(args.database))
        elif args.command == 'check-live':
            result = compare(read_document(args.previous), read_document(args.observed))
        elif args.command == 'review-dashboards':
            from .dashboard_review import review
            result = review(*[read_document(getattr(args, name))
                              for name in ('deployment', 'snapshot', 'documents', 'identities')])
        elif args.command == 'export-signoz':
            if args.output.exists():
                raise Conflict('Export output must be new')
            reader = SignozReader(args.url, args.token_file.read_text().strip(), ca_file=args.ca_file)
            snapshot, documents = signoz_export(reader, args.url.rstrip('/'), read_document(args.identities))
            args.output.mkdir(mode=0o700, parents=True)
            (args.output/'documents.json').write_text(canonical(documents)+'\n', encoding='utf-8')
            (args.output/'snapshot.json').write_text(canonical(snapshot)+'\n', encoding='utf-8')
            result = {'status': 'exported', 'output': str(args.output), 'deploy_authorized': False}
        elif args.command in ('export-homepage', 'export-storage'):
            def run(*command):
                process = subprocess.run(command, capture_output=True, text=True, timeout=30)
                if process.returncode:
                    raise Conflict('Scoped Docker read failed; no snapshot produced')
                return process.stdout
            result = (docker_inventory(run, args.project, args.scope) if args.command == 'export-storage'
                      else docker_homepage_export(run, args.container, args.image_id, args.scope))
        elif args.command == 'lock':
            result = make_lock([read_document(p) for p in args.package])
        elif args.command == 'render':
            deployment = read_document(args.deployment)
            state = resolve([read_document(p) for p in args.package], read_document(args.lock), deployment)
            write_bundle(args.output, state, deployment)
            result = {'status': 'rendered', 'output': str(args.output), 'deploy_authorized': False}
        elif args.command == 'plan':
            result = plan(*[read_document(getattr(args, name)) for name in ('previous', 'observed', 'candidate')])
        else:
            result = export_dashboard(read_document(args.state), args.id, read_document(args.document))
        print(canonical(result))
        return 2 if result.get('status') == 'blocked' else 0
    except Conflict as error:
        parser.exit(2, str(error)+'. No deployment performed.\n')
    except (ValueError, OSError, RecursionError, subprocess.TimeoutExpired):
        parser.exit(2, 'Content operation refused. Check schemas, ownership, lock hashes and output paths. '
                       'No deployment performed.\n')


if __name__ == '__main__':
    raise SystemExit(main())

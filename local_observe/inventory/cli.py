"""Inventory commands; discovery and forge writes require explicit configured scope."""
import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sqlite3
import datetime as dt
import uuid

from . import discovery, index
from .validation import InvalidInventory, declared, read_document, timestamp, utc_text
from local_observe.log import get_logger

log = get_logger(__name__)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    validate = commands.add_parser('validate')
    validate.add_argument('declarations', type=Path)
    build = commands.add_parser('build')
    build.add_argument('declarations', type=Path)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--revision', required=True)
    build.add_argument('--now', type=timestamp)
    resolve = commands.add_parser('resolve')
    resolve.add_argument('--index', type=Path, required=True)
    resolve.add_argument('--id')
    resolve.add_argument('--alias-type', choices=['hostname', 'host.id', 'ip', 'legacy_id', 'service.name'])
    resolve.add_argument('--alias-value')
    resolve.add_argument('--scope', default='')
    impact = commands.add_parser('dependents')
    impact.add_argument('--index', type=Path, required=True)
    impact.add_argument('--id', required=True)
    impact.add_argument('--limit', type=int, default=100)
    observe = commands.add_parser('observe')
    observe.add_argument('snapshot', type=Path)
    observe.add_argument('--database', type=Path, required=True)
    observe.add_argument('--now', type=timestamp)
    for name in ('drift', 'propose'):
        command = commands.add_parser(name)
        command.add_argument('--index', type=Path, required=True)
        command.add_argument('--observed', type=Path, required=True)
        command.add_argument('--source', required=True, action='append' if name == 'drift' else 'store')
        command.add_argument('--now', type=timestamp)
        command.add_argument('--max-age-seconds', type=int, default=3600)
        if name == 'propose':
            command.add_argument('--observation-id', required=True)
            command.add_argument('--output', type=Path, required=True)
    docker = commands.add_parser('discover-docker')
    docker.add_argument('--database', type=Path, required=True)
    docker.add_argument('--source', required=True)
    docker.add_argument('--socket', required=True)
    docker.add_argument('--expected-root', required=True)
    docker.add_argument('--project', action='append', required=True)
    forge = commands.add_parser('publish-proposal')
    forge.add_argument('--proposal', type=Path, required=True)
    forge.add_argument('--url', required=True)
    forge.add_argument('--repository', required=True)
    forge.add_argument('--base-branch', required=True)
    forge.add_argument('--declaration-path', required=True)
    forge.add_argument('--token-file', type=Path, required=True)
    export = commands.add_parser('export-logicmonitor',
                                 help='plan (default) or apply a one-way export of the index to LogicMonitor')
    export.add_argument('--index', type=Path, required=True)
    export.add_argument('--config', type=Path, required=True)
    export.add_argument('--token-file', type=Path, required=True,
                        help='file holding a LogicMonitor Bearer API token')
    export.add_argument('--apply', action='store_true',
                        help='perform the planned changes; without it nothing is written to LogicMonitor')
    args = parser.parse_args(argv)
    try:
        if args.command == 'validate':
            document = declared(read_document(args.declarations))
            result = {'status': 'valid', 'resources': len(document['resources'])}
        elif args.command == 'build':
            result = index.build(read_document(args.declarations), args.output, args.revision, now=args.now)
        elif args.command == 'resolve':
            if bool(args.alias_type) != bool(args.alias_value) or not (args.id or args.alias_type):
                raise InvalidInventory('Supply UUID or both alias type/value')
            aliases = ([{'type': args.alias_type, 'value': args.alias_value, 'scope': args.scope}]
                       if args.alias_type else [])
            with index.readonly(args.index) as connection:
                result = index.resolve(connection, resource_id=args.id, aliases=aliases)
        elif args.command == 'dependents':
            with index.readonly(args.index) as connection:
                result = index.dependents(connection, args.id, args.limit)
        elif args.command == 'observe':
            result = discovery.ingest(args.database, read_document(args.snapshot), now=args.now)
        elif args.command == 'drift':
            result = discovery.drift(args.index, args.observed, args.source, now=args.now,
                                     max_age_seconds=args.max_age_seconds)
        elif args.command == 'propose':
            result = discovery.propose(args.index, args.observed, args.source, args.observation_id,
                                       args.output, now=args.now, max_age_seconds=args.max_age_seconds)
        elif args.command == 'discover-docker':
            from .docker_provider import snapshot
            now = dt.datetime.now(dt.timezone.utc)
            try:
                document = snapshot(args.project, source=args.source, socket=args.socket,
                                    expected_root=args.expected_root, now=now)
            except (ValueError, OSError) as exc:
                document = {'schema_version': 1, 'source': args.source, 'snapshot_id': str(uuid.uuid4()),
                            'observed_at': utc_text(now), 'status': 'error', 'complete': False,
                            'scope': [], 'observations': [], 'error_code': 'docker_discovery_unavailable'}
                discovery.ingest(args.database, document, now=now)
                raise InvalidInventory('Discovery failed; error snapshot retained') from exc
            result = discovery.ingest(args.database, document, now=now)
            result['observations'] = len(document['observations'])
        elif args.command == 'export-logicmonitor':
            from . import logicmonitor
            from local_observe.http import JsonClient
            config = logicmonitor.load_config(read_document(args.config))
            with index.readonly(args.index) as connection:
                resources = logicmonitor.read_resources(connection)
            client = JsonClient(logicmonitor.portal_base(config), args.token_file.read_text().strip(), timeout=20)
            result = logicmonitor.plan(resources, logicmonitor.fetch_devices(client), config)
            result['mode'] = 'apply' if args.apply else 'dry-run'
            if args.apply:
                result['applied'] = logicmonitor.apply(client, result, config['max_changes'])
                if result['applied']['failed']:
                    print(json.dumps(result, indent=2, sort_keys=True))
                    return 1
        else:
            from .forge import publish
            from local_observe.http import JsonClient
            result = publish(JsonClient(args.url, args.token_file.read_text().strip(), scheme='token'), args.repository,
                             args.base_branch, args.declaration_path, read_document(args.proposal))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        # stdout keeps its machine-readable JSON contract; the diagnosis goes to the log stream.
        log.warning('Inventory command failed', extra={'command': args.command, 'error_class': type(exc).__name__})
        log.debug('Inventory command details', exc_info=True)
        print(json.dumps({'status': 'error',
                          'error': str(exc) if isinstance(exc, InvalidInventory) else type(exc).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

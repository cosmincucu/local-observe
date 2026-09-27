"""Local OS-authenticated observer commands. Structured logs never include evidence bodies."""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import sys

from .contract import Config, ObserverError, encoded, instant, strict_json
from .journal import Journal
from .runtime import Observer


def read_json(path: str, limit: int = 65536):
    with Path(path).open('rb') as stream:
        return strict_json(stream.read(limit + 1), limit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True, help='owned 0700 directory outside source control')
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('run', 'serve'):
        action = commands.add_parser(command)
        action.add_argument('--config', required=True)
        if command == 'run':
            action.add_argument('--cycle-id')
            action.add_argument('--now', help='explicit UTC observation window end for replayable local runs')
    check = commands.add_parser('check')
    check.add_argument('--max-age-seconds', type=int, default=7200)
    replay = commands.add_parser('replay')
    replay.add_argument('cycle_id')
    feedback = commands.add_parser('feedback')
    feedback.add_argument('cycle_id')
    feedback.add_argument('--id', required=True)
    feedback.add_argument('--input', required=True, help='JSON with independent human review fields')
    retrieve = commands.add_parser('retrieve')
    retrieve.add_argument('--query', default='')
    retrieve.add_argument('--limit', type=int, default=10)
    export = commands.add_parser('export')
    export.add_argument('--output', required=True, help='new file within the private state directory')
    export.add_argument('--limit', type=int, default=100)
    backup = commands.add_parser('backup')
    backup.add_argument('--output', required=True, help='new database within the private state directory')
    args = parser.parse_args(argv)
    journal = None
    try:
        journal = Journal(args.state)
        if args.command in ('run', 'serve'):
            config = Config.from_dict(read_json(args.config))
            fixed = instant(args.now) if args.command == 'run' and args.now else None
            observer = Observer(config, journal, clock=(lambda: fixed) if fixed else None)
            if args.command == 'serve':
                observer.serve()
                return 0
            result = observer.run(args.cycle_id)
            print(encoded({key: result[key] for key in ('cycle_id', 'status', 'coverage', 'decision', 'error',
                                                       'ended_at', 'delivery')}))
            return 0 if result['status'] == 'completed' else 2
        if args.command == 'check':
            result = journal.check(now=dt.datetime.now(dt.timezone.utc), max_age_seconds=args.max_age_seconds)
            print(encoded(result))
            return 0 if result['healthy'] else 2
        if args.command == 'replay':
            print(encoded(journal.replay(args.cycle_id)))
        elif args.command == 'feedback':
            result = journal.feedback(args.cycle_id, args.id, read_json(args.input, 16384))
            print(encoded(result))
        elif args.command == 'retrieve':
            print(encoded(journal.examples(query=args.query, limit=args.limit)))
        elif args.command == 'export':
            target = Path(args.output)
            if target.parent.resolve() != journal.directory.resolve():
                raise ObserverError('export_must_be_in_private_directory')
            examples = journal.examples(limit=args.limit)
            fd = journal.create_file(target)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                for example in examples:
                    stream.write(encoded(example) + '\n')
                stream.flush()
                os.fsync(stream.fileno())
            print(encoded({'exported': len(examples), 'schema_version': 1}))
        elif args.command == 'backup':
            journal.backup(args.output)
            print(encoded({'backup': 'verified'}))
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(encoded({'error': str(exc) if isinstance(exc, ObserverError) else 'observer_command_failed'}),
              file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    finally:
        if journal is not None:
            journal.close()


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())

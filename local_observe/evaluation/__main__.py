"""Print or exclusively create a deterministic offline evaluation or preflight report."""
import argparse
import json
import sys
from pathlib import Path

from .fault_inject import synthetic
from .model import load
from .report import evaluate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--observer-directory', type=Path,
                        help='Opt in to real observer/model calls; new protected runtime directory outside Git')
    parser.add_argument('--observer-config', type=Path, help='Evaluate this exact observer Config with corpus sources')
    parser.add_argument('--baseline-config', type=Path, help='Exact operator resource/metric threshold JSON')
    parser.add_argument('--preflight', action='store_true',
                        help='Feasibility check only: no model, journal or namespace, report to --output')
    args = parser.parse_args(argv)
    try:
        if args.preflight and args.observer_directory:
            raise ValueError('Preflight reserves no output namespace; omit --observer-directory')
        if args.preflight:
            missing = [name for name, value in (('--corpus', args.corpus), ('--observer-config', args.observer_config),
                                                ('--baseline-config', args.baseline_config), ('--output', args.output))
                       if value is None]
            if missing:
                raise ValueError('Preflight requires ' + ', '.join(missing))
        config = baseline_config = None
        if args.baseline_config:
            from local_observe.observer.contract import strict_json
            from .baseline_config import validate_config
            with args.baseline_config.open('rb') as stream:
                baseline_config = validate_config(strict_json(stream.read(65537)))
        if args.observer_config:
            from local_observe.observer.contract import Config, strict_json
            with args.observer_config.open('rb') as stream:
                config = Config.from_dict(strict_json(stream.read(65537)))
        if args.observer_directory:
            if not args.observer_directory.is_absolute():
                raise ValueError('Observer output requires an absolute private path')
            if not args.output or args.output.parent != args.observer_directory:
                raise ValueError('Observer report must be inside its protected output directory')
        private_output = args.preflight or any(value is not None for value in
                                               (args.corpus, args.observer_directory, args.baseline_config))
        if private_output:
            if not args.output or not args.output.is_absolute():
                raise ValueError('Supplied inputs require an absolute protected report output')
            from local_observe.observer.journal import private_directory, private_file
            import os
        if args.preflight:
            from .preflight import preflight
            report = preflight(load(args.corpus), revision=args.revision, observer_config=config,
                               baseline_config=baseline_config)
        else:
            report = evaluate(load(args.corpus) if args.corpus else synthetic(), revision=args.revision,
                              observer_directory=args.observer_directory, observer_config=config,
                              baseline_config=baseline_config)
        text = json.dumps(report, indent=2, allow_nan=False)
        if args.output:
            if private_output:
                fd = private_directory(args.output.parent, create=False, reject_git=True)
                try:
                    with os.fdopen(private_file(args.output.name, directory_fd=fd, exclusive=True),
                                   'w', encoding='utf-8') as stream:
                        stream.write(text + '\n')
                finally:
                    os.close(fd)
            else:
                with args.output.open('x', encoding='utf-8') as stream:
                    stream.write(text + '\n')
        else:
            print(text)
    except (ValueError, OSError) as exc:
        print(f'Evaluation refused: {exc}', file=sys.stderr)
        return 2
    return 2 if args.preflight and not report['inputs_feasible'] else 0


if __name__ == '__main__':
    raise SystemExit(main())

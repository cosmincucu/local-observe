"""Print or exclusively create a deterministic offline evaluation report."""
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
    args = parser.parse_args(argv)
    try:
        config = None
        if args.observer_config:
            from local_observe.observer.contract import Config, strict_json
            with args.observer_config.open('rb') as stream:
                config = Config.from_dict(strict_json(stream.read(65537)))
        if args.observer_directory:
            if not args.observer_directory.is_absolute():
                raise ValueError('Observer output requires an absolute private path')
            if not args.output or args.output.parent != args.observer_directory:
                raise ValueError('Observer report must be inside its protected output directory')
            from local_observe.observer.journal import private_file
            import os
        report = evaluate(load(args.corpus) if args.corpus else synthetic(), revision=args.revision,
                          observer_directory=args.observer_directory, observer_config=config)
        text = json.dumps(report, indent=2, allow_nan=False)
        if args.output:
            if args.observer_directory:
                with os.fdopen(private_file(args.output, exclusive=True), 'w', encoding='utf-8') as stream:
                    stream.write(text + '\n')
            else:
                with args.output.open('x', encoding='utf-8') as stream:
                    stream.write(text + '\n')
        else:
            print(text)
    except (ValueError, OSError) as exc:
        print(f'Evaluation refused: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

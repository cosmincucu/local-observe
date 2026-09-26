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
    args = parser.parse_args(argv)
    try:
        report = evaluate(load(args.corpus) if args.corpus else synthetic(), revision=args.revision)
        text = json.dumps(report, indent=2, allow_nan=False)
        if args.output:
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

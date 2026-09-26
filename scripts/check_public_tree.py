"""Check source paths, documentation links and an optional external identifier inventory.

This reads working-tree files, including untracked files not ignored by Git. It does not
inspect or clear Git history or metadata. Keep identifier policies and reports outside source.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PRIVATE_TREES = ('archive/', 'docs/agents/', 'docs/evidence/', 'docs/history/',
                 'docs/remediation/', 'docs/research/', 'docs/staging/')
LINK = re.compile(r'(?<!!)\[[^\]\n]+\]\(([^)\n]+)\)')
MAX_FILE = 8 * 1024 * 1024


def policy_tokens(path: Path | None, root: Path) -> tuple[str, ...]:
    if path is None:
        return ()
    path = path.resolve(strict=True)
    if path.is_relative_to(root.resolve()):
        raise ValueError('identifier policy must be outside the source tree')
    if path.stat().st_size > MAX_FILE:
        raise ValueError('identifier policy exceeds size limit')
    data = json.loads(path.read_text(encoding='utf-8'))
    tokens = data.get('forbidden') if isinstance(data, dict) else None
    if not isinstance(tokens, list) or not tokens or not all(
        isinstance(token, str) and token.strip() and '\x00' not in token for token in tokens
    ):
        raise ValueError('policy requires a nonempty forbidden string list')
    return tuple(tokens)


def source_paths(root: Path) -> list[str]:
    result = subprocess.run(
        ['git', '-c', f'safe.directory={root}', '-C', str(root), 'ls-files',
         '--cached', '--others', '--exclude-standard', '-z'],
        capture_output=True, check=True,
    )
    names = set(result.stdout.decode('utf-8').strip('\0').split('\0')) - {''}
    return sorted(name for name in names if (root / name).exists() or (root / name).is_symlink())


def check(root: Path, names: list[str], tokens: tuple[str, ...] = ()) -> list[str]:
    root = root.resolve(strict=True)
    errors = []
    for name in names:
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            errors.append(f'{name}: unsafe source path')
            continue
        path = root / relative
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            errors.append(f'{name}: linked source paths require separate review')
            continue
        # A tracked deletion is part of the reviewed working-tree diff.
        if not path.exists():
            continue
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            errors.append(f'{name}: source file cannot be inspected within limits')
            continue
        if name.startswith(PRIVATE_TREES):
            errors.append(f'{name}: private operational records are not product source')
        if (path.name == '.env' or path.suffix in ('.key', '.pat', '.pem', '.log', '.bundle') or
                (path.suffix == '.env' and not path.name.endswith('.env.example'))):
            errors.append(f'{name}: private runtime artifact must remain outside source')
        data = path.read_bytes()
        text = data.decode('utf-8', errors='replace')
        for token in tokens:
            if (token.casefold() in name.casefold() or token.casefold() in text.casefold() or
                    any(token.lower().encode(encoding) in data.lower()
                        for encoding in ('utf-8', 'utf-16-le', 'utf-16-be'))):
                errors.append(f'{name}: external identifier policy match')
                break
        if path.suffix.lower() != '.md':
            continue
        # Fenced examples contain intentionally hypothetical links and are not navigation.
        prose = re.sub(r'^```[^\n]*\n.*?^```[^\n]*$', '', text, flags=re.M | re.S)
        for raw in LINK.findall(prose):
            target = raw.split(' "', 1)[0].strip('<>')
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (path.parent / unquote(parsed.path)).resolve()
            if not destination.is_relative_to(root) or not destination.exists():
                errors.append(f'{name}: unresolved documentation link: {target}')
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--policy', type=Path, help='private JSON with a forbidden string list')
    args = parser.parse_args()
    try:
        names = source_paths(args.root)
        errors = check(args.root, names, policy_tokens(args.policy, args.root))
    except (OSError, ValueError, subprocess.CalledProcessError):
        print('Public source check could not read the tree or policy.', file=sys.stderr)
        return 2
    for error in errors:
        print(error)
    print(f'Public source check: {len(errors)} findings across {len(names)} candidate paths.')
    return int(bool(errors))


if __name__ == '__main__':
    raise SystemExit(main())

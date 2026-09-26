"""Immutable development/public release pins and conservative SQLite upgrade gates."""
from collections.abc import Callable, Sequence
from contextlib import closing
import ast
import hashlib
from pathlib import Path
import re
import sqlite3
import subprocess
from typing import Any

from .content import Conflict, HASH, LOCK, NAME, TEXT, obj, validate
from local_observe.inventory.validation import digest, read_document

SOURCE = obj({'kind': {'enum': ['git', 'snapshot']}, 'revision': {'type': ['string', 'null']},
              'files': {'type': 'object', 'minProperties': 1, 'additionalProperties': HASH}, 'sha256': HASH})
IMAGE = obj({'reference': TEXT, 'image_id': {'type': 'string', 'pattern': '^sha256:[a-f0-9]{64}$'},
             'platform': {'const': 'linux/amd64'}})
SQLITE = obj({'application_id': {'type': 'integer', 'minimum': 1},
              'user_version': {'type': 'integer', 'minimum': 1}, 'schema_sha256': HASH})
RELEASE = obj({'schema_version': {'const': 1}, 'name': NAME, 'channel': {'enum': ['development', 'public']},
    'source': SOURCE, 'customisations': SOURCE, 'content': LOCK, 'deployment_sha256': HASH,
    'components': {'type': 'object', 'minProperties': 1, 'propertyNames': NAME, 'additionalProperties': IMAGE},
    'contracts': obj({'content': {'const': 1}, 'platform_api': {'const': 1}, 'homepage': {'const': '1.13.2'},
                      'signoz_dashboards': {'const': 'v2-v6'}}),
    'state': obj({'platform': SQLITE, 'rollback': {'const': 'restore-backup'},
                  'migration': {'const': 'none'}})})
# Optional for historical v1 receipts; absent means the old, unguarded delivery contract.
RELEASE['properties']['contracts']['properties']['notification_safety'] = {'enum': [0, 1, 2]}


def notification_contract(root: Path | str) -> int:
    """Read the pinned source constant without importing the candidate's code."""
    path = Path(root) / 'local_observe/platform/notification_safety.py'
    if not path.exists():
        return 0
    tree = ast.parse(path.read_text(encoding='utf-8'))
    values = [node.value for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == 'SAFETY_CONTRACT' for target in node.targets)]
    if (len(values) != 1 or not isinstance(values[0], ast.Constant) or type(values[0].value) is not int
            or values[0].value not in (1, 2)):
        raise Conflict('Missing or unsupported notification safety contract constant')
    return values[0].value


def source_pin(root: Path | str, names: Sequence[str],
               revision: str | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    files = {}
    for name in sorted(names):
        path = root/name
        if not isinstance(name, str) or '\\' in name or Path(name).is_absolute() or '..' in Path(name).parts:
            raise Conflict('Unsafe source path')
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
            raise Conflict('Missing or unsafe source file')
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    pin = {'kind': 'git' if revision else 'snapshot', 'revision': revision, 'files': files, 'sha256': digest(files)}
    check_source(pin)
    return pin


def check_source(pin: dict[str, Any]) -> None:
    validate(pin, SOURCE, 'source pin')
    if pin['sha256'] != digest(pin['files']):
        raise Conflict('Source manifest digest differs')
    if pin['kind'] == 'git':
        if not isinstance(pin['revision'], str) or not re.fullmatch(r'[a-f0-9]{40}|[a-f0-9]{64}', pin['revision']):
            raise Conflict('Git source requires a complete commit ID')
    elif pin['revision'] is not None:
        raise Conflict('Snapshot must not claim a Git revision')
    for name in pin['files']:
        if '\\' in name or ':' in name or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/')):
            raise Conflict('Unsafe source manifest path')


def verify_source(root: Path | str, pin: dict[str, Any]) -> None:
    check_source(pin)
    if source_pin(root, pin['files'], pin['revision']) != pin:
        raise Conflict('Source files differ from release pin')


def verify_git_source(root: Path | str, pin: dict[str, Any], *,
                      git_directory: Path | str | None = None) -> None:
    """Prove declared commit blobs match the pinned build bytes; never fetch or trust a label."""
    check_source(pin)
    if pin['kind'] != 'git':
        raise Conflict('Committed source proof requires a Git pin')
    root = Path(root).resolve()
    git_directory = Path(git_directory).resolve() if git_directory else root
    repository = next((p for p in (git_directory, *git_directory.parents) if (p/'.git').exists()), git_directory)
    def git(*args):
        result = subprocess.run(['git', '-c', 'safe.directory='+repository.as_posix(), '-C', str(git_directory), *args],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise Conflict('Git commit/source proof unavailable')
        return result.stdout
    prefix = git('rev-parse', '--show-prefix').decode().strip()
    revision = git('rev-parse', '--verify', pin['revision']+'^{commit}').decode().strip()
    if revision != pin['revision']:
        raise Conflict('Source revision is not the named commit')
    for name, expected in pin['files'].items():
        if hashlib.sha256(git('show', revision+':'+prefix+name)).hexdigest() != expected:
            raise Conflict('Pinned source bytes differ from committed Git blobs; export exact Git bytes')
    verify_source(root, pin)


def check_release(release: dict[str, Any]) -> dict[str, Any]:
    validate(release, RELEASE, 'runtime release')
    for key in ('source', 'customisations'):
        check_source(release[key])
        if release['channel'] == 'public' and release[key]['kind'] != 'git':
            raise Conflict('Public deployment requires committed product and customisation sources')
    for pin in release['components'].values():
        registry = re.fullmatch(r'[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}', pin['reference'])
        local = pin['reference'] == pin['image_id']
        if not registry and not (local and release['channel'] == 'development'):
            raise Conflict('Image must be immutable; daemon-local IDs are development-only')
    return release


def verify_inputs(release: dict[str, Any], source: Path | str, customisations: Path | str) -> None:
    check_release(release)
    verify_source(source, release['source'])
    verify_source(customisations, release['customisations'])
    for root, pin in ((source, release['source']), (customisations, release['customisations'])):
        if pin['kind'] == 'git':
            verify_git_source(root, pin)
    if not {'deployment.json', 'release.lock.json'} <= set(release['customisations']['files']):
        raise Conflict('Customisation pin must include deployment and content lock')
    if digest(read_document(Path(customisations)/'deployment.json')) != release['deployment_sha256']:
        raise Conflict('Release deployment digest differs from pinned inputs')
    if read_document(Path(customisations)/'release.lock.json') != release['content']:
        raise Conflict('Release content lock differs from pinned inputs')


def verify_images(release: dict[str, Any], inspect: Callable[[str], dict[str, Any]]) -> None:
    check_release(release)
    for pin in release['components'].values():
        actual = inspect(pin['reference'])
        if actual['Id'] != pin['image_id'] or actual['Os']+'/'+actual['Architecture'] != pin['platform']:
            raise Conflict('Resolved image identity or platform differs from release pin')


def transition(previous: dict[str, Any], candidate: dict[str, Any],
               actual_state: dict[str, Any]) -> dict[str, Any]:
    """Decide whether a candidate release may be deployed against the state that is actually live.

    The explicit path the refusal below refers to is `lo-platform migrate`; `transition` itself never
    runs it, because deploying a candidate release is not the place to rewrite operational state.
    """
    check_release(previous)
    check_release(candidate)
    # A declared version alone never grants compatibility, and this function does not close the gap by
    # itself: `lo-platform migrate` is the operator's explicit act, taken before a candidate is promoted,
    # and it is never run from here (see the docstring).
    if previous['state']['platform'] != actual_state or candidate['state']['platform'] != actual_state:
        raise Conflict('Database migration or explicit restore required; no compatible v1 transition')
    old_safety = previous['contracts'].get('notification_safety', 0)
    new_safety = candidate['contracts'].get('notification_safety', 0)
    if new_safety < old_safety:
        raise Conflict('Rollback cannot remove notification safety enforcement')
    if ({k: v for k, v in previous['contracts'].items() if k != 'notification_safety'} !=
            {k: v for k, v in candidate['contracts'].items() if k != 'notification_safety'}):
        raise Conflict('Adapter contract transition is not implemented')
    if set(previous['components']) != set(candidate['components']):
        raise Conflict('Component addition/removal needs a separate lifecycle plan')
    return {'status': 'review-required', 'deploy_authorized': False,
            'previous_sha256': digest(previous), 'candidate_sha256': digest(candidate)}


def inspect_sqlite(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Conflict('Expected an existing regular SQLite database')
    with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('BEGIN')
        if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
            raise Conflict('SQLite integrity check failed')
        schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master"
                            " WHERE sql IS NOT NULL ORDER BY type,name").fetchall()
        result = {'application_id': db.execute('PRAGMA application_id').fetchone()[0],
                  'user_version': db.execute('PRAGMA user_version').fetchone()[0], 'schema_sha256': digest(schema)}
        validate(result, SQLITE, 'SQLite state pin')
        return result


def backup_sqlite(source: Path | str, target: Path | str) -> dict[str, Any]:
    source, target = Path(source), Path(target)
    inspect_sqlite(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidentally replacing the only recovery copy.
    with target.open('xb'):
        pass
    target.chmod(0o600)
    with closing(sqlite3.connect(source.resolve().as_uri()+'?mode=ro', uri=True)) as src:
        with closing(sqlite3.connect(target)) as dst:
            src.backup(dst)
    return {'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'state': inspect_sqlite(target)}

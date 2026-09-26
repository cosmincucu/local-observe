"""Read a running platform container's mounted role credentials.

The container is the default reader because user-namespace ownership may prevent a
host-side read. Callers with an explicitly readable copy may pass ``host_path``.
Environment-valued credentials are refused; mounts and complete identity/role/token
rows are required. Credential values must remain in memory and out of reports.
"""
from __future__ import annotations

import json
from pathlib import Path
from collections.abc import Sequence

from _lib.require import require
from _lib.run import run

#: Where ``components/control/platform/compose.yaml`` mounts the role list inside the container.
CREDENTIALS_MOUNT = '/run/secrets/platform-credentials'

#: The environment value security manifests retired. Its presence means the container predates the file mount.
RETIRED_ENVIRONMENT_VALUE = 'LO_PLATFORM_CREDENTIALS_JSON'


def role_credentials(container: str, *, mount: str = CREDENTIALS_MOUNT,
                     host_path: str | Path | None = None) -> list[dict]:
    """Return the ``{identity, role, token}`` rows one platform container was started with.

    Args:
        container: Name or id of the platform container to inspect.
        mount: Path *inside* that container where the manifest mounts the credentials file.
        host_path: Read this host file instead of the container's copy. Only for a caller that
            knows the file is readable by its own account; the container read is the default.

    Returns:
        The role list the service is actually serving, in manifest order.

    Raises:
        ValueError: The container still receives credentials as an environment value, does not name
            ``mount`` in its environment or in its mount table, has nothing readable at that path,
            or the file is not a non-empty list of complete identity/role/token rows.
    """
    # `--format '{{json .Config.Env}}'` prints the array itself, not an inspect object: there is no
    # container element to index. The same is true of `.Mounts` below. (The copy this moved out of
    # indexed [0], which made the env rows a single string and the mount rows its characters, so
    # every call died in the dict() comprehension before it could read anything.)
    environment = dict(row.split('=', 1) for row in
                       json.loads(run('docker', 'inspect', '--format', '{{json .Config.Env}}', container)))
    require(RETIRED_ENVIRONMENT_VALUE not in environment,
            'The staging platform still receives role credentials as an environment value; redeploy it first')
    require(environment.get('LO_PLATFORM_CREDENTIALS') == mount,
            'The staging platform does not read role credentials from ' + mount)
    if host_path is None:
        mounts = json.loads(run('docker', 'inspect', '--format', '{{json .Mounts}}', container))
        require(any(entry.get('Destination') == mount for entry in mounts),
                'The platform mounts nothing at ' + mount + '; the caller must pass host_path')
        text, where = _read_inside(container, mount), container + ':' + mount
    else:
        source = Path(host_path)
        require(source.is_file() and not source.is_symlink(),
                'Role credentials are not a regular file at ' + str(source))
        text, where = source.read_text(), str(source)
    try:
        rows = json.loads(text)
    except ValueError as exc:
        raise ValueError('Role credentials in ' + where + ' are not readable JSON (' + type(exc).__name__
                         + ')') from exc
    require(isinstance(rows, list) and rows
            and all({'identity', 'role', 'token'} <= set(row) and row['token'] for row in rows),
            'Role credential file is not a non-empty list of identity/role/token rows')
    return rows


def _read_inside(container: str, path: str) -> str:
    """Return the text of one file in a running container, refusing anything but a regular file.

    Two bounded ``docker exec`` reads rather than one: :func:`_lib.run.run` deliberately keeps a
    child's stderr out of the message it raises, so a failure inside the child would arrive as
    "exit 1" with no reason. The shape check therefore reports itself, in the parent's words.

    Args:
        container: The container to read from.
        path: Absolute path inside it.

    Returns:
        The file's text.

    Raises:
        ValueError: The path is absent, is a symlink, or is not a regular file in that container.
    """
    kind = run('docker', 'exec', container, 'python', '-B', '-c',
               "import os,sys; p=sys.argv[1]; "
               "print('symlink' if os.path.islink(p) else 'file' if os.path.isfile(p) else 'absent')", path)
    require(kind == 'file', 'Role credentials are not a regular file at ' + path + ' inside '
                            + container + ' (found ' + kind + ')')
    return run('docker', 'exec', container, 'python', '-B', '-c',
               "import sys; sys.stdout.write(open(sys.argv[1]).read())", path)


def token_for(rows: Sequence[dict], identity: str | None = None,
              role: str | None = None, *, label: str = 'credential') -> str:
    """Return the one token in ``rows`` matching ``identity`` or ``role``, refusing zero or many.

    Args:
        rows: A list as returned by :func:`role_credentials`.
        identity: Exact ``identity`` field to select, or ``None`` to select by ``role``.
        role: Exact ``role`` field to select, or ``None`` to select by ``identity``.
        label: What to call the selection in the refusal message, so a caller's error names itself.

    Returns:
        The selected row's token.

    Raises:
        ValueError: Neither selector was given, both matched no row, or both matched more than one.
    """
    require(identity is not None or role is not None, 'token_for() needs an identity or a role to select by')
    matches = [row for row in rows if (identity is None or row.get('identity') == identity)
               and (role is None or row.get('role') == role)]
    require(len(matches) == 1,
            'Exactly one ' + label + ' is expected for ' + str(identity or role) + ', found ' + str(len(matches)))
    return matches[0]['token']

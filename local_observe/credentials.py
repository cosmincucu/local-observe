"""Read a role credential from a mounted file, falling back to an environment value.

An environment value is visible to `docker inspect`, to `/proc/<pid>/environ` of every process in
the container and to any child that process spawns, so a credential must arrive as a file whose
path is what sits in the environment. The environment value stays supported as a fallback: the
shipped manifests and the staging scripts all write files now, but an operator bringing up one
container by hand, or a third-party tool that can only export a value, must not be locked out by
this module.

Nothing here ever returns, logs, prints or embeds a credential: the file contents leave this
module only as the function's return value, and every diagnostic names the *variable*.
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path

from local_observe.log import get_logger

log = get_logger(__name__)

MAX_CREDENTIAL_BYTES = 4096
FILE_SUFFIX = '_FILE'
# Every ASCII control character, C0 (NUL..US) plus DEL. A credential is one opaque bearer token on
# one line: `http.JsonClient` already refuses `\r` and `\n` in a token, so anything else here is a
# damaged or wrongly-authored file, and refusing it at the read is the whole point.
CONTROL_CHARACTER = re.compile(r'[\x00-\x1f\x7f]')


def read_credential(name: str, *, environ: Mapping[str, str] = os.environ) -> str:
    """Return the credential named *name*, preferring `<name>_FILE` over `<name>`.

    Resolution order: the file whose path is `<name>_FILE`, then the environment value `<name>`,
    then a `KeyError` naming both forms. When both are set the file wins and one `WARNING` is
    logged naming the variable (never the value), because an operator who set both is one deleted
    environment line away from a different credential than the one under review.

    A path is refused -- `ValueError`, no contents echoed -- when it names a directory, an empty
    file or a file larger than `MAX_CREDENTIAL_BYTES`, since each of those is a mistake rather
    than a credential. A missing file raises `OSError` from the read. A single trailing newline is
    stripped, because `echo` writes one and every consumer compares the value byte for byte.

    A value that still holds an ASCII control character after that strip is refused, whichever
    form it arrived in: a CRLF-authored file (which leaves `\\r`), a double newline, an embedded
    `\\x00`. `http.JsonClient` refuses `\\r` and `\\n` in a token, so accepting such a value here
    only moves the failure to the first request, far from the file that caused it. The message
    names the variable and the code point, never the value.
    """
    file_variable = name + FILE_SUFFIX
    path = environ.get(file_variable)
    value = environ.get(name)
    if path and value:
        log.warning('Credential file takes precedence over the environment value',
                    extra={'variable': name, 'preferred': file_variable})
    if path:
        return _reject_control_characters(file_variable, _read_file(name, file_variable, path))
    if value:
        return _reject_control_characters(name, value)
    raise KeyError(f'Neither {file_variable} (a file holding the credential) nor {name} '
                   f'(the credential itself) is configured')


def _read_file(name: str, file_variable: str, path: str) -> str:
    """Read one bounded credential file; every message names the variable, never the contents."""
    candidate = Path(path)
    if candidate.is_dir():
        raise ValueError(f'{file_variable} names a directory, not a credential file')
    with candidate.open('rb') as stream:
        raw = stream.read(MAX_CREDENTIAL_BYTES + 1)
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise ValueError(f'{file_variable} exceeds {MAX_CREDENTIAL_BYTES} bytes')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        raise ValueError(f'{file_variable} is not UTF-8 text: {exc}') from exc
    if text.endswith('\n'):
        text = text[:-1]
    if not text.strip():
        raise ValueError(f'{file_variable} holds no credential')
    return text


def _reject_control_characters(name: str, value: str) -> str:
    """Return *value*, or raise `ValueError` naming *name* and the code point -- never the value."""
    found = CONTROL_CHARACTER.search(value)
    if found:
        raise ValueError(f'{name} contains ASCII control character U+{ord(found.group()):04X}; a '
                         f'credential must hold one opaque token with no line ending, so create '
                         f'the file with printf rather than echo')
    return value


__all__ = ['read_credential', 'MAX_CREDENTIAL_BYTES', 'FILE_SUFFIX', 'CONTROL_CHARACTER']

"""Bounded command execution with stderr redaction enabled by default.

Commands use argument lists rather than shell strings. Every call has a timeout.
Docker diagnostics may contain credentials, so shared reports must not include stderr.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import subprocess
from typing import Any

#: Default command timeout in seconds.
#: Callers are expected to pass the bound their own command needs; this is a ceiling, not a hint.
DEFAULT_TIMEOUT = 120

#: How much stderr ``redact_stderr=False`` may include. Enough for a compose error, not a log.
STDERR_TAIL = 3000


def run(*args: Any, timeout: float = DEFAULT_TIMEOUT, redact_stderr: bool = True,
        scrub: Sequence[str] = (), env: Mapping[str, str] | None = None,
        data: str | None = None) -> str:
    """Run a command and return its stdout, stripped.

    Accepts either an argument list (``run(['docker', 'info'])``) or the parts of one
    (``run('docker', 'info')``); a non-string element is refused rather than stringified, because a
    stray ``Path`` in argv is a bug the caller should see.

    Args:
        *args: The command and its arguments. No shell is involved, so no quoting is implied.
        timeout: Seconds before the child is killed; the call never waits indefinitely.
        redact_stderr: On a non-zero exit, name only the program in the raised message. Keep the
            default for anything whose traceback may be recorded; ``False`` appends a tail of
            stderr for interactive debugging only.
        scrub: Strings (secrets from the environment, typically) removed from that tail.
        env: Replacement environment; ``None`` inherits this process's, which is what the guard in
            :mod:`_lib.guards` arranges.
        data: Text written to the child's stdin.

    Returns:
        The child's stdout with leading and trailing whitespace removed.

    Raises:
        ValueError: The command is empty or holds a non-string element.
        RuntimeError: The command exited non-zero; the message names the program, never its output.
        subprocess.TimeoutExpired: The command outlived ``timeout``.
    """
    argv: tuple[Any, ...] = args[0] if len(args) == 1 and isinstance(args[0], (list, tuple)) else args
    if not argv or not argv[0] or any(not isinstance(part, str) for part in argv):
        raise ValueError('run() needs a non-empty list of strings with a named program, got: ' + repr(argv)[:200])
    result = subprocess.run(list(argv), input=data, capture_output=True, text=True,
                            timeout=timeout, env=env)
    if result.returncode:
        if redact_stderr:
            raise RuntimeError('Command failed: ' + argv[0] + ' (exit ' + str(result.returncode)
                               + '; private stderr suppressed)')
        detail = (result.stderr or '')[-STDERR_TAIL:]
        for secret in scrub:
            if secret:
                detail = detail.replace(secret, '[REDACTED]')
        raise RuntimeError('Command failed: ' + argv[0] + ' (exit ' + str(result.returncode) + ')\n' + detail)
    return result.stdout.strip()

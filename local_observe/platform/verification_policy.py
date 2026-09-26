"""Load the one reviewed verification policy an operator names .

``LO_VERIFICATION_POLICY`` names a service file holding the document ``VerificationPolicy`` already
validates. This module turns that path plus the mounted role credentials into the same immutable
object ``Store`` accepts, and nothing else: no runtime wiring, no cache, no hot reload, no retry, no
default policy, no YAML, no network, no database, and no log line that could carry a path or a policy.
An absent variable is the off switch — ``None``, with no file opened and no credential read — while a
named-but-unusable file, a document that is not bounded JSON data, or a verifier the credentials do not
mount as a producer is a ``PolicyLoadError`` whose sentence names no input. Token *values* are never
read, so this loader authorises nobody: ``api.create_app`` keeps that job. Rules and limits are in
``docs/units/verification-policy.md``.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
from typing import Any

from .state import label
from .verification_records import MAX_POLICY_BYTES, VerificationPolicy

#: The variable naming the policy file. ``LO_VERIFY_CONFIG`` is unrelated (the evidence-only worker).
CONFIG_ENVIRONMENT = 'LO_VERIFICATION_POLICY'
#: ``api.create_app``'s credential-role vocabulary, as the closed set a *row* may name. The app stays
#: the authority that turns a token into an ``Actor``; this loader reads row shape only.
ROLES = frozenset({'reader', 'producer', 'proposer', 'human', 'executor', 'summary'})
CREDENTIAL_ROW_KEYS = frozenset({'identity', 'role', 'token'})
PRODUCER = 'producer'
CREDENTIAL_LIMIT = 256

BAD_PATH = 'Verification policy path is not a readable regular file'
BAD_ENVIRONMENT = 'Verification policy environment is not readable'
BAD_SIZE = f'Verification policy exceeds {MAX_POLICY_BYTES} bytes'
BAD_DOCUMENT = 'Verification policy is not bounded JSON data'
BAD_CREDENTIALS = 'Verification policy verifier list does not match the mounted credentials'


class PolicyLoadError(ValueError):
    """The configured verification policy is unusable; the sentence names no path, value or input."""


class _Rejected(Exception):
    """Internal signal for a rule ``json`` does not refuse by itself (a duplicate key, NaN/Infinity)."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Return one object's dict, refusing a key stated twice at this or any shallower level."""
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise _Rejected()
    return dict(pairs)


def _constant(_name: str) -> Any:
    """Refuse ``NaN``/``Infinity`` instead of letting them arrive as non-finite floats."""
    raise _Rejected()


def _decode(text: str) -> Any:
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (_Rejected, ValueError, RecursionError):
        raise PolicyLoadError(BAD_DOCUMENT) from None


def _path(value: Any) -> str:
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, bool) or not isinstance(value, str) or not value.strip():
        raise PolicyLoadError(BAD_PATH)
    return value


def _read(candidate: str) -> bytes:
    """Read one regular file once, in binary, bounded by ``MAX_POLICY_BYTES + 1`` bytes.

    ``O_NONBLOCK`` (where the platform has it) is what stops a FIFO from hanging the call before the
    ``fstat`` on that descriptor can say whether it is a regular file at all. The bound counts stored
    bytes, so whitespace and comments are spent against it.
    """
    flags = (os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0)
             | getattr(os, 'O_BINARY', 0))
    try:
        descriptor = os.open(candidate, flags)
    except (OSError, ValueError):
        raise PolicyLoadError(BAD_PATH) from None
    collected = bytearray()
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PolicyLoadError(BAD_PATH)
        while len(collected) <= MAX_POLICY_BYTES:
            chunk = os.read(descriptor, min(16_384, MAX_POLICY_BYTES + 1 - len(collected)))
            if not chunk:
                break
            collected += chunk
    except OSError:
        raise PolicyLoadError(BAD_PATH) from None
    finally:
        os.close(descriptor)
    if len(collected) > MAX_POLICY_BYTES:
        raise PolicyLoadError(BAD_SIZE)
    return bytes(collected)


def _text(raw: bytes) -> str:
    try:
        decoded = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise PolicyLoadError(BAD_DOCUMENT) from None
    if decoded.startswith('\ufeff'):  # a byte-order mark is not this document's text
        raise PolicyLoadError(BAD_DOCUMENT)
    return decoded


def _identity(value: Any) -> str:
    try:
        return label(value)
    except ValueError:
        raise PolicyLoadError(BAD_CREDENTIALS) from None


def _crosscheck(verifiers: tuple[str, ...], credentials: Any) -> None:
    """Require every verifier to be mounted as a producer and as nothing else; tokens are never read.

    Key *presence* is what is checked (``set(row)``), never ``row['token']``: which token is strong
    enough, and whether one is replayable, is ``api.create_app``'s judgement. Several producer rows for
    one verifier identity are permitted (a rotated pair), and valid rows for other roles are nobody's
    business here — unless they name a verifier, which is an identity two components may speak as.
    """
    if not isinstance(credentials, (list, tuple)) or not 1 <= len(credentials) <= CREDENTIAL_LIMIT:
        raise PolicyLoadError(BAD_CREDENTIALS)
    producers: set[str] = set()
    other_roles: set[str] = set()
    for row in credentials:
        if type(row) is not dict or set(row) != CREDENTIAL_ROW_KEYS:
            raise PolicyLoadError(BAD_CREDENTIALS)
        role = row['role']
        if not isinstance(role, str) or role not in ROLES:
            raise PolicyLoadError(BAD_CREDENTIALS)
        (producers if role == PRODUCER else other_roles).add(_identity(row['identity']))
    if any(name not in producers or name in other_roles for name in verifiers):
        raise PolicyLoadError(BAD_CREDENTIALS)


def load_policy(path: Any, credentials: Any) -> VerificationPolicy:
    """Read *path* once and return the policy it declares, crosschecked against *credentials*.

    Refusal is the only answer to anything unusable: :class:`PolicyLoadError`, one fixed sentence naming
    no path, no value and no parsed content, chaining no fault underneath. Parsing comes first, so a bad
    document is never reported as a credential problem.
    """
    try:
        policy = VerificationPolicy(_decode(_text(_read(_path(path)))))
    except PolicyLoadError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
        raise PolicyLoadError(BAD_DOCUMENT) from None
    _crosscheck(policy.verifiers, credentials)
    return policy


def policy_from_environment(credentials: Any, *, environ: Mapping[str, Any] | None = None
                            ) -> VerificationPolicy | None:
    """Return the policy ``LO_VERIFICATION_POLICY`` names, or ``None`` when that key is absent.

    The environment is read at call time (nothing is captured at import, so a test or a reload sets it
    and gets that value), and an absent key opens no file and reads no credential at all. A key that is
    present but blank, whitespace-only or not a string is a refusal: an operator who meant to mount a
    policy must never be answered with the off switch.
    """
    environment = os.environ if environ is None else environ
    if not isinstance(environment, Mapping):
        raise PolicyLoadError(BAD_ENVIRONMENT)
    if CONFIG_ENVIRONMENT not in environment:
        return None
    if not isinstance(environment[CONFIG_ENVIRONMENT], str):
        raise PolicyLoadError(BAD_PATH)
    return load_policy(environment[CONFIG_ENVIRONMENT], credentials)


__all__ = ['CONFIG_ENVIRONMENT', 'PolicyLoadError', 'load_policy', 'policy_from_environment']

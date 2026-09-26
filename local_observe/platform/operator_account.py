"""Password verifier behind the operator shell: one account document, PBKDF2, no session state.

The platform authenticates every API call with a mounted role bearer (``api.role_credentials``);
nothing here changes that. This module exists for one convenience the bearer-only shell could not
offer a installation operator: typing a username and a password into the UI instead of pasting a token.
The operator wrapper (``operator.py``) checks the supplied password against the single account
document named by ``LO_OPERATOR_ACCOUNT_FILE`` and, on success, forwards the request to the API with
the *already configured* human-role bearer. A password therefore never reaches ``Store``, and a
bearer never leaves the process that read it.

Design facts a reviewer should be able to check in one read:

* One account, one role. The document names one username and the platform identity it stands for;
  that identity must be the identity of exactly one ``human`` row in the mounted role list, so a
  password can only ever become the actor the deployment already authorised.
* ``argon2``/``bcrypt`` are not options here (Python 3.12, stdlib + PyYAML + jsonschema only), and
  ``hashlib.scrypt`` needs a salt policy of its own. ``hashlib.pbkdf2_hmac('sha256', ...)`` at
  600000 iterations is the stdlib primitive that ships with a constant-time comparison already used
  everywhere else in this package, so the whole trust surface is one hash and one comparison.
* The expensive part is deliberate: at 600000 iterations a wrong password costs the same as a right
  one, and the wrapper refuses excess attempts rather than queueing them (``operator.py``).
* Nothing here caches. Every request carrying ``Authorization: Basic`` is verified again. An
  operator's refresh issues a handful of requests; the bound on concurrent work is what makes that
  affordable, and a cache would be a second copy of a credential in memory.

No function logs credentials. Account creation returns the hash and salt for protected file storage;
human_bearer returns a credential only for internal forwarding. Refusals use fixed messages.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

#: The environment variable naming the *file* the operator account is mounted at. Like the role list
#: (``api.CREDENTIALS_PATH_ENVIRONMENT``), the secret material is a mounted file, never an
#: environment value: ``docker inspect`` and ``/proc/<pid>/environ`` expose the latter.
ACCOUNT_PATH_ENVIRONMENT = 'LO_OPERATOR_ACCOUNT_FILE'

#: The one document shape this reader accepts, and the only hash parameters it may name.
SCHEMA = 1
ALGORITHM = 'pbkdf2-sha256'
PBKDF2_ITERATIONS = 600000
SALT_BYTES = 16
HASH_BYTES = 32
ACCOUNT_KEYS = frozenset({'schema', 'username', 'identity', 'algorithm', 'iterations', 'salt',
                          'password_hash'})

#: Read ceilings, all of them refusals rather than truncations. The document is a few hundred bytes;
#: 8192 bounds the reader without bounding an attacker's memory. ``MAX_BASIC_DECODED_BYTES`` bounds
#: the decoded ``user:password`` pair, and the encoded ceiling is exactly what 2048 bytes base64 to
#: (``4 * ceil(2048 / 3)``), so an oversized header is refused before it is decoded.
MAX_FILE_BYTES = 8192
MAX_BASIC_DECODED_BYTES = 2048
MAX_BASIC_ENCODED_BYTES = 4 * ((MAX_BASIC_DECODED_BYTES + 2) // 3)

#: Password and username bounds. The password is bounded in *bytes* because that is what the KDF
#: costs; 1024 is far above any installation password and far below anything that would slow an honest
#: login. No composition requirement: a rule demanding a digit and a symbol produces a sticky note.
MAX_PASSWORD_BYTES = 1024
MAX_IDENTITY_CHARS = 128

#: ``[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`` — so 1..64 characters, never starting with a separator, and
#: ``\Z`` so no trailing newline rides along (``$`` would accept one).
USERNAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z')

#: Bytes no header value or password may contain, whatever the transport did to get them here. A CR
#: or LF in a credential is a split-header attempt; NUL is a truncation attempt.
FORBIDDEN_BYTES = frozenset({0x0d, 0x0a, 0x00})

HEX_LOWER = frozenset('0123456789abcdef')

# Fixed refusal sentences. Each is a whole message: none of them is formatted with caller-supplied
# text, a hash, a salt or a path value, so one can be returned or logged anywhere.
BAD_USERNAME = 'Invalid operator account username'
BAD_PASSWORD = 'Invalid operator account password'
BAD_IDENTITY = 'Invalid operator account identity'
MALFORMED_ACCOUNT = 'Malformed operator account document'
NO_HUMAN_CREDENTIAL = 'No human platform credential for operator login'
AMBIGUOUS_HUMAN_CREDENTIAL = 'More than one human platform credential for operator login'
IDENTITY_MISMATCH = 'Operator account identity differs from the human credential'


def _text(value: Any) -> str:
    """Return ``value`` as text if it is text, and refuse every other type the same way.

    The account document arrives from ``json.loads``, so a number or a list where a string belongs is
    a malformed file, not a type error to leak.
    """
    if not isinstance(value, str):
        raise ValueError(MALFORMED_ACCOUNT)
    return value


def _clean_text(value: Any, maximum: int, refusal: str) -> str:
    """Return ``value`` if it is bounded text with no CR, LF or NUL, refusing with ``refusal``.

    A field that is not a string at all (a JSON number, a list) is refused with the sentence naming
    the field the caller mislabeled, never with a type error: a setup worker reads one line and fixes
    the right key.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(refusal)
    try:
        raw = value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError(refusal) from None
    if FORBIDDEN_BYTES & set(raw):
        raise ValueError(refusal)
    return value


def _hex_bytes(value: Any, size: int) -> bytes:
    """Return the ``size`` bytes ``value`` names as lowercase hex, refusing anything else."""
    text = _text(value)
    if len(text) != size * 2 or not HEX_LOWER.issuperset(text):
        raise ValueError(MALFORMED_ACCOUNT)
    return bytes.fromhex(text)


def _password_bytes(password: Any) -> bytes | None:
    """Return the UTF-8 bytes of an admissible password, or ``None`` when it is not one.

    Total by design: it is the function the verification path calls with bytes a caller controlled,
    and a refusal there must be a failed login, never an exception that travels towards a response.
    """
    if not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_BYTES * 4:
        return None
    try:
        raw = password.encode('utf-8')
    except UnicodeEncodeError:
        return None
    if not 1 <= len(raw) <= MAX_PASSWORD_BYTES or FORBIDDEN_BYTES & set(raw):
        return None
    return raw


def _derive(salt: bytes, password: str, iterations: int) -> bytes:
    """Run the one key derivation this module knows, from inputs the caller already bounded."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)


def make_account(username: Any, password: Any, identity: Any = 'operator') -> dict[str, Any]:
    """Return a fresh operator account document for ``username`` and ``password``.

    The document is the whole file content: write it as JSON (``json.dumps(account, indent=2)``),
    mount it, and name its path in ``LO_OPERATOR_ACCOUNT_FILE``. The salt is 16 fresh random bytes,
    so two accounts with the same password share nothing, and the hash is never the password: the
    returned mapping is safe to hand to a setup worker's file write and nothing in it can be
    recovered to a password except by paying the iteration count.

    Args:
        username: Login name, ``[A-Za-z0-9][A-Za-z0-9_.-]{0,63}``.
        password: Between 1 and 1024 UTF-8 bytes, without CR, LF or NUL. No composition rule.
        identity: The platform Actor identity this login stands for; the deployment's human role.

    Returns:
        ``{schema, username, identity, algorithm, iterations, salt, password_hash}`` with ``salt`` and
        ``password_hash`` lowercase hex (32 and 64 characters).

    Raises:
        ValueError: A field is out of its bounds. The message names the field, never the value.
    """
    user = _clean_text(username, 64, BAD_USERNAME)
    if not USERNAME_PATTERN.match(user):
        raise ValueError(BAD_USERNAME)
    if _password_bytes(password) is None:
        raise ValueError(BAD_PASSWORD)
    actor = _clean_text(identity, MAX_IDENTITY_CHARS, BAD_IDENTITY)
    salt = os.urandom(SALT_BYTES)
    return {'schema': SCHEMA, 'username': user, 'identity': actor, 'algorithm': ALGORITHM,
            'iterations': PBKDF2_ITERATIONS, 'salt': salt.hex(),
            'password_hash': _derive(salt, password, PBKDF2_ITERATIONS).hex()}


def verify_password(account: Mapping[str, Any], username: Any, password: Any) -> bool:
    """Return whether ``username``/``password`` are the account's, and never raise on caller bytes.

    Both branches cost a derivation: the username is compared with ``secrets.compare_digest`` *after*
    the hash is computed, so a wrong username and a wrong password take the same time and answer the
    same way. Unknown or wrong-shaped input is ``False``, not an exception — the wrapper's only
    refusal vocabulary for a credential is 401, and an exception here would be a 500 that names
    nothing useful while telling the caller the server choked on their bytes.

    Args:
        account: A document from :func:`load_account` (already schema-checked).
        username: The login name a caller offered.
        password: The password a caller offered.

    Returns:
        ``True`` only when both the name and the password match the document.
    """
    try:
        salt = _hex_bytes(account['salt'], SALT_BYTES)
        expected = _hex_bytes(account['password_hash'], HASH_BYTES)
        name, secret = _text(username), password
        iterations = account.get('iterations', PBKDF2_ITERATIONS)
        if type(iterations) is not int or iterations != PBKDF2_ITERATIONS:
            return False
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    if _password_bytes(secret) is None:
        return False
    derived = _derive(salt, secret, iterations)
    name_matches = secrets.compare_digest(name.encode('utf-8', 'surrogatepass'),
                                          _text(account['username']).encode('utf-8'))
    hash_matches = secrets.compare_digest(derived, expected)
    return bool(name_matches and hash_matches)


def load_account(path: Path | str) -> dict[str, Any]:
    """Return the verified account document mounted at ``path``.

    Strict, and a malformed document is a startup refusal rather than a fallback: a deployment that
    boots with an unreadable password setting would otherwise be a deployment whose operator cannot
    tell whether password login works. Only the fixed sentences below name the fault, so the message
    can never carry the hash it was unhappy about.

    Args:
        path: The mounted file. Read once, at startup; never re-read per request.

    Returns:
        The document as a dict, with the caller's own key order and types validated.

    Raises:
        ValueError: Missing, unreadable, too big, not JSON, or outside the accepted schema.
    """
    try:
        # O_NONBLOCK prevents a mounted FIFO from hanging startup before fstat.
        descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0)
                             | getattr(os, 'O_BINARY', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError(MALFORMED_ACCOUNT)
            raw = stream.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise ValueError(MALFORMED_ACCOUNT) from None
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(MALFORMED_ACCOUNT)
    try:
        def unique_object(pairs):
            document = {}
            for key, value in pairs:
                if key in document:
                    raise ValueError(MALFORMED_ACCOUNT)
                document[key] = value
            return document
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        # ``exc`` carries a slice of the document, which carries the hash: the refusal is fixed.
        del exc
        raise ValueError(MALFORMED_ACCOUNT) from None
    if not isinstance(document, dict) or set(document) != ACCOUNT_KEYS:
        raise ValueError(MALFORMED_ACCOUNT)
    if type(document['schema']) is not int or document['schema'] != SCHEMA or document['algorithm'] != ALGORITHM:
        raise ValueError(MALFORMED_ACCOUNT)
    # Exactly the count `make_account` wrote. A file naming a cheaper one was not written by this
    # tool, and honouring it silently would make a weakened iteration count a file edit.
    if type(document['iterations']) is not int or document['iterations'] != PBKDF2_ITERATIONS:
        raise ValueError(MALFORMED_ACCOUNT)
    user = _clean_text(document['username'], 64, MALFORMED_ACCOUNT)
    if not USERNAME_PATTERN.match(user):
        raise ValueError(MALFORMED_ACCOUNT)
    _clean_text(document['identity'], MAX_IDENTITY_CHARS, MALFORMED_ACCOUNT)
    salt = _hex_bytes(document['salt'], SALT_BYTES)
    digest = _hex_bytes(document['password_hash'], HASH_BYTES)
    return {**document, 'username': user, 'salt': salt.hex(), 'password_hash': digest.hex()}


def account_from_environment(environ: Mapping[str, str] = os.environ) -> dict[str, Any] | None:
    """Return the mounted account document, or ``None`` when password login is not configured.

    Unset is the documented off switch and the legacy bearer UI's opt-out: the wrapper then reports
    ``mode: 'token'`` and behaves exactly as it did before this module existed. A *set* value naming
    an unreadable or malformed file is the refusal in :func:`load_account`, never a silent ``None`` —
    the difference between off and broken has to be visible at boot.

    Args:
        environ: The environment to read; defaults to this process's.

    Returns:
        The document, or ``None``.

    Raises:
        ValueError: A set value is blank, or the named file is malformed.
        ValueError: The named file is not readable.
    """
    declared = environ.get(ACCOUNT_PATH_ENVIRONMENT)
    if declared is None:
        return None
    if not declared.strip():
        raise ValueError(f'{ACCOUNT_PATH_ENVIRONMENT} is set but blank; unset it or name the file')
    return load_account(declared)


def parse_basic(value: Any) -> tuple[str, str] | None:
    """Return the ``(username, password)`` an ``Authorization: Basic`` value carries, else ``None``.

    Strict on purpose, because the alternative is guessing what a malformed credential meant:
    standard padded base64 only (``validate=True``, so embedded whitespace, newlines and a stray
    ``=`` are refusals), at most ``MAX_BASIC_DECODED_BYTES`` after decoding, mandatory UTF-8, and one
    ``:`` separator — ``partition`` splits once, so a password may contain ``:`` while a username may
    not. Every refusal is ``None``, which the wrapper answers with the same 401 it gives a wrong
    password: a caller cannot tell a transport mistake from a bad credential, and neither can a log.

    Args:
        value: The whole header value as the transport decoded it.

    Returns:
        The offered name and password, or ``None`` for anything that is not a well-formed pair.
    """
    if not isinstance(value, str) or not 7 <= len(value) <= 7 + MAX_BASIC_ENCODED_BYTES:
        return None
    if value[:6].lower() != 'basic ':
        return None
    try:
        encoded = value[6:].encode('ascii')
    except UnicodeEncodeError:
        # A non-ASCII byte anywhere in the token is not base64; the header was decoded latin-1 by the
        # transport, so the refusal is the same 401 a wrong password earns.
        return None
    if len(encoded) > MAX_BASIC_ENCODED_BYTES:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(decoded) > MAX_BASIC_DECODED_BYTES:
        return None
    try:
        text = decoded.decode('utf-8')
    except UnicodeDecodeError:
        return None
    user, separator, password = text.partition(':')
    if not separator or not user or not password:
        return None
    if FORBIDDEN_BYTES & set(decoded):
        return None
    if not USERNAME_PATTERN.match(user) or _password_bytes(password) is None:
        return None
    return user, password


def human_bearer(credentials: Sequence[Mapping[str, str]], account: Mapping[str, Any]) -> str:
    """Return the bearer the password stands for: the one human row the account's identity names.

    The substitution is the whole design, and this is the function that makes it safe. The password
    buys exactly the actor named by the mounted account document with ``role: 'human'`` — never
    an identity chosen by the browser or a union of credentials. Other human identities remain
    usable by their existing clients. Duplicate matching identities are a boot refusal: token
    selection must not depend on row order.

    Args:
        credentials: The mounted ``{identity, role, token}`` rows (``api.role_credentials()``).
        account: The document from :func:`load_account`.

    Returns:
        The human row's token. Callers pass it to the wrapper once, at build time; it is never
        returned over HTTP and never appears in a message raised here.

    Raises:
        ValueError: No human row, no matching identity, or duplicate matching identities.
    """
    rows = [item for item in credentials if item.get('role') == 'human']
    if not rows:
        raise ValueError(NO_HUMAN_CREDENTIAL)
    rows = [item for item in rows if item.get('identity') == account.get('identity')]
    if not rows:
        raise ValueError(IDENTITY_MISMATCH)
    if len(rows) > 1:
        raise ValueError(AMBIGUOUS_HUMAN_CREDENTIAL)
    return rows[0]['token']

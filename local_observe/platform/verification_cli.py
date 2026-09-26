"""The `verification` command group: HTTPS-only reads and one submit .

Nothing here judges anything. This group is a bounded *client* of the platform's own HTTPS surface: it
validates what the operator typed, reads one credential and one statement from files the operator
named, makes **exactly one** request through `local_observe.http.JsonClient`, and prints what the server
answered. The server stays the authority for role, policy, execution, binding, state and replay
decisions (`verification_records.py` judges; this module only asks). It opens no database and consults no
notification mode, policy document or local clock, and it sends the credential to one HTTPS endpoint only.

What is deliberately absent, and why: no raw-token argument or environment fallback (a secret in `argv`
is a secret in `ps` and in shell history), no `allow-http`/insecure escape hatch, no stdin statement, no
output file, no retry, no `--database`. Each would be a second way for one credential to leak or for one
submission to happen twice. `--timeout` and `--ca-file` are the only `JsonClient` options reachable here,
and both are its own bounds to enforce, not this module's to reimplement.

Because an unsuccessful `submit` may still have been accepted remotely, this module never retries and
never claims a rollback: the operator inspects the stored ids/records and resubmits the unchanged
statement as a second, explicit invocation. Pending-state durability and automatic exact replay stay
future work in #123.

Two fixed objects are the whole failure surface on stdout — `{"status": "error", "error_type":
"VerificationHTTPError", "http_status": N}` for any non-200 answer, and `{"status": "error",
"error_type": "VerificationCLIError"}` for every local refusal (bad input, bad config, transport
failure, unusable output). Neither carries a traceback, an exception cause, a token, a local path, a
request or a response document. `JsonClient` discards HTTP error bodies on purpose, which is also why
this client cannot tell `verification_busy` from `verification_unavailable` when both are 503, and does
not pretend to. Failures are not logged from here either: the transport already logs its own bounded
diagnosis, and a second copy would be a second thing that could leak.
"""
from __future__ import annotations

import argparse
from collections.abc import Callable
from http.client import HTTPException
import json
import math
import os
from pathlib import Path
import stat
from typing import Any

from local_observe.http import JsonClient, TransportError
from . import verification_records
from .state import StateError, identifier

__all__ = ('add_parser', 'run')

#: The credential bound, read as bytes and re-checked as text: one byte over the cap is a refusal, so
#: the read itself is capped at `TOKEN_BYTES + 1` and never streams the rest of a file.
TOKEN_BYTES = 4_096
#: Same lower bound `JsonClient` puts on a token, so this module never hands over a credential the
#: transport would refuse anyway — and never reports that refusal as somebody else's error.
TOKEN_BOUNDS = (24, 4_096)
#: Printable ASCII with no space at all: a token carrying a space or a control byte is a corrupted
#: file, not a token with a stylistic choice, and surrounding whitespace is already gone.
PRINTABLE = (0x21, 0x7E)
#: `JsonClient`'s own default and its own 1..20 s bound. Named here only as this group's default; the
#: transport is what refuses a value outside the range, before it opens anything.
DEFAULT_TIMEOUT = 10
CLI_ERROR = 'VerificationCLIError'
HTTP_ERROR = 'VerificationHTTPError'
BINDING_PATH = '/v1/verification/binding'
RECORDS_PATH = '/v1/verification/records'
RECORD_PATH = '/v1/verification/record'


class _Refused(Exception):
    """One local refusal. It carries no message on purpose: the operator's whole answer is fixed.

    Every sentence this can stand in for would name a field, a bound or a path, and printing one would
    turn a bounded error object into a place where caller content can ride out. The message-free
    exception is the cheapest way to keep the two failure surfaces (this object on stdout, the
    transport's own bounded log line) from merging.
    """


def _canonical_uuid(value: Any) -> str:
    """Return canonical 36-character UUID text, refusing every other spelling instead of normalising it.

    `state.identifier` compares the normalised form with its input, which is what makes `urn:uuid:`,
    braces, uppercase hex and a bare 32-hex digest refusals rather than second spellings of one id.
    Accepting a second spelling here would let one execution id reach the server as two different reads.
    """
    if not isinstance(value, str) or len(value) != 36:
        raise _Refused
    try:
        return identifier(value)
    except StateError:
        raise _Refused from None


def _hex64(value: Any) -> str:
    """Return one lowercase SHA-256 digest, with the storage layer's own strictness and its own sentence."""
    try:
        return verification_records._sha256(value, verification_records.BAD_VERIFICATION_ID)
    except StateError:
        raise _Refused from None


#: operation -> `(method, path, query parameter, identity validator)`. Each identity flag's `dest` *is*
#: its query parameter name, so no mapping between the two can drift. A `None` validator means the POST
#: whose document comes from `--statement`.
OPERATIONS: dict[str, tuple[str, str, str | None, Callable[[Any], str] | None]] = {
    'binding': ('GET', BINDING_PATH, 'action_id', _canonical_uuid),
    'records': ('GET', RECORDS_PATH, 'execution_id', _canonical_uuid),
    'record': ('GET', RECORD_PATH, 'verification_id', _hex64),
    'submit': ('POST', RECORDS_PATH, None, None),
}


def _read_limited(path: Any, limit: int) -> bytes:
    """Return the first *limit + 1* bytes of one regular file, refusing every other kind without reading.

    On POSIX, `O_NONBLOCK` prevents waiting for a FIFO writer. This is not a deadline on file opens;
    `fstat` on the descriptor decides "regular file" about the thing actually opened rather than about a
    path somebody else may have swapped. A symlink is followed, because the operator named this path: no
    permission or symlink policy is invented here, and none is claimed. The extra byte is read so that
    "one over the cap" is distinguishable from "at the cap" without streaming a large file.
    """
    # Windows text mode rewrites CRLF and treats Ctrl-Z as EOF; limits apply to raw bytes.
    flags = (os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0)
             | getattr(os, 'O_BINARY', 0))
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _Refused from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _Refused
        collected = bytearray()
        while len(collected) <= limit:
            block = os.read(descriptor, limit + 1 - len(collected))
            if not block:
                break
            collected += block
    except OSError:
        raise _Refused from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    if not 1 <= len(collected) <= limit:
        raise _Refused
    return bytes(collected)


def _text(raw: bytes) -> str:
    """Decode strict UTF-8: a replacement character would silently change what was submitted."""
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        raise _Refused from None


def _token(path: Any) -> str:
    """Return the one credential, from a bounded regular file the operator named, and from no other source.

    Outer whitespace is stripped (a trailing newline is how a `printf` writes a secret file), then the
    content must be entirely printable ASCII. The value is returned, never echoed: nothing in this
    module prints, logs or interpolates it.
    """
    text = _text(_read_limited(path, TOKEN_BYTES)).strip()
    if not TOKEN_BOUNDS[0] <= len(text) <= TOKEN_BOUNDS[1]:
        raise _Refused
    if any(not PRINTABLE[0] <= ord(character) <= PRINTABLE[1] for character in text):
        raise _Refused
    return text


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object, refusing a repeated key at whatever nesting level it appeared.

    `json.loads` keeps the last of two duplicate keys, so a statement that says `"outcome"` twice would
    reach the server as one clean-looking document whose first claim had been dropped. The storage layer
    cannot catch this afterwards (the pair is gone by then), which is why the parser is told to refuse.
    """
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise _Refused
        document[key] = value
    return document


def _float(text: str) -> float:
    """Refuse a float the JSON cannot mean: `1e999` parses to `inf` unless somebody says otherwise."""
    value = float(text)
    if not math.isfinite(value):
        raise _Refused
    return value


def _integer(text: str) -> int:
    """Refuse an integer wider than the platform's signed-64 bound (`verification_records.INTEGER_LIMIT`)."""
    value = int(text)
    if abs(value) > verification_records.INTEGER_LIMIT:
        raise _Refused
    return value


def _constant(text: str) -> Any:
    """Refuse `NaN`, `Infinity` and `-Infinity`: JSON data has no such value, whatever Python calls one."""
    raise _Refused


def _document(text: str) -> Any:
    """Parse the strict JSON subset a submitted statement may be written in."""
    try:
        return json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                          parse_float=_float, parse_int=_integer)
    except (ValueError, OverflowError, RecursionError):
        # `ValueError` is `JSONDecodeError`; `RecursionError` is a document nested deeper than either
        # this parser or `verification_records._plain` admits. Neither is a bug, and both are the same
        # fixed answer as any other unusable statement.
        raise _Refused from None


def _statement(path: Any) -> dict[str, Any]:
    """Return a submitted statement that the storage layer itself would accept, or refuse it whole.

    The byte bound is `verification_records.MAX_RECORD_BYTES` on the file as read, so an oversized file
    is refused before it is decoded. Shape, finiteness, nesting depth, container width, node count and
    the canonical-byte bound are then checked by `verification_records._incoming` itself rather than by a
    paraphrase of it that could drift: a statement this refuses is one the server would refuse too.

    What is submitted is the document as parsed, *not* `_incoming`'s normalised copy — the caller's
    spelling travels, and the server normalises and judges, exactly as it does for any other producer.
    No local grading, policy loading or timestamp rewriting happens on the way.
    """
    document = _document(_text(_read_limited(path, verification_records.MAX_RECORD_BYTES)))
    if not isinstance(document, dict):
        raise _Refused
    try:
        verification_records._incoming(document)
    except (StateError, ValueError, TypeError, RecursionError):
        raise _Refused from None
    return document


def _request(args: argparse.Namespace) -> tuple[str, str, Any]:
    """Return `(method, path, payload)` for this invocation, refusing bad input before anything else.

    Identity arguments are validated here, ahead of the token read and the transport construction, so a
    typo spends no request. Nothing quotes, encodes or normalises them: the validators admit canonical
    UUID text and lowercase hex only, so a value that would need percent-escaping, or that carries `..`,
    a second `?`, a `#` or a fragment, is refused rather than smuggled into the path.
    """
    method, path, parameter, validate = OPERATIONS[args.operation]
    if validate is None:
        return method, path, _statement(args.statement)
    return method, f'{path}?{parameter}={validate(getattr(args, parameter))}', None


def _report(status: Any, document: Any) -> int:
    """Print one answer and return the exit status: the server's object verbatim, or a fixed refusal.

    A 200 whose body is not a JSON object, or which carries a number JSON cannot express, is a local
    error rather than a success: `JsonClient` decodes with permissive defaults, so `NaN` can arrive in a
    valid response and must not be printed as if it were an answer. Nothing is synthesised, renamed or
    added to a document that *is* printable — a stored record reads back exactly as it was stored.
    """
    if isinstance(status, bool) or not isinstance(status, int):
        raise _Refused
    if status != 200:
        print(json.dumps({'status': 'error', 'error_type': HTTP_ERROR, 'http_status': status}))
        return 1
    if not isinstance(document, dict):
        raise _Refused
    try:
        printed = json.dumps(document, indent=2, allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        raise _Refused from None
    print(printed)
    return 0


def add_parser(subparsers: Any) -> None:
    """Register the `verification` group on `cli.main()`'s subparsers.

    The group owns its own `--url`/`--token-file`: they are not global options, so `notify`'s channel
    arguments and these credentials stay two separate flags on two separate commands. Options must
    precede the operation word, which is what makes an option after it an argparse refusal (exit 2)
    rather than something this module has to notice.
    """
    group = subparsers.add_parser('verification', allow_abbrev=False,
                                 help='read verification state and submit one '
                                                       'observation over HTTPS only; opens no local '
                                                       'database and reads no local policy')
    group.add_argument('--url', required=True,
                       help='the platform\'s HTTPS base, which may carry its configured base path')
    group.add_argument('--token-file', type=Path, required=True,
                       help='regular file holding the verifier credential; the only source of it')
    group.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help=f'seconds to wait for the one request (1..20, default {DEFAULT_TIMEOUT})')
    group.add_argument('--ca-file', type=Path,
                       help='PEM authority for the endpoint, passed to the existing bounded transport')
    operations = group.add_subparsers(dest='operation', required=True)
    binding = operations.add_parser('binding', allow_abbrev=False,
                                    help='read the durable binding captured for one action')
    binding.add_argument('--action-id', required=True)
    records = operations.add_parser('records', allow_abbrev=False,
                                    help='list what one execution has been verified by')
    records.add_argument('--execution-id', required=True)
    record = operations.add_parser('record', allow_abbrev=False,
                                   help='read one stored verification record back')
    record.add_argument('--verification-id', required=True)
    submit = operations.add_parser('submit', allow_abbrev=False,
                                   help='submit one observation; makes at most one request')
    submit.add_argument('--statement', type=Path, required=True,
                        help='regular file holding the JSON statement; never read from stdin')


def run(args: argparse.Namespace) -> int:
    """Answer one `verification` invocation with one request, and return the process exit status.

    The order is the contract: validate the input, then open the credential, then build the transport,
    then make the single request. Nothing below is reached twice, so no outcome — including a timeout or
    a lost submit acknowledgement — can send a second request.

    Only the classes this slice expects are caught, and all of them answer with the same fixed object.
    A `KeyError`, `AttributeError` or `AssertionError` from inside here is a bug in this module and is
    left to raise; `KeyboardInterrupt` and `SystemExit` are never caught.
    """
    try:
        method, path, payload = _request(args)
        token = _token(args.token_file)
        try:
            client = JsonClient(args.url, token, timeout=args.timeout, ca_file=args.ca_file)
        except ValueError:
            # URL parsing / custom TLS configuration may refuse before the transport is built.
            raise _Refused from None
        status, document = client.request(method, path, payload)
        return _report(status, document)
    except (_Refused, TransportError, HTTPException, OSError):
        print(json.dumps({'status': 'error', 'error_type': CLI_ERROR}))
        return 1

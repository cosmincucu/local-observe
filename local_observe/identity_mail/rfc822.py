"""Bounded structural reader: raw RFC 822 bytes to header fields and byte-exact level payloads.

Nothing here decides whether a message is believed. It answers one question — *can these bytes be read
safely and completely, and what exactly are the byte ranges a receiver would have authenticated?* — and
refuses everything it cannot answer within a bound. `parser.py` applies the trust gate and the provider
lexicon; `trust.py` decides belief.

Why the walk is hand-rolled instead of `email.message.Message.walk()`: this feed's whole security
property is that a verdict is bound to **the exact bytes a trusted receiver authenticated**. The stdlib
re-serialises a nested `message/rfc822` payload (`get_payload(decode=True)` returns `None` for it, and
`as_bytes()` is a re-encode, measured 2026-09-22), so a digest taken through that path is a digest of
bytes nobody sent. Walking at byte level keeps every level's `raw` verbatim, and it makes the two
decisions this unit must own explicit rather than inherited: where a level begins and ends, and which
bytes a transfer encoding would have to be applied to (refused, never guessed — see
`transfer-encoded-nested`).

The stdlib parser still runs, as an *independent second opinion* on the header block only: this reader
counts header fields itself and refuses a disagreement (`header-structure-disagreement`), and any
defect the stdlib reports on the same block is a refusal (`malformed-headers`). A parser that is only
ever consulted for the answers it agrees with would not be a check.

Bounds, and what each one costs when it is hit — every refusal here is a counted `parse-failure`
outcome upstream, never a truncation, because a silently unread message is an alert that did not happen:

* `MAX_MESSAGE_BYTES` — 256 KiB per level. Provider security mail is a few KiB; the ceiling exists to
  bound allocation, not to describe real mail. Over it: nothing is parsed at all.
* `MAX_HEADER_BLOCK_BYTES` / `MAX_HEADER_FIELDS` / `MAX_HEADER_VALUE_CHARS` — a header block that will
  not fit or has absurd field counts is a hostile input, not a mail client.
* `MAX_PARTS` / `MAX_LEVELS` / `MAX_CHAINS` — nested multipart and forwarded `message/rfc822` are both
  legitimate, both attacker-constructible, and both bounded. Deeper than `MAX_LEVELS` is refused rather
  than followed.
"""
from dataclasses import dataclass
import email.header
from email.parser import BytesParser
from email.policy import compat32
import re

__all__ = ['StructuralRefusal', 'HeaderField', 'Node', 'Document', 'read_message',
           'MAX_MESSAGE_BYTES', 'MAX_HEADER_BLOCK_BYTES', 'MAX_HEADER_FIELDS', 'MAX_LEVELS',
           'MAX_PARTS', 'MAX_CHAINS', 'collect_text']

#: The largest single level this reader will look at. 256 KiB is two orders of magnitude above the
#: Google/Microsoft sign-in mail this feed parses, and it is what makes "oversized" a real category:
#: without a ceiling, one message's size decides the collector's memory use.
MAX_MESSAGE_BYTES = 262144

#: The header block ceiling. `MAX_MESSAGE_BYTES` already bounds the whole level; this bounds the part
#: that is parsed twice (here and by the stdlib) and that every identity field lives in.
MAX_HEADER_BLOCK_BYTES = 32768

#: Field-count and field-length ceilings. Real provider mail carries a dozen `Received:` lines; a
#: message with hundreds of fields is a parser-pressure attempt, and the field count is also what makes
#: `duplicated headers` decidable at all — a cap above which counting stops cannot report a duplicate.
MAX_HEADER_FIELDS = 256
MAX_HEADER_VALUE_CHARS = 2048
MAX_FIELD_NAME_CHARS = 64

#: Nesting ceilings. `MAX_LEVELS` counts messages (`message/rfc822` links): a forward of a forward is
#: the deepest thing a real mailbox produces. `MAX_PARTS` bounds one multipart tree and `MAX_CHAINS`
#: bounds the number of message paths the reader will enumerate, so a many-attachment message cannot
#: turn one fetch into a tree walk of unbounded width.
MAX_LEVELS = 3
MAX_PARTS = 32
MAX_CHAINS = 8

#: Body text actually read for classification, in characters, per message. Only reached for mail that
#: has already passed the trust gate (see `parser.py`'s ordering), so this bounds work, not belief.
MAX_TEXT_CHARS = 6144
MAX_TEXT_PARTS = 8

_TOKEN = re.compile(rb'^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$')
_BOUNDARY = re.compile(r'^[0-9A-Za-z\'()+_,-./:=? ]{1,70}$')
_QP_SOFT = re.compile(rb'=[0-9A-Fa-f]{2}')


class StructuralRefusal(Exception):
    """These bytes cannot be read completely under the bounds above.

    Carries one fixed code from this module's refusal set and nothing else: no offset, no field text,
    no fragment of the message. The code is what lands in a counted outcome and a log line; the message
    a hostile input chose is not, because a refusal string that reaches an operator's dashboard through
    a log shipper is a second, unaudited content channel.
    """

    def __init__(self, code: str) -> None:
        super().__init__(f'RFC 822 read refused: {code}')
        self.code = code


@dataclass(frozen=True)
class HeaderField:
    """One header field, name lower-cased for lookup, value unfolded and ASCII-decoded."""
    name: str
    value: str


@dataclass(frozen=True)
class Node:
    """One message at one nesting level, with its own verbatim bytes.

    `raw` is the digest target: for the outermost node the fetched blob exactly as the transport
    returned it, for a nested `message/rfc822` node the transfer-decoded body bytes of that part (which,
    because a transfer-encoded nested part is refused, are the verbatim bytes inside the container).
    """
    depth: int
    raw: bytes
    headers: tuple[HeaderField, ...]
    body: bytes
    content_type: str
    parts: tuple['Node', ...]

    def values(self, name: str) -> tuple[str, ...]:
        """Every value carried under `name` (already lower-cased), in the order they appear."""
        wanted = name.lower()
        return tuple(field.value for field in self.headers if field.name == wanted)

    def first(self, name: str) -> str | None:
        """The first value of `name`, or `None`. Never a merge: callers that must know about
        duplicates ask `values()`."""
        found = self.values(name)
        return found[0] if found else None


@dataclass(frozen=True)
class Document:
    """The read message: its root node and every message-level chain the reader enumerated.

    `chains` holds tuples ordered outermost-first, so a chain's `i`-th entry is the level a receiver
    would have to attest to vouch for the chain's last entry. Selection of *which* chain carries the
    alert is a policy question and lives in `parser.py`; this reader enumerates them all, bounded.
    """
    root: Node
    chains: tuple[tuple[Node, ...], ...]

    @property
    def nodes(self) -> tuple[Node, ...]:
        """Every message-level node, outermost first, de-duplicated by object identity."""
        seen: list[Node] = []
        for chain in self.chains:
            for node in chain:
                if not any(node is item for item in seen):
                    seen.append(node)
        return tuple(seen)


def _split_header(raw: bytes) -> tuple[bytes, bytes]:
    """Header block and body, split at the first empty line (CRLF or LF, either accepted).

    A level with no blank line at all is headers-only, which is what the standard calls a message with
    an absent body; the empty-body case is refused upstream by content-type rules, not here, so this
    function stays a pure splitter.
    """
    position = 0
    while position < len(raw):
        end = raw.find(b'\n', position)
        line = raw[position:] if end == -1 else raw[position:end]
        if line.endswith(b'\r'):
            line = line[:-1]
        if not line:
            return raw[:position], (b'' if end == -1 else raw[end + 1:])
        position = len(raw) if end == -1 else end + 1
    return raw, b''


def _unfold(value: bytes) -> str:
    """Decode one field value: ASCII strict, continuation whitespace collapsed to one space.

    Non-ASCII bytes are refused rather than guessed at. Encoded-words (`=?utf-8?Q?…?=`) are ASCII on the
    wire and are decoded by `decoded()` below; raw non-ASCII in a header means the sender wrote bytes
    the standard does not have, and the choice then is between two guesses at the charset of the text
    that decides whether a sign-in alert is believed.
    """
    collapsed = re.sub(rb'[\r\n]+([ \t]+)', b' ', value)
    collapsed = re.sub(rb' {2,}', b' ', collapsed).strip()
    try:
        return collapsed.decode('ascii')
    except UnicodeDecodeError:
        raise StructuralRefusal('undecodable-header') from None


def _fields(header_block: bytes) -> tuple[HeaderField, ...]:
    """The header block as ordered `(name, value)` pairs, with continuations attached to their field.

    A line starting with whitespace before any field exists, or a line with no colon, is
    `malformed-headers`: the stdlib reads the latter as the start of the body, which is exactly the
    disagreement `_cross_check` is built to catch, and reading it as a field here instead would let a
    body line pose as a header.
    """
    fields: list[HeaderField] = []
    pending: list[tuple[str, bytes]] = []
    position = 0
    while position < len(header_block):
        end = header_block.find(b'\n', position)
        line = header_block[position:] if end == -1 else header_block[position:end]
        position = len(header_block) if end == -1 else end + 1
        if line.endswith(b'\r'):
            line = line[:-1]
        if line.startswith((b' ', b'\t')):
            if not pending:
                raise StructuralRefusal('malformed-headers')
            pending[-1] = (pending[-1][0], pending[-1][1] + b'\r\n' + line)
            continue
        name, separator, value = line.partition(b':')
        if not separator or not _TOKEN.match(name):
            raise StructuralRefusal('malformed-headers')
        pending.append((name.lower().decode('ascii'), value.lstrip(b' \t')))
    if len(pending) > MAX_HEADER_FIELDS:
        raise StructuralRefusal('header-count-exceeded')
    for _, value in pending:
        if len(value) > MAX_HEADER_VALUE_CHARS * 4:
            raise StructuralRefusal('header-value-too-large')
    for name, value in pending:
        text = _unfold(value)
        fields.append(HeaderField(name=name, value=text))
    return tuple(fields)


def decoded(value: str) -> str:
    """An RFC 2047 field value as text: encoded-words decoded, undecodable parts refused, never kept raw.

    A field whose encoded-word names an unknown or bogus charset is refused (`undecodable-header`)
    rather than left as `=?bogus?Q?xx?=`: the alternative is a subject line whose visible text depends
    on which decoder gets there first, and this unit's classification patterns match text.
    """
    try:
        parts = email.header.decode_header(value)
    except Exception:
        raise StructuralRefusal('undecodable-header') from None
    out: list[str] = []
    for payload, charset in parts:
        if isinstance(payload, bytes):
            try:
                out.append(payload.decode(charset or 'ascii'))
            except (LookupError, UnicodeDecodeError):
                raise StructuralRefusal('undecodable-header') from None
        else:
            out.append(payload)
    return ''.join(out)


def _content_type(node_headers: tuple[HeaderField, ...]) -> tuple[str, dict[str, str]]:
    """The declared content type (lower-cased) and its parameters; absent means `text/plain`.

    RFC 2045 §5.2 makes an absent `Content-Type` mean `text/plain` with ASCII, which is what a bare
    one-line security notice looks like. A *present* but unparseable value is a refusal: guessing the
    type of a part decides whether its body is read as text at all.
    """
    declared = [field.value for field in node_headers if field.name == 'content-type']
    if len(declared) > 1:
        raise StructuralRefusal('duplicate-content-type')
    if not declared:
        return 'text/plain', {}
    pieces = declared[0].split(';')
    main = pieces[0].strip().lower()
    if not re.fullmatch(r'[a-z0-9!#$&\-.^+_]+/[a-z0-9!#$&\-.^+_]+', main):
        raise StructuralRefusal('malformed-content-type')
    parameters: dict[str, str] = {}
    for piece in pieces[1:]:
        key, separator, raw = piece.partition('=')
        if not separator:
            continue
        name = key.strip().lower()
        value = raw.strip()
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1]
        parameters[name] = value
    return main, parameters


def _boundary(parameters: dict[str, str]) -> str:
    """The multipart boundary, validated before it is ever used to split bytes.

    An absent or duplicated `boundary` parameter, or one outside RFC 2046's character set and length, is
    `bad-boundary`: splitting a body on an unvalidated delimiter is how a message writes its own
    structure.
    """
    values = parameters.get('boundary')
    if values is None or not _BOUNDARY.match(values) or values.endswith(' '):
        raise StructuralRefusal('bad-boundary')
    return values


def _multipart(body: bytes, boundary: str) -> list[bytes]:
    """The raw byte blob of each part between `--boundary` delimiters, preamble and epilogue discarded.

    Delimiters are matched as whole lines, and a `--boundary--` close ends the tree. Zero parts is
    `malformed-multipart`: a multipart body with nothing in it carries no alert, and letting it through
    as "an empty message" would make the fetch count as read.
    """
    close = ('--' + boundary + '--').encode('ascii')
    open_ = ('--' + boundary).encode('ascii')
    parts: list[bytes] = []
    current: list[bytes] = []
    started = False

    def emit() -> None:
        blob = b''.join(current)
        # RFC 2046: the CRLF immediately before a delimiter belongs to the delimiter, not to the part.
        # Dropping exactly that one terminator is what makes a nested message's bytes the forwarded
        # original rather than the original plus a stray newline, which is the difference between a
        # receiver's digest matching and not matching.
        if blob.endswith(b'\r\n'):
            blob = blob[:-2]
        elif blob.endswith(b'\n'):
            blob = blob[:-1]
        parts.append(blob)

    for line in body.splitlines(keepends=True):
        stripped = line.rstrip(b'\r\n')
        if stripped == close:
            if started:
                emit()
            break
        if stripped == open_:
            if started:
                emit()
            current = []
            started = True
            continue
        if started:
            current.append(line)
    if not parts:
        raise StructuralRefusal('malformed-multipart')
    return parts


def _transfer_encoding(headers: tuple[HeaderField, ...]) -> str:
    """The declared transfer encoding, lower-cased, `7bit` when absent; a duplicate is a refusal.

    Two different `Content-Transfer-Encoding` fields make "which bytes did the receiver see?" unanswerable
    by construction, so there is no reasonable default to fall back to.
    """
    values = tuple(field.value for field in headers if field.name == 'content-transfer-encoding')
    if len(values) > 1:
        raise StructuralRefusal('duplicate-transfer-encoding')
    return (values[0].strip().lower() if values else '7bit')


def _decode_transfer(body: bytes, encoding: str) -> bytes:
    """The bytes a part's content actually is, for the two encodings this reader accepts.

    `7bit`/`8bit`/`binary` are verbatim. `base64` and `quoted-printable` are decoded here (and only
    here, for text parts) because a body that is encoded is still readable text; a *nested message*
    behind either is refused instead — see `_build`.
    """
    if encoding in ('7bit', '8bit', 'binary'):
        return body
    if encoding == 'base64':
        import base64
        # Line breaks are part of base64 *transport*, not content, so they are removed before the
        # strict decode; anything else that is not alphabet is a refusal rather than a silent skip.
        packed = re.sub(rb'[ \t\r\n]+', b'', body)
        try:
            return base64.b64decode(packed, validate=True)
        except ValueError:
            raise StructuralRefusal('malformed-body-encoding') from None
    if encoding == 'quoted-printable':
        import quopri
        return quopri.decodestring(body)
    raise StructuralRefusal('unsupported-transfer-encoding')


def _build(raw: bytes, depth: int, budget: list[int]) -> Node:
    """One node and its children. Message chains are derived afterwards by `_chains`, from this tree.

    `budget` is a single-element counter of nodes built in this call: the ceilings are enforced against
    it so a wide, shallow multipart tree and a deep chain are both bounded by one number.
    """
    if len(raw) > MAX_MESSAGE_BYTES:
        raise StructuralRefusal('oversized-message')
    header_block, body = _split_header(raw)
    if len(header_block) > MAX_HEADER_BLOCK_BYTES:
        raise StructuralRefusal('header-block-too-large')
    headers = _fields(header_block)
    _cross_check(raw, headers)
    content_type, parameters = _content_type(headers)
    encoding = _transfer_encoding(headers)
    children: list[Node] = []
    if content_type.startswith('multipart/'):
        boundary = _boundary(parameters)
        blobs = _multipart(body, boundary)
        if len(blobs) > MAX_PARTS:
            raise StructuralRefusal('too-many-parts')
        for blob in blobs:
            budget[0] += 1
            if budget[0] > MAX_PARTS * MAX_LEVELS:
                raise StructuralRefusal('too-many-parts')
            children.append(_build(blob, depth, budget))
        body_bytes = body
    elif content_type == 'message/rfc822':
        # A forwarded original behind base64 or quoted-printable cannot be attested: the receiver
        # verified the bytes it received, and this reader would be hashing bytes it reassembled by
        # guessing. Refusing names the case; the operator sees it as a counted parse failure.
        if encoding not in ('7bit', '8bit', 'binary'):
            raise StructuralRefusal('transfer-encoded-nested')
        if depth + 1 >= MAX_LEVELS:
            raise StructuralRefusal('nested-too-deep')
        budget[0] += 1
        if budget[0] > MAX_PARTS * MAX_LEVELS:
            raise StructuralRefusal('too-many-parts')
        children.append(_build(body, depth + 1, budget))
        body_bytes = body
    else:
        body_bytes = _decode_transfer(body, encoding)
    return Node(depth=depth, raw=raw, headers=headers, body=body_bytes, content_type=content_type,
                parts=tuple(children))


def _cross_check(raw: bytes, headers: tuple[HeaderField, ...]) -> None:
    """Ask the stdlib parser the same question and refuse when the answers differ.

    It is given the whole level, headers *and* body, because feeding it a header block alone would make
    a `multipart/*` message report `StartBoundaryNotFoundDefect` for a body it was never handed — the
    check would then refuse every legitimate forwarded alert (measured, not guessed). Two independent
    readings must agree on the top-level field count. They disagree when a body line is colon-free (the
    stdlib starts the body there), when a field name the stdlib rejects was accepted here, or when any
    defect was raised — the last of which is checked directly, because a defect means the stdlib
    *repaired* something rather than reading it.
    """
    probe = BytesParser(policy=compat32).parsebytes(raw)
    if probe.defects:
        raise StructuralRefusal('malformed-headers')
    if len(probe.items()) != len(headers):
        raise StructuralRefusal('header-structure-disagreement')


def _embedded(node: Node) -> list[Node]:
    """The messages this node embeds through `message/rfc822` parts, at any multipart depth.

    The level returned is the *embedded message*, not the MIME part carrying it: the part node's bytes
    are the part's own headers plus the original, while the original's bytes are what a DKIM verifier
    signed. Attestation has to bind to the latter, so that is what a level is.
    """
    found: list[Node] = []
    for child in node.parts:
        if child.content_type == 'message/rfc822':
            found.extend(child.parts or [child])
        else:
            found.extend(_embedded(child))
    return found


def _chains(root: Node) -> tuple[tuple[Node, ...], ...]:
    """Every message-level path from the root, ordered outermost-first.

    One entry per level that has to be attested to believe the leaf: attesting a level covers every byte
    inside it, so a forwarded alert needs its own attestation *and* the container's. Leaves are the
    candidate alert messages `parser.py` selects between.
    """
    paths: list[tuple[Node, ...]] = [(root,)]

    def descend(prefix: tuple[Node, ...], node: Node) -> None:
        for inner in _embedded(node):
            chain = prefix + (inner,)
            paths.append(chain)
            if len(paths) > MAX_CHAINS:
                raise StructuralRefusal('too-many-nested-chains')
            descend(chain, inner)

    descend((root,), root)
    return tuple(paths)


def read_message(raw: bytes) -> Document:
    """Read one fetched blob into nodes and chains, or refuse with one fixed code.

    Args:
        raw: The bytes exactly as the transport returned them. The digest of these bytes is what the
            outermost level's attestation has to match, so a transport that re-encodes on the way
            through cannot satisfy the gate.

    Raises:
        StructuralRefusal: Any bound or structural rule above. `TypeError` is not converted: a caller
            that handed over a `str` has a bug, not a hostile input.
    """
    if not isinstance(raw, bytes):
        raise StructuralRefusal('not-bytes')
    if not raw:
        raise StructuralRefusal('empty-message')
    if len(raw) > MAX_MESSAGE_BYTES:
        raise StructuralRefusal('oversized-message')
    root = _build(raw, 0, [1])
    return Document(root=root, chains=_chains(root))


def collect_text(node: Node, *, limit: int = MAX_TEXT_CHARS) -> tuple[str, tuple[str, ...], int]:
    """`(subject, text parts, parts skipped)` for one node, read only after the trust gate passed.

    `text/plain` is preferred and `text/html` is used only when there is no plain part anywhere in the
    node's tree, which is the ordering that keeps an HTML-only alert classifiable without ever making a
    choice depend on part *order*. The character budget stops at `limit` across all parts, and however
    many parts the budget could not reach are counted — a truncated read says it was truncated.
    """
    plain: list[bytes] = []
    html: list[bytes] = []

    def visit(current: Node) -> None:
        if current.content_type == 'text/plain' and current.body:
            plain.append(current.body)
        elif current.content_type == 'text/html' and current.body:
            html.append(current.body)
        for child in current.parts:
            if child.content_type != 'message/rfc822':
                visit(child)

    visit(node)
    chosen = plain or html
    skipped = max(0, len(chosen) - MAX_TEXT_PARTS)
    texts: list[str] = []
    used = 0
    for blob in chosen[:MAX_TEXT_PARTS]:
        try:
            text = blob.decode('utf-8', errors='strict')
        except UnicodeDecodeError:
            raise StructuralRefusal('undecodable-body') from None
        if used >= limit:
            skipped += 1
            continue
        room = limit - used
        texts.append(text[:room])
        if len(text) > room:
            # A part that was cut mid-body is a bounded read, and a bounded read has to say so: the
            # alternative is a classifier that matched the first 6 KiB of a message and reported as
            # though it had seen the whole thing.
            skipped += 1
        used += min(len(text), room)
    subject_field = node.first('subject')
    subject = decoded(subject_field)[:limit] if subject_field is not None else ''
    return subject, tuple(texts), skipped

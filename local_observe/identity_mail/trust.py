"""The trust gate: what a receiver must attest, in its own words, before a message is believed.

Nothing in this module reads a message. It compares two things that arrive through different channels
and says whether one of them vouches for the other:

* the **attestation** — a statement made by a receiving agent the operator named, over the exact bytes
  of each level of the message, on a channel the operator also named; and
* the **authentication results found inside the message**, which are text any sender can type.

The gate is the first item and only the first item, because `Authentication-Results` is a *header*: RFC
8601 defines who may write it, not who may forge it, and a message that arrives with
`dkim=pass header.d=…` in its own headers has proven only that somebody wrote those bytes. The identity mail collector's
DKIM/SPF hard gate therefore cannot be satisfied by reading the mail. It needs a verdict from something
the operator trusts, **bound to the bytes** — which is why every level attestation carries the
`sha256` of that level's bytes and a mismatch is a refusal rather than a downgrade.

Two consequences worth stating plainly, because both are places a later reader will be tempted to relax:

1. **Reading a mailbox is not a trust channel.** IMAP hands back the message and its headers; it does
   not hand back a receiver's DKIM verdict for those bytes, and Gmail's IMAP surface publishes no
   per-message authentication-result item that this unit could treat as one. So an IMAP collector is
   useful only behind a boundary that can attest — a receiving MTA the operator runs, or a provider API
   whose verified results the operator trusts and can name. `TRUSTED_CHANNELS` is a closed set precisely
   so that "I read the header off the message" has no spelling here.
2. **A forwarded alert needs its own attestation.** ARC (`arc=`) seals authentication headers against
   modification, but a seal says "these bytes were sealed by somebody in the chain", not "this operator
   trusts that somebody". So every level of a nested chain must be attested over its own bytes; an
   `arc=pass` that is not accompanied by a bound inner verdict is recorded as a diagnostic and does not
   open the gate. Forwarding by *filter into the collector mailbox* (one alert per top-level message)
   is the topology this gate is designed for — see `docs/units/identity-mail.md`.

Fail-closed rules, in the order assessed, each one a fixed code and nothing else: a refusal never
carries the domain, address or text it was decided about, because that text is attacker-chosen and a
reason string that reaches a dashboard is a content channel nobody audited.
"""
from dataclasses import dataclass, field
import datetime as dt
import hashlib
import re

from local_observe.inventory.validation import timestamp
from local_observe.platform.state import label

__all__ = ['AttestationError', 'Attestation', 'LevelAttestation', 'Level', 'ProviderTrust', 'TrustPolicy',
           'Assessment', 'TRUSTED_CHANNELS', 'MECHANISMS', 'policy_from_document', 'policy_fingerprint',
           'assess', 'parse_authentication_results', 'sha256_text', 'MAX_AUTH_RESULTS_CHARS']

#: The channels a trusted attestation may have arrived on, and the only ones. `receiver-log` is the
#: receiving agent's own record of what it authenticated for these bytes; `provider-api` is a mailbox
#: provider's verified result over an authenticated API; `mta-spool` is the delivered-copy audit of an
#: MTA the operator runs. There is deliberately no entry meaning "the message's own header", and no
#: caller can add one at runtime: `Attestation` validates the channel at construction.
TRUSTED_CHANNELS = ('receiver-log', 'provider-api', 'mta-spool')

#: The mechanisms whose verdicts this gate reads, from RFC 8601 §3.1 plus ARC's `arc` (RFC 8617).
#: Anything else parses and is ignored: an unknown mechanism claiming `pass` must not be able to open a
#: gate, and refusing the whole field for one mechanism the receiver invented would refuse genuine mail.
MECHANISMS = ('dkim', 'spf', 'dmarc', 'arc', 'dkim-adsp', 'pki', 'ct', 'mia', 'mhs', 'irs', 'not-prerfc')

#: Every result token this gate will parse, as one closed set across the mechanisms (RFC 8601 §3.2 and
#: §3.3, plus the DKIM/SPF-specific spellings real receivers still emit). An unrecognised token is
#: malformed text, not a soft pass.
RESULT_VALUES = frozenset({
    'none', 'pass', 'fail', 'policy', 'neutral', 'softfail', 'hardfail', 'temperror', 'permerror',
    'not-signed', 'not-provided', 'unknown',
})

MAX_AUTH_RESULTS_CHARS = 4096
MAX_STATEMENTS = 16
MAX_PROPERTIES = 24
MAX_VALUE_CHARS = 256
MAX_COMMENT_DEPTH = 8
MAX_DOMAIN_CHARS = 253
MAX_PROVIDER_DOMAINS = 16
MAX_TRUSTED_RECEIVERS = 8

#: The clock bounds on an attestation. An attestation older than `max_attestation_age_seconds` is
#: refused: it vouches for bytes the receiver saw at a moment that may be long gone, and a collector
#: that replays an old attestation over new bytes is exactly the forgery the digest binding exists to
#: stop (the binding catches it only if the old attestation covered *these* bytes, which a replay of a
#: genuine message's attestation does).
MIN_ATTESTATION_AGE_SECONDS = 60
MAX_ATTESTATION_AGE_SECONDS = 604800
CLOCK_SKEW_SECONDS = 60

_TOKEN = re.compile(r'^[A-Za-z][A-Za-z0-9\-]*$')
_DOMAIN = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9\-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]'
                     r'([A-Za-z0-9\-]{0,62}[A-Za-z0-9])?)*$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _valid_domain(value: object) -> bool:
    """A plain, case-foldable domain name: no spaces, no ports, no wildcards, no trailing dot games."""
    return isinstance(value, str) and bool(_DOMAIN.match(value.strip().rstrip('.').lower()))



class AttestationError(ValueError):
    """A configuration or attestation this module may not use. Fixed sentences; no attacker text."""


def sha256_text(raw: bytes) -> str:
    """The lowercase hex `sha256` of exactly these bytes — the binding both sides must compute the same way.

    `docs/units/identity-mail.md` states the byte definition per level (the fetched blob for the outer
    level; the embedded message's own bytes, minus the delimiter's preceding CRLF per RFC 2046, for a
    forwarded one). A boundary that digests different bytes cannot satisfy the gate, and will see
    `attestation-binding-mismatch` rather than a silent trust decision.
    """
    if not isinstance(raw, bytes):
        raise AttestationError('Level bytes must be given as bytes')
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Statement:
    """One parsed `mechanism=result key=value…` statement from an `Authentication-Results` field."""
    mechanism: str
    result: str
    properties: dict[str, str] = field(default_factory=dict)

    def value(self, name: str) -> str | None:
        return self.properties.get(name)


# ------------------------------------------------------------------ RFC 8601 field parsing


def _strip_comments(text: str) -> str:
    """Remove RFC 8601 free-text comments, honouring quoted strings and nesting.

    Comments are where receivers put their own prose ("example: 198.51.100.7 is authorized to send for
    example.com"). It can contain `=`, `;` and parentheses, so it has to go before any splitting — and
    an unbalanced comment or quote is refused, not repaired: a parser that guesses where a comment ends
    can be told to hide the `;` that separated two statements. Quoted strings survive untouched, because
    a quoted `;` or `(` is data (`header.i="smtp; out 4.99"`) rather than prose.
    """
    out: list[str] = []
    depth = 0
    quoted = False
    index = 0
    while index < len(text):
        character = text[index]
        if quoted:
            out.append(character)
            if character == '\\' and index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
                continue
            if character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            out.append(character)
            index += 1
            continue
        if character == '(':
            depth += 1
            if depth > MAX_COMMENT_DEPTH:
                raise ValueError('comment nesting')
            index += 1
            continue
        if character == ')':
            if depth == 0:
                raise ValueError('unbalanced comment')
            depth -= 1
            index += 1
            continue
        if depth == 0:
            out.append(character)
            index += 1
        else:
            index += 1
    if depth or quoted:
        raise ValueError('unterminated comment or string')
    return ''.join(out)


def _split_outside_quotes(text: str, separator: str) -> list[str]:
    pieces: list[str] = []
    current: list[str] = []
    quoted = False
    for character in text:
        if character == '"':
            quoted = not quoted
            current.append(character)
        elif character == separator and not quoted:
            pieces.append(''.join(current))
            current = []
        else:
            current.append(character)
    pieces.append(''.join(current))
    return pieces


def _property_tokens(text: str) -> list[str]:
    """Whitespace-split outside quotes, so a `header.i="a b"` survives as one token."""
    tokens: list[str] = []
    current: list[str] = []
    quoted = False
    for character in text:
        if character == '"':
            quoted = not quoted
            current.append(character)
        elif character.isspace() and not quoted:
            if current:
                tokens.append(''.join(current))
                current = []
        else:
            current.append(character)
    if current:
        tokens.append(''.join(current))
    return tokens


def _unquote(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1].replace('\\\\', '\\').replace('\\"', '"')
    return value


def _statement(text: str) -> Statement:
    """One statement, or `ValueError`. Every field of it is checked against a closed shape."""
    tokens = _property_tokens(text)
    if not 1 <= len(tokens) <= MAX_PROPERTIES + 1:
        raise ValueError('statement width')
    head, separator, raw_result = tokens[0].partition('=')
    if not separator:
        raise ValueError('missing result')
    mechanism = head.strip().lower()
    if not _TOKEN.match(mechanism) or mechanism not in MECHANISMS:
        raise ValueError('unknown mechanism')
    result = raw_result.strip().lower()
    if result not in RESULT_VALUES:
        raise ValueError('unknown result')
    properties: dict[str, str] = {}
    for token in tokens[1:]:
        key, equals, raw = token.partition('=')
        if not equals:
            raise ValueError('bare property')
        name = key.strip().lower()
        if not re.fullmatch(r'[a-z][a-z0-9.\-]{0,63}', name):
            raise ValueError('property name')
        value = _unquote(raw.strip())
        if not 1 <= len(value) <= MAX_VALUE_CHARS:
            raise ValueError('property width')
        properties[name] = value
    return Statement(mechanism=mechanism, result=result, properties=properties)


def parse_authentication_results(text: str) -> tuple[Statement, ...] | None:
    """Parse one `Authentication-Results` field body, or `None` when it is not a readable one.

    Safe on attacker-chosen text by construction: length- and count-bounded, comment-stripped before
    splitting, and every refusal path returns `None` rather than an exception, so the caller's job is
    one comparison instead of an exception taxonomy. The version prefix is required to be `1` when
    present; a field that omits it is still parsed (real receivers do), and the caller has no reason to
    care because the version buys nothing this gate relies on.
    """
    if not isinstance(text, str) or not 1 <= len(text) <= MAX_AUTH_RESULTS_CHARS:
        return None
    try:
        cleaned = _strip_comments(text)
    except ValueError:
        return None
    pieces = [piece.strip() for piece in _split_outside_quotes(cleaned, ';')]
    pieces = [piece for piece in pieces if piece]
    if not 1 <= len(pieces) <= MAX_STATEMENTS + 1:
        return None
    if re.fullmatch(r'[0-9]{1,3}', pieces[0]):
        if pieces[0] != '1':
            return None
        pieces = pieces[1:]
    if not 1 <= len(pieces) <= MAX_STATEMENTS:
        return None
    statements: list[Statement] = []
    try:
        for piece in pieces:
            statements.append(_statement(piece))
    except ValueError:
        return None
    return tuple(statements)


# ------------------------------------------------------------------------- attestations


@dataclass(frozen=True)
class LevelAttestation:
    """What a receiver asserts about one message level: its bytes, its verdict text, and when."""
    digest_sha256: str
    auth_results: str
    channel: str
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.digest_sha256, str) or not _HEX64.match(self.digest_sha256):
            raise AttestationError('Level attestation must carry a lowercase sha256 hex digest')
        if self.channel not in TRUSTED_CHANNELS:
            raise AttestationError('Level attestation names a channel this gate does not trust')
        if not isinstance(self.auth_results, str) or not 1 <= len(self.auth_results) <= MAX_AUTH_RESULTS_CHARS:
            raise AttestationError('Level attestation carries an unusable authentication-result field')
        moment = timestamp(self.observed_at)
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise AttestationError('Level attestation time must be timezone-aware')


@dataclass(frozen=True)
class Attestation:
    """One receiver's word for one fetched message, level by level, outermost first.

    `levels` is positional: entry `i` speaks for level `i` of the chain the collector read. A receiver
    that attests only the outer level cannot be used for a forwarded alert, and says so by carrying one
    entry — the mismatch is a refusal, never an inference that the missing levels were fine.
    """
    receiver: str
    levels: tuple[LevelAttestation, ...]

    def __post_init__(self) -> None:
        label(self.receiver)
        if not isinstance(self.levels, tuple) or not 1 <= len(self.levels) <= 3:
            raise AttestationError('Attestation must carry between 1 and 3 message levels')
        for item in self.levels:
            if not isinstance(item, LevelAttestation):
                raise AttestationError('Attestation levels must be LevelAttestation records')


@dataclass(frozen=True)
class Level:
    """The collector's side of the comparison for one message level.

    `digest_sha256` names the bytes, `sender_domain` is that level's own `From` domain (structural, and
    attacker-chosen — used only to ask *which signature must line up with it*), and
    `header_auth_results` carries the `Authentication-Results` fields the message contains for itself,
    which are read for forgery diagnostics and never for belief.
    """
    digest_sha256: str
    sender_domain: str
    header_auth_results: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.digest_sha256, str) or not _HEX64.match(self.digest_sha256):
            raise AttestationError('Level bytes must be named by a lowercase sha256 hex digest')
        folded = (self.sender_domain or '').strip().rstrip('.').lower()
        if not _DOMAIN.match(folded):
            raise AttestationError('Level sender domain must be a plain domain')
        if not isinstance(self.header_auth_results, tuple) or len(self.header_auth_results) > 8:
            raise AttestationError('Level header results must be a bounded tuple')
        for item in self.header_auth_results:
            if not isinstance(item, str) or not 1 <= len(item) <= MAX_AUTH_RESULTS_CHARS:
                raise AttestationError('Level header results must be bounded strings')


# ---------------------------------------------------------------------------- policy


@dataclass(frozen=True)
class ProviderTrust:
    """Which sender domains name a provider, and which DKIM domains may vouch for them.

    Keeping the two lists separate is the point. `sender_domains` decides *whose alert this looks like*
    (and therefore which parser's lexicon applies); `dkim_domains` decides *what may be believed about
    it*. A provider that signs its alert mail with a different domain from the one in `From:` is normal,
    so a single list would either refuse genuine mail or accept alignment tricks.
    """
    name: str
    sender_domains: tuple[str, ...]
    dkim_domains: tuple[str, ...]

    def __post_init__(self) -> None:
        label(self.name)
        for group in (self.sender_domains, self.dkim_domains):
            if not isinstance(group, tuple) or not 1 <= len(group) <= MAX_PROVIDER_DOMAINS:
                raise AttestationError(f'Provider {self.name} must name 1..{MAX_PROVIDER_DOMAINS} domains')
            for domain in group:
                if not _valid_domain(domain):
                    raise AttestationError(f'Provider {self.name} names an unusable domain')


@dataclass(frozen=True)
class TrustPolicy:
    """The operator's trust configuration: who may attest, on which channels, for which providers.

    `forwarder_dkim_domains` is the list that makes nesting possible at all, and it is empty by default:
    a container level (the forwarding message around a `message/rfc822` alert) is only ever believed for
    its own signature if the operator named that signing domain. Empty therefore means *forwarded
    alerts are refused*, which is the fail-closed reading of a configuration nobody filled in.
    """
    providers: tuple[ProviderTrust, ...]
    trusted_receivers: tuple[str, ...]
    channels: tuple[str, ...] = TRUSTED_CHANNELS
    forwarder_dkim_domains: tuple[str, ...] = ()
    max_attestation_age_seconds: int = 86400

    def __post_init__(self) -> None:
        if not isinstance(self.providers, tuple) or not 1 <= len(self.providers) <= 8:
            raise AttestationError('A trust policy needs between 1 and 8 providers')
        if not isinstance(self.trusted_receivers, tuple) or not 1 <= len(self.trusted_receivers) \
                <= MAX_TRUSTED_RECEIVERS:
            raise AttestationError('A trust policy needs between 1 and '
                                   f'{MAX_TRUSTED_RECEIVERS} trusted receivers')
        for receiver in self.trusted_receivers:
            label(receiver)
        if not isinstance(self.channels, tuple) or not 1 <= len(self.channels) <= len(TRUSTED_CHANNELS):
            raise AttestationError('A trust policy may narrow channels, never widen them')
        for channel in self.channels:
            if channel not in TRUSTED_CHANNELS:
                raise AttestationError('A trust policy names a channel this gate does not implement')
        if not isinstance(self.forwarder_dkim_domains, tuple) \
                or len(self.forwarder_dkim_domains) > MAX_PROVIDER_DOMAINS:
            raise AttestationError('Forwarder DKIM domains must be a bounded tuple')
        for domain in self.forwarder_dkim_domains:
            if not _valid_domain(domain):
                raise AttestationError('Forwarder DKIM domain is unusable')
        if (isinstance(self.max_attestation_age_seconds, bool)
                or not isinstance(self.max_attestation_age_seconds, int)
                or not MIN_ATTESTATION_AGE_SECONDS <= self.max_attestation_age_seconds
                <= MAX_ATTESTATION_AGE_SECONDS):
            raise AttestationError('Attestation age bound must be an integer seconds between '
                                   f'{MIN_ATTESTATION_AGE_SECONDS} and {MAX_ATTESTATION_AGE_SECONDS}')

    def provider_for_sender(self, domain: str) -> ProviderTrust | None:
        """Which supported provider `domain` names, if any — exact, case-folded, never a suffix match.

        Suffix or substring matching here is how `accounts.google.com.phish.example` becomes Google, so
        the comparison is equality on the whole domain and nothing else.
        """
        folded = domain.strip().rstrip('.').lower()
        for provider in self.providers:
            if folded in tuple(item.lower() for item in provider.sender_domains):
                return provider
        return None


_DOCUMENT_FIELDS = {'schema_version', 'providers', 'trusted_receivers', 'channels',
                    'forwarder_dkim_domains', 'max_attestation_age_seconds'}


def policy_from_document(document: object) -> TrustPolicy:
    """Validate an operator's trust document into a `TrustPolicy`.

    An empty allowlist is refused rather than trusted-by-default-nothing: with nothing configured the
    collector should not be running, and a document that quietly produces a policy believing nothing is
    indistinguishable at 3 a.m. from a parser that found nothing to believe.

    Raises:
        AttestationError: Any field is missing, unknown, unbounded or names something outside the sets
            this module implements.
    """
    if not isinstance(document, dict) or 'schema_version' not in document or set(document) - _DOCUMENT_FIELDS:
        raise AttestationError('Trust policy document must hold schema_version and known keys only')
    if document['schema_version'] != 1:
        raise AttestationError('Unsupported trust policy schema version')
    providers = document.get('providers')
    if not isinstance(providers, list) or not 1 <= len(providers) <= 8:
        raise AttestationError('Trust policy must declare between 1 and 8 providers')
    built: list[ProviderTrust] = []
    for entry in providers:
        if (not isinstance(entry, dict)
                or set(entry) != {'name', 'sender_domains', 'dkim_domains'}
                or not isinstance(entry['sender_domains'], list)
                or not isinstance(entry['dkim_domains'], list)):
            raise AttestationError('Trust policy provider must name name, sender_domains, dkim_domains')
        built.append(ProviderTrust(name=entry['name'], sender_domains=tuple(entry['sender_domains']),
                                  dkim_domains=tuple(entry['dkim_domains'])))
    receivers = document.get('trusted_receivers')
    if not isinstance(receivers, list) or not receivers:
        raise AttestationError('Trust policy must name at least one trusted receiver')
    channels = document.get('channels', list(TRUSTED_CHANNELS))
    if not isinstance(channels, list) or not channels:
        raise AttestationError('Trust policy channels must not be empty')
    forwarders = document.get('forwarder_dkim_domains', [])
    if not isinstance(forwarders, list):
        raise AttestationError('Trust policy forwarder_dkim_domains must be a list')
    age = document.get('max_attestation_age_seconds', MAX_ATTESTATION_AGE_SECONDS)
    return TrustPolicy(providers=tuple(built), trusted_receivers=tuple(receivers), channels=tuple(channels),
                       forwarder_dkim_domains=tuple(forwarders),
                       max_attestation_age_seconds=age if isinstance(age, int) else 0)


def policy_fingerprint(policy: TrustPolicy) -> str:
    """A stable digest of a validated policy, for a cursor to pin its batch against.

    The object itself is not storable (a dataclass is not canonical JSON), and the raw document a caller
    happened to parse is not either: two documents that validate to the same policy must produce the
    same fingerprint, or a re-formatting of the same trust decision looks like a trust change and
    strands a pending batch. So the digest covers the validated fields, in this module's own order.
    """
    from local_observe.inventory.validation import digest

    if not isinstance(policy, TrustPolicy):
        raise AttestationError('A policy fingerprint needs a TrustPolicy')
    return digest([[[provider.name, list(provider.sender_domains), list(provider.dkim_domains)]
                    for provider in policy.providers],
                   list(policy.trusted_receivers), list(policy.channels),
                   list(policy.forwarder_dkim_domains), policy.max_attestation_age_seconds])


# ------------------------------------------------------------------------------ gate


@dataclass(frozen=True)
class Assessment:
    """The gate's answer: believed or not, one code, and diagnostics that never change the verdict."""
    trusted: bool
    code: str
    diagnostics: tuple[str, ...] = ()
    provider: str | None = None
    sender_domain: str | None = None

    def __post_init__(self) -> None:
        if self.trusted and self.code != 'trusted':
            raise AttestationError('A trusted assessment must carry the trusted code')


def _aligned(dkim_domain: str, sender_domain: str) -> bool:
    """Relaxed alignment (RFC 7489 §3.1.1): equal, or the signer is a parent of the sender's domain.

    Parent-domain signing is how a provider signs account mail with its organisational domain, so
    refusing it would refuse genuine alerts; refusing *child*-domain signing is the point, because
    `phish.accounts.google.com` is a hostname somebody else owns.
    """
    if dkim_domain == sender_domain:
        return True
    return sender_domain.endswith('.' + dkim_domain)


def _dkim_verdict(statements: tuple[Statement, ...], allowlist: tuple[str, ...], sender_domain: str,
                  diagnostics: list[str]) -> str | None:
    """`None` when DKIM opens the gate for this level, otherwise one refusal code.

    Several DKIM statements are ordinary (a provider that re-signs, a forwarding MTA that added its own
    signature), so the rule is *at least one statement fully satisfies the gate*, not *the first
    statement*. A `pass` whose `header.d` is not allowlisted is not partial credit: it is a signature by
    somebody else. The refusal names the class of failure and never the domain, because the domain is
    attacker-chosen text and a reason string that reaches a dashboard is a content channel.
    """
    signing = [item for item in statements if item.mechanism == 'dkim']
    if not signing:
        return 'dkim-record-absent'
    if len(signing) > 1:
        diagnostics.append('multiple-dkim-statements')
    folded = tuple(domain.strip().rstrip('.').lower() for domain in allowlist)
    passing = [item for item in signing if item.result == 'pass']
    if not passing:
        return 'dkim-not-pass'
    aligned_seen = False
    for item in passing:
        signed = (item.properties.get('header.d') or item.properties.get('d') or '').strip().rstrip('.')
        signed = signed.lower()
        if not _DOMAIN.match(signed) or signed not in folded:
            continue
        if not _aligned(signed, sender_domain):
            aligned_seen = True
            continue
        return None
    return 'dkim-misaligned' if aligned_seen else 'dkim-domain-not-allowlisted'


def _header_forgery_diagnostics(level: Level, attested: LevelAttestation) -> tuple[str, ...]:
    """What the message claimed about itself versus what the receiver said — reported, never believed.

    These codes exist so an operator can see that somebody *tried*: a genuine alert whose own headers
    disagree with the receiver's verdict, or that carries an authentication header the receiver never
    wrote, is a forgery attempt or a mangled forward. Neither changes the verdict, because the verdict
    is a function of the attestation and the bytes only.
    """
    found: list[str] = []
    normalised = ' '.join(attested.auth_results.split())
    copies = [' '.join(item.split()) for item in level.header_auth_results]
    if not copies:
        found.append('receiver-copy-absent-from-message')
    elif normalised not in copies:
        found.append('receiver-copy-differs-from-message')
        claims = [statement for text in level.header_auth_results
                  for statement in (parse_authentication_results(text) or ())
                  if statement.mechanism == 'dkim']
        attested_passes = any(statement.mechanism == 'dkim' and statement.result == 'pass'
                              for statement in (parse_authentication_results(attested.auth_results) or ()))
        if claims and attested_passes:
            found.append('forged-authentication-header-observed')
    if len(level.header_auth_results) > 1:
        found.append('multiple-authentication-headers')
    return tuple(found)


def _claim_diagnostics(levels: tuple[Level, ...]) -> tuple[str, ...]:
    """What a message asserted about itself when nobody vouched for it.

    Reported, never believed. The verdict is already fixed (`attestation-absent`), and the thing an
    operator needs from it is a count of messages that claimed DKIM success with nobody backing the
    claim — the signature of a forgery campaign, and invisible if the gate stops at "no proof" without
    saying what was asserted.
    """
    found: list[str] = []
    for level in levels:
        if not level.header_auth_results:
            continue
        claims = [statement for text in level.header_auth_results
                  for statement in (parse_authentication_results(text) or ())
                  if statement.mechanism == 'dkim']
        if any(statement.result == 'pass' for statement in claims):
            found.append('authentication-header-claims-dkim-pass')
        if claims:
            found.append('authentication-header-observed')
        if len(level.header_auth_results) > 1:
            found.append('multiple-authentication-headers')
    return tuple(dict.fromkeys(found))


def assess(*, attestation: Attestation | None, policy: TrustPolicy, levels: tuple[Level, ...],
           provider: ProviderTrust, now: dt.datetime) -> Assessment:
    """Decide whether the attestation vouches for these bytes, for this provider, right now.

    Args:
        attestation: The receiver's word, or `None` when the boundary could not produce one. `None` is
            the ordinary case for a collector that has no verifier wired up, and it is the most common
            answer this function gives: no attestation, no belief, whatever the headers say.
        levels: One entry per chain level, outermost first, each naming the digest of that level's
            bytes, that level's own `From` domain, and the `Authentication-Results` fields inside it.
        provider: Whose alert this looks like, taken from the **last** level's sender domain by
            `parser.py`. The last level is the alert; anything before it is a container.
        now: The instant judging this. Never defaulted: a gate reading its own clock cannot be tested at
            a fixed second, and an attestation's freshness is a comparison against a real instant.

    Returns:
        An `Assessment`. It never raises for hostile input: every refusal is a code.
    """
    sender_domain = levels[-1].sender_domain if levels else ''
    if attestation is None:
        return Assessment(trusted=False, code='attestation-absent',
                          diagnostics=_claim_diagnostics(levels), provider=provider.name,
                          sender_domain=sender_domain)
    if attestation.receiver not in policy.trusted_receivers:
        return Assessment(trusted=False, code='receiver-untrusted', provider=provider.name,
                          sender_domain=sender_domain)
    if len(attestation.levels) != len(levels):
        return Assessment(trusted=False, code='attestation-level-count',
                          diagnostics=_claim_diagnostics(levels), provider=provider.name,
                          sender_domain=sender_domain)
    diagnostics: list[str] = []
    last = len(levels) - 1
    for position, (level, attested) in enumerate(zip(levels, attestation.levels, strict=True)):
        if attested.channel not in policy.channels:
            return Assessment(trusted=False, code='channel-untrusted', provider=provider.name,
                              sender_domain=sender_domain)
        if attested.digest_sha256 != level.digest_sha256:
            return Assessment(trusted=False, code='attestation-binding-mismatch',
                              diagnostics=tuple(diagnostics), provider=provider.name,
                              sender_domain=sender_domain)
        age = (now - timestamp(attested.observed_at)).total_seconds()
        if age < -CLOCK_SKEW_SECONDS:
            return Assessment(trusted=False, code='attestation-from-the-future', provider=provider.name,
                              sender_domain=sender_domain)
        if age > policy.max_attestation_age_seconds:
            return Assessment(trusted=False, code='attestation-stale', provider=provider.name,
                              sender_domain=sender_domain)
        statements = parse_authentication_results(attested.auth_results)
        if statements is None:
            return Assessment(trusted=False, code='attestation-malformed', provider=provider.name,
                              sender_domain=sender_domain)
        if position == last:
            allowlist = provider.dkim_domains
        elif policy.forwarder_dkim_domains:
            allowlist = policy.forwarder_dkim_domains
        else:
            # A container level with nothing authorised to vouch for it. Refusing here is the whole
            # point of `forwarder_dkim_domains` defaulting to empty: an operator who has not named the
            # forwarders they trust gets no forwarded alerts, rather than alerts whose container was
            # signed by whoever happened to relay them.
            return Assessment(trusted=False, code='forwarder-not-trusted', provider=provider.name,
                              sender_domain=sender_domain)
        refusal = _dkim_verdict(statements, allowlist, level.sender_domain, diagnostics)
        if refusal is not None:
            return Assessment(trusted=False, code=refusal, diagnostics=tuple(diagnostics),
                              provider=provider.name, sender_domain=sender_domain)
        for item in statements:
            if item.mechanism == 'dmarc' and item.result in ('fail', 'permerror', 'policy'):
                return Assessment(trusted=False, code='dmarc-refused', diagnostics=tuple(diagnostics),
                                  provider=provider.name, sender_domain=sender_domain)
            if item.mechanism == 'spf' and item.result in ('fail', 'permerror'):
                return Assessment(trusted=False, code='spf-refused', diagnostics=tuple(diagnostics),
                                  provider=provider.name, sender_domain=sender_domain)
            if item.mechanism == 'arc' and position == 0:
                diagnostics.append(f'arc-{item.result}')
        diagnostics.extend(_header_forgery_diagnostics(level, attested))
    return Assessment(trusted=True, code='trusted', diagnostics=tuple(dict.fromkeys(diagnostics)),
                      provider=provider.name, sender_domain=sender_domain)

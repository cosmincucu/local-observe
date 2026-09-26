"""The pipeline: fetched bytes plus a receiver's attestation become a classified outcome.

`parse_message` is the whole product boundary for one message, and its ordering *is* the security
property, so it is stated here once, in order:

1. **Read the bytes or refuse** (`rfc822`). Nothing is believed about an unread message; oversize,
   malformed headers, an undecodable field or a nesting width over the bound all end here as
   `parse-failure`, with a code and no text.
2. **Pick the alert message structurally**, from chain leaves and `From` domains only — deepest match
   wins, and two provider matches at the same depth is `ambiguous-alert-message` rather than a choice.
   Body text plays no part, so an attacker cannot put a Google-looking sentence in a container and have
   this step select their own message.
3. **Run the trust gate** (`trust.assess`) over every level of that chain. Refused → `untrusted`, and
   the function returns **before the subject or body is read**.
4. **Only now** read the alert's text and classify it against the provider's lexicon
   (`providers.Provider.classify`). No match is `unsupported`, never a guess.

The four classifications are exhaustive, and each is a different operational sentence:

* `event` — a believed message saying a recognised identity event. This is the only one that emits an event.
* `untrusted` — read fine, but nobody the operator trusts vouched for these bytes. Someone claiming to
  be Google is not evidence that Google said it.
* `parse-failure` — the feed is *blind* on this message. Silence must not mean all clear, so these are
  counted and reported as source coverage by the collector, not merely logged.
* `unsupported` — readable and out of scope: another provider's domain, a provider whose lexicon the
  operator has not shipped, or genuine provider mail saying something unrecognised.

A parse failure returns an outcome rather than raising, which is a deliberate difference from
`platform/intake.py` refusing a malformed webhook: a webhook sender can retry a 400, a delivered
message cannot be un-delivered, and raising here would stop the collector on the worst message in the
mailbox and lose every message behind it. The refusal still happens — it happens as a counted number.
"""
from dataclasses import dataclass
import datetime as dt
import email.utils

from local_observe.identity_mail import providers, rfc822, trust
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.log import get_logger

log = get_logger(__name__)

__all__ = ['CLASSIFICATIONS', 'ParseOutcome', 'SecurityAlert', 'parse_message', 'MAX_MESSAGE_AGE_SECONDS',
           'CLOCK_SKEW_SECONDS', 'MAX_IDENTITY_CHARS']

#: The exhaustive outcome set. The collector counts by these, and the coverage events the collector
#: emits are functions of those counts, so a fifth classification is a fan-out to `collector.py` and
#: `docs/units/identity-mail.md` in the same change.
CLASSIFICATIONS = ('event', 'untrusted', 'parse-failure', 'unsupported')

#: A message older than this is not a live alert. 400 days is generous on purpose: refusing a genuine
#: alert is a lost signal, accepting a years-old one as current is a false one, and a mailbox with an
#: old backlog is a migration event the operator should see as `date-out-of-range`, not as history.
MAX_MESSAGE_AGE_SECONDS = 400 * 86400

#: The same allowance `platform/state.py` grants a clock running ahead of the instant judging a message.
CLOCK_SKEW_SECONDS = 60

#: Ceiling on the raw `Message-ID` text used as the identity seed. Long enough for any real
#: provider's identifier, short enough that a 1 MiB `Message-ID` cannot slow identity derivation.
MAX_IDENTITY_CHARS = 256


@dataclass(frozen=True)
class SecurityAlert:
    """What a believed message says, in the closed vocabulary this feed is allowed to speak.

    Deliberately absent: the subject, the body, the sender's local part, the recipient's address, and
    every other string that came out of the mail. `account_hint` is a digest for exactly that reason —
    an operator can group findings by account without the address existing in an event, a trace or a
    model's context. `sender_domain` is not attacker text either: the gate only ever passes a domain
    that equalled one of the operator's allowlist entries, so the value is configuration echoed back.
    """
    provider: str
    alert_type: str
    occurred_at: str
    message_identity: str
    sender_domain: str
    account_hint: str | None
    level_count: int
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class ParseOutcome:
    """One message's verdict, its code, and the alert when there is one.

    `sender_hint` is the only field anywhere in this module that could resemble message content, and it
    is a sanitised, capped, lower-cased *domain-shaped* digest of nothing but the sender domain — the
    same `_name_hint` discipline `platform/intake.py` uses for an undeclared alert name. It is for the
    log line and the operator's triage; `events.py` never reads it.
    """
    classification: str
    code: str
    alert: SecurityAlert | None = None
    diagnostics: tuple[str, ...] = ()
    provider: str | None = None
    sender_hint: str = ''
    levels: int = 0
    bytes_read: int = 0

    def __post_init__(self) -> None:
        if self.classification not in CLASSIFICATIONS:
            raise ValueError('Unknown identity-mail classification')
        if (self.classification == 'event') != (self.alert is not None):
            raise ValueError('Only a classified alert may carry an alert, and it must')


def _hint(domain: str) -> str:
    """A loggable, bounded hint of a sender domain that no event may carry."""
    out: list[str] = []
    for character in domain.lower():
        if character.isalnum() or character in '.-':
            out.append(character)
        elif not out or out[-1] != '.':
            out.append('.')
    return ''.join(out)[:64].strip('.') or 'unnamed'


def _sender(node: rfc822.Node) -> tuple[str, str]:
    """`(domain, local-part)` of this node's single `From`, or a `parse-failure` refusal.

    Exactly one `From` is required at every level of a chain that is to be attested, because "which
    sender did the receiver verify?" has no honest answer when the message names two. The local part is
    returned only so the *recipient* hint can be built from the same shape, and it is discarded by the
    caller that does not need it.
    """
    values = node.values('from')
    if not values:
        raise _Refusal('missing-from')
    if len(values) > 1:
        raise _Refusal('duplicate-from')
    display, address = email.utils.parseaddr(_plain_field(values[0]))
    del display
    if '@' not in address:
        raise _Refusal('ambiguous-sender')
    local, _, domain = address.rpartition('@')
    folded = domain.strip().rstrip('.').lower()
    if not folded or not local.strip():
        raise _Refusal('ambiguous-sender')
    return folded, local.strip()


def _plain_field(value: str) -> str:
    """Accept a header value only in its plain form, for the fields that decide identity and dates.

    A value containing an RFC 2047 encoded-word (`=?utf-8?B?...?=`) is refused rather than decoded into
    an address or a date: base64 in the header that names who sent an alert is either a client bug or an
    encoding-trick probe, and a gate whose input depends on which decoder ran first is not a gate.
    Plain values pass through unchanged.
    """
    if '=?' in value:
        raise _Refusal('encoded-identity-header')
    return value


def _occurred_at(node: rfc822.Node, now: dt.datetime) -> dt.datetime:
    """The instant this message asserts it was sent, inside the window this feed will believe.

    A missing or duplicated `Date`, one with no timezone (`-0000` parses naive), one in the future past
    the skew allowance, or one older than `MAX_MESSAGE_AGE_SECONDS` is a refusal. The future bound
    matters most: the event window ends at this instant and `state.validate_event` refuses a window that
    runs ahead of the instant judging it, so a mail dated tomorrow would otherwise become an intake
    refusal two layers away from the message that caused it.
    """
    values = node.values('date')
    if not values:
        raise _Refusal('missing-date')
    if len(values) > 1:
        raise _Refusal('duplicate-date')
    try:
        parsed = email.utils.parsedate_to_datetime(_plain_field(values[0]))
    except (TypeError, ValueError):
        raise _Refusal('bad-date') from None
    if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _Refusal('date-without-timezone')
    moment = parsed.astimezone(dt.timezone.utc)
    if moment > now + dt.timedelta(seconds=CLOCK_SKEW_SECONDS):
        raise _Refusal('date-in-the-future')
    if (now - moment).total_seconds() > MAX_MESSAGE_AGE_SECONDS:
        raise _Refusal('date-out-of-range')
    return moment


def _message_identity(node: rfc822.Node) -> str:
    """The digest of this message's own `Message-ID`, for deduplication identity only.

    It is not an event identity (`events.py` derives that from the canonical window) and not a resource
    identity (nothing here claims one): it is the stable handle for "this exact alert mail", so a
    re-fetch of the same message is recognisable as the same message even when the mailbox renumbers
    it. A missing or duplicated `Message-ID` is refused — an identity that cannot be named cannot be
    deduplicated, and silently losing dedupe turns one alert into a burst.
    """
    values = node.values('message-id')
    if not values:
        raise _Refusal('missing-message-id')
    if len(values) > 1:
        raise _Refusal('duplicate-message-id')
    text = _plain_field(values[0]).strip()
    if not 1 <= len(text) <= MAX_IDENTITY_CHARS:
        raise _Refusal('unusable-message-id')
    return trust.sha256_text(text.encode('utf-8'))


def _recipient_hint(node: rfc822.Node) -> str | None:
    """The digest of this alert's first recipient, or `None` — never the address itself.

    Grouping findings by account needs something that is stable per account and useless to anybody who
    reads an event log without the address to begin with, which is exactly what a salted-by-nothing
    SHA-256 of the folded address is. Absent or undecodable recipients give `None` plus a diagnostic
    rather than a refusal: a mail with no `To:` (`Bcc:` delivery, a mailing-list rewrite) is still a
    genuine alert, and losing it would be the worse error.
    """
    for value in node.values('to'):
        try:
            _, address = email.utils.parseaddr(value)
        except (TypeError, ValueError):
            continue
        if '@' in address:
            return trust.sha256_text(address.strip().lower().encode('utf-8'))
    return None


class _Refusal(Exception):
    """Internal carrier for one fixed parse-failure code across the structural readers.

    Never escapes `parse_message`, which converts it into a counted `ParseOutcome`. The code is the whole
    payload: no offset, no field text, no fragment of the message.
    """

    def __init__(self, code: str) -> None:
        super().__init__(f'identity-mail read refused: {code}')
        self.code = code


class _Candidate:
    """One chain leaf and the structural facts read from it, kept private to this module."""

    def __init__(self, chain: tuple[rfc822.Node, ...], domain: str, local: str,
                 identity: str, occurred_at: dt.datetime) -> None:
        self.chain = chain
        self.domain = domain
        self.local = local
        self.identity = identity
        self.occurred_at = occurred_at

    @property
    def node(self) -> rfc822.Node:
        return self.chain[-1]

    @property
    def depth(self) -> int:
        return len(self.chain)


def _candidate_for(chain: tuple[rfc822.Node, ...], now: dt.datetime) -> _Candidate:
    """The structural facts of one chain, read from every level so a per-level verdict is meaningful.

    Every level must be attributable: a container whose `From` cannot be read cannot be the subject of a
    forwarder verdict either, so its failure is this candidate's failure.
    """
    node = chain[-1]
    domain, local = _sender(node)
    for container in chain[:-1]:
        _sender(container)
    return _Candidate(chain=chain, domain=domain, local=local, identity=_message_identity(node),
                      occurred_at=_occurred_at(node, now))


def _select(candidates: list[_Candidate], policy: trust.TrustPolicy) -> tuple[_Candidate, trust.ProviderTrust]:
    """The deepest candidate whose sender domain names a supported provider.

    Deepest wins because the forwarder's own `From` can also be a provider address (a mailbox on the
    same provider forwarding its alerts to another), and in that shape the *inner* message is the alert.
    Two provider-matching candidates at the same depth is a refusal: choosing one by list order would be
    this module inventing which of two provider messages the operator meant.
    """
    matched = [(item, policy.provider_for_sender(item.domain)) for item in candidates]
    matched = [(item, provider) for item, provider in matched if provider is not None]
    if not matched:
        raise _Refusal('sender-domain-unknown')
    deepest = max(item.depth for item, _ in matched)
    finalists = [(item, provider) for item, provider in matched if item.depth == deepest]
    if len(finalists) > 1:
        raise _Refusal('ambiguous-alert-message')
    return finalists[0]


def _levels(candidate: _Candidate) -> tuple[trust.Level, ...]:
    """One `trust.Level` per message in the chain, keyed by the digest of that level's own bytes."""
    levels: list[trust.Level] = []
    for node in candidate.chain:
        domain, _ = _sender(node)
        levels.append(trust.Level(digest_sha256=trust.sha256_text(node.raw), sender_domain=domain,
                                  header_auth_results=tuple(node.values('authentication-results'))))
    return tuple(levels)


def parse_message(raw: bytes, *, attestation: trust.Attestation | None, policy: trust.TrustPolicy,
                  now: dt.datetime) -> ParseOutcome:
    """Classify one fetched message. Never raises for message content; bounds and rules do the refusing.

    Args:
        raw: The fetched bytes, verbatim. The outer level's digest — and therefore the attestation that
            has to match it — is taken over exactly these bytes.
        attestation: The receiver's word for these bytes, or `None` when the collector boundary has no
            verifier. `None` is a normal production state, not an error, and it makes every message
            `untrusted` while the collector keeps running and keeps reporting coverage.
        policy: The operator's trust configuration.
        now: The instant judging the message; required, never defaulted, so the freshness and
            future-date bounds are testable at a fixed second.

    Returns:
        A `ParseOutcome` whose `classification` is one of `CLASSIFICATIONS` and whose `code` is one of
        the fixed codes listed in `docs/units/identity-mail.md`.
    """
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError('parse_message requires a timezone-aware now')
    if not isinstance(raw, bytes) or not raw:
        return ParseOutcome(classification='parse-failure', code='empty-message',
                            bytes_read=0 if not isinstance(raw, bytes) else len(raw))
    if len(raw) > rfc822.MAX_MESSAGE_BYTES:
        return ParseOutcome(classification='parse-failure', code='oversized-message', bytes_read=0)
    try:
        document = rfc822.read_message(raw)
        chains = list(document.chains)
        candidates = []
        failures: list[str] = []
        for chain in chains:
            try:
                candidates.append(_candidate_for(chain, now))
            except _Refusal as refusal:
                failures.append(refusal.code)
        if not candidates:
            if not failures:
                raise _Refusal('no-message-levels')
            ordered = sorted(set(failures), key=lambda code: (-failures.count(code), code))
            hint = _hint(_root_domain(document))
            depth = max(len(chain) for chain in chains)
            if set(failures) == {'sender-domain-unknown'}:
                # Nobody we support, not a broken read. Counting phishing and out-of-scope mail as a
                # parse failure would put junk volume on the monitor that exists to answer "is the feed
                # blind?", which is the one question that must keep a crisp signal.
                return ParseOutcome(classification='unsupported', code='sender-domain-unknown',
                                    sender_hint=hint, levels=depth, bytes_read=len(raw))
            return ParseOutcome(classification='parse-failure', code=ordered[0], sender_hint=hint,
                                levels=depth, bytes_read=len(raw))
        try:
            candidate, provider_trust = _select(candidates, policy)
        except _Refusal as refusal:
            if refusal.code != 'sender-domain-unknown':
                raise
            # A look-alike sender domain is the ordinary traffic of an identity mailbox exposed to the
            # internet. Counting it under `parse-failure` would bury "is the feed blind?" under "who is
            # mailing this?", so scope leaves as `unsupported` with the domain hint and no belief.
            return ParseOutcome(classification='unsupported', code=refusal.code,
                                sender_hint=_hint(candidates[0].domain), levels=candidates[0].depth,
                                bytes_read=len(raw))
        lexicon = providers.provider_named(provider_trust.name)
        if lexicon is None:
            return ParseOutcome(classification='unsupported', code='provider-not-supported',
                                provider=provider_trust.name, sender_hint=_hint(candidate.domain),
                                levels=candidate.depth, bytes_read=len(raw))
        assessment = trust.assess(attestation=attestation, policy=policy, levels=_levels(candidate),
                                 provider=provider_trust, now=now)
        diagnostics = tuple(dict.fromkeys(tuple(assessment.diagnostics) + tuple(failures)))
        if not assessment.trusted:
            log.warning('Identity mail is not attested; no content was read',
                        extra={'source': 'identity-mail', 'reason': assessment.code,
                               'provider': provider_trust.name, 'levels': candidate.depth})
            return ParseOutcome(classification='untrusted', code=assessment.code, diagnostics=diagnostics,
                                provider=provider_trust.name, sender_hint=_hint(candidate.domain),
                                levels=candidate.depth, bytes_read=len(raw))
        try:
            subject, texts, skipped = rfc822.collect_text(candidate.node)
        except rfc822.StructuralRefusal as refusal:
            return ParseOutcome(classification='parse-failure', code=refusal.code, provider=provider_trust.name,
                                sender_hint=_hint(candidate.domain), levels=candidate.depth,
                                bytes_read=len(raw))
        alert_type = lexicon.classify(subject, *texts)
        if alert_type is None:
            return ParseOutcome(classification='unsupported', code='alert-type-unrecognised',
                                diagnostics=diagnostics, provider=provider_trust.name,
                                sender_hint=_hint(candidate.domain), levels=candidate.depth,
                                bytes_read=len(raw))
        body_diagnostics = tuple(diagnostics) + (('text-read-truncated',) if skipped else ())
        alert = SecurityAlert(provider=provider_trust.name, alert_type=alert_type,
                             occurred_at=utc_text(candidate.occurred_at),
                             message_identity=candidate.identity, sender_domain=candidate.domain,
                             account_hint=_recipient_hint(candidate.node), level_count=candidate.depth,
                             diagnostics=body_diagnostics)
        return ParseOutcome(classification='event', code='classified', alert=alert,
                            diagnostics=body_diagnostics, provider=provider_trust.name,
                            sender_hint=_hint(candidate.domain), levels=candidate.depth,
                            bytes_read=len(raw))
    except _Refusal as refusal:
        return ParseOutcome(classification='parse-failure', code=refusal.code,
                            levels=0, bytes_read=len(raw))
    except rfc822.StructuralRefusal as refusal:
        return ParseOutcome(classification='parse-failure', code=refusal.code, bytes_read=len(raw))
    except trust.AttestationError:
        # A malformed attestation object is a boundary bug, and the safe reading of a boundary that
        # cannot describe what it verified is "nothing was verified" — the same answer as no attestation.
        log.warning('Identity-mail attestation was unusable; treating the message as unattested',
                    extra={'source': 'identity-mail', 'reason': 'attestation-unusable'})
        return ParseOutcome(classification='untrusted', code='attestation-unusable',
                            provider=None, sender_hint='', levels=0, bytes_read=len(raw))


def _root_domain(document: rfc822.Document) -> str:
    """The root's sender domain for a log hint, or a fixed placeholder when there is none.

    Used only when *no* candidate survived, where there is no candidate domain to name; the placeholder
    keeps the hint function total without inventing a domain.
    """
    try:
        return _sender(document.root)[0]
    except _Refusal:
        return 'absent'

"""Per-provider alert lexicons: which recognised identity event a trusted message is describing.

Two separate questions live apart on purpose:

* **Is it believed?** `trust.py`. A function of the receiver's attestation and the bytes. Nothing here
  participates, and nothing here is ever *asked* about an untrusted message — `parser.py`'s ordering
  refuses a message before a single character of its subject or body is read. That ordering is the
  reason a forged body cannot steer this feed: an attacker who wants a classification matched has to
  write it in mail that passes a DKIM gate they do not hold the key for.
* **What does it say?** This module. A closed list of substring rules per provider over normalised text,
  with declaration order as the tie-break, and a refusal (`alert-type-unrecognised`) when nothing
  matches — because "the provider mailed us something we do not parse" is coverage information, while a
  guessed type would be a security claim nobody made.

Google is the initial provider template. Every pattern is written against the *text* a plain
read of a Google account alert contains, and every fixture in `tests/test_identity_mail.py` uses RFC 2606
synthetic domains (`accounts.example`, `collector.example`), not the addresses in
`GOOGLE.trust`: those two lists are the operator's configuration surface and must be revalidated against
Google's published sender/DKIM domains before a live mailbox is pointed at this parser — the identity mail collector's
remaining acceptance item, which an offline source slice cannot close.

An empty allowlist in a policy trusts nothing; an empty lexicon matches nothing. Both are reachable by
configuration and both are loud: the collector reports `unsupported` counts, never silence.
"""
from dataclasses import dataclass

from local_observe.identity_mail.trust import ProviderTrust

__all__ = ['AlertRule', 'Provider', 'GOOGLE', 'PROVIDERS', 'provider_named', 'ALERT_TYPES',
           'MAX_PATTERNS_PER_RULE', 'MAX_PATTERN_CHARS']

#: The longest pattern this module will accept, and the count ceiling per rule. Patterns are operator
#: review surface: a rule set that grows past these bounds is a body of text matching somebody cannot
#: audit, which is how an alert feed starts believing marketing mail.
MAX_PATTERN_CHARS = 96
MAX_PATTERNS_PER_RULE = 8

#: The closed alert vocabulary this feed can emit. Adding a name here is the same kind of change as
#: adding an event kind: the reasoning layer, the docs and the dashboards all name these strings, and a
#: type that appears in one place only is a type that goes unjudged.
ALERT_TYPES = ('signin-new-device', 'signin-failed', 'signin-recent-activity', 'password-changed',
               'recovery-info-changed', 'two-step-changed', 'session-revoked', 'account-deletion-requested',
               'security-alert')


@dataclass(frozen=True)
class AlertRule:
    """One alert type and the phrases that name it. Any pattern matching is enough; ordering is decided
    by the provider's rule list, most specific first, so a "failed sign-in" mail does not land in the
    generic `security-alert` bucket merely because it also says "security alert".
    """
    alert_type: str
    patterns: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.alert_type not in ALERT_TYPES:
            raise ValueError(f'Unknown identity alert type {self.alert_type}')
        if not isinstance(self.patterns, tuple) or not 1 <= len(self.patterns) <= MAX_PATTERNS_PER_RULE:
            raise ValueError('An alert rule must carry between 1 and '
                             f'{MAX_PATTERNS_PER_RULE} patterns')
        for pattern in self.patterns:
            if not isinstance(pattern, str) or not 3 <= len(pattern) <= MAX_PATTERN_CHARS:
                raise ValueError('An alert pattern must be a bounded lowercase phrase')
            if pattern != pattern.lower():
                raise ValueError('An alert pattern must already be lowercase')


@dataclass(frozen=True)
class Provider:
    """A provider's trust facts and its lexicon, in one row.

    `trust` is what the operator may configure (domains); `rules` is code under review. A policy that
    names a provider with no lexicon here is refused by `parser.py` as `provider-not-supported` rather
    than parsed by guesswork — configuring a domain never invents vocabulary for it.
    """
    name: str
    trust: ProviderTrust
    rules: tuple[AlertRule, ...]

    def classify(self, *texts: str) -> str | None:
        """The alert type these texts describe, or `None` when this provider's rules name none of them.

        Case-folded and whitespace-normalised before matching, because the same sentence arrives with
        different line wrapping through different MTAs. No regular expressions: a substring list is
        reviewable line by line, and a regex in a lexicon is one more way for a clever pattern to match
        something nobody meant to trust.
        """
        haystack = ' '.join(' '.join(text.split()).lower() for text in texts if text)
        if not haystack:
            return None
        for rule in self.rules:
            if any(pattern in haystack for pattern in rule.patterns):
                return rule.alert_type
        return None


GOOGLE = Provider(
    name='google',
    trust=ProviderTrust(
        name='google',
        sender_domains=('accounts.google.com', 'googlemail.com'),
        dkim_domains=('accounts.google.com', 'google.com'),
    ),
    rules=(
        AlertRule('signin-failed', ('failed sign-in attempt', 'failed sign-in', 'sign-in was blocked',
                                    'rejected sign-in attempt')),
        AlertRule('signin-new-device', ('a new device signed in to your google account',
                                        'new sign-in on your google account',
                                        'a new sign-in on your google account',
                                        'signed in to your google account',
                                        'new sign-in to your google account')),
        AlertRule('session-revoked', ('all sign-in sessions have been revoked',
                                      'signed out of all sessions', 'sessions have been revoked')),
        AlertRule('password-changed', ('your google account password was changed',
                                       'password was changed', 'password for your google account')),
        AlertRule('two-step-changed', ('2-step verification was turned off',
                                       '2-step verification was turned on',
                                       'two-step verification was changed',
                                       'passkeys were added to your google account')),
        AlertRule('recovery-info-changed', ('recovery email was added', 'recovery phone was added',
                                           'recovery email address was changed',
                                           'recovery information was changed',
                                           'recovery phone number was changed')),
        AlertRule('account-deletion-requested', ('your google account is being deleted',
                                                 'we will start to delete your google account',
                                                 'deletion of your google account')),
        AlertRule('signin-recent-activity', ('someone may have tried to sign in',
                                             'unusual activity on your google account',
                                             'activity on your google account')),
        AlertRule('security-alert', ('security alert', 'security advice', 'important security warning')),
    ),
)

#: The shipped providers, in lookup order. Google only, per the card; a second provider is a reviewed
#: row here plus its trust domains in the operator's policy, and nothing else in this package changes.
PROVIDERS = (GOOGLE,)


def provider_named(name: str) -> Provider | None:
    """The lexicon for a provider name the policy used, or `None` when no reviewed lexicon exists."""
    for provider in PROVIDERS:
        if provider.name == name:
            return provider
    return None

"""Identity-alert mail: a bounded Google parser behind a receiver's attestation, and the collector on it.

The identity mail collector's slice of the identity-security feed. Three facts decide the shape of this package, and
each
one is a refusal of something easier:

* **A mail header cannot grant trust.** `Authentication-Results` is text a sender or a relayer can
  write, so belief comes only from an `trust.Attestation` handed over *beside* the message, by a
  receiving agent the operator named, bound to the `sha256` of each message level's bytes. No verdict
  without that, in either direction: no event, and no exception path in this package for taking one.
* **Reading a mailbox is not the same as verifying mail.** IMAP returns the message and its headers; it
  publishes no receiver verdict this unit could treat as one. `trust.TRUSTED_CHANNELS` is closed
  precisely so "I read it off the header" has no spelling here. What a deployment must provide is
  documented in `docs/units/identity-mail.md`, including the fact that no live collection has happened
  and that Google's own sender/DKIM domain list is an open acceptance item.
* **Mail content stops at the classifier.** Untrusted messages are refused before their subject or body
  is read; classified alerts leave as canonical events carrying a rule id, a bounded window and a
  `source-heartbeat` evidence reference — no subject, no address, no body. `account_hint` is a digest.

Read in this order: `rfc822.py` (what can be read at all, and which bytes each level is), `trust.py`
(what may be believed about those bytes), `providers.py` (what a believed message says), `parser.py`
(the ordering above, as one function), `events.py` (the product boundary), `collector.py` (the schedule,
the cursor and the coverage numbers). `tests/test_identity_mail.py` is the executable version of the
same list, and `docs/units/identity-mail.md` is the operator-facing one.

Nothing here authenticates, connects, reads a credential, or starts a service; the seams are injected
and the tests are offline. No new dependency, and `platform/intake.py` and `local_observe/store/` are
unchanged by this slice — see the fan-out note at the bottom of the unit doc.
"""
from local_observe.identity_mail import collector, events, parser, providers, rfc822, trust
from local_observe.identity_mail.collector import (CollectorError, EventSink, FetchedMessage, MailSource,
                                                   Report, collect)
from local_observe.identity_mail.events import SOURCE, Batch, coverage_event, events_for, prepared
from local_observe.identity_mail.parser import CLASSIFICATIONS, ParseOutcome, SecurityAlert, parse_message
from local_observe.identity_mail.trust import (Assessment, Attestation, AttestationError, Level,
                                              LevelAttestation, TrustPolicy, assess,
                                              policy_from_document, sha256_text)

__all__ = ['Attestation', 'AttestationError', 'Assessment', 'Batch', 'CLASSIFICATIONS', 'CollectorError',
           'EventSink', 'FetchedMessage', 'Level', 'LevelAttestation', 'MailSource', 'ParseOutcome',
           'Report', 'SecurityAlert', 'SOURCE', 'TrustPolicy', 'assess', 'collector', 'collect',
           'coverage_event', 'events', 'events_for', 'parse_message', 'parser', 'policy_from_document',
           'prepared', 'providers', 'rfc822', 'sha256_text', 'trust']

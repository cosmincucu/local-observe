"""The product boundary: a believed alert becomes the canonical events `Store.intake` already admits.

Built with `platform/detections.py`'s own `event` factory and nothing else, so the rows this feed files
are the same shape every other producer files — the same fourteen fields, the same canonical window
rule, the same evidence-reference contract, the same `rule_id`/`rule_version`/`condition` identity. A
producer that invents its own event shape is a producer whose events the readers, the incident logic and
the dashboards have all to learn separately.

Two choices are worth the reading, because both are places a later change could quietly go wrong:

**Windows run backwards from the message, not forwards from the tick.** A finding's window is
`[occurred_at - window_seconds, occurred_at]`, where `occurred_at` is the instant the *provider* dated
the alert. `state.validate_event` refuses a window ending more than 60 s ahead of the instant judging it,
so the forward form (`occurred_at .. occurred_at + 60`) is refused for any alert less than a minute old
— which is every alert that matters. Backwards is also the honest claim: an alert is a statement about
the moment it was sent, and the collector's own clock is not part of that statement. The same property
makes the event's bytes a pure function of the message, so re-reading the same mailbox message re-files
the same row (`accepted` → `duplicate`) instead of the `Event retry changed contents` 400 that a
clock-dependent identity produces — the exact defect `intake.retry_identity` documents for webhook alerts.

**Evidence is `source-heartbeat`, and no number is invented for it.** `Store.put_evidence` keeps a
boolean or a number, and a sign-in alert has neither: there is no reading to reference, only the
platform's own receipt that this attested message arrived. That is the same reference `intake` uses for
a verdict whose payload carried nothing keepable, and the same one `detections.evaluate` uses for
coverage. The consequence is stated plainly in `docs/units/identity-mail.md`: a finding from this feed
proves *the collector received and believed this mail*, and the collector's own coverage events are what
make that claim checkable. Manufacturing a `1` sample to satisfy a schema would be a synthesised
reference, which `docs/CONTRACTS.md` §6 refuses by name.

No severity is mapped either. Every firing finding takes the factory's `warning` and every resolved one
`info`; how loud "your password changed" is compared to "a new device signed in" is an operator policy
question, and the first version of a feed should not answer it by hardcoding a rung nobody voted on.
"""
from dataclasses import dataclass
import datetime as dt
from typing import Any

from local_observe.identity_mail import parser
from local_observe.platform import detections
from local_observe.platform.intake import Prepared
from local_observe.platform.state import StateError, validate_event

__all__ = ['SOURCE', 'SOURCE_COVERAGE_RULE', 'PARSE_COVERAGE_RULE', 'UNTRUSTED_COVERAGE_RULE',
           'COVERAGE_RULES', 'MAX_BATCH_EVENTS', 'rule_for', 'window_for', 'events_for',
           'coverage_event', 'prepared', 'Batch', 'validate']

#: The event `source` for this feed, and the name an intake rule document or a reader filter uses to
#: talk about it. Dots and hyphens only, because `state.label` is what refuses anything else.
SOURCE = 'identity-mail'

#: The three coverage rules this feed owns about *itself*. All are fixed strings, never derived from a
#: message, a provider name or a subject: identity that moves when mail moves is the defect
#: `docs/CONTRACTS.md` §4 refuses. They keep separate condition keys so a read gap can never mask a
#: source gap, a trust gap, or be masked by either.
SOURCE_COVERAGE_RULE = 'identity-mail.source.coverage'
PARSE_COVERAGE_RULE = 'identity-mail.parse-failure.coverage'

#: The third one, and why it is `coverage` and not `security`: mail that failed the gate is not a
#: statement about anybody's account, it is a statement about the feed — "something that looked like a
#: provider alert arrived and could not be believed". Filing it as a security finding is exactly the
#: mistake the gate exists to prevent (an attacker choosing what this feed reports), while dropping it
#: lets a forgery campaign look like a quiet mailbox. Coverage is the honest kind, and its own condition
#: key means a trust gap cannot mask, or be masked by, a read gap or a source gap.
UNTRUSTED_COVERAGE_RULE = 'identity-mail.untrusted.coverage'

COVERAGE_RULES = (SOURCE_COVERAGE_RULE, PARSE_COVERAGE_RULE, UNTRUSTED_COVERAGE_RULE)

#: Events one delivered batch may carry. The bound exists because the batch is written to the cursor
#: before it is delivered, and an unbounded batch is an unbounded state file — plus a sink failure with
#: a thousand events in flight replays all of them.
MAX_BATCH_EVENTS = 64

#: The rule-version string for every rule this producer emits. One producer, one version: a bump means
#: the mapping below changed, and old events keep their own version so a condition never silently
#: changes identity under an incident.
RULE_VERSION = '1'


@dataclass(frozen=True)
class Batch:
    """One collector batch: the events, in admission order, and how many findings of them were verdicts.

    `samples` is always empty and is kept in the shape anyway, because the transport rule this product
    lives by — `Store.put_evidence` for every sample before the event that references it — is stated
    once, in the platform, and a producer that omits the field is a producer a reader has to remember.
    """
    observed_at: str
    events: tuple[dict[str, Any], ...]
    samples: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.samples, tuple) or self.samples:
            raise StateError('Identity-mail batches reference no captured samples; see the module note')
        if not 1 <= len(self.events) <= MAX_BATCH_EVENTS:
            raise StateError(f'Identity-mail batch must hold 1..{MAX_BATCH_EVENTS} events')


def rule_for(alert: parser.SecurityAlert) -> str:
    """The rule id for one alert type: `<provider>.<alert-type>`.

    Derived from two closed vocabularies (`providers.PROVIDERS` names, `providers.ALERT_TYPES` names),
    so the set of rule ids this producer can emit is enumerable from the source and a rule id can never
    contain a subject, an address or a domain a sender chose.

    Raises:
        StateError: The alert names a provider or type outside those vocabularies — a hand-built
            `SecurityAlert`, which is the only way to reach this.
    """
    from local_observe.identity_mail import providers

    if alert.alert_type not in providers.ALERT_TYPES or providers.provider_named(alert.provider) is None:
        raise StateError('Identity alert names a provider or type outside the shipped vocabularies')
    return f'{alert.provider}.{alert.alert_type}'


def window_for(*, end: dt.datetime, seconds: int) -> dict[str, str]:
    """The bounded window ending at `end`, as the canonical text pair."""
    from local_observe.inventory.validation import utc_text

    if not isinstance(seconds, int) or isinstance(seconds, bool) or not 60 <= seconds <= 86400:
        raise StateError('Identity-mail window_seconds must be an integer 60..86400')
    return {'start': utc_text(end - dt.timedelta(seconds=seconds)), 'end': utc_text(end)}


def events_for(alert: parser.SecurityAlert, *, window_seconds: int = 60,
               resource_id: str | None = None) -> tuple[dict[str, Any], ...]:
    """The one canonical event a believed alert files, ready for `POST /v1/events`.

    `resource_id` stays `None` unless the caller resolves the *monitoring account* to an inventory
    resource — and it cannot be resolved here, because this feed has no host, address or name to ask the
    inventory about. An alert about an account is not an alert about a machine, and inventing a link (or
    deriving a UUID from an address digest) is the identity invention `intake`'s rule 2 refuses. The
    parameter exists so the integration slice can pass a declared resource for the mailbox once the
    inventory grows a resource kind that means "identity account"; until then `None` is the honest value.

    No coverage pair accompanies it: `detections.evaluate` emits coverage *before* a finding because a
    detector may have been unable to judge, and this producer's equivalent statement — "the feed could
    not read what arrived" — is `PARSE_COVERAGE_RULE`/`SOURCE_COVERAGE_RULE`, emitted once per collector
    batch by `collector.py` rather than once per message.
    """
    end = _moment(alert.occurred_at)
    built = detections.event(SOURCE, resource_id, rule_for(alert), 'security', 'firing',
                             window_for(end=end, seconds=window_seconds),
                             {'rule_id': rule_for(alert)}, query_type='source-heartbeat',
                             observed_at=alert.occurred_at, version=RULE_VERSION)
    return (built,)


def coverage_event(rule_id: str, *, firing: bool, now: dt.datetime, window_seconds: int = 300,
                   resource_id: str | None = None) -> dict[str, Any]:
    """A statement about this feed itself: `firing` means the feed was not whole during that span.

    `window_seconds` is the *span claimed* (how long a verdict must have been bad to be worth reading),
    and the window's end is this tick's own instant, floored to the second — it is deliberately not
    floored to a `window_seconds` bucket, because the bucket is what the store keys on:
    `Store.intake` identifies an event by `source` + `source_event_id`, and `detections.event` derives
    `source_event_id` from `[rule_id, rule_version, resource_id, window]`. The `status` is not in that
    list, so a `firing` coverage event and the `resolved` event that replaces it inside one bucketed
    window are the *same event* to the store — and the second one arrives as
    `Event retry changed contents`, a 400 that refuses the whole batch. `collector.collect` persists the
    batch as pending before it reaches the sink and replays it until it is accepted, so that refusal is
    not a dropped row: it is a wedged feed, a frozen cursor and no further coverage at all — the failure
    direction the coverage rules exist to avoid. `validate_event` cannot see this, because each event
    taken alone is valid; only the pair is not.

    What survives the change is the property that actually mattered: the same verdict evaluated at the
    same instant is byte-identical, so a replayed batch answers `duplicate` (`collector._replay` depends
    on exactly this), and a verdict that changes at a later tick carries a strictly later window end —
    which is what `conditions.watermark` is for, and the reason `detections.evaluate` floors to its own
    evaluation window rather than to a span wider than its tick.
    """
    if rule_id not in COVERAGE_RULES:
        raise StateError('Identity-mail coverage rule is not one this producer owns')
    end = dt.datetime.fromtimestamp(int(now.timestamp()), dt.timezone.utc)
    return detections.event(SOURCE, resource_id, rule_id, 'coverage', 'firing' if firing else 'resolved',
                            window_for(end=end, seconds=window_seconds), {'rule_id': rule_id},
                            query_type='source-heartbeat', version=RULE_VERSION)


def prepared(events: tuple[dict[str, Any], ...] | list[dict[str, Any]]) -> list[Prepared]:
    """The `intake.Prepared` shape a transport uses: event, sample-first ordering, link status.

    `link` is `not_configured` for every row here because there was no name to resolve — the same status
    `intake.Links` reports when no index was configured, and the reason this feed's events travel with a
    visible "unlinked" answer rather than a silent null. `resource_id` is what makes it non-null.
    """
    return [Prepared(event, None, 'not_configured') for event in events]


def validate(batch: Batch, now: dt.datetime) -> None:
    """Run every event in a batch through the store's own validator before anything posts it.

    Who calls it: the transport slice, not this one. `collector.collect` writes the batch to the cursor
    as pending and hands it to `EventSink.admit` without calling this — a stub sink accepts anything — so
    the integration that posts `/v1/evidence` and `/v1/events` must call it before its first request.
    Not paranoia: the alternative is discovering at the sink that a mapping produced a window the state
    layer refuses, after the cursor recorded the batch as delivered. `Store.intake` would answer 400 and
    the batch would sit in `pending`, replayed forever.

    What it cannot catch, and the caller must not read as safety: a batch of individually-valid events
    that the store still refuses because two of them collide on `source_event_id` (see
    `coverage_event`). That is a property of the *pair*, and only `Store.intake` judges it.

    Raises:
        StateError: The store would refuse an event. The inventory layer's own `InvalidInventory` (a
            window it cannot read as an instant) is mapped into this one sentence rather than escaping as
            a foreign type: `platform/api.py` classifies anything outside the platform's own sentences as
            a server-side fault, and a producer's bad mapping is not one.
    """
    from local_observe.inventory.validation import InvalidInventory

    for event in batch.events:
        try:
            validate_event(event, now)
        except InvalidInventory as exc:
            raise StateError('Identity-mail event carries an instant the store cannot read') from exc


def _moment(text: str) -> dt.datetime:
    """The alert's instant as an aware datetime. `parser` produced it, so a failure here is corruption."""
    from local_observe.inventory.validation import timestamp

    return timestamp(text)

"""The scheduled collector: bounded reads, a cursor that survives a failed sink, coverage that answers.

Three abstractions, and none of them is a mailbox:

* `MailSource` — the transport seam: `list_uids` / `fetch` / `mailbox_generation`. A real provider
  implementation lives outside this package, and what it must add to a plain fetch is the
  `trust.Attestation` for the bytes it returned. A source that cannot produce one returns `None`, the
  whole feed becomes `untrusted` counts, and that is the *correct* outcome — which is why
  `docs/units/identity-mail.md` spends its length on where an attestation can legitimately come from.
* `EventSink` — the delivery seam: `admit(batch)` accepts the whole batch or raises. Nothing here
  retries, sleeps or partially applies: the retry policy is the cursor, and the cursor is one file.
* `Report` — what the tick knew. Counts per classification, whether the tick could finish reading,
  whether the mailbox went quiet, and the coverage events that carry those answers into the product.

Why the cursor is written *before* the sink is called, and what makes that safe: the batch is a pure
function of the messages (`events.py`: windows come from the mail's own `Date`, never from the tick), so
re-delivering after a crash or a refused POST either folds into the row already stored (`duplicate`) or
files the event that was lost. The cursor advances at the one commit point after a successful `admit`, so
a sink that fails costs a re-read and never costs a verdict. `platform/cert_worker.py` already runs this
shape; a second way to sequence the same two steps would be two ways to lose a verdict differently.

So the pending entry is not only a batch: it is the whole *commit intent* of the read that produced it —
the cursor position that read reached, the mailbox generation it saw (as a digest), its tally, and
whether that read completed at all. A replay commits exactly that intent, stamped with the observation
time carried inside the batch, so a re-delivery lands the same source/cursor transition a first delivery
would have landed, and a replay of a read that never completed lands nothing. Delivery retry time never
enters the cursor: it says when the sink was asked again, not when the mailbox was read, and confusing
the two is how a permanently refused POST keeps a dead feed looking fresh.

Bounds, and what turning each down costs:

* `max_messages` (1..32 per tick) — the listing is capped at it, so a full page is reported as
  `backlog`: more may be waiting, nothing was skipped, and the cursor did not move past unread mail.
  Lower means more ticks to drain a backlog, never a silent gap.
* `max_message_bytes` — a bigger message is *not parsed* and counts as `parse-failure/oversized-message`.
  Reading a prefix would be a verdict about half a message.
* `max_tick_bytes` — the cumulative read budget. Over it the tick stops with `truncated`, and the unread
  messages keep their place because the cursor did not advance past them.
* `coverage_window_seconds` / `max_silence_seconds` — the floor on "how long is too long to hear
  nothing". Zero alerts and a dead collector look identical from outside; this is the number that says
  which one the operator is willing to accept, and silence past it fires source coverage rather than
  reading as all clear.
"""
from contextlib import ExitStack
from dataclasses import dataclass
import datetime as dt
import json
import os
import pathlib
import tempfile
from typing import Any

from local_observe.identity_mail import events, parser, trust
from local_observe.inventory.validation import canonical, digest, timestamp, utc_text
from local_observe.log import get_logger
from local_observe.platform.owner import exclusive_owner
from local_observe.platform.state import label

log = get_logger(__name__)

__all__ = ['CollectorError', 'FetchedMessage', 'MailSource', 'EventSink', 'Report', 'settings',
           'load_state', 'save_state', 'collect', 'STATUS_KINDS', 'CONFIG_ENVIRONMENT',
           'MAX_CURSOR_BYTES', 'MAX_MESSAGES_PER_TICK']

#: The cursor ceiling. It holds a fingerprint, five counters and one batch, so exceeding it means a
#: caller passed a configuration with an absurd bound; refusing beats growing a state file under a worker.
MAX_CURSOR_BYTES = 131072

#: Hard ceilings behind the operator's own bounds, so no configuration asks for more work per tick than
#: this slice was reviewed for: 32 messages, 32 findings plus 3 coverage events inside the 64-event batch
#: bound `events.py` enforces.
MAX_MESSAGES_PER_TICK = 32
MAX_MESSAGE_BYTES = 262144
MAX_TICK_BYTES = 8388608

STATUS_KINDS = ('idle', 'delivered', 'replayed', 'sink-failed', 'transport-failed')

_TALLY_FIELDS = ('fetched', 'findings', 'untrusted', 'parse_failures', 'unsupported')

_CONFIG_REQUIRED = {'schema_version', 'source', 'cursor_path', 'interval_seconds', 'max_messages',
                    'max_message_bytes', 'max_tick_bytes', 'coverage_window_seconds',
                    'max_silence_seconds', 'finding_window_seconds', 'policy'}

#: The environment variable naming the collector's JSON configuration file. Unset or blank is the
#: documented off switch for an optional feed, and off-by-default is the identity-alert feed decision: the identity feed
#: is an optional `full`-profile module, not a core service. `main()` is out of scope for this slice;
#: the variable is declared here so the integration fan-out has one name to wire.
CONFIG_ENVIRONMENT = 'LO_IDENTITY_MAIL_CONFIG'


class CollectorError(ValueError):
    """A configuration, cursor or protocol answer this collector may not act on. Fixed sentences only."""


def _refuse(what: str) -> None:
    raise CollectorError(f'Identity-mail collector refused {what}')


@dataclass(frozen=True)
class FetchedMessage:
    """One message as the transport returned it, plus whatever a receiver attests about those bytes.

    `attestation` may be `None`, and `None` is not an error: it is the shape of "this deployment has no
    verifier", whose honest output is an `untrusted` count rather than a belief.
    """
    uid: int
    raw: bytes
    attestation: trust.Attestation | None

    def __post_init__(self) -> None:
        if not isinstance(self.uid, int) or isinstance(self.uid, bool) or self.uid < 1:
            _refuse('a message identifier that is not a positive integer')
        if not isinstance(self.raw, bytes) or not self.raw:
            _refuse('a fetched message with no bytes')
        if self.attestation is not None and not isinstance(self.attestation, trust.Attestation):
            _refuse('an attestation that is not an Attestation')


class MailSource:
    """What the collector asks a mailbox. Subclass it for a real provider; never import one here.

    Implementations must return `raw` verbatim as the provider stores it. A transport that normalises
    line endings, re-wraps headers or re-encodes a body on the way through has changed the bytes, and the
    gate then answers `attestation-binding-mismatch` for every message — a loud failure, and the only
    one that cannot end in believing the wrong thing.
    """

    def list_uids(self, *, after: int | None, limit: int) -> tuple[int, ...]:
        """Up to `limit` identifiers newer than `after`, ascending. Reads no message body."""
        raise NotImplementedError

    def fetch(self, uid: int) -> FetchedMessage:
        """One message by identifier, with its attestation when the boundary can produce one."""
        raise NotImplementedError

    def mailbox_generation(self) -> str:
        """An opaque token naming the mailbox instance these identifiers belong to.

        For IMAP this is `UIDVALIDITY`. Only its digest is ever stored, so no provider text lands in the
        cursor; a change means the identifiers now mean something else, and the collector restarts its
        cursor and fires coverage instead of silently skipping or silently re-reading everything.
        """
        raise NotImplementedError


class EventSink:
    """The delivery target — in production the platform's `/v1/evidence` then `/v1/events` front door."""

    def admit(self, batch: events.Batch) -> None:
        """Accept every event in the batch, or raise. Partial acceptance is the caller's bug."""
        raise NotImplementedError


@dataclass(frozen=True)
class Report:
    """One tick's knowledge, plus the coverage events that make it auditable afterwards.

    The counts are the monitored surface: `parse_failures` is the card's "monitored parse failures",
    `untrusted` is the gate doing its work, and `coverage` names which coverage verdicts are firing.
    `reasons` carries fixed codes and exception class names only — never provider text, never mail text.
    """
    status: str
    fetched: int
    findings: int
    untrusted: int
    parse_failures: int
    unsupported: int
    bytes_read: int
    truncated: bool
    backlog: bool
    stale: bool
    uid_regression: bool
    mailbox_reset: bool
    silence_seconds: int | None
    last_success_at: str | None
    coverage: tuple[str, ...]
    reasons: tuple[str, ...]
    batch: events.Batch | None

    def __post_init__(self) -> None:
        if self.status not in STATUS_KINDS:
            raise CollectorError('Unknown collector status')

    @property
    def parse_failure_ratio(self) -> float:
        """Parse failures over messages read — the number a monitor can alert on.

        `fetched == 0` yields `0.0`, and that zero is deliberately *not* all clear: with nothing read,
        the answer to "is the feed healthy?" is `stale` and `silence_seconds`. A ratio presented as
        health is how a blind feed passes a threshold check.
        """
        if not self.fetched:
            return 0.0
        return round(self.parse_failures / self.fetched, 4)


# --------------------------------------------------------------------------- configuration


def settings(document: Any) -> dict[str, Any]:
    """Validate one collector configuration document; unknown keys refused, defaults resolved.

    The trust policy is validated here rather than at first use, so a typo in an allowlist fails at
    startup instead of at 3 a.m. on the one message that mattered. `policy_fingerprint` is the one
    derived key a caller may hand back in, which makes this function idempotent on its own output: the
    worker's validated configuration is a legal input, and a stale fingerprint (a policy edited under the
    same file) is refused rather than recomputed away.

    Raises:
        CollectorError: Any field is missing, unknown, out of bound, or not what its name claims.
    """
    if (not isinstance(document, dict) or not _CONFIG_REQUIRED <= set(document)
            or set(document) - _CONFIG_REQUIRED - {'policy_fingerprint'}):
        _refuse('a configuration with missing or unknown fields')
    result: dict[str, Any] = dict(document)
    if result['schema_version'] != 1:
        _refuse('an unsupported collector schema version')
    label(result['source'])
    if result['source'] != events.SOURCE:
        _refuse('a source this producer does not emit')
    cursor = result['cursor_path']
    if (not isinstance(cursor, str) or not cursor or '\0' in cursor
            or not pathlib.Path(cursor).is_absolute()):
        _refuse('a cursor path that is not an absolute path')
    for name, low, high in (('interval_seconds', 5, 86400),
                            ('max_messages', 1, MAX_MESSAGES_PER_TICK),
                            ('max_message_bytes', 1024, MAX_MESSAGE_BYTES),
                            ('max_tick_bytes', 4096, MAX_TICK_BYTES),
                            ('coverage_window_seconds', 60, 86400),
                            ('max_silence_seconds', 120, 30 * 86400),
                            ('finding_window_seconds', 60, 86400)):
        value = result[name]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            _refuse(f'{name} outside {low}..{high}')
    if result['max_tick_bytes'] < result['max_message_bytes']:
        _refuse('a tick budget smaller than one allowed message')
    document_policy = result['policy']
    # A validated `TrustPolicy` is accepted back as-is, so `settings(settings(config))` is idempotent.
    try:
        policy = (document_policy if isinstance(document_policy, trust.TrustPolicy)
                  else trust.policy_from_document(document_policy))
    except trust.AttestationError:
        # One refusal type at this module's edge. A policy the gate cannot use is a collector
        # configuration failure from the operator's point of view, and "which exception do I catch for a
        # bad config file?" should not depend on which layer of the trust module noticed.
        _refuse('a trust policy this gate cannot use')
    result['policy'] = policy
    result['policy_fingerprint'] = trust.policy_fingerprint(policy)
    if document.get('policy_fingerprint') not in (None, result['policy_fingerprint']):
        _refuse('a configuration whose policy fingerprint no longer matches its policy')
    return result


def _fingerprint(chosen: dict[str, Any]) -> str:
    """The cursor's pin for one exact configuration, the policy object and its digest included.

    A cursor is only meaningful for the settings that wrote it, so the digest covers every bound that
    decides what was read and which trust policy believed it. The policy enters as its fingerprint
    because a dataclass is not canonical JSON and two documents that validate identically must not look
    like a configuration change.
    """
    view = {name: value for name, value in chosen.items() if name != 'policy'}
    view['policy'] = chosen['policy_fingerprint']
    return digest(view)


def _fresh(settings: dict[str, Any]) -> dict[str, Any]:
    """A cursor for a mailbox this collector has never read."""
    window = dict.fromkeys(_TALLY_FIELDS, 0)
    window['started_at'] = None
    return {'schema_version': 1, 'configuration': _fingerprint(settings), 'generation_digest': None,
            'last_uid': None, 'last_success_at': None, 'pending': None, 'window': window}


def _tally(value: Any) -> dict[str, int]:
    """Five non-negative counters, or a refusal. `None` anywhere is a refusal, not a zero."""
    if not isinstance(value, dict) or set(value) != set(_TALLY_FIELDS):
        _refuse('a batch tally')
    tally: dict[str, int] = {}
    for name in _TALLY_FIELDS:
        item = value[name]
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 100000:
            _refuse('a batch tally counter')
        tally[name] = item
    return tally


def _batch(document: Any) -> events.Batch:
    """Rebuild a batch from the cursor, refusing anything the factory would not have written."""
    if (not isinstance(document, dict) or set(document) != {'observed_at', 'events', 'samples'}
            or not isinstance(document['events'], list) or document['samples'] != []
            or not 1 <= len(document['events']) <= events.MAX_BATCH_EVENTS):
        _refuse('a stored batch shape')
    timestamp(document['observed_at'])
    for event in document['events']:
        if not isinstance(event, dict) or event.get('source') != events.SOURCE:
            _refuse('a stored batch event')
    return events.Batch(observed_at=document['observed_at'], events=tuple(document['events']),
                        samples=())


def batch_json(batch: events.Batch) -> dict[str, Any]:
    """The cursor's JSON form of a batch. `_batch` is its inverse, and the two are pinned against each other."""
    return {'observed_at': batch.observed_at, 'events': [dict(event) for event in batch.events],
            'samples': [dict(sample) for sample in batch.samples]}


#: The pending record's fields. `fingerprint` pins every other one, so the commit intent — cursor
#: position, generation, tally and the read verdict — cannot be edited under a still-valid hash.
_PENDING_FIELDS = frozenset({'batch', 'fingerprint', 'through_uid', 'tally', 'generation_digest',
                             'source_read'})


def _pending_intent(pending: dict[str, Any]) -> dict[str, Any]:
    """What a pending record promises to commit, which is everything in it but its own fingerprint."""
    return {name: value for name, value in pending.items() if name != 'fingerprint'}


def _pending_record(*, batch: events.Batch, through_uid: int | None, tally: dict[str, int],
                    generation: str, source_read: bool) -> dict[str, Any]:
    """Build the cursor's pending record: the batch plus the source facts it was read under.

    `generation_digest` is `None` when the tick never got a generation answer, and `source_read` is
    `False` when the tick never got a listing. Both are needed because the batch alone does not say
    whether replaying it may move the cursor: coverage events filed by a failed read must be deliverable,
    but they must not be delivered *as* a completed read.
    """
    record: dict[str, Any] = {'batch': batch_json(batch), 'through_uid': through_uid,
                              'tally': dict(tally),
                              'generation_digest': digest([generation]) if generation else None,
                              'source_read': source_read}
    record['fingerprint'] = digest(_pending_intent(record))
    return record


def load_state(settings: dict[str, Any]) -> dict[str, Any]:
    """The cursor, validated against this exact configuration — or a fresh one when none exists.

    A cursor written under a different configuration is refused rather than adopted: `max_messages` or a
    trust policy changing mid-flight is precisely when a pending batch must not be delivered under the
    new rules, so the operator is told to look and the file stays put for inspection.

    Raises:
        CollectorError: Unreadable, empty, oversized, not UTF-8 JSON, not canonically encoded, a shape
            or fingerprint this module would not have written, or a pending batch that does not match
            its own fingerprint, that a read which never completed would move the cursor on, or that
            sits behind the cursor without a mailbox generation change to explain the restart.
    """
    path = pathlib.Path(settings['cursor_path'])
    if path.is_symlink():
        _refuse('a symlinked cursor path')
    if not path.exists():
        return _fresh(settings)
    try:
        raw = path.read_bytes()
    except OSError:
        _refuse('an unreadable cursor')
    if not raw or len(raw) > MAX_CURSOR_BYTES:
        _refuse('a cursor outside the size bound')
    try:
        document = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError, RecursionError):
        _refuse('a cursor that is not UTF-8 JSON')
    fields = {'schema_version', 'configuration', 'generation_digest', 'last_uid', 'last_success_at',
              'pending', 'window'}
    if (not isinstance(document, dict) or set(document) != fields or document['schema_version'] != 1
            or document['configuration'] != _fingerprint(settings)):
        _refuse('a cursor written by another configuration')
    try:
        if canonical(document).encode('utf-8') != raw:
            _refuse('a cursor that is not canonically encoded')
    except (TypeError, ValueError):
        _refuse('a cursor that is not expressible as canonical JSON')
    generation = document['generation_digest']
    if generation is not None and (not isinstance(generation, str) or len(generation) != 64):
        _refuse('a cursor mailbox generation')
    last_uid = document['last_uid']
    if last_uid is not None and (isinstance(last_uid, bool) or not isinstance(last_uid, int)
                                 or last_uid < 1):
        _refuse('a cursor message identifier')
    for name in ('last_success_at',):
        if document[name] is not None:
            timestamp(document[name])
    window = document['window']
    if not isinstance(window, dict) or set(window) != set(_TALLY_FIELDS) | {'started_at'}:
        _refuse('a cursor coverage window')
    if window['started_at'] is not None:
        timestamp(window['started_at'])
    _tally({name: window[name] for name in _TALLY_FIELDS})
    pending = document['pending']
    if pending is not None:
        # The exact field set, so a record written before the generation/read-verdict binding existed is
        # refused rather than adopted: an old pending batch cannot say whether its read completed, and
        # silently replaying one under the new rules would move a cursor on an unverifiable belief.
        if (not isinstance(pending, dict) or set(pending) != _PENDING_FIELDS):
            _refuse('a pending batch shape')
        batch_json(_batch(pending['batch']))
        if pending['fingerprint'] != digest(_pending_intent(pending)):
            _refuse('a pending batch that does not match its fingerprint')
        through = pending['through_uid']
        if through is not None and (isinstance(through, bool) or not isinstance(through, int)
                                    or through < 1):
            _refuse('a pending batch cursor')
        observed_generation = pending['generation_digest']
        if (observed_generation is not None
                and (not isinstance(observed_generation, str) or len(observed_generation) != 64)):
            _refuse('a pending batch mailbox generation')
        source_read = pending['source_read']
        if not isinstance(source_read, bool):
            _refuse('a pending batch source verdict')
        _tally(pending['tally'])
        if not source_read:
            # A read that never completed proved nothing about where the mailbox ends, so its batch may
            # be re-delivered only as coverage: the cursor it would write is the cursor already there.
            if through != last_uid:
                _refuse('a pending batch that would move the cursor without a completed read')
        elif through is not None and last_uid is not None and through < last_uid:
            # Rewinding is legitimate exactly once: the mailbox instance changed and its identifiers
            # restarted below where the old one left off. Anything else is an edited cursor.
            if observed_generation is None or observed_generation == generation:
                _refuse('a pending batch behind the cursor without a mailbox generation change')
    return document


def save_state(settings: dict[str, Any], state: dict[str, Any]) -> None:
    """Write the cursor atomically: temporary file, fsync, rename, directory fsync.

    The discipline `cert_worker.save` uses, for the failure it protects against: a crash between
    "parsed" and "delivered" must leave either the old cursor or the new one on disk, never a little of
    each. The state written here is always the whole document, and the batch precedes the commit.
    """
    raw = canonical(state).encode('utf-8')
    if len(raw) > MAX_CURSOR_BYTES:
        _refuse('a cursor larger than the bound')
    destination = pathlib.Path(settings['cursor_path'])
    temporary: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode='wb', dir=destination.parent, delete=False) as stream:
            temporary = pathlib.Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        temporary = None
        if os.name != 'nt':
            descriptor = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except OSError:
        _refuse('a cursor directory that cannot be written')
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


# -------------------------------------------------------------------------------- the tick


def collect(config: Any, source: MailSource, sink: EventSink, *, now: dt.datetime) -> Report:
    """Run one collector tick, or replay the batch a previous tick could not deliver.

    The order is the design: read what fits the budget → build the batch → write it to the cursor → hand
    it to the sink → advance the cursor. Failing in step four leaves step three's file behind, so the
    next tick replays it before reading anything new, and messages already parsed are not re-parsed
    under a policy that may have changed since.

    Args:
        config: The configuration document (`settings` runs here, so a caller cannot skip validation).
        source: The transport seam. Nothing here knows which protocol it speaks.
        sink: The delivery seam. Raising from it is an expected event, not a crash.
        now: The instant judging this tick. Required and never defaulted: the interval, the silence
            bound and every coverage window are comparisons against it.

    Returns:
        A `Report`. Transport and sink failures are statuses, not exceptions — a transport that is merely
        broken must produce coverage, not a traceback that stops the schedule.

    Raises:
        CollectorError: Configuration or cursor refusal, or a transport that breaks the protocol
            contract (a listing that is not a bounded ascending tuple, an answer for a different
            identifier). The owner lock is the one shared-state refusal that is *not* raised: an
            overlapping schedule returns `idle` with reason `owner-lock-held`.
    """
    chosen = settings(config)
    if not isinstance(now, dt.datetime) or now.tzinfo is None or now.utcoffset() is None:
        _refuse('a clock reading')
    destination = pathlib.Path(chosen['cursor_path'])
    destination.parent.mkdir(parents=True, exist_ok=True)
    stack = ExitStack()
    try:
        stack.enter_context(exclusive_owner(chosen['cursor_path']))
    except OSError:
        log.info('Another identity-mail collector owns the cursor; nothing was read',
                 extra={'source': events.SOURCE})
        return _report('idle', None, chosen, reasons=('owner-lock-held',), batch=None, silence=None)
    try:
        state = load_state(chosen)
        if state['pending'] is not None:
            return _replay(chosen, state, sink, now=now)
        silence = (None if state['last_success_at'] is None
                   else int((now - timestamp(state['last_success_at'])).total_seconds()))
        if silence is not None and silence < chosen['interval_seconds']:
            return _report('idle', state, chosen, reasons=('interval-not-elapsed',), batch=None,
                           silence=silence)
        generation, reset, transport = _generation(source, state)
        after = None if reset else state['last_uid']
        listed: tuple[int, ...] = ()
        regression = False
        selected: list[int] = []
        if transport is None:
            try:
                listed = source.list_uids(after=after, limit=chosen['max_messages'])
                regression, selected = _screen(listed, after)
            except Exception as exc:
                transport = type(exc).__name__
        # A full page is not a truncation: the transport was asked for `max_messages` and returned that
        # many, so the honest statement is "more may be waiting" (`backlog`) rather than "some mail was
        # dropped" (`truncated`). Only the byte budget below can genuinely stop a tick mid-queue, and
        # only that sets `truncated`.
        backlog = bool(transport is None and len(listed) >= chosen['max_messages'])
        if reset:
            log.warning('The mailbox generation changed; the cursor restarts and coverage fires',
                        extra={'source': events.SOURCE, 'reason': 'mailbox-reset'})
        tally = dict.fromkeys(_TALLY_FIELDS, 0)
        anomalies: list[str] = []
        codes: list[str] = []
        produced: list[dict[str, Any]] = []
        read_bytes = 0
        truncated = False
        through: int | None = after
        for position, uid in enumerate(selected):
            if read_bytes >= chosen['max_tick_bytes'] and position < len(selected):
                truncated = True
                anomalies.append('read-budget-exhausted')
                break
            try:
                fetched = source.fetch(uid)
            except Exception as exc:
                # One unfetchable message must not stop the tick, and must not be skipped either: it is
                # counted and the cursor stays behind it, so a later tick gets another chance.
                tally['fetched'] += 1
                tally['parse_failures'] += 1
                anomalies.append(type(exc).__name__)
                break
            if fetched.uid != uid:
                _refuse('a transport that answered a different message identifier')
            tally['fetched'] += 1
            read_bytes += len(fetched.raw)
            if len(fetched.raw) > chosen['max_message_bytes']:
                tally['parse_failures'] += 1
                anomalies.append('oversized-message')
                through = uid
                continue
            outcome = parser.parse_message(fetched.raw, attestation=fetched.attestation,
                                          policy=chosen['policy'], now=now)
            codes.append(outcome.code)
            if outcome.classification == 'event':
                tally['findings'] += 1
                produced.extend(events.events_for(outcome.alert,
                                                  window_seconds=chosen['finding_window_seconds']))
            elif outcome.classification == 'untrusted':
                tally['untrusted'] += 1
            elif outcome.classification == 'parse-failure':
                tally['parse_failures'] += 1
            else:
                tally['unsupported'] += 1
            through = uid
        stale = silence is not None and silence > chosen['max_silence_seconds']
        firing_source = bool(truncated or regression or reset or stale or anomalies or transport
                             or backlog)
        verdicts = ((events.SOURCE_COVERAGE_RULE, firing_source),
                    (events.PARSE_COVERAGE_RULE, tally['parse_failures'] > 0),
                    (events.UNTRUSTED_COVERAGE_RULE, tally['untrusted'] > 0))
        for rule, active in verdicts:
            produced.append(events.coverage_event(rule, firing=active, now=now,
                                                  window_seconds=chosen['coverage_window_seconds']))
        batch = events.Batch(observed_at=utc_text(now), events=tuple(produced))
        pending = _pending_record(batch=batch,
                                  through_uid=through if transport is None else state['last_uid'], tally=tally,
                                  generation=generation, source_read=transport is None)
        state['pending'] = pending
        save_state(chosen, state)
        try:
            sink.admit(batch)
        except Exception as exc:
            log.warning('Identity-mail delivery failed; the batch stays pending',
                        extra={'source': events.SOURCE, 'error_class': type(exc).__name__,
                               'events': len(batch.events)})
            return _report('sink-failed', state, chosen,
                           reasons=tuple(codes) + tuple(anomalies) + (type(exc).__name__,), batch=batch,
                           silence=silence, tally=tally, read_bytes=read_bytes, truncated=truncated,
                           stale=stale, regression=regression, reset=reset, backlog=backlog)
        if transport is None:
            _commit(state, tally, through_uid=through, now=now,
                    generation_digest=pending['generation_digest'], source_read=True, settings=chosen)
        else:
            # The coverage events above were filed, and nothing else was. `last_success_at` stays where
            # it was, because a tick that could not read the mailbox has not completed a read: marking
            # one would let a permanently broken transport time itself out of the staleness check that
            # exists to catch exactly that.
            state['pending'] = None
        save_state(chosen, state)
        return _report('transport-failed' if transport else 'delivered', state, chosen,
                       reasons=tuple(codes) + tuple(anomalies) + ((transport,) if transport else ()),
                       batch=batch, silence=silence, tally=tally, read_bytes=read_bytes,
                       truncated=truncated, stale=stale, regression=regression, reset=reset,
                       backlog=backlog)
    finally:
        stack.close()


def _generation(source: MailSource, state: dict[str, Any]) -> tuple[str, bool, str | None]:
    """The mailbox generation, whether it moved under the cursor, and any transport failure."""
    try:
        generation = source.mailbox_generation()
    except Exception as exc:
        return '', False, type(exc).__name__
    if not isinstance(generation, str) or not 1 <= len(generation) <= 256:
        _refuse('a mailbox generation token that is not a bounded string')
    recorded = state['generation_digest']
    reset = recorded is not None and recorded != digest([generation])
    return generation, reset, None


def _screen(uids: Any, last_uid: int | None) -> tuple[bool, list[int]]:
    """Validate the listing the transport returned, and separate what is genuinely new.

    Non-ascending or already-consumed identifiers set `uid_regression` and are dropped. Processing them
    would re-file messages the cursor says are done; refusing the tick would let one provider hiccup
    stop the feed. The flag is what makes the drop visible, and a coverage event is what carries a flag
    to an operator.
    """
    if not isinstance(uids, tuple) or len(uids) > MAX_MESSAGES_PER_TICK:
        _refuse('a listing that is not a bounded tuple of identifiers')
    regression = False
    selected: list[int] = []
    previous = last_uid or 0
    for uid in uids:
        if isinstance(uid, bool) or not isinstance(uid, int) or uid < 1:
            _refuse('a message identifier that is not a positive integer')
        if uid <= previous:
            regression = True
            continue
        selected.append(uid)
        previous = uid
    return regression, selected


def _commit(state: dict[str, Any], tally: dict[str, int], *, through_uid: int | None,
            now: dt.datetime, generation_digest: str | None, source_read: bool,
            settings: dict[str, Any]) -> None:
    """The single commit point: window counts folded, cursor moved to the observed position, cleared.

    `now` is the instant the mailbox was read. On a replay that is the batch's own `observed_at`, never
    the retry time: the cursor, the generation and `last_success_at` all describe a *read*, and a sink
    that finally accepts an old batch ten minutes later has not made that read any fresher.

    `source_read` is the other half of the same distinction. When the read never completed, nothing about
    the source is known, so the pending entry is cleared and the cursor, the generation and the success
    stamp all stay where they were — the coverage events in that batch are the only thing it may assert.
    """
    window = _roll(state, now, settings)
    for name in _TALLY_FIELDS:
        window[name] = min(100000, window[name] + int(tally.get(name, 0)))
    state['window'] = window
    if source_read:
        # Assigned, not guarded by `is not None`: `None` here means "a generation restart with nothing
        # new read yet", and leaving the old mailbox's identifier behind would skip the new one's UID 1.
        state['last_uid'] = through_uid
        state['last_success_at'] = utc_text(now)
        if generation_digest is not None:
            state['generation_digest'] = generation_digest
    state['pending'] = None


def _roll(state: dict[str, Any], now: dt.datetime, settings: dict[str, Any]) -> dict[str, Any]:
    """The coverage window to fold into, started afresh if the stored one has outlived four intervals.

    Rolling drops the expired span's counts. The events those counts produced are already filed, and a
    cursor that accumulates history forever is a cursor that one day stops the worker from starting.
    """
    window = dict(state['window'])
    started = window.get('started_at')
    if (started is None
            or (now - timestamp(started)).total_seconds() > settings['coverage_window_seconds'] * 4):
        window['started_at'] = utc_text(now)
        for name in _TALLY_FIELDS:
            window[name] = 0
    return window


def _replay(config: dict[str, Any], state: dict[str, Any], sink: EventSink, *,
            now: dt.datetime) -> Report:
    """Deliver the pending batch and read nothing else, until it is accepted.

    No mailbox read and no generation check happen here: a sink that is down is a delivery problem, and
    asking the mailbox more questions in that state would mix the two failure kinds in one report. What
    the commit writes is the recorded intent at the recorded observation time, so the replay is exactly
    equivalent to the delivery that failed — and is refused outright if the batch claims to have been
    observed after the clock it is being replayed on.
    """
    pending = state['pending']
    batch = _batch(pending['batch'])
    observed = timestamp(batch.observed_at)
    if now < observed:
        _refuse('a pending batch observed after the clock it is replayed on')
    try:
        sink.admit(batch)
    except Exception as exc:
        return _report('sink-failed', state, config, reasons=('pending-batch', type(exc).__name__),
                       batch=batch, silence=None, tally=pending['tally'])
    _commit(state, pending['tally'], through_uid=pending['through_uid'], now=observed,
            generation_digest=pending['generation_digest'], source_read=pending['source_read'],
            settings=config)
    save_state(config, state)
    reasons = ('pending-batch',) if pending['source_read'] else ('pending-batch', 'source-read-failed')
    return _report('replayed', state, config, reasons=reasons, batch=batch, silence=None,
                   tally=pending['tally'])


def _report(status: str, state: dict[str, Any] | None, config: dict[str, Any], *,
            reasons: tuple[str, ...] | list[str], batch: events.Batch | None, silence: int | None,
            tally: dict[str, int] | None = None, read_bytes: int = 0, truncated: bool = False,
            stale: bool = False, regression: bool = False, reset: bool = False,
            backlog: bool = False) -> Report:
    """Assemble the answer from the tick's own numbers, with the firing coverage rules read back out."""
    counts = dict.fromkeys(_TALLY_FIELDS, 0)
    counts.update(tally or {})
    firing = tuple(event['rule_id'] for event in (batch.events if batch else ())
                   if event['kind'] == 'coverage' and event['status'] == 'firing')
    return Report(status=status, fetched=counts['fetched'], findings=counts['findings'],
                  untrusted=counts['untrusted'], parse_failures=counts['parse_failures'],
                  unsupported=counts['unsupported'], bytes_read=read_bytes, truncated=truncated,
                  backlog=backlog,
                  stale=stale, uid_regression=regression, mailbox_reset=reset, silence_seconds=silence,
                  last_success_at=None if state is None else state.get('last_success_at'),
                  coverage=firing, reasons=tuple(reasons), batch=batch)

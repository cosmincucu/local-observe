"""The platform boundary: canonical events out, the platform's own receipt back, no claims in between.

Why this file exists instead of `pipeline.py` writing to SQLite directly: `platform/state.py` owns
incident state, and `platform/intake.py` owns the rule/kind/severity decisions that make an event
admissible. This package's job ends at producing the events those layers admit and reporting what they
answered. Three statuses, and only three:

* `admitted` -- the platform took the event and named a record. This is the only status that may be
  described as "the platform has it".
* `not_configured` -- this process had no way to reach the platform (no URL, no credential, no
  admitted actor). The events are returned unsent and the pipeline says so in every report it emits.
* `refused` -- the platform was reached and said no, with its reason carried through verbatim.

There is no fourth status like `assumed`, and no code path here that treats writing a local JSON file
as admission: a file this process wrote is evidence about this process, and nothing else. The
`admission_ready` helper is the strongest claim available offline -- `state.validate_event` accepts the
shape -- and it says "admissible", never "admitted". That distinction is what the card's review asked
for, and it is why the receipts, not a counter, are what the CLI prints.

The vocabulary is deliberately narrow and its cost is stated: `state.validate_event` admits exactly six
`kind` values (`availability`, `coverage`, `threshold`, `drift`, `anomaly`, `security`) and
`platform/vocabulary.py` carries no rows for a CI source. So a failed build is filed as
`availability` (the repository cannot produce a green build -- the same reading `platform/deadman.py`
uses for a job that stopped running) and a gap in this pipeline's own knowledge is `coverage`, never a
fabricated verdict. Adding a `ci` kind, or `gitea_ci` rows to the crosswalk, is a change to those two
modules and their own tests -- named as fan-out, not made here.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
from typing import Any
from collections.abc import Callable, Mapping, Sequence
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.log import get_logger
from local_observe.platform.detections import event as canonical_event
from local_observe.platform.state import StateError, validate_event
from .facts import CardIdentity, RunFact
from .transports import CiFailureError

log = get_logger(__name__)

__all__ = ['AdmissionReceipt', 'PlatformAdmission', 'admission_ready', 'build_events', 'SOURCE',
           'RULE_FAILURE', 'RULE_STUCK', 'RULE_COVERAGE', 'TERMINAL_EVIDENCE', 'COVERAGE_EVIDENCE']

#: The source name every event here carries. `state.label`'s character class applies, so `/`, space
#: and the repository's own name are excluded by construction, not by scrubbing.
SOURCE = 'gitea_ci'
RULE_FAILURE = 'ci.run.failed'
RULE_STUCK = 'ci.run.stuck'
RULE_COVERAGE = 'ci.intake.coverage'

#: How many coverage events one fact may generate. It is a ceiling, and it is the reason a log gap on
#: a thirty-job run cannot become thirty incidents. Evidence references per event are fixed at one
#: here (`detections.event` builds the single reference), inside `state.validate_event`'s 1..20.
MAX_COVERAGE_EVENTS = 3
MIN_WINDOW_SECONDS = 60

TERMINAL_EVIDENCE = 'observed-snapshot'
COVERAGE_EVIDENCE = 'source-heartbeat'

Admitter = Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class AdmissionReceipt:
    """One event, and what the platform said about it."""
    record_id: str
    rule_id: str
    status: str
    reason: str = 'none'

    @property
    def admitted(self) -> bool:
        return self.status == 'admitted'

    def as_dict(self) -> dict[str, Any]:
        return {'record_id': self.record_id, 'rule_id': self.rule_id, 'status': self.status,
                'reason': self.reason}


def _window(fact: RunFact, now: dt.datetime) -> dict[str, str]:
    """The evaluation slice this fact speaks for: observed .. judged, never longer than the ceiling.

    `state.validate_event` refuses a window whose start is not strictly before its end, one ending more
    than a minute in the future, and one spanning more than seven days. A run whose timestamps are
    missing -- or whose stored `updated_at` is somehow ahead of `now` -- therefore gets the shortest
    honest slice ending now, rather than a window that intake would reject or that silently claims
    hours this pipeline did not observe.
    """
    observed = fact.observed_at
    if observed is None or observed >= now:
        start = now - dt.timedelta(seconds=MIN_WINDOW_SECONDS)
    else:
        start = observed
    if now - start > dt.timedelta(days=6):
        start = now - dt.timedelta(days=6)
    if start >= now:
        start = now - dt.timedelta(seconds=MIN_WINDOW_SECONDS)
    return {'start': utc_text(start), 'end': utc_text(now)}


def build_events(fact: RunFact, identity: CardIdentity, *, now: dt.datetime,
                 source: str = SOURCE) -> list[dict[str, Any]]:
    """The canonical events one fact describes: coverage first, then the verdict it makes judgeable.

    The order is `platform/detections.evaluate`'s, and it is not cosmetic -- an intake that opens an
    incident for a firing event must already have heard that the evidence behind it is thin.

    Raises:
        CiFailureError: The fact cannot be expressed at all (no run id), which means the caller has a
            bug rather than a gap: a missing field is a `CoverageNote`, never a dropped event.
    """
    if not isinstance(fact, RunFact) or fact.run_id <= 0:
        raise CiFailureError('A fact must carry a run id to be attributable')
    window = _window(fact, now)
    snapshot_id = f'cirun-{fact.repository.replace("/", "-")}-{fact.run_id}'[:200]
    events: list[dict[str, Any]] = []
    for note in fact.coverage[:MAX_COVERAGE_EVENTS]:
        events.append(canonical_event(source, None, f'{RULE_COVERAGE}.{note.reason}', 'coverage',
                                      'firing', window, {'rule_id': RULE_COVERAGE},
                                      query_type=COVERAGE_EVIDENCE, observed_at=window['end'],
                                      version='1', severity='info'))
    if fact.status != 'completed':
        events.append(canonical_event(source, None, RULE_STUCK, 'availability', 'firing', window,
                                      {'snapshot_id': snapshot_id}, query_type=TERMINAL_EVIDENCE,
                                      observed_at=window['end'], version='1', severity='warning'))
    elif fact.is_failure:
        events.append(canonical_event(source, None, RULE_FAILURE, 'availability', 'firing', window,
                                      {'snapshot_id': snapshot_id}, query_type=TERMINAL_EVIDENCE,
                                      observed_at=window['end'], version='1',
                                      severity='critical' if fact.plane == 'main' else 'warning'))
    if not events:
        # A green run is not a verdict anybody needs an incident for, but silence is indistinguishable
        # from a dead pipeline, so the caller reports the count it chose not to send.
        return []
    return events


class PlatformAdmission:
    """Send canonical events through an injected admitter and keep the receipts it gives back.

    The admitter is a callable the *host* supplies -- in a real deployment, a function holding a
    producer `Actor` that calls `Store.put_evidence` for the referenced sample and then `Store.intake`
    for the event, exactly in that order (`platform/intake.py`'s rule: an event whose sample was never
    stored is a dead link). This package holds no `Actor`, no credential and no store handle, so it
    cannot do that itself, and it will not pretend otherwise: with no admitter, every event comes back
    `not_configured` and the report says so.
    """

    def __init__(self, admitter: Admitter | None = None, *, source: str = SOURCE) -> None:
        if admitter is not None and not callable(admitter):
            raise CiFailureError('A platform admitter must be callable or absent')
        self.admitter = admitter
        self.source = source

    @property
    def configured(self) -> bool:
        return self.admitter is not None

    def admit(self, events: Sequence[Mapping[str, Any]]) -> list[AdmissionReceipt]:
        """Hand each event over, in order, and return one receipt per event.

        An exception from the admitter is reported as `refused` with the exception class, not swallowed
        and not retried here: the caller's cursor has already advanced past the fact, and the honest
        report is "the platform did not take these", which is a coverage statement about the intake
        rather than a claim about the build.
        """
        receipts: list[AdmissionReceipt] = []
        for position, event in enumerate(events):
            record_id = str(event.get('source_event_id') or f'event-{position}')
            rule_id = str(event.get('rule_id') or 'unknown')
            if self.admitter is None:
                receipts.append(AdmissionReceipt(record_id, rule_id, 'not_configured',
                                                 'no platform admitter is wired'))
                continue
            try:
                answer = self.admitter(dict(event))
            except (StateError, CiFailureError, ValueError) as exc:
                receipts.append(AdmissionReceipt(record_id, rule_id, 'refused',
                                                 str(exc)[:200] or type(exc).__name__))
                continue
            except Exception as exc:  # a transport/OS failure is still an answer about the send
                log.warning('Platform admission raised', extra={'error_class': type(exc).__name__})
                receipts.append(AdmissionReceipt(record_id, rule_id, 'refused', type(exc).__name__))
                continue
            status, reason = _classify(answer)
            record = answer.get('event_id') if isinstance(answer, Mapping) else None
            receipts.append(AdmissionReceipt(str(record or record_id), rule_id, status, reason))
        return receipts


def _classify(answer: Any) -> tuple[str, str]:
    """Turn whatever the host's admitter returned into `admitted` or `refused`, with a reason."""
    if answer is None:
        return 'refused', 'the admitter returned nothing'
    if isinstance(answer, Mapping):
        if answer.get('accepted') is True or answer.get('event_id') or answer.get('incident_id'):
            return 'admitted', 'none'
        return 'refused', str(answer.get('reason') or answer.get('detail') or 'rejected')[:200]
    if answer is True:
        return 'admitted', 'none'
    return 'refused', f'unrecognised admitter answer {type(answer).__name__}'


def admission_ready(events: Sequence[Mapping[str, Any]], *, now: dt.datetime) -> int:
    """Prove every event is *admissible* by running the platform's own validator over it.

    This is an offline proof about shape: `state.validate_event` is the same function `Store.intake`
    calls before it writes a row, so an event that passes here could not be refused for being
    malformed. It is not evidence that a send happened -- that is what `AdmissionReceipt` is for.

    Returns the number of events checked, so a caller can assert it checked the ones it meant to.
    """
    if not events:
        return 0
    for event in events:
        validate_event(dict(event), now)
    return len(events)

"""The platform send side: canonical events out over the platform's own intake routes, receipt back.

`adapter.PlatformAdmission` owns the *boundary* and deliberately knows no URL, no HTTP and no
credential -- the host hands it an admitter callable. This module is the host's half of that hand-off:
one object holding a transport of the same shape every other seam here uses (`JsonClient.request`, so
the unit tier injects a recording fake and no socket exists), exposing `admit(event)` as the admitter.

What the platform really accepts, read off `platform/api.py` and `platform/state.py` rather than
assumed:

* `POST /v1/events` -- one canonical event, answered with `Store.intake`'s own outcome:
  `{'status': 'accepted' | 'duplicate', 'event_id': ..., 'incident_id': ..., 'transition': ...}`.
  This is the route the CI events go to; the events `adapter.plan_incident_keys` produces *are* canonical.
* `POST /v1/intake/<source>` -- a **source envelope**, answered **nested**:
  `{'source': ..., 'events': [ {one outcome per event, plus 'resource_link'} ]}`. Nothing is posted
  there from this package: that route normalises through a registered adapter, no adapter is
  registered for `gitea_ci`, and `intake.prepare` also refuses a source with no operator rules rows.
  `_receipt` still understands the nested shape, so a deployment that front-loads an envelope route
  reads the same flat receipt here rather than a second vocabulary.
* `POST /v1/evidence` -- one sample body, exactly `{'sample_id', 'observed_at', 'ok', 'value'}`,
  answered `{'evidence_id': ...}`.

**Evidence first, and only evidence that exists.** `platform/intake.py`'s first rule is that an event
may reference only a sample that was actually stored, and `detection_worker.tick` posts `/v1/evidence`
before `/v1/events` for exactly that reason -- but `Store.intake` does *not* check the link, so the
order is this transport's discipline and nobody else's check. The events built here reference a
*query* (`snapshot_id`, or `rule_id` for a coverage event), not a stored row, and `put_evidence` takes
only a bounded sample body: there is nothing here that could be stored without inventing contents, and
an invented sample is the dead link `docs/CONTRACTS.md` §4 refuses. `platform/pathcheck.py` and
`platform/configdrift.py` file `observed-snapshot` events under the same shape and post `/v1/events`
alone. `evidence_for` is therefore a seam, not a formality: hand it a callable that returns the sample
bodies an event names by `sample_id` and each one is posted, in order, before the event -- and if a
sample is refused, the event is **not** sent, because half a delivery that cites nothing is worse than
a missing one.

A failure to send is an *answer*, never a traceback and never a credential: a transport exception
becomes `{'accepted': False, 'reason': 'unavailable: <ExceptionClass>'}` and the class name is the only
detail logged, because a message from a transport can echo the url it failed on. `StateError` is caught
separately and answered `refused`: it is the platform's own refusal class, raised by `Store.intake` when
the store says no, and reporting it as an outage points an operator at a network that is fine. A non-2xx
answer carries the platform's stable `error` code out of the body -- the code only, bounded, never the
`detail`, because `platform/api.py` puts `str(exc)` in `detail` and a request echo belongs in nobody's
report. `adapter.PlatformAdmission` turns any of that into a `refused` receipt, `pipeline.TickReport`
into `platform_admission: refused`, and the CLI into its "unavailable" exit code. The events stay where
they are -- this module writes no state, so the *pipeline* keeps an unanswered verdict pending and
re-offers it once something answers.
"""
from __future__ import annotations

from typing import Any
from collections.abc import Callable, Mapping, Sequence

from local_observe.log import get_logger
from local_observe.platform.state import StateError
from .adapter import SOURCE
from .transports import CiFailureError, Transport

log = get_logger(__name__)

__all__ = ['PlatformIntake', 'EVIDENCE_ROUTE', 'EVENT_ROUTE', 'MAX_REASON_CHARS', 'MAX_SAMPLES_PER_EVENT']

#: The two routes this transport may post, spelled as `platform/api.py` registers them -- note there is
#: no `/api/v1` prefix on the platform, unlike the forge APIs in `cli._base_url`.
EVIDENCE_ROUTE = '/v1/evidence'
EVENT_ROUTE = '/v1/events'

#: How much of a refusal reason travels into a report. A reason is a status code and a class name, never
#: a response body: a 400 from a platform can echo request bytes, and those bytes can carry a token.
MAX_REASON_CHARS = 120

#: How many evidence rows one event may drag along. `state.validate_event` allows 20 references per
#: event; a send that posts more than that has a bug in the caller, and refusing is cheaper than an
#: unbounded loop over somebody's list.
MAX_SAMPLES_PER_EVENT = 20


class PlatformIntake:
    """Post one canonical event to the platform and return the receipt `PlatformAdmission` expects.

    The object is deliberately smaller than the adapter that uses it: it knows two paths, one source
    name, and the order evidence and event go in. It holds no store, no actor and no credential, and it
    decides nothing -- no severity, no kind, no "is this the same incident". `intake_status` is exposed
    so a caller (or an acceptance check) can read back which routes this object is able to reach.
    """

    def __init__(self, transport: Transport, *, source: str = SOURCE,
                 evidence_for: Callable[[Mapping[str, Any]], Sequence[Any]] | None = None) -> None:
        if not callable(getattr(transport, 'request', None)):
            raise CiFailureError('Platform intake needs a JsonClient-shaped transport')
        if source != SOURCE:
            raise CiFailureError(f'The platform intake source is fixed at {SOURCE!r}, not {source!r}')
        if evidence_for is not None and not callable(evidence_for):
            raise CiFailureError('evidence_for must be callable or absent')
        self.transport = transport
        self.source = source
        self.evidence_for = evidence_for

    @property
    def routes(self) -> tuple[str, ...]:
        """The paths this transport can post -- closed, and readable from outside the object."""
        return (EVIDENCE_ROUTE, EVENT_ROUTE)

    def admit(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Send one event, evidence first. Returns a receipt; never raises for a remote failure.

        Raises:
            CiFailureError: The caller passed something that is not an event at all (not a mapping, or
                naming a different source than this credential speaks for). Those are wiring bugs, and a
                wiring bug must not be reported as "the platform refused" -- an operator who sees
                `refused: unavailable` looks at the network, and an operator who sees this looks at the
                credential they mounted.
        """
        if not isinstance(event, Mapping):
            raise CiFailureError('Platform intake sends a canonical event object')
        if event.get('source') != self.source:
            raise CiFailureError(f'Event names source {event.get("source")!r}; this intake speaks for '
                                 f'{self.source!r} and the platform refuses the mismatch anyway')
        for sample in self._samples(event):
            try:
                status, answer = self.transport.request('POST', EVIDENCE_ROUTE, payload=sample)
            except StateError as exc:
                return _refused(f'evidence refused: {exc}')
            except Exception as exc:  # a failed send is an answer, not a traceback
                return _unavailable(exc)
            if not 200 <= int(status) < 300:
                return _refused(f'evidence refused with status {int(status)}{_error_code(answer)}; '
                                f'the event was not sent')
            if _sample_id(answer) is None:
                return _refused('evidence refused without an id; the event was not sent')
        try:
            status, answer = self.transport.request('POST', EVENT_ROUTE, payload=dict(event))
        except StateError as exc:  # the store's own no: a refusal, not an outage
            return _refused(f'intake refused: {exc}')
        except Exception as exc:  # same rule as the evidence leg above
            return _unavailable(exc)
        if not 200 <= int(status) < 300:
            return _refused(f'intake refused with status {int(status)}{_error_code(answer)}')
        return _receipt(answer)

    def _samples(self, event: Mapping[str, Any]) -> list[dict[str, Any]]:
        """The evidence bodies to store before this event, in the order they were handed over.

        With no `evidence_for`, the answer is empty and nothing is posted: the references these events
        carry name a query, not a sample row, and there is no body here that `put_evidence` could accept
        without this module inventing `ok`/`value` it never measured. A caller that *does* capture a
        sample supplies the callable, and then this is the evidence-before-event order `intake.py` names.
        """
        if self.evidence_for is None:
            return []
        rows = list(self.evidence_for(event) or ())
        if len(rows) > MAX_SAMPLES_PER_EVENT:
            raise CiFailureError(f'One event may store at most {MAX_SAMPLES_PER_EVENT} evidence rows')
        samples: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, Mapping):
                raise CiFailureError('An evidence sample must be an object')
            samples.append(dict(row))
        return samples


def _receipt(answer: Any) -> dict[str, Any]:
    """Map the platform's answer onto the one flat receipt the adapter classifies.

    Two shapes are accepted and only two: `Store.intake`'s own outcome (what `/v1/events` answers), and
    one entry of the nested `{'source': ..., 'events': [...]}` envelope body (what `/v1/intake/<source>`
    answers). Everything else -- a bare error object, a list, a string, an empty `events` array -- is a
    refusal, because "we sent it and got something back" is not the same claim as "the platform named a
    record", and only the second one may be reported as admission.
    """
    if not isinstance(answer, Mapping):
        return _refused('the platform answered without a receipt')
    rows = answer.get('events')
    if isinstance(rows, list):
        # The nested envelope answer: one entry per event the platform normalised, in payload order.
        if not rows:
            return _refused('the platform receipted no events')
        entry = rows[0]
        if not isinstance(entry, Mapping):
            return _refused('the platform receipt entry is not an object')
        receipt = dict(entry)
        if len(rows) > 1:
            receipt['sibling_events'] = len(rows) - 1
    else:
        receipt = dict(answer)
    if receipt.get('error'):
        # A 2xx carrying an error object is a refusal, and the platform's stable code is the reason.
        return _refused(str(receipt['error'])[:MAX_REASON_CHARS])
    if receipt.get('status') in ('accepted', 'duplicate'):
        # Spelled out so admission never depends on an id field merely being present.
        receipt['accepted'] = True
    return receipt


def _error_code(answer: Any) -> str:
    """What a non-2xx body adds to a refusal: the platform's stable code, and nothing else.

    `platform/api.py` answers a refusal as `respond(400, {'error': stable_code(...), 'detail': str(exc)})`.
    The code is a fixed token from the platform's own vocabulary and is what an operator needs to see in
    a report; the `detail` is a rendered exception message, which is exactly the bytes a send must not
    carry home in a log line or a report. A body that is not an object, or that names no `error`, adds
    nothing -- the status code is then the whole answer, as it always was.
    """
    code = answer.get('error') if isinstance(answer, Mapping) else None
    if not isinstance(code, str) or not code.strip():
        return ''
    return f': {code.strip()[:MAX_REASON_CHARS]}'


def _sample_id(answer: Any) -> str | None:
    """The evidence id a successful `POST /v1/evidence` named, or None when it named nothing."""
    if isinstance(answer, Mapping) and isinstance(answer.get('evidence_id'), str) \
            and answer['evidence_id'].strip():
        return answer['evidence_id']
    return None


def _refused(reason: str) -> dict[str, Any]:
    return {'accepted': False, 'status': 'refused', 'reason': reason[:MAX_REASON_CHARS]}


def _unavailable(exc: BaseException) -> dict[str, Any]:
    """One refusal naming the exception class and nothing else -- no message, no url, no credential."""
    log.warning('Platform intake send failed', extra={'error_class': type(exc).__name__})
    return {'accepted': False, 'status': 'unavailable',
            'reason': f'unavailable: {type(exc).__name__}'[:MAX_REASON_CHARS]}

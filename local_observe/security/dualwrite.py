"""Dual-write: the operational event stays in ``state.py``; the analytical copy carries its id (security store).

`docs/CONTRACTS.md` §4 states the reason in one sentence, and this module implements exactly that
sentence: *"Use stable event IDs when copying between operational state and ClickHouse so retries do
not multiply records used for incident decisions."* So the copy is keyed by the pair that already
identifies the event — ``(source, source_event_id)``, the pair ``platform/state.py`` enforces as
``events UNIQUE (source, source_event_id)`` — and never by a second identity invented here. The
runner replays an undelivered batch on its next tick; the replay is the case this is for, and the
answer is one row.

Three copies of one verdict, deliberately unequal:

* **operational** — `platform/state.py` (`events`, `conditions`, incidents). Authoritative for
  whether something is open, and unchanged by anything in this package (incident and action state).
* **analytical** — the owned ``security_events`` table, via `store.SecurityEventStore`. Long TTL, and
  the only place the sensitive columns (`principal`, `raw`) exist.
* **the short-TTL projection** — `short_ttl_projection`, a pruned `LogRecord` for a dashboard. It
  carries the verdict's *identity and shape* and drops both sensitive columns, which is what keeps
  the owned store the single privacy boundary: a 15-day dashboard copy of the payload would make the
  five-year tier meaningless.

**The projection has no exporter in this tree, and says so.** Telemetry enters this product through
the OTLP front door; nothing in ``local_observe/`` writes *out* to the store's log table, and adding
an exporter is a new component rather than a new function. So `dual_write` takes an optional
``log_writer`` seam and, with none supplied, reports ``projection='unwritten'`` and zero rows — a
visible, asserted gap rather than records computed and discarded. The privacy property this module
exists to protect (nothing sensitive in the projection) is proven on `short_ttl_projection` itself,
which is the half that cannot be weakened later by whoever wires the transport.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from local_observe.inventory.validation import InvalidInventory, canonical
from local_observe.platform.state import StateError, clock, validate_event
from local_observe.security.store import (SecurityEvent, SecurityStoreRefused,
                                         SecurityStoreUnavailable, TtlVerdict)
from local_observe.security.ttl import TTL_CHECK_INTERVAL_SECONDS, TtlComparison
from local_observe.store.client import LogRecord

# The prefix on every attribute the projection carries. Namespaced rather than bare because the
# projection lands in the same log table as everything else the operator queries, and `source`
# unqualified would read as the log source of the container that sent it.
PROJECTION_PREFIX = 'security.'
PROJECTION_FIELDS = ('event_id', 'rule_id', 'rule_version', 'status', 'tier', 'producer')

# The closed verdict vocabulary for one analytical write. `idle` is a status and not a silence: it
# says the batch held no security finding, which is the state in which the store was not asked.
WRITE_STATUSES = ('written', 'idle', 'unavailable', 'refused')
# What happened to the short-TTL copy: `none` (nothing to copy), `unwritten` (a finding exists and no
# exporter was configured) and `written` (a caller-supplied exporter took the records). `unwritten` is
# the state of this repository today, and it is reported rather than hidden.
PROJECTION_STATUSES = ('none', 'unwritten', 'written')


@dataclass(frozen=True)
class DualWriteResult:
    """What one dual-write did, in the two halves, reported separately.

    ``owned_written`` counts rows sent to the analytical store; ``projection`` and
    ``projection_rows`` say what happened to the short-TTL copy. They are separate fields because the
    two halves have different owners and a caller must be able to tell "no findings this window" from
    "the store refused".
    """

    owned_written: int
    projection_rows: int
    projection: str
    detail: str

    def __post_init__(self) -> None:
        """Refuse a projection verdict outside the closed set, so the gap cannot read as a send."""
        if self.projection not in PROJECTION_STATUSES:
            raise SecurityStoreRefused(f'unknown projection verdict {self.projection!r}; this tree answers '
                                       f'{", ".join(PROJECTION_STATUSES)}')
        if self.projection != 'written' and self.projection_rows:
            raise SecurityStoreRefused(f'a {self.projection} projection cannot claim rows')
        if self.projection == 'none' and self.owned_written:
            raise SecurityStoreRefused('a batch with no finding cannot have written an analytical row')
        if self.projection == 'written' and not self.projection_rows:
            raise SecurityStoreRefused('a written projection that took no rows is a silent drop')

    def as_dict(self) -> dict[str, Any]:
        """Return the result as JSON-safe text."""
        return {'owned_written': self.owned_written, 'projection_rows': self.projection_rows,
                'projection': self.projection, 'detail': self.detail}


def analytical_row(event: dict[str, Any], *, artifact_sha256: str = '', principal: str = '',
                   raw: str | None = None, now: dt.datetime | None = None) -> SecurityEvent:
    """Return the analytical copy of one canonical event, carrying the event's own identity.

    ``event`` is revalidated with ``state.validate_event`` rather than field-checked here: this repo
    has one event contract and a copy path that trusts its own narrower reading of it is how a row
    comes to exist that no event ever authorised. The identity is ``source_event_id`` copied
    verbatim — not a digest of it, not a UUID minted for the copy — because the retry that follows a
    lost acknowledgement must land on the row it already wrote.

    ``raw`` defaults to the canonical event text, which is what the operational record holds anyway;
    a producer that captured something more sensitive (an intake adapter keeping a provider payload)
    passes it explicitly and is then the only path by which that text exists in two places.
    ``principal`` has no default producer: the Sigma path counts rows and never sees an identity, so
    the column stays empty until a producer genuinely has one.
    """
    try:
        validate_event(event, now or clock())
    except (StateError, InvalidInventory) as exc:
        raise SecurityStoreRefused(f'the analytical copy needs a canonical event ({exc})') from None
    reference = next(iter(event['evidence']), {})
    parameters = reference.get('parameters', {}) if isinstance(reference, dict) else {}
    sample_id = parameters.get('sample_id', '')
    return SecurityEvent(
        ts=event['observed_at'], source=event['source'], event_id=event['source_event_id'],
        rule_id=event['rule_id'], rule_version=event['rule_version'], kind=event['kind'],
        status=event['status'], severity=event['severity'],
        window_start=event['window']['start'], window_end=event['window']['end'],
        observed_at=event['observed_at'], resource_id=event['resource_id'] or '',
        artifact_sha256=artifact_sha256, principal=principal,
        raw=canonical(event) if raw is None else raw,
        labels={'sample_id': sample_id} if sample_id else {})


def short_ttl_projection(row: SecurityEvent) -> LogRecord:
    """Project one analytical row onto the short-TTL dashboard copy, minus both sensitive columns.

    The input is the validated `SecurityEvent` and not the raw event, so the two copies derive from one
    checked object and cannot disagree about what the verdict was. The output is a `LogRecord` — the
    store facade's own record shape — carrying six attributes: the verdict's identity, rule, version,
    status, tier and producer. It never carries ``raw``, ``principal``, the event's evidence parameters
    or its labels, and `tests/test_security_dualwrite.py` proves it by putting a marker in each
    sensitive column and asserting the marker appears nowhere in the projection, keys or values. That
    negative test is the whole privacy claim of the two-tier design: the tier numbers only matter
    because the short copy is a thin one.
    """
    fields = {PROJECTION_PREFIX + name: value for name, value in (
        ('event_id', row.event_id), ('rule_id', row.rule_id), ('rule_version', row.rule_version),
        ('status', row.status), ('tier', row.retention_tier), ('producer', row.source))}
    return LogRecord(body=f"security finding {row.rule_id} is {row.status}", timestamp=row.observed_at,
                     severity=row.severity, fields=fields, resource_id=row.resource_id or None)


def dual_write(store: Any, events: Iterable[dict[str, Any]], *, artifact_sha256: str = '',
               principal: str = '', received_at: str | None = None,
               log_writer: Any = None) -> DualWriteResult:
    """Copy *events*' findings to the owned store, and project them for a short-TTL caller.

    Findings are selected by ``kind``, because §4 keeps the three kinds of record distinct: a
    `coverage` event says a signal was missing, which is a monitoring fact and not a security record,
    and writing the absence of a log source into a security-events table would make every blind window
    look like a finding. A batch of only coverage events writes zero rows and reports ``none`` rather
    than reporting a failure.

    ``log_writer`` is the exporter seam: a callable taking a list of `LogRecord` and returning how many
    it took. **Nothing in this repository supplies one** — telemetry enters through the OTLP front door
    and no component writes out to the store's log table — so the honest default leaves the projection
    unbuilt and says so (`projection='unwritten'`) instead of computing records to throw them away and
    calling that a dual-write. Whoever wires an exporter passes it here and changes no other line of
    this module.
    """
    findings = [event for event in events if event.get('kind') == 'security']
    if not findings:
        return DualWriteResult(owned_written=0, projection_rows=0, projection='none',
                               detail='no security finding in this batch')
    rows = [analytical_row(event, artifact_sha256=artifact_sha256, principal=principal)
            for event in findings]
    written = store.write(rows, received_at=received_at)
    if log_writer is None:
        return DualWriteResult(
            owned_written=written, projection_rows=0, projection='unwritten',
            detail=f'{written} analytical row(s) written; {len(rows)} short-TTL projection(s) not built '
                   f'(no log exporter in this tree)')
    taken = log_writer([short_ttl_projection(row) for row in rows])
    if isinstance(taken, bool) or not isinstance(taken, int) or taken < 0:
        raise SecurityStoreRefused('a log exporter must return how many records it took')
    if taken > len(rows):
        raise SecurityStoreRefused('a log exporter took more records than it was handed')
    return DualWriteResult(owned_written=written, projection_rows=taken, projection='written',
                           detail=f'{written} analytical row(s) written; {taken} projection(s) delivered')


@dataclass(frozen=True)
class SinkVerdict:
    """What the analytical store said about one produced batch, in the words a report uses.

    ``report`` is the runner's instruction: file a coverage event about the store, or stay out of the
    way. It is true when a write was attempted (so every finding carries its own store verdict) and
    when the periodic TTL read ran (so a store that stays quiet is still checked hourly). Nothing
    else emits an event per window — absence has to be visible, and presence does not have to be loud.
    """

    store: str
    rows: int
    ttl: TtlComparison | None
    report: bool
    detail: str

    def __post_init__(self) -> None:
        """Refuse a store verdict outside the closed set, so a runner cannot invent a healthy word."""
        if self.store not in WRITE_STATUSES:
            raise SecurityStoreRefused(f'unknown analytical-write verdict {self.store!r}; this sink answers '
                                       f'{", ".join(WRITE_STATUSES)}')

    @property
    def healthy(self) -> bool:
        """True when the store took the write (or had nothing to take) and the live TTL agrees."""
        return self.store in ('written', 'idle') and (self.ttl is None or self.ttl.matches)

    def as_dict(self) -> dict[str, Any]:
        """Return the verdict as JSON-safe text, with the TTL answer flattened into it."""
        return {'store': self.store, 'rows': self.rows, 'healthy': self.healthy,
                'ttl': self.ttl.as_dict() if self.ttl is not None else None, 'detail': self.detail}


class SecuritySink:
    """The producer-side hook: write a batch's findings, and keep the TTL check on a cadence.

    Built once per runner process and handed to ``sigma_runner.tick``. The TTL read is memoised on the
    instance against the ``now`` the caller already has, because the runner outlives its own windows:
    one aggregate ``SELECT`` on ``system.tables`` an hour, in a process that wakes every window, is a
    check that runs without becoming the runner's workload. A clock that moves backwards simply does
    not trigger a new read until it passes the last one.
    """

    def __init__(self, store: Any, *, check_interval_seconds: int = TTL_CHECK_INTERVAL_SECONDS) -> None:
        """Bind the sink to one `SecurityEventStore` and one re-read interval."""
        if not 60 <= check_interval_seconds <= 86400:
            raise SecurityStoreRefused('the TTL re-read interval must be 60 to 86400 seconds')
        if not hasattr(store, 'verify_ttl'):
            raise SecurityStoreRefused('the sink needs the owned store, not a transport')
        self.store, self.interval = store, check_interval_seconds
        self.last_check: dt.datetime | None = None

    def record(self, events: Sequence[dict[str, Any]], *, now: dt.datetime,
               artifact_sha256: str = '', received_at: str | None = None) -> SinkVerdict:
        """Write this batch's findings, run the TTL check if it is due, and answer in one word.

        No exception escapes: a store that is down, absent or in a shape nobody declared must reach the
        operator as a coverage event, not as a traceback that stops the operational delivery the
        platform actually depends on. That asymmetry is incident and action state's — `state.py` decides what is open
        — and
        it is why a failed analytical write is reported and never retried from here: the runner already
        replays the whole batch, and the replay is what the stable event id makes harmless.
        """
        findings = [event for event in events if event.get('kind') == 'security']
        rows, status, detail = 0, 'idle', 'no security finding in this batch'
        if findings:
            try:
                rows = dual_write(self.store, findings, artifact_sha256=artifact_sha256,
                                  received_at=received_at).owned_written
                status = 'written'
                detail = f'{rows} analytical row(s) written'
            except SecurityStoreUnavailable as exc:
                status, detail = 'unavailable', str(exc)
            except SecurityStoreRefused as exc:
                status, detail = 'refused', str(exc)
        comparison, checked = self._ttl_check(now)
        report = bool(findings) or checked
        return SinkVerdict(store=status, rows=rows, ttl=comparison, report=report, detail=detail)

    def _ttl_check(self, now: dt.datetime) -> tuple[TtlComparison | None, bool]:
        """Return the TTL verdict and whether it was read on this call (``None, False`` when skipped)."""
        if self.last_check is not None and now < self.last_check + dt.timedelta(seconds=self.interval):
            return None, False
        self.last_check = now
        try:
            verdict: TtlVerdict = self.store.verify_ttl(now=now)
        except SecurityStoreUnavailable as exc:
            return TtlComparison(status='unreadable', declared=self.store.policy, live=None,
                                 detail=str(exc)), True
        return verdict.comparison, True

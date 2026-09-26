"""The store facade: named bounded reads, answers shaped as evidence, one timestamp contract.

This module holds the *contract*; the two backends hold the *data*. Nothing here touches a network,
a file or a third-party package — the facade's types are importable on a base interpreter, and the
one transport seam lives in ``backends/clickhouse.py``.

Three v0.1 shapes are kept (`legacy:store/client.py`): an injected abstract client, the sample/record
dataclasses, and ``parse_ts``'s naive-==-UTC rule. Everything about the *outputs* is this repo's:
the v0.1 facade returned lists of rows, and here a query result is a reference that
``local_observe.platform.state.validate_event`` can admit as an event's evidence and reauthorise
later (docs/CONTRACTS.md §4: "They are reauthorised on retrieval, not arbitrary executable SQL from
an agent"). So a read hands back a `ReadOutcome` whose `ReadReceipt` names the query kind, the
approved parameters, the window, the expiry, the row count and whether the answer was truncated —
and refuses rather than presenting an answer that could not be filed as proof.

Two refusals carry most of the value:

* **expired evidence is never returned as rows** — a receipt whose ``expires_at`` is not later than
  ``window.end`` is refused, the same rule ``validate_event`` enforces at intake, so a caller cannot
  build an event that intake will reject or, worse, an incident that cites a dead link;
* **a series the store does not have is ``unavailable``** — never an empty list inside a success
  envelope (docs/CONTRACTS.md §2: "A failed query never returns the same successful envelope as an
  empty result"). Absence of data and absence of *records* are different verdicts and stay
  separate objects here.
"""
from __future__ import annotations

import abc
import datetime as dt
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

# The row cap every read inherits. It is the runner's bound (`SERIES_MAX_POINTS`), kept as one
# number in one place: the aggregate reads that answer with a single row pass `max_rows=1` in their
# own `QueryKind`, so a page can never be larger than the transport will accept.
MAX_ROWS = 2000
# `validate_event` refuses an evaluation window longer than 7 days; a read that could produce a
# receipt intake will reject is a read that should not have been offered.
MAX_WINDOW_SECONDS = 7 * 24 * 3600
# `state.Store.put_evidence` stamps its samples `observed_at + 15 days`. A read defaults to the same
# horizon so a receipt and the evidence row behind it age out together instead of one of them
# silently outliving the other.
EVIDENCE_RETENTION_DAYS = 15
# The closed vocabularies `state.validate_event` admits. A read may only carry parameters the intake
# rule will accept, so an evidence reference can never smuggle SQL, a credential or a host path.
APPROVED_PARAMETERS = frozenset({'snapshot_id', 'observation_id', 'endpoint', 'resource_id',
                                 'sample_id', 'rule_id', 'artifact_sha256'})
EVIDENCE_QUERY_TYPES = frozenset({'gatus-result', 'observed-snapshot', 'metric-threshold',
                                  'source-heartbeat', 'sigma-count', 'sigma-source-coverage'})
SIGNALS = ('metrics', 'logs', 'traces')

# The shape of every bounded name that reaches a receipt: `state.label`, restated so this package
# does not import the platform's SQLite layer to check a string. Kept byte-identical deliberately —
# a value accepted here MUST be accepted at intake, or a read produces a reference that cannot be
# filed. A metric name or a service name therefore never enters a receipt's parameters.
LABEL = re.compile(r'[a-zA-Z0-9_.:-]{1,128}')
# Selectors are bound as ClickHouse query parameters, never interpolated, but they are operator
# review material and are bounded tighter than a label: no quote, no backslash, no space unless the
# selector is prose (see SELECTOR_SHAPES).
SELECTOR = re.compile(r'[a-zA-Z0-9_./:-]{1,128}')
# A body search string is prose, not an identifier, so it gets its own shape: a space is allowed,
# quotes and backslashes are still refused. It travels as a bound query parameter either way; this
# alphabet is a size bound and defence in depth, not the mechanism that makes the statement safe.
SELECTOR_SHAPES: dict[str, re.Pattern[str]] = {'needle': re.compile(r'[a-zA-Z0-9 _./:-]{1,128}')}


class StoreRefused(ValueError):
    """A read this facade will not perform; the reason names the rule, never the data."""


class EvidenceNotApproved(StoreRefused):
    """This query kind's answer cannot be filed as evidence under the intake vocabulary."""


class RowsUnavailable(StoreRefused):
    """Rows were asked for from a read that returned no answer; the status says why."""


def parse_ts(value: str) -> dt.datetime:
    """Return *value* as an aware UTC datetime, reading a naive timestamp as UTC.

    The v0.1 contract, ported unchanged (`legacy:store/client.py:16`): `fromisoformat` accepts both
    ``2026-09-08T10:00:00`` and ``2026-09-08T10:00:00+00:00``, and the first one means a different
    instant on a host using a local timezone than on a host set to UTC. Every timestamp that crosses this
    package — a window bound, a sample stamp, an expiry — is converted here, so one string names one
    instant on every backend and every host. A trailing ``Z`` is accepted, and anything that is not
    text is refused rather than coerced: a missing timestamp is a bug, never midnight.
    """
    if not isinstance(value, str):
        raise ValueError('A timestamp must be ISO-8601 text')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    return parsed.replace(tzinfo=dt.timezone.utc) if parsed.tzinfo is None else parsed.astimezone(dt.timezone.utc)


def utc_text(value: dt.datetime) -> str:
    """Render an aware datetime as the UTC microsecond text this repo stores and compares.

    A twin of `local_observe.inventory.validation.utc_text`, restated here so importing the facade
    does not pull the inventory schema machinery: keep the two in step if either ever changes.
    """
    return value.astimezone(dt.timezone.utc).isoformat(timespec='microseconds')


@dataclass(frozen=True)
class Window:
    """One half-open UTC interval ``[start, end)`` — the pair intake records on the event.

    Both bounds are normalised to UTC microsecond text at construction so a receipt's window
    compares equal to the event window it was filed with (`validate_event` compares the two dicts
    for equality), and so a naive bound cannot mean local time on one host and UTC on another.
    """

    start: str
    end: str

    def __post_init__(self) -> None:
        """Reject a window this facade could not honestly answer for."""
        try:
            start, end = parse_ts(self.start), parse_ts(self.end)
        except (AttributeError, TypeError, ValueError) as exc:
            raise StoreRefused('Query window bounds must be ISO-8601 timestamps') from exc
        if start.tzinfo is None or end.tzinfo is None:  # pragma: no cover - parse_ts always resolves
            raise StoreRefused('Query window bounds must be timezone-aware')
        if not start < end:
            raise StoreRefused('Query window must satisfy start < end; the interval is half-open')
        if end - start > dt.timedelta(seconds=MAX_WINDOW_SECONDS):
            raise StoreRefused(f'Query window may not exceed {MAX_WINDOW_SECONDS // 86400} days')
        object.__setattr__(self, 'start', utc_text(start))
        object.__setattr__(self, 'end', utc_text(end))

    def as_dict(self) -> dict[str, str]:
        """Return the ``{'start', 'end'}`` pair an event's ``window`` field carries."""
        return {'start': self.start, 'end': self.end}

    def instant(self, bound: str) -> dt.datetime:
        """Return one normalised bound as an aware datetime (``'start'`` or ``'end'``)."""
        if bound not in ('start', 'end'):
            raise StoreRefused('Window bound must be "start" or "end"')
        return parse_ts(getattr(self, bound))


@dataclass(frozen=True)
class MetricSample:
    """One metric value at one instant, with the series labels that identify it."""

    name: str
    value: float
    timestamp: str
    labels: dict[str, str] = field(default_factory=dict)
    resource_id: str | None = None


@dataclass(frozen=True)
class LogRecord:
    """One log line with its severity and the resource/attribute maps that scope it."""

    body: str
    timestamp: str
    severity: str = 'info'
    fields: dict[str, str] = field(default_factory=dict)
    resource_id: str | None = None


@dataclass(frozen=True)
class TraceSpan:
    """One span: the identity pair, the work it names, and how long it took in whole nanoseconds."""

    trace_id: str
    span_id: str
    name: str
    service: str
    duration_ns: int
    timestamp: str
    status: str = ''


@dataclass(frozen=True)
class SignalPresence:
    """What the store actually holds for one signal and selector — the answer to "is it there at all".

    This is the object that keeps an empty window honest: a read that found nothing compares its own
    row count against this before it is allowed to report success, so ``row_count == 0`` here means
    the series is unknown to the store and the verdict is ``unavailable``.
    """

    signal: str
    row_count: int
    first_seen: str | None = None
    last_seen: str | None = None

    def __post_init__(self) -> None:
        """Reject a presence answer about a signal this store does not have."""
        if self.signal not in SIGNALS:
            raise StoreRefused('Signal presence names an unknown signal')
        if isinstance(self.row_count, bool) or not isinstance(self.row_count, int) or self.row_count < 0:
            raise StoreRefused('Signal presence row count is not a bounded integer')
        try:
            bounds = [parse_ts(value) for value in (self.first_seen, self.last_seen) if value]
        except (TypeError, ValueError) as exc:
            raise StoreRefused('Signal presence bounds must be ISO-8601 text') from exc
        if len(bounds) == 2 and bounds[0] > bounds[1]:
            raise StoreRefused('Signal presence first_seen is after last_seen')

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe form a portal or a bundle can carry."""
        return {'signal': self.signal, 'row_count': self.row_count,
                'first_seen': self.first_seen, 'last_seen': self.last_seen}


@dataclass(frozen=True)
class QueryKind:
    """One named read: what it touches, what it may say, and what it proves.

    ``parameters`` are drawn only from `APPROVED_PARAMETERS` and land in the evidence reference —
    they are how a reader reauthorises the same query later. ``selectors`` narrow the query (a
    metric name, a service, a body substring) and are bound as server-side query parameters, so they
    never reach the reference: the store's vocabulary has no approved parameter for them, and the
    reference names the reviewed rule (``rule_id`` + ``artifact_sha256``) that carries them instead.
    ``evidence_query_type`` is ``None`` when intake would refuse the answer as proof, which is a
    decision recorded in ``state.validate_event`` and not one this package can make.
    """

    query_type: str
    signal: str
    purpose: str
    description: str
    parameters: frozenset[str]
    required: frozenset[str]
    selectors: tuple[str, ...]
    max_rows: int = MAX_ROWS
    evidence_query_type: str | None = None

    def __post_init__(self) -> None:
        """Fail at import time rather than at the first read if a kind is built outside the rules."""
        if not LABEL.fullmatch(self.query_type):
            raise StoreRefused('Query kind must be a bounded label')
        if self.signal not in SIGNALS or self.purpose not in ('read', 'describe'):
            raise StoreRefused('Query kind names an unknown signal or purpose')
        if not self.parameters <= APPROVED_PARAMETERS or not self.required <= self.parameters:
            raise StoreRefused('Query kind carries a parameter intake does not admit')
        if self.evidence_query_type is not None and self.evidence_query_type not in EVIDENCE_QUERY_TYPES:
            raise StoreRefused('Query kind names an evidence type intake does not admit')
        if self.purpose == 'read' and not self.required:
            raise StoreRefused('A read must require at least one approved parameter')
        if not 1 <= self.max_rows <= MAX_ROWS:
            raise StoreRefused('Query kind row bound is outside the transport bound')

    def with_sql(self, sql: str) -> BoundQuery:
        """Attach this kind's reviewed SQL text, which lives only in a backend module."""
        return BoundQuery(kind=self, sql=sql)


@dataclass(frozen=True)
class BoundQuery:
    """A `QueryKind` plus the one SQL statement it is allowed to run (see ``backends/``)."""

    kind: QueryKind
    sql: str

    def placeholders(self) -> tuple[str, ...]:
        """Return every ``{name:Type}`` bindable in this statement — the caller's whole surface."""
        return tuple(sorted(set(re.findall(r'\{([a-z_]+):[A-Za-z0-9]+\}', self.sql))))


QUERY_KINDS: dict[str, QueryKind] = {kind.query_type: kind for kind in (
    QueryKind(
        query_type='metric-threshold', signal='metrics', purpose='read',
        description='the samples a numeric verdict was made from, for one declared resource',
        parameters=frozenset({'resource_id', 'rule_id', 'artifact_sha256'}),
        required=frozenset({'resource_id', 'rule_id'}), selectors=('metric_name',),
        evidence_query_type='metric-threshold'),
    QueryKind(
        query_type='source-heartbeat', signal='logs', purpose='read',
        description='whether a declared resource produced anything at all in the window',
        parameters=frozenset({'resource_id', 'rule_id', 'endpoint'}),
        required=frozenset({'resource_id'}), selectors=('dataset',), max_rows=1,
        evidence_query_type='source-heartbeat'),
    QueryKind(
        query_type='log-records', signal='logs', purpose='read',
        description='bounded log records for one declared resource, newest first',
        parameters=frozenset({'resource_id', 'rule_id', 'artifact_sha256'}),
        required=frozenset({'resource_id'}), selectors=('needle',), max_rows=200),
    QueryKind(
        query_type='trace-spans', signal='traces', purpose='read',
        description='bounded spans for one service, slowest first (a span names a service, not a '
                    'declared UUID: CONTRACTS §2 keeps unresolved sources queryable as unresolved)',
        parameters=frozenset({'rule_id', 'artifact_sha256'}),
        required=frozenset({'rule_id'}), selectors=('service',), max_rows=100),
    QueryKind(
        query_type='describe-metrics', signal='metrics', purpose='describe',
        description='what the metric tables hold for one metric name in the window',
        parameters=frozenset(), required=frozenset(), selectors=('metric_name',), max_rows=1),
    QueryKind(
        query_type='describe-logs', signal='logs', purpose='describe',
        description='what the log table holds for one declared resource in the window',
        parameters=frozenset(), required=frozenset(), selectors=('resource_id',), max_rows=1),
    QueryKind(
        query_type='describe-traces', signal='traces', purpose='describe',
        description='what the trace index holds for one service in the window',
        parameters=frozenset(), required=frozenset(), selectors=('service',), max_rows=1),
)}

# The kinds that may appear in an evidence reference, and the kinds that exist only as reads.
ADMISSIBLE_QUERY_TYPES = frozenset({name for name, kind in QUERY_KINDS.items()
                                    if kind.evidence_query_type is not None})

# Which describe answers "does this series exist in the window?" for each row-set read: a read that
# came back with nothing asks it, so an empty answer is measured rather than inferred from the
# absence of rows. The read's own extra narrowing (a body substring) is deliberately not part of the
# question — a resource that logged without matching the needle is an empty answer, not an absence.
PROBES: dict[str, str] = {'metric-threshold': 'describe-metrics', 'log-records': 'describe-logs',
                          'trace-spans': 'describe-traces'}


def probe_request(read_type: str, parameters: dict[str, str],
                  selectors: dict[str, str]) -> tuple[str, dict[str, str], dict[str, str]]:
    """Return the describe request that asks whether a row-set read's series exists at all.

    The question is about the *series* — this metric name, this resource, this service — so a
    narrowing only the read carries (a body substring) is dropped, and the resource scope moves from
    the evidence parameters into the describe kind's own selectors. Both backends ask through here,
    so an empty window cannot mean one thing on ClickHouse and another thing in a test.
    """
    target = QUERY_KINDS[PROBES[read_type]]
    narrowing = {name: value for name, value in selectors.items() if name in target.selectors}
    if 'resource_id' in target.selectors:
        narrowing['resource_id'] = parameters.get('resource_id', '')
    keeping = {name: value for name, value in parameters.items() if name in target.parameters}
    return target.query_type, keeping, narrowing


def describe_query(query_type: str) -> QueryKind:
    """Return the approved kind named *query_type*; an unknown name is refused, never guessed."""
    kind = QUERY_KINDS.get(query_type)
    if kind is None:
        raise StoreRefused(f'Unknown query kind {query_type!r}; the store runs a closed table of '
                           f'named reads: {", ".join(sorted(QUERY_KINDS))}')
    return kind


def check_parameters(kind: QueryKind, parameters: dict[str, Any]) -> dict[str, str]:
    """Return *parameters* as receipt-safe text, refusing anything intake would reject.

    Every key must be one this kind declares (which, by construction, is one of the seven approved
    evidence parameters) and every value a bounded label; the required set must be present, because a
    reference that cannot be reauthorised is a dead link the moment it is read.
    """
    if not isinstance(parameters, dict):
        raise StoreRefused('Evidence parameters must be a mapping')
    unknown = sorted(set(parameters) - set(kind.parameters))
    if unknown:
        raise StoreRefused(f'{kind.query_type} does not admit parameter(s): {", ".join(unknown)}; '
                           f'approved for this query: {", ".join(sorted(kind.parameters)) or "none"}')
    missing = sorted(set(kind.required) - set(parameters))
    if missing:
        raise StoreRefused(f'{kind.query_type} requires parameter(s): {", ".join(missing)}')
    checked: dict[str, str] = {}
    for key, value in sorted(parameters.items()):
        if not isinstance(value, str) or not LABEL.fullmatch(value):
            raise StoreRefused(f'Evidence parameter {key} must be 1-128 characters of [A-Za-z0-9_.:-]')
        checked[key] = value
    return checked


def check_selectors(kind: QueryKind, selectors: dict[str, Any] | None) -> dict[str, str]:
    """Return *selectors* as bound values this kind accepts; none of them reaches a receipt.

    Selectors narrow a query (a metric name, a service, a body substring). They are validated to a
    tighter alphabet than a label because they arrive from operator config rather than from the
    intake rule, and they are refused outright when the kind does not list them — a filter that
    quietly did nothing would read as a real answer.
    """
    if selectors is None:
        return {}
    if not isinstance(selectors, dict):
        raise StoreRefused('Query selectors must be a mapping')
    unknown = sorted(set(selectors) - set(kind.selectors))
    if unknown:
        raise StoreRefused(f'{kind.query_type} accepts no selector(s): {", ".join(unknown)}; '
                           f'this query narrows on: {", ".join(kind.selectors) or "nothing"}')
    checked: dict[str, str] = {}
    for key, value in sorted(selectors.items()):
        shape = SELECTOR_SHAPES.get(key, SELECTOR)
        if not isinstance(value, str) or not shape.fullmatch(value):
            raise StoreRefused(f'Selector {key} must be 1-128 characters matching {shape.pattern}')
        checked[key] = value
    return checked


@dataclass(frozen=True)
class ReadReceipt:
    """What one read answered: the query, its window, and how long it remains provable.

    The field set is the one ``state.validate_event`` admits as an evidence reference plus the two
    facts a reader needs to know whether it is looking at a whole answer (``sample_count``,
    ``truncated``). `as_evidence` is the projection that leaves the extras behind.
    """

    query_type: str
    parameters: dict[str, str]
    window: Window
    expires_at: str
    sample_count: int
    truncated: bool
    evidence_query_type: str | None = None

    def __post_init__(self) -> None:
        """Enforce the expiry rule that ``validate_event`` enforces at intake."""
        if self.query_type not in QUERY_KINDS:
            raise StoreRefused(f'Receipt names an unapproved query kind: {self.query_type!r}')
        if not isinstance(self.parameters, dict) or not 1 <= len(self.parameters) <= 10:
            raise StoreRefused('Evidence parameters must be 1-10 named values')
        if any(not LABEL.fullmatch(value) for value in self.parameters.values()):
            raise StoreRefused('Evidence parameter value is not a bounded label')
        if not isinstance(self.sample_count, int) or isinstance(self.sample_count, bool) \
                or not 0 <= self.sample_count <= MAX_ROWS:
            raise StoreRefused('Evidence row count is outside the bound')
        try:
            expiry, end = parse_ts(self.expires_at), self.window.instant('end')
        except StoreRefused as exc:
            raise StoreRefused('Evidence expiry must be an ISO-8601 timestamp') from exc
        if expiry <= end:
            raise StoreRefused('Evidence would already be expired for this window; '
                               'expiry must be later than the window end')

    def as_dict(self) -> dict[str, Any]:
        """Return the receipt as JSON-safe text (the six fields a read reports)."""
        return {'query_type': self.query_type, 'parameters': dict(self.parameters),
                'window': self.window.as_dict(), 'expires_at': self.expires_at,
                'sample_count': self.sample_count, 'truncated': self.truncated}

    def as_evidence(self, source: str) -> dict[str, Any]:
        """Return the exact reference ``validate_event`` admits, or refuse if it would not.

        ``source`` is the producer identity the event carries, not a store name: the reference says
        who is attesting, and intake reauthorises against that identity.
        """
        if self.evidence_query_type is None:
            raise EvidenceNotApproved(
                f'{self.query_type} cannot be filed as evidence: state.validate_event admits only '
                f'{", ".join(sorted(EVIDENCE_QUERY_TYPES))}, and this answer has no approved name. '
                'Widening that vocabulary is a platform decision (suppression/correlation own state.py), not a '
                'read option')
        if not isinstance(source, str) or not LABEL.fullmatch(source):
            raise StoreRefused('Evidence source must be a bounded label')
        return {'source': source, 'query_type': self.evidence_query_type,
                'parameters': dict(self.parameters), 'window': self.window.as_dict(),
                'schema_version': 1, 'expires_at': self.expires_at}


@dataclass(frozen=True)
class ReadOutcome:
    """One read's verdict: the receipt, and rows only when the store really answered.

    ``status`` uses the platform's own words — ``available``, ``unavailable``, ``expired`` — the same
    three `state.Store.get_evidence` returns, so a caller reads a store answer and a stored evidence
    row with one rule. ``detail`` carries the reason for a non-answer; it is text for a log line,
    never a payload.
    """

    status: str
    receipt: ReadReceipt
    samples: tuple[Any, ...] = ()
    detail: str | None = None

    def __post_init__(self) -> None:
        """Refuse the two shapes this repository exists to stop producing."""
        if self.status not in ('available', 'unavailable', 'expired'):
            raise StoreRefused('Unknown read verdict')
        if self.samples and self.status != 'available':
            raise StoreRefused('A refused or unanswered read never carries rows')
        if self.status == 'available' and len(self.samples) != self.receipt.sample_count:
            raise StoreRefused('Read row count disagrees with the rows returned')

    def rows(self) -> tuple[Any, ...]:
        """Return the answer, refusing when there was none: an empty list is never a fallback.

        Callers that can act on absence (a coverage event, an ``unknown`` verdict) read ``status``
        and decide; callers that need data call this and get an exception naming the reason.
        """
        if self.status != 'available':
            raise RowsUnavailable(f'store did not answer ({self.status}): {self.detail or "no reason"}')
        return self.samples

    def as_evidence(self, source: str) -> dict[str, Any]:
        """Return this read's evidence reference (see `ReadReceipt.as_evidence`)."""
        return self.receipt.as_evidence(source)

    def as_sample(self, sample_id: str, value: float | bool | None = None) -> dict[str, Any]:
        """Return the minimal sample ``Store.put_evidence`` retains, stamped with this read's verdict.

        This is the seam between a read and proof: the caller keeps this only when it wants the
        platform to be able to say *later* what the store said now. ``observed_at`` is the window
        end, so the evidence ages out with the window it describes, and ``ok`` is the read's verdict
        rather than the caller's opinion about it.
        """
        if not isinstance(sample_id, str) or not LABEL.fullmatch(sample_id):
            raise StoreRefused('Evidence sample_id must be a bounded label')
        if value is not None and not isinstance(value, (bool, int, float)):
            raise StoreRefused('Evidence sample value must be numeric or boolean')
        return {'sample_id': sample_id, 'observed_at': self.receipt.window.end,
                'ok': self.status == 'available', 'value': value}


def build_outcome(kind: QueryKind, parameters: dict[str, str], window: Window,
                  rows: Sequence[Any], *, expires_at: str | None = None,
                  store_ttl_hours: int | None = None,
                  series_exists: bool = True) -> ReadOutcome:
    """Turn one bounded query answer into a verdict, applying every read rule in one place.

    ``expires_at`` defaults to the platform's own 15-day evidence horizon. A caller that names one
    is refused when it does not outlive the window; a caller that also names the store's live TTL
    for this signal (``store_ttl_hours``, from ``store.retention``) is refused when it promises
    proof past the point the data is gone — a receipt may not outlive the rows it cites.

    ``series_exists`` separates "the selector is unknown to the store" from "the window is empty":
    zero rows with a known selector is an honest empty answer inside a success envelope, zero rows
    with an unknown selector is ``unavailable``.
    """
    parameters = check_parameters(kind, parameters)
    end = window.instant('end')
    expiry = utc_text(end + dt.timedelta(days=EVIDENCE_RETENTION_DAYS)) if expires_at is None \
        else utc_text(parse_ts(expires_at))
    if store_ttl_hours is not None:
        if not isinstance(store_ttl_hours, int) or isinstance(store_ttl_hours, bool) or store_ttl_hours < 1:
            raise StoreRefused('Store retention must be a whole number of hours of at least 1')
        if parse_ts(expiry) > end + dt.timedelta(hours=store_ttl_hours):
            raise StoreRefused(f'evidence expires {expiry}, past the {store_ttl_hours}h the store '
                               f'keeps {kind.signal}; the reference would be a dead link')
    count = len(rows)
    if count > kind.max_rows:
        raise StoreRefused(f'{kind.query_type} returned more rows than its bound of {kind.max_rows}')
    # An aggregate answers with exactly one row by construction, so a full page means nothing there;
    # only a row-set read can be cut off mid-stream.
    truncated = kind.max_rows > 1 and count >= kind.max_rows
    receipt = ReadReceipt(query_type=kind.query_type, parameters=parameters, window=window,
                          expires_at=expiry, sample_count=count, truncated=truncated,
                          evidence_query_type=kind.evidence_query_type)
    if count:
        return ReadOutcome(status='available', receipt=receipt, samples=tuple(rows))
    if series_exists:
        return ReadOutcome(status='available', receipt=receipt,
                           detail=f'{kind.signal} carries this selector but no rows in [start, end)')
    return ReadOutcome(status='unavailable', receipt=receipt,
                       detail=f'the store holds no {kind.signal} for this selector')


class StoreClient(abc.ABC):
    """The one read surface the platform uses: a bounded read per signal, plus a ``describe``.

    Every method takes a *query kind* and the approved parameter names — never SQL, never a
    caller-written filter expression, never a credential (store facade's port delta, and clickstack / hyperdx's rule
    that
    the facade binds ClickHouse tables rather than SigNoz HTTP APIs). Windows are half-open
    ``[start, end)`` in UTC, answers carry truncation and a verdict, and a read of a series the store
    does not have is ``unavailable`` rather than an empty list.
    """

    @abc.abstractmethod
    def read_metrics(self, query_type: str, *, window: Window, parameters: dict[str, str],
                     selectors: dict[str, str] | None = None, expires_at: str | None = None,
                     store_ttl_hours: int | None = None) -> ReadOutcome:
        """Read the metric samples behind a numeric verdict; ``query_type`` must be a metrics read."""

    @abc.abstractmethod
    def read_logs(self, query_type: str, *, window: Window, parameters: dict[str, str],
                  selectors: dict[str, str] | None = None, expires_at: str | None = None,
                  store_ttl_hours: int | None = None) -> ReadOutcome:
        """Read log records, or the fact that a source produced any; ``query_type`` must read logs."""

    @abc.abstractmethod
    def read_traces(self, query_type: str, *, window: Window, parameters: dict[str, str],
                    selectors: dict[str, str] | None = None, expires_at: str | None = None,
                    store_ttl_hours: int | None = None) -> ReadOutcome:
        """Read spans for one service; ``query_type`` must read traces."""

    @abc.abstractmethod
    def describe(self, query_type: str, *, window: Window,
                 selectors: dict[str, str] | None = None) -> SignalPresence:
        """Report what the store holds for one signal in *window* — the proof behind ``unavailable``.

        A caller that intends to act on absence (a coverage event, an ``unknown`` verdict) asks this
        first, so "no data" is a measured claim about the store rather than the absence of rows in
        whatever window it happened to query.
        """

    def read(self, query_type: str, *, window: Window, parameters: dict[str, str],
             selectors: dict[str, str] | None = None, expires_at: str | None = None,
             store_ttl_hours: int | None = None) -> ReadOutcome:
        """Dispatch one read to its signal's method, so a caller may name only the query kind.

        The signal comes from the kind's own declaration, never from the caller: asking
        ``read()`` for a logs query cannot reach the metric tables.
        """
        kind = prepare(query_type, 'read', parameters, selectors)
        method: dict[str, Any] = {'metrics': self.read_metrics, 'logs': self.read_logs,
                                  'traces': self.read_traces}
        return method[kind.signal](query_type, window=window, parameters=check_parameters(kind, parameters),
                                   selectors=selectors, expires_at=expires_at,
                                   store_ttl_hours=store_ttl_hours)


def prepare(query_type: str, purpose: str, parameters: dict[str, Any],
            selectors: dict[str, Any] | None) -> QueryKind:
    """Resolve and check one request against the closed table; return the kind it names.

    Shared by the ABC's dispatcher and by every backend, so a request cannot be valid on one
    backend and invalid on another: the rules are the facade's, not the transport's.
    """
    kind = describe_query(query_type)
    if kind.purpose != purpose:
        raise StoreRefused(f'{query_type} is a {kind.purpose} query, not a {purpose} one')
    check_parameters(kind, parameters)
    check_selectors(kind, selectors)
    return kind


def presence_of(signal: str, row: dict[str, Any]) -> SignalPresence:
    """Normalise one describe answer (``row_count``/``first_seen``/``last_seen``) into a verdict.

    Both backends answer a describe with exactly those three fields — ClickHouse after converting its
    epoch reading, the in-memory store from its own rows — so one constructor guards the shape for
    both, and a broken answer is refused here rather than coerced into a plausible-looking absence.
    """
    if not isinstance(row, dict) or set(row) != {'row_count', 'first_seen', 'last_seen'}:
        raise StoreRefused('A describe answer is one row_count/first_seen/last_seen record')
    count = row['row_count']
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise StoreRefused('Describe row count is not a bounded integer')
    bounds = {}
    for key in ('first_seen', 'last_seen'):
        value = row[key]
        bounds[key] = utc_text(parse_ts(value)) if isinstance(value, str) and value else None
    return SignalPresence(signal=signal, row_count=count, **bounds)

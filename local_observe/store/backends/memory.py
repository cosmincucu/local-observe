"""The in-memory store backend: the same refusals, no transport (tests and the offline demo).

Ported from `legacy:store/backends/memory.py` and reshaped for this repository: it is not a write target
— telemetry enters the product through the OTLP front door, never through a Python call — so rows are
*seeded*, by a test fixture or by an offline demo, and then read under exactly the rules the
ClickHouse backend applies. Every refusal below comes from `local_observe.store.client`, which is
what makes the two interchangeable in a test: a window, a parameter, a row bound or an expiry that one
backend rejects, the other rejects too.

Two behaviours are matched to the ClickHouse backend on purpose, because they are the ones a caller
could otherwise get right in a test and wrong in production:

* the half-open ``[start, end)`` window — a row stamped exactly at ``end`` belongs to the next window;
* a read that returns no rows asks whether the *series* exists in that window at all, so a series the
  store has never seen is ``unavailable`` while an empty window on a known series is an honest empty
  answer, and neither is reported as rows.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Iterable, Sequence
from typing import Any

from local_observe.store.client import (LogRecord, MetricSample, ReadOutcome, SignalPresence, StoreClient,
                                        TraceSpan, Window, build_outcome, check_parameters, check_selectors,
                                        describe_query, parse_ts, presence_of, prepare, probe_request,
                                        utc_text)

# The three row types are the whole seeding surface; a dict or a tuple is refused rather than guessed
# at, because a fixture that silently loads nothing is a test that proves nothing.
ROW_TYPES = (MetricSample, LogRecord, TraceSpan)
SIGNAL_OF_TYPE: dict[type, str] = {MetricSample: 'metrics', LogRecord: 'logs', TraceSpan: 'traces'}


def stamp(row: Any) -> str:
    """Return one seeded row's timestamp, whatever signal it is; anything else is a refusal."""
    value = getattr(row, 'timestamp', None)
    if not isinstance(value, str):
        raise ValueError('A seeded store row must carry an ISO-8601 timestamp')
    return value


# The heartbeat kind answers with an aggregate over its own narrowing, so its probe is its signal's
# describe; row-set reads use the shared table in ``client.PROBES``.
PROBES_BY_READ: dict[str, str] = {'source-heartbeat': 'describe-logs'}


class InMemoryStore(StoreClient):
    """A seeded, bounded store for tests and the offline demo, with every facade rule live.

    Nothing here reaches a network or a file, and nothing here relaxes a rule: the point of this
    backend is that a test can prove a caller handles ``unavailable``, truncation and an expired
    window without a ClickHouse to argue with.
    """

    def __init__(self, rows: Iterable[Any] = ()) -> None:
        """Seed the store from an iterable of `MetricSample`, `LogRecord` or `TraceSpan` rows."""
        self._rows: dict[str, list[Any]] = {'metrics': [], 'logs': [], 'traces': []}
        self.load(rows)

    def load(self, rows: Iterable[Any]) -> int:
        """Add seeded rows and return how many landed; the demo and the fixtures load here.

        A row of any other type is refused before anything is appended, so a half-loaded fixture
        cannot answer a query with a shorter history than it claims.
        """
        incoming = list(rows)
        signals = [SIGNAL_OF_TYPE.get(type(row)) for row in incoming]
        missing = sorted({type(row).__name__ for row, signal in zip(incoming, signals) if signal is None})
        if missing:
            raise ValueError(f'Unsupported seeded row type(s): {", ".join(missing)}; '
                             f'the store is seeded with {", ".join(kind.__name__ for kind in ROW_TYPES)}')
        for row, signal in zip(incoming, signals):
            stamp(row)
            self._rows[str(signal)].append(row)
        return len(incoming)

    def read_metrics(self, query_type: str, *, window: Window, parameters: dict[str, str],
                     selectors: dict[str, str] | None = None, expires_at: str | None = None,
                     store_ttl_hours: int | None = None) -> ReadOutcome:
        """Return the seeded samples for one resource (and metric name) inside *window*."""
        return self._read(query_type, 'metrics', window=window, parameters=parameters, selectors=selectors,
                          expires_at=expires_at, store_ttl_hours=store_ttl_hours)

    def read_logs(self, query_type: str, *, window: Window, parameters: dict[str, str],
                  selectors: dict[str, str] | None = None, expires_at: str | None = None,
                  store_ttl_hours: int | None = None) -> ReadOutcome:
        """Return the seeded log records for one resource inside *window*, newest first."""
        return self._read(query_type, 'logs', window=window, parameters=parameters, selectors=selectors,
                          expires_at=expires_at, store_ttl_hours=store_ttl_hours)

    def read_traces(self, query_type: str, *, window: Window, parameters: dict[str, str],
                    selectors: dict[str, str] | None = None, expires_at: str | None = None,
                    store_ttl_hours: int | None = None) -> ReadOutcome:
        """Return the seeded spans for one service inside *window*, slowest first."""
        return self._read(query_type, 'traces', window=window, parameters=parameters, selectors=selectors,
                          expires_at=expires_at, store_ttl_hours=store_ttl_hours)

    def describe(self, query_type: str, *, window: Window,
                 selectors: dict[str, str] | None = None) -> SignalPresence:
        """Report what was seeded for one signal inside *window*, in the store's own answer shape."""
        kind = prepare(query_type, 'describe', {}, selectors)
        narrowing = check_selectors(kind, selectors)
        return self._presence(kind.query_type, window, {}, narrowing)

    def _read(self, query_type: str, signal: str, *, window: Window, parameters: dict[str, str],
              selectors: dict[str, str] | None, expires_at: str | None,
              store_ttl_hours: int | None) -> ReadOutcome:
        """Filter seeded rows under the facade's rules and report the verdict.

        The signal named by the method is checked against the signal the kind declares, so asking the
        log reader for a metric query is a refusal here exactly as it is on ClickHouse — the two
        backends differ in transport, never in what they will answer.
        """
        kind = prepare(query_type, 'read', parameters, selectors)
        if kind.signal != signal:
            raise ValueError(f'{query_type} reads {kind.signal}, not {signal}')
        checked = check_parameters(kind, parameters)
        narrowing = check_selectors(kind, selectors)
        if kind.max_rows == 1:
            presence = self._presence(PROBES_BY_READ.get(query_type, 'describe-' + signal), window, checked,
                                      narrowing)
            rows: Sequence[Any] = [] if presence.row_count == 0 else [presence]
            series_exists = presence.row_count > 0
        else:
            rows = self._select(signal, window, checked, narrowing)[:kind.max_rows]
            series_exists = bool(rows) or self._ask_probe(query_type, window, checked, narrowing).row_count > 0
        return build_outcome(kind, checked, window, rows, expires_at=expires_at,
                             store_ttl_hours=store_ttl_hours, series_exists=series_exists)

    def _ask_probe(self, read_type: str, window: Window, parameters: dict[str, str],
                   selectors: dict[str, str]) -> SignalPresence:
        """Ask the shared existence question — see ``client.probe_request`` for what it drops."""
        describe_type, keeping, narrowing = probe_request(read_type, parameters, selectors)
        return self._presence(describe_type, window, keeping, narrowing)

    def _presence(self, describe_type: str, window: Window, parameters: dict[str, str],
                  selectors: dict[str, str]) -> SignalPresence:
        """Count one signal's seeded rows in the shape a describe answer arrives in."""
        kind = describe_query(describe_type)
        found = self._select(kind.signal, window, parameters, selectors)
        stamps = sorted(stamp(row) for row in found)
        return presence_of(kind.signal, {'row_count': len(found),
                                         'first_seen': stamps[0] if stamps else '',
                                         'last_seen': stamps[-1] if stamps else ''})

    def _select(self, signal: str, window: Window, parameters: dict[str, str],
                selectors: dict[str, str]) -> list[Any]:
        """Filter, then order the way the store's statement orders: logs newest-first, spans slowest-first."""
        kept = [row for row in self._rows[signal]
                if _in_window(row, window) and _matches(row, parameters, selectors)]
        if signal == 'logs':
            return sorted(kept, key=stamp, reverse=True)
        if signal == 'traces':
            return sorted(kept, key=lambda row: int(getattr(row, 'duration_ns', 0)), reverse=True)
        return sorted(kept, key=stamp)


def _resource(row: Any) -> str | None:
    """Return the declared resource a row is attributed to, or None when its producer sent none."""
    value = getattr(row, 'resource_id', None)
    if value is None and isinstance(getattr(row, 'labels', None), dict):
        value = row.labels.get('resource_id')
    return value if isinstance(value, str) else None


def _attribute(row: Any, key: str) -> str | None:
    """Return one attribute/label value a row carries, from whichever map that signal stores it in."""
    for name in ('fields', 'labels'):
        mapping = getattr(row, name, None)
        if isinstance(mapping, dict):
            value = mapping.get(key)
            if isinstance(value, str):
                return value
    return None


def _in_window(row: Any, window: Window) -> bool:
    """Apply the half-open rule: a row stamped exactly at ``end`` belongs to the next window."""
    instant = parse_ts(stamp(row))
    return window.instant('start') <= instant < window.instant('end')


def _matches(row: Any, parameters: dict[str, str], selectors: dict[str, str]) -> bool:
    """Apply the resource scope and the kind's own narrowing to one row.

    The keys mirror the ClickHouse statement's WHERE clause one for one: metric name and service are
    selectors, the resource is an evidence parameter (or a describe selector), the dataset narrows a
    heartbeat and the needle narrows a log search case-insensitively. An absent filter never excludes
    a row, so a probe that dropped a narrowing really does ask the wider question.
    """
    wanted = {'metric_name': getattr(row, 'name', None), 'service': getattr(row, 'service', None),
              'resource': _resource(row), 'dataset': _attribute(row, 'event.dataset'),
              'needle': str(getattr(row, 'body', '')).lower()}
    checks: list[tuple[str | None, str | None]] = [
        (selectors.get('metric_name'), wanted['metric_name']),
        (selectors.get('service'), wanted['service']),
        (parameters.get('resource_id') or selectors.get('resource_id'), wanted['resource']),
        (selectors.get('dataset'), wanted['dataset']),
    ]
    for need, have in checks:
        if need is not None and need != (have or ''):
            return False
    needle = selectors.get('needle')
    return not (needle and needle.lower() not in str(wanted['needle']))


def series(count: int, *, name: str, resource_id: str, start: str, step_seconds: int = 60,
           value: float = 1.0) -> list[MetricSample]:
    """Build a deterministic metric series for a fixture or the offline demo.

    Stamps are derived, never read from a clock, so a test that seeds 120 points gets the same 120
    instants on every host in every timezone — ``client.parse_ts``'s naive-==-UTC rule is what makes a
    generated stamp mean the same thing here as in production.
    """
    if not 1 <= count <= 2000 or not 1 <= step_seconds <= 86400:
        raise ValueError('Seeded series is outside the supported shape')
    origin = parse_ts(start)
    return [MetricSample(name=name, value=value, resource_id=resource_id, labels={'resource_id': resource_id},
                         timestamp=utc_text(origin + dt.timedelta(seconds=index * step_seconds)))
            for index in range(count)]

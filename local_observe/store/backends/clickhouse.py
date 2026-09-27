"""The ClickHouse read path: the bounded query client, and the facade that runs named reads on it.

Two clients live here and they are not the same thing.

``ClickHouse`` is the transport the Sigma runner has always used: one POST to the HTTP interface,
every server-side bound set on the request rather than trusted to the caller, reviewed SQL only, and
no endpoint that accepts a caller's query text. It moved here from
``local_observe/platform/sigma_runner.py`` unchanged by store facade so that runner's behaviour and its
tests do not move with it; ``sigma_runner`` re-imports the name, and the runner's compiled-artifact
SQL — checksum-verified in ``artifact()`` before it is ever sent — remains the only text that path
carries.

``ClickHouseStore`` is the facade callers use. It takes a **query kind** and the approved parameter
names, never SQL: the statements below are the complete set of questions the platform can ask the
store, so a stored evidence reference can only ever name one of them (clickstack / hyperdx's phase-1 rule — these
are ClickHouse tables, not SigNoz HTTP APIs).

Credential and grants: the user is ``lo-query``, which is ``readonly = 1``, ``allow_ddl = 0`` and
holds ``SELECT`` on the three signal databases only. That profile also *pins* ``max_result_rows`` to
1 and marks every bound ``changeable_in_readonly`` so this client's own request may state its row
cap — see ``components/data/store-signoz/CONTRACT.md`` ("Platform read path") for what each bound
costs and for what happens when the read-only user is missing.
"""
from __future__ import annotations

import datetime as dt
import json
import urllib.parse
import urllib.request
from typing import Any

from local_observe.http import NoRedirect, TransportError
from local_observe.log import get_logger
from local_observe.store.client import (MAX_ROWS, BoundQuery, LogRecord, MetricSample, PROBES, QUERY_KINDS,
                                        QueryKind, ReadOutcome, SignalPresence, StoreClient, TraceSpan,
                                        Window, build_outcome, check_parameters, check_selectors,
                                        presence_of, prepare, probe_request, utc_text)

log = get_logger(__name__)

# Result rows a series query may return. The bound is arithmetic, not taste: `series` reads at most
# 64 KiB of response and a JSON row of two numbers costs about 30 bytes, so 2 000 points fit inside
# the read cap. A query with fatter rows trips the byte cap instead — either way it fails closed
# rather than truncating a baseline into silence. One number for the whole package: it is
# ``client.MAX_ROWS``, so a facade kind can never be sized above what this transport will read.
SERIES_MAX_POINTS = MAX_ROWS

# The store's own table names, spelled out here rather than hidden in a builder: clickstack / hyperdx binds this
# repository to these tables, so a SigNoz schema change is a compatibility event, not a rename.
METRICS_SAMPLES = 'signoz_metrics.distributed_samples_v4'
METRICS_SERIES = 'signoz_metrics.distributed_time_series_v4'
LOGS = 'signoz_logs.distributed_logs_v2'
TRACES = 'signoz_traces.distributed_signoz_index_v3'

# Every statement the platform may run, keyed by the query kind that names it, and asserted against
# ``client.QUERY_KINDS`` at import. `{name:Type}` tokens are filled by ClickHouse query parameters
# (`param_name`), never by string interpolation: caller text reaches the server only as a bound value
# under a declared type. Optional narrowing uses the guard form `({x:String} = '' OR ...)` with an
# empty binding, because a fixed statement cannot be spliced — that costs ClickHouse one predicate
# evaluation per row on a scan it already bounds with max_bytes_to_read.
QUERY_SQL: dict[str, str] = {
    'metric-threshold': (
        'SELECT s.metric_name AS metric_name, s.unix_milli AS unix_milli, s.value AS value, '
        't.labels AS labels '
        f'FROM {METRICS_SAMPLES} AS s INNER JOIN '
        # Series metadata is stamped at the start of each hour; samples keep exact bounds.
        '(SELECT env, temporality, metric_name, fingerprint, '
        f'argMax(labels, unix_milli) AS labels FROM {METRICS_SERIES} '
        'WHERE unix_milli >= intDiv({start_ms:Int64}, 3600000) * 3600000 '
        'AND unix_milli < {end_ms:Int64} '
        "AND ({metric_name:String} = '' OR metric_name = {metric_name:String}) "
        'GROUP BY env, temporality, metric_name, fingerprint) AS t '
        'ON s.env = t.env AND s.temporality = t.temporality '
        'AND s.metric_name = t.metric_name AND s.fingerprint = t.fingerprint '
        'WHERE s.unix_milli >= {start_ms:Int64} AND s.unix_milli < {end_ms:Int64} '
        "AND JSONExtractString(t.labels, 'resource_id') = {resource_id:String} "
        "AND ({metric_name:String} = '' OR s.metric_name = {metric_name:String}) "
        'ORDER BY s.unix_milli ASC FORMAT JSON'),
    'source-heartbeat': (
        'SELECT count() AS row_count, min(timestamp) AS first_seen, max(timestamp) AS last_seen '
        f'FROM {LOGS} '
        'WHERE timestamp >= {start_ns:UInt64} AND timestamp < {end_ns:UInt64} '
        "AND resources_string['resource_id'] = {resource_id:String} "
        "AND ({dataset:String} = '' OR attributes_string['event.dataset'] = {dataset:String}) "
        'FORMAT JSON'),
    'log-records': (
        'SELECT timestamp AS timestamp_ns, body AS body, severity_text AS severity, '
        'attributes_string AS attributes, resources_string AS resources '
        f'FROM {LOGS} '
        'WHERE timestamp >= {start_ns:UInt64} AND timestamp < {end_ns:UInt64} '
        "AND resources_string['resource_id'] = {resource_id:String} "
        "AND ({needle:String} = '' OR positionCaseInsensitive(body, {needle:String}) > 0) "
        'ORDER BY timestamp DESC FORMAT JSON'),
    'trace-spans': (
        'SELECT traceID AS trace_id, spanID AS span_id, name AS name, serviceName AS service, '
        'durationNano AS duration_ns, toUnixTimestamp64Milli(timestamp) AS ts_ms, '
        'statusCode AS status_code '
        f'FROM {TRACES} '
        'WHERE timestamp >= fromUnixTimestamp64Nano({start_ns:UInt64}) '
        'AND timestamp < fromUnixTimestamp64Nano({end_ns:UInt64}) '
        "AND ({service:String} = '' OR serviceName = {service:String}) "
        'ORDER BY durationNano DESC FORMAT JSON'),
    'describe-metrics': (
        'SELECT count() AS row_count, min(unix_milli) AS first_ms, max(unix_milli) AS last_ms '
        f'FROM {METRICS_SAMPLES} '
        'WHERE unix_milli >= {start_ms:Int64} AND unix_milli < {end_ms:Int64} '
        "AND ({metric_name:String} = '' OR metric_name = {metric_name:String}) FORMAT JSON"),
    'describe-logs': (
        'SELECT count() AS row_count, min(timestamp) AS first_seen, max(timestamp) AS last_seen '
        f'FROM {LOGS} '
        'WHERE timestamp >= {start_ns:UInt64} AND timestamp < {end_ns:UInt64} '
        "AND ({resource_id:String} = '' OR resources_string['resource_id'] = {resource_id:String}) "
        'FORMAT JSON'),
    'describe-traces': (
        'SELECT count() AS row_count, min(toUnixTimestamp64Milli(timestamp)) AS first_ms, '
        f'max(toUnixTimestamp64Milli(timestamp)) AS last_ms FROM {TRACES} '
        'WHERE timestamp >= fromUnixTimestamp64Nano({start_ns:UInt64}) '
        'AND timestamp < fromUnixTimestamp64Nano({end_ns:UInt64}) '
        "AND ({service:String} = '' OR serviceName = {service:String}) FORMAT JSON"),
}


class ClickHouse:
    """Explicit endpoint and credentials; reviewed SQL only, no arbitrary user query API.

    ``query`` and ``series`` stay the compiled-artifact path used by the Sigma runner and the
    anomaly producer: the SQL they carry is reviewed as an artifact and checksum-verified before it
    is sent, which is what makes it different from a caller's string. Platform code that only wants
    data goes through :class:`ClickHouseStore`, which takes a query kind instead of a statement.
    """
    def __init__(self, url, user, password, *, allow_http=False):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme not in (('https', 'http') if allow_http else ('https',))
                or not parsed.hostname or parsed.username or parsed.password or parsed.query
                or parsed.fragment):
            raise ValueError('Explicit trusted ClickHouse endpoint required')
        self.url, self.user, self.password = url, user, password

    def _rows(self, sql: str, parameters: dict[str, Any], *, max_result_rows: int,
              expected_rows: int | None = None) -> list[Any]:
        """POST one reviewed SELECT under fixed read-only bounds and return its JSON rows.

        Every bound is set here rather than trusted to the caller: server-side `readonly`, a query
        time and read/write row limits that throw instead of truncating, a capped result size and a
        64 KiB response read. `expected_rows` is asserted inside the wrapped block so a wrong-shaped
        answer reaches the caller as one `TransportError`, never as a partial result.

        The leading underscore is kept from the runner's use of this class; ``ClickHouseStore`` is in
        this module and calls it on purpose, because the public ``series`` path carries the runner's
        fixed ``SERIES_MAX_POINTS`` bound and a facade read needs its kind's bound instead.
        """
        settings = {'readonly': '1', 'max_execution_time': '5', 'max_rows_to_read': '1000000',
                    'max_bytes_to_read': '67108864', 'max_memory_usage': '134217728',
                    'max_result_rows': str(max_result_rows), 'result_overflow_mode': 'throw',
                    'read_overflow_mode': 'throw'}
        settings.update({'param_' + key: value for key, value in parameters.items()})
        request = urllib.request.Request(self.url + '?' + urllib.parse.urlencode(settings),
                                         data=sql.encode(), method='POST',
                                         headers={'X-ClickHouse-User': self.user,
                                                  'X-ClickHouse-Key': self.password})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        try:
            with opener.open(request, timeout=10) as response:
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise ValueError('Oversized result')
                result = json.loads(raw)
                rows = result['data']
                if expected_rows is not None and len(rows) != expected_rows:
                    raise ValueError('Unexpected aggregate result')
                return rows
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log.debug('Bounded ClickHouse query failed', extra={'error_class': type(exc).__name__})
            raise TransportError('Bounded ClickHouse query failed') from None

    def query(self, sql: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Return the single aggregate row a reviewed `FORMAT JSON` SELECT produced."""
        return self._rows(sql, parameters, max_result_rows=1, expected_rows=1)[0]

    def series(self, sql: str, parameters: dict[str, Any]) -> list[Any]:
        """Return the bounded row set of a reviewed series SELECT, at most `SERIES_MAX_POINTS`."""
        return self._rows(sql, parameters, max_result_rows=SERIES_MAX_POINTS)


def _build_templates() -> dict[str, BoundQuery]:
    """Pair every approved query kind with its statement, refusing a mismatch at import.

    A kind with no statement is a name a caller can pass that fails at the first read; a statement
    with no kind can never be reached, which is how a second, unaudited query comes to exist in this
    file. Both are import failures instead, with the two lists in the message.
    """
    if set(QUERY_SQL) != set(QUERY_KINDS):
        missing = sorted(set(QUERY_KINDS) - set(QUERY_SQL))
        extra = sorted(set(QUERY_SQL) - set(QUERY_KINDS))
        raise ValueError(f'Store query table disagrees with the approved kinds '
                         f'(no statement for: {missing or "none"}; no kind for: {extra or "none"})')
    return {name: QUERY_KINDS[name].with_sql(QUERY_SQL[name]) for name in QUERY_SQL}


TEMPLATES: dict[str, BoundQuery] = _build_templates()

# Which describe answers the question "does the series this read asks about exist at all?" for each
# row-set read lives in ``client.PROBES``, shared with the in-memory backend so an empty window means
# the same verified thing on either side of the seam.

# Placeholder names derived from the request rather than supplied by a caller: a window is a Window,
# and the unit is whatever the statement asked for.
WINDOW_UNITS = frozenset({'start_ms', 'start_ns', 'end_ms', 'end_ns'})
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


def bound_values(query: BoundQuery, window: Window, parameters: dict[str, str],
                 selectors: dict[str, str]) -> dict[str, Any]:
    """Return exactly the values the statement's placeholders need, refusing an unbound one.

    This is what makes the templates safe to keep as fixed text: every ``{name:Type}`` token is
    filled from the window, from an approved parameter or from a declared selector, and a token that
    nothing binds is a defect in this module rather than a value a caller can supply. A selector the
    caller omitted binds empty, which the guard form in each statement reads as "no narrowing".
    """
    needed = set(query.placeholders())
    unbound = sorted(needed - WINDOW_UNITS - set(query.kind.parameters) - set(query.kind.selectors))
    if unbound:
        raise ValueError(f'{query.kind.query_type} binds undeclared placeholder(s): {", ".join(unbound)}')
    values: dict[str, Any] = {}
    for name in sorted(needed & WINDOW_UNITS):
        instant = window.instant('start' if name.startswith('start') else 'end')
        delta = instant - EPOCH
        micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        values[name] = micros * 1_000 if name.endswith('ns') else micros // 1_000
    for name in sorted(needed - WINDOW_UNITS):
        values[name] = parameters.get(name) or selectors.get(name, '')
    return values


def _number(value: Any) -> float:
    """Read one ClickHouse JSON scalar as a number: its JSON format quotes 64-bit integers."""
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError('Store returned a non-numeric measure')
    return float(value)


def _instant(value: Any, *, unit: str) -> str:
    """Convert one ClickHouse epoch reading into this repo's UTC text form."""
    divisor = {'ns': 1_000_000_000, 'ms': 1_000}[unit]
    return utc_text(EPOCH + dt.timedelta(seconds=_number(value) / divisor))


def _text(value: Any) -> str:
    """Return a ClickHouse string column as text, refusing anything that is not a string."""
    if not isinstance(value, str):
        raise ValueError('Store returned a non-text field')
    return value


def _map(value: Any) -> dict[str, str]:
    """Return a ClickHouse ``Map`` column as a plain string map, in either JSON shape it arrives in.

    ``FORMAT JSON`` renders a ``Map(String, String)`` as a JSON object while other paths render its
    text form; both decode to the same dict here, so a read does not depend on which the pinned
    build chose. Anything else is refused rather than stringified into a fake label.
    """
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else {}
    if not isinstance(value, dict) or any(not isinstance(key, str) or not isinstance(item, str)
                                          for key, item in value.items()):
        raise ValueError('Store returned a malformed attribute map')
    return dict(value)


def metric_row(row: Any) -> MetricSample:
    """Map one ``metric-threshold`` row to a sample, keeping the resource identity it was scoped by."""
    if not isinstance(row, dict):
        raise ValueError('Store returned a malformed metric row')
    labels = _map(row.get('labels', ''))
    return MetricSample(name=_text(row['metric_name']), value=_number(row['value']),
                        timestamp=_instant(row['unix_milli'], unit='ms'), labels=labels,
                        resource_id=labels.get('resource_id'))


def log_row(row: Any) -> LogRecord:
    """Map one ``log-records`` row to a record, keeping the attribute map the producer sent.

    ``severity_text`` arrives in the store's own casing (``INFO``); the record's default is lowercase,
    so the value is normalised to match rather than leaving a caller to compare two spellings.
    """
    if not isinstance(row, dict):
        raise ValueError('Store returned a malformed log row')
    resources, attributes = _map(row.get('resources', '')), _map(row.get('attributes', ''))
    return LogRecord(body=_text(row['body']), timestamp=_instant(row['timestamp_ns'], unit='ns'),
                     severity=_text(row.get('severity', '')).lower() or 'info',
                     fields=attributes, resource_id=resources.get('resource_id'))


def trace_row(row: Any) -> TraceSpan:
    """Map one ``trace-spans`` row to a span; duration stays whole nanoseconds, not float millis."""
    if not isinstance(row, dict):
        raise ValueError('Store returned a malformed span row')
    return TraceSpan(trace_id=_text(row['trace_id']), span_id=_text(row['span_id']),
                     name=_text(row['name']), service=_text(row['service']),
                     duration_ns=int(_number(row['duration_ns'])),
                     timestamp=_instant(row['ts_ms'], unit='ms'),
                     status=_text(row.get('status_code', '')))


ROW_MAPS: dict[str, Any] = {'metric-threshold': metric_row, 'log-records': log_row, 'trace-spans': trace_row}


def presence_row(query: BoundQuery, row: Any) -> SignalPresence:
    """Turn one aggregate answer into the store's answer about whether the data is there at all.

    ClickHouse names the oldest/newest reading per table (nanoseconds on logs, milliseconds on the
    metric samples), so the unit is read from the row's own field names before the value is
    converted; the three fields then go through the same constructor the in-memory backend uses.
    """
    if not isinstance(row, dict) or 'row_count' not in row:
        raise ValueError('Store returned a malformed aggregate answer')
    unit = 'ms' if 'first_ms' in row else 'ns'
    first = row.get('first_ms' if unit == 'ms' else 'first_seen')
    last = row.get('last_ms' if unit == 'ms' else 'last_seen')
    answer = {'row_count': int(_number(row['row_count'])),
              'first_seen': '' if first is None else _instant(first, unit=unit),
              'last_seen': '' if last is None else _instant(last, unit=unit)}
    return presence_of(query.kind.signal, answer)


class ClickHouseStore(StoreClient):
    """The store facade over ClickHouse: named reads only, on the injected bounded client.

    The transport is injected rather than constructed here, so a test supplies a fake answer and a
    deployment supplies the credential — the same shape ``sigma_runner.tick`` and ``anomaly.tick``
    already use, and the reason this package adds no second HTTP client.
    """

    def __init__(self, query: ClickHouse) -> None:
        """Bind the facade to one already-validated read-only ClickHouse client."""
        if not isinstance(query, ClickHouse):
            raise TypeError('ClickHouseStore needs the bounded ClickHouse client, not a query string')
        self.client = query

    def read_metrics(self, query_type: str, *, window: Window, parameters: dict[str, str],
                     selectors: dict[str, str] | None = None, expires_at: str | None = None,
                     store_ttl_hours: int | None = None) -> ReadOutcome:
        """Read the samples behind a numeric verdict for one declared resource."""
        return self._read(query_type, 'metrics', window=window, parameters=parameters, selectors=selectors,
                          expires_at=expires_at, store_ttl_hours=store_ttl_hours)

    def read_logs(self, query_type: str, *, window: Window, parameters: dict[str, str],
                  selectors: dict[str, str] | None = None, expires_at: str | None = None,
                  store_ttl_hours: int | None = None) -> ReadOutcome:
        """Read log records, or the fact that a source produced any, for one declared resource."""
        return self._read(query_type, 'logs', window=window, parameters=parameters, selectors=selectors,
                          expires_at=expires_at, store_ttl_hours=store_ttl_hours)

    def read_traces(self, query_type: str, *, window: Window, parameters: dict[str, str],
                    selectors: dict[str, str] | None = None, expires_at: str | None = None,
                    store_ttl_hours: int | None = None) -> ReadOutcome:
        """Read spans for one service, slowest first."""
        return self._read(query_type, 'traces', window=window, parameters=parameters, selectors=selectors,
                          expires_at=expires_at, store_ttl_hours=store_ttl_hours)

    def describe(self, query_type: str, *, window: Window,
                 selectors: dict[str, str] | None = None) -> SignalPresence:
        """Report what the store holds for one signal in *window*, under the same bounds as a read."""
        kind = prepare(query_type, 'describe', {}, selectors)
        checked = check_selectors(kind, selectors)
        query = TEMPLATES[query_type]
        try:
            row = self.client.query(query.sql, bound_values(query, window, {}, checked))
            return presence_row(query, row)
        except (TransportError, ValueError, KeyError, TypeError) as exc:
            log.debug('Store describe refused', extra={'query_type': query_type,
                                                       'error_class': type(exc).__name__})
            raise TransportError('Store describe unavailable') from None

    def _read(self, query_type: str, signal: str, *, window: Window, parameters: dict[str, str],
              selectors: dict[str, str] | None, expires_at: str | None,
              store_ttl_hours: int | None) -> ReadOutcome:
        """Run one approved query and turn its rows into a verdict.

        The signal named by the method is checked against the signal the kind declares, so
        ``read_logs('metric-threshold', ...)`` is a refusal rather than a surprise. A row-set read
        that comes back empty asks its probe, so "nothing here" is the store's answer and not an
        assumption. Mapping failures become one `TransportError`: a store that answers in a shape the
        pinned schema does not have is unavailable, and neither the row text nor the credential ever
        reaches a log line.
        """
        kind = prepare(query_type, 'read', parameters, selectors)
        if kind.signal != signal:
            raise TransportError(f'{query_type} reads {kind.signal}, not {signal}')
        query = TEMPLATES[query_type]
        checked = check_parameters(kind, parameters)
        narrowing = check_selectors(kind, selectors)
        try:
            values = bound_values(query, window, checked, narrowing)
            if kind.max_rows == 1:
                presence = presence_row(query, self.client.query(query.sql, values))
                rows: list[Any] = [] if presence.row_count == 0 else [presence]
                series_exists = presence.row_count > 0
            else:
                raw = self.client._rows(query.sql, values, max_result_rows=kind.max_rows + 1)
                rows = [ROW_MAPS[query_type](item) for item in raw[:kind.max_rows]]
                series_exists = bool(rows) or self._selector_present(kind, window, checked, narrowing)
        except (TransportError, ValueError, KeyError, TypeError) as exc:
            log.debug('Bounded store read refused', extra={'query_type': query_type,
                                                           'error_class': type(exc).__name__})
            raise TransportError('Bounded store read refused or unavailable') from None
        return build_outcome(kind, checked, window, rows, expires_at=expires_at,
                             store_ttl_hours=store_ttl_hours, series_exists=series_exists)

    def _selector_present(self, kind: QueryKind, window: Window, parameters: dict[str, str],
                          selectors: dict[str, str]) -> bool:
        """Ask the store whether the selector exists at all; called only when a read found nothing.

        This is the line between an empty window and a series the store has never seen, and it is
        measured rather than inferred from the absence of rows. A probe that itself fails counts as
        absent: an unanswered question must never be reported as data.
        """
        # describe-metrics counts samples without resource labels. It cannot establish that
        # an empty metric join has metadata for this resource, even when other samples exist.
        if kind.query_type == 'metric-threshold' or kind.query_type not in PROBES:
            return False
        describe_type, probe_parameters, narrowing = probe_request(kind.query_type, parameters, selectors)
        probe = TEMPLATES[describe_type]
        try:
            return presence_row(probe, self.client.query(
                probe.sql, bound_values(probe, window, probe_parameters, narrowing))).row_count > 0
        except (TransportError, ValueError, KeyError, TypeError):
            return False


def store_from_environment(environ: Any = None) -> ClickHouseStore:
    """Build the facade from the same three variables the Sigma runner's component already sets.

    No new credential arrives here: the read-only query endpoint, the user name and the mounted
    password file are ``LO_CLICKHOUSE_URL``, ``LO_CLICKHOUSE_USER`` and
    ``LO_CLICKHOUSE_PASSWORD_FILE`` (``components/control/sigma/compose.yaml``), so a deployment that
    runs the runner already has what the facade needs and nothing else may be granted to it.
    """
    import os
    from local_observe.credentials import read_credential

    values = os.environ if environ is None else environ
    return ClickHouseStore(ClickHouse(values['LO_CLICKHOUSE_URL'], values['LO_CLICKHOUSE_USER'],
                                      read_credential('LO_CLICKHOUSE_PASSWORD', environ=values),
                                      allow_http=values.get('LO_INTERNAL_ALLOW_HTTP') == '1'))

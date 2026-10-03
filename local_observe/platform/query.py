"""The platform's query envelope: bounded reads, refusals that never read as an empty success.

Where this sits. The store seam is ``local_observe/store`` (store facade): ``store/client.py`` holds the
closed table of query kinds and the receipt/outcome rules, ``store/backends/clickhouse.py`` holds the
only SQL text and the only network call in the product. This module adds the three things that seam
deliberately left to the platform side, and no fourth:

* **the ``docs/CONTRACTS.md`` §2 envelope.** A producer gets one dict — ``source``, ``query_type``,
  ``parameters``, ``window``, ``rows``, ``row_limit``, ``truncated``, ``error`` — the same half-open
  UTC ``[start, end)`` pair ``detections.event()`` records on a canonical event. The store facade
  answers with a ``ReadOutcome`` (a receipt plus rows); this is the projection a detector, an RCA
  bundle or an MCP tool can serialise without importing the store package's types.
* **a read path that never raises into a producer's loop.** A ``StoreClient`` method raises
  ``StoreRefused``/``TransportError``; a long-running producer must instead emit a coverage-shaped
  result with ``error`` set and one log line, which is what ``metrics``/``logs``/``traces`` do and
  what ``refusal`` does for the case where no reader was ever built (no credential, unreachable
  endpoint). An unconfigured reader is a stated state, never a traceback two layers away.
* **reauthorisation of a stored reference.** ``reauthorise`` asks the platform's own SQLite evidence
  table what a reference is worth *now* — ``available`` / ``expired`` / ``unavailable``, the same
  three words ``state.Store.get_evidence`` returns. It takes no store client and issues no query:
  re-running one to back-fill a link that has aged out would turn a dead reference into fresh data
  wearing the old reference's identity, which is the opposite of what an evidence link is for.

What it does NOT do: it runs no query of its own, builds no SQL, holds no transport, and never falls
back from the analysis user to the Sigma runner's ``lo-query`` credential. That fallback would be
"silently raising the ceiling": a reader configured for multi-row analysis would authenticate as the
aggregate-only user whose profile pins ``max_result_rows`` to 1
(``components/data/store-signoz/clickhouse-users.d/lo-query.xml``) and would report its own
misconfiguration as an empty window. Missing read credentials refuse, and say which variable is empty.

Row payload or reference? Both halves exist on purpose and neither is invented here. A caller that
wants *rows now* uses the envelope below; a caller that wants *proof later* keeps the facade's
``ReadOutcome``, files ``outcome.as_evidence(source)`` as the event's evidence and ``outcome.as_sample``
with ``Store.put_evidence``, and re-reads that link through ``reauthorise``. This module does not
re-implement ``as_evidence`` — widening what intake admits as proof is ``state.validate_event``'s call
(``docs/CONTRACTS.md`` §4), not a read option.
"""
from __future__ import annotations

import datetime as dt
import os
from collections.abc import Mapping
from typing import Any, Protocol
from dataclasses import fields, is_dataclass

from local_observe.credentials import read_credential
from local_observe.http import TransportError
from local_observe.log import get_logger
from local_observe.store.backends.clickhouse import ClickHouse, ClickHouseStore
from local_observe.store.client import LABEL, QUERY_KINDS, StoreClient, StoreRefused, Window

log = get_logger(__name__)

#: The eight keys every envelope carries, in the order ``docs/CONTRACTS.md`` §2 lists them. A read
#: that could not happen and a read that answered honestly differ in exactly one of them: ``error``.
ENVELOPE_FIELDS: tuple[str, ...] = ('source', 'query_type', 'parameters', 'window', 'rows', 'row_limit',
                                    'truncated', 'error')
#: The three verdicts ``state.Store.get_evidence`` answers with. Restated here, not imported, so a
#: caller of this module can branch on them without importing the platform's SQLite layer.
EVIDENCE_STATUSES = ('available', 'expired', 'unavailable')

# The analysis reader's own three variables. The endpoint is the runner's (`LO_CLICKHOUSE_URL`): store boundaries
# gives the product one telemetry store, so a second endpoint variable would be a second store.
READ_URL_VARIABLE = 'LO_CLICKHOUSE_URL'
READ_USER_VARIABLE = 'LO_CLICKHOUSE_READ_USER'
READ_PASSWORD_VARIABLE = 'LO_CLICKHOUSE_READ_PASSWORD'
ALLOW_HTTP_VARIABLE = 'LO_INTERNAL_ALLOW_HTTP'
#: The user ``clickhouse-users.d/lo-read.xml`` creates. A name, not a secret — the sibling user's
#: name is likewise defaulted in ``components/control/sigma/compose.yaml`` — but overridable, because
#: an operator who renames the fragment's user must not have to patch this module.
ANALYSIS_USER_DEFAULT = 'lo-read'

# A parameter value this module will echo into an envelope. The same shape `store.client` checks and
# intake admits; anything else is replaced by the placeholder rather than repeated, because a refused
# value is exactly the text an attacker or a typo produced and an envelope lands in an incident.
ECHO_REFUSAL = '<invalid>'
#: `store.client.ReadReceipt` admits at most ten named parameters; an envelope echoes no more.
MAX_ECHOED_PARAMETERS = 10
# Words that mean "someone tried to hand this module a statement". They are not a parser: an
# unapproved name is refused regardless, this only makes the reason honest instead of a list.
SQL_MARKERS = ('select ', 'insert ', 'update ', 'delete ', 'drop ', 'alter ', 'create ', 'truncate ',
               'from ', ';', '--')


class EvidenceStore(Protocol):
    """The half of ``platform.state.Store`` this module uses: reauthorise one stored sample."""

    def get_evidence(self, source: str, sample_id: str, *,
                     now: dt.datetime | None = None) -> dict[str, Any]:
        """Return ``{'status'}``, plus ``sample``/``expires_at`` when the row is still valid."""


def metrics(store: StoreClient | None, source: str, query_type: str, *, window: Window | Mapping[str, str],
            parameters: Mapping[str, str], selectors: Mapping[str, str] | None = None,
            expires_at: str | None = None, store_ttl_hours: int | None = None) -> dict[str, Any]:
    """Read the metric side of *store* as an envelope; see `_read` for the rules that never change.

    *query_type* is a name from ``store.client.QUERY_KINDS`` (``metric-threshold`` today), never a
    statement. A returned envelope carries ``rows`` only when the store answered, and ``error`` is
    non-``None`` for every other case: a refused request, a store that did not answer, and a series
    the store has never seen are three readings of one field, and none of them is an empty success.
    """
    return _read(store, 'read_metrics', source, query_type, window=window, parameters=parameters,
                 selectors=selectors, expires_at=expires_at, store_ttl_hours=store_ttl_hours)


def logs(store: StoreClient | None, source: str, query_type: str, *, window: Window | Mapping[str, str],
         parameters: Mapping[str, str], selectors: Mapping[str, str] | None = None,
         expires_at: str | None = None, store_ttl_hours: int | None = None) -> dict[str, Any]:
    """Read the log side of *store* as an envelope (`source-heartbeat`, `log-records`)."""
    return _read(store, 'read_logs', source, query_type, window=window, parameters=parameters,
                 selectors=selectors, expires_at=expires_at, store_ttl_hours=store_ttl_hours)


def traces(store: StoreClient | None, source: str, query_type: str, *, window: Window | Mapping[str, str],
           parameters: Mapping[str, str], selectors: Mapping[str, str] | None = None,
           expires_at: str | None = None, store_ttl_hours: int | None = None) -> dict[str, Any]:
    """Read the trace side of *store* as an envelope (`trace-spans`, slowest first)."""
    return _read(store, 'read_traces', source, query_type, window=window, parameters=parameters,
                 selectors=selectors, expires_at=expires_at, store_ttl_hours=store_ttl_hours)


def _read(store: StoreClient | None, method: str, source: str, query_type: str, *,
          window: Window | Mapping[str, str], parameters: Mapping[str, str],
          selectors: Mapping[str, str] | None, expires_at: str | None,
          store_ttl_hours: int | None) -> dict[str, Any]:
    """Run one named read and return its envelope, turning every failure into ``error`` text.

    The order is the contract: refuse caller-supplied SQL, refuse a window intake would reject,
    refuse a store that was never configured, and only then ask. Nothing below this function raises
    to a producer's loop — every exception class listed in the ``except`` is the store package's way
    of naming a refusal, and each becomes one envelope plus one log line naming the class, never the
    statement, the credential or a row.
    """
    base: dict[str, Any] = {'source': source, 'query_type': query_type, 'parameters': _echo(parameters),
                            'window': {}, 'row_limit': row_limit(query_type), 'truncated': False}
    if looks_like_sql(query_type):
        return _finish(base, (), 'refused: a query kind is a name from the approved table, never SQL')
    try:
        pair = window if isinstance(window, Window) else Window(str(window['start']), str(window['end']))
    except (StoreRefused, KeyError, TypeError, ValueError) as exc:
        return _finish(base, (), _reason(exc))
    base['window'] = pair.as_dict()
    if store is None:
        log.warning('Store read refused; no read-only client is configured',
                    extra={'source': source, 'query_type': query_type})
        return _finish(base, (), 'unavailable: no read-only store client (see query.open_reader)')
    try:
        outcome = getattr(store, method)(query_type, window=pair, parameters=dict(parameters),
                                         selectors=dict(selectors or {}), expires_at=expires_at,
                                         store_ttl_hours=store_ttl_hours)
    except (StoreRefused, TransportError, ValueError, KeyError, TypeError) as exc:
        log.warning('Store read refused', extra={'source': source, 'query_type': query_type,
                                                 'error_class': type(exc).__name__})
        return _finish(base, (), _reason(exc))
    return envelope_of(outcome, source)


def envelope_of(outcome: Any, source: str) -> dict[str, Any]:
    """Project one ``store.client.ReadOutcome`` onto the §2 envelope, keeping its verdict.

    ``available`` with no rows is an honest empty window and stays ``error=None``; ``unavailable``
    carries the store's own reason, prefixed with the verdict word so a reader never has to guess
    which of the two it is looking at. ``source`` is the producer identity, not a store name — the
    same meaning it has in an evidence reference (§4).
    """
    receipt = outcome.receipt
    error = None if outcome.status == 'available' else f'{outcome.status}: {outcome.detail or "no reason"}'
    if error is not None:
        log.info('Store read answered without rows', extra={'source': source, 'query_type': receipt.query_type,
                                                            'status': outcome.status})
    return {'source': source, 'query_type': receipt.query_type, 'parameters': _echo(receipt.parameters),
            'window': receipt.window.as_dict(), 'rows': tuple(jsonable(row) for row in outcome.samples),
            'row_limit': row_limit(receipt.query_type), 'truncated': receipt.truncated, 'error': error}


def refusal(source: str, query_type: str, *, window: Window | Mapping[str, str],
            parameters: Mapping[str, str], error: str) -> dict[str, Any]:
    """Build the envelope for a read that was never attempted, so a producer emits coverage, not silence.

    This is the shape ``docs/COMPONENTS.md``'s "If disabled" clause needs: the Sigma runner and the
    anomaly producer can post an event whose evidence says *this was refused and why*, instead of
    posting nothing. *error* must be non-empty — a refusal with no reason is an empty success wearing
    a different coat — and a bad *window* is refused here rather than carried into an event intake
    will reject.
    """
    if not isinstance(error, str) or not error.strip():
        raise ValueError('A refusal envelope must name its reason')
    try:
        pair = window if isinstance(window, Window) else Window(str(window['start']), str(window['end']))
    except (StoreRefused, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f'Refusal envelope window is invalid: {_reason(exc)}') from None
    return _finish({'source': source, 'query_type': query_type, 'parameters': _echo(parameters),
                    'window': pair.as_dict(), 'row_limit': row_limit(query_type), 'truncated': False},
                   (), error.strip())


def open_reader(*, environ: Mapping[str, str] | None = None,
                max_response_bytes: int | None = None) -> ClickHouseStore | None:
    """Return the analysis reader the environment configures, or ``None`` after one log line.

    Never raises: a producer that starts without a query path must still emit coverage events
    (``docs/COMPONENTS.md``: "UI works; platform analysis unavailable"), and SigNoz's own UI is
    untouched either way because it never uses this path. Four refusals, each logged once naming the
    variable and never its value: no endpoint, an endpoint the bounded client will not accept
    (plaintext ``http://`` without ``LO_INTERNAL_ALLOW_HTTP=1``, embedded credentials, a query
    string), a user name outside the bounded label shape, and a missing, unreadable or blank
    credential. There is no fallback to ``LO_CLICKHOUSE_PASSWORD`` — see the module docstring.
    """
    values = os.environ if environ is None else environ
    url = str(values.get(READ_URL_VARIABLE) or '').strip()
    if not url:
        return _reads_off(f'{READ_URL_VARIABLE} names no read-only endpoint')
    user = str(values.get(READ_USER_VARIABLE) or ANALYSIS_USER_DEFAULT).strip()
    if not LABEL.fullmatch(user):
        return _reads_off(f'{READ_USER_VARIABLE} is not a bounded label')
    try:
        password = read_credential(READ_PASSWORD_VARIABLE, environ=values)
    except (KeyError, OSError, ValueError) as exc:
        return _reads_off(f'{READ_PASSWORD_VARIABLE} (or its _FILE form) names no readable credential',
                          error=exc)
    if not password.strip():
        return _reads_off(f'{READ_PASSWORD_VARIABLE} is set and blank')
    try:
        bounds = {} if max_response_bytes is None else {'max_response_bytes': max_response_bytes}
        client = ClickHouse(url, user, password, allow_http=values.get(ALLOW_HTTP_VARIABLE) == '1', **bounds)
    except ValueError as exc:
        return _reads_off(f'{READ_URL_VARIABLE} is an endpoint this bounded client will not post to '
                          f'(plaintext http needs {ALLOW_HTTP_VARIABLE}=1)', error=exc)
    return ClickHouseStore(client)


def _reads_off(reason: str, *, error: BaseException | None = None) -> None:
    """Log the one line that says reads are off, name the variable, and give the caller nothing to hold.

    The variable is in the message rather than only in ``extra`` because the message is what an
    operator reads in a container log, and because a refusal diagnosable only at DEBUG level gets
    diagnosed by restarting the container with more logging instead. No value, URL or exception text
    is logged — only the class name, which is what ``local_observe/log.py`` asks of a call site.
    """
    if error is None:
        log.warning('Store reads are off; ' + reason)
    else:
        log.warning('Store reads are off; ' + reason, extra={'error_class': type(error).__name__})
    return None


def reauthorise(state: EvidenceStore, reference: Mapping[str, Any], *, sample_id: str | None = None,
                now: dt.datetime | None = None) -> dict[str, Any]:
    """Return what one stored evidence reference is worth now, from the platform's own state.

    Takes the platform store and the reference and *nothing else*: no ``StoreClient`` is accepted
    here, on purpose, so this function cannot quietly re-query the store to make a dead link look
    alive. ``sample_id`` is what the platform's evidence row is keyed on
    (``state.put_evidence``/``get_evidence``): taken from *reference*'s own parameters unless the
    caller names it, which a producer must do for a facade read, because no `store.client` query kind
    declares ``sample_id`` as an evidence parameter today — the sample an incident cites is the one
    the producer kept (`ReadOutcome.as_sample`), and the reference names the rule behind it. A
    reference that yields no sample id at all was never a stored sample and is reported
    ``unavailable`` with that reason, rather than looked up under an empty key.

    The reply is always the four keys ``status``/``sample``/``expires_at``/``detail``, ``status``
    one of `EVIDENCE_STATUSES`. An expired reference stays expired: the answer carries no sample and
    the detail says so.
    """
    if not isinstance(reference, Mapping):
        return _verdict('unavailable', detail='an evidence reference is a mapping of the fields §4 admits')
    parameters = reference.get('parameters')
    source = reference.get('source')
    if not isinstance(source, str) or not LABEL.fullmatch(source):
        return _verdict('unavailable', detail='evidence reference names no bounded source')
    if not isinstance(parameters, Mapping):
        return _verdict('unavailable', detail='evidence reference names no parameters mapping')
    if sample_id is None:
        sample_id = parameters.get('sample_id')
    if not isinstance(sample_id, str) or not LABEL.fullmatch(sample_id):
        return _verdict('unavailable',
                        detail='reference cites no stored sample_id; nothing was retained to reauthorise')
    try:
        fetched = state.get_evidence(source, sample_id, now=now)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        log.warning('Evidence reauthorisation failed', extra={'source': source,
                                                              'error_class': type(exc).__name__})
        return _verdict('unavailable', detail='the platform state could not answer for this reference')
    if not isinstance(fetched, Mapping) or fetched.get('status') not in EVIDENCE_STATUSES:
        return _verdict('unavailable', detail='the evidence store answered with an unknown verdict')
    status = str(fetched['status'])
    if status != 'available':
        return _verdict(status, detail=f'{status}; the adapter does not re-query the store to back-fill it')
    return _verdict('available', sample=fetched.get('sample'), expires_at=fetched.get('expires_at'),
                    detail='the retained sample is still within its retention')


def row_limit(query_type: str) -> int:
    """Return the row bound the named kind carries, or ``0`` when nothing names it.

    ``0`` rather than a default cap is the point: an envelope whose ``row_limit`` is zero states "no
    approved query answered this", so a caller cannot mistake a refusal for a query that ran and
    found fewer rows than it asked for.
    """
    kind = QUERY_KINDS.get(query_type) if isinstance(query_type, str) else None
    return kind.max_rows if kind is not None else 0


def looks_like_sql(query_type: str) -> bool:
    """Whether *query_type* is shaped like a statement rather than one of the seven approved names.

    A statement never reaches the transport from here for a stronger reason than this check — the
    store package builds its SQL from a table keyed by kind, and there is no parameter that accepts
    text to run. This guard exists so the *refusal message* says "that is SQL" instead of "unknown
    query kind", because a caller that passes SQL will read the second message as a lookup bug.
    """
    if not isinstance(query_type, str):
        return False
    text = query_type.lower()
    return any(marker in text for marker in SQL_MARKERS)


def jsonable(row: Any) -> Any:
    """Return one store row as JSON-safe data: the dataclass's own fields, flattened one level.

    ``store.client`` answers reads with frozen dataclasses (``MetricSample``, ``LogRecord``,
    ``TraceSpan``, ``SignalPresence``). An envelope is what goes into a bundle, a portal payload or
    an MCP tool result, so the conversion happens once here rather than at every consumer; a caller
    that wants the objects reads them from the ``ReadOutcome`` it built this envelope from.
    """
    if is_dataclass(row) and not isinstance(row, type):
        return {item.name: _scalar(getattr(row, item.name)) for item in fields(row)}
    return _scalar(row)


def _scalar(value: Any) -> Any:
    """Return a row field unchanged when it is JSON-safe, and its text when it is not."""
    if value is None or isinstance(value, (str, bool, int, float, list, dict)):
        return value
    return str(value)


def _echo(parameters: Mapping[str, Any]) -> dict[str, str]:
    """Return *parameters* with values that are not bounded labels replaced by a placeholder.

    Echoing a rejected value into an envelope puts it inside an event, a bundle and possibly a
    portal page. The name is kept — it is the reason the read was refused — and the value is not.
    """
    if not isinstance(parameters, Mapping):
        return {}
    echoed: dict[str, str] = {}
    for key in sorted(parameters)[:MAX_ECHOED_PARAMETERS]:
        value = parameters[key]
        echoed[str(key)] = value if isinstance(value, str) and LABEL.fullmatch(value) else ECHO_REFUSAL
    return echoed


def _finish(base: dict[str, Any], rows: tuple[Any, ...], error: str | None) -> dict[str, Any]:
    """Close an envelope with its rows and verdict, and pin its key set in one place."""
    envelope = {**base, 'rows': rows, 'error': error}
    return {key: envelope[key] for key in ENVELOPE_FIELDS}


def _verdict(status: str, *, sample: Any = None, expires_at: str | None = None,
             detail: str = '') -> dict[str, Any]:
    """Return one ``reauthorise`` reply: the status, and the retained sample only when it is valid."""
    return {'status': status, 'sample': sample if status == 'available' else None,
            'expires_at': expires_at if status == 'available' else None, 'detail': detail}


def _reason(exc: BaseException) -> str:
    """Return a bounded, secret-free reason for one refusal.

    ``StoreRefused``/``TransportError`` text is written by this repository and names rules, not data
    (``store.client`` and ``store.backends.clickhouse`` both keep it that way), so it is quoted.
    Anything else — a ``KeyError`` whose argument is a caller's field name, a ``TypeError`` naming a
    value — contributes only its class name, which is what ``local_observe/log.py`` asks of call
    sites for the same reason.
    """
    if isinstance(exc, (StoreRefused, TransportError)):
        return f'refused: {str(exc)[:300]}'
    return f'failed: {type(exc).__name__}'

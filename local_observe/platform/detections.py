"""Baseline availability, threshold and source-coverage verdicts; no AI dependency."""
import datetime as dt
import math
from pathlib import Path
from typing import Any

from local_observe.inventory import index
from local_observe.inventory.validation import digest, timestamp, utc_text
from .state import StateError, identifier, label
from .assertions import condition_report


def event(source: str, resource_id: str | None, rule_id: str, kind: str, status: str,
          window: dict[str, str], parameters: dict[str, Any], *, query_type: str,
          observed_at: str | None = None, version: str = '1',
          severity: str | None = None) -> dict[str, Any]:
    """Build one canonical event; `severity` is derived from the verdict unless the caller names it.

    The default keeps every existing detector's shape — a firing verdict is a `warning` and a
    resolved one is `info`. A producer that measures *how far* outside a condition it is (the
    anomaly baseline, event kinds) passes the severity it computed from that size; an invalid name is a
    refusal here rather than a 400 from intake two layers away.
    """
    label(source)
    label(rule_id)
    if severity is not None and severity not in ('info', 'warning', 'critical'):
        raise StateError('Invalid event severity')
    return {'schema_version': 1, 'source': source, 'source_event_id': digest([rule_id, version, resource_id, window]),
            'resource_id': resource_id, 'observed_at': observed_at or window['end'], 'kind': kind,
            'severity': severity or ('warning' if status != 'resolved' else 'info'), 'data_class': 'internal',
            'evidence': [{'source': source, 'query_type': query_type, 'parameters': parameters,
                          'window': window, 'schema_version': 1,
                          'expires_at': utc_text(timestamp(window['end']) + dt.timedelta(days=15))}],
            'rule_id': rule_id, 'rule_version': version, 'window': window, 'condition': rule_id, 'status': status}


def evaluate(index_path: Path | str, rule: dict[str, Any], sample: dict[str, Any] | None, *,
             now: dt.datetime, window_seconds: int = 60) -> list[dict[str, Any]]:
    """None/failed/stale input opens coverage, never recovers the underlying condition."""
    if set(rule) - {'id', 'kind', 'resource_id', 'source', 'max_age_seconds', 'threshold'}:
        raise StateError('Unknown rule configuration')
    identifier(rule['resource_id'])
    label(rule['id'])
    label(rule['source'])
    age_limit = rule.get('max_age_seconds', 120)
    if not 1 <= age_limit <= 86400 or not 1 <= window_seconds <= 3600:
        raise StateError('Invalid rule window/freshness')
    if rule['kind'] not in ('availability', 'threshold'):
        raise StateError('Unsupported baseline rule')
    with index.readonly(index_path) as connection:
        if index.resolve(connection, resource_id=rule['resource_id'])['status'] != 'resolved':
            raise StateError('Detection resource is not declared')
    end = dt.datetime.fromtimestamp(int(now.timestamp()) // window_seconds * window_seconds, dt.timezone.utc)
    window = {'start': utc_text(end - dt.timedelta(seconds=window_seconds)), 'end': utc_text(end)}
    fresh = False
    if sample is not None:
        if set(sample) != {'sample_id', 'observed_at', 'ok', 'value'} or not isinstance(sample['ok'], bool):
            raise StateError('Invalid sample contract')
        label(sample['sample_id'])
        age = (end - timestamp(sample['observed_at'])).total_seconds()
        fresh = sample['ok'] and 0 <= age <= age_limit
    parameters = {'sample_id': sample['sample_id']} if sample else {'rule_id': rule['id']}
    coverage = event(rule['source'], rule['resource_id'], rule['id'] + '.coverage', 'coverage',
                     'resolved' if fresh else 'firing', window, parameters, query_type='source-heartbeat')
    if not fresh:
        return [coverage]
    value = sample['value']
    if rule['kind'] == 'availability':
        if not isinstance(value, bool):
            raise StateError('Availability requires a boolean verdict')
        firing = not value
        query_type = 'gatus-result'
    else:
        threshold = rule.get('threshold')
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v)
               for v in (value, threshold)):
            raise StateError('Threshold requires finite numeric values')
        firing = value > threshold
        query_type = 'metric-threshold'
    finding = event(rule['source'], rule['resource_id'], rule['id'], rule['kind'],
                    'firing' if firing else 'resolved', window, parameters, query_type=query_type,
                    observed_at=sample['observed_at'])
    return [coverage, finding]


def _gatus_row(payload: Any, *, before: dt.datetime) -> dict[str, Any] | None:
    """Read the newest completed Gatus result no later than the evaluation watermark."""
    if not isinstance(payload, dict) or not isinstance(payload.get('results'), list) or len(payload['results']) > 1000:
        raise StateError('Unsupported Gatus result envelope')
    results = [row for row in payload['results']
               if isinstance(row, dict) and 'timestamp' in row and timestamp(row['timestamp']) <= before]
    if not results:
        return None
    row = max(results, key=lambda item: timestamp(item['timestamp']))
    if not isinstance(row.get('success'), bool):
        raise StateError('Missing Gatus boolean success')
    return row


def gatus_sample(payload: Any, *, before: dt.datetime) -> dict[str, Any] | None:
    """Legacy four-field sample, unchanged when named attribution is not configured."""
    row = _gatus_row(payload, before=before)
    if row is None:
        return None
    return {'sample_id': digest(row), 'observed_at': row['timestamp'], 'ok': True, 'value': row['success']}


def gatus_assertion_samples(payload: Any, mapping: dict[str, str], *, before: dt.datetime,
                            source: str, rule_id: str) -> tuple[dict[str, Any] | None, list]:
    """Return only safe four-field samples; never retain upstream expressions/response text."""
    row = _gatus_row(payload, before=before)
    if row is None:
        return None, []
    report = condition_report(row, mapping)
    named = []
    for result in report.results:
        measured = result.detail != 'not measured'
        sample = {'observed_at': row['timestamp'], 'ok': measured,
                  'value': result.ok if measured else None}
        sample['sample_id'] = digest([source, rule_id, result.name, sample])
        named.append((result.name, sample))
    aggregate = {'observed_at': row['timestamp'], 'ok': True,
                 'value': row['success'] and report.ok}
    aggregate['sample_id'] = digest([source, rule_id, aggregate, named])
    return aggregate, named

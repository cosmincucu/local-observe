"""Strict configuration, evidence and model contracts; input text grants no authority."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from local_observe.inventory.validation import is_secret_key


class ObserverError(ValueError):
    """A public, payload-free diagnostic code."""


def require(ok: bool, code: str) -> None:
    if not ok:
        raise ObserverError(code)


def encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def strict_json(raw: str | bytes, limit: int = 65536, *, max_depth: int = 12) -> Any:
    require(len(raw.encode('utf-8') if isinstance(raw, str) else raw) <= limit, 'json_too_large')

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result

    def constant(_value):
        raise ObserverError('nonfinite_json')

    try:
        result = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        bounded(result, max_depth=max_depth)
        return result
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise ObserverError('invalid_json') from exc


def bounded(value: Any, depth: int = 0, *, max_depth: int = 12) -> None:
    require(depth <= max_depth, 'structure_too_deep')
    if isinstance(value, dict):
        require(len(value) <= 256 and all(isinstance(k, str) and len(k) <= 128 for k in value),
                'invalid_object')
        for child in value.values():
            bounded(child, depth + 1, max_depth=max_depth)
    elif isinstance(value, list):
        require(len(value) <= 2000, 'too_many_items')
        for child in value:
            bounded(child, depth + 1, max_depth=max_depth)
    elif isinstance(value, str):
        require(len(value) <= 8192, 'string_too_long')
    elif isinstance(value, float):
        require(math.isfinite(value), 'nonfinite_number')
    else:
        require(value is None or type(value) in (int, bool), 'invalid_value')


def fields(value: Any, required: set[str], optional: set[str] = frozenset()) -> None:
    require(isinstance(value, dict) and required <= set(value) <= required | optional, 'invalid_fields')


def name(value: Any) -> str:
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', value) is not None,
            'invalid_identifier')
    return value


def instant(value: Any) -> dt.datetime:
    require(isinstance(value, str) and len(value) <= 40, 'invalid_timestamp')
    try:
        parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(parsed.tzinfo is not None, 'timezone_required')
        return parsed.astimezone(dt.timezone.utc)
    except ValueError as exc:
        raise ObserverError('invalid_timestamp') from exc


def utc(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def digest(value: Any) -> str:
    return hashlib.sha256(encoded(value).encode('utf-8')).hexdigest()


_SECRET_TEXT = re.compile(
    r'(?i)(\b(?:password|passwd|token|api[_-]?key|secret|authorization)\b\s*[=:]\s*)'
    r'(?:"[^"\n]*"|\'[^\'\n]*\'|(?:Bearer\s+)?[^\s,;]+)|\bBearer\s+[^\s,;]+|'
    r'(?<=://)[^\s/@]+:[^\s/@]+@')


def redact(value: Any, secrets: tuple[str, ...] = ()) -> Any:
    """Scrub secret fields, credential assignments and known mounted credentials before storage."""
    if isinstance(value, dict):
        return {k: '<redacted>' if is_secret_key(k) else redact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, '<redacted>')
        return _SECRET_TEXT.sub('<redacted>', value)
    return value


@dataclass(frozen=True)
class Source:
    id: str
    query_type: str
    resource_id: str
    adapter: str = 'store'
    initial: bool = True
    metric_name: str = ''
    path: str = ''
    base_url: str = ''
    credential_file: str = ''
    allow_http: bool = False
    data_class: str | None = None

    def __post_init__(self):
        require(all(isinstance(v, str) for v in (self.id, self.query_type, self.resource_id, self.adapter,
                                                self.metric_name, self.path, self.base_url, self.credential_file)),
                'invalid_source_string')
        name(self.id)
        require(self.query_type in ('metric-threshold', 'log-records'), 'unknown_query')
        try:
            require(str(uuid.UUID(self.resource_id)) == self.resource_id, 'invalid_resource_id')
        except (ValueError, TypeError, AttributeError) as exc:
            raise ObserverError('invalid_resource_id') from exc
        require(self.adapter in ('store', 'file', 'http'), 'unknown_adapter')
        require(self.data_class in (None, 'public', 'internal', 'restricted'), 'invalid_source_data_class')
        require(type(self.initial) is bool and type(self.allow_http) is bool, 'invalid_source_flag')
        if self.metric_name:
            name(self.metric_name)
        require(self.query_type != 'metric-threshold' or bool(self.metric_name), 'metric_name_required')
        if self.adapter == 'file':
            require(isinstance(self.path, str) and Path(self.path).is_absolute(), 'absolute_source_path_required')
        if self.adapter == 'http':
            parsed = urlsplit(self.base_url)
            require(parsed.scheme in (('https', 'http') if self.allow_http else ('https',))
                    and bool(parsed.hostname) and not parsed.username and not parsed.password
                    and not parsed.query and not parsed.fragment and parsed.path in ('', '/'), 'invalid_endpoint')
            require(re.fullmatch(r'/[A-Za-z0-9/_-]+', self.path or '') is not None, 'invalid_api_path')
            require(bool(self.credential_file) and Path(self.credential_file).is_absolute(),
                    'credential_file_required')
        require(self.adapter == 'http' or not (self.base_url or self.credential_file or self.allow_http),
                'unused_source_configuration')
        require(self.adapter != 'store' or not self.path, 'unused_source_configuration')


@dataclass(frozen=True)
class Config:
    sources: tuple[Source, ...]
    schema_version: int = 1
    cadence_seconds: int = 3600
    window_seconds: int = 3600
    max_sources: int = 8
    max_result_bytes: int = 65536
    max_model_calls: int = 2
    max_cycle_seconds: int = 120
    max_rows: int = 200
    max_age_seconds: int = 900
    data_class: str = 'internal'
    mode: str = 'shadow'
    retrieval_examples: int = 0
    retrieval_bytes: int = 8192

    def __post_init__(self):
        require(type(self.schema_version) is int and self.schema_version == 1, 'unsupported_config_version')
        bounds = {'cadence_seconds': (60, 86400), 'window_seconds': (60, 86400), 'max_sources': (1, 20),
                  'max_result_bytes': (1024, 65536), 'max_model_calls': (0, 4),
                  'max_cycle_seconds': (1, 600), 'max_rows': (1, 2000), 'max_age_seconds': (1, 86400),
                  'retrieval_examples': (0, 10), 'retrieval_bytes': (512, 16384)}
        for key, (low, high) in bounds.items():
            value = getattr(self, key)
            require(type(value) is int and low <= value <= high, 'invalid_' + key)
        require(isinstance(self.sources, tuple) and 1 <= len(self.sources) <= 20
                and all(isinstance(s, Source) for s in self.sources), 'invalid_sources')
        require(len({s.id for s in self.sources}) == len(self.sources), 'duplicate_source')
        require(any(s.initial for s in self.sources), 'initial_source_required')
        require(self.data_class in ('public', 'internal', 'restricted'), 'invalid_data_class')
        require(self.mode in ('shadow', 'recording'), 'delivery_requires_independent_evaluation')

    @classmethod
    def from_dict(cls, value: Any) -> Config:
        from dataclasses import fields as dataclass_fields
        allowed = {f.name for f in dataclass_fields(cls)}
        fields(value, {'schema_version', 'sources'}, allowed - {'schema_version', 'sources'})
        require(isinstance(value['sources'], list), 'invalid_sources')
        sources = []
        source_fields = {f.name for f in dataclass_fields(Source)}
        for source in value['sources']:
            fields(source, {'id', 'query_type', 'resource_id'}, source_fields - {'id', 'query_type', 'resource_id'})
            sources.append(Source(**source))
        return cls(**{**value, 'sources': tuple(sources)})


def snapshot(source: Source, raw: Any, window: dict, config: Config, now: dt.datetime,
             secrets: tuple[str, ...] = ()) -> dict:
    """Validate a normalized source envelope and retain only its redacted content."""
    bounded(raw)
    require(len(encoded(raw).encode()) <= config.max_result_bytes, 'result_too_large')
    fields(raw, {'schema_version', 'source', 'query_type', 'resource_id', 'window', 'observed_at', 'rows'},
           {'truncated'})
    require(type(raw['schema_version']) is int and raw['schema_version'] == 1, 'unsupported_evidence_version')
    require(raw['source'] == source.id and raw['query_type'] == source.query_type
            and raw['resource_id'] == source.resource_id and raw['window'] == window, 'evidence_provenance_mismatch')
    observed = instant(raw['observed_at'])
    require(0 <= (now - observed).total_seconds() <= config.max_age_seconds, 'stale_observation')
    require(type(raw.get('truncated', False)) is bool, 'invalid_truncation')
    rows = raw['rows']
    require(isinstance(rows, list) and len(rows) <= config.max_rows, 'invalid_rows')
    start, end = instant(window['start']), instant(window['end'])
    for row in rows:
        if source.query_type == 'metric-threshold':
            fields(row, {'timestamp', 'value', 'labels'}, {'resource_id'})
            require(type(row['value']) in (int, float) and math.isfinite(row['value']), 'invalid_metric_value')
        else:
            fields(row, {'timestamp', 'body', 'labels'}, {'severity', 'resource_id'})
            require(isinstance(row['body'], str), 'invalid_log_body')
            require('severity' not in row or isinstance(row['severity'], str), 'invalid_severity')
        require(start <= instant(row['timestamp']) < end, 'sample_outside_window')
        require(isinstance(row['labels'], dict), 'invalid_labels')
        require('resource_id' not in row or row['resource_id'] == source.resource_id, 'row_resource_mismatch')
        for key in ('resource_id', 'resource.id'):
            require(key not in row['labels'] or row['labels'][key] == source.resource_id, 'row_resource_mismatch')
    if rows:
        latest = max(instant(row['timestamp']) for row in rows)
        require((now - latest).total_seconds() <= config.max_age_seconds, 'stale_samples')
    result = redact(raw, secrets)
    result['metric_name'] = source.metric_name
    classes = ('public', 'internal', 'restricted')
    result['data_class'] = max((config.data_class, source.data_class or config.data_class), key=classes.index)
    result['coverage'] = 'partial' if not rows or raw.get('truncated') else 'complete'
    # A 64-character digest also survives the AI remote policy's bounded-identifier projection.
    result['evidence_id'] = digest(result)
    return result


def model_answer(raw: str, evidence: list[dict], allowed: set[str]) -> dict:
    """Validate exact row/field/value citations; prose remains an unverified model claim."""
    answer = strict_json(raw, 16384)
    fields(answer, {'schema_version', 'decision', 'rationale', 'citations', 'follow_up'}, {'findings'})
    require(type(answer['schema_version']) is int and answer['schema_version'] == 1, 'unsupported_answer_version')
    require(answer['decision'] in ('quiet', 'watch', 'tell'), 'invalid_decision')
    require(isinstance(answer['rationale'], str) and 1 <= len(answer['rationale']) <= 4000, 'invalid_rationale')
    require(isinstance(answer['follow_up'], list) and len(answer['follow_up']) <= 20
            and all(isinstance(s, str) and s in allowed for s in answer['follow_up']), 'unknown_follow_up')
    require(len(set(answer['follow_up'])) == len(answer['follow_up']), 'duplicate_follow_up')
    citations = answer['citations']
    require(isinstance(citations, list) and 1 <= len(citations) <= 40, 'citations_required')
    indexed = {item['evidence_id']: item for item in evidence}
    for citation in citations:
        fields(citation, {'evidence_id', 'row_index', 'field', 'value'})
        require(isinstance(citation['evidence_id'], str) and citation['evidence_id'] in indexed, 'unknown_evidence')
        rows = indexed[citation['evidence_id']]['rows']
        index = citation['row_index']
        require(type(index) is int and 0 <= index < len(rows), 'unknown_evidence_row')
        key = citation['field']
        require(isinstance(key, str) and key in ('timestamp', 'value', 'body', 'severity', 'labels')
                and key in rows[index], 'unknown_evidence_field')
        require(encoded(citation['value']) == encoded(rows[index][key]), 'forged_citation')
    findings = answer.get('findings', [])
    require(isinstance(findings, list) and len(findings) <= 20, 'invalid_findings')
    require(answer['decision'] != 'quiet' or not findings, 'quiet_has_findings')
    cited = {citation['evidence_id'] for citation in citations}
    for finding in findings:
        fields(finding, {'resource_id', 'kind', 'observed_at', 'evidence_ids'})
        require(finding['kind'] in ('availability', 'coverage', 'threshold', 'drift', 'anomaly', 'security'),
                'invalid_finding_kind')
        ids = finding['evidence_ids']
        require(isinstance(ids, list) and 1 <= len(ids) <= 20
                and all(isinstance(i, str) and i in cited for i in ids), 'invalid_finding_evidence')
        require(len(set(ids)) == len(ids), 'duplicate_finding_evidence')
        observed = instant(finding['observed_at'])
        for evidence_id in ids:
            item = indexed[evidence_id]
            require(finding['resource_id'] == item['resource_id'], 'finding_resource_mismatch')
            require(instant(item['window']['start']) <= observed < instant(item['window']['end']),
                    'finding_time_outside_window')
        cited_times = {instant(indexed[c['evidence_id']]['rows'][c['row_index']]['timestamp'])
                       for c in citations if c['evidence_id'] in ids}
        require(observed in cited_times, 'finding_time_not_observed')
    answer['findings'] = findings
    return answer

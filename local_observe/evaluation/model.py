"""Bounded corpus data; truth uses canonical resources, kinds and half-open windows."""
import datetime as dt
import json
import math
from pathlib import Path

from local_observe.inventory.validation import canonical, timestamp, utc_text
from local_observe.platform.state import EVENT_KINDS, identifier

MAX_BYTES = 1_048_576
MAX_ROWS = 2000
MAX_ITEMS = 128
ROOT = Path(__file__).resolve().parents[2]


class CorpusError(ValueError):
    """Refused evaluation input; never interpreted as a clean detector result."""


def number(value):
    if type(value) not in (int, float):
        raise CorpusError('Expected a finite number, not a boolean')
    try:
        result = float(value)
    except OverflowError as exc:
        raise CorpusError('Numeric value overflows a float') from exc
    if not math.isfinite(result):
        raise CorpusError('Expected a finite number')
    return result


def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected.split()):
        raise CorpusError('Unknown or missing object fields')
    return value


def window(value):
    keys(value, 'start end')
    if not all(isinstance(x, str) for x in value.values()):
        raise CorpusError('Window timestamps must be text')
    try:
        start, end = timestamp(value['start']), timestamp(value['end'])
    except (ValueError, TypeError, OverflowError) as exc:
        raise CorpusError('Invalid timestamp') from exc
    if not dt.timedelta(0) < end - start <= dt.timedelta(days=7):
        raise CorpusError('Window must be positive and at most seven days')
    return {'start': utc_text(start), 'end': utc_text(end)}


def rows(value):
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_ROWS:
        raise CorpusError('Series must contain 1..2000 rows')
    result = []
    for row in value:
        keys(row, 'ts v')
        instant, sample = number(row['ts']), number(row['v'])
        if not 978307200 <= instant <= 4102444800:
            raise CorpusError('Timestamp outside supported epoch')
        result.append({'ts': instant, 'v': sample})
    if any(a['ts'] >= b['ts'] for a, b in zip(result, result[1:])):
        raise CorpusError('Series timestamps must strictly increase')
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CorpusError('Duplicate JSON key')
        result[key] = value
    return result


def load(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise CorpusError('Corpus exceeds one MiB')
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (ValueError, RecursionError) as exc:
        raise CorpusError('Malformed JSON corpus') from exc
    return validate(value)


def validate(value):
    keys(value, 'schema_version id origin evaluation incidents quiet series')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise CorpusError('Unsupported corpus version')
    if not isinstance(value['id'], str) or not 1 <= len(value['id']) <= 64:
        raise CorpusError('Invalid corpus id')
    if value['origin'] not in ('generated-demo', 'anonymized-example'):
        raise CorpusError('Only demo-derived public corpus data is supported')
    evaluation = window(value['evaluation'])
    start, end = timestamp(evaluation['start']).timestamp(), timestamp(evaluation['end']).timestamp()
    for field in ('incidents', 'quiet', 'series'):
        if not isinstance(value[field], list) or not 1 <= len(value[field]) <= MAX_ITEMS:
            raise CorpusError('Corpus lists must contain 1..128 items')
    truth, quiet, series = [], [], []
    seen = set()
    for item in value['incidents']:
        keys(item, 'id resource_id window expected_class')
        if not isinstance(item['id'], str) or not 1 <= len(item['id']) <= 64 or item['id'] in seen:
            raise CorpusError('Incident ids must be unique bounded text')
        seen.add(item['id'])
        identifier(item['resource_id'])
        if item['expected_class'] not in EVENT_KINDS:
            raise CorpusError('Unknown canonical event class')
        truth.append({**item, 'window': window(item['window'])})
    for item in value['quiet']:
        quiet.append(window(item))
    for item in truth + [{'window': w} for w in quiet]:
        w = item['window']
        if not start <= timestamp(w['start']).timestamp() < timestamp(w['end']).timestamp() <= end:
            raise CorpusError('Truth/quiet windows must be inside evaluation')
    for i, left in enumerate(truth):
        for right in truth[i + 1:]:
            if (left['resource_id'] == right['resource_id']
                    and left['expected_class'] == right['expected_class']
                    and overlaps(left['window'], right['window'])):
                raise CorpusError('Ambiguous overlapping same-class truth')
        if any(overlaps(left['window'], w) for w in quiet):
            raise CorpusError('Quiet windows cannot hold incident truth')
    identities = set()
    for item in value['series']:
        keys(item, 'resource_id metric rows')
        identifier(item['resource_id'])
        if not isinstance(item['metric'], str) or not 1 <= len(item['metric']) <= 128:
            raise CorpusError('Invalid metric name')
        identity = item['resource_id'], item['metric']
        if identity in identities:
            raise CorpusError('Duplicate series identity')
        identities.add(identity)
        points = rows(item['rows'])
        if any(not start - 6 * 86400 <= row['ts'] < end for row in points):
            raise CorpusError('Series outside bounded history/evaluation')
        series.append({**item, 'rows': points})
    result = {**value, 'evaluation': evaluation, 'incidents': truth, 'quiet': quiet, 'series': series}
    if len(canonical(result).encode('utf-8')) > MAX_BYTES:
        raise CorpusError('Corpus exceeds one MiB')
    return result


def overlaps(left, right):
    return timestamp(left['start']) < timestamp(right['end']) and timestamp(right['start']) < timestamp(left['end'])

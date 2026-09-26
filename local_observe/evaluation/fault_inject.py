"""Executable synthetic telemetry injection into the real in-memory read backend."""
import datetime as dt

from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.store.backends.memory import InMemoryStore
from local_observe.store.client import MetricSample, Window

from .model import ROOT, CorpusError, validate

RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
START = dt.datetime(2026, 1, 5, tzinfo=dt.timezone.utc)


def text(instant):
    return utc_text(instant)


def synthetic():
    """Three labelled incident classes, quiet control, same-hour training; no captured data."""
    points = []
    for days, level in ((3, 18e9), (2, 20e9), (1, 22e9)):
        for hour in range(4):
            for minute in range(5):
                instant = START - dt.timedelta(days=days) + dt.timedelta(hours=hour, minutes=minute)
                points.append({'ts': instant.timestamp(), 'v': level})
    # threshold burst, statistical shift, then absent telemetry (coverage truth), and quiet.
    for hour, level in ((0, 96e9), (1, 32e9), (3, 20e9)):
        for minute in range(5):
            points.append({'ts': (START + dt.timedelta(hours=hour, minutes=minute)).timestamp(), 'v': level})
    def interval(hour):
        return {'start': text(START + dt.timedelta(hours=hour)),
                'end': text(START + dt.timedelta(hours=hour + 1))}
    return validate({'schema_version': 1, 'id': 'demo-detectors-v1', 'origin': 'generated-demo',
                     'evaluation': {'start': text(START), 'end': text(START + dt.timedelta(hours=4))},
                     'incidents': [{'id': name, 'resource_id': RESOURCE, 'window': interval(hour),
                                    'expected_class': kind} for hour, name, kind in
                                   ((0, 'burst', 'threshold'), (1, 'shift', 'anomaly'), (2, 'missing', 'coverage'))],
                     'quiet': [interval(3)],
                     'series': [{'resource_id': RESOURCE, 'metric': 'filesystem_used_bytes',
                                 'rows': sorted(points, key=lambda row: row['ts'])}]})


def seed_store(corpus):
    corpus = validate(corpus)
    declared = {item['id'] for item in read_document(ROOT / 'examples/inventory/declared.yaml')['resources']}
    samples = []
    for series in corpus['series']:
        if series['resource_id'] not in declared:
            raise CorpusError('Synthetic resource is not in the declared example inventory')
        samples.extend(MetricSample(series['metric'], row['v'],
                                    text(dt.datetime.fromtimestamp(row['ts'], dt.timezone.utc)),
                                    resource_id=series['resource_id']) for row in series['rows'])
    return InMemoryStore(samples)


def injected_read(corpus):
    """Round-trip bounded rows through the product facade; return data and read receipts."""
    corpus = validate(corpus)
    store = seed_store(corpus)
    result, receipts = [], []
    for series in corpus['series']:
        start = min(row['ts'] for row in series['rows'])
        window = Window(text(dt.datetime.fromtimestamp(start, dt.timezone.utc)), corpus['evaluation']['end'])
        outcome = store.read_metrics('metric-threshold', window=window,
                                     parameters={'resource_id': series['resource_id'], 'rule_id': 'eval.read'},
                                     selectors={'metric_name': series['metric']})
        if outcome.status != 'available' or len(outcome.samples) != len(series['rows']):
            raise CorpusError('Injected store read unavailable or truncated')
        result.append({**series, 'rows': [{'ts': timestamp(row.timestamp).timestamp(), 'v': row.value}
                                         for row in outcome.samples]})
        receipts.append({'status': outcome.status, 'rows': len(outcome.samples),
                         'resource_id': series['resource_id'], 'window': {'start': window.start, 'end': window.end}})
    return {**corpus, 'series': result}, receipts


if __name__ == '__main__':
    import json

    print(json.dumps(synthetic(), indent=2, allow_nan=False))

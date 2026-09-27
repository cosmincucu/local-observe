"""Threshold/seasonal evaluators and shaping baseline; model use is an explicit report opt-in."""
import datetime as dt
import math
from statistics import mean, pstdev

from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import anomaly, detections

from .model import ROOT, CorpusError

NAMES = ('static-threshold', 'seasonal', 'shaping', 'llm-rca')


def threshold_defaults():
    """Read shipped example limits, not an invented estate deployment."""
    document = read_document(ROOT / 'examples/platform/forecast.yaml')
    return {(row['resource_id'], row['series']): row['threshold'] for row in document['rules']}


def finding(resource_id, kind, instant, *, arm, window=None):
    end = dt.datetime.fromtimestamp(int(instant) // 3600 * 3600 + 3600, dt.timezone.utc)
    window = window or {'start': utc_text(end - dt.timedelta(hours=1)), 'end': utc_text(end)}
    return detections.event('eval-' + arm, resource_id, 'eval.' + arm + '.' + kind, kind, 'firing',
                            window, {'resource_id': resource_id}, query_type='metric-threshold',
                            observed_at=utc_text(dt.datetime.fromtimestamp(instant, dt.timezone.utc)))


def downsample(points, seconds=60):
    buckets = {}
    for instant, value in points:
        buckets.setdefault(int(instant) // seconds, []).append((instant, value))
    return [(max(t for t, _ in group), mean(v for _, v in group))
            for _, group in sorted(buckets.items())]


def shape(training, current):
    """Downsample, then two-sided Shewhart 3-sigma and CUSUM k=.5/h=4."""
    baseline = downsample(training)
    if len(baseline) < 3:
        return [], len(current)
    centre = mean(value for _, value in baseline)
    spread = pstdev(value for _, value in baseline)
    positive = negative = 0.0
    selected = []
    for instant, value in downsample(current):
        if not spread:
            if value != centre:
                selected.append(instant)
            continue
        z = (value - centre) / spread
        positive = max(0.0, positive + z - 0.5)
        negative = max(0.0, negative - z - 0.5)
        if abs(z) > 3 or max(positive, negative) > 4:
            selected.append(instant)
            positive = negative = 0.0
    return selected, 0


def judge(name, context, *, index_path):
    """Context contains telemetry/evaluation only, never incident or quiet labels."""
    if set(context) != {'series', 'evaluation'}:
        raise CorpusError('Arm context must not carry truth')
    if name not in NAMES:
        raise CorpusError('Unknown arm')
    if name == 'llm-rca':
        return {'status': 'unwired', 'findings': [],
                'reason': 'Observer comparison requires an explicit protected output directory and model configuration'}
    start = timestamp(context['evaluation']['start']).timestamp()
    limits = threshold_defaults() if name == 'static-threshold' else {}
    result, missing, unknown_series = [], 0, 0
    for series in context['series']:
        training = [(row['ts'], row['v']) for row in series['rows'] if row['ts'] < start]
        current = [(row['ts'], row['v']) for row in series['rows'] if row['ts'] >= start]
        selected = []
        kind = 'threshold' if name == 'static-threshold' else 'anomaly'
        if name == 'static-threshold':
            threshold = limits.get((series['resource_id'], series['metric']))
            if threshold is None:
                unknown_series += 1
                continue
            for instant, value in current:
                now = dt.datetime.fromtimestamp(instant + 60, dt.timezone.utc)
                sample = {'sample_id': 'eval-sample', 'observed_at': utc_text(
                    dt.datetime.fromtimestamp(instant, dt.timezone.utc)), 'ok': True, 'value': value}
                rule = {'id': 'eval.static-threshold', 'kind': 'threshold',
                        'resource_id': series['resource_id'], 'source': 'eval-static-threshold',
                        'threshold': threshold}
                events = detections.evaluate(index_path, rule, sample, now=now)
                selected.extend(instant for event in events
                                if event['kind'] == 'threshold' and event['status'] == 'firing')
        elif name == 'seasonal':
            baseline = anomaly.train(training, season='hour_of_day', min_per_bucket=3, k=3)
            detected = anomaly.detect(baseline, current)
            selected = [point.epoch_s for point in detected.deviations]
            missing += len(detected.skipped)
        else:
            selected, skipped = shape(training, current)
            missing += skipped
        # Fixed hourly filing cadence is part of this detector wrapper, not truth-window adjustment.
        by_hour = {}
        for instant in selected:
            by_hour.setdefault(int(instant) // 3600, instant)
        result.extend(finding(series['resource_id'], kind, instant, arm=name)
                      for instant in by_hour.values())
    return {'status': 'unjudgeable' if missing or unknown_series else 'measured',
            'findings': result, 'unjudgeable_points': missing, 'unconfigured_series': unknown_series,
            'filing_cadence_seconds': 3600}

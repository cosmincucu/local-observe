"""Canonical event scoring: one event can credit one truth incident, never point-adjust."""
from collections import Counter

from local_observe.inventory.validation import timestamp
from local_observe.platform.state import validate_event

from .model import CorpusError, validate

MAX_FINDINGS = 4096


def score(corpus, findings, *, min_precision=None, point_adjust=False):
    corpus = validate(corpus)
    if point_adjust is not False:
        raise CorpusError('Point-adjust is prohibited')
    if min_precision is not None and (type(min_precision) not in (int, float) or not 0 <= min_precision <= 1):
        raise CorpusError('Precision policy must be in 0..1')
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise CorpusError('Findings must be a bounded list')
    now = timestamp(corpus['evaluation']['end'])
    credited, seen = set(), set()
    tp = fp = duplicates = non_firing = 0
    for finding in findings:
        validate_event(finding, now)
        if finding['status'] != 'firing':
            non_firing += 1
            continue
        identity = finding['source'], finding['source_event_id']
        if identity in seen:
            duplicates += 1
            continue
        seen.add(identity)
        at = timestamp(finding['observed_at'])
        matches = [truth for truth in corpus['incidents']
                   if truth['resource_id'] == finding['resource_id']
                   and truth['expected_class'] == finding['kind']
                   and timestamp(truth['window']['start']) <= at < timestamp(truth['window']['end'])]
        if matches and matches[0]['id'] not in credited:
            credited.add(matches[0]['id'])
            tp += 1
        else:
            fp += 1  # Extra findings for an already credited incident still cost precision.
    fn = len(corpus['incidents']) - tp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn)
    duration = (now - timestamp(corpus['evaluation']['start'])).total_seconds()
    return {'true_positives': tp, 'false_positives': fp, 'false_negatives': fn,
            'precision': precision, 'recall': recall, 'duplicates': duplicates,
            'non_firing': non_firing, 'findings': tp + fp,
            'findings_per_day': (tp + fp) * 86400 / duration,
            'matched': sorted(credited),
            'verdict': ('measured' if min_precision is None else
                        'pass' if precision is not None and precision >= min_precision else 'fail')}


def flip_rate(runs):
    if not isinstance(runs, list) or len(runs) != 3:
        raise CorpusError('Exactly three runs required')
    names = set(runs[0])
    if not names or any(set(run) != names for run in runs):
        raise CorpusError('Every run must name the same arms')
    rates = {name: 1 - Counter(run[name] for run in runs).most_common(1)[0][1] / 3
             for name in sorted(names)}
    return {'runs': 3, 'per_arm': rates, 'rate': sum(rates.values()) / len(rates)}

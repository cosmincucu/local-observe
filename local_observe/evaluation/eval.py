"""Canonical event scoring: one event can credit one truth incident, never point-adjust."""
from collections import Counter

from local_observe.inventory.validation import canonical, timestamp
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
    credited, seen = set(), {}
    tp = fp = duplicates = non_firing = unknown = 0
    for finding in findings:
        validate_event(finding, now)
        identity = finding['source'], finding['source_event_id']
        if identity in seen:
            if seen[identity] != canonical(finding):
                raise CorpusError('Contradictory findings share an event identity')
            duplicates += 1
            continue
        seen[identity] = canonical(finding)
        if finding['status'] != 'firing':
            non_firing += 1
            continue
        at = timestamp(finding['observed_at'])
        if not timestamp(corpus['evaluation']['start']) <= at < now:
            raise CorpusError('Finding is outside the evaluation window')
        matches = [truth for truth in corpus['incidents']
                   if truth['resource_id'] == finding['resource_id']
                   and truth['expected_class'] == finding['kind']
                   and timestamp(truth['window']['start']) <= at < timestamp(truth['window']['end'])]
        if matches and matches[0]['id'] not in credited:
            credited.add(matches[0]['id'])
            tp += 1
        elif matches or any(timestamp(window['start']) <= at < timestamp(window['end'])
                 for window in corpus['quiet'] + [row['window'] for row in corpus['labelled']
                                                 if row['resource_id'] == finding['resource_id']]):
            fp += 1  # Extra findings for an already credited incident still cost precision.
        else:
            unknown += 1  # An unlabelled interval supplies neither positive nor negative truth.
    fn = len(corpus['incidents']) - tp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    duration = (now - timestamp(corpus['evaluation']['start'])).total_seconds()
    return {'true_positives': tp, 'false_positives': fp, 'false_negatives': fn,
            'precision': precision, 'recall': recall, 'duplicates': duplicates,
            'non_firing': non_firing, 'findings': tp + fp,
            'unlabelled_findings': unknown, 'total_findings': tp + fp + unknown,
            'findings_per_day': (tp + fp + unknown) * 86400 / duration,
            'matched': sorted(credited),
            'verdict': ('measured' if min_precision is None else
                        'pass' if precision is not None and precision >= min_precision else 'fail')}


def flip_rate(runs):
    if not isinstance(runs, list) or len(runs) != 3:
        raise CorpusError('Exactly three runs required')
    if any(not isinstance(run, dict) for run in runs):
        raise CorpusError('Runs must be arm mappings')
    names = set(runs[0])
    if not names or any(set(run) != names for run in runs):
        raise CorpusError('Every run must name the same arms')
    rates, measurements = {}, {}
    for name in sorted(names):
        rows = [run[name] for run in runs]
        if any(not isinstance(row, dict) for row in rows):
            raise CorpusError('Each arm needs an aligned decision mapping')
        keys = set().union(*(set(row) for row in rows))
        if any(not isinstance(key, str) for key in keys):
            raise CorpusError('Decision identities must be text')
        missing = sum(row.get(key) is None for key in keys for row in rows)
        if any(value is not None and not isinstance(value, str) for row in rows for value in row.values()):
            raise CorpusError('Decision signatures must be text or unknown')
        comparisons = 3 * len(keys)
        disagreements = (sum(3 - Counter(row[key] for row in rows).most_common(1)[0][1]
                             for key in keys) if keys and not missing else None)
        rates[name] = disagreements / comparisons if disagreements is not None else None
        measurements[name] = {'status': 'measured' if disagreements is not None else 'incomplete',
                              'units': len(keys), 'missing_decisions': missing,
                              'disagreements': disagreements, 'comparisons': comparisons}
    complete = all(rate is not None for rate in rates.values())
    return {'runs': 3, 'per_arm': rates, 'measurements': measurements,
            'rate': sum(rates.values()) / len(rates) if complete else None}

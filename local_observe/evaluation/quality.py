"""Independent quality measurements. This report never grants delivery permission."""
import math

from local_observe.inventory.validation import timestamp

from .eval import MAX_FINDINGS
from .model import CorpusError, validate
from .provenance import cycle_identity

DEFAULT_POLICY = {'minimum_precision': 0.7, 'maximum_findings_per_day': 2,
                  'maximum_flip_rate_exclusive': 0.1, 'minimum_novel_classes': 1}
BASELINES = ('static-threshold', 'seasonal')
COUNTS = ('true_positives', 'false_positives', 'false_negatives', 'duplicates', 'non_firing',
          'findings', 'unlabelled_findings', 'total_findings')
SCORE_FIELDS = {*COUNTS, 'precision', 'recall', 'findings_per_day', 'matched', 'verdict'}


def validate_score(value, corpus):
    if not isinstance(value, dict) or set(value) != SCORE_FIELDS:
        raise CorpusError('Missing or unknown score fields')
    if any(type(value[key]) is not int or not 0 <= value[key] <= MAX_FINDINGS for key in COUNTS):
        raise CorpusError('Score counts must be bounded integers')
    truth = {item['id'] for item in corpus['incidents']}
    matched = value['matched']
    if (not isinstance(matched, list) or any(not isinstance(item, str) for item in matched)
            or len(set(matched)) != len(matched) or not set(matched) <= truth):
        raise CorpusError('Matched incidents must be distinct evaluation truth IDs')
    tp, fp, fn = (value[key] for key in ('true_positives', 'false_positives', 'false_negatives'))
    total = tp + fp + value['unlabelled_findings']
    if (len(matched) != tp or fn != len(truth) - tp or value['findings'] != tp + fp
            or value['total_findings'] != total or total + value['duplicates'] + value['non_firing'] > MAX_FINDINGS):
        raise CorpusError('Inconsistent score counts')
    duration = (timestamp(corpus['evaluation']['end']) - timestamp(corpus['evaluation']['start'])).total_seconds()
    expected = {'precision': tp / (tp + fp) if tp + fp else None,
                'recall': tp / (tp + fn) if tp + fn else None, 'findings_per_day': total * 86400 / duration}
    for key, number in expected.items():
        actual = value[key]
        if number is None:
            if actual is not None:
                raise CorpusError('Undefined score rate must remain unknown')
        elif (type(actual) not in (int, float) or not math.isfinite(actual)
                or not math.isclose(actual, number, rel_tol=1e-12, abs_tol=1e-12)):
            raise CorpusError('Inconsistent score rate')
    if value['verdict'] not in ('measured', 'pass', 'fail'):
        raise CorpusError('Unknown score verdict')
    return value


def assess(corpus, runs, *, observer='llm-rca', observer_flip_rate):
    """Require all three independent runs to meet every floor, with no unknown labels.

    Input runs are produced by the evaluator after keeping truth out of the investigator.
    Novelty means a correctly detected class missed by both threshold baselines in each
    run; merely inventing an extra class cannot earn credit. The report is evidence for
    human review, never a capability accepted by a notification transport.
    """
    corpus = validate(corpus)
    if not isinstance(runs, list) or len(runs) != 3:
        raise CorpusError('Quality assessment requires exactly three runs')
    if observer_flip_rate is not None and (
            type(observer_flip_rate) not in (int, float) or not math.isfinite(observer_flip_rate)
            or not 0 <= observer_flip_rate <= 1):
        raise CorpusError('Observer flip rate must be in 0..1')
    truth = {row['id']: row['expected_class'] for row in corpus['incidents']}
    reasons, novel, identities = [], [], []
    for number, run in enumerate(runs, 1):
        prefix = f'run-{number}'
        if not isinstance(run, dict) or any(name not in run for name in (*BASELINES, observer)):
            raise CorpusError('Missing required comparison arm')
        for name in (*BASELINES, observer):
            arm = run[name]
            if (not isinstance(arm, dict) or set(arm) != {'execution', 'score', 'detail'}
                    or not isinstance(arm['detail'], dict)
                    or arm['execution'] not in ('measured', 'unwired', 'unjudgeable', 'failed', 'partial')):
                raise CorpusError('Invalid comparison arm')
            if arm['score'] is not None:
                validate_score(arm['score'], corpus)
            elif arm['execution'] == 'measured':
                raise CorpusError('Measured arm has no score')
        if (any(run[name]['execution'] != 'measured' or run[name]['detail'].get('coverage_complete') is not True
                for name in (*BASELINES, observer))
                or any(type(run[name]['detail'].get(key)) is not int or run[name]['detail'][key] != 0
                       for name in BASELINES for key in ('unjudgeable_points', 'unconfigured_series'))):
            reasons.append(f'{prefix}: incomplete comparison')
            novel.append(set())
            continue
        scored = run[observer]['score']
        detail = run[observer]['detail']
        identity = cycle_identity(detail.get('cycles'), detail.get('config_sha256'))
        if identity is None or detail.get('provenance') != identity:
            reasons.append(f'{prefix}: incomplete or inconsistent observer provenance')
        else:
            identities.append(identity)
        precision, volume = scored.get('precision'), scored.get('findings_per_day')
        if (type(precision) not in (int, float) or not math.isfinite(precision)
                or not DEFAULT_POLICY['minimum_precision'] <= precision <= 1):
            reasons.append(f'{prefix}: precision below floor or unknown')
        if (type(volume) not in (int, float) or not math.isfinite(volume)
                or not 0 <= volume <= DEFAULT_POLICY['maximum_findings_per_day']):
            reasons.append(f'{prefix}: notification volume above ceiling or unknown')
        if scored['unlabelled_findings'] != 0:
            reasons.append(f'{prefix}: findings without independent labels')
        matched = set(scored['matched'])
        baseline = set().union(*(set(run[name]['score']['matched']) for name in BASELINES))
        if not (matched | baseline) <= truth.keys():
            raise CorpusError('Matched incident is not in the evaluation truth')
        baseline_classes = {truth[key] for key in baseline}
        novel.append({truth[key] for key in matched} - baseline_classes)
    shared_novel = set.intersection(*novel)
    if len(shared_novel) < DEFAULT_POLICY['minimum_novel_classes']:
        reasons.append('no consistently detected class missed by both threshold baselines')
    if identities and any(item != identities[0] for item in identities):
        reasons.append('observer identity differs across runs')
    if observer_flip_rate is None or observer_flip_rate >= DEFAULT_POLICY['maximum_flip_rate_exclusive']:
        reasons.append('observer verdict flip rate is unknown or not below ceiling')
    return {'schema_version': 2, 'verdict': 'fail' if reasons else 'measured-pass',
            'policy': DEFAULT_POLICY.copy(), 'reasons': reasons,
            'novel_classes': sorted(shared_novel), 'observer_flip_rate': observer_flip_rate,
            'truth_incidents': len(truth), 'corpus_origin': corpus['origin'],
            'authorizes_delivery': False,
            'limitations': ['Measurements require independent truth and representative held-out incidents.',
                           'Generated fixtures demonstrate plumbing, not production model quality.',
                           'Human acceptance, hardware fit and workload measurements remain separate.']}

"""Independent quality measurements. This report never grants delivery permission."""
import math

from .model import CorpusError, validate

DEFAULT_POLICY = {'minimum_precision': 0.7, 'maximum_findings_per_day': 2,
                  'maximum_flip_rate_exclusive': 0.1, 'minimum_novel_classes': 1}
BASELINES = ('static-threshold', 'seasonal')


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
    if (type(observer_flip_rate) not in (int, float) or not math.isfinite(observer_flip_rate)
            or not 0 <= observer_flip_rate <= 1):
        raise CorpusError('Observer flip rate must be in 0..1')
    truth = {row['id']: row['expected_class'] for row in corpus['incidents']}
    reasons, novel = [], []
    for number, run in enumerate(runs, 1):
        prefix = f'run-{number}'
        if not isinstance(run, dict) or any(name not in run for name in (*BASELINES, observer)):
            raise CorpusError('Missing required comparison arm')
        if any(run[name].get('execution') != 'measured' or not isinstance(run[name].get('score'), dict)
               for name in (*BASELINES, observer)):
            reasons.append(f'{prefix}: incomplete comparison')
            novel.append(set())
            continue
        scored = run[observer]['score']
        precision, volume = scored.get('precision'), scored.get('findings_per_day')
        if (type(precision) not in (int, float) or not math.isfinite(precision)
                or not DEFAULT_POLICY['minimum_precision'] <= precision <= 1):
            reasons.append(f'{prefix}: precision below floor or unknown')
        if (type(volume) not in (int, float) or not math.isfinite(volume)
                or not 0 <= volume <= DEFAULT_POLICY['maximum_findings_per_day']):
            reasons.append(f'{prefix}: notification volume above ceiling or unknown')
        if scored.get('unlabelled_findings', 0) != 0:
            reasons.append(f'{prefix}: findings without independent labels')
        matched = set(scored.get('matched', []))
        baseline = set().union(*(set(run[name]['score'].get('matched', [])) for name in BASELINES))
        if not (matched | baseline) <= truth.keys():
            raise CorpusError('Matched incident is not in the evaluation truth')
        baseline_classes = {truth[key] for key in baseline}
        novel.append({truth[key] for key in matched} - baseline_classes)
    shared_novel = set.intersection(*novel)
    if len(shared_novel) < DEFAULT_POLICY['minimum_novel_classes']:
        reasons.append('no consistently detected class missed by both threshold baselines')
    if observer_flip_rate >= DEFAULT_POLICY['maximum_flip_rate_exclusive']:
        reasons.append('observer verdict flip rate is not below ceiling')
    return {'schema_version': 1, 'verdict': 'fail' if reasons else 'measured-pass',
            'policy': DEFAULT_POLICY.copy(), 'reasons': reasons,
            'novel_classes': sorted(shared_novel), 'observer_flip_rate': observer_flip_rate,
            'truth_incidents': len(truth), 'corpus_origin': corpus['origin'],
            'authorizes_delivery': False,
            'limitations': ['Measurements require independent truth and representative held-out incidents.',
                           'Generated fixtures demonstrate plumbing, not production model quality.',
                           'Human acceptance, hardware fit and workload measurements remain separate.']}

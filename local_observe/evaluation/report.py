"""Offline three-run report entrypoint; measurements never silently set a policy floor."""
import copy
import os
import tempfile
from pathlib import Path

from local_observe.inventory import index

from .arms import NAMES, judge
from .budget import enforced_limits
from .decisions import baseline
from .eval import flip_rate, score
from .fault_inject import injected_read
from .manifest import build_manifest
from .model import ROOT, CorpusError, validate
from .quality import assess
from .baseline_config import prepare, validate_config


def reserve_namespace(directory):
    """Reserve before any calls; an existing result can never be a fresh independent run."""
    from local_observe.observer.journal import private_directory
    path = Path(directory)
    if not path.is_absolute() or '..' in path.parts or path == Path('/') or path.is_relative_to(ROOT):
        raise CorpusError('Evaluation requires an absolute private directory outside product source')
    if path.exists() or path.is_symlink():
        raise CorpusError('Evaluation requires a fresh output directory')
    parent = private_directory(path.parent)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
    except FileExistsError as exc:
        raise CorpusError('Evaluation requires a fresh output directory') from exc
    finally:
        os.close(parent)
    return path


def evaluate(corpus, *, revision, observer_directory=None, observer_model_factory=None, observer_config=None,
             baseline_config=None):
    corpus = validate(corpus)
    baseline_config = validate_config(baseline_config) if baseline_config is not None else None
    thresholds, declaration, _ = prepare(corpus, baseline_config)
    if observer_config is not None and observer_directory is None:
        raise CorpusError('Observer configuration requires a protected comparison directory')
    initial = build_manifest(corpus, revision=revision, arms=NAMES, exclusions=[], baseline_config=baseline_config)
    if observer_directory is not None:
        observer_directory = reserve_namespace(observer_directory)
    runs, signatures, measurements = [], [], []
    with tempfile.TemporaryDirectory(prefix='lo-eval-') as scratch:
        inventory = Path(scratch) / 'inventory.db'
        index.build(declaration, inventory, 'detector-evaluation')
        for run_number in range(3):
            loaded, receipts = injected_read(copy.deepcopy(corpus),
                                            resources={row['id'] for row in declaration['resources']})
            results, signature, measured_inputs = {}, {}, {}
            for name in NAMES:
                context = {'series': copy.deepcopy(loaded['series']), 'evaluation': loaded['evaluation'].copy()}
                if name == 'llm-rca' and observer_directory is not None:
                    from .observer import judge as observe
                    actual = observe(context, directory=Path(observer_directory) / f'run-{run_number + 1}',
                                     model_factory=observer_model_factory, config=observer_config)
                else:
                    actual = judge(name, context, index_path=inventory, thresholds=thresholds)
                decisions = actual.get('decisions')
                if decisions is None:
                    decisions = baseline(context, actual)
                    actual['coverage_complete'] = bool(decisions) and all(v is not None for v in decisions.values())
                    if actual['status'] == 'measured' and not actual['coverage_complete']:
                        actual['status'] = 'unjudgeable'
                        decisions = baseline(context, actual)
                measured = None if actual['status'] == 'unwired' else score(corpus, actual['findings'])
                results[name] = {'execution': actual['status'], 'score': measured,
                                 'detail': {k: v for k, v in actual.items() if k not in ('findings', 'decisions')}}
                signature[name] = decisions
                measured_inputs[name] = {'findings': copy.deepcopy(actual['findings']),
                                         'decisions': copy.deepcopy(decisions)}
            runs.append(results)
            signatures.append(signature)
            measurements.append(measured_inputs)
    excluded = ['Private incidents: no publication approval; worked example is generated, not captured',
                'Live send testing, live ClickHouse and host fault injection are not exercised']
    if observer_directory is None:
        excluded.append('Observer model was not configured for this comparison')
    flips = flip_rate(signatures)
    for name, measurement in flips['measurements'].items():
        measurement['unit'] = 'cycle-window' if name == 'llm-rca' and observer_directory else 'resource-window'
    identity = {'schema_version': 1, 'config_sha256': None, 'configuration_authority': 'unconfigured',
                'provenance': None}
    if observer_directory is not None:
        detail = runs[0]['llm-rca']['detail']
        identity.update({key: detail[key] for key in ('config_sha256', 'configuration_authority', 'provenance')})
        if any(run['llm-rca']['detail']['provenance'] != identity['provenance'] for run in runs):
            identity['provenance'] = None
    manifest = build_manifest(corpus, revision=revision, arms=NAMES, exclusions=excluded, observer=identity,
                              baseline_config=baseline_config)
    if manifest['implementation_sha256'] != initial['implementation_sha256']:
        raise CorpusError('Implementation changed during evaluation')
    return {'schema_version': 2, 'arms': runs[0], 'flip_rate': flips,
            'measurement': {'schema_version': 1, 'corpus': corpus, 'baseline_config': baseline_config,
                            'runs': measurements},
            'runs': runs, 'read_receipts': receipts, 'notification_limits': enforced_limits(),
            'uncovered_truth_classes': sorted(set(row['expected_class'] for row in corpus['incidents'])
                                             - {'threshold', 'anomaly'}),
            'quality': assess(corpus, runs, observer_flip_rate=flips['per_arm']['llm-rca']),
            'policy': {'minimum_precision': 0.7, 'maximum_findings_per_day': 2,
                       'maximum_flip_rate_exclusive': 0.1, 'minimum_novel_classes': 1,
                       'requires_human_acceptance': True, 'findings_per_day_is_rate_not_send_limit': True},
            'manifest': manifest}

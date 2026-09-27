"""Offline three-run report entrypoint; measurements never silently set a policy floor."""
import copy
import tempfile
from pathlib import Path

from local_observe.inventory import index
from local_observe.inventory.validation import canonical, read_document

from .arms import NAMES, judge
from .budget import enforced_limits
from .eval import flip_rate, score
from .fault_inject import injected_read
from .manifest import build_manifest
from .model import ROOT, validate
from .quality import assess


def evaluate(corpus, *, revision, observer_directory=None, observer_model_factory=None):
    corpus = validate(corpus)
    runs, signatures = [], []
    with tempfile.TemporaryDirectory(prefix='lo-eval-') as scratch:
        inventory = Path(scratch) / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), inventory, 'demo-evaluation')
        for run_number in range(3):
            loaded, receipts = injected_read(copy.deepcopy(corpus))
            results, signature = {}, {}
            for name in NAMES:
                context = {'series': copy.deepcopy(loaded['series']), 'evaluation': loaded['evaluation'].copy()}
                if name == 'llm-rca' and observer_directory is not None:
                    from .observer import judge as observe
                    actual = observe(context, directory=Path(observer_directory) / f'run-{run_number + 1}',
                                     model_factory=observer_model_factory)
                else:
                    actual = judge(name, context, index_path=inventory)
                measured = None if actual['status'] == 'unwired' else score(corpus, actual['findings'])
                results[name] = {'execution': actual['status'], 'score': measured,
                                 'detail': {k: v for k, v in actual.items() if k != 'findings'}}
                signature[name] = canonical({'findings': actual['findings'], 'verdicts': actual['verdicts']}
                                             if 'verdicts' in actual else actual)
            runs.append(results)
            signatures.append(signature)
    excluded = ['Private incidents: no publication approval; worked example is generated, not captured',
                'Live send testing, live ClickHouse and host fault injection are not exercised']
    if observer_directory is None:
        excluded.append('Observer model was not configured for this comparison')
    flips = flip_rate(signatures)
    return {'schema_version': 1, 'arms': runs[0], 'flip_rate': flips,
            'runs': runs, 'read_receipts': receipts, 'notification_limits': enforced_limits(),
            'uncovered_truth_classes': sorted(set(row['expected_class'] for row in corpus['incidents'])
                                             - {'threshold', 'anomaly'}),
            'quality': assess(corpus, runs, observer_flip_rate=flips['per_arm']['llm-rca']),
            'policy': {'minimum_precision': 0.7, 'maximum_findings_per_day': 2,
                       'maximum_flip_rate_exclusive': 0.1, 'minimum_novel_classes': 1,
                       'requires_human_acceptance': True, 'findings_per_day_is_rate_not_send_limit': True},
            'manifest': build_manifest(corpus, revision=revision, arms=NAMES, exclusions=excluded)}

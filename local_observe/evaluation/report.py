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


def evaluate(corpus, *, revision):
    corpus = validate(corpus)
    runs, signatures = [], []
    with tempfile.TemporaryDirectory(prefix='lo-eval-') as scratch:
        inventory = Path(scratch) / 'inventory.db'
        index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), inventory, 'demo-evaluation')
        for _ in range(3):
            loaded, receipts = injected_read(copy.deepcopy(corpus))
            results, signature = {}, {}
            for name in NAMES:
                context = {'series': copy.deepcopy(loaded['series']), 'evaluation': loaded['evaluation'].copy()}
                actual = judge(name, context, index_path=inventory)
                measured = None if actual['status'] == 'unwired' else score(corpus, actual['findings'])
                results[name] = {'execution': actual['status'], 'score': measured,
                                 'detail': {k: v for k, v in actual.items() if k != 'findings'}}
                signature[name] = canonical(actual)
            runs.append(results)
            signatures.append(signature)
    excluded = ['Private incidents: no publication approval; worked example is generated, not captured',
                'LLM/RCA and similar-past-incident retrieval: no callable product integration',
                'Live send testing, live ClickHouse and host fault injection are not exercised']
    return {'schema_version': 1, 'arms': runs[0], 'flip_rate': flip_rate(signatures),
            'runs': runs, 'read_receipts': receipts, 'notification_limits': enforced_limits(),
            'uncovered_truth_classes': sorted(set(row['expected_class'] for row in corpus['incidents'])
                                             - {'threshold', 'anomaly'}),
            'policy': {'enforced_precision_floor': None, 'proposed_precision_floor': 0.5,
                       'proposal_requires_review': True, 'findings_per_day_is_rate_not_send_limit': True},
            'manifest': build_manifest(corpus, revision=revision, arms=NAMES, exclusions=excluded)}

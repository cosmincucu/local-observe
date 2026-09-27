"""Reproducible corpus, implementation and policy provenance; no captured estate content."""
import hashlib
import re

from local_observe.inventory.validation import canonical

from .model import ROOT, CorpusError, validate


def sha(value):
    return hashlib.sha256(value).hexdigest()


def build_manifest(corpus, *, revision, arms, exclusions):
    if not isinstance(revision, str) or re.fullmatch('[0-9a-f]{40}', revision) is None:
        raise CorpusError('Revision must be a complete lowercase Git commit id')
    corpus = validate(corpus)
    dependencies = ['examples/platform/forecast.yaml', 'examples/inventory/declared.yaml',
                    'local_observe/platform/anomaly.py', 'local_observe/platform/detections.py',
                    'local_observe/platform/notification_safety.py',
                    'local_observe/store/client.py', 'local_observe/store/backends/memory.py']
    dependencies += [path.relative_to(ROOT).as_posix()
                     for path in sorted((ROOT / 'local_observe/evaluation').glob('*.py'))]
    dependencies += [path.relative_to(ROOT).as_posix()
                     for path in sorted((ROOT / 'local_observe/observer').glob('*.py'))]
    return {'schema_version': 1, 'fixture_set': corpus['id'], 'origin': corpus['origin'],
            'revision': revision, 'revision_authority': 'caller-supplied; source hashes recorded independently',
            'corpus_sha256': sha(canonical(corpus).encode('utf-8')), 'arms': list(arms),
            'exclusions': list(exclusions),
            'implementation_sha256': {path: sha((ROOT / path).read_bytes()) for path in dependencies}}


def verify_manifest(manifest, corpus):
    rebuilt = build_manifest(corpus, revision=manifest['revision'], arms=manifest['arms'],
                             exclusions=manifest['exclusions'])
    if rebuilt != manifest:
        raise CorpusError('Manifest differs from corpus or implementation')
    return True

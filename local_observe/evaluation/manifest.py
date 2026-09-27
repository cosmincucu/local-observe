"""Reproducible corpus, implementation and policy provenance; no captured estate content."""
import hashlib
import re

from local_observe.inventory.validation import canonical

from .model import ROOT, CorpusError, validate
from .provenance import valid_hash, validate_provenance


def sha(value):
    return hashlib.sha256(value).hexdigest()


def build_manifest(corpus, *, revision, arms, exclusions, observer=None):
    if not isinstance(revision, str) or re.fullmatch('[0-9a-f]{40}', revision) is None:
        raise CorpusError('Revision must be a complete lowercase Git commit id')
    corpus = validate(corpus)
    dependencies = ['examples/platform/forecast.yaml', 'examples/inventory/declared.yaml',
                    'local_observe/platform/anomaly.py', 'local_observe/platform/detections.py',
                    'local_observe/platform/notification_safety.py',
                    'local_observe/store/client.py', 'local_observe/store/backends/memory.py']
    dependencies += [path.relative_to(ROOT).as_posix()
                     for path in sorted((ROOT / 'local_observe/evaluation').glob('*.py'))]
    for package in ('observer', 'ai'):
        dependencies += [path.relative_to(ROOT).as_posix()
                         for path in sorted((ROOT / 'local_observe' / package).glob('*.py'))]
    dependencies += ['local_observe/http.py', 'local_observe/credentials.py',
                     'local_observe/inventory/validation.py', 'local_observe/platform/query.py']
    if observer is None:
        observer = {'schema_version': 1, 'config_sha256': None,
                    'configuration_authority': 'unconfigured', 'provenance': None}
    if (not isinstance(observer, dict) or set(observer) != {
            'schema_version', 'config_sha256', 'configuration_authority', 'provenance'}
            or type(observer['schema_version']) is not int or observer['schema_version'] != 1
            or observer['configuration_authority'] not in ('unconfigured', 'operator-supplied', 'demo-default')
            or (observer['config_sha256'] is not None and not valid_hash(observer['config_sha256']))):
        raise CorpusError('Invalid observer manifest identity')
    if (observer['configuration_authority'] == 'unconfigured') != (observer['config_sha256'] is None):
        raise CorpusError('Observer configuration identity is inconsistent')
    if observer['provenance'] is not None:
        provenance = validate_provenance(observer['provenance'], require_complete=True)
        if provenance['config_sha256'] != observer['config_sha256']:
            raise CorpusError('Observer provenance configuration mismatch')
    return {'schema_version': 2, 'fixture_set': corpus['id'], 'origin': corpus['origin'],
            'revision': revision, 'revision_authority': 'caller-supplied; source hashes recorded independently',
            'corpus_sha256': sha(canonical(corpus).encode('utf-8')), 'arms': list(arms),
            'exclusions': list(exclusions), 'observer': observer,
            'implementation_sha256': {path: sha((ROOT / path).read_bytes()) for path in dependencies}}


def verify_manifest(manifest, corpus):
    required = {'schema_version', 'fixture_set', 'origin', 'revision', 'revision_authority', 'corpus_sha256',
                'arms', 'exclusions', 'observer', 'implementation_sha256'}
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise CorpusError('Invalid evaluation manifest fields')
    rebuilt = build_manifest(corpus, revision=manifest['revision'], arms=manifest['arms'],
                             exclusions=manifest['exclusions'], observer=manifest['observer'])
    if rebuilt != manifest:
        raise CorpusError('Manifest differs from corpus or implementation')
    return True

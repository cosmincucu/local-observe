"""Content-derived nonsecret implementation/config/model identity, including explicit unknowns."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from dataclasses import asdict

from .contract import Config, digest, fields, require


HASHES = ('implementation_sha256', 'prompt_sha256', 'config_sha256', 'policy_sha256',
          'capability_sha256', 'budget_sha256')
LABELS = ('configured_model', 'provider', 'model_version', 'response_model')
FIELDS = {'schema_version', *HASHES, *LABELS, 'complete', 'sha256'}


def label(value):
    unknown = ('unknown', 'unset', 'unmeasured', 'none', 'null')
    return value if (isinstance(value, str) and value.casefold() not in unknown
                     and '://' not in value
                     and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,159}', value)) else None


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def implementation_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    files = [*root.joinpath('observer').glob('*.py'), *root.joinpath('ai').glob('*.py')]
    files += [root / path for path in ('http.py', 'credentials.py', 'inventory/validation.py',
                                       'platform/query.py', 'store/client.py', 'store/backends/clickhouse.py')]
    return digest({path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in sorted(files)})


def provenance_digest(value: dict) -> str:
    return digest({k: v for k, v in value.items() if k != 'sha256'})


def validate_provenance(value, *, require_complete: bool = False) -> dict:
    fields(value, FIELDS)
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'unsupported_provenance_version')
    require(all(value[k] is None or is_digest(value[k]) for k in HASHES), 'invalid_provenance_hash')
    require(all(value[k] is None or label(value[k]) == value[k] for k in LABELS), 'invalid_provenance_label')
    known = all(value[k] is not None for k in (*HASHES, *LABELS))
    complete = known
    require(type(value['complete']) is bool and value['complete'] == complete, 'invalid_provenance_completeness')
    require(value['sha256'] == provenance_digest(value), 'provenance_digest_mismatch')
    require(not require_complete or complete, 'incomplete_provenance')
    return value


def build_provenance(config: Config, model, *, response_model=None) -> dict:
    from .adapters import prompt_contract
    metadata = model.provenance() if callable(getattr(model, 'provenance', None)) else {}
    require(isinstance(metadata, dict) and set(metadata) <= {*LABELS, 'policy_sha256', 'capability_sha256',
                                                            'budget_sha256'}, 'invalid_adapter_provenance')
    value = {'schema_version': 1, 'implementation_sha256': implementation_digest(),
             'prompt_sha256': digest(prompt_contract()), 'config_sha256': digest(asdict(config)),
             **{key: metadata.get(key) for key in ('policy_sha256', 'capability_sha256', 'budget_sha256')},
             **{key: label(metadata.get(key)) for key in ('configured_model', 'provider', 'model_version')},
             'response_model': label(response_model)}
    value['complete'] = all(value[k] is not None for k in (*HASHES, *LABELS))
    value['sha256'] = provenance_digest(value)
    return validate_provenance(value)

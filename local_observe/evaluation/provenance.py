"""Strict nonsecret observer identity, shared by measurements and their manifest."""
import hashlib
import json
import re

from .model import CorpusError

HASH_FIELDS = ('implementation_sha256', 'prompt_sha256', 'config_sha256', 'policy_sha256',
               'capability_sha256', 'budget_sha256')
IDENTITY_FIELDS = ('configured_model', 'provider', 'model_version', 'response_model')
FIELDS = {'schema_version', 'complete', 'sha256', *HASH_FIELDS, *IDENTITY_FIELDS}


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode('utf-8')).hexdigest()


def valid_hash(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def validate_provenance(value, *, require_complete=False):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise CorpusError('Invalid observer provenance fields')
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or type(value['complete']) is not bool:
        raise CorpusError('Invalid observer provenance version or completeness')
    for key in HASH_FIELDS:
        if value[key] is not None and not valid_hash(value[key]):
            raise CorpusError('Invalid observer provenance hash')
    for key in IDENTITY_FIELDS:
        item = value[key]
        if item is not None and (not isinstance(item, str) or
                re.fullmatch('[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,159}', item) is None or '://' in item
                or item.casefold() in ('unknown', 'unset', 'unmeasured', 'none', 'null')):
            raise CorpusError('Invalid observer provenance identity')
    complete = all(value[key] is not None for key in (*HASH_FIELDS, *IDENTITY_FIELDS))
    if value['complete'] != complete or require_complete and not complete:
        raise CorpusError('Observer provenance is incomplete')
    if not valid_hash(value['sha256']) or value['sha256'] != digest({k: v for k, v in value.items() if k != 'sha256'}):
        raise CorpusError('Observer provenance digest mismatch')
    return dict(value)


def safe_provenance(value):
    """Unknown/invalid metadata is not copied into a report as arbitrary text."""
    try:
        return validate_provenance(value)
    except CorpusError:
        return None


def cycle_identity(cycles, config_sha256):
    if not isinstance(cycles, list) or not cycles or not valid_hash(config_sha256):
        return None
    identities = []
    for cycle in cycles:
        if (not isinstance(cycle, dict) or cycle.get('status') != 'completed'
                or cycle.get('coverage') != 'complete' or cycle.get('config_sha256') != config_sha256
                or cycle.get('decision') not in ('quiet', 'watch', 'tell')
                or 'error' not in cycle or cycle['error'] is not None
                or cycle.get('structured_findings') is not True or cycle.get('evaluation_complete') is not True):
            return None
        calls = cycle.get('model_calls')
        if not isinstance(calls, list) or not calls:
            return None
        try:
            identity = validate_provenance(cycle.get('provenance'), require_complete=True)
            if identity['config_sha256'] != config_sha256:
                return None
            for call in calls:
                if (not isinstance(call, dict) or call.get('status') != 'completed'
                        or validate_provenance(call.get('provenance'), require_complete=True) != identity
                        or call.get('model') != identity['configured_model']
                        or call.get('response_model') != identity['response_model']):
                    return None
        except CorpusError:
            return None
        identities.append(identity)
    return identities[0] if all(item == identities[0] for item in identities) else None

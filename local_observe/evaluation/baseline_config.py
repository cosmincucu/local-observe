"""Explicit, content-addressed detector inputs; never derive thresholds from truth."""
from local_observe.inventory.validation import read_document
from local_observe.platform.state import identifier

from .model import CorpusError, ROOT, number
from .provenance import digest


def validate_config(value):
    if (not isinstance(value, dict) or set(value) != {'schema_version', 'thresholds'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or not isinstance(value['thresholds'], list) or not 1 <= len(value['thresholds']) <= 128):
        raise CorpusError('Invalid baseline configuration')
    rows, seen = [], set()
    for row in value['thresholds']:
        if not isinstance(row, dict) or set(row) != {'resource_id', 'metric', 'threshold'}:
            raise CorpusError('Invalid baseline threshold fields')
        identifier(row['resource_id'])
        if not isinstance(row['metric'], str) or not 1 <= len(row['metric']) <= 128:
            raise CorpusError('Invalid baseline metric')
        key = row['resource_id'], row['metric']
        if key in seen:
            raise CorpusError('Duplicate baseline source')
        seen.add(key)
        rows.append({**row, 'threshold': number(row['threshold'])})
    return {'schema_version': 1, 'thresholds': sorted(rows, key=lambda row: (row['resource_id'], row['metric']))}


def prepare(corpus, value=None):
    supplied = value is not None
    if value is None:
        value = {'schema_version': 1, 'thresholds': [
            {'resource_id': row['resource_id'], 'metric': row['series'], 'threshold': row['threshold']}
            for row in read_document(ROOT / 'examples/platform/forecast.yaml')['rules']]}
    config = validate_config(value)
    limits = {(row['resource_id'], row['metric']): row['threshold'] for row in config['thresholds']}
    if supplied and set(limits) != {(row['resource_id'], row['metric']) for row in corpus['series']}:
        raise CorpusError('Baseline configuration must match every corpus source exactly')
    if supplied:
        resources = sorted({row['resource_id'] for row in config['thresholds']})
        inventory = {'schema_version': 1, 'resources': [
            {'id': resource, 'kind': 'host', 'name': 'evaluation-' + str(n), 'aliases': [],
             'attributes': {}, 'relations': []} for n, resource in enumerate(resources)]}
    else:
        inventory = read_document(ROOT / 'examples/inventory/declared.yaml')
        if not {row['resource_id'] for row in corpus['series']} <= {row['id'] for row in inventory['resources']}:
            raise CorpusError('Corpus resources require explicit baseline configuration')
    identity = {'schema_version': 1, 'configuration_authority': 'operator-supplied' if supplied else 'demo-default',
                'config_sha256': digest(config), 'inventory_sha256': digest(inventory)}
    return limits, inventory, identity

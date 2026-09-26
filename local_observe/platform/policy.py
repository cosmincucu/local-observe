"""Deployment-owned action allowlist plus current inventory opt-in."""
from collections.abc import Callable
import json
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator

from local_observe.inventory import index
from local_observe.inventory.validation import canonical
from .state import StateError, identifier


def action_policy(index_path: Path | str,
                  definitions: dict[str, Any]) -> Callable[[dict[str, Any]], None]:
    def validate(request):
        targets = request['targets']
        if not isinstance(targets, list) or not 1 <= len(targets) <= 20 or len(set(targets)) != len(targets):
            raise StateError('Expected distinct bounded targets')
        for target in targets:
            identifier(target)
        definition = definitions.get(request['action'])
        if not definition or definition['version'] != request['version']:
            raise StateError('Action/version not allowlisted')
        if len(canonical(request['parameters']).encode()) > 8192:
            raise StateError('Action parameters exceed limit')
        if not Draft202012Validator(definition['parameters']).is_valid(request['parameters']):
            raise StateError('Action parameters do not match allowlisted schema')
        with index.readonly(index_path) as connection:
            for target in targets:
                row = connection.execute('SELECT attributes FROM resources WHERE id=?', (target,)).fetchone()
                if not row or json.loads(row[0]).get('remediation_enabled') is not True:
                    raise StateError('Target is not opted into remediation')
    return validate

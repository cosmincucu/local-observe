"""Fail-closed preflight for a whole-deployment rehearsal; never launches containers."""
import re
from typing import Any
from .content import Conflict
from .runtime_bundle import check_bundle, compare_bundles
from .recovery import bind_owners


def preflight(bundle: dict[str, Any], snapshot: dict[str, Any], plan: dict[str, Any], *,
              previous_bundle: dict[str, Any], free_bytes: int, required_copy_bytes: int,
              spare_memory_bytes: int, requested_memory_bytes: int, restore_receipts: dict[str, Any],
              now: float | None = None) -> dict[str, Any]:
    pins = check_bundle(bundle, snapshot, plan)
    comparison = compare_bundles(previous_bundle, bundle)
    _, ownership = bind_owners(plan, snapshot, now=now)
    reasons = []
    if pins['status'] == 'blocked':
        reasons.append('Running platform does not enforce notification safety contract')
    if ownership['status'] == 'blocked':
        reasons.append('Recovery ownership or external observation is incomplete')
    values = (free_bytes, required_copy_bytes, spare_memory_bytes, requested_memory_bytes)
    if (any(type(value) is not int or value < 0 for value in values) or not required_copy_bytes
            or not requested_memory_bytes):
        raise Conflict('Measured disk and memory requirements must be positive integers')
    # Backup + restore + rollback copies, plus fixed filesystem headroom.
    if free_bytes < 3 * required_copy_bytes + 2 * 1024**3:
        reasons.append('Insufficient space for verified backup, restore and rollback copies')
    if requested_memory_bytes > spare_memory_bytes:
        reasons.append('Insufficient memory inside the rehearsal budget')
    required = set(bundle['state_owners'])
    if not isinstance(restore_receipts, dict) or set(restore_receipts) != required:
        reasons.append('Per-owner consistent-backup and application-restore receipts are incomplete')
    else:
        recoveries = {o['id']: o['recovery'] for o in plan['owners'] + plan['external_owners']}
        for owner, receipt in restore_receipts.items():
            if (not isinstance(receipt, dict) or receipt.get('passed') is not True
                    or receipt.get('bundle_sha256') != pins['sha256']
                    or receipt.get('recovery') != recoveries[owner]
                    or not re.fullmatch(r'[a-f0-9]{64}', str(receipt.get('verification_sha256', '')))
                    or not receipt.get('verification_artifact')):
                reasons.append('Missing or mismatched restore evidence for '+owner)
            elif (recoveries[owner] == 'backup-restore'
                  and not re.fullmatch(r'[a-f0-9]{64}', str(receipt.get('backup_sha256', '')))):
                reasons.append('Missing verified backup for '+owner)
    return {'status': 'blocked' if reasons else 'review-required', 'deploy_authorized': False,
            'comparison': comparison,
            'whole_stack_recovery_proven': False, 'reasons': reasons,
            'next': 'Review exact isolated targets and writer-stop scope; never reuse live volumes or credentials'}

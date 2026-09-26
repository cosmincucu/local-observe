"""Portable upgrade orchestration with injected deployment and acceptance boundaries."""
from scripts._lib.require import require
from scripts.upgrade_rehearsal import prepare, restore_copy

def start_candidate(run_command, image, state_dir, original_pin, make_release,
                    verify_release, deploy, accept, durable):
    """Migrate and verify before starting; return only after runtime acceptance.

Injected boundaries let offline tests execute the driver's real command ordering.
This function writes no applied receipt, so any exception leaves the prior receipt
in place. Both the initial candidate and the candidate after rollback use it.
"""
    migration = prepare(run_command, image, state_dir, original_pin)
    candidate = make_release(migration['candidate_state'])
    verify_release(candidate)
    deploy()
    accepted = accept(candidate)
    require(durable() == migration['durable_sha256'],
            'Complete candidate durable state changed after migration')
    return candidate, migration, accepted


def require_off_runtime(runtime):
    require(runtime.get('notification_mode') == 'off' and runtime.get('sender_configured') is False,
            'Rehearsal runtime must use off mode without a sender')


def restore_original(stop, checkpoint, output, checkpoint_receipt, previous,
                     deploy, accept, durable, original_hash):
    """Run the original image on a fresh restored copy; never erase a candidate."""
    stop()
    restore_copy(checkpoint, output, checkpoint_receipt)
    deploy(output)
    accepted = accept(previous)
    require(durable() == original_hash, 'Restored original durable state changed')
    return accepted

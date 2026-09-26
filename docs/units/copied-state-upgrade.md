# Copied-state upgrade rehearsal

The portable helpers in `scripts/upgrade_rehearsal.py`, `scripts/upgrade_driver.py` and
`scripts/upgrade_acceptance.py` verify migrations and acceptance against isolated copies.
They do not select a host, grant access or authorize deployment.

## Prepare a copy

Use `local_observe/deployment/state_copy.py` to copy explicitly selected SQLite and JSON inputs.
The caller owns writer exclusion across related resources. A copied database does not prove
application recovery or a consistent snapshot of multiple services. Retain original inputs and
verified backups; use new output paths and preserve failed copies for inspection.

## Migrate and accept

`upgrade_rehearsal.prepare` checks the original pin and the candidate image's state contract,
migrates a stopped isolated `platform.db`, and verifies durable-table preservation. The candidate
image supplies its schema and migration-script identities. Unsupported downgrade or source
identity, changed scripts, unexpected rows and mismatched state are refused.

`upgrade_driver.start_candidate` performs preparation, release verification, deployment and
acceptance in that order through injected callables. It compares the complete durable state
after acceptance and writes no applied receipt. Exceptions leave the prior receipt authoritative.
`require_off_runtime` requires notification mode `off` and no sender during the rehearsal.

`restore_original` stops the candidate, restores into a new path, deploys the prior release and
checks acceptance and the original durable-state fingerprint. It never erases the candidate copy.
After rollback, a new candidate attempt performs migration again from the restored state.

The acceptance helper exercises migrated SQLite, required indexes and maintenance/escalation
behavior separately from the copied operational data. Tests cover actual migrations, tampered
checkpoints, startup state changes, unexpected audit rows and strict notification shutdown.

## Verification scope

`tests/test_upgrade_driver.py`, `tests/test_upgrade_copy_rehearsal.py` and
`tests/test_upgrade_acceptance.py` exercise these boundaries without a live deployment. They do
not establish host capacity, container compatibility, writer exclusion, off-host recovery or
production performance. Measure those for the chosen installation before promotion.

See [state copy](external-state-capture.md), [deployment](../DEPLOYMENT.md) and
[migration](../MIGRATION.md).

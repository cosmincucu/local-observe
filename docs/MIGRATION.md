# Migrating an installation

Migrate a bounded set of producers or capabilities after proving recovery. Keep installation-specific
inputs and evidence in your deployment repository or protected storage, outside the product checkout.

## Prepare

Record the current product revision, customisation revision, image digests, configuration, state
formats, writers and secret references. Inventory dashboards, queries, job definitions and consumers.
Take fresh backups and verify them by restoring into an isolated environment with sufficient capacity.

The baseline tools require explicit input paths. `scripts/prepare_migration.py --help` describes
capture; `scripts/check_migration.py --help` describes comparison. Set `--baseline-dir` or
`LO_MIGRATION_BASELINE_DIR` to an external directory and supply `--source` for the configuration
checkout it describes. These tools do not certify or authorize cutover.

## Rehearse

Use isolated projects, volumes, paths and ports. Do not attach a second database process to live
storage. Disable outbound notification delivery or use a recording sink. Compare representative
queries, stable resource IDs, event counts, dashboard behavior and durable operational state.

Exercise an upgrade, a deliberate acceptance failure, restoration of the previous executable and
compatible state, and a subsequent restart. Reversing an image pin alone cannot reverse a schema
change. Preserve the prior release and its verified backups until acceptance is complete.

## Promote

Choose one producer or capability, define success thresholds and a rollback trigger, and obtain
approval for the concrete operation. Recheck drift, pins, backups and permissions at the change
window. Keep one active notification owner per rule. Observe the result for the agreed period and
advance acceptance receipts only when every required check passes.

Retire old services and data as a separate, explicitly reviewed operation. See
[deployment](DEPLOYMENT.md) and [release requirements](RELEASING.md) for content and state contracts.

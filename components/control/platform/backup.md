# Platform backup and recovery

Back up the platform database, private configuration, credential references and
protected credential store, action policy and declared inventory revision. Retain
the product/image identity and state schema with each checkpoint. This build reads
platform schema **10**.

Use `Store.backup` or the CLI for a consistent standalone SQLite copy:

```sh
lo-platform --database /approved/private/platform.db backup \
  --output /approved/private/backups/platform-checkpoint.db
```

The destination must be new. The operation uses SQLite's online backup API and checks
integrity. Copying only an active database's main file can lose committed WAL data.
Protect backups as carefully as operational state.

The database includes events, incidents, approvals, outbox delivery state, audit,
append-only verification records, runner bindings and setup plans. Verification
history grants no action or notification authority. Callback digests, expiry and
consumed state are retained **as of the checkpoint**. A backup older than a callback's
consumption or an external send cannot know that later effect. Do not assume that
single-use authority survives rollback to an older checkpoint.

## Coordinated state

Pause producers and executors when creating a coordinated checkpoint. Retain:

- Detector cursors and pending batches with platform state.
- Trusted runner intent/execution journals, including protected capabilities.
- Approved guided setup configuration and its `.setup-plan` marker.
- Observer evidence, feedback, acceptance/revocation and delivery accounting through
  its separate [verified journal backup](../../../docs/units/observer.md).
- Protected model route declarations, when selected, including versions needed to resolve
  historical member digests. Route receipts do not contain a recoverable copy of that configuration.
- Independent service histories and receiver receipts where used;
  [synthetics recovery](../synthetics/backup.md) covers Gatus and its detector.

No database backup atomically captures external effects. Keep dispatch disabled after
recovery until retained records have been compared with actual engine and channel
history. Account for lost sends in the observer's daily budget.

## Restore acceptance

Restore a completed standalone backup to a **new destination**, with an image supporting
its schema. Check integrity, incident/event counts, audit history, approval expiry,
verification bindings and append-only triggers before switching services. Inspect
outbox callbacks without exposing digests or clear credentials. Check matching runner
journals, configuration and cursors.

Reconcile unknown claims and actions that may have started after the checkpoint.
Startup can mark retained interrupted claims unknown; it cannot reconstruct actions
missing from an older backup. Revoke or review outstanding authority before restoring
executor credentials. Observer delivery starts disarmed and requires a new process
challenge, independent quality acceptance and external-effect reconciliation.

Retain displaced databases, deployment trees and checkpoints until adoption and rollback
are accepted. Do not use overwrite restores or `down -v`. Exercise encrypted off-host
recovery separately; a local SQLite round trip does not establish recovery after loss
of the host or credential store.

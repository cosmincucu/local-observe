# Agent upgrade

1. Pin old/new collector digests and review receiver, semantic-convention,
   exporter-queue and file-storage compatibility changes.
2. Rehearse from a stopped agent-state snapshot and copied synthetic log files
   in an isolated project. Include both drained and pending-queue cases.
3. Verify stable UUID, changed hostname alias handling, per-core CPU, file
   rotation/offset continuity, authentication and queue recovery.
4. Restore the old image/configuration plus its stopped state snapshot for
   rollback. Reconcile duplicated or skipped markers; do not feed an old
   binary a changed storage format without evidence of compatibility.

Promotion requires recorded results, not just a successfully started container.

# Dagu conformance

Runtime conformance is not-run until verified in your installation.

- Propose a bounded job and verify that execution requires the configured approval.
- Confirm the acknowledged run can be found through the query-only adapter.
- Simulate a lost start acknowledgement; reconcile without duplicating the run.
- Repeat a runner call and verify idempotency and durable action state.
- Restart the engine and verify run history and platform state remain consistent.
- Restore the engine data volume and platform state from verified copies.
- Exercise version upgrade, failed acceptance and rollback on isolated state.
- Verify resource bounds and credential separation before enabling real actions.

An independent dead-man check is described by the
[job-observation contract](../job-observe/CONTRACT.md). Validate it separately; the witness uses
read-only platform access and cannot acquire action authority by reporting an outage.

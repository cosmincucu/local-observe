# Backup and restore

Stop new claims, wait for known runs or mark interrupted outcomes unknown. Stop
only the Dagu/runner services, archive dagu-data and runner journals, and checksum
the archives. Use the platform's online SQLite backup for approval state. Preserve
the pinned image, read-only DAG bytes/hash, binding and restricted credentials.

Restore copies into a separate project/network with execution disabled. Confirm
history for a known UUID and compare platform action/execution/audit counts.
Reconcile any external outcomes before enabling claims. Never replay restored
approvals automatically or delete unknown journals to force another dispatch.
Cold engine-volume restore has not yet been executed; platform-state restore has.

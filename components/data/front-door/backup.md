# Intake queue recovery

1. Stop or pause synthetic producers. Let the queue drain if the store is healthy;
   record accepted/rejected counts and unique stored markers, not just health.
2. Stop the front door before snapshotting `front-door-queue`. Preserve ownership,
   configuration, collector digest and exporter identity. Handle queued telemetry
   as private data. A live file copy is not an established consistent backup.
3. Coordinate the snapshot with the store and agent checkpoints. Restoring an old
   queue against newer store data may duplicate writes; restoring it without
   corresponding source data may lose data. State the chosen replay window.
4. Restore to a new isolated project/volume using the same digest and exporter
   identity. Point it only at the restored demo store, then start intake and
   reconcile unique markers before admitting new traffic.
5. Separately exercise process restart with a nonempty queue during store outage.
   Confirm the queue reopens, drains and exposes failures when the store returns.

Snapshot rollback is not an exactly-once protocol. Record observed loss,
duplicates, queue capacity and recovery time before declaring this recipe proven.

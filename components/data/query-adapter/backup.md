# Backup and restore

Component `query-adapter`. **This component holds no state.** That sentence is the whole content of
this file, so it needs the proof rather than the assertion — three claims, each checkable.

1. **The code is not state.** `local_observe/platform/query.py` and `local_observe/store/` are shipped
   inside the platform image (`docs/BUILD.md`); the running digest is recorded by
   `local_observe/platform/source_pin.py` at every serving start. Restoring a platform state database
   does not restore — or need to restore — any query code, and a reader from an older image reads the
   same store the same way.
2. **The privileges are not inside the volume.** `lo-read.xml` and `lo-query.xml` are bind-mounted from
   the checkout into `/etc/clickhouse-server/users.d/`, so no `CREATE USER` ever wrote a row into
   `/var/lib/clickhouse/access/`. A restored `clickhouse-data` volume therefore carries **no**
   privilege set of its own: the privileges come from the tree that mounts them. That is deliberate
   (the same argument `clickhouse-users.d/backup.md` makes for `lo-query`) — restoring a foreign or
   older volume cannot silently bring back a different grant.
3. **Nothing reads a cursor here.** The producers that consume this component keep their own cursors
   and owe their own backup coverage — the Sigma runner's cursor, the anomaly cursor
   (`local_observe/platform/anomaly_cursor.py`), the drift cursor. `docs/COMPONENTS.md` and
   `platform/README.md` say the estate-wide version of this: backing up the platform SQLite file alone
   is not whole-deployment protection. This component adds no file to that list and removes none.

Runtime state of this file's own: nothing has been restored, and every restore check below
is `not-run` — it is a recipe, recorded so the first operator to restore a deployment can run it.

## What a restore must check, in this order

* The four credential files still exist, in two pairs, and the two users' values differ. Per user
   there are two envelopes of one value: the bare file the client presents as `X-ClickHouse-Key`
   (`LO_CLICKHOUSE_PASSWORD_FILE`, `LO_CLICKHOUSE_READ_PASSWORD_FILE`) and the XML file ClickHouse
   substitutes server-side (`LO_CLICKHOUSE_QUERY_CREDENTIALS_FILE`,
   `LO_CLICKHOUSE_READ_CREDENTIALS_FILE`). A restore that reuses one value across the pairs collapses
   the two identities into one credential, and one that puts both `incl` values in a single document is
   the fail-open path `clickhouse-users.d/CONTRACT.md` argues about. Check for different **hashes**, and
   do not leave the output in a log.
* The server loaded both fragments: the two `system.users` commands in
  [`clickhouse-users.d/conformance.md`](../store-signoz/clickhouse-users.d/conformance.md). A restore
  of a volume whose databases are not `signoz_traces`/`signoz_metrics`/`signoz_logs` leaves both users
  reading nothing, which surfaces as `unavailable` envelopes and coverage events, not as an error.
* A read still refuses to write: `INSERT refused` and `DDL refused` from that same file, run against
  the **restored** store. Restoring privileges by reading a config file is a hope; running the refusal
  is a check.
* Evidence references opened *before* the restore are re-checked as they are read
  (`query.reauthorise`). A restore cannot make an `expired` reference available again, and must not:
  if it did, the platform would be citing rows it did not have at the time it made the claim.

## What is not covered here

Retention is not a backup. `local_observe/store/retention.py` reports the store's declared-versus-live
TTLs (retention's tool, `components/data/store-signoz/retention.py`) and the facade refuses an
`expires_at` that runs past the live TTL the caller supplies — a reference may not promise proof past
the point the rows are gone. That is a refusal at read time, not a recovery path: nothing in this
component can bring back expired telemetry, and the store's own backup/restore recipe is
[`../store-signoz/backup.md`](../store-signoz/backup.md).

# Backup and restore

Nothing in this directory holds state, and that is the point of doing it this way.

Both files reach the container from the checkout: `lo-query.xml` is bind-mounted read-only, and the
credential it substitutes is mounted from the operator's own private file. So a store restore needs
exactly what the store restore already needs (`clickhouse-data`, plus the operator's environment file
and credential directory) and no extra artefact. There is no user row inside ClickHouse's own state to
capture, which is the advantage over creating the user with `CREATE USER`: that would place the
account in `/var/lib/clickhouse/access/`, inside the volume, and a restore of a *foreign* or older
volume would silently carry a different privilege set than the one this directory declares.

Check after any restore that the restored store still refuses a write from this credential: the two
commands in `conformance.md`. A restore that brought back a `clickhouse-data` volume whose database
names differ from `signoz_traces`/`signoz_metrics`/`signoz_logs` leaves `lo-query` able to see nothing,
which surfaces as the Sigma runner failing its healthcheck, not as a silent gap.

## `lo-read` (query adapter) — same rule, one more file, nothing more to back up

`lo-read.xml` and `lo-read.compose.yaml` follow the rule above exactly: both reach the container from
the checkout, the credential stays the operator's private file, and no `CREATE USER` puts a row in
`/var/lib/clickhouse/access/` inside `clickhouse-data`. A restore therefore needs the same artefacts
and no new one — with one caveat specific to this user being **unwired**: if a restore brings back a
volume from before the delta was ever merged, `system.users` will list only `lo-query`, and a reader
configured for `lo-read` will report every read unavailable. Run the two `system.users` commands in
`conformance.md` after any restore, not one.

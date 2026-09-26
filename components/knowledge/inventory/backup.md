# Inventory backup and restore

Status: **recipe; staged lifecycle checks pending**.

Declared authority: preserve the Git YAML revision, schema/package version and
private credential references. Rebuild the index into a new snapshot directory,
compare normalized declaration hash/counts/lookups, then restart the read service
against it. Do not back up a derived index as the only declaration copy.

Observed authority: use sqlite3.Connection.backup with the writer connected, or
stop ingestion before copying the database and any required WAL state. Restore
to a separate path and check integrity, application_id/user_version, snapshot
identity/counts and latest-source selection. Repeat stale/error drift checks;
restoring observations must never change declared YAML. Preserve local review
proposals as review artifacts, not approved declarations. Same-disk copies are
not disaster recovery. Never copy only the main file of an active WAL database.

# Backup and restore

Compiled SQL and its source/version/hash manifest are immutable Git artifacts.
Preserve them with the declaration revision. Stop only the Sigma worker, then
copy its cursor JSON (including any pending batch), verify its checksum and parse
it before restart. Back up platform state through its SQLite backup command;
do not copy a live database without its WAL. Backups contain internal evidence.

Restore to an isolated output directory with intake/notifications disabled.
Verify artifact binding, cursor parsing and platform integrity, then replay the
pending batch against copied state: stable source event IDs must deduplicate.
Do not erase a pending batch to make a changed artifact start; drain/reconcile
the old worker first, then use a fresh cursor for the new rule version.

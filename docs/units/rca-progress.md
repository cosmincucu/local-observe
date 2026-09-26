# RCA incident rotation

`platform/rca_progress.py` gives every open incident a turn without reading all incident history.
`rca.tick` owns the analysis; `Progress` owns only a derived JSON cursor and read-only discovery.
The incident/status index installed by schema 6 is required; this unit creates no database schema.

## Public surface and flow

`location(database, source)` returns `<database>.rca.<source-digest>.cursor.json` beside the database.
The source is a validated producer label and its full SHA-256 digest is the filename fragment.
`with Progress(database, source)` holds `exclusive_owner` on that cursor until the tick exits.
`page(limit)` opens a read-only snapshot, obtains a fixed cycle high-water rowid when starting a cycle,
and reads at most `limit + 1` open incidents above the last examined rowid. The lookahead says whether
the cycle has more work. Both queries require the existing incidents/status index and have a shared
16,000 SQLite-instruction budget. At most 25 incidents enter analysis; only bounded incident/resource
identities cross the discovery boundary. The snapshot closes before the first analysis call.

`advance(rowid)` persists each completed or visibly refused attempt. `finish(more)` marks a short page
complete, including a tail whose incidents closed since the cycle began. The next tick starts at zero
with a new high-water. New arrivals cannot lengthen a running cycle, so they wait for the next cycle.
The existing 100-event bundle limit still applies to each incident's evidence; reaching an old incident
does not recover event history that its bundle cannot read.

The tick reports `attempted`, successful `analyzed`, `failed`, and a bounded `failures` list containing
incident ID, rowid and exception class. Known data/storage failures advance and retry next cycle;
unexpected programming exceptions escape and retain that incident's turn. Model budgets are still
shared by the round. `incidents_open` counts the offered page, `incidents_read` includes its optional
lookahead, and `count_scope: page` makes clear neither is a total open-set count. `capped` means more
eligible rows remain in this fixed cycle; `cycle_complete` means that cycle was exhausted.

## Ownership and durability

The cursor is at most 2 KiB and binds its schema, source and canonical database path. It stores only
the high-water and last examined rowid, never incident lists or telemetry. Unknown fields/versions,
duplicate keys, invalid positions, foreign source/path bindings, oversized/non-JSON files, nonregular
files and visible symlinks/junctions in the database/cursor/lock paths are refused. Refused cursor bytes
are preserved. Database binding is a path identity, not a database-content fingerprint or an
authentication mechanism.

This is single-host state on a local filesystem in the platform's protected database directory.
Advisory ownership and path checks are not protection against an attacker who can replace directory
entries, and network/mapped filesystems are unsupported. Each save writes an exclusive temporary file,
flushes and fsyncs it, then atomically replaces the cursor; POSIX also fsyncs the directory. Windows
rename durability across power loss is unverified. The owner lock remains as a file after exit; the
kernel releases ownership when the process exits. It must not be deleted while a tick is running.

An explanation is committed before progress advances. A crash in that gap repeats one attempt;
unchanged content is not appended again. A failed save can leave either old or new cursor bytes;
the next tick reloads them under ownership. No notification, incident, action, or control row is changed.

## Backup and restore

Stop the scheduled RCA invocations and verify their owners exited before copying the derived cursor
beside the consistent platform database backup. Lock files are excluded. Keep a verified copy of any
cursor before reconciling it. A cursor restored to the same database path resumes its cycle; a restored
database with fewer rows can finish the old tail and then restart on the following tick. Restoring to
a different database path is deliberately refused. In isolated staging, omit the derived cursor to
start a fresh cycle; the retained audit records remain and unchanged explanations do not duplicate.
Losing/resetting a cursor delays a turn until a new complete cycle; it does not lose incidents or
delete explanations. A rollback to an older image ignores this cursor, and its older scheduling limits
return. See the component's [backup](../../components/control/rca/backup.md) and
[upgrade](../../components/control/rca/upgrade.md) procedures.

`VACUUM` or a database rebuild can reassign hidden rowids. Stop and drain the RCA owner, take and
verify the database and cursor backups, and reset this derived cursor after that maintenance before
resuming. Keep audit history; the new cycle repeats unchanged explanations safely.

## Checks

`tests/test_rca_progress.py` covers six incidents with a five-incident budget and restart; more than
100 incidents and arrivals during a cycle; unchanged/replayed writes; one corrupt incident among valid
ones; cursor corruption, foreign bindings, ownership contention and path refusals; closed tails;
10,000 closed historical rows with indexed query plans; and an intentionally exhausted SQL budget.
`tests/test_rca_component.py` retains the CLI and unchanged operational-state scenarios.

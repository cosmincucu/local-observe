# Inventory upgrades

Status: **recipe; no cross-version upgrade path claimed**.



Pin old/new package, schema, Datasette/plugin and container identities. The runtime
package set is requirements.in (intent) and requirements.lock (resolved closure with one
sha256 per wheel); regenerate it with the command recorded in docs/BUILD.md and never by
hand. Rebuild a new declared snapshot; keep the old snapshot and reader image for rollback.
Existing immutable readers must be restarted when switching snapshots. Validate
UUID/alias continuity, graph results, auth, REST/GraphQL and bounded queries.



Back up observed state with SQLite's backup API before changing its schema.
Current readers/writers refuse unsupported application/schema identities; do not
invent a migration or overwrite an unrelated SQLite. Rehearse explicit future
migrations and rollback on copies, including retries, late snapshots and source
failures. Old binaries must not be pointed at migrated observed state without
compatibility evidence. PR proposals remain subject to human review throughout.

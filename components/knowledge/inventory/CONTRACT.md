# Inventory v1

Status: **experimental**. Run the conformance checks for your selected deployment.

Git YAML is authoritative; build output is disposable. Public schemas are packaged
under [local_observe/inventory/schemas](../../../local_observe/inventory/schemas).
Resources have canonical lowercase UUIDs, a supported kind, display name, explicit
typed/scoped aliases, scalar attributes and UUID relations. Hostnames normalize
case/trailing dots; IPs normalize through ipaddress. Other alias types and scopes
are case-sensitive. Names are not implicit aliases. Conflicts fail the declaration
build; conflicting observed aliases or unknown explicit UUIDs stay unresolved.
Keep old aliases on rename. Dependency cycles are allowed; bounded graph queries
deduplicate nodes. Obvious credential attribute names are rejected; this is not
a general secret scanner. Use credential_refs, not literal credential values.

The atomic builder validates all input before replacing an index. Metadata carries
schema version, caller-supplied revision label, normalized declaration hash and UTC
build time. A revision label is not proof that the YAML was committed. Resources,
aliases, relations and build_metadata are the initial tables, not speculative tables.
Failed builds preserve the old snapshot. Windows open-file replacement may fail
cleanly; never fall back to overwriting a served database in place.

Datasette 0.65.3 + datasette-graphql 2.2 serve an immutable index. Restart/recreate
the reader when promoting a new snapshot; do not replace a file under immutable
connections and assume hot reload. Mount only its snapshot directory read-only.
API requires a separate bearer credential, supplied as the file
`LO_INVENTORY_TOKEN_FILE` (Compose mounts it at `/run/secrets/inventory-token` from the host
path of the same-named variable) and never as an environment value: the value would be
readable through `docker inspect` and `/proc/<pid>/environ`, and the compose healthcheck
reads the same file rather than an env copy of it. Bearer auth is for API clients; browser
Basic auth uses user operator and that token as password. Only GET/HEAD/OPTIONS
are allowed. REST /inventory/resources.json and GET /graphql/inventory are read
interfaces, not action authority. SQL endpoint/download/streaming export disabled;
SQL time/row and GraphQL aggregate work limits are configured.

Bind loopback by default, use a verified tunnel or TLS proxy for remote access.
No observed DB, operational DB, Docker socket or host root is mounted. The optional
inventory service does not alter the required telemetry foundation.

Observation ingest is local trusted-provider input, not authenticated discovery
transport. It writes a separate WAL/FULL SQLite with snapshot retry identity and
source provenance. Failed, stale, incomplete or conflicting observations never
establish absence. Missing requires fresh successful complete scope. Partial
attribute observations compare only declared keys actually reported. Local
proposal JSON is review-only, mints a UUID once and never edits declarations.
Automatic forge PR delivery and live provider adapters remain unimplemented.

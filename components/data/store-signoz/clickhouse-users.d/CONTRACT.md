# Read-only ClickHouse query user (delta)

Not a component. This directory holds one Compose **delta** and the ClickHouse config it mounts, so
that `examples/full/` can give the Sigma runner a query credential that cannot write. It carries the
four lifecycle documents because `scripts/check_foundation.py` requires every Compose file reached
through an `include` entry to live in a directory that has them, which is also how
`components/control/operator/` (the other delta in this repository) is arranged.

| File | What it is |
| :-- | :-- |
| `lo-query.xml` | ClickHouse users config fragment: defines user `lo-query` and the profile that binds it. Mounted read-only at `/etc/clickhouse-server/users.d/lo-query.xml`. |
| `compose.yaml` | The delta: appends that mount and one secret to the `clickhouse` service of `../compose.yaml`. Merged by `examples/full/compose.yaml`; never used alone. |
| `lo-read.xml` | **query adapter.** The sibling fragment: user `lo-read` on profile `lo-analysis`, the same seven bounds with a multi-row ceiling. Ships reviewed and **unmounted** — see "The second user" below. |
| `lo-read.compose.yaml` | The delta that would mount it, plus its own required secret. In no example yet, deliberately; its header says why. Never used alone. |

## Contract

Each XML `<grant>` value must be a grant statement, for example
`GRANT SELECT ON signoz_logs.*`. Bare `SELECT ON ...` entries are invalid grant statements. Validate the query user
against the pinned ClickHouse release before using it.

The Sigma runner queries the store directly (`local_observe/platform/sigma_runner.py`, class
`ClickHouse`), so it needs a ClickHouse credential. That credential must not be able to change the
store, because the runner is the component most often restarted with a new compiled artifact and the
one whose query text arrives from a compiler rather than from a review of this directory. Three
things make that true, and `lo-query.xml` states all three:

* **`readonly = 1`** — read data queries only. ClickHouse's own page on query permissions: "When set
  to 1, allows: All types of read queries (like SELECT and equivalent queries). Queries that modify
  only session context (like USE)", and "After setting `readonly = 1`, the user can't change
  `readonly` and `allow_ddl` settings in the current session." An `INSERT`, `OPTIMIZE` or anything
  that alters data is refused.
* **`allow_ddl = 0`** — the same page lists `allow_ddl` as a separate setting with default **1**, so
  `readonly` alone would still permit `CREATE`/`ALTER`/`DROP`/`TRUNCATE`. Both are set.
* **grants limited to the three signal databases** — `SELECT ON signoz_traces.*`,
  `signoz_metrics.*`, `signoz_logs.*` and nothing else: no `system.*`, no other database, no column
  grants. ClickHouse's GRANT page: "the `GRANT SELECT ON db.* TO john` query allows john to execute
  the SELECT query over all the tables in db database".

The query user therefore **cannot write, cannot create a table, cannot alter retention and cannot
read telemetry outside the three SigNoz databases**. That is the whole claim of this directory;
`conformance.md` here is the command set that proves it rather than asserts it.

## The password, and why a missing one stops the boot

`lo-query.xml` does not contain the password. It contains `<password incl="lo_query_password"/>` and
an `include_from` naming `/run/secrets/clickhouse-query-credentials`, which the delta mounts from the
operator's `LO_CLICKHOUSE_QUERY_CREDENTIALS_FILE` (ClickHouse configuration docs, "Substitution with
file content": the `include_from` element "is read from each configuration file individually", so it
belongs in a `users.d` fragment, not in `config.d`).

The ClickHouse behaviour that decides the shape is a bad one: a substitution that cannot be resolved
"is recorded in the log" and the element is simply left empty, and an empty `<password>` is a user
with no password. So the path is a **required** Compose variable (`${VAR:?}`) holding the path of a
file that must exist: Compose refuses to render without it, which puts the failure in front of the
operator at `config` time instead of leaving an anonymous read account listening on the project
network. Never give this secret a default and never add `optional="true"`.

Two files carry the one value, in the two forms their readers demand: `LO_CLICKHOUSE_PASSWORD_FILE`
is the bare value the runner presents as `X-ClickHouse-Key`, and
`LO_CLICKHOUSE_QUERY_CREDENTIALS_FILE` is that same value wrapped in the XML ClickHouse substitutes.
The duplication is deliberate and is the same shape as `LO_PRODUCER_TOKEN_FILE`, which copies one row
out of the platform credentials file because a process may hold only the credential it needs.

## The second user (`lo-read`), and what it is not yet — query adapter

`lo-query` was written for one question per window. The platform now asks wider ones — the store
facade (`local_observe/store`, store facade) reads up to 2 000 metric samples, 200 log records and 100 spans
per read — and those reads are already running **as `lo-query`**. That is the finding this directory
had to write down rather than decorate:

`lo-query.xml` states `<max_result_rows>1</max_result_rows>` **and** marks `max_result_rows`
`changeable_in_readonly`. Under `readonly = 1` that marking is what allows a client to state its own
row cap at all (`lo-query.xml`'s own header says the marking exists so "the runner's own request is
not refused"), so the number `1` in that file is a default for a client that asks for nothing. It is
not a ceiling. A reader that states `max_result_rows=2001` is served 2 000 rows today, and the
sentence "aggregate-only, one row" in `docs/COMPONENTS.md` describes the runner's SQL, not the user's
privileges.

One profile cannot be both numbers, so query adapter splits the identities rather than editing the guarantee:

| | `lo-query` (existing) | `lo-read` (new, unwired) |
| :-- | :-- | :-- |
| Profile | `lo-readonly` | `lo-analysis` |
| `max_result_rows` default | 1 | 2 000 — `local_observe/store/client.py:MAX_ROWS`, the transport's own bound |
| The other six bounds | `5 / 1 000 000 / 64 MiB / 128 MiB / throw / throw` | identical, same sizes |
| Grants | `SELECT` on `signoz_traces|signoz_metrics|signoz_logs` | the same three, character for character |
| Password | `lo_query_password`, from `/run/secrets/clickhouse-query-credentials` | `lo_read_password`, from a **separate** file at `/run/secrets/clickhouse-read-credentials` |
| Mounted by | `compose.yaml`, included by `examples/full` | `lo-read.compose.yaml`, included by nothing yet |

`tests/test_query_adapter.py::AnalysisProfile` enforces the equality side of that table — same settings
keys, same constraint names, same three grants, one differing value — so a later edit that widens
`lo-read` past `lo-query`, or drops `allow_ddl` there, fails a test instead of passing a review.

**Two steps, in this order, and only the reviewer decides them.** The end state is `lo-query` narrowed
back to a real ceiling (delete its `max_result_rows` entry from `constraints`, so the number means
something) and the facade reading as `lo-read`. Reversed, it is an outage: `local_observe/store` still
sends `bound + 1` on the same credential, and ClickHouse refuses a non-`changeable_in_readonly` setting
change under `readonly = 1`. So:

1. wire `lo-read` (the `lo-read.compose.yaml` include, its `.env.example` line, the reader's
   `LO_CLICKHOUSE_READ_PASSWORD_FILE` mount in `components/control/sigma/compose.yaml`), and point the
   facade at it;
2. then narrow `lo-query`, and re-run this file's `conformance.md` against both users.

The credential is one value in one file each, and the reason they are not one file with two elements
is ClickHouse's own behaviour: an unresolvable `incl` is *logged and left empty*, and an empty
`<password>` is a passwordless user. A shared substitution document would mean that a file written for
`lo-query` — which is what exists on hosts brought up before this change — boots `lo-read` with no
password the moment its fragment is mounted. That is why the mount and its secret ship as one delta
and why `LO_CLICKHOUSE_READ_CREDENTIALS_FILE` is required with no default.

**What is not true today, stated plainly.** `lo-read` exists in this tree and nowhere else: no example
includes its delta, no host has created the user, and no command in `conformance.md` has been run
against it. `local_observe/platform/query.py` will therefore refuse to build a reader for it (one log
line naming `LO_CLICKHOUSE_READ_PASSWORD`) rather than fall back to `lo-query`'s credential — a silent
swap to the aggregate user is how a widened ceiling ends up invisible.

## A writer for the owned store (`security_events`) — **proposed, not applied** (security store)

`local_observe/security/` builds an owned `security_events` database for Sigma findings. Read the
claim on its own terms first: **no user in this directory can touch that database.** `lo-query` is
`readonly = 1` (an `INSERT` is refused, and so is `OPTIMIZE`), `allow_ddl = 0` (so it cannot create the
database either) and granted SELECT on the three signal databases only — which excludes both
`security_events.*` and the `system.tables` row the TTL drift check reads. The same is true of
`lo-read`, character for character on the grants. Nothing here is broken by that; the runner's
credential is deliberately unchanged, and its write hook stays unconfigured until this is decided.

So the store needs a third user, and the grant is **a reviewer's decision, not something this change
ships**: no XML below is applied, no delta mounts it, no example names a variable for it, and
`lo-query.xml` is untouched. What is proposed — the minimum set the product's own statements
need (`local_observe/security/store.py`: one `INSERT`, one aggregate `SELECT` of `create_table_query`,
and the event/expired count reads) — is `lo-security`: `readonly` unset, `allow_ddl = 0`, `INSERT ON security_events.events`,
`SELECT ON security_events.*`, `SELECT ON system.tables`, its own mounted credential in its own file
for the reason already stated above (an unresolvable `incl` leaves a *passwordless* user), and the same
seven read bounds as `lo-readonly` so the TTL read is no wider than any other. The exact fragment, as
a diff to a **new** file `lo-security.xml` plus its own `lo-security.compose.yaml` delta, is in the
security store worker report.

Three things the reviewer is being asked to accept, priced:

* **It is the first write-capable ClickHouse user this repository defines.** Every other credential is
  read-only by construction. The blast radius is one database that holds `principal` and `raw` (the
  columns deliberately kept out of the short-TTL projection) plus the ability to read `system.tables`
  table names and TTL strings; it cannot create, alter, drop or truncate (`allow_ddl = 0`), cannot
  touch `signoz_*`, and — if it is mounted with a `<networks>` block narrowed to the project subnet
  rather than copied from `lo-query.xml`'s `0.0.0.0/0` — cannot be reached from off that network.
  A leaked write credential can insert forged security rows and read what it inserted; it cannot erase
  the operational record, which lives in SQLite behind the platform's single writer.
* **The DDL stays outside it.** `apply-schema` needs `CREATE` and `allow_ddl = 1`, which this user
  deliberately does not hold, so provisioning the owned table is either the store administrator's
  `clickhouse-client` or `python -m local_observe.security.cli print-schema` piped to them. That is
  why a worker cannot create its own schema: it has no credential that could.
* **`OPTIMIZE` is not in the grant.** Proving aged rows *actually* disappear needs
  `OPTIMIZE TABLE security_events.events FINAL` (ClickHouse requires an `ALTER TABLE UPDATE/DELETE`
  permission for it) and it is deliberately an operator command, recorded in
  `components/data/store-signoz/backup.md` and `conformance.md`, not a scheduled job: forcing merges on
  a table with a five-year tier is a load decision, not a check.

Two unknowns this directory cannot settle and will not pretend to have: whether ClickHouse hides
`system.tables` rows for a database the user has no grant on (the proposed grant covers the case the
product asks about — its own database and its own table — and the other case is an observation, not a
requirement), and how the pinned server renders a multi-condition table TTL in the documented
[`system.tables.create_table_query`](https://clickhouse.com/docs/reference/system-tables/tables) column. Both are
answered by running the commands in this directory's `conformance.md`; until they are, the grant above
is a design. The existing bounded reader requests one aggregate row with `count()` and
`any(create_table_query)`; an absent or hidden table is `unreadable`, while an existing table without
a table TTL is `no-ttl`. The parser extracts the table TTL and refuses anything beyond the exact two
guarded timestamp-plus-day deletions. Pinned-server acceptance remains unverified.

## What this does NOT do

* **It does not restrict where `lo-query` may connect from.** `<networks>` allows any address on
  purpose: the runner is a container whose address on the Compose network is not stable, so the real
  boundary is that network plus the password. Narrow the two entries if you can name your project
  subnet.
* **It does not touch the store's `default` user**, which stays passwordless on the project network
  because SigNoz itself connects without credentials (`SIGNOZ_TELEMETRYSTORE_CLICKHOUSE_DSN=tcp://
  clickhouse:9000` in `../compose.yaml`). Closing that is a change to the store contract and to the
  SigNoz DSN, not something a delta can do, and it is recorded in `../CONTRACT.md` as the remaining
  hole in this network.
* **Nothing here has been executed.** There was no Docker host where full example gaps was drafted, and
  `components/control/sigma/conformance.md` still lists "Dedicated HTTP query-user permissions" as a
  gate before that component is called validated. The open questions worth a reviewer's attention are
  in `conformance.md`.

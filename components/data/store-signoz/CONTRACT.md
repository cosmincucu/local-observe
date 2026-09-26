# SigNoz reference store

## Interfaces and dependencies

- Internal OTLP: `signoz-otel-collector:4317` and `:4318`. Both require
  `Authorization: Bearer <the store credential>` — a **separate** credential from the
  front door's ingest token, so a leaked ingest token cannot write telemetry
  directly into the store. This is **transport auth, not tenant isolation**: one
  shared token authenticates every writer, and `resource_id` inside the payload is
  still a self-declared claim, not an authorisation. Nothing here stops a holder of
  the store token from writing any resource identity.
  `bearertokenauth` is assumed to exist because the image is a SigNoz build of the
  OpenTelemetry *contrib* collector; it is **not yet confirmed against this pinned
  digest** and must be confirmed on first boot (an unsupported extension makes the
  collector refuse to start — it fails closed, it does not silently listen open).
- That credential is a mounted secret, not an environment value: the service sets
  `LO_STORE_TOKEN_FILE=/run/secrets/store-receiver-token` and collector.yaml reads it with
  confmap's `file` provider. Read at the pinned tag `v0.144.8` of
  `SigNoz/signoz-otel-collector`: `signozcol/collector.go` (`newOtelColSettings`) registers
  `envprovider` **and** `fileprovider` as the resolver's providers, and
  `cmd/signozotelcollector/main.go` starts the collector through `signozcol.New` for the plain
  `--config` path this manifest uses — so `${file:...}` resolves in this image. As in the other
  collectors, the file holds the token and no trailing newline: `NewRetrievedFromYAML`
  (`confmap/provider.go`) returns the raw bytes for a string-valued file.
- The store's **own** session-signing secret is the one credential in this component still
  passed as an environment value (`SIGNOZ_TOKENIZER_JWT_SECRET`, from `SIGNOZ_JWT_SECRET`). It is
  named in neither the secret files table nor the `LO_` prefix range the foundation gate checks, and
  whether `signoz/signoz:v0.138.0` can read it from a file was not investigated for this change.
  It is therefore a known open item, not a decided exception.
- Store collector liveness: compose healthcheck probes the `health_check` extension
  on `127.0.0.1:13133` inside the container with `wget --spider -q`. The image's
  `/bin/sh` is proven by the service's own entrypoint; the presence of `wget` in it
  is **assumed and unconfirmed** — if absent the service reports unhealthy while
  still serving, which is a loud false alarm, not a silent pass.
- UI/API: `127.0.0.1:${LO_UI_PORT:-18081}`. Use a verified SSH tunnel remotely.
- Internal ClickHouse native/query endpoints: `clickhouse:9000` and `:8123`.
- ZooKeeper and ClickHouse are intentionally unauthenticated inside the isolated
  demo network. This is a trusted-network prototype, not a hostile-tenant boundary.
  Do not attach arbitrary workloads or publish their ports.
- Startup order: verified histogram binary and ZooKeeper, ClickHouse, completed
  schema migrations, then store collector and SigNoz. Migration failure must block
  dependent services. Health alone does not establish query/ingest conformance.
- No dependency on RCA, inference, inventory, portal, security or notifications.
- The store collector uses the checked-in static configuration. OpAMP-managed
  configuration is not enabled by default: the first empty-install rehearsal
  showed a running manager process without an OTLP listener. Ingestion must not
  wait for UI onboarding or a remotely supplied configuration.

Inputs: `LO_CLICKHOUSE_IMAGE`, `LO_ZOOKEEPER_IMAGE`, `LO_SIGNOZ_IMAGE`,
`LO_SIGNOZ_COLLECTOR_IMAGE` as digest-qualified references; `SIGNOZ_JWT_SECRET`;
`LO_STORE_TOKEN_FILE` (host path of the receiver credential file above); absolute Linux path
`LO_HISTOGRAM_BINARY` and its `LO_HISTOGRAM_SHA256`.
The binary is an executable trust input: verify provenance before mounting it.
Changing the JWT secret may invalidate sessions; it belongs in private secret storage.

## Persistence and limits

Project-scoped volumes: `clickhouse-data`, `signoz-sqlite`, `zookeeper-data`,
`ch-user-scripts`. Never reuse volumes from the source estate. SigNoz's SQLite
is application state, not the platform operational-state database in CONTRACTS.

Initial ClickHouse container cap is 8 GiB, server cap 6 GB, query cap 1 GiB;
these changed from the private source and need load validation. Retention is
separate and has its own section below; nothing in this directory bounds how long
application telemetry lives.

The store collector retains source in-memory batching/exporter behaviour, with a
`memory_limiter` added first in every pipeline (1100 MiB limit, 256 MiB spike, in a
1536 MiB container). Under pressure it now drops data instead of being OOM-killed;
that drop is not visible to the producer as a store-side failure.
An accepted OTLP request is not proof of a committed ClickHouse write.
Crash loss, duplicates and outage recovery must be measured before validation.
The front door's persistent queue cannot repair already-acknowledged store loss.

## Read-only query user

A deployment that runs the Sigma runner needs a ClickHouse credential that **cannot write**. That
user is `lo-query`, defined by [`clickhouse-users.d/lo-query.xml`](clickhouse-users.d/lo-query.xml):
`readonly = 1`, `allow_ddl = 0` and `SELECT` on `signoz_traces`, `signoz_metrics` and `signoz_logs`
and nothing else. It therefore cannot insert, merge, create, alter, drop or truncate a table, and
cannot read telemetry outside the three signal databases. `clickhouse-users.d/CONTRACT.md` carries
the settings one by one with the doc quotations, and `clickhouse-users.d/conformance.md` is the
command set that proves the claim instead of asserting it.

`compose.yaml` in **this** directory does not create or mount it. The store component runs today
exactly as it did before full example gaps, with one user that matters: `default`, **passwordless on the Compose
network**. That is not an oversight to fix inside an example — SigNoz itself connects with
`SIGNOZ_TELEMETRYSTORE_CLICKHOUSE_DSN=tcp://clickhouse:9000` and no credentials, so restricting or
renaming `default` means changing that DSN, the SigNoz contract and the migrator/collector DSNs in
the same move. Anyone who reads `lo-query` as "the store has no anonymous access" has read the wrong
boundary: the read-only user bounds what the *runner's* credential can do, and the network is still
the trust boundary for everything else. Closing the `default` hole is a separate change to this
contract, and its cost is three DSNs plus a credential file for SigNoz.

The read-only user arrives as a Compose **delta** merged by `examples/full/compose.yaml`, not by this
manifest, so that `examples/demo` is not required to carry a credential nothing in it reads (see the
delta's own header, and the `Example compositions and environment templates` row in
`DEPENDENCIES.md`). `components/control/sigma/conformance.md` still lists "dedicated HTTP query-user
permissions" as an open gate: no Docker host was available where this was written, so the user is a
reviewed config plus an unexecuted proof, not a validated behaviour.

## Platform read path

Every platform reader — the Sigma runner, the anomaly producer, and from store facade onward the store facade
that RCA, forecasts, error budgets and the assistant's read tools will use — asks this store one kind
of question: a `SELECT` posted to ClickHouse's HTTP interface under the profile above. clickstack / hyperdx's phase-1
rule is what binds it: **ClickHouse tables, not SigNoz HTTP APIs**. The SigNoz query API stays the
operator's UI and nothing in `local_observe/` calls it. The one exception is a write path rather than
a read: `retention.py` below reads and sets TTLs through the SigNoz settings API, because that setting
exists nowhere else — and `local_observe/store/retention.py` compares declared tiers against *that
program's own reading* (it imports it) instead of forking a second TTL client.

**Which tables.** `QUERY_SQL` in `local_observe/store/backends/clickhouse.py` names them; nothing else
is reachable through the facade:

| Query kind (`query_type`) | Tables | Rows |
| --- | --- | --- |
| `metric-threshold` | `signoz_metrics.distributed_samples_v4` joined to `signoz_metrics.distributed_time_series_v4` — newest labels per fingerprint, so a sample is not fanned out once per series row | 2 000 |
| `source-heartbeat` | `signoz_logs.distributed_logs_v2` | 1 aggregate |
| `log-records` | `signoz_logs.distributed_logs_v2` | 200 |
| `trace-spans` | `signoz_traces.distributed_signoz_index_v3` | 100 |
| `describe-metrics` / `describe-logs` / `describe-traces` | the same three, one aggregate each | 1 |

`signoz_logs.distributed_logs_v2_resource` is deliberately **not** read: it is the resource-attribute
table the v0.1 adapter used to list hosts, and this platform queries by the declared `resource_id` a
producer stamps on the signal itself (CONTRACTS §2), so a second table would be a second identity to
keep in step. A statement is reached only by its key: the public surface takes a query kind plus the
approved evidence parameter names, never a caller-supplied statement, and every `{name:Type}` token in
the text is filled by a ClickHouse query parameter (`param_name`). Optional filters narrow with the
guard form `({x:String} = '' OR …)` rather than by splicing the statement, which costs one predicate
evaluation per row on a scan those byte and row caps already bound.

**Which user, and where its credential comes from.** `lo-query`, through the three variables the Sigma
runner's component already sets — `LO_CLICKHOUSE_URL`, `LO_CLICKHOUSE_USER`,
`LO_CLICKHOUSE_PASSWORD_FILE` (a mounted file; `components/control/sigma/compose.yaml`). The read path
arrives with **no new mount, no new variable and no wider grant** than the runner already had, and
`store_from_environment` reads exactly those three.

**Which bounds.** Sent on every request rather than trusted to the caller, and all seven marked
`changeable_in_readonly` in the profile above so a request is not refused for asking: `readonly = 1`,
`max_execution_time = 5`, `max_rows_to_read = 1000000`, `max_bytes_to_read = 67108864`,
`max_memory_usage = 134217728`, `result_overflow_mode = throw`, `read_overflow_mode = throw`, plus
`max_result_rows` = the kind's row bound **plus one**. That extra row is what makes a cut detectable:
a page that filled its bound is reported as `truncated` rather than read as a whole answer. The
response itself is read at 65 537 bytes and anything larger is refused, the socket timeout is 10
seconds, and no proxy and no redirect is installed on the request's opener.

One coupling to know before editing either side: the profile pins `max_result_rows` to **1**, so
without the `changeable_in_readonly` entries a 2 000-row read is refused by the server. Removing one
of those entries turns a facade read into an error, never into a wider answer — the right failure,
but it will look like a store outage.

**What a read returns.** `docs/CONTRACTS.md` §2 and §4, not a row list: the answer is a reference
(query kind, approved parameters, window, expiry, row count, truncation) that platform intake admits as
an event's evidence and reauthorises later. A window whose evidence would already be expired is
refused before any row is returned; a read whose expiry runs past the retention the store reports is
refused; and a series the store has never seen answers `unavailable`, never an empty list inside a
success envelope. Only `metric-threshold` and `source-heartbeat` may be *named* as evidence, because
those are the two `state.validate_event` admits today; `log-records` and `trace-spans` return rows and
refuse to become a reference until the platform widens that vocabulary by decision.

**What happens when the read-only user is missing.** Three cases, and they fail differently:

- *The credential file is unset.* Compose refuses to render the required secret and
  `local_observe.credentials.read_credential` raises a `KeyError` naming both
  `LO_CLICKHOUSE_PASSWORD_FILE` and `LO_CLICKHOUSE_PASSWORD`. The reader never starts and never
  authenticates as nobody.
- *The user is absent, or its password disagrees.* ClickHouse answers 401/516, the client turns that
  into one `TransportError` carrying neither the credential nor any row text, and the facade reports
  the read as unavailable. There is no fallback to a second credential and no retry as another user: a
  store that will not answer the read-only user is a store this path cannot read.
- *The delta was never merged* — the state of `examples/demo`, which ships only `default`, which is
  passwordless on the project network. Pointing the facade at `default` runs the same seven statements
  and still sends `readonly = 1`, so *those queries* cannot write. What is lost is the grant boundary:
  `default` can read every database and can write through any other client, so read-only-ness becomes
  a property of this module's discipline rather than of the credential. Anyone running a second reader
  with that credential should assume it can write. Closing it is the separate `default`/DSN change
  named above, not something the facade can arrange.

**Status.** Never executed against a live store, exactly like the user itself. The row shapes above come
from the pinned SigNoz build's table definitions and from the compiled-Sigma path that has run against
staging, and `components/control/sigma/conformance.md` still carries the open permission gate. A read
that meets an unexpected column type or `Map` shape fails closed as unavailable; it never guesses a
unit or coerces a value into a plausible one.

## Owned `security_events` database (security store)

The Sigma runner's findings have somewhere analytical to go: a fourth database, `security_events`, with
one table this repository owns (`security_events.events`, DDL rendered by
`local_observe/security/schema.py` from the policy in `local_observe/security/ttl.py`). It is a
database and not a label inside `signoz_logs` for the two reasons §Retention cannot be bent to cover:
SigNoz's TTL setting is **per signal** — one number for every row of `signoz_logs` — and its upgrade
migrations rewrite the tables it manages, so a hand-ALTER inside `signoz_*` is a claim until the next
version. A tier over a security record needs both, so it lives where neither applies. The full contract
is `docs/CONTRACTS.md` §4.3; what this component has to hold is four things:

* **Nothing in this directory creates or mounts it.** The DDL is applied by an operator, explicitly:
  `python -m local_observe.security.cli apply-schema` (idempotent, `IF NOT EXISTS` throughout) or
  `print-schema` piped into `clickhouse-client`. No worker applies it on boot, and no code in the
  product issues an `ALTER` — a table whose extracted table TTL disagrees with the policy is reported
  as `drift` and fixed by a human, which is the whole point of the check.
* **Its retention is not this component's retention.** `retention.py` and the table above it speak the
  SigNoz settings API, which has no notion of a fourth database: `security_events` is invisible to
  `GET /api/v1/settings/ttl`, is not bounded by `LO_RETENTION_*_DAYS`, and does not use the
  per-signal telemetry retention settings. Its two tiers (1825 days `critical` / 90 days `routine`) live in
  `local_observe/security/ttl.py` alone and are read back with
  `python -m local_observe.security.cli verify-ttl`. Disk consequence, stated because the budget above
  does not cover it: this database grows with *findings per day* and nothing else, and its long tier is
  years — `bytes_kept = findings_per_day × row_bytes × days_kept`, measured the same way as above.
* **No existing user can touch it, and that is a decision and not an oversight.** `lo-query` is
  `readonly = 1` with SELECT on the three signal databases only: it can neither insert a finding nor
  read `security_events` nor read `system.tables` for the TTL check, and the runner's credential is
  deliberately unchanged by this change. The proposed separate writer user is in
  [`clickhouse-users.d/CONTRACT.md`](clickhouse-users.d/CONTRACT.md) ("A writer for the owned store")
  as a **proposal awaiting review**; the grant XML is not applied here and no host has the user.
  `store-signoz` therefore ships no `security_events` mount, no new variable and no new secret.
* **Its parts land inside `clickhouse-data`, which is what makes the backup claim checkable** — and it
  is a claim, not a fact anyone has measured. See [backup.md](backup.md) step 4a for the two commands
  that answer it and for the answer as of this writing.

The TTL read uses the documented [system.tables.create_table_query](https://clickhouse.com/docs/reference/system-tables/tables)
column through the existing bounded query client. It extracts only the table TTL and requires exactly
the two guarded timestamp-plus-day deletions, accepting `INTERVAL n DAY` and `toIntervalDay(n)`.
Absent or hidden tables and malformed metadata are `unreadable`; an existing table with no TTL is
`no-ttl`. Synthetic unit tests cover these shapes; pinned-server `verify-ttl` and reader-grant
acceptance remain unverified.

## Retention

Retention for application telemetry is a **server-side setting inside SigNoz, written through its
HTTP API**. No mounted file carries it, so no container can apply it at boot: the only retention
settings checked into this tree are ClickHouse's own internal logs (`clickhouse-memory.xml:6-10` --
`trace_log`, `text_log`, `query_log`, `processors_profile_log` at three days), which say nothing
about how long metric samples, log records and spans are kept. [`retention.py`](retention.py) is the
one thing in the product that sets telemetry retention.

| Signal | Expected default | Declared as | API write |
| --- | --- | --- | --- |
| traces | 7 days | `LO_RETENTION_TRACES_DAYS` | `POST /api/v1/settings/ttl?type=traces&duration=<days*24>h` |
| metrics | 30 days | `LO_RETENTION_METRICS_DAYS` | `POST /api/v1/settings/ttl?type=metrics&duration=<days*24>h` |
| logs | 14 days | `LO_RETENTION_LOGS_DAYS` | `POST /api/v2/settings/ttl` (JSON body, below) |

Logs is the odd one: it takes a JSON body `{"type":"logs","defaultTTLDays":N,"ttlConditions":[...]}`
instead of a query string, and its `ttlConditions` are carried back unchanged. Reads mirror the same
paths with `GET`.

Verify after every store bring-up, restore and upgrade (loopback, or a verified SSH tunnel to it):

```sh
set -a; . /approved/private/store.env; set +a   # the private file, not examples/*/.env.example
python3 components/data/store-signoz/retention.py \
  --url "http://127.0.0.1:${LO_UI_PORT:-18081}" \
  --credentials-file /approved/private/signoz-login.json \
  --traces-days "$LO_RETENTION_TRACES_DAYS" --metrics-days "$LO_RETENTION_METRICS_DAYS" \
  --logs-days "$LO_RETENTION_LOGS_DAYS"
echo "retention exit $?"   # 0 as configured | 1 the store differs (--apply) | 2 cannot be read
```

Agreement with the API is not proof of expiry: the ClickHouse-side check (rows in a dated partition
actually disappearing) belongs to [conformance](conformance.md), not to this tool.

Disk: retention is the only bound on `clickhouse-data` growth, so the budget per signal is
`bytes_kept = ingested_bytes_per_day_per_signal x compression_factor x retention_days`, and the
volume must hold the sum over the three signals plus headroom for one partition merge. Both
`bytes_per_day_per_signal` and `compression_factor` are properties of the workload and the pinned
build: measure them (`du -s` of the volume after a known volume of ingestion over a known window) and
re-measure after any collector or SigNoz upgrade, because a schema change moves both. There is no
honest number to ship here, and none is claimed.

See [conformance](conformance.md), [backup](backup.md) and [upgrade](upgrade.md). Retention tooling:
[`retention.py`](retention.py) and the Retention section above.

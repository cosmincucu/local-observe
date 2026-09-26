# Conformance

Use complete `GRANT SELECT ON ...` statements. Verify configuration loading and
least-privilege access against the selected ClickHouse release.

## The security retention checks: read-only security retention fixture runner

`scripts/security_retention_conformance.py` checks one fixed case on a separately
provisioned disposable ClickHouse server. It does not start Docker, provision
users, create/alter/drop tables, insert rows or change production grants. Its
offline tests exercise the real reader and parser with a test client; they are
not evidence that ClickHouse 25.12.5 has passed conformance.

The operator must first verify the approved rootless daemon, exact disposable
container and storage paths, and the image from `../image-lock.json`:
`clickhouse/clickhouse-server@sha256:10f54f04de6c61b756c4eaf9f1d17464a4ac3e1f94b5b410e0dec92a24dbeda8`
(`linux/amd64`, release tag `25.12.5`). Use new names and storage; refuse a
collision rather than overwrite existing fixture state. Snapshot and verify any
pre-existing state before changing it. The marker below checks explicit setup;
it does not independently or cryptographically prove server isolation or the
running image digest. Record those observations separately.

Run only through a loopback HTTP endpoint on port 1024..65535. The runner refuses
remote hosts, URL credentials, paths, query strings and redirects. Use a unique
fixture UUID and a separate reader named `lo-retention-conformance` with
`readonly=1`, `allow_ddl=0` and the shipped analysis profile's seven read bounds
and changeable settings. Grant that fixture reader SELECT on
`security_events.*`, `system.tables` and `lo_retention_conformance.identity`.
Keep shipped `lo-read` unchanged as the negative identity. These fixture grants
do not apply or validate the proposed write-capable `lo-security` user.

Keep the two passwords in separate mounted regular files, mode 0600 on POSIX.
Do not put their values in argv, environment variables, URLs or evidence. No
`--password` fallback is needed: this runner reads the protected files with the
product credential reader and sends the real bounded client's HTTP headers.
Container administration must likewise use protected client configuration or
stdin, with private stderr suppressed. Windows operators must independently
restrict file ACLs; POSIX mode checking does not establish Windows ACL privacy.

Prepare this one-row marker table as the fixture administrator:

```sql
CREATE DATABASE lo_retention_conformance;
CREATE TABLE lo_retention_conformance.identity
    (fixture_id String, case_name String, image_digest String) ENGINE = Memory;
```

Insert exactly one row with the fixture UUID, selected case name, and
`sha256:10f54f04de6c61b756c4eaf9f1d17464a4ac3e1f94b5b410e0dec92a24dbeda8`.
Between cases, replace only this fixture marker row after successful table
setup. The reader asks for one row without filtering away competing markers;
extra rows fail its aggregate bound. Keep the server exclusively owned by this
rehearsal for the complete case matrix.

The subject name is always `security_events.events`, because that is what the
real corrected reader queries. Isolate the entire server instead of rewriting
the reader's SQL. Use `local_observe.security.schema.ddl_statements()` for the
database and full empty table. The administrator may drop/recreate only that
empty fixture table between these closed cases:

| Case | Administrator's fixture setup | Reader expectation |
|---|---|---|
| `match` | Exact shipped schema, 1825-day critical / 90-day routine TTL | `match`, live and declared days equal, expired rows 0 |
| `drift` | Render the same schema with `RetentionPolicy(routine_days=91)` | `drift`, live 1825/91, expired rows 0 |
| `no-ttl` | Omit only `build_ttl_clause()` from the shipped table DDL | `no-ttl`, existing table, expired rows 0 |
| `absent` | Database exists, subject table absent | `unreadable`, metadata count 0, expired rows unreadable (-1) |
| `extra-delete` | Append `, toDateTime(ts) + INTERVAL 1 DAY DELETE` to the shipped two-rule table TTL before `SETTINGS` | Server accepts and returns the extra deletion rule; parser reports `unreadable` |
| `unsupported-ttl` | Replace the routine rule's `INTERVAL 90 DAY` with `INTERVAL 1 MONTH` | Server accepts a month-based rule; parser reports `unreadable` |
| `permission` | Restore the matching empty table; marker reader validates it, then unchanged `lo-read` reads it | Negative identity reports `unreadable`; expired rows unreadable (-1) |
| `bad-credential` | Matching empty table; positive reader validates it first | Generated different password cannot authenticate successfully; subject reads stay `unreadable` |

If ClickHouse rejects any fixture DDL, record setup failure. Do not substitute
a simulated response or label the case passed. Negative TTL setup is inspected
through the positive reader before the subject verdict, so a permission error
cannot masquerade as the extra-rule test. Nonempty tables, a changed marker,
changed DDL or an unexpected status fail the case. All emitted subject SQL is
fixed SELECT text; the writer object refuses every call.

Write a strict JSON contract with exactly these fields (paths here are examples
of protected mounted files, not password values):

```json
{
  "schema_version": 1,
  "fixture_id": "909e5c73-0d69-4bfb-a30e-8b031f440ca0",
  "url": "http://127.0.0.1:18991",
  "reader_password_file": "/run/secrets/retention-fixture-reader",
  "denied_password_file": "/run/secrets/retention-fixture-denied"
}
```

Invoke one case after its setup, with a new evidence filename each time:

```text
python -B scripts/security_retention_conformance.py --contract /approved/private/fixture.json --case match --output /approved/evidence/retention-match.json
```

Duplicate/unknown contract fields and oversized contracts are refused. The
existing bounded client sends `readonly=1`, execution time 5 seconds, scanned
rows 1,000,000, scanned bytes 64 MiB, memory 128 MiB and throwing overflow modes.
Each response permits one aggregate row and at most 64 KiB, with a 10-second
HTTP deadline. At most nine reads are made per case; apply an independent
180-second outer deadline and preserve failures without automatic retries.
Contract reads are capped at 8 KiB, credentials at the product's 4 KiB bound,
and evidence at 16 KiB. No event data is inserted by this harness.

Exit 0 means this case matched its expected observation, including deliberately
unreadable negative cases; it does not mean the whole matrix passed. Exit 1
records a fixed safe failure category. Receipts contain observed server version,
reader name, status, declared/live day numbers, source hashes and the returned
DDL's length/hash. Raw DDL, server bodies, credential values and arbitrary
exception details are not published. Save the actual fixture creation statement
separately through the positive bounded client for operator review; inspect it
before adding it to shared evidence. The script's image digest is a marker
declaration, not runtime image inspection.

The `permission` and `bad-credential` cases demonstrate unknown handling, not
the exact server authorization cause: the bounded client deliberately hides
HTTP bodies and a transient transport failure can also produce unreadable.
Separately retain a safe authorization response classification and actual grants
from the fixture administrator. Perform fixed INSERT/CREATE/ALTER refusal checks
as the intended reader against only the disposable fixtures, then independently
confirm row counts and DDL are unchanged. Those mutation-attempt probes are not
part of this read-only runner. Oversized live response proof, if required, also
remains a separate explicitly bounded fixture; offline size checks are not that
proof. Final evidence must include storage/row/response-byte bounds and verified
cleanup of the exact owned fixture resources. No production TTL or security data
may be changed to make these checks pass. The security retention checks stays open until the complete
runtime evidence and cleanup are recorded.

`check_foundation.py` proves this delta has a legal shape and nothing more: it never starts a
container, and a read-only user is a privilege claim, not a syntax claim. The claims below are only
made once someone has run them against the pinned store image and recorded the output as evidence.
None of them had been run when full example gaps was drafted: there is no Docker host in the drafting environment.

Run these with the store's private environment file and the project name the example uses. They go
through the **HTTP interface on `clickhouse:8123`**, which is the interface the Sigma runner uses
(`LO_CLICKHOUSE_URL=http://clickhouse:8123`), so the answer is about this deployment and not about a
client that behaves differently. `8123` is not published on the host, so the command has to run
inside the project network; the `sigma` container already holds the credential as a mounted file and
has Python in it.

```sh
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  exec -T sigma python - <<'PY'
import urllib.error, urllib.request
URL = "http://clickhouse:8123/"
KEY = open("/run/secrets/clickhouse-password", "rb").read().strip().decode()  # the runner's credential
USER = "lo-query"                                                 # the user lo-query.xml creates

def query(sql):
    request = urllib.request.Request(URL, data=sql.encode(), method="POST",
                                     headers={"X-ClickHouse-User": USER, "X-ClickHouse-Key": KEY})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=10) as response:
            return response.status, response.read()[:200]
    except urllib.error.HTTPError as error:
        return error.code, error.read()[:200]

for label, sql in [
    ("read-allowed", "SELECT count() FROM signoz_logs.distributed_logs_v2"),
    ("write-refused", "OPTIMIZE TABLE signoz_logs.distributed_logs_v2"),
    ("ddl-refused", "CREATE TABLE signoz_logs.lo_probe (x UInt8) ENGINE = Memory"),
    ("outside-grants", "SELECT count() FROM system.query_log"),
    ("setting-change-refused", "SELECT 1 SETTINGS max_memory_usage = 1099511627776"),
]:
    print(label, query(sql))
PY
```

| Check | Proves | Pass condition |
| :-- | :-- | :-- |
| `read-allowed` | the user exists, authenticates over HTTP, and can read the table the compiled artifacts query | HTTP 200 with a count |
| `write-refused` | `readonly = 1` (`OPTIMIZE` is in ClickHouse's own list of write queries, and unlike an `INSERT` it cannot leave a row behind if this check ever fails open) | 4xx whose body names `readonly` |
| `ddl-refused` | `allow_ddl = 0`, which `readonly` alone would not give | 4xx that names DDL or `allow_ddl` |
| `outside-grants` | the grants, not just the read-only flag | 4xx naming privileges. Some `system.*` tables are *filtered* to nothing rather than refused, so record which you got: the check passes only if nothing outside `signoz_traces`/`signoz_metrics`/`signoz_logs` can be read. |
| `setting-change-refused` | the profile, not the client: a caller cannot raise its own memory bound | 4xx naming the setting |

Two outcomes this file **cannot** predict, because they were never observed and ClickHouse's
documentation does not settle them; record the actual response rather than assuming a pass:

* Whether the server accepts the runner posting `readonly=1` back to itself. The runner sends that
  with every query (`local_observe/platform/sigma_runner.py`, `ClickHouse.query`), and the
  permissions page says a `readonly = 1` user "can't change `readonly` … in the current session".
  If refusing is the answer, the fix belongs in the runner (drop the redundant setting), not in this
  profile (loosening it would drop the guarantee this directory exists for).
* Whether query **parameters** (`param_start_ns`, `param_end_ns`, `param_resource_id`,
  `param_dataset` in the compiled SQL) count as settings changes under `readonly = 1`. The
  `constraints` block in `lo-query.xml` makes the seven named bounds changeable; the `param_*` names
  are not in it, because they differ per artifact. If the parameters are refused, the honest options
  are `readonly = 2` plus explicit `readonly` constraints on the bounds, or lifting the parameters
  out of the compiled SQL. Both change a guarantee and require an explicit deployment decision.

Then confirm the compose merge actually delivered the file, on the rendered model:

```sh
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  -f examples/full/compose.yaml config | grep -c "users.d/lo-query.xml"    # expect 1, not 0
```

and that the store loaded it, from inside the server (a fragment ClickHouse could not parse is
reported in its own log, not in `docker compose ps`):

```sh
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  exec -T clickhouse clickhouse-client --query "SELECT name, readonly, allow_ddl FROM system.users"
```

`system.users` must list `lo-query`. If it does not, read the clickhouse container's log before
touching the XML: the substitution file, the `include_from` path and the mount are the three places
this can fail.

---

# `lo-read` — the analysis user (query adapter). **Nothing below has been run.**

`lo-read.xml` is not mounted by any example yet (`lo-read.compose.yaml` is in no `include` entry), so
on any host brought up from this tree these commands answer `UNKNOWN_USER`. That is the expected state
and it is **not** a pass and not a store fault; it is the line between "shipped" and "validated". The
merge that changes it is three lines and is written up in `CONTRACT.md` ("The second user"), together
with the two-step order of operations that keeps `lo-query` from narrowing before `lo-read` exists.

They run through `clickhouse-client` inside the store container rather than through the Sigma
container's Python, for one reason: the reader container does not hold the analysis credential yet —
that mount belongs to `components/control/sigma/compose.yaml`, which is another item's file.
`8123`/`9000` are not published on the host, so the alternative would be to copy the secret out of the
operator's private directory onto a host that is not running the stack.

```sh
# The three refusals, plus the one positive read. Read the password on the host, hand it to the
# container as an environment value, and never write it to a file or a shell history line.
KEY="$(cat "$LO_CLICKHOUSE_READ_PASSWORD_FILE")"
run() {   # $1 = label, $2 = query; every line records status AND the first line of the answer
  docker compose --env-file /approved/private/full.env --project-name local-observe-full \
    exec -T -e CLICKHOUSE_USER=lo-read -e "CLICKHOUSE_PASSWORD=$KEY" clickhouse \
    clickhouse-client --query "$2" 2>&1 | head -2
  echo "  ^ $1"
}
run read-allowed           "SELECT count() FROM signoz_logs.distributed_logs_v2"
run insert-refused         "INSERT INTO signoz_logs.distributed_logs_v2 SELECT * FROM numbers(1)"
run ddl-refused            "CREATE TABLE signoz_logs.lo_probe (x UInt8) ENGINE = Memory"
run row-cap-refused        "SELECT number FROM numbers(5000)"
run row-cap-at-the-number  "SELECT count() FROM (SELECT number FROM numbers(2000))"
run setting-outside-profile "SELECT 1 SETTINGS max_threads = 64"
```

| Check | Proves | Pass condition |
| :-- | :-- | :-- |
| `read-allowed` | the user exists, authenticates, and its grants cover the table the facade reads | a count |
| `insert-refused` | `readonly = 1` on the user that is allowed to read **thousands of rows**, which is the privilege worth proving | a 4xx naming `readonly` |
| `ddl-refused` | `allow_ddl = 0`, which `readonly` alone would not give (`CREATE` is DDL, not a write) | a 4xx naming DDL or `allow_ddl` |
| `row-cap-refused` | the profile's `max_result_rows`, and `result_overflow_mode = throw` — a page wider than the number is an error, never a short answer read as complete | a 4xx naming `max_result_rows` / "too many rows" |
| `row-cap-at-the-number` | the cap is the number written in the file (2 000 = `store.client.MAX_ROWS`) and not something inherited from the store default | exactly `2000`, not a refusal |
| `setting-outside-profile` | the `constraints` block is a boundary and not decoration: only the seven named bounds may be stated by a client | a 4xx naming the setting |

`row-cap-refused` is the one command that must be read carefully rather than run: it passes when the
**profile default** refuses 5 000 rows, and that default is `changeable_in_readonly`, so a client that
asks for 2 001 rows is served them (that is the facade's own `bound + 1`, and it is why the marking is
there). Record the refusal as proof of the number in the file, never as proof that no client can read a
wider page. `CONTRACT.md` states the same limit in its own words; a conformance run that quietly
re-reads it as a hard maximum is how this directory would end up claiming something false.

Then confirm the fragment reached the server, exactly as above for `lo-query`, and that both users are
defined — run as the store's own passwordless `default` user, because `lo-read` holds no grant on
`system.*`:

```sh
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  -f examples/full/compose.yaml config | grep -c "users.d/lo-read.xml"      # expect 1, not 0

docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  exec -T clickhouse clickhouse-client \
  --query "SELECT name, auth_type, profile FROM system.users WHERE name LIKE 'lo-%' ORDER BY name"
```

`system.users` must list `lo-query` **and** `lo-read`, each with a non-empty password method and its
own profile. If `lo-read` is missing, check the three places the sibling section names — the
substitution file, the `include_from` path, the mount — and note that `lo-read` reads
`/run/secrets/clickhouse-read-credentials`, not `lo-query`'s file: mounting the wrong one there is the
fail-open path (`CONTRACT.md`, "The second user"), because an unresolved `incl` is logged and left
empty rather than refused.

Two outcomes this file cannot predict, for the same reason the section above cannot: whether the pinned
build honours `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` as environment values (if it does not, use
`--user`/`--password` and say in the evidence that the value was visible in that container's process
list for the length of the query), and whether `clickhouse-client` inside the store container can reach
`127.0.0.1:9000` on the pinned image's default configuration. Record what you get.

## The owned `security_events` writer — an open gate, and a negative check that can run today (security store)

`local_observe/security/` writes an owned fourth database. No user defined in this directory can write
it, and the grant that would is a proposal (`CONTRACT.md`, "A writer for the owned store"), so nothing
below has been run and no host has the user. What *can* be run today is the negative half — the proof
that the runner's credential really cannot reach the owned store, which is the claim the proposal is
measured against:

| Check | Command (as `lo-query`, the runner's credential) | Pass condition |
| :-- | :-- | :-- |
| `owned-store-read-refused` | `SELECT count() FROM security_events.events` | 4xx naming privileges (not a 200 with zero, and not a "table does not exist" that hides which of the two it is) |
| `owned-store-write-refused` | `INSERT INTO security_events.events FORMAT JSONEachRow {}` | 4xx naming `readonly` or privileges |
| `ttl-read-refused` | `SELECT count() AS table_count, any(create_table_query) AS create_table_query FROM system.tables WHERE database='security_events' AND name='events' FORMAT JSON` | 4xx naming privileges, or 200 with `table_count = 0` — ClickHouse may hide the row; record which. The product reports `unreadable` with an absent-table detail for a zero count. An unknown-column error is a failed check, not proof of denied access. |
| `ddl-refused` | `CREATE DATABASE security_events` | 4xx naming DDL or `allow_ddl` — this is why the schema is applied by an administrator |

Then, if and only if the reviewer approves a writer user, the positive half, all five as the new user,
each from a credential that lives in its own mounted file:

| Check | Pass condition |
| :-- | :-- |
| `create-database-refused` | 4xx: `allow_ddl = 0` must survive the addition of write rights, so provisioning stays an operator act |
| `insert-allowed` | 200, and `SELECT uniqExact(source, event_id)` rises by exactly one |
| `same-identity-inserted-twice-answers-one` | after two writes of one `(source, event_id)` pair: `uniqExact` is 1; record `count()` too — a `ReplacingMergeTree` may not have merged, which is why the product never asks it for a count |
| `ttl-read-allowed` | The same aggregate query above returns 200 with `table_count = 1` and `create_table_query`. Save that DDL in the evidence and run `verify-ttl`: its bounded parser extracts only the table TTL and requires both guarded timestamp-plus-day deletions. Existing tables without TTL report `no-ttl`; malformed metadata reports `unreadable`. Pinned-server acceptance is still unverified. |
| `signoz-databases-unreachable` | 4xx on `SELECT count() FROM signoz_logs.distributed_logs_v2`: write rights on the owned store must not widen read rights onto telemetry |

### Canonical TTL metadata on ClickHouse 25.12

The isolated 25.12.5.44 server's `SHOW CREATE TABLE` writes the default deletion
TTL as `toDateTime(ts) + toIntervalDay(1825) WHERE retention_tier = 'critical'`,
omitting `DELETE`. The reader accepts that spelling and the explicit `DELETE WHERE`
form, while requiring exactly the two known tier guards and whole-day timestamp
arithmetic. Unknown actions, duplicate/missing tiers and extra unconditional expiry
clauses remain unreadable. The extra-delete fixture accepts the server's corresponding
unconditional spelling when checking that its deliberately invalid third clause exists.

`test_security_ttl_metadata` records the actual canonical TTL shape; conformance fixture
tests exercise all cases with normalized intervals and omitted DELETE. This parser repair
addresses the observed `unreadable` result for correctly installed TTL, not data retention
execution or successful runtime acceptance of every case. Fresh pinned-server results
must still be recorded separately; offline acceptance does not replace them.

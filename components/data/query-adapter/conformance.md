# Conformance

Component `query-adapter`. **Result of everything in this file that touches a store: `not-run`.** No
container was started and no host was read while this directory was written, so no line below may be
read as a pass — `docs/CONTRACTS.md` §6 requires `pass`/`fail`/`not-run` per check and forbids turning
`not-run` into a pass because a dependency was missing. What *has* been run is the static tier, and it
is separated below for that reason.

## Deterministic checks

```sh
python -B scripts/check_foundation.py
#   Static foundation checks passed; runtime conformance not run.
python -B -m unittest tests.test_query_adapter tests.test_foundation_checks
python -B -m unittest discover -s tests          # full suite, this branch's base included
```

What those two prove, and no more:

* `lo-read.xml` parses, and `check_foundation`'s `components/**/*.xml` walk sees it (the gate's XML
  rule reaches it even though no `include` does).
* `tests/test_foundation_checks.py::...test_the_unwired_analysis_user_delta_is_gated_directly_...`
  merges `lo-read.compose.yaml` onto the store manifest the way an `include` entry would and asserts
  the merged model faults **nowhere** (the bind's source exists, is `:ro`, the secret is declared and
  mounted), and that the fragment read alone still reports the one line that makes it non-standalone.
* `tests/test_query_adapter.py::AnalysisProfile` asserts `lo-read` and `lo-query` differ in exactly one
  setting (`max_result_rows`), share the same three grants and the same seven constraint names, keep
  `readonly = 1` / `allow_ddl = 0`, and take their password from a substitution file that is **not**
  `lo-query`'s.
* `tests/test_query_adapter.py` (envelope shape, window rules, failure ≠ empty, truncation, arbitrary
  SQL, endpoint refusals, credential refusals, the evidence link) runs against
  `local_observe/store/backends/memory.py`, the same query kinds with the same rules and no transport.
  It is a contract test, not a store test: no ClickHouse answer was ever parsed.

## Static tier — what no static check in this repository can prove

That the pinned ClickHouse accepts a `users.d` fragment defining a second user; that the profile's
numbers are the ones in effect; that `FORMAT JSON` renders the columns `QUERY_SQL` selects; that a
full page truncates rather than errors. Each is a recipe below, and each was `not-run` here.

## Preconditions for every recipe

Bring up `examples/full` by [`examples/full/README.md`](../../../examples/full/README.md) (steps 1–6
cover the store, the credentials, the `lo-query` delta and the Sigma artifact), then wire `lo-read`
per [`clickhouse-users.d/CONTRACT.md`](../store-signoz/clickhouse-users.d/CONTRACT.md) ("The second
user"): the `lo-read.compose.yaml` include, its `.env.example` line, the reader's
`LO_CLICKHOUSE_READ_PASSWORD_FILE` mount. Stage one declared resource that is actually producing
metrics, logs and a span, and note its `resource_id`: every command below is scoped to it.

Read `docs/CONTRACTS.md` §6 before starting: the record this file asks for names component and
revision, the image digests from `components/data/store-signoz/image-lock.json`, the config identities
(`lo-read.xml`, the compiled artifact's `sql_sha256`, the mapping identity), the commands, start and
end times, and a verdict per line with redacted evidence.

## Recipe A — the profile is what the file says (delegated)

Run [`clickhouse-users.d/conformance.md`](../store-signoz/clickhouse-users.d/conformance.md), both
halves: the `lo-query` block that has never been run either, and the `lo-read` block (INSERT refused,
DDL refused, `row-cap-refused`, `row-cap-at-the-number`, a setting outside the seven refused, and the
two `system.users` checks). Record each line separately; a run that covers `lo-query` and not
`lo-read` leaves this component's own credential unproven, and vice versa proves the wrong user.

**Verdict: not-run.** Run against an isolated installation.

## Recipe B — the three reads answer in the envelope §2 promises

From a container that holds the read credential and Python (the `sigma` service once its credential is
mounted; it already has the platform code and the image ships it):

```sh
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  exec -T sigma python - <<'PY'
import json, datetime as dt
from local_observe.platform import query

reader = query.open_reader()                       # None is a refusal, and it logs why
end = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
window = {'start': (end - dt.timedelta(minutes=15)).isoformat(), 'end': end.isoformat()}
RESOURCE = '…the declared resource_id staged above…'

for label, call in [
    ('metrics', lambda: query.metrics(reader, 'conformance', 'metric-threshold', window=window,
                                       parameters={'resource_id': RESOURCE, 'rule_id': 'lo.conformance'},
                                       selectors={'metric_name': 'lo_process_running'})),
    ('logs',    lambda: query.logs(reader, 'conformance', 'log-records', window=window,
                                   parameters={'resource_id': RESOURCE})),
    ('traces',  lambda: query.traces(reader, 'conformance', 'trace-spans', window=window,
                                     parameters={'rule_id': 'lo.conformance'},
                                     selectors={'service': 'lo-front-door'})),
]:
    result = call()                                # never raises: that is the assertion
    print(label, json.dumps({k: v for k, v in result.items() if k != 'rows'}),
          'rows=', len(result['rows']))
PY
```

| Check | Pass condition | Proves |
| :-- | :-- | :-- |
| `metrics` / `logs` / `traces` | `rows=0` or more, `error: null`, and the printed keys exactly `source, query_type, parameters, window, row_limit, truncated` (rows counted, not dumped: a log body is telemetry and telemetry does not belong in an evidence file) | the named read runs against the real tables, the eight-key envelope holds, and no exception reached the loop |
| `row_limit` values | `2000`, `200`, `100` in that order | the row caps §2 demands are stated on the answer, not only in code |
| window shape | every printed `window` is `{'start','end'}` in UTC with microseconds | one time format across the platform (§4) |
| empty window | repeat with `window` set to one minute in the future: `rows=0`, `error` **set**, prefixed `unavailable:` | a series the store has never seen is never an empty success |
| truncation | against a resource with more than 200 log lines in the window: `truncated: true` at exactly 200 rows, `error: null` | the bound is honoured and a cut page is labelled |
| overflow | a kind whose full page exceeds 64 MiB of response, or a store that refuses the request: `error` set, `rows=0` | overflow is an error, not a short answer |
| arbitrary SQL | replace `'log-records'` with `'SELECT body FROM signoz_logs.distributed_logs_v2'`: `error` names SQL, `row_limit: 0`, and **ClickHouse's own query log shows no new query** | the closed table is the whole surface, server-side and not just in the docstring |
| credential absent | re-run with `LO_CLICKHOUSE_READ_PASSWORD_FILE` unset: three envelopes with `error` set, **one WARNING naming the variable**, exit code 0 | the refusal path is a coverage shape, not a traceback |

**Verdict: not-run.**

## Recipe C — `docs/COMPONENTS.md` §5 "Failure to recovery", end to end through this adapter

The scenario in the table's own words: *"Inject one service failure; incident names declared resource
and queryable evidence; recovery updates it."* The adapter's part is the middle clause — the evidence
must be **queryable** — and the part that has never been exercised anywhere is the aged-out link. The
steps are one continuous run; each records a verdict.

1. **Baseline.** On the platform host, confirm the declared resource is producing: Recipe B's `logs`
   call returns `rows > 0`, `error: null`. Record the window.
2. **Inject.** `docker compose ... stop agent-linux` — the source that produces for that resource.
   Nothing else is touched; the store keeps serving, which is the point.
3. **The failure becomes a finding.** Within the rule's window the Sigma/coverage producer emits its
   `coverage` event and intake opens or updates an incident. Record the incident id:

   ```sh
   # A reader-role credential (`LO_READER_TOKEN_FILE` on the platform service; see
   # components/control/platform/CONTRACT.md for which role may read which table).
   TOKEN=…; PLATFORM=http://127.0.0.1:18096     # LO_PLATFORM_PORT, published loopback-only
   curl -s -H "Authorization: Bearer $TOKEN" "$PLATFORM/v1/records/incidents?limit=5"
   curl -s -H "Authorization: Bearer $TOKEN" "$PLATFORM/v1/records/events?limit=5"
   ```

   Verdict condition: an incident exists, and its newest event names the declared `resource_id`.
4. **The evidence it names is queryable.** Take the event's evidence reference (from the `events` row)
   and reauthorise it in-process — the same call a portal or an MCP tool makes:

   ```python
   from local_observe.platform import query
   # `store` is an opened local_observe.platform.state.Store on the platform host; `reference` and
   # `sample_id` come from the event row in step 4's first half.
   verdict = query.reauthorise(store, reference, sample_id=sample_id)   # HTTP twin: GET /v1/evidence?source=&sample_id=
   ```

   Verdict condition: `status` is one of `available`/`expired`/`unavailable`, and if `available` the
   sample's `observed_at` is inside the incident's window. `query.refusal(...)`-shaped results count
   as a **pass** here if and only if the incident displays them as refused: the scenario fails on
   *silence*, not on a refusal that is shown.
5. **Recovery.** `docker compose ... start agent-linux`; the next evaluation resolves the condition and
   the same incident is updated rather than a second one opened (dedup: `events UNIQUE
   (source, source_event_id)` plus the condition watermark). Verdict condition: the incident's status
   changes and no sibling incident appears for that rule and resource.
6. **The expired branch, which is the half nobody has run.** Two ways, and the second is the honest
   one:
   * *Fast:* on a scratch copy of the platform state file, `UPDATE evidence SET expires_at = <past>` —
     it proves the read path's decision, not the producer's, and says so in the record.
   * *Real:* `Store.put_evidence` stamps 15 days; leave one conformance sample for 16 days, or set the
     store's retention (`components/data/store-signoz/retention.py`) so the rows age out first and the
     reference outlives them.
     Verdict condition: `reauthorise` answers `expired` with **no sample**, the incident still names
     the reference it was opened with, and the operator's view says *expired* rather than showing a
     fresh reading under the old reference's identity. Check ClickHouse's `system.query_log` for the
     interval: **a query run while answering `expired` is a fail of this step**, because
     back-filling a dead link is exactly what the rule forbids.
7. **Restart.** Restart the reader's container and re-run step 4. The verdict must be identical: no
   state lives in this component (see [`backup.md`](backup.md)), so a restart must change nothing.

**Verdict: not-run, all seven steps.** Step 6 in particular has never been executed anywhere in this
repository: `tests/test_query_adapter.py::EvidenceLink` exercises the expired branch against a real
`state.Store` and an in-memory store, which proves the rule in the code and proves nothing about a host.

## Record template (copy, fill, attach; §6's fields, none omitted)

# Store

The one read path to the telemetry store. Every platform reader that needs data — the Sigma runner,
the anomaly producer, and later RCA bundles, forecasts, error budgets and the assistant's read tools —
asks this package, and only this package. The contract it implements is
[`components/data/store-signoz/CONTRACT.md`](../../components/data/store-signoz/CONTRACT.md)
("Platform read path"); the facade keeps product queries independent of backend storage details.

- `client.py`: the contract, no I/O. The closed table of query kinds (`QUERY_KINDS`), the seven
  evidence parameter names intake admits, `parse_ts`'s naive-==-UTC rule, and the three objects a read
  returns: a `ReadReceipt` (query kind, parameters, window, expiry, row count, truncation), a
  `ReadOutcome` (`available` / `unavailable` / `expired`, plus rows only when the store answered) and
  the `StoreClient` ABC — `read_metrics`, `read_logs`, `read_traces`, `describe`.
- `backends/clickhouse.py`: `ClickHouse` (the bounded read-only POST the Sigma runner has always
  used — moved here from `platform/sigma_runner.py` by store facade, which re-exports the name) and
  `ClickHouseStore`, which runs the kind table on it. The only SQL and the only network seam in the
  package. `store_from_environment` builds it from the runner's own three variables.
- `backends/memory.py`: the same query kinds answered from seeded rows, for tests and the offline
  demo. Not a write path — telemetry arrives through the OTLP front door, never through Python.
- `retention.py`: `declared(path)` reads the operator's declared tiers, `diff(declared, live)` says
  where the store disagrees, and the live half comes from the retention tool's own session
  (`components/data/store-signoz/retention.py`, imported by file path; `LO_RETENTION_TOOL` points at it
  when the checkout layout differs). No second TTL reader exists in this repository.

## What each knob costs when you turn it down

- **A new query kind** — add it to `QUERY_KINDS` *and* `QUERY_SQL`, or the package refuses to import.
  It then needs its row bound: an unbounded kind is not available, and the row bound plus one is what
  lets a full page be reported as `truncated` rather than read as complete.
- **`expires_at` on a read** — defaults to the window end plus 15 days, the horizon
  `Store.put_evidence` itself stamps. Shortening it costs nothing but the length of proof; lengthening
  it past the retention the store reports is refused, because a reference outliving its rows is a dead
  link an incident would cite as proof.
- **`store_ttl_hours` on a read** — optional, and only meaningful when the caller has just read the
  store's retention (`retention.live`). Passing it makes the facade refuse a promise the store cannot
  keep. Omitting it means the facade trusts the caller's expiry: it checks the window, not the shelf.
- **The `needle` selector on `log-records`** — case-insensitive substring over the log body. Empty is
  "no narrowing", not "match nothing"; it is a selector, so it never reaches the evidence reference,
  which is why a reader re-runs it from the reviewed rule (`rule_id` + `artifact_sha256`), not from the
  reference alone.
- **`LO_INTERNAL_ALLOW_HTTP`** — lets the endpoint be plaintext `http://`. The examples set it to `1`
  because ClickHouse and the platform sit on the Compose project network, which is the trust boundary
  there (CONTRACT.md, "Read-only query user"); set it to `0` and the client refuses anything but HTTPS.
  Nothing else changes when you flip it, so on any network you cannot enumerate, the query credential
  and every row it reads are visible to whoever can.

## Provenance and standing limits

The **v0.1 facade's shape is kept** (injected ABC, one timestamp contract, the sample/record
dataclasses, the in-memory backend) and its **outputs are not**: it returned payloads, here a result is
a reference. Not ported: the SigNoz HTTP adapter, the OpenObserve backend (store boundaries — product validation
happens with one datastore) and `retention_check.py`'s TTL reader (`retention.py` already owns reading
and writing TTLs). A second backend is a configuration choice this seam permits later, not a refactor.

Tests: `tests/test_store_facade.py` (read rules, both backends, the evidence seam through real intake)
and `tests/test_store_retention.py` (declared-vs-live, including the divergence the estate actually
lived with: declared 90/30/90 days against a store applying 30/15/15). Nothing here has been executed
against a live ClickHouse: a store that answers in a shape the pinned build does not have is reported
unavailable, never guessed at.

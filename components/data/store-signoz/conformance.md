# Store conformance

Added 2026-09-07 and **not yet run**: the store receiver now demands a separate
`LO_STORE_TOKEN`, and a `memory_limiter` plus a container healthcheck were added. No
runtime evidence exists for any of the three; the round trips above predate them and
must be repeated before this component's status changes.

Added 2026-09-07 (retention) and **not yet run against the pinned SigNoz build**:
`retention.py` sets and reads retention through the HTTP API. Its endpoint paths and
response field names come from the remediation brief, not from a run on the pinned
digest, and the only evidence so far is unit-level plus a local stand-in server. The
first `--check` below is what confirms them; the 15/30/15 days recorded in the P1
evidence were observed without this tool.

Required staged checks:

- Resolved digest inputs, verified histogram checksum and valid Compose model.
- Initialization and migrations succeed on empty project volumes; deliberately
  wrong histogram hash and failed migration prevent dependent startup.
- Bounded metric, log and trace round trips with unique markers, plus UI query.
  `scripts/conformance_smoke.py` covers only the authenticated HTTP/store subset.
- No published ClickHouse, ZooKeeper or store-collector ports; UI requires login.
- Telemetry retention configured and observed. Run the read-back first, on the
  running store and with the same day counts the private environment declares:
  `python3 components/data/store-signoz/retention.py --url "http://127.0.0.1:${LO_UI_PORT:-18081}"
  --credentials-file <private file> --traces-days N --metrics-days N --logs-days N` must exit **0**
  after a `--apply` pass, and exit **1** when any of the three differs (that exit code is the check,
  not a crash: exit **2** means the setting could not be read at all, which is a failure of the
  check, not a pass). Then confirm the setting bites: insert dated rows and observe them expire in the
  actual main tables, as the forced-materialization run did. Agreement with the API alone is not
  expiry; neither is a `clickhouse-data` restore, because retention is SigNoz application state.
  Per-core CPU and host identity agree with the source. Assess memory caps under representative
  local load.
- Store restart and collector crash during traffic; measure acknowledged loss,
  retries and duplicate markers. Include a store outage longer than intake retry
  intervals and a queue-full case. Do not claim exactly-once delivery.
- Restore old data/UI state using backup.md, then execute upgrade.md with a
  selected old/new pair. Recreating an empty store is not either check.
- Repeat ingestion/query with all RCA, AI and other optional planes absent.

Record revision, effective non-secret configuration, digests, platform, commands,
redacted results, failures and recovery durations using docs/CONTRACTS.md.
Static tests and artifact presence alone cannot promote this component.

# Intake conformance

Added 2026-09-07 and **not yet run**: the exporter now presents a second credential,
`LO_STORE_TOKEN`, to the store receiver. Every round trip below predates that change
and must be repeated — a store that rejects the front door fails silently as missing
data, not as an intake failure.

- Reject missing/incorrect credentials on both protocols for every signal.
  A missing route or server error is not a successful authentication test.
- Accept valid credentials and query uniquely identified metric/log/trace data.
  The smoke tool covers HTTP only; gRPC remains a separate required check.
- Preserve source host/UUID attributes. Prove selected credential/prompt attribute
  deletion using synthetic canaries, checking storage, not only the collector.
- Document remaining body/resource-attribute coverage limits before real ingestion.
- Queue through a store outage, restart with nonempty state, recover and count
  missing/duplicate markers. Force queue capacity and disk-pressure conditions
  in a bounded disposable test. Intake must report rejection rather than silently
  claim acceptance when persistence fails.
- Verify no non-loopback published ports, token rotation, and remote TLS validation
  when a remote-producer overlay is introduced.
- Execute backup and upgrade recipes, including replay reconciliation.
- Repeat with all optional planes absent.

Save evidence per docs/CONTRACTS.md. Static checks verify configuration intent,
not collector-version compatibility or runtime security.

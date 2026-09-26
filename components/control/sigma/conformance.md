# Sigma conformance

Run the base test tier and `tests/compiler` in separate environments. The compiler
tier requires Python 3.13 and `compiler.lock`. Compiled artifacts must match their
source rules and mapping identity. Runtime conformance is **not-run** until verified
in the selected installation.

## Measurement status

Run `sigma_runner.measurement_report()` over the shipped artifacts as described in
[CONTRACT.md](CONTRACT.md). The sample pack contains two rules, both unmeasured.
A synthetic match fixture does not establish a false-positive rate for real traffic.
The optional overview signal reports shipped, measured and unmeasured counts; a
missing or unreadable artifact directory must report unknown rather than zero.

## Runtime acceptance

| Check | Required result | Status |
|---|---|---|
| Query-user permissions | The dedicated credential can read the required tables and cannot insert, alter or create objects. | **not-run** |
| Positive and negative fixtures | The compiled predicate produces the expected verdict for each fixture, including case and window boundaries. | **not-run** |
| Missing or unmapped data | Coverage fires; no absent sample resolves a security finding. | **not-run** |
| Intake authentication | A matching producer identity delivers events; missing and mismatched credentials are refused. | **not-run** |
| Restart and replay | A retained pending batch retries without duplicate logical events or premature cursor advance. | **not-run** |
| Backup and rollback | A verified copy restores the cursor and compiled artifact as described in the lifecycle documents. | **not-run** |

Use an isolated ClickHouse deployment. Deterministic fixtures verify the predicate
and bounds but do not establish server behavior, privileges or restart durability.

## Optional analytical copy

The analytical copy to `security_events` requires an explicitly provisioned writer
credential. The read-only query user must remain unable to insert. Test this using
the store's [permission conformance procedure](../../data/store-signoz/clickhouse-users.d/conformance.md).

A refused copy must leave operational event delivery running and fire the
`sigma.<uuid>.store-coverage` condition. Recovery requires both a successful write
and a matching TTL policy. Container health continues to measure cursor freshness;
the operational state store remains authoritative for incidents.

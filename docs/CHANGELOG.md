# Changelog

## Unreleased

- OpenTelemetry ingestion with SigNoz and ClickHouse.
- Versioned inventory, discovery proposals and topology queries. The resource, query, rule and
  deployment-configuration operations are served over HTTP as bounded reads and dry runs
  (`docs/api/resources.md`): declared and observed planes stay separate, a missing mount is stated instead
  of answered as empty, and nothing on those routes files an event, moves a cursor or writes a file.
- Incident detection, correlation, suppression, notifications and approval records.
- Durable acknowledgement and dismissal of alert occurrences over HTTP, with episode history,
  conditional writes and downstream projections (schema v12).
- Homepage navigation and a platform operations interface.
- Job-status, synthetic-check, security-event and identity-mail integrations.
- Optional model-assisted investigation and chat interfaces.
- Versioned deployment content, state compatibility checks and recovery tooling.

This is a development preview. See [product status](../STATUS.md) for readiness limits and
[release requirements](RELEASING.md) for the information each release must include.

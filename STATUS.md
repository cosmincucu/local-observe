# Product status

local-observe is a development preview. The source provides the capabilities below; an installation
must validate its selected components before relying on them. No production service level is claimed.

| Capability | Scope |
|---|---|
| Telemetry | Authenticated OpenTelemetry ingestion with SigNoz and ClickHouse |
| Inventory | Versioned declarations, observed resources and a rebuildable index |
| Incidents | Detection, correlation, suppression, notification state and approval records |
| Operations | Homepage navigation, platform interface and job-status adapters |
| Optional integrations | Model-assisted explanation, chat, additional sensors and external APIs |

Start with [installation](docs/INSTALLATION.md), the [full example](examples/full/README.md)
and the [component guide](docs/COMPONENTS.md). Each component documents its conformance,
backup and upgrade requirements.

Automated tests establish behavior under fixtures. The [evaluation harness](local_observe/evaluation/README.md)
uses a small generated corpus; its model-assisted arm is not scored. Those measurements do not
establish detection quality in a live installation.

Before promoting an installation, verify its full composition, credential boundaries, telemetry
freshness, actual notification delivery, restart behavior and restore procedure. Optional services
need their own acceptance evidence. Platform-dependent tests and unavailable extras must be
reported as skipped, not passed. See [testing](docs/testing-standards.md) and [release requirements](docs/RELEASING.md).

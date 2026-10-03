# Product status

local-observe is a development preview. The source provides the capabilities below; an installation
must validate its selected components before relying on them. No production service level is claimed.

| Capability | Scope |
|---|---|
| Telemetry | Authenticated OpenTelemetry ingestion with SigNoz and ClickHouse |
| Inventory | Versioned declarations, observed resources and a rebuildable index |
| Incidents | Detection, correlation, suppression, notification state and approval records |
| Operations | Homepage navigation, platform interface and job-status adapters |
| Observer | Scheduled, bounded investigations with retained redacted evidence and explicit incomplete coverage |
| Feedback | Optional authenticated browser review of quiet and finding cycles, versioned human corrections, eligible-case retrieval and provenance-preserving export |
| Guided setup | Reviewed plans and a separate trusted execution boundary |
| Optional integrations | Model-assisted explanation, chat, additional sensors and external APIs |

Start with [installation](docs/INSTALLATION.md), the [full example](examples/full/README.md)
and the [component guide](docs/COMPONENTS.md). Each component documents its conformance,
backup and upgrade requirements.

Automated tests establish behavior under fixtures. The [evaluation harness](local_observe/evaluation/README.md)
uses a small generated corpus by default. A configured observer can be compared with the same
threshold, seasonal and shaping baselines; fixture results do not establish live detection quality.
Ungraded cases stay unknown. The quality report cannot authorize notifications.
Private held-out input has its own corpus origin; that label does not certify its truth or anonymization.
An optional per-call deployment guard can reject a gateway response from a different configured model
deployment. Provider and weight version remain operator declarations, and missing identity blocks acceptance.

Live model quality, fit on a 16 GB VRAM device and human feedback burden across deployment
sizes require measured acceptance. No training run or fine-tuned model is shipped. Telegram is
an optional first channel behind the observer's replaceable delivery interface. The observer
starts in recording mode; urgent rule alerts keep their independent delivery path.
Use the [workload report](docs/units/feedback-measurement.md) to measure feedback coverage
and optional human-reported effort before choosing a review cadence.

Before promoting an installation, verify its full composition, credential boundaries, telemetry
freshness, actual notification delivery, restart behavior and restore procedure. Optional services
need their own acceptance evidence. Platform-dependent tests and unavailable extras must be
reported as skipped, not passed. See [testing](docs/testing-standards.md) and [release requirements](docs/RELEASING.md).

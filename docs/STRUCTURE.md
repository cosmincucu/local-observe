# Code structure

| Path | Responsibility |
|---|---|
| `local_observe/` | Product implementation and public command interfaces |
| `components/` | Component manifests, pins and lifecycle contracts |
| `examples/` | Synthetic reference configurations and deployments |
| `scripts/` | Portable checks, migration, conformance and recovery tools |
| `scripts/operator/` | Deployment pin and overlay checks |
| `tests/` | Base and optional-dependency tests |
| `tests/compiler/` | Hash-locked Sigma compiler tests |
| `docs/api/` | Capability census, the platform HTTP contract and its decisions |
| `docs/units/` | Detailed implementation contracts |

The main packages cover inventory, deployment, incident workflows, telemetry access, AI policy,
evaluation, security storage, service objectives, forecasting and external-event adapters.
Use [DEPENDENCIES.md](../DEPENDENCIES.md) to identify related changes and
[testing](testing-standards.md) to select the required checks.

Installation configuration, operational transcripts, credentials and private automation remain
outside the product tree. Generic upgrade orchestration lives in `scripts/upgrade_driver.py`;
its injected boundaries allow tests without a live deployment.

| Unit | Responsibility |
|---|---|
| [Observer](units/observer.md), `local_observe/observer/` | Scheduled investigations, protected evidence, independent feedback and delivery state |
| [Guided setup](units/guided-setup.md), `local_observe/deployment/guided.py` | Exact setup plans, human decisions and trusted apply |
| Evaluation, `local_observe/evaluation/` | Shared-evidence comparisons, unknown labels and independent quality measurements |
| [Refusal audit](units/refusal-audit.md) | Durable refusal records and bounded dispatch |
| API boundary, `local_observe/platform/api_contract.py` | Error envelope, request identity, idempotency, expected revision, bounded paging and actor context for platform routes; see [`docs/api/COVERAGE.md`](api/COVERAGE.md) |
| Planned maintenance, `local_observe/platform/maintenance.py` | Windows (a signed, bounded silence, stored as a control document) and the recurring schedules that materialize them; roles, bounds, DST policies, outcomes and historical reads in [`docs/api/maintenance.md`](api/maintenance.md) |
| Shared HTTP, `local_observe/http.py` | Explicit client trust configuration shared by integrations; no global TLS changes |

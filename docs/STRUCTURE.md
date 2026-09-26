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
| [Refusal audit](units/refusal-audit.md) | Durable refusal records and bounded dispatch |
| Shared HTTP, `local_observe/http.py` | Explicit client trust configuration shared by integrations; no global TLS changes |

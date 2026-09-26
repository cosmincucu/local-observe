# local-observe

Collect telemetry, investigate incidents and manage operational work in one self-hosted platform.

OpenTelemetry and SigNoz on ClickHouse provide metrics, logs and traces.
Inventory, detection, incident handling, job status and notifications build on
that foundation. Homepage links to the native service interfaces; the platform
interface shows operational state and requests awaiting approval. Model-assisted
explanation, chat and additional sensors are optional.

Automated tests cover the implemented workflows. A passing component test is not full installation acceptance:
[STATUS.md](STATUS.md) explains what has been proven and what remains open.

## Get started

Use one Linux/amd64 host with Docker Compose and Python 3.12. The reference
baseline is 16 GB RAM; selected integrations and model serving need additional
resources. Credentials and runtime data stay outside the source checkout.

1. Read [installation](docs/INSTALLATION.md) for prerequisites and the smaller
   telemetry-only setup.
2. Use the [full-stack example](examples/full/README.md) for inventory, incidents,
   job status and the main page together.
3. Follow [account setup](docs/OPERATOR-SETUP.md) to choose credentials for
   independent component accounts and handle native-registration exceptions.

The examples bind published ports to loopback. Use their documented access path
and verify your selected services before relying on them.

## Customise and upgrade

Keep deployment settings, dashboards and other custom content in your own
versioned repository. Pin a product release and review upgrades against that
content; do not maintain a fork of the product implementation. Runtime databases,
telemetry and secret values need separate protected backups.

See the [product philosophy](docs/PRODUCT-PHILOSOPHY.md),
[two-repository layout](docs/OPERATOR-MODEL.md) and
[customisation and upgrade contract](docs/DEPLOYMENT.md).

## Documentation

| Read | For |
|---|---|
| [Product status](STATUS.md) | Capabilities, evidence and remaining readiness checks |
| [Components](docs/COMPONENTS.md) | Required foundation, optional features and their boundaries |
| [Architecture](docs/ARCHITECTURE.md) | Component responsibilities and interfaces |
| [Code structure](docs/STRUCTURE.md) | Where behavior is implemented and tested |
| [Build](docs/BUILD.md) | Building the first-party images and reproducing dependency locks |
| [Testing](docs/testing-standards.md) | Test tiers and evidence requirements |
| [Deployment](docs/DEPLOYMENT.md) | Versioned custom content, state compatibility and upgrade checks |
| [Release contract](docs/RELEASING.md) | Release promises and the required `Operator actions` block |

This is a development preview. Review the component contracts and validate your selected
composition before using it for operational decisions.

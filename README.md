# local-observe

Watch your systems, investigate changes and review evidence-backed findings in one self-hosted platform.

OpenTelemetry and SigNoz on ClickHouse provide metrics, logs and traces.
Inventory, detection, incident handling, job status and notifications build on
that foundation. A bounded observer investigates configured sources on a schedule,
retains redacted evidence and learns from independently corrected cases through
retrieval. Guided setup prepares a plan for your approval before a trusted runner
applies it. External assistants can use the same bounded tools.

The telemetry foundation works with AI disabled. Homepage links to native service
interfaces; the platform interface shows operational state and requests awaiting
approval. Chat, additional sensors and model serving are optional.

Automated tests cover the implemented workflows. A passing component test is not full installation acceptance:
[STATUS.md](STATUS.md) explains what has been proven and what remains open.

## Get started

Use one Linux/amd64 host with Docker Compose and Python 3.12. The reference
baseline is 16 GB host RAM; selected integrations and model serving need additional
resources. The observer's 16 GB VRAM model target is a separate acceptance target,
not a measured hardware guarantee. Credentials, investigation records and runtime
data stay outside the source checkout.

1. Read [installation](docs/INSTALLATION.md) for prerequisites and the smaller
   telemetry-only setup.
2. Use the [full-stack example](examples/full/README.md) for inventory, incidents,
   job status and the main page together.
3. Follow [account setup](docs/OPERATOR-SETUP.md) to choose credentials for
   independent component accounts and handle native-registration exceptions.
4. Use [guided setup](docs/units/guided-setup.md) and the
   [observer walkthrough](docs/units/observer.md) for the first investigation.
   Start in recording mode and review evidence before enabling model notifications.

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
| [Observer](docs/units/observer.md) | Bounded investigations, retained evidence and feedback |
| [Guided setup](docs/units/guided-setup.md) | Reviewable setup and trusted execution |
| [Components](docs/COMPONENTS.md) | Required foundation, optional features and their boundaries |
| [Architecture](docs/ARCHITECTURE.md) | Component responsibilities and interfaces |
| [Code structure](docs/STRUCTURE.md) | Where behavior is implemented and tested |
| [Build](docs/BUILD.md) | Building the first-party images and reproducing dependency locks |
| [Testing](docs/testing-standards.md) | Test tiers and evidence requirements |
| [Deployment](docs/DEPLOYMENT.md) | Versioned custom content, state compatibility and upgrade checks |
| [Release contract](docs/RELEASING.md) | Release promises and the required `Operator actions` block |

This is a development preview. Review the component contracts and validate your selected
composition before using it for operational decisions.

# Design decisions

These choices define the product. Implementation and deployment requirements are documented in
[architecture](ARCHITECTURE.md), [component contracts](COMPONENTS.md) and [release requirements](RELEASING.md).

- The product and each installation's configuration have separate histories. A deployment pins
  a product revision and layers its own inventory, dashboards, rules and secret references.
- OpenTelemetry, SigNoz and ClickHouse provide the telemetry foundation. Operational state is
  distinct from telemetry, and the inventory index is rebuildable from versioned declarations.
- A resource receives a stable UUID at declaration. Hostnames and provider identifiers are aliases.
  Discovery proposes changes for review instead of silently editing declared inventory.
- Dagu runs file-based job definitions; Healthchecks observes existing jobs. Neither bypasses
  the platform's approval and audit boundaries. Job output can be collected as telemetry.
- Homepage is the reference navigation interface. The platform interface owns incident and
  approval workflows. Native service interfaces remain available through explicit links.
- Sigma rules compile to ClickHouse queries using pinned tooling. CrowdSec is an optional
  integration; any enforcement requires explicit policy and protected-address exclusions.
- AI, model serving, chat and remote providers are optional. Remote inference requires an explicit
  opt-in, bounded cost and controlled data disclosure. Explanations cannot authorize actions.
- Notification channels share the platform's approval model. A channel cannot create a second
  source of action authority. Unknown delivery outcomes remain visible.
- Installation data, private operational records and secret values do not belong in product source.
  Screenshots and examples use synthetic data. Source publication requires a separate review of
  content, Git metadata and history.
- Code uses Apache-2.0, documentation CC-BY-4.0 and examples CC0-1.0. Bundled third-party material
  retains its own notices and licenses; see [NOTICE](../NOTICE).

A component is validated only for the scope recorded by its contract, pinned inputs, conformance
checks, backup/restore procedure and upgrade procedure. A source test is not deployment evidence.

The example catalog records these selections using stable schema identifiers:

| ID | Selection | Boundary |
|---|---|---|
| D-101 | Portainer as an optional container console | A catalog entry does not install the console or grant platform action authority. |
| D-102 | Gatus for synthetic checks | The detector adapter owns event conversion and missing-source coverage. |
| D-103 | CrowdSec decision ingestion | Reads are separate from enforcement; writes require explicit approval and policy. |

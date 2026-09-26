# Architecture

local-observe combines telemetry, inventory and operational workflows through explicit component
interfaces. The telemetry foundation runs independently of optional reasoning, chat and sensors.

## Telemetry

Agents send metrics, logs and traces through an authenticated OpenTelemetry front door. The
collector redacts sensitive fields and forwards data to SigNoz and ClickHouse. Producers have
distinct credentials; query clients use bounded reads with their own access policy.

The Linux and Windows agent contracts describe permissions, resource identity and host telemetry.
Retention, queue recovery and backup requirements are part of the data component contracts.

## Inventory

Versioned declarations define resources with stable UUIDs, ownership, capabilities and dependency
edges. Provider observations remain separate from declarations. Discovery produces proposals for
review. The SQLite inventory index is a derived read model and can be rebuilt from its inputs.

Topology and query authorization use that model. An unavailable source is a coverage gap, not a
healthy resource. Installation-specific names, addresses and credentials belong outside product source.

## Incidents and operational state

Detectors produce bounded events. Intake validates source identity and data, then applies
deduplication, condition state, suppression and correlation. Durable SQLite state records incidents,
actions, delivery attempts, approvals and audit history. Schema changes require explicit migration
and compatible recovery; telemetry storage is not a substitute for operational-state backups.

Synthetic checks, Sigma queries, forecast models and anomaly detection are independent producers.
Optional CrowdSec and identity-mail integrations contribute events through the same boundaries.

## Actions and notifications

Proposing an action, approving it and executing it are distinct operations. Actor identity comes
from the authenticated credential, never an untrusted payload. Expired authority or evidence is
refused. Unknown execution and delivery outcomes remain visible for reconciliation.

Notifications use a shared registry and delivery state. Channel callbacks record approval intent;
the platform remains the decision authority. Reference examples default to recording or off.
Job adapters integrate Dagu and existing scheduled work without granting unrestricted host access.

## Interfaces and optional reasoning

Homepage provides navigation to native component interfaces. The platform UI exposes operational
status, incidents and requested actions. The optional MCP service offers authenticated, bounded
tools using the same policy boundaries.

Rule-based investigation assembles evidence and ranked causes. An optional model can explain
that result within a capability and cost budget; it cannot manufacture evidence or authorize
an action. Chat and model-serving candidates require separate configuration and validation.

## Packaging and deployment

Each component documents its contract, pinned inputs, conformance checks, backup and upgrade
procedure. [Examples](../examples/full/README.md) compose those components. Keep deployment
configuration in a separate repository that pins a product release. Store secret values and runtime
data outside both source histories. See [deployment](DEPLOYMENT.md), [components](COMPONENTS.md)
and [release requirements](RELEASING.md).

Code is licensed under Apache-2.0, documentation under CC-BY-4.0 and examples under CC0-1.0.
Third-party software retains its own licenses and notices; see [NOTICE](../NOTICE).

## 2. Infrastructure capabilities

These are capabilities to provide, not twelve machines or twelve mandatory
products. Existing infrastructure may fulfil them.

| Capability | Foundation requirement | Reference or optional integration |
|---|---|---|
| Container execution | Linux Docker Engine and Compose | One host can run the foundation; Portainer optional |
| Durable storage | Writable persistent volumes and sufficient disk capacity | Local volumes; no assumed ZFS dataset or NAS layout |
| Collection/network | One source can reach authenticated ingest | Existing LAN, DNS and router; no required router brand |
| Operator access | Authenticated UI access; TLS for traffic beyond local development | Existing proxy allowed; Caddy template optional; VPN for remote access |
| Secrets | Per-install credentials outside source control | Environment/files; Vaultwarden and OpenBao optional |
| Configuration source | Versioned product configuration and private overlay | A forge is optional at runtime |
| Backup target | Separate verified copy for a validated deployment | Directory/disk/host selected by overlay; same-volume copies are not DR |
| AI inference | None for foundation | llama.cpp reference; gateway and external API optional |
| Probes | None beyond the initial collection/verification path | Gatus for LAN synthetics; external vantage integration future |
| Home hub and power | None | Home Assistant telemetry/approvals, UPS and sensor integrations |
| Operator endpoints | A browser for the UI | Windows telemetry first-class in standard; phone portal remains usable |

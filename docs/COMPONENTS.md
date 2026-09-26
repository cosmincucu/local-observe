# Components

The repository provides reusable components and reference compositions. A shipped manifest is
not proof that a component has passed acceptance in your installation. Read each component's
contract and run its conformance checks before relying on it.

| Component | Purpose | Scope |
|---|---|---|
| [Front door](../components/data/front-door/CONTRACT.md) | Authenticate, redact and route telemetry | Foundation |
| [SigNoz store](../components/data/store-signoz/CONTRACT.md) | Metrics, logs, traces and query interface | Foundation |
| [Linux agent](../components/data/agent-linux/CONTRACT.md) | Host metrics and file logs | Selected hosts |
| [Windows agent](../components/data/agent-windows/CONTRACT.md) | Windows host telemetry | Selected hosts |
| [Inventory](../local_observe/inventory/README.md) | Declarations, discovery and resource relationships | Operational workflows |
| [Platform](../local_observe/platform/README.md) | Incidents, approvals, notifications and audit state | Operational workflows |
| [Homepage](../components/control/homepage/CONTRACT.md) | Navigation and status tiles | Optional |
| [Dagu](../components/control/dagu/CONTRACT.md) | File-based job definitions and execution adapter | Optional |
| [Job observation](../components/control/job-observe/CONTRACT.md) | Check-ins and missed-run visibility | Optional |
| [Synthetics](../components/control/synthetics/CONTRACT.md) | Gatus checks and event adapter | Optional |
| [Sigma](../components/control/sigma/CONTRACT.md) | Compiled detection queries | Optional |
| [Anomaly detection](../components/control/anomaly/CONTRACT.md) | Seasonal baseline events | Experimental |
| [CrowdSec](../components/control/crowdsec/CONTRACT.md) | Read-only decision ingestion | Optional; no enforcement service supplied |
| [MCP](../components/control/mcp/CONTRACT.md) | Authenticated platform tools | Optional; requires the MCP extra |
| [Investigation](../components/control/rca/CONTRACT.md) | Rule-based evidence bundles and optional explanation | No separate state-writing service |
| [AI](../components/control/ai/CONTRACT.md) | Model capability and provider integration | Experimental |
| [Chat](../components/control/chat/CONTRACT.md) | Candidate chat interface | Requires independent validation |

The [full example](../examples/full/README.md) documents its actual composition and opt-ins;
the [installation guide](INSTALLATION.md) also covers a smaller telemetry-only setup.
Home Assistant and other external systems are optional integrations, not startup dependencies.

For every selected component, verify authenticated access, input validation, telemetry or state
freshness, failure visibility, restart behavior, backup restoration and upgrades. Test notification
delivery only against an explicitly selected destination. Record the revision and environment for
each result. [Product status](../STATUS.md) describes the overall readiness boundary.

## 2. Component matrix

Validation vocabulary: selected = chosen but not implemented; experimental = implemented with
incomplete runtime acceptance; validated = all checks in the declared scope passed with evidence.
The catalog and component manifests use these values. "Built" below describes source availability.

| Component ID | Source status | Interfaces and limitations |
|---|---|---|
| agent-windows | built | `components/data/agent-windows/versions.json`, service installer, `collector-security.yaml` and the `otlp_http` exporter; native privileges require validation |
| synthetics | built | `components/control/synthetics/`; Gatus and its adapter. No synthetic coverage when disabled |

## 5. Acceptance scenarios

| Scenario | Required outcome |
|---|---|
| Failure to recovery | Inject one service failure; the incident names a declared resource and queryable evidence; recovery updates it. |
| Missed job | A missed deadline is visible, and a later successful run resolves the correct condition. |
| Approved action | A proposed action requires approval, executes once within its bounds and records an audit trail. |
| Operator surfaces | Homepage, MCP and the operator view agree on incident and approval status; disabled and stale states are visible; the phone layout remains usable. |
| Investigation | Evidence is bounded and attributable; missing sources remain visible; optional AI output cannot execute actions. |

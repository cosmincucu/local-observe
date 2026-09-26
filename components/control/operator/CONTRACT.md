# Operator surfaces (experimental)

Same-origin HTML/JS shell over the platform's existing authenticated API. The
operator factory replaces the plain API factory; it never opens a second owner
of the same operational database. Static assets are public; every data/command
request still requires the configured bearer identity. Tokens stay in memory,
not cookies, URLs or localStorage. Sign-out and reload require a new sign-in.

Views: incidents, approvals, executions, notifications, declared inventory,
events and audit. Search/status filters, bounded records, exact payload details,
evidence reads, human-only approve/reject, unknown-outcome reconciliation and
exhausted-delivery retry. Commands require explicit confirmation. Role enforcement
is server-side; hiding buttons is not the security boundary. No UI-triggered
runner dispatch or arbitrary SQL/shell interface exists.

Lucide 0.468.0 assets are locally packaged with their upstream licence. No CDN
requests, tracking or ambient external assets. CSP restricts scripts/styles to
self and disallows framing. HTTPS is required before exposure beyond loopback.

Optional MCP is a **separate service**, not a route on this one: it is built from
`components/control/mcp/` (image, lock, manifest — MCP component) and reaches this platform over
`LO_PLATFORM_URL` as an authenticated client. It uses official Python SDK 1.29.1, stateless Streamable
HTTP with JSON responses, and a bearer credential that arrives only as a file — either the per-agent map
(`LO_MCP_IDENTITIES`: a JSON list of `{identity, role, bearer_token, platform_token}` rows, roles
`reader`/`proposer`/`executor`, `human` refused) or the v0.1 single shared reader token
(`LO_MCP_TOKEN_FILE`). A process configured with both, or with neither, does not boot. Each agent's own
platform credential is what this platform then sees, which is what makes an `action.proposed` audit row
name an agent instead of a shared secret; the tokens identify requesters and never a human approver
(`docs/CONTRACTS.md` §5).

The tool set is decided by the registry in `local_observe/platform/tools.py`, not by this file: **four**
reads on the single-token shape (`platform_status`, `platform_overview`, `records`, `inventory`) and up to
**ten** on the per-agent shape — those four plus `evidence_window`, `signal_series` and
`topology_neighbourhood` (each of the last two present only when its store reader or inventory index is
mounted), `component_boundary`, and **exactly one** gated pair: `propose_action` files a request that a
human must decide, and `execute_action` refuses before any platform request because no trusted runner
handoff exists. There is still **no approval tool here and none in MCP**: the decision is
`POST /v1/actions/decision` under a `human` credential, which is what keeps agent self-approval
rejectable. `records` stays bounded at 20 rows and every answer is budgeted at 64 KiB in both directions
(a too-large request is a 413, a too-large answer is the refusal sentence, never a truncated document).
The counts and the refusal matrix are the ones `tests/test_mcp_component.py`,
`tests/test_mcp_surface.py` and `tests/test_platform_tools.py::ActionPairTests` pin; the surface has never
been run against a container (all eleven runtime rows of `components/control/mcp/conformance.md` are
`not-run`), and the SDK's own transport-security defaults have not been re-read at the pinned version,
so nothing here should be read as verified on a host.

There is no anonymous, cross-origin or OAuth discovery fallback, and no stdio transport or SSE resource
stream. Optional MCP absence does not affect normal operation: the extra is not installed in the platform
image, so this UI, every `/v1/*` route and the portal run exactly as they do with no MCP service on the
host. No AI model is required or invoked.

This manifest carries no healthcheck of its own by design: it is merged over the
platform component and replaces only the Uvicorn factory, so the platform's
authenticated healthcheck still applies to the operator factory, and a second probe
would double the requests against the same process.

# Conformance

2026-09-06: ASGI tests passed static CSP, unauthenticated denial, reader identity,
inventory reads, bounded record limits and rejection of reader approvals. Official
MCP transport passed authentication, tool enumeration, read calls and refusal of
an unknown approve tool. Only three read-only tools are registered.

Playwright 1.58.0 with installed Chrome passed 1440x960 and 390x844 checks:
sign-in, record inspection, approval cancellation, evidence read, reader button
restrictions, no page overflow and no JS errors. Screenshots inspected; evidence
in scratch/operator-demo/browser-report.json and desktop.png/mobile.png.

The local demo uses separate synthetic state and no notification client/executor.
It is not a host platform upgrade. Remaining: deployed UI/MCP checks over TLS,
real operator credential provisioning, confirmed human action workflow, and
explicit retention/pressure/cross-session concurrency coverage. AI/chat integration
is not implied by a working read-only MCP transport.

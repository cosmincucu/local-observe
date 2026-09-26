# `local_observe.ai` — the optional generation plane

Four decisions, one module each, plus the client that applies them in order:

| Module | The question it answers | Refuses with |
|---|---|---|
| `capability.py` | has anything *measured* this model doing that? | `capability_unknown` |
| `policy.py` | may this `data_class` be generated at all, and may it leave the LAN (remote inference policy)? | `policy_refused`, `remote_refused` |
| `budget.py` | does the bundle fit, and is it still fresh? | `budget_exceeded`, `expired_evidence`, `unavailable_evidence` |
| `client.py` | one OpenAI-compatible call, bounded, labelled, never retried | `endpoint_unavailable`, `response_too_large`, `malformed_response` |
| `telemetry.py` | what a caller may say about a call when payload capture is off (chat integration) | — |

The operator-facing contract — every `LO_AI_*` variable, the weight directory, the pinned serve,
what was measured against upstream and what was not — is
[`components/control/ai/CONTRACT.md`](../../components/control/ai/CONTRACT.md). This file is the code
map only, so the two do not drift.

## The two rules that hold the package together

1. **A consumer may not use a capability the manifest marks `unknown` or `false`** — stated once, in
   `capability.py`, and reached through `capability.require()` rather than re-derived at call sites.
2. **Nothing outside this package imports it.** `tests/test_ai_component.py` walks `local_observe/`
   and fails on a second importer, which is how "Rules and operator workflows work without
   generation" (`docs/COMPONENTS.md`, the `ai` row) stays true instead of becoming a hope. Consumers
   import lazily and keep their own floor: rca on its rules (investigation component), chat on the portal (chat integration).

There is no second rule about the store: this package imports no query builder, no `Store` and no
HTTP path to ClickHouse, so it *cannot* re-run a query to replace expired evidence. That absence is
asserted by a test, not by this sentence.

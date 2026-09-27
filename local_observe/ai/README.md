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

Results distinguish the requested `model` from the provider's `response_model`. If the
provider omits its model identifier, `response_model` is null. The requested name is not
proof of which model answered; consumers requiring complete provenance must refuse to
certify that result. A returned identifier that differs from the configured model is
still refused by the client.

## The two rules that hold the package together

1. **A consumer may not use a capability the manifest marks `unknown` or `false`** — stated once, in
   `capability.py`, and reached through `capability.require()` rather than re-derived at call sites.
2. **Only documented optional consumers import it.** `tests/test_ai_component.py` walks
   `local_observe/` and requires a reason for each allowed importer. The observer constructs
   its policy-gated client lazily for a model call. Telemetry and urgent rule workflows keep
   working with generation disabled; unavailable models produce explicit coverage failures.

There is no second rule about the store: this package imports no query builder, no `Store` and no
HTTP path to ClickHouse, so it *cannot* re-run a query to replace expired evidence. That absence is
asserted by a test, not by this sentence.

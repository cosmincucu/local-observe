# Conformance — component `ai`

Status: **not run**. Nothing below has been executed against a Docker daemon or a model. What *is*
executed on every commit is the deterministic half, listed first, because that half is the one that can
lie silently if nobody pins it.

## The scenario this component owes

`docs/COMPONENTS.md` §5, row *"Optional AI/chat"*: *"Selected integration tested without Telegram; remote
use gated; repeat core scenario with RCA/AI disabled."* Three clauses, two owners. **This component
owns `remote use gated` and `repeat core scenario with … AI disabled`.** The Telegram clause belongs to
chat integration (chat), and the `rca` half of the second clause belongs to investigation component — which is why the recipe below
disables exactly one thing and says so rather than claiming the row.

## 1. Deterministic half — runs in CI today

Command (repository root, the base tier of `docs/testing-standards.md`):

```
python -B -m unittest discover -s tests
python -B scripts/check_foundation.py
```

| Claim | Test | What it would catch |
|---|---|---|
| a capability the manifest marks `unknown` or `false` is unusable, including the context window | `tests/test_ai_capability.py` | a request sized from a model card, surfacing later as truncated evidence |
| policy refusal per `data_class`, `restricted` refused, remote refused without label **and** without `no_free_text` | `tests/test_ai_policy.py` | a "gate" that was a sentence in a document |
| **remote use gated** — a public-class bundle reaches a non-LAN endpoint only with the label and the scrubbing applied, and the same call for `internal`/`restricted` sends nothing at all | `tests/test_ai_client.py` (`remote_*`, and `transport.calls == []` on every refusal) | an opt-in that opt-in-ed itself |
| budget refusal (bytes, reference count) and the refusal is whole, not truncated | `tests/test_ai_budget.py` | an explanation whose missing half nobody can see |
| expired evidence is reported as expired | `tests/test_ai_budget.py`, `tests/test_ai_client.py` | a fresh query dressed up as evidence — and the accompanying structural test that this package imports no store, no query builder and no `Store` |
| payload capture is off unless the exact string `1`, and a refusal never carries a body | `tests/test_ai_client.py` | prompts ending up in a log store on the strength of `LO_AI_CAPTURE=yes` |
| an oversized response is refused | `tests/test_ai_client.py` | trusting the transport's larger bound as if it were this layer's |
| `model` observation: `disabled` / `unknown` / `degraded` / `healthy`, and **no socket opened** when unconfigured | `tests/test_overview.py` | a green tile for a model that was never measured |
| nothing outside `local_observe/ai/` imports it, and the component manifest passes the model rules | `tests/test_ai_component.py` | generation becoming a hidden prerequisite of a rule or a notification |

## 2. `repeat core scenario with AI disabled` — the recipe, not yet run

The claim to prove is that the disabled state is not a special case: the same acceptance run, one
variable removed. On a Linux host with the full example brought up per its README:

# B. Same host, ai component present, but generation refused: LO_AI_CAPTURE unset, LO_AI_POLICY
#    pointing at a copy of components/control/ai/policy.example.json (every class as shipped).
#    The tile must read "Degraded" (serve ready, capability unmeasured) and every consumer must still
#    complete its own work, on its rule floor, with one warning line naming the refusal code.
```

Pass criteria: the incident/approval/delivery outcomes are **identical** in A and B, and the only
difference in the logs is which refusal the AI layer reported. If any scenario needs an AI variable to
be set in order to pass, the `ai` row is a lie and this file must say so.

**Recorded honestly:** step A has not been run on a host either. What *has* been run is the
equivalent at the import level — the suite passes with `local_observe/ai/` removed from the tree
(`tests/test_ai_component.py` documents the experiment; the worker's report carries the command and the
result). That proves no module depends on the package; it does not prove a container never needed it.

## 3. `remote use gated` — the runtime half, not yet run

Against a real local serve, then against an endpoint the operator declares non-LAN
(`LO_AI_OUT_OF_LAN=1`, an HTTPS URL they control), with `public` permitted for remote in a **copy** of
the policy:

1. one local call: expect content, `out_of_lan: false`, and a `label` of `None`;
2. one remote call on a permitted class: expect `out_of_lan: true`, the label as the first line of
   `display_text`, and the *log* of what left the host — the request body is not logged, so read the
   call record's `evidence_bytes` and `redaction_counts`;
3. confirm the redaction actually ran: put a credential-named key and a 300-character log line into the
   bundle, and check the outgoing body contains `<redacted>` and `<withheld:free-text>` rather than
   either original. This is the step the deterministic tests cover with a stand-in transport; on a real
   endpoint it is the only proof that what left the LAN was what the policy described;
4. `internal` and `restricted` remotely: expect refusals naming the class, and expect the endpoint's own
   access log to contain **no request** — a refusal that produced a request is not a gate.
5. `tools`: `capability.validate` must refuse a manifest claiming `tools: true` while the shipped
   manifest starts the serve without `--tools` (CONTRACT.md §2 quotes the upstream help: `read_file`,
   `write_file`, `exec_shell_command`, "do not enable in untrusted environments").

Steps 1-5 are also the first time the two UNVERIFIED lines in CONTRACT.md §2 get answered — the header
the serve accepts, and whether the pinned build answers the product client at all. Until they have run,
`versions.json` keeps `runtime_conformance: "not-run"` and this row keeps `experimental`.

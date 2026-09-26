# Conformance — component `chat`

Status: **not run**. Not one row below with a `not-run` in its result column has been executed. No
image pull, no container start, no browser, no MCP call, no backup, no restore. The rows with a test
name in them run on every commit; they are listed first because they are the only half that can lie
silently if nobody pins it.

## The scenario this component owes

`docs/COMPONENTS.md` §5, row *"Optional AI/chat"*: *"Selected integration tested without Telegram;
remote use gated; repeat core scenario with RCA/AI disabled."* Three clauses, three owners, and the
splits are recorded on both sides so nobody marks the row satisfied from one half:

| Clause | Owner | State here |
|---|---|---|
| **"Selected integration tested without Telegram"** | **this component** (chat integration), and it is the first clause on purpose | **not satisfied.** Tested requires a started container. What exists is the negative proof (row 5: nothing in any shipped example configures Telegram, in this product *or* in the surface) plus a documented surface that has never been started. |
| "remote use gated" | AI integration (`ai`) — its `conformance.md` names the client tests | not this row's; nothing here reaches an endpoint outside the project network on its own |
| "repeat core scenario with RCA/AI disabled" | shared: the `rca` half is investigation component (merged), the `ai` half is AI integration, and the **chat** deletion is rows 9–10 below | structural half only |

`docs/CONTRACTS.md` §6 governs every `not-run` on this page: *"omitted dependencies never turn not-run
into pass."* The MCP leg of the round trip has an omitted dependency — **MCP component's deployable MCP
service** has not landed (the *tools* have, with mcp tool surface: `platform/tools.py::agent_registry`, and
`execute_action` refuses before any platform request, since `tools.py::execute_tool` raises first) — so rows 6–8 are
`blocked-on-MCP component`, a word that means the same as `not-run` and names why. Nothing on this page is a pass.

## 1. Deterministic half — runs in CI today

From the repository root (base tier, `docs/testing-standards.md`):

```
python -B -m unittest discover -s tests
python -B scripts/check_foundation.py
```

| # | Claim | Test | What it would catch |
|---|---|---|---|
| 1 | the five artefacts and the manifest exist, and the manifest passes every model rule the gate applies (`check_model`, `check_credential_files`) — which it needs, because **no example include line puts it inside `check_example`** | `tests/test_chat_component.py::ShippedArtefactsTests` | a component directory that only looks complete, and a manifest nobody polices |
| 2 | telemetry cannot be on: `DISABLE_TELEMETRY` is the literal `"true"`, the value the pinned build compares with `===` | `tests/test_chat_component.py` (`test_telemetry_is_off_in_the_exact_form_the_pinned_build_checks`) | a chat surface on the operator's LAN phoning an analytics endpoint because someone wrote `false`, `0` or `off` |
| 3 | publication is **off** and the widening is not half-applied: no `ports:` line, `chat` absent from `HOST_PUBLISHED_SERVICES`, and the commented intended line names the port it would use | `tests/test_chat_component.py` (`test_publication_is_commented_and_names_the_two_edits`) | a port opened by an edit to one file while the pinned tuple in `tests/test_ai_component.py` still says seven names — which is a red suite; the two named edits are written out in CONTRACT.md section 3 |
| 4 | no approval capability in the manifest or the contract: no auto-approved-skills env, and the contract's refusal table names `execute_action` and the decision route as refused | `tests/test_chat_component.py` (`test_the_surface_is_never_granted_approval_or_dispatch`) | an approval moved into the chat client, where the platform cannot see who agreed (integration validation's *"approval separation"*) |
| 5 | **operation without Telegram**: the component's own files name no Telegram token, key or variable, and no shipped example's `LO_CHAT_*` lines do either | `tests/test_chat_component.py::AbsentByDefaultTests` | adopting the surface's built-in connector by accident and calling the row non-Telegram |
| 6 | the component is absent from every example, its service is not in the full model, and its template lines are all commented | `tests/test_chat_component.py::AbsentByDefaultTests` | 1.1 GB and a chat credential becoming a boot need for `standard` (chat integration is provisional; §4 forbids the hidden prerequisite) |
| 7 | **authentication** (integration validation clause 1): an unauthenticated `/v1/actions` POST writes no row and opens no connection, and a bearer token names the actor the audit row carries | `tests/test_chat_approval_separation.py::IdentityTests` (over the existing transport tests' ground) | "whoever tapped" reading as an identity |
| 8 | **approval separation** (integration validation clause 3): a `proposer` credential — the shape of a chat-issued token — can propose and cannot decide, cannot claim, and cannot approve through the callback route | `tests/test_chat_approval_separation.py::ChatCannotApproveTests` | a chat surface that could approve its own proposal, or could launder an approval through a notification code |
| 9 | the round trip's platform legs, and **the answer a reader sees is the recorded status, not a guess**: after a denial, every read path (`/v1/records/actions`, `/v1/status`) says `denied` | `tests/test_chat_approval_separation.py::RoundTripTests` | a model sentence about an approval nobody gave, presented as state |
| 10 | **expire-unanswered**: the delivery loop's `expire_actions` pass moves an unanswered proposal to `expired` with one audit row, and a human decision arriving afterwards returns `expired` rather than honouring the click | `tests/test_chat_approval_separation.py::ExpiryTests` | a phone answer an hour late silently approving a stale action |
| 11 | the pin file states its own unknowns: `verified_on: null`, `image_digest` present *with* the read date and URL, and an `unverified` list that is not empty | `tests/test_chat_component.py::PinDocumentTests` | a digest without provenance, or a pin that implies a run that never happened |
| 12 | every upstream claim carries a source and a date — the dated reading in `CONTRACT.md`, the URLs in `versions.json` — and `not-run` appears in this file | `tests/test_chat_component.py` (`test_every_upstream_claim_carries_a_source_and_a_date`) | the docs truth defect class: a version claim with no source |

## 2. Runtime half — recipes, all `not-run`

Each row is a command and the answer it must give. **Nothing here is expected to pass today**; rows 3
and 6–8 are where a host run most likely produces a finding rather than a green tick, and the finding
is the deliverable.

| # | Check | Command (host, `examples/full` plus this include) | Expected | Result |
|---|---|---|---|---|
| 1 | AVX2 pre-flight, before anything is pulled | `lscpu \| grep -o avx2` **inside the guest/container host that will run the service** | prints `avx2`. Without it the pinned build dies the moment LanceDB loads — upstream's own text: *"Illegal instruction (core dumped) node /app/server/index.js"*, and `restart: unless-stopped` turns that into a crash loop. | **not-run** |
| 2 | image identity, before the first boot | `docker image inspect --format '{{.Config.User}}' "$LO_CHAT_IMAGE"` | `1000:1000`. This is the inference in compose.yaml's `user:` line and `versions.json` names it as unverified; anything else means the user line **and** the volume's seeded ownership are wrong together. | **not-run** |
| 3 | **read-only root boots** | `docker compose up -d chat && docker compose logs --since 5m chat` | `started` and `/api/ping` answers, **without** an `EROFS` from the entrypoint's `npx prisma generate`. If it fails, the two remedies are named in CONTRACT.md section 10 (a writable volume over the Prisma client output, or accepting a writable root for `/app/server`) and **both need a reviewer**: the first keeps generated code across a pin move, the second drops the property this gate exists to enforce. A component that cannot satisfy `read_only: true` keeps its row at `planned`; that is a finding, not a workaround. | **not-run** |
| 4 | healthcheck can go red | `docker compose exec chat curl -fsS http://127.0.0.1:3001/api/ping`, then stop the server process and repeat | 200 `{online:true}` while up; non-zero once down. Upstream's own script would answer 0 either way (it parses the code in bash), which is why the manifest does not copy it verbatim. | **not-run** |
| 5 | payload posture | open the UI, send one message, then `docker compose exec chat sh -c 'ls -l /app/server/storage'` and read `anythingllm.db` growth | the transcript **is** written (CONTRACT.md section 7 says so rather than claiming otherwise) and the UI does not list chat history back to a second reader (`DISABLE_VIEW_CHAT_HISTORY=1`) | **not-run** |
| 6 | **tool calls** (integration validation clause 2) — the chat surface reaches the platform's MCP facade over Streamable-HTTP with its own bearer token and lists exactly the tools in CONTRACT.md section 2 | register the server in AnythingLLM's admin panel (`storage/plugins/anythingllm_mcp_servers.json` is written by the app, not by a mount), ask it for `platform_status` | the tool list matches, and an unread token gets the facade's 401 with no body | **blocked-on-MCP component** — the tools exist (`tools.py::agent_registry`: the reads, plus `propose_action` for a `proposer` row, reached with that row's own bearer through `LO_MCP_IDENTITIES`) but **no container runs the MCP server**: `components/control/mcp/` does not exist, no `${LO_MCP_IMAGE}`, and `components/control/platform/Dockerfile:45` states the platform image does not install the `mcp` extra. The only process that answers today is the hand-started one in `examples/full/README.md` step 9, bound to the host's loopback and therefore not reachable from this service without an overlay this repository does not ship |
| 7 | **approval separation, at the surface** — the assistant proposes an action and then cannot approve it | ask the surface to propose; approve in the portal; ask the surface to approve its own proposal | `action.proposed` with actor `chat-<label>`; the surface's approval attempt has no route to land on — `POST /v1/actions/decision` is role `human` and no MCP tool wraps it | **blocked-on-MCP component** |
| 8 | the answer reflects the **recorded** outcome | after claim + outcome, read the thread | the number the surface quotes is the one `/v1/records/actions` returns | **blocked-on-MCP component** |
| 9 | **If disabled** — `If disabled: "Portal and direct MCP clients remain."` | delete the include line, `docker compose up -d`, and re-run the §5 *Failure to recovery* scenario and one approval through the portal | byte-identical durable state to the same two runs with the component present | **not-run** at host level; the structural half is pinned — no `depends_on`, no shared volume, no port, and `tests/test_chat_component.py::AbsentByDefaultTests` proves the full example's service set never contained it |
| 10 | restore into a staging volume | [backup.md](backup.md) section 3 | `integrity_check` = `ok` and the two counts match the pre-stop values | **not-run** |
| 11 | the volume is the only state | `docker compose exec chat command -v sqlite3`; then `docker compose cp chat:/app/server/storage /tmp/x && ls -la /tmp/x` | names what the image can and cannot do for itself — backup.md section 2's stopped-writer recipe stands or falls on the first answer | **not-run** |

## 3. What would move this row from `planned` to `built`

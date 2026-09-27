# Component `chat` — the phone surface, validated without Telegram

**Nothing in this directory has been run.** No image has been pulled, no container started, no
database migrated, no backup taken, no transcript read. Every runtime clause below is `not-run`, and
per `docs/CONTRACTS.md` §6 an omitted dependency is never reported as a pass — the MCP leg is omitted
here (MCP component's MCP **service** has not landed; its tools have, with mcp tool surface), so the round trip in
[conformance.md](conformance.md) says `not-run` in the row and not in a footnote.

## 1. What the row claims, and what is provisional about it

| Item | Value |
|---|---|
| Row (`docs/COMPONENTS.md`, `chat`) | *planned* → **planned**, still. Justified in section 3; the honest one-line reason is that the seam this surface consumes does not exist as a service yet. |
| Surface | AnythingLLM, one container, upstream `v1.16.1` (2026-08-27), MIT |
| Selection | Provisional chat integration; validate the MCP and provider paths before enabling it. |
| Why it exists at all | **phone surface**: *"chat + push approvals are the phone surface; the portal is desktop-first."* Chat is not a demo; it is where an approval is read. |
| Acceptance gate | **integration validation**: *"validate authentication, tool calls, approval separation and operation without Telegram. A failed optional integration does not block release of the working core."* |
| Relationship to prior integrations | The selected chat surface and notification rail replace the earlier deployment-specific chat integration. Web Push for the installation's phone interface remains a separate integration question; section 6 records the upstream capability and unresolved acceptance. |

## 2. The seam: MCP is the seam, chat is the client

The chat surface is an **MCP client** of the platform's own facade
(`local_observe/platform/mcp.py`) with a token issued for this surface alone. It is not a product
module, it opens no product socket, and no product code imports it. `local_observe/platform/chat.py`
does not exist and this component argues it should not (section 9).

### The tool set the surface may hold, and every refusal

| Tool (named as `platform/tools.py` registers it) | Held by the chat surface | Where the refusal lives |
|---|---|---|
| `platform_status`, `platform_overview`, `records`, `inventory` (v0.1's four reads) | **yes** | server side: the MCP bearer gate (`tools.authorize`, constant-time over the mounted map), then the platform's own GET role gate (`api.py`) reached with *that row's* `platform_token` |
| `evidence_window`, `component_boundary` | **yes** | same two gates; `component_boundary` answers from the product contract, not from a store this process cannot read |
| `signal_series` | **only when the MCP process was handed a store reader** | same two gates, plus `platform/query.py`'s evidence reauthorisation. Given no `LO_CLICKHOUSE_URL` the tool is **absent from the surface** rather than present and answering "unconfigured" (`query.open_reader` logs one line naming the variable and returns `None`) |
| `topology_neighbourhood` | **only when the process was handed `LO_INDEX_PATH`** | a capability of that process, not of the token; the same two gates |
| `propose_action` — one half of the gated pair | **yes**: it is exactly what this surface is for | server side: the tool's role hint names `proposer` (`ToolHints.roles`), so a reader row meets a refusal naming the role it lacked, and `Store.propose_action` then requires `proposer` or `human`; the requester written to the audit row is the authenticated identity and no body field is read as one |
| `execute_action` — the other half | **no** | the tool requires `executor`, so a chat proposer cannot reach it. A separately granted executor can request an approved trusted handoff; only the independent runner claims and dispatches. |
| *approve / deny* (the decision) | **no, and not a tool at all** | the only writer is `POST /v1/actions/decision`, whose role gate admits `human` alone (`state.py::Store.decide`), which no MCP tool wraps, and which the identity map may never be handed: `tools.identity_rows` refuses a row whose role is `human`, `producer` or `summary` |
| *claim / outcome* for a runner | **no** | role `executor`, and `Store.execution_outcome` additionally refuses a runner whose identity or token does not match the claim |

**The allowlist cannot be shipped as configuration, and pretending otherwise would be the fiction
this section exists to prevent.** At the pinned commit the MCP server registry is *application state*
the surface writes itself: `${STORAGE_DIR}/plugins/anythingllm_mcp_servers.json`
(`server/utils/MCP/hypervisor/index.js` resolves it from `STORAGE_DIR`; `server/.gitignore` lists the
file). It is not a file this repository can mount read-only, and per-server tool suppression lives in
it as `anythingllm.suppressedTools`. So the enforcement this row relies on is **server-side role
gating**, and the client-side suppression list is a convenience that hides tools the token could never
have used. The sentence an operator needs: *deleting the tool from AnythingLLM's panel changes nothing
about what the token can do; adding a tool there and a role here is what changes it.*

The tool registry and per-agent transport are implemented in
`local_observe/platform/tools.py` and `local_observe/platform/mcp.py`.
`execute_action` is refused before it reaches the platform. The optional MCP component
has its own image and manifest, but connecting the chat client to its per-agent
surface requires explicit configuration and acceptance testing. The platform image
does not install the MCP extra. Do not treat tool availability in source as proof
that a chat container can reach or authenticate to the service.

## 3. Publication, and why the row stays `planned`

What the operator gets today: a manifest, a pin, four lifecycle documents and **no reachable surface**
— `docker compose up` yields a container answerable only from inside the project network. That is a
rehearsal, not a phone. It is why the row says `planned` and not `built`, and it is the difference
between shipping a component and shipping an intention: the intention is honest, and it is named here
in the file an opt-in reader opens first.

`cors({ origin: true })` in `server/index.js` at the pinned commit is a second reason to be slow about
publication: the API answers any browser origin. Loopback plus AnythingLLM's own login is not nothing,
but it is not an edge. The TLS + authentication recipe
[`components/control/homepage/CONTRACT.md`](../homepage/CONTRACT.md) is the same documented recipe
this component points at and equally does not start.

## 4. Approval separation — the clause that decides whether this ships

The invariant, from `docs/CONTRACTS.md` §5 and incident and action state: **the platform owns approval state; identity
comes from authenticated transport; payload fields cannot claim that an agent is a human; read tokens
cannot approve or execute.** Everything below is that sentence expressed in one surface.

| Actor | Credential | May | May not |
|---|---|---|---|
| the chat surface (an agent) | **two** credentials, in one row of the MCP identity map (`LO_MCP_IDENTITIES`, four keys exactly: `identity`, `role`, `bearer_token`, `platform_token`): the bearer the surface presents to the MCP transport, and the *platform* role credential that MCP process replays upstream — role `proposer`, identity `chat-<label>` | read, propose | decide, claim, dispatch, spend an approval code |
| the human approver | a `human` role credential held by the portal/operator UI, never by the surface, and **refusable at the map itself**: `tools.identity_rows` refuses an MCP row whose role is `human`, `producer` or `summary` | `POST /v1/actions/decision`, `execution_outcome` | — |
| the runner | an `executor` credential (Dagu), per §5 *"Dagu is an executor, not a separate source of remediation approval"* | claim an approved action, record outcome — **directly over the API**, not through MCP | decide |

Two properties of that issuance are worth naming before the refusals, because they are the shape chat integration's
*"per-agent tokens identify requesters, not human approvers"* takes in code: a row's two credentials may
not be the same string (`identity_rows` refuses a repeated credential, including a bearer that is also
somebody's platform credential), and the map is 1–32 rows of 24-character-minimum tokens validated at
boot, so a chat deployment that shares one row between two surfaces has no answer to "who asked?" and
cannot get one later.

Three refusals carry this, all of them existing behaviour, all of them tested here:

1. **The surface cannot decide.** `Store.decide` admits role `human` only. A proposer credential
   reaching `/v1/actions/decision` gets the platform's fixed refusal and one `action.refused` audit
   row naming its own identity (`refusals.py`). Test:
   `tests/test_chat_approval_separation.py::ChatCannotApproveTests`.
2. **The surface cannot dispatch.** `Store.claim_action` admits role `executor` only, so even an
   action a human *did* approve cannot be claimed by `chat-<label>`. Same test class. There is a
   separate trusted boundary on the MCP path: an explicitly granted executor may request a
   durable handoff, but only the independently authenticated runner receives claim authority.
   The configured human-reviewed binding, policy and expiry remain mandatory. A chat proposer
   cannot approve or claim; the trusted runner must never share its credential with chat.
3. **The surface cannot launder an approval through a notification code.** `POST /v1/callbacks/{channel}`
   exists since notifications and its role gate admits `human`, `proposer` **and** `executor`
   (`state.py::Store.record_callback`). That is deliberate and it is the one place a `proposer` token reaches an
   approval-looking route, so it is pinned rather than assumed: what it writes is one
   `action.approval_intent` row and the action **stays `pending`** — the decision still needs a human
   credential. The risk it names: if the chat surface could both hold a callback code and post it, the
   audit trail would show an intent from `chat-<label>`, which is a machine claiming to have been at a
   phone. The rule that follows, and it is an operator rule because nothing in the code enforces it:
   **a `proposer` credential must not be usable against the callback route in a deployment where a
   human might be the one holding the code** — the code's audience is the phone, and the platform
   prints it on Telegram only (`notifications.py`), where this product configures nothing (section 6).
   Pinned as an assertion about the recorded row, not about a rule the transport cannot see.

**What the chat answer may say.** After a decision the surface's answer is read back from the platform
(`GET /v1/records/actions` or the MCP read of the same table), never from the model. The recorded
status is one of `pending`/`approved`/`denied`/`expired`/`executing`/`succeeded`/`failed`/`unknown`;
a model sentence that disagrees with the row is wrong in the only way this component can be wrong.
Section 5's round trip is what makes that sentence checkable.

## 5. The round trip this component exists to serve

```
event → incident → propose_action (from chat, role proposer, identity chat-<label>)
      → human decision IN THE PORTAL (role human)      ← never in chat, by design
      → claim (role executor) → outcome (role executor|human)
      → the chat answer reflects the RECORDED outcome
```

Everything between `propose_action` and the recorded status is product code, and
`tests/test_chat_approval_separation.py::RoundTripTests` walks it end to end at the unit tier:
intake → incident → propose as the chat credential → decide as a human → claim as the runner →
outcome → the status a reader gets back from `/v1/records/actions`. What is **not** tested is the
two edges that cross into this container — a tool call arriving from AnythingLLM and the answer it
puts in a thread. The **tool** exists now (mcp tool surface's `propose_action` in `platform/tools.py`); what does
not exist is a container running the MCP server for that call to arrive through, and this container has
never started. Those are rows 6–8 of [conformance.md](conformance.md), each marked for what stops it,
each carrying the command that would settle it. One leg of the diagram above is also no longer reachable
over MCP at all: the claim is the runner's, taken directly against the API, because `execute_action`
refuses before any platform request (`tools.py::execute_tool`) — which is the design point of the row,
not a gap in it.

**Expire-unanswered is already wired, and it is not this component's invention.** chat integration's recommendation
half names approver behaviour as *"expire-unanswered plus a tiny reversible allowlist"*. The first half
exists: every proposal must carry an `expires_at` inside the next 24 hours (`state.py::Store.propose_action`), the
delivery loop calls `Store.expire_actions` on its own pass (`api.py`'s delivery loop), an expired action moves to
`expired` with one `action.expired` audit row, and a *later* decision on it returns `expired` rather
than honouring the click (`state.py::Store.decide`, which rewrites the decision as `expired`) — so a phone answer arriving after the window is a recorded
fact, not a resurrection. Tested here: `ExpiryTests`. **The second half — the "tiny reversible
allowlist" — is NOT implemented and is not deferred quietly:** it is an authority mechanism (an action
that needs no human), it belongs to `policy.py`/`state.py` and not to a chat manifest, and it collides
with MCP component's *"exactly one pair"* rule. It is listed for the reviewer as a card to open, and until an
answer exists every chat-originated proposal expires unanswered by default. That default is the safe
side of an unanswered question, which is the correct place to sit.

## 6. No Telegram — including AnythingLLM's own

integration validation's last chat clause and the row's own words (*"Non-Telegram chat/tool workflow"*) make this the
acceptance gate rather than a preference. What ships:

## 7. Transcripts, and what "payload capture off" can and cannot mean here

chat integration's recommendation, and the same rule AI integration carries: a chat transcript is the most sensitive text
this system will hold. The honest answer has three parts, and the first one is a refusal to pretend.

1. **Where the bytes are.** AnythingLLM writes every message into
   `/app/server/storage/anythingllm.db` — `file:../storage/anythingllm.db` in
   `server/prisma/schema.prisma`, inside `STORAGE_DIR`, on the `chat-storage` volume — together with
   workspaces, users and API keys (`api_keys.secret`). It is the component's state and
   [backup.md](backup.md) is about it. It is **not** in the platform's SQLite, and nothing in this
   product's retention rules (retention/telemetry retention) reaches it: an operator who restores that volume restores a
   conversation history, and an operator who follows backup.md's deletion step destroys it deliberately.
2. **What is off by default in this manifest.** `DISABLE_VIEW_CHAT_HISTORY=1` (transcript hidden from
   the UI and the workspace APIs) and `WORKSPACE_DELETION_PROTECTION=1`. **No flag at the pinned commit
   stops the write**, and the memory-extraction background job (`server/models/memory.js`,
   `MEMORY_EXTRACTION_INTERVAL` default 15 m) distils chat content into a persistent store — so the
   claim "transcripts are ephemeral" would be false, and the claim this file makes instead is that
   transcripts are *local, non-viewable by default, and covered by one explicit deletion step*.
   `AGENT_AUTO_APPROVED_SKILLS` is deliberately unset for the same reason it belongs in section 4.
3. **What `data_class` a chat-originated proposal inherits: nothing, and no field invents one.** The
   `actions` table is `(id, requester, retry_key, fingerprint, payload, status, created_at,
   expires_at, decided_by)` (`state.py`, the `actions` table in its schema constant) and `evidence` carries `(id, source, payload,
   fingerprint, expires_at)` — no class on either. `data_class` is the AI plane's vocabulary
   (`ai/policy.py`, `DATA_CLASSES`) and `AiClient.complete()` takes it as a caller-supplied argument
   (`ai/client.py:169`); nothing derives it from who proposed what. Consequence an operator should
   know before pointing AnythingLLM at AI integration's endpoint: a proposal that arrives through chat is
   classified by the *caller of the generation*, not by the platform's record, so the classification
   this product can enforce sits on the outbound gate and nowhere else. If a future card wants
   provenance — "this action came from a chat surface" — the place it belongs is the proposal payload
   and the `action.proposed` audit detail, and that is `state.py`'s row in `DEPENDENCIES.md`, not a
   field to be smuggled into a manifest.

## 8. Opting in, and deleting it

**Opting in** is one `include:` line and the variables below. Nothing in a default bring-up needs an
image, a settings file or a chat credential, and the portal shows no chat tile because the product has
no chat tile.

```yaml
# examples/full/compose.yaml — an operator who wants the surface adds ONE item to the list that is
# already there. Never a second top-level `include:` key: Compose keeps one, and this example's store
# entry is a two-path merge that a duplicated key would silently discard.
#   include:
#     - ../../components/data/store-signoz/compose.yaml   (…existing entries…)
      - ../../components/control/chat/compose.yaml        (← the one line added)
```

| Variable | Layer | What it is | What happens if it is wrong |
|---|---|---|---|
| `LO_CHAT_IMAGE` | compose | the digest-pinned image (`docker.io/mintplexlabs/anythingllm:1.16.1@sha256:05617e7b…` is the identity this row resolved; pull from the registry you use and re-resolve) | `config` fails: it is a required image variable, and `pull_policy: never` means no silent fix |
| `LO_CHAT_MEM_LIMIT` | compose | container memory ceiling — upstream says 2 GB is the *minimum* for the container alone | unset → `config` fails; too low → the Node process is OOM-killed with a message in the container log, not in the UI |
| `LO_CHAT_CPUS` | compose | CPU cap, default `2` (upstream's stated minimum) | nothing dramatic; a busy reranker gets slow |
| `LO_CHAT_MAX_TOOL_CALLS` | compose | bound on one agent turn's chained tool calls, default `10` from upstream's own documented example | higher = a longer runaway budget, not a capability |
| `LO_CHAT_SETTINGS_FILE` | compose | the host file mounted read-only at `/app/server/.env` — AnythingLLM's own settings and any provider key, in plaintext | `config` fails. Create it owned so uid 1000 can read it (Compose bind-mounts a `file:` secret with its host ownership, it does not copy it), and read section 3 of [backup.md](backup.md) about the write the pinned build performs against this file's content on a UI action |
| `LO_CHAT_PORT` | compose (commented) | the loopback publication this row has not enabled | nothing today — see section 3 |

**Deleting it** is the row's `If disabled` clause: *"Portal and direct MCP clients remain."* The chat
service declares no `depends_on`, mounts no shared volume, publishes no port and is included by no
example, so removing its include line removes one container and changes nothing the platform can see —
the incident, approval and outbox state never had a chat write path. The proof is
[conformance.md](conformance.md) rows 9–10 (structurally pinned by
`tests/test_chat_component.py::AbsentByDefaultTests`; the `docker compose` version is `not-run`,
because no host run has been performed for this item).

## 9. No new product module, and why that is the disciplined answer

The allowlist permits `local_observe/platform/chat.py` *"only if a channel adapter is needed"* and a
callback route in `api.py` *"only if notifications did not already create one"*. Neither is needed:

* **No adapter.** The surface talks to the platform through two seams that already exist and already
  authenticate: MCP (`mcp.py`) and `/v1/actions` over the platform API. An adapter module would be a
  third copy of an HTTP client for a client that lives in another product's container — the mistake
  component plan's brief list calls *"building the third surface instead of the seam"*.
* **No new route.** notifications shipped `POST /v1/callbacks/{channel}` — single-use code in the body, actor
  from the bearer credential, expiry enforced, one `action.approval_intent` row, action stays
  `pending`. It is generic over channel names, so a future chat-native approval callback lands on it
  rather than beside it. Adding a route to it here would be editing a merged component from an
  unrelated card, which is what `DEPENDENCIES.md` exists to prevent.
* Consequence stated so nobody has to rediscover it: because the product writes no chat code, this
  component has **no import-graph footprint**, and `tests/test_ai_component.py::ImportGraphTests`'s
  rule ("nothing outside `local_observe/ai/` imports generation") is untouched. If a later card wires
  `local_observe.ai` into a chat path, that test's allowlist, its reason string and two rows in
  `DEPENDENCIES.md` move in the same change.

## 10. What is verified and what is not

Verified by reading pinned source or a dated registry/doc response, all on **2026-09-09**: image
digests and compressed sizes (Docker Hub tag record); release date and commit
(`35c58d89907e675a8c4fb10544c19be0f050f611`); MIT licence text at the tag; the entrypoint's two
processes, its `prisma generate`/`migrate deploy` boot and its `STORAGE_DIR` warning; the healthcheck
endpoint and that it needs no credential; `STORAGE_DIR` and the SQLite path; the enumerated write set
(`server/.gitignore`); the MCP client's Streamable-HTTP transport with headers, and the registry file's
location; the telemetry default; `AGENT_AUTO_APPROVED_SKILLS`, `DISABLE_VIEW_CHAT_HISTORY`,
`WORKSPACE_DELETION_PROTECTION`/`AGENT_MAX_TOOL_CALLS` as documented knobs; the Telegram/web-push/
mobile endpoints and `bootIfActive`; upstream's recommended minimum (2 GB / 2 cores with AVX2 / 5 GB)
and the AVX2 failure mode quoted from the live docs page.

**UNVERIFIED — every one of these is a line in [conformance.md](conformance.md), not a claim here:**
the image's actual `Config.User`; that `read_only: true` boots at all (`prisma generate` writes into
the image root — if the shipped client is not already generated, the first boot fails with `EROFS`, and
the two remedies are named there and applied by neither); what else the collector writes; the
uncompressed size on disk; whether the surface can run with no vector database at all; AnythingLLM's
UI default for skill auto-approval; compatibility with the selected assistant client;
and whether these source-derived expectations hold in a running installation. The claim that AnythingLLM's own Telegram
pairing gate is a *usable approval pattern* is an upstream integration candidate and is
**not** re-verified here and not relied on.

The candidate client uses `StreamableHTTPClientTransport` and
`anythingllm_mcp_servers.json`. End-to-end integration remains unbuilt and requires
independent validation; a client capability alone does not establish compatibility.

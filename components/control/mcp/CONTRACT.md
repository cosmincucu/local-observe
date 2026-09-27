# MCP tool surface — the image that carries the optional extra (component `mcp`, MCP component)

Status: **experimental, never run**. No image has been built from `Dockerfile` in this directory, no
container has been started from `compose.yaml`, and no MCP client has driven one surface end to end.
`versions.json` carries the SDK pin, the base pin, what was read from PyPI on 2026-09-10 and the
UNVERIFIED list; `conformance.md` carries what has to run before `docs/COMPONENTS.md` §3's `mcp` row can
be called anything better than `partial`.

What this directory **is**: the packaging of a surface that already exists and is already tested.
`local_observe/platform/tools.py` (the registry, the provenance envelope, the identity map, the refusal
table, the result budget) and `local_observe/platform/mcp.py` (the transport) arrived with mcp tool surface and the action execution boundary; the component row has been describing them ever since. What this directory **adds** is the thing the
row could not point at: an image a stranger can build from `docs/BUILD.md`, a hash-locked dependency set
that installs the `mcp` extra somewhere, a manifest with a healthcheck and a loopback publication, and the
five quality bar artefacts. It changes no product code. If you came here looking for `store_query`, a second
action tool or a working execution path, §5 and §7 say why none exists.

**Optional by construction,** like `ai` and `crowdsec`: no shipped example composition includes
`components/control/mcp/compose.yaml`, so `minimal`, `standard` and `full` boot, page, approve and record
with no MCP image on the host and no MCP credential staged. `docs/COMPONENTS.md` §4 defines `full` as
*"standard plus explicitly selected optional integrations"*, and this one is selected by an operator who
runs an agent, not by a release.

## 1. The contract this row has to keep

`docs/COMPONENTS.md` §3, the `mcp` row's Local MVP role, verbatim: *"Evidence-backed read access and
gated requests"*. chat integration supplies the shape; incident and action state and `docs/CONTRACTS.md` §5 supply the identity rules.

| Clause | Where it is enforced | What that actually means |
|---|---|---|
| Streamable-HTTP only | `mcp.py::_serve` builds one FastMCP with `stateless_http=True, json_response=True`, and `/mcp` on container port 8003 is the only route | no session outlives a request, so the agent a message is answered as is the agent whose bearer arrived with it; there is no stdio transport and no SSE resource stream to test |
| read tools **with an evidence envelope** | every answer is two `TextContent` blocks: the platform document byte-for-byte, then `{"provenance": {query_type, parameters, window, source, read_at}}` (`tools.Provenance`) | a read that carries no provenance is a fabrication path, which is why a new read is a row in two test files and not a function; `structuredContent` is gone — an answer with two halves has one schema for both |
| exactly **one** `propose_action` → `execute_action` pair | `tools.CAPABILITIES = ('read', 'propose', 'execute')` and `ToolHints.__post_init__` refuse a second of either; §5 counts it | adding a second action tool is a decision, not a task, and the registry says so at import of the second one |
| gated server-side, decision owned by the platform | the decision route is `/v1/actions/decision`, reached by a `human` credential; no tool names it | Proposing and requesting execution cannot create human approval; the trusted runner rechecks exact approved bindings |
| per-agent static bearer tokens | the map in `LO_MCP_IDENTITIES`: `{"identity","role","bearer_token","platform_token"}` rows, one credential → one agent → one platform credential | an `action.proposed` audit row names an agent rather than "MCP". **These tokens identify requesters, not human approvers** — chat integration's own caveat, and `human` is a refused role (§4) |
| read tokens cannot approve or execute | two gates, not one: `tools.authorize` refuses the tool before a request leaves the process, and `api.py`'s role gate refuses the platform route with the agent's own token | `404`-hiding a capability is not a gate: an agent hears "you may not", which is what makes a refusal auditable |
| 64 KiB in, 64 KiB out | `mcp.MAX_REQUEST_BYTES` (the body, refused as 413 before the SDK parses) and `tools.MAX_RESULT_BYTES` (the answer, refused with v0.1's sentence *"Read exceeds evidence budget; use a smaller result limit"*) | two bounds that happen to agree are not one bound; a truncated document wearing a success is the failure either of them exists to stop |

## 2. What the image is, and what it is not

A thin authenticated transport plus uvicorn. It opens **no database**, holds **no volume** and writes
**nothing durable**: every read and every proposal is an HTTP request to `${LO_PLATFORM_URL}` signed with
the *calling agent's* platform credential. Destroying the container destroys nothing, which is why
`backup.md` is three paragraphs long and `upgrade.md` is about a lock file.

The platform image still does not carry the extra — its Dockerfile says so and
`tests/test_platform_tools.py::ExtraRefusalTests` pins that sentence as behaviour. That division is the
reason this image exists rather than one fat platform image: an operator who runs no agent keeps an image
in which the SDK is *absent*, which is what makes integration validation ("a failed optional integration does not block the
core") observable instead of asserted, and keeps the base CI tier's assertion that the extra is missing
honest. The cost of the alternative is written up in `docs/BUILD.md` and in the report for MCP component: one
image means the `mcp` tier can no longer be an optional tier, and a broken SDK becomes a platform outage.

## 3. Variables

| Variable | Read by | What it does | If unset |
|---|---|---|---|
| `LO_MCP_IMAGE` | compose | the image built from this directory | `config` fails: no image is guessed, and `pull_policy: never` would refuse to fetch one anyway |
| `LO_PLATFORM_URL` | compose → `mcp.identities_with_clients` | the one endpoint agents read through | `config` fails (`:?`-required) — a surface that invented a default origin would be reading a platform nobody chose |
| `LO_INTERNAL_ALLOW_HTTP` | `local_observe/http.py` | whether a plaintext `http://` platform origin is accepted at all | refused: the client will not send a bearer over cleartext unless this is `1` |
| `LO_MCP_IDENTITIES` | `tools.read_identity_rows` | the per-agent map, as a **container** path (`/config/mcp-identities.json`) | not an error by itself; it is one half of "exactly one credential source" |
| `LO_MCP_TOKEN_FILE` | `tools.read_credential_file` | the v0.1 shared reader bearer, also a container path | with both blank the process **refuses to boot** rather than serve an open port |
| `LO_READER_TOKEN_FILE` | `credentials.read_credential`, in the shared-token shape only | the platform credential that single-token process reads with, at `/config/mcp-reader-token` | legacy mode fails at boot naming the variable; ignored entirely when the map is mounted, because each row carries its own `platform_token` |
| `LO_CLICKHOUSE_URL`, `LO_CLICKHOUSE_READ_USER`, `LO_MCP_READ_PASSWORD_PATH` | `platform/query.py::open_reader` | the bounded series read | `open_reader()` logs one line and answers `None`, and `signal_series` is **absent from the advertised tool list** — not present and failing |
| `LO_MCP_INDEX_PATH` (+ the `/inventory` bind) | `tools` → `inventory/index.py` | the declared-graph read | `topology_neighbourhood` is absent from the list, same rule |
| `LO_PLATFORM_POLICY_DIR`, `LO_INVENTORY_SNAPSHOT_DIR` | compose | the two read-only binds: `/config` and `/inventory` | `config` fails; `create_host_path: false` makes a directory nobody wrote a refusal that names the path instead of an empty mount Docker invented |
| `LO_MCP_PORT` | compose | the loopback host port | `18100`, which no shipped example uses |

`LO_MCP_IDENTITIES` is deliberately the **same** variable the platform manifest already carries: the map is
staged once, in the directory that already holds `actions.json`, and read by exactly one entry point (the
platform's API factory never opens it). Two variables naming two copies of a file full of bearer tokens is
two files that drift, and the drift that matters is a rotated token still living in one of them.

## 4. Identity, and what it is not

The mounted document is a JSON **list of rows**, not an object map — the shape `tools.py:85`
(`IDENTITY_KEYS`) defines and `components/control/platform/CONTRACT.md` §identity documents:

* 1 to 32 rows, file at most 16 KiB, non-empty, not a directory, no control characters;
* each row exactly the four keys `identity`, `role`, `bearer_token`, `platform_token` — a **fifth key is a
  boot refusal**, because a key the code does not read is a key the operator believes is configured;
* `identity` matches `[a-zA-Z0-9_.:-]{1,128}`; `bearer_token` at least 24 characters and **unique across
  rows** (one credential naming two identities makes every audit row a guess);
* roles limited to `reader`, `proposer`, `executor`. `human` is refused ("a human-role credential may not
  be handed to an MCP agent"), `producer` is refused (it posts to `/v1/events` with its own credential and
  needs no tool surface), `summary` is refused (it may not write).

**Not checked at boot:** a row's `platform_token` is not validated against `LO_PLATFORM_CREDENTIALS`. The
map is validated on its own; an unknown token is a `401` on that agent's first request. Catching it at
boot means mounting the role file into this container and is a decision, not an omission — the platform
contract says the same thing in the same words.

**The notification and state leftovers exemption is closed here.** Ledger notification and state leftovers recorded that this entry point's bare
`Path(...).read_text()` was deliberately left out of the `read_credential` sweep. The product no longer
reads an MCP credential that way (`tools.read_credential_file` is the bounded read, and the shared-token
shape reaches the platform through `credentials.read_credential`), and no credential value is an
environment key in `compose.yaml`, so `check_credential_files` needs no exception for this manifest and
`test_no_shipped_component_needs_an_exception` stays green.

## 5. The surface, counted

Read from the registry in a test process (2026-09-10) and pinned by `tests/test_mcp_component.py`, because
"exactly one pair" is a claim that needs a number:

| Shape | Tools |
|---|---|
| one shared token (`LO_MCP_TOKEN_FILE`) | **4**: `platform_status`, `platform_overview`, `records`, `inventory` — the v0.1 set, no action pair, because a shared credential has no answer to "who asked?" |
| a per-agent map, nothing optional mounted | **8**: those four plus `evidence_window`, `component_boundary`, `propose_action`, `execute_action` |
| a per-agent map **and** a store reader **and** an index | **10**: the eight plus `signal_series` and `topology_neighbourhood` |

That is the whole arithmetic: **up to six reads and exactly one propose→execute pair.** The two
capability-gated tools are *absent* rather than broken when their mount is missing (visibility follows the
mount), and every other tool is visible to every mounted agent whether or not its role may call it —
hiding a tool is not a gate, and "you may not" is the answer an agent should hear.

**What `propose_action` returns**, verbatim from `tools.propose_tool`: `action_id`, `status`, `outcome`
(`"filed, pending human decision"`), `performed`, `not_performed` (`["approved", "executed"]`),
`filed_by`, `filed_by_role`, `expires_at`. There is **no** `bound_parameters_sha256` in this surface: the
current API contract does not expose that field. `retry_key` makes the filing idempotent, so a doubled request is one `action_id` and one offer
to approve.

**What `execute_action` returns**: an executor receives a durable queue receipt for an
already approved action with a configured trusted runner. Other roles are refused. The
platform rechecks approval, policy and the reviewed runner binding. No runner credential
is returned to the assistant. Without a configured handoff, execution remains unavailable.
The independent runner journals its own capability before claiming, then dispatches or
reconciles an uncertain execution. See [trusted handoff](../../../docs/units/guided-setup.md).

**The annotations, and the one the registry refuses.** Both gated tools announce
`readOnlyHint: false`; `propose_action` is `idempotentHint: true`, `execute_action` is not; both are
`destructiveHint: false`, and `ToolHints.__post_init__` **refuses to register** a propose or execute tool
that claims otherwise ("Neither tool of the action pair is destructive: one files a request and the other
requests an approved, policy-bound trusted handoff"). The tool itself never runs a job;
the independently authenticated runner owns the eventual external effect.

**No `store_query` exists**, and none is planned: the registry *is* the surface
(`tests/test_mcp_surface.py` compares the bytes a client receives against `descriptors()` in both
directions). query adapter's store facade reaches agents through `signal_series`, and evidence resolves through
`evidence_window`, which answers the platform's own three words — `available`, `expired`, `unavailable` —
and reports `expired` as `expired`.

## 6. Publication, and the argument the tuple demands

`ports: ["127.0.0.1:${LO_MCP_PORT:-18100}:8003"]`, and `mcp` is therefore the eighth name in
`scripts/check_foundation.py`'s `HOST_PUBLISHED_SERVICES`. It is the first of those names that is not a
page a human opens, so the argument is not the UI argument restated:

**an MCP client is a process on another host** — an agent runtime, or a laptop running a client — and no
container on this project's network can reach it, because the caller is not in this deployment at all. For
every other service here, "internal" is a real answer; for this one it means "unreachable", and a manifest
that ships no port deploys a surface nobody can talk to. The publication is still `127.0.0.1:`-prefixed,
so no interface newly listens and the rule still refuses anything else; anything beyond the Docker host is
the same TLS-and-authentication edge the portal and the Healthchecks console document as a recipe this
repository ships and never starts.

**The alternative, priced** (rejected by the reviewer's correction of 2026-09-10): mount `/mcp` on
`local_observe/platform/operator.py`'s factory so one process answers the role API, the UI and the agents
on the port that already exists. It saves an image and a port, and costs three things: the SDK's
per-request session machinery and its 64-KiB body bound land in the process that owns the operational
database and holds its exclusive lock; a uvicorn worker saturated by agent traffic delays the operator's
own approvals; and `If disabled` stops meaning anything, because "the optional integration failed" becomes
indistinguishable from "the platform failed" — the one distinction integration validation and the row's own `If disabled`
cell exist to keep. It also would have made this component an edit to `operator.py`, which is not this
card's file.

## 7. If disabled (the row's `If disabled` cell, in full)

*"Browser/UI workflows remain."* True, and worth spelling out for whoever loses the surface and has to
decide whether to care:

* **Lost:** agent read access to platform state (`records`, `status`, `overview`, `inventory`, and the
  store/inventory/evidence reads when they were mounted), and the gated request path — an agent can no
  longer file a proposal for a human to decide. An operator's assistant integration either stops working
  or reaches the platform over `/v1/*` with its own credential, which is a wider surface, not a narrower
  one.
* **Unaffected:** the operator UI, every `/v1/*` route, the portal, incidents and approvals, the outbox,
  the Sigma path, Dagu and the store. Nothing in the product imports this image or the extra.
* **How to be sure it is really off:** the extra is not in the platform image, so an install that never
  builds this one has no SDK on any interpreter that serves it. `pip show mcp` inside
  `${LO_PLATFORM_IMAGE}` answers nothing, and the MCP tier's tests skip in the base tier with
  `Optional MCP extra not installed; run the MCP test tier separately` — which is the designed state of a
  machine that runs no agents, not a gap.
* **Teardown:** stop the service and delete its include entry. The identity map is the only artefact the
  feature ever touched, and it is the operator's file: nothing here creates, rotates or deletes a
  credential.

## 8. Parity with the private overlay is its own gate (agent delivery pipeline, quality bar)

`docs/COMPONENTS.md` §"Portal summary v1" already carries the sentence: *"The legacy estate MCP
capabilities have a separate coexistence/parity gate, not an implicit alias."* This component holds that
line:

* no legacy tool is renamed into the product, and no product tool is named after a legacy one;
* the private overlay stays outside — the estate read backends live in the operator's tree and reach the
  platform only through the same bounded HTTP interfaces this image uses. A throwaway tool in this
  checkout that read a hostname, a vault path or its own SQL is what `scripts/check_foundation.py` exists
  to fail, and step 8 of `components/control/platform/conformance.md` is the recipe that proves it;
* if the legacy assistant's tool set is ever compared against the ten above, the comparison is a
  conformance check **of its own**, with its own result and its own pass line. It is not in
  `conformance.md` here, because nothing has been compared and a parity row copied from an intention would
  be the same defect as an unrun row marked pass.

## 9. What this component does not have

No execution path (§5). No second action tool, no approval tool, no decision route. No free text in any
argument: UUIDs, bounded labels, closed enumerations and bounded integers only, so no tool accepts SQL, a
path, a URL or a query string, and `component_boundary` is the passthrough answer for capabilities that
stay elsewhere. No browser/UI automation workflow (the row's `If disabled` residue, and the homepage
component's own surface). No stdio transport, no SSE resource stream, no OAuth or discovery fallback, no
anonymous or cross-origin access, no per-agent rate limit (`api.py` has none to inherit), and no
`versions.json` claim about load, concurrency or token cost. No SDK version claim beyond the pin and the
PyPI metadata `versions.json` says it read.

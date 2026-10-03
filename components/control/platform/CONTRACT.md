# Platform state v1

## Ownership and durability

The platform alone owns incidents, canonical intake, approvals, execution claims,
notification attempts/outbox, immutable verification bindings/observations and append-only audit.
Verification storage is in-process only and defaults off; no new HTTP route or automatic
recovery is provided. See [the unit contract](../../../docs/units/verification-records.md).
SQLite application ID 0x4c4f5001, schema version 10 (every file older
than the build is refused until `lo-platform migrate` runs), WAL, synchronous FULL and
related-state transactions provide the initial persistence boundary. Inventory and observed
databases are
separate. An OS-held lock prevents two service processes from running concurrently.
CLI maintenance with database write access is trusted administration, not an agent
API. Run one Uvicorn worker; do not copy SQLite while ignoring WAL.

Schema 10 adds setup plans, human binding approvals and trusted runner requests. The
observer has a separate private journal; back up both selected state stores and configuration.
Reconcile external effects before resuming execution or delivery after restoring an older copy.

`LO_OBSERVER_REVIEW_STATE` optionally names an existing absolute observer state directory. The
platform process must own it (0700) and its journal (0600), using the same OS identity as the observer.
Provide an explicit read/write mount when enabling browser feedback; the default deployment adds no
mount and the routes remain disabled. Startup refuses invalid or missing configured state. Reads
never initialize a journal. The human-only `/v1/observer/cycles`, `/v1/observer/cycle` and
`/v1/observer/feedback` routes retain evidence in that journal and append authenticated review records
with atomic stale-review checks. Agent roles cannot read or write these routes. Browser review uses
the existing operator password or human credential; it grants no model delivery or action authority.
Back up the selected observer state before enabling writes. See the
[review contract](../../../docs/units/observer.md#optional-authenticated-review-api) for limits.

Intake v1 accepts source retry identity, nullable resource UUID, classification,
severity, status, rule/version, bounded evaluation window and evidence references.
The server derives event_id from source/source_event_id and assigns received_at;
records persist these separately from the submitted payload. Matching retry is
idempotent, changed retry conflicts. Resource/rule/source/version form an ordering
domain. Older windows remain evidence but cannot alter current incident state.
Two distinct evaluations at the same watermark conflict rather than guess order.
Unknown input never closes an incident. A later recurrence opens a new episode.

Incoming rule/sample configuration is deployment-owned, not arbitrary agent SQL.
Baseline availability/threshold rules resolve declared UUIDs. Missing, stale,
failed or future samples create coverage findings; they do not establish health.
The Gatus adapter uses completed result timestamps, not response arrival time.
Minimal boolean/numeric evidence is separately queryable with expiry status;
15 days is the current access window. Physical evidence garbage collection and
operational metadata retention remain work, not claimed TTL enforcement.

## Authority

Static bearer credentials map to server-configured identity and role: reader,
producer, proposer, human or executor. A producer is bound to its exact source.
Payload actor/role fields confer no authority. Never give real human-role tokens
to agents. All tokens in the staged rehearsal identify synthetic test actors only.

The credential list is supplied as a **file**, `LO_PLATFORM_CREDENTIALS`, mounted by
Compose from `LO_PLATFORM_CREDENTIALS_FILE` at `/run/secrets/platform-credentials`.
It is never an environment value: environment values are visible in `docker inspect`
and in `/proc/<pid>/environ`. Compose bind-mounts a `secrets:` `file:` entry with its
host ownership and mode, it does not copy it — so the file must be readable by the
container UID (65532) and must not be world-readable to satisfy that. The container
fails closed if it cannot read it.

The webhook channel's bearer credential follows the same rule with one difference: it is
optional, and a Compose secret cannot be declared conditionally, so it is not a top-level
secret. The manifest fixes its container path at `LO_NOTIFY_TOKEN_FILE=/config/notify-token`,
which is the same read-only directory `actions.json` is mounted from. An install that only
records deliveries has no such file and boots unchanged; `LO_NOTIFICATION_MODE=live` with a
`LO_NOTIFY_URL` and no file fails the boot rather than serving a channel that cannot send.
Telegram's token already arrived as a file (`LO_TELEGRAM_CONFIG`).

A second channel follows the same shape with one indirection: `LO_NOTIFY_CHANNELS` names a
mounted JSON document, and each webhook entry in it names a `token_file`. The secret is a file;
the document holds its path, and no variable in the feature holds a value. That is one step
stricter than the rule above, and it is why nothing here needs an entry in the credential gate's
exception list. The manifest wires it without adding a mount of its own: the document and every file
it names — each entry's `token_file`, a Telegram entry's `config` — are staged inside
`LO_PLATFORM_POLICY_DIR`, which the manifest already bind-mounts read-only at `/config` with
`create_host_path: false`, so they arrive exactly as `actions.json` does (staged by the operator,
readable by the container UID, never writable by it), and `LO_NOTIFY_CHANNELS` itself carries only
that container path. The variable is unset by default, so a recording install never opens the
document; in `live` mode a value that names no staged file stops the boot, so a channel the operator
believes is configured can never be quietly absent.
A file with an ASCII control character in it, an empty one, or one over 4096
bytes is a boot refusal that names the channel and the key and repeats no contents.

The MCP tool surface has its own credential document, and it follows the webhook-channel shape
rather than the top-level-secret shape, because it is optional in exactly the same way:
`LO_MCP_IDENTITIES` names `/config/mcp-identities.json` — a file staged inside
`LO_PLATFORM_POLICY_DIR`, which the manifest already mounts read-only at `/config` beside
`actions.json` — so the manifest adds no mount, no `secrets:` entry and no new host path, and a
`create_host_path: false` missing-directory refusal is the failure that tells the operator the map
was not staged. The variable is blank by default (`${LO_MCP_IDENTITIES:-}`), **blank means "not
configured"** (the same reading `LO_OVERVIEW_PATH` gets), and an install that runs no MCP service
boots unchanged. Only the MCP entry point opens the file; the API factory above never reads the
variable. It is a JSON list of 1 to 32 rows, one per agent, and each row names exactly four keys —
`identity`, `role`, `bearer_token`, `platform_token`, with nothing optional: a fifth key is a refusal,
because a key the code does not read is a key the operator believes is configured. The document holds
every secret the surface has (at most 16 KiB of it), so it is mode 0600
and never world-readable: a bearer credential any local uid can read is a credential any local uid
holds. Four conditions refuse the boot and none of them prints a value: the map and
`LO_MCP_TOKEN_FILE` both set (one credential source, decided by the operator, never by a precedence
rule); the map empty, malformed, over its read budget, or holding a duplicate credential or a
repeated `identity`; a row whose
role is not one an agent may hold (`human`, `producer` and `summary` are refused — an MCP agent is not
a person, does not sign observations, and must not hold the portal's read of `/v1/overview`); or a
credential shorter than the platform's own 24-character floor. A `platform_token` that is
**well-formed but unknown** to `LO_PLATFORM_CREDENTIALS` is *not* caught at boot: the map is read
without opening the role credential file (which this process is not given), so the first request that
agent makes is answered `401` by the platform and reaches the client as a tool error, never as an
empty success. That is weaker than a boot refusal, and it is written here rather than smoothed over.
`LO_MCP_TOKEN` — the value form,
which this surface never reads — is refused on sight, as the notification mode's value form is.

## Agent tool surface

The platform answers MCP over **Streamable HTTP only** (`local_observe.platform.mcp:app_factory`,
`POST /mcp`, bearer credential required, no SSE stream and no stdio server — those remain open,
see the conformance checklist). What it exposes is a declared registry, not the platform's whole
HTTP surface: one read per existing API capability plus exactly one action pair.

**Reads, and the bound each one inherits.** `platform_status`, `platform_overview`, `records`,
`inventory` are the four tools v0.1 had. `records` keeps v0.1's own window — 1 to 20 rows, default 10 —
which is **narrower** than `Store.records`' 1..100 and than what the route will answer, and the six
table names are the tuple `Store.records` admits minus `notification_attempts`, so a table this surface
cannot name is a table an agent does not ask for. `inventory` returns exactly the
`{'rows': [...]}` document `GET /v1/inventory` gives a reader token — up to 100 declared resources with
`id`, `kind`, `name` and the portal's two display labels — reached with the agent's own token: the tool
adds no field and strips none, because the route carries none worth stripping (no path, no credential,
no evidence reference appears in it). `evidence_window` answers the platform's own three words —
`available`, `expired`, `unavailable` — and on `available` the stored sample, which
`Store.put_evidence` has already bounded at 2 KiB of canonical JSON before it was ever written
(`state.py`); the caller names a `source` and a `sample_id`, never a path.
`signal_series` reads one named signal (`metrics`, `logs`, `traces`) through the same analysis reader
`local_observe/platform/query.py` builds, filtered by resource/rule/metric/service/artifact, over 1 to
10,080 minutes ending now (default 60) — the facade's own one-week ceiling, so the surface never
refuses later what the facade would refuse first. Topology is read **only** as
`topology_neighbourhood`: one declared
resource UUID, one direction, 1 to 4 hops (2 by default — a bound this surface sets tighter than
`topology.MAX_DEPTH` of 32, because an agent that wants the whole graph is asking for a different
product), from the shipped `local_observe/topology.py`, and the walk's own `truncated_by` field is kept
in the answer so a short list never reads as a complete neighbourhood. An undeclared UUID is refused,
not answered as an empty neighbourhood: "nothing depends on this" and "this is not a resource" are
different answers and only one of them is data. `component_boundary` is the component graph, which the platform holds but
ships no route for; it answers for agents and stops being absent from the HTTP surface.

**One action pair, with trusted execution.** `propose_action` posts to `/v1/actions`.
`execute_action` requires the mounted `executor` role and requests a durable handoff for an
already approved action. The platform requires an allowlisted runner and exact human-reviewed
binding. It returns queue status, never a runner credential. The independent runner owns its
journal, claim, dispatch and outcome. Missing configuration refuses without consuming approval.
See [guided setup and trusted execution](../../../docs/units/guided-setup.md).

The registry first checks the role mounted in the identity map: `propose_action needs role proposer`,
`execute_action needs role executor`. These refusals also make no platform call
(`tests/test_platform_tools.py` counts the calls). The platform's own role gate remains unchanged and answers
`400 not_authorised` for a reader or a summary credential on either route, which is what an agent
holding a reader token hears if it skips the surface and posts at the API directly. Never a 404 that
hides the capability, and never a different answer per role. Nothing executes at proposal time. The
pair is one pair: no tool composes a target, a parameter document, an approval or a retry, and no tool
names a runner, a command, a DAG, a URL or a file.

**Provenance, in the answer.** Every read returns two content blocks: the platform's document
unchanged, then `{"provenance": {"query_type", "parameters", "window", "source", "read_at"}}` —
what was asked with which bounds, which signal and table or facade it came from, and when it was
read. A refusal carries its reason and no provenance, because a refusal read nothing. A result over
the 64 KiB budget the evidence read already enforces is replaced by a refusal naming what to
narrow, never truncated into looking complete.

**No runner credential reaches MCP.** The execution tool makes no claim, obtains no runner credential
or action parameter document, and returns no execution id. The Dagu runner receives its credential
directly from the platform and keeps it in its own journal; it is never handed to the agent.
`platform_token` and
`bearer_token` values are never in an answer, a tool description, an error message, an audit row or
the log. **An undeclared argument is refused before the handler runs**: an `actor`, an `identity` or a
`role` sent as tool input is a refusal that names the argument, not a field that gets dropped —
payload fields confer no authority (§5), and the identity an action is recorded against is the one the
bearer credential names, bound by the transport and never taken from the request.

**No free-form anything.** Every tool argument is a UUID, a label inside a bounded character class,
one of a fixed set of names, or a bounded integer. There is no SQL, no query string, no URL, no
path, no table selector beyond the six, no document-shaped parameter: an agent asks the platform to
read, and the platform decides what the store may be asked. The MCP surface can read nothing the
bearer's role could not already read from the API at the same bound, and it publishes no port of
its own.

**What an operator may add behind this registry, and what may not cross (agent delivery pipeline).** The registry is a
seam, and it is deliberately narrower than the tool surface the estate assistant this shape came from
runs. A downstream operator may register further tools **in their own tree** — the private read
backends are roughly eight modules there: the DNS/blocklist reader, the forge (pull requests and CI),
the secrets manager, host-exec, the deploy map, the dashboard reader, and the two or three adjacent
readers those pages cite. Each is a provider implementation behind an operator-owned credential, and
`components/control/platform` carries no service, no mount and no variable for any of them.

What may never cross into product code is not a style preference: estate host names and DNS suffixes,
LAN ranges, vault or secrets-manager paths, forge URLs and tokens, deploy-map contents, SSH targets,
remote-execution endpoints, and any tool that runs a command, opens a shell, accepts SQL, accepts a
URL, or reads a path the caller names. Product tools reach only the interfaces in this repository —
the platform API with the agent's own token, `local_observe/store/client.py`'s bounded analysis read,
`local_observe/topology.py`, the inventory snapshot — and `scripts/check_foundation.py` is what fails
the build when a hostname or a private path appears in the shipped tree. That boundary is why this row
is an adaptation and not a port: the ~2,300 lines of estate backends are the reason the product surface
is ten tools instead of thirty, and the passthrough answer above (`component_boundary`) is the honest
shape of every capability that stays outside it.

This branch does not add a `mcp` service to any Compose file in this repository; the surface is a
process an operator starts from a tree that has the optional `mcp` extra installed — **not** from the
platform image, which does not install it (see `Dockerfile` and MCP component's `components/control/mcp/`) —
with the map above mounted. Approval preservation, the
refusal table and the credential rules are verified by tests
(`tests/test_platform_tools.py`, `tests/test_mcp_surface.py`), not by a deployment — the bring-up
and teardown steps live in
[conformance.md](conformance.md) under "Agent tool surface and the private overlay (chat integration)" and stay
uncorroborated until someone runs them against a real installation.

Actions bind requester/retry key, open incident, incident event evidence, action
name/version, exact parameters, targets and expiry. The deployment allowlist checks
parameters against JSON Schema and requires current remediation_enabled=true on
every target. Claim rechecks policy and incident status. The only staged action
is inspect-synthetic with no parameters; no Dagu, shell or SSH job is dispatched.

Human decisions are single-use. Claiming requires approved/unexpired state and
atomically creates one execution. Executor identity plus a separate runner token
bind outcome reports. Service restart marks interrupted executions unknown.
Unknown is never redispatched; authenticated reconciliation records its outcome.
An executor success does not resolve an incident; detection verifies recovery.
Future Dagu integration must query actual runner state before reconciliation.

## Read and delivery APIs

GET /v1/status, /v1/records/{events,incidents,actions,executions,audit,outbox,
notification_attempts}, and /v1/evidence?source=...&sample_id=... require read-capable
identity. Record queries return at most 100 rows; runner/claim secrets are removed.
`GET /v1/audit` answers under the same read-capable gate and is the one **paged** audit
read this component ships : at most `limit` rows (default and maximum 100), at
most 500 audit positions consumed per request including the rows a filter rejected,
the whole body inside 64 KiB, and a row too wide to carry reported as
`{sequence, omitted: "row_exceeds_page_budget"}` instead of being dropped or truncated.
It runs on its own read-only (`mode=ro`) connection with a deferred read transaction and
takes no write lock, holds nothing between pages, and changes no record route, no limit
behaviour and no stored byte. That 100-row cap above belongs to the record routes and
still stands: this route is a second door to the same table, not a widened window, and
neither door is ever an authorization input. See
[docs/units/audit-reader.md](../../../docs/units/audit-reader.md).
The `audit` stream also carries `action.refused`: one append-only row per refused
action attempt (propose, decide, claim, outcome) and per summary-role write refusal whose
audit this app's dispatcher admitted (the shed ones below leave a counter and no row) —
that one recorded before the request body is read, so it is a role denial and never a
parser verdict — naming the attempt, a fixed reason word and the authenticated
identity, with a subject that is a canonical UUID or the literal `unbound`. Rows are
subject to the process-local write budget: a `dropped`, `failed` or `unauditable`
refusal is counted on `GET /v1/runtime` and writes no row. It records that the platform
declined — it changes no state, authorises nothing, and no token, body, URL or exception
text is stored in it. The write counters for that stream (`refusal_audit`, reported by
the serving process's runtime read) are per-process and reset on restart; the rows are
not. A burst of refusal rows shares the same newest-first 100-row record window as every
other audit row, so it can crowd older rows out of that view without deleting them; the
rows behind that window are reachable through `GET /v1/audit` above, whose
`category=action-transitions` set names only completed transitions and therefore never
reads a refusal as one. See
[docs/units/refusal-audit.md](../../../docs/units/refusal-audit.md).

Incident transitions enqueue notifications in the same transaction. Sends use
30-second leases, a stable delivery_id/Idempotency-Key, bounded exponential retry
and a five-attempt limit. A dead earlier delivery blocks later messages for that
incident until operator retry; it remains visible. A matching durable receiver
receipt is mandatory. Restricted-class events are refused until a channel policy
is explicitly implemented. Receiver acceptance is not proof of human receipt.

## Delivery and the approval callback

The process can hold more than one channel, and the channel names are the same in the
process, in the routing decision and in the budget tables: `outbox.channel` records which
channel a claim routed a delivery to, `notification_reservations` charges the send to that
channel, and `circuit:<channel>` latches that channel's breaker alone. Configuration is one
document (`LO_NOTIFY_CHANNELS`) in the operator's preference order: the first channel whose
budget admits the delivery carries it, so a latched channel stops sending without stopping the
alerting. Two adapters ship — the send-only Telegram bot client and the generic HTTPS webhook —
and both are constructed from mounted paths only. The legacy single-channel variables still
work and mean the same thing; a document entry that names a channel one of them already claimed
fails the boot rather than winning a precedence rule.

A finished attempt names its cause from a bounded set (`accepted`, `rejected`, `transport`,
`policy`) and nothing else: no response body, no endpoint, no provider text, no credential.
That is what makes "the channel was unreachable" readable after the fifth retry, and the
Telegram redaction rule — the bot credential rides in the request URL, so no failure detail is
ever kept — is exactly as strong as it was.

A human-channel send also mints one single-use approval code: 32 URL-safe bytes, stored only as
a SHA-256 digest on the delivery with an expiry (default one hour) and a consumed marker, handed
to the channel in a copy of the payload so the durable row keeps holding no secret, and replaced
by a new one on every retry. `POST /v1/callbacks/{channel}` spends it. The code travels in the
request body — never the path, never a query string. The identity recorded is the one the bearer
credential carries; a body naming an identity is refused, and a `reader` or `summary` token never
reaches the lookup. A wrong code, an unknown channel and a code minted for another channel all
answer the same 401, so the route is not an oracle for which channels exist. What a valid callback
writes is one `action.approval_intent` audit row against a pending action on the notified
incident: **the action does not move**, no execution is created, and the decision still requires
`/v1/actions/decision` under a human credential. Replay answers with a durable "already consumed"
refusal; an expired code with its own. Restricted events are refused on every channel — widening
that is an owner decision, not a delivery feature.

Delivery is at-least-once: lost acknowledgement can repeat a send. Receivers must
deduplicate delivery_id. The staged webhook sink is a test fixture, not a phone
channel and not an approval authority. Credentials never follow redirects.
HTTPS is required except explicit isolated-network HTTP overlays. No production
socket, estate data mount, AI model or Git forge is required to run the core.

Delivery mode is declared by the manifest, not inherited from a code default:
`LO_NOTIFICATION_MODE` is set explicitly and defaults to `recording`, where every
transition still writes its outbox row and attempt history but nothing leaves the
host. `live` is an explicit operator opt-in (`off` suppresses sends entirely).
An `LO_NOTIFICATION_POLICY` that declares `delivery_mode` must state the same value
or the platform refuses to start — the two declarations cannot disagree quietly.
The remaining optional inputs are documented in the manifest and unset by default:
`LO_NOTIFICATION_POLICY`, `LO_DISPLAY_CONFIG`, `LO_OVERVIEW_PATH`,
`LO_TELEGRAM_CONFIG` (honoured only in `live` mode, and never together with
`LO_NOTIFY_URL`), `LO_NOTIFY_CHANNELS` (also `live`-only: the document is not opened, and no
channel credential is read, when the mode cannot send), and `LO_MCP_IDENTITIES` (opened by the MCP
entry point only, never by the API factory; see "Agent tool surface"). The webhook credential for `LO_NOTIFY_URL`
is a mounted file, not one of
these variables: see the credential paragraph above.

The continuous detector persists its exact pending batch before intake and a
completed-window cursor after acknowledgement. It retries identical payloads
after restart. Its cursor volume is job state, not action authority. Independent
monitoring of detector/scheduler failure belongs to the P2 dead-man work item.

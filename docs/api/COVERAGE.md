# Capability census and API coverage

Four artifacts describe the same surface, and a test refuses the moment they disagree:

| Artifact | What it answers | Who reads it |
| --- | --- | --- |
| `docs/api/coverage.yaml` | What the product can do, on every surface, per operation. | A person deciding what to build or what is safe to call. |
| `docs/api/openapi.yaml` | How the HTTP part of that is spoken: paths, bodies, statuses, roles. | A client author, and the conformance test. |
| `docs/api/DECISIONS.md` | Why the boundary is shaped like this, and what would change it. | A reviewer who disagrees with one of the choices. |
| `local_observe/platform/api_contract.py` | The rules themselves: envelope, request id, idempotency, revision, paging, actor. | The next route handler, instead of a copy of the previous one. |

`tests/test_api_openapi_conformance.py` checks each pair — census against contract, contract against the
source that answers a socket, contract against the running app — `tests/test_api_contract.py` checks the
behaviour the contract promises, and `tests/test_api_surface_parity.py` checks the absences: a capability on
a non-HTTP surface must say *why* in one of the four words the census defines. None of them is a
documentation linter: each can fail in ways the others cannot see.

A capability with rules a table cannot carry gets its own page beside these four:
[`maintenance.md`](maintenance.md) states the planned-maintenance family in prose — which credential may
silence what, over which scope, for how long, what happens when the clocks change, which outcomes a window
can reach, and what a bounded historical read may and may not claim.
[`resources.md`](resources.md) does the same for the resource, query, rule and configuration family — which
artifact has to be mounted for an answer, what the two planes refuse to merge, which routes are dry runs and
what they therefore never touch. The census row and the OpenAPI operation still decide what exists; the page
says what they mean.
[`administration.md`](administration.md) does the same for the operator surface — health and the
declared boundary, the credential ledger and revocation, and the two state jobs an approval can book.

## Reading a row

One row is one operation. `operation_id` is the stable name — `resource.verb`, dotted by resource — and it
is what the OpenAPI `operationId`, a future client method and a milestone card all refer to. The path is
where the operation happens today, not where it should happen.

| Field | Meaning |
| --- | --- |
| `surface` | `http`, `cli`, `mcp` or `ui`: how a caller reaches the operation. The same capability usually has two rows (`/v1/events` and `lo-platform`'s producer path) and that duplication is the point — the surfaces drift. |
| `method` | `GET`/`POST` for HTTP, `run`/`read`/`tool`/`render`/`interact` elsewhere. A command that only prints is `read`; one that writes state is `run`. |
| `path` | A route, a command line, a tool name, or a view. `planned` is not a path: a planned row carries the path it proposes, and the transport answers `404` there today. |
| `resource` | The thing operated on (`occurrence`, `action`, `maintenance-window`, `credential`…). Grouping only — it carries no authority. |
| `module` | The file that decides the behaviour, checked to exist by the test. Not "the file that mentions it". |
| `access` | `read` or `write`, meaning *does this leave a durable trace*. A `read` row may still cost a database page. |
| `required_role` | On an HTTP row, the credential roles that may call it. On the others, the authority reached: `local` is the operator's own file access, `bearer` a mounted credential, `none` deliberately unauthenticated. |
| `side_effects` | What exists afterwards that did not before — rows, files, messages sent. `none` is a claim, and `state_source` is what backs it. |
| `state_source` | Which store or file answers the operation. `sqlite: api_idempotency (schema v11)` is checkable; "the database" is not. |
| `status` | `implemented`, `planned` or `excluded`. `excluded` needs a reason in `notes`, because "nobody thought of it" and "we refused it" must not look the same in five years. |
| `http_via` | On a non-HTTP row: the HTTP operations that already answer this capability, so the absence of a second route is a decision already kept rather than an unfinished one. Carries existing `operation_id`s, each of which must be `implemented` on both sides. |
| `no_http` | On a non-HTTP row, and instead of `http_via`: one reason from `vocabularies.exclusion_reasons` why no route may answer this. A row carries exactly one of the two fields, and the reason travels with a `notes` sentence saying what an operator does instead. See "Why a capability stays off HTTP". |
| `owner_area` | One of the six areas below — the unit a reviewer can hold in their head. |
| `contract` | `openapi` (this row owes an OpenAPI operation) or `none`. Omitted means `openapi` when the row is an HTTP row with a single addressable path. |
| `notes` | The judgement a schema cannot carry: bounds, why a refusal is worded that way, what would break. |

Four rows are `contract: none` and that is deliberate, not a gap. Three of them are HTTP rules that run over
every route rather than operations you can address — `foundation.request_identity.apply`,
`foundation.idempotent_write.apply` and `administration.write_via_summary`, the role gate across four
documented writes. The fourth is `resource.dataset.read`, the third-party Datasette/GraphQL reference app in
`local_observe/inventory/api.py`: its route shapes belong to Datasette and are not this product's contract —
and it is now `excluded`, because fronting it would mean fronting arbitrary queries over the observed dataset.
`administration.ui.shell` is the fifth, a `ui` row. The browser-side rows (`administration.ui.shell` and the
other `ui` rows) are renders over served assets; the assets themselves are HTTP rows and are documented.

## What is in the census

Counted from the file, so this table cannot drift from it silently:

| Owner area | Rows | Implemented | Planned | Excluded |
| --- | --- | --- | --- | --- |
| `foundation` — identity, health, the transport boundary | 11 | 10 | 1 | 0 |
| `occurrences` — events, incidents, escalation, acknowledgement | 17 | 14 | 2 | 1 |
| `maintenance` — declared windows, suppression, flap accounting | 17 | 16 | 0 | 1 |
COUNTS_TABLE_PLACEHOLDER

### Why so many CLI rows

The product ships as a service *and* as a set of commands, and the commands are how an operator does
anything the interface has no view for — migration, rehearsal, backup, conformance, the observer export.
They are also the only surface with no authentication layer, which is exactly why their rows say
`local`: the security property being claimed is "this needs a shell account on the machine", and a reader
must be able to audit that claim per operation rather than assume it.

### MCP tools

Nine rows. Every one of them reads, proposes or executes; none approves. `action.approve.mcp` is
`excluded` with its reason attached, and `occurrence.acknowledge.mcp` is excluded for the same reason:
`docs/CONTRACTS.md` §5 says a payload field cannot make an agent into a human, and a bearer token minted
for an agent is a payload field with extra steps.

## Why a capability stays off HTTP

Twenty-seven of the rows in `foundation` and `administration` are not routes. Each carries exactly one of two
fields, and `tests/test_api_surface_parity.py` fails the file if one is missing, if both are present, or if
the reason is a word the census does not define. The two fields answer two different questions, and the
difference is the point: `http_via` says *the absence of a second route has already been decided, and here is
the route that answers it*, while `no_http` says *no route may answer this*.

| Reason | What it rules out, and why a route cannot |
| --- | --- |
| `long_lived_process` | The capability *is* running a server. `administration.component.serve` and `.serve_operator` are this row: a route cannot start the process that answers it, and `GET /v1/health` is the read that says whether it did. |
| `offline_bootstrap` | It must work while the API is down — migration, staged upgrades, conformance, credential files for a machine that has never run this. Naming a route for it would teach an operator to reach for the wrong tool during the one incident where the right one matters. |
| `unvalidated_proxy` | It would hand a bearer token somebody else's shell, SQL, DDL or CI backend, unvalidated, which `docs/CONTRACTS.md` §5 forbids whatever the role. `administration.security_schema.apply` and `.runner.run` are this row. |
| `human_approval_only` | The capability's whole output is a human decision this surface may not cast. `administration.state.gate` is this row: a release gate reachable by a caller on the network is not a gate. |

Where the capability *is* reachable, `http_via` names the operations, and this is most of the surface: the
MCP tools each name the HTTP read they mirror, the operator UI rows name the static and session routes behind
them, and `administration.state.backup` — the CLI copy an operator names a destination for — now also names
`administration.state.backup_request`, the job an operator approves by digest. Two rows for one capability
with two address shapes is not duplication: the CLI form writes where it is told and needs no credential, and
the HTTP form writes beside the state file under a published naming rule and needs a human bearer. The plan
page spells out what each half is for: [`administration.md`](administration.md).

## Offline bootstrap and recovery

The operations that matter when the service is down are `cli` rows, because a route cannot be reached
through a broken service:

| Row | What it gives you |
| --- | --- |
| `administration.state.backup` | A new file through the online backup API, integrity-checked; an existing destination is never replaced. |
| `administration.state.migrate` | The pre-migration verified copy, then one audited transaction per schema step. An older file is refused until this has run. |
| `administration.state.upgrade_rehearsal` | A migrated copy of a copy — the live file is never opened for writing. |
| `administration.state.upgrade_drive`, `.upgrade_accept`, `.state.gate`, `.state.copy` | The staged upgrade path around the rehearsal: drive it, accept it, check the gate. |
| `administration.recovery.conformance` | A restore into scratch, proven by reading it back. This is the check that a backup is a backup. |
| `administration.backup.conformance` | The declared state manifest's coverage answer, measured rather than asserted. |
| `administration.migration.prepare`, `.migration.check` | The layout a migration needs, and the check that it holds. |
| `administration.anomaly.migrate`, `.security_schema.apply`, `.security_retention.verify` | The two schemas that arrived after v1 and the retention proof. |
| `administration.event.intake_offline` | Replay of a stored feed into a store that was not serving while it was collected. |
| `administration.credential.configure`, `.operator_account.create` | Getting a credential file and an operator account onto a machine that has never run this. |

Coverage here is deliberately about *verifiability*, not about files existing: the two conformance rows
and the rehearsal row are what turn "we have a backup" into a claim you can check. Two limits belong in
the same sentence. Nothing in this list is reachable over HTTP — a recovery path that needs the service
up is not a recovery path — and the census records the operation, not the operator's own schedule: which
of these run on a timer is a deployment fact and lives in the deployment overlay, not in this repository.

One thing in the list above is now partly reachable, and the split is worth stating exactly. `POST
/v1/state/backups` and `POST /v1/state/verifications` book the two jobs a *serving* process can perform with
its own privileges on its own file: a verified copy, and the restore-and-read proof of a copy this service
made (`administration.state.backup` carries `http_via` for both). What stays on the command line is every act
that needs a container runtime, a second host, another store's administrator credentials, secret material, or
a destination the caller names — and *restoring* a copy over the operational database, which is the step that
cannot be taken while the process holding the file is serving.

## The HTTP surface, read from the contract

* **Auth.** One opaque bearer token, `Authorization` exactly once, compared with `secrets.compare_digest`.
  A token is never taken from a query string, a cookie or a body field, and the retired
  `LO_PLATFORM_CREDENTIALS_JSON` environment form is a boot refusal rather than a fallback (a token in an
  environment value is visible in `docker inspect` and `/proc`).
* **Roles.** Six server-side roles plus `summary`, and `x-required-role` is the only place the answer is
  written. `summary` may call `/v1/me` and `/v1/overview` and is refused on every write before its body is
  read, so the refusal cannot be a parser or size verdict wearing a 403.
* **Two verbs.** `GET` reads, `POST` writes. Anything else is `405`.
* **Six transport refusals.** `401`, `403`, `404`, `405`, `413`, `500` are stated once in
  `x-transport-errors` rather than repeated under all OPERATION_COUNT operations, because they are produced by the
  dispatcher before any handler runs. Each one is proved answerable by
  `test_the_six_transport_refusals_are_all_answerable`, so the shared list cannot accrete a code this app
  never returns.
* **Two error shapes, on purpose.** Answers that existed before the shared boundary keep
  `{"error": "<code>", "detail": "<sentence>"}` byte for byte — installed clients and this repository's
  own tests assert them. Answers the boundary produces use
  `{"error": {"code", "message", "request_id"}}`. `X-Request-Id` is on every response, both shapes, so one
  id ties a caller's complaint to a server-side log line. Which shape a response uses is a fact about
  which constructor ran, and `api_contract.LEGACY_CODES` makes the split auditable.
* **`Idempotency-Key` is opt-in, and guarded by shape as well as by list.**
  `api.IDEMPOTENT_POST_ROUTES` names seven exact writes whose durable answer must survive a lost
  acknowledgement, and `api.idempotency_enabled` adds four families that address their writes with caller
  data a list cannot name: `/v1/intake/<source>`, the occurrence disposition writes, the maintenance family
  (`maintenance_api.writes`) and the resource, rule and configuration family (`resources_api.writes`). Same key plus the same canonical
  body replays the stored answer with `X-Idempotency-Replayed: true`; same key plus a different body is
  `409 idempotency_conflict` and nothing runs; a key still in flight is `409 request_in_progress`, never a
  wait. Only a 2xx is stored, records expire after 24 hours, and a key claimed by a process that died is
  released after 300 seconds. `tests/test_api_contract.py` checks all of that against the database rather
  than against a dict.
* **Conditional writes are a helper, not a route yet.** `expected_revision`/`check_revision` read
  `If-Match` (or one named body field), and a mismatch is `412 stale_revision` — `409` where a write had
  already begun. No shipped route takes an expectation yet; the planned occurrence and window rows do.
* **Bounded paging is a helper too.** `page_params` refuses rather than clamps (`limit=201` is a `400`, not
  a quiet 200), cursors are opaque base64url positions and a token this service never issued is refused so a
  typo cannot read as "no more rows". `page_payload` emits `next_cursor` only for a full page. The shipped
  read routes still use their own older bounds (`/v1/audit` with `snapshot`/`before`, `/v1/records/{table}`
  with a capped window) and the document describes those as they are.

## Gaps, stated plainly

* **A recorded disposition can be read and made, but not taken back.** `occurrence.dismiss.revoke` and
  `occurrence.disposition.projection.drain` are `planned`. The five routes that answer are
  `/v1/alert-occurrences{,/{id},/{id}/history}` and the two writes, and they hold up under restart, replay
  and a re-fire (`docs/api/occurrences.md`); what is missing is the backward step. A revoked dismissal is
  not on the list because a tombstone cannot be unsaid — only replaced, by the next episode — and a caller
  that wants to drain a stalled projection must reach for `dispositions.drain` in code.
* **A maintenance window cannot be declared by a caller.** `maintenance.window.declare.http` and
  `.revoke` are `planned`; `declare_window` is reachable from library code that holds a real human `Actor`,
  and `maintenance.window.declare_cli` is `excluded` because minting `Actor(identity, 'human')` from a
  command-line flag would claim a role the caller never proved. The bounds (`MAX_WINDOW_SECONDS`, refused
  at declaration *and* at every use) and the audit attestation already exist on both paths.
* **The contract is a shipped file, not a route.** `platform.openapi.read` is `planned`: publishing the
  route table to every caller that can reach the port is a decision of its own, with a size and a
  cache-invalidity question attached.
* **A booked copy is verified, not restored.** The two state jobs answer "does the artifact still hash to what
  the backup reported, and does a restore of it open and read under this build". They do not answer "is the
  deployment's own schedule covering this database" — that measurement needs the deployment's schedule, which
  is `administration.backup.conformance` and stays a `cli` row with `no_http: offline_bootstrap`.
* **A POST whose body matches no branch answers `404`, not `400`.** `action.decide`, `action.claim`,
  `action.execute`, `action.runner.claim`, `notification.retry`, `notification.callback.record` and the
  setup writes all fall through to `not_found` when the body does not carry the fields that branch tests
  for. It is the dispatcher's shape, it is documented in `x-transport-errors`, and it is ugly: a client
  that sends the wrong shape learns "no such route". Changing it to `400` is a compatibility decision, not
  a cleanup, because an installed caller may treat the `404` as "this build does not have the feature".
* **`POST /v1/executions/outcome` with a missing field is a 500.** The handler indexes
  `body['execution_id']` directly, so an incomplete outcome report is answered `internal_error`/`KeyError`
  and logged as a bug. It is logged correctly (class name out, traceback in the log, request id on both),
  and it is still the wrong status: it is the caller's error. Naming it here rather than quietly wrapping
  it, because the fix changes a status code a runner may be branching on.
* **Idempotency covers the seven listed writes and four shape-matched families, not every write.** A write
  outside them ignores the header, so a client that sends a key there gets no replay promise. Some of those routes have
  their own durable deduplication (`events` by `source_event_id`, verification records by digest, actions by
  `retry_key`) and say so in their rows; the ones that have neither are candidates for the list, not
  accidents.
* **Conformance probes one minimal request per operation.** It proves the contract admits what the app
  actually answers; it does not enumerate every field-level refusal. The handler-specific tests do that, and
  `docs/testing-standards.md` is where the tiers are defined.
* **`verification.*` roles are conditional.** The rows and `x-required-role` list `producer`, and
  `x-admits-producer-when` carries the condition: a producer is admitted only while a mounted verification
  policy names it. With no policy mounted, reads still answer and writes are a `503`.
* **The UI rows are a description of behaviour, not a test.** The browser gates
  (`scripts/check_approval_browser.py` and its siblings) are what actually assert the flows in those rows.

## Adding an operation

1. Add the census row first. If it does not fit the vocabularies, that is the finding — extend
   `vocabularies` in `coverage.yaml` and say why in `DECISIONS.md`. If the row is not an HTTP one and the
   capability is reachable over a route that already exists, say so with `http_via`; if it is not, pick a
   reason from `exclusion_reasons` and write the sentence that goes with it. An unannotated absence fails
   `tests/test_api_surface_parity.py`.
2. Give the OpenAPI operation the same `operationId`, path, method, `x-status` and role list. Roles are
   compared as sets and must match exactly.
3. Use `api_contract` for the answer: `ContractError` for a refusal, `page_params`/`page_payload` for a
   list, `expected_revision`/`check_revision` for a conditional write, `actor_context` for who acted. If a
   durable answer must survive a lost acknowledgement, add the path to `IDEMPOTENT_POST_ROUTES` — and say
   in the row what the replay promise is. A family whose writes are addressed by id cannot be named as a list
   of exact paths, so it may expose a matcher instead and `idempotency_enabled` consults it beside the list
   (`maintenance_api.writes` is that matcher for `/v1/maintenance-windows/…` and `/v1/maintenance-schedules/…`).
4. Run the gates: `.venv/bin/python -B -m unittest tests.test_api_openapi_conformance
   tests.test_api_contract`, then the base tier, `scripts/check_foundation.py` and the public-tree check.
5. If the operation changes a status code an existing client can receive, that is a compatibility
   decision for `DECISIONS.md`, not an edit to a test.

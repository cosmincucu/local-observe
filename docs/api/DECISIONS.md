# API decisions

Product-wide choices of record are the bullet list in [`docs/DECISIONS.md`](../DECISIONS.md); the normative
behaviour they assume is in [`docs/CONTRACTS.md`](../CONTRACTS.md). These are the API-surface decisions, in
the order they were taken, written so a reviewer can argue with one without reconstructing it. Each has a status, the pressure that produced it, what was chosen, and what it now costs
to keep. Nothing here is a rule about product behaviour that `docs/CONTRACTS.md` does not already state;
where it leans on one, the section is cited.

## D1 — The census is data; the prose is generated from it

**Status:** accepted, 2026-10-30.

`docs/api/coverage.yaml` holds one row per operation and `docs/api/COVERAGE.md` explains the columns. The
tables in that file are transcribed from the YAML, and `tests/test_api_openapi_conformance.py` re-checks the
properties the prose claims (every row complete, every vocabulary closed, every HTTP row that owes an
operation having exactly that operation, with the same roles and the same status).

A Markdown table alone would have gone stale in a month, and a hand-written list of "what we have" is
exactly the artifact nobody trusts during an incident. The vocabularies live in the file so a new value is a
change to the census before it is a change to a handler.

**Cost:** a route and a census row are now one change, and the test refuses the half of it.
`contract: none` exists for the four rows that are rules over routes rather than addressable operations, so
that they are counted without inventing paths for them.

## D2 — A machine envelope alongside the bodies that already shipped

**Status:** accepted, 2026-10-30.

`{"error": {"code", "message", "request_id"}}` is what new code answers with. The flat
`{"error": "<code>", "detail": "<sentence>"}` stays exactly as it is on every route that existed first —
`tests/test_api_errors.py` pins those bytes, and installed clients assert them.

The temptation was to normalise everything in one pass. Rejected for two reasons: a status/body change is
not visible to the caller as a cleanup, it is a broken branch in their error handling; and a blanket rewrite
would have put the interesting work (the boundary rules) in the same commit as two hundred unrelated test
edits. So compatibility is a fact about *which constructor a response used* — `legacy_error` or
`error_envelope` — and `api_contract.LEGACY_CODES` lists which codes still speak the old shape. The
conformance test asserts the envelope's code enum equals `ERROR_CATALOGUE` and the flat shape's equals
`LEGACY_CODES`, so neither list can drift from the document.

`X-Request-Id` is the one thing added to every response, including the legacy ones: a header an existing
client ignores is not a contract change, and without it a caller cannot tie their refusal to the log line
that explains it.

## D3 — Idempotency is durable, in the operational store, and opt-in per route

**Status:** accepted, 2026-10-30. schema v11.

An in-process dict would answer "run it again" to the exact caller whose acknowledgement was lost — the one
case the header exists for. So `api_idempotency (actor, key, request_sha256, reserved_at, completed_at,
status, payload)` was added through the repository's own migration mechanism rather than as a side file or a
cache, with the same `Store` transaction discipline as every other table. Keys are scoped to the principal
that claimed them, which is how `actions.retry_key` already works.

The rules the store enforces: same key plus the same *canonical* body replays the stored answer (a reformatted
retry is the same statement, not a second write); same key plus a different body is `409
idempotency_conflict` and nothing runs; a key still in flight is `409 request_in_progress` rather than a
queue, because waiting here is just a backlog of duplicate side effects; only a 2xx is stored, since
freezing a "no" would outlive the state that made it true; and an answer wider than the column's CHECK bound
is served and *not* stored, because a truncated replay would be a lie about a completed write.

Expiry is swept inside `idempotency_reserve`, bounded to 200 rows per call, so the table cannot grow for the
life of the file and no new scheduler enters the product. A claim older than 300 seconds belongs to a
process that died and is handed over — 300 seconds is longer than any write this platform performs.

**Cost:** one more schema step for every installation to migrate, and an allow-list (`IDEMPOTENT_POST_ROUTES`)
that a reviewer must keep honest — a route added to it silently gains a stored-answer promise.

## D4 — Roles are an extension, not OAuth scopes

**Status:** accepted, 2026-10-30.

`x-required-role` lists the server-assigned roles that may call an operation. The standard field for
authorisation in OpenAPI is `securitySchemes.oauth2.scopes` (or an `oidc`/`jwt` bearer format), and this
product has no scope grant to describe: a bearer token *is* one of six identities with one role, decided by
the mounted credential file, and the body may not choose it (`docs/CONTRACTS.md` §5). Modelling roles as
scopes would imply a token that could hold a subset of them, which is not the system this is.

Where the answer is conditional, a second extension says so rather than lying in the role list:
`x-admits-producer-when` on the verification routes records that a producer is admitted only while a mounted
verification policy names it. The role list stays the set that *can* be admitted; the extension carries the
condition, and both artifacts must agree because the test compares them as sets.

## D5 — Proposed operations live in the same document, marked

**Status:** accepted, 2026-10-30.

`x-status: planned` marks operations the document proposes and the transport does not serve:
`GET /v1/openapi.json`, `POST /v1/alert-occurrences/{id}/dismissal-revocation`,
`GET`/`POST /v1/maintenance/windows`, `POST /v1/maintenance/windows/revoke`. The occurrence operation is the
backward step: the five routes that make and read a disposition are `x-status: implemented`, and the census
row for it carries the `planned:` prefix on its gap id so the family is not double-counted as served.
The projection drain is planned on the other side of the boundary — `surface: cli`, `contract: none` —
because a drain belongs beside `lo-platform escalate` and not in a request handler.

The alternative — a separate proposals file — reads more honestly but stops being checked, and an
unchecked proposal becomes a guess with a URL. Keeping them here means the same rules apply: a planned row
and its planned operation must agree, `test_a_planned_operation_answers_only_with_not_found` proves the app
still refuses them (with a credential; without one it gets the `401` it would get anywhere), and a planned
operation whose description does not say what is missing fails.

`tests/test_api_contract.py` is where the boundary a planned route depends on is already tested, so the
milestone that serves those routes is wiring, not invention.

## D6 — FastAPI and Pydantic are the planned HTTP direction; the server is not converted now

**Status:** proposed direction, 2026-10-30. Conversion requires the spike below to pass.

`local_observe/platform/api.py` is a hand-written ASGI callable: about a thousand lines of dispatch, with
every response body, status and refusal sentence chosen explicitly at its call site. It is not a framework's
mistake — it is what makes a fifteen-year-old compatibility surface auditable, and it has no dependencies
beyond the standard library on the serving path. It also has real costs: the 404-instead-of-400 fall-through
documented in `COVERAGE.md`, no machine-readable route table other than the file this milestone wrote, and a
request-validation rule that exists once per handler.

FastAPI (with Pydantic for request and response models) is the direction for *new* HTTP surface, because it
buys exactly the three things the census showed missing: routing with declared shapes, a generated contract,
and validation errors that do not need a hand-written sentence each. It is not adopted by declaration: a
framework earns its place here by passing a spike, not by being popular.

**Spike criteria — all six must hold before any route is converted:**

1. **Byte-identical compatibility.** Mount the *existing* app and one FastAPI router in the same process, and
   show that every pinned response in `tests/test_api_errors.py`,
   `tests/test_platform_api_intake.py`, `tests/test_verification_api.py` and
   `tests/test_observer_review_api.py` still matches byte for byte — including key order and the flat error
   shape, and including the `X-Request-Id` this milestone added.
2. **The contract stops being hand-kept.** Generate `openapi.json` from the mounted routes and show the
   diff against `docs/api/openapi.yaml` reduces to the extensions (`x-status`, `x-required-role`,
   `x-transport-errors`) plus the `cli`/`mcp`/`ui` surface that generation cannot know. If generation
   disagrees, generation is wrong until proven otherwise: the hand-written file has a test asserting it
   matches the running app, and the conformance test stays in force either way.
3. **The refusal vocabulary survives.** `api_contract.ContractError` must still answer the envelope with the
   catalogue's code and no added field, and a framework's own 422 must be translated into
   `invalid_request`/`error_envelope` rather than shipped — Pydantic's default error body leaks field
   values, which is the rule `api.py` already holds for a 500.
4. **Auth stays single-path.** One bearer, `Authorization` exactly once, `secrets.compare_digest`, no
   second token check in a dependency layer, and the `summary` gate still answering before the body is read.
   A dependency that reads the body to decide the role fails this criterion.
5. **Bounds stay ours, and stay bounded.** 64 KiB refused by the chunk that crosses it, 256 bytes of query
   before parsing, the bounded page helper still refusing rather than clamping, and the startup path still
   refusing to serve a route table it did not opt into.
6. **Cost measured on the reference deployment.** Pinned versions in the dependency manifest with a reason,
   a lockfile change and a rollback procedure; import time, first-request latency, RSS delta and image size
   recorded before and after; no new transitive package that reaches the network at import; the offline and
   air-gapped installs still working from the pinned set alone.

**Order if it passes.** Convert nothing that exists. Serve one *new* route family (the planned
`/v1/occurrences/*`) through the framework side by side, keep the census, roles and envelope shared, and
leave the existing routes to a separate decision made with that deployment's numbers in hand. The
`verification_api` and `observer_review` seams stay hand-written until their own contracts move, because
their refusal vocabularies are exact and their tests are the reason.

**Why not the alternatives.** Staying hand-written forever keeps the 404 fall-through and the per-handler
validation duplication, and makes the contract file the only machine-readable description — a file that must
be edited by hand forever. `connexion`/OpenAPI-first (server from the document) inverts the direction of
truth in a way that is hard to undo for a surface this old, and gives less control over exact bytes than a
router-level framework. Starlette alone would be honest but buys little over what is already here: it is the
routing layer, not validation, and the validation layer is the reason to look at Pydantic.

## D7 — The contract ships as a file; serving it is a separate decision

**Status:** accepted, 2026-10-30. `platform.openapi.read` is `planned`.

`docs/api/openapi.yaml` is a shipped artifact of the repository, reviewed in a diff and read without a
running service. `GET /v1/openapi.json` would publish the route table to anything that can reach the port,
which is a disclosure decision of its own — and it needs an answer about size, caching and what a caller
does when the served document and the installed build disagree. Neither is answered yet, so the route is not
served and the document says so.

## D8 — Two paging shapes, one rule

**Status:** accepted, 2026-10-30.

`api_contract.page_params`/`page_payload` give new routes `limit` plus an opaque `cursor`. The shipped read
routes keep their own older bounds: `/v1/audit` reads a snapshot and continues below a sequence,
`/v1/records/{table}` returns a capped newest-first window, `/v1/inventory` caps at 100 rows. The document
describes what is served, not what is preferred.

What is *not* duplicated is the rule underneath them: refuse rather than clamp, and never let a short answer
imply absence. `/v1/audit` states `scanned`; a truncated query says which bound cut it off; the helper emits
no `next_cursor` on a short page. Migrating the old routes onto the helper would change their query strings,
which is a client-visible change with no client benefit — so it stays a decision rather than a cleanup.

## D9 — A body that names an actor is refused, not ignored

**Status:** accepted, 2026-10-30.

`assert_no_actor_claim` refuses a top-level field from a closed list (`actor`, `identity`, `role`, `token`,
`impersonate`, and ten more) on every route that opted into the boundary. `Store` already refuses an
actor whose role does not fit the operation, so ignoring the field would have been safe — and would have
made `docs/CONTRACTS.md` §5 ("a payload field cannot claim that an agent is a human") false in the one place
a caller could test it. A refusal is legible; an ignored field teaches callers that it works sometimes.

The refusal counts the offending fields and never names them, so the answer cannot be used to probe which
spellings this module knows. Nested documents are not policed: the point is who acted, not what the payload
holds, and every body field this platform reads is already a closed shape.

## D10 — Request identity is offered, not trusted

**Status:** accepted, 2026-10-30.

A caller's `x-request-id` is reused only when exactly one well-formed value arrived; two headers, an unsafe
character or an over-long value get a fresh UUID. The reason is the log line: an id that two requests share
is worse than no id, and a value that cannot be echoed safely would land in a structured field and in a
response header. This is the same rule the credential and the idempotency key already follow — ambiguity is
the caller's to fix, never this process's to arbitrate.

## D11 — No new runtime dependency for this milestone

**Status:** accepted, 2026-10-30.

`api_contract.py` imports the standard library, `canonical` from the inventory validator, and four bound constants plus the `Actor` type
from `.state`. No framework, no schema library, no sibling transport module: `api.py` imports it at module
scope, so anything it needed would join every request's critical path and every optional-service install.

`PyYAML` was already a product dependency (deployment profiles), and `jsonschema` was already pinned in
`requirements-test-base.txt`, so the census, the contract and the conformance test needed nothing new. The
one runtime artifact the milestone did add — the `api_idempotency` table — arrived as migration v11 through
`state.MIGRATIONS`, with the pre-migration verified copy that every other step gets.

## D12 — Admitted investigation work is a job in the observer's journal, not a task in the platform process

**Status:** accepted, 2026-10-30.

A cycle takes minutes and an export walks the retained evidence, so neither runs inside a request. The
route records the ask and answers `202` with a job; `POST /v1/observer/runs` admits a cycle that the
observer process later claims (`lo-observer drain`), and `POST /v1/observer/exports` admits one this
service starts itself, because its work is a journal read and one file write.

The queue is a `platform_jobs` table in the **observer journal**, not a table in the operational store, and
that is the part a reviewer will be asked about. An investigation cycle may only run where the journal's
exclusive lock, the process's main thread and the protected model route already are — `observer/runtime.py`
refuses to run a cycle on any other thread outright — so a queue the API process owned would describe work
its owner cannot perform, and a claimer would have to reach across two databases to take a job. Living in
the journal also keeps this off `state.VERSION`: no migration step, no `tests/test_state_migration.py` pin,
and the table arrives by `CREATE TABLE IF NOT EXISTS` on first use, which is exactly how
`observer/delivery.py`'s session table arrived. The cost is the one every shared file pays: two processes
now hold facts about the same rows, and the rules below exist because of it.

- **Admission is not execution.** A `202` whose job stays `accepted` until a drainer arrives is honest, and
  says so in the body (`note`) and in the operation description. A caller that needs the cycle now runs the
  CLI it already runs.
- **One worker identity per process.** A claimer names itself (`os-uid:<uid>:<token>` for the CLI,
  `platform-<hex>` for this service) and only that claimer may close the row, so a dead service's work is
  left as evidence rather than reported as success by a process that never saw it.
- **A stalled job is judged, not resumed.** A `running` row nobody reported on for `JOB_STALE_SECONDS`
  becomes `unknown` at the head of the next read; its `finished_at` is the instant this process stopped
  believing the row described live work, never an instant somebody saw the work stop. Nothing retries it:
  a second investigation cycle is an external effect nobody authorised.
- **A running job cannot be withdrawn.** The `409` names the only thing that ends it — the cycle's own
  deadline — because a platform-side kill would leave a half-written journal and a claim nobody released.

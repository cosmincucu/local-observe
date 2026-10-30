# The operator surface: health, credentials, state jobs

Three questions an operator or an agent asks before it can act on anything else, and one it asks afterwards:

* **Is this installation wired the way I think?** `GET /v1/health` says what is served, what is off *by
  choice*, and what is absent because nothing this process could do would add it.
* **Is the thing I cannot find a gap or a decision?** `GET /v1/boundary` is the list of capabilities this
  product declines, with the owner of each.
* **Who may call this installation, and who does it now refuse?** `/v1/credentials`, and one write that cuts
  a bearer durably.
* **What did I ask it to do with its own database, and did it work?** `/v1/state`, the plan behind it, the two
  job requests, and `/v1/jobs`.

Everything here runs with the privileges the service already has, on the file it already holds open. Nothing
here can be reached with a new authority: no route mints a credential, opens a port, names a file, or runs a
command. That is the whole boundary of what was added, and the routes that would have crossed it are named in
[COVERAGE.md](COVERAGE.md) with a reason attached.

| Question this page answers | Section |
| --- | --- |
| What can I call, and with which credential? | [Routes](#routes) |
| What do the capability words mean? | [Health](#health-what-supported-does-not-mean-working) |
| How do I cut a leaked token? | [The credential ledger](#the-credential-ledger), [Revocation](#revocation) |
| How do I back that database up from here? | [The state lifecycle](#the-state-lifecycle-in-five-calls) |
| What does a job state mean, and what is `unknown`? | [Job states](#job-states) |
| What is deliberately not reachable over HTTP? | [Limitations](#limitations) |

## Prerequisites

* A platform database at **schema v14**. The v13→v14 step adds `platform_jobs` and
  `credential_revocations`; a database at v13 is *refused* by this build until
  `lo-platform --database <path> migrate` has run (`local_observe/platform/README.md`, `docs/CONTRACTS.md` §5).
  Nothing in this family rewrites an existing row.
* A **`reader`**, `proposer`, `human` or `executor` credential for the two reads anyone credentialed may make
  (`/v1/health`, `/v1/boundary`). A `summary` credential is refused on every route in this family, including
  the reads: it exists to see findings, not the shape of the installation holding them.
* A **`human`** credential for everything else in this page. The credential ledger, the state surface, the
  ledger of jobs and all four writes are `human`-only — the same rule the disposition and maintenance writes
  follow, because each of these can end a silence, cut a bearer, or make the service copy its own database.
  `producer` may not reach any of it: a detector that could read who is revoked could schedule its own
  revocation.
* Nothing optional. `/v1/health` answers over a bare app the same way it answers over a mounted one; it
  reports the difference rather than requiring it.

## Routes

| Method | Path | Credential | What it answers |
| --- | --- | --- | --- |
| `GET` | `/v1/health` | reader, proposer, human, executor | Each capability as `supported`, `disabled` or `unavailable`, with the evidence that decided it, plus what this endpoint cannot see. |
| `GET` | `/v1/boundary` | reader, proposer, human, executor | The declared refusals and who owns each — the same document the `component_boundary` MCP tool answers with. |
| `GET` | `/v1/credentials` | human | Identity, role and state of every mounted credential, joined to the durable revocations. Never token material. |
| `GET` | `/v1/credentials/{identity}` | human | One row. An identity nobody mounted answers `404` with the same bytes as a typo of one that is. |
| `POST` | `/v1/credentials/{identity}/revocations` | human | Refuse that bearer from the next request, durably. `reason` is required. `Idempotency-Key` honoured. |
| `GET` | `/v1/state` | human | The schema the file is at, every job state including the zeros, how many bearers are refused, the last backup, and the digest a copy request will demand. |
| `GET` | `/v1/state/backup-plan` | human | The plan one copy would carry, and its digest. Derived on every read, never stored. |
| `POST` | `/v1/state/backups` | human | Book a verified copy. `202` with a job id and no receipt. `Idempotency-Key` honoured. |
| `POST` | `/v1/state/verifications` | human | Book the restore-and-read check of one backup, addressed by **job id**. `202`. `Idempotency-Key` honoured. |
| `GET` | `/v1/jobs` | human | One bounded page, newest first. `limit` and `cursor` only; every other query key is `400 invalid_pagination`. |
| `GET` | `/v1/jobs/{job_id}` | human | One job: state, receipt, and for a backup whether anyone has ever verified its artifact. |
| `POST` | `/v1/jobs/{job_id}/cancellations` | human | Withdraw a booking that has not started. An empty JSON object as the body; `Idempotency-Key` honoured. |

Every write is signed by the credential, never by the body: `approved_by` and `revoked_by` in an answer are
the actor the server authenticated, and a body carrying `actor`, `identity`, `role`, `requested_by`,
`approved_by` or `revoked_by` is refused `400 actor_claim_refused` before anything is read. An unknown field
in any of these bodies is refused too, naming the fields the route does accept — a `dry_run`, a `destination`
or a retention period spelled another way would otherwise be a silent gap between what you asked and what ran.

## Health: what `supported` does not mean

Three words, because one word would force a guess:

* **`supported`** — wired into this process, and reachable from where it stands.
* **`disabled`** — this deployment chose not to. `delivery: disabled` means `delivery_mode: off`: nothing is
  broken, nothing will start by itself.
* **`unavailable`** — what it needs is absent and no choice of this process could add it. `delivery:
  unavailable` means the mode says `live` and no sender was configured: the pager will not go out, and the
  fix is on the host.

Each entry carries `evidence`, which is the fact rather than a restatement of the word. The only *judgment* in
the body is the schema: `Store` refuses to open a file whose version this build does not understand, so a
served answer always means code and file agree. Everything else is reported without a verdict, because "the
delivery loop has faulted 40 times" is a signal and "unhealthy" would be an opinion nobody defined — the
counts live in `/v1/status`, the volatile process counters in `/v1/runtime`, and `see_also` says so instead of
answering the same question twice from two places.

`not_measured` is the honest half: this endpoint cannot see another process on the host, cannot know whether
the operator's own backup schedule ran, and cannot reach a notification channel to test it. An installer who
reads `supported` on every line and has no backup is the failure that list exists to prevent.

## The credential ledger

The rows are the mounted role list this process was handed — projected from the credentials the request was
authenticated against, not re-read from disk, so this route is not a second place that opens a mounted secret
file — joined to the durable revocations in `credential_revocations`. No answer in this family contains token
material on any route; `tests/test_administration_api.py` asserts the absence rather than trusting the intent.

Enrollment is not here, and not because nobody thought of it: the mounted file is the only statement of who may
call, `administration.credential.configure` stays a `cli` row with `no_http: offline_bootstrap`, and a route
that wrote grants would be a route that could widen one.

## Revocation

`POST /v1/credentials/{identity}/revocations` writes one deny-list row and its audit row in the same
transaction. Enforcement is one read-only lookup by primary key, run *after* a bearer matches, on every
authenticated request — a revoked identity is refused `401 authentication_required`, byte-identical to an
unknown token, so the ledger cannot be probed to learn who has been cut. The read is `mode=ro` on purpose:
the write lock is not taken per request, so a bookkeeping lookup never serialises the API behind itself.

Three refusals worth knowing before an incident:

* `404` for an identity this installation never mounted. There is nothing to revoke, and no route can revoke a
  name the mount does not carry.
* `400` for a missing, blank, multi-line or over-400-character reason. The record has to be readable by the
  next shift rather than merely present.
* `409` for an identity already revoked, under a *different* `Idempotency-Key`. The same key replays the first
  revocation with `X-Idempotency-Replayed: true` and spends no second audit row.

There is no un-revoke route. A surface that could restore a revoked bearer is a surface that could hand back a
leaked token, and the fix for a wrong revocation is re-enrollment by whoever holds the role file — an
deliberately offline act, which is what makes it safe to be the recovery path. An identity mounted twice (two
bearers, one name) is revoked as one unit because the mount names no finer reference; per-token control is an
edit of that file.

Revocation is durable and cross-process: it lives in the database, not in a token cache, so a revoked bearer
fails on its next call *and* on the next instance that opens the file. `tests/test_api_only_lifecycle.py`
drives exactly that sequence over HTTP with no CLI in the loop.

## The state lifecycle, in five calls

```text
GET  /v1/state                      → schema version, job tallies, plan.digest
GET  /v1/state/backup-plan          → the same plan, if you want it on its own
POST /v1/state/backups              {approval: <digest>}          → 202 {job_id, state: accepted}
GET  /v1/jobs/<job_id>              → …state: succeeded, receipt: {artifact, bytes, sha256, integrity}
POST /v1/state/verifications        {backup_job: <job_id>, approval: <verification digest>} → 202
GET  /v1/jobs/<backup job_id>       → verification.state: succeeded
```

**The plan is derived, never stored.** There is no plan row to expire, adopt or race: the server recomputes the
same binding when the write arrives and compares it with the digest in the body. The digest covers the version
the copy comes from, the version it must open at, the artifact naming rule and the fact that an existing
destination is never replaced — so an upgrade makes every earlier approval fail `412 stale_revision` rather
than quietly starting to mean something else. An approval that names anything else `412`s and books **nothing**:
no row, no audit entry, no file.

**A booking answers `202` with a job id and no receipt,** because the copy has not happened. `accepted` means
the platform wrote down that it promised, which survives a restart; whether it finished is
`GET /v1/jobs/{job_id}`. The job runs on the thread the delivery loop already uses, *after* the page work of
each iteration — a state copy never sits in front of an alert — and one job is claimed per tick, because two
concurrent copies of one database is corruption rather than throughput.

**The artifact is addressed by job id, never by path.** No route in this family accepts or returns a path:
`ARTIFACT_NAME` forbids `/` in the one receipt field that names a file, and a verification resolves its
artifact from the receipt this service wrote for the job it was given. A copy lands beside the state file under
the published rule, and the answer names the file and reports its size, sha256 and `integrity_check` result.
The bytes leave by the operator's own file access, because this transport carries no state dump — one that did
would hand any bearer a copy of every audit row and approval in the deployment.

**A backup is proved by being read back, twice.** `Store.backup` refuses an existing destination and
integrity-checks the copy; this build then *opens* the copy and counts it (which is what proves it is a
platform database and not merely a readable file) and reports the sha256. A verification then copies the
artifact into a scratch file over SQLite's backup API on a connection that cannot write the artifact, opens and
counts the scratch, and removes it — along with the copy a migration took of it, whose path the migrator
reports rather than this job guessing at. A scratch file that could not be removed is reported in the receipt,
not hidden.

## Job states

`accepted` → `running` → one of `succeeded`, `failed`, `cancelled`, or `unknown`.

* **`accepted`** is a promise on the file. It survives a restart, and the next process's loop picks it up. An
  app served *without* running the lifespan leaves jobs in this state indefinitely — the word means "this
  process has not reached it yet", not "it is lost".
* **`running`** is a claim: one guarded `UPDATE` moved the row, so a second process cannot run the same copy.
  A copy already in flight is **not interruptible** — `POST /v1/jobs/{id}/cancellations` answers `409` rather
  than setting a flag some later code might honour, because the flag would be a promise about work already
  happening.
* **`cancelled`** is only reachable from `accepted`, and it is a withdrawal, not an outcome.
* **`failed`** carries a receipt with one of this module's own sentences (`SAFE_FAILURES`) — the artifact is
  gone, it no longer hashes to what the backup reported, it arrived with an un-recovered `-wal` sidecar — or,
  for anything else, the exception *class*. SQLite and OS messages name files, and an answer repeating one has
  told a caller the deployment layout it was never handed. The traceback goes to the log, where somebody with
  the host can read it.
* **`unknown`** is a job whose process died holding it. `recover()` marks those rows at startup and the ledger
  reports them, with `unknown: 0` in `/v1/state` saying so out loud when there are none. `succeeded` would be a
  durability claim nobody observed and `failed` would discard a copy that may exist; reconciling an `unknown`
  means reading the state directory or booking a fresh job, which is an act with its own row rather than a
  guess made here.

## Limitations

* **`accepted` needs a running loop.** Jobs are executed by this process's delivery loop and nothing else: no
  scheduler, no worker pool, no second queue. A deployment that cannot let a state copy delay the next
  delivery attempt by its own duration takes its copies with `lo-platform backup`, off-service.
* **The copy lands beside the file it protects.** That is recovery from a bad migration, not from a lost
  volume, and the plan says so in `destination`. The CLI form names its own destination and stays the one that
  survives a dead disk; `administration.state.backup` carries `http_via` for the job without pretending the
  two are the same act.
* **No restore over the operational database.** Applying a backup is the step that cannot happen while the
  process holds the file: it is `lo-platform migrate`'s sibling work on a stopped service, and it stays a
  `cli` row (`no_http: offline_bootstrap`). What the HTTP job answers is narrower and still worth having: does
  this artifact still hash to what the backup reported, and does a restore of it open and read under this build.
* **Two job kinds, and no way to add a third from a request.** `state.backup` and `state.backup_verification`
  are the whole vocabulary — `state.PLATFORM_JOB_KINDS` is the schema's `CHECK` as well as this page's list. No
  callable, command, query, path or URL enters from a body. A `state.schema_rehearsal` job was considered and
  dropped: the live store is already at `VERSION`, so a copy of it applies zero migrations and the rehearsal
  would be a false claim; `scripts/upgrade_rehearsal.py` needs a candidate container image, which is
  `offline_bootstrap`.
* **`GET /v1/openapi.json` is still `planned`.** Serving the contract publishes the route table to every caller
  that can reach the port; `docs/api/DECISIONS.md` D7 does not leave that open, and this page does not decide it.
* **No un-revoke, no re-enroll, no `dry_run`.** Each is a route that would widen an authority or pretend to
  book work it did not book. `docs/api/COVERAGE.md` carries the exclusion vocabulary that says which routes are
  refused for which reason.

## Errors

| Status | Code | When |
| --- | --- | --- |
| `400` | `invalid_request` | A digest that is not 64 hex characters, a missing or unprintable revocation reason, a body field the route does not read, a filter key on a list. |
| `400` | `actor_claim_refused` | A body naming who it thinks sent it. |
| `400` | `invalid_pagination` | Any `/v1/jobs` query key but `limit` and `cursor`, a limit over the ceiling, a cursor this service never issued. |
| `401` | `authentication_required` | No or wrong bearer — and the same bytes for a revoked one. |
| `403` | `not_authorised`, `summary_only` | A credential whose role may not reach this family; a `summary` bearer is turned away before routing. |
| `404` | `not_found` | A malformed id and an absent one answer alike: these routes are not oracles for identifier shape. |
| `409` | `conflict` | A revocation that already exists, a cancellation of a `running` or settled job, a verification of a job with no artifact yet. |
| `412` | `stale_revision` | An approval that does not name the plan this database would run now. Read the plan again. |
| `413` | `body_too_large` | A write body over the shared limit, answered by the dispatcher. |

Two error shapes coexist here as elsewhere: `ContractError` answers
`{"error": {"code", "message", "request_id"}}`, and a `Store` refusal keeps the flat
`{"error": "<code>", "detail": "<sentence>"}` byte-for-byte from before the shared boundary existed. Which
constructor ran decides which you get (`api_contract.LEGACY_CODES`).

## Where the rules live

`local_observe/platform/administration.py` holds the durable half — the plans, the ledger, the state machine,
the executors, the revocations — so the CLI, a worker and a test reach the same rules the transport does.
`local_observe/platform/administration_api.py` holds the paths, the role gates and the refusals that are this
family's own. `tools.boundary_document()` is shared with the MCP tool so one list of refusals has two
transports. The tests are `tests/test_administration_api.py` (every refusal, the executors, the bounds),
`tests/test_api_only_lifecycle.py` (the operator session and the two restart words), and
`tests/test_api_surface_parity.py` (why the rest of the area stays off HTTP).

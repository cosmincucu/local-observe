# Unit: verification records (`platform/verification_records.py` + the two v4 tables)

**File(s):** `local_observe/platform/verification_records.py` (policy, capture, submission, judgement,
reads), `local_observe/platform/state.py` (`Store.verification_policy`, the proposal-time capture inside
`propose_action`, the three delegating methods, `MIGRATIONS[4]`).
**Tests:** `tests/test_verification_records.py` and `tests/test_verification_records_migration.py`, plus
the current-table-set fixture in `tests/test_state_migration.py`. **Item:** the verification workflow's first coherent
storage slice. Contracts only: nothing here reports a test result, a suite outcome or a deployment.

## Purpose

`platform/verification.py` computes `cleared`/`not_cleared`/`unknown` and files it as one four-field
evidence row, which is why the threshold, the rule, the window and the reason behind a verdict were not
readable back (see [verification](verification.md), "Evidence truth"). This unit is the durable record
that gap named: the binding an action was proposed against, the observation a verifier submits about the
execution that action started, and the verdict this server derives from both.

This unit owns storage and server-side judgement. The separate [policy loader](verification-policy.md)
mounts reviewed authority; the [HTTP API](verification-api.md), [operator CLI](verification-cli.md)
and execution UI expose saved records. The [follower](verification-follower.md) adds one automatic
post-terminal observation through that same write surface. Candidate discovery is a separate
read-only helper; it changes neither these tables nor their write contract. No component here
resolves incidents, redispatches actions or enables a deployment merely by being installed.

The one claim it does make and the one it refuses to make are worth stating plainly:

* **made** — a stored record is immutable, attributable, scoped to one reviewed detector revision, and
  readable after a restart, a policy change or a backup/restore round trip;
* **refused** — that a remote read actually happened. Verifiers are **trusted for actual observation and
  completeness**: every check below is a consistency check against a reviewed definition, and a complete,
  bounded, mutually consistent set of claimed samples is still a claim. `unknown` means *this server could
  not derive an answer from what it was given*; it never means a verifier lied, and `cleared` never means
  the platform itself measured the signal.

## Public API

- `VerificationPolicy(document)` — validates and defensively snapshots a plain parsed dict. `verifiers`
  (immutable tuple), `mappings` (fresh copies), `allows(identity)`. Every bound is a refusal; nothing is
  clamped, defaulted or guessed.
- `Store(..., verification_policy=None)` — accepts `None` or a `VerificationPolicy`, validated **before**
  the file is opened; anything else (a bare dict included) is a `StateError`. Default is off.
- `Store.get_verification_binding(action_id, actor) -> dict` — `{action_id, status, reason, binding_id,
  origin}` and nothing else. `bound`/`matched` carries a SHA-256 `binding_id` and the captured mapping
  plus `event_id` and `action_targets`; `unbound` carries a captured reason with `binding_id` and `origin`
  null; an action with no stored row is `unbound`/`not-captured`. An unknown action is a refusal.
- `Store.put_verification(record, actor, *, now=None) -> dict` — `{verification_id, created}`. No caller
  verdict, threshold or reason field is accepted, or stored.
- `Store.get_verification(verification_id, actor) -> dict | None` — the whole stored document, re-parsed
  from stored text into a fresh copy on every call.

Every failure on every one of these surfaces is a `StateError` carrying one fixed sentence that names a
field, a bound or a piece of platform state — never the offending value. `inventory.timestamp`'s
`InvalidInventory` is converted, so a caller has one class to catch. This module's reads are exact
single-object lookups. The separate [verification reader](verification-reader.md) discovers at most
64 result IDs for one execution; both tables remain **outside** the `Store.records()` allowlist. Where an HTTP
caller reaches any of these, it reaches this method and nothing beside it: the route adds no fourth method, no
second validation and no second authority test, and it inherits these reads' transaction semantics as written —
a binding and a single record are read through the existing `Store` transaction machinery, which carries **no**
read-only-connection or read-only-filesystem promise; ID discovery and the separate candidate scan use dedicated read-only connections.

## Default off, and what "off" means exactly

With no policy mounted, `propose_action` never touches `verification_bindings` (the capture is one
`if self.verification_policy is not None:` guard deep — which is what lets the tests that simulate a
pre-v4 build keep proposing unchanged), every `put_verification` is refused with
`Verification policy is not configured; verification records cannot be written`, and both reads answer
from stored state only. Off is write-off, not read-off: an action bound while a policy was mounted still
reads `bound` with its captured origin after the policy is removed, because a binding is a statement about
the proposal, not about today's configuration. Since the verification API an unmounted-policy write attempt answers `503
verification_unavailable` at the route instead of a misleading "you are not allowed": the deployment refuses,
not the caller's identity.

`VERSION` 4 refuses an actual v3 file at `Store.__init__` until explicit migration. A v4 header does
not prove the tables are intact: both new reads and writes refuse an incomplete verification schema,
never reporting missing tables as missing records. The old-schema simulation tests still exercise the
unchanged lifecycle with policy off; those proposals do not query either new table.

## The policy document

`{schema_version, verifiers, mappings}` and nothing else. `schema_version` is strictly the integer `1`
(`1.0`, `True` and `"1"` are refusals); 1..32 distinct verifier identity labels (`state.label`);
0..64 mappings; the whole canonical UTF-8 document at most 65 536 bytes, measured on the caller's bytes
before normalisation. Unknown keys, non-JSON objects, NaN/infinity, booleans where a number belongs,
integers past signed-64 and structures deeper than eight levels are refusals. Validation bounds each
container to 64 items before traversing it and the whole document to 4,096 nodes before serialization.

Each mapping has exactly these twelve keys, all required:

| key | bound | why it is not optional |
| :-- | :-- | :-- |
| `source`, `rule_id`, `rule_version`, `condition` | `state.label` | together with `resource_id` these are the selector of one detector revision |
| `resource_id` | canonical UUID | a declared resource, never a hostname or a prose name |
| `query_type` | exactly `metric-threshold` | the only signal this repo can re-read as a number; a log/trace origin is refused at the policy, not mounted and answering `unknown` forever |
| `parameters` | exactly `resource_id` + `rule_id` + `artifact_sha256`, each equal to its own mapping field | the scope a receipt is compared against; stating the scope twice and requiring agreement is what stops a mapping scoping its read somewhere else |
| `metric_name` | `state.label` | the series the verdict is about (`Origin` may be built without one as a pure re-grader; a policy entry may not) |
| `threshold` | finite number, not a bool, float-normalised | so `90` and `90.0` cannot fork one binding digest |
| `comparison` | `lt`, `le`, `gt`, `ge`, `eq` | the vocabulary `verification.COMPARISONS` already has |
| `window_seconds` | int 60..86 400, not a bool | the only window length a submitted window may be |
| `artifact_sha256` | **required**, lowercase 64 hex | a missing historical detector pin is never guessed: the pin is what makes the reviewed SQL that fired the alert the same SQL a later reader reauthorises |

Two mappings sharing `(source, rule_id, rule_version, condition, resource_id)` are refused **even when
their thresholds differ**: there can be only one reviewed numeric meaning for an exact detector revision,
and a binding would otherwise have to pick one and cannot. The policy is treated as immutable — mutating
the caller's original dict or list, or an accessor's result, cannot change what it means.

## The binding, captured at proposal time

Inside `propose_action`'s existing transaction, after the existing action/evidence validation and before
the `action.proposed` audit row:

1. the action's `targets` must be exactly one canonical resource id, or the result is
   `unbound`/`unsupported-targets` — no rejection, no guessed partial binding;
2. only the immutable events this action explicitly cited are read (never "the newest event for this
   resource", which would let a signal arriving afterwards decide what the proposal meant);
3. an event matches a mapping when `source`, `rule_id`, `rule_version`, `condition` and `resource_id` are
   equal, the resource equals the action's single target, the event is `firing`, and it carries a
   reference whose `source` equals the event's own source, whose `query_type` equals the mapping's and
   whose `parameters` equal the mapping's — pin included, where "the pin is missing" is not "matches";
4. exactly one distinct `(event, mapping)` pair binds; zero is `origin-unmatched`, two or more is
   `origin-ambiguous`;
5. a bound result stores the complete normalized mapping plus `event_id` and `action_targets`, and digests
   that canonical origin into `binding_id`. A bound **or** explicit unbound result is persisted.

The action's stored payload and its approval fingerprint do not change, so an approval still covers
exactly what the proposer sent. A retried proposal returns its first result without rebinding; claims,
outcomes and recovery never bind, rebind, infer or backfill; nothing backfills history. The tables have
`BEFORE UPDATE`/`BEFORE DELETE` triggers, so "the binding cannot move" is a property of the file rather
than of this module's discipline.

## The submitted record and the server's judgement

`{execution_id, binding_id, window, outcome, receipt, samples}` and nothing else. Canonical UTF-8 of the
incoming record at most 32 768 bytes; `execution_id` a canonical UUID; `binding_id` lowercase SHA-256;
`window` exactly `{start,end}` aware timestamps normalized with `utc_text`; `outcome` one of
`available`/`unavailable`/`expired` — read-outcome **words**, not fields of a receipt.

`receipt` is null or exactly `ReadReceipt.as_dict()`'s six fields (`query_type`, `parameters`, `window`,
`expires_at`, `sample_count`, `truncated`), with `sample_count` 0..10 000 (non-bool), `truncated` strictly
a boolean and expiry later than its window end. A null receipt is admitted only with `unavailable` and no
rows; `unavailable`/`expired` never carry rows; more rows than the claimed count is refused. `samples` is
at most 20 rows of exactly `{resource_id, metric_name, observed_at, value}`, stamps inside `[start,end)`,
`value` a finite float-normalised number, not a bool.

**Scope before verdict.** The receipt's query kind, approved parameters and window must equal the captured
origin's and the submitted window's, the samples' resource and metric must equal the captured origin's,
the window must be exactly the captured `window_seconds` long, and `start < end <= now` on the **server's**
aware clock (`None` is the real UTC clock; a naive or non-datetime `now` is refused). All of that is a
refusal for every outcome — filing an `unknown` about a differently scoped read would let an unrelated page
become the durable answer about this execution. The execution and its stored binding are read in the same
write transaction; the binding must be `bound` and equal the id named; an `executing` execution is refused;
`succeeded`/`failed` are proved terminal states; nothing here overwrites an execution, action or incident.

Then the verdict, in this precedence and never out of it:

| # | condition | verdict / reason |
| :-- | :-- | :-- |
| 1 | execution status is `unknown` (it may still be running) | `unknown` / `execution-boundary-unknown` |
| 2 | `start < execution.updated_at` (equal is allowed) | `unknown` / `pre-execution-window` |
| 3 | no receipt, or the outcome is `unavailable`/`expired` | `unknown` / `store-unanswered` |
| 4 | receipt expiry `<= now` | `unknown` / `evidence-expired` |
| 5 | `receipt.truncated` | `unknown` / `evidence-truncated` |
| 6 | `receipt.sample_count > len(samples)` | `unknown` / `evidence-incomplete` |
| 7 | no samples | `unknown` / `window-empty` |
| 8 | newest sample instant `<= updated_at` (the deciding rows must be strictly after the boundary) | `unknown` / `pre-execution-sample` |
| 9 | every value at the newest instant satisfies the captured comparison | `cleared` / `comparison-satisfied` |
| 9 | any of them fails | `not_cleared` / `comparison-failed` |

At 9 the record stores the deciding value — the one least favourable to `cleared`, the same rule
`verification.check` applies (largest for `lt`/`le`, smallest for `gt`/`ge`, furthest from the line for
`eq`) — and that instant. Earlier samples never override a later one. Every accepted `unknown` and every
definitive result keeps the receipt and all bounded samples; an `unknown` stores no value and no instant,
because an unanswered question must not leave a number behind that reads like an answer.

## Identity, retries and the cap

The logical id is `digest([execution_id, binding_id, normalized window])` — deliberately excluding every
output field (receipt, value, actor, verdict, reason, status), so one check has one id whatever produced
it. The canonical normalized incoming statement is hashed separately as the fingerprint.

* same id, same fingerprint → `created: false`, the stored row and its `recorded_by` unchanged, **no audit
  row** — even after the evidence aged out or the execution was reconciled to `unknown`; authority and
  scope are still checked before a retry is accepted, but an accepted statement is never re-graded by a
  later clock or status;
* same id, different content (outcome, receipt, a sample value) → `Verification retry changed contents`;
* a later, different window is a legitimate separate check with its own id;
* two different currently authorised producers submitting identical bytes identify one check, and the
  original recorder stays recorded;
* at most 64 first-write records per execution; exact retries stay admissible at the cap and the 65th new
  window is refused.

`verification_id` is the primary key and the id `Store.get_verification` takes, so the duplicate rule and
the single-object read share one mechanism. One `BEGIN IMMEDIATE` covers the execution lookup, the
binding check, the duplicate check, the cap and the insert, which is what makes the retry answer true
under concurrency rather than merely intended.

## Authority

| surface | admitted |
| :-- | :-- |
| `put_verification` | `Actor` with role `producer` **and** an identity in the *current* policy's `verifiers`. A random producer, an executor/runner, a human, a proposer, a reader and anything that is not an `Actor` are refused. No policy mounted → every write refused. |
| `get_verification`, `get_verification_binding` | `reader`, `human`, `proposer`, `executor`; `producer` only while the current policy names it. `summary` and malformed actors are refused **before** the database is opened. |

No new role, no new token, no new credential vocabulary, and no HTTP route **in this slice** — the transport
that calls these gates arrived later , delegates to exactly these two helpers, and widens neither
([verification api](verification-api.md)). The [verification CLI](verification-cli.md) sits behind that transport
as a caller and nothing else: it carries a bearer credential read from `--token-file` to those same routes, holds
no role test of its own and derives no verdict locally.

## Audit, and what stays unaudited

A successful **first** write adds one `verification.recorded` audit row whose subject is the
`verification_id` and whose detail is only `{verdict, reason}` — no payload, no sample, no receipt, no
path. A duplicate replay and a conflict add nothing. These surfaces sit **outside** the four-action
refusal-audit boundary on purpose: a verification submission is not an action attempt, so no
`action.refused` row is written and nothing in `refusals.ATTEMPTS`/`REASONS` moved. The cost is stated
rather than hidden: a refused verification submission is durable nowhere — the caller receives a
`StateError`, not an audit row. The HTTP surface maps those `StateError` sentences to fixed route statuses and
fixed bodies, and it still writes no extra audit row for a verification submission.

## Schema v4 and what it does not change

`MIGRATIONS[4]` creates both tables in one audited step, using the existing explicit `migrate=True`
backup/transaction/audit mechanism. No migration touches 1..3, and no column of `actions`, `executions`
or `incidents` is widened — a verdict must not be able to overwrite the runner's own outcome, so the
judgement sits beside the lifecycle.

* `verification_bindings(action_id PRIMARY KEY REFERENCES actions(id), status, reason, binding_id, origin,
  captured_at)` with a `CHECK` admitting only `bound`+`matched`+origin-or-unbound+one of the three captured
  words, and append-only triggers. The primary key *is* the "one proposal, one binding" rule; `not-captured`
  is un-storable because it means "no row exists".
* `verification_records(verification_id PRIMARY KEY, execution_id REFERENCES executions(id), fingerprint,
  payload, verdict, reason, recorded_by, recorded_at)` with an execution lookup index, a 64 KiB payload
  bound, the three-word `verdict` `CHECK`, and append-only triggers. The stored document's canonical
  UTF-8 size is enforced in code before `INSERT` as well as in SQL.

`Store.records()` gains nothing, `Store.status()` keeps its fields (with `schema_version` now 4), and
`Store.audit_page()`'s category vocabulary
gains nothing (`verification.recorded` is reachable only under `category=all`), nothing prunes either table
and nothing here deletes on expiry. `Store.backup()` and `deployment/state_copy.py::copy_state` copy both
tables with the rest of the file, as they already copy the whole database; the pre-migration copy is the
rollback, as it is for every other step.

## Limitations (none of them fixed quietly)

* **Service wiring and a thin client exist; integration does not.** The loader is read at startup ,
  four exact routes call these methods, and the verification CLI adds the HTTP-only [verification CLI](verification-cli.md),
  which makes at most one request per invocation over those routes and never opens this database locally. Still
  absent: a portal field, a scheduler, and any client durable-retry integration — that CLI persists nothing, so
  an unanswered `submit` stays an open question for an operator to inspect and re-send by hand, never an automatic
  replay. Do not call this end-to-end delivery, and do not read it as evidence-only
  fallback: `verification.py` still files only its evidence row.
* **Trust, not proof** — see Purpose. A verifier that lies consistently about a real-looking window with a
  real-looking receipt and 20 plausible rows is stored as `cleared`.
* **No re-grading and no repair.** A record is never updated, corrected or deleted, so an error accepted
  under a policy stays in the table for the life of the file (bounded by 64 per execution).
* **`unbound` is not "not verifiable in principle"**, only "this action did not bind to one reviewed
  meaning at proposal time" — and `not-captured` is a third thing again (no row at all).
* The 64-record cap, the 20-row excerpt, the 10 000 claimed-row bound, the 32 KiB submission and the
  64 KiB stored document are this unit's bounds and are stated as numbers, not tuned per deployment.

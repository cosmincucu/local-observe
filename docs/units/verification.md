# Unit: post-action verification (`platform/verification.py`)

**File:** `local_observe/platform/verification.py`. **Tests:** `tests/test_verification.py` and
`tests/test_action_invariants.py`. This is remediation invariants's original evidence-only evaluator.
The platform separately provides [durable records](verification-records.md), the
[HTTP operator CLI](verification-cli.md), and saved verification history in the execution UI.
Cards #75/#123 add an opt-in [follower](verification-follower.md) that submits observations
against captured action bindings. Deployment and live verification remain separate work.
The refusal audit's [durable refusal audit](refusal-audit.md) is closed.

## Purpose

After a remediation has run, answer the one question that decides whether the incident may recover:
**did the signal that paged for it stop firing?** The answer is exactly one of `cleared`,
`not_cleared`, `unknown`. The unit exists because `docs/CONTRACTS.md` §5 says *"Verification after
execution determines incident recovery; process exit zero alone does not"* — a runner reporting
`succeeded` says a process finished, not that the condition ended.

**This module remains evidence-only.** It reads, judges, files one evidence sample and logs one
line. With no `LO_VERIFY_CONFIG`, it logs one `INFO` line and exits 0 without opening a connection.
Its `tick()` and `python -m local_observe.platform.verification` entry point are unchanged.
The separate follower writes execution-linked observations through the platform HTTP service;
the existing CLI and saved-history UI read those records. Neither path resolves incidents or
redispatches actions.

## The invariants, in words

The same list, with the enforcing test beside each item, is the module docstring of `verification.py`.
Lifecycle invariants are tested in `tests/test_action_invariants.py`, verdict invariants in
`tests/test_verification.py`.

1. A principal whose credential is not a `human` role cannot approve an action — including one its own
   kind proposed — and a body or header field can never claim a role the token does not carry. This is
   the whole of what `docs/CONTRACTS.md` §5 requires of the approver: *"Human identity is obtained from
   authenticated transport; payload fields cannot claim that an agent is a human. Read tokens cannot
   approve or execute."* §5 does **not** require two distinct humans, and `legacy:aiops/remediation` never
   did either — its `Policy.evaluate`/`validate_approver` and `ApprovalQueue.approve` reject **agent**
   approvers by kind, not humans who proposed. So a human credential may propose and approve one action,
   and the control that exists instead of an invented rule is attribution: `actions.requester` and
   `actions.decided_by` are both durable and the audit row names the approver
   (`test_a_human_who_proposed_may_approve_and_both_sides_are_durable`). Do not read that test as an
   approval-policy claim: it is a firewall-and-forensics pin.
2. Approval expiry blocks a **new** dispatch and never interrupts a **running** execution.
3. One action is claimed once; a second claim is refused while it runs and after it finishes.
4. A runner proves itself with the token it was given, from the identity that claimed it.
5. An interrupted execution is reconciled to `unknown` by observation; nothing is re-dispatched.
6. A `succeeded` outcome leaves the incident open. Only a resolved event closes it.
7. Dagu is an executor, not a source of remediation approval: no approved claim, no dispatch.
8. A mechanically successful run whose signal is still outside its threshold is `not_cleared`, and a
   signal that cannot be evaluated is `unknown` — **never** `cleared`.

## Public API

- `Origin(rule_id, resource_id, metric_name, threshold, comparison, window_seconds, artifact_sha256=None)`
  — a recheckable description of what fired, validated at construction: bad UUID, non-finite threshold,
  unsupported comparison, out-of-range window or an unbounded name is a `ConfigError`, never an
  `unknown`. The threshold is normalised to a float so a binding cannot fork on how a number was spelled.
  `read_parameters` is the approved-parameter set one read of this origin must carry, and it is the only
  spelling of that scope (the request and the receipt check share it).
- `check(origin, sample, threshold=None, comparison=None) -> Verdict` — **pure judging**: no store, no
  network, no clock. `sample` is a store `ReadOutcome` (preferred), one `MetricSample`, a sequence of
  them, or `None`. `threshold`/`comparison` re-grade that same sample, and the verdict's
  `origin_binding` then names the **effective** condition actually used, not the configured one.
- `read_sample(store, origin, *, now=None) -> ReadOutcome` — **the only I/O in the unit**: the named
  `metric-threshold` read of `local_observe/store/client.py`, scoped to one declared resource and one
  series. The store's answer is returned untouched, `unavailable` included. A `StoreRefused` propagates:
  a read that never happened produces no verdict and no evidence.
- `verify(store, origin, *, now=None, outcome=None) -> Verdict` — sample then judge, both steps visible
  at the call site. `outcome` grades a read already held, and this is where the clock lives: the reused
  read must be exactly the read this origin would have asked for at the instant being judged, else
  `window-mismatch`. **The instant being judged defaults to the real aware UTC clock** (`_now`), never to
  the reused receipt's own window end — a receipt that names the instant it is judged at certifies its own
  freshness. To verify history, pass that historical `now` explicitly, or use `check()` and let the
  verdict speak about the window it names. A `now` that is not an aware `datetime` is a `ConfigError`:
  a clock is caller configuration, not source data.
- `evidence_sample(verdict, *, subject=None) -> dict` — the four-key sample `Store.put_evidence` accepts.
  It takes **the verdict and nothing else**, so nobody can file a verdict against a definition other than
  the one it was made from.
- `record_evidence(store, sample, actor, *, now=None)` / `post_evidence(platform, sample)` — the two
  filing paths: in-process `put_evidence`, and `POST /v1/evidence` for a worker (the platform service is
  the single state writer, so the worker never opens the database itself).
- `tick(store, platform, origin, *, now=None) -> (Verdict, delivered)` — one round: read, judge, file,
  log one `INFO` line.
- `main()` — `python -m local_observe.platform.verification`; one round per invocation.
- `VERDICTS`, `COMPARISONS`, `UNVERIFIABLE_REASONS`, `ConfigError` — the closed vocabularies.

## Configuration

`LO_VERIFY_CONFIG` names one JSON file. **Absent or blank is the off switch**: one `INFO` line naming the
variable, exit 0, no connection, no read, no write. A file that is named but unreadable or unparseable is
a refusal and exit 1 — a check that fell back to defaults would report on a signal nobody pointed it at.

| key | required | bounds | what it does · what happens if it is wrong |
| :-- | :-- | :-- | :-- |
| `rule_id` | yes | `state.label` — `[A-Za-z0-9_.:-]{1,128}` | the evidence parameter a reader reauthorises later; refused at load |
| `resource_id` | yes | canonical UUID | scopes the read to one declared resource; refused at load |
| `metric_name` | **yes** | `state.label` | names the series that paged. `Origin` can be built without one (a pure re-grader may lack it) and then every verdict is `selector-missing` — "some number this resource reports is low" is not evidence that the metric which paged recovered |
| `threshold` | yes | finite number, not a bool | the line the value is judged against; refused at load |
| `comparison` | yes | `lt`, `le`, `gt`, `ge`, `eq` | which way round the judgement goes; refused at load |
| `window_seconds` | yes | 60…86 400 | how far back the re-check reads; refused outside it (the facade caps a receipt at 7 days) |
| `artifact_sha256` | no | 64 hex | cites a reviewed artifact; refused if malformed |

Nothing else is accepted: an unknown key is a refusal naming the key, so a typo cannot silently run a
different check than the one that was meant to be configured.

**Exit codes:** `0` when a verdict was reached *and* filed — including an honest `unknown` from a read
that answered "nothing in this window" — and `1` when the check could not be performed at all (unreadable
configuration, no store credential, a transport failure, or evidence the platform refused). `1` is never
a `not_cleared`: a still-firing signal is an answer, not a failure.

## The three verdicts

| verdict | code path | what it means |
| :-- | :-- | :-- |
| `cleared` | `check()`: rows of *this* series, *this* resource, inside *their* receipt's window, and **every** value at their newest instant satisfies `comparison` vs `threshold`, on a receipt that is this origin's read and is not truncated | the originating signal stopped firing — recovery becomes *statable*; closing the incident stays intake's decision about a resolved event |
| `not_cleared` | the same, with at least one value at the newest instant violating it | the run finished and the condition is still there |
| `unknown` | any of the twelve reasons below, or `verify()`'s window check | this unit could not tell, and says so instead of guessing |

`unknown` is reachable only through `UNVERIFIABLE_REASONS`, spelled once:

| reason | the situation |
| :-- | :-- |
| `selector-missing` | the origin does not name the series to re-check |
| `threshold-unusable` | no usable threshold (a re-grade override only — a configured one cannot be unusable) |
| `comparison-unsupported` | a comparison outside the five (a re-grade override only) |
| `sample-missing` | `sample` is `None`: nothing was sampled |
| `store-unanswered` | the read itself refused: `unavailable` or `expired` |
| `window-empty` | the read answered and carried no rows |
| `sample-off-origin` | rows arrived, but none is the declared series of the declared resource |
| `sample-not-numeric` | the newest value is missing, a bool or a string — or the rows are not metric readings at all (log/trace rows, dicts, objects) |
| `sample-not-finite` | the newest value is NaN, an infinity, or too large to be a float |
| `row-outside-window` | a row carries no usable ISO-8601 instant, or one outside the receipt's half-open window |
| `receipt-unusable` | the read is not this origin's read (other query kind, approved parameters that are not exactly `resource_id` + `rule_id` (+ the pinned `artifact_sha256`), unreadable expiry) **or its page was truncated** |
| `window-mismatch` | a reused `ReadOutcome` is not the read this origin would have asked for at the instant being judged — which is the real UTC clock unless `verify` was given another |

`test_every_unknown_names_a_documented_reason_and_every_reason_is_reachable` asserts that set in **both**
directions — every `unknown` produced names one of these, and each one is reachable by a listed input —
and `_unknown()` raises for a reason outside the set, so a thirteenth path cannot be added quietly. A
separate matrix test covers the opposite failure: a supported comparison over usable samples never decays
into `unknown` by accident.

## Why a receipt is distrusted as hard as a missing sample

The first version of this unit answered `cleared` — or raised straight through the verdict function — in
eight situations where the evidence had nothing to do with the alert: five found on the first review, and
three more on the correction pass (the unpinned receipt, the self-certifying clock, and the reused read
judged at no clock at all). Each is a test now (`FalseClearanceTests`, `ClockTests`), because each one is
a false recovery:

| the case | what it would have caused | the rule now |
| :-- | :-- | :-- |
| a sample of another `resource_id` | one host's healthy reading clears another host's page | the receipt must carry the origin's `resource_id` and `rule_id`; rows belonging elsewhere are `sample-off-origin` |
| a sample of another metric, newer than the alert's own last point | a healthy unrelated series replaces the sick one at the newest instant | rows are used only when their metric name equals the origin's `metric_name`; the newest point **of that series** decides |
| no `metric_name` configured | "some number this resource reports is low" read as recovery | `metric_name` is required of the worker; a hand-built origin without it is `selector-missing` |
| a truncated receipt | the metric statement is `ORDER BY s.unix_milli ASC` under a row cap, so a cut page of a rising series holds the *early low* points and is **missing** the firing ones | a truncated receipt is always `receipt-unusable` |
| a stale row, or a reused read from an older window | last week's recovery reported as this week's | every row must fall inside its receipt's half-open window (`row-outside-window`), and `verify(outcome=…)` must be handed the window this origin would have asked for **at the instant being judged, which is the real clock by default** (`window-mismatch`) |
| a receipt that carries none of the `artifact_sha256` the origin pinned | an ordinary unpinned read standing in for the reviewed rule the verdict claims to be about | the receipt's approved parameters must equal `Origin.read_parameters` exactly, in both directions: missing is not matching, and an extra hash means a differently scoped read |
| a reused read judged at no clock at all | the receipt chose its own evaluation instant, so any old page was eternally fresh | `verify` defaults to the real aware UTC clock (`_now`); a historical replay names its `now`, and `check()` — which has no clock — is the honest way to grade an old window |
| a log row, an undatable stamp, a value too large for a float | an exception escaping a verdict function — a crash where a refusal belongs | bad **data** is `unknown` with a named reason; only bad **configuration** (including a bad `now`) raises |

`check()` has no clock, and that limit is stated rather than papered over: it cannot tell a fresh read
from a three-week-old one, because freshness is a fact about the instant of asking, not about the sample.
`verify()` owns the clock and **uses the real one unless told otherwise** — the pure unit's own
``"no clock"`` claim is what makes re-grading history possible, and `verify()` refuses to let that
convenience turn into an unqualified present-tense claim. `check()` also cannot attest where rows came
from, so a verdict judged from a bare sequence carries no window and `evidence_sample()` refuses to file
it.

## Behavior worth knowing

* **Sampling and judging are separate on purpose.** `check()` is reproducible from the sample it names,
  with no store and no clock; `read_sample()` judges nothing. Re-grade an old answer with `check()`.
* **The newest instant of the originating series decides.** Not averaged, not majority-voted. Where
  several points of that series share the instant, the one least favourable to `cleared` is the one
  filed (`lt`/`le` by the largest, `gt`/`ge` by the smallest, `eq` by the point furthest from the
  threshold).
* **A poisoned newest sample is never stepped over.** A NaN or a bool at the newest instant of that
  series is `unknown`, not an invitation to fall back to the previous point — reaching back for a
  comfortable reading is how a live alert looks recovered. Unrelated rows are not "stepped over"; they
  were never this signal.
* **`ok` in the evidence row is the store's answer, not the verdict.** A `not_cleared` verdict files
  `ok=True` with the number that failed; `ok=False` with `value=None` means "we asked, and the store had
  nothing". Reading `ok` as "cleared" is a misreading of this unit.
* **The worker never opens the state database.** The platform service is the single writer (it holds the
  exclusive owner lock in its lifespan), so `main()` files through `POST /v1/evidence` with a producer
  credential, exactly as the detector and anomaly workers do.

## Evidence truth — what actually survives

`Store.put_evidence` keeps four fields and this unit adds no others, so what a reader can recover from a
filed verdict is:

* the **verdict word** — `verify.cleared` / `verify.not_cleared` / `verify.unknown`, in `sample_id`;
* the **value** the verdict was made on;
* the **window end**, as `observed_at`;
* **whether the store answered**, as `ok`.

The threshold, comparison, rule, series, full window and the `unknown` **reason** are **not** readable
back: they are inputs to a 32-hex digest inside `sample_id`, which re-derives only for someone who
already has them. The digest is a check, not a recovery — invert it and there is nothing. So "the verdict
is reproducible" means *the same read re-derives the same answer*, not *the evidence row can be read back
into a verdict*. `test_only_four_fields_survive_the_evidence_path_and_that_is_the_honest_claim` pins
exactly which fields survive, so no later reader or writer can claim more without changing `state.py`.

The separate [verification records](verification-records.md) unit closes that storage gap with
two append-only tables introduced in schema v4. It retains the captured action binding and the
submitted observation, including the server-derived verdict, reason and deciding sample.
The [CLI](verification-cli.md) and execution UI already expose saved history. The opt-in
[follower](verification-follower.md) supplies one automatic post-terminal observation per
eligible execution through HTTP. These records do not widen this module's four-field evidence
contract or turn its own `tick()` into an execution follower.

## No new durable state and no new backup mechanism — the backup rule still applies

What this section establishes is narrow: **no NEW runtime backup surface is added here**, and the
platform's existing backup still covers everything this unit writes. The verdict is filed in the existing
`evidence` table on the existing 15-day horizon (`store.client.EVIDENCE_RETENTION_DAYS` mirrors
`put_evidence`'s own stamp), so this unit moves no schema of its own and ships no `MIGRATIONS` entry, no
new file or service holds state, and the copy/backup/restore path is the one the platform database is
already on —
`Store.backup()` copies the whole file, this table included, as it always did, and
`deployment/state_copy.py::copy_state` already copies it the same way. Rolling back to a build without
this module loses only the verdicts filed after it; the incidents, actions and audit rows those verdicts
describe are untouched, so rollback is the ordinary binary rollback and not a data rollback.

That is **not** an exemption from the repository's backup directive, and nobody should read it as one.
`AGENTS.md` ("No data work without a backup taken and verified FIRST") applies to code and documents and
commits as well as to databases and migrations: changing tracked files is a mutation of repository state,
and the rule is take-and-verify a backup **before** mutating, then record
`Backup-taken: <artifact> sha256=<hex>` in the commit that lands the change. So this change owes a backup
and a `Backup-taken:` trailer like any other; what it does not owe is a *new* backup mechanism, a backup
matrix row, a `components/**/backup.md` entry or a retention tier, because it adds no new store. For
building and testing this unit no live state was read or written — every database touched was a temporary
file and no read reached a network — and the backups that guard the work itself are the reviewing
identity's, taken and verified before mutation, which is exactly what happened for this card.

One scope note, because `VERSION` has moved twice since this section was written and the wording above
can be misread as a standing promise about the repository: "adds no new store" is true of **this unit**
and of nothing else. Schema v3 added the delivery columns and schema v4 added
`verification_bindings`/`verification_records` for [verification records](verification-records.md), and
both are covered the same way the sentence above says everything is — the whole platform file, copied by
`Store.backup()` and by `deployment/state_copy.py::copy_state`, with the pre-migration copy as the
rollback — so no new backup mechanism appeared with either migration either.

## Gotchas / debt

* **Two entry points with different responsibilities.** This module keeps its evidence-only
  `python -m` entry point; `lo-platform verification` is the separate remote record client.
  The follower is a separately configured process, not a scheduler added to this module.
* **Runner outcome and verification remain distinct.** Records are keyed by execution and
  visible in saved history; they do not replace `succeeded`/`failed`/`unknown` in the execution.
  Nothing in this module writes those records.
* **It does not resolve incidents, by design.** Emitting a `resolved` event from here would invent the
  incident lifecycle this repository keeps in `state.py`/intake — a condition key is derived from a
  producer's rule, resource and condition, not from a threshold re-check. If recovery-on-verification is
  wanted, the open decision is which producer owns that event and under which rule identity: a platform
  decision, not a local one.
* **Durable refusal audit is closed as the refusal audit.** Its passing lifecycle invariant checks
  nine refused attempts and nine append-only `action.refused` rows. Verification records,
  their CLI, saved-history UI and the opt-in follower are separate units; deployment is
  not proved by their presence in the source tree.
  The measurement that filed it (on `main 8194c4b`, 2026-09-08: 30 refused attempts
  at the state boundary writing 0 audit rows, 8 refused ASGI requests writing 0 rows and emitting 0
  platform log records — the gap sat in `Store.decide`'s role gate, `Store.claim_action`,
  `Store.execution_outcome` and `api.create_app`'s `StateError` branch) is history, and
  [refusal audit](refusal-audit.md) is where the shipped boundary is documented. Neither file was
  remediation invariants's to change while this unit was written, and that is why the finding was filed as its own card
  rather than fixed here.
* **The approval firewall is a credential-role firewall, on purpose.** It is enforced twice: `require`
  inside `Store.decide` (which refuses anything that is not an `Actor` with role exactly
  `human`, tested with 16 malformed actor shapes), and `api.create_app`'s credential edge — the `Actor`
  is built only from the bearer token matched against the configured list, the decision route matches
  only the exact `{action_id, decision}` body, and `create_app` refuses a credential whose role is
  outside the six it knows. `policy.py::action_policy` is *not* a second firewall: its closure takes the
  payload only (`grep -n actor local_observe/platform/policy.py` matches nothing), so it cannot see a
  requester at all. That is the shape v0.1 had too (agent approvers rejected by kind), and no
  identity-level rule is asserted here — see "The invariants, in words" item 1.
* **`metric_name` is a selector, not evidence.** The store's vocabulary has no approved evidence
  parameter for a metric name, so it never appears in the filed reference, which cites `resource_id` +
  `rule_id` (+ `artifact_sha256`). That is exactly why the series name is required in configuration and
  why an unscoped check refuses instead of guessing. A hand-built `Origin` without one still *asks* — the
  read goes out resource- and rule-scoped, with an empty selector set — and then refuses to judge: an
  unbounded question is allowed, an unbounded answer is never turned into `cleared`.
* **Only `lt`/`le`/`gt`/`ge`/`eq` on a numeric metric.** No log-pattern, trace, composite or multi-series
  condition, and no hysteresis: a signal that flaps across the threshold reports whichever way its newest
  point lies.
* **No `expectedFailure` remains in the invariant file.** The one that was there filed **the refusal audit**
  (refused bad actions left no audit row at all, and `api.py` did not log the 400 either): a gap in
  `state.py`/`api.py`, neither of which remediation invariants may edit, reported as a measured gap and never as a
  passing invariant. Its marker was deleted in the same change that landed that card's implementation,
  so no unexpected pass was ever observed here to delete it: the measurement that carried the finding was
  main running the original unwrapped nine-attempt body against `main 8194c4b` and watching it fail, and
  the marker removal and the fix were drafted together. The assertion now runs as one of the file's
  invariants. The earlier `expectedFailure` that asserted "no principal may approve the action
  it proposed" was **removed**, not fixed: `docs/CONTRACTS.md` §5 requires an authenticated human
  approver, not two humans, v0.1's policy rejected agent approvers only, and the human approval policy is
  not this unit's to change. The firewall that does exist is pinned by the five tests named in "The
  invariants, in words" item 1.

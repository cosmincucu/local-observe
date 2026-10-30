# Planned maintenance: windows, schedules and outcomes

Planned maintenance is a **signed, bounded silence**. A human says which part of the estate is about to be
worked on, for how long, and what the platform should stop paging during it. Everything else in this
document is the consequence of that sentence: the silence has an author, an end, a scope that cannot drift,
and a record of what it cost.

Two objects exist because those two facts are not the same:

* a **window** is one silence. It is a control document in `notification_control`, immutable once declared,
  and it is read on the delivery path — every finding runs past it before a message is sent.
* a **schedule** is a plan that produces windows. It is a versioned row in `maintenance_schedules`, and it
  is *never* read on the delivery path. A recurring plan silences nothing by itself; only the windows
  materialized from it do.

That split is deliberate. An operator changing a plan must not be able to change what was already quiet, and
a reader asking "what was silenced at 15:30?" must get an answer that does not depend on whether somebody
edited a rule last week.

| Question this page answers | Section |
| --- | --- |
| What can I call, and with which credential? | [Routes](#routes) |
| What may a window cover? | [Scopes](#scopes), [Condition classes](#condition-classes) |
| How long, how many, how far ahead? | [Bounds](#bounds) |
| What happens when the clocks change? | [Recurrence and DST](#recurrence-and-dst) |
| What did the silence achieve? | [Outcomes](#outcomes), [Attribution and overlap](#attribution-and-overlap) |
| What was planned around a past instant? | [Historical reads](#historical-reads) |
| Which error answers which mistake? | [Errors](#errors) |
| What changed in the state file? | [Schema v12](#schema-v12-the-schedule-table-and-the-two-report-reads) |
| What does this build not do? | [Limitations](#limitations) |

The rules themselves are machine-readable in [`openapi.yaml`](openapi.yaml) and
[`coverage.yaml`](coverage.yaml); [`COVERAGE.md`](COVERAGE.md) explains how those two are kept honest.
`local_observe/platform/maintenance_api.py` is the transport, `maintenance.py` the domain, and
`suppression.py` the durable window and the delivery-path match.

## Prerequisites

* A platform database at **schema v12** (`GET /v1/health` reports `schema_version`; if it is lower, run
  `lo-platform --database <path> migrate`, which verifies a copy of the file first and refuses to open a
  database newer than the build). No stored window, incident or audit row is rewritten by that step.
* A credential whose role is **`human`** for every write. `producer` may neither write nor read this route
  family; `reader`, `proposer`, `human` and `executor` may read it; a `summary` credential is refused on
  every path, including the reads.
* A built inventory index, passed to the app as `index_path`, **only** for a `service` scope or a
  service-interval query. Without it those two refuse; a `resource` or `rule` scope needs nothing.
* An HTTP body under the transport's request limit, and `Content-Type: application/json`. Bodies are
  decoded strictly: no NaN/Infinity, duplicate keys or trailing data.
* `Idempotency-Key` on every write you care about retrying. It is optional (the API serves the write
  without one) and it is the only thing standing between a lost response and a second silence.

## Routes

| Method | Path | Roles | What it does |
| --- | --- | --- | --- |
| `POST` | `/v1/maintenance-windows` | `human` | Declare one window over a scope. Expands to one window per service member. |
| `GET` | `/v1/maintenance-windows` | `reader` `proposer` `human` `executor` | The windows live now, with `count` and the bounds the scan read against (`max_live_windows`, `max_rows`, `scanned`, `expired`, `revoked`, `unattested`, `bound_exceeded`). |
| `GET` | `/v1/maintenance-windows/{id}` | same | One window as stored, plus its outcome. Unknown id is a `404`. |
| `GET` | `/v1/maintenance-windows/{id}/history` | same | Declaration, cancellation and every page it folded, with outcome evidence. |
| `POST` | `/v1/maintenance-windows/{id}/cancellations` | `human` | Cancel one window. Empty body. |
| `POST` | `/v1/maintenance-schedules` | `human` | Declare a recurring plan and materialize its first bounded slice. |
| `GET` | `/v1/maintenance-schedules` | `reader` `proposer` `human` `executor` | Active plans, or `?state=all` / `?state=cancelled`. |
| `GET` | `/v1/maintenance-schedules/{id}` | same | The current version, the whole occurrence list, `materialized_through`. |
| `GET` | `/v1/maintenance-schedules/{id}/history` | same | Every version, oldest first, each with its stored state. |
| `PATCH` | `/v1/maintenance-schedules/{id}` | `human` | Append a version. Requires `expected_version`. |
| `POST` | `/v1/maintenance-schedules/{id}/cancellations` | `human` | Stop the plan and its unstarted windows. Empty body. |
| `POST` | `/v1/maintenance-schedules/{id}/materializations` | `human` | Roll materialization forward one bounded slice. Empty body. |
| `GET` | `/v1/maintenance-intervals` | `reader` `proposer` `human` `executor` | A span (`from`/`to`) or an instant (`at`) against the windows planned around it. |

`PATCH` exists on the schedule path and nowhere else in the API. A plan edit has to be a distinct verb: a
`POST` to the collection mints a second plan rather than appending a version to the one the operator is
standing on.

**Producers are outside this family in both directions.** They may not declare a window, and they may not
read which windows cover their own findings: a detector that can see its cover can schedule findings around
it. The write door answers `403 not_authorised`. A `producer` GET is refused one level earlier, by the
transport's own role gate, with `400 not_authorised` — the code `api.py` has always used for a credential
outside a route's gate; the same sentence, a different status. Neither refusal reaches the state layer, so
neither leaves an audit row: [Errors](#errors) says what this family records durably instead.

## Scopes

A scope is exactly `{"kind": "resource" | "service" | "rule", "id": ...}`. `resource` and `service` ids are
UUIDs; `rule` is the rule label as a detector files it.

| Kind | What is covered | When the member set is fixed |
| --- | --- | --- |
| `resource` | Every finding about that one resource. | Trivially. |
| `rule` | That rule on **any** resource: one window, no resource selector. Use it when the probe itself is being maintained. | Trivially. |
| `service` | The service resource and every resource whose `runs-on` / `depends-on` relation points at it, as the built inventory index reports them. | **At declaration.** The answer carries `members` and declares one window per member. |

A service scope is expanded once, when a human signs the plan, because the delivery path cannot match a
service: a canonical event names a resource and a rule, never a service. A window whose extent changed
whenever somebody re-ran a discovery job would be a silence nobody declared. A member added tomorrow is not
covered by a window signed today, and the answer says which members it did cover.

Refusals, all of them loud: no built index configured; an id the index does not hold; a walk the index
itself reports as truncated; more members than `MAX_SERVICE_MEMBERS` (16). The remedy for the last one is
to declare the members or narrow the service — the platform will not silently trim a silence.

## Condition classes

A window says which classes of condition it accounts for. `GET /v1/maintenance-windows` reports the list;
the delivery path checks it before folding anything.

| Class | Derived from | Explained by default? |
| --- | --- | --- |
| `availability` | `kind: availability`, `status: firing` | Yes |
| `restart` | `kind: availability`, `status: resolved` — the boot report | Yes |
| `silence` | `kind: coverage` plus heartbeat evidence (`query_type: source-heartbeat`) | Yes |
| `freshness` | any other `kind: coverage` finding | Yes |
| `backup-integrity` | `rule_id`/`condition` whose first dot-segment is exactly `backup` | **No** |
| `security` | `kind: security` | **No** |
| `application` | `kind: threshold`, `anomaly` or `drift` | **No** |
| `unclassified` | anything this build has no rule for | **No** |

The four defaults are the pages planned work genuinely explains. The four refusals are what maintenance
tends to break rather than cause: a compromise discovered during a window, a backup that did not verify, an
application that failed while the disk was being replaced. Those pages arrive inside a planned outage, and
the window's existence is not a reason to lose them.

`explains` is therefore opt-in, never a widening default:

```json
{"reason": "replace disk sdb", "scope": {"kind": "resource", "id": "…"},
 "starts_at": "2026-10-19T03:00:00Z", "ends_at": "2026-10-19T04:30:00Z",
 "explains": ["availability", "restart", "silence", "freshness", "security"]}
```

* Omit `explains` and you get the four defaults, not "everything". Through an HTTP door an omission has
  blast radius.
* Name classes explicitly to widen the silence. A duplicate or an unknown name is refused.
* A window declared before condition classes existed stores no list and is **class-blind**: it covers
  everything inside its selector, exactly as it did when it was approved. Narrowing a legacy silence is a
  human act — cancel it and declare a narrower one.
* The classification is a table over canonical event fields. There is no expression language and no matching
  on human labels, so nothing a producer can name loosely can buy a silence.

A folded page's `reason` names the class it folded, the work and its end, so "the disk was down for the disk
swap" and "the application error rate was up during the disk swap" cannot look the same line in a portal
months later:

```text
maintenance-window 6c1f… for resource 7b3e… explains availability until 2026-10-19T04:30:00+00:00; declared by operator: replace disk sdb
```

and its detail carries `window_id`, `condition_class`, `explained_at` and `late_seconds`.

## Recurrence and DST

```json
{"reason": "firmware refresh, Mondays", "scope": {"kind": "resource", "id": "…"},
 "recurrence": {"frequency": "weekly", "interval": 1, "days_of_week": [0],
                "time_of_day": "03:30", "duration_seconds": 1800,
                "timezone": "Europe/London", "dst": "wall"},
 "bounds": {"first_occurrence": "2026-10-19", "occurrences": 8}}
```

* `frequency`: `daily` or `weekly`. `interval` is 1–400 days or weeks. `days_of_week` (Monday is 0) is
  required for `weekly` and forbidden for `daily`; a repeated weekday is refused.
* `timezone` is an IANA zone name. A zone the host cannot resolve is refused at the door — never guessed as
  UTC, because a plan read as UTC is twelve hours of wrong silence for a Sydney operator.
* `duration_seconds` is 60 (`MIN_OCCURRENCE_SECONDS`) to `suppression.MAX_WINDOW_SECONDS` (86 400). A
  silence measured in seconds suppresses nothing a human would notice.
* `bounds` is `first_occurrence` **plus exactly one** of `occurrences` (1–400) or `until` (inclusive local
  date). Both is a contradiction waiting for the shorter of the two; neither is a permanent silence with a
  start date. `open-ended silence is not maintenance`.
* The plan cannot start in the past: if the first occurrence has already ended, the declaration is refused
  with the retroactive sentence below.

`dst` is required, and it is the operator's decision rather than the platform's cleverness. Both transition
nights are covered by `tests/test_maintenance_api.py`, using the real IANA rules:

| `dst` | 2026-10-25/26 fold (clocks back) | 2026-03-29 gap (clocks forward) |
| --- | --- | --- |
| `wall` | The local minute is kept. 03:30 London is 02:30Z before the change and 03:30Z after: the roster on the wall does not move. | The occurrence is kept and resolved at the pre-jump offset, so the instant is one the zone calls 02:30. `dst: "gap"` records it. |
| `fixed` | The offset the first occurrence established is kept, so the instant is constant and the local clock face moves. | Kept, offset-preserved; `dst: "offset-preserved"`. |
| `skip` | Kept, `wall` behaviour, since the minute exists. | **The occurrence is dropped**, and `dropped_occurrences` names the date, the local minute and the zone. It is not moved: shifting it would put the same work next to the following occurrence, which is a second window nobody planned. |

Each occurrence carries a stable `occurrence_id`, derived from the schedule id, its version, the position
and the start instant. It is the identity the window is stored under, which is what makes materialization
retryable: a process that died halfway is finished by the next pass, and each already-declared occurrence
answers `duplicate` rather than buying a second silence. A new version is a different plan, so its
occurrence ids differ; re-computing one version always yields the same ones.

`occurrences` in a read answer is the plan's own list, computed from the stored document; `windows` is what
this build has actually turned into silences. The two differ until a plan is rolled forward, and
`materialized_through` says where the second one stops.

## Materialization, edits and cancellation

A pass turns at most `MAX_MATERIALIZED_OCCURRENCES` (8) occurrences into windows and reaches at most
`MAX_HORIZON_SECONDS` (35 days) ahead of the clock. Nothing schedules that pass: it happens on declaration,
on edit, and when a human `POST`s `…/materializations`. A plan nobody rolls forward simply stops producing
windows — it does not suppress forever, which is the safe direction.

`GET /v1/maintenance-schedules/{id}` reports `occurrence_bound`, `materialized_through`,
`skipped_occurrences` and `dropped_occurrences`, so "is the plan still running?" has one answer.

An **edit** (`PATCH`) appends a version. It:

1. refuses unless `expected_version` matches the current one (`412 stale_revision`, and nothing written),
   because the durable record is an append-only version list and a blind overwrite would leave two
   active-looking versions;
2. revokes the *unstarted* windows of the version it supersedes (`windows_revoked`), leaves any window
   already running exactly as it was, and materializes the new version's slice;
3. keeps every prior version readable in `…/history`.

A **cancellation** marks the current version `cancelled`, revokes its unstarted windows, and keeps what
already ran — a window that ran keeps the record of having run. A cancelled schedule can be read but not
edited, cancelled again, or materialized: each refusal says the plan is cancelled rather than inventing a
second word for it.

Because `schedule_id` digests the reason, scope, author, recurrence and bounds, declaring one plan twice
answers `duplicate` while a plan that differs in any of those — including its `dst` policy — is a second
plan. `duplicate` means "this declaration is already the durable fact". Two different declarations that
reach one id are refused with a conflict rather than merged into a table that describes one plan beside
silences belonging to another.

## Bounds

A refusal is cheaper than a pager storm, so every bound is a number in the code and in the answer.

| Bound | Value | Applies to | What the answer says when it bites |
| --- | --- | --- | --- |
| `MAX_WINDOW_SECONDS` | 86 400 | one window, one occurrence's duration | refused |
| `MIN_OCCURRENCE_SECONDS` | 60 | one occurrence's duration | refused |
| `MAX_LIVE_WINDOWS` | 32 | windows live at once, platform-wide | refused; `max_live_windows` and `count` on the list read show how much is left |
| `MAX_WINDOW_ROWS` | 512 | rows a delivery-path scan walks | applies nothing, pages, and says so |
| `MAX_REASON_CHARS` | 200 | one printable line | refused |
| `MAX_OCCURRENCE_BOUND` | 400 | `occurrences`, and `interval` | refused |
| `MAX_MATERIALIZED_OCCURRENCES` | 8 | windows per materialization pass | `occurrence_bound`, and a roll-forward continues |
| `MAX_HORIZON_SECONDS` | 35 days | how far ahead of the clock | `materialized_through` |
| `MAX_SERVICE_MEMBERS` | 16 | a service scope's expansion | refused |
| version limit (`state.MAINTENANCE_SCHEDULE_VERSION_LIMIT`) | 1000 | edits per plan | refused |
| document limit (`state.MAINTENANCE_SCHEDULE_DOCUMENT_LIMIT`) | 65 536 bytes | one stored version | refused |
| `MAX_SCHEDULE_ROWS` | 256 | rows a schedule list walks | `count`, `returned_of`, `truncated` |
| `MAX_INTERVAL_ROWS` | 100 | windows a span lists | `truncated` |
| `MAX_QUERY_SPAN_SECONDS` | 92 days | `from`/`to` width | refused |
| `MAX_EVENT_LOOKBACK_SECONDS` | 7 days | how late a fact may be and still be judged at its own instant | judged at the clock, and `late_seconds` says how late |
| `MAX_HISTORY_ROWS` | 2048 | window rows a historical read walks | `bound_exceeded`, and no claim of absence |

## Outcomes

`outcome` is derived from stored rows — never from a column nobody updates — and the evidence line says
which rows said so.

| Outcome | True when |
| --- | --- |
| `planned` | Not started, not revoked. |
| `active` | Running now. Its findings are being folded at this instant. |
| `cancelled` | Revoked. `cancelled_before_start` separates work that never happened from work that ended early. |
| `completed` | Past its end, and at least one page it explained was folded inside it. |
| `unused` | Past its end, its scope was observed inside it, and nothing needed explaining. |
| `overrun` | Past its end **and** an incident about the window's own resource that opened at or before `ends_at` is still open when read: the condition outlived the declared silence. |
| `unknown` | Past its end and the evidence does not reach: no observation, an unattested or unreadable window, a truncated read, or a rule-scoped window whose incidents cannot be attributed to it. |

Two properties of that list are load-bearing:

* **An overrun stops suppressing at the declared end regardless.** `overrun` records that the pager came
  back on its own, which is what the operator asked for by declaring an end. Suppression does not extend
  because the work is late; extending it is a new declaration.
* **A resolved incident is not overrun evidence.** `incidents.updated_at` moves when a fact is *received*,
  so a boot report about 15:30 arriving at 17:30 would convict the window that planned the reboot. Only a
  still-open incident says "outlived".

`complete` says whether the read that produced the outcome could see everything it needed. `unknown` is
never `complete`: the answer withholds the claim rather than inferring quiet from a row that isn't there.
Read `attributions` — the pages folded — before concluding a window "did nothing".

## Attribution and overlap

Every folded page records the window that folded it (`window_id`, `condition_class`, `explained_at`) in the
`notification.suppressed` audit row, so attribution survives a restart, a re-open and a report written
months later. `GET /v1/maintenance-windows/{id}/history` reads them back through the `maintenance_attribution`
index and names the incident and notification each page belongs to.

**Two windows may cover the same resource at the same time, and each keeps its own list.** When more than
one live window covers a finding, the covering set is reported and the first match takes the page, so
`attributions` answers "which pages did *this* window fold" and not "which pages could this window have
folded". Cancelling one overlapping window does not touch the other: the delivery path asks whether *any*
live window covers a finding, so a cancellation that quietly took a sibling with it would end a silence
somebody else declared. A cancellation answer names only the id it cancelled — and a window cancelled
mid-flight keeps the attributions it earned before it was revoked, because that work already happened.

## Historical reads

`GET /v1/maintenance-intervals` answers two questions on one path. Exactly one scope
(`resource=` / `service=` / `rule=`), and either a span or an instant:

```
/v1/maintenance-intervals?resource=…&from=2026-10-19&to=2026-10-20
/v1/maintenance-intervals?resource=…&from=2026-10-19T09:00:00Z&to=2026-10-19T12:00:00Z&limit=20
/v1/maintenance-intervals?resource=…&at=2026-10-19T10:30:00Z&class=availability
```

A bare date names a day in UTC (`from=2026-10-25` is that day's start, `to=2026-10-25` its end, exclusive).
`class` is only asked with an instant; `limit` only with a span; an unknown parameter is refused rather than
ignored.

**A span** lists the windows whose span overlaps it — expired and revoked rows included, which the delivery
path never reads — each with its outcome, its `explains` list, `applied` (whether this build could apply it
at all: an unattested document silenced nothing) and `adjustment` (`revoked early`, with the span trimmed to
the revocation). `returned_of` and `truncated` distinguish "there were four" from "there were four and you
got four".

Beside them, `effective` merges the spans that were **actually applied** into the smallest set covering them,
each merged interval naming the window ids that produced it — so overlapping declarations stay visible
instead of collapsing into an anonymous union, and cancelling one of two overlapping windows visibly shrinks
the set. The class gate is not applied to a span: a span reports what each window claimed. "Would a
*security* finding at this instant have been silenced?" is the instant form of the question, asked with `at`
and `class`; omitting `class` asks the blunter "was anything planned around this instant?".

**An instant** classifies it: `planned`, `outside` or `unknown`, with every covering window, the `primary`
one, and `incomplete_reason` when the search could not finish. `outside` is a claim that requires a complete
search; an unfinished one answers `unknown`.

**Late facts.** A finding is matched by the instant it was *observed*, not the instant it arrived, clamped
to the clock and abandoned back to the clock beyond `MAX_EVENT_LOOKBACK_SECONDS` (7 days). A boot report
filed after the machine came up is therefore inside the window that planned the outage — and a finding
*observed* after a window's end matches nothing, whatever its arrival time. Note which side moves: candidates
are read as of the event instant, so an old fact walks more rows, and a set past the bound applies nothing
and pages, as it always has.

**A bound is answered as a bound.** When a historical search hits `MAX_HISTORY_ROWS`, the answer keeps
`bound_exceeded: true`, `complete: false`, `classification: unknown` and lists what it did read. "Nothing
was planned" is a sentence only a complete read may say.

## Retroactive declaration

**Not supported, and the door refuses rather than guessing.** A window whose span has already ended cannot
be declared; `starts_at` in the past is allowed only if `ends_at` has not passed (a window declared while
the work is already running is a real situation — you find the ticket and sign the silence that is missing).

> A maintenance window cannot begin in the past; planned work is declared in advance, and what was planned
> around a past instant is a question for /v1/maintenance-intervals

A schedule is held to the same rule against its first occurrence. A materialized occurrence *may* have
already begun — the plan was signed in advance, and the silence was declared before the work started.

Every historical read carries `retroactive: false` so a reader can see the stance instead of inferring it
from an absent field: no window in a span answer was signed after the fact, because this build has no door
for that. The question "what was planned around that outage?" is answered by the interval read: each row
there carries the window's `outcome`, and `GET /v1/maintenance-windows/{id}/history` carries that outcome's
`observed` flag with its evidence lines, which together say how far the record reaches.

## Errors

| Status | Code | When |
| --- | --- | --- |
| 401 | `authentication_required` | No bearer credential, or one this deployment does not know. |
| 403 | `not_authorised` | A role this route does not carry: a `producer` write, a `proposer` edit, an `executor` cancellation. |
| 403 | `summary_only` | A `summary` credential on any maintenance path, read or write. |
| 400 | `invalid_request` | A malformed scope, an unbounded span, a bad instant, an unknown field, a `class` on a span, a body on a cancellation, an over-long reason. |
| 400 | `actor_claim_refused` | A body naming its own `author` / `actor` / `identity` / `role`. The actor is the credential that signed the request. |
| 404 | `not_found` | A window or schedule with no row, or a path this family does not carry. |
| 405 | `method_not_allowed` | A verb the route does not carry. Legacy body: `{"error": "method_not_allowed"}`. |
| 409 | `conflict` | A cancellation of an already-cancelled window; a write against a cancelled schedule; a declaration needing more live windows than remain; a search that would exceed a read bound; two different declarations sharing one schedule id. |
| 409 | `idempotency_conflict` | An `Idempotency-Key` reused with a different body. Nothing was written. |
| 412 | `stale_revision` | A `PATCH` whose `expected_version` is not the current version. |
| 413 | `body_too_large` | A body over the transport limit. |

A structured refusal carries `{"error": {"code", "message", "detail"}}` (the `detail` is the sentence the
domain raised, so `maintenance.RETROACTIVE_REFUSAL` is what a caller reads); the 401, `summary_only` and 405
answers keep the transport's legacy one-word body, which is what the shared responses document. A role
refusal in this family is answered before the state layer runs, so it leaves **no** audit row: the durable
record of maintenance is the acts, not the refusals — `maintenance.declared` and `maintenance.revoked` per
window, `maintenance.schedule_declared` for every version appended (a cancellation is a version whose state
is `cancelled`, not a rewrite of the version it stops), `maintenance.schedule_materialized` for every
roll-forward, and `notification.suppressed` carrying the window id for every page a window folded. Every
response carries `X-Request-Id`.

**A retried write needs `Idempotency-Key`.** `POST`/`PATCH` on the window and schedule paths are claimed
before the state layer runs: a replay returns the first answer with `x-idempotency-replayed: true` and
writes nothing, a reused key with a different body writes nothing, and a write whose outcome could not be
recorded is *not* released for retry — the retry then answers `409`, because two silences are the failure
mode the header exists to prevent.

`PATCH /v1/maintenance-schedules/{id}` requires `expected_version`. A mismatch answers `412` and writes
nothing: a schedule edit that replaced somebody else's version would leave an append-only table with two
versions that both look in force, and the windows beside them belonging to neither.

## Schema v12: the schedule table and the two report reads

Migration 12 adds one table and two indexes. **It changes no existing row**: windows stayed control
documents (they are immutable declarations read on the delivery path), so every window declared before this
build is still readable, still honoured, and still class-blind.

* **`maintenance_schedules`** — one row per *(schedule, version)*: the canonical document, its `state`
  (`active` / `cancelled`), the `horizon` reached, and `attest`, the `audit` sequence of the row that booked
  it. Append-only `UPDATE`/`DELETE` triggers reject both with the same `append-only maintenance version`
  message as `api_idempotency`: version 2 must not be able to restate what version 1 said the plan was, and
  a row may not vanish while its windows still cover findings. `state` changes by appending a version, never
  by editing one, so `GET …/history` answers "what did the plan say in October?" in November.
* **`maintenance_outcome_evidence`** over `incidents(resource_id, opened_at)` — the one read an outcome
  needs and no existing index serves: incidents overlapping a past window, newest side first, with no upper
  bound on `opened_at` (which rules out the older `incidents_open` partial index and the `conditions`-led
  one). Without it every `GET …/history` on a past window is a scan of the incident table.
* **`maintenance_attribution`**, partial and over an expression, on `audit` for
  `notification.suppressed` rows keyed by `json_extract(detail, '$.window_id')`, guarded by `json_valid`
  inside the same expression. It answers "which pages did *this* window fold" from the id the decision
  already wrote, so attribution needs no second copy of the fact and no back-fill.

Neither index is named with `INDEXED BY`: both reads have an honest zero to report, and a missing index
would turn a report into an SQLite error. Authority stays where it always was — `suppression._scan`
re-checks every window it applies against the envelope, the declaration and the attestation, so an index key
is a search term and never a reason to silence a pager.

**Migration and rollback.** `lo-platform --database <path> migrate` makes and integrity-checks a
`<path>.pre-v<from>-<utc stamp>.db` copy before applying each missing step, each in its own transaction
ending in its own `PRAGMA user_version`, auditing one `schema.migrated` row per step. A crash between steps
leaves the last committed version readable. A database newer than the build is refused: there is no
downgrade, and rollback is the pre-migration copy, not a code rollback. `docs/CONTRACTS.md` §5 and the
migration notes in `local_observe/platform/README.md` carry the same step count; `tests/test_state_migration.py`
pins the table set and `tests/test_incident_grouping_migration.py` pins the `schema.migrated` subjects a v1
file walks to reach v12.

## Limitations

* **No retroactive silence.** See above. If you need to explain a past outage, the interval read tells you
  what *was* planned; nothing here can add a window to a span that already closed.
* **No background roll-forward.** Materialization is a human write. A plan that is never rolled forward
  stops suppressing at its horizon — deliberately, since a plan that keeps silencing while nobody is looking
  is the failure this feature must not have.
* **Service membership is a snapshot.** Taken at declaration, per window. Re-declare to move it.
* **A rule-scoped window cannot show its own overrun.** Incidents are keyed by resource, so the answer is
  `unknown` with a sentence saying why, not a guess.
* **`unused` requires an observation.** No finding about the scope inside the window is `unknown`, not
  `unused`: the platform will not report a quiet window from a read it did not perform.
* **One window covers one resource or one rule.** Not a tag, not a name pattern, not "everything in this
  cluster" beyond the 16-member service bound.
* **A window cannot be edited, only cancelled and re-declared.** That is the same rule as an audit row, and
  for the same reason: the pages already folded were folded by the span that was signed.
* **Condition classes are derived, not configured.** A rule this build cannot classify arrives as
  `unclassified` and is unexplained by default. Adding a class is a code change with a test, not a knob.
* **A `producer` credential cannot read this family.** If a detector needs to know what is quiet, that need
  is a design question, not a missing route.

## Testing

`tests/test_maintenance_api.py` covers this page: the route family over ASGI with real credentials
(authentication, roles, idempotent replay and conflict, verbs, bodies), the scopes including a service
expanded from a built index, the class gate both ways and the class-blind v1 window, DST against the 2026
London gap and fold for all three policies, stable occurrence ids, bounded materialization and roll-forward,
finite bounds, edits and cancellations, all seven outcomes, the overlap pair (attribution per window, no
collateral revocation), late facts, `bound_exceeded`, and a v1 window read after the migration. Timing
assertions pass a controlled `now=`; the transport class uses instants relative to the real clock, because
the transport's "that window has already ended" is a fact about the real one.

```sh
PYTHONPATH=tests .venv/bin/python -B -m unittest test_maintenance_api
PYTHONPATH=tests .venv/bin/python -B -m unittest test_maintenance_windows test_maintenance_history \
    test_api_openapi_conformance
```

`tests/test_maintenance_windows.py` and `tests/test_maintenance_history.py` own the durable window itself —
envelope, attestation, read bounds — and `tests/test_api_openapi_conformance.py` owns the claim that the
census, the OpenAPI document, the transport source and the running app agree.

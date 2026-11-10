# Unit: CI failure ingestion (`local_observe/ci_failures`)

**File(s):** `local_observe/ci_failures/{transports,store,facts,adapter,outlet,pipeline,platform_client,cli}.py` ·
**Tests:** `tests/test_ci_failures.py` (offline: injected transports, `SocketGuard` patches the network
stack off) · **Config:** `LO_CI_REPOSITORY`, `LO_CI_STATE_DIR`, `LO_CI_MAIN_BRANCHES`,
`LO_CI_STUCK_AFTER_SECONDS`, `LO_CI_HEARTBEAT_DEADLINE_SECONDS`, `LO_CI_MAX_PAGES`, `LO_CI_PER_PAGE`,
`LO_CI_MAX_OPEN_RUNS`, `LO_CI_FILE_CARDS`, `LO_CI_CARD_*`, `LO_CI_RUN_LINK_BASE`, `LO_CI_SEED_CURSOR`,
`LO_CI_ACTIONS_URL`, `LO_CI_BOARD_URL`, `LO_CI_PLATFORM_URL` (each with a `…_TOKEN_FILE` /
`…_TOKEN` credential)

Reads one repository's Actions history and folds it into incidents. Two scoped clients (GET-only
Actions, board reads plus `POST /issues` and `POST /issues/N/comments`), one durable state file, one
heartbeat and one outlet journal. The board is optional: with no board configured the same process is an
**incident source** instead, posting canonical events to the platform and writing no issue anywhere.

## Running it (`python -m local_observe.ci_failures`)

One required setting and two optional outlets. `LO_CI_REPOSITORY` (or `--repository`) names the
`owner/name` to read, and `LO_CI_ACTIONS_URL` (or `--actions-url`) the forge API to read it from. Every
URL is HTTPS unless `--allow-http` says otherwise, and no URL may carry a user, a password or a query
string -- a token goes in a mounted file, whose path is `LO_CI_ACTIONS_TOKEN_FILE`
(`LO_CI_ACTIONS_TOKEN` is the fallback), and the token never appears in output or a log line.

| Command | What it does |
|---|---|
| `--once` | One poll: read, record, decide, deliver, check in. Exit `0` when every verdict the poll decided was admitted or there was nothing to send; `3` if a source could not be reached **or any receipt came back refused** — including a poll where some other event was admitted; `4` if the configuration was refused, if the state file holds a row this poll cannot decode, or if the state file could not be used at all (a read-only or missing directory, a full or corrupt database, a file another process is holding: all of them one line on stderr, never a traceback). `--status` and `--check-heartbeat` answer the same way, and neither asks for the Actions credential first. |
| `--check-heartbeat` | Judges the last check-in from the same state file and writes nothing. Run it from its own timer. Exit `2` when the poller is overdue. |
| `--status` | Prints the stored counts (cursor, occurrences, pending deliveries, verdicts still owed to the platform, heartbeat) and exits. |

### The board outlet is opt-in, and so is the platform

* **No `--board-url` / `LO_CI_BOARD_URL`:** the service is built with no board transport and no outlet.
  Nothing is scanned, nothing is planned, nothing is written, and the report carries `"drained": null`
  and an empty `planned`. This is a complete run, not a degraded one: the facts, the cursor, the
  occurrences and the heartbeat are all still recorded.
* **`--file-cards` (or `LO_CI_FILE_CARDS=on`) with no board URL is a refusal**, exit `4`, one line: board
  filing is a request to write, and a run that wrote nothing because nothing was addressable would look
  like a run that had nothing to file. Point it at a board, or leave the switch off.
* **`--platform-url` / `LO_CI_PLATFORM_URL`** posts the poll's verdicts to the platform
  (`local_observe/platform`) as canonical events: `POST /v1/events` with the producer credential named by
  `LO_CI_PLATFORM_TOKEN_FILE`. One event per incident key -- `(repository, workflow file, plane)` -- so a
  page of failing runs of one workflow is one verdict, not a page of incidents, and the pull plane is
  recorded under a status that opens nothing (see "How wide an incident is" below). That credential must
  be a `producer` whose identity is `gitea_ci` -- the
  platform refuses an event whose `source` is not the identity of the token that posted it. The report
  then says `"platform_admission": "admitted"`; with no platform URL it says `"not-configured"`, the
  events are counted and not sent, and nothing is claimed either way. If the platform is unreachable or
  says no, the exit code is `3` and `receipts[]` names the event and the reason — the reason carries the
  platform's own stable `error` code from a non-2xx answer (`intake refused with status 400:
  invalid_request`), bounded, and never the `detail` field, which is a rendered exception message and can
  echo a credential. A `StateError` from an in-process store is a `refused` receipt, not an outage: the
  store answered, it simply said no. Whatever the platform did not take stays owed — see "Verdicts the
  platform never took" below.
* Card filing and platform admission are independent switches. A deployment can run both, either, or
  neither; the recommended order is neither (read and record only), then the platform, and the board
  only if somebody has decided they want an issue for this.

### Job logs

By default the poller also reads the failing job's log (`GET
/repos/{owner}/{repo}/actions/runs/{run}/jobs/{job}/logs`), because the log tail is what makes a card's
fingerprint specific rather than coarse. It is the same base and the same credential as the rest of the
Actions read -- there is no third token. The job id comes from the jobs endpoint; the number in a runner
container name is the runner's task id and is a different object. `--read-only-logs` skips it, and every
run then carries the `job-logs-not-wired` gap: its card is still filed, just coarser.

The reader never follows a redirect. That is deliberate — the log endpoint hands out a signed URL, and
following a `307` would hand the bearer token to whatever host answered — and it has a cost worth stating
before it is discovered at 3 a.m.: a log endpoint that answers 3xx to every request yields
`job-log-status-307` on **every run, forever**. That gap is a coverage incident which stays open (see
"Coverage conditions open and close"), and it makes every card from that repository coarse. Both are the
honest outcome — the log really cannot be read with this credential from this client — and the fix is on
the forge side (or `--read-only-logs`, which says the same thing in the operator's own words instead of
in the poller's).

The log reader bounds its token at 24..4096 characters where the JSON client bounds only from below, so a
very long Actions token is accepted by the run read and refused by the log read. `--once` then exits `4`
naming the `LO_CI_ACTIONS` credential and `--read-only-logs`; nothing is half-wired.


## The cursor contract (`store.run_cursor`, `pipeline.poll_once`)

The cursor answers one question: **every run *with a verdict* newer than me has been ingested.**

* It moves at the end of a walk that finished (`complete`), never mid-walk — an aborted walk cannot
  claim anything about rows it never reached.
* It moves only over runs whose `status` is `completed`. An unfinished row does **not** advance it: the
  fact that matters (the conclusion) does not exist yet, and a cursor parked on a queued run makes that
  run's own failure, arriving on a later tick at `run_id <= cursor`, read as history and dropped. That
  is the one shape of lost incident that leaves a green-looking poller, so the cursor waits.
* Consequence: while a run is still queued the cursor sits behind it and the pages above are re-read.
  That is cheap by design — `runs.event_key` and `occurrences(fingerprint, run_id)` make a replay a
  no-op — and it is bounded by `max_pages`/`per_page`.

## Open-run refresh (`pipeline._refresh_open_runs`, `ActionsSource.run`, `LO_CI_MAX_OPEN_RUNS`)

A run whose id has fallen **below** the cursor is invisible to the page walk for good, even if it was
still queued when the cursor passed it (any settled run with a higher id moves the cursor past a
waiting one). The store's own `open_runs` rows — written by `track_open_run`, the same table that keeps
the starvation clock across a restart — are the only list that still names such a run, and
`GET /runs/{id}` is the only read small enough to ask about each one.

* **Bounded:** at most `max_open_run_refresh` GETs per tick (default 20, range `0..50`, `0` disables),
  newest first, and only for open ids at or below the cursor. Ids above the cursor are already re-read
  by the walk. A poller that lost a page never answers by scanning the repository.
* **Not a second incident:** refreshed facts go through `record_facts` with the cursor unchanged (never
  backwards), so novelty decides. A `queued -> running` change reuses the same `event_key` (the key
  carries a *finished/stuck* class, not the raw status), returns no fresh pair, files nothing, and adds
  no occurrence.
* **A settling run replaces its own placeholder:** when a terminal fact arrives for a run, `record_facts`
  deletes that run's `outcome='stuck'` occurrence first. The starvation row was a status transition
  recorded under a coarser fingerprint (no log, no failing step); leaving it would count one
  starved-then-failed run twice and open two cards.
* **Failure modes:** a refresh that fails (outage, malformed) is coverage (`open-run-refresh-failed`)
  and the row **stays** — it is asked about again next tick. A 404 (`None`) means the forge dropped the
  run: coverage (`open-run-vanished`) and the row is retired, so the budget is not spent on it forever.
* The walk drops the row of any run it settles itself, so a run never lingers in the refresh set.

## `ActionsSource` scope (four path shapes, GET only)

`/actions/runs`, `/actions/runs/{id}`, `/actions/runs/{id}/jobs`,
`/actions/runs/{id}/jobs/{id}/logs` — compiled from this client's own validated repository identity, so
`POST /repos/{repo}/issues` is not a request this object can express. `request` checks the method
before the path, and a hostile id is refused before the transport is touched
(`tests.test_ci_failures.TransportScopeTests`). `run()` additionally refuses a detail body that answers
a **different** run id than was asked for (`ScopeRefused`): a substituted page must not be recorded
under the requested id.

## The real Gitea contract (`facts.parse_run_path`, `facts._route`, `transports._page_params`)

The parser supports the following Actions response shapes. Deterministic tests use
synthetic `acme/widgets` fixtures and fictional run identifiers.

* **`path` is the workflow identity and the ref.** A run object arrives as
  `path: "ci.yml@refs/heads/main"` or `"ci.yml@refs/pull/42/head"`, with `workflow_id`, `name`,
  `workflow_name` and `head_branch` null or absent. Parsing therefore reads the workflow file and the
  ref out of `path`: a bounded `.yml`/`.yaml` file (no `..`, no empty segment) and one of
  `refs/heads/<branch>`, `refs/pull/<n>/head|merge` (`refs/merge/<n>/head` accepted), `refs/tags/<tag>`.
  **When a payload carries both a `path` and a `workflow_id`, the file the path names is the identity**
  and the id is kept as a readable field but never keys anything: the file is what a developer, the
  workflow's own history and the incident's title all agree on, while the id is whatever one forge
  version mints (a number, or a ref-qualified string). Getting that order backwards splits one workflow
  across two incident subjects as soon as the two endpoints disagree, and a starvation fired under one key
  can never be closed by the verdict that arrives under the other — closure is keyed, never looked up.
  A present-but-unreadable path, or an unrecognised ref prefix, is `MalformedSource` — the run is
  refused durably, never bucketed under one shared `unknown` workflow (which used to make every
  workflow of a repository collapse into a single event identity).
* **The ref outranks `head_branch` and `event` when routing the plane.** With `head_branch` null, a
  branch/event lookup alone read every main push as `branch` and main-red stopped being main-red. A
  `refs/heads/<main>` ref is `main` even when the event is `workflow_dispatch`; a `refs/pull/...` ref is
  `pull` even when `head_branch` says `main` and even when the event word is `push` — the PR's base
  branch is never read, so nothing is inferred from it. Disagreement is recorded
  (`run-ref-outranks-branch-evidence`) rather than averaged, and a `head_branch` that contradicts a
  `refs/heads/` ref is a refusal, not a tie-break. When `path` is absent the old `plane_of(branch,
  event)` route still applies, so a GitHub-shaped forge behaves exactly as before.
* **Statuses are as documented:** `completed` carries `conclusion`; `queued`/`in_progress`/`waiting`/
  `blocked` do not. The parse rules were already right and are unchanged.
* **Timestamps are `started_at`/`completed_at`; `created_at`/`updated_at` do not exist, and an
  unfinished run's `completed_at` is the Unix epoch** (Go's zero time for a never-filled column). The
  placeholder is *unavailable*, never a 1970 moment: it parses to `None` and carries
  `timestamp-unavailable`. That matters because the starvation clock subtracts from it — trusted, the
  placeholder would make every queued run look 56 years overdue and file a `stuck` card on the first
  tick. `RunFact.observed_at` now falls through `updated_at, created_at, completed_at, started_at`, so
  an occurrence is placed on the instant the forge actually reported; with none, the poller's own clock
  is used and nothing is invented.
* **Queue timing lives on the job.** A job carries `created_at` (queued) and `started_at` (runner
  picked it up); the run does not carry `created_at`. When no run-level queue stamp exists, the earliest
  job `created_at` is used and the substitution is recorded as `queue-time-from-job-created-at`. A
  malformed job timestamp is `MalformedSource` naming the field and the job index; a missing one leaves
  `started_waiting_at` `None` — the run waits, it is not stale.
* **`limit` is the page-size parameter Gitea obeys.** `?per_page=3` returned 30 rows; `?limit=3`
  returned 3. Every list request (`runs`, `jobs`, issues, labels, comments) now sends `limit` and
  `per_page` with the same number, so the caller's bound holds whichever word the deployment reads —
  and a page that answers **more** rows than it was asked for is `MalformedSource`, because a 30-row
  page read as "shorter than 50, so that was everything" would end the walk early and let the cursor
  advance over runs nobody read.
* **Job reads are paged and bounded.** `ActionsSource.jobs` walks `/runs/{id}/jobs` with the same bound,
  stops at a short page, and raises `PaginationBudget` when the walk passes `MAX_JOBS_PAGES` or would
  exceed `MAX_JOBS_PER_RUN` (mirrored against `facts.MAX_JOBS`, asserted equal in the tests). The
  pipeline turns that into `job-list-unavailable` coverage: the run is still recorded and its card is
  coarse, never silently truncated into looking like a complete build.

## How wide an incident is (`facts.incident_key`, `adapter.plan_incident_keys`)

An incident is about **one workflow on one plane**, not about a run. The key is
`(repository, workflow file, plane)` -- `acme/widgets`, `ci.yml`, `main` -- and it travels as the event's
`resource_id`. `platform/state.py` computes an incident's condition key from
`(source, rule_id, rule_version, resource_id, condition)`, so the resource is the only field this source
may vary to set the width, and `validate_event` admits a `resource_id` that is null or a canonical UUID:
the readable key is `uuid5`-derived into one (`adapter.resource_id_for_key`). Nothing is declared in the
inventory and no topology is claimed -- a subject that no graph names simply groups with nothing.

| A failing run of `ci.yml` on… | Incident | Status filed | Severity |
|---|---|---|---|
| a pull request (`refs/pull/7/head`) | none: the event is recorded and opens nothing | `unknown` | `info` |
| the default branch (`refs/heads/main`) | one per (`acme/widgets`, `ci.yml`, `main`) | `firing` | `critical` |
| the default branch, on a schedule (`ci.yml@refs/heads/main`, `event: schedule`) | the same incident as the row above: the plane is the ref | `firing` | `critical` |
| a schedule or any other ref (`refs/heads/nightly-scan`) | one per (`acme/widgets`, `ci.yml`, `branch`) | `firing` | `warning` |

Loudness follows the **ref**, not the trigger: what makes a failure `critical` is that the default branch
cannot build, and a nightly scheduled run of that branch is exactly that. `event: schedule` on any other
branch is a `warning`.

* **Why the pull plane opens nothing.** `Store.intake` opens an incident for any event whose status is
  `firing` -- severity does not gate it, so `info` would still page. It admits a third word, `unknown`,
  and reads it as "record this verdict, change nothing": no incident, no transition, no delivery. That is
  the platform's own supported way to hear about a failing pull-request build without treating it as an
  outage, and it changes no intake rule. The pull plane is therefore *recorded*, not quietly dropped: the
  receipt says `event_status: unknown`, and `platform_admission` still reads `admitted`. A starved run of
  a pull-request workflow is recorded the same way, so one invariant holds everywhere: nothing on the pull
  plane opens an incident.
* **Stuck runs** share the same subject (one incident per repository and workflow) under their own rule
  `ci.run.stuck`, at `warning` on every plane -- a runner that never started is not a build that went red.
  Because the rule differs, a starved run and a failed run of one workflow are two conditions on one
  subject, which is what they are: one workflow waiting for a runner, and one workflow whose build broke.
* **Coverage events** (`ci.intake.coverage.*`) keep the shape they had: `resource_id` null, one condition
  per gap reason, `info`, and unchanged by plane -- a gap in what this poller could read is a statement
  about the poller, not about a workflow. They are coalesced **per reason per poll**, across every run
  that carried the gap, with the window folded to the span those runs were read at: two runs of one gap
  are two verdicts for *one* condition (the rule id is the condition and the resource is null for all of
  them), and `Store.intake` refuses the second at one watermark outright. Filing is the stricter question
  -- a completed green run declares no gap, because nothing depends on what a build that passed did not
  show.
* **Two keys, always.** Folding a disallowed character (`/`, a space) to `.` is deterministic, and every
  key carries a digest tail of the unfolded triple, so `ac.me/w1` and `ac/me.w1` do not land on one
  incident, and a name long enough to be truncated cannot collide with its own prefix. The whole key stays
  inside `state.label`'s character class and under its 128-character bound.

### One event per key per poll

A poll that sees five failing runs of one workflow sends **one** `ci.run.failed` event naming all five.
That is not a cosmetic reduction: `detections.event` derives `source_event_id` from
`(rule_id, rule_version, resource_id, window)`, so two events built for one key at one instant used to be
one record offered twice with different contents, and the platform answered the second offer with
`Event retry changed contents`. Coalescing happens *before* the event is built, so the collision cannot be
reproduced. The batch travels inside the one evidence reference the event already carries: its
`snapshot_id` is `cikey-<key>-n<count>-r<id>-r<id>…`, and when the list would not fit inside this
product's own `MAX_SNAPSHOT_CHARS` bound (200 characters, chosen to sit inside the 256 `validate_event`
allows), ids are dropped and the value says so (`-cut18`) rather than looking complete.

A poll never offers two events for one condition at one instant for a second reason too: `Store.intake`
refuses that as `Conflicting evaluations at the same condition watermark`. So per key per rule a poll
emits the firing verdict, or the closure, or nothing -- decided by run id, which the forge hands out in
creation order. If the newest run of a workflow in this poll is green and no incident is open, nothing is
sent about it at all: the failing runs older than it are listed in `superseded[]`, stay in the occurrence
table, and reach the board when a board is configured -- they just do not open an incident for a workflow
that is not red. The `resolved` event a closure sends names the green runs it speaks for; the runs it
overtook are the report's claim (`superseded[]`), not the evidence's, because a closure is a verdict about
the workflow being green and not an account of what it used to be.

### Closure (`resolved`)

A poll that sees a **completed successful run** for a key, newer than the newest failure it ever filed for
that key, sends one `resolved` event under the same rule id -- which is what closes an incident:
`Store.intake` reads a `resolved` against the condition and resolves the incident. The marker that makes
"newer than that key's last failure" answerable across polls is one row per key in this store's `meta`
table (`store.incident_key_states`), and **it is written from a receipt, not from an intent**: only the
marker moves whose event came back `admitted` are recorded (`adapter.claim_transitions`). A marker is
therefore a copy of an answer the platform gave, and nothing more.

That order is the whole difference between a marker that says "the platform has this" and one that says "I
decided this". Claimed at intent, a marker written for a verdict nobody offered (no credential wired yet)
or nobody took (a 503) told the next poll that the incident was open. The failing run behind it is behind
the cursor by then and will never be re-read, so the next green run spent its closure on a condition the
platform had never seen -- a `resolved` that is admitted as the no-op it is -- and the break itself never
became an incident. The verdict that never landed is kept instead, and asked about again: see "Verdicts the
platform never took".

**Upgrading across that change.** A build of this outlet that claimed markers at intent may hold `meta`
rows that are not copies of any answer: rows saying `open` for incidents the platform was never told about.
Nothing can tell those rows from honest ones after the fact, and no migration rewrites them -- the state
schema version is unchanged. An operator who wants the markers to mean what they now say deletes them and
lets the next polls rebuild them from receipts:

```sql
DELETE FROM meta WHERE key LIKE 'incident-key:%' AND key <> 'incident-key:ci.intake.coverage';
```

With the rows gone, the first tick after the upgrade knows nothing is open, so it files nothing about a
failure it can no longer see (the fact is behind the cursor) and re-opens from the next failing run it
reads. What that costs is not a closure arriving late -- it is a closure that can never be sent:

* **An incident the earlier build really did deliver is closed by hand.** The closure rule reads this
  store's `open` stamp ("a green run newer than the last failure this key ever filed"), and the stamp is
  exactly what the statement deletes. After it, a green run sends nothing about that key and the incident
  stays `open` on the platform however many green builds follow -- so close those incidents in the
  platform, or leave the rows alone. What the rows do keep, if you leave them, is the unverified `open`
  claim: a closure this source then sends may be the accepted no-op described below, which is harmless.
* **The gap subject is excluded from the statement on purpose.** `ci.intake.coverage`'s markers live in
  the same `meta` table under the same prefix, and a coverage incident is closed by the next poll that
  reads the gap gone -- which needs that same stamp. A gap this poller is still reading re-files itself and
  heals normally; a gap that healed before the upgrade would be left open on the platform with nothing left
  able to close it. Delete that row too only if you also close every open `ci.intake.coverage.*` incident
  by hand.

The state file is one SQLite file with a documented schema: stop the poller before editing it, and keep the
copy you edited from.

* **A marker never moves backwards.** `open` is `max(every failure this key has ever had admitted)`, in the
  planner and again in the store, and a closure is the one move that may set it to zero. A run that was
  recorded as queued and settles on a later tick (`_refresh_open_runs`) is a *new* fact carrying an *older*
  run id; letting it write `open: 800` over `open: 900` would let the next green run, at 850, close an
  incident whose newest failure is still red. The invariant a closure must satisfy is therefore
  `newest_green >= open`.
* **Cost: no extra requests.** Successful runs are already in the page walk the poller was doing; the
  closure is decided from verdicts this tick already read. A tick makes the same calls it made before this
  change -- the page reads, plus the bounded open-run refresh it already did.
* **A `resolved` names the key, so it closes only what this keying opened.** A build of this outlet from
  before the incident-key contract filed its verdicts under a different condition, and no closure sent
  here can reach those incidents: they are closed by hand. Nothing rewrites an incident's identity after
  the fact, and no released version keyed verdicts per run.
* **A `resolved` for a key the platform never opened is a no-op, and is treated as one.** `Store.intake`
  accepts it, leaves `incident_id` and `transition` null, writes no incident and books no delivery; the
  receipt reads `admitted` with `event_status: resolved`. That is the right answer for a marker older than
  the incident it refers to -- an operator closed it by hand, and this store's row outlived it -- and
  calling it a refusal would put a false alarm on every tick.
* **`recovered[]` stays**, and now says what it did. See `incident_statement` below.
* A starved run that later *fails* does not resolve its own starvation: a verdict is not a recovery. That
  incident closes the next time the workflow runs green, or not at all, and the report does not claim
  otherwise.

### Coverage conditions open and close

`platform/detections.py`, `platform/configdrift.py` and `platform/deadman.py` all spell a `coverage` kind
as open-and-close -- "could not be read (`firing`) or can be read again (`resolved`)" -- and this source
does the same. A gap is therefore not an incident that has to be closed by hand.

* **Opening:** a poll carries a gap reason on at least one run it could not fully read, and files one
  `firing` under `ci.intake.coverage.<reason>`.
* **Closing:** a later poll whose **own read came back** carries none of that reason, and files one
  `resolved` for it. The licence is the finished read, not the number of rows it returned: a poll that read
  a clean build closes a gap that build showed gone, and a poll the quiet repository left with nothing at
  all to read closes it too, because its walk finished, its credential worked, and nothing reported the
  gap. A poll that read nothing has not read anything back: a forge outage or a page-budget stop resolves
  no gap, because it proves nothing about the log reader or the timestamp fields. And a poll that read
  *some* rows and refused another has an answer missing, which is not an answer that came back: the refused
  row is neither a clean re-read nor a poll that finished reading, its notes hold the gaps it met open, and
  no stored closure is re-sent on a tick that left a row unparsed (see `run-malformed` below). The refusal is
  where an operator can see it -- the `refusals` count and the durable refusal row naming the field -- not in
  the exit code, which answers the narrower question of whether the source and the platform answered.
* **A gap that persists stays open, green builds or no builds.** Whether a reason is carried is asked of
  every run the poll read, and of **every** note on it: `MAX_COVERAGE_EVENTS` (three per run) caps what a
  poll may *file*, which is what stops a thirty-job run declaring thirty incidents, and it is not a limit on
  what this process knows. A poll that read four gaps and filed three has not read the fourth away, and
  reporting it as recovered would be a claim about the platform that this poll's own data contradicts.
  Filing is also limited to runs that can owe somebody an explanation -- a green build's unread log is not an
  incident waiting to happen. So `--read-only-logs` keeps `job-logs-not-wired` open across a thousand
  successful builds -- which is the true statement -- and it closes on the first poll that reads a log.
* **A gap that is already open says nothing further until it closes.** One `firing` is the whole page: the
  marker says `open`, **or** a firing for that reason is still owed (`verdicts_pending` holds the event the
  next poll will offer again), so a later poll carrying the same reason files no second event. What keeps
  landing every poll is the note on the run itself (`runs.detail.coverage`, which is what a card quotes) and
  the condition the platform still holds open: a gap that has waited three days is a three-day-old open
  coverage incident, and `store.incident_key_state('ci.intake.coverage')` says this source still stands by
  it. The `--status` report's `latest_coverage` is a different table answering a different question -- the
  poller's own reads (`actions-read-failed`, `scan-page-budget`, the open-run refresh) -- so a gap that is
  silently re-landing on every run is read from the runs, not from that list. Re-firing an open condition
  would be true and useless, and it would replace the stable stored event with a fresh window every tick.
  A configuration gap is carried on every poll for the same reason: `job-logs-not-wired` is a fact about
  this poller, so the note is added whether or not a run was read, and an empty tick cannot close what it
  never stopped being true.
* **A gap that healed during an outage is closed by the poll that reads it back, not opened one poll late.**
  The owed firing counts as open above, and because the closure speaks about that same (`subject`, rule id)
  pair, the stored firing is never re-offered: the closure retires it. A poll that filed a `firing`, lost the
  answer, and then read the gap gone therefore sends `resolved` for a condition the platform never opened --
  the accepted no-op described in "Closure" -- and no incident exists either way.
* **A closure the gap outlived is never owed.** A workflow verdict has to be kept when the platform refuses
  it, because the failing run behind it is behind the cursor and nothing else will ever say it again. A
  coverage closure is the opposite: it is re-derived every poll from the marker plus the absence of the gap,
  so the poll that next reads no gap says it again -- with a window that is true of that poll. Keeping it
  would be actively wrong, because a stored `resolved` travels to any poll whose plan said nothing about
  that pair, and the plan says nothing about a gap this poll is carrying: the recovery for a gap this
  poller has in its hands would reach the platform, the operator would be re-paged when the gap re-fired,
  and the marker would be cleared from the replayed receipt, so this source would forget a gap it was still
  reading. So a refused closure costs the exit code (`3` for that tick) and keeps nothing; a gap that
  flaps across an outage is reported when it last stops flapping.
* **A closure that arrives from the table is judged by the poll that reads it.** The rule above means a
  refused closure is normally not stored at all; what an older build, or the upgrade recipe that deleted
  `incident-key:*` rows, can leave behind is a stored closure that *is* still owed. The next poll decides it
  three ways, and says which: nothing this poll read carries the gap and its own read came back, so the
  closure is true and travels (this is what closes an incident the stranded row was holding open); the gap
  is carried, so the stored word is a lie and the row is retired and named in `abandoned[]` as
  `a coverage closure for a gap this poll is reading`; or this poll could not read its source, in which
  case it neither sends the closure nor gives up on it, and the two ceilings still bound the wait.
* **The marker is per reason**, in the same `meta` row mechanism as an incident key, under the reserved
  subject `ci.intake.coverage` (a subject is any bounded string to the store; a gap belongs to the poller
  and has no workflow to be keyed by). `open` holds the run the firing that opened it was about, and does
  not move again until a closure zeroes it and stamps the read that closed it -- a gap that persists is not
  re-filed, so it does not refresh the stamp either (see "A gap that persists stays open"). `--status`
  shows the `verdicts_pending` count, and the markers themselves are readable with
  `store.incident_key_state('ci.intake.coverage')`.

The gap reasons a poll can file, and where each one comes from:

| Reason | What happened |
|---|---|
| `job-logs-not-wired` | no log reader at all (the seam was never handed over, or `--read-only-logs`) |
| `job-log-absent` | the reader is wired and this run had no log body to hand over |
| `job-log-unreachable` | the log endpoint never answered (`JobLogClient`'s no-response shape) |
| `job-log-status-<code>` | the log endpoint answered with an error status, including a 3xx it will not follow |
| `job-log-truncated` | the tail was kept and the head dropped, so the fingerprint is of a partial log |
| `job-log-empty` | the endpoint answered 2xx with nothing in the body |
| `job-log-unreadable` | every character of the log was scrubbed away, so there is nothing to show |
| `job-list-absent` / `-malformed` / `-unavailable` | no job array reached the parser / it refused the parse / the walk could not be read |
| `job-id-absent` | the run has no job object to ask a log about |
| `timestamp-unavailable` | the run carried no usable instant, so the poller's clock was used |
| `queue-time-from-job-created-at` | the run-level queue stamp was absent and a job's was used |
| `run-path-without-ref`, `run-ref-outranks-*-evidence` | the ref the path carried said something the branch/event did not |
| `actions-read-failed`, `scan-page-budget` | the page walk could not finish (the gap is about the walk, not a run) |
| `open-run-refresh-failed`, `open-run-vanished` | the below-cursor refresh could not ask, or the forge no longer has that run |

A run whose every read failed cannot flood the poll: `MAX_COVERAGE_EVENTS` (three per run, in the order
the parser met them) bounds how many notes one run may *file* in a poll -- see "A gap that persists stays
open" for why it does not bound what the poll knows.

A run row this poll could not parse at all is refused (`run-malformed`, one durable refusal row naming the
field, and no verdict and no card for that run) -- but it **still carries the notes its reads collected**.
The job list and the log are asked for *before* the row is parsed, so a run whose `head_sha` is not a commit
id still proves the job endpoint never answered. Those notes travel on the refusal and hold the gaps they
name open, on this poll, exactly as a parsed run's notes do; the row itself is not a read that came back, so
it licenses no closure -- a gap its reads met is not one this poll has read healed.

What that row is *not* is a verdict, and the two uses are separated on the fact itself
(`facts.RunFact.read_complete`, false on a refusal carrier). Carried coverage is knowledge, and it holds a
gap open; a *read that came back* is the licence for closing one, and a row this poll threw away is not
that. Handing the carrier to the planner as a verdict would read it as a starved run filed under a
workflow identity no build can ever match -- unrecoverable by any green run, and re-firing on every poll
that refused it -- so `plan_incident_keys` refuses it outright (`A refused row is coverage, not a verdict:
pass it in `read_facts``) rather than deciding a page from a row the parser threw away.

### Verdicts the platform never took

A poll decides verdicts; the platform admits them or does not. Whatever it did not take is kept in the
state file's `verdicts_pending` table -- the canonical event itself, the marker move it was going to make,
the reason it was refused, and how many times it has been offered:

* **Re-offered** on every later tick until some poll speaks about that condition again or a receipt admits
  it, and no further once either of the two bounds below is reached. The *event* is stored rather than
  re-derived because the fact behind it is behind the cursor by then and `record_facts` will not call it new
  again; the stored body is written as canonical JSON, so the retry is byte-identical and `Store.intake`
  never sees it as a changed retry.
* **Superseded, not repeated**: a poll that has just spoken about a condition retires what it said before.
  A firing that never landed and a newer green run therefore produce the closure the newer run proves, and
  no stale page about a build that is now green.
* **Written before the send, not after the answer.** The row for a verdict exists in the state file before
  the request that may deliver it is made, and the receipt then retires it in the same commit that claims
  the marker (`store.record_incident_keys(claims, now=, drop=)`). Either half of that on its own loses a
  page: a store that fails between the send and the write used to leave the platform holding an incident
  this source had no record of owing, and the fact behind it was behind the cursor. Written first, that
  failure leaves the verdict owed, the next poll offers the same bytes, the platform answers `duplicate`
  -- which is an answer -- and the marker is claimed from that receipt.
* **Bounded four ways.** One row per `(subject, rule id)` -- a workflow that stays red through a long
  outage waits in one row, not one per build -- at most `PENDING_VERDICTS_BOUND` (200) subjects waiting in
  total, and two ceilings on how long one row may wait (`store.expire_pending_verdicts`, checked before
  every poll offers anything):
  * `PENDING_MAX_ATTEMPTS` (12) offers. An event refused for a property of the *event* -- a window ending
    in the future, which is what a skewed clock produces -- is refused identically on every retry, so a
    row offered twelve times has been proved unwanted rather than delayed. Twelve offers is a full hour of
    a five-minute schedule. An **offer** means a poll that had a platform to answer it: with no platform
    wired (`--platform-url` absent, the ramp-up order this page recommends), `not-configured` is not a
    refusal and the counter does not move. An unwired poller therefore keeps its backlog until the
    lifetime ceiling below retires it, and the report never says a verdict was "offered twelve times and
    never taken" to a platform that did not exist to take it.
  * `PENDING_EVIDENCE_LIFETIME_DAYS` (15) past the evidence's own expiry, which is the instant the event
    itself claims: `detections.event` stamps every reference with `expires_at` fifteen days after the
    window ends, and the ceiling reads the window, not the clock of the row. Re-offering an event past
    that instant would page about a window whose proof the platform has already discarded. An event with
    no window to measure is never retired by this ceiling -- only by the attempts above.

  A row that leaves the table is named in the tick report (`abandoned[]`, with the reason, the attempt
  count, the poll that decided it, and what this poll sent for that pair instead) rather than disappearing
  from a count. Three routes put a row there: the attempts ceiling, the lifetime ceiling, and the
  `PENDING_VERDICTS_BOUND` table bound -- a poll deciding more distinct incidents than the table holds
  gives up on the rows that had waited longest (newest-decided first, and where a single flood leaves every
  row decided at the same instant the tie is broken by key, which is an ordering nobody chose deliberately)
  and says so on the report line
  (`the pending-verdicts table holds at most 200 rows`) rather than letting `pending_verdicts` sit flat at
  200 while pages leave. Two fields carry what this poll did about the pair, and both are the planner's
  answer and not the store's: `reoffered` is true when this poll sent the same condition again as a
  `firing`, and `withdrawn` is true when this poll took the condition back -- it sent the `resolved` (or the
  pull-plane answer) for that exact pair. A row whose pair this poll said nothing about has both false: the
  condition went unsaid, which is a third thing and is not reported as either of the other two. One entry
  per pair, even where the bound dropped a row before the send and dropped the same pair again in the
  restatement after it: two drops are one lost page. A verdict about a run this store has already passed is
  gone (`reoffered` false, `withdrawn` false), and the tick that retires it is the last tick that
  mentions it -- a monitor reading exit codes sees `3` for the twelve
  refused polls and `0` from then on, which is the difference between an outage to fix and a permanent alarm
  about a pipeline that is working. **A gap this poll is still reading is the exception** (`reoffered`
  true): the row
  it just deleted was the only thing telling the planner that condition had already been said, so the same
  tick files a fresh `firing` for it with a window ending now, and the exit code stays `3` for as long as
  the reads keep landing. That is the honest reading rather than the quiet one -- the gap really is still
  there and the platform really is still refusing it -- but it means the attempt bound frees the exit code
  for verdicts this source can no longer re-decide, not for a broken endpoint it can. What is not done for
  you: the verdict itself is gone, so an operator who wants it filed has to fix why it was refused (or the
  clock) and wait for the next failing run of that workflow to re-decide it.
* `prune` never touches it. Neither does it touch the markers: both are the answer to "is this still
  owed?", and a retention job that deletes that answer cancels a page nobody declined.
* A pull-plane verdict filed under `unknown` opens nothing, so a refusal there is not kept: it costs a row
  in the platform's own event table, not a page nobody would be sent.
* The printed report counts them: `pending_verdicts`. A tick that admitted everything reports `0`; a
  ramp-up deployment with no platform wired reports every verdict this poll decided, which is the number to
  read before wiring one. Verdicts this tick gave up on are counted separately in `abandoned_verdicts` and
  listed in `abandoned[]`; they are no longer owed, and they are the reason `pending_verdicts` can fall to
  `0` without any receipt admitting anything.

## Store contracts an operator and the caller both read

* `record_facts(facts, cursor=, now=, outcomes=)` returns **`[(RunFact, outcome)]` that were new** — a
  list of pairs, not a count. The send path runs on that novelty: a fact re-read after a restart comes
  back absent from the list, so it is never admitted or planned twice.
* `record_incident_keys(transitions, now=, drop=)` applies **only** the marker moves a poll's receipts
  justified, and it is called after the send -- in the same commit that retires (`drop`) the owed rows those
  same receipts answered for, because a marker claimed without its row retired re-offers a verdict the
  platform already took, and a row retired without its marker claimed loses the closure a green run depends
  on. It never moves `open` backwards except to zero, which is what a closure means and which a caller says
  by handing over `open_run=0`: a replayed old verdict arriving after a newer one was admitted would
  otherwise let a green run close an incident the newest failure still owns, and a transition naming both
  halves at once does not get to lower `open` on the strength of its `closed` half. `incident_key_states()`
  reads the markers back, including the reserved `ci.intake.coverage` subject that carries this source's
  open gap reasons.
* `pending_verdicts()` / `record_pending_verdicts(rows, now=, counted=True)` / `drop_pending_verdicts(pairs)`
  / `expire_pending_verdicts(now=)` are the verdicts the platform never took, as the canonical event plus
  the marker move it owes. `counted=False` restates a row with the answer that kept it -- the placeholder
  written before the send is the offer, and `attempts` counts offers, not writes.
  `expire_pending_verdicts` applies the two waiting bounds above and returns what it retired; it is called
  by the poller, not by a retention job. `record_pending_verdicts` answers with `written` (the rows this call
  wrote itself) and `evicted` -- the rows the bound had to give up on, in the abandoned shape above, selected
  in the same transaction that deletes them, so a caller can report what left rather than infer it from a
  count that stayed the same. `prune` never touches that table, the markers, the filings or the
  delivery journal.
* `WindowStats.run_ids` is **ascending**, whatever order the rows were written in: it is a set summary,
  it is stored on the delivery row, and the comment batch token is derived from it. An order that moved
  under a replay would move the batch key with it.
* `run_detail(repository, run_id)` answers with the run's **newest** recorded event (`ORDER BY
  recorded_at DESC, event_key`). A run can own two `runs` rows — the unfinished event and the finished
  one — so an unordered lookup used to answer `waiting` for a run whose failure had already been
  ingested. It also has to select `run_id`, which it reports back: its `SELECT` used to omit the column
  and the method raised `IndexError` for every caller.
* `check_heartbeat` reads and never writes. `judge_lapse` (the independent monitor) and `record_success`
  (the poller's own recovery) both write the lapse row *before* the heartbeat moves, keyed by
  `digest(['lapse', last_success_at])`. `ON CONFLICT DO NOTHING` keeps the table at one row per gap, and
  `record_success` reports a lapse **only when its own insert created the row**: a gap an independent
  monitor already judged is not reported twice by the returning poller, and one outage produces one
  alert. The `lapses`/`unreported_lapses` readers stay write-free.

## What one `--once` reports

The JSON is the same shape with or without an outlet, so a log collector can read it either way:
`scanned`/`recorded`/`refusals`/`cursor`/`complete`, `planned` and `drained` (both `null`/empty with no
board), `events`, `keys`, `resolved`, `superseded[]`, `admitted`, `refused`, `refused_answered`,
`platform_admission` (`admitted`, `not-configured`, `mixed`, `refused` or `no-events`), `pending_verdicts`,
`abandoned_verdicts` / `abandoned[]` and `receipts[]` -- one entry per event with the record id the platform
named, the status the event carried (`firing`, `resolved` or `unknown`) and the reason the platform gave.
"The platform has it" is a claim about an answer this process received. Each `abandoned[]` entry is one
verdict this source stopped owing (`key`, `rule_id`, `event_status`, `attempts`, `decided_at`, the `reason`
that retired it, and `reoffered` / `withdrawn` -- whether this same poll said that condition again as a
firing, or took it back with a closure, which a gap the poller is still reading always does the first way),
and it is in the report because a page that will never be sent is news.

`events` is not bounded by `recorded` in either direction, and a reader that expects it to be will misread
both a quiet tick and a busy one. It counts one **verdict** per (`repository`, workflow, plane) per rule --
so five failing runs of one workflow are five recorded facts and one verdict -- **plus** at most three
coverage notes per run, coalesced to one event per gap reason for the whole poll. A poll of three starved
runs carrying three gaps each is nine coverage events and three verdicts over three new facts; a tick that
only re-offers a verdict the platform never took reports events with nothing recorded at all. Read
`keys` for the width claim, `receipts[]` for the send claim.

`refused` is `events - admitted`, which counts an event nobody was wired to receive. `refused_answered`
counts only receipts carrying an answer that was not admission -- it is what `--once` exits `3` on, because
"the platform said no" and "there is no platform" need different actions.

`recovered[]` names a run this store had already reported as starved that arrived with a non-failing
verdict. Each entry carries the incident key it belongs to and an `incident_statement` saying what was
handed to the platform about that incident:

| `incident_statement` | What it means |
|---|---|
| `{"sent": true, "reason": "resolved-offered"}` | this poll offered the `resolved` event for that key |
| `{"sent": false, "reason": "recorded-not-opened"}` | the starvation was a pull-request build: recorded under `unknown`, and nothing was ever opened to close |
| `{"sent": false, "reason": "open-not-closed"}` | this store's marker still says the key is open and this poll closed nothing -- what a refused closure and an incident closed by hand both look like from here |
| `{"sent": false, "reason": "nothing-known-open"}` | no marker under this key says anything is open -- which, since markers are claimed from receipts, is also what a starvation the platform was never offered looks like |

What the platform did with an offer is always the receipt's claim, printed beside it: this table states
what was offered, never what landed.

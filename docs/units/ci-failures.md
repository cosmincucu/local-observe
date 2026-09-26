# Unit: CI failure ingestion (`local_observe/ci_failures`)

**File(s):** `local_observe/ci_failures/{transports,store,facts,adapter,outlet,pipeline,cli}.py` ·
**Tests:** `tests/test_ci_failures.py` (offline: injected transports, `SocketGuard` patches the network
stack off) · **Config:** `LO_CI_REPOSITORY`, `LO_CI_STATE_DIR`, `LO_CI_MAIN_BRANCHES`,
`LO_CI_STUCK_AFTER_SECONDS`, `LO_CI_HEARTBEAT_DEADLINE_SECONDS`, `LO_CI_MAX_PAGES`, `LO_CI_PER_PAGE`,
`LO_CI_MAX_OPEN_RUNS`, `LO_CI_FILE_CARDS`, `LO_CI_CARD_*`, `LO_CI_RUN_LINK_BASE`, `LO_CI_SEED_CURSOR`

Reads one repository's Actions history, folds it into incidents, and files or updates board cards. Two
scoped clients (GET-only Actions, board reads plus `POST /issues` and `POST /issues/N/comments`), one
durable state file, one heartbeat and one outlet journal.

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

## Store contracts an operator and the caller both read

* `record_facts(facts, cursor=, now=, outcomes=)` returns **`[(RunFact, outcome)]` that were new** — a
  list of pairs, not a count. The send path runs on that novelty: a fact re-read after a restart comes
  back absent from the list, so it is never admitted or planned twice.
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

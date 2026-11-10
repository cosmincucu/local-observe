# Changelog

## Unreleased

Built-in scheduled investigations retain redacted evidence, bounded model/source work,
independent feedback and corrected-case retrieval. Guided setup produces a reviewable
plan and applies it through a separate trusted runner. Optional Telegram delivery
requires measured quality, human acceptance, its own daily budget and reconciliation
after restart or restore. Recording is the default.

Load-balanced model gateways can use a protected route declaration to retain bounded per-call
member receipts without changing routing. Unknown versions stay unknown; pooled quality acceptance
is explicitly unavailable. Existing single-deployment records and evaluation remain supported.

CI failure ingestion now runs as an incident source: `python -m local_observe.ci_failures --once` with
no board configured reads, records and reports a failing build without filing anything anywhere, and
with a platform endpoint and a `gitea_ci` producer credential it posts the event there, so the failure
becomes an incident in platform state. Board filing stays off unless a board is named and filing is
asked for; asking to file cards with no board is refused rather than run silently. The failing job's log
is read by default, and `--read-only-logs` turns that off.

An incident from that source is now as wide as the workflow, not the run: one incident per repository,
workflow file and plane, so a page of failing runs of one workflow is one verdict naming every run it
folds instead of one event per run (and no longer a refusal from the platform for offering one record
twice with different contents). A failing pull-request build is recorded and opens no incident; a failing
run of the default branch opens a critical one, and any other plane a warning; a starved run opens one
incident per workflow as before. A completed successful run newer than that workflow's last failure now
sends the `resolved` event that closes the incident it opened, at no extra cost in source requests, and
the tick report adds `keys`, `resolved` and `superseded` beside `events` and `receipts`. A `resolved` for
a key the platform never opened is accepted as the no-op it is. A build of this outlet from before the
change may hold incidents that this source can no longer reach, because the closure names the workflow
and not the run; those are closed by hand.

How loud a failure is follows the ref and not the trigger: a scheduled run of the default branch is a
main-plane failure and pages `critical`, and only a schedule on some other branch is a `warning`.
A gap in what the poller could read is a condition that opens and closes like any other: one coverage
event per gap reason per poll, its window folded across every run that carried it, and a later poll whose
own read came back without that gap sends the `resolved` that closes the incident -- including a poll the
quiet repository left nothing to read, whose walk finished and asked and got no gap. A gap that persists -- a log
reader that is still not wired, an endpoint that answers 3xx and will not be followed -- stays open
however many builds pass. A gap that is already open says nothing further: one `firing` is the whole page
(and a firing still owed to the platform counts as said), so a later poll carrying the same reason files no
second event -- the gap note keeps landing on every run it applies to, which is what makes a card coarse
and what that card quotes, so a gap that will not heal stays visible without being re-paged every five
minutes. Whether a reason is still carried is read from every note of every run the poll read (a run that
owes no verdict still carries one, and a note past the three-a-poll filing cap is still in this process's
hand), and a gap that healed while the platform was down is closed by the poll that reads it back rather
than opened one poll late by the replay of the firing it never sent. A refused *closure* is kept and
re-offered neither: unlike a verdict it is re-derived by every later poll whose own read came back -- a
poll that read a clean build, and the poll a quiet repository leaves nothing to read -- and a
stored closure replayed into a poll that is reading the gap again tells the platform a recovery that did not
happen, re-pages the operator when it re-fires, and clears this source's own memory of the gap. A closure
that is nevertheless *found* in the state file -- one left by an earlier build, or one whose marker an
operator deleted along with the rows a documented cleanup named -- is decided by the poll that reads it: sent
when nothing it read carries the gap, retired and named in the report when the gap is back in this poll's
hands, and held -- neither sent nor given up on -- when this poll's own read did not come back.

Nothing is now remembered as sent that was not. An incident marker is written only from a receipt that
came back admitted, and a verdict the platform never took -- because no credential was wired, or because
the answer was a 503 -- is kept in the state file and offered again on a later tick until something answers
or a newer verdict supersedes it. Wiring the platform after a failure, or losing it for one tick during
one, no longer costs the break its incident. The marker for a key never moves backwards except to zero, so
an older run that settles late cannot let a green build close a newer failure. `--once` exits `3` when any
receipt came back refused, including a poll where some other event was admitted, and a refused receipt now
carries the platform's own stable `error` code (never the response `detail`, which is a rendered exception
message and can echo a credential). The report adds `pending_verdicts` and `refused_answered` beside the
counts it already carried. What it waits for is now bounded as well as kept: a verdict that has been
offered twelve times, or whose evidence has passed the fifteen-day lifetime the event itself claims, is
retired instead of re-offered forever, and named in the report (`abandoned[]`, `abandoned_verdicts`). Twelve
offers means twelve polls that had a platform to answer them -- with no platform wired the rows wait, and
only the evidence lifetime retires them, so a deployment following the documented ramp-up order does not
throw an hour of breaks away as "offered twelve times and never taken". Each entry also says whether this
same poll said the condition again (`reoffered`): a verdict about a run the store has passed is a page that
will not be sent and the exit code frees, while a gap the poller is still reading is filed afresh on the
tick its row is retired, so the bound stops a permanently unsendable verdict rather than silencing a gap
that is still true. The field says what this poll *sent* for that exact pair, and a pair this poll took
back -- a `resolved`, or the pull-plane answer -- is said with its own word (`withdrawn`) rather than being
reported as re-offered. The third way a row leaves the table is now named too: a poll that decides more
incidents than the table holds (200) used to shed the extra rows while `pending_verdicts` stayed flat at
200, which is the difference between a backlog an operator can size and one that quietly walks out of the
state file. Those rows arrive in `abandoned[]` with the bound as their reason, once per verdict. Without
that bound one event this platform will never take -- the shape
a clock skewed into the future produces -- held every later tick at exit `3` and re-filed an incident whose
proof had already expired. An owed row is now written *before* the request is made and retired in the same
commit that claims the marker it was offered with, so a store that fails between the send and the write
leaves the verdict owed and the next tick converges on the platform's `duplicate` answer. A state file this
process cannot use -- a read-only or missing directory, a locked or corrupt database -- is the refusal the
CLI already documents (exit `4`, one line on stderr) instead of a Python traceback.

A run row this poll could not parse is now coverage rather than a verdict. It keeps its durable refusal,
its `run-malformed` reason and its exit code, and it no longer stands in the planner as a starved run under
a workflow identity no build can ever match -- a shape that filed a page no green run could close and re-fired
it on every poll that met the same broken row. The notes its own reads collected (the job list that never
answered, the log that answered 3xx) are still this poll's knowledge: they hold their gaps open, and they are
not counted as a read that came back: the gap that row met is not reported healed beside a passing
neighbour, and no stored closure is re-sent on a tick that left a row unparsed. The refusal itself keeps its
existing shape -- the `refusals` count and one durable refusal row naming the field, and no change to the exit
code, which answers whether the source and the platform answered rather than whether every row parsed. A poll
that read only refused rows therefore files no verdicts at all,
and the gap next to that row stays open beside a thousand passing builds.

The evaluator compares the actual observer with deterministic baselines and preserves
unknown labels and incomplete coverage. Synthetic validation does not establish live
model quality, hardware fit or human review workload.

### Operator actions

- Route receipts are opt-in through `LO_OBSERVER_MODEL_ROUTES`; follow the protected declaration
  format in the [observer walkthrough](docs/units/observer.md). No journal migration is required.
  Keep older declarations with configuration backups to interpret historical digests.
- Optional platform settings: `LO_GUIDED_SETUP_ROOT`, `LO_GUIDED_SETUP_RUNNER` and
  `LO_TRUSTED_RUNNERS_FILE`; see [guided setup](docs/units/guided-setup.md). No settings
  are renamed or removed. Observer settings and optional provider/version labels are
  documented in the [walkthrough](docs/units/observer.md).
- Optional CI-ingestion settings: `LO_CI_PLATFORM_URL` (or `--platform-url`) with a producer credential
  in `LO_CI_PLATFORM_TOKEN_FILE`, and `LO_CI_BOARD_URL` becomes optional. No state migration: a state file
  written before this change opens as-is and gains one table (`verdicts_pending`) on first open, and the
  `--once` report gained `receipts[]`, `recovered[]`, `pending_verdicts`, `refused_answered`, `abandoned[]`
  and `abandoned_verdicts`, whose entries now carry `withdrawn` beside `reoffered`. In-process callers of
  `store.record_pending_verdicts` read `written` and `evicted` off its answer instead of an integer. A run with
  no board still reports `platform_admission: not-configured` until the platform is named. Two behaviour
  changes an existing monitor has to be told about: a poll with any refused receipt exits `3` where it used
  to exit `0` when some other event was admitted, and a verdict the platform never took is re-offered on
  later ticks, so a tick's event count can be non-zero with nothing recorded.
  **Markers written by an earlier build are unverified, and upgrading does not repair them.** A build of
  this outlet that claimed a marker at the moment it *intended* a send may hold `meta` rows saying `open`
  for incidents the platform was never told about; nothing can tell those rows from honest ones after the
  fact, and no code rewrites them. An operator who wants the markers to mean what they now say stops the
  poller and deletes them in the state file:
  `DELETE FROM meta WHERE key LIKE 'incident-key:%' AND key <> 'incident-key:ci.intake.coverage';`
  and lets the next polls rebuild them from receipts. What that costs is a closure that can never be sent,
  not one that arrives late: the green run that would close an incident needs the `open` stamp that
  statement deletes, so an incident the earlier build really did deliver has to be closed by hand -- and the
  coverage subject is excluded from the statement for the same reason, because a gap that healed before the
  upgrade is closed by the next poll that reads it gone and needs its marker to do it. An operator who went
  further and deleted the coverage marker as well is no longer stranded: a stored closure that outlives that
  cleanup travels on the next poll whose own read came back, so an incident the older build opened is closed
  without a hand on it. Leaving the rows
  alone keeps every closure available and keeps the unverified `open` claims. See
  [CI failure ingestion](docs/units/ci-failures.md).
- Migrate existing platform state explicitly to schema 10 using
  `lo-platform --database /approved/private/platform.db migrate`, after a fresh verified
  backup and isolated rehearsal. See the [upgrade procedure](components/control/platform/upgrade.md).
  Observer journal schema 1 uses a separate owned private directory outside Git.
- Build and pin new first-party platform/MCP images from the accepted source revision.
  No published image or changed third-party image/compiler pin is supplied here.
- No rule recompilation or dashboard re-import is required by this change. One option was added to the
  shared HTTP client (`local_observe/http.py`, the `JsonClient` the observer, the platform CLI and the other
  units use): `JsonClient(..., error_body=True)`, off by default and bounded to 8 KiB of response body.
  Every existing caller keeps the answer it was written against, and the CI platform transport is the one
  caller that now reads a refusal's stable `error` code off the response body instead of reporting only its
  status. See [CI failure ingestion](docs/units/ci-failures.md) and the dependency map.
- Observer and runner services need explicit commands. Compose `command`, `entrypoint`
  and healthcheck `test` replace existing values; inspect the rendered configuration.
- Rollback requires the previous accepted image plus a compatible verified state,
  configuration and journal checkpoint. Keep dispatch off while reconciling external
  effects; an older backup must not silently re-arm actions or notifications.

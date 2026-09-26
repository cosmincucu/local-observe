# Platform

Durable operator state and explicit integrations. The `lo-platform` CLI exposes
the available server/worker commands; `api.create_app` builds the core ASGI app.

- `state.py`, `policy.py`: SQLite transactions, roles, idempotency, approval and
  execution transitions, audit and the notification outbox.
- `crowdsec.protected_schema`: action-policy exclusions retain every protected IPv4 network when
  an IPv6 entry adds the conservative refusal of all IPv6 values. `protected_from_definition` checks
  both families and rejects missing, changed or weakened exclusions. Both apply and remove proposals
  use this schema; containing-range limits remain in the [component contract](../../components/control/crowdsec/CONTRACT.md).
- `verification.py`: the post-action verdict (`cleared`/`not_cleared`/`unknown`) — exit zero alone is not recovery; off unless `LO_VERIFY_CONFIG` names a file, files evidence only; execution-linked records, their CLI, saved-history UI and follower are separate units ([unit README](../../docs/units/verification.md)).
- `verification_records.py`: the verification workflow's storage slice — the policy that says which detector revision a
  signal *means*, the binding captured inside a proposal's own transaction, and the durable submitted
  observation with the verdict this server derives (`Store.verification_policy`,
  `Store.get_verification_binding`, `Store.put_verification`, `Store.get_verification`). Off unless a
  `Store` is handed a `VerificationPolicy`: off is write-off, reads still answer. The module itself reads no
  environment value and owns no route, role, scheduler or portal field — the loader is `verification_policy.py`,
  the routes are `verification_api.py`, and the operator's terminal client is `verification_cli.py`; none
  of the three moves what this module judges. A stored `cleared` is a verifier's claim this
  server found consistent with the captured read, **not** proof that a remote read happened
  ([unit contract](../../docs/units/verification-records.md)).
- `verification_candidates.py`: listed-producer-only, read-only candidate pages for the
  [follower](../../docs/units/verification-follower.md). It scans bounded execution-ID pages,
  returns bound terminal executions with no accepted record, and adds no schema or claim.
- `verification_follower.py`: an opt-in HTTP client that saves one post-terminal observation
  before submission and replays it unchanged after a lost acknowledgement. The server derives
  the verdict; any accepted result ends automatic observation for that execution. No incident
  resolution, redispatch or deployment is implied.
- `verification_cli.py`: the **HTTPS-only operator client** for the four record operations —
  `verification` with one of `binding`, `records`, `record` or `submit` under `lo-platform` /
  `python -m local_observe.platform.cli`.
  At most one request per invocation, one mounted `--token-file`, one `--statement` file for the write, no
  local database, no retry, no local grading, and no credential on a command line or in the environment
  ([unit contract](../../docs/units/verification-cli.md)). Unlike the local operator commands, this group talks
  to a remote service without opening the SQLite file.
- `detections.py`, `detection_worker.py`, `sigma_*`: detector adapters and cursors.
- `assertions.py`, `certcheck.py`: [named synthetic checks and certificate stages](../../docs/units/synthetic-assertions.md), with bounded evidence and injected certificate facts; Gatus owns network probing.
  `sigma_compile.compile_rule` validates operator parameter declarations as authoring metadata;
  it does not bind their inputs. The public shipping `build_gate`, used by the CLI, refuses any
  nonempty declaration until input binding exists, including both `deny-all` and `refuse-to-build`.
  Parameter-free artifacts and SQL still build unchanged; the pinned compiler tier verifies both
  missing-input refusals and the committed artifact comparisons.
- `crowdsec.LocalApi`: read-only decision queries. A bare host passed to `decisions(cidr=...)`
  uses `/32` for IPv4 or `/128` for IPv6; equivalent address spellings send the same query.
  Explicit prefixes retain their width, and `ip=` filters remain bare addresses.
- `vocabulary.py`: the one severity/`kind` crosswalk (`severity(source, value)`,
  `classify(source, event_type)`) — producers cite it and never spell a severity literal; an unmapped
  word raises, and the table plus every refusal and its reason are in [docs/CONTRACTS.md §4.1](../../docs/CONTRACTS.md).
- `conditions.py`, `dynamic_bands.py`: the sustained-alert layer **above** `detections.py`, read through
  `lo-platform conditions` (one round; no looping producer exists yet). A rule says how long a state must
  hold before it is a finding (`for_seconds`, with `resolve_seconds` for the clear side), so a value that
  bounces across its threshold is one condition instead of several; `mode: "band"` rules replace a static
  number with the learned bands in `anomaly.py` (`train`/`detect` are reused, not re-implemented) and
  answer `insufficient` out loud while history is too thin to judge. Absence rules (`mode: "absence"`, one
  deadline `within_seconds`, and a rule that also sets `for_seconds` is refused rather than ignored) fire
  when a source stops producing at all; they are filed under the `coverage` event kind, and stale or
  missing input on any other mode is reported as `coverage` and never as a recovery. Like `anomaly.py`,
  off unless a document is named; state lives in this
  producer's own cursor, and the two disagree with a refusal rather than double-firing or silently
  restarting a timer.
  `interval_seconds` sets the schedule and cursor grid. Each rule floors that schedule end onto its own
  `evaluation_seconds` grid and uses that one instant for the query cutoff, the verdict, the coverage
  event a round files when it could not judge, and the `<rule>.coverage` companion a complete absence
  round files beside its absence verdict. With 900/600 seconds, a 12:15 schedule position reads and
  judges at 12:10.
  The point bound is on the round, not only on a page: 2 000 points is at once the
  store's page and the span a verdict may be built over, so the retry composes *under* it and stops where
  the span outruns the evaluator — a dense series comes back empty and `truncated`, with the reads it
  really spent, and never as a newest tail trimmed into a verdict. A `truncated` read is inability to judge
  and not a shorter memory to grade anyway: the store answers a full page with its *oldest* rows, so the
  fresh tail a run is dated from is the part that is missing, which can hide a firing period outright and
  not merely delay one. The round names such a rule `unreadable` beside its `truncated` list and files its
  `coverage` event with the reason — the shape a blind SLO burn and an `insufficient` band already have —
  and nothing about the condition itself, not a threshold verdict and not an absence rule's assertion of
  absence, so an incomplete read cannot recover what a complete one opened. The coverage event an
  incomplete round files is dated at that rule's own cutoff, the window the withheld verdict would have
  carried, so one rule per round names one window whether or not it could judge. Complete absence rounds
  also resolve the separate `<rule>.coverage` companion, even when the signal itself is absent; reader
  recovery must not leave its warning stuck open or hide the absence condition. Every other rule is still
  judged, delivered and acknowledged, and the cursor moves.
- `local_observe/forecast/` (a package beside this one, forecast): trend models and time-to-threshold
  predictions. It reuses this package rather than adding a layer — `conditions.SustainedStateMachine`
  judges it and `conditions.tick` drives its round — and it files `kind: threshold` under
  `<rule>.predicted`, so "will exceed" and "has exceeded" are two conditions to `Store.intake`. Off
  unless `LO_FORECAST_CONFIG` names a file — which is also the variable `lo-platform forecast` reads when
  no `--config` is given, so the worker and the one-shot round share one switch and one cursor; off is
  one `INFO` line and exit 0 (`tests/test_cli_slo_forecast.py`).
- `../slo/` (error budget, a sibling package): SLO objectives, error-budget attainment and the multi-window fast-burn condition, judged by the `for:` machine above and off unless `LO_SLO_CONFIG` names a document. It has two entry points and one state: `python -m local_observe.slo` loops and posts `/v1/events`, while `lo-platform slo` runs one round straight into the store in front of the operator, and both read `LO_SLO_CONFIG`/`LO_SLO_CURSOR` unless a flag names another file (`tests/test_cli_slo_forecast.py`), because one producer holding two cursor files can re-judge a window the other already delivered and a re-judged window is a new verdict rather than a duplicate the platform can fold; a window too thin to measure files `coverage`, never an attainment. Its round uses the same per-objective query/verdict cutoff described above: one instant is the read cutoff, the burn verdict and — when the read came back short — the coverage event that says so, while the cursor keeps recording the schedule grid. Its worker loop re-reads that cursor from disk inside `exclusive_owner` **before every round** — including the round after a transport refusal and the one after an event was accepted but its acknowledgement was lost — so the batch `alerts.tick` saved is the only thing the next round may deliver, and a stale in-memory copy can neither re-query a window nor overwrite the exact bytes still owed (`tests/test_slo_worker_replay.py`); a cursor that turns unreadable, foreign-version or bound to another rule set mid-run is refused on every round with one `WARNING` naming the exception class, no query and no POST, and left byte-for-byte as found — only an operator reconciles it.
- `rca.py`: the rule floor under an optional model, run by `lo-platform rca` (investigation component / port rca).
  Three parts, in the only order that keeps the honesty claim true: **bundle** the incident through
  existing read APIs only (`Store.records`, the Inventory read path, one fixed read of the incident's own
  rows out of `events` by its `incident_id` — one bound UUID and one bound row ceiling, which is
  membership and not a query of anybody's telemetry — and `query.reauthorise` for every
  evidence reference — never a direct read of the `evidence` table and never a store client, because
  `reauthorise` is the one function that *cannot* re-query a dead link to make it look alive, and a
  background component that re-implements the read weakly is the defect class retention collected);
  **floor** it with four ordered heuristics (`change-before-finding`, `baseline-break`,
  `earliest-upstream-finding`, `source-coverage-blind`), each carrying its tuning reason inside the
  `Rule` tuple; **explain** it, where a model may add prose and may not add or reorder a cause — the
  ranked set is built by `candidates()` and never touched again, this build applies **no** rerank
  because `json_mode` is an unmeasured capability, and `post_validate` drops any sentence whose uuid,
  number or dotted name is absent from the bundle text the model was actually shown, naming what it threw
  away (`discarded_fabrication`). No rule output means **no model call at all**. The durable output is
  one append-only `audit` row (`operation='rca.explained'`) holding the redacted minimum context —
  candidates, rule ids, citations, counts, digest — and no model prose and no telemetry sample value,
  so the row survives the retention window it cites without extending it. Off unless `--config` names
  a file. No table, column or environment variable is added. `rca_progress.py` gives every open
  incident a turn using a fixed rowid cycle and a source-specific cursor beside the database, owned
  exclusively for each tick. Each indexed read is at most the incident budget plus one lookahead and
  closes before analysis. Known per-incident refusals are visible and advance so other incidents run;
  page counts are labelled `count_scope: page`, and `capped` means more work in the current cycle.
  Cursor backup/restore and rowid-changing maintenance are documented in
  `docs/units/rca-progress.md`. What an incident *contains* is no longer a page question: `bundle()`
  reads its members through `events.incident_id` — the pointer `correlation` writes at intake and moves when a
  condition joins a group — under its own row ceiling (`MAX_MEMBER_ROWS`: the grouping module's member
  limit, plus the condition that opened the incident) and its own SQLite instruction budget
  (`MEMBER_READ_INSTRUCTIONS`), because an unindexed per-incident scan is the defect the bounded escalation history removed
  from `escalation.py`; schema migration 8 (below) is the index that read now runs on, and the budget
  stays for the case an index cannot serve — a file restored from a pre-v8 copy or one whose
  `lo-platform migrate` has not run. A member read that
  hits either bound is labelled, and never answered with a shorter memory: the 100-event window now
  bounds only the three recency channels (`neighbours`, `changes`, `baselines`), whose notes say so.
  The index that turns the read into a seek arrived as an `state migrations` `MIGRATIONS` decision and not a
  component one, which is migration 8's whole story below.
  One channel reaches outside the incident: `similar_past` reads the newest **resolved** incidents of the
  same `(rule_id, resource_id)` pair through one more budgeted, read-only statement (`SIMILAR_SQL` under
  `SIMILAR_READ_INSTRUCTIONS`), and carries incident ids and instants only — no payload value, no severity,
  no window — so it is "this rule on this resource has recovered before", never a resemblance somebody
  measured (`corpus eval`'s corpus is what would license that). An empty channel says which silence it is: nothing
  resolved on the pair, or the read stopped at its budget and says so (`tests/test_rca_bundle.py`).
  The five artefacts and the reason there is no `compose.yaml` are in
  `components/control/rca/CONTRACT.md`.
  The upstream heuristic requires a dated first incident member and an upstream finding
  observed at or before it. Later and downstream findings stay context; equal-time findings
  remain indicated, and the candidate resource identifies the selected neighbour.
  The incident view chooses each subject's newest matching explanation independently in
  batches of at most 200 identifiers. Other audit operations do not hide it, and each
  displayed cause matches that incident's individual latest-record read.

  Every rule bounds display prose to 140 characters before Candidate validation, adding
  an ellipsis when needed. Full producer rule/resource identities and citation links remain
  intact in the bundle, so valid maximum-length labels do not interrupt a round.

## Saved verification history in the operator UI

The UI's execution detail carries a **read-only verification history** section : it is absent
from every non-execution record, starts hidden and empty, and fetches nothing until the operator clicks
"Load verification history" (one `GET /v1/verification/records?execution_id=…`) and then one of the
returned ids (one `GET /v1/verification/record?verification_id=…`). What it renders is labelled
"Historical recorded result" and is exactly four stored fields — verdict, reason, observation window,
recorded time — with the execution's own status left untouched beside it: a `succeeded` run and a
recorded `not_cleared` are two separate statements, and nothing in this panel claims an incident
recovered, is re-graded, is re-run or is written to. Every state is its own fixed sentence — not loaded,
loading, none recorded, not permitted, absent, busy, unreadable, about-something-else, unavailable — and
no backend body, class name or path is ever echoed: the response is rendered through `textContent` only.
Every bound is a whole-field shape test, not a substring one — 64 characters for a record id, 36 for an
execution id, ids required to arrive in the lexical (never time) order the server returns them, a reason
that has to *be* a string before its characters are looked at, and instants that have to be real UTC
calendar moments in the stored form, with the window opening before it ends and the record stamped no
earlier than the window closed. A reply is dropped **before it does anything at all** — including signing
the operator out — unless it is the one this panel is still waiting for, under the sign-in that asked for
it, in a dialog that is still open (one generation counter, bumped on every request, id selection, close,
reopen and sign-out; the open-dialog test covers the moment after `close()` and before the close event
that bumps it). So a late answer cannot repaint a detail the operator left, and a 401 belonging to a
discarded request cannot log out the session now in front of the operator — while a 401 on the current
read still does. Reloading the list supersedes a record read that is still out: its in-flight flag is
cleared with it, so the panel cannot strand itself refusing clicks it no longer shows any reason for.
"This deployment mounts no verification policy" is not
"this deployment has no verification history": stored history remains readable with no policy mounted;
that setting disables new verification writes, not these reads. Actual read failures remain the server's
to report, not this panel's to guess at. Proof:
`python scripts/serve_operator_demo.py --background --fixture <new directory> 0` (a fixture it refuses
if it is not empty; with `--fixture` the child's two log files are created **beside** that directory,
because a log inside it would make the child refuse the fixture it was handed, and an existing log file
is a refusal rather than something to append to) and then
`python scripts/check_operator_verification_browser.py --fixture <that directory>`, which asserts the
races, refusals, both viewports and one hostile-string renderer case fed straight to the renderer (the
server's own rejection of that reply is asserted separately). `--negative-control outcome|stale|html`
is test-only: it serves a `ui.js` carrying exactly one reviewed mutation and **must** refuse to pass,
writing `verification-negative-control.json` and never the pass report. Plus
`tests/test_operator_verification_fixture.py` for what that fixture answers, refuses and leaves alone.

## Seasonal anomaly baselines (`anomaly.py`), off by default

`python -m local_observe.platform.anomaly` is another producer, not another kind of detector: it
learns what each series normally looks like at this hour and reports when it does not. It is a
module main rather than a `lo-platform` subcommand for the same reason the other long-running
workers are (`detection_worker`, `sigma_runner`, `overview_worker`, `job_worker`): it reaches the
store and the platform over the network and loops, while `lo-platform` is a one-shot operator command
that opens the SQLite file itself — the one worker-shaped subcommand it has, `notify`, delivers, and
this one must not. Points are
grouped into a seasonal bucket — `hour_of_day` (0..23) or `hour_of_week` (0..167) — and every bucket
learns `median ± k · 1.4826 · MAD`, where the scaled MAD is the usual σ estimate for normally
distributed data. A median and a MAD over a fixed list of points contain no randomness, so the same
history always yields the same band and the same verdict: there is nothing to seed and nothing to
relearn between runs.

Every verdict leaves through the `detections.event` factory as one canonical event per series per
evaluation window — `kind='anomaly'`, the resource from the series' declared UUID, and an evidence
sample holding the value and the instant behind the call. The producer pages nobody and reads no
delivery mode: what an anomaly event does to a human channel is the platform service's
`LO_NOTIFICATION_MODE` decision, exactly as it is for a Gatus result.

**Off is the default.** With `LO_ANOMALY_CONFIG` unset or blank the process logs one `INFO` line
naming the variable and exits 0: no loop, no connection, no invented baseline. A file that is named
but unreadable is the opposite case and exits 1 — a producer that quietly dropped the series it
could not parse would be reporting "nothing unusual" about a signal it never read.

### The knobs, what each one does, and what turning it down breaks

`LO_ANOMALY_CONFIG` names one JSON document. Shown whole, then tabled:

```json
{"series": [{"id": "demo-load", "resource_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2",
             "sql": "SELECT toUnixTimestamp(t) AS ts, avg(v) AS v FROM … WHERE t >= {start_s:UInt64} AND t < {end_s:UInt64} … FORMAT JSON",
             "sql_sha256": "<sha256 of the sql field, 64 hex>", "k": 3.0}],
 "k": 3.0, "window_days": 14, "min_points": 48, "min_per_bucket": 3,
 "season": "hour_of_day", "tick_seconds": 300, "evaluation_seconds": 300}
```

Every knob may be set once at the top level or per series, and a series value wins. Out-of-range or
unknown fields are refusals at load, never clamps.

| knob | default · bounds | what it does | off / turned down — what actually breaks |
| :-- | :-- | :-- | :-- |
| `k` | `3.0` · 1.0–20.0 | Band half-width, in scaled MADs from the bucket median. Also the escalation step: a point `k` MADs *beyond* the edge is `critical`, short of it `warning`. | Nothing to turn off; at `1.0` a healthy series fires on its own noise — roughly a quarter of normally distributed points sit outside a ±1σ band, so nearly every bucket reports an incident. Raising it is the cheap fix for a storm. |
| `window_days` | `14` · 1–90 | How far back the query reads: the training span. Not the event window. | Below ~8 days an `hour_of_week` season has fewer than one point per bucket and the producer goes quiet with `unjudgeable`. The bound that bites first is the shared 2 000-row result cap: 14 days supports roughly ten-minute resolution or coarser, so a finer series must either coarsen in SQL (`toStartOfTenMinutes`) or shorten this span. |
| `min_points` | `48` · 4–2000 | Training points required before the series is judged at all. | Below it the tick logs `insufficient` and posts nothing — that silence is the feature. Lower it and a series with two Mondays calls its own noise an anomaly; a busy install rarely wants this under 100. |
| `min_per_bucket` | `3` · 1–64 | Per-bucket floor. Thin buckets are named (`buckets_insufficient` in the log) and every point inside them is skipped, never judged normal. | At `1` one observation defines the band, so a single outlier becomes "normal" and — with zero spread — every later value reads as infinitely surprising (`critical`). At `3` the estimate is still crude; it is the port's floor, not a good one. |
| `season` | `hour_of_day` | Which cycle the buckets follow. | `hour_of_week` (168 buckets) needs ≥ 504 points to judge anything, so with the defaults (14 days, hourly) it reports `unjudgeable` and nothing else. Use it with a longer `window_days` and a coarser series. |
| `tick_seconds` | `300` · 60–86400 | The sleep between rounds — one round now covers every configured series, walking each one's owed windows up to the round's budget. It is also the `records_per_day` input in the log-volume table above, with the multiplier that table states. | Lowering it buys no accuracy and no earlier alert: with a retained coherent cursor a window is judged once and the next window opens on `evaluation_seconds`, not on this number (a window whose **read** failed before any payload existed is the exception, and is re-read on purpose), so a faster tick mostly writes `caught_up` lines and spends the owner lock. It is deliberately **not** part of the cursor's series binding — retuning how often the producer looks must not discard a backlog. Raising it is what a long outage costs in alert latency, because that outage drains one bounded round per tick. |
| `evaluation_seconds` | = `tick_seconds` · 60–6 days | The window that is judged *and* the window the event carries (`state.validate_event` caps any event window at 7 days, which is why 6 days is the ceiling here). Points inside it are excluded from training. | If it is shorter than the spacing of the series, most rounds find no current point and log `idle` — an hourly series on a 300-second tick is silent 11 rounds in 12. Set it to at least the point spacing. |
| `series` | 1–16 entries | The signals to watch. `id` becomes the rule name `anomaly.<id>`, so it must be a bounded label (`[A-Za-z0-9_.:-]`) short enough that the prefixed form stays under 128 characters; `resource_id` must be a **declared** UUID — an undeclared one refuses the round before any query runs. | Zero series is a refusal, not an off switch; the off switch is the absence of the file. |
| `sql` + `sql_sha256` | required | Reviewed SELECT text run through the Sigma runner's bounded client (`readonly=1`, 5 s, ≤ 2 000 rows, ≤ 64 KiB read). It must reference `{start_s:UInt64}` and `{end_s:UInt64}`, must end `FORMAT JSON`, and must contain no `;` and none of `outfile`, `s3(`, `url(`, `hdfs(`, `azure(`, `remote(` — the ways a read becomes a write or a request to somewhere else. Sigma needs no such list because its SQL comes from a pinned compiler; this text is typed by hand. | `sql_sha256` is the hex sha256 of the `sql` field — `python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '…'`. It refuses a truncated or hand-altered config, the same job the compiled Sigma artifact's checksum does; it is not a defence against someone free to edit both fields, and the real guard is the read-only query user on the store. |

The reviewed SQL has to alias its epoch-seconds timestamp as `ts` and its value as `v` (`SELECT
toUnixTimestamp(t) AS ts, avg(v) AS v …`), because `FORMAT JSON` answers with one object per row
keyed by the selected names and the pair is resolved by those names: key order is free, the two
aliases are not. A row with a third column, or missing either one, is refused — it is not the query
this producer reviewed. The two-number list row (`[ts, v]`) stays accepted for callers that build
their own points. The client refuses a row that is not two finite numbers, and any timestamp outside
the window that was asked for: a query that ignores its own bounds is a broken query, not a wider
baseline. A number the store answers as text (a quoted `UInt64`, a `Decimal`) is refused rather than
coerced — accepting it is a contract of its own, not a permissive read here.

### The cursor (`anomaly_cursor.py`): what a round owes, and what it refuses

Existing schema-1 files can be prepared for coverage with the explicit offline
`python -m local_observe.platform.anomaly_migrate` command. It defaults to dry-run,
requires an expected source digest, and applies only to a new destination under
the producer owner lock. It never enables the producer or rewrites its input.
See [the migration procedure](../../docs/units/anomaly-cursor.md#explicit-offline-schema-migration-275)
for backup, review and separate installation requirements.

The unit runs the producer once per interval and exits between runs, so the state that has to survive
that gap — "this window was judged, its evidence and its event are owed" — is a file: the JSON cursor
named by `LO_ANOMALY_CURSOR`. It is the only durable state this producer has, and the whole design is
one ordering rule: **both request bodies are on disk before either leaves the process, and the window
is acknowledged only after both answers arrived.** A `4xx`, a `5xx` and a lost socket are the same
event for the cursor — the batch stays pending, the position does not move, the refusal is counted in
the file and logged at `WARNING`, and the *stored* bytes are offered again next round. While that file
survives intact, a restart cannot forget an event the platform already accepted and cannot skip one it
never got; when it does not, see the restore note below, because the producer then behaves like a
producer with no memory. Re-sending **identical** bytes is what the store's dedup on
`(source, source_event_id)` (and on evidence `sample_id`) folds into one row rather than two — dedup of
identical bytes, and not a repair: a window re-*judged* after a lost cursor can come out differently,
and that is a second opinion, not a duplicate. `LO_ANOMALY_CURSOR` is read by
`anomaly_cursor.cursor_location` and is **not** part of the JSON document above, because the cursor is
not a tuning knob: a configured producer with no cursor refuses to start (one `WARNING` naming the
variable, exit 1) rather than deliver verdicts it cannot re-send, and "no configuration file" stays
the only off switch.

What the file holds: at the top, `schema_version`, the producer `source` and `last_served` — the
round-robin position, the name of the series given the last window attempt. Per series: the `binding`
digest of everything its stored verdicts are a statement about (`id`, `resource_id`, the SQL digest,
`season`, `k`, `window_days`, `min_points`, `min_per_bucket`, `evaluation_seconds` — **not**
`tick_seconds`, which is how often the producer looks, not what a window means), `last_acked_end`, its
first anchor, whether that anchor was already reported, the lifetime counters `delivered` /
`no_verdict` / `refusals` (which **saturate** at their ceiling rather than becoming a cursor that
cannot be written again, and therefore read as a **lower bound** — "at least this many" — in the
per-series row and the log line the moment one sits at the ceiling), `owed_end` (the window whose
**attempt** was recorded and never
acknowledged), and at most one `pending` batch: the window, the two payloads, and the sha256 of the
exact bytes `JsonClient` puts on the wire for each. Those digests are **corruption checks, not
authentication** — anyone who can rewrite the file can rewrite both numbers with it; nothing here
signs or seals anything.

Those last two are different debts, and the difference is the reason both exist. An owed **batch** is
replayed from stored bytes and never re-read: recomputing an old window after a crash can yield a
different value, a different instant, and therefore a different `sample_id` and event, which the platform
refuses as `Event retry changed contents`. An owed **attempt** — a window whose read failed before any
verdict existed — has no payload to replay, so the next round re-reads it and may legitimately reach a
new verdict, because nothing about that window was ever promised to anybody. Without `owed_end` the
second case is the silent gap: the entry has no acknowledged window either, so "the newest completed
window" an hour later is a *different* window, and the hour that failed is skipped by a producer that
had in fact begun it. So a round writes the cursor at four points — whose turn this is, that it is
attempting a window, that the window's payloads exist, and that the window was answered — and a refused
round writes only its refusal counter.

Every refusal is read-only — a cursor this module refuses is left byte-for-byte as it was found,
never rewritten, truncated, migrated or deleted, because it is the only record of what the platform
was already told:

| found | what happens |
| :-- | :-- |
| no `LO_ANOMALY_CURSOR`, with a configuration named | the producer does not start; one `WARNING` names the variable, exit 1 |
| a relative path, or a `..` segment | refused: this state would move when the service manager's working directory moves, and silently opening a *different* cursor is worse than not starting |
| a `\\\\host\\share\\…` or `\\\\.\\device` form on Windows | refused as an explicit network/device path. **What this does not detect:** a mapped drive letter that points at a share, or a POSIX NFS/SMB mount — no portable check distinguishes those, so such a deployment is unsupported and the operator verifies the filesystem is local. An advisory lock on a remote mount may be granted on two hosts at once rather than fail |
| parent missing, a symlink **anywhere in the directory ancestry**, or reachable by group/other (POSIX mode bits) | refused: the parent is created by an **operator** at mode `0700`, never by the producer choosing permissions around its own state. Windows has no mode check and no ACL proof is claimed here; trusted ancestry is provisioning, and a last-second swap of a directory above the file is a residual TOCTOU window this advisory lock does not close |
| file absent, parent sound | the first start: judged at the newest completed window, and one `WARNING` says in words that every earlier window was never judged and is **not** replayed, with the missed count stated as `unknown` — it is not knowable from what the store still holds |
| unparseable JSON, duplicated keys, unknown or missing keys, a foreign `schema_version`, another producer identity's `source`, a counter past its ceiling, an entry whose instants contradict each other (a batch for a window it does not owe, or one already acknowledged), a pending batch whose payloads disagree with the digests beside it, an owed batch with no evidence sample, more than `MAX_ENTRIES` (32) series entries, a file over 2 MiB | refuses the whole round, bytes unchanged; the remedy is an operator action, not a repair by the monitor |
| a configured series whose knobs or reviewed SQL changed since its entry was written | refuses the **whole round**, before its first query and without writing a byte: its entry keeps the binding the cursor was written with, and so do the other series their positions. One mistyped knob therefore holds every series' windows until it is fixed — the price of a refusal with nothing to undo — and the message names the series it is about |
| an owed batch that this configuration no longer authorises: another resource or none, another rule, a `rule_version` the current knobs do not produce, a different evidence query kind or parameters, an event paired with a sample the batch does not hold, a window that is not one configured evaluation long / not aligned / not exactly one evaluation past the last acknowledged window | refused **before** the round's first query, first POST and first byte, by the same up-front check as a changed binding. The digests are recomputed and still match in every one of those cases: this is a statement about the configuration, not a checksum |
| a stored window position this configuration could not have produced: `owed_end`, `last_acked_end` or `anchored_at` at a fraction of a second, off that series' evaluation grid, or an owed attempt anything other than exactly one evaluation past the last ack | refused by the same up-front check, and **for an entry that holds no payload at all** — that is the shape of a moved owed marker, and answering it would acknowledge the later window and never mention the interval in between. `load` accepts such a file (canonical text, ordering intact), which is why the refusal needs the resolved `evaluation_seconds`: configuration is speaking, not the checksums |
| a cursor that is a symlink, or one written through | refused before it is read |
| a `last_served` marker naming a series the configuration no longer names | **not** a refusal: the rotation starts from the head of the configuration. The marker is a fairness position, not an identity claim |

`LO_ANOMALY_SOURCE` has to match too: a restored cursor written by a different producer identity is
another producer's memory, and re-anchoring over it would silently drop what that identity still owes.

Writes use the sequence `inventory/index.py` uses to rebuild itself: one `mkstemp` name in the
cursor's own directory, write, `flush`, `fsync`, `chmod 0600`, one atomic `os.replace`, then a
directory `fsync` where the platform has one. The document is validated *before* the first byte, so
`save` can never create a cursor its own `load` would refuse; the temp file is unlinked in `finally`
and **only our own temp file** — the `.owner.lock` beside it is never removed by anything here, because
a lock file's presence says nothing about a live owner and deleting it is how two processes end up both
writing.

What a failed write costs depends on which side of the rename it happened, and the two are not the same
claim. Before `os.replace` — the write, the `fsync`, the `chmod`, the rename itself — the previous
cursor's bytes are still the file, and the round posts nothing. **After** the rename the only remaining
step is the POSIX directory `fsync`, and by then the new bytes are installed: what is uncertain is
whether they survive a crash or a power loss, which this code cannot know and does not claim either way
(on Windows there is no directory `fsync`, so the durability of the rename itself is unverified there).
So a failed `save` means "the cursor may be the old one or the new one", not "the old one is safely
still there". The producer does not reason from that uncertainty; it follows the ordering rule instead:
**nothing is POSTed on the strength of a save that did not succeed**, and the next delivery requires a
save that does. `anomaly.main` holds `owner.exclusive_owner` on the cursor for its whole life, so a
second anomaly process cannot advance the cursor past payloads its predecessor still owes; a held lock
surfaces as an `OSError` and exit 1, which is the correct reading of "something else is already
judging these series".

A round is bounded and says what it spent. Each series' own windows are **ascending and contiguous**,
derived from the file rather than the clock; **across series the order is a durable round-robin**, not a
race to the oldest debt. The cursor's `last_served` marker names the series that was last given an
attempt — written *before* that attempt's query and before its POSTs, so a restart continues the
rotation instead of restarting it — and the round starts after it and wraps. Leading with the oldest
owed window was the bug this replaced: a series whose payload the platform permanently refuses owes the
*same* window forever, so it held the front of the queue in every round and every restart, and sorting
equal windows by refusal counts did not reach the case where the two series owe *different* hours
(different windows never tie, so the older debt still won). Time now ranks nothing across series; a
name does. A series the file has never begun is anchored at **its own newest completed window** —
the durable anomaly cursor's first-start rule, asked per series, with no reference to what a sibling owes: a producer
configured to watch a series from now is not configured to replay the history its neighbour has been
walking, and there is deliberately no shared-horizon, backfill or join-depth policy here. One window per
series per pass, over at most `MAX_CATCH_UP_WINDOWS` (4) passes and never more than
`MAX_WINDOWS_PER_ROUND` (16) attempts, `MAX_QUERIES_PER_ROUND` (16) reads and `MAX_POSTS_PER_ROUND` (32)
requests — four code constants and not configuration, because they are the load bound the store's 2
000-row cap and this README's log-volume row were written against; a caller may pass a *smaller*
`RoundBudget`, never a larger one. A refused series costs the round one attempt and then settles for it,
so under any budget a configured series is served within `MAX_SERIES` rounds, whatever its backlog looks
like beside its neighbours'. The numbers land in
the one line per round that `main` keeps (`result`, `windows`, `queries`, `posts`, `delivered`,
`recovered`, `no_verdict`, `refusals`, `lag_windows`, `pending`, `stale_entries`,
`unresolved_pending`) plus one line per window attempted. `result` is the round's word and one of five:
`refused` (a window was refused), else `delivered` (an event was acknowledged), else `idle` (a window
advanced with nothing to say), else `deferred` — the round could not attempt a single window and a
configured series still owes one, which is what a zero or tight budget reports instead of the `caught_up`
it used to — else `caught_up`. That order is a precedence and not a menu: once a round attempted
something, what it did outranks what it ran out of budget for, and what it did not reach is the
`lag_windows` count reported beside the word, never in place of it. Each series' own row carries the word
that series earned (`refused`, `delivered`, `recovered`, `idle`, `insufficient`, `unjudgeable`,
`caught_up` when the cursor owes it nothing, `deferred` when the round had nothing left for it), because
one round can bring one series up to date and run out of budget on its neighbour. `no_verdict` (`idle`,
`insufficient`, `unjudgeable`) is counted apart from `delivered` because *judged* is not the same claim
as *reported*,
and folding them together makes a quiet series look busy. `stale_entries` and `unresolved_pending`
name cursor entries no configuration names any more: a series that left the file keeps its owed batch
and its counters, is never silently acked or deleted, and becomes visible instead of gone.

A note on restores, because this is the one file whose loss changes what an operator will read, and
the honest version of it is narrower than "just restore it". The safe case is a **coherent stopped
snapshot**: the producer stopped, then the platform database and this cursor copied together. That
resume is exact — the owed window is replayed from stored bytes and the store folds the identical
re-send into the row it already holds. Anything less coherent needs an operator, not a reset:

* **cursor missing** — the remembered history is gone with it. The producer anchors at the newest
  completed window, logs one `WARNING` saying earlier windows were never judged and are not replayed,
  and the missed count is stated as `unknown`. There is **no** guarantee of no duplicates or no extra
  incidents: a window the platform already accepted can be judged again, and a re-judgement is a new
  verdict, not a replay.
* **cursor older than the platform database** — the producer walks forward from where the old file
  stood, so it can **re-query a window the platform already accepted**. If the answer comes back the
  same, the dedup folds it; if it comes back different, the store either refuses the retry as changed
  contents or takes it as a second event under a new id. Database dedup is not a correctness repair
  here — it is a symptom of the asymmetry, and reconciling it (keep, delete the entry, or re-point the
  path) is an explicit operator decision. Nothing here automates a reset, a delete or a re-anchor.
* **restored onto a different host or a different producer identity** — refused, and that refusal is
  the point: `source` keys the event ids, so re-anchoring over another producer's memory would drop
  what that identity still owes.

The path is therefore the one thing about this worker an operator places deliberately: on a host-local
filesystem they have verified, inside a private directory that exists before the unit starts, with
trusted directory ancestry (see the symlink row above), and inside or outside the backup set **on
purpose** — because what a partial restore costs is measured in re-judged windows and an operator's
afternoon, not in a repair this code can make.

### What is deliberately not here yet

* **No trend, decay or seasonality beyond the bucket.** A series that drifts up 30 % over a month
  starts reporting anomalies at the top of its band. The ramp-up answer is a shorter `window_days`
  (it re-trains from the query every round, so this heals on its own) — not a new knob per week.
* **Coverage events are off by default.** Per-series `coverage_unjudgeable_windows` accepts an
  integer `0..100` (default `0`). A positive value opens one coverage incident after that many
  consecutive unjudgeable windows, only after a previously judgeable window. Cold start and
  insufficient history stay silent. Idle/insufficient/judgeable windows reset the streak; only a
  judgeable window resolves an open coverage incident, alongside its ordinary anomaly event.
  Recovery can cost four POSTs, within the unchanged 32-POST round bound. Fresh enabled deployments
  use cursor schema 2; enabling with an existing schema-1 cursor refuses read-only. Retain that
  cursor and disabled configuration pending a separately reviewed migration; no automatic conversion
  or deletion/reset remedy is provided. Older releases cannot read schema 2, so rollback needs a
  reviewed state plan. See `docs/units/anomaly-cursor.md`.
* **No cursor retention horizon or pruning command.** The file is bounded —
  `MAX_ENTRIES` (32) series entries, one owed batch each, 2 MiB — but nothing trims it: an entry whose
  series left the configuration stays, with its counters and its batch, and removing one is a
  hand-edit of a JSON file (the procedure and its two failure modes are in
  `docs/units/anomaly-cursor.md`). A `--show-cursor` / `--resolve-cursor` pair belongs on a later card.
* **The producer ships as a component, and no container from it has been started.** Since anomaly component,
  `components/control/anomaly/` exists: the producer as its own service on the platform's image, with
  the four lifecycle documents, the pin register and the gate coverage a component owes (its
  `conformance.md` lists the checks none of them has passed). Its env is
  `LO_ANOMALY_CONFIG`, `LO_ANOMALY_CURSOR` (the absolute host-local path of its durable cursor, which a
  named configuration makes required), `LO_ANOMALY_SOURCE` (the producer identity, which must match its
  token), `LO_INDEX_PATH` and the same `LO_CLICKHOUSE_*` / `LO_PLATFORM_URL` / `LO_INTERNAL_ALLOW_HTTP`
  the Sigma runner reads — plus `LO_ANOMALY_STALE_SECONDS`, read by nothing in this package but its
  container healthcheck. The token is the one credential that is *not* shared: the container still
  reads the name `LO_PRODUCER_TOKEN`, but since anomaly deployment support  the manifest mounts this
  producer's own host file behind it, because one row of the platform's credentials file
  authenticates exactly one identity (`components/control/anomaly/CONTRACT.md` §4).
  `examples/full/compose.yaml` has carried that manifest in its `include:` list since that same
  change, so an example does compose it — and nothing has rendered
  or started that composition, while the platform image pinned on this tree still predates these two
  modules: `components/control/anomaly/versions.json` states both facts and what each costs.

## Schema migrations

`state.VERSION` names the schema this build reads, and `state.MIGRATIONS` maps every target version
up to it to the script that reaches it — `VERSION == max(MIGRATIONS)` is re-checked before a file is
opened, so a build that bumped one and not the other touches nothing. Opening a platform database
older than the build refuses and names the command; nothing in the product changes a stored schema as
a side effect of being pointed at it. `lo-platform --database <path> migrate` is that command: it
copies the file to `<path>.pre-v<from>-<utc stamp>.db` and integrity-checks the copy first, then
applies each missing step in its own `BEGIN IMMEDIATE` that ends with its own `PRAGMA user_version`,
auditing one `schema.migrated` row per step. A crash between steps leaves the last committed version
— readable, and the point the next run continues from — never a half-created table. A database newer
than the build is refused: there is no downgrade, and `deployment.release.transition()` still refuses
a candidate whose state pin differs from what is live, so migrating is a separate operator action
taken before a release whose pin already names the version that migration produces. Rollback is the
pre-migration copy, not a code rollback.

`VERSION` is 9. Migration 2 is the first real one: it moves the runtime control of notification
delivery out of the audit log. It creates `notification_control` (the delivery mode under `mode`, one
flood breaker per channel under `circuit:<channel>`, one approved human-channel test window under
`test_window:<id>`), `notification_reservations` (every send slot already taken) and
`notification_suppressions` (every delivery that may never be sent), and back-fills all three from the
audit rows that used to be re-read on every claim. That back-fill is the only code left that reads the
audit log for control; `records('audit')` still reads it as the audit, and every `notification.*` row
is still written exactly as before — the migration copies those values, it moves none of them out of
the log. The consequence for an operator is a hard door where there was a silent one: a v1 file under
this build is refused until `lo-platform migrate` has run, and an older binary cannot open a v2 file
either, so a rollback is the pre-migration copy rather than the previous release.

Migration 3 (ledger notifications) adds five columns and no table: `outbox.channel`, which records the channel
a claim routed the delivery to, `outbox.callback_token_hash`, `callback_expires_at` and
`callback_consumed_at`, which hold the single-use approval code, and `notification_attempts.cause`,
which is the bounded outcome word described under "Delivery outcomes" below. The five are `ALTER TABLE
ADD COLUMN` statements with defaults chosen so that a migrated row asserts nothing v2 did not record:
`channel` becomes the empty string ("this build has not routed this row yet" — the channel a v2 send
used is a fact about the operator's policy, and it already lives, back-filled at v2, in
`notification_reservations`), and the three `cause` words that replace a v2 attempt's recorded boolean
are derived from that boolean and nothing else (`accepted`→`accepted`, `failed`→`rejected`, a claim
whose lease expired→`transport`). The approval code itself is never stored: only its digest is, which is
also why a restored or copied database cannot hand back a code that still works.

Migration 4  adds two tables and widens no existing column:
`verification_bindings` (one row per action proposed while a policy was mounted — `bound` with the
complete captured mapping digested into a SHA-256, or `unbound` with one of three captured reasons) and
`verification_records` (one immutable submitted observation per logical check, with the verdict this
server derived, the actor that filed it and the receipt and bounded samples behind it). Both are
append-only in SQL itself — `BEFORE UPDATE`/`BEFORE DELETE` triggers on each, the mechanism `audit` uses
— because the two promises that make a verification worth reading back are "this action's binding did not
move when the policy changed" and "that record was not corrected afterwards", and neither survives a
table that can be rewritten. Neither table is back-filled: an action proposed before the migration has no
row and reads `unbound`/`not-captured`, which is the truth, rather than a meaning this build never
witnessed. A v3 file is refused until `lo-platform migrate` has run whatever the policy; once migrated, a
default-off build queries **neither** table — the proposal-time capture is behind one
`if self.verification_policy is not None:` test — which is what lets the tests that simulate a pre-v4
build keep proposing unchanged, and `tests/test_state_migration.py`'s pinned table set grows by exactly
these two names. The `verification.recorded` audit row one accepted first write leaves rides in the
existing `audit` history, so `GET /v1/audit` shows it under `category=all` and no category vocabulary or
record-read allowlist moved ([unit contract](../../docs/units/verification-records.md)).

Migration 7 (correlation) adds one table and one index, and rewrites nothing: `incident_members(incident_id,
condition_key, rationale, at)` holds the durable reason several conditions are one incident (one row per
linking condition, the newest restatement of a pair winning) and carries **no index of its own** — its
primary key `(incident_id, condition_key)` already answers every read that table gets, so a second index
over the same leading column would be write cost for nothing. `conditions_incident` is the one index added,
for the per-resolution count that asks whether
any *other* open condition still points at this incident — a question the last-open-member rule asks on
every resolve and the schema had no index for in either direction. `incidents`, `conditions` and `events`
gain **no column**: `conditions.incident_id` is already the many-to-one pointer a group needs, and
`tests/test_rca_progress.py` inserts into `incidents` by position. A `CHECK` on the rationale width travels
with the table because one `CREATE` text serves a fresh file and a migrated one alike, and an old file
reaches v7 by the same explicit `lo-platform --database <path> migrate`, with its verified copy named for the
version it protects and one audited transaction per step — proven for a v1 file and a v6 file in
`tests/test_incident_grouping_migration.py`, which also proves the migrated file can then *group* rather than
merely hold the table.

Migration 8  adds one index over a column that has existed since migration 1, and rewrites
nothing: `events_incident` on `events(incident_id)`, the membership pointer `Store.intake` writes and
`Store._join_group` moves. It exists for one read — `rca.MEMBER_SQL`, "which events belong to this
incident?", made load-bearing by `correlation` and run once per incident per RCA round — and the reason a budget
was not a substitute is the plan: unindexed, that statement is `SCAN events`, so SQLite walks every event
row the file has ever held, and every payload string it passes on the way, to gather the handful that name
one incident. The work then grows with the life of the file while the answer stays the size of an incident,
and `rca.MEMBER_READ_INSTRUCTIONS` converts that into a guaranteed failure per incident rather than a
cheap answer. With the index the read seeks (`EXPLAIN QUERY PLAN` → `SEARCH events USING INDEX
events_incident (incident_id=?)`), `MAX_MEMBER_ROWS` becomes the ceiling that normally binds, and the
instruction budget stays as the second bound for a file restored from a pre-v8 copy or one whose
`lo-platform migrate` has not run. No table and no column move, so `tests/test_state_migration.py`'s
table pin does not; the step is proven on a v7 file in `tests/test_incident_grouping_migration.py`, which
also checks the plan names this index. Nothing in the product names it with `INDEXED BY`: `rca` already
answers a missing index with a stated gap, and the honest sentence there is worth more than an SQLite
error that reads like an unopenable file.

Migration 9  adds one index over one column of the table migration 7 created, and rewrites
nothing: `incident_members_condition` on `incident_members(condition_key)`. It exists for one read —
`suppression._absorbed_openings`, "how many of this condition's openings did a group swallow?", asked
inside the flap count once per page a booking round files. Migration 7 deliberately created **no** index on
that table, and was right at the time: its primary key `(incident_id, condition_key)` answers every read
that came from the incident side. This read comes from the *condition* side, which is the second column of
that key, and an index cannot serve a leading column it does not lead with — so the statement's plan was
`SCAN incident_members`: every link the file has ever recorded, and every rationale document it passed over,
to count the few naming one condition. Measured before the index (2026-09-10, worst case — a condition with
no link row): 0.1 ms at 500 links, 2.2 ms at 10 000, 9.3 ms at 50 000, and that is a per-page cost on the
path that also wants the writer's lock. With it the read seeks (`EXPLAIN QUERY PLAN` → `SEARCH
incident_members USING INDEX incident_members_condition (condition_key=?)`), and the row cap
`MAX_TRANSITION_ROWS` is then the bound that normally bites. What the index does **not** buy is the floor: a
group still swallows the member's recoveries and no row in this schema dates those, so any non-zero
`absorbed` keeps the count `complete: False`. No table and no column move, so
`tests/test_state_migration.py`'s table pin does not; the step is proven on a v8 file in
`tests/test_incident_grouping_migration.py`, which checks the plan names this index, asserts the step created
exactly one, and asserts the read still does **not** name it with `INDEXED BY` — a pre-v9 file must answer
zero-or-scan rather than raise an error that reads like an unopenable database, inside a transaction whose
contract is that grouping costs no finding.

Of the three notification tables, only `notification_reservations` ever shrinks: `Store.prune_reservations` (state leftovers) runs in
the same transaction as each outbox claim and deletes the slots of every channel this store has a policy
for that carry no test window and sit before the instant that channel's budget counts from (the later of
the configured window and the last human reset). Slots taken inside an approved test window and rows
belonging to a channel nobody here has a policy for are never deleted, and `notification_suppressions`
has no prune at all, because a suppressed delivery must never replay whatever its age — so the
reservations table is a budget that ages, not the history of deliveries. That history is the audit log,
which nothing here prunes.

Copy discipline is unchanged and stricter than it looks. `Store.backup()` — the online backup API,
which reads the `-wal` — stays the only safe copy of a running database. `Store.__init__` now refuses
a WAL-mode file whose own header says it still needs a `-wal` that is absent, but a file copied while
a writer holds uncheckpointed commits is self-consistent and merely missing rows, and nothing inside
the `.db` reveals it (measured on SQLite 3.49.1 while deciding this; see
`tests/test_regression_schema_version.py`).

## Logging contract

Every worker, client and CLI entry point here logs through `local_observe.log.get_logger`.
One JSON object per line on **stderr**; stdout stays exactly as machine-readable as it was —
the CLIs' JSON is a contract, not a log. (The `job_worker --verify-code` identity line was the other
one; the worker is archived, and so is that promise.)

Fixed fields, in this order: `ts` (UTC ISO 8601), `level`, `logger`, `event` (the message),
then whatever `extra` keys the call site supplied. `LO_LOG_LEVEL` sets the level from a
standard name, case-insensitively; any other value — a typo, an empty string, `NOTSET` — falls
back to `INFO`, because an unreadable setting must not silence a witness.

Logged: identifiers (delivery, event, incident, job, rule, execution), statuses, counts,
durations, and exception **class names**. Never logged: request or response payload bodies,
credentials, URLs carrying credentials, environment values. Tracebacks are emitted at `DEBUG`
only and dropped at every higher level, because exception text can echo the input that caused
it. Any value under a credential-named key — the same `SECRET_KEYS` set that
`inventory/validation.py` refuses at declaration time, matched after stripping
non-alphanumerics and lower-casing — becomes `<redacted>`; `local_observe.log.redacted` does
that and the formatter applies it to every extra, so a call-site mistake cannot leak one. Field
values, the event text and tracebacks are length- and depth-bounded: constructing a log line
must never raise, hang or grow without limit.

Each looping worker logs one `INFO` line per tick (`idle`, `delivered`, or the status it
observed) and a `WARNING` naming the error class whenever it retains a pending batch, so a
silent worker is a worker that is not running rather than a healthy one with nothing to say.
The inventory worker is one-shot: it logs one summary per invocation, and an uncaught failure
reaches the service manager as an exit status and a traceback.

### What that costs on disk, and which knob to turn

What an operator actually needs is "how far back do these logs go", because the
manifests cap them (`json-file`, `max-size: 10m` with `max-file: '3'` on the product services,
`5m × 2` on `sigma` and `dagu`) and reaching that cap deletes history rather than slowing
anything down. The formula, in the units Docker uses:

```
days_of_history = (max-size × max-file) / (records_per_day × bytes_per_record)
records_per_day = 86400 / tick_seconds
bytes_per_record = the JSON line + ~71 bytes of json-file envelope
```

The envelope is not optional: Docker stores each captured line as
`{"log": "<line>\n", "stream": "stderr", "time": "<nanosecond UTC>"}` and annotates every line with
its origin and timestamp ([`json-file`](https://docs.docker.com/engine/logging/drivers/json-file/),
read 2026-09-07), so a 166-byte line costs about 237 bytes of the quota. Docker's own example calls
`max-size: 10m` "10 megabytes"; a daemon that reads the suffix as 1024² shifts every figure below by
under 5 %, which is not the margin anyone decides on. The sizes are measured, not guessed: the
detection line the suite prints (`{"ts": …, "event": "Detection tick finished", "result":
"idle"}`) is 166 bytes on the wire; the same record rendered with `"result": "delivered"` is 171,
the Sigma line — which carries `rule_id`, a full UUID — is 214, and the retained-batch `WARNING`
is 216.

At the shipped 2-second tick that is 43,200 lines per worker per day. The `10m × 3` cap the
product services carry is 30 MB, and a 2-second logger fills it in **about 2.9 days**
(43,200 × 237 B ≈ 10.2 MB/day). Two details change that number per service, and both are
measured from the tree rather than assumed:

The `anomaly` row carries a multiplier the others do not, and it arrived with the cursor: a round
writes one summary line *plus* one line per series it reaches — a caught-up series still says so once
per round — so a three-series configuration at the default tick is 288 rounds × 4 lines ≈ 1,152 lines a
day, not 288, and the ≈ 436 days this row first claimed was four times optimistic. A backlog recovery
is the bounded burst: at most sixteen window lines and one round line per round whatever the size of
the gap, which is what `MAX_WINDOWS_PER_ROUND` costs in log volume as well as in queries.

Three days is the honest shape of these caps — "the logs stop at Tuesday" is the cap working, not
a bug — and Sigma's is under a day, which is the number an operator needs before blaming the
worker for a gap in its history. Anything that must survive longer belongs in the store, not in a
container's log files.

Two knobs, and each one costs something specific. **The tick is the sleep in the worker**
(`detection_worker.py`, `sigma_runner.py`: `time.sleep(2)`) — there is no `LO_*_INTERVAL`
environment variable to set, so changing it is a code change on a branch. Raising it buys history
linearly (30 s ⇒ the ~43 days above) and costs detection latency; note that lowering it below 5
seconds buys *nothing* but log volume, because the detector's evaluation window is aligned to
5-second boundaries (`int(now.timestamp()) // 5 * 5`) and returns `idle` without querying until a
new window opens — most of what a faster tick records is "still waiting". **The cap**
(`max-size`, `max-file`) is the retention window itself: lowering it never breaks a running
service, it shortens the period for which a past incident can be read back, and the point of these
workers' per-tick line is precisely to answer "what was it doing at 03:12". Raising `LO_LOG_LEVEL`
to `WARNING` is the third option and the worst trade: while a worker is healthy it writes nothing
at all, so the quota holds weeks instead of days — but the `idle` line is the only statement that
distinguishes a worker that is waiting from a worker that stopped, and that is the property the
paragraph above exists to keep.

## Error taxonomy

Every error body is a JSON object with a stable machine-readable `error` code and, where the
platform raised its own sentence, a `detail` holding it. Codes are `invalid_request`,
`not_authorised`, `conflict`, `not_found` and `internal_error`.

| what happened | status | body |
| :-- | :-- | :-- |
| no or ambiguous bearer credential | 401 | `{"error": "authentication_required"}` |
| role may not touch this path | 403 | `{"error": "summary_only"}` |
| body larger than 64 KiB | 413 | `{"error": "body_too_large"}` |
| verb the surface does not serve | 405 | `{"error": "method_not_allowed"}` |
| unknown path, or POST fields outside the declared shape | 404 | `{"error": "not_found"}` |
| malformed JSON body | 400 | `{"error": "invalid_request", "detail": "<decoder message>"}` |
| a refusal `state.py`/`policy.py`/inventory validation raised on purpose | 400 | `{"error": "<code>", "detail": "<that sentence>"}` |
| a configured transport refused | 400 | `{"error": "<code>", "detail": "<that sentence>"}` |
| anything else — a handler bug, a corrupt database, a broken driver | 500 | `{"error": "internal_error", "detail": "<exception class name>"}` |

The 400 `code` is derived from the wording the platform raised: sentences about authority
(`Actor is not authorised…`, `Runner identity/token mismatch`) become `not_authorised`; sentences
about state the caller could not see (`… retry changed contents`, `Action is not pending`,
`Execution already terminal or absent`, `… requires an open incident`) become `conflict`; every
other refusal is `invalid_request`. The tables live in `api.py` as `NOT_AUTHORISED_MESSAGES` and
`CONFLICT_MESSAGES`; a new `state.py` sentence needs no change there — it lands as
`invalid_request` until someone reads it and classifies it.

A 500 is a bug, not a client error, and is never reported as one: the body carries only the
exception *class name*, and the traceback goes to the log at `DEBUG` (see the logging contract
above). No value read from a request is echoed into an error body — the 400 sentences name fields,
counts and positions, never the data sent in them, and where an exception message *would* name
the offending input (`int()` on a bad `limit`, a UTF-8 decode failure) the handler returns its own
fixed sentence instead.

**Which refusals are durable.** A refusal that reaches the action lifecycle writes one append-only
`action.refused` audit row after its own transaction rolled back — one row per refusal the write budget
admitted and the identity permitted to name, since `dropped`, `failed` and `unauditable` refusals are
counted instead of written — and the summary-role 403 on the four action write routes writes one too.
A 401, a 404, a 405, a 413, malformed JSON and every refusal outside the action lifecycle write nothing
— an unauthenticated request never becomes a database writer. Those gates speak only when they are the
first to answer: the `summary` role gate runs before the body is read, so a summary credential posting
broken or oversized bytes is audited as the summary-role denial it already is. `GET /v1/records/audit`
serves the rows newest first, in the same capped 100-row window as every other record read, with no
offset (a 64-row burst can crowd older rows out of that view without deleting them); that window is
unchanged, and since the paged audit reader the rows behind it are reachable by a second route — `GET /v1/audit`, a
bounded paged read over the same table whose `category=action-transitions` excludes `action.refused`
precisely because a refusal is not a completed transition
([`audit_reader.py`](../../docs/units/audit-reader.md)); `GET /v1/runtime`'s `refusal_audit`
counts what this process wrote, dropped, failed to write and could not attribute, and its
`refusal_audit_dispatch` counts what this app's dispatcher admitted, shed or lost since it started.
That 403's write is dispatched off the serving loop to one slot per app, so a database locked elsewhere
cannot park a concurrent memory-only `/v1/runtime` behind it, and a refusal the dispatcher shed — slot
busy, or admission closed — writes no row at all and moves `overloaded` either way (`closed` is the
true/false flag saying which, not a count of sheds): **the 403 is not proof of a durable record.** See
[docs/units/refusal-audit.md](../../docs/units/refusal-audit.md).

## Refusal audit

`platform/refusals.py` decides what a refusal may say, `platform/state.py` is the only writer, and
`platform/refusal_dispatch.py` decides where the transport's own write runs (never on the serving loop)
and whether it may be attempted at all (one job per app). The boundary is `Store.refusal`, a context
manager wrapped around the whole of `propose_action`,
`decide`, `claim_action` and `execution_outcome` — role gate, validations and the injected policy
call included — so the refused partial state is rolled back and its connection closed *before* the
audit row commits in its own transaction. Only `StateError` and `InvalidInventory` are caught: those
are the platform refusing on purpose, and anything else stays the 500 it always was. The original
exception is re-raised unchanged, so an audit failure can neither upgrade a denial into a success nor
replace its sentence, and `store.status()` does not move.

The row carries five bounded fields — the instant, an identity that must be a platform `Actor` whose
identity passes `label()` and whose role is one of the six, the literal `action.refused`, a subject
that is a canonical UUID or the `unbound` sentinel, and `{attempt, reason, role}` where every word is
from a closed set. Never stored: a body, a token or the digest of one, a URL, a path, an exception
message, or an identity read out of a request. An identity the state layer cannot validate produces
**no row at all** and an `unauditable` count — a hashed or invented actor field would be a claim about
a person, and a direct `Store` caller's `Actor` is trusted attribution, not authentication proof.
The widest legal row is measured at ≤ 512 bytes.

Rate, not history: one process-local token bucket (capacity 64, initially full, 1 token/second from a
real monotonic clock — never the `now=` a caller passes) bounds how fast refusal rows may be written.
For the four lifecycle methods that is still the whole shape of a flood: a 64-row burst written in full,
then about one row a second. Above the rate the refusal still happens, the row does not, and `dropped`
counts it. A failed write spends its token too, so a locked or full database costs refusals instead of a
retry storm. The bucket, the counters and the rows they describe all start over at a restart, while the
rows already committed do not.

**Log volume.** No line per refusal: the durable row is the record, and a line would double the flood
surface a bounded row already covers. A *failed* audit write logs one `WARNING` naming nothing but the
exception class, no more than once per 60 s of actual elapsed monotonic time measured from the line that
was really printed (an aligned minute bucket would let two failures 0.1 s apart print twice) — the
counter is the count, the line is the signal.
`api.py`'s `StateError` branch logs nothing and writes nothing, deliberately: the state layer already
audited that refusal, which is why the transport's reason words and the state layer's are kept disjoint
rather than tracking a per-request "already audited?" flag.

**Backup linkage.** Nothing new: the rows live in the existing `audit` table, so `Store.backup()` and
`deployment/state_copy.py::copy_state` carry them with the rest of the database, that card owed no
migration and no retention tier or second database. The counters are the one
part of this feature that is not backed up — they are per-process and read zero after a restart while
the rows stay. Refusal rows are never read by anything that decides: the audit table is a record, not
authorization state.

## Verification over HTTPS (`verification_cli.py`)

The verification path is now reachable from a terminal without opening the platform database. Every form below
uses synthetic identifiers, an operator-owned HTTPS base that may keep a path prefix, and a **file-mounted**
credential — no command here takes a token as a value, and none prints or logs the one it reads.

```
python -m local_observe.platform.cli verification \
    --url https://edge.example.test/platform \
    --token-file /config/verification-token \
    [--timeout 5] [--ca-file /config/platform-ca.pem] \
    binding --action-id 4f2b1a63-9c7d-4d5e-8a1b-2c3d4e5f6a7b

… verification --url … --token-file … records --execution-id b1e4c2d0-7a3f-4c68-9d21-0f5a6b7c8d9e
… verification --url … --token-file … record  --verification-id f3d0e9c2b5a7461f8e4c0d2a6b5f4e3d1c0b9a87968574635241f0e1d2c3b4a5
… verification --url … --token-file … submit  --statement /tmp/statement.json
```

| rule | what it means at the keyboard |
| :-- | :-- |
| HTTPS, always | `--url` must be `https`; there is no `--allow-http`, `--insecure` or environment fallback. `--ca-file` passes a trust anchor to the shared `JsonClient`, which adjudicates it |
| at most one request | after preflight, including on failure and on a lost `submit` acknowledgement. No `--retries`, no backoff, no second attempt inside an invocation |
| bounds | `--timeout` is an integer `1..20` (default `10`); the client's 4 MiB response cap is untouched. A token file accepts 1..4096 raw bytes (24..4096 printable ASCII after stripping outer whitespace); a statement accepts at most 32 768 raw bytes of strict-UTF-8 JSON object. Reads stop at each cap plus one byte to detect overflow |
| no local database | `--database` is refused for this group (exit 2) even though the parser no longer requires it for every command; no database is opened, created or cached locally. Every other subcommand still refuses without it |
| dispatch order | the group runs before any `Store`, `NotificationPolicy`, `LO_NOTIFICATION_MODE` or policy/pin read, so a verification call neither needs nor touches the local operational configuration |
| server decides | role, policy presence, execution/binding state, replay vs first write, and the verdict all come back from the service; the client adds no field to a `200` and grades nothing locally |
| outputs | `200` + JSON object → that object on stdout, exit `0`. Any other status → `{"status": "error", "error_type": "VerificationHTTPError", "http_status": <n>}`, exit `1`. Input/config/transport/output failure → `{"status": "error", "error_type": "VerificationCLIError"}`, exit `1`. Bad syntax → argparse, exit `2` |
| no secrets in failures | no server body (the transport discards error bodies), no traceback, no exception cause, no token, no request/response document, no path. Two `503`s therefore look identical: `verification_busy` and `verification_unavailable` are **not** distinguishable here |

**An unanswered `submit` is not a refusal.** The record may still have been accepted. The command never retries
and never says *rollback*; the operator's move is `records --execution-id …` / `record --verification-id …`
followed by resubmitting the **unchanged** statement file, which storage folds into `created: false` — a
changed statement under the same id is a conflict. Automatic exact replay and pending-state durability belong to
the follower half of the verification workflow, not to this command.

Nothing here enables a producer or deploys one: no manifest, no example fragment, no `LO_*` variable, no mount,
no secret entry, and no new role, token kind or route. Saved history is already available in the execution
UI. The separately configured follower handles automatic observations and durable retries; the four
manual verification commands retain their behavior.

## Notification safety

`LO_NOTIFICATION_MODE` selects `off`, `recording` or `live`. The compatible default is
`recording`: when neither the environment nor the JSON policy's `delivery_mode` names a
mode, the platform starts against a local recording sink and never reads channel
credentials. `live` sends to a real human channel, so it must be declared explicitly by
one of those two. Contradictory declarations fail.
Off pauses the sender and leaves pending state untouched. Recording processes
eligible events from all sources into audited local receipts, without reading
Telegram/webhook credentials or constructing a network client. These receipts
are labelled "recorded locally; no message sent", not human delivery confirmation.
Live keeps the configured channel and existing durable budgets. Neither off nor
recording accepts a human-channel test window. API/intake/expiry still work in off.

The `lo-platform notify` subcommand is the other entry point that delivers, and it obeys the
same rule: it reads `LO_NOTIFICATION_MODE` and takes `--mode {off,recording,live}`, which wins
over the variable. With neither, it records — the delivery takes its slot against the local
recording sink (`notification_reservations` names `recording-sink`, and the audit row says the
same), and no channel credential is read. `--url` and `--token-file` are therefore optional and
are opened only on the live path; a recording run works against a database on a host with no
channel installed. `live` is never the default: the flag or the variable has to name it, and then
both `--url` and `--token-file` are required. A value that is none of the three modes is a
refusal that exits 1 and leaves the queued delivery `pending`, not a fallback to the safe mode:
`LO_NOTIFICATION_MODE=Live` is a typo, and the typo must not choose the delivery path. A variable
that is present and blank refuses in the same direction, in this CLI and in the API, and the
refusal names the variable: `LO_NOTIFICATION_MODE=` is a line somebody wrote, and answering it with
the default would give one environment two answers (notification and state leftovers).

The service records its mode under the exclusive writer lock, as the `mode` key of
`notification_control` and as an audit row; `lo-platform notify` makes that same call
(`Store.start_notification_mode`) before its first claim, because it is the call that enforces the
rule below — a CLI that skipped it could start live over a backlog the service had paused (notification and state leftovers,
from the test tooling review). A later live
startup refuses if a previously off/recording service has pending or sending
deliveries. An explicit human backlog reconciliation/reset is required, not an
automatic drain to Telegram. Recording consumes eligible rows locally; those
rows do not replay on a later live startup. This does not make an older binary
safe to run against guarded state. It also does not guard the independent witness.

Authenticated `GET /v1/runtime` reports the serving process's startup observation,
mode and whether a sender is configured; summary-only/producer credentials cannot
read it. Two live fields ride on that snapshot — `delivery_loop_failures` (iterations of
the delivery loop that raised, since process start) and `delivery_loop_last_failure_at`
(UTC, `null` while nothing has failed). The loop survives every failure and backs off to
five seconds between iterations after one, so a non-zero count means "degraded, look at the
log", not "stopped". No channel credentials or arbitrary environment values are returned.
Absent source pins are reported as unverified, never implicitly accepted.
This is not a hash of executed bytecode or continuous integrity attestation:
promotion must use fresh immutable source with no stale bytecode and verify the
actual serving endpoint after startup. A separate `docker exec` import is not
that endpoint. Recording tests do not exercise human-channel rate limits; retain
the separate bounded fake-provider tests.

Sources named `stage-*` and operator-configured `synthetic_sources` record
notifications locally by default. Outbox presentation names the recording sink;
it is not a Telegram receipt. Keep production producer names out of this reserved
namespace. Continuous synthetic checks must not rely on human notifications.

`LO_NOTIFICATION_POLICY` optionally names a JSON policy file. Defaults limit the
single human channel to ten attempted sends per ten minutes and reject events
older than fifteen minutes. Both firing and recovery, failed requests and unknown
outcomes consume slots. A slot is reserved transactionally before transport, in the
same commit as the claim, and written to `notification_reservations`; restarts do not
reset it, and the window count is a query over that table rather than a scan of the
audit log. A flood opens a persistent circuit in `notification_control` under
`circuit:<channel>` until a human resets it. Suppressed outbox rows are recorded in
`notification_suppressions` and retain payloads, incidents and an audit reason as
`dead`; they cannot be manually retried. This deliberately prevents delayed flood
replay. It also means the operator must inspect current incidents after suppression.

`GET /v1/notifications/safety` exposes circuit/suppression state. A human-only
`POST /v1/notifications/reset-safety` with `{}` suppresses the pending backlog
before resetting; it refuses outstanding claims. Since control state it also moves the start of
the send budget to the instant of the reset, so the slots that tripped the breaker stop
being held against the next send: a reset buys a fresh window of `max_attempts` sends
rather than only waiting for the old one to age out, and it does not forget them — the
reservations stay in the audit log as the history of what was sent. (Before schema v2 a
reset wrote no budget record at all and the next send re-latched the breaker; ledger
notification budget asked which of the two was the design, and control state is the answer taken.) The
independent witness remains a separate notification path, not covered by this platform
budget. Do not restore an older platform binary against guarded state: it cannot open a
v2 file at all, and pre-v2 binaries enforced the budget from the audit log.

An explicitly approved `test_window` has `id`, UTC `starts_at`, UTC `expires_at`
and `max_attempts` (1..10, at most ten minutes). Only synthetic events observed
inside that window can use the human channel; retries also consume its total
budget. The approved definition is stored in `notification_control` under
`test_window:<id>`, beside the audit row that records it, and reusing a window ID with
different settings is refused. Expiry suppresses
future attempts; an HTTP request already in flight can finish after the deadline.
No unattended script should create/renew these windows. Tests use `FakeProvider`
and never the real Telegram adapter for load/flap verification.

## Channels: seven adapters behind one registry

Which channels exist is one question with one answer: the channel set the delivery loop can send on,
the channel set `Store` routes across and the channel set the budget tables book sends against are the
same names, from the same configuration. `notifications.build_channels` is that mapping —
`{channel: client}` plus `{channel: NotificationPolicy}` — and `deliver_one` picks the client by the
channel the claim routed the row to (`outbox.channel`).

`LO_NOTIFY_CHANNELS` names a mounted JSON document holding a list in the operator's **preference
order**. The first channel whose budget admits a delivery carries it; a channel that refuses to admit
one (its breaker latched, its budget spent) is passed over, which is what makes a latched channel stop
sending without stopping the alerting:

```json
[{"channel": "primary", "type": "telegram", "config": "/config/telegram.json"},
 {"channel": "oncall", "type": "webhook", "url": "https://hook.example/receive",
  "token_file": "/config/oncall-token", "policy": {"max_attempts": 3, "window_seconds": 300}}]
```

`type` is one of the adapters this product ships — `telegram` (the send-only bot client, whose
`{token, chat_id}` file is the same shape `LO_TELEGRAM_CONFIG` already takes) and `webhook` (the generic
`JsonClient`) are the two that predate the port plan; `channels.py` adds the five it ports from v0.1's
notifier set — `ntfy` (`url`, `topic`, optional `token_file`), `slack` (`url_file`, because an
incoming-webhook URL *is* the credential), `matrix` (`url`, `room_id`, `token_file`), `pagerduty`
(`key_file`, whose routing key rides in the body) and `email` (`host`, `port`, `from`,
`recipients_file`, optional `username`/`password_file`), the last of which is the only transport that
is not HTTP and so the only one that does not go through `local_observe/http.py`. A webhook entry needs
`url` and `token_file`; `allow_http: true` is the isolated-network opt-in `JsonClient` itself
adjudicates. `policy` may tune that channel's `max_attempts`,
`window_seconds`, `max_event_age_seconds`, `synthetic_sources` and `test_window`. It may not name a
channel or pick a `delivery_mode`: the mode is one decision for the service (`LO_NOTIFICATION_MODE`),
and a channel that disagreed would be a second, quieter answer to a question the operator already
answered. A malformed entry, a duplicated channel name, a channel named after a sink (`recording-sink`,
`synthetic-sink`, which `deliver_one` reads as "replace the client with a local sink") and a document
that is not a non-empty list are all boot refusals that name the channel and the key — never a
credential, an endpoint path or a file's contents.

Two things this deliberately is not. It is not a channel with a retry loop of its own: every transport
answers one claim with one of three outcomes (`sent`, `rejected`, `unavailable`, crosswalked in
`channels.ATTEMPT_CAUSE` onto the `transport`/`rejected`/`accepted` words above), and v0.1's
`notifiers.dispatch` retry ladder is deliberately unported because a second retry count would be a
second, unbudgeted answer to "how many times has this been sent?". A channel that cannot tell "the
provider refused this message" from "the provider is unreachable" still cannot be added at all — that
is the requirement `notification_attempts.cause` exists to meet, and the reason each transport has a
taxonomy test rather than a happy-path one. ITSM sync stays excluded (itop, `docs/COMPONENTS.md` §3).
And it is not a new credential surface: no variable in this feature holds a secret. A channel's
credential arrives as a file whose path sits inside a mounted document, one step stricter than the
`*_FILE` rule the rest of the product follows, and a value with an ASCII control character in it is
refused at the read exactly as `local_observe/credentials.py` refuses it — which is why an email channel
refuses to authenticate to a relay that has not upgraded to TLS, and why no approval code is printed on
a channel with more than one reader (Telegram is the one channel whose reader is one known phone).

The two variables that predate the registry still work, and are the same thing spelled shorter:
`LO_TELEGRAM_CONFIG` or `LO_NOTIFY_URL` builds one client under the channel its
`LO_NOTIFICATION_POLICY` names (default `primary`). They still refuse each other. A registry entry that
claims a channel one of them already claimed is a boot failure (`Notification channel configured twice`),
not a precedence rule, because a channel reachable two ways makes "which channel sent this?" a question
with no durable answer. In `off` and `recording` modes the document is not opened at all: reading a
channel credential is what `live` means.

## Delivery outcomes and the approval callback

Every finished attempt records one bounded word in `notification_attempts.cause`, and it is the whole
diagnosis: `accepted` (a receipt that repeated the delivery id), `rejected` (the channel answered and did
not accept, or its adapter refused the send), `transport` (no answer could be obtained) or `policy` (the
platform refused to send at all — a restricted event, or a row routed to a channel this process has no
client for). `Store.finish_notification` accepts only those words and refuses anything else, so the
field cannot become a place to park a provider's response text. `presentation.delivery_route` shows the
last attempt's `result` and `cause` beside the route, and `GET /v1/records/notification_attempts` shows
one row per attempt. Before this, "the provider was down for five retries" and "the provider rejected
the message" were the same row, which is the half of *delivery absence is visible* that this closes.

`POST /v1/callbacks/{channel}` is the one inbound route a channel's message can point at, and it is
small on purpose. A human-channel send mints a single-use code (`secrets.token_urlsafe(32)`), stores its
SHA-256 digest on the outbox row with an expiry (default one hour, bounded 60..86400 s at the claim) and
hands the code to the channel in a *copy* of the payload, so the durable row keeps holding no secret;
`TelegramClient` prints it as one extra line only when `LO_DISPLAY_CONFIG` names an HTTPS
`callback_base` that carries no credentials, query or fragment, and the adapter still never reads the
bot's update queue. A retry mints a new code and the superseded one matches nothing stored.

Receipt answers:

| Situation | Answer | Why that one |
|---|---|---|
| Code matches the delivery, the channel and the time window | `200 {"status": "intent_recorded", "decided": false}` and one `action.approval_intent` audit row | The action stays `pending`: a callback is not completion (CONTRACTS §5) |
| Wrong code, unknown channel, or a code minted for another channel | `401 {"error": "callback_unauthorised"}` — one fixed body for all three | The difference would confirm which channels exist and which code shapes are recognised |
| Code already used | `400 {"error": "conflict", "detail": "Notification callback has already been consumed"}` | Durable, repeatable, and records nothing a second time |
| Code past its expiry | `400 {"error": "conflict", "detail": "Notification callback has expired"}` | A spent code and a stale one are different facts for the operator |
| Action absent, from another incident, or not `pending` | `400 conflict` | The intent is bound to the incident the delivery announced |
| A `reader` token | `400 not_authorised`, before the code is looked up | The role gate runs first, so a refusal cannot spend a code |
| A `summary` token | `403 summary_only` | The read-only portal surface stays read-only |

What the route cannot do is decide anything. It writes `action.approval_intent` naming the identity on
the **bearer credential** — no body field names an identity, and a body carrying any field beyond
`{token, action_id}` is not a callback at all — and the decision still goes through
`/v1/actions/decision` under a `human` credential. A `proposer` (agent) token may record an intent and
is refused the decision, which is the §5 self-approval clause kept intact on the new path. Restricted
events are still refused on every channel: widening that is a decision item, not a task.

"Expiry", which the component row names as a required interface, means three separate clocks and this is
the one place they are listed together, because a reader should not have to open three files to find out
which one a message refers to: the delivery **lease** (`outbox.lease_until`, 5..300 s, an expired lease
returns the row to `pending` or `dead`), the **attempt cap** (`max_attempts`, then the row is `dead` and
only a human retry moves it), the **staleness bound** on the event itself
(`max_event_age_seconds`, then the row is suppressed as `event-too-old` and never replays — this is the
"a delivery that is no longer worth sending" case, and the incident resolving while queued is covered by
the head-of-line rule, not by a fourth clock), the **action**'s own `expires_at`, and the **callback
code**'s `callback_expires_at`. All five are durable; none of them is the others.

The tests for this section are `tests/test_notification_channels.py` (registry, per-channel budgets, one
breaker not leaking into another), `tests/test_notification_attempts.py` (the cause words, the redaction
discipline re-run against a forced transport failure, and an old file opened under this build),
`tests/test_notification_callbacks.py` (every answer in the table above, plus the §5 approval scenario
taken through the callback) and `ApprovalLineTests` in `tests/test_telegram.py`.

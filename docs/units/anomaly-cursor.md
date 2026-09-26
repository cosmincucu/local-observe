# Unit: Anomaly cursor

**File(s):** `local_observe/platform/anomaly_cursor.py` (used by
`local_observe/platform/anomaly.py`) · **Tests:** `tests/test_anomaly_cursor.py` (the file's own
rules) and `tests/test_anomaly.py` (the producer's rounds, crash points and replays) ·
**Config:** `LO_ANOMALY_CURSOR`, alongside `LO_ANOMALY_CONFIG` and `LO_ANOMALY_SOURCE` — both
commented in `examples/full/.env.example`

> The durable anomaly cursor, the durable successor of event kinds's in-memory pending batch. Design:
> `scratch/codex-wave2-20260908/anomaly-durability-DESIGN.md` (approved) →
> `scratch/codex-wave3-20260908/anomaly-PLAN.md`; the amendments that changed it are in
> `scratch/codex-review-20260908/anomaly-durability-LEDGER.md`. The knob table and the reasoning for
> each default stay in [`local_observe/platform/README.md`](../../local_observe/platform/README.md)
> ("Seasonal anomaly baselines"); this file is the contract of the **state file** and what an operator
> does when it refuses.

## Purpose

### Opt-in coverage episodes

Per-series `coverage_unjudgeable_windows` defaults to `0` (disabled) and accepts
integers `0..100`. A positive threshold counts consecutive unjudgeable windows
only after this cursor has acknowledged a judgeable window for that series.
Cold start and insufficient history never open an incident. Idle, insufficient
and judgeable windows reset the count; only a judgeable window resolves an open
coverage episode. The counter saturates at 100. Coverage has its own stable
`anomaly-coverage.<series-id>` condition and version; ordinary anomaly identities
are unchanged.

With coverage disabled, cursor schema 1 and its existing bindings and payloads
are unchanged. A fresh cursor with any enabled series uses schema 2. Every
schema-2 entry additionally stores `coverage` with `previously_judgeable`,
`consecutive_unjudgeable` and `coverage_open`. Its pending envelope stores the
original verdict, next coverage state, and one or two complete sample/event
pairs with individual digests. A recovery can therefore deliver coverage
resolution and the ordinary anomaly verdict together. All four POST slots are
checked before starting that delivery. The 32-POST round ceiling and durable
round-robin scheduling remain in force. Counts, flags and the window are
acknowledged only after all responses arrive; partial delivery replays the
entire stored sequence byte for byte without reading the series again.

**No automatic migration or reset:** enabling coverage with an existing schema-1
cursor refuses before query, delivery or write. Retain the existing cursor and
disabled configuration until the explicit offline migration below is reviewed
for that deployment; do not delete or reset the cursor to enable this feature.
A schema-2 cursor is not readable by older releases, so rolling
back an enabled deployment also requires a separately reviewed state plan.
Unknown fields, invalid counters, oversized/missing deliveries and inconsistent
coverage transitions refuse read-only. The existing 2 MiB file cap still applies.

`tests/test_anomaly_coverage.py` exercises real verdicts, cursor save/load and
platform intake for cold start, thresholds, interrupted streaks, both recovery
statuses, partial responses, exact replay and malformed state.

Remember, across the gap between two runs of the producer, which evaluation window each series was
judged at and what the platform still has not accepted. Nothing here is a second opinion about
whether something is an anomaly: it is the memory that lets the same verdict be re-sent instead of
re-invented, and the reason a store outage costs latency instead of an incident.

The rule the whole module exists for:

1. record that this series **has the turn** (`last_served`), and for a fresh window that the window is
   **being attempted** (`owed_end`) — one fsync, before the store is asked anything about it;
2. read the store and judge it;
3. write **both** request bodies to the cursor and fsync them;
4. POST the evidence sample, then the event;
5. acknowledge the window — **only** after both answers arrived.

A crash, a refusal or a lost socket at any step leaves that window owed and the position unchanged, so
the next round starts from it. The two debts differ in one way that matters: an owed **attempt** is
re-read (nothing about that window was ever promised, so a fresh verdict is not a changed one), while an
owed **batch** is replayed from stored bytes and never re-read — recomputing an old window after a crash
can yield a different value, a different instant, and therefore a different `sample_id` and event, which
the platform refuses as `Event retry changed contents`. A series whose payload is already held is never
queried again, which is what makes the replayed event the same `source_event_id` and therefore one row in
the store rather than a re-fire.

Replaying stored bytes is only safe while those bytes still belong to the series that stored them, so
**every** configured entry is preflighted against the resolved configuration before the round's first
query: the entry's binding; its window positions — `last_acked_end`, `anchored_at` and `owed_end` are
whole seconds on that series' evaluation grid, and an owed attempt is exactly one evaluation past the
last ack, which is the check that stops a *payload-less* owed marker from being answered by judging the
hour after next and skipping the hour in between; and, if it owes a batch, the event's resource, rule,
`rule_version`, evidence query kind and parameters, and the window's length, alignment and distance
from the last acknowledged window, with the platform's own `state.validate_event` over the whole shape
(:func:`replay_coherent`). A mismatch is a refusal that performed no read, no POST and no write.

## The file

One JSON document, canonical form (sorted keys, compact separators — the same bytes
`local_observe/http.py` sends), mode `0600`, written `mkstemp` → write → `flush` → `fsync` →
`os.replace` → directory `fsync` on POSIX:

```json
{"last_served": "demo-load", "schema_version": 1, "source": "anomaly-detector", "series": {
  "demo-load": {
    "binding": "<sha256 of the series' identity and knob values>",
    "last_acked_end": "2026-08-05T00:00:00.000000+00:00",
    "anchored_at": "2026-08-05T00:00:00.000000+00:00",
    "anchor_logged": true,
    "owed_end": null,
    "delivered": 11, "no_verdict": 29, "refusals": 0,
    "pending": {
      "window": {"start": "…", "end": "…"},
      "sample": { …the exact /v1/evidence body… },
      "event":  { …the exact /v1/events body… },
      "evidence_sha256": "<sha256 of the wire bytes of sample>",
      "event_sha256": "<sha256 of the wire bytes of event>"}}}
```

`source` is the producer identity (`LO_ANOMALY_SOURCE`), and it is a binding, not a comment: a cursor
restored under a different identity refuses to open. `last_served` is the round-robin position — the
series that was last given a window attempt, **before** that attempt read or posted anything — and it is
a name rather than a counter so that no saturating count can flatten the schedule. `owed_end` is the
window whose attempt was recorded and never acknowledged — the trace a failed or interrupted **read**
leaves, and what stops the next round (with a newer clock) anchoring past an hour this producer already
began. `binding` covers `id`, `resource_id`, the SQL digest, `season`, `k`, `window_days`, `min_points`,
`min_per_bucket` and `evaluation_seconds`, and deliberately **not** `tick_seconds` — how often the
producer looks is not what a window means, so retuning the loop must not throw away a backlog.
`pending` is at most one batch per series, which is all one window can ever make, and it always holds
**both** bodies: an event with no evidence sample is a record this producer did not write, and is
refused.

Bounds, all refusals rather than clamps: `MAX_ENTRIES` 32 series entries (16 configurable + room to
retain ones that left), `MAX_EVENT_BYTES` 64 KiB and `MAX_SAMPLE_BYTES` 2 KiB per payload — the
platform's own ceilings in `state.validate_event` / `state.put_evidence` — and `MAX_CURSOR_BYTES`
2 MiB for the file. `MAX_COUNT` is the opposite: the lifetime counters **saturate** there rather than
refusing, because the ceiling is also what `load` checks against and a counter that walked past it
would leave a cursor holding an undelivered batch unable to save anything ever again. The consequence
is a number that stops being a census: **a count sitting at `MAX_COUNT` is a lower bound** — "at least
this many windows delivered / judged without a verdict / refused" — and the per-series row of a round
and the log line beside it must be read that way, not as an exact lifetime total. Nothing has been
measured at the ceiling on a real host — the point of stating it is that a reader who does meet
`1000000000000` in a log line knows it is a clamp and not a count.

The digests beside a pending batch are **corruption checks, not authentication**. Anyone who can write
this file can rewrite both numbers with it; what they buy is the refusal of a torn or hand-edited
payload. Nothing here signs, seals or verifies the cursor against a key, and the file's real protection
is the private parent directory and the single owner lock, both of which are provisioning the operator
owns.

## Public API

The module owns the file, not the decisions. `anomaly.py` calls these and nothing else touches the
path.

- `cursor_location(environment=None) -> Path | None` — the configured path, or None when unset/blank
  (the difference between *off* and *misconfigured*). Relative paths, `..` segments and — on the
  platform that has them — explicit UNC and device forms are refusals. Mapped drive letters and POSIX
  remote mounts are **not** detectable here and are unsupported instead: see the module docstring.
- `private_parent(path) -> Path` — the cursor's parent, checked for existing, for having **no symlinked
  ancestor at any level**, and for carrying no group/other access bit on POSIX. Called by `main` at
  startup and by `save` on every write; `symlink_present` is the single filesystem question it asks,
  and the seam the deterministic (every-platform) refusal tests substitute for.
- `load(path, *, source) -> dict` / `save(path, document) -> None` — read and write the validated
  document. `load` refuses a symlink as the file *or* anywhere above it, before opening it. `save`
  validates before it writes a byte, so it can never create a file its own `load` would refuse.
- `empty_document(source)`, `ensure_entry(document, series)` — a first-start document, and the one way
  an entry appears (adding past `MAX_ENTRIES` refuses rather than evicting).
- `serve(document, series)` / `rotation(document, names)` — take the turn and ask who is next. Written
  before the attempt's query and POST, so the rotation is the same answer in the next process.
- `begin(document, series, *, window, sample, event)` — store the two payloads owed for one window,
  with their wire digests. Called before the first POST, and it always names the owed window too.
- `replay_coherent(series, entry, *, source, now, rule_version)` — the preflight described above:
  binding, the entry's window positions against this series' evaluation interval, and every config-tied
  field of an owed batch, reusing `state.validate_event` rather than restating the event schema.
- `owe(document, series, *, window_end_s)` — record that a window is being attempted, **before the store
  is asked anything about it**. Cleared only by acknowledging that same window; no newer window may be
  acked, begun or owed on top of it.
- `acknowledge(document, series, *, window_end_s, verdict)` — the only direction a cursor travels:
  forward, one window at a time, and an event verdict requires the batch it delivered.
- `note_refusal`, `mark_anchored` — count a refusal (saturating; position and batch untouched); record
  that the anchor warning was already written.
- `align_end`, `next_window_end`, `lag_windows`, `window_text` — the arithmetic of what is owed.
  `next_window_end` is pending first, then the owed attempt, then `last_acked_end + evaluation`, then
  (an entry that never judged anything) **its own** newest completed window. The fourth case is asked
  per entry with the clock and nothing else: no function in this module computes a shared position for a
  newly configured series to inherit, because there is no approved shared-horizon, backfill or
  join-depth policy here. There is no `max(last + interval, now)` anywhere in it: the resume point is
  the cursor, never the clock.
- `stale_entries`, `unresolved_pending` — entries no configuration names, and those that also hold a
  batch. Both are reported by every round and repaired by nobody.
- `series_binding`, `wire_bytes`, `payload_digest` — the identity of a verdict, of a request body, and
  of the bytes the client will send.

## Behavior worth knowing

**A missing file is a first start; a missing variable is a refusal.** With `LO_ANOMALY_CONFIG` named
and `LO_ANOMALY_CURSOR` not, the producer exits 1 with one WARNING naming the variable: it will not
deliver verdicts it cannot re-send. An *absent* file inside a good parent is the operator's approved
first start — the newest completed window is judged, and one WARNING says in words that every earlier
window was never judged, is not replayed, and that the missed count is `unknown` (it is not knowable
from what the store still holds, and a number computed from the oldest training point would be a guess
wearing a measurement). A series **added to a cursor that already holds older siblings** is anchored the
same way, at its own newest completed window: the producer was not configured to judge that series
earlier, so it has no history of it to resume, and the durable anomaly cursor refuses the unbounded replay of one. The
sibling's backlog drains one window per turn beside it, which is the difference between *behind* and
*lost*. That line is written once per series, and the `anchor_logged` flag is what makes "once" survive a
restart.

**Refusals are read-only.** A cursor this module refuses is left byte-for-byte as it was found — never
rewritten, truncated, migrated, re-keyed or deleted. `refusals` is incremented only in the same
document write that a round was otherwise entitled to make, so a round that was refused *before* it
could earn a write — an undeclared resource, or a stored entry that the resolved configuration no longer
authorises — leaves no counter behind either. The refusal with no side effects is the one an operator can
fix and rerun without wondering what the rejected round already told the platform.

**One round is bounded and fair, and the fairness is a name rather than a comparison.** Across series
the round goes in durable round-robin order: `rotation` starts after `last_served` and wraps, and
`serve` records the turn *before* that window's query and before its POST, so a process that dies
mid-window leaves the turn consumed and the next process continues rather than restarting. What this
replaced is leading with the oldest owed window: a series whose payload the platform permanently refuses
owes the *same* window forever, so it held the front of every round and every restart and the series
behind it went unread — and sorting ties by refusal counts cannot reach that case when the two series
owe *different* hours, because different windows never tie. Time now ranks nothing across series.
Within a series nothing changed: pending batch first, then the owed attempt, then one window past the
last acknowledgement, ascending, contiguous, and never read off the clock. A caught-up series is skipped
(it owes nothing, so it takes no turn) and a refused series settles after one attempt, so every eligible
configured series is served within `MAX_SERIES` rounds at a budget of one window. Ceilings are code
constants a caller may only tighten: 4 passes per series (`MAX_CATCH_UP_WINDOWS`), 16 window attempts,
16 reads and 32 POSTs per round.

**An acknowledgement that was actually accepted looks identical to one that was not.** `JsonClient`
retries an idempotent request into a `TransportError` only when every attempt failed; a request that
the store accepted on attempt 2 and the transport lost on attempt 3 is indistinguishable from the
outside. The producer's response is not to guess: the batch stays pending, the same bytes go out
again, and the store's `events UNIQUE (source, source_event_id)` makes the second answer a duplicate
row. Refusing to re-send is what would lose an event. That protection is about *identical bytes only*:
it says nothing about a window this producer no longer remembers judging, and the platform cannot see a
local acknowledgement at all.

**A round that loses its own cursor mid-write has two different failure stories.** `save` writes a
fresh temp file and renames once. Anything that fails **before** the rename leaves the previous bytes
installed and readable — that is the half the producer relies on, and it is why a failed write means the
round posts nothing. A failure **after** the rename (on POSIX, the directory `fsync`) happens with the
new bytes already in place: they are what any running process reads, and only their durability through a
crash is unknown. So "a failed save preserved the old file" is not a promise this code makes or needs;
the rule is that nothing is delivered until a required save has succeeded. The temp file is unlinked in
`finally` — only our own temp file. The `.<cursor>.owner.lock` beside it is created by
`platform/owner.py` and is never unlinked by anything in this unit, producer included: a lock file's
presence says nothing about a live owner, and removing it is how two processes end up both writing.

## Operator surface

There is no command for this file. One round of the producer, with the cursor it will use:

```
LO_ANOMALY_CONFIG=/srv/anomaly.json LO_ANOMALY_CURSOR=/var/lib/local-observe-anomaly/cursor.json \
LO_ANOMALY_SOURCE=anomaly-detector LO_INDEX_PATH=… LO_CLICKHOUSE_*=… LO_PLATFORM_URL=… \
LO_PRODUCER_TOKEN=… python -m local_observe.platform.anomaly
```

To *read* what it holds, open the file: it is canonical JSON, one line, and `jq` can name every field
in the layout above. `series.*.pending` is what the platform has not accepted; `lag_windows` in the
round line is what is still owed; `stale_entries` and `unresolved_pending` name entries whose series no
longer exists in the configuration.

| symptom | what to do |
| :-- | :-- |
| `Anomaly producer cannot start; a configured producer will not deliver verdicts it cannot re-send` (`variable: LO_ANOMALY_CURSOR`) | name the cursor. There is no default path and no in-memory fallback on purpose |
| `LO_ANOMALY_CURSOR must name an absolute host-local path with no ".." segments` | use an absolute path. On Windows that means drive-anchored (`C:\…`), on POSIX root-anchored (`/var\lib\…`), and the same string cannot serve both. A `\\\\host\\share` or `\\\\.\\device` form is refused on Windows too |
| `Anomaly cursor parent directory does not exist; create it privately (mode 0700)` | `install -d -m 0700 -o local-observe /var/lib/local-observe-anomaly`. The producer will not create the directory around its own state |
| `Anomaly cursor parent is reachable by group or other; it must be mode 0700` | `chmod 0700` the parent. On Windows there is no mode to check and no ACL proof is claimed here: the parent is checked for existing and for not being a link, and its protection is whatever the operator provisioned |
| `Anomaly cursor path is reachable through a symlinked directory (…)` | the refusal names the ancestor, which may be well above the cursor's own directory. Replace the link with the real directory, or move the cursor under an ancestry the operator owns. Only symbolic links are detected: an NTFS junction, a bind mount or a drive letter redirected to a share is not, so the whole path to the cursor is trusted provisioning, and a directory swapped in the instant before the open is a TOCTOU gap this advisory lock does not close |
| `Refusing a symlinked anomaly cursor` | replace the symlink with the real file. If the cursor was deliberately moved, stop the producer, move the file, and restart |
| `Anomaly cursor was written by a different producer identity…` | `LO_ANOMALY_SOURCE` does not match the file. Fix the variable; do not edit `source` — that string is what makes an event's `source_event_id` reauthorisable |
| `Anomaly cursor is not JSON` / `… repeats a key` / `… holds unknown or missing top-level keys` / `… schema_version is not 1` / `… exceeds 2097152 bytes` | the file is damage. Restore the cursor from the host's backup, or stop the producer and move the file aside so the next start re-anchors and says so. Every refused window in it was already visible in a `WARNING` |
| `Anomaly cursor holds a pending batch for a window other than the one it owes` (and its siblings: a batch for an acknowledged window, an owed window at or behind the last ack, a count past the ceiling) | the entry contradicts itself, which no write of this producer could have done. Treat it as damage: restore, or read the entry and reconcile it by hand with the producer stopped |
| `Anomaly series <id> changed underneath the cursor…` | the reviewed SQL digest, the resource, or a knob moved. The **whole round** refuses before its first query and without writing a byte, so no series advances until this is resolved: either put the configuration back, or (if the change is intended) delete **that series' entry** while the producer is stopped — its backlog is a statement about the old configuration and cannot be mixed with the new one |
| `Anomaly series <id> owes a batch …` (for a resource the configuration no longer names / whose rule is not this series' / judged by different configuration / not the reviewed metric read / not one configured evaluation long, aligned or past the last ack) | the stored verdict belongs to something other than the series and window it is filed under, and it would have been POSTed as if it did not. Same remedy as a changed binding: restore the configuration, or delete that entry with the producer stopped. Note that the stored digests still match in every one of these cases — this is a disagreement with the **configuration**, not file damage, which is why the check runs against the resolved knobs and not against the checksums |
| `Anomaly series <id> holds <field> at a fraction of a second` / `… at a position that is not a whole number of configured evaluations …` / `… owes an attempt N seconds after the window this cursor acknowledged …` | the entry's *positions* are not ones this producer could have reached, whether or not it holds a payload — a moved `owed_end` alone is enough, and answering it would ack the later window and skip the interval in between silently. `load` accepts these files (the text is canonical and the ordering runs forwards), so this is the configuration speaking: check the series' `evaluation_seconds` first, and treat the entry as damage if the knob did not move — same remedy as the row above |
| `Anomaly cursor already holds 32 series entries` | stop the producer and delete the entries of series the configuration no longer names. They are retained deliberately, so this is the operator's cut, not the producer's |
| `OSError` at start (`another operation holds this resource` on Windows) | another anomaly process owns the cursor. Find it (`systemctl status local-observe-anomaly`) rather than deleting the lock file |
| `lag_windows` will not fall | the front of the queue is owed and refused: read the `WARNING` lines naming that series (`4xx` = the payload is wrong and will stay wrong until the configuration changes; a lost socket = the store is down, and the same bytes go out again next round) |

Deleting an entry is the only repair that touches the file by hand, and it drops a delivery the
platform never accepted. Do it with the producer stopped, or the next round will re-add the entry with
a *fresh* anchor and a second attempt at a window that may already have been told about.

## Backup and restore

This file is host-local state, which puts it inside W-P1-01's unfinished whole-deployment backup:
backing up the platform SQLite database alone does not carry it, and no claim here says it does. What
each outcome actually means:

- **a coherent stopped snapshot of both** (producer stopped, then database and cursor copied together)
  is the safe case, and the only one where the resume is exact: the owed window is replayed from stored
  bytes and the store folds it into the row it already has.
- **cursor absent, database restored** — a first start: one WARNING, no replay of history before the new
  anchor. The remembered history is gone, and with it any promise about duplicates or extra incidents:
  a window the platform already accepted may be judged again, and a re-judgement is a new verdict.
- **cursor older than the database** — the producer walks forward from where the old file stood, so it
  **can re-query a window the platform already accepted**. Identical bytes fold into the existing row;
  a changed verdict either meets `Event retry changed contents` or arrives as a second event under a
  new id. Database dedup is not a correctness repair — it is what the asymmetry looks like from
  downstream.
- **asymmetrical or partial restores** (one of the two files, the wrong host, the wrong producer
  identity) need an explicit operator reconciliation: read the entry, decide, and say what was done in
  the deployment record. Nothing here automates a reset, a delete or a re-anchor, and no code path in
  this unit deletes the file.

The cursor is not a copy of the platform's event history and must not be treated as one: it holds the
last acknowledged window per series, lifetime counters, and at most one undelivered batch.

## Explicit offline schema migration (#275)

`python -m local_observe.platform.anomaly_migrate` converts a schema-1 cursor to
schema 2 in a **new file**. The producer never invokes it. Required arguments are
`--input`, `--output`, `--config`, `--source` and `--expected-sha256`; `--config`
names the target configuration with at least one coverage threshold enabled.
Without `--apply`, the command checks a snapshot and writes nothing, including
no ownership lock. It returns JSON with the input/output digests and pending count.

Before applying, obtain approval for the deployment's exact state operation, stop
the producer and take a scope-appropriate backup under the procedure above.
Read that backup back and compare its file digest with the stopped input. Record
both paths and digests. The tool does not create or verify this backup for you.

For a reviewed deployment, a dry-run invocation has this shape (replace each
placeholder with the approved value):

```text
python -m local_observe.platform.anomaly_migrate --input INPUT --output NEW_OUTPUT --config TARGET_CONFIG --source PRODUCER_ID --expected-sha256 INPUT_SHA256
```

Adding `--apply` acquires the producer's existing owner lock, checks the source
again and creates the output exclusively with private permissions. Existing output,
input aliases, unsafe parents, identity/configuration drift, removed stored series,
malformed state and a digest mismatch refuse. Pending ordinary payloads, IDs,
digests, counters and checkpoints survive; coverage starts without invented history.
Pending acknowledgement is still performed by the producer, never this command.

Successful apply reports the new file's readback digest. A write/fsync/readback
failure leaves any new file **unverified** and returns failure; it never deletes
the input or replaces an existing destination. File fsync is performed, but no
directory-fsync/crash-atomic publication guarantee is claimed. The lock excludes
cooperating producers, not arbitrary external writers. A deployment owner must
review the new file and separately authorize its installation and enablement.
Rollback requires the corresponding coherent schema-1 backup and compatible
configuration; this command is not a downgrade tool.

## Gotchas / debt

- **No retention horizon and no compaction.** Idle series keep their entries forever; the file is
  bounded but nothing trims it. A `--show-cursor` / `--resolve-cursor` pair belongs on a later card.
- **`evaluation_seconds` and the unit's `schedule.interval` are not derived from each other.** A
  mismatch means the producer judges windows the unit never runs it for; the cursor will happily keep
  the resulting backlog.
- **`MAX_CATCH_UP_WINDOWS` (4) is the per-series depth and the fairness rotation's bound**, so a round
  that walks the deepest backlog in the file walks at most four windows of it. That is the intended trade
  — the round is a load bound, not a catch-up SLA — but it means a long outage drains several rounds
  after the store returns, and `lag_windows` is the number to watch, not `result`.
- **A window is judged once while this cursor survives intact, and that is all the file can promise.**
  The old clock-only behaviour — "the same window re-judged by a faster tick" — is gone, so a test or an
  operator who expects a second verdict from a second round at the same `now` will see `caught_up`
  instead. Two cases still re-read: a window whose **read** failed before any payload existed (nothing
  was ever promised about it), and anything a lost or stale cursor has forgotten judging.
- **Durability, stated as what is verified and what is not.** The temp file is fsynced before the atomic
  `os.replace`, which is what a running kernel needs to never show a half-written cursor. That is not a
  power-loss claim: no hardware, controller or filesystem behaviour has been verified here, and on
  Windows there is no directory `fsync` at all, so the durability of the rename itself is unverified on
  that platform. What a lost rename costs is one unacknowledged window that is retried, never a false
  acknowledgement — nothing is acked before both POSTs answered — and what a lost *file* costs is the
  remembered history, which nothing here can reconstruct.
- **The advisory lock is host-local, and no filesystem detection is attempted.** A single host on a
  local filesystem is the supported shape. `flock` on NFS/SMB/CIFS is host-local or absent, and such a
  mount does **not** necessarily fail closed: it may answer the lock on both machines at once. The
  operator verifies the path is local; the code refuses only what a path string and `is_symlink` can
  show (relative paths, `..`, symlinked ancestry, UNC/device forms on Windows), and a mapped drive or
  bind mount is invisible to it.

## Running its tests

```
python -B -m unittest tests.test_anomaly_cursor tests.test_anomaly -v
```

Both files run with no network, no ClickHouse and no systemd: the platform is the real
`platform/state.py` `Store` on a temp SQLite file, and the store is a stub that answers rows. The
durability half of `tests/test_anomaly.py` (`StartupTests`, `PendingBatchTests`, `CatchUpTests`,
`CursorRefusalTests`) is the reviewer's two reproductions from
`scratch/codex-review-20260908/verify-findings.py` — *a refused window was never retried* and *a
same-window re-read changed the event* — expressed as producer rounds rather than as calls into
private functions.

Six tests in these two files carry an OS gate: two POSIX mode-bit checks, three real-symbolic-link
integration cases that on Windows skip only when the host withholds `SeCreateSymbolicLinkPrivilege`
(`OSError.winerror == 1314`, and any other error is a failure), and one POSIX post-rename directory
`fsync` integration case. How many of the six actually skip depends on the host: six on a Windows host
without that privilege, three on a privileged Windows host (only the POSIX-gated ones), and **zero on
Linux, where all six must run**. They are named id by id with those conditions in
`docs/testing-standards.md`; the equivalent *refusal* logic is additionally pinned by
mocked-`symlink_present` and mocked-failure tests that run on every platform, and those prove the shape
of this implementation's checks — which paths it examines, in what order, that it refuses before
opening and writes nothing — not POSIX mode semantics, not how a kernel resolves a link, and not what
`fsync` survives. The Linux execution proof for the six is **pending main's CI run and has not been
measured from here**; the Windows-side counts are the only ones observed.

# Backup and recovery — LAN synthetics

Two independent units of state, and the reason `docs/CONTRACTS.md` §7 insists they be recorded
separately is exactly this component: one is a **history nobody relies on for correctness**, the other
is a **cursor whose loss silently changes what gets judged**. Backing up one and not the other is a
normal thing to do; pretending they are one backup is how a restore re-opens a closed window.

## 1. Gatus's own history — `gatus-data` (sqlite at `/data/gatus.db`)

| | |
| :-- | :-- |
| What lives here | probe results, state-change events, the per-endpoint uptime/response-time windows the badges and `/api/v1/endpoints/.../uptimes` render |
| Who reads it | Gatus's own API and dashboard, and — through the API — `local_observe/platform/detection_worker.py` |
| Is it platform authority? | **No.** The platform's incidents, events and evidence are the record. This is the engine's working history, and `docs/evidence`/`components/control/platform/backup.md` already says the synthetic overlay "owns Gatus history … Those are independent service data, not platform authority" |
| Loss means | the dashboard's charts and uptime percentages restart from the restore point. **No verdict is lost**: every result the adapter consumed was already posted to the platform as an event and (for a successful sample) an evidence row, and neither refers back into this database by key — `gatus_sample()` computes `sample_id` as a digest of the result row it read, not a Gatus row id |
| Duplicate policy on replay | re-serving old results is bounded by `gatus_sample()`'s watermark rule: results newer than the evaluation `before` are ignored, and the newest qualifying one wins. A restored history that re-answers a window cannot re-file a verdict for it, because the cursor refuses to re-run a completed window (§2) |

Recipe — the file is live while Gatus writes it, so stop the writer or copy it out of the running
container; do not tar a mounted sqlite directory:

```sh
project=…; docker compose -p "$project" stop gatus                       # Gatus has no online backup API
# There is no in-container copy step available: the image is FROM scratch, so `run --rm gatus cp …`
# has no /bin/cp to execute. Copy the VOLUME from the host instead — which is also the only way to do
# it without a tool inside an image this repository does not build.
docker run --rm -v "${project}_gatus-data:/data" -v /approved/scratch:/out alpine \
  sh -c 'cp -a /data/gatus.db /out/gatus.db && sqlite3 /out/gatus.db "PRAGMA integrity_check;"'
sha256sum /out/gatus.db
```

Verify by reading it back — `integrity_check` must answer `ok` and the row counts must be non-zero —
and name the artifact and its sha256 in the change that took it, before anything mutates.
`PRAGMA integrity_check` needs a `sqlite3` binary, which the scratch image does not have; run it on the
host or in the alpine helper above, never against the live file.

Restore is into a **new** volume in a **scratch project name**, `gatus` started alone (no detector, no
platform). The engine publishes no port, so read it from a container on that project's network — the
same shape as [conformance.md](conformance.md) step 2, with a scratch one-off instead of `detector` if
you brought the engine up bare:

```sh
docker compose -p gatus-restore run --rm --no-deps --entrypoint python \
  "$LO_PLATFORM_IMAGE" -c 'import os,urllib.request; print(urllib.request.urlopen(urllib.request.Request("http://gatus:8080/api/v1/endpoints/lo_platform-http/statuses", headers={"Authorization": "Basic " + os.environ["LO_GATUS_CRED"]}), timeout=5).status)'
```

…must answer 200 and the body must carry the endpoint's history (`?limit`/page sizing is upstream's;
`storage.maximum-number-of-results` bounds it at 100 by default). What is regenerated: nothing. There is no rebuild-from-source for
this volume; if it is gone, the history is gone and the honest statement is the "Loss means" row above.

## 2. The detector cursor — `detector-data` (`/data/cursor.json`)

| | |
| :-- | :-- |
| What lives here | `{'last_end': <utc text>, 'pending': {'end', 'sample', 'events'} \| None}` — the last window whose delivery the platform acknowledged, and the batch built but not yet acknowledged |
| Who reads it | only `detection_worker.tick()`, and it holds `exclusive_owner(cursor)` for the life of the process, so one writer at a time |
| Loss means | `last_end` is `None`, so the next tick evaluates the current window and continues. **No harm and no replay**: the cursor is not where a verdict comes from, it is where "which window did I already close" comes from, and every window it re-closes would be a *new* window anyway |
| Restoring it **forward** (a `last_end` in the future) | the adapter returns `idle` until wall clock passes that value: a synthetics blind period with a healthy-looking container. Prefer restoring the cursor *with* the platform file, or restore it absent and accept the one skipped window |
| Restoring it **back** (older than the platform's own record) | the same windows are evaluated and re-posted. This is the one case that needs a duplicate policy stated, and it holds: `detections.event()` derives `source_event_id` from `[rule_id, rule_version, resource_id, window]` and `state.py` declares `UNIQUE(source, source_event_id)` with an idempotent upsert, so a re-run window is *the same row*, not a second finding; and evidence dedups on `digest([identity, sample_id])` with `sample_id = digest(<the Gatus result row>)`. Restoring an older cursor therefore cannot multiply incidents — **provided** the Gatus history still contains those results (§1). With the cursor old and the engine's history truncated past them, `gatus_sample()` returns `None` and the window files `coverage`, not a fabricated verdict |
| A `pending` batch that never got acknowledged | is retried on the next tick, unchanged, and the process keeps raising until intake answers 200 — so a restore that carries a `pending` batch is a *resume*, not a replay hazard. Its `events` were built against the window named in `pending.end`, so the identity is stable across the retry |
| Clock | the file stores UTC text; a host restored with a clock behind `last_end` reads `idle` until it catches up. Nothing here trusts a monotonic clock |

Back it up **with** the platform database, in the same stopped window, and note the pairing in the
restore record — `components/control/platform/backup.md` already says to pause the detector around a
coordinated cursor/state checkpoint or to restore with the detector disabled and reconcile the cursor
and its pending batch before enabling it. `docs/CONTRACTS.md` §7's sentence "Record collector
queues/cursors separately and their replay/duplicate policy" is answered by the two rows above:
replay is idempotent by event identity, and coverage — not a false verdict — is what a gap produces.

## 3. What is not either of those

* `LO_GATUS_CONFIG` (the rendered Gatus document) and every rule file in `LO_DETECTION_RULE_DIR` are
  **declarations in the operator's versioned repository**, not runtime state: they are restored by
  deploying, and the copy in the rendered form here carries a bcrypt hash, so treat the host file the
  way the platform's credential files are treated (0600, in the secret backup set, never in a bundle).
* The credentials (`LO_GATUS_TOKEN_FILE`, `LO_PRODUCER_TOKEN_FILE`) belong to the credential set, not
  to this component's volumes.
* Nothing in either volume is a queue: the outbox, and therefore every notification promise, lives in
  the platform database and is covered by that component's backup.md.

Restore order that has any chance of being right: platform state, then the cursor, then the detector
enabled — with executors, producers and notification dispatch disabled until the outstanding windows
have been reconciled by hand. None of the recipes on this page has been run: they are written to be
run and reported in `STATUS.md`, and [conformance.md](conformance.md) marks the backup/restore rows
`not-run` for that reason.

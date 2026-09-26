# Upgrade — LAN synthetics

Nothing infrastructure-grade upgrades itself: the pin moves on a branch that carries a reason and a
rollback line, the candidate is seen running against its real consumer (**the detector**) before the
PR merges, and the merge authorises promotion rather than closing this item.

**No Gatus version upgrade has been run from this directory, and none has ever been rehearsed at
all.** `components/control/platform/upgrade.md` said "No Gatus version upgrade has been rehearsed yet"
before this component existed and still says it; this file is where the recipe now lives, and it is a
recipe, not a result.

## What a pin move actually touches

| Layer | What changes | Who else feels it |
| :-- | :-- | :-- |
| the image digest | `LO_GATUS_IMAGE`, plus `versions.json` here and its mirror in `components/control/platform/versions.json:gatus_image` (`tests/test_gatus_component.py` refuses the two drifting apart) | nobody else reads the engine's version, so this is the whole of the "image" decision |
| the config keys in `config.yaml` | upstream renames a `security`, `storage`, `client` or endpoint key | the engine **refuses to boot** on an invalid `security:` block, and validates endpoint conditions at load — a stale key is a start failure, not a silent downgrade |
| the shape of `GET /api/v1/endpoints/<key>/statuses` | `config/endpoint/status.go` and `result.go`'s JSON tags | `detections.gatus_sample()` — the only consumer, and it fails **closed**: an envelope with no `results` list, more than 1000 rows, a row without a parseable `timestamp`, or a row whose `success` is not a boolean is a `StateError`, which the adapter reads as "no sample", which files `coverage` |
| the route's auth semantics | `api/api.go`'s router order, `security/config.go`'s options | `detection_worker.main()`, which sends HTTP Basic because the pinned release offers nothing else on that route (CONTRACT.md). If a future release re-adds a bearer or static-token option, that one `scheme=` argument is the thing to revisit, and this line is the reason it is there |
| the window | `LO_DETECTION_WINDOW_SECONDS` (5..3600 s) | the detector's own healthcheck bound `max(3 * window, 60)` and the rule's `max_age_seconds` — three numbers with one ratio between them, restated in CONTRACT.md |

## In-flight windows across a version change — the question this file exists to answer

A window is `[end - window_seconds, end]`, built once, written to the cursor as `pending` **before**
any delivery, and only then posted; the cursor advances only after intake has acknowledged every event
in the batch. Against that, a Gatus restart or version change:

1. **Mid-window, engine dies or is replaced.** No window is in flight in the adapter's sense: it has
   not chosen a window until the engine answers. The tick's `GET` fails (`TransportError`) or returns
   an error status, `gatus_sample()` yields `None`, and `evaluate()` files `coverage` — **firing, not
   resolved**. The engine's own probe history is unchanged by the swap (same volume), so results
   produced by the old version are read by the new one.
2. **`pending` batch built, engine replaced before delivery.** The batch is durable in the cursor and
   is retried **verbatim**: same `events`, same `window`, same `source_event_id`. A new Gatus version
   cannot alter an event that was already built, so an upgrade in this window duplicates nothing
   (`state.py`'s `UNIQUE(source, source_event_id)` upsert) and loses nothing.
3. **The new version's newest result is older than the watermark.** `gatus_sample()` ignores anything
   *newer* than `before` and takes the newest qualifying row, so a slow-starting engine (first probe
   not yet due after a restart) reads as a missing sample for at most one engine `interval`, then as
   `coverage` if it persists. Set `LO_DETECTION_WINDOW_SECONDS` and the endpoint `interval` so that a
   cold start is visible as coverage rather than as a resolved-healthy gap — the shipped pair is
   30 s interval against a 5 s window and a 120 s `max_age_seconds`.
4. **A version that changes what `success` means for an existing condition.** Not detectable from the
   envelope. This is why step 3 below runs the *same* injected failure against the candidate and
   compares verdicts rather than confirming the container came up.
5. **Downgrade.** Always to a *verified* copy of both volumes plus the previous digest, never a live
   file rewritten in place; the engine's sqlite schema is forward-only across versions in practice
   (it has no migration ledger an operator can run), so a downgraded binary reading a newer
   `gatus.db` is UNVERIFIED territory. Roll back the **cursor** with it or reconcile it by hand
   ([backup.md](backup.md) §2's "restoring it back" row).

## Procedure

1. **Back up and verify first** — both units in [backup.md](backup.md), each read back (the
   `integrity_check`, the row counts, the `sha256sum`, the cursor JSON parsed), named in the change,
   **before** any candidate boots. `LO_GATUS_IMAGE` is `pull_policy: never`, so the candidate must
   already be in the local daemon: pull it by digest. Resolve the candidate the way the stage bundle
   does, with this repository's own tool rather than a registry web page — it takes the single
   linux/amd64 entry of the index and verifies every `Docker-Content-Digest` against the sha256 of the
   bytes it arrived with, which is the check that makes the number in step 6 mean something:
   ```sh
   python -B -c "import sys; sys.path.insert(0, 'scripts'); \
   from resolve_images import resolve; print(resolve('twinproduction/gatus:<candidate-tag>'))"
   ```
   It prints `source_index_digest`, `image` (the string that goes in `LO_GATUS_IMAGE`) and `platform`;
   `components/control/synthetics/versions.json` records the same command's output for the current pin.
2. Read the release notes for **every** version crossed, and the diff of `api/api.go`,
   `config/endpoint/{status,result}.go`, `security/*.go`, `config/config.go` and `Dockerfile` between
   the two tags. Two specific things to look for: a change to **which routes sit behind the security
   middleware** (that ordering is the entire authentication promise of `config.yaml`), and a change to
   the **JSON field names** `gatus_sample()` reads.
3. Run the candidate in a **different project name**, on a copy of the verified `gatus-data`, with the
   live stack still running. Neither service publishes a port, so the two requests below go through a
   container on the candidate's own network — the same snippet as
   [conformance.md](conformance.md) step 2, run with `-p <candidate>` and pointed at the candidate's
   endpoint key:
   ```sh
   compose-candidate exec detector python - <<'PY'   # LO_GATUS_URL points at the candidate's service
   import os, urllib.error, urllib.request
   url, token = os.environ['LO_GATUS_URL'], open(os.environ['LO_GATUS_TOKEN_FILE']).read().strip()
   def code(headers):
       try:
           return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=5).status
       except urllib.error.HTTPError as exc:
           return exc.code
   print('with:   ', code({'Authorization': 'Basic ' + token}))
   print('without:', code({}))
   PY
   ```
   Both lines are one check: a candidate that answers `200` to the second has lost the security
   middleware, and that is the defect class this component exists to have closed.
4. Point a **scratch** detector at the candidate and run the injected-failure scenario from
   [conformance.md](conformance.md) end to end, including the recovery half. Pass is the same four
   events in the same order with the same `rule_id`/`condition` spelling as the pinned version
   produced, and `finish` on no duplicate event rows for the windows.
5. Confirm the two `versions.json` copies name the new digest together (the mirror, see above), that
   the **superseded** block still names the digest being retired and why, and that
   `docs/COMPONENTS.md`'s row still agrees with reality. `docs/BUILD.md` names no third-party digest —
   it lists local build targets — so it is not one of the places a Gatus pin move has to touch.
6. Promote by editing the operator's environment file, then restart the two services. The cursor does
   not need a reset for a version move; it needs one only if it names a window in the future.

## Rollback

Old digest plus, if the engine wrote anything you did not read, the verified `gatus-data` copy it came
from. There is no schema downgrade path to test and none is claimed: `pull_policy: never`, the previous
image already in the daemon, and the two-line check in step 3 re-run against the rollback candidate.
No image here has been published, signed or promoted; both digests in `versions.json` are upstream's.

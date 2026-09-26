# Upgrade — component `anomaly`

> **NOT RUN.** No image has been built, no container started and no `docker compose` command of any
> kind has been executed from this repository (anomaly component's brief forbids it). Every command below is written
> from this manifest, `components/control/platform/Dockerfile`, `docs/BUILD.md` and what
> `anomaly_cursor.py` refuses. Each carries its pass criterion so the first host run is a check and not
> an experiment.

## The unit of upgrade

This component ships no image and no code, so there is nothing here to version on its own. An upgrade is
two things that move together:

1. **a rebuild of the platform image** (`docs/BUILD.md`: `docker build -f
   components/control/platform/Dockerfile --build-arg LO_SOURCE_REVISION="$(git rev-parse HEAD)" -t
   <tag> .` from the repository root), and
2. **the deployment image reference**, recorded with the reviewed source revision and
   successful conformance result. Keep the previous image and verified state backup for rollback.

`pull_policy: never` means the operator's `${LO_PLATFORM_IMAGE}` must be re-pointed at the new local
image by hand; a daemon that could pull a tag could pull one that judges differently.

## Preflight (each command, its pass criterion, all NOT RUN)

| # | command | pass criterion |
| :-- | :-- | :-- |
| P1 | `python -B -m unittest discover -s tests` (repository root) | ends `OK` — the producer's own behaviour is `tests/test_anomaly.py` + `tests/test_anomaly_cursor.py`; this manifest is `tests/test_anomaly_component.py` |
| P2 | `python -B scripts/check_foundation.py` | prints `Static foundation checks passed; runtime conformance not run.` — and since anomaly deployment support  that run **does** read this manifest: `examples/full/compose.yaml` carries it in its `include:` list, so `check_example` walks the merged model (see its `conformance.md` row 1.1). Before that date no example included it and the run proved only the privacy walk over `components/` |
| P3 | `docker volume ls --filter name=anomaly-state` | the volume the deployment will use is listed by its `<project>_anomaly-state` name, and `CONTRACT.md` step 3 printed `700 65532:65532` for it once |
| P4 | the copy-out in `backup.md` (producer stopped) | the extracted JSON parses and prints `1 <source> <series count> <pending count>`; a verified copy exists **before** anything is replaced, and `Backup-taken:` names its sha256 |
| P5 | `docker compose logs --tail 5 anomaly` on the running instance | last line is an `Anomaly round finished` with `pending` 0 and `unresolved_pending` 0 — a standing undelivered batch is drained or consciously carried, never upgraded away |
| P6 | `python -B -c "import json;d=json.load(open('anomaly-cursor.json'));print({k: v['binding'][:12] for k,v in d['series'].items()})"` against the copy, and the same digests after the new config is applied | unchanged, **or** the operator has read the row below about bindings |

**Bindings are the upgrade trap, not the image.** A configured series whose knobs or reviewed SQL
changed since its entry was written refuses the **whole round** — before its first query, its first POST
and its first byte, without writing anything — and the other series keep their positions. One mistyped
knob therefore holds every series' windows until it is fixed. If an upgrade changes `k`, `season`,
`window_days`, `min_points`, `min_per_bucket`, `evaluation_seconds` or the SQL, that is a
`rule_version` move for every series and it deserves its own change, its own cursor decision and the
same care `components/control/sigma/upgrade.md` asks for when an artifact moves.

## Ordered stop / start

The process holds `exclusive_owner` on the cursor **for its whole life** (`anomaly.py:1035`, and
`main`'s docstring: "never inferred from a file's presence, never released early, and never unlinked").
Two consequences, both operational:

* a **second copy against the same volume** is the failure to avoid. On one host it exits 1 on the lock,
  which is the correct reading of "something else is already judging these series"; across two hosts it
  is an advisory lock over state two machines both believe they own, and nothing here detects that.
  Never `docker compose up` this service on a second machine as a "warm standby";
* the stop is what makes the on-disk cursor coherent, so the copy in P4 is taken **after** the stop.

```
# 1. stop the writer and confirm it is gone (a stopped-but-restarting container defeats both the
#    backup and the lock argument above; `restart: unless-stopped` will fight a `stop` you did not
#    scale down if you are using `up -d --scale` anywhere in your overlay)
docker compose stop anomaly
docker compose ps anomaly                    # pass: the service is not running

# 2. take and VERIFY the copy (backup.md), before touching the image reference

# 3. point ${LO_PLATFORM_IMAGE} at the newly built image, and start
docker compose up -d anomaly

# 4. read the first round, do not trust the start
docker compose logs --since 5m anomaly | tail -30
docker inspect --format '{{.State.Health.Status}}' $(docker compose ps -q anomaly)
```

**Post-checks, each with its pass criterion (NOT RUN):**

| # | check | pass criterion |
| :-- | :-- | :-- |
| A1 | first `docker compose logs` | `Anomaly producer started` with the expected `series` count and `tick_seconds`, then at least one `Anomaly round finished` line carrying every `ROUND_FIELDS` name |
| A2 | the same lines | **no** `Anomaly round unavailable` and no `Anomaly window refused` — a refusal means the cursor did not move, so the new build did not like the configuration or the index |
| A3 | `Anomaly series anchored at a completed window` | **absent.** If it appears after an upgrade, the container is not reading the cursor you backed up (wrong path, wrong volume, wrong identity) and the previous cursor is the one to trust |
| A4 | the volume mode from `CONTRACT.md` step 3 | still `700 65532:65532` |
| A5 | health status | `healthy`, and it must go `unhealthy` within the `LO_ANOMALY_STALE_SECONDS` allowance + 3 × 60 s after `docker compose stop anomaly` — that negative test is the ledger's acceptance clause and it has never been run here |
| A6 | one event in the platform | an `anomaly` event whose `rule_id` is `anomaly.<series id>` arrives at intake with the new image's own verdict, and the platform's `state.VERSION` is the one the operator's database already reads |

## A cursor `SCHEMA_VERSION` move

`anomaly_cursor.SCHEMA_VERSION` is `1`, and `load` **refuses** anything else
(`Anomaly cursor schema_version is not 1`) as well as any unknown or missing top-level key. There is no
`MIGRATIONS` table for this file: unlike `state.py`, the cursor ships no migration ladder, and the
module's own position is that migrating or deleting an entry is an operator action
(`docs/units/anomaly-cursor.md`). So a bump demands, in this order:

1. **a written procedure in this component's `backup.md`**, reviewed by whoever owns `anomaly_cursor.py`;
2. a **conversion run offline against a copy** — never against the live volume — and a readback that
   parses under the *old* rules and the new ones;
3. a decision about anything in flight: `pending` batches carry exact bytes whose digests are
   re-verified on every load, so a schema change that touches `PENDING_KEYS` or the canonical form
   changes what "the same request" means and can turn an undelivered verdict into a refusal;
4. the rollback copy kept, because a **newer** cursor is unreadable to the **older** producer by the
   same rule that protects it from a foreign writer.

Until steps 1-4 exist, a schema bump is a fresh cursor and everything that costs: re-anchor at a
completed window, one `WARNING` that earlier history was never judged, no promise about duplicates or
extra incidents (`backup.md`).

## Rollback

Rollback is **the previous image plus the untouched cursor** — re-point `${LO_PLATFORM_IMAGE}` at the
image id the operator was running and start again. No state migration is run in the down direction, and
none is available: the product writes no cursor migration, so nothing needs unwinding.

What makes a rollback safe is not restoring anything, and what makes it unsafe is a cursor the older
build cannot read:

* if the newer build wrote a cursor with a **moved binding** (configuration changed alongside the
  image), the older producer refuses the round for the same reason the newer one did — the fix is the
  configuration, not the cursor;
* if the cursor's `SCHEMA_VERSION` moved, the older producer refuses it outright. That is why rollback
  keeps the P4 copy and why step 3 above is a decision rather than a script;
* events the newer build already delivered stay delivered. Dedup is `events UNIQUE (source,
  source_event_id)`, which folds a *byte-identical* replay and does nothing about a re-judged window:
  reconcile anything the new build judged by reading the incidents, not by deleting them.

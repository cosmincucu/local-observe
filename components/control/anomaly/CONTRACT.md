# Anomaly producer (experimental — never started)

Component `anomaly`: the deployment half of the seasonal-baseline producer that lives in
`local_observe/platform/anomaly.py` and `local_observe/platform/anomaly_cursor.py` (event kinds merged the
modules; this directory ships the service). It adds no image, no dependency and no product code.

**Read the last section before anything in this file that looks like a capability.** Every statement
about what the container does is reasoned from the code and the Dockerfile in this checkout. No
container has been started from this directory, `docker compose config` has never rendered this
manifest, and although `examples/full/compose.yaml` has carried it in its `include:` list since anomaly deployment support
(2026-09-10), nothing has rendered or started that composition either.

## 1. What this service decides, and what it is not

Every other producer in this product compares a number with a limit a human typed into a file. This
one learns the band from the series' own history — points fall into a seasonal bucket (`hour_of_day`
0..23 or `hour_of_week` 0..167) and each bucket learns `median ± k · 1.4826 · MAD` — so it is the only
place in the product that can say *"normal for this series at this hour, and it would not be normal at
04:00"*. Median and MAD over a fixed list contain no randomness, so the same history always yields the
same band: nothing to seed, nothing to relearn between runs.

**An anomaly is an input to incidents, never a page of its own.** In the module's own words
(`anomaly.py:18-21`):

> An anomaly is an *input* to incidents — it dedups and correlates like any other event and is never a
> standalone page. This worker notifies nobody and reads no delivery mode: the page-or-not decision
> belongs to the platform service, as it does for every other producer's event.

That is a deployment property, not a philosophy line: this manifest therefore ships **no notification
mode, no channel credential and no outbound path to a human**. Whether a firing anomaly reaches anyone
is the platform service's `LO_NOTIFICATION_MODE` decision, and disabling this component removes a
source of findings without touching the delivery rail.

What it does not decide: whether a service is *down* (the synthetics row owns availability), whether a
threshold was crossed (the detections row owns typed limits and Sigma findings), or why anything
happened (`rca`). Up to 16 series can be configured (`MAX_SERIES`), and every verdict is an ordinary
`kind='anomaly'` event through the same intake as every other producer's.

## 2. The service and its image

One service, `anomaly`, running `python -m local_observe.platform.anomaly` from
`${LO_PLATFORM_IMAGE}` — the platform image, built by
`components/control/platform/Dockerfile` and pinned in
`components/control/platform/versions.json`.

**Why the platform's image and not its own:** the producer is a module of the platform package. It
imports `platform.sigma_runner.ClickHouse` (the one bounded read-only query client, so this package
keeps one HTTP client and one set of server-side bounds) and `platform.detections.event` (its only
output), and `anomaly_cursor` reuses `inventory.validation.canonical` for the bytes it stores. A second
image would build the same `local_observe/` tree twice and leave two locks to rot.

Build the shared platform image from the reviewed source before enabling this producer.
Record the verified build in deployment configuration; see `docs/BUILD.md`.

`pull_policy: never` and `platform: linux/amd64` are the platform component's posture: a daemon that
could pull this tag could pull one that judges differently, and a silently-changed judge is a changed
detection surface.

**No published port, and no `depends_on:`.** Nothing reaches this service from the host or over the
Compose network — it opens two outbound connections and serves nothing — so `anomaly` is deliberately
absent from `check_foundation.py`'s `HOST_PUBLISHED_SERVICES`, and a gate change to admit a port here
would be the defect, not the fix. `depends_on` is absent because `check_example` refuses a dependency
naming a service this manifest does not declare, which would make the component unusable on its own
(the shape it ships in); start order is not needed anyway — a round that reaches no store or no intake
logs one refusal, advances nothing and repeats on the next tick.

## 3. Environment variables

`LO_ANOMALY_CONFIG_FILE`, `LO_ANOMALY_PRODUCER_TOKEN_FILE` and `LO_INVENTORY_SNAPSHOT_DIR` are **host**
paths consumed by Compose; the rest are container values. The two sides never share a name, because one
variable for both makes a reader guess which side of the mount a value belongs to.

| variable | what it does | unset or wrong | anything break? |
| :-- | :-- | :-- | :-- |
| `LO_ANOMALY_CONFIG` (`/config/anomaly.json`) | the container path of the reviewed series document — up to 16 series, each with reviewed SQL and its `sql_sha256` | **unset or blank is the off switch**: `anomaly.main` logs one `INFO` line naming the variable and exits 0, touching nothing. Named but unparseable, out of range, or holding an unknown key → exit 1 | the mount is `:ro` and the path is fixed by the manifest; a config the operator edits on the host must be re-read by a restart, because the file is parsed at start |
| `LO_ANOMALY_CURSOR` (`/state/cursor.json`) | where this producer remembers which windows it judged and what it still owes intake | unset while a config *is* named → refuses to start ("a configured producer will not deliver verdicts it cannot re-send", one `WARNING` naming the variable); a path whose parent is missing or mode-reachable → see §5 | this path must stay on the named volume: the cursor's parent must already exist at mode `0700`, and `check_model` refuses any non-read-only bind, so a bind mount is not available |
| `LO_ANOMALY_SOURCE` | the producer identity, which the cursor records and the platform's token is bound to | unset → `anomaly.main` refuses (a `KeyError` caught into the same exit-1 line); mismatched with the token → every `POST /v1/events` answers 401 | it must **match its token**; a second producer sharing one identity has its events folded into the first one's by the store's dedup, which is a lost verdict and not a dedup |
| `LO_INDEX_PATH` (`/inventory/inventory.db`) | the read-only inventory snapshot every series' `resource_id` must resolve in | unset → refusal at start; stale or missing index → the **whole round** refuses before its first query, one line per round | a snapshot older than the declarations is a refusal, not a pass: an undeclared resource never gets judged |
| `LO_CLICKHOUSE_URL` | the query endpoint | unset → `docker compose config` stops (`:?`); unreachable → the round refuses and the container survives | plaintext HTTP is refused unless `LO_INTERNAL_ALLOW_HTTP=1` |
| `LO_CLICKHOUSE_USER` (default `lo-query`) | the SELECT-only query user's **name**, not a secret | defaulted on purpose: it is the name `components/data/store-signoz/clickhouse-users.d/lo-query.xml` creates (`readonly=1`, `allow_ddl=0`, SELECT on the signal databases only). Override only if your store names it differently | the default cannot authenticate as someone else, because the password beside it stays a required file |
| `LO_CLICKHOUSE_PASSWORD_FILE` (`/run/secrets/anomaly-clickhouse-password`) | container path of the mounted query credential | unset → `read_credential` raises `KeyError` naming both forms → refusal at start | see §4 for why a path and never a value |
| `LO_PLATFORM_URL` | platform intake base URL | unset → `config` stops (`:?`); unreachable → rounds refuse, cursor unmoved, `unhealthy` after the allowance in §5 | see the `LO_INTERNAL_ALLOW_HTTP` row |
| `LO_PRODUCER_TOKEN_FILE` (`/run/secrets/anomaly-producer-token`) | container path of the mounted producer token — the host file behind it is this component's own `${LO_ANOMALY_PRODUCER_TOKEN_FILE}`, since 2026-09-10 (§4) | unset → `KeyError` at the read → refusal at start; wrong token → 401 per POST, and the refusal counter climbs while nothing moves | a pending batch survives a 401 exactly as it survives an outage: it is retried, byte for byte, and never dropped |
| `LO_INTERNAL_ALLOW_HTTP` (default `1`) | permits the plaintext endpoints on the isolated project network | anything other than exactly `1` → the shared clients refuse `http://` and the producer refuses to start | set `0` when both endpoints are HTTPS; leaving it `1` on an HTTPS deployment breaks nothing but keeps a plaintext route permitted |
| `LO_ANOMALY_STALE_SECONDS` (default `1800`) | **this manifest's own knob**: read by the healthcheck below and by no product code | unset → the probe falls back to 1800; non-numeric → the probe exits 1, which reads as unhealthy (fail-closed for a liveness check) | too small → false `unhealthy` on an idle producer (§5's formula); too large → a dead producer stays `healthy` that much longer |

The knobs *inside* the config document (`k`, `window_days`, `min_points`, `min_per_bucket`, `season`,
`tick_seconds`, `evaluation_seconds`, and the per-series overrides) are not environment variables and
are not this table's: each one's default, bounds and what turning it down breaks are in
`local_observe/platform/README.md`, "The knobs, what each one does, and what turning it down breaks".
Out-of-range or unknown fields there are refusals at load, never clamps.

## 4. The two credentials

`anomaly-clickhouse-password` and `anomaly-producer-token`, both mounted files, with only their
container paths in the environment. An environment *value* is readable through `docker inspect`,
through `/proc/<pid>/environ` of every process in the container, and by any child that process spawns;
`scripts/check_foundation.py`'s credential rule exists to refuse that shape, and
`local_observe/credentials.read_credential` prefers the `_FILE` path while still accepting the bare
value for hand-run containers (when both are set the file wins and one `WARNING` names the variable,
never the value).

**Dedicated secret names and producer identity.** `anomaly-producer-token` and
`anomaly-clickhouse-password` use distinct Compose resource names so the component
can be included alongside Sigma. The read-only query password may use the same
`${LO_CLICKHOUSE_PASSWORD_FILE}`. The producer credential must use this service's own
`${LO_ANOMALY_PRODUCER_TOKEN_FILE}` and a matching platform identity.

One row of the platform's credentials file
carries exactly one `identity`, and `local_observe/platform/state.py` answers `Source identity differs
from authenticated producer` to an event whose `source` is not that identity. Mounting the runner's
token beside `LO_ANOMALY_SOURCE=anomaly-example` therefore shipped the failure the row above warns
about — a container that starts, judges every series and has every `POST /v1/events` refused, with the
same window owed forever and the healthcheck still green because a refused attempt rewrites the cursor
file on its way out without acknowledging anything (`anomaly.py:764-785` plus `_deliver`, read from the
source and never observed here) — so the shared file was the bug and its own credential is the fix.

Staging it is two steps, not one: add a **second `producer` row** to the credentials file the platform
already reads, whose `identity` is exactly the `LO_ANOMALY_SOURCE` value, and copy *that row's* token
(minted, not copied from the sigma row — the store dedups on `(source, source_event_id)`, so one
identity for two producers folds two verdict streams into one) into its own mode-`0444` file and name
it from the variable. `examples/full/README.md` step 5 carries the commands and step 4 selects the
runner's row by identity for the same reason. Nothing here has rendered or started either credential:
this section is a claim about files, and `conformance.md` row 2.12 is the check that makes it a claim
about a running producer. The ClickHouse user is a name and stays in the environment; the producer
token is the one value here that mints events, so it is bounded at 4 KiB, refused if it holds any ASCII
control character, and created with `printf` rather than `echo`.

## 5. The cursor: the one state, and the mount that refuses to work by itself

The only state this service writes is one JSON document (`anomaly_cursor`, `SCHEMA_VERSION = 1`)
holding, per series: which windows are acknowledged, which window it *began* and did not finish, the
exact bytes still owed to intake, its lifetime counters and the round-robin marker. Writes go through
`mkstemp` in the cursor's own directory → write → `flush` → `fsync` → `chmod 0600` → one atomic
`os.replace` → directory `fsync` where the platform has one. One process holds
`exclusive_owner` on it (`<cursor>.owner.lock`) for its whole life, and that lock file is never
unlinked by anything in the product.

The **parent directory** is the operator's job, and the producer refuses to choose it — because the
file is written `0600` and holds the payloads of verdicts, so a producer that created its own directory
would be picking the permissions around its own state, and would happily create it inside a mount
somebody else exported. `anomaly_cursor.private_parent` (`anomaly_cursor.py:230-235`) says so in two
messages, quoted verbatim:

```
Anomaly cursor parent directory does not exist; create it privately (mode 0700) before starting the producer
```

```
Anomaly cursor parent is reachable by group or other; it must be mode 0700
```

### Cursor volume ownership

The platform Dockerfile creates `/state` at mode 0700 owned by uid/gid 65532.
Verify that a fresh named volume retains those permissions before starting the producer.
An older or custom image may require the preparation recipe below.

A named volume is the only option, because `check_foundation.check_model` refuses any bind mount that
is not read-only and a cursor is a write.

### Preparation recipe — the fallback for an image built before 2026-09-10 — **NOT RUN**

**This is no longer the primary path.** An image rebuilt from this tree creates `/state` at mode 0700
owned by 65532 in the Dockerfile (the two paragraphs above), so the four commands below are what an
operator running the pinned image — or any image built before that line — still has to do once, and what
every operator does until row 2.11 says the rebuilt image is enough.

Derived from the Dockerfile and the refusals above. **Nothing in this block has been executed from this
repository**; it is the recipe a host run has to prove. `python:3.12-slim` (the image's base) carries
`sh`, `chown`, `chmod` and `stat`; the Dockerfile sets no `ENTRYPOINT` and only a `CMD`, so the trailing
command below replaces the uvicorn line; and the Dockerfile's `USER 65532:65532` is why step 2 asks for
`--user 0:0`.

```
# 1. create the volume BEFORE the first `up`, so Compose finds it instead of making it
docker volume create <project>_anomaly-state

# 2. one throwaway root container makes it private and hands it to the runtime user
docker run --rm --user 0:0 -v <project>_anomaly-state:/state \
  ${LO_PLATFORM_IMAGE} sh -c 'chown 65532:65532 /state && chmod 700 /state'

# 3. verify (this one runs as the image's own user, and must print exactly `700 65532:65532`)
docker run --rm -v <project>_anomaly-state:/state \
  ${LO_PLATFORM_IMAGE} stat -c '%a %u:%g' /state

# 4. only now
docker compose up -d anomaly
```

`<project>` is the Compose project name — the directory the top-level model is composed from, or
whatever `-p` says — which the operator substitutes; `docker volume ls` after step 1 is how they confirm
the name matches what `up` will look for. **Step 3's pass criterion is the line `700 65532:65532`** and
nothing else.

**An already-created volume is never re-chowned.** If `up` ran first, Compose made the volume
`root:root` mode `0755` and the producer refuses with the second message above. The repair is
`docker compose stop anomaly`, then step 2, then start again — and nothing is lost by doing it, because
a producer that refused at startup never wrote a cursor.

**And the honest limit of this block:** none of it was run, and steps 2-4 assume a daemon that behaves
the way a rootful daemon does. A rootless install remaps `0:0` and `65532`, so the numbers *inside* the
container are right while what the host sees differs. Separate open question, sidestepped rather than
answered here: **does Docker copy the image's directory mode onto a fresh named volume?** The recipe
did not depend on the answer when it was written, because the image carried no `/state` for a mode to be
copied from; since anomaly deployment support it does, which is the difference between this block being a fallback and being
redundant — and it is still an unanswered question, because nothing here builds an image. Report item R3
of anomaly component (the clean fix: one `RUN` line creating `/state` at mode 0700 owned by 65532, which also gives
Sigma's `/state` the same shape) is **done** in `components/control/platform/Dockerfile` as of
2026-09-10, and unverified until that image is built; report item R5 (the rootless remap) is not a
Dockerfile problem and stays open here and in `conformance.md` row 2.3. Record verified image identities in deployment configuration.

## 6. Health: what the probe proves, and what it does not

The healthcheck is a cursor-staleness probe, in the same shape as `components/control/sigma/compose.yaml`
and with the same honest weakness: it answers **"this producer has stopped advancing windows"**, not
"this process is alive".

```
LO_ANOMALY_STALE_SECONDS  >=  max(evaluation_seconds over the configured series) + 2 x tick_seconds
```

Shipped default **1800**, which covers the shipped defaults (`DEFAULT_TICK_SECONDS = 300` at
`anomaly.py:82`, and `load_config` at `352-353` defaults `evaluation_seconds` to `tick_seconds`).

Why the allowance is not one window: the cursor is a *window-advance* signal, not a liveness beacon. A
round whose series are all caught up takes the `None` branch at `anomaly.py:885-895`, logs `caught_up`
and calls **no** `anomaly_cursor.save` — every other path does save (`764, 769, 774, 780, 785`, and the
refusal counter at `979`). So while the process lives, the cursor's mtime advances at least once per
`evaluation_seconds` per series, and not more often than that when the producer is idle. An allowance
of exactly one window would call a healthy idle producer `unhealthy`.

What that buys and what it costs, plainly:

* a producer that **stopped** advancing windows — wedged round, unreadable cursor, a store it cannot
  reach — goes `unhealthy` within the allowance + 3 × 60 s of interval;
* a producer that is **idle and healthy** stays `healthy` for the same length of time, which is the
  point of the allowance and the reason the number is a knob and not a constant;
* the **one false-unhealthy case this admits**: an operator who raises `evaluation_seconds` in the
  config file and does not raise `LO_ANOMALY_STALE_SECONDS`. The manifest cannot see the config file's
  contents, so it cannot check that inequality; the symptom is a container that goes `unhealthy` while
  judging exactly as it always did;
* a process that is alive and keeps completing windows is `healthy` even if it is slowly failing
  elsewhere — this probe reads an mtime, not the process;
* `start_period: 90s` is enough because `anomaly.main` runs `tick` before its first `sleep`, and a new
  series writes its first window to the cursor before the store is asked anything (`anomaly.py:749-764`).

The ledger row asked for "a liveness artefact the producer must start writing". Writing one means
editing `anomaly.py`, which is a separate implementation change, so the probe uses the
artefact the producer already writes and declares its limit instead of inventing a claim.

## 7. Log volume

The cap is `json-file`, `max-size: 10m`, `max-file: "3"` — 30 MB, the product-service cap and the one
the platform README's log-volume table already computed this worker against:

> | `anomaly.py`, at its shipped default tick | 300 s | `10m × 3` = 30 MB, the cap
> `components/control/anomaly/compose.yaml` ships | ≈ 109 days (computed from the formula above, never
> measured: no container from that manifest has been started) |

That row said "none shipped" until this change wrote the shipped cap into it (anomaly component's report item R2,
applied by anomaly deployment support on 2026-09-10); the ≈ 109 days is the number this manifest ships toward. Note the
multiplier the other workers do not carry, from the
paragraph beside it: a round writes one summary line **plus** one line per series it reaches, and a
caught-up series still says so once per round — so three series at the default tick is ~1,152 lines a
day, not 288, and the row that first claimed ≈ 436 days was four times optimistic. A backlog recovery is
a bounded burst (at most `MAX_WINDOWS_PER_ROUND` window lines per round whatever the gap). No figure
here was measured by starting a container.

## 8. Coverage and remaining limits

The per-series coverage adds opt-in per-series `coverage_unjudgeable_windows` (integer 0..100,
default 0). It starts counting only after a previously judgeable window. At N
consecutive unjudgeable windows it opens one coverage incident; the first
judgeable window resolves it, retaining that window's ordinary anomaly event.
Idle and insufficient windows reset the streak but never resolve an open
episode. Cold-start `hour_of_week` with the default three observations per
bucket remains silent. Coverage and ordinary anomaly deliveries are persisted
together and replayed identically until all responses arrive.

This requires a fresh schema-2 cursor. Existing schema-1 deployments keep their
disabled configuration and cursor pending a separately reviewed migration;
enabling against that cursor refuses read-only. There is no automatic migration
or cursor-deletion remedy. See `docs/units/anomaly-cursor.md` for compatibility,
rollback and the four-POST recovery bound.

### Historical D1 ruling (default behavior retained)

**No coverage event for an unjudgeable series — ruled, not overlooked.** In the platform README's words
("What is deliberately not here yet"), quoted verbatim:

> * **No coverage event for an unjudgeable series.** `insufficient` and `unjudgeable` stay in the log
>   and out of the incident stream, per this card's brief. If that turns out to be the wrong trade —
>   silence reading as health — the coverage-event pattern in `detections.evaluate` is the shape to
>   copy, and it belongs on a later card.

Before the per-series coverage this component shipped only that ruling. Its original reasons, in
order:

1. **`unjudgeable` is not a failure to observe.** The store answered, the rows parsed, the points were
   inside the window (`anomaly.py:546-547` reaches that verdict only *after* `series_points` and
   `train` succeeded). What is missing is training history — the state **every correctly configured new
   series passes through**: an `hour_of_week` season (168 buckets, `SEASONS` at `anomaly.py:72`) with
   the default `min_per_bucket = 3` cannot judge a given bucket until three weeks of history exist. A
   coverage event here fires on every healthy new series, at the moment of configuration.
2. **A firing coverage event opens an incident, and this producer has no resolve path for one.**
   Ledger row drift resolution records that exact defect class for the drift producer: intake closes an incident
   only on a `resolved` event for the same condition key, so one artifact change opens an incident that
   stays open until the rule is removed. Shipping the same shape knowingly is worse than the log line.
3. **The distinction worth an event needs the two modules this item may not edit.** "Unjudgeable for N
   *consecutive* windows" is a per-series counter in the cursor document, i.e. changes to `anomaly.py`
   and `anomaly_cursor.py`, which implement the producer and cursor contract.

`state.EVENT_KINDS` already admits `coverage`, so nothing about the vocabulary blocks the later change;
the missing counter and resolve path were the follow-up in report item **R4**.
The per-series coverage now supplies them for explicitly enabled fresh deployments.

**With coverage disabled, the signals remain:** the per-window `INFO` line — `anomaly.py:810`
`"Anomaly window finished"`, carrying `result` and, for an unjudgeable window, the `skipped` /
`buckets_insufficient` counts from `anomaly.py:544-545` — and the round summary's `no_verdict` counter
(`anomaly.py:848-850`), which counts windows advanced with nothing posted (`idle`, `insufficient`,
`unjudgeable`) *apart* from `delivered` precisely so a quiet series cannot read as a busy one. Both are
log lines: they are greppable, they are not incidents, and nothing pages on them.

Also not here: no cursor-retention horizon and no `--show-cursor` / `--resolve-cursor` command (the
README's own bullets), no `compose.yaml` for the `rca` command that consumes these events, and no second
producer image.

## 9. Status of every claim in this file

| claim | state |
| :-- | :-- |
| the manifest passes the product's model and credential rules | **run**, `tests/test_anomaly_component.py` (offline, no Docker) |
| the healthcheck's three answers (fresh cursor → 0, aged → 1, missing → 1) | **run**, same file, by executing the code out of the manifest |
| a container starts from this directory | **never done** |
| `docker compose config` renders it | **never done** |
| the D3 volume recipe works, including step 3 printing `700 65532:65532` | **never done**; reasoned from the Dockerfile, and untested against a rootless daemon |
| Compose would or would not merge two identical secret definitions across an `include` | **never tested** (§4); the names are distinct because of what is documented, not what was measured |
| the platform image an operator has today contains the module | **no**: `versions.json` records why the pinned `image_id` predates `anomaly.py` |
| an image rebuilt from this tree carries `/state` at `0700`/`65532`, and a fresh named volume inherits it | **never built**; the Dockerfile line landed with anomaly deployment support on 2026-09-10 and `conformance.md` row 2.11 is the check that turns it into a fact |
| the producer turns a container `unhealthy` when it stops ticking | **never done** — the ledger's acceptance clause, available here only as the offline probe test |
| an `anomaly` event reaches platform intake from this service | **never done**; the producer's own behaviour is tested in `tests/test_anomaly.py`, which is not this component |
| backup / restore / upgrade rehearsed | **never done**, commands in `backup.md` and `upgrade.md` are marked not run |
| the memory and CPU caps are right-sized | **not measured** — they copy the Sigma runner's envelope, which is itself unmeasured here |

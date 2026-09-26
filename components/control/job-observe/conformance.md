# Conformance

Component `job-observe`. Two things have been run against this directory: the static gate, and the
compose loader with a filled environment. **No container has been started.** Everything below the
"Static checks that pass today" line is a recipe, not a result — recorded here so the first operator
to run it can paste it, and so nobody mistakes the manifest for evidence.

## Static checks that pass today (2026-09-08)

```sh
python -B scripts/check_foundation.py                     # Static foundation checks passed; runtime conformance not run.
python -B -m unittest tests.test_job_observe              # the four documents exist; the manifest renders with this example's own values
python -B -m unittest discover -s tests                   # full suite
```

`check_foundation` proves: the image is a required runtime variable, the published port is
loopback-only, no credential of this project's sits in a container environment, the secret is
declared as a top-level `secrets:` entry and mounted by the service that reads its path, the data
volume is project-scoped, no private host path or estate identifier appears anywhere under
`components/` or `examples/`, and the four lifecycle documents exist. It proves nothing about
whether the container starts.

## Preconditions for the recipes below

Run them on a disposable host, in a project name that is not the reference one.

```sh
HC=http://127.0.0.1:18097                       # matches LO_HEALTHCHECKS_SITE_ROOT
docker compose -p r27-stage -f components/control/job-observe/compose.yaml up -d
# `ping_url` in every response below is PING_ENDPOINT + the check's UUID, with no trailing slash
# (docs/apiv2.md, "Example Response"), which is what makes appending /fail a plain concatenation.
# One console account, created against the running container (upstream's own documented command):
docker compose -p r27-stage -f components/control/job-observe/compose.yaml \
  run --rm healthchecks /opt/healthchecks/manage.py createsuperuser
# Then in the console: Project Settings -> API Access -> create a READ-ONLY key.
RO=…        # that key, 32 characters; a shorter one is refused with HTTP 400 by the metrics view
RW=…        # a read-WRITE key, for creating the two checks below; delete it when the recipe passes
PROJECT=…   # the project UUID shown in the browser's address bar
```

Two checks, one minute apart in intent and different in kind — this is the whole point of the pair:

```sh
# A: "did it run?"  — a monitor with no producer on purpose
A=$(curl -fsS -X POST -H "X-Api-Key: $RW" -H 'Content-Type: application/json' \
      -d '{"name":"r27-missed-deadline","timeout":60,"grace":60}' "$HC/api/v2/checks/" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["ping_url"])')
# B: "did it succeed?" — a producer that does run, and reports failure
B=$(curl -fsS -X POST -H "X-Api-Key: $RW" -H 'Content-Type: application/json' \
      -d '{"name":"r27-failed-checkin","timeout":600,"grace":60}' "$HC/api/v2/checks/" \
      | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["ping_url"])')
# The ping URL is a credential: never echo it into a shared log, and never commit it.
printf '%s' "$A" > /tmp/r27-ping-A && printf '%s' "$B" > /tmp/r27-ping-B && chmod 0600 /tmp/r27-ping-*
```

(`RW` is a read-**write** key: the read-only key cannot create checks and omits the `*_url` fields
from responses, per `docs/apiv2.md`. Mint it for the rehearsal and delete it after.)

### 0. Arm the check, or the test proves nothing

**A check that has never been pinged cannot alert.** Read at `hc/api/models.py` and
`hc/api/management/commands/sendalerts.py` on 2026-09-08: `get_grace_start()` returns `None` for a
check whose status is `new`, `going_down_after()` therefore returns `None`, and `sendalerts`'s
`handle_going_down()` clears `alert_after` and moves on — so a never-pinged check stays `new`,
exports **`hc_check_up 1`** (the metrics view writes 0 only when the status is `down`), and raises no
alert forever. This is the "the cron job never ran, not once" case, and it is silent by design.

Pass for this step: after `curl -fsS "$(cat /tmp/r27-ping-A)"` the check leaves `new`, `hc_check_up`
still reads 1 (correctly: it ran), and the console shows a scheduled `next_ping`. Step 1 then waits
for the deadline the arming ping started. For a real timer, the arming ping is the job's first
success after install — **record the install-time check-in as part of creating the check**, or the
monitor is decorative.

## Scenario "Missed job" — the two states must stay distinct

`docs/COMPONENTS.md` §5 requires: *missed deadline and failed job are distinct; restarting Dagu does
not silence the dead-man coverage.*

### 1. A missed deadline, with nothing ever failing

After arming it, do nothing further to check **A**. There is no failure anywhere in the estate — no
failed unit, no error line, no log to grep; the only fact is that a deadline passed. After period +
grace (≈120 s from the arming ping):

```sh
curl -sS "$HC/projects/$PROJECT/metrics/$RO" | grep -E 'hc_check_(up|grace)\{name="r27-missed'
```

Pass: `hc_check_up{...name="r27-missed-deadline"...} 0`, and in the console the check reads **down**,
not "no data". Halfway there (after the period, before grace expires) the status is `grace` — record
`hc_check_grace` at that moment too, because `hc_check_up` alone does *not* distinguish late from up
(`hc_check_up` is 0 only for `down`, per `hc/integrations/prometheus/views.py`), and an alert rule
that watches only `hc_check_up` turns "running long" green until it is too late.

### 2. A failed check-in, immediately, with no missed deadline

```sh
curl -fsS "$(cat /tmp/r27-ping-B)"        # success: the check goes up, and next_ping is scheduled
curl -fsS "$(cat /tmp/r27-ping-B)/fail"   # upstream's documented way to signal failure now
```

Pass: the state flips to down **within one request**, not at the next deadline — that is what
appending `/fail` buys (`templates/docs/signaling_failures.md`) — and check A is still in its own
state, untouched: two checks, two verdicts, one series each.

### 3. The two are not the same event

| Observation | 1 (missed) | 2 (failed) |
|---|---|---|
| a ping ever arrived | once, to arm it (step 0) | yes |
| when the alert fires | period + grace after the last ping | immediately |
| `hc_check_started` | 0 | 0 after the fail |
| `systemd_unit_state{state="failed"}` for the timer's service | unchanged | unchanged (this is a *missing/late* signal, not a unit failure) |

Pass is the whole table holding, read from the metrics endpoint and the exporter, not from the UI.
If a change makes them collapse into one signal, this scenario has failed — which is the failure mode
job observation was asked to avoid. Note what is *not* in the table: neither state depends on reading the job's
logs, and neither needs a process owned by this repository to be alive to notice.

### 4. "The job ran and failed" on the pull side, on the same host

```sh
# a scratch host: a one-shot unit that exits non-zero, read through systemd_exporter on :9558
systemd-run --unit=lo-r27-fail --service-type=oneshot /bin/false
curl -sS http://127.0.0.1:9558/metrics | grep 'lo-r27-fail'
systemctl reset-failed lo-r27-fail.service && systemctl disable --now lo-r27-fail.service 2>/dev/null
```

Pass: `systemd_unit_state{name="lo-r27-fail.service",type="service",state="failed"} 1` (the metric
table and label set are in the exporter's README at the pinned tag, `systemd_unit_state` with
`name`, `type`, `state`). Clean up with `reset-failed`, or the unit's failed state persists and the
next reader inherits a false alarm. UNVERIFIED here: this was not executed, and the label spelling
must be read off a running exporter before it goes into an alert rule.

### 5. Restarting the scheduler does not silence the dead man

```sh
docker compose -p r27-stage -f components/control/dagu/compose.yaml stop dagu   # or the local equivalent
```

Pass, all three, while Dagu stays down:

1. the witness's own check keeps ticking and keeps its deadline: with the platform reachable,
   `hc_check_up{name="<the witness check>"}` stays 1; stop `platform` and within period+grace it goes
   0 and then `hc_check_down_total` counts it — the alarm survives the loss of both the scheduler and
   the monitored service, because the only thing between the check and the alarm is Healthchecks;
2. the store still gets the series: scrape `metrics_path: /projects/$PROJECT/metrics/$RO` from the
   front door (see `components/data/agent-linux/CONTRACT.md` for the opt-in block) and confirm the
   `hc_` metrics land with `job_name` = your scrape job's name;
3. `hc_checks_total` does not change when Dagu stops: a stopped scheduler cannot pause, delete or
   silence a check, because it holds no key to this component.

That third line is the regression guard for the retired design, where the worker that evaluated the
deadlines was a process this repository owned and could therefore be the thing that went quiet.

### 6. The witness client itself

```sh
LO_HEALTHCHECKS_PING_FILE=/tmp/r27-ping-B LO_DEADMAN_STATE=/tmp/r27-witness.json \
LO_PLATFORM_URL=http://127.0.0.1:18096 LO_READER_TOKEN_FILE=… \
  python -B -m local_observe.platform.deadman
```

Pass: `GET <ping>` while `/v1/status` answers 200 with `schema_version: 1`, `GET <ping>/fail` when it
does not (or the platform is unreachable); `/tmp/r27-witness.json` still records its own failure
clock and incident id; the process refuses to start with a missing or malformed ping file rather
than running unwatched. Covered by `tests/test_deadman.py` for the state machine and the client's
contract, and unproven against a live Healthchecks until step 1 of this file is executed.

## Still open before this component may be called experimental

- **nothing above has been run**; the first pass must be recorded in `STATUS.md` with versions.
- `read_only: true` on the service — needs the uWSGI static-gzip cache path (`static-collected/CACHE`)
  proven writable elsewhere, or the flag stays off and this line stays open.
- the scrape wiring for `hc_*` in the **front door's** `collector.yaml` (out of job observe standard's file list; see
  DEPENDENCIES.md) and, on observed hosts, `systemd_exporter` itself — its config is shipped
  unreferenced and inert by default.
- a `docker compose cp`-free path for the backup (the recipe uses the container's own `/tmp`).
- cold restore of `healthchecks-data`, upgrade rehearsal and rollback, and a cross-host ping through
  an operator's TLS proxy (`SECURE_PROXY_SSL_HEADER` and `X-Forwarded-Proto`).
- alert rules in the store for `hc_check_up`/`hc_check_grace` and for
  `systemd_unit_state{state="failed"}`: this component produces the series, and nothing in the tree
  yet turns them into a page.

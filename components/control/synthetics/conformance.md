
# Conformance — LAN synthetics

Component `synthetics`. Per `docs/CONTRACTS.md` §6 every check reports `pass`, `fail` or `not-run`,
and an omitted dependency never turns `not-run` into `pass`. Read the two columns apart: **what is true
of the tree today** is proven by commands anyone can re-run here; **what is true of a running
engine** is a recipe, and every one of those rows is `not-run` because nothing in this repository has
started this manifest.

The one thing this file is *for* is the acceptance scenario in `docs/COMPONENTS.md` §5:

> **Failure to recovery** — *Inject one service failure; incident names declared resource and
> queryable evidence; recovery updates it.*

## Preconditions for the recipes

A disposable project name, not the reference one; a scratch rule file and a scratch cursor.

```sh
set -a; . /approved/private/synthetics.env; set +a         # the filled template, 0600
proj=synthetics-stage
compose() { docker compose -p "$proj" --env-file /approved/private/synthetics.env \
              -f examples/full/compose.yaml "$@"; }        # or the platform stage's own composition
```

Three things must be true before any of this means anything, and each is a *check*, not a hope:

```sh
# a) the resource the rule names is declared, or evaluate() refuses the tick ("Detection resource is
#    not declared") and every row below reports a refusal instead of a verdict
curl -sS -H "Authorization: Bearer $reader" "http://127.0.0.1:${LO_PLATFORM_PORT}/v1/status" | head -c 200
# b) the engine's config actually rendered — read the endpoint key back FROM the engine, never off the
#    file. Neither service publishes a port, so this runs inside the project network via the container
#    that already lives there:
compose exec detector python - <<'PY'
import json, os, urllib.request
token = open(os.environ['LO_GATUS_TOKEN_FILE']).read().strip()
base, _, _ = os.environ['LO_GATUS_URL'].partition('/api/v1/')
statuses = base + '/api/v1/endpoints/statuses'
request = urllib.request.Request(statuses, headers={'Authorization': 'Basic ' + token})
print(sorted(e['key'] for e in json.load(urllib.request.urlopen(request, timeout=5))))
PY
#    expected: ['lo_platform-http'] — the derived key, not the name config.yaml shows
# c) the cursor directory exists and is writable by the process that will own it
```

## Scenario "Failure to recovery" — the recipe

Run with the detector and Gatus up and the platform reachable. Capture before/after of the platform's
own records; the assertions are read from the platform API, not from a dashboard.

```sh
events() { curl -sS -H "Authorization: Bearer $reader" \
             "http://127.0.0.1:${LO_PLATFORM_PORT}/v1/records/events" | python3 -m json.tool; }
```

### 1. Baseline: one healthy window

Pass: `events()` shows the pair `synthetic-http.coverage` **resolved** and — for an
`availability` rule — no firing finding; `detector` reports `healthy` (its cursor mtime is inside
`max(3 × window, 60)`); the window text in the event matches `LO_DETECTION_WINDOW_SECONDS`'
grid. Record the `source_event_id`s: step 4 asserts against them.

### 2. The credential is real (auth refusal, the component's own contract)

Neither service publishes a host port, so both requests run inside the project network — through the
detector container, which is already there and already holds the credential at the path its environment
names:

```sh
compose exec detector python - <<'PY'
import os, urllib.error, urllib.request
url, token = os.environ['LO_GATUS_URL'], open(os.environ['LO_GATUS_TOKEN_FILE']).read().strip()
def code(headers):
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=5).status
    except urllib.error.HTTPError as exc:
        return exc.code
print('with:    ', code({'Authorization': 'Basic ' + token}))
print('without: ', code({}))
PY
```

Pass: `with: 200` and `without: 401`. A `200` on the second line means the `security:` block is absent
or inert and the rest of this file is measuring an open API — stop and fix that before recording
anything else. Checklist row 8 stays `not-run` until someone pastes these two lines.

### 3. Inject one service failure

```sh
compose stop platform          # the declared service the committed endpoint probes
```

Pass, in this order and within about `interval + window + max_age_seconds` (90 + 5 + 120 s with the
shipped values, so give it four minutes before calling it a failure of the check):

* Gatus's result for `lo_platform-http` turns unsuccessful (`[STATUS]` resolves to 0 for a refused
  connection, which fails `[STATUS] == any(200, 401)`);
* the adapter files an `availability` finding for the rule with `status: firing`, `severity: warning`,
  and a second event `…​.coverage` **resolved** (the engine is alive and answering, the target is not —
  those are different claims and the pair is the point);
* an incident opens whose resource is the **declared inventory resource** the rule names, not a free
  text host, and the event's evidence reference is `query_type: gatus-result` with the `sample_id` of
  the result row;
* the evidence itself is retrievable: the adapter posts the sample to `/v1/evidence` for a successful
  poll, so `GET /v1/evidence?source=<source>&sample_id=<sample_id>` answers (and the incident's
  evidence link resolves), while an unauthenticated
  read is refused.

### 4. Recovery updates it

```sh
compose start platform
```

Pass: the next completed window files the same `rule_id` with `status: resolved`, the incident closes,
and **no new event row appears for any window step 1 already recorded** — re-run steps 1-4 with the
detector restarted mid-batch (`docker compose -p "$proj" kill -s SIGKILL detector`) and confirm the
`pending` batch is retried verbatim rather than re-derived: the `source_event_id`s from step 1 must
still be unique.

### 5. The absent-engine case

```sh
compose stop gatus                              # engine gone, platform and inventory untouched
# then, as a separate run, leave gatus UP but point the adapter at a key that does not exist:
LO_GATUS_URL=http://gatus:8080/api/v1/endpoints/no_such_endpoint/statuses   # 404 path
```

Pass, both variants, and this is the difference between an honest system and a comforting one:

* the rule's `coverage` event **fires** (`severity: warning`) and stays fired;
* the underlying `availability` condition is **never resolved** by an absent sample — no sample is a
  hole in coverage, not an all-clear. `detections.evaluate` returns a coverage event when
  a sample is missing, stale or refused; checklist row 5 covers this behavior.
* a `404` and a refused connection behave identically from the adapter's side — both are "no sample",
  neither is a parse error, and neither is logged with the response body;
* `detector` goes **unhealthy** only if it stops closing windows, not because the engine is down: an
  engine-down detector keeps ticking, keeps filing coverage and keeps its cursor fresh, which is
  correct — the process is fine and the *observation* is missing.

### 6. If disabled (the row's `If disabled` clause)

Remove the include entry, `compose up -d`, then repeat step 5's pass conditions and add: nothing else
in the stack fails to start, the store still accepts telemetry, and the Sigma runner and the
inventory reader are untouched.

## Runtime acceptance

Run the checks below against an isolated installation. One detector process reads one rule;
additional targets need additional services. Path monitoring (`netpath`) and named-assertion
expiry require their own adapters and acceptance checks. Gatus runs with its upstream image
identity; use the host-side volume procedure in [backup.md](backup.md).

## Acceptance checklist

Record results for your installation. Runtime acceptance is **not-run** in this source release.

| Check | Requirement | Result | Verification |
|---|---|---|---|
| 1 | Manifest, secrets, volumes and publications | **not-run** | Run `scripts/check_foundation.py` against the selected example. |
| 2 | Model and credential-file rules | **not-run** | Run `tests/test_gatus_component.py`. |
| 3 | Required Compose variables resolve | **not-run** | Render the example with its completed environment file. |
| 4 | Adapter accepts valid Gatus timestamps and rejects malformed envelopes | **not-run** | Run `tests/test_detection_worker.py` and `tests/test_platform.py`. |
| 5 | Absent engine produces firing coverage without a false recovery | **not-run** | Run the absent-engine recipe above and the deterministic worker tests. |
| 6 | Window bounds are 5..3600 seconds | **not-run** | Check window parsing and cursor replay in `tests/test_detection_worker.py`. |
| 7 | Containers start and Gatus answers | **not-run** | Check authenticated engine responses and detector cursor freshness. |
| 8 | Engine authentication | **not-run** | Require HTTP 401 without the credential and 200 with it. |
| 9 | Failure and recovery reach platform intake | **not-run** | Compare the finding and coverage events with the recipe above. |
| 10 | Durable restart | **not-run** | SIGKILL the detector between batch creation and delivery; require one retry of the retained batch and no premature cursor advance. |
| 11 | Missing dependencies stay visible | **not-run** | Test an undeclared resource, missing inventory snapshot and nonexistent Gatus key; require refusal or firing coverage. |
| 12 | Backup and restore | **not-run** | Follow [backup.md](backup.md) for both the volume and cursor. |
| 13 | Upgrade and rollback | **not-run** | Exercise the in-flight-window cases in [upgrade.md](upgrade.md). |
| 14 | Both services remain unpublished | **not-run** | Inspect the rendered model and running container ports. |
| 15 | Detector producer identity | **not-run** | An unset `LO_DETECTOR_PRODUCER_TOKEN_FILE` must fail configuration. A different producer's token must leave delivery refused and the pending batch retained; the matching identity must deliver one event pair per window. |

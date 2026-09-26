# LAN synthetics — Gatus engine plus the platform adapter (experimental)

Decision **gatus for synthetics** adopted Gatus as the synthetic-probe engine and kept "the bespoke
assertion/verdict layer only where Gatus cannot express it (path monitoring, 'is it me or them')".
**outside-in probes** ships LAN synthetics and nothing else: no hosted probe service, no remote vantage point, and
the abandoned `probe` package stays abandoned, following `docs/COMPONENTS.md` §3's "no hosted probe
service operated by this project".

Status is **experimental**. Validate the component using [conformance.md](conformance.md).

Path verdicts (`pathcheck.py`, path monitoring) and synthetic assertions (`assertions.py`, synthetic assertions)
remain in the platform. The netpath capability does not run in the Gatus container.

## What is product, what is the operator's (overlay compatibility)

| Half | Owner | Artefact |
| :-- | :-- | :-- |
| the engine and its version | product | `compose.yaml` here, `versions.json` here |
| the *shape* of a Gatus document | product | `config.yaml` here |
| the verdict rules and the event shape | product | `local_observe/platform/detection_worker.py`, `detections.py::gatus_sample/evaluate` |
| **which LAN targets are probed** | operator's overlay | their own rendered copy of `config.yaml`, at `LO_GATUS_CONFIG` |
| one availability rule document per monitored target | operator | a file in `LO_DETECTION_RULE_DIR` |

This product ships **zero real LAN targets**. The one endpoint in `config.yaml` names `platform`, a
service that is already in every composition that includes this one, so the committed file proves the
mechanism without naming a host an operator did not choose. Adding a target is an overlay edit with
an explicit opt-in, one address at a time: no sweep ranges, and no address literal that is not one of
synthetic naming's reserved placeholders — the scheme reserves RFC 1918 `10.11.0.0/16` for exactly this, and the
commented examples in `config.yaml` use nothing else. A target outside that rule is a private
topology in a shipped file and `scripts/check_foundation.py` refuses the tree for it.

## The credential: what the pinned release actually accepts

**The adapter used to send a bearer token to an engine that cannot read one, and the engine used to
run with no authentication at all.** Both halves are this section's subject, and the second is the one
that would have shipped open.

Read at the pinned tag `v5.36.0` (each file fetched from
`https://raw.githubusercontent.com/TwiN/gatus/v5.36.0/<path>` on 2026-09-09):

* `api/api.go` registers `GET /api/v1/endpoints/:key/statuses` on `protectedAPIRouter`, and that
  router gets `cfg.Security.ApplySecurityMiddleware(...)` **only when `cfg.Security != nil`**. With no
  `security:` key in the config file the "protected" routes have no middleware and answer anyone who
  can reach the port. The comment in that file says it: *"ORDER IS IMPORTANT: all routes applied AFTER
  the security middleware will require authn"*.
* `security/config.go` — `Config` has exactly two members, `basic` (`security.basic`) and `oidc`
  (`security.oidc`). There is **no** bearer-token or static-token option for these routes, and no
  `jwt` or `headers` key at this tag.
* `security/basic.go` — `security.basic.username` plus
  `security.basic.password-bcrypt-base64` ("Password hashed with Bcrypt and then encoded with
  base64"), documented in `README.md`'s "Basic Authentication" table with a worked example. Both must
  be non-empty or `ValidateSecurityConfig` returns `ErrInvalidSecurityConfig` (`config/config.go`) and
  Gatus does not start — so an unrendered `config.yaml` fails toward *closed*, which is why
  `config.yaml` here ships literal `RENDER-ME-…` markers rather than `${VAR}` expansions: an unset
  variable expands to an empty string via `os.ExpandEnv` (`config/config.go`) and would stop the boot
  with a message about a security config, far from the environment file that caused it.
* The markers take the *other* closed door, which is worth knowing before the first bring-up: they are
  non-empty, so `ValidateAndSetDefaults` passes them, and the boot then dies one step later —
  `ApplySecurityMiddleware` calls `base64.URLEncoding.DecodeString` on `password-bcrypt-base64` and
  returns the error (`security/config.go`), which `api/api.go` turns into `panic(err)`. Unrendered,
  the engine crash-loops and answers nothing; it is never open. `tests/test_gatus_component.py` pins
  that by decoding the shipped value under the same alphabet rule (`test_the_shipped_marker_cannot_be_decoded_so_an_unrendered_file_cannot_boot`),
  because "the marker is unrenderable" is a claim about bytes, and a marker that one day decodes is a
  marker that boots an engine nobody authenticated.
* **Two base64 alphabets, and they are not interchangeable.** The credential the detector presents is
  decoded by fiber with `base64.StdEncoding` (`middleware/basicauth/basicauth.go`, the `auth[6:]`
  slice), so `LO_GATUS_TOKEN_FILE` is standard-alphabet base64 with its `=` padding. The hash field
  above is decoded by Gatus with `base64.URLEncoding`, whose alphabet swaps `+`→`-` and `/`→`_` and
  which is strict about padding — it *refuses* a `+` or a `/` in what it is handed, and a refused field
  panics the boot. Generate the field with `base64.urlsafe_b64encode` (shell: `base64 -w0 | tr '+/'
  '-_'`) and nothing else, and note what the two halves of that rule are worth separately: the
  **padding/strictness** is what decides whether the engine boots, while the alphabet swap is a
  belt-and-braces guarantee here — a bcrypt hash's own characters are `.`/`/`/digits/letters, all of
  them `≤ 0x7A`, and six-bit groups read off bytes that small never reach indices 62/63, so standard
  base64 of a real bcrypt digest contains no `+` and no `/` to begin with. Encoding it URL-safe anyway
  is what upstream documents and what this repository generates; the case where the two alphabets
  actually diverge is a *non*-bcrypt value in that field, which is a render error either way and is
  refused at the render (`scripts/conformance_platform_stage.py::urlsafe_hash_field` asks for a bcrypt
  shape before it encodes anything).
* `security/oidc.go` — the other option. It needs an issuer, a client and a browser session
  (`gatus_session` cookie), i.e. an identity provider this product does not ship and a LAN engine has
  no reason to front. Not used; recorded so the reader knows it was read and refused, not missed.
* `github.com/gofiber/fiber v2.52.13`, `middleware/basicauth/basicauth.go` (the version
  `go.mod` at v5.36.0 names): the header must begin `basic ` (case-insensitive) followed by
  base64 of `username:password`, or the middleware answers 401. So `Bearer …` is not merely
  unrecognised, it is refused by construction.
* `api/external_endpoint.go` is where Gatus *does* speak bearer: `POST
  /api/v1/endpoints/:key/external` demands `Authorization: Bearer <token>` matching
  `external-endpoints[].token`. That is the write side for pushes, not a read path, and this product
  reads. It is named here because it is the reason a bearer token looked plausible in the first place.

**Consequence, and the one product-code change this makes:** `detection_worker.main()` builds the
Gatus client with `scheme='Basic'`, so `LO_GATUS_TOKEN_FILE` holds `base64("<username>:<password>")`
and no trailing newline. The variable name is unchanged on purpose (the stage's environment file, the
docs and the mount all keep working); its **content rule changed**, and the generator is:

```sh
user=lo-detector                                   # must equal security.basic.username in the
                                                   # rendered config.yaml — see the coupling below
pass=$(openssl rand -hex 24)                        # the password the engine's bcrypt hash verifies
umask 077; printf '%s' "$(printf '%s:%s' "$user" "$pass" | base64 -w0)" > gatus-token
```

and on the engine side, the value `config.yaml` needs is the bcrypt hash of *that same password*,
base64-encoded **in the URL-safe alphabet** (the rule and the reason are two bullets above).

**The generator line upstream's own README suggests for that field is wrong, and it was wrong in this
file until the authenticated Gatus probe.** It hands the password to `htpasswd` as a **command-line argument** and then
deletes the colon and the newlines out of the tool's own output before encoding what is left. That
pipeline is deliberately **not** reproduced here as something to paste; both halves are worth stating
in prose, because one is upstream's bug and the other is this repository's rule.

First: `htpasswd` prints `username:hash`, and deleting the separator and the newlines does not delete
the username — it glues the username to the front of the hash. The field then decodes to something
that is not a bcrypt digest, `ApplySecurityMiddleware` fails on it, and `api/api.go` turns that into a
panic: a crash loop nobody reads at a glance. The fix is to **extract** the hash rather than tidy the
line — `cut -d: -f2-`, lossless because a bcrypt digest holds no colon.

Second: a password in `argv` is readable with `ps` by anyone who can run it on this host, and secret files of
this repository is that a secret reaches a child through a file or its stdin.

The four flags the corrected form below uses are documented by the tool itself, in the Apache HTTP
Server `htpasswd` program page (<https://httpd.apache.org/docs/2.4/programs/htpasswd.html>), read
there on 2026-09-09: **`-n`** prints the record to stdout instead of touching a file, **`-i`** reads
the password from stdin (unmasked, on the first line), **`-B`** selects bcrypt, and **`-C cost`** sets
the cost factor — which is the cost upstream's own worked example for this field uses. The staging
driver passes those four as one combined argument, `-niBC 9 <username>`. The corrected pair, with the
password on stdin and the hash extracted:

```sh
user=lo-detector                                     # equals security.basic.username in the rendered file
umask 077
# 1. the hash alone: cut -d: -f2- keeps a bcrypt digest intact (it holds no colon)
hash=$(printf '%s\n' "$pass" | htpasswd -niBC 9 "$user" | cut -d: -f2-)
# 2. the two fields, in their two alphabets
printf '%s' "$(printf '%s:%s' "$user" "$pass" | base64 -w0)" > gatus-token
printf '%s' "$(printf '%s' "$hash" | base64 -w0 | tr '+/' '-_')"   # -> password-bcrypt-base64
```

The two files hold one secret: mode 0600 on the host, mounted read-only, never an environment value
(secret files) — and the rendered `config.yaml` is itself a credential-bearing file because it carries the
hash. A stage run adds a third artefact that is not a credential, only a path: the endpoint document
the container probe reads (`/checks/gatus-endpoint.json`), so the adapter's `LO_GATUS_URL` and the
probe's request path are one derivation and cannot drift apart.

**The stage now does the same thing automatically** : `scripts/conformance_platform_stage.py`
mints a synthetic `lo-stage-detector` principal per stage run, hashes its password with that stdin
form, renders `runtime/gatus-config.yaml` with the matching `security.basic` block, and hands
the same credential to the container probe through the platform's read-only `/config` bind. What is
still **UNVERIFIED** is unchanged in kind: the pair above is generated, mounted and cross-checked
against its own bytes offline, and no bcrypt verification or live-engine authentication has happened
anywhere in the tests — the component requires runtime acceptance, and step 2
of [conformance.md](conformance.md) is what would turn that into a result.

**UNVERIFIED:** that this pair authenticates end to end. No request has ever been sent to a running
Gatus with these values; the option names, the route ordering and the wire format above were read in
the source at the pinned tag, and `README.md`'s table is documentation, not a test. The first run of
[conformance.md](conformance.md) step 2 is what turns that line into a result.

**Also UNVERIFIED and deliberately left alone:** the engine runs as uid 0. Upstream's Dockerfile is
`FROM scratch` with one binary and no `USER` line, so `user: "65532:65532"` in the manifest would have
to be proven against a named volume that Docker initialises as root-owned. The staging service has run
uid 0 with `read_only: true`, `cap_drop: [ALL]` and `no-new-privileges` since the P2 milestone; this
component carries that shape forward and records it as an open item rather than silently changing a
credential boundary and a filesystem one in the same move.

## What the credential does *not* cover

`security:` guards the routes registered after it. At v5.36.0 these stay **unauthenticated by design
upstream**, on the same port:

| Route | What it leaks |
| :-- | :-- |
| `/api/v1/endpoints/<key>/health/badge.svg`, `…/uptimes/<d>`, `…/response-times/<d>` (+ `.svg`, `/chart.svg`, `/history`) | that a named endpoint is up/down and how fast, including the raw JSON of `/uptimes` and `/response-times` |
| `GET /api/v1/config` | `{"oidc": bool, "authenticated": bool, "announcements": [...]}` — nothing secret (`api/config.go` builds exactly those three keys) |
| `/health` | liveness only (it is what an operator's own monitor should scrape; see below) |
| `POST /api/v1/endpoints/<key>/external` | not a leak — it demands its own bearer token per `external-endpoints[].token` |

Endpoint *names* therefore appear in unauthenticated badges the moment an operator adds a target, and
those names are topology. That is the reason both services here publish no host port: on this
project's network the audience is every container in the stack, which is the same trust boundary the
platform's own plaintext producer token already assumes (`LO_INTERNAL_ALLOW_HTTP`). Anything narrower
is a TLS and authentication edge, and this repository ships that as a recipe, not a service
(`docs/DEPLOYMENT.md`).

## The detector's platform credential: one row, one identity

The section above decides how the detector gets **in** to the engine. This one decides whether the
platform accepts what the detector brings out, and until card **#265** (2026-09-10) it was the Sigma
runner's file — a refusal with a healthy-looking container on top of it, the same shape anomaly deployment support found in
`components/control/anomaly` at card **#259**.

`detector-producer-token` reads `${LO_DETECTOR_PRODUCER_TOKEN_FILE}`: a file of this service's own,
holding the token of a `producer` row in the same role file the platform reads
(`LO_PLATFORM_CREDENTIALS_FILE`; `examples/full/README.md` step 4 writes it and names its path). The
reason is four lines of `local_observe/platform/state.py` (947-948, read at this checkout, never
observed from a running container):

```python
if event['source'] != actor.identity:
    raise StateError('Source identity differs from authenticated producer')
```

One row of that file carries exactly one `identity`, so one token authenticates exactly one producer.
`Store.intake` is the same method the Sigma runner and the anomaly producer reach, and
`api.py` turns that `StateError` into **HTTP 400** with `{'error': 'not_authorised', 'detail':
'Source identity differs from authenticated producer'}` (`stable_code` maps the fixed sentence through
`NOT_AUTHORISED_MESSAGES`) — not a 401. (The sentence in `components/control/anomaly/compose.yaml:74`
calls it a 401; it is wrong there and outside this card's file list, so it is named in the report and
left alone here.)

**This producer's identity is named by a rule document, not by a variable.** The other two producers in
the stack each carry an environment value that must equal their row's `identity` —
`LO_SIGMA_SOURCE`, `LO_ANOMALY_SOURCE`. The detector has no such variable and ships none: `tick()`
posts `source=rule['source']` (`local_observe/platform/detection_worker.py`), and
`detections.evaluate()` stamps that same value on both the `availability` finding and the `.coverage`
event (`detections.py:63,80`), while `detections.py:44` (`label(rule['source'])`) makes the key
required in the document. So the operator's rule files are configuration that names an identity, and
the rule for them is:

* **every** document in `LO_DETECTION_RULE_DIR` mounted into one detector must name the identity this
  token was minted for. A rule naming anything else has its events refused forever — the engine keeps
  being polled, the cursor keeps its last value, and no verdict ever reaches the store;
* one rule per detector service (section "One rule per detector") means one producer row per detector
  service today. The rule-list change that file names would need N rows and N token files, one per
  distinct `source` — not one token for all of them, which is this defect wearing a new shape;
* the shipped example rule (`examples/platform/availability.yaml`) reads `source: stage-detector`, so
  an operator who installs that file unedited (`examples/full/README.md` step 5) mints a row named
  `stage-detector`. Renaming the rule's `source` renames the row, and the token file has to be
  rewritten from the new row or the detector is back in the refusal below.

**What the refusal looks like from outside, and the two ways it differs from the anomaly producer's.**
Both differences matter for whoever has to read a broken deployment, so they are stated rather than
assumed from anomaly deployment support's write-up:

* **the evidence lands, the event does not.** `tick()` posts the sample to `/v1/evidence` first, and
  `Store.put_evidence` (state.py:1686) reads no `source` field — it keys the row by the
  *authenticated* identity (`digest([actor.identity, sample['sample_id']])`, state.py:1698). So a
  wrong token leaves samples filed under someone else's name, and they are unretrievable by the name
  the event would have carried, because `get_evidence(source, sample_id)` (state.py:1708) rebuilds
  that same digest from the *asked* source. The failure is not cleanly rolled back: it writes.
* **this container does go `unhealthy`, and still does not say why.** A refused event raises
  `TransportError` after the batch was saved, and `tick()` only re-enters its build branch when
  `pending` is empty — so a retained batch is retried every 2 s without ever rewriting the cursor file,
  the cursor's mtime freezes, and the staleness probe (`max(3 × window, 60)`, `interval: 30s`,
  `retries: 3`) turns the container `unhealthy` inside about two and a half minutes at the default
  window. The anomaly producer inverts both halves: its cursor moves on every refused attempt and its
  healthcheck stays green. Neither container tells you *why* at default level: `main()` logs
  `Detection delivery unavailable; retaining pending batch` with `error_class: TransportError` at
  WARNING, and the raised sentence (`Event intake refused; pending batch retained`) appears only at
  DEBUG with the traceback. Read the log, not `docker ps` — and read the platform's refusal audit
  before blaming the store.

**Staging it** — `examples/full/README.md` step 5 carries the commands, and this is the third
`producer` row of that example (sigma, anomaly, detector). Add
`{"identity": "<the rule's source>", "role": "producer", "token": "<24+ chars, its own value>"}` to
the role file, then copy *that row's* token with `printf` (never `echo`; `read_credential` strips
exactly one trailing newline and a second one is a credential nobody accepts) into a mode-`0444`
file, because Compose bind-mounts a `file:` secret with its host mode and the container runs as uid
65532. Mint the token rather than copying the sigma row's value: the store dedups on
`(source, source_event_id)`, so two producers sharing one identity fold two verdict streams into one.

**UNVERIFIED:** as with every other claim in this directory — no `docker compose config`, no
container, no platform request has been made from this repository. The refusal sentence, its 400 /
`not_authorised` shape, the evidence-keying behaviour and the cursor-freeze reasoning above are read
from `state.py`, `api.py` and `detection_worker.py` at this checkout. Row **15** of
[conformance.md](conformance.md) is the check that turns them into a result, and it is `not-run`.

## Endpoint keys are derived, not declared

`config/key/key.go`: `key = sanitize(group) + "_" + sanitize(name)`, where `sanitize` lowercases and
maps `/ _ . , space # + &` to `-`. So `group: lo`, `name: platform-http` → **`lo_platform-http`**, and
`LO_GATUS_URL` addresses that string. An unknown key answers 404, `gatus_sample` sees no envelope it
recognises, and the adapter files `coverage` — a wrong key is loud, never a silent healthy zero.
Read it back with `python3 -c "from urllib.parse import quote; …"` or by asking the engine for
`/api/v1/endpoints/statuses` with the credential and grepping `key`.

## The window, and what each bound costs

`LO_DETECTION_WINDOW_SECONDS` (default **5 s**, valid **5..3600 s**) is the width of the completed
window the adapter closes per tick. It replaces a hardcoded `// 5` and the same bound is the one
`detections.evaluate()` already enforced on its `window_seconds` argument, so a value that passes one
check cannot fail the other; out of range or non-integer stops the process
(`detection_worker.window_from_environment`) rather than adopting something the operator did not say.

* What it sets: the finest granularity of an availability verdict, the interval below which the
  cursor refuses to re-run, and the base the detector's healthcheck multiplies (`max(3 * window, 60)`).
* What it does **not** set: the loop's cadence. `main()` sleeps 2 s between ticks whatever the window
  is, and each wake logs one `INFO` line (the logging cap in `compose.yaml` is sized for that, ~43,000 a
  day). A 1-hour window therefore asks the engine once an hour — `tick` returns `idle` before the
  `GET` while the cursor already covers the current window — and still writes 43,000 log lines a day.
  Raising the window buys the engine and the intake relief, not log relief.
* In the shipped range the window is the *reporting* grid, not a delay: an outage is filed at the end
  of the window that contains it, so the worst-case detection latency is the window plus the engine's
  own `interval`. At 3600 s a real outage waits up to an hour plus one probe interval (76 minutes at
  the shipped 30 s) for its first event. That is the actual cost of the upper bound, and it is the
  reason the default stays at 5 s.
* Lower bound 5 s: below one tick's worth of work the loop becomes a poll storm against Gatus's own
  cache and the platform's intake, at ~43,000 log lines a day (measured in logging's report).
* Upper bound 3600 s: `evaluate()` refuses above it, and a wider window means a stale sample reads as
  fresh for longer than any `max_age_seconds` in a shipped rule.
* **The engine's `interval` must stay well inside the rule's `max_age_seconds`** (three times is the
  working ratio). `config.yaml` probes every 30 s; the shipped rule default of `max_age_seconds: 120`
  satisfies the ratio, and `examples/platform/availability.yaml`'s `30` was authored for the stage's
  2 s probe and would flap against this interval.
* The **Gatus service has no healthcheck and cannot have one**: its image is `FROM scratch` with one
  binary, so there is nothing for `CMD` to execute. Engine loss therefore surfaces as a `coverage`
  verdict in the platform (which is what `detections.evaluate` is for and what
  `tests/test_detection_worker.py` pins for the *absent* case), not as an unhealthy container.

## Editing the config while the engine runs

`main.go` at v5.36.0 polls the configuration file every 30 seconds (`listenToConfigurationFileChanges`)
and, when its mtime moves, shuts the watchdog down, reloads and restarts it. Two consequences that are
worth knowing before an operator edits a rendered file in place:

* **a bad edit stops the engine rather than running it differently.** `skip-invalid-config-update`
  defaults to `false` (README's parameter table; upstream's own advice at the same section is not to
  turn it on), so a config that no longer validates takes the process down with it. With
  `restart: unless-stopped` in the manifest that is a crash loop the platform reports as coverage —
  loud, which is the direction this component chooses.
* **the file is bind-mounted, one file, read-only, `create_host_path: false`.** An in-place write
  (`echo … > file`, `sed -i` variants differ) and a rename-over differ in whether the container sees
  the same inode; `install` and editors that write a new file and rename it can leave the mount
  pointing at the old bytes. **UNVERIFIED** at the pinned release — nothing here has been bind-mounted
  and reloaded — so the documented path is: render the file, then `docker compose up -d gatus` (or
  `restart gatus`) rather than relying on the hot reload.

## One rule per detector

`LO_DETECTION_RULE` names one document, so one `detector` container evaluates one target. The
component ships as it found this, and names it: to monitor N targets today you run N detector
services (patched in an overlay, each with its own `LO_GATUS_URL`, rule file and `detector-data`
volume) or you make the rule-list change below. That change is small but not free — the cursor's
pending-batch shape and the log-volume note both assume one window per process — so it is not smuggled
into a card whose subject is the missing directory. Recorded in `docs/COMPONENTS.md`'s `synthetics`
row and in `conformance.md`'s open list.

## Publication

Neither service publishes a port. `gatus` and `detector` are therefore **absent** from
`scripts/check_foundation.py`'s `HOST_PUBLISHED_SERVICES`, which is the required publication boundary and
the state the gate enforces (an internal service with a `ports:` line is an error). Gatus's status
page is a real feature and would need a loopback publication plus a name on that tuple; that is an
argument in a PR, not an edit here.

## What synthetics component's move costs the live platform stage (four call-sites, applied by the authenticated Gatus probe)

The fix is not one flag per call-site, and the authenticated Gatus probe is the reason that answer is on the record: the
right chain depends on **which package a deployment is**, so each of those four places now reads it
from the selected deployment's own files instead of typing a list from memory.
`components/control/synthetics/compose.yaml` is added when, and only when, that file exists in the
deployment; a frozen package whose fragment still declares the two services keeps its two layers
unchanged, and no archived byte is rewritten. A package with neither loop, with only one of the two
services, or with both files declaring them, is refused.
`scripts/conformance_platform_stage.py` refuses a package with no component at all rather than running
the weaker chain, because a fresh stage that starts no engine has no business reporting lifecycle
checks as a result.

The stage's own `private.env` gained the second half of the fix:

```sh
LO_GATUS_URL=http://gatus:8080/api/v1/endpoints/staging_synthetic-http/statuses
```

## If disabled

Remove the `../../components/control/synthetics/compose.yaml` include entry (or never add it). Then:

* the store, the inventory, the incidents, the outbox and the Sigma path are untouched — this
  component owns no part of them, declares no `depends_on` on it, and nothing else in the shipped tree
  waits on `gatus` or `detector`;
* the availability rules the detector used to evaluate **stop being evaluated**, and any rule that was
  firing stays firing on `coverage` rather than resolving: `detections.evaluate()` opens
  `coverage` for a `None`/stale/refused sample and never resolves the underlying condition
  (`detections.py`, pinned for the absent-engine case by `tests/test_detection_worker.py` and `tests/test_platform.py::PlatformTests::test_detection_absence_and_threshold`);
* the row's `If disabled` clause is exactly **"No synthetic coverage"** — no probe, no synthetic
  availability finding, and no false all-healthy;
* `GATUS`/`detector` volumes keep their contents; deleting them is a separate, destructive act
  ([backup.md](backup.md)).

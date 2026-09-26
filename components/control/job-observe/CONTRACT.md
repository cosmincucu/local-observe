# Job observation: Healthchecks (selected, not validated)

Component id `job-observe` combines Healthchecks push check-ins with per-host
`systemd_exporter` metrics. Existing systemd timers remain the executors. This contract
covers push check-ins; the exporter is documented in the
[Linux agent contract](../../data/agent-linux/CONTRACT.md).

## 1. What each half decides, and why two

| Question | Decided by | Reaches the operator as |
|---|---|---|
| "the job did not run by its deadline" | Healthchecks (this component) — it owns the period and the grace, and evaluates them off the job's host | a store metric (`hc_check_up`) plus Healthchecks' own notification channel |
| "the job ran and failed" | `systemd_exporter` on the job's host | a store metric (`systemd_unit_state{state="failed"}`, `systemd_timer_last_trigger_seconds`) |
| "the platform API stopped answering" | `local_observe/platform/deadman.py`, which pings a check here every 30 s | a missed or failed check-in, i.e. the same two signals as above |

They are distinct on purpose: a job that never started leaves no failed unit, and a job that failed
in the last second did not miss its deadline. The "Missed job" acceptance scenario
(`docs/COMPONENTS.md` §5) is the test that a change has not merged the two together —
[conformance.md](conformance.md) holds the recipe.

**A check must be armed, or it watches nothing.** Read at upstream `hc/api/models.py` and
`hc/api/management/commands/sendalerts.py` on 2026-09-08: a check that has never been pinged has
status `new`, `get_grace_start()` returns None for it, `going_down_after()` therefore returns None,
`sendalerts` clears its `alert_after` and moves on — and the metrics view writes `hc_check_up 1` for
anything that is not `down`. So the job that never ran **even once** is the one state Healthchecks
will not alarm on, and the install-time check-in is part of creating a check, not an afterthought.
`conformance.md` step 0 is the check that proves this on a running instance.

## 2. Pins, licences, and where each claim comes from

Both images were read from an upstream release on 2026-09-08 and **never run here**; digests and the
method are in [versions.json](versions.json). Nothing in this file is a runtime claim.

- **Healthchecks v4.4** (released 2026-08-31), **BSD-3-Clause**, image
  `healthchecks/healthchecks:v4.4`. Upstream states the pre-built images exist for amd64, arm/v7 and
  arm64, that uWSGI performs database migrations on startup and runs `sendalerts`, `sendreports` and
  `smtpd` itself, and that the images do **not** terminate TLS:
  [docker/README.md](https://github.com/healthchecks/healthchecks/blob/master/docker/README.md).
- **`systemd_exporter` v0.7.0** (released 2025-03-14), **Apache-2.0**, image
  `prometheuscommunity/systemd-exporter:v0.7.0`, listening on `:9558` and running as `nobody`
  ([Dockerfile at the tag](https://github.com/prometheus-community/systemd_exporter/blob/v0.7.0/Dockerfile)).

## 3. The two interfaces this product relies on

**(a) The Prometheus scrape endpoint** — what makes a missed check-in "an ordinary metric alert in
the store" instead of a bespoke alert channel. Upstream documents the scrape target as
`metrics_path: /projects/{your-project-uuid}/metrics/{your-readonly-api-key}` with a **read-only**
API key ("Prometheus does not need read-write API access") and lists the exported names in
[Configuring Prometheus](https://github.com/healthchecks/healthchecks/blob/master/templates/docs/configuring_prometheus.md).
The names this product's alert rules read, confirmed against
[`hc/integrations/prometheus/views.py`](https://github.com/healthchecks/healthchecks/blob/master/hc/integrations/prometheus/views.py)
at master on 2026-09-08, are `hc_check_up`, `hc_check_started`, `hc_check_grace`, `hc_check_paused`,
`hc_tag_up`, `hc_checks_total`, `hc_checks_down_total`, each check series labelled `name`, `tags`,
`unique_key`. `hc_check_up` is 0 only when the check's status is `down`, so **`late` reads as up** —
an alert rule must watch `hc_check_grace`/`hc_check_started` too, or the difference between "running
long" and "missed" is lost. The same source shows a Bearer-key variant at
`/projects/<uuid>/metrics/` and that a key shorter than 32 characters is refused with 400.

**(b) The ping URL** — the push half of a check-in, and the reason no credential is needed to
submit one. Upstream documents that appending `/fail` (or `/<nonzero-exit-status>`) to the normal
ping URL reports a failure immediately rather than at the deadline
([Signaling failures](https://github.com/healthchecks/healthchecks/blob/master/templates/docs/signaling_failures.md)).
`local_observe/platform/deadman.py` uses exactly that: one mounted URL, `GET <url>` when the probe
passed and `GET <url>/fail` when it did not. **A ping URL is a bearer credential** — anyone holding
it can mark the job up — so it is a mounted file with only its path in the environment, and it is
never logged: see §5.

**(c) The management API**, used by operators and by nothing in the product today:
`GET {SITE_ROOT}/api/v2/checks/` with an `X-Api-Key` header
([Management API v2](https://github.com/healthchecks/healthchecks/blob/master/templates/docs/apiv2.md)).
Check `status` values are `up`, `late`, `down`, `paused`; a **read-only** key omits the `*_url`
fields from responses, which is what makes it safe to hand to a scrape or a report. If a future item
mirrors Healthchecks' verdict into platform *state* (see §6), that API is the input and it should be
a read-only key.

## 4. Configuration surface

| Variable | Value in the manifest | Notes |
|---|---|---|
| `LO_HEALTHCHECKS_IMAGE` | required | the **amd64** digest from versions.json; `platform: linux/amd64` is set because the tag is multi-arch |
| `LO_HEALTHCHECKS_PORT` | `18097` | loopback publication only, like every other port in this product |
| `LO_HEALTHCHECKS_SITE_ROOT` | `http://127.0.0.1:18097` | the URL the UI and the generated ping URLs are built from |
| `LO_HEALTHCHECKS_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Django's Host-header allowlist; defaults to the domain part of `SITE_ROOT` upstream |
| `LO_HEALTHCHECKS_PING_ENDPOINT` | `http://127.0.0.1:18097/ping/` | see §7 — the reason this is a limit and not a default to change casually |
| `LO_HEALTHCHECKS_SECRET_FILE` | required, mounted | Django `SECRET_KEY`, via the file form upstream supports natively |

**A misconfiguration here fails the boot, which is the point.** uWSGI runs `manage.py migrate` in a
pre-app hook, and `migrate` runs Django's system checks; upstream registers
`hc.api.E002` — *"The hostname in settings.SITE_ROOT is not found in settings.ALLOWED_HOSTS"* — in
`hc/api/apps.py`, so a `SITE_ROOT` whose host is not in `LO_HEALTHCHECKS_ALLOWED_HOSTS` is a container
that never becomes healthy rather than a console that half-works. `hc.api.W002` warns (does not fail)
when no SMTP host is configured, which is the shipped state.

SQLite is the shipped mode because it is the image's own default and it keeps the component to one
service and one volume: `DB` defaults to `sqlite` and `DB_NAME` defaults to a file inside the
project directory
([self-hosted configuration](https://github.com/healthchecks/healthchecks/blob/master/templates/docs/self_hosted_configuration.md)),
which is why the manifest sets `DB_NAME=/data/hc.sqlite` — `/data` is the directory the Dockerfile
creates and hands to the service user. **Choosing Postgres instead** means a second service, a second
credential (`DB_PASSWORD_FILE`, which upstream also supports in file form), a `pg_dump` in
[backup.md](backup.md) and a cross-host backup dependency; it buys concurrency and a supported
large-installation path this reference deployment does not claim to need.

## 5. Credentials

- `LO_HEALTHCHECKS_SECRET_FILE` → mounted at `/run/secrets/healthchecks-secret`, and the
  environment carries only that path. This is the secret files shape and it needed no exception, because
  upstream reads secrets through an `envsecret()` helper that prefers `SECRET_KEY_FILE` over
  `SECRET_KEY` (`hc/settings.py`: *"This function either reads the secret from a file (if s +
  `_FILE` environment variable has a non-empty value), or calls `os.getenv()`"*). Setting
  `SECRET_KEY` as well would put the value back where `docker inspect` and
  `/proc/<pid>/environ` can read it, so the manifest does not name it at all.
- **No administrator credential is shipped.** Healthchecks' console account is created by the
  operator against a running container (`manage.py createsuperuser`, which upstream's own Docker
  README gives as the documented command). The alternatives were both refused: a password as an
  environment value fails this project's credential rule, and Compose cannot feed a file into the
  interactive prompt. The consequence is honest and stated: **until that command has run, the
  console has no login, and with no login there is no way to mint the API keys that create checks**
  — so the order in [docs/INSTALLATION.md](../../../docs/INSTALLATION.md) §6 and
  [examples/full/README.md](../../../examples/full/README.md) step 6 is account → keys → checks →
  arming ping, and nothing earlier in that list works without the step before it.
- The per-check ping URLs live in **Healthchecks' database**, not in this manifest, and the copies
  that matter to the product are the ones mounted on the *job hosts* (see §6). A ping URL in a
  committed file, a log line or a Compose environment value is a leaked credential.

## 6. How a check-in reaches this component, and where the event lands

`local_observe/platform/deadman.py` remains what it always was — an external witness with its own
persisted failure clock, holding only a **reader** credential and writing to nothing inside the
platform. What changed is its reporting target: it reads one URL from `LO_HEALTHCHECKS_PING_FILE`
(`local_observe/credentials.read_credential('LO_HEALTHCHECKS_PING')`, so a mounted file is preferred
over an environment value) and, every 30-second tick, `GET`s it on a good probe and `GET`s
`<url>/fail` on a bad one. Missing or malformed configuration is a boot refusal, not a silently
unwatched witness.

A missed check-in is then an availability finding, and **the event kind is `availability`**:
`state.py`'s `validate_event` admits exactly `availability`, `coverage`, `threshold` and `drift`
(measured at this commit), so there is no `job` kind to use and inventing one is a schema decision
(`docs/DECISIONS.md` event vocabulary adds `anomaly`/`security` in item event kinds — it does not add `job`). The
witness stamps the event with `kind='availability'`, `rule_id='deadman-checkin'` and the
**declared inventory resource id of the job** it is watching, taken from `LO_DEADMAN_RESOURCE_ID`;
absent that variable the payload keeps its pre-job observe standard shape, so an existing deployment does not
suddenly name a resource it never declared.

What the witness deliberately does **not** gain is write access. Posting an event into
`/v1/events` needs a *producer* credential, and a witness holding one could be silenced by the
system it watches — the property `docs/ARCHITECTURE.md` §3.5 calls "keep the independent dead-man
outside the scheduler failure boundary". So the event object the witness emits is canonical and the
authoritative write of it into platform state belongs to a separate, reviewer-approved decision:
either a small pull adapter on the §3(c) API with a read-only key, or the store-side metric rule.
This integration remains unimplemented. Keep the witness credential read-only.

## 7. Limits of the loopback-only rule

The reference deployment publishes no non-loopback port, which is the right posture for a service
this repository tests and an operator fronts with their own proxy. It has a real consequence:
**a job on another host cannot check in here**, because its ping destination would have to be
reachable from that host. Same-host jobs and the platform witness work as shipped; cross-host
coverage needs the operator's TLS reverse proxy in front of `SITE_ROOT` plus the matching
`ALLOWED_HOSTS`, and then two more things upstream requires:

- the proxy must set `X-Forwarded-Proto` and discard any client-supplied value, or Django's CSRF
  protection answers login POSTs with a 403 (upstream's docker README documents exactly this
  failure and the `$scheme`/`ssl_fc` fix). The matching Healthchecks setting is
  `SECURE_PROXY_SSL_HEADER=HTTP_X_FORWARDED_PROTO,https`, documented in
  [self_hosted_configuration.md](https://github.com/healthchecks/healthchecks/blob/master/templates/docs/self_hosted_configuration.md)
  with the warning that it may be set *only* when the operator controls the proxy — so it is not in
  this manifest, where nothing terminates TLS;
- `LO_HEALTHCHECKS_PING_ENDPOINT` must name the proxied URL, since that is what the generated ping
  URLs are built from.

Both are named checks in [conformance.md](conformance.md), because both are the kind of thing that
is discovered the night a backup silently stops checking in.

## 8. UNVERIFIED, stated plainly

- **Nothing in this component has been run.** No image pulled, no container started, no ping sent,
  no metric scraped, no restore. The compose file has been read by `scripts/check_foundation.py`'s
  loader and rendered against a filled environment by `tests/test_job_observe.py`; that proves
  shape, not function.
- The default `LO_HEALTHCHECKS_PORT` (18097) is chosen to be free of the two shipped examples; the
  collision that matters is with the operator's own services and is theirs to check.
- Whether `read_only: true` can be turned on depends on the uWSGI static-gzip cache path; see
  §"Configuration" in [conformance.md](conformance.md).
- The `systemd_exporter` opt-in in `components/data/agent-linux/collector.yaml` ships **unreferenced
  by any pipeline**, so the shipped agent scrapes nothing until an operator edits both the config and
  its own compose environment. That edit is deliberately outside job observe standard's file list; see its CONTRACT.
- Healthchecks' `hc_*` metric names are read from source at `master` (2026-09-08), not from the v4.4
  tag, because `templates/docs/configuring_prometheus.md` and the views module are the same file at
  both; re-read them against the tag you actually run before writing an alert rule.

See [backup.md](backup.md), [upgrade.md](upgrade.md), [conformance.md](conformance.md).

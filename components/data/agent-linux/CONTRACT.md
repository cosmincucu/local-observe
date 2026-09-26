# Linux reference agent

Requires `LO_OTEL_IMAGE` digest, the ingest credential as a file, stable inventory UUID
`LO_RESOURCE_ID`, mutable `LO_HOST_NAME`, an approved existing `LO_HOST_ROOT`
and `LO_LOG_DIR`. Agent state is the project-scoped `agent-state` volume.
Default `LO_INGEST_URL` is the internal demo front door; remote endpoints need
validated TLS or a verified encrypted tunnel. No engine socket or host network.
The agent authenticates with the ingest credential only — the store credential
never reaches an observed host.

That credential is mounted, not exported, and this is the component where it matters most: the
agent runs on an **observed host**, whose root can read any container environment
(`docker inspect`, `/proc/<pid>/environ`) and inherits it into every child process. The manifest
therefore sets `LO_INGEST_TOKEN_FILE=/run/secrets/agent-ingest-token` — a path — and
collector.yaml presents the token through confmap's `file` provider, so the value never enters
the process environment at all. No exception is recorded for this service. The file must hold
the token with no trailing newline (`printf '%s'`, never `echo`): the provider passes the bytes
through, and the newline would be sent inside the `Authorization` header. The secret is named
`agent-ingest-token`, not `ingest-token`, so that including the front door in the same project
cannot declare one secret name twice; both mount the same host file.

No compose healthcheck is declared for the agent: this component records no image
lock, so no executable inside the collector image is known and a probe command would
be a guess. The `health_check` extension listens on `:13133` inside the container and
the agent publishes no port, so there is nothing to probe from the host either. Agent
liveness is the freshness of its data in the store, not a container health state.

Host metrics are collected every 30 seconds, including per-core CPU. The root
filesystem input is read-only but broad: setting it to `/` exposes the host's
files to a root collector. This requires explicit staging-host approval and is
not equivalent to least-privilege access. Do not auto-enrol a production host.
Host network/process identity and mount coverage need runtime verification.
`LO_FILESYSTEM_MOUNT_PATTERN` selects filesystem mount points (regex, default
`.*`). A restricted staging account should select only its approved mounts;
do not grant access to production volumes to silence filesystem scrape errors.

Only `*.log` files in the approved directory are ingested. For the first demo,
use a new synthetic-only directory. File offsets and exporter queues persist
across restarts; files start at beginning when no matching offset exists.
Retention/rotation must leave files available long enough for retry. Queue
capacity is 1,000 requests, not an unlimited outage buffer or byte limit.

The agent sets `resource_id` and `host.name` on its own data. These are not
authentication claims. The platform inventory remains identity authority.
It does not open an OTLP receiver and cannot collect arbitrary application
traces; the front door accepts those separately. No optional-plane dependency.

## Job observation on this host (`systemd_exporter`, optional sidecar)

Decided by **job observation** and owned by the [job-observe component](../../control/job-observe/CONTRACT.md),
which ships the push half (Healthchecks, "the job did not run by its deadline"). **This** half answers
"the job ran and failed", on each observed host, as ordinary metrics in the store.

**`systemd_exporter` is not a service in any Compose manifest in this repository.** It is a per-host
agent, and it is not shipped enabled: nothing here starts it, no manifest declares it, and the
collector block that could read it is present but unreferenced (see below). Enabling it is a host
change with a host review.

How to run it, upstream's own shape, pinned at v0.7.0 (Apache-2.0; amd64 digest and the source lines
for the port and the user are in
[job-observe/versions.json](../../control/job-observe/versions.json)):

```sh
# On the observed host, not in this Compose project. The image listens on :9558 (EXPOSE 9558 and
# webflag.AddFlags(..., ":9558") at the tag) and runs as `nobody` (its Dockerfile).
podman run -d --name systemd-exporter --restart unless-stopped \
  -v /run/dbus/system_bus_socket:/run/dbus/system_bus_socket:ro \
  -v /proc:/host/proc:ro -p 127.0.0.1:9558:9558 \
  quay.io/prometheuscommunity/systemd-exporter:v0.7.0 \
  --web.listen-address=0.0.0.0:9558 \
  --systemd.collector.unit-include='.*\.(timer|service)'
```

Two host facts decide whether it works, and both are the reason this stays opt-in rather than shipped
enabled: it needs **systemd's D-Bus** ("User needs to access systemd dbus, typically exporter needs to
see node's `/proc` to work" — README, "User privileges"), which means a socket mount into the
container that this project's gate refuses for every manifest it ships (mounting the Docker control
socket is a banned token under `components/**` and `examples/**` for the same class of reason: one
mount of a control socket hands the container the host's init); and its unit-selection flags are
`--systemd.collector.unit-include` (default `.+`) and `--systemd.collector.unit-exclude`
(default `.+\.(device)`), RE2, so the *default* exports every unit on the host — cardinals per unit
that the store's retention then has to absorb. Bind the publication to `127.0.0.1` and let only the
local collector read it.

**Which metrics, and what they cost.** From the table in the exporter's README at the tag — every row
of it is labelled **UNSTABLE**, so a store-side alert rule on one is a pin and belongs in
`versions.json` reasoning, not in a dashboard nobody owns:

| Metric | What it answers | Caveat |
|---|---|---|
| `systemd_unit_state{name,type,state}` | "is this unit failed / active / inactive" — states `activating`, `active`, `deactivating`, `failed`, `inactive`; 5 series per unit | the exporter says a *failed* unit keeps its failed state until `systemctl reset-failed`, so "failed" is a latch, not a moment; a per-job alert must key on the unit name and reset it deliberately |
| `systemd_timer_last_trigger_seconds` | "when did this timer last fire" — the *missed-run* signal on the pull side | one series per timer; the value is systemd's, not a proof the job succeeded |
| `systemd_unit_start_time_seconds` | when the service last started | 1 per service |
| `systemd_service_restart_total` | restart count — a crash-loop tell | **off by default**: needs `--systemd.collector.enable-restart-count` and systemd ≥235 |

**How the data reaches the store.** Two shapes, and the choice is the operator's because the collector
config file is where it is decided:

1. *Scrape it* — the shipped `collector.yaml` carries a `prometheus/job-observe` receiver that is
   **not named in any pipeline**, so the agent starts exactly as it did before this block existed and
   scrapes nothing. To opt in, the operator adds `prometheus/job-observe` to
   `service.pipelines.metrics.receivers` **and** points `targets` at an address the agent container can
   actually reach. The shipped literal (`127.0.0.1:9558`) is deliberately unreachable-looking: this
   container shares no network namespace with the host (`network_mode: host` is refused by
   `check_foundation.py`), so a loopback target inside the agent is the agent's own loopback. Put the
   exporter's host-reachable address there, or run the exporter as a container on a network this agent
   joins. No environment variable is involved, which is why activating it means editing this file —
   `agent-linux/compose.yaml` deliberately gained no line it did not need.
2. *Skip the exporter* — the same `LO_OTEL_IMAGE` (contrib) has a native `systemd` receiver that reads
   D-Bus directly and emits `systemd.unit.state{systemd.unit.name=..., systemd.unit.active_state=...}`
   at **alpha** stability ([receiver README](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/receiver/systemdreceiver/README.md)).
   It needs the same D-Bus access and no extra container, at the cost of an alpha component and a
   *different* metric spelling from the Prometheus world. job observation chose `systemd_exporter` by name; using
   the collector's own receiver instead is a legitimate deviation, so it is recorded here rather than
   substituted silently, and both spellings differ from what this product's retired worker produced.

The front door can scrape the Healthchecks side (`hc_check_up` and friends) the same way; that wiring
lives in `components/data/front-door/collector.yaml`, which is outside this item's file list, so the
`metrics_path` to use is written in
[job-observe/CONTRACT.md](../../control/job-observe/CONTRACT.md) §3(a) and the open card is recorded in
`DEPENDENCIES.md`.

See [conformance](conformance.md), [backup](backup.md), [upgrade](upgrade.md).

Host-specific exporter access and complete runtime conformance remain UNVERIFIED until tested in your installation.

# Installation

For an observer over existing services, use [guided setup](units/guided-setup.md), then
the [observer walkthrough](units/observer.md). You need a bounded read source, an explicitly
configured model and protected runtime storage. Start with recording; configure a phone
channel separately. The manual foundation installation below remains supported and runs
without a model. Guided configuration does not install or validate third-party services.

For interactive component access, begin with [account setup](OPERATOR-SETUP.md).
Choose credentials once, use Homepage as the main page, and follow the generated
handoff for components that require native registration. Machine credentials
remain separate. The steps below still own data-plane installation.

This guide starts the smaller telemetry composition: an authenticated
OpenTelemetry front door, SigNoz/ClickHouse and one Linux collector. The
[full-stack example](../examples/full/README.md) adds inventory, incident handling,
job status and the main page. Windows collection is an optional native install
in section 7.

The source has automated tests; this guide is not a
claim that every included component has passed full installation acceptance.
Read [current status](../STATUS.md) and each selected component's conformance
record before relying on the deployment.
## 1. Prerequisites

- One Linux/amd64 Docker host. The reference baseline is 16 GB RAM plus headroom
  for whatever else that host runs; the per-container caps in `components/` are not
  load-tested.
- Docker Compose **2.23.1 or newer**. `examples/demo/compose.yaml` uses `include`,
  and the store model uses inline `configs.content`, introduced in that version
  ([Compose reference](https://docs.docker.com/reference/compose-file/configs/)).
- Python 3.12 on that host for the two `scripts/` commands below. Both are
  stdlib-only and talk to the Docker CLI and to loopback ports of the machine they
  run on, so run them on the target host, never through a remote Docker context.
- Outbound HTTPS to the image registries and to the SigNoz GitHub release, and a
  small binary you download once (step 3).
- Loopback ports 18081 (UI), 14317/14318 (OTLP) and 13133 (front-door health) free
  on the host. Every published port binds `127.0.0.1`.
- The Linux collector reads a host directory tree. Its default scope is the whole
  root filesystem, which exposes host files to a root collector, so run it in a
  disposable guest or set `LO_HOST_ROOT` deliberately
  ([agent contract](../components/data/agent-linux/CONTRACT.md)).

## 2. Build the first-party images

The telemetry-only composition below uses pinned third-party images and does
not require a first-party build. The full composition needs the platform and
inventory images; the optional MCP service has its own image.
Follow [the build guide](BUILD.md) for Dockerfiles, dependency locks and image
provenance. Build only the images required by your selected composition.

## 3. Fill the environment file

Copy `examples/demo/.env.example` to a file **outside the checkout** and fill every
variable; none may stay empty. Keep it out of shared evidence: a resolved Compose
model still contains the one credential that is an environment value (`SIGNOZ_JWT_SECRET`);
the others appear there only as the path of a file the manifests mount.

- `LO_CLICKHOUSE_IMAGE`, `LO_ZOOKEEPER_IMAGE`, `LO_SIGNOZ_IMAGE`,
  `LO_SIGNOZ_COLLECTOR_IMAGE`, `LO_OTEL_IMAGE` — take each value from the `image`
  field of the matching key in
  [`../components/data/store-signoz/image-lock.json`](../components/data/store-signoz/image-lock.json).
  Each is a `repository@sha256:<64 hex>` reference. The plain tags in
  `versions.json` are candidates kept for provenance; re-resolve digests only for a
  reviewed pin change, and a failed pull is a blocker, not permission to use
  `latest`.
- `LO_HISTOGRAM_BINARY` — absolute path to a `linux-amd64` `histogramQuantile`
  binary, and `LO_HISTOGRAM_SHA256` — its SHA256. Download the archive named in
  `histogram_binary.url` in that component's `versions.json`, inspect its member
  paths and reject absolute or traversal paths, extract into a temporary directory
  and hash the binary. `histogram_binary.sha256` in that file is the **extracted
  binary** hash and is the value this variable takes; `histogram_binary.archive_sha256`
  is the download and never goes into the environment. ClickHouse will not start
  unless the bind-mounted binary hashes to `LO_HISTOGRAM_SHA256`.
- `LO_INGEST_TOKEN_FILE` — the absolute path of a file holding the ingest credential, generated
  for this installation (at least 24 characters). Compose mounts that file into the front door and
  into the Linux agent as a secret, so the environment never carries the value. Create it once, on
  the host that runs the stack, with `printf` and not `echo` — the collector sends the file's bytes
  verbatim and a trailing newline would travel inside the `Authorization` header:

  ```sh
  mkdir -p -m 700 /approved/private
  umask 077; printf '%s' "$(openssl rand -hex 32)" > /approved/private/ingest-token
  ```

  `LO_STORE_TOKEN_FILE` is the same shape with a **separate** value (the front-door → store-collector
  hop); reusing one credential across the two hops is the defect the split exists to prevent.
- `SIGNOZ_JWT_SECRET` — one random secret of at least 24 characters, generated for this
  installation. It is still an environment **value**, not a file: it belongs to an image this
  repository does not build, and the exception is recorded in
  `components/data/store-signoz/CONTRACT.md`.
- `LO_HOST_NAME` — the name you want on this host's telemetry.
  `LO_RESOURCE_ID` — a UUID you generate now. The value committed in
  `.env.example` is a placeholder; reusing it makes several installations report as
  one resource, and the platform resolves `resource_id` when it decides what an
  action may touch.
- `LO_HOST_ROOT` and `LO_FILESYSTEM_MOUNT_PATTERN` — the read scope of the Linux
  collector (see prerequisites). `LO_LOG_DIR` — a directory you create for the
  synthetic file-log source; the agent appends markers there during conformance.
- `LO_UI_PORT`, `LO_OTLP_GRPC_PORT`, `LO_OTLP_HTTP_PORT`, `LO_INGEST_HEALTH_PORT` —
  loopback publication ports; change them only if another project on that host
  already holds them.

## 4. Start the data plane

Run from the checkout root, with your own environment path in place of the
placeholder, and only continue after each command succeeds. Two offline checks need
no Docker and can run first: `python3 -B scripts/check_foundation.py --json` on the
model files, and the unit suite (`python3 -B -m unittest discover -s tests`, which
needs `requirements-dev.txt`). The bring-up sequence below is the one written in
[`../examples/demo/README.md`](../examples/demo/README.md):

```sh
python3 -B scripts/conformance_smoke.py --env-file /approved/private/demo.env --preflight
docker compose --env-file /approved/private/demo.env --project-name local-observe-demo -f examples/demo/compose.yaml up -d
docker compose --env-file /approved/private/demo.env --project-name local-observe-demo -f examples/demo/compose.yaml ps -a
python3 -B scripts/conformance_smoke.py --env-file /approved/private/demo.env
# The same smoke run against `examples/full` rather than the demo: the script reads the
# rendered model of whatever composition you name, so it drives that project too. This line needs the
# full stack of section 6 up under the project name it gives, not the demo above.
python3 -B scripts/conformance_smoke.py --env-file /approved/private/full.env \
  --compose examples/full/compose.yaml --project local-observe-full
```

`--preflight` renders the configuration and checks the model without printing any
secret. The initialization and migration containers are expected to exit
successfully; the store, front door, collector and agent stay running. Inspect a
failure privately rather than pasting a config dump.

## 5. Verify

The last command in step 4 is the check. It sends synthetic OTLP HTTP metrics, logs
and traces through the front door, confirms a missing credential and a wrong
credential are both refused, and reads its unique markers back with bounded
ClickHouse queries. Exit 0 is a pass, exit 1 is a failed check, exit 2 means the
Docker daemon is not reachable from that host. It does not start containers and does
not cover gRPC ingest, redaction, the UI, crash durability, backup/restore or
upgrades — each component's `conformance.md` holds those checks and states which of
them have not run.

Open the UI at `http://127.0.0.1:18081`. Because the store publishes on loopback
only, on a remote host forward that port from your workstation or tunnel to it;
do not republish it on `0.0.0.0`. Complete the initial SigNoz login privately.

Stop with the project-qualified command and keep the volumes until you decide what
to do with them:

```sh
docker compose --env-file /approved/private/demo.env --project-name local-observe-demo -f examples/demo/compose.yaml stop
```

Never use an unqualified prune or `down -v`, and rehearse a restore in a differently
named project with different ports and fresh volumes
([backup and restore](../components/data/store-signoz/backup.md)).

## 6. Add the platform and selected integrations

The [full-stack example](../examples/full/README.md) composes the store, front
door, Linux agent, inventory reader, platform interface, detection workers, job
services and Homepage. Follow its ordered steps rather than adding independent
services against the same state database.

| Capability | What you must prepare |
|---|---|
| Platform and operational interface | Build the platform image, mount its credentials and persistent state, and provide the inventory snapshot. The interface overrides the platform command; it is not a second database writer. |
| Inventory | Build the resource index with `lo-inventory build` and mount its directory as `LO_INVENTORY_SNAPSHOT_DIR`. The full composition includes the reader service. See the [inventory guide](../local_observe/inventory/README.md). |
| Sigma and anomaly detection | Supply compiled rules or selected-series configuration, store-read credentials, platform intake credentials and owned durable cursor paths. Validate restart, replay and any cursor migration before enablement. |
| Dagu job execution | Provide a reviewed job-definition directory. The bind refuses a missing path and is read-only; create it deliberately rather than relying on Docker to create an empty directory. |
| Job observation | Configure deadline check-ins and host outcomes under the [job-observation contract](../components/control/job-observe/CONTRACT.md). A newly created check that has never received a ping is not proof of monitoring. |
| Homepage | Render its configuration and provide the required credential files. It links to native interfaces; an access gateway and account configuration remain deployment responsibilities. |
| Gatus synthetic checks | Configure targets, HTTP Basic authentication and detector rules. Its engine is internal to the Compose network; do not assume a browser-facing status page. |
| AI, MCP and chat | Separate opt-ins in the full-example guide. The foundation needs no model or chat account; each selected integration still needs credentials, compatibility checks and component acceptance. |
| CrowdSec | A separate optional [example](../examples/crowdsec/README.md). Decision intake is not a privileged enforcement grant. |
| Retention and recovery | Configure retention deliberately and verify consistent backup, copied-state restore and rollback for the selected components. A passing telemetry smoke does not cover these operations. |

Check [components](COMPONENTS.md) for the source map and [status](../STATUS.md)
for dated acceptance. Selected synthetic and upgrade rehearsals have passed;
that does not establish acceptance of the complete full-stack composition or
real notification delivery.

The [platform staging composition](../examples/platform/compose.yaml) adds a probe
target and a recording sink for isolated tests. Its override fragment is not a
standalone service or an instruction to change a running installation.

## 7. An optional Windows source host

Nothing here is Compose. A Windows host runs one native executable
([`components/data/agent-windows/`](../components/data/agent-windows/CONTRACT.md)) that sends the
same authenticated OTLP as the Linux agent, and it is optional: the data plane above needs no
Windows host, and this section installs no platform/inventory/Sigma service.

1. **Obtain and verify the binary before you run it.** Follow the
   [provenance recipe](../components/data/agent-windows/CONTRACT.md#provenance-download-verify-then-install):
   download the asset named in
   [`versions.json`](../components/data/agent-windows/versions.json), compare the download against
   the publisher's *own* checksum file, inspect the archive's member paths, then compare the
   extracted `otelcol-contrib.exe` against `collector.binary_sha256`. Each step refuses, and the
   product ships no binary of its own. The version is a pin, not the newest release.
2. **Create the ingest credential as a file**, not an environment value, with no trailing newline
   (`CONTRACT.md` explains why this host in particular must not carry it in the environment, and
   gives the two PowerShell commands that create and verify it).
3. **Set the five variables** the config reads: `LO_AGENT_STATE_DIR`, `LO_LOG_GLOB`,
   `LO_HOST_NAME`, `LO_RESOURCE_ID`, `LO_INGEST_URL`. `LO_RESOURCE_ID` is the host's inventory UUID,
   the same rule as every other source.
4. **Start it in the foreground first**, from the directory holding the config:

   ```powershell
   otelcol-contrib.exe validate --config file:collector.yaml
   otelcol-contrib.exe --config file:collector.yaml
   ```

   Expect it to print "Everything is ready" and stay up. A refusal naming
   `bind: Only one usage of each socket address` means something already holds `127.0.0.1:8888` —
   another collector on this host. Keep `service.telemetry.metrics.level: none`, which the shipped
   config sets, and fix the other agent's port instead.
5. **Then install it as a service**, with Windows' own `New-Service` — this repository ships no
   installer, and that is a verified fact about the pinned binary, not an omission
   (`CONTRACT.md` "Install and service"). The service account is the decision worth reading before
   you type: `LocalSystem` (the default) reads every file on the host.
6. **Security channel — optional, and off unless you ask.** `collector.yaml` reads no Windows Event
   Log channel. Adding `--config file:collector-security.yaml` as a second config location merges in
   one narrow query over six Security event ids. It needs the **"Manage auditing and security log"**
   right (`SeSecurityPrivilege`) for the account the service runs as, and without it the *whole*
   agent refuses to start with `failed to open local subscription ... Access is denied.` Run the
   two pre-flight commands in `CONTRACT.md` as that account first. An event collected this way is
   **stored, not detected**: the Sigma compiler here accepts one logsource
   (`linux`/`process_creation`) without an explicit Windows mapping.
7. **Check it natively**, from a checkout on that host, pointing the script at the executable you
   verified in step 1:

   ```powershell
   .venv\Scripts\python -B scripts\check_windows_agent.py --executable C:\local-observe\agent\otelcol-contrib.exe --with-security
   ```

   It runs the collector in a private directory against a loopback receiver: pin and hash, one
   synthetic log record, one CPU series per core, queue recovery across a kill, and with
   `--with-security` the merged config plus what the host says when the Security channel is not
   readable. It never touches an installed service. Its output and the dated results are in
   [`conformance.md`](../components/data/agent-windows/conformance.md).

**Not installable from this section, honestly:** the `New-Service` recipe has never been executed by
this repository's evidence (no service was created on any host, so the account/privilege question in
step 6 stays open), no event has ever travelled the Security pipeline, and no native
upgrade/restore/cold-state restore has been run. Each is named `not-run` in `conformance.md` rather
than implied by the steps above.

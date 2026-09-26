# Full-stack example

This Compose project combines telemetry storage and collection with resource
inventory, incident handling, detection workers, job services and Homepage.
The platform API and its operational interface share one service. AI, MCP and
chat remain separate opt-ins described below.

Use the [installation guide](../../docs/INSTALLATION.md) for prerequisites and
the smaller telemetry-only example. Begin with [account setup](../../docs/OPERATOR-SETUP.md)
for interactive access; native-registration exceptions are named in its handoff.

Status: **experimental reference composition**. Static checks cover includes,
required variables and loopback publications. [Current status](../../STATUS.md)
links the dated source and selected staging acceptance; those results do not
certify this entire composition or every optional integration. Render your exact
configuration, verify credentials and complete the selected components' checks
before relying on the installation.

"Full" is the default composition below, not every optional component.
`components/data/agent-windows/` ships
no Compose model **by design**: the Windows agent is installed natively on the observed Windows
host (`docs/INSTALLATION.md` §7) and pinned by `components/data/agent-windows/versions.json`, so it
is not in this project and nothing is owed.

## What starts, and where it is reachable

Component paths below are under `components/`.

| Component | Service | Published on the host |
| :-- | :-- | :-- |
| `data/store-signoz/` | `zookeeper-1`, `clickhouse`, `signoz` + two one-shots | SigNoz UI `127.0.0.1:18091` |
| `data/front-door/` | `lo-front-door` | OTLP gRPC `18092`, OTLP HTTP `18093`, health `18094` |
| `data/agent-linux/` | `agent-linux` | nothing — it pushes to the front door |
| `knowledge/inventory/` | `inventory` | reader API `127.0.0.1:18095` |
| `control/platform/` **merged with** `control/operator/` | `platform` | role API **and** operator UI `127.0.0.1:18096` |
| `control/sigma/` | `sigma` | nothing — queries the store, posts to the platform |
| `control/anomaly/` | `anomaly` | nothing — the same shape: two outbound connections, no server, so no `LO_*_PORT` line exists for it |
| `control/dagu/` | `dagu` | `127.0.0.1:18084` (`LO_DAGU_PORT`) |
| `control/job-observe/` | `healthchecks` | console and scrape endpoint `127.0.0.1:18099` (`LO_HEALTHCHECKS_PORT`) |
| `control/homepage/` | `homepage` | portal page `127.0.0.1:18097` (`LO_HOMEPAGE_PORT`) |
| `control/synthetics/` | `gatus`, `detector` | nothing — the detector polls the engine over this project's network, and the engine's status page is deliberately not published |
| `control/ai/` | **not in this composition** — see step 8 | no host port, including when you opt in |
| `control/mcp/` | **not in this composition** — see step 9 | when opted in, `127.0.0.1:18100` (`LO_MCP_PORT`): loopback only, and published at all because an MCP client is a process on another machine, not a container on this network |
| `control/chat/` | **not in this composition** — see step 10 | nothing to publish today: the intended loopback line sits commented in the manifest with the two-file widening it needs (`components/control/chat/CONTRACT.md` section 3) |

Ports are loopback-only and differ from the demo's, so both examples can run on one host. Nothing
listens on `0.0.0.0`. Reach any of this from another machine through a verified SSH tunnel to the
Docker host — do not widen a publication to make browsing easier.

## 1. Render before starting

On a Linux/amd64 Docker host with Compose V2 (`include` needs 2.23.1 or newer; the merge inside a
`path:` list is the part to confirm your version supports):

```sh
cp examples/full/.env.example /approved/private/full.env   # then fill it in; keep it 0600
docker compose --env-file /approved/private/full.env \
  --project-name local-observe-full -f examples/full/compose.yaml config > /tmp/full.rendered.yaml
grep -n 'operator:app_factory' /tmp/full.rendered.yaml
grep -c 'users.d/lo-query.xml' /tmp/full.rendered.yaml
```

`config` fails, naming the variable, if any value is still empty — that is the intended failure.
The first `grep` must match: it proves the operator override was merged rather than dropped as a name
conflict. If your Compose rejects the `path:` list, or the grep finds nothing, merge the override on
the command line instead (`-f examples/full/compose.yaml -f components/control/operator/compose.yaml`)
and re-check. The second `grep` must print `1`: it proves the *store* entry merged its second file
(`components/data/store-signoz/clickhouse-users.d/compose.yaml`), which is what gives this stack its
read-only ClickHouse query user. `config` prints resolved manifests: keep the output out of chat and
evidence, since it contains your tokens.

## 2. Build the first-party images

Follow [`docs/BUILD.md`](../../docs/BUILD.md) from the repository root on that host. Two of the three
are needed by this example as it ships; the third (`components/control/mcp/Dockerfile`) runs the
optional MCP surface and is built only if you do step 9:

```sh
docker build -f components/knowledge/inventory/Dockerfile \
  --build-arg LO_SOURCE_REVISION="$(git rev-parse HEAD)" -t local-observe-inventory:dev .
docker build -f components/control/platform/Dockerfile \
  --build-arg LO_SOURCE_REVISION="$(git rev-parse HEAD)" -t local-observe-platform:dev .
docker image inspect local-observe-inventory:dev --format '{{.Id}}'
docker image inspect local-observe-platform:dev --format '{{.Id}}'
# optional, step 9 only:
docker build -f components/control/mcp/Dockerfile \
  --build-arg LO_SOURCE_REVISION="$(git rev-parse HEAD)" -t local-observe-mcp:dev .
docker image inspect local-observe-mcp:dev --format '{{.Id}}'
```

Put each printed image ID in `LO_INVENTORY_IMAGE` and `LO_PLATFORM_IMAGE` (and `LO_MCP_IMAGE` if you
built the third). All three manifests set
`pull_policy: never`, so an ID that the daemon does not already have is a hard failure, not a pull.
The other six image variables are third-party: resolve their `repository@sha256:` digests yourself
for `linux/amd64` (`components/data/store-signoz/image-lock.json` records a known-good set) and
record what you chose. Never substitute a tag.

## 3. Declare the inventory and build the snapshot

The example ships `examples/full/inventory/declared.yaml` with generic names (`host-01`) and
placeholder UUIDs. Copy it to your deployment tree and give it a host id you generated:

```sh
mkdir -p -m 755 /approved/deploy/full/inventory /approved/deploy/full/index \
                  /approved/deploy/full/config /approved/deploy/full/private
cp examples/full/inventory/declared.yaml /approved/deploy/full/inventory/declared.yaml
uuid=$(python3 -c "import uuid; print(uuid.uuid4())")
sed -i "s/a2bb9adb-a78a-429c-b13c-d4e11dec9510/$uuid/g" /approved/deploy/full/inventory/declared.yaml
lo-inventory validate /approved/deploy/full/inventory/declared.yaml
lo-inventory build /approved/deploy/full/inventory/declared.yaml \
  --output /approved/deploy/full/index/inventory.db --revision "$(git rev-parse HEAD)"
```

`lo-inventory` is the console script installed by `pip install -e .`; from a plain checkout run
`python3 -B -m local_observe.inventory.cli` instead. The built snapshot goes in its own directory:
that directory is what the containers mount read-only.

Set `LO_RESOURCE_ID` in the environment file to `$uuid` — the same value, not a second one. The
agent stamps telemetry with it and the Sigma runner looks it up in the index; two different UUIDs
mean the runner reports `Undeclared resource` and never posts an event.
`LO_INVENTORY_SNAPSHOT_DIR` and `LO_PLATFORM_INDEX_DIR` are both `/approved/deploy/full/index`:
one directory holding `inventory.db`, read by three containers (the reader, the platform, the
Sigma runner). Never point two of them at two copies of the snapshot.

## 4. Write the credentials — the role file, then every single-value file

For a new installation, use [operator setup](../../docs/OPERATOR-SETUP.md) to
choose a username/password once and generate independent initial accounts plus
machine credentials. Its handoff identifies native-registration exceptions.
The manual role-file format below remains useful for existing deployments.

No credential in this example is an environment value. Each one is a file the manifests mount into
its container, because an env value is readable through `docker inspect` and
`/proc/<pid>/environ` of the process that holds it. The variables in `.env.example` are therefore
paths, and the files they name are the only place the values exist.

The platform reads a JSON **file**, mounted as a secret; it refuses to start on a short or
duplicated token, or on an unknown role. Roles are `reader`, `producer`, `proposer`, `human`,
`executor`, `summary`, and each entry is `{identity, role, token}` with the token at least 24
characters:

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # once per row
```

```json
[
  {"identity": "operator-ui", "role": "reader", "token": "<generated>"},
  {"identity": "sigma-example", "role": "producer", "token": "<generated>"},
  {"identity": "inventory-proposer", "role": "proposer", "token": "<generated>"},
  {"identity": "operator", "role": "human", "token": "<generated>"},
  {"identity": "runner", "role": "executor", "token": "<generated>"},
  {"identity": "summary", "role": "summary", "token": "<generated>"}
]
```

`producer` is the only role that may post events, and this example has **three** rows with that role:
`sigma-example` for the runner, `anomaly-example` for the seasonal producer
and a separate synthetics detector row — the last two are staged in step 5.
What each identity must equal: the sigma row's `identity` is `LO_SIGMA_SOURCE`, the anomaly row's is
`LO_ANOMALY_SOURCE`, and the detector's is the `source:` line of the rule documents in
`LO_DETECTION_RULE_DIR` — that producer has **no** `LO_*_SOURCE` variable, so its identity is written in
a rule file and not in this example's environment (step 5 names the shipped rule's value). Each row's
token goes into its own file, because one row authenticates
exactly one identity — the same file under two services is one producer, whichever name the other one
stamps. So `LO_PRODUCER_TOKEN_FILE` holds the **sigma** row's token (one more file, one more copy of
one secret: the runner cannot read the credentials JSON itself, since it is scoped to exactly the one
role it may use) and `LO_SIGMA_SOURCE` must equal that row's `identity`.
Keep `human` for a person: it is the role that approves actions, and an agent or a runner must not
hold it. Save as `/approved/deploy/full/private/platform-credentials.json` and set
`LO_PLATFORM_CREDENTIALS_FILE` to that path.

The containers run as uid/gid 65532 and read their inputs through bind mounts and one secret file,
so every file the containers mount — the credentials file, the action policy, the compiled rule,
everything inside the snapshot directory — must be readable by that uid. A `0600` file owned by your
login is unreadable inside the container, and it surfaces as a startup or healthcheck failure:

```sh
install -m 640 -o 65532 -g 65532 /tmp/platform-credentials.json \
  /approved/deploy/full/private/platform-credentials.json
```

The five remaining credentials are single values in single files, plus a sixth that is a copy of a row
you already wrote (`homepage-overview-token` below, and `producer-token` above for the same reason;
step 5 writes a seventh copy the same way, for the anomaly producer, and an eighth for the synthetics
detector).
`printf`, never `echo`: the
OpenTelemetry collectors read the file's bytes verbatim, so a trailing newline is sent inside the
`Authorization` header and the receiver refuses the request — a failure that looks like a bad token.
`umask 077` only fixes files you create afterwards, so apply it to the directory too (Docker binds
the host file into `/run/secrets/` as-is, which is why ownership matters again):

```sh
mkdir -p -m 700 /approved/deploy/full/private
for name in ingest-token store-token inventory-token producer-token clickhouse-password; do
  umask 077; printf '%s' "$(openssl rand -hex 32)" > "/approved/deploy/full/private/$name"
done
# The portal's credential is the `summary` row of the credentials file, not a new secret — the
# platform authenticates the portal against the list it already has, and a freshly generated value
# would simply be a token nobody accepts:
python3 - <<'PY'
import json
rows = json.load(open('/approved/deploy/full/private/platform-credentials.json'))
print(next(row['token'] for row in rows if row['role'] == 'summary'))
PY
# ... write that value over homepage-overview-token with printf (no trailing newline: Homepage
# substitutes the file's bytes into an Authorization header). It is the narrowest credential in this
# stack — the platform restricts `summary` to /v1/me and /v1/overview — and the only one a browser-
# facing service holds.
# ClickHouse cannot read a bare one-value file as a user password; it wants an `incl` substitution
# file. Derive it from the file above so the two copies of the secret cannot drift, and keep it in a
# heredoc so the value never appears in `ps` output the way a `sed 's/X/password/'` would put it.
python3 - <<'PY'
from pathlib import Path
# removesuffix, not strip: local_observe/credentials.py._read_file removes exactly one trailing
# newline and nothing else, so this file must agree with it byte for byte or the substitution holds
# a password the runner never presents.
value = Path('/approved/deploy/full/private/clickhouse-password').read_text().removesuffix('\n')
Path('/approved/deploy/full/private/clickhouse-query-credentials.xml').write_text(
    f'<clickhouse><lo_query_password>{value}</lo_query_password></clickhouse>\n')
PY
# That file holds a credential in a new form, so it needs the same chmod 0444 as the rest below
# (ClickHouse reads it as its own user). Values from `openssl rand -hex 32` are hex only; a password
# containing & or < must be XML-escaped here or the server misparses the substitution.
# The Sigma producer token is one row of the credentials file, not a sixth secret — and now that the
# file carries three `producer` rows, select it by identity, never by role, or the loop below can copy
# the anomaly or the detector row into the runner's file and quietly produce the intake refusal step 5
# warns about (HTTP 400, error `not_authorised` — not a 401):
python3 - <<'PY'
import json
rows = json.load(open('/approved/deploy/full/private/platform-credentials.json'))
print(next(row['token'] for row in rows if row['identity'] == 'sigma-example'))
PY
# ... write that value over producer-token with printf, then chmod 0444 every file Docker mounts,
# since the containers run as 65532 and cannot read a 0600 file owned by your login.
```

`LO_INGEST_TOKEN_FILE` is read by two services (the front door that checks it, the Linux agent that
presents it) from two differently named secrets mounted from the one host file — one project cannot
declare the same secret name twice, so the agent mounts `agent-ingest-token`. Dagu is the odd one
out: its password is a setting inside a config file rather than a bare value, so
`LO_DAGU_CONFIG_FILE` names a rendered fragment:

```sh
umask 077; printf 'auth:\n  basic:\n    password: "%s"\n' "$(openssl rand -hex 32)" \
  > /approved/deploy/full/private/dagu-config.yaml
chmod 0444 /approved/deploy/full/private/dagu-config.yaml
```

## 5. Stage the action policy and the optional inputs

```sh
install -m 640 -o 65532 -g 65532 examples/platform/actions.json /approved/deploy/full/config/actions.json
```

`LO_PLATFORM_POLICY_DIR` is `/approved/deploy/full/config`; the platform opens
`/config/actions.json` from it, so the filename is not free. An empty policy means no operation is
approvable — the platform still serves reads and intake.

The inputs below matter only if you want those services to do work, and each variable has to be
filled either way because the manifests require it. Dagu's job-definition
directory must already exist; its bind does not create that directory for you.

* **Sigma** — copy one compiled artifact out of the checkout (for example
  `examples/sigma/compiled/process-marker.json`, produced by the pinned compiler described in
  `components/control/sigma/CONTRACT.md`). The **read-only** query user it authenticates as is no
  longer something you have to invent: this example's `compose.yaml` merges
  `components/data/store-signoz/clickhouse-users.d/lo-query.xml` into the store, and that fragment
  creates `lo-query` with `readonly=1`, `allow_ddl=0` and `SELECT` on the three signal databases and
  nothing else. You still have to write its credential (step 4: two files, one value). Prove the
  privileges rather than trusting them with the commands in
  [`clickhouse-users.d/conformance.md`](../../components/data/store-signoz/clickhouse-users.d/conformance.md),
  which is also where the two unanswered questions about that user are recorded. The store's `default`
  user remains passwordless on the project network — SigNoz itself uses it — so the boundary this
  buys is around the runner's credential, not around the whole network.
* **Dagu** — `LO_DAGU_DAGS_DIR` is the directory of job definitions the runner may execute, and it is
  a path in your deployment. Create the directory and put only
  reviewed job files in it (Dagu runs the shell commands a DAG names):

  ```sh
  mkdir -p -m 755 /approved/deploy/full/dags
  install -m 644 examples/jobs/inspect-synthetic.yaml /approved/deploy/full/dags/
  ```

  The bind is read-only and `create_host_path: false`, so the directory must exist (an empty one is
  fine: a runner with no work is a stated state, not a failure) and the UI cannot write a new DAG into
  it. Dagu reads it as uid 1000, so keep it world-readable. The UI's host port is `LO_DAGU_PORT` now,
  at 18084 as before.
* **Healthchecks (job deadlines)** — nothing to stage on the host except the one credential step 4
  writes (`LO_HEALTHCHECKS_SECRET_FILE`). Two things are true about this service until you act on it,
  and both are stated so nobody mistakes them for a failure: **the console has no account** (the
  component ships no admin password, on purpose — `CONTRACT.md` §5 says why) and **no check exists**, so
  nothing is being watched. Section 6 ends with the three commands that change both. A job on another
  host cannot check in over this publication at all; that is the loopback rule, not a missing setting
  (`components/control/job-observe/CONTRACT.md` §7).
* **The operator portal's config** — unlike the bullets above, `LO_HOMEPAGE_CONFIG_DIR` is required by
  the manifest, and this repository ships no config to put in it: `local_observe/platform/homepage.py`
  renders the layout, and the link lists inside it are yours (decision deployment separation — the product owns the
  shape, the overlay owns the destinations, overlay compatibility). Empty lists are a valid state: the Overview tab
  still reports real numbers and the other two tabs hold nothing.

  ```sh
  mkdir -p -m 755 /approved/deploy/full/portal-config
  python3 - <<'PY'
  import yaml
  from local_observe.platform.homepage import configuration
  # dashboards/consoles are the operator's links: name, href, icon. [] is honest, not a placeholder.
  docs = configuration('http://127.0.0.1:18096', 'http://platform:8002/v1/overview', dashboards=[], consoles=[])
  for name, value in docs.items():
      open('/approved/deploy/full/portal-config/' + name, 'w').write(yaml.safe_dump(value, sort_keys=False))
  PY
  install -m 644 local_observe/platform/static/homepage.css /approved/deploy/full/portal-config/custom.css
  : > /approved/deploy/full/portal-config/custom.js && chmod 644 /approved/deploy/full/portal-config/custom.js
  ```

  Three things to get right, all of them failures that look like something else:
  *the first URL is the operator UI's address as a browser reaches it* (`http://127.0.0.1:18096` here,
  the TLS edge's address if you put one in front) because the tiles link there; *the second is
  `http://platform:8002/v1/overview`* because Homepage's own server — not your browser — fetches it,
  over the project network. `LO_HOMEPAGE_BOOTSTRAP` is the deployed copy of
  `scripts/homepage_start.cjs`, which is what makes the mounted config render at all
  (`components/control/homepage/CONTRACT.md`, "Readiness"). And `LO_HOMEPAGE_ALLOWED_HOSTS` must name
  the host:port you will type, or every browse is refused.

* **LAN synthetics (Gatus plus the adapter)** — four host artefacts, and two couplings whose mismatch
  is the usual cause of a component that "does nothing": three values in two files have to agree for
  the engine to answer (lines 1 and 2 below), and the platform credential has to name the identity the
  rule document names (lines 3 and 4):

  ```sh
  mkdir -p -m 755 /approved/deploy/full/rules
  install -m 644 examples/platform/availability.yaml /approved/deploy/full/rules/availability.yaml
  mkdir -p -m 700 /approved/deploy/full/gatus
  install -m 600 components/control/synthetics/config.yaml /approved/deploy/full/gatus/config.yaml
  ```

  1. **Render the engine's config.** `LO_GATUS_CONFIG` is your copy of
     `components/control/synthetics/config.yaml`, and two lines in it are marked `RENDER-ME`: the
     basic-auth username and the bcrypt hash of a password you generate now. Left unrendered the engine
     does not boot at all — it panics while base64-decoding the hash field, so the failure is
     fail-closed and loud rather than an open API — which makes this a correctness step, not a security
     one, and it is the step that decides whether the component does anything. The hash field wants
     **URL-safe** base64 (`-_`, padded); the standard alphabet panics the same boot. The generator, and
     the reason the detector's own file is standard base64 instead, is `CONTRACT.md` ("Credential").
  2. **Write the credential that matches it.** `LO_GATUS_TOKEN_FILE` is
     base64(`"<user>:<password>"`), *not* a bearer token: at the pinned release the status route accepts
     only HTTP Basic (or OIDC), and its middleware refuses an `Authorization` header that does not begin
     `basic `. Same username as line 1, and the password whose bcrypt hash line 1 holds.

     ```sh
     user=lo-detector; pass=$(openssl rand -hex 24)
     umask 077; printf '%s' "$(printf '%s:%s' "$user" "$pass" | base64 -w0)" \
       > /approved/deploy/full/private/gatus-token
     chmod 0444 /approved/deploy/full/private/gatus-token        # Docker mounts the host mode
     printf '%s:%s' "$user" "$pass"          # keep both for the check below; never commit them
     ```
  3. **One rule per target, and the rule's `resource_id` must be declared** (step 3's UUID, or
     `evaluate()` refuses the tick). The detector reads `/rules/availability.yaml`, so that filename is
     not free, and one process evaluates one rule: a second monitored service is a second `detector` in
     an overlay, not a second line here. Keep the shipped `max_age_seconds` default (120) — the stage
     example's `30` was authored for a 2 s probe and flaps against this product's 30 s interval.
  4. **The detector's producer row — the third `producer` row in this example.** The file you installed
     at line 3 is not only a rule: its `source:` line *is* the identity this container posts as
     (`detection_worker.tick()` sends `source=rule['source']`; there is no `LO_DETECTOR_SOURCE` to set),
     and `local_observe/platform/state.py` refuses an event whose `source` is not the identity the
     request authenticated as. So `platform-credentials.json` gains a third `producer` row — its own
     minted token, not a copy — and `LO_DETECTOR_PRODUCER_TOKEN_FILE` names that row's file:

     ```sh
     # step 4's platform-credentials.json gains a THIRD producer row, matching line 3's `source:`:
     #   {"identity": "stage-detector", "role": "producer", "token": "<24+ chars, not a copy>"}
     # (the example rule installed above reads `source: stage-detector`, so an unedited copy means that
     #  name; rename the rule's `source` and you rename this row, then rewrite the file from the new row)
     python3 - <<'PY'
     import json
     rows = json.load(open('/approved/deploy/full/private/platform-credentials.json'))
     print(next(row['token'] for row in rows if row['identity'] == 'stage-detector'))
     PY
     # ... write that value over detector-producer-token with printf (no trailing newline), chmod 0444 it
     # with the rest, and set LO_DETECTOR_PRODUCER_TOKEN_FILE to it.
     ```

  After `up`, one command decides whether the wiring is real. Neither service publishes a port, so it
  runs **inside** the project network by way of the service that already lives there — and the engine
  addresses an endpoint by its **derived** key (`group` + `_` + sanitised `name`, so `lo`/`platform-http`
  is `lo_platform-http`), which is why you read the answer from the engine rather than guessing at it:

  ```sh
  docker compose --env-file /approved/private/full.env --project-name local-observe-full \
    exec detector python - <<'PY'
  import os, urllib.error, urllib.request
  url, token = os.environ['LO_GATUS_URL'], open(os.environ['LO_GATUS_TOKEN_FILE']).read().strip()
  def code(headers):
      try:
          return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=5).status
      except urllib.error.HTTPError as exc:
          return exc.code
  print('with credential:   ', code({'Authorization': 'Basic ' + token}))
  print('without credential:', code({}))
  PY
  ```

  Pass is `200` then `401`. `200` on the second line means the engine has no `security:` block and will
  answer anyone on this network, which is the state the platform stage runs in and says so in
  `examples/platform/gatus.yaml`; `401` on the first means the three values in step 1 and step 2 above
  do not agree. The rest of the acceptance scenario — the injected failure, the recovery, the absent
  engine — is [`components/control/synthetics/conformance.md`](../../components/control/synthetics/conformance.md),
  including the fact that none of it has been run from this manifest. Its `CONTRACT.md` states what was
  verified against the pinned release and the one claim that stays UNVERIFIED because no request has
  ever been sent: that this credential authenticates.

* **The anomaly producer** — one host file, one more row in the credentials file, and one volume
  prepared in advance:

  ```sh
  install -m 644 /your/reviewed/anomaly.json /approved/deploy/full/private/anomaly.json
  # step 4's platform-credentials.json gains a SECOND producer row, with its own generated token:
  #   {"identity": "anomaly-example", "role": "producer", "token": "<24+ chars, not a copy>"}
  python3 - <<'PY'
  import json
  rows = json.load(open('/approved/deploy/full/private/platform-credentials.json'))
  print(next(row['token'] for row in rows if row['identity'] == 'anomaly-example'))
  PY
  # ... write that value over anomaly-producer-token with printf (no trailing newline), chmod 0444 it
  # with the rest, and set LO_ANOMALY_PRODUCER_TOKEN_FILE to it.
  docker volume create local-observe-full_anomaly-state     # then CONTRACT.md's chown/chmod/stat
  ```

  `LO_ANOMALY_CONFIG_FILE` is your reviewed series document — up to 16 series, each naming its own SQL
  and its `sql_sha256`, and a malformed or out-of-range document is a refusal at load, never a clamp
  (the knobs and what turning each down costs are in
  [`local_observe/platform/README.md`](../../local_observe/platform/README.md), "Seasonal anomaly
  baselines"). The volume is the step that decides whether the container starts: an image built from
  this tree after 2026-09-10 creates `/state` at mode `0700` owned by uid 65532 in its Dockerfile, but
  **no such image has been built here**, so the recipe an operator follows today is
  [`components/control/anomaly/CONTRACT.md`](../../components/control/anomaly/CONTRACT.md) — create the
  volume before `up`, run one throwaway root container to `chown 65532:65532` and `chmod 700` it, and
  let the `stat` line print exactly `700 65532:65532` before starting anything. None of those four
  commands has ever been run from this repository, and the image `versions.json` pins predates the
  producer module entirely: an operator who starts this service on that image gets `No module named
  local_observe.platform.anomaly` and exits, which step 2's rebuild is what fixes.
  The second credential row is the step that anomaly component shipped without, and it is a refusal and not a
  warning: `LO_ANOMALY_SOURCE` is the `source` on every event this service posts, and
  `local_observe/platform/state.py` rejects an event whose `source` is not the identity its token
  authenticated as — `Source identity differs from authenticated producer`. The manifest used to mount
  the Sigma runner's `producer-token` file here, which is one credential asked to be two identities: the
  container started, judged every series, and had every POST refused — the same window staying owed
  forever, and the healthcheck still green, because a refused attempt rewrites the cursor file on its
  way out even though it acknowledges nothing (`anomaly.py:764-785` and `_deliver`; read from the
  source, never observed here). The dedicated anomaly credential settled it on 2026-09-10: the manifest mounts its own
  `LO_ANOMALY_PRODUCER_TOKEN_FILE`, which is the one new secret file this component asks an operator to
  stage. Give the row its own
  generated token rather than a copy of the sigma one: the store dedups on `(source, source_event_id)`,
  so two producers sharing one identity have their findings folded into one stream, which loses a
  verdict. None of this has been executed: no image built and no container started from this repository.

* **Webhook delivery (optional, off by default)** — `LO_NOTIFY_TOKEN_FILE` is not a variable you
  set: the manifest fixes it at `/config/notify-token`, which is this same `config` directory seen
  from inside the container. Only when you move to `LO_NOTIFICATION_MODE=live` with a
  `LO_NOTIFY_URL`, write the channel's bearer token there:
  ```sh
  umask 077; printf '%s' "$token" > /approved/deploy/full/config/notify-token
  chmod 0444 /approved/deploy/full/config/notify-token
  ```
  In `recording` (the shipped default) nothing reads the file, so an install with no channel boots
  with no such file; in `live` a configured URL and no file stops the boot instead of serving a
  channel that cannot send.
* **More than one channel (optional)** — `LO_NOTIFY_CHANNELS` is the container path of one JSON
  document listing every channel in your **preference order**: the first channel whose budget admits a
  delivery carries it, so a latched channel stops sending without stopping the alerting. The manifest
  adds no mount for it — stage the document in this same `config` directory and write every path it
  names (`token_file` for a webhook entry, `config` for a Telegram one) as a path under `/config`,
  because that read-only mount is the only route a channel credential has into the container; no token
  is ever an environment value here:

  ```sh
  cat > /approved/deploy/full/config/channels.json <<'EOF'
  [{"channel": "primary", "type": "telegram", "config": "/config/telegram.json"},
   {"channel": "oncall", "type": "webhook", "url": "https://hook.example/receive",
    "token_file": "/config/oncall-token"}]
  EOF
  chmod 0444 /approved/deploy/full/config/channels.json
  ```

  It is opened in `live` only, so a recording install never reads it or the credentials beside it;
  naming a document you never staged stops the boot in `live` rather than serving a channel that
  cannot send. Claiming `primary` here **and** in `LO_TELEGRAM_CONFIG`/`LO_NOTIFY_URL` is a boot
  failure (`Notification channel configured twice`), never a precedence rule, and no entry in the
  document may pick a `delivery_mode` — that stays one decision for the service.

* **Adding a channel (the five ported transports)** — a new channel is one more entry in that same
  document plus one more file in that same `config` directory; nothing is added to this `.env` file, to
  the manifest or to the container's environment, which is why `check_credential_files` has no new
  exception to grant and why a wrong path is a boot refusal that names the channel and the key rather
  than a send that quietly never happened. `type` is one of `telegram`, `webhook`, `ntfy`, `slack`,
  `matrix`, `pagerduty` or `email`; each names its own credential file (`token_file`, `url_file`,
  `key_file`, `password_file`/`recipients_file`, or `config` for Telegram) as a path under `/config`:

  ```sh
  umask 077
  printf '%s' "$matrix_token"  > /approved/deploy/full/config/room-token
  printf '%s\n%s\n' "oncall@example.org" "second@example.org" > /approved/deploy/full/config/recipients
  printf '%s' "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXXXXXXXXXX" \
    > /approved/deploy/full/config/slack-url
  chmod 0444 /approved/deploy/full/config/{room-token,recipients,slack-url}
  ```

  Three choices are deliberate and one of them surprises an operator who expects a channel to "just
  send": **Slack's URL is the credential**, so it lives in `url_file` and never in the document — an
  incoming-webhook URL carries its secret in its path, and a document field would put a secret where
  configuration is copied. **An email channel will not authenticate over a plain connection**: naming a
  `password_file` without STARTTLS is refused at boot, because that password would otherwise cross
  whatever sits between here and the relay. And **PagerDuty's routing key is a body field read from
  `key_file`**, not a header, so it appears in no proxy's header log. The delivery id goes on the wire
  for every one of them (`Idempotency-Key`; Matrix also puts it in the transaction path segment,
  PagerDuty in `dedup_key`, email in `Message-ID`), so a re-delivery after a crash or an expired lease
  is one alert at the receiving end and not two. ITSM sync is not one of these types: it is excluded by
  itop and `docs/COMPONENTS.md` §3.

  One ordering caveat, because it is whoever writes this file who finds it: the platform's **own**
  channel — the one `LO_NOTIFICATION_POLICY` names, `primary` by default — is offered before anything
  in the document, and the registry compares its budget entry for entry, so an entry that leaves
  `policy` out while the service policy states non-default numbers is refused at boot
  (`Notification channel is registered with two budgets`). Write the service's own numbers into that
  entry's `policy` block (or leave both at the defaults); `primary` belongs on the channel you want
  tried first.

  The one display field this rail adds is `callback_base` inside `LO_DISPLAY_CONFIG`: a single HTTPS
  origin, with no credentials, query or fragment in it, that the Telegram alert names as where to send
  back its single-use approval code. Without it the message says nothing about approvals and everything
  else about the rail still works — the safe direction to be wrong, because an operator trusts whichever
  destination they are shown. A callback records an intent and completes nothing: the decision still
  needs a `human` credential at `/v1/actions/decision`, which is what the operator UI of step 7 does.

Finally create the log directory the agent tails (empty is fine) and point `LO_LOG_DIR` at it;
`LO_HOST_ROOT=/` is a broad host read — use a disposable Linux guest if that scope is wrong for
your host.

## 6. Start it and check the platform

```sh
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  -f examples/full/compose.yaml config          # again, now that every value is real
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  -f examples/full/compose.yaml up -d
docker compose --env-file /approved/private/full.env --project-name local-observe-full ps -a
```

The two `restart: 'no'` services (`init-clickhouse`, `signoz-telemetrystore-migrator`) are one-shots
and must exit 0; everything else must stay Up. Then read the status endpoint with the `reader`
token. Read it out of the host copy of the file — inside the container the same file sits at
`/run/secrets/platform-credentials`, and nothing here needs the token in an environment value:

```sh
reader=$(python3 - <<'PY'
import json
rows = json.load(open('/approved/deploy/full/private/platform-credentials.json'))
print(next(row['token'] for row in rows if row['role'] == 'reader'))
PY
)
curl -sS -H "Authorization: Bearer $reader" http://127.0.0.1:18096/v1/status
curl -sS http://127.0.0.1:18096/v1/status                     # no token: {"error":"authentication_required"}
curl -sS -H "Authorization: Bearer $reader" \
  http://127.0.0.1:18095/inventory/resources.json             # the inventory reader, different token
```

An unauthenticated request must be refused, not served. That is the check that the credentials are
actually in force, and it is the one line of this example that proves something about security
rather than about wiring.

### Healthchecks: an account, one check, and the ping that arms it

The container is healthy at this point, which means only that its database answers
(`fetchstatus.py` probes `/api/v3/status/`). The console for the rest of this section is
`http://127.0.0.1:18099/` — `LO_HEALTHCHECKS_PORT`, which this example moves off the manifest's 18097
default because that port is used by Homepage. Three steps make it a monitor:

```sh
# 1. The console account. This is upstream's own command, run against the running image.
docker compose --env-file /approved/private/full.env --project-name local-observe-full \
  run --rm healthchecks /opt/healthchecks/manage.py createsuperuser
# 2. In the console (Project Settings -> API Access) mint a read-only key for the scrape, and note
#    the project UUID from the browser's address bar. Then create one check per timer you depend on:
RW=…      # a read-write key, only for creating checks; delete it afterwards
curl -fsS -X POST -H "X-Api-Key: $RW" -H 'Content-Type: application/json' \
  -d '{"name":"backup-nightly","timeout":86400,"grace":3600}' \
  http://127.0.0.1:18099/api/v2/checks/
```

**Ping the returned `ping_url` once.** A check that has never been pinged stays `new`, exports
`hc_check_up 1`, and never alerts — Healthchecks has no deadline for a job that has not reported even
once (read in its own `Check.get_grace_start`/`going_down_after`, and recorded in the component's
`conformance.md` step 0). The arming ping is the job's first real check-in, so wire the timer before
you create the check rather than the other way round:

```sh
curl -fsS "$PING_URL"        # success; "$PING_URL/fail" reports a failure without waiting for the deadline
```

Give the independent witness the URL of its own check as a mounted file — the file holds the URL and
only its path goes in the environment, because the URL by itself marks the job up
(`printf '%s' "$PING_URL" > /approved/deploy/full/private/healthchecks-ping; chmod 0400 …`).
`local_observe/platform/deadman.py` refuses to start without it.

What this still does not do: nothing here scrapes `hc_check_up` into the store yet (the front door's
`metrics_path` is an open item in `DEPENDENCIES.md`), and no alert rule exists on either side. The
component is installed, not validated — its `conformance.md` says exactly which checks remain.

## 7. Open the operator UI

The UI is the same origin as the API: browse `http://127.0.0.1:18096/` **on the Docker host**, or
forward it first and keep the binding loopback:

```sh
ssh -N -L 18096:127.0.0.1:18096 <approved-operator>@<staging-host>
```

Paste a token into the field on the page; the header then shows the identity and role that token
maps to. A `reader` token shows every view — incidents, approvals, executions, the outbox, the
inventory, events and audit — and can change none of them; recording a decision needs the `human`
token, and claiming a job needs `executor`. The assets are served with `no-store` and a strict CSP,
and the script keeps the token in memory only, so a reload asks for it again.

## 8. Open the portal

The portal is a *viewer*: it renders the summary the platform produces and links to the UI above. It
holds one credential — the `summary` row, which the platform restricts to `/v1/me` and `/v1/overview`
and to nothing else — and it can change nothing.

```sh
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18097/     # 200 once the portal's own container healthcheck is green
docker compose --env-file /approved/private/full.env --project-name local-observe-full ps homepage
```

Browse `http://127.0.0.1:18097/` on the Docker host (or tunnel it, loopback at both ends, as in step 7)
and `HOMEPAGE_ALLOWED_HOSTS` must contain `127.0.0.1:18097`, or Homepage answers 403 to every request —
that refusal is the setting working, not a broken build. Three tabs: `Overview` with the platform's own
counts, `Observability` with your dashboard links, `Consoles` collapsed. The `Incidents and approvals`
tile links to the operator UI, where an approval is actually made.

Two things this step cannot prove from a Windows workstation, said plainly rather than left to be
discovered: this manifest has never been rendered by `docker compose config` or started, and the page
has never been looked at on a phone. What each clause of the portal's acceptance scenario needs is
written down in
[`components/control/homepage/conformance.md`](../../components/control/homepage/conformance.md),
including the viewport check that has no script yet.
## 8. Optional: the AI component, off by default

Nothing above needs a model. The `ai` component is deliberately **not** in the `include:` list, so this
bring-up renders, starts, pages, approves and records with no image pulled, no weights on disk and no
AI credential created — and the portal's Model tile reads `Disabled`, which is a real observation and
not a placeholder (its producer is `local_observe/platform/overview_worker.py`).

Opting in is one line and one block of variables, and the line goes in this file's `include:` list:

```yaml
  - ../../components/control/ai/compose.yaml
```

Then fill the commented `Optional: the AI component` block in `.env.example` (`LO_AI_IMAGE`,
`LO_AI_MODEL_DIR`, `LO_AI_MODEL_FILE`, `LO_AI_MODEL`, `LO_AI_CTX_SIZE`, `LO_AI_MEM_LIMIT`,
`LO_AI_API_KEY_FILE`, `LO_AI_CAPABILITY`, `LO_AI_POLICY`, and the optional `LO_AI_MODEL_FAST`,
`LO_AI_BUDGET`, `LO_AI_OUT_OF_LAN`, `LO_AI_CAPTURE`). Three of those are costs this repository cannot
pay for you, and none of them has a shipped default worth trusting:

- **an image digest** — `pull_policy: never`, so resolve the digest and pull it deliberately. The
  registry publishes a moving `server` tag and build tags, and nothing in the published tag list maps
  a build to a release: `components/control/ai/CONTRACT.md` says which parts of that are unverified.
- **the weights** — create the directory before `up` (the bind is read-only with
  `create_host_path: false`, so a missing directory stops the boot rather than mounting an empty one)
  and put the file where the serve reads it as uid 65532:
  ```sh
  mkdir -p -m 755 /approved/deploy/full/models
  install -m 644 /your/downloaded/model.gguf /approved/deploy/full/models/
  ```
- **a measured capability manifest** — copy `components/control/ai/capability.example.json`, which
  says `"unknown"` for every field, and leave it that way until you have measured. A consumer may not
  use a capability the manifest marks `unknown` or `false`, so an unmeasured manifest generates nothing
  and the tile reads `Degraded`. That is the component working as designed: the alternative is an
  explanation whose evidence was silently truncated because someone typed a context size off a model
  card. `CONTRACT.md` section 4 says how each of the eight fields gets measured.

Also copy `policy.example.json`: it refuses `restricted` outright and keeps every class inside the LAN,
so a remote endpoint sees nothing until you change one boolean on a class that already carries a label
and the `no_free_text` step (`docs/COMPONENTS.md` §5, "remote use gated" — the recipe for that clause is
in `components/control/ai/conformance.md`, and none of it has been run against a real endpoint).

Two properties hold with the component on and stay true with it off, which is the point of the row's
`If disabled` column: no module outside `local_observe/ai/` imports the client
(`tests/test_ai_component.py` walks the tree), and the suite passes with the package removed from the
import graph. Turning the component off is not a supported-but-degraded mode; it is the default mode.

## 9. Optional: the MCP tool surface, off by default

No service in this example declares an MCP reader, and `up -d` starts none. The packaged, pinned
component is `components/control/mcp/`: an image that carries the `mcp` extra the platform image
deliberately refuses to install, its own hash-locked lock, and a Compose manifest you add as one
`include:` entry. Supply one credential map staged where the process
can read it, plus the process — and "the process" now has two answers: the container, or the source-tree
form written at the end of this step. What has *not* changed is that the platform image cannot serve it:
importing `local_observe.platform.mcp` inside `${LO_PLATFORM_IMAGE}` still stops at a `ModuleNotFoundError`,
which is the loud refusal the code is written to give and not a bug to route around. Nothing here has
been built or started; `components/control/mcp/versions.json` records `image.identity: null`.

It is off unless you say otherwise, exactly as the AI component above is, and `up -d` proves nothing
about it. Two things turn it on: a credential map staged where the process can read it, and the
process.

Stage one row per agent in the directory `LO_PLATFORM_POLICY_DIR` already names (the one holding
`actions.json`, which the platform mounts read-only at `/config`), then name it by that **container**
path — the same shape `LO_NOTIFY_CHANNELS` uses, so the manifest gains no mount and no secret:

```sh
umask 077
python3 - <<'PY'
import json, secrets, pathlib
rows = [{'identity': 'reader-1', 'role': 'reader',
         'bearer_token': secrets.token_urlsafe(24),
         'platform_token': pathlib.Path('/approved/private/mcp-reader-token').read_text().strip()},
        {'identity': 'runner-1', 'role': 'proposer',
         'bearer_token': secrets.token_urlsafe(24),
         'platform_token': pathlib.Path('/approved/private/mcp-proposer-token').read_text().strip()}]
pathlib.Path('/approved/deploy/full/policy/mcp-identities.json').write_text(json.dumps(rows))
PY
```

Four keys per row and no fifth (`identity`, `role`, `bearer_token`, `platform_token`), 1 to 32 rows,
and a document the boot refuses rather than half-reads: a duplicated credential, a repeated identity,
a role outside `reader`/`proposer`/`executor`, or a token under 24 characters. `human`, `producer` and
`summary` are on the refused list on purpose — an MCP agent is not a person, does not sign
observations, and must not hold the portal's read of `/v1/overview`.

Both `platform_token` values are rows copied out of `LO_PLATFORM_CREDENTIALS_FILE`, not new secrets:
the platform authenticates every MCP request against the credential file it already has, so an agent's
reach is that row's role and nothing the MCP layer invents. The file is 0600 because it holds every
bearer credential the surface has; a map any local uid can read is a map any local uid can use. One
gap to know before relying on it: a `platform_token` that is well-formed but **not** in that credential
file is not caught at boot — the map is validated on its own — so that agent's first request answers
401. The component contract says so in as many words.

```sh
# in the env file, beside LO_PLATFORM_POLICY_DIR:
LO_MCP_IDENTITIES=/config/mcp-identities.json
python3 -B -m uvicorn local_observe.platform.mcp:app_factory --factory --host 127.0.0.1 --port 18000
```

That command is the source-tree form, and it binds `127.0.0.1` on a port nothing in this repository
publishes — the only way to reach it is from the machine that runs it. The container form is the one
that has a home: `components/control/mcp/compose.yaml` publishes `127.0.0.1:${LO_MCP_PORT:-18100}`
(loopback like every other publication here, and the reason `mcp` is named in
`scripts/check_foundation.py`'s `HOST_PUBLISHED_SERVICES` with an argument — an MCP client is a process on
another host, so for this service only, "internal" would mean unreachable). Anything beyond the Docker
host is the TLS-and-authentication edge the portal's contract documents as a recipe, and this example
ships no certificate.

To run it as part of this project rather than as a process on the host, add one include entry and fill
the commented MCP block in `.env.example`:

```sh
# examples/full/compose.yaml, appended to `include:`
#   - ../../components/control/mcp/compose.yaml

LO_MCP_IMAGE=$(docker image inspect local-observe-mcp:dev --format '{{.Id}}')   # step 2's third build
LO_MCP_PORT=18100
# optional, and it changes the advertised tool list when set: the analysis reader's credential, staged
# in the same read-only policy directory and named as a CONTAINER path
cp /approved/private/clickhouse-read-password /approved/deploy/full/policy/clickhouse-read-password
LO_MCP_READ_PASSWORD_PATH=/config/clickhouse-read-password   # with LO_CLICKHOUSE_URL already set above
```

Two properties worth knowing before you wire a client to it. The manifest deliberately **shares the
platform's `LO_PLATFORM_POLICY_DIR` bind**: the map you staged beside `actions.json` (step 9) is the file
the container reads,
so there is no second copy of a directory full of bearer tokens to drift on a rotation. And
`LO_MCP_INDEX_PATH` defaults to `/inventory/inventory.db` — the snapshot directory is mounted here anyway,
so the topology read is on unless you blank that variable, which is the difference between a surface that
offers eight tools and one that offers ten.

What each read needs follows from how it is reached, and it is worth naming before anyone wires a
container. `platform_status`, `platform_overview`, `records`, `inventory` and `evidence_window` are
requests to `LO_PLATFORM_URL` made with that agent's own platform token: the MCP process opens no
database, so the surface cannot read anything a reader token could not already read from the API, at the
same bound. `topology_neighbourhood` opens the inventory snapshot at `LO_INDEX_PATH`. `signal_series`
is the one read that needs something this example's platform container does not carry: the read-only
analysis endpoint and its credential (`LO_CLICKHOUSE_URL`, `LO_CLICKHOUSE_READ_USER`,
`LO_CLICKHOUSE_READ_PASSWORD_FILE`), the same trio `components/control/sigma` uses for its runner.
Given none of those, a tool is **absent from the surface** rather than present and answering
"unconfigured" — `local_observe/platform/query.py::open_reader` logs one line naming the variable and
returns `None`. `propose_action` and `execute_action` are POSTs to `LO_PLATFORM_URL` too, so the state
change stays the platform's and an MCP process never writes the platform's database.

If you do not use the map, a running deployment changes nothing. With `LO_MCP_IDENTITIES` blank or
unset and `LO_MCP_TOKEN_FILE` mounted, the same entry point serves v0.1's shape: one shared reader
token, the four read tools, no action pair. What it must not do is configure both — that is a boot
refusal naming the two variables, not a precedence rule. Setting `LO_MCP_TOKEN` as a value is refused
on sight, because an environment value is readable by anyone who can run `docker inspect`.

The steps above are bring-up wording, not evidence. Two recipes exist and neither has been run: the
surface's, in `components/control/platform/conformance.md` ("Agent tool surface and the private overlay
(chat integration)"), and the packaging's, in `components/control/mcp/conformance.md` (eleven runtime rows — build,
start, probe, list, refuse, budget, grep, tear down — every one of them `not-run`). This step is what
makes the first recipe runnable against an image instead of a source tree; it is not that recipe having
been run. What the suite proves is the surface in the MCP test tier, and the loud refusal in the base tier
where the extra is absent (`docs/testing-standards.md` says why the tiers are separate).

## 10. Optional: the chat surface, off by default

The chat component is a provisional integration with a manifest, an upstream pin
and lifecycle procedures. Runtime acceptance remains not-run. Read its
[contract](../../components/control/chat/CONTRACT.md) before enabling it.

Nothing above needs it: no example includes `components/control/chat/compose.yaml`, so this bring-up
boots with no chat image, no chat settings file and no chat credential. Opting in is one item added to
the **existing** `include:` list in this example's `compose.yaml` — never a second `include:` key,
because Compose keeps one and the store entry's two-path merge depends on it:

```yaml
  - ../../components/control/chat/compose.yaml
```

Then fill the commented `Optional: the chat surface` block in `.env.example` (`LO_CHAT_IMAGE`,
`LO_CHAT_MEM_LIMIT`, `LO_CHAT_SETTINGS_FILE`, and the optional `LO_CHAT_CPUS`,
`LO_CHAT_MAX_TOOL_CALLS`). What it costs, stated before the pull rather than after:

- **1.1 GB of download** — `compressed_size_bytes` in
  [`components/control/chat/versions.json`](../../components/control/chat/versions.json) is the exact
  figure (`1101725314`) read from the registry on 2026-09-09, and the uncompressed size is recorded as
  unknown because the registry does not report it. Upstream's disk figure for a working instance is 5 GB.
- **2 GB of RAM on a host that publishes 16 GB for `minimal`** — the hardware baseline, in a composition that already defines 17 services. That number
  is upstream's minimum for the container alone, not a measurement taken here, and `LO_CHAT_MEM_LIMIT`
  has no shipped default for exactly that reason.
- **a CPU instruction set** — `lscpu | grep -o avx2` **inside the guest that will run it**, before the
  first `up`. Without AVX2 the pinned build dies the moment its default vector database loads, and
  `restart: unless-stopped` makes that a crash loop.
- **one file that holds provider keys in plaintext** — `LO_CHAT_SETTINGS_FILE` is mounted where the
  pinned build's dotenv reads it, because the product's rule (a credential is a mounted file, never an
  environment value) has no `*_FILE` convention in this third-party image to hang off. Two consequences
  are named in CONTRACT.md sections 3 and 7 and neither is hidden: the build rewrites that file's
  content on a UI action, which a read-only mount refuses, and anything written into it persists on the
  host outside every retention rule this product enforces.

Two things this step does **not** do, on purpose:

* **It is not an approver.** The surface may read and may propose; the decision route
  (`POST /v1/actions/decision`) admits role `human` and the surface's credential is `proposer`, and
  `tests/test_chat_approval_separation.py` pins the refusals — including the one that matters most on
  a phone, that a spent approval code records an *intent* and leaves the action `pending`.
* **It configures no Telegram.** Not this product's (`LO_TELEGRAM_CONFIG` is a separate, existing
  optional rail) and not the surface's own connector, which stays unconfigured because
  `TelegramBotService.bootIfActive()` starts nothing without a bot token the operator must mint.
  integration validation's acceptance gate is operation *without* Telegram, and adopting a Telegram approval path by
  leaving one enabled would fail that gate quietly instead of loudly.

What it cannot do yet, and the honest reason. The seam is MCP, and the **tool** half of it landed: the
registry lives in `local_observe/platform/tools.py`, and a `proposer`-role row in the step 9 identity
map gives this surface `propose_action` plus the reads, with `execute_action` refusing before any
platform request and no tool at all able to cast the decision. What has not landed is the
**service**: the deployable half in `components/control/mcp/` is a manifest and documents only, no shipped image installs the
optional `mcp` extra (`components/control/platform/Dockerfile` says so), and nothing in this example
publishes 18000. So a chat container started here has no MCP endpoint inside the project network to
register — the only MCP process today is the hand-started one in step 9, reachable from the host, not
from that container — and `docker compose up` yields a surface that answers its own `/api/ping` and
lists no platform tools. Rows 6–8 of
[`components/control/chat/conformance.md`](../../components/control/chat/conformance.md) say
`blocked-on-MCP component` (deployable service, not the tool) rather than `not-run`, so a future reader cannot
mistake the gap for a skipped test.

## What this does and does not prove

`up -d` plus the `curl` lines above prove the model renders, the containers start, credentials are
required, and the UI is served. They do not prove conformance. The smoke script is not
hard-wired to the demo and can drive this project too:

```sh
python3 -B scripts/conformance_smoke.py --env-file /approved/private/full.env \
  --compose examples/full/compose.yaml --project local-observe-full
```

It reads the rendered model of whatever file you name, so before it injects anything it requires
every service that model declares to be present: `running`, and `healthy` wherever a healthcheck is
declared, and exit 0 for the two one-shots — waiting up to `--wait-seconds` (default 120) because the
Sigma runner's own `start_period` is 60 s and a single early reading would fail a stack that is merely
still booting. That wait includes the `anomaly` producer's cursor-staleness healthcheck, so
if you have not staged its config file, its second producer credential row and its prepared
volume this script times out on `anomaly` — that reading is missing staging, not a product defect,
and what is missing is named either by `docker compose config` (a variable nobody supplied) or by the
container's own refusal line (a cursor parent, an unreadable document). Then it does what it has always
done: refuses anonymous and wrong-token OTLP, accepts
the authenticated request, and reads one synthetic trace, metric and log back out of ClickHouse.
The default `--compose` is still `examples/demo/compose.yaml`, so every demo command recorded elsewhere
in this repository runs unchanged.

What it does **not** reach here: it talks to the front door with the ingest credential and to
ClickHouse as the store's own `default` user through `clickhouse-client`. It therefore says nothing
about the Sigma runner's read-only query path, the platform's role API or the Dagu engine — those are
per-component recipes in each component's `conformance.md`, including
[`clickhouse-users.d/conformance.md`](../../components/data/store-signoz/clickhouse-users.d/conformance.md)
for the query user. Recovery and upgrade are per-component in `backup.md` and `upgrade.md`. Rehearse
a restore in a *differently named* project with different ports and fresh volumes — never reattach
these volumes to an experiment.

Teardown keeps the data: `docker compose --project-name local-observe-full ... stop`. Use `down -v`
only when you have decided to destroy the volumes, and no unqualified `prune` anywhere.

Record the source revision, the image IDs, the resolved digests and the command results as evidence.
Keep secrets (tokens, the credentials file, the rendered manifest) out of the record.

# Windows agent (experimental)

OTel Contrib 0.159.0, tested as a separate foreground executable with synthetic log/state paths.
It collects bounded file inputs and host metrics, sets `resource_id` and `host.name`, and uses
persistent file checkpoints/export queues. Paths in file globs use forward slashes. CPU attributes
explicitly retain `cpu` and `state`. The core configuration opens no metrics listener, avoiding
conflicts with an already-installed agent (measured again 2026-09-08: a run that leaves
`service.telemetry.metrics` at its default binds `127.0.0.1:8888` for its internal Prometheus
reader and dies with `bind: Only one usage of each socket address` beside an agent already holding
it; the shipped `level: none` is what prevents that). It does not install or modify a Windows
service -- see [Install and service](#install-and-service).

## Pin

There is still no `compose.yaml`, and there will not be one: a Windows host is not a Compose target.
The five artefacts are `versions.json` plus this contract, `collector.yaml` (and
`collector-security.yaml`), `conformance.md`, `backup.md`, `upgrade.md`.

## Required overlay variables

`LO_AGENT_STATE_DIR`, `LO_LOG_GLOB`, `LO_HOST_NAME`, `LO_RESOURCE_ID`, `LO_INGEST_URL`. Use HTTPS
for remote ingestion and an ingest-only credential. Restrict state/config permissions to the agent
account. Do not collect user transcripts or unrelated folders implicitly; the Security channel is
below, and it is opt-in rather than implicit.

## Security channel (opt-in, off by default)

`collector.yaml` reads **no Windows Event Log channel**. The Security channel lives in
[`collector-security.yaml`](collector-security.yaml), which `collector.yaml` does not reference.
You select it by naming it as a second config location -- confmap merges the two, so the overlay
adds one receiver and one `logs/security` pipeline and changes nothing else:

```powershell
otelcol-contrib.exe --config file:collector.yaml --config file:collector-security.yaml
```

It reads six event ids from that one channel -- 4624 (successful logon), 4625 (failed logon), 4688
(process created), 1102 (audit log cleared), 4720 (user account created), 4732 (member added to a
security-enabled local group) -- through one XML `query`, with `start_at: end` (no history replay),
`raw: false` (structured body, not the XML string) and `storage: file_storage` so the bookmark
survives a restart. The receiver itself is **alpha for logs** at this pin (`versions.json →
windows_event_log.stability`), which is why this pipeline is opt-in and why its evidence in
`conformance.md` stops short of a claim. **Whether an event exists to read is a separate decision
from whether an agent may read it:** each of those ids appears only if the matching audit
subcategory is enabled on the host (`auditpol /get /category:'Account Logon'` etc.), and audit
policy is not this component's to
set. 4624 is the high-volume member; on a chatty host lower `max_reads`, raise `poll_interval`, or
delete that id from the query.

**What is off while the overlay is not selected.** The host sends metrics and the approved file
glob only. No Windows Event Log data of any kind reaches the store, so no Windows detection can
fire and the store raises no Security finding however long it runs -- the absence is not visible in
a dashboard, only in the fact that nothing arrives. Other hosts are unaffected.

**Collected is not detected.** The platform's Sigma compiler here accepts exactly one logsource --
`logsource: {product: linux, category: process_creation}` (`local_observe/platform/sigma_compile.py`)
-- so a Windows Security record that arrives today is stored and queryable and **cannot raise a
finding**. Mapping Windows event ids into that compiler is remediation item Sigma compiler; until both land,
the honest end state of this component's Security channel is *collected, not detected*. Do not
describe it as detection coverage in a combination table or a runbook.

## Privilege

Opening the Security channel needs the **"Manage auditing and security log"** user right, constant
`SeSecurityPrivilege` ([Microsoft: Manage auditing and security log](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/manage-auditing-and-security-log),
read 2026-09-08; that page also states the right lets its holder *view and clear* the Security log,
so a holder can erase the evidence trail this channel feeds -- an account grant is a reviewable
decision, not a formality).

Pre-flight, as the account the service will run under, before you enable the overlay:

```powershell
whoami /priv                                       # a line naming SeSecurityPrivilege
wevtutil qe Security /c:1 /rd:true /f:text         # the read this channel needs, in one command
```

Measured 2026-09-08 without the right: `whoami /priv` prints no `SeSecurityPrivilege` line; the
`wevtutil` probe answers `Access is denied.` followed by `Failed to open event query.` (the same
command on the `Application` channel prints an event, so the shape is right and the difference is
the channel). `Get-WinEvent -LogName Security -MaxEvents 1` fails the same cause differently --
`System.UnauthorizedAccessException: Attempted to perform an unauthorized operation.` Reading the
audit policy is a separate privilege question: `auditpol /get /category:'Account Logon'` answers
`Error 0x00000522 occurred: A required privilege is not held by the client.` on the same host, so
run it elevated when you check *which* subcategories can produce those six ids at all.

**Observable failure when the right is missing** (quoted, not paraphrased). With the overlay loaded
as shipped and no `SeSecurityPrivilege` in the process token, the collector exits at startup --
measured 2026-09-08 on the pinned build, `windows_event_log/security` receiver, un-elevated:

```text
Error: cannot start pipelines: failed to start "windows_event_log/security" receiver: start stanza:
failed to open local subscription, error: failed to subscribe to  channel: Access is denied.
```

The doubled space is upstream's, not a transcription slip: that message names the channel, and with
`query` in use the channel is not set as a field (the build refuses `channel` and `query` together
with `either \`channel\` or \`query\` must be set, but not both`), so it prints empty. Read the
`windows_event_log/security` id in the line above it to tell which receiver refused.

`ignore_channel_errors` is left at its default (`false`) deliberately: without the right the whole
agent refuses to start -- `metrics` and the file-log pipeline included. Set it to `true` only if
you prefer the opposite trade: the agent stays up, the overlay's own log line warns once, and no
Security event is collected until someone notices.

**UNVERIFIED (not run, and this session could not run it).** Whether an *interactive elevated*
prompt is enough, or the right must be granted to the *service account* specifically. Elevation was
unavailable here, so the delivery of a Security event through this pipeline has never been
observed -- the 2026-09-08 run proved the pipeline carries a Windows event with stable identity on
a channel readable without the right (`Application`), and proved the refusal on `Security`. What is
documented as required is the right, from Microsoft's page, plus the refusal, from the binary; the
account-and-elevation question belongs to whoever runs the check on a host where they can elevate,
and its answer goes in `conformance.md` with a date.

Two verified facts to build on. `pkg/stanza/operator/input/windows` at tag `v0.159.0` contains no
privilege-adjusting call in `api.go`, `input.go`, `subscription.go`, `event.go` or `security.go`
(read 2026-09-08), so the process token must already carry the right. And in that build the
receiver treats exactly two OS errors as fatal-on-start — `ERROR_ACCESS_DENIED` and
`ERROR_EVT_CHANNEL_NOT_FOUND` (`isNonTransientError`, `input.go:118`) — logging a warning and
continuing for anything else. "Not permitted" and "no such channel" therefore both stop the agent
loudly; some *other* open failure would leave it running while collecting nothing, which is the one
shape of silence this component cannot see from its own dashboard.

## Install and service

This product ships **no service installer**. Verified negative, not an omission: the pinned
executable's own subcommands are `completion`, `components`, `featuregate`, `help`, `print-config`
and `validate` (`otelcol-contrib.exe --help`, 2026-09-08) -- there is no `service install` and no
`--start-as-service`. Run the binary under the OS's own service control, which is how the service
manager starts a plain executable:

```powershell
New-Service -Name local-observe-agent -BinaryPathName `
  'C:\local-observe\agent\otelcol-contrib.exe --config file:C:\local-observe\agent\collector.yaml' `
  -StartupType Automatic
```

- Put the executable, `collector.yaml`, the state directory and the credential file under one
  directory you own; every path in the shipped config is absolute and is the contract.
- `-Credential` runs it as a named account. To collect the Security channel that account must hold
  `SeSecurityPrivilege` (above). The default (`LocalSystem`) is the widest account on the host:
  it reads every file on it and holds the machine's domain credential, so prefer a managed service
  account unless you have read the [agent-linux contract](../agent-linux/CONTRACT.md) equivalent
  argument for host-wide read. **UNVERIFIED**: whether a LocalSystem service holds
  `SeSecurityPrivilege` *enabled* on this build; `sc.exe qc local-observe-agent` shows the logon
  account, `whoami /priv` **in the service's own process** shows the token -- the check is not
  reachable from a normal session, so leave it to the host run and record what it printed.
- A second collector process must not share `LO_AGENT_STATE_DIR` with a first one. Measured
  2026-09-08: the newcomer dies in exporter startup (`failed to start "otlp_http" exporter:
  timeout`) while `file_storage` is held. That message names the exporter's config key, which this
  component renamed in otlp http alias; the run has not been repeated. If you run the Security overlay as
  its own service, give it its own state directory as well as its own config.
- The service is not monitored by this product: no `health_check` extension is declared and no port
  is opened, so liveness is the freshness of this host's data in the store (same posture as the
  Linux agent).

## Provenance: download, verify, then install

This is the one place the estate meets an upstream binary it did not build. Each step refuses; do
not continue past a refusal by "temporarily" using the file anyway.

```powershell
$asset  = 'otelcol-contrib_0.159.0_windows_amd64.tar.gz'          # collector.asset in versions.json
$dir    = 'C:\local-observe\downloads'; New-Item -ItemType Directory -Force $dir | Out-Null
Invoke-WebRequest https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.159.0/$asset -OutFile "$dir\$asset"
Invoke-WebRequest "https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.159.0/$asset.sha256" -OutFile "$dir\$asset.sha256"
# 1. the publisher's own checksum against the download (not against this repository's file)
if (-not ( (Get-FileHash "$dir\$asset" -Algorithm SHA256).Hash -eq (Get-Content "$dir\$asset.sha256").Trim() )) { throw 'archive hash differs from the publisher checksum' }
# 2. the archive's member paths, before extracting anything
tar -tvzf "$dir\$asset"      # expect README.md and otelcol-contrib.exe only; reject absolute or traversal paths
# 3. the extracted binary against versions.json -- the value a stranger can compare
tar -xzf "$dir\$asset" -C $dir
if (-not ( (Get-FileHash "$dir\otelcol-contrib.exe" -Algorithm SHA256).Hash -eq (Get-Content components/data/agent-windows/versions.json | ConvertFrom-Json).collector.binary_sha256 )) { throw 'binary differs from the pin' }
```

Verified 2026-09-08 by the hand that wrote this file, on windows/amd64: the publisher's `.sha256`
matched the 100,059,664-byte download (`86434cf1…59bb`), the archive held exactly `README.md` and
`otelcol-contrib.exe` with no absolute or traversal member paths, and the extracted executable
hashed to `e15e33cbd50c5890abff1776a997c56b007a1d1bbf617e9faac80dabd016d8cb` -- the hash
`conformance.md` records and the hash `check_windows_agent.py` now refuses anything else to match.

**Not claimed:** no signature verification and no registry publication. The release also serves
`$asset.sigstore.json`; nothing here verifies it, because this repository ships no sigstore/cosign
dependency (`versions.json` states both, and `signature_verified` is `false`).

The upstream current release at the time of writing is v0.160.0 (2026-09-02). **Not selected**: the
front door, the store collector and this agent are one contrib version, and the remediation ledger
records 0.159.0 → 0.160.0 as *pending-data-pass*. A pin moves in its own commit, with a reason and
a rollback line, after it has been seen running against its real consumers -- never inside another
component's change.

## Ingest credential (unchanged; credential file leftovers)

The ingest credential is **not** one of the overlay variables. It is read from a file by the
collector's confmap `file` provider — `Authorization: Bearer
${file:C:/local-observe/agent/secrets/ingest-token}` in `collector.yaml` — because an
environment value is visible to anyone who can read this host's process data and is inherited by
every child the collector spawns; this is a host on which an agent is installed, frequently one
someone else also administers. Confmap cannot nest (`${file:${env:…}}` is not expanded), so the
path cannot come from the environment: **the path above is the contract**, and `C:/local-observe/
agent/secrets/` is a product convention, not a discovery rule. To put the secret elsewhere, edit
that one line in your own copy of `collector.yaml` and keep the two in step. The Security overlay
exports through that same `otlp_http` exporter and defines no credential of its own.

Create the file with **no trailing newline and no byte-order mark** — the provider hands the file's
bytes to the exporter, and a newline would travel inside the `Authorization` header, where the
front door reads it as a different token and answers 401:

```powershell
$token = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 40 | ForEach-Object {[char]$_})
New-Item -ItemType Directory -Force 'C:/local-observe/agent/secrets' | Out-Null
# WriteAllText emits UTF-8 without a BOM and adds no line ending; Set-Content adds both.
[System.IO.File]::WriteAllText('C:/local-observe/agent/secrets/ingest-token', $token)
icacls 'C:/local-observe/agent/secrets' /inheritance:r /grant:r "${env:USERNAME}:(OI)(CI)(R)"
```

`Set-Content`/`echo` are the wrong tools here: they append a line ending. Verify before starting
the agent — a length of exactly 40 (or whatever you generated) and no `0D 0A` at the end:

```powershell
$b = [System.IO.File]::ReadAllBytes('C:/local-observe/agent/secrets/ingest-token')
"$($b.Length) last=$($b[-1])"     # last must not be 10 (LF) or 13 (CR)
```

Evidence that the pinned Windows build can read it, read rather than inferred: the SPDX SBOM
attached to `otelcol-contrib_0.159.0_windows_amd64.tar.gz` at tag `v0.159.0` of
`open-telemetry/opentelemetry-collector-releases` lists the package
`go.opentelemetry.io/collector/confmap/provider/fileprovider` `v1.65.0`, and that release's
`distributions/otelcol-contrib/manifest.yaml` names it under `providers:` for every target. The
provider's own documentation (`confmap/provider/fileprovider/provider.go`, tag `v0.159.0` of
`open-telemetry/opentelemetry-collector`) states the URI is `file: [drive-letter] file-path` and
gives `file:c:/path/to/file` and `file:c:\path\to\file` as supported absolute Windows forms. The
`${file:…}` shape was also run against that build: `otelcol-contrib.exe validate` on a config
carrying `${file:C:/…}` returns 0 for an existing file and names the Windows path it tried to open
when the file is removed — so the form is resolved on this OS, not silently passed through.

The same build used to print one more warning about this file: the exporter key every shipped
config carried was the older, now-deprecated spelling of `otlp_http` (warning observed
2026-09-08, at component build). otlp http alias renamed it here and in every other shipped collector config
in one change, so the tree's exporter vocabulary stays single. The pin did not move: an exporter
type is a property of the build, and `versions.json` is byte-identical. The evidence is upstream
source read at tag `v0.159.0`, not a run -- `distributions/otelcol-contrib/manifest.yaml` pins
this exporter's module at `v0.159.0`, and that module's
`internal/metadata/generated_status.go` sets `Type = component.MustNewType("otlp_http")` with the
older spelling registered beside it as the deprecated alias. No collector process has been
started with the renamed config.

Rotation is offline: stop the agent, replace the file's bytes, start it. The path must not widen
the file's read scope to every authenticated producer, and the credential stays transport auth,
not tenant isolation — as in the front-door contract, an authenticated writer may assert any
`resource_id`.

## What a stranger can and cannot check here

`python -B scripts/check_foundation.py` scans this directory's text for private references, and
that is all it does: the gate walks the Compose models in `EXAMPLE_MANIFESTS` and the collector
config of each included component, and this component ships no Compose model for an example to
include. So `check_collector` -- the rule that every pipeline reference resolves to a declared
component -- never sees `collector.yaml` unless a test hands it the document. `tests/test_windows_agent.py`
does exactly that for the merged pair, and pins the shape of `versions.json`, the two refusals, and
the overlay's option names and event-id set. The native half is
[conformance](conformance.md); nothing in the suite runs a collector.

See [conformance](conformance.md), [backup](backup.md), [upgrade](upgrade.md).

# Guided setup and trusted execution

Guided setup prepares a small observer configuration over an existing telemetry store
and an explicitly local model endpoint. It uses platform authentication for planning,
human decisions and runner requests. It never starts a service or executes a shell.
The transport and runner must use independent credentials; never mount a human or
trusted runner credential in an assistant service.

The integration constructs `GuidedSetup(store, configuration_root, runner_identity)`
and passes it as `guided_setup=` to `platform.api.create_app`. The configuration root
must already be an owned POSIX directory with mode 0700. The platform database must
be a regular owned 0600 file under an owned 0700 parent. Create these with a private
umask before initializing the platform. Windows guided application is unsupported.

The existing `lo-deployment` command is unaffected; the HTTP operations below are the
shared mechanism for a manual client and an assistant. A command-line integration
uses `lo-guided-setup --url https://platform.example.test --token-file /run/secrets/CALLER`.
Use `plan --profile profile.json`, then a separate human client's
`decision PLAN_ID --decision approved --expires-at TIMESTAMP`, then `request PLAN_ID`.
Only the configured runner's client can call `apply PLAN_ID`; `verify PLAN_ID` checks the result.
The profile cannot select the caller's role or credential.

Platform startup enables guided setup only when both `LO_GUIDED_SETUP_ROOT` and
`LO_GUIDED_SETUP_RUNNER` are supplied. The root is the existing protected configuration
directory; the identity must have its own executor credential in the platform role map.
`LO_TRUSTED_RUNNERS_FILE` separately selects an exact version-1 JSON object with
`schema_version: 1` and `runners: {identity: [binding, ...]}`. Blank, partial or invalid
configuration refuses startup. With these settings absent, existing platform behavior remains.
Use a private creation umask and an owned 0600 database before enabling either service.

| Request | Credential | Body / result |
|---|---|---|
| `POST /v1/setup/plan` | proposer or human | `{ "profile": ... }`; returns deterministic plan, hash ID and local preflight |
| `POST /v1/setup/decision` | human | `plan_id`, `decision` (`approved` or `denied`), UTC `expires_at` within one hour |
| `POST /v1/setup/request` | proposer, executor or human | `plan_id`; queues a currently approved plan |
| `GET /v1/setup/pending` | configured runner | Up to 20 queued plan IDs |
| `POST /v1/setup/apply` | configured runner | `plan_id`; applies and verifies the stored plan |
| `POST /v1/setup/verify` | reader, proposer, executor or human | `plan_id`; verifies existing output without writes |

All objects reject extra fields. New setup/handoff request parsers also reject duplicate
JSON keys, nonfinite constants and deeply nested input. A caller-supplied approver,
plan, destination or recomputed hash is never approval. The server binds the exact
profile, source-tree digest, destination directory identity, runner and file hashes
to its durable human decision. Source drift requires service restart and a new plan.
An approval can be withdrawn until application begins. The SQLite write transaction
serializes withdrawal against application.

The version 1 profile has exactly these fields:

```json
{
  "schema_version": 1,
  "name": "example",
  "interval_seconds": 3600,
  "telemetry": {
    "url": "https://telemetry.example.test",
    "token_file": "/run/secrets/store-reader",
    "resource_id": "11111111-1111-4111-8111-111111111111",
    "metric_name": "system.cpu.utilization"
  },
  "model": {
    "url": "https://model.example.test",
    "token_file": "/run/secrets/model-reader",
    "model": "observer-model",
    "local": true,
    "capability": {
      "schema_version": 1,
      "context_tokens": "unknown",
      "tools": false,
      "json_mode": "unknown",
      "streaming": false,
      "vision": false,
      "parallel": "unknown",
      "quant": "unknown",
      "measured_tok_per_s": "unknown"
    }
  },
  "channel": {"type": "recording"}
}
```

Supply the actual inventory resource ID, stored metric name and measured model
capabilities. Unknown capability values are valid configuration and refuse unsupported
model use; setup does not invent measurements. Telemetry uses the existing ClickHouse
read-only store facade and its default analysis user. Model endpoints must be local
by explicit operator declaration and use HTTPS origins without an API path. The client
appends its API path. This starter does not configure a
remote-model privacy policy. A Telegram preference may instead name exactly `type`,
`token_file` and `destination_file`, with both references under `/run/secrets/`.

Application creates `profile.json`, runnable `observer.json`,
`observer-environment.json`, `ai-policy.json`, `ai-capability.json` and `channel.json`.
The environment artifact is a JSON mapping for the launcher, never shell text to source.
It supplies `LO_CLICKHOUSE_URL`, `LO_CLICKHOUSE_READ_PASSWORD_FILE`, `LO_AI_BASE_URL`,
`LO_AI_MODEL`, `LO_AI_API_KEY_FILE`, `LO_AI_OUT_OF_LAN=0`, `LO_AI_CAPTURE=0`,
`LO_AI_POLICY` and `LO_AI_CAPABILITY`. The two policy paths point into the approved
destination. Secrets remain mounted; setup neither reads nor copies them. Configure
the observer's protected runtime directory separately from configuration and Git.

The generated observer runs in recording mode with one metric source and one model
call per cycle. Live model delivery remains disabled even when Telegram is selected.
`channel.json` records that preference for subsequent independently evaluated channel
integration. Urgent rule alerts keep their own existing configuration. Preflight
establishes local filesystem readiness only; endpoint access, metric availability,
credential validity and measured capabilities require runtime verification.

Files are created exclusively with mode 0600, read back and hashed. No existing file
is overwritten. Paths use directory descriptors and refuse ancestor/target symlinks,
FIFOs, hardlinks, unexpected content and unsafe permissions. A matching `.setup-plan`
marker permits an interrupted application to resume only its missing files. An
unchanged completed apply is a verification-only repeat, including after approval
expiry. A partial plan needs a still-current approval to resume.

If a crash leaves no valid marker, a truncated file or changed content, retain the
directory for inspection and prepare a new profile name. Do not delete or repair
unknown content automatically. Missing unchanged files after completed application
are reported as drift. Back up the platform database and operator configuration
before upgrades; restore the matching pair and reconcile any external effects before
running again.

## Trusted action handoff

Construct `RunnerHandoff(store, action_policy, {runner_identity: [binding, ...]})`
and pass it as `runner_handoff=` to `create_app`. Each binding has exactly `action`,
`version`, ordered canonical UUID `targets`, `dag` and specification `sha256`.
Only empty action parameters are supported by this deterministic executor.

The human first reads `GET /v1/actions/review?action_id=...`, then includes its
`binding_sha256` in the existing action-decision POST when approving. The server
recomputes that digest inside the decision transaction and stores it separately from
the proposal. A changed binding invalidates review and approval. An approval from
before handoff configuration cannot be reused: create and review a new proposal.
Denial/withdrawal uses the existing two-field decision request.

The existing MCP `execute_action` tool now posts `/v1/actions/execute` with only the
action ID. It returns a queue receipt, never an execution credential or a claim of
success. Missing runner configuration remains a non-consuming refusal. With a
handoff configured, the legacy direct claim endpoint is disabled. Only configured
runner identities can read `GET /v1/runner/requests` or post `/v1/runner/claim`.

The trusted runner calls `run_request(platform_client, dagu_client, request, binding,
journal_directory, immutable_dag_root=...)`. Both clients hold its own credentials.
The owned journal directory must already be 0700. Token-bearing intent and execution
journals are 0600 from first write, including exclusive random temporary files.
The runner fsyncs its token before claiming; the DB stores only its digest.

Fresh dispatch fails closed without a read-only DAG mount and a DAG name ending in
`-<first 16 hex characters of specification SHA-256>`. The runner verifies the
corresponding `.yaml` file and Dagu's reported specification. **Deployment acceptance
must establish that Dagu uses this same immutable release source and has no mutable
alternate specification source or writable alias.** A read-only bind mount over a
separately writable source does not establish that property. Do not enable the runner
until that mapping is proven. Another GET/hash check alone cannot close the race
between reading a specification and starting a DAG by name.

Queue identity is the action ID; its execution remains single-use. Request retries
cannot produce another queue entry. A lost claim response can recover only with the
same runner identity and journaled token. Recovery without a dispatch journal polls
the execution ID and records unknown when absent; it never starts a job. A crash
after durable dispatch intent also only polls. Missing journals/tokens, unknown
outcomes and old-backup restoration require operator reconciliation; never recreate
an action to hide the uncertainty. The human may withdraw before claim; claim checks
current policy, target opt-in, incident state, expiry and approved binding atomically.

Schema 10 adds `runner_approvals`, `runner_requests` and `setup_plans` through the
existing explicit `lo-platform migrate` path, with its verified pre-migration copy
and audit. No existing table is rewritten. Older binaries refuse schema 10; rollback
uses the verified prior backup, with external execution reconciliation first.

Tests cover authenticated role separation, exact approval binding, output hash
readback, recovery, refusal paths, schema 9 migration and concurrent queue/claim
attempts. Queue tests use an in-memory engine; actual immutable mount mapping and
live service behavior remain deployment acceptance checks.

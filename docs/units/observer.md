# Scheduled observer

The observer is a read-only, bounded investigator with its own private SQLite journal.
It starts from configured telemetry sources; no incident or rule candidate is required.
`python -m local_observe.observer` provides `run`, `serve`, `check`, `replay`, `feedback`,
`retrieve`, `export` and `backup`. Python 3.12 and the product base dependencies are required.
The protected directory handles require Linux; the scheduler deadline requires the main Python thread.

## Configuration and adapters

The operator supplies a strict versioned JSON file outside the source checkout:

```json
{
  "schema_version": 1,
  "cadence_seconds": 3600,
  "window_seconds": 3600,
  "max_sources": 8,
  "max_result_bytes": 65536,
  "max_model_calls": 2,
  "max_cycle_seconds": 120,
  "max_rows": 200,
  "max_age_seconds": 900,
  "data_class": "internal",
  "mode": "shadow",
  "sources": [{
    "id": "service-cpu",
    "adapter": "store",
    "query_type": "metric-threshold",
    "resource_id": "00000000-0000-4000-8000-000000000001",
    "metric_name": "cpu.utilization",
    "initial": true
  }]
}
```

`store` uses the existing read-only ClickHouse facade and its named `metric-threshold`
and `log-records` queries. It requires `LO_CLICKHOUSE_URL` and
`LO_CLICKHOUSE_READ_PASSWORD_FILE`; existing `LO_CLICKHOUSE_READ_USER` and
`LO_INTERNAL_ALLOW_HTTP` settings apply. Metrics require `metric_name`. No model can
provide SQL, selectors, resource IDs, URLs or commands. Sources with `initial: false`
can be requested only by their configured ID in an allowed follow-up list.
An optional source `data_class` can raise classification to `internal` or `restricted`.
The most restrictive configured class in the evidence bundle governs each model request;
telemetry cannot supply or lower that classification.

`file` uses an absolute `path` to a bounded normalized evidence JSON file. `http` uses
an operator-configured `base_url`, fixed absolute API `path`, and `credential_file`.
It sends a GET with `source`, `query_type`, `resource_id`, `start`, `end`, `limit` and
optional `metric_name` query parameters. This is a normalized JSON source integration
contract, not a new endpoint supplied by the platform. HTTPS is the default; explicit
`allow_http: true` is for an operator-controlled internal network. The existing
`JsonClient` disables proxy inheritance and redirects; its transport reads at most
4 MiB before the observer enforces the smaller total accepted-evidence byte limit.

File and HTTP sources return exactly this envelope, optionally with boolean `truncated`:

```json
{
  "schema_version": 1,
  "source": "service-cpu",
  "query_type": "metric-threshold",
  "resource_id": "00000000-0000-4000-8000-000000000001",
  "window": {"start": "2026-01-01T11:00:00Z", "end": "2026-01-01T12:00:00Z"},
  "observed_at": "2026-01-01T12:00:00Z",
  "rows": [{"timestamp": "2026-01-01T11:59:00Z", "value": 0.8,
            "labels": {"service": "example-service"}}]
}
```

Log rows replace `value` with string `body` and may include string `severity`.
Labels may contain bounded nested objects and arrays. Timestamps must be timezone-aware;
rows must fall inside `[start, end)`. Both observation time and the newest sample must
meet the freshness limit. Empty rows, truncation, failed reads and budget skips are
coverage gaps, never invented measurements. Unknown fields, versions and query names fail.

The model adapter lazily uses `AiClient.from_environment`, including the existing
`LO_AI_BASE_URL`, model, measured capability, policy and budget settings. It additionally
requires `LO_AI_API_KEY_FILE` and forces payload capture off. A configured local or remote
API remains subject to the existing policy, capability and per-call token/byte budgets.
Unknown model cost remains null; reported input/output token counts and elapsed time are retained.
Remote requests carry the fixed output contract in short structured fields, so the existing
`no_free_text` policy does not erase the instructions or evidence IDs. If that policy withholds
any evidence text, the cycle fails explicitly as `model_evidence_withheld`; it cannot become
a quiet finding over data the model did not receive. Prefer local inference for prose-heavy logs.

## Running and reviewing

Create the state directory with mode 0700, outside Git and owned by the service account.
Each journal, lock, export and backup file is mode 0600. Use an existing private parent directory.

```sh
python -m local_observe.observer --state /var/lib/local-observe/observer run --config /etc/local-observe/observer.json
python -m local_observe.observer --state /var/lib/local-observe/observer serve --config /etc/local-observe/observer.json
python -m local_observe.observer --state /var/lib/local-observe/observer check --max-age-seconds 7200
python -m local_observe.observer --state /var/lib/local-observe/observer replay CYCLE_ID
python -m local_observe.observer --state /var/lib/local-observe/observer feedback CYCLE_ID --id REVIEW_ID --input review.json
python -m local_observe.observer --state /var/lib/local-observe/observer retrieve --query example-service --limit 5
python -m local_observe.observer --state /var/lib/local-observe/observer export --output /var/lib/local-observe/observer/examples.jsonl
python -m local_observe.observer --state /var/lib/local-observe/observer backup --output /var/lib/local-observe/observer/backup.sqlite3
```

`run` exits 0 only for complete execution/coverage, 2 for partial/failed/skipped work.
`check` reports independent execution freshness, not a model assurance or human endorsement.
A fresh, complete `tell` can be a healthy *observer execution*. A quiet result remains
unreviewed until a human grades it. An external scheduler can monitor `check` without
depending on the observer model or notification channel. `serve` defaults to hourly UTC
slots and resumes the same durable slot ID after restart; it does not backfill missed slots.

Human review JSON separates `usefulness` (`useful`, `noise`, `unsure`) and `correctness`
(`correct`, `incorrect`, `unsure`). Optional fields are `corrected_answer`, `outcome_refs`
(retained evidence IDs), and `export_approved` (default false). No response stays unknown.
The CLI authenticates through the OS-owned private directory and derives reviewer identity
from the OS UID. Do not expose it as a web service or run it from model-selected commands.
Reviews are append-only, with idempotent review IDs. Reusing an ID with different content fails.
Later reviews supersede earlier export eligibility without erasing review history.

Retrieval and JSONL export require a nonempty independent correction, an explicit export
approval, evidence, and a decided correctness grade. Scalar grades alone are insufficient.
Examples are labelled `untrusted_reference_only`; they are never inserted as policy.
Retrieval scans at most the latest 1,000 independently reviewed cycles and returns at most 100.
It is a local evaluation/training preparation seam, not a fine-tuning or self-training loop.

## Durable states and safety boundaries

Every admitted attempt is committed before source or model work. SQLite FULL synchronous
transactions retain redacted evidence, exact final model rationale, visible read activity,
model metadata and usage. Hidden reasoning is not requested or retained. Duplicate cycle
IDs return the original record. A kernel lock permits one active cycle; concurrent attempts
receive durable `skipped` records. Source count, total evidence bytes, result rows, model
calls and wall time have independent ceilings. A killed process leaves `running`; the next
lock holder marks it failed/interrupted without requerying or repeating delivery.

`run` and `serve` support `shadow` and `recording` modes. Their delivery is a durable recording
with a stable cycle ID and `external_send: false`. Optional Telegram delivery is a separate
post-cycle API described below. Model text cannot approve its own release. Urgent rule
notifications remain independent of this observer and its message budget.

Credential-named fields, recognizable credential assignments, URL credentials and known
mounted credential values are redacted before persistence. Arbitrary unlabelled secrets
cannot be reliably detected: source operators must exclude them. The journal still contains
sensitive telemetry and prose and needs protected backups. There is no automatic pruning:
every cycle is retained, so operators must monitor disk space and provision retention storage.
Disk failure can prevent any writer from committing; a persisted running record then remains
recoverable and the external heartbeat must detect the missing completion.

`backup` uses SQLite's backup API and an independent integrity check. Preserve the whole
private state directory during host recovery and reopen a restored database under the same
schema version. Offline replay uses the retained snapshot even after original telemetry expires.
No restore, deletion, migration or source requery happens implicitly.

## Python integration

`Config.from_dict(document)` validates the public configuration. `Journal(private_directory)`
owns persistence. `Observer(config, journal, sources=..., model=..., clock=...).run(cycle_id)`
is the production investigator, with an injectable UTC clock and no ground-truth input.
The source adapter implements `read(source: Source, window: dict, now: datetime) -> dict`;
the model adapter implements `complete(evidence, allowed_source_ids, config, now) -> dict`
returning `content`, optional `model`/`response_model`, and `usage` with token counts.
Adapters may expose a tuple `secrets` for exact-value scrubbing. Injected adapters are
trusted application code; telemetry and model response content are not.

Model `content` is strict JSON with `schema_version: 1`, `decision`, `rationale`,
`citations`, `follow_up`, and optional `findings`. Each citation must contain `evidence_id`, zero-based `row_index`,
`field` and an exact copied `value`. At least one citation is required. Citation validation
checks identity and values, not the semantic correctness of prose; independent evaluation
and human review remain necessary. Unknown fields, invented citations and unsupported
follow-ups fail the cycle. Results expose `status`, `coverage`, `decision`, `answer`,
`evidence`, `activity`, `model_calls` and `delivery`. Each cited snapshot carries resource UUID,
source/query IDs and window, allowing a parent adapter to map findings to canonical events.
Each structured finding has exactly `resource_id`, `kind` (`availability`, `coverage`,
`threshold`, `drift`, `anomaly`, `security`), `observed_at` and `evidence_ids`. Its resource
must match every cited snapshot, and its timestamp must equal a cited row timestamp inside
the window. Quiet results require empty findings. No findings are inferred from prose;
an evaluator must refuse to score an actionable result without structured findings.

An evaluation harness should inject only source series and an observation window, invoke
this production callable for each repetition, and retain separate journals or cycle IDs.
It must keep incident labels and quiet ground truth outside the source/model arguments.
Failures and coverage gaps must be scored separately from quiet observations.

## Optional Telegram delivery and phone grading

`local_observe.observer.telegram.Telegram` is a replaceable post-cycle API, separate from
the default CLI scheduler. It uses a fixed `https://api.telegram.org` host, disables proxies
and redirects, reads a token FILE reference, and never logs token-bearing paths. Sends and
polls have a 20-second overall deadline. A completed, fully covered `tell` with structured
findings is required; restricted evidence is refused. The phone message contains only a
finding category, resource UUID, trusted configured metric name, cited numeric value,
sample timestamp, coverage and cycle ID, not arbitrary model prose or source logs.
Full evidence and rationale stay in protected local replay; the phone digest alone may
not provide enough context for a correctness decision, so `unsure` is explicit.

Construct `TelegramConfig(token_file, chat_id, user_id, daily_limit=2, feedback_seconds=86400)`
and `Telegram(journal, config, verifier=..., config_digest=...)`. The required verifier is
trusted application code supplied by the integration, not model output. It receives
`(cycle, binding, now)` and must return exactly `True` only after independently verifying
accepted evaluation evidence for the supplied configuration/model and delivery binding.
There is no default verifier or built-in self-certification. The binding includes schema,
the exact observer configuration SHA-256, actual response model, cycle SHA-256, fixed
channel, allowed chat/user IDs, optional trusted review URL and delivery epoch. `cycle['config_sha256']` is computed by
the production observer as the canonical SHA-256 of `dataclasses.asdict(config)`.
`review_base_url` can name an operator-controlled HTTPS review route; the adapter appends
the validated cycle ID. A finding without numeric context requires this URL, otherwise
delivery is refused before reserving budget. No telemetry or model text supplies URLs.

Every new instance starts disarmed, including after reopening a restored database.
An operator must reconcile previous external effects and explicitly call
`arm_after_reconciliation(fresh_uuid_epoch)`. A stored/environment flag cannot re-arm it;
the CLI intentionally has no automatic arming command. Changing the epoch also invalidates
old phone callbacks. The verifier must be integrated with the installation's independently
accepted quality artifact before an operator arms delivery. Scheduler wiring, signed-artifact
validation and operator UX for reconciliation are integration responsibilities.

Call `deliver(cycle_id, now=utc_datetime)` after the cycle completes. It rechecks the gate,
debits an observer-only maximum two-per-UTC-day budget, and commits `sending` before provider
I/O. The debit survives failure and restart and is shared across epochs. An acknowledged
receipt becomes `sent`; lost acknowledgement, malformed receipt and interrupted dispatch
become `uncertain`. Duplicate requests return the existing outcome. No uncertain send is
retried or sent through a fallback channel. `outcome(cycle_id)` reads this separate delivery
record; the original cycle's recording receipt remains an accurate historical record.

Call `poll_feedback(now=utc_datetime)` to pull a bounded batch through the authenticated
Telegram API. There is no public callback service. Inline buttons offer combinations of
usefulness and correctness. The callback must match the configured human user (not a bot),
chat, acknowledged message ID, cycle-bound random nonce, current epoch and expiry. A callback
is consumed once; its human feedback and the polling cursor commit atomically. Rejected or
replayed callbacks create no labels or action approval. Phone scalar grades cannot enable
retrieval/export; an independently reviewed correction and explicit local export approval
are still required. Each bot should belong to this integration, because Telegram polling
cursors are shared by all consumers of a bot.

Backups include delivery outcomes, spent reservations, cursor, callback consumption and
grades in the same SQLite database. An older backup cannot prove which external effects
happened after it: reopening stays disarmed, and operator reconciliation is required before
a fresh epoch. This is an intentional restoration boundary, not exactly-once delivery.

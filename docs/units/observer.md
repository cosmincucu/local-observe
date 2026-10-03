# Scheduled observer

The observer is a read-only, bounded investigator with its own private SQLite journal.
It starts from configured telemetry sources; no incident or rule candidate is required.
`python -m local_observe.observer` provides `run`, `serve`, `check`, `replay`, `feedback`,
`retrieve`, `export`, `backup` and the optional delivery commands below.
Python 3.12 and the product base dependencies are required.
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

The observer allows ClickHouse wire responses up to twice `max_result_bytes`, with a minimum
of 64 KiB and a hard maximum of 128 KiB, to accommodate JSON formatting. Normalized evidence
still has its configured limit, at most 64 KiB. An oversized wire response records
`source_result_too_large`; oversized normalized evidence records `result_too_large`. Both
refuse the whole result without truncating evidence or including response text in errors.
Narrow the window or selector if the result cannot fit.

The model adapter lazily uses `AiClient.from_environment`, including the existing
`LO_AI_BASE_URL`, model, measured capability, policy and budget settings. It additionally
requires `LO_AI_API_KEY_FILE` and forces payload capture off. A configured local or remote
API remains subject to the existing policy, capability and per-call token/byte budgets.
For reasoning models, the optional AI budget can explicitly allow up to 16 384 completion
tokens and a `request_timeout_seconds` of at most 120. Defaults remain 512 tokens and a
10-second socket timeout. An optional `reasoning_effort` (`low`, `medium`, `high` or
`xhigh`) is sent unchanged within the same request bounds. Omission leaves the parameter
unset. The budget provenance hash and configuration-drift check include an explicit value.
Verify support against the configured gateway/model; this setting does not guarantee
completion or cause the observer to retain reasoning text.
Test representative observation windows before selecting limits:
the completion allowance covers reasoning and final text together and can be exhausted before
an answer finishes. Increasing it does not extend the socket timeout or cycle deadline. The full
serialized prompt and model response must still fit their independent byte bounds.
The final observer JSON answer is limited to 16 KiB; reasoning tokens belong in the
provider's separate reasoning field, never in the final answer. Known AI budget and
transport refusals are retained as fixed `model_*` journal codes; provider error text
and unrecognized codes are not persisted.
A reply reporting truncated output without answer text is journalled as
`model_incomplete_response`. Partial answers that contain text keep the
`incomplete_model_response` code. Both are refused without retaining response or reasoning
text. Failed calls keep null token counts in the journal; validated counters from answerless
truncation are available in the AI component's call record.
Unknown model cost remains null; reported input/output token counts and elapsed time are retained.
Remote requests carry the fixed output contract in short structured fields, so the existing
`no_free_text` policy does not erase the instructions or evidence IDs. If that policy withholds
any evidence text, the cycle fails explicitly as `model_evidence_withheld`; it cannot become
a quiet finding over data the model did not receive. Prefer local inference for prose-heavy logs.

`run` and `serve` accept `--environment /private/path/observer-environment.json`, including
the JSON emitted by guided setup. This is an allowlisted mapping of environment names to
strings, never a shell script. The file must be an owned, regular mode-0600 file within an
owned mode-0700 directory, with no symlinks or hardlinks. It replaces ambient settings;
it does not merge with them. Allowed settings are the ClickHouse URL, read user and password
file; AI base URL, key file, model/fast model, out-of-LAN flag, capture flag, policy, capability
and budget files; internal HTTP flag; and the nonsecret `LO_OBSERVER_MODEL_PROVIDER` and
`LO_OBSERVER_MODEL_VERSION` labels. Raw credentials and other names are rejected. Capture
is always disabled. Without this option, only the same allowlisted ambient names are used.

## Running and reviewing

Create the state directory with mode 0700, outside Git and owned by the service account.
The journal rejects `.git` directories or worktree marker files on every ancestor.
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
It describes the newest finished cycle while the next cycle runs. That result keeps its original
completion time: active work cannot refresh it or hide a newer failed, partial or skipped result.
Only complete coverage within `--max-age-seconds` is healthy; stale or future completions fail.
With no finished cycle, a running attempt remains unhealthy and an empty journal reports
`never_run`. Once the active cycle finishes, its result replaces the previous observation.
A fresh, complete `tell` can be a healthy *observer execution*. A quiet result remains
unreviewed until a human grades it. An external scheduler can monitor `check` without
depending on the observer model or notification channel. `serve` defaults to hourly UTC
slots and resumes the same durable slot ID after restart; it does not backfill missed slots.

Human review JSON separates `usefulness` (`useful`, `noise`, `unsure`) and `correctness`
(`correct`, `incorrect`, `unsure`). Optional fields are `corrected_answer`, `outcome_refs`
(retained evidence IDs), `export_approved` (default false), and `review_seconds` (an integer
from 0 through 3600). Review time is human self-report, not measured elapsed time; omitted
values remain null. Each review version retains its own value. No response stays unknown.
The CLI authenticates through the OS-owned private directory and derives reviewer identity
from the OS UID. It is not a network listener and must not be run from model-selected
commands; an installation that wants review from a browser enables the optional platform
review routes below, which append to the same journal under the platform's own credential.
Reviews are append-only, with idempotent review IDs. Reusing an ID with different content fails.
Later reviews supersede earlier export eligibility without erasing review history.

## Optional authenticated review API

The observer service listens on nothing. An installation that also runs the platform API can set
`LO_OBSERVER_REVIEW_STATE` to the observer's private state directory, which adds three routes to
that API. Unset is the default: the three paths answer `404 not_found`, no journal is opened, and
existing platform behavior continues. Blank, relative, missing, unsafe or invalid state refuses
platform startup. The review surface only opens an existing versioned journal; it never creates
a database, and reading reviews does not initialize or migrate state.

| Route | Answer |
|---|---|
| `GET /v1/observer/cycles` | At most 100 newest cycle summaries, newest first, including quiet, failed and in-flight work. Optional `limit` (1-100) and `after=<cycle_id>` cursor. Reports `limit`, `returned`, `total_cycles`, `truncated` and `next_after`. `queue_reason` reuses the workload report's `quiet-sample` and `finding-or-coverage-gap` words per row, without its window-based sampling, and is absent for a cycle that cannot be graded yet. A summary carries no evidence, answer, rationale or grade, only the newest review's ID. |
| `GET /v1/observer/cycle?cycle_id=ID` | Retained redacted evidence, rationale, activity and the latest 100 review versions, oldest first within that page. `feedback_total` and `feedback_truncated` disclose older retained reviews; full history remains available through local replay. Also returns `cycle_sha256`, `reviewable` and `latest_feedback_id`. The digest covers the stored cycle record and must be echoed by a review form. An unknown cycle is `404`. |
| `POST /v1/observer/feedback` | Accepts exactly `cycle_id`, `feedback_id`, `cycle_sha256`, `previous_feedback_id` and `values`, where `values` is the same review document the CLI accepts. Returns the stored feedback record. |

Every route requires a `human` bearer credential from the platform's mounted role list — the same
credential the operator shell substitutes for a password login. `reader`, `proposer`, `executor` and
`producer` tokens are answered `403 not_authorised`, a `summary` token `403 summary_only`, and a
missing, wrong or duplicated `Authorization` header `401 authentication_required`. No request field
names a reviewer, an identity or a role: the journal records `platform-human:<authenticated identity>`,
while CLI reviews keep their `os-uid:<uid>` reviewer.

A submission is refused with no append when the retained cycle's digest has changed
(`409 cycle_digest_changed`) or the review it names is no longer the newest (`409 stale_review`, where
`previous_feedback_id: null` means "this cycle has no review yet"). Repeating a review ID with the same
reviewer and the same contents returns the original receipt, including after a later review arrived;
changing a grade, a correction or the reviewer under an ID already in use is `409 feedback_id_reused`.
Both judgements happen inside the journal's own write transaction. A review never rewrites a cycle
record, its delivery state, its acceptance binding or its retention, and it cannot make an unreviewed
`quiet`, failed or skipped result read as correct: such a cycle stays `review: unknown`.

Inputs are bounded before the journal is opened, and refusals are fixed: 256 query bytes, 65536 body
bytes, the journal's bounded identifier shape, one 64-character lowercase digest, and an exact field set
on both the body and `values`. A duplicate JSON key, a non-object body, a non-finite number, an
oversized document or undecodable UTF-8 is a `400 invalid_request` naming a public journal code. An
unopenable, unowned, unversioned or unreadable journal, and any fault this process cannot judge, is one
`503 observer_state_unavailable`. No path, exception text, credential or request value appears in any
answer. This surface adds no service, no scheduler, no delivery and no grade of its own; automatic
notification rules are unchanged.

Retrieval and JSONL export require a nonempty independent correction, an explicit export
approval, evidence, and a decided correctness grade. Scalar grades alone are insufficient.
Examples are labelled `untrusted_reference_only`; they are never inserted as policy.
Retrieval scans at most the latest 1,000 independently reviewed cycles and returns at most 100.
It is a local evaluation/training preparation seam, not a fine-tuning or self-training loop.
Automatic retrieval is off by default. Set `retrieval_examples` (0–10) and optionally
`retrieval_bytes` (512–16384, default 8192) in Config to enable it. The observer uses only
approved corrections reviewed before the current window end, with older evidence windows.
Whole examples must fit both retrieval and total evidence byte budgets. Their IDs, feedback
versions, digests and classifications are retained on the cycle. Historical evidence cannot
validate current citations. Its classification can only raise the model request's class;
remote redaction still applies. Models cannot grant export approval or create human grades.

## Durable states and safety boundaries

Every admitted attempt is committed before source or model work. SQLite FULL synchronous
transactions retain redacted evidence, exact final model rationale, visible read activity,
model metadata and usage. Hidden reasoning is not requested or retained. Duplicate cycle
IDs return the original record. A kernel lock permits one active cycle; concurrent attempts
receive durable `skipped` records. Source count, total evidence bytes, result rows, model
calls and wall time have independent ceilings. A killed process leaves `running`; the next
lock holder marks it failed/interrupted without requerying or repeating delivery.

`run` and `serve` support `shadow` and `recording` modes. Their default delivery is a durable
recording with a stable cycle ID and `external_send: false`. Optional Telegram delivery uses
the separate acceptance and reconciliation boundary below. Model text cannot approve its own release. Urgent rule
notifications remain independent of this observer and its message budget.

Each cycle and model call retains provenance schema v1: `implementation_sha256`,
`prompt_sha256`, `config_sha256`, `policy_sha256`, `capability_sha256`, `budget_sha256`,
`configured_model`, `provider`, `model_version`, `response_model`, `complete` and `sha256`.
Together with `schema_version`, these are the exact allowed fields. `sha256` hashes the
canonical object excluding that digest itself. Implementation covers observer, AI and
relevant shared source files; policy, capability and budget hash effective documents.
The configured model and actual provider response model are separate identities. Missing
metadata remains null and makes `complete` false; shadow observation can still proceed.
Mixed provenance within a cycle fails it. Provider/version labels are explicit operator
metadata, not independently verified provider claims. No endpoints, credential references,
prompt bodies or evidence bodies appear in this object.

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
An adapter enabling retrieval implements `complete_with_history(..., history=...)`.
Its optional `provenance()` returns configured model/provider/version labels and effective
policy/capability/budget hashes. The observer supplies implementation, prompt and Config
hashes and reads actual response identity from the adapter's provider-envelope result.
Unknown provenance cannot enable delivery. Stable alias/backend differences are represented
by the contract; the existing production AI adapter still enforces its own model matching policy.

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

`local_observe.observer.telegram.Telegram` implements the replaceable channel interface used
by `DeliverySession` and the optional CLI scheduler wiring. It uses a fixed
`https://api.telegram.org` host, disables proxies
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
`AcceptedQuality` is the supplied protected-file verifier; there is no default-true verifier.
The binding includes schema,
the exact observer configuration SHA-256, actual response model, cycle SHA-256, fixed
channel, allowed chat/user IDs, optional trusted review URL, daily budget, full channel
configuration hash, provenance hash and delivery epoch. `cycle['config_sha256']` is computed by
the production observer as the canonical SHA-256 of `dataclasses.asdict(config)`.
`review_base_url` can name an operator-controlled HTTPS review route; the adapter appends
the validated cycle ID. A finding without numeric context requires this URL, otherwise
delivery is refused before reserving budget. No telemetry or model text supplies URLs.

Store channel JSON in an owned mode-0600 file in a private mode-0700 directory:

```json
{"schema_version":1,"mode":"telegram","token_file":"/private/telegram-token","chat_id":42,"user_id":7,"daily_limit":2}
```

Guided setup's `mode: recording` channel remains offline. Before enabling Telegram, an
OS-authenticated human must review an evaluation schema-v2 report from three complete runs
with the exact operator Config and complete, identical runtime provenance. Generated/demo
corpora, demo-default Config, unknown measurements, incomplete baselines and model drift are
refused. The report must meet precision >=0.7, at most two findings/day, flip rate <0.1 and
at least one novel correctly detected class. The separate human attestation must establish
independent held-out labels; the report's origin label cannot establish that itself.

The report must retain its complete normalized measurement corpus, canonical findings and
aligned decisions for all three runs. Acceptance recomputes scores, novelty and flip rates,
checks the summaries and verifies corpus, source and configuration hashes. Both observer
and baseline settings must be operator-supplied. Every configured observer source and cycle
window must be covered; a repeated cycle verdict is counted once, regardless of source count.
Reports without this measurement envelope require a fresh evaluation. They contain telemetry
and independent labels and must stay in protected storage.

```sh
python -m local_observe.observer --state /private/observer quality-accept --config /private/observer.json --environment /private/observer-environment.json --channel /private/channel.json --report /private/evaluation/report.json --output /private/observer/accepted.json --expires-at 2026-02-01T00:00:00Z --attest-independent-held-out-labels
python -m local_observe.observer --state /private/observer serve --config /private/observer.json --environment /private/observer-environment.json --channel /private/channel.json --acceptance /private/observer/accepted.json --report /private/evaluation/report.json
python -m local_observe.observer --state /private/observer delivery-status
python -m local_observe.observer --state /private/observer reconcile --session CURRENT_SESSION_ID --epoch FRESH_UUID --attest-external-effects-reconciled
```

Replace the illustrative expiry with a future UTC instant at most 30 days away. The report
and receipt must be protected regular files. The receipt pins exact report bytes, Config,
provenance, OS UID, channel/budget, attestation and expiry. This is an OS-account trust
boundary, not a digital signature or a model-generated approval. The verifier rereads both
files before delivery. Changing implementation, model metadata, policy, Config, report or
channel requires fresh evaluation and acceptance as applicable.

Every new process starts disarmed, including after restore. Starting `serve` prints a fresh
one-hour session challenge; reconcile it from another terminal after checking external
effects. Persisted acceptance cannot rearm the process. A fresh UUID invalidates old phone
callbacks. Only cycles created after activation may send; retained cycles cannot be resent
by choosing a new epoch. Without `--used-today-floor`, delivery waits until the next UTC day.
For same-day operation, a human can explicitly supply the total sends already spent today
including those absent from a restored database. The value must cover retained reservations
and previous confirmed spend floors and cannot exceed the daily budget. In the Python API, pass the same value to
`arm_after_reconciliation(epoch, now=..., used_today_floor=...)`.

For one new cycle, `deliver NEW_CYCLE_ID` takes the same Config/environment/channel/acceptance/
report options and optional `--used-today-floor`. It requires a real interactive terminal
and the human to type the fresh displayed challenge, then collects a new cycle and attempts
delivery. It cannot dispatch an existing cycle. `serve` polls feedback at most every 30
seconds and checks reconciliation before starting each new scheduled cycle. A slot already
recorded before reconciliation remains ineligible; the next fresh slot can send.

`disarm` immediately invalidates the running session's epoch. `quality-revoke` takes the
Config/environment/channel/acceptance options and records revocation in the journal.
Expiry, changed bindings, revocation, or post-acceptance reviewed correctness below 0.7
returns the session to shadow. The correctness calculation uses the latest independent
human grade for delivered matching-provenance cycles; unknown and unsure are reported
separately and excluded from the known denominator. No known grades means unknown
precision, never measured success. A new process and reconciliation are needed after demotion.

Missing or invalid optional channel/acceptance/report files at `run` or `serve` startup produce
an explicit `delivery_startup_failed` shadow diagnostic while recording continues. A failure
during delivery or polling, including a hard deadline or an unavailable report, also demotes
the session and invalidates its send epoch. The subsequent observation cycles continue.
Restoring the file or channel does not automatically arm the session; start a new process and
reconcile again. Manual `quality-accept` and `deliver` commands still refuse invalid inputs.
Intentional process interruption is preserved. A failure of the recording journal itself
cannot be made safe by an optional-channel fallback.

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
are still required. Quick phone grades leave `review_seconds` null. Each bot should belong to this integration, because Telegram polling
cursors are shared by all consumers of a bot.

Backups include delivery outcomes, spent reservations, cursor, callback consumption and
grades in the same SQLite database. An older backup cannot prove which external effects
happened after it, including sends or revocations: reopening stays disarmed, and operator
reconciliation is required before a fresh epoch. Unknown same-day spend defers new sends
until the next UTC day. This is an intentional restoration boundary, not exactly-once delivery.

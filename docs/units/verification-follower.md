# Automatic verification after execution

The follower reads terminal executions from the platform, samples the signal
captured when each action was proposed, and submits a durable observation for
the server to judge. A successful process can therefore have a `not_cleared`
verification record beside its `succeeded` execution. The follower never
dispatches actions, approves them, emits recovery events or closes incidents.

**It makes one automatic observation per execution, including `unknown` and
`not_cleared`.** Discovery excludes executions with any verification record.
This is not a retry-until-cleared monitor. An authorized operator can submit
additional observations through the existing manual `verification submit`
command. Transport retries below repeat only the identical saved observation.

Configure one follower with a shared cursor per deployment. Separate cursors
or concurrent manual submissions can race and create multiple valid records.
Discovery grants no distributed claim or global exactly-once guarantee.

## Enablement and configuration

The default is off. With no `--config` and no nonblank `LO_VERIFY_FOLLOW_CONFIG`,
both entry points return zero without reading files or credentials, constructing
clients, opening a cursor, querying telemetry or sleeping, even with `--loop`.
The existing `verification` CLI and legacy `LO_VERIFY_CONFIG` worker are unchanged.

Enable one bounded round with:

```text
python -m local_observe.platform.verification_follower --config /etc/local-observe/verify-follow.json
lo-platform verify-follow --config /etc/local-observe/verify-follow.json
```

Both accept explicit `--loop --interval 30` for repeated bounded rounds.
The interval is 5..3600 seconds, defaults to 30, and is a delay after a round
finishes. Every round reloads configuration and the cursor; failures are visible
and retained pending statements are retried on the next round. No mutable
in-memory cursor carries across rounds. Stopping the process releases the
kernel-held cursor ownership lock. No service or component is enabled by this
code change; deployment remains an explicit follow-up.

The mounted JSON configuration contains only endpoint details and credential
file references. It accepts these fields, and no others:

```json
{
  "schema_version": 1,
  "platform_url": "https://platform.example.com/platform",
  "platform_token_file": "/run/secrets/verification-token",
  "cursor_path": "/var/lib/local-observe/verify-follow.json",
  "store_url": "https://store.example.com",
  "store_user": "lo-query",
  "store_password_file": "/run/secrets/store-read-password",
  "page_size": 16,
  "timeout": 10,
  "ca_file": "/etc/local-observe/platform-ca.pem",
  "store_allow_http": false
}
```

The first seven fields are required. Paths must be absolute, with an existing
writable parent for the cursor; Windows deployments use their own absolute
paths. Cursor, platform token and store password paths must be distinct.
`page_size` defaults to 16 and is bounded to 1..32. `timeout` is the platform
HTTP timeout, 1..20 seconds, default 10. Optional `ca_file` supplies the platform
CA; omitting it uses the existing transport's certificate verification. The
platform URL requires HTTPS and may include its configured path prefix.
`store_url` names the ClickHouse root endpoint, with no query or credentials in
the URL. Its separate read-only credential is loaded through the existing
`store_from_environment` adapter, using these explicit fields rather than
uncontrolled environment overrides. That backend retains its existing ten-second
request timeout and TLS behavior. `store_allow_http` defaults false and enables
only that backend's existing explicitly configured internal HTTP mode. It never
weakens the platform's HTTPS requirement.

The platform token's identity must be an existing producer named in the mounted
verification policy's `verifiers` list. This adds no role or permission. No
raw-token argument, environment token fallback, local `--database`, arbitrary
SQL, resource discovery or latest-policy lookup is provided.

## Sampling and durable delivery

`tick(settings, platform, store_factory, now=aware_datetime)` owns one cursor
lock and handles at most one discovery page. It calls:

1. `GET /v1/verification/candidates?limit=N[&after=UUID]`.
2. `GET /v1/verification/binding?action_id=UUID` for each candidate.
3. The named telemetry query described by that captured binding.
4. `POST /v1/verification/records` for each saved six-field statement.

The binding's digest, exact mapping, cited event and action target are checked
before use. Only the captured resource, metric name, rule and artifact pin
select telemetry. The read window is `[now - captured_window_seconds, now)`;
its start must be at or after the terminal `finished_at`. An immature execution
is skipped until a later sweep. The server also requires the deciding sample
to be strictly after the terminal boundary, and alone derives the verdict.

`observation` converts a typed `ReadOutcome` to exactly `execution_id`,
`binding_id`, `window`, `outcome`, `receipt`, `samples`. Actual sample identity,
value and timestamp are preserved; arbitrary labels and backend detail text
are omitted. The receipt retains its six existing fields. Genuine unavailable
or expired outcomes carry no rows and produce server-derived `unknown` records.
Malformed or foreign-scope receipts/rows are refused without a POST; they are
not repaired into an apparent reading. A fixed warning names the validated
execution ID and error class so an operator can locate the candidate. The page
still advances, and the refused candidate is eligible on a later sweep.

The telemetry facade can return 2,000 rows; a record can retain only 20. Every
returned row is validated before taking an excerpt, including rows beyond the
retained 20. A larger valid read retains its first 20 rows and **original**
`sample_count`, and sets `truncated: true` to state the client-side excerpt.
Original truncation is preserved even on a smaller result. The server therefore
records `unknown`, never a fabricated clearance from an incomplete answer.

Before the first POST the follower saves all statements for the page, their
fingerprint, next-page cursor and next unacknowledged index. A private temporary
file is flushed and fsynced, atomically replaced, and its parent fsynced on
POSIX. Windows uses file fsync and atomic replacement under its owned lock.
Each acknowledged record advances only the saved index, after checking the
exact `{verification_id, created}` response: the ID must equal the digest of
execution, binding and normalized window, and `created` must be a boolean.
The page cursor advances only after the entire saved batch is acknowledged.

On restart or lost acknowledgement, pending statements are delivered unchanged
**before discovery or any telemetry read**. Even if evidence has since expired,
the server can recognize an already accepted exact retry without regrading it.
A permanent POST refusal or wrong acknowledgement keeps the pending batch and
returns a visible failure; later work waits until that delivery problem is
repaired. Nothing silently drops an owed statement or constructs a newer window.

The cursor is bounded JSON (1,114,112 bytes), bound to normalized configuration,
and validates every pending statement before use. Unknown fields, duplicate JSON
keys, nonfinite numbers, bad identifiers, inconsistent fingerprints, oversized
files and changed configuration are refusals without rewriting the cursor.
The config file is bounded to 16 KiB. Cursor permissions protect integrity;
its fingerprint detects accidental changes and is not a signature against an
actor who can rewrite the cursor and recompute hashes.

Discovery's `next_after` tracks scanned execution UUIDs rather than just eligible
items. An empty filtered page with a nonnull continuation advances. A null
continuation wraps to the start on the next sweep, so newly terminal executions,
future windows and UUIDs inserted behind the previous cursor are revisited.

## Verification and deployment boundary

`tests/test_verification_follower.py` exercises the named read conversion,
strict configuration/cursor limits, off-by-default module and CLI, two scheduled
rounds with lost acknowledgement, exact expiry replay, captured-policy stability,
page fairness and canonical durable records. Binding and record tests use the
real authenticated in-process API and Store; discovery pages there are explicit
contract fixtures. The separate discovery and integration tests exercise the
server's actual candidate endpoint. These are offline tests, not evidence that
a live follower or telemetry query is deployed and working.

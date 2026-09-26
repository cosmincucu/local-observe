# Unit: verification operator CLI (`platform/verification_cli.py`)

**File:** `local_observe/platform/verification_cli.py` — `add_parser(subparsers)` and `run(args) -> int`, plus
the two bounded file reads, the id/statement gates and the fixed output shapes.
**Registered by:** `local_observe/platform/cli.py` (one `add_parser` call, one post-parse dispatch — see
"Dispatch"; no other command's code moved). **Transport:** the existing `local_observe.http.JsonClient`,
unmodified — this module builds no client of its own, touches no TLS machinery and opens no socket directly.
**Authority:** the server — [verification api](verification-api.md) → `verification_records`' own gates → `Store`.
**Tests:** `tests/test_verification_cli.py`, `tests/test_verification_cli_boundary.py`.
**Item:** the verification CLI, the verification workflow's HTTP-only client slice (wave 11). Contracts only — nothing here claims a test
ran, a CI outcome or a merge.

## Purpose

The four verification routes have existed since the verification API and the durable records since #150, but reaching them
from a terminal meant writing Python: an operator could not ask "what did this action bind to?", "what was filed
for this execution?" or "file this observation" without a `Store` in hand — which for a remote platform is the
wrong tool entirely, and this slice must not become the right one by growing features. This module is a
**thin client of those four operations on three paths**: at most one request per invocation, one JSON answer
printed, a credential file read (plus a statement for submit), and verdict decisions left on the server.

The command remains a one-request operator client. Saved history is also available in the
execution UI. Automatic discovery and durable delivery retries belong to the separate
[follower](verification-follower.md); they do not change this CLI's four operations or enable
incident resolution.

## Public command

```
python -m local_observe.platform.cli verification \
    --url https://edge.example.test/platform \
    --token-file /config/verification-token \
    [--timeout 5] [--ca-file /config/platform-ca.pem] \
    OPERATION
```

`lo-platform` is the same `cli.main`, so the group is spelled identically from the console script. The base URL
may keep an operator path prefix (`/platform` above) — `JsonClient` concatenates base + request path and this
module neither strips nor re-adds one. All identifiers and names below are synthetic.

| operation | the one request it makes | the id it takes |
| :-- | :-- | :-- |
| `binding --action-id 4f2b1a63-9c7d-4d5e-8a1b-2c3d4e5f6a7b` | `GET /v1/verification/binding?action_id=…` | 36-character canonical UUID |
| `records --execution-id b1e4c2d0-7a3f-4c68-9d21-0f5a6b7c8d9e` | `GET /v1/verification/records?execution_id=…` | 36-character canonical UUID |
| `record --verification-id f3d0e9c2b5a7461f8e4c0d2a6b5f4e3d1c0b9a87968574635241f0e1d2c3b4a5` | `GET /v1/verification/record?verification_id=…` | 64 lowercase hex (SHA-256) |
| `submit --statement /tmp/statement.json` | `POST /v1/verification/records` (the validated object as the payload) | — the file holds the six-field statement |

```
… verification --url https://edge.example.test/platform --token-file /config/verification-token \
    binding --action-id 4f2b1a63-9c7d-4d5e-8a1b-2c3d4e5f6a7b
… verification … records --execution-id b1e4c2d0-7a3f-4c68-9d21-0f5a6b7c8d9e
… verification … record  --verification-id f3d0e9c2b5a7461f8e4c0d2a6b5f4e3d1c0b9a87968574635241f0e1d2c3b4a5
… verification … submit  --statement /tmp/statement.json
```

The `submit` body is the statement `verification_records` already defines —
`{execution_id, binding_id, window, outcome, receipt, samples}` and nothing else — e.g. an execution id, a
lowercase binding digest, a `{"start": "2026-09-08T12:15:00+00:00", "end": "2026-09-08T12:20:00+00:00"}`
window, `"outcome": "available"`, a receipt and at most 20 sample rows. Field-by-field bounds belong to
[verification records](verification-records.md); this file duplicates none of them.

## What the group has no flag for, and why

| absent | the reason |
| :-- | :-- |
| `--database` (refused *for this group*, see "Dispatch") | a remote verifier has no local database, and a flag that looks available would be an invitation to open one |
| `--token`, and any `LO_*`/environment fallback | the credential is a **file the operator mounts**: `--token-file /config/verification-token`. Its value never appears on a command line, in a process list, in the environment or in this module's output; nothing here prints or logs it |
| `--allow-http`, `--insecure`, `--no-verify` | HTTPS is the only scheme that reaches `JsonClient` here (`allow_http` stays at its `False` default), and a custom trust anchor is `--ca-file`, which `JsonClient` itself adjudicates. An insecure escape hatch on the one command that carries a producer credential is the thing the transport was written to refuse |
| stdin statement, `--output` | one file in, stdout out. A statement read from a pipe would be a byte source this slice does not bound, and an output file is a second place to put server bytes nobody asked to keep |
| `--retries`, `--backoff`, `--wait` | one request per invocation, including on failure. A retry here would be a second writer of an immutable record nobody authorised |
| `--source`, `--actor`, `--role` | attribution is the identity the **server** maps from the bearer credential; a local flag claiming an identity would be a lie the caller chose |
| `--policy`, `--now`, `--verdict` | no policy loading, no clock, no grading, no verdict word: the server derives `cleared`/`not_cleared`/`unknown` and this client cannot pre-empt it |

## Dispatch — the one change to an existing file

`cli.main()` registers `verification_cli.add_parser(sub)`, makes the global `--database` **syntactically
optional**, and then, immediately after `parse_args()`:

* `verification` **and** a provided `--database` → `parser.error` (exit 2), and
* `verification` alone → `return verification_cli.run(args)`.

That return happens **before** any local operational configuration is touched: no `Store` construction, no
`NotificationPolicy`, no `notification_mode()` and therefore no `LO_NOTIFICATION_MODE` read, no code-pin or
other environment/policy file read. (Importing `Store` at module level is not constructing it.) Unknown,
missing or conflicting syntax for this group is argparse's own exit 2 — before any file read or request.
Option abbreviations are disabled for this group and its operations; `--token` is not `--token-file`.
Every other subcommand still ends in `parser.error` without `--database`: same exit code 2, same refusal on
stderr, with the sentence now coming from that post-parse check instead of argparse's required-argument
message. Peer commands and flags — `status`, `migrate`, `backup`, `intake`, `evaluate`, `drift`, `notify`,
`conditions`, `pathcheck`, `escalate` — are unchanged in behaviour, including the neighbouring `pathcheck`
group, which this card only asserts still refuses without a database rather than edits.

## One request, and the bounds that come with it

Once input/configuration preflight passes, an invocation makes **exactly one** `JsonClient.request`: one GET for the three reads, one POST for
`submit`. Failures included — a refusal, a timeout, a lost acknowledgement — never a second attempt inside one
invocation. Inherited from the shared client, unchanged, and deliberately not restated as this module's own:

* request timeout `--timeout`, an **integer 1..20**, default `10`;
* response read capped at **4 MiB**, and the client's existing JSON decoding;
* `https` only here, no embedded credentials/query/fragment in the base, no redirects followed, no environment
  proxies, one `Authorization` bearer header carrying the token read from `--token-file` and nothing else;
* a token of at least 24 characters is checked twice — here for the printable-ASCII rule, by `JsonClient`
  for its own bound.

A non-integer timeout is a syntax refusal (exit 2). An integer outside 1..20 is a transport-configuration
refusal (exit 1), before any request, not a promise of no preceding local file read.

Query text is built from a value that already matched its exact shape, so it needs no percent-encoding and can
carry no `?`, `&`, `#`, `..`, or `/` — which is what keeps the request inside the strict single-pair parser the
routes run. An invalid id is refused locally; nothing is "normalised" into a spelling the server might accept.

## Files read

**`--token-file`** — at most 4097 bytes of binary read (the extra byte is how "over 4096" is detected), a
regular file required (`fstat`; `os.open(O_NONBLOCK)` avoids waiting for POSIX FIFO writers;
`O_BINARY` prevents Windows CRLF/Ctrl-Z translation), 1..4096 raw bytes, strict UTF-8,
outer whitespace stripped, and the result must be 24..4096 bytes of
printable ASCII with no space (`0x21..0x7e`). A missing file, a directory, a FIFO, an oversize file, invalid
UTF-8 or an out-of-range token is one fixed local error; the content is never echoed. **No permission or symlink
policy is invented here**: an operator-selected regular file may be a symlink to a regular file, and no
symlink/TOCTOU guarantee is claimed either way. File opens/reads do not have an elapsed-time deadline;
the HTTP timeout does not bound a slow filesystem or a Windows device/named-pipe open.

**`--statement`** — the same regular-file/bounded binary read, raw bytes at most
`verification_records.MAX_RECORD_BYTES` (32 768), strict UTF-8, one JSON object with duplicate keys refused at
every nesting level and no non-finite constant, float overflow, signed-64 overflow or recursion failure
accepted (the storage layer's `INTEGER_LIMIT` is reused, not restated). Then `verification_records._incoming`
checks shape, finiteness, depth, item/node and canonical-byte bounds — the same storage validation
used by the service. Its normalized return is ignored: the original parsed document is sent.
A structurally invalid statement is refused before any request; no state-dependent verdict is computed. `OSError` and decode failures
become fixed errors naming no path.

Ordering is the contract: **ids and the statement are validated before the token file is opened or the client
is constructed**, so bad input spends no token read and no request.

## Answers and exit codes

| outcome | stdout | exit |
| :-- | :-- | :-- |
| `200` with a JSON **object** | that object, unchanged, `json.dumps(indent=2, allow_nan=False)` | `0` |
| `200` with a non-object or non-finite document | `{"status": "error", "error_type": "VerificationCLIError"}` | `1` |
| any other status (`400`, `403`, `404`, `409`, `413`, `500`, `503`, …) | `{"status": "error", "error_type": "VerificationHTTPError", "http_status": <status>}` | `1` |
| bad id, bad/unreadable file, config or transport failure, output refusal | `{"status": "error", "error_type": "VerificationCLIError"}` | `1` |
| unusable CLI syntax | argparse's own stderr message | `2` |

Success output is the server's document: no field is added, renamed, defaulted or dropped, and no success is
synthesised — stored-document reads (`created: false` replays, `unbound` bindings, `unknown` verdicts) print
exactly as the service answered. Failure bodies carry a class name and, for an HTTP failure, the status: never
a raw server body, a driver message, a traceback or exception cause, a token, a request/response document or a
local path. `JsonClient` discards HTTP error bodies by design, so **this client cannot tell
`verification_busy` from `verification_unavailable` when both are `503`** and must not be documented or tested
as if it could. It likewise makes no claim of strict duplicate-key rejection of a *response* — that bound
belongs to the request-side parser only, and the client's decoder does not provide it. Nothing from this group
is routed into `cli.py`'s `DEBUG` traceback logger; only the expected exception classes are caught, so a
programmer bug stays a bug, and `KeyboardInterrupt`/`SystemExit` propagate. HTTP protocol exceptions
(including truncated responses and invalid ports) become the same fixed local error without a retry.

## Server authority, and what an answer is not

Role, policy presence, execution state, binding identity, replay/first-write (`created`), the verdict and every
`StateError` sentence are decided by the service; the status map is the verification API's table. A `403` means this
credential's identity is not a verifier the current policy names (or may not read), a `503
verification_unavailable` means the deployment has no policy mounted, a `409` means the execution is still
executing / the record cap is reached / the same id carries different bytes, and a `400` may be a scope
refusal this client never saw the shape of. The verifier behind a submission is a name like `verify-worker`
(synthetic), and it is a word the **server** reads out of the mounted credential's mapping against the current
policy's `verifiers` list — never something the command line states, which is why there is no `--source` here.
The client adds no second opinion: no local policy file, no
grading, no timestamp rewriting, no verdict word, no "accepted" of its own.

`Keep submitted semantics unchanged` also limits what the client may promise about bytes on the wire:
`JsonClient` sends `canonical(payload)`, so the request is a canonical JSON encoding of the validated object,
not a byte-for-byte copy of the operator's file (key order and number spelling may move; the statement's
meaning does not).

## A submit that is not answered

Any failure of `submit` — timeout, refused connection, `5xx`, an unreadable or unexpectedly-shaped `200` —
leaves one question open: **the server may still have accepted the record.** So this slice never retries
inside an invocation, and never says *rollback*, *rolled back*, *not submitted* or *safe to re-send* — none of
which it can know. The operator's own procedure is the whole answer available here: read the state back with
`records --execution-id …` and `record --verification-id …`, and resubmit the **unchanged** statement file if
the record is absent — storage folds an identical normalized statement into `created: false` with the original row untouched, and
answers a changed statement under the same id with a conflict. Pending-state durability and an automatic exact
replay are the rest of the verification workflow and are **not** provided here: each invocation is independent, and a lost acknowledgement stays a question until an operator looks.

## Debt and what is not here

* **No producer enablement, no deployment.** Nothing ships a manifest, systemd unit, example fragment,
  `LO_*` variable, mount or secret entry for this command, and no credential is created or named for a service.
  It is run by an operator who already has an HTTPS endpoint and a mounted verifier credential.
* **No local state at all**: no database path is opened or created for a GET or a submit, no cache, no
  cursor, no receipt, no pending file. Consequence: this command keeps nothing to replay from, which is exactly
  why the ambiguity above belongs to a follower and not to it.
* **Separate consumers.** The execution UI reads saved history, and the follower keeps its own
  pending delivery. This CLI starts neither; `verification.py` still files only its evidence row.
* **No extra control-plane actions.** The three GETs are the same routes an ordinary reader
  token uses; the one write is `submit`. Nothing here can decide, claim, retry or resolve anything, and no new
  role, token kind or route is introduced — these four operations retain their existing paths. The additional candidate route is for the
  follower and is not exposed as a fifth CLI operation.
* **Bounds are inherited, not owned.** If `JsonClient`'s 4 MiB read cap or 1..20 s window ever changes, the
  numbers above and this unit's tests move with it — but this card neither widened nor copied them.
* `tests/test_verification_records.py`'s synthetic statement fixtures are the intended starting point for the
  `submit` cases; this slice must not re-invent hundreds of setup lines to file one record.

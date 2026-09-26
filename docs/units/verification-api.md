# Unit: verification routes (`platform/verification_api.py`)

**File:** `local_observe/platform/verification_api.py` (the owned paths, the strict parser, the status map,
the one off-loop slot). **Mounted by:** `api.create_app` (see "Wiring").
**Reads/writes through:** `Store.get_verification_binding`, `Store.list_verifications`,
`Store.get_verification`, `Store.put_verification`. **Authority owned by:** `verification_records._reader` /
`_writer`. **Tests:** `tests/test_verification_api.py`, `tests/test_verification_api_boundary.py`,
`tests/test_verification_factory.py`. **Item:** the verification API. Called from a terminal by
`platform/verification_cli.py` (see [verification CLI](verification-cli.md)).
Contracts only — nothing here claims a test ran.

## Purpose

`verification_records.py` judges a submitted observation and `verification_reader.py` discovers the ids one
execution carries, but neither was reachable over HTTP: a verifier had no way to file an observation, and a
reader holding an execution or a verification id had no way to ask the service about it. This module is that
missing edge and nothing more — five operations, one path set, one worker. It runs no SQL, derives no verdict,
owns no schema, mints no role, reads no environment value and writes no audit row of its own. Every
durable decision stays with `Store`.

## API

`owns(path)` is membership in a four-literal set — no prefix matching, so no other path under
`/v1/verification/` is adopted by association. Everything else is `VerificationAPI(store)`:

| route | answer |
| :-- | :-- |
| `GET /v1/verification/binding?action_id=<canonical UUID>` | the stored binding document, `200` |
| `GET /v1/verification/records?execution_id=<canonical UUID>` | `{"verification_ids": [...]}` — ids only, `200` |
| `GET /v1/verification/record?verification_id=<lowercase SHA-256>` | the exact stored document, `200`; never recorded → `404` |
| `GET /v1/verification/candidates?after=<UUID>&limit=<1..32>` | bounded producer-only `{items, next_after}`; both query parameters optional |
| `POST /v1/verification/records` | `Store.put_verification`'s own `{verification_id, created}`, `200` for a first acceptance **and** for an exact replay |

`async handle(scope, receive, actor) -> tuple[int, dict] | None`. `None` means "not mine" (a path `owns`
rejected), so the caller can continue routing, or "the caller hung up mid-body", which sends nothing. Bearer extraction
stays in `api.py`: this seam sees an authenticated `Actor` and no token. `close()` shuts admission
synchronously; `async wait_idle()` returns once this instance's synchronous work has really ended.

No query string on the POST. The three record/binding GETs admit exactly one `name=value` pair — the name that route names, no
duplicate, no blank, no extra, at most 256 raw bytes, ASCII-decoded strictly and percent-decoded strictly
(no `urllib.parse`: it replaces undecodable bytes and reads `+` as a space), then type-and-length bounds,
then `state.identifier`/the SHA-256 rule. A recognized path with an unsupported verb is `405` with no body
read, no slot and no database; summary credentials retain their earlier 403. The submitted body is the six-field record itself: no envelope, strict
UTF-8 (decoded *before* `json.loads`, so a UTF-16/32 BOM is a refusal rather than a sniff), one JSON object,
no duplicate key at any level, no `NaN`/`Infinity`, no `1e400`, no integer past signed-64, no nesting deep
enough to threaten the interpreter, at most 32 768 raw bytes checked before concatenation. Everything past
that point — field names, bounds, scope, the verdict — is `verification_records`' judgement on its own
`MAX_RECORD_BYTES`, and this file duplicates none of it.

## Authority and errors

`summary` is turned away with `{"error": "summary_only"}` before `receive()` and before storage. Reads use
`verification_records._reader(policy, actor)` and writes `_writer(policy, actor)` — the same call the
storage layer makes again before opening its transaction, so the role and allowlist vocabulary exists once.
Ordinary reading is never gated on a mounted policy (off is write-off), and a `producer` may read only
while the current policy names it.

Statuses are chosen by comparing `str(StateError)` against **imported constants**, never against
`api.stable_code`'s substrings, because three of these sentences come from one module and mean three
different statuses:

| fault | answer |
| :-- | :-- |
| `BAD_ACTOR` / `require`'s sentence | `403 not_authorised` |
| `NO_POLICY` (a producer with nothing mounted) | `503 verification_unavailable` |
| `UNKNOWN_ACTION`, `UNKNOWN_EXECUTION`, a valid id never recorded | `404 not_found` |
| POST `RETRY_CHANGED`, `EXECUTING_EXECUTION`, `RECORD_LIMIT` | `409 conflict` |
| any other POST `StateError` | `400 invalid_request` (the storage sentence, if it is one this build knows) |
| any GET `StateError` after the identifier was accepted | `500 verification_storage_error` |
| `NEEDS_MIGRATION`, `BAD_STORED_BINDING`, `BAD_STORED_EXECUTION`, `BAD_DERIVATION`, `BAD_CLOCK`, `RECORD_TOO_LARGE`, `verification_reader.READ_FAILED` | `500 verification_storage_error` |
| a driver error, or JSON/Unicode corruption while re-reading a stored document | `500 verification_storage_error` |
| syntax (query, body, size, query-on-write) | `400 invalid_request` / `413 body_too_large`, fixed detail |
| anything nobody chose (`TypeError`, `KeyError`, …) | propagates to `api.py`'s existing 500 handling |

A `500` body is the fixed `{"error": "verification_storage_error"}`: no driver text, no path, no request, no
payload — and the one log line it produces carries the exception class only. A `detail` is echoed only when
the sentence is one of the known constants (`KNOWN_SENTENCES`), so a message this build has never reviewed
cannot reach a body. No refusal on these routes audits anything: a verification submission is not an action
attempt, and the only row a success adds is `Store`'s own `verification.recorded`.

## Lifetime

One `VerificationAPI` per app instance, built with a `Store` and nothing else: **no thread, no executor, no
loop and no policy document at construction** — the pool appears the first time a request needs one, so an
app that is built and thrown away, or served only through direct ASGI calls, costs no thread.

* **Capacity is one actual synchronous `Store` callable, and there is no queue.** Parsing and authority run
  first; then availability is tested and `ThreadPoolExecutor(max_workers=1).submit` happens under one
  `threading.Lock`, with no `await` and no lock release between them. Anything that cannot get the slot —
  busy or closed — is `503 verification_busy` with a fixed body, immediately.
* **The `concurrent.futures.Future` is the completion authority.** The slot is free when that future reports
  `done()`, which for a concurrent future means the callable returned, raised, or provably never started
  (`Future.cancel()` is refused once the item began). The request awaits it through `asyncio.shield`; the
  wrapper is never cancelled by anything in this module, so no cancellation path reaches the work.
  Detached outcomes are consumed by a done-callback.
* **Cancellation and disconnect free nothing.** A disconnect before the body is complete returns `None` —
  no response, no write. A cancellation after admission abandons that answer only: the slot stays claimed,
  the write commits or fails on its own thread, and the next request still sheds until then.
* **`close()` is `shutdown(wait=False)` and never `cancel_futures`.** A queue item already admitted still
  runs; `wait_idle()` is how the lifespan learns how it ended. `wait_idle` polls the future's own state
  (never a thread join, never a deadline) and re-raises a cancellation only after the callable has really
  finished — because that wait is what stands between the write and the owner lock being handed back.
* `api.py`'s drain must therefore await `wait_idle()` **before** `release_ownership()`, beside
  `refusal_dispatch.wait_idle()`.

## Wiring

`create_app`: import the module, build one `VerificationAPI(store)`, expose it as `app.verification_api` for
lifecycle tests the way `app.refusal_audit_dispatch` is exposed. Inside the authenticated `try`, **before**
the existing GET gate and before any POST body read: if `verification_api.owns(path)` then `await handle(...)`
and, unless it returned `None`, respond with the pair and return. `REFUSAL_POST_ROUTES`, the four audited
lifecycle routes, `Store.records()`' allowlist and every existing route stay untouched — a producer admitted
here is admitted to these three paths only, not to `GET /v1/me` or anything else. In lifespan cleanup:
`verification_api.close()` beside `refusal_dispatch.close()`, and `verification_api.wait_idle()` in the drain
ahead of the owner release, under the existing protected-cleanup rules.

## Limitations (none fixed quietly)

* **Service only.** `create_app` mounts these routes and `app_factory` loads the optional policy before
  Store construction. The verification API shipped no client of its own; the verification CLI adds one —
  `platform/verification_cli.py`, an HTTPS-only operator command that calls exactly these four routes and
  changes nothing in this file ([verification CLI](verification-cli.md)). The verification history view added a second reader,
  also without changing anything here: the operator UI's execution detail offers a **read-only** verification
  history, one `GET /v1/verification/records?execution_id=…` behind an explicit click and one
  `GET /v1/verification/record?verification_id=…` behind a second one, rendering only verdict, reason,
  observation window and recorded time as a *historical recorded result* (see
  [`local_observe/platform/README.md`](../../local_observe/platform/README.md)). That reader posts nothing,
  polls nothing, never reads `/v1/verification/binding`, and treats 403/404/503/500, an unreadable or
  over-cap reply and a reply about another execution as distinct refusals to show anything; authority stays
  entirely in `_reader` and in this seam, so no role is widened by the UI reading these paths. Its own
  display bounds are shape only, taken from the contracts above and never re-derived into a verdict: ids
  are exactly 64 lowercase hex characters as a whole field and must arrive in the lexical ascending order
  `verification_reader._digests` answers in (an unsorted, repeated or newline-suffixed list is refused, not
  tidied), execution ids are 36-character canonical UUIDs, a reason must be a `state.label`-shaped **string**,
  and every instant must be the `utc_text` form read back as a real UTC calendar instant with
  `window.start < window.end <= recorded_at`. A reply it cannot account for is refused into its own state
  rather than shortened, re-ordered, re-graded or reinterpreted. No durable follower uses these routes yet;
  retains that work. No deployment or automatic recovery is implied.
* **Same-app loop only.** `asyncio.wrap_future` binds to the loop that awaits, so one app must be driven
  from the loop that serves it. No cross-thread application use is promised.
* **Busy is not a queue.** Under concurrency one caller is admitted and the next is shed with a 503 and no
  retry hint, no counter and no `Retry-After`: capacity tuning, counters and operator visibility for this path are
  not in this slice, and adding a queue would be a second buffer in front of a locked file.
* **No new observability.** `GET /v1/runtime` reports nothing about this seam — no admitted/shed tallies, no
  slot field. `slot_busy` and `closed` exist for lifecycle tests, not for a report.
* **No new operation or drain deadline.** Existing SQLite connection/busy timeouts remain unchanged;
  those do not bound every possible filesystem stall. The bound here is one callable, not its duration.
* `RECORD_LIMIT` as a 409 is reached from the writer's own cap; this seam only maps the sentence.

## Candidate discovery (cards 75/123)

The fourth literal path, `/v1/verification/candidates`, calls the read-only
`verification_candidates.list_candidates` helper directly with this service's Store.
It uses the existing off-loop slot, never a second Store or execution queue.
`_writer` authorizes a currently listed producer before query parsing and is checked
again inside the helper before SQLite opens. This authority is intentionally narrower
than the other GET routes: a reader credential cannot enumerate eligible executions.

Optional `after` is a canonical UUID; optional `limit` is canonical unsigned decimal
1..32 (default 16). Both may appear once, in either order; unknown, duplicate or blank
parameters, invalid percent encodings, and over-256-byte queries refuse before the slot.
The answer is exactly `{items, next_after}`, where each item has `execution_id`,
`action_id` and the actual terminal `updated_at` as UTC `finished_at`. `next_after`
advances across raw scanned executions, including ineligible ones, and null means the
end of a sweep. A later sweep restarts to observe new UUIDs or newly terminal runs.
See [candidate discovery](verification-candidates.md) for bounds, corruption checks and
why accepted record payloads are not regraded. Existing ID-only record discovery,
manual submissions and stored history retain their contracts unchanged.

# Unit: bounded verification id discovery (`platform/verification_reader.py`)

**File(s):** `local_observe/platform/verification_reader.py` (the only SQL this read runs, its bounds, the
read-only connection), `local_observe/platform/state.py` (`Store.list_verifications`, a delegation seam and
nothing else). **Tests:** `tests/test_verification_reader.py` (lifecycle, reopen, empty/unknown, role
authority, byte stability), `tests/test_verification_reader_boundary.py` (bounds and indexed-query cost),
reusing the fixture in `tests/test_verification_records.py`. The verification history reader.
**Contracts only — nothing here claims a test ran.**

## Purpose, and the one question it answers

`Store.get_verification(verification_id, actor)` reads one stored document by its exact id, and that id is
`digest([execution_id, binding_id, normalized window])` — so an operator or a later service holding only an
execution had no way to ask *which* verifications this run carries without already knowing the binding and
every window. This unit answers that one question: `Store.list_verifications(execution_id, actor)` returns
`list[str]`.

**IDs only.** No payload, metadata, verdict, reason, timestamp, claim, token, sample or action record leaves
this read; each id returned is then read one at a time through `get_verification`, which stays the only way
to see a document. Nothing here re-reads, re-grades or re-decides an accepted result, no execution, action
or incident state moves, and `verification.recorded` audit rows are neither written nor implied.

Since the verification API a service does offload this read: `GET /v1/verification/records?execution_id=` answers from it
through the application's single off-loop slot ([verification api](verification-api.md)). That wiring adds no
second query, no second bound and no new authority test — the route calls `Store.list_verifications`, which
delegates here. Listing and subsequent exact reads are separate transactions. Existing records stay stable
because the tables are append-only; records added after the list's snapshot require another list call.

The [verification CLI](verification-cli.md)  is now a remote caller of that same route: one
`GET /v1/verification/records?execution_id=` per invocation, the server's answer printed unchanged, no local
database, list, cache or cursor kept to reconcile later. The operator can read returned ids individually with
the separate `record` command; no automatic follow-up request occurs. It adds no bound, ordering or authority test here, The execution UI also reads saved history. The separate [candidate scan](verification-candidates.md)
feeds the [follower](verification-follower.md); it does not replace this exact execution-ID lookup.

## Authority (owned by `verification_records.py`, not copied)

The gate is `verification_records._reader(policy, actor)` itself, called **before** any database is opened:

| actor | admitted |
| :-- | :-- |
| `reader`, `human`, `proposer`, `executor` | yes, with or without a policy mounted |
| `producer` | only while the *current* policy names that identity as a verifier |
| `summary`, any other role, a non-`Actor`, an `Actor` whose identity is not a bounded `label` | refused, no connection opened |

Ordinary reading is never gated on a policy being mounted (off is write-off, not read-off), and no policy is
consulted for a non-`producer` reader. `verification_records.py` remains the single authorization and schema
vocabulary owner; this module imports `_reader`, `_ready`, `_identifier`, `_sha256` and the constants/sentences
`RECORDS_PER_EXECUTION`, `RECORD_LIMIT`, `UNKNOWN_EXECUTION`, `NEEDS_MIGRATION`, `BAD_VERIFICATION_ID` from
it. That coupling to same-package private helpers is deliberate: a second copy of the role test or the
"both tables" test is a second thing that can drift open while the first one still passes. `BAD_EXECUTION_ID`
restates `state.identifier`'s own sentence (`Expected canonical UUID`, the key `refusals.SENTENCES` maps to
`bad-identifier`) rather than inventing a second bad-UUID word.

## Order of decisions, and what each one costs

1. `_reader` — authority, from the actor and the in-memory policy alone. No file is named.
2. `_canonical` — the execution id must be a `str` of exactly 36 characters *and* then
   `verification_records._identifier`'s canonical UUID. The length/type test runs first so arbitrary caller
   text never reaches an identifier parser, and both failures are the one fixed bad-identifier sentence.
3. Open, `BEGIN`, `_ready`, existence, one bounded `SELECT`, `COMMIT`, close.
4. Validate the fetched id metadata in Python, then sort.

An unknown execution is a `StateError` (`Execution already terminal or absent`); a **known** execution with
no records answers `[]`. Those are different facts and only one of them is an error. An `executing`
execution is listable and usually empty — this read draws no conclusion about the run's outcome from
whatever it finds or does not find.

## The bounds

* **One statement, one bound parameter.** `SELECT typeof(verification_id), substr(CAST(verification_id AS
  BLOB), 1, 65) FROM verification_records INDEXED BY verification_records_execution WHERE execution_id=?
  LIMIT 65`. `payload` is never named, never `SELECT *`, and no `length()` runs over an unbounded payload:
  the widest thing transferred is 65 bytes of id. No `count(*)`, no full-table scan, no `OFFSET`, no action
  enumeration, no N+1 payload queries.
* **65 is the overshoot that makes two claims checkable.** It is `RECORDS_PER_EXECUTION + 1` rows and one
  byte past a legal id: enough to *see* an over-cap history and an over-length id, never enough to have to
  guess about either. The writer enforces 64 records per execution; more than 64 rows here means the file
  disagrees with the code that wrote it, and the answer is `RECORD_LIMIT`, not the first 64 ids. Silently
  truncating would present a partial list as the whole answer.
* **`INDEXED BY` is a refusal, not a hint.** `verification_records_execution` is the index `MIGRATIONS[4]`
  creates for this exact lookup; a file that lost it fails closed (`sqlite3.Error` → one `StateError`)
  instead of turning this read into an unbounded scan. There is no schema or index migration and no version
  bump: this unit reads the v4 file as it is.
* **No `ORDER BY` on a stored column.** Sorting before `LIMIT` could process an arbitrarily large
  corrupt over-cap history. The validated ≤64 ids are sorted in Python instead.
* **Lexical ascending, explicitly not chronology.** `recorded_at` is never read. A caller wanting order by
  time has to read the documents, which is `get_verification`'s job.
* **A corrupt row refuses the whole list.** `typeof` not `text`, bytes that are not valid UTF-8, more than
  64 bytes, or text that is not exactly 64 lowercase hex characters (uppercase included) → `StateError`.
  Nothing is repaired, omitted, replaced with a placeholder or returned as a shorter list, because a list
  that quietly drops a row is a claim that the remaining ids are all there were.
* **Defensive new list per call.** Ids are immutable strings and the list is rebuilt every call, so a caller
  that sorts, pops or appends to one answer cannot change another caller's or the file's.

## The connection

`sqlite3.connect(<resolved path>.as_uri() + '?mode=ro', uri=True, isolation_level=None, timeout=10)`,
wrapped in `closing`, with one explicit `BEGIN` — a **deferred** read transaction, never `BEGIN IMMEDIATE`
and never `Store.transaction()`, which takes the write lock and sets `journal_mode=WAL`/`synchronous=FULL`
pragmas a read has no business writing. The connection is closed before the list is returned: no
executor, thread, background task or held handle, and nothing in the lifecycle, refusal-audit or
notification paths moved.

Read-only means the refusals too: no schema migration, no write, no audit row, and **no new database on an
absent path** (a missing file is `unable to open database file`, normalized below, and the path stays
missing). Every `sqlite3.Error` — absent file, not-a-database, locked, lost index — becomes the one fixed
`StateError(READ_FAILED)` raised `from None`, so no driver text (which carries paths) reaches the caller.
This does not diagnose a migration requirement from an operational failure. An incomplete
verification schema (either table missing) is `NEEDS_MIGRATION`, a schema failure and never an empty answer.
Only `sqlite3.Error` is caught: a `TypeError` from a bug here stays a `TypeError`, and no `BaseException` is
absorbed.
SQLite may create WAL/shared-memory sidecars while reading an existing WAL database. This is not a
promise of zero filesystem bookkeeping; the reader issues no durable-state writes or journal-mode changes.
And this connection belongs to discovery alone: the binding read and the single-record read that the same HTTP
surface exposes run through the existing `Store` transactions, so no read-only-connection or
read-only-filesystem property may be inferred for them from this page.

Every refusal is one fixed sentence naming a field, a bound or a piece of platform state — never the input,
the path, a stored value or a chained exception. `Store.records()`' allowlist is unchanged (neither
verification table is in it), `api.py` grew no route **in this card** (the original four verification operations are
the verification API's, and they delegate here rather than duplicating it), and `refusals.SENTENCES` gains no entry:
this read is outside the four audited action attempts, so a refused list request writes no `action.refused`
row, exactly as a refused verification submission does not.

## Verification main runs (not claimed here)

Real lifecycle roundtrip and reopen for two separate executions; empty-known versus unknown versus
`executing`; every role, admitted and refused, with the refusals proven I/O-free; all returned ids readable
by an existing `reader` credential; over-cap (>64) and over-length (65-byte), nontext, non-UTF-8 and
non-hex stored ids; missing table, missing index, missing file, and a v3 file refused at open unchanged;
audit rows and file bytes unchanged across repeated discovery calls; and that the indexed read scales with
the records wanted rather than with unrelated history — `EXPLAIN QUERY PLAN` plus a progress handler over
synthetic rows.

# Unit: bounded audit history page (`platform/audit_reader.py` + `GET /v1/audit`)

**File(s):** `local_observe/platform/audit_reader.py` (the query grammar, the bounds, the cursor walk,
the only SQL this read runs), `local_observe/platform/state.py` (`Store.audit_page`, a delegation seam and
nothing else), `local_observe/platform/api.py` (the `GET /v1/audit` route inside the existing GET role
gate). **Tests:** `tests/test_audit_reader.py` (the unit
directly: query grammar, bounds, cursor arithmetic, oversized rows) and
`tests/test_audit_reader_api.py` (real authenticated ASGI calls, authorization, legacy-route byte
equality). The paged audit reader. Contracts only — nothing here claims a test ran.

## Purpose and the boundary it does not move

`GET /v1/records/audit` stays byte-for-byte what it was: `Store.records('audit')` is
`ORDER BY rowid DESC LIMIT ?` capped at 100, no offset, no filter, and it ignores unknown query fields.
That is the surface [refusal audit](refusal-audit.md) describes when it says a 64-row burst crowds older
rows out of the window an operator reads by default. This unit adds a **second** door rather than
widening that one: an explicit `GET /v1/audit` that walks the same append-only table backwards in
bounded pages. No legacy read changes shape, limit behaviour or bytes, and no page field reaches the
legacy route.

## Route, roles, and what a request may say

`GET /v1/audit`, served under the GET authorization that already exists — `reader`, `human`, `proposer`
and `executor` read it; `summary` gets the unchanged `403 summary_only` (the route is not in its
two-path allowlist) and `producer` the unchanged role-gate refusal. No new role, credential, body,
schema version, index, retention tier or client rollout, and no change to the lifecycle or refusal
dispatcher.

Query fields are exactly `limit`, `category`, `snapshot`, `before`:

| field | default | accepted | refused |
| :-- | :-- | :-- | :-- |
| `limit` | `100` | canonical decimal `1`–`100` | `0`, `101`, `+1`, `01`, ` 1`, `1.0`, `1_0`, an empty value, a `bool` at the direct-call seam |
| `category` | `all` | `all`, `action-transitions` | any other word |
| `snapshot`, `before` | absent | both together, canonical decimal `0`–`2**63-1`, `before <= snapshot` | one without the other, `before > snapshot`, an oversized or non-canonical integer |

`category=action-transitions` is the closed set of eight **completed** transitions: `action.proposed`,
`action.approved`, `action.denied`, `action.expired`, `execution.claimed`, `execution.succeeded`,
`execution.failed`, `execution.unknown`. An approval **intent** (`action.approval_intent`) and a refused
attempt (`action.refused`) are not completed transitions — CONTRACTS §5 says a callback receipt is not
action completion and the refusal audit says a refusal is a denial — so neither appears under that category and
both appear under `all`. There is no operation, actor, subject, time or SQL filter of any kind: the
category is checked in Python over bounded metadata from static, parameterized SQL. Caller text is
never concatenated into a statement.

`parse_query` judges the raw query bytes before anything is opened, and refuses with a fixed sentence
that names a field or a bound owned by this module and never the offending text: a query over
`QUERY_MAXIMUM_BYTES` (2048) bytes; raw control or non-ASCII bytes; a malformed percent escape (`%2`,
`%zz`, a trailing `%`) or a percent-escape that does not decode to valid UTF-8; an unknown field; a
duplicated field (never last-wins); a blank field or value; a valueless field (`?limit`); and every
non-canonical or oversized integer. `+` is a literal plus, not a space. A body is never read: this is a
GET, and the request that fails to parse opens no SQLite connection.

## The cursor

`snapshot` is the maximum committed audit sequence at the moment the first page was read (`0` for an
empty database), captured **inside the same read transaction as that page**. An initial request omits
both `snapshot` and `before`; a continuation must supply both, and reads `sequence <= snapshot` and
`sequence < before`, newest first. There is no `before` bound on a first page.

A client must hold `snapshot` and `category` fixed for the life of a traversal: changing either starts a
new traversal, not a continuation of the old one — that is its own snapshot with its own `next_before`
chain, and mixing chains gets you a refusal at best and an incomplete walk at worst. Appends above
`snapshot` can neither duplicate nor displace the walk. **A cursor is a position, not authority or a
secret:** nothing signs it, no key is involved, the server keeps no per-client memory, and `0` is a legal
value (the empty database). Continuity is not promised across a database that is restored or replaced —
that is a different table, and `sequence` values there are unrelated to the ones you were handed.

`next_before` is **exclusive**: the next page reads sequences strictly below it. A page that settled its
last position reports that position's sequence; a page that had to leave a matching row behind — because
the limit was reached or the byte budget was full — reports *one above it*, so that row is still on the
next page. That is why a well-behaved client can be asked for one final empty page after stopping
exactly at a limit or scan boundary: `next_before` non-null means "ask again", `null` means the end is
known.

## The response, and the two ways a page comes up short

```json
{"rows": [...], "snapshot": 4211, "next_before": 4103, "scanned": 137}
```

Exactly those four keys. A normal row carries the six stored audit columns and nothing else — `sequence`,
`at`, `actor`, `operation`, `subject`, `detail`, as stored. No `display` expansion (that is
`presentation.records`, and this route does not import it), no derived field, and no new field that could
carry a secret: `audit` has no token, claim or callback column, which is why this read needs no
secret-stripping step.

* **`scanned`** counts audit positions inspected, including a row deferred by the byte/limit cut, and never passes
  `SCAN_BUDGET` (500). Rows that did not match the category are counted, because they cost the walk.
* An **empty page with a non-null `next_before`** means a filtered scan spent its budget without finding
  anything to show: continue. An empty page with `null` means there is nothing below.
* A row whose **stored** text exceeds `ROW_STORED_TEXT_MAXIMUM` (49 152 bytes), or one whose canonical
  escaping would not fit even on a page containing nothing else, is returned in place as
  `{"sequence": N, "omitted": "row_exceeds_page_budget"}`. That entry consumes its position and counts
  toward `limit` like any other: it is **not** a complete row, it is never silently dropped, and the walk
  keeps moving past it. A row that is only too big *because earlier rows filled this page* is deferred to
  the next page rather than replaced by a placeholder — `next_before` points at it.

`PAGE_MAXIMUM_BYTES` (65 536) covers the whole canonical UTF-8 body, metadata included. The check is
made before a row joins the page and reserves the largest signed-64 cursor (also larger than JSON
`null`) and `SCAN_BUDGET` for the count, so the bytes actually sent
are inside the cap rather than estimated to be.

## How a hostile historical row is kept out of memory

No audit row is ever read whole on a hunch. Per page there are exactly three statement shapes, all
static, all values bound:

1. `SELECT MAX(sequence) FROM audit` — a B-tree maximum, not a scan.
2. The metadata read, at most `SCAN_BUDGET` positions: `sequence`, `operation` clipped to
   `OPERATION_METADATA_BYTES` (64) **bytes** as a BLOB, the `length(CAST(x AS BLOB))` sum of the five
   stored text columns, and one `typeof(x)='text'` conjunction. SQLite computes the widths; Python
   receives integers and at most 64 bytes per position.
   A single upper sequence key combines snapshot and exclusive before, so SQLite seeks to the
   continuation instead of scanning newer history to evaluate an optional predicate.
3. One row fetched **only** when its stored width passed bound 2, with its text columns read as BLOB and
   decoded strictly. A stored value that is not valid UTF-8, or is not text at all, yields the omission
   placeholder rather than a rewritten byte or a 500: repairing history with replacement characters would
   be editing the audit.

The clip cannot cost a match: every word in the category is 19 bytes or shorter, so a value long enough
to be clipped is not one of them — and the clipped bytes are only compared, never returned. **What these
bounds buy is Python allocation, not total disk IO or latency:** reading 500 positions of metadata from a
file holding megabyte-scale historical blobs still touches that file, and nothing here claims otherwise.

## The connection

`sqlite3.connect(<resolved path URI> + '?mode=ro', uri=True, isolation_level=None, timeout=10)`, wrapped
in `closing`, with one explicit `BEGIN` — a **deferred** read transaction, never `BEGIN IMMEDIATE`, never
`Store.transaction()` (which takes the write lock with `journal_mode=WAL`/`synchronous=FULL` pragmas that
a read has no business writing). `COMMIT` ends it and the connection is closed before the page is
returned: no connection is held between pages, no executor, thread or background task is added, no lock
or lifecycle code moves, and every other read endpoint is untouched. The busy timeout is the
`sqlite3.connect` argument, not a URI parameter.

## Limits a reviewer should not have to rediscover

* `rows` is at most `limit`; `scanned` is at most 500; the body is at most 65 536 bytes; one row is at
  most 49 152 stored text bytes before complete retrieval. Constants are owned by this module;
  `state.py` and `api.py` delegate, and these documents describe the current values.
* A page is a *read*: nothing here mutates, prunes or assumes `sequence` is contiguous. Gaps are safe;
  continuity across restored or replaced files is not promised. `snapshot` is a position within whatever
  this file happens to hold.
* The first page's `scanned` can hit the budget with `rows: []` on a category-filtered table — cheap to
  produce, and the reason `next_before` exists rather than a "there is more" flag.
* 500 positions per request means a deep walk over a busy audit table costs many requests; this is an
  operator surface, not a bulk export, and it deliberately has no larger page, no offset and no filter
  that would turn it into one.
* `Store.audit_page` takes `None` for "the unit's default" so the defaults are spelled once; a `bool`
  passed as any integer field is a refusal at both seams. Canonical decimal strings are accepted by
  the direct seam too. Query numeric validation follows percent-decoding (`%31` means `1`).
* `refusals.SENTENCES` gains no entry from this card, and none is needed: these sentences come from a
  parser in front of `Store`, the `api.py` `StateError` branch stays write-free, and no audited lifecycle
  method is entered. Adding a transport-stage reason word would break the disjointness that is the refusal audit's duplicate-row firewall.

Verification this contract needs (main runs it, not this document): accepted lifecycle rows surviving
more than 64 refusal rows through real authenticated ASGI calls; every page bound; both categories;
repeated and concurrent appends against a fixed `snapshot`; the final empty page; oversized Unicode and
control-character rows; every authorization and invalid-query case; and the legacy
`/v1/records/audit` bytes plus the database's contents and schema unchanged.

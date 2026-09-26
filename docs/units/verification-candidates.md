# Unit: verification candidate discovery

`local_observe/platform/verification_candidates.py` supplies one bounded page of
executions that the automatic post-action verifier can inspect. It performs no
claim, dispatch, migration, verdict write or lifecycle change.

`list_candidates(store, actor, *, after=None, limit=16)` returns exactly:

```json
{
  "items": [{
    "execution_id": "00000000-0000-0000-0000-000000000001",
    "action_id": "00000000-0000-0000-0000-000000000002",
    "finished_at": "2026-09-10T12:00:00.000000Z"
  }],
  "next_after": null
}
```

The API exposes this through `GET /v1/verification/candidates`, with optional
`after=<canonical UUID>` and `limit=<integer 1..32>`. Default limit is 16; omitted
`after` starts a sweep. Both the transport and the helper use the existing
verification **writer authority**: only a producer currently named in the mounted
verification policy may discover candidates. Reader, human, proposer, executor
and unlisted producer credentials cannot enumerate executions this way. Authority
is checked before parsing and again before opening SQLite in the service worker.
The existing four record/binding operations retain their own read/write authority.

## Pages and fairness

The page walks the executions primary-key index in lexical UUID order. It fetches
at most `limit + 1` raw rows, validates the lookahead UUID, and inspects bindings
and record existence for only the first `limit` rows. Filtering never occurs ahead
of the row limit. Each scanned execution is checked for valid IDs, status and
timestamp; its bound origin is validated against the captured mapping contract
and digest, not rematched against a changed current policy.

Eligible rows have terminal status `succeeded`, `failed` or `unknown`, a valid
captured bound origin, and no verification record. `finished_at` is the actual
`executions.updated_at` boundary normalized to UTC, never the current clock or
the action approval time. It conveys no claim that an unknown execution stopped
successfully; the existing record writer still decides its verification verdict.

When a lookahead row exists, `next_after` names the **last raw scanned** execution,
even if every scanned row was ineligible and `items` is empty. Otherwise it is
null. Null marks the end of one sweep, not completion of all future work. The
follower must restart later sweeps from omitted `after`, because UUIDs created
later can sort behind an old cursor and an executing row can become terminal.
The helper maintains no server cursor, lock, queue or snapshot across requests.

An existing valid verification ID skips the execution for this automatic
one-observation follower. Its accepted payload is never loaded or regraded here;
the existing record read owns document-corruption checks. Manual additional
verification records remain supported. A discovered candidate is not claimed:
the follower and record writer must still handle races and exact replay.

## Bounds and failures

The helper uses a dedicated read-only SQLite connection and one deferred read
transaction, with the existing ten-second busy timeout. Every selected text
column is transferred as a bounded byte prefix plus its SQLite type, including
an extra byte that detects overlength rather than truncating silently. The
captured origin uses the existing 65,536-byte policy bound. No runner token,
execution payload or record payload is selected or returned.

The named execution and binding primary-key indexes and the existing
`verification_records_execution` index are required. Missing indexes/tables,
invalid UTF-8, malformed IDs/timestamps, malformed or mismatched binding origins
and corrupt existence-probe IDs refuse the page as a whole. They are never
silently skipped as ineligible. The byte bounds constrain SQL result transfer;
they do not promise a wall-clock bound over a damaged SQLite file.

The API parses at most 256 raw query bytes, with strict ASCII/percent decoding,
no duplicate/unknown/blank parameters, and canonical unsigned decimal limit
spelling. Refusals occur before the shared service slot is claimed. Candidate
reads use the same single off-loop callable slot as record reads and writes:
busy requests receive `503 verification_busy`, with no queue or new writer.
Storage failures return the fixed `verification_storage_error` body without
paths, SQL text or private values.

## Tests and related units

`tests/test_verification_candidates.py` exercises real captured action bindings
and execution outcomes; pagination through entirely ineligible pages; new IDs and
newly terminal executions on a later sweep; policy revocation; corrupt and
overlength stored values; missing schema/indexes; indexed query plans, bounded
probe counts and SQLite progress budget; unchanged database bytes; strict HTTP
parsing; and shared-slot off-loop/busy behavior. Existing API regressions retain
their three ID-parameter contracts while acknowledging the fourth owned path.

See [verification API](verification-api.md), [records](verification-records.md)
and [record ID discovery](verification-reader.md). This unit itself installs or
enables no follower, scheduler, service or runtime mount.

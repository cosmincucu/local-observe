# RCA — backup

**Add the derived RCA cursor to the platform's existing backup set.** Explanation records remain
inside the operational database, covered by `docs/CONTRACTS.md` §7's consistent-SQLite-backup rule
(online backup API or a stopped writer, never a live copy that ignores WAL). Stop and drain scheduled
RCA invocations before copying their cursors with that backup; this adds no separate service or job.

## What is already covered

| Object | Where the explanation lives | Covered by |
|---|---|---|
| The explanation records | `audit`, operation `rca.explained`, append-only | the existing backup unit for `state.db` (`local_observe/platform/README.md`, the *Backup* section: `sqlite3 .backup`) — the same unit that protects the events, incidents and audit trail an incident report depends on |
| The incident view's cause label | read from `audit` at view time | nothing of its own: it is a read of the row above |
| The bundle | built per round, never stored | nothing — it is a function of the incident, the store and the inventory |
| The rule floor | in `local_observe/platform/rca.py`, version control | git |
| Per-source rotation progress | `<database>.rca.<source-digest>.cursor.json`, at most 2 KiB | copy after stopping and draining RCA invocations; exclude `.owner.lock` files |

The derived cursor records only source/path binding, schema and two rowid positions. An adjacent
`.owner.lock` protects each active tick; the kernel releases it when the process exits. Operational
row counts reported by `Store.status()` stay unchanged after a round, as checked by
`tests/test_rca_component.py`.

A restored cursor at the same database path resumes its fixed cycle. If an older database has fewer
rows than the remembered position, one empty tail completes the old cycle and the following tick
restarts from the beginning. A foreign source or canonical database path is refused. For a staging
restore at a new path, omit the derived cursor after preserving its verified backup; the new cycle
retains audit history and unchanged explanations do not append again. Do not delete an owner lock
while a tick runs. `VACUUM` or a rebuild may reassign hidden rowids: stop and drain the owner, verify
database/cursor backups and reset the derived cursor after that maintenance. See
[the progress unit](../../../docs/units/rca-progress.md) for the single-host filesystem and crash limits.

## Why losing it costs little, and what would actually hurt

The record is **rebuildable**: the next round recomputes the same candidates and writes a new row with a
new `explained_at`. Losing every `rca.explained` row in a restore loses an operator the cause label on
incident views for incidents that were explained before the restore point — the detection, the incident,
the notification and the audit trail of the decisions that mattered are all elsewhere and all still
there.

The asymmetry worth stating out loud, from the telemetry row of `docs/COMPONENTS.md`: **losing the
backing store costs analysis history you cannot reconstruct**. That sentence is about ClickHouse and the
telemetry pipeline, and it is *not* this component's to make — nothing here touches the telemetry stack.
If this component's records matter to a post-incident review, the reason is that they sit in the same
file as the audit trail, and that trail is the thing worth recovering.

## Restore, and the probe that proves the read path

1. Restore `state.db` into a **separate staging volume**, per `docs/CONTRACTS.md` §7 ("Restore only into
   separate staging volumes first"). Never over a live database while the serving process holds
   `platform/owner.py`'s lock on it.
2. Read one explanation back, with no model configured and no inventory required. A staging copy needs
   no server, so this is the plain read of the row:

   ```
   sqlite3 /staging/state.db "SELECT json_extract(detail,'$.confidence'),
                                     json_extract(detail,'$.causes')
                            FROM audit WHERE operation='rca.explained'
                            ORDER BY sequence DESC LIMIT 5"
   ```

   The reader this product uses over the same rows is `local_observe/platform/audit_reader.py` behind
   `GET /v1/audit`; it refuses a detail payload that is not a JSON object, so either form prints records
   or names the row that is corrupt.
3. Ask the incident view the same question, because that is the question an operator actually has —
   `GET /v1/records/incidents` against the staging server, which is `presentation.records`, the function
   that attaches the label:

   ```
   curl -H "Authorization: Bearer <staging reader token>" \n        "<staging platform address>/v1/records/incidents?limit=5"
   ```

   A row whose incident has an explanation carries `cause_name`, `cause_confidence` and `cause_basis` in
   its `display`; a row without one carries none of those keys. An explanation that restored but does not
   display is a read-path failure, not a success with a missing step.
4. Record what was restored and what was regenerated, which is the sentence §7 asks for. For this
   component the honest entry is: *restored with the database, or regenerated on the first round after
   restore — and the difference is invisible to an operator unless the incident closed in between.*

## What is deliberately not here

No `pg_dump`-shaped job, no object storage, no second copy of the audit trail, no schedule. A restore
into production is the same operation as the restore of the operational store and is governed by the
rules in that file's backup unit, not by this one.

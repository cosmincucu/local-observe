# Platform backup and recovery

Persistent state: platform-data/platform.db plus active WAL; detector-data/cursor.json;
private configuration/credentials/action policy; declared inventory source/revision.
The synthetic overlay also owns Gatus history and the conformance receiver's
deduplicated receipts. Those are independent service data, not platform authority.
The two units are now recorded separately, each with its own replay/duplicate policy as
`docs/CONTRACTS.md` §7 requires, in
[components/control/synthetics/backup.md](../synthetics/backup.md): Gatus's sqlite history (`gatus-data`,
whose loss costs charts and not verdicts) and the detector cursor (`detector-data`, whose loss costs one
window and whose *replay* cannot multiply a finding, because `source_event_id` is a digest of the
rule and the window and `events` is `UNIQUE(source, source_event_id)`). Neither recipe has been run.

The notification approval codes are operational state and they restore with this database:
`outbox.callback_token_hash`, `callback_expires_at` and `callback_consumed_at` are columns of
the platform file, so a verified backup carries them and a restore needs no separate secret
store. There is no separate secret store to lose: the code itself is never written anywhere, only
its SHA-256 digest, and a receiver that holds the clear code is a phone message and a channel
log, not this file. Two consequences, both of them intended. A restored database cannot hand back
a code that still works — a code minted after the backup's recovery point is simply absent from
it, so an operator who taps an approval from a stale message gets "not recognised", not a spent
intent. And a restore does not re-open a spent one: `callback_consumed_at` is part of the copy,
so single use survives the round trip. Verify both on the restored copy by reading
`GET /v1/records/outbox` (the digest is popped from every read path, so its absence there is the
check that the redaction held) and by replaying a code the restored file never issued.

Use Store.backup or the lo-platform backup command for a consistent online SQLite
copy. It refuses an existing destination and checks integrity. Do not copy just
the live main database. Save the image ID and schema version alongside a backup.
The schema version this build reads is 4.
Pause the detector around coordinated cursor/state checkpoints, or restore with
the detector disabled and reconcile its cursor/pending batch before enabling it.

Restore a completed standalone backup to a NEW destination and check integrity,
incidents/events/actions/audit/outbox before switching services. The executed
compatibility rehearsal explicitly checked no nonempty WAL accompanied the saved
backup before copying it into tmpfs. It never raw-copied live platform.db.

The two verification tables (schema v4, the verification workflow's storage slice) are tables of this same file and need
nothing separate: `verification_bindings` (one proposal-time binding per action) and
`verification_records` (the submitted observations and the verdict the platform derived) travel with every
verified copy for the same reason the approval codes above do — there is no second store, no sidecar and
no cursor beside them. Three schema-specific consequences of restoring them:

* Nothing prunes or expires either table, so a restored copy re-presents every verification ever recorded,
  including verdicts whose evidence long ago aged out. That is history and not permission: a verification
  record decides no action, resolves no incident and moves no execution or incident status, and the
  append-only triggers stay in the file, so the restored copy is as unmodifiable in place as the live one.
* Verify the boundary and the shape on the restored copy, not on the live one: both tables exist under the
  names above, `PRAGMA integrity_check` says `ok`, an action proposed before the migration reads
  `unbound`/`not-captured` (nothing back-fills a binding a build never witnessed), and an `UPDATE` or
  `DELETE` against either table fails with the append-only message. Re-running `lo-platform migrate` on a
  copy already at v4 must report `current` and write no copy of its own.
* A restore to before a verification was recorded lets the *identical* statement be accepted again, because
  the logical id is a digest of the execution, the binding and the window rather than of a write event: the
  row comes back the same, and its recorder and timestamp become those of the re-submission. A record whose
  bytes differ is refused as a changed retry against whatever the restored file holds. Reconcile the
  verifier's own history first; nothing here detects that a row was re-recorded.

Keep executors, producers and notification dispatch disabled during restoration.
Restored approvals are historical data, not permission to replay actions: a job
or notification may have happened after the backup. Reconcile runner history and
receiver delivery IDs first; invalidate/review outstanding authority before
restoring executor credentials. Startup only marks claims present in that DB
unknown; it cannot reconstruct actions lost after the backup's recovery point.
Automated restore quarantine/external reconciliation is still an open gate.

The conformance run restored SQLite contents on the same NAS and on independent
tmpfs copies under both binaries. It does not cover NAS loss or encrypted off-host
recovery. Retain all earlier deployment trees/volumes/checkpoints until adoption
and rollback are deliberately completed; no prune, down -v or overwrite restore.

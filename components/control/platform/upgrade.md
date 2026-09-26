# Platform upgrades

Pin the source revision, Python base digest, local image ID and complete
dependency lock before testing. The build installs this component's own lock
(requirements.in is the intent, requirements.lock the resolved closure: PyYAML,
jsonschema, uvicorn plus their transitive dependencies, each with a sha256) and no
longer reuses the inventory lock, so Datasette and the packages around it never enter
this image. Build recipe and lock regeneration: docs/BUILD.md.

2026-09-07 (remediation installability): the Dockerfile became a two-stage build runnable from a
checkout — it defaults LO_PYTHON_IMAGE to the python_base digest in versions.json, installs with
--require-hashes --no-cache-dir --prefix=/install, and keeps no wheel directory in the
final image. The image IDs recorded in versions.json predate that change (they were built
from the inventory lock) and have not been rebuilt since; no image has been rebuilt,
published, signed or promoted as part of that change, and the new recipe has not yet been
run on a container host.

2026-09-10 (remediation anomaly deployment support, the dedicated anomaly credential): the same `RUN` line grew a second command — `install -d -m
0700 -o 65532 -g 65532 /state` — so the image carries the directory the anomaly producer's cursor lives
in, at the mode `anomaly_cursor.private_parent` demands, instead of leaving a fresh named volume to
arrive root-owned 0755 (the recipe and the refusal are `components/control/anomaly/CONTRACT.md` §5; the
Sigma runner writes its cursor into the same `/state`). Nothing else in the image moved: no dependency,
no base digest, no lock entry, no user, no port. What that means for an operator: the `image_id` and
`earlier_compatible_image_id` above were both built before this line, so neither image has a `/state`,
and until someone rebuilds, `components/control/anomaly/CONTRACT.md`'s four-step volume recipe is still
the path that works. No state format, no schema and no API moved, so an upgrade across this line is the
same backup-and-rehearse procedure as any image change — and no image has been rebuilt, published,
signed or promoted for it, because nothing here builds one.

Stop new dispatch, save a consistent operational backup and detector cursor, then
test the candidate against an isolated restored copy. Check event retry semantics,
incident history, approval expiry/identity, unknown executions, delivery leases,
evidence retrieval and unsupported-schema refusal. Keep receivers/executors disabled
until restored external effects have been reconciled.

2026-09-08 : this build's `state.VERSION` is 4, and migration 4
creates two tables — `verification_bindings` (one proposal-time binding per action) and
`verification_records` (submitted observations plus the verdict this build derived) — each guarded by
`BEFORE UPDATE`/`BEFORE DELETE` triggers. The operator-facing door is the one the mechanism already has: a
v3 file under this build does not open and names `lo-platform migrate`, which writes and integrity-checks
`platform.db.pre-v3-<utc stamp>.db` first, applies the step in its own audited `BEGIN IMMEDIATE`, and
commits one `schema.migrated` row. Migrating stays a separate action taken *before* a release whose state
pin names 4, because `deployment.release.transition()` refuses a candidate whose pin differs from what is
live.

What a rehearsal of this step owes, on an isolated restored copy with executors, producers and notification
dispatch disabled — none of it run for this change, so nothing here is a result: every pre-existing row
readable and unchanged; both tables present with their triggers; both append-only boundaries enforced (an
`UPDATE` or `DELETE` refused with the `append-only verification …` message); a default-off reopen that
proposes an action without querying either table; one bind/submit/read round; then a backup and a restore of
the migrated copy. There is no back-fill, so an action proposed before the migration reads
`unbound`/`not-captured` and that is the expected answer, not a failed migration. No verification record
moves an action, an execution or an incident, on upgrade or afterwards.

Rollback is old image plus a compatible fresh copy of a verified checkpoint, not
old code opening a migrated live database. No Gatus version upgrade has been
rehearsed yet — and as of synthetics component that sentence no longer has to live here: the engine's pin, the
upgrade recipe and the four things an in-flight window can do across a version change moved to
[components/control/synthetics/upgrade.md](../synthetics/upgrade.md), which states plainly that it too
has run nothing. What stays true in this file is the platform's half of that move: the detector cursor
is this component's state, so a Gatus version change is rehearsed against a copy of `platform.db`
*and* of `cursor.json` together, never one without the other (that file's
[backup.md](../synthetics/backup.md) §2 says what a cursor restored backwards or forwards costs).
No image has been published, signed or promoted to production. None of that changed for
schema v4 either: nothing was rebuilt, migrated against operational state, rehearsed, published, signed or
promoted for it, and an older binary refuses a v4 file outright, so rollback from v4 is the pre-migration
copy and no downgrade path exists.

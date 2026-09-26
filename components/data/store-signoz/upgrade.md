# Store upgrade rehearsal

1. Establish the pinned baseline with full conformance and a proven restore.
2. Review release/migration notes for all four store images together. Record
   proposed old/new digests; do not silently float an individual dependency.
3. Restore the baseline backup into an isolated rehearsal project. Apply new
   configuration and images there, retaining migration output privately.
4. Check schema versions, old markers, UI state, new three-signal writes, query
   bounds and resource usage. Exercise a failed migration; dependent services
   must stay blocked rather than serve against a partially migrated schema.
5. Rehearse rollback by restoring the pre-upgrade data and old image/config set
   into fresh volumes. Running old binaries against migrated data is not rollback.
6. Record durations, incompatibilities, data reconciliation and the exact tested
   path in conformance evidence. Promote only after owner review.

The baseline and copied rehearsal run; broader component conformance is incomplete.

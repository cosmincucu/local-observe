# Platform upgrades

The current platform state schema is **10**. Existing databases require explicit
migration; opening an older database does not silently upgrade it. Schema 10 adds
`runner_approvals`, `runner_requests` and `setup_plans`. Existing incidents, events,
actions, audit records and verification history remain in the database.

Pin the source revision, Python base digest, component dependency lock and built image
identity. Follow the [build guide](../../../docs/BUILD.md). The platform image contains
the observer; the optional MCP SDK is packaged separately.

## Rehearse and apply

1. Pause execution and notification dispatch. Save and verify a consistent
   [platform backup](backup.md), configuration, inventory revision, detector cursors
   and trusted runner journals. Save observer state separately.
2. Restore the standalone database backup to a new isolated destination. Keep live
   receiver, runner and notification credentials unavailable to the rehearsal.
3. Run the candidate's migration against that restored copy:

   ```sh
   lo-platform --database /approved/private/rehearsal/platform.db migrate
   lo-platform --database /approved/private/rehearsal/platform.db status
   ```

   The migrator creates and integrity-checks a pre-migration copy, then applies and
   audits schema steps. Repeating migration at schema 10 reports the current schema.
4. Verify retained records, role separation, approval expiry and withdrawal, exact
   runner bindings, interrupted claims, duplicate event retries and repeat setup
   application. Check append-only verification records and their triggers. Rehearse
   backup and restore of the migrated copy.
5. After acceptance and deployment approval, take a fresh verified operational backup,
   stop writers, migrate the operational database and start the pinned candidate.
   Reconcile external actions and delivery receipts before enabling dispatch.

Guided setup requires a protected configuration root and independent executor identity;
see [guided setup](../../../docs/units/guided-setup.md). The trusted action runner also
requires proof that it and Dagu use the same immutable specification source. A successful
state migration establishes neither condition.

## Rollback

Older binaries cannot open schema 10. Restore a verified compatible pre-migration
backup into a new destination with its matching previous image, configuration and
cursor/journal recovery points. An image rollback alone is insufficient.

Keep executors and receivers disabled while reconciling actions or notifications
after the checkpoint. A restored approval is historical data, not permission to repeat
an external action. Preserve displaced state; do not overwrite live databases or prune
volumes as part of rollback.

The [synthetics procedure](../synthetics/upgrade.md) covers the Gatus engine separately.
Model quality, live phone delivery and hardware fit require their own acceptance;
schema and fixture tests do not establish them.

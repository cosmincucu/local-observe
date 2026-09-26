# Store backup and restore rehearsal

1. Record product revision, image digests, histogram checksum, private overlay
   revision and schema migration versions. Keep secret values out of evidence;
   preserve them separately in approved encrypted storage.
2. Inject unique metric/log/trace markers and record bounded query counts plus
   one UI configuration change. Stop demo producers, drain intake, and confirm
   the markers are queryable. Record outstanding queue counts; a timer alone
   is not a drain check.
3. Stop front door, store collector and SigNoz after draining, then ClickHouse,
   then ZooKeeper. Verify stopped state before copying any volume. Abort on an
   uncertain stop; do not make a live filesystem copy and call it consistent.
4. With an owner-approved backup mechanism, snapshot/archive all four volumes
   listed in CONTRACT.md, preserving numeric ownership and permissions. Record
   volume IDs, checksums, time and tools. Protect the SQLite contents and telemetry
   as private data. Include the coordinated queue/cursor snapshots from both
   agent and front-door recipes when they are not empty.
4a. **Ask whether the copy actually holds `security_events` before calling it complete.** The owned
    analytical table (security store, `local_observe/security/`) is a fourth database in the same ClickHouse
    server, so its parts land under the server's data directory and *would* ride the `clickhouse-data`
    volume this step copies — a claim about a layout, cheap to check and expensive to assume. Inside
    the project network, name the table's paths and the volume they sit on:

    ```sh
    docker compose --env-file /approved/private/full.env --project-name local-observe-full \
      exec -T clickhouse clickhouse-client --query \
      "SELECT name, engine, data_paths, create_table_query FROM system.tables WHERE database='security_events' AND name='events'"
    docker inspect --format '{{ json .Mounts }}' <clickhouse-container> \
      | python3 -c 'import json,sys; [print(m["Source"], "<-", m["Destination"]) for m in json.load(sys.stdin)]'
    ```

    `create_table_query` is the [documented table DDL column](https://clickhouse.com/docs/reference/system-tables/tables);
    inspect its table-level TTL alongside the paths. This command still needs pinned-server evidence.
    The `Source` beside the mount that contains the `data_paths` answer **is** the unit being copied, or
    it is not. Then ask the product, which needs the server's own data directory named (it ships no
    default for that path, on purpose):

    ```sh
    LO_SECURITY_EVENTS_DATA_ROOT=<the Source path above> \
      python3 -m local_observe.security.cli verify-backup    # 0 inside | 1 not inside | 2 not nameable
    ```

    **The answer as this was written (2026-09-09): not proven, in both directions.** The DDL has never
    been applied anywhere — the writer grant is an unapproved proposal — so the table exists on no host
    and there is nothing inside the backup unit to cover. `verify-backup` answers `1` with "the owned
    schema was never applied here", and that sentence, not a green check, is the current claim. Two
    consequences worth more than the check: the owned table's TTL is **DDL**, stored in that same
    `clickhouse-data` volume, so unlike the SigNoz settings it *is* restored by a volume copy and is
    *not* restored by restoring `signoz-sqlite` alone; and a five-year tier means a restore rehearsal
    that discards its copy also discards the only surviving copy of `principal`/`raw`, because the
    short-TTL projection deliberately never held them.
5. Restore into **new** volumes under a different `local-observe-demo-restore-*`
   project with different loopback ports and a synthetic log directory. Never
   point the restore at original volumes or the live producer directories.
6. Start the pinned restored store, check migration state and query the original
   markers before injecting new ones. Confirm saved UI state, then run the smoke
   test and reconcile restored queued records. Record missing and duplicate data.
7. Record actual restore duration, failure points and cleanup approval. Retain the
   baseline until the operator accepts the rehearsal. Never use `down -v` on the
   original project as part of this procedure.

An empty fresh store passing smoke is not a restore pass. Backup automation and
precise host commands follow the approved staging/storage layout; access is not
assumed by this document.

# Isolated data-foundation rehearsal

## Offline checks

From the checkout root with Python 3.12+ and requirements-dev.txt installed:

```text
python -B scripts/check_foundation.py --json
python -B -m unittest discover -s tests -v
```

These check references and selected isolation/authentication invariants, not the
full Compose schema, collector compatibility or runtime behaviour.

## Stage prerequisites

Before running this example, review the account, test directory, mounts, resource
budget and operations described
in [ACCESS.md](../../docs/ACCESS.md). Run on the same Linux/amd64 host as the
target Docker daemon; the smoke tool queries that host's loopback listeners.
Do not use a remote Docker context from a different host.

Use Compose 2.23.1 or newer: this model uses `include` and inline `configs.content`,
the latter introduced in that version ([Docker reference](https://docs.docker.com/reference/compose-file/configs/)).
The initial reference budget is 16 GB host RAM plus existing workload headroom;
the component caps have not been load-tested. Use a dedicated daemon/VM when
the shared host cannot safely accommodate the rehearsal.

1. Stage only this checkout in an approved new directory. Exclude `.git`, `.codex`,
   scratch, caches and private environment files from automatic copying.
2. Create an owner-readable private environment file from `.env.example` and a
   new synthetic-only log directory. Keep the environment outside shared evidence.
   `LO_HOST_ROOT=/` is a broad host read mount requiring explicit approval; use a
   disposable Linux guest if that scope is unsuitable on the staging host.
3. Use the resolved set in `components/data/store-signoz/image-lock.json` for this
   rehearsal. Re-resolve only for a deliberately reviewed pin change. Candidates
   are retained in `versions.json` for provenance. For a future pin change, on the
   approved staging daemon, pull each candidate for linux/amd64 and resolve its
   repository digest, for example:

   ```sh
   docker pull --platform linux/amd64 clickhouse/clickhouse-server:25.12.5
   docker image inspect --format '{{json .RepoDigests}}' clickhouse/clickhouse-server:25.12.5
   ```

   Set every image variable to its matching `repository@sha256:...` reference.
   Record the platform and resolved set privately. Runtime compatibility is not
   established; a failed pull is a blocker, not permission to use latest.
4. Obtain the histogram archive from the recorded upstream release through an
   approved authenticated HTTPS route. Inspect its member paths before extracting
   into a dedicated temporary directory; reject absolute/traversal paths. Verify
   any available publisher checksum/signature independently. Record origin and
   the archive and extracted binary hashes. A self-computed hash pins bytes but
   does not authenticate the publisher; record that limitation if no independent
   verification exists and get approval before executing the binary. Set the
   absolute binary path and **extracted binary** SHA256, not the archive hash.
5. Generate two independent random secrets (at least 24 characters) for ingest
   and SigNoz JWT. The ingest one is no longer an environment value: it is the file that
   `LO_INGEST_TOKEN_FILE` names, written with `printf '%s'` (no trailing newline, which the collector
   would send inside the Authorization header) and mode 0600, so keep the file — not a line in an env
   file — in the protected environment/secret store. The SigNoz JWT stays an environment value: it is
   a third-party image's own setting and the exception is recorded in
   `components/data/store-signoz/CONTRACT.md`. Never either in chat
   or committed evidence. Confirm UUID/hostname, approved source paths and unused
   loopback ports. Do not reuse production credentials or volumes.

## Preflight and start

The commands below use `/approved/private/demo.env` as a placeholder for the
owner-approved environment path. Run from this checkout's root. Preflight
renders configuration internally and does not print its secret values:

```sh
python3 -B scripts/conformance_smoke.py --env-file /approved/private/demo.env --preflight
docker compose --env-file /approved/private/demo.env --project-name local-observe-demo -f examples/demo/compose.yaml up -d
docker compose --env-file /approved/private/demo.env --project-name local-observe-demo -f examples/demo/compose.yaml ps -a
python3 -B scripts/conformance_smoke.py --env-file /approved/private/demo.env
```

Run each command only after the preceding check succeeds. Initialization and
migration containers should exit successfully; persistent services must stay
running. Inspect failures privately, without pasting environment/config dumps.
The smoke sends synthetic OTLP HTTP metrics, logs and traces, checks missing/bad
credentials, and runs bounded ClickHouse queries for those unique markers. It
does not start containers, test the Linux file receiver, gRPC, redaction, UI,
crash durability, backup/restore or upgrades. Exit 2 means unavailable Docker;
exit 1 means failure. A smoke pass is not full conformance.

Use a verified SSH tunnel for UI access to the loopback UI port; do not change
publication to `0.0.0.0`. Complete initial SigNoz login/bootstrap privately.
Append synthetic markers to an approved `.log` file and verify Linux host metrics
and file ingestion separately using the component conformance checklist.

## Recovery and evidence

Follow each component's CONTRACT.md, backup.md, upgrade.md and conformance.md.
Rehearse recovery in a differently named project with different ports and fresh
volumes. Never attach the baseline/estate volumes to a restore experiment.
Use project-qualified `stop` after tests; no unqualified prune or `down -v`.
Keep the baseline and backup until explicitly accepted for removal.

Record source revision, config/overlay identity, image digests, binary checksum,
non-secret command results and measured recovery outcomes. Keep unavailable
checks marked not-run. Summarise the next unfinished action in STATUS.md after
each item; do not mark the components validated just because artifacts exist.

## Isolated recovery rehearsals

The `scripts/conformance_recovery.py`, `conformance_backup.py`, `conformance_upgrade.py`,
`conformance_pressure.py`, `conformance_coverage.py` and `conformance_final.py` commands
require `--env-file`, `--base`, `--uid` and `--docker-root`. The upgrade command also
requires its verified `--checkpoint`. Choose an existing scratch directory and a
rootless Docker data directory beneath it; the account UID must be non-root.
The commands refuse a different daemon before operating on the demo project.

These are operational rehearsals that can stop containers in the selected demo.
Use a disposable `local-observe-demo` project containing synthetic telemetry, with
the expected `logs`, `backups` and `artifacts` directories under the selected base.
They are not run by source tests. Keep their generated reports outside this checkout.

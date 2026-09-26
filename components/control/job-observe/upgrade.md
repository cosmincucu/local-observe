# Upgrade

Nothing infrastructure-grade upgrades itself: a pin moves on a branch, with a reason and a rollback
line, and is seen running against its real consumers **before** it merges. Promotion is an operator
action after that, never a side effect of `docker compose up`.

## What an upgrade moves

| Layer | What changes | Who decides it is safe |
|---|---|---|
| the image pin | `LO_HEALTHCHECKS_IMAGE` in the environment file, plus `versions.json` here | the reading agent, against the release notes and the diff of `docker/` (Dockerfile, `uwsgi.ini`, base Python image) |
| the schema inside `hc.sqlite` | `manage.py migrate`, run automatically by uWSGI in a `hook-pre-app` exec **before the first request is served** | nobody: it is forward-only, and it happens on boot, so the pre-upgrade copy is the only rollback |
| the settings surface | any `environment:` key in `compose.yaml` that upstream renames or changes the default of | `versions.json` records the version the keys were read at; re-read [self_hosted_configuration.md](https://github.com/healthchecks/healthchecks/blob/master/templates/docs/self_hosted_configuration.md) against the new tag |
| the `hc_*` metric names and labels | `hc/integrations/prometheus/` | any store-side alert rule that reads `hc_check_up` is a pin on this file; upstream labels the endpoint's metrics as an integration, not a stable API |

## Procedure

1. **Back up first, and verify the backup by reading it back** — the `PRAGMA integrity_check`, the
   `SELECT name,status` list and the `sha256sum` in [backup.md](backup.md), recorded in the change,
   before any candidate boots. `migrate` runs on the first start of the candidate, so "we will restore
   if it goes wrong" is only true if the copy is already proven. Do not run the candidate against the
   live volume to find out.
2. Read the release notes for every version crossed, and the diff of `docker/Dockerfile` and
   `docker/uwsgi.ini` between the two tags. Two things to look for specifically: a **base-image
   change** (the pinned release runs `python:3.14.7-slim-trixie` — a Python minor bump can change
   the uWSGI build) and a **new or renamed setting** that this manifest sets.
3. Boot the candidate in a **different project name on different loopback ports** with a copy of the
   verified database, never over the live one. The checks and their ping URLs come with the copy, so
   the candidate can be probed for real:
   ```sh
   curl -sS http://127.0.0.1:18098/api/v3/status/                     # the same endpoint the healthcheck uses
   curl -sS -H "X-Api-Key: $RO_KEY" http://127.0.0.1:18098/api/v2/checks/ | head -40
   curl -sS "http://127.0.0.1:18098/projects/$PROJECT/metrics/$RO_KEY" | grep -E '^hc_' | head
   ```
   Pass: the check list matches the pre-upgrade `SELECT`, the healthcheck passes inside the start
   period with migrations logged as applied, and `hc_check_up` still carries the same label set
   (`name`, `tags`, `unique_key`) — a label rename silently orphans every alert rule.
4. Run the two live checks in [conformance.md](conformance.md) — **missed deadline** and **failed
   check-in** — against the candidate, with the real timer that pings it. Both must produce the same
   state transitions they produced before the upgrade.
5. Promote by changing one value in the environment file and restarting the one service. Confirm the
   running version from the console's own report (the "Healthchecks version" line it renders) and
   from `docker inspect` showing the pinned digest, then keep the previous image locally for the
   rollback window.

## Rollback

Roll back the image **and the database copy taken in step 1 together**: a schema migrated by the
candidate is not readable by the previous release (upstream ships no down-migrations), so the old
binary against the new file is a broken container, and "old binary, live file" is not a rollback but
an outage. Restore per [backup.md](backup.md), then re-check the ping URLs by pinging one — after a
restore the URL must move state, or the monitor is decorative.

Expect to lose whatever check-ins arrived between the copy and the rollback: deadlines restart from
the restored `last_ping`, so a check restored from an old copy can report a **missed job that already
ran** — a false alarm, and the honest price of a forward-only migration. Say which copies are in play
in the run log; do not let two containers point at one database file, since neither locks against the
other's migrations.

## Not yet done

No version upgrade of this component has been rehearsed, so no rollback line above has been executed.
The first rehearsal must be recorded in `STATUS.md` with the before/after digests and the exact
`PRAGMA integrity_check` output before this component may be called experimental.

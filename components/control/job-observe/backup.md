# Backup and restore

The whole state of this component is one SQLite file plus the key that signs its sessions.
Everything else in the container is rebuildable: the image, the static files, the uWSGI config.

## What is state

| Artifact | Lives at | Lost if it is not backed up |
|---|---|---|
| checks, schedules, ping URLs, pings received, notifications sent | `/data/hc.sqlite` inside the container, on the project-scoped `healthchecks-data` volume | every check definition **and every ping URL**, which means every job host's check-in line, the `LO_HEALTHCHECKS_PING_FILE` content on each job host, and every stored check history |
| the session-signing key | the host file `LO_HEALTHCHECKS_SECRET_FILE` names, never in the container | active logins only; losing it does not lose checks, and a new key invalidates sessions without touching data |
| the operator's own account | inside the SQLite file (Django auth tables) | the console login; recoverable by `manage.py createsuperuser` against a restored database |

The ping URLs are derived from a check's stored `code`, so a restored database answers on the **same**
URLs it did before. Restoring into a new installation is therefore safe for the check-in lines that
jobs already point at — but minting a *new* installation and copying nothing means every job host is
pinging a URL that no longer exists, and Healthchecks has no reason to say so: an unknown code is a
404, and 404s do not alert anyone.

## Backup

The deadline state is live: `hc_check_up` changes as checks flip, so a copy taken by `cp` under a
running writer can be a torn file that opens and looks fine. Use SQLite's own online backup, which is
the only method here that does not need the service stopped:

```sh
# The online-consistent copy; a bare cp of a live -wal-backed database is not.
docker compose exec -T healthchecks python -c \
  'import sqlite3;src=sqlite3.connect("/data/hc.sqlite");dst=sqlite3.connect("/tmp/hc-backup.sqlite");src.backup(dst);dst.close();src.close()'
docker compose cp healthchecks:/tmp/hc-backup.sqlite ./hc-backup.sqlite
```

Then read it back before calling it a backup — the file's existence proves nothing:

```sh
sqlite3 ./hc-backup.sqlite 'PRAGMA integrity_check;'    # must print exactly: ok
sqlite3 ./hc-backup.sqlite 'SELECT count(*) FROM api_check;'   # a number you expected
sqlite3 ./hc-backup.sqlite 'SELECT name,status FROM api_check ORDER BY name;'  # the checks you think exist
sha256sum ./hc-backup.sqlite                            # record this, in the card or the run log
docker compose exec -T healthchecks rm -f /tmp/hc-backup.sqlite   # never leave a copy inside the container
```

Table names are Django's default `app_label_model`: the checks live in `api_check` and the ping log
in `api_ping` — `hc/api/models.py` names its indexes `api_check_aa_not_down` and
`api_check_project_slug`, and `hc/api/apps.py` queries `TABLE_NAME = 'api_check'` directly. Upstream's
own cleanup section (README, "Database Cleanup") names `api_ping`, `api_flip` and `api_notification`
as the automatically-trimmed tables, which is why a long history is not a promise: only the most
recent pings per check are kept (default 100, raised per profile). If the names above do not resolve
against your version, list them with `.tables` and record what you found rather than guessing — a
backup verified against a table that does not exist is unverified.

Cold-copy alternative, if the service may be stopped: stop it, then copy `hc.sqlite` **together
with** `-wal` and `-shm` if they exist, and start the copy in a scratch container. A stopped-but-not
checkpointed database restored from the main file alone loses whatever was still in the write-ahead
log — the last few check-ins, which are exactly the ones you would want.

## Restore

Restore into a **different project name, different container name, different loopback port and a
fresh key file**, never over the live volume:

```sh
docker compose -p job-observe-restore -f components/control/job-observe/compose.yaml config --quiet
# ...copy the verified file into the scratch project's volume, then start it and read:
curl -sS http://127.0.0.1:18098/api/v3/status/           # the DB-alive endpoint the healthcheck uses
curl -sS -H "X-Api-Key: $RO_KEY" http://127.0.0.1:18098/api/v2/checks/ | head -40
```

The pass condition is a check whose stored state you can name: the restored list matches the
`SELECT name,status` you recorded, `hc_check_up` for a known-down check is still 0 in
`/projects/<uuid>/metrics/<ro-key>`, and — the one that matters — **pinging the restored URL of a
check moves its state**. A restore that answers the API but rejects every ping is a dead monitor
that looks alive.

Do not restore the live volume in place to "check" it, and do not run two instances of one database:
the container that boots second migrates and writes, and uWSGI runs `manage.py migrate` before it
serves, so a second writer is not a read-only rehearsal.

## What is not covered here

This component holds no credential to any other system, no job output and no platform state: the
approval and incident history is the platform's SQLite file (`components/control/platform/backup.md`)
and the telemetry is the store's. Restoring this component does not restore a missed-job *record* in
the store, and the store's own retention is what bounds how far back a missed deadline can be proved
after the fact.

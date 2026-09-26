# Backup and recovery — component `crowdsec`

Two named volumes, and both hold state an operator cannot regenerate. store boundaries allows this datastore ("it
does not prohibit additional datastore(s), but the product validation happens with one datastore") — it
does not make the data disposable, and this file is where that distinction is paid for.

Nothing below has been run. No restore has been rehearsed for this component, and `conformance.md` keeps
the two recovery rows as `not-run`. Read the commands as the recipe to prove, not as a proof.

## 1. What is in each volume, and why it is not reproducible

| Volume | Path | Contents | Lost-it cost |
|---|---|---|---|
| `crowdsec-data` | `/var/lib/crowdsec/data` | the SQLite database: **decisions** (who is banned, until when, from which alert), **alerts**, machines, bouncers and their key hashes, the hub's installed-item state | decisions and their history are gone. Machine/bouncer registration is gone with them: every agent and bouncer must be re-added and every key reissued, and the old keys stop working — which is an outage for anything that was relying on them, not a re-key annoyance |
| `crowdsec-config` | `/etc/crowdsec` | config overlays the entrypoint wrote on first start, the **machine ID and its Local API credentials**, and — once a human enrols this instance — the Central API login/key file (community blocklist dependency) | the machine's identity. Re-enrolment is a human act against an account, and the old ID may still hold a reputation the new one does not |

The container's own root filesystem holds nothing worth keeping: `read_only: true`, `/tmp` on a tmpfs,
and the hub content re-downloads. The four read-only binds (acquisition, logs, profiles, notification
config) are the operator's files and are backed up where the operator keeps them, not here.

## 2. Take the backup, then read it back

`/var/lib/crowdsec/data` is the directory the image refuses to start without mounted (README at the
pinned tag, "Required configuration / Volumes"), so it is the volume that matters. SQLite defaults to
rollback-journal mode here — `USE_WAL` is **not** set in `compose.yaml`, deliberately: WAL would make the
consistent-copy step below a three-file operation (`-wal` and `-shm`) for no benefit at this size.

```
# Stop the writer first. A file copied while SQLite is writing is a copy that may open and may not be
# consistent, and "it copied without error" is not a verification — that is the defect class this
# repository has already been fooled by (an `[ -s "$tar" ]` that was true of a *directory*).
docker compose -f examples/crowdsec/compose.yaml stop crowdsec
volume=$(docker volume ls --filter name=crowdsec-data --format '{{.Name}}')
target="$(date -u +%Y%m%dT%H%M%SZ)"
# `-e target=` and not host-side interpolation: the tar path is built inside the
# container's shell, so a `$target` written in single quotes silently produces a file
# called crowdsec-data-.tar.gz — a backup that is not there until you go looking.
docker run --rm -v "$volume:/from:ro" -v "$PWD:/to" -e target="$target" alpine \
  sh -c 'cd /from && tar -czf "/to/crowdsec-data-$target.tar.gz" .'
```

Then **verify it by reading it back**, before calling the backup taken:

```
gzip -t crowdsec-data-<stamp>.tar.gz && tar -tzf crowdsec-data-<stamp>.tar.gz | grep -c .
sha256sum crowdsec-data-<stamp>.tar.gz
```

A listing count of zero is a green pipeline that protects nothing, and `gzip -t` alone only proves the
container is intact — the entry list is what proves the database was inside it. Name the artifact, its
size and its sha256 in the change that touches this component's state
(`Backup-taken: crowdsec-data-<stamp>.tar.gz sha256=<64 hex>`), per `AGENTS.md`.

The strongest check is not in that list: restore the tar into a scratch directory, start a second
container from it with a different project name, and run `cscli decisions list` and `cscli alerts list`
against it. That is the only way to learn whether the copy answers, and it is row 6 of
`conformance.md` — not run.

## 3. The config volume is smaller and worse to lose

`crowdsec-config` is a handful of YAML files plus credential files. Copy it the same way (stop, tar, list,
checksum). It contains **secrets** — the Local API machine credentials and, after enrolment, the Central
API key — so the artifact must land where the operator keeps every other secret (their vault, not a
build artifact, not a shared volume, not git). If that is not acceptable, back up the config volume
*before* enrolment only and treat the enrolment as an act you can repeat; the file's existence is then a
decision the operator made knowingly, and this repository deliberately does not name the vault that
holds it.

## 4. Restore

```
docker run --rm -v "$volume:/to" -v "$PWD:/from:ro" alpine \
  sh -c 'cd /to && tar -xzf "/from/crowdsec-data-<stamp>.tar.gz" .'
docker compose -f examples/crowdsec/compose.yaml up -d crowdsec
docker compose exec -T crowdsec cscli decisions list | head
```

Restore both volumes together when the enrolment exists: a data volume that names a machine ID the config
volume no longer has produces an engine that cannot reach the Central API and an operator who wonders why
nothing arrived after a "successful" restore. Restoring to a *newer* release's data format is a different
question and belongs in `upgrade.md`, which is where the in-flight-decision rule lives.

## 5. What is not this component's backup

The platform's own operational SQLite (`components/control/platform`, `Store.backup()`) is a separate
database on a separate volume: it holds the incidents and approvals that *cite* CrowdSec findings, and
neither restore implies the other. A restore that brings CrowdSec back to a state from before an
approval the platform still records is a real and unreconciled skew — the platform will believe a block
was proposed that the engine has never seen. There is no cross-store consistency promise in this
component, and saying so is the honest half of the row.

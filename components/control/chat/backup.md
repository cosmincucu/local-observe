# Backup and restore — component `chat`

Nothing in this recipe has been executed. It is derived from the write set the pinned commit
enumerates (`server/.gitignore`, `server/prisma/schema.prisma`, `server/utils/MCP/hypervisor/index.js`)
and from `docs/CONTRACTS.md` §7's rule for SQLite state. Every command below is a recipe with a
`not-run` mark in [conformance.md](conformance.md) row 11.

**Read the first line of [CONTRACT.md](CONTRACT.md) section 7 before backing this up at all.** The
state of this component is a conversation history. It is the most sensitive text this system holds, it
is not covered by any retention rule the product enforces, and an operator who backs it up nightly has
made copies of every incident conversation outside the platform's database. That is a legitimate choice;
it is not the default, and it must be a choice.

## 1. What is state

| Artifact | Lives at | Lost if it is not backed up |
|---|---|---|
| users, sessions, **API keys**, workspaces, threads and every chat message | `anythingllm.db` inside the `chat-storage` volume (`file:../storage/anythingllm.db` relative to `server/prisma/`, i.e. `/app/server/storage/anythingllm.db`) | the login, the surface's own API keys, the whole conversation history, and the workspace the MCP registry's settings sit next to. There is no export of any of it. |
| the MCP server registry — the endpoint URL, its `Authorization` header and each server's suppressed-tool list | `storage/plugins/anythingllm_mcp_servers.json` inside the same volume | the seam. Re-creatable by hand through the admin panel, and nothing else; note the bearer token for the platform's MCP facade is **stored in this file, in whatever plaintext the pinned release stores it in** — UNVERIFIED whether it is encrypted at rest, so treat the volume as credential-bearing. |
| the vector store, documents, generated files | `storage/lancedb/`, `storage/documents/`, `storage/generated-files/`, `storage/assets/` in that volume | nothing this profile wants: section 3 of CONTRACT.md says ingestion is not a feature. They are in the tarball because they are in the volume, not because they are wanted. |
| web-push keys (VAPID) | `storage/push-notifications/` in that volume | every subscription the browser made: a new keypair invalidates them all silently, and nothing reports a push that stopped arriving |
| the embedding cache and scratch | `storage/comkey/`, `storage/tmp/`, `storage/vector-cache/` | regenerable; included only because they share the volume |
| the settings file — `JWT_SECRET`, `SIG_KEY`, `SIG_SALT`, `AUTH_TOKEN`, any provider key | the host file `LO_CHAT_SETTINGS_FILE` names, **never inside the container** | active sessions and logins, and if `AUTH_TOKEN` was set, the shared password to the install. Losing it does not lose the transcript. Write it with no trailing newline (`printf`, never `echo`) and own it so uid 1000 can read the mount — Compose bind-mounts a `file:` secret with its host ownership and mode, it does not copy it. |
| the image, `node_modules`, the Prisma client, hotdir/outputs | the image and tmpfs | nothing: the image is digest-pinned, and the two collector directories are ephemeral by design |

## 2. Backup

The writer is live: a chat message is an `INSERT`, and `anythingllm.db` runs in WAL mode like every
Prisma SQLite client, so `-wal` and `-shm` sidecars hold committed rows the `.db` file does not.
`docs/CONTRACTS.md` §7 is explicit — *"a consistent SQLite backup (online backup API or stopped writer,
not a live copy ignoring WAL)"*. The online-copy API is not available here: the image ships no
`sqlite3` binary (`docker/Dockerfile` installs curl, netcat, git, ffmpeg and Node, not sqlite —
**UNVERIFIED**, and the check is `docker compose exec chat command -v sqlite3`, recorded in
conformance.md row 11), and no HTTP endpoint of the pinned release produces a consistent database copy.

So the stopped-writer form is the recipe, and the stop is the reason it works:

```sh
# 1. Stop the only writer before reading. `down` would remove the network and the tmpfs as well, which
#    is harmless but slower; `stop` is enough and leaves the volume attached.
docker compose stop chat

# 2. Copy the whole volume out. A named volume is not a host path, so a bare `cp` cannot reach it.
docker run --rm --volumes-from "$(docker compose ps -q chat)" -v "$PWD:/backup" \
  alpine:3.20 tar czf /backup/chat-storage-$(date -u +%Y%m%dT%H%M%SZ).tar.gz \
  --exclude 'app/server/storage/tmp' --exclude 'app/server/storage/vector-cache' /app/server/storage

# 3. The settings file is outside the volume and outside every compose `down`; copy it explicitly.
cp -p "$LO_CHAT_SETTINGS_FILE" "./chat-settings-$(date -u +%Y%m%dT%H%M%SZ).bak"

# 4. Bring the surface back up.
docker compose up -d chat
```

**Verify by reading it back — the file's existence proves nothing, and this repository has been fooled
by `[ -s "$tar" ]` matching a directory before:**

```sh
sha256sum ./chat-storage-*.tar.gz ./chat-settings-*.bak      # record these, on the card or in the run log
tar -tzf ./chat-storage-*.tar.gz | head -20                  # names the files it claims to hold
tar -tzf ./chat-storage-*.tar.gz | grep -c .                 # a count you can compare next week
mkdir -p scratch/restore-check && tar -xzf ./chat-storage-*.tar.gz -C scratch/restore-check
python3 -c "import sqlite3;c=sqlite3.connect('scratch/restore-check/app/server/storage/anythingllm.db');\
print(c.execute('PRAGMA integrity_check').fetchone()[0]);\
print(c.execute('select count(*) from users').fetchone()[0], c.execute('select count(*) from chats').fetchone()[0])"
```

`integrity_check` must print exactly `ok`. If it prints anything else the copy is torn and the backup
did not happen; if `sqlite3` reports *unable to open database file*, the copy ignored the WAL sidecars
and this section's premise is the bug. The two counts are the check that a *content* expectation held:
zero chats on an instance that has been used is a silent truncation, not an empty install.

Table names are Prisma's (`users`, `chats`, `threads`, `workspaces`, `api_keys`, `system_settings`) —
`server/prisma/schema.prisma` at the pinned commit names each `model`, and the model name is the table
name in this schema. Confirm against the tarball rather than this sentence on the first run.

## 3. Restore

Restore into a **separate volume** first, never over the running one (`docs/CONTRACTS.md` §7):

```sh
docker volume create chat-restore-check
docker run --rm -v chat-restore-check:/restore -v "$PWD:/backup" alpine:3.20 \
  sh -c 'tar xzf /backup/chat-storage-'"$(date -u +%Y%m%d)"'*T*Z.tar.gz -C /restore'
# then point a scratch compose project at that volume and start it, expecting `prisma migrate deploy`
# to apply nothing (same digest) or to refuse (a newer schema in an older image).
```

What that run proves and what it does not: it proves the bytes open, the schema is readable and the
login from the restored DB works. It does **not** prove the platform's approval state agrees with
anything in this volume — the two databases are independent by design and neither references the other,
so a chat transcript describing an approved action is not evidence that the action exists
(`docs/CONTRACTS.md` §5: *"Deleting or expiring raw telemetry must not delete action authority
records"*, and the converse — a transcript is not an authority record — is equally true).

Two things go stale on restore, both silent:

* **Web push.** If `storage/push-notifications/` did not come back with the volume, the keypair is
  regenerated at boot and every existing browser subscription is dead with no error anywhere.
* **The settings file.** Restoring the volume without the matching settings file is a login failure
  (`JWT_SECRET` seeds the session tokens), not a data loss — the transcript is intact and unreadable to
  the sessions that used the old key.

## 4. Deleting the transcript instead of backing it up

The clause CONTRACT.md section 7 exists for. There is no retention knob at the pinned commit
(`DISABLE_VIEW_CHAT_HISTORY` hides, it does not delete; the memory job *adds* derived rows), so deletion
is a volume-level act:

```sh
docker compose stop chat
docker run --rm --volumes-from "$(docker compose ps -q chat)" alpine:3.20 \
  sh -c 'rm -rf /app/server/storage/anythingllm.db* /app/server/storage/lancedb'
docker compose up -d chat        # boot recreates the schema; the onboarding wizard runs again
```

Do it deliberately and name the artifact you destroyed in the card or the run log. Deleting the volume
of a running instance is also deleting the only record of what was proposed from this surface — which
is fine, because the authoritative record of a proposal was never here: it is in the platform's
operational SQLite, with its `action.proposed` audit row naming `chat-<label>` as the requester
(CONTRACT.md section 4). If that audit row is missing, this section is not the way to reconstruct it.

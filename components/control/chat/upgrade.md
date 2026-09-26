# Upgrade — component `chat`

No version of this image has ever run in this repository, so there is no upgrade to rehearse yet —
which is the same sentence `components/control/ai/upgrade.md` opens with, and the reason this file is
rules rather than steps. The rule that outranks the rest:

> **Nothing infrastructure-grade upgrades itself, ever.** A pin moves on a branch carrying a reason and
> a rollback line, seen running against its real consumers before the PR merges (AGENTS.md). For this
> component the rule has teeth the others do not, because the pinned build runs
> `npx prisma migrate deploy` **at every container start** (`docker/docker-entrypoint.sh`): pointing
> `LO_CHAT_IMAGE` at a newer digest and restarting is not an image swap, it is an unattended schema
> migration over a conversation history, performed by a process whose entrypoint cannot be told not to
> do it.

## What a pin move touches

## Before moving the pin

1. **Back up first, and verify the backup by reading it** — [backup.md](backup.md), including the
   `integrity_check`/`ok` and the two row counts. `docs/CONTRACTS.md` §7's line applies with no
   exception here: *"a digest rollback is not a data rollback."* A schema migrated forward by the new
   image does not go back by relaunching the old digest, and this component's data is a transcript an
   operator cannot regenerate.
2. **Restore-test that backup into a scratch volume** (backup.md section 3) before pointing anything at
   a new digest.
3. Read the release notes for the range being crossed for two specific things this product's contract
   asserts rather than assumes: the `/api/ping` healthcheck route, and the storage layout
   (`STORAGE_DIR`, `anythingllm.db`, `plugins/anythingllm_mcp_servers.json`). Either moving makes a
   line in `compose.yaml` or `backup.md` false, and a false line in a lifecycle document is worse than
   a missing one.
4. Check the two upstream behaviours this manifest relies on for its refusals: that
   `DISABLE_TELEMETRY === "true"` is still the only off switch, and that
   `DISABLE_VIEW_CHAT_HISTORY` still means *hidden* rather than *not written*. If it ever comes to mean
   the latter, CONTRACT.md section 7's honest-sounding sentence needs rewriting in the same change.

## Rehearsal

Against a copy, never the running volume:

```sh
docker volume create chat-upgrade-rehearsal
docker run --rm -v chat-upgrade-rehearsal:/restore -v "$PWD:/backup" alpine:3.20 \
  tar xzf /backup/chat-storage-<stamp>.tar.gz -C /restore
# start the NEW digest with STORAGE_DIR pointed at that copy, on a scratch project, then:
docker compose -f scratch.compose.yaml exec chat \
  sh -c 'curl -fsS http://127.0.0.1:3001/api/ping'
python3 -c "import sqlite3;print(sqlite3.connect('…/anythingllm.db').execute('PRAGMA integrity_check').fetchone()[0])"
```

Expected: the entrypoint's `prisma migrate deploy` prints the migrations it applied — **and if it
prints none, that is also a result worth recording**, because it means the two versions share a schema
and the rollback is a digest move. If it applies any, the rollback line for the pin move has to name
the backup that survives the newer schema, and `versions.json` records which.

## Rollback

1. `LO_CHAT_IMAGE` back to the digest in this file's history (git holds it; that is the point of
   recording the digest rather than a tag).
2. If the new digest applied **any** migration, restoring the old digest is not enough — restore the
   volume from the pre-move backup, into the same volume name, and re-run the read-back.
3. If `storage/push-notifications/` did not come back, every browser subscription is dead and nothing
   will report it (backup.md section 3).
4. Re-run rows 3, 4 and 5 of [conformance.md](conformance.md) after any pin move: the read-only boot, a
   healthcheck that can go red, and the payload posture. Rows 6–8 stay `blocked-on-MCP component` until that
   item lands, and a pin move does not change that.

## What must not be inherited silently

A pin move that does not re-date `runtime_facts_read_at_the_pinned_commit` is a document describing an
image nobody has read. `tests/test_chat_component.py` will not catch that (it cannot read upstream),
which is exactly why the sentence belongs here in the file the person moving the pin is reading.

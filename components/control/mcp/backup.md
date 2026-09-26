# MCP tool surface — backup and recovery

**The one-sentence answer, because quality bar asks for it: this component owns no state, so there is nothing
here to back up — and the two things that are someone's to keep are the operator's identity map (already
inside the platform's backup scope) and the build recipe (a git revision plus a lock).**

Nothing below has been run. No restore has been rehearsed for this component; the rows that would need a
host are `not-run` in `conformance.md` and this file does not upgrade them by describing them.

## 1. What the container owns, and what it does not

`compose.yaml` declares **no volume** and no `secrets:` entry, and the image creates no writable path (no
`mkdir /data`, no `VOLUME`). Its root filesystem is read-only, `/tmp` is a tmpfs that dies with the
container, and everything it says is a durable fact is written by the platform it calls, not by itself:

| Thing | Where it actually lives | Whose backup covers it |
|---|---|---|
| the audit trail of what an agent proposed (`action.proposed`, naming the agent identity), the action rows, the execution rows | the platform's SQLite database | `components/control/platform/backup.md` — "Persistent state: platform-data/platform.db plus active WAL; **private configuration/credentials/action policy**; declared inventory source/revision" |
| the per-agent identity map (`mcp-identities.json`), the legacy shared bearer, the legacy reader credential | the directory `LO_PLATFORM_POLICY_DIR` names, mounted read-only at `/config` | the same platform row, in the clause quoted above. This component adds **no new file to back up** and no new location: the map is staged beside `actions.json`, which is already in that scope |
| the analysis reader's and the platform's other credentials | the same policy directory, or a declared Compose secret of the service that owns them | those components' own `backup.md` |
| the built image | the Docker host's image store, identified by a **local config ID**, not a registry digest | nobody's: it is rebuildable from the lock. Do not treat a config ID as restorable — see §3 |
| anything the process remembered between requests | nothing. `stateless_http=True` means one HTTP request is one JSON-RPC message with nothing carried over | — |

Losing this container costs an unreachable surface. It does not cost a decision, an approval, an audit row
or a credential: the platform holds the first three and the operator holds the last.

## 2. The map is credentials, so "back it up" has a condition attached

`mcp-identities.json` is a plaintext JSON list of bearer tokens and platform tokens at mode 0600. It is
inside the platform's backup scope and inherits that scope's rules, which are worth restating here because
this file is where a reader arrives looking for the MCP answer:

* it must never reach this repository, an issue, a PR body, a log line or a ticket — `check_foundation.py`
  polices the tree, and the grep in `conformance.md` row 10 is the check that it stayed out of a
  deployment's logs and audit export;
* wherever the platform's policy directory is snapshotted, that artifact now carries every agent's
  credential, so its off-host copy needs the same protection as the platform database and the channel
  secrets next to it — one leaked map is one leaked estate of agent credentials;
* **read it back**, as always: list the rows (`python -c "import json;print([(r['identity'],r['role']) for r in json.load(open(p))])"`, which prints identities and roles and no token) rather than trusting
  that a `.verified` marker means the bytes are the bytes you wanted. The map is 16 KiB and human-sized;
  an unverified backup of it is a file that hopes.

What losing the map costs is not data, it is coordination: every agent's credential is gone, each row must
be reissued, each client reconfigured, and — because a `platform_token` is a row of the platform's role
file and not a secret this component mints — the platform's credential file only needs touching if you
rotate there too. Nothing in the product can regenerate it: no code here creates, rotates or deletes a
credential, and that is a boundary rather than a gap.

## 3. Recovery, which is a rebuild

```
# 1. rebuild from the revision named in versions.json / the platform's deployment record
git -C <checkout> fetch && git -C <checkout> switch <the-revision-this-image-was-built-from>
docker build -f components/control/mcp/Dockerfile \
  --build-arg LO_SOURCE_REVISION="$(git -C <checkout> rev-parse HEAD)" \
  -t local-observe-mcp:dev .
# 2. point the environment at the new local config ID and start the service
LO_MCP_IMAGE="$(docker image inspect local-observe-mcp:dev --format '{{.Id}}')"
docker compose -f components/control/mcp/compose.yaml --env-file <private env> up -d mcp
# 3. prove the surface, on the host, before telling anyone it is back: rows 3, 4 and 5 of conformance.md
```

There is no restore step because there is nothing to restore **into**: no database to open, no cursor to
re-anchor, no lease to expire. If the platform itself is being restored, restore it first and by its own
recipe; this surface needs nothing except a platform to talk to, and it will refuse every request until
one answers.

The build is not bit-reproducible. `docs/BUILD.md` is blunt that `docker image inspect --format '{{.Id}}'`
is a local config ID that changes with the build host and the layer order, so a "restore" that expects the
old ID back will conclude the restore failed when it did not. Record the **source revision** beside the ID
in `versions.json` (that is what the field is for) and treat the ID as a fingerprint of one host, not as an
artifact name.

## 4. What is *not* in scope for this file

The store, the inventory snapshot, the platform database, the channel credentials, CrowdSec's two volumes
and the Dagu state are other components' backups and are named in their own `backup.md`. Backing up this
component well does not protect any of them, and — the direction that actually bites — **restoring the
platform database without the policy directory loses the map**. Agents then hold bearer tokens the
restored deployment has never heard of, every request comes back as the single 401 this transport gives,
and nothing in the platform explains it, because the audit trail (restored) and the credential table that
produced it (lost) are two different files. The same asymmetry the platform's own `backup.md` names for
`actions.json`: configuration is not regenerable state.

# Upgrade — component `crowdsec`

Rollback must account for this failure mode: **deleting a bounced address's
record while it is still blocked on a host is how an upgrade becomes an outage.** An engine upgrade that
forgets the decisions it made leaves a firewall holding a block whose reason nobody can show, and — the
worse half — nothing left that can lift it once the old volume is gone. Everything below is that
sentence, made procedural.

Nothing here has been run. `verified_on: null` in `versions.json` and rows 5-7 of `conformance.md` are
`not-run`; this is the recipe to prove, in the order an operator should have to follow it.

## What an upgrade moves

| Layer | Moves when | Who reads it | Consequence nobody should discover later |
|---|---|---|---|
| The image (the digest in `LO_CROWDSEC_IMAGE`) | you resolve and pin a new one | the daemon | parsers and scenarios run a new engine; the decision database may be a newer schema than the previous binary can read |
| The hub content (`COLLECTIONS`, `NO_HUB_UPGRADE`) | **every container start**, unless `NO_HUB_UPGRADE=true` | the engine, at boot, over the network | this is the quiet half: bumping the image digest is not the only thing that changes behaviour, and the pin in `versions.json` says nothing about what the hub served that morning. Nothing in this component pins hub content, and that is stated rather than hidden |
| SQLite (the `crowdsec-data` volume) | the engine writes it | the engine | it is the state an upgrade must survive — see the procedure |
| `LO_ACTION_POLICY` | the operator edits it | `policy.py` at boot | a protected-destination list that no longer matches its own schema makes every CrowdSec action refuse; `--check-actions` says so before the restart |

## Procedure

1. **Take and verify the backup first** — `backup.md`, both volumes, artifact + size + sha256 named in
   public before anything mutates. No exception is claimed here; the two volumes are exactly the state
   the rule exists for.
2. **Read the new release's notes**, from the tag page `versions.json` links, for anything that touches
   the decision or alert schema, the notification plugins (the inbound path) or the volume requirements
   ("since CrowdSec 1.7.0, `/var/lib/crowdsec/data` is required to be mounted in a volume" is the kind of
   sentence that only ever arrives in a release note).
3. **Resolve the new digest and record it**, in `versions.json`: the tag, the registry URL, the date, the
   amd64 and index digests, produced by `scripts/resolve_images.py::resolve`. A pin move is a
   branch with a reason and a rollback line, never a `latest` bump — `latest` and `v1.8.1` carry the same
   content today (measured 2026-09-09) and will not tomorrow, which is exactly why the file records both.
4. **Export the live decisions before the old container goes away**, while both the old binary and its
   data still exist:

   ```
   docker compose exec -T crowdsec cscli decisions list -o json > crowdsec-decisions-before-<stamp>.json
   docker compose exec -T crowdsec cscli alerts list -o json  > crowdsec-alerts-before-<stamp>.json
   ```

   This is the rollback's other half and the reason an upgrade is not a restart: a JSON export of what was
   decided is a list a human can re-apply by hand if the new release cannot read the old database. If
   `-o json` is not a flag the pinned release has, that is a correction to this line and it must be found
   out on the old container, while it still runs.
5. **Start the new digest.** Same volumes, no deletion, no `docker volume prune`, no
   `down --volumes` — `down --volumes` on this project destroys the decision store and the machine
   identity in one flag, and it is the single command this component most wants nobody to type from habit.
6. **Prove the state came through**: `cscli decisions list` shows the same count and the same
   expirations as step 4's export; `cscli alerts list` the same recent alerts; a
   `crowdsec.py`-style read against the new container answers for one known address; and one test alert
   still reaches the platform
   (`cscli decisions add --ip 203.0.113.9` — a documentation range, so it can be a test address without
   touching a real host, and the intake answer should be `accepted`, not `duplicate`, for a fresh
   incident).
7. **Say which digest runs, in the change that says it** — commit message or card, with the rollback line
   naming the previous digest. `docs/COMPONENTS.md` §3's row does not move to `built` on the strength of a
   pin; it moves on the conformance rows this file just asked for.

## Rollback

Rollback is a **digest move plus the same volumes**, not a restore, and only while the data is
backward-readable. Copy the previous value out of the record rather than retyping it — a digest an
operator types from memory is a pin nobody can reproduce later, which is the defect
`components/control/synthetics/versions.json` records for the Gatus move:

```
export LO_CROWDSEC_IMAGE=$(python -B -c "import json; print(json.load(open('components/control/crowdsec/versions.json'))['image'])")
```

The superseded digest belongs in this file the moment a move happens, with the reason, exactly as the
synthetics component keeps its `superseded_digest` block.

If the newer engine already wrote the SQLite in a schema the older one cannot read, rollback is:
restore `backup.md`'s verified artifact into the *old* image's volume, and re-apply by hand from step 4's
`cscli decisions list -o json` export whatever still needs blocking. Whether any given release pair is
backward-readable is **not known** and is not claimed here — it is row 7 of `conformance.md`, and until
it is run on a host, "rollback" for this component means "restore plus re-decide", which is a slower and
more honest description.

## In flight, both directions

An upgrade that lands while a block is live must not: expire decisions early, rewrite an alert's
`uuid`, or drop the machine ID. The first two are the engine's own behaviour at the pinned version and
unverified here; the third is why `crowdsec-config` is in `backup.md` at all. What is *this* repository's
problem, and belongs to whoever ships the writer: an approved-and-claimed action whose outcome was never
reported sits in `executions` as `unknown` until a human reconciles it (`state.py`'s
`recover_executions`/`execution_outcome`), and the CrowdSec-side effect — a ban that a bouncer may or may
not have applied — is invisible to the platform because the platform did not apply it. Restart the engine
before the platform, never between the two, so a reconciliation is at least reading the new state.

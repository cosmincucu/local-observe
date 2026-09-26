# Backup and restore — the portal

## What there is to back up

Two things, and one of them is not this container's:

| Artefact | Where | Why it is the thing worth keeping |
| :-- | :-- | :-- |
| The rendered portal config | the host directory `LO_HOMEPAGE_CONFIG_DIR` names (mounted read-only at `/app/config`) | the operator's destinations — dashboards and consoles — plus the file `homepage.py` generated for the layout. Nothing else on the host can rebuild the `dashboards`/`consoles` lists; they arrive from the operator's own repository (decision deployment separation) |
| The `summary` token file | `LO_HOMEPAGE_TOKEN_FILE` | a bearer credential. It follows the **platform role-credential** procedure, which is the vault, not a tarball beside the config it authenticates to |

Everything else the portal touches is either reproducible or ephemeral: `bootstrap.cjs` is source,
the image is a digest in `versions.json`, and `/tmp` and `/app/.next/cache` are tmpfs — they are gone
on every restart by design and their loss means nothing.

The service declares **no volume**. If a future change adds one, this file is wrong and that change
owes the correction, not the other way round.

## Take it

```sh
tar -czf portal-config-$(date -u +%Y%m%dT%H%M%SZ).tgz -C "$(dirname "$LO_HOMEPAGE_CONFIG_DIR")" \
  "$(basename "$LO_HOMEPAGE_CONFIG_DIR")"
sha256sum portal-config-*.tgz | tee portal-config-*.tgz.sha256
tar -tzf portal-config-*.tgz          # read it back: an unverified backup is a file that hopes
```

`tar -tzf` is not ceremony: a `[ -s "$tar" ]` test is true for a directory, and the size alone proves
nothing about the contents. Record the checksum and the entry list in the run record, never the token.

## Restore

1. Restore the platform state first, in quarantine, with its own procedure
   (`components/control/platform/backup.md`). The portal shows that database; a portal restored ahead
   of it renders numbers from a store that is not the one it will be asked about.
2. Put the config directory back at the path `LO_HOMEPAGE_CONFIG_DIR` names and keep the mode that
   lets uid 65532 read it. The bind sets `create_host_path: false`, so a directory that is not there
   stops the boot instead of mounting an empty one Docker made up — which is the failure you want,
   because a portal rendering an empty config looks like a portal with no dashboards, not like a
   restore that went wrong.
3. Re-create the token file from the vault, `printf '%s'`, no trailing newline, `chmod 0444`.
4. Start only this service and read it back before calling the restore good:

   ```sh
   docker compose -f examples/full/compose.yaml --project-name <project> up -d --no-deps homepage
   curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:${LO_HOMEPAGE_PORT:-18097}/
   ```

   Then in a browser: the Overview tab shows the platform's real counts, and a backup tile shows
   `Unknown`/`Stale` rather than a value — after a restore the observation document really is old, and
   a portal that shows a fresh-looking backup at that moment is lying.

## What a restore does not do

It does not restore what the portal *reports*. The incidents, approvals and outbox rows belong to the
platform database; the observation document behind `LO_OVERVIEW_PATH` belongs to whatever produces it
(the job/backup/model signals), and a restored portal pointed at an observation document nobody has
written since the incident will report `stale` for exactly as long as that is true. Nothing here may
make that look healthier than it is.

The portal holds no queue, no cursor and no session: no reconciliation step exists, and there is no
state to roll forward. Restoring it onto a *newer* release's renderer is not a restore — re-render
the config from the release that is actually running (see upgrade.md).

# Upgrade — the portal

Upgrade policy: **nothing infrastructure-grade upgrades itself.** A pin moves on a
branch that carries a reason and a rollback line, is seen running against its real consumers before
its PR merges, and the merge authorises promotion rather than closing the item. For this component
the "real consumers" are the platform API it reads through one `summary` credential, the config that
`local_observe/platform/homepage.py` renders into its mounted directory, and the edge that terminates
TLS in front of it.

## What a pin move is, in this repository

Two places name this version, and they move together or the release receipt stops matching the
thing it describes:

| Place | Line | What it means |
| :-- | :-- | :-- |
| `components/control/homepage/versions.json` | `image`, `index_digest`, `linux_amd64_digest` | the candidate and the platform it was resolved for. Re-resolve by requesting the tag's manifest and reading `Docker-Content-Digest`; the registry's `tags/list` page is capped and its silence proves nothing |
| `local_observe/deployment/release.py` | `contracts.homepage`, a JSON-Schema **`const`** | the release contract. The schema refuses a receipt that names any other Homepage version, so an image bump is a contract change: `tests/test_release.py` asserts the current value, and a receipt written by an older build is then a different contract, not a stale file to edit |

`components/**/versions.json` records candidates and provenance. It is not the value Compose uses:
`LO_HOMEPAGE_IMAGE` is what runs, so a bump that changes the file and not the environment changes
nothing except the documentation.

## Before starting the candidate

1. **Back up first, and verify the backup** — the platform state by its own procedure, and the config
   directory by [backup.md](backup.md). Read both back before the first mutating command.
2. **Re-render the config with the candidate's own renderer.** The image and
   `local_observe/platform/homepage.py` are one release: a v1 renderer's YAML inside a v2 server is a
   support question nobody can answer later. Keep the previous rendered directory; it is the rollback.
3. Check the five things this component depends on, for the version you are about to run:
   * `/api/revalidate` still answers `revalidated: true` — the readiness bootstrap and the
     healthcheck are both built on that one field, and if it changes quietly the portal either never
     becomes healthy or becomes healthy while serving a page built from the image's bundled config;
   * the `HOMEPAGE_FILE_*` substitution still exists and still inserts a file's **contents** — the
     credential design is that the token appears in no YAML and no browser HTML. If the templating
     prefix or its semantics move, `homepage.py` and this manifest move in the same change or the
     widgets start sending the *path* in an Authorization header;
   * `HOMEPAGE_ALLOWED_HOSTS` still means "the Host header the browser sends";
   * the layout keys the portal layout budget rests on (`tab`, `initiallyCollapsed`, group style/columns) still
     exist, or "3 tabs, 3 tiles, 8 fields" stops being a statement about the screen an operator sees;
   * the writable paths still are `/tmp` and `/app/.next/cache`; a v2 build that writes elsewhere
     fails inside a read-only root in a way that reads like a memory problem.
4. Diff the upstream release notes for **deprecations that render blank rather than fail**: a widget
   option that stops being read does not log, it just stops showing a number, and a missing number on
   an operator portal is worse than an error.

## Run the candidate where a failure cannot reach an operator

Start it as a separate project with its own port and its own allow-list entry, pointing at the same
read-only platform credential path — never by mutating the running portal in place:

```sh
docker compose --env-file <candidate.env> --project-name <candidate-project> \
  -f examples/full/compose.yaml config          # every variable resolves, before anything starts
docker compose --env-file <candidate.env> --project-name <candidate-project> \
  -f examples/full/compose.yaml up -d --no-deps homepage
```

with `LO_HOMEPAGE_PORT` and `LO_HOMEPAGE_ALLOWED_HOSTS` set to the candidate's numbers. `config` first
is not a formality: this service has four required variables, and an unset one is a refusal at
`config`, not a warning at `up`.

Then run the recipe in [conformance.md](conformance.md) against the candidate and compare it against
the running release — including the clause that reads `/v1/overview`, the MCP `platform_overview` tool
and the portal's own tiles and requires the three to agree. A portal upgrade that silently drops the
`dead_deliveries` tile is an operator-visible change of meaning, and the field-coverage test in
`tests/test_homepage_layout.py` is what catches it before the browser does.

Also re-check the credential boundary did not move: request a record endpoint with the portal's
`summary` token and require `403` (`local_observe/platform/api.py` restricts it to `/v1/me` and
`/v1/overview`; an image that starts sending a second request would show up as a refusal in its own
logs, which is a better outcome than a portal that can read everything).

## Promote, or roll back

Promote by changing `LO_HOMEPAGE_IMAGE` in the operator's environment file to the digest that just
passed, keeping the previous image in the local daemon (do not prune it) until the portal has been
used, and recording the new digest plus the passing run in `versions.json` and the release evidence.
This manifest sets `pull_policy: never`, so promotion means the image is already present and
identified — `docker image inspect --format '{{.Id}}' <name>` for the ID, `versions.json` for the
digest it came from.

Roll back by pointing `LO_HOMEPAGE_IMAGE` and `HOMEPAGE_ALLOWED_HOSTS`/`LO_HOMEPAGE_PORT` back at the
retained image and restoring the previous rendered config directory. There is no state migration in
either direction and nothing of the portal's to migrate: **if a Homepage upgrade needs a data
rollback, the wrong component was upgraded.**

Record the running image digest and source revision in the installation release receipt.

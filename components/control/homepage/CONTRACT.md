# Operator portal — Homepage (experimental)

The reference deployment's front door: one [Homepage](https://gethomepage.dev) instance rendering
one config directory that this repository renders for it. Status is **experimental** in the sense
this repository uses for it — the manifest and its five artefacts exist and are checked statically,
and this image has been started once, in the isolated staging rehearsal described in
[conformance.md](conformance.md); nothing here has been started from `examples/full/compose.yaml`.

Positioning, from decision positioning: this is the operator's front door, not a "single pane of glass".
It shows what the platform's own summary says and links to the places that hold detail.

## Who owns which half (overlay compatibility)

**The product owns the shape.** `local_observe/platform/homepage.py::configuration` decides the
tabs, the groups, which tiles exist, which endpoint each read widget binds to, and how the
credential is referenced. Nothing in this component re-derives that layout, and an operator overlay
that edits it is editing the product's contract with the layout test in `tests/test_homepage_layout.py`.

**The overlay owns the destinations.** The `dashboards` and `consoles` arguments are the operator's
list of links (name, href, icon, description). This repository ships none of them: like every other
private input they come from the operator's own versioned repository (decision deployment separation), and a portal
rendered with both lists empty is a valid, honest state — the Overview tab still reports real
numbers and the two link groups hold nothing.

One portal only (one portal or several). Homarr, Glance and Dashy are not validated surfaces of this product and no
manifest here starts them.

## The layout budget (portal layout), as a number

| Measure | Value shipped | Enforced by |
| :-- | :-- | :-- |
| Tabs | 3 — `Overview`, `Observability`, `Consoles` | `test_three_tabs_in_the_order_the_decision_settled` |
| Stateful tiles on the first screen (the `Overview` tab) | 3 | `test_the_first_screen_respects_the_q9_budget` |
| Live `customapi` fields rendered by those tiles | 8 | same test, budget 10; measured in `test_the_first_screen_measures_three_tiles_and_eight_fields` |
| Pure links on the first screen | 0 — every non-widget item sits in a group whose tab is `Observability` or the collapsed `Consoles` | `test_every_pure_link_is_off_the_first_screen_and_the_consoles_tab_starts_collapsed` |

portal layout asked for "3 tabs, ≤10 stateful items on the first screen". Three tiles carrying eight named
fields is the current reading of that, and both readings of "item" are bounded (tiles and fields),
because the looser one is unfalsifiable. The budget test compares against 10, so a change that adds a
ninth field passes and one that adds an eleventh fails with the budget in its message; a second test
names the measured 3/8, and failing there says "move the table above" rather than "the decision
changed". `test_the_budget_check_bites` mutates the config eleven ways and proves the guard is a guard,
and `tests/test_homepage_render.py` re-measures the same numbers after dumping the config to YAML and
reloading it through the gate's own loader.

## Data: one datum, two consumers

Every read widget is a `customapi` binding on `GET /v1/overview` — the same document the MCP tool
`platform_overview` returns (portal layout: "same data, two consumers"). Three things follow, and all three are
asserted in `tests/test_homepage_surfaces.py`:

1. The portal, the MCP tool and the operator UI's own counts come from one store read. The overview
   counts equal `/v1/status`'s counts field for field, and the MCP tool returns the identical
   document; the only permitted difference between two reads is `generated_at`.
2. A missing observation is a state, never a healthy zero. `unknown`, `disabled` and `stale` reach
   the browser as those words (`backup_display`, `jobs_display`, `jobs_status`, `model_display`) and
   reach the MCP caller as `signals.<name>.status`. A portal that shows `0` for a backup nobody
   verified is the defect this rule exists to prevent.
3. Every field name the rendered config maps must exist in the served document. A rename in
   `overview.py` that misses `homepage.py` fails there instead of rendering a blank tile.

The `Consoles` group links to the operator UI, where incidents and approvals are acted on. Acting is
never a portal function: the portal's credential could not approve anything even if the UI offered to
(let it be server-side, not by hiding a button — `local_observe/platform/api.py`).

## Credential

The portal holds exactly one credential: a bearer token in the platform's **`summary`** role, whose
reads are restricted to `/v1/me` and `/v1/overview` and nothing else (`api.py`, enforced server-side).

It travels as a file, never as a value:

So the token is absent from the rendered YAML and absent from the HTML the browser receives — the
staging rehearsal asserts exactly that (`token not in html` before it accepts a page). Two operational
consequences, both the same as the platform's role file:

* Compose bind-mounts a `file:` secret with its host ownership and mode; it does not copy it. The file
  must be readable by uid 65532 (`chmod 0444` after writing it, like every other mounted credential)
  and must not be world-readable to satisfy that.
* Write it with `printf '%s'`, no trailing newline: the value goes into a header verbatim, and the
  platform compares the header it receives. The token is the `summary` row of
  `LO_PLATFORM_CREDENTIALS_FILE`, copied out — not a freshly generated second secret, because the
  platform authenticates against the credentials list it already has.

Read widgets are fetched by Homepage's **server**, not by the browser, which is why the overview URL
names the service on the project network (`http://platform:8002/v1/overview`) and must be reachable
from this container. Making it reachable from a browser instead would put a platform credential in
front of whoever can open devtools.

## Readiness: the bootstrap, and why it is mounted

`entrypoint: [node]` / `command: [/bootstrap.cjs]` replace the image's entrypoint with
`scripts/homepage_start.cjs`, mounted read-only through `LO_HOMEPAGE_BOOTSTRAP`. It starts the
bundled `server.js`, polls `/api/revalidate` until it answers `revalidated: true`, and only then
writes the `/tmp/portal-ready` file that the healthcheck probes. Without it the first page a browser
receives after a start is the page pre-built into the image, not the config mounted at `/app/config`,
and a healthcheck reading "container is up" would call that healthy.

This component deliberately ships **no second copy** of that script. The running upgrade rehearsal
(your deployment verification) hashes the bootstrap inside the container against the
source-tree file it shipped, and that check is only worth anything while one file is both. The
variable exists so a deploy tree can say where that file landed; the shipped tree keeps it at
`scripts/homepage_start.cjs`.

## Publication and the TLS edge

Loopback only: `127.0.0.1:${LO_HOMEPAGE_PORT:-18097}:3000`, and `homepage` is named in
`scripts/check_foundation.py`'s `HOST_PUBLISHED_SERVICES` — the one shipped manifest addition of this
row that widens the exposed surface, argued in that comment and in the PR body.

Beyond the Docker host the portal needs an edge that authenticates, because the portal itself does
not: it holds a platform credential and shows operational state. The product ships this **recipe**,
not a service and not a certificate (docs/DEPLOYMENT.md owns the TLS requirement):

```caddyfile
{
    admin off
    auto_https off
}
https://<portal-host>:<tls-port> {
    tls <issued-cert.pem> <issued-key.pem>
    basic_auth { <user> <argon2-or-bcrypt-hash> }
    header Cache-Control no-store
    reverse_proxy homepage:3000
}
```

Generate the hash with the same pinned Caddy image that holds the certificate
(`caddy hash-password`, fed on stdin so the password never appears in a process list), mount the
Caddyfile and the key pair read-only, and set `HOMEPAGE_ALLOWED_HOSTS` to the host:port the browser
uses — Homepage refuses a request whose Host header it does not recognise, which is the second reason
that variable is required rather than defaulted. The isolated rehearsal ran this shape in front of this image: Homepage unpublished inside the project
network, the edge the only thing with a host publication, TLS terminated by the pinned Caddy image, the
Caddyfile and key pair mounted read-only, and an anonymous request refused with 401 while an
authenticated one returned the page with the token absent from its markup — all of which is staging
evidence for the *edge pattern*, not a conformance record for this manifest. Its limits are in
[conformance.md](conformance.md).

Caddy is an optional module of the platform (docs/COMPONENTS.md §3), so the edge is an operator's
overlay, versioned in the operator's own repository. Do not add it to this manifest: a portal that
depends on a service this file does not declare is a boot failure with no owner.

## Phone use (phone surface)

The operator's decision: chat plus push approvals are the phone surface; the portal is desktop-first,
"however the portal should work on the phone if needed". The layout above is phone-shaped by
construction — three tabs, a collapsed `Consoles` group, three tiles on the first screen — and
`local_observe/platform/static/homepage.css` (copied to `custom.css` in the config directory, with an
empty `custom.js`, as the rehearsal does) carries **no media query**: measured 2026-09-08,
`grep -c '@media' local_observe/platform/static/homepage.css` answers 0.

So the honest statement is: **the portal has never been rendered at a phone viewport in this
repository.** The viewport check is written down as a runnable recipe in
[conformance.md](conformance.md) and marked `not-run`, and the `interaction` row in
docs/COMPONENTS.md names that clause as unproven rather than claiming the answer.

## If the portal is disabled

Delete the `homepage` include entry from the example (or run a stack without it). What must, and
does, stay true:

* the platform, the operator UI and the store are untouched — this service declares no volume and
  owns no state, and nothing in the shipped tree declares a `depends_on` for `homepage`
  (`test_no_shipped_service_waits_on_the_portal` keeps that a fact rather than an intention);
* the platform does not fail to start because no portal exists, and still serves `/v1/overview` to
  whatever reads it next — the summary is produced by the platform with or without a viewer;
* the `summary` credential keeps working for MCP and for a hand-written `curl`; it simply has no
  portal to render it;
* what is lost is exactly the row's `If disabled` clause: **SigNoz remains usable; there is no unified
  operator view.**

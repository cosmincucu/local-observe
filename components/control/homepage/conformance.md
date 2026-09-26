# Conformance — the operator portal

The scenario this component owes is **"Operator surfaces"** in `docs/COMPONENTS.md` §5, verbatim:

> Homepage/MCP/view agree on incident/approval status; disabled and stale states visible; usable phone
> layout

Three clauses. Each is mapped below to the check that settles it, or to `not-run` with the recipe that
would. Nothing in this file claims a container was started: run the acceptance recipe for your installation.

## Clause 1 — "Homepage/MCP/view agree on incident/approval status"

**Status: proven in process, never against a running portal.**

| Check | What it settles |
| :-- | :-- |
| `tests/test_homepage_surfaces.py::SummaryAndViewTests::test_the_summary_and_the_view_agree_field_for_field` | `open_incidents`, `pending_approvals`, `pending_deliveries` and `dead_deliveries` in `/v1/overview` (the tiles' document) equal the same values in `/v1/status` (what `local_observe/platform/static/ui.js` fetches), read from one store over the real ASGI app |
| `...::test_the_rendered_widgets_bind_to_the_document_the_api_serves` | every field the rendered widgets map exists in the served document and is never null there — a renamed field fails here instead of rendering blank |
| `...::test_the_store_under_test_holds_the_state_these_checks_need` | the fixture really holds one incident, one approval and one queued delivery, so the agreement above is not three zeros agreeing |
| `tests/test_homepage_surfaces.py::MCPSurfaceTests::test_the_tool_and_the_portal_return_one_document` (MCP tier) | `platform_overview` returns the byte-identical document; the only field allowed to differ is `generated_at`, which is popped on both sides and asserted present first |
| `...::test_the_facade_still_offers_no_write_tool` | `tools/list` is still the four read-only tools; a portal does not become an agent's route to an approval |
| `tests/test_homepage_layout.py::TileContractTests::test_the_portal_credential_can_read_exactly_what_the_rendered_config_fetches` | the `summary` token the portal holds can read every URL the rendered config fetches, and is refused `/v1/status` — the config and the role cannot drift apart quietly |

### Recipe: the same clause over a running stack (not-run)

Needs a Docker host; `examples/full` has never started this service.

```sh
docker compose --env-file <env> --project-name local-observe-full -f examples/full/compose.yaml config
docker compose --env-file <env> --project-name local-observe-full -f examples/full/compose.yaml up -d
docker compose --project-name local-observe-full ps homepage        # must reach `healthy`, not merely running
summary=$(python3 -c "import json;print(next(r['token'] for r in json.load(open('$LO_PLATFORM_CREDENTIALS_FILE')) if r['role']=='summary'))")
curl -sS -H "Authorization: Bearer $summary" http://127.0.0.1:18096/v1/overview    # the datum itself
curl -sS -H "Authorization: Bearer $summary" http://127.0.0.1:18096/v1/records/incidents   # must be 403
curl -sS -u "<edge-user>:<edge-password>" "http://127.0.0.1:${LO_HOMEPAGE_PORT:-18097}/" \
  | grep -c -- "$summary"      # must print 0: the portal's token is never in the markup it serves
```

(`18096` is the platform port in `examples/full`, `18097` the portal's: the portal is a viewer, not a
proxy, so the overview is read from the platform and the portal page is read for the absence of the
token. The `summary` row must exist in the role-credentials file — `examples/full/README.md` writes it
and copies it to `LO_HOMEPAGE_TOKEN_FILE`.)

Then in a browser on the portal: the `Incidents and approvals` tile shows the four numbers `curl`
printed, and the operator UI's own header shows the same two counts. Record both readings; the pass
condition is equality, not "the page loaded". A tile that shows nothing at all is `not-run`, not a
pass — Homepage renders a failing `customapi` call as an empty field, which is the quietest failure
this component has.

## Clause 2 — "disabled and stale states visible"

**Status: proven at the boundary the browser reads; the browser itself has not read it.**

| Check | What it settles |
| :-- | :-- |
| `tests/test_homepage_surfaces.py::SummaryAndViewTests::test_disabled_stale_and_unconfigured_reach_the_screen_as_words` | an observation past `max_age_seconds` arrives as `stale` with a null value and the string `Stale` in `backup_display`; an unenrolled job monitor arrives as `disabled`/`Disabled`; an unconfigured probe arrives as `unknown`/`Unknown`. Three states, none of them a zero |
| `...::MCPSurfaceTests::test_the_tool_reports_the_same_disabled_and_stale_states` | an agent reading `platform_overview` sees the same `signals` block as the tile, including `"failed_jobs": null` — an absent count never reads as zero to either consumer |
| `tests/test_overview.py` (`test_unconfigured_is_unknown_not_zero`, `test_fresh_stale_future_and_invalid`) | the freshness rules themselves — future-dated backups refused, values nulled past the bound — which this component consumes and does not re-test |
| `tests/test_homepage_layout.py::TileContractTests::test_every_field_a_tile_renders_exists_in_the_served_document` | the strings above reach the browser under the field names the config actually maps (`backup_display`, `jobs_display`, `jobs_status`, `model_display`) |

### Recipe, over a running stack (not-run)

Stop the process that writes the observation document (`LO_OVERVIEW_PATH`), wait past the signals'
`max_age_seconds`, reload the portal. Every observation tile must change to `Stale`, and the numbers
must not change: an expired observation is not an incident. Then set `LO_OVERVIEW_PATH` to an empty
value and require `Unknown` rather than a zero. A tile that shows `0 failed jobs` while its producer is
unreachable is the defect this clause exists to catch, and it is the one clause a screenshot can prove.

## Clause 3 — "usable phone layout"

**Status: NOT RUN. Not proven, in any sense.** No page from this component has ever been rendered at a
phone viewport in this repository, and nothing here claims it works.

What is true statically, and is not the same claim: the layout is phone-shaped by construction (three
tabs, three tiles on the first screen, the link-heavy `Consoles` group starting collapsed —
`tests/test_homepage_layout.py`). What is known against it: the shipped stylesheet
`local_observe/platform/static/homepage.css`, copied to `custom.css`, carries no media query —
measured 2026-09-08, `grep -c '@media' local_observe/platform/static/homepage.css` answers `0`. phone surface
makes the portal desktop-first and asks that it work on a phone "if needed", so this is a gap to state,
not a blocker to this row.

### Recipe (not-run)

`scripts/check_operator_browser.py` is the pattern and the pin: Playwright `1.58.0`
(`scripts/requirements-browser.txt`), viewports `1440x960` and `390x844`, and the same discipline —
every claim in the report comes from an assertion that ran, and an unmet condition writes no report.
That script drives the **local operator demo**, not this portal, so the phone clause needs a sibling
check that:

1. serves a portal whose config points at a platform with at least one open incident and one pending
   approval, behind its own basic-auth edge or on loopback with the edge disabled;
2. at `390x844`: no horizontal overflow (`document.documentElement.scrollWidth <= clientWidth`), the
   `Overview` tab's tiles readable without horizontal scroll, tab labels reachable;
3. reaches the incident/approval view — the tile's `href` is the operator UI, so the check follows that
   link at the phone viewport and asserts the incident list renders and an approval can be inspected
   (not approved) there. phone surface's "incident/approval views reachable on the phone" is about this link,
   not about acting inside Homepage, which cannot act at all;
4. throws no page script error, and screenshots both viewports into the evidence directory.

Runtime browser acceptance remains **not-run**. Run the reference composition,
authentication checks and browser recipe in your installation, and record the image
digest, source revision, viewport sizes and observed results in private release evidence.

The deterministic checks are `scripts/check_foundation.py`, `tests/test_homepage_surfaces.py`
and `tests/test_homepage_layout.py`. The MCP comparison requires the optional MCP test tier.

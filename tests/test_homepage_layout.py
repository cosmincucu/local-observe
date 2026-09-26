"""The portal layout layout budget, and the contract between a rendered tile and the document behind it.

operator portal item 3: `local_observe/platform/homepage.py` already emits the shape decision portal layout asked for
("Rebuild as **3 tabs, ≤10 stateful items on the first screen**"), but nothing failed if someone later
added a tile. These tests are that failure. `tests/test_overview.py` already pins the tab count and the
token placeholder for the overview feature; what lives here is the *budget* (with a mutation test that
proves the budget bites), the placement rule for plain links, and the two contracts a tile can break
without anybody noticing: its fields must exist in `/v1/overview`, and the credential it ships must be
able to read exactly the URLs it names.
"""
from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path
import sys
import unittest
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from local_observe.platform.homepage import configuration   # noqa: E402
from local_observe.platform.overview import overview   # noqa: E402
from local_observe.platform.api import create_app   # noqa: E402

OPERATOR_URL = "https://operator.invalid"
OVERVIEW_URL = "http://platform:8002/v1/overview"

# Decision portal layout, verbatim: "Rebuild as 3 tabs, ≤10 stateful items on the first screen". Both readings of
# "item" are bounded, because the looser one is unfalsifiable: a tab carrying ten tiles of ten fields
# each is not what "≤10 stateful items" describes.
Q9_TABS = 3
Q9_FIRST_SCREEN_ITEMS = 10
FIRST_TAB = "Overview"


def docs(**kwargs: Any) -> dict[str, Any]:
    """The rendered portal, with the operator's link lists supplied the way an overlay supplies them."""
    return configuration(OPERATOR_URL, OVERVIEW_URL, **kwargs)


def groups_by_tab(document: dict[str, Any]) -> dict[str, list[str]]:
    """`{tab name: [group name, ...]}` — which group of tiles lands on which screen."""
    layout = document["settings.yaml"]["layout"]
    placed: dict[str, list[str]] = {}
    for group, options in layout.items():
        placed.setdefault(options["tab"], []).append(group)
    return placed


def first_screen(document: dict[str, Any]) -> dict[str, int]:
    """Count what the operator sees before clicking: widget-bearing tiles, and the fields they render.

    A tile is stateful when it carries a `widget` — a number on the screen that came from the platform
    rather than from the config file. Plain links are not counted here and are separately refused on the
    first screen by :func:`q9_violations`.
    """
    groups = groups_by_tab(document).get(FIRST_TAB, [])
    tiles = fields = 0
    for group in groups:
        for block in document["services.yaml"]:
            for entry in block.get(group, []):
                for _label, service in entry.items():
                    widget = service.get("widget")
                    if not widget:
                        continue
                    tiles += 1
                    fields += len(widget.get("mappings", []))
    return {"tiles": tiles, "fields": fields}


def q9_violations(document: dict[str, Any]) -> list[str]:
    """Every way this rendered portal departs from decision portal layout, one line each; empty means compliant."""
    found = []
    tabs = list(groups_by_tab(document))
    if len(tabs) != Q9_TABS:
        found.append(f"{len(tabs)} tabs, portal layout settled on {Q9_TABS}")
    counts = first_screen(document)
    for name, measured in counts.items():
        if measured > Q9_FIRST_SCREEN_ITEMS:
            found.append(f"{measured} stateful {name}s on the first screen, portal layout bound is "
                         f"{Q9_FIRST_SCREEN_ITEMS}")
    for block in document["services.yaml"]:
        for group, tiles in block.items():
            tab = document["settings.yaml"]["layout"].get(group, {}).get("tab")
            for entry in tiles:
                for label, service in entry.items():
                    if "widget" not in service and tab == FIRST_TAB:
                        found.append(f"{label} is a plain link on the first screen (tab {FIRST_TAB!r})")
    return found


LINKED = [{"SigNoz": {"href": "http://store.invalid", "icon": "mdi-chart-box-outline"}}]
CONSOLES = [{"Forge": {"href": "https://forge.invalid", "icon": "mdi-open-in-new"}}]


class LayoutBudgetTests(unittest.TestCase):
    """The portal layout shape, as a number the suite knows."""

    def test_three_tabs_in_the_order_the_decision_settled(self) -> None:
        """portal layout: three tabs, and the order is the order an operator reads them in."""
        self.assertEqual(list(groups_by_tab(docs())), ["Overview", "Observability", "Consoles"])

    def test_the_first_screen_measures_three_tiles_and_eight_fields(self) -> None:
        """If this fails, the table in components/control/homepage/CONTRACT.md is stale too."""
        self.assertEqual(first_screen(docs()), {"tiles": 3, "fields": 8})

    def test_the_first_screen_respects_the_q9_budget(self) -> None:
        """The ceiling itself, plus a clean read of the unmutated portal with its link lists filled."""
        measured = first_screen(docs())
        self.assertLessEqual(measured["tiles"], Q9_FIRST_SCREEN_ITEMS, measured)
        self.assertLessEqual(measured["fields"], Q9_FIRST_SCREEN_ITEMS, measured)
        self.assertEqual(q9_violations(docs(dashboards=LINKED, consoles=CONSOLES)), [])

    def test_the_budget_check_bites(self) -> None:
        """A guard that cannot fail is a description of the present, so mutate the present.

        Two mutations, because the budget has two readings: eleven fields across three tiles, and
        eleven tiles of one field each. Both must be refused, and a fourth tab must be refused too.
        """
        crowded_fields = copy.deepcopy(docs())
        mappings = crowded_fields["services.yaml"][0]["Platform"][0]["Incidents and approvals"]["widget"]["mappings"]
        mappings.extend({"field": f"extra_{index}", "label": f"Extra {index}", "format": "text"}
                        for index in range(3))
        self.assertEqual(first_screen(crowded_fields), {"tiles": 3, "fields": 11})
        self.assertTrue(any("stateful fields" in line for line in q9_violations(crowded_fields)),
                        q9_violations(crowded_fields))

        crowded_tiles = copy.deepcopy(docs())
        crowded_tiles["services.yaml"][0]["Platform"].extend(
            [{f"Tile {index}": {"icon": "mdi-dot", "widget": {
                "type": "customapi", "url": OVERVIEW_URL, "refreshInterval": 15000,
                "headers": {"Authorization": "Bearer {{HOMEPAGE_FILE_OVERVIEW_TOKEN}}"},
                "mappings": [{"field": "open_incidents", "label": "Open incidents", "format": "text"}]}}}
             for index in range(9)])
        self.assertEqual(first_screen(crowded_tiles), {"tiles": 12, "fields": 17})
        self.assertTrue(any("stateful tiles" in line for line in q9_violations(crowded_tiles)),
                        q9_violations(crowded_tiles))

        extra_tab = copy.deepcopy(docs())
        extra_tab["settings.yaml"]["layout"]["Alerts"] = {"tab": "Alerts", "style": "row", "columns": 3}
        extra_tab["services.yaml"][0]["Alerts"] = []
        self.assertEqual(len(groups_by_tab(extra_tab)), 4, groups_by_tab(extra_tab))
        self.assertTrue(any("tabs" in line for line in q9_violations(extra_tab)), q9_violations(extra_tab))

    def test_a_plain_link_on_the_first_screen_is_a_violation(self) -> None:
        """The rule that keeps tiles honest: a link with no reading behind it belongs in `Consoles`."""
        leaked = copy.deepcopy(docs(dashboards=LINKED, consoles=CONSOLES))
        leaked["services.yaml"][0]["Platform"].append({"Somewhere": {"href": "https://elsewhere.invalid"}})
        self.assertTrue(any("plain link" in line for line in q9_violations(leaked)), q9_violations(leaked))

    def test_every_pure_link_is_off_the_first_screen_and_the_consoles_tab_starts_collapsed(self) -> None:
        """Where the operator's links live, asserted for every link the renderer was handed."""
        document = docs(dashboards=LINKED, consoles=CONSOLES)
        layout = document["settings.yaml"]["layout"]
        self.assertTrue(layout["Consoles"]["initiallyCollapsed"],
                        "an open Consoles group puts a wall of links on the second screen")
        for block in document["services.yaml"]:
            for group, tiles in block.items():
                for entry in tiles:
                    for label, service in entry.items():
                        if "widget" in service:
                            continue
                        tab = layout[group]["tab"]
                        with self.subTest(tile=label):
                            self.assertNotEqual(tab, FIRST_TAB)
                            self.assertIn(group, ("Dashboards", "Consoles"))

    def test_the_renderer_emits_no_link_group_content_of_its_own(self) -> None:
        """Product owns the shape, the overlay owns destinations (overlay compatibility), so the product ships none."""
        self.assertEqual(docs()["services.yaml"][1:], [{"Dashboards": []}, {"Consoles": []}])


class TileContractTests(unittest.TestCase):
    """A tile is a promise about a document and about the credential that reads it."""

    def test_every_read_widget_binds_to_the_overview_endpoint(self) -> None:
        """One datum, one endpoint (portal layout): a tile bound elsewhere is a second integration nobody sized."""
        document = docs()
        for block in document["services.yaml"]:
            for tiles in block.values():
                for entry in tiles:
                    for service in entry.values():
                        widget = service.get("widget")
                        if widget:
                            self.assertEqual(widget["type"], "customapi")
                            self.assertEqual(widget["url"], OVERVIEW_URL)

    def test_every_field_a_tile_renders_exists_in_the_served_document(self) -> None:
        """A rename in overview.py that misses homepage.py renders blank, silently. This is the check.

        The fixture store is the one `tests/test_overview.py` uses for the same endpoint, so the served
        keys here are the keys that endpoint really returns rather than a list maintained twice.
        """
        from test_overview import Store
        served = overview(Store())
        mapped = {(entry["field"], entry["label"])
                  for block in docs()["services.yaml"] for tiles in block.values() for item in tiles
                  for service in item.values()
                  for entry in service.get("widget", {}).get("mappings", [])}
        self.assertTrue(mapped, "the portal renders no fields at all")
        missing = sorted(field for field, _label in mapped if field not in served)
        self.assertEqual(missing, [], f"tiles map fields /v1/overview never serves: {missing}")

    def test_the_portal_credential_can_read_exactly_what_the_rendered_config_fetches(self) -> None:
        """The role/endpoint pair, read from the rendered config instead of asserted from a list.

        `tests/test_overview.py::test_summary_credential_cannot_read_records_or_mutate` owns the
        exhaustive refusal matrix for the `summary` role. This is the other direction: a change that
        pointed a widget at `/v1/records/incidents` would keep that test green and hand the browser
        token a wider read than the layout was reviewed for.
        """
        from test_overview import Store
        token = "portal-layout-token-" * 3
        paths = {httpx.URL(widget["url"]).path
                 for block in docs()["services.yaml"] for tiles in block.values() for item in tiles
                 for service in item.values()
                 if (widget := service.get("widget"))}
        self.assertEqual(paths, {"/v1/overview"}, paths)

        async def check() -> None:
            app = create_app(Store(), [{"token": token, "identity": "portal", "role": "summary"}], None)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://localhost") as client:
                headers = {"Authorization": "Bearer " + token}
                for path in sorted(paths):
                    self.assertEqual((await client.get(path, headers=headers)).status_code, 200, path)
                self.assertEqual((await client.get("/v1/status", headers=headers)).status_code, 403)
                self.assertEqual((await client.get("/v1/status")).status_code, 401)

        asyncio.run(check())

    def test_the_rendered_config_carries_no_credential_value(self) -> None:
        """The `{{HOMEPAGE_FILE_*}}` placeholder is the only token-shaped thing an operator may commit."""
        rendered = json.dumps(docs())
        self.assertIn("{{HOMEPAGE_FILE_OVERVIEW_TOKEN}}", rendered)
        self.assertNotIn("Bearer ", rendered.replace("Bearer {{HOMEPAGE_FILE_OVERVIEW_TOKEN}}", ""))


if __name__ == "__main__":
    unittest.main()

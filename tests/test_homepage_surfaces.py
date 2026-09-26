"""§5 "Operator surfaces": three readers, one datum (operator portal item 5, decision portal layout).

`docs/COMPONENTS.md` §5 requires that "Homepage/MCP/view agree on incident/approval status; disabled
and stale states visible; usable phone layout". The first two clauses are here; the third needs a
browser and is recorded as `not-run` in `components/control/homepage/conformance.md`.

Three readers, three routes, one store:

| Reader | What it reads |
| :-- | :-- |
| the portal's read widgets (`local_observe/platform/homepage.py`) | `GET /v1/overview` with a `summary` token |
| the MCP tool `platform_overview` (`local_observe/platform/mcp.py`) | the same route, with a reader token |
| the operator UI (`local_observe/platform/static/ui.js`) | `GET /v1/status` |

Everything here drives the real ASGI application over one `Store`, so the comparison is between two
live reads and not between a read and a hand-copied expectation. The non-zero assertions are load
bearing: three zeros agreeing is not agreement, it is usually an empty fixture.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from local_observe.platform.api import create_app   # noqa: E402
import test_platform as fixtures   # noqa: E402

SUMMARY_TOKEN = "summary-surface-token-" * 2
READER_TOKEN = "reader-surface-token-" * 2
HUMAN_TOKEN = "human-surface-token-" * 2
MCP_TOKEN = "mcp-read-only-test-token-" * 2
# Counts the fixture produces: one intake opens an incident and queues one delivery, one proposal adds
# one pending approval. If the fixture drifts, test_the_store_under_test_holds_the_state_these_checks_needs
# says so before any agreement assertion can pass vacuously.
OBSERVED = {"open_incidents": 1, "pending_approvals": 1, "pending_deliveries": 1, "dead_deliveries": 0}


def signal(status: str, value: Any, age_seconds: int, max_age: int, source: str) -> dict[str, Any]:
    """One observation as the overview worker writes it: a state, a value and its own freshness bound."""
    return {"status": status, "value": value, "source": source, "max_age_seconds": max_age,
            "observed_at": (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=age_seconds)).isoformat()}


class PlatformBridge:
    """A `JsonClient`-shaped reader of the real application, for the MCP server's synchronous calls.

    `local_observe/platform.mcp` calls `client.request` from a plain function, which runs inside the
    MCP server's own event loop; an `httpx.ASGITransport` read needs a loop, so each call gets one on a
    worker thread. That keeps the shape the product uses — a blocking call from the tool's point of
    view, one credential, no retries — and replaces only the network.
    """

    def __init__(self, app: Any, token: str) -> None:
        self.app = app
        self.token = token

    def request(self, method: str, path: str, body: Any | None = None) -> tuple[int, Any]:
        """Perform one read against the in-process platform; a mutation here is a test failure."""
        if method != "GET":
            raise AssertionError(f"the read-only MCP facade attempted {method} {path}")

        async def go() -> tuple[int, Any]:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),
                                         base_url="http://localhost") as client:
                response = await client.get(path, headers={"Authorization": "Bearer " + self.token})
                return response.status_code, response.json()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, go()).result()


class SurfaceTests(unittest.TestCase):
    """The shared fixture: one platform, one observation document, three tokens."""

    def setUp(self) -> None:
        """One platform with a real incident and a real pending approval, and one observation document."""
        self.fixture = fixtures.PlatformTests("test_restart_preserves_state")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.intake()
        self.fixture.action()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.observation = Path(directory.name) / "overview.json"
        self.write_observations({"backup": signal("healthy", dt.datetime.now(dt.timezone.utc).isoformat(),
                                                  60, 3600, "nightly backup job"),
                                 "jobs": signal("degraded", 2, 60, 3600, "job monitor cursor"),
                                 "model": signal("healthy", "resident-model-v1", 60, 3600, "serve state")})

    def write_observations(self, signals: dict[str, Any]) -> None:
        """Replace the observation document the platform summarises, keeping schema version 1."""
        self.observation.write_text(json.dumps({"schema_version": 1, "signals": signals}), encoding="utf-8")

    def app(self) -> Any:
        """The role-enforced API, serving the overview this test wrote."""
        return create_app(self.fixture.store, [
            {"identity": "portal", "role": "summary", "token": SUMMARY_TOKEN},
            {"identity": "reader", "role": "reader", "token": READER_TOKEN},
            {"identity": "operator", "role": "human", "token": HUMAN_TOKEN}],
            self.fixture.policy, index_path=self.fixture.index, overview_path=self.observation)

    async def read(self, app: Any, path: str, token: str) -> dict[str, Any]:
        """One authenticated read of one route, with the status asserted before the body is returned."""
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://localhost") as client:
            response = await client.get(path, headers={"Authorization": "Bearer " + token})
            self.assertEqual(response.status_code, 200, path)
            return response.json()


class SummaryAndViewTests(SurfaceTests):
    """Base tier: the portal's document and the operator UI's document are the same numbers."""

    def test_the_store_under_test_holds_the_state_these_checks_need(self) -> None:
        """Guard for the vacuous-pass case: if the fixture stops producing state, say that instead."""
        summary = asyncio.run(self.read(self.app(), "/v1/overview", SUMMARY_TOKEN))
        self.assertEqual({key: summary[key] for key in OBSERVED}, OBSERVED)

    def test_the_summary_and_the_view_agree_field_for_field(self) -> None:
        """/v1/status is what `static/ui.js` fetches; /v1/overview is what the tiles fetch."""
        async def check() -> None:
            app = self.app()
            status = await self.read(app, "/v1/status", READER_TOKEN)
            summary = await self.read(app, "/v1/overview", SUMMARY_TOKEN)
            self.assertEqual(summary["open_incidents"], status["incidents"].get("open", 0))
            self.assertEqual(summary["pending_approvals"], status["actions"].get("pending", 0))
            self.assertEqual(summary["pending_deliveries"],
                             status["notifications"].get("pending", 0) + status["notifications"].get("sending", 0))
            self.assertEqual(summary["dead_deliveries"], status["notifications"].get("dead", 0))
            self.assertEqual({key: summary[key] for key in OBSERVED}, OBSERVED)
        asyncio.run(check())

    def test_disabled_stale_and_unconfigured_reach_the_screen_as_words(self) -> None:
        """portal layout's point: `unknown`/`disabled`/`stale` are states an operator reads, never a healthy zero.

        The three display strings below are exactly the fields the portal's widgets map, so this is the
        browser's behaviour asserted at the boundary the browser reads.
        """
        self.write_observations({
            "backup": signal("healthy", dt.datetime.now(dt.timezone.utc).isoformat(), 7200, 3600,
                             "nightly backup job"),                     # observed, but past its bound
            "jobs": signal("disabled", None, 60, 3600, "job monitor not enrolled"),
            "model": signal("unknown", None, 60, 3600, "model probe returned nothing")})
        summary = asyncio.run(self.read(self.app(), "/v1/overview", SUMMARY_TOKEN))
        self.assertEqual(summary["signals"]["backup"]["status"], "stale")
        self.assertEqual(summary["backup_display"], "Stale")
        self.assertIsNone(summary["last_verified_backup"])
        self.assertEqual(summary["jobs_status"], "disabled")
        self.assertEqual(summary["jobs_display"], "Disabled")
        self.assertIsNone(summary["failed_jobs"])
        self.assertEqual(summary["model_display"], "Unknown")
        self.assertEqual(summary["jobs_scope"], "job monitor not enrolled", "scope names the reader's limit")
        for key, expected in OBSERVED.items():
            self.assertEqual(summary[key], expected, "a missing observation never changes an incident count")

    def test_the_rendered_widgets_bind_to_the_document_the_api_serves(self) -> None:
        """The tile field list and the served document must not drift apart silently (portal layout, item 5)."""
        from local_observe.platform.homepage import configuration
        served = asyncio.run(self.read(self.app(), "/v1/overview", SUMMARY_TOKEN))
        for block in configuration("https://operator.invalid", "http://platform:8002/v1/overview")["services.yaml"]:
            for tiles in block.values():
                for item in tiles:
                    for label, service in item.items():
                        for entry in service.get("widget", {}).get("mappings", []):
                            with self.subTest(field=entry["field"]):
                                self.assertIn(entry["field"], served, f"{label} renders an absent field")
                                self.assertIsNot(served[entry["field"]], None,
                                                 f"{entry['field']} is never null in a served summary")


@unittest.skipUnless(importlib.util.find_spec("mcp"),
                     "Optional MCP extra not installed; run the MCP test tier separately")
class MCPSurfaceTests(SurfaceTests):
    """MCP tier: the tool an agent reads is the document the browser renders (portal layout, "two consumers")."""

    async def tool(self, app: Any, name: str) -> dict[str, Any]:
        """Call one MCP tool over its real Streamable-HTTP app and return the decoded payload."""
        from local_observe.platform.mcp import create_server
        server_app, server = create_server(PlatformBridge(app, READER_TOKEN), MCP_TOKEN)
        async with server.session_manager.run():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server_app),
                                         base_url="http://localhost:8000") as client:
                headers = {"Authorization": "Bearer " + MCP_TOKEN,
                           "Accept": "application/json, text/event-stream"}
                call = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                        "params": {"name": name, "arguments": {}}}
                response = await client.post("/mcp", json=call, headers=headers)
                self.assertEqual(response.status_code, 200, response.text)
                result = response.json()["result"]
                self.assertFalse(result["isError"], result)
                return json.loads(result["content"][0]["text"])

    def test_the_tool_and_the_portal_return_one_document(self) -> None:
        """Two consumers, one datum: identical except the timestamp of the read itself."""
        async def check() -> None:
            app = self.app()
            portal = await self.read(app, "/v1/overview", SUMMARY_TOKEN)
            tool = await self.tool(app, "platform_overview")
            self.assertEqual(tool["schema_version"], portal["schema_version"])
            self.assertIn("generated_at", tool)
            self.assertIn("generated_at", portal)
            tool.pop("generated_at")
            portal.pop("generated_at")
            self.assertEqual(tool, portal)
        asyncio.run(check())

    def test_the_tool_reports_the_same_disabled_and_stale_states(self) -> None:
        """The states an agent must not read as zeroes survive the MCP path unchanged."""
        self.write_observations({
            "backup": signal("healthy", dt.datetime.now(dt.timezone.utc).isoformat(), 7200, 3600,
                             "nightly backup job"),
            "jobs": signal("disabled", None, 60, 3600, "job monitor not enrolled"),
            "model": signal("unknown", None, 60, 3600, "model probe returned nothing")})

        async def check() -> None:
            app = self.app()
            portal = await self.read(app, "/v1/overview", SUMMARY_TOKEN)
            tool = await self.tool(app, "platform_overview")
            tool.pop("generated_at")
            portal.pop("generated_at")
            self.assertEqual(tool["signals"], portal["signals"])
            self.assertEqual(tool["signals"]["backup"]["status"], "stale")
            self.assertEqual(tool["jobs_status"], "disabled")
            self.assertIsNone(tool["failed_jobs"], "an agent must not read an absent count as zero")
        asyncio.run(check())

    def test_the_facade_still_offers_no_write_tool(self) -> None:
        """The portal's rise must not become an agent's reason to expect an approve tool (MCP component territory)."""
        from local_observe.platform.mcp import create_server

        async def check() -> None:
            app = self.app()
            server_app, server = create_server(PlatformBridge(app, READER_TOKEN), MCP_TOKEN)
            async with server.session_manager.run():
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server_app),
                                             base_url="http://localhost:8000") as client:
                    headers = {"Authorization": "Bearer " + MCP_TOKEN,
                               "Accept": "application/json, text/event-stream"}
                    body = {"jsonrpc": "2.0", "id": 8, "method": "tools/list", "params": {}}
                    tools = (await client.post("/mcp", json=body, headers=headers)).json()["result"]["tools"]
                    self.assertEqual({tool["name"] for tool in tools},
                                     {"platform_status", "platform_overview", "records", "inventory"})
        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()

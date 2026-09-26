"""One real Homepage render, parsed exactly as a portal would parse it, and measured against portal layout.

`tests/test_homepage_component.py` checks the manifest; this checks the *document* the shipped
component tells an operator to render — `local_observe/platform/homepage.py::configuration` written to
disk with `yaml.safe_dump`, then re-read through the foundation gate's own loader (`UniqueLoader`,
which refuses a duplicate key rather than letting the later one win, the failure mode a portal would
otherwise discover at browse time). `examples/full/README.md` step 5 is the procedure under test; the
`custom.css`/`custom.js` pair it names is checked here because the layout an operator sees is the
rendered YAML plus that stylesheet, not the Python dict.

The point is the budget and the token: decision portal layout fixed the shape ("3 tabs, <=10 stateful items on
the first screen") and nothing failed when a later change might add a tile; and a rendered file is the
one artefact an operator commits, so it must carry a placeholder and never a credential.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks   # noqa: E402

from local_observe.platform.homepage import configuration   # noqa: E402
import test_homepage_layout as layout   # noqa: E402

CUSTOM_CSS = ROOT / "local_observe/platform/static/homepage.css"


def write_portal(directory: Path) -> dict[str, Any]:
    """Render, dump and reload the portal config the way the reference example's step 5 does it."""
    documents = configuration(layout.OPERATOR_URL, layout.OVERVIEW_URL,
                              [{"Store": {"href": "http://127.0.0.1:18091", "icon": "mdi-chart-box-outline"}}],
                              [{"Forge": {"href": "https://forge.invalid", "icon": "mdi-open-in-new"}}])
    for name, value in documents.items():
        (directory / name).write_text(checks.yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
    (directory / "custom.css").write_text(CUSTOM_CSS.read_text(encoding="utf-8"), encoding="utf-8")
    (directory / "custom.js").write_text("", encoding="utf-8")
    return {name: checks.read_yaml(directory / name) for name in documents}


class RenderedPortalTests(unittest.TestCase):
    """The committed artefact: what an operator writes to disk and a browser then parses."""
    def test_the_rendered_config_reloads_through_the_gate_own_loader(self) -> None:
        """A dump that re-parses differently is a portal that renders someone else's layout."""
        with tempfile.TemporaryDirectory() as directory:
            loaded = write_portal(Path(directory))
            self.assertEqual(set(loaded), {
                "services.yaml", "settings.yaml", "widgets.yaml", "bookmarks.yaml", "docker.yaml",
                "kubernetes.yaml", "proxmox.yaml"})
            self.assertTrue((Path(directory) / "custom.css").read_text(encoding="utf-8").strip())
            self.assertEqual((Path(directory) / "custom.js").read_text(encoding="utf-8"), "")

    def test_the_rendered_page_is_three_tabs_with_three_tiles_and_eight_fields(self) -> None:
        """The portal layout shape, measured on the parsed YAML. Stale here means CONTRACT.md's table is stale."""
        with tempfile.TemporaryDirectory() as directory:
            loaded = write_portal(Path(directory))
            self.assertEqual(list(layout.groups_by_tab(loaded)), ["Overview", "Observability", "Consoles"])
            self.assertEqual(layout.first_screen(loaded), {"tiles": 3, "fields": 8})
            self.assertEqual(layout.q9_violations(loaded), [])

    def test_no_rendered_file_carries_an_authorization_value(self) -> None:
        """The placeholder is the only thing that may sit after `Bearer ` in a file an operator commits."""
        with tempfile.TemporaryDirectory() as directory:
            write_portal(Path(directory))
            for path in sorted(Path(directory).iterdir()):
                with self.subTest(file=path.name):
                    body = path.read_text(encoding="utf-8")
                    self.assertEqual(re.findall(r"Bearer (?!.*HOMEPAGE_FILE_OVERVIEW_TOKEN)\S+", body), [],
                                     f"{path.name} holds a credential value, not a placeholder")

    def test_the_stylesheet_ships_no_phone_rule_yet(self) -> None:
        """Recorded as a fact, because phone surface's phone clause rests on it: `custom.css` has no media query.

        Not an aspiration test — nothing here promises a media query will appear. If one does, this
        fails, and the sentence in components/control/homepage/CONTRACT.md that quotes the `0` has to be
        rewritten in the same change as the layout claim it supports.
        """
        self.assertEqual(len(re.findall(r"@media", CUSTOM_CSS.read_text(encoding="utf-8"))), 0)


if __name__ == "__main__":
    unittest.main()

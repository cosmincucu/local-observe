"""Issue #286: the privacy gate must see `local_observe/` and `tests/`, in any casing, and every
allowance it grants must be an exact path plus the exact tokens measured in that file.

Three defects are pinned here, each in the shape that made it real:

* **scope** — the walk stopped at `components/`, `examples/` and `scripts/`, so the package the public
  export ships first was never read (#286 finding 1);
* **case** — the gate matched `token in body` while the exporter matches case-insensitively, so CI
  accepted what the export refused: a contract that quoted the operator's first name, a component
  document that named the private port table, and two scripts whose tokens are all-initial or
  mixed-case product names (#286 finding 2, measured below against the real files);
* **allowance drift** — a product/test allowance that outlives its file, names a token the file does
  not carry, states no reason, or aims at a directory instead of a path would quietly widen the gate.
  The one allowance #286 called legitimate — the rootless socket validator in
  `local_observe/inventory/docker_provider.py` — is pinned as exact in both directions here.

No test string in this file spells a banned token: every one is taken from the gate's own lists, so
this file needs no waiver of its own and a leak added here would still fail the gate. Each case runs
against a temporary checkout, never against this one, except where a test says it is reading the
shipped registers and this tree.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks  # noqa: E402  (the same gate CI runs, imported as the other gate tests do)

TREES = ("local_observe", "components", "examples", "scripts", "tests")
ALLOWED_TREES = ("local_observe", "tests")
ROOTLESS_SOCKET = "local_observe/inventory/docker_provider.py"


def write_checkout(root: Path, files: dict[str, str]) -> Path:
    """Materialise `files` (relative path -> body) under `root`, which stands in for a checkout."""
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


def capitalised_tokens(relative: str) -> list[str]:
    """Banned tokens this checkout spells with any capital letter — the exact class #286 missed.

    A token is reported here when its case-folded form is in the file and its exact lowercase form is
    not: the token is named, but only in a casing a case-sensitive scan walks straight past.
    """
    exact = (ROOT / relative).read_text(encoding="utf-8")
    return [token for token in checks.BANNED_TOKENS if token in exact.casefold() and token not in exact]


class ScanFixture(unittest.TestCase):
    """`scan()` runs the shipped gate over a synthetic checkout with registers supplied by the test."""

    def scan(self, files, *, allowances=None, register=None):
        with tempfile.TemporaryDirectory() as directory:
            return checks.check_private_references(write_checkout(Path(directory), files),
                                                   register=register, allowances=allowances)


class ScopeAndCase(ScanFixture):
    def test_every_tree_is_walked_in_every_casing(self):
        """#286 findings 1 and 2 together: a mixed-case token under any scanned tree must be refused."""
        for tree in TREES:
            for token in checks.BANNED_TOKENS:
                with self.subTest(tree=tree, token=token):
                    relative = f"{tree}/new_source.py"
                    found = self.scan({relative: f"# forbidden fixture: {token.swapcase()}\n"})
                    self.assertEqual(len(found), 1, found)
                    self.assertIn(relative, found[0])
                    self.assertIn(token, found[0])

    def test_uppercase_extension_is_not_an_escape(self):
        """The suffix filter is case-folded too: `README.MD` is the same kind of file as `README.md`."""
        for suffix in (".MD", ".PY", ".PS1", ".YAML"):
            with self.subTest(suffix=suffix):
                found = self.scan({"local_observe/note" + suffix: checks.BANNED_TOKENS[0].upper() + "\n"})
                self.assertEqual(len(found), 1, found)

    def test_clean_product_and_test_trees_stay_quiet(self):
        """Widening the walk must not invent findings: generic Linux paths and plain prose still pass."""
        self.assertEqual(self.scan({"local_observe/inventory/x.py": "socket = '/run/user/1001/daemon'\n",
                                    "tests/test_x.py": "assert 'elsewhere' in text\n",
                                    "components/clean.yaml": "name: elsewhere\n"}), [])

    def test_a_root_without_the_new_trees_is_scanned_without_complaint(self):
        """A fixture checkout holding only `components/` owes nobody a `local_observe/` (#286 scope)."""
        self.assertEqual(self.scan({"components/clean.yaml": "name: elsewhere\n"}), [])

    def test_the_shipped_checkout_passes_the_widened_gate(self):
        """The measured baseline: green here means #286's rewrites landed; red is a live leak in this tree."""
        self.assertEqual(checks.check_private_references(ROOT), [])



class Allowances(ScanFixture):
    def test_an_allowance_covers_one_path_and_the_tokens_it_names(self):
        """Exact path and exact token, never a directory exemption (#286's "behind a register")."""
        for tree in ALLOWED_TREES:
            with self.subTest(tree=tree):
                token, other = checks.BANNED_TOKENS[0], checks.BANNED_TOKENS[1]
                relative = f"{tree}/fixture.py"
                allowance = {relative: ("Intentional refusal fixture.", (token,))}
                self.assertEqual(self.scan({relative: token.swapcase() + "\n"}, allowances=allowance), [])
                found = self.scan({relative: f"{token} {other}\n", f"{tree}/other.py": token + "\n"},
                                  allowances=allowance)
                self.assertEqual(len(found), 2, found)
                self.assertTrue(any(relative in e and other in e for e in found), found)
                self.assertTrue(any(f"{tree}/other.py" in e for e in found), found)

    def test_allowance_never_reaches_the_shipped_component_or_script_trees(self):
        """`components/` and `examples/` hold no exception and `scripts/` has its own register: an
        allowance aimed at either is refused as an entry and does not hide the leak."""
        token = checks.BANNED_TOKENS[0]
        for relative in ("components/fixture.py", "examples/fixture.py", "scripts/stage.py"):
            with self.subTest(path=relative):
                found = self.scan({relative: token + "\n"},
                                  allowances={relative: ("Not a source or test fixture.", (token,))})
                self.assertTrue(any("exact source or test path" in e for e in found), found)
                self.assertTrue(any("private or forbidden" in e for e in found), found)

    def test_a_pattern_or_traversal_allowance_matches_nothing_and_is_itself_refused(self):
        """`tests/**` is a directory exemption wearing an entry and `tests/../local_observe/x.py`
        walks out of the tree it claims to guard. Neither may hide the file that is really there."""
        token = checks.BANNED_TOKENS[0]
        for pattern in ("tests/**.py", "tests/../local_observe/x.py", "local_observe"):
            with self.subTest(pattern=pattern):
                found = self.scan({"local_observe/x.py": token + "\n"},
                                  allowances={pattern: ("Broad on purpose.", (token,))})
                self.assertTrue(any("private or forbidden" in e for e in found), found)
                self.assertTrue(any("require an exact source or test path" in e or "path does not exist" in e
                                    for e in found), found)

    def test_a_blank_reason_waives_nothing(self):
        """Rule 5 of the scripts register, mirrored: the reason is the review, not decoration."""
        token = checks.BANNED_TOKENS[0]
        for reason in ("", "   "):
            with self.subTest(reason=repr(reason)):
                relative = "tests/fixture.py"
                found = self.scan({relative: token + "\n"},
                                  allowances={relative: (reason, (token,))})
                self.assertTrue(any("must state its reason" in e for e in found), found)
                self.assertTrue(any("private or forbidden" in e for e in found), found)

    def test_an_allowance_must_name_canonical_banned_tokens(self):
        """An entry with no token, a near-miss token or a misspelled one waives what it matches — nothing.

        The near-miss has to be reported and the file still has to be refused: a typo that quietly
        matches nothing is how a waiver becomes a permanent hole.
        """
        token = checks.BANNED_TOKENS[0]
        for tokens in ((), (token[0] + token[1:].replace("a", "-"),), (token, token + "x")):
            with self.subTest(tokens=tokens):
                relative = "tests/fixture.py"
                found = self.scan({relative: token + "\n"},
                                  allowances={relative: ("Intentional fixture.", tokens)})
                self.assertTrue(any("exact banned tokens" in e for e in found), found)
                self.assertTrue(any("private or forbidden" in e for e in found), found)

    def test_a_stale_allowance_token_is_reported(self):
        """A fixture that stopped naming the token retires its entry instead of widening the gate."""
        token, gone = checks.BANNED_TOKENS[0], checks.BANNED_TOKENS[1]
        found = self.scan({"tests/fixture.py": token + "\n"},
                          allowances={"tests/fixture.py": ("Old refusal fixture.", (token, gone))})
        self.assertEqual(len(found), 1, found)
        self.assertIn("absent tokens", found[0])
        self.assertIn(gone, found[0])

    def test_an_allowance_for_a_path_that_is_gone_is_reported(self):
        """A moved or deleted fixture leaves its entry behind, and an orphan entry is a standing hole."""
        token = checks.BANNED_TOKENS[0]
        found = self.scan({"tests/clean.py": "generic content\n"},
                          allowances={"tests/moved_away.py": ("Removed refusal fixture.", (token,))})
        self.assertEqual(len(found), 1, found)
        self.assertIn("tests/moved_away.py", found[0])
        self.assertIn("path does not exist", found[0])

    def test_the_default_allowances_stay_quiet_against_a_foreign_root(self):
        """`--root` (release contract): a foreign checkout is not this checkout's waiver review, but a leak in it
        is still a leak — the shipped entries neither hide it nor complain about being unmatched."""
        token = checks.BANNED_TOKENS[0]
        with tempfile.TemporaryDirectory() as directory:
            root = write_checkout(Path(directory), {"tests/leak.py": token + "\n"})
            found = checks.check_private_references(root)
        self.assertEqual(len(found), 1, found)
        self.assertIn("tests/leak.py", found[0])
        self.assertIn("private or forbidden", found[0])
        self.assertNotIn("stale waiver", found[0])


class ShippedRegister(unittest.TestCase):
    """The entries this checkout ships, each one checked against the file it claims to describe."""

    def test_every_shipped_allowance_is_an_exact_existing_source_or_test_path(self):
        self.assertTrue(checks.PRIVACY_ALLOWANCES, "an empty register would mean these trees are clean")
        for relative, (reason, tokens) in checks.PRIVACY_ALLOWANCES.items():
            with self.subTest(path=relative):
                self.assertTrue(reason.strip(), "an entry waiving nothing needs no reason")
                self.assertTrue(tokens)
                self.assertTrue(relative.startswith(ALLOWED_TREES), relative)
                self.assertNotIn("..", Path(relative).parts)
                self.assertFalse(any(character in relative for character in "*?[]"), relative)
                self.assertTrue((ROOT / relative).is_file(), f"{relative} is not in this checkout")
                self.assertTrue(all(token in checks.BANNED_TOKENS for token in tokens), relative)

    def test_every_shipped_allowance_is_load_bearing_in_both_directions(self):
        """Without the entry the file is refused for exactly its tokens; with it, that file alone is clean.

        A waiver that hides nothing is stale and the gate says so; one that a cleaned file no longer
        needs is caught the same way. This asserts both halves per entry, on the real bytes.
        """
        for relative, (reason, tokens) in checks.PRIVACY_ALLOWANCES.items():
            body = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                with tempfile.TemporaryDirectory() as directory:
                    root = write_checkout(Path(directory), {relative: body})
                    naked = checks.check_private_references(root, register={}, allowances={})
                self.assertEqual(len(naked), 1, naked)
                for token in tokens:
                    self.assertIn(token, naked[0])
                with tempfile.TemporaryDirectory() as directory:
                    root = write_checkout(Path(directory), {relative: body})
                    waived = checks.check_private_references(root, register={},
                                                             allowances={relative: (reason, tokens)})
                self.assertEqual(waived, [], waived)

    def test_the_generic_rootless_socket_needs_its_own_entry_and_no_more(self):
        """The allowance #286 asked for by name: a rootless socket path used as a validation pattern is
        generic Linux, not estate topology — the same text anywhere else is still a leak."""
        reason, tokens = checks.PRIVACY_ALLOWANCES[ROOTLESS_SOCKET]
        self.assertTrue(any("sock" in token for token in tokens), tokens)
        self.assertIn("run/user", (ROOT / ROOTLESS_SOCKET).read_text(encoding="utf-8"))
        body = "PATTERN = '/run/user/1001/" + tokens[0] + "'\n"
        with tempfile.TemporaryDirectory() as directory:
            guarded = checks.check_private_references(
                write_checkout(Path(directory), {ROOTLESS_SOCKET: body}), register={},
                allowances={ROOTLESS_SOCKET: (reason, tokens)})
        with tempfile.TemporaryDirectory() as directory:
            elsewhere = checks.check_private_references(
                write_checkout(Path(directory), {"local_observe/inventory/other.py": body}),
                register={}, allowances={})
        self.assertEqual(guarded, [], guarded)
        self.assertEqual(len(elsewhere), 1, elsewhere)



if __name__ == "__main__":
    unittest.main()

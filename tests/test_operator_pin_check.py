"""Tests for the two operator gates the product ships (release contract): the pin check and the wrapper.

`scripts/operator/pin_check.py` answers one question offline: is the operator's committed
`local-observe.pin.json` still true of the product checkout standing beside it? The commit half of
that question is answered from `git`, so most of it is tested through an injected resolver and a
mocked `subprocess.run`.

overlay gate rules closed the seam this file used to report: `overlay_gate.sh`'s all-pass path now runs end to end
against a fixture release (`git_fixture_release`), which is a real git repository carrying a real
`v0.1.0` tag, standing in a `tempfile.TemporaryDirectory()`. That is the one exception to the rule
that this suite runs no state-changing git, and it is narrow: **`init`, `commit --allow-empty` and
`tag` inside that temporary directory, run with `git -C <fixture>` only. Nothing in the worktree this
suite runs from is committed, added, stashed, branched, tagged or pushed, and the fixture is never
fetched from or pushed to a remote.** Where no `git` or no POSIX shell is on the host the wrapper
tests skip and say so; the interpreter-level test runs everywhere and is the one that proves the
fixture.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "operator"))
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation
import pin_check

COMMIT = "a" * 40
OTHER_COMMIT = "c" * 40
PLATFORM_DIGEST = "sha256:" + "1" * 64
SIGNOZ_DIGEST = "sha256:" + "2" * 64
CLICKHOUSE_DIGEST = "sha256:" + "3" * 64
UNRECORDED_DIGEST = "sha256:" + "9" * 64


def product_checkout(root: Path) -> Path:
    """Write a product tree whose pin registers record the three digests these tests use."""
    platform = root / "components" / "control" / "platform"
    store = root / "components" / "data" / "store-signoz"
    platform.mkdir(parents=True)
    store.mkdir(parents=True)
    (platform / "versions.json").write_text(json.dumps({
        "image_id": PLATFORM_DIGEST,
        "gatus_image": f"example/gatus@{PLATFORM_DIGEST}",
        "distribution": "local image config IDs; no registry publication claimed",
    }), encoding="utf-8")
    (store / "versions.json").write_text(json.dumps({
        "images": {"LO_SIGNOZ_IMAGE": "example/signoz:v0.138.0",
                   "LO_CLICKHOUSE_IMAGE": "example/clickhouse:25.12.5"},
    }), encoding="utf-8")
    (store / "image-lock.json").write_text(json.dumps({
        "images": {"LO_SIGNOZ_IMAGE": {"candidate": "example/signoz:v0.138.0",
                                        "image": f"example/signoz@{SIGNOZ_DIGEST}"},
                   "LO_CLICKHOUSE_IMAGE": {"candidate": "example/clickhouse:25.12.5",
                                           "image": f"example/clickhouse@{CLICKHOUSE_DIGEST}"}},
    }), encoding="utf-8")
    return root


def pin(tag: str = "v0.1.0", commit: str = COMMIT, images: dict | None = None) -> dict:
    """One operator pin, with the three keys the contract allows and defaults that match the fixture."""
    return {"tag": tag, "commit": commit,
            "images": images if images is not None
            else {"LO_SIGNOZ_IMAGE": f"example/signoz@{SIGNOZ_DIGEST}",
                  "LO_PLATFORM_IMAGE": PLATFORM_DIGEST}}


def write_pin(directory: Path, value: object) -> Path:
    """Write a pin file (or anything else) and return its path."""
    path = directory / "local-observe.pin.json"
    text = value if isinstance(value, str) else json.dumps(value, indent=2)
    path.write_text(text, encoding="utf-8")
    return path


def run_check(pin_value: dict, checkout: Path, resolved: str | None = COMMIT) -> list[str]:
    """check_pin with the two external readers replaced: the tag resolver and a fixed product tree."""
    return pin_check.check_pin(pin_value, checkout, resolve=lambda _path, _tag: resolved)


#: The four lifecycle documents a directory under `components/` owes the gate.
LIFECYCLE_DOCS = ("CONTRACT.md", "backup.md", "upgrade.md", "conformance.md")
#: A component carrying a platform marker and the shipped non-sending delivery default: the shape
#: `check_delivery` reads out of the merged model (overlay gate rules), measured to pass every other rule.
FIXTURE_COMPONENT = ("services:\n  thing:\n    image: ${LO_THING_IMAGE:?pin the thing image}\n"
                     "    environment:\n"
                     "      LO_STATE_PATH: /data/platform.db\n"
                     "      LO_PLATFORM_CREDENTIALS: /run/secrets/platform-credentials\n"
                     "      LO_NOTIFICATION_MODE: ${LO_NOTIFICATION_MODE:-recording}\n"
                     "    secrets:\n      - platform-credentials\n"
                     "    volumes:\n      - ./thing.yaml:/etc/thing.yaml:ro\n"
                     "secrets:\n  platform-credentials:\n"
                     "    file: ${LO_PLATFORM_CREDENTIALS_FILE:?path to the role credentials JSON}\n")
#: The operator's top-level file: one entry merging the pinned component with their own overlay.
FIXTURE_MODEL = ("include:\n"
                 "  - path:\n"
                 "      - ../../product/components/control/thing/compose.yaml\n"
                 "      - ./thing.overlay.yaml\n"
                 "    project_directory: ../../product/components/control/thing\n")
#: The overlay of the passing fixture: one extra environment key, no rule touched.
FIXTURE_OVERLAY = "services:\n  thing:\n    environment:\n      LO_EXTRA: '1'\n"
#: The overlay of the refusing fixture: a live default merged into the platform-marked service.
LIVE_OVERLAY = ("services:\n  thing:\n    environment:\n"
                "      LO_NOTIFICATION_MODE: ${LO_NOTIFICATION_MODE:-live}\n")


def git_environment() -> dict[str, str]:
    """The host's environment with every way in which a developer's git could answer instead of us.

    `GIT_DIR`/`GIT_WORK_TREE`/`GIT_INDEX_FILE` are removed (this suite runs inside a git worktree, and
    an inherited one would aim the fixture's commands at it), global and system config are pointed at
    the bit bucket so no identity, `commit.gpgsign`, `core.hooksPath` or template directory can change
    the result, and the author/committer are named here.
    """
    env = dict(os.environ)
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        env.pop(key, None)
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_AUTHOR_NAME": "local-observe tests", "GIT_AUTHOR_EMAIL": "tests.invalid",
                "GIT_COMMITTER_NAME": "local-observe tests", "GIT_COMMITTER_EMAIL": "tests.invalid"})
    return env


def run_fixture_git(checkout: Path, *arguments: str) -> str:
    """One git call aimed at the fixture checkout and nowhere else: list argv, scrubbed env, timeout.

    Only three of these change state (`init`, `commit --allow-empty`, `tag`) and `rev-parse` is the
    single read-only call, used to hand the new commit's ID back to the caller.
    """
    result = subprocess.run(["git", "-C", str(checkout), *arguments], env=git_environment(),
                            capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(f"fixture git {' '.join(arguments)} failed in {checkout}: "
                           f"{result.stdout.strip()} {result.stderr.strip()}")
    return result.stdout.strip()


def git_fixture_release(base: Path) -> tuple[Path, str]:
    """A product checkout that is also a git repository carrying the tag a pin can name.

    Returns (checkout, commit). Everything happens inside `base`, a temporary directory: `git init`,
    one `--allow-empty` commit and one `v0.1.0` tag, with the host's global and system gitconfig
    switched off so a developer's identity, signing or hook template cannot change the result. The
    tag peels to a commit and `pin_check.tag_commit` never reads the tree, which is why an empty
    commit is enough. No git command here touches the worktree this suite runs from.

    The tree is the one `check_foundation` accepts: `product_checkout`'s pin registers (so the
    default pin's two digests match), plus one component under `components/control/thing/` with its
    four lifecycle documents and its `thing.yaml`. The operator's `deploy/compose.yaml` and its
    `thing.overlay.yaml` go in `operator/`, a sibling of the checkout and outside it -- which is the
    layout overlay gate rules made gateable, and the reason `--root` alone cannot walk this fixture.
    """
    checkout = product_checkout(base / "product")
    component = checkout / "components" / "control" / "thing"
    component.mkdir(parents=True)
    (component / "compose.yaml").write_text(FIXTURE_COMPONENT, encoding="utf-8")
    (component / "thing.yaml").write_text("# component configuration\n", encoding="utf-8")
    for name in LIFECYCLE_DOCS:
        (component / name).write_text(f"# {name}\n", encoding="utf-8")
    deploy = base / "operator" / "deploy"
    deploy.mkdir(parents=True)
    (deploy / "thing.overlay.yaml").write_text(FIXTURE_OVERLAY, encoding="utf-8")
    (deploy / "compose.yaml").write_text(FIXTURE_MODEL, encoding="utf-8")
    run_fixture_git(checkout, "init", "-b", "main")
    run_fixture_git(checkout, "commit", "--allow-empty", "-m", "fixture release for the overlay gate")
    run_fixture_git(checkout, "tag", "v0.1.0")
    return checkout, run_fixture_git(checkout, "rev-parse", "HEAD")


class PinMatchesTests(unittest.TestCase):
    """The passing case, and the shapes that must not be mistaken for one."""

    def test_a_pin_that_matches_the_checkout_reports_no_error(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            self.assertEqual(run_check(pin(), checkout), [])

    def test_the_pin_names_are_read_from_the_release_registers_by_name(self):
        """`LO_SIGNOZ_IMAGE` is a key the product uses, so its own digest is the only one accepted."""
        with tempfile.TemporaryDirectory() as directory:
            product_pins, by_digest, errors = pin_check.product_pins(product_checkout(Path(directory)))
        self.assertEqual(errors, [])
        self.assertEqual(product_pins["LO_SIGNOZ_IMAGE"],
                         {SIGNOZ_DIGEST: "components/data/store-signoz/image-lock.json"})
        self.assertEqual(by_digest[CLICKHOUSE_DIGEST], "components/data/store-signoz/image-lock.json")
        self.assertEqual(product_pins["image_id"], {PLATFORM_DIGEST: "components/control/platform/versions.json"})

    def test_a_commit_that_is_not_the_tag_s_commit_is_refused_naming_both(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            found = run_check(pin(commit=OTHER_COMMIT), checkout, resolved=COMMIT)
            self.assertEqual(len(found), 1, found)
            self.assertIn("v0.1.0", found[0])
            self.assertIn(OTHER_COMMIT, found[0])
            self.assertIn(COMMIT, found[0])
            self.assertIn("a tag that moved is a different release", found[0])

    def test_a_tag_the_checkout_does_not_have_is_refused_rather_than_assumed(self):
        """An absent tag is the most dangerous input here: treating it as "unknown, fine" is a green CI
        over an installation whose product bytes nobody reviewed."""
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            found = run_check(pin(), checkout, resolved=None)
            self.assertEqual(len(found), 1, found)
            self.assertIn("resolves no such tag", found[0])


class PinImageDigestTests(unittest.TestCase):
    """The image half: every pinned reference must be a digest this release records, under its name."""

    def test_a_digest_recorded_for_a_different_name_is_refused(self):
        """Two pins swapped is the failure a bare set-membership test would wave through."""
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            swapped = pin(images={"LO_SIGNOZ_IMAGE": f"example/signoz@{CLICKHOUSE_DIGEST}"})
            found = run_check(swapped, checkout)
            self.assertEqual(len(found), 1, found)
            self.assertIn("LO_SIGNOZ_IMAGE", found[0])
            self.assertIn(CLICKHOUSE_DIGEST, found[0])
            self.assertIn(SIGNOZ_DIGEST, found[0], "the refusal must say what the release records")
            self.assertIn("components/data/store-signoz/image-lock.json", found[0])

    def test_a_tag_only_reference_is_refused_because_it_is_not_a_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            found = run_check(pin(images={"LO_SIGNOZ_IMAGE": "example/signoz:v0.138.0"}), checkout)
            self.assertEqual(len(found), 1, found)
            self.assertIn("carries no sha256 digest", found[0])

    def test_a_digest_the_release_records_nowhere_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            found = run_check(pin(images={"LO_SIGNOZ_IMAGE": UNRECORDED_DIGEST}), checkout)
            self.assertEqual(len(found), 1, found)
            self.assertIn("records", found[0])

    def test_an_image_the_product_does_not_name_by_that_key_is_judged_against_every_recorded_digest(self):
        """An operator may key a pin by their own label; the digest still has to be this release's."""
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            self.assertEqual(run_check(pin(images={"gatus": f"example/gatus@{PLATFORM_DIGEST}"}),
                                       checkout), [])
            found = run_check(pin(images={"gatus": UNRECORDED_DIGEST}), checkout)
            self.assertEqual(len(found), 1, found)
            self.assertIn("gatus", found[0])

    def test_a_non_string_image_value_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            found = run_check(pin(images={"LO_SIGNOZ_IMAGE": {"image": SIGNOZ_DIGEST}}), checkout)
            self.assertEqual(len(found), 1, found)
            self.assertIn("must be one reference string", found[0])

    def test_a_broken_pin_register_refuses_the_checkout_instead_of_emptying_it(self):
        """An unreadable register must not read as a register with nothing in it."""
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            broken = checkout / "components" / "data" / "store-signoz" / "image-lock.json"
            broken.write_text('{"images": ', encoding="utf-8")
            _by_name, _by_digest, errors = pin_check.product_pins(checkout)
            self.assertEqual(len(errors), 1, errors)
            self.assertIn("image-lock.json", errors[0])
            self.assertIn("not valid JSON", errors[0])
            found = run_check(pin(), checkout)
            self.assertTrue(any("not valid JSON" in line for line in found), found)


class MalformedPinFileTests(unittest.TestCase):
    """load_pin: a file that cannot be understood is refused whole, and nothing is checked against it."""

    def setUp(self) -> None:
        self.checkout = product_checkout(Path(tempfile.mkdtemp()) / "product")

    def load(self, value: object) -> tuple[dict, list[str]]:
        with tempfile.TemporaryDirectory() as directory:
            return pin_check.load_pin(write_pin(Path(directory), value))

    def test_a_file_that_is_not_json_is_refused(self):
        pin_value, errors = self.load('{"tag": ')
        self.assertEqual(pin_value, {})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("is not readable JSON", errors[0])

    def test_a_file_that_is_not_an_object_is_refused(self):
        _pin_value, errors = self.load(["v0.1.0", COMMIT])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("must hold one JSON object", errors[0])

    def test_a_missing_key_is_refused_by_name(self):
        pin_value, errors = self.load({"tag": "v0.1.0", "images": {}})
        self.assertEqual(pin_value, {})
        self.assertTrue(any("missing required key 'commit'" in line for line in errors), errors)

    def test_an_unknown_key_is_refused_because_a_typo_would_drop_a_promise(self):
        _pin_value, errors = self.load(dict(pin(), accepted="2026-09-15"))
        self.assertTrue(any("unknown pin key 'accepted'" in line for line in errors), errors)
        _pin_value, errors = self.load({"tag": "v0.1.0", "commmit": COMMIT, "images": {"a": SIGNOZ_DIGEST}})
        self.assertTrue(any("missing required key 'commit'" in line for line in errors), errors)
        self.assertTrue(any("unknown pin key 'commmit'" in line for line in errors), errors)

    def test_an_abbreviated_commit_or_a_tag_name_in_the_commit_field_is_refused(self):
        for value in (COMMIT[:12], "v0.1.0", COMMIT.upper(), 1234):
            with self.subTest(commit=value):
                _pin_value, errors = self.load(dict(pin(commit=value), images={"a": SIGNOZ_DIGEST}))
                self.assertTrue(any("full 40-hex-digit commit ID" in line for line in errors), errors)

    def test_a_tag_that_is_not_a_release_number_is_refused(self):
        for value in ("0.1.0", "v0.1", "v0.1.0.0", "main", "v0.1.0-rc1", None):
            with self.subTest(tag=value):
                _pin_value, errors = self.load(dict(pin(tag=value), images={"a": SIGNOZ_DIGEST}))
                self.assertTrue(any("vMAJOR.MINOR.PATCH" in line for line in errors), errors)

    def test_an_empty_images_map_is_refused_because_it_checks_nothing(self):
        _pin_value, errors = self.load(pin(images={}))
        self.assertTrue(any("non-empty mapping" in line for line in errors), errors)

    def test_a_pin_file_that_does_not_exist_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            pin_value, errors = pin_check.load_pin(Path(directory) / "local-observe.pin.json")
        self.assertEqual(pin_value, {})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("no operator pin file there", errors[0])

    def test_a_malformed_pin_never_reaches_the_git_or_digest_checks(self):
        """Half a pin is not a promise: the resolver must not be called for a file that will not load."""
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            pin_path = write_pin(Path(directory), '{"tag": ')
            calls: list[str] = []
            with patch.object(pin_check, "tag_commit", side_effect=lambda *_a: calls.append("called")), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = pin_check.main(["--pin", str(pin_path), "--checkout", str(checkout)])
        self.assertEqual(code, 1)
        self.assertEqual(calls, [], "a malformed pin is refused before anything is resolved")


class GitResolutionTests(unittest.TestCase):
    """tag_commit: one read-only `git rev-parse`, asked of the tag and never of a branch."""

    def recorded(self, returncode: int, stdout: str = COMMIT + "\n") -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(args=["git"], returncode=returncode, stdout=stdout, stderr="")

    def test_the_question_asked_is_for_refs_tags_and_the_peeled_commit(self):
        with patch.object(pin_check.subprocess, "run", return_value=self.recorded(0)) as run:
            resolved = pin_check.tag_commit(Path("some/checkout"), "v0.1.0")
        arguments = run.call_args.args[0]
        self.assertEqual(resolved, COMMIT)
        self.assertEqual(arguments[0], "git")
        self.assertEqual(arguments[arguments.index("-C") + 1], str(Path("some/checkout")))
        self.assertIn("refs/tags/v0.1.0^{commit}", arguments)
        self.assertTrue(run.call_args.kwargs["timeout"] <= 30, "a gate cannot hang on a repository")

    def test_a_tag_that_is_absent_or_a_repository_that_errors_both_resolve_to_nothing(self):
        """No answer from git is never treated as agreement: all three shapes refuse."""
        for returncode, stdout in ((1, ""), (128, ""), (0, "  \n")):
            with self.subTest(returncode=returncode, stdout=stdout), patch.object(
                    pin_check.subprocess, "run", return_value=self.recorded(returncode, stdout)):
                self.assertIsNone(pin_check.tag_commit(Path("."), "v0.1.0"))


class CommandLineTests(unittest.TestCase):
    """main(): the two required arguments, the verdict line, the machine report and the exit code."""

    def test_a_matching_pin_exits_zero_and_says_what_it_matched(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            pin_path = write_pin(Path(directory), pin())
            out = io.StringIO()
            with patch.object(pin_check, "tag_commit", return_value=COMMIT), \
                    contextlib.redirect_stdout(out):
                code = pin_check.main(["--pin", str(pin_path), "--checkout", str(checkout)])
        self.assertEqual(code, 0, out.getvalue())
        self.assertIn("pin OK: v0.1.0", out.getvalue())
        self.assertIn("2 image digest(s)", out.getvalue())

    def test_a_refusal_exits_one_and_prints_every_line_of_it(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            pin_path = write_pin(Path(directory), pin(commit=OTHER_COMMIT,
                                                      images={"LO_SIGNOZ_IMAGE": UNRECORDED_DIGEST}))
            out = io.StringIO()
            with patch.object(pin_check, "tag_commit", return_value=COMMIT), \
                    contextlib.redirect_stdout(out):
                code = pin_check.main(["--pin", str(pin_path), "--checkout", str(checkout)])
        self.assertEqual(code, 1)
        self.assertIn("a tag that moved", out.getvalue())
        self.assertIn("LO_SIGNOZ_IMAGE", out.getvalue())

    def test_the_json_report_names_the_verdict_the_pin_and_the_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = product_checkout(Path(directory) / "product")
            pin_path = write_pin(Path(directory), pin(commit=OTHER_COMMIT))
            out = io.StringIO()
            with patch.object(pin_check, "tag_commit", return_value=COMMIT), \
                    contextlib.redirect_stdout(out):
                code = pin_check.main(["--pin", str(pin_path), "--checkout", str(checkout), "--json"])
        report = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertEqual(report["pin_check"], "fail")
        self.assertEqual(report["tag"], "v0.1.0")
        self.assertEqual(len(report["errors"]), 1, report["errors"])

    def test_the_arguments_are_required_because_a_default_pin_would_check_nothing(self):
        for arguments in ([], ["--pin", "x.json"], ["--checkout", "product"]):
            with self.subTest(arguments=arguments), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as stopped:
                pin_check.main(arguments)
            self.assertEqual(stopped.exception.code, 2)


class OverlayGateScriptTests(unittest.TestCase):
    """overlay_gate.sh: its argument and pre-flight paths, and since overlay gate rules its all-pass path too.

    The first five tests need no repository. The last three stand on `git_fixture_release`, a real
    checkout with a real tag inside a temporary directory, and skip with a stated reason where the
    host has no `git` or no POSIX shell -- a skip is reported as a skip, never written as a pass.
    """

    sh = shutil.which("sh") or shutil.which("bash")
    script = ROOT / "scripts" / "operator" / "overlay_gate.sh"

    def run_gate(self, *arguments: str) -> subprocess.CompletedProcess:
        interpreter = Path(sys.executable).as_posix()
        return subprocess.run([self.sh, str(self.script), "--python", interpreter, *arguments], cwd=ROOT,
                              capture_output=True, text=True, timeout=180)

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    def test_missing_arguments_are_a_usage_error_not_a_pass(self):
        for arguments in (["--root", "."], ["--root", ".", "--pin", "x.json"],
                          ["--root", ".", "--pin", "x.json", "--bogus"]):
            with self.subTest(arguments=arguments):
                result = self.run_gate(*arguments)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("usage", (result.stdout + result.stderr).lower())

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    def test_no_arguments_at_all_is_a_usage_error(self):
        """The wrapper is called with its own defaults first, so the bare call must refuse too."""
        result = subprocess.run([self.sh, str(self.script)], cwd=ROOT, capture_output=True,
                                text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("usage", result.stderr.lower())

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    def test_a_root_that_is_not_a_product_checkout_refuses_before_any_gate_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_gate("--root", directory, "--pin", "x.json", "model.yaml")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not a product checkout", result.stderr)
        self.assertNotIn("check_foundation", result.stdout, "the gates never ran")

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    def test_help_names_the_arguments_and_exits_zero(self):
        result = self.run_gate("--help")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--pin PIN MODEL", result.stdout)

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    def test_both_gates_run_and_any_refusal_sets_the_exit_code(self):
        """One real product checkout, one operator model, and a pin whose tag does not exist here.

        `git tag` is empty in this repository (docs/RELEASING.md is what changes that, and the owner
        cuts the tag), so the pin half must refuse -- which is the assertion: the wrapper reports both
        halves and exits 1 rather than stopping at the first gate or hiding the second one.
        """
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "merged.compose.yaml"
            model.write_text("services:\n  thing:\n    image: ${LO_THING_IMAGE:?pin the thing image}\n"
                             "    ports: [\"0.0.0.0:9999:8080\"]\n", encoding="utf-8")
            pin_path = write_pin(Path(directory), pin())
            result = self.run_gate("--root", str(ROOT), "--pin", str(pin_path), str(model))
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("check_foundation --root", combined, "the merged-model gate ran")
        self.assertIn("development publication must be loopback-only", combined)
        self.assertIn("pin_check --pin", combined, "the pin gate ran too, after a failing first gate")
        self.assertIn("resolves no such tag", combined)
        self.assertIn("overlay_gate: FAILED", combined)

    @unittest.skipIf(shutil.which("git") is None, "no git on this host")
    def test_a_fixture_release_clears_both_gates_when_they_are_called_directly(self):
        """The fixture is sound, proven without a shell: this is what a Windows host can always run.

        Two calls, both of which the wrapper makes: `check_foundation` over the operator's merged
        model (which under overlay gate rules no longer crashes on a checkout that ships no front door, and now
        reads the delivery rule out of the merged model) and `pin_check.main` against the tag the
        fixture cut. Both green means the wrapper tests below fail for the wrapper's own reasons only.
        """
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            checkout, commit = git_fixture_release(base)
            model = checkout.parent / "operator" / "deploy" / "compose.yaml"
            self.assertEqual(check_foundation.check_foundation(checkout, [str(model)]), [])
            pin_path = write_pin(checkout.parent / "operator", pin(commit=commit))
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                code = pin_check.main(["--pin", str(pin_path), "--checkout", str(checkout)])
            self.assertEqual(code, 0, printed.getvalue())
            self.assertIn("pin OK: v0.1.0", printed.getvalue())

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    @unittest.skipIf(shutil.which("git") is None, "no git on this host")
    def test_the_wrapper_passes_end_to_end_on_a_fixture_release(self):
        """The all-pass path, which had never run: exit 0, both gate banners, and no FAILED line.

        The wrapper runs *this* checkout's gate scripts (`here` comes from its own location) against
        the fixture given by `--root`; the scripts are not copied into the fixture. Paths go to it in
        POSIX form (`as_posix()`), because the shell on this host is MSYS and forward slashes are the
        one spelling neither it nor Python argues with.
        """
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            checkout, commit = git_fixture_release(base)
            model = checkout.parent / "operator" / "deploy" / "compose.yaml"
            pin_path = write_pin(checkout.parent / "operator", pin(commit=commit))
            result = self.run_gate("--root", checkout.as_posix(), "--pin", pin_path.as_posix(),
                                   model.as_posix())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--- check_foundation --root", result.stdout)
        self.assertIn("--- pin_check --pin", result.stdout)
        self.assertIn("pin OK: v0.1.0", result.stdout)
        self.assertNotIn("overlay_gate: FAILED", result.stdout + result.stderr)

    @unittest.skipIf(sh is None, "no POSIX shell on this host")
    @unittest.skipIf(shutil.which("git") is None, "no git on this host")
    def test_the_wrapper_refuses_an_overlay_that_defaults_to_live_delivery(self):
        """The negative half of the ledger row, end to end -- and it must refuse for the right reason.

        One byte of the fixture changes from the test above: the operator's overlay, standing in their
        own directory outside `--root`, merges `LO_NOTIFICATION_MODE:-live` into the platform-marked
        service. The pin still passes (its banner is asserted below), so the exit code can only come
        from the delivery rule the merged model is now anchored on.
        """
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            checkout, commit = git_fixture_release(base)
            model = checkout.parent / "operator" / "deploy" / "compose.yaml"
            (model.parent / "thing.overlay.yaml").write_text(LIVE_OVERLAY, encoding="utf-8")
            pin_path = write_pin(checkout.parent / "operator", pin(commit=commit))
            result = self.run_gate("--root", checkout.as_posix(), "--pin", pin_path.as_posix(),
                                   model.as_posix())
        combined = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, combined)
        self.assertIn("notification mode must default to a non-sending mode", result.stdout)
        self.assertIn("pin OK: v0.1.0", result.stdout, "the pin passed: the refusal is the model's")
        self.assertIn("overlay_gate: FAILED", result.stderr)


if __name__ == "__main__":
    unittest.main()

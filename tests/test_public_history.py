"""Real synthetic Git roots exercise publication metadata and export receipt checks.

Each fixture is a fresh single-commit repository: `commit --amend` would leave the previous root
unreachable in the same object database, which is a refusal under test rather than a fixture.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    SPEC = importlib.util.spec_from_file_location("check_public_history", SCRIPTS / "check_public_history.py")
    checker = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(checker)
    EXPORTER_SPEC = importlib.util.spec_from_file_location("export_public_tree_round", SCRIPTS / "export_public_tree.py")
    exporter = importlib.util.module_from_spec(EXPORTER_SPEC)
    EXPORTER_SPEC.loader.exec_module(exporter)
finally:
    sys.path.pop(0)


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class PublicHistoryTests(unittest.TestCase):
    README = b"Generic product\n"
    LOGO = b"\x89BIN\x00\x01" + bytes(range(32, 127))  # NUL-bearing, holds no forbidden token

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.policy = self.root / "private-policy.json"
        self.report = self.root / "private-report.json"
        self.identity = {"name": "Example Project", "email": "project@example.invalid"}
        self.policy_json = {"version": 1, "include": ["*"], "exclude": [], "replacements": [],
                            "forbidden": ["private-fixture"], "binary_sha256": {},
                            "public_identity": self.identity}
        self.sequence = 0
        self.build({"README.md": self.README})

    # ---------------------------------------------------------------- fixture
    def git(self, *args):
        return subprocess.run(
            ["git", "-c", f"safe.directory={self.candidate.as_posix()}", "-C", str(self.candidate),
             "-c", "core.autocrlf=false", "-c", "user.name=Example Project",
             "-c", "user.email=project@example.invalid", *args], check=True, capture_output=True,
        ).stdout.decode("utf-8")

    def build(self, files):
        """Rebuild candidate, private policy and private report so the three agree."""
        self.sequence += 1
        self.candidate = self.root / f"candidate-{self.sequence}"
        self.candidate.mkdir()
        self.files = dict(files)
        for name, payload in sorted(self.files.items()):
            path = self.candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.git("init", "-q")
        self.git("add", "--all")
        self.git("commit", "-qm", "Initial product")
        self.revision = self.git("rev-parse", "HEAD").strip()
        self.data = {"history_included": False, "public_identity": self.policy_json["public_identity"],
                     "files": [{"source_path": name, "path": name, "mode": "100644", "bytes": len(payload),
                                "sha256": digest(payload)} for name, payload in sorted(self.files.items())]}
        if "utf8_approvals" in self.policy_json:
            self.data["utf8_approvals"] = self.policy_json["utf8_approvals"]
        self.save_policy()

    def write_policy(self):
        self.policy.write_text(json.dumps(self.policy_json), encoding="utf-8")

    def save_report(self):
        self.report.write_text(json.dumps(self.data), encoding="utf-8")

    def save_policy(self):
        """Edit the policy and keep the report's hash of it consistent; drift has its own test."""
        self.write_policy()
        self.data["policy_sha256"] = hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.save_report()

    def row(self, index=0):
        return self.data["files"][index]

    def check(self):
        return checker.check_history(self.candidate, self.revision, self.policy, self.report)

    def index_state(self):
        index = self.candidate / ".git/index"
        return index.read_bytes(), index.stat().st_mtime_ns

    def configure_monitor(self) -> Path:
        """Point the candidate's own core.fsmonitor at a command that leaves a marker behind."""
        marker = self.root / "monitor-marker.txt"
        script = self.root / "monitor.sh"
        script.write_text("#!/bin/sh\ntouch " + shlex.quote(marker.as_posix()) + "\nexit 0\n", encoding="utf-8")
        os.chmod(script, 0o755)
        self.git("config", "core.fsmonitor", script.as_posix())
        return marker

    # ---------------------------------------------------------------- contract
    def test_root_identity_and_committed_bytes_verified_without_mutation(self):
        # A stale stat is what makes `git status` rewrite .git/index when optional locks are allowed.
        os.utime(self.candidate / "README.md", (0, 0))
        before = self.index_state()
        result = self.check()
        self.assertTrue(result["fresh_root"])
        self.assertTrue(result["identity_verified"])
        self.assertTrue(result["manifest_match"])
        self.assertTrue(result["content_rescan_clean"])
        self.assertFalse(result["publication_authorized"])
        # Bytes and mtime, not porcelain text: a refresh-write can leave the text identical.
        self.assertEqual(self.index_state(), before)
        self.assertEqual(self.git("status", "--porcelain=v1"), "")

    def test_repository_configured_fsmonitor_is_never_invoked(self):
        """core.fsmonitor is a program the candidate repository chooses; git status must not run it.

        The control invocation proves this Git really does execute a configured monitor, so the
        assertion below is a discrimination and not an absence of mechanism.
        """
        marker = self.configure_monitor()
        self.git("status", "--porcelain=v1")
        if not marker.exists():
            self.skipTest("this Git does not invoke a configured core.fsmonitor command")
        marker.unlink()
        result = self.check()
        self.assertTrue(result["manifest_match"])
        self.assertTrue(result["content_rescan_clean"])
        self.assertFalse(marker.exists())

    def test_repository_configured_fsmonitor_cannot_declare_a_dirty_tree_clean(self):
        """The monitor's answer is also disabled, so an untracked leftover still refuses."""
        marker = self.configure_monitor()
        (self.candidate / "leftover.txt").write_bytes(b"Generic leftover\n")
        with self.assertRaisesRegex(checker.ExportError, "not clean"):
            self.check()
        self.assertFalse(marker.exists())

    def test_wrong_identity_in_policy_refused(self):
        self.policy_json["public_identity"] = {"name": "Different Project", "email": "project@example.invalid"}
        self.write_policy()
        with self.assertRaisesRegex(checker.ExportError, "author or committer"):
            self.check()

    def test_second_commit_refused(self):
        self.git("commit", "--allow-empty", "-qm", "Second")
        self.revision = self.git("rev-parse", "HEAD").strip()
        with self.assertRaises(checker.ExportError):
            self.check()

    def test_unreachable_private_history_refused(self):
        self.git("commit", "--amend", "-qm", "Different root")
        self.revision = self.git("rev-parse", "HEAD").strip()
        with self.assertRaisesRegex(checker.ExportError, "additional history"):
            self.check()

    def test_alternates_refused(self):
        (self.candidate / ".git/objects/info/alternates").write_text(str(self.root / "elsewhere"), encoding="utf-8")
        with self.assertRaisesRegex(checker.ExportError, "inherit"):
            self.check()

    def test_symlinked_history_path_refused(self):
        elsewhere = self.root / "private-objects"
        elsewhere.mkdir()
        link = self.candidate / ".git/objects/info/alternates"
        try:
            link.symlink_to(elsewhere)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(checker.ExportError, "inherit"):
            self.check()

    def test_dangling_symlinked_history_path_refused(self):
        """Path.exists() is False for a dangling link; the lexical check must still refuse."""
        link = self.candidate / ".git/shallow"
        try:
            link.symlink_to(self.root / "never-created")
        except OSError:
            self.skipTest("symlinks unavailable")
        self.assertFalse(link.exists())
        with self.assertRaisesRegex(checker.ExportError, "inherit"):
            self.check()

    def test_dangling_link_arm_is_lexical_where_links_cannot_be_created(self):
        """Unprivileged hosts refuse symlink(): prove the arm answers lexically, not by following."""
        real_islink = os.path.islink
        target = self.candidate / ".git/shallow"

        def islink(path):
            return Path(path) == target or real_islink(path)

        with mock.patch.object(os.path, "islink", islink), mock.patch.object(os.path, "lexists", lambda path: False):
            with self.assertRaisesRegex(checker.ExportError, "inherit"):
                self.check()

    def test_junction_on_intermediate_objects_component_refused(self):
        """A junction is not a symlink on Windows; objects/info components must refuse one too.

        Covered synthetically because a real junction over .git/objects would have to displace the
        fixture's own object store; the .git-root junction case exercises the same OS answer for real.
        """
        target = (self.candidate / ".git/objects").resolve()
        real_islink, real_junction = os.path.islink, Path.is_junction

        def islink(path):
            # Exactly what a junction reports on Windows: islink() False.
            return False if Path(path).resolve() == target else real_islink(path)

        def is_junction(path):
            return True if Path(path).resolve() == target else real_junction(path)

        self.assertFalse(real_islink(target))
        self.assertFalse(real_junction(target))
        with mock.patch.object(os.path, "islink", islink), mock.patch.object(Path, "is_junction", is_junction):
            with self.assertRaisesRegex(checker.ExportError, "inherit"):
                self.check()

    def test_junction_on_info_component_refused(self):
        """The same answer for the second chain, so no name in the list depends on the first."""
        target = (self.candidate / ".git/info").resolve()
        real_junction = Path.is_junction

        def is_junction(path):
            return True if Path(path).resolve() == target else real_junction(path)

        with mock.patch.object(Path, "is_junction", is_junction):
            with self.assertRaisesRegex(checker.ExportError, "inherit"):
                self.check()

    def test_linked_dot_git_directory_refused(self):
        """A linked .git borrows another object database: symlink where allowed, junction on Windows."""
        holder = self.root / "holder"
        holder.mkdir()
        link = holder / ".git"
        try:
            link.symlink_to(self.candidate / ".git", target_is_directory=True)
        except OSError:
            if os.name != "nt":
                self.skipTest("no link type available")
            made = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(self.candidate / ".git")],
                                  capture_output=True, check=False)
            if made.returncode or not link.is_junction():
                self.skipTest("no link type available")
        with self.assertRaisesRegex(checker.ExportError, "own Git directory"):
            checker.check_history(holder, self.revision, self.policy, self.report)

    # ---------------------------------------------------------------- refs
    def test_extra_benign_branch_refused(self):
        """A second branch on the same commit adds no object and no reachable commit."""
        self.git("branch", "wip-copy")
        with self.assertRaisesRegex(checker.ExportError, "exactly one"):
            self.check()

    def test_private_branch_name_refused(self):
        self.git("branch", "-m", "private-fixture-branch")
        with self.assertRaisesRegex(checker.ExportError, "ref name"):
            self.check()

    def test_note_ref_refused(self):
        self.git("notes", "add", "-m", "private-fixture note")
        with self.assertRaisesRegex(checker.ExportError, "exactly one"):
            self.check()

    def test_extra_loose_blob_refused(self):
        secret = self.root / "private.txt"
        secret.write_bytes(b"private-fixture")
        self.git("hash-object", "-w", str(secret))
        with self.assertRaisesRegex(checker.ExportError, "unreviewed objects"):
            self.check()

    # ---------------------------------------------------------------- manifest
    def test_manifest_hash_drift_refused(self):
        self.row()["sha256"] = "0" * 64
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "blob differs"):
            self.check()

    def test_manifest_bytes_drift_refused(self):
        self.row()["bytes"] = len(self.README) - 1
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "blob differs"):
            self.check()

    def test_manifest_mode_drift_refused(self):
        self.row()["mode"] = "100755"
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "blob differs"):
            self.check()

    def test_manifest_policy_hash_drift_refused(self):
        self.data["policy_sha256"] = "0" * 64
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "reviewed policy"):
            self.check()

    def test_manifest_row_shape_refused(self):
        base = {"source_path": "README.md", "path": "README.md", "mode": "100644",
                "bytes": len(self.README), "sha256": digest(self.README)}
        cases = [{"source_path": "README.md", "path": "README.md", "bytes": 16, "sha256": "0" * 64},
                 {**base, "bytes": "16"},
                 {**base, "bytes": True},
                 {**base, "bytes": -1},
                 {**base, "sha256": "zz" * 32},
                 {**base, "sha256": digest(self.README).upper()},
                 {**base, "path": "../escape"},
                 {**base, "path": "README.md", "source_path": "other.md"}]
        for row in cases:
            self.data["files"] = [row]
            with self.subTest(row=sorted(row)):
                self.save_report()
                with self.assertRaises(checker.ExportError):
                    self.check()

    def test_tree_file_absent_from_manifest_refused(self):
        self.build({"README.md": self.README, "docs/guide.md": b"Generic guide\n"})
        self.data["files"] = [row for row in self.data["files"] if row["path"] != "docs/guide.md"]
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "differs from export manifest"):
            self.check()

    def test_manifest_path_not_selected_by_policy_refused(self):
        self.build({"README.md": self.README, "docs/guide.md": b"Generic guide\n"})
        self.policy_json["include"] = ["README.md"]
        self.save_policy()
        with self.assertRaisesRegex(checker.ExportError, "not selected by the private policy"):
            self.check()

    def test_rewritten_output_is_selected_by_its_source_path(self):
        """Selection and rewriting follow the private source path, as they do in the exporter."""
        self.policy_json["replacements"] = [{"from": "private-host", "to": "nas"}]
        self.policy_json["include"] = ["private-host/*", "README.md"]
        self.build({"nas/app.py": b"print(1)\n"})
        self.row()["source_path"] = "private-host/app.py"
        self.save_policy()
        self.assertTrue(self.check()["manifest_match"])

    def test_manifest_path_not_rewritten_by_policy_refused(self):
        self.policy_json["replacements"] = [{"from": "private-host", "to": "nas"}]
        self.policy_json["include"] = ["private-host/*", "README.md"]
        self.build({"nas/app.py": b"print(1)\n"})
        self.save_policy()
        with self.assertRaisesRegex(checker.ExportError, "not selected|policy rewrite"):
            self.check()

    def test_manifest_private_path_refused(self):
        """A manifest can faithfully describe a private filename; the path ban is not delegated."""
        self.build({"README.md": self.README, "private-fixture/runbook.md": b"Generic runbook\n"})
        with self.assertRaisesRegex(checker.ExportError, "remains in exported path"):
            self.check()

    def test_private_content_surviving_a_faithful_manifest_refused(self):
        leaked = b"Generic product mentions private-fixture\n"
        self.build({"README.md": leaked})
        self.assertEqual(digest(leaked), self.row()["sha256"])
        with self.assertRaisesRegex(checker.ExportError, "remains in candidate content"):
            self.check()

    def test_private_filename_in_tree_refused_even_if_manifest_agrees(self):
        self.build({"private-fixture.md": self.README})
        with self.assertRaisesRegex(checker.ExportError, "remains in exported path"):
            self.check()

    # ---------------------------------------------------------------- approvals
    def approve(self, name, payload, sha=None):
        self.policy_json["utf8_approvals"] = [{"path": name,
                                               "sha256": sha or digest(payload),
                                               "token": "private-fixture",
                                               "reason": "Canonical example placeholder in the demo fixture"}]
        self.build({name: payload})

    def test_exact_hash_utf8_approval_is_honoured_by_rescan(self):
        leaked = b"Generic product mentions private-fixture\n"
        self.approve("docs/demo.md", leaked)
        self.assertTrue(self.check()["content_rescan_clean"])

    def test_stale_approval_hash_refused_by_rescan(self):
        self.approve("docs/demo.md", b"Generic product mentions private-fixture\n", sha="0" * 64)
        with self.assertRaisesRegex(checker.ExportError, "content or approval"):
            self.check()

    def test_unused_approval_refused(self):
        self.approve("docs/demo.md", b"Generic product\n")
        with self.assertRaisesRegex(checker.ExportError, "every reviewed UTF-8 approval"):
            self.check()

    def test_approval_does_not_exempt_filename(self):
        leaked = b"Generic product mentions private-fixture\n"
        self.approve("private-fixture.md", leaked)
        with self.assertRaisesRegex(checker.ExportError, "remains in exported path"):
            self.check()

    def test_approval_does_not_exempt_binary_bytes(self):
        """Even an approved-by-hash binary is refused when it names a forbidden identifier."""
        payload = b"\x00private-fixture\x00"
        self.policy_json["binary_sha256"] = {"assets/logo.bin": digest(payload)}
        self.approve("assets/logo.bin", payload)
        with self.assertRaisesRegex(checker.ExportError, "remains in candidate content"):
            self.check()

    # ---------------------------------------------------------------- binary approvals
    def test_unapproved_binary_behind_a_faithful_report_refused(self):
        """A report that describes unreviewed bytes perfectly is still an unreviewed binary.

        The payload names no forbidden identifier, so the content re-scan would pass it: only the
        exporter's binary_sha256 rule, re-derived here against the committed bytes, refuses.
        """
        self.build({"assets/logo.bin": self.LOGO})
        self.assertEqual(digest(self.LOGO), self.row()["sha256"])
        with self.assertRaisesRegex(checker.ExportError, "lacks its approved source hash"):
            self.check()

    def test_approved_binary_passes_the_rescan(self):
        self.policy_json["binary_sha256"] = {"assets/logo.bin": digest(self.LOGO)}
        self.build({"assets/logo.bin": self.LOGO})
        self.assertTrue(self.check()["content_rescan_clean"])

    def test_binary_approval_with_other_hash_refused(self):
        self.policy_json["binary_sha256"] = {"assets/logo.bin": "0" * 64}
        self.build({"assets/logo.bin": self.LOGO})
        with self.assertRaisesRegex(checker.ExportError, "lacks its approved source hash"):
            self.check()

    def test_binary_approval_keyed_by_rewritten_output_path_refused(self):
        """binary_sha256 maps the PRIVATE source path, as in the exporter, never the output name."""
        self.policy_json["replacements"] = [{"from": "private-host", "to": "nas"}]
        self.policy_json["include"] = ["private-host/*"]
        self.policy_json["binary_sha256"] = {"nas/logo.bin": digest(self.LOGO)}
        self.build({"nas/logo.bin": self.LOGO})
        self.row()["source_path"] = "private-host/logo.bin"
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "lacks its approved source hash"):
            self.check()

    def test_report_approval_drift_refused(self):
        self.approve("docs/demo.md", b"Generic product mentions private-fixture\n")
        del self.data["utf8_approvals"]
        self.save_report()
        with self.assertRaisesRegex(checker.ExportError, "approvals differ"):
            self.check()

    # ---------------------------------------------------------------- round trip
    def export_source(self, files):
        """A private repository committed by a private author identity; returns it and its root."""
        source = self.root / f"source-{self.sequence}"
        source.mkdir()

        def src(*args):
            return subprocess.run(
                ["git", "-c", f"safe.directory={source.as_posix()}", "-C", str(source),
                 "-c", "core.autocrlf=false", "-c", "user.name=fixture-private-author",
                 "-c", "user.email=author@private-host.invalid", *args], check=True, capture_output=True,
            ).stdout.decode("utf-8").strip()

        for name, payload in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        src("init", "-q")
        src("add", "--all")
        src("commit", "-qm", "private chronology private-host")
        return source, src("rev-parse", "HEAD")

    def test_real_export_and_fresh_root_round_trip_is_verified(self):
        """The exporter's own report passes the checker: rewrites, exclusions and one approval."""
        source = self.root / "source"
        source.mkdir()

        def src(*args):
            return subprocess.run(
                ["git", "-c", f"safe.directory={source.as_posix()}", "-C", str(source),
                 "-c", "core.autocrlf=false", "-c", "user.name=fixture-private-author",
                 "-c", "user.email=author@private-host.invalid", *args], check=True, capture_output=True,
            ).stdout.decode("utf-8").strip()

        demo = b"Reviewed vendor string: spark here\n"
        for name, payload in {"private-host/settings.json": b'{"host": "private-host"}\n',
                              "docs/demo.md": demo,
                              "private/note.md": b"synthetic-secret\n"}.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        src("init", "-q")
        src("add", "--all")
        src("commit", "-qm", "private chronology private-host synthetic-secret")
        revision = src("rev-parse", "HEAD")

        self.policy_json["exclude"] = ["private/*"]
        self.policy_json["include"] = ["private-host/*", "docs/*"]
        self.policy_json["replacements"] = [{"from": "private-host", "to": "nas"}]
        self.policy_json["forbidden"] = ["private-host", "synthetic-secret", "spark"]
        self.policy_json["utf8_approvals"] = [{"path": "docs/demo.md", "sha256": digest(demo),
                                              "token": "spark", "reason": "Reviewed upstream vendor name"}]
        round_private = self.root / "round-private"
        round_private.mkdir()
        round_policy = round_private / "round-policy.json"
        round_report = round_private / "round-report.json"
        round_policy.write_text(json.dumps(self.policy_json), encoding="utf-8")
        destination = self.root / "candidate-round"
        exported = exporter.export_tree(source, revision, round_policy, destination, round_report)
        self.assertEqual([row["path"] for row in exported["files"]], ["docs/demo.md", "nas/settings.json"])

        self.candidate = destination
        self.git("init", "-q")
        self.git("add", "--all")
        self.git("commit", "-qm", "Initial product")
        self.revision = self.git("rev-parse", "HEAD").strip()
        result = checker.check_history(destination, self.revision, round_policy, round_report)
        self.assertEqual(result["files"], 2)
        self.assertTrue(result["manifest_match"])
        self.assertTrue(result["content_rescan_clean"])
        self.assertFalse(result["publication_authorized"])

    def test_real_export_round_trips_a_binary_approved_by_private_source_path(self):
        """Exporter and checker must agree on one binary rule: approved source path, exact bytes.

        The exporter rewrites the path but never the bytes, so the approval survives the rewrite only
        under its private key; the re-keyed forgery is the last arm of this test.
        """
        source, revision = self.export_source({"private-host/logo.bin": self.LOGO,
                                               "docs/demo.md": b"Reviewed text\n"})
        self.policy_json["include"] = ["private-host/*", "docs/*"]
        self.policy_json["replacements"] = [{"from": "private-host", "to": "nas"}]
        self.policy_json["forbidden"] = ["private-host", "synthetic-secret"]
        self.policy_json["binary_sha256"] = {"private-host/logo.bin": digest(self.LOGO)}
        private = self.root / "binary-private"
        private.mkdir()
        policy, report = private / "binary-policy.json", private / "binary-report.json"
        policy.write_text(json.dumps(self.policy_json), encoding="utf-8")
        destination = self.root / "candidate-binary"
        exported = exporter.export_tree(source, revision, policy, destination, report)
        self.assertEqual([row["path"] for row in exported["files"]], ["docs/demo.md", "nas/logo.bin"])
        self.assertEqual([row["binary"] for row in exported["files"]], [False, True])

        self.candidate = destination
        self.git("init", "-q")
        self.git("add", "--all")
        self.git("commit", "-qm", "Initial product")
        self.revision = self.git("rev-parse", "HEAD").strip()
        result = checker.check_history(destination, self.revision, policy, report)
        self.assertTrue(result["content_rescan_clean"])

        # Same committed bytes, same tree, only the approval re-keyed onto the public path.
        forged_policy = json.loads(policy.read_text(encoding="utf-8"))
        forged_policy["binary_sha256"] = {"nas/logo.bin": digest(self.LOGO)}
        policy.write_text(json.dumps(forged_policy), encoding="utf-8")
        forged_report = json.loads(report.read_text(encoding="utf-8"))
        forged_report["policy_sha256"] = hashlib.sha256(policy.read_bytes()).hexdigest()
        report.write_text(json.dumps(forged_report), encoding="utf-8")
        with self.assertRaisesRegex(checker.ExportError, "lacks its approved source hash"):
            checker.check_history(destination, self.revision, policy, report)

    # ---------------------------------------------------------------- worktree
    def test_dirty_and_untracked_tree_refused(self):
        for name in ("README.md", "new.txt"):
            with self.subTest(name=name):
                path = self.candidate / name
                path.write_bytes(b"different")
                with self.assertRaisesRegex(checker.ExportError, "not clean"):
                    self.check()
                if name == "README.md":
                    path.write_bytes(self.README)
                else:
                    path.unlink()

    def test_ignored_leftover_refused(self):
        exclude = self.candidate / ".git/info/exclude"
        exclude.write_text(exclude.read_text(encoding="utf-8") + "ignored.txt\n", encoding="utf-8")
        (self.candidate / "ignored.txt").write_bytes(b"different")
        with self.assertRaisesRegex(checker.ExportError, "not clean"):
            self.check()


if __name__ == "__main__":
    unittest.main()

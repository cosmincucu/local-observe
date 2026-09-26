"""Synthetic private Git fixtures verify the public-export boundary independently."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("export_public_tree", Path(__file__).resolve().parents[1] / "scripts/export_public_tree.py")
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


class PublicExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.private = self.root / "private"
        self.private.mkdir()
        self.policy_path = self.private / "policy.json"
        self.destination = self.root / "public"
        self.report = self.private / "report.json"
        self.policy = {"version": 1, "include": ["*"], "exclude": ["private/*"],
                       "replacements": [{"from": "private-host", "to": "nas"},
                                        {"from": "owner.invalid", "to": "example.test"}],
                       "forbidden": ["private-host", "owner.invalid", "synthetic-secret"], "binary_sha256": {}}
        self.git("init", "-q")
        self.write("private-host/settings.json", json.dumps({"nested": {"array": ["private-host.owner.invalid", None, 7]}}))
        self.write("private/note.md", "synthetic-secret")
        self.write(".hidden", "caf\u00e9 private-host\r\n")
        self.revision = self.commit()

    def git(self, *args):
        result = subprocess.run(["git", "-c", f"safe.directory={self.source.as_posix()}", "-C", str(self.source),
                                 "-c", "core.autocrlf=false",
                                 "-c", "user.name=fixture-private-author", "-c", "user.email=author@owner.invalid", *args],
                                capture_output=True, check=True)
        return result.stdout.decode().strip()

    def write(self, name, value):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "-qm", "private-host synthetic-secret private chronology")
        return self.git("rev-parse", "HEAD")

    def run_export(self, **kwargs):
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        return exporter.export_tree(self.source, self.revision, self.policy_path, self.destination, self.report, **kwargs)

    def refused(self):
        with self.assertRaises(exporter.ExportError):
            self.run_export()
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.report.exists())

    def test_pinned_nested_content_hidden_paths_no_history_and_repeatability(self):
        self.write("untracked-secret", "synthetic-secret")
        self.write(".hidden", "dirty synthetic-secret")
        before = self.git("status", "--porcelain=v1")
        result = self.run_export()
        expected = {".hidden", "nas/settings.json"}
        self.assertEqual({p.relative_to(self.destination).as_posix() for p in self.destination.rglob("*") if p.is_file()}, expected)
        self.assertEqual(json.loads((self.destination / "nas/settings.json").read_text()), {"nested": {"array": ["nas.example.test", None, 7]}})
        self.assertEqual((self.destination / ".hidden").read_bytes(), "caf\u00e9 nas\r\n".encode())
        self.assertFalse((self.destination / ".git").exists())
        self.assertEqual(self.git("status", "--porcelain=v1"), before)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.revision)
        for file in self.destination.rglob("*"):
            if file.is_file():
                self.assertNotIn(b"private", file.read_bytes())
                self.assertNotIn(b"synthetic-secret", file.read_bytes())
        self.destination = self.root / "public-two"
        self.report = self.private / "report-two.json"
        repeated = self.run_export()
        self.assertEqual(result, repeated)
        for row in repeated["files"]:
            self.assertEqual(hashlib.sha256((self.destination / row["path"]).read_bytes()).hexdigest(), row["sha256"])

    def test_dry_run_writes_nothing(self):
        result = self.run_export(dry_run=True)
        self.assertEqual(len(result["files"]), 2)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.report.exists())

    def test_hidden_content_secret_refused_before_output(self):
        self.write(".hidden-secret", "synthetic-secret")
        self.revision = self.commit()
        self.refused()

    def test_filename_secret_refused(self):
        self.write("synthetic-secret.txt", "clean")
        self.revision = self.commit()
        self.refused()

    def test_case_insensitive_forbidden(self):
        self.write("note", "SYNTHETIC-SECRET")
        self.revision = self.commit()
        self.refused()

    def test_binary_requires_hash_even_when_name_is_text(self):
        self.write("opaque.txt", b"\x00\xffsafe")
        self.revision = self.commit()
        self.refused()
        self.policy["binary_sha256"] = {"opaque.txt": hashlib.sha256(b"\x00\xffsafe").hexdigest()}
        self.run_export()
        self.assertEqual((self.destination / "opaque.txt").read_bytes(), b"\x00\xffsafe")

    def test_approved_binary_still_scanned(self):
        content = b"\x00synthetic-secret\xff"
        self.write("binary", content)
        self.revision = self.commit()
        self.policy["binary_sha256"] = {"binary": hashlib.sha256(content).hexdigest()}
        self.refused()

    def test_non_utf8_rejected(self):
        self.write("odd", b"\xff")
        self.revision = self.commit()
        self.refused()

    def test_symlink_blob_rejected_without_following(self):
        self.git("update-index", "--add", "--cacheinfo", "120000", self.git("rev-parse", "HEAD:.hidden"), "link")
        self.git("commit", "-qm", "link fixture")
        self.revision = self.git("rev-parse", "HEAD")
        self.refused()

    def test_submodule_rejected(self):
        self.git("update-index", "--add", "--cacheinfo", "160000", self.revision, "module")
        self.git("commit", "-qm", "module fixture")
        self.revision = self.git("rev-parse", "HEAD")
        self.refused()

    def test_rename_case_collision(self):
        self.write("NAS/settings.json", "other")
        self.revision = self.commit()
        self.refused()

    def test_file_directory_collision(self):
        self.write("nas", "other")
        self.revision = self.commit()
        self.refused()

    def test_longest_replacement_is_simultaneous(self):
        self.policy["replacements"] = [{"from": "private-host.owner.invalid", "to": "ai.example.test"},
                                       {"from": "private-host", "to": "nas"}, {"from": "nas", "to": "backup"}]
        self.run_export()
        self.assertIn("ai.example.test", (self.destination / "nas/settings.json").read_text())

    def test_unsafe_renames(self):
        for replacement in ("../bad", "/absolute", "C:/drive", ".git", "CON", "bad."):
            with self.subTest(replacement=replacement):
                self.policy["replacements"][0]["to"] = replacement
                self.refused()

    def test_private_mapping_never_selected(self):
        self.write("anonymise.map", "decoder")
        self.revision = self.commit()
        self.refused()

    def test_policy_schema_malformed(self):
        baseline = self.policy
        for broken in ([], {}, {**baseline, "version": True}, {**baseline, "replacements": [{"from": "x"}]},
                       {**baseline, "include": "*"}, {**baseline, "forbidden": []},
                       {**baseline, "binary_sha256": {"bad": "no"}}, {**baseline, "extra": 1}):
            with self.subTest(policy=broken):
                self.policy = broken
                self.refused()

    def test_duplicate_json_key(self):
        self.policy_path.write_text('{"version":1,"version":1}', encoding="utf-8")
        with self.assertRaises(exporter.ExportError):
            exporter.read_policy(self.policy_path)

    def test_full_revision_required(self):
        self.revision = "HEAD"
        self.refused()

    def test_empty_selection_refused(self):
        self.policy["include"] = ["absent/*"]
        self.refused()

    def test_existing_output_preserved(self):
        self.destination.mkdir()
        sentinel = self.destination / "keep"
        sentinel.write_text("retained")
        with self.assertRaises(exporter.ExportError):
            self.run_export()
        self.assertEqual(sentinel.read_text(), "retained")

    def test_report_inside_output_refused(self):
        self.report = self.destination / "report.json"
        self.refused()

    def test_output_inside_source_refused(self):
        self.destination = self.source / "public"
        self.refused()

    def test_output_inside_policy_directory_refused(self):
        self.destination = self.private / "public"
        self.refused()

    def test_rewrite_expansion_is_bounded_before_allocation(self):
        original = exporter.MAX_FILE
        exporter.MAX_FILE = 100
        self.addCleanup(setattr, exporter, "MAX_FILE", original)
        rewrite = exporter._rewriter({"replacements": [{"from": "x", "to": "z" * 60}]})
        with self.assertRaises(exporter.ExportError):
            rewrite("xx")

    def test_long_path_component_refused(self):
        self.policy["replacements"] = [{"from": "private-host", "to": "z" * 300}]
        self.refused()

    def test_selected_input_size_bound(self):
        self.write("oversize.txt", "a" * 2000)
        self.revision = self.commit()
        original = exporter.MAX_FILE
        exporter.MAX_FILE = 1000
        self.addCleanup(setattr, exporter, "MAX_FILE", original)
        self.refused()

    def test_diagnose_collects_nested_array_hits_without_context(self):
        self.write("nested.json", json.dumps({"items": ["prefix SYNTHETIC-SECRET private-context",
                                                        {"value": "synthetic-secret another-private-context"}]}))
        self.write("other.txt", "synthetic-secret")
        self.revision = self.commit()
        with self.assertRaises(exporter.ExportError):
            self.run_export(dry_run=True, diagnose=True)
        self.assertFalse(self.destination.exists())
        raw = self.report.read_text(encoding="utf-8")
        report = json.loads(raw)
        self.assertEqual(report["status"], "refused")
        self.assertFalse(report["publication_authorized"])
        self.assertNotIn("private-context", raw)
        self.assertNotIn("prefix", raw)
        self.assertEqual(report["diagnostics"]["matched_occurrences"], 3)
        self.assertEqual(report["diagnostics"]["total_findings"], 2)
        findings = report["diagnostics"]["findings"]
        self.assertEqual({row["path"]: row["count"] for row in findings}, {"nested.json": 2, "other.txt": 1})
        self.assertTrue(all(row["token"] == "synthetic-secret" for row in findings))

    def test_diagnose_successful_dry_run_writes_only_private_report(self):
        self.run_export(dry_run=True, diagnose=True)
        self.assertFalse(self.destination.exists())
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "validated")
        self.assertEqual(report["validated_files"], 2)

    def test_diagnostics_are_bounded_and_metadata_is_sanitized(self):
        token = "x" * 300 + "\n\x1b[31m"
        self.policy["forbidden"] = [token]
        for index in range(exporter.MAX_DIAGNOSTICS + 2):
            self.write(f"hit-{index:03d}.txt", "DO-NOT-DISCLOSE-CONTEXT " + token)
        self.revision = self.commit()
        with self.assertRaises(exporter.ExportError):
            self.run_export(diagnose=True)
        raw = self.report.read_bytes()
        report = json.loads(raw)
        diagnostics = report["diagnostics"]
        self.assertLess(len(raw), exporter.MAX_DIAGNOSTIC_BYTES)
        self.assertEqual(len(diagnostics["findings"]), exporter.MAX_DIAGNOSTICS)
        self.assertEqual(diagnostics["total_findings"], exporter.MAX_DIAGNOSTICS + 2)
        self.assertTrue(diagnostics["truncated"])
        self.assertNotIn(b"DO-NOT-DISCLOSE-CONTEXT", raw)
        self.assertTrue(all(row["token"].isprintable() for row in diagnostics["findings"]))
        self.assertTrue(all(len(row["token"]) <= 142 for row in diagnostics["findings"]))

    def test_named_schema_errors_and_private_diagnostics(self):
        del self.policy["binary_sha256"]
        with self.assertRaisesRegex(exporter.ExportError, "missing policy key: binary_sha256"):
            self.run_export(diagnose=True)
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertIn("binary_sha256", report["error"])
        self.assertFalse(self.destination.exists())

    def test_unknown_and_nested_missing_keys_are_named_without_values(self):
        cases = [({**self.policy, "typo": "PRIVATE-VALUE"}, "unknown policy key: typo"),
                 ({**self.policy, "replacements": [{"from": "PRIVATE-VALUE"}]}, "missing replacement key: to"),
                 ({**self.policy, "utf8_approvals": [{"path": "vendor.js"}]}, "missing UTF-8 approval key: reason")]
        for policy, message in cases:
            with self.subTest(message=message):
                self.policy = policy
                with self.assertRaisesRegex(exporter.ExportError, message) as caught:
                    self.run_export()
                self.assertNotIn("PRIVATE-VALUE", str(caught.exception))

    def test_duplicate_nested_key_is_named(self):
        self.policy_path.write_text('{"replacements":[{"from":"a","from":"b"}]}', encoding="utf-8")
        with self.assertRaisesRegex(exporter.ExportError, "duplicate policy key: from"):
            exporter.read_policy(self.policy_path)

    def test_unsafe_diagnostic_locations_never_write(self):
        self.policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
        for report, output, message in [
            (self.report, self.private / "output", "private policy directory"),
            (self.destination, self.destination, "private report and output"),
            (self.source / "diagnostic.json", self.destination, "private report must be outside source"),
            (self.policy_path, self.destination, "private report must differ from private policy"),
            (self.destination / "diagnostic.json", self.destination, "private report and output"),
        ]:
            with self.subTest(message=message):
                before = self.policy_path.read_bytes()
                with self.assertRaisesRegex(exporter.ExportError, message):
                    exporter.export_tree(self.source, self.revision, self.policy_path, output, report, diagnose=True)
                self.assertEqual(self.policy_path.read_bytes(), before)
                self.assertFalse(output.exists())
        self.assertFalse((self.source / "diagnostic.json").exists())

    def test_existing_diagnostic_report_is_not_overwritten(self):
        self.report.write_text("preserve", encoding="utf-8")
        with self.assertRaises(exporter.ExportError):
            self.run_export(diagnose=True)
        self.assertEqual(self.report.read_text(encoding="utf-8"), "preserve")
        self.assertFalse(self.destination.exists())

    def test_dangling_report_symlink_refused(self):
        target = self.private / "uncreated-target.json"
        try:
            self.report.symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaisesRegex(exporter.ExportError, "symlinks"):
            self.run_export(diagnose=True)
        self.assertFalse(target.exists())

    def approve_vendor(self):
        self.write("private-host/vendor.js", "private-host Spark spark")
        self.revision = self.commit()
        self.policy["forbidden"].append("spark")
        approval = {"path": "nas/vendor.js", "sha256": hashlib.sha256(b"nas Spark spark").hexdigest(),
                    "token": "spark", "reason": "Reviewed upstream icon names, unrelated to private hosts"}
        self.policy["utf8_approvals"] = [approval]
        return approval

    def test_exact_reviewed_utf8_output_hash_allows_only_named_token(self):
        approval = self.approve_vendor()
        result = self.run_export()
        self.assertEqual((self.destination / "nas/vendor.js").read_bytes(), b"nas Spark spark")
        self.assertEqual(result["utf8_approvals"], [approval])

    def test_utf8_substring_ban_remains_strict_by_default(self):
        self.approve_vendor()
        del self.policy["utf8_approvals"]
        self.refused()

    def test_changed_bytes_and_stale_approval_refused(self):
        self.approve_vendor()
        for content in ("private-host Spark spark changed", "no forbidden token remains"):
            with self.subTest(content=content):
                self.write("private-host/vendor.js", content)
                self.revision = self.commit()
                self.refused()

    def test_approval_for_omitted_or_wrong_path_refused(self):
        approval = self.approve_vendor()
        self.policy["exclude"].append("*/vendor.js")
        self.refused()
        self.policy["exclude"].pop()
        approval["path"] = "private-host/vendor.js"
        self.refused()

    def test_utf8_approval_does_not_exempt_filename_or_other_tokens(self):
        approval = self.approve_vendor()
        self.write("spark.js", "private-host Spark spark")
        self.revision = self.commit()
        self.policy["utf8_approvals"].append({**approval, "path": "spark.js"})
        self.refused()
        self.policy["exclude"].append("spark.js")
        self.policy["utf8_approvals"].pop()
        self.write("private-host/vendor.js", "private-host Spark spark synthetic-secret")
        self.revision = self.commit()
        approval["sha256"] = hashlib.sha256(b"nas Spark spark synthetic-secret").hexdigest()
        self.refused()

    def test_utf8_approval_never_exempts_binary(self):
        approval = self.approve_vendor()
        binary = b"\x00Spark spark"
        self.write("private-host/vendor.js", binary)
        self.revision = self.commit()
        approval["sha256"] = hashlib.sha256(binary).hexdigest()
        self.policy["binary_sha256"] = {"private-host/vendor.js": approval["sha256"]}
        self.refused()

    def test_malformed_utf8_approvals(self):
        approval = self.approve_vendor()
        for broken in ({}, [None], [{**approval, "extra": 1}], [{**approval, "token": "not-in-policy"}],
                       [{**approval, "reason": " "}], [{**approval, "sha256": "f"}],
                       [{**approval, "path": "../escape"}], [approval, approval]):
            with self.subTest(broken=broken):
                self.policy["utf8_approvals"] = broken
                self.refused()

    def test_public_identity_validated_and_reported_privately(self):
        self.policy["public_identity"] = {"name": "Platform Project", "email": "maintainer@example.org"}
        result = self.run_export()
        self.assertEqual(result["public_identity"], self.policy["public_identity"])
        self.assertEqual(json.loads(self.report.read_text(encoding="utf-8"))["public_identity"], self.policy["public_identity"])
        self.assertFalse((self.destination / ".git").exists())

    def test_invalid_and_private_public_identities_refused(self):
        valid = {"name": "Platform Project", "email": "maintainer@example.org"}
        for identity in (None, {}, {**valid, "extra": "x"}, {**valid, "name": "OWNER.INVALID"},
                         {**valid, "name": "x\nInjected"}, {**valid, "name": "x" * 101},
                         {**valid, "email": "person@OWNER.INVALID"}, {**valid, "email": "bad address@example.org"},
                         {**valid, "email": "person@example.org\nInjected"}, {**valid, "email": "Name <person@example.org>"}):
            with self.subTest(identity=identity):
                self.policy["public_identity"] = identity
                self.refused()


if __name__ == "__main__":
    unittest.main()

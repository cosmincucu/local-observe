"""The Windows agent's machine-readable pin and its opt-in Security overlay.

Why these rules live here and not in ``scripts/check_foundation.py``: that gate walks the Compose
models named in ``EXAMPLE_MANIFESTS`` and, through them, the collector config of each included
component. ``components/data/agent-windows/`` ships no Compose model (a Windows host is not a
Compose target), so no example includes it and ``check_collector`` never sees its configuration --
only ``check_private_references`` reaches it, by scanning ``components/**`` text. The first test
below hands the merged pair to that same ``check_collector`` so the component is held to the rule
it would face if it were includable; the rest add what no Compose-shaped gate can say about a
native binary: the pin exists and is machine-readable, the check script reads the pin instead of
prose, the Security overlay is opt-in and narrow, and every option it uses exists in the pinned
upstream release. The last class reaches past this component on purpose: the deprecated-exporter
check is the ledger's acceptance test for a rename shared by every shipped collector config, and
this is the module that already stands in for the gate on one of those configs.

Everything here is a static read of the shipped files: no collector binary is executed and no
Windows host is touched, which is why the suite runs on the Linux runner.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks
import check_windows_agent as agent

COMPONENT = ROOT / "components" / "data" / "agent-windows"
PINNED_VERSION = "0.159.0"
# The executable hash conformance.md records and the native check compares against.
PINNED_BINARY_SHA256 = "e15e33cbd50c5890abff1776a997c56b007a1d1bbf617e9faac80dabd016d8cb"
# Every receiver option the pinned build accepts, read from its own schemas at tag v0.159.0:
# pkg/stanza/operator/input/windows/config.schema.yaml and pkg/stanza/adapter/config.schema.yaml
# (the receiver's own config.schema.yaml delegates to exactly those two). A new release may add
# fields; it is not this file's job to track them, only to refuse an option the pinned build has
# never heard of -- confmap is strict, so such a config would not start on the host either.
WINDOWS_INPUT_FIELDS = {
    "channel", "event_data_format", "event_driven_scraping", "exclude_providers",
    "ignore_channel_errors", "include_log_record_original", "max_events_per_poll", "max_reads",
    "path", "poll_interval", "query", "raw", "remote", "start_at", "suppress_rendering_info",
    "wait_timeout",
}
STANZA_BASE_FIELDS = {"operators", "retry_on_failure", "storage"}
# The six Security event ids the overlay reads, each named in the component's contract.
SELECTED_EVENT_IDS = {"4624", "4625", "4688", "1102", "4720", "4732"}


def read(name: str) -> dict:
    """Load one shipped document through the gate's own loader, which rejects duplicate keys."""
    return checks.read_yaml(COMPONENT / name)


def body_text(name: str) -> str:
    """Return a shipped document as text, for the rules that are about wording rather than shape."""
    return (COMPONENT / name).read_text(encoding="utf-8")


class PinDocumentTests(unittest.TestCase):
    """versions.json is the pin: complete, machine-readable, and still 0.159.0."""

    def setUp(self) -> None:
        self.pin = json.loads((COMPONENT / "versions.json").read_text(encoding="utf-8"))

    def test_the_component_directory_holds_all_five_artefacts(self) -> None:
        """quality bar's five, in the shape this component can actually have them (no Compose model)."""
        for name in ("CONTRACT.md", "backup.md", "upgrade.md", "conformance.md", "versions.json"):
            self.assertTrue((COMPONENT / name).is_file(), name)

    def test_the_pin_is_readable_by_the_code_that_enforces_it(self) -> None:
        """``pinned_release`` is what the native check calls; it must accept the committed file."""
        document = agent.pinned_release(COMPONENT / "versions.json")
        self.assertEqual(document["collector"]["version"], PINNED_VERSION)
        self.assertEqual(document["collector"]["binary_sha256"], PINNED_BINARY_SHA256)

    def test_a_pin_missing_the_hash_is_refused_like_a_missing_pin(self) -> None:
        """Half a pin is worse than none: it reads as satisfied while checking nothing."""
        body = json.loads(json.dumps(self.pin))
        del body["collector"]["binary_sha256"]
        with tempfile.TemporaryDirectory() as scratch:
            incomplete = Path(scratch) / "versions.json"
            incomplete.write_text(json.dumps(body), encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                agent.pinned_release(incomplete)
        self.assertIn("binary_sha256", str(caught.exception))

    def test_a_missing_pin_is_refused(self) -> None:
        with self.assertRaises(ValueError) as caught:
            agent.pinned_release(COMPONENT / "no-such-versions.json")
        self.assertIn("No machine-readable pin", str(caught.exception))

    def test_the_hashes_are_full_digests_and_the_asset_urls_are_https(self) -> None:
        collector = self.pin["collector"]
        for field in ("archive_sha256", "binary_sha256"):
            self.assertRegex(collector[field], r"^[0-9a-f]{64}$")
        for field in ("url", "publisher_checksum_url"):
            self.assertTrue(collector[field].startswith("https://github.com/"), field)
            self.assertIn("/releases/download/v" + PINNED_VERSION + "/", collector[field])
        self.assertEqual(self.pin["provenance"]["archive_member_paths"],
                         ["README.md", "otelcol-contrib.exe"])
        self.assertIs(self.pin["provenance"]["archive_contains_absolute_or_traversal_paths"], False)

    def test_no_signature_or_publication_is_claimed(self) -> None:
        """The pin may say what it verified, but must not claim a signature nobody checked."""
        self.assertIs(self.pin["collector"]["publisher_checksum_verified"], True)
        self.assertIs(self.pin["collector"]["signature_verified"], False)
        self.assertIn("not performed", self.pin["provenance"]["signature_verification"])
        self.assertNotIn("signed", json.dumps(self.pin["provenance"]).lower())

    def test_the_pending_version_move_has_not_slipped_into_anything_executable(self) -> None:
        """Only 0.159.0 is executable here; prose may name v0.160.0 to say it was not taken.

        The 0.159.0 -> 0.160.0 move is recorded pending-data-pass and belongs on its own branch, so
        what must not be able to hide it is an address or a config: every pin field that a recipe
        would fetch or a collector would load, plus the two shipped configs. ``CONTRACT.md`` and
        ``upgrade.md`` naming v0.160.0 as "upstream current, deliberately not selected" is
        disclosure -- that is what the pin's ``upstream`` block exists to carry.
        """
        collector = self.pin["collector"]
        for field in ("version", "release_tag", "asset", "url", "publisher_checksum_url"):
            self.assertIn(PINNED_VERSION, collector[field], field)
        for name in ("collector.yaml", "collector-security.yaml"):
            for other in ("0.158.", "0.160.", "0.161."):
                self.assertNotIn(other, body_text(name), f"{name} mentions {other}")
        self.assertEqual(self.pin["upstream"]["selected"], PINNED_VERSION)
        self.assertIn("0.160", self.pin["upstream"]["current_at_time_of_writing"])

    def test_the_contract_no_longer_admits_a_missing_pin(self) -> None:
        """The paragraph that said "the only component without a machine-readable pin" is closed."""
        contract = body_text("CONTRACT.md")
        self.assertNotIn("ships no `versions.json`", contract)
        self.assertIn("versions.json", contract)

    def test_no_private_reference_lands_in_the_component(self) -> None:
        """The one rule the foundation gate already applies here, asserted on this directory."""
        found = [error for error in checks.check_private_references(ROOT) if "agent-windows" in error]
        self.assertEqual(found, [])


class PinnedRefusalTests(unittest.TestCase):
    """The refusals the native check makes, exercised without a Windows host."""

    def setUp(self) -> None:
        self.pin = agent.pinned_release(COMPONENT / "versions.json")

    def test_the_pinned_version_is_accepted(self) -> None:
        agent.require_pinned_version("otelcol-contrib version " + PINNED_VERSION, self.pin)

    def test_a_different_version_is_named_and_refused(self) -> None:
        for reported in ("otelcol-contrib version 0.158.0", "otelcol-contrib version 0.160.0", ""):
            with self.subTest(reported=reported):
                with self.assertRaises(ValueError) as caught:
                    agent.require_pinned_version(reported, self.pin)
                message = str(caught.exception)
                self.assertIn(PINNED_VERSION, message)
                self.assertIn("versions.json", message)

    def test_a_different_binary_is_named_and_refused(self) -> None:
        other = "0" * 64
        with self.assertRaises(ValueError) as caught:
            agent.require_pinned_binary(other, self.pin)
        self.assertIn(other, str(caught.exception))
        self.assertIn(PINNED_BINARY_SHA256, str(caught.exception))

    def test_the_script_holds_no_version_of_its_own(self) -> None:
        """The pin is the only source: a literal in the script is a second pin waiting to drift."""
        source = (ROOT / "scripts" / "check_windows_agent.py").read_text(encoding="utf-8")
        self.assertNotIn(PINNED_VERSION, source)
        self.assertIn("pinned_release()", source)


class SecurityOverlayTests(unittest.TestCase):
    """The Security pipeline is a separate, narrow, opt-in overlay and nothing more."""

    def setUp(self) -> None:
        self.base = read("collector.yaml")
        self.overlay = read("collector-security.yaml")
        self.merged = agent.merge_configs(self.base, self.overlay)

    def test_the_default_agent_reads_no_event_log_channel(self) -> None:
        self.assertEqual(sorted(self.base["service"]["pipelines"]), ["logs", "metrics"])
        self.assertEqual(sorted(self.base["receivers"]), ["filelog", "hostmetrics"])

    def test_the_overlay_is_off_unless_the_operator_names_a_second_config(self) -> None:
        """Nothing in collector.yaml references the overlay: selection happens on the command line."""
        base_text = body_text("collector.yaml")
        self.assertIn("collector-security.yaml", base_text)   # the pointer comment
        self.assertNotIn("windows_event_log", base_text)
        self.assertNotIn("windowseventlog", base_text)

    def test_the_merge_adds_exactly_one_pipeline_and_one_receiver(self) -> None:
        self.assertEqual(sorted(self.merged["service"]["pipelines"]),
                         ["logs", "logs/security", "metrics"])
        self.assertEqual(sorted(self.merged["receivers"]),
                         ["filelog", "hostmetrics", "windows_event_log/security"])
        self.assertEqual(self.merged["service"]["pipelines"]["logs"],
                         self.base["service"]["pipelines"]["logs"])

    def test_the_merged_pair_satisfies_the_gate_that_cannot_reach_it(self) -> None:
        """check_collector walks pipeline references; the merged agent must have nothing dangling."""
        self.assertEqual(checks.check_collector(self.merged, "agent-windows"), [])
        for pipeline in self.merged["service"]["pipelines"].values():
            self.assertEqual(pipeline["processors"][0], "memory_limiter")
            self.assertIn("resource/identity", pipeline["processors"])
            self.assertEqual(pipeline["exporters"], ["otlp_http"])

    def test_the_overlay_alone_is_an_overlay_not_an_agent(self) -> None:
        """Loaded by itself it must be an obvious refusal, not a half-working second agent."""
        errors = checks.check_collector(self.overlay, "collector-security.yaml")
        self.assertTrue(errors)
        self.assertIn("otlp_http", " ".join(errors))

    def test_it_reuses_the_shared_components_instead_of_reduplicating_them(self) -> None:
        """Storage, limits, identity and the credential-bearing exporter belong to the base file."""
        self.assertEqual(sorted(self.overlay), ["receivers", "service"])
        self.assertEqual(self.overlay["service"]["pipelines"]["logs/security"]["processors"],
                         ["memory_limiter", "resource/identity"])
        self.assertNotIn("otlp_http", self.overlay.get("exporters", {}))
        self.assertNotIn("file_storage", self.overlay.get("extensions", {}))
        self.assertNotIn("env:LO_INGEST_TOKEN", yaml.safe_dump(self.overlay))

    def test_the_receiver_uses_only_options_the_pinned_build_has(self) -> None:
        self.assertEqual(list(self.overlay["receivers"]), ["windows_event_log/security"])
        receiver = self.overlay["receivers"]["windows_event_log/security"]
        unknown = set(receiver) - WINDOWS_INPUT_FIELDS - STANZA_BASE_FIELDS
        self.assertEqual(unknown, set(), f"options absent from the v{PINNED_VERSION} schemas: {unknown}")

    def test_the_current_component_name_is_used_not_the_deprecated_alias(self) -> None:
        """metadata.yaml at the tag: type windows_event_log, deprecated_type windowseventlog."""
        text = body_text("collector-security.yaml")
        self.assertNotIn("windowseventlog:", text)
        self.assertIn("windows_event_log/security:", text)

    def test_channel_and_query_are_not_both_set(self) -> None:
        """The pinned build refuses the pair; the channel therefore lives inside the XML query."""
        receiver = self.overlay["receivers"]["windows_event_log/security"]
        self.assertNotIn("channel", receiver)
        self.assertIn("query", receiver)
        self.assertIn('Path="Security"', receiver["query"])

    def test_the_query_bounds_the_read_to_the_selected_event_ids(self) -> None:
        receiver = self.overlay["receivers"]["windows_event_log/security"]
        query = " ".join(receiver["query"].split())
        self.assertEqual(re.findall(r'Path="([^"]+)"', query), ["Security"],
                         "every Select must name a channel, and only the Security one")
        ids = set(re.findall(r"EventID=(\d+)", query))
        self.assertEqual(ids, SELECTED_EVENT_IDS)
        self.assertIn("or", query)

    def test_the_bounded_settings_are_stated_rather_than_inherited(self) -> None:
        receiver = self.overlay["receivers"]["windows_event_log/security"]
        self.assertEqual(receiver["start_at"], "end")
        self.assertIs(receiver["raw"], False)
        self.assertEqual(receiver["storage"], "file_storage")
        self.assertIsInstance(receiver["max_reads"], int)
        self.assertLessEqual(receiver["max_reads"], 1000)
        self.assertIs(receiver["retry_on_failure"]["enabled"], True)

    def test_no_ignore_channel_errors_means_a_missing_right_is_loud(self) -> None:
        """Default false: the agent refuses to start rather than run looking configured."""
        receiver = self.overlay["receivers"]["windows_event_log/security"]
        self.assertNotIn("ignore_channel_errors", receiver)


class DocumentationContractTests(unittest.TestCase):
    """What the documents must say now that the row claims an install and a Security channel."""

    def test_the_contract_names_the_overlay_and_its_privilege(self) -> None:
        contract = body_text("CONTRACT.md")
        self.assertIn("collector-security.yaml", contract)
        self.assertIn("SeSecurityPrivilege", contract)
        self.assertIn("Access is denied", contract)

    def test_the_contract_states_that_collected_is_not_detected(self) -> None:
        """Sigma here compiles linux/process_creation only, so a Security event cannot yet find anything."""
        contract = body_text("CONTRACT.md")
        self.assertRegex(contract.lower(), r"not detected|cannot raise|no finding")

    def test_the_conformance_record_distinguishes_run_from_not_run(self) -> None:
        conformance = body_text("conformance.md")
        self.assertIn("Runtime status", conformance)
        self.assertIn("not-run", conformance)
        self.assertIn("Access is denied", conformance)

    def test_the_upgrade_and_backup_documents_do_not_claim_a_native_upgrade(self) -> None:
        self.assertIn("not run", (body_text("upgrade.md") + body_text("backup.md")).lower())

    def test_the_installation_guide_has_a_windows_section_that_names_the_executable_flag(self) -> None:
        installation = (ROOT / "docs" / "INSTALLATION.md").read_text(encoding="utf-8")
        self.assertRegex(installation, r"(?m)^#+.*[Ww]indows")
        self.assertIn("--executable", installation)
        self.assertIn("collector-security.yaml", installation)

    def test_the_component_row_names_where_each_required_interface_lives(self) -> None:
        text = (ROOT / "docs" / "COMPONENTS.md").read_text(encoding="utf-8")
        row = next(line for line in text.splitlines() if line.startswith("| agent-windows "))
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        self.assertEqual(cells[0], "agent-windows")
        # Status is read from the tree; evidence progress is STATUS.md's, and conformance.md keeps
        # this component experimental. The row must say where each required interface lives.
        self.assertEqual(cells[1], "built")
        self.assertIn("versions.json", cells[2])
        joined = " ".join(cells)
        for needle in ("collector-security.yaml", "otlp_http", "service"):
            self.assertIn(needle, joined, joined)

    def test_the_identity_contract_survives_the_new_pipeline(self) -> None:
        """credential file leftovers's file-delivered credential and the three identity attributes, unchanged."""
        base = read("collector.yaml")
        self.assertTrue(str(base["exporters"]["otlp_http"]["headers"]["Authorization"])
                        .startswith("Bearer ${file:C:/local-observe/agent/secrets/"))
        keys = [item["key"] for item in base["processors"]["resource/identity"]["attributes"]]
        self.assertEqual(keys, ["host.name", "resource_id", "service.name"])
        merged = agent.merge_configs(base, read("collector-security.yaml"))
        self.assertEqual(merged["processors"]["resource/identity"], base["processors"]["resource/identity"])


class DeprecatedExporterAliasTests(unittest.TestCase):
    """otlp http alias's acceptance test: no shipped collector config names the deprecated exporter alias.

    At the pinned build the canonical exporter type is ``otlp_http`` and the older spelling survives
    only as a deprecated alias, so a config that still carries it starts anyway and prints one
    warning line -- a green run would never show the defect, which is why it is checked in the text.
    The parsed half catches the opposite mistake: a pipeline reference renamed while its definition
    was not (or the reverse) is a dangling component name. ``check_foundation.check_collector``
    reports exactly that for the configs an example includes, but ``agent-windows`` ships no Compose
    model, so this is the only place its pair is looked at.
    """

    # Every collector config this repository ships, named by path under components/data/.
    SHIPPED_CONFIGS = (
        "agent-linux/collector.yaml",
        "agent-windows/collector.yaml",
        "agent-windows/collector-security.yaml",
        "front-door/collector.yaml",
        "store-signoz/collector.yaml",
    )
    DEPRECATED_ALIAS = "otlphttp"

    def test_no_shipped_collector_config_uses_the_deprecated_exporter_alias(self) -> None:
        """Text, exporter keys and pipeline references must all name the canonical type."""
        for relative in self.SHIPPED_CONFIGS:
            with self.subTest(config=relative):
                path = ROOT / "components" / "data" / relative
                self.assertTrue(path.is_file(), relative)
                self.assertNotIn(self.DEPRECATED_ALIAS, path.read_text(encoding="utf-8"),
                                 f"{relative} still carries the deprecated exporter alias")
                config = checks.read_yaml(path)
                for exporter in config.get("exporters", {}):
                    self.assertNotEqual(exporter, self.DEPRECATED_ALIAS,
                                        f"{relative} defines the deprecated exporter")
                for pipeline, parts in config.get("service", {}).get("pipelines", {}).items():
                    for component in parts.get("exporters", []):
                        self.assertNotEqual(component, self.DEPRECATED_ALIAS,
                                            f"{relative}/{pipeline} references the deprecated exporter")


if __name__ == "__main__":
    unittest.main()

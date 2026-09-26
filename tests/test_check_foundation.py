"""The credential-file gate: what a shipped manifest may and may not put in a container."""
from __future__ import annotations

import copy
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks


def model_with(service_name: str, environment: dict, **extra) -> dict:
    """A minimal one-service manifest the credential rule can be pointed at.

    The image value is the shape `check_model` demands, so the same model can be fed to either
    check; `extra` adds the top-level sections (usually `secrets`) a service needs.
    """
    model = {"services": {service_name: {"image": "${LO_PLATFORM_IMAGE:?pin the platform image}",
                                         "environment": environment, **extra.get("service", {})}}}
    model.update({key: value for key, value in extra.items() if key != "service"})
    return model


class CredentialFileGateTests(unittest.TestCase):
    """check_credential_files: the env form fails, the mounted form passes, exceptions need reasons."""

    def test_an_environment_credential_value_is_an_error(self):
        model = model_with("inventory", {"LO_INVENTORY_TOKEN": "${LO_INVENTORY_TOKEN:?set a token}"})
        found = checks.check_credential_files(model)
        self.assertEqual(len(found), 1, found)
        self.assertIn("inventory: LO_INVENTORY_TOKEN", found[0])
        self.assertIn("mount it as a file", found[0])

    def test_a_password_and_a_secret_are_named_by_the_same_rule(self):
        model = model_with("sigma", {"LO_CLICKHOUSE_PASSWORD": "${LO_CLICKHOUSE_PASSWORD:?credential}",
                                     "DAGU_AUTH_BASIC_PASSWORD": "${LO_DAGU_PASSWORD:?credential}"})
        found = checks.check_credential_files(model)
        self.assertIn("LO_CLICKHOUSE_PASSWORD", " ".join(found))
        # The third-party key is caught by the LO_ variable it interpolates, not by its own name.
        self.assertIn("LO_DAGU_PASSWORD", " ".join(found))

    def test_a_credential_nested_in_a_longer_value_is_still_found(self):
        model = model_with("front-door", {"SOME_HEADER": "Bearer ${LO_STORE_TOKEN}"})
        self.assertIn("LO_STORE_TOKEN", " ".join(checks.check_credential_files(model)))

    def test_a_file_variable_holding_a_mounted_path_passes(self):
        model = model_with(
            "inventory",
            {"LO_INVENTORY_TOKEN_FILE": "/run/secrets/inventory-token"},
            service={"secrets": ["inventory-token"]},
            secrets={"inventory-token": {"file": "${LO_INVENTORY_TOKEN_FILE:?path to the file}"}},
        )
        self.assertEqual(checks.check_credential_files(model), [])

    def test_a_file_variable_naming_a_secret_the_service_never_mounts_is_an_error(self):
        """The path in the environment is only a promise; the mount is the thing that must exist."""
        model = model_with(
            "inventory",
            {"LO_INVENTORY_TOKEN_FILE": "/run/secrets/inventory-token"},
            secrets={"inventory-token": {"file": "${LO_INVENTORY_TOKEN_FILE:?path}"}},
        )
        self.assertTrue(any("does not mount" in error for error in checks.check_credential_files(model)))

    def test_a_mount_path_with_no_top_level_secret_behind_it_is_an_error(self):
        model = model_with(
            "inventory",
            {"LO_INVENTORY_TOKEN_FILE": "/run/secrets/inventory-token"},
            service={"secrets": ["inventory-token"]},
        )
        self.assertTrue(any("top-level `secrets:`" in error for error in checks.check_credential_files(model)))

    def test_a_nested_path_under_the_secret_directory_is_an_error(self):
        model = model_with(
            "inventory",
            {"LO_INVENTORY_TOKEN_FILE": "/run/secrets/teams/inventory-token"},
            service={"secrets": ["teams"]},
            secrets={"teams": {"file": "${LO_INVENTORY_TOKEN_FILE:?path}"}},
        )
        self.assertTrue(any("nested path" in error for error in checks.check_credential_files(model)))

    def test_an_exception_without_a_reason_fails_the_gate(self):
        model = model_with("inventory", {"LO_INVENTORY_TOKEN": "${LO_INVENTORY_TOKEN:?set}"})
        for reason in ("", "   "):
            exceptions = {("inventory", "LO_INVENTORY_TOKEN"): reason}
            with self.subTest(reason=repr(reason)):
                found = checks.check_credential_files(model, exceptions=exceptions)
                self.assertTrue(any("must state its reason" in error for error in found), found)
                self.assertTrue(any("puts a credential in the container environment" in error
                                    for error in found), found)

    def test_an_exception_with_a_reason_is_accepted_and_is_noticed_when_it_stops_being_true(self):
        model = model_with("inventory", {"LO_INVENTORY_TOKEN": "${LO_INVENTORY_TOKEN:?set}"})
        exceptions = {("inventory", "LO_INVENTORY_TOKEN"): "The reader takes a value only, ever."}
        self.assertEqual(checks.check_credential_files(model, exceptions=exceptions), [])
        # An exception nobody needs is dead weight, and the rule reports it as such: with the
        # credential gone, the entry names nothing -- so review notices it only as a stale row, and
        # the shipped dict is asserted empty below rather than allowed to drift.
        self.assertEqual(checks.check_credential_files(model_with("inventory", {}),
                                                      exceptions=exceptions), [])

    def test_third_party_variable_names_are_outside_the_rules_scope(self):
        """The rule knows the product's own names; it cannot claim anything about a foreign image."""
        model = model_with("signoz", {"SIGNOZ_TOKENIZER_JWT_SECRET": "${SIGNOZ_JWT_SECRET:?set in .env}"})
        self.assertEqual(checks.check_credential_files(model), [])

    def test_no_shipped_component_needs_an_exception(self):
        self.assertEqual(checks.CREDENTIAL_ENV_EXCEPTIONS, {},
                         "every credential in components/ is mounted; a new exception needs a card")


class ShippedManifestsTests(unittest.TestCase):
    """The real tree, through the same loader the gate uses: no Docker required, no guessing."""

    def compose_files(self):
        return sorted((ROOT / "components").glob("*/*/compose.yaml"))

    def test_every_component_manifest_is_checked_and_carries_no_environment_credential(self):
        files = self.compose_files()
        # 8 -> 9 (operator portal homepage, PR #112) -> 10 (AI integration ai) -> 11: job observe standard adds
        # components/control/job-observe (Healthchecks, decision job observation). ai carries only a credential
        # *path* (LO_AI_API_KEY_FILE -> a declared secret), so the assertion below holds for it
        # unchanged. No shipped example includes ai, which is why tests/test_ai_component.py runs
        # check_model on that manifest directly: check_example, and so `python -B
        # scripts/check_foundation.py`, never reaches a file no example composes.
        # 11 -> 12: synthetics component adds components/control/synthetics (the Gatus engine and its adapter).
        # 12 -> 13: crowdsec adds components/control/crowdsec (the Security Engine's Local API, the
        # decisions-only shape threat detection engine kept). It mounts every credential as a path and declares no
        # compose
        # `secrets:` block, so the assertion below holds for it unchanged — and no shipped example includes
        # it, which is why tests/test_crowdsec_component.py reads that manifest directly, exactly as the
        # ai row above does for the same reason.
        # 13 -> 14: anomaly component adds components/control/anomaly (the seasonal-baseline producer, on the
        # platform's image). It shipped in no example — examples/full was delivery channels's while that item ran —
        # which is why tests/test_anomaly_component.py runs check_model and check_example on that
        # manifest directly. examples/full has included it since anomaly deployment support , so the
        # gate reaches it both ways now; the direct run stays, because it names this component where an
        # example failure would name an example.
        # 14 -> 15: chat integration adds components/control/chat/compose.yaml (the optional AnythingLLM surface). Like
        # `ai` it is in no example, so check_example still never reaches it and tests/test_chat_component.py
        # runs check_model on it directly; it publishes no port and holds no credential in the environment
        # (its one secret is the mounted settings file, declared as a compose `secrets:` `file:` source and
        # named only by a `*_FILE` variable), so the credential walk below passes unchanged.
        # 15 -> 16: MCP component adds components/control/mcp (the MCP tool surface's own image, so the optional
        # `mcp` extra has somewhere to live that is not the platform image). Same shape as crowdsec and
        # ai: in no shipped example, so its manifest is read directly by tests/test_mcp_component.py.
        # anomaly component and chat integration moved it first; 16 is the wave-7 total.
        self.assertEqual(len(files), 16, "the component set changed shape; update this list")
        for path in files:
            with self.subTest(manifest=path.relative_to(ROOT).as_posix()):
                self.assertEqual(checks.check_credential_files(checks.read_yaml(path)), [])

    def test_only_path_variables_mention_a_product_credential_in_a_manifest(self):
        """The grep an operator would run, written down as an assertion.

        Inside `components/**/compose.yaml` a product credential name may appear only as a `*_FILE`
        variable (which carries a path, never a value) or inside the `file:` source of a declared
        secret. A bare `LO_*_TOKEN`/`_PASSWORD`/`_SECRET` line means a value is going back into a
        container environment. Third-party names are outside this assertion for the same reason they
        are outside the gate: `signoz` takes `SIGNOZ_TOKENIZER_JWT_SECRET` as a value, and this
        repository does not build that image.
        """
        names_credential = re.compile(r"\bLO_[A-Z0-9_]*_(?:TOKEN|PASSWORD|SECRET)\w*\b")
        is_a_path = re.compile(r"\bLO_[A-Z0-9_]*_(?:TOKEN|PASSWORD|SECRET)_FILE\b")
        offenders = []
        for path in self.compose_files():
            for line in path.read_text(encoding="utf-8").splitlines():
                if names_credential.search(line) and not is_a_path.search(line):
                    offenders.append(f"{path.relative_to(ROOT).as_posix()}: {line.strip()}")
        self.assertEqual(offenders, [])

    def test_examples_render_with_every_credential_mounted(self):
        self.assertEqual(checks.check_foundation(), [])


class CollectorCredentialFormTests(unittest.TestCase):
    """The confmap `${file:…}` form is required where it was adopted; `${env:…}` is not."""

    def setUp(self):
        self.front = checks.read_yaml(ROOT / "components/data/front-door/collector.yaml")
        self.store = checks.read_yaml(ROOT / "components/data/store-signoz/collector.yaml")
        self.agent = checks.read_yaml(ROOT / "components/data/agent-linux/collector.yaml")

    def test_the_shipped_forms_pass_their_own_checks(self):
        self.assertEqual(checks.check_ingest(self.front), [])
        self.assertEqual(checks.check_store(self.store), [])
        self.assertEqual(checks.check_collector(self.agent, "agent-linux"), [])

    def test_an_environment_form_is_rejected_by_both_guards_that_read_a_bearer_token(self):
        """The `${env:…}` form was the defect; accepting it again must fail the gate."""
        self.assertTrue(any("mounted secret file" in error for error in
                            checks.check_ingest(swapped(self.front, "${env:LO_INGEST_TOKEN}"))))
        self.assertTrue(any("mounted secret file" in error for error in
                            checks.check_store(swapped(self.store, "${env:LO_STORE_TOKEN}"))))

    def test_a_literal_token_in_a_collector_config_is_rejected(self):
        for name, config in (("ingest", self.front), ("store", self.store)):
            with self.subTest(check=name):
                guard = checks.check_ingest if name == "ingest" else checks.check_store
                self.assertTrue(guard(swapped(config, "hardcoded-token-value")))

    def test_the_agent_exporter_reads_its_token_from_the_mount(self):
        self.assertEqual(self.agent["exporters"]["otlp_http"]["headers"]["Authorization"],
                         "Bearer ${file:/run/secrets/agent-ingest-token}")

    def test_the_front_door_exports_with_the_store_credential_from_a_file(self):
        self.assertEqual(self.front["exporters"]["otlp"]["headers"]["Authorization"],
                         "Bearer ${file:/run/secrets/front-door-store-token}")

    def test_the_store_receiver_reads_its_credential_from_a_file(self):
        self.assertEqual(self.store["extensions"]["bearertokenauth"]["token"],
                         "${file:/run/secrets/store-receiver-token}")

    def test_every_secret_a_service_points_at_is_declared_in_the_same_manifest(self):
        """The mount path in an environment value is a promise this check keeps."""
        for path in sorted((ROOT / "components").glob("*/*/compose.yaml")):
            model = checks.read_yaml(path)
            mounted = {name for service in model.get("services", {}).values()
                       for name in checks.declared_secret_names(service)}
            declared = set((model.get("secrets") or {}).keys())
            with self.subTest(manifest=path.relative_to(ROOT).as_posix()):
                self.assertEqual(sorted(mounted - declared), [], "service mounts an undeclared secret")


def swapped(config, value):
    """A copy of a collector config whose bearer token is `value`."""
    broken = copy.deepcopy(config)
    broken["extensions"]["bearertokenauth"]["token"] = value
    return broken


if __name__ == "__main__":
    unittest.main()

"""The shipped portal component (operator portal): manifest shape, its artefacts, and what `disabled` costs.

`docs/COMPONENTS.md` §5 demands that a component be a component, not a driver: before this row the
portal existed only as `scripts/stage_homepage.py`, which hard-codes an image and writes a manifest at
run time. These tests are the static half of the difference — the five quality bar artefacts, a manifest the
foundation gate accepts on its own, the credential arriving as a file, one deliberate loopback
publication, and the `If disabled` clause being a fact about the tree rather than a hope.

Nothing here starts a container. The runtime half belongs to
`components/control/homepage/conformance.md`, which names what has and has not been run.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks   # noqa: E402

COMPONENT = ROOT / "components/control/homepage"
MANIFEST = COMPONENT / "compose.yaml"
ARTIFACTS = ("compose.yaml", "versions.json", "CONTRACT.md", "backup.md", "upgrade.md", "conformance.md")
IMAGE_VARIABLE = re.compile(r"^\$\{LO_HOMEPAGE_IMAGE:\?\S.*\}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
FULL_EXAMPLE = ROOT / "examples/full/compose.yaml"


def manifest_model() -> dict[str, Any]:
    """The portal's own Compose model, read the way the gate reads every shipped manifest."""
    return checks.read_yaml(MANIFEST)


def portal_service() -> dict[str, Any]:
    """The single service the portal manifest declares."""
    return manifest_model()["services"]["homepage"]


def mount_sources(service: dict[str, Any]) -> list[dict[str, Any]]:
    """The long-form bind mounts of one service, which is the only form this manifest uses."""
    return [mount for mount in service["volumes"] if isinstance(mount, dict)]


class ComponentArtefactsTests(unittest.TestCase):
    """quality bar: a component is a manifest, a pin and four lifecycle documents, not a script to remember."""

    def test_every_shipped_artefact_is_present_and_readable(self) -> None:
        """Each artefact exists and carries prose, not a heading someone will finish later."""
        for name in ARTIFACTS:
            with self.subTest(artifact=name):
                path = COMPONENT / name
                self.assertTrue(path.is_file(), f"{name} is missing from the shipped component")
                self.assertGreater(len(path.read_text(encoding="utf-8").strip()), 400,
                                   f"{name} is a stub, not an artefact")

    def test_the_pin_names_one_digest_resolved_for_one_platform(self) -> None:
        """The pin must be re-resolvable and must say so: a bare tag is a moving part."""
        pin = json.loads((COMPONENT / "versions.json").read_text(encoding="utf-8"))
        self.assertEqual(pin["schema_version"], 1)
        self.assertRegex(pin["verified_on"], r"^\d{4}-\d{2}-\d{2}$", "a pin without a date is a claim")
        self.assertTrue(DIGEST.match(pin["index_digest"]), pin["index_digest"])
        self.assertTrue(DIGEST.match(pin["linux_amd64_digest"]), pin["linux_amd64_digest"])
        self.assertEqual(pin["platform"], "linux/amd64")
        # The `image` line is what an operator copies into LO_HOMEPAGE_IMAGE; it must be the same
        # digest this file documents, or the file documents one image and ships another.
        tag, _, digest = pin["image"].rpartition("@")
        self.assertTrue(DIGEST.match(digest), pin["image"])
        self.assertEqual(digest, pin["index_digest"])
        self.assertTrue(tag.startswith("ghcr.io/gethomepage/homepage:v"), tag)
        self.assertRegex(pin["digest_provenance"]["read_on"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertIn("Docker-Content-Digest", pin["digest_provenance"]["method"])

    def test_the_pin_states_what_was_run_and_what_is_only_a_candidate(self) -> None:
        """The pin must distinguish the image something started from a tag that merely resolves."""
        pin = json.loads((COMPONENT / "versions.json").read_text(encoding="utf-8"))
        self.assertIn("actually_run", pin, "a pin must admit whether anything started it")
        self.assertIn("v1.13.2", pin["actually_run"]["statement"])
        candidate = pin["candidate"]
        self.assertTrue(DIGEST.match(candidate["index_digest"]), candidate["index_digest"])
        self.assertTrue(DIGEST.match(candidate["linux_amd64_digest"]), candidate["linux_amd64_digest"])
        self.assertNotEqual(candidate["index_digest"], pin["index_digest"], "a candidate is not the pin")
        self.assertIn("not_adopted_because", candidate)

    def test_no_estate_identifier_reaches_the_shipped_component(self) -> None:
        """The gate's privacy rule, applied to one directory and stated where someone will read it."""
        found = [f"{path.name}: {token}" for path in sorted(COMPONENT.iterdir())
                 if path.suffix in checks.SCANNED_SUFFIXES
                 for token in checks.BANNED_TOKENS if token in path.read_text(encoding="utf-8")]
        self.assertEqual(found, [])


class ManifestModelTests(unittest.TestCase):
    """The manifest alone, through the same loader and rules the whole tree is policed with."""

    def test_the_manifest_passes_the_model_gate_by_itself(self) -> None:
        """No example's help: the portal's own directory must be clean enough to ship."""
        self.assertEqual(checks.check_model(manifest_model(), COMPONENT), [])

    def test_the_image_is_a_required_variable_and_is_never_pulled_at_start(self) -> None:
        """No default image: an unset pin is a refusal, and `never` stops a moving tag at start."""
        service = portal_service()
        self.assertRegex(service["image"], IMAGE_VARIABLE)
        self.assertEqual(service["pull_policy"], "never")

    def test_the_container_is_unprivileged_and_bounded(self) -> None:
        """Drops, read-only root, and the memory/CPU/pid/task caps the staging rehearsal ran under."""
        service = portal_service()
        self.assertEqual(service["user"], "65532:65532")
        self.assertTrue(service["read_only"])
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", service["security_opt"])
        self.assertTrue(service["mem_limit"].endswith("m"), service["mem_limit"])
        self.assertLessEqual(service["cpus"], 1)
        self.assertGreater(service["pids_limit"], 0)
        logging = service["logging"]
        self.assertEqual(logging["driver"], "json-file")
        self.assertIn("max-size", logging["options"])
        self.assertIn("max-file", logging["options"])

    def test_the_config_directory_is_read_only_and_never_created_for_the_operator(self) -> None:
        """A portal reads the operator's rendered config and writes nothing back to it."""
        mounts = {mount["target"]: mount for mount in mount_sources(portal_service())}
        config = mounts["/app/config"]
        self.assertTrue(config["read_only"])
        self.assertIs(config["bind"]["create_host_path"], False,
                      "an empty config directory is a portal with no dashboards, not a failure")
        self.assertRegex(config["source"], r"^\$\{LO_HOMEPAGE_CONFIG_DIR:\?\S.*\}$")

    def test_the_readiness_bootstrap_is_mounted_read_only_from_a_variable(self) -> None:
        """The bootstrap is product source, mounted; this component ships no second copy of it."""
        mounts = {mount["target"]: mount for mount in mount_sources(portal_service())}
        bootstrap = mounts["/bootstrap.cjs"]
        self.assertTrue(bootstrap["read_only"])
        self.assertIs(bootstrap["bind"]["create_host_path"], False)
        self.assertRegex(bootstrap["source"], r"^\$\{LO_HOMEPAGE_BOOTSTRAP:\?\S.*\}$")
        self.assertFalse((COMPONENT / "bootstrap.cjs").exists(),
                         "a second copy would make the upgrade rehearsal's bootstrap hash meaningless")
        self.assertEqual(portal_service()["entrypoint"], ["node"])
        self.assertEqual(portal_service()["command"], ["/bootstrap.cjs"])

    def test_the_credential_is_a_mounted_file_path_and_never_a_value(self) -> None:
        """`docker inspect` may show where the portal's token lives, never what it is."""
        model, service = manifest_model(), portal_service()
        environment = checks.compose_environment(service)
        self.assertEqual(environment["HOMEPAGE_FILE_OVERVIEW_TOKEN"], "/run/secrets/homepage-overview-token")
        self.assertEqual(checks.declared_secret_names(service), ["homepage-overview-token"])
        self.assertIn("homepage-overview-token", model["secrets"])
        self.assertRegex(model["secrets"]["homepage-overview-token"]["file"],
                         r"^\$\{LO_HOMEPAGE_TOKEN_FILE:\?\S.*\}$")
        self.assertEqual(checks.check_credential_files(model), [])
        # The substitution placeholder is the only form the token may take inside rendered markup.
        from local_observe.platform.homepage import configuration
        rendered = json.dumps(configuration("https://portal.invalid", "http://platform:8002/v1/overview"))
        self.assertIn("{{HOMEPAGE_FILE_OVERVIEW_TOKEN}}", rendered)
        self.assertNotIn("Bearer ey", rendered)

    def test_the_publication_is_loopback_only_and_the_exemption_is_deliberate(self) -> None:
        """The name in `HOST_PUBLISHED_SERVICES` is the widening; assert it, do not inherit it."""
        service = portal_service()
        self.assertEqual(len(service["ports"]), 1, service["ports"])
        self.assertTrue(service["ports"][0].startswith("127.0.0.1:"), service["ports"])
        # Adding the name is the widening; assert it here so removing the rule's teeth fails too.
        self.assertIn("homepage", checks.HOST_PUBLISHED_SERVICES)
        self.assertRegex(service["ports"][0], r"^127\.0\.0\.1:\$\{LO_HOMEPAGE_PORT:-\d+\}:3000$")

    def test_the_healthcheck_probes_the_file_the_bootstrap_writes(self) -> None:
        """Entrypoint, command and probe are one mechanism; a probe of "the port answers" is a lie."""
        health = portal_service()["healthcheck"]
        self.assertIn("/tmp/portal-ready", " ".join(health["test"]))
        self.assertEqual(health["test"][:2], ["CMD", "node"])

    def test_the_allowed_hosts_list_is_required_because_the_server_enforces_it(self) -> None:
        """Homepage 403s an unknown Host, so an unset allow-list must fail at `config`, not at browse."""
        environment = checks.compose_environment(portal_service())
        self.assertRegex(environment["HOMEPAGE_ALLOWED_HOSTS"], r"^\$\{LO_HOMEPAGE_ALLOWED_HOSTS:\?\S.*\}$")
        self.assertEqual(environment["NEXT_TELEMETRY_DISABLED"], "1")
        self.assertEqual(environment["LOG_TARGETS"], "stdout")


class IfDisabledTests(unittest.TestCase):
    """The row's `If disabled` clause: the portal is a viewer, so deleting it must cost only the view."""

    def test_the_portal_owns_no_state(self) -> None:
        """No volume, no dependency: this service is a viewer, which is what makes the clause testable."""
        model = manifest_model()
        self.assertNotIn("volumes", model, "a portal volume needs a backup recipe this row does not have")
        self.assertEqual(portal_service().get("depends_on") or {}, {})

    def test_no_shipped_service_waits_on_the_portal(self) -> None:
        """Removing the include entry must remove one service, not break a dependency graph."""
        for name in ("examples/demo/compose.yaml", "examples/full/compose.yaml",
                     "examples/platform/compose.yaml"):
            services, errors = checks.example_services(ROOT, ROOT / name)
            self.assertEqual(errors, [], name)
            with self.subTest(example=name):
                for service_name, service in services.items():
                    self.assertNotIn("homepage", service.get("depends_on") or {},
                                     f"{service_name} would fail to start with the portal deleted")

    def test_the_reference_example_includes_the_portal(self) -> None:
        """`examples/full` is the composition a release ships, so the portal must be reachable from it."""
        included: list[str] = []
        for entry in checks.read_yaml(FULL_EXAMPLE).get("include") or []:
            files, _directory = checks.include_entry(entry, FULL_EXAMPLE.parent)
            included.extend(item.resolve().relative_to(ROOT.resolve()).as_posix() for item in files)
        self.assertIn("components/control/homepage/compose.yaml", included)


if __name__ == "__main__":
    unittest.main()

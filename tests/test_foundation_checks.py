import copy
import contextlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_foundation as checks
import conformance_smoke as smoke


REQUIRED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):\?")
DEFAULTED_VARIABLE = re.compile(r"\$\{([A-Z0-9_]+):-([^}]*)\}")


def included_manifests(example):
    """Every component Compose file an example pulls in, in include order."""
    files = []
    for entry in checks.read_yaml(example).get("include") or []:
        files.extend(checks.include_entry(entry, example.parent)[0])
    return [path.resolve() for path in files]


def example_variables(example):
    """(required, defaulted) Compose variables across an example and everything it includes."""
    required, defaulted = set(), set()
    for path in [example, *included_manifests(example)]:
        body = path.read_text(encoding="utf-8")
        required.update(match.group(1) for match in REQUIRED_VARIABLE.finditer(body))
        defaulted.update(match.group(1) for match in DEFAULTED_VARIABLE.finditer(body))
    return required, defaulted


def published_ports(example):
    """(service, rendered port) pairs, with the example's own .env.example values substituted."""
    values = dict(re.findall(r"(?m)^([A-Z0-9_]+)=(.*)$",
                             (example.parent / ".env.example").read_text(encoding="utf-8")))

    def render(value):
        value = REQUIRED_VARIABLE.sub(lambda match: values.get(match.group(1), ""), value)
        return DEFAULTED_VARIABLE.sub(lambda match: values.get(match.group(1)) or match.group(2), value)

    services, errors = checks.example_services(ROOT, example)
    assert errors == []
    return [(name, render(port)) for name, service in services.items() for port in service.get("ports", [])]


class FoundationChecks(unittest.TestCase):
    def test_full_example_starts_every_built_component(self):
        """demo full stack: this example is the composition a release ships, so name the service set.

        job observe standard added `healthchecks` (component `job-observe`, decision job observation), operator portal added
        `homepage`
        (the operator portal) and synthetics component added `gatus` plus `detector` (component `synthetics`, moved
        here out of the platform stage fragment so the row in docs/COMPONENTS.md describes a component
        and not a staging accident). anomaly deployment support added `anomaly` , which is also why
        `tests/test_anomaly_component.py` lost the
        assertion that no shipped example composes that manifest. Nothing else moved.
        """
        services, errors = checks.example_services(ROOT, ROOT / "examples/full/compose.yaml")
        self.assertEqual(errors, [])
        self.assertEqual(set(services), {
            "init-clickhouse", "zookeeper-1", "clickhouse", "signoz", "signoz-telemetrystore-migrator",
            "signoz-otel-collector", "lo-front-door", "agent-linux", "inventory", "platform", "sigma",
            "anomaly", "dagu", "healthchecks", "homepage", "gatus", "detector"})

    def test_full_example_merges_the_operator_override_into_the_platform(self):
        """The operator file patches the platform service; a second platform service cannot work."""
        services, _ = checks.example_services(ROOT, ROOT / "examples/full/compose.yaml")
        platform = services["platform"]
        self.assertNotIn("operator", services)
        self.assertIn("local_observe.platform.operator:app_factory", platform["command"])
        self.assertEqual(platform["image"], "${LO_PLATFORM_IMAGE:?pin the platform image}")
        # A merge must keep everything the override does not name, not only the command.
        self.assertEqual(platform["secrets"], ["platform-credentials"])
        self.assertIn("healthcheck", platform)

    def test_env_templates_cover_every_required_variable_and_nothing_else(self):
        for name in ("examples/demo/compose.yaml", "examples/full/compose.yaml",
                     "examples/platform/compose.yaml"):
            example = ROOT / name
            required, defaulted = example_variables(example)
            keys = set(re.findall(r"(?m)^([A-Z0-9_]+)=",
                                  (example.parent / ".env.example").read_text(encoding="utf-8")))
            with self.subTest(example=name):
                self.assertEqual(sorted(required - keys), [], "required variable with no template line")
                self.assertEqual(sorted(keys - required - defaulted), [], "template line no manifest reads")

    def test_example_publications_are_loopback_unique_and_apart(self):
        demo = {port.split(":")[1] for _, port in published_ports(ROOT / "examples/demo/compose.yaml")}
        full = published_ports(ROOT / "examples/full/compose.yaml")
        self.assertTrue(full)
        for name, port in full:
            with self.subTest(service=name, port=port):
                self.assertTrue(port.startswith("127.0.0.1:"), port)
                self.assertNotEqual(port.split(":")[1], "", "published port has no value in .env.example")
        host_ports = [port.split(":")[1] for _, port in full]
        self.assertEqual(len(host_ports), len(set(host_ports)), "two services publish the same host port")
        self.assertEqual(set(host_ports) & demo, set(), "the full example reuses a demo port")
        # operator portal names the portal's publication explicitly. Two rows added one each (operator portal homepage,
        # job observe standard healthchecks), so no count is claimed here. Name the portal anyway, so a
        # change that quietly drops its `ports:` line (leaving HOST_PUBLISHED_SERVICES pointing at a
        # service nobody publishes, or a duplicate number) fails here rather than in a browser.
        self.assertIn(("homepage", "127.0.0.1:18097:3000"), full, full)
        # notification and state leftovers: the platform stage is the third composition, and the one most likely to
        # boot beside the
        # other two on the same host, so its single publication must answer on neither of them.
        stage = published_ports(ROOT / "examples/platform/compose.yaml")
        self.assertTrue(stage)
        for name, port in stage:
            with self.subTest(example="platform", service=name, port=port):
                self.assertTrue(port.startswith("127.0.0.1:"), port)
                self.assertNotEqual(port.split(":")[1], "", "published port has no value in .env.example")
        stage_ports = [port.split(":")[1] for _, port in stage]
        self.assertEqual(len(stage_ports), len(set(stage_ports)), "two stage services publish one port")
        self.assertEqual(set(stage_ports) & (demo | set(host_ports)), set(),
                         "the platform stage example reuses a demo or full port")

    def test_a_service_declared_locally_and_included_is_reported(self):
        """Compose includes do not merge names, so an example must not redefine an included service."""
        component = "services:\n  platform:\n    image: ${LO_PLATFORM_IMAGE:?pin}\n"
        both = ("include:\n  - ../../components/control/compose.yaml\n"
                "services:\n  platform:\n    image: ${LO_PLATFORM_IMAGE:?pin}\n")
        only = "include:\n  - ../../components/control/compose.yaml\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "components" / "control").mkdir(parents=True)
            (root / "examples" / "e").mkdir(parents=True)
            (root / "components" / "control" / "compose.yaml").write_text(component, encoding="utf-8")
            example = root / "examples" / "e" / "compose.yaml"
            example.write_text(both, encoding="utf-8")
            expected = ["platform: declared by the example and also included; include does not merge"]
            self.assertEqual(checks.example_services(root, example)[1], expected)
            example.write_text(only, encoding="utf-8")
            self.assertEqual(checks.example_services(root, example)[1], [])

    def test_the_platform_stage_composition_merges_what_the_fragment_alone_cannot_state(self):
        """notification and state leftovers item 7: examples/platform/compose.yaml is what makes the stage fragment checkable.

        `examples/platform/staging.compose.yaml` is a Compose override fragment: its `platform:` block
        adds one read-only bind and declares no image, so a standalone scan of it reports "platform:
        image must be a required runtime image variable" -- a false positive, because the manifest it
        patches is what supplies that image. Both halves are pinned: the fragment alone still reports
        the line, and the composition resolves ONE `platform` service carrying the component's image
        *and* the fragment's /checks bind, which the model rules fault nowhere.

        gate example fragments closed the last step: `check_example`'s component-documentation loop is scoped to
        directories under `components/`, so the fragment's own directory (`examples/platform`) is no
        longer asked for the four lifecycle documents an example does not carry, and this composition
        joined EXAMPLE_MANIFESTS -- which is what puts it inside `python3 -B scripts/check_foundation.py`.
        """
        example = ROOT / "examples/platform/compose.yaml"
        fragment = example.parent / "staging.compose.yaml"
        self.assertIn("platform: image must be a required runtime image variable",
                      checks.check_model(checks.read_yaml(fragment), fragment.parent))
        services, errors = checks.example_services(ROOT, example)
        self.assertEqual(errors, [])
        self.assertEqual({"platform", "demo-target", "gatus", "notification-sink", "detector"},
                         set(services))
        # synthetics component: `gatus` and `detector` still resolve here, but from the component manifest this
        # example now includes rather than from the fragment, so the stage's own service set -- and
        # every environment file written for it -- is unchanged by the move.
        fragment_services = set(checks.read_yaml(fragment).get("services", {}))
        self.assertEqual({"platform", "demo-target", "notification-sink"}, fragment_services)
        self.assertNotIn("gatus", fragment_services)
        self.assertNotIn("detector", fragment_services)
        platform = services["platform"]
        self.assertEqual("${LO_PLATFORM_IMAGE:?pin the platform image}", platform["image"])
        self.assertIn("/checks", json.dumps(platform["volumes"]))
        self.assertEqual(["platform-credentials"], platform["secrets"])
        entries = list(checks.loaded_includes(ROOT, example, errors))
        self.assertEqual(2, len(entries), "the platform pair is one entry, and synthetics is the second")
        _files, directory, model = entries[0]
        self.assertEqual((ROOT / "components/control/platform").resolve(), directory.resolve())
        self.assertEqual([], checks.check_model(model, directory))
        # synthetics component: the synthetics manifest is its OWN entry, because it patches nothing -- and the stage
        # composition must still resolve the two services it moved in, on the entry that now declares
        # them. A name declared by two include entries is a dropped definition, so `example_services`
        # reporting no error here is the assertion that the fragment stopped defining them.
        stage_files, stage_directory, stage_model = entries[1]
        self.assertEqual((ROOT / "components/control/synthetics").resolve(), stage_directory.resolve())
        self.assertEqual({"gatus", "detector"}, set(stage_model["services"]))
        self.assertEqual([], checks.check_model(stage_model, stage_directory))
        self.assertEqual(errors, [])
        # gate example fragments: the composition is now policed by the gate itself. The four lifecycle documents are
        # required only of a shipped component, so the only lines that used to stand here --
        # "platform: missing CONTRACT.md" and its three siblings, asked of examples/platform -- are
        # gone, and this example is walked by check_foundation.
        self.assertIn("examples/platform/compose.yaml", checks.EXAMPLE_MANIFESTS)
        self.assertEqual([], checks.check_example(ROOT, example))

    def test_lifecycle_documents_are_required_of_components_only(self):
        """gate example fragments: the documentation loop in check_example is scoped, not removed.

        One fixture carries both halves of the rule, so a change that skips the loop for everything
        (un-policing a real component) and a change that applies it to anything (charging an example
        directory for documents only components/ ships) both fail here:

        - an override fragment that sits beside the example including it is not a shipped component
          and owes none of the four lifecycle documents;
        - an included file under a temporary `components/<x>/` directory is a component and still
          owes all four, named one per line.
        """
        component_body = "services:\n  thing:\n    image: ${LO_THING_IMAGE:?pin the thing image}\n"
        fragment_body = "services:\n  sidecar:\n    image: ${LO_SIDECAR_IMAGE:?pin the sidecar image}\n"
        lifecycle_docs = ("CONTRACT.md", "backup.md", "upgrade.md", "conformance.md")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            component = root / "components" / "control" / "thing"
            component.mkdir(parents=True)
            (root / "examples" / "stage").mkdir(parents=True)
            (component / "compose.yaml").write_text(component_body, encoding="utf-8")
            (root / "examples/stage/override.compose.yaml").write_text(fragment_body, encoding="utf-8")
            example = root / "examples/stage/compose.yaml"
            example.write_text("include:\n  - ../../components/control/thing/compose.yaml\n"
                               "  - ./override.compose.yaml\n", encoding="utf-8")
            # Only the component is charged -- and it is charged all four. The fragment's own directory
            # is named `stage`, so an unscoped loop would add four `stage: missing ...` lines here and
            # this equality would fail; a loop removed altogether would report nothing and fail it too.
            expected = [f"thing: missing {name}" for name in lifecycle_docs]
            self.assertEqual(sorted(expected), sorted(checks.check_example(root, example)))
            # With the component carrying its documents, the same two-file composition is clean: the
            # fragment is exempt, and neither file faults a model rule.
            for name in lifecycle_docs:
                (component / name).write_text(f"# {name}\n", encoding="utf-8")
            self.assertEqual([], checks.check_example(root, example))

    def test_the_unwired_analysis_user_delta_is_gated_directly_and_states_one_variable(self):
        """query adapter: `lo-read.compose.yaml` is in no example yet, so the gate cannot reach it by walking.

        The precedent is `components/control/ai`, which ships a manifest no example includes: a
        manifest the walk cannot reach is checked by naming it, never skipped. Two lines are pinned
        here because both can silently change meaning when the delta is wired up:

        * merged onto the store manifest the way its `include` entry will merge it, the model faults
          nowhere -- the bind's source exists, is read-only, and the secret is declared;
        * read alone, the delta still reports the one false positive that makes it non-standalone
          (no `image:`), which is why nothing may treat this file as a service definition.

        The required variable it introduces is named, so the day an example includes the delta,
        `test_env_templates_cover_every_required_variable_and_nothing_else` is the check that makes
        the operator's template carry it. Until then that check cannot see the name at all, which is
        the cost of the delta being unwired and is written up in the delta's own header.
        """
        directory = ROOT / "components/data/store-signoz"
        delta = directory / "clickhouse-users.d/lo-read.compose.yaml"
        merged = checks.merge_models(checks.read_yaml(directory / "compose.yaml"),
                                     checks.read_yaml(delta))
        self.assertEqual([], checks.check_model(merged, directory))
        self.assertEqual(["clickhouse: image must be a required runtime image variable"],
                         checks.check_model(checks.read_yaml(delta), directory))
        body = delta.read_text(encoding="utf-8")
        self.assertEqual(["LO_CLICKHOUSE_READ_CREDENTIALS_FILE"],
                         sorted(set(REQUIRED_VARIABLE.findall(body))))
        self.assertIn("lo-read.xml:/etc/clickhouse-server/users.d/lo-read.xml:ro", body)

    def test_store_ingest_does_not_require_opamp_onboarding(self):
        model = checks.read_yaml(ROOT / "components/data/store-signoz/compose.yaml")
        command = " ".join(model["services"]["signoz-otel-collector"]["command"])
        self.assertNotIn("--manager-config", command)
        self.assertIn("--config=/etc/otel-collector-config.yaml", command)

    def test_prepared_modules_are_consistent(self):
        self.assertEqual(checks.check_foundation(), [])

    def test_duplicate_yaml_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            checks.yaml.load("services: {}\nservices: {}", Loader=checks.UniqueLoader)

    def test_unprotected_grpc_is_rejected(self):
        config = checks.read_yaml(ROOT / "components/data/front-door/collector.yaml")
        del config["receivers"]["otlp"]["protocols"]["grpc"]["auth"]
        self.assertTrue(any("grpc" in e for e in checks.check_ingest(config)))

    def test_store_receiver_must_authenticate_both_protocols(self):
        config = checks.read_yaml(ROOT / "components/data/store-signoz/collector.yaml")
        self.assertEqual(checks.check_store(config), [])
        for protocol in ("grpc", "http"):
            broken = copy.deepcopy(config)
            del broken["receivers"]["otlp"]["protocols"][protocol]["auth"]
            with self.subTest(protocol=protocol):
                self.assertTrue(any(protocol in e for e in checks.check_store(broken)))

    def test_store_must_not_reuse_the_ingest_credential(self):
        config = checks.read_yaml(ROOT / "components/data/store-signoz/collector.yaml")
        config["extensions"]["bearertokenauth"]["token"] = "${env:LO_INGEST_TOKEN}"
        self.assertTrue(any("distinct" in e for e in checks.check_store(config)))

    def test_store_memory_bound_must_precede_every_pipeline(self):
        config = checks.read_yaml(ROOT / "components/data/store-signoz/collector.yaml")
        for pipeline in config["service"]["pipelines"]:
            broken = copy.deepcopy(config)
            broken["service"]["pipelines"][pipeline]["processors"] = ["batch", "memory_limiter"]
            with self.subTest(pipeline=pipeline):
                self.assertTrue(any(pipeline in e for e in checks.check_store(broken)))

    def test_platform_manifest_declares_a_safe_delivery_default(self):
        model = checks.read_yaml(ROOT / "components/control/platform/compose.yaml")
        self.assertEqual(checks.check_delivery(model), [])
        environment = model["services"]["platform"]["environment"]
        self.assertNotIn("LO_PLATFORM_CREDENTIALS_JSON", environment)
        for change in ("live", "absent", "credentials"):
            broken = copy.deepcopy(model)
            values = broken["services"]["platform"]["environment"]
            if change == "live":
                values["LO_NOTIFICATION_MODE"] = "${LO_NOTIFICATION_MODE:-live}"
            elif change == "absent":
                del values["LO_NOTIFICATION_MODE"]
            else:
                values["LO_PLATFORM_CREDENTIALS_JSON"] = "[{\"token\": \"x\"}]"
            with self.subTest(change=change):
                self.assertTrue(checks.check_delivery(broken))

    def test_estate_identifiers_are_rejected_in_docs_and_json(self):
        self.assertEqual(checks.check_private_references(ROOT), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "components").mkdir()
            (root / "examples").mkdir()
            (root / "components" / "notes.md").write_text("staged on storage-host", encoding="utf-8")
            (root / "examples" / "pins.json").write_text('{"repo": "deployment-config"}', encoding="utf-8")
            found = checks.check_private_references(root)
        self.assertEqual(len(found), 2)
        self.assertTrue(all("private or forbidden" in e for e in found))

    # --- privacy checks: `scripts/` is walked behind an enumerated debt register (five rules, one case each) ---

    def scan_fixture(self, files, register):
        """Run the scan over a temporary checkout holding `files`, waivered by `register`.

        The register is always supplied: the shipped one is correct by construction against the real
        tree, so a fixture can only exercise the rules against a register written for the fixture.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in files.items():
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
            return checks.check_private_references(root, register=register)

    def test_a_scripts_file_with_no_register_entry_is_refused(self):
        """Rule 1: the register is what makes a new leak fail, so an unwaived file must not pass."""
        found = self.scan_fixture({"scripts/driver.py": "host = 'storage-host'\n",
                                   "scripts/clean.py": "host = 'elsewhere'\n"}, {})
        self.assertEqual(len(found), 1, found)
        self.assertIn("scripts/driver.py", found[0])
        self.assertIn("storage-host", found[0])
        self.assertIn("SCRIPTS_PRIVACY_DEBT", found[0])

    def test_a_registered_file_may_not_carry_a_token_it_never_declared(self):
        """Rule 2: an entry waives the tokens measured today, and a new one names itself in the error."""
        found = self.scan_fixture({"scripts/driver.py": "host = 'storage-host'\npath = '/srv/observe/x'\n"},
                                  {"scripts/driver.py": ("staging debt", ("storage-host",))})
        self.assertEqual(len(found), 1, found)
        self.assertIn("/srv/observe", found[0])
        self.assertIn("does not tolerate", found[0])

    def test_a_waiver_for_a_token_that_is_gone_is_reported(self):
        """Rule 3, against this checkout: debt that has been paid must be deleted, not left to drift."""
        register = {**checks.SCRIPTS_PRIVACY_DEBT,
                    "scripts/_lib/guards.py": (checks.GUARD_DEBT, ("docker.sock", "admin-host"))}
        found = checks.check_private_references(ROOT, register=register)
        self.assertEqual(len(found), 1, found)
        self.assertIn("scripts/_lib/guards.py", found[0])
        self.assertIn("stale waiver, delete it", found[0])
        self.assertIn("admin-host", found[0])

    def test_a_waiver_for_a_path_that_does_not_exist_is_reported(self):
        """Rule 4: a driver moved or archived leaves its entry behind, and an empty waiver is a lie."""
        register = {**checks.SCRIPTS_PRIVACY_DEBT,
                    "scripts/staging/a_driver_that_was_moved.py": (checks.GUARD_DEBT, ("storage-host",))}
        found = checks.check_private_references(ROOT, register=register)
        self.assertEqual(len(found), 1, found)
        self.assertIn("scripts/staging/a_driver_that_was_moved.py", found[0])
        self.assertIn("does not exist", found[0])

    def test_a_waiver_without_a_reason_waives_nothing(self):
        """Rule 5, mirroring the credential exceptions above: the leak is still reported (rule 1 fires).

        The shipped register's two reasons are never blank, so the blank case can only be written
        against a register supplied by this test.
        """
        register = {**checks.SCRIPTS_PRIVACY_DEBT,
                    "scripts/_lib/guards.py": ("   ", ("docker.sock",))}
        found = checks.check_private_references(ROOT, register=register)
        named = [error for error in found if "scripts/_lib/guards.py" in error]
        self.assertEqual(len(named), 2, named)
        self.assertTrue(any("must state its reason" in error for error in named), named)
        self.assertTrue(any("private or forbidden" in error and "docker.sock" in error for error in named), named)

    def test_the_debt_register_describes_this_checkout_only(self):
        """Rules 3 and 4 stay quiet against a foreign root (`--root`, release contract): it owes nobody's waiver review.

        Rules 1 and 2 still bite there — a leak is a leak in any checkout — so a stale entry is silent
        and a new one is not: a foreign tree that leaks is refused, a foreign tree that simply does not
        match this register is not.
        """
        stale = {"scripts/absent.py": ("staging debt", ("storage-host",)), "scripts/here.py": ("staging debt", ("nope",))}
        found = self.scan_fixture({"scripts/here.py": "name = 'anything'\n"}, stale)
        self.assertEqual(found, [], found)
        leaked = self.scan_fixture({"scripts/here.py": "name = 'example-site'\n"},
                                   {"scripts/here.py": ("staging debt", ())})
        self.assertEqual(len(leaked), 1, leaked)
        self.assertIn("example-site", leaked[0])

    def test_the_scan_reaches_source_files_not_only_manifests(self):
        """The second hole privacy checks found: `.py` under `components/` was never scanned at all."""
        found = self.scan_fixture({"components/tool.py": "HOST = 'storage-host'\n"}, {})
        self.assertEqual(len(found), 1, found)
        self.assertIn("components/tool.py", found[0])

    def test_a_root_without_scripts_is_scanned_without_complaint(self):
        """A fixture checkout holding only `components/` is nobody's defect: the missing base is skipped."""
        found = self.scan_fixture({"components/clean.yaml": "name: elsewhere\n"}, {})
        self.assertEqual(found, [])

    def test_the_shipped_register_carries_a_reason_for_every_waiver_it_states(self):
        """The register is read once here so the tree does not have to be broken for the rule to be seen."""
        self.assertTrue(checks.SCRIPTS_PRIVACY_DEBT, "an empty register would mean scripts/ is clean")
        for relative, (reason, tokens) in checks.SCRIPTS_PRIVACY_DEBT.items():
            with self.subTest(path=relative):
                self.assertIn(reason, (checks.GUARD_DEBT,),
                              "a new kind of debt needs its own named reason")
                self.assertTrue(tokens, "an entry waiving no token waives nothing")
                self.assertNotIn(relative, ("scripts/check_foundation.py",),
                                 "the gate's own file is skipped by name, never registered")

    def test_a_re_added_baseline_tree_is_refused(self):
        """deployment separation/decision deployment separation: private preparation inputs left the product tree and must not come back.

        `baseline.json`, `baseline-02.json` and `ownership.yaml` described one estate's hosts, tiles
        and dashboards, and every script that reads them now takes the directory from
        `LO_MIGRATION_BASELINE_DIR`. The fixture pins all three shapes: the `migration/estate/`
        directory is refused once for the whole subtree (not once per file), a stray `baseline*.json`
        anywhere under `migration/` is refused on its own name, and an unrelated file under that
        directory stays nobody's business -- the check must not become a blanket ban that hides the
        real signal.
        """
        self.assertEqual(checks.check_baseline_inputs(ROOT), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            estate = root / "migration" / "estate"
            estate.mkdir(parents=True)
            (estate / "baseline.json").write_text('{}', encoding="utf-8")
            (estate / "ownership.yaml").write_text('{}', encoding="utf-8")
            found = checks.check_baseline_inputs(root)
            self.assertEqual(len(found), 1, found)
            self.assertIn("migration/estate", found[0])
            for token in ("decision deployment separation", "LO_MIGRATION_BASELINE_DIR", "operator's repository"):
                self.assertIn(token, found[0], found[0])
            # A capture outside that directory is refused by name, and only it.
            (root / "migration" / "estate" / "baseline.json").unlink()
            (root / "migration" / "estate" / "ownership.yaml").unlink()
            (root / "migration" / "estate").rmdir()
            (root / "migration" / "notes.md").write_text('# public prose\n', encoding="utf-8")
            (root / "migration" / "baseline-02.json").write_text('{}', encoding="utf-8")
            found = checks.check_baseline_inputs(root)
            self.assertEqual(len(found), 1, found)
            self.assertIn("migration/baseline-02.json", found[0])
            self.assertNotIn("notes.md", found[0])
            (root / "migration" / "baseline-02.json").unlink()
            self.assertEqual(checks.check_baseline_inputs(root), [], "an unrelated file is not a defect")

    def test_the_foundation_gate_wires_the_baseline_check_in(self):
        """The rule must be a gate, not a helper: `check_foundation` has to report it.

        Every other check is stubbed here because a fixture checkout holds no components or examples;
        what is left unstubbed is the wiring line, so a check that exists but is never called cannot
        pass this test.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "migration" / "estate").mkdir(parents=True)
            (root / "migration" / "estate" / "baseline.json").write_text('{}', encoding="utf-8")
            with contextlib.ExitStack() as stack:
                for name, value in (("EXAMPLE_MANIFESTS", ()), ("read_yaml", lambda _path: {}),
                                    ("check_ingest", lambda _config: []), ("check_store", lambda _config: []),
                                    ("check_delivery", lambda _config: []),
                                    ("check_private_references", lambda _root: [])):
                    stack.enter_context(patch.object(checks, name, value))
                found = checks.check_foundation(root)
        self.assertEqual(len(found), 1, found)
        self.assertIn("decision deployment separation", found[0])

    def test_volatile_queue_is_rejected(self):
        config = checks.read_yaml(ROOT / "components/data/front-door/collector.yaml")
        del config["exporters"]["otlp"]["sending_queue"]["storage"]
        self.assertTrue(any("persistent" in e for e in checks.check_ingest(config)))

    def test_internal_database_port_is_rejected(self):
        directory = ROOT / "components/data/store-signoz"
        model = checks.read_yaml(directory / "compose.yaml")
        model["services"]["clickhouse"]["ports"] = ["127.0.0.1:8123:8123"]
        self.assertTrue(any("internal service" in e for e in checks.check_model(model, directory)))

    def test_undefined_processor_is_rejected(self):
        config = checks.read_yaml(ROOT / "components/data/agent-linux/collector.yaml")
        config["service"]["pipelines"]["logs"]["processors"].append("not-defined")
        self.assertTrue(any("not-defined" in e for e in checks.check_collector(config, "agent")))

    def test_connector_is_allowed_only_in_receiver_and_exporter_positions(self):
        config = {"connectors": {"bridge": {}}, "service": {"pipelines": {
            "metrics": {"receivers": ["bridge"], "exporters": ["bridge"]}}}}
        self.assertEqual(checks.check_collector(config, "test"), [])
        config["service"]["pipelines"]["metrics"]["processors"] = ["bridge"]
        self.assertTrue(checks.check_collector(config, "test"))

    def test_runtime_rejects_tags_public_ports_and_reused_credentials(self):
        # full example gaps changed this fixture, not the assertions: since secret files the front door's credential
        # is a
        # /run/secrets path in the environment plus a top-level secrets: block naming the host file,
        # so the model this test hands validate_runtime has to look like that (it modelled the
        # pre-secret files shape, which no shipped manifest renders any more). The file-backed credential
        # checks — including "two paths, one value" — live in tests/test_conformance_smoke.py.
        with tempfile.TemporaryDirectory() as directory:
            files = {name: Path(directory) / name for name in ("ingest-token", "store-token")}
            for name, value in (("ingest-token", "a" * 32), ("store-token", "d" * 32)):
                files[name].write_text(value, encoding="utf-8")
            model = {"services": {
                "lo-front-door": {"image": "example/collector@sha256:" + "a" * 64,
                    "environment": {"LO_INGEST_TOKEN_FILE": "/run/secrets/ingest-token",
                                    "LO_STORE_TOKEN_FILE": "/run/secrets/store-token"},
                    "ports": [{"target": 4318, "published": "14318", "host_ip": "127.0.0.1"}]},
                "signoz": {"image": "example/signoz@sha256:" + "b" * 64,
                    "environment": {"SIGNOZ_TOKENIZER_JWT_SECRET": "b" * 32}}
            }, "secrets": {name: {"file": str(path)} for name, path in files.items()}}
            self.assertEqual(smoke.validate_runtime(model), ("http://127.0.0.1:14318", "a" * 32))
            for change in ("tag", "port", "credential"):
                invalid = copy.deepcopy(model)
                front = invalid["services"]["lo-front-door"]
                if change == "tag":
                    front["image"] = "example/collector:latest"
                elif change == "port":
                    front["ports"][0]["host_ip"] = "0.0.0.0"
                else:
                    files["ingest-token"].write_text("b" * 32, encoding="utf-8")
                with self.subTest(change=change), self.assertRaises(ValueError):
                    smoke.validate_runtime(invalid)
            files["ingest-token"].write_text("a" * 32, encoding="utf-8")

    def test_http_redirect_cannot_forward_credentials(self):
        self.assertIsNone(smoke.NoRedirect().redirect_request(None, None, 302, "", {}, "http://elsewhere/"))

    def test_auth_smoke_does_not_treat_a_broken_route_as_secure(self):
        for status in (200, 400, 404, 500, 503):
            with self.subTest(status=status), self.assertRaises(ValueError):
                smoke.require_rejected(status)
        for status in (401, 403):
            smoke.require_rejected(status)

    def test_partial_otlp_failure_is_not_a_pass(self):
        with self.assertRaises(ValueError):
            smoke.require_accepted(200, b'{"partialSuccess":{"rejectedLogRecords":"1"}}')
        smoke.require_accepted(200, b'{}')

    def test_generated_signals_and_queries_share_unique_identity(self):
        samples, queries = smoke.payloads("abcdef")
        self.assertEqual(set(samples), {"metrics", "logs", "traces"})
        self.assertIn("lo_conformance_abcdef", json.dumps(samples["metrics"]))
        self.assertIn("lo_conformance_abcdef", queries["metrics"])
        trace = samples["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(len(trace["traceId"]), 32)
        self.assertIn(trace["traceId"], queries["traces"])


class ComposeModelGateTests(unittest.TestCase):
    """release contract: `--root`/`--compose` point these same rules at another checkout and at an overlay model.

    Each fixture is two sibling trees -- a product checkout holding one component and one overlay
    fragment, and an operator repository holding the top-level file that `include:`s them as ONE
    merged entry. That is the shape `docs/OPERATOR-MODEL.md` section 2 describes, and these tests say
    plainly which part of it the gate accepts and which part it refuses; overlay gate rules widened the containment
    rule to admit the operator's own directory, so the trees below are both gated trees now.
    """

    #: A shipped component: a required image variable and a read-only config file beside it.
    COMPONENT = ("services:\n  thing:\n    image: ${LO_THING_IMAGE:?pin the thing image}\n"
                 "    volumes:\n      - ./thing.yaml:/etc/thing.yaml:ro\n")
    #: An operator overlay that breaks exactly one rule: a publication on every interface.
    OVERLAY = "services:\n  thing:\n    ports: [\"0.0.0.0:9999:8080\"]\n"
    #: An operator overlay that breaks no rule: it adds one environment key to the merged service.
    PASSING_OVERLAY = "services:\n  thing:\n    environment:\n      LO_EXTRA: '1'\n"
    #: The same benign overlay for the front-door fixture, which patches the service the product
    #: ships (`lo-front-door`), so it must name that service and not invent a second one.
    PASSING_FRONT_DOOR_OVERLAY = ("services:\n  lo-front-door:\n"
                                  "    environment:\n      LO_EXTRA: '1'\n")
    #: The component of `COMPONENT` plus a platform marker: the shape `check_delivery` is called on,
    #: measured to pass every current rule (required image variable, read-only bind, mounted secret).
    PLATFORM_COMPONENT = ("services:\n  thing:\n    image: ${LO_THING_IMAGE:?pin the thing image}\n"
                          "    environment:\n"
                          "      LO_STATE_PATH: /data/platform.db\n"
                          "      LO_PLATFORM_CREDENTIALS: /run/secrets/platform-credentials\n"
                          "      LO_NOTIFICATION_MODE: ${LO_NOTIFICATION_MODE:-recording}\n"
                          "    secrets:\n      - platform-credentials\n"
                          "    volumes:\n      - ./thing.yaml:/etc/thing.yaml:ro\n"
                          "secrets:\n  platform-credentials:\n"
                          "    file: ${LO_PLATFORM_CREDENTIALS_FILE:?path to the role credentials JSON}\n")
    #: The front door as the product ships it: one read-only bind of a `./…yaml` collector config,
    #: which is the first of the two shapes `anchored_collector_configs` resolves (the second, a
    #: service `configs:` list naming a top-level entry, is what the real store manifest uses and is
    #: exercised on the shipped tree by the default run of the gate).
    FRONT_DOOR_COMPONENT = ("services:\n  lo-front-door:\n"
                            "    image: ${LO_OTEL_IMAGE:?set a digest-pinned collector image}\n"
                            "    volumes:\n"
                            "      - ./collector.yaml:/etc/otelcol-contrib/config.yaml:ro\n")
    #: A collector config that passes `check_collector` and fails `check_ingest` on one line only:
    #: the `${env:…}` bearer token form (`tests/test_check_foundation.py` pins the same defect).
    INSECURE_COLLECTOR = (
        "receivers:\n  otlp:\n    protocols:\n"
        "      grpc: {auth: {authenticator: bearertokenauth}}\n"
        "      http: {auth: {authenticator: bearertokenauth}}\n"
        "extensions:\n  bearertokenauth:\n    token: ${env:LO_INGEST_TOKEN}\n"
        "processors:\n  attributes/redact:\n    actions: []\n"
        "exporters:\n  otlp:\n    sending_queue:\n      storage: file_storage\n"
        "service:\n  pipelines:\n    traces:\n"
        "      receivers: [otlp]\n      processors: [attributes/redact]\n      exporters: [otlp]\n")
    LIFECYCLE_DOCS = ("CONTRACT.md", "backup.md", "upgrade.md", "conformance.md")

    def build(self, base: Path) -> tuple[Path, Path]:
        """Create the two-tree fixture and return (product root, the operator's model path).

        The operator's model file is written by each test, because its `include:` list is the thing
        under observation.
        """
        product, operator = base / "product", base / "operator"
        component = product / "components" / "control" / "thing"
        component.mkdir(parents=True)
        (product / "examples" / "stage").mkdir(parents=True)
        (operator / "deploy").mkdir(parents=True)
        (component / "compose.yaml").write_text(self.COMPONENT, encoding="utf-8")
        (component / "thing.yaml").write_text("# component configuration\n", encoding="utf-8")
        for name in self.LIFECYCLE_DOCS:
            (component / name).write_text(f"# {name}\n", encoding="utf-8")
        (product / "examples/stage/thing.overlay.yaml").write_text(self.OVERLAY, encoding="utf-8")
        return product, operator / "deploy" / "compose.yaml"

    def write_model(self, model: Path, include: str) -> None:
        """Write the operator's top-level file: no services of its own, one `include:` block."""
        model.write_text("include:\n" + include, encoding="utf-8")

    def test_a_model_that_includes_only_pinned_product_files_passes(self):
        """An operator file whose include chain lies inside `--root` is gated like a shipped example."""
        with tempfile.TemporaryDirectory() as directory:
            product, model = self.build(Path(directory))
            self.write_model(model, "  - ../../product/components/control/thing/compose.yaml\n")
            self.assertEqual(checks.check_example(product, model), [])
            self.assertEqual(set(checks.example_services(product, model)[0]), {"thing"})

    def test_an_overlay_that_publishes_a_host_port_is_refused_through_the_merged_model(self):
        """One fragment overriding one key fails the merged model, and says which rule it broke.

        The fragment sits inside the fixture checkout -- the position
        `examples/platform/staging.compose.yaml` occupies in the real tree. overlay gate rules admits a second tree,
        so a fragment no longer *has* to sit there for the merge to happen; the next test pins the
        same two errors when it stands in the operator's own repository instead.
        """
        with tempfile.TemporaryDirectory() as directory:
            product, model = self.build(Path(directory))
            self.write_model(model, "  - path:\n"
                                    "      - ../../product/components/control/thing/compose.yaml\n"
                                    "      - ../../product/examples/stage/thing.overlay.yaml\n"
                                    "    project_directory: ../../product/components/control/thing\n")
            services, errors = checks.example_services(product, model)
            self.assertEqual(services["thing"]["ports"], ["0.0.0.0:9999:8080"], "the merge happened")
            self.assertEqual(errors, [], "a model rule is reported, not a structural complaint")
            self.assertEqual(sorted(checks.check_example(product, model)), sorted([
                "thing: development publication must be loopback-only",
                "thing: internal service publishes a host port"]))

    def test_an_operator_overlay_beside_its_own_model_is_gated_not_refused_as_an_escape(self):
        """overlay gate rules: containment admits the model's own directory, so an outside overlay is *read*.

        `loaded_includes` used to require every included file to lie under `--root`, which refused the
        include+overlay layout of `docs/OPERATOR-MODEL.md` section 2 -- a pinned product manifest plus
        the operator's own fragment as one merged entry -- and stopped the walk before any rule ran.
        That refusal was pinned here as a known gap; this is the item that widened the rule, so the
        gap test becomes the gated case. Two clauses over the same outside position
        (`model.parent / "thing.overlay.yaml"`, the operator's composition directory):

        * `PASSING_OVERLAY` merges and nothing is refused, and the merged service carries the
          overlay's own key -- the merge happened, it was not silently skipped;
        * `OVERLAY`, the port-breaking fragment, earns exactly the two model errors its sibling test
          pins for the identical overlay merged from *inside* the checkout. The rules run over the
          operator's bytes wherever they stand, which is the whole point of the widening.

        The shared `OVERLAY` constant is not edited: the test above writes it inside the checkout and
        depends on those same two lines.
        """
        with tempfile.TemporaryDirectory() as directory:
            product, model = self.build(Path(directory))
            include = ("  - path:\n"
                       "      - ../../product/components/control/thing/compose.yaml\n"
                       "      - ./thing.overlay.yaml\n"
                       "    project_directory: ../../product/components/control/thing\n")
            self.write_model(model, include)
            (model.parent / "thing.overlay.yaml").write_text(self.PASSING_OVERLAY, encoding="utf-8")
            self.assertEqual(checks.check_example(product, model), [],
                             "an outside overlay that breaks no rule is gated and passes")
            services, structural = checks.example_services(product, model)
            self.assertEqual(structural, [])
            self.assertEqual(services["thing"]["environment"]["LO_EXTRA"], "1", "the merge happened")
            (model.parent / "thing.overlay.yaml").write_text(self.OVERLAY, encoding="utf-8")
            self.assertEqual(sorted(checks.check_example(product, model)), sorted([
                "thing: development publication must be loopback-only",
                "thing: internal service publishes a host port"]))

    def test_an_overlay_reached_from_a_third_directory_is_refused_naming_both_trees(self):
        """Containment widened to two trees, not to any path the operator names.

        A sibling of the model's directory and a directory reached by walking out with `..` are both
        outside the product checkout *and* outside the composition directory, so both are refused --
        and the refusal prints the checkout, the model directory and the offending file, because an
        operator needs to see which two trees were open. `check_example` reports one escaped include
        twice (its own walk, then `example_services`' walk), so the list is collapsed the way
        `check_foundation` collapses it at the end of a run.
        """
        for spelling, where in (("../../elsewhere/thing.overlay.yaml", "elsewhere"),
                                ("../elsewhere/thing.overlay.yaml", "operator/elsewhere")):
            with self.subTest(include=spelling):
                with tempfile.TemporaryDirectory() as directory:
                    base = Path(directory)
                    product, model = self.build(base)
                    stray = base
                    for part in where.split("/"):
                        stray = stray / part
                    stray.mkdir(parents=True)
                    (stray / "thing.overlay.yaml").write_text(self.PASSING_OVERLAY, encoding="utf-8")
                    self.write_model(model, "  - path:\n"
                                            "      - ../../product/components/control/thing/compose.yaml\n"
                                            f"      - {spelling}\n"
                                            "    project_directory: ../../product/components/control/thing\n")
                    found = list(dict.fromkeys(checks.check_example(product, model)))
                    self.assertEqual(len(found), 1, found)
                    self.assertIn("include escapes both the product checkout and the model's own "
                                  "directory", found[0])
                    self.assertIn(str(product.resolve()), found[0], "the checkout it was judged against")
                    self.assertIn(str(model.parent.resolve()), found[0], "the model's own directory")
                    self.assertIn("thing.overlay.yaml", found[0])

    def test_an_overlay_setting_a_live_notification_default_is_refused_through_the_merged_model(self):
        """The negative the ledger row asks for, and the hole release contract left open.

        `check_delivery` used to run only on `components/control/platform/compose.yaml` under `--root`,
        so a platform service merged from an operator overlay could end up sending and nothing
        complained. It now runs over every model `check_example` opens. The component carries a
        platform marker and the shipped non-sending default; the overlay, standing in the operator's
        own directory, replaces that one key. Both spellings of a live default are refused with the
        untouched delivery message.
        """
        for value in ("${LO_NOTIFICATION_MODE:-live}", "live"):
            with self.subTest(mode=value), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                product, model = self.build(base)
                (product / "components/control/thing/compose.yaml").write_text(self.PLATFORM_COMPONENT,
                                                                               encoding="utf-8")
                (model.parent / "thing.overlay.yaml").write_text(
                    f"services:\n  thing:\n    environment:\n      LO_NOTIFICATION_MODE: {value}\n",
                    encoding="utf-8")
                self.write_model(model, "  - path:\n"
                                        "      - ../../product/components/control/thing/compose.yaml\n"
                                        "      - ./thing.overlay.yaml\n"
                                        "    project_directory: ../../product/components/control/thing\n")
                self.assertEqual(checks.check_example(product, model),
                                 ["thing: notification mode must default to a non-sending mode "
                                  "(recording or off)"])

    def test_a_literal_recording_mode_is_refused_as_strictly_as_live_by_design(self):
        """Pinned deliberate strictness, not a bug to fix here.

        `SAFE_NOTIFICATION_MODE` (`scripts/check_foundation.py:22`) is
        `^\\$\\{LO_NOTIFICATION_MODE:-(recording|off)\\}$`, which a bare `recording` cannot fullmatch,
        so a literal safe default earns the same refusal a live one does. The component's own
        `${LO_NOTIFICATION_MODE:-recording}` is what the rule wants an operator to keep; hard-coding
        the word is a deployment that cannot be switched to live by accident, and is still refused.
        Question for the reviewer: whether that line should say "use the ${…:-} form" instead of
        repeating the non-sending wording, which reads like a false claim about `recording`.
        """
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            product, model = self.build(base)
            (product / "components/control/thing/compose.yaml").write_text(self.PLATFORM_COMPONENT,
                                                                           encoding="utf-8")
            self.write_model(model, "  - path:\n"
                                    "      - ../../product/components/control/thing/compose.yaml\n"
                                    "      - ./thing.overlay.yaml\n"
                                    "    project_directory: ../../product/components/control/thing\n")
            refused: list[str] = []
            for value in ("recording", "${LO_NOTIFICATION_MODE:-live}"):
                (model.parent / "thing.overlay.yaml").write_text(
                    f"services:\n  thing:\n    environment:\n      LO_NOTIFICATION_MODE: {value}\n",
                    encoding="utf-8")
                refused.append(checks.check_example(product, model))
            self.assertEqual(refused[0], refused[1],
                             "a literal `recording` and a defaulted `live` are one and the same line")
            self.assertEqual(refused[0], ["thing: notification mode must default to a non-sending mode "
                                          "(recording or off)"])

    def test_the_anchor_resolver_reads_both_shapes_and_refuses_a_config_it_cannot_open(self):
        """Both Compose shapes that carry a collector config, plus the fail-closed half of the rule.

        `check_anchored_collectors` promises authentication for whatever collector configuration the
        merged model actually mounts, so its resolver is pinned here shape by shape: the front door's
        read-only bind of a `./collector.yaml` source, and the store's service `configs:` item naming
        a top-level `configs:` entry that carries the `file:`. The store half matters most: on the
        shipped tree it is visible only as an ABSENCE in the default run -- break it and the gate
        goes red, but nothing says which service stopped being read. The last two clauses are the
        refusal: an anchored service that names no collector file at all, or names one that is not
        there, is refused rather than quietly passed, because the gate cannot promise a rule it could
        not open.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "collector.yaml").write_text("# read by the resolver test only\n", encoding="utf-8")
            front_door = {"services": {"lo-front-door": {"volumes": [
                "./collector.yaml:/etc/otelcol-contrib/config.yaml:ro", "queue:/var/lib/otelcol"]}}}
            store = {"services": {"signoz-otel-collector": {"configs": [
                         {"source": "signoz-otelcol-config",
                          "target": "/etc/otel-collector-config.yaml"}]}},
                     "configs": {"signoz-otelcol-config": {"file": "./collector.yaml"}}}
            self.assertEqual(checks.anchored_collector_configs(front_door, root),
                             {"lo-front-door": [root / "collector.yaml"]},
                             "the bind shape: the ./<file>.yaml source counts, not the named volume")
            self.assertEqual(checks.anchored_collector_configs(store, root),
                             {"signoz-otel-collector": [root / "collector.yaml"]},
                             "the configs shape: service item -> top-level entry -> that entry's file")
            unreadable = checks.check_anchored_collectors(
                {"services": {"lo-front-door": {"image": "${LO_OTEL_IMAGE:?pin}"}}}, root)
            self.assertEqual(len(unreadable), 1, unreadable)
            self.assertIn("lo-front-door", unreadable[0])
            self.assertIn("unreadable", unreadable[0])
            missing = checks.check_anchored_collectors(
                {"services": {"signoz-otel-collector": {"volumes": ["./absent.yaml:/x:ro"]}}}, root)
            self.assertEqual(len(missing), 1, missing)
            self.assertIn("absent.yaml", missing[0], "the candidate that could not be opened is named")

    def test_an_anchored_front_door_is_read_from_the_merged_model_and_named_by_config_path(self):
        """`check_anchored_collectors` follows the bind the model mounts, and says which file failed.

        The fixture service is the name the product ships (`lo-front-door`), its collector config is
        the `${env:…}` bearer token `tests/test_check_foundation.py` pins as the defect, and the gate
        is the merged model: the error must carry the resolved config path as its prefix, so an
        operator with two collector files sees which one broke. Nothing here touches `--root`'s own
        front door, which the default run still reads by path.
        """
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            product, model = self.build(base)
            component = product / "components" / "control" / "thing"
            (component / "compose.yaml").write_text(self.FRONT_DOOR_COMPONENT, encoding="utf-8")
            (component / "thing.yaml").unlink()
            collector = component / "collector.yaml"
            collector.write_text(self.INSECURE_COLLECTOR, encoding="utf-8")
            (model.parent / "thing.overlay.yaml").write_text(self.PASSING_FRONT_DOOR_OVERLAY,
                                                              encoding="utf-8")
            self.write_model(model, "  - path:\n"
                                    "      - ../../product/components/control/thing/compose.yaml\n"
                                    "      - ./thing.overlay.yaml\n"
                                    "    project_directory: ../../product/components/control/thing\n")
            found = list(dict.fromkeys(checks.check_example(product, model)))
            self.assertEqual(len(found), 1, found)
            self.assertIn("mounted secret file", found[0])
            self.assertTrue(found[0].startswith(f"{collector.resolve()}: "),
                            f"the error must name the config file: {found[0]}")

    def test_relative_model_names_resolve_against_the_working_directory_not_the_root(self):
        """`--root` bounds what may be included; it must not relocate the file `--compose` names."""
        with tempfile.TemporaryDirectory() as directory:
            product, model = self.build(Path(directory))
            self.assertEqual(checks.compose_models(product),
                             [product / name for name in checks.EXAMPLE_MANIFESTS])
            self.assertEqual(checks.compose_models(product, ["examples/full/compose.yaml"]),
                             [Path.cwd() / "examples/full/compose.yaml"])
            self.assertEqual(checks.compose_models(product, [model]), [model])
            outside = Path(directory) / "operator" / "missing.yaml"
            self.assertEqual(checks.compose_models(product, [outside]), [outside])

    def test_a_named_model_replaces_the_shipped_examples_rather_than_adding_to_them(self):
        """Which Compose models get walked is the whole meaning of `--compose`, so pin the selection.

        The three product-anchored readers are stubbed: a fixture checkout holds no front door, store
        or platform manifest, and what is under test here is the walk list, not them.
        """
        with tempfile.TemporaryDirectory() as directory:
            product, model = self.build(Path(directory))
            self.write_model(model, "  - ../../product/components/control/thing/compose.yaml\n")
            with contextlib.ExitStack() as stack:
                for name, value in (("check_ingest", lambda _config: []),
                                    ("check_store", lambda _config: []),
                                    ("check_delivery", lambda _config: []),
                                    ("read_yaml", lambda _path: {})):
                    stack.enter_context(patch.object(checks, name, value))
                walked: list[Path] = []
                stack.enter_context(patch.object(checks, "check_example",
                                                 lambda _root, example: walked.append(example) or []))
                self.assertEqual(checks.check_foundation(product, [model]), [])
                self.assertEqual(walked, [model], "one named model, and nothing else")
                walked.clear()
                self.assertEqual(checks.check_foundation(product),
                                 [f"Compose model is missing: {product / name}"
                                  for name in checks.EXAMPLE_MANIFESTS],
                                 "with no --compose the walk list is the shipped examples, missing included")
                self.assertEqual(walked, [], "a fixture tree ships no examples, so none was opened")

    def test_the_scope_line_says_what_was_walked_and_the_default_line_is_untouched(self):
        """A green report must not read as a claim about a tree this run never opened.

        The unqualified run's sentence is quoted in docs/INSTALLATION.md, so it is pinned byte for
        byte here; anything else names the checkout and the models, because `--root` moves the gate.
        """
        other = Path(tempfile.gettempdir()) / "product-checkout"
        default_scope = ("shipped manifests, dashboards and collector configs in this repository: "
                         "static shape, ingest protection and privacy rules only; no container was "
                         "started and no host was read")
        self.assertEqual(checks.scope_text(checks.ROOT, None), default_scope)
        self.assertEqual(checks.scope_text(checks.ROOT, []), default_scope)
        moved = checks.scope_text(other, ["deploy/compose.yaml"])
        self.assertIn(str(other), moved)
        self.assertIn("deploy/compose.yaml", moved)
        self.assertNotEqual(moved, default_scope)
        named_root_only = checks.scope_text(other, None)
        self.assertIn(str(other), named_root_only)
        self.assertIn("examples/full/compose.yaml", named_root_only, "the shipped list is still named")


class ComposeModelCommandLineTests(unittest.TestCase):
    """The release contract flags end to end: the default run is unchanged, and a named model can pass or refuse."""

    def run_gate(self, *arguments: str) -> subprocess.CompletedProcess:
        """Run the gate as an operator would, from the repository root, and capture its verdict."""
        return subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / "check_foundation.py"),
                               *arguments], cwd=ROOT, capture_output=True, text=True, timeout=120)

    def test_the_default_run_is_still_the_default_run(self):
        """No arguments means no behaviour change: same exit, same sentence, same scope claim."""
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(),
                         "Static foundation checks passed; runtime conformance not run.")
        self.assertIn("in this repository", json.loads(self.run_gate("--json").stdout)["scope"])

    def test_the_documented_command_line_passes_over_the_shipped_full_example(self):
        """`--root . --compose examples/full/compose.yaml` is the line the ledger row is verified by."""
        result = self.run_gate("--root", ".", "--compose", "examples/full/compose.yaml")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(),
                         "Static foundation checks passed; runtime conformance not run.")

    def test_a_model_that_breaks_a_rule_refuses_the_run(self):
        """A model outside the checkout still fails the gate, and the error names the rule."""
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "merged.compose.yaml"
            model.write_text("services:\n  thing:\n    image: ${LO_THING_IMAGE:?pin the thing image}\n"
                             "    ports: [\"0.0.0.0:9999:8080\"]\n", encoding="utf-8")
            result = self.run_gate("--root", ".", "--compose", str(model))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("thing: development publication must be loopback-only", result.stdout)

    def test_a_missing_model_is_named_rather_than_crashing_the_gate(self):
        """An operator typo is a reported defect, never a stack trace or a silent pass."""
        result = self.run_gate("--root", ".", "--compose", "examples/nope/compose.yaml")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Compose model is missing:", result.stdout)


if __name__ == "__main__":
    unittest.main()

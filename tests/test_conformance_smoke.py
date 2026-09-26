"""Argument handling and the compose-ps parser of scripts/conformance_smoke.py (full example gaps).

Both are pure functions over the rendered Compose model and the JSON that ``docker compose ps``
prints, so they are testable on a host with no Docker. What the rest of the script does (posting
OTLP, reading ClickHouse) cannot be tested here and is not claimed by these tests.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import conformance_smoke as smoke


DIGEST = "example/image@sha256:" + "a" * 64


def model_with_secrets(ingest: str, store: str) -> tuple:
    """A rendered model in the shape secret files produces: paths in the environment, values in files.

    Returns ``(model, directory)``; the caller owns ``directory`` and must clean it up. The two
    credential files are written there, and their paths are what the model's top-level ``secrets:``
    block names, exactly as ``docker compose config --format json`` reports them.
    """
    directory = Path(tempfile.mkdtemp())
    ingest_file, store_file = directory / "ingest-token", directory / "store-token"
    ingest_file.write_text(ingest, encoding="utf-8")
    store_file.write_text(store, encoding="utf-8")
    model = {
        "services": {
            "lo-front-door": {
                "image": DIGEST,
                "environment": {"LO_INGEST_TOKEN_FILE": "/run/secrets/front-door-ingest-token",
                                "LO_STORE_TOKEN_FILE": "/run/secrets/front-door-store-token"},
                "secrets": ["front-door-ingest-token", "front-door-store-token"],
                "ports": [{"target": 4318, "published": "14318", "host_ip": "127.0.0.1"}],
            },
            "signoz": {"image": DIGEST, "environment": {"SIGNOZ_TOKENIZER_JWT_SECRET": "b" * 32}},
        },
        "secrets": {
            "front-door-ingest-token": {"file": str(ingest_file)},
            "front-door-store-token": {"file": str(store_file)},
        },
    }
    return model, directory


def fixture_model() -> dict:
    """A small three-service model: one healthchecked, one plain, one a successful one-shot."""
    return {"services": {
        "clickhouse": {"image": DIGEST, "healthcheck": {"test": ["CMD", "wget"]}},
        "lo-front-door": {"image": DIGEST},
        "init-clickhouse": {"image": DIGEST, "restart": "no"},
    }}


def ps_rows(**states) -> list:
    """ps rows for the fixture model, one per keyword argument ``service=(state, health, exit)``."""
    return [{"Service": name, "State": state, "Health": health, "ExitCode": code}
            for name, (state, health, code) in states.items()]


class ArgumentHandling(unittest.TestCase):
    def test_default_compose_is_still_the_demo(self):
        """full example gaps added --compose without moving the default: every recorded command names the demo."""
        args = smoke.parse_args(["--env-file", "private.env"])
        self.assertEqual(args.compose, (ROOT / "examples/demo/compose.yaml").resolve())
        self.assertEqual(args.project, "local-observe-demo")

    def test_full_example_is_selected_by_relative_path(self):
        args = smoke.parse_args(["--env-file", "private.env", "--compose", "examples/full/compose.yaml",
                                 "--project", "local-observe-full"])
        self.assertEqual(args.compose, (ROOT / "examples/full/compose.yaml").resolve())

    def test_project_outside_the_two_examples_is_refused(self):
        """The guard keeps the script off a live deployment; full example gaps widened it by one rehearsal name."""
        for project in ("local-observe-production", "local-observe", "local-observe-demox", "demo"):
            with self.subTest(project=project), self.assertRaises(SystemExit):
                smoke.parse_args(["--env-file", "private.env", "--project", project])
        for project in ("local-observe-demo", "local-observe-demo-r22", "local-observe-full",
                        "local-observe-full-r22"):
            with self.subTest(project=project):
                self.assertEqual(smoke.parse_args(["--env-file", "private.env", "--project", project]).project,
                                 project)

    def test_compose_must_be_a_file_inside_the_checkout(self):
        with self.assertRaises(SystemExit):
            smoke.parse_args(["--env-file", "private.env", "--compose", "../outside.yaml"])
        with self.assertRaises(SystemExit):
            smoke.parse_args(["--env-file", "private.env", "--compose", "examples/full/nope.yaml"])

    def test_wait_seconds_stays_bounded(self):
        for seconds in ("0", "601", "-1"):
            with self.subTest(seconds=seconds), self.assertRaises(SystemExit):
                smoke.parse_args(["--env-file", "private.env", "--wait-seconds", seconds])


class CredentialFiles(unittest.TestCase):
    def model(self, ingest: str, store: str) -> dict:
        """A model with real credential files, with its directory removed when the test ends."""
        model, directory = model_with_secrets(ingest, store)
        self.addCleanup(lambda: shutil.rmtree(directory, ignore_errors=True))
        return model

    def test_r18_model_reads_the_secret_file_not_the_environment(self):
        """The KeyError secret files left behind: the environment holds a path, so the value is in the file."""
        model = self.model("c" * 32, "d" * 32)
        url, token = smoke.validate_runtime(model)
        self.assertEqual(url, "http://127.0.0.1:14318")
        self.assertEqual(token, "c" * 32)
        environment = model["services"]["lo-front-door"]["environment"]
        self.assertNotIn("LO_INGEST_TOKEN", environment, "the value must not be in the environment")
        self.assertTrue(all(name.endswith("_FILE") for name in environment), environment)

    def test_same_value_in_two_files_is_reused_credential(self):
        """Comparing paths would pass; the two files' contents are what must differ."""
        self.assertRaises(ValueError, smoke.validate_runtime, self.model("e" * 32, "e" * 32))

    def test_a_bare_environment_token_is_no_longer_accepted(self):
        model = self.model("f" * 32, "g" * 32)
        front = model["services"]["lo-front-door"]
        front["environment"]["LO_INGEST_TOKEN"] = "f" * 32
        del front["environment"]["LO_INGEST_TOKEN_FILE"]
        with self.assertRaises(ValueError):
            smoke.validate_runtime(model)

    def test_secret_mount_naming_an_undeclared_secret_is_refused(self):
        model = self.model("h" * 32, "i" * 32)
        model["services"]["lo-front-door"]["environment"]["LO_INGEST_TOKEN_FILE"] = "/run/secrets/absent"
        with self.assertRaises(ValueError):
            smoke.validate_runtime(model)

    def test_nested_or_non_file_secret_paths_are_refused_not_silently_empty(self):
        model = self.model("j" * 32, "k" * 32)
        front = model["services"]["lo-front-door"]
        for value in ("/run/secrets/", "/run/secrets/sub/dir-token", "ingest-token"):
            with self.subTest(value=value):
                front["environment"]["LO_INGEST_TOKEN_FILE"] = value
                with self.assertRaises(ValueError):
                    smoke.validate_runtime(model)
        model["secrets"]["front-door-store-token"] = {"external": True}
        front["environment"]["LO_INGEST_TOKEN_FILE"] = "/run/secrets/front-door-ingest-token"
        with self.assertRaises(ValueError):
            smoke.validate_runtime(model)


class ServiceState(unittest.TestCase):
    def test_requirements_come_from_the_model(self):
        self.assertEqual(smoke.service_requirements(fixture_model()),
                         {"clickhouse": "healthy", "lo-front-door": "running", "init-clickhouse": "oneshot"})

    def test_every_service_in_its_promised_state_passes(self):
        problems = smoke.service_state_problems(fixture_model(), ps_rows(**{
            "clickhouse": ("running", "healthy", 0),
            "lo-front-door": ("running", "", 0),
            "init-clickhouse": ("exited", "", 0),
        }))
        self.assertEqual(problems, [])

    def test_a_service_with_a_healthcheck_must_report_healthy(self):
        """`running` is not enough: a container up and refusing queries is still running."""
        model = fixture_model()
        rows = ps_rows(**{"clickhouse": ("running", "unhealthy", 0), "lo-front-door": ("running", "", 0),
                          "init-clickhouse": ("exited", "", 0)})
        problems = smoke.service_state_problems(model, rows)
        self.assertEqual(len(problems), 1)
        self.assertIn("clickhouse", problems[0])
        rows[0]["Health"] = "starting"
        self.assertIn("starting", smoke.service_state_problems(model, rows)[0])

    def test_a_service_without_a_healthcheck_is_not_invented_one(self):
        """The parser judges health only where the manifest declares a healthcheck.

        Compose reports no health for the front door, and a stray value there is not this check's
        business: inventing a requirement the manifest does not state would fail a stack that is
        fine, which is how a check stops being trusted.
        """
        model = fixture_model()
        rows = ps_rows(**{"clickhouse": ("running", "healthy", 0), "lo-front-door": ("running", "", 0),
                          "init-clickhouse": ("exited", "", 0)})
        self.assertEqual(smoke.service_state_problems(model, rows), [])
        rows[1]["Health"] = "unhealthy"
        self.assertEqual(smoke.service_state_problems(model, rows), [])
        model["services"]["clickhouse"].pop("healthcheck")
        self.assertEqual(smoke.service_requirements(model)["clickhouse"], "running")

    def test_not_running_is_reported_for_every_class(self):
        for state in ("exited", "restarting", "dead", ""):
            with self.subTest(state=state):
                rows = ps_rows(**{"clickhouse": (state, "", 0), "lo-front-door": ("running", "", 0),
                                  "init-clickhouse": ("exited", "", 0)})
                self.assertIn("clickhouse", " ".join(smoke.service_state_problems(fixture_model(), rows)))

    def test_one_shot_must_have_succeeded(self):
        for exit_code, passes in (("0", True), ("1", False), ("", False)):
            with self.subTest(exit_code=exit_code):
                rows = ps_rows(**{"clickhouse": ("running", "healthy", 0), "lo-front-door": ("running", "", 0),
                                  "init-clickhouse": ("exited", "", exit_code)})
                problems = " ".join(smoke.service_state_problems(fixture_model(), rows))
                self.assertEqual("init-clickhouse" in problems, not passes)
        still_up = ps_rows(**{"clickhouse": ("running", "healthy", 0), "lo-front-door": ("running", "", 0),
                             "init-clickhouse": ("running", "", 0)})
        self.assertEqual(smoke.service_state_problems(fixture_model(), still_up), [])

    def test_a_declared_service_missing_from_ps_is_a_problem(self):
        """An include entry that silently did not start must not read as an empty project."""
        rows = ps_rows(**{"clickhouse": ("running", "healthy", 0)})
        problems = smoke.service_state_problems(fixture_model(), rows)
        self.assertEqual(len(problems), 2)
        self.assertTrue(all("no container" in problem for problem in problems))

    def test_containers_not_in_the_model_are_ignored(self):
        """A project may hold one-off `docker compose run` containers; they are not a service state."""
        rows = ps_rows(**{"clickhouse": ("running", "healthy", 0), "lo-front-door": ("running", "", 0),
                          "init-clickhouse": ("exited", "", 0), "one-off": ("created", "", 0)})
        self.assertEqual(smoke.service_state_problems(fixture_model(), rows), [])


class PsParsing(unittest.TestCase):
    def test_json_array_form(self):
        rows = smoke.parse_ps('[{"Service": "a", "State": "running"}]')
        self.assertEqual(rows, [{"Service": "a", "State": "running"}])

    def test_newline_delimited_form(self):
        text = '{"Service": "a"}\n{"Service": "b"}\n'
        self.assertEqual([row["Service"] for row in smoke.parse_ps(text)], ["a", "b"])

    def test_a_single_object_is_still_one_row(self):
        self.assertEqual(smoke.parse_ps('{"Service": "a"}'), [{"Service": "a"}])

    def test_empty_or_unshaped_output_is_an_error_not_a_pass(self):
        for output in ("", "   ", "null", "[1, 2]", "not json"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                smoke.parse_ps(output)


class Polling(unittest.TestCase):
    def test_wait_for_services_returns_the_first_clean_reading(self):
        good = json.dumps([{"Service": "clickhouse", "State": "running", "Health": "healthy"},
                           {"Service": "lo-front-door", "State": "running"},
                           {"Service": "init-clickhouse", "State": "exited", "ExitCode": 0}])
        calls = []

        def fake_compose_output(prefix, *args):
            calls.append(args)
            return good if len(calls) > 1 else '[{"Service": "lo-front-door", "State": "running"}]'

        original, original_sleep = smoke.compose_output, time.sleep
        smoke.compose_output = fake_compose_output
        time.sleep = lambda seconds: None
        self.addCleanup(setattr, smoke, "compose_output", original)
        self.addCleanup(setattr, time, "sleep", original_sleep)
        problems = smoke.wait_for_services(["docker", "compose"], fixture_model(), time.monotonic() + 60)
        self.assertEqual(problems, [])
        self.assertEqual(calls, [("ps", "--format", "json")] * 2)

    def test_wait_for_services_reports_the_last_problems(self):
        def fake_compose_output(prefix, *args):
            return json.dumps([{"Service": "clickhouse", "State": "running", "Health": "unhealthy"}])

        original, original_sleep = smoke.compose_output, time.sleep
        smoke.compose_output = fake_compose_output
        time.sleep = lambda seconds: None
        self.addCleanup(setattr, smoke, "compose_output", original)
        self.addCleanup(setattr, time, "sleep", original_sleep)
        problems = smoke.wait_for_services(["docker", "compose"], fixture_model(), time.monotonic())
        self.assertTrue(any("clickhouse" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()

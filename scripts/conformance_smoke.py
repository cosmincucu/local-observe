"""Inject synthetic OTLP into an already-running isolated example and verify it in ClickHouse.

Does not start/stop containers or perform backup/restore. A pass is only the
auth and three-signal smoke subset, not full component validation. ``--compose`` selects which
example to drive (the demo by default), and the service-state check reads that file's own model,
so nothing here is specific to one example.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.run import run

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$")
#: The example this script has driven since it was written. Unchanged default: every recorded
#: conformance run and docs/INSTALLATION.md step names the demo with no --compose argument.
DEFAULT_COMPOSE = "examples/demo/compose.yaml"
#: Only the project names the shipped examples declare, optionally with a per-run suffix. The guard
#: exists so a mistyped ``--project`` cannot point this script at a deployment that is not an
#: isolated rehearsal, and it has to name the full example too now that --compose can select it.
PROJECT_NAME = re.compile(r"local-observe-(?:demo|full)(?:-[a-z0-9-]+)?")
SECRET_PREFIX = "/run/secrets/"
#: How long the service-state check waits for containers still starting. Healthchecks carry their
#: own start_period (the Sigma runner's is 60 s), so a single reading taken straight after `up -d`
#: would report a stack that is merely still booting as a failure.
STATE_POLL_SECONDS = 5.0


def compose_environment(service: dict) -> dict:
    """Return a service's Compose environment as a mapping, accepting both notations.

    ``docker compose config --format json`` renders a mapping, but a hand-written fixture or an
    older renderer may use the list of ``NAME=value`` strings, and the manifests themselves use both.
    """
    environment = service.get("environment", {})
    if isinstance(environment, list):
        return dict(item.split("=", 1) for item in environment)
    return dict(environment)


def secret_credential(model: dict, service_name: str, variable: str) -> str:
    """Read the host file that one service's mounted secret was bound from.

    Since secret files a product credential never appears as an environment value: the environment carries
    the *container path* (``/run/secrets/<name>``) and the manifest's top-level ``secrets:`` block
    names the host file behind that name. So the value the container actually holds is the contents
    of that file, and this is the only honest way for a script outside the containers to obtain it.

    Raises:
        KeyError: the service, the variable or the secret is absent from the model.
        ValueError: the variable does not name a secret mount, or the secret is not a file the
            script can read (an ``external`` or swarm secret has no host file to compare).
    """
    container_path = str(compose_environment(model["services"][service_name]).get(variable, ""))
    if not container_path.startswith(SECRET_PREFIX) or container_path.rstrip("/") == SECRET_PREFIX.rstrip("/"):
        raise ValueError(f"{service_name}/{variable} is not a {SECRET_PREFIX} mount path, so the model "
                         f"does not say which secret holds this credential")
    name = container_path[len(SECRET_PREFIX):].strip("/")
    if "/" in name:
        raise ValueError(f"{service_name}/{variable} names a nested secret path {container_path}, "
                         f"which Compose does not create")
    entry = (model.get("secrets") or {}).get(name)
    if entry is None:
        raise ValueError(f"{service_name}/{variable} reads {container_path}, but the rendered model "
                         f"declares no top-level secret named {name}")
    if "file" not in entry:
        raise ValueError(f"secret {name} is not a file secret in the rendered model, so its value "
                         f"cannot be read back for comparison")
    return Path(entry["file"]).read_text(encoding="utf-8")


def compose_output(prefix, *args):
    """Return the stdout of a compose command; stderr is never repeated into a shared string."""
    return run([*prefix, *args], timeout=60)


def service_requirements(model: dict) -> dict:
    """Map each declared service to the state this smoke is allowed to accept for it.

    Three kinds, all read from the model rather than guessed from names:

    ``"oneshot"``
        ``restart: 'no'`` (``none`` means the same thing). ``init-clickhouse`` and the SigNoz
        migrator do their work and exit 0; requiring them to still be running would make the check
        unsatisfiable, and requiring nothing would let a crashed one-shot pass.
    ``"healthy"``
        the service declares a ``healthcheck``, so ``running`` alone proves nothing: a container that
        is up and refusing every query is ``running``. The store's UI, the collector and the Sigma
        runner are all in this class.
    ``"running"``
        no healthcheck is declared (the front door and the Linux agent), so ``running`` is the whole
        of what Compose can report.
    """
    requirements = {}
    for name, service in (model.get("services") or {}).items():
        if str(service.get("restart", "")).lower() in ("no", "none"):
            requirements[name] = "oneshot"
        elif service.get("healthcheck"):
            requirements[name] = "healthy"
        else:
            requirements[name] = "running"
    return requirements


def parse_ps(output: str) -> list:
    """Return the container rows of ``docker compose ps --format json``.

    Compose V2 prints one JSON array; a version that prints newline-delimited objects is accepted
    too, because the two differ only in framing and a silently-empty row list would read as an
    empty project rather than a parse failure. An empty input is refused for that reason.

    Raises:
        ValueError: the output is not a JSON array of objects, or is empty.
    """
    text = (output or "").strip()
    if not text:
        raise ValueError("compose ps returned nothing; the project has no containers to inspect")
    try:
        decoded = json.loads(text)
        rows = decoded if isinstance(decoded, list) else [decoded]
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("compose ps returned something that is not a list of container objects")
    return rows


def service_state_problems(model: dict, rows: list) -> list:
    """Return one line per service that is not in the state its own manifest promises.

    An empty list is the pass condition: every service the rendered model declares exists in the
    ``ps`` output, is ``running`` (or exited 0, for the two one-shots), and reports ``healthy``
    wherever a healthcheck exists. A service missing from ``ps`` is reported rather than ignored:
    an ``include`` entry that silently failed to start is exactly what this check is for.
    """
    problems = []
    seen = {}
    for row in rows:
        name = str(row.get("Service", ""))
        if name:
            seen.setdefault(name, row)
    for name, requirement in sorted(service_requirements(model).items()):
        row = seen.get(name)
        if row is None:
            problems.append(f"{name}: no container in compose ps")
            continue
        state = str(row.get("State", "")).lower()
        health = str(row.get("Health", "")).lower()
        if requirement == "oneshot":
            if state == "running":
                continue
            if state in ("exited", "complete") and str(row.get("ExitCode", "")) == "0":
                continue
            problems.append(f"{name}: one-shot is {state} (exit {row.get('ExitCode', '?')}), not "
                            f"completed successfully")
            continue
        if state != "running":
            problems.append(f"{name}: state is {state or 'unknown'}, not running")
        elif requirement == "healthy" and health != "healthy":
            problems.append(f"{name}: health is {health or 'none'}, not healthy")
    return problems


def wait_for_services(prefix, model: dict, deadline: float) -> list:
    """Poll compose ps until every service is in its promised state or the deadline passes.

    Returns the last problem list, which is empty on success. Each poll is one ``docker compose ps``
    call; the deadline belongs to the caller so the same bound covers the roundtrip wait below.
    """
    problems = service_state_problems(model, parse_ps(compose_output(prefix, "ps", "--format", "json")))
    while problems and time.monotonic() < deadline:
        time.sleep(STATE_POLL_SECONDS)
        problems = service_state_problems(model, parse_ps(compose_output(prefix, "ps", "--format", "json")))
    return problems


def validate_runtime(model: dict) -> tuple:
    """Return (front-door HTTP URL, ingest token) after checking the resolved model.

    The token is read from the host file the front door mounts, and it is compared against the
    *contents* of the store receiver's file rather than against a path: two different paths holding
    one value would be one credential used for two roles, which is the thing the comparison is for.
    """
    services = model["services"]
    for name, service in services.items():
        if not DIGEST.fullmatch(service.get("image", "")):
            raise ValueError(f"{name}: resolve image to a digest before runtime conformance")
        for port in service.get("ports", []):
            if port.get("host_ip") != "127.0.0.1":
                raise ValueError(f"{name}: smoke supports loopback-only demo publication")
    token = secret_credential(model, "lo-front-door", "LO_INGEST_TOKEN_FILE")
    store = secret_credential(model, "lo-front-door", "LO_STORE_TOKEN_FILE")
    jwt = services["signoz"]["environment"]["SIGNOZ_TOKENIZER_JWT_SECRET"]
    if len(token) < 24 or len(jwt) < 24 or token == jwt:
        raise ValueError("use separate generated ingest and JWT credentials (at least 24 characters)")
    if token == store:
        raise ValueError("the ingest credential and the store receiver credential are the same value; "
                         "the front door would then present the token it accepts, so a leaked producer "
                         "credential would also carry the store's receiver secret")
    ports = services["lo-front-door"]["ports"]
    port = next(p["published"] for p in ports if int(p["target"]) == 4318)
    return f"http://127.0.0.1:{port}", token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def post(url, payload, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, json.dumps(payload).encode(), headers, method="POST")
    # A loopback conformance call must not leak its bearer through an HTTP proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def require_rejected(status):
    if status not in (401, 403):
        raise ValueError(f"expected authentication rejection, got HTTP {status}")


def require_accepted(status, body):
    if status != 200:
        raise ValueError(f"authenticated OTLP returned HTTP {status}")
    response = json.loads(body or b"{}")
    if response.get("partialSuccess"):
        raise ValueError("OTLP reported partial success; inspect private collector logs")


def payloads(run_id):
    now = time.time_ns()
    resource = {"attributes": [
        {"key": "service.name", "value": {"stringValue": "local-observe-conformance"}},
        {"key": "host.name", "value": {"stringValue": "probe-1"}},
        {"key": "resource_id", "value": {"stringValue": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"}},
    ]}
    metric_name = f"lo_conformance_{run_id}"
    log_body = f"local-observe-conformance:{run_id}"
    trace_id = uuid.uuid4().hex
    metrics = {"resourceMetrics": [{"resource": resource, "scopeMetrics": [{"metrics": [
        {"name": metric_name, "gauge": {"dataPoints": [{"timeUnixNano": str(now), "asDouble": 1.0}]}}
    ]}]}]}
    logs = {"resourceLogs": [{"resource": resource, "scopeLogs": [{"logRecords": [
        {"timeUnixNano": str(now), "severityNumber": 9, "severityText": "INFO",
         "body": {"stringValue": log_body}}
    ]}]}]}
    traces = {"resourceSpans": [{"resource": resource, "scopeSpans": [{"spans": [
        {"traceId": trace_id, "spanId": uuid.uuid4().hex[:16], "name": "conformance",
         "kind": 1, "startTimeUnixNano": str(now), "endTimeUnixNano": str(now + 1000000)}
    ]}]}]}
    queries = {
        "metrics": f"SELECT count() FROM signoz_metrics.distributed_samples_v4 WHERE metric_name = '{metric_name}'",
        "logs": f"SELECT count() FROM signoz_logs.distributed_logs_v2 WHERE body = '{log_body}'",
        "traces": f"SELECT count() FROM signoz_traces.distributed_signoz_index_v3 WHERE trace_id = '{trace_id}'",
    }
    return {"metrics": metrics, "logs": logs, "traces": traces}, queries


def parse_args(argv=None) -> argparse.Namespace:
    """Parse and validate the command line; every failure is an argparse exit, never a partial run.

    ``--compose`` selects which example to drive and defaults to the demo, so the recorded conformance
    commands need no change. The path is resolved against this checkout and refused outside it: the
    script posts telemetry and reads stored rows, so it must not be pointed at an arbitrary tree
    (and ``--project`` above keeps it off a project that is not a rehearsal).
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--compose", type=Path, default=Path(DEFAULT_COMPOSE),
                        help=f"example Compose file to drive, relative to the checkout "
                             f"(default: {DEFAULT_COMPOSE})")
    parser.add_argument("--project", default="local-observe-demo")
    parser.add_argument("--wait-seconds", type=int, default=120)
    parser.add_argument("--preflight", action="store_true", help="validate resolved Compose inputs without injecting data")
    args = parser.parse_args(argv)
    if not PROJECT_NAME.fullmatch(args.project):
        parser.error("project must be local-observe-demo(-<suffix>) or local-observe-full(-<suffix>): "
                     "this script posts telemetry, so it only runs against an isolated rehearsal project")
    if not 1 <= args.wait_seconds <= 600:
        parser.error("wait-seconds must be between 1 and 600")
    compose = (args.compose if args.compose.is_absolute() else ROOT / args.compose).resolve()
    if not compose.is_relative_to(ROOT.resolve()):
        parser.error(f"--compose must be inside the checkout: {compose}")
    if not compose.is_file():
        parser.error(f"--compose names no Compose file: {compose}")
    args.compose = compose
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    if not shutil.which("docker"):
        print(json.dumps({"preflight" if args.preflight else "smoke": "not-run", "reason": "Docker CLI unavailable"}))
        return 2
    prefix = ["docker", "compose", "--env-file", str(args.env_file.resolve()),
              "--project-name", args.project, "-f", str(args.compose)]
    example = args.compose.relative_to(ROOT.resolve()).as_posix()
    report = {"smoke": "fail", "checks": {}, "full_conformance": "not-run", "compose": example,
              "scope": (f"authentication, service state and one synthetic signal of each type into an "
                        f"already-running isolated project on this host, driven by {example}; component "
                        "validation, backup and restore are not-run")}
    try:
        model = json.loads(compose_output(prefix, "config", "--format", "json"))
        url, token = validate_runtime(model)
        if args.preflight:
            print(json.dumps({"preflight": "pass", "smoke": "not-run", "full_conformance": "not-run",
                              "compose": example,
                              "scope": "resolved Compose inputs only; nothing was started and no telemetry injected"}))
            return 0
        problems = wait_for_services(prefix, model, time.monotonic() + args.wait_seconds)
        if problems:
            raise ValueError("services are not all in their promised state: " + "; ".join(problems))
        report["checks"]["service_state"] = "pass"
        samples, queries = payloads(uuid.uuid4().hex)
        for signal in samples:
            for credential in (None, "invalid-conformance-token"):
                status, _ = post(f"{url}/v1/{signal}", {}, credential)
                require_rejected(status)
            report["checks"][f"{signal}_auth"] = "pass"
            require_accepted(*post(f"{url}/v1/{signal}", samples[signal], token))
        pending = set(queries)
        deadline = time.monotonic() + args.wait_seconds
        while pending and time.monotonic() < deadline:
            for signal in sorted(pending):
                output = compose_output(prefix, "exec", "-T", "clickhouse", "clickhouse-client",
                                        "--query", queries[signal] + " SETTINGS max_execution_time=10 FORMAT TabSeparated")
                if int(output.strip()) > 0:
                    report["checks"][f"{signal}_roundtrip"] = "pass"
                    pending.remove(signal)
            if pending:
                time.sleep(2)
        if pending:
            raise ValueError("missing stored signals: " + ", ".join(sorted(pending)))
        report["smoke"] = "pass"
    except (ValueError, KeyError, StopIteration, OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        report["reason"] = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
    print(json.dumps(report, indent=2))
    return 0 if report["smoke"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())

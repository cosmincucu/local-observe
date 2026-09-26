"""Check the prepared foundation without starting or modifying any containers."""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
IMAGE_VARIABLE = re.compile(r"^\$\{LO_[A-Z_]+_IMAGE:\?.+\}$")
# Synthetic deployment markers exercise exact privacy allowances. Real identifying
# values belong in an external policy passed to check_public_tree.py, never in source.
BANNED_TOKENS = ("example-site", "private-address-marker", "example-operator", "/srv/observe", "docker.sock",
                 "storage-host", "worker-host", "notification-bot", "openbao", "deployment-config", "admin-host")
SCANNED_SUFFIXES = (".yaml", ".xml", ".md", ".json", ".py", ".ps1", ".sh", ".cjs", ".txt")
# The only trees a privacy allowance may aim at (#286). `components/` and `examples/` hold no
# exception of any kind and `scripts/` is waived only by its enumerated debt register below.
ALLOWANCE_TREES = ("local_observe/", "tests/")
# Any of these identifies a service as a platform process rather than a data component.
PLATFORM_MARKERS = ("LO_PLATFORM_CREDENTIALS", "LO_PLATFORM_CREDENTIALS_JSON", "LO_STATE_PATH")
SAFE_NOTIFICATION_MODE = re.compile(r"^\$\{LO_NOTIFICATION_MODE:-(recording|off)\}$")
# Example deployments the static checks below walk. Each one is a composition of component
# manifests, so scanning every entry keeps every shipped manifest covered by check_model.
EXAMPLE_MANIFESTS = ("examples/demo/compose.yaml", "examples/full/compose.yaml",
                     "examples/platform/compose.yaml")
# Services an operator reaches from the host: the store UI, the ingest front door, and the
# control-plane consoles (role API + operator UI, the inventory reader, the job engine, the Healthchecks
# console, the Homepage portal and — since MCP component — the MCP tool surface). Every other service that
# publishes a host port is a defect, so adding a name here widens the exposed surface and should be
# argued in the change that does it.
# `healthchecks` joined in job observe standard on exactly that argument: it is a console a human opens (its checks,
# their deadlines, the read-only API key for the scrape), it authenticates, and no data-path component
# reads it over the host interface.
# `homepage` (operator portal) joins it on the same argument the two UIs already rest on: it is a browser
# surface, so a host port is the whole of its function and a manifest without one deploys a portal
# nobody can open. Both are loopback-only, so the widening is a name on a 127.0.0.1 line and not a
# newly reachable interface; the rule below still refuses any publication not prefixed `127.0.0.1:`,
# homepage publishes no new protocol to other containers (those keep talking to the platform over the
# project network), and anything beyond loopback goes through the TLS and authentication edge recipe in
# components/control/homepage/CONTRACT.md, which this repository ships as a recipe and does not start.
# `mcp` (MCP component) is the fourth name and the first that is not a human-facing page, so the argument is a
# different one and it is here rather than only in a PR body: an MCP client is a process on ANOTHER
# host — an agent runtime, or a laptop running a client — and no container on the project network can
# reach it, because the deployment's container network is not where the caller lives. Publishing is
# therefore the whole of the service's reachability, exactly as it is for the two UIs, and the
# alternative the reviewer rejected (mounting /mcp on the operator factory so the platform's existing
# loopback port answers both) would put the SDK's session machinery and its 64-KiB request bound in
# the process that owns the operational database, and make "the optional integration failed" (integration validation)
# indistinguishable from "the platform failed". The published line is `127.0.0.1:`-prefixed, so no
# interface newly listens; reaching it from another machine stays the TLS-and-authentication edge
# decision it already was for the portal and the console, and components/control/mcp/CONTRACT.md says
# so in the same words the homepage contract uses.
HOST_PUBLISHED_SERVICES = ("signoz", "lo-front-door", "platform", "inventory", "dagu",
                           "healthchecks", "homepage", "mcp")
# Relative bind sources the product deliberately ships without content. Every other "./" source must
# be a real, committed file, which is what stops a manifest from pointing at a configuration nobody
# wrote. The set has been empty since full example gaps replaced Dagu's `./dags` bind with the operator-supplied
# ${LO_DAGU_DAGS_DIR}: no shipped manifest names a checkout-relative path it does not also commit. The
# name stays because the check below needs an exemption list to be an exemption list at all -- the day
# a new one appears, it appears here with a reason and a reviewer.
UNSHIPPED_CONTENT_SOURCES: frozenset[str] = frozenset()
# Compose replaces these instead of appending to them, so an override file swaps them wholesale.
REPLACED_KEYS = frozenset({"command", "entrypoint", "test"})
# Product credentials must arrive as mounted files. An environment value is readable by anyone who
# can run `docker inspect`, by anyone who can read /proc/<pid>/environ of a process in the
# container, and by every child that process spawns -- so the environment may carry the PATH of a
# credential (a variable ending in _FILE, or a literal mount path) and never the value. The rule
# covers the product's own names, whether they appear as an `environment:` key or as the variable a
# value interpolates. Third-party names are outside it: this gate cannot claim anything about an
# image it does not build, and `signoz` still takes its session secret
# (SIGNOZ_TOKENIZER_JWT_SECRET, components/data/store-signoz/compose.yaml) as an environment value.
CREDENTIAL_NAME = re.compile(r"_(TOKEN|PASSWORD|SECRET)$")
PRODUCT_VARIABLE = re.compile(r"^LO_[A-Z0-9_]+$")
INTERPOLATED_VARIABLE = re.compile(r"\$\{([A-Za-z][A-Za-z0-9_]*)(?::[^}]*)?\}")
SECRET_MOUNT_PREFIX = "/run/secrets/"
# (service, variable) pairs that keep a credential in the environment, each with the one-sentence
# reason it earns the exception. Adding a name without a reason is an error, and an empty reason is
# an error too: an exception must say why, or it outlives the reason and becomes the norm.
CREDENTIAL_ENV_EXCEPTIONS: dict[tuple[str, str], str] = {}
# Exact allowances document tokens used by guards rather than deployment bindings.
GUARD_DEBT = "the token is what this code refuses or checks for, not a deployment dependency"
# The gate's own file carries every token by definition -- it holds the ban list -- so it is skipped by
# name rather than registered: a waiver there would need editing every time the list changed.
GATE_OWN_FILE = "scripts/check_foundation.py"
SCRIPTS_PRIVACY_DEBT: dict[str, tuple[str, tuple[str, ...]]] = {
    "scripts/_lib/guards.py": (GUARD_DEBT, ("docker.sock",)),
}
# Exact path/token allowances for `local_observe/` and `tests/` (#286): the shipped trees are held to
# the ban with no register, so the only widening available here is one entry per file, carrying a
# reason and the exact tokens measured in that file. They never exempt a directory, a pattern or an
# undeclared token, and a file that stops naming its token retires its entry -- the same five rules
# SCRIPTS_PRIVACY_DEBT reads, one sentence each under tests/. The one hit that is not a test input is
# the rootless-socket validator: `/run/user/<uid>/docker.sock` is a generic Linux path, not topology.
PRIVACY_ALLOWANCES: dict[str, tuple[str, tuple[str, ...]]] = {
    "local_observe/inventory/docker_provider.py": (
        "validates the generic rootless /run/user/<uid>/ socket, not an estate daemon",
        ("docker.sock",)),
    "tests/test_catalog_manifest.py": ("rejects an estate-specific capability name", ("worker-host",)),
    "tests/test_discovery_providers.py": ("rootless daemon observation fixtures", ("docker.sock",)),
    "tests/test_foundation_checks.py": (
        "privacy scanner refusal and exact-allowance regression inputs",
        ("example-site", "/srv/observe", "storage-host", "deployment-config", "admin-host", "docker.sock")),
    "tests/test_inventory_integrations.py": (
        "rootless acceptance and rootful refusal fixtures", ("docker.sock",)),
    "tests/test_migration.py": ("legacy tool-set extraction fixture", ("openbao",)),
    "tests/test_migration_layout.py": (
        "asserts the migration target omits a private repository name", ("deployment-config",)),
    "tests/test_pathcheck.py": (
        "asserts path-monitoring outputs contain no estate identifiers",
        ("private-address-marker", "example-site", "storage-host", "worker-host", "admin-host", "openbao", "example-operator")),
    "tests/test_platform_tools.py": (
        "asserts public tool output contains no estate identifiers",
        ("example-site", "private-address-marker", "storage-host", "worker-host", "notification-bot", "openbao", "deployment-config", "admin-host",
         "/srv/observe", "example-operator")),
    "tests/test_query_adapter.py": (
        "asserts generic query output contains no estate identifiers",
        ("private-address-marker", "storage-host", "worker-host", "deployment-config", "openbao", "example-operator", "/srv/observe", "example-site")),
    "tests/test_scripts_lib.py": ("rootless daemon environment guard fixtures", ("docker.sock",)),
    "tests/test_security_store.py": (
        "asserts security storage output contains no estate identifiers",
        ("private-address-marker", "storage-host", "worker-host", "example-site", "openbao", "deployment-config", "example-operator", "/srv/observe",
         "notification-bot", "admin-host")),
    "tests/test_store_facade.py": (
        "asserts store results contain no estate identifiers",
        ("private-address-marker", "storage-host", "worker-host", "example-site", "openbao", "deployment-config", "example-operator", "/srv/observe",
         "notification-bot", "admin-host")),
}
#: Services whose collector configuration carries a product promise, and which rule reads it. The key
#: is the service name the product ships, because that is the name an operator's overlay patches; a
#: service renamed in an overlay is not anchored, which this gate cannot detect and must not pretend
#: to (stated in docs/RELEASING.md). `check_anchored_collectors` is the only reader of this table.
COLLECTOR_ANCHORS: dict[str, str] = {"lo-front-door": "ingest", "signoz-otel-collector": "store"}


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def read_yaml(path):
    return yaml.load(path.read_text(encoding="utf-8"), Loader=UniqueLoader)


def check_collector(config, name):
    errors = []
    for extension in config.get("service", {}).get("extensions", []):
        if extension not in config.get("extensions", {}):
            errors.append(f"{name}: missing extension {extension}")
    for pipeline, parts in config.get("service", {}).get("pipelines", {}).items():
        for kind in ("receivers", "processors", "exporters"):
            for component in parts.get(kind, []):
                connector = kind in ("receivers", "exporters") and component in config.get("connectors", {})
                if component not in config.get(kind, {}) and not connector:
                    errors.append(f"{name}/{pipeline}: missing {kind} component {component}")
    return errors


def check_ingest(config):
    """The front door must authenticate producers, persist its queue and redact secrets."""
    errors = []
    protocols = config.get("receivers", {}).get("otlp", {}).get("protocols", {})
    for protocol in ("grpc", "http"):
        if protocols.get(protocol, {}).get("auth", {}).get("authenticator") != "bearertokenauth":
            errors.append(f"front door: {protocol} must authenticate")
    token = config.get("extensions", {}).get("bearertokenauth", {}).get("token")
    if "ingest" not in str(token).lower():
        errors.append("front door: bearer credential must be the ingest credential, a distinct secret")
    elif not secret_file_reference(token):
        errors.append("front door: bearer credential must be read from a mounted secret file")
    exporter = config.get("exporters", {}).get("otlp", {})
    if exporter.get("sending_queue", {}).get("storage") != "file_storage":
        errors.append("front door: queue must be persistent")
    for pipeline in config.get("service", {}).get("pipelines", {}).values():
        if "attributes/redact" not in pipeline.get("processors", []):
            errors.append("front door: each signal must use attribute redaction")
    return errors


def check_store(config):
    """The store receiver must authenticate and must bound its own memory before any work."""
    errors = []
    protocols = config.get("receivers", {}).get("otlp", {}).get("protocols", {})
    for protocol in ("grpc", "http"):
        if protocols.get(protocol, {}).get("auth", {}).get("authenticator") != "bearertokenauth":
            errors.append(f"store: {protocol} must authenticate")
    token = config.get("extensions", {}).get("bearertokenauth", {}).get("token")
    if "ingest" in str(token).lower():
        errors.append("store: receiver credential must be a distinct runtime-supplied token")
    elif not secret_file_reference(token):
        errors.append("store: receiver credential must be read from a mounted secret file")
    for pipeline, parts in config.get("service", {}).get("pipelines", {}).items():
        if (parts.get("processors") or [None])[0] != "memory_limiter":
            errors.append(f"store/{pipeline}: memory_limiter must be the first processor")
    return errors


def compose_environment(service):
    """Return a service environment as a mapping, accepting both Compose notations."""
    environment = service.get("environment", {})
    if isinstance(environment, list):
        return dict(item.split("=", 1) for item in environment)
    return dict(environment)


def secret_file_reference(value):
    """Whether a collector value reads a credential through confmap's `file` provider."""
    return isinstance(value, str) and bool(re.fullmatch(r"\$\{file:/run/secrets/[a-z0-9-]+\}", value))


def declared_secret_names(service):
    """The secret names one service mounts, accepting both the short and the long Compose syntax."""
    names = []
    for entry in service.get("secrets") or []:
        names.append(entry if isinstance(entry, str) else str(entry.get("source", "")))
    return names


def check_credential_files(model, exceptions=None):
    """Every product credential in a Compose model must be a mounted file, and every mount declared.

    A credential is a product variable -- one named `LO_...` -- whose name ends in `_TOKEN`,
    `_PASSWORD` or `_SECRET`: here as a service `environment:` key, or as the variable an
    `environment:` value interpolates. Both forms put the secret itself into the container
    environment, which is readable through `docker inspect` and `/proc/<pid>/environ`; the fix is a
    `*_FILE` variable naming a mount under `/run/secrets/`, which this function also requires to be a
    secret the manifest actually declares. `exceptions` exists for tests to exercise the rule without
    editing the shipped list.
    """
    errors = []
    allowed = CREDENTIAL_ENV_EXCEPTIONS if exceptions is None else exceptions
    for (service_name, variable), reason in sorted(allowed.items()):
        if not str(reason).strip():
            errors.append(f"{service_name}/{variable}: an environment credential exception must "
                          f"state its reason in one sentence")
    # An exception with no reason is not an exception: it exempts nothing, so the credential defect
    # below is still reported. A malformed waiver must never be the quieter of the two errors.
    waiving = {key for key, reason in allowed.items() if str(reason).strip()}
    for service_name, service in model.get("services", {}).items():
        for variable, value in sorted(compose_environment(service).items()):
            names = ([variable] if PRODUCT_VARIABLE.fullmatch(variable) else [])
            names += [match.group(1) for match in INTERPOLATED_VARIABLE.finditer(str(value))
                      if PRODUCT_VARIABLE.fullmatch(match.group(1))]
            for name in dict.fromkeys(names):
                if CREDENTIAL_NAME.search(name) and (service_name, name) not in waiving:
                    errors.append(f"{service_name}: {name} puts a credential in the container "
                                  f"environment; mount it as a file and pass its path in a "
                                  f"*_FILE variable")
        mounted = declared_secret_names(service)
        declared = (model.get("secrets") or {}).keys()
        for variable, value in sorted(compose_environment(service).items()):
            text = str(value)
            if not text.startswith(SECRET_MOUNT_PREFIX):
                continue
            secret = text[len(SECRET_MOUNT_PREFIX):].rstrip("/")
            if "/" in secret:
                errors.append(f"{service_name}: {variable} names a nested path under {SECRET_MOUNT_PREFIX}, "
                              f"which Compose does not create for a secret")
            elif secret not in mounted:
                errors.append(f"{service_name}: {variable} reads {text}, which the service does not mount "
                              f"(add it to the service's `secrets:` list)")
            elif secret not in declared:
                errors.append(f"{service_name}: {variable} reads {text}, but the manifest declares no "
                              f"top-level `secrets:` entry named {secret}")
    return errors


def anchored_collector_configs(model, directory):
    """The collector configuration files each anchored service mounts, resolved against `directory`.

    Two Compose shapes carry one today, and both resolve against the directory the include entry
    sets, which is where Compose resolves them too:

    * **a read-only bind of a checkout-relative YAML** (the front door; measured at
      `components/data/front-door/compose.yaml:29`, one volume entry spelled
      `./collector.yaml:/etc/otelcol-contrib/config.yaml:ro`): for each string entry of the
      service's `volumes:` the candidate is the part before the first `:`, admitted when it starts
      with `./` and ends with `.yaml`; and
    * **a service `configs:` list naming a top-level `configs:` entry** (the store; measured at
      `components/data/store-signoz/compose.yaml:204-206` for the service half -- `configs:` /
      `- source: signoz-otelcol-config` / `target: /etc/otel-collector-config.yaml` -- and
      `:244-245` for the top-level half -- `signoz-otelcol-config:` / `file: ./collector.yaml`): the
      service names an *entry*, not a file, so each item (a string in Compose's short form,
      otherwise the `source` of a mapping) is looked up in the merged model's top-level `configs:`
      mapping, and an entry carrying `file:` yields `directory / file`.

    Joining those two blocks is the whole of the second rule: a resolver reading only the top-level
    block finds a file for a service that never mounted it, and one reading only the service block
    finds nothing at all. Returns `{service name: [candidate Path, ...]}` for every anchored service
    the model declares -- an anchored service with no candidate is reported empty, never omitted, so
    the caller can refuse it.
    """
    directory = Path(directory)
    declared = model.get("configs") or {}
    found: dict[str, list[Path]] = {}
    for name, service in model.get("services", {}).items():
        if name not in COLLECTOR_ANCHORS:
            continue
        service = service or {}
        candidates: list[Path] = []
        for mount in service.get("volumes") or []:
            if not isinstance(mount, str):
                continue
            source = mount.split(":", 1)[0]
            if source.startswith("./") and source.endswith(".yaml"):
                candidates.append(directory / source)
        for item in service.get("configs") or []:
            source = item if isinstance(item, str) else (item or {}).get("source")
            entry = declared.get(source) if isinstance(source, str) else None
            if isinstance(entry, dict) and isinstance(entry.get("file"), str):
                candidates.append(directory / entry["file"])
        found[name] = candidates
    return found


def check_anchored_collectors(model, directory):
    """Run the ingest/store rules over what the merged model mounts, not over a fixed path.

    `check_foundation`'s three fixed reads only ever see the shipped tree, so an operator overlay
    that re-points a collector at a configuration which drops the bearer authentication passed the
    merged-model gate. This reads each anchored service present in `model` (see
    `COLLECTOR_ANCHORS`) from the model being gated instead.

    Fail closed: an anchored service whose candidate paths are all unreadable is refused with one
    line, because the gate cannot promise authentication for a configuration it cannot open. Each
    error a readable candidate raises is prefixed with that resolved file path, so two files
    breaking the same rule stay two lines and `check_foundation`'s final de-duplication cannot merge
    them into one. The limitation is the anchor's own: it matches the service name the product
    ships, so a service renamed in an overlay is silently not anchored.
    """
    errors: list[str] = []
    readers = {"ingest": check_ingest, "store": check_store}
    for name, candidates in anchored_collector_configs(model, directory).items():
        rule = COLLECTOR_ANCHORS[name]
        reader = readers[rule]      # a register naming a rule this function does not know is a bug
        readable = [path for path in candidates if path.is_file()]
        if not readable:
            named = (", ".join(str(path) for path in candidates)
                     or "the service names no ./<file>.yaml bind and no top-level configs entry")
            errors.append(f"{name}: its {rule} collector configuration is unreadable ({named}); the "
                          f"gate refuses to promise a rule it could not open")
            continue
        for path in readable:
            resolved = path.resolve()
            errors.extend(f"{resolved}: {error}" for error in reader(read_yaml(path)))
    return errors


def check_delivery(model):
    """A platform manifest must state a non-sending delivery default and keep credentials out of env."""
    errors = []
    for name, service in model.get("services", {}).items():
        environment = compose_environment(service)
        if not any(marker in environment for marker in PLATFORM_MARKERS):
            continue
        if "LO_PLATFORM_CREDENTIALS_JSON" in environment:
            errors.append(f"{name}: role credentials must be a mounted file, never an environment value")
        if environment.get("LO_PLATFORM_CREDENTIALS") != "/run/secrets/platform-credentials":
            errors.append(f"{name}: role credentials must be read from the mounted secret path")
        if not SAFE_NOTIFICATION_MODE.fullmatch(environment.get("LO_NOTIFICATION_MODE", "")):
            errors.append(f"{name}: notification mode must default to a non-sending mode (recording or off)")
    return errors


def privacy_leak(relative, hits):
    """One leak report, shared by the unregistered and the un-waived case so both read the same way.

    The register the message names is the one that can answer for that tree: `scripts/` owes an entry
    in `SCRIPTS_PRIVACY_DEBT`, `local_observe/` and `tests/` owe an exact entry in
    `PRIVACY_ALLOWANCES`, and `components/`/`examples/` owe a rewrite -- they hold no exception.
    """
    if relative.startswith("scripts/"):
        remedy = ("scripts/ may name the estate only behind a SCRIPTS_PRIVACY_DEBT entry that states "
                  "its reason")
    elif relative.startswith(ALLOWANCE_TREES):
        remedy = ("local_observe/ and tests/ may name it only behind a PRIVACY_ALLOWANCES entry "
                  "stating that exact path and those exact tokens")
    else:
        remedy = "shipped components and examples name none of these at all, in any casing"
    return f"{relative}: private or forbidden deployment dependency ({', '.join(hits)}); {remedy}"


def allowance_shape_errors(relative, reason, tokens):
    """Every way one `PRIVACY_ALLOWANCES` entry fails on its own terms; empty when it may be honoured.

    An entry that fails here waives nothing at all — the file it named is still reported as a leak —
    so a mistyped path, a blank reason or a near-miss token is loud in both directions.
    """
    errors = []
    if not str(reason).strip():
        errors.append(f"{relative}: a privacy allowance must state its reason")
    if not relative.startswith(ALLOWANCE_TREES) or ".." in Path(relative).parts:
        errors.append(f"{relative}: privacy allowances require an exact source or test path")
    if not tokens or any(token not in BANNED_TOKENS for token in tokens):
        errors.append(f"{relative}: privacy allowances require exact banned tokens")
    return errors


def check_private_references(root, register=None, allowances=None):
    """Reject estate identifiers case-insensitively in product, component, example, script and test trees.

    `components/` and `examples/` are held to the rule with no exception: nothing they name may be a
    live host, a private path or one estate's service name. `scripts/` is walked behind `register`
    (default: the shipped `SCRIPTS_PRIVACY_DEBT`), an enumerated register of measured debt, so a new
    estate token there fails the gate instead of joining the pile. Five rules, each one's own failure:
    (1) a hit with no entry; (2) a hit on a token the entry does not tolerate; (3) an entry tolerating
    a token its file no longer names; (4) an entry naming a path that does not exist; (5) an entry with
    no reason, which waives nothing -- so rule 1 fires for that file too. Rules 3 and 4 are raised only
    for the checkout this script lives in: against another root (`--root`, release contract) the shipped register
    describes this tree, not that one, and a stale-entry error there would be a false failure. Rules 1
    and 2 -- the ones that catch a leak -- apply to every root. A base directory the root does not have
    is skipped: a fixture checkout holding only `components/` is not a privacy defect.

    `local_observe/` and `tests/` joined the walk in #286 behind `allowances` (default: the shipped
    `PRIVACY_ALLOWANCES`), which reads the same five rules and adds nothing to them: the entries are
    functional guards and deliberate refusal fixtures, never a directory, and matching is case-folded
    everywhere because the export tool has always matched case-insensitively. Rules 3 and 4 for these
    trees fire whenever `allowances` is supplied (a fixture's own entries) or the root is this one.
    """
    root = Path(root)
    errors = []
    entries = SCRIPTS_PRIVACY_DEBT if register is None else register
    permitted = PRIVACY_ALLOWANCES if allowances is None else allowances
    allowed = {}
    for relative, (reason, tokens) in sorted(permitted.items()):
        failures = allowance_shape_errors(relative, reason, tokens)
        errors.extend(failures)
        if not failures:
            allowed[relative] = tokens
    for relative, (reason, _tokens) in sorted(entries.items()):
        if not str(reason).strip():
            errors.append(f"{relative}: a privacy debt entry must state its reason in one sentence")
    waiving = {relative: tokens for relative, (reason, tokens) in entries.items() if str(reason).strip()}
    for base in (root / "components", root / "examples", root / "scripts",
                 root / "local_observe", root / "tests"):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in SCANNED_SUFFIXES:
                continue
            relative = path.relative_to(root).as_posix()
            body = path.read_text(encoding="utf-8").casefold()
            hits = [token for token in BANNED_TOKENS if token in body]
            if not relative.startswith("scripts/"):
                untolerated = [token for token in hits if token not in allowed.get(relative, ())]
                if untolerated:
                    errors.append(privacy_leak(relative, untolerated))
            elif relative != GATE_OWN_FILE:
                if relative not in waiving:
                    if hits:
                        errors.append(privacy_leak(relative, hits))
                    continue
                untolerated = [token for token in hits if token not in waiving[relative]]
                if untolerated:
                    errors.append(f"{relative}: names {', '.join(untolerated)}, which its "
                                  f"SCRIPTS_PRIVACY_DEBT entry does not tolerate")
    if root.resolve() == ROOT.resolve():
        for relative, (reason, tokens) in sorted(entries.items()):
            if relative == GATE_OWN_FILE:
                continue
            path = root/relative
            if not path.is_file():
                errors.append(f"{relative}: SCRIPTS_PRIVACY_DEBT waives a path that does not exist in "
                              f"this checkout; stale waiver, delete it")
                continue
            body = path.read_text(encoding="utf-8").casefold()
            stale = [token for token in tokens if token not in body]
            if stale:
                errors.append(f"{relative}: SCRIPTS_PRIVACY_DEBT tolerates {', '.join(stale)}, which that "
                              f"file no longer names; stale waiver, delete it")
    # Default allowances belong to this checkout. Explicit fixtures still exercise
    # missing-path and stale-token checks without pretending to be the shipped root.
    if root.resolve() == ROOT.resolve() or allowances is not None:
        for relative, tokens in sorted(allowed.items()):
            path = root / relative
            if not path.is_file():
                errors.append(f"{relative}: privacy allowance path does not exist; stale waiver, delete it")
                continue
            body = path.read_text(encoding="utf-8").casefold()
            stale = [token for token in tokens if token not in body]
            if stale:
                errors.append(f"{relative}: privacy allowance names absent tokens {', '.join(stale)}; "
                              "stale waiver, delete it")
    return errors


def check_baseline_inputs(root):
    """Keep private baseline inputs outside the product tree.

    `migration/estate/` and `baseline*.json` under `migration/` describe installation-specific
    hosts, tiles and dashboards. Scripts read those files from
    `LO_MIGRATION_BASELINE_DIR` (or `--baseline-dir`) instead, so nothing here needs them and a copy
    in this checkout would ship a private topology to strangers. One error is reported per offending
    subtree, never one per file inside it, and paths stay relative to the root this was given so a
    test fixture in a temporary directory is refused exactly like the real checkout.
    """
    tree = root / "migration"
    if not tree.exists():
        return []
    private = [path for path in sorted(tree.rglob("*"))
               if path.relative_to(tree).as_posix().split("/")[0] == "estate"
               or (path.is_file() and path.match("baseline*.json"))]
    named = [path for path in private if not any(other is not path and other in path.parents for other in private)]
    return [f"migration/{path.relative_to(tree).as_posix()}: private preparation input belongs in the "
            f"operator's repository, not this checkout (decision deployment separation); scripts read it from "
            f"LO_MIGRATION_BASELINE_DIR or --baseline-dir" for path in named]


def checkout_relative(path):
    """Return a checkout-relative POSIX path, or None when the path lies outside the checkout."""
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return None


def merge_models(base, override):
    """Merge two Compose models the way Compose merges a list of files for one `include` entry.

    Mappings merge key by key, sequences append, and the keys in REPLACED_KEYS (shell commands and
    a healthcheck test) are replaced by the later file rather than appended to it.
    """
    merged = dict(base)
    for key, value in (override or {}).items():
        current = merged.get(key)
        if isinstance(value, dict) and isinstance(current, dict):
            merged[key] = merge_models(current, value)
        elif isinstance(value, list) and isinstance(current, list) and key not in REPLACED_KEYS:
            merged[key] = current + value
        else:
            merged[key] = value
    return merged


def include_entry(entry, base):
    """Return (files, directory) for one `include` entry: the short syntax names one file, the long
    syntax may name several that merge into a single model, with an optional project directory.

    The directory is where relative paths inside those files resolve: Compose uses the included
    file's own directory, not the example's, unless `project_directory` says otherwise.
    """
    if isinstance(entry, str):
        path = base / entry
        return [path], path.parent
    if isinstance(entry, dict) and entry.get("path"):
        paths = entry["path"]
        files = [base / item for item in ([paths] if isinstance(paths, str) else paths)]
        return files, (base / entry["project_directory"]) if entry.get("project_directory") else files[0].parent
    return [], base


def loaded_includes(root, example, errors):
    """Yield (files, directory, model) for each `include` entry of an example, appending load errors.

    An entry that names several files merges them into one model, which is how an override file --
    the operator command override, for instance -- is applied to the component it patched, without
    that component's manifest being duplicated in the example.

    Containment (overlay gate rules): an included file is admitted when it resolves inside the product checkout
    (`root`, the pinned release) **or** inside the directory of the model being gated
    (`example.parent`, the operator's own composition directory). Both trees are resolved before the
    prefix test, and so is the candidate, which is what catches a path walked out through `..`:
    `../../elsewhere/thing.overlay.yaml` spelled from inside the model's directory lands outside
    both, and is refused. The second tree is what makes the shape `docs/OPERATOR-MODEL.md` section 2
    recommends gateable at all -- one entry listing the pinned component manifest plus
    `./overlay.yaml` beside the operator's top-level file, and that overlay is outside `--root` by
    definition. The widening is unconditional; it does not look at `--compose`, because for every
    shipped example `example.parent` already sits inside the checkout, so the default run walks
    exactly the files it walked before (pinned by `tests/test_foundation_checks.py`).

    What that honestly gives up: an operator may now merge a manifest of their own beside the pinned
    one, so the merged model is no longer guaranteed to be only pinned bytes. Accepted because every
    model rule still runs over the merged result -- an overlay cannot hide a service from
    `check_model`, `check_delivery` or `check_anchored_collectors` -- and tying a release's images to
    these checkout bytes is `scripts/operator/pin_check.py`'s job, not this walk's.
    """
    base = example.parent
    admitted = (root.resolve(), base.resolve())
    for entry in read_yaml(example).get("include") or []:
        files, directory = include_entry(entry, base)
        if not files:
            errors.append(f"{example.name}: unsupported or empty include entry {entry!r}")
            continue
        model: dict = {}
        for path in files:
            resolved = path.resolve()
            if not any(resolved.is_relative_to(tree) for tree in admitted):
                errors.append(f"component include escapes both the product checkout and the model's "
                              f"own directory: {resolved} lies under neither {admitted[0]} nor "
                              f"{admitted[1]}")
                continue
            if not resolved.is_file():
                errors.append(f"included Compose file is missing: {resolved}")
                continue
            model = merge_models(model, read_yaml(resolved))
        yield files, directory, model


def example_services(root, example):
    """Return (services, errors): every service an example resolves to, and any structural error."""
    errors: list[str] = []
    own = read_yaml(example).get("services") or {}
    services: dict = {}
    for _files, _directory, model in loaded_includes(root, example, errors):
        for name, service in model.get("services", {}).items():
            if name in services:
                errors.append(f"duplicate service across includes: {name}")
            services[name] = service
    for name in own:
        if name in services:
            errors.append(f"{name}: declared by the example and also included; include does not merge")
    services.update(own)
    return services, errors


def check_example(root, example):
    """Check one example deployment: every component manifest it includes, plus its own services.

    The two product promises that ride on a Compose model -- the delivery default (`check_delivery`)
    and the anchored collector rules (`check_anchored_collectors`) -- are read out of every model this
    walk opens: the top-level file's own services and each merged `include`, not only the fixed files
    under `root` that `check_foundation` reads on the default run.
    """
    errors: list[str] = []
    own = read_yaml(example)
    errors.extend(check_model(own, example.parent))
    errors.extend(check_delivery(own))
    errors.extend(check_anchored_collectors(own, example.parent))
    for files, directory, model in loaded_includes(root, example, errors):
        errors.extend(check_model(model, directory))
        errors.extend(check_delivery(model))
        errors.extend(check_anchored_collectors(model, directory))
        for path in files:
            component = path.resolve().parent
            collector = component / "collector.yaml"
            if collector.is_file():
                errors.extend(check_collector(read_yaml(collector), component.name))
            # The four lifecycle documents belong to a shipped component, which is a directory under
            # components/. An override fragment an example keeps beside its own compose.yaml
            # (examples/platform/staging.compose.yaml, patched over the platform manifest by
            # examples/platform/compose.yaml) is not a component and owes none of them; it is checked
            # by check_model above like any other included file, so nothing about credentials, images,
            # ports or privacy is relaxed here. The directory is resolved against the root this
            # function was given rather than the module's ROOT, so a fixture checkout in tests means
            # "a shipped component" the same way the real checkout does.
            try:
                relative = component.relative_to(root.resolve()).as_posix()
            except ValueError:
                relative = ""   # outside this checkout, so it ships nothing
            if not relative.startswith("components/"):
                continue
            for required in ("CONTRACT.md", "backup.md", "upgrade.md", "conformance.md"):
                if not (component / required).is_file():
                    errors.append(f"{component.name}: missing {required}")
    services, structural = example_services(root, example)
    errors.extend(structural)
    for name, service in services.items():
        for dependency in service.get("depends_on", {}):
            if dependency not in services:
                errors.append(f"{name}: unresolved service dependency {dependency}")
    return errors


def check_model(model, directory):
    errors = []
    errors.extend(check_credential_files(model))
    for name, service in model.get("services", {}).items():
        if "container_name" in service or "cpuset" in service:
            errors.append(f"{name}: fixed container name/CPU placement is not portable")
        if not IMAGE_VARIABLE.fullmatch(service.get("image", "")):
            errors.append(f"{name}: image must be a required runtime image variable")
        if service.get("privileged") or service.get("network_mode") == "host":
            errors.append(f"{name}: unexpected host privilege/network access")
        for port in service.get("ports", []):
            if not isinstance(port, str) or not port.startswith("127.0.0.1:"):
                errors.append(f"{name}: development publication must be loopback-only")
            if name not in HOST_PUBLISHED_SERVICES:
                errors.append(f"{name}: internal service publishes a host port")
        for mount in service.get("volumes", []):
            if isinstance(mount, str):
                src = mount.split(":", 1)[0]
                if "docker.sock" in mount:
                    errors.append(f"{name}: Docker socket mount is forbidden")
                if src.startswith("./"):
                    target = directory / src
                    if not target.is_file() and checkout_relative(target) not in UNSHIPPED_CONTENT_SOURCES:
                        errors.append(f"{name}: missing configuration {src}")
                    if not mount.endswith(":ro"):
                        errors.append(f"{name}: configuration mount must be read-only")
                elif src.startswith("${"):
                    # A host path the environment supplies. The manifest cannot say what lives
                    # there, so the only thing it can promise is that we do not write to it.
                    if not mount.endswith(":ro"):
                        errors.append(f"{name}: environment-supplied bind mount must be read-only")
                elif src not in model.get("volumes", {}):
                    errors.append(f"{name}: undeclared volume {src}")
            elif mount.get("type") == "bind":
                if not mount.get("read_only") or mount.get("bind", {}).get("create_host_path") is not False:
                    errors.append(f"{name}: bind input must exist and be read-only")
        for mount in service.get("configs", []):
            source = mount if isinstance(mount, str) else mount["source"]
            if source not in model.get("configs", {}):
                errors.append(f"{name}: missing config {source}")
    for name, volume in model.get("volumes", {}).items():
        if volume and any(k in volume for k in ("name", "external", "driver_opts")):
            errors.append(f"{name}: persistence must be project-scoped by default")
    for name, config in model.get("configs", {}).items():
        if "file" in config and not (directory / config["file"]).is_file():
            errors.append(f"{name}: missing config file")
        if "content" in config:
            try:
                ET.fromstring(config["content"])
            except ET.ParseError:
                errors.append(f"{name}: invalid embedded XML")
    return errors


def compose_models(root, compose=None):
    """Which Compose models the gate walks: the examples shipped under `root`, or the files given.

    With no `--compose` the answer is the shipped example list, exactly as before. Given one or more
    files, they *replace* that list rather than adding to it: an operator who names a file is asking
    about that file, and the product's own examples stay policed by the unqualified run of this gate
    on `main` (which is what CI runs). Relative names resolve against the current directory, not
    against `--root`, because the model an operator hands this flag lives in the operator's repository
    while `--root` is the pinned product checkout its `include:` entries reach into.
    """
    root = Path(root)
    if compose is None:
        return [root / relative for relative in EXAMPLE_MANIFESTS]
    models = []
    for item in compose:
        path = Path(item)
        models.append(path if path.is_absolute() else Path.cwd() / path)
    return models


def check_foundation(root=ROOT, compose=None):
    """Run every static rule over `root`, checking the Compose models `compose` names (or the examples).

    `compose` files are checked by the same `check_example` rules as a shipped example, which is what
    makes the flag usable by an operator: their top-level file `include:`s the pinned component
    manifests merged with their own overlays, and `check_example` walks that chain -- merged model,
    image variables, credential mounts, loopback publication, component lifecycle documents. The two
    product promises that a merged model can move are now read out of the model itself, not out of a
    fixed path: `check_delivery` runs over every model this gate walks, and
    `check_anchored_collectors` runs `check_ingest`/`check_store` over the collector configuration
    each anchored service actually mounts, located by service name (`COLLECTOR_ANCHORS`). The three
    fixed reads below therefore run on the default pass only: this checkout's own files stay
    policed even in a shape no example mounts, while under `--compose` a checkout that ships no
    front door is a question about the operator's model, not a crash. What the anchoring cannot
    see, and does not claim to: a service renamed by an overlay is no longer anchored by name.
    """
    root = Path(root)
    errors: list[str] = []
    for example in compose_models(root, compose):
        if not example.is_file():
            errors.append(f"Compose model is missing: {example}")
            continue
        errors.extend(check_example(root, example))
    if compose is None:
        # The default run: the shipped files, anchored by path, exactly as before overlay gate rules. Under
        # --compose these three reads are replaced by the model-anchored ones inside check_example.
        errors.extend(check_ingest(read_yaml(root / "components/data/front-door/collector.yaml")))
        errors.extend(check_store(read_yaml(root / "components/data/store-signoz/collector.yaml")))
        errors.extend(check_delivery(read_yaml(root / "components/control/platform/compose.yaml")))
    for path in (root / "components").rglob("*.xml"):
        ET.parse(path)
    # The prepared deployment must be independent of private estate paths/identifiers.
    errors.extend(check_private_references(root))
    # deployment separation/deployment separation: private baseline inputs left the product tree and must not come back.
    errors.extend(check_baseline_inputs(root))
    # The same manifest can be reached from more than one example; report each defect once.
    return list(dict.fromkeys(errors))


def scope_text(root: Path, compose: list[str] | None) -> str:
    """Name the tree and the Compose models actually walked, so a green report cannot be read as a
    claim about a checkout this run never opened. The default (no arguments) keeps its own wording:
    that string is quoted in the documentation of the plain run and must not drift with this change.
    """
    if root == ROOT and not compose:
        return ("shipped manifests, dashboards and collector configs in this repository: static shape, "
                "ingest protection and privacy rules only; no container was started and no host was read")
    models = (", ".join(str(item) for item in compose) if compose else ", ".join(EXAMPLE_MANIFESTS))
    return (f"shipped manifests, dashboards and collector configs in the checkout {root}; Compose "
            f"models walked: {models}. Static shape, ingest protection and privacy rules only; "
            f"no container was started and no host was read")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--root", type=Path, default=None,
                        help="product checkout to walk; default is the checkout this script lives in")
    parser.add_argument("--compose", action="append", default=None, metavar="FILE",
                        help="check this Compose model instead of the examples shipped under --root; "
                             "repeat per file. The file may live outside --root, and so may each "
                             "`include` it names provided that file sits either inside --root or "
                             "inside this model's own directory (a fragment reached from anywhere "
                             "else fails). "
                             "Pass the operator's own top-level file, NOT the output of "
                             "`docker compose config`: rendering resolves the ${VAR:?} image pins away, "
                             "and the image rule is one of the things this gate exists to check.")
    args = parser.parse_args()
    root = ROOT if args.root is None else Path(args.root).resolve()
    try:
        errors = check_foundation(root, args.compose)
    except (ValueError, KeyError, OSError, yaml.YAMLError, ET.ParseError) as exc:
        errors = [f"configuration check failed: {exc}"]
    report = {"static_checks": "fail" if errors else "pass", "errors": errors,
              "runtime_conformance": "not-run", "component_status": "experimental",
              "scope": scope_text(root, args.compose)}
    summary = "\n".join(errors or ["Static foundation checks passed; runtime conformance not run."])
    print(json.dumps(report, indent=2) if args.json else summary)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

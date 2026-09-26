"""Native isolated Windows collector checks: pinned build, file/CPU/restart, and the opt-in Security
overlay. Copies the executable into a private directory and never touches the installed service.
"""
from __future__ import annotations

import argparse
import collections
from collections.abc import Mapping, Sequence
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
from typing import Any
import uuid

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.require import refuse_optimized, require

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / 'components' / 'data' / 'agent-windows'
BASE_CONFIG = COMPONENT / 'collector.yaml'
OVERLAY_CONFIG = COMPONENT / 'collector-security.yaml'
PIN_FILE = COMPONENT / 'versions.json'
# Phase B replays a whole channel from `beginning`, so the sink must not grow without bound.
# 400 POST bodies is far more than either phase needs and keeps the run's memory bounded.
MAX_STORED_REQUESTS = 400
# The two strings that make a refusal legible: the first is the failure the receiver reports, the
# second is the OS reason that makes it a permission story rather than an unknown one. A collector
# that dies carrying neither is a check failure, not an observation.
SUBSCRIPTION_FAILURE = 'failed to open local subscription'
PERMISSION_DENIED = 'Access is denied'
# The identity this run claims for itself, asserted on every record the Security overlay carries.
# One constant because the two uses sit 120 lines apart, and a mismatch there fails the check with
# "the pipeline is broken" when the real defect is a typo in a hostname.
TEST_HOST_NAME = 'windows-synthetic'


def pinned_release(pin_file: Path = PIN_FILE) -> dict[str, Any]:
    """Read the machine-readable pin for this component and refuse an incomplete one.

    Args:
        pin_file: The component's ``versions.json``.

    Returns:
        The parsed document.

    Raises:
        ValueError: The file is absent, unreadable, not an object, or missing a field this check
            needs. The pin is the only thing that says which upstream binary is acceptable, so a
            half-filled file is treated exactly like a mismatched version.
    """
    require(pin_file.is_file(), 'No machine-readable pin at ' + str(pin_file)
            + '; this component ships no binary, so without it nothing here says what to install')
    try:
        document = json.loads(pin_file.read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise ValueError('Unreadable pin ' + str(pin_file) + ': ' + str(exc)) from exc
    require(isinstance(document, dict), 'Pin ' + str(pin_file) + ' is not a JSON object')
    collector = document.get('collector')
    require(isinstance(collector, dict), 'Pin ' + str(pin_file) + ' names no "collector" object')
    for field in ('version', 'binary_sha256', 'asset'):
        value = collector.get(field)
        require(isinstance(value, str) and value.strip(), 'Pin ' + str(pin_file)
                + ' has no usable collector.' + field)
    require(len(collector['binary_sha256']) == 64, 'Pin ' + str(pin_file)
            + ': collector.binary_sha256 must be a full SHA256, got ' + collector['binary_sha256'])
    return document


def require_pinned_version(version_output: str, pinned: dict[str, Any]) -> None:
    """Refuse a collector whose own ``--version`` output does not report the pinned version.

    Args:
        version_output: Stdout of ``otelcol-contrib.exe --version``.
        pinned: The document from :func:`pinned_release`.

    Raises:
        ValueError: The pinned version string is not in the output.
    """
    version = pinned['collector']['version']
    require(version in version_output,
            'The collector under test is not the pinned version: versions.json pins ' + version
            + ', this executable reports ' + (version_output.strip() or '<nothing>')
            + '. Move the pin in its own commit, with a reason and a rollback line; do not move'
            + ' the binary under it')


def require_pinned_binary(digest: str, pinned: dict[str, Any]) -> None:
    """Refuse a collector executable that is not the bytes the pin names.

    The version string above says what a build claims to be; this says what the file is. An
    unsigned upstream release makes the hash the only claim available, so the two are checked
    separately and both must hold.

    Args:
        digest: SHA256 (lowercase hex) of the executable about to be run.
        pinned: The document from :func:`pinned_release`.

    Raises:
        ValueError: ``digest`` differs from ``collector.binary_sha256``.
    """
    expected = pinned['collector']['binary_sha256']
    require(digest == expected,
            'The executable hashes to ' + digest + ' but versions.json pins ' + expected
            + ' for ' + pinned['collector']['asset'] + '. Refusing to run it: see the provenance'
            + ' recipe in CONTRACT.md, and if the pin itself is what changed, say so in that commit')


def merge_configs(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge two collector documents the way confmap does: maps deep, anything else replaces.

    Used for the isolated phase-B config, which is the shipped merge with one receiver changed.
    The real two-file invocation is exercised separately with ``--config`` twice, so a stranger's
    start line is never validated against an invented merge.

    Args:
        base: The first config location.
        overlay: The second config location, whose scalars and lists win.

    Returns:
        A new document; neither argument is modified.
    """
    if not (isinstance(base, dict) and isinstance(overlay, dict)):
        return overlay
    merged = dict(base)
    for key, value in overlay.items():
        merged[key] = merge_configs(base[key], value) if key in base else value
    return merged


def sha256_file(path: Path) -> str:
    """Return the lowercase hex SHA256 of a file, read whole (collector binaries are a few hundred MB)."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def security_records(requests: list[tuple[str, dict[str, Any]]], channel: str, resource: str) -> int:
    """Count delivered log records that came from ``channel`` and carry this run's identity.

    A Windows event record has a structured body (the overlay sets ``raw: false``), so it is
    recognised by its ``channel`` key; the file-log records in the same run have string bodies and
    cannot be mistaken for it. Identity is checked on the resource attributes, not assumed.

    Args:
        requests: ``(path, document)`` pairs received on loopback during this run.
        channel: The channel the isolated security receiver was configured to read.
        resource: The ``resource_id`` UUID generated for this run.

    Returns:
        The number of matching records; 0 means the overlay carried nothing.
    """
    matches = 0
    for _path, body in requests:
        for resource_logs in body.get('resourceLogs', []):
            attrs = {a['key']: a['value'].get('stringValue')
                     for a in resource_logs.get('resource', {}).get('attributes', [])}
            if attrs.get('resource_id') != resource or attrs.get('host.name') != TEST_HOST_NAME:
                continue
            for scope in resource_logs.get('scopeLogs', []):
                for record in scope.get('logRecords', []):
                    values = record.get('body', {}).get('kvlistValue', {}).get('values', [])
                    if any(v.get('key') == 'channel' and v.get('value', {}).get('stringValue') == channel
                           for v in values):
                        matches += 1
    return matches


def run_validation(executable: Path, config_paths: list[Path], environment: Mapping[str, str],
                   destination: Path) -> None:
    """Run ``validate`` over these config locations and refuse if the pinned build refuses them.

    ``validate`` checks the shape of the configuration -- every option name, every component type.
    It cannot see a permission failure, which only appears when a receiver opens its channel, so a
    passing validation is never evidence that the Security channel is readable.

    Args:
        executable: The copied collector.
        config_paths: One or more ``--config`` locations, in merge order.
        environment: The ``LO_*`` environment for this isolated run.
        destination: Where to keep the collector's own output for review.
    """
    command = [str(executable), 'validate'] + [arg for path in config_paths for arg in ('--config', str(path))]
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=60)
    destination.write_text(result.stdout + result.stderr)
    require(result.returncode == 0, 'The collector refused this configuration: '
            + (result.stdout + result.stderr).strip()[:600])


def main(argv: list[str] | None = None) -> None:
    """Run the isolated native checks and write a bounded report under ``scratch/staging``."""
    refuse_optimized()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable', required=True, type=Path,
                        help='path to the otelcol-contrib.exe to check; this product ships no binary,'
                             ' so there is no default to guess (see the provenance recipe in CONTRACT.md)')
    parser.add_argument('--with-security', action='store_true',
                        help='also check the opt-in Security overlay: that the pinned build accepts'
                             ' it merged, what it does without the privilege, and that the pipeline'
                             ' carries an event with stable identity')
    parser.add_argument('--security-channel', default='Application',
                        help='channel the isolated identity check may read without the Security right'
                             ' (default: Application); the shipped overlay stays pointed at Security')
    args = parser.parse_args(argv)
    if os.name != 'nt':
        raise ValueError('Native Windows check required')
    pinned = pinned_release()
    directory = ROOT / 'scratch/staging' / ('windows-' + uuid.uuid4().hex[:12])
    # parents=True: a fresh clone has no scratch/ at all (it is gitignored), and an isolated check
    # that dies on a missing directory tells a stranger nothing about their collector.
    directory.mkdir(parents=True)
    source = args.executable
    require(source.is_file(), 'No collector executable at ' + str(source) + '; download and verify the'
            + ' asset named in versions.json first -- the recipe refuses step by step in CONTRACT.md')
    executable = directory / source.name
    shutil.copyfile(source, executable)
    checksum = sha256_file(executable)
    require(checksum == sha256_file(source), 'The copied collector binary differs from the one on disk')
    require_pinned_binary(checksum, pinned)
    token, resource = secrets.token_urlsafe(32), str(uuid.uuid4())
    received: collections.deque = collections.deque(maxlen=MAX_STORED_REQUESTS)
    failed = [True]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4194304:
                self.send_error(413)
                return
            raw = self.rfile.read(length)
            if self.headers.get('Authorization') != 'Bearer ' + token:
                self.send_error(401)
                return
            if failed[0]:
                self.send_error(503)
                return
            if self.headers.get('Content-Encoding') == 'gzip':
                raw = gzip.decompress(raw)
            received.append((self.path, json.loads(raw)))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = yaml.safe_load(BASE_CONFIG.read_text())
    # The shipped config must read its credential through confmap's `file` provider; this check
    # would otherwise pass happily against a `${env:…}` form that secret files's rule forbids.
    shipped_header = str(config['exporters']['otlp_http']['headers']['Authorization'])
    require(shipped_header.startswith('Bearer ${file:'),
            'The Windows agent must read its ingest credential from a mounted file, not the '
            'environment; collector.yaml presents ' + shipped_header.split()[-1])
    config['receivers']['hostmetrics']['collection_interval'] = '2s'
    config['exporters']['otlp_http']['encoding'] = 'json'
    config['exporters']['otlp_http']['retry_on_failure']['max_interval'] = '2s'
    config_path = directory / 'collector.yaml'
    log_path = directory / 'synthetic.log'
    marker = 'local-observe-windows-' + uuid.uuid4().hex
    log_path.write_text(marker + '\n')
    # The run points the `file` provider at this private directory rather than the path the shipped
    # config names: an isolated check must never read -- let alone overwrite -- the credential of an
    # installed agent. Mode 0600, not 0400: Windows maps a mode without the write bit to the
    # read-only attribute, which the file's owner then cannot clear. Same bytes as the operator's
    # file: the token and no trailing newline, which is what the provider passes through.
    token_file = directory / 'ingest-token'
    with open(token_file, 'x', opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
        stream.write(token)
    config['exporters']['otlp_http']['headers']['Authorization'] = 'Bearer ${file:' + token_file.as_posix() + '}'
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    env = dict(os.environ, LO_AGENT_STATE_DIR=str(directory / 'state'), LO_LOG_GLOB=log_path.as_posix(),
               LO_HOST_NAME=TEST_HOST_NAME, LO_RESOURCE_ID=resource,
               LO_INGEST_URL='http://127.0.0.1:' + str(server.server_port))
    process = None
    report = {'status': 'running', 'binary_sha256': checksum, 'installed_service_changed': False,
              'output': str(directory),
              'pin_source': str(PIN_FILE.relative_to(ROOT)),
              'pinned_version': pinned['collector']['version'],
              'binary_matches_pin': True,
              'credential_delivery': 'mounted file read by the collector `file` provider; no token in the process environment',
              'scope': ('one isolated run of the collector binary in a private directory on this Windows host: file, '
                        'CPU and restart behaviour'
                        + (', plus the opt-in Security overlay' if args.with_security else '')
                        + '; the installed service was neither read nor changed')}
    try:
        version = subprocess.run([str(executable), '--version'], capture_output=True, text=True, timeout=10)
        report['version'] = version.stdout.strip()
        require_pinned_version(report['version'], pinned)
        run_validation(executable, [config_path], env, directory / 'validate.log')
        with (directory / 'collector.log').open('a') as logs:
            process = subprocess.Popen([str(executable), '--config', str(config_path)], env=env, stdout=logs, stderr=logs,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(8)
            require(process.poll() is None, 'The collector exited on start')
            require(list((directory / 'state').glob('*')), 'The collector wrote no state directory')
            process.kill()
            process.wait(timeout=10)
            failed[0] = False
            process = subprocess.Popen([str(executable), '--config', str(config_path)], env=env, stdout=logs, stderr=logs,
                                       creationflags=subprocess.CREATE_NO_WINDOW)

            def evidence():
                matches, cpus = [], set()
                for path, body in list(received):
                    for resource_logs in body.get('resourceLogs', []):
                        attrs = {a['key']: a['value'].get('stringValue') for a in resource_logs['resource']['attributes']}
                        for scope in resource_logs['scopeLogs']:
                            for record in scope['logRecords']:
                                if record.get('body', {}).get('stringValue') == marker:
                                    require(attrs['resource_id'] == resource,
                                            'A matching log record carried the wrong resource identity')
                                    matches.append(record)
                    for resource_metrics in body.get('resourceMetrics', []):
                        for scope in resource_metrics['scopeMetrics']:
                            for metric in scope['metrics']:
                                if metric['name'] == 'system.cpu.time':
                                    for point in metric['sum']['dataPoints']:
                                        attrs = {a['key']: a['value'].get('stringValue') for a in point['attributes']}
                                        if 'cpu' in attrs:
                                            cpus.add(attrs['cpu'])
                return matches, cpus
            for _ in range(45):
                matches, cpus = evidence()
                if matches and len(cpus) == os.cpu_count():
                    break
                require(process.poll() is None, 'The collector exited while waiting for its evidence')
                time.sleep(1)
            require(len(matches) == 1 and len(cpus) == os.cpu_count(),
                    'Expected one persisted record and one CPU series per core, got '
                    + str((len(matches), len(cpus), os.cpu_count())))
            report.update(status='pass', persisted_log_records=len(matches), cpu_series=len(cpus), expected_cpus=os.cpu_count(),
                          interrupted_queue_recovered=True, resource_identity='pass')
            if args.with_security:
                # file_storage refuses a second process on the same directory: on this pinned build
                # the newcomer dies inside exporter start (`failed to start "otlp_http" exporter:
                # timeout`, measured 2026-09-08 against the key this component renamed in otlp http alias and
                # not re-run since) while the first one still holds it. Finish the
                # queue-recovery process before reusing this run's state directory.
                process.kill()
                process.wait(timeout=10)
                run_security_phase(executable, config, config_path, env, directory, logs, received, resource,
                                   args.security_channel, report)
    except Exception as exc:
        report.update(status='fail', error_type=type(exc).__name__)
        raise
    finally:
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))


def run_security_phase(executable: Path, base_config: dict[str, Any], base_path: Path, env: Mapping[str, str],
                       directory: Path, logs: Any,
                       received: Sequence[tuple[str, dict[str, Any]]],
                       resource: str, channel: str, report: dict[str, Any]) -> None:
    """Check the opt-in Security overlay in isolation, and record what the host actually did.

    Three facts, each named in the report rather than inferred from the others:

    1. the pinned build accepts ``collector.yaml`` plus the shipped overlay as two ``--config``
       locations (its own ``validate``, on the shipped bytes of the overlay);
    2. whether this host may open the ``Security`` channel at all -- with the overlay as shipped;
    3. whether the overlay pipeline carries a Windows event to the exporter with this run's
       ``resource_id``, which is proven on a channel this session can read, because the point of
       item 2 is that ``Security`` is usually not readable here.

    Args:
        executable: The copied collector.
        base_config: The isolated base document already re-pointed at this run's token and files.
        base_path: Where that document was written, for the two-file invocation.
        env: The ``LO_*`` environment for this isolated run.
        directory: This run's private directory.
        logs: The open log file every collector process writes to.
        received: The sink's stored ``(path, document)`` pairs.
        resource: This run's ``resource_id``.
        channel: A channel readable without the Security right, for item 3.
        report: Updated in place with the three named observations.
    """
    overlay = yaml.safe_load(OVERLAY_CONFIG.read_text())
    run_validation(executable, [base_path, OVERLAY_CONFIG], env, directory / 'validate-security.log')
    report['security_overlay_validates_merged'] = 'pass'
    shipped = subprocess.Popen([str(executable), '--config', str(base_path), '--config', str(OVERLAY_CONFIG)],
                               env=env, stdout=logs, stderr=logs, creationflags=subprocess.CREATE_NO_WINDOW)
    time.sleep(6)
    exit_code = shipped.poll()
    if exit_code is None:
        shipped.kill()
        shipped.wait(timeout=10)
        report['security_channel_permission'] = 'accepted (this host may open Security)'
    else:
        observed = (directory / 'collector.log').read_text(errors='replace')
        named = [line for line in observed.splitlines() if SUBSCRIPTION_FAILURE in line]
        require(named, 'The collector died as soon as the Security overlay was added, and its own log '
                       'does not say why; read ' + str(directory / 'collector.log') + ' and record what'
                       ' it found rather than passing this check on a guess')
        require(PERMISSION_DENIED in observed, 'The Security overlay was refused for a reason other'
                + ' than a missing permission; the log line is: ' + named[-1][:400])
        report['security_channel_permission'] = 'refused: missing permission'
        report['security_channel_observed_error'] = named[-1][:400]
    # Item 3. `channel` and `query` are mutually exclusive in this build, so the isolated variant
    # replaces the query with the readable channel and replays it from the beginning; nothing about
    # the shipped file is trusted by this substitution, which is why the shipped form above is
    # validated and started unchanged.
    isolated = merge_configs(base_config, overlay)
    receiver = isolated['receivers']['windows_event_log/security']
    del receiver['query']
    receiver['channel'] = channel
    receiver['start_at'] = 'beginning'
    isolated_path = directory / 'collector-security-iso.yaml'
    isolated_path.write_text(yaml.safe_dump(isolated, sort_keys=False))
    run_validation(executable, [isolated_path], env, directory / 'validate-security-iso.log')
    carrier = subprocess.Popen([str(executable), '--config', str(isolated_path)], env=env, stdout=logs,
                               stderr=logs, creationflags=subprocess.CREATE_NO_WINDOW)
    records = 0
    for _ in range(45):
        records = security_records(list(received), channel, resource)
        if records:
            break
        require(carrier.poll() is None, 'The collector carrying the Security overlay exited before it'
                                        ' delivered anything; see ' + str(directory / 'collector.log'))
        time.sleep(1)
    carrier.kill()
    carrier.wait(timeout=10)
    require(records, 'The Security overlay reached the exporter with no event at all: nothing carried a'
            + ' structured body from the ' + channel + ' channel with this run\'s resource_id. That is'
            + ' not a permission story (this channel is readable) -- the pipeline is broken')
    report['security_overlay_channel'] = channel
    report['security_overlay_records_with_identity'] = records
    report['security_overlay_identity'] = 'pass'


if __name__ == '__main__':
    main()

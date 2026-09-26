"""Read an explicitly selected rootless daemon; inspect only allowlisted service fields.

The read is scoped three times over: an explicit Compose project allowlist, a rootless socket path
that must match the pattern and whose daemon must report the expected data root, and a five-key Go
template so the fields below are the only parts of a container object this process ever receives.
That template is the narrowing v0.1 lacked: its Docker source read whole container objects, which
carries `Config.Env` — where an operator's secrets are kept — into an observed-plane database that
is archived. Everything this module returns is a `discovery.Observation`; it never writes.

Container identity here is per service, not per container: one observation per Compose project and
service, counting replicas. A recreate therefore keeps its identity and changes its `evidence`,
which is where the per-instance container ids live, so a replaced instance is visible in every
finding that quotes it rather than being invisible. Per-instance aging for a source like this one —
which names only the projects it was told to read — goes through `discovery.ageing`, and this source
declares `complete: False`, so it can never conclude absence on its own.
"""
from collections.abc import Sequence
import datetime as dt
import json
import os
import re
import subprocess
from typing import Any

from . import discovery
from .validation import InvalidInventory, digest

FIELDS = {'id': '.Id', 'state': '.State.Status', 'project': '(index .Config.Labels "com.docker.compose.project")',
          'service': '(index .Config.Labels "com.docker.compose.service")',
          'resource_id': '(index .Config.Labels "local-observe.resource_id")'}
INSTANCE_EVIDENCE = 18


def observe(projects: Sequence[str], *, source: str, socket: str, expected_root: str,
            now: dt.datetime | None = None) -> list[discovery.Observation]:
    """Inspect the allowlisted fields of every container in `projects`; return service observations.

    Raises rather than reporting a partial view: a daemon that is not the expected rootless one, a
    container that changed project mid-read, a replica group carrying two different resource UUID
    labels, or an over-long listing all end the read instead of shrinking it.
    """
    if not discovery.SOURCE_SHAPE.fullmatch(source):
        raise InvalidInventory('Docker discovery source must be a bounded lowercase name')
    if not projects or any(not re.fullmatch('[a-z0-9][a-z0-9_-]{0,62}', item) for item in projects):
        raise InvalidInventory('Explicit Compose project allowlist required')
    if not re.fullmatch(r'/run/user/[0-9]+/docker.sock', socket) or not expected_root.startswith('/'):
        raise InvalidInventory('Expected explicit rootless socket and data root')
    now = now or dt.datetime.now(dt.timezone.utc)
    env = dict(os.environ, DOCKER_HOST='unix://' + socket)
    env.pop('DOCKER_CONTEXT', None)
    env.pop('DOCKER_TLS_VERIFY', None)
    env.pop('DOCKER_CERT_PATH', None)

    def docker(*args):
        try:
            result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=30, env=env)
        except subprocess.SubprocessError as exc:
            raise InvalidInventory('Scoped Docker discovery timed out') from exc
        if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
            raise InvalidInventory('Scoped Docker discovery failed or exceeded bound')
        return result.stdout.strip()

    info = json.loads(docker('info', '--format', '{{json .}}'))
    if info['DockerRootDir'] != expected_root or not any('rootless' in item for item in info['SecurityOptions']):
        raise InvalidInventory('Docker daemon identity does not match discovery scope')
    template = '{' + ','.join(json.dumps(key) + ':{{json ' + value + '}}' for key, value in FIELDS.items()) + '}'
    groups = {}
    for project in sorted(set(projects)):
        ids = docker('ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project).splitlines()
        if len(ids) > 500:
            raise InvalidInventory('Discovery container limit exceeded')
        for cid in ids:
            if not re.fullmatch('[a-f0-9]{12,64}', cid):
                raise InvalidInventory('Invalid Docker container ID')
            row = json.loads(docker('inspect', '--format', template, cid))
            if row['project'] != project or not row['service']:
                raise InvalidInventory('Container changed discovery scope during read')
            groups.setdefault((project, row['service']), []).append(row)
    observations = []
    for (project, service), rows in sorted(groups.items()):
        explicit = {row['resource_id'] for row in rows if row['resource_id']}
        if len(explicit) > 1:
            raise InvalidInventory('Conflicting replica resource UUID labels')
        instances = sorted(row['id'][:12] for row in rows)
        evidence = ['docker-service:' + project + '/' + service]
        evidence += ['docker-container:' + item for item in instances[:INSTANCE_EVIDENCE]]
        if len(instances) > INSTANCE_EVIDENCE:
            evidence.append(f'docker-container-remainder:{len(instances) - INSTANCE_EVIDENCE}')
        item = discovery.Observation(
            source=source, observed_at=now, observation_id=digest([project, service]),
            aliases=({'type': 'service.name', 'scope': project, 'value': service},),
            attributes={'replicas': len(rows),
                        'running_replicas': sum(row['state'] == 'running' for row in rows)},
            evidence=tuple(evidence), kind='service', name=service,
            resource_id=next(iter(explicit)) if explicit else None)
        observations.append(item)
    return observations


def snapshot(projects: Sequence[str], *, source: str, socket: str, expected_root: str,
             scope: Sequence[str] = (), now: dt.datetime | None = None) -> dict[str, Any]:
    """Return one bounded observation snapshot for the named projects; append-only, never a write."""
    now = now or dt.datetime.now(dt.timezone.utc)
    return discovery.snapshot(source, observe(projects, source=source, socket=socket,
                                             expected_root=expected_root, now=now),
                             now=now, scope=scope, complete=False)


class DockerProvider:
    """The scoped Docker read behind the `discovery.Provider` interface, for one bound instant."""

    def __init__(self, projects: Sequence[str], *, source: str, socket: str, expected_root: str,
                 scope: Sequence[str] = (), now: dt.datetime | None = None) -> None:
        """Bind the read scope; the project allowlist and socket are checked at read time as before."""
        self.projects = list(projects)
        self.source = source
        self.socket = socket
        self.expected_root = expected_root
        self.scope = list(scope)
        self.now = now

    def observe(self) -> list[discovery.Observation]:
        """Inspect the allowlisted fields and return the service observations."""
        return observe(self.projects, source=self.source, socket=self.socket,
                       expected_root=self.expected_root, now=self.now)

    def snapshot(self) -> dict[str, Any]:
        """Seal the read as one partial observed-plane document."""
        return snapshot(self.projects, source=self.source, socket=self.socket, expected_root=self.expected_root,
                        scope=self.scope, now=self.now)

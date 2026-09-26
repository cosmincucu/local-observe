"""Read a Kubernetes pod listing through a named field allowlist; emit service observations.

Ported from v0.1's Kubernetes discovery source, which called `inventory.upsert` per pod. Here the
source stops at observations, and the listing is injected — a parsed `kubectl get pods -o json`
document or a test fixture. This module contains no API client, no kubeconfig reader and nothing
else that could reach a cluster: which cluster to look at is the operator's decision, made outside
at is the operator's decision, made outside this repository, and the answer arrives as data.

The field allowlist below is the discipline copied from `docker_provider.py:38`, where the Docker
read names five keys in a Go template and every other field of the container object is never
requested. Here the listing may be arbitrary JSON, so the allowlist is applied on read instead of
pushed into the query. What is dropped is the security-relevant half of the port: `metadata.annotations`
(anyone can write anything into one, including a token), `spec.containers[].env` and `envFrom`
(where a pod keeps its secrets), `imagePullSecrets` and secret/projected volumes, `serviceAccountName`,
scheduling fields, `ownerReferences`, and `status.containerStatuses[].imageID` (a registry digest is
a supply-chain identifier, not an identity this product declared). Widening `KUBE_FIELDS` widens
what gets copied out of a cluster, so it is a reviewed change to the contract, not a feature flag.

Identity follows the pod, not the workload: the observation key is namespace plus pod name, which
carries the generated instance suffix, so a recreated pod is a new instance whose evidence names its
uid and whose predecessor ages out under `discovery.ageing`. `complete` stays False — a listing of
some namespaces is not a statement that nothing else exists.
"""
from collections.abc import Sequence
import datetime as dt
import ipaddress
import re
from typing import Any

from . import discovery
from .validation import InvalidInventory, digest

RESOURCE_ID_LABEL = 'local-observe.resource_id'
MAX_ITEMS = 2000
MAX_TEXT = 256
MAX_IMAGES = 2048
DISCOVERED_BY = 'kubernetes'
UUID_SHAPE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')

# Every field this source reads out of a pod object, addressed by path. Add a key here and it must
# appear in the provider contract in local_observe/inventory/README.md in the same change.
KUBE_FIELDS: dict[str, tuple[str, ...]] = {
    'name': ('metadata', 'name'),
    'namespace': ('metadata', 'namespace'),
    'uid': ('metadata', 'uid'),
    'node': ('spec', 'nodeName'),
    'phase': ('status', 'phase'),
    'pod_ip': ('status', 'podIP'),
    'resource_id': ('metadata', 'labels', RESOURCE_ID_LABEL),
}
IMAGES_PATH = ('spec', 'containers')


def field(item: dict[str, Any], path: Sequence[str]) -> Any:
    """Walk one allowlisted path; a missing or mistyped intermediate reads as absent, not as an error."""
    current: Any = item
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def bounded_text(value: Any, *, limit: int = MAX_TEXT) -> str | None:
    """Return the value as bounded plain text, or None when it is not a usable scalar string."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    text = str(value).strip()
    return text[:limit] or None


class KubeProvider:
    """One injected pod listing, reported as service observations.

    The listing is data the caller already holds. Nothing in this class opens a connection, reads a
    credential or resolves a server: there is no argument it could be given to aim at a cluster.
    """

    def __init__(self, *, source: str, listing: dict[str, Any],
                 now: dt.datetime | None = None) -> None:
        """Bind the source name and a listing whose `items` is a bounded list of objects."""
        if not discovery.SOURCE_SHAPE.fullmatch(source):
            raise InvalidInventory('Kubernetes source must be a bounded lowercase name')
        if not isinstance(listing, dict) or not isinstance(listing.get('items'), list):
            raise InvalidInventory('Kubernetes listing must carry an items list')
        if len(listing['items']) > MAX_ITEMS:
            raise InvalidInventory(f'Kubernetes listing exceeds the bound of {MAX_ITEMS} items')
        self.source = source
        self.items: Sequence[Any] = listing['items']
        self.now = now

    def observe(self) -> list[discovery.Observation]:
        """Return one observation per pod item, reading nothing beyond `KUBE_FIELDS`."""
        moment = self.now or dt.datetime.now(dt.timezone.utc)
        observations = []
        for position, item in enumerate(self.items):
            if not isinstance(item, dict):
                raise InvalidInventory(f'Kubernetes listing item {position} is not an object')
            values = {key: field(item, path) for key, path in KUBE_FIELDS.items()}
            name, namespace = bounded_text(values['name']), bounded_text(values['namespace']) or 'default'
            if not name:
                raise InvalidInventory(f'Kubernetes listing item {position} has no metadata.name')
            aliases: list[dict[str, Any]] = [{'type': 'service.name', 'scope': namespace, 'value': name}]
            evidence = [f'kube:{namespace}/{name}']
            uid = bounded_text(values['uid'])
            if uid:
                evidence.append('kube-uid:' + uid)
            pod_ip = bounded_text(values['pod_ip'])
            if pod_ip:
                try:
                    aliases.append({'type': 'ip', 'value': str(ipaddress.ip_address(pod_ip))})
                except ValueError:
                    # A pod IP this product cannot normalise is reported as unusable evidence, and
                    # never becomes an alias: a wrong alias is a wrong identity, not a missing one.
                    evidence.append('kube-pod-ip-unusable')
            resource_id = bounded_text(values['resource_id'], limit=MAX_TEXT)
            if resource_id is not None and not UUID_SHAPE.fullmatch(resource_id):
                resource_id = None
                evidence.append('kube-resource-id-unusable')
            containers = field(item, IMAGES_PATH)
            images = ','.join(text for container in (containers if isinstance(containers, list) else [])
                              if isinstance(container, dict)
                              for text in [str(container.get('image', '')).strip()] if text)
            attributes: dict[str, Any] = {'discovered_by': DISCOVERED_BY, 'namespace': namespace,
                                         'images': images[:MAX_IMAGES]}
            for key in ('phase', 'node'):
                text = bounded_text(values[key])
                if text:
                    attributes[key] = text
            observations.append(discovery.Observation(
                source=self.source, observed_at=moment,
                observation_id=digest([DISCOVERED_BY, namespace, name]),
                aliases=tuple(aliases), attributes=attributes, evidence=tuple(evidence),
                kind='service', name=f'{namespace}/{name}', resource_id=resource_id))
        return observations

    def snapshot(self) -> dict[str, Any]:
        """Seal the listing as an observed-plane document that claims no coverage it does not have."""
        return discovery.snapshot(self.source, self.observe(), now=self.now, complete=False)

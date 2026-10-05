"""Optional operator-declared route pool behind one gateway alias, with auditable per-call membership.

One gateway alias can load-balance across several distinct backends, so one expected deployment ID names
a single box instead of the pool the operator actually configured. `load_pool` reads a small protected
declaration of every member of that pool -- each with its own provider and weight version -- and
`PoolGuard` admits a successful response only when exactly one response header names one declared member.
`RoutePool.model_version` then identifies the *declaration as a whole* by digest, so a record can carry a
bounded, comparable value for a call whose backend the gateway chose.

Recording is all this buys, and three limits are what make it worth anything. The received header value
is matched and dropped: it is never returned, stored, logged, or hashed into a receipt, and the receipt a
caller may keep holds only configured digests and one boolean. A matching header is transport metadata
about which declared member answered, never an attestation of the weights it loaded -- provider and model
version stay explicit operator metadata. And a pool cannot be half-declared: selecting
`LO_OBSERVER_MODEL_ROUTES` together with any single-deployment variable is refused as ambiguous, while an
unselected variable attaches no wrapper and changes no existing behavior. Pooled routing is auditable
here and nothing else: it never establishes model quality and never authorizes acceptance or delivery.

Refusals are payload-free `ObserverError` codes, one per diagnosis: `invalid_pool_path` (the selection
value cannot name a file), `absolute_private_path_required`, `model_route_pool_ambiguous`, `unsupported_pool_version`,
`invalid_pool_declaration` (top-level shape, or the route map itself), `invalid_pool_member` (a member ID
or member object), `invalid_pool_metadata` (a provider or version that is neither null nor a bounded label),
`model_deployment_mismatch` (shared with the single-deployment guard) and `model_route_pool_unsupported`
(a transport that cannot carry the contract). The protected-file reader answers with its own codes for an
oversized file (`protected_file_too_large`), a wrong owner, mode or symlink (`private_owned_file_required`,
`private_owned_directory_required`, `unsafe_state_ancestor`) and for unreadable or ambiguous text
(`invalid_json`, which is also what a duplicated key becomes).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from local_observe.http import JsonClient, ResponseHeader

from .contract import digest, require
from .model_route import DEPLOYMENT_HEADER, deployment_id
from .provenance import label

POOL_VARIABLE = 'LO_OBSERVER_MODEL_ROUTES'
POOL_PROVIDER = 'declared-route-pool'
POOL_PREFIX = 'route-pool-sha256:'

# Single-deployment configuration that a pool declaration replaces: any one of them nonempty next to the
# pool variable leaves two authorities claiming the same call, so the whole contract is refused.
SINGLE_DEPLOYMENT_VARIABLES = ('LO_OBSERVER_MODEL_DEPLOYMENT', 'LO_OBSERVER_MODEL_PROVIDER',
                               'LO_OBSERVER_MODEL_VERSION')

MAX_POOL_MEMBERS = 16
POOL_BYTE_LIMIT = 16384
MEMBER_FIELDS = frozenset({'provider', 'model_version'})


def selected_pool_path(environ: Any) -> str | None:
    """Return the declared pool file, or None when this contract is unselected.

    Absence is a choice, not a defect: an operator who declared no pool keeps the transport, and for the
    single-deployment case the guard, they were built with. A present but unusable value is refused
    rather than read as absence, because a truncated path would otherwise silently drop the pool.
    """
    value = environ.get(POOL_VARIABLE) if isinstance(environ, dict) else None
    if value is None or value == '':
        return None
    require(isinstance(value, str) and value == value.strip() and 1 <= len(value) <= 2048
            and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'invalid_pool_path')
    require(Path(value).is_absolute() and '..' not in Path(value).parts, 'absolute_private_path_required')
    return value


def load_pool(environ: Any) -> RoutePool | None:
    """Load the declared route pool, or return None when the operator selected no pool.

    Together with a single-deployment variable the declaration is ambiguous, so it is refused: the two
    contracts answer different questions and neither one wins by precedence.
    """
    path = selected_pool_path(environ)
    if path is None:
        return None
    for variable in SINGLE_DEPLOYMENT_VARIABLES:
        require(environ.get(variable) in (None, ''), 'model_route_pool_ambiguous')
    from .environment import protected_json  # the reader pulls in the filesystem and mode checks
    return RoutePool(protected_json(path, POOL_BYTE_LIMIT))


def _validated(value: Any) -> dict:
    """Validate one declaration into a fresh, self-contained document, refusing every other shape."""
    require(isinstance(value, dict) and set(value) == {'schema_version', 'routes'}, 'invalid_pool_declaration')
    require(type(value['schema_version']) is int and value['schema_version'] == 1, 'unsupported_pool_version')
    routes = value['routes']
    require(isinstance(routes, dict) and 1 <= len(routes) <= MAX_POOL_MEMBERS, 'invalid_pool_declaration')
    members = {}
    for member, metadata in routes.items():
        require(isinstance(member, str) and deployment_id(member) == member, 'invalid_pool_member')
        require(isinstance(metadata, dict) and set(metadata) == set(MEMBER_FIELDS), 'invalid_pool_member')
        declared = {field: metadata[field] for field in sorted(MEMBER_FIELDS)}
        require(all(item is None or (isinstance(item, str) and label(item) == item)
                    for item in declared.values()), 'invalid_pool_metadata')
        members[member] = declared
    return {'schema_version': 1, 'routes': members}


class RoutePool:
    """Immutable, validated view of one declared route pool, identified by the digest of its contents.

    The declaration is rebuilt as a fresh document on the way in, so a caller that keeps a reference to
    the dict it passed cannot rewrite what the digest certifies, and every document handed back is a new
    copy. Metadata the operator left null stays null: an unknown weight version is unknown, never a hash
    that invents one.
    """

    def __init__(self, declaration: Any) -> None:
        self._data = _validated(declaration)
        self._sha256 = digest(self._data)

    @property
    def sha256(self) -> str:
        """Digest of the whole validated declaration; keys are sorted, so declaration order cannot move it."""
        return self._sha256

    @property
    def complete(self) -> bool:
        """True only when every declared member names both a provider and a model version."""
        return all(all(item is not None for item in metadata.values())
                   for metadata in self._data['routes'].values())

    @property
    def model_version(self) -> str | None:
        """The pool as one bounded provenance version, or None while any member stays undeclared.

        A digest of the declaration rather than of one backend: with a load-balanced alias the operator
        knows the pool that answered, not the box, and naming a pool it did not declare would be a claim
        this module cannot support.
        """
        return POOL_PREFIX + self._sha256 if self.complete else None

    @property
    def member_receipts(self) -> dict[str, dict]:
        """One safe receipt per declared member, keyed by member ID for the parent's own bookkeeping."""
        return {member: self._receipt(member, metadata) for member, metadata in self._data['routes'].items()}

    def receipt_for(self, observed: Any) -> dict | None:
        """Return the configured receipt of the member *observed* names, or None when it names no member.

        The answer is built from the declaration, never from the received bytes: a value that happens to
        match still yields only configured digests, and anything else -- a URL, a credential-shaped token,
        another deployment -- yields nothing rather than a copy of itself.
        """
        member = observed if isinstance(observed, str) and deployment_id(observed) == observed else None
        metadata = self._data['routes'].get(member) if member is not None else None
        return None if metadata is None else self._receipt(member, metadata)

    def _receipt(self, member: str, metadata: dict) -> dict:
        return {'schema_version': 1, 'pool_sha256': self._sha256,
                'member_sha256': digest([member, metadata['provider'], metadata['model_version']]),
                'complete': metadata['provider'] is not None and metadata['model_version'] is not None}


class PoolGuard:
    """Transport seam that admits one declared pool member per successful response and keeps its receipt.

    One attempt is forwarded per call, the previous receipt is cleared before that attempt starts and a
    fresh single-header slot is built for it, so neither a retry nor a header left over from an earlier
    call -- including one that timed out, answered with an error status, or returned a body that never
    parsed -- can certify a later call.
    """

    def __init__(self, transport: JsonClient, pool: RoutePool) -> None:
        require(isinstance(pool, RoutePool), 'model_route_pool_unsupported')
        require(isinstance(transport, JsonClient), 'model_route_pool_unsupported')
        self.transport = transport
        self.pool = pool
        self.receipt = None

    def request(self, method: str, path: str = '', payload: Any = None, **kwargs) -> tuple[int, Any]:
        self.receipt = None
        collected = ResponseHeader(DEPLOYMENT_HEADER)
        status, body = self.transport.request(method, path, payload=payload, response_header=collected,
                                              **kwargs)
        # A non-2xx answer is refused by the existing status gate before any result is used, and it
        # carries no verified member; only the answer that produced content can.
        # Match the AI client's accepted statuses; other statuses keep its endpoint-status refusal.
        if status in (200, 201):
            observed = collected.values
            collected.values = []
            self.receipt = self.pool.receipt_for(observed[0] if len(observed) == 1 else None)
            require(self.receipt is not None, 'model_deployment_mismatch')
        return status, body

    def take_receipt(self) -> dict | None:
        """Hand over the receipt of the most recent admitted response, then forget it.

        One read per call: a caller that keeps the document owns it, and the guard cannot later be asked
        to vouch for a response it no longer holds.
        """
        receipt, self.receipt = self.receipt, None
        return receipt


def guard_pool_client(client: Any, pool: RoutePool) -> Any:
    """Wrap *client*'s transport in the guard for *pool*, reusing an existing identical wrap.

    Repeated model calls in one cycle reuse the same client, so a wrap for this exact declaration is left
    alone instead of nested, and a wrap for a changed declaration is unwrapped by one layer and replaced.
    A transport that is not the product `JsonClient` cannot carry the single-header contract, and a
    single-deployment `DeploymentGuard` answers a different question than a pool wrap, so both are
    refused rather than quietly unchecked.
    """
    require(isinstance(pool, RoutePool), 'model_route_pool_unsupported')
    transport = getattr(client, 'transport', None)
    if isinstance(transport, PoolGuard):
        if transport.pool.sha256 == pool.sha256:
            return client
        transport = transport.transport
    require(isinstance(transport, JsonClient), 'model_route_pool_unsupported')
    client.transport = PoolGuard(transport, pool)
    return client

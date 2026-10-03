"""Optional per-call gateway deployment check for operator-selected local inference endpoints.

One gateway alias can front several distinct backends, so the model name inside the response envelope
cannot say which deployment answered. When the operator declares the expected gateway deployment ID,
`DeploymentGuard` reads exactly one response header from the same successful answer and refuses
anything else, and `route_label` folds the *expected* ID together with the declared model version into
one bounded provenance label.

Three limits keep this honest. The observed header value is only compared: it is never returned,
stored, logged or hashed into the journal. A matching header is transport metadata about where the
request went, not an attestation of which weights were loaded -- provider and model version stay
explicit operator metadata. And an unconfigured `LO_OBSERVER_MODEL_DEPLOYMENT` attaches no wrapper and
changes no behavior: existing clients keep the transport they were built with.
"""
from __future__ import annotations

import re
from typing import Any

from local_observe.http import JsonClient, ResponseHeader

from .contract import digest, require
from .provenance import label

DEPLOYMENT_VARIABLE = 'LO_OBSERVER_MODEL_DEPLOYMENT'
DEPLOYMENT_HEADER = 'x-litellm-model-id'
ROUTE_PREFIX = 'route-sha256:'

# A bounded, single, printable deployment identifier: no URL, no folding byte, no space, no separator
# a header value could hide behind, and no over-long value. Credential-shaped bytes are not rejected
# for their shape; they are rejected because they are not the declared ID, and they are never copied.
_DEPLOYMENT_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}')


def deployment_id(value: Any) -> str | None:
    """Return *value* as a bounded deployment ID label, or None when it is not one.

    `label` keeps the shared unknown vocabulary ('unknown', 'none', ...) out of a field that would
    otherwise read as a known deployment; the stricter shape below also refuses URLs, paths, folding
    bytes, spaces and over-long input.
    """
    if not isinstance(value, str) or label(value) is None:
        return None
    return value if _DEPLOYMENT_ID.fullmatch(value) is not None else None


def declared_deployment(environ: Any) -> str | None:
    """Return the operator-selected expected ID, or None when this contract is unselected or unusable."""
    value = environ.get(DEPLOYMENT_VARIABLE) if isinstance(environ, dict) else None
    return deployment_id(value) if isinstance(value, str) and value else None


def expected_deployment(environ: Any) -> str | None:
    """`declared_deployment`, refusing a value that is set but cannot name one deployment."""
    value = environ.get(DEPLOYMENT_VARIABLE) if isinstance(environ, dict) else None
    if value is None or value == '':
        return None
    expected = deployment_id(value)
    require(expected is not None, 'invalid_model_deployment')
    return expected


def route_label(model_version: Any, expected: Any) -> str | None:
    """Bind one declared model version to one expected deployment as a bounded provenance label.

    Unknown stays unknown: without an explicit operator version there is nothing to bind, and a digest
    of the expected deployment alone would read like a known weight revision. The inputs are hashed
    rather than joined, so neither value is copied into the journal.
    """
    version, deployment = label(model_version), deployment_id(expected)
    return ROUTE_PREFIX + digest([version, deployment]) if version and deployment else None


class DeploymentGuard:
    """Transport seam that admits one expected deployment ID per successful response.

    One attempt is forwarded per call and one fresh `ResponseHeader` slot is built for it, so neither a
    retry nor a header left over from an earlier call -- including one that timed out or answered with
    an error status -- can certify a later call.
    """

    def __init__(self, transport: JsonClient, expected: str) -> None:
        self.transport = transport
        self.expected = expected

    def request(self, method: str, path: str = '', payload: Any = None, **kwargs) -> tuple[int, Any]:
        collected = ResponseHeader(DEPLOYMENT_HEADER)
        status, body = self.transport.request(method, path, payload=payload, response_header=collected,
                                              **kwargs)
        # A non-2xx answer is refused by the existing status gate before any result is used, and it
        # carries no verified deployment; only the answer that produced content can.
        if 200 <= status < 300:
            observed = collected.values
            collected.values = []
            require(len(observed) == 1 and deployment_id(observed[0]) == self.expected,
                    'model_deployment_mismatch')
        return status, body


def guard_client(client: Any, environ: Any) -> Any:
    """Wrap *client*'s transport once when the operator selected the deployment contract.

    Repeated model calls in one cycle reuse the same client, so an already wrapped transport is left
    alone rather than nested. A client whose transport is not the product `JsonClient` cannot carry the
    single-header contract, so it is refused instead of silently unchecked.
    """
    expected = expected_deployment(environ)
    if expected is None:
        return client
    transport = getattr(client, 'transport', None)
    if isinstance(transport, DeploymentGuard):
        if transport.expected == expected:
            return client
        transport = transport.transport
    require(isinstance(transport, JsonClient), 'model_deployment_unsupported')
    client.transport = DeploymentGuard(transport, expected)
    return client

"""The tested capability manifest: what this deployment may claim its model can do.

`docs/ARCHITECTURE.md` §3.4 makes a capability manifest part of the AI contract and the `ai` row of
`docs/COMPONENTS.md` names it first among the interfaces the component owes. It is a file with a
status per field rather than a constant because of one sentence: a model card is not a measurement
of what *this* serve, on *this* host, with *these* weights, at *this* context size can do. Every
field therefore starts as the literal string ``"unknown"``, and the rule a consumer follows is
stated once, here, and never re-derived downstream:

    **a consumer may not use a capability the manifest marks** ``unknown`` **or** ``false``.

The consequence is deliberate and it is the point of the exercise: an unmeasured deployment
generates nothing. :func:`require` refuses, names the field, the caller logs the refusal and the
explanation path (rca, investigation component) stays on its rule floor — instead of inventing a context budget from a
marketing page and handing the operator an explanation whose evidence was silently truncated.

This module reads and judges a document. It never fetches one, never defaults a field to a value
from upstream documentation, and never touches the network.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from local_observe.ai import AiError

UNKNOWN = 'unknown'
# The eight fields the component brief names. A manifest with any other key set is a manifest this
# product cannot read, so it is refused rather than tolerated: a renamed field is an unmeasured one.
FIELDS: tuple[str, ...] = ('context_tokens', 'tools', 'json_mode', 'streaming', 'vision',
                           'parallel', 'quant', 'measured_tok_per_s')
BOOLEAN_FIELDS = frozenset({'tools', 'json_mode', 'streaming', 'vision'})
COUNT_FIELDS = frozenset({'context_tokens', 'parallel'})
RATE_FIELDS = frozenset({'measured_tok_per_s'})
LABEL_FIELDS = frozenset({'quant'})
# Bounds on the measured values themselves. A manifest is operator-authored, so an implausible
# number is a mistake, not a fact: refusing it at the read is cheaper than sizing a request from it.
COUNT_BOUNDS: dict[str, tuple[int, int]] = {'context_tokens': (1, 1_000_000), 'parallel': (1, 64)}
MAX_RATE = 100_000
MAX_LABEL_LENGTH = 32
MAX_MANIFEST_BYTES = 4_096
# `--tools` in the pinned serve turns the endpoint into a file/exec agent (its own upstream help
# says "do not enable in untrusted environments"), and the shipped manifest never passes it. A
# manifest claiming `tools: true` therefore describes a serve this component does not deploy, and
# saying so here is cheaper than letting a consumer plan tool calls the endpoint cannot make.
FORBIDDEN_TRUE = frozenset({'tools'})


class CapabilityError(AiError):
    """A capability is unknown, false, or the manifest cannot be read as one."""

    code = 'capability_unknown'


def load(path: Path | str) -> dict[str, Any]:
    """Read one bounded capability manifest from *path* and return it validated.

    A missing file raises `OSError` and an unparseable one raises `CapabilityError` naming the path:
    an absent manifest means "nothing measured", which the caller must report rather than guess.
    """
    raw = Path(path).read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise CapabilityError(f'{path} exceeds {MAX_MANIFEST_BYTES} bytes')
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise CapabilityError(f'{path} is not JSON') from exc
    return validate(document)


def validate(document: Any) -> dict[str, Any]:
    """Return *document* as a capability manifest, or raise `CapabilityError`.

    Shape: ``{"schema_version": 1, <the eight fields>}`` — no extra key, no missing key, each value
    either the literal ``"unknown"`` or a value inside that field's own bounds.
    """
    if not isinstance(document, dict):
        raise CapabilityError('A capability manifest must be a JSON object')
    if document.get('schema_version') != 1:
        raise CapabilityError('Unsupported capability manifest schema_version (expected 1)')
    extra = sorted(set(document) - set(FIELDS) - {'schema_version'})
    missing = sorted(set(FIELDS) - set(document))
    if extra or missing:
        raise CapabilityError(f'Capability manifest fields must be exactly the eight measured ones '
                              f'(unexpected {extra}, missing {missing})')
    for name in FIELDS:
        value = document[name]
        if value == UNKNOWN:
            continue
        if name in BOOLEAN_FIELDS:
            if not isinstance(value, bool):
                raise CapabilityError(f'{name} must be true, false or "{UNKNOWN}"')
            if value and name in FORBIDDEN_TRUE:
                raise CapabilityError(f'{name} may not be true in a manifest for the shipped serve: '
                                      f'the serve is started without it, so this manifest describes a '
                                      f'different deployment (see components/control/ai/CONTRACT.md)')
        elif name in COUNT_FIELDS:
            low, high = COUNT_BOUNDS[name]
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise CapabilityError(f'{name} must be "{UNKNOWN}" or an integer in {low}..{high}')
        elif name in RATE_FIELDS:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= MAX_RATE:
                raise CapabilityError(f'{name} must be "{UNKNOWN}" or a positive number at most {MAX_RATE}')
        elif name in LABEL_FIELDS:
            if (not isinstance(value, str) or not 1 <= len(value.strip()) <= MAX_LABEL_LENGTH
                    or any(char in value for char in '\r\n\t')):
                raise CapabilityError(f'{name} must be "{UNKNOWN}" or a one-line label of at most '
                                      f'{MAX_LABEL_LENGTH} characters')
    return dict(document)


def unknown(manifest: dict[str, Any]) -> list[str]:
    """Return the fields of *manifest* nothing has measured, in declaration order."""
    return [name for name in FIELDS if manifest.get(name) == UNKNOWN]


def measured(manifest: dict[str, Any]) -> bool:
    """Whether every field of *manifest* carries a measurement (no field left ``unknown``)."""
    return not unknown(manifest)


def usable(manifest: dict[str, Any], name: str) -> bool:
    """Whether a consumer may rely on capability *name* — the one rule, in code.

    ``False``, ``"unknown"`` and an absent field all answer "no", so a caller that forgets to
    distinguish "measured as absent" from "never measured" still cannot over-reach the model.
    """
    value = manifest.get(name, UNKNOWN)
    return value != UNKNOWN and value is not False and bool(value)


def require(manifest: dict[str, Any], name: str) -> Any:
    """Return the measured value of *name*, or raise `CapabilityError` naming what is missing.

    This is what a caller uses when it needs the number (a context ceiling) rather than a yes/no.
    """
    if name not in FIELDS:
        raise CapabilityError(f'{name} is not one of the eight capability fields')
    if not usable(manifest, name):
        reason = 'was never measured' if manifest.get(name, UNKNOWN) == UNKNOWN else 'is marked false'
        raise CapabilityError(f'capability {name} {reason}; a consumer may not use a capability the '
                              f'manifest does not measure (unknown fields: '
                              f'{", ".join(unknown(manifest)) or "none"})',
                              code='capability_unknown')
    return manifest[name]


def context_tokens(manifest: dict[str, Any]) -> int:
    """Return the measured context window, refusing when it is unknown or false.

    The one capability with no honest fallback: any number small enough to "work" is a silent
    truncation of the evidence an explanation was supposed to be grounded in.
    """
    value = require(manifest, 'context_tokens')
    return int(value)


def summarise(manifest: dict[str, Any]) -> dict[str, str]:
    """Return ``{field: "measured" | "false" | "unknown"}`` — statuses only, never values.

    This is the form an observation or a telemetry record carries, so a portal can say *which* half
    of the model's capability is unmeasured without restating operator numbers it does not own.
    """
    return {name: ('unknown' if manifest.get(name) == UNKNOWN
                   else 'false' if manifest.get(name) is False
                   else 'measured') for name in FIELDS}

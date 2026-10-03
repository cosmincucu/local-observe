"""The evidence budget: what one request may carry, and the refusal when it cannot.

Two refusals live here because they are the same decision taken over the same list — *what may go
into this request* — and splitting them lets one become a warning.

**Size.** The ceilings are request-side and enforced before anything is sent: a bundle that will not
fit is refused whole rather than truncated, because a truncated bundle is an explanation whose
missing half the operator cannot see. The defaults copy bounds the product already holds: twenty
evidence references is `platform/state.py:778`'s own ceiling on an event, and 64 KiB is the byte
ceiling that file puts on the whole canonical event (`state.py:758`).

**Freshness.** The evidence freshness rule is — *expired
evidence is reported as expired, never replaced by a fresh query to make the explanation look
complete*. The mechanism is that this module has no store, no query builder and no SQL: an expired
item is the last word, and the refusal says so in as many words.

The optional `reasoning_effort` request setting is validated with the budget so it participates
in provenance and drift checks. It has no default and requires backend-specific measurement.

Completion tokens cover reasoning and final text together. A larger explicit allowance may still
produce no complete answer or exceed the configured timeout.
"""
from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
import json
from pathlib import Path
from typing import Any

from local_observe.ai import AiError
from local_observe.inventory.validation import canonical, timestamp

# Keys an evidence reference must carry — the set `platform/state.py:782-783` requires of a canonical
# event, read from that file rather than invented here so the two cannot drift apart in meaning.
REFERENCE_FIELDS: frozenset[str] = frozenset({'source', 'query_type', 'parameters', 'window',
                                              'schema_version', 'expires_at'})
OPTIONAL_FIELDS: frozenset[str] = frozenset({'status', 'sample'})
EVIDENCE_STATUSES = ('available', 'expired', 'unavailable')
DEFAULTS: dict[str, int] = {'max_evidence_items': 20, 'max_evidence_bytes': 16_384,
                            'max_prompt_bytes': 24_576, 'max_completion_tokens': 512}
# A budget file may replace defaults only within these hard bounds. The timeout is optional so
# legacy validated documents (and their provenance digests) keep exactly their existing shape.
CEILINGS: dict[str, tuple[int, int]] = {'max_evidence_items': (1, 20), 'max_evidence_bytes': (256, 65_536),
                                        'max_prompt_bytes': (1_024, 65_536), 'max_completion_tokens': (1, 16_384),
                                        'request_timeout_seconds': (1, 120)}
# Optional request setting; the vocabulary does not imply backend support.
REASONING_EFFORT = 'reasoning_effort'
REASONING_EFFORTS: tuple[str, ...] = ('low', 'medium', 'high', 'xhigh')
MAX_BUDGET_BYTES = 4_096
# The serialised envelope around the payload text: model name, flags, JSON syntax. Measured as an
# allowance so `max_prompt_bytes` means "the whole body", not "the part of it you remembered". The
# caller that writes the body checks the exact figure too; this one is what refuses before one exists.
ENVELOPE_ALLOWANCE_BYTES = 512


class BudgetError(AiError):
    """The bundle does not fit the budget, or it is not evidence this call may use."""

    code = 'budget_exceeded'


def load(path: Path | str | None) -> dict[str, Any]:
    """Return the budget named by *path*, or the shipped defaults when *path* is empty.

    The budget is the one part of this contract that is safe to default: every value makes a call
    *smaller*, so a missing file cannot widen what leaves the host. An explicit effort is preserved;
    a missing file leaves it unset.
    """
    if path is None or (isinstance(path, str) and not path.strip()):
        return dict(DEFAULTS)
    raw = Path(path).read_bytes()
    if len(raw) > MAX_BUDGET_BYTES:
        raise BudgetError(f'{path} exceeds {MAX_BUDGET_BYTES} bytes')
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise BudgetError(f'{path} is not JSON') from exc
    return validate(document)


def validate(document: Any) -> dict[str, Any]:
    """Merge *document* over `DEFAULTS` after checking every key and bound, refusing a stray key.

    Omitting the optional effort preserves the legacy document shape and provenance digest.
    """
    if not isinstance(document, dict):
        raise BudgetError('A budget file must be a JSON object')
    readable = sorted([*CEILINGS, REASONING_EFFORT])
    stray = sorted(set(document) - set(readable))
    if stray:
        raise BudgetError(f'budget file names unknown limits {stray}; this product reads {readable}')
    merged = dict(DEFAULTS)
    merged.update(document)
    if REASONING_EFFORT in merged and (not isinstance(merged[REASONING_EFFORT], str)
                                      or merged[REASONING_EFFORT] not in REASONING_EFFORTS):
        # Rejected values may contain sensitive text; report only the accepted vocabulary.
        raise BudgetError(f'budget {REASONING_EFFORT} must be one of {list(REASONING_EFFORTS)}')
    for name, value in merged.items():
        if name == REASONING_EFFORT:
            continue
        low, high = CEILINGS[name]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            raise BudgetError(f'budget limit {name} must be an integer in {low}..{high}')
    if merged['max_prompt_bytes'] < merged['max_evidence_bytes']:
        raise BudgetError('max_prompt_bytes must be at least max_evidence_bytes: the evidence is part '
                          'of the prompt, and a smaller ceiling there hides which one refused')
    return merged


def payload_bytes(value: Any) -> int:
    """Return the UTF-8 byte length of *value* as this product serialises it (same form as `canonical`)."""
    return len(canonical(value).encode())


def plan(budget: dict[str, Any], items: Sequence[Any], *, prompt_bytes: int,
         now: dt.datetime) -> dict[str, Any]:
    """Return the admitted bundle, or raise `BudgetError` naming the limit or the stale reference.

    *items* are evidence references in the canonical shape (see `REFERENCE_FIELDS`), optionally
    carrying `status`/`sample` as `Store.get_evidence` returned them. *prompt_bytes* is only the
    framing the caller wraps around them — its instruction and header text. The evidence is measured
    here, so a caller that hands over the whole request text charges the bundle twice and refuses a
    body that would have fitted. An empty bundle is refused: an explanation with nothing behind it is
    the failure this whole component exists to make loud.

    The client includes any explicit effort in its subsequent exact request-size check.
    """
    if not isinstance(items, (list, tuple)):
        raise BudgetError('An evidence bundle must be a list of evidence references')
    if not items:
        raise BudgetError('An explanation with no evidence is not an explanation; refusing the call',
                          code='no_evidence')
    if len(items) > budget['max_evidence_items']:
        raise BudgetError(f'{len(items)} evidence references exceed the budget of '
                          f'{budget["max_evidence_items"]}; narrow the window or the selection rather '
                          f'than the ceiling', code='too_many_references')
    for index, item in enumerate(items):
        _reference(item, index=index, now=now)
    evidence_bytes = payload_bytes(items)
    if evidence_bytes > budget['max_evidence_bytes']:
        raise BudgetError(f'{evidence_bytes} bytes of evidence exceed the budget of '
                          f'{budget["max_evidence_bytes"]}; the bundle is refused whole, never '
                          f'truncated into an explanation', code='evidence_bytes')
    body_bytes = evidence_bytes + int(prompt_bytes) + ENVELOPE_ALLOWANCE_BYTES
    if body_bytes > budget['max_prompt_bytes']:
        raise BudgetError(f'a {body_bytes}-byte request body exceeds the budget of '
                          f'{budget["max_prompt_bytes"]}; the bundle is refused whole, never truncated',
                          code='prompt_bytes')
    return {'status': 'ok', 'items': [dict(item) if isinstance(item, dict) else item for item in items],
            'evidence_bytes': evidence_bytes, 'body_bytes': body_bytes,
            'max_completion_tokens': budget['max_completion_tokens']}


def _reference(item: Any, *, index: int, now: dt.datetime) -> None:
    """Check one reference and its freshness; every message names the index, never the payload."""
    if not isinstance(item, dict):
        raise BudgetError(f'evidence reference {index} is not an object', code='invalid_reference')
    keys = set(item)
    if not REFERENCE_FIELDS <= keys or keys - REFERENCE_FIELDS - OPTIONAL_FIELDS:
        raise BudgetError(f'evidence reference {index} must carry exactly {sorted(REFERENCE_FIELDS)} '
                          f'plus at most {sorted(OPTIONAL_FIELDS)}', code='invalid_reference')
    if item['schema_version'] != 1:
        raise BudgetError(f'evidence reference {index} has an unsupported schema_version',
                          code='invalid_reference')
    window = item['window']
    if not isinstance(window, dict) or set(window) != {'start', 'end'}:
        raise BudgetError(f'evidence reference {index} needs a bounded {{start,end}} window',
                          code='invalid_reference')
    try:
        start, end, expires = (timestamp(window['start']), timestamp(window['end']),
                               timestamp(item['expires_at']))
    except (OSError, ValueError, TypeError) as exc:
        raise BudgetError(f'evidence reference {index} carries an unparseable timestamp',
                          code='invalid_reference') from exc
    if not start < end:
        raise BudgetError(f'evidence reference {index} has an empty or reversed window',
                          code='invalid_reference')
    if expires <= end:
        raise BudgetError(f'evidence reference {index} expires at or before the end of its own window; '
                          f'it cannot support a claim about that window', code='invalid_reference')
    status = item.get('status')
    if status is not None and status not in EVIDENCE_STATUSES:
        raise BudgetError(f'evidence reference {index} reports an unknown status', code='invalid_reference')
    if status == 'expired' or expires <= now:
        raise BudgetError(f'evidence reference {index} is expired and is reported as expired: this '
                          f'client holds no store access and re-queries nothing to make an explanation '
                          f'look complete', code='expired_evidence')
    if status == 'unavailable':
        raise BudgetError(f'evidence reference {index} is unavailable; refusing to explain over a '
                          f'hole in the evidence', code='unavailable_evidence')

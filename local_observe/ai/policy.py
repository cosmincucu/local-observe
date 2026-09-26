"""Per-`data_class` generation policy: may a bundle be generated at all, and may it leave the LAN.

remote inference policy is the decision this file exists to obey — *"allow, opt-in, gated as described"*, where "as
described" is *"only for* ***`data_class` below a threshold, with redaction, and clearly labelled in
every output"*. Three words in that sentence are load-bearing and each becomes a rule here, not a
paragraph of documentation:

* **opt-in** — a class with no entry in the policy file is a config error, never an implicit yes, and
  `restricted` may never be sent to an endpoint outside the LAN at all (the threshold, written down);
* **with redaction** — a class may only be marked `remote: true` if it also names the redaction steps
  that run first, and one of them must be `no_free_text`, so "gated" cannot mean "we hope the caller
  scrubbed it" (key-level scrubbing alone leaves whole log lines and operator prose intact);
* **clearly labelled** — a remote-capable class must carry a non-empty `label`, and `client.py` puts
  that label in the output object it returns, not in a comment in the docs.

The posture copies `local_observe/platform/notifications.py:27-28`, which refuses a `restricted`
delivery outright: the same three class names, the same default. This module reads and judges a
document; it performs no request and holds no credential.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from local_observe.ai import AiError
from local_observe.log import is_secret_key

# The same vocabulary `platform/state.py:768` admits on a canonical event. A second classification
# vocabulary would be a second thing to keep honest, and the policy's whole job is to read that field.
DATA_CLASSES: tuple[str, ...] = ('public', 'internal', 'restricted')
CLASS_FIELDS: tuple[str, ...] = ('generate', 'remote', 'redact', 'label')
# The closed set of scrubbing steps `redact` can perform. A name outside it is a config error: a
# policy that silently ignores an unknown step is a policy that promises redaction it does not do.
KNOWN_REDACTIONS: tuple[str, ...] = ('secret_keys', 'no_free_text')
MAX_LABEL_LENGTH = 80
MAX_POLICY_BYTES = 8_192
# A label that survives `no_free_text`: short, one line, and the kind of thing that identifies a
# series or a resource rather than carrying prose an operator or a log line wrote.
MAX_KEEPED_TEXT_LENGTH = 64
REDACTED_PLACEHOLDER = '<redacted>'
FREE_TEXT_PLACEHOLDER = '<withheld:free-text>'


class PolicyError(AiError):
    """The policy refuses this bundle, or the policy file cannot be trusted to decide."""

    code = 'policy_refused'


def load(path: Path | str) -> dict[str, Any]:
    """Read one bounded policy file from *path* and return it validated.

    A missing file raises `OSError`: an install with no policy has no permission, which the caller
    surfaces as a refusal naming the variable rather than as generation that quietly works.
    """
    raw = Path(path).read_bytes()
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f'{path} exceeds {MAX_POLICY_BYTES} bytes')
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise PolicyError(f'{path} is not JSON') from exc
    return validate(document)


def validate(document: Any) -> dict[str, Any]:
    """Return *document* as a policy, or raise `PolicyError`.

    Shape: ``{"schema_version": 1, "classes": {<every one of DATA_CLASSES>: {generate, remote,
    redact, label}}}``. Every class must be named — an omitted class is an undecided class, and this
    product does not decide it on the operator's behalf in either direction.
    """
    if not isinstance(document, dict) or set(document) != {'schema_version', 'classes'}:
        raise PolicyError('A policy file must hold exactly schema_version and classes')
    if document['schema_version'] != 1:
        raise PolicyError('Unsupported policy schema_version (expected 1)')
    classes = document['classes']
    if not isinstance(classes, dict):
        raise PolicyError('policy classes must be an object keyed by data_class')
    missing = sorted(set(DATA_CLASSES) - set(classes))
    unknown = sorted(set(classes) - set(DATA_CLASSES))
    if missing or unknown:
        raise PolicyError(f'policy must decide every data_class of {list(DATA_CLASSES)} '
                          f'(missing {missing}, not understood {unknown})')
    for name in DATA_CLASSES:
        entry = classes[name]
        if not isinstance(entry, dict) or set(entry) != set(CLASS_FIELDS):
            raise PolicyError(f'policy class {name} must hold exactly {list(CLASS_FIELDS)}')
        for flag in ('generate', 'remote'):
            if not isinstance(entry[flag], bool):
                raise PolicyError(f'policy class {name} has a non-boolean {flag}')
        steps = entry['redact']
        if (not isinstance(steps, list) or len(set(steps)) != len(steps)
                or any(step not in KNOWN_REDACTIONS for step in steps)):
            raise PolicyError(f'policy class {name} must name unique steps from {list(KNOWN_REDACTIONS)}')
        label = entry['label']
        if not isinstance(label, str) or len(label) > MAX_LABEL_LENGTH or '\n' in label or '\r' in label:
            raise PolicyError(f'policy class {name} needs a one-line label of at most '
                              f'{MAX_LABEL_LENGTH} characters')
        if entry['remote'] and not (entry['generate'] and label.strip() and steps):
            raise PolicyError(f'policy class {name} may not allow a remote endpoint without generating, '
                              f'a label and at least one redaction step (remote inference policy: redacted and clearly '
                              f'labelled, not merely permitted)')
        if entry['remote'] and 'no_free_text' not in steps:
            raise PolicyError(f'policy class {name} may not allow a remote endpoint without the '
                              f'no_free_text step: with only key-level scrubbing, whole log lines and '
                              f'operator prose would leave the LAN intact, which is not "with redaction"')
        if name == 'restricted' and entry['remote']:
            raise PolicyError('restricted data may never be sent to an endpoint outside the LAN: that '
                              'is remote inference policy\'s threshold, and it is not a knob')
    return {'schema_version': 1, 'classes': {name: dict(document['classes'][name]) for name in DATA_CLASSES}}


def decide(policy: dict[str, Any], data_class: Any, *, out_of_lan: bool) -> dict[str, Any]:
    """Return the decision for one bundle, or raise `PolicyError` with the reason.

    Called **before** any request text exists — that ordering is why the caller passes the
    classification in as its own argument instead of letting this module read it out of the payload.
    *out_of_lan* is the caller's statement of where the configured endpoint lives; it fails closed,
    so anything other than a deliberate "this is on the LAN" is treated as remote (see
    `client.endpoint_out_of_lan`).
    """
    if not isinstance(data_class, str) or data_class not in DATA_CLASSES:
        raise PolicyError(f'data_class {data_class!r} is not one of {list(DATA_CLASSES)}; an '
                          f'unclassified bundle is never classified low enough to generate',
                          code='policy_refused')
    entry = policy['classes'][data_class]
    if not entry['generate']:
        raise PolicyError(f'policy refuses generation for data_class {data_class}; the rules and the '
                          f'operator workflows keep working without it', code='policy_refused')
    if out_of_lan and not entry['remote']:
        raise PolicyError(f'data_class {data_class} may not be sent to an endpoint outside the LAN; '
                          f'set the policy for that class (and note it must then name redaction and a '
                          f'label) or point the client at a local serve', code='remote_refused')
    return {'allowed': True, 'data_class': data_class, 'out_of_lan': out_of_lan,
            'redact': list(entry['redact']), 'label': entry['label'].strip() or None}


def redact(value: Any, steps: list[str]) -> tuple[Any, dict[str, int]]:
    """Return ``(scrubbed_value, counts)`` after applying *steps* in the order the policy named them.

    `secret_keys` replaces the value of any key that names a credential, using the same secret-name
    set the log formatter uses (`local_observe.log.is_secret_key`), so one list decides both.
    `no_free_text` keeps identifiers, numbers, booleans, timestamps and short one-line labels and
    replaces every longer string with a placeholder: what a remote endpoint sees is which resource,
    which window and which count, never a log line or an operator's sentence.
    """
    counts = {step: 0 for step in steps}
    scrubbed = value
    for step in steps:
        if step not in KNOWN_REDACTIONS:
            raise PolicyError(f'unknown redaction step {step!r}; this product knows {list(KNOWN_REDACTIONS)}')
        scrubbed, changed = _STEP[step](scrubbed)
        counts[step] = changed
    return scrubbed, counts


def _secret_keys(value: Any) -> tuple[Any, int]:
    """Replace credential-named entries at any depth; return the number of entries removed."""
    if isinstance(value, dict):
        total = 0
        result: dict[str, Any] = {}
        for key, item in value.items():
            if is_secret_key(key):
                result[str(key)] = REDACTED_PLACEHOLDER
                total += 1
            else:
                child, changed = _secret_keys(item)
                result[str(key)] = child
                total += changed
        return result, total
    if isinstance(value, (list, tuple)):
        items = [_secret_keys(item) for item in value]
        return [item for item, _count in items], sum(count for _item, count in items)
    return value, 0


def _free_text(value: Any) -> tuple[Any, int]:
    """Replace long or multi-line strings with a placeholder, keeping bounded single-line labels."""
    if isinstance(value, str):
        keepable = (len(value) <= MAX_KEEPED_TEXT_LENGTH and value == value.strip()
                    and '\n' not in value and '\r' not in value)
        return (value, 0) if keepable else (FREE_TEXT_PLACEHOLDER, 1)
    if isinstance(value, dict):
        total = 0
        result: dict[str, Any] = {}
        for key, item in value.items():
            child, changed = _free_text(item)
            result[str(key)] = child
            total += changed
        return result, total
    if isinstance(value, (list, tuple)):
        items = [_free_text(item) for item in value]
        return [item for item, _count in items], sum(count for _item, count in items)
    return value, 0


_STEP = {'secret_keys': _secret_keys, 'no_free_text': _free_text}

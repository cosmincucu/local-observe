"""GenAI-named call records for the AI plane; prompt and response bodies stay out (chat integration).

The records carry the attribute *names* the OTLP GenAI semantic conventions use
(`gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, …) so a store query
reads the same way whichever transport eventually carries it. What they are **not** is OTLP spans:
this repository ships no span exporter (stdlib has no protobuf encoder and `pyproject.toml` may not
gain a dependency without an entry in `docs/DECISIONS.md`), so these are structured log lines that
travel the path the product already has — container `json-file` log → the Linux collector → the
store's log table under the configured retention policy (14 days for logs by default).
The component contract describes the limits of log-based telemetry.

Two invariants hold regardless of what a caller asks for:

* identifiers, counts, statuses and durations only, never bodies — until `LO_AI_CAPTURE=1`, and even
  then a bounded excerpt (see `MAX_CAPTURE_CHARS`) rather than a transcript;
* a refusal is a recorded outcome. Nothing in this package fails quietly: an operator who asked for
  an explanation and got the rule floor must be able to find the line that says which gate closed.
"""
from __future__ import annotations

from typing import Any

from local_observe.log import get_logger

log = get_logger(__name__)

# The logger bounds every scalar at 300 characters (`local_observe/log.py:38`), so a longer slice
# here would be cut by the formatter anyway and would read as a promise the transport does not keep.
MAX_CAPTURE_CHARS = 300
OPERATION = 'chat'
PROVIDER = 'llama.cpp'


def call(*, status: str, code: str | None = None, provider: str = PROVIDER, model: str,
         slot: str, response_model: str | None = None, usage: dict[str, Any] | None = None,
         data_class: str, out_of_lan: bool, evidence_count: int, evidence_bytes: int | None,
         duration_ms: int, capture: bool, redacted: dict[str, int] | None = None,
         endpoint_status: int | None = None, prompt_excerpt: str | None = None,
         response_excerpt: str | None = None) -> None:
    """Emit exactly one record for one generation attempt (successful or refused).

    Nothing returned, nothing raised: an unemitable value is bounded by the log formatter, and a
    logging failure must never become a generation failure. *prompt_excerpt* and *response_excerpt*
    are dropped unless the caller passes ``capture=True``, which is the operator's explicit
    `LO_AI_CAPTURE=1` decision and nothing else.

    `evidence_bytes` is ``null`` when the call never reached the stage that measures a bundle: a
    policy or capability refusal has no request size, and writing `0` there would make a gate look
    like a one-byte call.
    """
    fields: dict[str, Any] = {
        'gen_ai.operation.name': OPERATION,
        'gen_ai.provider.name': provider,
        'gen_ai.request.model': model,
        'gen_ai.usage.input_tokens': (usage or {}).get('input_tokens'),
        'gen_ai.usage.output_tokens': (usage or {}).get('output_tokens'),
        'status': status,
        'data_class': data_class,
        'slot': slot,
        'out_of_lan': out_of_lan,
        'evidence_count': evidence_count,
        'evidence_bytes': evidence_bytes,
        'duration_ms': duration_ms,
        'capture': capture,
    }
    if response_model:
        fields['gen_ai.response.model'] = response_model
    if redacted:
        fields['redaction_counts'] = dict(redacted)
    if code:
        fields['refusal'] = code
    if endpoint_status is not None:
        # A status code is a number the endpoint chose, not payload: it says whether the refusal was
        # the serve refusing, loading, or a proxy in the way, and it is the first thing to grep.
        fields['http_status'] = endpoint_status
    if capture:
        if prompt_excerpt is not None:
            fields['capture_prompt'] = prompt_excerpt[:MAX_CAPTURE_CHARS]
        if response_excerpt is not None:
            fields['capture_response'] = response_excerpt[:MAX_CAPTURE_CHARS]
    if status == 'ok':
        log.info('AI generation attempted', extra=fields)
    else:
        # A refusal is loud on purpose: "the explanation is missing" and "the explanation was refused"
        # are different operator questions and only this line distinguishes them later.
        log.warning('AI generation attempted', extra=fields)


def capture_enabled(raw: Any) -> bool:
    """Whether the environment turns payload capture on — only the exact string ``1`` does.

    The default is off (chat integration) and a value that is not exactly ``1`` is off too, so an operator who
    writes ``true``, ``yes`` or ``0`` gets the safe reading rather than the one a loose truthiness
    test would give them.
    """
    return isinstance(raw, str) and raw == '1'

"""The stdlib-only chat-completions client for the optional `ai` component.

One job: turn a caller's instruction plus an evidence bundle into one OpenAI-compatible
`POST /v1/chat/completions` against a serve the operator pointed at, and return an object that says
honestly where the text came from. Everything that could make an explanation look better than the
evidence behind it is refused *before* the request exists, in this order:

1. `policy.decide` — the caller hands `data_class` in as its own argument, so the class is decided
   before any request text is built (a bundle that arrives unclassified is refused, not assumed low);
2. `capability.require` — a capability the manifest marks `unknown` or `false` is unusable, which
   includes the context window itself, so nothing in a request is sized from a model card;
3. `policy.redact` — the class's scrubbing steps run over the instruction and the bundle;
4. `budget.plan` — bytes, reference count and freshness; expired evidence is reported as expired.

Then, and only then, the body is serialised and sent: **one** attempt, no ambient retry (a generation
has no idempotency key, and a timed-out explanation retried is two explanations), one bounded
response read, and remote inference policy's label on the output object whenever the endpoint may have seen the bundle.

No module outside `local_observe/ai/` may import this one, and this one imports no store, no query
builder and no state database — the structural half of "never re-query the store to make an
explanation look complete".
"""
from __future__ import annotations

import datetime as dt
import os
import time
from typing import Any
import urllib.parse
import uuid

from local_observe.ai import AiError
from local_observe.ai import budget as budget_module
from local_observe.ai import capability as capability_module
from local_observe.ai import policy as policy_module
from local_observe.ai import telemetry
from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.inventory.validation import canonical
from local_observe.log import get_logger

log = get_logger(__name__)

EVIDENCE_HEADER = 'Evidence (redacted, canonical JSON references; do not invent beyond it):'

BASE_URL_VARIABLE = 'LO_AI_BASE_URL'
API_KEY_NAME = 'LO_AI_API_KEY'
MODEL_VARIABLE = 'LO_AI_MODEL'
MODEL_FAST_VARIABLE = 'LO_AI_MODEL_FAST'
POLICY_VARIABLE = 'LO_AI_POLICY'
CAPABILITY_VARIABLE = 'LO_AI_CAPABILITY'
BUDGET_VARIABLE = 'LO_AI_BUDGET'
OUT_OF_LAN_VARIABLE = 'LO_AI_OUT_OF_LAN'
CAPTURE_VARIABLE = 'LO_AI_CAPTURE'
# The same switch the Sigma runner and the anomaly producer read: plaintext HTTP is acceptable only
# on a project network the operator controls, and it is never the default.
ALLOW_HTTP_VARIABLE = 'LO_INTERNAL_ALLOW_HTTP'

COMPLETIONS_PATH = '/v1/chat/completions'
# The 64 KiB idiom this repository uses everywhere (`platform/state.py:758` for a canonical event,
# `platform/overview.py:19` for an observation document). The transport underneath reads up to 4 MiB
# before this layer sees anything, so 4 MiB is the real memory bound and 64 KiB is the bound on what
# this client will accept and parse; the difference is stated in components/control/ai/CONTRACT.md
# rather than hidden behind the smaller number.
MAX_RESPONSE_BYTES = 65_536
MAX_MODEL_LABEL = 160
MAX_INSTRUCTION_BYTES = 8_192
SLOTS = ('model', 'model_fast')


class AiNotConfigured(AiError):
    """The component is not deployed: a required variable is missing, empty or malformed.

    Every optional component here is absent by default, so this is the ordinary state on `minimal`
    and on any `standard` install that did not select generation. A caller catches it and stays on
    its own floor — which is the `If disabled` column of the `ai` row in `docs/COMPONENTS.md`.
    """

    code = 'not_configured'


def endpoint_out_of_lan(environ: Any = os.environ) -> bool:
    """Whether the configured endpoint must be treated as outside the LAN.

    It fails closed: only the exact string ``0`` in `LO_AI_OUT_OF_LAN` means "this serve is on my
    network". Unset, empty, ``true``, ``1`` or a typo all mean *assume remote*, because the failure
    this guards is an operator who never set the variable discovering that their evidence left the
    building — not an operator who set it and got a local serve refused.
    """
    return environ.get(OUT_OF_LAN_VARIABLE) != '0'


def required(environ: Any, name: str) -> str:
    """Return a non-empty required variable, or raise `AiNotConfigured` naming it (never its value)."""
    value = environ.get(name)
    if not isinstance(value, str) or not value.strip():
        raise AiNotConfigured(f'{name} is not set; the ai component is not configured and generation is '
                              f'unavailable (rules, incidents, approvals and notifications do not '
                              f'depend on it)')
    return value.strip()


def model_label(value: Any, name: str) -> str:
    """Return *value* as a bounded one-line model identifier, or raise `AiNotConfigured`."""
    if (not isinstance(value, str) or not 1 <= len(value) <= MAX_MODEL_LABEL
            or any(char in value for char in '\r\n\t ')):
        raise AiNotConfigured(f'{name} must be a single-line model identifier of at most '
                              f'{MAX_MODEL_LABEL} characters')
    return value


class AiClient:
    """One serve, one policy, one capability manifest, one budget: the whole AI contract in a class."""

    def __init__(self, *, base_url: str, api_key: str, model: str, capability: dict[str, Any],
                 policy: dict[str, Any], budget: dict[str, int], model_fast: str | None = None,
                 out_of_lan: bool = True, capture: bool = False, allow_http: bool = False,
                 timeout: int = 10, provider: str = telemetry.PROVIDER, transport: Any = None) -> None:
        """Bind the four contract values plus the two documents; refuse a shape that cannot be honest.

        *capability* and *budget* are documents, not paths, and this re-validates them rather than
        trusting that whoever constructed the client read them carefully. *transport* exists so a test
        can hand in a stand-in that counts calls, which is how "nothing was sent" becomes observable
        rather than asserted.
        """
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme not in (('https', 'http') if allow_http else ('https',)) or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ('', '/')):
            raise AiNotConfigured(f'{BASE_URL_VARIABLE} must be a scheme://host[:port] endpoint with no '
                                  f'path, no query and no embedded credential')
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 20:
            raise AiNotConfigured('The AI request timeout must be an integer between 1 and 20 seconds')
        self.model = model_label(model, MODEL_VARIABLE)
        self.model_fast = model_label(model_fast, MODEL_FAST_VARIABLE) if model_fast else self.model
        self.capability = capability_module.validate(capability)
        self.policy = policy_module.validate(policy)
        self.budget = budget_module.validate(budget)
        self.out_of_lan = bool(out_of_lan)
        self.capture = bool(capture)
        self.provider = provider
        self.transport = transport or JsonClient(base_url, api_key, allow_http=allow_http, timeout=timeout)

    @classmethod
    def from_environment(cls, environ: Any = os.environ) -> AiClient:
        """Build the client from the `LO_AI_*` contract, or raise `AiNotConfigured` naming what is missing.

        The bearer value arrives through `local_observe.credentials.read_credential`, which prefers
        `LO_AI_API_KEY_FILE` (a mounted secret) over the environment value; it must be at least 24
        characters, because `local_observe/http.py` requires that of every credential it will send.
        """
        capability_path = required(environ, CAPABILITY_VARIABLE)
        policy_path = required(environ, POLICY_VARIABLE)
        capture = telemetry.capture_enabled(environ.get(CAPTURE_VARIABLE))
        if capture:
            log.warning('AI payload capture is enabled; prompt and response excerpts become log '
                        'records in the telemetry store', extra={'variable': CAPTURE_VARIABLE})
        fast = environ.get(MODEL_FAST_VARIABLE)
        return cls(base_url=required(environ, BASE_URL_VARIABLE),
                   api_key=read_credential(API_KEY_NAME, environ=environ),
                   model=model_label(required(environ, MODEL_VARIABLE), MODEL_VARIABLE),
                   model_fast=fast.strip() if isinstance(fast, str) and fast.strip() else None,
                   capability=capability_module.load(capability_path),
                   policy=policy_module.load(policy_path),
                   budget=budget_module.load(environ.get(BUDGET_VARIABLE)),
                   out_of_lan=endpoint_out_of_lan(environ), capture=capture,
                   allow_http=environ.get(ALLOW_HTTP_VARIABLE) == '1')

    def complete(self, *, instruction: str, data_class: str, evidence: list[dict[str, Any]],
                 slot: str = 'model', json_mode: bool = False, streaming: bool = False,
                 now: dt.datetime | None = None) -> dict[str, Any]:
        """Ask for one grounded explanation, or raise `AiError` naming the gate that refused it.

        *instruction* is the caller's framing text; *evidence* is a bundle of canonical evidence
        references, optionally carrying the `status`/`sample` fields `Store.get_evidence` returns. The
        bundle is redacted per the class's policy before it is measured, and the measured body is what
        is sent: no later step enlarges what the budget already read.
        """
        if slot not in SLOTS:
            raise AiError(f'slot {slot!r} is not one of {list(SLOTS)}', code='invalid_slot')
        if not isinstance(instruction, str) or not instruction.strip():
            raise AiError('An instruction is required; a bare bundle of evidence is not a question',
                          code='invalid_instruction')
        if len(instruction.encode()) > MAX_INSTRUCTION_BYTES:
            raise AiError(f'an instruction over {MAX_INSTRUCTION_BYTES} bytes is not a question an '
                          f'operator can read either', code='invalid_instruction')
        started = dt.datetime.now(dt.timezone.utc)
        began = time.monotonic()
        try:
            decision, text, bundle, counts = self._gates(data_class=data_class, instruction=instruction,
                                                         evidence=evidence, json_mode=json_mode,
                                                         streaming=streaming)
        except AiError as exc:
            # A refusal before a request existed is still an answer the operator has to be able to
            # find. Recorded with the class and the count, never with the instruction: the redaction
            # that would have made it safe to quote ran in the stage that just refused.
            self._emit(data_class=data_class, model=self.model_for(slot), slot=slot, status='refused',
                       code=exc.code, plan=None, counts={}, began=began)
            raise
        content = f'{text}\n\n{EVIDENCE_HEADER}\n{canonical(bundle)}'
        try:
            plan = budget_module.plan(self.budget, bundle, prompt_bytes=len(content.encode()),
                                      now=now or started)
            payload: dict[str, Any] = {'model': self.model if slot == 'model' else self.model_fast,
                                       'messages': [{'role': 'user', 'content': content}],
                                       'max_tokens': plan['max_completion_tokens'], 'stream': False}
            if json_mode:
                payload['response_format'] = {'type': 'json_object'}
            if budget_module.payload_bytes(payload) > self.budget['max_prompt_bytes']:
                raise AiError('the serialised request body exceeds max_prompt_bytes once written; the '
                              'bundle is refused whole, never truncated', code='prompt_bytes')
        except AiError as exc:
            self._emit(data_class=decision['data_class'], model=self.model_for(slot), slot=slot,
                       status='refused', code=exc.code, plan=None, counts=counts, began=began)
            raise
        return self._attempt(payload, plan, decision=decision, counts=counts, slot=slot,
                              instruction=text, started=started, began=began)

    def model_for(self, slot: str) -> str:
        """Return the model id a request in *slot* would name — for records written before one exists."""
        return self.model if slot == 'model' else self.model_fast

    def _gates(self, *, data_class: str, instruction: str, evidence: list[dict[str, Any]],
               json_mode: bool, streaming: bool) -> tuple[dict[str, Any], str, Any, dict[str, int]]:
        """Run policy, then capability, then redaction: everything that may refuse before any counting."""
        decision = policy_module.decide(self.policy, data_class, out_of_lan=self.out_of_lan)
        capability_module.require(self.capability, 'context_tokens')
        if streaming:
            # Upstream can stream; this client deliberately cannot, so the manifest is not even asked.
            raise AiError('this client reads one bounded response; streaming is not supported by the '
                          'client whatever the manifest measures', code='streaming_unsupported')
        if json_mode:
            capability_module.require(self.capability, 'json_mode')
        counts: dict[str, int] = {}
        text, changed = policy_module.redact(instruction, decision['redact'])
        for step, count in changed.items():
            counts[step] = counts.get(step, 0) + count
        bundle, changed = policy_module.redact(list(evidence), decision['redact'])
        for step, count in changed.items():
            counts[step] = counts.get(step, 0) + count
        return decision, text, bundle, counts

    def _attempt(self, payload: dict[str, Any], plan: dict[str, Any], *, decision: dict[str, Any],
                 counts: dict[str, int], slot: str, instruction: str, started: dt.datetime,
                 began: float) -> dict[str, Any]:
        """Send the one permitted attempt and turn the reply into a result object that labels itself."""
        model = payload['model']
        try:
            status, body = self.transport.request('POST', COMPLETIONS_PATH, payload=payload)
        except TransportError as exc:
            self._emit(data_class=decision['data_class'], model=model, slot=slot, status='refused',
                       code='endpoint_unavailable', plan=plan, counts=counts, began=began,
                       instruction=instruction)
            raise AiError('the model endpoint did not answer; nothing was retried',
                          code='endpoint_unavailable') from exc
        if status not in (200, 201):
            self._emit(data_class=decision['data_class'], model=model, slot=slot, status='refused',
                       code='endpoint_status', plan=plan, counts=counts, began=began,
                       instruction=instruction, endpoint_status=status)
            raise AiError(f'the model endpoint answered {status}; nothing was retried',
                          code='endpoint_status')
        if budget_module.payload_bytes(body) > MAX_RESPONSE_BYTES:
            self._emit(data_class=decision['data_class'], model=model, slot=slot, status='refused',
                       code='response_too_large', plan=plan, counts=counts, began=began,
                       instruction=instruction)
            raise AiError(f'a response larger than {MAX_RESPONSE_BYTES} bytes is refused unread; an '
                          f'explanation that size is not grounded in the bundle that was sent',
                          code='response_too_large')
        try:
            content, finish, usage, response_model = parse_reply(body)
        except AiError as exc:
            self._emit(data_class=decision['data_class'], model=model, slot=slot, status='refused',
                       code=exc.code, plan=plan, counts=counts, began=began, instruction=instruction)
            raise
        if response_model and response_model != model:
            # The serve answered as a different model than the one asked for. llama.cpp reports the
            # weight path unless --alias names it (tools/server/README.md:191,1253 at v0.4.0), so this
            # is what a lost --alias looks like: a name nobody pinned. Refusing here is cheaper than an
            # explanation attributed to the wrong model.
            self._emit(data_class=decision['data_class'], model=model, slot=slot, status='refused',
                       code='model_mismatch', plan=plan, counts=counts, began=began,
                       instruction=instruction, response_model=response_model)
            raise AiError(f'the endpoint answered as {response_model!r}, not the configured model; '
                          f'an explanation attributed to the wrong model is not evidence',
                          code='model_mismatch')
        label = decision['label'] if self.out_of_lan else None
        self._emit(data_class=decision['data_class'], model=model, slot=slot, status='ok', code=None,
                   plan=plan, counts=counts, began=began, instruction=instruction, usage=usage,
                   response_model=response_model, content=content)
        return {'status': 'ok', 'call_id': uuid.uuid4().hex, 'model': model,
                'response_model': response_model, 'slot': slot, 'content': content,
                'display_text': f'{label}\n{content}' if label else content, 'label': label,
                'out_of_lan': self.out_of_lan, 'data_class': decision['data_class'],
                'finish_reason': finish, 'usage': usage, 'evidence_count': len(plan['items']),
                'evidence_bytes': plan['evidence_bytes'], 'redaction_counts': counts,
                'capture': self.capture}

    def _emit(self, *, data_class: Any, model: str, slot: str, status: str, code: str | None,
              plan: dict[str, Any] | None, counts: dict[str, int], began: float,
              instruction: str | None = None, usage: dict[str, Any] | None = None,
              response_model: str | None = None, endpoint_status: int | None = None,
              content: str | None = None) -> None:
        """Emit the one call record for this attempt; bodies only when the operator enabled capture.

        *plan* is absent for a refusal that happened before a bundle was measured: the count and the
        byte size of a request that was never built are not facts, and inventing zeros for them would
        make a gate refusal look like a call.
        """
        telemetry.call(status=status, code=code, provider=self.provider, model=model, slot=slot,
                       response_model=response_model, usage=usage, data_class=data_class,
                       out_of_lan=self.out_of_lan,
                       evidence_count=len(plan['items']) if plan else 0,
                       evidence_bytes=plan['evidence_bytes'] if plan else None,
                       duration_ms=max(int((time.monotonic() - began) * 1000), 0), capture=self.capture,
                       redacted=counts, endpoint_status=endpoint_status,
                       prompt_excerpt=instruction if self.capture else None,
                       response_excerpt=content if self.capture else None)


def parse_reply(body: Any) -> tuple[str, str, dict[str, Any], str | None]:
    """Pull ``(content, finish_reason, usage, response model)`` from one OpenAI-style reply or refuse.

    An absent or malformed reply is a refusal, never an empty success: `docs/CONTRACTS.md` §2 states
    that a failed query must not return the same envelope as an empty result, and a model that
    produced no text has produced no explanation.
    """
    if not isinstance(body, dict) or not isinstance(body.get('choices'), list) or not body['choices']:
        raise AiError('the model endpoint returned no choices; an explanation was not produced',
                      code='malformed_response')
    choice = body['choices'][0]
    if not isinstance(choice, dict) or not isinstance(choice.get('message'), dict):
        raise AiError('the model endpoint returned a choice with no message; an explanation was not '
                      'produced', code='malformed_response')
    content = choice['message'].get('content')
    if not isinstance(content, str) or not content.strip():
        raise AiError('the model returned no content; an empty explanation is not an explanation',
                      code='empty_content')
    finish = choice.get('finish_reason')
    usage_raw = body.get('usage') if isinstance(body.get('usage'), dict) else {}
    usage = {'input_tokens': token_count(usage_raw.get('prompt_tokens')),
             'output_tokens': token_count(usage_raw.get('completion_tokens'))}
    response_model = body.get('model') if isinstance(body.get('model'), str) else None
    return content, (finish if isinstance(finish, str) else 'unknown'), usage, response_model


def token_count(value: Any) -> int | None:
    """Return a token count, or ``None`` when the endpoint did not supply one — unknown is not zero."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


__all__ = ['AiClient', 'AiError', 'AiNotConfigured', 'COMPLETIONS_PATH', 'MAX_RESPONSE_BYTES', 'SLOTS',
           'endpoint_out_of_lan', 'parse_reply']

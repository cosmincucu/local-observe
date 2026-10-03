# llama.cpp serve — optional component `ai`

Status: **experimental, never run**. Nothing in this directory has been started against a Docker
daemon, no weights have been loaded and no model has answered a request from this manifest. What
follows separates three different things deliberately: what upstream documents, what was read in the
pinned tag's source, and what nobody has measured. `conformance.md` lists what has to happen before
this row can be called validated.

The serve is **optional by construction**: no shipped example includes this manifest. deployment baseline/hardware baseline set the
reference host at 16 GB and say anything smaller is the user's risk, which is why the component is
absent-by-default rather than small-by-default — a `minimal` install must not even be able to ask for
an image it cannot run.

## 1. What this component is, and the contract it implements

One container that turns a text prompt plus a bounded evidence bundle into generated text, for the
consumers that opt in: rca's explanation (investigation component) and chat (chat integration). Rules, incidents, approvals and
notifications never learn it exists (`docs/COMPONENTS.md`, the `ai` row: *"Rules and operator
workflows work without generation"*).

`docs/ARCHITECTURE.md` §3.4 names the contract `AI_BASE_URL`, `AI_API_KEY`, `AI_MODEL`,
`AI_MODEL_FAST` and `AI_POLICY`, plus a capability manifest. **This component ships those as
`LO_AI_*` and one name is renamed for a reason:**

| Architecture name | Shipped as | Why the difference |
|---|---|---|
| `AI_BASE_URL` | `LO_AI_BASE_URL` | the product prefix every other variable uses |
| `AI_API_KEY` | `LO_AI_API_KEY_FILE` | the credential must arrive as a mounted file, never an environment value |
| `AI_MODEL` / `AI_MODEL_FAST` | `LO_AI_MODEL` / `LO_AI_MODEL_FAST` | unchanged in meaning; `model_fast` is the rerank/summarise slot model capabilities named |
| `AI_POLICY` | `LO_AI_POLICY` | a path to the policy file, not the policy itself |
| — | `LO_AI_CAPABILITY` | the capability manifest file the §3.4 sentence promises |
| — | `LO_AI_BUDGET`, `LO_AI_OUT_OF_LAN`, `LO_AI_CAPTURE` | the budget, the locality declaration and the capture switch |

The prefix is not decoration. `scripts/check_foundation.py`'s credential rule (`check_credential_files`)
polices variables matching `^LO_[A-Z0-9_]+$` whose name *ends* in `_TOKEN`, `_PASSWORD` or `_SECRET`.
A bare `AI_API_KEY` in an `environment:` block is invisible to that gate on **both** counts — wrong
prefix and wrong suffix — so shipping the architecture's literal name would put a credential outside
the one job that checks credentials. `LO_AI_API_KEY_FILE` is inside the pattern's reach in shape but
not in name (`API_KEY` is not one of the three suffixes), so two things are true at once and both are
stated: the gate does not police this variable, and the manifest therefore carries a **path** under
`secrets:` and never a value, which is the part a gate could not check anyway. Extending the pattern
with `_API_KEY` is a separate change with its own argument, not a side effect of this one.

| Variable | Read by | What it does | If unset |
|---|---|---|---|
| `LO_AI_IMAGE` | compose | the serve image, digest-pinned | `config` fails: no image is guessed |
| `LO_AI_MODEL_DIR` | compose | host directory holding the GGUF weights, mounted read-only at `/models` | `config` fails; `create_host_path: false` makes a missing directory a boot failure, not an empty mount |
| `LO_AI_MODEL_FILE` | compose | the weights file's name inside that directory | `config` fails |
| `LO_AI_MODEL` | compose (`--alias`), client | the id the API answers to | `config` fails; without `--alias` the API reports the weight path, and the client's own check that it asked for what it was given stops meaning anything |
| `LO_AI_CTX_SIZE` | compose (`--ctx-size`) | the context the serve is built with | `config` fails; must equal the manifest's `context_tokens` |
| `LO_AI_MEM_LIMIT` | compose | container memory ceiling: weights + KV cache + headroom | `config` fails — see "Memory" below |
| `LO_AI_API_KEY_FILE` | compose secret | a file with one API key per line | `config` fails |
| `LO_AI_CAPABILITY` | `local_observe/ai/client.py`, the overview worker | the measured capability manifest | the client raises `not_configured`; nothing generates |
| `LO_AI_POLICY` | client | the per-`data_class` policy | same: a missing policy is no permission |
| `LO_AI_BUDGET` | client | optional ceilings on one request | shipped defaults apply (they only ever make a call smaller) |
| `LO_AI_MODEL_FAST` | client | the rerank/summarise slot | falls back to `LO_AI_MODEL`, recorded as `slot` in the call record |
| `LO_AI_OUT_OF_LAN` | client | the operator's statement that the endpoint is inside the LAN | **treated as remote** — only the exact `0` means local, so the safe reading is the one an operator gets by default |
| `LO_AI_CAPTURE` | client | payload capture | off (chat integration); only the exact `1` turns it on |
| `LO_INTERNAL_ALLOW_HTTP` | client | permits a plaintext `http://` base URL on the project network | refused: an `http://` base URL is rejected by default |

## 2. Upstream: what was read, and what was not verified

Read on **2026-09-08** against the pinned tag. Nothing here was measured on a host.

| Claim | Source, at tag `v0.4.0` |
|---|---|
| Release `v0.4.0` exists and was published `2026-09-04T19:56:47Z` | <https://github.com/ggml-org/llama.cpp/releases/tag/v0.4.0> and the GitHub API `repos/ggml-org/llama.cpp/releases/tags/v0.4.0` `published_at` |
| `ghcr.io/ggml-org/llama.cpp:server` "only includes the `llama-server` executable", platforms `linux/amd64`, `linux/arm64`, `linux/s390x` | [docs/docker.md:12](https://github.com/ggml-org/llama.cpp/blob/v0.4.0/docs/docker.md) |
| The image installs `curl` and its `server` stage declares `HEALTHCHECK CMD ["curl","-f","http://localhost:8080/health"]`, sets `ENV LLAMA_ARG_HOST=0.0.0.0` and ends `ENTRYPOINT ["/app/llama-server"]`; there is no `USER` line, so it runs as root unless the manifest says otherwise | [.devops/cpu.Dockerfile:56-127](https://github.com/ggml-org/llama.cpp/blob/v0.4.0/.devops/cpu.Dockerfile) |
| `--host` defaults to `127.0.0.1`, `--port` to `8080` | [tools/server/README.md:194-195](https://github.com/ggml-org/llama.cpp/blob/v0.4.0/tools/server/README.md) |
| `GET /health` "is public (no API key check)"; 200 `{"status":"ok"}` when ready, 503 while the model loads | tools/server/README.md:472-483 |
| `--api-key-file FNAME` takes keys "one per line", `#` starts a comment | tools/server/README.md:215 |
| `POST /v1/chat/completions` is the OpenAI-compatible surface; the reply carries `usage.prompt_tokens` / `usage.completion_tokens` | tools/server/README.md:1310, 1425-1437 |
| `-a, --alias STRING` sets the model id the API reports; by default the id **is the `-m` model path** | tools/server/README.md:191, 1253 |
| `--tools` enables `read_file`, `write_file`, `edit_file`, `exec_shell_command` and is labelled "experimental … do not enable in untrusted environments" | tools/server/README.md:206 |
| `--no-webui`, `--no-slots`, `-c/--ctx-size` (default 0 = from model), `-np/--parallel` (default auto) exist | tools/server/README.md:211, 226, 50, 178 |

**UNVERIFIED — do not read a pin in the missing place.** The registry's own tag list, read the same
day through ghcr.io's anonymous pull token, contains `server` and build tags from `server-b4729` to
`server-b5350` and **no tag naming a release**. Nothing in that list says which build carried
`v0.4.0`, so `versions.json` records the release, the tag, the date and a `null` digest, and the
operator resolves the digest for the build they actually run. `server` is a moving tag: pinning it by
name in an environment file is how a capability manifest ends up describing a different binary.

**UNVERIFIED:** which HTTP header the serve accepts for a configured API key. `tools/server/README.md`
documents `--api-key`/`--api-key-file` and shows `Authorization: Bearer …` in its OpenAI examples, but
does not state the header it checks. The product client presents `Authorization: Bearer`
(`local_observe/http.py`); step 3 of `conformance.md` is the command that proves it.

**UNVERIFIED:** whether the serve answers the product client at all. No request has been sent.

## 3. Weights and memory

Weights are overlay-owned: never in git, never fetched by a service at boot, never in the checkout.
They arrive as `${LO_AI_MODEL_DIR}`, a directory only the operator creates, mounted read-only with
`create_host_path: false` (the full example gaps argument for Dagu's DAG directory, same reason: a missing
directory should stop the boot, not silently mount an empty one — here the silent version is a serve
whose model does not exist).

model capabilities took llama.cpp as the *server*; the model itself is a deployment choice recorded per component,
not a product constant. For example, Qwen3-30B-A3B uses Apache-2.0 licensing, and a
4-bit quantisation of a 30B-class MoE is roughly 18-20 GB of weights — **larger than the 16 GB
reference floor of hardware baseline before the KV cache, the OS or the store is counted.** So the honest
statement is a floor with a number in it:

| Deployment | What it can hold |
|---|---|
| `minimal` (hardware baseline: 16 GB) | nothing from this component — and it needs nothing, it is absent by default |
| `standard`/`full` on 16 GB | a 6-8 GB quantisation at a small context, single-slot, tens of seconds per explanation on CPU; `measured_tok_per_s` decides whether that is usable, not this table |
| a host with a GPU and a CUDA/Vulkan build of the same image | the same manifest with a different `LO_AI_IMAGE`; the capability manifest, not this file, is where the difference is recorded |

`mem_limit` is required rather than defaulted because both directions of the guess are bad: too low
and the container is OOM-killed during model load, which looks like a broken model; unset and one
typo costs the host. Set it to at least the weight file's size plus
`context_tokens × bytes-per-token-for-this-model's-KV` plus headroom, and measure the middle term
once — the manifest records it.

## 4. The capability manifest: `LO_AI_CAPABILITY`

A JSON file with `schema_version: 1` and exactly the eight fields
`context_tokens, tools, json_mode, streaming, vision, parallel, quant, measured_tok_per_s`. Every
field is the literal string `"unknown"` until something measures it, and one rule governs every
consumer, stated once in `local_observe/ai/capability.py`:

> **a consumer may not use a capability the manifest marks `unknown` or `false`.**

The consequence is that a fresh install generates nothing at all. That is the design working, not a
defect: without it, rca sizes a context budget from a model card and the failure surfaces much later
as an explanation whose evidence was quietly truncated. `components/control/ai/capability.example.json`
ships every field `unknown`, which is the only honest state for a model this repository has not run.

How each field becomes measured — all of it measured against *this* serve, *these* weights, *this* host:

| Field | How to measure it | What "unknown" protects against |
|---|---|---|
| `context_tokens` | the `--ctx-size` you passed, confirmed by the serve accepting a prompt that fills it (`GET /slots` is disabled here, so confirm by request, not by introspection) | inventing a budget; silent truncation of evidence |
| `tools` | **not measurable in this deployment**: the manifest never passes `--tools`, and `capability.validate` refuses `true` outright | treating a chat endpoint as an agent with file and shell access |
| `json_mode` | one `response_format: {"type":"json_object"}` request that returns parseable JSON | a caller that branches on JSON it did not get |
| `streaming` | a `stream: true` request and a chunked read | this client cannot consume a stream, so it refuses `streaming=True` regardless of the manifest |
| `vision` | an image part accepted on a multimodal build | promising image evidence to a text-only build |
| `parallel` | the slot count the serve came up with (`-np`, default auto) | two callers overwriting one context |
| `quant` | the quantisation in the file name you chose, read from the GGUF metadata | a token/s number carried across quantisations |
| `measured_tok_per_s` | timed generation on this host, cold and warm, both recorded; one number is a median of your own runs, `n` stated | every latency claim an operator makes to their phone |

No field may be inherited from a model card. The tile and every call record carry **statuses**, never
values (`capability.summarise`), so an operator can see *which* half is unmeasured.

## 5. The policy: `LO_AI_POLICY`

A JSON file deciding, per `data_class` — the same three names `local_observe/platform/state.py:768`
admits on a canonical event (`public`, `internal`, `restricted`) — whether generation happens at all,
whether an endpoint **outside the LAN** may see the bundle (remote inference policy), and what redaction runs first.
Every class must be named: an undecided class is a config error, never an implicit yes.

`validate` enforces the parts of remote inference policy that must not be optional:

* a class may be `remote: true` only with a non-empty `label`, at least one redaction step, and
  `no_free_text` among them — with only key-level scrubbing, whole log lines and operator prose would
  leave the building intact, which is not "with redaction";
* **`restricted` may never be `remote: true`** — that is remote inference policy's threshold written into code, and it is
  not a knob. `restricted` generation is refused by default even locally (the shipped example says
  `generate: false`), which copies the posture `platform/notifications.py:27-28` takes for restricted
  deliveries;
* an unknown or missing `data_class` is refused: an unclassified bundle is never classified low
  enough to generate.

Redaction steps are a closed set — `secret_keys` (values under credential-named keys, using the same
secret-name set as the log formatter, `local_observe.log.is_secret_key`) and `no_free_text` (short
one-line labels, numbers and identifiers survive; longer or multi-line strings become a placeholder).
The class decides, not the wire: a class's steps run on every call, local included, because they
describe the data.

Where the labelling lands: `client.complete()` returns `label` and `display_text`, and when the
endpoint may have seen the bundle `display_text` is the label on its own line above the text. A
consumer that renders `content` instead of `display_text` has removed the indication remote inference policy asked for;
`tests/test_ai_client.py` asserts the shape, and investigation component/chat integration must read `display_text`.

## 6. The evidence budget

`LO_AI_BUDGET` names an optional JSON file; its limits replace the shipped defaults within
hard ceilings: `max_evidence_items` 20 (the same twenty `platform/state.py:778` allows on one
event), `max_evidence_bytes` 16 KiB (ceiling 64 KiB), `max_prompt_bytes` 24 KiB (ceiling 64 KiB),
`max_completion_tokens` 512 (ceiling 8 192). A bundle that does not fit is **refused whole, never
truncated** — a truncated bundle is an explanation whose missing half nobody can see.

An optional `request_timeout_seconds` integer from 1 to 120 sets the AI transport timeout.
When absent, the timeout remains 10 seconds and an explicit client override may be at most
20 seconds. When present, a client override may only shorten it. Existing budget documents
retain their validated shape and provenance digest. Other HTTP clients keep their existing
defaults. This is a socket timeout, not a total elapsed-time guarantee; the observer also
checks its cycle deadline. Each generation still makes one attempt, without retries.

Reasoning models may spend their completion allowance before producing an answer. Measure
the chosen model with representative evidence before selecting explicit token and timeout
limits; a larger allowance does not guarantee a usable answer. The response byte limit
below applies independently.

**Two measurements, one ceiling.** `max_prompt_bytes` means the whole serialised body, so it is
checked twice before anything is sent. `budget.plan` measures the evidence itself and is handed only
the bytes the caller wraps around it (the instruction and the evidence header) plus a fixed envelope
allowance; the client then measures the exact serialised request against the same ceiling. The two
gates cannot be collapsed into one number: JSON escaping grows the text a second time — a quote, a
backslash and a non-ASCII character each cost more bytes once the canonical evidence is embedded as a
string inside the body — and an allowance is an allowance. A request sized only by the estimate either
refuses a bundle that would have fitted or sends a body over the ceiling. Both refusals report
`prompt_bytes`, and neither builds a request.

**Response bound, honestly stated.** `client.py` refuses a reply whose parsed body exceeds
`MAX_RESPONSE_BYTES` = 65 536 (the 64 KiB idiom used across this repository). The transport
underneath — `JsonClient.request`, `local_observe/http.py:120-122`, shared by every client here —
reads up to 4 MiB before returning it, so 4 MiB is this process's real memory bound and 64 KiB is the
bound on what the AI layer will accept and parse. Raising the smaller number to match the larger
would be the wrong direction; a dedicated bounded transport is not worth one component and
`DEPENDENCIES.md` forbids a second HTTP client.

## 7. Telemetry, and what payload capture actually does

The integration defaults are: capture **off** by default, LLM telemetry into the
existing store. Each attempt emits exactly one structured record from `local_observe/ai/telemetry.py`
carrying the OTLP GenAI *attribute names* (`gen_ai.operation.name`, `gen_ai.provider.name`,
`gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`,
`gen_ai.usage.output_tokens`) plus status, refusal code, `data_class`, whether the endpoint was
outside the LAN, evidence count and bytes, redaction counts and duration.

For `incomplete_response`, the endpoint reported truncated output without answer text. Its
validated `prompt_tokens` and `completion_tokens` are retained in the refusal record. Other
refusals keep both counters `null`. Boolean, fractional, string and negative counters remain
unknown; reasoning text is never recorded.

**These are log records, not OTLP spans.** The product has no span
exporter (no protobuf encoder in the standard library, and `pyproject.toml` may not gain a dependency
without an entry in `docs/DECISIONS.md`). Accepting the substitution is the reviewer's call, recorded
against AI integration. The path the records take is the one that already exists: container `json-file` log →
the Linux collector's configured log source → the store's log table.

Where captured bodies land, when an operator sets `LO_AI_CAPTURE=1`: the same log line, as
`capture_prompt` and `capture_response`, sliced to 300 characters here because
`local_observe/log.py:38` bounds every scalar at 300 — a longer slice would be cut by the formatter
and would read as a promise the transport does not keep. From there they sit in the store's logs with
the configured log retention policy (**14 days** by default),
inside the volume's reach and readable by anyone who can open the SigNoz UI or query ClickHouse with
the read credentials — including the read-only `lo-query` user, which cannot write but can select.
Turning capture on is therefore a decision about who reads prompts, not a debugging switch: it logs a
`WARNING` naming the variable at construction, and the container log caps (`max-size 5m`,
`max-file 2`) mean a busy capture overwrites itself within minutes, which is a further reason not to
leave it on.

## 8. Why nothing is published

`check_foundation.py`'s `HOST_PUBLISHED_SERVICES` names the services an operator reaches *from the
host*: the store UI, the front door, the platform, the inventory reader and Dagu. This component is
not one of them and the list was not touched. Every consumer in the product is a container on the
project network (`http://ai:8080`), so a published loopback port would add a listener on the host for
no consumer, put an unauthenticated-by-default inference API in front of anything on the machine that
can read `127.0.0.1`, and make the serve reachable from a browser — which is where the CORS notes in
upstream's own README start to matter. **A host that wants to talk to it from outside the project
network is a different deployment and needs a different argument.**

That is a smaller exposure, not a wall: any container on the project network holding the key can call
the serve. The key is what makes that a deliberate act rather than a default.

## 9. Health, and the `model` tile

`platform/overview.py:25-57` already validates a `model` signal and the Homepage already renders
`model_display`; before this component **nothing in the tree wrote it**. The producer is
`platform/overview_worker.py:model_signal`, running in the same process that publishes the job
signal, writing both into `LO_OVERVIEW_PATH` in one atomic replace — one writer, not two.

Four states, from the public `GET /health` plus the capability manifest:

| Published | Meaning |
|---|---|
| `disabled` | no `ai` block in `LO_OVERVIEW_CONFIG`: the component is not deployed (no socket is opened at all) |
| `unknown` | the serve did not confirm it is ready — loading, unreachable, refused — or the label is malformed. Unknown is never healthy |
| `degraded` | ready and labelled, but the capability manifest is unreadable, incomplete or still `unknown`: a model nobody may generate with yet |
| `healthy` | ready, labelled, every capability field measured |

`observed_at` is stamped every tick and the freshness bound is 120 s; a stale observation nulls itself
to `stale` in `overview.py:54-55`, which is unchanged.

## 10. Failure modes

| Symptom | Cause | Operator's next command |
|---|---|---|
| container is `unhealthy` for minutes | weights still loading; `/health` answers 503 | `docker compose logs ai` — do not lower `start_period` to make the colour change |
| tile says `Degraded` | serve up, manifest unmeasured | `docker compose ps`; then measure §4 |
| the client raises `capability_unknown` | same, seen from a consumer | nothing to fix in code: measure it or accept the rule floor |
| `policy_refused` / `remote_refused` | the class does not permit this call | the refusal names the class; the rules-based path still ran |
| `expired_evidence` | an evidence reference is past `expires_at` | investigate why the explanation was asked for stale evidence; **do not** re-run the query to fill the gap |
| `response_too_large` | the serve returned more than 64 KiB | lower `max_completion_tokens` in the budget |
| `endpoint_unavailable` | nothing answered; nothing was retried | check the service, then the base URL and `LO_INTERNAL_ALLOW_HTTP` |
| `incomplete_response` | the endpoint reported truncated output without answer text | inspect the recorded token counts and the model's behavior within the configured budget; narrow the request or evaluate a supported model configuration before retrying; unfinished output remains refused |

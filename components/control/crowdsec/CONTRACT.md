# CrowdSec Security Engine — optional decision store (component `crowdsec`, crowdsec)

Status: **experimental, never run**. No container has been started from this directory, no alert has
ever been posted to `/v1/intake/crowdsec`, and no decision has been read from a Local API by
`local_observe/platform/crowdsec.py`. `versions.json` carries the pin, the two digests, the registry URL
each was read from, the date (2026-09-09) and the UNVERIFIED list; `conformance.md` carries what has to
run before `docs/COMPONENTS.md` §3's row can be called validated. What follows separates three things
deliberately: what upstream documents at the pinned tag, what was read in its source at that tag, and
what nobody has measured.

**Optional by construction, like `ai`:** no shipped example composition includes
`components/control/crowdsec/compose.yaml`, so `minimal`, `standard` and `full` need no CrowdSec image
and no CrowdSec credential. `docs/COMPONENTS.md` §4 defines `full` as *"standard plus explicitly
selected optional integrations"* — a selection an operator makes, which is what `examples/crowdsec/`
exists to be selected.

## 1. The contract this row has to keep

`docs/COMPONENTS.md` §3 L83, verbatim: *"Optional; blocklist opt-in; platform approval and protected
destinations enforced."* Three clauses, and only the first two are easy.

| Clause | Where it is enforced | What that actually means |
|---|---|---|
| Optional | no `include:` in `examples/{demo,full,platform}/compose.yaml`; `crowdsec` is absent from `check_foundation.py`'s `HOST_PUBLISHED_SERVICES` and publishes no port | deleting this component changes nothing else, and the "if disabled" text below is the promise that claim is honest |
| blocklist opt-in | `DISABLE_ONLINE_API: ${LO_CROWDSEC_CAPI_DISABLED:-true}` (community blocklist dependency) | shipped off; one environment line opts in, **after** a human enrols the machine (see "Enrolment") |
| platform approval and protected destinations enforced | `local_observe/platform/policy.py::action_policy` over the definitions merged from `actions.example.json` into the operator's `LO_ACTION_POLICY` file | an address inside a protected network fails the allowlisted parameter schema, so the refusal is `Action parameters do not match allowlisted schema` → audit word `policy-parameters-schema` (`refusals.py`, the refusal audit's taxonomy). No new approval path, no new refusal word |

## 2. Product, operator, and the line between them (overlay compatibility)

Product: this directory, `local_observe/platform/crowdsec.py`, `examples/crowdsec/` as shapes.
Operator: the rendered `profiles.yaml`, the rendered `http-notification.yaml` (it carries a credential),
the acquisition YAMLs, the log paths, the `LO_ACTION_POLICY` merge, the pin value, the intake rules
document, and every one of the three protected networks. Nothing in the product names a host, a network
or an address: `SHIPPED_PROTECTED_SLOTS` are RFC 5737 documentation ranges and the privacy walk's ban
list (`BANNED_TOKENS` in `scripts/check_foundation.py`) is enforced over every file here.

| Variable | Read by | What it does | If unset |
|---|---|---|---|
| `LO_CROWDSEC_IMAGE` | compose | the engine image, digest-pinned | `config` fails: no image is guessed |
| `LO_CROWDSEC_ACQUIS_DIR` | compose | acquisition YAMLs, read-only at `/etc/crowdsec/acquis.d` | `config` fails; `create_host_path: false` makes a missing directory a boot failure, not an empty mount |
| `LO_CROWDSEC_LOG_DIR` | compose | the log files the acquisition names, read-only at `/logs` | `config` fails (see "Journald" for why no journal bind ships) |
| `LO_CROWDSEC_PROFILES_FILE` | compose | `profiles.yaml`, read-only | `config` fails — without it the alert-to-notification decision is upstream's default, which is not this component's default |
| `LO_CROWDSEC_NOTIFICATIONS_FILE` | compose | the HTTP plugin config, read-only; **carries the intake bearer token** | `config` fails |
| `LO_CROWDSEC_COLLECTIONS` | compose (`COLLECTIONS`) | which hub collections to install on first start | `crowdsecurity/linux`, the image's own default. See "Hub content" |
| `LO_CROWDSEC_CAPI_DISABLED` | compose (`DISABLE_ONLINE_API`) | the Central API channel: signal sharing, and the community blocklist's route in | `true` — off (community blocklist dependency) |
| `LO_CROWDSEC_LAPI_URL` | `crowdsec.py::client_from_environment` | the Local API base URL for decision reads | decision reads are off: one INFO line naming the variable, and `client_from_environment` returns `None` |
| `LO_CROWDSEC_BOUNCER_TOKEN_FILE` | `crowdsec.py` (via `credentials.read_credential`) | the `X-Api-Key` value, as a file | an endpoint with no readable credential is a start-up refusal naming the variable; never an environment value in any shipped manifest (`check_credential_files`) |
| `LO_INTAKE_RULES` | `intake.py` (the **platform** service) | the declared scenarios, one row each | the documented off switch: every `/v1/intake/*` POST is refused with a reason naming the variable |
| `LO_ACTION_POLICY` | `policy.py` (the **platform** service) | the allowlisted actions, including the two here and their protected networks | the platform refuses to start (`api.app_factory` reads it unconditionally) |

## 3. Decisions are read state; blocks are approved actions

`docs/CONTRACTS.md` §4 already settled the vocabulary: *"a decision is read state and a block is an
approved action"*, and `crowdsec.decision` is refused as an event type. This component honours that with
two separate surfaces:

* **Read freely.** `LocalApi.decisions(...)` reads `GET /v1/decisions` (query by `ip`, `range` or
  `scope`/`value`) with a bouncer API key. A `reader` credential can do this today through
  `crowdsec.py`; no approval, no audit row, no state written. `covers()` answers "is this address
  already decided?" and can only answer it when the endpoint answered 200 — an unreachable Local API is
  a `TransportError`, never an empty list, because "no decision" and "no answer" are different facts and
  the second one must not read as permission. A bare address queried through `range=` uses its host
  prefix: `/32` for IPv4 and `/128` for IPv6. Explicit prefixes keep their width; prefixes with host bits
  set are refused. The `ip=` filter remains a bare address.
* **Act through the lifecycle.** `crowdsec-decision-apply` and `crowdsec-decision-remove` go through
  `propose_action` → human `decide` → `claim_action` (role `executor`) → `execution_outcome`, with
  `policy()` re-run at both the propose and the claim end. The address is always in `parameters`
  (`action_request` refuses a proposal that names a CrowdSec row instead), because a gate that judges an
  identifier is a gate that approves bytes.

**There is no writer, and that is the shape rather than an oversight.** Upstream's permission model is
explicit: an API key "can only read decisions", and creating one needs a *machine* credential
(login/password), `local_api/authentication.md` at v1.8.1. This repository ships neither a machine
credential nor the write endpoints (the verb and path are in `versions.json`'s UNVERIFIED list — the
source file that registers them was unreachable from this checkout on 2026-09-09). So an approved
`crowdsec-decision-apply` has nothing that can claim it, and the honest reading of the row is
*"approval is enforced; enforcement is not yet wired"*. A card that ships an applier owns four things at
once — the machine credential's delivery, the write endpoints read from the pinned source and not from
memory, the containment check (`protected_covers` exists for exactly this), and this paragraph.

## 4. Protected destinations (auto-block authority) — and what the schema cannot see

The three allowlisted classes are the VPN path, the LAN gateway and the ISP ranges. They live in
`LO_ACTION_POLICY`, mounted read-only and read once at service start, so an agent that has persuaded the
platform to propose a block cannot widen the list from a request body. Enforcement is the allowlisted
parameter schema, which is deliberately chosen over a new check in `policy.py`: a new refusal sentence
there needs a `refusals.SENTENCES` entry *and* a matrix row in `tests/test_refusal_audit.py`, neither of
which is this card's file, and "add no second approval path" is easier to trust when the second path does
not exist at all. Three limits, all of them load-bearing and all of them named here:

* **Text, not arithmetic.** The protected list is expressed as anchored prefixes over the value's text
  (`protected_schema`). `CANONICAL_VALUE` closes the obvious evasion — `192.000.002.007` is the same
  address as `192.0.2.7` and matches none of the prefixes, so the schema admits only the spelling
  `ipaddress` itself accepts. What it cannot express is **prefix overlap**: a proposal to ban
  `192.0.2.0/23` over a protected `192.0.2.128/25` is refused only if the text happens to start with the
  protected prefix. `protected_covers` computes overlap exactly, and today nothing calls it at
  decision time — see "no writer" above. Until something does, an over-broad `Range` proposal is stopped
  by a human reading the parameters, which is not a gate and is not described as one here.
* **Octet-aligned IPv4 only, and any IPv6 entry protects all of IPv6.** `protected_networks` refuses a
  `/17` and names the aligned prefix to write instead; listing any IPv6 network adds a refusal of
  **every** IPv6-shaped value while retaining each IPv4 restriction, because compressed-v6 containment
  is not a pattern property.
  Both refusals over-protect, which is the direction auto-block authority's failure mode (locked out of the VPN) prefers.
* **A removal is a block-shaped act.** Both actions carry the same protected schema, so "unban the whole
  /0" is refused by the same rule as "ban the gateway".

The `protected_destinations` list a human edits and the schema that bites are kept from drifting apart by
`protected_from_definition`, which re-derives the networks from the patterns and refuses a definition
where either family's restrictions are missing or changed. Extra conditions inside an exclusion are
also refused, since they could make a protected pattern ineffective.
`python -B -m local_observe.platform.crowdsec --check-actions FILE` runs it over
a whole policy file before the service is restarted. **No product runtime path calls that validator** —
`api.app_factory` reads the policy file with plain `json.loads`, and adding a CrowdSec-shaped validation
step to a generic loader is a change to a file this card does not own. `tests/test_crowdsec_actions.py`
pins the shipped fragment so that what ships is sound; the operator's own merged file is sound only if
they run the check, and that is a documented operator step, not a gate.

**The actor who proposed cannot be the actor who approved — with one caveat stated plainly.** At the role
boundary this is enforced and tested: only a credential whose authenticated role is `human` decides, so
the `proposer` credential that filed the block cannot approve it, at the state layer and at the HTTP edge
(`tests/test_crowdsec_actions.py`). What §5 does *not* require is two distinct humans:
`tests/test_action_invariants.py::test_a_human_who_proposed_may_approve_and_both_sides_are_durable`
pins that a single human holding both ends is permitted on this main today, with the contract's own
reasoning in its docstring. This card does not change that rule and does not claim it. If "a CrowdSec
block needs a second pair of eyes" is the intent, that is a `docs/CONTRACTS.md` §5 decision (a D-item),
not a worker's edit to `state.py`.

## 5. Alerts in, and the one envelope that is honest

Upstream renders the body with the HTTP notification plugin's `format` template over a **list** of
`models.Alert` objects — its shipped default is `{{.|toJson}}` and its own comment says the output "goes
in the http request body" (`cmd/notification-http/http.yaml` at v1.8.1). This platform's transport will not
carry that default: every POST route reads named fields and answers 400 `Expected a JSON object body` to a
body that is not a JSON object (`api.py`). `crowdsec.alerts` therefore accepts exactly two shapes — the
object with one `alerts` key holding the array, which is what `examples/crowdsec/http-notification.yaml`
makes the template emit, and the bare array, for a fixture file read off a disk — and refuses anything
else. It is registered as intake source `crowdsec` (`intake.register`, the way `intake.py` registers its
own adapter) and reached at `POST /v1/intake/crowdsec` by the `crowdsec` producer credential —
`intake_target` refuses a path naming anyone other than the authenticated caller.

The rules document (`LO_INTAKE_RULES`, source `crowdsec`, one row per scenario) decides which scenarios
speak, what rule identity their finding carries, and which measurement it keeps. The shipped example
uses `sample_field: alert.events_count` to select the native alert-level `events_count` in
`models.Alert` at v1.8.1. It accepts only a non-boolean integer in 0..2147483647; absent, malformed or
out-of-range counts produce coverage only. It never counts the retained `events` details, which may
be a smaller sample. Existing metadata selectors, including `metric:events_count`, still read only
the named `events[].meta` pair; they do not fall back to the native count.
A scenario with no row is not a guess: it is `crowdsec.undeclared-scenario.coverage`, a firing
coverage event about the intake source, and one WARNING naming a bounded `name_hint`. An alert with no
keepable reading is coverage about that rule and opens no incident — the rule is
`docs/CONTRACTS.md` §4's evidence rule, and it is the reason an Alertmanager-shaped envelope does not
satisfy this source on its own: §6 of the port table names `aiops/ingest` as the reason ("an adapter may
not synthesise an evidence reference to data it did not capture"), and a CrowdSec alert that reaches the
platform as a bare verdict with `source-heartbeat` evidence would be a finding about an address with
nothing behind it but the fact that somebody asked.

Four consequences operators need in words:

* **No resolution transition exists in this source.** The plugin reports new alerts, never a decision's
  expiry, so nothing this adapter emits can carry `status='resolved'`. An incident opened from a
  brute-force finding is closed by the platform's own absence/coverage judgement or by a human. An
  "auto-close on decision expiry" adapter would have to invent that transition, which is the false
  recovery `docs/CONTRACTS.md` §4 audits for; if it is ever wanted, it belongs in `vocabulary` and §4 as
  a new decision, not in this module.
* **Event identity carries the alert `uuid`.** Two distinct alerts for one address in one window share a
  rule, a resource and a window; under `detections.event`'s own derivation the second is
  `Event retry changed contents` and the whole envelope 400s behind it. `_identity` therefore joins the
  `uuid` — per-alert, never derived from label text, so a re-post folds into one row (§5's "replay does
  not multiply findings") and a renamed scenario rewrites nothing. Coverage events keep
  `intake.retry_identity`'s `status`-keyed form instead, which is what keeps one gap in one window to one
  row however many alerts repeat it.
* **Severity is never in the payload.** `crowdsec` declares no severity words
  (`vocabulary.SOURCE_VOCABULARIES`; §4's crosswalk table says why: *"a CrowdSec alert is a scenario"*),
  so no severity argument is ever passed and a firing finding is the factory's `warning`.
  `tests/test_crowdsec_intake.py` refuses any admitted severity literal in this module's source.
* **The bytes run out before the count does.** `MAX_ALERTS` = 50 bounds how many incidents one POST can
  open; the transport bounds what it will read at all, refusing a body over **65 536 bytes** with
  `413 body_too_large` before this adapter sees a byte of it (`api.py`'s chunked read). A
  `group_threshold` large enough to matter therefore fails at the transport, whole, and the plugin's own
  retry counter is where that shows up — which is why `examples/crowdsec/http-notification.yaml` batches
  at ten. `tests/test_crowdsec_intake.py::IntakeRouteTests` pins both halves: an oversized body stores
  nothing, and a bare array — what upstream's shipped `format` renders — is a 400 the transport answers
  before any source runs, which is the single reason the shipped template wraps the array in one
  `alerts` key.

## 6. Hub content, and the names this component does not use

`COLLECTIONS` ships `crowdsecurity/linux` because that is the image's own documented default at the
pinned tag. threat detection engine narrows detection to ssh/proxy brute force, and the collection names that narrowing
needs are **not** written anywhere in this component: no hub catalogue was reachable from this checkout
on 2026-09-09 (`hub.crowdsec.net`'s API answered 404 to a GET) and a collection name written from memory
installs a parser nobody has read. Read the hub's collection list, then set `LO_CROWDSEC_COLLECTIONS`;
`versions.json` keeps this as an UNVERIFIED line and `conformance.md` has a row for it.

The scenario keys in `examples/crowdsec/intake-rules.json` are the same story one level down:
`crowdsecurity/ssh-bf` is a **shape**, valid as a rules document key and not verified as an upstream
scenario name. A key that never arrives costs nothing; a real scenario whose row is missing costs a
visible coverage gap, which is the failure mode this design chooses on purpose.

## 7. Budget

notification budget's precision budget is Sigma compiler's metric (`sigma_*.py`, `per-rule precision`), and this component's
obligation is to publish its own noise into the same object rather than to claim a number. **No budget
exists for this component, because nothing has run.** `≤2/week` would be an invention, so none is
stated; what is stated is the shape of the measurement when someone has data — the alert count this
source files, per declared rule, over the outbox rows the budget already counts, and the coverage events
this module emits are the "noise" half of that ratio and belong in the numerator.

## 8. Enrolment is a human act (community blocklist dependency)

Enrolling a machine ID against the Central API needs an account, a login key and possibly 2FA — a
credential the agent must not hold and a portal click with no programmatic path in this repository. So
the blocklist ships off, the opt-in is one line, and enrolment requires your explicit approval, documented
in a runbook. `cscli capi register` inside the container is the mechanical half of that step and is
named here so nobody has to guess where the boundary is: a human supplies the key, the file lands in
`/etc/crowdsec` (the config volume), and `backup.md` treats that volume as state the operator cannot
regenerate because of it.

## 9. The bouncer is an overlay, and the gate is right

A CrowdSec bouncer is the thing that makes a decision bite: `crowdsecurity/cs-firewall-bouncer`'s own
README says it "will fetch new and old decisions from a CrowdSec API to add them in a blocklist used by
supported firewalls", and lists iptables, nftables, ipset and pf. On Linux that means netfilter writes,
which in practice means `--cap-add NET_ADMIN` (or `--privileged`) and usually `network_mode: host`, and
that is precisely what `scripts/check_foundation.py::check_model` refuses:
*"unexpected host privilege/network access"*.

1. `crowdsec` joins **no** `EXAMPLE_MANIFESTS` composition, so the plain gate run never opens this
   component's manifest. `tests/test_crowdsec_component.py` runs `check_model` over it directly and
   `check_foundation(root, compose=['examples/crowdsec/compose.yaml'])` over the example, which is what
   closes the hole the absence would otherwise leave. What the gate still cannot see, and this is the
   one line to say it: **any bouncer an operator adds in their own overlay — its privileges, its host
   network, its blast radius — is outside every check this repository runs**, because the moment it is a
   host-netfilter actor it cannot be a checked service here.
2. A block cannot be applied from this product, so the approval gate protects against a decision record
   being *acted on* by nothing. Read the row's third clause as "the platform will not be the one that
   skips you", not as "nothing is blocked".
3. `protected_destinations` therefore guards a proposal, not a netfilter table. It stays in
   `LO_ACTION_POLICY` — not in a prompt, not in `presentation.py` — so that when a writer arrives it
   guards the same list it guards today, and the card that adds a bouncer has to move this paragraph and
   not invent a second answer.

## 10. If disabled

Remove or never add the `include:` entry. Then: no CrowdSec findings arrive, no decision store exists,
nothing is blocked, and **nothing this product does changes** — Sigma detections, incidents,
notifications, the portal, the outbox and the budgets never learn this component exists, because the only
arrow into the platform is the generic intake route that already serves Alertmanager.

The sentence that matters, and the one an operator only thinks of while locked out: **an address a
bouncer previously applied stays applied.** Disabling this component removes the thing that *decided*,
not the thing that *blocked*, and this repository ships no writer that could undo it. `upgrade.md` says
what to do about the decisions that are still live before a version move; the answer for removal is the
same command on the host that owns the table (`cscli decisions list`, then the firewall's own
`nft list ruleset` / `iptables -S`), and it is a host action, not a product one.

The quieter half of the same failure: with this component gone but `LO_INTAKE_RULES` still naming source
`crowdsec`, the platform starts normally and every CrowdSec POST is refused with
"No adapter is registered for source crowdsec". `intake.validate_rules` refusing that document at boot
would be the better behaviour; it is not this card's file, and the fact is recorded here rather than
being quietly true.

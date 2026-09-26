# Extraction contracts v0

Updated: **2026-09-14** — wording and the staging-access paragraph corrected; the contracts below
are unchanged since 2026-09-06. Implementation baseline for the settled core. Fields
and interfaces below are proposed concrete implementations of accepted
decisions, not a claim of an already-stable public API. Changes before the first
release remain reviewable in Git; the answers recorded in DECISIONS remain authoritative.

## Portal summary v1

Authenticated `GET /v1/overview` returns schema_version 1, generated_at, durable
incident/action/delivery counts and freshness-qualified backup, job and model
observations. Each observation includes status, value, observed_at and source.
Unknown, disabled, stale or future-dated observations have null values; missing
coverage must not imply zero failures or a verified backup. Job count scope is
explicit and can be a subset of the estate. Running jobs currently make that
subset's count unknown until their outcome is observable.

The `summary` credential role permits only GET `/v1/overview` and `/v1/me`.
Record reads and all mutations are denied. Homepage resolves the credential
from a mounted secret on its server, never a token embedded in browser markup.
Its authenticated TLS edge is required; an allowed-host setting alone is not
authentication. Product MCP exposes the same overview through platform_overview.
Existing `/v1/status` and MCP tools remain compatible. The legacy estate MCP
capabilities have a separate coexistence/parity gate, not an implicit alias.

## 1. Component and configuration ownership

The [versioned customisation contract](DEPLOYMENT.md) defines stable content IDs,
independently pinned data-only packages, user ownership, explicit overrides,
deterministic rendering and drift-aware upgrade plans. Its v1 content lock does
not yet pin the full source/image/state compatibility tuple required to deploy.

Each component owns its Compose model, internal configuration, health interface
and persistent-state manifest. Cross-component calls use named endpoints and
versioned payloads. No component imports a private estate checkout to start.

The product owns image/version selection and defaults. An overlay owns:
- Component selection and deployment identifier.
- Published addresses/ports, proxy routes and optional DNS records.
- Inventory declarations, resource IDs and integration endpoints.
- Credential references and private values; never baked into an image.
- Persistent storage placement, backup destination and retention configuration.

Product configuration paths are relative to the component directory. Compose
includes resolve each module from its own directory; use an explicit global
override or per-include override list for customisation. Do not depend on
implicit merging of same-named resources in the including file.

Use one synthetic Compose project with no static container_name or external
estate network. Default host publication is loopback for development. LAN use
requires an explicit overlay and authenticated/TLS access. No service may bind
an existing estate directory by default. A second project must get separate
volumes and ports rather than reuse the first deployment's data.

Secrets are required variables or mounted files. Missing credentials fail
startup; no anonymous fallback. Generate local example credentials separately
from committed .env.example files. Environment output and resolved Compose
models may contain secrets and must not be published as test logs.

## 2. Telemetry and query interface

Public ingest: OTLP/HTTP and OTLP/gRPC with a per-install bearer credential at
the front door. Downstream collector and DB ports are private to the Compose
network. A loopback DB port, if needed for tests, is an explicit demo-only
override and must not become a LAN default.

Metrics, logs and traces retain source timestamps and resource attributes.
host.name and service.name describe the source, never the receiver container.
Inventory-aware producers add resource_id containing the declared UUID;
producers without one remain queryable as unresolved sources.

The reference adapter exposes metric/log/trace queries with UTC half-open time
windows [start,end), explicit row limits and server-side execution bounds.
Results identify source, query, time window, truncation and errors. A failed
query never returns the same successful envelope as an empty result. Row limits are per query kind
and are stated on the answer: 2 000 metric samples, 200 log records, 100 spans, one row per aggregate
(`local_observe/store/client.py` `QUERY_KINDS`), and the read-only analysis profile repeats the widest
of them (`max_result_rows = 2000`, `result_overflow_mode = throw`,
`components/data/store-signoz/clickhouse-users.d/lo-read.xml`) so a page wider than its bound is an
error at the server and a labelled `truncated` at the client, never a short answer read as a whole one.

Version the compatible tuple: ClickHouse, SigNoz, its collector/migrator,
front-door collector, query adapter and Sigma field mapping. Test supported
table/attribute layouts rather than inferring compatibility from a UI brand.
Compiled SQL includes rule ID/version, compiler/mapping identity and a hash.
Runtime compilation is not required by the initial runner.

## 3. Inventory identity and build

Declared YAML has schema_version and resources. A resource has UUID id, kind,
name, aliases, attributes and relations, plus one optional typed `owner`: a
single bounded string naming the on-call identity the operator's overlay
declares (a team, an account, a mailbox-shaped string), never a hostname and
never inferred from one. Relation targets are UUIDs; credential
attributes carry references only. UUIDs are generated once at declaration,
not regenerated from a changing hostname or IP. Alias collisions are rejected
or surfaced as unresolved; they are not silently merged.

The builder validates shape and relation integrity, writes a new SQLite index,
then atomically replaces the served snapshot. Record declaration revision,
schema version and build time. Datasette is read-only. Rebuild from YAML after
loss; no operator edits to the index. The observed dataset instead records
source, observed_at, resource aliases and evidence; it never edits declarations.

During later estate adoption, retain the old IDs as explicit aliases. Test old
telemetry queries and new UUID queries before migrating consumers. A partial
inventory import is not grounds to delete the private source inventory.

A discovery source implements the provider contract (`local_observe/inventory/discovery.py`, discovery providers): it returns observations and holds no write path; each source reads a named field allowlist, and widening it is a contract change. What a source stops seeing is aged with `observed_at` evidence, never removed, and only a fresh, successful, complete read may evidence absence.

## 4. Canonical events and evidence

Event v0 requires schema_version, event_id, source, source_event_id,
resource_id (nullable if unresolved), observed_at, received_at, kind, severity,
data_class and evidence references. The source supplies a stable retry identity;
intake enforces uniqueness on (source, source_event_id). Detection events also
identify the rule version and evaluation window. Severity mapping is explicit
per source and independent of delivery priority.

`kind` is a closed vocabulary — `availability`, `coverage`, `threshold`, `drift`,
`anomaly`, `security` — and a value outside it is refused at intake, never stored
and never rendered. Each name says what produced the verdict, not how bad it is:
`security` is a matched Sigma rule (it rode `threshold` until event vocabulary, which made a
security finding and a CPU breach indistinguishable in every view), and `anomaly`
is a value outside a seasonal baseline its own series learned — a judgement with
an explicit training floor, so a producer with too little history emits nothing and
says so in its log rather than filing a verdict. Severity is carried separately:
`anomaly` names `warning` for a point outside its band and `critical` once it sits
a further `k` scaled-MADs beyond that edge.

### 4.1 The crosswalk every producer cites (`platform/vocabulary.py`)

A producer never spells a severity literal and never invents a `kind`: it names its source vocabulary
and hands the upstream word to `vocabulary.severity(source, value)`, and names its verdict to
`vocabulary.classify(source, event_type)`. **A word with no row raises** (`VocabularyError`, a
`ValueError`, which reaches intake as a 400 naming the field), and there is no default in either
direction — intake admits exactly `info`, `warning` and `critical`, so any fallback would be a silent
downgrade of a verdict somebody measured. Loudness moves only by editing a row here, in a diff.
The tables, the refusals and the reason for each refusal are the module's; this section is the
contract they must agree with, and `tests/test_event_vocabulary.py` fails if they drift.

**Severity — keyed per source, never per value.** Ladders differ in length, so one word sits at a
different height in two sources: keyed by value alone, `error` would be `critical` in one producer and
`warning` in another, which is the fragmentation this section exists to prevent.

| source vocabulary | its own words → here | refused by decision |
| :-- | :-- | :-- |
| `core-events-v1` | `critical`→`critical`, `error`→**`warning`**, `warning`→`warning`, `info`→`info` | `unknown` |
| `alertmanager` | `critical`/`crit`→`critical`, `error`/`err`→`warning`, `warning`/`warn`→`warning`, `info`→`info` | `none`, `unknown` |
| `sigma` | `critical`→`critical`, `high`/`medium`/`low`→`warning`, `informational`→`info` | — |
| `signoz` | `fatal`→`critical`, `error`/`warn`/`warning`→`warning`, `info`/`debug`/`trace`→`info` | `unspecified`, `unknown` |
| `gatus`, `healthchecks`, `crowdsec` | **none**: these sources carry no severity word — a Gatus result is a boolean, a check-in status is a verdict, a CrowdSec alert is a scenario — so severity is derived from the verdict by `detections.event` | every value, `warning` included |

Case and surrounding space carry no meaning in any of these vocabularies (`alertmanager` labels are
operator-typed, SigNoz stores `SeverityText` upper-cased), so the lookup folds both and echoes nothing
raw: `platform/api.py` answers a refusal with the raised sentence, so a refusal names the word only
after reducing it to `[a-z0-9_.:-]`, capped.

`error`→`warning` is the row that changes an operator's reading of the estate, so it is argued, not
asserted. v0.1's ladder above `info` runs critical > error > warning (`alerting/conditions.py`, read
most-severe-first), while this repo's `critical` is not a rung anybody types: `anomaly.severity_for`
reserves it for a point another `k` scaled-MADs beyond the band its own series learned. Mapping the
middle rung to `critical` would file every ported `error` finding — a failed synthetic probe, a job
that missed its check-in — at the loudest level there is, beside a measured statistical escalation, and
would contradict the producers already merged (`detections.event`, `sigma_runner` and `anomaly` all
call an ordinary firing verdict `warning`). v0.1's `error` and this repo's `warning` are the same
statement in two dialects. Nothing gets quieter: the finding still opens an incident and still reaches
the same policy — and per the sentence above, delivery priority never rides on the mapping anyway.
The rule that row generalises: **a source's own top rung may name `critical`; every rung below it
collapses onto `warning`, and only the rungs the source itself calls informational become `info`.**

**Where an `unknown` severity lands: nowhere, as a severity.** v0.1 sets it when no adapter claimed a
payload (`core/events.py`'s `normalize`) or when a label went unrecognised. It names a missing
adapter, not a state of the watched world, so the word is refused and the caller emits a `coverage`
event *about that source* — the pattern `detections.evaluate` already uses for a sample that is
missing, failed or stale. Coverage says the one thing actually known (this signal cannot currently
describe the thing we watch); storing the event as `info` would downgrade it and storing it as
`critical` would invent it.

**A mapped severity describes the firing verdict.** A recovery carries `info`: the factory derives it,
v0.1's own dispatcher did the same (`alerting/dispatch.py` files `info` on `alert.resolved`), and a
recovery must not keep the loudness of the failure that ended. Producers pass no severity for a
recovery.

**Type → `kind`/`condition`.** The boundary that decides every row below, and the one a reviewer
should test any new row against: **a test that ran and failed is `availability`; a test that could not
run, or a signal that never arrived, is `coverage`.** `classify` returns `(kind, condition)` and the
producer passes that condition as its `rule_id`, because `detections.event()` sets
`condition = rule_id` and takes no other argument — a card that needs a condition distinct from its
rule identity widens that factory (`alert conditions` owns it), it does not hand-edit the event. For
`core-events-v1` the condition is the v0.1 type verbatim, so a ported event and the v0.1 rule that
made it are greppable by the same string; the two types `core/events.py` itself emits carry no package
prefix and take one (`core.`), because an unqualified condition would collide with anything a later
rule invents.

| v0.1 `type` | `kind` | `condition` | why |
| :-- | :-- | :-- | :-- |
| `probe.check_failed` | `availability` | `probe.check_failed` | a probe ran and the answer was bad |
| `synthetics.http.check_failed` | `availability` | `synthetics.http.check_failed` | as above, per engine (synthetics component/gatus for synthetics) |
| `synthetics.dns.check_failed` | `availability` | `synthetics.dns.check_failed` | |
| `synthetics.api_chain.check_failed` | `availability` | `synthetics.api_chain.check_failed` | |
| `synthetics.browser.journey_failed` | `availability` | `synthetics.browser.journey_failed` | the journey completed and failed |
| `synthetics.tls.check_failed` | `availability` | `synthetics.tls.check_failed` | |
| `synthetics.http.transport_error` | `coverage` | `synthetics.http.transport_error` | the probe never got an answer to judge |
| `synthetics.api_chain.transport_error` | `coverage` | `synthetics.api_chain.transport_error` | |
| `synthetics.dns.resolver_error` | `coverage` | `synthetics.dns.resolver_error` | |
| `synthetics.browser.engine_error` | `coverage` | `synthetics.browser.engine_error` | the engine itself was unusable |
| `synthetics.browser.unavailable` | `coverage` | `synthetics.browser.unavailable` | |
| `synthetics.tls.fetch_error` | `coverage` | `synthetics.tls.fetch_error` | |
| `synthetics.tls.expiry` | `threshold` | `synthetics.tls.expiry` | a certificate is not *down*, days-left is past a limit |
| `probe.test_refused` | `coverage` | `probe.test_refused` | scheduled but not run is a monitoring gap |
| `probe.runner_error` | `coverage` | `probe.runner_error` | |
| `collector.poll_failed` | `coverage` | `collector.poll_failed` | the `abandon` row's one useful shape; `store facade`'s reads need it |
| `heartbeat.missed_checkin` | `coverage` | `heartbeat.missed_checkin` | a job that did not report is exactly the stale/absent input `detections.evaluate` refuses to read as a verdict about the job |
| `heartbeat.ran_too_long` | `threshold` | `heartbeat.ran_too_long` | a duration past a configured limit |
| `slo.fast_burn` | `threshold` | `slo.fast_burn` | a burn rate over a budgeted rate (`error budget`) |
| `rum.cwv_spike` | `threshold` | `rum.cwv_spike` | a policy limit on a measured value |
| `config.changed` | `drift` | `config.changed` | declared-versus-observed configuration, the only producer `drift` has (`drift producer`) |
| `anomaly.detected` | `anomaly` | `anomaly.detected` | a value outside a band its own series learned (`event kinds`) |
| `unnormalized` | `coverage` | `core.unnormalized` | an inbound payload no adapter claimed |
| `webhook` | `coverage` | `core.webhook` | a generic webhook with no declared type says nothing about what was measured |

| other source vocabulary | its word | `kind` | `condition` |
| :-- | :-- | :-- | :-- |
| `sigma` | `finding` | `security` | `sigma.finding` |
| `sigma` | `coverage` | `coverage` | `sigma.coverage` |
| `gatus` | `result` | `availability` | `gatus.result` |
| `gatus` | `coverage` | `coverage` | `gatus.coverage` |
| `healthchecks` | `late`/`down` | `availability` | `healthchecks.check-in` (the watched job did not run or finish; matches job observe standard's `deadman-checkin`) |
| `healthchecks` | `up`/`new`/`started`/`finished` | `coverage` | `healthchecks.check-in` |
| `healthchecks` | `paused` | `coverage` | `healthchecks.paused` |
| `crowdsec` | `alert` | `security` | `crowdsec.alert` |
| `crowdsec` | `coverage` | `coverage` | `crowdsec.coverage` |

A Sigma rule's identity is its own UUID and lives in the `rule_id` (`sigma.<uuid>`, as
`sigma_runner` already composes it), so the crosswalk names the *channel*, not the rule; the same
holds for a Gatus endpoint or a CrowdSec scenario, whose name belongs in the evidence parameters.
`crowdsec.decision` is not an event at all: a decision is read state and a block is an approved
action (`crowdsec`).

**Types refused by decision, and what to do instead.** `alert.fired` and `alert.resolved` name a
*transition* of an alerting condition, not a verdict: the kind belongs to the condition (absence →
`coverage`, static tier → `threshold`, learned band → `anomaly`) and the transition belongs in
`status`, so `alert conditions` classifies per condition. `forecast.threshold_predicted` describes a future
window while every `kind` describes the window the event carries, and intake opens an incident for any
firing event whatever its severity — filed as `threshold` it would page as if a limit had already been
crossed, so `forecast` owes a decision (widen `EVENT_KINDS` through its four places, or an advisory that
opens nothing), not a mapping. `netpath.path_change` is neither declared-versus-observed inventory
(`drift`) nor a failed test (`availability`); `path monitoring` files the consequence, and a bare route change
belongs in the topology read-model (`topology read model`). The four BGP types — `netpath.bgp_withdrawal`,
`netpath.bgp_hijack`, `netpath.bgp_path_anomaly`, `netpath.bgp_visibility_drop` — have no producer: the
BGP feed was culled (dead code, `path monitoring` names `netpath/bgp.py` not ported), and a type with no producer is
vocabulary debt; if the feed returns, a hijack is a `security` finding and the rest are
`availability`/`coverage` about the path, decided then. `alertmanager` and `signoz` declare no closed
type space at all (`labels.alertname` is free text an operator typed; SigNoz is the store, not a
detector), so `classify` refuses every value for them and the kind comes from the rule that judged the
sample.

**`dedup_key` is not ported and has no home here.** v0.1's `derive_dedup_key` hashes
`source + resource_ref + type + sorted(labels)`, which makes event identity a function of mutable
label text: add one label to a rule and every past incident becomes a different event. Identity here
is two durable pairs in `platform/state.py` — `events UNIQUE (source, source_event_id)` for retry
identity (the factory derives `source_event_id` from rule, version, resource and window, so a
replayed evaluation is one row, not a re-fire) and `conditions (key, watermark, status, incident_id)`
where `key` digests `(source, rule_id, rule_version, resource_id, condition)`, which is what groups
verdicts into one incident. `suppression`'s suppression and flap folding build on those; nothing re-derives
a name-based key. And a ported producer delivers over intake into that store, whose §5 outbox carries
the consequence: `core/bus.py`'s in-process bus is not ported, because a restart must not lose a
pending consequence, which an in-process bus guarantees it does.

Evidence references contain query type/parameters, window, schema version and
source. They are reauthorised on retrieval, not arbitrary executable SQL from
an agent. Declare source retention and expose expired evidence; a dead link is
not proof. Incident state preserves the minimum redacted context needed to
understand an action after source data expires.

**Grouping: when several conditions are one incident (`platform/correlation.py`, correlation).** One
`condition_key` is one condition, and an incident is allowed to hold several of them. The rule is temporal
proximity **and** at least one corroborating structural signal, never proximity alone: two unrelated things
failing in the same minute is coincidence, and grouping on coincidence replaces N symptoms with one symptom
that misreports all of them. `link()` composes the two halves and is the only function a caller may ask;
the invariant is tested as a property over a grid of gaps and pairs, not asserted in a comment.

The structural signal this repository can actually evaluate is a **declared dependency path** between two
*different* resources — declared UUIDs and the graph, read through `local_observe/topology.py`, never a
name-derived id. Three refusals are part of the rule and not implementer's taste. `absent`, `incomplete`
and `depth_exceeded` from `shortest_path` group nothing: a search that could not answer is not a negative
answer, and the same discipline already stops `suppression` suppressing on a truncated walk. Two conditions on
the *same* resource do not group, because `detections.evaluate` files a source-coverage condition beside
the finding it explains and §4.2 says plainly that coverage does not open the underlying condition —
collapsing them by identity would let "the probe could not run" hold a service's real outage open, and
later resolve it. And `label_affinity`, the third signal v0.1 carried, is **not ported**: the canonical
event field set is closed and carries no labels, and widening it to feed a heuristic is the trade backwards.
The group is decided in creation order — first matching incident, first matching member — so the answer is
reproducible from the file, and its bounds (`300 s` window, `2` hops, `32` members, `50` candidates
examined) all fail toward *a second incident*, because the cost of a wrong group is an operator trusting an
explanation that misattributes a cause. The gap is measured between the arriving event's window end and the
**subject event** of the candidate (the verdict that last changed that incident, which `intake` already
records as `incidents.last_event_id`); the alternative — an anchor time kept per group — is a clock this
schema does not have, so a long-lived incident whose first symptom is older than the window stops accepting
members while its own conditions keep firing. That is correlation's stated limit, not a hidden one, and it too
fails toward the second incident.

The **rationale is stored, redacted and bounded**, because the paragraph above this one is the reason the
explanation cannot be a live query: telemetry retention's retention windows expire the telemetry, and an incident whose
"why" was a live query becomes unreadable exactly when someone asks why an action was approved. Schema v7
adds `incident_members(incident_id, condition_key, rationale, at)` — one row per grouping link, keyed by
the pair, the newest restatement winning — and no column on `incidents`: `conditions.incident_id` is
already the many-to-one pointer. Each stored line is `{kind, detail, score, references}` in canonical JSON:
one sentence this module composed, and references that are *references* — the path as resource UUIDs, the
relation words, and the SHA-256 of the declaration it was read from. Never an event payload, an evidence
parameter, a credential, an address or a name-derived identity; the bound is 1 024 characters, enforced
twice (before the link is returned, and as the column's own CHECK), and a link whose explanation would not
fit it does not group. `GET /v1/records/incidents` carries the members and each per-link rationale on the
row, and one labelled line in `display`.

Two consequences of a group, both deliberate. **Resolution belongs to the last open member:** an incident
stays `open` while another condition still points at it, so one member's recovery is not the incident's,
and a single-condition incident resolves exactly as it always did. **Pages stay per condition:** grouping
is context, not a delivery policy — the outbox still books one delivery per transition, `claim_notification`
keeps its head-of-line rule untouched, and the "one cause page" promise lives in the operator view. The
alternative (one page per group) would require the delivery rail to un-book a row another producer filed, or
to suppress a real finding because a neighbour arrived first; both cost more than a second message. A group's
severity is *derived* on read — the loudest member, promoted one rank toward `critical` once the group spans
`promotion_threshold` distinct resources, capped — because §5's schema carries no severity column and a stored
group severity would be a number nobody re-checked when a member joined.

**An escalation rung is outside every group, in both directions.** A rung is filed under `<rule>.stage<N>`
(`platform/escalation.py`) precisely so that it is a condition of its own with its own booked delivery, and
the ladder's durable cursor tracks one rung per incident; let stage 2 join the incident that opened it and
the cursor is left counting a rung that no longer has its own incident, so the next stage is the one the
ladder believes it already filed. Grouping therefore exempts a rung as a member and refuses a rung-opened
incident as a host. That is not a claim that a rung is unrelated — it is the same cause, filed separately on
purpose.

**One writer, and one store.** Grouping is a call site of `Store.intake`'s admission seam — the same seam
`suppression`'s fold uses — so a group commits with the event that joined it, and a second intake cannot open a
second incident for the group it serialises behind (`BEGIN IMMEDIATE`). Nothing about a group is held in
process memory, and nothing about one is read from ClickHouse: copies of findings in the analytical store are
for analysis and dashboards, never an input to a grouping decision, which is the same §5 boundary that keeps
approval authority out of the telemetry store. `platform/owner.py` remains the only single-service lock; the
admission is where grouping obeys it. The same seam is wired on **every event-filing entry point that names
an inventory index** — the two HTTP intake routes and the six producer rounds of `lo-platform` (`evaluate`,
`drift`, `conditions`, `pathcheck`, `slo`, `forecast`), so a finding filed at the keyboard is not the one
condition in the estate that never joins anything. `lo-platform intake` groups when it is given `--index`
(correlation followups 2): with that flag it passes the same admission over the same built index, and with it omitted — no
declared graph to consult — it files the behaviour that predates grouping, which is a choice the flag
leaves open and not a gap. Both halves are pinned by `tests/test_correlation.py::CliGroupingTests`.

**An incident's owner is read from the declaration and from nowhere else:** the incident's own resource is
looked up in the built index and the label is what its declaration says — the typed `owner` field of the
declared resource, which the build stores in its own `resources.owner` column and the read consults
first. The older `attributes['owner']` spelling is still read, so an overlay written before the field
keeps routing while it moves, but its label says which spelling it came from and asks for the typed one;
the two never print alike. correlation followups drafted the field on its own and withdrew it (2026-09-10): a field the
built index drops is an owner declared and never shown, so the field, the column (built-index schema
version 2) and the read order arrived together in typed inventory records, and an index built at version 1 is refused with
the rebuild command rather than read as if nobody had an owner. Never a name derived from a hostname or
an alias, and a group routes on the resource that opened it (`tests/test_incident_routing.py`).

Keep raw provider events, detection findings and incident state distinct. Write
analytical security events to the owned security_events store with bounded TTL.
Use stable event IDs when copying between operational state and ClickHouse so
retries do not multiply records used for incident decisions. (`local_observe/security/`
implements that sentence; §4.3 states what it copies, who may write it, and what its TTL is not.)

### 4.2 Event intake from an external alert source (`platform/intake.py`)

A source outside this repository arrives with words and shapes of its own, and an Alertmanager webhook
is the proof: it carries no rule version, no evaluation window the platform can sign, no evidence
reference and sometimes no severity at all. v0.1's `aiops/ingest` published such a payload anyway and
noted the gaps in labels. This contract does not: **intake admits events, not intentions**, so the
normaliser either produces an event `state.validate_event` admits or it produces a `coverage` event
about the intake source. Three consequences follow, and each is a rule rather than a style choice.

**1. Evidence, or coverage — never a reference to something that was not captured.** An event may
reference only a sample this platform *kept*: the route calls `Store.put_evidence` for the sample the
payload itself carried, immediately before admitting the event that names it, the same two-write order
`detection_worker.tick` already uses over HTTP. A payload with nothing keepable — no number, no
boolean, a value that is not either — becomes `coverage` `firing` and **does not open the underlying
condition**, because opening it would need a reference this process invented. `detections.evaluate`'s
coverage-then-finding pair is the shape, reused rather than restated. The one asymmetry is a
*resolution*, which files its verdict with a `source-heartbeat` reference even when it brought no
number: evidence is required to open a condition, never to close one, and refusing a resolution would
strand an incident open forever. A captured sample is referenced as `observed-snapshot`, not
`metric-threshold` — intake compared nothing to a limit, the upstream rule did.

**2. Loudness comes from the crosswalk; `kind` comes from a declared rule.** Severity is
`vocabulary.severity('alertmanager', labels.severity)`, which already folds `crit`/`err`/`warn` and
refuses `none`/`unknown` (§4.1); a refusal becomes `coverage` about the ingest path, which is what that
section prescribes. The `kind` cannot come from `classify`, because `alertmanager` deliberately declares
no closed type space — `labels.alertname` is free text somebody typed into a route. So the operator
declares it: `LO_INTAKE_RULES` names a JSON file mapping alert name → `{rule_id, kind, rule_version?,
window_seconds?, sample_field?}`, validated at start, bounded to 64 KiB and 500 names per source, and
refusing a `kind` outside `EVENT_KINDS` (a configuration file may not widen the vocabulary). An unset
variable is the off switch, and off is loud: every webhook then refuses with the reason rather than
being accepted and published under a rule nobody wrote. An alert name with no row is `coverage`, and its
name never becomes an identifier — the gap rule ids are fixed strings
(`alertmanager.undeclared-rule.coverage`, `alertmanager.severity-refused.coverage`), because identity
that moves when somebody renames a rule is the `derive_dedup_key` defect §4 refuses by name.

**3. Linking is enrichment, and a missing resource is not a refusal.** `instance`/`host` is offered to
the existing `inventory/index.resolve` as a candidate set (the raw value, the same value without a
`:port`, and the address form) in one call, so a name claimed by two declarations answers `conflict`
rather than taking whichever came first. A name that does not resolve lands as the admitted
`resource_id = null` — §4 makes that field nullable, so this is the *answer*, not a refusal — and the
route's per-event `resource_link` (`resolved`/`unknown`/`conflict`/`no_alias`/`index_unavailable`/
`not_configured`) is where the degradation is visible, because the canonical field set is closed and
must stay so. An unreadable index leaves intake running: a front door that stops intake because its
inventory read failed manufactures the outage it exists to report. No UUID is derived from a name.

**What the delta costs, per contract rule.**

| rule `state.validate_event` enforces | what an Alertmanager payload brings | what intake does instead |
| :-- | :-- | :-- |
| `resource_id`, or an explicit null | `labels.instance`/`labels.host`, a name | resolve it, else the admitted null plus `resource_link` |
| `rule_id` + `rule_version` | `labels.alertname`, operator-typed, no version | the declared rule row supplies both; no row, no verdict |
| window ≤ 7 d, ending at or before the instant judging it | `startsAt`, and a *scheduled* `endsAt` in the future | firing `[startsAt, startsAt + window_seconds]`; resolved `[max(startsAt, endsAt − window_seconds), endsAt]`, both payload-only, so a re-post is byte-identical |
| 1–20 evidence refs, each `expires_at` after the window end | nothing | capture the declared sample first, or file coverage |
| `observed_at` may not be future | `startsAt`/`endsAt`, and the zero time `0001-01-01` | the zero time means *no instant*: ignored on a firing alert, refused on a resolution, which cannot close a condition at a watermark nobody read |
| event ≤ 64 KiB | envelopes reach 64 KiB first | the transport answers `body_too_large` before parsing; the per-event ceiling is therefore only reachable by a producer calling `Store.intake` in-process, and no route here enforces it |
| one row per `(source, source_event_id)` | the same alert re-posted, and both its transitions | identity is `(source, rule_id, rule_version, resource_id, window.start, window.end, status)` — see the note below |

`source_event_id` adds `status` to what `detections.event` would derive, and only that. Alertmanager
posts a firing alert and its resolution with the same `startsAt`, so under the factory's identity a
resolution can arrive as "the same event, with different contents" — which `Store` refuses, the
resolution is lost and the incident never closes. The limit of that fix is stated rather than hidden:
if a condition clears at the exact instant the firing event's derived window ends, the two verdicts do
genuinely disagree at one condition watermark, and `Store` refuses the second
(`Conflicting evaluations at the same condition watermark`). Nothing lands and the incident stays open —
the safe direction, but it is an open item for `suppression`'s flap handling (or a watermark rule in
`state.py`), not something the intake path may settle by inventing an instant.

**Envelope rules, all of them refusals.** `POST /v1/intake/<source>` keeps `/v1/events`' role matrix
unchanged — `summary` is turned away before the body is read and `reader` is refused by the state
layer's producer check, so no role that could not post an event before can now — and the path must name
the caller's own credential identity, so one producer cannot post on another's behalf. An `alerts[]`
list may hold at most 50 entries; more is refused whole, never truncated, because a dropped alert is a
silently dropped outage. A body that is not an object, a missing or empty `alerts`, a non-object entry
(v0.1 wrapped these), an unparseable or naive timestamp, a status that is neither `firing` nor
`resolved` (v0.1 defaulted those to `firing`), or an unbounded label object refuses the envelope, and
`validate_event` runs over every produced event before a single write, so a refusal means nothing
landed. Envelope-level fields (`status`, `groupKey`, `receiver`, `commonLabels`) and `fingerprint` are
not read; `summary`/`description` annotations are **dropped**, because the canonical event carries no
free-text field and inventing one is how a payload's text becomes an operator-visible label — what an
alert said lives in the source tool, and what it *was* lives in the rule id and the evidence.

### 4.3 The owned `security_events` store (`local_observe/security/`)

The paragraph two sections above — analytical security events, bounded TTL, stable event ids — is a
promise with an implementation behind it as of security store. Its content is three properties, not a schema:
the retention numbers live in one module, the sensitive payload lives in one place, and backup
coverage has a verified answer. clickstack / hyperdx's rule applies unchanged: this is a **ClickHouse table this
repository owns**, not a label inside SigNoz's managed schema (whose retention is per-signal and whose
upgrades rewrite its tables), and every read of it goes through the same bounded read-only client the
rest of the platform uses.

**What is copied, and under which identity.** Only a `security` event — the kind a matched Sigma rule
carries since event vocabulary (`state.EVENT_KINDS`; the §4.1 row `sigma`/`finding`), so no new `kind` value was
needed and none was invented — is copied, and the copy carries the operational event's own
`(source, source_event_id)` pair verbatim. That pair is §4.1's retry identity, and it is the table's
dedupe key (`ORDER BY (source, event_id)` on a `ReplacingMergeTree`) rather than a second identifier
minted beside it: the replay of a lost acknowledgement must land on the row it already wrote, because
a second analytical record is a second data point in whatever an incident decision was made from. A
count of this store is therefore `uniqExact(source, event_id)` and never `count()`, which would rise
and fall with merge timing. The rule namespace is the runner's existing one — `sigma.<uuid>` for the
finding, `sigma.<uuid>.store-coverage` for the store's own verdict below. A `coverage` event is
**never** copied: §4 keeps raw provider events, findings and incident state distinct, and the absence
of a log source is not a security record.

**One place for the TTL, and it is not telemetry retention's.** `security/ttl.py` holds both numbers
(`critical` 1825 days, `routine` 90) and nothing else in the product states them: `security/schema.py`
renders the table's multi-condition `TTL` clause *from* that policy, so a declared table cannot be
built with a retention the policy does not say. The same bounded ClickHouse reader obtains
`count()` and `any(create_table_query)` from [system.tables](https://clickhouse.com/docs/reference/system-tables/tables).
The parser extracts only the table-level TTL, ignoring column TTLs and quoted/comment text, then
requires exactly the two timestamp-plus-day deletions guarded by retention tier. An absent or hidden
table is `unreadable`, with an absent-table detail; an existing table without TTL is `no-ttl`.
Malformed metadata and transport failures are `unreadable`; declared-policy differences are `drift`.
Pinned-server readback and the proposed reader grant remain unverified.
**Security retention is separate from per-signal telemetry retention.** SigNoz
retention for traces, metrics and logs is compared by `local_observe/store/retention.py`.
Do not apply those settings to the owned security-event table.
A row's tier is *derived* from its event severity by that module and is not a field a writer
may set, so nothing is promoted to the long tier by whoever is inserting it — and because the Sigma
runner files a finding at `warning`, every Sigma row is `routine` today and the long tier stays empty
until a producer files `critical`.

**The privacy boundary, and what is not yet wired.** `principal` and `raw` are columns of the owned
table and appear in no projection of it: the short-TTL dashboard copy carries six attributes (event
id, rule, version, status, tier, producer) and that omission is proven by markers in a test, because a
five-year tier is meaningless if a 15-day dashboard holds the payload. **The projection has no
exporter in this tree** — telemetry enters through the OTLP front door and nothing writes out to the
store's log table — so a dual-write reports its projection as `unwritten` with a row count of zero.
That gap is stated rather than closed by a second transport, and wiring it is its own card.

**Who reads and who writes, decided in the open.** Nothing that exists today can touch this table:
`lo-query` (the runner's credential) is `readonly = 1` with `SELECT` on the three signal databases, so
it can neither insert nor read `security_events` nor query `system.tables` for the TTL check. The
proposal — **a reviewer decision, not a shipped grant**, and the runner's own user is deliberately
unchanged — is a separate `lo-security` user holding `INSERT` and `SELECT` on `security_events.*` plus
`SELECT` on `system.tables`, still `allow_ddl = 0`, with the DDL applied only by an operator running
`python -m local_observe.security.cli apply-schema` as a store administrator. Full text and the
proposed fragment: `components/data/store-signoz/clickhouse-users.d/CONTRACT.md` ("A writer for the
owned store"). Until that decision lands, the runner's write hook stays unconfigured: with no
`LO_SECURITY_CLICKHOUSE_URL` it files the two events it always filed and logs one line at start.

**Absence is a reported state.** The declared-versus-live TTL check runs on a cadence inside the
runner and reports where coverage is already reported: the batch carrying a finding also carries
`sigma.<uuid>.store-coverage`, `resolved` when the store took the copy and the live TTL agrees,
`firing` otherwise — the same shape as `detections.evaluate`'s coverage-then-finding pair, filed with
a `source-heartbeat` reference so intake admits it. A store that cannot be reached never delays or
replaces the operational event (incident and action state: `state.py` decides what is open), and never passes silently:
the copy is re-attempted while the batch is still owed, and the coverage condition stays open until a
read agrees.

## 5. Operational SQLite and action lifecycle

One platform service is the initial owner/writer. A schema migration version
and durable volume are mandatory. Use database transactions for related state
changes and an outbox for notifications and analytical copies. The derived
inventory database is separate and is never used to store approvals.

The platform schema is v9. The v8-to-v9 step adds one index, `incident_members_condition` over
`incident_members(condition_key)`, for the one read that asks how many openings a group swallowed for one
condition (`platform/suppression.py::_absorbed_openings`, inside the flap count). That table's primary key
leads with `incident_id`, so the read by condition had no index to take and walked the whole link table;
the step makes it a seek, and adds no table, column or stored value — so it moves no table pin in
`tests/test_state_migration.py`, and it is proven from a v8 file by `tests/test_incident_grouping_migration.py`,
which also asks `EXPLAIN QUERY PLAN` for that statement and requires the answer to name the index rather
than scan the table. The v7-to-v8 step adds one index, `events_incident` over `events(incident_id)`,
for the one read that asks which events belong to one incident (`platform/rca.py::MEMBER_SQL`), and adds no
table, column or stored value — so it moves no table pin in `tests/test_state_migration.py`, and it is
proven from a v7 file by `tests/test_incident_grouping_migration.py`, which also asks `EXPLAIN QUERY PLAN`
for that statement and requires the answer to name the index rather than scan the table. The v6-to-v7 step
adds one table, `incident_members`, and the one index a new read needs (`tests/test_state_migration.py` is
the test that moves when this sentence names a new table). It adds no
column to `incidents`, `conditions` or `events`, so an operational database reaches grouping by migrating
and no stored row changes — `tests/test_incident_grouping_migration.py` asserts that on v1 and v6 files
alike, and that the migrated file can then group.
The v5-to-v6 step added only indexes for bounded escalation reads.
The v4-to-v5 step adds only an index for bounded maintenance-window
candidate reads; it changes no table or stored document. Opening an older file requires an explicit
`lo-platform --database <path> migrate`, which verifies a pre-migration copy before applying the step
and appends one `schema.migrated` audit row. An older binary requires that copy for rollback; opening
the migrated file never downgrades it. Migration 4's verification-table contract remains unchanged.

Store incidents, events, notification attempts, approvals, execution attempts
and append-only audit records with stable IDs. Acknowledging an intake event
means its state is durable, not merely scheduled for a later memory flush.
Deleting or expiring raw telemetry must not delete action authority records.

Approval request binds: requester identity, incident/evidence references,
action name/version, target UUIDs, canonical parameters/hash, creation and
expiry. Human identity is obtained from authenticated transport; payload fields
cannot claim that an agent is a human. Read tokens cannot approve or execute.

Lifecycle: proposed -> pending -> approved/denied/expired. Claim an approved
request atomically before dispatch, recording execution ID and runner token.
Then record executing -> succeeded/failed/unknown. A second claim is rejected.
Use the execution ID as the runner idempotency key where supported. Dagu is an
executor, not a separate source of remediation approval.

If dispatch succeeds but acknowledgement is lost, query the existing runner
execution. If the outcome cannot be established, retain unknown and require
reconciliation; do not silently mark failed and resubmit. Approval expiry
prevents a new dispatch but does not erase a running action. Verification after
execution determines incident recovery; process exit zero alone does not.

Notification callbacks bind the same request, actor and expiry and are single
use. Callback receipt is not action completion. An unavailable notification
channel leaves state inspectable and retries bounded. A working log database
does not compensate for a lost authoritative approval database.

`POST /v1/callbacks/{channel}` is the route that carries one: the single-use
code in the request body (never the path or a query string) names the delivery
it was minted for, the bearer credential names the actor, and what it records is
one `action.approval_intent` audit row against an action that stays `pending`.

A refused action attempt is itself durable state: one append-only `action.refused`
audit row per refusal that the process-local write budget admitted and the identity
permitted to name, written after the refused transaction rolled back and never
inside it, with a fixed attempt and reason word, a subject that is a canonical UUID
or the `unbound` sentinel, and the identity from the authenticated transport. Where no
row exists the refusal is still counted and not silent: `dropped` (over quota),
`failed` (the write itself failed) and `unauditable` (no honest identity) are reported
on `GET /v1/runtime`, reset when the process does, and never become a different answer
to the caller. A refusal row records that the platform declined; it changes no
lifecycle state, authorises nothing, and is never read as an authorization input. A
request rejected by the parser, size or shape gate, and any unauthenticated request or
unknown route, writes no row and opens no connection — an unauthenticated request never
becomes a database writer. The `summary`-role gate on the four action write routes runs
before the body is read, so it takes precedence over those gates: a summary credential
sending malformed or oversized bytes is audited as the summary-role denial it is,
without body inspection. The rows are bounded in width and in write rate, and one rate
bound is not the whole cost of a flood. The four lifecycle refusals, audited inside the
store, can still spend a 64-row per-process burst and about one bounded row a second
thereafter, the loss counted rather than silent. The `summary` denial on those same four
routes carries one more consequence since the asynchronous audit writer: its write no longer runs on the
serving loop, so a database locked elsewhere cannot block that loop or a concurrent
memory-only `GET /v1/runtime` read. The app adds ONE audit slot per application instance
— one attempt submitted or running at a time, no queue and no waiter for admission, busy
or closing alike — and a denial arriving then is shed with the byte-identical
`403 summary_only`, no body read and no token spent, counted in `overloaded` while
`closed` says which state the gate was in, never a tally. An admitted request still
awaits its own attempt, off the loop, before its `403` is sent, and an attempt is still
not a row; a cancelled request keeps its write and its slot, and lifespan shutdown drains
what it admitted — the delivery loop's blocking call included, and after a failing
startup, a failing `receive()` or `send()`, or a repeated cancellation — before it
releases the exclusive state-file owner lock or claims `shutdown.complete`. Neither
counter set is a complete history of refusals: the `refusals` rate budget, the four
lifecycle methods' inline audit and every other synchronous read are unchanged, and no
role, route, schema version, variable or knob appears with this
(`docs/units/refusal-audit.md` holds the detail). No request body, token, URL or
exception message may appear in such a row, and an identity that cannot be validated
produces no row at all rather than an invented one.
The boundary is the action lifecycle: notification-callback and intake refusals are
outside it today and named as such in `docs/units/refusal-audit.md` rather than implied
by this paragraph.

Audit history is read two ways, and neither read is an authority input. The first is
unchanged: `GET /v1/records/audit` answers newest-first, at most 100 stored rows, no
offset. The second, since the paged audit reader, is `GET /v1/audit` — a bounded paged walk over the
same append-only table under the same authenticated GET role gate (`summary` and
`producer` are refused by the gates that already exist, and no role, credential, schema
version, index or retention tier appears with it). A request may name only `limit`
(1..100), `category` (`all`, or the closed eight-word `action-transitions` set of
**completed** transitions — an approval intent and a refused attempt are not completions,
§5 above, so neither shows there), and the pair `snapshot`/`before` that continues a
traversal: `snapshot` fixes the maximum sequence the walk may show, captured inside the
read transaction of its own first page, so appends can neither duplicate nor displace
rows. A client keeps `snapshot` and `category` fixed and passes the returned `next_before`
as its next `before`. A page is `{rows, snapshot, next_before, scanned}` of the six stored columns,
inside a byte cap, and a row too wide to carry is named in place by `{sequence, omitted}`
rather than silently dropped or truncated. It identifies an omitted position, not a full row;
this API adds no arbitrary-row retrieval endpoint. A cursor is a position, not a
credential — nothing signs it and no continuity is promised across a restored or replaced
database (`docs/units/audit-reader.md` holds the bounds).

### 5.1 The verification read/write surface (`platform/verification_api.py`)

Verification state became readable and submittable over HTTP without becoming a second platform API. The
surface is deliberately small and closed: **five operations over four literal paths** —
`GET /v1/verification/binding?action_id=<canonical UUID>`,
`GET /v1/verification/records?execution_id=<canonical UUID>`,
`GET /v1/verification/record?verification_id=<lowercase SHA-256>` , `POST /v1/verification/records`, and
`GET /v1/verification/candidates` with optional `after=<canonical UUID>` and `limit=1..32`
(default 16).
Path ownership is an exact-string test, not a prefix: a path outside those four returns to the existing API
and keeps whatever answer it had before, and a recognised path with an unsupported method is `405` with no body
read and no database connection (summary credentials retain their earlier 403). Nothing here adds a role, a token, a credential, a mount, a schema version or
an environment value, and nothing here widens `Store.records()`' allowlist, the `summary` credential's two
routes or any action-lifecycle rule in §5 above.

**Responses are the storage layer's answers, verbatim.** The binding read returns the existing
`{action_id, status, reason, binding_id, origin}` dict; the execution read returns
`{verification_ids: […]}` of exact IDs from the bounded discovery read; the record read returns the whole
stored document or `404`; and `POST` returns `put_verification`'s own `{verification_id, created}` at HTTP
`200` for a **first acceptance and for an exact replay alike** — no envelope wraps the submitted six-field
record, no second record schema is validated here, and no verdict vocabulary is restated. A caller that wants a
different answer about an accepted record is asking for behaviour §5 refuses: an accepted statement is never
re-observed, re-graded or repaired; reading the stored result is still supported.

**Authority is delegated, not duplicated.** Bearer extraction stays in the transport; this surface receives an
already-authenticated `Actor`. `summary` is refused `403 summary_only` before the body is read or a database is
opened; the three record reads pass through `verification_records`' own reader gate against the **current** policy, and
`POST` and candidate discovery through its writer gate — so reader/human/proposer/executor answer `403 not_authorised`, a producer the
current policy does not name answers `403`, and a producer arriving while **no** policy is mounted answers
`503 verification_unavailable`, which is a statement about the deployment, not about the caller. `Store` repeats
its own authorization internally; no second role or policy vocabulary exists at the transport, and admitting a
producer to these routes grants it nothing else — `/v1/me` and every other GET answer exactly as before.

**Statuses on these routes only, and they are additive.** The refusals come from `verification_records`' own
explicit constants rather than substring matching on the platform's general error codes: `400 invalid_request`
for a query or payload that fails the syntax and bound gates, `404 not_found` for an unknown action, an unknown
execution or an absent record, `409 conflict` for a replay whose contents changed, an execution still `executing`
or the 64-record cap, `413 body_too_large`, `503 verification_unavailable`, and
`500 verification_storage_error` for a stored-state or driver failure (a file needing migration, a corrupt
stored binding/execution/derivation/clock or id/capacity, an oversized stored document, a failed read, or
SQLite/JSON/Unicode corruption). A `500` body is that one fixed code and nothing else — no driver text, no
path, no request, no payload — and an unexpected defect still reaches the transport's existing `500
internal_error` handling rather than being laundered into a client error. Every other route keeps §5's
taxonomy; this section narrows nothing outside these verification operations.

**Bounded work off the serving loop, and the promise it does not make.** One application instance admits at most
**one** actual synchronous `Store` callable at a time, with no queue and no waiter: an arrival while the slot is
busy or closing is shed with `503 verification_busy` and a fixed body, having opened no database
connection. Authorized POST bodies are read and parsed first; authority and parsing precede admission,
and submission happens with no await between
the availability check and the claim. The retained completion future — not a timer, a counter or a response —
owns when the slot is free again. A cancellation or disconnect **after** admission may abandon the response but
frees no slot and cancels no work: an admitted SQLite transaction runs to its own conclusion. Therefore no
answer on these routes, `503` or a dropped connection included, may be read as a rollback — a busy shed and an
immutable replay are different facts, and the durable one is that an accepted record stays accepted. Shutdown
closes admission without cancelling and without joining a thread on the loop, and drains real completion before
the state-file owner lock is released, beside the refusal-audit dispatcher it mirrors; the scope is this
application's own event loop, and no cross-thread use of the application is promised. There is no global
executor configuration, no timeout and no retry client here.

**Candidate discovery is read-only and bounded.** A page scans at most `limit` executions plus
one lookahead through the execution-ID index before filtering. Bounded indexed probes retain only
terminal executions with a captured bound origin and no accepted verification record. The response is
`{items: [{execution_id, action_id, finished_at}], next_after}`; `finished_at` is the stored terminal
`updated_at`. The cursor follows raw scanned UUIDs, including ineligible rows; null means the sweep
ended. A later sweep starts again so executions that finish later and new UUIDs behind a cursor remain
reachable. Discovery creates no claim, queue, audit row or execution change.

**Wiring and separate consumers.** Startup validates credentials, loads `LO_VERIFICATION_POLICY`
before state/notification clients, and passes the immutable policy to the store. Unset means no policy
I/O and no new verification writes or candidate discovery; authorized saved-history reads still work.
A malformed policy refuses startup, and no automatic migration occurs. The HTTP-only CLI retains its
four record operations, and the execution UI already reads saved verification history.

The separate opt-in follower waits for one full captured post-terminal window and saves its bounded
observation before `POST /v1/verification/records`. It retries exactly that statement after refusal,
lost acknowledgement or restart before sampling again; the server remains the verdict authority.
Discovery excludes an execution after any accepted record, including `unknown` or `not_cleared`, so
this is one automatic observation per execution, not polling until recovery. The older evidence-only
`platform/verification.py` and `LO_VERIFY_CONFIG` remain unchanged. Neither follower nor saved records
resolve incidents, change runner outcomes or redispatch actions. Source implementation is not a
claim that a follower is deployed or that live verification has passed.

## 6. Component conformance record

Record component/revision, image digests, config/schema identities, platform,
commands, start/end time and results with redacted evidence. Every check reports
pass, fail or not-run; omitted dependencies never turn not-run into pass.

Required checks scale with component behaviour: readiness and contract I/O,
auth refusal, durable restart, missing dependency, backup/restore and compatible
upgrade. Composite tests exercise cross-component effects such as queue replay,
duplicate detection and interrupted actions. Static YAML/schema checks do not
establish runtime validation.

## 7. Backup, upgrade and staging boundaries

Inventory is rebuilt from declarations; operational SQLite needs a consistent
SQLite backup (online backup API or stopped writer, not a live copy ignoring
WAL). The telemetry stack's backup unit includes ClickHouse, SigNoz metadata
and coordination state as required by its tested recipe. Record collector
queues/cursors separately and their replay/duplicate policy.

Restore only into separate staging volumes first. Record what is restored and
what is regenerated. Snapshot before a schema change; a digest rollback is not
a data rollback. Upgrades must prove data access and recovery on an isolated
copy before touching the estate.

Staging writes go to the isolated account on the host the project maintainer has granted for it.
Which host that is today, what has already been verified and what is still deferred are dated access
records, not part of this contract — this repository's `docs/ACCESS.md` and the runbook it points at
name them, and neither is release documentation. Before access is requested, provide the exact
OpenBao policy and authentication instructions derived from the actual key path and account, and
scope writes to a separate project, directory and volume set. Host access exists for local AI or an
explicit host integration — never as a fallback Docker target assumed from old source paths. Do not
reuse another agent's credentials.

# RCA — component contract

Rule-first root-cause candidates for an open incident, and an optional model that may **explain** that
ranking and may not produce it. Selected under `docs/DECISIONS.md` investigation policy and `docs/PLAN.md` phase 4; built
by investigation component (port twin rca). No upstream version exists to pin, so [`versions.json`](versions.json) says
`status: selected` with `verified_on: null` and `validation.runtime_conformance: not-run`, and publishes
no precision figure — the gate that would produce one is `corpus eval` and it has not run.

## What this component is, and therefore what it has no manifest for

**There is no `compose.yaml` here, and there must not be one without a decision recorded against this
file.** The reason is a lock, not taste:

* `docs/CONTRACTS.md` §5 names **one** `platform` service as the owner and writer of the operational
  database.
* `local_observe/platform/owner.py::exclusive_owner` takes an OS lock on a sidecar of that file
  (`<database>.owner.lock`) and holds it for the whole life of the process that took it — the serving
  process, for its entire life.
* This component writes explanations through `Store`, whose `transaction()` opens a write transaction
  on that same database; derived rotation progress uses its own owned sidecar. A second container running this
  command against the same file would be a second writer of state that has exactly one owner, and the
  lock that enforces it is designed to make that impossible rather than to negotiate it.

So the component is a **command inside the platform image**: `${LO_PLATFORM_IMAGE}` —
`docker/Dockerfile.platform`, built from `python:3.12-slim-bookworm`, the digest the operator resolves
and pins the way `examples/full/compose.yaml` pins every other service there — invoked as:

```
lo-platform --database "$LO_DATABASE" rca --config /etc/local-observe/rca.json \
            --index /etc/local-observe/inventory.db --source rca-cron
```

`components/data/agent-windows` is the manifest-set precedent: `versions.json` plus this contract,
`backup.md`, `upgrade.md`, `conformance.md` and two collector files, **no `compose.yaml`** — its own
`CONTRACT.md` says "There is still no `compose.yaml`, and there will not be one", for a reason a reader
can check. `components/control/ai` is the neighbouring case and is **not** this one: it *does* ship a
`compose.yaml`, and keeps itself out of every shipped example instead
(`tests/test_ai_component.py::test_the_full_example_service_set_has_no_ai_service`). Here the
agent-windows shape is the closest match, and for a harder reason than "not a Compose target": a Compose
model here would name a service that the platform's own lock forbids.

The five artefacts are [`versions.json`](versions.json) plus this contract, [`backup.md`](backup.md),
[`upgrade.md`](upgrade.md) and [`conformance.md`](conformance.md). The `lo-platform` command this
component adds is documented in the *Commands and units* section of
[`local_observe/platform/README.md`](../../../local_observe/platform/README.md).

## What it reads

The upstream-cause rule requires a dated first incident member and a declared upstream finding
observed at or before that anchor. Equal-time findings remain `indicated`, not causal proof. Later
and downstream findings remain visible as bundle context; they cannot become this rule's candidate.
The candidate's resource identity names the selected upstream neighbour.

The batched explanation read chooses the newest `rca.explained` row independently for every requested
incident. Later audit operations of other kinds cannot hide it. Reads use at most 200 bound incident
identifiers per query; each rendered label matches the individual latest-record read.

Candidate display prose is limited to 140 characters before candidate validation. A longer sentence
ends with an ellipsis; the complete producer rule, resource identity and declared name remain in the
cited bundle items. Machine rule identifiers, resource identifiers and citation links are never
clipped. Valid long labels therefore cannot abort an analysis round.

Bundle events use `Store.records('events', RECORDS_LIMIT)`, `presentation.resource_info` supplies
names, `topology.Topology` supplies the declared graph, and `query.reauthorise` checks every evidence
reference. Incident discovery uses `rca_progress`'s bounded, read-only status/rowid index walk. Its
snapshot closes before analysis writes an explanation.

Rounds rotate through a fixed cycle of open incidents, persisting each examined row in a source-specific
sidecar beside the database. Later arrivals wait for the next cycle. Restart resumes from disk, unchanged
explanations do not append, and a known per-incident refusal is reported and skipped for this cycle so
others continue. `incidents_open` and `incidents_read` are page counts (`count_scope: page`), not totals;
`capped` means more work in this cycle. Cursor bounds, ownership, restore limits and the meaning of
`attempted`/`analyzed`/`failed` are in [the progress unit](../../../docs/units/rca-progress.md).

The incidents view reads the explanations back through `rca.latest_many`: **one query per page, not one
per row**. `audit` carries no index on `operation` or `subject` (`EXPLAIN QUERY PLAN` answers `SCAN audit`),
so a per-row read rescans the whole audit table for every incident on the page — 43.8 ms against 2.5 ms
measured on a 100-incident page over a 20 100-row audit trail. The proper fix is an index on `audit`,
which is a schema change and therefore `state migrations`'s, not this component's.

| Channel | Source | Bound |
|---|---|---|
| `members` | the `events` rows whose `incident_id` is this incident, payload parsed by `_event` and dropped whole if it is not a canonical event | 12 |
| `evidence` | `platform/query.py::reauthorise` for each member's evidence reference | 20 |
| `declaration` | `presentation.resource_info` for the incident's resource — labels only | 1 |
| `topology` | `topology.Topology.upstream/impact` at depth 1, one item per declared neighbour | 5 |
| `neighbours` | firing findings on those neighbours, from the same event window | 8 |
| `changes` | firing `drift` events on the resource or a declared neighbour | 8 |
| `baselines` | firing `anomaly` events, same scope | 8 |
| `similar_past` | the most recent resolved incidents with the same `(rule_id, resource_id)` — identifiers and instants only, one read-only budgeted statement (`SIMILAR_SQL`, events incident index) | 5 |

`RECORDS_LIMIT` (100) caps how many event rows are read once for the whole bundle; `MAX_ITEM_BYTES`
(1 024) caps each row, so the eight channels' 67 rows bound the text near 64 KB by arithmetic rather than
by a cap somebody has to remember to lower. `body['bytes']` reports what this bundle actually cost. A
truncated channel says so in its own `note` field, which is a **recorded gap and not a refusal**: the
bundle ships the gap by name, and the rule floor is forbidden from reading past it. An empty channel
also says why.

`similar_past` (since events incident index, the incident evidence index) names the most recent resolved incidents of the same rule and resource — their ids, opened/resolved instants and the resolving event id, never a payload value — read through one read-only statement with its own instruction budget, because `incidents` carries no `resource_id` index; a cut read says so in its note rather than answering with a shorter history, and an open twin is never listed. The rule floor does not read it yet; it is context the model may cite by id.

## Evidence is never read directly

This component asks no HTTP route and holds no token, so it cannot borrow `platform/api.py`'s
authentication; and it must not re-implement a weaker version of it. What it uses instead is
`platform/query.py::reauthorise`, which takes the platform store and one evidence reference **and nothing
else** — in its own words: *"no `StoreClient` is accepted here, on purpose, so this function cannot
quietly re-query the store to make a dead link look alive."* Two properties follow, and both are load-
bearing here:

* **an expired reference stays expired** — the verdict carries no sample, and `rca.py` records it as a
  named gap that is absent from the bundle text by construction, so a model cannot cite what retention
  removed;
* **a reference with no sample id was never a sample** — it is reported `unavailable` with that reason
  rather than looked up under an empty key.

A bundle whose evidence is gone can only ever produce `unknown`: the component that has nothing must not
be the one that fills the hole. What this leaves genuinely unguarded is stated in
[`conformance.md`](conformance.md) rather than papered over — see *"What this boundary does not do"*.

## Outputs

One append-only `audit` row per incident whose explanation changed, operation `rca.explained`, actor
the operator-named `--source` (a `producer` identity, the same convention as every other background
writer), `subject` the incident id, `detail` exactly these fields:

`schema_version`, `producer`, `confidence`, `rules`, `causes`, `citations`, `llm_used`,
`degraded_reason`, `gaps`, `bundle_digest`, `source`. The set is `EXPLANATION_KEYS`, and
`explanation_record` refuses a detail whose keys differ from it, so "a bag of whatever was handy" is
unstorable here rather than merely unadvised. The ceiling is `MAX_EXPLANATION_BYTES` (8 KiB), met by
bounding every field before it is added rather than by truncating a finished row.

`causes`, with `rules` beside it, is the **only** part that can change when the model answers, and the
entries in it are the rule floor's in the rule order, cut only at `MAX_CAUSE_CHARS` (140). `source` is
where an operator sees `rules` or `rules+model`, and `llm_used` is the same fact as a boolean. No
telemetry sample value appears anywhere: `citations` name the `evidence:<n>` row, and that row is
re-readable by anyone allowed to read `docs/CONTRACTS.md` §5. A record whose `schema_version` this reader
cannot place renders as no record at all (`readable_schema`), while a *newer* version still reads —
refusing an explanation because the viewer is old would delete a statement still true of its incident.

The record is **derived, rebuildable state**: losing it costs an operator the cause label on an incident
view, changes no detection, and is regenerated by the next round. That is what makes
[`backup.md`](backup.md) short rather than a new backup job.

## The model interface

The platform half never imports `local_observe.ai`. `local_observe/ai/__init__.py` states the rule in
its own words — *"Nothing outside this package may import it"* — and names this component as a consumer
that must *"import lazily and keep its own floor when the import or the call fails"*.
`tests/test_ai_component.py::ImportGraphTests` enforces it: `ALLOWED_IMPORTERS` is empty and the test
walks every product module outside the package, so *today, nothing does* — its own docstring says
"`rca` and `chat` import lazily when they arrive (investigation component, chat integration); today, nothing does". Joining that
allowlist would be an edit to a test outside this brief's allowlist, so the model reaches this component
a different way and without an import at all: as an **injected callable**, invoked with keywords only.
Nothing in `local_observe/platform/` constructs one, so the floor stays standing when the tier is absent,
refused by policy or unreachable — which is the property the lazy import was written to provide.

```python
generate(instruction=..., data_class=..., evidence=..., now=...) -> dict | str
```

`evidence` is the bundle's own flattened item list and `instruction` is this module's fixed text with the
rule floor's answer appended, so everything the model is allowed to mention is in those two arguments —
which is also what `post_validate` then checks its reply against (`body['text']`, the same bytes). The
`now` the caller passed travels with the request, so a replay of a round is a replay of its clock.

A callable that raises is a normal outcome, not a failure of this component: `explain` and `analyze`
never propagate it. Replies are read `display_text` → `content` → plain string, in that order, because
`display_text` is the label the remote put on its own output (remote inference policy, the remote inference policy lesson) and reading
`content` first would strip it in silence.

The instruction is fixed text in this module — the only variables are the bundle and the rule floor's
own answer. `data_class` must be one of `public`, `internal`, `restricted` — the three classes
`local_observe/ai/policy.py::DATA_CLASSES` routes on, spelled identically here so the two files cannot
drift apart in meaning. An absent or other value is a refusal before a prompt is built, because the
bundle has no default classification and "internal, probably" is a guess about someone else's data. The
configuration default is `internal`, and it is a default only in the sense that whoever wrote `{}` chose
it.

`json_mode` is one of the eight fields in `local_observe/ai/capability.py::FIELDS`, and no capability
manifest has been measured against any serve here. That is the honest word about the executor's
structured-output shape: this build asks for prose, and **applies no rerank**:
the model's reply is recorded as a request to reorder, never as a reorder. When a validated structured
output exists, the seam is `rerank.apply` — the candidate set's order still may not change there, only
the model's stated preference may be recorded beside it.

## The executor seam — the half that is not built, and the shapes it will need

No `executor` config is accepted while no executor exists: `load_config` refuses
`executor.enabled = true` outright, so a manifest cannot quietly promise a deployment nobody built. What
validates **today** is exactly two fields, and nothing else:

```json
{"executor": {"enabled": false, "note": "optional executor documented, not built"}}
```

`_check_executor` refuses any other key and any value of `enabled` other than `false`, which is what
stops the proposal below from being read as a document this build accepts: the fields after `enabled` are
**not accepted today**, and each one arrives only with an implementation and a test in the same PR. This
section is the **only place in the product tree** those shapes may be written down, and they are a
proposal, not a contract — an implementation may replace them **only** with the same properties: bounded
in advance, no free text in the durable record, and the rule floor unchanged by whatever comes back.

```json
{
  "executor": {
    "enabled": false,
    "endpoint": "https://ai.example.invalid",
    "auth": "file-mounted token, mode 0400, never an inline literal (the foundation gate)",
    "tool_adapters": ["signoz", "inventory"],
    "timeout_seconds": 20,
    "max_tool_calls": 4,
    "response": "display_text first, then content; a non-Mapping reply is malformed"
  }
}
```

What is **not** in that proposal, on purpose: an api_key value, a kubeconfig, an unbounded response
size, a retry loop, or any field whose name implies the executor may open a store the platform owns.

## Bounded inputs, and the failure mode each bound is holding back

| Bound | Value | What it prevents |
|---|---|---|
| incidents per round | 1–25, default 5 | one round writing thousands of audit rows |
| incident discovery | at most the round limit plus one lookahead; 16,000 SQL instructions | scans or sorts across lifetime history |
| rotation cursor | 2 KiB, source and canonical database-path bound | an unbounded queue or silently resumed foreign progress |
| model calls per round | 0–10, default 5 | the spend of a control loop that never asks |
| lookback | 60–86 400 s, default 3 600 | a rule that finds "the" change by scanning a year |
| rows per channel | `MAX_ITEMS` | an unbounded prompt, and a bundle that grows with the estate |
| event rows read | `RECORDS_LIMIT`, 100 | the read path degenerating into a table scan |
| cause text per candidate | `MAX_CAUSE_CHARS`, 140 | a cause that arrives as an argument |
| durable record size | `MAX_EXPLANATION_BYTES`, 8 KiB | a row that grows with the estate |
| config file size | `MAX_CONFIG_BYTES`, 64 KiB, closed schema | a config that smuggles a prompt |
| fabrication check | per sentence | a fluent sentence that cites nothing |

## Tests

`tests/test_rca_bundle.py` (channels, bounds, expired-evidence-as-gap, no-samples-in-the-record),
`tests/test_rca_rules.py` (the four rules both ways, the tuning reason of each, and
`test_an_empty_rule_floor_sends_nothing_to_the_model`),
`tests/test_rca_llm_fabrication.py` (`test_a_lying_model_changes_the_prose_and_never_the_ranked_cause_set`),
`tests/test_rca_component.py` (artefacts, the import boundary, the CLI, and the core scenario unchanged
with the component used or unused), and `tests/test_rca_progress.py` (fair bounded cycles, restart,
new arrivals, known refusals, cursor ownership/corruption/restore and indexed query budgets).

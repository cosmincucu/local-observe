# RCA — conformance

**Nothing in this file has been run.** Every line below is a recipe with its expected answer, written
against code and fixtures in this repository and never against a running estate. `versions.json` says
`status: selected`, `verified_on: null` and `validation.runtime_conformance: not-run`; this file is the
reason those three fields are not `null`-free, and the first person to run one of these sections replaces
its heading's `not run` with a dated measurement in the same PR.

The rule that makes this file worth reading: a `verified_on` date licenses printing the version, not
claiming the outcome (`docs/COMPONENTS.md`, *What `verified_on` does and does not license*). There is no
version here to license and no outcome to claim, so there is no date.

## What the unit suite does prove, and where it stops

Four test modules run in the base tier (`python -B -m unittest discover -s tests`, the same tier
`.gitea/workflows/ci.yml` runs):

| File | The claim it earns |
|---|---|
| `tests/test_rca_bundle.py` | the eight channels exist, are bounded, cite only what is available, and an unavailable sample is a named gap the model can never cite |
| `tests/test_rca_rules.py` | four rules fire, four named situations keep them silent, each carries its tuning reason, and an empty floor sends nothing to a model |
| `tests/test_rca_llm_fabrication.py` | a **scripted** model that invents a metric, a number and a resource uuid changes the prose and cannot change the ranked cause set |
| `tests/test_rca_component.py` | the artefacts, the import boundary, the CLI, and the core scenario byte-for-byte the same with the component used or unused |

Where that stops, stated as plainly as the table: **no behaviour of any real model has been observed.**
The lying model is a fixture that returns a string written in this file. It proves the guard's logic, not
that guards hold against a model that has never seen this prompt. Any sentence a model wrote is untested
content, and that is why the durable record stores no prose at all.

## 1. The §5 core scenario, with this component present — not run

Run the failure-to-recovery path in `docs/CONTRACTS.md` §5 with `rca` scheduled alongside the platform:

```
lo-platform --database "$LO_STATE_DB" intake --source rca-conformance --event finding.json
lo-platform --database "$LO_STATE_DB" rca --config rca.json --index "$LO_INVENTORY_DB" --source rca-conformance
lo-platform --database "$LO_STATE_DB" notify            # recording mode until --mode live says otherwise
```

Expected, in this order, each one checked and not assumed:

1. `intake` files the finding and opens an incident (`lo-platform … status` shows one open incident).
2. `rca` answers `{"status": "ran", "analyzed": 1, "written": 1, "model_used": false}`. `model_used` is
   false because the command never hands `tick` a generator at all: `generate` keeps its default of
   `None`, so this run proves the rule floor alone and no endpoint is anywhere in the picture.
3. The audit trail gained exactly one row:
   `sqlite3 "$LO_STATE_DB" "SELECT count(*) FROM audit WHERE operation='rca.explained'"` → `1`.
4. `GET /v1/records/incidents` returns that incident with `cause_name`, `cause_confidence` and
   `cause_basis` in its `display`, and `cause_basis` reads `Rule floor only`.
5. Recovery (`resolved` for the same condition) leaves the incident closed; a later round leaves the
   closed incident alone — `analyze` is not run over resolved incidents, and rewriting history is not a
   round's job.
6. Running the same round twice in a row writes the second time **nothing**: `written: 0, unchanged: 1`.
   This is the one expectation on this page that a host run is most likely to break, and it is the
   difference between an audit trail and an audit flood.
7. No outbox row, no action and no delivery appeared because `rca` ran. `lo-platform … status` before and
   after is the check.

## 2. `If disabled: "Detection, incidents and notifications still work"` — host check, not run

The row's clause, as an executable question on a host. The component is a command, so "disabled" has two
meanings and the recipe does both:

* **not scheduled** — delete the invocation from whatever timer or unit runs it (`systemd` timer, `cron`,
  or the equivalent in the deployment that owns the schedule). Nothing in the platform image changes.
* **not in the image** — `docker compose exec platform sh -c 'python -c "import local_observe.platform.rca"'`
  is expected to fail after the module is removed from a scratch copy of the image. Do not do this to a
  running host; the in-repo equivalent below is the same claim without the vandalism.

Then run §5 and check five things:

1. the detection fired and opened the incident,
2. the incident reached `resolved` on the recovery event,
3. the notification queued in `outbox` and delivered,
4. the incident view still renders — with **no** `cause_*` keys in `display`, which is the correct
   absence (an unexplained incident must not read as "explained, no cause found"),
5. the audit trail contains no `rca.explained` row.

The in-repo version of this check runs now, on every CI pass, and is
`tests/test_rca_component.py::CoreScenarioUnchangedTests`: the same scenario executed twice in two
databases, with `events`, `incidents`, `outbox` payloads, `evidence` counts and every non-`rca` audit
row compared for equality. What the host run adds is the container's own behaviour — the process, the
lock, the file modes — and nothing substitutes for it.

## 3. Bounded prompt under a real load — not run

Feed a host a wide incident (many members, many neighbours) and read what the bundle said about itself:

```
lo-platform --database "$LO_STATE_DB" rca --config rca.json --index "$LO_INVENTORY_DB" --source rca-conformance
```

Expected: the report's `bundle_bytes` stays under roughly 64 KB whatever the estate's size, because the
cap is `MAX_ITEMS` × `MAX_ITEM_BYTES` and not an estimate of how much an incident has. A channel that hit
its cap says so in its `note`, and `gaps` counts the evidence rows that could not be read. **A number
that grows with the estate is a failure of this component**, and the way to see it is to compare
`bundle_bytes` on a small estate and a large one rather than to trust the constant.

## 4. Fabrication guard against a live endpoint — not run, and blocked

Only meaningful once an endpoint, a capability manifest and a policy decision exist (the three
prerequisites of the `ai` row). The recipe, when those exist:

1. Point `LO_AI_*` at a **local** serve — `local_observe/ai/client.py` refuses a non-loopback endpoint
   while `LO_AI_ALLOW_REMOTE` is unset (remote inference policy), so a remote test needs that variable stated out loud.
2. Ask for an explanation of a real incident whose bundle contains no numbers except the ones an
   operator can point at.
3. Read `discarded` in the report. Expected on a healthy guard: any invented metric name, uuid or number
   appears there and not in `text`. Expected on a **broken** guard: it appears in `text` — and that is a
   stop-ship finding for this component, not a tuning problem, because the only thing the model is allowed
   to add is wording.
4. Never conclude from one run. The guard is per-sentence containment against the bundle text; how often
   a real model needs it is a **rate**, and a rate is exactly what `corpus eval`'s labelled corpus exists to
   measure. Until then this section records a recipe and no result.

## 5. Restore probe — not run

[`backup.md`](backup.md)'s four steps, on a staging copy. The expected answer at step 3 is that an
incident whose explanation restored shows `cause_name` and one whose explanation did not shows no
`cause_*` keys at all.

## What this boundary does not do, stated rather than implied

`reauthorise` answers what a reference is worth **from the platform's own evidence table**. It is not an
authorization check and this component does not claim it is one, which leaves three facts an operator
should be able to read off a design review and cannot read off a passing suite:

* **No actor is passed and no actor is checked here.** The identity `rca` writes under
  (`require(actor, 'producer')`) authorises the *write*, not the read: whoever can run the command can
  build a bundle. The per-actor read discipline in `platform/policy.py` therefore binds the API's reads
  and **not** this background path, and a deployment where `lo-platform rca` runs as a different unix
  user than the one that may read the incidents is not a deployment this component protects. It is a
  reason to run the command as the platform's own user, which is what the platform image does.
* **No `data_class` gate sits on the read.** `data_class` in the configuration governs what may be sent
  to a model, and it is a decision written down by the operator. A `restricted` bundle with no model
  configured never leaves the process, and a `restricted` bundle with a model configured is exactly the
  case `local_observe/ai/policy.py` is supposed to refuse — which is not this component's judgment to
  make, and it remains the reason the CLI hands `tick` no generator at all.
* **What is in the evidence table is what the producer kept.** `rca` cannot widen a sample, re-poll a
  target, or fetch a value a rule chose not to retain. If a producer stored only a verdict, the bundle
  holds a verdict and no number, and a rule that wanted a number will say nothing.

The first of the three is the one worth a decision if this component ever grows an HTTP surface: the
route would have to carry an actor into the bundle, and that is `rca`'s half B conversation with
`correlation`, not a refactor of this file.

## Out of scope here, on purpose

* **The `≤3 findings/day` budget** in `docs/PLAN.md` phase 4. It is a target, and the only honest
  sentence about it in this repository is that it has not been measured. Measuring it is `corpus eval`'s job.
* **Any precision figure.** No accuracy or precision number appears in this component's tree, and none
  may be quoted from it before a labelled corpus and a blind backtest exist — including a favourable one,
  and including one copied from HolmesGPT's own paper.
* **The executor.** It is not installed, not pinned, and refusing it is tested
  (`tests/test_rca_rules.py::test_an_enabled_executor_refuses_and_names_the_document_that_holds_the_shapes`).
  A host run cannot test what does not exist.

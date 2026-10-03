# Offline detector evaluation

This package measures canonical detector events against independently labelled incidents.
The default uses generated telemetry and makes no network calls. Explicit observer comparison
calls the configured model over that same telemetry, using the production investigator and a
protected journal. Neither path sends notifications or injects faults into a host.

Run `python -B -m local_observe.evaluation --revision <full-commit-id> --output <new-report.json>`.
Existing outputs are refused. `--corpus` reads the bounded public exchange format in
`examples/corpus/schema.json`; without it the executable fault generator provides synthetic rows.
The revision is caller-supplied; the manifest independently hashes the corpus, implementation,
real estimator, store facade and configuration files. Runtime dependencies are the existing product
base environment only; no evaluation dependency was added.

To compare the configured observer, supply `--observer-directory /approved/private/new-evaluation`
and `--output /approved/private/new-evaluation/report.json`. The directory must be new, outside
Git, with safe ancestors. This explicitly opts in to model calls under the existing `LO_AI_*`
capability, disclosure and budget policy. Retained cycle journals and the report are private.
Historical sample time does not rewind live model credential or capability checks.
The shared `evaluate()` API also reserves this namespace exclusively before source or model
calls. A failed comparison retains diagnostics; use a new directory to try again.

Add `--observer-config /approved/private/observer.json` (or pass `observer_config=Config(...)`
to `evaluate`) to measure an exact operator configuration. Every configured metric source must
match one corpus series by resource UUID and metric name. Missing, duplicate, extra or non-metric
sources refuse. Corpus data replaces source reads without changing the Config, its hash, limits,
cadence or observation window. Without this option, the manifest identifies the generated Config
as `demo-default`; it cannot establish quality for another runtime configuration.

Operator resources also require explicit detector settings: pass `--baseline-config baseline.json`
(Python: `baseline_config=...`). This strict JSON object lists exactly every corpus resource/metric:

```json
{
  "schema_version": 1,
  "thresholds": [
    {"resource_id": "cccccccc-cccc-4ccc-8ccc-ccccccccccc3", "metric": "queue_depth", "threshold": 100}
  ]
}
```

Supply canonical inventory UUIDs and operator-chosen finite numeric thresholds. Missing, extra or
duplicate source mappings, unknown fields and nonfinite/boolean thresholds refuse. The evaluator builds
an ephemeral detector index from those explicit resources; it never writes an installation inventory or
learns thresholds from truth or telemetry. Static detection still uses the actual platform detector.
Without explicit settings, offline demo runs use shipped example inventory and thresholds and identify
their baseline authority as `demo-default`. Arbitrary resources require operator settings.

For every supplied `--corpus` or operator baseline configuration, `--output` must be an absolute filename
inside an existing owned 0700 directory outside Git, even when demo baselines are selected. Reports are
created exclusively with mode 0600 and symlinks refused. Only default generated runs without supplied
corpus/operator inputs can print the full report to stdout or use ordinary CI output files.
Observer comparisons still require a fresh `--observer-directory` and report output inside it.

## Data and scoring

`fault_inject.py` seeds actual `MetricSample` records into `InMemoryStore`, checks the resources
against the declared example inventory, then reads them through bounded `metric-threshold` queries.
It requires every seeded row to round-trip, refusing truncation. Platform intake validity is checked
on every scored canonical event; a test also files a generated event into the real temporary Store.
This is a deterministic detector-quality simulation, not proof of host failure handling.

`model.py` validates half-open truth windows, identities, classes, quiet controls and nested numeric
series. `eval.py` credits at most one true positive per incident; an identical source event is
deduplicated, while additional distinct findings for the same incident cost precision. Different
finding classes have distinct event identities; contradictory reuse of an identity refuses. Resource,
kind and observation time must all match. Resolved/unknown events cannot earn true-positive credit.
There is no tolerance or point-adjust mode; requesting point adjustment refuses. A zero-finding
precision is undefined (JSON null), never a perfect score.

Unlabelled intervals are unknown. Their findings count toward notification volume, but not
precision or recall. An empty incident list has undefined recall. Corpus `labelled` entries declare
exhaustive annotation for a specific resource and half-open window. Explicit `quiet` windows
declare global negative intervals. Positive incidents do not label other resources or times;
omitting `labelled` never implies exhaustive annotation. Extra distinct detections of an already
credited incident still cost precision.

## Arms

- Static thresholds use the actual baseline detector and read the limits for matching resource and
  metric from `examples/platform/forecast.yaml`. These are shipped example settings, not evidence
  of estate deployment. The forecast time-to-threshold algorithm itself is not scored here.
- Seasonal detection imports `platform/anomaly.py` train/detect with hourly buckets, three training
  points and k=3; missing bucket history is explicitly unjudgeable. Any skipped points or
  unconfigured series make an entire baseline incomplete, even when other points yield findings.
- Shaping is a separate comparison baseline: minute means, Shewhart three-sigma detection and
  two-sided CUSUM (k=.5, h=4), resetting cumulative excess after firing. It is labelled comparison
  code, not an existing deployed detector.
- The `llm-rca` arm runs the actual observer when explicitly configured. It receives only series
  and evaluation windows, never incident, exhaustive annotation or quiet labels. Each cycle uses production
  evidence validation and structured, grounded findings. Missing coverage, model failure and
  unstructured actionable output make the comparison incomplete. Without opt-in it stays
  unconfigured with no score. Retained journals are separate for each of the three runs.

Baseline wrappers file at most once per metric series and class per fixed hour, before truth is consulted.
Observer filing follows its configured cadence. The missing-telemetry class is deliberately
uncovered by these value-based arms; the report names it and marks their missing decision windows
incomplete. The current corpus gives static precision 1, seasonal/shaping precision
.5, rates 6/12/12 findings per day (normalised from four hours), and recall 1/3 for each. These values
reflect explicit class matching on this tiny corpus, not broad production performance.

`report.py` runs each arm three times over fresh store/context data. Baseline repeatability units are
resource UUID plus observation window, with the decision and sorted finding classes. The observer
produces one cycle-wide verdict, so its unit is one configured cycle window; its signature contains
that decision and unique sorted resource/class pairs. It never copies the verdict onto every resource.
Each configured source must actually be read completely for that cycle to enter the comparison;
unrequested optional sources remain unknown and make the comparison incomplete. Separate resource
finding summaries describe classes or unknown, without inventing resource-level quiet/watch/tell verdicts.
For each aligned unit, disagreements equal three minus the largest equal-signature count;
the denominator is three times the unit count. One differing decision among 100 units therefore
gives 1/300, not 1/3. Missing or null decisions make that arm's rate unknown, never zero.
Observer timing, token counts and prose do not change a signature. The default observer reads one
hour per cycle; seasonal/shaping baselines use the corpus's bounded preceding history. These
different context limits are disclosed in the report and must be considered when comparing quality.
`budget.py` imports
NotificationPolicy: attempts per channel rolling window, exhaustion latch and explicit reset;
no daily findings cap or per-rule precision floor is enforced by that legacy object.

The independent quality report requires precision ≥0.7, ≤2 findings/day, at least one correctly
detected class missed by both threshold baselines, and <10% observer verdict flips across three
runs. Every run must meet the floors; incomplete comparisons and unlabelled findings cannot pass.
Every present score must include all counts, rates and distinct matched truth IDs with consistent
totals. Missing fields never default to zero.
Even a measured pass has `authorizes_delivery: false`. Representative held-out evidence and human
acceptance are separate from a synthetic CI pass. A four-hour demo cannot establish daily workload,
fit on a 16 GB VRAM device, review burden or long-term reliability.

Keep training/retrieval records separated from evaluation by incident and time. Preserve the frozen
evaluation set when comparing a later prompt, retrieval policy or model; never grade on its own
training corrections. Runtime evidence and exports belong in protected storage, outside Git.

## Report and runtime identity

Report, quality and manifest schemas use version 2. `manifest.observer` has exactly `schema_version`
(1), `configuration_authority` (`unconfigured`, `demo-default` or `operator-supplied`),
`config_sha256` and `provenance`. The latter two are null when unconfigured. Configured comparisons
hash the exact runtime Config; unknown or mixed provenance remains null and prevents a quality pass.

Observer provenance version 1 contains SHA-256 hashes for implementation, prompt, Config, effective
policy, capability and budget, plus configured model alias, provider, model version and actual
response model. It includes `complete` and a canonical self-digest. Every cycle and call must have
complete identical provenance, and the same identity must hold across all three runs. A gateway
alias may differ from the returned backend identifier; each must remain stable separately.
Unknown metadata cannot be replaced by a placeholder label. Reports preserve cycle Config hashes
and call provenance; manifests also hash the relevant observer and AI source files. They export no
raw Config, paths, endpoints, credential references, prompt bodies or evidence bodies in provenance.
Retained cycle metadata includes the observation `window`, `covered_sources` and `evaluation_complete`;
acceptors must compare coverage with the accepted Config and derive expected cadence windows.

`manifest.baseline` has exactly `schema_version` (1), `configuration_authority` (`demo-default` or
`operator-supplied`), `config_sha256` and `inventory_sha256`. The config digest covers validated settings
with finite floating-point thresholds sorted by resource/metric. The inventory digest covers the exact
ephemeral declaration used by the detector. `verify_manifest()` requires `baseline_config=` to verify an
operator baseline; an omitted or changed policy cannot verify it. Deployment acceptance must require
operator-supplied baseline authority as well as the accepted observer Config.

Reports retain a `measurement` envelope (schema version 1) containing the full validated `corpus`,
normalized `baseline_config` (null for demo defaults) and exactly three `runs`. Each run names every arm;
each arm retains its complete canonical `findings` array and aligned `decisions` map. Identical retries
remain in that array for the scorer to deduplicate; different observation times or evidence identities
remain distinct. An acceptor must recompute scores, novelty and flip rates from this envelope and reject
contradictory summaries. The corpus digest must match the manifest. These retained inputs do not
authenticate truth labels or replace independent human acceptance.

Real reports therefore contain private telemetry and labels and must stay in protected storage. They
are not anonymized merely by an origin label. Generated CI reports remain synthetic. Truth enters the
report after investigations; it never enters the investigator context.

Use `origin: operator-held-out` for private independently labelled operator telemetry. The existing
`anonymized-example` origin remains supported; neither spelling proves independence, anonymization
or model quality. `generated-demo` inputs can exercise the evaluator but cannot authorize delivery.
All origins retain the same input bounds and measurement checks. Real reports and corpus files stay
outside source control, including when resource identifiers have been replaced. Keep incident/time
windows disjoint from training and retrieval, freeze the corpus before comparing candidates, and
record unavailable labels as unknown. Human acceptance still requires an explicit independent-label
attestation after reviewing the report.

`flip_rate.measurements` records each arm's explicit unit, status, units, missing decisions, disagreements and
comparisons. `per_arm` and aggregate `rate` are null when the corresponding population is incomplete.
Deployment review needs an independently held-out corpus, operator-supplied configuration, matching
runtime identity and separate human acceptance bound to the report, channel and budget. A corpus
origin label or a passing generated fixture does not supply that acceptance.

## Tests and CI

The `evaluation` subgroup is registered in `tests/tiers.py`. Run all evaluation regression modules:
`PYTHONPATH=tests:. python -B -m unittest test_eval_gate test_eval_arms test_eval_corrections test_eval_final test_observer_evaluation test_fault_injection`.
CI executes these tests once inside the existing covered base pass. Its additional evaluation step
generates and uploads the quality report, without a second unittest pass. Negative controls prove
fires-everywhere fails a deliberately chosen test policy and unwired stays unwired. Bounds,
half-open endpoints, wrong hosts/classes, duplicate findings, provenance tampering, missing seasonal
history, actual store reads and schema/checklist checks are covered. No numerical policy is adopted
by a successful test run.

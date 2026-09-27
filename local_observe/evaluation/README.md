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

## Data and scoring

`fault_inject.py` seeds actual `MetricSample` records into `InMemoryStore`, checks the resources
against the declared example inventory, then reads them through bounded `metric-threshold` queries.
It requires every seeded row to round-trip, refusing truncation. Platform intake validity is checked
on every scored canonical event; a test also files a generated event into the real temporary Store.
This is a deterministic detector-quality simulation, not proof of host failure handling.

`model.py` validates half-open truth windows, identities, classes, quiet controls and nested numeric
series. `eval.py` credits at most one true positive per incident; an identical source event is
deduplicated, while additional distinct findings for the same incident cost precision. Resource,
kind and observation time must all match. Resolved/unknown events cannot earn true-positive credit.
There is no tolerance or point-adjust mode; requesting point adjustment refuses. A zero-finding
precision is undefined (JSON null), never a perfect score.

Unlabelled intervals are unknown. Their findings count toward notification volume, but not
precision or recall. An empty incident list has undefined recall. Explicit quiet windows and
incident windows define the labelled intervals; a curated incident interval must enumerate its
known resource/class incidents before treating unmatched findings there as false positives.
No incident report by itself establishes quiet truth.

## Arms

- Static thresholds use the actual baseline detector and read the limits for matching resource and
  metric from `examples/platform/forecast.yaml`. These are shipped example settings, not evidence
  of estate deployment. The forecast time-to-threshold algorithm itself is not scored here.
- Seasonal detection imports `platform/anomaly.py` train/detect with hourly buckets, three training
  points and k=3; missing bucket history is explicitly unjudgeable.
- Shaping is a separate comparison baseline: minute means, Shewhart three-sigma detection and
  two-sided CUSUM (k=.5, h=4), resetting cumulative excess after firing. It is labelled comparison
  code, not an existing deployed detector.
- The `llm-rca` arm runs the actual observer when explicitly configured. It receives only series
  and evaluation windows, never incident or quiet labels. Each fixed hourly cycle uses production
  evidence validation and structured, grounded findings. Missing coverage, model failure and
  unstructured actionable output make the comparison incomplete. Without opt-in it stays
  unconfigured with no score. Retained journals are separate for each of the three runs.

Wrappers file at most once per resource per fixed hour, before truth is consulted. This cadence is
reported explicitly. The missing-telemetry class is deliberately uncovered by these value-based
arms; the report names it. The current corpus gives static precision 1, seasonal/shaping precision
.5, rates 6/12/12 findings per day (normalised from four hours), and recall 1/3 for each. These values
reflect explicit class matching on this tiny corpus, not broad production performance.

`report.py` runs each arm three times over fresh store/context data. Flip rates compare per-arm
outcomes, not disagreement between different arms. Observer timing, token counts and prose do not
change a verdict signature; decisions, coverage and canonical findings do. The observer reads one
fixed hour per cycle; seasonal/shaping baselines use the corpus's bounded preceding history. These
different context limits are disclosed in the report and must be considered when comparing quality.
`budget.py` imports
NotificationPolicy: attempts per channel rolling window, exhaustion latch and explicit reset;
no daily findings cap or per-rule precision floor is enforced by that legacy object.

The independent quality report requires precision ≥0.7, ≤2 findings/day, at least one correctly
detected class missed by both threshold baselines, and <10% observer verdict flips across three
runs. Every run must meet the floors; incomplete comparisons and unlabelled findings cannot pass.
Even a measured pass has `authorizes_delivery: false`. Representative held-out evidence and human
acceptance are separate from a synthetic CI pass. A four-hour demo cannot establish daily workload,
fit on a 16 GB VRAM device, review burden or long-term reliability.

Keep training/retrieval records separated from evaluation by incident and time. Preserve the frozen
evaluation set when comparing a later prompt, retrieval policy or model; never grade on its own
training corrections. Runtime evidence and exports belong in protected storage, outside Git.

## Tests and CI

The `evaluation` subgroup is registered in `tests/tiers.py`. Focused command:
`python -B tests/tiers.py --start-dir tests --only-tier evaluation --json <new-tier-report.json>`.
CI executes these tests once inside the existing covered base pass. Its additional evaluation step
generates and uploads the quality report, without a second unittest pass. Negative controls prove
fires-everywhere fails a deliberately chosen test policy and unwired stays unwired. Bounds,
half-open endpoints, wrong hosts/classes, duplicate findings, provenance tampering, missing seasonal
history, actual store reads and schema/checklist checks are covered. No numerical policy is adopted
by a successful test run.

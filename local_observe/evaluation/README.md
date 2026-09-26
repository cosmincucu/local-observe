# Offline detector evaluation

This package measures canonical detector events against labelled demo incidents. It never sends
notifications, reaches a live store, injects faults into a host or imports private incident data.

Run `python -B -m local_observe.evaluation --revision <full-commit-id> --output <new-report.json>`.
Existing outputs are refused. `--corpus` reads the bounded public exchange format in
`examples/corpus/schema.json`; without it the executable fault generator provides synthetic rows.
The revision is caller-supplied; the manifest independently hashes the corpus, implementation,
real estimator, store facade and configuration files. Runtime dependencies are the existing product
base environment only; no evaluation dependency was added.

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

## Arms

- Static thresholds use the actual baseline detector and read the limits for matching resource and
  metric from `examples/platform/forecast.yaml`. These are shipped example settings, not evidence
  of estate deployment. The forecast time-to-threshold algorithm itself is not scored here.
- Seasonal detection imports `platform/anomaly.py` train/detect with hourly buckets, three training
  points and k=3; missing bucket history is explicitly unjudgeable.
- Shaping is a separate comparison baseline: minute means, Shewhart three-sigma detection and
  two-sided CUSUM (k=.5, h=4), resetting cumulative excess after firing. It is labelled comparison
  code, not an existing deployed detector.
- LLM/RCA is explicitly unwired because this revision exposes no callable analyser. Its report has
  no score; it cannot silently pass by returning no findings. Similar-incident retrieval is excluded.

Wrappers file at most once per resource per fixed hour, before truth is consulted. This cadence is
reported explicitly. The missing-telemetry class is deliberately uncovered by these value-based
arms; the report names it. The current corpus gives static precision 1, seasonal/shaping precision
.5, rates 6/12/12 findings per day (normalised from four hours), and recall 1/3 for each. These values
reflect explicit class matching on this tiny corpus, not broad production performance.

`report.py` runs each arm three times over fresh store/context data. Flip rates compare per-arm
complete output signatures, not disagreement between different arms. `budget.py` imports
NotificationPolicy: attempts per channel rolling window, exhaustion latch and explicit reset;
no daily findings cap or per-rule precision floor is currently enforced by that object. The report
proposes .5 precision for review; CI installs no new numerical floor and preserves coverage at 76.

## Tests and CI

The `evaluation` subgroup is registered in `tests/tiers.py`. Focused command:
`python -B tests/tiers.py --start-dir tests --only-tier evaluation --json <new-tier-report.json>`.
CI executes these tests once inside the existing covered base pass. Its additional evaluation step
generates and uploads the quality report, without a second unittest pass. Negative controls prove
fires-everywhere fails a deliberately chosen test policy and unwired stays unwired. Bounds,
half-open endpoints, wrong hosts/classes, duplicate findings, provenance tampering, missing seasonal
history, actual store reads and schema/checklist checks are covered. No numerical policy is adopted
by a successful test run.

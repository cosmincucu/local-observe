# Detector corpus and publication review

`worked-example.json` demonstrates the public shape for an anonymised incident set. Its contents
were generated entirely by `python -B -m local_observe.evaluation.fault_inject`; no real incident
was anonymised or imported. Resource identities come from the declared demo inventory. It carries
a threshold burst, a statistical shift, missing telemetry and a quiet hour with no incident truth.

`schema.json` defines the exchange structure. The runtime validator additionally enforces finite
numbers, strictly increasing sample times, canonical UUIDs, non-overlapping same-class truth,
quiet/truth separation, bounded history and a one-MiB file limit. JSON Schema alone does not prove
these semantic invariants. Incident classes use the platform event kinds and are matched explicitly;
a threshold finding does not automatically receive credit for an anomaly-labelled incident.

Reviewer checklist for this generated worked example:

- [x] Generated from demo identities and a fixed clock; no captured telemetry, host names, addresses,
  account names, domains, file paths, log text, incident narratives or credentials are present.
- [x] Rows, intervals and class labels are reproducible from the generator. Missing telemetry is
  represented by absence of rows, not invented zero-valued observations.
- [x] Quiet intervals carry no incident truth. Labels are withheld from detector inputs.
- [x] Product foundation token scan runs over this directory; the regression test repeats the exact
  scanner's token list instead of restating a second list here.
- [ ] Any future private incident publication needs a separate owner-approved, reviewer-checked
  demo-overlay transformation, including indirect identifiers and linkability across timelines.
  This example is a format demonstration and grants no private-data publication permission.

Run `python -B -m local_observe.evaluation --corpus examples/corpus/worked-example.json --revision
<full-commit-id>` to print measurements and provenance. The imported notification policy reports
attempts per rolling window and a latched circuit; findings/day is a measured rate, not a send cap.

# Measuring review workload

Choose a bounded observation period before deciding how often to review findings.
Record deployment size, configured cadence and source coverage alongside feedback.
The same review frequency can create very different work on one resource and twenty.
Fixture tests cover these sizes; they do not measure a person's workload.

The local report reads protected observer state and sends no requests:

```sh
python -m local_observe.evaluation.feedback --state /approved/private/observer \
  --since 2026-01-01T00:00:00Z --until 2026-01-08T00:00:00Z --quiet-every 24
```

Replace the example dates with the actual measurement window. Keep the report private:
its review queue contains cycle identifiers. Windows are limited to 31 days and 3,000
cycles; use smaller windows when running more frequently. The report includes:

- Resources present in retained evidence, complete cycles and structured findings per day.
- Reviewed cycles, response rate and known versus unknown correctness.
- A bounded queue of findings, coverage gaps and sampled quiet cycles still awaiting review.
- Feedback latency, plus separately reported review effort when supplied.

Use `lo-observer ... replay CYCLE_ID` to inspect evidence, then submit independent feedback.
The optional `review_seconds` field records the human's estimate for that feedback version,
from 0 to 3,600 seconds. A correction may add another duration. The report sums supplied
durations and counts versions with missing durations separately. Telegram quick feedback
does not measure active review time. Time between an investigation and a response includes
waiting; it must never be presented as time spent reviewing.

The quiet interval selects every Nth complete quiet cycle in the measured cohort, starting
with the first. Reviewed cycles keep their position, so completing one review does not shift
the remaining sample. Sampling creates a local queue; it neither sends reminders nor labels
unsampled periods as correct. The default of 24 is configurable, not a recommended daily
commitment. Measure response rate and effort before choosing a sustained schedule.

A complete quiet cycle establishes only what the retained sources showed in that window.
Unanswered feedback and `unsure` correctness remain unknown. Resource count is not an
inventory census, and finding volume is not a count of successful phone deliveries. Compare
the channel delivery records separately. Evaluation must retain unlabelled findings and
incomplete coverage rather than turning either into a quality pass.

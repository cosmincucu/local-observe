"""Error budgets: what an SLO's attainment is, how fast its budget is burning, and when that pages.

Ported from `legacy:slo/` (370 lines: `objectives.py` 97, `errorbudget.py` 264, `__init__.py` 9),
converted on the strength of what the port plan recorded about it — "signal-source-agnostic and well
built" — and against its two stated reasons for deferring, which are answered here rather than argued
away:

* **it needed the escalation layer first**, because an error-budget burn is an *alerting condition* and
  v0.1 alerted by calling `derive_dedup_key` on a label set. That layer (`platform/conditions.py`,
  `platform/escalation.py`) merged as alert conditions, so the burn rule is now one more subject judged by the same
  ``for:`` state machine every other condition here uses, and its identity is `state.py`'s condition key
  rather than a hash of mutable label text;
* **nothing named an SLO surface in `docs/COMPONENTS.md`.** It still does not, and this card does not add
  a matrix row unilaterally; the proposal (and the §2 definition applied to it) is in the worker report,
  with the honest alternative being the `detections` row's `Where`/`If disabled` cells naming this
  package beside `conditions.py` and `dynamic_bands.py`, because that is what it is: one more producer of
  ordinary events.

Three modules, one boundary each:

* :mod:`local_observe.slo.objectives` — what an objective *is*: a target, a rolling compliance window and
  a good/bad classifier, importing nothing local. Its docstring names the two signals this build can
  actually evaluate and the one dead code culled.
* :mod:`local_observe.slo.budget` — the arithmetic: attainment, remaining budget, burn rate, and the
  multi-window fast-burn pair. Pure and clock-injected; it files nothing and knows no event schema.
* :mod:`local_observe.slo.alerts` — the contract crossing: the operator document (`LO_SLO_CONFIG`), the
  read through `local_observe/store/client.py` and nothing else, the burn as a sustained condition, and
  the canonical events out of `platform/detections.event` — the only event author in the package.

:mod:`local_observe.slo.__main__` is the looping worker (`python -m local_observe.slo`); the
`lo-platform slo` subcommand runs one round of the same `alerts.tick` (registered by rca, sharing
this package's configuration and cursor variables).

**No delivery path exists in this package.** Its one network call is ``POST /v1/events`` — the platform's
event door, which every producer here posts to and which books no send by itself. `grep -rn
"JsonClient|http" local_observe/slo` returns that import, its two construction arguments and the one
prose line naming the grep, and nothing else: no channel transport, no outbox claim, no delivery mode
read. `tests/test_slo_burn.py::SurfaceTests` pins that as syntax — the imports and the call names, not a
text scan, because `alerts.py` discusses the delivery rail in prose to answer notification budget. What this package
emits is events; whether a burn reaches a human is the platform service's decision, taken in
`platform/notification_safety.py` against the same per-channel budget every other alert spends (notification budget's
paragraph is in `alerts.py`, where the loudness is decided).
"""

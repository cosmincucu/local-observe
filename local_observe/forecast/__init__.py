"""Forecast: trend models and time-to-threshold predictions, filed as ordinary sustained events.

Ported from `legacy:forecast/` (T3.2 — `models.py` 127 lines, `timetothreshold.py` 139, `__init__.py` 21),
which the port plan deferred for two reasons. One is answered: v0.1's models read their series through
v0.1's own store facade (`legacy:forecast/models.py:14`), and `local_observe/store/client.py` (store facade) now
provides the equivalent, which is what `timetothreshold.points_from_store` reads through. The other is
**not** answered by this package and is stated for the reviewer rather than decided here: no
`docs/COMPONENTS.md` row names a capacity component to own a forecast. The candidate that honestly
covers it is `detections` — "Proven findings and source-coverage checks", read through the query
adapter, filed through event intake — and this package claims no new row unilaterally; the argument is
in the card's report.

What the port is, in one line each:

* `models.py` — OLS linear trend and Holt double-exponential smoothing over plain
  ``(epoch_seconds, value)`` points. Pure, bounded, stdlib arithmetic only.
* `timetothreshold.py` — the analytic crossing time for a linear fit and the step projection for Holt,
  each refusal carrying its reason (`flat`, `receding`, `insufficient`, `unfittable`, `already`); the
  `ForecastRule` that wraps a `conditions.Rule`; and the verdict that turns a prediction into a finding
  only through `alert conditions`'s sustained state machine.

The event: `kind='threshold'` with the ``.predicted`` condition namespace, severity from
`platform/vocabulary.severity` — never a `forecast` kind (event vocabulary owns that vocabulary, and
`vocabulary.REFUSALS` refuses v0.1's type by name) and never a severity literal. Read that module's
docstring before changing any of it.

Run it as ``python -m local_observe.forecast`` (the looping worker) or ``lo-platform forecast`` (one
round, registered by rca). Off unless ``LO_FORECAST_CONFIG`` names a file.
"""
from __future__ import annotations

from .models import (HoltFit, MAX_FIT_POINTS, MIN_FIT_POINTS, ModelRefused, Trend, checked,
                     fit, fit_holt, fit_linear)
from .timetothreshold import (CONFIG_ENVIRONMENT, CURSOR_ENVIRONMENT, OUTCOMES, PREDICTED_SUFFIX,
                              PREDICTION_STATES, SOURCE_ENVIRONMENT, ForecastRule, Prediction,
                              evaluate, load_config, points_from_store, producer_config, rule,
                              time_to_threshold, verdict)

__all__ = ['CONFIG_ENVIRONMENT', 'CURSOR_ENVIRONMENT', 'ForecastRule', 'HoltFit', 'MAX_FIT_POINTS',
           'MIN_FIT_POINTS', 'ModelRefused', 'OUTCOMES', 'PREDICTED_SUFFIX', 'PREDICTION_STATES',
           'Prediction', 'SOURCE_ENVIRONMENT', 'Trend', 'checked', 'evaluate', 'fit', 'fit_holt',
           'fit_linear', 'load_config', 'points_from_store', 'producer_config', 'rule',
           'time_to_threshold', 'verdict']

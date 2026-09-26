"""``python -m local_observe.forecast`` — the looping producer; off unless a file is named.

The start rules match the other optional product producers, so "off" means one thing
across the package (`anomaly.main`, `pathcheck.main`, `configdrift.main`):

* ``LO_FORECAST_CONFIG`` unset or blank → one INFO line naming the variable, exit 0, nothing opened —
  no store read, no cursor, no socket;
* the file named but unreadable or invalid → exit 1, because a producer that survived a broken
  configuration would be reporting a healthy capacity position on the strength of nothing;
* a configured producer with no cursor → exit 1. `conditions.tick` advances its window only after every
  event of a round was accepted, and a verdict with nowhere to record what it owes is a verdict that can
  be lost;
* the cursor's parent directory must already exist (the operator places it, as `anomaly_cursor` states
  for its own) and the process must hold `exclusive_owner` on it for its whole life, so two workers
  cannot judge the same series and open two incidents for one ramp.

The clock is the only wall-clock read here, and it is passed down: `verdict` aligns the evaluation
window to the document's `interval_seconds` exactly as `conditions.tick` does for a static tier, so a
restarted worker re-judging the same grid position asks the store the same question and gets
``duplicate`` from intake rather than a second page.

``lo-platform forecast`` is the one-round subcommand that reads the store in front of the operator
(registered by rca in `platform/cli.py`); this module stays the looping worker.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import os
import sqlite3
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from local_observe.credentials import read_credential
from local_observe.http import JsonClient, TransportError
from local_observe.log import get_logger
from local_observe.platform import conditions
from local_observe.platform.owner import exclusive_owner
from local_observe.platform.state import label
from . import timetothreshold

#: Not `__name__`: under ``python -m local_observe.forecast`` this module's own name is `__main__`, and
#: a service whose log lines are attributed to `__main__` cannot be grepped for by the operator who is
#: reading its journal. The package name is what the unit file and the portal will search for.
log = get_logger('local_observe.forecast')

#: The variables this worker reads. The first three are its own; the rest are what the Sigma runner and
#: every other producer already reads, so turning a forecast on grants nothing new.
STORE_VARIABLES = ('LO_CLICKHOUSE_URL', 'LO_CLICKHOUSE_USER', 'LO_CLICKHOUSE_PASSWORD_FILE')


def store_reader(environment: Mapping[str, str] | None = None) -> Any:
    """Build the store read facade, or refuse naming the variable that is missing.

    `local_observe/store/backends/clickhouse.py::store_from_environment` is the only way in — store facade
    fixed one read surface and one set of bounds, and a second query client in a forecasting package is
    a second thing to audit. `platform/cli.py::store_reader` is the same wrapper written for the
    conditions subcommand; it is not imported here because its refusal sentence names *its* producer,
    and an operator reading "conditions needs LO_CLICKHOUSE_USER" out of a forecast log line would be
    sent to the wrong service. Moving one helper out of the argparse layer to serve both is a follow-up
    for whichever card next owns `cli.py`.
    """
    values = os.environ if environment is None else environment
    missing = [name for name in STORE_VARIABLES if not values.get(name)]
    if missing:
        raise ValueError('forecast needs ' + ', '.join(missing)
                         + ' to read series; no second query transport exists in this product')
    from local_observe.store.backends.clickhouse import store_from_environment
    return store_from_environment(values)


def cursor_location(config: Mapping[str, Any],
                    environment: Mapping[str, str] | None = None) -> Path:
    """Return the cursor this producer may resume from, refusing a configured producer that has none.

    The document's own ``cursor`` key wins and ``LO_FORECAST_CURSOR`` is the alternative, because
    `pathcheck` carries its cursor in the document and `anomaly` carries it in the environment and this
    producer is allowed to be started the way either of its siblings is. What it will not do is run at
    all with neither: `conditions.load_cursor` would then have nothing to hold an undelivered batch, and
    a producer that drops the events it owes is worse than one that refuses to start.
    """
    environ = os.environ if environment is None else environment
    named = config.get('cursor') or (environ.get(timetothreshold.CURSOR_ENVIRONMENT) or '').strip()
    if not named:
        raise ValueError('Forecast producer needs a cursor: set the document\'s cursor key or '
                         + timetothreshold.CURSOR_ENVIRONMENT)
    return Path(str(named))


def round_once(index_path: Path | str, config: Mapping[str, Any], cursor: Path, reader: Any,
               deliver: Any, *, now: dt.datetime) -> dict[str, Any]:
    """Run one round through `conditions.tick` and return its summary — the whole delivery contract.

    The round driver is alert conditions's, unchanged: it resolves every rule's resource against the built index
    before any read runs, reads each series through `conditions.read_points` (one facade, one page
    bound), judges with the rule's own `judge`, holds the undelivered batch in the cursor and advances
    only once every event was accepted. Nothing here re-implements any of that.
    """
    state = conditions.load_cursor(cursor, config)
    return conditions.tick(index_path, config, cursor, reader, deliver, now=now, state=state)


def main() -> int:
    """Run the producer loop; exit 0 without touching anything when nothing is configured.

    Each round logs one INFO line with the per-rule outcome words — and, for a rule that predicted
    something, the instant it predicted — because the predicted crossing has no field in a canonical
    event (`state.validate_event`'s object is closed) and the log line is where an operator reads it. A
    failed round logs a WARNING naming the error class and repeats: the cursor is not advanced, so the
    window is owed again. This worker neither reads nor writes a notification mode; whether a predicted
    crossing pages a human is `Store.intake`'s booking decision and the channel budgets', as it is for
    every other producer's event.
    """
    stack = contextlib.ExitStack()
    try:
        config = timetothreshold.producer_config()
        if config is None:
            return 0
        cursor = cursor_location(config)
        if not cursor.parent.is_dir():
            raise ValueError('Forecast cursor parent does not exist; create it before starting')
        allow_http = os.environ.get('LO_INTERNAL_ALLOW_HTTP') == '1'
        reader = store_reader()
        platform = JsonClient(os.environ['LO_PLATFORM_URL'], read_credential('LO_PRODUCER_TOKEN'),
                              allow_http=allow_http)
        index_path = os.environ['LO_INDEX_PATH']
        source = os.environ[timetothreshold.SOURCE_ENVIRONMENT]
        label(source)
        stack.enter_context(exclusive_owner(cursor))
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        log.warning('Forecast producer cannot start; configuration is missing or invalid',
                    extra={'variable': timetothreshold.CONFIG_ENVIRONMENT,
                           'error_class': type(exc).__name__})
        stack.close()
        return 1

    def deliver(item: dict[str, Any]) -> None:
        """Post one event; anything other than 200 raises, so the cursor keeps the batch owed."""
        if platform.request('POST', '/v1/events', item)[0] != 200:
            raise TransportError('Forecast intake refused; the cursor is not advanced')

    log.info('Forecast producer started', extra={'rules': len(config['rules']),
                                                 'tick_seconds': config['interval_seconds']})
    try:
        while True:
            try:
                summary = round_once(index_path, config, cursor, reader, deliver,
                                     now=dt.datetime.now(dt.timezone.utc))
                log.info('Forecast round finished',
                         extra={'result': summary['result'], 'rules': summary['rules'],
                                'events': summary['events'], 'refusals': summary['refusals'],
                                'truncated': summary['truncated'],
                                # The refusal reasons travel on the line, because a refusal an operator
                                # cannot read is the same silence as a bug: `flat`, `insufficient` and
                                # "beyond the horizon" are each one sentence from `timetothreshold`, and
                                # the logging layer caps and redacts whatever a value smuggles in.
                                'because': {name: item['reason'] for name, item
                                            in summary['detail'].items() if item.get('reason')},
                                'predicted': {name: item['prediction']['eta']
                                              for name, item in summary['detail'].items()
                                              if item.get('prediction')}})
            except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
                # sqlite3.Error because a round opens the inventory index, whose absence or damage
                # surfaces as an OperationalError and is not an OSError: uncaught, it would end the loop
                # and let the service manager restart-loop on a missing mount (pathcheck's reason).
                log.warning('Forecast round unavailable; the cursor is not advanced, this round repeats',
                            extra={'error_class': type(exc).__name__})
                log.debug('Forecast round failed', exc_info=True)
            time.sleep(config['interval_seconds'])
    finally:
        stack.close()


if __name__ == '__main__':
    raise SystemExit(main())

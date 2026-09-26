"""`lo-platform slo` and `lo-platform forecast`: one round each, and off when nothing names a document.

Both subcommands were registered on this brief's custody of `cli.py` because their own packages had
parked them here: `local_observe/slo/__init__.py` and `local_observe/forecast/__init__.py` each said the
subcommand was "not registered, because `platform/cli.py` is another card's file in this wave", and
`docs/remediation/LEDGER.md`'s error budget row listed the same as a follow-up. What they asked for was "a few
lines rather than a redesign", and that is what this is: `alerts.tick` and `conditions.tick` are the same
drivers the looping workers call, reached through the same arguments, with the store in front of the
operator instead of `POST /v1/events`.

Four properties, per producer, and each one is why the subcommand is allowed to exist:

* **absent configuration is off** — exit 0, one INFO line naming the variable, nothing judged and
  nothing filed. An optional producer that is not switched on must not look broken;
* **a named document runs the real round** — a real built index, the real in-memory store backend, a
  real cursor file, and events that land in the platform's own table through `Store.intake`;
* **the flag and the looping worker agree on state** — with no `--config`/`--cursor`, the producer's own
  `$LO_SLO_CONFIG` / `$LO_SLO_CURSOR` (and the forecast document's `cursor` key, then
  `$LO_FORECAST_CURSOR`) are what get read, because one producer with two cursor files can re-judge a
  window the other already delivered, and a re-judged window is a *new* verdict rather than a duplicate
  the platform can fold;
* **a half-configuration is a refusal and never off** — a document named with no cursor, a cursor whose
  parent nobody created, and a document that is named but unreadable all answer one JSON line and exit 1,
  because reporting "nothing is burning" about budgets this round never opened is the one answer neither
  producer is allowed to give.

Everything runs in-process, following `tests/test_conditions.py::CommandLineTests`: `sys.argv` is
swapped, stdout captured, and `cli.store_reader` substituted, because the product's only series transport
is a ClickHouse the suite must never reach. The `Store`, the inventory index, the cursor file and the
intake are the real ones.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from local_observe.forecast import timetothreshold
from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import cli
from local_observe.platform.state import Store
from local_observe.slo import alerts
from local_observe.store.backends.memory import InMemoryStore, series
from local_observe.store.client import MetricSample

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
SLO_SOURCE = 'lo-slo'
FORECAST_SOURCE = 'lo-forecast'
METRIC = 'demo-availability'
SERIES = 'disk_used'
INTERVAL = 300
STEP = 300
#: Every variable these two producers read, so a test can be sure none of them leaked in from the
#: ambient environment: an off round that inherited somebody else's `LO_SLO_CONFIG` is not an off round.
MANAGED = (alerts.CONFIG_ENVIRONMENT, alerts.CURSOR_ENVIRONMENT, alerts.SOURCE_ENVIRONMENT,
           timetothreshold.CONFIG_ENVIRONMENT, timetothreshold.CURSOR_ENVIRONMENT,
           timetothreshold.SOURCE_ENVIRONMENT)


@contextlib.contextmanager
def clean_environment(**values: str | None):
    """Run the block with these variables set (a `None` deletes one) and every managed one otherwise clean."""
    keys = set(MANAGED) | set(values)
    previous = {key: os.environ.get(key) for key in keys}
    for key in keys:
        os.environ.pop(key, None)
    os.environ.update({key: value for key, value in values.items() if value is not None})
    try:
        yield
    finally:
        for key, value in previous.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value


def objective(objective_id: str, resource: str) -> dict:
    """One burning availability objective: 90 % over a day, the 15-minute/5-minute pair at 5x.

    The shape `tests/test_slo_worker_replay.py` drives its worker with, so a round here is a round that
    file already trusts, told through the CLI instead of through the loop.
    """
    return {'objective_id': objective_id, 'resource_id': resource, 'signal': 'availability',
            'target': 0.9, 'window_days': 1, 'long_window': 900, 'short_window': 300,
            'burn_threshold': 5.0, 'metric': METRIC, 'min_samples': 1,
            'severity_source': 'core-events-v1', 'severity_tier': 'warning',
            'evaluation_seconds': 300, 'for_seconds': 300, 'max_age_seconds': 900}


def forecast_rule(resource: str, **overrides) -> dict:
    """One forecast rule: a rising disk series that crosses 54 inside the hour.

    A flat series would be refused as `flat` and file nothing, which would make "the round filed its
    events" below a test of the refusal path rather than of the round.
    """
    document = {'id': 'pool-disk', 'series': SERIES, 'resource_id': resource, 'source': FORECAST_SOURCE,
                'severity_source': 'core-events-v1', 'severity_tier': 'warning', 'threshold': 54.0,
                'model': 'linear', 'horizon_seconds': 3600, 'min_points': 4,
                'evaluation_seconds': STEP, 'history_seconds': 86400, 'max_age_seconds': 3600,
                'for_seconds': 600}
    document.update(overrides)
    return document


def ramp_rows(resource: str, *, count: int = 40, start_value: float = 10.0) -> list[MetricSample]:
    """A rising series whose newest point sits one step inside the read window, as store rows.

    The half-open `[start, end)` window is `store/backends/memory.py`'s rule: a row stamped exactly at
    ``end`` belongs to the next window, so a fixture that put its newest sample there would be one point
    shorter than its name says and could quietly stop the fit from having enough points.
    """
    edge = NOW - dt.timedelta(seconds=STEP)
    return [MetricSample(name=SERIES, value=float(start_value + position), resource_id=resource,
                         labels={'resource_id': resource},
                         timestamp=utc_text(edge - dt.timedelta(seconds=STEP * (count - 1 - position))))
            for position in range(count)]


class CommandLineRoundTests(unittest.TestCase):
    """`lo-platform slo` / `lo-platform forecast`, driven the way an operator drives them."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.database = self.root / 'state.db'
        self.cursor = self.root / 'cursor.json'

    def write(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def run_cli(self, *arguments: str, reader: InMemoryStore | None = None):
        """One `cli.main()` call: argv swapped, stdout and stderr captured, the store facade substituted.

        The substituted reader is counted, so an off round can be shown to have asked for no series
        rather than being believed when it says so.
        """
        argv = ['lo-platform', '--database', str(self.database), *arguments]
        out, err = io.StringIO(), io.StringIO()
        probe = mock.Mock(return_value=reader or InMemoryStore())
        with mock.patch.object(cli, 'store_reader', probe), mock.patch.object(sys, 'argv', argv), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main()
        return code, json.loads(out.getvalue()), err.getvalue(), probe

    def filed(self) -> list[dict]:
        return [json.loads(row['payload']) for row in Store(self.database).records('events')]

    # -- slo ------------------------------------------------------------------------------------

    def slo_config(self, **overrides) -> Path:
        document = {'objectives': [objective('api.availability', self.host)],
                    'interval_seconds': INTERVAL}
        document.update(overrides)
        return self.write('slo.json', document)

    def burning(self) -> InMemoryStore:
        """Failed availability checks spanning an hour before `NOW` to past it, so the burn is current."""
        return InMemoryStore(series(90, name=METRIC, resource_id=self.host,
                                    start=utc_text(NOW - dt.timedelta(seconds=3600)),
                                    step_seconds=60, value=0.0))

    def test_slo_with_nothing_named_is_off_and_asks_the_store_for_nothing(self) -> None:
        with clean_environment():
            code, result, _log, probe = self.run_cli('slo', reader=self.burning())
        self.assertEqual(code, 0)
        self.assertEqual(result, {'status': 'off', 'configured': False})
        probe.assert_not_called()
        self.assertFalse(self.cursor.exists())
        store = Store(self.database)
        self.assertEqual(store.records('events'), [])
        self.assertEqual(store.status()['incidents'], {})

    def test_slo_off_says_so_once_and_names_the_variable_it_wanted(self) -> None:
        """`off` is a sentence an operator can grep, and only one line of it.

        The line is the producer package's own (`alerts.producer_config`), which is why the CLI writes no
        second one: two ways of saying "not switched on", from two loggers, is two things to keep in
        step and one more place for the wording to disagree with the component contract.
        """
        with clean_environment(), self.assertLogs(alerts.__name__, 'INFO') as captured:
            code, result, _log, probe = self.run_cli('slo', reader=self.burning())
        self.assertEqual((code, result['status']), (0, 'off'))
        probe.assert_not_called()
        infos = [record for record in captured.records if record.levelname == 'INFO']
        named = [record for record in infos if alerts.CONFIG_ENVIRONMENT in record.getMessage()
                 or alerts.CONFIG_ENVIRONMENT in str(getattr(record, 'variable', ''))]
        self.assertEqual(len(named), 1, f'off is one line wide, saw: {infos}')

    def test_slo_a_named_document_files_its_objectives_into_the_store(self) -> None:
        config = self.slo_config()
        with clean_environment():
            code, result, _log, _probe = self.run_cli(
                'slo', '--config', str(config), '--cursor', str(self.cursor), '--index',
                str(self.index), '--source', SLO_SOURCE, '--now', utc_text(NOW), reader=self.burning())
        self.assertEqual(code, 0, result)
        self.assertEqual(result['status'], 'delivered')
        self.assertGreaterEqual(result['events'], 1, 'a burning objective must file something')
        self.assertEqual(len(result['intake']), result['events'])
        self.assertEqual(len(self.filed()), result['events'])
        self.assertTrue(self.cursor.exists(), 'the round that filed also recorded what it owed')

    def test_slo_reads_its_own_environment_when_the_flag_stays_home(self) -> None:
        """The variables the worker already reads are the ones the command reads: no new names.

        This is the half that keeps one producer holding one cursor: if the command invented its own
        variable, an operator switching the service on would get a round that judged the same windows
        from a different file and re-delivered what the worker had already sent.
        """
        config = self.slo_config()
        with clean_environment(**{alerts.CONFIG_ENVIRONMENT: str(config),
                                  alerts.SOURCE_ENVIRONMENT: SLO_SOURCE,
                                  alerts.CURSOR_ENVIRONMENT: str(self.cursor)}):
            code, result, _log, _probe = self.run_cli('slo', '--index', str(self.index),
                                                      reader=self.burning())
        self.assertEqual(code, 0, result)
        self.assertEqual(result['status'], 'delivered')
        self.assertTrue(self.cursor.exists())

    def test_slo_the_flag_names_the_cursor_the_worker_would_have_used_instead(self) -> None:
        """Precedence is stated and pinned: the flag, then the worker's variable, then a refusal."""
        config = self.slo_config()
        other = self.root / 'other-cursor.json'
        with clean_environment(**{alerts.CURSOR_ENVIRONMENT: str(other)}):
            code, _result, _log, _probe = self.run_cli(
                'slo', '--config', str(config), '--cursor', str(self.cursor), '--index',
                str(self.index), '--source', SLO_SOURCE, '--now', utc_text(NOW), reader=self.burning())
        self.assertEqual(code, 0)
        self.assertTrue(self.cursor.exists())
        self.assertFalse(other.exists(), 'the environment cursor was not touched by an overriding flag')

    def test_slo_a_document_with_no_cursor_is_a_refusal_and_not_off(self) -> None:
        config = self.slo_config()
        with clean_environment():
            code, result, _log, probe = self.run_cli('slo', '--config', str(config), '--index',
                                                    str(self.index), '--source', SLO_SOURCE,
                                                    reader=self.burning())
        self.assertEqual((code, result['status'], result['error_type']), (1, 'error', 'ValueError'))
        probe.assert_not_called()
        self.assertEqual(Store(self.database).records('events'), [])

    def test_slo_an_unreadable_document_is_a_refusal_and_not_off(self) -> None:
        """A file that is named and broken cannot answer "nothing is burning"."""
        broken = self.root / 'slo-broken.json'
        broken.write_text('{not json', encoding='utf-8')
        with clean_environment():
            code, result, _log, _probe = self.run_cli('slo', '--config', str(broken), '--cursor',
                                                      str(self.cursor), '--index', str(self.index),
                                                      '--source', SLO_SOURCE)
        self.assertEqual((code, result['status']), (1, 'error'))
        self.assertFalse(self.cursor.exists())

    def test_slo_a_cursor_parent_that_does_not_exist_is_refused_before_any_read(self) -> None:
        config = self.slo_config()
        with clean_environment():
            code, result, _log, probe = self.run_cli(
                'slo', '--config', str(config), '--cursor', str(self.root / 'nope' / 'c.json'),
                '--index', str(self.index), '--source', SLO_SOURCE, reader=self.burning())
        self.assertEqual((code, result['status']), (1, 'error'))
        probe.assert_not_called()

    # -- forecast -------------------------------------------------------------------------------

    def forecast_config(self, *, cursor: str | None = None) -> Path:
        document: dict = {'rules': [forecast_rule(self.host)], 'interval_seconds': INTERVAL}
        if cursor is not None:
            document['cursor'] = cursor
        return self.write('forecast.json', document)

    def rising(self) -> InMemoryStore:
        return InMemoryStore(ramp_rows(self.host))

    def test_forecast_with_nothing_named_is_off_and_asks_the_store_for_nothing(self) -> None:
        with clean_environment(), self.assertLogs(timetothreshold.__name__, 'INFO') as captured:
            code, result, _log, probe = self.run_cli('forecast', reader=self.rising())
        self.assertEqual(code, 0)
        self.assertEqual(result, {'status': 'off', 'configured': False})
        probe.assert_not_called()
        infos = [record for record in captured.records if record.levelname == 'INFO']
        named = [record for record in infos
                 if timetothreshold.CONFIG_ENVIRONMENT in record.getMessage()
                 or timetothreshold.CONFIG_ENVIRONMENT in str(getattr(record, 'variable', ''))]
        self.assertEqual(len(named), 1, f'off is one line wide, saw: {infos}')
        self.assertFalse(self.cursor.exists())
        self.assertEqual(Store(self.database).records('events'), [])

    def test_forecast_a_named_document_files_its_prediction_as_a_condition(self) -> None:
        config = self.forecast_config()
        with clean_environment():
            code, result, _log, _probe = self.run_cli(
                'forecast', '--config', str(config), '--cursor', str(self.cursor), '--index',
                str(self.index), '--now', utc_text(NOW), reader=self.rising())
        self.assertEqual(code, 0, result)
        self.assertEqual(result['status'], 'delivered')
        self.assertGreaterEqual(result['events'], 1, 'a rising series inside its horizon must file')
        self.assertEqual(len(result['intake']), result['events'])
        self.assertTrue(self.cursor.exists())
        kinds = {item['kind'] for item in self.filed()}
        conditions = {item['rule_id'] for item in self.filed()}
        self.assertIn('threshold', kinds, 'a prediction files a `threshold` condition, never a new kind')
        self.assertTrue(any('.predicted' in str(value) for value in conditions),
                        'the predicted crossing is its own condition namespace')

    def test_forecast_the_document_s_cursor_key_is_respected(self) -> None:
        """`forecast` reads its cursor from the document first, because that is how its worker starts."""
        inside = self.root / 'from-document.json'
        config = self.forecast_config(cursor=str(inside))
        with clean_environment(**{timetothreshold.CURSOR_ENVIRONMENT: str(self.root / 'env.json')}):
            code, _result, _log, _probe = self.run_cli('forecast', '--config', str(config), '--index',
                                                      str(self.index), '--now', utc_text(NOW),
                                                      reader=self.rising())
        self.assertEqual(code, 0)
        self.assertTrue(inside.exists())
        self.assertFalse((self.root / 'env.json').exists())

    def test_forecast_a_document_with_no_cursor_anywhere_is_a_refusal_and_not_off(self) -> None:
        config = self.forecast_config()
        with clean_environment():
            code, result, _log, probe = self.run_cli('forecast', '--config', str(config), '--index',
                                                     str(self.index), reader=self.rising())
        self.assertEqual((code, result['status'], result['error_type']), (1, 'error', 'ValueError'))
        probe.assert_not_called()
        self.assertEqual(Store(self.database).records('events'), [])

    def test_forecast_a_cursor_parent_that_does_not_exist_is_refused_before_any_read(self) -> None:
        config = self.forecast_config()
        with clean_environment():
            code, result, _log, probe = self.run_cli(
                'forecast', '--config', str(config), '--cursor', str(self.root / 'nope' / 'c.json'),
                '--index', str(self.index), reader=self.rising())
        self.assertEqual((code, result['status']), (1, 'error'))
        probe.assert_not_called()

    def test_forecast_an_unreadable_document_is_a_refusal_and_not_off(self) -> None:
        broken = self.root / 'forecast-broken.json'
        broken.write_text('[1,2,3]', encoding='utf-8')
        with clean_environment():
            code, result, _log, _probe = self.run_cli('forecast', '--config', str(broken), '--cursor',
                                                      str(self.cursor), '--index', str(self.index))
        self.assertEqual((code, result['status']), (1, 'error'))
        self.assertFalse(self.cursor.exists())


if __name__ == '__main__':
    unittest.main()

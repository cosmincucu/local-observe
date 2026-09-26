"""The component wrapper: what ships, what it may not touch, and the row's *If disabled* clause as a test.

Three claims from `docs/COMPONENTS.md`'s `rca` row are checked here rather than asserted in prose:

* the five quality bar artefacts, **minus the one this component deliberately does not have**, with the reason
  in the file that replaces it;
* `versions.json` says `selected`, which is the artefact line that says nothing here is validated
  (task 7: no published quality claim before the corpus gate, `corpus eval`);
* *"Detection, incidents and notifications still work"* — proven twice: structurally, by naming every
  module that imports this one, and behaviourally, by running the same §5 failure-to-recovery path with
  the component used and unused and comparing the durable state it left behind.
"""
import ast
import contextlib
from collections.abc import Mapping
from contextlib import closing
import datetime as dt
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
from typing import Any

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp, utc_text
from local_observe.platform import cli, rca
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_foundation as checks  # noqa: E402  (the script tree is not a package)

COMPONENT = ROOT / 'components' / 'control' / 'rca'
NOW = timestamp('2026-09-09T12:00:00Z')
SERVICE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
HOST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
WINDOW = {'start': '2026-09-09T11:58:00Z', 'end': '2026-09-09T11:59:00Z'}
LATER = {'start': '2026-09-09T12:00:00Z', 'end': '2026-09-09T12:01:00Z'}
PRODUCER = Actor('component-detector', 'producer')
UUID_TEXT = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
INSTANT = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})')


def declared_fixture(root: Path) -> Path:
    path = root / 'inventory.db'
    index.build(read_document(ROOT / 'examples/inventory/declared.yaml'), path, 'fixture', now=NOW)
    return path


def open_incident(store: Store) -> None:
    """The §5 first half: one injected service failure, filed through the only event door there is."""
    store.put_evidence({'sample_id': 'component-sample', 'observed_at': WINDOW['end'], 'ok': False,
                        'value': 0}, PRODUCER, now=NOW)
    store.intake(event('component-detector', SERVICE, 'api.down', 'availability', 'firing', WINDOW,
                       {'sample_id': 'component-sample'}, query_type='gatus-result'), PRODUCER, now=NOW)


def resolve_incident(store: Store) -> None:
    """The §5 second half: the recovery that updates the same condition, an hour later in the clock."""
    store.intake(event('component-detector', SERVICE, 'api.down', 'availability', 'resolved', LATER,
                       {'sample_id': 'component-sample'}, query_type='gatus-result'), PRODUCER,
                 now=NOW + dt.timedelta(hours=1))


def durable_state(store: Store) -> dict:
    """Everything the core scenario is allowed to leave behind, minus the explanation rows.

    `audit` is excluded on one axis only — the operations this component writes — because comparing it
    whole would compare the proof of the test alongside the thing under test. Every other byte of
    operational state must be identical with the component running and without it.

    Two things are masked rather than compared, because they differ by construction and not by
    behaviour: identifiers (every row id, incident id and outbox id is a fresh uuid4 per database) and
    instants (each run stamps its own wall clock). Masking them is the honest form of the question —
    "did the component change what the platform decided, stored, queued and said?" — while comparing the
    raw ids would compare two different runs of the same scenario and call the difference a finding. What
    stays unmasked is every verdict, status, condition key, resource id, payload field, attempt count and
    audit operation, which is where a side effect would have to appear.
    """
    with closing(sqlite3.connect(store.path)) as connection:
        audit = [(mask(row[0]), row[1], row[2], row[3]) for row in connection.execute(
            'SELECT at, actor, operation, subject FROM audit ORDER BY sequence')]
        return {'status': mask(store.status()),
                'events': [mask(row['payload']) for row in store.records('events')],
                'incidents': [(row['status'], mask(row['condition_key']), row['resource_id'],
                               '<id>') for row in store.records('incidents')],
                'outbox': [mask(json.loads(row['payload'])) for row in store.records('outbox')],
                'evidence_rows': connection.execute('SELECT count(*) FROM evidence').fetchone()[0],
                'audit_without_rca': [row for row in audit if not row[2].startswith('rca.')],
                'audit_all': audit}


def mask(value: Any) -> Any:
    """Replace identifiers and instants with fixed placeholders, recursively and read-only.

    The shapes are the product's own: a uuid4 in its canonical text form, and an ISO-8601 instant with
    an offset or a `Z`. Anything that is not one of those two shapes survives untouched, so a changed
    verdict, severity, condition key or delivery mode cannot hide inside the masking — the only way to
    pass this comparison while having changed a decision is to make the uuid or timestamp regexes wrong,
    which is a defect a reader would see in these four lines.
    """
    if isinstance(value, str):
        value = UUID_TEXT.sub('<id>', value)
        return INSTANT.sub('<t>', value)
    if isinstance(value, Mapping):
        return {key: mask(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [mask(item) for item in value]
    return value


class ShippedArtefactsTests(unittest.TestCase):
    def test_the_four_lifecycle_documents_and_the_pin_are_all_present(self) -> None:
        for name in ('CONTRACT.md', 'backup.md', 'upgrade.md', 'conformance.md', 'versions.json'):
            with self.subTest(artefact=name):
                self.assertTrue((COMPONENT / name).is_file(), f'{name} is missing')

    def test_the_component_ships_no_compose_model_and_says_which_image_it_runs_in(self) -> None:
        """Task 5's question, answered in the tree: no service, because it is a command in the platform image.

        A second container would be a second writer of the operational database, and
        `docs/CONTRACTS.md` §5 names one platform service as its owner/writer — the serving process
        holds `platform/owner.py`'s exclusive lock on that file for its whole life. The component
        therefore runs inside `${LO_PLATFORM_IMAGE}` as `lo-platform rca`, and the manifest it owes is
        the sentence that says so. `components/data/agent-windows` is the precedent: a row with no
        Compose model by design, for a reason a reader can check.
        """
        self.assertFalse((COMPONENT / 'compose.yaml').exists(),
                         'a compose.yaml here would promise a service the platform lock forbids')
        contract = (COMPONENT / 'CONTRACT.md').read_text(encoding='utf-8')
        for claim in ('LO_PLATFORM_IMAGE', 'no `compose.yaml`', 'exclusive_owner',
                      'components/data/agent-windows'):
            with self.subTest(claim=claim):
                self.assertIn(claim, contract)

    def test_the_pin_file_states_selected_and_says_so_in_the_line_that_carries_it(self) -> None:
        """Task 7: nothing is validated before `corpus eval`, and `versions.json` is where that is written."""
        pin = json.loads((COMPONENT / 'versions.json').read_text(encoding='utf-8'))
        self.assertEqual(pin['component'], 'rca')
        self.assertEqual(pin['status'], 'selected')
        self.assertIsNone(pin['verified_on'])
        self.assertEqual(pin['validation']['runtime_conformance'], 'not-run')
        self.assertFalse(pin['validation']['container_started'])
        self.assertFalse(pin['validation']['corpus_gate_run'],
                         'the quality claim gate is corpus eval and it has not run')
        self.assertIsNone(pin['quality_claim']['precision'])
        self.assertIn('corpus eval', json.dumps(pin['quality_claim']))

    def test_no_shipped_example_composes_this_component(self) -> None:
        """Like `components/control/ai`: the manifest is opt-in, and a default install needs none of it."""
        for name in ('examples/full/compose.yaml', 'examples/demo/compose.yaml',
                     'examples/platform/compose.yaml'):
            body = (ROOT / name).read_text(encoding='utf-8')
            with self.subTest(example=name):
                self.assertNotIn('control/rca', body)
        services, errors = checks.example_services(ROOT, ROOT / 'examples/full/compose.yaml')
        self.assertEqual(errors, [])
        self.assertNotIn('rca', services)

    def test_the_privacy_gate_still_passes_over_the_whole_tree(self) -> None:
        """`check_example` never reaches a directory no example includes, so the privacy walk is the check."""
        self.assertEqual(checks.check_private_references(ROOT), [])


class ImportBoundaryTests(unittest.TestCase):
    """`If disabled: Detection, incidents and notifications still work`, as a property of the tree."""

    def importers(self) -> list[str]:
        """Every product module that reaches this one with an `import`, found by AST and not by grep.

        Three shapes count, because the product uses all three: importing the name `rca` absolutely,\n"
        importing it relatively (`from . import escalation, rca` in `cli.py`), and importing anything out
        of `....rca` — which includes the function-local `from .rca import stored` in `presentation.py`,
        because an AST walk does not care where in a file a line sits. A relative import is matched on
        the tail of its module rather than by package arithmetic: the question is "does this file reach
        rca", not "under what absolute name does it arrive".
        """
        found = []
        for path in sorted((ROOT / 'local_observe').rglob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import) and any(alias.name.split('.')[-1] == 'rca'
                                                        for alias in node.names):
                    found.append(path)
                    break
                if isinstance(node, ast.ImportFrom) and (node.module or '').split('.')[-1] == 'rca':
                    found.append(path)
                    break
                if isinstance(node, ast.ImportFrom) and any(alias.name == 'rca'
                                                            for alias in node.names):
                    found.append(path)
                    break
        return [path.relative_to(ROOT).as_posix() for path in found]

    def test_exactly_two_modules_import_this_one(self) -> None:
        """The command that runs a round, and the view that reads the record back. Nothing else.

        This is the `If disabled` clause read structurally: `api.py` cannot depend on it, the delivery
        rail cannot, and no producer can, so deleting this module costs an operator one label on one view
        and one subcommand — which is exactly what the component row claims, and the only two names this
        assertion can therefore tolerate.
        """
        self.assertEqual(self.importers(), ['local_observe/platform/cli.py',
                                            'local_observe/platform/presentation.py'])

    def test_the_serving_and_delivery_modules_do_not_name_it_at_all(self) -> None:
        for relative in ('local_observe/platform/api.py', 'local_observe/platform/notifications.py',
                         'local_observe/platform/state.py', 'local_observe/platform/detections.py',
                         'local_observe/platform/conditions.py', 'local_observe/platform/channels.py'):
            with self.subTest(module=relative):
                self.assertNotIn('rca.', (ROOT / relative).read_text(encoding='utf-8'))


class CoreScenarioUnchangedTests(unittest.TestCase):
    """The same §5 run, one variable: whether `rca` was ever asked to do anything."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = declared_fixture(self.root)

    def store(self, name: str) -> Store:
        return Store(self.root / f'{name}.db')

    def deliver(self, store: Store) -> None:
        """Send what the outbox holds into a recording sink, the way `lo-platform notify` does."""
        from local_observe.platform.notification_safety import RecordingSink
        from local_observe.platform.notifications import deliver_one

        store.start_notification_mode()
        deliver_one(store, RecordingSink())

    def run_scenario(self, store: Store, *, with_rca: bool) -> dict:
        open_incident(store)
        if with_rca:
            rca.tick(store, self.index,
                     config={'max_incidents': 5, 'max_model_calls': 2, 'lookback_seconds': 3_600,
                             'data_class': 'internal'},
                     source='component-rca', now=NOW)
        self.deliver(store)
        resolve_incident(store)
        if with_rca:
            rca.tick(store, self.index,
                     config={'max_incidents': 5, 'max_model_calls': 2, 'lookback_seconds': 3_600,
                             'data_class': 'internal'},
                     source='component-rca', now=NOW + dt.timedelta(hours=1))
        self.deliver(store)
        return durable_state(store)

    def test_the_core_scenario_is_the_same_state_with_the_component_running_or_deleted(self) -> None:
        """Identical incidents, events, outbox payloads, evidence and non-rca audit rows.

        This is the row's *If disabled* clause at the only level this repository can prove it: a host
        run (`docker compose rm` of the command that invokes it, per `conformance.md`) is the same
        claim one floor up, and is listed un-run in that file.
        """
        quiet = self.run_scenario(self.store('quiet'), with_rca=False)
        talking_store = self.store('talking')
        talking = self.run_scenario(talking_store, with_rca=True)
        for key in ('status', 'events', 'incidents', 'outbox', 'evidence_rows', 'audit_without_rca'):
            with self.subTest(state=key):
                self.assertEqual(quiet[key], talking[key])
        written = [row for row in talking['audit_all'] if row[2] == 'rca.explained']
        self.assertTrue(written, 'the component wrote nothing, so the comparison above compared '
                                 'nothing but itself')
        self.assertEqual({row[1] for row in written}, {'component-rca'})

    def test_the_component_writes_no_operational_state_of_its_own(self) -> None:
        """One audit row per explanation, and nothing else: no event, incident, outbox or evidence write."""
        store = self.store('writes')
        open_incident(store)
        before = store.status()
        with closing(sqlite3.connect(store.path)) as connection:
            counts = {table: connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                      for table in ('events', 'incidents', 'outbox', 'evidence', 'actions',
                                    'executions', 'notification_attempts', 'notification_reservations',
                                    'notification_suppressions')}
        rca.tick(store, self.index, config={'max_incidents': 5, 'max_model_calls': 2,
                                            'lookback_seconds': 3_600, 'data_class': 'internal'},
                 source='component-rca', now=NOW)
        with closing(sqlite3.connect(store.path)) as connection:
            after = {table: connection.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
                     for table in counts}
            audit_rows = connection.execute("SELECT count(*) FROM audit WHERE operation='rca.explained'"
                                            ).fetchone()[0]
        self.assertEqual(before, store.status(), 'incidents, actions or deliveries moved')
        self.assertEqual(counts, after, 'the component wrote to a table other than audit')
        self.assertEqual(audit_rows, 1)


class CommandTests(unittest.TestCase):
    """`lo-platform rca`: absent configuration is off, and off writes nothing."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = self.root / 'state.db'
        self.index = declared_fixture(self.root)
        open_incident(Store(self.database))

    def config(self, payload: dict) -> Path:
        path = self.root / 'rca.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def run_cli(self, *argv: str) -> tuple[int, dict, str]:
        original = list(sys.argv)
        sys.argv = ['lo-platform', '--database', str(self.database), *argv]
        printed, logged = io.StringIO(), io.StringIO()
        try:
            with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(logged):
                code = cli.main()
        finally:
            sys.argv = original
        return code, json.loads(printed.getvalue()), logged.getvalue()

    def rows(self, sql: str) -> list[tuple]:
        with closing(sqlite3.connect(self.database)) as connection:
            return [tuple(row) for row in connection.execute(sql)]

    def test_no_config_named_is_off_and_wrote_nothing(self) -> None:
        code, payload, log = self.run_cli('rca')
        self.assertEqual(code, 0)
        self.assertEqual(payload, {'status': 'off', 'configured': False, 'analyzed': 0})
        self.assertEqual(log, '', 'an off round has nothing to warn about, and nothing to leak')
        self.assertEqual(self.rows("SELECT count(*) FROM audit WHERE operation='rca.explained'"), [(0,)])

    def test_a_round_records_one_explanation_and_the_next_round_records_nothing_new(self) -> None:
        document = self.config({'max_incidents': 3, 'max_model_calls': 1})
        code, payload, _ = self.run_cli('rca', '--config', str(document), '--index', str(self.index),
                                        '--source', 'component-rca', '--now', '2026-09-09T12:00:00Z')
        self.assertEqual(code, 0, payload)
        self.assertEqual(payload['status'], 'ran')
        self.assertEqual(payload['analyzed'], 1)
        self.assertEqual(payload['written'], 1)
        self.assertFalse(payload['model_used'], 'the CLI never constructs the optional client')
        self.assertEqual(self.rows("SELECT count(*) FROM audit WHERE operation='rca.explained'"), [(1,)])

        code, again, _ = self.run_cli('rca', '--config', str(document), '--index', str(self.index),
                                      '--source', 'component-rca', '--now', '2026-09-09T12:05:00Z')
        self.assertEqual(code, 0)
        self.assertEqual(again['written'], 0)
        self.assertEqual(again['unchanged'], 1)
        self.assertEqual(self.rows("SELECT count(*) FROM audit WHERE operation='rca.explained'"), [(1,)],
                         'a five-minute timer must not turn one quiet incident into 288 audit rows a day')

    def test_the_record_reaches_the_incident_view_as_a_label_and_only_a_label(self) -> None:
        from local_observe.platform import presentation

        document = self.config({})
        code, _payload, _log = self.run_cli('rca', '--config', str(document), '--index',
                                            str(self.index), '--source', 'component-rca', '--now',
                                            '2026-09-09T12:00:00Z')
        self.assertEqual(code, 0)
        store = Store(self.database)
        rows = presentation.records(store, 'incidents', store.records('incidents'), self.index)
        display = rows[0]['display']
        self.assertIn('cause_name', display)
        self.assertIn(display['cause_confidence'], rca.CONFIDENCE)
        self.assertEqual(display['cause_basis'], 'Rule floor only')
        self.assertTrue(len(json.dumps(display)) < 2_000, 'a display cell is a label, not a bundle')

    def test_a_source_without_a_config_is_refused_before_the_store_is_opened_for_writing(self) -> None:
        document = self.config({})
        code, payload, _ = self.run_cli('rca', '--config', str(document))
        self.assertEqual(code, 1)
        self.assertEqual(payload['status'], 'error')
        self.assertEqual(self.rows("SELECT count(*) FROM audit WHERE operation='rca.explained'"), [(0,)])

    def test_an_enabled_executor_refuses_from_the_cli_too(self) -> None:
        code, payload, log = self.run_cli('rca', '--config', str(self.config({'executor':
                                                                             {'enabled': True}})),
                                          '--source', 'component-rca')
        self.assertEqual(code, 1)
        self.assertEqual(payload, {'status': 'error', 'error_type': 'RcaError'})
        self.assertEqual(self.rows("SELECT count(*) FROM audit WHERE operation='rca.explained'"), [(0,)],
                         'a refused configuration still wrote its answer into the audit trail')


class LatestExplanationPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'state.db')

    def incidents(self, count: int) -> list[dict]:
        for number in range(count):
            self.store.intake(event(PRODUCER.identity, None, f'page.{number}', 'availability',
                                    'firing', WINDOW, {'rule_id': f'page.{number}'},
                                    query_type='gatus-result'), PRODUCER, now=NOW)
        with closing(sqlite3.connect(self.store.path)) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute('SELECT * FROM incidents ORDER BY rowid')]

    def explain(self, incident: dict, cause: str) -> dict:
        body = rca.bundle(self.store, incident, now=NOW)
        detail = rca.explanation_record(PRODUCER.identity, body, rca.explain(body))
        detail.update(causes=[cause], confidence='indicated', rules=['earliest-upstream-finding'])
        rca.record(self.store, incident['id'], detail, PRODUCER, now=NOW)
        return detail

    def test_independent_revisions_missing_incident_and_unrelated_operations_match_single_reads(self) -> None:
        from local_observe.platform import presentation

        rows = self.incidents(3)
        self.explain(rows[0], 'First revision for first incident')
        self.explain(rows[1], 'First revision for second incident')
        second = self.explain(rows[1], 'Latest second cause')
        first = self.explain(rows[0], 'Latest first cause')
        with self.store.transaction() as connection:
            self.store.audit(connection, NOW, PRODUCER.identity, 'incident.note', rows[1]['id'], first)
            self.store.audit(connection, NOW, PRODUCER.identity, 'rca.explained',
                             '09c61a92-a4a3-4865-bd3d-1b5e48f434c4', second)
        with closing(sqlite3.connect(self.store.path)) as connection:
            many = rca.latest_many(connection, [row['id'] for row in rows])
            self.assertEqual(many, {rows[0]['id']: first, rows[1]['id']: second})
            self.assertEqual(many, {row['id']: value for row in rows
                                    if (value := rca.stored(connection, row['id'])) is not None})
        rendered = presentation.records(self.store, 'incidents', rows)
        self.assertEqual([row['display'].get('cause_name') for row in rendered],
                         ['Latest first cause', 'Latest second cause', None])

    def test_more_than_one_chunk_renders_every_latest_label_with_bounded_batch_queries(self) -> None:
        from local_observe.platform import presentation

        rows = self.incidents(rca.LATEST_MANY_CHUNK + 1)
        # Valid records for each real incident, inserted in one fixture transaction.
        template = self.explain(rows[0], 'Cause 0')
        with self.store.transaction() as connection:
            for number, row in enumerate(rows[1:], 1):
                self.store.audit(connection, NOW, PRODUCER.identity, 'rca.explained', row['id'],
                                 dict(template, causes=[f'Cause {number}']))
        statements = []
        connect = sqlite3.connect

        def traced(*args, **kwargs):
            connection = connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        with patch.object(presentation.sqlite3, 'connect', side_effect=traced):
            rendered = presentation.records(self.store, 'incidents', rows)
        self.assertEqual([row['display'].get('cause_name') for row in rendered],
                         [f'Cause {number}' for number in range(len(rows))])
        batch_queries = [sql for sql in statements if 'MAX(sequence)' in sql]
        self.assertEqual(len(batch_queries), 2)
        with closing(connect(self.store.path)) as connection:
            for row in rendered:
                self.assertEqual(presentation.cause_info(rca.stored(connection, row['id']))['cause_name'],
                                 row['display']['cause_name'])


if __name__ == '__main__':
    unittest.main()

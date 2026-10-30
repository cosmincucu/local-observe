"""Schema v15: the three columns that let a stored decision say *which kind of operator* made it.

`docs/api/DECISIONS.md` D16 states the product reason — an automated operator under its own credential may
now acknowledge, dismiss and maintain, and a row that records only a name reads differently the day a second
kind of name is allowed to sign one. This file is the storage half of that claim, which is the half a reviewer
cannot check from a contract document:

* **an existing row is a human's, not an unknown's.** The step is `ALTER TABLE ... ADD COLUMN ... NOT NULL
  DEFAULT 'human'`, and the default states a *fact* about every row already in the file: before v15 exactly one
  role could sign a disposition, a disposition history entry or a schedule version. A read answering `null`, or
  a read refusing, would both be this build editing the history it was only supposed to extend. So the rows
  below are written by the real writers on a file held at v14, and read back through the served reads at v15.
* **fresh and upgraded files agree.** `Store._create` applies every migration and `_migrate` applies each
  missing step in turn, so the three columns arrive by the same `ALTER` either way — and that is asserted on
  the stored DDL, not on a belief about the loop. A schema that differs by installation history is the defect
  the whole `MIGRATIONS` chain exists to prevent.
* **the CHECK is in the file.** A row naming a role the platform cannot authenticate — `Human`, `operator`,
  `reader`, the empty string — is refused by SQLite and not by a caller's discipline, so no bug in the Python
  above it can write one.
* **what the step left alone stays alone.** The dismissal tombstone, the projection payload,
  `platform_jobs.approved_by` and `credential_revocations.revoked_by` are asserted not to have gained a role
  column, because the gates that write them still refuse an automated operator. A migration that quietly
  widened one of those lands here as a changed column list rather than as a surprise in production.

Every database here is a temporary file. Nothing is networked and nothing is sent.
"""
import contextlib
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import api_contract, dispositions, maintenance, state, suppression
from local_observe.platform.detections import event
from local_observe.platform.state import (HUMAN, OPERATOR_AGENT, OPERATOR_ROLE_DISPOSITIONS,
                                          OPERATOR_ROLE_SCHEDULES, Actor, StateError, Store)

NOW = timestamp('2026-09-15T12:00:00Z')
PRODUCER = Actor('lo-detector', 'producer')
#: The v14 actor context: the role that was, until this step, the only one the writers could hear.
PERSON = api_contract.ActorContext(identity='operator', role=HUMAN, request_id='r' * 64)
#: The same surface after the step, reached by an automated operator under its own credential.
AGENT = api_contract.ActorContext(identity='night-bot', role=OPERATOR_AGENT, request_id='q' * 64)
#: One human and one agent, as `state.Actor` rather than as a transport context (`maintenance` takes these).
OPERATOR = Actor('operator', HUMAN)
AUTOMATION = Actor('night-bot', OPERATOR_AGENT)

#: The three columns this step adds, spelled from `state` so a rename that leaves a test behind is a failure
#: and not a green suite with a stale expectation.
COLUMNS = {state.OCCURRENCE_DISPOSITION_TABLE: OPERATOR_ROLE_DISPOSITIONS,
           state.OCCURRENCE_DISPOSITION_HISTORY_TABLE: OPERATOR_ROLE_DISPOSITIONS,
           state.MAINTENANCE_SCHEDULE_TABLE: OPERATOR_ROLE_SCHEDULES}
#: The identities this step deliberately did not widen, each with the sentence that says why in `state.py`.
UNTOUCHED = (state.OCCURRENCE_DISMISSAL_TABLE, state.OCCURRENCE_PROJECTION_TABLE, state.PLATFORM_JOB_TABLE,
             state.CREDENTIAL_REVOCATION_TABLE)


def identifier(name: str) -> str:
    """A stable synthetic UUID for a synthetic name, never a real estate id."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'operator-agent-migration/' + name))


RESOURCE = identifier('host')


def verdict(version: str = '1', status: str = 'firing') -> dict:
    """One detector verdict, in the shape `Store.intake` accepts."""
    window = {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)}
    return event(PRODUCER.identity, RESOURCE, 'gatus.result', 'availability', status, window,
                 {'rule_id': 'gatus.result', 'resource_id': RESOURCE}, query_type='gatus-result',
                 version=version)


def plan(reason: str = 'firmware refresh') -> dict:
    """One recurring plan whose first occurrence has not ended, so declaring it materializes windows."""
    return {'reason': reason, 'scope': {'kind': 'resource', 'id': RESOURCE},
            'recurrence': {'frequency': 'daily', 'interval': 1, 'days_of_week': [], 'time_of_day': '03:30',
                           'duration_seconds': 1800, 'timezone': 'Europe/London', 'dst': 'wall'},
            'bounds': {'first_occurrence': (NOW + dt.timedelta(days=1)).date().isoformat(),
                       'occurrences': 2}}


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection

def hold_at_v14(path: Path) -> None:
    """Rewind a file this build created to the shape v15's step starts from.

    Three `ALTER TABLE ... DROP COLUMN` statements and a version rewind, run in one transaction: the rows,
    their actors, their triggers and the whole audit log stay exactly as the writers left them, and only the
    columns the step adds are missing — which is what a deployed v14 file is. Dropping in the reverse order
    of the step matters: a column named by a later statement must not be needed by an earlier one.
    """
    with contextlib.closing(sqlite3.connect(path)) as connection:
        connection.execute('BEGIN IMMEDIATE')
        for table in reversed(list(COLUMNS)):
            connection.execute(f'ALTER TABLE {table} DROP COLUMN {COLUMNS[table]}')
        connection.execute('PRAGMA user_version=14')
        connection.commit()


class FreshFileTests(unittest.TestCase):
    """What a file this build creates contains, and what the CHECK inside the file refuses."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'
        self.store = Store(self.path)

    def info(self, table: str) -> dict[str, sqlite3.Row]:
        with contextlib.closing(connect(self.path)) as connection:
            return {row['name']: row for row in connection.execute(f'PRAGMA table_info({table})')}

    def test_the_three_columns_are_in_the_file_and_say_what_the_writers_write(self):
        for table, column in COLUMNS.items():
            with self.subTest(table=table):
                info = self.info(table)
                self.assertIn(column, info)
                self.assertEqual(info[column]['notnull'], 1, 'a stored role is never absent')
                self.assertEqual(info[column]['dflt_value'], f"'{HUMAN}'",
                                 'a row this build did not write is a human row')

    def test_the_column_refuses_every_word_but_the_two_the_platform_authenticates(self):
        """The CHECK and not the caller: a role nobody can authenticate is unrepresentable."""
        incident = self.store.intake(verdict(), PRODUCER, now=NOW)['incident_id']
        dispositions.acknowledge(self.store, incident, 'looking at it', PERSON, now=NOW)
        for word in ('', 'Human', 'human ', 'operator', 'operator_agent', 'reader', 'producer', 'null', None):
            with self.subTest(refused=word):
                with self.assertRaises(sqlite3.IntegrityError):
                    with self.store.transaction() as connection:
                        connection.execute(f'UPDATE {state.OCCURRENCE_DISPOSITION_TABLE}'
                                           f' SET {OPERATOR_ROLE_DISPOSITIONS}=?'
                                           ' WHERE occurrence_id=?', (word, incident))

    def test_the_step_added_no_role_column_where_the_gates_still_refuse_an_agent(self):
        """Four identities stay human-only, checked as columns and not as a comment."""
        names = {table: set(self.info(table)) for table in UNTOUCHED}
        self.assertNotIn('actor_role', names[state.OCCURRENCE_DISMISSAL_TABLE],
                         'a tombstone says whether an episode closed, not who closed it')
        self.assertNotIn('actor_role', names[state.OCCURRENCE_PROJECTION_TABLE],
                         'a projection names the decision in its payload, where the role already travels')
        self.assertNotIn('approved_by_role', names[state.PLATFORM_JOB_TABLE])
        self.assertNotIn('revoked_by_role', names[state.CREDENTIAL_REVOCATION_TABLE])
        self.assertNotIn('materialized_by_role', set(self.info(state.MAINTENANCE_SCHEDULE_TABLE)),
                         'which scheduler run materialized a plan is not who signed it; the windows it'
                         ' produced name their author and that author\'s role')

    def test_an_agent_disposition_stores_the_agent_role_in_the_row_and_in_the_log(self):
        incident = self.store.intake(verdict(), PRODUCER, now=NOW)['incident_id']
        out = dispositions.dismiss(self.store, incident, 'known flapping rule', AGENT, now=NOW)
        self.assertEqual((out['disposition']['actor'], out['disposition']['actor_role']),
                         ('night-bot', OPERATOR_AGENT))
        with contextlib.closing(connect(self.path)) as connection:
            row = connection.execute(
                f'SELECT d.actor, d.{OPERATOR_ROLE_DISPOSITIONS} as role, a.detail'
                f' FROM {state.OCCURRENCE_DISPOSITION_TABLE} d'
                ' JOIN audit a ON a.subject = d.occurrence_id'
                f" AND a.operation = '{state.OCCURRENCE_DISPOSITION_OPERATION}'"
                ' WHERE d.occurrence_id=?', (incident,)).fetchone()
        self.assertEqual((row['actor'], row['role']), ('night-bot', OPERATOR_AGENT))
        self.assertEqual(json.loads(row['detail'])['actor_role'], OPERATOR_AGENT,
                         'the audit row an operator reads names the role too, not only the identity')
        for projection in connection_projections(self.path, incident):
            self.assertEqual(json.loads(projection)['actor_role'], OPERATOR_AGENT,
                             'a downstream told about the decision is told who made it')


class UpgradeFromV14Tests(unittest.TestCase):
    """A deployed v14 file gains three columns, and every row it already held still reads as a human's."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'
        store = Store(self.path)
        self.incident = store.intake(verdict(), PRODUCER, now=NOW)['incident_id']
        dispositions.acknowledge(store, self.incident, 'paged the on-call', PERSON, now=NOW)
        dispositions.dismiss(store, self.incident, 'tracked elsewhere', PERSON, now=NOW)
        self.scheduled = maintenance.declare_schedule(store, plan(), OPERATOR, now=NOW)
        self.window = self.scheduled['windows'][0]['id']
        maintenance.cancel_schedule(store, self.scheduled['id'], OPERATOR, now=NOW)
        self.audit_rows = self.count('SELECT count(*) FROM audit')
        self.dispositions = self.count(f'SELECT count(*) FROM {state.OCCURRENCE_DISPOSITION_TABLE}')
        del store
        hold_at_v14(self.path)

    def count(self, sql: str, args: tuple = ()) -> int:
        with contextlib.closing(connect(self.path)) as connection:
            return int(connection.execute(sql, args).fetchone()[0])

    def test_the_file_refuses_service_until_migrated_and_opens_at_v15_after(self):
        with self.assertRaises(StateError):
            Store(self.path)
        Store(self.path, migrate=True)
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], state.VERSION)
        self.assertEqual(state.VERSION, 15)
        self.assertIs(state.MIGRATIONS[15], state.OPERATOR_ATTRIBUTION_SCHEMA)

    def test_the_step_wrote_one_audit_row_and_changed_no_data_row(self):
        """Three `ALTER`s and the one `schema.migrated` line the migrator always writes; nothing else."""
        Store(self.path, migrate=True)
        self.assertEqual(self.count("SELECT count(*) FROM audit WHERE operation != 'schema.migrated'"),
                         self.audit_rows)
        self.assertEqual(self.count("SELECT count(*) FROM audit WHERE operation = 'schema.migrated'"), 1)
        self.assertEqual(self.count("SELECT count(*) FROM audit WHERE operation = 'schema.migrated'"
                                    ' AND actor=?', (state.MIGRATE_ACTOR,)), 1,
                         'the migrator signs its own row, and an automated operator did not migrate anything')
        self.assertEqual(self.count(f'SELECT count(*) FROM {state.OCCURRENCE_DISPOSITION_TABLE}'),
                         self.dispositions)
        self.assertEqual(self.count('SELECT count(*) FROM incidents'), 1)
        self.assertEqual(self.count('SELECT count(*) FROM notification_control'),
                         len(self.scheduled['windows']) + 1, 'one document per materialized window and a horizon')

    def test_every_row_the_old_file_held_reads_as_a_human_decision(self):
        """The backfill is a fact about the writer, so no read guesses and none branches on a version."""
        store = Store(self.path, migrate=True)
        document = dispositions.occurrence(store, self.incident)
        self.assertEqual(document['disposition']['actor'], 'operator')
        self.assertEqual(document['disposition']['actor_role'], HUMAN)
        history = dispositions.history(store, self.incident)
        self.assertEqual([row['actor_role'] for row in history['rows']], [HUMAN, HUMAN],
                         'the append-only history of a v14 file is still a history of one human')
        for name in ('schedule', 'history'):
            with self.subTest(read=name):
                answer = (maintenance.schedule(store, self.scheduled['id']) if name == 'schedule'
                          else maintenance.schedule_history(store, self.scheduled['id']))
                versions = answer['history'] if name == 'schedule' else answer['versions']
                self.assertEqual([row['declared_by_role'] for row in versions], [HUMAN, HUMAN],
                                 'two versions: the plan and its cancellation, both a human\'s')
                self.assertEqual([row['declared_by'] for row in versions], ['operator', 'operator'])
        window = suppression.window_by_id(store, self.window)
        self.assertEqual((window['author'], window['author_role']), ('operator', HUMAN))
        cancelled = suppression.windows_spanning(store, span_from=NOW - dt.timedelta(days=1),
                                                 span_to=NOW + dt.timedelta(days=30))
        self.assertEqual([row['revoked_by_role'] for row in cancelled['windows']],
                         [HUMAN] * len(cancelled['windows']),
                         'the cancellation a v14 file holds was the only kind of cancellation it could make')

    def test_the_rollback_copy_is_the_v14_file_the_migrator_left_behind(self):
        Store(self.path, migrate=True)
        copies = sorted(self.path.parent.glob('state.db.pre-v14-*.db'))
        self.assertEqual(len(copies), 1, 'a migration that wrote no copy leaves nothing to roll back to')
        with contextlib.closing(sqlite3.connect(copies[0])) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 14)
            for table, column in COLUMNS.items():
                names = {row[1] for row in connection.execute(f'PRAGMA table_info({table})')}
                self.assertNotIn(column, names)

    def test_the_upgraded_file_accepts_an_agent_and_leaves_the_human_rows_alone(self):
        store = Store(self.path, migrate=True)
        other = store.intake(verdict('2'), PRODUCER, now=NOW)['incident_id']
        out = dispositions.acknowledge(store, other, 'agent runbook is on it', AGENT, now=NOW)
        self.assertEqual(out['disposition']['actor_role'], OPERATOR_AGENT)
        self.assertEqual(out['state'], 'acknowledged')
        self.assertEqual([row['actor_role'] for row in dispositions.history(store, other)['rows']],
                         [OPERATOR_AGENT])
        self.assertEqual(dispositions.occurrence(store, self.incident)['disposition']['actor_role'], HUMAN,
                         'one file, two kinds of operator, each still named as itself')

    def test_a_schedule_an_agent_declares_after_the_step_carries_the_agent_role(self):
        store = Store(self.path, migrate=True)
        declared = maintenance.declare_schedule(store, plan('agent certificate rotation'), AUTOMATION,
                                                now=NOW)
        answer = maintenance.schedule(store, declared['id'])
        self.assertEqual((answer['schedule']['declared_by'], answer['schedule']['declared_by_role']),
                         ('night-bot', OPERATOR_AGENT))
        self.assertEqual([row['declared_by_role'] for row in answer['history']], [OPERATOR_AGENT])
        self.assertEqual(maintenance.schedule(store, self.scheduled['id'])['schedule']['declared_by_role'],
                         HUMAN)
        window = suppression.window_by_id(store, declared['windows'][0]['id'])
        self.assertEqual(window['author_role'], OPERATOR_AGENT,
                         'a window an agent\'s plan materialized says an agent materialized it')

    def test_a_window_an_agent_declares_after_the_step_names_the_agent(self):
        store = Store(self.path, migrate=True)
        start = NOW + dt.timedelta(days=9)
        answer = suppression.declare_window(
            store, {'resource_id': RESOURCE, 'starts_at': utc_text(start),
                    'ends_at': utc_text(start + dt.timedelta(minutes=30)), 'reason': 'agent restart',
                    'explains': ['availability']}, AUTOMATION, now=NOW)
        self.assertEqual(answer['window']['author_role'], OPERATOR_AGENT)
        stored = suppression.window_by_id(store, answer['id'])
        self.assertEqual((stored['author'], stored['author_role']), ('night-bot', OPERATOR_AGENT))
        self.assertEqual(suppression.window_by_id(store, self.window)['author_role'], HUMAN)


class OneShapeForBothWaysTests(unittest.TestCase):
    """A file created at v15 and a file rewound to v14 and migrated hold the same three columns."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fresh = self.root / 'fresh.db'
        Store(self.fresh)
        self.upgraded = self.root / 'upgraded.db'
        Store(self.upgraded)
        hold_at_v14(self.upgraded)

    def ddl(self, path: Path) -> dict[str, str]:
        with contextlib.closing(sqlite3.connect(path)) as connection:
            return {row[0]: row[1] for row in connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type='table'")}

    def test_the_stored_table_definitions_are_identical(self):
        Store(self.upgraded, migrate=True)
        fresh, upgraded = self.ddl(self.fresh), self.ddl(self.upgraded)
        for table in COLUMNS:
            with self.subTest(table=table):
                self.assertEqual(fresh[table], upgraded[table])

    def test_the_upgrade_step_is_idempotent_about_the_version_it_reached(self):
        """A second `migrate` on a v15 file is a no-op that writes no copy and no audit row."""
        Store(self.upgraded, migrate=True)
        before = self.ddl(self.upgraded)
        with contextlib.closing(sqlite3.connect(self.upgraded)) as connection:
            rows = connection.execute('SELECT count(*) FROM audit').fetchone()[0]
        Store(self.upgraded, migrate=True)
        self.assertEqual(self.ddl(self.upgraded), before)
        with contextlib.closing(sqlite3.connect(self.upgraded)) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM audit').fetchone()[0], rows)


def connection_projections(path: Path, incident: str) -> list[str]:
    """The payload of every projection row one occurrence owes, read straight off the file."""
    with contextlib.closing(connect(path)) as connection:
        return [row[0] for row in connection.execute(
            f'SELECT payload FROM {state.OCCURRENCE_PROJECTION_TABLE} WHERE occurrence_id=?', (incident,))]


if __name__ == '__main__':
    unittest.main()

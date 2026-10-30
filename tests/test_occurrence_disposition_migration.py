"""Schema v12: the four tables that let a named human answer an alert, and what each one refuses.

Before this step the platform had *evidence* that a human had touched an incident — a decided `actions` row, a
spent callback token — and no place to store the thing an operator actually says: "I have this", or "this
episode needs nobody", with a name and a reason attached. The evidence is not the statement (see
`docs/api/occurrences.md` §6), and a pager that cannot tell the two apart either pages over a human who
answered or stays quiet for a decision nobody recorded.

Four tables, because four different lifetimes are in play, and `state.MIGRATIONS`' own comment is the place
that argues it. Briefly:

* **the effective disposition**, keyed by occurrence, one row, replaced in place — the read the operator
  surface and the escalation scheduler make thousands of times a day;
* **the history**, keyed by nothing but its own sequence, never updated, never deleted — the answer to
  "who else touched this, and when", which a row that gets overwritten cannot give;
* **the dismissal tombstones**, keyed by (episode, condition) — the durable *no* that must outlive the
  process that wrote it and must not outlive its own episode;
* **the projection records**, keyed by (episode, target) — a downstream that is down may not undo a
  decision, so the promise to tell it is a row and not a call.

What is checked here is the part a reviewer cannot see from the contract document: the CHECK bounds and the
triggers do the work, so a defect in the Python above them cannot write a row the schema would refuse. An
append-only table whose no-update trigger was never created is a table that silently stopped being one, and a
tombstone keyed on the condition alone is a dismissal that never ends — both are tested by trying to break
them, not by reading the DDL.

Every database here is a temporary file. Nothing is networked and nothing is sent.
"""
import contextlib
import datetime as dt
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import api_contract, dispositions, state
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store
from local_observe.platform.suppression import condition_key as derived_condition_key

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-08T12:00:00Z')
PRODUCER = Actor('lo-detector', 'producer')
OPERATOR = api_contract.ActorContext(identity='operator', role='human', request_id='r' * 32)
#: The four names this step adds, spelled from `state` so a rename that leaves a test behind is a failure and
#: not a green suite with a stale expectation.
NEW_TABLES = {state.OCCURRENCE_DISPOSITION_TABLE, state.OCCURRENCE_DISPOSITION_HISTORY_TABLE,
              state.OCCURRENCE_DISMISSAL_TABLE, state.OCCURRENCE_PROJECTION_TABLE}
TRIGGERS = frozenset({state.OCCURRENCE_DISPOSITION_HISTORY_TABLE + '_no_update',
                      state.OCCURRENCE_DISPOSITION_HISTORY_TABLE + '_no_delete'})
INDEXES = frozenset({state.OCCURRENCE_DISPOSITION_HISTORY_TABLE + '_occurrence',
                     state.OCCURRENCE_PROJECTION_TABLE + '_due'})


def identifier(name: str) -> str:
    """A stable synthetic UUID for a synthetic name, never a real estate id (`tests/test_topology.py`'s convention)."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'occurrence-disposition-fixture/' + name))


#: The resource every verdict here reports on. `Store.intake` validates `resource_id` as a canonical UUID, so
#: a hostname would be refused before the schema under test is ever reached — and one constant, not five
#: literals, is what makes "the same resource, different rule version" checkable in the tombstone tests.
RESOURCE = identifier('host')


def verdict(version: str, status: str = 'firing') -> dict:
    """One detector verdict, in the shape `Store.intake` accepts, with `version` carried in `condition`."""
    window = {'start': utc_text(NOW - dt.timedelta(seconds=60)), 'end': utc_text(NOW)}
    return event(PRODUCER.identity, RESOURCE, 'gatus.result', 'availability', status, window,
                 {'rule_id': 'gatus.result', 'resource_id': RESOURCE}, query_type='gatus-result',
                 version=version)


def condition_key(document: dict) -> str:
    """The key `conditions.key` holds for one verdict, asked of `suppression`: the one definition of it."""
    return derived_condition_key(document)


def connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


class SchemaV12Tests(unittest.TestCase):
    """What a file this build creates contains, checked against the file and not against the DDL string."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'
        self.store = Store(self.path)

    def names(self, kind: str) -> set[str]:
        with contextlib.closing(connect(self.path)) as connection:
            return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type=?",
                                                         (kind,))}

    def test_version_and_migration_table_agree(self):
        self.assertGreaterEqual(state.VERSION, 12)
        self.assertEqual(max(state.MIGRATIONS), state.VERSION)
        self.assertIs(state.MIGRATIONS[12], state.OCCURRENCE_DISPOSITION_SCHEMA)
        with contextlib.closing(connect(self.path)) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], state.VERSION)

    def test_the_four_tables_exist_and_no_fifth_was_invented(self):
        present = self.names('table')
        self.assertTrue(NEW_TABLES <= present, sorted(NEW_TABLES - present))
        self.assertEqual(len(NEW_TABLES), 4)

    def test_the_append_only_guards_and_the_two_indexes_were_created(self):
        self.assertTrue(TRIGGERS <= self.names('trigger'), sorted(TRIGGERS - self.names('trigger')))
        self.assertTrue(INDEXES <= self.names('index'), sorted(INDEXES - self.names('index')))

    def test_history_rows_cannot_be_changed_or_removed(self):
        """The trigger and not the comment: an UPDATE and a DELETE both abort, and an INSERT still works."""
        incident = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        with self.store.transaction() as connection:
            connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_TABLE} VALUES (?,?,?,?,?,?)',
                               (incident, 'acknowledged', 'operator', 'looking', utc_text(NOW), 1))
            # Row triggers, so rows come first: SQLite fires a `BEFORE UPDATE`/`BEFORE DELETE` trigger once per
            # row it is actually changing, and a statement over an empty table changes none — it would succeed
            # and prove nothing about the trigger. The two statements are therefore refused *after* the rows
            # they would have rewritten exist, which is also the order a defect could reach this table in.
            for kind, reason in (('acknowledged', 'looking'), ('dismissed', 'closed it')):
                connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_HISTORY_TABLE}'
                                   ' VALUES (NULL,?,?,?,?,?,?)',
                                   (incident, kind, 'operator', reason, utc_text(NOW), 1))
            for statement, parameters in ((f'UPDATE {state.OCCURRENCE_DISPOSITION_HISTORY_TABLE}'
                                           ' SET reason=? WHERE 1=1', ('rewritten',)),
                                          (f'DELETE FROM {state.OCCURRENCE_DISPOSITION_HISTORY_TABLE}'
                                           ' WHERE 1=1', ())):
                with self.assertRaises(sqlite3.IntegrityError) as caught:
                    connection.execute(statement, parameters)
                self.assertIn('append-only disposition history', str(caught.exception))
        with contextlib.closing(connect(self.path)) as connection:
            rows = connection.execute(f'SELECT sequence, kind, reason'
                                      f' FROM {state.OCCURRENCE_DISPOSITION_HISTORY_TABLE}'
                                      ' ORDER BY sequence').fetchall()
        self.assertEqual([(row['sequence'], row['kind'], row['reason']) for row in rows],
                         [(1, 'acknowledged', 'looking'), (2, 'dismissed', 'closed it')],
                         'the history keeps both decisions in order, whatever the effective row says next')

    def test_the_kind_column_refuses_every_word_but_the_two(self):
        incident = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        for offset, kind in enumerate(('ACKNOWLEDGED', 'suppress', '', 'muted')):
            with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
                connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_TABLE} VALUES (?,?,?,?,?,?)',
                                   (f'{incident[:-3]}{offset:03x}' if offset else incident,
                                    kind, 'operator', 'reason', utc_text(NOW), 1))

    def test_a_reason_cannot_be_empty_or_endless(self):
        """The bound lives in the file: a caller past `dispositions._reason` still cannot store silence."""
        incident = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        for ordinal, reason in ((1, ''), (2, 'x' * (state.OCCURRENCE_REASON_LIMIT + 1))):
            with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
                connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_TABLE} VALUES (?,?,?,?,?,?)',
                                   (incident, 'acknowledged', 'operator', reason, utc_text(NOW), ordinal))

    def test_one_effective_row_per_occurrence(self):
        incident = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        with self.store.transaction() as connection:
            connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_TABLE} VALUES (?,?,?,?,?,?)',
                               (incident, 'acknowledged', 'operator', 'first', utc_text(NOW), 1))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_TABLE} VALUES (?,?,?,?,?,?)',
                                   (incident, 'dismissed', 'operator', 'second', utc_text(NOW), 2))

    def test_a_disposition_cannot_be_recorded_about_an_episode_that_never_opened(self):
        """The foreign key is why the routes can answer 404 instead of writing a fact about nothing."""
        with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
            connection.execute(f'INSERT INTO {state.OCCURRENCE_DISPOSITION_TABLE} VALUES (?,?,?,?,?,?)',
                               ('00000000-0000-4000-8000-000000000000', 'acknowledged', 'operator',
                                'nowhere', utc_text(NOW), 1))

    def test_a_tombstone_needs_both_halves_of_its_key(self):
        incident = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        key = condition_key(verdict('1'))
        with self.store.transaction() as connection:
            connection.execute(f'INSERT INTO {state.OCCURRENCE_DISMISSAL_TABLE} VALUES (?,?,?,?)',
                               (incident, key, 'operator', utc_text(NOW)))
            for short in (key[:63], key + 'a'):
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(f'INSERT INTO {state.OCCURRENCE_DISMISSAL_TABLE} VALUES (?,?,?,?)',
                                       (incident, short, 'operator', utc_text(NOW)))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(f'INSERT INTO {state.OCCURRENCE_DISMISSAL_TABLE} VALUES (?,?,?,?)',
                                   (incident, key, 'operator', utc_text(NOW)))

    def test_a_projection_row_names_only_a_known_target_and_a_real_status(self):
        incident = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        for offset, (kind, status) in enumerate((('pager', 'pending'), ('telemetry-metric', 'queued'))):
            with self.assertRaises(sqlite3.IntegrityError), self.store.transaction() as connection:
                connection.execute(f'INSERT INTO {state.OCCURRENCE_PROJECTION_TABLE} VALUES (?,?,?,?,?,?,?,?)',
                                   (incident, kind, '{}', status, offset, utc_text(NOW), utc_text(NOW), ''))
        with self.store.transaction() as connection:                # the row this build really writes
            connection.execute(f'INSERT INTO {state.OCCURRENCE_PROJECTION_TABLE} VALUES (?,?,?,?,?,?,?,?)',
                               (incident, 'telemetry-metric', '{}', 'pending', 0, utc_text(NOW),
                                utc_text(NOW), ''))
        with contextlib.closing(connect(self.path)) as connection:
            self.assertEqual(connection.execute(f'SELECT count(*) FROM {state.OCCURRENCE_PROJECTION_TABLE}'
                                                ).fetchone()[0], 1)


class DismissalLookupTests(unittest.TestCase):
    """`episode_dismissed` answers for a pair, and the pair is the whole bound of a dismissal."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'
        self.store = Store(self.path)

    def test_the_pair_answers_and_nothing_else_does(self):
        first = self.store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        second = self.store.intake(verdict('2'), PRODUCER, now=NOW)['incident_id']
        key = condition_key(verdict('1'))
        with self.store.transaction() as connection:
            connection.execute(f'INSERT INTO {state.OCCURRENCE_DISMISSAL_TABLE} VALUES (?,?,?,?)',
                               (first, key, 'operator', utc_text(NOW)))
            self.assertTrue(state.episode_dismissed(connection, first, key))
            self.assertFalse(state.episode_dismissed(connection, second, key),
                             'a dismissal of one episode may not silence another episode of one condition')
            self.assertFalse(state.episode_dismissed(connection, first, condition_key(verdict('2'))))

    def test_a_lookup_against_an_unmigrated_file_fails_loudly(self):
        """No silent "nobody dismissed anything": a rail that could not check must not claim it did."""
        with self.store.transaction() as connection:
            connection.execute(f'DROP TABLE {state.OCCURRENCE_DISMISSAL_TABLE}')
        with self.store.transaction() as connection, self.assertRaises(sqlite3.Error):
            state.episode_dismissed(connection, '00000000-0000-4000-8000-000000000000', 'anything')


class UpgradeFromV11Tests(unittest.TestCase):
    """A deployed v11 file gains the four tables, keeps what it had, and can be dismissed."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'
        store = Store(self.path)
        self.incident = store.intake(verdict('1'), PRODUCER, now=NOW)['incident_id']
        with store.transaction() as connection:
            store.audit(connection, NOW, 'operator', 'action.decision', self.incident, {'decision': 'approved'})
        del store
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            for table in sorted(NEW_TABLES):
                connection.execute(f'DROP TABLE IF EXISTS {table}')
            # A real v11 file also lacks the later steps' objects (v13 maintenance schedules).
            connection.execute(f'DROP TABLE IF EXISTS {state.MAINTENANCE_SCHEDULE_TABLE}')
            connection.execute(f'DROP INDEX IF EXISTS {state.MAINTENANCE_OUTCOME_INDEX}')
            connection.execute(f'DROP INDEX IF EXISTS {state.MAINTENANCE_ATTRIBUTION_INDEX}')
            connection.execute('PRAGMA user_version=11')
            connection.commit()

    def test_the_file_opens_at_v12_with_its_history_intact(self):
        with self.assertRaises(StateError):        # an unmigrated file may not simply be opened for service
            Store(self.path)
        Store(self.path, migrate=True)
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], state.VERSION)
            self.assertEqual(connection.execute('SELECT status FROM incidents WHERE id=?',
                                                (self.incident,)).fetchone()[0], 'open')
            self.assertEqual(connection.execute("SELECT count(*) FROM audit WHERE operation='action.decision'"
                                                ).fetchone()[0], 1)
        self.assertTrue(NEW_TABLES <= self.names())

    def test_a_v11_incident_can_be_dismissed_after_the_upgrade(self):
        store = Store(self.path, migrate=True)
        out = dispositions.dismiss(store, self.incident, 'known flapping rule', OPERATOR)
        self.assertTrue(out['created'])
        self.assertEqual(out['state'], 'dismissed')
        self.assertEqual(out['folded'], 1, 'the alert the v11 file had queued was folded by the dismissal')

    def test_the_rollback_is_the_verified_copy_the_migrator_left_behind(self):
        Store(self.path, migrate=True)
        copies = sorted(self.path.parent.glob('state.db.pre-v11-*.db'))
        self.assertEqual(len(copies), 1, 'a migration that wrote no copy leaves nothing to roll back to')
        with contextlib.closing(sqlite3.connect(copies[0])) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 11)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name=?",
                                                 (state.OCCURRENCE_DISPOSITION_TABLE,)).fetchone())

    def names(self) -> set[str]:
        with contextlib.closing(sqlite3.connect(self.path)) as connection:
            return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}

"""The operator's acknowledgement tool (drift resolution): what it files, and the things it refuses to.

The tool sits between a human and two files the producer owns elsewhere: the acknowledgement tree and
the platform database. Every test here therefore checks **both sides of one run** — the record the
producer will read, and the audit row that says who filed it — plus the state that must NOT have changed
when a run refuses. A writer that leaves a half-filed acknowledgement behind is worse than a refusal,
because the producer would then act on an instruction nobody completed.

Refusals are checked twice on purpose: against the CLI's JSON contract on stdout (the shape
`lo-platform` keeps, which says only the exception class) and against the fixed `refusal` code on the log
line, because a terminal is where an operator needs to learn which step they failed and stdout is not
where a sentence belongs.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, timestamp
from local_observe.platform import configdrift, drift_ack
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
DECLARED = ROOT / 'examples/inventory/declared.yaml'
DECLARED_RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
FOREIGN = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
SOURCE = 'config-drift-test'
PRODUCER = Actor(SOURCE, 'producer')
RULE = 'drift.router-running-config'
NOW = timestamp('2026-08-05T12:00:05Z')
LATER = timestamp('2026-08-05T12:05:05Z')
THIRD = timestamp('2026-08-05T12:10:05Z')
ACTOR = 'operator-one'
REASON = 'checked against the change ticket'
ORIGINAL = 'hostname router-01\nsnmp-server community public\n'
EDITED = 'hostname router-01\nsnmp-server community private\n'


def sha256(text: str) -> str:
    """Return the digest the producer reports for *text*: taken over the bytes as stored."""
    return hashlib.sha256(text.encode()).hexdigest()


class ToolFixture(unittest.TestCase):
    """One snapshot tree, one drift document, one platform database, and the paths between them."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tree = self.root / 'snapshots'
        self.acks = self.root / 'acknowledgements'
        self.cursor = self.root / 'state/drift-cursor.json'
        self.database = self.root / 'state.db'
        self.artifact = self.tree / DECLARED_RESOURCE / 'running-config'
        self.artifact.parent.mkdir(parents=True, exist_ok=True)
        self.write_artifact(EDITED)

    def write_artifact(self, text: str) -> Path:
        """Put *text* where the producer expects the one configured artifact."""
        self.artifact.write_text(text, encoding='utf-8', newline='')
        return self.artifact

    def write_config(self, *, acknowledgements: str | None = 'default') -> Path:
        """Write the drift document the tool is pointed at; *acknowledgements* = None omits the key."""
        document: dict = {'root': str(self.tree), 'cursor': str(self.cursor),
                          'resources': [{'resource_id': DECLARED_RESOURCE, 'name': 'running-config',
                                         'rule_id': RULE}],
                          'interval_seconds': 300}
        if acknowledgements == 'default':
            document['acknowledgements'] = str(self.acks)
        elif acknowledgements is not None:
            document['acknowledgements'] = acknowledgements
        path = self.root / 'drift.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def make_database(self) -> Path:
        """Create the platform database the way a running platform would have: real, and empty."""
        Store(self.database)
        return self.database

    def argv(self, digest_value: str, *, config: Path | None = None, database: Path | None = None,
             resource_id: str = DECLARED_RESOURCE, name: str = 'running-config',
             actor: str = ACTOR) -> list[str]:
        """A complete command line with one field swapped out by the test that needs to break it."""
        return ['--config', str(config or self.write_config()),
                '--database', str(database or self.make_database()),
                '--resource-id', resource_id, '--name', name, '--sha256', digest_value,
                '--actor', actor, '--reason', REASON]

    def run_ok(self, argv: list[str]) -> tuple[int, dict]:
        """Run the CLI on a path expected to succeed and return its code and the JSON it printed."""
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            code = drift_ack.main(argv)
        return code, json.loads(printed.getvalue())

    def run_refused(self, argv: list[str]) -> tuple[int, dict, list]:
        """Run the CLI on a path expected to refuse; return code, JSON and the WARNING records."""
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed), \
                self.assertLogs('local_observe.platform.drift_ack', 'WARNING') as captured:
            code = drift_ack.main(argv)
        return code, json.loads(printed.getvalue()), list(captured.records)

    def audit_rows(self) -> list[tuple[str, str, str, dict]]:
        """Every `drift.acknowledged` row, as (actor, operation, subject, detail), oldest first.

        A database that was never created answers with no rows rather than by creating one: `sqlite3`
        opens an absent path lazily, and a check that manufactured the file it was auditing would prove
        nothing about the refusal it was checking.
        """
        if not self.database.is_file():
            return []
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            rows = connection.execute('SELECT actor,operation,subject,detail FROM audit '
                                      "WHERE operation='drift.acknowledged' ORDER BY sequence").fetchall()
        return [(row[0], row[1], row[2], json.loads(row[3])) for row in rows]

    def codes(self, records: list) -> list[str]:
        """The fixed refusal codes this run logged, in order, ignoring lines that carry none."""
        return [record.refusal for record in records if hasattr(record, 'refusal')]

    def audit_operations(self) -> list[tuple[str, str]]:
        """Every audit row as (actor, operation), oldest first, or nothing when there is no database."""
        if not self.database.is_file():
            return []
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            return [(row[0], row[1]) for row in connection.execute(
                'SELECT actor,operation FROM audit ORDER BY sequence').fetchall()]

    def nothing_filed(self) -> None:
        """Assert a refusal wrote neither half of an acknowledgement: no tree, no audit row."""
        self.assertFalse(self.acks.exists())
        self.assertEqual(self.audit_rows(), [])


class AckToolRefusalTests(ToolFixture):
    """Four refusals the operator can reach by typing, and the state each one must leave untouched."""

    def test_a_configuration_with_no_acknowledgements_directory_is_refused_and_names_the_key(self):
        config = self.write_config(acknowledgements=None)
        code, result, records = self.run_refused(self.argv(sha256(EDITED), config=config))
        self.assertEqual(code, 1)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(self.codes(records), ['no_acknowledgements_directory'])
        with self.assertRaises(ValueError) as raised:
            drift_ack.acknowledge(config_path=config, database_path=self.make_database(),
                                  resource_id=DECLARED_RESOURCE, name='running-config',
                                  artifact_sha256=sha256(EDITED), actor=ACTOR, reason=REASON)
        self.assertIn('acknowledgements', str(raised.exception))
        self.nothing_filed()

    def test_an_artifact_the_configuration_does_not_name_is_refused(self):
        for resource_id, name in ((FOREIGN, 'running-config'), (DECLARED_RESOURCE, 'startup-config')):
            with self.subTest(resource_id=resource_id, name=name):
                database = self.make_database()
                argv = self.argv(sha256(EDITED), database=database, resource_id=resource_id, name=name)
                code, result, records = self.run_refused(argv)
                self.assertEqual(code, 1)
                self.assertEqual(result['error_type'], 'Refusal')
                self.assertEqual(self.codes(records), ['artifact_not_configured'])
                self.nothing_filed()

    def test_a_database_that_does_not_exist_is_refused_rather_than_created(self):
        """`Store(path)` creates a file; an acknowledgement audited into it records nothing anyone reads."""
        missing = self.root / 'absent.db'
        code, result, records = self.run_refused(self.argv(sha256(EDITED), database=missing))
        self.assertEqual(code, 1)
        self.assertEqual(self.codes(records), ['database_absent'])
        self.assertFalse(missing.exists())
        self.assertFalse(missing.with_name(missing.name + '-wal').exists())
        self.assertFalse(self.database.exists(), 'the refusal opened the database it refused to write')
        self.nothing_filed()

    def test_only_the_bytes_that_are_on_disk_now_may_be_acknowledged(self):
        """The refused digest is a revision that is not in the tree: one ack, one exact digest."""
        database = self.make_database()
        argv = self.argv(sha256(EDITED), database=database)
        self.write_artifact(ORIGINAL)              # the tree is not what the typed digest describes
        code, result, records = self.run_refused(argv)
        self.assertEqual(code, 1)
        self.assertEqual(self.codes(records), ['digest_not_on_disk'])
        self.nothing_filed()

    def test_a_digest_that_is_not_a_digest_is_refused_before_the_tree_is_read(self):
        code, result, records = self.run_refused(self.argv('not-64-hex-at-all'))
        self.assertEqual(code, 1)
        self.assertEqual(result['error_type'], 'Refusal')
        self.assertEqual(self.codes(records), ['digest_malformed'])
        self.nothing_filed()

    def test_an_unreadable_artifact_is_refused_as_the_reader_refuses_it(self):
        """Not this module's refusal, and it does not pretend to be one: the OSError says what it says."""
        self.artifact.unlink()
        code, result, records = self.run_refused(self.argv(sha256(EDITED)))
        self.assertEqual(code, 1)
        self.assertEqual(result['error_type'], 'FileNotFoundError')
        self.assertEqual(self.codes(records), [])
        self.nothing_filed()

    def test_the_tool_writes_nothing_its_own_reader_would_refuse(self):
        """The writer and the reader are one rule, so an unbounded actor name never reaches either file."""
        code, result, records = self.run_refused(self.argv(sha256(EDITED), actor='a name with spaces'))
        self.assertEqual(code, 1)
        self.assertEqual(result['error_type'], 'ValueError')
        self.nothing_filed()


class AckToolWriteTests(ToolFixture):
    """The two artifacts a successful run owes, and the one it must never touch."""

    def test_a_run_writes_the_record_and_the_audit_row_that_describes_it(self):
        code, result = self.run_ok(self.argv(sha256(EDITED)))
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'acknowledged')
        self.assertEqual(result['artifact'], f'{DECLARED_RESOURCE}/running-config')
        self.assertEqual(result['rule_id'], RULE)
        self.assertEqual(result['artifact_sha256'], sha256(EDITED))
        self.assertEqual(Path(result['path']),
                         configdrift.acknowledgement_path(self.acks, DECLARED_RESOURCE, 'running-config'))
        document, identity = configdrift.read_acknowledgement(self.acks, DECLARED_RESOURCE,
                                                              'running-config')
        self.assertEqual(identity, result['acknowledgement_sha256'],
                         'the identity printed for the operator is the one the producer will compute')
        self.assertEqual((document['resource_id'], document['name'], document['rule_id']),
                         (DECLARED_RESOURCE, 'running-config', RULE))
        self.assertEqual(document['artifact_sha256'], sha256(EDITED))
        self.assertEqual(document['actor'], ACTOR)
        self.assertEqual(document['reason'], REASON)
        self.assertEqual(self.audit_rows(), [(ACTOR, 'drift.acknowledged', RULE, document)],
                         'the audit row and the record must say the same thing, or one of them is a lie')

    def test_the_record_is_readable_by_the_account_that_runs_the_producer(self):
        if os.name == 'nt':
            self.skipTest('this asserts POSIX mode bits, which Windows does not store')
        self.run_ok(self.argv(sha256(EDITED)))
        path = configdrift.acknowledgement_path(self.acks, DECLARED_RESOURCE, 'running-config')
        self.assertEqual(path.stat().st_mode & 0o077, 0o044,
                         'a private acknowledgement is one the producer can never act on')

    def test_a_second_run_leaves_no_temporary_file_behind(self):
        self.run_ok(self.argv(sha256(EDITED)))
        self.assertEqual(sorted(path.name for path in self.acks.rglob('*') if path.is_file()),
                         ['running-config.json'])

    def test_re_acknowledging_the_same_digest_at_a_later_instant_is_a_new_record(self):
        """Two acknowledgements of one digest differ, which is what lets one artifact be closed twice."""
        common = {'config_path': self.write_config(), 'database_path': self.make_database(),
                  'resource_id': DECLARED_RESOURCE, 'name': 'running-config',
                  'artifact_sha256': sha256(EDITED), 'actor': ACTOR, 'reason': REASON}
        first = drift_ack.acknowledge(**{**common, 'now': NOW})
        second = drift_ack.acknowledge(**{**common, 'now': LATER})
        self.assertNotEqual(first['acknowledgement_sha256'], second['acknowledgement_sha256'])
        self.assertEqual(first['artifact_sha256'], second['artifact_sha256'])
        _, identity = configdrift.read_acknowledgement(self.acks, DECLARED_RESOURCE, 'running-config')
        self.assertEqual(identity, second['acknowledgement_sha256'], 'the newer record is the live one')
        rows = self.audit_rows()
        self.assertEqual(len(rows), 2, 'both acknowledgements are owned claims, so both are audited')
        self.assertNotEqual(rows[0][3]['at'], rows[1][3]['at'])

    def test_the_cursor_is_left_alone_because_the_producer_owns_it(self):
        """The tool never opens the cursor and never asks for its lock: the producer holds it for life."""
        self.cursor.parent.mkdir(parents=True, exist_ok=True)
        self.cursor.write_text('this file is not for the acknowledgement tool', encoding='utf-8')
        before = self.cursor.read_bytes()
        self.run_ok(self.argv(sha256(EDITED)))
        self.assertEqual(self.cursor.read_bytes(), before)
        self.assertFalse(list(self.cursor.parent.glob('*.lock')))


class AcknowledgeRoundTripTests(ToolFixture):
    """The whole path: the tool files it, and the producer's next round closes the incident it opened."""

    def setUp(self) -> None:
        super().setUp()
        self.index = self.root / 'inventory.db'
        index.build(read_document(DECLARED), self.index, 'fixture')
        self.store = Store(self.database)

    def run_round(self, *, now) -> tuple[dict, list[dict], list[dict]]:
        """One producer round against the same tree, cursor and database the tool writes to.

        Returns the round's summary, the events it emitted and the receipts `intake` answered with —
        three different things, and the two that matter (`kind`/`status` versus `transition`) live in
        only one of them each.
        """
        config = configdrift.load_config(self.write_config())
        events: list[dict] = []
        receipts: list[dict] = []

        def deliver(item: dict) -> None:
            events.append(dict(item))
            receipts.append(self.store.intake(item, PRODUCER, now=now))

        return configdrift.tick(self.index, config, self.cursor, deliver, now=now, source=SOURCE), events, \
            receipts

    def incident_status(self, incident_id: str) -> str:
        with contextlib.closing(sqlite3.connect(self.database)) as connection:
            return connection.execute('SELECT status FROM incidents WHERE id=?',
                                      (incident_id,)).fetchone()[0]

    def test_the_producer_closes_the_incident_the_tool_acknowledged(self):
        self.write_artifact(ORIGINAL)
        _, baseline, _ = self.run_round(now=NOW)
        self.assertEqual(baseline, [], 'a baseline round opened an incident')

        self.write_artifact(EDITED)
        _, fired, fired_receipts = self.run_round(now=LATER)
        self.assertEqual([(item['kind'], item['status']) for item in fired], [('drift', 'firing')])
        self.assertEqual(fired_receipts[0]['transition'], 'opened')
        incident_id = fired_receipts[0]['incident_id']
        self.assertEqual(self.incident_status(incident_id), 'open')

        code, result = self.run_ok(self.argv(sha256(EDITED), database=self.database))
        self.assertEqual(code, 0)

        summary, closed, closed_receipts = self.run_round(now=THIRD)
        self.assertEqual([(item['kind'], item['status']) for item in closed], [('drift', 'resolved')])
        self.assertEqual(closed_receipts[0]['transition'], 'resolved')
        self.assertEqual(closed_receipts[0]['incident_id'], incident_id)
        self.assertEqual(self.incident_status(incident_id), 'resolved')
        self.assertEqual(summary['acknowledged'], 1)
        self.assertEqual(summary['evaluations'][0]['ack'], 'applied')
        self.assertEqual(result['acknowledgement_sha256'],
                         configdrift.load_cursor(self.cursor, configdrift.load_config(
                             self.write_config()))['seen'][f'{DECLARED_RESOURCE}/running-config']
                         ['ack_applied'],
                         'the producer remembered spending exactly the record the tool filed')

    def test_an_acked_artifact_with_no_open_incident_closes_nothing_and_harms_nothing(self):
        """The third stated limit: the producer never reads the incidents table, so an ack can be early."""
        _, baseline, _ = self.run_round(now=NOW)                     # stable artifact, nothing ever filed
        self.assertEqual(baseline, [])
        code, _ = self.run_ok(self.argv(sha256(EDITED), database=self.database))
        self.assertEqual(code, 0)
        summary, closed, receipts = self.run_round(now=LATER)        # the round applies the record
        self.assertEqual([(item['kind'], item['status']) for item in closed], [('drift', 'resolved')])
        self.assertIsNone(receipts[0]['incident_id'], 'a resolve filed with nothing open closed one')
        self.assertIsNone(receipts[0]['transition'])
        self.assertEqual(summary['acknowledged'], 1)
        self.assertEqual(summary['result'], 'delivered')

    def test_an_actor_is_recorded_and_no_more(self):
        """The limit the unit document states, pinned: the name reaches the audit row and nothing else.

        The close itself is filed under the producer's identity, because `Store.intake` is the only
        writer the incidents table has and it names whoever posted the event. Fixing that needs the
        `state.py` migration suppression/correlation hold plus event intake's route — not a change in this tool.
        """
        self.write_artifact(ORIGINAL)
        self.run_round(now=NOW)
        self.write_artifact(EDITED)
        self.run_round(now=LATER)
        self.run_ok(self.argv(sha256(EDITED), database=self.database))
        self.run_round(now=THIRD)
        operations = self.audit_operations()
        self.assertIn((ACTOR, 'drift.acknowledged'), operations)
        self.assertEqual([actor for actor, operation in operations if operation == 'event.intake'],
                         [SOURCE, SOURCE], 'the human must not appear to have filed the events')


if __name__ == '__main__':
    unittest.main()

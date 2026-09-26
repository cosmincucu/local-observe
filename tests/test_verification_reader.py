"""The verification history reader: `Store.list_verifications(execution_id, actor)` — bounded verification id discovery.

Smoke tests over the real surface, reusing `tests/test_verification_records.py`'s fixture as a *module*
(`import test_verification_records as casebook`) so its lifecycle scenario is not collected twice. Main
owns the independent boundary matrix (over-cap/over-length/corrupt ids, EXPLAIN QUERY PLAN, progress
handler, full role/echo sweep); this file pins what only a real run can pin: the lifecycle roundtrip and
reopen, empty-versus-unknown, the executing case, role authority measured by connection count, and that a
read leaves the file and the audit alone. Contracts, not test-result claims.
"""
import datetime as dt
import sqlite3
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest import mock

import test_verification_records as casebook
from local_observe.inventory.validation import canonical
from local_observe.platform.state import Actor

TERMINAL = casebook.TERMINAL
READER, HUMAN, AGENT, RUNNER = casebook.READER, casebook.HUMAN, casebook.AGENT, casebook.RUNNER
VERIFIER, UNLISTED, SUMMARY = casebook.VERIFIER, casebook.UNLISTED, casebook.SUMMARY
LEAKED = ('cleared', 'not_cleared', 'unknown', 'verdict', 'receipt', 'samples', 'observed_at',
          'recorded_at', 'origin', casebook.SERIES, VERIFIER.identity)


class ListVerifications(casebook.VerificationFixture):
    """Discovery through the real proposal/claim/outcome path, on temporary files."""

    def test_the_helper_base_contributes_no_collected_cases(self):
        """`VerificationFixture` is helpers only, which is what makes subclassing it safe here."""
        self.assertEqual(sorted(name for name in vars(casebook.VerificationFixture)
                                if name.startswith('test')), [])

    def test_discovery_follows_the_real_lifecycle_and_survives_a_reopen(self):
        """Ids appear as records are written, stay after a reopen, and never leak into one another."""
        case = self.executed(self.bound('lifecycle'))
        store = case['store']
        self.assertEqual(store.list_verifications(case['execution_id'], READER), [])
        first = self.put(case)['verification_id']
        second = self.put(case, window=self.window(case, ends_at=TERMINAL + dt.timedelta(minutes=8)))
        wanted = sorted([first, second['verification_id']])
        other = self.executed(self.bound('neighbour'))
        third = self.put(other)['verification_id']
        self.assertEqual(store.list_verifications(case['execution_id'], READER), wanted)
        self.assertEqual(other['store'].list_verifications(other['execution_id'], HUMAN), [third],
                         'one execution may not answer for another')
        reopened = self.open(case['name'], policy=case['policy'])
        self.assertEqual(reopened.list_verifications(case['execution_id'], READER), wanted,
                         'ids are stored, not derived per connection')
        for verification_id in wanted:
            self.assertEqual(sorted(reopened.get_verification(verification_id, READER)),
                             sorted(casebook.RECORD_FIELDS))
        mutable = reopened.list_verifications(case['execution_id'], READER)
        mutable.append('tampered')
        self.assertEqual(reopened.list_verifications(case['execution_id'], READER), wanted,
                         'a fresh list each call')

    def test_the_answer_is_validated_ids_and_nothing_a_document_read_owes(self):
        """Sorted lexical ascending, every id readable by the existing reader, and no payload in sight."""
        case = self.executed(self.bound('shape'))
        submitted = []
        for minute in (6, 8, 10):
            submitted.append(self.put(case, window=self.window(
                case, ends_at=TERMINAL + dt.timedelta(minutes=minute)))['verification_id'])
        listed = case['store'].list_verifications(case['execution_id'], READER)
        self.assertEqual(sorted(submitted), listed)
        self.assertEqual(listed, sorted(listed), 'the order is lexical, and that is the whole order')
        for verification_id in listed:
            self.assertRegex(verification_id, casebook.SHA256)
            self.assertEqual(case['store'].get_verification(verification_id, READER)['verification_id'],
                             verification_id)
        body = canonical(listed)
        for word in LEAKED:
            self.assertNotIn(word, body, 'this read returns ids, never a document')

    def test_a_known_execution_may_be_empty_and_an_unknown_one_is_refused(self):
        """`executing` is listable and empty; no records and no execution are different answers."""
        running = self.executed(self.bound('running'), outcome=None)
        self.assertEqual(running['store'].list_verifications(running['execution_id'], READER), [],
                         'an in-flight run is listable and this read infers no terminal outcome')
        terminal = self.executed(self.bound('quiet'))
        self.assertEqual(terminal['store'].list_verifications(terminal['execution_id'], READER), [])
        self.refused(lambda: terminal['store'].list_verifications(str(uuid.uuid4()), READER))
        for broken in ('', 'x' * 36, str(uuid.uuid4())[:-1], str(uuid.uuid4()).upper(), 36, None,
                       ['not', 'an', 'id']):
            self.refused(lambda value=broken: terminal['store'].list_verifications(value, READER))

    def test_readers_need_no_policy_and_a_producer_needs_the_current_one(self):
        """Every admitted role lists with a policy mounted and with none; an unlisted producer never may."""
        case = self.executed(self.bound('authority'))
        listed = [self.put(case)['verification_id']]
        self.assertEqual(listed, case['store'].list_verifications(case['execution_id'], READER))
        for actor in (HUMAN, AGENT, RUNNER, VERIFIER):
            self.assertEqual(case['store'].list_verifications(case['execution_id'], actor), listed)
        unmounted = self.open(case['name'], policy=None)
        for actor in (READER, HUMAN, AGENT, RUNNER):
            self.assertEqual(unmounted.list_verifications(case['execution_id'], actor), listed,
                             'ordinary reading is not gated on today\'s policy')
        self.refused(lambda: unmounted.list_verifications(case['execution_id'], VERIFIER))

    def test_every_refusal_is_settled_before_the_database_is_opened(self):
        """No connection is made for a role, an actor shape or an identifier this read will not accept."""
        case = self.executed(self.bound('noio'))
        self.put(case)
        with mock.patch.object(sqlite3, 'connect') as opened:
            for actor in (SUMMARY, UNLISTED, 'reader-1', None, object(), Actor('bad identity', 'reader'),
                          Actor('x' * 129, 'reader')):
                self.refused(lambda who=actor: case['store'].list_verifications(case['execution_id'], who))
            for broken in ('', 'not-a-uuid', str(uuid.uuid4()) + 'x', 42, ['id']):
                self.refused(lambda value=broken: case['store'].list_verifications(value, READER))
            self.assertEqual(opened.call_count, 0, 'authority and identifier come before the open')

    def test_the_read_changes_no_stored_byte_and_leaves_the_audit_alone(self):
        """Repeated discovery costs no row and no byte: the database and its -wal come back identical."""
        case = self.executed(self.bound('bytes'))
        self.put(case)
        audit_before = case['store'].records('audit', 100)
        listed = case['store'].list_verifications(case['execution_id'], READER)
        before = self.owning_bytes(case['store'].path)
        for _ in range(3):
            self.assertEqual(case['store'].list_verifications(case['execution_id'], READER), listed)
        self.assertEqual(self.owning_bytes(case['store'].path), before,
                         'a read writes nothing (-shm is SQLite scratch and is not stored state)')
        self.assertEqual(case['store'].records('audit', 100), audit_before, 'a read audits nothing')

    def test_an_absent_file_a_lost_table_and_a_lost_index_are_refusals_not_empty_answers(self):
        """Nothing here creates, repairs or migrates a database, and no history hole reads as absence."""
        case = self.executed(self.bound('schema'))
        self.put(case)
        for statement in ('DROP INDEX verification_records_execution', 'DROP TABLE verification_records'):
            with closing(sqlite3.connect(case['store'].path)) as db:
                db.execute(statement)
            self.refused(lambda: case['store'].list_verifications(case['execution_id'], READER),
                         str(case['store'].path))
        gone = self.executed(self.bound('absent'))
        self.put(gone)
        gone['store'].path.unlink()
        self.refused(lambda: gone['store'].list_verifications(gone['execution_id'], READER),
                     str(gone['store'].path))
        self.assertFalse(gone['store'].path.exists(), 'a read may not create the database it was asked about')

    def owning_bytes(self, path: Path) -> dict[str, bytes]:
        """The stored bytes of `path` and its `-wal`, so "unchanged" is a byte claim and not a hope."""
        return {item.name: item.read_bytes() for item in sorted(path.parent.iterdir())
                if item.name == path.name or item.name == path.name + '-wal'}


if __name__ == '__main__':
    unittest.main()

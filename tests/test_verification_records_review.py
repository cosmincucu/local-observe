"""Main-review boundary regressions, supplementing the independent contract tests."""
import datetime as dt
import sqlite3
from contextlib import closing

from local_observe.deployment.state_copy import copy_state
from local_observe.platform.state import StateError, Store
from local_observe.platform.verification_records import VerificationPolicy
from test_verification_records import RECORD_NOW, READER, VERIFIER, VerificationFixture


class ReviewBoundaries(VerificationFixture):
    def test_a_tzinfo_without_an_offset_is_not_an_aware_server_clock(self):
        class NoOffset(dt.tzinfo):
            def utcoffset(self, value):
                return None

        case = self.executed(self.bound('no-offset'))
        self.refused(lambda: self.put(case, now=RECORD_NOW.replace(tzinfo=NoOffset())))

    def test_out_of_range_utc_conversion_is_a_safe_timestamp_refusal(self):
        case = self.executed(self.bound('overflow-clock'))
        for start in ('0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00'):
            with self.subTest(start=start):
                self.refused(lambda: self.put(case, window={'start': start,
                                                            'end': self.window(case)['end']},
                                              outcome='unavailable', receipt=None, samples=[]))

    def test_oversized_container_is_refused_before_traversal(self):
        class Oversized(list):
            def __iter__(self):
                raise AssertionError('oversized collection was traversed')

        with self.assertRaises(StateError):
            VerificationPolicy({'schema_version': 1, 'verifiers': ['verifier'],
                                'mappings': Oversized([{}] * 65)})

    def test_unpaired_surrogate_is_a_safe_refusal(self):
        self.refused(lambda: VerificationPolicy(
            {'schema_version': 1, 'verifiers': ['\ud800'], 'mappings': []}))

    def test_missing_table_is_not_reported_as_an_absent_record_or_binding(self):
        case = self.executed(self.bound('corrupt-schema'))
        wanted = self.put(case)['verification_id']
        # Deliberately corrupt this test's disposable DB, not any operator state.
        with case['store'].transaction() as db:
            db.execute('DROP TABLE verification_records')
        self.refused(lambda: case['store'].get_verification(wanted, READER))
        self.refused(lambda: case['store'].get_verification_binding(case['action_id'], READER))

    def test_invalid_persisted_execution_status_cannot_be_graded_terminal(self):
        case = self.executed(self.bound('corrupt-status'))
        with case['store'].transaction() as db:
            db.execute('UPDATE executions SET status=? WHERE id=?', ('invalid', case['execution_id']))
        self.refused(lambda: case['store'].put_verification(self.statement(case), VERIFIER,
                                                           now=RECORD_NOW))
        self.assertEqual(self.ops(case['store'], 'verification.recorded'), [])

    def test_bounded_state_copy_preserves_verification_and_append_only_guards(self):
        (self.root / 'live').mkdir()
        case = self.executed(self.bound('live/copy'))
        wanted = self.put(case)['verification_id']
        before = case['store'].get_verification(wanted, READER)
        report = copy_state({'platform': (case['store'].path, 'sqlite')}, self.root,
                            self.root / 'copy', allow_checkpoint=True)
        self.assertTrue(report)
        restored = Store(self.root / 'copy/platform.db')
        self.assertEqual(restored.get_verification(wanted, READER), before)
        self.assertEqual(restored.get_verification_binding(case['action_id'], READER), case['binding'])
        with closing(sqlite3.connect(restored.path)) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchall(), [('ok',)])
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(), [])
            for table in ('verification_bindings', 'verification_records'):
                with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                    db.execute(f'DELETE FROM {table}')
                db.rollback()

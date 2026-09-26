"""Bounded discovery over real action/execution fixtures and the shared API slot."""
import asyncio
from contextlib import closing, nullcontext
import hashlib
import json
import sqlite3
import threading
import uuid
from unittest import mock

import test_verification_records as casebook
from local_observe.platform import verification_api as api
from local_observe.platform import verification_candidates as candidates
from local_observe.platform.state import Actor, StateError


def uid(number):
    return str(uuid.UUID(int=number))


class CandidateTests(casebook.VerificationFixture):
    def setUp(self):
        super().setUp()
        self.case = self.executed(self.bound())
        self.store = self.case['store']
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('UPDATE executions SET id=? WHERE id=?', (uid(100), self.case['execution_id']))
            db.commit()
        self.case['execution_id'] = uid(100)

    def page(self, **kwargs):
        return candidates.list_candidates(self.store, casebook.VERIFIER, **kwargs)

    def clone(self, number, *, status='succeeded', binding=True, connection=None):
        """Seed additional valid stored lifecycle rows without running a dispatcher."""
        with closing(sqlite3.connect(self.store.path)) if connection is None else nullcontext(connection) as db:
            for table, key, old_id, changes in (
                ('actions', 'id', self.case['action_id'], {'id': uid(1000 + number), 'retry_key': str(number)}),
                ('executions', 'id', uid(100), {'id': uid(number), 'action_id': uid(1000 + number), 'status': status}),
                ('verification_bindings', 'action_id', self.case['action_id'], {'action_id': uid(1000 + number)}),
            ):
                if table == 'verification_bindings' and not binding:
                    continue
                cursor = db.execute(f'SELECT * FROM {table} WHERE {key}=?', (old_id,))
                row = dict(zip([d[0] for d in cursor.description], cursor.fetchone()))
                row.update(changes)
                db.execute(f'INSERT INTO {table} ({",".join(row)}) VALUES ({",".join("?" for _ in row)})',
                           tuple(row.values()))
            if connection is None:
                db.commit()

    def test_terminal_bound_execution_returns_only_ids_and_actual_terminal_stamp(self):
        result = self.page()
        self.assertEqual(result, {'items': [{'execution_id': uid(100), 'action_id': self.case['action_id'],
                                            'finished_at': casebook.utc_text(casebook.TERMINAL)}],
                                  'next_after': None})
        for status in ('failed', 'unknown'):
            with closing(sqlite3.connect(self.store.path)) as db:
                db.execute('UPDATE executions SET status=?', (status,))
                db.commit()
            self.assertEqual(self.page(), result)

    def test_all_ineligible_page_advances_raw_cursor_and_does_not_starve_later_execution(self):
        self.clone(1, status='executing')
        self.clone(2, binding=False)
        first = self.page(limit=2)
        self.assertEqual(first, {'items': [], 'next_after': uid(2)})
        second = self.page(after=first['next_after'], limit=2)
        self.assertEqual([x['execution_id'] for x in second['items']], [uid(100)])
        self.assertIsNone(second['next_after'])
        self.clone(3)
        self.assertEqual([x['execution_id'] for x in self.page(limit=32)['items']], [uid(3), uid(100)])

    def test_end_of_sweep_revisits_new_uuid_behind_cursor_and_new_terminal_execution(self):
        self.clone(1, status='executing')
        self.assertEqual(self.page(limit=1)['next_after'], uid(1))
        self.assertIsNone(self.page(after=uid(1), limit=1)['next_after'])
        self.clone(2)
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute("UPDATE executions SET status='succeeded' WHERE id=?", (uid(1),))
            db.commit()
        self.assertEqual([x['execution_id'] for x in self.page()['items']], [uid(1), uid(2), uid(100)])

    def test_existing_accepted_verification_skips_without_reading_payload(self):
        recorded = self.put(self.case)['verification_id']
        self.assertEqual(self.page(), {'items': [], 'next_after': None})
        self.assertTrue(recorded)
        self.assertNotIn('payload', candidates.RECORD_SQL)
        self.assertNotIn('fingerprint', candidates.RECORD_SQL)

    def test_existing_unknown_observation_also_completes_automatic_discovery(self):
        recorded = self.put(self.case, outcome='unavailable')['verification_id']
        self.assertEqual(self.store.get_verification(recorded, casebook.READER)['verdict'], 'unknown')
        self.assertEqual(self.page(), {'items': [], 'next_after': None})

    def test_current_authority_and_query_refusals_precede_sqlite(self):
        for actor in (casebook.HUMAN, casebook.READER, casebook.RUNNER,
                      Actor('stranger', 'producer'), Actor('', 'producer'), None):
            with self.subTest(actor=actor), mock.patch.object(candidates, '_connect') as connect:
                with self.assertRaises(StateError):
                    candidates.list_candidates(self.store, actor)
                connect.assert_not_called()
        for args in ({'limit': 0}, {'limit': 33}, {'limit': True}, {'limit': '16'},
                     {'after': ''}, {'after': 'a' * 10000}, {'after': uid(123).upper() + 'X'}):
            with self.subTest(args=args), mock.patch.object(candidates, '_connect') as connect:
                with self.assertRaises(StateError):
                    self.page(**args)
                connect.assert_not_called()
        self.store.verification_policy = None
        with mock.patch.object(candidates, '_connect') as connect, self.assertRaises(StateError):
            self.page()
        connect.assert_not_called()

    def test_corrupt_execution_values_and_probe_id_refuse_without_echo(self):
        for column, value in [('id', 'private-id'), ('action_id', 'secret-action'),
                              ('status', 'mystery'), ('updated_at', 'private-stamp'),
                              ('updated_at', 'x' * 10000)]:
            with self.subTest(column=column):
                with closing(sqlite3.connect(self.store.path)) as db:
                    old = db.execute(f'SELECT {column} FROM executions').fetchone()[0]
                    db.execute(f'UPDATE executions SET {column}=?', (value,))
                    db.commit()
                with self.assertRaisesRegex(StateError, '^' + candidates.BAD_STORED + '$'):
                    self.page()
                with closing(sqlite3.connect(self.store.path)) as db:
                    db.execute(f'UPDATE executions SET {column}=?', (old,))
                    db.commit()
        self.clone(200)
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('UPDATE executions SET id=? WHERE id=?', ('z' * 10000, uid(200)))
            db.commit()
        with self.assertRaises(StateError):
            self.page(limit=1)

    def test_corrupt_binding_origin_and_record_id_refuse(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('DROP TRIGGER verification_bindings_no_update')
            old = db.execute('SELECT origin FROM verification_bindings').fetchone()[0]
            db.execute('UPDATE verification_bindings SET origin=?', ('{"private":"wrong"}',))
            db.commit()
        with self.assertRaisesRegex(StateError, candidates.BAD_STORED):
            self.page()

        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('UPDATE verification_bindings SET origin=?', (old,))
            db.execute('INSERT INTO verification_records VALUES (?,?,?,?,?,?,?,?)',
                       ('bad-id', uid(100), 'x', '{}', 'unknown', 'x', 'fixture', casebook.utc_text(casebook.TERMINAL)))
            db.commit()
        with self.assertRaisesRegex(StateError, candidates.BAD_STORED):
            self.page()

    def test_changed_oversized_and_noncanonical_binding_origins_refuse(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('DROP TRIGGER verification_bindings_no_update')
            original = db.execute('SELECT origin FROM verification_bindings').fetchone()[0]
            db.commit()
        changed = json.loads(original)
        changed['threshold'] = 2.0
        for value in (original + ' ', 'x' * (candidates.MAX_POLICY_BYTES + 1), json.dumps(changed)):
            with self.subTest(shape=len(value)):
                with closing(sqlite3.connect(self.store.path)) as db:
                    db.execute('UPDATE verification_bindings SET origin=?', (value,))
                    db.commit()
                with self.assertRaisesRegex(StateError, candidates.BAD_STORED):
                    self.page()

    def test_missing_verification_schema_is_not_empty_discovery(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('DROP TABLE verification_records')
            db.commit()
        with self.assertRaisesRegex(StateError, candidates.NEEDS_MIGRATION):
            self.page()

    def test_maximum_page_and_after_identity_preserve_exact_bounded_shape(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            for n in range(1, 34):
                self.clone(n, connection=db)
            db.commit()
        first = self.page(limit=32)
        self.assertEqual(len(first['items']), 32)
        self.assertEqual(first['next_after'], uid(32))
        tail = self.page(after=first['next_after'], limit=32)
        self.assertEqual([x['execution_id'] for x in tail['items']], [uid(33), uid(100)])
        self.assertIsNone(tail['next_after'])
    def test_missing_index_refuses_even_an_empty_page(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('DROP INDEX verification_records_execution')
            db.commit()
        with self.assertRaisesRegex(StateError, candidates.READ_FAILED):
            self.page(after=uid(999999))

    def test_named_indexes_avoid_sort_and_work_is_limited_before_filtering(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            for n in range(1, 65):
                self.clone(n, status='executing', connection=db)
            db.commit()
        statements = []
        original = candidates._connect
        def connect(path):
            db = original(path)
            db.set_trace_callback(statements.append)
            count = [0]
            def progress():
                count[0] += 1
                return count[0] > 3000
            db.set_progress_handler(progress, 1)
            return db
        with mock.patch.object(candidates, '_connect', side_effect=connect):
            self.assertEqual(self.page(limit=2), {'items': [], 'next_after': uid(2)})
        queries = [s for s in statements if s.startswith('SELECT')]
        self.assertEqual(sum('FROM executions ' in s for s in queries), 1)
        self.assertEqual(sum('FROM verification_bindings ' in s for s in queries), 2)
        self.assertEqual(sum('FROM verification_records ' in s for s in queries), 2)
        with closing(original(self.store.path)) as db:
            plan = db.execute('EXPLAIN QUERY PLAN ' + candidates.NEXT_SQL, (uid(1), 3)).fetchall()
        text = repr(plan)
        self.assertIn(candidates.EXECUTION_INDEX, text)
        self.assertIn('SEARCH', text)
        self.assertNotIn('TEMP B-TREE', text)

    def test_read_only_connection_and_repeated_pages_leave_database_bytes_unchanged(self):
        before = hashlib.sha256(self.store.path.read_bytes()).hexdigest()
        with closing(candidates._connect(self.store.path)) as db:
            with self.assertRaises(sqlite3.OperationalError):
                db.execute("UPDATE executions SET status='failed'")
        self.page()
        self.page()
        self.assertEqual(hashlib.sha256(self.store.path.read_bytes()).hexdigest(), before)

    async def _request(self, service, query=b'', actor=casebook.VERIFIER, method='GET'):
        async def receive():
            raise AssertionError('candidate discovery may not read a body')
        return await service.handle({'path': api.CANDIDATES_ROUTE, 'method': method,
                                     'query_string': query}, receive, actor)

    def test_http_query_authority_and_method_before_slot_or_io(self):
        async def scenario():
            service = api.VerificationAPI(self.store)
            try:
                with mock.patch.object(candidates, '_connect') as connect:
                    for query in (b'limit=0', b'limit=33', b'limit=01', b'limit=1&limit=2', b'after=',
                                  b'limit=1&', b'unknown=1', b'after=%ZZ', b'limit=+1', b'limit=1.0',
                                  b'limit=%ff', b'x' * 257):
                        self.assertEqual((await self._request(service, query))[0], 400)
                    self.assertEqual((await self._request(service, b'limit=broken', actor=casebook.READER))[0], 403)
                    self.assertEqual((await self._request(service, method='POST'))[0], 405)
                    connect.assert_not_called()
                    self.assertIsNone(service._executor)
                status, body = await self._request(service, b'limit=1')
                self.assertEqual(status, 200)
                self.assertEqual(set(body), {'items', 'next_after'})
            finally:
                service.close()
                await service.wait_idle()
        asyncio.run(scenario())

    def test_candidates_share_busy_slot_and_run_off_loop_without_queue(self):
        async def scenario():
            service = api.VerificationAPI(self.store)
            entered, release = threading.Event(), threading.Event()
            loop_thread = threading.get_ident()
            original = candidates._connect
            calls = []
            def blocked(path):
                calls.append(threading.get_ident())
                entered.set()
                if not release.wait(3):
                    raise AssertionError('test release not signalled')
                return original(path)
            try:
                with mock.patch.object(candidates, '_connect', side_effect=blocked):
                    first = asyncio.create_task(self._request(service))
                    self.assertTrue(await asyncio.wait_for(asyncio.to_thread(entered.wait, 2), 3))
                    self.assertEqual(await self._request(service), (503, {'error': 'verification_busy'}))
                    async def receive():
                        raise AssertionError('read only')
                    other = await service.handle({'path': api.BINDING_ROUTE, 'method': 'GET',
                                                  'query_string': ('action_id=' + self.case['action_id']).encode()},
                                                 receive, casebook.VERIFIER)
                    self.assertEqual(other, (503, {'error': 'verification_busy'}))
                    self.assertEqual(len(calls), 1)
                    self.assertNotEqual(calls[0], loop_thread)
                    release.set()
                    self.assertEqual((await first)[0], 200)
            finally:
                release.set()
                service.close()
                await service.wait_idle()
        asyncio.run(scenario())

    def test_policy_is_rechecked_after_slot_admission_and_storage_errors_are_fixed(self):
        async def scenario():
            service = api.VerificationAPI(self.store)
            original = service._offload
            async def revoke(call):
                self.store.verification_policy = None
                return await original(call)
            service._offload = revoke
            try:
                with mock.patch.object(candidates, '_connect') as connect:
                    self.assertEqual((await self._request(service))[0], 503)
                    connect.assert_not_called()
            finally:
                service.close()
                await service.wait_idle()
        asyncio.run(scenario())
        self.store.verification_policy = self.case['policy']
        service = api.VerificationAPI(self.store)
        self.addCleanup(service.close)
        with mock.patch.object(candidates, '_connect', side_effect=sqlite3.OperationalError('private-sentinel')):
            result = asyncio.run(self._request(service))
        self.assertEqual(result, (500, {'error': api.STORAGE_ERROR}))
        self.assertNotIn('private-sentinel', json.dumps(result))

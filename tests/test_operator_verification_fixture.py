"""Tests for the operator demo fixture as a carrier of verification history .

The card needs an operator to be able to click a real execution and read real records out of a real API.
That is a fixture problem before it is a UI problem: the demo has to hold a terminal execution with saved
verification records, and it has to keep holding the properties the existing operator proof depends on
while doing it. These tests pin both halves, and they run in-process against the same API the browser
drives — no socket, no deployed platform, no live store.

Why the isolation option is tested here rather than only used: a proof run that silently adopted the
credentials and database of an earlier run would still print "pass", so the freshness rule is a claim
about this code and not about how carefully the checker was written. The background handoff is tested
with a recorded process opener for the same reason — the defect it pins (a log file opened *inside* the
fresh fixture, which the child then refuses) is invisible to a test that only inspects the argument list.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

import serve_operator_demo as demo
from local_observe.platform.state import Store

TABLES = ('events', 'actions', 'executions', 'incidents', 'audit')


def get(application, token: str, path: str) -> tuple[int, object]:
    """One GET through the ASGI app, in-process: the same handler chain a browser request walks.

    ``http://localhost`` is a name this transport never resolves — nothing here opens a socket.
    """
    async def go():
        transport = httpx.ASGITransport(app=application)
        async with httpx.AsyncClient(transport=transport, base_url='http://localhost') as client:
            return await client.get(path, headers={'Authorization': 'Bearer ' + token})

    answer = asyncio.run(go())
    body = answer.json() if 'json' in answer.headers.get('content-type', '') else answer.text
    return answer.status_code, body


def digest(value: str) -> bool:
    """Lowercase SHA-256 hex, which is what the record route will accept and the UI will render."""
    return len(value) == 64 and value == value.lower() and all(char in '0123456789abcdef' for char in value)


class FixtureOptionTests(unittest.TestCase):
    """The CLI surface: a new directory asked for, or nothing about the old behaviour changed."""

    def test_the_default_invocation_is_unchanged(self):
        # An operator running the demo by hand must still get the shared fixture, port 0, no background:
        # the isolation option only exists for whoever asks for it.
        self.assertEqual(demo.options([]), {'port': 0, 'background': False, 'fixture': None})
        self.assertEqual(demo.options(['8123']), {'port': 8123, 'background': False, 'fixture': None})
        self.assertEqual(demo.options(['0']), {'port': 0, 'background': False, 'fixture': None})
        self.assertEqual(demo.options(['--background']), {'port': 0, 'background': True, 'fixture': None})
        self.assertEqual(demo.DEFAULT_FIXTURE, ROOT / 'scratch/operator-demo')

    def test_an_unknown_option_and_a_missing_port_are_refused(self):
        for argv in (['8123', '--fixture'], ['--verbose', '0'], ['not-a-port']):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    demo.options(argv)

    def test_a_blank_fixture_value_is_refused(self):
        for argv in (['--fixture', ''], ['--fixture'], ['--fixture=']):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    demo.options(argv)

    def test_a_repeated_option_two_ports_or_a_port_that_is_not_one_whole_number_are_refused(self):
        # Silence here is how a proof run ends up serving something other than what it asked for.
        for argv in (['--fixture', 'a', '--fixture', 'b'], ['--background', '--background'],
                     ['8123', '8124'], ['70000'], ['-1'], ['8123x'], [''], ['08'], ['--fixture', '   ']):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError):
                    demo.options(argv)

    def test_an_explicit_fixture_refuses_a_directory_that_already_holds_something(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        occupied = root / 'earlier-run'
        occupied.mkdir()
        (occupied / 'credentials.json').write_text('{"not": "yours"}')
        before = (occupied / 'credentials.json').read_text()

        with self.assertRaises(ValueError) as refused:
            demo.fixture_directory(occupied)
        # The message has to name the directory it refused, or the next minute is spent guessing.
        self.assertIn(str(occupied), str(refused.exception))
        self.assertIn('non-empty', str(refused.exception))
        self.assertEqual(before, (occupied / 'credentials.json').read_text())
        self.assertFalse((occupied / 'state.db').exists())
        self.assertFalse((occupied / 'server.json').exists())

    def test_a_directory_that_is_a_file_is_refused_rather_than_replaced(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        blocked = root / 'not-a-directory'
        blocked.write_text('a file is not a fixture')

        with self.assertRaises(ValueError):
            demo.fixture_directory(blocked)
        self.assertTrue(blocked.is_file())

    def test_a_fresh_fixture_is_created_empty_and_may_be_named_by_a_missing_path(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        empty = root / 'empty'
        empty.mkdir()
        brand_new = root / 'deeper' / 'run-7'

        self.assertEqual(demo.fixture_directory(empty), empty)
        self.assertEqual(demo.fixture_directory(brand_new), brand_new)
        self.assertTrue(brand_new.is_dir())
        self.assertEqual(list(brand_new.iterdir()), [])

    def test_the_background_child_is_handed_the_same_fixture_it_serves(self):
        # The child re-enters this script; without the path it would serve the shared default while the
        # parent waited on a server.json in a different directory than the one it reads. Compared as
        # paths, not as slash spelling: what has to survive the handoff is the location, and on Windows
        # `str(Path('a/b'))` is not the text that was typed.
        wanted = Path('scratch') / 'proof-run'
        with_fixture = demo.child_command(0, wanted)
        self.assertEqual(with_fixture.count(demo.FIXTURE_OPTION), 1)
        index = with_fixture.index(demo.FIXTURE_OPTION)
        self.assertIsInstance(with_fixture[index + 1], str)
        self.assertEqual(Path(with_fixture[index + 1]), wanted.resolve())
        self.assertEqual(with_fixture[index + 2:], [])          # one whole argument, never split text
        plain = demo.child_command(8123, None)
        self.assertEqual(plain[-1], '8123')
        self.assertNotIn(demo.FIXTURE_OPTION, plain)
        # Whatever the parent is willing to accept, the child must accept too.
        self.assertEqual(Path(demo.options([demo.FIXTURE_OPTION, str(wanted), '0'])['fixture']).resolve(),
                         wanted.resolve())


class FakeProcess:
    """The handle a mocked spawner hands back: a pid and nothing else."""

    pid = 4242


class BackgroundLaunchTests(unittest.TestCase):
    """The parent/child handoff of `--background`, with no server and no second process started.

    The defect these pin is real rather than cosmetic: a background launch that opened its log files
    *inside* the fresh fixture handed the child a directory that was no longer empty, and the child's own
    freshness refusal then killed every `--fixture` run. A test that only reads `child_command` cannot see
    that, because the two files are created by the parent in passing.
    """

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.runs = self.root / 'runs'
        self.runs.mkdir()

    def launch(self, fixture, port=0):
        spawned = []

        def popen(command, **streams):
            spawned.append((command, streams))
            return FakeProcess()

        return demo.start_background(port, fixture, popener=popen), spawned

    def test_a_fresh_launch_hands_over_a_still_empty_fixture_and_logs_beside_it(self):
        target = self.runs / 'proof-1'
        answer, spawned = self.launch(target)
        self.assertEqual(len(spawned), 1)
        command, streams = spawned[0]
        # The child is handed the resolved absolute directory, as one whole argument, and with no flag
        # anywhere that would let it adopt a directory it ought to refuse.
        handed = Path(command[command.index(demo.FIXTURE_OPTION) + 1])
        self.assertEqual(handed, target.resolve())
        self.assertTrue(handed.is_absolute())
        self.assertNotIn('--allow-existing', command)
        self.assertEqual(list(target.iterdir()), [])
        for key in ('stdout', 'stderr'):
            path = Path(streams[key].name)
            self.assertEqual(path.parent, self.runs)
            self.assertNotIn(target, path.parents)
            self.assertTrue(path.is_file())
        self.assertEqual(answer['url_file'], str(target / 'server.json'))
        self.assertEqual(answer['pid'], FakeProcess.pid)
        # The child re-parses these arguments, so they must parse back to exactly this fixture and port.
        reloaded = demo.options(command[3:])
        self.assertEqual(Path(reloaded['fixture']), target.resolve())
        self.assertEqual(reloaded['port'], 0)
        self.assertFalse(reloaded['background'])
        # And the empty directory it is handed is one the normal fresh-fixture check accepts.
        self.assertEqual(demo.fixture_directory(handed), handed)

    def test_an_existing_sibling_log_refuses_the_launch_before_anything_is_spawned(self):
        target = self.runs / 'proof-2'
        foreign = self.runs / 'proof-2.stdout.log'
        foreign.write_text('another run wrote this')

        def popen(command, **streams):                                    # pragma: no cover - must not run
            raise AssertionError('a refused launch must not start a server')

        with self.assertRaises(ValueError) as refused:
            demo.start_background(0, target, popener=popen)
        self.assertIn('existing background log', str(refused.exception))
        self.assertEqual(foreign.read_text(), 'another run wrote this')
        self.assertFalse((self.runs / 'proof-2.stderr.log').exists())

    def test_the_shared_fixture_keeps_its_logs_inside_it_and_appends_to_them(self):
        shared = self.runs / 'operator-demo'
        shared.mkdir()
        inside = shared / demo.LOG_NAMES[0]
        inside.write_text('earlier run\n')

        out, err, mode = demo.background_logs(shared, False)
        self.assertEqual([out.name, err.name], list(demo.LOG_NAMES))
        self.assertEqual((out.parent, mode), (shared, 'a'))
        with out.open(mode) as handle:
            handle.write('second run\n')
        self.assertEqual(inside.read_text(), 'earlier run\nsecond run\n')

        fresh_out, fresh_err, fresh_mode = demo.background_logs(self.runs / 'proof-3', True)
        self.assertEqual([fresh_out.name, fresh_err.name],
                         ['proof-3.stdout.log', 'proof-3.stderr.log'])
        self.assertEqual((fresh_out.parent, fresh_mode), (self.runs, 'x'))


class DemoHistoryReads(unittest.TestCase):
    """What the fixture answers over the API, and what reading it leaves alone."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.home = self.root / 'fresh'
        self.application = demo.app(self.home)
        self.credentials = json.loads((self.home / 'credentials.json').read_text())
        self.human = next(item['token'] for item in self.credentials if item['role'] == 'human')
        self.reader = next(item['token'] for item in self.credentials if item['role'] == 'reader')
        self.database = self.home / 'state.db'

    def read(self, path: str, application=None, token=None) -> tuple[int, object]:
        return get(application or self.application, token or self.human, path)

    def snapshot(self) -> dict:
        """Every row of every table the demo writes, plus the status roll-up, as text.

        `Store.records` bounds a read at 100 rows, which is above the handful this fixture holds, so the
        snapshot is the whole table and not a truncation of it.
        """
        store = Store(self.database, verification_policy=None)
        state = {table: [json.dumps(row, sort_keys=True, default=str)
                         for row in store.records(table, 100)] for table in TABLES}
        state['status'] = json.dumps(store.status(), sort_keys=True, default=str)
        return state

    def executions(self, application=None) -> list[dict]:
        status, body = self.read('/v1/records/executions', application)
        self.assertEqual(status, 200)
        return body['rows']

    def history(self, execution_id: str, application=None) -> tuple[int, object]:
        return self.read('/v1/verification/records?execution_id=' + execution_id, application)

    def record(self, verification_id: str, application=None) -> tuple[int, object]:
        return self.read('/v1/verification/record?verification_id=' + verification_id, application)

    def listing(self, application=None) -> dict[str, list[str]]:
        """The id lists, keyed by execution, for the two terminal executions the demo seeds."""
        terminal = [row['id'] for row in self.executions(application) if row['status'] == 'succeeded']
        self.assertEqual(len(terminal), 2)
        return {key: list(self.history(key, application)[1]['verification_ids']) for key in terminal}

    def test_the_fixture_holds_two_terminal_executions_and_two_saved_records(self):
        listed = self.listing()
        self.assertEqual(sorted(len(ids) for ids in listed.values()), [0, 2])
        loaded = next(ids for ids in listed.values() if ids)
        # What the UI shows is exactly what the server returned: ids only, sorted, inside the cap the UI
        # enforces, and every one of them a lowercase SHA-256 digest.
        self.assertLessEqual(len(loaded), 64)
        self.assertEqual(loaded, sorted(loaded))
        self.assertTrue(all(digest(item) for item in loaded))

    def test_the_list_answer_is_ids_only_and_carries_no_payload_of_any_kind(self):
        listed = self.listing()
        execution = next(key for key, ids in listed.items() if ids)
        status, body = self.history(execution)
        self.assertEqual(status, 200)
        # One key, and the raw text of the answer holds no verdict, reason or window: the list route
        # answers "which ids exist", and the UI has to ask again to find out anything about one of them.
        self.assertEqual(list(body), ['verification_ids'])
        text = json.dumps(body)
        for word in ('verdict', 'reason', 'window', 'outcome', 'samples', 'not_cleared', 'unknown'):
            self.assertNotIn(word, text)

    def test_a_record_document_answers_for_each_id_and_names_the_execution_it_belongs_to(self):
        execution = next(key for key, ids in self.listing().items() if ids)
        documents = {}
        for verification_id in self.listing()[execution]:
            status, body = self.record(verification_id)
            self.assertEqual(status, 200)
            self.assertEqual(body['execution_id'], execution)
            self.assertEqual(body['verification_id'], verification_id)
            self.assertEqual(set(body['window']), {'start', 'end'})
            documents[body['verdict']] = body

        # The reason for seeding two records: one verdict the UI must render verbatim, and one it must
        # not be able to read as a recovery. Both answers come from the stored document, not from the run.
        self.assertEqual(documents['not_cleared']['reason'], 'comparison-failed')
        self.assertIsNotNone(documents['not_cleared']['value'])
        self.assertEqual(documents['unknown']['reason'], 'store-unanswered')
        self.assertEqual([row['status'] for row in self.executions() if row['id'] == execution],
                         ['succeeded'])

    def test_a_missing_history_is_an_empty_answer_and_never_a_forged_one(self):
        silent = next(key for key, ids in self.listing().items() if not ids)
        self.assertEqual(self.history(silent), (200, {'verification_ids': []}))

    def test_history_reads_leave_every_lifecycle_row_and_the_audit_trail_untouched(self):
        before = self.snapshot()
        for execution_id in self.listing():
            self.history(execution_id)
        for verification_id in [item for ids in self.listing().values() for item in ids]:
            self.record(verification_id)
        self.record('0' * 64)                                   # including the reads that come back 404
        self.assertEqual(before, self.snapshot())

    def test_history_survives_a_deployment_that_mounts_no_policy(self):
        # The operator-facing claim: "this deployment mounts no verification policy" is not "this
        # deployment has no verification history". Serving the same file with nothing mounted answers
        # both reads exactly as before, because what a record says was settled when it was accepted.
        listed = self.listing()
        execution = next(key for key, ids in listed.items() if ids)
        documents = {item: self.record(item)[1] for item in listed[execution]}

        unmounted = demo.app(self.home, policy=None)
        self.assertEqual(listed, self.listing(unmounted))
        for verification_id, document in documents.items():
            self.assertEqual(self.record(verification_id, unmounted)[1], document)

    def test_an_absent_execution_is_404_and_a_query_the_contract_refuses_is_400(self):
        missing = 'f' * 8 + '-0000-4000-8000-000000000000'
        self.assertEqual(self.history(missing), (404, {'error': 'not_found'}))
        self.assertEqual(self.record('0' * 64), (404, {'error': 'not_found'}))
        # A malformed identifier is refused on shape, before any query is parsed or any database opened,
        # and the body names the rule — never the offending text, which is what these two assert.
        for refused in (self.history('not-an-uuid'), self.record('A' * 64)):
            status, body = refused
            self.assertEqual((status, body['error']), (400, 'invalid_request'))
            self.assertIn('detail', body)
            self.assertNotIn('not-an-uuid', json.dumps(body))
            self.assertNotIn('AAAA', json.dumps(body))

    def test_both_operator_credentials_read_the_same_history_and_neither_writes_it(self):
        listed = self.listing()
        execution = next(key for key, ids in listed.items() if ids)
        for token, role in ((self.human, 'human'), (self.reader, 'reader')):
            answer = self.read('/v1/verification/records?execution_id=' + execution, token=token)
            self.assertEqual(answer[1]['verification_ids'], listed[execution], role)
        # Mounting a policy is what lets the demo *seed* a record; handing out a producer credential is
        # not, and would turn a read-only UI proof into a writable platform.
        self.assertEqual({item['role'] for item in self.credentials}, {'human', 'reader'})

    def test_the_assumptions_the_existing_operator_proof_makes_still_hold(self):
        # check_operator_browser.py asserts exactly one open incident, a pending row on top of the action
        # table, and a first event row carrying the gatus sample id. Seeding a verification history had to
        # keep all three, because that history is inserted before them and rows come back newest-first.
        store = Store(self.database, verification_policy=None)
        # `status()` counts the statuses that exist; one open incident is the claim, not a zero-filled
        # taxonomy the roll-up has never answered with.
        self.assertEqual(store.status()['incidents'], {'open': 1})
        actions, events = store.records('actions', 10), store.records('events', 10)
        self.assertEqual([row['status'] for row in actions if row['status'] == 'pending'], ['pending'])
        self.assertEqual(actions[0]['status'], 'pending')
        # A stored event row is the canonical document as written: the query kind and the sample id
        # the evidence read asks for are fields of its evidence reference, not of the row itself.
        first = json.loads(events[0]['payload'])
        self.assertEqual(first['evidence'][0]['query_type'], 'gatus-result')
        self.assertEqual(first['evidence'][0]['parameters'].get('sample_id'), 'operator-demo')
        # And the two executions each belong to one of the two actions that finished, which is the
        # only reason an execution row can be asked about a verification history at all.
        finished = sorted(row['id'] for row in actions if row['status'] == 'succeeded')
        self.assertEqual(sorted(row['action_id'] for row in store.records('executions', 10)), finished)


if __name__ == '__main__':
    unittest.main()

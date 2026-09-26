import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.http import TransportError
from local_observe.inventory.index import build
from local_observe.inventory.validation import read_document
from local_observe.platform.sigma_runner import ARTIFACT_MAX_BYTES, artifact, tick
from local_observe.platform.state import Actor, Store

ROOT = Path(__file__).resolve().parents[1]
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'


class Query:
    def __init__(self, match=1, total=2, usable=2):
        self.row = {'source_count': total, 'usable_count': usable, 'match_count': match}
        self.calls = 0

    def query(self, sql, parameters):
        self.calls += 1
        return self.row


class Intake:
    def __init__(self, store, now):
        self.store, self.now, self.fail = store, now, False

    def request(self, method, path, payload):
        actor = Actor('sigma-stage', 'producer')
        if path == '/v1/events':
            result = self.store.intake(payload, actor, now=self.now)
        else:
            result = self.store.put_evidence(payload, actor, now=self.now)
        if self.fail and path == '/v1/events':
            self.fail = False
            raise TransportError('Lost acknowledgement')
        return 200, result


class SigmaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index = self.root / 'index.db'
        build(read_document(ROOT / 'examples/inventory/declared.yaml'), self.index, 'fixture')
        self.compiled = artifact(ROOT / 'examples/sigma/compiled/process-marker.json')
        self.cursor = self.root / 'cursor.json'
        self.store = Store(self.root / 'state.db')
        self.now = dt.datetime(2026, 9, 6, 15, 0, tzinfo=dt.timezone.utc)
        self.intake = Intake(self.store, self.now)

    def run_tick(self, query):
        return tick(self.index, self.compiled, RESOURCE, self.cursor, query, self.intake, now=self.now)

    def test_positive_negative_and_duplicate(self):
        query = Query()
        self.assertEqual(self.run_tick(query), 'delivered')
        self.assertEqual(self.run_tick(query), 'idle')
        self.assertEqual(query.calls, 1)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.now += dt.timedelta(minutes=1)
        self.intake.now = self.now
        self.run_tick(Query(match=0))
        self.assertEqual(self.store.status()['incidents'], {'resolved': 1})

    def test_missing_source_does_not_recover_finding(self):
        self.run_tick(Query())
        self.now += dt.timedelta(minutes=1)
        self.intake.now = self.now
        self.run_tick(Query(0, 0, 0))
        self.assertEqual(self.store.status()['incidents'], {'open': 2})

    def test_missing_mapping_is_coverage_failure(self):
        self.run_tick(Query(0, 2, 1))
        events = self.store.records('events')
        self.assertEqual(len(events), 1)
        self.assertEqual(json.loads(events[0]['payload'])['kind'], 'coverage')

    def test_restart_replays_exact_query_result(self):
        query = Query()
        self.intake.fail = True
        with self.assertRaises(TransportError):
            self.run_tick(query)
        self.assertIsNotNone(json.loads(self.cursor.read_text())['pending'])
        query.row['match_count'] = 0
        self.run_tick(query)
        self.assertEqual(query.calls, 1)
        self.assertEqual(self.store.status()['incidents'], {'open': 1})
        self.assertEqual(len(self.store.records('events')), 2)

    def test_cursor_bound_to_artifact(self):
        self.run_tick(Query())
        self.compiled['sql_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.run_tick(Query())

    def test_modified_artifact_refused(self):
        path = self.root / 'altered.json'
        self.compiled['sql'] += ' altered'
        path.write_text(json.dumps(self.compiled))
        with self.assertRaises(ValueError):
            artifact(path)

    def test_oversized_artifact_is_refused_by_name_and_size(self):
        """map guard and artifact cap : one big file in a mounted pack must never be read whole.

        The refusal names all three things an operator needs to act on it — which file, how big it is,
        what the bound is — because the artifact directory is an operator mount and the file that trips
        this is usually not a rule at all.
        """
        path = self.root / 'huge.json'
        path.write_bytes(json.dumps(self.compiled).encode('utf-8') + b' ' * ARTIFACT_MAX_BYTES)
        self.assertGreater(path.stat().st_size, ARTIFACT_MAX_BYTES)
        with self.assertRaises(ValueError) as context:
            artifact(path)
        message = str(context.exception)
        for expected in (path.name, str(path.stat().st_size), str(ARTIFACT_MAX_BYTES)):
            self.assertIn(expected, message)

    def test_artifact_exactly_at_the_bound_is_read(self):
        """The bound is inclusive, so the check is `>` and not `>=`: a file of exactly the bound parses.

        Padded with trailing whitespace rather than a second JSON document, which `json.loads` ignores
        and would otherwise refuse for a different reason: this test is about the byte count alone.
        """
        path = self.root / 'at-bound.json'
        text = json.dumps(self.compiled).encode('utf-8')
        path.write_bytes(text + b' ' * (ARTIFACT_MAX_BYTES - len(text)))
        self.assertEqual(path.stat().st_size, ARTIFACT_MAX_BYTES)
        self.assertEqual(artifact(path), self.compiled)

    def test_missing_artifact_keeps_its_file_error(self):
        """The size check must not turn an unmounted rule into a value refusal (map guard and artifact cap step 5)."""
        with self.assertRaises(FileNotFoundError):
            artifact(self.root / 'not-mounted.json')

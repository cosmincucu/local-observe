import copy
from contextlib import closing
import datetime as dt
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from local_observe.inventory import discovery, index
from local_observe.inventory.validation import InvalidInventory, declared, read_document, timestamp

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / 'inventory.db'
        self.observed = self.root / 'observed.db'
        self.document = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.snapshot = read_document(ROOT / 'examples/inventory/observed.yaml')
        self.host = self.document['resources'][0]['id']
        self.service = self.document['resources'][1]['id']
        index.build(self.document, self.db, 'fixture-v1', now=NOW)

    def ingest(self, snapshot=None):
        return discovery.ingest(self.observed, snapshot or self.snapshot, now=NOW)

    def findings(self, now=NOW):
        return discovery.drift(self.db, self.observed, ['synthetic-fixture'], now=now)['findings']

    def test_example_and_renamed_host_keep_uuid(self):
        self.document['resources'][0]['name'] = 'new-name'
        self.document['resources'][0]['aliases'].append({'type': 'hostname', 'value': 'new-name.example.test'})
        index.build(self.document, self.db, 'rename', now=NOW)
        with index.readonly(self.db) as connection:
            for alias in ('PROBE-1.EXAMPLE.TEST.', 'new-name.example.test'):
                match = index.resolve(connection, aliases=[{'type': 'hostname', 'value': alias}])
                self.assertEqual(match['resource_id'], self.host)

    def test_duplicate_uuid_and_normalized_alias_rejected(self):
        for mutate in (lambda doc: doc['resources'].append(doc['resources'][0]),
                       lambda doc: doc['resources'][1]['aliases'].append({'type': 'hostname', 'value': 'PROBE-1.EXAMPLE.TEST.'})):
            document = copy.deepcopy(self.document)
            mutate(document)
            with self.assertRaises(InvalidInventory):
                declared(document)

    def test_alias_scopes_do_not_merge(self):
        self.document['resources'][0]['aliases'].append({'type': 'service.name', 'value': 'demo-api', 'scope': 'different'})
        index.build(self.document, self.db, 'scope', now=NOW)
        with index.readonly(self.db) as connection:
            self.assertEqual(index.resolve(connection, aliases=[{'type': 'service.name', 'value': 'demo-api', 'scope': 'different'}])['resource_id'], self.host)

    def test_bad_uuid_unknown_relation_and_secret_value_rejected(self):
        mutations = [lambda doc: doc['resources'][0].update(id='not-a-uuid'),
                     lambda doc: doc['resources'][1]['relations'][0].update(target='a' * 36),
                     lambda doc: doc['resources'][0]['attributes'].update(api_key='synthetic-secret'),
                     lambda doc: doc.update(unexpected=True)]
        for mutate in mutations:
            document = copy.deepcopy(self.document)
            mutate(document)
            with self.assertRaises(InvalidInventory):
                declared(document)

    def test_valid_uuid_but_dangling_relation_is_rejected(self):
        self.document['resources'][1]['relations'][0]['target'] = '11111111-1111-4111-8111-111111111111'
        with self.assertRaises(InvalidInventory):
            declared(self.document)

    def test_duplicate_yaml_keys_anchors_and_nan_rejected(self):
        for content in ('schema_version: 1\nschema_version: 2', 'a: &a [1]\nb: *a', 'a: .nan', 'a: !!python/object:object {}'):
            path = self.root / 'bad.yaml'
            path.write_text(content)
            with self.assertRaises(InvalidInventory):
                read_document(path)

    def test_failed_validation_and_replace_preserve_previous_index(self):
        before = self.db.read_bytes()
        self.document['resources'][0]['id'] = 'bad'
        with self.assertRaises(InvalidInventory):
            index.build(self.document, self.db, 'bad', now=NOW)
        self.assertEqual(self.db.read_bytes(), before)
        self.document['resources'][0]['id'] = self.host
        with patch.object(index.os, 'replace', side_effect=PermissionError), self.assertRaises(PermissionError):
            index.build(self.document, self.db, 'blocked', now=NOW)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(list(self.root.glob('.inventory-*')), [])

    def test_build_normalizes_order_deterministically(self):
        before = self.db.read_bytes()
        self.document['resources'].reverse()
        self.document['resources'][1]['aliases'].reverse()
        index.build(self.document, self.db, 'fixture-v1', now=NOW)
        self.assertEqual(self.db.read_bytes(), before)

    def test_readonly_enforced_and_other_database_not_overwritten(self):
        with index.readonly(self.db) as connection, self.assertRaises(sqlite3.OperationalError):
            connection.execute('DELETE FROM resources')
        other = self.root / 'operational.db'
        with closing(sqlite3.connect(other)) as connection:
            connection.execute('CREATE TABLE approvals(id TEXT)')
        before = other.read_bytes()
        with self.assertRaises(InvalidInventory):
            index.build(self.document, other, 'bad')
        self.assertEqual(other.read_bytes(), before)
        with self.assertRaises(InvalidInventory):
            discovery.ingest(self.db, self.snapshot, now=NOW)

    def test_conflicting_aliases_and_unknown_uuid_stay_unresolved(self):
        aliases = [{'type': 'hostname', 'value': 'probe-1.example.test'}, {'type': 'service.name', 'value': 'demo-api', 'scope': 'demo'}]
        with index.readonly(self.db) as connection:
            self.assertEqual(index.resolve(connection, aliases=aliases)['status'], 'conflict')
            result = index.resolve(connection, resource_id='11111111-1111-4111-8111-111111111111', aliases=aliases[:1])
            self.assertEqual(result['status'], 'unknown_uuid')
            self.assertIsNone(result['resource_id'])

    def test_dependency_cycles_terminate_and_limits_report_truncation(self):
        self.document['resources'][0]['relations'] = [{'type': 'depends-on', 'target': self.service}]
        index.build(self.document, self.db, 'cycle', now=NOW)
        with index.readonly(self.db) as connection:
            self.assertEqual(index.dependents(connection, self.host)['resources'][0]['id'], self.service)
            with self.assertRaises(InvalidInventory):
                index.dependents(connection, self.host, 1001)

    def test_snapshot_replay_is_idempotent_and_changed_replay_rejected(self):
        self.assertEqual(self.ingest()['status'], 'inserted')
        self.assertEqual(self.ingest()['status'], 'duplicate')
        self.snapshot['observations'][0]['name'] = 'changed-again'
        with self.assertRaises(InvalidInventory):
            self.ingest()
        with closing(sqlite3.connect(self.observed)) as connection:
            self.assertEqual(connection.execute('SELECT count(*) FROM snapshots').fetchone()[0], 1)

    def test_older_arrival_does_not_replace_latest_observation(self):
        self.ingest()
        older = copy.deepcopy(self.snapshot)
        older.update(snapshot_id='11111111-1111-4111-8111-111111111111', observed_at='2026-09-06T11:00:00Z')
        self.ingest(older)
        self.assertEqual(discovery.latest(self.observed, 'synthetic-fixture')['snapshot_id'], self.snapshot['snapshot_id'])

    def test_future_timestamp_and_duplicate_observation_id_rejected(self):
        future = copy.deepcopy(self.snapshot)
        future['observed_at'] = '2026-09-07T12:00:00Z'
        with self.assertRaises(InvalidInventory):
            self.ingest(future)
        self.snapshot['observations'].append(self.snapshot['observations'][0])
        with self.assertRaises(InvalidInventory):
            self.ingest()

    def test_fresh_incomplete_discovery_never_claims_absence(self):
        self.ingest()
        kinds = {item['kind'] for item in self.findings()}
        self.assertEqual(kinds, {'changed', 'undeclared', 'coverage_incomplete'})

    def test_stale_and_error_discovery_never_claim_absence(self):
        self.ingest()
        self.assertEqual([item['kind'] for item in self.findings(NOW + dt.timedelta(hours=2))], ['source_stale'])
        failed = copy.deepcopy(self.snapshot)
        failed.update(snapshot_id='11111111-1111-4111-8111-111111111111', observed_at='2026-09-06T12:01:00Z',
                      status='error', error_code='permission_denied', complete=False, observations=[])
        self.ingest(failed)
        self.assertEqual([item['kind'] for item in self.findings()], ['source_unavailable'])

    def test_missing_requires_complete_successful_scoped_snapshot(self):
        self.snapshot.update(complete=True, observations=[], scope=[self.service])
        self.ingest()
        findings = self.findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]['kind'], findings[0]['resource_id']), ('missing', self.service))

    def test_conflicts_suppress_absence(self):
        item = self.snapshot['observations'][0]
        item['aliases'].append({'type': 'service.name', 'scope': 'demo', 'value': 'demo-api'})
        self.snapshot.update(complete=True, observations=[item], scope=[self.host, self.service])
        self.ingest()
        self.assertEqual({item['kind'] for item in self.findings()}, {'identity_unresolved', 'coverage_incomplete'})

    def test_findings_are_stable_across_evaluation_retries(self):
        self.ingest()
        first = {item['finding_id'] for item in self.findings()}
        second = {item['finding_id'] for item in self.findings(NOW + dt.timedelta(seconds=1))}
        self.assertEqual(first, second)

    def test_proposal_is_review_only_idempotent_and_preserves_declarations(self):
        before = self.db.read_bytes()
        self.ingest()
        path = self.root / 'proposal.json'
        args = (self.db, self.observed, 'synthetic-fixture', 'new-service-001', path)
        first = discovery.propose(*args, now=NOW)
        second = discovery.propose(*args, now=NOW)
        self.assertEqual(first, second)
        self.assertEqual(first['status'], 'needs_review')
        self.assertEqual(self.db.read_bytes(), before)
        declared({'schema_version': 1, 'resources': [first['resource']]})
        with self.assertRaises(InvalidInventory):
            discovery.propose(self.db, self.observed, 'synthetic-fixture', 'host-001', path, now=NOW)

    def test_an_index_built_at_another_schema_version_is_refused_with_the_rebuild_command(self):
        """A built index is derived data: the read refuses a stale one and names the rebuild, never migrates.

        Written with raw sqlite so the file says what an old build says — `application_id` of this product,
        `user_version` 1, i.e. an index built before typed inventory records added the `owner` column. Reading it
        would answer
        "No owner declared" for a resource whose operator did declare one, so the refusal is the answer.
        """
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute('PRAGMA user_version=1')
        with self.assertRaises(InvalidInventory) as caught:
            with index.readonly(self.db):
                pass
        sentence = str(caught.exception)
        self.assertIn('Unsupported inventory index schema', sentence)
        self.assertIn('built at version 1', sentence)
        self.assertIn('this build reads 2', sentence)
        self.assertIn('lo-inventory build', sentence)
        # The command that sentence names must be able to land on this very path: a stale index of this
        # product is replaced in place, while a file that is not an index of this product still is not.
        index.build(self.document, self.db, 'rebuilt-rev', now=NOW)
        with index.readonly(self.db) as connection:
            self.assertEqual(connection.execute('PRAGMA user_version').fetchone()[0], 2)
        foreign = Path(self.root) / 'foreign.db'
        with closing(sqlite3.connect(foreign)) as connection:
            connection.execute('CREATE TABLE t (x)')
        with self.assertRaises(InvalidInventory):
            index.build(self.document, foreign, 'foreign-rev', now=NOW)

    def test_the_built_index_stores_a_declared_owner_and_null_without_one(self):
        """The column the version bump exists for, read back out of a file the example declaration built."""
        with index.readonly(self.db) as connection:
            self.assertIsNone(connection.execute('SELECT owner FROM resources WHERE id=?',
                                                 (self.host,)).fetchone()[0],
                              'the shipped example names nobody, so the column stays NULL')
        self.document['resources'][0]['owner'] = 'team-platform'
        index.build(self.document, self.db, 'owner-rev', now=NOW)
        with index.readonly(self.db) as connection:
            self.assertEqual(connection.execute('SELECT owner FROM resources WHERE id=?',
                                                (self.host,)).fetchone()[0], 'team-platform')


if __name__ == '__main__':
    unittest.main()

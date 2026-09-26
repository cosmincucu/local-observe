import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from local_observe.deployment.content import Conflict
from local_observe.deployment.recovery import coverage, docker_inventory, resources
from local_observe.inventory.validation import digest


NOW = 1000
ID = 'a'*64


def document():
    return {'Id': ID, 'Name': '/stage-db-1', 'Image': 'sha256:'+'b'*64,
            'Config': {'Env': ['SECRET=must-not-export'], 'Labels': {
                'com.docker.compose.project': 'stage', 'com.docker.compose.service': 'db',
                'private': 'must-not-export'}}, 'State': {'Status': 'running'},
            'HostConfig': {'ReadonlyRootfs': False}, 'Mounts': [
                {'Type': 'volume', 'Name': 'stage-data', 'Source': '/internal/docker/path',
                 'Destination': '/data', 'RW': True},
                {'Type': 'bind', 'Source': '/private/config', 'Destination': '/config', 'RW': False},
                {'Type': 'tmpfs', 'Destination': '/tmp', 'RW': True}]}


def snapshot(doc=None):
    doc = document() if doc is None else doc
    def run(*args):
        if args[:3] == ('docker', 'ps', '-aq'):
            return ID+'\n'
        if args == ('docker', 'inspect', ID):
            return json.dumps([doc])
        raise AssertionError('Unexpected Docker operation: '+repr(args))
    return docker_inventory(run, ['stage'], 'isolated-test-daemon', now=NOW)


def ownership(actual):
    return {'schema_version': 1, 'inventory_sha256': actual['sha256'], 'owners': [
        {'id': 'database', 'description': 'Database, configuration and scratch layer',
         'resources': list(resources(actual)), 'recovery': 'backup-restore',
         'procedure': 'Test fixture only; no restore has occurred'}]}


class RecoveryTests(unittest.TestCase):
    def test_read_only_inventory_has_images_mounts_no_environment_or_extra_labels(self):
        actual = snapshot()
        self.assertEqual(actual['containers'][0]['image_id'], 'sha256:'+'b'*64)
        self.assertNotIn('must-not-export', json.dumps(actual))
        self.assertNotIn('/internal/docker/path', json.dumps(actual))
        self.assertEqual(set(resources(actual)), {'volume:stage-data', 'bind:/private/config', 'layer:'+ID})

    def test_missing_owner_blocks_with_human_service_and_target(self):
        actual = snapshot()
        result = coverage({'schema_version': 1, 'inventory_sha256': actual['sha256'], 'owners': []}, actual, now=NOW)
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(len(result['unassigned']), 3)
        self.assertIn('stage/db (stage-db-1) -> /data [rw]', result['unassigned'][2]['used_by'])

    def test_complete_coverage_never_claims_restore_or_authorizes_deployment(self):
        actual = snapshot()
        result = coverage(ownership(actual), actual, now=NOW)
        self.assertEqual(result['status'], 'review-required')
        self.assertFalse(result['deploy_authorized'])
        self.assertFalse(result['recovery_proven'])

    def test_readonly_root_removes_only_layer_not_readonly_binds(self):
        doc = document()
        doc['HostConfig']['ReadonlyRootfs'] = True
        self.assertEqual(set(resources(snapshot(doc))), {'volume:stage-data', 'bind:/private/config'})

    def test_unknown_or_duplicate_assignments_block(self):
        actual = snapshot()
        plan = ownership(actual)
        plan['owners'][0]['resources'].append('volume:other-daemon-data')
        self.assertEqual(coverage(plan, actual, now=NOW)['status'], 'blocked')
        plan = ownership(actual)
        plan['owners'].append(copy.deepcopy(plan['owners'][0]))
        with self.assertRaises(Conflict):
            coverage(plan, actual, now=NOW)
        plan['owners'][1]['id'] = 'different-owner'
        with self.assertRaises(Conflict):
            coverage(plan, actual, now=NOW)

    def test_stale_future_and_changed_inventory_are_rejected(self):
        actual = snapshot()
        plan = ownership(actual)
        for now in [NOW-1, NOW+61]:
            with self.subTest(now=now), self.assertRaises(Conflict):
                coverage(plan, actual, now=now)
        actual['containers'][0]['image_id'] = 'sha256:'+'c'*64
        with self.assertRaises(Conflict):
            coverage(plan, actual, now=NOW)
        actual['sha256'] = digest({k: v for k, v in actual.items() if k != 'sha256'})
        with self.assertRaises(Conflict):
            coverage(plan, actual, now=NOW)

    def test_changed_second_capture_is_refused(self):
        calls = 0
        def run(*args):
            nonlocal calls
            if args[1] == 'ps':
                return ID
            calls += 1
            doc = document()
            if calls == 2:
                doc['Mounts'][0]['Name'] = 'different-state'
            return json.dumps([doc])
        with self.assertRaises(Conflict):
            docker_inventory(run, ['stage'], 'test', now=NOW)

    def test_empty_partial_foreign_and_unsupported_inspection_refused(self):
        for change in ['empty', 'partial', 'foreign', 'unsupported', 'missing-source']:
            with self.subTest(change=change):
                doc = document()
                if change == 'foreign':
                    doc['Config']['Labels']['com.docker.compose.project'] = 'production'
                if change == 'unsupported':
                    doc['Mounts'][0]['Type'] = 'cluster'
                if change == 'missing-source':
                    del doc['Mounts'][1]['Source']
                def run(*args):
                    if args[1] == 'ps':
                        return '' if change == 'empty' else ID
                    return json.dumps([] if change == 'partial' else [doc])
                with self.assertRaises(Conflict):
                    docker_inventory(run, ['stage'], 'test', now=NOW)

    def test_invalid_project_never_calls_docker(self):
        def run(*args):
            self.fail('Docker called for invalid project')
        for projects in [[], ['stage', 'stage'], ['--all'], ['stage;rm'], ['']]:
            with self.subTest(projects=projects), self.assertRaises(Conflict):
                docker_inventory(run, projects, 'test', now=NOW)

    def test_duplicate_targets_and_missing_project_coverage_refused(self):
        doc = document()
        doc['Mounts'].append(copy.deepcopy(doc['Mounts'][0]))
        with self.assertRaises(Conflict):
            snapshot(doc)
        actual = snapshot()
        actual['projects'].append('missing-project')
        actual['sha256'] = digest({k: v for k, v in actual.items() if k != 'sha256'})
        with self.assertRaises(Conflict):
            resources(actual)

    def test_shared_bind_lists_all_consumers_once(self):
        actual = snapshot()
        second = copy.deepcopy(actual['containers'][0])
        second.update(id='c'*64, name='stage-reader-1', service='reader', readonly_rootfs=True)
        second['mounts'] = [m for m in second['mounts'] if m['type'] == 'bind']
        actual['containers'].append(second)
        actual['sha256'] = digest({k: v for k, v in actual.items() if k != 'sha256'})
        self.assertEqual(len(resources(actual)['bind:/private/config']), 2)
        self.assertEqual(coverage(ownership(actual), actual, now=NOW)['status'], 'review-required')

    def test_cli_missing_ownership_exits_two_without_deployment(self):
        import time
        actual = snapshot()
        actual['captured_at'] = time.time()
        actual['sha256'] = digest({k: v for k, v in actual.items() if k != 'sha256'})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'inventory.json').write_text(json.dumps(actual))
            (root/'owners.json').write_text(json.dumps({'schema_version': 1, 'inventory_sha256': actual['sha256'], 'owners': []}))
            result = subprocess.run([sys.executable, '-B', '-m', 'local_observe.deployment.cli', 'check-ownership',
                                     '--ownership', str(root/'owners.json'), '--inventory', str(root/'inventory.json')],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(json.loads(result.stdout)['deploy_authorized'])

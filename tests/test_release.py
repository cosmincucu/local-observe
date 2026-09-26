import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from local_observe.deployment.content import Conflict, make_lock
from local_observe.deployment.defaults import package
from local_observe.deployment.release import backup_sqlite, check_release, inspect_sqlite, source_pin, transition, verify_images, verify_inputs, verify_source
from local_observe.deployment.live import capture, compare, dashboard_document, docker_homepage_export, homepage_export, signoz_export, SignozReader
from local_observe.inventory.validation import digest
from local_observe.platform.state import Store


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'code.py').write_text('source')
        Store(self.root/'state.db')
        self.state = inspect_sqlite(self.root/'state.db')
        pin = source_pin(self.root, ['code.py'])
        self.release = {'schema_version': 1, 'name': 'test-release', 'channel': 'development', 'source': pin,
            'customisations': pin, 'content': make_lock([package()]), 'deployment_sha256': '0'*64,
            'components': {'platform': {'reference': 'sha256:'+'1'*64, 'image_id': 'sha256:'+'1'*64, 'platform': 'linux/amd64'}},
            'contracts': {'content': 1, 'platform_api': 1, 'homepage': '1.13.2', 'signoz_dashboards': 'v2-v6'},
            'state': {'platform': self.state, 'rollback': 'restore-backup', 'migration': 'none'}}

    def test_pins_verify_and_changed_bytes_refuse(self):
        check_release(self.release)
        verify_source(self.root, self.release['source'])
        (self.root/'code.py').write_text('changed')
        with self.assertRaises(Conflict):
            verify_source(self.root, self.release['source'])

    def test_mutable_image_refused(self):
        self.release['components']['platform']['reference'] = 'python:latest'
        with self.assertRaises(Conflict):
            check_release(self.release)

    def test_public_cannot_claim_uncommitted_or_local_image(self):
        self.release['channel'] = 'public'
        with self.assertRaises(Conflict):
            check_release(self.release)
        for key in ('source', 'customisations'):
            self.release[key] = source_pin(self.root, ['code.py'], 'a'*40)
        with self.assertRaises(Conflict):
            check_release(self.release)
        self.release['components']['platform']['reference'] = 'example.test/platform@sha256:'+'2'*64
        check_release(self.release)

    def test_transition_requires_actual_schema(self):
        self.assertEqual(transition(self.release, self.release, self.state)['status'], 'review-required')
        # 99, not a plausible next number: since control state the fixture's own user_version is 2, so any small
        # literal risks being the version some future build makes current and this refusing nothing.
        for key, value in [('user_version', 99), ('application_id', 2), ('schema_sha256', 'a'*64)]:
            changed = {**self.state, key: value}
            with self.assertRaises(Conflict):
                transition(self.release, self.release, changed)

    def test_guard_contract_cannot_be_removed_by_old_schema_compatible_binary(self):
        guarded = copy.deepcopy(self.release)
        guarded['contracts']['notification_safety'] = 1
        self.assertEqual(transition(self.release, guarded, self.state)['status'], 'review-required')
        with self.assertRaises(Conflict):
            transition(guarded, self.release, self.state)
        modes = copy.deepcopy(guarded)
        modes['contracts']['notification_safety'] = 2
        self.assertEqual(transition(guarded, modes, self.state)['status'], 'review-required')
        with self.assertRaises(Conflict):
            transition(modes, guarded, self.state)

    def test_git_proof_checks_actual_blob_not_just_commit_shaped_text(self):
        from local_observe.deployment.release import verify_git_source
        pin = source_pin(self.root, ['code.py'], 'a'*40)
        outputs = [b'', b'a'*40+b'\n', b'source']
        def run(*args, **kwargs):
            return subprocess.CompletedProcess(args, 0, outputs.pop(0), b'')
        with patch('local_observe.deployment.release.subprocess.run', side_effect=run):
            verify_git_source(self.root, pin)
        outputs = [b'', b'a'*40+b'\n', b'different committed bytes']
        with patch('local_observe.deployment.release.subprocess.run', side_effect=run):
            with self.assertRaises(Conflict): verify_git_source(self.root, pin)

    def test_notification_contract_reads_constant_without_execution(self):
        from local_observe.deployment.release import notification_contract
        self.assertEqual(notification_contract(self.root), 0)
        path = self.root / 'local_observe/platform/notification_safety.py'
        path.parent.mkdir(parents=True)
        for version in (1, 2):
            path.write_text(f'SAFETY_CONTRACT = {version}\nraise RuntimeError("never execute")\n')
            self.assertEqual(notification_contract(self.root), version)
        for source in ('SAFETY_CONTRACT = True', 'SAFETY_CONTRACT = 3', 'SAFETY_CONTRACT = int("2")',
                       'SAFETY_CONTRACT = 1\nSAFETY_CONTRACT = 2', 'other = 2'):
            path.write_text(source)
            with self.assertRaises(Conflict):
                notification_contract(self.root)

    def test_backup_and_restore_inspection(self):
        result = backup_sqlite(self.root/'state.db', self.root/'backup.db')
        self.assertEqual(result['state'], self.state)
        self.assertEqual(inspect_sqlite(self.root/'backup.db'), self.state)
        with self.assertRaises(FileExistsError):
            backup_sqlite(self.root/'state.db', self.root/'backup.db')

    def test_unsafe_source_path_refused(self):
        with self.assertRaises(Conflict):
            source_pin(self.root, ['../outside'])

    def test_source_manifest_hash_refused(self):
        self.release['source']['sha256'] = 'f'*64
        with self.assertRaises(Conflict):
            check_release(self.release)

    def test_registry_reference_must_resolve_to_pinned_platform_image(self):
        actual = {'Id': 'sha256:'+'1'*64, 'Os': 'linux', 'Architecture': 'amd64'}
        verify_images(self.release, lambda _: actual)
        for bad in ({**actual, 'Id': 'sha256:'+'2'*64}, {**actual, 'Architecture': 'arm64'}):
            with self.assertRaises(Conflict):
                verify_images(self.release, lambda _: bad)

    def test_customisation_inputs_bind_release_metadata(self):
        import json
        (self.root/'deployment.json').write_text(json.dumps({'example': 1}))
        (self.root/'release.lock.json').write_text(json.dumps(self.release['content']))
        self.release['customisations'] = source_pin(self.root, ['deployment.json', 'release.lock.json'])
        self.release['deployment_sha256'] = digest({'example': 1})
        verify_inputs(self.release, self.root, self.root)
        self.release['deployment_sha256'] = '0'*64
        with self.assertRaises(Conflict):
            verify_inputs(self.release, self.root, self.root)


class LiveTests(unittest.TestCase):
    def test_fresh_complete_same_scope_required(self):
        old = capture('homepage-files-v1', 'stage', {'a': 'a'*64}, now=1)
        new = {**old, 'captured_at': 100}
        self.assertEqual(compare(old, new, now=100)['status'], 'review-required')
        for bad in ({**new, 'scope': 'prod'}, {**new, 'captured_at': 0}, {**new, 'complete': False},
                    {**new, 'sha256': 'b'*64}, {**new, 'captured_at': 101}):
            with self.assertRaises(Conflict):
                compare(old, bad, now=100)

    def test_live_file_change_and_unmanaged_block(self):
        a = homepage_export(lambda _: b'initial', 'container-a')
        b = homepage_export(lambda name: b'edited' if name == 'services.yaml' else b'initial', 'container-a')
        self.assertEqual(compare(a, b)['drift'], ['services.yaml'])
        b = capture('homepage-files-v1', 'container-a', {**a['artifacts'], 'extra': 'f'*64})
        self.assertEqual(compare(a, b)['status'], 'blocked')

    def test_missing_live_file_does_not_produce_snapshot(self):
        with self.assertRaises(Conflict):
            homepage_export(lambda _: None, 'stage')

    @staticmethod
    def doc():
        return {'id': 'abc', 'name': 'dashboard', 'tags': [], 'schemaVersion': 'v6',
                'spec': {'panels': {'query': 'SELECT 1'}, 'display': {'name': 'Hello'}}, 'updatedAt': 'ignored'}

    def get(self, path):
        return {'data': {'total': 1, 'dashboards': [self.doc()]}} if '?' in path else {'data': self.doc()}

    def test_dashboard_export_retains_queries_and_maps_ids(self):
        snapshot, docs = signoz_export(self.get, 'stage', {'user.dashboard': 'abc'})
        self.assertEqual(docs['user.dashboard']['spec']['panels']['query'], 'SELECT 1')
        self.assertNotIn('updatedAt', docs['user.dashboard'])
        self.assertIn('$identity-map', snapshot['artifacts'])

    def test_dashboard_edit_blocks(self):
        a, _ = signoz_export(self.get, 'stage', {'user.dashboard': 'abc'})
        def changed(path):
            value = self.get(path)
            if '?' not in path:
                value['data']['spec']['panels']['query'] = 'SELECT 2'
            return value
        b, _ = signoz_export(changed, 'stage', {'user.dashboard': 'abc'})
        self.assertEqual(compare(a, b)['drift'], ['user.dashboard'])

    def test_missing_mapping_partial_list_and_new_schema_refused(self):
        with self.assertRaises(Conflict):
            signoz_export(self.get, 'stage', {'user.dashboard': 'missing'})
        with self.assertRaises(Conflict):
            signoz_export(lambda _: {'data': {'total': 2, 'dashboards': [self.doc()]}}, 'stage', {})
        with self.assertRaises(Conflict):
            dashboard_document({**self.doc(), 'schemaVersion': 'v7'})

    def test_duplicate_id_and_changing_list_refused(self):
        with self.assertRaises(Conflict):
            signoz_export(lambda _: {'data': {'total': 2, 'dashboards': [self.doc(), self.doc()]}}, 'stage', {})
        calls = []
        def changing(path):
            value = self.get(path)
            if '?' in path:
                calls.append(path)
                if len(calls) == 2:
                    value['data']['dashboards'][0]['updatedAt'] = 'changed'
            return value
        with self.assertRaises(Conflict):
            signoz_export(changing, 'stage', {})

    def test_reader_refuses_non_tls_and_mutator(self):
        with self.assertRaises(Conflict):
            SignozReader('http://example.test', 'secret')
        reader = SignozReader('https://example.test', 'secret')
        with self.assertRaises(Conflict):
            reader('/api/v2/dashboards/abc/delete')

    def test_docker_capture_checks_instance_image_and_stability(self):
        import json
        image = 'sha256:'+'a'*64
        state = {'State': {'Running': True}, 'Image': image, 'Id': 'container-id'}
        def run(*args):
            return json.dumps([state]) if args[1] == 'inspect' else 'aGVsbG8='
        self.assertTrue(docker_homepage_export(run, 'stage-homepage', image, 'stage')['complete'])
        with self.assertRaises(Conflict):
            docker_homepage_export(run, 'stage-homepage', 'sha256:'+'b'*64, 'stage')
        reads = []
        def changing(*args):
            if args[1] == 'exec':
                reads.append(args)
                return 'aGVsbG8=' if len(reads) <= 9 else 'ZGlmZmVyZW50'
            return run(*args)
        with self.assertRaises(Conflict):
            docker_homepage_export(changing, 'stage-homepage', image, 'stage')

    def test_detail_change_and_invalid_mapping_refused(self):
        with self.assertRaises(Conflict):
            signoz_export(self.get, 'stage', {'user.dashboard': ['bad']})
        reads = []
        def changing(path):
            value = self.get(path)
            if '?' not in path:
                reads.append(path)
                if len(reads) == 2:
                    value['data']['spec']['panels']['query'] = 'SELECT 2'
            return value
        with self.assertRaises(Conflict):
            signoz_export(changing, 'stage', {})


if __name__ == '__main__':
    unittest.main()

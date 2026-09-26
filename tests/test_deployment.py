import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

from local_observe.deployment.content import Conflict, export_dashboard, make_lock, plan, render, resolve, write_bundle
from local_observe.inventory.validation import digest, read_document

ROOT = Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.package = read_document(ROOT/'examples/deployment/core-v1.yaml')
        self.deployment = read_document(ROOT/'examples/deployment/custom.yaml')

    def state(self, package=None, deployment=None):
        package = self.package if package is None else package
        return resolve([package], make_lock([package]), self.deployment if deployment is None else deployment)

    def override(self, mode='patch', **values):
        row = next(row for row in self.package['content'] if row['id'] == 'core.operator')
        return {'id': row['id'], 'expect_sha256': digest(row), 'mode': mode, **values}

    def test_upgrade_preserves_user_content(self):
        old = self.state()
        package = copy.deepcopy(self.package)
        package['version'] = '0.2.0-demo.1'
        package['content'][-1]['spec']['description'] = 'Upstream improvement'
        new = self.state(package)
        change = plan(old, old, new)
        self.assertEqual(change['change'], ['core.health'])
        self.assertFalse(change['deploy_authorized'])
        self.assertEqual([r for r in old['content'] if r['owner'] == 'user'], [r for r in new['content'] if r['owner'] == 'user'])

    def test_lock_rejects_mutated_package_and_version(self):
        lock = make_lock([self.package])
        for field, value in (('version', 'next'), ('content_contract', 2)):
            changed = {**self.package, field: value}
            with self.assertRaises(Conflict):
                resolve([changed], lock, self.deployment)
        self.package['content'][-1]['spec']['title'] = 'Changed bytes'
        with self.assertRaises(Conflict):
            resolve([self.package], lock, self.deployment)

    def test_patch_retains_unset_fields_and_rejects_upstream_change(self):
        self.deployment['overrides'] = [self.override(set={'name': 'My incidents'})]
        row = next(r for r in self.state()['content'] if r['id'] == 'core.operator')
        self.assertEqual(row['spec']['name'], 'My incidents')
        self.assertIn('href', row['spec']['config'])
        self.package['content'][2]['spec']['order'] = 2
        with self.assertRaisesRegex(Conflict, 'beneath override'):
            self.state()

    def test_replacement_is_explicit_and_disable_is_reviewed(self):
        original = self.state()
        spec = copy.deepcopy(self.package['content'][2]['spec'])
        spec['config'] = {'href': 'https://replacement.example.test'}
        self.deployment['overrides'] = [self.override('replace', spec=spec)]
        row = next(r for r in self.state()['content'] if r['id'] == 'core.operator')
        self.assertEqual(row['spec'], spec)
        self.deployment['overrides'] = [self.override('disable')]
        change = plan(original, original, self.state())
        self.assertEqual(change['remove'], ['core.operator'])
        self.assertTrue(change['requires_removal_review'])
        self.assertEqual(change['status'], 'review-required')

    def test_override_schema_and_targets_fail_closed(self):
        for change in (self.override('patch'), self.override('disable', set={}),
                       {**self.override(set={}), 'id': 'core.missing'},
                       {**self.override(set={}), 'id': 'user.media'}):
            self.deployment['overrides'] = [change]
            with self.assertRaises(Conflict):
                self.state()
        self.deployment['overrides'] = [self.override(set={'unknown_field': 1})]
        with self.assertRaises(Conflict):
            self.state()

    def test_duplicate_ids_and_namespace_violations(self):
        for source in ('package', 'deployment'):
            package, deployment = copy.deepcopy(self.package), copy.deepcopy(self.deployment)
            document = package if source == 'package' else deployment
            document['content'].append(copy.deepcopy(document['content'][0]))
            with self.assertRaises(Conflict):
                self.state(package, deployment)
        self.deployment['content'][0]['id'] = 'core.media'
        with self.assertRaises(Conflict):
            self.state()

    def test_dangling_group_and_name_collision(self):
        self.deployment['content'][0]['spec']['group'] = 'core.missing'
        with self.assertRaises(Conflict):
            self.state()
        self.deployment['content'][0]['spec']['group'] = 'core.consoles'
        duplicate = copy.deepcopy(self.deployment['content'][0])
        duplicate['id'] = 'user.another'
        self.deployment['content'].append(duplicate)
        with self.assertRaises(Conflict):
            self.state()

    def test_widget_secrets_require_file_references_and_safe_urls(self):
        config = self.deployment['content'][0]['spec']['config']
        for key, value in (('password', 'secret-value'), ('href', 'https://user:password@example.test'), ('href', 'javascript:alert(1)')):
            changed = copy.deepcopy(self.deployment)
            changed['content'][0]['spec']['config'][key] = value
            with self.assertRaises(Conflict):
                self.state(deployment=changed)
        config['widget'] = {'headers': {'Authorization': 'Bearer {{HOMEPAGE_FILE_READER_TOKEN}}'}}
        self.assertIn('HOMEPAGE_FILE_READER_TOKEN', json.dumps(self.state()))

    def test_runtime_edits_and_missing_records_block_upgrade(self):
        old = self.state()
        actual = copy.deepcopy(old)
        actual['content'][-1]['spec']['order'] = 99
        self.assertEqual(plan(old, actual, old)['status'], 'blocked')
        actual['content'].pop()
        self.assertEqual(plan(old, actual, old)['status'], 'blocked')

    def test_unmanaged_content_retained_and_collision_blocks(self):
        old = self.state()
        actual = copy.deepcopy(old)
        row = {'id': 'user.extra', 'kind': 'dashboard', 'spec': {'title': 'UI draft'}, 'owner': 'user'}
        actual['content'].append(row)
        self.assertEqual(plan(old, actual, old)['retain_unmanaged'], ['user.extra'])
        new = copy.deepcopy(old)
        new['content'].append(row)
        self.assertEqual(plan(old, actual, new)['unmanaged_collisions'], ['user.extra'])

    def test_deterministic_render_and_fresh_output(self):
        state = self.state()
        files = render(state, self.deployment)
        shuffled = copy.deepcopy(self.deployment)
        shuffled['content'].reverse()
        self.assertEqual(files, render(self.state(deployment=shuffled), shuffled))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'render'
            write_bundle(output, state, self.deployment)
            manifest = json.loads((output/'files.json').read_text())
            for name, expected in manifest.items():
                self.assertEqual(hashlib.sha256((output/name).read_bytes()).hexdigest(), expected)
            with self.assertRaises(FileExistsError):
                write_bundle(output, state, self.deployment)
        with self.assertRaises(Conflict):
            render(state, {**self.deployment, 'id': 'different'})

    def test_dashboard_export_is_a_review_proposal(self):
        state = self.state()
        before = copy.deepcopy(state)
        result = export_dashboard(state, 'user.energy', {'title': 'Edited in UI'})
        self.assertEqual(result['next_step'], 'review user definition edit')
        result = export_dashboard(state, 'core.health', {'title': 'Edited in UI'})
        self.assertIn('override', result['next_step'])
        self.assertEqual(state, before)

    def test_additional_content_package_has_separate_pin(self):
        extension = {'schema_version': 1, 'name': 'media', 'version': '1.0.0', 'content_contract': 1,
                     'content': [{'id': 'media.dashboard', 'kind': 'dashboard', 'spec': {'title': 'Media'}}]}
        lock = make_lock([extension, self.package])
        state = resolve([self.package, extension], lock, self.deployment)
        self.assertIn('media.dashboard', [r['id'] for r in state['content']])
        with self.assertRaises(Conflict):
            resolve([self.package], lock, self.deployment)

    def test_duplicate_yaml_and_unknown_contract_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'bad.yaml'
            path.write_text('schema_version: 1\nschema_version: 2\n')
            with self.assertRaises(ValueError):
                read_document(path)
        self.deployment['schema_version'] = 2
        with self.assertRaises(Conflict):
            self.state()

    def test_homepage_settings_change_and_drift_are_visible(self):
        old = self.state()
        changed = {**self.deployment, 'homepage': {**self.deployment['homepage'], 'title': 'New title'}}
        new = self.state(deployment=changed)
        self.assertTrue(plan(old, old, new)['homepage_settings_change'])
        observed = copy.deepcopy(old)
        observed['homepage']['title'] = 'Runtime edit'
        self.assertEqual(plan(old, observed, new)['status'], 'blocked')

    def test_reference_defaults_have_owned_stable_ids(self):
        from local_observe.deployment.defaults import package
        product = package()
        deployment = {**self.deployment, 'content': [], 'overrides': []}
        state = resolve([product], make_lock([product]), deployment)
        self.assertEqual(len(state['content']), 6)
        self.assertEqual(len(render(state, deployment)), 9)

    def test_cli_render_and_conflict_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root/'lock.json'
            lock.write_text(json.dumps(make_lock([self.package])))
            command = [sys.executable, '-B', '-m', 'local_observe.deployment.cli', 'render',
                '--package', str(ROOT/'examples/deployment/core-v1.yaml'), '--lock', str(lock),
                '--deployment', str(ROOT/'examples/deployment/custom.yaml'), '--output', str(root/'out')]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)['deploy_authorized'])
            self.assertEqual(subprocess.run(command, cwd=ROOT, capture_output=True).returncode, 2)
            lock.write_text('{}')
            command[-1] = str(root/'invalid')
            self.assertEqual(subprocess.run(command, cwd=ROOT, capture_output=True).returncode, 2)
            self.assertFalse((root/'invalid').exists())

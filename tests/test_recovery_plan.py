import copy
import unittest
import tempfile
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import test_recovery as fixture
from local_observe.deployment.content import Conflict
from local_observe.deployment.recovery import bind_owners
from local_observe.deployment.runtime_bundle import artifact_hash, check_bundle, compare_bundles
from local_observe.deployment.rehearsal import preflight
from local_observe.inventory.validation import digest


def plan():
    return {'schema_version': 1, 'owners': [{'id': 'data', 'description': 'Fixture state',
        'recovery': 'backup-restore', 'procedure': 'Stop fixture and copy to new volume',
        'state_format': 'fixture-v1', 'verification': 'Read sentinel from restored copy',
        'writers': ['stage/db'], 'selectors': [
            {'project': 'stage', 'service': 'db', 'target': target, 'type': kind, 'sources': [source]}
            for target, kind, source in [('/data', 'volume', 'stage-data'), ('/config', 'bind', '/private/config'), ('$writable-layer', 'layer', '$container-layer')]]}],
        'external_owners': []}


def bundle(snapshot, owners):
    return {'schema_version': 1, 'scope': snapshot['scope'], 'product_revision': 'a'*40,
        'customisation_revision': 'b'*40, 'inventory_sha256': snapshot['sha256'],
        'recovery_plan_sha256': digest(owners), 'notification_safety_contract': 1,
        'services': {'stage/db': {'image_id': 'sha256:'+'b'*64,
            'effective_config_sha256': snapshot['containers'][0]['effective_config_sha256'],
            'artifacts': [{'path': '/compose.json', 'sha256': 'd'*64, 'kind': 'compose'}]}},
        'state_owners': {o['id']: {'format': o['state_format'], 'recovery': o['recovery'],
            'verification': o['verification']} for o in owners['owners']}}


class RecoveryPlanTests(unittest.TestCase):
    def test_cli_exposes_new_schemas_and_validates_runtime_bundle(self):
        from local_observe.deployment.cli import main
        for name in ('owner-plan', 'runtime-bundle'):
            output = io.StringIO()
            with patch('sys.argv', ['lo-deployment', 'schema', name]), redirect_stdout(output):
                self.assertEqual(main(), 0)
            self.assertEqual(json.loads(output.getvalue())['type'], 'object')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            actual, owners = fixture.snapshot(), plan()
            for name, data in [('inventory', actual), ('owners', owners), ('bundle', bundle(actual, owners))]:
                (root/(name+'.json')).write_text(json.dumps(data))
            command = ['lo-deployment', 'check-runtime']
            for name in ('inventory', 'owners', 'bundle'):
                command += ['--'+name, str(root/(name+'.json'))]
            with patch('sys.argv', command), redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)
    def test_artifact_tree_hashes_files_and_empty_directories_and_refuses_partial_reads(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = artifact_hash(root, root)
            (root/'empty').mkdir()
            self.assertNotEqual(artifact_hash(root, root), first)
            (root/'file').write_text('one')
            first = artifact_hash(root, root)
            (root/'file').write_text('two')
            self.assertNotEqual(artifact_hash(root, root), first)
            with self.assertRaises(Conflict): artifact_hash(root/'absent', root)
            with self.assertRaises(Conflict): artifact_hash(root, root, max_bytes=1)
            with patch('local_observe.deployment.runtime_bundle.os.walk', side_effect=PermissionError):
                with self.assertRaises(PermissionError): artifact_hash(root, root)

    def test_whole_stack_preflight_cannot_pass_without_per_owner_evidence(self):
        actual, owners = fixture.snapshot(), plan()
        pins = bundle(actual, owners)
        args = dict(previous_bundle=copy.deepcopy(pins), free_bytes=10*1024**3, required_copy_bytes=512*1024**2,
                    spare_memory_bytes=1024**3, requested_memory_bytes=512*1024**2,
                    restore_receipts={}, now=fixture.NOW)
        self.assertEqual(preflight(pins, actual, owners, **args)['status'], 'blocked')
        for change in ({'required_copy_bytes': 0}, {'requested_memory_bytes': True}):
            with self.assertRaises(Conflict): preflight(pins, actual, owners, **(args | change))
        result = preflight(pins, actual, owners, **(args | {'free_bytes': 0, 'spare_memory_bytes': 0}))
        self.assertEqual(len(result['reasons']), 3)

    def test_preflight_rejects_changes_against_previous_release(self):
        actual, owners = fixture.snapshot(), plan()
        pins = bundle(actual, owners)
        for change in ('format', 'scope', 'service'):
            previous = copy.deepcopy(pins)
            if change == 'format': previous['state_owners']['data']['format'] = 'older-format'
            if change == 'scope': previous['scope'] = 'another-scope'
            if change == 'service': previous['services']['stage/removed'] = previous['services']['stage/db']
            with self.subTest(change=change), self.assertRaises(Conflict):
                preflight(pins, actual, owners, previous_bundle=previous,
                    free_bytes=10*1024**3, required_copy_bytes=512*1024**2,
                    spare_memory_bytes=1024**3, requested_memory_bytes=512*1024**2,
                    restore_receipts={}, now=fixture.NOW)

    def test_owner_declarations_and_observed_effective_config_must_match(self):
        actual, owners = fixture.snapshot(), plan()
        for field in ('format', 'recovery', 'verification'):
            bad = bundle(actual, owners)
            bad['state_owners']['data'][field] = 'contradictory'
            with self.subTest(field=field), self.assertRaises(Conflict):
                check_bundle(bad, actual, owners)
        bad = bundle(actual, owners)
        bad['services']['stage/db']['effective_config_sha256'] = '0'*64
        with self.assertRaises(Conflict): check_bundle(bad, actual, owners)
        doc = fixture.document()
        doc['Config']['Env'] = ['CHANGED=configuration']
        changed = fixture.snapshot(doc)
        bad = bundle(actual, owners)
        bad['inventory_sha256'] = changed['sha256']
        with self.assertRaises(Conflict): check_bundle(bad, changed, owners)
    def test_stable_plan_rebinds_container_ids_not_unknown_mounts(self):
        first = fixture.snapshot()
        owners, report = bind_owners(plan(), first, now=fixture.NOW)
        self.assertEqual(report['status'], 'review-required')
        changed = copy.deepcopy(first)
        changed['containers'][0]['id'] = 'e'*64
        changed['sha256'] = digest({k:v for k,v in changed.items() if k != 'sha256'})
        rebound, _ = bind_owners(plan(), changed, now=fixture.NOW)
        self.assertNotEqual(owners['owners'][0]['resources'], rebound['owners'][0]['resources'])
        changed['containers'][0]['mounts'].append({'type': 'volume', 'source': 'new', 'target': '/unknown', 'writable': True})
        changed['sha256'] = digest({k:v for k,v in changed.items() if k != 'sha256'})
        self.assertEqual(bind_owners(plan(), changed, now=fixture.NOW)[1]['status'], 'blocked')
        changed = copy.deepcopy(first)
        changed['containers'][0]['mounts'][0]['source'] = '/substituted'
        changed['sha256'] = digest({k:v for k,v in changed.items() if k != 'sha256'})
        with self.assertRaises(Conflict): bind_owners(plan(), changed, now=fixture.NOW)

    def test_duplicate_missing_stale_and_external_owners_block(self):
        actual = fixture.snapshot()
        for modify in ('duplicate', 'missing'):
            candidate = plan()
            if modify == 'duplicate':
                candidate['owners'][0]['selectors'].append(candidate['owners'][0]['selectors'][0])
            else:
                candidate['owners'][0]['selectors'][0]['target'] = '/absent'
            with self.assertRaises(Conflict):
                bind_owners(candidate, actual, now=fixture.NOW)
        with self.assertRaises(Conflict):
            bind_owners(plan(), actual, now=fixture.NOW+61)
        candidate = plan()
        candidate['external_owners'] = [{'id': 'witness', 'host': 'other-host', 'path': '/state',
            'recovery': 'backup-restore', 'procedure': 'verified copy', 'verification': 'sentinel', 'observed': False}]
        self.assertEqual(bind_owners(candidate, actual, now=fixture.NOW)[1]['status'], 'blocked')

    def test_bundle_coverage_mismatch_and_downgrade_fail(self):
        actual, owners = fixture.snapshot(), plan()
        good = bundle(actual, owners)
        self.assertFalse(check_bundle(good, actual, owners)['deploy_authorized'])
        for change in ('service', 'owner', 'image', 'compose', 'safety'):
            bad = copy.deepcopy(good)
            if change == 'service': bad['services']['unobserved/db'] = bad['services']['stage/db']
            if change == 'owner': bad['state_owners']['extra'] = bad['state_owners']['data']
            if change == 'image': bad['services']['stage/db']['image_id'] = 'sha256:'+'0'*64
            if change == 'compose': bad['services']['stage/db']['artifacts'][0]['kind'] = 'config'
            if change == 'safety': bad['notification_safety_contract'] = 2
            with self.assertRaises(Conflict): check_bundle(bad, actual, owners)
        changed = copy.deepcopy(good)
        changed['state_owners']['data']['format'] = 'fixture-v2'
        with self.assertRaises(Conflict): compare_bundles(good, changed)
        changed = copy.deepcopy(good)
        changed['notification_safety_contract'] = 0
        self.assertEqual(check_bundle(changed, actual, owners)['status'], 'blocked')
        with self.assertRaises(Conflict): compare_bundles(good, changed)

    def test_missing_mounted_source_pin_is_not_complete(self):
        actual, owners = fixture.snapshot(), plan()
        owners['owners'][0]['recovery'] = 'rebuild'
        candidate = bundle(actual, owners)
        with self.assertRaises(Conflict): check_bundle(candidate, actual, owners)
        candidate['services']['stage/db']['artifacts'].append({'path': '/private/config', 'sha256': 'e'*64, 'kind': 'config'})
        self.assertEqual(check_bundle(candidate, actual, owners)['status'], 'review-required')

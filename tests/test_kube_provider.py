"""The Kubernetes source: an injected listing, a pinned field allowlist, and pod instance identity."""
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import discovery, kube_provider
from local_observe.inventory.kube_provider import KubeProvider
from local_observe.inventory.validation import InvalidInventory, observed, read_document, timestamp

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
POD_UID = '6b1f1a3c-2f4d-4a5b-8c9d-0e1f2a3b4c5d'
OTHER_UID = '9c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f'
DECLARED_HOST_IP = '10.11.0.21'   # the address probe-1 owns in examples/inventory/declared.yaml
JUNK_MARKERS = ('annotation-marker', 'env-marker', 'exec-marker', 'pull-marker', 'volume-marker',
                'sa-marker', 'digest-marker', 'resourceVersion', 'ownerReferences', 'nodeSelector',
                'tolerations', 'restartCount')


def pod(name='web-7d9d4c8f5-a1b2c', namespace='demo', uid=POD_UID, node='probe-1', phase='Running',
        pod_ip=DECLARED_HOST_IP, images=('registry.example.invalid/demo/api:1.4.0',), resource_id=None):
    """Build one pod object in the shape `kubectl get pods -o json` produces, plus its junk.

    The junk is the point: every field below is real Kubernetes payload that a discovery source
    could copy, and each one carries a marker so a test can prove it never reached the snapshot.
    """
    labels = {'app': 'web'}
    if resource_id is not None:
        labels[kube_provider.RESOURCE_ID_LABEL] = resource_id
    return {
        'apiVersion': 'v1', 'kind': 'Pod',
        'metadata': {'name': name, 'namespace': namespace, 'uid': uid, 'labels': labels,
                     'annotations': {'token.example/leak': 'annotation-marker'},
                     'ownerReferences': [{'kind': 'ReplicaSet', 'name': 'web-7d9d4c8f5'}],
                     'resourceVersion': '88213'},
        'spec': {'nodeName': node, 'serviceAccountName': 'sa-marker',
                 'containers': [{'name': 'api', 'image': image,
                                 'env': [{'name': 'API_PASSWORD', 'value': 'env-marker'}],
                                 'command': ['exec-marker']} for image in images],
                 'imagePullSecrets': [{'name': 'pull-marker'}],
                 'volumes': [{'name': 'tls', 'secret': {'secretName': 'volume-marker'}}],
                 'nodeSelector': {'disktype': 'ssd'}, 'tolerations': [{'key': 'role', 'value': 'sa-marker'}]},
        'status': {'phase': phase, 'podIP': pod_ip,
                   'containerStatuses': [{'imageID': 'sha256:digest-marker', 'restartCount': 3}]},
    }


def listing(*items):
    """Wrap pods in a PodList envelope whose own fields a reader must not be able to reach."""
    return {'apiVersion': 'v1', 'kind': 'PodList', 'metadata': {'resourceVersion': '1'}, 'items': list(items)}


def read(*pods, now=NOW, source='kube-demo'):
    return KubeProvider(source=source, listing=listing(*pods), now=now)


class KubeFieldAllowlistTests(unittest.TestCase):
    def test_the_allowlist_is_pinned_so_widening_it_is_a_review(self):
        """One more key here means one more thing copied out of someone's cluster."""
        self.assertEqual(kube_provider.KUBE_FIELDS, {
            'name': ('metadata', 'name'),
            'namespace': ('metadata', 'namespace'),
            'uid': ('metadata', 'uid'),
            'node': ('spec', 'nodeName'),
            'phase': ('status', 'phase'),
            'pod_ip': ('status', 'podIP'),
            'resource_id': ('metadata', 'labels', kube_provider.RESOURCE_ID_LABEL),
        })
        self.assertEqual(kube_provider.IMAGES_PATH, ('spec', 'containers'))

    def test_every_field_the_allowlist_drops_stays_out_of_the_snapshot(self):
        result = read(pod()).snapshot()
        observed(result, NOW)
        body = json.dumps(result)
        for marker in JUNK_MARKERS:
            with self.subTest(marker=marker):
                self.assertNotIn(marker, body)
        item = result['observations'][0]
        self.assertEqual(sorted(item['attributes']), ['discovered_by', 'images', 'namespace', 'node', 'phase'])
        self.assertEqual(item['attributes'], {'discovered_by': 'kubernetes', 'namespace': 'demo',
                                             'node': 'probe-1', 'phase': 'Running',
                                             'images': 'registry.example.invalid/demo/api:1.4.0'})
        self.assertEqual(item['aliases'], [{'type': 'service.name', 'scope': 'demo',
                                           'value': 'web-7d9d4c8f5-a1b2c'},
                                          {'type': 'ip', 'value': DECLARED_HOST_IP}])
        self.assertEqual(item['evidence'], ['kube:demo/web-7d9d4c8f5-a1b2c', 'kube-uid:' + POD_UID])
        self.assertEqual(item['kind'], 'service')
        self.assertEqual(item['name'], 'demo/web-7d9d4c8f5-a1b2c')

    def test_the_envelope_carries_nothing_into_the_snapshot(self):
        noisy = listing(pod())
        noisy['metadata'] = {'annotations': {'leak': 'annotation-marker'}, 'name': 'envelope-marker'}
        noisy['selfLink'] = 'https://cluster.example.invalid/api/v1/pods'
        result = KubeProvider(source='kube-demo', listing=noisy, now=NOW).snapshot()
        observed(result, NOW)
        self.assertNotIn('envelope-marker', json.dumps(result))
        self.assertNotIn('cluster.example.invalid', json.dumps(result))

    def test_two_pods_are_two_observations_and_both_validate(self):
        result = read(pod(), pod(name='worker-5f8a9-b9c3d', namespace='batch',
                                pod_ip='10.11.0.24')).snapshot()
        observed(result, NOW)
        self.assertEqual(len(result['observations']), 2)
        self.assertEqual([item['name'] for item in result['observations']],
                         ['demo/web-7d9d4c8f5-a1b2c', 'batch/worker-5f8a9-b9c3d'])


class KubeInstanceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name)/'observations.db'

    def test_a_recreated_pod_is_a_new_instance_and_carries_its_own_evidence(self):
        first = read(pod()).observe()[0]
        second = read(pod(name='web-7d9d4c8f5-zz9yy', uid=OTHER_UID)).observe()[0]
        self.assertNotEqual(first.observation_id, second.observation_id)
        self.assertNotEqual(first.name, second.name)
        self.assertNotIn('kube-uid:' + OTHER_UID, first.evidence)
        self.assertIn('kube-uid:' + OTHER_UID, second.evidence)

    def test_a_restarted_pod_keeps_its_instance_identity(self):
        self.assertEqual(read(pod(phase='Running')).observe()[0].observation_id,
                         read(pod(phase='Running')).observe()[0].observation_id)

    def test_a_gone_pod_is_not_removed_and_a_partial_source_may_not_claim_it_is_gone(self):
        discovery.ingest(self.db, read(pod()).snapshot(), now=NOW)
        later = NOW.replace(minute=30)
        discovery.ingest(self.db, read(pod(name='web-7d9d4c8f5-zz9yy'), now=later).snapshot(), now=later)
        report = discovery.ageing(self.db, 'kube-demo', now=later, grace_seconds=60)
        self.assertEqual((report['status'], report['reason'], report['aged_out']),
                         ('coverage_incomplete', 'newest_snapshot_partial', []))
        self.assertEqual(len(discovery.history(self.db, 'kube-demo')), 2, 'append-only: nothing was deleted')
        aged = discovery.history(self.db, 'kube-demo')[1]['observations']
        self.assertEqual([item['name'] for item in aged], ['demo/web-7d9d4c8f5-a1b2c'],
                         'the first listing is still readable, with its own observed_at')


class KubeRefusalTests(unittest.TestCase):
    def refuse(self, document):
        with self.assertRaises(InvalidInventory) as caught:
            KubeProvider(source='kube-demo', listing=document, now=NOW).snapshot()
        return str(caught.exception)

    def test_an_item_without_a_name_is_refused_by_position_never_by_value(self):
        broken = pod()
        broken['metadata']['name'] = ''
        broken['spec']['containers'][0]['env'][0]['value'] = 'quoted-secret-marker'
        message = self.refuse(listing(broken, pod()))
        self.assertIn('item 0', message)
        self.assertNotIn('quoted-secret-marker', message)

    def test_a_non_object_item_is_refused(self):
        self.assertIn('item 1', self.refuse(listing(pod(), 'not-a-pod')))

    def test_a_listing_without_items_is_refused(self):
        self.assertIn('items', self.refuse({'kind': 'PodList'}))
        with self.assertRaises(InvalidInventory):
            KubeProvider(source='kube-demo', listing={'items': {'not': 'a list'}}, now=NOW)
        with self.assertRaises(InvalidInventory):
            KubeProvider(source='kube-demo', listing=[], now=NOW)

    def test_an_oversized_listing_is_refused_before_any_observation(self):
        many = [pod(name='p' + str(row)) for row in range(kube_provider.MAX_ITEMS + 1)]
        self.assertIn('bound', self.refuse(listing(*many)))

    def test_a_bad_source_name_is_refused(self):
        with self.assertRaises(InvalidInventory):
            read(pod(), source='Kube Demo')

    def test_a_mistyped_container_list_does_not_break_the_read(self):
        broken = pod()
        broken['spec']['containers'] = 'mistakenly-a-string'
        self.assertEqual(read(broken).observe()[0].attributes['images'], '')
        broken['spec']['containers'] = [3, None, {'no_image': True}]
        self.assertEqual(read(broken).observe()[0].attributes['images'], '')

    def test_an_overlong_image_list_is_bounded_so_the_snapshot_stays_valid(self):
        wide = read(pod(images=['registry.example.invalid/a' + str(row) + ':latest' for row in range(200)]))
        result = wide.snapshot()
        observed(result, NOW)
        images = result['observations'][0]['attributes']['images']
        self.assertLessEqual(len(images), kube_provider.MAX_IMAGES)
        self.assertTrue(images.startswith('registry.example.invalid/a0:latest'))


class KubeFieldFallbackTests(unittest.TestCase):
    def test_an_unusable_pod_ip_never_becomes_an_alias(self):
        for bad in ('not-an-address', '10.11.0.256', '10.11.0.1/32'):
            with self.subTest(pod_ip=bad):
                item = read(pod(pod_ip=bad)).observe()[0]
                self.assertEqual([alias['type'] for alias in item.aliases], ['service.name'])
                self.assertIn('kube-pod-ip-unusable', item.evidence)

    def test_a_missing_pod_ip_simply_has_no_ip_alias(self):
        blank = pod()
        blank['status'].pop('podIP')
        item = read(blank).observe()[0]
        self.assertEqual([alias['type'] for alias in item.aliases], ['service.name'])
        self.assertNotIn('kube-pod-ip-unusable', item.evidence)

    def test_the_resource_uuid_label_is_echoed_only_when_it_is_a_uuid(self):
        self.assertEqual(read(pod(resource_id=POD_UID)).observe()[0].resource_id, POD_UID)
        for bad in ('res-6b1f1a3c', POD_UID.upper(), 'not-a-uuid'):
            with self.subTest(label=bad):
                item = read(pod(resource_id=bad)).observe()[0]
                self.assertIsNone(item.resource_id)
                self.assertIn('kube-resource-id-unusable', item.evidence)

    def test_the_absence_of_the_label_is_not_reported_as_an_unusable_one(self):
        item = read(pod(resource_id='')).observe()[0]
        self.assertIsNone(item.resource_id)
        self.assertNotIn('kube-resource-id-unusable', item.evidence)

    def test_a_missing_namespace_is_labelled_default_not_guessed_at(self):
        blank = pod()
        blank['metadata'].pop('namespace')
        item = read(blank).observe()[0]
        self.assertEqual(item.attributes['namespace'], 'default')
        self.assertEqual(item.aliases[0]['scope'], 'default')
        self.assertEqual(item.name, 'default/web-7d9d4c8f5-a1b2c')

    def test_no_scope_is_invented_and_no_coverage_is_claimed(self):
        result = read(pod()).snapshot()
        self.assertEqual(result['scope'], [], 'scope is declared UUIDs this source may expect')
        self.assertFalse(result['complete'], 'a namespace listing is not a claim that nothing else exists')


class KubeExampleShapeTests(unittest.TestCase):
    def test_the_provider_output_matches_the_shape_the_committed_example_ships(self):
        """The example is what a reader copies, so the provider and the example must not drift."""
        fixture = read_document(ROOT/'examples/inventory/observed.yaml')
        result = read(pod()).snapshot()
        self.assertEqual(set(result) - {'snapshot_id', 'observed_at', 'source'},
                          set(fixture) - {'snapshot_id', 'observed_at', 'source'})
        self.assertEqual(sorted(result['observations'][0]), sorted(fixture['observations'][1]),
                         'a service observation must carry the same keys as the shipped example')
        self.assertIn('discovered_by', result['observations'][0]['attributes'],
                      'every observation says which source produced it')


if __name__ == '__main__':
    unittest.main()

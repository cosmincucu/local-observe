import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index, logicmonitor
from local_observe.inventory.logicmonitor import ExportError, load_config, plan

PREFIX = 'lo.'


def resource(rid, name, *, hostnames=(), ips=(), kind='host', owner=None, **attributes):
    return {'id': rid, 'kind': kind, 'name': name, 'owner': owner, 'attributes': attributes,
            'aliases': [{'scope': '', 'type': 'hostname', 'value': h} for h in hostnames]
            + [{'scope': '', 'type': 'ip', 'value': i} for i in ips]}


def device(did, display, name=None, props=None, device_type=0):
    return {'id': did, 'displayName': display, 'name': name or display, 'deviceType': device_type,
            'customProperties': [{'name': k, 'value': v} for k, v in (props or {}).items()]}


def config(**overrides):
    document = {'schema_version': 1, 'portal': 'example', 'attributes': ['presence', 'monitoring']}
    document.update(overrides)
    return load_config(document)


R1 = '11111111-1111-4111-8111-111111111111'
R2 = '22222222-2222-4222-8222-222222222222'
R3 = '33333333-3333-4333-8333-333333333333'


class Matching(unittest.TestCase):
    def test_claimed_device_is_updated_only_where_properties_differ(self):
        result = plan([resource(R1, 'host-01', presence='always-on', monitoring='priority')],
                      [device(7, 'host-01', props={'lo.resource_id': R1, 'lo.kind': 'host',
                                                   'lo.presence': 'always-on', 'lo.monitoring': 'standard'})],
                      config())
        self.assertEqual(result['actions'], [{'op': 'update', 'device_id': 7, 'resource_id': R1,
                                              'from_display_name': 'host-01', 'display_name': None,
                                              'properties': {'lo.monitoring': 'priority'}}])

    def test_an_in_sync_device_produces_no_action(self):
        props = {'lo.resource_id': R1, 'lo.kind': 'host', 'lo.presence': 'always-on'}
        result = plan([resource(R1, 'host-01', presence='always-on')], [device(7, 'host-01', props=props)], config())
        self.assertEqual((result['actions'], result['summary']['unchanged']), ([], 1))

    def test_adopts_by_normalised_name_and_renames(self):
        result = plan([resource(R1, 'Core Switch 24')],
                      [device(9, 'CoreSwitch24.example.invalid')], config())
        action = result['actions'][0]
        self.assertEqual((action['op'], action['device_id'], action['display_name']), ('adopt', 9, 'Core Switch 24'))
        self.assertEqual(action['properties']['lo.resource_id'], R1)

    def test_adopts_by_fixed_address_alias(self):
        result = plan([resource(R1, 'host-01', ips=['198.51.100.10'])], [device(3, '198.51.100.10')], config())
        self.assertEqual(result['actions'][0]['op'], 'adopt')

    def test_a_dhcp_address_alone_is_never_adopted(self):
        result = plan([resource(R1, 'tablet', ip_observed='198.51.100.20')], [device(4, '198.51.100.20')], config())
        self.assertEqual(result['actions'], [])
        self.assertIn('DHCP', result['review'][0]['reason'])

    def test_two_candidate_devices_are_ambiguous(self):
        result = plan([resource(R1, 'host-01', ips=['198.51.100.10'])],
                      [device(1, 'host-01'), device(2, '198.51.100.10')], config())
        self.assertEqual((result['actions'], result['review'][0]['candidates']), ([], [1, 2]))

    def test_one_device_matched_by_two_resources_is_adopted_by_neither(self):
        result = plan([resource(R1, 'phone', hostnames=['phone']), resource(R2, 'Phone')],
                      [device(5, 'phone.example.invalid')], config())
        self.assertEqual(result['actions'], [])
        self.assertEqual(len(result['review']), 2)

    def test_orphan_claims_are_reported_and_left_alone(self):
        result = plan([], [device(6, 'gone', props={'lo.resource_id': R3})], config())
        self.assertEqual((result['actions'], result['orphans'][0]['device_id']), ([], 6))

    def test_non_regular_devices_are_never_matched(self):
        result = plan([resource(R1, 'website')], [device(8, 'website', device_type=18)], config())
        self.assertEqual(result['actions'], [])

    def test_a_dotted_display_name_is_not_cut_at_the_dot(self):
        result = plan([resource(R1, 'Garage Switch 2.5G')], [device(9, 'GarageSwitch25G.example.invalid')], config())
        self.assertEqual(result['actions'][0]['device_id'], 9)

    def test_an_operator_pin_adopts_a_dhcp_only_match(self):
        result = plan([resource(R1, 'tablet', ip_observed='198.51.100.20')], [device(4, '198.51.100.20')],
                      config(adopt={R1: 4}))
        self.assertEqual((result['actions'][0]['op'], result['review']), ('adopt', []))

    def test_a_pin_to_an_unavailable_device_is_reviewed(self):
        result = plan([resource(R1, 'tablet')], [device(4, 'x', props={'lo.resource_id': R2})],
                      config(adopt={R1: 4}))
        self.assertEqual(result['actions'], [])
        self.assertIn('pinned', result['review'][0]['reason'])

    def test_rename_is_skipped_when_the_name_is_taken(self):
        result = plan([resource(R1, 'host-01', ips=['198.51.100.10'])],
                      [device(1, '198.51.100.10'), device(2, 'host-01', props={'lo.resource_id': R3})], config())
        self.assertIsNone(result['actions'][0]['display_name'])
        self.assertIn('already used', result['notes'][0]['note'])


class Creation(unittest.TestCase):
    def test_creation_is_off_by_default(self):
        result = plan([resource(R1, 'host-01', hostnames=['host-01'])], [], config())
        self.assertEqual(result['not_created'][0]['reason'], 'creation disabled')

    def test_eligible_resource_is_created_with_its_properties(self):
        cfg = config(create={'enabled': True, 'collector_id': 4, 'host_group_ids': [2, 3],
                             'dns_suffix': 'example.invalid', 'when': {'monitoring': ['priority']}})
        result = plan([resource(R1, 'host-01', hostnames=['host-01'], monitoring='priority'),
                       resource(R2, 'tv', monitoring='inventory-only', ip_observed='198.51.100.30')], [], cfg)
        create = [a for a in result['actions'] if a['op'] == 'create']
        self.assertEqual(len(create), 1)
        payload = create[0]['payload']
        self.assertEqual((payload['name'], payload['preferredCollectorId'], payload['hostGroupIds']),
                         ('host-01.example.invalid', 4, '2,3'))
        self.assertIn({'name': 'lo.resource_id', 'value': R1}, payload['customProperties'])
        self.assertEqual(result['not_created'][0]['reason'], 'not eligible under create.when')


class Configuration(unittest.TestCase):
    def test_the_shipped_example_loads(self):
        root = Path(__file__).resolve().parents[1]
        loaded = load_config(json.loads((root / 'examples/inventory/logicmonitor-export.json').read_text()))
        self.assertFalse(loaded['create']['enabled'])

    def test_rejects_unknown_keys_and_missing_collector(self):
        with self.assertRaises(ExportError):
            load_config({'schema_version': 1, 'portal': 'example', 'surprise': 1})
        with self.assertRaises(ExportError):
            load_config({'schema_version': 1, 'portal': 'example', 'create': {'enabled': True}})
        with self.assertRaises(ExportError):
            load_config({'schema_version': 1, 'portal': 'Example.logicmonitor.com'})


class FakeClient:
    def __init__(self, pages=None):
        self.calls, self.pages = [], pages or []

    def request(self, method, path, payload=None, *, headers=None):
        self.calls.append((method, path, payload, headers))
        if method == 'GET':
            return 200, self.pages.pop(0)
        if method == 'POST':
            return 200, {'id': 99}
        return 200, {}


class Transport(unittest.TestCase):
    def test_fetch_reads_every_page_with_version_three(self):
        client = FakeClient([{'total': 1001, 'items': [device(1, 'a')] * 1000}, {'total': 1001, 'items': [device(2, 'b')]}])
        self.assertEqual(len(logicmonitor.fetch_devices(client)), 1001)
        self.assertTrue(all(call[3] == {'X-Version': '3'} for call in client.calls))

    def test_apply_patches_with_replace_and_creates(self):
        client = FakeClient()
        document = {'actions': [
            {'op': 'adopt', 'device_id': 3, 'resource_id': R1, 'display_name': 'host-01',
             'properties': {'lo.resource_id': R1}},
            {'op': 'create', 'resource_id': R2, 'payload': {'name': 'x', 'displayName': 'x'}}]}
        result = logicmonitor.apply(client, document, max_changes=5)
        self.assertEqual((result['status'], result['applied']), ('applied', 2))
        method, path, payload, _ = client.calls[0]
        self.assertEqual(method, 'PATCH')
        self.assertIn('opType=replace', path)
        self.assertEqual(payload['displayName'], 'host-01')
        self.assertFalse(any(call[0] == 'DELETE' for call in client.calls))

    def test_apply_refuses_a_plan_above_the_change_limit(self):
        with self.assertRaises(ExportError):
            logicmonitor.apply(FakeClient(), {'actions': [{'op': 'create'}] * 3}, max_changes=2)


class IndexRead(unittest.TestCase):
    def test_reads_resources_and_aliases_from_a_built_index(self):
        document = {'schema_version': 1, 'resources': [
            {'id': R1, 'kind': 'host', 'name': 'host-01', 'owner': 'ops',
             'aliases': [{'type': 'hostname', 'value': 'host-01'}, {'type': 'ip', 'value': '198.51.100.10'}],
             'attributes': {'presence': 'always-on'}, 'relations': []}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'inventory.db'
            index.build(document, path, 'test')
            with index.readonly(path) as connection:
                resources = logicmonitor.read_resources(connection)
        self.assertEqual(resources[0]['owner'], 'ops')
        self.assertEqual(json.dumps(sorted(a['type'] for a in resources[0]['aliases'])), '["hostname", "ip"]')


if __name__ == '__main__':
    unittest.main()

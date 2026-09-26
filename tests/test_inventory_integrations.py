import base64
import copy
import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from local_observe.http import JsonClient, TransportError
from local_observe.inventory.docker_provider import snapshot
from local_observe.inventory.forge import ForgeError, publish
from local_observe.inventory.validation import InvalidInventory, read_document, observed, timestamp

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')


class FakeForge:
    def __init__(self):
        self.base = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.document = copy.deepcopy(self.base)
        self.pulls, self.calls = [], []
        self.branch = None
        self.lose_pr_ack = False

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method == 'GET' and '/pulls?' in path:
            return 200, self.pulls
        if method == 'GET' and '/branches/' in path:
            if path.endswith('/main') or self.branch:
                return 200, {'commit': {'id': 'abc123'}}
            return 404, None
        if method == 'POST' and path.endswith('/branches'):
            self.branch = payload['new_branch_name']
            return 201, {'commit': {'id': 'abc123'}}
        if method == 'GET' and '/contents/' in path:
            return 200, {'sha': 'sha-before', 'content': base64.b64encode(json.dumps(self.document).encode()).decode()}
        if method == 'PUT':
            self.document = json.loads(base64.b64decode(payload['content']))
            return 200, {}
        if method == 'POST' and path.endswith('/pulls'):
            pull = {'number': 1, 'html_url': 'https://forge.example.test/review/1', 'body': payload['body'],
                    'head': {'ref': payload['head']}, 'base': {'ref': payload['base']}}
            self.pulls.append(pull)
            if self.lose_pr_ack:
                raise TransportError('lost acknowledgement')
            return 201, pull
        raise AssertionError((method, path))


class IntegrationTests(unittest.TestCase):
    def proposal(self):
        return {'status': 'needs_review', 'proposal_id': 'a' * 64, 'resource': {
            'id': '2e75aacb-76ac-490a-8dfa-de5137f73747', 'kind': 'service', 'name': 'new-service',
            'aliases': [{'type': 'service.name', 'scope': 'demo', 'value': 'new-service'}],
            'attributes': {}, 'relations': []}}

    def test_pr_only_idempotent(self):
        forge = FakeForge()
        first = publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', self.proposal())
        second = publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', self.proposal())
        self.assertEqual(first['status'], 'created')
        self.assertEqual(second['status'], 'existing')
        self.assertEqual(len(forge.document['resources']), 3)
        self.assertEqual(len(forge.pulls), 1)
        writes = [call for call in forge.calls if call[0] == 'PUT']
        self.assertEqual(len(writes), 1)
        self.assertTrue(writes[0][2]['branch'].startswith('local-observe/discovery/'))

    def test_lost_pr_ack_reconciles(self):
        forge = FakeForge()
        forge.lose_pr_ack = True
        with self.assertRaises(TransportError):
            publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', self.proposal())
        self.assertEqual(publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', self.proposal())['status'], 'existing')
        self.assertEqual(len(forge.pulls), 1)

    def test_reminted_uuid_cannot_open_second_pr_for_same_observation(self):
        forge = FakeForge()
        proposal = self.proposal()
        publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', proposal)
        proposal['resource']['id'] = '2f5f7a69-0e3c-43a1-978e-46bda5e84d4c'
        with self.assertRaises(ForgeError):
            publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', proposal)
        self.assertEqual(len(forge.pulls), 1)

    def test_conflicting_alias_does_not_write_declaration(self):
        forge = FakeForge()
        proposal = self.proposal()
        proposal['resource']['aliases'] = forge.document['resources'][0]['aliases']
        with self.assertRaises(InvalidInventory):
            publish(forge, 'owner/repo', 'main', 'inventory/declared.yaml', proposal)
        self.assertFalse(any(call[0] == 'PUT' for call in forge.calls))

    def test_forge_scope_and_transport_security(self):
        with self.assertRaises(ForgeError):
            publish(FakeForge(), 'owner/repo', 'main', '../DECISIONS.yaml', self.proposal())
        for url in ('http://forge.example.test', 'https://token@forge.example.test', 'https://forge.example.test?token=a'):
            with self.assertRaises(TransportError):
                JsonClient(url, 'a' * 32)

    def test_rootless_discovery_selects_service_fields(self):
        def docker(args, **kwargs):
            if args[1] == 'info':
                body = {'DockerRootDir': '/stage/docker', 'SecurityOptions': ['name=rootless']}
            elif args[1] == 'ps':
                return SimpleNamespace(returncode=0, stdout='a' * 12)
            else:
                self.assertNotIn('.Config.Env', args[3])
                body = {'id': 'a' * 64, 'state': 'running', 'project': 'demo', 'service': 'api', 'resource_id': ''}
            return SimpleNamespace(returncode=0, stdout=json.dumps(body))
        with patch('local_observe.inventory.docker_provider.subprocess.run', side_effect=docker):
            result = snapshot(['demo'], source='docker-stage', socket='/run/user/1001/docker.sock', expected_root='/stage/docker', now=NOW)
        observed(result, NOW)
        self.assertFalse(result['complete'])
        self.assertEqual(result['observations'][0]['attributes']['running_replicas'], 1)

    def test_production_socket_refused(self):
        with self.assertRaises(InvalidInventory):
            snapshot(['demo'], source='docker', socket='/var/run/docker.sock', expected_root='/var/lib/docker')

    def test_new_inventory_file_is_only_created_on_review_branch(self):
        class EmptyForge(FakeForge):
            def request(self, method, path, payload=None):
                if method == 'GET' and '/contents/' in path:
                    return 404, None
                if method == 'POST' and '/contents/' in path:
                    self.calls.append((method, path, payload))
                    self.document = json.loads(base64.b64decode(payload['content']))
                    return 201, {}
                return super().request(method, path, payload)
        forge = EmptyForge()
        # The filename is a synthetic value: staging inventory out moved the real staging declaration out of this
        # repository, and what this test pins is that a not-yet-existing path is created only on a
        # review branch, which holds for any legal name.
        result = publish(forge, 'owner/repo', 'main', 'inventory/discovered.yaml', self.proposal())
        self.assertEqual(result['status'], 'created')
        self.assertEqual(len(forge.document['resources']), 1)
        create = next(item for item in forge.calls if item[0] == 'POST' and '/contents/' in item[1])
        self.assertNotEqual(create[2]['branch'], 'main')

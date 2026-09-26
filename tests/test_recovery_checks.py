import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from conformance_backup import VOLUMES, restore_model
from conformance_coverage import retention


class RecoveryChecks(unittest.TestCase):
    def test_store_collector_receives_shutdown_signals(self):
        path = Path(__file__).resolve().parents[1] / 'components/data/store-signoz/compose.yaml'
        model = yaml.safe_load(path.read_text())
        command = '\n'.join(model['services']['signoz-otel-collector']['command'])
        self.assertIn('exec /signoz-otel-collector --config=', command)

    def model(self):
        return {'name': 'local-observe-demo', 'volumes': {x: {'name': 'local-observe-demo_' + x} for x in VOLUMES},
                'networks': {'default': {'name': 'local-observe-demo_default'}},
                'services': {'signoz': {'ports': [{'target': 8080, 'published': '18081', 'host_ip': '127.0.0.1'}]}}}

    def test_restore_has_distinct_network_volumes_and_ports(self):
        source = self.model()
        before = copy.deepcopy(source)
        with tempfile.TemporaryDirectory() as directory:
            model = restore_model(source, Path(directory), 'local-observe-demo-restore-test')
        self.assertEqual(source, before)
        self.assertEqual(model['networks']['default']['name'], 'local-observe-demo-restore-test_default')
        for name, value in model['volumes'].items():
            self.assertEqual(value['name'], 'local-observe-demo-restore-test_' + name)
        self.assertEqual(model['services']['signoz']['ports'][0]['published'], '28081')

    def test_external_network_and_volume_are_rejected(self):
        for section, name in [('networks', 'default'), ('volumes', 'agent-state')]:
            source = self.model()
            source[section][name]['external'] = True
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                restore_model(source, Path(directory), 'local-observe-demo-restore-test')

    def test_writable_bind_is_rejected(self):
        source = self.model()
        source['services']['signoz']['volumes'] = [{'type': 'bind', 'source': '/unapproved', 'target': '/data'}]
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            restore_model(source, Path(directory), 'local-observe-demo-restore-test')

    def test_retention_uses_bounded_tuple_partitions_and_resumes_merges(self):
        demo = Mock(run='a' * 32)
        demo.query.side_effect = ['1', '0'] * 3
        retention(demo)
        statements = [call.args[-1] for call in demo.compose.call_args_list]
        materialize = [sql for sql in statements if 'MATERIALIZE TTL' in sql]
        self.assertEqual(len(materialize), 3)
        self.assertTrue(all('IN PARTITION tuple(' in sql for sql in materialize))
        self.assertEqual(sum(sql.startswith('SYSTEM START TTL MERGES') for sql in statements), 3)

    def test_retention_resumes_merges_on_insert_failure(self):
        demo = Mock(run='a' * 32)
        demo.compose.side_effect = ['', RuntimeError('test failure'), '']
        with self.assertRaises(RuntimeError):
            retention(demo)
        self.assertTrue(demo.compose.call_args.args[-1].startswith('SYSTEM START TTL MERGES'))


if __name__ == '__main__':
    unittest.main()

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('rehearse_witness', ROOT / 'scripts/rehearse_witness.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class WitnessRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.handoff = self.root / 'handoff'
        self.handoff.mkdir()
        self.state = {'last_check': '2026-09-07T12:00:00Z', 'failed_since': None, 'incident_id': None, 'pending': []}
        self.write()

    def write(self):
        data = json.dumps(self.state).encode()
        (self.handoff / 'witness-state.json').write_bytes(data)
        self.receipt = {'schema_version': 1, 'state_sha256': hashlib.sha256(data).hexdigest(),
                        'state_bytes': len(data), 'credentials_read': False, 'service_changed': False,
                        'pending_count': len(self.state['pending']), 'unit_sha256': 'a' * 64}
        (self.handoff / 'report.json').write_text(json.dumps(self.receipt))

    def test_restore_replay_is_offline_and_preserves_handoff(self):
        before = (self.handoff / 'witness-state.json').read_bytes()
        with patch('socket.socket', side_effect=AssertionError('No sockets permitted')):
            result = module.rehearse(self.handoff, self.root / 'rehearsal')
        self.assertTrue(result['copied_state_replay_passed'])
        self.assertEqual(result['local_attempts'], 3)
        self.assertEqual(result['distinct_deliveries'], 2)
        self.assertFalse(result['live_restart_proven'])
        self.assertEqual(before, (self.handoff / 'witness-state.json').read_bytes())
        with self.assertRaises(FileExistsError):
            module.rehearse(self.handoff, self.root / 'rehearsal')

    def test_changed_or_nonhealthy_snapshot_refused_before_output(self):
        for key, value in [('state_sha256', '0' * 64), ('credentials_read', True), ('service_changed', True)]:
            bad = dict(self.receipt, **{key: value})
            (self.handoff / 'report.json').write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                module.rehearse(self.handoff, self.root / 'bad')
            self.assertFalse((self.root / 'bad').exists())
        self.state['incident_id'] = 'unresolved'
        self.write()
        with self.assertRaisesRegex(ValueError, 'healthy'):
            module.rehearse(self.handoff, self.root / 'bad')
        self.assertFalse((self.root / 'bad').exists())

    def test_output_cannot_replace_or_live_inside_handoff(self):
        for output in (self.root, self.handoff, self.handoff / 'nested'):
            with self.assertRaises(ValueError):
                module.rehearse(self.handoff, output)

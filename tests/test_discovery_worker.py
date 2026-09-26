import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from local_observe.inventory.index import build
from local_observe.inventory.validation import read_document, timestamp
from local_observe.inventory.worker import tick

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')


class DiscoveryWorkerTests(unittest.TestCase):
    def test_snapshot_retry_and_proposal_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build(read_document(ROOT/'examples/inventory/declared.yaml'), root/'index.db', 'test', now=NOW)
            snapshot = read_document(ROOT/'examples/inventory/observed.yaml')
            config = {'state': str(root/'state'), 'index': str(root/'index.db'),
                      'proposal_allowlist': ['new-service-001']}
            with patch('local_observe.inventory.worker.discovery.ingest', side_effect=OSError):
                with self.assertRaises(OSError):
                    tick(config, lambda: snapshot, now=NOW)
            state = json.loads((root/'state/cursor.json').read_text())
            self.assertEqual(state['pending'], snapshot)
            def forbidden():
                self.fail('Retry must not rediscover or remint snapshot identity')
            first = tick(config, forbidden, now=NOW)
            second = tick(config, lambda: snapshot, now=NOW)
            self.assertEqual(first['proposals'], second['proposals'])
            self.assertEqual(len(list((root/'state/proposals').glob('*.json'))), 1)
            changed = copy.deepcopy(snapshot)
            changed['snapshot_id'] = 'e4fa8765-dc5b-488e-9c8b-47caf82b6b11'
            changed['observed_at'] = '2026-09-06T12:00:30Z'
            changed['observations'][1]['attributes']['environment'] = 'changed'
            result = tick(config, lambda: changed, now=NOW)
            self.assertEqual(result['proposals'][0]['status'], 'changed_observation_needs_review')
            with self.assertRaises(ValueError):
                tick({**config, 'proposal_allowlist': []}, forbidden, now=NOW)

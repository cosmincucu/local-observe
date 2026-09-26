import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('sigma_compile', ROOT / 'local_observe/platform/sigma_compile.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CompilerTests(unittest.TestCase):
    def setUp(self):
        # utf-8 explicitly: the compiler hashes the text it is handed, and the build reads the rule as
        # utf-8. Without the encoding this line used the platform locale (cp1252 on Windows), so any
        # non-ASCII character in a rule made `rule_sha256` differ per host and this check failed on one
        # machine while passing on the Linux runner.
        self.raw = (ROOT / 'examples/sigma/process-marker.yaml').read_text(encoding='utf-8')

    def test_reproducible_shipped_artifact(self):
        expected = json.loads((ROOT / 'examples/sigma/compiled/process-marker.json').read_text())
        self.assertEqual(module.compile_rule(self.raw), expected)

    def test_unknown_field_rejected(self):
        with self.assertRaises(ValueError):
            module.compile_rule(self.raw.replace('Image|', 'UnmappedField|'))

    def test_unmapped_logsource_rejected(self):
        with self.assertRaises(ValueError):
            module.compile_rule(self.raw.replace('product: linux', 'product: windows'))

    def test_unvalidated_modifier_rejected(self):
        with self.assertRaises(ValueError):
            module.compile_rule(self.raw.replace('Image|endswith', 'Image|re'))

    def test_no_unbounded_scan_in_artifact(self):
        sql = module.compile_rule(self.raw)['sql']
        for value in ('{start_ns:UInt64}', '{end_ns:UInt64}', '{resource_id:String}', '{dataset:String}'):
            self.assertIn(value, sql)
        self.assertNotIn('SELECT *', sql)

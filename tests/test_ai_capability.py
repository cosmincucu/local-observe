"""Tests for the capability manifest: the one rule, the eight fields, and no inherited number."""
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.ai import capability
from local_observe.ai.capability import CapabilityError

ROOT = Path(__file__).resolve().parents[1]

MEASURED = {'schema_version': 1, 'context_tokens': 8192, 'tools': False, 'json_mode': True,
            'streaming': True, 'vision': False, 'parallel': 2, 'quant': 'Q4_K_M',
            'measured_tok_per_s': 14.5}


def manifest(**changes):
    """A valid measured manifest with *changes* applied — the shape every negative case mutates."""
    document = dict(MEASURED)
    document.update(changes)
    return document


class CapabilityRuleTests(unittest.TestCase):
    def test_unknown_and_false_are_both_not_usable(self):
        """The rule in `capability.py`: a consumer may not use what the manifest marks unknown/false."""
        document = capability.validate(manifest(json_mode='unknown', vision=False))
        self.assertFalse(capability.usable(document, 'json_mode'))
        self.assertFalse(capability.usable(document, 'vision'))
        self.assertFalse(capability.usable({}, 'context_tokens'), 'a missing field is not usable either')
        self.assertTrue(capability.usable(document, 'context_tokens'))

    def test_requiring_an_unmeasured_capability_names_the_field(self):
        document = capability.validate(manifest(context_tokens='unknown'))
        with self.assertRaises(CapabilityError) as caught:
            capability.require(document, 'context_tokens')
        self.assertEqual(caught.exception.code, 'capability_unknown')
        self.assertIn('context_tokens', str(caught.exception))
        self.assertIn('was never measured', str(caught.exception))
        with self.assertRaises(CapabilityError):
            capability.context_tokens(document)

    def test_a_capability_measured_as_false_stays_refused(self):
        with self.assertRaises(CapabilityError) as caught:
            capability.require(capability.validate(MEASURED), 'vision')
        self.assertIn('is marked false', str(caught.exception))

    def test_require_rejects_a_name_that_is_not_a_capability(self):
        with self.assertRaises(CapabilityError):
            capability.require(capability.validate(MEASURED), 'function_calling')

    def test_unknown_and_measured_and_summarise_agree(self):
        document = capability.validate(manifest(context_tokens='unknown', quant='unknown'))
        self.assertEqual(capability.unknown(document), ['context_tokens', 'quant'])
        self.assertFalse(capability.measured(document))
        summary = capability.summarise(document)
        self.assertEqual({'unknown', 'false', 'measured'}, set(summary.values()))
        self.assertEqual(summary['context_tokens'], 'unknown')
        self.assertEqual(summary['vision'], 'false')
        self.assertEqual(summary['quant'], 'unknown')
        self.assertEqual(sorted(capability.FIELDS), sorted(summary))
        self.assertTrue(capability.measured(capability.validate(MEASURED)))
        self.assertEqual(capability.unknown(capability.validate(MEASURED)), [])


class CapabilityValidationTests(unittest.TestCase):
    def test_the_measured_manifest_round_trips(self):
        self.assertEqual(capability.validate(MEASURED), MEASURED)

    def test_zero_context_and_zero_rate_are_refused_not_tolerated(self):
        for name, value in (('context_tokens', 0), ('context_tokens', 8192.0), ('context_tokens', True),
                            ('context_tokens', 1_000_001), ('parallel', 0), ('parallel', 65),
                            ('measured_tok_per_s', 0), ('measured_tok_per_s', -1),
                            ('measured_tok_per_s', 'fast'), ('json_mode', 'true'), ('json_mode', 1)):
            with self.subTest(name=name, value=value):
                with self.assertRaises(CapabilityError):
                    capability.validate(manifest(**{name: value}))

    def test_quant_is_one_bounded_line(self):
        for value in ('', '   ', 'a' * 33, 'Q4\n_K', 'Q4\t_K'):
            with self.subTest(value=repr(value)):
                with self.assertRaises(CapabilityError):
                    capability.validate(manifest(quant=value))
        self.assertEqual(capability.validate(manifest(quant='Q5_K_S'))['quant'], 'Q5_K_S')

    def test_the_field_set_is_exactly_the_eight(self):
        for document in ({**MEASURED, 'thinking': True},
                         {key: value for key, value in MEASURED.items() if key != 'vision'},
                         {'schema_version': 2, **{key: value for key, value in MEASURED.items()
                                                  if key != 'schema_version'}},
                         [], 'x', None):
            with self.subTest(document=str(document)[:40]):
                with self.assertRaises(CapabilityError):
                    capability.validate(document)

    def test_tools_true_is_refused_because_the_serve_never_enables_it(self):
        """A manifest may not claim a file/exec agent the shipped serve does not run.

        The upstream help for `--tools` lists read_file, write_file, edit_file and
        exec_shell_command and says "do not enable in untrusted environments"
        (tools/server/README.md:206 at tag v0.4.0); components/control/ai/compose.yaml never passes
        the flag, so `tools: true` describes a different deployment than this component ships.
        """
        with self.assertRaises(CapabilityError) as caught:
            capability.validate(manifest(tools=True))
        self.assertIn('tools', str(caught.exception))

    def test_a_file_is_bounded_and_must_be_json(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cap.json').write_text(json.dumps(MEASURED), encoding='utf-8')
            self.assertEqual(capability.load(root / 'cap.json'), MEASURED)
            (root / 'big.json').write_text(json.dumps({**MEASURED, 'quant': 'Q' * 5000}), encoding='utf-8')
            with self.assertRaises(CapabilityError):
                capability.load(root / 'big.json')
            (root / 'broken.json').write_text('{', encoding='utf-8')
            with self.assertRaises(CapabilityError):
                capability.load(root / 'broken.json')
            with self.assertRaises(OSError):
                capability.load(root / 'absent.json')

    def test_the_shipped_example_is_unmeasured_by_construction(self):
        """Every field but `tools` is unknown in the file the operator copies, so nothing generates yet."""
        document = capability.load(ROOT / 'components/control/ai/capability.example.json')
        self.assertEqual(capability.unknown(document),
                         ['context_tokens', 'json_mode', 'streaming', 'vision', 'parallel', 'quant',
                          'measured_tok_per_s'])
        self.assertFalse(document['tools'])
        with self.assertRaises(CapabilityError):
            capability.context_tokens(document)


if __name__ == '__main__':
    unittest.main()

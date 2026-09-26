"""Multi-instance expansion, its refusal set, and the two port deltas (module contract).

The compiler ships with **no** example module (see ``local_observe/modules/compiler.py``), so these
tests are its only conformance evidence: they inject rows, and every one of them pins a defect that a
future consumer would otherwise discover at run time.
"""
import copy
import unittest
import uuid
from typing import Any

from local_observe.modules import compiler, schema

HOST_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'modules-fixture/probe-1'))
OTHER_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'modules-fixture/probe-2'))


def module_document(multi: bool = True, **overrides: Any) -> dict[str, Any]:
    """A valid module, optionally carrying a ``multi_instance`` block keyed on ``{ifName}``."""
    document: dict[str, Any] = {
        'schema_version': 1, 'name': 'interface-table', 'module_version': 1,
        'applies_to': {'any_of': [{'id': HOST_ID}]},
        'collection': {'receiver': 'hostmetrics', 'interval_seconds': 30},
        'datapoints': [{'name': 'system.network.io', 'unit': 'By', 'type': 'counter'},
                       {'name': 'system.network.errors', 'unit': '{errors}', 'type': 'counter'}],
    }
    if multi:
        document['multi_instance'] = {'discovery': {'source': 'otel/receiver_creator'},
                                      'instance_label': '{ifName}'}
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not None}


def row(name: str = 'eth0', **extra: Any) -> dict[str, Any]:
    return dict({'ifName': name, 'ifSpeed': 1000, 'ifUp': True}, **extra)


class SingleInstanceTests(unittest.TestCase):
    def test_a_module_without_the_block_yields_exactly_one_unchanged_set(self):
        compiled = compiler.compile_module(module_document(multi=False))
        self.assertEqual(len(compiled), 1)
        self.assertIsNone(compiled[0].instance_label)
        self.assertIsNone(compiled[0].instance)
        self.assertEqual(compiled[0].labels, {})
        self.assertIsNone(compiled[0].resource_id)      # binding is the loader's, not the compiler's
        self.assertEqual([point['name'] for point in compiled[0].datapoints],
                         ['system.network.io', 'system.network.errors'])

    def test_discovered_rows_for_a_single_instance_module_are_a_refusal(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(multi=False), [row()])
        self.assertIn('declares no multi_instance block', str(caught.exception))

    def test_returned_datapoints_are_copies(self):
        document = module_document(multi=False)
        compiled = compiler.compile_module(document)
        compiled[0].datapoints[0]['name'] = 'sabotaged'
        self.assertEqual(document['datapoints'][0]['name'], 'system.network.io')
        self.assertEqual(module_document(multi=False), document)


class MultiInstanceTests(unittest.TestCase):
    def test_one_datapoint_set_per_discovered_instance(self):
        compiled = compiler.compile_module(module_document(), [row('eth0'), row('eth1'), row('eth2')])
        self.assertEqual([item.instance_label for item in compiled], ['eth0', 'eth1', 'eth2'])
        for item in compiled:
            self.assertEqual([point['name'] for point in item.datapoints],
                             ['system.network.io', 'system.network.errors'])

    def test_the_metric_name_is_not_rewritten_and_the_instance_rides_in_the_labels(self):
        """v0.1 emitted ``<name>.<label>``; here that would be a series no store can ever show."""
        item = compiler.compile_module(module_document(), [row('eth0')])[0]
        self.assertEqual([point['name'] for point in item.datapoints],
                         ['system.network.io', 'system.network.errors'])
        self.assertEqual(item.labels['instance'], 'eth0')

    def test_every_row_field_becomes_a_string_label(self):
        item = compiler.compile_module(module_document(), [row()])[0]
        self.assertEqual(item.labels, {'ifName': 'eth0', 'ifSpeed': '1000', 'ifUp': 'True',
                                       'instance': 'eth0'})
        self.assertEqual(item.instance['ifSpeed'], 1000)            # the row itself is kept as found

    def test_an_empty_discovery_result_is_an_answer_and_not_an_error(self):
        self.assertEqual(compiler.compile_module(module_document(), []), [])

    def test_a_multi_instance_module_needs_its_rows_handed_in(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document())
        sentence = str(caught.exception)
        self.assertIn('needs the discovered rows', sentence)
        self.assertIn('otel/receiver_creator', sentence)             # the seam it wants run

    def test_a_missing_template_field_is_named_with_the_template(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(), [{'ifSpeed': 10}])
        sentence = str(caught.exception)
        self.assertIn('ifName', sentence)
        self.assertIn('{ifName}', sentence)
        self.assertIn('instances[0]', sentence)

    def test_a_label_that_renders_blank_or_outside_the_label_shape_is_refused(self):
        for value in ('', '   ', 'eth 0', 'eth\n0', 'eth0;rm -rf', 'x' * 129):
            with self.subTest(ifName=value):
                with self.assertRaises(compiler.ModuleCompileError) as caught:
                    compiler.compile_module(module_document(), [{'ifName': value}])
                # A blank/spacey value is caught on the way in as a field bound; only a value that is
                # a legal field can reach the rendered-label rule, and both refusals name the row.
                self.assertIn('instances[0]', str(caught.exception))

    def test_the_same_label_on_two_resources_is_not_a_duplicate(self):
        """The port delta that makes a per-host interface table compilable at all."""
        compiled = compiler.compile_module(module_document(),
                                           [{'ifName': 'eth0', 'resource_id': HOST_ID},
                                            {'ifName': 'eth0', 'resource_id': OTHER_ID}])
        self.assertEqual([item.resource_id for item in compiled], [HOST_ID, OTHER_ID])

    def test_a_duplicate_label_on_one_resource_is_refused_naming_the_first_row(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(), [{'ifName': 'eth0'}, {'ifName': 'eth0'}])
        self.assertIn('duplicate instance label', str(caught.exception))
        self.assertIn('instances[0]', str(caught.exception))

    def test_a_rows_resource_id_must_be_a_canonical_uuid(self):
        for value in (HOST_ID.upper(), 'probe-1', 7, HOST_ID[:-1]):
            with self.subTest(resource_id=value):
                with self.assertRaises(compiler.ModuleCompileError) as caught:
                    compiler.compile_module(module_document(), [{'ifName': 'eth0',
                                                                 'resource_id': value}])
                self.assertIn('resource_id', str(caught.exception))

    def test_a_nested_or_oddly_named_row_is_refused_not_stringified(self):
        cases = ('not a mapping', ['eth0'], {'ifName': {'nested': 'value'}},
                 {'ifName': 'eth0', 'if name': 1}, {'ifName': 'eth0', '2fast': 1},
                 {'ifName': 'eth0', 'ifSpeed': float('nan')},
                 {f'field_{step}': str(step) for step in range(compiler.MAX_LABELS)})
        for case in cases:
            with self.subTest(row=str(case)[:40]):
                with self.assertRaises(compiler.ModuleCompileError) as caught:
                    compiler.compile_module(module_document(), [case])
                self.assertIn('instances[0]', str(caught.exception))

    def test_a_row_may_not_name_the_label_the_compiler_renders(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(), [{'ifName': 'eth0', 'instance': 'spoofed'}])
        self.assertIn('instance', str(caught.exception))

    def test_a_row_whose_value_is_too_long_to_be_a_label_is_refused(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(),
                                    [{'ifName': 'eth0', 'ifAlias': 'x' * (compiler.MAX_LABEL_CHARS + 1)}])
        self.assertIn('characters', str(caught.exception))

    def test_a_run_above_the_instance_bound_is_refused_rather_than_emitted(self):
        rows = [{'ifName': f'iface-{step}'} for step in range(compiler.MAX_INSTANCES + 1)]
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(), rows)
        self.assertIn(f'{compiler.MAX_INSTANCES}-instance bound', str(caught.exception))

    def test_every_defect_of_the_run_arrives_in_the_one_raise_and_nothing_partial_escapes(self):
        rows = [{'ifName': 'eth0'}, {'ifSpeed': 1}, {'ifName': 'eth0'}, 'junk']
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(), rows)
        joined = '; '.join(caught.exception.errors)
        for needle in ('instances[1]', 'instances[2]', 'instances[3]'):
            self.assertIn(needle, joined)
        self.assertEqual(len(caught.exception.errors), 3)

    def test_the_input_module_is_never_mutated(self):
        document = module_document()
        before = copy.deepcopy(document)
        compiler.compile_module(document, [{'ifName': 'eth0'}])
        self.assertEqual(document, before)


class InvalidModuleTests(unittest.TestCase):
    def test_a_module_the_loader_would_refuse_is_refused_here_too(self):
        document = module_document(schema_version=2, applies_to='kind=host')
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(document, [{'ifName': 'eth0'}])
        joined = '; '.join(caught.exception.errors)
        self.assertIn('schema_version', joined)
        self.assertIn('a rule string', joined)

    def test_an_unnamed_module_is_reported_as_invalid_rather_than_crashing(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module({'schema_version': 1}, None)
        self.assertEqual(caught.exception.module_name, '<invalid>')

    def test_the_error_carries_the_module_name_for_the_log_line(self):
        with self.assertRaises(compiler.ModuleCompileError) as caught:
            compiler.compile_module(module_document(multi=False), [row()])
        self.assertEqual(caught.exception.module_name, 'interface-table')
        self.assertIn('interface-table', str(caught.exception))


class ShapeTests(unittest.TestCase):
    def test_the_compiled_set_is_json_safe(self):
        item = compiler.compile_module(module_document(),
                                       [{'ifName': 'eth0', 'resource_id': HOST_ID}])[0]
        as_dict = item.as_dict()
        self.assertEqual(as_dict['resource_id'], HOST_ID)
        self.assertEqual(as_dict['instance_label'], 'eth0')
        self.assertEqual(as_dict['labels']['instance'], 'eth0')
        self.assertEqual(len(as_dict['datapoints']), 2)

    def test_the_contract_this_file_names_without_a_consumer_is_documented(self):
        """The shipped example set is empty on purpose; the docstring is the promise, so pin it."""
        doc = (compiler.__doc__ or '').lower()
        self.assertIn('shipped example set is empty', doc)
        self.assertIn('prototype library', doc)


if __name__ == '__main__':
    unittest.main()

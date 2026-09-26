"""The module schema's refusal set: every defect named, no invented vocabulary (module contract).

Fixture shape note: module names, resource ids and hostnames are synthetic (a ``uuid5`` of the name,
the ``tests/test_topology.py`` idiom), and the only real strings quoted here are the OTel names this
repository already ships. Nothing in this file is an estate identifier.
"""
import copy
import json
import unittest
import uuid
from pathlib import Path
from typing import Any

from local_observe.inventory import validation
from local_observe.modules import schema, select
from local_observe.platform import conditions, dynamic_bands, vocabulary, state
from local_observe.store import client as store_client

ROOT = Path(__file__).resolve().parents[1]
HOST_ID = str(uuid.uuid5(uuid.NAMESPACE_DNS, 'modules-fixture/probe-1'))


def module_document(**overrides: Any) -> dict[str, Any]:
    """One valid module, with any key replaced by a keyword argument (``None`` deletes it)."""
    document: dict[str, Any] = {
        'schema_version': 1,
        'name': 'host-metrics',
        'module_version': 1,
        'applies_to': {'any_of': [{'id': HOST_ID}]},
        'collection': {'receiver': 'hostmetrics', 'interval_seconds': 30, 'scrapers': ['cpu'],
                       'resource_attributes': ['host.name', 'resource_id']},
        'datapoints': [{'name': 'system.cpu.time', 'unit': 's', 'type': 'counter'}],
        'default_graphs': [{'title': 'CPU time', 'datapoints': ['system.cpu.time']}],
        'default_alerts': [{'name': 'cpu-absent', 'datapoint': 'system.cpu.time', 'mode': 'absence',
                            'within_seconds': 300, 'severity': 'warning'}],
    }
    document.update(overrides)
    return {key: value for key, value in document.items() if value is not None}


def errors(**overrides: Any) -> tuple[str, ...]:
    return schema.validate(module_document(**overrides)).errors


def first_error(needle: str, **overrides: Any) -> str:
    """The one error naming *needle*, so a test asserts on the sentence rather than on a count."""
    matches = [error for error in errors(**overrides) if needle in error]
    assert len(matches) == 1, f'expected exactly one error naming {needle!r}, got {matches}'
    return matches[0]


class AdmissibleTests(unittest.TestCase):
    def test_the_reference_shape_validates(self):
        result = schema.validate(module_document())
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.errors, ())

    def test_every_optional_key_is_optional(self):
        for key in ('description', 'default_graphs', 'default_alerts', 'multi_instance'):
            with self.subTest(omitted=key):
                result = schema.validate(module_document(**{key: None}))
                self.assertTrue(result.ok, result.errors)

    def test_the_shipped_reference_module_validates(self):
        """examples/modules/host-metrics.yaml is held to the contract by this suite, not by review."""
        document = validation.read_document(ROOT / 'examples/modules/host-metrics.yaml')
        result = schema.validate(document)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(schema.datapoint_names(document), ('system.cpu.time',))

    def test_multi_instance_validates_with_a_discovery_seam(self):
        block = {'discovery': {'source': 'snmp/iftable'}, 'instance_label': '{ifName}'}
        self.assertTrue(schema.validate(module_document(multi_instance=block)).ok)

    def test_a_non_mapping_is_one_error_and_not_a_crash(self):
        for document in (None, [], 'name: x', 7):
            with self.subTest(document=type(document).__name__):
                result = schema.validate(document)
                self.assertFalse(result.ok)
                self.assertEqual(result.errors, ('module: must be a mapping (a parsed YAML object)',))


class FieldDisciplineTests(unittest.TestCase):
    def test_each_required_key_refuses_separately_and_by_name(self):
        for key in schema.MODULE_REQUIRED:
            with self.subTest(missing=key):
                self.assertIn(f'{key}: missing required field', errors(**{key: None}))

    def test_an_unknown_top_level_key_is_named(self):
        self.assertIn('collect_when: unknown field (this schema admits no additional property)',
                      errors(collect_when='cpu'))

    def test_only_the_supported_schema_version_is_read(self):
        error = first_error('schema_version', schema_version=2)
        self.assertIn('is not supported', error)
        self.assertIn('refused', error)
        self.assertIn('schema_version: missing required field', errors(schema_version=None))

    def test_module_version_is_a_whole_positive_number(self):
        for value in (0, -1, '1', 1.0, True, None):
            with self.subTest(value=value):
                self.assertTrue(errors(module_version=value), value)

    def test_a_module_name_is_a_bounded_lowercase_label(self):
        for value in ('Host_CPU', 'a' * 65, 'has space', '-leading', 3, ''):
            with self.subTest(value=value):
                self.assertTrue(errors(name=value), value)
        self.assertTrue(schema.validate(module_document(name='linux.host-metrics_1')).ok)

    def test_text_fields_are_bounded_and_never_blank(self):
        self.assertTrue(errors(description=' ' * 5))
        self.assertTrue(errors(description='x' * 513))
        self.assertTrue(schema.validate(module_document(description='host CPU time')).ok)


class CollectionTests(unittest.TestCase):
    def test_the_fragment_shape_only(self):
        for key in schema.COLLECTION_REQUIRED:
            fragment = module_document()['collection']
            fragment.pop(key)
            with self.subTest(missing=key):
                self.assertIn(f'collection.{key}: missing required field', errors(collection=fragment))

    def test_no_free_form_params_map_exists(self):
        """v0.1's `params` is where an endpoint or a community string arrived; there is no such field."""
        fragment = dict(module_document()['collection'], params={'community': 'public'})
        self.assertIn('collection.params: unknown field (this schema admits no additional property)',
                      errors(collection=fragment))

    def test_interval_seconds_is_a_whole_number_of_five_to_a_day(self):
        for value in (0, 4, 86401, '30', 30.0, True, None):
            with self.subTest(value=value):
                self.assertTrue(errors(collection=dict(module_document()['collection'],
                                                       interval_seconds=value)), value)

    def test_otel_names_are_bounded_and_may_hold_a_slash(self):
        fragment = dict(module_document()['collection'], receiver='prometheus/job-observe',
                        scrapers=['cpu', 'network'])
        self.assertTrue(schema.validate(module_document(collection=fragment)).ok)
        for bad in ('CPU', 'x' * 65, 'has space', ''):
            with self.subTest(scraper=bad):
                self.assertTrue(errors(collection=dict(module_document()['collection'],
                                                       scrapers=[bad])), bad)

    def test_scoped_name_lists_refuse_duplicates_and_length(self):
        collection = dict(module_document()['collection'], scrapers=['cpu', 'cpu'])
        self.assertIn('collection.scrapers[1]: duplicate name', errors(collection=collection))
        collection = dict(module_document()['collection'],
                          scrapers=[f'step-{step}' for step in range(33)])
        self.assertTrue(errors(collection=collection))


class DatapointTests(unittest.TestCase):
    def test_shape_and_required_fields(self):
        for key in schema.DATAPOINT_REQUIRED:
            point = module_document()['datapoints'][0]
            point.pop(key)
            with self.subTest(missing=key):
                self.assertIn(f'datapoints[0].{key}: missing required field',
                              errors(datapoints=[point]))
        self.assertIn('datapoints[0].role: unknown field (this schema admits no additional property)',
                      errors(datapoints=[dict(module_document()['datapoints'][0], role='primary')]))

    def test_a_datapoint_name_is_exactly_what_the_store_can_bind(self):
        """The schema's name shape and the facade's selector shape are proved to agree on examples.

        A name the query adapter cannot bind is a datapoint that can never be proven, so the two rules
        must not be able to disagree — on either side. Source text is compared nowhere; a name that
        validates here is handed to ``check_selectors`` and must not be refused, and vice versa.
        """
        kind = store_client.describe_query('describe-metrics')
        for good in ('system.cpu.time', 'lo_process_running', 'a:b/c-d.1', 'x' * 128):
            with self.subTest(name=good):
                self.assertTrue(schema.validate(module_document(
                    datapoints=[{'name': good, 'unit': '1', 'type': 'gauge'}],
                    default_graphs=None, default_alerts=None)).ok)
                store_client.check_selectors(kind, {'metric_name': good})
        for bad in ('has space', "quote'd", 'x' * 129, '', 'back\\slash'):
            with self.subTest(name=bad):
                self.assertTrue(errors(datapoints=[{'name': bad, 'unit': '1', 'type': 'gauge'}],
                                       default_graphs=None, default_alerts=None), bad)
                with self.assertRaises(store_client.StoreRefused):
                    store_client.check_selectors(kind, {'metric_name': bad})

    def test_types_are_the_two_this_contract_admits(self):
        point = module_document()['datapoints'][0]
        for value in ('histogram', 'SUM', 'gauge ', None):
            with self.subTest(type=value):
                self.assertTrue(errors(datapoints=[dict(point, type=value)]), value)
        for value in schema.DATAPOINT_TYPES:
            with self.subTest(type=value):
                self.assertTrue(schema.validate(module_document(
                    datapoints=[dict(point, type=value)])).ok)

    def test_units_follow_the_otel_token_convention(self):
        point = module_document()['datapoints'][0]
        for good in ('s', '1', 'By', '{bytes}', 'MiB/s', '1/s'):
            with self.subTest(unit=good):
                self.assertTrue(schema.validate(module_document(datapoints=[dict(point, unit=good)])).ok)
        for bad in ('', ' ', 'seconds per core', 'x' * 65, 'unit\nwith\nnewlines'):
            with self.subTest(unit=bad):
                self.assertTrue(errors(datapoints=[dict(point, unit=bad)]), bad)

    def test_duplicate_and_over_long_lists_are_refused(self):
        point = module_document()['datapoints'][0]
        self.assertIn('datapoints[1].name: duplicate datapoint name',
                      errors(datapoints=[dict(point), dict(point)]))
        many = [{'name': 'series_%03d' % step, 'unit': '1', 'type': 'gauge'}
                for step in range(schema.MAX_DATAPOINTS + 1)]
        self.assertTrue(errors(datapoints=many))
        self.assertTrue(errors(datapoints=[]))


class GraphTests(unittest.TestCase):
    def test_a_graph_may_only_name_declared_datapoints(self):
        graphs = [{'title': 'CPU', 'datapoints': ['system.cpu.time', 'system.memory.usage']}]
        error = first_error('default_graphs[0].datapoints', default_graphs=graphs)
        self.assertIn('system.memory.usage', error)
        self.assertIn('is not a declared datapoint', error)

    def test_shape_bounded_references_and_an_empty_panel(self):
        cases = ([{'title': 'x', 'datapoints': []}], [{'title': 'x'}], [{'title': '', 'datapoints':
                                                                       ['system.cpu.time']}],
                 [{'title': 'x', 'datapoints': ['system.cpu.time'], 'unit': 's'}], ['a string'],
                 {'title': 'x', 'datapoints': ['system.cpu.time']})
        for graphs in cases:
            with self.subTest(graphs=graphs):
                self.assertTrue(errors(default_graphs=graphs), graphs)

    def test_a_panel_beyond_the_series_bound_is_refused(self):
        points = [{'name': 'series_%02d' % step, 'unit': '1', 'type': 'gauge'}
                  for step in range(schema.MAX_GRAPH_SERIES + 1)]
        graphs = [{'title': 'everything', 'datapoints': [point['name'] for point in points]}]
        self.assertTrue(errors(datapoints=points, default_graphs=graphs))


class AlertTests(unittest.TestCase):
    def setUp(self):
        self.alert = module_document()['default_alerts'][0]

    def test_the_condition_modes_are_the_ones_that_exist(self):
        """alert conditions is the only source for these words: a module cannot name a machine that has none."""
        self.assertEqual(schema.ALERT_MODES,
                         tuple(sorted(tuple(conditions.MODES) + (dynamic_bands.BAND_MODE,))))
        self.assertEqual(schema.ALERT_OPS, tuple(sorted(conditions.OPS)))
        for mode in ('threshold', 'absence', 'availability', 'band'):
            with self.subTest(mode=mode):
                self.assertTrue(schema.validate(module_document(
                    default_alerts=[_alert_for_mode(mode)])))

    def test_a_mode_nobody_judges_is_refused_and_names_where_modes_lives(self):
        error = first_error('mode', default_alerts=[dict(self.alert, mode='flapping')])
        self.assertIn('is not a condition type that exists', error)
        self.assertIn('platform/conditions.py', error)

    def test_severity_comes_from_the_crosswalk_not_from_this_file(self):
        self.assertEqual(schema.ALERT_SEVERITIES, vocabulary.ADMITTED_SEVERITIES)
        self.assertEqual(set(schema.ALERT_SEVERITIES), {'info', 'warning', 'critical'})
        for bad in ('error', 'unknown', 'crit', None, 3):
            with self.subTest(severity=bad):
                self.assertIn('severity', first_error('severity', default_alerts=[
                    dict(self.alert, severity=bad)]))
        # v0.1's five-severity ladder has no encoding here: `error` is the lossy one the port table names.
        self.assertIn('state.validate_event', first_error('severity', default_alerts=[
            dict(self.alert, severity='error')]))

    def test_a_threshold_alert_names_a_comparison_and_a_finite_number(self):
        base = _alert_for_mode('threshold')
        self.assertTrue(schema.validate(module_document(default_alerts=[base])).ok)
        for bad in ('==', '!=', '', None):
            with self.subTest(op=bad):
                self.assertTrue(errors(default_alerts=[dict(base, op=bad)]), bad)
        for bad in (None, 'high', float('nan'), float('inf'), True):
            with self.subTest(threshold=bad):
                self.assertTrue(errors(default_alerts=[dict(base, threshold=bad)]), bad)

    def test_modes_that_judge_no_comparison_refuse_op_and_threshold(self):
        for mode in ('availability', 'band'):
            base = _alert_for_mode(mode)
            self.assertTrue(schema.validate(module_document(default_alerts=[base])).ok)
            for extra in ({'op': '>'}, {'threshold': 90}, {'op': '>', 'threshold': 90}):
                with self.subTest(mode=mode, **extra):
                    self.assertTrue(errors(default_alerts=[dict(base, **extra)]), extra)

    def test_absence_has_one_deadline_and_a_duration_behind_it_is_refused(self):
        base = _alert_for_mode('absence')
        self.assertTrue(schema.validate(module_document(default_alerts=[base])).ok)
        self.assertIn('one deadline', first_error('for_seconds', default_alerts=[
            dict(base, for_seconds=120)]))
        for bad in (59, 86401, '600', 60.0, False, None):
            with self.subTest(within_seconds=bad):
                self.assertTrue(errors(default_alerts=[dict(base, within_seconds=bad)]), bad)
        self.assertIn('only an absence alert is judged by the clock', first_error(
            'within_seconds', default_alerts=[_alert_for_mode('availability', within_seconds=600)]))

    def test_for_seconds_is_bounded_where_a_mode_may_carry_it(self):
        for bad in (-1, 86401, '300', 30.5, True):
            with self.subTest(for_seconds=bad):
                self.assertTrue(errors(default_alerts=[_alert_for_mode('threshold', op='>',
                                                                      threshold=90,
                                                                      for_seconds=bad)]), bad)

    def test_alert_names_are_unique_and_bounded(self):
        first = _alert_for_mode('availability')
        self.assertIn('duplicate alert name',
                      ' '.join(errors(default_alerts=[dict(first), dict(first)])))
        self.assertTrue(errors(default_alerts=[dict(first, name='CPU_Absent')]))

    def test_a_reference_to_an_undeclared_datapoint_refuses_before_any_store_is_asked(self):
        error = first_error('datapoint', default_alerts=[dict(self.alert, datapoint='nope.total')])
        self.assertIn('is not a declared datapoint', error)


class MultiInstanceTests(unittest.TestCase):
    def test_both_fields_are_required_and_shaped(self):
        cases = ({}, {'discovery': {'source': 'snmp/iftable'}},
                 {'instance_label': '{ifName}'},
                 {'discovery': {'source': 'snmp/iftable', 'params': {'community': 'x'}},
                  'instance_label': '{ifName}'},
                 {'discovery': 'snmp/iftable', 'instance_label': '{ifName}'},
                 {'discovery': {'source': 'has space'}, 'instance_label': '{ifName}'},
                 {'discovery': {'source': 'snmp/iftable'}, 'instance_label': ''},
                 {'discovery': {'source': 'snmp/iftable'}, 'instance_label': 'no placeholders'},
                 {'discovery': {'source': 'snmp/iftable'}, 'instance_label': '{0}'},
                 {'discovery': {'source': 'snmp/iftable'}, 'instance_label': '{if.name}'},
                 {'discovery': {'source': 'snmp/iftable'}, 'instance_label': '{ifName',
                  'extra': 1},
                 'not a mapping')
        for block in cases:
            with self.subTest(multi_instance=block):
                result = schema.validate(module_document(multi_instance=block))
                self.assertFalse(result.ok, block)
                self.assertTrue(all('multi_instance' in error for error in result.errors),
                                result.errors)

    def test_a_valid_block_names_no_endpoint_and_no_credential(self):
        """`discovery` carries a source name only: v0.1's discovery `params` is where those lived."""
        block = {'discovery': {'source': 'otel/receiver_creator'}, 'instance_label': '{name}'}
        self.assertTrue(schema.validate(module_document(multi_instance=block)).ok)


class EchoSafetyTests(unittest.TestCase):
    """Refusal sentences reach an HTTP error body the way ``api.py`` builds one, so a value is echoed
    only when it is short and inside the bounded alphabet — the ``vocabulary._ECHO_SAFE`` rule."""

    def test_an_unsafe_value_is_not_quoted_back(self):
        secret = 'hunter2 secret value with spaces and a very long tail ' + 'x' * 200
        result = schema.validate(module_document(datapoints=[{'name': 'a.series', 'unit': 's',
                                                            'type': secret}]))
        self.assertFalse(result.ok)
        self.assertNotIn('hunter2', ' '.join(result.errors))
        self.assertIn("'?'", ' '.join(result.errors))

    def test_a_bounded_value_is_quoted_so_the_operator_can_find_it(self):
        self.assertIn("'histogram'", first_error('type', datapoints=[{'name': 'a.series', 'unit': 's',
                                                                     'type': 'histogram'}]))


class PinnedAgainstOtherPeoplesFilesTests(unittest.TestCase):
    """These constants restate shapes this brief may not edit; the tests are what keep them honest."""

    def test_the_alias_and_uuid_shapes_are_common_jsons(self):
        common = json.loads((ROOT / 'local_observe' / 'inventory' / 'schemas' /
                             'common.json').read_text())
        self.assertEqual(select.UUID_SHAPE.pattern, common['$defs']['uuid']['pattern'])
        self.assertEqual(set(select.ALIAS_TYPES),
                         set(common['$defs']['alias']['properties']['type']['enum']))
        self.assertEqual(select.MAX_VALUE_CHARS, common['$defs']['text']['maxLength'])
        self.assertEqual(select.ALIAS_KEYS, set(common['$defs']['alias']['properties']))

    def test_a_datapoint_name_survives_the_store_selector_rule(self):
        """Names admitted here must be bindable there, or the proof can never be asked."""
        for name in ('system.cpu.time', 'lo_process_running', 'a:b/c-d.1'):
            self.assertTrue(store_client.SELECTOR.fullmatch(name), name)
        state.label('host-metrics')          # the rule-id half of a rendered condition stays admissible
        state.label('a' * 64)

    def test_the_schema_uses_no_severity_literal_of_its_own(self):
        body = (ROOT / 'local_observe/modules/schema.py').read_text()
        for word in ("'error'", "'unknown'", "'crit'"):
            self.assertNotIn(word, body, f'schema.py must cite vocabulary.py, not spell {word}')


class HelperTests(unittest.TestCase):
    def test_datapoint_names_tolerates_an_unvalidated_document(self):
        self.assertEqual(schema.datapoint_names({'datapoints': [{'name': 'a'}, 'x', {}, {'name': 2}]}),
                         ('a',))
        self.assertEqual(schema.datapoint_names({}), ())

    def test_referenced_datapoints_is_in_order_and_deduplicated(self):
        document = module_document(
            datapoints=[{'name': 'system.cpu.time', 'unit': 's', 'type': 'counter'},
                        {'name': 'system.memory.usage', 'unit': 'By', 'type': 'gauge'}],
            default_graphs=[{'title': 'a', 'datapoints': ['system.cpu.time']},
                            {'title': 'b', 'datapoints': ['system.cpu.time']}],
            default_alerts=[{'name': 'x', 'datapoint': 'system.cpu.time', 'mode': 'availability',
                             'severity': 'warning'}])
        self.assertEqual(schema.referenced_datapoints(document), ('system.cpu.time',))
        self.assertEqual(schema.datapoint_names(document), ('system.cpu.time',
                                                            'system.memory.usage'))

    def test_the_two_lists_partition_what_the_module_declared(self):
        document = copy.deepcopy(module_document())
        referenced = set(schema.referenced_datapoints(document))
        declared = set(schema.datapoint_names(document))
        self.assertTrue(referenced <= declared)


def _alert_for_mode(mode: str, **extra: Any) -> dict[str, Any]:
    """One alert shaped the way *mode* can mean: the fields it judges, and none it does not."""
    alert: dict[str, Any] = {'name': 'declared-alert', 'datapoint': 'system.cpu.time', 'mode': mode,
                             'severity': 'warning'}
    if mode == 'threshold':
        alert.update({'op': '>', 'threshold': 90})
    if mode == 'absence':
        alert['within_seconds'] = 300
    alert.update(extra)
    return alert


if __name__ == '__main__':
    unittest.main()

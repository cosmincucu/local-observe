"""privacy checks: the migration capture takes its estate from one declared operator file, never a default.

`scripts/migration_layout.py` is the only reader of `source-layout.json`, and the capture copies what
it validated into the baseline it writes (schema 2), so the drift gate and the candidate preparer
never open a second operator input and can never disagree with the capture about which estate was
read. What is pinned here is the refusal side of that contract — a missing key, a bad path, a
declared contract set the tool surface does not carry — plus one round trip proving the validated
layout survives the capture verbatim.

Every fixture is synthetic and placeholder-only: the estate's own paths are what this item removes, so
a test naming them would re-add the thing the gate now refuses.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
for entry in (str(ROOT), str(ROOT / 'tests'), str(ROOT / 'scripts')):
    if entry not in sys.path:
        sys.path.insert(0, entry)
import migration_layout   # noqa: E402
import test_migration as fixtures   # noqa: E402


def read_from_document(document):
    """Validate `document` through the module's own validator, bypassing the JSON round trip.

    Used where a case needs a value JSON cannot carry (a non-string object key); the file-reading path
    is exercised by every other case through `read_layout`.
    """
    return migration_layout.validate_layout(document)


class LayoutLocationTests(unittest.TestCase):
    """Where the layout lives, and the refusal when it is not there."""

    def test_a_configured_directory_holding_no_layout_is_refused_by_name(self):
        """A missing operator input is refused by name, not reported as drift (mirrors `baseline_file`)."""
        with tempfile.TemporaryDirectory() as directory:
            operator = Path(directory)
            (operator/'baseline-02.json').write_text('{}', encoding='utf-8')   # the baseline alone is not enough
            for call in (lambda: migration_layout.layout_file(operator),
                         lambda: migration_layout.read_layout(operator)):
                with self.subTest(call=call):
                    with self.assertRaises(ValueError) as caught:
                        call()
                    self.assertIn(migration_layout.LAYOUT_NAME, str(caught.exception))
                    self.assertIn(str(operator), str(caught.exception))

    def test_a_layout_name_cannot_reach_outside_the_operator_directory(self):
        """Same bound as the baseline name: one file inside the directory, never a path."""
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/migration_layout.LAYOUT_NAME).write_text('{}', encoding='utf-8')
            for name in ('../' + migration_layout.LAYOUT_NAME, str(Path(directory)/'source-layout.json'),
                         'sub/source-layout.json'):
                with self.subTest(name=name), self.assertRaises(ValueError) as caught:
                    migration_layout.layout_file(Path(directory), name)
                self.assertIn('file name inside the baseline directory', str(caught.exception))


class LayoutValidationTests(unittest.TestCase):
    """Every key is required, and every refusal names the key it refused on."""

    def valid(self):
        return fixtures.synthetic_layout()

    def read(self, document):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/migration_layout.LAYOUT_NAME).write_text(json.dumps(document), encoding='utf-8')
            return migration_layout.read_layout(Path(directory))

    def assert_refused(self, document, token):
        with self.assertRaises(ValueError) as caught:
            self.read(document)
        self.assertIn(token, str(caught.exception), str(caught.exception))

    def test_every_required_key_is_demanded_by_name(self):
        for key in migration_layout.REQUIRED_KEYS:
            with self.subTest(key=key):
                document = self.valid()
                del document[key]
                self.assert_refused(document, key)

    def test_an_unknown_key_is_refused_rather_than_ignored(self):
        document = self.valid()
        document['collector_directory'] = 'estate/agents'
        self.assert_refused(document, 'collector_directory')

    def test_schema_version_must_be_the_one_this_reader_understands(self):
        for version in (0, 2, '1', True, None):
            with self.subTest(version=version):
                document = self.valid()
                document['schema_version'] = version
                self.assert_refused(document, 'schema_version')

    def test_a_path_value_may_be_neither_absolute_nor_escaping_nor_backslashed(self):
        cases = {'/etc/passwd': 'homepage_services', 'D:/operator/repo': 'homepage_services',
                 '../outside.yaml': 'homepage_services', '..\\outside.yaml': 'homepage_services',
                 'estate/../../outside.yaml': 'homepage_services', '': 'homepage_services'}
        for value, key in cases.items():
            with self.subTest(value=value):
                document = self.valid()
                document[key] = value
                self.assert_refused(document, key)

    def test_each_path_bearing_key_takes_the_same_rule(self):
        for key in migration_layout.PATH_FIELDS:
            with self.subTest(key=key):
                document = self.valid()
                document[key] = '/absolute/' + key
                self.assert_refused(document, key)

    def test_a_collector_path_takes_the_same_rule_and_is_named_by_index(self):
        document = self.valid()
        document['collector_configs'][1]['path'] = '../elsewhere/host-b.yaml'
        self.assert_refused(document, 'collector_configs[1].path')

    def test_a_collector_entry_must_carry_exactly_host_and_path(self):
        for entry in ({'host': 'host-a'}, {'path': 'estate/agents/host-a.yaml'},
                      {'host': 'host-a', 'path': 'estate/agents/host-a.yaml', 'port': 4318}, 'host-a'):
            with self.subTest(entry=entry):
                document = self.valid()
                document['collector_configs'] = [entry]
                self.assert_refused(document, 'collector_configs[0]')

    def test_an_empty_collector_list_is_refused(self):
        """The capture would otherwise write a baseline with no producers at all and call it a capture."""
        for value in ([], {}, None, 'estate/agents'):
            with self.subTest(value=value):
                document = self.valid()
                document['collector_configs'] = value
                self.assert_refused(document, 'collector_configs')

    def test_a_trailing_slash_on_the_dashboard_directory_is_refused(self):
        """The capture joins the dashboard file name with one separator; a slash here would hash `//`."""
        for value in ('estate/dashboards/', 'estate/dashboards//'):
            with self.subTest(value=value):
                document = self.valid()
                document['dashboard_directory'] = value
                self.assert_refused(document, 'dashboard_directory')

    def test_the_endpoint_is_a_url_and_never_a_path(self):
        """`legacy_mcp_endpoint` is compared, not opened, so it takes URL rules and not `relative_source`."""
        document = self.valid()
        document['legacy_mcp_endpoint'] = 'http://mcp.invalid:8464/mcp/'
        self.assertEqual(self.read(document)['legacy_mcp_endpoint'], 'http://mcp.invalid:8464/mcp/')
        for value in ('', '   ', 'ftp://mcp.invalid/mcp/', 'mcp.invalid/mcp/', '/mcp/', None, 8464):
            with self.subTest(value=value):
                document = self.valid()
                document['legacy_mcp_endpoint'] = value
                self.assert_refused(document, 'legacy_mcp_endpoint')

    def test_the_deployment_block_carries_exactly_the_four_declared_fields(self):
        full = {'id': 'synthetic', 'title': 'Synthetic', 'theme': 'light', 'color': 'gray'}
        for change, token in (({'color': ''}, 'deployment.color'),
                              ({'theme': None}, 'deployment.theme'),
                              ({'extra': 'x'}, 'deployment carries key(s)')):
            with self.subTest(token=token):
                document = self.valid()
                document['deployment'] = {key: value for key, value in full.items() if key not in change}
                document['deployment'].update(change)
                self.assert_refused(document, token)
        document = self.valid()
        document['deployment'] = {'id': 'synthetic', 'title': 'Synthetic', 'theme': 'light'}
        self.assert_refused(document, 'deployment is missing')

    def test_a_declared_empty_list_is_allowed_and_a_missing_one_is_not(self):
        """'This estate declares none' is a decision; forgetting the key is a different failure."""
        document = self.valid()
        for key in ('preserved_services', 'widget_status_tiles', 'tile_dispositions', 'tile_availability'):
            document[key] = {} if key.startswith('tile_') else []
        layout = self.read(document)
        self.assertEqual(layout['preserved_services'], [])
        self.assertEqual(layout['tile_dispositions'], {})
        self.assertEqual(layout['widget_status_tiles'], [])
        self.assertEqual(layout['tile_availability'], {})
        self.assertTrue(layout['mcp_contract_sets'], 'the contract sets are the one list that may not be empty')

    def test_an_empty_mcp_contract_set_list_is_refused(self):
        """The drift gate reports it too, but a capture built from a layout that names no set is refused first."""
        self.assert_refused({**self.valid(), 'mcp_contract_sets': []}, 'mcp_contract_sets')

    def test_a_map_value_must_be_text_to_text(self):
        for bad in ({'Test': 7}, {'Test': {'sentence': True}}, {'': 'sentence'}, {'Test': '  '}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as caught:
                    read_from_document({**self.valid(), 'tile_dispositions': bad})
                self.assertIn('tile_dispositions', str(caught.exception))
        self.assertEqual(read_from_document({**self.valid(), 'tile_availability': {'Test': 'on demand'}})
                         ['tile_availability'], {'Test': 'on demand'})

    def test_the_group_prefix_is_a_bare_string_and_not_a_path(self):
        for value in ('', '  ', None, 7):
            with self.subTest(value=value):
                self.assert_refused({**self.valid(), 'dashboard_group_prefix': value},
                                    'dashboard_group_prefix')
        self.assertEqual(self.read({**self.valid(), 'dashboard_group_prefix': 'Overview'})['dashboard_group_prefix'],
                         'Overview')


class CaptureUsesTheLayoutTests(unittest.TestCase):
    """The capture reads the estate through the layout, and refuses a contract set it cannot find."""

    def build(self, directory):
        source = Path(directory)/'source'
        fixtures.write_source_fixture(source)
        return source, fixtures.synthetic_layout()

    def test_a_capture_round_trips_and_carries_the_layout_verbatim(self):
        with tempfile.TemporaryDirectory() as directory:
            source, layout = self.build(directory)
            capture, check = fixtures.module('prepare_migration').capture, fixtures.module('check_migration').check
            baseline = capture(source, layout)
            self.assertEqual(baseline['schema_version'], 2)
            self.assertEqual(baseline['layout'], layout, 'the capture stores the layout it read, unchanged')
            report = check(baseline, source)
            self.assertTrue(report['preparation_valid'], report['errors'])
            self.assertEqual([row['host'] for row in baseline['producers']], ['host-a', 'host-b'],
                             'every declared collector is captured, not just the first')
            self.assertEqual(baseline['mcp']['legacy_endpoint'], layout['legacy_mcp_endpoint'])

    def test_a_declared_contract_set_absent_from_the_tool_surface_is_refused(self):
        """Fail closed: a set the surface does not define must not reach the baseline as an empty one."""
        with tempfile.TemporaryDirectory() as directory:
            source, layout = self.build(directory)
            layout['mcp_contract_sets'] = layout['mcp_contract_sets'] + ['MISSING_TOOLS']
            capture = fixtures.module('prepare_migration').capture
            with self.assertRaises(ValueError) as caught:
                capture(source, layout)
            self.assertIn('MISSING_TOOLS', str(caught.exception))

    def test_a_tile_the_layout_does_not_name_keeps_the_neutral_disposition(self):
        """No entry means no override: the capture may not invent a sentence for a tile it was not told about."""
        with tempfile.TemporaryDirectory() as directory:
            source, layout = self.build(directory)
            layout['tile_dispositions'] = {}
            baseline = fixtures.module('prepare_migration').capture(source, layout)
            self.assertEqual({row['name']: row['disposition'] for row in baseline['services']},
                             {'Test': 'preserve existing endpoint'})
            self.assertNotIn('expected_availability', baseline['services'][0])

    def test_a_baseline_carrying_no_layout_is_refused_by_the_gate_and_by_the_candidate_preparer(self):
        with tempfile.TemporaryDirectory() as directory:
            source, layout = self.build(directory)
            capture, check = fixtures.module('prepare_migration').capture, fixtures.module('check_migration').check
            baseline = capture(source, layout)
            del baseline['layout']
            report = check(baseline, source)
            self.assertFalse(report['preparation_valid'])
            self.assertTrue(any('layout' in error for error in report['errors']), report['errors'])
            # The preparer's own drift refusal runs first (privacy checks task 4, pinned by
            # tests/test_customisation_candidate.py), so what it raises here is that sentence; its
            # layout refusal sits behind it as the contract statement for any caller that skips check().
            preparer = fixtures.module('prepare_customisation_candidate')
            with tempfile.TemporaryDirectory() as out:
                with self.assertRaises(ValueError) as caught:
                    preparer.prepare(source, copy.deepcopy(baseline), 'https://example.test', Path(out)/'candidate')
            self.assertIn('Baseline drift', str(caught.exception))
            self.assertIn('predates the layout contract',
                          (ROOT/'scripts/prepare_customisation_candidate.py').read_text(encoding='utf-8'))

    def test_a_schema_one_capture_is_refused_as_a_missing_versioned_baseline(self):
        """The version bump is enforced, not advisory: a v1 capture names no layout to read."""
        with tempfile.TemporaryDirectory() as directory:
            source, layout = self.build(directory)
            capture, check = fixtures.module('prepare_migration').capture, fixtures.module('check_migration').check
            baseline = capture(source, layout)
            baseline['schema_version'] = 1
            report = check(baseline, source)
            self.assertFalse(report['preparation_valid'])
            self.assertEqual(report['errors'], ['Missing versioned source baseline'])

    def test_a_layout_declaring_no_contract_sets_is_reported_by_the_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            source, layout = self.build(directory)
            capture, check = fixtures.module('prepare_migration').capture, fixtures.module('check_migration').check
            baseline = capture(source, layout)
            baseline['layout']['mcp_contract_sets'] = []
            report = check(baseline, source)
            self.assertFalse(report['preparation_valid'])
            self.assertIn('Baseline declares no required MCP contract sets', report['errors'])
            baseline['layout']['mcp_contract_sets'] = ['ABSENT_TOOLS']
            report = check(baseline, source)
            self.assertIn('Required MCP contract missing', report['errors'],
                          'a declared set the capture never took stays a failure')


class CandidateReadsTheCapturedLayoutTests(unittest.TestCase):
    """Task 4, end to end: the preparer takes every estate name from the capture, and ships none.

    The whole candidate path runs here against the synthetic fixture, which is the only way to see the
    deployment identity arrive from the layout rather than from a literal — the literal was the estate's
    own name, and no source-text grep can tell a copied value from a hard-coded one.
    """

    def prepared(self, directory, widget=False, status_tiles=('Test',)):
        """Capture from the synthetic layout and prepare a candidate under `directory`; return both reports."""
        source = Path(directory)/'source'
        fixtures.write_source_fixture(source)
        if widget:
            (source/'estate/homepage/services.yaml').write_text(
                '- Dashboards / test:\n    - Test:\n'
                '        href: https://example.test/dashboard/id\n'
                '        # dashboard: test.json\n'
                '        widget:\n          type: custom\n          url: https://example.test\n'
                '          mappings:\n            - field: enabled\n              property: state\n',
                encoding='utf-8')
        layout = fixtures.synthetic_layout()
        layout['widget_status_tiles'] = list(status_tiles)
        operator = Path(directory)/'operator'
        fixtures.write_layout_fixture(operator, layout)
        layout = migration_layout.read_layout(operator)   # the same read the capture's own main() does
        baseline = fixtures.module('prepare_migration').capture(source, layout)
        output = Path(directory)/'candidate'
        report = fixtures.module('prepare_customisation_candidate').prepare(
            source, baseline, 'https://operator.example.test', output)
        return report, json.loads((output/'deployment.json').read_text(encoding='utf-8'))

    def test_the_deployment_identity_and_paths_arrive_from_the_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            report, deployment = self.prepared(directory)
            self.assertEqual(report['status'], 'prepared')
            self.assertFalse(report['deploy_authorized'])
            self.assertNotIn('deployment-config', report['target_after_review'])
            self.assertEqual(deployment['id'], 'synthetic')
            self.assertEqual(deployment['homepage'], {'title': 'Synthetic', 'theme': 'light', 'color': 'gray'})
            self.assertEqual(deployment['schema_version'], 1,
                             'the content document keeps its own contract version, pinned by content.py')
            self.assertEqual([row['kind'] for row in deployment['content']], ['tile', 'dashboard'],
                             'the Homepage tile and the dashboard both came through the declared paths')

    def test_only_a_tile_the_layout_names_and_that_has_a_widget_moves_group(self):
        with tempfile.TemporaryDirectory() as directory:
            _report, deployment = self.prepared(directory, widget=True, status_tiles=('Test',))
            tile = [row for row in deployment['content'] if row['kind'] == 'tile'][0]
            self.assertEqual(tile['spec']['group'], 'core.platform')
            mappings = tile['spec']['config']['widget']['mappings']
            self.assertEqual(mappings[0]['remap'][0], {'value': True, 'to': 'Enabled'},
                             'the remap the estate relied on is built for a declared status tile')
        with tempfile.TemporaryDirectory() as directory:
            _report, deployment = self.prepared(directory, widget=True, status_tiles=())
            tile = [row for row in deployment['content'] if row['kind'] == 'tile'][0]
            self.assertEqual(tile['spec']['group'], 'core.dashboards',
                             'an undeclared tile is not a status tile, widget or no widget')


class SourceArgumentTests(unittest.TestCase):
    """No `--source`, no run: the three readers refuse explicitly instead of defaulting to a path."""

    BASELINE_ENV = 'LO_MIGRATION_BASELINE_DIR'

    def run_script(self, name, arguments, environment):
        base = {key: value for key, value in os.environ.items() if key != self.BASELINE_ENV}
        base.update(environment)
        return subprocess.run([sys.executable, '-B', str(ROOT/'scripts'/name), *arguments],
                              capture_output=True, text=True, env=base, cwd=str(ROOT))

    def test_each_reader_names_the_source_it_wants_before_reading_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            operator = Path(directory)/'operator'
            operator.mkdir()
            (operator/'baseline-02.json').write_text(json.dumps({'schema_version': 2, 'layout': {}}),
                                                     encoding='utf-8')
            cases = {
                'check_migration.py': (),
                'prepare_migration.py': (),
                'prepare_customisation_candidate.py': ('--operator-url', 'https://example.test',
                                                       '--output', str(Path(directory)/'candidate')),
            }
            for name, arguments in cases.items():
                with self.subTest(script=name):
                    result = self.run_script(name, ('--baseline-dir', str(operator)) + arguments, {})
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(result.stdout, '')
                    self.assertNotIn('Traceback', result.stderr, result.stderr)
                    self.assertIn('--source', result.stderr, result.stderr)
                    self.assertIn('operator checkout', result.stderr, result.stderr)
                    self.assertNotIn('LO_MIGRATION_BASELINE_DIR', result.stderr,
                                     'the baseline refusal already passed, so it must not come back')
            self.assertFalse((Path(directory)/'candidate').exists(), 'a refusal writes nothing')

    def test_the_baseline_refusal_still_outranks_the_source_refusal(self):
        """Order is fixed by three existing cases (privacy checks section B): directory first, then --source."""
        result = self.run_script('check_migration.py', (), {})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('LO_MIGRATION_BASELINE_DIR', result.stderr, result.stderr)
        self.assertNotIn('--source to the operator checkout', result.stderr, result.stderr)


if __name__ == '__main__':
    unittest.main()

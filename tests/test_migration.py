import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
BASELINE_ENV = 'LO_MIGRATION_BASELINE_DIR'


def module(name):
    """Load one gate script by path the way ``python scripts/<name>.py`` would.

    ``scripts/`` goes on the import path because deployment separation made the readers share the baseline-location
    helpers in ``check_migration``: a script run as a file gets its own directory there for free, an
    importlib load does not.
    """
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(name, SCRIPTS/f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def write_source_fixture(root):
    """Build the smallest checkout the capture accepts, and return the files it wrote.

    Synthetic names and hashes, never a copy of a real estate baseline: enough Homepage structure for
    one dashboard tile with one panel, one MCP tool surface and an empty deploy map. Since privacy checks the
    paths are the ones `synthetic_layout()` declares, so nothing here names a host, a service of one
    estate or the directory layout of one operator's repository.
    """
    files = {
        'estate/homepage/services.yaml': '- Dashboards / test:\n    - Test:\n'
                                         '        href: https://example.test/dashboard/id\n'
                                         '        # dashboard: test.json\n',
        'estate/dashboards/test.json': json.dumps(
            {'widgets': [{'title': 'Test', 'query': {'queryType': 'builder', 'metricName': 'system.cpu.time'}}]}),
        'estate/agents/host-a.yaml': 'receivers: {}\nservice: {pipelines: {}}\n',
        'estate/agents/host-b.yaml': 'receivers: {}\nservice: {pipelines: {}}\n',
        'estate/mcp/tool_surface.py': "TELEMETRY_TOOLS = {'query_metrics'}\n"
                                      "GITEA_TOOLS = {'list_prs'}\n"
                                      "OPENBAO_TOOLS = {'get_secret_metadata'}\n",
        'estate/deploy-map.json': '{"hosts": {}}'}
    for name, raw in files.items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw, encoding='utf-8')
    return files


def synthetic_layout():
    """Return a version-1 `source-layout.json` document matching `write_source_fixture`.

    Placeholders only, the way `examples/inventory/` declares an estate: no host name, no private
    address, no service of the source estate. The two collector entries are deliberate — one would not
    prove the capture iterates the declared list.
    """
    return {'schema_version': 1,
            'homepage_services': 'estate/homepage/services.yaml',
            'dashboard_directory': 'estate/dashboards',
            'dashboard_group_prefix': 'Dashboards',
            'collector_configs': [{'host': 'host-a', 'path': 'estate/agents/host-a.yaml'},
                                  {'host': 'host-b', 'path': 'estate/agents/host-b.yaml'}],
            'mcp_tool_surface': 'estate/mcp/tool_surface.py',
            'mcp_contract_sets': ['TELEMETRY_TOOLS', 'GITEA_TOOLS', 'OPENBAO_TOOLS'],
            'legacy_mcp_endpoint': 'https://mcp.example.test/mcp/',
            'deploy_map': 'estate/deploy-map.json',
            'preserved_services': ['homepage'],
            'deployment': {'id': 'synthetic', 'title': 'Synthetic', 'theme': 'light', 'color': 'gray'},
            'tile_dispositions': {'Test': 'declared but unavailable in review; not a validated fallback'},
            'tile_availability': {},
            'widget_status_tiles': ['Test']}


def write_layout_fixture(operator_dir, layout=None):
    """Write `source-layout.json` beside a baseline in an operator directory and return the document.

    privacy checks: the capture reads the layout from the same operator directory the baselines live in, so every
    case that runs `prepare_migration.py` for real needs one — and only that script ever opens it.
    """
    document = synthetic_layout() if layout is None else layout
    directory = Path(operator_dir)
    directory.mkdir(parents=True, exist_ok=True)
    (directory/'source-layout.json').write_text(json.dumps(document), encoding='utf-8')
    return document


class MigrationTests(unittest.TestCase):
    def test_capture_and_drift_are_read_only_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = write_source_fixture(root)
            layout = synthetic_layout()
            capture, check = module('prepare_migration').capture, module('check_migration').check
            baseline = capture(root, layout)
            report = check(baseline, root)
            self.assertTrue(report['preparation_valid'])
            self.assertFalse(report['migration_ready'])
            self.assertEqual(report['counts']['panels'], 1)
            for name, raw in files.items():
                self.assertEqual((root/name).read_text(), raw)
            damaged = copy.deepcopy(baseline)
            damaged['dashboards'][0]['href'] = 'https://wrong.test/'
            self.assertFalse(check(damaged, root)['preparation_valid'])
            damaged = copy.deepcopy(baseline)
            damaged['sources']['../outside'] = hashlib.sha256(b'').hexdigest()
            self.assertFalse(check(damaged, root)['preparation_valid'])
            (root/'estate/deploy-map.json').write_text('{"hosts": {}, "changed": true}')
            self.assertFalse(check(baseline, root)['preparation_valid'])


class BaselineLocationTests(unittest.TestCase):
    """deployment separation (decision deployment separation): the baselines are operator files, so every reader needs that directory.

    The product tree ships no ``migration/estate/`` and keeps no default path to one, so the only
    ways in are ``--baseline-dir`` (the argument wins) and the ``LO_MIGRATION_BASELINE_DIR``
    environment variable. A missing input is refused before any source file is read, and a generated
    capture cannot land back inside this checkout.
    """

    REFUSAL_TOKENS = (BASELINE_ENV, "operator's repository")

    def run_script(self, name, arguments=(), environment=None):
        """Run one gate script as the operator would, with this variable absent unless supplied."""
        base = {key: value for key, value in os.environ.items() if key != BASELINE_ENV}
        base.update(environment or {})
        return subprocess.run([sys.executable, '-B', str(SCRIPTS/name), *arguments],
                              capture_output=True, text=True, env=base, cwd=str(ROOT))

    def assert_refused(self, result):
        """A refusal is exit 2 explained on stderr, naming the variable and the operator's repository."""
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertNotIn('Traceback', result.stderr, result.stderr)
        for token in self.REFUSAL_TOKENS:
            self.assertIn(token, result.stderr, result.stderr)

    def test_the_product_tree_ships_no_baseline_directory(self):
        """deployment separation in one assertion: nothing here may grow a `migration/` again."""
        self.assertFalse((ROOT/'migration').exists(),
                         'private preparation inputs belong in the operator repository (deployment separation)')

    def test_each_reader_refuses_when_neither_the_argument_nor_the_variable_is_set(self):
        cases = {
            'check_migration.py': (),
            'prepare_migration.py': (),
            'prepare_customisation_candidate.py': ('--operator-url', 'https://example.test',
                                                   '--output', str(ROOT/'scratch/r17a-no-baseline')),
        }
        for name, arguments in cases.items():
            with self.subTest(script=name):
                self.assert_refused(self.run_script(name, arguments))
        self.assertFalse((ROOT/'scratch/r17a-no-baseline').exists(), 'a refusal writes nothing')

    def test_a_directory_holding_no_capture_is_refused_by_name(self):
        """The second half of the rule: a configured directory without the file is still a refusal."""
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory)/'operator'
            empty.mkdir()
            candidate = ('--operator-url', 'https://example.test', '--output', str(Path(directory)/'out'))
            cases = [
                ('check_migration.py', '--baseline-only by variable', ('--baseline-only',),
                 {BASELINE_ENV: str(empty)}),
                ('check_migration.py', '--baseline-only by argument',
                 ('--baseline-only', '--baseline-dir', str(empty)), None),
                ('prepare_customisation_candidate.py', 'candidate by variable', candidate,
                 {BASELINE_ENV: str(empty)}),
                ('prepare_customisation_candidate.py', 'candidate by argument',
                 candidate + ('--baseline-dir', str(empty)), None),
            ]
            for name, label, arguments, environment in cases:
                with self.subTest(case=label):
                    result = self.run_script(name, arguments, environment)
                    self.assert_refused(result)
                    self.assertIn('baseline-02.json', result.stderr, result.stderr)
                    self.assertIn(str(empty), result.stderr, result.stderr)

    def test_the_capture_is_read_from_the_operator_directory_by_variable_or_argument(self):
        """A valid baseline outside the checkout runs the gate, and the argument wins over the variable."""
        with tempfile.TemporaryDirectory() as directory:
            root, operator, wrong = Path(directory)/'source', Path(directory)/'operator', Path(directory)/'wrong'
            write_source_fixture(root)
            operator.mkdir()
            wrong.mkdir()
            # privacy checks: the layout travels beside the baselines, and only the capture ever opens it.
            layout = write_layout_fixture(operator)
            (operator/'baseline-02.json').write_text(json.dumps(module('prepare_migration').capture(root, layout)),
                                                     encoding='utf-8')
            cases = (('--baseline-dir argument wins over the variable',
                      ['--baseline-dir', str(operator)], {BASELINE_ENV: str(wrong)}),
                     ('the variable alone is enough', [], {BASELINE_ENV: str(operator)}))
            for label, arguments, environment in cases:
                with self.subTest(case=label):
                    result = self.run_script('check_migration.py',
                                             ['--source', str(root), '--baseline-only', *arguments], environment)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertTrue(json.loads(result.stdout)['preparation_valid'])

    def test_a_generated_capture_must_not_land_in_the_product_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root, operator = Path(directory)/'source', Path(directory)/'operator'
            write_source_fixture(root)
            operator.mkdir()
            write_layout_fixture(operator)      # privacy checks: the capture reads its estate from here
            inside = ROOT/'scratch/r17a-must-not-be-written.json'
            refused = self.run_script('prepare_migration.py',
                                      ['--source', str(root), '--baseline-dir', str(operator),
                                       '--output', str(inside)])
            self.assertEqual(refused.returncode, 2, refused.stderr)
            self.assertIn('deployment separation', refused.stderr, refused.stderr)
            self.assertFalse(inside.exists(), 'the refusal must come before any write')
            fresh = self.run_script('prepare_migration.py',
                                    ['--source', str(root), '--baseline-dir', str(operator)])
            self.assertEqual(fresh.returncode, 0, fresh.stderr)
            self.assertTrue((operator/'baseline-next.json').is_file(),
                            'the default output is a NEW file in the operator directory')
            again = self.run_script('prepare_migration.py',
                                    ['--source', str(root), '--baseline-dir', str(operator)])
            self.assertNotEqual(again.returncode, 0, 'an existing capture is never overwritten')

    def test_a_directory_inside_this_checkout_is_refused(self):
        """Pointing the variable back at the product tree is the half of deployment separation an operator can undo by hand."""
        for arguments in (('--baseline-dir', 'migration'), ('--baseline-dir', str(ROOT/'scratch'))):
            with self.subTest(argument=arguments[-1]):
                result = self.run_script('check_migration.py', arguments + ('--baseline-only',))
                self.assert_refused(result)
                self.assertIn('deployment separation', result.stderr, result.stderr)

    def test_a_capture_name_cannot_reach_outside_the_operator_directory(self):
        check = module('check_migration')
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory)/'baseline-02.json').write_text('{}', encoding='utf-8')
            for name in ('../baseline-02.json', str(Path(directory)/'baseline-02.json'), 'sub/baseline.json'):
                with self.subTest(name=name), self.assertRaises(ValueError) as caught:
                    check.baseline_file(Path(directory), name)
                self.assertIn('file name inside the baseline directory', str(caught.exception))

    def test_a_blank_variable_counts_as_unset(self):
        """A half-configured shell must not silently point the gate at the working directory."""
        check = module('check_migration')
        for value in ('', '   '):
            with self.subTest(value=repr(value)), mock.patch.dict(os.environ, {BASELINE_ENV: value}):
                with self.assertRaises(ValueError) as caught:
                    check.baseline_file()
                self.assertIn(BASELINE_ENV, str(caught.exception))



if __name__ == '__main__':
    unittest.main()

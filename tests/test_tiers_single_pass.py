"""The dependency import boundary: each start directory executes exactly once, and ``collected`` is counted before it.

The fault injection adds ``--only-tier`` here: the cases that pin what the flag keeps, what it refuses and the
table it selects from.

Drives ``tests/tiers.py`` over tiny uniquely-named fixture directories -- never the repository suite
-- and never imports coverage, which the plain base tier must run without.
"""
from __future__ import annotations

import ast
import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))

import tiers  # noqa: E402

GATE = "sys.platform == 'the dependency import boundary-not-a-platform'"
BROKEN_IMPORT = 'import local_observe_module_that_cannot_exist\n'
NO_TESTS = "def helper():\n    return 'a module discovery loads and finds nothing in'\n"
TIER_KEYS = {'start_dir', 'collected', 'ran', 'skipped', 'expected_failures', 'unexpected_successes',
             'failures', 'errors', 'error_traces', 'collection_errors', 'skips'}
_counter = itertools.count()

# One of every outcome the report keeps a bucket for: seven tests, seven outcomes.
MIXED = """import sys
import unittest


class Mixed154(unittest.TestCase):
    def test_passed(self): pass

    def test_failed(self): self.assertEqual('collected-once', 'counted-before-run')

    def test_errored(self): raise RuntimeError('the dependency import boundary deliberate error')

    @unittest.skipUnless(__GATE__, 'posix gate: the dependency import boundary needs a posix filesystem')
    def test_skipped_by_decorator(self): raise AssertionError('a skipped test must not run')

    def test_skipped_at_runtime(self): self.skipTest('optional dependency the dependency import boundary extra is missing')

    @unittest.expectedFailure
    def test_fails_as_declared(self): self.fail('the dependency import boundary failure that was asked for')

    @unittest.expectedFailure
    def test_passes_unasked(self): pass
""".replace('__GATE__', GATE)

# A refused class fixture and a class skipped from setUpClass: both collected, neither runs.
FIXTURES = """import unittest


class ClassError154(unittest.TestCase):
    @classmethod
    def setUpClass(cls): raise RuntimeError('the dependency import boundary class fixture refused')

    def test_one(self): self.fail('a refused class fixture must not run')

    def test_two(self): self.fail('a refused class fixture must not run')


class ClassSkip154(unittest.TestCase):
    @classmethod
    def setUpClass(cls): raise unittest.SkipTest('optional dependency the dependency import boundary extra is missing')

    def test_three(self): self.fail('a skipped class must not run')

    def test_four(self): self.fail('a skipped class must not run')
"""

SUBTESTS = """import unittest


class Subtest154(unittest.TestCase):
    def test_two_cases(self):
        for label in ('alpha', 'beta'):
            with self.subTest(case=label):
                if label == 'beta':
                    self.fail('the dependency import boundary one subcase fails')
"""

# Two classes, each ticking a file as it runs: a tier filter has to execute one and never start the
# other, which a count alone cannot tell apart from running both and reporting one.
FILTERED = """from pathlib import Path
import unittest

COUNTER = Path(%r)


def tick(label):
    with COUNTER.open('a', encoding='utf-8') as handle:
        handle.write(str(label) + '\\n')


tick('import')


class Kept251(unittest.TestCase):
    def test_alpha(self): tick('alpha')

    def test_beta(self): tick('beta')


class Dropped251(unittest.TestCase):
    def test_gamma(self): tick('gamma')

    def test_delta(self): tick('delta')

    def test_epsilon(self): tick('epsilon')
"""

# One mcp-module probe. The backslash in the pattern is what keeps this file out of its own scan:
# the pattern asks for `find_spec(` and this source carries `find_spec\(`.
MCP_PROBE = re.compile(r'''find_spec\(\s*['"]mcp['"]''')

# Files that name the probe without gating a test on it: an assertion about the workflow's venv
# checks, in a string. The guard below compares this list with what the scan finds, so a file that
# joins it -- a gate written in a shape the scan does not read, or a probe left behind by a deleted
# gate -- has to be explained here before it can go unregistered.
MCP_PROBE_WITHOUT_A_GATE = {
    'test_ci_single_pass.py': 'asserts the workflow proves the base venv has no mcp',
}


def mcp_gates(root: Path) -> tuple[list[str], list[str], list[str]]:
    """Scan the real test tree for decorators that gate on the optional mcp extra.

    Returns ``(mcp_only, extra_present, unexplained)`` as sorted ``module.Class`` / ``module.Class.method``
    ids: classes and methods that run only when the extra is installed, the ones that run only when it
    is absent (``skipIf``), and files carrying a probe that no gate of either kind explains.

    The scan reads source text and imports nothing: the fact under test is which decorators are
    written in ``tests/``, and importing a test module to ask would execute its module-level code --
    the same reason this file never runs discovery over the repository suite.
    """
    mcp_only: list[str] = []
    extra_present: list[str] = []
    unexplained: list[str] = []
    for path in sorted(root.rglob('test_*.py')):
        source = path.read_text(encoding='utf-8')
        if not MCP_PROBE.search(source):
            continue
        gates_here = 0
        for node in ast.walk(ast.parse(source, filename=str(path))):
            if not isinstance(node, ast.ClassDef):
                continue
            for decorator in node.decorator_list:
                text = ast.get_source_segment(source, decorator) or ''
                if not MCP_PROBE.search(text):
                    continue
                gates_here += 1
                target = f'{path.stem}.{node.name}'
                if 'skipUnless' in text:
                    mcp_only.append(target)
                elif 'skipIf' in text:
                    extra_present.append(target)
            for method in node.body:
                if not isinstance(method, ast.FunctionDef):
                    continue
                for decorator in method.decorator_list:
                    text = ast.get_source_segment(source, decorator) or ''
                    if not MCP_PROBE.search(text):
                        continue
                    gates_here += 1
                    target = f'{path.stem}.{node.name}.{method.name}'
                    if 'skipUnless' in text:
                        mcp_only.append(target)
                    elif 'skipIf' in text:
                        extra_present.append(target)
        if not gates_here:
            unexplained.append(path.name)
    return sorted(mcp_only), sorted(extra_present), sorted(unexplained)


def counting_source(counter: Path, names: list[str]) -> str:
    """Return a module with one test per name that ticks ``counter``, plus one import-time tick."""
    body = ''.join(f"\n    def test_{name}(self): tick({name!r})\n" for name in names)
    return ("import unittest\nfrom pathlib import Path\n\nCOUNTER = Path(%r)\n\n\n"
            "def tick(label):\n"
            "    with COUNTER.open('a', encoding='utf-8') as handle:\n"
            "        handle.write(str(label) + '\\n')\n\n\n"
            "tick('import')\n\n\nclass Counted154(unittest.TestCase):" % str(counter)) + body


class ConsumedSuite(unittest.TestSuite):
    """Suite wrapper whose countTestCases() drops to 0 once run, so a late read would report 0."""

    def __init__(self, tests: list) -> None:
        super().__init__(tests)
        self.total = sum(test.countTestCases() for test in tests)
        self.executed = False

    def run(self, result):
        self.executed = True
        return super().run(result)

    def countTestCases(self) -> int:
        return 0 if self.executed else self.total


class Scratch:
    """Scratch directory, uniquely-named fixture modules, import restore, in-process and CLI runs."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.json_path = self.root / 'tier-report.json'
        self.stem: dict[str, str] = {}
        self.imported: list[str] = []
        path_before = list(sys.path)
        self.addCleanup(self.restore_imports, path_before)

    def restore_imports(self, path_before: list[str]) -> None:
        """Drop the fixture modules and paths discovery left behind, so the real suite sees neither."""
        for stem in self.imported:
            sys.modules.pop(stem, None)
        sys.path[:] = path_before

    def fixture_dir(self, role: str, source: str | None) -> Path:
        """Write one fixture module under a stem that is unique in this process and importable."""
        target = self.root / role
        target.mkdir()
        if source is not None:
            stem = f'test_c154_{role.replace("-", "_")}_{next(_counter):04d}'
            (target / f'{stem}.py').write_text(source, encoding='utf-8')
            self.stem[role] = stem
            self.imported.append(stem)
        return target

    def counting_dir(self, role: str, names: list[str]) -> Path:
        return self.fixture_dir(role, counting_source(self.root / f'counter-{role}.txt', names))

    def ticks(self, role: str) -> dict[str, int]:
        """Return {label: times written} for a counting directory: executions, not imports."""
        path = self.root / f'counter-{role}.txt'
        lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
        return {label: lines.count(label) for label in set(lines)}

    def argv(self, dirs: list[Path], flags: list[str], json_path: Path | None = None) -> list[str]:
        return (['--json', str(json_path or self.json_path)]
                + [item for d in dirs for item in ('--start-dir', str(d))] + list(flags))

    def capture(self, action):
        printed, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(errors):
            return action(), printed.getvalue(), errors.getvalue()

    def run_main(self, *dirs: Path) -> tuple[int, dict, str, str]:
        """Run ``tiers.main`` in-process; return exit status, read-back report, stdout, stderr."""
        code, printed, errors = self.capture(lambda: tiers.main(self.argv(list(dirs), [])))
        return code, self.read_json(), printed, errors

    def cli(self, *dirs: Path, flags: list[str] = (),
            json_path: Path | None = None) -> subprocess.CompletedProcess:
        """Run the tool the way CI does, in a real subprocess started inside the scratch directory."""
        argv = [sys.executable, '-B', str(ROOT / 'tests' / 'tiers.py'),
                *self.argv(list(dirs), flags, json_path)]
        return subprocess.run(argv, cwd=str(self.root), env=dict(os.environ, PYTHONIOENCODING='utf-8'),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              encoding='utf-8', errors='replace', timeout=180)

    def read_json(self, path: Path | None = None) -> dict:
        return json.loads((path or self.json_path).read_text(encoding='utf-8'))


class SinglePassTests(Scratch, unittest.TestCase):
    """One execution per requested directory, and a collection count that outlives that execution."""

    def test_each_start_directory_executes_exactly_once(self) -> None:
        """Two directories, one pass each, in quiet and in verbose mode."""
        for verbose in (False, True):
            with self.subTest(verbose=verbose):
                first = self.counting_dir(f'once-a-{verbose}', ['alpha', 'beta'])
                second = self.counting_dir(f'once-b-{verbose}', ['gamma'])
                report, printed, errors = self.capture(
                    lambda: tiers.build_report([str(first), str(second)], verbose=verbose))
                self.assertEqual([str(first), str(second)], [t['start_dir'] for t in report['tiers']])
                self.assertEqual({'import': 1, 'alpha': 1, 'beta': 1}, self.ticks(f'once-a-{verbose}'),
                                  'a test body ran more or fewer times than once')
                self.assertEqual({'import': 1, 'gamma': 1}, self.ticks(f'once-b-{verbose}'),
                                 'the second directory paid for the first one as well')
                self.assertEqual({'collected': 3, 'ran': 3, 'skipped': 0, 'failures': 0, 'errors': 0,
                                  'collection_errors': 0}, report['totals'])
                self.assertEqual(verbose, 'test_alpha' in printed + errors,
                                 'per-test output must follow the verbose flag and nothing else')

    def test_a_subprocess_tier_executes_exactly_once(self) -> None:
        """The claim CI cares about, measured by the child process CI would have started."""
        target = self.counting_dir('clipass', ['alpha', 'beta'])
        completed = self.cli(target, flags=['--verbose'])
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual({'import': 1, 'alpha': 1, 'beta': 1}, self.ticks('clipass'))
        self.assertIn(f"{self.stem['clipass']}.Counted154.test_alpha) ... ok", completed.stderr)
        self.assertEqual(2, self.read_json()['tiers'][0]['collected'])

    def test_collected_is_counted_before_the_suite_is_consumed(self) -> None:
        """A suite that reports nothing once walked must still be reported as what discovery found."""
        target = self.counting_dir('snapshot', ['alpha', 'beta'])
        original = unittest.TestLoader.discover

        def discover(loader, *args, **kwargs):
            return ConsumedSuite(original(loader, *args, **kwargs))

        unittest.TestLoader.discover = discover
        self.addCleanup(setattr, unittest.TestLoader, 'discover', original)
        tier, _printed, _errors = self.capture(lambda: tiers.run_start_dir(str(target)))
        self.assertEqual(2, tier.collected, 'collected was read off a suite the run had consumed')
        self.assertEqual(2, tier.ran)
        self.assertEqual({'import': 1, 'alpha': 1, 'beta': 1}, self.ticks('snapshot'))

    def test_every_result_class_lands_in_its_own_bucket_once(self) -> None:
        """Pass, fail, error, two skips, expected failure, unexpected success: seven, none lost."""
        target = self.fixture_dir('mixed', MIXED)
        code, report, _printed, _errors = self.run_main(target)
        tier, stem = report['tiers'][0], self.stem['mixed']
        self.assertEqual(1, code)
        self.assertEqual({'collected': 7, 'ran': 7, 'skipped': 2},
                         {key: tier[key] for key in ('collected', 'ran', 'skipped')})
        self.assertEqual([f'{stem}.Mixed154.test_failed'], tier['failures'])
        self.assertEqual([f'{stem}.Mixed154.test_errored'], tier['errors'])
        self.assertEqual([f'{stem}.Mixed154.test_fails_as_declared'], tier['expected_failures'])
        self.assertEqual([f'{stem}.Mixed154.test_passes_unasked'], tier['unexpected_successes'])
        self.assertEqual(2, len({skip['test'] for skip in tier['skips']}), 'one id per skipped test')

    def test_class_fixture_errors_and_skips_are_collected_but_never_run(self) -> None:
        """collected > ran is legitimate here: unittest refuses a class without starting its tests."""
        target = self.fixture_dir('fixtures', FIXTURES)
        code, report, printed, _errors = self.run_main(target)
        tier = report['tiers'][0]
        self.assertEqual(1, code)
        self.assertEqual(4, tier['collected'])
        self.assertEqual(0, tier['ran'], 'no test of a refused or skipped class is ever started')
        self.assertEqual([], tier['collection_errors'], 'the module imported, so this is not one')
        self.assertIn('setUpClass', tier['errors'][0])
        self.assertIn('ClassError154', tier['errors'][0])
        self.assertIn('setUpClass', tier['skips'][0]['test'])
        self.assertIn('setUpClass', printed, 'the table names the id that did not pass')

    def test_a_subtest_failure_is_one_test_and_names_its_parameters(self) -> None:
        """Two subcases are one collected test, and the failing one stays identifiable."""
        target = self.fixture_dir('subtest', SUBTESTS)
        code, report, _printed, _errors = self.run_main(target)
        tier = report['tiers'][0]
        self.assertEqual(1, code)
        self.assertEqual(1, tier['collected'])
        self.assertEqual(1, tier['ran'])
        self.assertEqual(1, len(tier['failures']), f'one failing subcase, got {tier["failures"]}')
        self.assertIn('Subtest154.test_two_cases', tier['failures'][0])
        self.assertIn("case='beta'", tier['failures'][0], 'the failing case is not merged away')
        self.assertIn('the dependency import boundary one subcase fails', tier['error_traces'][0])

    def test_a_directory_that_collects_nothing_is_a_collection_error(self) -> None:
        """Empty, test-less and unimportable directories are collection errors, never a green tier."""
        for label, source, collected in (('empty', None, 0), ('loaded', NO_TESTS, 0),
                                         ('unimportable', BROKEN_IMPORT, 1)):
            with self.subTest(case=label):
                good = self.counting_dir(f'good-{label}', ['alpha'])
                nothing = self.fixture_dir(f'nothing-{label}', source)
                code, report, printed, _errors = self.run_main(good, nothing)
                tier = report['tiers'][1]
                self.assertEqual(1, code, 'collecting nothing is a collection error, not a pass')
                self.assertIn('collection error:', printed)
                self.assertEqual(collected, tier['collected'])
                self.assertEqual(collected, tier['ran'])
                self.assertEqual(0, tier['skipped'], 'a tier that said nothing says no skips either')
                self.assertEqual(str(nothing), tier['start_dir'], 'the guilty tier is the one it names')
                self.assertTrue([line for line in tier['collection_errors'] if line.strip()],
                                f'a collection error that says nothing is no help: {tier}')
                if collected:
                    stem = self.stem[f'nothing-{label}']
                    self.assertIn(stem, tier['collection_errors'][0])
                    self.assertIn(stem, tier['errors'][0], 'the placeholder error names the module too')
                self.assertEqual(1, report['tiers'][0]['collected'], 'the other tier is untouched')
                self.assertEqual({'import': 1, 'alpha': 1}, self.ticks(f'good-{label}'))

    def test_verbose_changes_the_output_and_not_the_document(self) -> None:
        """schema_version 1, the same tier fields and the same tallies, verbose or not."""
        target = self.fixture_dir('shape', MIXED)
        quiet, printed, errors = self.capture(lambda: tiers.build_report([str(target)]))
        loud, loud_out, loud_err = self.capture(
            lambda: tiers.build_report([str(target)], verbose=True))
        self.assertEqual('', printed + errors, 'the default is quiet per test')
        self.assertIn('test_passed', loud_err)
        self.assertEqual('', loud_out, 'verbose writes on stderr, leaving stdout to the table')
        self.assertEqual(1, quiet['schema_version'])
        self.assertEqual(TIER_KEYS, set(quiet['tiers'][0]))
        self.assertEqual(json.dumps(quiet['tiers'], sort_keys=True),
                         json.dumps(loud['tiers'], sort_keys=True),
                         'verbose changed what the report says, not only what it printed')


class CommandLineTests(Scratch, unittest.TestCase):
    """The CLI as CI invokes it: real subprocess, real exit status, real artifact on disk."""

    def test_expected_failure_and_unexpected_success_decide_the_exit_alone(self) -> None:
        for verbose in (False, True):
            for fails in (False, True):
                with self.subTest(verbose=verbose, fails=fails):
                    body = "self.fail('expected')" if fails else 'pass'
                    source = ('import unittest\nclass Expected(unittest.TestCase):\n'
                              '    @unittest.expectedFailure\n    def test_result(self):\n'
                              f'        {body}\n')
                    target = self.fixture_dir(f'expected-{verbose}-{fails}', source)
                    completed = self.cli(target, flags=['--verbose'] if verbose else [])
                    tier = self.read_json()['tiers'][0]
                    self.assertEqual(0 if fails else 1, completed.returncode, completed.stderr)
                    self.assertEqual([], tier['failures'] + tier['errors'] + tier['collection_errors'])
                    self.assertEqual(int(fails), len(tier['expected_failures']))
                    self.assertEqual(int(not fails), len(tier['unexpected_successes']))

    def test_every_cli_mode_reports_the_failing_tier_it_ran(self) -> None:
        """Default and --quiet both exit 1 on a red tier, honour --json, and stay quiet per test."""
        target = self.fixture_dir('cli', MIXED)
        nested = self.root / 'reports' / 'tier-report-base.json'
        nested.parent.mkdir()
        for label, flags in (('default', []), ('quiet', ['--quiet'])):
            with self.subTest(case=label):
                completed = self.cli(target, flags=flags, json_path=nested)
                tier = self.read_json(nested)['tiers'][0]
                self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
                self.assertEqual(7, tier['collected'])
                self.assertEqual([f"{self.stem['cli']}.Mixed154.test_failed"], tier['failures'])
                self.assertFalse(self.json_path.exists(), '--json decides where the artifact goes')
                self.assertNotIn('test_passed', completed.stdout + completed.stderr,
                                 'without --verbose the run must stay quiet per test')
                if flags:
                    self.assertEqual('', completed.stdout, '--quiet buys silence, not success')
                else:
                    self.assertIn('tier report', completed.stdout)
                    self.assertIn(str(nested), completed.stdout, 'the table says where the report went')
                    self.assertIn('the dependency import boundary deliberate error', completed.stderr, 'traces stay on stderr')

    def test_quiet_and_verbose_conflict_exits_two_before_anything_runs(self) -> None:
        """Mutually exclusive flags: status 2, both named, no artifact written, nothing executed."""
        target = self.counting_dir('conflict', ['alpha'])
        completed = self.cli(target, flags=['--quiet', '--verbose'])
        self.assertEqual(2, completed.returncode, completed.stderr)
        self.assertIn('--quiet', completed.stderr)
        self.assertIn('--verbose', completed.stderr)
        self.assertFalse(self.json_path.exists(), 'a refused command line must not write a report')
        self.assertEqual({}, self.ticks('conflict'), 'a refused command line must not run the tier')

    def test_the_existing_command_line_still_parses(self) -> None:
        """Old argument lists keep their meaning: repeatable directories, default JSON path, no flags."""
        args = tiers.parse_args(['--start-dir', 'tests', '--start-dir', 'tests/compiler',
                                 '--json', 'out.json'])
        self.assertEqual(['tests', 'tests/compiler'], args.start_dirs)
        self.assertEqual('out.json', args.json_path)
        self.assertEqual(str(tiers.DEFAULT_JSON), tiers.parse_args([]).json_path)
        self.assertFalse(args.quiet or args.verbose, 'both output levels default to off')
        self.assertTrue(tiers.parse_args(['--verbose']).verbose)
        self.assertFalse(tiers.parse_args(['--verbose']).quiet)
        self.assertTrue(tiers.parse_args(['--quiet']).quiet)
        self.assertFalse(tiers.parse_args(['--quiet']).verbose)


class TierFilterTests(Scratch, unittest.TestCase):
    """The fault injection: ``--only-tier`` executes the ids one tier owns and never the rest of the directory."""

    def filtered_dir(self, role: str) -> Path:
        """One module, two counting classes: the filter may execute one of them and import both."""
        return self.fixture_dir(role, FILTERED % str(self.root / f'counter-{role}.txt'))

    def with_table(self, tier: str, selectors: tuple[str, ...]) -> None:
        """Swap the tier table for the duration of this test, so a fixture module can own a tier."""
        self.addCleanup(setattr, tiers, 'TIER_TESTS', tiers.TIER_TESTS)
        tiers.TIER_TESTS = {tier: selectors}

    def test_the_flag_parses_and_the_default_carries_no_filter(self) -> None:
        """An argument list without the flag means what it meant before it existed."""
        self.assertIsNone(tiers.parse_args([]).only_tier, 'the default runs what discovery finds')
        self.assertIsNone(tiers.parse_args(['--start-dir', 'tests']).only_tier)
        self.assertEqual('mcp', tiers.parse_args(['--only-tier', 'mcp']).only_tier)

    def test_only_tier_runs_what_it_owns_and_never_the_rest(self) -> None:
        """The claim the flag exists for: two classes in one directory, one class executed."""
        target = self.filtered_dir('filter-kept')
        self.with_table('c251', (f'{self.stem["filter-kept"]}.Kept251',))
        code, printed, errors = self.capture(
            lambda: tiers.main(self.argv([target], ['--only-tier', 'c251'])))
        self.assertEqual(0, code, printed + errors)
        report = self.read_json()
        tier = report['tiers'][0]
        self.assertEqual(2, tier['collected'], 'collected counted the whole directory, not the tier')
        self.assertEqual(2, tier['ran'])
        self.assertEqual({'import': 1, 'alpha': 1, 'beta': 1}, self.ticks('filter-kept'),
                         'a class the filter dropped still executed')
        self.assertEqual('c251', report['only_tier'], 'the artifact does not say it is a slice')
        self.assertIn('--only-tier c251', printed, 'the table must say which filter produced it')

    def test_an_unfiltered_tier_records_no_filter_and_runs_the_directory(self) -> None:
        """The base tier keeps its old meaning exactly: every id in the directory, no filter line."""
        target = self.filtered_dir('filter-all')
        code, report, printed, errors = self.run_main(target)
        self.assertEqual(0, code, printed + errors)
        self.assertIsNone(report['only_tier'], 'an unfiltered artifact claims a filter')
        self.assertEqual(5, report['tiers'][0]['collected'])
        self.assertEqual({'import': 1, 'alpha': 1, 'beta': 1, 'gamma': 1, 'delta': 1, 'epsilon': 1},
                         self.ticks('filter-all'))
        self.assertNotIn('tier filter', printed)

    def test_a_selector_matches_at_the_dot_and_not_inside_a_name(self) -> None:
        """Class, module and method selectors keep their own tests and no neighbour's."""
        selectors = ('test_a.TestX', 'test_b.', 'test_c.Case.test_one')
        for test_id in ('test_a.TestX.test_one', 'test_b.OtherCase.test_two', 'test_c.Case.test_one'):
            self.assertTrue(tiers.id_selected(test_id, selectors), f'{test_id} belongs to the tier')
        for test_id in ('test_a.TestXY.test_one', 'test_c.Case.test_two', 'test_d.TestX.test_one'):
            self.assertFalse(tiers.id_selected(test_id, selectors), f'{test_id} belongs to no tier here')
        self.assertEqual((), tiers.tier_selectors(None), 'no flag must mean no filter, not no tests')
        self.assertEqual(tiers.TIER_TESTS['mcp'], tiers.tier_selectors('mcp'))

    def test_a_filter_that_selects_nothing_is_a_collection_error(self) -> None:
        """Run through CI's own command line: an empty slice is red, and it says which filter failed."""
        target = self.filtered_dir('filter-empty')
        completed = self.cli(target, flags=['--only-tier', 'mcp'])
        self.assertEqual(1, completed.returncode, completed.stdout + completed.stderr)
        tier = self.read_json()['tiers'][0]
        self.assertEqual(0, tier['collected'])
        self.assertEqual(0, tier['ran'])
        self.assertEqual([], tier['skips'], 'a tier that ran nothing reports no skips')
        self.assertIn('--only-tier mcp selected no test under', tier['collection_errors'][0])
        self.assertIn(str(target), tier['collection_errors'][0], 'the error names the directory too')
        self.assertIn('--only-tier mcp selected no test under', completed.stdout,
                      'the table prints the collection error, not only the JSON')
        self.assertEqual({'import': 1}, self.ticks('filter-empty'),
                         'discovery still imports the module; no test body of it may run')

    def test_an_unknown_tier_is_refused_before_anything_runs(self) -> None:
        """argparse choices: status 2, the real tier names printed, no artifact, no test executed."""
        target = self.filtered_dir('filter-bad')
        completed = self.cli(target, flags=['--only-tier', 'the fault injection-not-a-tier'])
        self.assertEqual(2, completed.returncode, completed.stderr)
        self.assertIn('--only-tier', completed.stderr)
        self.assertIn('mcp', completed.stderr, 'the refusal must name the tiers that do exist')
        self.assertFalse(self.json_path.exists(), 'a refused command line must not write a report')
        self.assertEqual({}, self.ticks('filter-bad'))

    def test_the_mcp_table_owns_every_mcp_gate_written_in_the_tree(self) -> None:
        """An unregistered gate skips in the base tier and never runs anywhere: the gap this pins.

        Reads the decorators with ``ast`` and imports nothing, so it costs a file walk and not a suite
        pass. A probe the scan cannot attribute to a gate has to be listed in MCP_PROBE_WITHOUT_A_GATE
        with a reason, which is what makes a new gate style fail here rather than go uncounted.
        """
        mcp_only, extra_present, unexplained = mcp_gates(ROOT / 'tests')
        self.assertEqual(sorted(MCP_PROBE_WITHOUT_A_GATE), unexplained,
                         'a test file gates on the mcp extra in a shape this scan does not read: '
                         'teach the scan or explain the file, never add it to the table silently')
        self.assertTrue(mcp_only, 'the scan found no mcp gate at all, which is how a broken pattern '
                                  'would look')
        self.assertEqual(sorted(tiers.TIER_TESTS['mcp']), mcp_only,
                         'tests/ and tiers.TIER_TESTS disagree about which ids need the mcp extra')
        self.assertEqual([], [gate for gate in extra_present
                              if tiers.id_selected(gate, tiers.TIER_TESTS['mcp'])],
                         'a gate that skips WHEN the extra is installed must not sit in the mcp tier: '
                         'it would skip in both environments and run in neither')
        for selector in tiers.TIER_TESTS['mcp']:
            stem = selector.split('.')[0]
            self.assertTrue(list((ROOT / 'tests').rglob(f'{stem}.py')),
                            f'{selector} names no test module in tests/')

"""Self-test for ``tests/tiers.py``, the tool CI uses to prove which tests ran and which skipped.

``tiers.py`` turns ``unittest``'s human-readable skips into a machine-readable report, and until
ledger test tooling the only thing that ever exercised it was CI itself. A broken skip parser would not have
failed a job: the tier report would simply have said "0 skipped" and the union of the tiers would
have looked complete. These tests drive ``tiers.main()`` over a throwaway start directory they build
themselves — one passing test, one gated skip carrying its own reason, one deliberate failure, and in
a directory of its own one module that cannot be imported — then read the JSON artifact back.

Discovery deliberately never runs over this repository's real ``tests/`` from inside a test: the
point of the tool is a count it reports about *other* people's tests, and the only way to assert a
count is to know what went in. Fixture module names are unique per test and their modules are dropped
from ``sys.modules`` and ``sys.path`` afterwards, because ``unittest`` discovery leaves both behind.
"""
from __future__ import annotations

import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))

import tiers  # noqa: E402  (tests/ is not a package; the tool sits beside this test)

# A gate expression that is false on every host this suite runs on, written in the shape the real
# gates use (a comparison against this machine), so the skip path is exercised on Windows and Linux
# alike. `os.name == 'posix'` would skip here and run on the CI runner.
GATE = "sys.platform == 'r21-not-a-platform'"

PASSING = '''import unittest


class Passing(unittest.TestCase):
    def test_passes(self):
        self.assertTrue(True)
'''

FAILING = '''import unittest


class Failing(unittest.TestCase):
    def test_fails(self):
        self.assertEqual(1, 2)
'''

GATED = '''import sys
import unittest


class Gated(unittest.TestCase):
%(methods)s'''

BROKEN = 'import local_observe_module_that_cannot_exist\n'

SKIP_REASON = 'posix gate: the symlink rebind needs a posix filesystem'

_COUNTER = itertools.count()


def next_token() -> str:
    """Return a short unique token, so no two fixture modules in one process share a stem."""
    return '%04d' % next(_COUNTER)


def gated_source(reasons: list[str]) -> str:
    """Return a test module holding one always-skipped test per entry of ``reasons``, in order."""
    methods = ''.join(
        f"\n    @unittest.skipUnless({GATE}, {reason!r})\n"
        f"    def test_gate_{index}(self):\n"
        f"        raise AssertionError('a skipped test must not run')\n"
        for index, reason in enumerate(reasons))
    return GATED % {'methods': methods}


class TierReportTests(unittest.TestCase):
    """What ``tiers.main()`` counts, prints, writes and returns for a directory it is handed."""

    def setUp(self) -> None:
        """Give each test its own scratch directory and remember the import state to restore."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.json_path = self.root / 'tier-report.json'
        self.imported: list[str] = []
        self.path_before = list(sys.path)
        self.addCleanup(self.restore_import_state)

    def restore_import_state(self) -> None:
        """Drop the fixture modules and paths discovery left behind, so the real suite sees neither.

        ``unittest`` loads every collected module into ``sys.modules`` under its file stem and puts the
        start directory on ``sys.path`` for good. Without this the next test in the process could
        import a fixture instead of a real module, and the scratch directory would outlive itself.
        """
        for name in self.imported:
            sys.modules.pop(name, None)
        sys.path[:] = self.path_before

    def directory(self, *files: tuple[str, str]) -> Path:
        """Write ``test_r21_<n>_<role>.py`` for each ``(role, source)`` pair; return their directory.

        The counter in the name keeps module stems unique across tests: two tests writing the same
        stem into two directories would share one loaded module, and the second discovery would run
        the first directory's code.
        """
        target = self.root / ('tier-' + next_token())
        target.mkdir()
        for role, source in files:
            stem = f'test_r21_{next_token()}_{role}'
            (target / f'{stem}.py').write_text(source, encoding='utf-8')
            self.imported.append(stem)
        return target

    def run_report(self, *start_dirs: Path, quiet: bool = False
                   ) -> tuple[int, dict, str, str]:
        """Run ``tiers.main`` over ``start_dirs``; return its exit status, report, stdout and stderr.

        Both streams are captured because the tool prints a table and the tracebacks of what failed:
        the assertions read them, and the suite's own output stays clean.
        """
        argv = ['--json', str(self.json_path)]
        for start_dir in start_dirs:
            argv += ['--start-dir', str(start_dir)]
        if quiet:
            argv.append('--quiet')
        printed, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(printed), contextlib.redirect_stderr(errors):
            code = tiers.main(argv)
        report = json.loads(self.json_path.read_text(encoding='utf-8'))
        return code, report, printed.getvalue(), errors.getvalue()

    def test_a_skip_is_counted_with_its_own_id_and_reason(self) -> None:
        """The claim the tool exists for: the skipped test keeps its id and the decorator's reason."""
        passing = self.directory(('passing', PASSING))
        gated = self.directory(('gated', gated_source([SKIP_REASON])))
        failing = self.directory(('failing', FAILING))
        stem = [name for name in self.imported if name.endswith('_gated')][0]

        code, report, printed, _ = self.run_report(passing, gated, failing)

        self.assertEqual(1, code, 'a directory with a failure must not report success')
        tier = next(item for item in report['tiers'] if item['start_dir'] == str(gated))
        self.assertEqual(1, tier['collected'])
        self.assertEqual(1, tier['ran'])
        self.assertEqual(1, tier['skipped'])
        self.assertEqual([{'test': f'{stem}.Gated.test_gate_0', 'reason': SKIP_REASON,
                           'category': 'posix-gate'}], tier['skips'])
        self.assertEqual([], tier['failures'])
        self.assertEqual([], tier['collection_errors'])
        self.assertEqual(3, report['totals']['ran'], 'one tier per start directory, joined by test id')
        self.assertEqual(1, report['totals']['skipped'])
        self.assertEqual(1, report['totals']['failures'])
        self.assertEqual([{'start_dir': str(gated), 'test': f'{stem}.Gated.test_gate_0',
                           'reason': SKIP_REASON, 'category': 'posix-gate'}], report['skips'])
        self.assertIn(f'{stem}.Gated.test_gate_0', printed, 'the table names the skipped test')
        self.assertIn(SKIP_REASON, printed)

    def test_a_clean_directory_exits_zero_and_says_there_were_no_skips(self) -> None:
        """0 skipped is only meaningful when the tool can tell "nothing skipped" from "nothing ran"."""
        passing = self.directory(('passing', PASSING))

        code, report, printed, _ = self.run_report(passing)

        self.assertEqual(0, code)
        tier = report['tiers'][0]
        self.assertEqual(1, tier['collected'])
        self.assertEqual(1, tier['ran'])
        self.assertEqual(0, tier['skipped'])
        self.assertEqual([], tier['skips'])
        self.assertIn('no skips here', printed)

    def test_a_failing_test_is_named_and_exits_one(self) -> None:
        """A failure is reported by id and the trace reaches stderr: never hidden behind a report."""
        failing = self.directory(('failing', FAILING))

        code, report, printed, errors = self.run_report(failing)

        self.assertEqual(1, code)
        tier = report['tiers'][0]
        stem = [name for name in self.imported if name.endswith('_failing')][0]
        self.assertEqual([f'{stem}.Failing.test_fails'], tier['failures'])
        self.assertEqual(0, tier['skipped'], 'a failure is never a skip')
        self.assertEqual([], tier['collection_errors'])
        self.assertIn(f'{stem}.Failing.test_fails', printed)
        self.assertIn('AssertionError: 1 != 2', errors)

    def test_an_unimportable_module_is_a_collection_error_not_a_skip(self) -> None:
        """The failure mode this tool could otherwise hide: a module that never loaded reports as a tier.

        ``unittest`` turns an unimportable module into a placeholder test that errors. What matters
        for the union of the tiers is that it is *not* counted as a skip — a tier that failed to load
        says nothing about its tests — and that the run is not clean.
        """
        broken = self.directory(('passing', PASSING), ('broken', BROKEN))

        code, report, printed, _ = self.run_report(broken)

        self.assertEqual(1, code)
        tier = report['tiers'][0]
        stem = [name for name in self.imported if name.endswith('_broken')][0]
        self.assertEqual(1, len(tier['collection_errors']))
        self.assertIn(stem, tier['collection_errors'][0])
        self.assertEqual(0, tier['skipped'])
        self.assertEqual([], tier['skips'])
        self.assertEqual(1, len(tier['errors']))
        self.assertTrue(any(stem in error for error in tier['errors']),
                        f'the placeholder error should name {stem}, got {tier["errors"]}')
        self.assertEqual(1, report['totals']['collection_errors'])
        self.assertIn('collection error:', printed)

    def test_skip_reasons_are_classified_by_their_own_wording(self) -> None:
        """The four buckets the table prints, including the catch-all a new skip must land in."""
        reasons = ['posix gate: needs a posix box', 'windows only: the PowerShell handoff',
                   'optional dependency mcp is not installed', 'fixture states nothing about this one']
        gated = self.directory(('gated', gated_source(reasons)))

        code, report, printed, _ = self.run_report(gated)

        self.assertEqual(0, code, 'a skip is not a failure')
        tier = report['tiers'][0]
        self.assertEqual(4, tier['skipped'])
        self.assertEqual(reasons, [skip['reason'] for skip in tier['skips']],
                         'every reason survives into the report verbatim, in the order taken')
        self.assertEqual(['posix-gate', 'windows-gate', 'optional-dependency', 'other'],
                         [skip['category'] for skip in tier['skips']])
        for reason in reasons:
            self.assertIn(reason, printed)

    def test_one_tier_per_start_directory_and_the_totals_join_them(self) -> None:
        """The union CI reads is these reports joined by test id: each directory keeps its own tally."""
        clean = self.directory(('passing', PASSING))
        noisy = self.directory(('failing', FAILING), ('gated', gated_source([SKIP_REASON])))

        code, report, _, _ = self.run_report(clean, noisy)

        self.assertEqual(1, code, 'one dirty tier makes the run dirty')
        self.assertEqual([str(clean), str(noisy)], [tier['start_dir'] for tier in report['tiers']])
        by_dir = {tier['start_dir']: tier for tier in report['tiers']}
        self.assertEqual([], by_dir[str(clean)]['failures'])
        self.assertEqual(1, len(by_dir[str(noisy)]['failures']))
        self.assertEqual({'collected': 3, 'ran': 3, 'skipped': 1, 'failures': 1, 'errors': 0,
                          'collection_errors': 0}, report['totals'])

    def test_quiet_writes_the_report_and_prints_nothing(self) -> None:
        """CI parses the artifact; --quiet must still produce it and stay silent on stdout."""
        gated = self.directory(('gated', gated_source([SKIP_REASON])))

        code, report, printed, _ = self.run_report(gated, quiet=True)

        self.assertEqual(0, code)
        self.assertEqual('', printed)
        self.assertTrue(self.json_path.exists())
        self.assertEqual(1, report['totals']['skipped'])

    def test_the_report_names_the_version_and_interpreter_it_came_from(self) -> None:
        """An artifact a human will compare across hosts has to say which host and interpreter it was."""
        passing = self.directory(('passing', PASSING))

        _, report, _, _ = self.run_report(passing)

        self.assertEqual(tiers.SCHEMA_VERSION, report['schema_version'])
        self.assertEqual('tests/tiers.py', report['generated_by'])
        environment = report['environment']
        self.assertEqual(os.name, environment['os_name'])
        self.assertEqual(sys.platform, environment['sys_platform'])
        self.assertEqual(platform.python_version(), environment['python_version'])
        self.assertEqual(['mcp'], list(environment['optional_modules']))
        self.assertIsInstance(environment['optional_modules']['mcp'], bool)

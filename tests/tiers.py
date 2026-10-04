"""Tier report: which tests ran, which skipped, and on which gate. Stdlib only, not a test module.

This repository has no single environment that runs everything. Three tiers need different
interpreters and dependency sets (the base 3.12 tier, the optional MCP tier, and the hash-locked
Sigma compiler tier on 3.13), and some tests are gated to one OS: the staging-daemon guards in
``test_scripts_lib`` run only on posix, native Windows checks require Windows.
``unittest`` prints those skips to a human and keeps nothing else, so the union of the tiers could
not be audited after the fact — a skip on one host looked like coverage on the project.

This tool runs unittest discovery in-process for each start directory given, records every skipped
test id with the reason its own decorator supplied, separates genuine collection failures from
environment skips, prints a bounded table and writes a machine-readable report (``tier-report.json``
by default) that CI keeps as an artifact. One report per tier, joined by test id, is the union.

The filename carries no ``test_`` prefix on purpose: discovery must never collect it. It imports
nothing from ``local_observe`` — a reporting tool must not depend on the code it reports on.

One pass per start directory is the point: the measured base tier used to run its suite twice, once
under ``coverage`` and once here, and the two passes could disagree. ``--verbose`` is what makes a
single pass enough — it streams unittest's own per-test output on stderr, so the coverage run is also
the readable one.

Usage from the repository root::

    python -B tests/tiers.py --start-dir tests --json tier-report-base.json
    python -B tests/tiers.py --start-dir tests --only-tier mcp --json tier-report-mcp.json
    python -B tests/tiers.py --start-dir tests/compiler --json tier-report-compiler.json
    python -B -m coverage run tests/tiers.py --start-dir tests --json tier-report-base.json --verbose

``--verbose`` (live unittest progress on stderr) and ``--quiet`` (no summary on stdout) are
mutually exclusive; the default prints the table on stdout and stays quiet while collecting.

``--only-tier TIER`` keeps only the test ids that tier owns (``TIER_TESTS`` below) and leaves the
rest of the start directory to the tier that already runs them. It exists so the MCP environment can
execute its own fraction of ``tests/`` instead of the whole tree a second time ; the base
tier keeps running the whole tree once, where those ids are reported as ``optional-dependency`` skips,
so the union of the reports by test id is still complete. A filter that selects nothing is a
collection error, never a green tier.

Exit status is 0 when every collected test ran or skipped on a gate; 1 when any test failed or
errored, when a start directory could not be imported (usually the wrong interpreter for that tier),
or when a start directory collected no test at all (including through ``--only-tier``); 2 when the
command line itself is wrong -- ``--only-tier`` accepts only the names in ``TIER_TESTS`` and a bad
one is refused before anything runs.
Collecting nothing is a collection error and not a green tier: ``collected 0, ran 0, failures 0`` is
what a mistyped ``--start-dir`` looks like when nothing checks it. JSON is written before the summary,
including on ordinary test failures. Abrupt termination or report-write errors cannot promise an artifact.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import platform
import sys
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_JSON = Path('tier-report.json')
MAX_TABLE_ROWS = 40
MAX_TRACES = 5
TRACE_CHARS = 1200
OPTIONAL_MODULES = ('mcp',)
ROOT = Path(__file__).resolve().parents[1]

# The test-id prefixes each optional-dependency tier owns: the classes that skip in the base tier
# because the extra is not installed there, and that the environment holding the extra is asked to
# run. ``--only-tier`` selects on these, which is how the MCP CI step stopped executing the whole
# tree a second time : the base tier still runs everything once and reports these ids as
# ``optional-dependency`` skips, so every id is still executed by exactly one tier per environment.
# An entry may be a test module (``test_mcp_surface.``), a test class (``test_operator.MCPTests``)
# or one test method. A gate inherited from a decorated base class is invisible to the guard named
# below and needs its own entry. ``tests/test_tiers_single_pass.py`` compares this table with the
# ``skipUnless(find_spec('mcp'), ...)`` decorators actually written in ``tests/`` and fails when the
# two disagree in either direction, because an id missing here skips in base and then never runs
# anywhere -- the silent gap this tool was written to make loud.
TIER_TESTS: dict[str, tuple[str, ...]] = {
    # Deterministic named subgroup: CI executes these once in base; the evaluation report
    # step measures the fixture, not a second unittest pass. This selector is for focused runs.
    'evaluation': ('test_eval_gate.', 'test_eval_arms.', 'test_fault_injection.',
                   'test_observer_evaluation.', 'test_eval_corrections.', 'test_eval_final.', 'test_eval_preflight.',
                   'test_feedback_measurement.',
                   'test_observer_acceptance_integration.', 'test_operator_held_out_corpus.'),
    'mcp': ('test_homepage_surfaces.MCPSurfaceTests',
            'test_mcp_surface.LegacySurfaceUnchangedTests',
            'test_mcp_surface.TransportTests',
            'test_operator.MCPTests'),
}


def bootstrap_path() -> None:
    """Put the repository root on sys.path so the suites import local_observe when run as a script.

    ``python tests/tiers.py`` starts with ``tests/`` — not the root — on sys.path, and unittest
    discovery only adds the start directory. Without this the base tier would report import errors
    for the product package instead of running it.
    """
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))


def classify(reason: str) -> str:
    """Group a skip reason for the report table by reading the decorator's own wording.

    This is a label over the text the test chose, not a claim about the code: the raw ``reason`` is
    always written to the JSON too. Anything the keywords do not recognise lands in ``other`` so a
    new skip is visible rather than quietly merged into an existing bucket.
    """
    text = reason.lower()
    if 'posix' in text or 'linux' in text:
        return 'posix-gate'
    if 'windows' in text:
        return 'windows-gate'
    if 'optional' in text or 'mcp' in text or 'dependency' in text or 'extra' in text:
        return 'optional-dependency'
    return 'other'


@dataclass
class TierResult:
    """What one start directory did in this interpreter, as reported and printed."""

    start_dir: str
    collected: int = 0
    ran: int = 0
    skipped: list[dict[str, str]] = field(default_factory=list)
    expected_failures: list[str] = field(default_factory=list)
    unexpected_successes: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    error_traces: list[str] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        """Return the JSON-safe form of this tier."""
        return {
            'start_dir': self.start_dir,
            'collected': self.collected,
            'ran': self.ran,
            'skipped': len(self.skipped),
            'expected_failures': self.expected_failures,
            'unexpected_successes': self.unexpected_successes,
            'failures': self.failures,
            'errors': self.errors,
            'error_traces': self.error_traces,
            'collection_errors': self.collection_errors,
            'skips': self.skipped,
        }


class _QuietStream:
    """Where ``_Recorder`` writes when nobody asked for output: nothing is kept and nothing is shown.

    ``unittest.TextTestResult`` wants a stream even at verbosity 0 (it flushes it after every test),
    and giving it a discard sink is what keeps the default run exactly as silent as it was before
    ``--verbose`` existed.
    """

    def write(self, text: str) -> int:
        """Drop ``text`` and report it as written, the way a real stream would."""
        return len(text)

    def writeln(self, text: str = '') -> None:
        """Drop ``text``. Present because the stdlib result may call it through a decorator."""

    def flush(self) -> None:
        """Do nothing, as fast as possible."""


class _Recorder(unittest.TextTestResult):
    """A text TestResult that keeps skip reasons and test ids; silent unless given a real stream.

    Subclassing the stdlib text result instead of a bare ``TestResult`` is what makes ``--verbose``
    unittest's own output rather than a second description of the same run that can drift from it.
    Every callback still reaches ``super()`` and still lands in the standard lists, so the outcomes
    this reports are the ones unittest decided: ``setUpClass``/``tearDownClass`` and module fixture
    errors (which ``TestSuite`` reports through an ``_ErrorHolder`` id such as
    ``setUpClass (test_x.Class)``), a ``SkipTest`` raised by a class fixture, and subtest failures
    (whose ids include their subtest parameters) are all accounted for. The
    ``*args``/``**kwargs`` are the stdlib's own ``durations`` plumbing, which it warns changes between
    releases; this tool must not be the thing that breaks when it does. ``verbosity`` defaults to 0 so
    a recorder built by hand — the default path — writes nothing.
    """

    def __init__(self, stream: Any = None, descriptions: bool = True, verbosity: int = 0,
                 *args: Any, **kwargs: Any) -> None:
        super().__init__(stream if stream is not None else _QuietStream(), descriptions, verbosity,
                         *args, **kwargs)
        self.skips: list[tuple[str, str]] = []

    def addSkip(self, test: Any, reason: str) -> None:
        """Record the id and the decorator's reason, then behave like the normal result."""
        super().addSkip(test, reason)
        self.skips.append((_test_id(test), reason))


def _test_id(test: Any) -> str:
    """Return a stable dotted id for a test or subtest, falling back to its str() form."""
    try:
        return str(test.id())
    except Exception:  # pragma: no cover - a broken test can raise from id()
        return str(test)


def _ids(result: list[Any]) -> list[str]:
    """Extract ids from a TestResult failure list, which holds (test, traceback) pairs."""
    return [_test_id(pair[0]) for pair in result]


def _traces(pairs: list[Any]) -> list[str]:
    """Return at most MAX_TRACES tracebacks, each cut to TRACE_CHARS, from (test, tb) pairs.

    Bounded on purpose: the report is an artifact, and an unbounded traceback from a test that
    dumps a whole file would turn a small JSON into a large one.
    """
    return [f'{_test_id(pair[0])}\n{str(pair[1])[:TRACE_CHARS]}' for pair in pairs[:MAX_TRACES]]


def _execute(suite: unittest.TestSuite, verbose: bool) -> _Recorder:
    """Run ``suite`` exactly once and hand back the recorder that watched it.

    ``verbose`` runs it under ``unittest.TextTestRunner`` at verbosity 2 — the same output
    ``python -m unittest discover -v`` gives, per test and its traceback on failure, on stderr.
    The stream is read here rather than at import time so a caller that redirects stderr sees it.
    Both modes swallow the tests' own stdout: the tool's table is the stdout of this process.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        if verbose:
            return unittest.TextTestRunner(stream=sys.stderr, verbosity=2, resultclass=_Recorder).run(suite)
        recorder = _Recorder()
        suite.run(recorder)
        return recorder


def tier_selectors(only_tier: str | None) -> tuple[str, ...]:
    """Return the test-id prefixes ``only_tier`` owns; ``None`` means no filter and nothing is kept out."""
    return TIER_TESTS[only_tier] if only_tier else ()


def id_selected(test_id: str, selectors: tuple[str, ...]) -> bool:
    """True when ``test_id`` is one of ``selectors`` or sits under one, matched on dotted boundaries.

    A selector names a module, a class or a method, so ``test_a.TestX`` must not select
    ``test_a.TestXYZ.test_one``: the comparison happens at the dot, not at the character.
    """
    for selector in selectors:
        prefix = selector if selector.endswith('.') else selector + '.'
        if test_id == selector or test_id.startswith(prefix):
            return True
    return False


def select_suite(suite: unittest.TestSuite, selectors: tuple[str, ...]) -> unittest.TestSuite:
    """Return a new suite holding only the selected tests, in discovery order.

    ``TestSuite`` offers no filter, so the walk is here. Nested suites (discovery hands back one per
    module) are rebuilt rather than mutated: the caller still holds the unfiltered suite for its
    counting, and a tool that reports on other people's tests must not edit them in place.
    """
    kept: list[Any] = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            kept.extend(select_suite(item, selectors))
        elif id_selected(_test_id(item), selectors):
            kept.append(item)
    return unittest.TestSuite(kept)


def run_start_dir(start_dir: str, verbose: bool = False, only_tier: str | None = None) -> TierResult:
    """Load and run the tests under ``start_dir`` in this process -- all of them, or ``only_tier``'s.

    The tests log JSON lines to stdout; those are swallowed in both modes so the report stays
    readable. ``verbose`` puts unittest's live progress and tracebacks on stderr, which is what lets
    the measured tier run this as its only pass instead of running the suite twice. Nothing here
    hides a failure: failures and errors are recorded and exit 1.

    The collection count is taken before the suite is consumed, so ``collected`` is what discovery
    handed over rather than something read off the run: ``TestSuite`` drops entries as it goes, and a
    class whose ``setUpClass`` fails never has the rest of its tests run at all. A directory that
    collects nothing is reported as a collection error, without running an empty suite.

    ``only_tier`` filters the discovered suite before it is counted, so ``collected`` is what that
    tier owns rather than what the directory holds. A module that failed to import stays in
    ``collection_errors`` even when the filter drops its placeholder test, so a filtered tier cannot
    read green over a suite it never loaded.
    """
    tier = TierResult(start_dir=start_dir)
    selectors = tier_selectors(only_tier)
    loader = unittest.TestLoader()
    try:
        suite = loader.discover(start_dir=start_dir, pattern='test*.py')
    except Exception as error:  # discovery itself refused to start
        tier.collection_errors.append(f'{type(error).__name__}: {error}')
        return tier
    tier.collection_errors.extend(str(item).splitlines()[0] for item in loader.errors)
    if selectors:
        suite = select_suite(suite, selectors)
    tier.collected = suite.countTestCases()
    if tier.collected == 0:
        tier.collection_errors.append(f'no tests collected from {start_dir}' if not selectors else
                                      f'--only-tier {only_tier} selected no test under {start_dir}')
        return tier
    recorder = _execute(suite, verbose)
    tier.ran = recorder.testsRun
    tier.skipped = [{'test': test_id, 'reason': reason, 'category': classify(reason)}
                    for test_id, reason in recorder.skips]
    tier.expected_failures = _ids(recorder.expectedFailures)
    tier.unexpected_successes = [_test_id(test) for test in recorder.unexpectedSuccesses]
    tier.failures = _ids(recorder.failures)
    tier.errors = _ids(recorder.errors)
    tier.error_traces = _traces(list(recorder.failures) + list(recorder.errors))
    return tier


def tier_clean(tier: dict[str, Any]) -> bool:
    """True when a tier reported no failure, no error, no unexpected pass and no import failure."""
    return not any(tier[key] for key in ('failures', 'errors', 'collection_errors', 'unexpected_successes'))


def environment() -> dict[str, Any]:
    """Describe this interpreter and the optional extras the tiers gate on."""
    extras = {name: importlib.util.find_spec(name) is not None for name in OPTIONAL_MODULES}
    return {
        'os_name': os.name,
        'sys_platform': sys.platform,
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'optional_modules': extras,
    }


def build_report(start_dirs: list[str], verbose: bool = False,
                 only_tier: str | None = None) -> dict[str, Any]:
    """Run each start directory exactly once and assemble the report document.

    ``only_tier`` is recorded in the document so an artifact read beside the other tiers says which
    slice it is: ``collected 20, ran 20`` from a filtered tier is twenty tests, not a whole suite.
    """
    tiers = [run_start_dir(start_dir, verbose=verbose, only_tier=only_tier) for start_dir in start_dirs]
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_by': 'tests/tiers.py',
        'only_tier': only_tier,
        'environment': environment(),
        'tiers': [tier.as_dict() for tier in tiers],
        'totals': {
            'collected': sum(tier.collected for tier in tiers),
            'ran': sum(tier.ran for tier in tiers),
            'skipped': sum(len(tier.skipped) for tier in tiers),
            'failures': sum(len(tier.failures) for tier in tiers),
            'errors': sum(len(tier.errors) for tier in tiers),
            'collection_errors': sum(len(tier.collection_errors) for tier in tiers),
        },
        'skips': [{'start_dir': tier.start_dir, **skip} for tier in tiers for skip in tier.skipped],
    }


def print_table(report: dict[str, Any]) -> None:
    """Print a fixed-width skip table plus per-tier tallies, capped at MAX_TABLE_ROWS rows.

    ASCII only in everything this prints: local runs happen on consoles whose code page cannot
    encode more, and a UnicodeEncodeError from a reporting tool reads like a test failure.
    """
    env = report['environment']
    mcp = 'present' if env['optional_modules'].get('mcp') else 'absent'
    print(f"tier report - {env['os_name']} python {env['python_version']} [{env['sys_platform']}] "
          f"(mcp {mcp})")
    for tier in report['tiers']:
        print()
        print(f"{tier['start_dir']}: collected {tier['collected']}, ran {tier['ran']}, "
              f"skipped {tier['skipped']}, expected failures {len(tier['expected_failures'])}, "
              f"failures {len(tier['failures'])}, errors {len(tier['errors'])}, "
              f"collection errors {len(tier['collection_errors'])}")
        for line in tier['collection_errors'][:3]:
            print(f'  collection error: {line}')
        for test_id in tier['failures'] + tier['errors']:
            print(f'  not passed: {test_id}')
    skips = report['skips']
    print()
    print(f"{'CATEGORY':<20} {'TEST ID':<78} REASON")
    for skip in skips[:MAX_TABLE_ROWS]:
        print(f"{skip['category']:<20} {skip['test']:<78} {skip['reason']}")
    if len(skips) > MAX_TABLE_ROWS:
        print(f"... {len(skips) - MAX_TABLE_ROWS} more skip(s); see the JSON report")
    if not skips:
        print('(no skips here: every gated test in this start directory ran. The union of the tiers '
              'is the reports joined by test id, so keep a report from every tier and environment)')


def print_traces(report: dict[str, Any]) -> None:
    """Write the tracebacks of tests that did not pass to stderr, already bounded by _traces()."""
    for tier in report['tiers']:
        for trace in tier['error_traces']:
            print(trace, file=sys.stderr)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse the command line: repeatable start directory, JSON output path, and one output level."""
    parser = argparse.ArgumentParser(description='Report which tests ran and which skipped, per tier.')
    parser.add_argument('--start-dir', action='append', dest='start_dirs', metavar='DIR',
                        help='directory to run unittest discovery over; repeat per tier '
                             '(default: tests)')
    parser.add_argument('--json', dest='json_path', metavar='PATH', default=str(DEFAULT_JSON),
                        help=f'where to write the machine-readable report (default: {DEFAULT_JSON})')
    parser.add_argument('--only-tier', dest='only_tier', metavar='TIER', choices=sorted(TIER_TESTS),
                        help='run only the test ids owned by one named tier ('
                             + '; '.join(f'{name}: {len(prefixes)} id prefix/es'
                                         for name, prefixes in sorted(TIER_TESTS.items()))
                             + '); every other id in the start directory is left to the tier that '
                               'already runs it, which reports these as skips')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('--quiet', action='store_true', help='write JSON without the stdout summary')
    output.add_argument('--verbose', action='store_true',
                        help='stream unittest per-test output and tracebacks on stderr while the '
                             'suite runs (what the measured tier uses, so CI runs each directory '
                             'once instead of twice); the table is still printed afterwards')
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run every requested tier, write the report, print the table, return the exit status.

    The report goes to disk before the summary is printed: a tier that failed is precisely the tier
    whose artifact CI needs, and it must not depend on the printing succeeding afterwards. A bad
    command line (``--quiet`` with ``--verbose``) is refused by argparse with status 2 and runs,
    and writes, nothing.
    """
    args = parse_args(argv)
    bootstrap_path()
    start_dirs = args.start_dirs or ['tests']
    report = build_report(start_dirs, verbose=args.verbose, only_tier=args.only_tier)
    Path(args.json_path).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    clean = all(tier_clean(tier) for tier in report['tiers'])
    if not args.quiet:
        if args.only_tier:
            selectors = sorted(tier_selectors(args.only_tier))
            print(f'tier filter: --only-tier {args.only_tier} keeps {len(selectors)} id prefix/es: '
                  + ', '.join(selectors))
            print('every other id in this start directory belongs to another tier and is reported '
                  'there, not here')
        print_table(report)
        print(f"report written: {args.json_path}")
    if not clean and not args.verbose:
        # Verdicts are printed either way; in verbose mode unittest already wrote the tracebacks as
        # they happened, and repeating them here would only lengthen the log of a failing tier.
        print_traces(report)
    return 0 if clean else 1


if __name__ == '__main__':
    sys.exit(main())

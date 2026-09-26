"""The dependency import boundary CI guard: the tier reporter is the only thing that executes a tier in the job.

The fault injection adds the two guards over the shape that pass left behind: the MCP tier runs only the ids it
owns (`--only-tier mcp`), and the three suite steps carry the step-level `timeout-minutes` that
act_runner 0.6.1 actually enforces.

Parses ci.yml with the PyYAML the base tier already installs and reads every run step as argv lists,
not as loose text, so a wrapped or commented line cannot satisfy an assertion by accident.
"""
from __future__ import annotations

from pathlib import Path
import shlex
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.gitea' / 'workflows' / 'ci.yml'
TEST_JOB, SCAN_JOB, REPORTER = 'deterministic-tests', 'secret-scan', 'tests/tiers.py'

# tier -> its own interpreter, the tree it collects, the artifact it writes. Every reporter run
# carries --verbose, because that flag is what replaced the deleted `unittest discover -v` command.
TIERS = {
    'base': ('/tmp/lo-base/bin/python', 'tests', 'tier-report-base.json'),
    'mcp': ('/tmp/lo-mcp/bin/python', 'tests', 'tier-report-mcp.json'),
    'compiler': ('/tmp/lo-compiler/bin/python', 'tests/compiler', 'tier-report-compiler.json'),
}


def document() -> dict:
    """Parse the checked-out workflow, refusing a file that is empty or has no jobs."""
    parsed = yaml.safe_load(WORKFLOW.read_text(encoding='utf-8'))
    if not isinstance(parsed, dict) or not parsed.get('jobs'):
        raise AssertionError(f'{WORKFLOW}: no jobs in the workflow')
    return parsed


def job(job_id: str) -> dict:
    jobs = document()['jobs']
    if job_id not in jobs:
        raise AssertionError(f'{job_id} is gone; the workflow has {sorted(jobs)}')
    return jobs[job_id]


def commands(job_id: str) -> list[list[str]]:
    """A job's shell commands in runner order, as argv lists, comments dropped and backslashes joined."""
    out: list[list[str]] = []
    for step in job(job_id).get('steps', []):
        pending = ''
        for raw in str(step.get('run', '')).splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.endswith('\\'):
                pending += line[:-1] + ' '
                continue
            out.append(shlex.split(pending + line))
            pending = ''
    if not out:
        raise AssertionError(f'job {job_id} exposed no shell command')
    return out


def reporter(cmds: list[list[str]], artifact: str) -> list[str]:
    """The single reporter command writing ``artifact``; a job with none or with two has failed."""
    found = [c for c in cmds if REPORTER in c and artifact in c]
    if len(found) != 1:
        raise AssertionError(f'{artifact}: expected one reporter command, found '
                             + ' | '.join(' '.join(c) for c in found))
    return found[0]


def flag(command: list[str], name: str) -> str | None:
    """The argument after ``name``, positional, so --start-dir tests cannot quietly mean tests/compiler."""
    return command[command.index(name) + 1] if name in command else None


def step_timeouts(job_id: str = TEST_JOB) -> dict[str, int | None]:
    """Every named step in a job -> its step-level ``timeout-minutes``, ``None`` when it has none.

    Step names are the handle here, not step order: a step this guard cannot find is reported as a
    missing name rather than silently shifting the assertion onto its neighbour.
    """
    return {str(step.get('name')): step.get('timeout-minutes') for step in job(job_id)['steps']}


def coverage(cmds: list[list[str]], verb: str = '') -> list[list[str]]:
    return [c for c in cmds if 'coverage' in c and (not verb or verb in c)]


class TierCommandsTest(unittest.TestCase):
    """What the dependency import boundary changed: one reporter invocation per tier and nothing else running a suite."""

    def test_each_tier_is_executed_once_by_the_reporter(self) -> None:
        """Three reporter commands, each in its own environment, on its own tree and artifact."""
        cmds = commands(TEST_JOB)
        running = [c for c in cmds if REPORTER in c]
        self.assertEqual(3, len(running), 'one reporter command per tier: '
                         + ' | '.join(' '.join(c) for c in running))
        for tier, (python, start_dir, artifact) in TIERS.items():
            with self.subTest(tier=tier):
                command = reporter(cmds, artifact)
                self.assertEqual(python, command[0], f'{tier} ran in the wrong environment: {command}')
                self.assertIn('-B', command, 'no __pycache__ may appear mid-run')
                self.assertEqual(start_dir, flag(command, '--start-dir'), f'{tier} collected the wrong tree')
                self.assertEqual(artifact, flag(command, '--json'), f'{tier} wrote the wrong artifact')
                self.assertIn('--verbose', command, f'{tier} silenced the run its report describes')

    def test_only_the_mcp_tier_selects_its_own_ids(self) -> None:
        """The fault injection: MCP runs the ids base skips for want of the extra; the other two filter nothing.

        Base and compiler own whole directories, so a ``--only-tier`` on either of them would leave ids
        that no tier executes. The value is pinned to the literal ``mcp`` rather than to
        ``tiers.TIER_TESTS`` because this file's claim is about the workflow's command line, and the
        table's own contents are guarded by tests/test_tiers_single_pass.py.
        """
        cmds = commands(TEST_JOB)
        for tier, (_python, _start, artifact) in TIERS.items():
            with self.subTest(tier=tier):
                command = reporter(cmds, artifact)
                if tier == 'mcp':
                    self.assertEqual('mcp', flag(command, '--only-tier'),
                                     f'{tier} is running the whole tree a second time: {command}')
                else:
                    self.assertNotIn('--only-tier', command,
                                     f'{tier} filters a directory it is meant to run entire: {command}')

    def test_no_command_runs_a_suite_a_second_time(self) -> None:
        """The defect itself: a bare unittest command in the job is a duplicate execution of a tier."""
        duplicated = [c for c in commands(TEST_JOB) if 'unittest' in c]
        self.assertEqual([], duplicated, 'these run a tier the reporter already ran: '
                         + ' | '.join(' '.join(c) for c in duplicated))

    def test_coverage_still_measures_the_base_tier_it_reports(self) -> None:
        """One ``coverage run`` wrapping the base reporter, then the floor, then the xml artifact."""
        cmds = commands(TEST_JOB)
        run, report, xml = coverage(cmds, 'run'), coverage(cmds, 'report'), coverage(cmds, 'xml')
        self.assertEqual([1, 1, 1], [len(run), len(report), len(xml)], 'coverage changed its shape')
        self.assertEqual(reporter(cmds, TIERS['base'][2]), run[0], 'coverage traced something else')
        self.assertLess(run[0].index('coverage'), run[0].index(REPORTER), 'the tracer must start first')
        self.assertLess(cmds.index(run[0]), cmds.index(report[0]), 'reported before the run filled it')
        self.assertLess(cmds.index(report[0]), cmds.index(xml[0]), 'xml came before the report')
        self.assertIn('--fail-under=76', report[0], 'the coverage floor moved with this card')
        self.assertIn('--precision=2', report[0])
        self.assertEqual(3, len(coverage(cmds)), 'coverage gained or lost a subcommand')


class StepTimeoutTest(unittest.TestCase):
    """The fault injection: the only timeouts the runner enforces are the step-level ones (act_runner 0.6.1).

    The job-level budget stays at 15 and is asserted in UnchangedWorkflowTest; these tests pin the
    numbers that actually kill a hung suite, so moving either one is a deliberate edit and not a typo.
    """

    # Run 2657 needed 1,720 seconds for 4,140 base tests on the shared runner. Keep an
    # enforced 35-minute limit; 10 and 15 on the other tiers allow their venv installs.
    SUITE_STEPS = {'Base dependencies only': 35, 'Optional MCP protocol': 10, 'Locked Sigma compiler': 15}
    # Steps that execute no suite: ruff, and the two always() uploads.
    UNSUITED_STEPS = ('Lint (ruff, pinned in requirements-dev.txt)', 'Tier union report',
                      'Base tier coverage xml')

    def test_test_job_has_bounded_executable_temporary_storage(self) -> None:
        container = job(TEST_JOB)['container']
        self.assertNotIn('image', container, 'retain the runner-selected image')
        self.assertEqual(shlex.split(container['options']),
                         ['--tmpfs', '/tmp:rw,exec,mode=1777,size=2g'])
        self.assertNotIn('container', job(SCAN_JOB), 'do not change the secret-scan job')

    def test_the_three_suite_steps_carry_their_own_timeout(self) -> None:
        """35, 10 and 15, on the three steps that run a tier and nothing else."""
        timeouts = step_timeouts()
        for name, minutes in self.SUITE_STEPS.items():
            with self.subTest(step=name):
                self.assertIn(name, timeouts, f'{name} lost its name, so no step timeout binds it')
                self.assertEqual(minutes, timeouts[name], f'{name} no longer carries {minutes} minutes')

    def test_the_steps_that_run_no_suite_carry_none(self) -> None:
        """A budget on lint or on an upload would stop a job for the reason this one is not about."""
        timeouts = step_timeouts()
        for name in self.UNSUITED_STEPS:
            with self.subTest(step=name):
                self.assertIn(name, timeouts, f'{name} lost its name, so no step timeout binds it')
                self.assertIsNone(timeouts[name], f'{name} took a timeout it does not need')


class UnchangedWorkflowTest(unittest.TestCase):
    """What the dependency import boundary promised to leave alone, asserted so a refactor cannot move it unnoticed."""

    def test_environments_stay_isolated_and_still_prove_what_they_gate(self) -> None:
        """Four venvs, each installing with its own interpreter; base has the tracer and no mcp."""
        cmds = commands(TEST_JOB)
        self.assertEqual(sorted('/tmp/lo-base /tmp/lo-compiler /tmp/lo-lint /tmp/lo-mcp'.split()),
                         sorted(c[-1] for c in cmds if 'venv' in c))
        lint = [c for c in cmds if c[:1] == ['/tmp/lo-lint/bin/python']]
        self.assertIn('requirements-dev.txt', lint[0], 'ruff is no longer pinned by the dev tree')
        self.assertEqual(['-m', 'ruff', 'check', 'local_observe', 'tests', 'scripts',
                          'components', 'examples'], lint[1][1:])
        gates = {'base': "find_spec('mcp') is None", 'mcp': 'import mcp'}
        for tier, (python, _start, _artifact) in TIERS.items():
            with self.subTest(tier=tier):
                own = [c for c in cmds if c[:1] == [python]]
                installs = [c for c in own if 'install' in c]
                self.assertEqual(1, len(installs), f'{tier} installed outside its own venv')
                traced = any('coverage' in token for token in installs[0])
                self.assertEqual(tier == 'base', traced, f'{tier} took the tracer: {installs[0]}')
                if tier in gates:
                    joined = ' '.join(' '.join(c) for c in own)
                    self.assertIn(gates[tier], joined, f'{tier} stopped proving its dependency set')

    def test_interpreter_pins_and_the_compiler_hash_lock_survive(self) -> None:
        """3.12 then 3.13, each before the tier that needs it, and the compiler installs by hash."""
        steps = job(TEST_JOB)['steps']
        setups = [index for index, step in enumerate(steps)
                  if 'setup-python' in str(step.get('uses', ''))]
        self.assertEqual(['3.12', '3.13'],
                         [str((steps[i].get('with') or {}).get('python-version')) for i in setups])
        tier_steps = {tier: next(i for i, s in enumerate(steps) if TIERS[tier][0] in str(s.get('run')))
                      for tier in TIERS}
        self.assertLess(setups[0], tier_steps['base'], 'the base tier ran before its interpreter')
        self.assertLess(setups[0], tier_steps['mcp'], 'the MCP tier ran before its interpreter')
        self.assertLess(setups[1], tier_steps['compiler'], 'the compiler tier ran on 3.12')
        self.assertLess(tier_steps['base'], tier_steps['compiler'], 'the tiers changed order')
        lock = [c for c in commands(TEST_JOB) if c[:1] == [TIERS['compiler'][0]] and 'install' in c]
        self.assertEqual(1, len(lock), 'one compiler install command')
        self.assertIn('--require-hashes', lock[0], 'the compiler tier stopped pinning by hash')
        self.assertIn('components/control/sigma/compiler.lock', lock[0])

    def test_triggers_runner_labels_and_timeouts_are_unchanged(self) -> None:
        """Pushes to main and every pull request, on the same runners, inside the same bounds."""
        triggers = document().get('on', document().get(True))  # PyYAML reads a bare `on:` as True
        self.assertEqual('ci', document().get('name'))
        self.assertEqual(['main'], triggers['push']['branches'])
        self.assertIn('pull_request', triggers)
        for job_id, timeout in ((TEST_JOB, 15), (SCAN_JOB, 5)):
            self.assertEqual(('ubuntu-latest', timeout), (job(job_id).get('runs-on'),
                                                          job(job_id).get('timeout-minutes')))

    def test_uploads_keep_their_names_paths_and_always_condition(self) -> None:
        """A report that vanishes on a red job is not evidence, so both uploads stay ``always()``."""
        uploads = {str((step.get('with') or {}).get('name')): step
                   for step in job(TEST_JOB)['steps']
                   if 'upload-artifact' in str(step.get('uses', ''))}
        self.assertEqual({'tier-reports', 'coverage-xml'}, set(uploads))
        self.assertEqual(sorted([spec[2] for spec in TIERS.values()] + ['evaluation-report.json']),
                         sorted(str((uploads['tier-reports'].get('with') or {})['path']).split()))
        self.assertEqual('coverage.xml', str((uploads['coverage-xml'].get('with') or {})['path']))
        for name, step in uploads.items():
            self.assertIn('upload-artifact@v3', str(step.get('uses')), f'{name} moved the action pin')
            self.assertIn('always()', str(step.get('if')), f'{name} no longer uploads on a red job')
            self.assertEqual('warn', (step.get('with') or {}).get('if-no-files-found'), name)

    def test_the_secret_scan_job_is_untouched(self) -> None:
        """Pinned tool and digest, verified download, full history, redaction."""
        steps = job(SCAN_JOB)['steps']
        pinned = [s.get('env') for s in steps if 'GL_SHA256' in str(s.get('env'))][0]
        checkout = [s for s in steps if 'checkout' in str(s.get('uses', ''))][0]
        scan = ' '.join(' '.join(c) for c in commands(SCAN_JOB))
        self.assertRegex(str(pinned['GL_VER']), r'^\d+\.\d+\.\d+$', 'gitleaks is unpinned')
        self.assertRegex(str(pinned['GL_SHA256']), r'^[0-9a-f]{64}$', 'that is not a digest')
        self.assertEqual(0, (checkout.get('with') or {}).get('fetch-depth'), 'the scan lost its history')
        for needle in ('sha256sum -c -', 'gitleaks detect', '--redact'):
            self.assertIn(needle, scan)

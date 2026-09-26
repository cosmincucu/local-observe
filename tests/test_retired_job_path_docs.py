"""Guard: the documents that survived job observe standard's job-worker retirement still read true.

job observe standard (decision job observation) retired the `busctl` job worker and busctl retirement scripts moved its drivers
and tests into
`archive/platform-jobs/`. The prose written while that code was live stayed behind, so a document
could name a test id nobody can run, point at an archived module as if it were in the tree, list a
kept script that is now archived, or print a run command for a driver that no longer ships. Each
test below reads one such document and checks the mechanical fact it asserts; none imports
`local_observe`, because the claim under test is about files on disk, not about product behaviour.

Every offender in a file is collected and compared against `[]` in one assertion, so a single run
names every broken id rather than stopping at the first.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

# Basenames of the job-observation drivers busctl retirement scripts moved under archive/platform-jobs/.
ARCHIVED_JOB_DRIVERS = ('job_snapshot.py', 'rehearse_job_recovery.py', 'job_busctl_fixture.py',
                        'register_job_monitor.py', 'bounded_worker_observation.py')


class DocGuardTests(unittest.TestCase):
    """The four mechanical facts a retired path must not be allowed to leave in the docs."""

    def test_the_skip_column_names_tests_that_exist(self):
        """Every test id written as a bullet in docs/testing-standards.md resolves to real code."""
        text = (ROOT / 'docs' / 'testing-standards.md').read_text(encoding='utf-8')
        bullet = re.compile(r'^- `(test_[a-z0-9_]+)\.([A-Za-z0-9_]+)\.([a-z0-9_]+)`$')
        offenders: list[str] = []
        for line in text.splitlines():
            match = bullet.match(line)
            if match is None:
                continue
            module, klass, method = match.groups()
            path = ROOT / 'tests' / f'{module}.py'
            if not path.exists():
                offenders.append(f'{module}.{klass}.{method} -> tests/{module}.py does not exist')
                continue
            source = path.read_text(encoding='utf-8')
            if f'class {klass}' not in source:
                offenders.append(f'{module}.{klass}.{method} -> no class {klass} in tests/{module}.py')
            if f'def {method}' not in source:
                offenders.append(f'{module}.{klass}.{method} -> no def {method}() in tests/{module}.py')
        self.assertEqual(offenders, [])

    def test_the_tiers_docstring_names_a_module_that_exists(self):
        """The reporter's own docstring may only point at a test module that is still in tests/."""
        source = (ROOT / 'tests' / 'tiers.py').read_text(encoding='utf-8')
        docstring = ast.get_docstring(ast.parse(source)) or ''
        literal = re.compile(r'``(test_[a-z][a-z0-9_]*)``')
        offenders = [f'``{name}`` -> tests/{name}.py does not exist'
                     for name in literal.findall(docstring)
                     if not (ROOT / 'tests' / f'{name}.py').exists()]
        self.assertEqual(offenders, [])


    def test_a_document_that_prints_an_archived_job_command_carries_the_retirement_banner(self):
        """A runbook whose fenced block still prints an archived driver says so at the top."""
        offenders: list[str] = []
        for path in sorted((ROOT / 'docs').rglob('*.md')):
            if 'remediation' in path.relative_to(ROOT / 'docs').parts:
                continue
            inside_fence = False
            named = False
            for line in path.read_text(encoding='utf-8').splitlines():
                if line.startswith('```'):
                    inside_fence = not inside_fence
                    continue
                if inside_fence and any(driver in line for driver in ARCHIVED_JOB_DRIVERS):
                    named = True
                    break
            if not named:
                continue
            head = '\n'.join(path.read_text(encoding='utf-8').splitlines()[:25])
            if 'archive/platform-jobs' not in head:
                offenders.append(str(path.relative_to(ROOT).as_posix()))
        self.assertEqual(offenders, [])


if __name__ == '__main__':
    unittest.main()

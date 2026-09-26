"""The source-tree digest the platform pins itself with, plus the guard on the retired job path.

job observe standard moved the busctl job worker's own pin and unit renderer to `archive/platform-jobs/`; the
source digest stayed in the product, renamed with the module it lives in (`job_runtime.py` ->
`source_pin.py`, busctl retirement scripts), because `runtime.observe_startup` calls it on every platform start to prove
the loaded tree matches `LO_PLATFORM_CODE_SHA256`. That proof and its refusals belong to
`tests/test_platform_runtime.py`. What is pinned here is the digest itself, and the fact that the
retired modules really are gone from the product tree.
"""
from pathlib import Path
import sys
import tempfile
import unittest

from local_observe.platform.source_pin import code_digest

ROOT = Path(__file__).resolve().parents[1]


class CodeDigestTests(unittest.TestCase):
    def tree(self, root: Path) -> Path:
        """A minimal regular source tree to digest, with one module and no symlinks."""
        package = root / 'local_observe'
        package.mkdir(parents=True)
        (package / '__init__.py').write_text('', encoding='utf-8')
        (package / 'thing.py').write_text('VALUE = 1\n', encoding='utf-8')
        return root

    def test_the_digest_is_stable_and_moves_with_any_file_or_path(self):
        with tempfile.TemporaryDirectory() as directory:
            first = self.tree(Path(directory) / 'a')
            second = self.tree(Path(directory) / 'b')
            self.assertEqual(code_digest(first), code_digest(second))
            (first / 'local_observe' / 'thing.py').write_text('VALUE = 2\n', encoding='utf-8')
            self.assertNotEqual(code_digest(first), code_digest(second))
            (second / 'local_observe' / 'other.py').write_text('VALUE = 1\n', encoding='utf-8')
            self.assertNotEqual(code_digest(first), code_digest(second))   # same bytes, new name
            (first / 'local_observe' / 'other.py').write_text('VALUE = 1\n', encoding='utf-8')
            (first / 'local_observe' / 'thing.py').unlink()                 # the path moved, the bytes did not
            self.assertNotEqual(code_digest(first), code_digest(second))

    def test_a_symlinked_or_empty_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.tree(Path(directory))
            link = root / 'local_observe' / 'elsewhere.py'
            try:
                link.symlink_to(root / 'local_observe' / 'thing.py')
            except (OSError, NotImplementedError):        # Windows without the privilege to symlink
                self.skipTest('symlinks unavailable in this environment')
            with self.assertRaises(ValueError):
                code_digest(root)
            link.unlink()
            with self.assertRaises(ValueError):
                code_digest(Path(directory) / 'now-here')                   # no local_observe/, no files

    def test_the_shipped_tree_digests(self):
        self.assertRegex(code_digest(ROOT), r'^[a-f0-9]{64}$')


class RetiredModulesTests(unittest.TestCase):
    """The busctl worker is archive, not dead code: nothing may still import it from the product."""

    def test_the_worker_modules_are_no_longer_in_the_product_tree(self):
        for name in ('jobs.py', 'job_worker.py'):
            with self.subTest(module=name):
                self.assertFalse((ROOT / 'local_observe' / 'platform' / name).exists())

    FORBIDDEN_LEAVES = ('jobs', 'job_worker')   # the two modules job observe standard retired

    def test_nothing_outside_the_archive_imports_the_retired_worker(self):
        """Checked as syntax, not as text: prose may name the retired modules, `import` may not.

        This is the LEDGER acceptance line for job observe standard ("no import of `platform.jobs` left outside
        `archive/`") written down, and it reads the parsed tree so that a docstring or a comment --
        which is how the retired path is *documented* in the files that replaced it -- is not a false
        failure someone then deletes. `scripts/` joined the scanned bases with busctl retirement scripts, which is the
        change that made it pass there: `scripts/job_snapshot.py` had that import and is archived.
        """
        import ast
        offenders = []
        for base in (ROOT / 'local_observe', ROOT / 'tests', ROOT / 'scripts'):
            for path in base.rglob('*.py'):
                tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
                for node in ast.walk(tree):
                    for name in self.imported_names(node):
                        if name.rsplit('.', 1)[-1] in self.FORBIDDEN_LEAVES:
                            offenders.append(f"{path.relative_to(ROOT).as_posix()}: {name}")
        self.assertEqual(sorted(offenders), [])

    @staticmethod
    def imported_names(node):
        """The dotted names one import statement binds; relative imports keep their leading dots."""
        import ast
        if isinstance(node, ast.Import):
            return [alias.name for alias in node.names]
        if isinstance(node, ast.ImportFrom):
            return ['.' * node.level + (node.module or '') + '.' + alias.name for alias in node.names]
        return []


    def test_the_platform_source_pin_module_has_no_leftover_name(self):
        """The digest helper is `source_pin.py`; the worker's name is off the product tree."""
        self.assertTrue((ROOT / 'local_observe' / 'platform' / 'source_pin.py').is_file())
        self.assertFalse((ROOT / 'local_observe' / 'platform' / 'job_runtime.py').exists())



if __name__ == '__main__':
    unittest.main()

"""Core imports must work even on machines without any optional integrations."""
import ast
from pathlib import Path
import subprocess
import sys
import unittest


class OptionalDependencyTests(unittest.TestCase):

    def test_core_cli_imports_without_optional_packages(self):
        program = '''
import importlib.abc
import sys
class NoExtras(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'mcp', 'uvicorn', 'datasette', 'datasette_graphql'}:
            raise ModuleNotFoundError('Optional dependency blocked by test: ' + fullname)
sys.meta_path.insert(0, NoExtras())
from local_observe.inventory import cli
from local_observe.platform import cli, api, operator
from local_observe.deployment import cli, release, live, recovery
try:
    import local_observe.platform.mcp
except ModuleNotFoundError as error:
    assert 'Optional dependency blocked by test: mcp' in str(error), str(error)
else:
    raise AssertionError('MCP unexpectedly available')
'''
        result = subprocess.run([sys.executable, '-B', '-c', program],
                                cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

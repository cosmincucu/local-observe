"""deployment separation (decision deployment separation): the customisation candidate reads its estate capture from the operator.

``prepare_customisation_candidate.py`` cannot be run end to end here: a real run needs a whole estate
source checkout and writes a private candidate directory. What is testable is the location contract,
and it is testable in both directions. With no operator directory the script refuses and writes
nothing; with one supplied it gets past that refusal and reports *baseline drift* instead, which it
could not do without opening the file the operator pointed it at.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'prepare_customisation_candidate.py'
BASELINE_ENV = 'LO_MIGRATION_BASELINE_DIR'


class CustomisationCandidateBaselineTests(unittest.TestCase):
    def run_candidate(self, arguments, environment=None):
        """Run the candidate preparer with this variable absent unless the case supplies it."""
        base = {key: value for key, value in os.environ.items() if key != BASELINE_ENV}
        base.update(environment or {})
        return subprocess.run([sys.executable, '-B', str(SCRIPT), *arguments],
                              capture_output=True, text=True, env=base, cwd=str(ROOT))

    def test_a_supplied_capture_is_the_file_that_gets_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            operator = Path(directory)/'operator'
            (operator/'baseline-02.json').parent.mkdir(parents=True)
            (operator/'baseline-02.json').write_text(json.dumps({'schema_version': 1}), encoding='utf-8')
            result = self.run_candidate(('--source', str(Path(directory)/'source'),
                                         '--operator-url', 'https://example.test',
                                         '--output', str(Path(directory)/'candidate'),
                                         '--baseline-dir', str(operator)))
            self.assertNotEqual(result.returncode, 2, result.stderr)
            self.assertIn('Baseline drift', result.stderr, result.stderr)
            self.assertNotIn(BASELINE_ENV, result.stderr, result.stderr)
            self.assertFalse((Path(directory)/'candidate').exists(), 'a drift refusal writes no candidate')

    def test_the_script_names_no_default_path_inside_the_checkout(self):
        """The old default was `migration/estate/baseline-02.json`, which deployment separation removed from this tree."""
        source = SCRIPT.read_text(encoding='utf-8')
        self.assertNotIn('migration/estate', source)
        self.assertIn('baseline_file(args.baseline_dir', source)
        self.assertNotIn("'migration", source)


if __name__ == '__main__':
    unittest.main()

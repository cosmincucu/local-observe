"""Require action approval and observer review to pass in a real browser without skips."""
import os
from pathlib import Path
import sys
import unittest


def main():
    from playwright.sync_api import sync_playwright
    root = Path(__file__).resolve().parents[1]
    sys.path[:0] = [str(root), str(root / 'tests')]
    with sync_playwright() as browser_api:
        selected = os.environ.get('LO_TEST_BROWSER') or browser_api.chromium.executable_path
    if not Path(selected).is_file() or not os.access(selected, os.X_OK):
        print('Install the pinned Playwright Chromium browser before this check.', file=sys.stderr)
        return 2
    os.environ['LO_TEST_BROWSER'] = selected
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        'test_operator.OperatorTests.test_action_approval_in_chromium_with_real_platform_api',
        'test_observer_review_browser'])
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and expected >= 2 and result.testsRun == expected and not result.skipped else 1


if __name__ == '__main__':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())

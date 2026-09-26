"""Desktop and mobile operator workflow checks using an isolated demo.

Each report entry comes from an assertion that ran. Failed assertions or page errors
refuse the report. Screenshots and credentials stay in the ignored scratch directory.
"""
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _lib.report import write_report
from _lib.require import require

ROOT = Path(__file__).resolve().parents[1]
directory = ROOT / 'scratch/operator-demo'
credentials = json.loads((directory / 'credentials.json').read_text())
VIEWPORTS = [('desktop', {'width': 1440, 'height': 960}), ('mobile', {'width': 390, 'height': 844})]
CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe'


def verify(ran, viewport, name, condition):
    """Record ``name`` as verified for ``viewport``, or refuse the whole run.

    Every check the script claims must come through here, so a claim in the report is only ever a
    value this run observed. An unmet condition raises before the record is appended, which means a
    partial run can never be written up as a pass.

    Args:
        ran: Per-viewport list of checks verified so far, appended to in place.
        viewport: The ``<width>x<height>`` label the check ran under.
        name: Plain words for what was verified, written into the report.
        condition: The observed truth of that claim.

    Raises:
        ValueError: ``condition`` is false; no report is written.
    """
    require(condition, 'operator check failed: ' + name + ' at ' + viewport)
    ran.setdefault(viewport, []).append(name)


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=CHROME, headless=True)
    failures = []
    ran = {}
    for name, size in VIEWPORTS:
        viewport = str(size['width']) + 'x' + str(size['height'])
        page = browser.new_page(viewport=size)
        page.on('pageerror', lambda error: failures.append(str(error)))
        page.goto(json.loads((directory / 'server.json').read_text())['url'])
        page.locator('#token').fill(credentials[0]['token'])
        page.get_by_role('button', name='Sign in', exact=True).click()
        page.locator('#records tr').first.wait_for()
        verify(ran, viewport, 'sign-in lists the open record', page.locator('#open-count').inner_text() == '1')
        verify(ran, viewport, 'no horizontal overflow',
               page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'))
        page.screenshot(path=str(directory / (name + '.png')), full_page=True)
        page.locator('[data-view="actions"]').click()
        page.get_by_role('button', name='Inspect record', exact=True).first.click()
        page.get_by_role('button', name='Approve', exact=True).wait_for()
        verify(ran, viewport, 'operator is offered the approval action',
               page.get_by_role('button', name='Approve', exact=True).count() == 1)
        page.get_by_role('button', name='Approve', exact=True).click()
        page.get_by_role('button', name='Cancel', exact=True).click()
        verify(ran, viewport, 'approving then cancelling keeps the detail open',
               page.locator('#detail').is_visible())
        page.get_by_role('button', name='Close', exact=True).click()
        page.locator('[data-view="events"]').click()
        page.get_by_role('button', name='Inspect record', exact=True).first.click()
        page.get_by_role('button', name='Read evidence', exact=True).click()
        page.locator('#evidence pre').wait_for()
        verify(ran, viewport, 'evidence names the demo record',
               'operator-demo' in page.locator('#evidence').inner_text())
        page.get_by_role('button', name='Close', exact=True).click()
        page.get_by_role('button', name='Sign out', exact=True).click()
        page.locator('#token').fill(credentials[1]['token'])
        page.get_by_role('button', name='Sign in', exact=True).click()
        page.locator('[data-view="actions"]').click()
        page.get_by_role('button', name='Inspect record', exact=True).first.click()
        verify(ran, viewport, 'a reader is never offered the approval action',
               page.get_by_role('button', name='Approve', exact=True).count() == 0)
        page.close()
    browser.close()
    verify(ran, 'all', 'no page script errors', not failures)
    write_report(directory / 'browser-report.json', {
        'status': 'pass',
        'scope': ('the bundled operator demo served locally on one port, driven in one headless Chrome '
                  'at two viewports, against its own generated records; no deployed platform and no live store'),
        'limitations': ['page script errors are collected per viewport and never counted as UI behaviour',
                        'visual layout is captured in screenshots only; styling is not asserted'],
        'viewports': [str(size['width']) + 'x' + str(size['height']) for _name, size in VIEWPORTS],
        'checks': list(dict.fromkeys(check for names in ran.values() for check in names)),
        'checks_by_viewport': ran,
        'screenshots': [name + '.png' for name, _size in VIEWPORTS]})
    print('Desktop/mobile operator checks passed')

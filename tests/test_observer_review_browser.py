"""The operator UI over the authenticated observer review API, driven in a real browser.

`test_observer_review_api.py` proves the routes answer correctly and `test_operator.py` proves the
shell's approval workflow. Neither covers the last metre: a person on a phone who has to read a retained
cycle, find the two grade questions, and be sure the review they submitted was recorded once. These tests
run the actual ``ui.js``, ``index.html`` and ``ui.css`` in Chromium against the actual ASGI app and a real
observer ``Journal``, with no mocked success anywhere:

* **one review, appended once** — the identity, grades, correction and export approval that arrive in the
  journal are the ones on screen, and the reviewer named is the authenticated human;
* **nothing invented** — an ungraded cycle says ``not reviewed``, the grade boxes start untouched, a cycle
  the journal cannot grade offers no form, and a refusal leaves the answer visible;
* **no second append by accident** — a retry of the same review repeats one review id, changed content
  after an unknown outcome is refused before it leaves the page, and a 409 stops the form until the record
  is read again;
* **a phone-sized answer** — at 390x844 and at 1440x960 the record, its nested evidence labels and a long
  correction fit without a sideways swipe, and a rationale containing ``<script>`` stays text: no script
  runs, no dialog opens, no element is created.

Browser requests are fulfilled through ``httpx.ASGITransport``, so nothing listens on a socket and nothing
outside the synthetic origin is reached. Every cycle is the synthetic fixture of
``test_observer_review_api.py``; no real installation's telemetry appears here.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import importlib.util
import json
import os
import re
import unittest

import httpx

import test_observer_review_api as review
from local_observe.platform import observer_review
from local_observe.platform.api import create_app
from local_observe.platform.operator import with_ui

ORIGIN = 'https://observer.example.test'
PHONE = (390, 844)
DESKTOP = (1440, 960)
#: Ordinary prose on purpose: ``journal.feedback`` redacts credential-shaped text, so a correction that
#: looked like a secret would come back compared against a value the journal itself had already masked.
CORRECTION = ('The corrected reading: widen the window before trusting a quiet result. The collector '
              'restart at 00:20 falls inside the sampled range.')
#: The five keys the review route names, and the five it names inside ``values``. A page that invented a
#: sixth — a ``reviewer``, a ``role``, an ``identity`` — would be asking the platform to trust the body.
BODY_KEYS = {'cycle_id', 'feedback_id', 'cycle_sha256', 'previous_feedback_id', 'values'}
VALUE_KEYS = {'usefulness', 'correctness', 'corrected_answer', 'export_approved', 'review_seconds'}
REVIEW_ID = re.compile(r'^review-[0-9a-f]{32}$')
#: The three widths that may have to be compared on a phone: the page against the screen, the list
#: against its own box, and the open record against the dialog it lives in. Each one is a sideways swipe
#: an operator would have to make, which is exactly what this surface must not need.
FITS = '''() => ({
  page: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  list: (() => {
    const wrap = document.querySelector('.table-wrap'), table = document.querySelector('table');
    return wrap && table ? table.scrollWidth - wrap.clientWidth : 0;
  })(),
  dialog: (() => {
    const box = document.getElementById('detail');
    return box && box.open ? box.scrollWidth - box.clientWidth : 0;
  })()
})'''


def app_for(store, credentials, state=None):
    """The real platform app — review surface enabled unless ``state`` is None — behind the shell."""
    return with_ui(create_app(store, credentials, {}, observer_review=state))


@asynccontextmanager
async def session(browser, app, size):
    """One page whose every request is answered by ``app``, with what left the page written down.

    The mapping it yields is a case's only handle on the platform: ``posts`` is what the browser actually
    sent, ``errors`` and ``dialogs`` are what executed, and the fault switches break the platform rather
    than the page — a transport failure, a status, a body rewritten into an unusable shape, or a request
    held open so an operator can sign out or close a record while the answer is still on its way.
    """
    state = {'posts': [], 'errors': [], 'dialogs': [], 'abort': [], 'status': {}, 'rewrite': {},
             'defer': [], 'waiters': [], 'delivered': 0}

    async def forward(request):
        return await state['client'].request(request.method, request.url, headers=request.headers,
                                             content=request.post_data)

    async def deliver(route, request, response):
        await route.fulfill(status=response.status_code, headers=dict(response.headers),
                            body=response.content)
        state['delivered'] += 1

    async def route_request(route):
        request = route.request
        url = httpx.URL(request.url)
        if url.host != 'observer.example.test':
            await route.abort()
            raise AssertionError('Unexpected browser origin: ' + url.host)
        if request.method == 'POST':
            state['posts'].append((url.path, request.post_data_json))
        # Paths are matched exactly, never as prefixes: `/v1/observer/cycle` is a prefix of
        # `/v1/observer/cycles`, so a fault aimed at one record would otherwise catch the list too.
        if url.path in state['abort']:
            await route.abort()
            return
        if url.path in state['defer']:
            state['waiters'].append((route, request))
            return
        response = await forward(request)
        rewrite = state['rewrite'].get(url.path)
        if rewrite is not None:
            await route.fulfill(status=response.status_code, json=rewrite(response.json()))
            state['delivered'] += 1
            return
        fake = state['status'].get(url.path)
        if fake:
            await route.fulfill(status=fake, json={'error': 'refused'})
            state['delivered'] += 1
            return
        await deliver(route, request, response)

    async def release():
        """Let every held request through, so a late answer arrives after the operator has moved on."""
        held, state['waiters'] = state['waiters'], []
        for route, request in held:
            await deliver(route, request, await forward(request))
        await quiesce(state['page'])

    state['release'] = release
    context = await browser.new_context(viewport={'width': size[0], 'height': size[1]})
    page = state['page'] = await context.new_page()
    page.on('pageerror', lambda error: state['errors'].append(str(error)))

    async def on_dialog(dialog):
        state['dialogs'].append(dialog.message)
        await dialog.dismiss()

    page.on('dialog', on_dialog)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        state['client'] = client
        await context.route('**/*', route_request)
        try:
            yield state
        finally:
            await context.close()


async def quiesce(page) -> None:
    """Wait until the page has taken another turn of its own event loop.

    A timer scheduled inside the page can only run after the tasks already queued in it, so this is how a
    case proves a delivered answer had its chance to touch the screen before the screen is read.
    """
    await page.evaluate('() => new Promise((resolve) => setTimeout(resolve, 120))')


@unittest.skipUnless(importlib.util.find_spec('playwright') and os.environ.get('LO_TEST_BROWSER'),
                     'browser acceptance requires Playwright and LO_TEST_BROWSER executable')
class ObserverReviewBrowserTests(unittest.TestCase):
    """Chromium acceptance for the investigations view; every case uses the real app and the real journal."""

    def setUp(self) -> None:
        self.human = {'Authorization': 'Bearer ' + review.HUMAN_A['token']}
        self.fresh()

    def fresh(self):
        """A new state directory, store and four synthetic cycles, cleaned up with this test.

        A case that runs one flow at two viewport sizes needs the same starting journal twice: the
        reviews recorded during the phone pass would otherwise be facts the desktop pass has to explain.
        """
        self.case = review.ReviewFixture()
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.case.seeded()
        return self.case

    def reviews(self, cycle_id: str) -> list[dict]:
        """The reviews this journal holds for one cycle, oldest first, read back row by row."""
        rows = self.case.journal.db.execute(
            'SELECT document FROM feedback WHERE cycle_id=? ORDER BY rowid', (cycle_id,)).fetchall()
        return [json.loads(row[0]) for row in rows]

    def submits(self, state) -> list[dict]:
        return [body for path, body in state['posts'] if path == observer_review.FEEDBACK_ROUTE]

    async def start(self, state, token=review.HUMAN_A['token']):
        from playwright.async_api import expect
        page = state['page']
        await page.goto(ORIGIN + '/')
        await page.locator('#token').fill(token)
        await page.get_by_role('button', name='Sign in', exact=True).click()
        await expect(page.locator('#login')).not_to_be_visible()
        await page.locator('[data-view="investigations"]').click()
        return page

    async def sign_in(self, state, token=review.HUMAN_A['token']) -> None:
        """Sign in again on a page that is already open, without reloading the shell."""
        from playwright.async_api import expect
        page = state['page']
        await page.locator('#token').fill(token)
        await page.get_by_role('button', name='Sign in', exact=True).click()
        await expect(page.locator('#login')).not_to_be_visible()

    async def sign_out(self, state) -> None:
        from playwright.async_api import expect
        await state['page'].get_by_role('button', name='Sign out', exact=True).click()
        await expect(state['page'].locator('#login')).to_be_visible()

    async def open_record(self, state, cycle_id: str, settled: str):
        """Inspect one cycle, then wait for the panel to say what it holds rather than that it is loading."""
        from playwright.async_api import expect
        page = state['page']
        await page.locator('#records tr').filter(has_text=cycle_id) \
            .get_by_role('button', name='Inspect investigation').click()
        await expect(page.locator('#observer-state')).to_contain_text(settled)
        return page

    async def close_record(self, state) -> None:
        await state['page'].locator('#close-detail').click()

    async def grade(self, state, usefulness: str, correctness: str) -> None:
        from playwright.async_api import expect
        page = state['page']
        await page.locator('#observer-grades input[name="observer-usefulness"][value="%s"]' % usefulness).check()
        await page.locator('#observer-grades input[name="observer-correctness"][value="%s"]' % correctness).check()
        await expect(page.locator('#observer-submit')).to_be_enabled()

    async def fits(self, state, size) -> None:
        """No sideways swipe anywhere: page, list and the open record each stay inside their own box."""
        page = state['page']
        self.assertEqual(await page.evaluate('window.innerWidth'), size[0])
        room = await page.evaluate(FITS)
        self.assertEqual(state['errors'], [])
        for name, overflow in room.items():
            self.assertLessEqual(overflow, 1, '%s needs a sideways swipe at %dx%d (%d px over)'
                                 % (name, size[0], size[1], overflow))

    async def reached(self, state, *selectors) -> None:
        """Every control the operator has to use is on the screen, not past its edge or under its floor."""
        page = state['page']
        screen = await page.evaluate('() => [window.innerWidth, window.innerHeight]')
        for selector in selectors:
            control = page.locator(selector)
            await control.scroll_into_view_if_needed()
            box = await control.bounding_box()
            self.assertIsNotNone(box, selector + ' has no box on screen')
            self.assertGreaterEqual(box['x'], 0, selector + ' starts off the left edge')
            self.assertLessEqual(box['x'] + box['width'], screen[0] + 1, selector + ' passes the right edge')
            self.assertGreaterEqual(box['y'], 0, selector + ' starts above the screen')
            self.assertLessEqual(box['y'] + box['height'], screen[1] + 1, selector + ' passes the bottom edge')

    def test_review_a_quiet_cycle_once_on_a_phone_and_a_desktop(self):
        """Sign in, read what was retained, correct it, approve the export, and see who recorded it."""
        async def check():
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    for size in (PHONE, DESKTOP):
                        case = self.fresh()
                        async with session(browser, app_for(case.store, review.CREDENTIALS, case.state),
                                           size) as state:
                            await self.review_flow(state, size)
                finally:
                    await browser.close()

        from playwright.async_api import async_playwright
        asyncio.run(check())

    async def review_flow(self, state, size) -> None:
        from playwright.async_api import expect
        page = await self.start(state)
        rows = page.locator('#records tr')
        await expect(rows).to_have_count(4)
        await expect(page.locator('#observer-summary')).to_have_text('4 of 4 retained cycles, newest first.')
        for cycle_id in ('quiet-1', 'tell-1', 'failed-1', 'running-1'):
            await expect(rows.filter(has_text=cycle_id).locator('td').nth(2)).to_have_text(
                re.compile(r'^not reviewed'))
        await expect(rows.filter(has_text='quiet-1').locator('td').nth(1)).to_have_text(
            'quiet / complete / completed')
        await expect(rows.filter(has_text='running-1').locator('td').nth(2)).to_contain_text(
            'cannot be graded yet')
        await self.fits(state, size)

        # The retained record: the observer's own words and evidence whose labels are still nested.
        # The fixture's rationale is shell- and markup-shaped on purpose. The digest a review must answer is
        # a submission precondition, not something a person needs to grade an investigation: sent, never shown.
        await self.open_record(state, 'quiet-1', 'The record below is what the observer retained')
        record = page.locator('#observer-record')
        digest = (await state['client'].get(observer_review.CYCLE_ROUTE + '?cycle_id=quiet-1',
                                           headers=self.human)).json()['cycle_sha256']
        for expected in (review.RATIONALE, '"role": "test"', '"tags"', 'not recorded'):
            await expect(record).to_contain_text(expected)
        # The digest stays off the page and is still echoed back on send (asserted with the submitted body).
        await expect(page.locator('body')).not_to_contain_text(digest)
        await expect(record).to_contain_text('Human grade')
        await expect(page.locator('#observer-history')).to_contain_text('0 review(s) held')
        self.assertEqual(await page.locator('#observer-grades input:checked').count(), 0)
        await expect(page.locator('#observer-submit')).to_be_disabled()
        await expect(page.locator('#observer-feedback')).to_be_hidden()
        await self.fits(state, size)
        await self.reached(state, '#observer-grades', '#observer-answer', '#observer-export',
                           '#observer-seconds', '#observer-submit')

        await self.grade(state, 'useful', 'correct')
        await page.locator('#observer-answer').fill(CORRECTION)
        await page.locator('#observer-seconds').fill('42')
        await page.locator('#observer-export').check()
        await page.locator('#observer-submit').click()
        await expect(page.locator('#observer-feedback')).to_have_text(
            "Review recorded. The observer's retained record of this cycle is unchanged."
            ' Recorded by platform-human:operator-a.')
        self.assertEqual(len(self.submits(state)), 1)
        body = self.submits(state)[0]
        self.assertEqual(set(body), BODY_KEYS)
        self.assertEqual(set(body['values']), VALUE_KEYS)
        self.assertRegex(body['feedback_id'], REVIEW_ID)
        self.assertEqual(body['cycle_sha256'], digest)
        self.assertIsNone(body['previous_feedback_id'])
        held = self.reviews('quiet-1')
        self.assertEqual(len(held), 1)
        self.assertEqual(held[0]['reviewer'], 'platform-human:operator-a')
        self.assertEqual(held[0]['usefulness'], 'useful')
        self.assertEqual(held[0]['corrected_answer'], CORRECTION)
        self.assertTrue(held[0]['export_approved'])
        self.assertEqual(held[0]['review_seconds'], 42)
        # Nothing executed on the way there: no page error, no dialog, and no element made from that text.
        self.assertEqual(state['errors'], [])
        self.assertEqual(state['dialogs'], [])
        self.assertEqual(await page.locator('#observer-record script, #observer-record iframe,'
                                            '#observer-record img, #observer-record object').count(), 0)
        self.assertEqual(await page.evaluate('document.scripts.length'), 2)
        # Grading a cycle does not make it ungradeable or rewrite it: the same read still offers a form.
        self.assertTrue((await state['client'].get(observer_review.CYCLE_ROUTE + '?cycle_id=quiet-1',
                                                   headers=self.human)).json()['reviewable'])

        # And the record read back says what the human said, newest first, under their own identity.
        await expect(page.locator('#observer-history')).to_contain_text('1 review(s) held')
        await expect(page.locator('#observer-history')).to_contain_text('Latest review')
        await expect(page.locator('#observer-history')).to_contain_text('platform-human:operator-a')
        await expect(page.locator('#observer-history')).to_contain_text('yes')
        self.assertEqual(await page.locator('#observer-grades input:checked').count(), 0)
        await self.close_record(state)
        await page.get_by_role('button', name='Refresh', exact=True).click()
        await expect(page.locator('#records tr').filter(has_text='quiet-1').locator('td').nth(2)) \
            .to_have_text(re.compile(r'^reviewed'))

        # A cycle still running is readable and refuses a grade. A failed one can be graded but has no
        # evidence, so an export approval on it is refused rather than quietly allowed.
        await self.open_record(state, 'running-1', 'still running')
        await expect(page.locator('#observer-review')).to_be_hidden()
        await expect(page.locator('#observer-record')).to_contain_text('running')
        await self.fits(state, size)
        await self.close_record(state)
        await self.open_record(state, 'failed-1', 'The record below is what the observer retained')
        await expect(page.locator('#observer-record')).to_contain_text('No evidence was retained')
        await self.grade(state, 'useful', 'correct')
        await page.locator('#observer-answer').fill(CORRECTION)
        await page.locator('#observer-export').check()
        await page.locator('#observer-submit').click()
        await expect(page.locator('#observer-feedback')).to_have_text(
            'Refused (corrected_evidence_required_for_export). Nothing was recorded.')
        self.assertEqual(self.reviews('failed-1'), [])
        self.assertEqual(len(self.submits(state)), 2)
        await page.locator('#observer-export').uncheck()
        await page.locator('#observer-submit').click()
        await expect(page.locator('#observer-feedback')).to_contain_text('Review recorded.')
        self.assertEqual([row['reviewer'] for row in self.reviews('failed-1')], ['platform-human:operator-a'])
        self.assertFalse(self.reviews('failed-1')[0]['export_approved'])
        self.assertIsNone(self.reviews('failed-1')[0]['review_seconds'])
        await self.fits(state, size)

    def test_a_stale_review_is_refused_until_the_record_is_read_again(self):
        """Another human's review lands mid-form: refuse, keep the typed answer, record after a reload."""
        async def check():
            from playwright.async_api import expect
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    async with session(browser, app_for(self.case.store, review.CREDENTIALS,
                                                        self.case.state), PHONE) as state:
                        page = await self.start(state)
                        shown = (await state['client'].get(observer_review.CYCLE_ROUTE + '?cycle_id=quiet-1',
                                                          headers=self.human)).json()
                        await self.open_record(state, 'quiet-1', 'The record below')
                        rival = await state['client'].post(
                            observer_review.FEEDBACK_ROUTE,
                            headers={'Authorization': 'Bearer ' + review.HUMAN_B['token']},
                            json=review.submission('quiet-1', 'rival-1', shown['cycle_sha256'], None,
                                                   usefulness='noise', correctness='incorrect'))
                        self.assertEqual(rival.status_code, 200)
                        await self.grade(state, 'useful', 'correct')
                        await page.locator('#observer-answer').fill(CORRECTION)
                        await page.locator('#observer-submit').click()
                        await expect(page.locator('#observer-feedback')).to_have_text(
                            'This review was refused: the cycle moved on, or another review became the '
                            'newest. Nothing was recorded. Reload this record before grading it again.')
                        await expect(page.locator('#observer-submit')).to_be_disabled()
                        await expect(page.locator('#observer-reload')).to_be_enabled()
                        self.assertEqual([row['feedback_id'] for row in self.reviews('quiet-1')], ['rival-1'])
                        self.assertEqual(len(self.submits(state)), 1)
                        # The refused answer is still on screen: nothing the operator typed was thrown away.
                        self.assertEqual(await page.locator('#observer-answer').input_value(), CORRECTION)
                        await page.locator('#observer-reload').click()
                        await expect(page.locator('#observer-history')).to_contain_text(
                            'platform-human:operator-b')
                        self.assertEqual(await page.locator('#observer-answer').input_value(), CORRECTION)
                        await self.grade(state, 'useful', 'correct')
                        await page.locator('#observer-submit').click()
                        await expect(page.locator('#observer-feedback')).to_contain_text('Review recorded.')
                        self.assertEqual([row['reviewer'] for row in self.reviews('quiet-1')],
                                         ['platform-human:operator-b', 'platform-human:operator-a'])
                        self.assertEqual(self.submits(state)[-1]['previous_feedback_id'], 'rival-1')
                        self.assertEqual(self.submits(state)[-1]['feedback_id'],
                                         self.reviews('quiet-1')[1]['feedback_id'])
                        self.assertEqual(state['errors'], [])
                        self.assertEqual(state['dialogs'], [])
                finally:
                    await browser.close()

        from playwright.async_api import async_playwright
        asyncio.run(check())

    def test_one_review_is_one_append_whatever_the_network_does(self):
        """A send whose answer never arrived is repeated with the same id; a different review waits."""
        async def check():
            from playwright.async_api import expect
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    async with session(browser, app_for(self.case.store, review.CREDENTIALS,
                                                        self.case.state), PHONE) as state:
                        page = await self.start(state)
                        await self.open_record(state, 'quiet-1', 'The record below')
                        await self.grade(state, 'useful', 'correct')
                        await page.locator('#observer-answer').fill(CORRECTION)
                        state['abort'] = [observer_review.FEEDBACK_ROUTE]
                        await page.locator('#observer-submit').click()
                        await expect(page.locator('#observer-feedback')).to_have_text(
                            "The platform's answer did not arrive, so it is not known whether this review "
                            'was recorded. Reload this record before trying again, and only send a '
                            'different review after you have seen what the record holds.')
                        self.assertEqual(len(self.submits(state)), 1)
                        self.assertEqual(self.reviews('quiet-1'), [])
                        self.assertEqual(await page.locator('#observer-answer').input_value(), CORRECTION)
                        # Same grades, different words: this panel will not put a second answer on the
                        # wire while the fate of the first is unknown.
                        await page.locator('#observer-answer').fill(CORRECTION + ' Checked the exporter.')
                        await page.locator('#observer-submit').click()
                        await expect(page.locator('#observer-feedback')).to_have_text(
                            'This is a different review from the one whose outcome is unknown. Nothing '
                            'was sent: reload this record first.')
                        self.assertEqual(len(self.submits(state)), 1)
                        self.assertEqual(self.reviews('quiet-1'), [])
                        # Back to the review already attempted: the same id goes out, however many times.
                        await page.locator('#observer-answer').fill(CORRECTION)
                        await page.locator('#observer-submit').click()
                        self.assertEqual(len(self.submits(state)), 2)
                        self.assertEqual(self.submits(state)[0]['feedback_id'],
                                         self.submits(state)[1]['feedback_id'])
                        state['abort'] = []
                        await page.locator('#observer-submit').click()
                        await expect(page.locator('#observer-feedback')).to_contain_text('Review recorded.')
                        self.assertEqual(len(self.submits(state)), 3)
                        self.assertEqual({body['feedback_id'] for body in self.submits(state)},
                                         {self.submits(state)[0]['feedback_id']})
                        self.assertEqual(len(self.reviews('quiet-1')), 1)
                        self.assertEqual(self.reviews('quiet-1')[0]['corrected_answer'], CORRECTION)
                        self.assertEqual(state['errors'], [])
                finally:
                    await browser.close()

        from playwright.async_api import async_playwright
        asyncio.run(check())

    def test_each_failure_says_its_own_true_thing(self):
        """No journal, no authority, an unusable reply, a refused read: four states, never a green page."""
        async def check():
            from playwright.async_api import expect
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    # The optional feature is off: the route answers 404 and the page says so, rather than
                    # showing an empty list a tired reader could mistake for a quiet platform.
                    async with session(browser, app_for(self.case.store, review.CREDENTIALS), PHONE) as state:
                        page = await self.start(state)
                        await expect(page.locator('#observer-summary')).to_have_text(
                            'Investigation review is unavailable: this platform has no observer journal '
                            'configured.')
                        self.assertEqual(await page.locator('#records tr').count(), 0)
                        await expect(page.locator('#observer-more')).to_be_hidden()
                        self.assertEqual(state['errors'], [])

                    async with session(browser, app_for(self.case.store, review.CREDENTIALS,
                                                        self.case.state), PHONE) as state:
                        page = await self.start(state, review.READER['token'])
                        await expect(page.locator('#observer-summary')).to_have_text(
                            'This sign-in may not read investigations, so nothing is shown.')
                        self.assertEqual(await page.locator('#records tr').count(), 0)
                        await self.sign_out(state)

                        missing = lambda body: {key: value for key, value in body.items()  # noqa: E731
                                                if key != 'total_cycles'}
                        renamed = lambda body: {  # noqa: E731
                            **body, 'cycles': [{key: value for key, value in row.items() if key != 'cycle_id'}
                                               for row in body['cycles']]}
                        for fault, expected in (
                                ({'rewrite': {observer_review.CYCLES_ROUTE: missing}},
                                 'The reply was not an investigation list this panel can vouch for, so '
                                 'nothing is listed.'),
                                ({'rewrite': {observer_review.CYCLES_ROUTE: renamed}},
                                 'The reply was not an investigation list this panel can vouch for, so '
                                 'nothing is listed.'),
                                ({'status': {observer_review.CYCLES_ROUTE: 503}},
                                 'The observer journal could not be read. Nothing was listed, and nothing '
                                 'was recorded.'),
                                ({'abort': [observer_review.CYCLES_ROUTE]},
                                 'The platform could not be reached. Nothing was listed, and nothing was '
                                 'recorded.')):
                            state.update(fault)
                            await self.sign_in(state)
                            await page.locator('[data-view="investigations"]').click()
                            await expect(page.locator('#observer-summary')).to_have_text(expected)
                            self.assertEqual(await page.locator('#records tr').count(), 0)
                            await expect(page.locator('#observer-more')).to_be_hidden()
                            await expect(page.locator('#refresh')).to_be_enabled()
                            state['rewrite'], state['status'], state['abort'] = {}, {}, []
                            await self.sign_out(state)

                        # A record this panel cannot vouch for is shown as nothing and offers no form; a
                        # refused read names which refusal it was. Neither can be graded by accident.
                        await self.sign_in(state)
                        await page.locator('[data-view="investigations"]').click()
                        await expect(page.locator('#records tr')).to_have_count(4)
                        state['rewrite'] = {observer_review.CYCLE_ROUTE: lambda body: {
                            **body, 'cycle_sha256': 'not-a-digest'}}
                        await self.open_record(state, 'quiet-1', 'not an investigation record')
                        await expect(page.locator('#observer-review')).to_be_hidden()
                        await expect(page.locator('#observer-record')).to_be_empty()
                        await expect(page.locator('#observer-reload')).to_be_enabled()
                        state['rewrite'] = {}
                        state['status'] = {observer_review.CYCLE_ROUTE: 404}
                        await page.locator('#observer-reload').click()
                        await expect(page.locator('#observer-state')).to_have_text(
                            'The observer journal has no record of this cycle, so there is nothing to grade.')
                        await self.close_record(state)
                        state['status'] = {observer_review.CYCLE_ROUTE: 403}
                        await self.open_record(state, 'tell-1', 'may not read investigations')
                        await expect(page.locator('#observer-review')).to_be_hidden()
                        self.assertEqual(self.submits(state), [])
                        self.assertEqual(state['errors'], [])
                        self.assertEqual(state['dialogs'], [])
                finally:
                    await browser.close()

        from playwright.async_api import async_playwright
        asyncio.run(check())

    def test_a_late_answer_lands_nowhere_after_sign_out_or_a_closed_record(self):
        """Hold a request open, move on, then let the answer arrive: no rows, no record, no form."""
        async def check():
            from playwright.async_api import expect
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    async with session(browser, app_for(self.case.store, review.CREDENTIALS,
                                                        self.case.state), PHONE) as state:
                        page = await self.start(state)
                        await expect(page.locator('#records tr')).to_have_count(4)
                        state['defer'] = [observer_review.CYCLES_ROUTE]
                        await page.get_by_role('button', name='Refresh', exact=True).click()
                        await expect(page.locator('#observer-summary')).to_have_text('Loading investigations.')
                        await self.sign_out(state)
                        await state['release']()
                        # The answer arrived and changed nothing: no row, no list count, and a shell that
                        # is still waiting at its own sign-in form.
                        self.assertGreaterEqual(state['delivered'], 2)
                        self.assertEqual(await page.evaluate('document.querySelectorAll("#records tr").length'), 0)
                        self.assertEqual(await page.evaluate(
                            'document.getElementById("observer-summary").textContent'), '')
                        self.assertTrue(await page.evaluate('document.getElementById("login").open'))
                        await page.locator('#token').wait_for(state='visible')
                        state['defer'] = []

                        await self.sign_in(state)
                        await page.locator('[data-view="investigations"]').click()
                        await expect(page.locator('#records tr')).to_have_count(4)
                        state['defer'] = [observer_review.CYCLE_ROUTE]
                        await page.locator('#records tr').filter(has_text='tell-1') \
                            .get_by_role('button', name='Inspect investigation').click()
                        await expect(page.locator('#observer-state')).to_have_text(
                            'Reading the retained investigation.')
                        await self.close_record(state)
                        await state['release']()
                        # The record arrived after its dialog went away, so it wrote into no panel and no
                        # grade form is sitting there for the next cycle that gets opened.
                        self.assertEqual(await page.evaluate(
                            'document.getElementById("observer-record").children.length'), 0)
                        self.assertEqual(await page.evaluate(
                            'document.getElementById("observer-grades").children.length'), 0)
                        self.assertTrue(await page.evaluate('document.getElementById("observer").hidden'))
                        self.assertFalse(await page.evaluate('document.getElementById("detail").open'))
                        # Still the same sign-in: only the held-open request had to go away before the
                        # panel could be asked for that record again.
                        state['defer'] = []
                        await page.locator('[data-view="investigations"]').click()
                        await expect(page.locator('#records tr')).to_have_count(4)
                        await self.open_record(state, 'tell-1', 'The record below is what the observer retained')
                        await expect(page.locator('#observer-history')).to_contain_text('0 review(s) held')
                        self.assertEqual(state['errors'], [])
                finally:
                    await browser.close()

        from playwright.async_api import async_playwright
        asyncio.run(check())

    def test_older_investigations_are_offered_and_then_kept(self):
        """One page is an answer about a page, not about the journal: `Load older` extends it in order."""
        async def check():
            from playwright.async_api import expect
            case = self.fresh()
            for index in range(21, 46):  # four from `fresh()`, then 25 more: a page and a remainder
                review.add_cycle(case.journal, 'bulk-%02d' % index, minutes=index,
                                 answer=dict(review.QUIET_ANSWER))
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(executable_path=os.environ['LO_TEST_BROWSER'])
                try:
                    async with session(browser, app_for(case.store, review.CREDENTIALS, case.state),
                                       PHONE) as state:
                        page = await self.start(state)
                        rows = page.locator('#records tr')
                        await expect(rows).to_have_count(20)
                        await expect(page.locator('#observer-summary')).to_have_text(
                            '20 of 29 retained cycles, newest first \u2014 9 older cycle(s) available below.')
                        cells = page.locator('#records tr td:first-child')
                        self.assertEqual(await cells.first.inner_text(), 'bulk-45')
                        self.assertEqual(await cells.nth(19).inner_text(), 'bulk-26')
                        await self.fits(state, PHONE)
                        first_page = await cells.all_text_contents()

                        await page.get_by_role('button', name='Load older investigations').click()
                        await expect(rows).to_have_count(29)
                        await expect(page.locator('#observer-summary')).to_have_text(
                            '29 of 29 retained cycles, newest first.')
                        await expect(page.locator('#observer-more')).to_be_hidden()
                        await expect(page.get_by_role('button', name='Refresh', exact=True)).to_be_enabled()
                        # The older page was added under the one already on screen, in the same order: no
                        # row the operator had read disappeared or moved because a second page arrived.
                        self.assertEqual((await cells.all_text_contents())[:20], first_page)
                        self.assertEqual(await cells.nth(28).inner_text(), 'quiet-1')

                        # The search box works over what is loaded, and says so when it matches nothing.
                        await page.locator('#search').fill('failed-1')
                        await expect(rows).to_have_count(1)
                        await expect(page.locator('#empty')).to_be_hidden()
                        await page.locator('#search').fill('quiet-sample-missing')
                        await expect(rows).to_have_count(0)
                        await expect(page.locator('#empty')).to_have_text('No listed cycle matches this search.')
                        await page.locator('#search').fill('')
                        await expect(rows).to_have_count(29)
                        self.assertEqual(state['errors'], [])
                        self.assertEqual(state['dialogs'], [])
                finally:
                    await browser.close()

        from playwright.async_api import async_playwright
        asyncio.run(check())


if __name__ == '__main__':
    unittest.main()

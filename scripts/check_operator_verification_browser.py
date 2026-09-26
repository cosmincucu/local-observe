"""Browser proof for the read-only verification history in the operator's execution detail .

What this drives is the real UI against the real API of ``scripts/serve_operator_demo.py``, in one headless
Chrome at two viewports, inside a fixture directory created fresh for the run it points at. The report is
written only after every assertion has passed, and every entry in it is something this run observed — the
same discipline as ``check_operator_browser.py``, which this file neither touches nor reuses.

Why a separate script: this proof needs an isolated dataset with saved verification records in it. The
existing checker reads the long-lived ``scratch/operator-demo`` fixture; this one refuses that path,
because a proof run that quietly adopted an earlier run's credentials or database would prove nothing
about the history it claims to have read.

How the two halves split:

* the **positive path is the real server** — the ids listed, the record shown, the empty answer and the
  order they arrive in all come from ``GET /v1/verification/records`` and ``GET /v1/verification/record``
  over the loopback socket, and the expected values are read out-of-band with the same credential rather
  than typed into this file;
* **negative payloads and timing are injected** — 403/404/503/500, a dropped connection, malformed and
  over-cap bodies, mismatched identity fields, a markup-bearing string, and the delayed replies that turn
  a stale-result race into a deterministic one. Interception replaces a *reply*; it never stands in for
  the UI's own request, and every injected response carries the server's own ``cache-control: no-store``
  so the header assertion tests the request the page actually made.

The async API is deliberate: a delayed response has to still be in flight *while* this script clicks
another row, closes the dialog or signs out. A sleeping route handler under the sync API blocks the
dispatcher that would deliver those clicks, so the races this script exists to run would not be races.

Ordering comes from events and route gates, not from sleeps. Every delayed answer sets an
`asyncio.Event` *after* its response has been handed to the browser, and where the ordering is the point
the handler also waits on a second `gate` event that this script sets only after it has closed the dialog,
switched the row or replaced the sign-in — so "the answer arrived after the operator stopped looking" is
arranged rather than hoped for. Every "nothing appeared" claim is measured after that event *and* after
:func:`settle`, which does not infer network completion from frames: a test-only init script
(:data:`COMPLETION_PROBE`) wraps the page's own global `historyFetch` once `ui.js` has defined it and
records every Promise that call actually returned. Awaiting them is what proves a read resolved *as the
page knows it* — animation frames alone prove only that the page got a turn, never that a response
arrived, and they now come second, to let the continuation awaiting that Promise run. The wrapper hands
back the identical Promise, and no product file is read, rewritten or served differently to install it.
`DELAY` only keeps a request demonstrably in flight while the interruption is carried out; it is a test
injection, not a measurement of any real read, and no assertion here is `sleep(n)`-then-look.

**Negative controls** (`--negative-control outcome|stale|html`, test-only). Each one replaces this app's
own `ui.js` response with text differing from the shipped file in exactly one exact-match string, and the
run must then *refuse* to pass: `outcome` makes the record note claim the incident recovered (the
recovery-word census must trip), `stale` makes the staleness gate always admit (the late-answer cases must
trip), `html` renders one record field through `innerHTML` (the direct renderer assertion must trip). A
mutation that does not match exactly once is refused before the browser starts, and a run whose assertions
all pass with a mutation installed is itself the failure — it raises, and writes no report. A negative run
never writes `verification-browser-report.json`: it writes the separate
`verification-negative-control.json`, whose status names it as evidence that a check refuses, not as a
pass of any kind. Ordinary runs behave exactly as they did.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import sys
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _lib.report import write_report
from _lib.require import require
import serve_operator_demo
from playwright.async_api import async_playwright

VIEWPORTS = [('desktop', {'width': 1440, 'height': 960}), ('mobile', {'width': 390, 'height': 844})]
CHROME = 'C:/Program Files/Google/Chrome/Application/chrome.exe'
RECORDS_PATH = '/v1/verification/records'
RECORD_PATH = '/v1/verification/record'
#: Injected responses carry the header the real server sends, so "this read was no-store" is measured
#: against the same contract on both halves of the run instead of a fixture that never set the header.
NO_STORE = {'cache-control': 'no-store'}
#: The platform's own words and shapes. None of them may reach the screen: the panel answers each state
#: with its own fixed sentence, and a backend body on the page would be a payload dump in an error's clothes.
BACKEND_TEXT = ('verification_busy', 'verification_unavailable', 'summary_only', 'not_found',
                'authentication_required', 'verification_storage_error',
                'Verification policy is not configured', 'Verification query is malformed',
                'internal_error', 'Traceback', 'sqlite3', '{', '}')
#: Words that would turn a recorded verdict into a claim about an incident's outcome. The panel's own
#: wording avoids them on purpose — it says what a record does *not* speak to rather than naming a state
#: it cannot know — which is what makes their absence an assertion and not a coincidence.
OUTCOME_WORDS = ('recovered', 'recovery', 'resolved', 'back to normal', 'incident closed', 'is clear')
#: One answer and one status pair, reused for both routes: `None` status means drop the connection.
ANSWERS = [('forbidden', 403, {'error': 'summary_only'}),
           ('absent', 404, {'error': 'not_found'}),
           ('busy', 503, {'error': 'verification_busy'}),
           ('unavailable', 500, {'error': 'verification_storage_error'}),
           ('unavailable', None, None)]
DELAY = 1.5
MARKUP = '<img src=q onerror=alert(1)>'
#: Test-only mutations for :option:`--negative-control`, each one the *whole* text it looks for and the
#: single text it replaces. Every search string must occur exactly once in the shipped `ui.js`: a match
#: count of anything but one is refused before the browser starts, because a mutation that landed twice
#: (or not at all) would be reporting on a file this run never served.
NEGATIVE_CONTROLS = {
    # The recovery-word census is the guard being tested, so the mutation leaves the panel's honest "it
    # changes nothing" sentence in place and corrupts only the sentence beside it.
    'outcome': ('the recorded result claims the incident recovered',
                '"live reading, and it says nothing about whether this incident is over."',
                '"live reading, and it means this incident recovered."'),
    # Every late-answer case in this file is the guard for this one: the gate admits whatever arrives.
    'stale': ('the staleness gate always admits a response',
              'return mine === verification.generation && !!token && $("detail").open;',
              'return true;'),
    # The direct renderer assertion is the guard for this one: a record field is written as markup.
    'html': ('a record field is written through innerHTML',
             'detail.textContent = text;',
             'detail.innerHTML = text;'),
}
#: Where a negative run writes its evidence, named apart from the pass report on purpose.
NEGATIVE_REPORT = 'verification-negative-control.json'
PASS_REPORT = 'verification-browser-report.json'


class RefusedRun(ValueError):
    """An assertion this run refused to paper over.

    It is a `ValueError` so an ordinary run fails exactly as it always did. The negative-control run tells
    its two outcomes apart by class: a `RefusedRun` is the mutation being caught, while any other fault
    (a missing server, a mutation that matched twice) is a broken run and never a caught mutation.
    """


class Traffic:
    """Every API request the page itself made: the count, the method, and the query it carried.

    ``history`` is the working window a case resets before it counts; ``journal`` is the same facts never
    cleared, which is what the report quotes, so a count written up at the end of a run names every read
    the run spent and not merely the ones since the last case began.
    """

    def __init__(self) -> None:
        self.api: list[tuple[str, str]] = []
        self.history: list[tuple[str, str]] = []
        self.journal: list[tuple[str, str]] = []
        self.no_store: list[bool] = []

    def request(self, request) -> None:
        if '/v1/' not in request.url:
            return
        self.api.append((request.method, request.url))
        if '/v1/verification/' in request.url:
            self.history.append((request.method, request.url))
            self.journal.append((request.method, request.url))

    def response(self, response) -> None:
        if '/v1/verification/' in response.url:
            self.no_store.append((response.headers.get('cache-control') or '') == 'no-store')

    def reset(self) -> None:
        self.history.clear()

    async def reach(self, count: int = 1, seconds: float = 15.0) -> bool:
        """Wait until at least *count* history requests have been seen, and say whether they were.

        A click returns to this script before the browser's request event has crossed the wire, so an
        absence measured immediately after one proves nothing: the wait is what turns "I saw no request"
        into a measurement instead of a timing accident.
        """
        deadline = time.monotonic() + seconds
        while len(self.history) < count and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        return len(self.history) >= count

    async def none(self, seconds: float = 1.0) -> bool:
        """Whether no history request arrives for *seconds* — how a no-eager-fetch claim is measured."""
        return not await self.reach(1, seconds)

    async def settled(self, quiet: float = 0.4, seconds: float = 10.0) -> int:
        """The request count once it has stopped moving: what one intent really spent."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            before = len(self.history)
            await asyncio.sleep(quiet)
            if len(self.history) == before:
                return len(self.history)
        return len(self.history)

    def methods(self) -> set[str]:
        return {method for method, _ in self.history}

    def queries(self) -> list[str]:
        return [url.split('?', 1)[1] if '?' in url else '' for _, url in self.history]

    def wrote_anything(self) -> bool:
        """Whether the page issued any non-GET API request — the whole "history never writes" claim."""
        return any(method != 'GET' for method, _ in self.api)


def verify(ran: dict, viewport: str, name: str, condition: bool) -> None:
    """Record ``name`` as verified for ``viewport``, or refuse the whole run.

    Every claim in the report comes through here, so a partial run can never be written up as a pass. The
    raised class is :class:`RefusedRun` so a negative-control run can tell "this check refused the mutated
    UI, as it had to" apart from "this run never got far enough to check anything".
    """
    try:
        require(condition, 'verification history check failed: ' + name + ' at ' + viewport)
    except ValueError as fault:
        raise RefusedRun(str(fault)) from fault
    ran.setdefault(viewport, []).append(name)


def read_api(url: str, token: str, path: str) -> object:
    """Read one endpoint out-of-band with the operator's own credential, to know what to expect.

    This is a second reader of the same API the page reads. It is what lets the assertions name the ids
    the server really returned instead of ids typed into a script.
    """
    request = urllib.request.Request(url + path, headers={'Authorization': 'Bearer ' + token,
                                                          'Accept': 'application/json'})
    with urllib.request.urlopen(request, timeout=30) as answer:
        return json.loads(answer.read())


def expected(url: str, token: str) -> dict:
    """The executions, id lists and stored verdicts this server really answers with, right now."""
    executions = [row for row in read_api(url, token, '/v1/records/executions')['rows']
                  if row['status'] == 'succeeded']
    require(executions, 'the fixture holds no terminal execution to inspect')
    ids: dict[str, list[str]] = {}
    records: dict[str, dict[str, dict]] = {}
    for row in executions:
        answer = read_api(url, token, RECORDS_PATH + '?execution_id=' + row['id'])
        require(isinstance(answer, dict) and list(answer) == ['verification_ids'],
                'the list route answers {"verification_ids": [...]} and nothing else')
        require(len(answer['verification_ids']) <= 64, 'the server itself stayed inside the id cap')
        ids[row['id']] = list(answer['verification_ids'])
        records[row['id']] = {}
        for verification_id in answer['verification_ids']:
            record = read_api(url, token, RECORD_PATH + '?verification_id=' + verification_id)
            require(record['execution_id'] == row['id'], 'a record names the execution it belongs to')
            records[row['id']][verification_id] = {'verdict': record['verdict'],
                                                   'reason': record['reason'],
                                                   'window': dict(record['window']),
                                                   'recorded_at': record['recorded_at']}
    return {'executions': [row['id'] for row in executions], 'ids': ids, 'records': records}


def responder(status: int | None, payload: object):
    """An intercepted answer for whichever verification request arrives: fixed status, fixed body.

    ``status=None`` drops the connection instead of answering it, which is the other way a read can be
    unavailable and the one way to show the panel has no exception text to leak.
    """
    async def action(route) -> None:
        if status is None:
            return await route.abort()
        return await route.fulfill(status=status, content_type='application/json', headers=NO_STORE,
                                   body='' if payload is None else json.dumps(payload))
    return action


def delayed_for(which: str, match: str, seconds: float, landed: asyncio.Event, *,
                status: int = 200, payload: object = None, once: bool = True,
                gate: asyncio.Event | None = None):
    """Answer *one* named verification request late, and let every other read reach the real server.

    ``which`` is the route the plan names, ``match`` is the query text the request must carry (so a
    delayed answer for row A cannot also answer row B, which is what the race is about), and ``landed`` is
    set *after* the response has been handed over — the script waits on that event rather than guessing how
    long a sleep was enough. ``gate``, when given, is awaited before the answer goes out: the script sets
    it once it has finished closing the dialog, switching the row or signing out, so "the answer arrived
    after the operator stopped looking" is a fact this run arranged rather than one it hoped the sleep was
    long enough for. ``seconds`` then only guarantees the request is genuinely still in flight while the
    interruption happens. ``once`` makes it a single-shot fault: the read that is meant to go stale stays
    stale while the operator's next read is answered by the real server, which is the only way a
    sign-out/re-login race measures the old request instead of the new one.
    """
    spent = {'done': False}

    async def action(route) -> None:
        path = RECORDS_PATH if which == 'records' else RECORD_PATH
        if path not in route.request.url or ('?' + match) not in route.request.url:
            return await route.continue_()
        if once and spent['done']:
            return await route.continue_()
        spent['done'] = True
        await asyncio.sleep(seconds)
        if gate is not None:
            await gate.wait()
        await route.fulfill(status=status, content_type='application/json', headers=NO_STORE,
                            body='' if payload is None else json.dumps(payload))
        landed.set()
    return action


def plan_runner(plan: dict):
    """The one route handler the whole run installs; the plan says, case by case, what it answers."""
    async def intercept(route) -> None:
        which = 'records' if RECORDS_PATH in route.request.url else 'record'
        action = plan.get(which)
        return await route.continue_() if action is None else await action(route)
    return intercept


def served_ui(url: str) -> tuple[str, dict[str, str]]:
    """Read this app's own ``ui.js``, and the security header it is actually served with.

    A negative-control run replaces that one response, and the replacement has to differ from the real
    file in the mutation and nothing else — so the page's own content-security-policy is carried over
    rather than guessed at, and a response served without it would silently change how much injected
    markup the browser is willing to run.
    """
    with urllib.request.urlopen(url + '/ui.js', timeout=30) as answer:
        text = answer.read().decode('utf-8')
        policy = answer.headers.get('content-security-policy')
    require(policy, 'the demo served ui.js with no content-security-policy header, so a replaced response '
                    'could not be made equivalent to the real one in any other respect')
    return text, {'content-security-policy': policy}


def mutation(name: str, source: str) -> tuple[str, str]:
    """Return ``ui.js`` carrying exactly one reviewed change, and the words for what was changed.

    The match count is the guard: a search string found twice means the mutation reached two places and
    the run would be reporting on a program nobody reviewed, and one found nowhere means the shipped file
    already changed shape and the control is testing nothing. Either way this refuses before a browser
    starts, and no report is written.
    """
    label, find, replace = NEGATIVE_CONTROLS[name]
    count = source.count(find)
    require(count == 1, 'negative control ' + name + ' must match ui.js exactly once; it matched '
                        + str(count) + ' time(s): ' + label)
    return source.replace(find, replace), label


def ui_replacer(body: str, headers: dict[str, str]):
    """Answer for ``ui.js`` alone, with the mutated text. Installed only for a negative-control run."""
    async def action(route) -> None:
        return await route.fulfill(status=200, content_type='text/javascript', headers=headers, body=body)
    return action


def document(execution_id: str, verification_id: str, **changes) -> dict:
    """A complete 15-key stored document, changed only by the case at hand.

    Shaped from ``verification_records.RECORD_DOCUMENT_KEYS``, with every stamp in the form
    `inventory.validation.utc_text` prints (whole seconds, microseconds, ``+00:00``): a reply missing a
    field, or carrying an instant in some other spelling, would be refused for the wrong reason, so each
    case below changes exactly one thing that is under test.
    """
    stored = {'verification_id': verification_id, 'execution_id': execution_id,
              'action_id': '11111111-1111-1111-1111-111111111111', 'binding_id': 'b' * 64,
              'origin': {'threshold': 90.0, 'comparison': 'lt'},
              'window': {'start': '2026-09-09T09:00:00.000000+00:00',
                         'end': '2026-09-09T09:05:00.000000+00:00'},
              'outcome': 'available', 'receipt': {'sample_count': 1, 'truncated': False},
              'samples': [{'metric_name': 'lo_cpu', 'value': 95.0}], 'verdict': 'not_cleared',
              'reason': 'comparison-failed', 'value': 95.0,
              'sampled_at': '2026-09-09T09:01:00.000000+00:00', 'recorded_by': 'demo-verifier',
              'recorded_at': '2026-09-09T09:10:00.000000+00:00'}
    stored.update(changes)
    return stored


def stored_document(want: dict, execution_id: str, verification_id: str) -> dict:
    """One real stored record, in the whole-document shape the record route answers with.

    The four fields the panel shows are the server's own (read out-of-band by :func:`expected`); the rest
    of the document is the fixed shape above, because the case under test is timing and not content.
    """
    item = want['records'][execution_id][verification_id]
    return document(execution_id, verification_id, verdict=item['verdict'], reason=item['reason'],
                    window=dict(item['window']), recorded_at=item['recorded_at'])


async def detail_fields(page) -> dict:
    """The labelled values of the open detail, read as rendered text from the DOM."""
    return await page.evaluate(
        """() => { const out = {}; const dl = document.getElementById('detail-fields');
                   for (let i = 0; i + 1 < dl.children.length; i += 2)
                       out[dl.children[i].textContent] = dl.children[i + 1].textContent;
                   return out; }""")


async def close_detail(page) -> None:
    # A closed native dialog is `display: none`, so this waits on the property rather than on a selector
    # Playwright would insist on seeing rendered.
    if await page.is_visible('#detail'):
        await page.get_by_role('button', name='Close', exact=True).click()
        await page.wait_for_function("() => !document.getElementById('detail').open", timeout=20000)


async def go_to(page, view: str) -> None:
    """Switch views, closing any open detail first: a modal dialog makes the nav bar unreachable."""
    await close_detail(page)
    await page.click('[data-view="' + view + '"]')
    await page.locator('#records tr').first.wait_for()


async def open_execution(page, wanted: str) -> None:
    """Open the detail dialog of the execution row whose id is *wanted*, or fail naming what was listed."""
    rows = page.get_by_role('button', name='Inspect record', exact=True)
    seen = []
    for index in range(await rows.count()):
        await close_detail(page)
        await rows.nth(index).click()
        await page.wait_for_selector('#detail[open]')
        identifier = (await detail_fields(page)).get('id', '')
        seen.append(identifier)
        if identifier == wanted:
            return
    raise ValueError('no execution row named ' + wanted + '; the list holds ' + repr(seen))


async def wait_state(page, code: str, selector: str = 'verification-state') -> None:
    """Wait for the panel to reach *code*, so no check below depends on a sleep being long enough."""
    await page.wait_for_function(
        """([id, code]) => document.getElementById(id).dataset.state === code""",
        arg=[selector, code], timeout=20000)


#: Test-only instrumentation, installed before the first navigation and reinstalled by every one. It waits
#: for `ui.js` to define `historyFetch`, records the Promise each real call returns and hands that same
#: Promise back. A page this script cannot instrument is refused by :func:`settle`, not read as an empty set.
COMPLETION_PROBE = """(() => {
  const install = () => {
    const pending = new Set();
    window.__historyPending = pending;
    const original = window.historyFetch;
    if (typeof original !== "function") { window.__historyWrapped = "absent"; return; }
    window.historyFetch = function () {
      const answer = original.apply(this, arguments);
      if (!answer || typeof answer.then !== "function") return answer;
      pending.add(answer);
      const finished = () => pending.delete(answer);
      answer.then(finished, finished);   // both arms: no stranded set, no unhandled `finally` copy
      window.__historyWrapped = "wrapped";
      return answer;                     // the identical Promise the caller always waited on
    };
  };
  if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", install); }
  else { install(); }
})();"""


async def settle(page) -> None:
    """Wait until no verification read the page made is unresolved, then give the page one turn.

    Not a duration and not a frame count: :data:`COMPLETION_PROBE` holds the Promises the page's own
    ``historyFetch`` really returned, so awaiting that set is what proves the fetch resolved; the frames
    after it only let the continuation awaiting it run and write. The set must exist, or an absence below
    would be unmeasured rather than asserted.
    """
    await asyncio.wait_for(page.evaluate("""async () => {
        const pending = window.__historyPending;
        if (!(pending instanceof Set) || window.__historyWrapped !== "wrapped")
            throw new Error('history completion instrumentation is missing (' +
                            (window.__historyWrapped || 'no init script ran') + ')');
        await Promise.all([...pending]);
    }"""), timeout=20)
    await page.evaluate("""() => new Promise(resolve => requestAnimationFrame(() =>
        requestAnimationFrame(() => setTimeout(resolve, 0))))""")


async def panel(page) -> dict:
    """What the history panel holds right now: id buttons, result nodes, both states, the control."""
    return await page.evaluate(
        """() => ({ids: [...document.querySelectorAll('#verification-ids button')].map(b => b.textContent),
                   nodes: [...document.getElementById('verification-result').children].map(n => n.tagName),
                   html: document.getElementById('verification-result').innerHTML,
                   text: document.getElementById('verification-result').innerText,
                   state: document.getElementById('verification-state').dataset.state,
                   record: document.getElementById('verification-record-state').dataset.state,
                   hidden: document.getElementById('verification').hidden,
                   loadDisabled: document.getElementById('verification-load').disabled})""")


async def fits(page) -> dict:
    """Both overflow questions: the page as a whole, and the dialog that can scroll on its own."""
    return await page.evaluate(
        """() => ({page: document.documentElement.scrollWidth <= window.innerWidth,
                   dialog: (() => { const d = document.getElementById('detail');
                                    return d.scrollWidth <= d.clientWidth; })()})""")


def sanitized(text: str, *tokens: str) -> str:
    """Strip this run's synthetic credentials out of any text the script may print or raise."""
    for token in tokens:
        text = text.replace(token, '[redacted]')
    return text


async def attempt(which: str, token: str, *steps: tuple) -> None:
    """Run each ``(label, action)`` of a sign-in; make the first failure fatal, named and inert.

    A Playwright action failure logs its own arguments, and `fill`'s is the operator's live credential —
    that is how selector1 and positive6 leaked one. The step is named instead, the token replaced, and the
    run stops there: nothing retried, nothing swallowed.
    """
    for step, action in steps:
        try:
            await action()
        except Exception as fault:
            raise ValueError(which + ' failed while ' + step + ': '
                             + sanitized(str(fault), token)) from None


def credential_steps(page, token: str) -> list:
    """The steps both sign-in forms share after the dialog is open — one fill site, one naming of it."""
    return [('supplying the credential', lambda: page.locator('#token').fill(token)),
            ('submitting the form', lambda: page.get_by_role('button', name='Sign in', exact=True).click()),
            ('waiting for the dialog to close',
             lambda: page.wait_for_function("() => !document.getElementById('login').open", timeout=20000)),
            ('waiting for the first record row', lambda: page.locator('#records tr').first.wait_for())]


async def sign_in(page, url: str, token: str) -> None:
    """Sign in from a fresh navigation, the dialog waited for *before* it is typed into: opening it is
    `ui.js`'s last act, so a fill begun earlier is a timeout about a boot that never finished.
    """
    await attempt('sign-in', token, ('opening the demo page', lambda: page.goto(url)),
                  ('waiting for the sign-in dialog',
                   lambda: page.wait_for_selector('#login[open]', timeout=20000)),
                  *credential_steps(page, token))


async def sign_in_again(page, token: str) -> None:
    """Sign in again *without* navigating, so a request the old sign-in left in flight stays in flight.

    :func:`sign_in` reloads the page, which would cancel the very request a stale-answer race is about.
    Same step naming, same redaction, same fatal-on-failure rule.
    """
    await attempt('repeated sign-in', token,
                  ('waiting for the sign-in dialog',
                   lambda: page.wait_for_selector('#login[open]', timeout=20000)),
                  *credential_steps(page, token))


async def signed_in_as(page) -> str:
    """Who the page says it is talking as right now — the header's own text, never a script literal."""
    return await page.evaluate("() => document.getElementById('identity').textContent")


async def simulated_signout(page) -> None:
    """Sign out through the header button's own entry point, for the races the real button cannot reach.

    It is a *real* sign-out in every sense that matters to the panel (`signout()` is what the button's
    handler calls), but it is not a click: the header sits behind the modal detail, so a case that needs
    the detail still open names it as simulated. The hand sign-out case below closes the detail first and
    clicks the actual button, and the two are reported under different check names.
    """
    await page.evaluate('() => signout()')
    await page.wait_for_selector('#login[open]', timeout=20000)


async def start_load(page, traffic: Traffic) -> None:
    """Click the control, and wait until the request it spent is actually on the wire."""
    traffic.reset()
    await page.click('#verification-load')
    require(await traffic.reach(1), 'clicking Load verification history spent no request at all')


async def click_load(page, traffic: Traffic, ran: dict, viewport: str) -> None:
    """One click, and the requests it spent — asserted as exactly one, and as a GET."""
    await start_load(page, traffic)
    verify(ran, viewport, 'one click on Load issues exactly one request', await traffic.settled() == 1)
    verify(ran, viewport, 'that request is a GET', traffic.methods() == {'GET'})


async def run_viewport(browser, name: str, size: dict, url: str, human: str, reader: str,
                       want: dict, ran: dict, traffic: Traffic, plan: dict, directory: Path,
                       ui: tuple[str, dict[str, str]] | None = None, prefix: str = '') -> None:
    """The whole run for one viewport, in roughly the order an operator would do it."""
    viewport = str(size['width']) + 'x' + str(size['height'])
    page = await browser.new_page(viewport=size)
    await page.add_init_script(COMPLETION_PROBE)   # before any navigation; every navigation reinstalls it
    faults: list[str] = []

    def noted(error: Exception) -> None:
        # Diagnostic text never includes the synthetic credentials, even if a browser exception does.
        text = sanitized(str(error), human, reader)
        faults.append(text)
        print('Browser script error: ' + text, flush=True)

    page.on('pageerror', noted)        # asserted at the end of this viewport, below
    # `requestfailed` stays informational by design: a dropped connection and a deliberately aborted read
    # are cases this run arranges, so their count proves nothing either way.
    page.on('requestfailed', lambda request: print('Browser request failed: ' + request.method + ' '
            + urllib.parse.urlsplit(request.url).path, flush=True))
    page.on('request', traffic.request)
    page.on('response', traffic.response)
    await page.route('**/v1/verification/**', plan_runner(plan))
    if ui is not None:
        await page.route('**/ui.js', ui_replacer(ui[0], ui[1]))
    traffic.reset()                  # a case counts from here; `journal` keeps the whole run's history

    with_history = [key for key, ids in want['ids'].items() if ids]
    require(len(with_history) == 1, 'the fixture must hold exactly one execution carrying history')
    execution = with_history[0]
    silent = next(key for key in want['ids'] if key != execution)
    shown = want['records'][execution]
    require(len(shown) == 2, 'the fixture holds two records for one execution')
    not_cleared = next(key for key, item in shown.items() if item['verdict'] == 'not_cleared')
    unread = next(key for key in shown if key != not_cleared)

    await sign_in(page, url, human)
    await go_to(page, 'executions')
    verify(ran, viewport, 'listing executions fetches no verification data', await traffic.none())

    await open_execution(page, execution)
    verify(ran, viewport, 'opening an execution detail fetches no verification data', await traffic.none())
    await page.wait_for_selector('#verification:visible')
    seen = await panel(page)
    verify(ran, viewport, 'a fresh detail starts not-loaded with nothing in it',
           seen['state'] == 'not-loaded' and not seen['ids'] and not seen['nodes'] and seen['html'] == ''
           and seen['record'] == '' and not seen['loadDisabled'])

    # A record that is not an execution gets no history affordance at all: the panel is about one run.
    await go_to(page, 'actions')
    await page.get_by_role('button', name='Inspect record', exact=True).first.click()
    await page.wait_for_selector('#detail[open]')
    verify(ran, viewport, 'a record that is not an execution offers no history and asks for none',
           not await page.is_visible('#verification') and await traffic.none())
    await go_to(page, 'executions')

    # --- an empty history, answered by the real server ---------------------------------------------------
    await open_execution(page, silent)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'empty')
    verify(ran, viewport, 'that one request named the execution being inspected',
           traffic.queries() == ['execution_id=' + silent])
    seen = await panel(page)
    verify(ran, viewport, 'a terminal execution with nothing recorded says so and lists nothing',
           seen['state'] == 'empty' and seen['ids'] == [] and seen['nodes'] == [])
    verify(ran, viewport, 'an empty history costs no record request and leaves the control usable',
           await traffic.settled() == 1 and not seen['loadDisabled'])

    # --- the real id list, then the real stored document -------------------------------------------------
    traffic.reset()
    await open_execution(page, execution)
    verify(ran, viewport, 'reopening a detail refetches nothing until the operator asks',
           await traffic.none())
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    seen = await panel(page)
    verify(ran, viewport, 'the ids listed are the ids the server returned, in the order it returned them',
           seen['ids'] == want['ids'][execution] and seen['ids'] == sorted(seen['ids']))
    verify(ran, viewport, 'the list says in words that id order is not time order',
           'not time order' in await page.inner_text('#verification-state'))
    verify(ran, viewport, 'listing ids fetches no record document', await traffic.settled() == 1)
    verify(ran, viewport, 'no result is shown before an id is selected', seen['nodes'] == [])

    traffic.reset()
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    verify(ran, viewport, 'one id selection issues exactly one record request for that id',
           len(traffic.history) == 1 and traffic.queries() == ['verification_id=' + not_cleared])
    seen = await panel(page)
    stored = shown[not_cleared]
    verify(ran, viewport, 'the result is labelled as a historical recorded result',
           'Historical recorded result' in seen['text'])
    verify(ran, viewport, 'verdict, reason, observation window and recorded time are the stored ones',
           all(needle in seen['text'] for needle in
               ('not_cleared', stored['reason'], stored['window']['start'], stored['window']['end'],
                stored['recorded_at'])))
    verify(ran, viewport, 'nothing the document carries beyond those four fields is rendered',
           not any(needle in seen['text'] for needle in
                   (unread, 'demo-verifier', 'binding', 'origin', 'receipt', 'sample', '95.0', '11111111')))
    verify(ran, viewport, 'the panel says it changed nothing about the run or the incident',
           'changes nothing' in seen['text'])
    verify(ran, viewport, 'a succeeded execution and a not_cleared record stay two separate statements',
           (await detail_fields(page)).get('status') == 'succeeded' and 'not_cleared' in seen['text'])
    detail_text = (await page.inner_text('#detail')).lower()
    verify(ran, viewport, 'reading history never speaks of an incident outcome',
           not any(word in detail_text for word in OUTCOME_WORDS))
    verify(ran, viewport, 'the only verdict word ever shown is the one that was recorded',
           'cleared' not in seen['text'].replace('not_cleared', ''))

    # --- the renderer, on its own, with a string no server is allowed to send it -------------------------
    # This case feeds `historyRenderRecord` directly, so it is a statement about the renderer and not a
    # claim that the platform would ever answer this way — the API's own rejection of such a reply is the
    # case set below. It is the assertion that would stay green if `textContent` became `innerHTML` while
    # every validator kept working, which is exactly why it does not go through a route.
    hostile = '<img src=q onerror="window.__historyPwned=1"><script>alert(1)</script>'
    rendered = await page.evaluate("""(hostile) => {
        historyRenderRecord({verdict: 'not_cleared', reason: hostile, start: hostile, end: hostile,
                             recordedAt: hostile});
        const box = document.getElementById('verification-result');
        return {text: box.innerText, html: box.innerHTML, pwned: window.__historyPwned === 1,
                img: box.querySelectorAll('img').length, script: box.querySelectorAll('script').length,
                dds: [...box.querySelectorAll('dd')].map(node => node.textContent)};
    }""", hostile)
    verify(ran, viewport, 'the renderer writes a hostile string as inert text, with no element and no event',
           rendered['img'] == 0 and rendered['script'] == 0 and rendered['pwned'] is False
           and hostile in rendered['text'] and '<img' not in rendered['html']
           and '&lt;img' in rendered['html'])
    verify(ran, viewport, 'each of the three free-text fields reaches the screen as exactly the text given',
           sum(1 for text in rendered['dds'] if hostile in text) == 3)
    traffic.reset()
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    restored = await panel(page)
    verify(ran, viewport, 'selecting an id again restores the panel to the stored record',
           hostile not in restored['text'] and stored['reason'] in restored['text']
           and restored['nodes'] == seen['nodes'] and len(traffic.history) == 1)

    bounds = await fits(page)
    verify(ran, viewport, 'no horizontal overflow with a record on screen (document)', bounds['page'])
    verify(ran, viewport, 'no horizontal overflow with a record on screen (detail dialog)', bounds['dialog'])
    await page.locator('#verification-result').scroll_into_view_if_needed()
    await page.screenshot(path=str(directory / (prefix + name + '-verification.png')), full_page=True)

    traffic.reset()
    await close_detail(page)
    verify(ran, viewport, 'closing the detail issues no request at all', await traffic.none())

    # --- every refusal is its own state, in its own words, on both routes -------------------------------
    for code, status, payload in ANSWERS:
        plan['records'] = responder(status, payload)
        await open_execution(page, execution)
        await click_load(page, traffic, ran, viewport)
        await wait_state(page, code)
        seen = await panel(page)
        words = await page.inner_text('#verification-state')
        verify(ran, viewport, 'a ' + (str(status) if status else 'dropped') + ' list read answers as '
               + code + ' with nothing listed',
               seen['state'] == code and seen['ids'] == [] and seen['nodes'] == [])
        verify(ran, viewport, 'the ' + code + ' list state quotes no backend body, class or path',
               not any(needle in words + seen['html'] for needle in BACKEND_TEXT))
        verify(ran, viewport, 'the ' + code + ' list state leaves the control usable for another read',
               not seen['loadDisabled'])
        plan['records'] = None                       # real list read; only the document route is
        plan['record'] = responder(status, payload)  # being made to answer badly
        await click_load(page, traffic, ran, viewport)
        await wait_state(page, 'loaded')
        traffic.reset()
        await page.get_by_role('button', name=not_cleared, exact=True).click()
        await wait_state(page, code, 'verification-record-state')
        seen = await panel(page)
        record_text = await page.inner_text('#verification-record-state')
        verify(ran, viewport, 'the same answer on the record route shows no result and no backend text',
               seen['nodes'] == [] and seen['html'] == ''
               and not any(needle in record_text + seen['html']
                           for needle in BACKEND_TEXT))
        traffic.reset()
        await close_detail(page)
    plan['records'] = plan['record'] = None

    # --- over-cap and malformed replies are refusals, never a shorter list ------------------------------
    over_cap = [f'{index:02x}' * 32 for index in range(65)]
    descending = sorted(want['ids'][execution], reverse=True)
    for label, payload in (('a string where a list of ids belongs', {'verification_ids': 'not-a-list'}),
                           ('an id that is not a digest', {'verification_ids': ['zz']}),
                           ('an uppercase digest', {'verification_ids': [not_cleared.upper()]}),
                           ('a second key beside the ids',
                            {'verification_ids': [not_cleared], 'verdict': 'cleared'}),
                           ('a list past the 64-record cap', {'verification_ids': over_cap}),
                           ('an array where an object belongs', [not_cleared]),
                           ('markup in place of an id', {'verification_ids': [MARKUP]}),
                           ('an id with a newline appended', {'verification_ids': [not_cleared + '\n']}),
                           ('an id whose last character is a newline',
                            {'verification_ids': [not_cleared[:63] + '\n']}),
                           ('an id with a space appended', {'verification_ids': [not_cleared + ' ']}),
                           ('a number in place of an id', {'verification_ids': [42]}),
                           ('the same id twice', {'verification_ids': [not_cleared, not_cleared]}),
                           ('ids in descending order, which the server never answers',
                            {'verification_ids': descending}),
                           ('an empty body answered as success', '')):
        plan['records'] = responder(200, payload)
        await open_execution(page, execution)
        await click_load(page, traffic, ran, viewport)
        await wait_state(page, 'malformed')
        seen = await panel(page)
        verify(ran, viewport, label + ' is refused rather than shown as a partial list',
               seen['state'] == 'malformed' and seen['ids'] == [] and seen['nodes'] == []
               and MARKUP not in await page.inner_text('#detail'))
        state_text = await page.inner_text('#verification-state')
        verify(ran, viewport, label + ' invents no verdict of its own',
               not any(word in state_text + seen['text']
                       for word in ('cleared', 'not_cleared', 'unknown')))
        await close_detail(page)
    plan['records'] = None

    # --- a record document that is not the one this panel asked for, or not one it can read -------------
    for label, payload, code in (
            ('a document about another execution', document(silent, not_cleared), 'mismatch'),
            ('a document whose id is not the one selected', document(execution, 'a' * 64), 'mismatch'),
            ('a verdict word this platform never files', document(execution, not_cleared,
                                                                  verdict='recovered'), 'malformed'),
            ('a reason carrying markup', document(execution, not_cleared, reason='x' + MARKUP),
             'malformed'),
            ('a reason that is the number 123, not a word', document(execution, not_cleared,
                                                                    reason=123), 'malformed'),
            ('a reason that is absent', document(execution, not_cleared, reason=None), 'malformed'),
            ('a reason with a trailing newline',
             document(execution, not_cleared, reason='comparison-failed\n'), 'malformed'),
            ('a window that is not an instant',
             document(execution, not_cleared, window={'start': 'yesterday', 'end': 'today'}),
             'malformed'),
            ('a window whose bounds are the wrong way round',
             document(execution, not_cleared, window={'start': '2026-09-09T09:05:00.000000+00:00',
                                                     'end': '2026-09-09T09:00:00.000000+00:00'}),
             'malformed'),
            ('a window on a date that never happened',
             document(execution, not_cleared,
                      window={'start': '2026-02-30T09:00:00.000000+00:00',
                              'end': '2026-02-30T09:05:00.000000+00:00'}), 'malformed'),
            ('a window carrying a third bound',
             document(execution, not_cleared, window={'start': '2026-09-09T09:00:00.000000+00:00',
                                                      'end': '2026-09-09T09:05:00.000000+00:00',
                                                      'zone': 'UTC'}), 'malformed'),
            ('a recorded time that is not an instant',
             document(execution, not_cleared, recorded_at='just now'), 'malformed'),
            ('a recorded time with a trailing newline',
             document(execution, not_cleared, recorded_at='2026-09-09T09:10:00.000000+00:00\n'),
             'malformed'),
            ('a recorded time one microsecond before its window ended',
             document(execution, not_cleared,
                      window={'start': '2026-09-09T09:00:00.000000+00:00',
                              'end': '2026-09-09T09:05:00.000002+00:00'},
                      recorded_at='2026-09-09T09:05:00.000001+00:00'), 'malformed'),
            ('a recorded time before its own window ended',
             document(execution, not_cleared, recorded_at='2026-09-09T08:59:00.000000+00:00'),
             'malformed'),
            ('an instant in a spelling utc_text never prints',
             document(execution, not_cleared, recorded_at='2026-09-09T09:10:00+00:00'), 'malformed')):
        plan['record'] = responder(200, payload)
        await open_execution(page, execution)
        await click_load(page, traffic, ran, viewport)
        await wait_state(page, 'loaded')
        traffic.reset()
        await page.get_by_role('button', name=not_cleared, exact=True).click()
        await wait_state(page, code, 'verification-record-state')
        seen = await panel(page)
        verify(ran, viewport, label + ' shows no result and cost exactly one request',
               seen['nodes'] == [] and seen['html'] == '' and len(traffic.history) == 1)
        verify(ran, viewport, label + ' never becomes markup or page text',
               MARKUP not in seen['html'] and MARKUP not in await page.inner_text('#detail')
               and 'recovered' not in seen['text'])
        await close_detail(page)
    plan['records'] = plan['record'] = None

    # --- a late answer after the detail was closed, and after a switch to another row -------------------
    late_list, hold = asyncio.Event(), asyncio.Event()
    plan['records'] = delayed_for('records', 'execution_id=' + execution, DELAY, late_list,
                                  payload={'verification_ids': want['ids'][execution]}, gate=hold)
    await open_execution(page, execution)
    await start_load(page, traffic)
    await wait_state(page, 'loading')
    verify(ran, viewport, 'a read in flight disables the control against a second click',
           (await panel(page))['loadDisabled'])
    await page.locator('#verification-load').dispatch_event('click')
    verify(ran, viewport, 'a synthetic click on the in-flight control spends no second request',
           await traffic.settled() == 1)
    await close_detail(page)
    hold.set()                                   # the answer is released only now, after the close
    await asyncio.wait_for(late_list.wait(), timeout=20)
    await settle(page)
    plan['records'] = None
    await open_execution(page, execution)
    seen = await panel(page)
    verify(ran, viewport, 'a late list for a closed detail never repopulates it',
           seen['state'] == 'not-loaded' and seen['ids'] == [] and seen['nodes'] == [])

    stale_list, hold = asyncio.Event(), asyncio.Event()
    plan['records'] = delayed_for('records', 'execution_id=' + silent, DELAY, stale_list,
                                  payload={'verification_ids': []}, gate=hold)
    await open_execution(page, silent)
    await start_load(page, traffic)
    await wait_state(page, 'loading')
    await open_execution(page, execution)                    # the row switch, mid-flight
    await start_load(page, traffic)
    await wait_state(page, 'loaded')
    hold.set()                             # the earlier read is answered only once the later one is done
    await asyncio.wait_for(stale_list.wait(), timeout=20)
    await settle(page)
    plan['records'] = None
    seen = await panel(page)
    verify(ran, viewport, 'an out-of-order answer for another row never replaces the row being read',
           seen['state'] == 'loaded' and seen['ids'] == want['ids'][execution])

    # --- the native Escape close, and the gap between close() and the event it queues -------------------
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    before_close = await page.evaluate('() => verification.generation')
    await page.keyboard.press('Escape')                      # the browser's own close, not this panel's
    await page.wait_for_function(
        "(before) => !document.getElementById('detail').open && verification.generation > before",
        arg=before_close, timeout=20000)
    seen = await panel(page)
    verify(ran, viewport, 'the native Escape close empties the panel the way the close button does',
           seen['state'] == 'not-loaded' and seen['ids'] == [] and seen['nodes'] == []
           and seen['record'] == '' and seen['hidden'])

    # `close()` clears the dialog's `open` property synchronously and only *queues* its event, so between
    # those two moments the generation counter still names the request in flight and the open-dialog test
    # is the only thing standing between a completion and a closed panel. This reads the gate from inside
    # that window — one page task, with nothing awaited in it, so the event cannot have run — and then
    # waits for the generation to move, which is what proves the reading was taken before it did.
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    gap = await page.evaluate("""() => { const dialog = document.getElementById('detail');
        const before = verification.generation; dialog.close();
        return {before: before, open: dialog.open, answered: historyAnswered(before)}; }""")
    await page.wait_for_function("(before) => verification.generation > before", arg=gap['before'],
                                 timeout=20000)
    verify(ran, viewport, 'a completion in the gap between close() and its event is refused by the '
                          'open-dialog test', gap['open'] is False and gap['answered'] is False)

    # --- a 401 that arrives late is not a 401 about the current sign-in --------------------------------
    # Signing out is the one side effect a response can have all by itself, so it goes through the same
    # gate the DOM writes do. A *current* 401 still signs the operator out — that case is below.
    late_401, hold = asyncio.Event(), asyncio.Event()
    plan['records'] = delayed_for('records', 'execution_id=' + execution, DELAY, late_401, status=401,
                                  payload={'error': 'authentication_required'}, gate=hold)
    await open_execution(page, execution)
    await start_load(page, traffic)
    await wait_state(page, 'loading')
    operator = await signed_in_as(page)
    await close_detail(page)
    hold.set()                                  # the 401 is released only after the detail is shut
    await asyncio.wait_for(late_401.wait(), timeout=20)
    await settle(page)
    plan['records'] = None
    verify(ran, viewport, 'a 401 that arrives after the detail was closed logs nobody out',
           operator != 'Disconnected' and not await page.is_visible('#login')
           and await signed_in_as(page) == operator)
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    verify(ran, viewport, 'and that dropped answer leaves the panel usable for the next read',
           (await panel(page))['ids'] == want['ids'][execution])

    stale_401, hold = asyncio.Event(), asyncio.Event()
    plan['records'] = delayed_for('records', 'execution_id=' + execution, DELAY, stale_401, status=401,
                                  payload={'error': 'authentication_required'}, gate=hold)
    await open_execution(page, execution)
    await start_load(page, traffic)
    await wait_state(page, 'loading')
    await simulated_signout(page)                            # the header button's own entry point
    plan['records'] = None             # only that one read is stale; every read after it is the live one
    await sign_in_again(page, human)   # no reload, so the stale read is still travelling
    await go_to(page, 'executions')
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    hold.set()                       # the old credential's 401 is released only against the new session
    await asyncio.wait_for(stale_401.wait(), timeout=20)
    await settle(page)
    verify(ran, viewport, 'a 401 from a request the previous sign-in made never ends the new one',
           not await page.is_visible('#login') and await signed_in_as(page) != 'Disconnected'
           and (await panel(page))['ids'] == want['ids'][execution])

    # --- a record read the operator supersedes by asking for the list again -----------------------------
    # The flag meaning "a record is on its way" belongs to the request this reload just discarded. Were it
    # kept, the panel would sit refusing every later click while looking entirely idle, because the answer
    # it was waiting for is now one it has thrown away.
    late_record, hold = asyncio.Event(), asyncio.Event()
    plan['record'] = delayed_for('record', 'verification_id=' + not_cleared, DELAY, late_record,
                                 payload=stored_document(want, execution, not_cleared), gate=hold)
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'loading', 'verification-record-state')
    await start_load(page, traffic)                          # the reload that supersedes it
    await wait_state(page, 'loaded')
    idle = await panel(page)
    verify(ran, viewport, 'reloading history mid-record clears that read\'s state and leaves the controls '
                          'usable', idle['record'] == '' and idle['nodes'] == [] and not idle['loadDisabled'])
    await page.get_by_role('button', name=unread, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    current = await panel(page)
    verify(ran, viewport, 'after a superseded record read the new selection is answered and displayed',
           shown[unread]['reason'] in current['text']
           and shown[not_cleared]['reason'] not in current['text'])
    hold.set()                     # the discarded record answer is released only now, over the new one
    await asyncio.wait_for(late_record.wait(), timeout=20)
    await settle(page)
    plan['record'] = None
    after = await panel(page)
    verify(ran, viewport, 'the superseded record answer never replaces the one now displayed',
           after['text'] == current['text'] and shown[not_cleared]['reason'] not in after['text'])

    # --- a record answer that lands after the operator stopped looking at that record -------------------
    for label, interrupt in (('after its detail was closed', lambda: close_detail(page)),
                             ('after another row was opened', lambda: open_execution(page, silent)),
                             ('after a simulated sign-out', lambda: simulated_signout(page))):
        late_record, hold = asyncio.Event(), asyncio.Event()
        plan['record'] = delayed_for('record', 'verification_id=' + not_cleared, DELAY, late_record,
                                     payload=stored_document(want, execution, not_cleared), gate=hold)
        await open_execution(page, execution)
        await click_load(page, traffic, ran, viewport)
        await wait_state(page, 'loaded')
        await page.get_by_role('button', name=not_cleared, exact=True).click()
        await wait_state(page, 'loading', 'verification-record-state')
        await interrupt()
        hold.set()                                # released only once the operator has moved on
        await asyncio.wait_for(late_record.wait(), timeout=20)
        await settle(page)
        plan['record'] = None
        seen = await panel(page)
        verify(ran, viewport, 'a record answer that lands ' + label + ' shows nothing at all',
               seen['nodes'] == [] and seen['html'] == ''
               and shown[not_cleared]['reason'] not in seen['text'])
    await sign_in_again(page, human)
    await go_to(page, 'executions')

    # --- a lost session clears the panel rather than reporting a state -----------------------------------
    plan['records'] = responder(401, {'error': 'authentication_required'})
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await page.wait_for_selector('#login[open]')
    seen = await panel(page)
    verify(ran, viewport, 'a 401 signs the operator out and clears the history panel',
           seen['ids'] == [] and seen['nodes'] == [] and seen['state'] == 'not-loaded')
    plan['records'] = None

    # --- signing out by hand clears a loaded list and a shown record -------------------------------------
    # This one is the real header button: the detail is closed first, so nothing about it is simulated.
    await sign_in(page, url, human)
    await go_to(page, 'executions')
    await open_execution(page, execution)
    await start_load(page, traffic)
    await wait_state(page, 'loaded')
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    await close_detail(page)
    await page.get_by_role('button', name='Sign out', exact=True).click()
    await page.wait_for_selector('#login[open]')
    seen = await panel(page)
    verify(ran, viewport, 'the header sign-out button itself clears every node and state the panel put up',
           seen['ids'] == [] and seen['nodes'] == [] and seen['state'] == 'not-loaded'
           and seen['record'] == '' and seen['hidden'])

    # --- the server, not the page, decides who may read -------------------------------------------------
    await sign_in(page, url, reader)
    await go_to(page, 'executions')
    await open_execution(page, execution)
    await click_load(page, traffic, ran, viewport)
    await wait_state(page, 'loaded')
    verify(ran, viewport, 'a reader credential reads the same history the server lets it read',
           (await panel(page))['ids'] == want['ids'][execution])
    # The reader's half does not stop at the list: what it may list it may also read, one document per
    # click on the same one request, and with the same nothing written and nothing concluded.
    traffic.reset()
    await page.get_by_role('button', name=not_cleared, exact=True).click()
    await wait_state(page, 'recorded', 'verification-record-state')
    read = await panel(page)
    verify(ran, viewport, 'a reader selecting an id issues exactly one GET for that id and no write',
           len(traffic.history) == 1 and traffic.queries() == ['verification_id=' + not_cleared]
           and traffic.methods() == {'GET'} and not traffic.wrote_anything())
    verify(ran, viewport, 'a reader is shown the stored verdict, reason, window and recorded time',
           all(needle in read['text'] for needle in
               (stored['verdict'], stored['reason'], stored['window']['start'], stored['window']['end'],
                stored['recorded_at'])) and 'Historical recorded result' in read['text']
           and not any(needle in read['text'] for needle in (unread, 'demo-verifier', 'binding')))
    reader_detail_text = (await page.inner_text('#detail')).lower()
    verify(ran, viewport, 'a reader reading history never speaks of an incident outcome',
           not any(word in reader_detail_text for word in OUTCOME_WORDS))
    bounds = await fits(page)
    verify(ran, viewport, 'no horizontal overflow at the end of the run', bounds['page'])
    await page.locator('#verification-result').scroll_into_view_if_needed()
    await page.screenshot(path=str(directory / (prefix + name + '-verification-reader.png')), full_page=True)
    verify(ran, viewport, 'no uncaught page script error ran in this viewport', not faults)
    await page.close()


async def main(fixture: Path, url: str | None, browser_path: str, control: str | None = None) -> int:
    credentials = json.loads((fixture / 'credentials.json').read_text())
    human = next(item['token'] for item in credentials if item['role'] == 'human')
    reader = next(item['token'] for item in credentials if item['role'] == 'reader')
    address = url or json.loads((fixture / 'server.json').read_text())['url']
    require(address.startswith('http://127.0.0.1:'), 'the demo server must be loopback-only: ' + address)
    want = expected(address, human)
    # A negative run differs in one response and in where it writes: the same assertions, one mutated
    # `ui.js`, and the pass report path is never opened. The mutated text is prepared before the browser
    # starts, so a control that does not match exactly once costs a refusal and not a partial run.
    ui = None
    label = ''
    if control is not None:
        body, headers = served_ui(address)
        body, label = mutation(control, body)
        ui = (body, headers)
    prefix = '' if control is None else 'negative-' + control + '-'
    ran: dict[str, list[str]] = {}
    traffic, plan = Traffic(), {'records': None, 'record': None}
    try:
        async with async_playwright() as driver:
            browser = await driver.chromium.launch(executable_path=browser_path, headless=True)
            try:
                for name, size in VIEWPORTS:
                    try:
                        await run_viewport(browser, name, size, address, human, reader, want, ran, traffic,
                                           plan, fixture, ui=ui, prefix=prefix)
                    except Exception:
                        # A failed run keeps a bounded picture and startup facts, never a DOM/credential dump.
                        for context in browser.contexts:
                            for page in context.pages:
                                await page.screenshot(path=str(fixture / (prefix + name + '-failed.png')))
                                print('Browser failure state: ' + json.dumps(await page.evaluate('''() => ({
                                    ready: document.readyState, loginOpen: document.getElementById('login')?.open,
                                    icons: typeof lucide, startup: typeof signout})''')), flush=True)
                        raise
                verify(ran, 'all', 'the history UI issued no write of any kind', not traffic.wrote_anything())
                verify(ran, 'all', 'every verification response was answered no-store',
                       bool(traffic.no_store) and all(traffic.no_store))
            finally:
                await browser.close()
    except RefusedRun as refused:
        expected_refusal = {
            'outcome': 'reading history never speaks of an incident outcome',
            'html': 'the renderer writes a hostile string as inert text, with no element and no event',
            'stale': 'an out-of-order answer for another row never replaces the row being read',
        }
        if ui is None or not str(refused).startswith(
                'verification history check failed: ' + expected_refusal[control] + ' at '):
            raise
        write_report(fixture / NEGATIVE_REPORT, {
            'status': 'negative-control-refused',
            'scope': ('a deliberately mutated copy of this app\'s own ui.js served to the browser in place '
                      'of the shipped one; this file is evidence that one named check refuses one named '
                      'defect, and it is not a pass for the UI, for this fixture or for anything else'),
            'control': control,
            'mutation': label,
            'refused_at': str(refused),
            'checks_completed_before_refusal': sorted({item for names in ran.values() for item in names}),
            'limitations': [
                'the mutation is a test artefact: no product file was changed or written to produce it, '
                'and the shipped ui.js was only ever read',
                'a caught mutation shows this check can fail; it says nothing about the unmutated UI, '
                'which the ordinary run reports separately and under a different file name',
                'the run stopped at the first refusal, so the checks sequenced after it never ran'],
            'fixture': str(fixture),
            'url': address,
            'screenshots': sorted(path.name for path in fixture.glob(prefix + '*.png'))})
        print('Negative control ' + control + ' refused, as it had to be: ' + str(refused))
        return 0
    if ui is not None:
        raise ValueError('negative control ' + control + ' did not stop this run: every assertion passed '
                         'with "' + label + '" installed, so the check that should have refused it is not '
                         'doing its job and no report of any kind was written')
    write_report(fixture / PASS_REPORT, {
        'status': 'pass',
        'scope': ('the bundled operator demo served on loopback from a fixture created fresh for this '
                  'run, driven in one headless Chrome at two viewports against its own saved '
                  'verification records; the positive path is the real HTTP API, while negative '
                  'payloads and delayed completions are injected at the network boundary; no deployed '
                  'platform, no live store, no verifier process and no notification delivery'),
        'limitations': [
            'an injected reply proves how the UI answers a status or a shape; it is not evidence that '
            'the platform produces that shape, which the API tests own',
            'the in-flight cases are delayed by this script, so they pin the stale-result rule and say '
            'nothing about how long any real read takes; each answer is released by a route gate the '
            'script sets after its own interruption and awaited as the page\'s own fetch promise settling '
            'plus one page task turn, so no assertion depends on how long a sleep happened to be and no '
            'absence is measured against a response the page is still waiting for',
            'that fetch promise is recorded by a test-only wrapper installed in the browser only '
            '(COMPLETION_PROBE): it returns the same promise the page made, and no product file was read, '
            'changed or served differently to install it',
            'uncaught page script errors are collected (sanitized) and refused per viewport; failed '
            'requests are logged but never faults, because a dropped connection is arranged here',
            'the hostile-string renderer case feeds historyRenderRecord directly and asserts what the '
            'renderer writes; it is not a claim that the server would answer such a document, and the '
            'rejection of that reply is asserted separately',
            'two sign-outs are distinct: the races use the header button\'s own sign-out entry point '
            'while the detail is open (a real click cannot reach it behind a modal), and the hand sign-out '
            'case closes the detail and clicks the actual button',
            'layout is asserted as the absence of overflow plus screenshots; styling is not asserted',
            'the fixture mounts a verification policy so history can be seeded, and ships no producer '
            "credential, so a read is proven for a human and a reader only; role authority stays the "
            "server's",
            'the shared scratch/operator-demo fixture is refused here, so nothing in this run reuses an '
            'earlier server, credential file or database'],
        'fixture': str(fixture),
        'url': address,
        'executions': want['executions'],
        'verification_ids': want['ids'],
        'records_read': {key: sorted(value) for key, value in want['records'].items()},
        'viewports': [str(size['width']) + 'x' + str(size['height']) for _name, size in VIEWPORTS],
        'verification_requests': [{'method': method, 'url': target} for method, target in traffic.journal],
        'verification_request_count': len(traffic.journal),
        'api_request_methods': sorted({method for method, _ in traffic.api}),
        'verification_responses_were_no_store': traffic.no_store,
        'checks': list(dict.fromkeys(check for names in ran.values() for check in names)),
        'checks_by_viewport': ran,
        'screenshots': [prefix + name + suffix for name, _size in VIEWPORTS
                        for suffix in ('-verification.png', '-verification-reader.png')]})
    print('Verification history browser checks passed')
    return 0


def cli(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--fixture', required=True, type=Path,
                        help='A fresh operator-demo fixture directory, the same path given to '
                             'serve_operator_demo.py')
    parser.add_argument('--url', help='Serve address; defaults to <fixture>/server.json')
    parser.add_argument('--browser', default=CHROME, help='Chrome/Chromium executable to launch')
    parser.add_argument('--negative-control', choices=tuple(sorted(NEGATIVE_CONTROLS)),
                        help='TEST ONLY: serve this app\'s ui.js back with exactly one reviewed change '
                             'installed (outcome: the record note claims the incident recovered; stale: '
                             'the staleness gate always admits a response; html: one record field is '
                             'written through innerHTML) and require that this run refuse to pass. Writes '
                             + NEGATIVE_REPORT + ' and never ' + PASS_REPORT + '; a mutation that does not '
                             'match exactly once is refused before the browser starts.')
    return parser.parse_args(argv)


def guard(fixture: Path) -> None:
    """Refuse to run against anything but an explicitly named fixture with a server answering on it."""
    require(fixture.resolve() != serve_operator_demo.DEFAULT_FIXTURE.resolve(),
            'refusing the shared scratch/operator-demo fixture: this proof needs its own directory, '
            'created by `python scripts/serve_operator_demo.py --background --fixture <directory> 0`')
    require((fixture / 'credentials.json').is_file() and (fixture / 'server.json').is_file(),
            'no demo server found in ' + str(fixture) + '; start one with `python scripts/'
            'serve_operator_demo.py --background --fixture ' + str(fixture) + ' 0` and let it write '
            'server.json')


if __name__ == '__main__':
    arguments = cli()
    guard(arguments.fixture)
    raise SystemExit(asyncio.run(main(arguments.fixture, arguments.url, arguments.browser,
                                      arguments.negative_control)))

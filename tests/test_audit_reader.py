"""The paged audit reader: the bounded read-only audit page, proved at the `Store.audit_page` seam.

`tests/test_audit_reader_api.py` is the transport half of this card (the real authenticated
`GET /v1/audit`, its strict query parser, and the legacy `/v1/records/audit` bytes that must not move).
This file is the seam the contract names — `Store.audit_page(*, limit, category, snapshot, before)` —
against a real SQLite file, with no stand-in between the assertion and the rows. Fixture style follows
`tests/test_refusal_audit.py` (a real `Store` on a temp path, the lifecycle an action policy needs, and
`Store.audit` inside a transaction to plant history the lifecycle cannot produce).

What is pinned, and why each one is a way the feature could be quietly wrong:

* **The documented answer shape.** Exactly `rows`/`snapshot`/`next_before`/`scanned`; a normal row is the
  six stored audit columns and nothing else (no display expansion, no new secret-bearing field).
* **Validation that protects a direct caller too.** `limit` is a canonical decimal 1..100, `category` is
  `all`/`action-transitions`, `snapshot`/`before` are a signed-63-bit pair with `before <= snapshot`, and
  a `bool` is not an integer. Every refusal here opens no connection at all (measured, not assumed).
* **Cursor arithmetic.** Newest first, `sequence <= snapshot`, `sequence < before` for continuations, no
  before bound on the first page, the cursor never advances over a row it did not deliver, and
  `scanned` never exceeds 500 positions — including positions that matched nothing.
* **A traversal that cannot lie.** Every committed sequence at or below the captured snapshot appears
  exactly once across pages, an append above the snapshot can neither duplicate nor displace a row, and
  the end is said once (`next_before` null) after at most one trailing empty page.
* **The byte budget, honestly.** One row too large to fetch, or too large once canonical escaping is
  applied, is replaced by an explicit `{sequence, omitted: "row_exceeds_page_budget"}` placeholder that
  consumes its position and counts toward the limit; a row that merely found the page already full is
  deferred and comes back complete on the next page. A placeholder never carries the row's text, and a
  deferred row is never silently converted into one.
* **A read that is really a read.** With the file switched to its rollback journal and a real writer
  holding `BEGIN IMMEDIATE`, the page still answers (so it is not asking for the write lock), reports the
  maximum *committed* sequence, refuses to see the uncommitted row, and leaves every row, the schema and
  the journal mode exactly as it found them.

What this file deliberately does **not** claim: it does not measure total disk IO or latency against a
hostile history (the contract bounds allocation, not IO), it does not promise continuity across a
restored or replaced database, and it does not test a connection pool it cannot see — "keep no connection
between pages" is proved by what the next request can read, which is the only observable form of it.
"""
import datetime as dt
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
import uuid
from collections.abc import Mapping
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from local_observe.inventory import index
from local_observe.inventory.validation import canonical, read_document, timestamp, utc_text
from local_observe.platform import detections, refusals
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
PRODUCER = Actor('test-detector', 'producer')
AGENT = Actor('agent-1', 'proposer')
HUMAN = Actor('operator', 'human')
RUNNER = Actor('runner-1', 'executor')
# Planted inside history the page must refuse to render: if it comes back, the row leaked.
SENTINEL = 'never-rendered-text'

# The bounds as the contract states them. They are literals here on purpose: a test that read them back
# out of the unit under test could not notice the unit moving one of them.
DOCUMENTED_FIELDS = ('rows', 'snapshot', 'next_before', 'scanned')
AUDIT_COLUMNS = ('sequence', 'at', 'actor', 'operation', 'subject', 'detail')
PLACEHOLDER_FIELDS = ('sequence', 'omitted')
PLACEHOLDER = 'row_exceeds_page_budget'
LIMIT_MAX = 100
SCAN_BUDGET = 500
PAGE_BUDGET_BYTES = 65536
STORED_TEXT_BUDGET = 49152
INT64_MAX = 2 ** 63 - 1
TRANSITIONS = frozenset(('action.proposed', 'action.approved', 'action.denied', 'action.expired',
                         'execution.claimed', 'execution.succeeded', 'execution.failed',
                         'execution.unknown'))
# Words a prefix or substring match would let through, planted so the filter is proved to be a set of
# whole operation words rather than a pattern. `action.approval_intent` is an accepted intent and not a
# completed transition; `action.refused` is an attempt that never happened.
NEAR_MISS_OPERATIONS = ('action.approval_intent', 'action.approved-but-not', 'execution.claiming',
                        'execution.succeeded_eventually', 'action.deniedx' * 40)


class SteppingClock:
    """A monotonic source that moves one second per read, so every refusal is allowed its row.

    The refusal bucket  holds 64 tokens and refills at one per second, and this card's
    headline case needs *more* than a burst of refusals to prove that a flood cannot crowd accepted
    transitions out of the audit history. The injected clock is `Store`'s own seam for that: nothing
    here sleeps, and it is never the `now=` a lifecycle method accepts (a rate limit an attacker sets is
    not a limit). Thread-safe because one test appends from a second thread on purpose.
    """

    def __init__(self) -> None:
        self.value = 0.0
        self._moves = threading.Lock()

    def __call__(self) -> float:
        with self._moves:
            current = self.value
            self.value += 1.0
            return current


class AuditFixture:
    """A real platform database, its real lifecycle, and history planted the only legal way.

    Mixed into `TestCase` subclasses; it defines no tests. `build()` opens the store; the rest are
    producers and readers. Clients of the finished page read it exclusively through `page()`/`traverse()`
    (the documented seam) or through `Store.records` for the legacy comparison — never through a private
    helper of the unit under test, because there is none to reach.
    """

    # ------------------------------------------------------------------ construction

    def build(self) -> Store:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = SteppingClock()
        self.store = Store(self.root / 'state.db', refusal_clock=self.clock)
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.declared['resources'][0]['attributes']['remediation_enabled'] = True
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        # A canonical UUID that names no action: every refusal below is a real one about it.
        self.absent = str(uuid.uuid4())
        return self.store

    # ------------------------------------------------------- real accepted transitions

    def event(self, status='firing', minute=0):
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        return detections.event(PRODUCER.identity, self.host, 'availability', 'availability', status,
                                window, {'sample_id': f'audit-page-{minute}'}, query_type='gatus-result')

    def open_incident(self, minute=0, status='firing'):
        return self.store.intake(self.event(status, minute), PRODUCER, now=NOW + dt.timedelta(minutes=minute))

    def propose(self, retry_key, incident, minute=0, actor=AGENT):
        document = {'retry_key': retry_key, 'incident_id': incident['incident_id'], 'action': 'inspect',
                    'version': '1', 'targets': [self.host], 'parameters': {},
                    'evidence': [incident['event_id']],
                    'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        moment = NOW + dt.timedelta(minutes=minute)
        return self.store.propose_action(document, actor, self.policy, now=moment)['action_id']

    def accepted_transitions(self) -> dict[str, list[dict]]:
        """Walk every one of the eight documented transitions, and return the stored rows by operation.

        An approval *intent* and a refused attempt are written too (the intent is planted, the refusals
        come from `refuse`) so the filter has near-misses to exclude rather than an empty neighbourhood.
        """
        seen: dict[str, list[dict]] = {}

        first = self.open_incident(minute=0)
        winning = self.propose('page-succeeded', first)
        self.store.decide(winning, 'approved', HUMAN, now=NOW)
        claim = self.store.claim_action(winning, RUNNER, self.policy, now=NOW)
        self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'],
                                     now=NOW)
        denied = self.propose('page-denied', first, minute=1)
        self.store.decide(denied, 'denied', HUMAN, now=NOW + dt.timedelta(minutes=1))
        stale = self.propose('page-expired', first, minute=2)
        # Two hours later the approval window is gone: the decision is recorded as an expiry, which is a
        # completed transition and is the only way `action.expired` arrives from a real caller.
        self.store.decide(stale, 'approved', HUMAN, now=NOW + dt.timedelta(hours=2))
        self.open_incident(minute=3, status='resolved')
        second = self.open_incident(minute=4)
        lost = self.propose('page-unknown', second, minute=4)
        self.store.decide(lost, 'approved', HUMAN, now=NOW + dt.timedelta(minutes=4))
        lost_claim = self.store.claim_action(lost, RUNNER, self.policy, now=NOW + dt.timedelta(minutes=4))
        self.store.recover_executions(now=NOW + dt.timedelta(minutes=5))
        self.store.execution_outcome(lost_claim['execution_id'], 'failed', RUNNER,
                                     lost_claim['runner_token'], now=NOW + dt.timedelta(minutes=6))
        for row in self.raw_audit():
            if row['operation'] in TRANSITIONS:
                seen.setdefault(row['operation'], []).append(row)
        self.assertEqual(set(seen), set(TRANSITIONS), 'the fixture did not reach every transition')
        return seen

    def refuse(self, count: int) -> int:
        """Write `count` real `action.refused` rows, one per genuine lifecycle refusal."""
        for _ in range(count):
            with self.assertRaises(StateError):
                self.store.decide(self.absent, 'approved', HUMAN, now=NOW)
        return count

    # ------------------------------------------------------------------ planted history

    def filler(self, count, *, operation='filler.page', size=0, actor='operator'):
        """Return `count` row tuples: small by default, padded when a test wants byte pressure."""
        detail = {'pad': 'p' * size} if size else None
        return [(NOW, actor, operation, 'unbound', detail) for _ in range(count)]

    def plant(self, rows) -> list[int]:
        """Append audit rows through `Store.audit` inside one transaction; return their sequences.

        The pathological history a reader must survive is not something the lifecycle produces — a 60 KB
        stored blob, a run of backslashes that fits in the file and cannot fit once escaped, an operation
        word nobody declared, an actor holding control characters. This is the route the brief allows for
        planting it, and every assertion still reads the result back through the page itself.
        """
        first = self.max_sequence() + 1
        with self.store.transaction() as connection:
            for at, actor, operation, subject, detail in rows:
                Store.audit(connection, at, actor, operation, subject, detail)
        return list(range(first, first + len(rows)))

    # ------------------------------------------------------------------------ raw reads

    def readonly(self) -> sqlite3.Connection:
        """A read-only view of the same file, so a fixture's own reading cannot perturb what it checks.

        Every caller wraps this in `closing`, including the one that runs on the second thread, so no
        connection outlives the assertion that opened it.
        """
        return sqlite3.connect(self.store.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=10)

    def raw_audit(self) -> list[dict]:
        columns = AUDIT_COLUMNS
        with closing(self.readonly()) as db:
            return [dict(zip(columns, row)) for row in
                    db.execute('SELECT sequence, at, actor, operation, subject, detail FROM audit '
                               'ORDER BY sequence')]

    def max_sequence(self) -> int:
        with closing(self.readonly()) as db:
            return db.execute('SELECT COALESCE(MAX(sequence), 0) FROM audit').fetchone()[0]

    def stored_lengths(self, sequence: int) -> dict[str, int]:
        """The SQL-side byte lengths of one row's text columns — the same measure the page's metadata
        read is documented to take, so a fixture can prove which budget its planted row is testing."""
        with closing(self.readonly()) as db:
            row = db.execute('SELECT length(at), length(actor), length(operation), length(subject),'
                             ' length(detail) FROM audit WHERE sequence=?', (sequence,)).fetchone()
        return dict(zip(('at', 'actor', 'operation', 'subject', 'detail'), row))

    def rendered_bytes(self, row: Mapping) -> int:
        """How many bytes this stored row would occupy if the page returned it whole."""
        return len(canonical({name: row[name] for name in AUDIT_COLUMNS}).encode())

    def fingerprint(self) -> str:
        """Every row of every table plus the schema text — the state a read must not disturb.

        `rootpage` is excluded: it says where a page lives, not what it says, and it moves under an
        ordinary checkpoint. The audit table's append-only triggers are part of the schema text, so a
        page that tried to add or drop one would be caught here too.
        """
        with closing(self.readonly()) as db:
            schema = db.execute("SELECT type, name, sql FROM sqlite_master "
                                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name").fetchall()
            tables = [row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' "
                'ORDER BY name')]
            body = {table: db.execute(f'SELECT * FROM "{table}" ORDER BY rowid').fetchall()
                    for table in tables}
            integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
            journal = db.execute('PRAGMA journal_mode').fetchone()[0]
        payload = repr((schema, sorted(body.items()), integrity, journal))
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_rollback_journal(self) -> str:
        """Switch the file to its rollback journal, so a write transaction and a read are provably different."""
        with closing(sqlite3.connect(self.store.path, timeout=10)) as db:
            return db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]

    # ------------------------------------------------------------------ the page itself

    def refused(self, **kwargs) -> str:
        """Call the seam expecting a validation refusal; return the sentence it raised."""
        with self.assertRaises(ValueError) as caught:
            self.store.audit_page(**kwargs)
        self.assertIsInstance(caught.exception, ValueError)
        return str(caught.exception)

    def page(self, **kwargs) -> dict:
        """One call of the documented seam, normalised to the four documented fields.

        The contract states the answer is exactly `{rows, snapshot, next_before, scanned}`; whether the
        seam hands that back as a mapping or as a small record is its own choice, so both are read here
        and the assertions below stay about the documented fields. A missing field fails here with a
        named complaint instead of becoming an `AttributeError` three lines into an assertion.
        """
        result = self.store.audit_page(**kwargs)
        if isinstance(result, Mapping):
            fields = dict(result)
        else:
            missing = [name for name in DOCUMENTED_FIELDS if not hasattr(result, name)]
            self.assertEqual(missing, [], f'audit_page returned no {missing}')
            fields = {name: getattr(result, name) for name in DOCUMENTED_FIELDS}
        self.assertEqual(set(fields), set(DOCUMENTED_FIELDS), 'audit_page changed the documented fields')
        snapshot, cursor, scanned, rows = (fields['snapshot'], fields['next_before'],
                                           fields['scanned'], fields['rows'])
        self.assertIsInstance(snapshot, int)
        self.assertNotIsInstance(snapshot, bool)
        self.assertIsInstance(scanned, int)
        self.assertNotIsInstance(scanned, bool)
        self.assertIsInstance(rows, list)
        if cursor is not None:
            self.assertIsInstance(cursor, int)
            self.assertNotIsInstance(cursor, bool)
        for row in rows:
            self.assertIsInstance(row, Mapping, f'a row came back as {type(row).__name__}, which no '
                                                f'JSON surface could encode')
        return fields

    def check_page(self, fields: dict, *, limit: int, before: int | None = None) -> list[int]:
        """Assert the per-page invariants every page must satisfy, and return its sequences."""
        sequences = []
        for row in fields['rows']:
            keys = tuple(sorted(row))
            if keys == tuple(sorted(PLACEHOLDER_FIELDS)):
                self.assertEqual(row['omitted'], PLACEHOLDER, 'an unknown omission word was invented')
                self.assertIsInstance(row['sequence'], int)
                self.assertNotIsInstance(row['sequence'], bool)
            else:
                self.assertEqual(keys, tuple(sorted(AUDIT_COLUMNS)),
                                 f'a normal row carries {keys}, not the six stored columns')
            sequences.append(row['sequence'])
        self.assertLessEqual(len(sequences), limit, 'a page returned more rows than it was asked for')
        self.assertLessEqual(fields['scanned'], SCAN_BUDGET, 'a page scanned past its budget')
        self.assertEqual(sequences, sorted(sequences, reverse=True), 'a page is not newest-first')
        self.assertEqual(len(set(sequences)), len(sequences), 'one page repeated a position')
        if sequences:
            self.assertLessEqual(max(sequences), fields['snapshot'], 'a page returned a row above its snapshot')
        if before is not None:
            self.assertTrue(all(sequence < before for sequence in sequences),
                            'a continuation returned a row it had already delivered')
        cursor = fields['next_before']
        if cursor is not None:
            upper = before if before is not None else fields['snapshot'] + 1
            self.assertGreaterEqual(cursor, 0)
            self.assertLess(cursor, upper, 'the cursor did not advance: this page would repeat forever')
            if sequences:
                self.assertLessEqual(cursor, min(sequences),
                                     'the cursor passed a row this page had already delivered')
        return sequences

    def traverse(self, *, limit: int = LIMIT_MAX, category: str = 'all', max_pages: int = 400,
                 between=None) -> list[dict]:
        """Page a snapshot to the end through the seam, and return every page in order.

        `between(pages)` runs between requests — that is where an append belongs if a test wants one.
        The loop itself asserts the two rules a client depends on: the snapshot never moves, and each
        continuation is built from the cursor it was just handed and nothing else.
        """
        pages: list[dict] = []
        kwargs: dict = {'limit': limit, 'category': category}
        before: int | None = None
        while True:
            fields = self.page(**kwargs)
            if before is None:
                self.assertNotIn('snapshot', kwargs)
                self.assertNotIn('before', kwargs)
            self.check_page(fields, limit=limit, before=before)
            if pages:
                self.assertEqual(fields['snapshot'], pages[0]['snapshot'],
                                 'the snapshot moved in the middle of one traversal')
            pages.append(fields)
            if between is not None:
                between(pages)
            cursor = fields['next_before']
            self.assertLess(len(pages), max_pages, f'the cursor never ended after {max_pages} pages')
            if cursor is None:
                return pages
            kwargs = {'limit': limit, 'category': category, 'snapshot': fields['snapshot'],
                      'before': cursor}
            before = cursor

    def traverse_rows(self, **kwargs) -> list[dict]:
        """Every row one full traversal delivers, newest first, placeholders included."""
        return [row for page in self.traverse(**kwargs) for row in page['rows']]

    def assert_complete(self, pages: list[dict], expected: list[int]) -> list[dict]:
        """Assert the pages delivered exactly `expected`, once each, newest first; return the rows."""
        rows = [row for page in pages for row in page['rows']]
        sequences = [row['sequence'] for row in rows]
        self.assertEqual(len(sequences), len(set(sequences)), 'a sequence arrived on two pages')
        self.assertEqual(sequences, sorted(sequences, reverse=True), 'the traversal is not newest-first')
        self.assertEqual(sequences, sorted(expected, reverse=True),
                         'the traversal duplicated or lost a committed position')
        return rows


class AuditPageTraversalTests(unittest.TestCase, AuditFixture):
    """The card's headline, at the seam: a flood of refusals may not bury the transitions.

    `GET /v1/records/audit` reads a capped newest-first window, so 130 refusal rows push every accepted
    transition out of view without deleting anything — that crowding is the reason this page exists, and
    the same fixture proves both halves: the legacy window really does go blind here, and the new page
    still returns every transition, complete, in one traversal.
    """

    REFUSALS = 130

    def setUp(self):
        self.build()
        self.transitions = self.accepted_transitions()
        # Near-miss operation words sit between the transitions and the flood, so the filter is exercised
        # against a word that starts with a transition and against one that merely contains it.
        self.near_misses = self.plant([(NOW, 'operator', operation, 'unbound', None)
                                       for operation in NEAR_MISS_OPERATIONS])
        self.refuse(self.REFUSALS)
        self.raw = self.raw_audit()

    def test_accepted_transitions_survive_a_refusal_flood_of_more_than_sixty_four_rows(self):
        rows_by_sequence = {row['sequence']: row for row in self.raw}
        refusals_written = [row for row in self.raw if row['operation'] == refusals.OPERATION]
        self.assertEqual(len(refusals_written), self.REFUSALS)
        self.assertGreater(self.REFUSALS, refusals.CAPACITY,
                           'the fixture stayed inside one burst, so it tested the wrong thing')
        self.assertEqual(self.store.refusal_audit_status()['written'], self.REFUSALS)
        pages = self.traverse(limit=LIMIT_MAX)
        delivered = {row['sequence']: row for row in self.assert_complete(pages, list(rows_by_sequence))}
        self.assertEqual(len(delivered), len(self.raw), 'a position arrived twice or not at all')
        for operation, group in self.transitions.items():
            for expected in group:
                with self.subTest(operation=operation, sequence=expected['sequence']):
                    row = delivered[expected['sequence']]
                    self.assertEqual(tuple(sorted(row)), tuple(sorted(AUDIT_COLUMNS)),
                                     'an accepted transition came back as a placeholder')
                    for name in AUDIT_COLUMNS:
                        self.assertEqual(row[name], expected[name])

    def test_the_legacy_hundred_row_window_is_exactly_where_those_rows_stop_being_visible(self):
        """The gap this card closes, measured rather than asserted in prose.

        If the refusal count ever drops below the legacy window this test stops being meaningful, so the
        precondition is stated as an assertion: the newest 100 rows the old reader can reach are all
        refusals, and every accepted transition sits below the oldest row it can show at all.
        """
        legacy = self.store.records('audit', LIMIT_MAX)
        self.assertEqual(len(legacy), LIMIT_MAX)
        self.assertEqual({row['operation'] for row in legacy}, {refusals.OPERATION})
        oldest_visible = min(row['sequence'] for row in legacy)
        for row in self.raw:
            if row['operation'] in TRANSITIONS:
                self.assertLess(row['sequence'], oldest_visible,
                                f"{row['operation']} is still visible to the legacy window")
        recovered = {row['sequence'] for page in self.traverse(limit=LIMIT_MAX) for row in page['rows']}
        hidden = {row['sequence'] for row in self.raw if row['operation'] in TRANSITIONS}
        self.assertTrue(hidden <= recovered, 'a transition the legacy window lost never came back')

    def test_the_action_transitions_filter_is_the_eight_documented_words_exactly(self):
        expected = [row['sequence'] for row in self.raw if row['operation'] in TRANSITIONS]
        pages = self.traverse(limit=1, category='action-transitions')
        rows = self.assert_complete(pages, expected)
        self.assertEqual({row['operation'] for row in rows}, set(TRANSITIONS))
        self.assertNotIn(refusals.OPERATION, {row['operation'] for row in rows})
        for sequence in self.near_misses:
            self.assertNotIn(sequence, [row['sequence'] for row in rows],
                             'a near-miss operation word was counted as a completed transition')
        self.assertGreaterEqual(max(page['scanned'] for page in pages), len(rows),
                               'the scan count is smaller than the rows it delivered')

    def test_a_long_operation_word_is_delivered_whole_even_though_the_metadata_read_clips_it(self):
        """The 64-byte clip is a bound on the page's own scratch space, never on what an operator reads.

        A planted operation word far longer than 64 bytes, which begins with a real transition word: if
        the page decided the category from a clipped prefix, or delivered a clipped value, this row is
        where it would show.
        """
        longest = max(NEAR_MISS_OPERATIONS, key=len)
        self.assertGreater(len(longest), 64)
        planted = next(row for row in self.raw if row['operation'] == longest)
        delivered = next(row for row in self.traverse_rows(limit=LIMIT_MAX)
                         if row['sequence'] == planted['sequence'])
        self.assertEqual(delivered['operation'], longest, 'the delivered column was clipped')
        filtered = [row['sequence'] for row in self.traverse_rows(limit=LIMIT_MAX,
                                                                  category='action-transitions')]
        self.assertNotIn(planted['sequence'], filtered,
                         'a clipped prefix match put a non-transition in the filtered page')

    def test_limit_bounds_rows_and_the_scan_budget_bounds_positions(self):
        for limit in (1, 3, LIMIT_MAX):
            with self.subTest(limit=limit):
                pages = self.traverse(limit=limit)
                self.assertTrue(all(len(page['rows']) <= limit for page in pages))
                self.assertTrue(all(0 <= page['scanned'] <= SCAN_BUDGET for page in pages))
                self.assertTrue(all(page['scanned'] >= len(page['rows']) for page in pages),
                                'a page delivered rows it never scanned')
        self.assertEqual(max(len(page['rows']) for page in self.traverse(limit=7)), 7,
                         'no page ever filled the limit, so the limit was not exercised')

    def test_an_append_between_pages_can_neither_duplicate_nor_displace_the_traversal(self):
        """The snapshot is a position, not a lock: the writer keeps writing while a reader pages.

        The append runs on a second thread against the same file, so it can land before or after the
        first page's read transaction — and the assertions hold either way, which is the whole promise:
        rows above the captured snapshot never enter this traversal, and rows at or below it never leave.
        """
        started = threading.Event()
        appended: list[int] = []

        def append_while_reading():
            started.wait(timeout=30)
            appended.extend(self.plant(self.filler(8, operation='filler.concurrent')))

        thread = threading.Thread(target=append_while_reading)
        thread.start()
        self.addCleanup(thread.join)
        first = self.page(limit=20)
        started.set()
        thread.join(timeout=30)
        snapshot = first['snapshot']
        expected = [row['sequence'] for row in self.raw if row['sequence'] <= snapshot]
        pages = [first]
        cursor = first['next_before']
        while cursor is not None:
            fields = self.page(limit=20, snapshot=snapshot, before=cursor)
            self.check_page(fields, limit=20, before=cursor)
            self.assertEqual(fields['snapshot'], snapshot, 'a continuation re-captured the snapshot')
            pages.append(fields)
            cursor = fields['next_before']
            self.assertLess(len(pages), 400, 'the cursor never ended')
        self.assert_complete(pages, expected)
        self.assertTrue(appended, 'the concurrent writer wrote nothing, so this proved less than it claims')
        fresh = self.page(limit=LIMIT_MAX)
        self.assertGreater(fresh['snapshot'], snapshot, 'a new traversal did not see the committed append')


class AuditPageScanBudgetTests(unittest.TestCase, AuditFixture):
    """A page is bounded in positions, not in matches — and it says which bound it hit.

    `scanned` is the operator's answer to "is there more?" when the page itself is empty: an empty page
    with a cursor means the filter spent its budget, and an empty page without one means the history is
    exhausted. Collapse those two and a client stops paging at the first quiet stretch.
    """

    def setUp(self):
        self.build()

    def test_a_filtered_scan_that_matched_nothing_spends_its_whole_budget_first(self):
        self.plant(self.filler(620))
        pages = self.traverse(category='action-transitions', limit=LIMIT_MAX)
        self.assertEqual([page['rows'] for page in pages], [[] for _ in pages],
                         'a transition appeared in a history that holds none')
        self.assertEqual(len(pages), 2, 'a 620-row history took an unexpected number of filtered pages')
        self.assertEqual(pages[0]['scanned'], SCAN_BUDGET, 'the first page did not use the scan budget')
        self.assertIsNotNone(pages[0]['next_before'], 'an exhausted scan claimed the end')
        self.assertLess(pages[0]['next_before'], SCAN_BUDGET + 100,
                        'the cursor did not land near the positions it consumed')
        self.assertIsNone(pages[1]['next_before'], 'the end was not said when the history ran out')
        self.assertTrue(120 <= pages[1]['scanned'] <= 121,
                        'the last page reported a scan that was not the rest of the file')

    def test_a_history_with_more_refusals_than_the_budget_never_loses_the_older_transitions(self):
        self.transitions = self.accepted_transitions()
        self.plant(self.filler(700))
        expected = [row['sequence'] for row in self.raw_audit() if row['operation'] in TRANSITIONS]
        pages = self.traverse(category='action-transitions', limit=LIMIT_MAX)
        self.assert_complete(pages, expected)
        self.assertGreater(len(pages), 1, 'a 700-row scan range needed no continuation at all')
        self.assertTrue(any(page['rows'] == [] and page['next_before'] is not None for page in pages),
                        'no page in this traversal was an empty-but-continue page')

    def test_a_page_bounded_to_nothing_scans_nothing(self):
        self.plant(self.filler(3))
        for snapshot, before in ((0, 0), (1, 1), (3, 1), (INT64_MAX, 0)):
            with self.subTest(snapshot=snapshot, before=before):
                fields = self.page(snapshot=snapshot, before=before)
                self.assertEqual(fields['rows'], [])
                self.assertEqual(fields['scanned'], 0)
                self.assertIsNone(fields['next_before'])
                self.assertEqual(fields['snapshot'], snapshot)

    def test_changing_the_category_midway_is_a_new_traversal_and_not_a_repair(self):
        """The cursor is a position, not authority: it is legal to reuse it under another filter.

        The contract says a client must preserve `snapshot` and `category`, and that changing them is a
        new traversal — which is a statement about clients, not a demand that the server remember them.
        So a stale pair is answered as what it literally asks for, consistently, and never "fixed".
        """
        self.accepted_transitions()
        self.plant(self.filler(40))
        first = self.page(limit=3, category='all')
        mixed = self.page(limit=3, category='action-transitions', snapshot=first['snapshot'],
                          before=first['next_before'])
        self.check_page(mixed, limit=3, before=first['next_before'])
        self.assertTrue(all(row['operation'] in TRANSITIONS for row in mixed['rows']))
        self.assertEqual(mixed['snapshot'], first['snapshot'])

    def test_one_hundred_rows_is_a_page_however_long_the_rows_are(self):
        sequences = self.plant(self.filler(250, size=20))
        pages = self.traverse(limit=LIMIT_MAX)
        self.assert_complete(pages, sequences)
        self.assertTrue(all(len(page['rows']) <= LIMIT_MAX for page in pages))


class AuditPageByteBudgetTests(unittest.TestCase, AuditFixture):
    """The page may not grow without bound, and it may not solve that by losing a row.

    Three distinct outcomes, and the difference between them is the whole test:

    * **too large to fetch** — one row whose stored text is past the fetch budget is replaced by
      `{sequence, omitted: "row_exceeds_page_budget"}`, which consumes that position and counts toward
      the limit, so the traversal still says where it has been;
    * **too large once escaped** — a row that fits the fetch bound in the file can overflow the page
      after canonical escaping, and gets the same explicit placeholder rather than a cut-down row;
    * **merely late** — a row that would have fit on a page of its own, but found the budget already
      spent, is *deferred*: it comes back whole on the next page and is never turned into a placeholder.

    Every case plants the row and then reads it back through the page, and each test first asserts the
    precondition with SQL `length()` and the measured canonical width — otherwise a fixture that quietly
    stopped being pathological would pass by proving nothing.
    """

    def setUp(self):
        self.build()

    def page_text(self, pages: list[dict]) -> str:
        return canonical([[dict(row) for row in page['rows']] for page in pages])

    def test_a_row_too_large_to_fetch_is_an_explicit_placeholder_and_not_a_gap(self):
        low = self.plant(self.filler(1))[0]
        blob = self.plant([(NOW, 'operator', 'filler.blob', 'unbound',
                            {'blob': SENTINEL + ('x' * 60000)})])[0]
        high = self.plant(self.filler(1))[0]
        self.assertGreater(self.stored_lengths(blob)['detail'], STORED_TEXT_BUDGET,
                           'the planted row is no longer past the fetch budget')
        pages = self.traverse(limit=LIMIT_MAX)
        rows = {row['sequence']: row for row in self.assert_complete(pages, [low, blob, high])}
        self.assertEqual(rows[blob], {'sequence': blob, 'omitted': PLACEHOLDER})
        for sequence in (low, high):
            self.assertEqual(tuple(sorted(rows[sequence])), tuple(sorted(AUDIT_COLUMNS)),
                             'a row that fits was displaced by its oversized neighbour')
        text = self.page_text(pages)
        self.assertNotIn(SENTINEL, text, 'the page rendered the content it was meant to refuse')
        self.assertNotIn('x' * 4096, text, 'the page streamed an unbounded historical blob')

    def test_a_placeholder_consumes_its_position_and_counts_toward_the_limit(self):
        blob = self.plant([(NOW, 'operator', 'filler.blob', 'unbound', {'blob': 'y' * 60000})])[0]
        only = self.page(limit=1)
        self.assertEqual(only['rows'], [{'sequence': blob, 'omitted': PLACEHOLDER}])
        self.assertEqual(only['scanned'], 1, 'a placeholder was not booked as a scanned position')
        self.assertIsNone(only['next_before'])

        newer = self.plant(self.filler(1))[0]
        # The oversized row is now the older of the two, so one limit-1 page sits above it and the cursor
        # it hands back has to lead to the placeholder rather than past it.
        first = self.page(limit=1)
        self.assertEqual([row['sequence'] for row in first['rows']], [newer])
        self.assertIsNotNone(first['next_before'], 'the page above the placeholder never got a cursor')
        rest = self.page(limit=1, snapshot=first['snapshot'], before=first['next_before'])
        self.assertEqual(rest['rows'], [{'sequence': blob, 'omitted': PLACEHOLDER}])
        self.assertIsNone(rest['next_before'])

    def test_escaping_can_make_a_fetchable_row_unrenderable(self):
        """Stored bytes and response bytes are different measurements, and only one of them bounds a page.

        Each backslash in the stored column costs two characters once the row is itself encoded as a JSON
        string, so a 40 KB stored value needs an 80 KB response: inside the fetch budget, outside the page
        budget. The preconditions are asserted from SQL and from the measured canonical width, so this
        cannot drift into silently re-testing the oversized case above.
        """
        escaped = self.plant([(NOW, 'operator', 'filler.escape', 'unbound', {'blob': '\\' * 20000})])[0]
        stored = self.stored_lengths(escaped)
        self.assertLessEqual(stored['detail'], STORED_TEXT_BUDGET,
                             'the fixture planted an oversized row, not an escaping case')
        row = next(item for item in self.raw_audit() if item['sequence'] == escaped)
        self.assertGreater(self.rendered_bytes(row), PAGE_BUDGET_BYTES,
                           'the fixture planted a row that fits once escaped, so nothing was proved')
        page = self.page(limit=LIMIT_MAX)
        self.assertEqual(page['rows'], [{'sequence': escaped, 'omitted': PLACEHOLDER}])
        self.assertEqual(page['scanned'], 1)
        self.assertIsNone(page['next_before'])

    def test_the_budget_covers_every_text_column_not_only_the_detail(self):
        """`at`, `actor`, `operation` and `subject` are stored columns too, and history has seen all four.

        The metadata read is documented to bound the byte length of *all* text fields, so an oversized
        actor must be refused the same way an oversized detail is — a reader that only measured `detail`
        would load a 60 KB identity into Python on the way to saying it could not render it.
        """
        wide = self.plant([(NOW, 'q' * 60000, 'filler.actor', 'unbound', None)])[0]
        self.assertGreater(self.stored_lengths(wide)['actor'], STORED_TEXT_BUDGET)
        page = self.page(limit=LIMIT_MAX)
        self.assertEqual(page['rows'], [{'sequence': wide, 'omitted': PLACEHOLDER}])
        self.assertNotIn('q' * 1024, canonical([dict(r) for r in page['rows']]))

    def test_unicode_and_control_characters_survive_as_one_complete_escaped_row(self):
        """What must happen when the row is hostile but *small*: every byte of it, escaped and lossless.

        Escaping is the mechanism, not the failure: the response carries ASCII escapes, and decoding them
        must return exactly the stored text — including the characters a terminal would act on. A reader
        that dropped this row to be safe would be deleting ordinary awkward history.
        """
        actor = 'uni\u00f1code \u2713 \U0001F980 host\x01\x07\x1b\x7f'
        subject = 'tab\there\nnewline\rDEL\x7f\u2028\u2029"quote\\slash'
        note = {'note': 'a"b\\c\nd\u00e9\U0001F600\x0b'}
        sequence = self.plant([(NOW, actor, 'filler.unicode', subject, note)])[0]
        page = self.page(limit=LIMIT_MAX)
        raw = canonical(page).encode()
        self.assertLessEqual(len(raw), PAGE_BUDGET_BYTES)
        self.assertTrue(all(byte < 0x80 for byte in raw), 'a non-ASCII byte reached a canonical response')
        delivered = page['rows'][0]
        stored = next(item for item in self.raw_audit() if item['sequence'] == sequence)
        self.assertEqual({name: delivered[name] for name in AUDIT_COLUMNS},
                         {name: stored[name] for name in AUDIT_COLUMNS},
                         'the delivered row is not the stored row')
        self.assertEqual(delivered['actor'], actor)
        self.assertEqual(delivered['subject'], subject)
        self.assertEqual(json.loads(delivered['detail']), note)

    def test_a_row_that_only_found_the_page_full_is_deferred_and_never_replaced(self):
        """The deferral rule, with the arithmetic shown.

        120 rows of roughly 830 canonical bytes each cannot all fit inside 64 KiB, so the byte budget —
        not the limit — has to stop the first page. Every one of those rows fits on a page of its own, so
        none of them may arrive as a placeholder, and the pages have to butt up against each other with no
        position stepped over.
        """
        sequences = self.plant(self.filler(120, size=700))
        widths = {row['sequence']: self.rendered_bytes(row) for row in self.raw_audit()}
        self.assertTrue(all(500 < width < PAGE_BUDGET_BYTES for width in widths.values()),
                        'each planted row must fit alone and overflow in numbers')
        self.assertGreater(sum(widths.values()), PAGE_BUDGET_BYTES,
                           'the planted history fits one page, so the byte budget was never reached')
        pages = self.traverse(limit=LIMIT_MAX)
        first = pages[0]
        self.assertLess(len(first['rows']), LIMIT_MAX,
                        'the byte budget did not cut the page, so this test proved nothing')
        self.assertGreaterEqual(len(first['rows']), 20, 'the page cut itself far too early')
        text = self.page_text(pages)
        self.assertNotIn(PLACEHOLDER, text, 'a row that merely arrived late was replaced by a placeholder')
        rows = self.assert_complete(pages, sequences)
        self.assertEqual({tuple(sorted(row)) for row in rows}, {tuple(sorted(AUDIT_COLUMNS))})
        for page in pages:
            self.assertLessEqual(len(canonical(page).encode()), PAGE_BUDGET_BYTES,
                                 'a page exceeded the whole-response budget')
        for earlier, later in zip(pages, pages[1:]):
            self.assertEqual(later['rows'][0]['sequence'], earlier['rows'][-1]['sequence'] - 1,
                             'the next page did not resume on the deferred row')


class AuditPageReadTests(unittest.TestCase, AuditFixture):
    """The read is a read: real SQLite, real lock, real bytes, and nothing written.

    The contract asks for a dedicated read-only connection inside a *deferred* read transaction and no
    `BEGIN IMMEDIATE`. This proves it the only way SQLite can: put the file in its rollback journal, take
    the write lock with a real `BEGIN IMMEDIATE` from a second connection, and show that the page still
    answers while another writer on the same file is refused outright. A page that asked for the write
    lock would fail exactly where this one succeeds, and the failure would be SQLite's, not an
    assertion about a call nobody made.
    """

    def setUp(self):
        self.build()
        self.sequences = self.plant(self.filler(9))
        self.assertEqual(self.to_rollback_journal(), 'delete')

    def test_a_page_answers_while_a_writer_holds_the_write_lock_that_would_refuse_another_writer(self):
        before = self.fingerprint()
        writer = sqlite3.connect(self.store.path, timeout=10)
        self.addCleanup(writer.close)
        writer.execute('BEGIN IMMEDIATE')
        with closing(sqlite3.connect(self.store.path, timeout=0.05)) as blocked:
            with self.assertRaises(sqlite3.OperationalError) as caught:
                blocked.execute('BEGIN IMMEDIATE')
        self.assertIn('locked', str(caught.exception), 'the control writer was not refused, so no lock '
                                                      'was held and the page proved nothing')
        fields = self.page(limit=LIMIT_MAX)
        self.assertEqual([row['sequence'] for row in fields['rows']],
                         sorted(self.sequences, reverse=True))
        self.assertEqual(fields['snapshot'], max(self.sequences))
        self.assertEqual(self.fingerprint(), before, 'a page read changed the database it read')

    def test_deep_continuation_seeks_past_newer_history(self):
        with self.store.transaction() as connection:
            connection.executemany(
                'INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                [('now', 'fixture', 'action.proposed', 'subject', '{}')] * 20000)
        real_connect = sqlite3.connect
        callbacks = []

        def measured_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connection.set_progress_handler(lambda: callbacks.append(1) or 0, 100)
            return connection

        with patch('sqlite3.connect', side_effect=measured_connect):
            page = self.store.audit_page(snapshot=20009, before=10)
        self.assertEqual([row['sequence'] for row in page['rows']], list(range(9, 0, -1)))
        self.assertEqual(page['scanned'], 9)
        self.assertLess(len(callbacks) * 100, 5000,
                        'the cursor scanned newer history instead of seeking directly to its upper key')

    def test_each_request_reads_afresh_so_a_committed_append_is_visible_to_the_next_traversal(self):
        """No connection is kept between pages, and the pinned snapshot is what a continuation reads.

        Three facts in one walk: the cursor a limited page hands back leads to the row it stopped at
        instead of stepping over it; a continuation reports the snapshot it was *given*, not a fresh
        capture; and a brand-new first page does see what was committed in between. A reader holding one
        transaction open across pages would fail the last of those three, and a reader that re-captured
        its snapshot would fail the second.
        """
        self.assertEqual(self.sequences, [1, 2, 3, 4, 5, 6, 7, 8, 9])
        first = self.page(limit=5)
        self.assertEqual([row['sequence'] for row in first['rows']], [9, 8, 7, 6, 5])
        self.assertEqual(first['next_before'], 5, 'the cursor stepped over row 4 or promised row 5 again')
        appended = self.plant(self.filler(1))
        self.assertEqual(appended, [10])
        rest = self.page(limit=LIMIT_MAX, snapshot=first['snapshot'], before=first['next_before'])
        self.assertEqual([row['sequence'] for row in rest['rows']], [4, 3, 2, 1])
        self.assertEqual(rest['snapshot'], 9, 'a continuation re-captured the snapshot under the client')
        self.assertIsNone(rest['next_before'], 'the end was withheld after a scan that read the file out')
        fresh = self.page(limit=LIMIT_MAX)
        self.assertEqual(fresh['snapshot'], 10, 'a new traversal kept a stale snapshot')
        self.assertEqual([row['sequence'] for row in fresh['rows']], list(range(10, 0, -1)))
        with closing(self.readonly()) as db:
            self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'delete',
                             'a page opened the file for writing and put it back to WAL')

    def test_a_page_leaves_every_row_and_the_schema_exactly_as_it_found_them(self):
        expected = self.fingerprint()
        self.plant(self.filler(3, size=300))
        pinned = self.fingerprint()
        for limit in (1, 4, LIMIT_MAX):
            self.traverse(limit=limit)
        self.traverse(limit=LIMIT_MAX, category='action-transitions')
        self.assertEqual(self.fingerprint(), pinned, 'a page read moved rows, the schema or the journal')
        self.assertNotEqual(expected, pinned)
        with closing(self.readonly()) as db:
            self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(db.execute('SELECT count(*) FROM audit').fetchone()[0], 12)


# The shapes a caller may hand the seam that are not answers. Every entry is refused, and every entry is
# refused *without* a connection: `limit=0` must not become "the query returned nothing".
NONCANONICAL_LIMITS = (0, -1, -100, LIMIT_MAX + 1, 200, 10 ** 12, INT64_MAX, INT64_MAX + 1,
                       '0', '007', '+5', '1_0', ' 5', '5 ', '5\n', '5.0', '١٠',
                       'five', '', ' ', f'5 {SENTINEL}', SENTINEL, b'5', 1.0, 0.5, 99.0, [],
                       {}, (), uuid.uuid4(), object())
NONCANONICAL_POSITIONS = (-1, -INT64_MAX, INT64_MAX + 1, 2 ** 64, '01', '+1', '1_0', ' 1',
                          f'1 {SENTINEL}', SENTINEL, b'1', 1.0, None, [], {}, uuid.uuid4())
UNKNOWN_CATEGORIES = ('', ' ', 'ALL', 'All', ' all', 'all ', 'all%', 'action_transitions',
                      'action-transitions ', 'actiontransition', 'events', 'audit', 'refusals',
                      refusals.OPERATION, 'action.refused', 'transitions', 'default', SENTINEL,
                      b'all', 0, True, False, [], {}, ('all',))


class AuditPageShapeTests(unittest.TestCase, AuditFixture):
    """What one page answers, and what the two documented cursors do to it.

    The empty database is the case that tells a `0` from a `None`: the contract says the captured snapshot
    is *zero* there, not absent, and a client that cannot tell "nothing has ever happened" from "I lost
    the snapshot" is a client that cannot page.
    """

    def setUp(self):
        self.build()

    def test_an_empty_database_reports_zero_as_its_snapshot_and_stops(self):
        fields = self.page()
        self.assertEqual(fields['rows'], [])
        self.assertEqual(fields['snapshot'], 0)
        self.assertIsNone(fields['next_before'])
        self.assertEqual(fields['scanned'], 0, 'an empty scan reported positions it did not take')
        self.assertEqual(canonical(fields)[:1], '{')

    def test_a_bounded_continuation_on_an_empty_database_is_empty_and_ended(self):
        for snapshot, before in ((0, 0), (INT64_MAX, 0)):
            with self.subTest(snapshot=snapshot, before=before):
                fields = self.page(snapshot=snapshot, before=before)
                self.assertEqual(fields['rows'], [])
                self.assertEqual(fields['snapshot'], snapshot)
                self.assertIsNone(fields['next_before'])

    def test_the_first_page_has_no_before_bound_and_starts_at_the_newest_row(self):
        sequences = self.plant(self.filler(3))
        self.plant(self.filler(1, operation='filler.newer'))
        newest = self.max_sequence()
        fields = self.page(limit=LIMIT_MAX)
        self.check_page(fields, limit=LIMIT_MAX)
        self.assertEqual(fields['snapshot'], newest)
        self.assertEqual([row['sequence'] for row in fields['rows']], sorted(sequences + [newest],
                                                                            reverse=True))

    def test_the_documented_defaults_are_limit_one_hundred_and_category_all(self):
        sequences = self.plant(self.filler(5))
        implicit = self.page()
        explicit = self.page(limit=LIMIT_MAX, category='all')
        self.assertEqual(implicit, explicit, 'the default page is not the page the contract names')
        self.assertEqual(implicit, self.page(limit=None, category=None))
        self.assertEqual(implicit, self.page(limit='100', category='all'))
        self.assertEqual(self.page(snapshot='5', before='3'), self.page(snapshot=5, before=3))
        self.assertEqual([row['sequence'] for row in implicit['rows']], sorted(sequences, reverse=True))

    def test_a_continuation_reads_below_its_cursor_and_never_above_its_snapshot(self):
        sequences = self.plant(self.filler(6))
        self.assertEqual(sequences, [1, 2, 3, 4, 5, 6])
        newest = self.page(limit=2)
        self.assertEqual([row['sequence'] for row in newest['rows']], [6, 5])
        # Exactly one cursor satisfies both rules at once: it may not re-deliver 5, and it may not step
        # past 4. A page that answered 4 here ("strictly below the last row I showed you") would lose a
        # committed row, and a page that answered 6 would loop forever.
        self.assertEqual(newest['next_before'], 5)
        below = self.page(limit=2, snapshot=newest['snapshot'], before=newest['next_before'])
        self.check_page(below, limit=2, before=newest['next_before'])
        self.assertEqual([row['sequence'] for row in below['rows']], [4, 3])
        # A snapshot below the newest row is a narrower view of the same history, not a fresh traversal.
        capped = self.page(snapshot=3, before=3, limit=LIMIT_MAX)
        self.assertEqual(capped['snapshot'], 3)
        self.assertEqual([row['sequence'] for row in capped['rows']], [2, 1])
        cursor = capped['next_before']
        self.assertTrue(cursor is None or 0 <= cursor <= 1, 'the cursor ran past the oldest row it read')
        if cursor is not None:
            last = self.page(snapshot=3, before=cursor)
            self.assertEqual(last['rows'], [])
            self.assertIsNone(last['next_before'])

    def test_a_page_full_of_rows_leaves_a_cursor_and_the_final_page_says_the_end_once(self):
        sequences = self.plant(self.filler(4))
        pages = self.traverse(limit=2)
        self.assert_complete(pages, sequences)
        self.assertTrue(pages[-1]['rows'] or pages[-1]['next_before'] is None)
        self.assertIsNone(pages[-1]['next_before'], 'the last page did not say the end')
        for page in pages[:-1]:
            self.assertIsNotNone(page['next_before'], 'an interior page claimed the end early')
        cursors = [page['next_before'] for page in pages[:-1]]
        self.assertEqual(cursors, sorted(cursors, reverse=True), 'the cursor moved backwards')
        self.assertEqual(len(cursors), len(set(cursors)), 'the cursor stood still on two pages')


class AuditPageValidationTests(unittest.TestCase, AuditFixture):
    """The seam validates its own callers.

    The route is not the only way in: `Store.audit_page` is public, and a caller that reaches it with a
    `True`, a `'007'`, or a `before` above its snapshot must be refused by this unit rather than by a
    handler that happens to have parsed the same words first. Every refusal here also has to cost no I/O:
    a validation that runs after the connection is opened is a validation that can be probed.
    """

    def setUp(self):
        self.build()
        self.plant(self.filler(3))

    def test_limit_is_a_canonical_decimal_integer_between_one_and_one_hundred(self):
        for value in (1, 2, 7, 99, LIMIT_MAX):
            with self.subTest(limit=value):
                self.check_page(self.page(limit=value), limit=value)
        for value in NONCANONICAL_LIMITS:
            with self.subTest(limit=repr(value)):
                sentence = self.refused(limit=value)
                self.assertNotIn(SENTINEL, sentence, 'the refusal echoed the value it refused')
                self.assertLessEqual(len(sentence), 200)

    def test_a_boolean_is_not_an_integer_for_any_argument(self):
        """`True == 1` is Python, and a limit that accepts it silently means "one row".

        The contract names this case, so it is named here too, in all three positions and as a pair:
        a page that read `True` as `1` would answer correctly by accident and wrongly the first time a
        caller passed a flag it had parsed from a form.
        """
        for kwargs in ({'limit': True}, {'limit': False}, {'snapshot': True, 'before': True},
                       {'snapshot': False, 'before': False}, {'snapshot': 3, 'before': True},
                       {'snapshot': True, 'before': 1}):
            with self.subTest(kwargs=kwargs):
                self.refused(**kwargs)

    def test_category_is_all_or_action_transitions_and_nothing_else(self):
        for value in ('all', 'action-transitions'):
            with self.subTest(category=value):
                self.check_page(self.page(category=value), limit=LIMIT_MAX)
        for value in UNKNOWN_CATEGORIES:
            with self.subTest(category=repr(value)):
                sentence = self.refused(category=value)
                self.assertNotIn(SENTINEL, sentence, 'the refusal echoed the value it refused')
                self.assertLessEqual(len(sentence), 200)

    def test_snapshot_and_before_arrive_together_or_not_at_all(self):
        for kwargs in ({'before': 2}, {'before': 0}, {'snapshot': 2}, {'snapshot': 0}):
            with self.subTest(kwargs=kwargs):
                self.refused(**kwargs)
        self.check_page(self.page(snapshot=3, before=3), limit=LIMIT_MAX, before=3)
        self.check_page(self.page(snapshot=0, before=0), limit=LIMIT_MAX, before=0)

    def test_before_may_not_exceed_the_snapshot_it_belongs_to(self):
        """`before` is a position inside one snapshot, not a second independent bound.

        A pair that contradicts itself (`before` above `snapshot`) describes a range the traversal never
        captured; reading it anyway would mean serving rows from a history the caller never pinned, so it
        is a refusal. `before == snapshot` is the legal edge of the same rule and returns nothing new.
        """
        for snapshot, before in ((2, 3), (0, 1), (3, 4), (1, 2)):
            with self.subTest(snapshot=snapshot, before=before):
                self.refused(snapshot=snapshot, before=before)
        self.check_page(self.page(snapshot=3, before=3), limit=LIMIT_MAX, before=3)
        # The edge of the rule, stated as rows: `sequence <= snapshot` is the bound that exists on every
        # page, `sequence < before` is the one a continuation adds inside it, so this pair reads 2 and 1
        # and never 3.
        self.assertEqual([row['sequence'] for row in self.page(snapshot=3, before=3)['rows']], [2, 1])
        self.assertEqual([row['sequence'] for row in self.page(snapshot=3, before=2)['rows']], [1])

    def test_positions_are_canonical_decimal_integers_within_signed_sixty_three_bits(self):
        for value in NONCANONICAL_POSITIONS:
            with self.subTest(snapshot=repr(value)):
                self.refused(snapshot=value, before=1)
            with self.subTest(before=repr(value)):
                self.refused(snapshot=INT64_MAX, before=value)
        for pair in ((0, 0), (1, 0), (INT64_MAX, INT64_MAX), (INT64_MAX, 0)):
            with self.subTest(pair=pair):
                self.check_page(self.page(snapshot=pair[0], before=pair[1]), limit=LIMIT_MAX,
                                before=pair[1])

    def test_a_refusal_opens_no_connection_and_leaves_the_file_alone(self):
        """The whole point of validating in the unit that owns the read, not in the handler above it.

        Counting `sqlite3.connect` is the measurement: "we checked first" is worth nothing unless the
        driver is shown never to have been called, and the fingerprint shows a refused call did not
        grow, touch or reorder a row either.
        """
        before = self.fingerprint()
        attempts = ({'limit': 0}, {'limit': '05'}, {'limit': True}, {'category': 'refusals'},
                    {'category': []}, {'snapshot': 5}, {'before': 5}, {'snapshot': 2, 'before': 3},
                    {'snapshot': -1, 'before': 0}, {'snapshot': INT64_MAX + 1, 'before': 0},
                    {'snapshot': '01', 'before': '0'})
        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            for kwargs in attempts:
                with self.subTest(kwargs=kwargs):
                    connect.reset_mock()
                    self.refused(**kwargs)
                    self.assertEqual(connect.call_count, 0,
                                     f'audit_page({kwargs}) opened a database to say no')
        self.assertEqual(self.fingerprint(), before, 'a refused call moved the database')


if __name__ == '__main__':
    unittest.main()

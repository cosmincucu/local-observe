"""Issue #197: a suppression is decided *inside* the admission that booked the page, not after it.

The shape this file exists to kill was two commits. `file_event` called `Store.intake`, which filed the
event, the condition, the incident and an outbox row and **committed** them; then this module decided
whether that delivery was allowed to reach a human and, when it was not, marked it `dead` in a second
transaction. Between those two commits the row was `pending`, durable, and visible to
`Store.claim_notification` — so a notifier that happened to tick in that window could lease a page that
was about to be folded, send it, and leave the operator with an alert that fired during a maintenance
window, during a flap, or under a parent that was already paged. Nothing had to be wrong with the
decision for that to happen; it only had to be late.

The fix is one keyword-only argument on `Store.intake` (`admission=`) and the callback `file_event` hands
it: intake files and audits, then calls back **on its own connection, before committing**, and the fold
lands there. So the two properties the module header argues for are one property — the event is filed
before it is decided (the flap count includes this transition) and the fold commits with the filing (no
lease can be granted in a gap that no longer exists).

**How the races below are real rather than described.** Every test here runs a real temporary SQLite
database, a real `Store`, and real threads: the writer runs the real `suppression.file_event`, the
notifier runs the real `Store.claim_notification` — the delivery rail's own claim, the one that would
have handed a `pending` row to `deliver_one` — and they meet at `_count_transitions`, the first read every
decision makes, wrapped (not replaced) for one call on the connection the decision is being made against.
Coordination is by `threading.Event` handshakes and never by a sleep, every join is bounded, and `raced`
is the observation that separates the two orderings: did the claim *finish* while the decision was still
undecided?

**Why the negative controls are in this file.** Without them a green `raced is False` could mean "fixed"
or could mean "the notifier never got close enough to see".
`test_the_committed_before_deciding_ordering_loses_the_page_to_the_notifier` reconstructs the superseded
ordering inside the test — `intake` commits, the claim runs, `suppress_delivery` arrives afterwards — and
shows the notifier winning a row that was already folded in intent.
`test_a_notifier_claiming_the_instant_the_filing_returns_finds_nothing_to_send` makes the same point with
no threads, by wrapping the real `Store.intake` and claiming the first instant its rows are visible: that
is the control to run against a restored `file_event`.

The two AST checks at the end of the file pin what a behavioural test cannot: the seam sits inside
`intake`'s one transaction after its audit row, and the callback opens no transaction and no read-only
connection of its own. No network is reachable from any of this: every `Store` is built with an explicit
`notification_safety.NotificationPolicy(delivery_mode='recording')`, and the tests call the claim, not
`notifications.deliver_one`, so no client exists to send through.
"""
import ast
import datetime as dt
import sqlite3
import tempfile
import threading
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest import mock

from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import suppression
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-09T12:00:00Z')
REVISION = 'fixture-rev-1'
PRODUCER = Actor('admission-fixture', 'producer')
HUMAN = Actor('operator', 'human')

#: The bound on every thread join in this file. Nothing here waits on a sleep as synchronization: a
#: thread that outlives this is a test failure, not a slower machine.
JOIN_SECONDS = 30
#: How long an admission waits to learn whether a competing claim has already finished. In the ordering
#: this item replaced a claim finishes here in milliseconds; under the admission callback it cannot
#: finish at all, because the notifier is parked on `BEGIN IMMEDIATE` until the decision commits. The
#: outcome of every test below is the same whatever this number is — the fold commits either way — it is
#: only the *observation* of the notifier that needs the patience.
CLAIM_WINDOW_SECONDS = 1.0


def identifier(name: str) -> str:
    """A stable synthetic UUID for a name, never a real estate id."""
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'suppression-admission/' + name))


def resource(name: str, relations: tuple[tuple[str, str], ...] = ()) -> dict:
    """One declared resource, with optional outgoing depends-on relations."""
    return {'id': identifier(name), 'kind': 'service', 'name': name,
            'aliases': [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
            'attributes': {'environment': 'fixture'},
            'relations': [{'type': relation, 'target': identifier(target)} for relation, target in relations]}


def chain(names: list[str]) -> list[dict]:
    """A depends-on chain: `names[0]` rests on `names[1]`, which rests on `names[2]`, and so on."""
    return [resource(name, (('depends-on', names[position + 1]),) if position + 1 < len(names) else ())
            for position, name in enumerate(names)]


class FaultyGraph:
    """A `topology.Topology` stand-in that fails at the hop a dependency decision asks for.

    Only `upstream()` is reached by `suppression.dependency`, and the raised class is chosen so the
    decision cannot swallow it: `dependency` catches the driver, inventory and OS families around that
    call and answers "this finding stands on its own", so a fault in one of those would file the event
    and queue the page instead of unwinding the admission. `RuntimeError` is outside all of them.
    """

    def __init__(self, error: BaseException) -> None:
        self.error = error

    def upstream(self, resource_id: str, depth: int, *, max_rows: int | None = None) -> dict:
        raise self.error


class AdmissionRaceTests(unittest.TestCase):
    """One writer filing, one notifier claiming, and no gap between the booking and the fold."""

    def setUp(self):
        """A scratch directory, a declared two-resource graph and one recording-only store."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = self.root / 'inventory.db'
        index.build({'schema_version': 1, 'resources': chain(['demo-worker', 'demo-api'])},
                    self.index_path, REVISION, now=NOW)
        self.store = self.recording_store('admission.db')

    # --- fixtures -----------------------------------------------------------------------------

    def recording_store(self, name: str) -> Store:
        """A store whose channel can only ever record: no client is constructed, so none can send."""
        return Store(self.root / name, notification_policy=NotificationPolicy(delivery_mode='recording'))

    def verdict(self, status: str, at: dt.datetime, *, name: str, rule: str | None = None) -> dict:
        """One canonical event about the resource called `name`, at `at`."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, identifier(name), rule or f'{name}-down', 'availability', status,
                     window, {'sample_id': 'fixture'}, query_type='gatus-result')

    def file(self, status: str, at: dt.datetime, *, name: str, rule: str | None = None) -> dict:
        """File one event through the suppression path, with the declared graph attached."""
        return suppression.file_event(self.store, self.verdict(status, at, name=name, rule=rule),
                                      PRODUCER, now=at, index_path=self.index_path)

    def declare(self, at: dt.datetime) -> dict:
        """Open a maintenance window over `demo-api`, as a human would, covering `at`."""
        return suppression.declare_window(
            self.store, {'resource_id': identifier('demo-api'), 'starts_at': utc_text(at),
                         'ends_at': utc_text(at + dt.timedelta(hours=4)), 'reason': 'replace the disk'},
            HUMAN, now=at)

    def drain(self, at: dt.datetime) -> list[str]:
        """Send everything currently queued, so the only queue head left is the one under decision.

        A notifier competing at a head of `sending` rows would answer None for the head-of-queue clause
        rather than for the fold, which would be an accident passing as a result. `sent` rows stop
        blocking their incident's later deliveries, so what a claim finds during an admission is the row
        that admission booked and nothing else.
        """
        sent = []
        while True:
            claim = self.store.claim_notification(now=at)
            if claim is None:
                return sent
            self.store.finish_notification(claim['id'], claim['claim_token'], True, now=at)
            sent.append(claim['id'])

    def raw(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite, so no answer here comes from the code under test."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    def counting_transitions(self) -> tuple[list, object]:
        """Return a wrapper for `_count_transitions` that records every call, calling the real one.

        Captured before `mock.patch.object` replaces the attribute, so the wrapper is a spy on the real
        read and not a substitute for it.
        """
        calls: list[str] = []
        real = suppression._count_transitions

        def spy(db, condition, start, finish, seconds):
            calls.append(condition)
            return real(db, condition, start, finish, seconds)

        return calls, spy

    def race(self, verdict: dict, at: dt.datetime, store: Store | None = None, **kwargs) -> dict:
        """File one event while a real notifier tries to claim whatever that filing booked.

        The writer thread runs `suppression.file_event`; the notifier thread runs
        `Store.claim_notification` — both real entry points, both on their own connections, over one
        SQLite file. The handshake sits on the first read every decision makes:

        1. the decision starts counting transitions on intake's connection and sets `deciding`;
        2. the notifier waits for that, enters `claim_notification`, and sets `requested`;
        3. the decision waits up to `CLAIM_WINDOW_SECONDS` to see whether the claim **finished** — the
           `raced` answer — and then proceeds to fold and let the transaction commit;
        4. both threads are joined with a bound, and anything still alive is a failure.

        Returns the box the threads filled in: `result`, `claim`, `errors`, `raced`, `claimed`, `decided`.
        """
        store = store or self.store
        deciding, requested, claimed = threading.Event(), threading.Event(), threading.Event()
        box: dict[str, object] = {'result': None, 'claim': None, 'errors': [], 'raced': None,
                                  'claimed': False, 'decided': 0}
        real = suppression._count_transitions

        def rendezvous(db, condition, start, finish, seconds):
            box['decided'] += 1
            if box['decided'] == 1:
                deciding.set()
                self.assertTrue(requested.wait(JOIN_SECONDS), 'the notifier never entered claim_notification')
                box['raced'] = claimed.wait(CLAIM_WINDOW_SECONDS)
            return real(db, condition, start, finish, seconds)

        def writer() -> None:
            try:
                box['result'] = suppression.file_event(store, verdict, PRODUCER, now=at, **kwargs)
            except BaseException as exc:                       # carried to the joining thread
                box['errors'].append(exc)

        def notifier() -> None:
            if not deciding.wait(JOIN_SECONDS):
                box['errors'].append(AssertionError('the admission never reached a decision'))
                return
            requested.set()
            try:
                box['claim'] = store.claim_notification(now=at + dt.timedelta(seconds=1))
            except BaseException as exc:
                box['errors'].append(exc)                      # a lock error is a finding, not a flake
            finally:
                claimed.set()
                box['claimed'] = True

        with mock.patch.object(suppression, '_count_transitions', new=rendezvous):
            threads = [threading.Thread(target=writer, name='intake'),
                       threading.Thread(target=notifier, name='notifier')]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(JOIN_SECONDS)
            box['alive'] = [thread.name for thread in threads if thread.is_alive()]
        self.assertEqual(box['alive'], [], 'a thread outlived its bound join')
        return box

    def unfolded(self, box: dict) -> dict:
        """Assert the race ran to the end without faulting, and hand back the filing's own result."""
        self.assertEqual(box['errors'], [], 'a thread raised; the box holds it for the report')
        self.assertTrue(box['claimed'], 'the notifier must have run to an answer, not been skipped')
        self.assertEqual(box['decided'], 1, 'one decision per filing')
        self.assertIs(box['raced'], False, 'the claim finished while the decision was still undecided, so '
                                           'the booking was already committed — which is the ordering '
                                           'this issue exists to remove')
        return box['result']

    # --- the races ----------------------------------------------------------------------------

    def test_a_maintenance_window_folds_the_page_before_a_notifier_can_lease_it(self):
        """The brief's case, run as a race: the notifier competes and must be handed nothing sendable.

        The window is declared first, so the decision is not close: this page must never go out. The
        assertion that carries the item is not `suppressed` — that was always true — it is that the
        concurrent `claim_notification` could not finish under the decision (`raced`) and came back with
        nothing (`claim is None`) once the admission committed: the row was `dead` before it was ever
        durable, so there was no instant in which it could be sent.
        """
        at = NOW + dt.timedelta(minutes=1)
        self.declare(at)
        box = self.race(self.verdict('firing', at, name='demo-api'), at)
        result = self.unfolded(box)
        self.assertTrue(result['suppressed'])
        self.assertEqual(result['decision'].cause, 'maintenance-window')
        self.assertEqual(result['intake']['status'], 'accepted', 'the finding is still filed')
        self.assertIsNone(box['claim'], 'the delivery rail was handed nothing it could send')

    def test_a_folded_page_is_dead_refused_and_audited_in_the_filing_itself(self):
        """One commit, three refusal rows and no second transaction: the durable footprint.

        `event.intake` and `notification.suppressed` sit in the same audit sequence with nothing between
        them, which is the fingerprint of the fold having run inside the admission: in the two-commit
        ordering the second row was written by a *later* transaction, after a window in which the row was
        claimable. The event, its incident and its condition are all present, because a fold is a state
        and never a drop.
        """
        at = NOW + dt.timedelta(minutes=1)
        self.declare(at)
        box = self.race(self.verdict('firing', at, name='demo-api'), at)
        result = self.unfolded(box)
        delivery = result['delivery']
        self.assertIsNone(box['claim'])
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?', (delivery,))[0]['status'], 'dead')
        self.assertEqual(len(self.raw('SELECT outbox_id FROM notification_suppressions WHERE outbox_id=?',
                                      (delivery,))), 1)
        operations = [row['operation'] for row in
                      self.raw('SELECT operation FROM audit WHERE subject IN (?,?) ORDER BY sequence',
                               (result['intake']['event_id'], delivery))]
        self.assertEqual(operations, ['event.intake', 'notification.suppressed'],
                         'one transaction wrote both halves of this admission')
        self.assertEqual(len(self.raw('SELECT id FROM events')), 1)
        self.assertEqual(len(self.raw('SELECT id FROM incidents WHERE status=\'open\'')), 1)

    def test_the_flap_fold_counts_the_transition_this_admission_itself_just_filed(self):
        """The threshold is reached by the transition being decided, on the connection that wrote it.

        Three edges are filed first, so the committed database holds three transitions; the fourth edge
        is the one racing the notifier. A decision reading a *committed* snapshot would count three,
        miss the threshold of four and let the page go — which is the half of the old ordering that was
        wrong even without a race. The assertion on the pre-read count is what makes this a test of the
        count and not of a number the module happens to print.
        """
        for step in range(3):
            at = NOW + dt.timedelta(seconds=10 * step)
            self.file('resolved' if step % 2 else 'firing', at, name='demo-api')
        at = NOW + dt.timedelta(seconds=30)
        key = suppression.condition_key(self.verdict('firing', at, name='demo-api'))
        self.assertEqual(suppression.transitions(self.store, key, now=at)['transitions'], 3,
                         'three transitions are committed before the fourth event exists')
        self.assertEqual(len(self.drain(at + dt.timedelta(seconds=1))), 3,
                         'the three pages the episode was allowed are out of the queue')
        box = self.race(self.verdict('resolved', at, name='demo-api'), at)
        result = self.unfolded(box)
        self.assertEqual(result['decision'].transitions, 4, 'including the one this admission just filed')
        self.assertEqual(result['decision'].cause, 'flapping')
        self.assertTrue(result['suppressed'])
        self.assertIsNone(box['claim'], 'the folded page was never leasable')
        self.assertIsNone(self.store.claim_notification(now=at + dt.timedelta(seconds=2)))

    def test_a_dependency_symptom_is_folded_before_a_notifier_can_lease_it(self):
        """The parent is already paged, so the child's page is folded — and never queue-head pending.

        The down set is read on the admission's own connection, so the fold is decided against the same
        `incidents` rows the event is being filed beside, not against a snapshot taken before it.
        """
        self.file('firing', NOW, name='demo-api')
        at = NOW + dt.timedelta(seconds=30)
        self.assertEqual(len(self.drain(at + dt.timedelta(seconds=1))), 1, 'the parent paged once')
        box = self.race(self.verdict('firing', at, name='demo-worker'), at, index_path=self.index_path)
        result = self.unfolded(box)
        self.assertEqual(result['decision'].cause, 'dependency')
        self.assertTrue(result['suppressed'])
        self.assertIsNone(box['claim'], 'the symptom was never leasable')
        self.assertIsNone(self.store.claim_notification(now=at + dt.timedelta(seconds=2)))

    def test_an_unfolded_page_is_claimable_the_moment_the_admission_commits(self):
        """The fix must not cost the delivery rail a send: a page owed to a human is still handed out.

        Nothing about this finding is suppressed, so the competing claim is expected to win — but only
        *after* the commit, which is what `raced is False` says. The row it comes back with is the one the
        admission booked, and it is `sending`: the notifier waited on the write lock for a row that was
        never once visible as `pending`.
        """
        at = NOW + dt.timedelta(minutes=1)
        box = self.race(self.verdict('firing', at, name='demo-api'), at)
        result = self.unfolded(box)
        self.assertFalse(result['suppressed'])
        self.assertIsNone(result['decision'].cause)
        self.assertIsNotNone(box['claim'])
        self.assertEqual(box['claim']['id'], result['delivery'])
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?', (result['delivery'],))[0]['status'],
                         'sending')

    def test_a_duplicate_and_a_finding_that_files_no_transition_still_decide_nothing(self):
        """Unchanged replay behaviour: no decision, no fold, no audit line, and no callback read either.

        Both shapes were answered before the delivery rail could be confused and they are answered the
        same way now: a repeat of an event `intake` already holds, and a firing event that found an open
        incident and booked no send. The spy on the transition read proves the *absence* of a decision
        rather than inferring it from a flag, and the queue head the first event left is asserted
        untouched — a fold that reached a row it did not book would show up here.
        """
        at = NOW + dt.timedelta(minutes=1)
        first = self.file('firing', at, name='demo-api')
        calls, spy = self.counting_transitions()
        with mock.patch.object(suppression, '_count_transitions', new=spy):
            repeat = suppression.file_event(self.store, self.verdict('firing', at, name='demo-api'),
                                            PRODUCER, now=at)
            later = suppression.file_event(self.store, self.verdict('firing', at + dt.timedelta(seconds=30),
                                                                  name='demo-api'),
                                           PRODUCER, now=at + dt.timedelta(seconds=30))
        self.assertEqual(calls, [], 'neither filing asked a question of the transition count')
        self.assertEqual(repeat['intake']['status'], 'duplicate')
        self.assertIsNone(repeat['decision'])
        self.assertFalse(repeat['suppressed'])
        self.assertEqual(later['intake']['status'], 'accepted')
        self.assertIsNone(later['intake']['transition'])
        self.assertIsNone(later['decision'])
        self.assertIsNone(later['delivery'])
        self.assertFalse(later['suppressed'])
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?', (first['delivery'],))[0]['status'],
                         'pending')
        self.assertEqual(self.raw('SELECT outbox_id FROM notification_suppressions'), [])
        self.assertEqual(self.raw("SELECT sequence FROM audit WHERE operation='notification.suppressed'"), [])

    def test_an_injected_decision_failure_rolls_back_the_event_the_decision_was_about(self):
        """A fold that cannot be reached leaves no page behind — and no finding either.

        The fault is injected through a public seam, `file_event`'s own `graph=` argument, so nothing in
        the decision is mocked: a `topology` double fails at `upstream()`, which the decision reaches
        after `intake` has inserted the event, its condition, its incident, its booked delivery and its
        `event.intake` audit row. `RuntimeError` is the point, not a detail — `dependency` catches the
        driver and inventory families around that call and answers "no suppression", which would have
        filed the event *and* queued the page the caller could not decide about. The counted tables are
        the assertion: nothing moved, and the store still files the next event normally.
        """
        self.file('firing', NOW, name='demo-api')
        tables = ('events', 'conditions', 'incidents', 'outbox', 'audit', 'notification_suppressions')
        with closing(sqlite3.connect(self.store.path)) as db:
            before = {name: db.execute(f'SELECT count(*) FROM {name}').fetchone()[0] for name in tables}
        at = NOW + dt.timedelta(seconds=30)
        with self.assertRaisesRegex(RuntimeError, 'injected decision failure'):
            suppression.file_event(self.store, self.verdict('firing', at, name='demo-worker'), PRODUCER,
                                   now=at, graph=FaultyGraph(RuntimeError('injected decision failure')))
        with closing(sqlite3.connect(self.store.path)) as db:
            after = {name: db.execute(f'SELECT count(*) FROM {name}').fetchone()[0] for name in tables}
        self.assertEqual(after, before, 'the rolled-back admission wrote nothing anywhere')
        self.assertEqual(self.raw('SELECT status FROM outbox')[0]['status'], 'pending',
                         'the parent\'s own page is untouched, and was never offered a fold')
        reopened = suppression.file_event(self.store, self.verdict('firing', at, name='demo-worker'),
                                         PRODUCER, now=at, index_path=self.index_path)
        self.assertEqual(reopened['intake']['status'], 'accepted', 'the file is usable afterwards')
        self.assertTrue(reopened['suppressed'], 'and this time the symptom is folded before it is durable')

    # --- the negative controls -------------------------------------------------------------------

    def test_the_committed_before_deciding_ordering_loses_the_page_to_the_notifier(self):
        """The defect, reproduced on purpose: when the booking commits first, a folded page still sends.

        Nothing in this test calls the fixed path. It drives the three steps the superseded `file_event`
        drove, in that order and with those public calls: `Store.intake` (commit), `claim_notification`
        (the notifier, in the gap), `suppress_delivery` (the decision, too late). The notifier wins a
        sendable row and the fold refuses to touch it — which is the whole reason the tests above are
        believed: the harness can see a claim landing in a gap, so their passing is the fix.
        """
        at = NOW + dt.timedelta(minutes=1)
        store = self.recording_store('old-ordering.db')
        self.assertEqual(suppression.declare_window(
            store, {'resource_id': identifier('demo-api'), 'starts_at': utc_text(at),
                    'ends_at': utc_text(at + dt.timedelta(hours=4)), 'reason': 'replace the disk'},
            HUMAN, now=at)['status'], 'declared')
        outcome = store.intake(self.verdict('firing', at, name='demo-api'), PRODUCER, now=at)
        self.assertEqual(outcome['transition'], 'opened', 'the booking is durable before any decision')
        claim = store.claim_notification(now=at + dt.timedelta(seconds=1))
        self.assertIsNotNone(claim, 'the notifier found the page pending, as it always could')
        folded = suppression.suppress_delivery(store, claim['id'],
                                               'maintenance-window x for resource y covers this finding',
                                               cause='maintenance-window', now=at)
        self.assertFalse(folded, 'the fold arrives after the lease and may not edit it')
        with closing(sqlite3.connect(store.path)) as db:
            self.assertEqual(db.execute('SELECT status FROM outbox WHERE id=?', (claim['id'],)).fetchone()[0],
                             'sending')
            self.assertEqual(db.execute('SELECT count(*) FROM notification_suppressions').fetchone()[0], 0)
        self.assertEqual(claim['payload']['event_id'], outcome['event_id'])

    def test_a_notifier_claiming_the_instant_the_filing_returns_finds_nothing_to_send(self):
        """The ordering told without threads: the earliest look the delivery rail can get is already too late.

        `Store.intake` commits as it returns, so a claim run from a wrapper around the real method sees
        the booked row at the first instant anything can — no handshake, no window, no timing assumption.
        Under the admission the fold committed with the filing, so there is nothing to lease. Restore the
        superseded `file_event` (intake, claim, `suppress_delivery`, in that order) against this same
        wrapper and the claim wins a `sending` lease on a row whose fold had not run yet.
        """
        at = NOW + dt.timedelta(minutes=1)
        self.declare(at)
        real_intake = self.store.intake                 # the bound method, taken before it is wrapped
        seen: dict[str, object] = {}

        def racing(*args, **kwargs):
            outcome = real_intake(*args, **kwargs)      # every supplied argument, `admission` included
            seen['claim'] = self.store.claim_notification(now=at + dt.timedelta(seconds=1))
            return outcome

        with mock.patch.object(self.store, 'intake', racing):
            result = suppression.file_event(self.store, self.verdict('firing', at, name='demo-api'),
                                            PRODUCER, now=at, index_path=self.index_path)
        self.assertIsNone(seen['claim'], 'the row was dead before it was ever visible, so nothing to send')
        self.assertTrue(result['suppressed'])
        self.assertEqual(result['decision'].cause, 'maintenance-window')
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?', (result['delivery'],))[0]['status'],
                         'dead')

    # --- the seam, seen from the store side -----------------------------------------------------

    def test_the_admission_decides_off_rows_that_are_not_committed_yet(self):
        """The callback is handed intake's connection, at the moment nothing else can see the rows.

        Asserted from both sides of that boundary on one real file: the callback's own connection answers
        one event row and one booked delivery, and a *separate* connection opened while the callback is
        still running answers zero for both. That is the property `file_event` needs — and the reason the
        fold cannot be decided off a second, read-only connection, which would be reading the `zero`.
        """
        at = NOW + dt.timedelta(minutes=1)
        verdict = self.verdict('firing', at, name='demo-api')
        seen: dict[str, object] = {}

        def admit(connection, outcome):
            seen['event'] = connection.execute('SELECT count(*) FROM events WHERE id=?',
                                               (outcome['event_id'],)).fetchone()[0]
            seen['delivery'] = connection.execute('SELECT count(*) FROM outbox').fetchone()[0]
            with closing(sqlite3.connect(self.store.path)) as elsewhere:
                seen['event_elsewhere'] = elsewhere.execute('SELECT count(*) FROM events').fetchone()[0]
                seen['delivery_elsewhere'] = elsewhere.execute('SELECT count(*) FROM outbox').fetchone()[0]
            seen['outcome'] = dict(outcome)

        outcome = self.store.intake(verdict, PRODUCER, now=at, admission=admit)
        self.assertEqual(seen['event'], 1, 'the callback sees the event it was given')
        self.assertEqual(seen['delivery'], 1, 'and the delivery that filing booked')
        self.assertEqual(seen['event_elsewhere'], 0, 'nothing else does, yet')
        self.assertEqual(seen['delivery_elsewhere'], 0, 'not even the booked send')
        self.assertEqual(outcome, seen['outcome'], 'the callback is handed the outcome this call returns')
        self.assertEqual(seen['outcome']['transition'], 'opened')
        with closing(sqlite3.connect(self.store.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone()[0], 1,
                             'and after the commit, everything does')

    def test_the_admission_is_not_called_for_a_duplicate_and_rolls_back_everything_when_it_raises(self):
        """Default behaviour is unchanged for a replay, and an admitted failure files nothing at all.

        The two halves are the seam's whole risk surface: a callback that ran against an already-filed
        event would fold a delivery this filing never booked, and a callback that raised *after* the rows
        were written must not leave them behind. The second half is asserted by counting every row in
        every table the admission path writes, before and after, and the store still working afterwards
        is what says the rollback closed cleanly rather than wedged the file.
        """
        at = NOW + dt.timedelta(minutes=1)
        verdict = self.verdict('firing', at, name='demo-api')
        self.store.intake(verdict, PRODUCER, now=at)
        calls: list[dict] = []

        def noted(connection, outcome):
            calls.append(outcome)

        self.assertEqual(self.store.intake(verdict, PRODUCER, now=at, admission=noted)['status'],
                         'duplicate')
        self.assertEqual(calls, [], 'a duplicate booked nothing, so there is nothing to decide')

        tables = ('events', 'conditions', 'incidents', 'outbox', 'audit', 'notification_suppressions')
        with closing(sqlite3.connect(self.store.path)) as db:
            before = {name: db.execute(f'SELECT count(*) FROM {name}').fetchone()[0] for name in tables}

        def fault(connection, outcome):
            raise RuntimeError('injected admission failure')

        later = self.verdict('firing', at + dt.timedelta(seconds=30), name='demo-api', rule='second-rule')
        with self.assertRaises(RuntimeError):
            self.store.intake(later, PRODUCER, now=at + dt.timedelta(seconds=30), admission=fault)
        with closing(sqlite3.connect(self.store.path)) as db:
            after = {name: db.execute(f'SELECT count(*) FROM {name}').fetchone()[0] for name in tables}
        self.assertEqual(after, before, 'the failed admission wrote nothing anywhere')
        self.assertEqual(self.store.intake(later, PRODUCER, now=at + dt.timedelta(seconds=60))['status'],
                         'accepted', 'and the file is usable afterwards')


class DefaultCallerTests(unittest.TestCase):
    """`Store.intake` without an admission is the method it was, byte for byte."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'intake.db')

    def verdict(self, status: str, at: dt.datetime, rule: str = 'disk-watermark') -> dict:
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, identifier('demo-api'), rule, 'availability', status, window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')

    def test_an_event_filed_the_old_way_leaves_the_old_rows_and_the_old_answer(self):
        """No callback, no suppression read, one commit: the API's `POST /v1/events` path is untouched.

        The shape `api.admit_intake` and every producer depends on — the four keys of the answer, the
        one booked delivery, the single `event.intake` audit row and the refusal wording of a conflicting
        watermark — is asserted here because the fix widened this method's signature to get the fold.
        """
        at = NOW + dt.timedelta(minutes=1)
        outcome = self.store.intake(self.verdict('firing', at), PRODUCER, now=at)
        self.assertEqual(sorted(outcome), ['event_id', 'incident_id', 'status', 'transition'])
        self.assertEqual((outcome['status'], outcome['transition']), ('accepted', 'opened'))
        rows = self.store.records('outbox')
        self.assertEqual([row['status'] for row in rows], ['pending'], 'the delivery rail keeps its claim')
        self.assertEqual([row['operation'] for row in self.store.records('audit')], ['event.intake'])
        # The same window, re-sent with a different verdict, is the case intake has always refused: its
        # `source_event_id` is the rule and the window, so it is caught as a repeat whose contents moved.
        with self.assertRaisesRegex(StateError, 'changed contents'):
            self.store.intake(self.verdict('resolved', at), PRODUCER, now=at)


class AdmissionShapeTests(unittest.TestCase):
    """Two structural pins: the seam's place in the commit, and what the callback may not reach for."""

    def state_tree(self) -> ast.Module:
        return ast.parse((ROOT / 'local_observe' / 'platform' / 'state.py').read_text())

    def suppression_tree(self) -> ast.Module:
        return ast.parse((ROOT / 'local_observe' / 'platform' / 'suppression.py').read_text())

    @staticmethod
    def function(tree: ast.Module, class_name: str | None, name: str) -> ast.FunctionDef:
        node = tree
        if class_name is not None:
            node = next(node for node in tree.body
                        if isinstance(node, ast.ClassDef) and node.name == class_name)
        return next(node for node in node.body if isinstance(node, ast.FunctionDef) and node.name == name)

    def test_the_admission_runs_inside_intakes_one_transaction_and_after_its_audit(self):
        """Behavioural tests show the fold lands first; this one says why it cannot drift back out.

        The callback call must sit inside the single `with self.transaction()` block of `Store.intake` —
        that nesting *is* the rollback and the *is* the no-gap property — and after the `event.intake`
        audit row, so a deciding callback sees the whole admission. Moving the call to after the commit
        would keep every behaviour test above passing on a quiet machine and re-open issue #197 in
        production, which is the failure a comment cannot prevent and this shape check can.
        """
        intake = self.function(self.state_tree(), 'Store', 'intake')
        transactions = [node for node in ast.walk(intake) if isinstance(node, ast.With) and any(
            isinstance(item.context_expr, ast.Call) and isinstance(item.context_expr.func, ast.Attribute)
            and item.context_expr.func.attr == 'transaction' for item in node.items)]
        self.assertEqual(len(transactions), 1, 'intake is one transaction, and the seam belongs inside it')
        block = transactions[0]
        calls = [node for node in ast.walk(block) if isinstance(node, ast.Call)]
        admitted = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id == 'admission']
        self.assertEqual(len(admitted), 1, 'the admission is called exactly once, inside that transaction')
        audited = [node for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == 'audit'
                   and any(isinstance(arg, ast.Constant) and arg.value == 'event.intake' for arg in node.args)]
        self.assertEqual(len(audited), 1)
        self.assertLess(audited[0].lineno, admitted[0].lineno,
                        'the seam runs after the intake audit row, so a callback sees the whole admission')

    def test_the_admission_callback_opens_no_transaction_and_no_read_only_connection(self):
        """`file_event`'s callback decides on the connection it was handed, or it decides too early.

        A nested `store.transaction()` here would be a second writer inside the admission (and SQLite
        would answer it as an error, not as a cheaper read), and a `_readonly(store)` connection would be
        a snapshot of the database as it stood *before* this event — a flap count missing its own
        transition, a down set missing its own parent. Both are one careless line away, so the callback's
        own body is walked for both call names.
        """
        file_event = self.function(self.suppression_tree(), None, 'file_event')
        admit = next(node for node in file_event.body
                     if isinstance(node, ast.FunctionDef) and node.name == 'admit')
        for node in ast.walk(admit):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, ('transaction', '_readonly'),
                                 f'the admission opens its own connection on line {node.lineno}')


if __name__ == '__main__':
    unittest.main()

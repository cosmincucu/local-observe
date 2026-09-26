"""suppression: a maintenance window is declared control state, and it silences a send and nothing else.

The port source is ``legacy:detections/maintenance-windows.yaml`` — 91 lines of prose declaring which
detections sleep through which planned work. Its content is private and stays there; what is ported is
the *shape* (`id`, what it covers, a start, an end, a reason, an author) and the stance its header
argues for: a window is a decision somebody made, so it is recorded with a name on it and an expiry, and
it is not a filter that makes findings disappear.

Two properties are the item, and each is attacked from both ends here:

* **a window is opened by a human, and only by one.** The role gate is the same `state.require` the
  approval path uses. A ``producer`` credential that could declare the window covering its own findings
  would be a detector able to silence its own pager, and that is the class of defect the brief names as
  worth a refusal test of its own.
* **an open-ended window cannot exist.** A window is one key in control state's `notification_control` table and
  not a typed table of its own (`state.py`, above `MIGRATIONS`, is why), so there is no `CHECK` to lean
  on and the item is tested as what it is: the bound is refused by `declare_window`, re-refused by
  `live_windows` on every read, and the declaration a row points at is verified against the append-only
  audit log — so a hand-written, restored or later-edited row that no human declaration attests is
  counted and never applied. `tests/test_state_migration.py`'s `CURRENT_TABLES` pin is asserted
  **unchanged** from here, which is the checkable form of "this feature adds no table".

Everything else in the file is the "suppressed is a state, not a drop" half: the event still lands, the
incident still opens and resolves, the refusal is written in the three places a refusal belongs, and the
portal line says so — which `platform/presentation.py` already did for budget refusals, so this module
needed no change there and this file is the proof that it did not.
"""
import datetime as dt
import json
import sqlite3
import sys
import tempfile
import unittest
import uuid
from contextlib import closing, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from local_observe.inventory.validation import canonical, timestamp, utc_text
from local_observe.platform import presentation, state, suppression
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store
from test_state_migration import CURRENT_TABLES      # noqa: E402  (tests/ is not a package)

NOW = timestamp('2026-09-09T12:00:00Z')
PRODUCER = Actor('window-detector', 'producer')
HUMAN = Actor('operator', 'human')
RESOURCE = '7b3e9c1d-2f4a-4b5c-9d8e-1a2b3c4d5e6f'
OTHER = '1a2b3c4d-5e6f-4a5b-8c9d-0e1f2a3b4c5d'
RULE = 'disk-watermark'


class MaintenanceWindowTests(unittest.TestCase):
    """Declaring, expiring, revoking and being seen to do it."""

    def setUp(self):
        """One scratch directory, one store, and a helper's worth of canonical events."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'windows.db')

    def verdict(self, status: str, at: dt.datetime, *, rule: str = RULE,
                resource: str | None = RESOURCE) -> dict:
        """One canonical event for `rule` on `resource`, at `at`."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, resource, rule, 'availability', status, window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')

    def declaration(self, **overrides) -> dict:
        """A well-formed declaration, with the caller's overrides applied."""
        document = {'resource_id': RESOURCE, 'starts_at': utc_text(NOW),
                    'ends_at': utc_text(NOW + dt.timedelta(hours=4)), 'reason': 'replace the disk'}
        document.update(overrides)
        return document

    def declare(self, **overrides) -> dict:
        """Declare the shared window on the shared store."""
        return suppression.declare_window(self.store, self.declaration(**overrides), HUMAN, now=NOW)

    def raw(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite, so no answer here comes from the code under test."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    def window_rows(self) -> list[str]:
        """The stored text of every window control row, raw and in key order, however malformed.

        A window is a key in `notification_control`, so this is the whole surface a restore or a hand
        edit could leave behind — including values that are not window documents at all, which the tests
        below plant on purpose and which must be counted rather than skipped.
        """
        return [row[0] for row in self.raw(
            "SELECT value FROM notification_control WHERE key LIKE 'maintenance:%' ORDER BY key")]

    def window_document(self, window_id: str) -> dict:
        """One stored window document, parsed from the text the file holds."""
        row = self.raw('SELECT value FROM notification_control WHERE key=?',
                       (state.maintenance_key(window_id),))
        return json.loads(row[0][0]) if row else None

    def plant(self, name: str, *, start: dt.datetime, end: dt.datetime, reason: str = 'work',
              attest: bool = True) -> str:
        """Write one window control row straight into the file (see `plant_window` below)."""
        return plant_window(self.store, name, start=start, end=end, reason=reason, attest=attest)

    def audit(self, operation: str) -> list[sqlite3.Row]:
        """Every audit row carrying one operation, oldest first."""
        return self.raw('SELECT sequence, at, actor, operation, subject, detail FROM audit'
                        ' WHERE operation=? ORDER BY sequence', (operation,))

    # --- who may declare ----------------------------------------------------------------------

    def test_only_a_human_actor_may_open_a_window(self):
        """The brief's refusal test: a `producer` role asking for a window is refused, and writes nothing.

        Every other role the platform knows (`reader`, `summary`, `executor`, `proposer`) is refused by
        the same line, and the empty audit log after each attempt is the half that matters: a refused
        declaration must not leave a row behind that a later reader could mistake for a window.
        """
        for role in ('producer', 'reader', 'summary', 'executor', 'proposer'):
            with self.subTest(role=role):
                with self.assertRaisesRegex(StateError, 'not authorised'):
                    suppression.declare_window(self.store, self.declaration(), Actor('someone', role),
                                               now=NOW)
        self.assertEqual(self.audit('maintenance.declared'), [])
        self.assertEqual(self.window_rows(), [])
        self.assertEqual(suppression.covering_window(self.store, self.verdict('firing', NOW), now=NOW),
                         None)

    def test_an_anonymous_human_is_refused_too(self):
        """`require` refuses an empty identity whatever the role: a window needs a name on it."""
        with self.assertRaisesRegex(StateError, 'not authorised'):
            suppression.declare_window(self.store, self.declaration(), Actor('', 'human'), now=NOW)

    def test_declaring_writes_one_row_and_one_audit_line_naming_who_and_what(self):
        """Create-time audit, in the declarer's own identity, and the row points back at it."""
        declared = self.declare()
        self.assertEqual(declared['status'], 'declared')
        rows = self.window_rows()
        self.assertEqual(len(rows), 1)
        document = self.window_document(declared['id'])
        self.assertEqual(document['schema_version'], suppression.WINDOW_DOCUMENT_VERSION)
        self.assertIsNone(document['revoked'])
        stored = document['declared']
        self.assertEqual(stored['author'], HUMAN.identity)
        self.assertEqual(stored['resource_id'], RESOURCE)
        self.assertIsNone(stored['rule_id'])
        lines = self.audit('maintenance.declared')
        self.assertEqual([(line['actor'], line['subject']) for line in lines],
                         [(HUMAN.identity, declared['id'])])
        detail = json.loads(lines[0]['detail'])
        self.assertEqual(detail, stored,
                         'the audit row is the whole declaration, which is what an attestation compares')
        self.assertEqual(document['attest'], lines[0]['sequence'],
                         'the stored window names the audit row that made it real')
        self.assertEqual(detail['reason'], 'replace the disk')
        self.assertIsNone(detail['rule_id'])

    def test_the_same_declaration_twice_is_one_window_and_no_second_audit_line(self):
        """Content-addressed identity: a re-typed declaration is answered `duplicate` and writes nothing.

        The second person who types it does not become its author — the stored row is handed back with
        the name that got there first, because that is the fact the audit trail already holds.
        """
        first = self.declare()
        again = suppression.declare_window(self.store, self.declaration(), Actor('second-operator', 'human'),
                                           now=NOW + dt.timedelta(minutes=1))
        self.assertEqual(again['status'], 'duplicate')
        self.assertEqual(again['id'], first['id'])
        self.assertEqual(again['window']['author'], HUMAN.identity)
        self.assertEqual(len(self.window_rows()), 1)
        self.assertEqual(len(self.audit('maintenance.declared')), 1)
        # A different end is a different window, and it is declared like any other.
        later = self.declare(ends_at=utc_text(NOW + dt.timedelta(hours=8)))
        self.assertEqual(later['status'], 'declared')
        self.assertNotEqual(later['id'], first['id'])

    # --- the bounds ---------------------------------------------------------------------------

    def test_every_unbounded_declaration_is_refused_before_it_is_written(self):
        """Each refusal is its own sentence, and none of them leaves a row behind.

        The list is the bound set of this feature: a selector that is both or neither, a timestamp that
        is not aware-UTC text, an end that is not after a start, a span over `MAX_WINDOW_SECONDS`, a
        window that was already over the moment it was declared, a reason that is not one printable
        bounded line, and a key nobody defined.
        """
        naive = utc_text(NOW).replace('+00:00', '')
        cases = {
            'both selectors': self.declaration(rule_id=RULE),
            'neither selector': {'starts_at': utc_text(NOW), 'ends_at': utc_text(NOW + dt.timedelta(hours=1)),
                                 'reason': 'work'},
            'unknown key': self.declaration(ticket='CH-1'),
            'naive start': self.declaration(starts_at=naive),
            'missing start': self.declaration(starts_at=None),
            'end before start': self.declaration(ends_at=utc_text(NOW - dt.timedelta(minutes=5))),
            'zero span': self.declaration(ends_at=utc_text(NOW)),
            'over the bound': self.declaration(ends_at=utc_text(NOW + dt.timedelta(seconds=86401))),
            'already over': self.declaration(starts_at=utc_text(NOW - dt.timedelta(hours=3)),
                                             ends_at=utc_text(NOW - dt.timedelta(hours=1))),
            'empty reason': self.declaration(reason=''),
            'long reason': self.declaration(reason='x' * 201),
            'multiline reason': self.declaration(reason='disk swap\nsecond line'),
            'tab reason': self.declaration(reason='disk\tswap'),
            'control reason': self.declaration(reason='disk\x07swap'),
            'resource not a uuid': self.declaration(resource_id='this-host'),
            'rule not a label': self.declaration(rule_id='disk swap / nightly'),
        }
        for name, document in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(StateError):
                    suppression.declare_window(self.store, document, HUMAN, now=NOW)
        self.assertEqual(self.window_rows(), [])
        self.assertEqual(self.audit('maintenance.declared'), [])

    def test_a_control_row_that_no_human_declaration_attests_is_never_applied(self):
        """Insert straight past `declare_window` and the row still silences nothing.

        This is what the item pays for choosing a key in `notification_control` over a typed table: there
        is no `CHECK` in the file holding a window to its bounds, so every applied window names the
        append-only `maintenance.declared` row that created it (`state.py`, above `MIGRATIONS`, states the
        trade). A row written by hand, restored from a copy or left by a wider build has no such row, and
        refusing it is the direction that pages rather than the one that goes quiet.
        """
        self.plant('unattested', start=NOW, end=NOW + dt.timedelta(hours=4), attest=False)
        answer = suppression.live_windows(self.store, now=NOW)
        self.assertEqual((answer['count'], answer['unattested'], answer['unusable']), (0, 1, 0))
        self.assertIsNone(suppression.covering_window(self.store, self.verdict('firing', NOW), now=NOW))
        self.assertFalse(suppression.decide(self.store, self.verdict('firing', NOW),
                                            now=NOW).suppressed,
                         'an unattested window must not fold a page')
        self.assertEqual(suppression.stats(self.store, now=NOW)['windows']['unattested'], 1)

    def test_a_window_row_whose_text_moved_after_it_was_declared_is_never_applied(self):
        """Tamper with a stored declaration and the attestation is what notices, on every read.

        The row below started life honest — `declare_window` wrote it and the audit row behind it is
        genuine — and then its `ends_at` was widened in the file, which is exactly what a `CHECK` in a
        typed table would have refused. The comparison is against the whole declared block, so a moved
        end, a rewritten reason or a different author all land in the same place: not applied. Revoking
        still works, because signing a cancellation can never silence anything.
        """
        declared = self.declare()
        key = state.maintenance_key(declared['id'])
        with self.store.transaction() as connection:
            document = json.loads(connection.execute(
                'SELECT value FROM notification_control WHERE key=?', (key,)).fetchone()[0])
            document['declared']['ends_at'] = utc_text(NOW + dt.timedelta(hours=20))
            connection.execute('UPDATE notification_control SET value=? WHERE key=?',
                               (canonical(document), key))
        widened = suppression.live_windows(self.store, now=NOW)
        self.assertEqual((widened['count'], widened['unattested']), (0, 1))
        self.assertFalse(suppression.decide(self.store, self.verdict('firing', NOW),
                                            now=NOW).suppressed)
        self.assertEqual(suppression.revoke_window(self.store, declared['id'], HUMAN,
                                                   now=NOW)['status'], 'revoked')

    def test_a_declaration_is_written_once_and_only_its_revoke_pair_is_ever_added(self):
        """No edit path: the primitive this module writes with inserts, and revoke adds two fields.

        The typed table had an UPDATE trigger permitting exactly one transition. The same promise here is
        made by `state.control_declare` answering 0 for a key that already holds a declaration — so a
        re-typed window can neither widen its own end nor change whose name is on it — and by the fact
        that the only value this module ever rewrites is the stored document plus its `revoked` pair. The
        declared text is compared against the audit row that attests it, which is the version a human
        signed.
        """
        declared = self.declare()
        key = state.maintenance_key(declared['id'])
        before = self.window_document(declared['id'])
        self.assertIsNone(before['revoked'])
        with self.store.transaction() as connection:
            self.assertEqual(state.control_declare(connection, key, '{"overwritten":true}', NOW), 0,
                             'the insert-only primitive replaced a declaration that was already there')
        self.assertEqual(self.window_document(declared['id']), before,
                         'and the stored text did not move')
        at = NOW + dt.timedelta(minutes=1)
        suppression.revoke_window(self.store, declared['id'], HUMAN, now=at)
        after = self.window_document(declared['id'])
        self.assertEqual(after['declared'], json.loads(self.audit('maintenance.declared')[0]['detail']))
        self.assertEqual(after['attest'], before['attest'])
        self.assertEqual(sorted(after['revoked']), ['revoked_at', 'revoked_by'])
        self.assertEqual(after['revoked']['revoked_by'], HUMAN.identity)
        self.assertEqual(len(self.window_rows()), 1, 'a revoke is not the insertion of a second window')

    def test_the_live_window_bound_is_enforced_at_declaration(self):
        """The 32nd live window is refused: past that the platform is not sleeping, it is dark."""
        for step in range(suppression.MAX_LIVE_WINDOWS):
            at = NOW + dt.timedelta(minutes=step)
            declared = suppression.declare_window(self.store, self.declaration(
                resource_id=f'{step:08x}-0000-4000-8000-000000000000',
                starts_at=utc_text(at), ends_at=utc_text(at + dt.timedelta(minutes=30))), HUMAN, now=NOW)
            self.assertEqual(declared['status'], 'declared', f'window {step}')
        with self.assertRaisesRegex(StateError, 'live maintenance windows'):
            suppression.declare_window(self.store, self.declaration(
                resource_id='ffffffff-0000-4000-8000-000000000000',
                starts_at=utc_text(NOW), ends_at=utc_text(NOW + dt.timedelta(minutes=30))), HUMAN, now=NOW)
        # An expired window is not live, so it buys no room either: revoking is what frees a slot.
        self.assertEqual(suppression.live_windows(self.store, now=NOW)['count'],
                         suppression.MAX_LIVE_WINDOWS)

    # --- what it covers ----------------------------------------------------------------------

    def test_a_window_over_the_resource_suppresses_the_send_and_names_itself_in_the_reason(self):
        """The brief's case: a window covering the resource, and the operator can read who said so."""
        declared = self.declare()
        round_ = suppression.file_event(self.store, self.verdict('firing', NOW + dt.timedelta(minutes=1)),
                                        PRODUCER, now=NOW + dt.timedelta(minutes=1))
        self.assertTrue(round_['suppressed'])
        decision = round_['decision']
        self.assertEqual(decision.cause, 'maintenance-window')
        self.assertIn('maintenance-window', decision.reason)
        self.assertIn(RESOURCE, decision.reason)
        self.assertIn('replace the disk', decision.reason)
        self.assertEqual(decision.detail['window_id'], declared['id'])
        self.assertEqual(decision.detail['declared_by'], HUMAN.identity)

    def test_a_window_over_the_rule_suppresses_that_rule_and_no_other(self):
        """The other selector shape, and its boundary: another rule on the same resource still pages."""
        suppression.declare_window(self.store, self.declaration(resource_id=None, rule_id=RULE), HUMAN,
                                   now=NOW)
        at = NOW + dt.timedelta(minutes=1)
        covered = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        neighbour = suppression.file_event(self.store, self.verdict('firing', at, rule='other-rule'),
                                           PRODUCER, now=at)
        self.assertTrue(covered['suppressed'])
        self.assertFalse(neighbour['suppressed'])
        self.assertEqual(neighbour['decision'].cause, None)

    def test_a_window_on_another_resource_suppresses_nothing(self):
        """Exact matching means a declaration about one resource never sleeps another one's findings."""
        self.declare(resource_id=OTHER)
        self.assertFalse(suppression.file_event(self.store, self.verdict('firing', NOW + dt.timedelta(minutes=1)),
                                                PRODUCER, now=NOW + dt.timedelta(minutes=1))['suppressed'])

    def test_a_platform_level_finding_is_covered_only_by_a_rule_window(self):
        """An event naming no resource cannot be matched to a resource, so only the rule selector reaches it.

        `resource_id` is nullable on a canonical event (a source-coverage finding about the platform
        itself carries none). A resource window must not swallow those by matching on NULL.
        """
        at = NOW + dt.timedelta(minutes=1)
        self.declare(resource_id=RESOURCE)
        self.assertFalse(suppression.file_event(self.store, self.verdict('firing', at, resource=None),
                                                PRODUCER, now=at)['suppressed'])
        fresh = Store(self.root / 'rule-window.db')
        suppression.declare_window(fresh, {'rule_id': RULE, 'starts_at': utc_text(NOW),
                                           'ends_at': utc_text(NOW + dt.timedelta(hours=4)),
                                           'reason': 'collector offline'}, HUMAN, now=NOW)
        covered = suppression.file_event(fresh, self.verdict('firing', at, resource=None), PRODUCER, now=at)
        self.assertTrue(covered['suppressed'])
        self.assertIn('rule ' + RULE, covered['decision'].reason)

    def test_the_window_boundary_is_inclusive_at_one_end_and_exclusive_at_the_other(self):
        """Covers at `starts_at`, stops covering at `ends_at`, and so stops one second past it.

        The brief's "expired by one second" case is the second assertion; the first is what makes the
        second one mean *exclusive end* rather than a clock that has drifted a second.
        """
        self.declare(ends_at=utc_text(NOW + dt.timedelta(minutes=30)))
        for label, now, covered in (
                ('at the start', NOW, True),
                ('one second before the end', NOW + dt.timedelta(minutes=30, seconds=-1), True),
                ('exactly at the end', NOW + dt.timedelta(minutes=30), False),
                ('one second after the end', NOW + dt.timedelta(minutes=30, seconds=1), False)):
            with self.subTest(case=label):
                decision = suppression.decide(self.store, self.verdict('firing', now), now=now)
                self.assertEqual(decision.suppressed, covered)
                self.assertEqual(decision.cause, 'maintenance-window' if covered else None)

    def test_a_window_that_has_not_started_yet_suppresses_nothing(self):
        """Planned work is not ongoing work: a future declaration covers the moment it names, not now."""
        self.declare(starts_at=utc_text(NOW + dt.timedelta(hours=2)),
                     ends_at=utc_text(NOW + dt.timedelta(hours=3)))
        answer = suppression.live_windows(self.store, now=NOW)
        self.assertEqual(answer['count'], 1, 'it is live — it is simply not covering yet')
        self.assertFalse(answer['windows'][0]['covers_now'])
        for at, covered in ((NOW + dt.timedelta(minutes=30), False),
                            (NOW + dt.timedelta(hours=2, seconds=30), True),
                            (NOW + dt.timedelta(hours=3, seconds=1), False)):
            with self.subTest(at=str(at)):
                self.assertEqual(suppression.decide(self.store, self.verdict('firing', at), now=at)
                                 .suppressed, covered)

    def test_revoking_closes_a_window_audited_and_once(self):
        """A cancelled job must not leave the pager asleep, and only a human may cancel one.

        Revoking is not deleting: the row keeps everything it was declared with, and the second revoke
        is refused rather than silently re-stamped, so `revoked_at` stays the one instant it happened.
        """
        declared = self.declare()
        at = NOW + dt.timedelta(minutes=1)
        with self.assertRaisesRegex(StateError, 'not authorised'):
            suppression.revoke_window(self.store, declared['id'], PRODUCER, now=at)
        self.assertTrue(suppression.file_event(self.store, self.verdict('firing', at), PRODUCER,
                                               now=at)['suppressed'])
        revoked = suppression.revoke_window(self.store, declared['id'], HUMAN, now=at)
        self.assertEqual(revoked['status'], 'revoked')
        lines = self.audit('maintenance.revoked')
        self.assertEqual([(line['actor'], line['subject']) for line in lines],
                         [(HUMAN.identity, declared['id'])])
        self.assertEqual(suppression.covering_window(self.store, self.verdict('firing', at), now=at), None)
        later = suppression.file_event(self.store, self.verdict('firing', at + dt.timedelta(seconds=30)),
                                       PRODUCER, now=at + dt.timedelta(seconds=30))
        self.assertFalse(later['suppressed'], 'a revoked window covers nothing again')
        with self.assertRaisesRegex(StateError, 'already revoked'):
            suppression.revoke_window(self.store, declared['id'], HUMAN, now=at)
        with self.assertRaisesRegex(StateError, 'No such maintenance window'):
            suppression.revoke_window(self.store, declared['id'].replace('a', 'b'), HUMAN, now=at)
        self.assertEqual(len(self.window_rows()), 1,
                         'revoking kept the record of the silence')

    # --- the decision is visible ---------------------------------------------------------------

    def test_a_windowed_finding_lands_as_an_event_an_incident_and_a_refusal_row(self):
        """Both halves of the brief's task 4, and the third one it inherits from the delivery rail.

        The event is in `events` and the incident it opened is in `incidents` (so the condition's
        history reads the same as an unsuppressed one), while the refusal writes the same trio a budget
        refusal writes: `status='dead'`, a `notification_suppressions` row, and one audit line naming
        `maintenance-window` as its cause. `Store.retry_notification` then refuses to replay it, which is
        the cost of that reuse and is asserted here rather than discovered later.
        """
        declared = self.declare()
        at = NOW + dt.timedelta(minutes=1)
        round_ = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        event_id = round_['intake']['event_id']
        self.assertEqual(len(self.raw('SELECT id FROM events WHERE id=?', (event_id,))), 1)
        self.assertTrue(round_['intake']['incident_id'])
        self.assertEqual(self.raw('SELECT status FROM incidents WHERE id=?',
                                  (round_['intake']['incident_id'],))[0]['status'], 'open')
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?',
                                  (round_['delivery'],))[0]['status'], 'dead')
        rows = self.raw('SELECT reason, at FROM notification_suppressions WHERE outbox_id=?',
                        (round_['delivery'],))
        self.assertEqual(len(rows), 1, 'a suppressed send still writes the notification_suppressions row')
        self.assertIn(declared['id'], rows[0]['reason'])
        lines = self.audit('notification.suppressed')
        self.assertEqual(json.loads(lines[0]['detail'])['cause'], 'maintenance-window')
        self.assertEqual(json.loads(lines[0]['detail'])['producer'], PRODUCER.identity)
        self.assertEqual(lines[0]['actor'], suppression.WORKER_ACTOR,
                         'the decision names the module, not the producer whose finding it folded')
        with self.assertRaisesRegex(StateError, 'cannot be replayed'):
            self.store.retry_notification(round_['delivery'], HUMAN, now=at)

    def test_the_operator_view_says_suppressed_with_the_reason_and_needs_no_change(self):
        """`presentation.py` already renders a refusal row as `(suppressed: <reason>)`.

        Task 4 asked for the smallest possible label there, or a report that it is not expressible. The
        answer is better than either: nothing had to change, because topology read model's `delivery_route` prints
        whatever `notification_suppressions` holds. This test is the evidence, and it is why
        `presentation.py` is not in this item's diff.
        """
        self.declare()
        at = NOW + dt.timedelta(minutes=1)
        suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        rows = presentation.records(self.store, 'outbox', self.store.records('outbox'))
        labels = [row['display']['delivery_name'] for row in rows]
        self.assertEqual(len(labels), 1)
        self.assertTrue(labels[0].startswith('Incident alert (suppressed: maintenance-window '), labels[0])
        self.assertIn('replace the disk', labels[0])
        self.assertTrue(rows[0]['delivery_safety']['reason'].startswith('maintenance-window '),
                        rows[0]['delivery_safety'])

    def test_a_suppressed_send_is_never_claimed_and_the_recording_sink_sees_nothing(self):
        """The delivery rail's view: there is no row left for it to lease.

        Without the `dead` status the refusal row alone would not stop a send —
        `claim_notification` selects on ``status='pending'`` and the suppression table only ever
        *unblocks* its head-of-queue clause. That is the reason this module writes the trio and not the
        note, and this is the test that would fail if it wrote only the note.
        """
        self.declare()
        at = NOW + dt.timedelta(minutes=1)
        round_ = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        self.assertTrue(round_['suppressed'])
        self.assertIsNone(self.store.claim_notification(now=at + dt.timedelta(seconds=1)))

    def test_suppress_delivery_refuses_to_rewrite_a_row_that_is_no_longer_queued(self):
        """A send already leased is the delivery rail's decision; a second reason must not edit it.

        Returns False and writes nothing — no refusal row, no audit line — so the attempt cannot
        retroactively claim a page that was actually made.
        """
        at = NOW + dt.timedelta(minutes=1)
        round_ = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        claim = self.store.claim_notification(now=at)
        self.assertEqual(claim['id'], round_['delivery'])
        reason = 'maintenance-window x for resource y covers this finding'
        self.assertFalse(suppression.suppress_delivery(self.store, round_['delivery'], reason,
                                                      cause='maintenance-window', now=at))
        self.assertEqual(self.raw('SELECT outbox_id FROM notification_suppressions'), [])
        self.assertEqual(self.audit('notification.suppressed'), [])
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?',
                                  (round_['delivery'],))[0]['status'], 'sending')
        with self.assertRaisesRegex(StateError, 'Unknown suppression cause'):
            suppression.suppress_delivery(self.store, round_['delivery'], reason, cause='because-i-said',
                                          now=at)
        with self.assertRaisesRegex(StateError, 'one printable bounded line'):
            suppression.suppress_delivery(self.store, round_['delivery'], 'x' * 401, cause='flapping',
                                          now=at)

    # --- restart and migration ---------------------------------------------------------------

    def test_a_reopened_store_applies_the_same_window_with_the_same_sentence(self):
        """Restart invariance, on the window half: the declaration is a row, not an object.

        The reason string is compared and not just the boolean, because the reason carries the window
        id, its end and its author — if any of those were reconstructed differently after a restart, the
        operator would read a different explanation for the same silence.
        """
        self.declare()
        at = NOW + dt.timedelta(minutes=1)
        before = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        reopened = Store(self.root / 'windows.db')
        after = suppression.decide(reopened, self.verdict('firing', at), now=at)
        self.assertEqual(after.reason, before['decision'].reason)
        self.assertTrue(after.suppressed)
        self.assertEqual(after.cause, 'maintenance-window')
        self.assertEqual(suppression.live_windows(reopened, now=at)['count'], 1)

    def test_a_v3_database_migrates_before_accepting_maintenance_windows(self):
        """A v3 file reaches the current schema before declaring and applying a maintenance window."""
        self.assertEqual(sorted(state.MIGRATIONS), list(range(1, state.VERSION + 1)))
        self.assertEqual(state.MIGRATIONS[5], state.MAINTENANCE_WINDOW_SCHEMA)
        path = self.root / 'v3.db'
        with mock.patch.object(state, 'MIGRATIONS', {number: state.MIGRATIONS[number] for number in
                                                     range(1, 4)}), \
                mock.patch.object(state, 'VERSION', 3):
            old = Store(path)
        old.intake(self.verdict('firing', NOW), PRODUCER, now=NOW)
        moved = Store(path, migrate=True)
        self.assertEqual(moved.migrated_from, 3, 'the run starts where the file stopped, not at its end')
        with closing(sqlite3.connect(path)) as db:
            self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], state.VERSION)
            self.assertEqual(db.execute('SELECT count(*) FROM incidents').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT count(*) FROM outbox').fetchone()[0], 1)
        # And the new state works on the migrated file, which is what the step was ever for. A different
        # rule is filed because the v3 half already holds an open incident on the first one, and a second
        # firing on an open condition books no send to fold.
        suppression.declare_window(moved, self.declaration(), HUMAN, now=NOW)
        self.assertTrue(suppression.file_event(moved, self.verdict('firing', NOW + dt.timedelta(minutes=1),
                                                                  rule='post-migration'),
                                               PRODUCER,
                                               now=NOW + dt.timedelta(minutes=1))['suppressed'])

    def test_this_feature_adds_no_table_and_the_pinned_table_set_stays_whole(self):
        """The pin `tests/test_state_migration.py` holds, asserted from here as an unchanged set.

        Two files name the table list and that is deliberate: the one is the mechanism's pin, and this one
        is the feature's — but where a typed table would have *extended* the pin, this feature claims not
        to touch it. `CURRENT_TABLES` is imported from the pinning file rather than copied, so the
        assertion below fails the moment anyone adds a table here and leaves the pin behind (or the
        other way round).
        """
        tables = state_tables(self.store)
        self.assertNotIn('maintenance_windows', tables)
        self.assertEqual(tables, CURRENT_TABLES,
                         'a window is a key in `notification_control`; a new table belongs in a commit '
                         'that moves the three schema pins with it, which is not this one')


def plant_window(store: Store, name: str, *, start: dt.datetime, end: dt.datetime,
                 reason: str = 'work', attest: bool = True) -> str:
    """Write one window control row straight into `store`, past every validation in the module.

    These are the rows a restore, a copy or a wider build leaves behind: `declare_window` would never
    write them, which is the point, and the read path is the last thing standing between them and a quiet
    night. With `attest` the matching `maintenance.declared` audit row is written first and its sequence
    stored, so the only thing that can refuse the row is its shape or its bound — an unattested row is a
    different refusal, tested by name.
    """
    declared = {'id': str(uuid.uuid5(uuid.NAMESPACE_DNS, f'fixture-window/{name}')),
                'resource_id': RESOURCE, 'rule_id': None, 'starts_at': utc_text(start),
                'ends_at': utc_text(end), 'reason': reason, 'author': 'operator',
                'declared_at': utc_text(NOW)}
    document = {'schema_version': suppression.WINDOW_DOCUMENT_VERSION, 'declared': declared,
                'revoked': None,
                # An unattested row still names a sequence: "no attestation field at all" is a malformed
                # document and lands in `unusable`, which is a different refusal from one whose
                # attestation names an audit row that does not exist. This number is past anything the
                # databases below reach.
                'attest': 999_999}
    with store.transaction() as connection:
        if attest:
            connection.execute('INSERT INTO audit(at,actor,operation,subject,detail) VALUES (?,?,?,?,?)',
                               (utc_text(NOW), 'operator', 'maintenance.declared', declared['id'],
                                canonical(declared)))
            document['attest'] = int(connection.execute('SELECT last_insert_rowid()').fetchone()[0])
        connection.execute('INSERT INTO notification_control(key,value,updated_at) VALUES (?,?,?)',
                           (state.maintenance_key(declared['id']), canonical(document), utc_text(NOW)))
    return declared['id']


def state_tables(store: Store) -> set[str]:
    """Every table in `store`'s file, for the set comparison above."""
    with closing(sqlite3.connect(store.path)) as db:
        return {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


class UntrustedWindowRowsTests(unittest.TestCase):
    """The ways the live set stops being safe to act on, none of which may silence a pager.

    All of them need rows that `declare_window` would never write, which is the point: they arrive by a
    restore, a copy, or a build whose bound was wider, and the read path is the only thing left standing
    between them and a quiet night. Each is counted in the field that names why (`unusable`,
    `unattested`, `bound_exceeded`) rather than dropped, because a store the module cannot fully read is a
    fact an operator is owed.
    """

    def setUp(self):
        """A store and the raw-write helper, so the rows below bypass the declaration path."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'rows.db')

    def test_more_live_windows_than_the_bound_are_applied_none_of(self):
        """Past `MAX_LIVE_WINDOWS` the module cannot claim it saw the covering row, so it applies none."""
        for step in range(suppression.MAX_LIVE_WINDOWS + 1):
            plant_window(self.store, str(step), start=NOW - dt.timedelta(minutes=step),
                         end=NOW + dt.timedelta(minutes=30))
        answer = suppression.live_windows(self.store, now=NOW)
        self.assertTrue(answer['bound_exceeded'])
        self.assertIsNone(suppression.covering_window(self.store, self.verdict('firing', NOW), now=NOW))
        self.assertFalse(suppression.decide(self.store, self.verdict('firing', NOW),
                                            now=NOW).suppressed)
        self.assertTrue(suppression.stats(self.store, now=NOW)['windows']['bound_exceeded'])

    def test_a_row_whose_span_breaches_the_bound_is_reported_and_never_applied(self):
        """A wider build's file, restored here: the read re-checks what no CHECK guarantees.

        The row is attested — a human really did declare a week of silence, somewhere — and it is legal
        where it came from. Applying it here would keep a promise this build never made, so `live_windows`
        drops it into `unusable` and the finding pages.
        """
        plant_window(self.store, 'wide', start=NOW, end=NOW + dt.timedelta(days=7),
                     reason='a week of silence')
        answer = suppression.live_windows(self.store, now=NOW + dt.timedelta(hours=1))
        self.assertEqual((answer['count'], answer['unusable'], answer['unattested']), (0, 1, 0))
        self.assertIsNone(suppression.covering_window(self.store, self.verdict('firing', NOW), now=NOW))
        self.assertFalse(suppression.decide(self.store, self.verdict('firing', NOW),
                                            now=NOW).suppressed)
        self.assertEqual(suppression.stats(self.store, now=NOW)['windows']['unusable'], 1)

    def verdict(self, status: str, at: dt.datetime) -> dict:
        """One canonical event on the shared resource (the same helper the tests above use)."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, RESOURCE, RULE, 'availability', status, window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')


class WindowReadTests(unittest.TestCase):
    """The read surface and the CLI, both of which must answer without writing."""

    def setUp(self):
        """One store with three windows: one covering, one expired, one revoked."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'read.db')
        self.covering = suppression.declare_window(self.store, self.document(
            'covering', NOW - dt.timedelta(hours=1), NOW + dt.timedelta(hours=1)), HUMAN, now=NOW)
        self.expired = suppression.declare_window(self.store, self.document(
            'expired', NOW - dt.timedelta(hours=6), NOW - dt.timedelta(hours=2)), HUMAN,
            now=NOW - dt.timedelta(hours=5))
        self.revoked = suppression.declare_window(self.store, self.document(
            'revoked', NOW - dt.timedelta(hours=1), NOW + dt.timedelta(hours=1)), HUMAN, now=NOW)
        suppression.revoke_window(self.store, self.revoked['id'], HUMAN, now=NOW)

    @staticmethod
    def document(reason: str, start: dt.datetime, end: dt.datetime) -> dict:
        """One resource-scoped window declaration."""
        return {'resource_id': RESOURCE, 'starts_at': utc_text(start), 'ends_at': utc_text(end),
                'reason': reason}

    def test_live_windows_lists_only_unrevoked_and_unexpired_rows_in_a_stable_order(self):
        """Expired and revoked are different facts and neither is listed; the order is not insertion order."""
        answer = suppression.live_windows(self.store, now=NOW)
        self.assertEqual([window['reason'] for window in answer['windows']], ['covering'])
        self.assertEqual(answer['count'], 1)
        self.assertFalse(answer['bound_exceeded'])
        self.assertEqual(answer['unusable'], 0)
        self.assertEqual(answer['max_seconds'], suppression.MAX_WINDOW_SECONDS)
        self.assertTrue(answer['windows'][0]['covers_now'])
        stats = suppression.stats(self.store, now=NOW)
        # Every window number here counts *candidates*: the rows schema v5's index offered this read,
        # i.e. declared, unrevoked and not yet expired. The expired and revoked rows are never fetched,
        # so they are neither scanned nor counted; `tests/test_maintenance_history.py` pins that.
        self.assertEqual(stats['windows'], {'declared': 1, 'live': 1, 'revoked': 0, 'expired': 0,
                                            'unusable': 0, 'unattested': 0, 'bound_exceeded': False,
                                            'max_seconds': suppression.MAX_WINDOW_SECONDS,
                                            'max_live_windows': suppression.MAX_LIVE_WINDOWS,
                                            'max_rows': suppression.MAX_WINDOW_ROWS})

    def main(self, *argv: str) -> tuple[int, dict]:
        """Run this module's entry point in process, and return its exit code and its stdout object."""
        buffer = StringIO()
        with redirect_stdout(buffer), mock.patch.object(sys, 'argv', ['suppression', *argv]):
            code = suppression.main()
        return code, json.loads(buffer.getvalue())

    def test_the_entry_point_answers_all_three_reads_and_files_nothing(self):
        """`python -m local_observe.platform.suppression`: the CLI this item ships instead of a subcommand.

        Every state assertion here is a *count*: the read surface must not be able to write, because the
        one thing that would make a window from a command line is a `Actor(identity, 'human')` built out
        of nothing but a flag.
        """
        before = (len(self.raw('SELECT id FROM events')), len(self.raw('SELECT sequence FROM audit')))
        code, stats = self.main('--database', str(self.store.path), 'stats')
        self.assertEqual(code, 0)
        self.assertEqual(stats['suppressed_by_cause'], {'maintenance-window': 0, 'dependency': 0,
                                                        'flapping': 0, 'other': 0})
        code, listed = self.main('--database', str(self.store.path), 'windows',
                                 '--now', utc_text(NOW))
        self.assertEqual([window['reason'] for window in listed['windows']], ['covering'])
        at = NOW + dt.timedelta(minutes=30)
        code, answer = self.main('--database', str(self.store.path), 'inspect', '--event',
                                 self.write_event('firing', at), '--now', utc_text(at))
        self.assertEqual(code, 0)
        self.assertTrue(answer['suppressed'])
        self.assertEqual(answer['cause'], 'maintenance-window')
        self.assertEqual((len(self.raw('SELECT id FROM events')), len(self.raw('SELECT sequence FROM audit'))),
                         before)

    def test_the_entry_point_answers_a_bad_request_with_one_json_line_and_a_nonzero_exit(self):
        """The `lo-platform` contract, kept: a machine-readable line, no traceback, and no echo."""
        missing = self.root / 'not-here.json'
        code, body = self.main('--database', str(self.store.path), 'inspect', '--event', str(missing))
        self.assertEqual(code, 1)
        self.assertEqual(sorted(body), ['error_type', 'status'])
        code, body = self.main('--database', str(self.store.path), 'inspect', '--event',
                               self.write_event('not-a-status', NOW))
        self.assertEqual((code, body['error_type']), (1, 'StateError'))
        code, body = self.main('--database', str(self.store.path), 'stats', '--flap-threshold', '1')
        self.assertEqual((code, body['error_type']), (1, 'StateError'))

    def write_event(self, status: str, at: dt.datetime) -> str:
        """Write one canonical event to a scratch file and return its path, for `--event`."""
        path = self.root / f'event-{len(list(self.root.glob("event-*.json")))}.json'
        path.write_text(json.dumps(self.event(status, at)))
        return str(path)

    @staticmethod
    def event(status: str, at: dt.datetime) -> dict:
        """One canonical event on the shared resource."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, RESOURCE, RULE, 'availability', status, window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')

    def raw(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()


if __name__ == '__main__':
    unittest.main()

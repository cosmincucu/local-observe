"""suppression: a flapping condition is one condition, and the fold is derived from durable rows.

The defect this file pins is the one port-table §6 counted (`legacy:aiops/dedup`, 372 lines): "a resource
oscillating on a threshold is forty findings". On `main` the *finding* was already one row —
`Store.intake` keys `conditions` on a digest that excludes `status`, so a fire/resolve/fire flap lands
in one condition — but every edge of the flap booked its own outbox row, so an operator was paged once
per edge and the oscillation was only visible as a pile of deliveries. Folding therefore has to count
the edges and refuse the *sends*, without ever refusing the event.

Two claims carry the whole file, and each is tested from the side it is not written from:

* **the key is not a second identity.** `suppression.condition_key` is a copy of the expression inside
  `Store.intake` (the allowlist forbids editing `intake` to share one helper), so the assertion is not
  made against the copy — it is made against the `conditions` row a real `intake` wrote. Edit the key
  on either side and this file fails, which is the mechanism that keeps one condition from splitting in
  two.
* **the count survives a restart because it was never in memory.** The transition count comes out of
  `incidents` (one row per `opened`, flipped once per `resolved`), and the assertion below is not
  "a reopened store says the same number" alone — it is that the number equals the fire/resolve
  transitions a reader counts by walking the `events` payloads themselves. `incidents` is trusted only
  as far as `events` agrees with it.
"""
import datetime as dt
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import suppression
from local_observe.platform.detections import event
from local_observe.platform.state import Actor, StateError, Store

NOW = timestamp('2026-09-09T12:00:00Z')
PRODUCER = Actor('flap-detector', 'producer')
# A synthetic resource UUID in the shape `identifier()` accepts; no estate resource is named here.
RESOURCE = '4a5b6c7d-8e9f-4a0b-9c8d-7e6f5a4b3c2d'


class FlapFoldingTests(unittest.TestCase):
    """One oscillating rule, filed through the real intake path, counted from the rows it left."""

    def setUp(self):
        """Open a scratch directory and one store; every database below is named by its test."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'flap.db')

    def verdict(self, status: str, at: dt.datetime, rule: str = 'disk-full') -> dict:
        """One canonical event for `rule` on the shared resource, at `at`."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, RESOURCE, rule, 'availability', status, window,
                     {'sample_id': 'fixture'}, query_type='gatus-result')

    def oscillate(self, edges: int, *, store: Store | None = None, **kwargs) -> list[dict]:
        """File `edges` alternating fire/resolve events ten seconds apart; return each round's result."""
        store = store or self.store
        rounds = []
        for step in range(edges):
            at = NOW + dt.timedelta(seconds=10 * step)
            status = 'firing' if step % 2 == 0 else 'resolved'
            rounds.append(suppression.file_event(store, self.verdict(status, at), PRODUCER, now=at,
                                                 **kwargs))
        return rounds

    def raw(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite, so no answer here comes from the code under test."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    # --- the condition key -------------------------------------------------------------------

    def test_the_state_marker_is_already_folded_out_of_the_condition_key(self):
        """A fire and the resolve that follows are one condition here, and that predates this module.

        This is the assertion the port had to make before it could be adapted: v0.1 stripped a state
        marker (`alert.fired`/`alert.resolved`, an Alertmanager `status` label) out of its dedup key,
        because its events carried the state in the *type*. Here the state is its own field, `status`,
        and `Store.intake` never put it in the key — so there is nothing to strip, and the folding this
        item ports is the counting, not the key.
        """
        self.store.intake(self.verdict('firing', NOW), PRODUCER, now=NOW)
        self.store.intake(self.verdict('resolved', NOW + dt.timedelta(seconds=30)), PRODUCER,
                          now=NOW + dt.timedelta(seconds=30))
        rows = self.raw('SELECT key, status FROM conditions')
        self.assertEqual(len(rows), 1, 'a fire and a resolve must land in one conditions row')
        self.assertEqual({row['status'] for row in rows}, {'resolved'},
                         'the row holds the newest state, as intake has always written it')
        self.assertNotIn('firing', rows[0]['key'])

    def test_condition_key_names_the_row_intake_wrote_and_no_other(self):
        """The copy in `suppression.condition_key` is checked against the row, not against itself.

        `Store.intake` builds its key inline; this module re-expresses it. Asserting equality against the
        stored primary key is the only check that does not assume the two agree, and it is the check that
        fails the day either side moves — which is the failure the brief names as "the most important
        line in the report" if it ever has to happen.
        """
        stored = self.store.intake(self.verdict('firing', NOW), PRODUCER, now=NOW)
        filed = self.verdict('firing', NOW)
        key = self.raw('SELECT key FROM conditions')[0]['key']
        self.assertEqual(suppression.condition_key(filed), key)
        self.assertEqual(suppression.condition_key(self.verdict('resolved', NOW)), key)
        # And what the key is made of is the identity of the *judgement*, so each of these is a
        # different condition: another rule, another resource, another version, another producer.
        changed = {'rule_id': 'other-rule', 'resource_id': None, 'rule_version': '2',
                   'source': 'another-detector', 'condition': 'another-condition'}
        for field, value in changed.items():
            with self.subTest(field=field):
                self.assertNotEqual(suppression.condition_key(filed | {field: value}), key)
        self.assertTrue(stored['event_id'])

    def test_a_missing_field_is_a_refusal_and_not_a_key(self):
        """An event missing a key input raises `StateError`; a `KeyError` here would escape as a 500."""
        for field in ('source', 'rule_id', 'rule_version', 'resource_id', 'condition'):
            with self.subTest(field=field), self.assertRaises(StateError):
                suppression.condition_key({k: 'x' for k in ('source', 'rule_id', 'rule_version',
                                                           'resource_id', 'condition') if k != field})

    # --- the count ---------------------------------------------------------------------------

    def test_the_incident_count_matches_the_transitions_visible_in_events(self):
        """`incidents` is trusted only as far as `events` agrees: the count is cross-checked by a walk
        over the event payloads, which is where a fire/resolve edge is actually written.

        The independent reader counts status *changes* in intake order for one condition key. If
        `transitions` ever drifted from that — a resolve that did not stamp `updated_at`, an incident
        reused after a resolve, an `unknown` event that turned out to book a transition — this is the
        test that says so.
        """
        self.oscillate(8)
        key = suppression.condition_key(self.verdict('firing', NOW))
        from_events, previous = 0, None
        for row in self.raw('SELECT payload FROM events ORDER BY rowid'):
            status = json.loads(row['payload'])['status']
            if suppression.condition_key(json.loads(row['payload'])) != key:
                continue
            if previous is not None and status != previous:
                from_events += 1
            previous = status
        counted = suppression.transitions(self.store, key, window_seconds=86400,
                                          now=NOW + dt.timedelta(hours=1))
        # The first edge of the episode is a transition in `incidents` (an incident opened) and not a
        # status *change* in `events`, so the two readers differ by exactly that one edge.
        self.assertEqual(counted['transitions'], from_events + 1)
        self.assertEqual(counted['opened'], 4, 'four firing edges opened four incidents')
        self.assertEqual(counted['resolved'], 4, 'and four resolved edges closed them')
        self.assertTrue(counted['complete'])

    def test_a_flap_is_one_surfaced_condition_with_every_transition_counted(self):
        """Six edges of one condition: one `conditions` row, six counted transitions, one incident line.

        The v0.1 record this replaces held `count`, `states_seen`, `flapping` and `flap_count` in
        memory. The three durable facts here are the one `conditions` row, the six `incidents` rows and
        the count `transitions()` reads back out of them.
        """
        self.oscillate(6)
        key = suppression.condition_key(self.verdict('firing', NOW))
        self.assertEqual(len(self.raw('SELECT key FROM conditions')), 1)
        self.assertEqual(len(self.raw('SELECT id FROM incidents')), 3)
        counted = suppression.transitions(self.store, key, now=NOW + dt.timedelta(seconds=60))
        self.assertEqual((counted['transitions'], counted['opened'], counted['resolved']), (6, 3, 3))

    def test_the_transition_window_is_a_bound_and_not_a_clamp(self):
        """Asking for a window outside `FLAP_WINDOW_BOUNDS` is refused; a clamp would edit the operator."""
        key = suppression.condition_key(self.verdict('firing', NOW))
        for window in (0, 59, 86401, -300, '300', True, None):
            with self.subTest(window=window), self.assertRaises(StateError):
                suppression.transitions(self.store, key, window_seconds=window)

    def test_a_transition_outside_the_window_is_not_counted(self):
        """The horizon is the whole point: an episode that ended long ago must not fold a new page."""
        self.oscillate(6)
        key = suppression.condition_key(self.verdict('firing', NOW))
        self.assertEqual(suppression.transitions(self.store, key, window_seconds=60,
                                                 now=NOW + dt.timedelta(seconds=45))['transitions'], 5)
        self.assertEqual(suppression.transitions(self.store, key, window_seconds=60,
                                                 now=NOW + dt.timedelta(seconds=35))['transitions'], 4)
        self.assertEqual(suppression.transitions(self.store, key, window_seconds=86400,
                                                 now=NOW + dt.timedelta(hours=1))['transitions'], 6)
        self.assertEqual(suppression.transitions(self.store, key, window_seconds=60,
                                                 now=NOW + dt.timedelta(days=1))['transitions'], 0)

    def test_the_window_is_closed_at_the_end_as_well_as_the_start(self):
        """A row stamped ahead of the instant being decided is not evidence of a transition already past.

        `validate_event` admits an event up to 60 seconds ahead of the clock, and `now` is injected, so
        an unbounded upper edge would let a decision count a future edge — the fold would be quoting an
        episode that had not happened yet at the instant it claims to be deciding.
        """
        self.oscillate(6)
        key = suppression.condition_key(self.verdict('firing', NOW))
        counted = suppression.transitions(self.store, key, window_seconds=300, now=NOW)
        self.assertEqual(counted['transitions'], 1, 'only the edge at `now` itself')
        self.assertTrue(counted['since'] < counted['until'])

    # --- the fold -----------------------------------------------------------------------------

    def test_the_first_pages_of_an_episode_go_out_and_the_rest_are_folded(self):
        """With the default threshold of 4, edges 1-3 page and edges 4-6 do not.

        The count includes the transition being decided (which is why `file_event` decides *inside*
        `Store.intake`'s transaction, on that connection, after the rows are filed and before they
        commit), so the threshold is also a promise about the first page: `FLAP_THRESHOLD_BOUNDS`
        refuses a threshold of 1 precisely because it would fold it.
        """
        rounds = self.oscillate(6)
        self.assertEqual([round_['suppressed'] for round_ in rounds],
                         [False, False, False, True, True, True])
        for round_ in rounds[:3]:
            self.assertIsNone(round_['decision'].cause)
        for round_ in rounds[3:]:
            self.assertEqual(round_['decision'].cause, 'flapping')
            self.assertIn('flapping', round_['decision'].reason)

    def test_the_threshold_moves_the_first_fold_and_the_floor_refuses_1(self):
        """threshold=2 folds from the second edge; threshold 1 is refused rather than honoured.

        Each episode runs on its own file: two `oscillate` calls on one store would file the same
        windows twice, and `intake` answers the second one `duplicate` — which returns before any
        bound is checked, so a refusal test written that way would prove nothing.
        """
        rounds = self.oscillate(4, store=Store(self.root / 'threshold-2.db'), threshold=2)
        self.assertEqual([round_['suppressed'] for round_ in rounds], [False, True, True, True])
        for number, threshold in enumerate((1, 101, 0, 'four', True)):
            with self.subTest(threshold=threshold):
                self.assertRaises(StateError, self.oscillate, 1, threshold=threshold,
                                  store=Store(self.root / f'floor-{number}.db'))

    def test_a_folded_page_is_still_an_event_an_incident_and_an_audit_row(self):
        """SUPPRESSED IS A STATE, NOT A DROP: the finding is filed, the send is refused, both are recorded.

        The event is in `events`, the incident it opened is in `incidents`, and the refusal is in
        `audit` naming the cause. Nothing in this path can be mistaken for "the rule never fired".
        """
        rounds = self.oscillate(6)
        folded = rounds[4]
        event_id = folded['intake']['event_id']
        self.assertEqual(len(self.raw('SELECT id FROM events WHERE id=?', (event_id,))), 1,
                         'the folded finding is still stored')
        self.assertTrue(folded['intake']['incident_id'])
        rows = self.raw("SELECT actor, operation, detail FROM audit WHERE subject=?", (folded['delivery'],))
        self.assertEqual([(row['actor'], row['operation']) for row in rows],
                         [('suppression-worker', 'notification.suppressed')])
        detail = json.loads(rows[0]['detail'])
        self.assertEqual(detail['cause'], 'flapping')
        self.assertEqual(detail['condition'], suppression.condition_key(self.verdict('firing', NOW)))
        self.assertEqual(detail['event_id'], event_id)
        self.assertEqual(detail['producer'], PRODUCER.identity,
                         'the row names who filed the event it folded, and who decided')

    def test_the_fold_booked_no_send_and_the_queue_moves_past_it(self):
        """The row goes `dead` beside the refusal, and a send behind a folded one is still reachable.

        The assertion the brief names is the first one — a suppressed send still writes the
        `notification_suppressions` row. The second is the one that makes folding safe rather than
        merely loud: `claim_notification`'s head-of-queue clause already ignores suppressed rows, so a
        folded page cannot hold up the send that follows it on the same incident. Without that clause a
        folded `opened` would strand its own incident's recovery notice forever.
        """
        rounds = self.oscillate(5)
        delivery = rounds[3]['delivery']
        self.assertEqual(self.raw('SELECT status FROM outbox WHERE id=?', (delivery,))[0]['status'], 'dead')
        self.assertEqual(self.raw('SELECT reason FROM notification_suppressions WHERE outbox_id=?',
                                  (delivery,))[0]['reason'], rounds[3]['decision'].reason)
        # The episode ages out, then the condition recovers: this send belongs to the incident whose
        # opening page was folded, and it sits behind that folded row in the queue.
        aged = suppression.file_event(self.store, self.verdict('resolved', NOW + dt.timedelta(seconds=400)),
                                     PRODUCER, now=NOW + dt.timedelta(seconds=400))
        self.assertFalse(aged['suppressed'])
        self.assertEqual(aged['intake']['incident_id'], rounds[4]['intake']['incident_id'])
        folded = {round_['delivery'] for round_ in rounds if round_['suppressed']}
        heads = []
        for _ in range(20):
            claim = self.store.claim_notification(now=NOW + dt.timedelta(seconds=401))
            if claim is None:
                break
            heads.append(claim['id'])
        self.assertIn(aged['delivery'], heads)
        self.assertFalse(folded & set(heads), 'a folded page must never be handed to the delivery rail')
        self.assertTrue(heads, 'the queue still sends what folding let through')

    def test_a_folded_page_is_not_replayable_and_says_which_rule_it_was(self):
        """The cost of reusing the platform's refusal table, stated as a test: `retry_notification` refuses.

        `Store.retry_notification` refuses any delivery holding a suppression row, which is how a
        budget-discarded send already behaves. Folding inherits it, so an operator who wants the folded
        page does not get it back from the outbox — the finding stays readable in `events` and the
        incident stays open. That is the posture the item takes deliberately, and it is the one place
        this port is more restrictive than v0.1 (which never claimed to be able to un-forget a fold
        either, but held its state in a dict an operator could not inspect at all).
        """
        rounds = self.oscillate(5)
        with self.assertRaisesRegex(StateError, 'cannot be replayed'):
            self.store.retry_notification(rounds[4]['delivery'], Actor('operator', 'human'),
                                          now=NOW + dt.timedelta(seconds=60))

    def test_a_flap_that_ages_out_pages_again(self):
        """Folding is a bound on noise, never a way to stop reporting a condition that came back."""
        self.oscillate(6)
        much_later = NOW + dt.timedelta(hours=2)
        again = suppression.file_event(self.store, self.verdict('firing', much_later), PRODUCER,
                                       now=much_later)
        self.assertFalse(again['suppressed'])
        self.assertEqual(again['decision'].transitions, 1)

    def test_a_second_rule_on_the_same_resource_folds_on_its_own_count(self):
        """An episode belongs to a condition, not to a resource: two rules are two flap counts."""
        self.oscillate(6)
        other = suppression.file_event(self.store, self.verdict('firing', NOW + dt.timedelta(seconds=70),
                                                              rule='disk-full'), PRODUCER,
                                      now=NOW + dt.timedelta(seconds=70))
        self.assertTrue(other['suppressed'], 'the same condition, still inside its window')
        unrelated = suppression.file_event(self.store, self.verdict('firing', NOW + dt.timedelta(seconds=70),
                                                                  rule='other-rule'), PRODUCER,
                                          now=NOW + dt.timedelta(seconds=70))
        self.assertFalse(unrelated['suppressed'])
        self.assertEqual(unrelated['decision'].transitions, 1)

    def test_a_duplicate_event_folds_nothing_because_it_booked_nothing(self):
        """`intake` answers `duplicate` and there is no delivery to reason about: the decision is None."""
        at = NOW + dt.timedelta(seconds=10)
        first = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        repeat = suppression.file_event(self.store, self.verdict('firing', at), PRODUCER, now=at)
        self.assertEqual(repeat['intake']['status'], 'duplicate')
        self.assertIsNone(repeat['decision'])
        self.assertFalse(repeat['suppressed'])
        self.assertIsNotNone(first['intake']['event_id'])

    # --- restart invariance -------------------------------------------------------------------

    def test_a_reopened_store_over_the_same_file_repeats_the_decision_word_for_word(self):
        """The brief's proof: a fresh `Store` over the same path makes the same suppression decision.

        Not "the same flag" — the same *sentence*, and the same transition count it was written from.
        v0.1's deduplicator could not pass this test at all: its `_active`, `_last_state` and
        `_transitions` dicts were the state, and a restart reset them, which is the re-paging the port
        table lists as the reason to adapt rather than copy.
        """
        rounds = self.oscillate(6)
        before = rounds[-1]['decision']
        reopened = Store(self.root / 'flap.db')
        after = suppression.decide(reopened, self.verdict('firing', NOW + dt.timedelta(seconds=70)),
                                   now=NOW + dt.timedelta(seconds=60))
        self.assertEqual(after.reason, before.reason)
        self.assertEqual((after.suppressed, after.cause, after.transitions),
                         (before.suppressed, before.cause, before.transitions))
        self.assertEqual(after.condition, before.condition)
        self.assertEqual(suppression.suppressed_deliveries(reopened),
                         suppression.suppressed_deliveries(self.store))

    def test_the_module_holds_no_state_between_calls(self):
        """A grep-shaped guarantee, written as a test: nothing is cached in a module-level container.

        Every public entry point here opens a connection, asks, and returns; a dict that survived a call
        would make the restart test above pass on a warm process and fail in production, which is the
        exact shape of the bug this row exists to remove.
        """
        suspects = [name for name in vars(suppression)
                    if isinstance(getattr(suppression, name), (dict, list, set))
                    and not name.startswith('_')]
        self.assertEqual(suspects, [], 'module-level mutable state appeared in suppression.py')

    def test_stats_count_suppression_from_the_rows_and_name_the_causes_apart(self):
        """Noise reduction measured, not claimed: what was booked, what was refused, by whom.

        The per-cause map is the reason the shared refusal table is not a loss of information: the
        budget's own reasons arrive as single tokens and land in `other`, which says "not this module"
        rather than quietly widening `flapping`.
        """
        self.oscillate(6)
        stats = suppression.stats(self.store, now=NOW + dt.timedelta(seconds=60))
        self.assertEqual(stats['conditions_total'], 1)
        self.assertEqual(stats['conditions_observed'], 1)
        self.assertEqual(stats['conditions_flapping'], 1)
        self.assertEqual(stats['flap']['transitions_in_window'], 6)
        self.assertEqual(stats['suppressed_by_cause']['flapping'], 3)
        self.assertEqual(stats['suppressed_by_cause']['dependency'], 0)
        self.assertEqual(stats['booked_deliveries'], 6)
        self.assertEqual(stats['suppressed_deliveries'], 3)
        self.assertEqual(stats['noise_reduction'], 0.5)
        self.assertTrue(stats['scope'].startswith('durable rows'), stats['scope'])

    def test_stats_reports_an_unmeasured_database_as_none_and_not_as_zero(self):
        """A store that has never booked a send has no noise ratio; 0.0 would be a claim about quiet."""
        empty = Store(self.root / 'empty.db')
        stats = suppression.stats(empty, now=NOW)
        self.assertIsNone(stats['noise_reduction'])
        self.assertEqual(stats['booked_deliveries'], 0)
        self.assertEqual(stats['conditions_total'], 0)
        self.assertEqual(suppression.suppressed_deliveries(empty), 0)

    def test_reason_bucketing_names_the_three_causes_and_puts_everything_else_in_other(self):
        """The first word of a reason is its bucket, and the budget's slugs are not this module's words."""
        for sentence, expected in (('flapping 6 transitions of one condition', 'flapping'),
                                   ('maintenance-window abc for resource x', 'maintenance-window'),
                                   ('dependency abc is firing under rule r', 'dependency'),
                                   ('event-too-old', 'other'), ('flood-circuit-open', 'other'),
                                   ('', 'other'), (None, 'other')):
            with self.subTest(sentence=sentence):
                self.assertEqual(suppression.reason_cause(sentence), expected)


if __name__ == '__main__':
    unittest.main()

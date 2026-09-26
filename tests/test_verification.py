"""remediation invariants: the three verdicts of post-action verification, and the refusals that keep them honest.

`local_observe/platform/verification.py` answers one question — did the signal that paged for this
action stop firing? — with exactly `cleared`, `not_cleared` or `unknown`. The tests below exist to pin
the two ways that answer can go wrong:

* **an optimistic `unknown`** — treating "we could not tell" as "it recovered". So every way a read can
  fail to give a usable answer is asserted to land on `unknown` and never on `cleared`; and
* **an accidental `unknown`** — a check that shrugs when the data was perfectly good, which would read
  as health. So a matrix of supported comparisons over clearly-satisfied and clearly-violating values
  is asserted to produce a real verdict every time.

Between them those two claims need the sharper one: **`unknown` is not reachable by accident.**
`test_every_unknown_names_a_documented_reason_and_every_reason_is_reachable` asserts
`verification.UNVERIFIABLE_REASONS` in both directions — every `unknown` produced names one of the
twelve, and each of the twelve is reachable by a listed input — and `_unknown()` raises for a reason
outside the set, so a thirteenth path cannot be added quietly.

The second group of tests is the adversarial one. Every case in it answered `cleared` (or raised) in
the first draft of this unit, found by reviewing the public `check()` surface against evidence that had
nothing to do with the alert: a sample of another resource, a sample of another series, a truncated
page, a stale window, and inputs that crashed the verdict function instead of refusing. Those cases are
tests now, in `FalseClearanceTests`. The reviewer's correction pass found two more of the same kind — a
receipt that carried none of the `artifact_sha256` the origin pinned, and a reused receipt allowed to
name the instant it was judged at, which let a nine-month-old page certify its own freshness — and both
are pinned here too (`test_a_receipt_that_does_not_carry_the_pinned_artifact_is_not_the_pinned_read`,
`ClockTests`). Nothing about those two was fixed by loosening prose: each is a case that used to answer
`cleared`, run against the module before the fix and after it.

The clock is only testable if the code can be told to stop reading it, so the unit keeps one named seam
(`verification._now`) and `ClockTests` patches that: the default clock is asserted, not assumed, and
`test_the_pure_judge_reads_no_clock_at_all` fails loudly if `check()` ever grows a `datetime.now()` call.

Nothing here touches a network or a live store: sampling is injected (the real in-memory backend for
the ordinary paths, `store.client.build_outcome` for receipts that must be exact, and a
read-recording double for the "only the facade is used" invariant), and the clock is a fixed instant.
`Store.put_evidence` is exercised against the real platform database, because the four fields it keeps
are exactly the durability this unit is allowed to claim.
"""
import datetime as dt
import json
import math
from dataclasses import replace
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from local_observe.platform import verification
from local_observe.platform.state import Actor, StateError, Store
from local_observe.store import client as facade
from local_observe.store.backends.memory import InMemoryStore
from local_observe.store.client import LogRecord, MetricSample, ReadOutcome, Window

RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
OTHER = '9f1b2c3a-0d4e-4f5a-8b6c-7d8e9f0a1b2c'
PIN = 'a' * 64
OTHER_PIN = 'b' * 64
NOW = dt.datetime(2026, 9, 8, 10, 5, tzinfo=dt.timezone.utc)
WINDOW_SECONDS = 300
WINDOW = Window(start='2026-09-08T10:00:00Z', end='2026-09-08T10:05:00Z')
INSIDE = '2026-09-08T10:04:00+00:00'
SERIES = 'lo_cpu'
RULE = 'inspect.cpu'
PRODUCER = Actor('verify-worker', 'producer')


def origin(**changes):
    """One verified check, changed only by what the test is about."""
    fields = {'rule_id': RULE, 'resource_id': RESOURCE, 'threshold': 90, 'comparison': 'lt',
              'window_seconds': WINDOW_SECONDS, 'metric_name': SERIES}
    fields.update(changes)
    return verification.Origin(**fields)


def sample(value, *, name=SERIES, resource_id=RESOURCE, at=INSIDE):
    return MetricSample(name=name, value=value, timestamp=at, resource_id=resource_id,
                        labels={'resource_id': resource_id})


def seeded(*rows):
    return InMemoryStore(list(rows))


def answered(rows, *, parameters=None, window=WINDOW, kind='metric-threshold', truncated=False,
             series_exists=None, status=None):
    """A real `ReadOutcome`, built by the facade's own constructor.

    `build_outcome` is what both backends call, so the receipt here carries a real query kind, real
    approved parameters, a real window, a real row count and a real truncation flag — nothing invented
    for the test. `status` overrides only the verdict word, which is how a test produces the
    `unavailable`/`expired` answers the in-memory store will not itself give for a seeded series.
    """
    checked = dict(parameters if parameters is not None else
                   ({'resource_id': RESOURCE, 'rule_id': RULE} if facade.QUERY_KINDS[kind].required else {}))
    rows = list(rows)
    built = facade.build_outcome(facade.QUERY_KINDS[kind], checked, window, rows,
                                 series_exists=bool(rows) if series_exists is None else series_exists)
    receipt = replace(built.receipt, truncated=truncated) if truncated else built.receipt
    if status is None and not truncated:
        return built
    if status not in (None, 'available'):
        # The facade's own rule: a refused read never carries rows, so a test that fakes one must fake
        # the emptiness too.
        return ReadOutcome(status=status, receipt=replace(built.receipt, sample_count=0),
                           detail='test-declared-verdict')
    return ReadOutcome(status=status or built.status, receipt=receipt,
                       samples=built.samples, detail=built.detail)


class VerdictTests(unittest.TestCase):
    """The three answers, each from its own code path, and nothing else reachable."""

    def test_cleared_when_the_newest_sample_of_that_series_is_back_under_the_threshold(self):
        """Proof of `cleared`: the store answered, and the condition that fired no longer holds."""
        result = verification.verify(seeded(sample(42.0)), origin(), now=NOW)
        self.assertEqual(result.state, 'cleared')
        self.assertEqual(result.reason, 'comparison-satisfied')
        self.assertTrue(result.cleared)
        self.assertEqual(result.value, 42.0)
        self.assertEqual(result.samples, 1)
        self.assertTrue(result.answered)
        # The provenance is the store's receipt, not a restatement of the caller's intent.
        self.assertEqual(result.query_type, 'metric-threshold')
        self.assertEqual(dict(result.parameters), {'resource_id': RESOURCE, 'rule_id': RULE})
        self.assertEqual(dict(result.window), {'start': facade.utc_text(WINDOW.instant('start')),
                                               'end': facade.utc_text(WINDOW.instant('end'))})
        # And the verdict says which condition it applied.
        self.assertEqual((result.metric_name, result.threshold, result.comparison), (SERIES, 90, 'lt'))

    def test_not_cleared_when_the_signal_is_still_firing(self):
        """Proof of `not_cleared`: a real answer, not a failure — and the opposite of `cleared`."""
        result = verification.verify(seeded(sample(95.0)), origin(), now=NOW)
        self.assertEqual(result.state, 'not_cleared')
        self.assertEqual(result.reason, 'comparison-failed')
        self.assertFalse(result.cleared)
        self.assertTrue(result.answered)
        self.assertEqual(result.value, 95.0)

    def test_unknown_when_the_store_holds_nothing_for_that_series(self):
        """Proof of `unknown`: absence of data is never read as a recovery."""
        result = verification.verify(seeded(), origin(), now=NOW)
        self.assertEqual(result.state, 'unknown')
        self.assertEqual(result.reason, 'store-unanswered')
        self.assertFalse(result.cleared)
        self.assertFalse(result.answered)

    def test_the_verdict_vocabulary_is_closed(self):
        """Nothing outside the three words is reachable, and nothing raises, whatever is handed in."""
        self.assertEqual(verification.VERDICTS, ('cleared', 'not_cleared', 'unknown'))
        inputs = [None, 42, 10 ** 400, 'hot', [], [sample(1.0)], [sample(float('nan'))], [sample(True)],
                  [MetricSample(name=SERIES, value=1, timestamp='yesterday')],
                  {'value': 1}, object(), sample(1.0),
                  answered([sample(1.0)]), answered([]), answered([sample(1.0)], status='unavailable'),
                  answered([LogRecord(body='booted', timestamp=INSIDE, resource_id=RESOURCE)],
                           kind='log-records', parameters={'resource_id': RESOURCE})]
        for item in inputs:
            for compared in (None, 'lt', 'ne', 'eq'):
                for threshold in (None, 90, float('nan'), 'ninety'):
                    verdict = verification.check(origin(), item, threshold, compared)
                    self.assertIn(verdict.state, verification.VERDICTS, f'{item!r} / {compared}')
                    if verdict.state == 'unknown':
                        self.assertIn(verdict.reason, verification.UNVERIFIABLE_REASONS, str(item))

    def test_supported_reads_are_always_decided_and_never_accidentally_unknown(self):
        """The anti-accident proof: a usable threshold and real samples always produce a verdict.

        Five comparisons x clearly-satisfied and clearly-violating values: every cell answers `cleared`
        or `not_cleared`. If someone later wraps a comparison in `except Exception: return unknown`,
        this fails — which is the point, because a check that shrugs when the data was fine is worse
        than one that refuses, since a shrug reads as health.
        """
        cases = {  # comparison: (satisfied values, violated values)
            'lt': ((1.0, 89.9, 0.0), (90.0, 90.1, 1000.0)),
            'le': ((1.0, 90.0), (90.1, 1000.0)),
            'gt': ((90.1, 1000.0), (90.0, 1.0)),
            'ge': ((90.0, 1000.0), (89.9, 1.0)),
            'eq': ((90.0,), (89.9, 90.1)),
        }
        for comparison, (satisfied, violated) in cases.items():
            for value in satisfied:
                verdict = verification.verify(seeded(sample(value)), origin(comparison=comparison), now=NOW)
                self.assertEqual((value, verdict.state), (value, 'cleared'), comparison)
            for value in violated:
                verdict = verification.verify(seeded(sample(value)), origin(comparison=comparison), now=NOW)
                self.assertEqual((value, verdict.state), (value, 'not_cleared'), comparison)

    def test_every_unknown_names_a_documented_reason_and_every_reason_is_reachable(self):
        """The closed set, in both directions.

        Each row is one way the check cannot know, plus the reason that says which. Equality with
        `UNVERIFIABLE_REASONS` is what makes this a proof rather than a sample: a new `unknown` path
        would have to reuse one of these names (and this test still says which) or appear without a row
        (and this test fails on set inequality), while `_unknown()` refuses to build one that names
        nothing.
        """
        cases = [
            ('selector-missing', lambda: verification.check(origin(metric_name=None), answered([sample(1.0)]))),
            ('threshold-unusable', lambda: verification.check(origin(), answered([sample(1.0)]), float('nan'))),
            ('threshold-unusable', lambda: verification.check(origin(), answered([sample(1.0)]), 'ninety')),
            ('threshold-unusable', lambda: verification.check(origin(), answered([sample(1.0)]), True)),
            ('comparison-unsupported', lambda: verification.check(origin(), answered([sample(1.0)]), 90, 'ne')),
            ('comparison-unsupported', lambda: verification.check(origin(), answered([sample(1.0)]), 90, '')),
            ('sample-missing', lambda: verification.check(origin(), None)),
            ('store-unanswered', lambda: verification.check(origin(), answered([sample(1.0)], status='unavailable'))),
            ('store-unanswered', lambda: verification.check(origin(), answered([], status='expired'))),
            ('window-empty', lambda: verification.check(origin(), answered([], series_exists=True))),
            ('window-empty', lambda: verification.check(origin(), [])),
            ('sample-off-origin', lambda: verification.check(origin(), answered([sample(1.0, name='lo_other')]))),
            ('sample-off-origin', lambda: verification.check(origin(),
                                                             answered([sample(1.0, resource_id=OTHER)]))),
            ('sample-off-origin', lambda: verification.check(origin(), [sample(1.0, resource_id=None)])),
            ('sample-not-numeric', lambda: verification.check(origin(), 42)),
            ('sample-not-numeric', lambda: verification.check(origin(), 'hot')),
            ('sample-not-numeric', lambda: verification.check(origin(), {'value': 1})),
            ('sample-not-numeric', lambda: verification.check(origin(), [sample(True)])),
            ('sample-not-numeric', lambda: verification.check(origin(),
                                                              answered([LogRecord(body='up', timestamp=INSIDE,
                                                                                  resource_id=RESOURCE)],
                                                                       kind='log-records',
                                                                       parameters={'resource_id': RESOURCE}))),
            ('sample-not-finite', lambda: verification.check(origin(), [sample(float('nan'))])),
            ('sample-not-finite', lambda: verification.check(origin(), [sample(float('inf'))])),
            ('sample-not-finite', lambda: verification.check(origin(), [sample(10 ** 400)])),
            ('row-outside-window', lambda: verification.check(origin(),
                                                              [sample(1.0, at='quarter past ten')])),
            ('row-outside-window', lambda: verification.check(origin(),
                                                              answered([sample(1.0, at='2026-09-08T09:00:00+00:00')]))),
            ('receipt-unusable', lambda: verification.check(origin(),
                                                            answered([sample(1.0)], truncated=True))),
            ('receipt-unusable', lambda: verification.check(origin(),
                                                            answered([sample(1.0)],
                                                                     parameters={'resource_id': RESOURCE,
                                                                                 'rule_id': 'other.rule'}))),
            ('receipt-unusable', lambda: verification.check(origin(),
                                                            answered([sample(1.0)], kind='trace-spans',
                                                                     parameters={'rule_id': RULE}))),
            ('window-mismatch', lambda: verification.verify(seeded(sample(1.0)), origin(), now=NOW,
                                                            outcome=answered(
                                                                [sample(1.0, at='2026-09-08T09:04:00+00:00')],
                                                                window=Window(start='2026-09-08T09:00:00Z',
                                                                            end='2026-09-08T09:05:00Z')))),
        ]
        reasons = set()
        for expected, produce in cases:
            verdict = produce()
            self.assertEqual((verdict.state, verdict.reason), ('unknown', expected), expected)
            reasons.add(verdict.reason)
        self.assertEqual(reasons, set(verification.UNVERIFIABLE_REASONS))
        self.assertNotIn('cleared', {produce().state for _, produce in cases})

    def test_unknown_needs_a_reason_and_no_fourth_state_is_constructible_by_accident(self):
        with self.assertRaises(verification.ConfigError):
            verification._unknown('weather-was-fine', origin())

    def test_a_newest_sample_that_cannot_be_read_is_never_skipped_for_an_older_one(self):
        """Dropping the freshest point of the originating series to reach a comfortable one is the defect."""
        poisoned = [sample(10.0, at=INSIDE), sample(float('nan'), at='2026-09-08T10:04:30+00:00')]
        self.assertEqual((verification.check(origin(), poisoned).state,
                          verification.check(origin(), poisoned).reason),
                         ('unknown', 'sample-not-finite'))

    def test_ties_at_the_newest_instant_are_resolved_against_clearance(self):
        """Two points of one series at one instant: the pessimistic one decides, and is the one filed."""
        tied = [sample(42.0), sample(95.0)]
        verdict = verification.check(origin(), answered(tied))
        self.assertEqual(verdict.state, 'not_cleared')
        self.assertEqual(verdict.value, 95.0)
        self.assertEqual(verification.check(origin(comparison='gt', threshold=50),
                                           answered(tied)).value, 42.0)

    def test_only_the_newest_sample_matters_not_the_row_order(self):
        """The verdict reads the newest instant of the declared series, whichever order it arrives in."""
        rows = [sample(95.0, at='2026-09-08T10:01:00+00:00'), sample(42.0, at=INSIDE)]
        self.assertEqual(verification.check(origin(), rows).state, 'cleared')
        self.assertEqual(verification.check(origin(), list(reversed(rows))).state, 'cleared')

    def test_the_verdict_never_raises_for_a_row_that_is_not_a_reading(self):
        """An attribute error out of a verdict function is a crash where a refusal belongs."""
        inputs = [answered([LogRecord(body='kernel: boot', timestamp=INSIDE, resource_id=RESOURCE)],
                           kind='log-records', parameters={'resource_id': RESOURCE}),
                  [sample(1.0), 'and a string'], [{'value': 1}], [None], [object()], 10 ** 400, object()]
        for item in inputs:
            with self.subTest(repr(item)):
                self.assertEqual(verification.check(origin(), item).state, 'unknown')


class FalseClearanceTests(unittest.TestCase):
    """The review's findings: each of these answered `cleared` in the first draft. They are gaps now."""

    def test_a_sample_of_another_resource_cannot_clear_this_alert(self):
        """A read scoped to a different resource is somebody else's evidence, whatever it says."""
        foreign_read = answered([sample(1.0, resource_id=OTHER)],
                                parameters={'resource_id': OTHER, 'rule_id': RULE})
        self.assertEqual(verification.check(origin(), foreign_read).reason, 'receipt-unusable')
        # The same read shape, with rows that belong to another resource: off-origin, and not `cleared`.
        self.assertEqual(verification.check(origin(), answered([sample(1.0, resource_id=OTHER)])).reason,
                         'sample-off-origin')

    def test_an_unrelated_series_cannot_stand_in_for_the_one_that_paged(self):
        """The newest point of the wrong metric used to replace the oldest point of the right one."""
        rows = [sample(95.0, at='2026-09-08T10:01:00+00:00'),                    # still firing
                sample(1.0, name='lo_memory', at='2026-09-08T10:04:00+00:00')]  # newer, unrelated, low
        verdict = verification.check(origin(), answered(rows))
        self.assertEqual(verdict.state, 'not_cleared')
        self.assertEqual(verdict.value, 95.0)
        # And when the read holds nothing but unrelated series, that is not a clearance either.
        unrelated = verification.check(origin(), answered([sample(1.0, name='lo_memory')]))
        self.assertEqual((unrelated.state, unrelated.reason), ('unknown', 'sample-off-origin'))

    def test_an_origin_that_names_no_series_refuses_to_judge_anything(self):
        """No series name means "whatever this resource reported", which is not the alert."""
        verdict = verification.check(origin(metric_name=None),
                                     answered([sample(1.0, name='lo_unrelated')]))
        self.assertEqual((verdict.state, verdict.reason), ('unknown', 'selector-missing'))

    def test_a_truncated_page_cannot_prove_a_condition_stopped(self):
        """`store.client` bounds a read and the metric statement orders oldest-first: a cut page of a rising series holds the low points."""
        verdict = verification.check(origin(), answered([sample(1.0)], truncated=True))
        self.assertEqual((verdict.state, verdict.reason), ('unknown', 'receipt-unusable'))

    def test_a_row_outside_the_window_the_receipt_claims_is_not_evidence_about_it(self):
        stale = answered([sample(1.0, at='2026-09-07T10:04:00+00:00')])
        self.assertEqual(verification.check(origin(), stale).reason, 'row-outside-window')

    def test_a_reused_read_that_is_not_the_one_being_judged_is_refused(self):
        """`verify(outcome=...)` may not be handed last week's window and called a recovery."""
        last_week = answered([sample(1.0, at='2026-09-01T10:04:00+00:00')],
                             window=Window(start='2026-09-01T10:00:00Z', end='2026-09-01T10:05:00Z'))
        self.assertEqual(verification.verify(None, origin(), now=NOW, outcome=last_week).reason,
                         'window-mismatch')
        # And it may not choose the instant it is judged at either: with no `now`, `verify` uses the
        # real clock, so a nine-month-old page is refused exactly as loudly as it is when the caller
        # names today. (This assertion is the reviewer's second finding: the draft borrowed the
        # receipt's own window end as its clock, which let any old read certify itself fresh.)
        with mock.patch.object(verification, '_now', return_value=NOW):
            verdict = verification.verify(None, origin(), outcome=last_week)
        self.assertEqual((verdict.state, verdict.reason), ('unknown', 'window-mismatch'))
        # The same read, judged at the instant it names, is a verdict about *that* window: replaying
        # history is allowed when the caller says it is history, and `check` (no clock at all) is the
        # other honest way to do it.
        self.assertEqual(verification.verify(None, origin(),
                                             now=dt.datetime(2026, 9, 1, 10, 5, tzinfo=dt.timezone.utc),
                                             outcome=last_week).state, 'cleared')
        self.assertEqual(verification.check(origin(), last_week).state, 'cleared')

    def test_a_receipt_that_does_not_carry_the_pinned_artifact_is_not_the_pinned_read(self):
        """A reused read from an unpinned query is not evidence about the rule that pinned one.

        "The receipt names no `artifact_sha256`" is not the same fact as "the receipt names the hash
        this origin reviewed", and the draft accepted it. The comparison is against the exact parameter
        set :meth:`Origin.read_request` would have sent, in both directions.
        """
        pinned = origin(artifact_sha256=PIN)
        scoped = {'resource_id': RESOURCE, 'rule_id': RULE}
        for label, parameters in (
                ('the pinned hash, matching', dict(scoped, artifact_sha256=PIN)),
                ('no artifact_sha256 at all', dict(scoped)),
                ('a different artifact', dict(scoped, artifact_sha256=OTHER_PIN))):
            read = answered([sample(1.0)], parameters=parameters)
            verdict = verification.check(pinned, read)
            if label.startswith('the pinned'):
                self.assertEqual((label, verdict.state), (label, 'cleared'))
            else:
                self.assertEqual((label, verdict.state, verdict.reason),
                                 (label, 'unknown', 'receipt-unusable'))
        # The converse, so this is a scope rule and not a preference for extra parameters: an origin
        # that pinned nothing is not served by a read scoped to some artifact.
        unpinned = verification.check(origin(), answered([sample(1.0)],
                                                        parameters=dict(scoped, artifact_sha256=PIN)))
        self.assertEqual((unpinned.state, unpinned.reason), ('unknown', 'receipt-unusable'))

    def test_a_receipt_of_another_query_kind_is_not_this_reads_evidence(self):
        """The `available` flag alone does not say what was asked for."""
        for kind, parameters in (('source-heartbeat', {'resource_id': RESOURCE}),
                                 ('trace-spans', {'rule_id': RULE})):
            verdict = verification.check(origin(), answered([sample(1.0)], kind=kind, parameters=parameters))
            self.assertEqual((verdict.state, verdict.reason), ('unknown', 'receipt-unusable'), kind)

    def test_a_read_scoped_to_another_rule_is_not_this_alerts_evidence(self):
        verdict = verification.check(origin(), answered([sample(1.0)],
                                                       parameters={'resource_id': RESOURCE,
                                                                   'rule_id': 'someone.elses.rule'}))
        self.assertEqual((verdict.state, verdict.reason), ('unknown', 'receipt-unusable'))


class ClockTests(unittest.TestCase):
    """Freshness is a fact about the instant of asking, so it belongs to `verify` and to nothing else.

    The reviewer's second finding: the draft let `verify(outcome=...)` fall back to the reused
    receipt's own window end as its clock, which is a receipt certifying its own freshness — a read
    from last quarter answered `cleared` forever. These tests hold the real clock still with a fixed
    instant and prove an old read is refused by default, replayed only when the caller names history,
    and that a clock which is not an aware UTC instant refuses instead of guessing.
    """

    def test_the_default_clock_is_the_real_one_and_is_used_once(self):
        """No `now` means *this* instant, not the sample's."""
        with mock.patch.object(verification, '_now', return_value=NOW) as fake:
            verdict = verification.verify(seeded(sample(42.0)), origin())
        self.assertEqual((verdict.state, fake.call_count), ('cleared', 1))
        self.assertEqual(dict(verdict.window), {'start': facade.utc_text(WINDOW.instant('start')),
                                                'end': facade.utc_text(WINDOW.instant('end'))})

    def test_an_internally_valid_read_from_an_older_window_is_refused_under_a_fixed_current_clock(self):
        """Nothing is wrong with the old receipt; it is simply not evidence about now.

        It is untruncated, correctly scoped, carries a usable expiry and its rows sit inside its own
        window — the only defect is age, which is visible only against a clock the read does not own.
        """
        long_ago = Window(start='2025-12-01T10:00:00Z', end='2025-12-01T10:05:00Z')
        read = answered([sample(1.0, at='2025-12-01T10:04:00+00:00')], window=long_ago)
        self.assertFalse(read.receipt.truncated)
        self.assertEqual(dict(read.receipt.parameters), {'resource_id': RESOURCE, 'rule_id': RULE})
        self.assertGreater(read.receipt.expires_at, long_ago.end)
        with mock.patch.object(verification, '_now', return_value=NOW):
            verdict = verification.verify(None, origin(), outcome=read)
        self.assertEqual((verdict.state, verdict.reason), ('unknown', 'window-mismatch'))
        # `check` is the honest way to grade that window: it has no clock, and the verdict says which
        # interval it spoke about instead of implying it is the current one.
        graded = verification.check(origin(), read)
        self.assertEqual((graded.state, dict(graded.window)['end']),
                         ('cleared', facade.utc_text(long_ago.instant('end'))))

    def test_a_named_instant_replays_history_and_a_non_utc_one_is_normalised(self):
        """Replaying a past verification is allowed, and "12:05 +02:00" names the same instant."""
        historical = dt.datetime(2026, 9, 1, 10, 5, tzinfo=dt.timezone.utc)
        last_week = answered([sample(1.0, at='2026-09-01T10:04:00+00:00')],
                             window=Window(start='2026-09-01T10:00:00Z', end='2026-09-01T10:05:00Z'))
        self.assertEqual(verification.verify(None, origin(), now=historical, outcome=last_week).state,
                         'cleared')
        shifted = dt.datetime(2026, 9, 1, 12, 5, tzinfo=dt.timezone(dt.timedelta(hours=2)))
        self.assertEqual(verification.verify(None, origin(), now=shifted, outcome=last_week).state,
                         'cleared')

    def test_a_clock_that_is_not_an_aware_utc_datetime_is_refused_not_degraded(self):
        """A clock is caller configuration: it refuses loudly, while bad *data* degrades to `unknown`."""
        read = answered([sample(1.0)])
        for bad in ('2026-09-08T10:05:00Z', dt.datetime(2026, 9, 8, 10, 5), 1757325900, [NOW], NOW.date()):
            with self.subTest(repr(bad)):
                with self.assertRaises(verification.ConfigError):
                    verification.verify(None, origin(), now=bad, outcome=read)
                with self.assertRaises(verification.ConfigError):
                    verification.verify(None, origin(), now=bad, outcome='not even a read')
                with self.assertRaises(verification.ConfigError):
                    verification.read_sample(seeded(sample(1.0)), origin(), now=bad)

    def test_the_pure_judge_reads_no_clock_at_all(self):
        """`check` is reproducible because it cannot consult the time: one call raises if it ever tries."""
        with mock.patch.object(verification, '_now',
                               side_effect=AssertionError('check() consulted a clock; it has no business doing so')):
            self.assertEqual(verification.check(origin(), answered([sample(1.0)])).state, 'cleared')
            self.assertEqual(verification.check(origin(), [sample(1.0)]).state, 'cleared')
            self.assertEqual(verification.check(origin(), answered([sample(95.0)])).state, 'not_cleared')

    def test_one_worker_round_uses_the_instant_it_is_given_and_no_other(self):
        """The scheduled path must not read the wall clock behind a test's back, and does not."""
        class Platform:
            def request(self, method, path, payload=None):
                return 200, {'evidence_id': 'a' * 64}

        with mock.patch.object(verification, '_now',
                              side_effect=AssertionError('tick(now=…) must not consult the real clock')):
            verdict, delivered = verification.tick(seeded(sample(42.0)), Platform(), origin(), now=NOW)
        self.assertEqual((verdict.state, delivered), ('cleared', True))


class SamplingTests(unittest.TestCase):
    """The read half: one named facade query, no second transport, no judgement smuggled in."""

    def test_the_only_read_is_the_named_metric_threshold_query(self):
        calls = []

        class Recording:
            def read(self, query_type, *, window, parameters, selectors=None, expires_at=None,
                     store_ttl_hours=None):
                calls.append((query_type, dict(parameters), dict(selectors or {}), window))
                return facade.build_outcome(facade.QUERY_KINDS[query_type], dict(parameters), window,
                                            [sample(42.0)])

            def __getattr__(self, name):
                raise AssertionError(f'verification reached for store.{name}; the facade read is the only seam')

        verdict = verification.verify(Recording(), origin(), now=NOW)
        self.assertEqual(verdict.state, 'cleared')
        query_type, parameters, selectors, window = calls[0]
        self.assertEqual(query_type, 'metric-threshold')
        self.assertTrue(set(parameters) <= facade.APPROVED_PARAMETERS)
        self.assertEqual(parameters, {'resource_id': RESOURCE, 'rule_id': RULE})
        self.assertEqual(selectors, {'metric_name': SERIES})
        self.assertIsInstance(window, Window)
        self.assertEqual(window.instant('end'), NOW)
        self.assertEqual(window.instant('start'), NOW - dt.timedelta(seconds=WINDOW_SECONDS))
        self.assertEqual(len(calls), 1, 'one read per verdict; no second query to widen the surface')

    def test_the_check_itself_performs_no_io(self):
        """`check` is pure: the same sample judged twice gives the same answer and reads nothing."""
        rows = [sample(42.0)]
        for _ in range(5):
            self.assertEqual(verification.check(origin(), rows).state, 'cleared')
        self.assertEqual(verification.check(origin(), rows).state,
                         verification.check(origin(), list(reversed(rows))).state)
        self.assertEqual(verification.check(origin(), None).state, 'unknown')

    def test_read_sample_returns_the_stores_own_answer_untouched(self):
        refused = InMemoryStore()
        result = verification.read_sample(refused, origin(), now=NOW)
        self.assertEqual(result.status, 'unavailable')
        self.assertEqual(result.samples, ())
        self.assertEqual(verification.check(origin(), result).state, 'unknown')

    def test_a_store_that_cannot_be_read_yields_no_verdict_at_all(self):
        """`StoreRefused` propagates: a read not performed means no verdict filed, not an honest `unknown`."""
        class Broken:
            def read(self, *args, **kwargs):
                raise facade.StoreRefused('the transport refused this query')

        with self.assertRaises(facade.StoreRefused):
            verification.read_sample(Broken(), origin(), now=NOW)
        with self.assertRaises(facade.StoreRefused):
            verification.verify(Broken(), origin(), now=NOW)

    def test_metric_name_is_a_selector_and_never_reaches_the_evidence_reference(self):
        """The store's own rule, restated here: a verification that invented a parameter could not be reauthorised."""
        self.assertNotIn('metric_name', facade.QUERY_KINDS['metric-threshold'].parameters)
        verdict = verification.verify(seeded(sample(42.0, name='lo.cpu_percent')),
                                      origin(metric_name='lo.cpu_percent'), now=NOW)
        self.assertEqual(dict(verdict.parameters), {'resource_id': RESOURCE, 'rule_id': RULE})
        self.assertEqual(verdict.metric_name, 'lo.cpu_percent')

    def test_a_series_another_resource_reports_is_absence_for_this_one_not_a_verdict(self):
        """The store's existence probe asks about the series, not the resource, so both answers are honest and both are `unknown`."""
        reported_elsewhere = seeded(sample(42.0, resource_id=OTHER))
        never_seen = seeded(sample(42.0, name='lo_other_series'))
        self.assertEqual(verification.verify(reported_elsewhere, origin(), now=NOW).reason, 'window-empty')
        self.assertEqual(verification.verify(never_seen, origin(), now=NOW).reason, 'store-unanswered')
        for store in (reported_elsewhere, never_seen):
            self.assertEqual(verification.verify(store, origin(), now=NOW).state, 'unknown')


class ConfigurationTests(unittest.TestCase):
    """Bounded config or nothing: a check that cannot say what it measures refuses before any read."""

    def test_unbounded_or_unsupported_configuration_is_refused_not_degraded(self):
        refusals = (
            {'rule_id': 'bad rule', 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 300},
            {'rule_id': RULE, 'resource_id': 'not-a-uuid', 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 300},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': float('nan'),
             'comparison': 'lt', 'window_seconds': 300},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': True,
             'comparison': 'lt', 'window_seconds': 300},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'nope', 'window_seconds': 300},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 30},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 86_401},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': 'select *', 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 300},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 300, 'artifact_sha256': 'deadbeef'},
            {'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES, 'threshold': 90,
             'comparison': 'lt', 'window_seconds': 300, 'kind': 'log-records'},
            # The series name is required of a worker: an unscoped read verifies whatever happened to
            # come back, which is the false clearance the review found.
            {'rule_id': RULE, 'resource_id': RESOURCE, 'threshold': 90, 'comparison': 'lt',
             'window_seconds': 300},
        )
        for document in refusals:
            with self.assertRaises(ValueError, msg=str(sorted(document))):
                verification.Origin.from_document(document)

    def test_unknown_or_missing_document_keys_are_refused_by_name(self):
        with self.assertRaises(verification.ConfigError) as caught:
            verification.Origin.from_document({'rule_id': RULE, 'resource_id': RESOURCE,
                                               'metric_name': SERIES, 'threshold': 1, 'comparison': 'lt',
                                               'window_seconds': 60, 'operator': 'me'})
        self.assertIn('operator', str(caught.exception))
        with self.assertRaises(verification.ConfigError) as caught:
            verification.Origin.from_document({'rule_id': RULE, 'threshold': 1, 'comparison': 'lt'})
        self.assertIn('metric_name', str(caught.exception))
        self.assertIn('resource_id', str(caught.exception))
        with self.assertRaises(verification.ConfigError):
            verification.Origin.from_document([{'rule_id': RULE}])

    def test_the_bounded_window_is_inside_the_facades_own_bound(self):
        """A receipt this unit asks for can never be refused for size."""
        self.assertLessEqual(verification.WINDOW_SECONDS_LIMITS[1], facade.MAX_WINDOW_SECONDS)
        longest = origin(window_seconds=verification.WINDOW_SECONDS_LIMITS[1])
        _, _, _, window = longest.read_request(NOW)
        self.assertEqual(window.instant('start'),
                         NOW - dt.timedelta(seconds=verification.WINDOW_SECONDS_LIMITS[1]))

    def test_an_unvalidated_origin_cannot_reach_the_verdict_function(self):
        """The four-argument `check` is honest about what it needs: an Origin, not a dict."""
        with self.assertRaises(verification.ConfigError):
            verification.check({'comparison': 'lt', 'threshold': 90}, [sample(1.0)])

    def test_a_configuration_file_is_read_with_bounds_and_refuses_junk(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'verify.json'
            path.write_text(json.dumps({'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES,
                                        'threshold': 90, 'comparison': 'lt', 'window_seconds': 300,
                                        'artifact_sha256': 'a' * 64}), encoding='utf-8')
            configured = verification.load_config(path)
            self.assertEqual((configured.metric_name, configured.artifact_sha256), (SERIES, 'a' * 64))
            for document in ('{not json',
                             json.dumps({'rule_id': RULE, 'resource_id': RESOURCE, 'metric_name': SERIES,
                                         'threshold': 90, 'comparison': 'lt', 'window_seconds': 300,
                                         'extra': 1})):
                path.write_text(document, encoding='utf-8')
                with self.assertRaises(verification.ConfigError):
                    verification.load_config(path)
            with self.assertRaises(verification.ConfigError):
                verification.load_config(path.parent / 'absent.json')


class EffectiveConditionTests(unittest.TestCase):
    """A re-grade is a different check, and must say so in its own binding."""

    def test_an_override_changes_the_binding_the_verdict_carries(self):
        base = origin()
        rows = [sample(95.0)]
        as_configured = verification.check(base, answered(rows))
        regraded = verification.check(base, answered(rows), 100)
        self.assertEqual((as_configured.state, regraded.state), ('not_cleared', 'cleared'))
        self.assertNotEqual(regraded.origin_binding, base.binding)
        self.assertEqual(as_configured.origin_binding, base.binding)
        self.assertEqual((regraded.threshold, regraded.comparison), (100.0, 'lt'))
        # The overridden verdict and the definition it actually used agree with each other.
        self.assertEqual(regraded.origin_binding,
                         origin(threshold=100).binding)

    def test_evidence_is_filed_from_the_verdict_alone_and_not_from_an_origin_handed_in_later(self):
        """The filing call takes no Origin, so nobody can attach a verdict to a definition it did not use."""
        regraded = verification.check(origin(), answered([sample(95.0)]), 100)
        document = verification.evidence_sample(regraded)
        self.assertTrue(document['sample_id'].startswith('verify.cleared.'))
        self.assertNotEqual(document['sample_id'],
                            verification.evidence_sample(verification.check(origin(),
                                                                            answered([sample(95.0)])))['sample_id'])
        with self.assertRaises(TypeError):
            verification.evidence_sample(origin(), regraded)          # the signature takes no origin
        with self.assertRaises(verification.ConfigError):
            verification.evidence_sample(verdict=origin())            # and refuses one passed as a verdict


class EvidenceTests(unittest.TestCase):
    """The verdict leaves through `Store.put_evidence`, in that store's shape and with its limits."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'state.db')

    def test_a_verdict_is_filed_as_the_platform_minimal_sample(self):
        verdict = verification.check(origin(), answered([sample(95.0)]))
        document = verification.evidence_sample(verdict)
        self.assertEqual(set(document), {'sample_id', 'observed_at', 'ok', 'value'})
        self.assertEqual(document['value'], 95.0)
        self.assertTrue(document['ok'])
        self.assertEqual(document['observed_at'], facade.utc_text(WINDOW.instant('end')))
        key = verification.record_evidence(self.store, document, PRODUCER, now=NOW)
        self.assertEqual(self.store.get_evidence(PRODUCER.identity, document['sample_id'],
                                                now=NOW)['status'], 'available')
        self.assertEqual(self.store.get_evidence(PRODUCER.identity, document['sample_id'],
                                                now=NOW + dt.timedelta(days=16))['status'], 'expired')
        # Filing the same read twice is the same row, not a second copy of the truth.
        self.assertEqual(verification.record_evidence(self.store, document, PRODUCER, now=NOW), key)

    def test_only_four_fields_survive_the_evidence_path_and_that_is_the_honest_claim(self):
        """What is durable is the verdict word, the value, the window end and whether the store answered.

        The threshold, comparison, rule, series and window behind the verdict are *not* readable back:
        they are folded into a digest that only re-derives for someone who already knows them. This test
        pins the limit so no later reader can believe the evidence row is the whole verdict, and no
        writer can claim more without changing `state.py`.
        """
        verdict = verification.check(origin(), answered([sample(95.0)]))
        document = verification.evidence_sample(verdict)
        verification.record_evidence(self.store, document, PRODUCER, now=NOW)
        stored = self.store.get_evidence(PRODUCER.identity, document['sample_id'], now=NOW)['sample']
        self.assertEqual(set(stored), {'sample_id', 'observed_at', 'ok', 'value'})
        self.assertEqual(stored['value'], 95.0)
        self.assertIn('not_cleared', stored['sample_id'])
        for field in ('threshold', 'comparison', 'rule_id', 'resource_id', 'metric_name', 'window',
                      'reason'):
            self.assertNotIn(field, json.dumps(stored))

    def test_ok_is_the_stores_answer_and_not_the_verdict(self):
        """`ok=True` with a `not_cleared` verdict is deliberate: the read answered, the alert did not clear."""
        still_firing = verification.check(origin(), answered([sample(95.0)]))
        unanswered = verification.check(origin(), answered([], status='unavailable'))
        self.assertEqual((still_firing.state, verification.evidence_sample(still_firing)['ok']),
                         ('not_cleared', True))
        self.assertEqual((unanswered.state, verification.evidence_sample(unanswered)['ok']),
                         ('unknown', False))
        self.assertIsNone(verification.evidence_sample(unanswered)['value'])

    def test_the_verdict_and_the_read_it_was_made_from_are_in_the_sample_identity(self):
        first = verification.check(origin(), answered([sample(95.0)]))
        cleared = verification.check(origin(), answered([sample(42.0)]))
        self.assertNotEqual(verification.evidence_sample(first)['sample_id'],
                            verification.evidence_sample(cleared)['sample_id'])
        self.assertEqual(verification.evidence_sample(first),
                         verification.evidence_sample(verification.check(origin(), answered([sample(95.0)]))))
        # Naming the action or execution it verifies is part of the identity: one window verified for
        # two actions leaves two rows instead of one overwriting the other.
        self.assertNotEqual(verification.evidence_sample(first)['sample_id'],
                            verification.evidence_sample(first, subject='execution-7'))
        # A different unknown reason about the same window is a different statement.
        empty = verification.check(origin(), answered([], series_exists=True))
        refused = verification.check(origin(), answered([], status='unavailable'))
        self.assertEqual((empty.reason, refused.reason), ('window-empty', 'store-unanswered'))
        self.assertNotEqual(verification.evidence_sample(empty)['sample_id'],
                            verification.evidence_sample(refused)['sample_id'])

    def test_a_verdict_with_no_read_behind_it_is_not_fileable(self):
        """A bare list of rows has no window, so filing it would create proof that cannot be reauthorised."""
        bare = verification.check(origin(), [sample(95.0)])
        self.assertIsNone(bare.window)
        with self.assertRaises(verification.ConfigError):
            verification.evidence_sample(bare)

    def test_the_platform_refuses_a_sample_stamped_in_the_future(self):
        """The evidence clock rule is the platform's, so it is asserted here rather than assumed."""
        document = verification.evidence_sample(verification.check(origin(), answered([sample(95.0)])))
        document['observed_at'] = facade.utc_text(NOW + dt.timedelta(days=2))
        with self.assertRaises(StateError):
            verification.record_evidence(self.store, document, PRODUCER, now=NOW)


class WorkerTests(unittest.TestCase):
    """The `python -m` entry point: off by default, one round per invocation, loud about refusals."""

    def test_absent_configuration_is_off_and_opens_nothing(self):
        with mock.patch.dict('os.environ', {}, clear=True), \
                mock.patch('local_observe.store.backends.clickhouse.store_from_environment',
                           side_effect=AssertionError('the off path must not build a store')):
            with self.assertLogs('local_observe.platform.verification', 'INFO') as captured:
                self.assertEqual(verification.main(), 0)
        self.assertEqual(len(captured.records), 1)
        self.assertEqual(captured.records[0].levelname, 'INFO')
        self.assertEqual(captured.records[0].variable, verification.CONFIG_ENVIRONMENT)

    def test_blank_configuration_is_off_too(self):
        with mock.patch.dict('os.environ', {verification.CONFIG_ENVIRONMENT: '   '}):
            self.assertIsNone(verification.producer_config())

    def test_unreadable_configuration_exits_one_before_any_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = {verification.CONFIG_ENVIRONMENT: str(Path(directory) / 'absent.json')}
            with mock.patch.dict('os.environ', environment, clear=True), \
                    mock.patch('local_observe.store.backends.clickhouse.store_from_environment',
                               side_effect=AssertionError('a refused worker must not connect')):
                with self.assertLogs('local_observe.platform.verification', 'WARNING'):
                    self.assertEqual(verification.main(), 1)

    def test_one_round_files_the_verdict_and_reports_whether_it_landed(self):
        posted = []

        class Platform:
            def request(self, method, path, payload=None):
                posted.append((method, path, payload))
                return 200, {'evidence_id': 'a' * 64}

        with self.assertLogs('local_observe.platform.verification', 'INFO') as captured:
            verdict, delivered = verification.tick(seeded(sample(95.0)), Platform(), origin(), now=NOW)
        self.assertEqual((verdict.state, delivered), ('not_cleared', True))
        self.assertEqual(posted[0][:2], ('POST', '/v1/evidence'))
        self.assertEqual(set(posted[0][2]), {'sample_id', 'observed_at', 'ok', 'value'})
        line = captured.records[-1]
        self.assertEqual((line.verdict, line.reason, line.evidence_delivered),
                         ('not_cleared', 'comparison-failed', True))
        self.assertEqual((line.rule_id, line.metric_name), (RULE, SERIES))
        self.assertEqual(line.window_end, facade.utc_text(WINDOW.instant('end')))

    def test_a_refused_evidence_post_is_not_reported_as_recorded(self):
        class Platform:
            def request(self, method, path, payload=None):
                return 400, {'error': 'invalid_request'}

        with self.assertLogs('local_observe.platform.verification', 'INFO'):
            verdict, delivered = verification.tick(seeded(sample(42.0)), Platform(), origin(), now=NOW)
        self.assertEqual((verdict.state, verdict.cleared, delivered), ('cleared', True, False))
        self.assertFalse(verification.post_evidence(Platform(), {'sample_id': 'x'}))

    def test_an_unknown_is_a_delivered_verdict_not_a_failed_run(self):
        """The store answered "nothing here": the worker files that and says unknown, never cleared."""
        class Platform:
            def request(self, method, path, payload=None):
                self.payload = payload
                return 200, {'evidence_id': 'a' * 64}

        platform = Platform()
        with self.assertLogs('local_observe.platform.verification', 'INFO'):
            verdict, delivered = verification.tick(InMemoryStore(), platform, origin(), now=NOW)
        self.assertEqual((verdict.state, verdict.cleared, delivered), ('unknown', False, True))
        self.assertFalse(platform.payload['ok'])
        self.assertIsNone(platform.payload['value'])

    def test_the_verdict_is_reproducible_from_the_read_it_cites(self):
        """quality bar: no new durable state is needed, because the same read re-derives the same statement."""
        store = seeded(sample(95.0))
        first = verification.check(origin(), verification.read_sample(store, origin(), now=NOW))
        again = verification.check(origin(), verification.read_sample(store, origin(), now=NOW))
        self.assertEqual(first.as_dict(), again.as_dict())
        self.assertEqual(verification.evidence_sample(first), verification.evidence_sample(again))
        rendered = json.loads(json.dumps(first.as_dict(), sort_keys=True))
        self.assertEqual(rendered['verdict'], 'not_cleared')
        self.assertIsInstance(rendered['value'], float)
        self.assertFalse(math.isnan(rendered['value']))
        self.assertEqual(rendered['origin_binding'], origin().binding)


if __name__ == '__main__':
    unittest.main()

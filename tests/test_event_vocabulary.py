"""Refusal tests for the event crosswalk (`platform/vocabulary.py`), and the round trips it must survive.

Four claims are pinned here and nowhere else in the suite:

* every `severity` and every `kind` this build admits is **reachable** through the crosswalk, and no
  row produces a value outside the vocabularies `state.validate_event` admits — the two directions of
  one check, so a widening that skips a row fails as loudly as a row that invents a value;
* an unmapped word, and a word refused on purpose, **raise**, naming the source and the word, and the
  sentence never echoes raw caller data: `api.py` answers a refusal with `{'detail': str(exc)}`, so
  these messages can reach an HTTP body;
* every admitted row produces an event that `validate_event` **accepts** when built through
  `detections.event()` — the only factory — one round trip per declared source plus a sweep of every
  type row, on a fixed clock, against the shipped demo resource, with no network;
* `docs/CONTRACTS.md` §4.1 lists every condition, every source and every refusal the code can emit,
  which is what stops the table and the contract from drifting apart after event vocabulary merges.
"""
import datetime as dt
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import validation
from local_observe.platform import detections, presentation, vocabulary
from local_observe.platform.state import EVENT_KINDS, Actor, StateError, Store, label, validate_event

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = (ROOT / 'docs' / 'CONTRACTS.md').read_text(encoding='utf-8')
FIXED_NOW = validation.timestamp('2026-09-06T12:01:00Z')
RESOURCE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'   # probe-1 in examples/inventory/declared.yaml
ADMITTED = ('info', 'warning', 'critical')          # what validate_event admits, spelled for the diff
SOURCES = ('alertmanager', 'core-events-v1', 'crowdsec', 'gatus', 'healthchecks', 'sigma', 'signoz')

# One round trip per declared source. A `None` word means that half is refused by decision — an open
# type space, or a source that carries no severity — and the missing half then comes from the verdict.
ROUND_TRIPS = (
    {'source': 'core-events-v1', 'type_word': 'probe.check_failed', 'severity_word': 'error',
     'kind': 'availability', 'condition': 'probe.check_failed', 'severity': 'warning'},
    {'source': 'alertmanager', 'type_word': None, 'severity_word': 'crit',
     'kind': 'availability', 'condition': 'alertmanager.rule-1', 'severity': 'critical'},
    {'source': 'gatus', 'type_word': 'result', 'severity_word': None,
     'kind': 'availability', 'condition': 'gatus.result', 'severity': 'warning'},
    {'source': 'healthchecks', 'type_word': 'down', 'severity_word': None,
     'kind': 'availability', 'condition': 'healthchecks.check-in', 'severity': 'warning'},
    {'source': 'sigma', 'type_word': 'finding', 'severity_word': 'critical',
     'kind': 'security', 'condition': 'sigma.finding', 'severity': 'critical'},
    {'source': 'crowdsec', 'type_word': 'alert', 'severity_word': None,
     'kind': 'security', 'condition': 'crowdsec.alert', 'severity': 'warning'},
    {'source': 'signoz', 'type_word': None, 'severity_word': 'FATAL',
     'kind': 'threshold', 'condition': 'signoz.query-1', 'severity': 'critical'},
)


def window(*, offset_minutes: float = 0.0) -> dict[str, str]:
    """One legal one-minute evaluation window ending at the fixed clock (plus an offset)."""
    end = FIXED_NOW + dt.timedelta(minutes=offset_minutes)
    return {'start': validation.utc_text(end - dt.timedelta(minutes=1)), 'end': validation.utc_text(end)}


def build(source: str, rule: str, kind: str, *, status: str = 'firing', severity: str | None = None,
          query_type: str = 'observed-snapshot', offset_minutes: float = 0.0) -> dict:
    """Build an event the way a producer does: through the one factory, never by hand."""
    return detections.event(source, RESOURCE, rule, kind, status, window(offset_minutes=offset_minutes),
                            {'rule_id': rule}, query_type=query_type, severity=severity)


def case_event(case: dict, *, status: str = 'firing', **kwargs) -> dict:
    """The event one `ROUND_TRIPS` row stands for.

    A named severity travels only with a firing verdict: a recovery carries the factory's `info`,
    which is the rule docs/CONTRACTS.md §4.1 states and v0.1's own dispatcher followed.
    """
    named = (None if case['severity_word'] is None or status == 'resolved'
             else vocabulary.severity(case['source'], case['severity_word']))
    return build(case['source'], case['condition'], case['kind'], status=status, severity=named, **kwargs)


class VocabularyShapeTests(unittest.TestCase):
    """The tables cover exactly what this build admits — never wider, never narrower."""

    def test_every_admitted_severity_is_reachable(self):
        self.assertEqual(vocabulary.ADMITTED_SEVERITIES, ADMITTED)
        reached = {value for value in vocabulary.SEVERITY_CROSSWALK.values()}
        self.assertEqual(reached, set(ADMITTED),
                         'an admitted severity no source can produce is one no ported producer can set')

    def test_every_admitted_kind_is_reachable(self):
        reached = {kind for kind, _ in vocabulary.TYPE_CROSSWALK.values()}
        self.assertEqual(reached, set(EVENT_KINDS),
                         'a kind the crosswalk cannot produce is a kind no ported producer may use')

    def test_no_row_produces_a_value_state_refuses(self):
        for (source, word), value in vocabulary.SEVERITY_CROSSWALK.items():
            self.assertIn(source, vocabulary.SOURCE_VOCABULARIES, word)
            self.assertIn(word, vocabulary.SOURCE_VOCABULARIES[source].severities,
                          f'{source}/{word} is mapped but not declared by that source')
            self.assertIn(value, ADMITTED, f'{source}/{word}')
        for (source, word), (kind, condition) in vocabulary.TYPE_CROSSWALK.items():
            self.assertIn(source, vocabulary.SOURCE_VOCABULARIES, word)
            self.assertIn(kind, EVENT_KINDS, f'{source}/{word}')
            label(condition)          # a condition that is not a bounded label can never be a rule_id
            self.assertEqual(condition, condition.lower(), f'{source}/{word}')

    def test_every_declared_severity_word_is_either_mapped_or_refused(self):
        for source, record in vocabulary.SOURCE_VOCABULARIES.items():
            for word in record.severities:
                key = (source, word)
                answered = key in vocabulary.SEVERITY_CROSSWALK or key in vocabulary.REFUSALS
                self.assertTrue(answered,
                                f'{source}/{word} is declared by its source and answered by neither table')

    def test_the_seven_declared_sources_are_the_ones_the_port_plan_names(self):
        self.assertEqual(tuple(sorted(vocabulary.SOURCE_VOCABULARIES)), SOURCES)

    def test_every_refusal_gives_its_reason_in_one_bounded_line(self):
        for (source, word), reason in vocabulary.REFUSALS.items():
            self.assertIn(source, vocabulary.SOURCE_VOCABULARIES, word)
            self.assertTrue(reason.strip(), f'{source}/{word} is refused with no reason')
            self.assertNotIn('\n', reason, f'{source}/{word}')
            self.assertLess(len(reason), 480, f'{source}/{word} is too long to read in an error body')

    def test_the_sources_that_carry_no_severity_say_so_by_being_empty(self):
        for source in ('gatus', 'healthchecks', 'crowdsec'):
            self.assertEqual(vocabulary.declared_severities(source), (), source)
        for source in ('alertmanager', 'signoz'):
            self.assertEqual(vocabulary.declared_types(source), (), source)


class RefusalTests(unittest.TestCase):
    """Nothing maps by default: an unclaimed word stops the producer instead of becoming a guess."""

    def test_an_unmapped_severity_raises_naming_source_and_value(self):
        for source, word in (('core-events-v1', 'catastrophic'), ('sigma', 'emergency'),
                             ('signoz', 'information'), ('alertmanager', 'fatal')):
            with self.subTest(source=source, word=word):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.severity(source, word)
                self.assertIn(source, str(caught.exception))
                self.assertIn(word, str(caught.exception))

    def test_a_refused_severity_raises_with_its_recorded_reason(self):
        for source, word in (('core-events-v1', 'unknown'), ('alertmanager', 'none'),
                             ('alertmanager', 'unknown'), ('signoz', 'unspecified'),
                             ('signoz', 'unknown')):
            with self.subTest(source=source, word=word):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.severity(source, word)
                self.assertIn(vocabulary.REFUSALS[(source, word)], str(caught.exception))

    def test_a_source_that_carries_no_severity_refuses_even_an_admitted_value(self):
        for source in ('gatus', 'healthchecks', 'crowdsec'):
            for word in ADMITTED:
                with self.subTest(source=source, word=word):
                    with self.assertRaises(vocabulary.VocabularyError) as caught:
                        vocabulary.severity(source, word)
                    self.assertIn(source, str(caught.exception))

    def test_a_refused_word_and_an_undeclared_word_say_different_things(self):
        with self.assertRaises(vocabulary.VocabularyError) as refused:
            vocabulary.severity('core-events-v1', 'unknown')       # refused by decision, has a reason
        self.assertIn('refused by design', str(refused.exception))
        with self.assertRaises(vocabulary.VocabularyError) as unmapped:
            vocabulary.severity('core-events-v1', 'notice')        # never spelled by that source at all
        self.assertIn('not a word that source spells', str(unmapped.exception))

    def test_an_unmapped_type_raises_naming_source_and_value(self):
        for source, word in (('core-events-v1', 'slo.slow_burn'), ('sigma', 'other'),
                             ('crowdsec', 'decision'), ('healthchecks', 'deleted'), ('gatus', 'skipped')):
            with self.subTest(source=source, word=word):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.classify(source, word)
                self.assertIn(source, str(caught.exception))
                self.assertIn(word, str(caught.exception))

    def test_a_type_with_no_row_says_so_rather_than_picking_a_kind(self):
        with self.assertRaises(vocabulary.VocabularyError) as caught:
            vocabulary.classify('core-events-v1', 'probe.uninvented')
        self.assertIn('has no crosswalk row', str(caught.exception))

    def test_a_refused_type_raises_with_its_recorded_reason(self):
        refused = {key: reason for key, reason in vocabulary.REFUSALS.items() if '.' in key[1]}
        self.assertTrue(refused, 'the refusals table names no type word at all')
        for (source, word), reason in refused.items():
            with self.subTest(source=source, word=word):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.classify(source, word)
                self.assertIn(reason, str(caught.exception))

    def test_an_alert_transition_is_refused_because_it_names_no_verdict(self):
        for word in ('alert.fired', 'alert.resolved'):
            with self.subTest(word=word):
                with self.assertRaises(vocabulary.VocabularyError):
                    vocabulary.classify('core-events-v1', word)
                self.assertIn('alert conditions', vocabulary.REFUSALS[('core-events-v1', word)])

    def test_an_open_type_space_refuses_and_names_who_owes_the_kind(self):
        # `labels.alertname` is free text an operator typed into a route; SigNoz is a store, not a detector.
        for source, owner in (('alertmanager', 'event intake'), ('signoz', 'store facade')):
            for word in ('CPU High', 'disk_full', 'KillWeb01', 'anomaly.detected'):
                with self.subTest(source=source, word=word):
                    with self.assertRaises(vocabulary.VocabularyError) as caught:
                        vocabulary.classify(source, word)
                    message = str(caught.exception)
                    self.assertIn('no closed type vocabulary', message)
                    self.assertIn(owner, message)

    def test_an_undeclared_source_raises_naming_the_declared_ones(self):
        for source in ('netdata', 'signoz-v2', 'gatus-two'):
            with self.subTest(source=source):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.severity(source, 'warning')
                message = str(caught.exception)
                self.assertIn('no event vocabulary declared', message)
                self.assertIn(source, message)
                for declared in SOURCES:
                    self.assertIn(declared, message)

    def test_a_source_name_is_matched_exactly_while_its_words_are_folded(self):
        # `gatus` is an identifier here, not a word inside someone else's payload: folding it would let
        # a typo pick a vocabulary.
        for source in ('Gatus', 'GATUS', ' gatus'):
            with self.subTest(source=source):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.severity(source, 'warning')
                self.assertIn('no event vocabulary declared', str(caught.exception))

    def test_case_and_surrounding_space_carry_no_meaning_in_a_source_word(self):
        self.assertEqual(vocabulary.severity('alertmanager', '  CRIT  '), 'critical')
        self.assertEqual(vocabulary.severity('signoz', 'Fatal'), 'critical')
        self.assertEqual(vocabulary.severity('core-events-v1', 'Error'), 'warning')
        self.assertEqual(vocabulary.classify('core-events-v1', 'SLO.Fast_Burn'),
                         ('threshold', 'slo.fast_burn'))

    def test_a_non_string_word_is_refused_without_naming_its_contents(self):
        for value in (1, ['warning'], {'severity': 'critical'}, None, True, 3.5):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.severity('core-events-v1', value)
                self.assertNotIn('critical', str(caught.exception))
                self.assertNotIn('warning', str(caught.exception))

    def test_a_refusal_never_echoes_raw_caller_data_into_its_own_sentence(self):
        hostile = ['<script>alert(1)</script>', 'a' * 4000, 'severite' + chr(0) + 'x',
                   'CRITICA1' + chr(9), 'warning' + chr(10) + 'INJECTED']
        for word in hostile:
            with self.subTest(word=repr(word[:14])):
                with self.assertRaises(vocabulary.VocabularyError) as caught:
                    vocabulary.severity('core-events-v1', word)
                message = str(caught.exception)
                self.assertNotIn('<', message)
                self.assertNotIn('\n', message)
                self.assertNotIn(chr(0), message)
                self.assertLess(len(message), 900, 'a refusal sentence is bounded too')

    def test_an_empty_word_is_a_refusal_rather_than_a_silent_miss(self):
        for word in ('', '   ', chr(9)):
            with self.subTest(word=repr(word)):
                with self.assertRaises(vocabulary.VocabularyError):
                    vocabulary.severity('core-events-v1', word)


class RoundTripTests(unittest.TestCase):
    """Every admitted row survives the factory and intake; every refusal stops before them."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_one_round_trip_per_source_survives_validation(self):
        for case in ROUND_TRIPS:
            with self.subTest(source=case['source']):
                if case['type_word'] is not None:
                    self.assertEqual(vocabulary.classify(case['source'], case['type_word']),
                                     (case['kind'], case['condition']), case['source'])
                event = case_event(case)
                validate_event(event, FIXED_NOW)
                self.assertEqual(event['kind'], case['kind'], case['source'])
                self.assertEqual(event['severity'], case['severity'], case['source'])

    def test_every_type_row_produces_an_event_intake_validates(self):
        for (source, word), (kind, condition) in sorted(vocabulary.TYPE_CROSSWALK.items()):
            with self.subTest(source=source, word=word):
                event = build(source, condition, kind)
                validate_event(event, FIXED_NOW)
                self.assertEqual(event['rule_id'], condition, f'{source}/{word}')
                self.assertEqual(event['condition'], condition,
                                 f'{source}/{word}: the factory sets condition = rule_id, so the '
                                 'crosswalk condition must be what the producer passes as rule_id')
                self.assertEqual(event['severity'], 'warning', f'{source}/{word}')

    def test_every_severity_row_survives_validation_on_an_event(self):
        for (source, word), value in sorted(vocabulary.SEVERITY_CROSSWALK.items()):
            with self.subTest(source=source, word=word):
                self.assertEqual(vocabulary.severity(source, word), value)
                validate_event(build('crosswalk-probe', 'crosswalk.probe', 'coverage', severity=value),
                               FIXED_NOW)

    def test_the_crosswalked_kind_is_one_the_operator_can_name(self):
        """A kind that reaches the records view without a label is an incident nobody can read."""
        for case in ROUND_TRIPS:
            with self.subTest(kind=case['kind']):
                description = presentation.describe(case_event(case))['description']
                self.assertTrue(description.strip(), case['kind'])
                self.assertNotEqual(description, 'Monitoring incident', case['kind'])

    def test_an_unmapped_value_produces_no_event_at_all(self):
        broken = dict(ROUND_TRIPS[0], severity_word='catastrophic')
        with self.assertRaises(vocabulary.VocabularyError):
            case_event(broken)
        with self.assertRaises(vocabulary.VocabularyError):
            vocabulary.classify(ROUND_TRIPS[2]['source'], 'uninvented')

    def test_the_refused_unknown_lands_as_a_coverage_event_about_the_source(self):
        """The `unknown` answer: monitoring says the one thing it knows, and invents no severity.

        v0.1 files an unclaimed payload as `severity: unknown`; that word is refused here, and the
        `detections.evaluate` pattern takes its place — a `coverage` event about the source, carrying
        the severity the verdict derives rather than one somebody typed.
        """
        with self.assertRaises(vocabulary.VocabularyError):
            vocabulary.severity('core-events-v1', 'unknown')
        kind, condition = vocabulary.classify('core-events-v1', 'unnormalized')
        self.assertEqual((kind, condition), ('coverage', 'core.unnormalized'))
        event = build('core-events-v1', condition, kind, query_type='source-heartbeat')
        validate_event(event, FIXED_NOW)
        self.assertEqual(event['severity'], 'warning')
        self.assertEqual(event['status'], 'firing')

    def test_intake_accepts_a_crosswalked_event_and_replays_it_as_one_row(self):
        store = Store(self.root / 'state.db')
        actor = Actor('gatus', 'producer')
        event = case_event(ROUND_TRIPS[2])
        first = store.intake(event, actor, now=FIXED_NOW)
        self.assertEqual(first['status'], 'accepted')
        self.assertEqual(first['transition'], 'opened')
        again = store.intake(event, actor, now=FIXED_NOW)
        self.assertEqual(again['status'], 'duplicate')
        self.assertEqual(again['event_id'], first['event_id'])
        self.assertEqual(len(store.records('events')), 1)

    def test_a_distinct_condition_is_a_distinct_incident_not_a_dedup_hit(self):
        """Identity is (source, source_event_id) plus the conditions key — never a name-derived hash."""
        store = Store(self.root / 'state.db')
        actor = Actor('gatus', 'producer')
        result_a = store.intake(case_event(ROUND_TRIPS[2]), actor, now=FIXED_NOW)
        coverage = {'source': 'gatus', 'type_word': 'coverage', 'severity_word': None,
                    'kind': 'coverage', 'condition': 'gatus.coverage', 'severity': 'warning'}
        self.assertEqual(vocabulary.classify('gatus', 'coverage'), ('coverage', 'gatus.coverage'))
        result_b = store.intake(case_event(coverage), actor, now=FIXED_NOW)
        self.assertEqual(result_b['status'], 'accepted')
        self.assertNotEqual(result_a['incident_id'], result_b['incident_id'])
        self.assertEqual(store.status()['incidents'], {'open': 2})

    def test_a_recovery_after_a_crosswalked_finding_resolves_the_same_incident(self):
        store = Store(self.root / 'state.db')
        actor = Actor('sigma', 'producer')
        opened = store.intake(case_event(ROUND_TRIPS[4]), actor, now=FIXED_NOW)
        resolved = case_event(ROUND_TRIPS[4], status='resolved', offset_minutes=5)
        later = FIXED_NOW + dt.timedelta(minutes=5)
        validate_event(resolved, later)
        self.assertEqual(resolved['severity'], 'info', 'a recovery carries no inherited loudness')
        outcome = store.intake(resolved, actor, now=later)
        self.assertEqual(outcome['incident_id'], opened['incident_id'])
        self.assertEqual(outcome['transition'], 'resolved')

    def test_intake_still_refuses_a_severity_the_crosswalk_never_emits(self):
        store = Store(self.root / 'state.db')
        actor = Actor('gatus', 'producer')
        event = case_event(ROUND_TRIPS[2])
        event['severity'] = 'error'                       # v0.1's own word, unadmitted by construction
        with self.assertRaises(StateError):
            store.intake(event, actor, now=FIXED_NOW)
        self.assertEqual(store.records('events'), [])

    def test_no_new_producer_side_severity_literal_entered_the_tree(self):
        """The grep the card reports, pinned: five files name a severity, each with a reason to.

        `deadman.py` joined the list with job observe standard: the witness builds its own canonical event because it
        must not import platform storage (pinned in `tests/test_deadman.py`), so it repeats
        `detections.event`'s factory default — firing `warning`, resolved `info` — and invents no
        loudness of its own. A producer naming a different rung still fails here.
        """
        named = sorted(path.name for path in (ROOT / 'local_observe' / 'platform').rglob('*.py')
                       if any("'" + level + "'" in path.read_text(encoding='utf-8')
                              for level in ('critical', 'warning')))
        self.assertEqual(named, ['anomaly.py', 'deadman.py', 'detections.py', 'state.py', 'vocabulary.py'],
                         'a new producer-side severity literal: cite vocabulary.py instead, and let '
                         'detections.event derive the rest')


class ContractDocumentTests(unittest.TestCase):
    """docs/CONTRACTS.md §4.1 carries what the code can emit, in the same words."""

    def section(self) -> str:
        start = CONTRACTS.index('### 4.1 The crosswalk')
        return CONTRACTS[start:CONTRACTS.index('## 5. Operational SQLite and action lifecycle')]

    def test_every_condition_the_code_can_emit_appears_in_the_contract(self):
        section = self.section()
        for _, condition in vocabulary.TYPE_CROSSWALK.values():
            self.assertIn('`' + condition + '`', section, condition)

    def test_every_source_vocabulary_is_named_in_the_contract(self):
        section = self.section()
        for source in vocabulary.SOURCE_VOCABULARIES:
            self.assertIn('`' + source + '`', section, source)

    def test_every_refusal_is_written_down_in_the_contract(self):
        section = self.section()
        for (source, word), _reason in vocabulary.REFUSALS.items():
            self.assertIn('`' + word + '`', section,
                          f'{source}/{word} is refused in code and silent in the contract')

    def test_the_contract_states_the_boundaries_the_table_is_evidence_for(self):
        section = self.section()
        for sentence in ('a test that ran and failed is `availability`',
                         'keyed per source, never per value',
                         '`dedup_key` is not ported'):
            self.assertIn(sentence, section)


if __name__ == '__main__':
    unittest.main()

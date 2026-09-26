"""The Alertmanager adapter: field mapping, the zero-time quirk, and evidence-or-coverage per fixture.

event intake ports `legacy:aiops/ingest/adapters/alertmanager.py`. What moved unchanged is the *mapping*
(`labels.severity`, `labels.alertname`, `labels.instance`/`labels.host`, `startsAt`/`endsAt`); what
deliberately did not is v0.1's visible-but-published degradation: `severity: unknown` for an
unrecognised label, `status` defaulting to `firing`, non-object alerts wrapped and published, and
`status: resolved` recorded as a label nobody downstream could act on.

Which of the two outcomes each fixture exercises — a real event whose evidence this platform kept, or
coverage about the intake — is in the test names. The summary, per fixture:

- firing alert, declared rule, `annotations.value` a number → coverage `resolved` + the verdict: the
  payload carried a sample `Store.put_evidence` could keep.
- firing alert, declared rule, no `sample_field` in that rule → coverage `firing` only: nothing was
  captured, so the condition is not opened.
- firing alert, declared rule, value not a number or a boolean word → the same coverage-only answer:
  a placeholder row would be the synthesised reference the port table refuses.
- firing alert with no declared rule row, or with a severity word `vocabulary` refuses → coverage
  `firing` about the intake source: a `kind` or a loudness nobody named is not invented here.
- resolved alert with a usable `endsAt` → coverage `resolved` + the verdict `resolved`.
- any alert whose body is malformed → nothing at all, and a refusal naming the position: a fabricated
  firing event is worse than a lost one.
"""
import datetime as dt
import unittest

from local_observe.platform import intake, vocabulary
from local_observe.platform.state import StateError, validate_event

NOW = dt.datetime(2026, 9, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
STARTS_AT = '2026-09-08T11:50:00Z'
WINDOW_START = '2026-09-08T11:50:00.000000+00:00'
WINDOW_END = '2026-09-08T11:55:00.000000+00:00'
ZERO_ENDS_AT = '0001-01-01T00:00:00Z'
RULE = {'rule_id': 'alertmanager.high_cpu', 'kind': 'threshold', 'window_seconds': 300,
        'sample_field': 'value', 'rule_version': '1'}
DOCUMENT = {'schema_version': 1, 'sources': {'alertmanager': {'HighCPU': RULE}}}


def rules() -> dict:
    """The validated document, in the shape `prepare` reads."""
    return intake.validate_rules(DOCUMENT)


def alert(labels=None, annotations=None, **fields) -> dict:
    """One `alerts[]` entry that fires, carries a severity and a number, and knows its host.

    The same fixture helper as `tests/test_intake.py` — test files here do not import one another, so
    the duplication is deliberate and small. A bare `alertname=`/`severity=`/`instance=`/`host=`
    keyword edits `labels` (`None` deletes that label); `labels=`/`annotations=` replace those objects
    wholesale, which is how the malformed-payload tests say what they mean; any other keyword sets the
    alert's own field, including `status=None` for the tests that need the field to be nonsense.
    """
    item = {'status': 'firing',
            'labels': {'alertname': 'HighCPU', 'severity': 'crit', 'instance': 'web01:9100'},
            'annotations': {'value': '0.93'},
            'startsAt': STARTS_AT, 'endsAt': ZERO_ENDS_AT,
            'fingerprint': 'aaaa', 'generatorURL': 'http://example.invalid/graph'}
    for name in ('alertname', 'severity', 'instance', 'host'):
        if name in fields:
            merged = dict(item['labels'])
            value = fields.pop(name)
            if value is None:
                merged.pop(name, None)
            else:
                merged[name] = value
            item['labels'] = merged
    if labels is not None:
        item['labels'] = labels
    if annotations is not None:
        item['annotations'] = annotations
    item.update(fields)
    return item


def payload(*alerts, **envelope_fields) -> dict:
    """An Alertmanager webhook body; bare keywords alter the envelope, arguments are its alerts."""
    body = {'version': '4', 'groupKey': '{}:{}/{}/{}', 'status': 'firing', 'receiver': 'webhook',
            'alerts': list(alerts) or [alert()]}
    body.update(envelope_fields)
    return body


ABSENT = object()


def prepared(*, body=ABSENT, now: dt.datetime = NOW, document=ABSENT,
             index_path=None) -> list[intake.Prepared]:
    """`prepare` for the shared fixtures, so each test states only the thing it is about.

    `document` is a raw rules document and is validated here, exactly as `LO_INTAKE_RULES` is read and
    validated at process start; a test that means "no rules at all" passes `{}`.
    """
    ruleset = rules() if document is ABSENT else (intake.validate_rules(document) if document else document)
    return intake.prepare('alertmanager', payload() if body is ABSENT else body, now=now,
                          index_path=index_path, rules=ruleset)


def events(**changes) -> list[dict]:
    """The events one alert produces, altered field by field with `changes` on the alert."""
    return [item.event for item in prepared(body=payload(alert(**changes)))]


def verdict(**changes) -> dict:
    """The non-coverage event of one alert, which is what a test is usually about."""
    found = [item for item in events(**changes) if item['kind'] != 'coverage']
    if len(found) != 1:
        raise AssertionError(f'expected exactly one verdict event, got {[i["kind"] for i in found]}')
    return found[0]


def coverage(**changes) -> dict:
    """The coverage half of one alert, or the whole of a degraded one."""
    found = [item for item in events(**changes) if item['kind'] == 'coverage']
    if not found:
        raise AssertionError('no coverage event was produced')
    return found[0]


class FieldMappingTests(unittest.TestCase):
    """What each Alertmanager field becomes, and the two places v0.1's answer was not good enough."""

    def test_a_firing_alert_files_its_coverage_before_its_verdict(self):
        """The pair `detections.evaluate` emits, in that order, so coverage can never mask a finding."""
        produced = events()
        self.assertEqual([item['kind'] for item in produced], ['coverage', 'threshold'])
        self.assertEqual([item['status'] for item in produced], ['resolved', 'firing'])
        self.assertEqual(produced[0]['rule_id'], 'alertmanager.high_cpu.coverage')
        self.assertEqual(produced[1]['rule_id'], 'alertmanager.high_cpu')

    def test_the_severity_label_rides_the_crosswalk_including_its_short_spellings(self):
        """`crit`/`err`/`warn` are v0.1's alias table, and event vocabulary merged it into `vocabulary.py`.

        A test may name the target of a row: the rule the crosswalk exists to enforce is that no
        *producer* module spells a severity literal, which
        `tests/test_intake.py::SurfaceTests` checks against `intake.py` itself.
        """
        for label, expected in (('critical', 'critical'), ('crit', 'critical'),
                                ('error', 'warning'), ('err', 'warning'),
                                ('warning', 'warning'), ('warn', 'warning'),
                                ('CRIT', 'critical'), ('  Warning  ', 'warning'),
                                ('info', 'info')):
            with self.subTest(severity=label):
                self.assertEqual(verdict(severity=label)['severity'], expected)

    def test_the_short_aliases_are_the_ones_the_vocabulary_declares(self):
        """If event vocabulary's rows ever stop carrying `crit`/`err`/`warn`, this port is what breaks first."""
        for short, long in (('crit', 'critical'), ('err', 'error'), ('warn', 'warning')):
            with self.subTest(alias=short):
                self.assertEqual(verdict(severity=short)['severity'],
                                 verdict(severity=long)['severity'])

    def test_the_window_is_the_declared_interval_from_the_alert_start(self):
        """`startsAt` opens the window and the rule's `for:` closes it; `endsAt` is not consulted."""
        built = verdict()
        self.assertEqual(built['window'], {'start': WINDOW_START, 'end': WINDOW_END})
        self.assertEqual(built['observed_at'], WINDOW_START)

    def test_a_firing_alerts_scheduled_end_is_never_used_as_a_window_end(self):
        """Alertmanager puts the next repeat in `endsAt`, and `validate_event` refuses a future window."""
        built = verdict(endsAt='2026-09-08T14:00:00Z')
        self.assertEqual(built['window']['end'], WINDOW_END)
        validate_event(built, NOW)

    def test_the_zero_time_is_read_as_no_instant_rather_than_the_year_one(self):
        """The quirk, named: `0001-01-01` would otherwise make a ~2,000-year window and a refusal."""
        built = verdict(endsAt=ZERO_ENDS_AT)
        self.assertEqual(built['window'], {'start': WINDOW_START, 'end': WINDOW_END})
        for variant in ('0001-01-01T00:00:00.000Z', '0001-01-01 00:00:00 +00:00'):
            with self.subTest(endsAt=variant):
                self.assertEqual(verdict(endsAt=variant)['window'], built['window'])

    def test_a_resolution_observes_the_instant_the_condition_cleared(self):
        """`status: resolved` lands as `status='resolved'`, which is what closes an incident here."""
        ends = '2026-09-08T11:59:00Z'
        built = verdict(status='resolved', endsAt=ends)
        self.assertEqual(built['status'], 'resolved')
        self.assertEqual(built['observed_at'], '2026-09-08T11:59:00.000000+00:00')
        self.assertEqual(built['window']['end'], '2026-09-08T11:59:00.000000+00:00')

    def test_a_resolution_of_an_incident_older_than_the_window_ceiling_is_still_admissible(self):
        """A condition that fired three weeks ago must be closable: the window is the last five minutes."""
        built = verdict(status='resolved', startsAt='2026-08-19T11:50:00Z', endsAt='2026-09-08T11:59:00Z')
        self.assertEqual(built['window']['start'], '2026-09-08T11:54:00.000000+00:00')
        validate_event(built, NOW)

    def test_a_resolution_without_an_instant_is_refused_rather_than_guessed(self):
        """The zero time and an absent `endsAt` both mean nobody measured when it ended."""
        for ends_at in (ZERO_ENDS_AT, None, '', 'yesterday'):
            with self.subTest(endsAt=ends_at):
                with self.assertRaises(StateError) as caught:
                    events(status='resolved', endsAt=ends_at)
                self.assertIn('endsAt', str(caught.exception))

    def test_a_recovery_never_borrows_the_loudness_of_the_failure_it_ended(self):
        """docs/CONTRACTS.md §4.1: the mapped word describes the firing verdict, so a recovery is `info`."""
        self.assertEqual(verdict(status='resolved', severity='crit',
                                endsAt='2026-09-08T11:59:00Z')['severity'], 'info')

    def test_status_is_read_without_case_or_surrounding_space(self):
        """' Resolved ' is the same transition; anything else is not a transition at all."""
        self.assertEqual(coverage(status=' RESOLVED ', endsAt='2026-09-08T11:59:00Z')['status'], 'resolved')

    def test_a_status_that_is_neither_word_is_refused_rather_than_defaulted_to_firing(self):
        """v0.1 wrote `firing` for anything it did not recognise, which pages on a typo."""
        for status in (None, '', 'resolved?', 'unknown', 7, {'x': 1}):
            with self.subTest(status=status):
                with self.assertRaises(StateError):
                    events(status=status)

    def test_a_future_start_is_refused_by_this_module_and_not_left_to_the_state_layer(self):
        """The contract rule is `observed_at` may not be future; the refusal says which alert did it."""
        with self.assertRaises(StateError) as caught:
            events(startsAt='2026-09-08T12:05:00Z')
        self.assertIn('future observed_at', str(caught.exception))

    def test_an_alert_that_has_not_completed_its_declared_window_is_refused(self):
        """No window may be invented to make an alert admissible: five minutes is five minutes."""
        with self.assertRaises(StateError) as caught:
            prepared(body=payload(alert(startsAt='2026-09-08T11:59:30Z')), now=NOW)
        self.assertIn('not completed its declared evaluation window', str(caught.exception))

    def test_an_unparseable_or_naive_timestamp_is_refused_naming_the_field(self):
        """v0.1 passed whatever text it found onwards; here a naive time is a refusal."""
        for starts_at in ('2026-09-08T11:50:00', 'yesterday', '2026-09-08 11:50', 1756468200, True):
            with self.subTest(startsAt=starts_at):
                with self.assertRaises(StateError) as caught:
                    events(startsAt=starts_at)
                self.assertIn('startsAt', str(caught.exception))

    def test_the_envelope_level_status_is_not_the_alerts_status(self):
        """A group is a delivery artefact; the per-alert status is the truth of one condition."""
        produced = [item.event for item in prepared(body=payload(status='resolved'))]
        verdicts = [item for item in produced if item['kind'] != 'coverage']
        self.assertEqual([item['status'] for item in verdicts], ['firing'])

    def test_the_alert_name_is_read_from_labels_and_from_nowhere_else(self):
        """An `alertname` in `annotations` describes the alert; it does not name the rule that spoke."""
        produced = events(labels={'alertname': 'Other', 'severity': 'crit', 'instance': 'web01'},
                          annotations={'value': '0.93', 'alertname': 'HighCPU'})
        self.assertEqual([item['kind'] for item in produced], ['coverage'])
        self.assertEqual(produced[0]['rule_id'], intake.UNDECLARED_RULE_COVERAGE)

    def test_the_rule_version_is_the_declaration_and_not_something_read_off_the_payload(self):
        """Nothing in an Alertmanager payload identifies a rule's version; the operator's row does."""
        self.assertEqual(verdict()['rule_version'], '1')
        document = {'schema_version': 1, 'sources': {'alertmanager': {'HighCPU': {
            **RULE, 'rule_version': '2026-09-08'}}}}
        self.assertEqual(verdicts_version(document), '2026-09-08')


def verdicts_version(document: dict) -> str:
    """The verdict's rule version under a different declaration."""
    return [item for item in prepared(document=document) if item.event['kind'] != 'coverage'][0] \
        .event['rule_version']


class EnvelopeShapeTests(unittest.TestCase):
    """A payload that cannot be read is refused whole. v0.1 published these; nothing here is admitted."""

    def test_a_non_object_body_is_refused(self):
        for body in (None, [], 'alerts', 7, True):
            with self.subTest(body=body):
                with self.assertRaises(StateError):
                    prepared(body=body)

    def test_a_body_without_an_alerts_list_is_refused_naming_the_field(self):
        """A single bare alert is not accepted either: one shape, so one answer to "what posted?"."""
        for body in ({}, {'alert': []}, {'alerts': 'nope'}, {'alerts': {}},
                     alert()):
            with self.subTest(body=sorted(body)[:3]):
                with self.assertRaises(StateError) as caught:
                    prepared(body=body)
                self.assertIn('alerts', str(caught.exception))

    def test_an_empty_envelope_is_refused_rather_than_treated_as_all_clear(self):
        """`{"alerts": []}` says nothing; reading it as a recovery would close an incident."""
        for body in ({'alerts': []}, {'version': '4', 'status': 'resolved', 'alerts': []}):
            with self.subTest(body=body):
                with self.assertRaises(StateError):
                    prepared(body=body)

    def test_a_resolution_that_ended_before_it_started_is_refused(self):
        """An inverted pair of instants is a broken payload, not a condition that closed in the past."""
        with self.assertRaises(StateError) as caught:
            events(status='resolved', startsAt='2026-09-08T11:59:00Z', endsAt='2026-09-08T11:50:00Z')
        self.assertIn('resolved before it started', str(caught.exception))

    def test_an_envelope_over_the_documented_ceiling_is_refused_not_truncated(self):
        """Dropping the tail would silently drop an outage with it."""
        many = [alert(labels={'alertname': 'UnDeclared', 'severity': 'crit', 'instance': 'web01'})
                for _index in range(intake.MAX_ENVELOPE_ALERTS + 1)]
        with self.assertRaises(StateError) as caught:
            prepared(body=payload(*many))
        self.assertIn(str(intake.MAX_ENVELOPE_ALERTS), str(caught.exception))

    def test_the_ceiling_itself_is_accepted(self):
        """The bound is inclusive, so a test must sit on it and not beside it."""
        many = [alert(labels={'alertname': 'UnDeclared', 'severity': 'crit', 'instance': 'web01'})
                for _index in range(intake.MAX_ENVELOPE_ALERTS)]
        self.assertEqual(len(prepared(body=payload(*many))), intake.MAX_ENVELOPE_ALERTS)

    def test_a_non_object_alert_refuses_the_envelope_instead_of_being_wrapped(self):
        """v0.1 turned a stray string into `{'summary': repr(alert)}` and published it."""
        for bad in ('a line of text', 7, None, []):
            with self.subTest(alert=bad):
                with self.assertRaises(StateError) as caught:
                    prepared(body={'alerts': [alert(), bad]})
                self.assertIn('alert 1', str(caught.exception))

    def test_labels_and_annotations_must_be_bounded_string_documents(self):
        """`str(None)` writing `None` into a comparison is how an absent field looks chosen."""
        for labels in ('nope', {'severity': 7}, {'severity': None}, {7: 'x'},
                       {f'k{index}': 'v' for index in range(intake.MAX_LABELS + 1)},
                       {'severity': 'x' * 300}):
            with self.subTest(labels=labels):
                with self.assertRaises(StateError):
                    events(labels=labels)
        for annotations in ('nope', {'value': 7}, {'a' * 300: 'x'},
                            {f'k{index}': 'v' for index in range(intake.MAX_ANNOTATIONS + 1)}):
            with self.subTest(annotations=annotations):
                with self.assertRaises(StateError):
                    events(annotations=annotations)

    def test_absent_labels_are_the_undeclared_case_rather_than_a_crash(self):
        """v0.1 tolerated a missing labels object; so does this, and it becomes coverage."""
        item = alert()
        del item['labels']
        produced = prepared(body=payload(item))
        self.assertEqual(produced[0].event['rule_id'], intake.UNDECLARED_RULE_COVERAGE)
        # No index was configured for this app, which is reported apart from "looked and found nothing".
        self.assertEqual(produced[0].link, 'not_configured')

    def test_one_position_names_the_refusal_so_a_group_of_fifty_says_which_one(self):
        """The alert index is the only part of a payload a refusal may echo, and it is an integer."""
        with self.assertRaises(StateError) as caught:
            prepared(body=payload(alert(), alert(), alert(status='sideways')))
        self.assertIn('alert 2', str(caught.exception))


class EvidenceOrCoverageTests(unittest.TestCase):
    """§6's rule in force: a reference only ever names a sample this platform captured."""

    def test_a_payload_carrying_a_number_yields_a_sample_to_keep(self):
        """Exactly the shape `Store.put_evidence` admits, and nothing beyond it."""
        kept = prepared()[1].sample
        self.assertEqual(set(kept), {'sample_id', 'observed_at', 'ok', 'value'})
        self.assertEqual(kept['value'], 0.93)
        self.assertIs(kept['ok'], True)
        self.assertEqual(kept['observed_at'], WINDOW_START)

    def test_the_captured_sample_is_referenced_as_a_snapshot_not_a_threshold(self):
        """This process compared nothing to a limit; `metric-threshold` would claim that it did."""
        built = verdict()
        self.assertEqual(built['evidence'][0]['query_type'], 'observed-snapshot')
        self.assertEqual(sorted(built['evidence'][0]['parameters']), ['rule_id', 'sample_id'])

    def test_the_reference_outlives_the_window_it_describes(self):
        """`expires_at` at or before the window end is refused by intake, so it must be beyond it."""
        built = verdict()
        self.assertGreater(built['evidence'][0]['expires_at'], built['window']['end'])
        self.assertEqual(built['evidence'][0]['window'], built['window'])

    def test_a_rule_that_declares_no_sample_field_produces_coverage_only(self):
        """No capture, no verdict, no incident on the watched condition."""
        document = {'schema_version': 1, 'sources': {'alertmanager': {
            'HighCPU': {'rule_id': 'alertmanager.high_cpu', 'kind': 'availability'}}}}
        produced = prepared(document=document)
        self.assertEqual([item.event['kind'] for item in produced], ['coverage'])
        self.assertEqual(produced[0].event['status'], 'firing')
        self.assertIsNone(produced[0].sample)
        self.assertEqual(produced[0].event['evidence'][0]['query_type'], 'source-heartbeat')

    def test_a_value_that_is_not_a_number_or_a_boolean_word_is_no_sample_at_all(self):
        """A placeholder row would be the synthesised reference this port exists to refuse."""
        for value in ('', '   ', 'n/a', 'nan', 'inf', '-Infinity', '1e999', 'x' * 40, '0.9.3', None):
            with self.subTest(value=value):
                body = payload(alert(annotations={'value': value} if value is not None else {}))
                produced = prepared(body=body)
                self.assertEqual([item.event['kind'] for item in produced], ['coverage'])
                self.assertIsNone(produced[0].sample)

    def test_a_boolean_word_is_a_sample_because_the_store_keeps_booleans(self):
        """`true`/`false` in any case, so an availability alert can carry its own answer."""
        for value, expected in (('true', True), ('TRUE', True), (' false', False), ('False', False)):
            with self.subTest(value=value):
                self.assertEqual(prepared(body=payload(alert(annotations={'value': value})))[1].sample['value'],
                                 expected)

    def test_a_number_is_kept_as_a_number_not_as_the_text_the_alert_carried(self):
        """A sample of text is not a value the platform can compare to anything later."""
        for value, expected in (('-3', -3.0), (' 42 ', 42.0), ('0', 0.0), ('1e3', 1000.0)):
            with self.subTest(value=value):
                kept = prepared(body=payload(alert(annotations={'value': value})))[1].sample
                self.assertEqual(kept['value'], expected)
                self.assertIsInstance(kept['value'], float)

    def test_the_sample_identity_repeats_for_a_repeated_alert(self):
        """`put_evidence` folds a retry only when the name is the same and the bytes agree."""
        first = prepared()[1].sample['sample_id']
        second = prepared(now=NOW + dt.timedelta(minutes=30))[1].sample['sample_id']
        self.assertEqual(first, second)

    def test_a_different_value_is_a_different_sample_not_an_edit_of_the_previous_one(self):
        """Two readings of one window must not overwrite each other under one name."""
        low = prepared(body=payload(alert(annotations={'value': '0.93'})))[1].sample['sample_id']
        high = prepared(body=payload(alert(annotations={'value': '0.99'})))[1].sample['sample_id']
        self.assertNotEqual(low, high)

    def test_the_resolution_of_a_rule_that_carries_no_sample_still_closes_the_condition(self):
        """The asymmetry, stated: evidence is required to OPEN a condition, never to close one."""
        document = {'schema_version': 1, 'sources': {'alertmanager': {
            'HighCPU': {'rule_id': 'alertmanager.high_cpu', 'kind': 'availability'}}}}
        produced = prepared(document=document,
                            body=payload(alert(status='resolved', endsAt='2026-09-08T11:59:00Z')))
        self.assertEqual([item.event['kind'] for item in produced], ['coverage', 'availability'])
        self.assertEqual([item.event['status'] for item in produced], ['resolved', 'resolved'])
        self.assertEqual(produced[1].event['evidence'][0]['query_type'], 'source-heartbeat')
        self.assertIsNone(produced[1].sample)


class DegradationTests(unittest.TestCase):
    """An alert that cannot become a verdict still says something true: coverage about the intake."""

    def test_an_undeclared_alert_name_opens_coverage_about_the_intake_not_the_condition(self):
        """One event, `kind='coverage'`, naming the source's own rule; nothing claims the host is sick."""
        produced = events(labels={'alertname': 'BrandNewRule', 'severity': 'crit', 'instance': 'web01'})
        self.assertEqual(len(produced), 1)
        self.assertEqual(produced[0]['kind'], 'coverage')
        self.assertEqual(produced[0]['rule_id'], intake.UNDECLARED_RULE_COVERAGE)
        self.assertEqual(produced[0]['condition'], intake.UNDECLARED_RULE_COVERAGE)
        self.assertNotIn('BrandNewRule', str(produced))

    def test_a_refused_severity_word_is_coverage_and_never_a_guessed_rung(self):
        """`none` and `unknown` are refusals event vocabulary wrote down; both land as coverage about the source."""
        for severity in ('none', 'unknown', 'fatal', '', None):
            with self.subTest(severity=severity):
                labels = {'alertname': 'HighCPU', 'instance': 'web01'}
                if severity is not None:
                    labels['severity'] = severity
                produced = events(labels=labels)
                self.assertEqual([item['kind'] for item in produced], ['coverage'])
                self.assertEqual(produced[0]['rule_id'], intake.SEVERITY_REFUSED_COVERAGE)
                self.assertEqual(produced[0]['status'], 'firing')

    def test_the_two_gaps_never_share_a_condition_key(self):
        """An undeclared rule and an unlabelled one page differently, so they must not fold together."""
        undeclared = events(labels={'alertname': 'New', 'severity': 'crit'})[0]
        unlabelled = events(labels={'alertname': 'HighCPU', 'instance': 'web01'})[0]
        self.assertEqual(undeclared['kind'], unlabelled['kind'])
        self.assertNotEqual(undeclared['condition'], unlabelled['condition'])

    def test_a_coverage_event_references_the_platform_receipt_and_no_sample(self):
        """`source-heartbeat` is the one legal form for "this source spoke about this rule"."""
        item = prepared(body=payload(alert(labels={'alertname': 'New', 'severity': 'crit'})))[0]
        self.assertEqual(item.sample, None)
        evidence = item.event['evidence'][0]
        self.assertEqual(evidence['query_type'], 'source-heartbeat')
        self.assertEqual(evidence['parameters'], {'rule_id': 'alertmanager'})


class VocabularyBoundaryTests(unittest.TestCase):
    """Where the severity table lives, and the fact that this module does not own one."""

    def test_the_alias_table_used_here_is_the_one_r_p02_merged(self):
        """`vocabulary.SEVERITY_CROSSWALK` carries alertmanager's rows; `intake` adds none."""
        for word in ('critical', 'crit', 'error', 'err', 'warning', 'warn', 'info'):
            with self.subTest(word=word):
                self.assertEqual(verdict(severity=word)['severity'],
                                 vocabulary.severity('alertmanager', word))
        self.assertEqual(intake.SOURCE_VOCABULARY, 'alertmanager')

    def test_the_refused_words_are_refusals_in_the_vocabulary_too(self):
        """If event vocabulary ever maps `none`, this module's coverage path becomes dead code and a test fails."""
        refused = dict(vocabulary.REFUSALS)
        for word in ('none', 'unknown'):
            self.assertIn(('alertmanager', word), refused)
            with self.assertRaises(vocabulary.VocabularyError):
                vocabulary.severity('alertmanager', word)

    def test_the_kind_never_comes_from_the_alert_name(self):
        """`classify('alertmanager', anything)` refuses, so the declared row is the only door."""
        for name in ('http', 'probe.check_failed', 'HighCPU', 'finding'):
            with self.assertRaises(vocabulary.VocabularyError):
                vocabulary.classify('alertmanager', name)
        document = {'schema_version': 1, 'sources': {'alertmanager': {
            'HighCPU': {**RULE, 'kind': 'drift'}}}}
        produced = prepared(document=document)
        self.assertIn('drift', {item.event['kind'] for item in produced if item.event['kind'] != 'coverage'})

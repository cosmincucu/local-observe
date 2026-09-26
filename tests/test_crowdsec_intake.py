"""The CrowdSec inbound adapter (crowdsec task 3): the envelope, the evidence rule, the identity rule.

crowdsec does not build an emitter. It plugs a source into `event intake`'s normaliser, so these tests are mostly
about the four rules `intake.py` states at the top of its own docstring and what a second source must
not break while joining them:

* **evidence, or coverage** — a CrowdSec alert is only a verdict if the payload carried a keepable
  reading: its native integer `events_count` or an explicitly selected metadata value;
* **linking is enrichment** — `source.value` is asked of the declared index and a name that does not
  resolve lands as an admitted `resource_id = None` plus a visible `resource_link`;
* **a malformed payload is refused, not degraded** — the whole envelope, with the alert's position in
  the sentence;
* **loudness and kind come from the vocabulary, not the payload** — the reverse of Alertmanager's fourth
  rule, because `crowdsec` is the source that *does* declare a closed type space (`alert` → `security`)
  and *no* severity words at all.

The §5 proving combination this item borrows is `Security detection`: positive fixture, negative fixture,
absent sensor, replay. Those four clauses are named in the test docstrings below, and `conformance.md`
maps each one to a run recipe that has not been run. Nothing here binds or connects a socket; the route
tests drive the ASGI app in process, the way `tests/test_platform_api_intake.py` does.
"""
import asyncio
import datetime as dt
import json
from pathlib import Path
import re
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document
from local_observe.platform import crowdsec, intake
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store, validate_event

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 9, 9, 12, 0, 0, tzinfo=dt.timezone.utc)
START = '2026-09-09T11:00:00.123456789Z'
STOP = '2026-09-09T11:02:00.123456789Z'
SCENARIO = 'crowdsecurity/ssh-bf'
HOST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
DECLARED_IP = '10.11.0.21'
PRODUCER = {'identity': 'crowdsec', 'role': 'producer', 'token': 'p' * 32}
WRONG = {'identity': 'alertmanager', 'role': 'producer', 'token': 'w' * 32}
READER = {'identity': 'watcher', 'role': 'reader', 'token': 'r' * 32}
CREDENTIALS = [PRODUCER, WRONG, READER]
DOCUMENT = {'schema_version': 1, 'sources': {
    'crowdsec': {SCENARIO: {'rule_id': 'crowdsec.ssh-brute-force', 'kind': 'security',
                            'window_seconds': 120, 'sample_field': 'alert.events_count'}}}}


def alert(**changes) -> dict:
    """One `models.Alert` in the shape the HTTP plugin's default template posts.

    Field names are `pkg/models/alert.go` at v1.8.1 (`scenario`, `uuid`, `start_at`, `stop_at`,
    `source`, `events_count`, `events[].meta`); `10.11.0.21` is the address the shipped inventory fixture declares, so
    the default alert is the *linked* case and `source=` is the unlinked one.
    """
    item = {'uuid': 'a' * 32, 'scenario': SCENARIO, 'start_at': START, 'stop_at': STOP,
            'source': {'scope': 'Ip', 'value': DECLARED_IP, 'ip': DECLARED_IP},
            'events': [{'timestamp': STOP,
                        'meta': [{'key': 'service', 'value': 'ssh'},
                                 {'key': 'source_ip', 'value': DECLARED_IP}]}],
            'capacity': 5, 'events_count': 12, 'remediation': True, 'simulated': True,
            'machine_id': 'crowdsec', 'labels': ['crowdsecurity/ssh'], 'message': 'ssh brute force',
            'decisions': [{'scope': 'Ip', 'value': DECLARED_IP, 'type': 'ban', 'duration': '4h',
                           'origin': 'crowdsec', 'scenario': SCENARIO}]}
    for name, value in changes.items():
        if value is None:
            item.pop(name, None)
        else:
            item[name] = value
    return item


class RegistrationTests(unittest.TestCase):
    """The source exists because the registry says so, and its rules cannot widen a closed vocabulary."""

    def test_crowdsec_is_a_registered_intake_source(self):
        self.assertIn(crowdsec.SOURCE, intake.adapters())

    def test_importing_the_module_twice_registers_nothing_twice(self):
        """`register` is idempotent, because an import that could fail `api`'s start-up is a defect."""
        crowdsec.register()
        crowdsec.register()
        self.assertEqual(list(intake.adapters()).count(crowdsec.SOURCE), 1)

    def test_the_source_word_is_the_one_the_vocabulary_already_declares(self):
        """This adds a producer to an existing word, not a new word: `alert` and `coverage` only."""
        from local_observe.platform import vocabulary
        self.assertEqual(vocabulary.declared_types(crowdsec.SOURCE), ('alert', 'coverage'))
        self.assertEqual(vocabulary.classify(crowdsec.SOURCE, 'alert'), ('security', 'crowdsec.alert'))
        self.assertEqual(vocabulary.declared_severities(crowdsec.SOURCE), ())

    def test_a_rule_row_naming_a_kind_the_source_does_not_admit_is_refused(self):
        broken = json.loads(json.dumps(DOCUMENT))
        broken['sources']['crowdsec'][SCENARIO]['kind'] = 'availability'
        with self.assertRaises(StateError) as caught:
            crowdsec.validate_rules(broken)
        self.assertIn('closed vocabulary', str(caught.exception))
        # intake alone accepts it: the guard is this source's, and it must be this source's call.
        self.assertIn('availability', {row['kind'] for row in intake.validate_rules(broken)['crowdsec'].values()})

    def test_no_rules_configured_is_a_refusal_and_not_a_wildcard(self):
        with self.assertRaises(StateError) as caught:
            intake.prepare(crowdsec.SOURCE, [alert()], now=NOW, rules={'crowdsec': {}})
        self.assertIn('No intake rules are configured', str(caught.exception))

    def test_the_alert_bound_is_the_number_the_documented_envelope_bound_is(self):
        """Pinned equal, not aliased: a source's bound may move alone, but only in a reviewed change."""
        self.assertEqual(crowdsec.MAX_ALERTS, intake.MAX_ENVELOPE_ALERTS)


class SecurityDetectionTests(unittest.TestCase):
    """The four §5 clauses this component borrows, one test each, on the fixture pair."""

    def setUp(self):
        self.rules = crowdsec.validate_rules(DOCUMENT)

    def prepare(self, payload, **kwargs):
        return intake.prepare(crowdsec.SOURCE, payload, now=NOW, rules=self.rules, **kwargs)

    def test_positive_fixture_a_declared_alert_becomes_coverage_then_a_security_finding(self):
        """`Security detection`: the positive reference fixture, in the order intake must write it."""
        coverage, finding = self.prepare([alert()])
        self.assertEqual(coverage.event['kind'], 'coverage')
        self.assertEqual(coverage.event['status'], 'resolved')
        self.assertEqual(coverage.event['rule_id'], 'crowdsec.ssh-brute-force.coverage')
        self.assertIsNone(coverage.sample)
        self.assertEqual(finding.event['kind'], 'security')
        self.assertEqual(finding.event['status'], 'firing')
        self.assertEqual(finding.event['source'], 'crowdsec')
        # Severity is the factory's for a firing verdict: this source declares no severity words, so no
        # argument is ever passed and a payload that carried one would be ignored, not obeyed.
        self.assertEqual(finding.event['severity'], 'warning')
        self.assertEqual(finding.event['evidence'][0]['query_type'], 'observed-snapshot')
        self.assertTrue(finding.sample)
        self.assertEqual(finding.sample['value'], 12.0)
        self.assertEqual(finding.sample['observed_at'], finding.event['window']['end'])

    def test_both_events_are_admissible_canonical_events(self):
        """The route validates with `state.validate_event`; doing it here says the shape is honest."""
        for item in self.prepare([alert()]):
            validate_event(item.event, NOW)

    def test_negative_fixture_an_undeclared_scenario_is_coverage_and_opens_no_condition(self):
        """"Negative fixture": a scenario nobody declared must not become a verdict by guessing."""
        produced = self.prepare([alert(scenario='crowdsecurity/unknown-thing')])
        self.assertEqual(len(produced), 1)
        event = produced[0].event
        self.assertEqual(event['kind'], 'coverage')
        self.assertEqual(event['status'], 'firing')
        self.assertEqual(event['rule_id'], crowdsec.UNDECLARED_SCENARIO_COVERAGE)
        self.assertIsNone(produced[0].sample)

    def test_absent_sensor_the_coverage_condition_is_the_one_intake_wrote(self):
        """`Absent sensor detected`: the coverage row names the rule it is coverage *of*."""
        coverage, finding = self.prepare([alert()])
        self.assertEqual(coverage.event['evidence'][0]['parameters'],
                         {'rule_id': 'crowdsec.ssh-brute-force'})
        self.assertEqual(coverage.event['window'], finding.event['window'])
        self.assertEqual(coverage.event['resource_id'], finding.event['resource_id'])

    def test_a_declared_alert_with_no_keepable_reading_is_coverage_and_not_a_verdict(self):
        """The evidence rule, not the coverage rule: §6 forbids a synthesised reference outright."""
        for raw in (None, '', '12', 'not-a-number', float('nan'), float('inf'), 12.0, 1.5,
                    True, False, -1, 2 ** 31, [], {}):
            with self.subTest(value=raw):
                produced = self.prepare([alert(events_count=raw)])
                self.assertEqual(len(produced), 1, 'a verdict arrived with nothing behind it')
                self.assertEqual(produced[0].event['kind'], 'coverage')
                self.assertEqual(produced[0].event['status'], 'firing')
                self.assertIsNone(produced[0].sample)

    def test_native_count_boundaries_do_not_depend_on_retained_event_details(self):
        for count in (0, 12, 2 ** 31 - 1):
            for events in ([], alert()['events']):
                with self.subTest(count=count, retained=len(events)):
                    coverage, finding = self.prepare([alert(events_count=count, events=events)])
                    self.assertEqual(coverage.event['status'], 'resolved')
                    self.assertEqual(finding.sample['value'], count)
                    self.assertIs(type(finding.sample['value']), int)

    def test_existing_metadata_selectors_keep_numeric_and_boolean_readings(self):
        document = json.loads(json.dumps(DOCUMENT))
        document['sources']['crowdsec'][SCENARIO]['sample_field'] = 'metric:events_count'
        rules = crowdsec.validate_rules(document)
        for raw, expected in (('12', 12.0), ('true', True), ('false', False)):
            with self.subTest(value=raw):
                item = alert(events_count=999, events=[{
                    'timestamp': STOP, 'meta': [{'key': 'metric:events_count', 'value': raw}]}])
                _, finding = intake.prepare(crowdsec.SOURCE, [item], now=NOW, rules=rules)
                self.assertEqual(finding.sample['value'], expected)
                self.assertIs(type(finding.sample['value']), type(expected))
        for raw in (None, 'nan', 'inf', 'not-a-number'):
            with self.subTest(value=raw):
                meta = [] if raw is None else [{'key': 'metric:events_count', 'value': raw}]
                produced = intake.prepare(crowdsec.SOURCE, [alert(events=[{'meta': meta}])],
                                          now=NOW, rules=rules)
                self.assertEqual(len(produced), 1, 'legacy selector fell back to the native count')
                self.assertEqual(produced[0].event['kind'], 'coverage')
                self.assertIsNone(produced[0].sample)

    def test_native_selector_does_not_fall_back_to_metadata(self):
        item = alert(events_count=None, events=[{
            'meta': [{'key': 'alert.events_count', 'value': '12'},
                     {'key': 'metric:events_count', 'value': '12'}]}])
        produced = self.prepare([item])
        self.assertEqual(len(produced), 1)
        self.assertEqual(produced[0].event['kind'], 'coverage')
        self.assertIsNone(produced[0].sample)


class LinkingTests(unittest.TestCase):
    """`source.value` is enrichment: asked of the declared index, never invented from a name."""

    def setUp(self):
        self.rules = crowdsec.validate_rules(DOCUMENT)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.index_path = Path(self.temp.name) / 'inventory.db'
        index.build(read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml'), self.index_path,
                    'fixture-v1', now=NOW)

    def test_an_address_the_declaration_names_is_linked_to_its_uuid(self):
        produced = intake.prepare(crowdsec.SOURCE, [alert()], now=NOW, index_path=self.index_path,
                                  rules=self.rules)
        for item in produced:
            self.assertEqual(item.link, 'resolved')
            self.assertEqual(item.event['resource_id'], HOST_ID)

    def test_an_address_no_one_declared_is_admitted_unresolved_and_says_so(self):
        """"A null `resource_id` is the admitted answer", and `resource_link` is where it is visible."""
        item = alert(source={'scope': 'Ip', 'value': '203.0.113.77'})
        produced = intake.prepare(crowdsec.SOURCE, [item], now=NOW, index_path=self.index_path,
                                  rules=self.rules)
        for item in produced:
            self.assertIsNone(item.event['resource_id'])
            self.assertEqual(item.link, 'unknown')

    def test_no_index_configured_links_as_not_configured_rather_than_as_unknown(self):
        produced = intake.prepare(crowdsec.SOURCE, [alert()], now=NOW, rules=self.rules)
        self.assertEqual({item.link for item in produced}, {'not_configured'})


class RefusalTests(unittest.TestCase):
    """A malformed payload is refused whole, and the sentence names the position that broke."""

    def setUp(self):
        self.rules = crowdsec.validate_rules(DOCUMENT)

    def refuse(self, payload, marker):
        with self.assertRaises(StateError) as caught:
            intake.prepare(crowdsec.SOURCE, payload, now=NOW, rules=self.rules)
        self.assertIn(marker, str(caught.exception))

    def test_both_shipped_forms_carry_the_same_array(self):
        """The wrapped object is what the route can deliver; the bare array is what a fixture file holds."""
        wrapped = intake.prepare(crowdsec.SOURCE, {crowdsec.ALERTS_KEY: [alert()]}, now=NOW,
                                 rules=self.rules)
        bare = intake.prepare(crowdsec.SOURCE, [alert()], now=NOW, rules=self.rules)
        self.assertEqual([item.event for item in wrapped], [item.event for item in bare])

    def test_the_envelope_must_hold_an_alert_array_and_little_else(self):
        self.refuse({'alerts': 'many'}, 'must be an alert array')
        self.refuse({'alerts': [alert()], 'source': 'crowdsec'}, 'must be an alert array')
        self.refuse({'version': '4', 'alerts': [alert()]}, 'must be an alert array')
        self.refuse([], 'must carry between 1 and')
        self.refuse({crowdsec.ALERTS_KEY: []}, 'must carry between 1 and')
        self.refuse([alert()] * (crowdsec.MAX_ALERTS + 1), 'must carry between 1 and')

    def test_a_malformed_alert_refuses_the_whole_envelope(self):
        """"Nothing is admitted when the envelope cannot be read" — the sibling half of `intake`'s rule 3."""
        good = alert()
        for broken, marker in (('not-an-object', 'is not an object'),
                              (alert(scenario=None), 'unusable scenario'),
                              (alert(uuid=None), 'unusable uuid'),
                              (alert(uuid='x' * 200), 'unusable uuid'),
                              (alert(start_at=None), 'unusable start_at'),
                              (alert(start_at='2026-09-09T11:00:00'), 'naive start_at'),
                              (alert(start_at='yesterday'), 'unparseable start_at'),
                              (alert(source=None), 'no source object'),
                              (alert(source={'scope': 'Ip'}), 'unusable source.value'),
                              (alert(events='many'), 'events value that is not a list'),
                              (alert(events=[{'timestamp': STOP}] * (crowdsec.MAX_EVENTS_PER_ALERT + 1)),
                               'exceeds the per-alert event bound'),
                              (alert(events=[{'meta': [{'key': 'k'}]}]), 'unusable meta entry')):
            with self.subTest(alert=str(broken)[:40]):
                self.refuse({crowdsec.ALERTS_KEY: [good, broken]}, marker)

    def test_windows_that_cannot_be_honest_are_refused(self):
        limit = NOW + dt.timedelta(minutes=30)
        for changes, marker in (('stop_at', 'ends before it starts'),
                                ('future', 'future observed_at'),
                                ('long', 'bounded evaluation window')):
            with self.subTest(case=changes):
                if changes == 'stop_at':
                    self.refuse([alert(start_at='2026-09-09T11:02:00Z', stop_at='2026-09-09T11:01:00Z')],
                                marker)
                elif changes == 'future':
                    self.refuse([alert(start_at=limit.isoformat().replace('+00:00', 'Z'),
                                       stop_at=(limit + dt.timedelta(minutes=2)
                                                ).isoformat().replace('+00:00', 'Z'))], marker)
                else:
                    self.refuse([alert(start_at='2026-01-01T00:00:00Z', stop_at='2026-09-09T00:00:00Z')],
                                marker)

    def test_a_missing_stop_at_uses_the_span_the_rule_declared_and_no_longer(self):
        """`window_seconds` is read only here, and it is the rule's number, not the payload's silence."""
        rows = intake.validate_rules({'schema_version': 1, 'sources': {crowdsec.SOURCE: {
            SCENARIO: {'rule_id': 'crowdsec.ssh-brute-force', 'kind': 'security',
                       'window_seconds': 60, 'sample_field': 'alert.events_count'}}}})
        window = intake.prepare(crowdsec.SOURCE, [alert(stop_at=None)], now=NOW, rules=rows)[0].event['window']
        self.assertEqual(window['start'], intake.utc_text(dt.datetime.fromisoformat(
            '2026-09-09T11:00:00.123456+00:00')))
        self.assertEqual(window['end'], intake.utc_text(dt.datetime.fromisoformat(
            '2026-09-09T11:01:00.123456+00:00')))

    def test_a_missing_stop_at_reads_as_the_declared_span_and_not_as_forever(self):
        produced = intake.prepare(crowdsec.SOURCE, [alert(stop_at=None)], now=NOW,
                                  rules=self.rules)
        window = produced[0].event['window']
        self.assertEqual(window['start'], intake.utc_text(dt.datetime.fromisoformat(
            '2026-09-09T11:00:00.123456+00:00')))
        self.assertEqual(window['end'], intake.utc_text(dt.datetime.fromisoformat(
            '2026-09-09T11:02:00.123456+00:00')))

    def test_upstreams_zero_time_is_absent_and_never_the_year_one(self):
        produced = intake.prepare(crowdsec.SOURCE, [alert(stop_at='0001-01-01T00:00:00Z')], now=NOW,
                                  rules=self.rules)
        self.assertTrue(produced[0].event['window']['end'].startswith('2026-09-09'))

    def test_a_rule_row_that_disagrees_with_the_vocabulary_refuses_at_the_alert_too(self):
        """The boot-time check is `validate_rules`; this is the same guard on the path that has no boot."""
        rows = intake.validate_rules({'schema_version': 1, 'sources': {'crowdsec': {
            SCENARIO: {'rule_id': 'crowdsec.ssh-brute-force', 'kind': 'availability'}}}})
        with self.assertRaises(StateError) as caught:
            intake.prepare(crowdsec.SOURCE, [alert()], now=NOW, rules=rows)
        self.assertIn('does not allow', str(caught.exception))


class IdentityTests(unittest.TestCase):
    """§5's "replay does not multiply findings", and the collision that would otherwise 400 an envelope."""

    def setUp(self):
        self.rules = crowdsec.validate_rules(DOCUMENT)

    def canonical(self, payload):
        return [json.dumps(item.event, sort_keys=True)
                for item in intake.prepare(crowdsec.SOURCE, payload, now=NOW, rules=self.rules)]

    def test_reposting_the_same_notification_is_byte_identical(self):
        """Determinism is what turns a retry into `duplicate` rather than into a second incident."""
        self.assertEqual(self.canonical([alert()]), self.canonical([alert()]))

    def test_the_same_id_is_the_row_intake_holds_and_no_other_alert_shares_it(self):
        """"Replay does not multiply findings", asserted on the identity `events UNIQUE` actually keys."""
        first, second = self.canonical([alert()]), self.canonical([alert()])
        self.assertEqual([row['source_event_id'] for row in map(json.loads, first)],
                         [row['source_event_id'] for row in map(json.loads, second)])
        rows = list(map(json.loads, self.canonical([alert(), alert(uuid='b' * 32)])))
        findings = [row for row in rows if row['kind'] == 'security']
        self.assertEqual(len({row['source_event_id'] for row in findings}), 2,
                         'two alerts of one scenario in one window collided on one finding')
        gaps = [row for row in rows if row['kind'] == 'coverage']
        self.assertEqual(len({row['source_event_id'] for row in gaps}), 1,
                         'one window is one coverage fact: two alerts must not write it twice')

    def test_two_alerts_in_one_window_do_not_answer_event_retry_changed_contents(self):
        """The collision this card's identity rule exists to prevent, stated as its own test."""
        produced = intake.prepare(crowdsec.SOURCE, [alert(), alert(uuid='b' * 32, events_count=99)],
            now=NOW, rules=self.rules)
        findings = [item for item in produced if item.event['kind'] == 'security']
        self.assertEqual(len(findings), 2)
        self.assertNotEqual(findings[0].event['source_event_id'], findings[1].event['source_event_id'])

    def test_coverage_identity_keys_on_status_so_firing_and_resolved_are_two_rows(self):
        """One gap in one window is one row; a gap that ended is a different fact, not a rewrite."""
        verdict = self.canonical([alert()])
        gap = self.canonical([alert(events_count=None)])
        self.assertNotEqual(json.loads(verdict[0])['source_event_id'],
                            json.loads(gap[0])['source_event_id'])


class SurfaceTests(unittest.TestCase):
    """The vocabulary line, pinned on the source text the way `tests/test_intake.py` pins it."""

    SOURCE_TEXT = (ROOT / 'local_observe' / 'platform' / 'crowdsec.py').read_text(encoding='utf-8')

    def test_no_admitted_severity_word_appears_in_the_adapter(self):
        """`crowdsec` declares no severities (§4's table): naming one here would be inventing loudness."""
        for word in ('critical', 'warning', 'info'):
            with self.subTest(word=word):
                self.assertNotIn(repr(word), self.SOURCE_TEXT)

    def test_the_adapter_never_writes_a_resolved_verdict(self):
        """This source has no resolution transition; the only `resolved` it may emit is coverage."""
        statuses = [item.event['status'] for item in intake.prepare(
            crowdsec.SOURCE, [alert(), alert(events_count=None),
                              alert(scenario='nobody/declared-me')], now=NOW,
            rules=crowdsec.validate_rules(DOCUMENT))]
        self.assertEqual(sorted(set(statuses)), ['firing', 'resolved'])
        for item in intake.prepare(crowdsec.SOURCE, [alert()], now=NOW,
                                   rules=crowdsec.validate_rules(DOCUMENT)):
            if item.event['status'] == 'resolved':
                self.assertEqual(item.event['kind'], 'coverage')

    def test_the_sample_parser_agrees_with_the_normalisers_own(self):
        """`_sample_value` is a documented copy of `intake`'s private rule; equality is the price."""
        for raw in ('12', '12.5', '-1', 'true', 'FALSE', 'nan', 'inf', '1e400', ' ', '',
                    '0.93', 'x' * 40, '0012', '12px'):
            with self.subTest(raw=raw[:12]):
                self.assertEqual(crowdsec._sample_value(raw), intake._sample_value(raw))


class IntakeRouteTests(unittest.TestCase):
    """`POST /v1/intake/crowdsec`: the identity check, the two-write order, and the answer's shape."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'state.db', NotificationPolicy(delivery_mode='off'))
        self.index_path = Path(self.temp.name) / 'inventory.db'
        index.build(read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml'), self.index_path,
                    'fixture-v1', now=NOW)
        self.rules = crowdsec.validate_rules(DOCUMENT)

    def app(self, rules=None):
        return create_app(self.store, CREDENTIALS, {}, None, self.index_path, None, None,
                          self.rules if rules is None else rules)

    def post(self, body, token=PRODUCER['token'], path='/v1/intake/crowdsec', app=None):
        """One POST through the app. `body=None` sends the raw `body=` bytes untouched."""
        output = []
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()

        async def receive():
            return {'type': 'http.request', 'body': raw, 'more_body': False}

        async def send(message):
            output.append(message)

        async def drive():
            await (app or self.app())({'type': 'http', 'method': 'POST', 'path': path,
                                       'headers': [(b'authorization', ('Bearer ' + token).encode())],
                                       'query_string': b''}, receive, send)
        asyncio.run(drive())
        return output[0]['status'], json.loads(output[1]['body'])

    def test_the_producer_posts_its_own_envelope_and_two_events_arrive(self):
        status, body = self.post({crowdsec.ALERTS_KEY: [alert()]})
        self.assertEqual(status, 200)
        self.assertEqual(body['source'], 'crowdsec')
        self.assertEqual([row['status'] for row in body['events']], ['accepted', 'accepted'])
        self.assertEqual([row['resource_link'] for row in body['events']], ['resolved', 'resolved'])
        self.assertEqual(json.loads(self.store.records('events', 10)[0]['payload'])['kind'], 'security')

    def test_a_bare_array_body_is_refused_by_the_transport_before_this_source_sees_it(self):
        """Why `examples/crowdsec/http-notification.yaml` wraps: every POST route demands an object body.

        Upstream's shipped `format` renders a bare JSON array, so pasting it verbatim produces a CrowdSec
        that retries against a 400 and a platform that never sees an alert. This test is the reason the
        example is not upstream's default file.
        """
        status, body = self.post([alert()])
        self.assertEqual(status, 400)
        self.assertIn('Expected a JSON object body', body['detail'])
        self.assertEqual(self.store.records('events', 10), [])

    def test_a_body_over_the_transports_ceiling_is_refused_without_being_normalised(self):
        """64 KiB is the operative bound, not `MAX_ALERTS`: the bytes run out before the count does."""
        inflated = alert(message='x' * 2000)
        body = json.dumps({crowdsec.ALERTS_KEY: [inflated] * 40}).encode()
        self.assertGreater(len(body), 65536, 'the fixture must actually reach the ceiling')
        status, answer = self.post(body=body)
        self.assertEqual((status, answer['error']), (413, 'body_too_large'))
        self.assertEqual(self.store.records('events', 10), [])

    def test_a_repeated_notification_is_duplicate_and_not_a_second_incident(self):
        payload = {crowdsec.ALERTS_KEY: [alert()]}
        first = self.post(payload)[1]['events']
        second = self.post(payload)[1]['events']
        self.assertEqual([row['status'] for row in first], ['accepted', 'accepted'])
        self.assertEqual([row['status'] for row in second], ['duplicate', 'duplicate'])
        self.assertEqual(len(self.store.records('events', 10)), 2)

    def test_shipped_rules_preserve_native_count_and_replay_through_authenticated_http(self):
        document = json.loads((ROOT / 'examples/crowdsec/intake-rules.json').read_text(encoding='utf-8'))
        self.assertEqual(document, DOCUMENT)
        app = self.app(crowdsec.validate_rules(document))
        payload = {crowdsec.ALERTS_KEY: [alert()]}
        self.assertEqual(len(payload['alerts'][0]['events']), 1)
        status, first = self.post(payload, app=app)
        self.assertEqual(status, 200)
        self.assertEqual([row['status'] for row in first['events']], ['accepted', 'accepted'])
        finding = next(json.loads(row['payload']) for row in self.store.records('events', 10)
                       if json.loads(row['payload'])['kind'] == 'security')
        sample_id = finding['evidence'][0]['parameters']['sample_id']
        evidence = self.store.get_evidence('crowdsec', sample_id, now=NOW)
        self.assertEqual(evidence['status'], 'available')
        self.assertEqual(evidence['sample']['value'], 12)
        status, replay = self.post(payload, app=app)
        self.assertEqual(status, 200)
        self.assertEqual([row['status'] for row in replay['events']], ['duplicate', 'duplicate'])
        self.assertEqual(len(self.store.records('events', 10)), 2)
        self.assertEqual(len(self.store.records('incidents', 10)), 1)
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 1)

    def test_missing_and_malformed_native_counts_persist_only_coverage(self):
        for count in (None, '12', True, -1, 12.5, 2 ** 31):
            with self.subTest(count=count):
                status, body = self.post({crowdsec.ALERTS_KEY: [alert(events_count=count)]})
                self.assertEqual(status, 200)
                self.assertEqual(len(body['events']), 1)
        for row in self.store.records('events', 10):
            event = json.loads(row['payload'])
            self.assertEqual((event['kind'], event['status']), ('coverage', 'firing'))
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute('SELECT COUNT(*) FROM evidence').fetchone()[0], 0)

    def test_a_credential_that_is_not_the_source_is_turned_away_before_the_body_is_normalised(self):
        status, body = self.post({crowdsec.ALERTS_KEY: [alert()]}, token=WRONG['token'])
        self.assertEqual(status, 400)
        self.assertEqual(body['error'], 'not_authorised')
        self.assertEqual(self.store.records('events', 10), [])

    def test_a_reader_credential_is_refused_before_a_single_byte_of_the_envelope_is_read(self):
        status, body = self.post({crowdsec.ALERTS_KEY: [alert()]}, token=READER['token'])
        self.assertNotEqual(status, 200)
        self.assertEqual(self.store.records('events', 10), [])

    def test_the_wrong_path_segment_cannot_borrow_the_crowdsec_credential(self):
        """`intake_target`: the path must name the caller, so one token cannot speak as two sources."""
        status, body = self.post({crowdsec.ALERTS_KEY: [alert()]}, path='/v1/intake/alertmanager')
        self.assertEqual((status, body['error']), (400, 'not_authorised'))

    def test_an_unreadable_rules_document_refuses_everything_rather_than_guessing(self):
        """The documented off switch: no rules for the source means a refusal naming the variable."""
        status, body = self.post({crowdsec.ALERTS_KEY: [alert()]}, app=self.app(rules={}))
        self.assertEqual(status, 400)
        self.assertIn('No intake rules', body['detail'])


if __name__ == '__main__':
    unittest.main()

"""Event intake: the normaliser, the adapter registry, the rules document and resource linking.

event intake ports v0.1's `aiops/ingest` front door into `local_observe/platform/intake.py`. These tests
cover the parts that do not depend on Alertmanager's field spellings (those are
`tests/test_intake_alertmanager.py`) and the HTTP route (`tests/test_platform_api_intake.py`).

Neither intake test file opens a network endpoint: the ASGI app in the route tests is called directly,
following `tests/test_api_errors.py`, and `intake.py` carries no transport layer at all (see
`SurfaceTests.test_the_module_imports_nothing_that_could_open_a_connection`, which checks the import
allowlist rather than grepping prose).
"""
import ast
import datetime as dt
import logging
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document
from local_observe.platform import intake, vocabulary
from local_observe.platform.state import EVENT_KINDS, StateError, identifier, validate_event

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime(2026, 9, 8, 12, 0, 0, tzinfo=dt.timezone.utc)
STARTS_AT = '2026-09-08T11:50:00Z'
HOST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
RULES_DOCUMENT = {'schema_version': 1, 'sources': {'alertmanager': {
    'HighCPU': {'rule_id': 'alertmanager.high_cpu', 'kind': 'threshold', 'window_seconds': 300,
                'sample_field': 'value'}}}}


def rules() -> dict:
    """The validated rules document, in the shape `prepare` reads."""
    return intake.validate_rules(RULES_DOCUMENT)


LABEL_SHORTCUTS = ('alertname', 'severity', 'instance', 'host')


def alert(labels=None, annotations=None, **fields) -> dict:
    """One Alertmanager `alerts[]` entry, carrying a keepable sample by default.

    A bare `alertname=`/`severity=`/`instance=`/`host=` keyword is a shortcut for editing `labels`,
    and `None` deletes that label; `labels=`/`annotations=` given a document replace or merge it, and
    any other keyword (`status=`, `startsAt=`, `endsAt=`, `fingerprint=`) sets the alert's own field.
    A non-document `labels=`/`annotations=` is set verbatim, which is how the malformed-payload tests
    say what they mean.
    """
    item = {'status': 'firing',
            'labels': {'alertname': 'HighCPU', 'severity': 'crit', 'instance': 'web01:9100'},
            'annotations': {'value': '0.93'},
            'startsAt': STARTS_AT, 'endsAt': '0001-01-01T00:00:00Z',
            'fingerprint': 'deadbeef', 'generatorURL': 'http://example.invalid/rule'}
    shortcuts = {name: fields.pop(name) for name in LABEL_SHORTCUTS if name in fields}
    for name, overlay in (('labels', labels), ('annotations', annotations)):
        if name == 'labels' and shortcuts and isinstance(overlay, dict):
            overlay = {**overlay, **shortcuts}
        elif name == 'labels' and shortcuts and overlay is None:
            overlay = shortcuts
        if overlay is None:
            continue
        if not isinstance(overlay, dict):
            item[name] = overlay
            continue
        merged = dict(item[name])
        for key, value in overlay.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        item[name] = merged
    item.update(fields)
    return item


def envelope(*alerts) -> dict:
    """A webhook body carrying the given alerts (one by default)."""
    return {'version': '4', 'groupKey': '{}:{}', 'status': 'firing', 'receiver': 'webhook',
            'alerts': list(alerts) or [alert()]}


def prepared(*, payload=None, index_path=None, document=None, source='alertmanager',
             now: dt.datetime = NOW) -> list[intake.Prepared]:
    """`prepare` with the shared fixtures, so a test names only what it is testing."""
    return intake.prepare(source, envelope() if payload is None else payload, now=now,
                          index_path=index_path, rules=rules() if document is None else document)


class RegistryTests(unittest.TestCase):
    """A source name is the whole of the routing decision, and it is checked before any work."""

    def test_the_alertmanager_adapter_is_registered_at_import_time(self):
        """Importing the module is enough to serve the one source ported so far (v0.1's pattern)."""
        self.assertIn('alertmanager', intake.adapters())

    def test_an_unknown_source_is_refused_and_names_the_registered_ones(self):
        """A webhook for a source with no normaliser is a refusal that says what exists."""
        with self.assertRaises(StateError) as caught:
            prepared(source='gatus')
        self.assertIn('No intake adapter is registered for source gatus', str(caught.exception))
        self.assertIn('alertmanager', str(caught.exception))

    def test_a_source_may_not_be_registered_twice(self):
        """Two mappings for one source would make the live one a function of import order."""
        with self.assertRaises(StateError):
            intake.register('alertmanager', intake.alertmanager)

    def test_a_source_name_outside_the_identifier_vocabulary_is_refused(self):
        """A source name reaches `label()` before it reaches a registry or an error body."""
        for bad in ('', 'has space', '../etc', 'x' * 129):
            with self.assertRaises(StateError):
                intake.register(bad, intake.alertmanager)


class RulesDocumentTests(unittest.TestCase):
    """The operator declares which kind of verdict each upstream alert name makes. No receiver guesses."""

    def test_a_rule_row_resolves_its_defaults(self):
        """Absent `rule_version`/`window_seconds`/`sample_field` take the documented defaults."""
        row = intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
            'ServiceDown': {'rule_id': 'alertmanager.service_down', 'kind': 'availability'}}}})
        self.assertEqual(row['alertmanager']['ServiceDown'],
                         {'rule_id': 'alertmanager.service_down', 'kind': 'availability',
                          'rule_version': '1', 'window_seconds': 60, 'sample_field': None})

    def test_a_rule_for_a_source_with_no_adapter_is_refused(self):
        """A rule that could never fire is a typo, and silence about it is the bug this refuses."""
        with self.assertRaises(StateError) as caught:
            intake.validate_rules({'schema_version': 1, 'sources': {'gatus': {
                'site': {'rule_id': 'gatus.site', 'kind': 'availability'}}}})
        self.assertIn('no adapter is registered', str(caught.exception))

    def test_a_kind_outside_the_admitted_vocabulary_is_refused(self):
        """A configuration file may not widen `kind`; the vocabulary has four places to move."""
        for kind in ('job', 'availability ', 'CRITICAL', ''):
            with self.assertRaises(StateError):
                intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
                    'X': {'rule_id': 'alertmanager.x', 'kind': kind}}}})
        for kind in EVENT_KINDS:
            document = intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
                'X': {'rule_id': 'alertmanager.x', 'kind': kind}}}})
            self.assertEqual(document['alertmanager']['X']['kind'], kind)

    def test_a_window_over_the_state_layers_ceiling_is_refused_at_the_file(self):
        """`window_seconds` is capped at seven days because `validate_event` caps the window there."""
        document = intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
            'X': {'rule_id': 'alertmanager.x', 'kind': 'threshold', 'window_seconds': 86400}}}})
        self.assertEqual(document['alertmanager']['X']['window_seconds'], 86400)
        for seconds in (0, 59, 86401, 86400 * 2, '300', True, None):
            with self.assertRaises(StateError):
                intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
                    'X': {'rule_id': 'alertmanager.x', 'kind': 'threshold',
                          'window_seconds': seconds}}}})

    def test_a_rule_may_not_carry_a_field_this_contract_does_not_have(self):
        """`severity`, `escalate`, `token`: a row is not a place to invent contract fields."""
        for extra in ({'severity': 'critical'}, {'escalate': True}, {'token': 'abc'},
                      {'query_type': 'sql'}):
            row = {'rule_id': 'alertmanager.x', 'kind': 'threshold'}
            row.update(extra)
            with self.assertRaises(StateError):
                intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {'X': row}}})

    def test_an_empty_rule_set_is_refused_and_is_never_a_wildcard(self):
        """`{"alertmanager": {}}` says nothing, so it must not mean "admit everything"."""
        for document in ({'schema_version': 1, 'sources': {'alertmanager': {}}},
                         {'schema_version': 1, 'sources': {}},
                         {'schema_version': 1, 'sources': {'alertmanager': 'all'}}):
            with self.assertRaises(StateError):
                intake.validate_rules(document)

    def test_the_document_shape_is_closed(self):
        """Only `schema_version` and `sources`, and only version 1."""
        for document in ({'sources': RULES_DOCUMENT['sources']},
                         {'schema_version': 2, 'sources': RULES_DOCUMENT['sources']},
                         {'schema_version': 1, 'sources': RULES_DOCUMENT['sources'], 'tokens': []},
                         {'schema_version': 1, 'sources': []}):
            with self.assertRaises(StateError):
                intake.validate_rules(document)

    def test_an_unusable_sample_field_is_refused(self):
        """The field name is an annotation key, so it is bounded and may not carry surrounding space."""
        for field in ('', ' value ', 'x' * 65, 7, True):
            with self.assertRaises(StateError):
                intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
                    'X': {'rule_id': 'alertmanager.x', 'kind': 'threshold', 'sample_field': field}}}})

    def test_the_rules_file_is_read_bounded_and_refuses_what_it_cannot_parse(self):
        """Every way a mounted file can be wrong is a refusal naming the file's problem, not a crash."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            good = root / 'rules.json'
            good.write_text('{"schema_version": 1, "sources": '
                            '{"alertmanager": {"X": {"rule_id": "alertmanager.x",'
                            ' "kind": "threshold"}}}}', encoding='utf-8')
            self.assertEqual(sorted(intake.load_rules(good)['alertmanager']), ['X'])

            for name, content in (('empty', b''), ('oversized', b'{' + b' ' * intake.MAX_RULES_BYTES),
                                  ('not-json', b'nonsense'), ('not-utf8', b'\xff\xfe{"a":1}')):
                path = root / name
                path.write_bytes(content)
                with self.assertRaises(StateError):
                    intake.load_rules(path)
            with self.assertRaises(StateError):
                intake.load_rules(root / 'absent.json')

    def test_the_environment_off_switch_returns_no_rules_and_names_the_variable_it_read(self):
        """No `LO_INTAKE_RULES` is the documented off switch; a named-but-bad file is a boot failure."""
        for environment in ({}, {intake.RULES_ENVIRONMENT: ''}, {intake.RULES_ENVIRONMENT: '   '}):
            self.assertEqual(intake.rules_from_environment(environment), {})
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / 'rules.json'
            bad.write_text('{"schema_version": 1}', encoding='utf-8')
            with self.assertRaises(StateError):
                intake.rules_from_environment({intake.RULES_ENVIRONMENT: str(bad)})

    def test_an_unconfigured_webhook_refuses_with_the_reason_rather_than_inventing_a_rule(self):
        """Off must be loud to the sender: an accepted alert with a made-up rule would hide the outage."""
        with self.assertRaises(StateError) as caught:
            prepared(document={})
        self.assertIn('No intake rules are configured', str(caught.exception))

    def test_a_rules_document_keyed_by_source_is_not_mistaken_for_alert_names(self):
        """Handing `prepare` the whole document is the common mistake; it must not silently match."""
        rows = rules()
        self.assertEqual(prepared(document=rows)[0].event['rule_id'], 'alertmanager.high_cpu.coverage')
        with self.assertRaises(StateError):
            prepared(document=rows['alertmanager'])


class ResourceLinkTests(unittest.TestCase):
    """Linking is enrichment: the inventory decides, and nothing here invents a UUID."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.index_path = Path(cls.temp.name) / 'inventory.db'
        index.build(read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml'), cls.index_path,
                    'fixture-v1', now=NOW)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_the_instance_resolves_through_the_declared_hostname_alias(self):
        """A hostname an operator declared is the only thing that can name a resource."""
        items = prepared(index_path=self.index_path,
                         payload=envelope(alert(instance='probe-1.example.test')))
        self.assertEqual(items[0].link, 'resolved')
        self.assertEqual({item.event['resource_id'] for item in items}, {HOST_ID})
        for item in items:
            identifier(item.event['resource_id'])

    def test_a_port_suffix_is_not_part_of_the_host_name(self):
        """`instance="probe-1.example.test:9100"` is one exporter endpoint, not a different resource."""
        items = prepared(index_path=self.index_path,
                         payload=envelope(alert(instance='probe-1.example.test:9100')))
        self.assertEqual(items[0].event['resource_id'], HOST_ID)
        self.assertEqual(items[0].link, 'resolved')

    def test_an_address_instance_resolves_through_the_ip_alias(self):
        """An `instance` that is an address is looked up as one, not as a hostname."""
        items = prepared(index_path=self.index_path,
                         payload=envelope(alert(labels={'alertname': 'HighCPU', 'severity': 'crit',
                                                        'instance': '10.11.0.21'})))
        self.assertEqual(items[0].event['resource_id'], HOST_ID)

    def test_the_host_label_is_a_candidate_too(self):
        """v0.1 read `instance` then `host`; both are offered to `resolve` in one call."""
        items = prepared(index_path=self.index_path,
                         payload=envelope(alert(instance=None, host='probe-1.example.test')))
        self.assertEqual(items[0].event['resource_id'], HOST_ID)

    def test_an_undeclared_instance_is_admitted_unresolved_with_no_invented_uuid(self):
        """The admitted answer is a null resource plus a visible link, never a name-derived UUID."""
        items = prepared(index_path=self.index_path,
                         payload=envelope(alert(instance='not-declared.example')))
        self.assertEqual([item.event['resource_id'] for item in items], [None, None])
        self.assertEqual({item.link for item in items}, {'unknown'})
        for item in items:
            self.assertNotIn('not-declared', str(item.event))

    def test_an_alert_naming_no_instance_says_so_rather_than_guessing_a_host(self):
        """No candidate names means no lookup was possible; the event is still admissible."""
        items = prepared(index_path=self.index_path, payload=envelope(alert(instance=None)))
        self.assertEqual({item.link for item in items}, {'no_alias'})
        self.assertEqual([item.event['resource_id'] for item in items], [None, None])

    def test_an_unreadable_index_leaves_intake_running_and_the_link_says_which(self):
        """A front door that stops intake because its inventory read failed manufactures an outage."""
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / 'absent.db'
            items = prepared(index_path=missing, payload=envelope(alert(instance='probe-1.example.test')))
        self.assertEqual({item.link for item in items}, {'index_unavailable'})
        self.assertEqual([item.event['resource_id'] for item in items], [None, None])

    def test_no_index_configured_is_reported_apart_from_a_broken_one(self):
        """'Nothing was configured' and 'the configured index failed to open' are different answers."""
        items = prepared(payload=envelope(alert(instance='probe-1.example.test')))
        self.assertEqual({item.link for item in items}, {'not_configured'})

    def test_the_link_never_reaches_the_stored_event(self):
        """The canonical field set is closed; a link belongs in the response, not in the event."""
        for item in prepared(index_path=self.index_path):
            self.assertNotIn('link', item.event)
            self.assertNotIn('resource_link', item.event)

    def test_the_candidates_ask_the_index_once_and_never_pick_a_winner_themselves(self):
        """`host:port` yields the raw name, the bare name and the address form, in that order."""
        self.assertEqual(intake.candidate_aliases({'instance': 'web-1.example.test:9100'}),
                         [{'type': 'hostname', 'value': 'web-1.example.test:9100'},
                          {'type': 'hostname', 'value': 'web-1.example.test'}])
        self.assertEqual(intake.candidate_aliases({'instance': '10.11.0.21:9100'}),
                         [{'type': 'hostname', 'value': '10.11.0.21:9100'},
                          {'type': 'hostname', 'value': '10.11.0.21'},
                          {'type': 'ip', 'value': '10.11.0.21'}])
        self.assertEqual(intake.candidate_aliases({'instance': 'two words'}), [])
        self.assertEqual(intake.candidate_aliases({}), [])
        self.assertEqual(intake.candidate_aliases({'instance': 'x' * 300}), [])

    def test_the_candidate_list_is_bounded_so_one_alert_cannot_ask_for_the_index(self):
        """Six candidates is an upper bound on what one alert may probe."""
        labels = {f'instance{i}': f'h{i}.example' for i in range(10)}
        labels['instance'] = 'a.example'
        labels['host'] = 'b.example'
        self.assertLessEqual(len(intake.candidate_aliases(labels)), 6)


class IdentityTests(unittest.TestCase):
    """What makes a re-post one row, and what is deliberately absent from it."""

    def test_the_identity_covers_status_so_a_resolution_is_not_a_rewritten_replay(self):
        """Alertmanager posts both transitions of a condition with the same `startsAt`."""
        firing = intake.retry_identity({'source': 'alertmanager', 'rule_id': 'r', 'rule_version': '1',
                                        'resource_id': None, 'window': {'start': 'a', 'end': 'b'},
                                        'status': 'firing'})
        resolved = intake.retry_identity({'source': 'alertmanager', 'rule_id': 'r', 'rule_version': '1',
                                          'resource_id': None, 'window': {'start': 'a', 'end': 'b'},
                                          'status': 'resolved'})
        self.assertNotEqual(firing, resolved)

    def test_the_identity_ignores_every_field_that_moves_with_an_operator_editing_a_label(self):
        """`fingerprint`, `generatorURL` and annotation text are read by nobody here, by design."""
        first = prepared(payload=envelope(alert()))
        second = prepared(payload=envelope(alert(fingerprint='other', generatorURL='http://elsewhere',
                                                 annotations={'value': '0.93', 'summary': 'new text'})))
        self.assertEqual([item.event['source_event_id'] for item in first],
                         [item.event['source_event_id'] for item in second])

    def test_the_identity_is_stable_across_repeats_of_the_same_alert(self):
        """Byte-identical events are the precondition of `Store`'s duplicate answer."""
        first = prepared(payload=envelope(alert()))
        second = prepared(payload=envelope(alert()), now=NOW + dt.timedelta(hours=1))
        self.assertEqual([item.event for item in first], [item.event for item in second])

    def test_retry_identity_refuses_something_that_is_not_a_canonical_event(self):
        """A missing window or a non-string resource is a bug in a caller, not a client error."""
        good = {'source': 's', 'rule_id': 'r', 'rule_version': '1', 'resource_id': None,
                'window': {'start': 'a', 'end': 'b'}, 'status': 'firing'}
        intake.retry_identity(good)
        for mutate in (lambda item: item.pop('window'), lambda item: item.pop('status'),
                       lambda item: item.update(window={'start': 'a'}),
                       lambda item: item.update(resource_id=7),
                       lambda item: item.update(rule_id=None)):
            broken = dict(good)
            mutate(broken)
            with self.assertRaises(StateError):
                intake.retry_identity(broken)


class SurfaceTests(unittest.TestCase):
    """The two public surfaces agree, everything produced is valid, and no severity word lives here."""

    def test_normalise_returns_exactly_the_events_prepare_returns(self):
        """`normalise` is the contract's interface; `prepare` is what a transport must use."""
        events = intake.normalise('alertmanager', envelope(), now=NOW, rules=rules())
        items = prepared()
        self.assertEqual(events, [item.event for item in items])
        self.assertEqual(len(events), 2)

    def test_every_event_this_module_produces_passes_the_platform_validator(self):
        """The point of the port: what the normaliser emits is what `Store` admits."""
        cases = [envelope(),
                 envelope(alert(status='resolved', endsAt='2026-09-08T11:59:00Z')),
                 envelope(alert(severity='none')),
                 envelope(alert(alertname='UnDeclared', instance='web01')),
                 envelope(alert(annotations={}))]
        for payload in cases:
            for item in prepared(payload=payload):
                validate_event(item.event, NOW)

    def test_the_severity_words_live_in_vocabulary_and_appear_nowhere_here(self):
        """event vocabulary's crosswalk is the only author of loudness; this module must not spell a severity."""
        admitted = set(vocabulary.ADMITTED_SEVERITIES)
        tree = ast.parse((ROOT / 'local_observe' / 'platform' / 'intake.py').read_text(encoding='utf-8'))
        spelled = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value in admitted:
                spelled.add(node.value)
        self.assertEqual(spelled, set())

    def test_the_module_imports_nothing_that_could_open_a_connection(self):
        """The unit tier never binds or connects: what `intake` imports is an allowlist, not a habit.

        Stated as what is permitted rather than as a list of banned transport names, so the check
        cannot be satisfied by renaming a dependency and stays prose-proof for the module docstring,
        which does describe the rule it enforces.
        """
        allowed = {'collections.abc', 'contextlib', 'dataclasses', 'datetime', 'ipaddress', 'json',
                   'math', 'pathlib', 'sqlite3', 'typing', 'local_observe'}
        tree = ast.parse((ROOT / 'local_observe' / 'platform' / 'intake.py').read_text(encoding='utf-8'))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.add('local_observe.platform' if node.level else node.module or '')
        self.assertTrue(imported, 'a module with no imports cannot be checked this way')
        self.assertEqual(sorted(name for name in imported
                                if not any(name == root or name.startswith(root + '.')
                                           for root in allowed)), [])


class DegradationLoggingTests(unittest.TestCase):
    """The refusals to invent something are logged where an operator will look, and say little."""

    def record(self, payload):
        """The one WARNING this payload produced, as the record the logging machinery actually saw."""
        with self.assertLogs('local_observe.platform.intake', level='WARNING') as captured:
            prepared(payload=payload)
        self.assertEqual(len(captured.records), 1)
        return captured.records[0]

    def test_an_undeclared_alert_name_is_logged_with_a_folded_hint_and_no_payload_value(self):
        """`name_hint` lets an operator find the rule to declare; nothing else from the payload travels.

        This is the logging contract of `local_observe/log.py` (logging): identifiers and statuses, never
        payload bodies. The hint is folded to `[a-z0-9.]`, so a name carrying a URL or a newline cannot
        put either on the line — and it never reaches the event, where it would have become identity.
        """
        record = self.record(envelope(alert(alertname='CPU pressure "quoted" http://x/y')))
        self.assertEqual(record.rule_id, intake.UNDECLARED_RULE_COVERAGE)
        self.assertEqual(record.source, 'alertmanager')
        self.assertTrue(record.name_hint.startswith('cpu.pressure'))
        self.assertNotIn('/', record.name_hint)
        self.assert_no_payload_values(record)

    def assert_no_payload_values(self, record):
        # LogRecord timestamps can contain a payload-shaped decimal by coincidence.
        # Inspect the emitted message and every custom field, not standard runtime metadata.
        standard = set(vars(logging.LogRecord('name', logging.INFO, 'path', 1,
                                              'message', (), None))) | {'message', 'asctime'}
        custom = {name: value for name, value in vars(record).items() if name not in standard}
        joined = str(record.getMessage()) + str(custom)
        for leaked in ('0.93', 'deadbeef', 'web01:9100', 'http://'):
            self.assertNotIn(leaked, joined)

    def test_numeric_log_metadata_is_not_mistaken_for_a_payload_leak(self):
        record = self.record(envelope(alert(alertname='CPU pressure')))
        record.created = 0.93
        record.relativeCreated = 0.93
        self.assertIn('0.93', str(vars(record)))
        self.assert_no_payload_values(record)

    def test_payload_leaks_in_custom_fields_or_message_are_still_refused(self):
        for leaked in ('0.93', 'deadbeef', 'web01:9100', 'http://'):
            for field in ('custom', 'message'):
                with self.subTest(leaked=leaked, field=field):
                    record = self.record(envelope(alert(alertname='CPU pressure')))
                    if field == 'custom':
                        record.synthetic_payload = leaked
                    else:
                        record.msg, record.args = '%s', (leaked,)
                    with self.assertRaises(AssertionError):
                        self.assert_no_payload_values(record)

    def test_a_refused_severity_is_logged_as_the_refusal_it_is(self):
        """The crosswalk refused the word; the log says which rule now carries the gap."""
        record = self.record(envelope(alert(severity='none')))
        self.assertEqual(record.rule_id, intake.SEVERITY_REFUSED_COVERAGE)
        self.assertEqual(record.error_class, 'VocabularyError')

    def test_a_missing_sample_is_logged_against_the_rule_that_owed_it(self):
        """'This declared rule brought no number' names a different gap from 'nobody declared it'."""
        record = self.record(envelope(alert(annotations={'value': 'not-a-number'})))
        self.assertEqual(record.rule_id, 'alertmanager.high_cpu.coverage')

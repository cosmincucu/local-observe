"""store facade: the declared retention tiers against the retention the store actually applies.

The source estate carried a file that said 90/30/90 days and a store that applied 30/15/15, and
nothing ever compared them: the logs tier had been raised precisely because 15 days was destroying
incident evidence, and it stayed at 15. These tests pin both halves of that failure — the diff must
say three lines for that shape of divergence and none when the tiers agree, and the live half must
come from the one tool that reads retention in this project rather than from a second HTTP client
that can drift from it.
"""
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.store import retention
from local_observe.store.client import SIGNALS

ROOT = Path(__file__).resolve().parents[1]
# The estate's measured shape : every signal
# declared above what the store applied.
DECLARED_DAYS = {'metrics': 90, 'traces': 30, 'logs': 90}
LIVE_DAYS = {'metrics': 30, 'traces': 15, 'logs': 15}
ORIGIN = 'http://127.0.0.1:18081'
EMAIL = 'operator@example.test'
ORG = '0b114c14-1f2a-4a2a-9b0e-2a0d0e0a1f2c'


def hours(days: dict[str, int]) -> dict[str, int]:
    """Convert a ``{signal: days}`` shape to the hours the store answers in."""
    return {signal: value * 24 for signal, value in days.items()}


class DeclaredTiers(unittest.TestCase):
    """`declared`: one JSON object of operator intent, read narrowly."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, document, name='retention.json'):
        """Put one document on disk, text or object alike, and return its path."""
        path = self.root / name
        path.write_text(document if isinstance(document, str) else json.dumps(document), encoding='utf-8')
        return path

    def document(self, **overrides):
        tiers = {signal: {'ttl_days': DECLARED_DAYS[signal]} for signal in SIGNALS}
        document = {'schema_version': '1', 'tiers': tiers}
        document.update(overrides)
        return document

    def test_the_estate_declaration_becomes_hours(self):
        self.assertEqual(retention.declared(self.write(self.document())), hours(DECLARED_DAYS))

    def test_a_yaml_document_needs_an_explicit_loader(self):
        text = 'schema_version: "1"\ntiers:\n' + ''.join(
            f'  {signal}:\n    ttl_days: {DECLARED_DAYS[signal]}\n' for signal in SIGNALS)
        path = self.write(text, name='retention.yaml')
        with self.assertRaises(retention.RetentionRefused) as caught:
            retention.declared(path)
        self.assertIn('loader', str(caught.exception))
        loaded = retention.declared(path, loader=lambda text: {'schema_version': '1',
                                                              'tiers': {signal: {'ttl_days': DECLARED_DAYS[signal]}
                                                                        for signal in SIGNALS}})
        self.assertEqual(loaded, hours(DECLARED_DAYS))

    def test_every_malformed_document_is_named_and_refused(self):
        broken = {
            'not an object': '[1, 2]',
            'unknown field': self.document(extra=1),
            'wrong schema version': self.document(schema_version='2'),
            'tiers missing': {'schema_version': '1'},
            'tiers not a mapping': self.document(tiers='90 days'),
            'unknown signal': self.document(tiers={**{'metrics': {'ttl_days': 90}, 'traces': {'ttl_days': 30},
                                                      'logs': {'ttl_days': 90}, 'profiles': {'ttl_days': 1}}}),
            'hour field instead of days': self.document(tiers={signal: {'ttl_hours': 24} for signal in SIGNALS}),
            'zero days': self.document(tiers={signal: ({'ttl_days': 0} if signal == 'logs' else
                                                       {'ttl_days': DECLARED_DAYS[signal]})
                                              for signal in SIGNALS}),
            'days as text': self.document(tiers={signal: ({'ttl_days': '90'} if signal == 'logs' else
                                                          {'ttl_days': DECLARED_DAYS[signal]})
                                                 for signal in SIGNALS}),
            'a tier with a spare key': self.document(tiers={**{signal: {'ttl_days': DECLARED_DAYS[signal]}
                                                               for signal in SIGNALS},
                                                            'logs': {'ttl_days': 90, 'cold_storage': True}}),
        }
        for label, document in broken.items():
            with self.subTest(defect=label):
                with self.assertRaises(retention.RetentionRefused):
                    retention.declared(self.write(document, name=f'{abs(hash(label))}.json'))

    def test_a_missing_tier_names_the_signal_that_has_no_declaration(self):
        tiers = {signal: {'ttl_days': DECLARED_DAYS[signal]} for signal in SIGNALS if signal != 'logs'}
        with self.assertRaises(retention.RetentionRefused) as caught:
            retention.declared(self.write(self.document(tiers=tiers)))
        self.assertIn('logs', str(caught.exception))

    def test_a_missing_or_oversized_file_is_refused_without_reading_it(self):
        with self.assertRaises(retention.RetentionRefused):
            retention.declared(self.root / 'absent.json')
        path = self.root / 'huge.json'
        path.write_text('[' + '1,' * (retention.MAX_DECLARED_BYTES) + ']', encoding='utf-8')
        with self.assertRaises(retention.RetentionRefused):
            retention.declared(path)


class RetentionDiff(unittest.TestCase):
    """`diff`: one line per divergence, and silence only when the store agrees."""

    def test_the_estate_divergence_is_three_lines(self):
        lines = retention.diff(hours(DECLARED_DAYS), hours(LIVE_DAYS))
        self.assertEqual(len(lines), 3)
        self.assertEqual(sorted(line.split(':')[0] for line in lines), sorted(SIGNALS))
        self.assertIn('metrics: declared 90d (2160h) but the store applies 30d (720h)', lines)
        self.assertIn('traces: declared 30d (720h) but the store applies 15d (360h)', lines)
        self.assertIn('logs: declared 90d (2160h) but the store applies 15d (360h)', lines)

    def test_matching_tiers_are_silent(self):
        for agreement in (DECLARED_DAYS, LIVE_DAYS, {'metrics': 7, 'traces': 7, 'logs': 7}):
            with self.subTest(tiers=agreement):
                self.assertEqual(retention.diff(hours(agreement), hours(agreement)), [])

    def test_a_signal_the_store_does_not_report_is_a_divergence_not_a_pass(self):
        live = hours(LIVE_DAYS)
        del live['logs']
        lines = retention.diff(hours(DECLARED_DAYS), live)
        self.assertEqual(len(lines), 3)
        self.assertIn('logs: declared 90d (2160h) but the live settings do not name it', lines)

    def test_a_signal_the_store_keeps_but_nobody_declared_is_reported(self):
        live = {**hours(LIVE_DAYS), 'profiles': 24}
        lines = retention.diff(hours(DECLARED_DAYS), live)
        self.assertIn('profiles: the store reports 1d (24h) and nothing is declared for it', lines)

    def test_a_retention_that_is_not_whole_days_is_printed_as_hours(self):
        lines = retention.diff({'metrics': 48, 'logs': 48, 'traces': 48},
                               {'metrics': 36, 'logs': 48, 'traces': 48})
        self.assertEqual(lines, ['metrics: declared 2d (48h) but the store applies 36h'])

    def test_a_signal_the_store_reports_as_unset_is_its_own_line(self):
        lines = retention.diff({'metrics': 24, 'logs': 24, 'traces': 24},
                               {'metrics': None, 'logs': 24, 'traces': 24})
        self.assertEqual(lines, ['metrics: declared 1d (24h) but the store reports no retention at all, '
                                 'so nothing is expiring on this signal by design'])

    def test_two_mappings_are_required(self):
        for wrong in (None, [], 'metrics=90', 7):
            with self.subTest(wrong=wrong):
                with self.assertRaises(retention.RetentionRefused):
                    retention.diff({'metrics': 24, 'logs': 24, 'traces': 24}, wrong)


class SessionStub:
    """The retention tool's ``StoreSession`` surface, with the answers one store gave."""

    def __init__(self, answers: dict[str, tuple[int, list]]) -> None:
        self.answers, self.asked = answers, []

    def read(self, signal: str):
        self.asked.append(signal)
        return self.answers[signal]


class LiveFromSession(unittest.TestCase):
    """The live half reads through the tool's session, and never turns a refusal into a zero."""

    def test_three_signals_are_read_once_each(self):
        session = SessionStub({signal: (value, []) for signal, value in
                               (('metrics', 720), ('logs', 360), ('traces', 360))})
        self.assertEqual(retention.live_from_session(session), {'metrics': 720, 'logs': 360, 'traces': 360})
        self.assertEqual(sorted(session.asked), sorted(SIGNALS))

    def test_the_logs_ttl_conditions_are_carried_unread_and_never_become_a_number(self):
        session = SessionStub({signal: (720, [{'label': 'no-deletes'}]) for signal in SIGNALS})
        self.assertEqual(set(retention.live_from_session(session).values()), {720})

    def test_an_unreadable_retention_is_refused_rather_than_reported_as_zero_days(self):
        for value in (0, None, '30d', True, -1):
            answers = {signal: (720, []) for signal in SIGNALS}
            answers['logs'] = (value, [])
            with self.subTest(value=value):
                with self.assertRaises(retention.RetentionRefused):
                    retention.live_from_session(SessionStub(answers))

    def test_a_store_that_raises_propagates_the_tools_bounded_error(self):
        class Refusing(SessionStub):
            def read(self, signal):
                raise RuntimeError('the pinned SigNoz names that field differently')

        with self.assertRaises(RuntimeError):
            retention.live_from_session(Refusing({}))


class ThroughTheShippedTool(unittest.TestCase):
    """The tool is imported, not imitated: its own session code produces the live dict.

    The stub here implements the tool's transport contract (one call in, one bounded reply out), so
    the login mechanism, the duration parsing and the response-shape refusals under test are the
    product's real ones. Nothing here reaches a socket.
    """

    REPLIES = {
        'POST /api/v2/sessions/email_password': {'status': 'success',
                                                 'data': {'accessToken': 'jwt-' + 'x' * 48}},
        'GET /api/v1/settings/ttl?type=traces': {'status': 'success', 'data': {'ttl': '360h'}},
        'GET /api/v1/settings/ttl?type=metrics': {'status': 'success', 'data': {'ttl': '720h'}},
        'GET /api/v2/settings/ttl?type=logs': {'status': 'success',
                                               'data': {'defaultTTLDays': 15, 'ttlConditions': []}},
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.module = retention.tool_module()
        self.original = self.module.HttpTransport
        module = self.module
        self.replies = dict(self.REPLIES)
        replies = self.replies

        class Transport:
            """The tool's transport: a route table, and a 404 for anything not in it."""

            calls: list[str] = []

            def __init__(self, origin, **_kwargs):
                self.origin = origin

            def request(self, method, path, payload=None, *, headers=None):
                key = f'{method} {path}'
                Transport.calls.append(key)
                body = replies.get(key)
                return module.Response(404) if body is None else module.Response(200, body)

        self.Transport = Transport
        self.module.HttpTransport = Transport
        self.addCleanup(setattr, self.module, 'HttpTransport', self.original)

    def credentials(self, **overrides):
        document = {'email': EMAIL, 'password': 'Sentinel-Password-9f3a', 'orgID': ORG}
        document.update(overrides)
        path = Path(self.temp.name) / 'login.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def test_the_live_dict_comes_from_the_tools_reader(self):
        live = retention.live(ORIGIN, self.credentials(), tool=self.module)
        self.assertEqual(live, {'metrics': 720, 'logs': 360, 'traces': 360})
        self.assertEqual(sorted(self.Transport.calls), sorted(self.REPLIES))

    def test_the_diff_against_the_live_reading_is_the_estate_three_lines(self):
        live = retention.live(ORIGIN, self.credentials(), tool=self.module)
        lines = retention.diff(hours(DECLARED_DAYS), live)
        self.assertEqual(len(lines), 3)
        self.assertTrue(all('but the store applies' in line for line in lines))

    def test_a_store_that_refuses_the_login_is_the_tools_error_not_a_zero(self):
        del self.replies['POST /api/v2/sessions/email_password']
        with self.assertRaises(self.module.RetentionError) as caught:
            retention.live(ORIGIN, self.credentials(), tool=self.module)
        self.assertIn('login', str(caught.exception).lower())

    def test_a_clear_text_is_refused_before_any_login_is_attempted(self):
        with self.assertRaises(self.module.RetentionError):
            retention.live('http://store.example.test', self.credentials(), tool=self.module)

    def test_the_credentials_file_is_read_by_the_tool_and_its_bounds_are_its_own(self):
        path = self.credentials(unexpected='x')
        with self.assertRaises(self.module.RetentionError):
            retention.live(ORIGIN, path, tool=self.module)

    def test_a_missing_tool_is_named_with_the_variable_that_would_point_at_it(self):
        with self.assertRaises(retention.RetentionRefused) as caught:
            retention.tool_module(Path(self.temp.name) / 'nowhere.py')
        self.assertIn(retention.TOOL_ENVIRONMENT, str(caught.exception))

    def test_a_tool_that_stops_covering_the_three_signals_is_refused(self):
        original = self.module.SIGNALS
        self.module.SIGNALS = ('metrics', 'logs')
        try:
            with self.assertRaises(retention.RetentionRefused) as caught:
                retention.live(ORIGIN, self.credentials(), tool=self.module)
            self.assertIn('metrics', str(caught.exception))
        finally:
            self.module.SIGNALS = original

    def test_the_tool_is_the_one_r15_program_this_repository_ships(self):
        text = (ROOT / 'components/data/store-signoz/retention.py').read_text(encoding='utf-8')
        self.assertIn('retention', text)
        for name in ('HttpTransport', 'StoreSession', 'read_credentials', 'validate_origin'):
            self.assertTrue(hasattr(self.module, name), name)
        self.assertEqual(set(self.module.SIGNALS), set(SIGNALS))


class Posture(unittest.TestCase):
    """No second TTL reader, no second transport, no secret on the way through."""

    def source(self) -> str:
        return (ROOT / 'local_observe/store/retention.py').read_text(encoding='utf-8')

    def test_the_module_builds_no_request_of_its_own(self):
        text = self.source()
        for forbidden in ('urlopen', 'build_opener', 'http.client', 'socket', 'Authorization'):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, text)

    def test_the_password_is_only_a_path_handed_to_the_tool(self):
        text = self.source()
        self.assertIn('read_credentials', text)
        for not_ours in ('"email"', "'email'", 'accessToken', 'Cookie'):
            with self.subTest(token=not_ours):
                self.assertNotIn(not_ours, text)


if __name__ == '__main__':
    unittest.main()

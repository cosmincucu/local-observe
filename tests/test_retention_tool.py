"""Tests for the SigNoz retention tool (retention): arguments, request shapes, exit codes, redaction."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('store_retention',
                                              ROOT / 'components/data/store-signoz/retention.py')
RET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RET)

PASSWORD = 'Sentinel-Password-9f3a-not-printed'
EMAIL = 'operator@example.test'
ORG = '0b114c14-1f2a-4a2a-9b0e-2a0d0e0a1f2c'
ORIGIN = 'http://127.0.0.1:18081'


def traces(hours):
    """One traces/metrics TTL document as the v1 API returns it (a Go duration string)."""
    return RET.Response(200, {'status': 'success', 'data': {'type': 'traces', 'ttl': hours}})


def logs(days, conditions=()):
    """One logs TTL document as the v2 API returns it (whole days plus per-condition rules)."""
    return RET.Response(200, {'status': 'success',
                              'data': {'type': 'logs', 'defaultTTLDays': days, 'ttlConditions': list(conditions)}})


def login_cookie():
    return RET.Response(200, {'status': 'success', 'data': {'user': {'email': EMAIL}}},
                        {'signoz-ae-session': 'session-value', 'signoz-refresh-token': 'refresh-value'})


def login_token(token='jwt-' + 'x' * 48):
    return RET.Response(200, {'status': 'success', 'data': {'accessToken': token}})


ACCEPT = RET.Response(200, {'status': 'success'})


class FakeStore:
    """A scripted stand-in for the store API: serves canned replies and records every request."""

    def __init__(self, routes, *, default=None) -> None:
        self.routes = {key: list(value) for key, value in routes.items()}
        self.default = RET.Response(404) if default is None else default
        self.calls: list[tuple[str, object, dict[str, str]]] = []

    def request(self, method, path, payload=None, *, headers=None):
        key = f'{method} {path}'
        self.calls.append((key, payload, dict(headers or {})))
        queue = self.routes.get(key)
        if not queue:
            return self.default
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def keys(self):
        return [key for key, _payload, _headers in self.calls]

    def payload(self, key):
        return next(payload for called, payload, _headers in self.calls if called == key)

    def headers_for(self, key):
        return next(headers for called, _payload, headers in self.calls if called == key)


def routes(login=None, *, trace_reads=None, metric_reads=None, log_reads=None, days=(7, 30, 14)):
    """A complete route table: one login, three TTL reads and the three writes that accept it."""
    traces_write, metrics_write, logs_write = days
    table = {
        'POST /api/v2/sessions/email_password': [login or login_cookie()],
        f'POST /api/v1/settings/ttl?type=traces&duration={traces_write * 24}h': [ACCEPT],
        f'POST /api/v1/settings/ttl?type=metrics&duration={metrics_write * 24}h': [ACCEPT],
        'POST /api/v2/settings/ttl': [ACCEPT],
    }
    if trace_reads is not None:
        table['GET /api/v1/settings/ttl?type=traces'] = trace_reads
    if metric_reads is not None:
        table['GET /api/v1/settings/ttl?type=metrics'] = metric_reads
    if log_reads is not None:
        table['GET /api/v2/settings/ttl?type=logs'] = log_reads
    return table


class RetentionToolTests(unittest.TestCase):
    """Everything the tool must do without ever reaching a network."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def credentials(self, values=None, *, name='creds.json'):
        """Write a credentials file holding *values* verbatim, or a complete set of defaults."""
        path = self.root / name
        body = {'email': EMAIL, 'password': PASSWORD, 'orgID': ORG}
        path.write_text(json.dumps(body if values is None else values), encoding='utf-8')
        return path

    def run_tool(self, argv, store=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = RET.main(argv, transport=store)
        return code, out.getvalue() + err.getvalue()

    def base_args(self, path):
        return ['--url', ORIGIN, '--credentials-file', str(path)]

    # --- argument validation -------------------------------------------------------------------

    def test_missing_url_or_credentials_file_is_a_usage_error(self):
        for argv in ([], ['--url', ORIGIN], ['--credentials-file', 'x.json']):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()) as noise:
                with self.assertRaises(SystemExit) as caught:
                    RET.main(argv)
                self.assertEqual(caught.exception.code, 2)
                self.assertIn('required', noise.getvalue())

    def test_check_and_apply_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()) as noise:
            with self.assertRaises(SystemExit) as caught:
                RET.main(self.base_args(self.credentials()) + ['--check', '--apply'])
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('not allowed with argument', noise.getvalue())

    def test_days_outside_the_supported_range_are_refused(self):
        path = self.credentials()
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        for value in ('0', '3651', '-1'):
            with self.subTest(value=value):
                code, text = self.run_tool(self.base_args(path) + ['--logs-days', value], store)
                self.assertEqual(code, 2)
                self.assertIn('logs-days', text)
                self.assertEqual(store.keys(), [], 'an invalid day count must fail before any request')
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:  # argparse owns the type, not this tool
                self.run_tool(self.base_args(path) + ['--logs-days', 'seven'], store)
        self.assertEqual(caught.exception.code, 2)

    def test_plaintext_non_loopback_url_is_refused_unless_allowed(self):
        path = self.credentials()
        code, text = self.run_tool(['--url', 'http://store.internal:8080', '--credentials-file', str(path)],
                                   FakeStore(routes()))
        self.assertEqual(code, 2)
        self.assertIn('plaintext', text)
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        code, _text = self.run_tool(['--url', 'http://store.internal:8080', '--credentials-file', str(path),
                                     '--allow-insecure-http'], store)
        self.assertEqual(code, 0, 'the explicit opt-in must reach the store')
        self.assertIn('POST /api/v2/sessions/email_password', store.keys())

    def test_url_with_credentials_or_query_is_refused(self):
        path = self.credentials()
        for url in ('https://admin:pw@example.test', 'https://example.test?next=evil', 'ftp://example.test',
                    'https://example.test/api', 'https://example.test:notaport'):
            with self.subTest(url=url):
                code, text = self.run_tool(['--url', url, '--credentials-file', str(path)], FakeStore(routes()))
                self.assertEqual(code, 2)
                self.assertIn('--url', text)

    # --- credentials file ----------------------------------------------------------------------

    def test_credentials_file_must_be_a_readable_json_object(self):
        cases = {
            'absent.json': None,
            'notjson.json': 'not json at all',
            'list.json': '[1, 2]',
            'unknown.json': json.dumps({'email': EMAIL, 'password': PASSWORD, 'org': 'x'}),
            'noemail.json': json.dumps({'password': PASSWORD, 'orgID': 'o'}),
            'noorg.json': json.dumps({'email': EMAIL, 'password': PASSWORD}),
            'empty.json': json.dumps({'email': EMAIL, 'password': '', 'orgID': 'o'}),
            'control.json': json.dumps({'email': 'op\n@example.test', 'password': PASSWORD, 'orgID': 'o'}),
            'nested.json': json.dumps({'email': {'a': 1}, 'password': PASSWORD, 'orgID': 'o'}),
        }
        for name, body in cases.items():
            path = self.root / name
            if body is not None:
                path.write_text(body, encoding='utf-8')
            with self.subTest(case=name):
                code, text = self.run_tool(self.base_args(path), FakeStore(routes()))
                self.assertEqual(code, 2)
                self.assertIn('credentials file', text)
                self.assertNotIn(PASSWORD, text)

    def test_credentials_file_size_is_bounded(self):
        path = self.credentials()
        path.write_text(json.dumps({'email': EMAIL, 'password': PASSWORD, 'orgID': 'o',
                                    'padding': 'y' * (RET.MAX_CREDENTIALS_BYTES + 1)}), encoding='utf-8')
        code, text = self.run_tool(self.base_args(path), FakeStore(routes()))
        self.assertEqual(code, 2)
        self.assertIn('bytes', text)

    def test_organization_name_is_accepted_instead_of_an_identifier(self):
        path = self.credentials({'email': EMAIL, 'password': PASSWORD, 'organizationName': 'default'})
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        code, _text = self.run_tool(self.base_args(path), store)
        self.assertEqual(code, 0)
        self.assertEqual(store.payload('POST /api/v2/sessions/email_password')['organizationName'], 'default')

    # --- check ---------------------------------------------------------------------------------

    def test_default_mode_reads_only_and_agreement_is_zero(self):
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 0)
        self.assertIn('all 3 signals match', text)
        self.assertEqual([key for key in store.keys() if '/settings/ttl' in key and key.startswith('POST')], [],
                         'a check must never write')

    def test_check_mismatch_exits_one_and_names_every_differing_signal(self):
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('360h0m0s')],
                                 log_reads=[logs(15)]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 1)
        self.assertEqual(text.count('MISMATCH'), 2)
        self.assertIn('--apply', text)

    def test_check_reports_an_unreadable_setting_as_two_not_as_zero(self):
        for store in (
                FakeStore(routes(trace_reads=[RET.Response(200, {'status': 'success',
                                                                 'data': {'type': 'traces'}})],
                                 metric_reads=[traces('720h0m0s')], log_reads=[logs(14)])),
                FakeStore(routes(trace_reads=[RET.Response(404)], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)])),
                FakeStore(routes(), default=RET.Response(503))):
            with self.subTest(routes=store.default.status):
                code, text = self.run_tool(self.base_args(self.credentials()), store)
                self.assertEqual(code, 2)
                self.assertIn('UNKNOWN', text)

    def test_login_failure_is_a_loud_two(self):
        store = FakeStore(routes(login=RET.Response(401, {'status': 'error'}),
                                 trace_reads=[traces('168h0m0s')]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 2)
        self.assertIn('login refused (HTTP 401)', text)
        self.assertEqual([key for key in store.keys() if 'ttl' in key], [], 'nothing is read after a refused login')

    def test_a_session_mechanism_the_store_refuses_is_retried_with_the_other_one(self):
        store = FakeStore(routes(login=RET.Response(200, {'status': 'success',
                                                         'data': {'accessToken': 'jwt-' + 'y' * 48}},
                                                        {'signoz-ae-session': 'session-value'}),
                                 trace_reads=[RET.Response(401), traces('168h0m0s'), traces('168h0m0s'),
                                              traces('168h0m0s')],
                                 metric_reads=[traces('720h0m0s')], log_reads=[logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 0, text)

    def test_every_session_mechanism_refused_is_a_two(self):
        store = FakeStore(routes(login=RET.Response(200, {'status': 'success',
                                                         'data': {'accessToken': 'jwt-' + 'y' * 48}},
                                                        {'signoz-ae-session': 'session-value'}),
                                 trace_reads=[RET.Response(403)]),
                          default=RET.Response(403))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 2)
        self.assertIn('refused every session credential', text)

    def test_a_login_that_returns_no_credential_is_not_a_pass(self):
        store = FakeStore(routes(login=RET.Response(200, {'status': 'success', 'data': {}}),
                                 trace_reads=[traces('168h0m0s')]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 2)
        self.assertIn('neither an access token nor a session cookie', text)

    # --- apply ---------------------------------------------------------------------------------

    def test_apply_sends_the_documented_request_shapes(self):
        store = FakeStore(routes(trace_reads=[traces('360h0m0s'), traces('168h0m0s')],
                                 metric_reads=[traces('360h0m0s'), traces('720h0m0s')],
                                 log_reads=[logs(15), logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()) + ['--apply'], store)
        self.assertEqual(code, 0, text)
        self.assertEqual(store.payload('POST /api/v2/sessions/email_password'),
                         {'email': EMAIL, 'password': PASSWORD, 'orgID': ORG})
        self.assertIn('POST /api/v1/settings/ttl?type=traces&duration=168h', store.keys())
        self.assertIn('POST /api/v1/settings/ttl?type=metrics&duration=720h', store.keys())
        self.assertEqual(store.payload('POST /api/v2/settings/ttl'),
                         {'type': 'logs', 'defaultTTLDays': 14, 'ttlConditions': []})
        self.assertIsNone(store.payload('POST /api/v1/settings/ttl?type=traces&duration=168h'),
                          'the v1 write carries hours in the query, not a body')

    def test_apply_warns_loudly_before_shortening_retention(self):
        store = FakeStore(routes(trace_reads=[traces('720h0m0s'), traces('168h0m0s')],
                                 metric_reads=[traces('720h0m0s'), traces('720h0m0s')],
                                 log_reads=[logs(30), logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()) + ['--apply'], store)
        self.assertEqual(code, 0)
        self.assertIn('WILL BE DELETED', text)
        self.assertIn('irreversible', text)

    def test_apply_keeps_existing_per_condition_log_ttl_rules(self):
        existing = [{'table': 'logs', 'ttl': 45, 'condition': {'sql': {'query': 'severity_text = 6'}}}]
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(15, existing), logs(14, existing)]))
        code, text = self.run_tool(self.base_args(self.credentials()) + ['--apply'], store)
        self.assertEqual(code, 0, text)
        self.assertEqual(store.payload('POST /api/v2/settings/ttl')['ttlConditions'], existing)
        self.assertIn('keeping 1 existing per-condition TTL rule', text)

    def test_apply_refuses_to_write_when_a_setting_cannot_be_read_first(self):
        store = FakeStore(routes(trace_reads=[RET.Response(500)], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()) + ['--apply'], store)
        self.assertEqual(code, 2)
        self.assertIn('ABORTED, nothing written', text)
        self.assertEqual([key for key in store.keys() if '/settings/ttl' in key and key.startswith('POST')], [],
                         'a failed read must stop the whole apply, not the one signal')

    def test_apply_proves_the_write_by_reading_it_back(self):
        store = FakeStore(routes(trace_reads=[traces('360h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()) + ['--apply'], store)
        self.assertEqual(code, 1, 'a store that ignored the write must not be reported as success')
        self.assertEqual(text.count('MISMATCH'), 1)

    def test_a_write_that_fails_halfway_says_which_signals_are_already_in_force(self):
        table = routes(trace_reads=[traces('360h0m0s'), traces('168h0m0s')],
                       metric_reads=[traces('360h0m0s')], log_reads=[logs(14)])
        table['POST /api/v1/settings/ttl?type=metrics&duration=720h'] = [RET.Response(500)]
        store = FakeStore(table)
        code, text = self.run_tool(self.base_args(self.credentials()) + ['--apply'], store)
        self.assertEqual(code, 2)
        self.assertIn('PARTIAL APPLY', text)
        self.assertIn('in force now: traces', text)
        self.assertIn('not set: metrics, logs', text)
        self.assertNotIn('POST /api/v2/settings/ttl', store.keys(), 'the signals after the failure stay untouched')

    # --- TTL units -----------------------------------------------------------------------------

    def test_durations_normalise_to_whole_hours(self):
        for value, unit, hours in (('336h0m0s', 'duration', 336), ('168h', 'duration', 168),
                                   ('7d', 'duration', 168), ('7 days', 'duration', 168),
                                   ('336h', 'days', 336), (7, 'days', 168), (15, 'duration', 15),
                                   (168 * 3_600_000_000_000, 'duration', 168), (7.0, 'days', 168)):
            with self.subTest(value=value, unit=unit):
                self.assertEqual(RET.parse_hours(value, unit=unit), hours)

    def test_unclear_or_impossible_durations_are_refused_not_guessed(self):
        for value, unit in (('15m', 'duration'), ('', 'duration'), ('seven days', 'duration'),
                            (0, 'days'), (0, 'duration'), (999999, 'duration'), (None, 'duration'),
                            (True, 'duration'), ([], 'duration'), (1.5, 'duration')):
            with self.subTest(value=value, unit=unit), self.assertRaises(RET.RetentionError):
                RET.parse_hours(value, unit=unit)

    def test_hours_render_as_days_when_they_divide(self):
        self.assertEqual(RET.format_hours(336), '14d (336h)')
        self.assertEqual(RET.format_hours(160), '6.67d (160h)')

    # --- transport rules -----------------------------------------------------------------------

    def test_the_store_origin_and_credentials_never_reach_a_log_or_message(self):
        """The sentinel password and the account name must not appear in anything the tool prints."""
        cases = {
            'refused login': (['--apply'],
                              FakeStore(routes(login=RET.Response(403, {'status': 'error'})))),
            'mismatch': (['--check'],
                         FakeStore(routes(trace_reads=[traces('360h0m0s')], metric_reads=[traces('360h0m0s')],
                                          log_reads=[logs(30)]))),
            'server error': ([], FakeStore(routes(), default=RET.Response(500))),
            'refused origin': (['--url', 'http://elsewhere.test:9'], FakeStore(routes())),
            'unreadable response': (['--check'],
                                    FakeStore(routes(trace_reads=[RET.Response(200, {'data': {'x': PASSWORD}})],
                                                     metric_reads=[traces('720h0m0s')],
                                                     log_reads=[logs(14)]))),
        }
        for name, (argv, store) in cases.items():
            with self.subTest(case=name):
                argv = list(argv)
                if '--url' in argv:
                    argv = argv + self.base_args(self.credentials())[2:]
                else:
                    argv = self.base_args(self.credentials()) + argv
                _code, text = self.run_tool(argv, store)
                self.assertNotIn(PASSWORD, text)
                self.assertNotIn(EMAIL, text)
                self.assertNotIn('orgID', text)

    def test_the_password_reaches_only_the_login_body_and_never_a_header(self):
        store = FakeStore(routes(trace_reads=[traces('168h0m0s')], metric_reads=[traces('720h0m0s')],
                                 log_reads=[logs(14)]))
        code, _text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 0)
        for key, payload, headers in store.calls:
            self.assertNotIn(PASSWORD, json.dumps(headers), key)
            if 'sessions' in key:
                continue
            self.assertNotIn(PASSWORD, json.dumps(payload), key)

    def test_the_urllib_path_refuses_proxies_and_redirects(self):
        """An installed ProxyHandler rewrites the destination from http_proxy/HTTP_PROXY.

        Handing build_opener a ProxyHandler({}) installs none at all, so the environment cannot
        send an administrator session somewhere else; the redirect handler is refused outright.
        """
        transport = RET.HttpTransport(ORIGIN)
        handlers = {type(handler).__name__ for handler in transport.opener.handlers}
        self.assertIn('NoRedirect', handlers)
        self.assertNotIn('ProxyHandler', handlers)
        self.assertEqual([handler for handler in transport.opener.handlers
                          if hasattr(handler, 'proxy_bisect')], [])
        self.assertIsNone(next(h for h in transport.opener.handlers
                               if type(h).__name__ == 'NoRedirect').redirect_request(
            None, None, 302, '', {}, 'http://elsewhere/'))

    def test_an_unreachable_store_is_a_two_with_no_traceback(self):
        path = self.credentials()
        code, text = self.run_tool(['--url', 'http://127.0.0.1:1', '--credentials-file', str(path)])
        self.assertEqual(code, 2)
        self.assertIn('retention:', text)
        self.assertNotIn('Traceback', text)

    def test_the_product_transport_is_preferred_when_importable(self):
        seen = {}

        class StubClient:
            def __init__(self, base, token, **kwargs):
                seen['base'], seen['token'], seen['kwargs'] = base, token, kwargs

            def request(self, method, path, payload=None, *, headers=None):
                seen['call'] = (method, path)
                return 200, {'status': 'success'}

        original = RET.json_client_class
        RET.json_client_class = lambda: StubClient
        self.addCleanup(setattr, RET, 'json_client_class', original)
        transport = RET.PackageTransport(ORIGIN)
        self.assertTrue(transport.usable({'Authorization': 'Bearer ' + 't' * 40}))
        for unfit in ({'Cookie': 'a=b'}, {'Authorization': 'Bearer short'}, {'Authorization': 'Basic ' + 'a' * 40},
                      {'Authorization': 'Bearer tok' + '\nenv'}, {}):
            with self.subTest(headers=unfit):
                self.assertFalse(transport.usable(unfit))
        response = transport.request('GET', '/api/v1/settings/ttl?type=traces',
                                     headers={'Authorization': 'Bearer ' + 't' * 40})
        self.assertEqual(response.status, 200)
        self.assertEqual(seen['call'], ('GET', '/api/v1/settings/ttl?type=traces'))
        self.assertEqual(seen['token'], 't' * 40)
        self.assertTrue(seen['kwargs']['allow_http'])
        with self.assertRaises(RET.RetentionError):
            transport.request('GET', '/api/v1/settings/ttl?type=logs', headers={'Cookie': 'a=b'})

    def test_a_store_version_that_names_other_fields_fails_closed_with_the_names(self):
        store = FakeStore(routes(trace_reads=[RET.Response(200, {'status': 'success',
                                                                 'data': {'warmInterval': '7d'}})],
                                 metric_reads=[traces('720h0m0s')], log_reads=[logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 2)
        self.assertIn('no ttl field', text)
        self.assertIn('warmInterval', text)

    def test_a_ttl_list_response_is_matched_on_its_type(self):
        store = FakeStore(routes(trace_reads=[RET.Response(200, {'status': 'success', 'data': [
            {'type': 'metrics', 'ttl': '720h0m0s'}, {'type': 'traces', 'ttl': '168h0m0s'}]})],
                                 metric_reads=[traces('720h0m0s')], log_reads=[logs(14)]))
        code, text = self.run_tool(self.base_args(self.credentials()), store)
        self.assertEqual(code, 0, text)

    def test_permission_warning_only_fires_on_loose_posix_modes(self):
        self.assertIsNone(RET.permissions_warning(0o600))
        self.assertIsNone(RET.permissions_warning(None))
        self.assertIn('mode 644', RET.permissions_warning(0o644))
        self.assertIsNone(RET.permissions_warning(0o700), 'owner-only bits are not exposure')
        self.assertIn('mode 660', RET.permissions_warning(0o660))

    def test_defaults_match_the_documented_env_template(self):
        self.assertEqual(RET.DEFAULT_DAYS, {'traces': 7, 'metrics': 30, 'logs': 14})
        self.assertEqual(RET.resolve_days({}), RET.DEFAULT_DAYS)
        self.assertEqual(RET.resolve_days({'logs': 30}), {'traces': 7, 'metrics': 30, 'logs': 30})
        with self.assertRaises(RET.RetentionError):
            RET.resolve_days({'metrics': 4000})


if __name__ == '__main__':
    unittest.main()

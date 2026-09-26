"""The read-only Local API client (crowdsec task 3, second half): what the bouncer key can and cannot do.

`threat detection engine`'s kept half makes CrowdSec's Local API the decision store, so this component needs to *show*
decisions. It does not need to make them — and upstream's own permission model says so: an API key "can
only read decisions", where creating one takes a **machine** credential. `LocalApi` is that boundary in
code, so the tests are about the boundary rather than about HTTP:

* the key rides `X-Api-Key` and never `Authorization`, and no write verb is ever issued;
* **no write verb exists to issue** — asserted on the module's own syntax tree, not on a code review;
* `null` from a 200 is "no decisions", and anything else (a 401, a non-list, a field nobody read) is an
  error, never an empty list — the difference between "nothing is blocking that address" and "we could
  not tell", which is the difference an operator is about to act on;
* **one host asks one question** — the scope that leaves the process for a `range=` read comes from the
  parsed address's own family, so a bare v4 host and its `/32`, and a bare v6 host (compressed or
  expanded) and its `/128`, send one identical query. The component validation's `/32` literal sent two.

Nothing here opens a socket: `LocalApi.client` is replaced with a recorder, the way
`tests/test_ai_client.py` drives its transport. `conformance.md` carries the runtime rows that would need
a real CrowdSec, all of them `NOT RUN`.
"""
import ast
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

from local_observe.http import JsonClient, TransportError
from local_observe.platform import crowdsec
from local_observe.platform.state import StateError

ROOT = Path(__file__).resolve().parents[1]
MODULE_SOURCE = (ROOT / 'local_observe' / 'platform' / 'crowdsec.py').read_text(encoding='utf-8')
ENDPOINT = 'https://lapi.invalid'
DECISION = {'id': 7, 'origin': 'crowdsec', 'scope': 'Ip', 'type': 'ban', 'value': '10.11.0.21',
            'duration': '4h', 'scenario': 'crowdsecurity/ssh-bf', 'simulated': False}


class Recorder:
    """A stand-in transport that records what was asked and answers what the test says it should."""

    def __init__(self, answer=(200, [dict(DECISION)])):
        self.answer = answer
        self.calls = []

    def request(self, method, path='', payload=None, *, headers=None, timeout=None):
        self.calls.append({'method': method, 'path': path, 'payload': payload, 'headers': dict(headers or {})})
        return self.answer


def client(answer=(200, [dict(DECISION)]), *, url=ENDPOINT, token='bouncer-key'):
    api = crowdsec.LocalApi(url, token)
    api.client = Recorder(answer)
    return api


def asked(path: str) -> dict[str, list[str]]:
    """Decode the query sent to the recorded request boundary."""
    return urllib.parse.parse_qs(urllib.parse.urlparse(path).query)


class SurfaceTests(unittest.TestCase):
    """The read-only promise, pinned where a later edit cannot quietly widen it."""

    def test_the_client_offers_two_reads_and_no_verb_that_could_block(self):
        self.assertEqual(sorted(name for name in dir(crowdsec.LocalApi) if not name.startswith('_')),
                         ['covers', 'decisions'])
        for name in ('add_decision', 'delete_decisions', 'post', 'delete', 'apply', 'remove', 'pulse'):
            with self.subTest(verb=name):
                self.assertFalse(hasattr(crowdsec.LocalApi, name))

    def test_the_module_issues_get_and_nothing_else(self):
        """Every `self.client.request(...)` call site in the module, read out of its own syntax tree.

        A method list can be extended by one line of code; this test is the reason that line has to be
        reviewed as the change in power that it is.
        """
        tree = ast.parse(MODULE_SOURCE)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == 'request']
        self.assertTrue(calls, 'the client reads through a transport, or this test has lost its subject')
        for call in calls:
            self.assertEqual(ast.literal_eval(call.args[0]), 'GET')
            self.assertLessEqual(len(call.args), 2, 'a request with a payload is a write wearing a GET')

    def test_the_key_is_an_api_key_and_never_an_authorization_header(self):
        """Upstream distinguishes the two credential kinds; sending the wrong one is a 401 with no clue."""
        api = client()
        api.decisions()
        sent = api.client.calls[0]['headers']
        self.assertEqual(sent, {'X-Api-Key': 'bouncer-key'})
        self.assertNotIn('Authorization', sent)

    def test_the_transport_itself_carries_no_bearer_token(self):
        """`JsonClient(base, None)` is the documented no-Authorization mode: one credential, one header."""
        built = crowdsec.LocalApi(ENDPOINT, 'bouncer-key')
        self.assertIsInstance(built.client, JsonClient)
        self.assertIsNone(built.client.token)


class ReadTests(unittest.TestCase):
    """A 200 is an answer, `null` is "nothing matches", and everything else is an error."""

    def test_one_decision_comes_back_as_a_bounded_defensive_dict(self):
        self.assertEqual(client().decisions(), [DECISION])

    def test_the_query_string_is_what_upstream_documents(self):
        api = client()
        api.decisions(ip='10.11.0.21')
        api.decisions(cidr='10.11.0.0/24')
        api.decisions(scope='username', value='admin')
        self.assertEqual([call['path'] for call in api.client.calls],
                         ['/v1/decisions?ip=10.11.0.21', '/v1/decisions?range=10.11.0.0%2F24',
                          '/v1/decisions?scope=username&value=admin'])

    def test_an_empty_answer_upstream_reads_as_no_decisions_not_as_a_failure(self):
        """The v1.8.1 release note about `null` vs an empty slice is why this needs its own test."""
        for answer in ((200, None), (200, [])):
            with self.subTest(answer=answer[1]):
                api = client(answer)
                self.assertEqual(api.decisions(), [])
                self.assertFalse(api.covers('10.11.0.21'))

    def test_covers_asks_the_one_question_upstream_answers_authoritatively(self):
        """Containment is upstream's job here: `?ip=` answers with the ranges that contain the address.

        So this method must not re-filter the answer — a local `ip in value` check would disagree with
        upstream about a `/24` decision in the direction of "not covered", which is the wrong way to be
        wrong when the caller is deciding whether an address is already blocked. The test pins the
        question, not an answer the stub invented.
        """
        api = client()
        self.assertTrue(api.covers('10.11.0.21'))
        self.assertEqual(api.client.calls[0]['path'], '/v1/decisions?ip=10.11.0.21')
        with self.assertRaises(StateError):
            api.covers('10.11.0.21/24')
        self.assertEqual(len(api.client.calls), 1, 'a refused address must not reach the endpoint')

    def test_a_refusal_is_never_mistaken_for_an_empty_decision_list(self):
        """`False` from `covers()` on a 401 would read as "nothing is blocking it" to a human deciding."""
        for status in (401, 403, 500):
            with self.subTest(status=status):
                with self.assertRaises(TransportError):
                    client(answer=(status, [])).decisions()

    def test_filters_are_asked_one_at_a_time(self):
        api = client()
        with self.assertRaises(StateError):
            api.decisions(ip='10.11.0.21', cidr='10.11.0.0/24')
        with self.assertRaises(StateError):
            api.decisions(ip='10.11.0.21', scope='username')
        with self.assertRaises(StateError):
            api.decisions(scope='username')
        self.assertEqual(api.client.calls, [], 'a refused question was still asked of the network')

    def test_an_unparseable_address_is_refused_before_the_request(self):
        api = client()
        for bad in ('10.11.0.300', 'anything', '203.0.113.9/33', '10.11.0.21/24', ''):
            with self.subTest(value=bad):
                with self.assertRaises(StateError):
                    api.decisions(ip=bad)
        self.assertEqual(api.client.calls, [])

    def test_a_range_question_is_written_as_a_prefix(self):
        """`?range=` wants a prefix: a bare v4 host is asked as its own /32, host bits refused."""
        api = client()
        api.decisions(cidr='10.11.0.21')
        api.decisions(cidr='10.11.0.0/24')
        self.assertEqual([call['path'] for call in api.client.calls],
                         ['/v1/decisions?range=10.11.0.21%2F32', '/v1/decisions?range=10.11.0.0%2F24'])
        with self.assertRaises(StateError) as caught:
            api.decisions(cidr='10.11.0.21/24')
        self.assertIn('10.11.0.0/24', str(caught.exception), 'the refusal names the prefix to ask for')

    def test_the_host_prefix_comes_from_the_address_family_not_from_a_literal(self):
        """Equivalent bare and explicit host prefixes send the same query in both address families."""
        for spellings, expect in ((('10.11.0.21', '10.11.0.21/32'), '10.11.0.21/32'),
                                  (('2001:db8::1234', '2001:0db8:0000:0000:0000:0000:0000:1234',
                                    '2001:db8:0000:0000:0000:0000:0000:1234/128'), '2001:db8::1234/128')):
            api = client()
            for spelling in spellings:
                api.decisions(cidr=spelling)
            with self.subTest(address=expect):
                self.assertEqual(len({call['path'] for call in api.client.calls}), 1,
                                 'the same host asked as more than one scope')
                self.assertEqual(asked(api.client.calls[0]['path']), {'range': [expect]})

    def test_an_explicit_prefix_keeps_the_width_it_was_given_in_either_family(self):
        """The fix is about bare addresses only: a written prefix is a written prefix, `/48` included."""
        api = client()
        api.decisions(cidr='2001:db8::/48')
        api.decisions(cidr='2001:db8:1::/64')
        api.decisions(cidr='10.11.0.0/24')
        self.assertEqual([asked(call['path']) for call in api.client.calls],
                         [{'range': ['2001:db8::/48']}, {'range': ['2001:db8:1::/64']},
                          {'range': ['10.11.0.0/24']}])
        with self.assertRaises(StateError) as caught:
            api.decisions(cidr='2001:db8::5/64')
        self.assertIn('2001:db8::/64', str(caught.exception), 'the refusal names the prefix to ask for')
        self.assertEqual(len(api.client.calls), 3, 'a refused prefix was still asked of the endpoint')

    def test_an_address_question_stays_bare_in_both_families(self):
        """`prefix=True` is the only place a host prefix is added, so `ip=` must never grow one."""
        api = client()
        api.decisions(ip='2001:db8::1234')
        api.decisions(ip='10.11.0.21')
        self.assertEqual([asked(call['path']) for call in api.client.calls],
                         [{'ip': ['2001:db8::1234']}, {'ip': ['10.11.0.21']}])
        with self.assertRaises(StateError):
            api.decisions(ip='2001:db8::1234/128')
        self.assertEqual(len(api.client.calls), 2)


class BoundedAnswerTests(unittest.TestCase):
    """A surprising answer is a refusal, because the caller is about to approve a block."""

    def rows(self, answer):
        return crowdsec._decision_rows(answer)

    def test_only_the_fields_this_contract_read_are_kept(self):
        self.assertEqual(sorted(self.rows([dict(DECISION)])[0]), sorted(DECISION))

    def test_a_field_nobody_read_at_the_pinned_version_refuses_the_whole_answer(self):
        with self.assertRaises(StateError) as caught:
            self.rows([dict(DECISION, simulated_by_a_new_field='x')])
        self.assertIn('field this contract has not read', str(caught.exception))

    def test_an_answer_that_is_not_a_list_is_refused(self):
        for answer in ({'decisions': []}, 'many', 7, [DECISION, 'not-an-object']):
            with self.subTest(answer=str(answer)[:18]):
                with self.assertRaises(StateError):
                    self.rows(answer)

    def test_an_answer_beyond_the_bound_is_refused_rather_than_truncated(self):
        with self.assertRaises(StateError):
            self.rows([dict(DECISION, id=index) for index in range(crowdsec.MAX_DECISIONS + 1)])

    def test_only_the_types_the_evidence_store_can_hold_are_accepted(self):
        for broken, marker in ((dict(DECISION, id='7'), 'not an integer'),
                               (dict(DECISION, id=True), 'not an integer'),
                               (dict(DECISION, simulated='false'), 'not a boolean'),
                               (dict(DECISION, value='x' * 300), 'unbounded decision value'),
                               (dict(DECISION, value=''), 'unbounded decision value'),
                               (dict(DECISION, value=7), 'unbounded decision value')):
            with self.subTest(field=list(set(broken) - set(DECISION) - {'id', 'simulated', 'value'}) or marker):
                with self.assertRaises(StateError) as caught:
                    self.rows([broken])
                self.assertIn(marker, str(caught.exception))

    def test_a_stored_row_round_trips_as_json(self):
        """The defensive copy has to survive the store: a tuple or an IPv4 object would not."""
        self.assertEqual(json.loads(json.dumps(self.rows([dict(DECISION)])))[0]['value'], '10.11.0.21')


class EnvironmentTests(unittest.TestCase):
    """The off switch, and the mounted-file rule the credential reader enforces."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / 'bouncer'
        # Bytes, no line ending: `read_credential` refuses a file holding a control character, and
        # `echo x > file` on Windows writes the CRLF that trips it — a mount that fails at service start
        # for a reason no error message mentions is the failure mode worth encoding here.
        self.key.write_bytes(b'bouncer-key')
        self.key.chmod(0o600)

    def environ(self, **changes):
        base = {crowdsec.LAPI_URL_ENVIRONMENT: ENDPOINT,
                f'{crowdsec.BOUNCER_TOKEN_ENVIRONMENT}_FILE': str(self.key)}
        for name, value in changes.items():
            if value is None:
                base.pop(name, None)
            else:
                base[name] = value
        return base

    def test_no_endpoint_is_the_documented_off_switch_and_builds_nothing(self):
        self.assertIsNone(crowdsec.client_from_environment({}))
        self.assertIsNone(crowdsec.client_from_environment(self.environ(**{
            crowdsec.LAPI_URL_ENVIRONMENT: '   '})))

    def test_an_endpoint_without_a_credential_names_the_file_it_wanted(self):
        with self.assertRaises(StateError) as caught:
            crowdsec.client_from_environment(self.environ(**{
                f'{crowdsec.BOUNCER_TOKEN_ENVIRONMENT}_FILE': str(self.root / 'absent')}))
        self.assertIn(f'{crowdsec.BOUNCER_TOKEN_ENVIRONMENT}_FILE', str(caught.exception))

    def test_a_plaintext_endpoint_needs_the_estate_wide_acknowledgement(self):
        """`http://` is the flat internal network, and saying so is a flag, not a default."""
        with self.assertRaises(TransportError):
            crowdsec.client_from_environment(self.environ(**{crowdsec.LAPI_URL_ENVIRONMENT:
                                                             'http://lapi.invalid:8080'}))
        built = crowdsec.client_from_environment(self.environ(**{
            crowdsec.LAPI_URL_ENVIRONMENT: 'http://lapi.invalid:8080', 'LO_INTERNAL_ALLOW_HTTP': '1'}))
        self.assertIsNotNone(built)

    def test_the_client_a_deployment_gets_reads_the_key_it_mounted(self):
        built = crowdsec.client_from_environment(self.environ())
        self.assertIsNotNone(built)
        self.assertEqual(built.token, 'bouncer-key')
        built.client = Recorder()
        built.decisions()
        self.assertEqual(built.client.calls[0]['headers'], {'X-Api-Key': 'bouncer-key'})


if __name__ == '__main__':
    unittest.main()

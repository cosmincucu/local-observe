"""Route coverage for `POST /v1/intake/<source>` (event intake): roles, bounds, and what lands in the store.

The transport is deliberately thin — normalisation lives in `local_observe/platform/intake.py` — so
these tests are about the four things only the route can get wrong: who may post, how big a body may
be, what the answer says, and the order writes go in (evidence before the event that cites it, the way
`detection_worker.tick` already posts `/v1/evidence` before `/v1/events`).

Style follows `tests/test_api_errors.py`: a real `Store` on a temp path and the ASGI app called
directly. No network endpoint is bound or connected anywhere in this file.
"""
import asyncio
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from local_observe.inventory import index
from local_observe.inventory.validation import read_document, utc_text
from local_observe.platform import intake
from local_observe.platform.api import create_app
from local_observe.platform.detections import event as build_event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Store

ROOT = Path(__file__).resolve().parents[1]
# The route under test reads the real clock (state.clock()), and evidence expires 15 days after
# its window (store.client.EVIDENCE_RETENTION_DAYS). A fixed calendar date therefore turned into
# 'expired' on 2026-09-23. Every alert time here is an offset from NOW, an hour before the current
# minute, so a firing alert's evaluation window has always finished, as it had for the old fixed date.
NOW = dt.datetime.now(dt.timezone.utc).replace(second=0, microsecond=0) - dt.timedelta(hours=1)


def at(minutes: int) -> str:
    """An Alertmanager timestamp `minutes` after NOW (negative is earlier)."""
    return utc_text(NOW + dt.timedelta(minutes=minutes))


STARTS_AT = at(-10)
HOST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
PRODUCER = {'identity': 'alertmanager', 'role': 'producer', 'token': 'p' * 32}
READER = {'identity': 'watcher', 'role': 'reader', 'token': 'r' * 32}
SUMMARY = {'identity': 'homepage', 'role': 'summary', 'token': 's' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
CREDENTIALS = [PRODUCER, READER, SUMMARY, HUMAN]
DOCUMENT = {'schema_version': 1, 'sources': {'alertmanager': {
    'HighCPU': {'rule_id': 'alertmanager.high_cpu', 'kind': 'threshold', 'window_seconds': 300,
                'sample_field': 'value'}}}}


def alert(**changes) -> dict:
    """One firing `alerts[]` entry; `severity=`/`instance=` edit labels, anything else the alert itself."""
    item = {'status': 'firing',
            'labels': {'alertname': 'HighCPU', 'severity': 'crit', 'instance': 'web01:9100'},
            'annotations': {'value': '0.93'}, 'startsAt': STARTS_AT,
            'endsAt': '0001-01-01T00:00:00Z', 'fingerprint': 'aaaa'}
    for name in ('alertname', 'severity', 'instance'):
        if name in changes:
            value = changes.pop(name)
            if value is None:
                item['labels'].pop(name, None)
            else:
                item['labels'][name] = value
    item.update(changes)
    return item


def envelope(*alerts, **fields) -> dict:
    """A webhook body carrying the given alerts (one firing alert if none are named)."""
    body = {'version': '4', 'groupKey': '{}:{}', 'status': 'firing', 'receiver': 'webhook',
            'alerts': list(alerts) or [alert()]}
    body.update(fields)
    return body


async def _call(app, method: str, path: str, token: str | None, body: bytes = b'',
                query: bytes = b'') -> tuple[int, dict]:
    """One request through the ASGI app itself; `token=None` sends no Authorization header at all."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)
    headers = [] if token is None else [(b'authorization', ('Bearer ' + token).encode())]
    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers,
               'query_string': query}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


class IntakeRouteTests(unittest.TestCase):
    """The route's own promises: admission, idempotence, and the answer's shape."""

    def setUp(self):
        """A fresh store, a built inventory index and the one declared rule, per test."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.store = Store(root / 'state.db', NotificationPolicy(delivery_mode='off'))
        self.index_path = root / 'inventory.db'
        index.build(read_document(ROOT / 'examples' / 'inventory' / 'declared.yaml'), self.index_path,
                    'fixture-v1', now=NOW)
        self.rules = intake.validate_rules(DOCUMENT)

    def app(self, rules=None, index_path='default'):
        """The app under test; `rules=None` means the documented off switch, not a wildcard."""
        return create_app(self.store, CREDENTIALS, {}, None,
                          self.index_path if index_path == 'default' else index_path,
                          None, None, self.rules if rules is None else rules)

    def post(self, path='/v1/intake/alertmanager', body=None, token=PRODUCER['token'], app=None):
        """One POST of a document (or raw bytes) through a freshly built app."""
        raw = body if isinstance(body, bytes) else json.dumps(envelope() if body is None else body).encode()
        return asyncio.run(_call(app or self.app(), 'POST', path, token, raw))

    def get(self, path: str, query: bytes = b'', token: str = READER['token']):
        """One GET through a freshly built app."""
        return asyncio.run(_call(self.app(), 'GET', path, token, b'', query))

    def rows(self, table: str):
        """Every row of one operational table, newest first, as `Store` keeps them."""
        return self.store.records(table, 100)

    # ---------------------------------------------------------------- admission

    def test_a_producer_posts_the_sources_own_envelope_and_two_events_arrive(self):
        """Coverage resolved then the verdict, in that order, over the same condition's two rules."""
        status, body = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(body['source'], 'alertmanager')
        self.assertEqual([item['status'] for item in body['events']], ['accepted', 'accepted'])
        self.assertEqual([item['transition'] for item in body['events']], [None, 'opened'])
        kinds = [json.loads(row['payload'])['kind'] for row in self.rows('events')]
        self.assertEqual(sorted(kinds), ['coverage', 'threshold'])

    def test_the_answer_names_the_link_verdict_that_the_stored_event_cannot_carry(self):
        """A resolved host and an unresolved one look identical in the row; the answer says which."""
        resolved = self.post(body=envelope(alert(instance='probe-1.example.test:9100')))[1]['events']
        self.assertEqual({item['resource_link'] for item in resolved}, {'resolved'})
        unknown = self.post(body=envelope(alert(instance='not-declared.example')))[1]['events']
        self.assertEqual({item['resource_link'] for item in unknown}, {'unknown'})
        stored = [json.loads(row['payload']) for row in self.rows('events')]
        self.assertEqual({item['resource_id'] for item in stored}, {HOST_ID, None})

    def test_an_unresolved_instance_is_admitted_rather_than_refused(self):
        """docs/CONTRACTS.md §4 makes `resource_id` nullable: unresolved is the admitted answer."""
        status, body = self.post(body=envelope(alert(instance='nowhere.invalid')))
        self.assertEqual(status, 200)
        self.assertTrue(all(item['event_id'] for item in body['events']))

    def test_the_declared_uuid_is_what_lands_and_never_a_name_derived_from_the_host(self):
        """The instance string appears nowhere in the stored row once the alias resolved."""
        self.post(body=envelope(alert(instance='probe-1.example.test:9100')))
        for row in self.rows('events'):
            self.assertEqual(json.loads(row['payload'])['resource_id'], HOST_ID)
            self.assertNotIn('probe-1', row['payload'])

    def test_a_reposted_envelope_is_duplicate_rows_one_incident_and_one_outbox_entry(self):
        """The retry identity's whole purpose: Alertmanager repeats, and incidents must not multiply."""
        first = self.post()[1]['events']
        second = self.post()[1]['events']
        self.assertEqual([item['status'] for item in first], ['accepted', 'accepted'])
        self.assertEqual([item['status'] for item in second], ['duplicate', 'duplicate'])
        self.assertEqual([item['event_id'] for item in first], [item['event_id'] for item in second])
        self.assertEqual(len(self.rows('incidents')), 1)
        self.assertEqual(len(self.rows('outbox')), 1)
        self.assertEqual(len(self.rows('events')), 2)

    def test_a_resolution_closes_the_incident_the_firing_alert_opened(self):
        """`status: resolved` on the event is the field that closes it, which v0.1 recorded as a label."""
        opened = self.post()[1]['events'][1]
        closed = self.post(body=envelope(alert(status='resolved', endsAt=at(-1))))
        self.assertEqual(closed[0], 200)
        self.assertEqual(closed[1]['events'][1]['transition'], 'resolved')
        self.assertEqual(closed[1]['events'][1]['incident_id'], opened['incident_id'])
        self.assertEqual([row['status'] for row in self.rows('incidents')], ['resolved'])

    def test_the_two_transitions_of_one_alert_are_two_events_not_one_rewritten_row(self):
        """The reason `retry_identity` puts `status` in the identity, and the limit of what that buys.

        Alertmanager posts a firing alert and its resolution with the same `startsAt`. Under
        `detections.event`'s identity the two would collide on `events UNIQUE (source,
        source_event_id)` with different contents — `Event retry changed contents` — so `status` is
        part of the identity here, and a resolution whose `endsAt` coincides with the firing event's
        window end is refused for the *real* reason instead: `Store` refuses two verdicts that disagree
        at one condition watermark. Both halves are pinned, because the second is an open item for
        `suppression` and not something this route can fix without lying about a window.
        """
        opened = self.post()[1]['events'][1]
        status, body = self.post(body=envelope(alert(status='resolved', endsAt=at(-2))))
        self.assertEqual(status, 200)
        self.assertEqual(body['events'][1]['incident_id'], opened['incident_id'])
        self.assertEqual(body['events'][1]['transition'], 'resolved')
        self.assertNotIn('retry changed contents', json.dumps(body))

    def test_a_resolution_ending_exactly_where_the_firing_window_ends_is_refused_as_a_conflict(self):
        """The one coincidence this design cannot resolve, named rather than papered over.

        The firing event's window is `[startsAt, startsAt + window_seconds]`, so a condition that
        cleared at that same instant produces a resolution with the same window end: two opposite
        verdicts about one watermark, which `state.py` refuses. Nothing further lands, the incident
        stays open, and the refusal is stable — a re-post answers the same way. Closing it needs
        `suppression`'s flap handling or a watermark rule in `state.py`, not a window invented here.
        """
        self.post()
        status, body = self.post(body=envelope(alert(status='resolved', endsAt=at(-5))))
        self.assertEqual((status, body['error']), (400, 'conflict'))
        self.assertIn('watermark', body['detail'])
        again = self.post(body=envelope(alert(status='resolved', endsAt=at(-5))))
        self.assertEqual(again[0], 400)
        self.assertEqual([row['status'] for row in self.rows('incidents')], ['open'])
        self.assertEqual(len(self.rows('events')), 2)

    def test_a_flap_opens_a_second_incident_which_is_the_fact_r_p05_folds(self):
        """Re-firing after a resolution is a new condition occurrence, not a duplicate of the first.

        Recorded here so the behaviour is pinned rather than discovered later: this route opens two
        incidents for a flapping condition, and `suppression`'s suppression decides when the second one is
        worth a page. Nothing in this change folds them.
        """
        first = self.post()[1]['events'][1]['incident_id']
        self.post(body=envelope(alert(status='resolved', endsAt=at(-1))))
        again = self.post(body=envelope(alert(startsAt=at(0))))
        self.assertEqual(again[0], 200)
        self.assertNotEqual(again[1]['events'][1]['incident_id'], first)
        self.assertEqual(len(self.rows('incidents')), 2)

    def test_the_sample_the_route_captured_is_readable_as_evidence_afterwards(self):
        """The whole point of the two-write order: a reference that names a row the platform kept."""
        status, body = self.post()
        verdict = json.loads([row for row in self.rows('events')
                              if json.loads(row['payload'])['kind'] != 'coverage'][0]['payload'])
        sample_id = verdict['evidence'][0]['parameters']['sample_id']
        self.assertEqual(status, 200)
        answer = self.get('/v1/evidence', f'source=alertmanager&sample_id={sample_id}'.encode())
        self.assertEqual(answer[0], 200)
        self.assertEqual(answer[1]['status'], 'available')
        self.assertEqual(answer[1]['sample']['value'], 0.93)

    def test_an_alert_that_brought_no_number_creates_no_evidence_row(self):
        """§6's negative: coverage references the platform's receipt, and no sample is written."""
        document = intake.validate_rules({'schema_version': 1, 'sources': {'alertmanager': {
            'HighCPU': {'rule_id': 'alertmanager.high_cpu', 'kind': 'availability'}}}})
        status, body = self.post(body=envelope(), app=self.app(rules=document))
        self.assertEqual(status, 200)
        self.assertEqual([json.loads(row['payload'])['kind'] for row in self.rows('events')], ['coverage'])
        self.assertEqual(len(self.store.records('events', 10)), 1)
        self.assertEqual(self.get('/v1/evidence', b'source=alertmanager&sample_id=anything')[1],
                         {'status': 'unavailable'})
        self.assertNotIn('evidence_id', json.dumps(body))

    def test_one_malformed_alert_refuses_the_envelope_and_writes_no_rows_at_all(self):
        """Shape is judged for every event before the first write, so a 400 means nothing landed."""
        status, body = self.post(body=envelope(alert(), alert(status='si'), alert()))
        self.assertEqual(status, 400)
        self.assertIn('alert 1', body['detail'])
        self.assertEqual(self.rows('events'), [])
        self.assertEqual(self.rows('incidents'), [])
        self.assertEqual(self.rows('outbox'), [])

    def test_a_degraded_alert_is_admitted_as_coverage_and_opens_its_own_incident(self):
        """v0.1's `unnormalized=True`, in the shape this platform can act on: visible and durably filed."""
        status, body = self.post(body=envelope(alert(alertname='NobodyDeclaredMe')))
        self.assertEqual(status, 200)
        self.assertEqual([item['transition'] for item in body['events']], ['opened'])
        event = json.loads(self.rows('events')[0]['payload'])
        self.assertEqual(event['kind'], 'coverage')
        self.assertEqual(event['rule_id'], intake.UNDECLARED_RULE_COVERAGE)

    # ---------------------------------------------------------------- roles and paths

    def test_a_reader_may_not_post_and_nothing_is_written_on_the_way_out(self):
        """The role gate is `Store`'s producer check, reached before the envelope is normalised."""
        status, body = self.post(token=READER['token'])
        self.assertEqual((status, body['error']), (400, 'not_authorised'))
        self.assertEqual(self.rows('events'), [])

    def test_a_summary_credential_is_turned_away_before_the_body_is_read(self):
        """The same `summary_only` answer `/v1/events` gives, and the same non-audited one."""
        status, body = self.post(token=SUMMARY['token'])
        self.assertEqual((status, body['error']), (403, 'summary_only'))
        self.assertEqual(self.rows('events'), [])

    def test_a_request_with_no_credential_is_refused_as_unauthenticated(self):
        """No branch of this route is reachable without a bearer token."""
        self.assertEqual(self.post(token=None)[0], 401)

    def test_the_path_must_name_the_callers_own_identity(self):
        """A producer token cannot post on another source's behalf, whatever the path claims."""
        status, body = self.post(path='/v1/intake/gatus')
        self.assertEqual((status, body['error']), (400, 'not_authorised'))
        self.assertEqual(self.rows('events'), [])

    def test_a_path_that_names_no_single_source_is_refused_naming_the_rule(self):
        """`/v1/intake/` and `/v1/intake/a/b` are neither this route nor an unknown one."""
        for path in ('/v1/intake/', '/v1/intake/alertmanager/extra', '/v1/intake//'):
            with self.subTest(path=path):
                status, body = self.post(path=path)
                self.assertEqual(status, 400)
                self.assertIn('exactly one source', body['detail'])

    def test_a_registered_source_with_no_rules_leaves_the_webhook_refusing(self):
        """The off switch is loud to the sender: an accepted alert with an invented rule would be silent."""
        status, body = self.post(app=self.app(rules={}))
        self.assertEqual(status, 400)
        self.assertIn('No intake rules are configured', body['detail'])
        self.assertEqual(self.rows('events'), [])

    def test_a_source_with_no_adapter_is_refused_and_told_what_exists(self):
        """A webhook for a source nobody has ported is a refusal, not an unnormalised publication."""
        other = {'identity': 'gatus', 'role': 'producer', 'token': 'g' * 32}
        app = create_app(self.store, CREDENTIALS + [other], {}, None, self.index_path, None, None,
                         self.rules)
        status, body = self.post(path='/v1/intake/gatus', app=app, token=other['token'])
        self.assertEqual(status, 400)
        self.assertIn('No intake adapter is registered for source gatus', body['detail'])
        self.assertIn('alertmanager', body['detail'])

    def test_an_intake_body_that_is_not_a_json_object_is_a_client_error(self):
        """The parser's existing answer, named here because this route reads the same body."""
        self.assertEqual(self.post(body=b'[1,2,3]')[0], 400)
        self.assertEqual(self.post(body=b'{')[0], 400)

    # ---------------------------------------------------------------- bounds

    def test_an_envelope_over_the_body_ceiling_is_refused_whole_before_being_parsed(self):
        """64 KiB is the platform's event ceiling, and this route inherits it as a request bound.

        The bound fires on the bytes, not on the parse: the answer is one fixed code, and nothing from
        the rejected body — not a note, not a hostname, not a token in a URL — reaches the response.
        """
        padded = {'version': '4', 'status': 'firing',
                  'alerts': [dict(alert(), annotations={'value': '0.93',
                                                        'note': 'secret-text' + 'n' * 2000})
                             for _index in range(40)]}
        self.assertGreater(len(json.dumps(padded).encode()), 65536)
        status, body = self.post(body=padded)
        self.assertEqual((status, body['error']), (413, 'body_too_large'))
        self.assertEqual(self.rows('events'), [])
        self.assertNotIn('secret-text', json.dumps(body))

    def test_the_transport_bound_is_what_an_oversized_event_meets_first(self):
        """`state.validate_event`'s 64 KiB ceiling is unreachable over this route, and that is honest.

        A body that large is refused as `body_too_large` before a byte of it is parsed, so the state
        layer's `Event exceeds 64 KiB` can only ever fire for a producer that calls `Store.intake`
        in-process (the CLI and the workers do). Recorded as a test because the alternative is a
        reader believing the API enforces a per-event size it never sees.
        """
        padded = {'version': '4', 'status': 'firing',
                  'alerts': [dict(alert(), annotations={'value': '0.93', 'note': 'p' * 3000})
                             for _index in range(30)]}
        self.assertGreater(len(json.dumps(padded).encode()), 65536)
        self.assertEqual(self.post(body=padded)[0], 413)
        oversized = build_event('alertmanager', None, 'alertmanager.big', 'threshold', 'firing',
                                {'start': utc_text(NOW - dt.timedelta(minutes=1)), 'end': utc_text(NOW)},
                                {'rule_id': 'alertmanager.big'}, query_type='source-heartbeat')
        oversized['evidence'] = oversized['evidence'] * 300
        self.assertGreater(len(json.dumps(oversized).encode()), 65536)
        self.assertEqual(self.post(path='/v1/events', body=oversized)[0], 413)

    def test_an_envelope_over_the_alert_ceiling_is_refused_while_fitting_the_byte_bound(self):
        """The count bound bites first, and its refusal is a reason rather than a truncated batch."""
        many = [alert(labels={'alertname': 'UnDeclared', 'severity': 'crit', 'instance': 'web01'})
                for _index in range(intake.MAX_ENVELOPE_ALERTS + 1)]
        body_document = envelope(*many)
        self.assertLess(len(json.dumps(body_document).encode()), 65536)
        status, body = self.post(body=body_document)
        self.assertEqual(status, 400)
        self.assertIn(str(intake.MAX_ENVELOPE_ALERTS), body['detail'])
        self.assertEqual(self.rows('events'), [])

    def test_a_future_observed_at_is_refused_at_the_route_as_well_as_in_the_normaliser(self):
        """The contract rule, named: no event may describe an instant that has not happened."""
        ahead = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
        status, body = self.post(body=envelope(alert(startsAt=utc_text(ahead))))
        self.assertEqual(status, 400)
        self.assertIn('future observed_at', body['detail'])
        self.assertEqual(self.rows('events'), [])

    def test_a_window_of_exactly_seven_days_is_still_the_largest_the_state_layer_admits(self):
        """`MAX_WINDOW_SECONDS` in `intake.py` is `validate_event`'s ceiling, not a second opinion."""
        window = {'start': utc_text(NOW - dt.timedelta(days=7)), 'end': utc_text(NOW)}
        status, body = self.post(path='/v1/events',
                                 body=build_event('alertmanager', None, 'alertmanager.week', 'threshold',
                                                  'firing', window, {'rule_id': 'alertmanager.week'},
                                                  query_type='source-heartbeat'))
        self.assertEqual((status, body.get('status')), (200, 'accepted'))
        too_long = {'start': utc_text(NOW - dt.timedelta(days=8)), 'end': utc_text(NOW)}
        refused = self.post(path='/v1/events',
                            body=build_event('alertmanager', None, 'alertmanager.week', 'threshold',
                                             'firing', too_long, {'rule_id': 'alertmanager.week'},
                                             query_type='source-heartbeat'))
        self.assertEqual(refused[0], 400)
        self.assertIn('bounded evaluation window', refused[1]['detail'])


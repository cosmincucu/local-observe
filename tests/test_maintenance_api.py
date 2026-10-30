"""The planned-maintenance API: what may be silenced, by whom, for how long, and what it cost.

This file tests the route family in `local_observe/platform/maintenance_api.py` and the domain rules
behind it in `maintenance.py`/`suppression.py`. `tests/test_maintenance_windows.py` and
`tests/test_maintenance_history.py` already own the durable window itself — its envelope, its
attestation, its read bounds — and `tests/test_api_openapi_conformance.py` owns the claim that the
document, the census and the transport agree. What is tested *here* is the seam between them, because
that is where the interesting failures live:

* **a silence is signed by a credential.** A declaration is authored by the bearer, never by a body
  field; `producer` cannot write one, and cannot read the family either (a detector that can see which
  windows cover its own findings can schedule findings around them). Writes are idempotent, so a client
  that retried a declaration does not buy a second silence.
* **the plan is not the silence.** A schedule is a versioned document with a finite bound and an
  explicit DST policy; the windows are its consequence, materialized in bounded slices. Every DST
  behaviour is checked against a real IANA transition — the fold of 2026-10-25 and the gap of
  2026-03-29 in `Europe/London` — because a recurrence rule that is right on ordinary days and wrong
  twice a year is the bug this feature would be remembered for.
* **attribution survives overlap.** Two windows may cover the same resource at the same time; cancelling
  one must not cancel the other, and each keeps its own list of folded pages.
* **a bound is answered as a bound.** `bound_exceeded` and `unknown` are what an incomplete read says;
  "nothing was planned" is a claim only a complete read may make.
* **history is readable and retroactivity is not.** A window from before schema v2 is still honoured
  (class-blind, exactly as approved); a window whose span has already ended cannot be declared, and the
  reads say `retroactive: false` so a reader knows the question has a different answer.

The clock is controlled everywhere it matters: the timing classes pass `now=` to the domain and never
read the wall clock, and the transport class uses instants relative to the real clock, because the
transport's own refusal ("that window has already ended") is a fact about the real one.
"""
import asyncio
import datetime as dt
import json
import tempfile
from pathlib import Path
import unittest
from unittest import mock
import uuid

from local_observe.inventory.index import build as build_index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import api_contract, maintenance, maintenance_api, suppression
from local_observe.platform.api import create_app
from local_observe.platform.detections import event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, StateError, Store
from test_maintenance_windows import plant_window  # noqa: E402  (tests/ is not a package)

#: A Monday, one week before the fold that ends British Summer Time in 2026. Every recurrence assertion
#: below crosses that instant, so a plan that only works on ordinary days cannot pass.
NOW = timestamp('2026-10-19T09:00:00Z')
FOLD_DAY = '2026-10-25'
GAP_DAY = '2026-03-29'
RESOURCE = '7b3e9c1d-2f4a-4b5c-9d8e-1a2b3c4d5e6f'
OTHER = '1a2b3c4d-5e6f-4a5b-8c9d-0e1f2a3b4c5d'
SERVICE = 'c2d3e4f5-6a7b-4c8d-9e0f-1a2b3c4d5e6f'
MEMBER = 'd3e4f5a6-7b8c-4d9e-0f1a-2b3c4d5e6f70'
RULE = 'disk-watermark'
HUMAN = Actor('operator', 'human')
PRODUCER = Actor('window-detector', 'producer')
READER = Actor('report', 'reader')

CREDENTIALS = [
    {'identity': 'report', 'role': 'reader', 'token': 'r' * 32},
    {'identity': 'window-detector', 'role': 'producer', 'token': 'p' * 32},
    {'identity': 'operator', 'role': 'human', 'token': 'h' * 32},
    {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32},
]
TOKENS = {row['role']: row['token'] for row in CREDENTIALS}


def http(app, method: str, path: str, role: str | None, body=None, query: bytes = b'',
         key: str | None = None) -> tuple[int, dict, dict]:
    """Drive one request through the ASGI app and return status, decoded body and headers."""
    output = []
    payload = b'' if body is None else json.dumps(body).encode()

    async def receive():
        return {'type': 'http.request', 'body': payload, 'more_body': False}

    async def send(message):
        output.append(message)

    headers = [] if role is None else [(b'authorization', ('Bearer ' + TOKENS[role]).encode())]
    if key is not None:
        headers.append((b'idempotency-key', key.encode()))
    asyncio.run(app({'type': 'http', 'method': method, 'path': path, 'headers': headers,
                     'query_string': query}, receive, send))
    kinds = {name.lower(): value for name, value in output[0].get('headers', [])}
    return output[0]['status'], json.loads(output[-1]['body']), kinds


class ClockedReader(unittest.TestCase):
    """Shared fixtures for the domain classes: one store, one clock, canonical verdicts on demand."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'maintenance.db', NotificationPolicy(delivery_mode='off'))

    def reloaded(self) -> Store:
        """The same file through a second `Store`, which is what a restart is."""
        return Store(self.root / 'maintenance.db', NotificationPolicy(delivery_mode='off'))

    def verdict(self, at: dt.datetime, *, kind: str = 'availability', rule: str = RULE,
                status: str = 'firing', query_type: str = 'gatus-result',
                resource: str = RESOURCE) -> dict:
        """One canonical finding about `resource`, observed at `at`."""
        window = {'start': utc_text(at - dt.timedelta(seconds=60)), 'end': utc_text(at)}
        return event(PRODUCER.identity, resource, rule, kind, status, window,
                     {'sample_id': 'fixture'}, query_type=query_type)

    def declare(self, *, start: dt.datetime, end: dt.datetime, resource: str = RESOURCE,
                explains=None, now: dt.datetime = NOW, reason: str = 'replace the disk') -> str:
        """Declare one window through the HTTP door's own function and return its id."""
        request = {'reason': reason, 'scope': {'kind': 'resource', 'id': resource},
                   'starts_at': utc_text(start), 'ends_at': utc_text(end)}
        if explains is not None:
            request['explains'] = explains
        answer = maintenance.declare_window(self.store, request, HUMAN, now=now)
        return answer['windows'][0]['window_id']

    def file_at(self, verdict: dict, at: dt.datetime, *, arrival: dt.datetime | None = None) -> dict:
        """File one finding at the instant it was observed, arriving whenever the caller says."""
        return suppression.file_event(self.store, verdict, PRODUCER, now=arrival or at)


class MaintenanceRouteTests(ClockedReader):
    """The seven paths answer, refuse, and replay the way the contract says they do."""

    def setUp(self):
        super().setUp()
        self.app = create_app(self.store, CREDENTIALS, {})

    def call(self, method, path, role, body=None, query=b'', key=None):
        return http(self.app, method, path, role, body, query, key)

    def window_request(self, *, hours_ahead: int = 2, minutes: int = 45, **overrides) -> dict:
        start = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=hours_ahead)
        return dict({'reason': 'replace the disk', 'scope': {'kind': 'resource', 'id': RESOURCE},
                     'starts_at': utc_text(start.replace(microsecond=0)),
                     'ends_at': utc_text((start + dt.timedelta(minutes=minutes)).replace(microsecond=0))},
                    **overrides)

    def schedule_request(self, *, days_ahead: int = 6, **overrides) -> dict:
        first = (dt.date.today() + dt.timedelta(days=days_ahead)).isoformat()
        request = {'reason': 'firmware refresh', 'scope': {'kind': 'resource', 'id': RESOURCE},
                   'recurrence': {'frequency': 'weekly', 'interval': 1, 'days_of_week': [1],
                                  'time_of_day': '03:30', 'duration_seconds': 1800,
                                  'timezone': 'Europe/London', 'dst': 'wall'},
                   'bounds': {'first_occurrence': first, 'occurrences': 3}}
        request.update(overrides)
        return request

    def test_every_route_in_the_family_answers(self):
        """One pass through the whole surface: no path in it is a 404 and no handler is a stub."""
        status, declared, _headers = self.call('POST', '/v1/maintenance-windows', 'human',
                                               self.window_request())
        self.assertEqual(status, 200, declared)
        window = declared['windows'][0]['window_id']
        self.assertEqual(declared['count'], 1)
        self.assertEqual(sorted(declared['explains']), sorted(suppression.EXPLAINED_BY_DEFAULT),
                         'the default silence names the four classes planned work explains')

        status, listing, _ = self.call('GET', '/v1/maintenance-windows', 'reader')
        self.assertEqual((status, listing['count']), (200, 1))
        status, detail, _ = self.call('GET', f'/v1/maintenance-windows/{window}', 'reader')
        self.assertEqual((status, detail['outcome']['outcome']), (200, 'planned'))
        self.assertEqual(detail['window']['document_version'], suppression.WINDOW_DOCUMENT_VERSION)
        status, history, _ = self.call('GET', f'/v1/maintenance-windows/{window}/history', 'reader')
        self.assertEqual((status, [row['what'] for row in history['events']]), (200, ['declared']))
        status, cancelled, _ = self.call('POST', f'/v1/maintenance-windows/{window}/cancellations',
                                         'human', {})
        self.assertEqual((status, cancelled['status'], cancelled['cancelled_by']),
                         (200, 'cancelled', 'operator'))

        status, schedule, _ = self.call('POST', '/v1/maintenance-schedules', 'human',
                                        self.schedule_request())
        self.assertEqual(status, 200, schedule)
        ident = schedule['id']
        self.assertEqual(schedule['declared'], 3)
        status, schedules, _ = self.call('GET', '/v1/maintenance-schedules', 'reader')
        self.assertEqual((status, schedules['count']), (200, 1))
        status, one, _ = self.call('GET', f'/v1/maintenance-schedules/{ident}', 'reader')
        self.assertEqual(status, 200, one)
        self.assertEqual(one['materialized_through'], schedule['horizon'])
        status, edited, _ = self.call('PATCH', f'/v1/maintenance-schedules/{ident}', 'human',
                                      dict(self.schedule_request(
                                          recurrence=dict(schedule['schedule']['recurrence'],
                                                          time_of_day='04:30')),
                                          expected_version=1))
        self.assertEqual((status, edited['version'], edited['windows_revoked']), (200, 2, 3),
                         'an edit appends a version and stops the unstarted windows it supersedes')
        status, versions, _ = self.call('GET', f'/v1/maintenance-schedules/{ident}/history', 'reader')
        self.assertEqual((status, [row['version'] for row in versions['versions']]), (200, [1, 2]))
        status, rolled, _ = self.call('POST', f'/v1/maintenance-schedules/{ident}/materializations',
                                      'human', {})
        self.assertEqual(status, 200, rolled)
        self.assertEqual(rolled['status'], 'rolled_forward')
        status, cancelled, _ = self.call('POST', f'/v1/maintenance-schedules/{ident}/cancellations',
                                         'human', {})
        self.assertEqual((status, cancelled['status']), (200, 'cancelled'))
        self.assertGreaterEqual(cancelled['windows_revoked'], 1)

    def test_the_interval_route_answers_both_questions(self):
        """A span lists what was quiet; an instant classifies it; the two share one path.

        This class declares against the real clock, because `retroactive` and `classification` are answers
        about *now*. Outcome vocabulary is exercised under a controlled clock in `MaintenanceOutcomeTests`.
        """
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        start, end = now + dt.timedelta(hours=1), now + dt.timedelta(hours=3)
        window = self.declare(start=start, end=end, now=now)
        inside = now + dt.timedelta(hours=2)
        self.assertTrue(self.file_at(self.verdict(inside), inside)['suppressed'])

        span = f'resource={RESOURCE}&from={utc_text(start)}&to={utc_text(end)}'.encode()
        status, answer, _ = self.call('GET', '/v1/maintenance-intervals', 'reader', query=span)
        self.assertEqual(status, 200, answer)
        self.assertEqual([row['window_id'] for row in answer['intervals']], [window])
        self.assertTrue(answer['complete'], answer['bounds'])
        self.assertFalse(answer['retroactive'],
                         'the stance against retroactive declaration is stated in the read, not implied')
        self.assertEqual(answer['intervals'][0]['outcome'], 'planned')
        self.assertEqual(answer['effective'][0]['explained_by'], [window])

        instant = f'resource={RESOURCE}&at={utc_text(inside)}&class=availability'.encode()
        status, at, _ = self.call('GET', '/v1/maintenance-intervals', 'reader', query=instant)
        self.assertEqual((status, at['classification'], at['primary']['window_id']),
                         (200, 'planned', window), at)
        status, unexplained, _ = self.call(
            'GET', '/v1/maintenance-intervals', 'reader',
            query=f'resource={RESOURCE}&at={utc_text(inside)}&class=security'.encode())
        self.assertEqual(unexplained['classification'], 'outside',
                         'a security finding is not explained by a window that did not name it')

    def test_an_anonymous_caller_is_refused_before_the_route_is_considered(self):
        for method, path, body in (('GET', '/v1/maintenance-windows', None),
                                   ('GET', '/v1/maintenance-intervals', None),
                                   ('POST', '/v1/maintenance-windows', {}),
                                   ('POST', '/v1/maintenance-schedules', {})):
            with self.subTest(method=method, path=path):
                status, answer, headers = http(self.app, method, path, None, body)
                self.assertEqual((status, answer), (401, {'error': 'authentication_required'}))
                self.assertIn(b'x-request-id', headers)

    def test_a_producer_can_neither_write_nor_read_the_family(self):
        """The declaration is a human act; reading it is not a detector's business either."""
        status, answer, _ = self.call('POST', '/v1/maintenance-windows', 'producer',
                                      self.window_request())
        self.assertEqual((status, answer['error']['code']), (403, 'not_authorised'))
        status, answer, _ = self.call('POST', '/v1/maintenance-schedules', 'producer',
                                      self.schedule_request())
        self.assertEqual((status, answer['error']['code']), (403, 'not_authorised'))
        # `producer` is outside the GET branch's own gate, which predates this family and answers the
        # state layer's sentence as a 400. Pinned rather than fixed here: widening that gate is a decision
        # about every read route, not about maintenance (WORKER-REPORT open question).
        status, answer, _ = self.call('GET', '/v1/maintenance-windows', 'producer')
        self.assertEqual((status, answer['error']), (400, 'not_authorised'))

    def test_a_summary_credential_is_refused_on_every_maintenance_path(self):
        for method, path, body in (('GET', '/v1/maintenance-windows', None),
                                   ('GET', '/v1/maintenance-schedules', None),
                                   ('POST', '/v1/maintenance-windows', {}),
                                   ('PATCH', '/v1/maintenance-schedules/' + RESOURCE, {})):
            with self.subTest(method=method, path=path):
                status, answer, _ = self.call(method, path, 'summary', body)
                self.assertEqual((status, answer), (403, {'error': 'summary_only'}))

    def test_the_write_family_is_idempotent_and_binds_the_key_to_the_body(self):
        """A retried declaration replays its first answer; a re-used key with a new body does nothing."""
        request = self.window_request(reason='rotate the array')
        first, body, headers = self.call('POST', '/v1/maintenance-windows', 'human', request, key='k')
        self.assertEqual(first, 200, body)
        again, replayed, headers = self.call('POST', '/v1/maintenance-windows', 'human', request,
                                             key='k')
        self.assertEqual(again, 200, replayed)
        self.assertEqual(replayed, body)
        self.assertEqual(headers.get(api_contract.REPLAYED_HEADER), b'true')
        status, conflict, _ = self.call('POST', '/v1/maintenance-windows', 'human',
                                        dict(request, reason='something else'), key='k')
        self.assertEqual((status, conflict['error']['code']), (409, 'idempotency_conflict'))
        with self.store.transaction() as connection:
            rows = connection.execute("SELECT 1 FROM audit WHERE operation='maintenance.declared'"
                                      " AND detail LIKE '%rotate the array%'").fetchall()
        self.assertEqual(len(rows), 1, 'the replay wrote no second declaration')

    def test_a_body_may_not_claim_an_author(self):
        """§5: the actor is the credential. A payload field cannot promote a caller to a human."""
        status, answer, _ = self.call('POST', '/v1/maintenance-windows', 'human',
                                      dict(self.window_request(), author='operator'))
        self.assertEqual((status, answer['error']['code']), (400, 'actor_claim_refused'))

    def test_only_the_documented_verbs_are_answered(self):
        """PATCH exists for one route; everything else that is not GET or POST is a 405."""
        window = self.declare(start=NOW + dt.timedelta(hours=1), end=NOW + dt.timedelta(hours=2),
                              now=NOW)
        cases = [('PUT', f'/v1/maintenance-windows/{window}'),
                 ('DELETE', '/v1/maintenance-windows'),
                 ('PATCH', '/v1/maintenance-windows'),
                 ('PATCH', f'/v1/maintenance-windows/{window}/cancellations'),
                 ('POST', f'/v1/maintenance-schedules/{RESOURCE}'),
                 # The verb is admitted for one path, not for the API: a route that never carried `PATCH`
                 # must still answer 405 for it rather than 404, which is what `maintenance_api.edits` is for.
                 ('PATCH', '/v1/audit'),
                 ('PATCH', '/v1/incidents/' + RESOURCE + '/acknowledgements'),
                 ('PATCH', '/v1/maintenance-schedules/' + RESOURCE + '/history')]
        for method, path in cases:
            with self.subTest(method=method, path=path):
                status, answer, _ = self.call(method, path, 'human', {})
                self.assertEqual((status, answer), (405, {'error': 'method_not_allowed'}),
                                 'the contract documents the legacy body for 405, not a second shape')

    def test_a_route_that_does_not_exist_is_a_404_and_a_bad_identifier_is_a_400(self):
        status, answer, _ = self.call('GET', '/v1/maintenance-windows/anything/else/deep', 'reader')
        self.assertEqual((status, answer['error']['code']), (404, 'not_found'))
        status, answer, _ = self.call('GET', '/v1/maintenance-windows/not-a-uuid', 'reader')
        self.assertEqual((status, answer['error']), (400, 'invalid_request'), answer)
        detail = answer.get('detail', '')
        self.assertNotIn('not-a-uuid', detail, 'the request is not echoed back')
        status, answer, _ = self.call('GET', '/v1/maintenance-windows/' + RESOURCE, 'reader')
        self.assertEqual((status, answer['error']['code']), (404, 'not_found'),
                         'a well-formed id that nothing was declared under says so')

    def test_a_cancellation_takes_no_body_fields(self):
        window = self.declare(start=NOW + dt.timedelta(hours=1), end=NOW + dt.timedelta(hours=2),
                              now=NOW)
        status, answer, _ = self.call('POST', f'/v1/maintenance-windows/{window}/cancellations',
                                      'human', {'reason': 'finished early'})
        self.assertEqual(status, 400, answer)
        self.assertIn('no body fields', answer['detail'])

    def test_a_window_that_has_already_ended_cannot_be_declared(self):
        """Retroactive silence is refused, and the refusal names the door that can answer the question."""
        now = dt.datetime.now(dt.timezone.utc)
        status, answer, _ = self.call('POST', '/v1/maintenance-windows', 'human',
                                      {'reason': 'explain the outage',
                                       'scope': {'kind': 'resource', 'id': RESOURCE},
                                       'starts_at': utc_text(now - dt.timedelta(hours=5)),
                                       'ends_at': utc_text(now - dt.timedelta(hours=4))})
        self.assertEqual(status, 400, answer)
        self.assertIn(maintenance.RETROACTIVE_REFUSAL, answer['detail'])
        self.assertIn('/v1/maintenance-intervals', answer['detail'])


class MaintenanceScopeTests(ClockedReader):
    """What a scope actually covers, and what it refuses to guess."""

    def inventory(self) -> Path:
        """A built index holding one service and one resource that runs on it."""
        document = {'schema_version': 1, 'resources': [
            {'id': SERVICE, 'kind': 'service', 'name': 'demo-api', 'aliases': [],
             'attributes': {'environment': 'demo', 'enabled': True}, 'relations': []},
            {'id': MEMBER, 'kind': 'host', 'name': 'member-1', 'aliases': [],
             'attributes': {'os': 'linux', 'environment': 'demo'},
             'relations': [{'type': 'runs-on', 'target': SERVICE}]}]}
        path = self.root / 'inventory.db'
        build_index(document, path, 'fixture', now=NOW)
        return path

    def test_a_resource_scope_covers_its_resource_and_nothing_else(self):
        self.declare(start=NOW, end=NOW + dt.timedelta(hours=2))
        inside = self.file_at(self.verdict(NOW + dt.timedelta(hours=1)), NOW + dt.timedelta(hours=1))
        outside = self.file_at(self.verdict(NOW + dt.timedelta(hours=1), resource=OTHER),
                               NOW + dt.timedelta(hours=1))
        self.assertTrue(inside['suppressed'])
        self.assertFalse(outside['suppressed'])

    def test_a_rule_scope_covers_the_rule_on_any_resource(self):
        answer = maintenance.declare_window(
            self.store, {'reason': 'probe maintenance', 'scope': {'kind': 'rule', 'id': RULE},
                         'starts_at': utc_text(NOW), 'ends_at': utc_text(NOW + dt.timedelta(hours=2))},
            HUMAN, now=NOW)
        self.assertEqual(answer['count'], 1)
        self.assertIsNone(answer['windows'][0]['resource_id'])
        for resource in (RESOURCE, OTHER):
            filed = self.file_at(self.verdict(NOW + dt.timedelta(hours=1), resource=resource),
                                 NOW + dt.timedelta(hours=1))
            self.assertTrue(filed['suppressed'], resource)
        other_rule = self.file_at(self.verdict(NOW + dt.timedelta(hours=1), rule='other-rule'),
                                  NOW + dt.timedelta(hours=1))
        self.assertFalse(other_rule['suppressed'])

    def test_a_service_scope_expands_to_members_and_declares_one_window_each(self):
        index = self.inventory()
        answer = maintenance.declare_window(
            self.store, {'reason': 'hypervisor patch', 'scope': {'kind': 'service', 'id': SERVICE},
                         'starts_at': utc_text(NOW), 'ends_at': utc_text(NOW + dt.timedelta(hours=2))},
            HUMAN, now=NOW, index_path=index)
        self.assertEqual(sorted(answer['members']), sorted([SERVICE, MEMBER]))
        self.assertEqual(answer['count'], 2)
        self.assertEqual(len({row['window_id'] for row in answer['windows']}), 2,
                         'the members are separate windows, each revocable on its own')
        for resource in (SERVICE, MEMBER):
            self.assertTrue(self.file_at(self.verdict(NOW + dt.timedelta(hours=1), resource=resource),
                                         NOW + dt.timedelta(hours=1))['suppressed'], resource)

    def test_a_service_scope_refuses_a_missing_index_and_an_unknown_service(self):
        with self.assertRaisesRegex(StateError, 'built inventory index'):
            maintenance.declare_window(
                self.store, {'reason': 'x', 'scope': {'kind': 'service', 'id': SERVICE},
                             'starts_at': utc_text(NOW),
                             'ends_at': utc_text(NOW + dt.timedelta(hours=1))}, HUMAN, now=NOW)
        index = self.inventory()
        with self.assertRaisesRegex(StateError, 'does not hold'):
            maintenance.declare_window(
                self.store, {'reason': 'x', 'scope': {'kind': 'service', 'id': RESOURCE},
                             'starts_at': utc_text(NOW),
                             'ends_at': utc_text(NOW + dt.timedelta(hours=1))}, HUMAN, now=NOW,
                index_path=index)

    def test_an_oversized_member_set_is_refused_rather_than_trimmed(self):
        index = self.inventory()
        with mock.patch.object(maintenance, 'MAX_SERVICE_MEMBERS', 1):
            with self.assertRaisesRegex(StateError, 'at most 1 resources'):
                maintenance.resolve_scope(self.store, {'kind': 'service', 'id': SERVICE},
                                          index_path=index)


class MaintenanceConditionClassTests(ClockedReader):
    """What a window accounts for, and what pages through it anyway."""

    def open_window(self, **overrides) -> str:
        return self.declare(start=NOW + dt.timedelta(minutes=30),
                            end=NOW + dt.timedelta(minutes=90),
                            now=NOW + dt.timedelta(minutes=20), **overrides)

    def findings(self) -> dict[str, dict]:
        """One finding of every class the platform can name, at one instant inside the window."""
        at = NOW + dt.timedelta(hours=1)
        return {
            'availability': self.verdict(at),
            'restart': self.verdict(at, status='resolved'),
            'silence': self.verdict(at, rule='input-silence', kind='coverage',
                                    query_type='source-heartbeat'),
            'freshness': self.verdict(at, rule='input-stale', kind='coverage',
                                       query_type='observed-snapshot'),
            'backup-integrity': self.verdict(at, rule='backup.integrity', kind='threshold'),
            'security': self.verdict(at, rule='sigma-hit', kind='security',
                                     query_type='sigma-count'),
            'application': self.verdict(at, rule='error-rate', kind='threshold'),
        }

    def test_the_default_window_explains_four_classes_and_no_others(self):
        self.open_window()
        for name, verdict in self.findings().items():
            with self.subTest(condition_class=name):
                decision = suppression.decide(self.store, verdict, now=NOW + dt.timedelta(hours=1))
                self.assertEqual(suppression.condition_class(verdict), name)
                self.assertEqual(bool(decision.suppressed), name in suppression.EXPLAINED_BY_DEFAULT,
                                 decision.reason or 'no reason given')
                if name in suppression.NEVER_EXPLAINED_BY_DEFAULT:
                    self.assertIsNone(suppression.covering_window(
                        self.store, verdict, now=NOW + dt.timedelta(hours=1)),
                        'the window is there and does not cover this class')

    def test_a_widened_silence_names_everything_it_covers(self):
        self.open_window(explains=list(suppression.CONDITION_CLASSES))
        for name, verdict in self.findings().items():
            with self.subTest(condition_class=name):
                self.assertTrue(suppression.decide(self.store, verdict,
                                                   now=NOW + dt.timedelta(hours=1)).suppressed, name)

    def test_an_unclassified_finding_is_not_explained_by_default(self):
        """`unclassified` is the fallback for a kind this build has no rule for, and it is not free.

        Checked on the classifier rather than filed: `state.intake` refuses an unknown `kind` long before a
        window could explain it, so the only place this class exists today is the mapping itself. That is
        the honest shape of the requirement — a plan cannot buy a silence for a class by leaving it out of
        `EXPLAINED_BY_DEFAULT`, and a future detector's new `kind` arrives unexplained, not silently
        covered.
        """
        verdict = self.verdict(NOW + dt.timedelta(hours=1), rule='what-is-this', kind='threshold')
        self.assertEqual(suppression.condition_class(verdict), 'application',
                         'a threshold rule nobody named is an application condition, not a mystery')
        self.assertEqual(suppression.condition_class(dict(verdict, kind='cost-anomaly')), 'unclassified')
        self.assertFalse(suppression.explains({'explains': list(suppression.EXPLAINED_BY_DEFAULT)},
                                             'unclassified'))
        self.assertTrue(suppression.explains({'explains': None}, 'unclassified'),
                        'a class-blind window explains what this build cannot name')
        self.assertTrue(suppression.explains({'explains': ['unclassified']}, 'unclassified'),
                        'a plan may still name it, in words, and be held to them')

    def test_a_condition_class_is_decided_from_canonical_fields_only(self):
        """No expression language, no label matching: the mapping is a table over fields that exist."""
        at = NOW + dt.timedelta(hours=1)
        cases = {
            'availability': self.verdict(at),
            'restart': self.verdict(at, status='resolved'),
            'silence': self.verdict(at, rule='input-silence', kind='coverage',
                                    query_type='source-heartbeat'),
            'freshness': self.verdict(at, rule='input-stale', kind='coverage',
                                       query_type='observed-snapshot'),
            'backup-integrity': self.verdict(at, rule='backup.integrity', kind='threshold'),
            'security': self.verdict(at, rule='sigma-hit', kind='security', query_type='sigma-count'),
            'application': self.verdict(at, rule='error-rate', kind='threshold'),
        }
        for name, verdict in cases.items():
            with self.subTest(condition_class=name):
                self.assertEqual(suppression.condition_class(verdict), name)
        produced = set(cases)
        self.assertEqual(set(suppression.CONDITION_CLASSES) - produced, {'unclassified'},
                         'every class this build can name is reachable except the fallback')
        self.assertEqual(set(suppression.EXPLAINED_BY_DEFAULT)
                         | set(suppression.NEVER_EXPLAINED_BY_DEFAULT),
                         set(suppression.CONDITION_CLASSES),
                         'the default gate has an opinion about every class, including the fallback')
        self.assertEqual(set(suppression.EXPLAINED_BY_DEFAULT),
                         {'availability', 'restart', 'silence', 'freshness'})

    def test_a_v1_window_is_class_blind_and_covers_what_it_always_did(self):
        """A row approved before condition classes existed keeps the behaviour it was approved under."""
        plant_window(self.store, 'legacy-blind', start=NOW, end=NOW + dt.timedelta(hours=2),
                     version=1)
        at = NOW + dt.timedelta(hours=1)
        for name in ('security', 'application', 'backup-integrity'):
            verdict = self.findings()[name]
            with self.subTest(condition_class=name):
                self.assertTrue(suppression.decide(self.store, verdict, now=at).suppressed,
                                'narrowing a legacy silence is a human act, not a reader default')

    def test_the_page_says_what_explained_it(self):
        window = self.open_window()
        filed = self.file_at(self.findings()['availability'], NOW + dt.timedelta(hours=1))
        self.assertTrue(filed['suppressed'])
        reason = filed['decision'].reason
        self.assertIn('explains availability', reason)
        self.assertIn('replace the disk', reason, 'the page names the work and the human who signed it')
        self.assertEqual(filed['decision'].detail['condition_class'], 'availability')
        self.assertEqual(filed['decision'].detail['window_id'], window)


#: The instant a plan is signed at in this class. It is *before* the first occurrence, because a plan whose
#: first slice has already ended is a retroactive claim and the door refuses it; every other clock in this
#: class is derived from it, so the DST assertions stay legible.
PLAN_NOW = dt.datetime(2026, 10, 19, 0, 0, tzinfo=dt.timezone.utc)


class MaintenanceScheduleTests(unittest.TestCase):
    """Recurring plans: DST behaviour, stable occurrence ids, bounded materialization, finite bounds."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'schedules.db', NotificationPolicy(delivery_mode='off'))

    def weekly(self, *, recurrence=None, **overrides) -> dict:
        """A weekly Monday-03:30 plan in `Europe/London`, starting the week of the 2026 fold."""
        request = {'reason': 'firmware refresh', 'scope': {'kind': 'resource', 'id': RESOURCE},
                   'recurrence': {'frequency': 'weekly', 'interval': 1, 'days_of_week': [0],
                                  'time_of_day': '03:30', 'duration_seconds': 1800,
                                  'timezone': 'Europe/London', 'dst': 'wall'},
                   'bounds': {'first_occurrence': '2026-10-19', 'occurrences': 4}}
        if recurrence:
            request['recurrence'] = dict(request['recurrence'], **recurrence)
        request.update(overrides)
        return request

    def declare(self, request: dict | None = None, *, now: dt.datetime = PLAN_NOW, **overrides):
        return maintenance.declare_schedule(self.store, request or self.weekly(**overrides), HUMAN,
                                            now=now)

    def revised(self, id: str, *, minute: str, now: dt.datetime = PLAN_NOW,
                expected: int = 1) -> dict:
        """Move the weekly minute and append the version that says so."""
        return maintenance.revise_schedule(self.store, id, self.weekly(recurrence={'time_of_day': minute}),
                                           HUMAN, expected_version=expected, now=now)

    def test_wall_keeps_the_local_minute_across_the_fold(self):
        answer = self.declare()
        starts = [row['starts_at'] for row in answer['occurrences']]
        self.assertEqual(starts[0], '2026-10-19T02:30:00.000000+00:00',
                         'BST: 03:30 on the London clock face is 02:30Z')
        self.assertEqual(starts[1], '2026-10-26T03:30:00.000000+00:00',
                         'after the clocks go back, 03:30 local is 03:30Z: the roster did not move')
        self.assertEqual([row['dst'] for row in answer['occurrences']], ['normal'] * 4)
        self.assertEqual(answer['declared'], 4)

    def test_fixed_keeps_the_offset_and_lets_the_local_minute_move(self):
        answer = self.declare(recurrence={'dst': 'fixed'})
        starts = [row['starts_at'] for row in answer['occurrences']]
        self.assertEqual(starts[:2], ['2026-10-19T02:30:00.000000+00:00',
                                      '2026-10-26T02:30:00.000000+00:00'],
                         'a shift that must never overlap itself keeps the instant, not the clock face')

    def test_skip_drops_the_occurrence_whose_minute_does_not_exist(self):
        """The spring-forward gap, both ways: `skip` loses the occurrence, `wall` moves it.

        The gap falls on a Sunday, so a weekly-on-Monday plan can never land in it and this plan is daily.
        01:30 does not exist in London on 2026-03-29; the minute either side does, and under `wall` it is
        still 01:30 local, which is 00:30Z once the clocks have jumped — an occurrence list that kept saying
        01:30Z across the transition would be quietly an hour late for half the year.
        """
        zone = maintenance._zone('Europe/London')
        self.assertEqual(maintenance.transition(dt.datetime(2026, 3, 29, 1, 30), zone), 'gap')
        self.assertEqual(maintenance.transition(dt.datetime(2026, 10, 25, 1, 30), zone), 'fold')
        self.assertEqual(maintenance.transition(dt.datetime(2026, 10, 19, 3, 30), zone), 'normal')
        bounds = {'first_occurrence': '2026-03-28', 'occurrences': 3}
        march = dt.datetime.fromisoformat('2026-03-21T00:00:00+00:00')

        skipped = self.declare(self.weekly(recurrence={'frequency': 'daily', 'days_of_week': [],
                                                      'time_of_day': '01:30', 'dst': 'skip'},
                                          bounds=bounds), now=march)
        self.assertEqual([row['starts_at'] for row in skipped['occurrences']],
                         ['2026-03-28T01:30:00.000000+00:00', '2026-03-30T00:30:00.000000+00:00',
                          '2026-03-31T00:30:00.000000+00:00'],
                         'the minute that does not exist is dropped; the days around it are not moved')
        self.assertEqual(skipped['skipped_occurrences'], 1)
        self.assertEqual([(row['local'], row['time_of_day'], row['timezone'])
                          for row in skipped['dropped_occurrences']],
                         [('2026-03-29', '01:30', 'Europe/London')],
                         'the answer names which minute was lost, not only that one was')
        self.assertEqual(skipped['declared'], 3, 'three windows, for the three minutes that exist')

        moved = self.declare(self.weekly(recurrence={'frequency': 'daily', 'days_of_week': [],
                                                    'time_of_day': '01:30', 'dst': 'wall'},
                                        bounds=bounds), now=march)
        self.assertEqual([row['dst'] for row in moved['occurrences']], ['normal', 'gap', 'normal'],
                         'the other policies keep the occurrence and record what the zone did to it')
        self.assertEqual(moved['occurrences'][1]['starts_at'], '2026-03-29T01:30:00.000000+00:00',
                         'the imaginary minute is read at the offset the clock had before it jumped, so the '
                         'instant is one the zone calls 02:30 — never an instant whose own label is a lie')
        self.assertEqual(moved['skipped_occurrences'], 0)
        self.assertEqual(moved['declared'], 3)

    def test_occurrence_ids_are_stable_and_name_the_version_that_minted_them(self):
        answer = self.declare()
        first = answer['occurrences'][0]
        self.assertEqual(maintenance.occurrence_id(answer['id'], 1, first['index'],
                                                   dt.datetime.fromisoformat(first['starts_at'])),
                         first['occurrence_id'],
                         'the id is the plan, the version, the position and the instant: nothing random, '
                         'so a half-finished roll-forward converges on one row per occurrence')
        again = maintenance.occurrences(answer['schedule'], now=PLAN_NOW)
        self.assertEqual([row['occurrence_id'] for row in again['occurrences']],
                         [row['occurrence_id'] for row in answer['occurrences']],
                         'the same version always computes the same instants and ids')
        revised = self.revised(answer['id'], minute='04:30')
        self.assertNotEqual([row['occurrence_id'] for row in revised['occurrences']],
                            [row['occurrence_id'] for row in answer['occurrences']],
                            'a new version is a different plan, and its occurrences are different windows')

    def test_materialization_is_bounded_in_count_and_in_days(self):
        answer = self.declare(bounds={'first_occurrence': '2026-10-19', 'occurrences': 400})
        self.assertLessEqual(len(answer['occurrences']), maintenance.MAX_MATERIALIZED_OCCURRENCES)
        horizon = dt.datetime.fromisoformat(answer['horizon'])
        self.assertLessEqual(horizon - PLAN_NOW,
                             dt.timedelta(seconds=maintenance.MAX_HORIZON_SECONDS))
        rolled = maintenance.materialize_schedule(self.store, answer['id'], HUMAN,
                                                 now=PLAN_NOW + dt.timedelta(days=30))
        self.assertEqual(rolled['status'], 'rolled_forward')
        self.assertEqual(rolled['duplicates'], 0, 'the roll-forward continues past the old horizon')
        again = maintenance.materialize_schedule(self.store, answer['id'], HUMAN,
                                                now=PLAN_NOW + dt.timedelta(days=30))
        self.assertEqual(again['declared'], 0,
                         'a second pass with nothing new writes nothing and says so')
        live = suppression.live_windows(self.store, now=PLAN_NOW)
        self.assertLessEqual(live['count'], suppression.MAX_LIVE_WINDOWS,
                             'one plan cannot take the platform whole window budget')

    def test_bounds_must_be_finite_and_unambiguous(self):
        for label, word, bounds in (
                ('open-ended', 'neither', {'first_occurrence': '2026-10-19'}),
                ('both ends', 'both', {'first_occurrence': '2026-10-19', 'occurrences': 4,
                                       'until': '2027-01-01'}),
                ('ends before it starts', 'until', {'first_occurrence': '2026-10-19',
                                                    'until': '2026-10-12'})):
            with self.subTest(bound=label):
                with self.assertRaises(StateError) as caught:
                    self.declare(bounds=bounds)
                self.assertIn(word, str(caught.exception).lower())
        with self.assertRaisesRegex(StateError, 'cannot begin in the past'):
            self.declare(bounds={'first_occurrence': '2020-01-06', 'occurrences': 4})

    def test_two_different_plans_under_one_reason_do_not_collide(self):
        """`duplicate` means "this declaration is already the durable fact", not "the reason matched".

        The two plans below differ only in their DST policy, which is the least visible way for two plans to
        be different. Ided on the reason alone, the second would have answered `duplicate`, stored the first
        document and then declared the *second* plan's windows — a table describing one plan beside silences
        belonging to another. Now they are two plans, and a genuine collision is refused rather than merged.
        """
        bounds = {'first_occurrence': '2026-03-28', 'occurrences': 3}
        march = dt.datetime.fromisoformat('2026-03-21T00:00:00+00:00')
        skip = self.declare(self.weekly(recurrence={'time_of_day': '01:30', 'dst': 'skip'},
                                        bounds=bounds), now=march)
        wall = self.declare(self.weekly(recurrence={'time_of_day': '01:30', 'dst': 'wall'},
                                       bounds=bounds), now=march)
        self.assertNotEqual(skip['id'], wall['id'])
        self.assertEqual((skip['status'], wall['status']), ('declared', 'declared'))
        self.assertEqual((skip['declared'], wall['declared']), (3, 3))
        self.assertEqual(len(maintenance.schedules(self.store)['schedules']), 2)
        retry = self.declare(self.weekly(recurrence={'time_of_day': '01:30', 'dst': 'skip'},
                                        bounds=bounds), now=march)
        self.assertEqual((retry['status'], retry['id']), ('duplicate', skip['id']),
                         'the same plan, declared twice, is one plan')

    def test_a_recurrence_this_build_cannot_speak_is_refused(self):
        for label, patch in (('frequency', {'frequency': 'monthly'}),
                            ('dst', {'dst': 'nearest'}),
                            ('timezone', {'timezone': 'Mars/Olympus_Mons'}),
                            ('weekday', {'days_of_week': [7]})):
            with self.subTest(field=label):
                request = self.weekly()
                request['recurrence'] = dict(request['recurrence'], **patch)
                with self.assertRaises(StateError):
                    self.declare(request)
        request = self.weekly()
        request['recurrence'] = dict(request['recurrence'], days_of_week=[])
        with self.assertRaisesRegex(StateError, 'names at least one day_of_week'):
            self.declare(request)

    def test_an_edit_leaves_a_running_window_alone_and_cuts_only_the_future(self):
        answer = self.declare()
        first = answer['windows'][0]['id']
        during = PLAN_NOW + dt.timedelta(minutes=160)   # inside the first occurrence, 02:30-03:00Z
        revised = self.revised(answer['id'], minute='04:30', now=during)
        self.assertEqual(revised['windows_revoked'], 3, 'the three unstarted occurrences stopped')
        live = suppression.live_windows(self.store, now=during)
        self.assertEqual({row['schedule_version'] for row in live['windows'] if row['id'] != first}, {2},
                         'what is live from now on is the new version')
        self.assertEqual([row['schedule_version'] for row in live['windows'] if row['id'] == first], [1])
        stored = suppression.window_by_id(self.store, first)
        self.assertIsNone(stored['revoked_at'],
                          'a silence an operator is standing inside is not cut short by an edit')
        self.assertEqual(maintenance.window_history(self.store, first,
                                                    now=during)['outcome']['outcome'], 'active')

    def test_an_edit_that_names_a_stale_version_writes_nothing(self):
        answer = self.declare()
        with self.assertRaisesRegex(StateError, 'revision does not match'):
            self.revised(answer['id'], minute='05:30', expected=99)
        self.assertEqual(maintenance.schedule_history(self.store, answer['id'])['count'], 1)

    def test_cancelling_a_plan_stops_its_future_and_keeps_its_past(self):
        later = PLAN_NOW + dt.timedelta(days=1)
        answer = self.declare()
        started, unstarted = answer['windows'][0]['id'], answer['windows'][1]['id']
        cancelled = maintenance.cancel_schedule(self.store, answer['id'], HUMAN, now=later)
        self.assertEqual(cancelled['status'], 'cancelled')
        self.assertEqual(cancelled['windows_revoked'], 3,
                         'the occurrence already under way is left alone; the three after it stop')
        self.assertEqual(suppression.live_windows(self.store, now=later)['count'], 0)
        self.assertEqual(maintenance.window_history(self.store, unstarted,
                                                   now=later)['outcome']['outcome'], 'cancelled')
        self.assertEqual(suppression.window_by_id(self.store, started)['revoked_at'], None,
                         'a window that ran keeps the record of having run')
        self.assertEqual([row['state'] for row in
                          maintenance.schedule_history(self.store, answer['id'])['versions']],
                         ['active', 'cancelled'])
        for label, operation in (
                ('cancel', lambda: maintenance.cancel_schedule(self.store, answer['id'], HUMAN,
                                                               now=later)),
                ('materialize', lambda: maintenance.materialize_schedule(self.store, answer['id'],
                                                                        HUMAN, now=later)),
                ('revise', lambda: self.revised(answer['id'], minute='04:30', now=later,
                                                expected=2))):
            with self.subTest(operation=label):
                with self.assertRaisesRegex(StateError, 'cancelled'):
                    operation()

    def test_a_producer_may_not_touch_a_plan(self):
        for operation in (lambda: maintenance.declare_schedule(self.store, self.weekly(), PRODUCER,
                                                               now=NOW),
                          lambda: maintenance.cancel_schedule(self.store, 'x' * 36, PRODUCER, now=NOW)):
            with self.assertRaisesRegex(StateError, 'not authorised'):
                operation()


class MaintenanceOutcomeTests(ClockedReader):
    """What a window became, from the platform's own evidence, and where suppression had to stop."""

    def outcome(self, window: str, at: dt.datetime) -> dict:
        return maintenance.window_history(self.store, window, now=at)['outcome']

    def case(self, name: str) -> str:
        """A resource of its own for one outcome, so no incident ever speaks for two windows."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f'fixture-maintenance/{name}'))

    def test_the_outcomes_a_window_can_reach_are_the_ones_the_contract_names(self):
        """Each outcome is produced, not asserted, and each is produced on its own resource.

        Every window is read at `NOW`, which is the only instant at which `planned` and `active` are true of
        it; asking a future window what it became, seven days later, is a different question and gets the
        answer the past-tense vocabulary has to give (`unknown`, for a window nothing was recorded inside).
        """

        def window_for(name: str, day: int, *, length: int = 30, now: dt.datetime | None = None):
            start = NOW + dt.timedelta(days=day)
            return self.declare(start=start, end=start + dt.timedelta(minutes=length),
                                resource=self.case(name),
                                now=now or start - dt.timedelta(hours=1)), start

        planned, _ = window_for('planned', 6)

        active, _ = window_for('active', 0, now=NOW - dt.timedelta(days=1))
        completed, completed_start = window_for('completed', -5)
        cancelled, cancelled_start = window_for('cancelled', -4)
        unused, unused_start = window_for('unused', -3)
        overrun, overrun_start = window_for('overrun', -2)
        unknown, _ = window_for('unknown', -1)

        # completed: a finding the window explained, and recovered from, inside its span.
        self.file_at(self.verdict(completed_start + dt.timedelta(minutes=10),
                                  resource=self.case('completed')),
                     completed_start + dt.timedelta(minutes=10))
        self.file_at(self.verdict(completed_start + dt.timedelta(minutes=20), status='resolved',
                                  resource=self.case('completed')),
                     completed_start + dt.timedelta(minutes=20))
        # cancelled: revoked before it ever started.
        maintenance.cancel_window(self.store, cancelled, HUMAN, now=cancelled_start)
        # unused: the condition overlapped the plan, and was never the plan's to explain.
        for minute, status in ((10, 'firing'), (25, 'resolved')):
            self.file_at(self.verdict(unused_start + dt.timedelta(minutes=minute), kind='threshold',
                                      rule='error-rate', status=status, resource=self.case('unused')),
                         unused_start + dt.timedelta(minutes=minute))
        # overrun: a condition the window opened, still firing when the window ended.
        self.file_at(self.verdict(overrun_start + dt.timedelta(minutes=10),
                                  resource=self.case('overrun')),
                     overrun_start + dt.timedelta(minutes=10))
        self.assertEqual(maintenance.attributed(self.store, unknown)['count'], 0)

        for (window, expected) in ((planned, 'planned'), (active, 'active'), (completed, 'completed'),
                                   (cancelled, 'cancelled'), (unused, 'unused'),
                                   (overrun, 'overrun'), (unknown, 'unknown')):
            with self.subTest(outcome=expected):
                answer = self.outcome(window, NOW)
                self.assertIn(expected, maintenance.OUTCOMES)
                self.assertEqual(answer['outcome'], expected, answer['evidence'])
                if expected != 'unknown':
                    self.assertTrue(answer['complete'], answer)
                else:
                    self.assertFalse(answer['complete'],
                                     'a window nothing was recorded inside is not evidence of quiet')
        self.assertEqual(maintenance.attributed(self.store, overrun)['count'], 1,
                         'an overrun still folded what it covered; it simply could not cover the rest')

    def test_an_overrun_stops_silencing_at_the_declared_end(self):
        """The whole reason overrun is loud: the plan expired, so the pager came back on its own.

        Two findings on one resource inside one window. The first is the condition the work was for, and it
        is folded. The second is a *different* condition — one the window never undertook to explain — and
        it opens an incident that is still open when the window ends. That incident is what makes the plan
        an overrun, and what makes the finding after the declared end page: suppression stops at the end the
        human signed, whatever the plan then looks like in retrospect.
        """
        start = NOW - dt.timedelta(days=2)
        end = start + dt.timedelta(minutes=30)
        window = self.declare(start=start, end=end, now=start - dt.timedelta(hours=1))
        self.assertTrue(self.file_at(self.verdict(start + dt.timedelta(minutes=5)),
                                     start + dt.timedelta(minutes=5))['suppressed'])
        self.file_at(self.verdict(start + dt.timedelta(minutes=10), rule='disk-full', kind='threshold'),
                     start + dt.timedelta(minutes=10))
        answer = self.outcome(window, NOW)
        self.assertEqual(answer['outcome'], 'overrun', answer['evidence'])
        self.assertTrue(answer['complete'])
        for minute in (31, 90):
            late = end + dt.timedelta(minutes=minute)
            self.assertFalse(self.file_at(self.verdict(late), late)['suppressed'],
                             f'a finding {minute} minutes past the end is not covered by the plan')

    def test_overlapping_windows_keep_their_own_attribution_and_their_own_cancellation(self):
        """The brief's overlap rule, both halves: attribution per window, and no collateral revocation."""
        start = NOW - dt.timedelta(days=1)
        disk = self.declare(start=start, end=start + dt.timedelta(hours=1),
                            now=start - dt.timedelta(hours=1), reason='replace the disk')
        network = self.declare(start=start + dt.timedelta(minutes=30),
                               end=start + dt.timedelta(hours=2), resource=RESOURCE,
                               now=start - dt.timedelta(hours=1), reason='rewire the uplink')
        at = start + dt.timedelta(minutes=45)
        self.assertTrue(self.file_at(self.verdict(at), at)['suppressed'])
        attributed = maintenance.attributed(self.store, disk)['attributions']
        self.assertEqual(len(attributed), 1)
        self.assertEqual(maintenance.attributed(self.store, network)['count'], 0,
                         'the first covering window takes the page, and the name on it is the one that did')

        maintenance.cancel_window(self.store, disk, HUMAN, now=at)
        still = self.file_at(self.verdict(at + dt.timedelta(minutes=10), rule='host-down-2'),
                             at + dt.timedelta(minutes=10))
        self.assertTrue(still['suppressed'], 'the sibling is still running and still covering')
        self.assertEqual(still['decision'].detail['window_id'], network)
        self.assertEqual(suppression.window_by_id(self.store, network)['revoked_at'], None)
        self.assertEqual(len(self.outcome(disk, NOW)['attributions']), 1,
                         'a cancelled window keeps the pages it folded before it was cancelled')

    def test_attribution_survives_a_restart(self):
        start = NOW - dt.timedelta(days=1)
        window = self.declare(start=start, end=start + dt.timedelta(hours=1),
                              now=start - dt.timedelta(hours=1))
        self.file_at(self.verdict(start + dt.timedelta(minutes=30)), start + dt.timedelta(minutes=30))
        reopened = self.reloaded()
        answer = maintenance.attributed(reopened, window)
        self.assertEqual(answer['count'], 1)
        self.assertEqual(answer['attributions'][0]['condition_class'], 'availability')
        self.assertFalse(answer['truncated'])


class MaintenanceEventTimeTests(ClockedReader):
    """Late facts and bounded searches: the instant judged is the one the finding was observed at."""

    def late_boot(self, observed: dt.datetime, *, rule='host-down', status='resolved',
                  resource=RESOURCE) -> dict:
        """A boot report about `observed`: the class a late arrival has to be judged by is `restart`."""
        return self.verdict(observed, rule=rule, status=status, resource=resource)

    def test_a_fact_that_arrives_after_the_window_is_still_explained_by_it(self):
        start = NOW - dt.timedelta(hours=2)
        window = self.declare(start=start, end=start + dt.timedelta(hours=1),
                              now=start - dt.timedelta(hours=1), reason='reboot the host')
        down, up = start + dt.timedelta(minutes=10), start + dt.timedelta(minutes=30)
        arrival = start + dt.timedelta(hours=3)          # ninety minutes after the plan ended
        # The pair matters: a `resolved` fact that follows no open condition books no transition, and a
        # transition nobody booked has no page to fold. So the outage is filed while the window runs, and the
        # late arrival under test is its *resolution* — the page a build that judged by arrival time would
        # send hours after the machine came back, about work everybody had already agreed to do.
        self.assertTrue(self.file_at(self.late_boot(down, status='firing'), down)['suppressed'])
        filed = self.file_at(self.late_boot(up), up, arrival=arrival)
        self.assertTrue(filed['suppressed'], 'the boot report is about an instant inside the plan')
        self.assertEqual(filed['decision'].detail['condition_class'], 'restart')
        self.assertEqual(filed['decision'].detail['late_seconds'], int((arrival - up).total_seconds()))
        self.assertEqual(filed['decision'].detail['explained_at'], utc_text(up))
        self.assertEqual(sorted(row['condition_class'] for row in
                                maintenance.attributed(self.store, window)['attributions']),
                         ['availability', 'restart'],
                         'the outage and its recovery are both credited to the window that planned them')

    def test_a_window_that_had_already_ended_explains_nothing_whatever_the_arrival_is(self):
        start = NOW - dt.timedelta(hours=4)
        self.declare(start=start, end=start + dt.timedelta(hours=1),
                     now=start - dt.timedelta(hours=1))
        observed = start + dt.timedelta(hours=2)          # observed after the end, arriving now
        filed = self.file_at(self.late_boot(observed), observed, arrival=NOW)
        self.assertFalse(filed['suppressed'])
        self.assertIsNone(suppression.covering_window(self.store, self.late_boot(observed), now=NOW))

    def test_an_instant_lookup_distinguishes_planned_outside_and_unknown(self):
        start = NOW - dt.timedelta(days=1)
        window = self.declare(start=start, end=start + dt.timedelta(hours=1),
                              now=start - dt.timedelta(days=2))
        inside = maintenance.window_at(self.store, scope={'kind': 'resource', 'id': RESOURCE},
                                       at=start + dt.timedelta(minutes=30), klass='availability')
        self.assertEqual((inside['classification'], inside['complete']), ('planned', True))
        self.assertEqual(inside['primary']['window_id'], window)
        outside = maintenance.window_at(self.store, scope={'kind': 'resource', 'id': RESOURCE},
                                        at=start + dt.timedelta(hours=5))
        self.assertEqual((outside['classification'], outside['complete']), ('outside', True),
                         'a complete search is what licenses the word outside')

    def test_a_bounded_search_reports_a_bound_and_never_claims_absence(self):
        start = NOW - dt.timedelta(days=1)
        self.declare(start=start, end=start + dt.timedelta(hours=1),
                     now=start - dt.timedelta(days=2))
        # A second window on the same resource, so a bound of one row is genuinely over-scanned: the claim
        # under test is that an incomplete search may not assert absence, not that a small limit is refused.
        self.declare(start=start + dt.timedelta(hours=2), end=start + dt.timedelta(hours=3),
                     now=start - dt.timedelta(days=2), reason='and a network rewire')
        with mock.patch.object(suppression, 'MAX_HISTORY_ROWS', 1):
            answer = maintenance.window_at(self.store, scope={'kind': 'resource', 'id': RESOURCE},
                                           at=start + dt.timedelta(minutes=30))
            self.assertEqual((answer['classification'], answer['complete']), ('unknown', False), answer)
            self.assertEqual(answer['incomplete_reason'], maintenance.INCOMPLETE_SEARCH)
            self.assertTrue(answer['bounds']['bound_exceeded'])
            span = maintenance.intervals(self.store, scope={'kind': 'resource', 'id': RESOURCE},
                                         span_from=start - dt.timedelta(days=2),
                                         span_to=NOW, now=NOW)
            self.assertFalse(span['complete'])
            self.assertTrue(span['bounds']['bound_exceeded'])
        self.assertGreater(span['count'], 0, 'the rows were still listed; only the claim is withheld')

    def test_a_query_past_the_lookback_is_refused_rather_than_answered_from_the_clock(self):
        verdict = self.late_boot(NOW - dt.timedelta(days=30))
        with mock.patch.object(suppression, 'MAX_EVENT_LOOKBACK_SECONDS', 86400):
            at, late = suppression._decision_instant(verdict, NOW)
        self.assertEqual(at, NOW, 'a fact older than the bound is judged at the clock, and says so')
        self.assertGreater(late, 0)

    def test_the_history_read_sees_windows_the_delivery_path_never_will(self):
        start = NOW - dt.timedelta(days=3)
        window = self.declare(start=start, end=start + dt.timedelta(hours=1),
                              now=start - dt.timedelta(hours=1))
        self.assertEqual(suppression.live_windows(self.store, now=NOW)['count'], 0,
                         'an expired window is not read on the delivery path, and that is the point')
        span = maintenance.intervals(self.store, scope={'kind': 'resource', 'id': RESOURCE},
                                     span_from=start - dt.timedelta(hours=1),
                                     span_to=start + dt.timedelta(hours=2), now=NOW)
        self.assertEqual([row['window_id'] for row in span['intervals']], [window])
        self.assertEqual(span['intervals'][0]['raw']['ends_at'], utc_text(start + dt.timedelta(hours=1)),
                         'the span a human signed never moves, whatever happened to it afterwards')


class MaintenanceSchemaTests(unittest.TestCase):
    """The v12 migration: a table for plans, triggers that keep it append-only, and no rewrite."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'state.db'

    def columns(self, table: str) -> set[str]:
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self.path)) as db:
            return {row[1] for row in db.execute(f'PRAGMA table_info({table})')}

    def indexes(self, table: str) -> set[str]:
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(self.path)) as db:
            return {row[1] for row in db.execute(f'PRAGMA index_list({table})')}

    def test_the_schedule_table_lands_with_its_triggers_and_indexes(self):
        Store(self.path, NotificationPolicy(delivery_mode='off'))
        self.assertEqual(self.columns('maintenance_schedules'),
                         {'schedule_id', 'version', 'document', 'state', 'horizon', 'declared_at',
                          'declared_by', 'attest'})
        self.assertIn('maintenance_outcome_evidence', self.indexes('incidents'))
        self.assertIn('maintenance_attribution', self.indexes('audit'))
        with Store(self.path, NotificationPolicy(delivery_mode='off')).transaction() as connection:
            connection.execute('INSERT INTO maintenance_schedules(schedule_id,version,document,state,'
                               'horizon,declared_at,declared_by,attest) VALUES (?,?,?,?,?,?,?,?)',
                               (RESOURCE, 1, '{}', 'active', utc_text(NOW), utc_text(NOW), 'operator', 1))
            for statement in ('UPDATE maintenance_schedules SET state=? WHERE 1=1',
                              'DELETE FROM maintenance_schedules'):
                with self.subTest(statement=statement.split()[0]):
                    with self.assertRaises(Exception) as caught:
                        connection.execute(statement, ('x',) if 'SET' in statement else ())
                    self.assertIn('append-only', str(caught.exception).lower().replace(chr(39), ''))

    def test_windows_declared_before_the_migration_are_still_read_and_still_honoured(self):
        """Existing state stays readable: the migration adds a table and touches no window."""
        before = Store(self.path, NotificationPolicy(delivery_mode='off'))
        window = plant_window(before, 'pre-v12', start=NOW, end=NOW + dt.timedelta(hours=2),
                              version=1)
        reopened = Store(self.path, NotificationPolicy(delivery_mode='off'))
        live = suppression.live_windows(reopened, now=NOW + dt.timedelta(hours=1))
        self.assertEqual([row['id'] for row in live['windows']], [window])
        self.assertIsNone(live['windows'][0]['explains'])
        stored = suppression.window_by_id(reopened, window)
        self.assertEqual(stored['document_version'], 1)
        self.assertEqual(suppression.stats(reopened, now=NOW + dt.timedelta(hours=1))
                         ['windows']['live'], 1, 'a pre-v12 row still counts as live coverage')
        # The plan table is empty and every schedule read answers it, so the upgrade path is additive.
        self.assertEqual(maintenance.schedules(reopened)['count'], 0)
        answer = maintenance.declare_schedule(
            reopened, {'reason': 'firmware refresh', 'scope': {'kind': 'resource', 'id': RESOURCE},
                       'recurrence': {'frequency': 'weekly', 'interval': 1, 'days_of_week': [0],
                                      'time_of_day': '03:30', 'duration_seconds': 1800,
                                      'timezone': 'Europe/London', 'dst': 'wall'},
                       'bounds': {'first_occurrence': '2026-10-19', 'occurrences': 2}},
            HUMAN, now=PLAN_NOW)
        self.assertEqual(answer['status'], 'declared')
        after = suppression.live_windows(reopened, now=NOW + dt.timedelta(hours=1))
        self.assertIn(window, [row['id'] for row in after['windows']])
        self.assertEqual(after['count'], 2,
                         'the pre-migration window and the plan that has not run yet coexist; the slice that'
                         ' already ended is past')

    def test_a_store_that_cannot_be_read_to_the_end_says_so_rather_than_omitting_rows(self):
        store = Store(self.path, NotificationPolicy(delivery_mode='off'))
        maintenance.declare_schedule(
            store, {'reason': 'one', 'scope': {'kind': 'resource', 'id': RESOURCE},
                    'recurrence': {'frequency': 'daily', 'interval': 1, 'days_of_week': [],
                                   'time_of_day': '04:00', 'duration_seconds': 600,
                                   'timezone': 'UTC', 'dst': 'wall'},
                    'bounds': {'first_occurrence': '2026-10-20', 'occurrences': 2}},
            HUMAN, now=NOW)
        with store.transaction() as connection:
            connection.execute('INSERT INTO maintenance_schedules(schedule_id,version,document,state,'
                               'horizon,declared_at,declared_by,attest) VALUES (?,?,?,?,?,?,?,?)',
                               ('e3f4a5b6-7c8d-4e9f-0a1b-2c3d4e5f6a7b', 1, 'not json', 'active',
                                utc_text(NOW), utc_text(NOW), 'operator', 1))
        answer = maintenance.schedules(store, now=NOW)
        self.assertEqual((answer['count'], answer['unreadable']), (1, 1),
                         'a row this build cannot read is counted, not hidden')


if __name__ == '__main__':
    unittest.main()

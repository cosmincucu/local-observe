"""What a named human decided about one alert occurrence, answered through the served transport.

`docs/api/occurrences.md` is the contract and `local_observe/platform/dispositions.py` is its implementation;
this file is the reason either of them can be trusted. Almost every assertion goes through `create_app` over a
real `Store` on a temp path, because the three claims that matter are about durable state and not about a
function's return value:

* **An acknowledgement stops repeats and resolves nothing.** "Stopped" is measured as a provider call count
  (`FakeProvider`) and as `outbox` rows read straight off the file, and the genuine clear that follows an
  acknowledgement is asserted to *still* be delivered — the half a pager must not get wrong.
* **A dismissal outlives the process that recorded it and does not outlive its episode.** A new `create_app`
  over the same file is the API restart, a new `Store` handle is the notifier restart, and the same verdict
  re-filed after both is the replay. The page that must not arrive is the provider's silence; the *next*
  boot's page is that same counter going up, with a control run that differs only by the dismissal.
* **A refusal writes nothing.** Every 400/401/403/404/409/412 below is followed by a count of the disposition
  and history tables, because a half-applied disposition is worse than the absence of one.

Fixtures are synthetic: `uuid5`-derived resource ids and reserved `fixture`/`demo-*` names, one small declared
inventory document for the group tests, and no network, host, credential or real channel client anywhere. The
clock is injected into every call, including the ones that let a delivery lease lapse.
"""
import concurrent.futures
import contextlib
import datetime as dt
import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import uuid

from local_observe.inventory import index
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform import api_contract, dispositions, escalation, notifications
from local_observe.platform import policy as action_policy_module
from local_observe.platform.api import create_app
from local_observe.platform.correlation import Grouping
from local_observe.platform.detections import event as build_event
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import (Actor, OCCURRENCE_DISMISSAL_TABLE, OCCURRENCE_DISMISSAL_ACK_CAUSE,
                                          OCCURRENCE_DISMISSAL_CAUSE, StateError, Store)

NOW = timestamp('2026-09-12T09:00:00Z')
PRODUCER = Actor('lo-detector', 'producer')
HUMAN = Actor('operator', 'human')
PROPOSER = Actor('agent-1', 'proposer')
HUMAN_TOKEN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
READER = {'identity': 'dashboard', 'role': 'reader', 'token': 'r' * 32}
PRODUCER_TOKEN = {'identity': 'lo-detector', 'role': 'producer', 'token': 'p' * 32}
PROPOSER_TOKEN = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
EXECUTOR = {'identity': 'runbook', 'role': 'executor', 'token': 'e' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
CREDENTIALS = [HUMAN_TOKEN, READER, PRODUCER_TOKEN, PROPOSER_TOKEN, EXECUTOR, SUMMARY]
#: `live`, because the acceptance cases are about a page that arrives or does not. A 20-send budget is so that
#: the flood breaker is never the reason a repeat is missing from a control run.
LIVE = NotificationPolicy(delivery_mode='live', max_attempts=20)
ESCALATION_SOURCE = 'lo-escalation'
BASE_RULE = 'gatus.result'


class FakeProvider:
    """A channel that records every call and always accepts.

    This object is the whole measurement of "no page": a suppressed delivery is one it never saw, and a
    recalled one would be a call it made and then un-made, which no channel supports.
    """

    def __init__(self):
        self.calls = []

    def request(self, method, *, payload, headers):
        self.calls.append(payload)
        return 202, {'accepted': True, 'delivery_id': payload['delivery_id']}


def _text(value) -> str:
    """One header field as text, whether the transport sent bytes or already decoded it."""
    return value.decode() if isinstance(value, bytes) else str(value)


def human_context() -> api_contract.ActorContext:
    """One actor context as the transport would have built it from the human credential."""
    return api_contract.ActorContext(identity=HUMAN.identity, role='human',
                                     request_id=api_contract.new_request_id())


class DispositionFixture(unittest.TestCase):
    """One store, one app, one injected clock, and the two restarts the contract promises about."""

    policy = LIVE

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provider = FakeProvider()
        self.path = self.root / 'state.db'
        self.store = Store(self.path, self.policy)
        self.now = NOW

    # --- the transport, and its restarts -----------------------------------------------------

    def app(self):
        """A freshly built app over the shared store: the whole of what an API restart is to this contract."""
        return create_app(self.store, CREDENTIALS, {})

    def restart_api(self):
        return self.app()

    def restart_notifier(self):
        """Reopen the store, which is what a notifier process restart is.

        Nothing in this build caches a disposition in memory, so a new handle over the same file is the
        honest test of "the answer an operator gave outlives the process that recorded it".
        """
        self.store = Store(self.path, self.policy)
        return self.store

    def at(self, minutes: int = 0, seconds: int = 0) -> dt.datetime:
        return NOW + dt.timedelta(minutes=minutes, seconds=seconds)

    # --- filing verdicts ---------------------------------------------------------------------

    @staticmethod
    def resource_id(name: str) -> str:
        """A stable synthetic UUID for a synthetic name — never a real estate id."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, 'occurrence-fixture/' + name))

    def verdict(self, rule: str = BASE_RULE, *, status: str = 'firing', at: dt.datetime = None,
                resource: str = 'demo-host', condition: str | None = None) -> dict:
        """One canonical verdict.

        `condition=` is how a producer reporting discrete occurrences (one per boot, session or run) carries
        its own identity: `dispositions._episode` reads that field to answer `identity_basis: discrete`, and
        `suppression.condition_key` folds it into the condition digest, so the next boot is a different
        condition and therefore a different episode. Leaving it unset is the ordinary state-reporting
        producer, whose episode is delimited by its own clear/re-fire boundary.
        """
        moment = at or self.now
        window = {'start': utc_text(moment - dt.timedelta(seconds=60)), 'end': utc_text(moment)}
        verdict = build_event(PRODUCER.identity, self.resource_id(resource), rule, 'availability', status,
                              window, {'rule_id': rule}, query_type='gatus-result')
        if condition is not None:
            verdict['condition'] = condition
        return verdict

    def file(self, verdict: dict, *, at: dt.datetime = None, grouped: bool = False) -> dict:
        """File one verdict through `Store.intake`, optionally under the declared-graph grouping.

        `at` defaults to the instant the verdict's own window ends and not to `self.now`: `validate_event`
        refuses a window that ends after the clock it is filed at, and a test that moved a verdict and forgot
        to move the intake clock would be refused for something it did not do.
        """
        moment = at or timestamp(verdict['window']['end'])
        admission = (self.store.grouping_admission(self.index_path, PRODUCER, now=moment, grouping=Grouping())
                     if grouped else None)
        return self.store.intake(verdict, PRODUCER, now=moment, admission=admission)

    def open_episode(self, rule: str = BASE_RULE, **kwargs) -> str:
        """File one firing verdict and return the occurrence (incident) id it opened."""
        outcome = self.file(self.verdict(rule, **kwargs))
        self.assertEqual(outcome['transition'], 'opened', 'the fixture must open a real episode')
        return outcome['incident_id']

    # --- HTTP --------------------------------------------------------------------------------

    def request(self, method: str, path: str, *, token: str | None = HUMAN_TOKEN['token'], body=None,
                query: str = '', headers: list[tuple[bytes, bytes]] | None = None, app=None):
        """One request through the ASGI app, no socket, on its own event loop."""
        raw = b'' if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        scope_headers = list(headers or [])
        if token is not None:
            scope_headers.append((b'authorization', ('Bearer ' + token).encode()))
        output: list[dict] = []

        async def receive():
            return {'type': 'http.request', 'body': raw, 'more_body': False}

        async def send(message):
            output.append(message)

        async def go():
            scope = {'type': 'http', 'http_version': '1.1', 'method': method, 'path': path,
                     'raw_path': path.encode(), 'scheme': 'http', 'query_string': query.encode(),
                     'headers': scope_headers, 'client': ('127.0.0.1', 50000),
                     'server': ('127.0.0.1', 8080), 'root_path': ''}
            await (app or self.app())(scope, receive, send)

        asyncio.run(go())
        start = output[0]
        payload = json.loads(output[-1]['body']) if output[-1].get('body') else None
        return (start['status'], payload,
                {_text(name).lower(): _text(value) for name, value in start.get('headers', [])})

    def read(self, path: str, query: str = '', **kwargs):
        return self.request('GET', path, query=query, **kwargs)

    def write(self, path: str, body, **kwargs):
        return self.request('POST', path, body=body, **kwargs)

    def ack(self, occurrence: str, reason: str = 'looking at it now', **kwargs):
        body = kwargs.pop('body', None) or {'reason': reason}
        return self.write(f'/v1/alert-occurrences/{occurrence}/acknowledgements', body, **kwargs)

    def dismiss(self, occurrence: str, reason: str = 'not actionable: tracked elsewhere', **kwargs):
        body = kwargs.pop('body', None) or {'reason': reason}
        return self.write(f'/v1/alert-occurrences/{occurrence}/dismissals', body, **kwargs)

    def record(self, occurrence: str, kind: str = 'acknowledged',
               reason: str = 'looking at it now') -> dict:
        """Record a disposition through the library, on the clock this test is holding.

        Used by the projection tests, whose subject is the backoff arithmetic in `drain`: a disposition
        reaches its `available_at` through the instant it was recorded at, and the transport injects no
        clock into that field (`api.py` passes none), so a test that mixed an HTTP-recorded disposition with
        an injected drain would be comparing a wall clock with a fixture one.
        """
        call = dispositions.acknowledge if kind == 'acknowledged' else dispositions.dismiss
        return call(self.store, occurrence, reason, human_context(), now=self.now)

    # --- the delivery rail --------------------------------------------------------------------

    def deliver(self, *, until: dt.datetime | None = None) -> list[dict]:
        """Drain the queue through the real notifier loop and return every decision it recorded.

        `notifications.deliver_one` repeated until it says `idle` is what the notifier service does; each
        call makes exactly one admission decision through `notification_safety.reserve`, and a suppressed
        row is consumed by its claim, so this cannot spin.
        """
        reports = []
        moment = until or self.now
        while True:
            report = notifications.deliver_one(self.store, self.provider, now=moment)
            if report['status'] == 'idle':
                return reports
            reports.append(report)

    # --- raw state ----------------------------------------------------------------------------

    def rows(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        """Read the store's own file with raw sqlite, so no answer below comes from the code under test."""
        with contextlib.closing(sqlite3.connect(f'file:{self.path}?mode=ro', uri=True)) as db:
            db.row_factory = sqlite3.Row
            return db.execute(sql, parameters).fetchall()

    def count(self, table: str, where: str = '', parameters: tuple = ()) -> int:
        return self.rows('SELECT count(*) AS n FROM ' + table
                         + ((f' WHERE {where}') if where else ''), parameters)[0]['n']

    def document(self, occurrence: str) -> dict:
        status, body, _ = self.read(f'/v1/alert-occurrences/{occurrence}')
        self.assertEqual(status, 200, body)
        return body

    def audit_rows(self, operation: str) -> list[dict]:
        return [{'actor': row['actor'], 'detail': json.loads(row['detail'])}
                for row in self.rows('SELECT actor, detail FROM audit WHERE operation=?', (operation,))]


# ------------------------------------------------------------------------- the reads, first


class OccurrenceReadTests(DispositionFixture):
    """What an untouched episode says, and the bound every page of it obeys."""

    def test_an_open_episode_reads_as_unacknowledged_with_nothing_recorded(self):
        """Three axes, three sources, and no invented disposition on an episode nobody has spoken for."""
        occurrence = self.open_episode()
        body = self.document(occurrence)
        self.assertEqual(body['occurrence_id'], occurrence, 'the occurrence id IS the incident id (§1)')
        self.assertEqual(body['state'], 'unacknowledged')
        self.assertIsNone(body['disposition'])
        self.assertEqual(body['measured']['status'], 'open')
        self.assertEqual(body['measured']['condition_status'], 'firing')
        self.assertEqual(body['episode']['identity_basis'], 'incident')
        self.assertEqual(body['episode']['rule_id'], BASE_RULE)
        self.assertEqual(body['episode']['source'], PRODUCER.identity)
        self.assertFalse(body['episode']['rung'])
        self.assertEqual(body['episode']['members'], 1)
        self.assertEqual(body['legacy_evidence'], [])
        self.assertEqual({kind: row['status'] for kind, row in body['projections'].items()},
                         {'telemetry-metric': 'unconfigured', 'rule-card': 'unconfigured'},
                         'no disposition, so no downstream statement was ever booked')
        self.assertEqual(body['delivery']['queued'], 1, 'the opening page is still in the queue')
        self.assertEqual(body['delivery']['suppressed'], 0)
        self.assertFalse(body['delivery']['recalled'])
        self.assertFalse(body['delivery']['uncertain'])

    def test_a_discrete_producer_names_its_own_identity_basis(self):
        """`identity_basis` answers "would the next one be covered?" without the operator reading the code."""
        occurrence = self.file(self.verdict('disk.boot.failed', condition='boot-2f6c1a'))['incident_id']
        body = self.document(occurrence)
        self.assertEqual(body['episode']['identity_basis'], 'discrete')
        self.assertEqual(body['episode']['condition'], 'boot-2f6c1a')
        self.assertEqual(body['episode']['rule_id'], 'disk.boot.failed')

    def test_the_page_walks_oldest_first_and_refuses_a_cursor_it_never_issued(self):
        """`limit` is refused and not clamped, and a page is continued only by the token this service gave."""
        opened = [self.open_episode(rule=f'fixture.rule.{number}') for number in range(3)]
        status, first = self.read('/v1/alert-occurrences', 'limit=2')[:2]
        self.assertEqual(status, 200)
        self.assertEqual([row['occurrence_id'] for row in first['rows']], opened[:2])
        self.assertEqual(first['returned'], 2)
        self.assertEqual(first['limit'], 2)
        status, second = self.read('/v1/alert-occurrences', f"limit=2&cursor={first['next_cursor']}")[:2]
        self.assertEqual([row['occurrence_id'] for row in second['rows']], opened[2:])
        self.assertNotIn('next_cursor', second, 'a short page is the end and must not pretend otherwise')
        for query in ('limit=0', 'limit=201', 'limit=abc', 'limit=1e3', 'cursor=not-a-cursor',
                      'status=open', 'limit=2&limit=3'):
            with self.subTest(query=query):
                status, body = self.read('/v1/alert-occurrences', query)[:2]
                self.assertEqual(status, 400, body)
                self.assertEqual(body['error']['code'], 'invalid_pagination')
        self.assertEqual(self.read('/v1/alert-occurrences')[1]['limit'], api_contract.PAGE_LIMIT_DEFAULT)

    def test_a_dismissed_episode_reports_the_disposition_and_the_measurement_at_once(self):
        """`dismissed` beside `open` in one answer: the disposition is not the measurement (§2)."""
        occurrence = self.open_episode()
        self.assertEqual(self.dismiss(occurrence)[0], 200)
        body = self.document(occurrence)
        self.assertEqual(body['state'], 'dismissed')
        self.assertEqual(body['measured']['status'], 'open', 'a dismissal resolved nothing')
        self.assertEqual(body['measured']['condition_status'], 'firing')
        self.assertEqual(body['disposition']['actor'], HUMAN.identity)
        self.assertEqual(body['disposition']['revision'], 1)

    def test_the_history_page_is_a_bounded_page_of_every_statement(self):
        """History holds what the effective state has moved past — that is the point of keeping it."""
        occurrence = self.open_episode()
        for reason in ('one', 'two', 'three'):
            self.assertEqual(self.ack(occurrence, reason=reason)[0], 200)
        first = self.read(f'/v1/alert-occurrences/{occurrence}/history', 'limit=2')[1]
        self.assertEqual([row['reason'] for row in first['rows']], ['one', 'two'])
        self.assertEqual(first['rows'][0]['actor'], HUMAN.identity)
        self.assertEqual(first['rows'][0]['revision'], 1)
        second = self.read(f'/v1/alert-occurrences/{occurrence}/history',
                           f"limit=2&cursor={first['next_cursor']}")[1]
        self.assertEqual([row['reason'] for row in second['rows']], ['three'])
        self.assertEqual(self.read(f'/v1/alert-occurrences/{occurrence}/history', 'cursor=77')
                         [1]['error']['code'], 'invalid_pagination')


# ---------------------------------------------------------------------- acknowledge: what it buys


class AcknowledgementTests(DispositionFixture):
    """An acknowledgement is "a human has this"; this class checks exactly what that sentence buys."""

    def test_an_acknowledgement_names_who_and_why_and_folds_the_queued_page(self):
        occurrence = self.open_episode()
        status, body, headers = self.ack(occurrence, reason='investigating the disk alert')
        self.assertEqual(status, 200, body)
        self.assertTrue(body['created'])
        self.assertEqual(body['folded'], 1)
        self.assertEqual(body['state'], 'acknowledged')
        self.assertEqual({key: body['disposition'][key] for key in ('kind', 'actor', 'reason', 'revision')},
                         {'kind': 'acknowledged', 'actor': HUMAN.identity,
                          'reason': 'investigating the disk alert', 'revision': 1})
        # The instant is the store's own clock (the transport injects none) and is pinned to the history row
        # it was written beside, which is the durable half of "who said what, when".
        self.assertEqual(timestamp(body['disposition']['at']),
                         timestamp(self.rows('SELECT at FROM occurrence_disposition_history')[0]['at']))
        self.assertNotIn('etag', headers, 'a write answers in its body; the tag rides the read')
        self.assertEqual(self.read('/v1/alert-occurrences/' + occurrence)[2]['etag'], body['revision'],
                         'and the read carries the tag the next conditional write must send back')
        self.assertEqual(self.count('outbox', "status='dead'"), 1)
        self.assertEqual(self.count('notification_suppressions'), 1)
        self.assertTrue(self.rows('SELECT reason FROM notification_suppressions')[0]['reason']
                        .startswith(OCCURRENCE_DISMISSAL_ACK_CAUSE + ':'))
        self.assertEqual(self.count('audit', 'operation=?', ('occurrence.disposed',)), 1)
        self.assertEqual(self.deliver(), [], 'the provider was never asked')
        self.assertEqual(self.provider.calls, [])

    def test_the_fold_is_the_same_durable_fact_every_other_fold_writes(self):
        """So that the retry route, the delivery view and the suppression statistics see one vocabulary."""
        occurrence = self.open_episode()
        delivery = self.rows('SELECT id FROM outbox WHERE incident_id=?', (occurrence,))[0]['id']
        self.assertEqual(self.ack(occurrence)[0], 200)
        row = self.rows('SELECT reason FROM notification_suppressions WHERE outbox_id=?', (delivery,))[0]
        self.assertEqual(row['reason'].split(':')[0], OCCURRENCE_DISMISSAL_ACK_CAUSE)
        detail = json.loads(self.rows("SELECT detail FROM audit WHERE operation='notification.suppressed'"
                                       ' AND subject=?', (delivery,))[0]['detail'])
        self.assertEqual(detail['cause'], OCCURRENCE_DISMISSAL_ACK_CAUSE)
        self.assertEqual(detail['occurrence_id'], occurrence)
        self.assertEqual(detail['transition'], 'opened')
        self.assertEqual(self.document(occurrence)['delivery']['suppressed'], 1)
        with self.assertRaises(StateError):
            self.store.retry_notification(delivery, HUMAN)      # §8: a fold is not replayable

    def test_an_acknowledged_episode_still_delivers_its_genuine_clear(self):
        """The one page an operator who said "I have this" must not be denied."""
        occurrence = self.open_episode()
        self.assertEqual(self.ack(occurrence)[0], 200)
        self.file(self.verdict(status='resolved', at=self.at(minutes=2)))
        self.assertEqual(self.count('outbox', "status='pending'"), 1,
                         'the clear booked its own delivery, after the fold')
        reports = self.deliver(until=self.at(minutes=3))
        self.assertEqual([report['status'] for report in reports], ['sent'])
        self.assertEqual(len(self.provider.calls), 1)

    def test_a_genuine_clear_resolves_the_episode_and_outranks_the_disposition_in_state(self):
        occurrence = self.open_episode()
        self.assertEqual(self.ack(occurrence)[0], 200)
        self.file(self.verdict(status='resolved', at=self.at(minutes=5)))
        body = self.document(occurrence)
        self.assertEqual(body['measured']['status'], 'resolved')
        self.assertEqual(body['state'], 'source-resolved')
        self.assertEqual(body['disposition']['kind'], 'acknowledged',
                         'the act is still true and still readable; only the derived state moved')

    def test_a_refire_after_a_genuine_clear_is_a_new_unacknowledged_episode(self):
        """Why an acknowledgement needs no expiry: the episode has an end of its own."""
        first = self.open_episode()
        self.assertEqual(self.ack(first)[0], 200)
        self.file(self.verdict(status='resolved', at=self.at(minutes=5)))
        second = self.file(self.verdict(at=self.at(minutes=10)))['incident_id']
        self.assertNotEqual(second, first)
        self.assertEqual(self.document(second)['state'], 'unacknowledged')
        self.assertIsNone(self.document(second)['disposition'])
        reports = self.deliver(until=self.at(minutes=10))
        self.assertEqual([report['status'] for report in reports], ['sent', 'sent'],
                         'the clear the acknowledgement left queued, then the new episode\'s own opening page')
        self.assertEqual(len(self.provider.calls), 2, 'the new episode pages, which is what §2 promises')

    def test_an_acknowledged_episode_may_be_dismissed_forward(self):
        occurrence = self.open_episode()
        self.assertEqual(self.ack(occurrence)[0], 200)
        status, body = self.dismiss(occurrence, reason='rolled into planned work')[:2]
        self.assertEqual(status, 200, body)
        self.assertEqual(body['state'], 'dismissed')
        self.assertEqual(body['disposition']['revision'], 2)
        self.assertEqual([row['kind'] for row in
                          self.rows('SELECT kind FROM occurrence_disposition_history ORDER BY sequence')],
                         ['acknowledged', 'dismissed'])
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE), 1, 'the tombstone arrives with the dismissal')

    def test_durable_who_when_why_across_an_api_restart_and_a_notifier_restart(self):
        """One history row per decision, and a retry that is not a second decision."""
        occurrence = self.open_episode()
        status, body = self.ack(occurrence, reason='first shift')[:2]
        self.assertEqual((status, body['created']), (200, True))
        self.now = self.at(minutes=10)
        status, body = self.ack(occurrence, reason='first shift')[:2]
        self.assertEqual((status, body['created']), (200, False))
        self.assertEqual(body['disposition']['reason'], 'first shift',
                         'the stored row keeps the FIRST actor, reason and instant')
        self.assertEqual(self.count('occurrence_disposition_history'), 1)
        self.restart_api()
        self.restart_notifier()
        self.assertEqual(self.document(occurrence)['disposition']['reason'], 'first shift')
        status, body = self.ack(occurrence, reason='second shift, still on it')[:2]
        self.assertTrue(body['created'], 'a new reason is a new statement')
        self.assertEqual(body['disposition']['revision'], 2)
        history = self.read(f'/v1/alert-occurrences/{occurrence}/history')[1]
        self.assertEqual([row['reason'] for row in history['rows']],
                         ['first shift', 'second shift, still on it'])


# ------------------------------------------------------------------- dismissal: durable, and bounded


class DismissalTests(DispositionFixture):
    """A dismissal is "this episode is not actionable", said once and obeyed after this process dies."""

    def boot(self, boot_id: str, *, minutes: int = 0) -> dict:
        return self.verdict('disk.boot.failed', at=self.at(minutes=minutes), condition='boot-' + boot_id)

    def test_dismissing_a_boot_silences_replays_through_both_restarts_and_the_replay(self):
        """Identical observations after an API restart and a notifier restart produce no page at all."""
        occurrence = self.file(self.boot('2f6c1a'))['incident_id']
        self.assertEqual(self.document(occurrence)['episode']['identity_basis'], 'discrete')
        status, body = self.dismiss(occurrence)[:2]
        self.assertEqual(status, 200, body)
        self.assertEqual(body['folded'], 1)
        self.assertEqual(body['state'], 'dismissed')
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE), 1, 'the tombstone is the durable half')

        self.restart_api()
        self.restart_notifier()
        for repeat in range(4):                    # the replay: the same boot, reported again and again
            outcome = self.file(self.boot('2f6c1a', minutes=1 + repeat))
            self.assertEqual(outcome['incident_id'], occurrence,
                             'a repeat of the same boot is the same episode, not a new one')
        self.assertEqual(self.deliver(until=self.at(minutes=6)), [], 'nothing was left to send')
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.count('outbox', "status='sent'"), 0)
        self.assertEqual(self.document(occurrence)['state'], 'dismissed')

    def test_the_next_boot_pages_and_so_does_an_unrelated_condition(self):
        """The pair and never the condition alone is the tombstone key.

        Two negatives, one defect: a lookup that ignored `incident_id` would silence every future boot of
        that host, which is the failure mode this table exists not to be.
        """
        dismissed = self.file(self.boot('2f6c1a'))['incident_id']
        self.assertEqual(self.dismiss(dismissed)[0], 200)
        self.deliver()
        self.assertEqual(self.provider.calls, [])

        next_boot = self.file(self.boot('9b0d22', minutes=1))['incident_id']
        unrelated = self.file(self.verdict('disk.smart.predict', at=self.at(minutes=2)))['incident_id']
        self.assertNotIn(next_boot, (dismissed, unrelated))
        self.assertEqual(self.document(next_boot)['state'], 'unacknowledged')
        self.assertEqual(self.count('outbox', "status='pending'"), 2)
        self.deliver(until=self.at(minutes=5))
        self.assertEqual(len(self.provider.calls), 2, 'a new episode pages exactly as the last one did')

    def test_a_dismissal_does_not_resolve_the_condition_it_closed(self):
        """Two fields at once, and neither written over the other."""
        occurrence = self.file(self.boot('2f6c1a'))['incident_id']
        self.assertEqual(self.dismiss(occurrence)[0], 200)
        body = self.document(occurrence)
        self.assertEqual(body['state'], 'dismissed')
        self.assertEqual(body['measured']['status'], 'open')
        self.assertEqual(self.count('incidents', 'id=? AND status=?', (occurrence, 'resolved')), 0)
        self.assertEqual(self.rows('SELECT status FROM conditions ORDER BY rowid DESC LIMIT 1')
                         [0]['status'], 'firing')

    def test_a_dismissed_episode_stays_silent_through_its_own_recovery_message(self):
        """The recovery page is booked *after* the dismissal, and the tombstone is what refuses it."""
        occurrence = self.open_episode()
        self.assertEqual(self.dismiss(occurrence)[0], 200)
        self.file(self.verdict(status='resolved', at=self.at(minutes=3)))
        self.assertEqual(self.count('outbox', "status='pending'"), 1,
                         'the clear really did book a delivery, after the dismissal')
        reports = self.deliver(until=self.at(minutes=4))
        self.assertEqual([report['reason'] for report in reports], [OCCURRENCE_DISMISSAL_CAUSE])
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.document(occurrence)['state'], 'source-resolved')
        self.assertEqual(self.document(occurrence)['delivery']['sent'], 0)

    def test_a_dismissed_episode_cannot_be_acknowledged_afterwards(self):
        occurrence = self.open_episode()
        self.assertEqual(self.dismiss(occurrence)[0], 200)
        status, body = self.ack(occurrence)[:2]
        self.assertEqual(status, 409)
        self.assertEqual(body['error']['code'], 'conflict')
        self.assertEqual(self.document(occurrence)['state'], 'dismissed')
        self.assertEqual(self.count('occurrence_disposition_history'), 1)
        self.assertEqual(self.count('outbox', "status='pending'"), 0, 'the refusal wrote nothing')

    def test_a_dismissal_survives_a_replay_of_the_verdict_that_opened_it(self):
        """The same source event again is a duplicate to `intake`: nothing new, and nothing pages."""
        verdict = self.boot('2f6c1a')
        occurrence = self.file(verdict)['incident_id']
        self.assertEqual(self.dismiss(occurrence)[0], 200)
        replay = self.file(verdict)
        self.assertEqual(replay['status'], 'duplicate',
                         'the replay created no event, no incident and no delivery to suppress')
        self.assertEqual(self.deliver(until=self.at(minutes=2)), [])
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.count('incidents'), 1)


# --------------------------------------------------------------- groups: silence covers what existed


class GroupedEpisodeTests(DispositionFixture):
    """One episode may hold several conditions; a disposition covers exactly the ones it could see."""

    PLAN = (('demo-host', 'host.down'), ('demo-api', 'api.down'), ('demo-api', 'api.latency'),
            ('demo-api', 'api.tls'), ('demo-api', 'api.cert'), ('demo-worker', 'worker.down'),
            ('demo-worker', 'worker.memory'), ('demo-worker', 'worker.disk'))

    def setUp(self):
        super().setUp()
        def declared(name: str, kind: str, relations: tuple = ()) -> dict:
            return {'id': self.resource_id(name), 'kind': kind, 'name': name,
                    'aliases': [{'type': 'service.name', 'value': name, 'scope': 'fixture'}],
                    'attributes': {'environment': 'fixture'},
                    'relations': [{'type': relation, 'target': self.resource_id(target)}
                                  for relation, target in relations]}
        self.index_path = self.root / 'inventory.db'
        index.build({'schema_version': 1, 'resources': [
            declared('demo-host', 'host'),
            declared('demo-api', 'service', (('runs-on', 'demo-host'),)),
            declared('demo-worker', 'service', (('depends-on', 'demo-api'),))]},
            self.index_path, 'occurrence-fixture', now=NOW)

    def join(self, count: int, *, gap_seconds: int = 10) -> tuple[str, list[dict]]:
        """File `count` distinct conditions inside one window over the connected graph.

        Returns the group's occurrence id and the verdict documents filed, so a test can replay exactly the
        same reports later (which is what a replayed producer does, and the case the tombstone is for).
        """
        verdicts, group = [], None
        for step, (resource, rule) in enumerate(self.PLAN[:count]):
            moment = self.at(seconds=step * gap_seconds)
            verdict = self.verdict(rule, resource=resource, at=moment)
            outcome = self.file(verdict, at=moment, grouped=True)
            group = group or outcome['incident_id']
            self.assertEqual(outcome['incident_id'], group,
                             f'the fixture must join {rule} onto one episode, not keep its own')
            verdicts.append(verdict)
        return group, verdicts

    def test_a_disposition_covers_every_member_that_existed_when_it_was_recorded(self):
        group, verdicts = self.join(8)
        self.assertEqual(self.document(group)['episode']['members'], 8)
        self.assertEqual(self.count('outbox', "incident_id=? AND status='pending'", (group,)), 8)

        status, body = self.dismiss(group)[:2]
        self.assertEqual(status, 200, body)
        self.assertEqual(body['folded'], 8, 'eight conditions, one occurrence, one fold')
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE, 'occurrence_id=?', (group,)), 8)
        self.assertEqual(self.deliver(), [])
        self.assertEqual(self.provider.calls, [])

        self.restart_api()
        self.restart_notifier()
        for step, verdict in enumerate(verdicts):                 # the producer replays all eight reports
            moment = self.at(minutes=10, seconds=step)
            self.assertEqual(self.file(verdict, at=moment, grouped=True)['incident_id'], group)
        self.assertEqual(self.deliver(until=self.at(minutes=11)), [])
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.count('notification_suppressions'), 8, 'the eight folds are each recorded')

    def test_the_same_eight_verdicts_with_no_dismissal_page_eight_times(self):
        """The control: same script, same clock, same budget — eight pages.

        Without this, "eight absent pages" in the test above could be the flood breaker, the event-age bound
        or the queue's ordering rule. Here they are not, and the one variable is the dismissal.
        """
        group, _ = self.join(8)
        self.assertEqual(self.count('outbox', "incident_id=? AND status='pending'", (group,)), 8)
        reports = self.deliver(until=self.at(minutes=5))
        self.assertEqual([report['status'] for report in reports], ['sent'] * 8)
        self.assertEqual(len(self.provider.calls), 8)
        self.assertEqual(self.count('notification_suppressions'), 0)

    def test_a_new_member_joining_an_acknowledged_episode_still_pages(self):
        """Silence that grows by inheritance is what §4 refuses."""
        group, _ = self.join(3)
        self.assertEqual(self.ack(group)[0], 200)
        moment = self.at(minutes=1)
        joined = self.file(self.verdict('api.disk', resource='demo-api', at=moment),
                           at=moment, grouped=True)
        self.assertEqual(joined['incident_id'], group, 'the new condition joined the acknowledged episode')
        self.assertEqual(joined['transition'], 'opened', 'and it booked its own page')
        self.assertEqual(self.deliver(until=moment)[0]['status'], 'sent')
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.document(group)['episode']['members'], 4)

    def test_a_disposition_recorded_after_a_member_joined_covers_that_member_too(self):
        group, _ = self.join(3)
        moment = self.at(minutes=1)
        self.file(self.verdict('api.disk', resource='demo-api', at=moment), at=moment, grouped=True)
        self.assertEqual(self.document(group)['episode']['members'], 4)
        status, body = self.dismiss(group)[:2]
        self.assertEqual(status, 200, body)
        self.assertEqual(body['folded'], 4)
        self.assertEqual(self.deliver(until=moment), [])
        self.assertEqual(self.provider.calls, [])

    def test_a_restated_dismissal_cannot_widen_the_silence_onto_a_member_that_joined_later(self):
        """The rule that keeps §4's promise honest, pinned from the refusing side.

        A second dismissal of one episode is refused `409 conflict` whatever its reason, so the tombstone set
        an operator wrote at one instant cannot be silently grown later: the one way to widen the silence is
        to wait for the next episode, which arrives unacknowledged and pages. `docs/api/occurrences.md` §2
        and §4 say the same thing from the other side.
        """
        group, _ = self.join(3)
        self.assertEqual(self.dismiss(group, reason='first pass')[0], 200)
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE, 'occurrence_id=?', (group,)), 3)
        moment = self.at(minutes=1)
        joined = self.file(self.verdict('api.disk', resource='demo-api', at=moment), at=moment, grouped=True)
        self.assertEqual(joined['incident_id'], group)
        status, body = self.dismiss(group, reason='widened on purpose')[:2]
        self.assertEqual(status, 409)
        self.assertEqual(body['error']['message'], dispositions.DISMISSAL_ALREADY_RECORDED)
        status, body = self.ack(group, reason='looking at it after all')[:2]
        self.assertEqual(status, 409)
        self.assertEqual(body['error']['message'], dispositions.DISMISSAL_IS_FINAL)
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE, 'occurrence_id=?', (group,)), 3,
                         'the new member is covered by nothing, and its page still goes')
        reports = self.deliver(until=moment)
        self.assertEqual([report['status'] for report in reports], ['sent'])

    def test_an_independent_condition_on_a_related_resource_keeps_paging(self):
        """A disposition belongs to one episode and says nothing about any other episode."""
        group, _ = self.join(1)
        self.assertEqual(self.dismiss(group)[0], 200)
        moment = self.at(minutes=1)
        other = self.file(self.verdict('api.down', resource='demo-api', at=moment), at=moment)['incident_id']
        self.assertNotEqual(other, group, 'filed without grouping, so it kept its own episode')
        self.deliver(until=moment)
        self.assertEqual(len(self.provider.calls), 1)
        self.assertEqual(self.document(other)['state'], 'unacknowledged')

    def test_the_last_member_s_resolution_is_the_group_s_recovery_and_is_tombstoned(self):
        """Resolution belongs to the last open member, and a dismissal closed even that page."""
        group, _ = self.join(2)
        self.assertEqual(self.dismiss(group)[0], 200)
        for step in (0, 1):
            moment = self.at(minutes=2, seconds=step)
            self.file(self.verdict(status='resolved', resource=self.PLAN[step][0],
                                   rule=self.PLAN[step][1], at=moment), at=moment, grouped=True)
        self.deliver(until=self.at(minutes=3))
        self.assertEqual(self.provider.calls, [], 'the group never pages again, not even to say it ended')
        self.assertEqual(self.document(group)['state'], 'source-resolved')


# --------------------------------------------------------- the boundary: keys, revisions, roles


class BoundaryTests(DispositionFixture):
    """A lost answer must not become a second decision, and nobody may speak as somebody they are not."""

    def test_a_lost_answer_replayed_under_the_same_key_returns_the_stored_answer(self):
        occurrence = self.open_episode()
        key = [(b'idempotency-key', b'fixture-ack-1')]
        status, body, headers = self.ack(occurrence, reason='first try', headers=key)
        self.assertEqual(status, 200, body)
        self.assertNotIn('x-idempotency-replayed', headers)
        self.now = self.at(minutes=10)                     # a replay is not a re-run: the clock may move
        again_status, again_body, again_headers = self.ack(occurrence, reason='first try', headers=key)
        self.assertEqual(again_status, status)
        self.assertEqual(again_body, body)
        self.assertEqual(again_headers.get('x-idempotency-replayed'), 'true')
        self.assertEqual(self.count('occurrence_disposition_history'), 1)
        self.assertEqual(self.count('outbox', "status='dead'"), 1, 'one fold, not two')

    def test_a_replayed_key_over_a_changed_body_is_refused_and_nothing_runs(self):
        occurrence = self.open_episode()
        key = [(b'idempotency-key', b'fixture-ack-2')]
        self.assertEqual(self.ack(occurrence, reason='first try', headers=key)[0], 200)
        status, body = self.ack(occurrence, reason='a different reason now', headers=key)[:2]
        self.assertEqual(status, 409)
        self.assertEqual(body['error']['code'], 'idempotency_conflict')
        self.assertEqual(self.document(occurrence)['disposition']['reason'], 'first try')
        self.assertEqual(self.count('occurrence_disposition_history'), 1)

    def test_a_key_is_scoped_to_one_identity_and_names_one_intention(self):
        """The key is bound to (credential, key, method + path + body digest).

        These routes carry their identifier in the path and nowhere in the body, so one key reused
        against a second occurrence with the same reason is a second intention: it is refused as an
        idempotency conflict, and neither the first answer is replayed nor the second write performed.
        """
        first = self.open_episode('fixture.rule.one')
        second = self.open_episode('fixture.rule.two')
        key = [(b'idempotency-key', b'fixture-ack-3')]
        answer = self.ack(first, headers=key)
        self.assertEqual(answer[0], 200)
        reused = self.ack(second, headers=key)
        self.assertEqual((reused[0], reused[1]['error']['code']), (409, 'idempotency_conflict'))
        self.assertNotEqual(reused[2].get('x-idempotency-replayed'), 'true')
        self.assertEqual(self.document(second)['state'], 'unacknowledged', 'nothing ran for the second')
        replay = self.ack(first, headers=key)
        self.assertEqual((replay[0], replay[2].get('x-idempotency-replayed')), (200, 'true'))
        self.assertEqual(replay[1]['occurrence_id'], first)

    def test_a_key_still_in_flight_is_refused_and_releases_afterwards(self):
        occurrence = self.open_episode()
        body = {'reason': 'held elsewhere'}
        context = api_contract.actor_context(HUMAN, api_contract.new_request_id(),
                                             idempotency_key='fixture-in-flight')
        digest = api_contract.request_digest(
            'POST', f'/v1/alert-occurrences/{occurrence}/acknowledgements', body)
        # The in-flight marker goes stale against the transport's own clock, and the transport injects none
        # (`api.py` calls `reserve(...)` with no `now`), so holding a key open for this test means reserving
        # it at the instant the request will arrive at. Everything else here stays on `NOW`.
        moment = dt.datetime.now(dt.timezone.utc)
        self.store.idempotency_reserve(context.identity, context.idempotency_key, digest, now=moment)
        status, answer = self.ack(occurrence, body=body,
                                  headers=[(b'idempotency-key', b'fixture-in-flight')])[:2]
        self.assertEqual((status, answer['error']['code']), (409, 'request_in_progress'))
        self.assertEqual(self.count('occurrence_dispositions'), 0)
        self.store.idempotency_release(context.identity, context.idempotency_key, digest)
        self.assertEqual(self.ack(occurrence, body=body,
                                  headers=[(b'idempotency-key', b'fixture-in-flight')])[0], 200)

    def test_a_clear_that_happened_while_the_operator_read_refuses_the_ack(self):
        """412 `stale_revision`: the revision tag moves when the episode's own status moves."""
        occurrence = self.open_episode()
        stale = self.read(f'/v1/alert-occurrences/{occurrence}')[2]['etag'].strip('"')
        self.file(self.verdict(status='resolved', at=self.at(minutes=3)))
        status, body = self.write(f'/v1/alert-occurrences/{occurrence}/acknowledgements',
                                  {'reason': 'too late'},
                                  headers=[(b'if-match', stale.encode())])[:2]
        self.assertEqual((status, body['error']['code']), (412, 'stale_revision'))
        self.assertEqual(self.count('occurrence_dispositions'), 0)
        status, body = self.ack(occurrence, body={'reason': 'too late', 'expected_revision': stale})[:2]
        self.assertEqual((status, body['error']['code']), (412, 'stale_revision'))
        self.assertEqual(self.count('occurrence_disposition_history'), 0)

    def test_a_disposition_moves_the_revision_and_invalidates_the_previous_caller(self):
        occurrence = self.open_episode()
        before = self.read(f'/v1/alert-occurrences/{occurrence}')[2]['etag'].strip('"')
        self.assertEqual(self.ack(occurrence)[0], 200)
        after = self.read(f'/v1/alert-occurrences/{occurrence}')[2]['etag'].strip('"')
        self.assertNotEqual(before, after)
        self.assertEqual(self.dismiss(occurrence, headers=[(b'if-match', before.encode())])
                         [1]['error']['code'], 'stale_revision')
        self.assertEqual(self.dismiss(occurrence, headers=[(b'if-match', after.encode())])[0], 200)

    def test_a_repeat_verdict_does_not_move_the_revision_somebody_is_writing_against(self):
        """The other half of the rule: only a disposition or a status change invalidates a write."""
        occurrence = self.open_episode()
        revision = self.read(f'/v1/alert-occurrences/{occurrence}')[2]['etag'].strip('"')
        for repeat in range(3):                   # the same condition, reported again and again
            moment = self.at(minutes=repeat + 1)
            self.file(self.verdict(at=moment), at=moment)
        self.assertEqual(self.read(f'/v1/alert-occurrences/{occurrence}')[2]['etag'].strip('"'), revision)
        self.assertEqual(self.ack(occurrence, headers=[(b'if-match', revision.encode())])[0], 200)

    def test_only_a_human_credential_may_record_a_disposition(self):
        """The role test lives in the state layer, so no transport can forget it and no role can claim up."""
        occurrence = self.open_episode()
        for credential in (PRODUCER_TOKEN, READER, PROPOSER_TOKEN, EXECUTOR):
            for command in ('acknowledgements', 'dismissals'):
                with self.subTest(role=credential['role'], command=command):
                    status, body = self.write(f'/v1/alert-occurrences/{occurrence}/{command}',
                                              {'reason': 'trying'}, token=credential['token'])[:2]
                    self.assertEqual(status, 403, body)
                    self.assertEqual(body['error']['code'], 'not_authorised')
        for command in ('acknowledgements', 'dismissals'):
            # The `summary` refusal belongs to the transport's own gate, which runs before routing and never
            # reaches this module: the pre-existing flat body rather than the envelope, and audited there.
            with self.subTest(role='summary', command=command):
                status, body = self.write(f'/v1/alert-occurrences/{occurrence}/{command}',
                                          {'reason': 'trying'}, token=SUMMARY['token'])[:2]
                self.assertEqual((status, body), (403, {'error': 'summary_only'}))
        status, body = self.ack(occurrence, token=None)[:2]
        self.assertEqual((status, body), (401, {'error': 'authentication_required'}),
                         'authentication is refused ahead of routing, in the shape every route here uses')
        self.assertEqual(self.count('occurrence_dispositions'), 0)
        self.assertEqual(self.count('occurrence_disposition_history'), 0)
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE), 0)

    def test_the_reads_answer_to_the_transport_s_four_read_roles(self):
        """`producer` and `summary` are refused by gates that predate this route family.

        Pinned rather than assumed, because the OpenAPI role list is the promise: the four roles that may
        read are `reader`, `proposer`, `human` and `executor`; a producer gets the flat 400 every other `GET`
        gives it, and a summary credential the flat 403 every other read gives it.
        """
        occurrence = self.open_episode()
        for role in ('reader', 'proposer', 'human', 'executor'):
            for path in ('/v1/alert-occurrences', f'/v1/alert-occurrences/{occurrence}',
                         f'/v1/alert-occurrences/{occurrence}/history'):
                with self.subTest(role=role, path=path):
                    token = next(row['token'] for row in CREDENTIALS if row['role'] == role)
                    self.assertEqual(self.read(path, token=token)[0], 200)
        for role, expected in (('producer', (400, 'not_authorised')), ('summary', (403, 'summary_only'))):
            token = next(row['token'] for row in CREDENTIALS if row['role'] == role)
            for path in ('/v1/alert-occurrences', f'/v1/alert-occurrences/{occurrence}'):
                with self.subTest(role=role, path=path):
                    status, body = self.read(path, token=token)[:2]
                    self.assertEqual((status, body.get('error')), expected)
        self.assertEqual(self.read('/v1/alert-occurrences', token=None)[0], 401)

    def test_a_body_that_claims_an_identity_is_refused_as_such_and_a_stray_field_as_a_bad_request(self):
        occurrence = self.open_episode()
        for field, code in (('actor', 'actor_claim_refused'), ('actor_id', 'actor_claim_refused'),
                            ('identity', 'actor_claim_refused'), ('operator', 'actor_claim_refused'),
                            ('token', 'actor_claim_refused'), ('impersonate', 'actor_claim_refused'),
                            ('role', 'actor_claim_refused'),
                            ('kind', 'invalid_request'), ('reason_extra', 'invalid_request'),
                            ('note', 'invalid_request')):
            with self.subTest(field=field):
                status, answer = self.write(f'/v1/alert-occurrences/{occurrence}/acknowledgements',
                                            {'reason': 'ok', field: 'operator'})[:2]
                self.assertEqual(status, 400, answer)
                self.assertEqual(answer['error']['code'], code)
                self.assertEqual(self.count('occurrence_dispositions'), 0)
        for body, code in (({}, 'invalid_request'),
                           ({'reason': 'ok', 'expected_revision': 'no~such-tag'}, 'invalid_revision'),
                           ({'reason': 'ok', 'expected_revision': 4}, 'invalid_revision'),
                           ({'reason': 'ok', 'expected_revision': ['a']}, 'invalid_revision')):
            with self.subTest(body=sorted(body)):
                status, answer = self.write(f'/v1/alert-occurrences/{occurrence}/dismissals', body)[:2]
                self.assertEqual(status, 400, answer)
                self.assertEqual(answer['error']['code'], code)
            self.assertEqual(self.count('occurrence_dispositions'), 0)

    def test_a_reason_is_required_printable_and_bounded(self):
        occurrence = self.open_episode()
        for reason in ('', '   ', 'line\r\nbreak', 'nul\x00', 'x' * (dispositions.MAX_REASON_CHARS + 1),
                       None, 7):
            with self.subTest(reason=repr(reason)[:24]):
                status, body = self.ack(occurrence, reason=reason)[:2]
                self.assertEqual(status, 400, body)
                self.assertEqual(body['error']['code'], 'invalid_request')
        self.assertEqual(self.count('occurrence_dispositions'), 0)
        boundary = 'x' * dispositions.MAX_REASON_CHARS
        status, body = self.ack(occurrence, reason=boundary)[:2]
        self.assertEqual(status, 200, body)
        self.assertEqual(body['disposition']['reason'], boundary)
        self.assertEqual(self.count('occurrence_disposition_history'), 1)

    def test_no_identifier_names_an_episode_that_does_not_exist(self):
        """A malformed id and an unknown one answer identically, so the route is not an id oracle."""
        unknown = str(uuid.uuid4())
        for target in ('not-a-uuid', '', unknown.upper(), unknown.replace('-', ''), '0' * 36, unknown):
            for suffix, method in (('', 'GET'), ('/history', 'GET'),
                                   ('/acknowledgements', 'POST'), ('/dismissals', 'POST')):
                if not target and method == 'POST':
                    continue            # an empty id segment is not this route; pinned separately below
                with self.subTest(target=repr(target), suffix=suffix):
                    status, body = self.request(method, f'/v1/alert-occurrences/{target}{suffix}',
                                                body={'reason': 'x'} if method == 'POST' else None)[:2]
                    self.assertEqual(status, 404, body)
                    self.assertEqual(body['error']['code'], 'not_found')
        # A path that is not a disposition route is answered by the transport, in the flat body every
        # unmatched address here has always got; a path under the prefix that names no id is answered by the
        # module, in the envelope. The two are different questions and are not made to look alike.
        for stray in ('/v1/alert-occurrences//acknowledgements',
                      '/v1/alert-occurrences/x/y/acknowledgements',
                      '/v1/alert-occurrences/' + unknown + '/acknowledgements/extra'):
            with self.subTest(path=stray):
                status, body = self.write(stray, {'reason': 'x'})[:2]
                self.assertEqual((status, body), (404, {'error': 'not_found'}))
        status, body = self.read('/v1/alert-occurrences/' + unknown + '/nonsense')[:2]
        self.assertEqual((status, body['error']['code']), (400, 'invalid_request'),
                         'a segment naming neither an episode nor its history is a broken caller')
        empty = self.read('/v1/alert-occurrences/')
        self.assertEqual((empty[0], empty[1]['error']['code']), (404, 'not_found'),
                         'a path with no id in it names no occurrence, like any other absent one')

    def test_every_answer_carries_one_request_id_and_refusals_share_the_three_field_envelope(self):
        occurrence = self.open_episode()
        _, _, headers = self.ack(occurrence)
        self.assertRegex(headers['x-request-id'], r'^[A-Za-z0-9_-]{8,64}$')
        _, body, _ = self.ack(occurrence, reason='')
        self.assertEqual(set(body['error']), {'code', 'message', 'request_id'})
        _, unreadable, _ = self.dismiss(occurrence, headers=[(b'if-match', b'no~such-tag')])
        self.assertEqual(unreadable['error']['code'], 'invalid_revision')
        _, other_request, _ = self.dismiss(occurrence, headers=[(b'if-match', b'not.a.tag')])
        self.assertEqual(other_request['error']['code'], 'stale_revision',
                         'a tag-shaped expectation that merely disagrees is a stale read, not a bad header')
        _, wildcard, _ = self.dismiss(occurrence, headers=[(b'if-match', b'*')])
        self.assertEqual(wildcard['state'], 'dismissed', 'If-Match * states no expectation at all')


# ---------------------------------------------------------------- the delivery rail's two halves


class DeliveryRailTests(DispositionFixture):
    """A queued message may be stopped; a leased or dispatched one may not be recalled."""

    def test_a_leased_row_is_not_recalled_and_the_read_says_the_page_may_still_arrive(self):
        occurrence = self.open_episode()
        claimed = self.store.claim_notification(now=self.now)
        self.assertIsNotNone(claimed)
        status, body = self.ack(occurrence)[:2]
        self.assertEqual(status, 200)
        self.assertEqual(body['folded'], 0, 'the only row this episode had was already on a lease')
        self.assertEqual(body['delivery']['in_flight'], 1)
        self.assertTrue(body['delivery']['uncertain'])
        self.assertFalse(body['delivery']['recalled'])
        self.assertEqual(self.count('outbox', "id=? AND status='sending'", (claimed['id'],)), 1)
        self.assertEqual(self.count('notification_suppressions'), 0)
        reports = self.deliver(until=self.at(minutes=5))          # the lease has lapsed
        self.assertEqual([report['status'] for report in reports], ['sent'])
        self.assertEqual(len(self.provider.calls), 1, 'a page the platform already had still goes')

    def test_a_leased_row_of_a_dismissed_episode_is_not_recalled_but_never_pages_afterwards(self):
        """The half of rule 3 that a dismissal alone decides.

        The fold leaves the leased row where it is (nothing is unsent, and no recall verb exists), and the
        read says so. What differs from an acknowledgement is what happens when that lease lapses: the row
        goes back to `pending`, `notification_safety.reserve` asks `occurrence_dismissals`, and it is
        refused — the answer an operator gave outlives the notifier that had already picked the row up.
        """
        occurrence = self.open_episode()
        claimed = self.store.claim_notification(now=self.now)
        _, body = self.dismiss(occurrence)[:2]
        self.assertEqual(body['folded'], 0)
        self.assertEqual(body['delivery']['in_flight'], 1)
        self.assertTrue(body['delivery']['uncertain'])
        self.assertEqual(self.count('outbox', "id=? AND status='sending'", (claimed['id'],)), 1)
        reports = self.deliver(until=self.at(minutes=5))
        self.assertEqual([report['reason'] for report in reports], [OCCURRENCE_DISMISSAL_CAUSE])
        self.assertEqual(self.provider.calls, [])

    def test_an_attempt_with_no_acknowledgement_obtained_reads_as_uncertain_and_not_as_sent(self):
        """`dispatched` counts an attempt that ended with `result='unknown'` — the notifier died mid-send."""
        occurrence = self.open_episode()
        self.store.claim_notification(now=self.now)
        self.assertEqual(self.document(occurrence)['delivery']['dispatched'], 0)
        self.store.claim_notification(now=self.at(minutes=5))     # the lease lapsed: the attempt is unknown
        delivery = self.document(occurrence)['delivery']
        self.assertEqual(delivery['dispatched'], 1)
        self.assertTrue(delivery['uncertain'])
        self.assertEqual(delivery['sent'], 0)

    def test_a_folded_row_does_not_block_the_queue_s_ordering_behind_it(self):
        """The claim waits for the earliest unsuppressed row of an episode; a fold must not jam that."""
        occurrence = self.open_episode()
        self.assertEqual(self.ack(occurrence)[0], 200)
        self.file(self.verdict(status='resolved', at=self.at(minutes=2)))
        reports = self.deliver(until=self.at(minutes=3))
        self.assertEqual([report['status'] for report in reports], ['sent'])

    def test_a_sent_page_is_reported_as_sent_and_a_disposition_does_not_claim_to_have_stopped_it(self):
        occurrence = self.open_episode()
        self.deliver()
        self.assertEqual(len(self.provider.calls), 1)
        _, body = self.dismiss(occurrence)[:2]
        self.assertEqual(body['folded'], 0)
        self.assertEqual(body['delivery']['sent'], 1)
        self.assertFalse(body['delivery']['uncertain'])


# ---------------------------------------------------------------------------- two writers, one file


class ConcurrencyTests(DispositionFixture):
    """Two operators, one episode, one transaction: the file decides, and never leaves a torn half."""

    def race(self, count: int, action) -> list:
        """Run `action` `count` times, all threads released by one barrier, and collect their answers."""
        gate = threading.Barrier(count)

        def run():
            gate.wait(timeout=30)
            return action()

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            return [future.result() for future in [pool.submit(run) for _ in range(count)]]

    def test_eight_identical_acks_race_one_episode_and_one_of_them_is_a_decision(self):
        occurrence = self.open_episode()
        answers = self.race(8, lambda: self.ack(occurrence, reason='on it'))
        self.assertEqual([status for status, _, _ in answers], [200] * 8)
        self.assertEqual(sum(1 for _, body, _ in answers if body['created']), 1,
                         'exactly one decision; the other seven are the identical statement restated')
        self.assertEqual(self.count('occurrence_disposition_history'), 1)
        self.assertEqual(self.count('occurrence_dispositions'), 1)
        self.assertEqual(self.document(occurrence)['disposition']['revision'], 1)
        self.assertEqual(self.count('outbox', "status='dead'"), 1, 'one fold of one queued page')
        self.assertEqual(self.count('audit', 'operation=?', ('occurrence.disposed',)), 1)
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE), 0, 'an acknowledgement never tombstones')

    def test_a_racing_ack_and_dismiss_leave_one_effective_state_and_an_append_only_history(self):
        occurrence = self.open_episode()
        gate = threading.Barrier(2)

        def run(action):
            gate.wait(timeout=30)
            return action()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run, lambda: self.ack(occurrence, reason='mine')),
                       pool.submit(run, lambda: self.dismiss(occurrence, reason='mine'))]
            answers = [future.result() for future in futures]
        statuses = sorted(status for status, _, _ in answers)
        self.assertIn(statuses, ([200, 200], [200, 409]),
                      'either both were accepted in some order, or the ack arrived after a dismissal')
        body = self.document(occurrence)
        self.assertEqual(body['state'], 'dismissed', 'dismissal is forward-only, so it always wins here')
        self.assertEqual(body['disposition']['revision'], self.count('occurrence_disposition_history'))
        self.assertEqual(self.count(OCCURRENCE_DISMISSAL_TABLE, 'occurrence_id=?', (occurrence,)), 1)
        self.assertEqual(self.count('occurrence_dispositions'), 1)

    def test_a_recovery_racing_an_acknowledgement_still_delivers_the_clear(self):
        occurrence = self.open_episode()
        moment = self.at(minutes=2)
        gate = threading.Barrier(2)

        def run(action):
            gate.wait(timeout=30)
            return action()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run, lambda: self.ack(occurrence)),
                       pool.submit(run, lambda: self.file(self.verdict(status='resolved', at=moment),
                                                          at=moment))]
            answers = [future.result() for future in futures]
        self.assertEqual(answers[0][0], 200, answers[0][1])
        body = self.document(occurrence)
        self.assertEqual(body['measured']['status'], 'resolved')
        self.assertEqual(body['state'], 'source-resolved')
        self.assertEqual(body['disposition']['kind'], 'acknowledged')
        reports = self.deliver(until=moment)
        self.assertEqual([report['status'] for report in reports], ['sent'],
                         'whichever order won, an ack never folded the clear')

    def test_a_dismissal_racing_a_later_verdict_never_pages_the_closed_episode(self):
        """The fold and the later booking are concurrent; the tombstone is the tie-breaker."""
        occurrence = self.file(self.verdict('fixture.rule.one'))['incident_id']
        gate = threading.Barrier(2)

        def run(action):
            gate.wait(timeout=30)
            return action()

        moment = self.at(minutes=1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(run, lambda: self.dismiss(occurrence)),
                       pool.submit(run, lambda: self.file(self.verdict('fixture.rule.two', at=moment),
                                                          at=moment))]
            [future.result() for future in futures]
        self.assertEqual(self.document(occurrence)['state'], 'dismissed')
        self.deliver(until=self.at(minutes=5))
        self.assertEqual(len(self.provider.calls), 1,
                         'exactly one page went: the second episode is a different pair')


# ------------------------------------------------------------------- projections: downstream optional


class ProjectionTests(DispositionFixture):
    """A disposition is a fact about this database; the surfaces that learn it later may fail.

    The dispositions here are recorded through `dispositions` directly and every drain call carries the
    fixture's clock, because `available_at` is derived from the instant a disposition was recorded at: a test
    that mixed a transport-recorded disposition with an injected drain would be measuring the wall clock
    against a synthetic one. `test_the_transport_and_the_library_book_the_same_statements` is the case that
    pins the two entry points against each other.
    """

    def test_a_disposition_books_both_projections_without_calling_anything(self):
        occurrence = self.open_episode()
        self.record(occurrence, 'dismissed', 'not actionable')
        self.assertEqual({row['status'] for row in self.document(occurrence)['projections'].values()},
                         {'pending'})
        self.assertEqual(self.count('occurrence_projections'), 2)
        report = dispositions.drain(self.store, {}, now=self.now)
        self.assertEqual((report['attempted'], report['sent'], report['unconfigured'], report['failed']),
                         (2, 0, 2, 0))
        stored = self.document(occurrence)['projections']
        self.assertEqual({row['last_error'] for row in stored.values()}, {'not-configured'})
        self.assertEqual({row['attempts'] for row in stored.values()}, {1})
        self.assertEqual(self.document(occurrence)['state'], 'dismissed', 'and the action never moved')
        self.assertEqual(self.deliver(), [], 'a projection is not a page')

    def test_a_downstream_that_throws_leaves_the_disposition_and_its_silence_intact(self):
        occurrence = self.open_episode()
        self.record(occurrence)
        statements: list[dict] = []

        def broken(statement):
            statements.append(statement)
            raise ConnectionError('a body nobody may store: https://secret.invalid/token')

        report = dispositions.drain(self.store, {'telemetry-metric': broken,
                                                 'rule-card': lambda statement: True}, now=self.now)
        self.assertEqual((report['attempted'], report['sent'], report['failed']), (2, 1, 1))
        row = self.rows("SELECT status, attempts, last_error FROM occurrence_projections WHERE kind=?",
                        ('telemetry-metric',))[0]
        self.assertEqual((row['status'], row['attempts'], row['last_error']),
                         ('pending', 1, 'ConnectionError'), 'the class, never the message')
        self.assertEqual(len(statements), 1)
        self.assertEqual(statements[0]['kind'], 'acknowledged')
        self.assertEqual(statements[0]['projection'], 'telemetry-metric')
        self.assertEqual(self.deliver(), [])
        self.assertEqual(self.provider.calls, [])
        self.assertEqual(self.document(occurrence)['state'], 'acknowledged')

    def test_a_failing_downstream_is_bounded_work_and_backs_off(self):
        occurrence = self.open_episode()
        self.record(occurrence)
        sinks = {'telemetry-metric': lambda statement: (_ for _ in ()).throw(TimeoutError('slow')),
                 'rule-card': lambda statement: (_ for _ in ()).throw(TimeoutError('slow'))}
        dispositions.drain(self.store, sinks, now=self.now)
        self.assertEqual(dispositions.drain(self.store, sinks, now=self.at(seconds=1))['attempted'], 0,
                         'a record that just failed waits before its next attempt')
        self.assertEqual(dispositions.drain(self.store, sinks, now=self.at(seconds=3))['failed'], 2)
        self.assertEqual({row['attempts'] for row in self.document(occurrence)['projections'].values()}, {2})

    def test_a_drain_call_attempts_at_most_its_bound_and_the_rest_wait_for_the_next(self):
        occurrences = [self.open_episode(rule=f'fixture.rule.{number}') for number in range(4)]
        for occurrence in occurrences:
            self.record(occurrence)
        sinks = {'telemetry-metric': lambda statement: True, 'rule-card': lambda statement: True}
        report = dispositions.drain(self.store, sinks, now=self.now, limit=3)
        self.assertEqual((report['attempted'], report['sent'], report['pending']), (3, 3, 0))
        self.assertEqual(self.count('occurrence_projections', "status='pending'"), 5)
        dispositions.drain(self.store, sinks, now=self.now)
        self.assertEqual(self.count('occurrence_projections', "status='sent'"), 8)

    def test_a_sink_that_returns_a_refusal_is_recorded_as_one_and_a_later_success_closes_it(self):
        occurrence = self.open_episode()
        self.record(occurrence, 'dismissed')
        dispositions.drain(self.store, {'telemetry-metric': lambda statement: False,
                                        'rule-card': lambda statement: False}, now=self.now)
        self.assertEqual({row['last_error'] for row in self.document(occurrence)['projections'].values()},
                         {'refused'})
        dispositions.drain(self.store, {'telemetry-metric': lambda statement: True,
                                        'rule-card': lambda statement: True}, now=self.at(minutes=20))
        self.assertEqual({row['status'] for row in self.document(occurrence)['projections'].values()},
                         {'sent'})
        self.assertEqual(dispositions.drain(self.store, {}, now=self.at(minutes=30))['attempted'], 0)

    def test_a_restated_disposition_resets_the_projection_it_owes(self):
        occurrence = self.open_episode()
        self.record(occurrence, reason='first')
        dispositions.drain(self.store, {'telemetry-metric': lambda statement: (_ for _ in ()).throw(OSError()),
                                        'rule-card': lambda statement: True}, now=self.now)
        self.assertEqual(self.rows("SELECT attempts FROM occurrence_projections WHERE kind=?",
                                   ('telemetry-metric',))[0]['attempts'], 1)
        self.record(occurrence, reason='second')
        row = self.rows("SELECT attempts, status, payload FROM occurrence_projections WHERE kind=?",
                        ('telemetry-metric',))[0]
        self.assertEqual((row['attempts'], row['status']), (0, 'pending'),
                         'attempts count the failures of what is pending now')
        self.assertEqual(json.loads(row['payload'])['reason'], 'second')

    def test_no_disposition_means_no_projection_and_draining_an_empty_table_is_a_no_op(self):
        occurrence = self.open_episode()
        self.assertEqual(self.count('occurrence_projections'), 0)
        self.assertEqual(dispositions.drain(self.store, {}, now=self.now)['attempted'], 0)
        self.assertEqual({row['status'] for row in self.document(occurrence)['projections'].values()},
                         {'unconfigured'})

    def test_the_transport_and_the_library_book_the_same_statements(self):
        """A console POST and a host-side library call must owe the same two rows.

        The reason this matters is `lo-platform`'s own acknowledgement path: whichever door a disposition
        comes through, the downstream contract is the same, and a difference here would be a silent gap in
        what a metric consumer counts.
        """
        posted = self.open_episode(rule='fixture.rule.posted')
        self.assertEqual(self.ack(posted)[0], 200)
        recorded = self.open_episode(rule='fixture.rule.recorded')
        self.record(recorded, reason='recorded from the host')
        from_post = self.rows('SELECT kind, payload, status, attempts FROM occurrence_projections'
                              ' WHERE occurrence_id=? ORDER BY kind', (posted,))
        from_call = self.rows('SELECT kind, payload, status, attempts FROM occurrence_projections'
                              ' WHERE occurrence_id=? ORDER BY kind', (recorded,))
        self.assertEqual([row['kind'] for row in from_post], [row['kind'] for row in from_call])
        self.assertEqual([(row['status'], row['attempts']) for row in from_post],
                         [(row['status'], row['attempts']) for row in from_call])
        shape = [sorted(json.loads(row['payload'])) for row in from_post]
        self.assertEqual(shape, [sorted(json.loads(row['payload'])) for row in from_call])
        # `actor_role` (schema v15) travels with `actor`: a downstream that learns about a disposition from
        # this document would otherwise be told "an operator named X dismissed this" by a statement an
        # automated operator made — same effect to act on, different words to print.
        self.assertEqual(shape[0], ['actor', 'actor_role', 'at', 'condition_key', 'kind', 'occurrence_id',
                                    'projection', 'reason', 'resource_id'])
        self.assertNotIn('window', shape[0], 'a projection names the decision, never a verdict payload')


# ------------------------------------------------------------------ the ladder and the legacy reads


class EscalationLadderTests(DispositionFixture):
    """A disposition on the base episode holds the ladder; an independent condition does not."""

    def setUp(self):
        super().setUp()
        self.index_path = self.root / 'inventory.db'
        index.build({'schema_version': 1, 'resources': [{
            'id': self.resource_id('demo-host'), 'kind': 'host', 'name': 'demo-host',
            'aliases': [{'type': 'hostname', 'value': 'demo-host', 'scope': 'fixture'}],
            'attributes': {'environment': 'fixture', 'remediation_enabled': True}, 'relations': []},
            {'id': self.resource_id('demo-api'), 'kind': 'service', 'name': 'demo-api',
             'aliases': [{'type': 'service.name', 'value': 'demo-api', 'scope': 'fixture'}],
             'attributes': {'environment': 'fixture'}, 'relations': []}]},
            self.index_path, 'occurrence-fixture', now=NOW)
        self.cursor = self.root / 'escalation-cursor.json'
        self.chains = escalation.config(self.chains_at('escalation-chains.json', BASE_RULE))['chains']

    def chains_at(self, name: str, rule: str, *, interval: int = 300) -> Path:
        document = {'chains': [{'id': 'on-call', 'rule_id': rule, 'resource_id': None, 'stages': [
            {'interval_seconds': interval, 'severity_source': 'sigma', 'severity_tier': 'high'},
            {'interval_seconds': interval + 300, 'severity_source': 'sigma', 'severity_tier': 'critical'},
            {'interval_seconds': interval + 1200, 'severity_source': 'alertmanager',
             'severity_tier': 'error'}]}]}
        path = self.root / name
        path.write_text(json.dumps(document), encoding='utf-8')
        return path

    def round(self, at: dt.datetime, chains=None) -> dict:
        return escalation.tick(self.store, self.cursor, chains=chains or self.chains,
                               source=ESCALATION_SOURCE, now=at)

    def rungs(self) -> list[dict]:
        rows = [json.loads(row['payload']) for row in reversed(self.store.records('events'))]
        return [row for row in rows if row['rule_id'].startswith(BASE_RULE + '.stage')]

    def action_policy(self):
        rule = {'inspect': {'version': '1', 'parameters': {'type': 'object', 'properties': {},
                                                           'additionalProperties': False}}}
        return action_policy_module.action_policy(self.index_path, rule)

    def proposal(self, incident_id: str, event_id: str, resource: str) -> dict:
        return {'retry_key': 'occurrence-fixture', 'incident_id': incident_id, 'action': 'inspect',
                'version': '1', 'targets': [resource], 'parameters': {}, 'evidence': [event_id],
                'expires_at': utc_text(NOW + dt.timedelta(hours=1))}

    def base_event_id(self) -> str:
        return [row['id'] for row in self.store.records('events')
                if json.loads(row['payload'])['rule_id'] == BASE_RULE][0]

    def test_an_acknowledged_episode_never_gets_a_later_rung(self):
        occurrence = self.open_episode()
        self.assertEqual(self.round(self.at(minutes=1))['enrolled'], 1)
        self.assertEqual(self.ack(occurrence)[0], 200)
        for minutes in (5, 15, 45):
            self.assertEqual(self.round(self.at(minutes=minutes))['escalated'], 0)
        self.assertEqual(self.rungs(), [])
        rows = self.audit_rows('escalation.acknowledged')
        self.assertEqual(len(rows), 1, 'a held ladder is said once and not once per round')
        self.assertEqual(rows[0]['detail']['evidence'], OCCURRENCE_DISMISSAL_ACK_CAUSE)
        self.assertEqual(self.count('outbox', "status='pending'"), 0)

    def test_an_independent_episode_escalates_while_another_one_is_acknowledged(self):
        """Two episodes of one rule, one ladder: the acknowledgement says nothing about the other."""
        first = self.open_episode()
        second = self.open_episode(resource='demo-api')
        self.assertNotEqual(first, second)
        self.assertEqual(self.round(self.at(minutes=1))['enrolled'], 2)
        self.assertEqual(self.ack(first)[0], 200)
        advanced = self.round(self.at(minutes=5))
        self.assertEqual(advanced['escalated'], 1, 'the unacknowledged episode still owes its rung')
        self.assertEqual([row['rule_id'] for row in self.rungs()], [BASE_RULE + '.stage1'])
        rung = self.rungs()[0]
        self.assertEqual(rung['resource_id'], self.resource_id('demo-api'))
        self.assertEqual(self.deliver(until=self.at(minutes=5)) and len(self.provider.calls), 2)

    def test_a_dismissed_episode_holds_the_ladder_and_a_new_episode_climbs_it(self):
        occurrence = self.open_episode()
        self.round(self.at(minutes=1))
        self.assertEqual(self.dismiss(occurrence)[0], 200)
        self.assertEqual(self.round(self.at(minutes=5))['escalated'], 0)
        self.assertEqual(self.rungs(), [])
        self.assertEqual(self.audit_rows('escalation.acknowledged')[0]['detail']['evidence'],
                         OCCURRENCE_DISMISSAL_CAUSE)
        self.file(self.verdict(status='resolved', at=self.at(minutes=6)))
        self.assertEqual(self.round(self.at(minutes=7))['closed'], 1)
        fresh = self.file(self.verdict(at=self.at(minutes=8)))['incident_id']
        self.assertEqual(self.round(self.at(minutes=9))['enrolled'], 1)
        self.assertEqual(self.round(self.at(minutes=14))['escalated'], 1,
                         'the next episode climbs the ladder as if nobody had ever spoken')
        self.assertEqual([row['rule_id'] for row in self.rungs()], [BASE_RULE + '.stage1'])
        self.assertEqual(self.document(fresh)['state'], 'unacknowledged')

    def test_a_page_link_tap_is_not_an_acknowledgement_even_though_it_holds_the_ladder(self):
        """§6: a tap proves a message reached a surface, not that a named human gave a reason."""
        occurrence = self.open_episode()
        claimed = self.store.claim_notification(now=self.now)
        action = self.store.propose_action(self.proposal(occurrence, self.base_event_id(),
                                                         self.resource_id('demo-host')),
                                          PROPOSER, self.action_policy(), now=self.now)
        spent = self.store.record_callback(claimed['channel'], claimed['callback']['token'],
                                           action['action_id'], HUMAN, now=self.now)
        self.assertEqual(spent['status'], 'intent_recorded')
        body = self.document(occurrence)
        self.assertEqual(body['state'], 'unacknowledged', 'a tap wrote no disposition')
        self.assertIsNone(body['disposition'])
        self.assertEqual(body['legacy_evidence'], [escalation.ACK_INTENT])
        self.assertEqual(self.count('occurrence_disposition_history'), 0)
        self.assertEqual(self.count('occurrence_projections'), 0, 'and it owes no downstream statement')
        self.assertEqual(self.round(self.at(minutes=5))['escalated'], 0, 'the ladder still holds')
        self.assertEqual(self.ack(occurrence)[0], 200)
        body = self.document(occurrence)
        self.assertEqual(body['state'], 'acknowledged')
        self.assertIn(escalation.ACK_INTENT, body['legacy_evidence'], 'the tap is still visible')
        self.assertEqual(self.round(self.at(minutes=60))['escalated'], 0)

    def test_a_decided_action_is_legacy_evidence_and_not_a_disposition(self):
        occurrence = self.open_episode()
        action = self.store.propose_action(self.proposal(occurrence, self.base_event_id(),
                                                         self.resource_id('demo-host')),
                                          PROPOSER, self.action_policy(), now=self.now)
        self.store.decide(action['action_id'], 'approved', HUMAN, now=self.now)
        body = self.document(occurrence)
        self.assertEqual(body['state'], 'unacknowledged')
        self.assertEqual(body['legacy_evidence'], [escalation.ACK_DECISION])
        self.assertEqual(self.round(self.at(minutes=5))['escalated'], 0)

    def test_a_rung_s_own_episode_can_be_dismissed_without_touching_its_base(self):
        occurrence = self.open_episode()
        self.round(self.at(minutes=1))
        self.assertEqual(self.round(self.at(minutes=5))['escalated'], 1)
        rung = [row for row in self.store.records('incidents', 20) if row['id'] != occurrence][0]['id']
        self.assertEqual(self.dismiss(rung, reason='the repeat was noise')[0], 200)
        self.assertEqual(self.document(occurrence)['state'], 'unacknowledged',
                         'the base episode is untouched, and so is its next rung')
        self.assertEqual(self.round(self.at(minutes=15))['escalated'], 1)


if __name__ == '__main__':
    unittest.main()

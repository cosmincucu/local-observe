"""The optional authenticated review API over the observer journal: authority, bounds and no lost review.

`local_observe/platform/observer_review.py` is a seam between two owners that already exist: the bearer
credentials `platform/api.py` authenticates and the append-only `feedback` journal of
`observer/journal.py`. These tests are therefore about the four ways a seam like this goes wrong, and not
about the observer's investigation logic (that is `test_observer_runtime.py`):

* **authority** — every non-`human` role, a missing or wrong token, and a body that tries to name its own
  reviewer;
* **staleness** — a review submitted against a cycle whose digest or newest review has moved on, which
  must be refused *without* an append, while a byte-identical retry of an ID already held still returns
  the original receipt;
* **shape** — string/null/unknown/duplicate-key/oversized/undecodable bodies and query strings, refused
  before the journal is opened, in fixed words that never echo a path or the caller's bytes;
* **protected state** — a state directory whose journal is missing is a refusal, never an empty database
  this process created, and a review never rewrites the cycle it grades.

Fixture style follows `tests/test_api_errors.py` (real `Store`, the ASGI app called directly, no socket)
and `tests/test_observer_runtime.py` (a real `Journal` in a mode-0700 temporary directory). Every cycle
here is synthetic: nothing is derived from a real installation's telemetry, and no test invents a grade on
a cycle it did not write itself.
"""
from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from local_observe.observer.contract import digest, encoded, utc
from local_observe.observer.journal import Journal, REVIEWABLE_STATUSES
from local_observe.platform import observer_review, operator, operator_account
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Store

HUMAN_A = {'identity': 'operator-a', 'role': 'human', 'token': 'a' * 32}
HUMAN_B = {'identity': 'operator-b', 'role': 'human', 'token': 'b' * 32}
READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
PRODUCER = {'identity': 'test-detector', 'role': 'producer', 'token': 'p' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
EXECUTOR = {'identity': 'runner', 'role': 'executor', 'token': 'e' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
CREDENTIALS = [HUMAN_A, HUMAN_B, READER, PRODUCER, PROPOSER, EXECUTOR, SUMMARY]

START = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)
WINDOW = {'start': '2026-10-01T00:00:00Z', 'end': '2026-10-01T01:00:00Z'}
RESOURCE = '2b1c1b6a-5a4e-4b02-9d3f-7a1c2d3e4f50'
EVIDENCE_ID = 'e' * 64
#: Nested and non-scalar on purpose: a summary that quietly stringified labels, or a review form that
#: refused a tag list, would both be invisible with a flat `{'host': 'test'}` fixture.
NESTED_LABELS = {'host': {'role': 'test'}, 'tags': ['a', 'b']}
#: Shell- and markup-looking prose, because retained rationale is data: it must survive a replay as bytes
#: and must never be re-emitted inside a list row that a browser would interpret.
RATIONALE = 'rm -rf /srv && $(whoami) | <script>alert("quiet")</script> — no anomaly'
EVIDENCE = [{'schema_version': 1, 'source': 'example-metric', 'query_type': 'metric-threshold',
             'resource_id': RESOURCE, 'window': WINDOW, 'observed_at': WINDOW['start'],
             'rows': [{'timestamp': WINDOW['start'], 'value': 0.25, 'labels': NESTED_LABELS}],
             'metric_name': 'example_cpu', 'data_class': 'internal', 'coverage': 'complete',
             'evidence_id': EVIDENCE_ID}]
QUIET_ANSWER = {'schema_version': 1, 'decision': 'quiet', 'rationale': RATIONALE,
                'citations': [{'evidence_id': EVIDENCE_ID, 'row_index': 0, 'field': 'value', 'value': 0.25}],
                'follow_up': [], 'findings': []}
TELL_ANSWER = {'schema_version': 1, 'decision': 'tell', 'rationale': 'example-service is over threshold.',
               'citations': [{'evidence_id': EVIDENCE_ID, 'row_index': 0, 'field': 'value', 'value': 0.25}],
               'follow_up': [],
               'findings': [{'resource_id': RESOURCE, 'kind': 'threshold', 'observed_at': WINDOW['start'],
                             'evidence_ids': [EVIDENCE_ID]}]}
#: The exact keys a list row may carry. Anything more is review data leaking into a summary; anything
#: less is a row that cannot be read without a second request per cycle.
SUMMARY_KEYS = {'cycle_id', 'started_at', 'ended_at', 'status', 'coverage', 'decision', 'mode',
                'delivery_status', 'review', 'reviewable', 'findings', 'queue_reason',
                'latest_feedback_id'}


async def request(app, method: str, path: str, *, token: str | None = None, raw: bytes = b'',
                  query: bytes = b'', headers: list[tuple[bytes, bytes]] | None = None
                  ) -> tuple[int, dict]:
    """Drive one request through the ASGI app itself and return its status plus decoded body."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': raw, 'more_body': False}

    async def send(message):
        output.append(message)
    if headers is None:
        headers = [] if token is None else [(b'authorization', ('Bearer ' + token).encode())]
    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers,
               'query_string': query}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


def add_cycle(journal: Journal, cycle_id: str, *, minutes: int, status: str = 'completed',
              coverage: str = 'complete', decision: str | None = 'quiet', mode: str = 'recording',
              answer: dict | None = None, evidence: list | None = None) -> dict:
    """Commit one synthetic cycle through the journal's own `begin`/`save` pair, so its record shape is real."""
    started = START + dt.timedelta(minutes=minutes)
    document, created = journal.begin(cycle_id, started, dict(WINDOW), mode)
    assert created
    document.update(status=status, coverage=coverage, decision=decision, answer=answer,
                    evidence=EVIDENCE if evidence is None else evidence,
                    ended_at=None if status == 'running' else utc(started + dt.timedelta(minutes=5)))
    journal.save(document)
    return document


def submission(cycle_id: str, feedback_id: str, cycle_sha256: str, previous: str | None = None,
               **values) -> dict:
    """One well-formed review document; `values` defaults to a bare two-grade answer."""
    return {'cycle_id': cycle_id, 'feedback_id': feedback_id, 'cycle_sha256': cycle_sha256,
            'previous_feedback_id': previous,
            'values': {'usefulness': 'useful', 'correctness': 'correct', **values}}


class ReviewFixture(unittest.TestCase):
    """Shared protected-state, store and app plumbing for the review surface."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'observer'
        self.state.mkdir(mode=0o700)
        self.journal = Journal(self.state)
        self.addCleanup(self.journal.close)
        self.store = Store(self.root / 'state.db', NotificationPolicy(delivery_mode='off'))

    def app(self, state=None, credentials=CREDENTIALS):
        """Build the platform app with the review surface enabled over `self.state`."""
        return create_app(self.store, credentials, {},
                          observer_review=self.state if state is None else state)

    def get(self, path: str, *, token: str = HUMAN_A['token'], query: bytes = b'', app=None, **call):
        return asyncio.run(request(app or self.app(), 'GET', path, token=token, query=query, **call))

    def post(self, path: str, body, *, token: str = HUMAN_A['token'], app=None, query: bytes = b'',
             **call):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return asyncio.run(request(app or self.app(), 'POST', path, token=token, raw=raw, query=query,
                                   **call))

    def seeded(self) -> None:
        """Four cycles: a gradeable quiet result, a tell, a failed no-data run and one still running."""
        add_cycle(self.journal, 'quiet-1', minutes=0, answer=dict(QUIET_ANSWER))
        add_cycle(self.journal, 'tell-1', minutes=60, decision='tell', answer=dict(TELL_ANSWER))
        add_cycle(self.journal, 'failed-1', minutes=120, status='failed', coverage='failed', decision=None,
                  evidence=[])
        add_cycle(self.journal, 'running-1', minutes=180, status='running', coverage='unknown',
                  decision=None, evidence=[])

    def rows(self, **call) -> list[dict]:
        status, body = self.get(observer_review.CYCLES_ROUTE, **call)
        self.assertEqual(status, 200)
        return body['cycles']

    def feedback_count(self, cycle_id: str | None = None) -> int:
        sql = 'SELECT count(*) FROM feedback' if cycle_id is None else \
            'SELECT count(*) FROM feedback WHERE cycle_id=?'
        arguments = () if cycle_id is None else (cycle_id,)
        return self.journal.db.execute(sql, arguments).fetchone()[0]


class DisabledAndStartupTests(ReviewFixture):
    """Unconfigured is invisible; configured-but-unusable refuses to start and never creates state."""

    def test_routes_absent_without_configured_state(self):
        for method, path in (('GET', observer_review.CYCLES_ROUTE), ('GET', observer_review.CYCLE_ROUTE),
                             ('POST', observer_review.FEEDBACK_ROUTE)):
            status, body = asyncio.run(request(create_app(self.store, CREDENTIALS, {}), method, path,
                                               token=HUMAN_A['token'], query=b'cycle_id=quiet-1',
                                               raw=b'{}'))
            self.assertEqual((status, body), (404, {'error': 'not_found'}), path)

    def test_environment_unset_is_the_off_switch(self):
        self.assertIsNone(observer_review.state_path_from_environment({}))

    def test_blank_relative_or_missing_journal_refuses(self):
        empty = self.root / 'empty'
        empty.mkdir(mode=0o700)
        for value in ('', '   ', 'relative/observer', str(empty), str(self.root / 'nowhere')):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    observer_review.state_path_from_environment({observer_review.ENVIRONMENT: value})
                self.assertIn(observer_review.ENVIRONMENT, str(caught.exception))

    def test_existing_journal_is_accepted(self):
        found = observer_review.state_path_from_environment(
            {observer_review.ENVIRONMENT: str(self.state)})
        self.assertEqual(found, self.state)

    def test_app_construction_refuses_and_creates_no_journal(self):
        missing = self.root / 'nowhere'
        with self.assertRaises(ValueError):
            self.app(missing)
        self.assertFalse(missing.exists())
        untouched = self.root / 'empty'
        untouched.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.app(untouched)
        self.assertEqual(sorted(path.name for path in untouched.iterdir()), [])

    def test_blank_environment_value_is_refused_by_the_reader_app_factory_calls(self):
        # Only the environment read is exercised: no state file, no credential and no socket is opened.
        with mock.patch.dict(os.environ, {observer_review.ENVIRONMENT: ' '}, clear=True):
            with self.assertRaises(ValueError):
                observer_review.state_path_from_environment()


class AuthorityTests(ReviewFixture):
    """The credential decides who reviews. Nothing in a request body gets a vote."""

    def test_missing_wrong_and_duplicated_credentials_are_401(self):
        app = self.app()
        for headers in ([], [(b'authorization', b'Bearer not-a-token')],
                        [(b'authorization', ('Bearer ' + HUMAN_A['token']).encode())] * 2,
                        [(b'authorization', b'Basic Tm9uZTpOb25l')]):
            with self.subTest(headers=len(headers)):
                status, body = self.get(observer_review.CYCLES_ROUTE, app=app, token=None, headers=headers)
                self.assertEqual((status, body), (401, {'error': 'authentication_required'}))

    def test_non_human_roles_cannot_read_or_write(self):
        self.seeded()
        app = self.app()
        for credential in (READER, PRODUCER, PROPOSER, EXECUTOR):
            for path, query in ((observer_review.CYCLES_ROUTE, b''),
                                (observer_review.CYCLE_ROUTE, b'cycle_id=quiet-1')):
                status, body = self.get(path, token=credential['token'], app=app, query=query)
                with self.subTest(role=credential['role'], path=path):
                    self.assertEqual(status, 403)
                    self.assertEqual(body['error'], 'not_authorised')
            status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                     submission('quiet-1', 'x-1', '0' * 64),
                                     token=credential['token'], app=app)
            self.assertEqual((status, body['error']), (403, 'not_authorised'), credential['role'])
        self.assertEqual(self.feedback_count(), 0)

    def test_summary_role_keeps_its_own_fixed_answer(self):
        self.seeded()
        app = self.app()
        for method, path, query, raw in (('GET', observer_review.CYCLES_ROUTE, b'', b''),
                                        ('GET', observer_review.CYCLE_ROUTE, b'cycle_id=quiet-1', b''),
                                        ('POST', observer_review.FEEDBACK_ROUTE, b'', b'{}')):
            status, body = asyncio.run(request(app, method, path, token=SUMMARY['token'], raw=raw,
                                               query=query))
            with self.subTest(method=method, path=path):
                self.assertEqual((status, body), (403, {'error': 'summary_only'}))
        self.assertEqual(self.feedback_count(), 0)

    def test_human_may_read_and_write(self):
        self.seeded()
        self.assertEqual(self.get(observer_review.CYCLES_ROUTE, token=HUMAN_B['token'])[0], 200)
        cycle = self.journal.get('quiet-1')
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-1', digest(cycle)), token=HUMAN_B['token'])
        self.assertEqual(status, 200)
        self.assertEqual(body['feedback']['reviewer'], 'platform-human:operator-b')

    def test_a_password_login_reviews_as_the_human_credential_it_substitutes(self):
        # The operator shell turns a mounted password account into the human bearer this deployment already
        # configured, so the reviewer recorded is that credential's identity — not the username someone
        # typed, and not any name in the body.
        password = 'review-pass\u00e9'
        account = operator_account.make_account('alice', password)
        shell = operator.with_ui(self.app(credentials=[HUMAN_A]), account, HUMAN_A['token'])
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        basic = 'Basic ' + base64.b64encode(('alice:' + password).encode()).decode()
        status, body = self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1', cycle),
                                 app=shell, token=None, headers=[(b'authorization', basic.encode())])
        self.assertEqual(status, 200)
        self.assertEqual(body['feedback']['reviewer'], 'platform-human:operator-a')
        self.assertNotIn('alice', json.dumps(body))
        self.assertEqual(self.journal.replay('quiet-1')['feedback'][0]['reviewer'],
                         'platform-human:operator-a')

    def test_an_unusable_mounted_identity_refuses_a_write_without_echoing_it(self):
        self.seeded()
        # `validate_credentials` accepts any identity string, so a mounted human row can name something
        # the journal cannot retain as a reviewer. Reads keep working; the append refuses with the fixed
        # state answer and never quotes the identity it would have written.
        broken = [{**HUMAN_A, 'identity': 'operator a'}]
        app = self.app(credentials=broken)
        self.assertEqual(self.get(observer_review.CYCLES_ROUTE, app=app)[0], 200)
        cycle = digest(self.journal.get('quiet-1'))
        status, body = self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1', cycle),
                                 app=app)
        self.assertEqual((status, body), (503, {'error': 'observer_state_unavailable'}))
        self.assertNotIn('operator', json.dumps(body))
        self.assertEqual(self.feedback_count(), 0)

    def test_body_supplied_identity_is_refused_and_records_nothing(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        for extra in ({'reviewer': 'os-uid:0'}, {'identity': 'operator-b'}, {'role': 'human'},
                      {'actor': 'telegram-user:1'}, {'values': 'useful'},
                      {'values': {'usefulness': 'useful', 'correctness': 'correct', 'reviewer': 'x'}}):
            body = {**submission('quiet-1', 'review-x', cycle), **extra}
            status, answer = self.post(observer_review.FEEDBACK_ROUTE, body)
            with self.subTest(extra=sorted(extra)):
                self.assertEqual(status, 400)
                self.assertEqual(answer, {'error': 'invalid_request', 'detail': 'invalid_fields'})
        self.assertEqual(self.feedback_count(), 0)


class CycleListTests(ReviewFixture):
    """A page of newest-first summaries that names quiet, failed, in-flight and unreviewed work as such."""

    def test_page_covers_every_cycle_and_labels_it(self):
        self.seeded()
        status, body = self.get(observer_review.CYCLES_ROUTE)
        self.assertEqual(status, 200)
        self.assertEqual([row['cycle_id'] for row in body['cycles']],
                         ['running-1', 'failed-1', 'tell-1', 'quiet-1'])
        self.assertEqual([row['review'] for row in body['cycles']], ['unknown'] * 4)
        self.assertEqual([row['reviewable'] for row in body['cycles']],
                         [False, True, True, True])
        self.assertEqual([row['queue_reason'] for row in body['cycles']],
                         [None, observer_review.FINDING_OR_GAP, observer_review.FINDING_OR_GAP,
                          observer_review.QUIET_SAMPLE])
        self.assertEqual([row['findings'] for row in body['cycles']], [0, 0, 1, 0])
        self.assertEqual([row['mode'] for row in body['cycles']], ['recording'] * 4)
        self.assertEqual([row['delivery_status'] for row in body['cycles']], ['not_attempted'] * 4)
        self.assertEqual((body['limit'], body['returned'], body['total_cycles'], body['truncated'],
                          body['next_after']), (100, 4, 4, False, None))

    def test_empty_journal_is_an_honest_empty_page(self):
        status, body = self.get(observer_review.CYCLES_ROUTE)
        self.assertEqual(status, 200)
        self.assertEqual(body, {'schema_version': 1, 'cycles': [], 'limit': 100, 'returned': 0,
                               'total_cycles': 0, 'truncated': False, 'next_after': None})

    def test_page_is_bounded_and_states_its_truncation(self):
        for minute in range(12):
            add_cycle(self.journal, f'quiet-{minute:02d}', minutes=minute, answer=dict(QUIET_ANSWER))
        status, body = self.get(observer_review.CYCLES_ROUTE, query=b'limit=5')
        self.assertEqual((body['limit'], body['returned'], body['total_cycles']), (5, 5, 12))
        self.assertTrue(body['truncated'])
        self.assertEqual(body['next_after'], 'quiet-07')
        status, second = self.get(observer_review.CYCLES_ROUTE, query=b'limit=5&after=quiet-07')
        self.assertEqual([row['cycle_id'] for row in second['cycles']],
                         ['quiet-06', 'quiet-05', 'quiet-04', 'quiet-03', 'quiet-02'])
        self.assertTrue(second['truncated'])
        status, last = self.get(observer_review.CYCLES_ROUTE, query=b'limit=5&after=quiet-02')
        self.assertEqual([row['cycle_id'] for row in last['cycles']],
                         ['quiet-01', 'quiet-00'])
        self.assertFalse(last['truncated'])
        self.assertIsNone(last['next_after'])

    def test_page_cannot_exceed_one_hundred(self):
        self.seeded()
        for query in (b'limit=101', b'limit=0', b'limit=-1', b'limit=abc', b'limit=01', b'limit=1&limit=2',
                      b'limit=1&after=', b'unknown=1', b'after=', b'after=' + b'x' * 200,
                      b'cycle_id=quiet-1', b'&', b'=1', b'limit=' + b'9' * 300,
                      b'limit=\xc3\xa9'):
            status, body = self.get(observer_review.CYCLES_ROUTE, query=query)
            with self.subTest(query=query):
                self.assertEqual(status, 400)
                self.assertEqual(body['error'], 'invalid_request')
                self.assertNotIn(str(self.state), json.dumps(body))
        # A cursor that names no retained cycle is not a malformed request: it is an answer about state,
        # and an empty page would be indistinguishable from a journal with nothing in it.
        status, body = self.get(observer_review.CYCLES_ROUTE, query=b'after=not-a-cycle')
        self.assertEqual((status, body), (404, {'error': 'not_found'}))

    def test_summaries_carry_no_review_data_no_grade_and_no_path(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        self.post(observer_review.FEEDBACK_ROUTE,
                  submission('quiet-1', 'review-1', cycle, corrected_answer='A human correction.'))
        rows = self.rows()
        body = json.dumps(rows)
        for forbidden in (RATIONALE, 'correctness', 'usefulness', 'corrected_answer', 'A human correction',
                          'evidence', 'labels', 'example_cpu', 'citations', 'rationale', str(self.state),
                          'observer.sqlite3'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, body)
        for row in rows:
            self.assertEqual(set(row), SUMMARY_KEYS)
        quiet = [row for row in rows if row['cycle_id'] == 'quiet-1'][0]
        # The newest review's ID is the one review fact a summary may carry: it is what a form echoes back
        # as `previous_feedback_id`, and it names no grade, no correction and no evidence.
        self.assertEqual((quiet['review'], quiet['latest_feedback_id']), ('reviewed', 'review-1'))

    def test_unreviewed_quiet_is_never_reported_as_correct(self):
        self.seeded()
        status, detail = self.get(observer_review.CYCLE_ROUTE, query=b'cycle_id=quiet-1')
        self.assertEqual(status, 200)
        self.assertEqual(detail['replay']['review'], 'unknown')
        self.assertEqual(detail['replay']['feedback'], [])
        self.assertEqual(detail['latest_feedback_id'], None)
        self.assertEqual([row['review'] for row in self.rows()], ['unknown'] * 4)
        for row in self.rows():
            self.assertIn(row['review'], ('unknown', 'reviewed'))
            # Nothing a summary says may read as a verdict: `unknown` is the journal's own word for
            # "nobody has graded this", and no field of a quiet, unanswered row carries a grade word.
            for value in (row['review'], row['status'], row['coverage'], row['decision'],
                          row['mode'], row['delivery_status'], row['queue_reason']):
                self.assertNotIn('correct', str(value))


class CycleDetailTests(ReviewFixture):
    """One cycle: the retained replay, the digest a form must echo, and the newest review ID."""

    def test_replay_retains_nested_labels_and_script_like_rationale_unchanged(self):
        self.seeded()
        status, body = self.get(observer_review.CYCLE_ROUTE, query=b'cycle_id=quiet-1')
        self.assertEqual(status, 200)
        replay = body['replay']
        self.assertEqual(replay['evidence'][0]['rows'][0]['labels'], NESTED_LABELS)
        self.assertEqual(replay['answer']['rationale'], RATIONALE)
        self.assertEqual(body['cycle_sha256'], digest(self.journal.get('quiet-1')))
        self.assertTrue(body['reviewable'])
        self.assertEqual(body['schema_version'], 1)

    def test_latest_feedback_id_is_the_newest_of_several_reviews(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1', cycle, None))
        self.post(observer_review.FEEDBACK_ROUTE,
                  submission('quiet-1', 'review-2', cycle, 'review-1', correctness='unsure'))
        status, body = self.get(observer_review.CYCLE_ROUTE, query=b'cycle_id=quiet-1')
        self.assertEqual(status, 200)
        self.assertEqual(body['latest_feedback_id'], 'review-2')
        self.assertEqual([item['feedback_id'] for item in body['replay']['feedback']],
                         ['review-1', 'review-2'])
        self.assertEqual(body['replay']['review'], 'reviewed')

    def test_running_cycle_is_returned_and_marked_not_reviewable(self):
        self.seeded()
        status, body = self.get(observer_review.CYCLE_ROUTE, query=b'cycle_id=running-1')
        self.assertEqual(status, 200)
        self.assertFalse(body['reviewable'])
        self.assertEqual(body['replay']['status'], 'running')
        self.assertEqual(body['cycle_sha256'], digest(self.journal.get('running-1')))

    def test_query_bounds_and_unknown_cycle(self):
        self.seeded()
        for query, expected in ((b'', 'cycle_id_required'), (b'cycle_id=', 'invalid_query'),
                                (b'cycle_id=quiet-1&cycle_id=quiet-1', 'invalid_query'),
                                (b'cycle_id=quiet-1&limit=1', 'invalid_query'),
                                # An unknown name is a malformed query; no parameter at all is a missing
                                # one, and a caller can only act on the right one of those two.
                                (b'limit=1', 'invalid_query'),
                                (b'cycle_id=bad/id', 'invalid_identifier'),
                                (b'cycle_id=' + b'x' * 90, 'invalid_identifier'),
                                (b'cycle_id=' + b'\xff\xfe', 'invalid_query')):
            status, body = self.get(observer_review.CYCLE_ROUTE, query=query)
            with self.subTest(query=query):
                self.assertEqual(status, 400)
                self.assertEqual(body, {'error': 'invalid_request', 'detail': expected})
        status, body = self.get(observer_review.CYCLE_ROUTE, query=b'cycle_id=no-such-cycle')
        self.assertEqual((status, body), (404, {'error': 'not_found'}))

    def test_owned_path_with_the_wrong_method_is_405(self):
        self.seeded()
        status, body = self.get(observer_review.FEEDBACK_ROUTE, query=b'')
        self.assertEqual((status, body), (405, {'error': 'method_not_allowed'}))
        status, body = self.post(observer_review.CYCLES_ROUTE, b'{}')
        self.assertEqual((status, body), (405, {'error': 'method_not_allowed'}))


class FeedbackWriteTests(ReviewFixture):
    """Append-only, preconditioned, idempotent-by-content review writes through a human credential."""

    def test_no_cycle_record_is_rewritten_by_a_review(self):
        self.seeded()
        census = 'SELECT cycle_id, document FROM cycles ORDER BY rowid'
        before = encoded([tuple(row) for row in self.journal.db.execute(census).fetchall()])
        cycle = digest(self.journal.get('quiet-1'))
        self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1', cycle))
        # Byte for byte: a review appends to `feedback` and writes nothing else. Delivery state, schema
        # version, coverage and the retained answer all keep the bytes the observer committed, and no
        # review here can make an unapproved example eligible for export.
        self.assertEqual(encoded([tuple(row) for row in self.journal.db.execute(census).fetchall()]),
                         before)
        self.assertEqual(self.journal.replay('quiet-1')['delivery'], {'status': 'not_attempted'})
        self.assertEqual(self.journal.replay('quiet-1')['schema_version'], 1)
        self.assertEqual(self.journal.examples(), [])

    def test_append_is_the_journal_append_with_the_authenticated_reviewer(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-1', cycle, None, review_seconds=90))
        self.assertEqual(status, 200)
        record = body['feedback']
        self.assertEqual((record['reviewer'], record['cycle_id'], record['feedback_id']),
                         ('platform-human:operator-a', 'quiet-1', 'review-1'))
        self.assertEqual(record['review_seconds'], 90)
        self.assertIs(record['export_approved'], False)
        self.assertIsNone(record['corrected_answer'])
        self.assertEqual(body['schema_version'], 1)
        self.assertEqual([item['reviewer'] for item in self.journal.replay('quiet-1')['feedback']],
                         ['platform-human:operator-a'])

    def test_two_humans_are_two_appends_and_neither_rewrites_the_other(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        self.assertEqual(self.post(observer_review.FEEDBACK_ROUTE,
                                   submission('quiet-1', 'review-1', cycle))[0], 200)
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-2', cycle, 'review-1'),
                                 token=HUMAN_B['token'])
        self.assertEqual(status, 200)
        self.assertEqual(body['feedback']['reviewer'], 'platform-human:operator-b')
        self.assertEqual(self.feedback_count('quiet-1'), 2)

    def test_stale_form_is_refused_and_appends_nothing(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1', cycle))
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-2', cycle, None, correctness='incorrect'),
                                 token=HUMAN_B['token'])
        self.assertEqual((status, body), (409, {'error': 'conflict', 'detail': 'stale_review'}))
        self.assertEqual(self.feedback_count('quiet-1'), 1)
        # The same form, reopened against the state the operator can actually see, is accepted.
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-2', cycle, 'review-1',
                                            correctness='incorrect'), token=HUMAN_B['token'])
        self.assertEqual(status, 200)
        self.assertEqual(self.feedback_count('quiet-1'), 2)

    def test_changed_cycle_digest_is_refused_and_appends_nothing(self):
        self.seeded()
        other = digest(self.journal.get('tell-1'))
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-1', other))
        self.assertEqual((status, body), (409, {'error': 'conflict', 'detail': 'cycle_digest_changed'}))
        self.assertEqual(self.feedback_count(), 0)
        for bad in ('0' * 63, '0' * 65, 'A' * 64, 'not-a-digest', 12345, None, ['x' * 64]):
            status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                     submission('quiet-1', 'review-1', bad))
            with self.subTest(bad=repr(bad)):
                self.assertEqual((status, body), (400, {'error': 'invalid_request',
                                                       'detail': 'invalid_cycle_digest'}))
        self.assertEqual(self.feedback_count(), 0)

    def test_same_id_retry_returns_the_original_receipt_even_after_a_later_append(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        original = self.post(observer_review.FEEDBACK_ROUTE,
                             submission('quiet-1', 'review-1', cycle))[1]['feedback']
        self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-2', cycle, 'review-1'),
                  token=HUMAN_B['token'])
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-1', cycle))
        self.assertEqual(status, 200)
        self.assertEqual(body['feedback'], original)
        self.assertEqual(self.feedback_count('quiet-1'), 2)

    def test_changed_contents_or_identity_under_a_used_id_is_refused(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1', cycle))
        attempts = (
            ('a different grade', submission('quiet-1', 'review-1', cycle, None, correctness='incorrect'),
             HUMAN_A['token']),
            ('a different correction',
             submission('quiet-1', 'review-1', cycle, None,
                        corrected_answer='Something else entirely.', export_approved=False),
             HUMAN_A['token']),
            ('the same contents from another human', submission('quiet-1', 'review-1', cycle),
             HUMAN_B['token']),
            ('a different cycle', submission('tell-1', 'review-1', digest(self.journal.get('tell-1'))),
             HUMAN_A['token']))
        for label, body, token in attempts:
            with self.subTest(case=label):
                status, answer = self.post(observer_review.FEEDBACK_ROUTE, body, token=token)
                self.assertEqual((status, answer), (409, {'error': 'conflict',
                                                         'detail': 'feedback_id_reused'}))
        self.assertEqual(self.feedback_count(), 1)
        self.assertEqual(self.journal.replay('quiet-1')['feedback'][0]['reviewer'],
                         'platform-human:operator-a')

    def test_running_and_unknown_cycles_are_refused_without_an_append(self):
        self.seeded()
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('running-1', 'review-1', digest(self.journal.get('running-1'))))
        self.assertEqual((status, body), (409, {'error': 'conflict', 'detail': 'cycle_not_reviewable'}))
        status, body = self.post(observer_review.FEEDBACK_ROUTE, submission('no-such-cycle', 'review-1',
                                                                          '0' * 64))
        self.assertEqual((status, body), (404, {'error': 'not_found'}))
        self.assertEqual(self.feedback_count(), 0)

    def test_failed_no_data_cycle_is_reviewable_but_not_exportable(self):
        self.seeded()
        cycle = digest(self.journal.get('failed-1'))
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('failed-1', 'review-1', cycle, None, usefulness='unsure',
                                            correctness='unsure'))
        self.assertEqual(status, 200)
        self.assertEqual(body['feedback']['correctness'], 'unsure')
        self.assertEqual(self.journal.examples(), [])
        for number, extra in enumerate(({'export_approved': True}, {'outcome_refs': [EVIDENCE_ID]},
                                        {'outcome_refs': 'evidence-not-a-list'})):
            status, answer = self.post(observer_review.FEEDBACK_ROUTE,
                                       submission('failed-1', f'review-extra-{number}', cycle, 'review-1',
                                                  **extra))
            with self.subTest(extra=sorted(extra)):
                self.assertEqual(status, 400)
                self.assertIn(answer['detail'], observer_review.FEEDBACK_REQUEST_CODES)
        self.assertEqual(self.feedback_count('failed-1'), 1)

    def test_malformed_bodies_are_refused_before_the_journal_is_touched(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        whole = json.dumps(submission('quiet-1', 'review-1', cycle)).encode()
        cases = [('empty body', b''), ('truncated object', b'{"cycle_id": "quiet-1"'),
                 ('array body', b'[1, 2]'), ('scalar body', b'"useful"'), ('null body', b'null'),
                 ('not json', b'not json at all'),
                 # Two spellings of one key: a plain `json.loads` keeps the last and never says so, so this
                 # surface refuses rather than grade a cycle the caller did not name first.
                 ('duplicate keys', b'{"cycle_id":"quiet-1","cycle_id":"tell-1","feedback_id":"review-1",'
                                   b'"cycle_sha256":"' + cycle.encode() + b'","previous_feedback_id":null,'
                                   b'"values":{"usefulness":"useful","correctness":"correct"}}'),
                 ('invalid utf-8', b'\xff\xfe' + whole),
                 ('oversized', b'{"a":"' + b'x' * 70000 + b'"}')]
        for label, raw in cases:
            with self.subTest(case=label):
                status, body = self.post(observer_review.FEEDBACK_ROUTE, raw)
                self.assertIn(status, (400, 413))
                self.assertNotEqual(status, 500)
                self.assertNotIn(str(self.state), json.dumps(body))
        self.assertEqual(self.feedback_count(), 0)

    def test_query_on_a_submission_is_refused(self):
        self.seeded()
        cycle = digest(self.journal.get('quiet-1'))
        status, body = self.post(observer_review.FEEDBACK_ROUTE,
                                 submission('quiet-1', 'review-1', cycle),
                                 query=b'cycle_id=quiet-1')
        self.assertEqual((status, body), (400, {'error': 'invalid_request', 'detail': 'invalid_query'}))
        self.assertEqual(self.feedback_count(), 0)


class JournalSeamTests(ReviewFixture):
    """The CLI's defaults and the shared reviewability rule, guarded where the API borrows them."""

    def test_reviewable_statuses_cannot_drift_from_the_journal(self):
        self.assertEqual(observer_review.REVIEWABLE, REVIEWABLE_STATUSES)

    def test_cli_defaults_stay_os_derived_and_precondition_free(self):
        self.seeded()
        first = self.journal.feedback('quiet-1', 'review-1', {'usefulness': 'useful',
                                                             'correctness': 'correct'})
        self.assertEqual(first['reviewer'], f'os-uid:{os.getuid()}')
        second = self.journal.feedback('quiet-1', 'review-2', {'usefulness': 'noise',
                                                              'correctness': 'unsure'})
        self.assertEqual(second['reviewer'], first['reviewer'])
        self.assertEqual(self.journal.feedback('quiet-1', 'review-1',
                                               {'usefulness': 'useful', 'correctness': 'correct'}), first)
        with self.assertRaises(Exception) as changed:
            self.journal.feedback('quiet-1', 'review-1', {'usefulness': 'noise', 'correctness': 'correct'})
        self.assertEqual(str(changed.exception), 'feedback_id_reused')

    def test_explicit_preconditions_are_journal_decisions_not_api_only(self):
        self.seeded()
        cycle = self.journal.get('quiet-1')
        with self.assertRaises(Exception) as stale:
            self.journal.feedback('quiet-1', 'review-1', {'usefulness': 'useful', 'correctness': 'correct'},
                                  reviewer='platform-human:operator-a', previous_feedback_id='not-there')
        self.assertEqual(str(stale.exception), 'stale_review')
        with self.assertRaises(Exception) as wrong_digest:
            self.journal.feedback('quiet-1', 'review-1', {'usefulness': 'useful', 'correctness': 'correct'},
                                  reviewer='platform-human:operator-a', cycle_sha256='0' * 64)
        self.assertEqual(str(wrong_digest.exception), 'cycle_digest_changed')
        with self.assertRaises(Exception) as bad_reviewer:
            self.journal.feedback('quiet-1', 'review-1', {'usefulness': 'useful', 'correctness': 'correct'},
                                  reviewer='os-uid:operator-a')
        self.assertEqual(str(bad_reviewer.exception), 'invalid_reviewer')
        self.assertEqual(self.feedback_count(), 0)
        self.journal.feedback('quiet-1', 'review-1', {'usefulness': 'useful', 'correctness': 'correct'},
                              reviewer='platform-human:operator-a', cycle_sha256=digest(cycle),
                              previous_feedback_id=None)
        self.assertEqual(self.feedback_count(), 1)


class ProtectedStateTests(ReviewFixture):
    """A journal that disappears after startup is a refusal, and is never reopened as an empty database."""

    def test_missing_journal_is_a_fixed_refusal_and_is_not_recreated(self):
        self.seeded()
        app = self.app()
        self.assertEqual(self.get(observer_review.CYCLES_ROUTE, app=app)[0], 200)
        for name in ('observer.sqlite3', 'observer.sqlite3-wal', 'observer.sqlite3-shm',
                     'observer.sqlite3-journal'):
            (self.state / name).unlink(missing_ok=True)
        status, body = self.get(observer_review.CYCLES_ROUTE, app=app)
        self.assertEqual((status, body), (503, {'error': 'observer_state_unavailable'}))
        self.assertFalse((self.state / 'observer.sqlite3').exists())
        status, body = self.post(observer_review.FEEDBACK_ROUTE, submission('quiet-1', 'review-1',
                                                                          '0' * 64), app=app)
        self.assertEqual((status, body), (503, {'error': 'observer_state_unavailable'}))
        self.assertFalse((self.state / 'observer.sqlite3').exists())

    def test_unreadable_journal_is_the_same_fixed_refusal(self):
        self.seeded()
        app = self.app()
        (self.state / 'observer.sqlite3').write_bytes(b'not a database at all')
        # A well-formed submission, so the refusal is the state's and not the body's: a malformed body is
        # answered by the parser without the journal being opened at all (see the malformed-body tests).
        well_formed = json.dumps(submission('quiet-1', 'review-1', '0' * 64)).encode()
        for method, path, query, raw in (
                ('GET', observer_review.CYCLES_ROUTE, b'', b''),
                ('GET', observer_review.CYCLE_ROUTE, b'cycle_id=quiet-1', b''),
                ('POST', observer_review.FEEDBACK_ROUTE, b'', well_formed)):
            status, body = asyncio.run(request(app, method, path, token=HUMAN_A['token'],
                                               query=query, raw=raw))
            with self.subTest(method=method, path=path):
                self.assertEqual((status, body), (503, {'error': 'observer_state_unavailable'}))


if __name__ == '__main__':
    unittest.main()

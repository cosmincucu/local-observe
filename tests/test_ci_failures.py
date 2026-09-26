"""CI failure ingestion (`local_observe/ci_failures`) — the CI failure ingestion section C in product form.

Everything here is offline: the two scoped transports are injected fakes that record calls, and the
integration tier patches `socket.socket` and `urllib.request.urlopen` to raise, so "no socket was
opened" is proved rather than asserted. What the fakes let this file test is the *real* object graph —
`build_service` is called with the same arguments a deployment uses, so a wiring defect (a board outlet
handed the GET-only Actions client, a pipeline that shares one credential across two scopes) fails
here instead of on a host.

The scenarios are the ones the card's review named as blockers on the previous draft:

* the Actions reader refuses an issue write, and the board client can scan, look up labels, create and
  comment;
* three failures across two SHAs produce exactly one card, a fourth comments on it;
* an interrupt at each delivery/checkpoint boundary retains the pending delivery, and reconciliation
  after the restart resolves it without a silent loss or a duplicate card;
* heartbeat is judged by a separate call, before a returning poller records a successful tick;
* malformed payloads are refused, and a missing or truncated log is coverage, not a diagnosis.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import logging
import re
import socket
import sys
import tempfile
import unittest
import urllib.request

from local_observe.ci_failures import (ActionsSource, BoardClient, BoardOutlet, CiFailureError,
                                       CiFailureStore, MalformedSource, OutletConfig, PaginationBudget,
                                       Pipeline, PipelineConfig, PlatformAdmission, ScopeRefused,
                                       SourceUnavailable, Thresholds, admission_ready, build_events,
                                       build_service, card_identity, environment_config, parse_run)
from local_observe.ci_failures.adapter import RULE_COVERAGE, RULE_FAILURE, SOURCE
from local_observe.ci_failures.facts import MAX_JOBS, CoverageNote, event_identity, is_failure, \
    parse_run_path, plane_of
from local_observe.ci_failures.transports import MAX_JOBS_PER_RUN
from local_observe.ci_failures.facts import scrub_excerpt
from local_observe.ci_failures.outlet import OWNED_MARKER, batch_token, fingerprint_of_body
from local_observe.ci_failures.pipeline import COVERAGE_SOURCE
from local_observe.ci_failures.store import STATE_DELIVERED
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.state import validate_event

REPO = 'acme/widgets'
OWNER, NAME = 'acme', 'widgets'
ACTIONS_TOKEN = 'actions-token-' + ('a' * 40)
BOARD_TOKEN = 'board-token-' + ('b' * 40)
T0 = dt.datetime(2026, 9, 22, 12, tzinfo=dt.timezone.utc)
SHA_A, SHA_B, SHA_C = 'a' * 40, 'b' * 40, 'c' * 40
BAD_EXCERPT = ("2026-09-22T11:50:01Z ##[error] /home/runner/work/acme/widgets/ci/test_suite.py:14: "
               "AssertionError in 12.5 s token: supersecretvalue1234567890abcdef commit 7f3a9c2b8d4e "
               "on http://runner.internal:8080/build/42")


def iso(moment: dt.datetime) -> str:
    return moment.isoformat().replace('+00:00', 'Z')


def job(job_id=501, name='build', conclusion='failure', status='completed', steps=None,
        failure_reason=None):
    if steps is None:
        steps = [{'name': 'checkout', 'status': 'completed', 'conclusion': 'success'},
                 {'name': 'unit tests', 'status': 'completed', 'conclusion': conclusion}]
    row = {'id': job_id, 'run_id': 1, 'name': name, 'status': status, 'conclusion': conclusion,
           'steps': steps}
    if failure_reason is not None:
        row['failure_reason'] = failure_reason
    return row


def run_payload(run_id, sha, *, branch='feature/one', event='pull_request', status='completed',
                conclusion='failure', workflow='ci', workflow_id='ci.yml', when=T0, nested_jobs=None,
                minutes=5):
    payload = {'id': run_id, 'name': workflow, 'workflow_id': workflow_id, 'head_branch': branch,
               'head_sha': sha, 'event': event, 'status': status, 'conclusion': conclusion,
               'created_at': iso(when - dt.timedelta(minutes=minutes)), 'updated_at': iso(when),
               'run_started_at': iso(when - dt.timedelta(minutes=minutes))}
    if conclusion == 'success':
        payload['conclusion'] = 'success'
    if nested_jobs is not None:
        payload['workflow_jobs'] = nested_jobs
    return payload


class ActionsFake:
    """A recording stand-in for the Actions API: pages, nested job arrays, and injected failures."""

    def __init__(self, *, runs=(), jobs=None, faults=None, log_text=None, log_status=200):
        self.runs = list(runs)
        self.jobs = dict(jobs or {})
        self.faults = dict(faults or {})
        self.calls: list[tuple[str, str, dict]] = []
        self.log_calls: list[str] = []
        self.log_text = log_text
        self.log_status = log_status
        self.token_seen: list[str] = []

    def log_reader(self, path):
        self.log_calls.append(path)
        return self.log_status, self.log_text

    def request(self, method, path, *, params=None, payload=None):
        assert method == 'GET', f'the Actions fake only ever receives GET: {method} {path}'
        assert payload is None, 'a read must not carry a body'
        self.calls.append((method, path, dict(params or {})))
        key = None
        if path.endswith('/actions/runs'):
            key = f'page:{int((params or {}).get("page", 1))}'
            if self.faults.get(key) == 'unavailable':
                raise SourceUnavailable('offline')
            if self.faults.get(key) == 'garbage':
                return 200, {'unexpected': 'shape'}
            per_page = int((params or {}).get('limit', (params or {}).get('per_page', 50)))
            page = int((params or {}).get('page', 1))
            ordered = sorted(self.runs, key=lambda row: -int(row['id']))
            rows = ordered[(page - 1) * per_page:page * per_page]
            return 200, {'total_count': len(ordered), 'workflow_runs': rows}
        match = re.search(r'/actions/runs/(\d+)/jobs$', path)
        if match:
            run_id = int(match.group(1))
            if self.faults.get(f'jobs:{run_id}') == 'unavailable':
                raise SourceUnavailable('offline')
            if self.faults.get(f'jobs:{run_id}') == 'garbage':
                return 200, {'jobs': 'not-a-list'}
            ordered = self.jobs.get(run_id, [])
            size = int((params or {}).get('limit', (params or {}).get('per_page', 50)))
            page = int((params or {}).get('page', 1))
            return 200, {'total_count': len(ordered), 'jobs': ordered[(page - 1) * size:page * size]}
        single = re.search(r'/actions/runs/(\d+)$', path)
        if single:
            run_id = int(single.group(1))
            if self.faults.get(f'run:{run_id}') == 'unavailable':
                raise SourceUnavailable('offline')
            if self.faults.get(f'run:{run_id}') == 'garbage':
                return 200, 'not-an-object'
            if self.faults.get(f'run:{run_id}') == 'other-run':
                return 200, dict(run_payload(run_id + 1, SHA_A))
            for row in self.runs:
                if int(row['id']) == run_id:
                    return 200, dict(row)
            return 404, {'message': 'not found'}
        if re.search(r'/actions/runs/\d+/jobs/\d+/logs$', path):
            return self.log_status, self.log_text
        raise AssertionError(f'unexpected Actions path {path}')


class StubTransport:
    """Returns one fixed answer, so a malformed response shape can be tested without a scenario."""

    def __init__(self, body, status=200):
        self.body, self.status = body, status
        self.calls: list[tuple[str, str]] = []

    def request(self, method, path, *, params=None, payload=None):
        self.calls.append((method, path))
        return self.status, self.body


class BoardFake:
    """The board side, with the exact failure modes a non-atomic remote write produces."""

    def __init__(self, *, issues=None, labels=None, comments=None, faults=None, next_number=101):
        self.issues = list(issues or [])
        self.labels = list(labels if labels is not None else
                          [{'id': 7, 'name': 'aiops'}, {'id': 8, 'name': 'audit-finding'},
                           {'id': 9, 'name': 'kanban/doing'}])
        self.comments = {int(key): list(value) for key, value in (comments or {}).items()}
        self.faults = set(faults or ())
        self.created: list[dict] = []
        self.posted: list[tuple[int, str]] = []
        self.calls: list[tuple[str, str]] = []
        self.next_number = next_number

    def request(self, method, path, *, params=None, payload=None):
        self.calls.append((method, path))
        if path.endswith('/actions/runs'):
            raise AssertionError('the board fake must never be asked for Actions data')
        if method == 'GET' and path.endswith('/issues'):
            if 'scan' in self.faults:
                raise SourceUnavailable('board offline')
            return 200, self.issues
        if method == 'GET' and path.endswith('/labels'):
            if 'labels' in self.faults:
                raise SourceUnavailable('board offline')
            return 200, self.labels
        if method == 'GET' and re.search(r'/issues/(\d+)/comments$', path):
            number = int(re.search(r'/issues/(\d+)/comments$', path).group(1))
            if 'comments-read' in self.faults:
                raise SourceUnavailable('board offline')
            return 200, self.comments.get(number, [])
        if method == 'POST' and path.endswith('/issues'):
            if 'create' in self.faults:
                return 500, None
            number = self.next_number
            self.next_number += 1
            self.created.append({'number': number, **dict(payload or {})})
            self.issues.append({'number': number, 'title': payload['title'], 'body': payload['body']})
            self.comments.setdefault(number, [])
            if 'create-ack-lost' in self.faults:
                self.faults.discard('create-ack-lost')
                raise SourceUnavailable('connection reset after the write landed')
            return 201, {'number': number, 'html_url': f'https://board.example/{REPO}/issues/{number}'}
        if method == 'POST' and re.search(r'/issues/(\d+)/comments$', path):
            number = int(re.search(r'/issues/(\d+)/comments$', path).group(1))
            if 'comment' in self.faults:
                return 500, None
            self.posted.append((number, str((payload or {}).get('body'))))
            self.comments.setdefault(number, []).append({'body': str((payload or {}).get('body'))})
            if 'comment-ack-lost' in self.faults:
                self.faults.discard('comment-ack-lost')
                raise SourceUnavailable('connection reset after the comment landed')
            return 201, {'id': 1}
        raise AssertionError(f'unexpected board call {method} {path}')


def config(**overrides) -> PipelineConfig:
    base = {'repository': REPO, 'file_cards': True}
    base.update(overrides)
    return PipelineConfig(**base)


def service(actions: ActionsFake, board: BoardFake | None, state: str, *,
            cfg: PipelineConfig | None = None, log_reader=None,
            admission: PlatformAdmission | None = None):
    return build_service(config=cfg or config(), state_path=state, actions_transport=actions,
                         board_transport=board, log_reader=log_reader, admission=admission)


class SocketGuard:
    """Fail the test loudly if any code path reaches the network stack."""

    def __enter__(self):
        self._socket, self._urlopen = socket.socket, urllib.request.urlopen
        socket.socket = _refused
        urllib.request.urlopen = _refused
        return self

    def __exit__(self, *exc_info):
        socket.socket, urllib.request.urlopen = self._socket, self._urlopen


def _refused(*args, **kwargs):
    raise AssertionError('a unit test opened the network')


class QueryRecorder:
    """A transport-shaped recorder used to pin `JsonTransport`'s query-string construction."""

    def __init__(self):
        self.path = None

    def request(self, method, path, *, params=None, payload=None):
        self.path = path
        return 200, []


class TransportScopeTests(unittest.TestCase):
    def setUp(self):
        self.actions = ActionsFake(runs=[run_payload(1, SHA_A)])
        self.board = BoardFake()

    def test_the_actions_reader_is_get_only_on_four_path_shapes(self):
        source = ActionsSource(self.actions, REPO)
        self.assertEqual(200, source.request('GET', f'/repos/{REPO}/actions/runs')[0])
        self.assertEqual(200, source.request('GET', f'/repos/{REPO}/actions/runs/1')[0])
        self.assertEqual(200, source.request('GET', f'/repos/{REPO}/actions/runs/7/jobs')[0])
        self.assertEqual(200, source.request('GET', f'/repos/{REPO}/actions/runs/7/jobs/9/logs')[0])
        for path in (f'/repos/{REPO}/issues', f'/repos/{REPO}/actions/runs/7/logs',
                     '/repos/other/thing/actions/runs', f'/repos/{REPO}/actions/workflows/ci.yml',
                     f'/repos/{REPO}/actions/runs/../issues', f'/repos/{REPO}/actions/runs/7/jobs/9/log'):
            with self.assertRaises(ScopeRefused, msg=path):
                source.request('GET', path)
        for method in ('POST', 'PATCH', 'PUT', 'DELETE'):
            with self.assertRaises(ScopeRefused, msg=method):
                source.request(method, f'/repos/{REPO}/issues')
            with self.assertRaises(ScopeRefused, msg=method):
                source.request(method, f'/repos/{REPO}/actions/runs')
        self.assertEqual([(call[0], call[1]) for call in self.actions.calls],
                         [('GET', f'/repos/{REPO}/actions/runs'),
                          ('GET', f'/repos/{REPO}/actions/runs/1'),
                          ('GET', f'/repos/{REPO}/actions/runs/7/jobs'),
                          ('GET', f'/repos/{REPO}/actions/runs/7/jobs/9/logs')])

    def test_the_single_run_read_answers_the_fourth_shape_and_nothing_else(self):
        """`/runs/{id}` is a real read with real bounds, not a pattern that happens to compile.

        It is the read the poller uses to ask about a run its page walk has left behind, so the shape
        must work while every neighbour of it stays refused: no `POST` to the same path, no id that is
        not a plain positive integer, no body that talks about a different run.
        """
        actions = ActionsFake(runs=[run_payload(7, SHA_A, status='queued', conclusion='')],
                              faults={'run:8': 'garbage', 'run:9': 'unavailable',
                                      'run:10': 'other-run'})
        source = ActionsSource(actions, REPO)
        self.assertEqual(7, source.run(7)['id'])
        self.assertEqual(7, source.run('7')['id'])
        self.assertEqual([(call[0], call[1]) for call in actions.calls],
                         [('GET', f'/repos/{REPO}/actions/runs/7'),
                          ('GET', f'/repos/{REPO}/actions/runs/7')])
        self.assertIsNone(source.run(11), 'a run the forge dropped is a 404, not an empty object')
        self.assertEqual(3, len(actions.calls))
        for value in ('7;DROP', '../7', '7.5', True, None, '-7', '0', '1 OR 1', 10 ** 30):
            with self.assertRaises(ScopeRefused, msg=repr(value)):
                source.run(value)
        with self.assertRaises(ScopeRefused):
            source.request('POST', f'/repos/{REPO}/actions/runs/7')
        self.assertEqual(3, len(actions.calls), 'a hostile id or method never reaches the transport')
        with self.assertRaises(MalformedSource):
            source.run(8)
        with self.assertRaises(SourceUnavailable):
            source.run(9)
        with self.assertRaises(ScopeRefused, msg='a detail page about another run is not this run'):
            source.run(10)
        self.assertEqual(6, len(actions.calls))

    def test_the_log_path_is_a_reader_path_and_a_log_becomes_text(self):
        source = ActionsSource(self.actions, REPO, log_reader=self.actions.log_reader)
        self.actions.log_text = 'step ran\n##[error] boom'
        read = source.job_log(7, 9)
        self.assertEqual('step ran\n##[error] boom', read.excerpt)
        self.assertIsNone(read.coverage)
        self.assertEqual([f'/repos/{REPO}/actions/runs/7/jobs/9/logs'], self.actions.log_calls)
        with self.assertRaises(ScopeRefused):
            source.request('GET', f'/repos/{REPO}/actions/runs/7/jobs/9/logs/extra')

    def test_the_board_client_holds_reads_and_exactly_two_writes(self):
        board = BoardClient(self.board, REPO)
        root = f'/repos/{REPO}'
        self.assertEqual(f'{root}/issues', board.allows('GET', f'{root}/issues'))
        self.assertEqual(f'{root}/labels', board.allows('GET', f'{root}/labels'))
        self.assertEqual(f'{root}/issues/4/comments', board.allows('GET', f'{root}/issues/4/comments'))
        self.assertEqual(f'{root}/issues', board.allows('POST', f'{root}/issues'))
        self.assertEqual(f'{root}/issues/4/comments', board.allows('POST', f'{root}/issues/4/comments'))
        for method, path in (('PATCH', f'{root}/issues/4'), ('PUT', f'{root}/issues/4'),
                             ('DELETE', f'{root}/issues/4/comments'), ('POST', f'{root}/labels'),
                             ('POST', f'{root}/issues/4/labels'), ('GET', f'{root}/actions/runs'),
                             ('POST', f'{root}/issues/4/assignees')):
            with self.assertRaises(ScopeRefused, msg=f'{method} {path}'):
                board.allows(method, path)

    def test_hostile_repository_and_path_values_are_refused_before_any_request(self):
        self.board.calls.clear()
        self.actions.calls.clear()
        for value in ('', 'acme', 'acme/widgets/extra', '../../etc/passwd', 'acme/..', '../widgets',
                      'acme/wid%2Fgets', 'acme/wid gets', 'ACME/WIDGETS ', 'acme/.', 'acme/wid\ngets',
                      f'{"a" * 100}/widgets', 'acme/wid#get', 'acme\\widgets', None, 7,
                      {'owner': 'acme'}):
            with self.assertRaises(CiFailureError, msg=repr(value)):
                ActionsSource(self.actions, value)
            with self.assertRaises(CiFailureError, msg=repr(value)):
                BoardClient(self.board, value)
        self.assertEqual([], self.actions.calls)
        self.assertEqual([], self.board.calls)

    def test_hostile_ids_never_reach_the_transport(self):
        source = ActionsSource(self.actions, REPO)
        for value in ('1;DROP', '../../1', '1.5', True, None, '-1', '0', '1 OR 1', 10 ** 30, 0):
            with self.assertRaises(CiFailureError, msg=repr(value)):
                source.jobs(value)
            with self.assertRaises(CiFailureError, msg=repr(value)):
                source.job_log(value, 5)
        board = BoardClient(self.board, REPO)
        for value in ('1;DROP', '../../1', True, None, '0', '-3'):
            with self.assertRaises(CiFailureError, msg=repr(value)):
                board.comment(value, 'body')
        self.assertEqual([], self.actions.calls)
        self.assertEqual([], self.board.calls)

    def test_query_values_are_bounded_scalars(self):
        from local_observe.ci_failures.transports import JsonTransport

        recorder = QueryRecorder()
        transport = JsonTransport(recorder)
        self.assertEqual(200, transport.request('GET', f'/repos/{REPO}/actions/runs',
                                                params={'page': 2, 'state': 'open'})[0])
        self.assertEqual(f'/repos/{REPO}/actions/runs?page=2&state=open', recorder.path)
        for params in ({'page': 'a b'}, {'page': 'x&y=z'}, {'PaGe': 1}, {'page': [1]}, {'page': True}):
            with self.assertRaises(CiFailureError, msg=str(params)):
                transport.request('GET', f'/repos/{REPO}/actions/runs', params=params)

    def test_an_error_status_is_an_outage_not_a_page_of_data(self):
        actions = ActionsFake(runs=[run_payload(1, SHA_A)], faults={'page:1': 'unavailable'})
        source = ActionsSource(actions, REPO)
        with self.assertRaises(SourceUnavailable):
            source.runs(page=1)


class ParsingTests(unittest.TestCase):
    def test_nested_run_and_job_arrays_parse(self):
        fact = parse_run(REPO, run_payload(11, SHA_A, nested_jobs=[job(501)]))
        self.assertEqual(('build',), tuple(job.name for job in fact.jobs))
        self.assertEqual('unit tests', fact.first_failing_step())
        self.assertEqual('pull', fact.plane)
        self.assertTrue(fact.is_failure)
        self.assertEqual('failure', fact.failure_class())
        self.assertTrue(is_failure('completed', 'cancelled'))
        self.assertFalse(is_failure('waiting', ''))

    def test_malformed_and_missing_field_payloads_are_refused_by_name(self):
        broken = {
            'no id': {'status': 'completed', 'conclusion': 'failure', 'head_sha': SHA_A},
            'string id': dict(run_payload(1, SHA_A), id='seven'),
            'missing sha': {'id': 3, 'status': 'completed', 'conclusion': 'failure'},
            'non-hex sha': dict(run_payload(1, SHA_A), head_sha='zzzz'),
            'unknown status': dict(run_payload(1, SHA_A), status='exploded'),
            'unknown conclusion': dict(run_payload(1, SHA_A), conclusion='maybe'),
            'completed without conclusion': dict(run_payload(1, SHA_A), conclusion=''),
            'jobs not a list': dict(run_payload(1, SHA_A), workflow_jobs='nope'),
            'job without id': dict(run_payload(1, SHA_A), workflow_jobs=[{'name': 'build'}]),
            'bad timestamp': dict(run_payload(1, SHA_A), created_at='yesterday'),
            'control character name': dict(run_payload(1, SHA_A), name='ci\nbad'),
            'payload is a list': [run_payload(1, SHA_A)],
            'payload is text': 'hello',
        }
        for label, payload in broken.items():
            with self.subTest(label):
                with self.assertRaises(MalformedSource, msg=label):
                    parse_run(REPO, payload)

    def test_missing_job_list_and_log_are_coverage_not_a_verdict(self):
        fact = parse_run(REPO, run_payload(12, SHA_A))
        self.assertIn('job-list-absent', fact.coverage_reasons())
        self.assertIn('job-log-absent', fact.coverage_reasons())
        self.assertIsNone(fact.excerpt)
        identity = card_identity(fact)
        self.assertTrue(identity.coarse)
        self.assertIn('error-excerpt-absent', identity.reasons)
        self.assertIn('job-log-absent', '\n'.join(note.line() for note in fact.coverage))

    def test_truncated_log_is_coverage_and_keeps_the_tail(self):
        source = ActionsSource(ActionsFake(), REPO,
                               log_reader=lambda path: (200, 'x' * 9000))
        read = source.job_log(1, 2)
        self.assertTrue(read.truncated)
        self.assertEqual('job-log-truncated', read.coverage)
        self.assertEqual(4096, len(read.excerpt or ''))
        unwired = ActionsSource(ActionsFake(), REPO).job_log(1, 2)
        self.assertIsNone(unwired.excerpt)
        self.assertEqual('job-logs-not-wired', unwired.coverage)
        empty = ActionsSource(ActionsFake(), REPO, log_reader=lambda path: (200, '   ')).job_log(1, 2)
        self.assertEqual('job-log-empty', empty.coverage)
        gone = ActionsSource(ActionsFake(), REPO, log_reader=lambda path: (410, None)).job_log(1, 2)
        self.assertEqual('job-log-status-410', gone.coverage)

    def test_a_page_shorter_than_the_page_size_ends_the_walk(self):
        runs = [run_payload(number, SHA_A) for number in range(1, 6)]
        actions = ActionsFake(runs=runs)
        source = ActionsSource(actions, REPO, per_page=2)
        self.assertEqual([5, 4], [row['id'] for row in source.runs(page=1)])
        self.assertEqual([3, 2], [row['id'] for row in source.runs(page=2)])
        self.assertEqual([1], [row['id'] for row in source.runs(page=3)])
        self.assertEqual(3, len(actions.calls), 'three pages: two full, one short')
        with self.assertRaises(CiFailureError):
            source.runs(page=1, per_page=51)
        with self.assertRaises(CiFailureError):
            source.runs(page=0)

    def test_a_bare_array_page_is_accepted_where_gitea_returns_one(self):
        actions = StubTransport([{'id': 9, 'status': 'completed', 'conclusion': 'success',
                                  'head_sha': SHA_A, 'name': 'ci', 'event': 'push',
                                  'head_branch': 'main'}])
        source = ActionsSource(actions, REPO)
        rows = source.runs(page=1)
        self.assertEqual([9], [row['id'] for row in rows])

    def test_a_page_with_the_wrong_shape_is_malformed_not_empty(self):
        with self.assertRaises(MalformedSource):
            ActionsSource(ActionsFake(faults={'page:1': 'garbage'}), REPO).runs(page=1)
        with self.assertRaises(MalformedSource):
            ActionsSource(ActionsFake(faults={'jobs:1': 'garbage'}), REPO).jobs(1)
        for shape in ({'workflow_runs': {}}, {'workflow_runs': ['text']}, {'total': 2}, {},
                      ['text'], None):
            with self.subTest(repr(shape)):
                with self.assertRaises(MalformedSource):
                    ActionsSource(StubTransport(shape), REPO).runs(page=1)

    def test_scrubbing_removes_secrets_paths_times_and_shas(self):
        scrubbed = scrub_excerpt(BAD_EXCERPT)
        for fragment in ('supersecretvalue', 'token:', '/home/runner', '7f3a9c2b8d4e',
                         '2026-09-22', '12.5', '8080'):
            self.assertNotIn(fragment, scrubbed)
        self.assertIn('<credential>', scrubbed)
        self.assertIn('<path>', scrubbed)
        self.assertNotIn('\n', scrubbed)

    def test_plane_and_identity_rules(self):
        self.assertEqual('main', plane_of('main', 'workflow_dispatch'))
        self.assertEqual('main', plane_of('master', 'push'))
        self.assertEqual('pull', plane_of('feature/x', 'pull_request'))
        self.assertEqual('branch', plane_of('feature/x', 'schedule'))
        self.assertEqual('branch', plane_of('topic', 'push', main_branches=('trunk',)))
        one = parse_run(REPO, run_payload(21, SHA_A, event='push'), jobs=[job(1)])
        twin = parse_run(REPO, run_payload(22, SHA_A, event='pull_request'), jobs=[job(1)])
        self.assertEqual(event_identity(one), event_identity(twin))
        later = parse_run(REPO, run_payload(23, SHA_B, event='pull_request'), jobs=[job(1)])
        self.assertNotEqual(event_identity(one), event_identity(later))
        self.assertEqual(card_identity(one).fingerprint, card_identity(later).fingerprint)
        self.assertEqual(16, len(card_identity(one).fingerprint))
        different = parse_run(REPO, run_payload(24, SHA_C), jobs=[job(1, name='lint')])
        self.assertNotEqual(card_identity(one).fingerprint, card_identity(different).fingerprint)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def test_cursor_and_facts_commit_together_and_replay_is_idempotent(self):
        store = CiFailureStore(self.state)
        fact = parse_run(REPO, run_payload(31, SHA_A), jobs=[job(1)])
        # The contract is the *pairs that were new*, not a count: the send path runs on novelty, so the
        # caller has to be handed the facts back, with the outcome the store recorded them under.
        self.assertEqual([(fact, 'failure')], store.record_facts([fact], cursor=31, now=T0))
        self.assertEqual([], store.record_facts([fact], cursor=31, now=T0))
        self.assertEqual(31, store.cursor())
        identity = card_identity(fact)
        self.assertEqual(1, store.window(identity.fingerprint, now=T0).count)
        store.close()

    def test_window_counts_distinct_shas_and_drops_stale_rows(self):
        store = CiFailureStore(self.state)
        facts = [parse_run(REPO, run_payload(number, sha, when=T0 - dt.timedelta(days=days)),
                           jobs=[job(number)])
                 for number, sha, days in ((41, SHA_A, 0), (42, SHA_B, 1), (43, SHA_A, 20))]
        store.record_facts(facts, cursor=43, now=T0)
        fingerprint = card_identity(facts[0]).fingerprint
        stats = store.window(fingerprint, now=T0)
        self.assertEqual(2, stats.count, 'a 20-day-old occurrence is outside the recurrence window')
        self.assertEqual(2, stats.distinct_shas)
        self.assertEqual((41, 42), stats.run_ids,
                         'the touched-run list is a set summary: ascending, whatever order it was written in')
        self.assertEqual((41, 42), store.window(fingerprint, now=T0 + dt.timedelta(days=1)).run_ids)
        self.assertEqual(3, len(store.occurrences_of(fingerprint)))
        # The windowed read applies the same cut as `window()` above: 41 and 42 are inside seven days,
        # the 20-day-old 43 is not. Two rows, both times -- the two reads must not disagree.
        self.assertEqual(2, len(store.occurrences_of(fingerprint, now=T0)))
        # `run_detail` is what a reader uses to answer "what do you know about run 42?". It used to
        # raise IndexError for every caller (its SELECT omitted the column it reports), and it now
        # answers with the run's newest event rather than an arbitrary one.
        detail = store.run_detail(REPO, 42)
        self.assertEqual(42, detail['run_id'])
        self.assertEqual(fingerprint, detail['fingerprint'])
        self.assertEqual('failure', detail['outcome'])
        self.assertIsNone(store.run_detail(REPO, 41),
                          'runs 41 and 43 are one event (same SHA, same verdict): the row carries the '
                          'newer run id, which is the collapse record_facts promises')
        self.assertEqual(43, store.run_detail(REPO, 43)['run_id'])
        self.assertIsNone(store.run_detail(REPO, 999))
        store.close()

    def test_delivery_journal_moves_from_pending_to_delivered_or_blocked(self):
        store = CiFailureStore(self.state)
        fact = parse_run(REPO, run_payload(51, SHA_A), jobs=[job(1)])
        fingerprint = card_identity(fact).fingerprint
        delivery_id, fresh = store.plan_delivery(fingerprint=fingerprint, repository=REPO,
                                                 action='create', run_ids=[51],
                                                 detail={'title': 't', 'body': 'b'}, now=T0)
        self.assertTrue(fresh)
        self.assertEqual((delivery_id, False), store.plan_delivery(fingerprint=fingerprint,
                                                                  repository=REPO, action='create',
                                                                  run_ids=[51],
                                                                  detail={'title': 't', 'body': 'b'},
                                                                  now=T0))
        self.assertEqual(1, len(store.pending_deliveries()))
        store.mark_blocked(delivery_id, 'create-failed:SourceUnavailable', T0)
        pending = store.pending_deliveries()
        self.assertEqual(1, len(pending))
        self.assertTrue(pending[0].blocked)
        self.assertEqual(1, pending[0].attempts)
        with self.assertRaises(CiFailureError):
            store.mark_delivered(delivery_id, issue_number=None, now=T0)
        store.mark_delivered(delivery_id, issue_number=123, now=T0)
        self.assertEqual([], store.pending_deliveries())
        self.assertEqual(STATE_DELIVERED, store.delivery(delivery_id).state)
        self.assertEqual(123, store.delivery(delivery_id).issue_number)
        store.close()

    def test_heartbeat_check_reads_and_judge_lapse_writes_one_row_per_gap(self):
        store = CiFailureStore(self.state)
        self.assertEqual('cold-start', store.check_heartbeat(now=T0, deadline_seconds=600).state)
        self.assertTrue(store.check_heartbeat(now=T0, deadline_seconds=600).lapsed)
        store.record_success(now=T0, outcome='ok', detail={}, deadline_seconds=600)
        self.assertEqual('ok', store.check_heartbeat(now=T0 + dt.timedelta(seconds=599),
                                                     deadline_seconds=600).state)
        verdict, lapse = store.judge_lapse(now=T0 + dt.timedelta(seconds=900), deadline_seconds=600)
        self.assertEqual('lapsed', verdict.state)
        self.assertIsNotNone(lapse)
        self.assertEqual(utc_text(T0), lapse['started_at'])
        store.record_success(now=T0 + dt.timedelta(seconds=901), outcome='ok', detail={},
                             deadline_seconds=600)
        self.assertEqual(1, len(store.lapses()))
        self.assertEqual(utc_text(T0), store.lapses()[0]['started_at'])
        self.assertEqual(T0 + dt.timedelta(seconds=901), store.last_success()[0])
        store.close()

    def test_a_refusal_and_a_coverage_note_survive_reopening(self):
        store = CiFailureStore(self.state)
        store.refusal(REPO, 'run-malformed', 'run carries an unknown status', run_id=99, now=T0)
        store.refusal(REPO, 'run-malformed', 'run carries an unknown status', run_id=99, now=T0)
        store.coverage(COVERAGE_SOURCE, CoverageNote('actions-read-failed', 'page-1'), now=T0)
        store.close()
        again = CiFailureStore(self.state)
        self.assertEqual(1, len(again.refusal_rows()))
        self.assertEqual(1, len(again.coverage_rows()))
        self.assertEqual(0, again.status(now=T0)['cursor'])
        self.assertEqual('cold-start', again.status(now=T0)['heartbeat']['state'])
        again.close()

    def test_a_foreign_schema_version_is_refused(self):
        import sqlite3

        store = CiFailureStore(self.state)
        store.close()
        connection = sqlite3.connect(self.state)
        connection.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        connection.commit()
        connection.close()
        with self.assertRaises(CiFailureError):
            CiFailureStore(self.state)


class OutletTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def _outlet(self, board: BoardFake, **kwargs) -> tuple[CiFailureStore, BoardOutlet]:
        store = CiFailureStore(self.state)
        outlet = BoardOutlet(store, BoardClient(board, REPO),
                             config=OutletConfig(thresholds=kwargs.pop('thresholds', Thresholds()),
                                                 file_cards=kwargs.pop('file_cards', True)))
        return store, outlet

    def test_scan_before_file_and_the_fingerprint_line(self):
        body = 'irrelevant\n```text\nfingerprint: ' + '0' * 16 + '\nfiled-by: ci-failure-pipeline\n```\n'
        self.assertIsNone(fingerprint_of_body(body))
        real = 'header\n' + OWNED_MARKER + '\nfingerprint: ' + '0' * 16 + '\n'
        self.assertEqual('0' * 16, fingerprint_of_body(real))
        self.assertIsNone(fingerprint_of_body('no marker here'))
        self.assertIsNone(fingerprint_of_body(None))

    def test_below_threshold_files_nothing_and_says_why(self):
        store, outlet = self._outlet(BoardFake())
        fact = parse_run(REPO, run_payload(61, SHA_A), jobs=[job(1, name='build')])
        identity = card_identity(fact)
        store.record_facts([fact], cursor=61, now=T0)
        plan = outlet.plan([(fact, identity)], now=T0)
        self.assertEqual([], list(plan.created))
        self.assertEqual([(identity.fingerprint, 'below-threshold')], list(plan.held))
        self.assertEqual([], store.pending_deliveries())
        store.close()

    def test_three_across_two_shas_files_one_card_and_a_fourth_comments(self):
        board = BoardFake()
        store, outlet = self._outlet(board)
        facts = [parse_run(REPO, run_payload(71, SHA_A, when=T0), jobs=[job(1, name='build')]),
                 parse_run(REPO, run_payload(72, SHA_A, when=T0 + dt.timedelta(minutes=1)),
                           jobs=[job(1, name='build')])]
        pairs = [(fact, card_identity(fact)) for fact in facts]
        store.record_facts(facts, cursor=72, now=T0 + dt.timedelta(minutes=1))
        held = outlet.plan(pairs, now=T0 + dt.timedelta(minutes=1))
        self.assertEqual([], list(held.created), 'two occurrences on one SHA are not a card')
        self.assertEqual([], board.created)
        third = parse_run(REPO, run_payload(73, SHA_B, when=T0 + dt.timedelta(minutes=2)),
                          jobs=[job(1, name='build')])
        store.record_facts([third], cursor=73, now=T0 + dt.timedelta(minutes=2))
        plan = outlet.plan([(third, card_identity(third))], now=T0 + dt.timedelta(minutes=2))
        self.assertEqual(1, len(plan.created))
        self.assertEqual([], board.created, 'planning alone never writes to the board')
        self.assertEqual(1, len(outlet.drain(now=T0 + dt.timedelta(minutes=2)).delivered))
        fingerprint = card_identity(facts[0]).fingerprint
        body = board.created[0]['body']
        self.assertEqual(fingerprint, fingerprint_of_body(body))
        self.assertEqual([7, 8], board.created[0]['labels'])
        self.assertNotIn('kanban', json.dumps(board.created))
        filing = store.filing(fingerprint)
        self.assertEqual(101, filing['issue_number'])
        fourth = parse_run(REPO, run_payload(74, SHA_C, when=T0 + dt.timedelta(minutes=3)),
                           jobs=[job(1, name='build')])
        store.record_facts([fourth], cursor=74, now=T0 + dt.timedelta(minutes=3))
        outlet.plan([(fourth, card_identity(fourth))], now=T0 + dt.timedelta(minutes=3))
        outlet.drain(now=T0 + dt.timedelta(minutes=3))
        self.assertEqual(1, len(board.created), 'a recurrence must never file a second card')
        self.assertEqual(1, len(board.posted))
        self.assertIn(batch_token([74]), board.posted[0][1])
        self.assertIn('Occurrences now: 4', board.posted[0][1])
        store.close()

    def test_main_red_files_immediately_without_waiting_for_the_threshold(self):
        board = BoardFake()
        store, outlet = self._outlet(board)
        fact = parse_run(REPO, run_payload(81, SHA_A, branch='main', event='push'),
                         jobs=[job(1, name='build')])
        store.record_facts([fact], cursor=81, now=T0)
        outlet.plan([(fact, card_identity(fact))], now=T0)
        outlet.drain(now=T0)
        self.assertEqual(1, len(board.created))
        self.assertIn('main red:', board.created[0]['title'])
        store.close()

    def test_a_storm_of_starved_runs_folds_to_one_create(self):
        board = BoardFake()
        store, outlet = self._outlet(board)
        facts = [parse_run(REPO, run_payload(90 + index, (SHA_A, SHA_B)[index % 2],
                                             branch='feature/storm', event='push', status='waiting',
                                             conclusion=''),
                           jobs=[job(1, name='build', conclusion='', status='waiting')])
                 for index in range(12)]
        store.record_facts(facts, cursor=101, now=T0, outcomes=['stuck'] * 12)
        outlet.plan([(fact, card_identity(fact)) for fact in facts], now=T0)
        outlet.drain(now=T0)
        self.assertEqual(1, len(board.created), 'twelve starved runs are one incident, not twelve')
        self.assertIn('- Occurrences: 12', board.created[0]['body'])
        self.assertEqual([], board.posted, 'the first filing is not also a recurrence comment')
        store.close()

    def test_missing_labels_are_reported_in_the_body_not_substituted(self):
        board = BoardFake(labels=[{'id': 7, 'name': 'aiops'}])
        store, outlet = self._outlet(board)
        fact = parse_run(REPO, run_payload(111, SHA_A, branch='main', event='push'),
                         jobs=[job(1, name='build')])
        store.record_facts([fact], cursor=111, now=T0)
        outlet.plan([(fact, card_identity(fact))], now=T0)
        outlet.drain(now=T0)
        self.assertEqual([7], board.created[0]['labels'])
        self.assertIn('audit-finding', board.created[0]['body'])
        self.assertIn('Labels not applied', board.created[0]['body'])
        store.close()

    def test_file_cards_off_keeps_state_without_writing(self):
        board = BoardFake()
        store, outlet = self._outlet(board, file_cards=False)
        facts = [parse_run(REPO, run_payload(121 + index, sha, when=T0 + dt.timedelta(minutes=index)),
                           jobs=[job(1, name='build')])
                 for index, sha in enumerate((SHA_A, SHA_B, SHA_A))]
        store.record_facts(facts, cursor=123, now=T0 + dt.timedelta(minutes=2))
        plan = outlet.plan([(fact, card_identity(fact)) for fact in facts],
                           now=T0 + dt.timedelta(minutes=2))
        self.assertEqual([], list(plan.created))
        self.assertIn(plan.held[0][1], ('card-filing-disabled', 'below-threshold'))
        self.assertEqual([], board.created)
        store.close()

    def test_scan_failure_blocks_delivery_and_retains_it(self):
        board = BoardFake(faults={'scan'})
        store, outlet = self._outlet(board)
        fact = parse_run(REPO, run_payload(131, SHA_A, branch='main', event='push'),
                         jobs=[job(1, name='build')])
        store.record_facts([fact], cursor=131, now=T0)
        outlet.plan([(fact, card_identity(fact))], now=T0)
        report = outlet.drain(now=T0)
        self.assertEqual(1, len(report.blocked))
        self.assertEqual(1, len(store.pending_deliveries()))
        self.assertTrue(store.pending_deliveries()[0].blocked)
        self.assertEqual(0, len(board.created))
        store.close()

    def test_http_rejection_is_blocked_not_guessed_at(self):
        board = BoardFake(faults={'create'})
        store, outlet = self._outlet(board)
        fact = parse_run(REPO, run_payload(141, SHA_A, branch='main', event='push'),
                         jobs=[job(1, name='build')])
        store.record_facts([fact], cursor=141, now=T0)
        outlet.plan([(fact, card_identity(fact))], now=T0)
        report = outlet.drain(now=T0)
        self.assertIn('create-failed', report.blocked[0][1])
        self.assertEqual(1, len(store.pending_deliveries()))
        store.close()

    def test_label_lookup_failure_is_a_blocked_result_not_a_drop(self):
        board = BoardFake(faults={'labels'})
        store, outlet = self._outlet(board)
        fact = parse_run(REPO, run_payload(151, SHA_A, branch='main', event='push'),
                         jobs=[job(1, name='build')])
        store.record_facts([fact], cursor=151, now=T0)
        outlet.plan([(fact, card_identity(fact))], now=T0)
        report = outlet.drain(now=T0)
        self.assertEqual(1, len(report.blocked))
        self.assertEqual(1, len(store.pending_deliveries()))
        self.assertEqual(0, len(board.created))
        store.close()

    def test_comment_without_a_receipt_is_blocked_rather_than_invented(self):
        board = BoardFake()
        store, outlet = self._outlet(board)
        fact = parse_run(REPO, run_payload(161, SHA_A), jobs=[job(1, name='build')])
        fingerprint = card_identity(fact).fingerprint
        store.record_facts([fact], cursor=161, now=T0)
        delivery_id, _ = store.plan_delivery(fingerprint=fingerprint, repository=REPO,
                                             action='comment', run_ids=[161],
                                             detail={'body': 'x', 'batch': batch_token([161])},
                                             now=T0)
        report = outlet.drain(now=T0)
        self.assertEqual([(delivery_id, 'no-filing-receipt')], list(report.blocked))
        self.assertEqual([], board.posted)
        store.close()

    def test_a_card_already_on_the_board_is_adopted_not_duplicated(self):
        fact = parse_run(REPO, run_payload(171, SHA_A, branch='main', event='push'),
                         jobs=[job(1, name='build')])
        identity = card_identity(fact)
        body = f'{OWNED_MARKER}\nfingerprint: {identity.fingerprint}\n'
        board = BoardFake(issues=[{'number': 55, 'title': 'existing', 'body': body}])
        store, outlet = self._outlet(board)
        store.record_facts([fact], cursor=171, now=T0)
        outlet.plan([(fact, identity)], now=T0)
        report = outlet.reconcile(now=T0)
        self.assertEqual([(identity.fingerprint, 55)], list(report.adopted))
        outlet.drain(now=T0)
        self.assertEqual([], board.created)
        self.assertEqual(55, store.filing(identity.fingerprint)['issue_number'])
        store.close()


class ServiceConstructionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def test_build_service_wires_two_scoped_clients_and_a_real_pipeline(self):
        actions, board = ActionsFake(runs=[run_payload(181, SHA_A)]), BoardFake()
        built = service(actions, board, self.state)
        self.assertIsInstance(built.actions, ActionsSource)
        self.assertIsInstance(built.board, BoardClient)
        self.assertIsInstance(built.outlet, BoardOutlet)
        self.assertIsInstance(built.pipeline, Pipeline)
        self.assertEqual('gitea-actions-read', built.actions.scope)
        self.assertEqual('board-read-write', built.board.scope)
        self.assertIs(built.outlet.board, built.board)
        self.assertEqual(200, built.actions.request('GET', f'/repos/{REPO}/actions/runs')[0])
        with self.assertRaises(ScopeRefused):
            built.actions.request('POST', f'/repos/{REPO}/issues')
        self.assertEqual([], [call for call in actions.calls if call[0] != 'GET'])
        built.close()

    def test_the_actions_credential_never_reaches_the_board(self):
        actions, board = ActionsFake(runs=[]), BoardFake()
        built = service(actions, board, self.state)
        self.assertIsNot(built.actions.transport, built.board.transport)
        self.assertIs(built.actions.transport, actions)
        self.assertIs(built.board.transport, board)
        built.close()

    def test_sharing_one_transport_between_the_two_scopes_is_refused(self):
        shared = ActionsFake(runs=[])
        store = CiFailureStore(self.state)
        actions = ActionsSource(shared, REPO)
        outlet = BoardOutlet(store, BoardClient(shared, REPO))
        with self.assertRaises(ScopeRefused):
            Pipeline(store, actions, outlet=outlet, config=config())
        store.close()

    def test_a_reader_and_a_board_naming_different_repositories_are_refused(self):
        store = CiFailureStore(self.state)
        actions = ActionsSource(ActionsFake(runs=[]), 'acme/widgets')
        outlet = BoardOutlet(store, BoardClient(BoardFake(), 'acme/other'))
        with self.assertRaises(ScopeRefused):
            Pipeline(store, actions, outlet=outlet, config=config())
        with self.assertRaises(CiFailureError):
            Pipeline(store, actions, config=config(repository='acme/different'))
        store.close()

    def test_without_a_board_client_the_service_plans_nothing_and_says_so(self):
        built = service(ActionsFake(runs=[run_payload(191, SHA_A)]), None, self.state)
        self.assertIsNone(built.board)
        self.assertIsNone(built.outlet)
        self.assertIsNone(built.pipeline.outlet)
        built.close()


class FailingAdmitter:
    """A stand-in for the host's platform send, so admission status is testable offline."""

    def __init__(self, events: list, *, accept=True):
        self.events = events
        self.accept = accept

    def __call__(self, event):
        self.events.append(event)
        if not self.accept:
            raise ValueError('intake refused: rule not declared')
        return {'event_id': event['source_event_id'], 'accepted': True}


class PollerIntegrationTests(unittest.TestCase):
    """The card's acceptance list, driven through the built service with no sockets."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def failing(self, run_id, sha, when, *, branch='feature/one', event='pull_request',
                status='completed', conclusion='failure'):
        return run_payload(run_id, sha, branch=branch, event=event, status=status,
                           conclusion=conclusion, when=when)

    def test_three_failures_two_shas_one_card_fourth_updates_it(self):
        board = BoardFake()
        actions = ActionsFake(runs=[self.failing(201, SHA_A, T0), self.failing(202, SHA_A,
                                                                              T0 + dt.timedelta(minutes=1))],
                              jobs={201: [job(1)], 202: [job(1)]}, log_text=BAD_EXCERPT)
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        with SocketGuard():
            first = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
            self.assertEqual(2, first.scanned)
            self.assertEqual([], board.created, 'two failures on one SHA are not a card')
            actions.runs.append(self.failing(203, SHA_B, T0 + dt.timedelta(minutes=3)))
            actions.jobs[203] = [job(1)]
            built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=4))
            self.assertEqual(1, len(board.created), 'three occurrences across two SHAs is one card')
            actions.runs.append(self.failing(204, SHA_C, T0 + dt.timedelta(minutes=5)))
            actions.jobs[204] = [job(1)]
            built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=6))
        self.assertEqual(1, len(board.created), 'a fourth occurrence must never file a second card')
        self.assertEqual(1, len(board.posted))
        self.assertIn('Occurrences now: 4', board.posted[0][1])
        fingerprint = re.search(r'fingerprint: ([0-9a-f]{16})', board.created[0]['body']).group(1)
        stats = built.store.window(fingerprint, now=T0 + dt.timedelta(minutes=6))
        self.assertEqual(4, stats.count)
        self.assertEqual(3, stats.distinct_shas)
        # The push+PR twins of one SHA are one *event*: runs 201 and 202 share an event key even though
        # both are occurrences of the card. That collapse is the card's C2 rule, checked here on the
        # table the platform reads.
        self.assertEqual(1, len(built.store.recorded_runs(REPO) & {201, 202}))
        # Both runs were fresh facts on the first tick (the event-row collapse happens in `runs`, not in
        # the occurrence count), which is what the send path keys on.
        self.assertEqual(2, first.recorded)
        built.close()

    def test_pr_failures_do_not_file_before_the_threshold_and_main_red_does(self):
        board = BoardFake()
        actions = ActionsFake(runs=[self.failing(211, SHA_A, T0)], jobs={211: [job(1)]})
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual([], board.created)
        built.close()
        board2 = BoardFake()
        actions2 = ActionsFake(runs=[self.failing(212, SHA_A, T0, branch='main', event='push')],
                               jobs={212: [job(1)]})
        built2 = service(actions2, board2, self.state, log_reader=actions2.log_reader)
        built2.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, len(board2.created))
        self.assertIn('main red:', board2.created[0]['title'])
        built2.close()

    def test_a_stopped_page_save_loses_nothing_and_duplicates_nothing(self):
        """A page that fails to arrive leaves the cursor where the last committed walk left it."""
        board = BoardFake()
        actions = ActionsFake(runs=[self.failing(221, SHA_A, T0), self.failing(222, SHA_B, T0)],
                              jobs={221: [job(1)], 222: [job(2)]}, faults={'page:2': 'unavailable'},
                              log_text=BAD_EXCERPT)
        built = service(actions, board, self.state, log_reader=actions.log_reader,
                        cfg=config(per_page=1, file_cards=True))
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertFalse(report.complete)
        self.assertEqual('SourceUnavailable', report.error)
        self.assertEqual(0, report.cursor, 'an unfinished walk may not advance the cursor')
        self.assertEqual({222}, built.store.recorded_runs(REPO))
        del actions.faults['page:2']
        second = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
        self.assertEqual(222, built.store.cursor())
        self.assertEqual({221, 222}, built.store.recorded_runs(REPO))
        self.assertEqual(1, second.recorded, 'the missed page arrived; the replayed row was not new')
        fingerprint = card_identity(parse_run(REPO, self.failing(221, SHA_A, T0), jobs=[job(1)],
                                              log=BAD_EXCERPT)).fingerprint
        self.assertEqual([221, 222],
                         [row['run_id'] for row in built.store.occurrences_of(fingerprint, now=T0)])
        built.close()

    def test_a_lost_create_acknowledgement_is_adopted_after_restart(self):
        board = BoardFake(faults={'create-ack-lost'})
        actions = ActionsFake(runs=[self.failing(231, SHA_A, T0, branch='main', event='push')],
                              jobs={231: [job(1)]})
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, len(report.drained.blocked))
        self.assertEqual(1, len(built.store.pending_deliveries()))
        self.assertEqual(1, len(board.created), 'the write landed even though the answer did not')
        built.close()
        restarted = service(ActionsFake(runs=[]), BoardFake(issues=board.issues,
                                                            labels=board.labels,
                                                            comments=board.comments),
                            self.state)
        reconciled = restarted.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
        self.assertEqual(1, len(reconciled.reconciled.adopted))
        self.assertEqual([], restarted.store.pending_deliveries())
        self.assertEqual(1, len(board.created), 'no second card for the same fingerprint')
        restarted.close()

    def test_a_lost_comment_acknowledgement_is_adopted_after_restart(self):
        board = BoardFake()
        actions = ActionsFake(runs=[self.failing(241, SHA_A, T0), self.failing(242, SHA_B, T0),
                                    self.failing(243, SHA_A, T0)],
                              jobs={241: [job(1)], 242: [job(1)], 243: [job(1)]},
                              log_text=BAD_EXCERPT)
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, len(board.created))
        actions.runs.append(self.failing(244, SHA_C, T0 + dt.timedelta(minutes=2)))
        actions.jobs[244] = [job(1)]
        board.faults.add('comment-ack-lost')
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=3))
        self.assertEqual(1, len(board.posted))
        self.assertEqual(1, len(report.drained.blocked))
        built.close()
        restarted = service(ActionsFake(runs=[]), BoardFake(issues=board.issues, labels=board.labels,
                                                            comments=board.comments),
                            self.state)
        restarted.pipeline.poll_once(now=T0 + dt.timedelta(minutes=4))
        self.assertEqual([], restarted.store.pending_deliveries())
        self.assertEqual(1, len(board.posted), 'the recurrence comment was not written twice')
        restarted.close()

    def test_interrupted_before_checkpoint_replays_without_a_duplicate_card(self):
        """Kill the process between the write and the checkpoint, then start a fresh service."""
        board = BoardFake()
        actions = ActionsFake(runs=[self.failing(251, SHA_A, T0, branch='main', event='push')],
                              jobs={251: [job(1)]})
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, len(board.created))
        fingerprint = re.search(r'fingerprint: ([0-9a-f]{16})', board.created[0]['body']).group(1)
        built.store.forget_filing(fingerprint)  # the crash landed after POST, before the receipt
        built.close()
        restarted = service(ActionsFake(runs=[self.failing(251, SHA_A, T0, branch='main',
                                                          event='push')],
                                       jobs={251: [job(1)]}), board, self.state)
        restarted.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
        self.assertEqual(1, len(board.created), 'a replayed run may not file a second card')
        self.assertEqual(fingerprint,
                         re.search(r'fingerprint: ([0-9a-f]{16})', board.created[0]['body']).group(1))
        restarted.close()

    def test_malformed_runs_are_refused_durable_and_do_not_stop_the_walk(self):
        good = self.failing(261, SHA_A, T0)
        board = BoardFake()
        actions = ActionsFake(runs=[dict(good, conclusion='exploded'), good],
                              jobs={261: [job(1)]})
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, report.refusals)
        self.assertEqual(1, report.recorded)
        self.assertEqual(261, report.cursor)
        refusals = built.store.refusal_rows()
        self.assertEqual(1, len(refusals))
        self.assertIn('unknown conclusion', refusals[0]['detail'])
        self.assertEqual('run-malformed', refusals[0]['reason'])
        built.close()

    def test_missing_job_list_and_log_are_coverage_in_the_card_and_the_events(self):
        board = BoardFake()
        actions = ActionsFake(runs=[self.failing(271, SHA_A, T0, branch='main', event='push')])
        built = service(actions, board, self.state, cfg=config(thresholds=Thresholds()))
        events: list[dict] = []
        built.pipeline.admission = PlatformAdmission(FailingAdmitter(events))
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, len(board.created))
        body = board.created[0]['body']
        self.assertIn('Not captured', body)
        self.assertIn('Log excerpt', body)
        self.assertIn('- Log excerpt captured: no', body)
        rules = [event['rule_id'] for event in events]
        self.assertTrue(any(rule.startswith(RULE_COVERAGE) for rule in rules), rules)
        self.assertTrue(any(rule == RULE_FAILURE for rule in rules), rules)
        self.assertTrue(all(event['source'] == SOURCE for event in events))
        self.assertEqual(len(events), admission_ready(events, now=T0 + dt.timedelta(minutes=1)))
        self.assertTrue(report.receipts)
        self.assertTrue(all(receipt.status == 'admitted' for receipt in report.receipts))
        self.assertEqual('admitted', report.platform_admission)
        built.close()

    def test_platform_admission_is_reported_as_configured_or_not_and_never_assumed(self):
        actions = ActionsFake(runs=[self.failing(281, SHA_A, T0, branch='main', event='push')],
                              jobs={281: [job(1)]})
        built = service(actions, None, self.state)
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual('not-configured', report.platform_admission)
        self.assertEqual(0, report.admitted)
        self.assertTrue(report.events > 0)
        built.close()

    def test_an_admitter_that_refuses_is_reported_and_the_fact_is_not_retraised(self):
        def refusing(event):
            raise ValueError('intake refused: rule not declared')

        actions = ActionsFake(runs=[self.failing(291, SHA_A, T0, branch='main', event='push')],
                              jobs={291: [job(1)]})
        built = service(actions, None, self.state, admission=PlatformAdmission(refusing))
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual('refused', report.platform_admission)
        self.assertEqual(0, report.admitted)
        self.assertTrue(any('refused' == receipt.status for receipt in report.receipts))
        self.assertEqual(291, built.store.cursor(), 'a refused send does not rewind the cursor')
        built.close()

    def test_starved_runs_fold_into_one_incident_and_are_reported_once(self):
        board = BoardFake()
        waiting = T0 - dt.timedelta(minutes=45)
        runs = [self.failing(301 + index, (SHA_A, SHA_B)[index % 2], waiting, status='waiting',
                             conclusion='', event='push', branch='feature/long')
                for index in range(8)]
        actions = ActionsFake(runs=runs, jobs={row['id']: [job(row['id'], name='build',
                                                               conclusion='', status='waiting')]
                                               for row in runs})
        built = service(actions, board, self.state, log_reader=actions.log_reader)
        first = built.pipeline.poll_once(now=T0)
        self.assertEqual(1, len(board.created))
        self.assertEqual(8, first.recorded)
        actions.log_text = None  # no logs anywhere: every identity is coarse, one card
        second = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=5))
        self.assertEqual(1, len(board.created))
        self.assertEqual(0, len(board.posted), 'a re-read starved run is not a new occurrence')
        fingerprint = card_identity(parse_run(REPO, runs[0],
                                              jobs=[job(1, name='build', conclusion='',
                                                       status='waiting')])).fingerprint
        self.assertEqual(8, built.store.window(fingerprint, now=T0 + dt.timedelta(minutes=5)).count)
        self.assertTrue(second.complete)
        built.close()

    def test_a_source_outage_is_coverage_and_keeps_every_recorded_fact(self):
        actions = ActionsFake(runs=[self.failing(311, SHA_A, T0, branch='main', event='push')],
                              jobs={311: [job(1)]}, faults={'page:1': 'unavailable'})
        built = service(actions, BoardFake(), self.state, log_reader=actions.log_reader)
        report = built.pipeline.poll_once(now=T0)
        self.assertEqual('SourceUnavailable', report.error)
        self.assertEqual(0, report.recorded)
        self.assertEqual(0, report.cursor)
        coverage = built.store.coverage_rows()
        self.assertEqual('actions-read-failed', coverage[0]['reason'])
        self.assertEqual('page-1', coverage[0]['detail'])
        self.assertTrue(built.store.check_heartbeat(now=T0, deadline_seconds=600).lapsed)
        del actions.faults['page:1']
        recovered = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        self.assertEqual(1, recovered.recorded)
        self.assertEqual(311, recovered.cursor)
        built.close()


class UnfinishedRunCursorTests(unittest.TestCase):
    """A run counts against the cursor when its verdict arrives, not when its row first scrolls past.

    The card's ingest rule is "no failure lost to pagination", and the cursor is how the poller avoids
    re-reading history. Those two collide if an unfinished run moves the cursor: the queued row is seen
    on tick one, its failure lands on tick three below the cursor, and `run_id <= cursor` files it as
    already-read history -- the one shape of lost incident that leaves a healthy-looking pipeline. The
    fix has two halves, and both are checked here: the cursor advances only over runs whose verdict has
    arrived, and the runs the walk can no longer reach come back through bounded single-run GETs driven
    by the store's own open-run set.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def test_a_queued_run_that_fails_two_ticks_later_files_one_incident(self):
        run = run_payload(301, SHA_A, status='queued', conclusion='', branch='feature/one')
        actions = ActionsFake(runs=[run], jobs={301: []}, log_text=BAD_EXCERPT)
        board = BoardFake()
        built = service(actions, board, self.state, cfg=config(thresholds=Thresholds(occurrences=1,
                                                                                    distinct_shas=1)),
                        log_reader=actions.log_reader)
        with SocketGuard():
            waiting = built.pipeline.poll_once(now=T0)
            self.assertEqual(1, waiting.recorded, 'the queued row is stored once')
            self.assertEqual(0, waiting.cursor, 'but the cursor waits for its verdict')
            self.assertEqual([301], built.store.open_run_ids(REPO), 'the run stays on the open list')
            run.update(status='in_progress')
            running = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
            self.assertEqual(0, running.recorded, 'queued -> running is a status change, not an incident')
            self.assertEqual(0, running.cursor)
            self.assertEqual([], board.created)
            run.update(status='completed', conclusion='failure')
            actions.jobs[301] = [job(1)]
            failed = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
        self.assertEqual(1, failed.recorded, 'the verdict arrives exactly once')
        self.assertEqual(301, failed.cursor, 'and only now does the cursor pass the run')
        self.assertEqual([], built.store.open_run_ids(REPO), 'a settled run stops being refreshed')
        fingerprint = re.search(r'fingerprint: ([0-9a-f]{16})', board.created[0]['body']).group(1)
        self.assertEqual(1, len(board.created), 'three ticks of one run are one card')
        self.assertEqual([], board.posted)
        self.assertEqual(1, built.store.window(fingerprint, now=T0 + dt.timedelta(minutes=2)).count,
                         'and one occurrence: the waiting and running ticks added none')
        self.assertEqual(1, len(built.store.occurrences_of(fingerprint)))
        built.close()

    def test_a_pending_run_below_the_cursor_comes_back_as_one_bounded_get(self):
        newer = [run_payload(502, SHA_B, branch='feature/one'),
                 run_payload(501, SHA_A, branch='feature/one')]
        pending = run_payload(500, SHA_C, status='queued', conclusion='', branch='feature/one')
        actions = ActionsFake(runs=newer + [pending], jobs={501: [job(1)], 502: [job(1)], 500: []},
                              log_text=BAD_EXCERPT)
        board = BoardFake()
        built = service(actions, board, self.state, cfg=config(per_page=2, max_pages=3),
                        log_reader=actions.log_reader)
        with SocketGuard():
            first = built.pipeline.poll_once(now=T0)
            self.assertEqual(3, first.scanned, 'the walk reads page one and the queued row on page two')
            self.assertEqual(502, first.cursor, 'the cursor stops at the newest run with a verdict')
            self.assertEqual([500], built.store.open_run_ids(REPO))
            self.assertEqual([], board.created, 'two occurrences on two SHAs are still below threshold')
            # The pending run fails while its id is below the cursor and beyond the first history page:
            # the walk breaks on `run_id <= cursor` before it ever reaches row three again.
            pending.update(status='completed', conclusion='failure')
            actions.jobs[500] = [job(1)]
            mark = len(actions.calls)
            second = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
            tick2 = actions.calls[mark:]
            open_after = list(built.store.open_run_ids(REPO))
            detail = built.store.run_detail(REPO, 500)
            fp500 = detail['fingerprint']
            rows_500 = [row['run_id'] for row in built.store.occurrences_of(fp500)]
            mark3 = len(actions.calls)
            third = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=3))
            tick3 = actions.calls[mark3:]
        history = [call for call in tick2 if call[1].endswith('/actions/runs')]
        refreshes = [call for call in tick2 if call[1] == f'/repos/{REPO}/actions/runs/500']
        self.assertEqual(1, len(history), 'the walk stopped at the cursor, as it always has')
        self.assertEqual(1, len(refreshes), 'the lost run comes back through exactly one GET')
        self.assertEqual(1, second.recorded)
        self.assertEqual(502, second.cursor, 'a refreshed verdict never moves the cursor backwards')
        self.assertIn(500, built.store.recorded_runs(REPO))
        self.assertEqual([], open_after, 'the settled run leaves the refresh set')
        self.assertEqual('failure', detail['outcome'])
        self.assertEqual(1, len([row for row in rows_500 if row == 500]),
                         'the refreshed failure is counted exactly once, not once per status change')
        self.assertEqual(0, third.recorded, 'and it is not re-reported on the tick after')
        self.assertEqual([], [c for c in tick3 if c[1] == f'/repos/{REPO}/actions/runs/500'],
                         'a settled run is not asked about again')
        built.close()

    def test_an_unreachable_pending_run_keeps_its_row_and_a_vanished_one_loses_it(self):
        newer = [run_payload(511, SHA_A, branch='feature/one')]
        pending = run_payload(510, SHA_B, status='queued', conclusion='', branch='feature/one')
        actions = ActionsFake(runs=newer + [pending], jobs={511: [job(1)], 510: []},
                              faults={'run:510': 'unavailable'}, log_text=BAD_EXCERPT)
        built = service(actions, BoardFake(), self.state, cfg=config(per_page=2, max_pages=3),
                        log_reader=actions.log_reader)
        with SocketGuard():
            built.pipeline.poll_once(now=T0)
            outage = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=2))
            kept = list(built.store.open_run_ids(REPO))
            actions.faults.pop('run:510')
            actions.runs.remove(pending)  # the forge dropped it (a purged run, not an outage)
            vanished = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=3))
            final = built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=4))
        self.assertEqual(0, outage.recorded)
        self.assertEqual([510], kept,
                         'an outage on the refresh is coverage, and the run is asked about again')
        self.assertEqual(0, vanished.recorded)
        self.assertEqual([], built.store.open_run_ids(REPO), 'a 404 retires the row and its budget')
        self.assertEqual(0, final.recorded)
        reasons = [row['reason'] for row in built.store.coverage_rows(limit=20)]
        self.assertIn('open-run-refresh-failed', reasons)
        self.assertIn('open-run-vanished', reasons)
        built.close()

    def test_the_refresh_is_bounded_to_its_own_budget(self):
        pending = [run_payload(600 + offset, '%040x' % (offset + 10), status='queued', conclusion='')
                   for offset in range(6)]
        settled = [run_payload(700, SHA_A)]
        actions = ActionsFake(runs=settled + pending, jobs={700: [job(1)]}, log_text=BAD_EXCERPT)
        built = service(actions, BoardFake(), self.state,
                        cfg=config(per_page=50, max_pages=3, max_open_run_refresh=2),
                        log_reader=actions.log_reader)
        with SocketGuard():
            built.pipeline.poll_once(now=T0)
            mark = len(actions.calls)
            built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        asked = [call for call in actions.calls[mark:] if re.fullmatch(
            rf'/repos/{REPO}/actions/runs/[0-9]+', call[1])]
        self.assertEqual(2, len(asked), 'at most the budgeted number of runs is refreshed per tick')
        self.assertEqual([605, 604], [int(call[1].rsplit('/', 1)[1]) for call in asked],
                         'newest first, so a long backlog drains from the front')
        built.close()


class LivenessIndependenceTests(unittest.TestCase):
    """D4: a stopped poller must be noticed by a process that is not the poller."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def test_a_stopped_poller_is_lapsed_to_another_process(self):
        actions = ActionsFake(runs=[run_payload(401, SHA_A)], jobs={401: [job(1)]})
        built = service(actions, BoardFake(), self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0)
        built.close()
        monitor = CiFailureStore(self.state)
        verdict = monitor.check_heartbeat(now=T0 + dt.timedelta(hours=1), deadline_seconds=1800)
        self.assertEqual('lapsed', verdict.state)
        # `lapses()` is the read side of the liveness table and answers a list; the claim under test is
        # that a monitor which only looked wrote nothing, which is an empty list, not None.
        self.assertEqual([], monitor.lapses(), 'reading liveness must not record anything')
        monitor.close()

    def test_the_lapse_is_judged_before_a_returning_poller_moves_the_heartbeat(self):
        actions = ActionsFake(runs=[run_payload(411, SHA_A)], jobs={411: [job(1)]})
        built = service(actions, BoardFake(), self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0)
        built.close()
        monitor = CiFailureStore(self.state)
        verdict, lapse = monitor.judge_lapse(now=T0 + dt.timedelta(minutes=40), deadline_seconds=1800)
        self.assertEqual('lapsed', verdict.state)
        self.assertEqual(utc_text(T0), lapse['started_at'])
        monitor.close()
        restarted = service(ActionsFake(runs=[run_payload(412, SHA_B)], jobs={412: [job(1)]}),
                            BoardFake(), self.state)
        report = restarted.pipeline.poll_once(now=T0 + dt.timedelta(minutes=41))
        self.assertEqual('ok', report.heartbeat['state'])
        self.assertIsNone(report.lapse, 'the monitor already judged this gap; the row is not doubled')
        self.assertEqual(1, len(restarted.store.lapses()))
        restarted.close()

    def test_recovery_alone_still_records_the_gap_before_the_timestamp_moves(self):
        actions = ActionsFake(runs=[run_payload(421, SHA_A)], jobs={421: [job(1)]})
        built = service(actions, BoardFake(), self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0)
        built.close()
        restarted = service(ActionsFake(runs=[run_payload(422, SHA_B)], jobs={422: [job(1)]}),
                            BoardFake(), self.state)
        report = restarted.pipeline.poll_once(now=T0 + dt.timedelta(hours=2))
        self.assertIsNotNone(report.lapse)
        self.assertEqual(utc_text(T0), report.lapse['started_at'])
        self.assertEqual(1, len(restarted.store.lapses()))
        self.assertEqual('poller-recovery', report.lapse['judged_by'])
        restarted.close()


class LogCapture(logging.Handler):
    """Collects every emitted log record so "no credential in the logs" is a checked statement."""

    def __init__(self):
        super().__init__()
        self.records: list[str] = []
        self.formatted = ''

    def emit(self, record):
        try:
            self.records.append(f'{record.getMessage()} {getattr(record, "__dict__", {})}')
        except Exception:
            self.records.append('unreadable record')

    def install(self):
        logging.getLogger('local_observe').addHandler(self)
        logging.getLogger('local_observe').setLevel(logging.DEBUG)

    def remove(self):
        logging.getLogger('local_observe').removeHandler(self)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'
        from local_observe.ci_failures import cli

        self.cli = cli

    def tearDown(self):
        self.temp.cleanup()

    def _run(self, argv, actions, board, environ=None):
        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            code = self.cli.main(argv, environ=environ or {'LO_CI_REPOSITORY': REPO},
                                 transports=(actions, board))
        finally:
            out, err = sys.stdout.getvalue(), sys.stderr.getvalue()
            sys.stdout, sys.stderr = stdout, stderr
        return code, out, err

    def test_once_polls_delivers_and_prints_no_credential(self):
        actions = ActionsFake(runs=[run_payload(501, SHA_A, branch='main', event='push')],
                              jobs={501: [job(1)]}, log_text=BAD_EXCERPT)
        board = BoardFake()
        captured = LogCapture()
        captured.install()
        try:
            code, out, err = self._run(['--once', '--state', self.state, '--file-cards'], actions,
                                       board, environ={'LO_CI_REPOSITORY': REPO,
                                                       'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN,
                                                       'LO_CI_BOARD_TOKEN': BOARD_TOKEN})
        finally:
            captured.remove()
        self.assertEqual(self.cli.EXIT_OK, code, err)
        report = json.loads(out)
        self.assertEqual(1, report['recorded'])
        self.assertEqual(1, len(board.created))
        self.assertEqual('not-configured', report['platform_admission'])
        for blob in [out, err, '\n'.join(captured.records), json.dumps(board.created),
                     json.dumps(actions.calls)]:
            self.assertNotIn(ACTIONS_TOKEN, blob)
            self.assertNotIn(BOARD_TOKEN, blob)
            self.assertNotIn('supersecretvalue', blob)
            self.assertNotIn('a' * 40, blob)

    def test_check_heartbeat_exits_non_zero_for_a_cold_start_and_zero_after_a_tick(self):
        actions = ActionsFake(runs=[run_payload(511, SHA_A)], jobs={511: [job(1)]})
        code, out, err = self._run(['--once', '--state', self.state], actions, BoardFake())
        self.assertEqual(self.cli.EXIT_OK, code, err)
        code, out, _ = self._run(['--check-heartbeat', '--state', self.state,
                                  '--deadline-seconds', '900'], actions, BoardFake())
        self.assertEqual(self.cli.EXIT_OK, code)
        self.assertFalse(json.loads(out)['lapsed'])
        code, out, _ = self._run(['--check-heartbeat', '--state', f'{self.temp.name}/other.sqlite3',
                                  '--deadline-seconds', '900'], actions, BoardFake())
        self.assertEqual(self.cli.EXIT_LAPSED, code)
        self.assertEqual('cold-start', json.loads(out)['state'])

    def test_status_and_argument_discipline_never_reach_the_network(self):
        self._run(['--once', '--state', self.state], ActionsFake(runs=[run_payload(521, SHA_A)],
                                                                 jobs={521: [job(1)]}), BoardFake())
        code, out, _ = self._run(['--status', '--state', self.state], ActionsFake(), BoardFake())
        self.assertEqual(self.cli.EXIT_OK, code)
        self.assertIn('cursor', json.loads(out))
        code, _, err = self._run([], ActionsFake(), BoardFake())
        self.assertEqual(self.cli.EXIT_REFUSED, code)
        self.assertIn('exactly one', err)
        code, out, err = self._run(['--once', '--state', self.state], ActionsFake(), BoardFake())
        self.assertEqual(self.cli.EXIT_OK, code)
        self.assertEqual(0, json.loads(out)['recorded'], 'an empty history is a clean tick')

    def test_a_missing_board_url_is_refused_before_any_request(self):
        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            code = self.cli.main(['--once', '--state', f'{self.temp.name}/x.sqlite3'],
                                 environ={'LO_CI_REPOSITORY': REPO})
        finally:
            err = sys.stderr.getvalue()
            sys.stdout, sys.stderr = stdout, stderr
        self.assertEqual(self.cli.EXIT_REFUSED, code)
        self.assertIn('LO_CI_ACTIONS_URL', err)


class PlatformBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'

    def tearDown(self):
        self.temp.cleanup()

    def test_events_the_pipeline_produces_are_admissible_to_the_platform_validator(self):
        fact = parse_run(REPO, run_payload(601, SHA_A, branch='main', event='push'), jobs=[job(1)],
                         log=BAD_EXCERPT)
        events = build_events(fact, card_identity(fact), now=T0)
        self.assertEqual(len(events), admission_ready(events, now=T0))
        kinds = {event['kind'] for event in events}
        self.assertTrue(kinds <= {'availability', 'coverage'}, kinds)
        failure = [event for event in events if event['rule_id'] == RULE_FAILURE]
        self.assertEqual('critical', failure[0]['severity'], 'main-red is never a warning')
        branch = parse_run(REPO, run_payload(602, SHA_A), jobs=[job(1)], log=BAD_EXCERPT)
        branch_events = build_events(branch, card_identity(branch), now=T0)
        self.assertEqual('warning',
                         [event for event in branch_events if event['rule_id'] == RULE_FAILURE][0]
                         ['severity'])
        for event in events:
            validate_event(event, T0)

    def test_a_green_run_produces_no_incident_event(self):
        fact = parse_run(REPO, run_payload(611, SHA_A, conclusion='success'),
                         jobs=[job(1, conclusion='success')], log='all good')
        self.assertEqual([], build_events(fact, card_identity(fact), now=T0))
        self.assertFalse(fact.is_failure)

    def test_the_pipeline_writes_no_incident_state_of_its_own(self):
        actions = ActionsFake(runs=[run_payload(621, SHA_A, branch='main', event='push')],
                              jobs={621: [job(1)]}, log_text=BAD_EXCERPT)
        built = service(actions, BoardFake(), self.state, log_reader=actions.log_reader)
        built.pipeline.poll_once(now=T0 + dt.timedelta(minutes=1))
        tables = {row[0] for row in built.store.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn('incidents', tables)
        self.assertNotIn('events', tables)
        self.assertIn('deliveries', tables)
        built.close()

    def test_environment_config_bounds_values_and_names_the_state_file(self):
        cfg, state = environment_config({'LO_CI_REPOSITORY': REPO, 'LO_CI_STATE_DIR': self.temp.name,
                                        'LO_CI_FILE_CARDS': 'on', 'LO_CI_CARD_OCCURRENCES': '4',
                                        'LO_CI_CARD_DISTINCT_SHAS': '3',
                                        'LO_CI_MAIN_BRANCHES': 'trunk,main'})
        self.assertTrue(cfg.file_cards)
        self.assertEqual(('trunk', 'main'), cfg.main_branches)
        self.assertEqual(4, cfg.thresholds.occurrences)
        self.assertTrue(str(state).endswith('ci-failures.sqlite3'))
        off, _ = environment_config({'LO_CI_REPOSITORY': REPO})
        self.assertFalse(off.file_cards, 'board writes are off unless the operator turns them on')
        for environ in ({'LO_CI_REPOSITORY': REPO, 'LO_CI_STUCK_AFTER_SECONDS': 'nope'},
                        {'LO_CI_REPOSITORY': 'not-a-repo'},
                        {'LO_CI_REPOSITORY': REPO, 'LO_CI_CARD_WINDOW_DAYS': '30'}):
            with self.subTest(str(sorted(environ))):
                with self.assertRaises(CiFailureError):
                    environment_config(environ)


EPOCH_PLACEHOLDER = '1970-01-01T00:00:00Z'


def gitea_run(run_id, sha, *, path, event='push', status='completed', conclusion='failure',
              head_branch=None, started=T0 - dt.timedelta(minutes=4), completed=T0):
    """One run object in the shape the live Actions API was captured answering.

    `path` is the only field naming the workflow and the ref; `workflow_id`, `head_branch`,
    `created_at` and `updated_at` are null or absent; the instants that do exist are `started_at` and
    `completed_at`, and an unfinished run carries the epoch placeholder in `completed_at`. Synthetic
    identifiers only -- nothing here is a host, a repository or a token from any real deployment.
    """
    return {'id': run_id, 'path': path, 'event': event, 'status': status, 'conclusion': conclusion,
            'head_sha': sha, 'head_branch': head_branch, 'workflow_id': None,
            'created_at': None, 'updated_at': None, 'started_at': iso(started),
            'completed_at': EPOCH_PLACEHOLDER if status != 'completed' else iso(completed)}


def gitea_job(job_id, name='build', *, status='completed', conclusion='failure',
              created=T0 - dt.timedelta(minutes=10), started=T0 - dt.timedelta(minutes=2),
              completed=T0, steps=None):
    """One job object in the captured shape: the run's missing `created_at` exists at job level."""
    return {'id': job_id, 'run_id': 1, 'name': name, 'status': status, 'conclusion': conclusion,
            'created_at': iso(created), 'started_at': iso(started),
            'completed_at': EPOCH_PLACEHOLDER if status != 'completed' else iso(completed),
            'steps': steps if steps is not None else
            [{'name': 'checkout', 'status': 'completed', 'conclusion': 'success'},
             {'name': 'unit tests', 'status': 'completed', 'conclusion': conclusion}]}


class PagedActions:
    """An Actions fake that honours the page-size parameter the caller really sends (`limit`).

    The live endpoint ignored `per_page` and obeyed `limit`, so a fake that read `per_page` would pass
    while the pipeline over-read. This one refuses the test if a request omits `limit`.
    """

    def __init__(self, *, runs=(), jobs=None, endless_jobs=False):
        self.runs = sorted(runs, key=lambda row: -int(row['id']))
        self.jobs = {int(key): list(value) for key, value in (jobs or {}).items()}
        self.endless_jobs = endless_jobs
        self.calls: list[tuple[str, dict]] = []

    def request(self, method, path, *, params=None, payload=None):
        assert method == 'GET', 'the Actions fake only ever receives GET'
        assert payload is None
        query = dict(params or {})
        self.calls.append((path, query))
        size = int(query.get('limit', 0))
        assert size > 0, f'a list request without the Gitea limit parameter: {path} {query}'
        page = int(query.get('page', 1))
        if path.endswith('/actions/runs'):
            rows = self.runs[(page - 1) * size:page * size]
            return 200, {'total_count': len(self.runs), 'workflow_runs': rows}
        match = re.search(r'/actions/runs/(\d+)/jobs$', path)
        if match:
            if self.endless_jobs:
                return 200, {'total_count': 999, 'jobs': [gitea_job(700 + page * 10 + index)
                                                          for index in range(size)]}
            ordered = self.jobs.get(int(match.group(1)), [])
            return 200, {'total_count': len(ordered), 'jobs': ordered[(page - 1) * size:page * size]}
        single = re.search(r'/actions/runs/(\d+)$', path)
        if single:
            for row in self.runs:
                if int(row['id']) == int(single.group(1)):
                    return 200, dict(row)
            return 404, {'message': 'not found'}
        if re.search(r'/actions/runs/\d+/jobs/\d+/logs$', path):
            return 200, ''
        raise AssertionError(f'unexpected Actions path {path}')


class OverDeliveringRuns:
    """A source that ignores the requested page size, exactly as the live endpoint did with per_page."""

    def __init__(self, rows):
        self.rows = list(rows)
        self.calls: list[dict] = []

    def request(self, method, path, *, params=None, payload=None):
        assert method == 'GET'
        self.calls.append(dict(params or {}))
        if re.search(r'/actions/runs/\d+$', path):
            return 404, {'message': 'not found'}
        return 200, {'total_count': len(self.rows), 'workflow_runs': self.rows}


class PagedBoard:
    """The board endpoint answering a fixed table of rows, paged by the `limit` it is handed."""

    def __init__(self, rows=None, *, endless=False):
        self.rows = list(rows if rows is not None else [{'number': 1, 'title': 'card'}])
        self.endless = endless
        self.calls: list[dict] = []

    def request(self, method, path, *, params=None, payload=None):
        assert method == 'GET'
        query = dict(params or {})
        self.calls.append((path, query))
        size = int(query.get('limit', 0))
        assert size > 0, f'a board list request without the Gitea limit parameter: {query}'
        page = int(query.get('page', 1))
        # `endless` over-delivers: the source answers more rows than the bound it was given, which is
        # what the live endpoint did to a `per_page` it ignored.
        rows = self.rows[:size + 2] if self.endless else self.rows[(page - 1) * size:page * size]
        return 200, rows


class LiveContractParsingTests(unittest.TestCase):
    def test_parent_ref_preserves_branch_and_nested_workflow_identity(self):
        one = parse_run(REPO, gitea_run(901, SHA_A, path='group-a/ci.yml@refs/heads/main'))
        two = parse_run(REPO, gitea_run(902, SHA_A, path='group-b/ci.yml@refs/heads/main'))
        self.assertEqual('main', one.head_branch)
        self.assertNotEqual(event_identity(one), event_identity(two))

    def test_parent_wrong_typed_timestamps_are_refused(self):
        for value in [True, 7, {}, []]:
            payload = gitea_run(903, SHA_A, path='ci.yml@refs/heads/main')
            payload['completed_at'] = value
            with self.subTest(value=value), self.assertRaises(MalformedSource):
                parse_run(REPO, payload)

    def test_parent_completion_time_precedes_creation_for_occurrence(self):
        payload = gitea_run(904, SHA_A, path='ci.yml@refs/heads/main')
        payload['created_at'] = '2026-01-01T00:00:00Z'
        payload['completed_at'] = '2026-01-01T00:10:00Z'
        fact = parse_run(REPO, payload)
        self.assertEqual(fact.completed_at, fact.observed_at)

    def test_parent_oversize_workflow_id_is_not_truncated(self):
        payload = gitea_run(905, SHA_A, path='ci.yml@refs/heads/main')
        payload['workflow_id'] = 10 ** 80
        with self.assertRaises(MalformedSource):
            parse_run(REPO, payload)

    """The response shape the real Gitea Actions API answers with, asserted field by field."""

    def test_a_main_push_arrives_as_a_path_and_keeps_its_workflow_plane_and_verdict(self):
        fact = parse_run(REPO, gitea_run(900, SHA_A, path='ci.yml@refs/heads/main'))
        self.assertEqual('ci.yml', fact.workflow_id)
        self.assertEqual('ci.yml', fact.workflow_name)
        self.assertEqual('path', fact.workflow_source)
        self.assertEqual('main', fact.plane)
        self.assertTrue(fact.is_failure)
        self.assertEqual('failure', fact.failure_class())
        self.assertEqual('main', fact.head_branch, 'the branch is established by the explicit heads ref')
        self.assertIsNone(fact.created_at)
        self.assertIsNone(fact.updated_at)
        self.assertEqual(iso(T0 - dt.timedelta(minutes=4)), fact.started_at.isoformat()
                         .replace('+00:00', 'Z'))
        self.assertNotIn('unknown', (fact.workflow_id, fact.workflow_name))

    def test_two_workflows_on_one_sha_are_distinct_events_and_distinct_cards(self):
        ci = parse_run(REPO, gitea_run(901, SHA_A, path='ci.yml@refs/heads/main'))
        nightly = parse_run(REPO, gitea_run(902, SHA_A, path='nightly.yml@refs/heads/main'))
        self.assertEqual(ci.head_sha, nightly.head_sha)
        self.assertNotEqual(event_identity(ci), event_identity(nightly))
        self.assertNotEqual(card_identity(ci).fingerprint, card_identity(nightly).fingerprint)

    def test_a_pull_ref_is_the_work_plane_even_when_branch_and_event_say_main(self):
        row = gitea_run(903, SHA_A, path='ci.yml@refs/pull/1068/head', event='push',
                        head_branch='main', status='completed', conclusion='success')
        row['pull_requests'] = [{'base': {'ref': 'main'}, 'head': {'ref': 'main'}}]
        fact = parse_run(REPO, row)
        self.assertEqual('pull', fact.plane)
        self.assertEqual(1068, fact.pr_number)
        self.assertFalse(fact.is_failure)  # success in the fixture, and never a main-red either
        self.assertIn('run-ref-outranks-branch-evidence', fact.coverage_reasons())
        route = parse_run_path('ci.yml@refs/pull/1068/head')
        self.assertEqual(('ci.yml', 'pull', None, 1068),
                         (route.workflow, route.plane, route.branch, route.pr_number))

    def test_a_pull_ref_routed_from_a_failing_run_is_still_not_main_red(self):
        fact = parse_run(REPO, gitea_run(904, SHA_A, path='ci.yml@refs/pull/1068/head',
                                         head_branch='main'))
        self.assertEqual('pull', fact.plane)
        self.assertTrue(fact.is_failure)
        self.assertEqual(1, len([note for note in fact.coverage
                                 if note.reason == 'run-ref-outranks-branch-evidence']))

    def test_unreadable_run_paths_are_refused_rather_than_silently_bucketed(self):
        for label, path in (('no extension', 'checkout@refs/heads/main'),
                            ('unknown ref prefix', 'ci.yml@refs/notes/main'),
                            ('two refs', 'ci.yml@refs/heads/main@refs/heads/dev'),
                            ('traversal', '../secrets/ci.yml@refs/heads/main'),
                            ('empty segment', 'ci//yml@refs/heads/main'),
                            ('not a string', 4711)):
            with self.subTest(label):
                row = dict(gitea_run(905, SHA_A, path='ci.yml@refs/heads/main'), path=path)
                with self.assertRaises(MalformedSource):
                    parse_run(REPO, row)

    def test_a_head_branch_that_contradicts_the_ref_is_refused(self):
        row = gitea_run(906, SHA_A, path='ci.yml@refs/heads/main', head_branch='release/7')
        with self.assertRaises(MalformedSource):
            parse_run(REPO, row)

    def test_a_run_naming_no_workflow_is_refused_rather_than_bucketed_as_unknown(self):
        row = gitea_run(907, SHA_A, path='ci.yml@refs/heads/main')
        del row['path']
        with self.assertRaises(MalformedSource):
            parse_run(REPO, row)
        del row['workflow_id']
        with self.assertRaises(MalformedSource):
            parse_run(REPO, row)

    def test_a_path_without_a_ref_routes_on_the_fallback_and_says_so(self):
        fact = parse_run(REPO, dict(gitea_run(908, SHA_A, path='ci.yml@refs/heads/main'),
                                    path='ci.yml'), jobs=[gitea_job(1)])
        self.assertEqual('ci.yml', fact.workflow_id)
        self.assertEqual('branch', fact.plane)
        self.assertIn('run-path-without-ref', fact.coverage_reasons())

    def test_the_epoch_completed_at_placeholder_is_unavailable_not_a_1970_moment(self):
        fact = parse_run(REPO, gitea_run(909, SHA_A, path='ci.yml@refs/heads/main',
                                         status='in_progress', conclusion=None))
        self.assertIsNone(fact.completed_at)
        self.assertEqual('in_progress', fact.status)
        self.assertFalse(is_failure(fact.status, fact.conclusion))
        self.assertIn('timestamp-unavailable', fact.coverage_reasons())
        self.assertIsNone(fact.started_waiting_at, 'no real queue stamp exists, so none is invented')

    def test_job_created_at_supplies_queue_timing_with_a_recorded_justification(self):
        queued = T0 - dt.timedelta(minutes=30)
        jobs = [gitea_job(11, name='build', status='in_progress', conclusion=None,
                          created=queued, started=T0 - dt.timedelta(minutes=1))]
        fact = parse_run(REPO, gitea_run(910, SHA_A, path='ci.yml@refs/heads/main',
                                         status='in_progress', conclusion=None), jobs=jobs)
        self.assertEqual(queued, fact.started_waiting_at)
        self.assertIn('queue-time-from-job-created-at', fact.coverage_reasons())
        self.assertEqual(queued, fact.jobs[0].created_at)
        self.assertEqual(T0 - dt.timedelta(minutes=1), fact.jobs[0].started_at)
        self.assertIsNone(fact.jobs[0].completed_at)

    def test_malformed_or_missing_job_timestamps_fail_or_stay_absent_without_invention(self):
        broken = dict(gitea_job(12), created_at='yesterday')
        with self.assertRaises(MalformedSource) as caught:
            parse_run(REPO, gitea_run(911, SHA_A, path='ci.yml@refs/heads/main',
                                      status='in_progress', conclusion=None), jobs=[broken])
        self.assertIn('created_at', str(caught.exception))
        silent = {key: value for key, value in gitea_job(13).items() if key != 'created_at'}
        fact = parse_run(REPO, gitea_run(912, SHA_A, path='ci.yml@refs/heads/main',
                                         status='queued', conclusion=None), jobs=[silent])
        self.assertIsNone(fact.jobs[0].created_at)
        self.assertIsNone(fact.started_waiting_at)
        self.assertNotIn('queue-time-from-job-created-at', fact.coverage_reasons())

    def test_a_github_shaped_run_still_routes_on_its_branch_and_names_its_workflow(self):
        fact = parse_run(REPO, run_payload(913, SHA_A, branch='main', event='push'))
        self.assertEqual('main', fact.plane)
        self.assertEqual('ci.yml', fact.workflow_id)
        self.assertEqual('fields', fact.workflow_source)


class LiveContractPaginationTests(unittest.TestCase):
    """Bounded reads, asserted on the outgoing request as well as on the rows that come back."""

    def setUp(self):
        self.rows = [gitea_run(1000 - index, SHA_A, path='ci.yml@refs/heads/main')
                     for index in range(9)]

    def test_run_pages_are_requested_with_the_parameter_gitea_honours(self):
        transport = PagedActions(runs=self.rows)
        source = ActionsSource(transport, REPO, per_page=4)
        rows = source.runs(page=2)
        self.assertEqual(4, len(rows))
        self.assertEqual({'page': 2, 'per_page': 4, 'limit': 4}, transport.calls[0][1])

    def test_a_page_longer_than_its_bound_is_malformed_not_the_end_of_history(self):
        source = ActionsSource(OverDeliveringRuns(self.rows), REPO, per_page=4)
        with self.assertRaises(MalformedSource):
            source.runs(page=1, per_page=4)

    def test_job_pages_are_walked_with_the_same_bound_and_stop_on_a_short_page(self):
        jobs = [gitea_job(20 + index, name=f'job-{index}') for index in range(7)]
        transport = PagedActions(runs=[], jobs={500: jobs})
        source = ActionsSource(transport, REPO, per_page=3)
        self.assertEqual(7, len(source.jobs(500)))
        self.assertEqual(['page:1', 'page:2', 'page:3'],
                         [f"page:{query['page']}" for _, query in transport.calls])
        self.assertTrue(all(query['limit'] == 3 and query['per_page'] == 3
                            for _, query in transport.calls))

    def test_an_unfinished_job_walk_is_a_refusal_after_a_finite_number_of_pages(self):
        transport = PagedActions(runs=[], jobs={501: [gitea_job(30)]}, endless_jobs=True)
        source = ActionsSource(transport, REPO, per_page=3)
        with self.assertRaises(PaginationBudget):
            source.jobs(501, max_pages=4)
        self.assertEqual(4, len(transport.calls), 'the walk is bounded, not open-ended')

    def test_the_job_bound_the_parser_enforces_is_the_bound_the_walk_enforces(self):
        self.assertEqual(MAX_JOBS, MAX_JOBS_PER_RUN)

    def test_board_list_walks_carry_the_gitea_limit_too(self):
        transport = PagedBoard(rows=[{'number': 10 + index, 'title': 'card'} for index in range(9)])
        board = BoardClient(transport, REPO, per_page=4)
        self.assertEqual(9, len(board.open_issues()))
        self.assertEqual([1, 2, 3], [query['page'] for _, query in transport.calls])
        self.assertTrue(all(query['limit'] == 4 and query['per_page'] == 4
                            for _, query in transport.calls))
        self.assertEqual({'page': 1, 'per_page': 4, 'limit': 4, 'state': 'open', 'type': 'issues'},
                         transport.calls[0][1])
        labels = BoardClient(PagedBoard(rows=[{'id': 7, 'name': 'aiops'}]), REPO, per_page=2)
        self.assertEqual({'aiops': 7}, labels.label_ids())
        self.assertEqual(2, labels.per_page)
        comments = PagedBoard(rows=[])
        client = BoardClient(comments, REPO, per_page=3)
        self.assertEqual([], client.issue_comments(7))
        self.assertEqual([], client.open_issues(max_pages=1))
        self.assertEqual({'page': 1, 'per_page': 3, 'limit': 3}, comments.calls[0][1])
        self.assertEqual({'page': 1, 'per_page': 3, 'limit': 3, 'state': 'open', 'type': 'issues'},
                         comments.calls[1][1])

    def test_a_board_page_that_ignores_its_bound_is_refused_not_trusted(self):
        board = BoardClient(PagedBoard(rows=[{'number': index} for index in range(6)], endless=True),
                            REPO, per_page=4)
        with self.assertRaises(MalformedSource):
            board.open_issues()
        with self.assertRaises(MalformedSource):
            board.label_ids()


class LiveContractPipelineTests(unittest.TestCase):
    """The same shape through the real object graph, so a contract defect fails the tick it breaks."""

    def setUp(self):
        self.state = tempfile.mkdtemp() + '/ci.sqlite3'

    def test_a_live_shaped_main_failure_files_one_card_routed_as_main_red(self):
        board = BoardFake()
        actions = PagedActions(runs=[gitea_run(1001, SHA_A, path='ci.yml@refs/heads/main')],
                               jobs={1001: [gitea_job(41, name='unit-tests')]})
        built = service(actions, board, self.state,
                        cfg=config(per_page=5, max_pages=2, file_cards=True))
        report = built.pipeline.poll_once(now=T0)
        self.assertEqual(1, report.recorded)
        self.assertEqual(1, len(board.created))
        self.assertIn('main red:', board.created[0]['title'])
        self.assertIn('ci.yml', board.created[0]['title'])
        built.close()

    def test_a_work_plane_failure_from_a_pull_ref_files_no_main_card(self):
        board = BoardFake()
        actions = PagedActions(
            runs=[gitea_run(1002, SHA_A, path='ci.yml@refs/pull/1068/head', head_branch='main')],
            jobs={1002: [gitea_job(42, name='unit-tests')]})
        built = service(actions, board, self.state,
                        cfg=config(per_page=5, max_pages=2, file_cards=True))
        built.pipeline.poll_once(now=T0)
        self.assertEqual(0, len(board.created), 'one PR failure is below the filing threshold')
        self.assertEqual(1002, built.store.cursor(), 'the walk finished and committed')
        self.assertTrue(all('refs/heads/main' not in row['detail'] for row in
                            built.store.coverage_rows(limit=20)))
        built.close()

    def test_a_queued_epoch_run_waits_instead_of_looking_stuck_since_1970(self):
        board = BoardFake()
        actions = PagedActions(
            runs=[gitea_run(1003, SHA_A, path='ci.yml@refs/heads/main',
                            status='queued', conclusion=None)], jobs={1003: []})
        built = service(actions, board, self.state,
                        cfg=config(per_page=5, max_pages=2, file_cards=True))
        report = built.pipeline.poll_once(now=T0 + dt.timedelta(hours=2))
        self.assertEqual(1, report.recorded)
        self.assertEqual(0, len(board.created),
                         'the epoch placeholder must not read as 24 hours of starvation')
        self.assertEqual(0, report.cursor, 'an unfinished run does not move the cursor')
        built.close()

    def test_an_over_delivered_run_page_leaves_the_cursor_and_claims_nothing(self):
        board = BoardFake()
        actions = OverDeliveringRuns([gitea_run(1004 + index, SHA_A, path='ci.yml@refs/heads/main')
                                      for index in range(3)])
        built = service(actions, board, self.state,
                        cfg=config(per_page=2, max_pages=3, file_cards=True))
        report = built.pipeline.poll_once(now=T0)
        self.assertEqual('MalformedSource', report.error)
        self.assertFalse(report.complete)
        self.assertEqual(0, report.recorded)
        self.assertEqual(0, report.cursor)
        self.assertEqual(0, len(board.created))
        self.assertEqual(1, len(actions.calls), 'one bounded request, then the refusal')
        self.assertEqual('actions-read-failed', built.store.coverage_rows()[0]['reason'])
        built.close()

    def test_an_unbounded_job_list_is_coverage_on_its_run_not_a_green_build(self):
        board = BoardFake()
        actions = PagedActions(runs=[gitea_run(1005, SHA_A, path='ci.yml@refs/heads/main')],
                               jobs={1005: [gitea_job(43)]}, endless_jobs=True)
        built = service(actions, board, self.state,
                        cfg=config(per_page=5, max_pages=2, file_cards=True))
        report = built.pipeline.poll_once(now=T0)
        self.assertEqual(1, report.recorded)
        self.assertEqual(1, len(board.created), 'main-red is still filed, coarsely')
        detail = json.dumps(built.store.run_detail(REPO, 1005))
        self.assertIn('job-list-unavailable', detail)
        self.assertIn('job-list-absent', card_identity(
            parse_run(REPO, gitea_run(1005, SHA_A, path='ci.yml@refs/heads/main'))).reasons)
        built.close()


if __name__ == '__main__':
    unittest.main()

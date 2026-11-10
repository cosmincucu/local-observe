"""CI failure ingestion (`local_observe/ci_failures`) — the CI failure ingestion section C in product form.

Everything here is offline: the two scoped transports are injected fakes that record calls, and the
integration tier patches `socket.socket` and `urllib.request.urlopen` to raise, so "no socket was
opened" is proved rather than asserted. What the fakes let this file test is the *real* object graph —
`build_service` is called with the same arguments a deployment uses, so a wiring defect (a board outlet
handed the GET-only Actions client, a pipeline that shares one credential across two scopes) fails
here instead of on a host.

The scenarios below are the failure modes this outlet cannot be trusted without:

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
import email.message
from contextlib import ExitStack
from dataclasses import replace
import io
import json
import logging
import os
import re
import socket
import sys
import tempfile
from typing import Any
import unittest
from unittest import mock
import urllib.error
import urllib.request

from local_observe.ci_failures import (ActionsSource, BoardClient, BoardOutlet, CiFailureError,
                                       CiFailureStore, JsonTransport, MalformedSource, OutletConfig,
                                       PaginationBudget, Pipeline, PipelineConfig, PlatformAdmission,
                                       ScopeRefused, SourceUnavailable, Thresholds, admission_ready,
                                       build_events, build_service, card_identity, environment_config,
                                       parse_run)
from local_observe.ci_failures.adapter import (MAX_COVERAGE_EVENTS, MAX_SNAPSHOT_CHARS,
                                              COVERAGE_SUBJECT, PULL_STATUS, RULE_COVERAGE,
                                              RULE_FAILURE, RULE_STUCK, SOURCE, KeyTransition,
                                              coverage_rule, plan_incident_keys, resource_id_for_key)
from local_observe.ci_failures.facts import (MAX_JOBS, CoverageNote, coverage_only_fact, incident_key,
                                             event_identity, is_failure, parse_run_path, plane_of)
from local_observe.ci_failures.platform_client import PlatformIntake
from local_observe.ci_failures.transports import JobLogClient, MAX_LOG_CHARS, MAX_JOBS_PER_RUN
from local_observe.http import JsonClient, MAX_ERROR_BODY_BYTES, TransportError
from local_observe.ci_failures.facts import scrub_excerpt
from local_observe.ci_failures.outlet import OWNED_MARKER, batch_token, fingerprint_of_body
from local_observe.ci_failures.pipeline import COVERAGE_SOURCE
from local_observe.ci_failures.store import (PENDING_EVIDENCE_LIFETIME_DAYS, PENDING_MAX_ATTEMPTS,
                                              PENDING_VERDICTS_BOUND, KEY_MARKER_PREFIX,
                                              STATE_DELIVERED, StoreError)
from local_observe.ci_failures import store as ci_store_module
import sqlite3
from local_observe.inventory.validation import timestamp, utc_text
from local_observe.platform.detections import event as canonical_event
from local_observe.platform.state import (Actor, StateError, Store, identifier,
                                          label as bounded_label, validate_event)

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


def coverage_markers(state: str) -> dict[str, dict[str, int]]:
    """This source's own coverage markers, read straight out of the state file.

    The second half of every coverage claim: what the platform was told is one table, what this poller
    still believes is the other, and a `resolved` that reached the first while the second still names the
    run that carried the gap is the defect the tests around here are about.
    """
    with CiFailureStore(state) as store:
        return store.incident_key_state(COVERAGE_SUBJECT)


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

    def test_a_verdict_the_platform_never_took_waits_in_the_state_file_byte_for_byte(self):
        store = CiFailureStore(self.state)
        fact = parse_run(REPO, run_payload(51, SHA_A), jobs=[job(1)])
        store.record_facts([fact], cursor=51, now=T0)
        event = next(event for event in plan_incident_keys([fact], None, now=T0).events
                     if event['rule_id'] == RULE_FAILURE)
        subject, rule = incident_key(fact), RULE_FAILURE
        rows = [{'key': subject, 'rule_id': rule, 'event': event, 'open_run': 51,
                 'closed_run': None, 'reason': 'not_configured'}]

        self.assertEqual(1, store.record_pending_verdicts(rows, now=T0).written)
        waiting = store.pending_verdicts()[subject][rule]
        # The bytes have to come back identical, because `Store.intake` answers a retry whose contents
        # changed with `Event retry changed contents`: a verdict that mutates on the way to disk is a
        # verdict that can never be re-offered.
        self.assertEqual(event, waiting['event'], 'the stored verdict is the event, unchanged')
        self.assertEqual(51, waiting['open_run'])
        self.assertEqual('not_configured', waiting['reason'])
        self.assertEqual(1, waiting['attempts'])
        self.assertEqual(1, store.pending_verdict_count())
        self.assertEqual(1, store.status(now=T0)['counts']['verdicts_pending'],
                         '`--status` counts what is owed')
        # The same verdict decided on a later poll counts as a second attempt and keeps the stamp of the
        # poll that decided it: an event that has waited three days must look like one.
        store.record_pending_verdicts(rows, now=T0 + dt.timedelta(minutes=30))
        again = store.pending_verdicts()[subject][rule]
        self.assertEqual(2, again['attempts'])
        self.assertEqual(store.pending_verdicts()[subject][rule]['at'], again['at'])
        store.close()

        reopened = CiFailureStore(self.state)
        self.assertEqual(2, reopened.pending_verdicts()[subject][rule]['attempts'],
                         'a restart does not cancel a verdict the platform never took')
        # A refusal on the way in is a refusal on the way out: a subject that could not be a subject
        # cannot be trusted to name a verdict either, and the whole call is one transaction.
        with self.assertRaises(StoreError):
            reopened.record_pending_verdicts([{'key': 'unsafe subject', 'rule_id': rule,
                                              'event': event}], now=T0)
        self.assertEqual(1, reopened.pending_verdict_count())
        self.assertEqual(1, reopened.drop_pending_verdicts([(subject, rule)]))
        self.assertEqual({}, reopened.pending_verdicts())
        reopened.close()

    def test_more_verdicts_waiting_than_the_bound_lose_the_one_that_has_waited_longest(self):
        """The bound drops the oldest row, and says which one it was.

        Two halves, and the second is the one an operator reads: the table cannot grow, so something has to
        give, and the row that gave is a page this source will not send. `pending_verdicts` reads 200
        whether 200 verdicts wait or 261 were decided and 61 left, so the write returns what it evicted and
        the tick report names it beside the rows the two ceilings retired.
        """
        store = CiFailureStore(self.state)
        fact = parse_run(REPO, run_payload(52, SHA_A), jobs=[job(1)])
        event = next(event for event in plan_incident_keys([fact], None, now=T0).events
                     if event['rule_id'] == RULE_FAILURE)
        for index in range(PENDING_VERDICTS_BOUND):
            store.record_pending_verdicts([{'key': f'pending-{index:04d}', 'rule_id': RULE_FAILURE,
                                           'event': event, 'open_run': 52}],
                                         now=T0 + dt.timedelta(minutes=index))
        self.assertEqual(PENDING_VERDICTS_BOUND, store.pending_verdict_count())
        written = store.record_pending_verdicts([{'key': 'pending-newest', 'rule_id': RULE_FAILURE,
                                                 'event': event, 'open_run': 52}],
                                               now=T0 + dt.timedelta(minutes=PENDING_VERDICTS_BOUND))
        waiting = store.pending_verdicts()
        self.assertEqual(PENDING_VERDICTS_BOUND, store.pending_verdict_count(),
                         'the table stays bounded without a schema migration')
        self.assertIn('pending-newest', waiting)
        self.assertNotIn('pending-0000', waiting,
                         'the verdict that has waited longest is the one most likely to be moot')
        self.assertIn('pending-0001', waiting)
        self.assertEqual(1, written.written, 'the row written is counted separately from the row dropped')
        self.assertEqual(1, len(written.evicted), f'and the drop is reported: {written.evicted}')
        gone = written.evicted[0]
        self.assertEqual({'key', 'rule_id', 'reason', 'attempts', 'decided_at', 'event_status'},
                         set(gone), 'the same shape `expire_pending_verdicts` returns, so one list holds both')
        self.assertEqual('pending-0000', gone['key'])
        self.assertEqual(RULE_FAILURE, gone['rule_id'])
        self.assertEqual(event['status'], gone['event_status'],
                         'the status the row carried, so a reader can tell a firing from a closure')
        self.assertEqual(1, gone['attempts'])
        self.assertEqual(utc_text(T0), gone['decided_at'],
                         'the report names the poll that decided it, which is the one to look at')
        self.assertIn(str(PENDING_VERDICTS_BOUND), gone['reason'],
                      f'the bound is the reason and it is said out loud: {gone["reason"]}')
        store.close()

    def test_retention_prunes_the_facts_but_not_the_verdict_still_owed(self):
        store = CiFailureStore(self.state)
        stale = parse_run(REPO, run_payload(53, SHA_A, when=T0 - dt.timedelta(days=400)),
                         jobs=[job(1)])
        store.record_facts([stale], cursor=53, now=T0 - dt.timedelta(days=400))
        event = next(event for event in plan_incident_keys([stale], None, now=T0).events
                     if event['rule_id'] == RULE_FAILURE)
        store.record_pending_verdicts([{'key': incident_key(stale), 'rule_id': RULE_FAILURE,
                                       'event': event, 'open_run': 53}], now=T0 - dt.timedelta(days=400))

        counts = store.prune(now=T0)
        self.assertEqual(1, counts['runs'], 'the run itself is history nobody re-reads')
        self.assertEqual(1, store.pending_verdict_count(),
                         'pruning the owed verdict is how an outage silently cancels a page')
        self.assertEqual([{'event': event, 'open_run': 53, 'closed_run': None,
                          'reason': '', 'at': utc_text(T0 - dt.timedelta(days=400)), 'attempts': 1}],
                         [row for rules in store.pending_verdicts().values() for row in rules.values()])
        store.close()

    def test_a_marker_that_named_both_halves_cannot_drag_open_below_the_newest_firing(self):
        """`open` moves backwards for one writer only, and naming a closure is not that writer.

        The rule is that `closed` may run ahead of `open` while an older verdict is still in flight (a
        replay out of the pending table can arrive after a newer one landed), and the only hand that may
        lower `open` is the closure, which says so by handing over `open_run=0`. A caller that sends both
        halves at once (`open_run=800, closed_run=900`) is claiming a firing and a closure in one breath;
        honouring its `open` half would rewind a marker the platform took at run 900, and the next green
        run at 850 would then be told the incident is already closed -- so the failure it can still see
        files nothing, and nothing re-opens it.
        """
        store = CiFailureStore(self.state)
        subject = 'acme.widgets.ci.yml.main:deadbeef'
        store.record_incident_keys([KeyTransition(subject, RULE_FAILURE, open_run=900)], now=T0)
        store.record_incident_keys([KeyTransition(subject, RULE_FAILURE, open_run=800,
                                                 closed_run=900)], now=T0)
        rung = store.incident_key_state(subject)[RULE_FAILURE]
        self.assertEqual(900, rung['open'], 'the newer firing the platform took stays the newest firing')
        self.assertEqual(900, rung['closed'], 'and the half that was true is still recorded')
        # The closure itself is the exception, and it is spelled `open_run=0`: nothing is open any more.
        store.record_incident_keys([KeyTransition(subject, RULE_FAILURE, open_run=0,
                                                 closed_run=950)], now=T0)
        rung = store.incident_key_state(subject)[RULE_FAILURE]
        self.assertEqual({'open': 0, 'closed': 950}, rung)
        store.close()

    def test_the_answer_that_kept_a_verdict_owed_does_not_count_as_a_second_offer(self):
        """The write before the send is the attempt; the write that explains the row afterwards is not.

        `attempts` is what retires a verdict the platform will never take, so it has to count offers and
        nothing else. A poll that restates a row with the refusal it actually received asked the platform
        once, and a counter that ticks twice per tick would abandon a deliverable verdict after half as
        many offers as the bound says.
        """
        store = CiFailureStore(self.state)
        fact = parse_run(REPO, run_payload(57, SHA_A), jobs=[job(1)])
        event = next(event for event in plan_incident_keys([fact], None, now=T0).events
                     if event['rule_id'] == RULE_FAILURE)
        subject, rule = incident_key(fact), RULE_FAILURE
        row = {'key': subject, 'rule_id': rule, 'event': event, 'open_run': 57, 'closed_run': None}

        store.record_pending_verdicts([{**row, 'reason': 'offered, no answer read back'}], now=T0)
        store.record_pending_verdicts([{**row, 'reason': 'intake refused with status 400'}], now=T0,
                                      counted=False)
        waiting = store.pending_verdicts()[subject][rule]
        self.assertEqual(1, waiting['attempts'], 'one offer, however many writes described it')
        self.assertEqual('intake refused with status 400', waiting['reason'],
                         'and the row still says why it is sitting there')
        store.record_pending_verdicts([{**row, 'reason': 'offered, no answer read back'}],
                                      now=T0 + dt.timedelta(minutes=5))
        self.assertEqual(2, store.pending_verdicts()[subject][rule]['attempts'],
                         'the next tick is the second offer')
        store.close()

    def test_a_verdict_that_cannot_converge_is_retired_and_handed_back_by_name(self):
        """Both ceilings on the owed table, read back rather than swallowed.

        A row the platform refuses on a rule (a clock skewed into the future, an id it cannot resolve) is
        refused identically forever, and an event whose evidence has expired pages about a window nobody
        can check any more. Either way the row has to go -- and `prune` is not the way, because retention
        knows nothing about delivery. What makes this a test instead of a deletion is the return value:
        an operator has to be able to see which page was cancelled, so the rows come back with the reason
        the retirement claims, and nothing is dropped on a date field this store could not read.
        """
        store = CiFailureStore(self.state)
        stale = parse_run(REPO, run_payload(58, SHA_A), jobs=[job(1)])
        event = next(event for event in plan_incident_keys([stale], None, now=T0).events
                     if event['rule_id'] == RULE_FAILURE)
        subject, rule = incident_key(stale), RULE_FAILURE
        row = {'key': subject, 'rule_id': rule, 'event': event, 'open_run': 58, 'closed_run': None}
        store.record_pending_verdicts([{**row, 'reason': 'refused'}], now=T0)
        self.assertEqual([], store.expire_pending_verdicts(now=T0 + dt.timedelta(days=1)),
                         'one refusal on a fresh verdict retires nothing')

        aged = store.pending_verdicts()[subject][rule]
        for _ in range(PENDING_MAX_ATTEMPTS - 1):
            store.record_pending_verdicts([{**row, 'reason': aged['reason']}], now=T0)
        self.assertEqual(PENDING_MAX_ATTEMPTS, store.pending_verdicts()[subject][rule]['attempts'])
        given_up = store.expire_pending_verdicts(now=T0 + dt.timedelta(days=2))
        self.assertEqual(1, len(given_up), f'the exhausted row is named: {given_up}')
        self.assertEqual({'key': subject, 'rule_id': rule, 'attempts': PENDING_MAX_ATTEMPTS},
                         {key: value for key, value in given_up[0].items()
                          if key in ('key', 'rule_id', 'attempts')})
        self.assertIn(f'{PENDING_MAX_ATTEMPTS} times', given_up[0]['reason'])
        self.assertEqual(0, store.pending_verdict_count(), 'and it is off the table, not still owed')

        # The other ceiling is the evidence's own: `detections.event` stamps `expires_at` a fixed lifetime
        # after the window, so a verdict decided before that instant cannot be delivered usefully again.
        long_ago = T0 - dt.timedelta(days=PENDING_EVIDENCE_LIFETIME_DAYS + 3)
        old = next(event for event in plan_incident_keys([stale], None, now=long_ago).events
                   if event['rule_id'] == RULE_FAILURE)
        store.record_pending_verdicts([{**row, 'event': old, 'reason': 'refused'}], now=long_ago)
        expired = store.expire_pending_verdicts(now=T0)
        self.assertEqual(1, len(expired))
        self.assertIn('evidence', expired[0]['reason'])
        self.assertEqual(utc_text(long_ago), expired[0]['decided_at'],
                         'the report says which poll owed it, which is the one an operator would check')
        self.assertEqual(0, store.pending_verdict_count())

        # An event whose dates this store cannot read is *kept*: the attempts ceiling is the honest way to
        # retire a row whose bytes are unintelligible, and dropping a page because a field did not parse
        # would be the store destroying the one thing it promised to keep.
        maimed = {key: value for key, value in old.items() if key not in ('window', 'evidence')}
        store.record_pending_verdicts([{**row, 'event': maimed, 'reason': 'refused'}], now=T0)
        self.assertEqual([], store.expire_pending_verdicts(now=T0 + dt.timedelta(days=900)))
        self.assertEqual(1, store.pending_verdict_count())
        store.close()

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
            with mock.patch.object(self.cli, '_moment', return_value=T0):
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
        self.assertEqual('firing', failure[0]['status'])
        branch = parse_run(REPO, run_payload(602, SHA_A, branch='feature/long', event='push'),
                           jobs=[job(1)], log=BAD_EXCERPT)
        branch_events = build_events(branch, card_identity(branch), now=T0)
        branch_failure = [event for event in branch_events if event['rule_id'] == RULE_FAILURE][0]
        self.assertEqual('warning', branch_failure['severity'])
        self.assertEqual('firing', branch_failure['status'], 'a scheduled or branch failure still opens')
        pull = parse_run(REPO, run_payload(603, SHA_A), jobs=[job(1)], log=BAD_EXCERPT)
        self.assertEqual('pull', pull.plane)
        pull_failure = [event for event in build_events(pull, card_identity(pull), now=T0)
                        if event['rule_id'] == RULE_FAILURE][0]
        self.assertEqual('info', pull_failure['severity'])
        self.assertEqual('unknown', pull_failure['status'],
                         'the pull plane is recorded and opens nothing, whatever the severity says')
        for event in events:
            validate_event(event, T0)

    def test_the_platform_outlet_may_not_share_the_actions_transport(self):
        """The third outlet POSTs, and one transport in two scopes means asking the forge for intake.

        The board-vs-Actions comparison already refused the pair that could comment on an issue with the
        wrong credential; the platform slot is the one that posts events, so the same check has to reach
        it. A bare callable in the admission slot is opaque and passes unjudged -- this refuses the shape
        this package builds, not every shape a host could invent.
        """
        actions = ActionsFake(runs=[], jobs={}, log_text='')
        shared = PlatformAdmission(PlatformIntake(actions).admit)
        with self.assertRaises(ScopeRefused) as caught:
            service(actions, None, self.state, admission=shared)
        self.assertIn('platform intake', str(caught.exception))
        self.assertEqual([], actions.calls, 'the refusal lands before anything is asked of a socket')

    def test_a_log_reader_that_raises_is_coverage_on_its_run_and_not_a_lost_tick(self):
        """The injected reader is a documented seam, so whatever it raises ends as a gap.

        `JobLogClient` swallows its own failures, but a caller may hand over any callable, and the
        documented default is the shape a caller could hand over next. A failure here is a gap in what
        this poller knows about one run -- not a reason to lose the failure that run carries, and not a
        traceback out of a `--once` that a timer unit has to read an exit code from.
        """
        def broken_reader(path):
            raise RuntimeError('the injected reader has no manners')

        actions = ActionsFake(runs=[run_payload(641, SHA_A, branch='main', event='push')],
                              jobs={641: [job(901)]}, log_text=BAD_EXCERPT)
        built = service(actions, None, self.state, log_reader=broken_reader,
                        admission=PlatformAdmission())
        try:
            with SocketGuard():
                report = built.pipeline.poll_once(now=T0)
        finally:
            built.close()
        self.assertIsNone(report.error, 'the tick completed: the gap is reported, not raised')
        self.assertEqual(1, report.recorded, 'the failing run is still a fact this store holds')
        fired = [receipt.rule_id for receipt in report.receipts
                 if receipt.rule_id == f'{RULE_COVERAGE}.job-log-unreachable']
        self.assertEqual(1, len(fired), f'one gap, one verdict: {report.receipts}')
        with CiFailureStore(self.state) as store:
            detail = store.run_detail(REPO, 641)
        self.assertIn('job-log-unreachable', ' '.join(detail['coverage']),
                      'the run itself carries the gap, so `--status` and a later card can read it')
        self.assertEqual(1, sum(1 for note in detail['coverage'] if 'job-log-unreachable' in note),
                         'one failed read is one note -- a doubled note doubles the gap it reports')

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


#: One intake outcome, spelled the way `Store.intake` spells it: `/v1/events` answers this dict, and
#: `/v1/intake/<source>` wraps one per event inside `{'source': ..., 'events': [...]}`.
PLATFORM_ACCEPTED = {'status': 'accepted', 'event_id': '3f2b0c00-0000-4000-8000-0000000000a1',
                     'incident_id': '7a1c0000-0000-4000-8000-0000000000b2', 'transition': 'opened'}
PLATFORM_TOKEN = 'platform-token-' + ('c' * 40)
LOG_TOKEN = 'job-log-token-' + ('d' * 40)
LOG_PATH = '/repos/acme/widgets/actions/runs/7/jobs/9/logs'

#: "the caller handed me no opinion about this slot", which a plain `None` cannot say.
_NO_PLATFORM = object()
_NO_READER = object()


class PlatformFake:
    """The platform's two intake routes, answered in the shapes `platform/api.py` really answers.

    A route named in `faults` raises instead of answering: that is how "the send did not complete" is
    tested with no socket, and the exception class is all the admitter is allowed to report.
    """

    def __init__(self, *, event=None, evidence=None, faults=()):
        self.event_answer = event if event is not None else (200, dict(PLATFORM_ACCEPTED))
        self.evidence_answer = evidence if evidence is not None else (200, {'evidence_id': 'ev-1'})
        self.faults = set(faults)
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[dict] = []

    @property
    def paths(self) -> list[str]:
        return [path for _method, path in self.calls]

    def request(self, method, path, *, params=None, payload=None):
        assert method == 'POST', f'the platform fake only ever receives POST: {method} {path}'
        assert params is None, 'an intake request carries no query string'
        assert path in ('/v1/events', '/v1/evidence'), f'unknown platform route {path}'
        self.calls.append((method, path))
        self.bodies.append(dict(payload or {}))
        if path in self.faults:
            raise OSError('connection reset on the way to the platform')
        answer = self.event_answer if path == '/v1/events' else self.evidence_answer
        return answer[0], answer[1]


class StoreBackedPlatform:
    """The intake routes served by a real `platform.state.Store`, in this process, with no socket.

    Answering from a fixed receipt would prove only what this package reports; answering from the store
    proves what the platform *has*, which is the claim an incident source exists to make. The actor is
    the producer identity a CI credential carries, and `Store.intake` refuses an event whose `source`
    differs from it -- so a producer posting CI events under somebody else's token fails here instead of
    on a host.
    """

    def __init__(self, path, *, now=T0):
        self.store = Store(path)
        self.actor = Actor(SOURCE, 'producer')
        self.now = now
        self.calls: list[tuple[str, str]] = []

    @property
    def paths(self) -> list[str]:
        return [path for _method, path in self.calls]

    def incidents(self) -> dict[str, set[str]]:
        """`rule_id -> the incident ids the platform filed for it`, read out of its own tables."""
        filed: dict[str, set[str]] = {}
        for row in self.store.records('events'):
            rule = json.loads(row['payload'])['rule_id']
            filed.setdefault(rule, set()).add(row['incident_id'])
        return filed

    def offered(self, rule_id: str) -> list[dict]:
        """The event bodies the platform kept for one rule, oldest first -- what it was actually told."""
        rows = list(reversed(self.store.records('events')))
        return [json.loads(row['payload']) for row in rows
                if json.loads(row['payload'])['rule_id'] == rule_id]

    def status_of(self, rule_id: str) -> str | None:
        """`open` / `resolved` for the incident one rule's conditions point at, or None if there is none.

        `open` wins over `resolved` when a rule has more than one incident: the question this answers is
        "is the platform still paging about this rule", and one open incident is the loud answer.
        """
        wanted = {row['incident_id'] for row in self.store.records('events')
                  if row['incident_id'] and json.loads(row['payload'])['rule_id'] == rule_id}
        states = {row['status'] for row in self.store.records('incidents') if row['id'] in wanted}
        if 'open' in states:
            return 'open'
        return 'resolved' if states else None

    def request(self, method, path, *, params=None, payload=None):
        assert method == 'POST' and path in ('/v1/events', '/v1/evidence'), f'{method} {path}'
        self.calls.append((method, path))
        if path == '/v1/events':
            return 200, self.store.intake(dict(payload), self.actor, now=self.now)
        return 200, {'evidence_id': self.store.put_evidence(dict(payload), self.actor, now=self.now)}


class RefusablePlatform(StoreBackedPlatform):
    """`StoreBackedPlatform` with a hiccup switch: answer 503 for a tick, then serve from the store again.

    `PlatformFake` can refuse but cannot say what the platform *has*, and a real store cannot be told to
    refuse at all. The tests about a refused send -- a closure the platform would not take, a row the bound
    evicted, an incident stranded by an upgrade recipe -- need both halves: the refusal, and the incident
    table to read back once the refusal ends.
    """

    def __init__(self, path, *, now=T0, refusing=False):
        super().__init__(path, now=now)
        self.refusing = refusing

    def request(self, method, path, *, params=None, payload=None):
        if self.refusing and path == '/v1/events':
            return 503, {'error': 'unavailable'}
        return super().request(method, path, params=params, payload=payload)


class PlatformIntakeTests(unittest.TestCase):
    """`platform_client.PlatformIntake`: what came back, and the only claims that answer permits."""

    def _events(self, run_id=9001, sha=SHA_A, when=T0):
        fact = parse_run(REPO, run_payload(run_id, sha, branch='main', event='push'), jobs=[job(1)],
                         log=BAD_EXCERPT)
        return build_events(fact, card_identity(fact), now=when)

    def test_an_accepted_intake_is_admitted_and_names_the_platform_record(self):
        platform = PlatformFake()
        events = self._events()
        receipts = PlatformAdmission(PlatformIntake(platform).admit).admit(events)
        self.assertEqual(['admitted'] * len(events), [receipt.status for receipt in receipts])
        self.assertEqual({PLATFORM_ACCEPTED['event_id']}, {receipt.record_id for receipt in receipts},
                         "the record id is the platform's, not the event's position in the batch")
        self.assertEqual(['/v1/events'] * len(events), platform.paths)

    def test_a_duplicate_is_admitted_because_the_platform_already_holds_the_event(self):
        platform = PlatformFake(event=(200, {'status': 'duplicate',
                                            'event_id': PLATFORM_ACCEPTED['event_id'],
                                            'incident_id': PLATFORM_ACCEPTED['incident_id']}))
        receipts = PlatformAdmission(PlatformIntake(platform).admit).admit(self._events()[:1])
        self.assertEqual(['admitted'], [receipt.status for receipt in receipts],
                         'a re-send the platform folded is still "the platform has it"')

    def test_the_nested_envelope_receipt_maps_to_the_entry_for_this_event(self):
        nested = {'source': SOURCE, 'events': [dict(PLATFORM_ACCEPTED),
                                               {'status': 'accepted', 'event_id': 'second-event-id',
                                                'incident_id': 'second-incident-id',
                                                'resource_link': 'unresolved'}]}
        receipts = PlatformAdmission(PlatformIntake(PlatformFake(event=(200, nested))).admit) \
            .admit(self._events()[:1])
        self.assertEqual('admitted', receipts[0].status)
        self.assertEqual(PLATFORM_ACCEPTED['event_id'], receipts[0].record_id,
                         'the envelope answer names its events in payload order: the first is this one')

    def test_a_2xx_that_receipts_nothing_is_a_refusal(self):
        events = self._events()[:1]
        for body in ({'source': SOURCE, 'events': []}, {'error': 'internal_error'}, {'detail': 'x'},
                     [], 'accepted', None):
            with self.subTest(str(body)):
                answer = PlatformIntake(PlatformFake(event=(200, body))).admit(events[0])
                receipts = PlatformAdmission(lambda event: answer).admit(events)
                self.assertEqual('refused', receipts[0].status, f'{body} read as admission')
                self.assertTrue(receipts[0].reason)

    def test_a_2xx_detail_is_not_lifted_into_the_reason_that_travels_everywhere(self):
        """The non-2xx rule (`_error_code`: code travels, prose does not) has a 2xx half.

        `platform/api.py` puts its rendered exception message in `detail`, and this path used to lift it
        into the receipt reason whenever a 2xx carried nothing else. A receipt reason is kept in this
        source's state file and printed in its report, so the lift copied endpoint prose -- which can quote
        the bytes of a request, a query, or a credential -- into durable storage on a path that looked
        safe because "the status said 200". A 2xx that names no `reason` is refused as `rejected`: the one
        word that is true and belongs to this package.
        """
        events = self._events()[:1]
        leaky = {'detail': 'duplicate key value violates unique "ci_idx" token: supersecretvalue12345'}
        answer = PlatformIntake(PlatformFake(event=(200, leaky))).admit(events[0])
        receipts = PlatformAdmission(lambda event: answer).admit(events)
        self.assertEqual('refused', receipts[0].status)
        self.assertEqual('rejected', receipts[0].reason, 'a reason, not the endpoint\'s prose')
        self.assertNotIn('supersecretvalue', json.dumps([receipt.as_dict() for receipt in receipts]))
        # `reason` is still honoured when the admitter supplies one -- this is not a ban on explanations,
        # it is a ban on importing somebody else's unbounded string as this source's verdict.
        explained = PlatformAdmission(lambda event: {'reason': 'stale_watermark'}).admit(events)
        self.assertEqual('stale_watermark', explained[0].reason)

    def test_a_2xx_refusal_that_names_its_stable_code_in_error_is_heard(self):
        """Both field names the platform uses for a stable code are read; prose in any other is not.

        `platform_client._receipt` reads a 2xx body's `error` as the refusal's reason, and `platform/api.py`
        writes its stable codes under exactly that key -- but the receipt then travels through `_classify`,
        which looked only at `reason`. A host admitter that hands back `{'accepted': False, 'error':
        'id_conflict'}` was therefore reported as the bare word `rejected`: the one outcome the rule beside
        it claims cannot happen. `reason` still wins when an admitter supplies both, and `detail` -- the
        rendered exception message -- is still not a reason whatever else the body does.
        """
        events = self._events()[:1]
        coded = PlatformAdmission(lambda event: {'accepted': False, 'error': 'id_conflict'}).admit(events)
        self.assertEqual('refused', coded[0].status)
        self.assertEqual('id_conflict', coded[0].reason,
                         "the platform's own word for what it refused, not this package's guess")
        both = PlatformAdmission(lambda event: {'reason': 'stale_watermark',
                                                'error': 'id_conflict'}).admit(events)
        self.assertEqual('stale_watermark', both[0].reason, 'the field this boundary owns comes first')
        prose = PlatformAdmission(lambda event: {'accepted': False,
                                                 'detail': 'duplicate key token abc123xyz'}).admit(events)
        self.assertEqual('rejected', prose[0].reason, 'and a body naming no code says nothing more than that')
        self.assertNotIn('abc123xyz', json.dumps([receipt.as_dict() for receipt in prose]))

    def test_a_non_2xx_is_a_refused_receipt_naming_the_status_and_the_stable_code(self):
        platform = PlatformFake(event=(403, {'error': 'forbidden', 'detail': 'token abc123xyz'}))
        receipts = PlatformAdmission(PlatformIntake(platform).admit).admit(self._events()[:1])
        self.assertEqual('refused', receipts[0].status)
        self.assertEqual('intake refused with status 403: forbidden', receipts[0].reason,
                         "the status and the platform's stable code travel; the body does not")
        self.assertNotIn('abc123xyz', receipts[0].reason,
                         'a `detail` is a rendered exception message and can echo a credential')

    def test_a_non_2xx_with_no_body_is_still_the_status_and_nothing_invented(self):
        platform = PlatformFake(event=(502, None))
        answer = PlatformIntake(platform).admit(self._events()[0])
        self.assertEqual('refused', answer['status'])
        self.assertEqual('intake refused with status 502', answer['reason'],
                         'a body this platform did not send is not a reason this client may invent')

    def test_the_stable_code_survives_the_real_http_client_that_served_it(self):
        """The whole chain, with a `JsonClient` in it: body off the wire, code into the receipt.

        `platform_client._error_code` and `platform/api.py`'s refusal shape agree with each other, and the
        test above feeds the body in by hand -- which is how the middle of the chain went unnoticed: the
        `JsonClient` that a real deployment builds answered every error status with `(code, None)`, so the
        stable code was parsed by a function that was never handed a body, and every intake refusal in the
        field reported no more than "status 400". This runs the shipping transport, opener patched, and
        no socket exists anywhere in it.
        """
        refused = json.dumps({'error': 'run_reference_unknown',
                              'detail': 'run 9 is not in the window token abc123xyz'}).encode()
        client = JsonClient('https://platform.example.invalid', PLATFORM_TOKEN, scheme='Bearer',
                            error_body=True)
        requests: list = []
        client.opener = _FakeOpener(requests, error=_http_error(400, refused))
        events = self._events()
        receipts = PlatformAdmission(PlatformIntake(JsonTransport(client)).admit).admit(events)
        self.assertEqual(['refused'] * len(events), [receipt.status for receipt in receipts])
        for receipt in receipts:
            self.assertEqual('intake refused with status 400: run_reference_unknown', receipt.reason,
                             "the endpoint's own word for what it refused")
            self.assertNotIn('abc123xyz', receipt.reason, 'and not the prose wrapped around it')
        self.assertEqual(1, len(requests), 'evidence is posted before the event, and this ended at the '
                                           'first refusal: one request, not a retry storm')

    def test_a_failed_send_is_a_refusal_naming_the_exception_class_and_nothing_else(self):
        answer = PlatformIntake(PlatformFake(faults={'/v1/events'})).admit(self._events()[0])
        self.assertEqual('unavailable', answer['status'])
        self.assertEqual('unavailable: OSError', answer['reason'])

    def test_the_store_saying_no_is_a_refusal_and_not_an_outage(self):
        """`StateError` is the platform's own refusal class, and an outage is a different diagnosis.

        `platform/api.py` answers it with a 400, and an in-process store raises it straight to the
        caller. Folding it into `unavailable` sends an operator to look at a network that is fine: the
        store has the event, it simply refuses this one. The platform's sentence is carried because it
        names what to fix, and it is bounded because it is still somebody else's text.
        """
        class Refusing:
            def request(self, method, path, *, params=None, payload=None):
                raise StateError('Conflicting evaluations at the same condition watermark')

        intake = PlatformIntake(Refusing())
        answer = intake.admit(self._events()[0])
        self.assertEqual('refused', answer['status'], 'a 400-shaped no must not read as "retry later"')
        self.assertIn('Conflicting evaluations', answer['reason'])
        self.assertLessEqual(len(answer['reason']), 120, 'a sentence, bounded, not a stack')
        receipt = PlatformAdmission(intake.admit).admit(self._events()[:1])[0]
        self.assertEqual('refused', receipt.status,
                         'and the report the operator reads calls it a refusal too')
        self.assertNotIn('unavailable', receipt.reason)

    def test_evidence_goes_first_when_the_event_names_a_sample(self):
        sample = {'sample_id': 'sample-1', 'observed_at': utc_text(T0), 'ok': True, 'value': False}
        platform = PlatformFake()
        answer = PlatformIntake(platform, evidence_for=lambda event: [sample]).admit(self._events()[0])
        self.assertTrue(answer['accepted'])
        self.assertEqual(['/v1/evidence', '/v1/events'], platform.paths,
                         'the order intake.py names: the stored sample, then the event citing it')
        self.assertEqual(sample, platform.bodies[0])

    def test_a_refused_sample_withholds_the_event_that_cites_it(self):
        sample = {'sample_id': 'sample-1', 'observed_at': utc_text(T0), 'ok': True, 'value': False}
        platform = PlatformFake(evidence=(503, {'error': 'unavailable'}))
        answer = PlatformIntake(platform, evidence_for=lambda event: [sample]).admit(self._events()[0])
        self.assertEqual(['/v1/evidence'], platform.paths,
                         'an event whose sample was never stored is a dead link, so it is not sent')
        self.assertIn('evidence refused with status 503', answer['reason'])

    def test_an_event_naming_another_source_is_a_wiring_refusal(self):
        event = dict(self._events()[0], source='other_producer')
        with self.assertRaises(CiFailureError):
            PlatformIntake(PlatformFake()).admit(event)

    def test_the_intake_source_is_fixed_and_its_routes_are_the_platforms_two(self):
        self.assertEqual(('/v1/evidence', '/v1/events'), PlatformIntake(PlatformFake()).routes)
        with self.assertRaises(CiFailureError):
            PlatformIntake(PlatformFake(), source='alertmanager')

    def test_a_wiring_mistake_in_this_seam_is_refused_at_construction(self):
        with self.assertRaises(CiFailureError):
            PlatformIntake(object())  # an object with no request method to post with
        with self.assertRaises(CiFailureError):
            PlatformIntake(PlatformFake(), evidence_for='sample-1')  # not a resolver

    def test_sending_something_that_is_not_an_event_is_refused_before_the_send(self):
        platform = PlatformFake()
        with self.assertRaises(CiFailureError):
            PlatformIntake(platform).admit(PLATFORM_ACCEPTED['event_id'])
        self.assertEqual([], platform.calls, 'and the platform is not asked about it')

    def test_an_answer_that_is_not_an_object_is_a_refused_receipt(self):
        receipts = PlatformAdmission(PlatformIntake(PlatformFake(event=(200, 'accepted'))).admit) \
            .admit(self._events()[:1])
        self.assertEqual('refused', receipts[0].status)
        self.assertEqual('the platform answered without a receipt', receipts[0].reason)

    def test_a_nested_entry_that_is_not_an_object_is_a_refused_receipt(self):
        nested = {'source': SOURCE, 'events': ['not-an-event-record']}
        receipts = PlatformAdmission(PlatformIntake(PlatformFake(event=(200, nested))).admit) \
            .admit(self._events()[:1])
        self.assertEqual('the platform receipt entry is not an object', receipts[0].reason)

    def test_a_sample_send_that_dies_is_a_refusal_and_the_event_stays_unsent(self):
        sample = {'sample_id': 'sample-1', 'observed_at': utc_text(T0), 'ok': True, 'value': False}
        platform = PlatformFake(faults={'/v1/evidence'})
        answer = PlatformIntake(platform, evidence_for=lambda event: [sample]).admit(self._events()[0])
        self.assertEqual('unavailable: OSError', answer['reason'])
        self.assertEqual(['/v1/evidence'], platform.paths)

    def test_a_sample_accepted_without_naming_its_id_withholds_the_event(self):
        sample = {'sample_id': 'sample-1', 'observed_at': utc_text(T0), 'ok': True, 'value': False}
        platform = PlatformFake(evidence=(200, {'status': 'ok'}))
        answer = PlatformIntake(platform, evidence_for=lambda event: [sample]).admit(self._events()[0])
        self.assertIn('evidence refused without an id', answer['reason'])
        self.assertEqual(['/v1/evidence'], platform.paths)

    def test_the_sample_resolver_is_bounded_and_typed(self):
        event = self._events()[0]
        with self.assertRaises(CiFailureError):
            PlatformIntake(PlatformFake(), evidence_for=lambda e: [{'sample_id': str(index)}
                                                                  for index in range(21)]).admit(event)
        with self.assertRaises(CiFailureError):
            PlatformIntake(PlatformFake(), evidence_for=lambda e: ['not-a-sample']).admit(event)
        quiet = PlatformFake()
        self.assertTrue(PlatformIntake(quiet, evidence_for=lambda e: []).admit(event)['accepted'])
        self.assertEqual(['/v1/events'], quiet.paths, 'an empty resolver posts nothing, as it should')


class JobLogReaderTests(unittest.TestCase):
    """`transports.JobLogClient`: the one Actions read that answers text, and what it must not do."""

    def setUp(self):
        self.requests: list = []

    def _client(self, *, status=200, body=b'job log tail', error=None, **kwargs):
        opener = _FakeOpener(self.requests, status=status, body=body, error=error)
        return JobLogClient('https://forge.example.invalid/api/v1', LOG_TOKEN, opener=opener, **kwargs)

    def _read(self, client, run_id=7, job_id=9):
        return ActionsSource(StubTransport({}), REPO, log_reader=client).job_log(run_id, job_id)

    def test_the_reader_returns_the_text_and_bears_the_actions_token(self):
        status, text = self._client(body=b'2026-09-22 boom in test_suite.py')(LOG_PATH)
        self.assertEqual(200, status)
        self.assertIn('boom', text)
        request = self.requests[0]
        self.assertEqual('https://forge.example.invalid/api/v1' + LOG_PATH, request.full_url)
        self.assertEqual('token ' + LOG_TOKEN, request.headers['Authorization'])
        self.assertEqual('GET', request.method)

    def test_a_long_log_arrives_as_its_tail_so_the_card_hashes_the_failure(self):
        body = b'HEAD' + (b'x' * 40000) + b'The assertion that actually failed'
        read = self._read(self._client(body=body))
        self.assertEqual('job-log-truncated', read.coverage)
        self.assertTrue(read.truncated)
        self.assertTrue(read.excerpt.endswith('The assertion that actually failed'),
                        'the end of a long log is its tail, not the end of whatever was read first')

    def test_an_error_status_stays_a_status_and_an_unreachable_log_is_its_own_gap(self):
        refused = self._read(self._client(status=410, body=b''))
        self.assertEqual('job-log-status-410', refused.coverage)
        self.assertIsNone(refused.excerpt)
        http_error = urllib.error.HTTPError('https://forge.example.invalid/api/v1' + LOG_PATH, 410,
                                            'Gone', email.message.Message(), io.BytesIO(b''))
        self.assertEqual('job-log-status-410', self._read(self._client(error=http_error)).coverage)
        offline = self._read(self._client(error=OSError('no route to host')))
        self.assertEqual('job-log-unreachable', offline.coverage,
                         '"the endpoint refused" and "there was no endpoint" are different repairs')

    def test_the_reader_refuses_a_path_it_was_not_given(self):
        client = self._client()
        for path in ('/repos/acme/widgets/issues', '/repos/acme/widgets/actions/runs/7/jobs/9',
                     '/repos/acme/../../etc/passwd', 'https://other.invalid/v1/events', ''):
            with self.subTest(path), self.assertRaises(ScopeRefused):
                client(path)
        self.assertEqual([], self.requests, 'the refusal lands before any connection')

    def test_the_reader_refuses_a_base_or_token_it_cannot_bound(self):
        for base in ('http://forge.example.invalid', 'https://user@forge.example.invalid',
                     'https://forge.example.invalid?token=x', 'not-a-url'):
            with self.subTest(base), self.assertRaises(CiFailureError):
                JobLogClient(base, LOG_TOKEN)
        with self.assertRaises(CiFailureError):
            JobLogClient('https://forge.example.invalid', 'short')
        with self.assertRaises(CiFailureError):
            JobLogClient('https://forge.example.invalid', LOG_TOKEN + '\n')

    def test_loopback_http_is_admitted_only_when_development_asked_for_it(self):
        client = JobLogClient('http://127.0.0.1:3000/api/v1', LOG_TOKEN, allow_http=True,
                              opener=_FakeOpener(self.requests, body=b'ok'))
        self.assertEqual((200, 'ok'), client(LOG_PATH))
        with self.assertRaises(CiFailureError):
            JobLogClient('http://127.0.0.1:3000/api/v1', LOG_TOKEN)


class _FakeResponse:
    """The two things `JobLogClient` reads off a connection: a status, and bytes on demand."""

    def __init__(self, status, chunks):
        self.status = status
        self._chunks = list(chunks)

    def read(self, size=-1):
        return self._chunks.pop(0) if self._chunks else b''

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


class _FakeOpener:
    """Stands in for `urllib.request.OpenerDirector`: one fixed answer, or one fixed failure."""

    def __init__(self, requests, *, status=200, body=b'', error=None, chunk=65536):
        self.requests = requests
        self.status = status
        self.body = body
        self.error = error
        self.chunk = chunk

    def open(self, request, timeout=None):
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        pieces = [self.body[start:start + self.chunk] for start in range(0, len(self.body), self.chunk)]
        return _FakeResponse(self.status, pieces)


def _http_error(status, body):
    """One real `HTTPError` -- the shape `urllib` raises, with a body `JsonClient` can read off it.

    `body` is the bytes an endpoint sent, or any object a caller wants hung in the response slot so a
    read from it can be made to fail.
    """
    fp = io.BytesIO(body) if isinstance(body, bytes) else body
    return urllib.error.HTTPError('https://platform.example.invalid/v1/events', status, 'refused',
                                  email.message.Message(), fp)


class ErrorAnswerTests(unittest.TestCase):
    """`http.JsonClient`'s answer to an error status, and the one caller that asked to see its body.

    Every caller in this repository asked "did it work?", and for a long time the honest answer was the
    status alone: the client dropped the body of a non-2xx answer on the floor. That is now a choice the
    caller makes (`error_body`), and the choice is only worth having if the default stays exactly what it
    was -- thirty-odd callers that read `(status, body)` and treat a body on an error status as a success
    payload would otherwise change behaviour one endpoint at a time, in production.
    """

    BASE = 'https://platform.example.invalid'
    TOKEN = PLATFORM_TOKEN

    def setUp(self):
        self.requests: list = []

    def _client(self, *, status=400, body=b'', error=None, **kwargs):
        client = JsonClient(self.BASE, self.TOKEN, scheme='Bearer', **kwargs)
        client.opener = _FakeOpener(self.requests, status=status, body=body, error=error)
        return client

    def _refusal(self, client):
        return client.request('POST', '/v1/events', payload={'source': 'gitea_ci'})

    def test_an_endpoint_that_explains_itself_is_heard_by_the_caller_that_asked(self):
        answer = json.dumps({'error': 'run_reference_unknown', 'detail': 'rendered prose'}).encode()
        status, body = self._refusal(self._client(status=400, body=answer, error=_http_error(400, answer),
                                                  error_body=True))
        self.assertEqual(400, status)
        self.assertEqual('run_reference_unknown', body['error'],
                         'the stable code is the part an operator can act on')

    def test_the_answer_every_other_caller_was_written_against_is_unchanged(self):
        answer = json.dumps({'error': 'run_reference_unknown'}).encode()
        for label, client in (('default', self._client(error=_http_error(400, answer))),
                              ('opt-out', self._client(error=_http_error(400, answer),
                                                       error_body=False))):
            with self.subTest(label):
                self.assertEqual((400, None), self._refusal(client),
                                 'a body nobody asked for is still not handed over')
        with self.assertRaises(TransportError):
            # An endpoint that never answered has one answer in this package, and an error-body caller
            # does not get a second one: there is no body to read, and `TransportError` is the report.
            self._client(error=OSError('no route to host'), error_body=True).request('GET', '/v1/events')
        # A 2xx is untouched by the option: the bound, the parse and the `accept_non_json` rule are the
        # same code path every other caller uses.
        self.assertEqual((200, {'ok': True}),
                         self._client(status=200, body=b'{"ok": true}',
                                      error_body=True).request('GET', '/v1/events'))

    def test_an_error_body_this_client_cannot_use_stays_the_status_alone(self):
        """Bounded, JSON or nothing -- and a body that will not arrive is not a new failure either."""
        oversized = json.dumps({'error': 'x', 'pad': 'y' * (MAX_ERROR_BODY_BYTES + 10)}).encode()
        cases = {'a page instead of an answer': b'<html><body>500</body></html>',
                 'bigger than an answer ever is': oversized,
                 'nothing at all': b''}
        for label, raw in cases.items():
            with self.subTest(label):
                status, body = self._refusal(self._client(error=_http_error(400, raw), error_body=True))
                self.assertEqual((400, None), (status, body))

        class Unreadable:
            """A response object whose own body read fails -- a truncated chunked answer, say."""

            def read(self, size=-1):
                raise OSError('connection reset while reading the error body')

            def close(self):
                return None

        status, body = self._refusal(self._client(error=_http_error(400, Unreadable()), error_body=True))
        self.assertEqual((400, None), (status, body),
                         'the caller asked what the status was, and that is still what it gets')

    def test_the_only_way_to_ask_for_an_error_body_is_to_ask_for_it(self):
        for value in ('yes', 1, None, 0):
            with self.subTest(value=value), self.assertRaises(TransportError):
                JsonClient(self.BASE, self.TOKEN, error_body=value)
        for value in (True, False):
            with self.subTest(accepted=value):
                self.assertIs(value, JsonClient(self.BASE, self.TOKEN, error_body=value).error_body)

    def test_the_scoped_transport_passes_the_answer_through_and_nothing_else(self):
        """`JsonTransport` is the seam the platform client holds; it may not eat the body it is handed."""
        answer = json.dumps({'error': 'id_conflict', 'detail': 'x' * 400}).encode()
        client = self._client(error=_http_error(409, answer), error_body=True)
        status, body = JsonTransport(client).request('POST', '/v1/events', payload={'a': 1})
        self.assertEqual(409, status)
        self.assertEqual('id_conflict', body['error'])


class IncidentSourceCliTests(unittest.TestCase):
    """The CLI as an incident source: no board, or a board, or a platform -- and the refusal between them.

    Every test runs the real `cli.main`, and lets it resolve its own outlets: `cli._http_transport` is the
    one place a `JsonClient` is constructed and `cli._log_reader` the one place the object that owns a
    connection is built, so patching those two leaves nothing between this process and a socket while
    still running the real `_wiring` that decides which outlets exist. That decision is what is under
    test -- the shape that had never run, because the board transport used to be mandatory and the
    platform could be wired only by a test calling `build_service` directly.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = f'{self.temp.name}/ci.sqlite3'
        from local_observe.ci_failures import cli

        self.cli = cli
        self.built: dict = {}

    def tearDown(self):
        self.temp.cleanup()

    def _main(self, argv, *, environ, actions, board=None, platform=_NO_PLATFORM, reader=_NO_READER,
              moment=T0, seam=True):
        """One `main()` that resolves its own outlets, with the client factory replaced.

        Leaving `transports` absent is the point: the CLI then runs `_wiring`, so which bases were named,
        which outlets were built at all, and what Authorization scheme each credential goes out under are
        facts read back from this run (`built`) rather than inferred from the source. `seam=False` leaves
        the real factory in place, which is what a credential refusal needs -- building a `JsonClient`
        opens no socket, and `SocketGuard` proves the rest.
        """
        rows = {'LO_CI_ACTIONS': actions, 'LO_CI_BOARD': board, 'LO_CI_PLATFORM': platform}

        def fake_transport(base, prefix, given, *, allow_http, scheme='token', error_body=False):
            self.built[prefix] = (base, scheme, error_body)
            if rows[prefix] is _NO_PLATFORM:
                raise AssertionError(f'the CLI built a {prefix} transport nobody configured: {base}')
            return rows[prefix]

        def fake_reader(base, prefix, given, *, allow_http):
            self.built[f'reader:{prefix}'] = (base, allow_http)
            return None if reader is _NO_READER else reader

        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        # `create=True` so a build of this CLI that has no job-log reader to wire can still be handed the
        # patch: the unchanged-behaviour guard below then fails only on behaviour, never on the harness.
        patches = [mock.patch.object(self.cli, '_moment', return_value=moment),
                   mock.patch.object(self.cli, '_log_reader', side_effect=fake_reader, create=True)]
        if seam:
            patches.append(mock.patch.object(self.cli, '_http_transport', side_effect=fake_transport))
        with ExitStack() as stack:
            for item in patches:
                stack.enter_context(item)
            try:
                code = self.cli.main(argv, environ=environ)
            finally:
                out, err = sys.stdout.getvalue(), sys.stderr.getvalue()
                sys.stdout, sys.stderr = stdout, stderr
        return code, out, err

    def _failing(self, run_id=1001, sha=SHA_A, **kwargs):
        return ActionsFake(runs=[run_payload(run_id, sha, branch='main', event='push', **kwargs)],
                           jobs={run_id: [job(901)]}, log_text=BAD_EXCERPT)

    def test_a_tick_with_no_board_at_all_polls_records_and_sends_nothing(self):
        actions = self._failing()
        with SocketGuard():
            code, out, err = self._main(['--once', '--state', self.state,
                                         '--actions-url', 'https://forge.example.invalid'],
                                        environ={'LO_CI_REPOSITORY': REPO,
                                                 'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                        actions=actions)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        report = json.loads(out)
        self.assertEqual(1, report['recorded'])
        self.assertEqual(1001, report['cursor'])
        self.assertEqual('not-configured', report['platform_admission'])
        self.assertEqual(0, report['admitted'], 'nothing may be claimed as sent')
        self.assertEqual([], report['planned'])
        self.assertIsNone(report['drained'], 'no outlet, so no delivery report to read')
        self.assertNotIn('LO_CI_BOARD', self.built, 'no board URL means no board transport is built')
        self.assertEqual('https://forge.example.invalid/api/v1', self.built['LO_CI_ACTIONS'][0],
                         'the forge base is still completed with the API prefix its clients build on')

    def test_filing_cards_without_a_board_is_refused_before_any_request(self):
        actions = self._failing(1002)
        with SocketGuard():
            code, out, err = self._main(['--once', '--state', f'{self.temp.name}/a.sqlite3',
                                         '--actions-url', 'https://forge.example.invalid',
                                         '--file-cards'],
                                        environ={'LO_CI_REPOSITORY': REPO,
                                                 'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                        actions=actions)
        self.assertEqual(self.cli.EXIT_REFUSED, code)
        self.assertIn('board filing needs a board', err)
        self.assertEqual(1, len(err.strip().splitlines()), 'one line, not a stack of advice')
        self.assertEqual([], actions.calls, 'the refusal lands before the first read')
        self.assertEqual('', out)

    def test_filing_cards_by_environment_without_a_board_is_refused_too(self):
        code, out, err = self._main(['--once', '--state', f'{self.temp.name}/b.sqlite3',
                                     '--actions-url', 'https://forge.example.invalid'],
                                    environ={'LO_CI_REPOSITORY': REPO, 'LO_CI_FILE_CARDS': 'on',
                                             'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                    actions=self._failing(1003))
        self.assertEqual(self.cli.EXIT_REFUSED, code)
        self.assertIn('board filing needs a board', err)

    def test_a_configured_board_still_scans_files_and_reports_as_before(self):
        actions, board = self._failing(1004), BoardFake()
        code, out, err = self._main(['--once', '--state', f'{self.temp.name}/c.sqlite3',
                                     '--actions-url', 'https://forge.example.invalid',
                                     '--board-url', 'https://board.example.invalid', '--file-cards'],
                                    environ={'LO_CI_REPOSITORY': REPO,
                                             'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN,
                                             'LO_CI_BOARD_TOKEN': BOARD_TOKEN},
                                    actions=actions, board=board)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual(1, len(board.created), 'a named board still gets its outlet')
        self.assertEqual('not-configured', json.loads(out)['platform_admission'],
                         'and card filing still says nothing at all about the platform')
        self.assertEqual(('https://board.example.invalid/api/v1', 'token', False),
                         self.built['LO_CI_BOARD'],
                         'the board scope asks for no error body: its callers read a status, and http\'s '
                         'default keeps their answer byte-for-byte what it was')

    def test_a_wired_platform_turns_one_failure_into_admitted_receipts(self):
        actions, platform = self._failing(1005), PlatformFake()
        code, out, err = self._main(['--once', '--state', f'{self.temp.name}/d.sqlite3',
                                     '--actions-url', 'https://forge.example.invalid',
                                     '--platform-url', 'https://platform.example.invalid'],
                                    environ={'LO_CI_REPOSITORY': REPO}, actions=actions,
                                    platform=platform)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        report = json.loads(out)
        self.assertEqual('admitted', report['platform_admission'])
        self.assertEqual(report['events'], report['admitted'])
        self.assertEqual(['/v1/events'] * report['events'], platform.paths,
                         'a CI event cites a query, not a stored sample: nothing to pre-post')
        self.assertEqual([SOURCE] * report['events'], [body['source'] for body in platform.bodies])

    def test_the_platform_url_is_validated_and_its_credential_goes_as_a_bearer(self):
        code, out, err = self._main(['--once', '--state', f'{self.temp.name}/e.sqlite3',
                                     '--actions-url', 'https://forge.example.invalid',
                                     '--platform-url', 'https://platform.example.invalid'],
                                    environ={'LO_CI_REPOSITORY': REPO,
                                             'LO_CI_PLATFORM_TOKEN': PLATFORM_TOKEN},
                                    actions=self._failing(1006), platform=PlatformFake())
        self.assertEqual(self.cli.EXIT_OK, code, err)
        base, scheme, error_body = self.built['LO_CI_PLATFORM']
        self.assertEqual('https://platform.example.invalid', base,
                         'the platform serves /v1/events off its root: /api/v1 would 404 every send')
        self.assertEqual('Bearer', scheme, 'platform/api.py compares Bearer <token> and nothing else')
        self.assertTrue(error_body, 'and this is the one scope whose endpoint explains its refusals, so '
                                    'this is the one transport that is told to read the answer body')
        self.assertNotIn(PLATFORM_TOKEN, out + err)

    def test_a_plain_http_platform_url_is_refused_unless_development_said_so(self):
        for argv, expected in ((['--platform-url', 'http://platform.invalid'], self.cli.EXIT_REFUSED),
                               (['--platform-url', 'http://platform.invalid', '--allow-http'],
                                self.cli.EXIT_OK)):
            code, out, err = self._main(['--once', '--state', f'{self.temp.name}/f.sqlite3',
                                         '--actions-url', 'https://forge.example.invalid'] + argv,
                                        environ={'LO_CI_REPOSITORY': REPO},
                                        actions=self._failing(1007), platform=PlatformFake())
            with self.subTest(' '.join(argv)):
                self.assertEqual(expected, code, err or out)
        code, out, err = self._main(['--once', '--state', f'{self.temp.name}/f2.sqlite3',
                                     '--actions-url', 'https://forge.example.invalid',
                                     '--platform-url', 'https://user@platform.invalid'],
                                    environ={'LO_CI_REPOSITORY': REPO}, actions=self._failing(1008),
                                    platform=PlatformFake())
        self.assertEqual(self.cli.EXIT_REFUSED, code)
        self.assertIn('no credentials or query', err)

    def test_a_platform_that_refuses_is_reported_and_exits_unavailable(self):
        platform = PlatformFake(event=(400, {'error': 'invalid_request',
                                            'detail': 'a detail that must not travel'}))
        code, out, err = self._main(['--once', '--state', f'{self.temp.name}/g.sqlite3',
                                     '--actions-url', 'https://forge.example.invalid',
                                     '--platform-url', 'https://platform.example.invalid'],
                                    environ={'LO_CI_REPOSITORY': REPO}, actions=self._failing(1009),
                                    platform=platform)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code)
        report = json.loads(out)
        self.assertEqual('refused', report['platform_admission'])
        self.assertEqual(0, report['admitted'])
        self.assertEqual(report['events'], len(report['receipts']))
        self.assertEqual({'intake refused with status 400: invalid_request'},
                         {receipt['reason'] for receipt in report['receipts']},
                         'the platform\'s stable code is the reason an operator gets to see')
        self.assertNotIn('must not travel', out + err, 'a platform body is not pasted into a report')
        self.assertNotIn('Traceback', out + err)

    def test_a_platform_that_is_unreachable_is_a_refusal_not_a_traceback(self):
        platform = PlatformFake(faults={'/v1/events'})
        captured = LogCapture()
        captured.install()
        try:
            code, out, err = self._main(['--once', '--state', f'{self.temp.name}/h.sqlite3',
                                         '--actions-url', 'https://forge.example.invalid',
                                         '--platform-url', 'https://platform.example.invalid'],
                                        environ={'LO_CI_REPOSITORY': REPO,
                                                 'LO_CI_PLATFORM_TOKEN': PLATFORM_TOKEN},
                                        actions=self._failing(1010), platform=platform)
        finally:
            captured.remove()
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code)
        report = json.loads(out)
        self.assertEqual('refused', report['platform_admission'])
        self.assertEqual(report['events'], len(report['receipts']), 'every event keeps its own answer')
        self.assertEqual({'unavailable: OSError'},
                         {receipt['reason'] for receipt in report['receipts']})
        for blob in [out, err, '\n'.join(captured.records)]:
            self.assertNotIn(PLATFORM_TOKEN, blob)
            self.assertNotIn('c' * 40, blob)
            self.assertNotIn('Traceback', blob)

    def test_a_missing_platform_credential_is_a_refusal_not_a_traceback(self):
        with SocketGuard():
            code, out, err = self._main(['--once', '--state', f'{self.temp.name}/k.sqlite3',
                                         '--actions-url', 'https://forge.example.invalid',
                                         '--platform-url', 'https://platform.example.invalid'],
                                        environ={'LO_CI_REPOSITORY': REPO,
                                                 'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                        actions=self._failing(1011), seam=False)
        self.assertEqual(self.cli.EXIT_REFUSED, code)
        self.assertIn('LO_CI_PLATFORM_TOKEN', err)
        self.assertNotIn('Traceback', err)

    def test_a_client_that_cannot_complete_is_an_outage_the_walk_can_report(self):
        from local_observe.http import TransportError

        class Down:
            """`http.JsonClient`'s real answer to a network that is merely down or answered rubbish."""

            def request(self, method, path, *, payload=None):
                raise TransportError('Endpoint unavailable or invalid JSON response')

        source = ActionsSource(JsonTransport(Down()), REPO)
        with self.assertRaises(SourceUnavailable):
            source.runs(page=1, per_page=1)

    def test_a_forge_that_will_not_answer_exits_unavailable_without_a_traceback(self):
        from local_observe.http import TransportError

        class Down:
            def request(self, method, path, *, payload=None):
                raise TransportError('Endpoint unavailable or invalid JSON response')

        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(self.cli, '_moment', return_value=T0), \
                    mock.patch.object(self.cli, '_http_transport', return_value=JsonTransport(Down())), \
                    mock.patch.object(self.cli, '_log_reader', side_effect=lambda *a, **k: None):
                code = self.cli.main(['--once', '--state', self.state,
                                      '--actions-url', 'https://forge.example.invalid'],
                                     environ={'LO_CI_REPOSITORY': REPO,
                                              'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN})
        finally:
            out, err = sys.stdout.getvalue(), sys.stderr.getvalue()
            sys.stdout, sys.stderr = stdout, stderr
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code)
        report = json.loads(out)
        self.assertEqual('SourceUnavailable', report['error'])
        self.assertFalse(report['complete'])
        self.assertEqual(0, report['cursor'], 'a read that never happened moves nothing')
        self.assertNotIn('Traceback', out + err)
        self.assertNotIn(ACTIONS_TOKEN, out + err)

    def test_a_state_file_this_process_cannot_write_is_a_refusal_not_a_traceback(self):
        """A state file that cannot be opened is the same news as a state file that is corrupt.

        Every class this package raises is in the CLI's net, and the ones that come out of SQLite are not
        this package's vocabulary at all: a read-only directory, a full filesystem or a page that will not
        parse arrive as `sqlite3.OperationalError` / `sqlite3.DatabaseError`, which are neither `OSError`
        nor `ValueError`. So the operator of a timer unit got a Python traceback on stderr and the exit
        status of a crash, when the sentence is short -- this process cannot use the state it was pointed
        at -- and the code for it is the refusal this CLI already documents.
        """
        # The state's parent is a regular file: no process can create a database under it, root included
        # (a 0500 directory is no obstacle to root, which is what CI runs as).
        room = f'{self.temp.name}/not-a-directory'
        open(room, 'w', encoding='utf-8').close()
        try:
            for argv in (['--once'], ['--status']):
                with self.subTest(argv[0]):
                    code, out, err = self._main(['--state', f'{room}/ci.sqlite3',
                                                 '--actions-url', 'https://forge.example.invalid'] + argv,
                                                environ={'LO_CI_REPOSITORY': REPO,
                                                         'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                                actions=self._failing(1014))
                    self.assertEqual(self.cli.EXIT_REFUSED, code, err)
                    self.assertIn('refused:', err)
                    self.assertNotIn('Traceback', out + err)
                    self.assertEqual('', out, 'a run that never opened its state prints no report')
        finally:
            os.unlink(room)

    def test_a_state_file_held_by_another_writer_is_a_refusal_not_a_traceback(self):
        """The other half of "the state is busy": a lock, not a permission.

        This is the overlap a `--status` read and a scheduled tick can hit each other with. The store
        waits on the lock for its documented five seconds and then raises, so what is under test is that
        the wait ends in exit `4` and one line rather than in a stack: the wait itself is shortened through
        the store module's own connection call, because a test that paid five real seconds for every
        refused lock is a test that gets deleted.
        """
        real = sqlite3.connect

        class BriefWait:
            """The `sqlite3` namespace the store uses, with one knob changed: the busy timeout."""

            def connect(self, *args, **kwargs):
                kwargs['timeout'] = 0.05
                return real(*args, **kwargs)

            def __getattr__(self, name):
                return getattr(sqlite3, name)

        holder = CiFailureStore(self.state)
        holder.connection.execute('BEGIN IMMEDIATE')
        holder.connection.execute('CREATE TABLE keeper (x INTEGER)')
        try:
            with mock.patch.object(ci_store_module, 'sqlite3', BriefWait()):
                code, out, err = self._main(['--once', '--state', self.state,
                                             '--actions-url', 'https://forge.example.invalid'],
                                            environ={'LO_CI_REPOSITORY': REPO,
                                                     'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                            actions=self._failing(1015))
        finally:
            holder.connection.execute('ROLLBACK')
            holder.close()
        self.assertEqual(self.cli.EXIT_REFUSED, code, err)
        self.assertIn('refused:', err)
        self.assertNotIn('Traceback', out + err)
        self.assertEqual('', out)

    def test_the_default_job_log_reader_is_wired_on_the_actions_credential(self):
        actions = self._failing(1012)
        code, out, err = self._main(['--once', '--state', self.state,
                                     '--actions-url', 'https://forge.example.invalid'],
                                    environ={'LO_CI_REPOSITORY': REPO,
                                             'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                    actions=actions, reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual(['/repos/acme/widgets/actions/runs/1012/jobs/901/logs'], actions.log_calls,
                         'the log asked for is named by a job id out of the jobs endpoint')
        self.assertEqual(('https://forge.example.invalid/api/v1', False),
                         self.built['reader:LO_CI_ACTIONS'],
                         'same base, same credential scope: a job log is an Actions read')
        with CiFailureStore(self.state) as store:
            detail = json.dumps(store.run_detail(REPO, 1012))
        self.assertNotIn('job-logs-not-wired', detail)
        self.assertIn('unit tests', detail)

    def test_read_only_logs_leaves_the_reader_unwired_and_says_which_gap_it_is(self):
        actions = self._failing(1013)
        code, out, err = self._main(['--once', '--state', self.state,
                                     '--actions-url', 'https://forge.example.invalid',
                                     '--read-only-logs'],
                                    environ={'LO_CI_REPOSITORY': REPO,
                                             'LO_CI_ACTIONS_TOKEN': ACTIONS_TOKEN},
                                    actions=actions, reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual([], actions.log_calls)
        self.assertNotIn('reader:LO_CI_ACTIONS', self.built, 'the switch skips the reader entirely')
        with CiFailureStore(self.state) as store:
            self.assertIn('job-logs-not-wired', json.dumps(store.run_detail(REPO, 1013)))


class IncidentSourceDedupTests(unittest.TestCase):
    """Two ticks of one problem, one incident: the claim the board-free mode exists to make.

    The proof is the platform's own database. `Store.intake` keys a condition on
    `(source, rule_id, rule_version, resource_id, condition)`, and this source puts its incident key --
    `(repository, workflow file, plane)` -- in the resource, so two failing runs of one workflow are one
    condition and the second tick's verdict lands on the incident the first opened. One poll goes one
    step further and emits a single event for that pair, because two events for one key at one instant
    would be the same record offered with different contents. The `ci-failures` store meanwhile keeps one
    occurrence row per failing run under one card fingerprint, which is what the card threshold counts.
    Both halves are read back.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        from local_observe.ci_failures import cli

        self.cli = cli

    def _tick(self, actions, platform, state, moment, log_reader=None, env=None):
        code, report, err = self._raw(actions, platform, state, moment, log_reader=log_reader, env=env)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        return report

    def _raw(self, actions, platform, state, moment, *, log_reader=None, env=None):
        """One `--once` through the real CLI, with the exit code left in for the reader.

        `_tick` insists on the clean-exit half of the contract. A test about a poll the platform refused,
        or about a platform nobody has wired yet, has to read the code as well as the report, because the
        code is what a timer unit sees. `env` adds configuration variables -- a page size, for a test about
        which runs a walk can reach.
        """
        stdout, stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
        try:
            with mock.patch.object(self.cli, '_moment', return_value=moment):
                if platform is not None:
                    platform.now = moment
                environ = {'LO_CI_REPOSITORY': REPO, 'LO_CI_FILE_CARDS': 'off'}
                environ.update(env or {})
                code = self.cli.main(['--once', '--state', state],
                                     environ=environ,
                                     transports=(actions, None, platform), log_reader=log_reader)
        finally:
            out, err = sys.stdout.getvalue(), sys.stderr.getvalue()
            sys.stdout, sys.stderr = stdout, stderr
        # A tick that died on the way leaves no JSON behind: the CLI's promise is one line on stderr and an
        # exit code, so a test about that tick reads the code and the line rather than a report.
        return code, (json.loads(out) if out.strip() else {}), err

    def test_two_ticks_of_one_failure_are_one_incident_and_two_occurrences(self):
        state = f'{self.temp.name}/ci.sqlite3'
        actions = ActionsFake(runs=[run_payload(1101, SHA_A, branch='main', event='push')],
                              jobs={1101: [job(1)], 1102: [job(1)]}, log_text=BAD_EXCERPT)
        platform = StoreBackedPlatform(f'{self.temp.name}/platform.sqlite3')
        one = self._tick(actions, platform, state, T0)
        actions.runs.append(run_payload(1102, SHA_B, branch='main', event='push'))
        two = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5))
        self.assertEqual('admitted', one['platform_admission'])
        self.assertEqual('admitted', two['platform_admission'], 'a repeat failure is still admitted')
        self.assertEqual(1101, one['cursor'], 'the cursor passed the run whose verdict arrived')
        self.assertEqual(1102, two['cursor'])
        filed = platform.incidents()
        self.assertEqual(1, len(filed[RULE_FAILURE]), f'one incident for two failing runs: {filed}')
        coverage = {rule: ids for rule, ids in filed.items() if rule.startswith(RULE_COVERAGE)}
        self.assertTrue(coverage, 'these runs arrived with no log, and the events say so')
        self.assertEqual([1] * len(coverage), [len(ids) for ids in coverage.values()],
                         f'every coverage note keeps its own condition and dedups there: {filed}')
        self.assertEqual(0, platform.paths.count('/v1/evidence'),
                         'no sample was stored: nothing in these events had one to store')
        with CiFailureStore(state) as store:
            rows = store.connection.execute('SELECT fingerprint, run_id FROM occurrences'
                                            ' ORDER BY run_id').fetchall()
        self.assertEqual([1101, 1102], [row['run_id'] for row in rows])
        self.assertEqual(1, len({row['fingerprint'] for row in rows}),
                         'two runs, one problem fingerprint: the SHA is not part of it')

    def test_two_failing_runs_of_one_workflow_in_one_tick_are_one_event_and_one_incident(self):
        """The defect the incident-key contract removes, and the shape that replaced it.

        This is what a busy poll actually produces: one page, two failing runs, one `now`. Under the old
        per-fact build both runs emitted a `ci.run.failed` event, and because `detections.event` derives
        `source_event_id` from `(rule_id, rule_version, resource_id, window)` -- all four of which are
        equal for two runs of one workflow read at one instant, since resource_id was null -- the second
        event arrived as the same record with different contents. `Store.intake` answers that with
        `Event retry changed contents`, and the test on `main` pinned the refusal in place.

        Now the two runs are coalesced *before* the event exists, so the platform is offered one verdict
        naming both run ids, refuses nothing, and the incident count is the same one it always reached.
        """
        state = f'{self.temp.name}/same-tick.sqlite3'
        actions = ActionsFake(runs=[run_payload(1101, SHA_A, branch='main', event='push'),
                                    run_payload(1102, SHA_B, branch='main', event='push')],
                              jobs={1101: [job(1)], 1102: [job(1)]}, log_text=BAD_EXCERPT)
        platform = StoreBackedPlatform(f'{self.temp.name}/same-tick-platform.sqlite3')
        report = self._tick(actions, platform, state, T0)
        failure = [receipt for receipt in report['receipts'] if receipt['rule_id'] == RULE_FAILURE]
        self.assertEqual(1, len(failure), f'one key, one verdict: {failure}')
        self.assertEqual(['admitted'], [item['status'] for item in failure],
                         'and the platform refused nothing: the collision is gone, not merely hidden')
        self.assertEqual(0, report['refused'])
        self.assertEqual(1, report['keys'], 'two runs, one (repository, workflow, plane) subject')
        offered = [event for event in platform.offered(RULE_FAILURE)]
        self.assertEqual(1, len(offered))
        snapshot = offered[0]['evidence'][0]['parameters']['snapshot_id']
        self.assertIn('-n2-', snapshot, f'the event says it speaks for two runs: {snapshot}')
        self.assertIn('-r1101-', snapshot)
        self.assertIn('-r1102', snapshot)
        self.assertEqual(1, len(platform.incidents()[RULE_FAILURE]),
                         f'two runs, one incident: {platform.incidents()}')
        with CiFailureStore(state) as store:
            rows = store.connection.execute('SELECT run_id, fingerprint FROM occurrences'
                                            ' ORDER BY run_id').fetchall()
        self.assertEqual([1101, 1102], [row['run_id'] for row in rows])
        self.assertEqual(1, len({row['fingerprint'] for row in rows}))

    def test_the_old_refusal_shape_still_refuses_the_platform_when_events_are_not_coalesced(self):
        """Proof of what was wrong, against the real store: two events, one id, different contents.

        The two events are built the way the old code built them -- same rule, same window, no resource
        -- and differ only in the evidence naming their own run. Handing them to `Store.intake` is what
        the pipeline used to do on a busy tick, and the platform's answer is the refusal named above. The
        coalesced event the new code builds for the same two runs is then handed over and is admitted,
        so the fix is shown against the platform's own rule rather than against this package's opinion.
        """
        platform = StoreBackedPlatform(f'{self.temp.name}/old-shape.sqlite3')
        window = {'start': utc_text(T0 - dt.timedelta(minutes=1)), 'end': utc_text(T0)}
        old_pair = [self._old_style_event(run_id, window) for run_id in (1151, 1152)]
        self.assertEqual({event['source_event_id'] for event in old_pair}, {old_pair[0]['source_event_id']},
                         'the two runs really did compute one event id')
        platform.store.intake(old_pair[0], platform.actor, now=T0)
        with self.assertRaises(StateError) as caught:
            platform.store.intake(old_pair[1], platform.actor, now=T0)
        self.assertIn('Event retry changed contents', str(caught.exception))
        coalesced = plan_incident_keys([parse_run(REPO, run_payload(1151, SHA_A, branch='main',
                                                                    event='push'), jobs=[job(1)]),
                                        parse_run(REPO, run_payload(1152, SHA_B, branch='main',
                                                                    event='push'), jobs=[job(1)])],
                                       None, now=T0)
        verdicts = [event for event in coalesced.events if event['rule_id'] == RULE_FAILURE]
        self.assertEqual(1, len(verdicts))
        self.assertNotEqual(old_pair[0]['source_event_id'], verdicts[0]['source_event_id'],
                            'the coalesced event is its own record, keyed by the workflow it describes')
        outcome = platform.store.intake(verdicts[0], platform.actor, now=T0)
        self.assertEqual('accepted', outcome['status'])
        self.assertTrue(outcome['incident_id'], 'and the one event is enough to open the incident')
        self.assertEqual('opened', outcome['transition'])

    def _old_style_event(self, run_id: int, window: dict[str, str]) -> dict[str, Any]:
        """One event exactly as `build_events` emitted it before the incident-key contract."""
        return canonical_event(SOURCE, None, RULE_FAILURE, 'availability', 'firing', dict(window),
                               {'snapshot_id': f'cirun-acme-widgets-{run_id}'},
                               query_type='observed-snapshot', observed_at=window['end'], version='1',
                               severity='critical')

    def test_a_starved_run_that_lands_green_is_reported_as_recovered(self):
        state = f'{self.temp.name}/recovered.sqlite3'
        queued = run_payload(1111, SHA_A, status='queued', conclusion='', branch='main', event='push',
                             minutes=10)
        actions = ActionsFake(runs=[queued], jobs={1111: []}, log_text='all good')
        platform = StoreBackedPlatform(f'{self.temp.name}/platform-2.sqlite3')
        starved = self._tick(actions, platform, state, T0 + dt.timedelta(hours=3))
        self.assertEqual(1, starved['recorded'])
        self.assertIn(RULE_STUCK, platform.incidents(),
                      'the starvation is the incident the first tick opened')
        self.assertEqual('open', platform.status_of(RULE_STUCK))
        self.assertEqual([], starved['recovered'], 'nothing has come back yet')
        queued.update(status='completed', conclusion='success')
        actions.jobs[1111] = [job(1, conclusion='success')]
        back = self._tick(actions, platform, state, T0 + dt.timedelta(hours=4))
        self.assertEqual(2, back['events'],
                         'the green run sends the closure, and closes the one gap that really went away')
        self.assertEqual(2, back['resolved'])
        self.assertEqual('admitted', back['platform_admission'])
        self.assertEqual('resolved', platform.status_of(RULE_STUCK),
                         'the incident the starvation opened is closed in the platform, not just here')
        self.assertEqual('resolved', platform.status_of(RULE_COVERAGE + '.job-list-absent'),
                         'a job list arrived this tick, so that gap is a story this poll can tell')
        self.assertEqual('open', platform.status_of(RULE_COVERAGE + '.job-logs-not-wired'),
                         'and the log reader is still not wired: a passing build has not read that away')
        recovered = back['recovered']
        self.assertEqual(1, len(recovered))
        self.assertEqual({'repository': REPO, 'run_id': 1111, 'was_reported': 'stuck',
                          'outcome': 'success'},
                         {key: value for key, value in recovered[0].items()
                          if key in ('repository', 'run_id', 'was_reported', 'outcome')})
        self.assertEqual({'sent': True, 'reason': 'resolved-offered'},
                         recovered[0]['incident_statement'],
                         'the recovery names the event it offered; the receipt says what came back')

    def test_a_starved_run_that_lands_neutral_says_the_incident_is_still_open(self):
        """The fourth answer: this source's marker says open, and nothing this tick closed it.

        `neutral` is neither a failure nor a recovery, so no `resolved` is owed and the starvation
        incident stays open on the platform. Saying `nothing-known-open` here would be the old
        three-answer shape claiming something this store does not believe: the marker it wrote when the
        platform took the firing is the reason this run is worth a sentence at all.
        """
        state = f'{self.temp.name}/neutral.sqlite3'
        queued = run_payload(1161, SHA_A, status='queued', conclusion='', branch='main', event='push',
                             minutes=10)
        actions = ActionsFake(runs=[queued], jobs={1161: []}, log_text='all good')
        platform = StoreBackedPlatform(f'{self.temp.name}/neutral-platform.sqlite3')
        starved = self._tick(actions, platform, state, T0 + dt.timedelta(hours=3))
        self.assertEqual('open', platform.status_of(RULE_STUCK))
        self.assertEqual([], starved['recovered'])
        queued.update(status='completed', conclusion='neutral')
        actions.jobs[1161] = [job(1, conclusion='neutral')]
        back = self._tick(actions, platform, state, T0 + dt.timedelta(hours=4))
        self.assertEqual(1, len(back['recovered']))
        self.assertEqual({'sent': False, 'reason': 'open-not-closed'},
                         back['recovered'][0]['incident_statement'],
                         'the incident is open on the platform and this tick said nothing about it')
        self.assertEqual('open', platform.status_of(RULE_STUCK), 'and it is still open after the tick')
        verdicts = [receipt for receipt in back['receipts']
                    if not receipt['rule_id'].startswith(RULE_COVERAGE)]
        self.assertEqual([], verdicts,
                         'a neutral verdict is neither a failure nor a recovery: nothing about the '
                         'starvation was owed')
        # What this tick *does* say is about itself. The run arrived with a job list this time, so the gap
        # the starved run carried is read back -- and the log reader is still not wired, so that one stays
        # open. A tick with no verdict to give still read the runs, and a poller that only notices its own
        # healed gaps on a tick that happened to file a verdict is reporting recovery when it merely had
        # nothing better to do.
        coverage = {receipt['rule_id']: receipt['event_status'] for receipt in back['receipts']
                    if receipt['rule_id'].startswith(RULE_COVERAGE)}
        self.assertEqual({'resolved'}, set(coverage.values()), f'a gap closed and nothing fired: {coverage}')
        self.assertEqual('resolved', platform.status_of(RULE_COVERAGE + '.job-list-absent'),
                         'a job list arrived this tick, so that gap is a story this poll can tell')
        self.assertEqual('open', platform.status_of(RULE_COVERAGE + '.job-logs-not-wired'),
                         'and the log reader is still not wired: a neutral build has not read that away')

    # ---- a gap that opens, and a gap that closes ---------------------------------------

    def test_two_runs_carrying_one_gap_are_one_coverage_verdict_and_no_conflict(self):
        """One gap, two runs, two instants: the poll says it once, and nothing is refused.

        Every run this poller reads carries the same gap when the log reader is not wired, and a
        coverage event names no resource -- `Store.intake` keys its condition on
        `(source, rule_id, rule_version, resource_id, condition)` and `condition` is the rule id, so two
        runs of one gap are two verdicts for *one* condition. Built per run, they carry the same
        `source_event_id` (rule, version, resource, window) and the platform answers the second with
        `Conflicting evaluations at the same condition watermark`: a refused receipt, a `mixed` poll, and
        a gap incident filed under whichever run happened to sort first. Runs read at two different
        instants is what makes the two windows differ, which is why the width tests -- all of which give
        every run one `when` -- never reached it.
        """
        state = f'{self.temp.name}/gap-width.sqlite3'
        actions = ActionsFake(runs=[
            run_payload(1131, SHA_A, branch='main', event='push', when=T0 - dt.timedelta(hours=2)),
            run_payload(1132, SHA_B, branch='main', event='push')],
            jobs={1131: [job(1)], 1132: [job(1)]}, log_text=BAD_EXCERPT)
        platform = StoreBackedPlatform(f'{self.temp.name}/gap-width-platform.sqlite3')
        report = self._tick(actions, platform, state, T0)
        gap = f'{RULE_COVERAGE}.job-logs-not-wired'
        self.assertEqual(0, report['refused'], f'one gap may not be refused: {report["receipts"]}')
        self.assertEqual('admitted', report['platform_admission'])
        self.assertEqual(1, len([receipt for receipt in report['receipts']
                                 if receipt['rule_id'] == gap]), 'one gap, one verdict per poll')
        self.assertEqual(1, len(platform.offered(gap)), 'and the platform kept one event for it')
        self.assertEqual(1, len(platform.incidents()[gap]), 'one incident for the gap, not one per run')
        self.assertEqual('open', platform.status_of(gap))
        older = parse_run(REPO, actions.runs[0], jobs=[job(1)], log=None)
        self.assertEqual(utc_text(older.observed_at), platform.offered(gap)[0]['window']['start'],
                         'the one window is the span both runs were read at, not the newer one alone')
        self.assertEqual(utc_text(T0), platform.offered(gap)[0]['window']['end'])

    def test_a_gap_a_later_poll_reads_back_closes_its_own_incident(self):
        """A coverage condition is open-and-close, like every other producer's coverage rule.

        The first poll has no log reader and says so; the second reads the same kind of run with one
        wired, and the gap is gone. What makes this a test rather than a report is where the open marker
        lives: the store's `meta` table, under the reserved `ci.intake.coverage` subject and keyed by the
        gap's own rule id, which is the only thing that lets a *later* poll know there is something to
        close. The reader being wired between ticks is also why a gap that is still open stays open: the
        second tick's run carries the gap note itself, and a poll that read only green builds has not
        read anything back.
        """
        state = f'{self.temp.name}/gap-close.sqlite3'
        actions = ActionsFake(runs=[run_payload(1141, SHA_A, branch='main', event='push')],
                              jobs={1141: [job(1)], 1142: [job(1)]}, log_text=BAD_EXCERPT)
        platform = StoreBackedPlatform(f'{self.temp.name}/gap-close-platform.sqlite3')
        gap = f'{RULE_COVERAGE}.job-logs-not-wired'
        first = self._tick(actions, platform, state, T0)
        self.assertEqual('open', platform.status_of(gap))
        self.assertEqual(0, first['refused'])
        with CiFailureStore(state) as store:
            marker = store.incident_key_state(COVERAGE_SUBJECT)
        self.assertEqual(1141, marker[gap]['open'], 'the marker remembers the newest run that carried it')
        self.assertEqual(0, marker[gap]['closed'])
        actions.runs.append(run_payload(1142, SHA_B, branch='main', event='push'))
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5),
                            log_reader=actions.log_reader)
        self.assertEqual('resolved', platform.status_of(gap), 'a poll that read the log says so')
        self.assertEqual(0, second['refused'])
        with CiFailureStore(state) as store:
            closed = store.incident_key_state(COVERAGE_SUBJECT)
        self.assertEqual(0, closed[gap]['open'])
        self.assertEqual(1142, closed[gap]['closed'], 'and the marker says which read closed it')
        third = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10),
                           log_reader=actions.log_reader)
        self.assertEqual([], [receipt for receipt in third['receipts'] if receipt['rule_id'] == gap],
                         'a condition already closed is not closed a second time')

    # ---- what the platform never took ---------------------------------------------------

    def test_a_failure_the_platform_never_heard_is_offered_again_once_it_answers(self):
        """No platform on the first tick is a verdict owed, not a verdict delivered.

        Wiring the platform between the ticks is the ramp-up order the unit's own docs recommend, and the
        failing run is behind the cursor by the second tick -- `record_facts` will not call it new again
        -- so the only thing that can still open the incident is the verdict this store kept. The marker
        is the sharp half of this: written at intent time it said `open: 1151` to a platform that had
        never heard of the failure, and the next green run then spent its closure on a condition that did
        not exist.
        """
        state = f'{self.temp.name}/late-wiring.sqlite3'
        actions = ActionsFake(runs=[run_payload(1151, SHA_A, branch='main', event='push')],
                              jobs={1151: [job(1)]}, log_text=BAD_EXCERPT)
        first = self._tick(actions, None, state, T0)
        self.assertEqual('not-configured', first['platform_admission'])
        self.assertEqual(2, first['pending_verdicts'],
                         'the failure and the gap it carried are both still owed')
        with CiFailureStore(state) as store:
            self.assertEqual({}, store.incident_key_states(),
                              'no marker may claim a verdict nobody was offered')
        platform = StoreBackedPlatform(f'{self.temp.name}/late-wiring-platform.sqlite3')
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5))
        self.assertEqual('admitted', second['platform_admission'])
        self.assertIn(RULE_FAILURE, platform.incidents(),
                      'the failure reaches the platform late, rather than never')
        self.assertEqual('open', platform.status_of(RULE_FAILURE))
        self.assertEqual(0, second['pending_verdicts'], 'and the owed table is empty once it landed')
        with CiFailureStore(state) as store:
            self.assertEqual(1151, store.incident_key_state(incident_key(
                parse_run(REPO, run_payload(1151, SHA_A, branch='main', event='push'),
                          jobs=[job(1)], log=None)))[RULE_FAILURE]['open'])
        third = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10))
        self.assertEqual([], [receipt for receipt in third['receipts'] if receipt['rule_id'] ==
                             RULE_FAILURE], 'a verdict that landed is not offered a second time')

    def test_a_platform_that_refused_is_asked_again_on_the_next_tick(self):
        """One 503 during a break must not be the reason the break never pages.

        The refused tick exits non-zero (a timer unit has to see it) and keeps both verdicts. When the
        platform answers on the next tick the same runs are behind the cursor, so these stored verdicts
        are the whole delivery -- and the marker moves only now, with the receipt behind it.
        """
        state = f'{self.temp.name}/blip.sqlite3'
        actions = ActionsFake(runs=[run_payload(1152, SHA_A, branch='main', event='push')],
                              jobs={1152: [job(1)]}, log_text=BAD_EXCERPT)
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        code, first, err = self._raw(actions, refusing, state, T0)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertEqual('refused', first['platform_admission'])
        self.assertEqual(0, first['admitted'])
        self.assertEqual(2, first['pending_verdicts'], 'still red, still owed')
        with CiFailureStore(state) as store:
            self.assertEqual({}, store.incident_key_states())
        platform = StoreBackedPlatform(f'{self.temp.name}/blip-platform.sqlite3')
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5))
        self.assertEqual('admitted', second['platform_admission'])
        self.assertEqual('open', platform.status_of(RULE_FAILURE))
        self.assertEqual(0, second['pending_verdicts'])

    def test_a_poll_the_platform_took_only_part_of_exits_unavailable(self):
        """`mixed` is a failed send: one receipt admitted does not pay for the one refused.

        The half-admitted poll used to exit 0 while its own report said `mixed`, so a unit watching exit
        codes never saw the defect at all. The refused half also stays owed -- the point of the exit code
        is that something has to happen next.
        """
        class HalfAnswering:
            """Takes the first event the platform is asked about and refuses every later one."""

            def __init__(self) -> None:
                self.calls: list[tuple[str, str]] = []

            def request(self, method, path, *, params=None, payload=None):
                self.calls.append((method, path))
                if len(self.calls) == 1:
                    return 200, {'status': 'accepted', 'event_id': 'event-1', 'incident_id': None}
                return 503, {'error': 'service_unavailable', 'detail': 'later'}

        state = f'{self.temp.name}/half.sqlite3'
        actions = ActionsFake(runs=[run_payload(1153, SHA_A, branch='main', event='push')],
                              jobs={1153: [job(1)]}, log_text=BAD_EXCERPT)
        half = HalfAnswering()
        code, report, err = self._raw(actions, half, state, T0)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code,
                         'a poll with a refused receipt in it is not a clean tick')
        self.assertEqual('mixed', report['platform_admission'])
        self.assertEqual(1, report['admitted'])
        self.assertEqual(2, report['events'])
        self.assertEqual(1, report['refused_answered'], 'and the printed counts keep both meanings apart')
        self.assertEqual(1, report['pending_verdicts'], 'the refused half is owed')
        self.assertIn('service_unavailable',
                      ' '.join(receipt['reason'] for receipt in report['receipts']),
                      'the platform\'s stable code is what the operator reads')
        self.assertNotIn('later', err + json.dumps(report['receipts']),
                         'its `detail` is not: a body can echo a credential')

    # ---- what "still open" is decided from ----------------------------------------------

    def test_a_fourth_gap_in_the_same_read_is_carried_though_it_may_not_be_filed(self):
        """The filing cap stops a page; it does not stop the poll knowing about the gap.

        One run whose read came apart in four different ways files three coverage events -- that ceiling
        is what keeps a thirty-job run from opening thirty incidents -- and the fourth note is still in
        this process's hand. Reading *both* questions off the capped slice meant the fourth reason was
        invisible to the closure rule, so a poll that had the gap in front of it reported the condition as
        recovered: the platform stopped paging, the store kept landing the note, and the next poll filed
        the same gap as if it had just appeared. `MAX_COVERAGE_EVENTS` bounds filing and nothing else.
        """
        reasons = ('job-list-unavailable', 'job-logs-not-wired', 'job-list-absent',
                   'timestamp-unavailable')
        self.assertEqual(3, MAX_COVERAGE_EVENTS, 'the cap this test is written against')
        fact = parse_run(REPO, run_payload(1201, SHA_A, branch='main', event='push'), jobs=[job(1)],
                        log=None)
        fact = replace(fact, coverage=tuple(CoverageNote(reason) for reason in reasons))
        self.assertEqual(4, len(fact.coverage))
        gap = coverage_rule(reasons[-1])
        # Only the fourth reason is known to be open -- which is the one the capped read could not see.
        markers = {COVERAGE_SUBJECT: {gap: {'open': 1200, 'closed': 0}}}
        plan = plan_incident_keys([fact], markers, now=T0)
        spoken = {claim.rule_id: plan.events[claim.index]['status'] for claim in plan.claims}
        filed = [rule for rule, word in spoken.items() if rule.startswith(RULE_COVERAGE)
                 and word == 'firing']
        self.assertEqual({coverage_rule(reason) for reason in reasons[:MAX_COVERAGE_EVENTS]}, set(filed),
                         f'three gaps, three verdicts: {spoken}')
        self.assertNotIn(gap, spoken,
                         'the note past the cap is carried, so nothing may claim it recovered')
        self.assertEqual([], [word for rule, word in spoken.items() if word == 'resolved'],
                         f'no gap this poll read is reported as read back: {spoken}')

    def test_a_gap_carried_by_a_run_that_owes_no_verdict_is_not_reported_as_recovered(self):
        """A queued run is not a verdict, but it is a read -- and it is the same poll's read.

        The first poll finds a red build whose job log answers 503 and files the gap. The second finds a
        green build whose log reads perfectly well *and* a run that has been queued for two minutes whose
        log still answers 503. The queued run can neither fire nor close a verdict -- it is under the stuck
        deadline, and no green run has any bearing on it -- and because only the runs that owed a verdict
        reached the planner, the log gap was decided from the green build alone and closed. The log
        endpoint was still broken; the poll that could see it broken said it was fixed.
        """
        class SelectiveLogs:
            """The log endpoint as a real one behaves during a partial outage: broken per run."""

            def __init__(self, broken):
                self.broken = set(broken)
                self.calls: list[str] = []

            def __call__(self, path):
                self.calls.append(path)
                run_id = int(re.search(r'/runs/(\d+)/', path).group(1))
                return (503, None) if run_id in self.broken else (200, BAD_EXCERPT)

        state = f'{self.temp.name}/queued-gap.sqlite3'
        broken = SelectiveLogs({1210, 1211})
        red = run_payload(1210, SHA_A, branch='main', event='push')
        actions = ActionsFake(runs=[red], jobs={1210: [job(1)]})
        platform = StoreBackedPlatform(f'{self.temp.name}/queued-gap-platform.sqlite3')
        gap = f'{RULE_COVERAGE}.job-log-status-503'
        first = self._tick(actions, platform, state, T0, log_reader=broken)
        self.assertEqual('open', platform.status_of(gap), "the red build's log answered 503")
        with CiFailureStore(state) as store:
            self.assertEqual(1210, store.incident_key_state(COVERAGE_SUBJECT)[gap]['open'],
                             'the marker remembers the run whose log broke: ' + str(first['receipts']))

        # The next poll: a green build whose log reads, and a build queued two minutes ago whose does not.
        actions.runs.append(run_payload(1211, SHA_B, branch='main', event='push', status='queued',
                                       conclusion='', minutes=2))
        actions.runs.append(run_payload(1212, SHA_C, branch='main', event='push',
                                       conclusion='success'))
        actions.jobs.update({1211: [job(2)], 1212: [job(3, conclusion='success')]})
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5), log_reader=broken)
        self.assertEqual([], [receipt for receipt in second['receipts']
                             if receipt['rule_id'] == gap and receipt['event_status'] == 'resolved'],
                         'a poll that read a run whose log still 503s has not read that gap back')
        self.assertEqual('open', platform.status_of(gap))

        # And the closure is deferred, not lost: once the queued run\'s log reads, the next poll says so.
        broken.broken.clear()
        third = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10), log_reader=broken)
        self.assertEqual('resolved', platform.status_of(gap),
                         'the poll that can read every log closes the gap it could not read before')
        self.assertEqual(0, third['refused'])

    def test_a_gap_that_stays_broken_says_nothing_further_while_its_condition_is_open(self):
        """A permanent gap pages once, and stays visible without re-paging.

        Three polls, three fresh failing runs, one log endpoint that answers 307 every time. The marker
        said `open` from the first poll on, and nothing read it: each poll re-filed the firing, so the
        stable event the pending table exists to keep was replaced with a fresh window every tick and
        offered to a platform that already had the condition open. What keeps an operator informed about a
        gap that will not heal is the store-side coverage note, which no receipt gates and `--status`
        reads -- and which keeps landing here, every poll.
        """
        state = f'{self.temp.name}/persistent-gap.sqlite3'
        actions = ActionsFake(runs=[], jobs={}, log_status=307)
        platform = StoreBackedPlatform(f'{self.temp.name}/persistent-gap-platform.sqlite3')
        gaps = (f'{RULE_COVERAGE}.job-log-status-307', f'{RULE_COVERAGE}.job-log-absent')
        reports = []
        for index in range(3):
            run_id = 1221 + index
            actions.runs.append(run_payload(run_id, chr(ord('a') + index) * 40, branch='main',
                                            event='push'))
            actions.jobs[run_id] = [job(run_id * 10)]
            reports.append(self._tick(actions, platform, state,
                                      T0 + dt.timedelta(minutes=6 * index), log_reader=actions.log_reader))
        for index, report in enumerate(reports[1:], start=1):
            self.assertEqual([], [receipt for receipt in report['receipts']
                                 if receipt['rule_id'] in gaps],
                            f'poll {index} re-filed a gap the platform already holds open')
            self.assertEqual(1, len(platform.offered(gaps[0])),
                            'one event for one open condition, not one per poll')
        self.assertEqual('open', platform.status_of(gaps[0]), 'the incident is still the one it opened')
        self.assertEqual([1] * len(gaps), [len(ids) for rule, ids in platform.incidents().items()
                                          if rule in gaps])
        with CiFailureStore(state) as store:
            noted = [store.run_detail(REPO, run_id) for run_id in (1221, 1222, 1223)]
        self.assertEqual([True, True, True], [row is not None for row in noted],
                         'three polls, three runs read')
        for row in noted:
            self.assertIn('job-log-status-307', json.dumps(row['coverage']),
                          'every one of those polls still said so on the run it read: '
                          + str(row['coverage']))

        # The closure still rides the receipt, so the gap that finally heals is closed by the poll that
        # reads it back -- the silence above is "nothing new to say", never "nothing left to close".
        actions.log_status, actions.log_text = 200, BAD_EXCERPT
        actions.runs.append(run_payload(1224, 'd' * 40, branch='main', event='push'))
        actions.jobs[1224] = [job(12240)]
        healed = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=18),
                            log_reader=actions.log_reader)
        self.assertEqual({'resolved'},
                         {receipt['event_status'] for receipt in healed['receipts']
                          if receipt['rule_id'] in gaps})
        self.assertEqual('resolved', platform.status_of(gaps[0]))

    def test_a_gap_that_healed_while_the_platform_was_down_is_closed_not_opened_late(self):
        """The outage ends after the gap did: nothing may page about a gap that is already history.

        The first poll cannot reach the platform, so its two gap firings wait in the owed table and no
        marker exists -- a marker is a copy of an answer, and there was none. The second poll reads the
        same build with the log endpoint working. The gap is gone from this poll's own facts, and the
        firing that would have opened it is still owed: deciding "is it open?" from the markers alone
        meant the replay re-offered the stale firing and the platform opened an incident for a gap that
        had already healed, one poll late. An owed firing holds the condition open *and* is the thing the
        closure retires -- which is why the closure is spoken here instead of the replay being sent.
        """
        state = f'{self.temp.name}/healed-outage.sqlite3'
        actions = ActionsFake(runs=[run_payload(1231, SHA_A, branch='main', event='push')],
                              jobs={1231: [job(1)]}, log_status=307)
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        code, first, err = self._raw(actions, refusing, state, T0, log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        gap = f'{RULE_COVERAGE}.job-log-status-307'
        with CiFailureStore(state) as store:
            owed = store.pending_verdicts()
            self.assertEqual({gap, f'{RULE_COVERAGE}.job-log-absent'},
                             {rule for rule in owed.get(COVERAGE_SUBJECT, {})
                              if rule.startswith(RULE_COVERAGE)}, 'the firings are owed, not claimed')
            self.assertEqual({}, store.incident_key_states())
        actions.log_status, actions.log_text = 200, BAD_EXCERPT
        actions.runs.append(run_payload(1232, SHA_B, branch='main', event='push'))
        actions.jobs[1232] = [job(2)]
        platform = StoreBackedPlatform(f'{self.temp.name}/healed-outage-platform.sqlite3')
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5),
                            log_reader=actions.log_reader)
        said = {receipt['rule_id']: receipt['event_status'] for receipt in second['receipts']}
        self.assertEqual('resolved', said.get(gap),
                         f'the healed gap is closed on the poll that read it back: {said}')
        self.assertNotIn('firing', [word for rule, word in said.items() if rule == gap])
        self.assertIsNone(platform.status_of(gap),
                          'and no incident was ever opened for the gap that healed during the outage')
        self.assertEqual(0, second['pending_verdicts'], 'the owed firing was retired, not re-offered')
        with CiFailureStore(state) as store:
            self.assertEqual(0, store.incident_key_state(COVERAGE_SUBJECT)[gap]['open'])

    def test_a_verdict_the_store_could_not_write_after_the_send_is_still_owed(self):
        """The row exists before the send, so a crash in between cannot lose the incident.

        The order used to be send -> markers -> owed rows, three commits, and the owed row was only ever
        written for a *refusal*. A store that fails right after the platform answered is the case that
        order cannot survive: the platform opened the incident, this source kept neither a marker nor a
        row, and the run behind the cursor means nothing will ever say it again. Here the row is on disk
        before the request is made, so the failure leaves the verdict owed, the next tick re-offers the
        identical bytes, the platform answers `duplicate` -- which is an answer -- and the marker is
        claimed from that receipt. The incident then closes exactly as it would have.
        """
        state = f'{self.temp.name}/crash-after-send.sqlite3'
        actions = ActionsFake(runs=[run_payload(1241, SHA_A, branch='main', event='push')],
                              jobs={1241: [job(1)]}, log_text=BAD_EXCERPT)
        platform = StoreBackedPlatform(f'{self.temp.name}/crash-platform.sqlite3')
        with mock.patch.object(CiFailureStore, 'record_incident_keys',
                             side_effect=StoreError('database disk image is malformed')):
            code, report, err = self._raw(actions, platform, state, T0)
        self.assertEqual(self.cli.EXIT_REFUSED, code, 'a tick that could not finish its own bookkeeping')
        self.assertIn('malformed', err)
        self.assertEqual({}, report, 'and nothing was printed as if the poll had been judged')
        self.assertEqual('open', platform.status_of(RULE_FAILURE),
                         'the platform really does hold the incident: the send happened')
        with CiFailureStore(state) as store:
            owed = store.pending_verdicts()
            self.assertEqual({}, store.incident_key_states(),
                              'no marker was claimed, because the claim is what failed')
            self.assertEqual(2, store.pending_verdict_count(),
                             f'the verdict and its gap are both still owed: {owed}')
            self.assertIn('no answer read back', owed[COVERAGE_SUBJECT][f'{RULE_COVERAGE}'
                                                                        '.job-logs-not-wired']['reason'])
        # The failing run is behind the cursor now, so this tick has nothing new to decide: the stored
        # bytes are the whole delivery, and the platform answers them `duplicate`.
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5))
        self.assertEqual('admitted', second['platform_admission'])
        self.assertEqual(0, second['pending_verdicts'], 'the owed rows are retired by that receipt')
        self.assertEqual(1, len(platform.offered(RULE_FAILURE)),
                         'a duplicate did not become a second event')
        with CiFailureStore(state) as store:
            self.assertEqual(1241, store.incident_key_state(incident_key(
                parse_run(REPO, run_payload(1241, SHA_A, branch='main', event='push'),
                          jobs=[job(1)], log=BAD_EXCERPT)))[RULE_FAILURE]['open'],
                         'and the marker arrived one tick late, with the receipt behind it')
        actions.runs.append(run_payload(1242, SHA_B, branch='main', event='push',
                                       conclusion='success'))
        actions.jobs[1242] = [job(2, conclusion='success')]
        third = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10))
        self.assertEqual('resolved', platform.status_of(RULE_FAILURE),
                         'the incident a crash nearly lost is closed by the next green run')
        self.assertEqual(0, third['pending_verdicts'])

    def test_a_verdict_refused_twelve_times_is_given_up_on_and_said_so(self):
        """An event this platform will never take may not hold every later tick at `refused`.

        Twelve polls, three refused receipts each, and a monitor that has been told for an hour that
        something is owed -- about an event whose refusal is a property of the event. The bound retires
        the row and, more importantly, *names* it: the report says which verdicts were given up on and
        why, and the tick after that one exits clean, because a page nobody can deliver is not a pipeline
        that keeps failing. Abandoning quietly would be the same loss with the evidence removed.
        """
        state = f'{self.temp.name}/twice-twelve.sqlite3'
        actions = ActionsFake(runs=[run_payload(1251, SHA_A, branch='main', event='push')],
                              jobs={1251: [job(1)]}, log_text=BAD_EXCERPT)
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        owed = None
        for index in range(PENDING_MAX_ATTEMPTS):
            code, report, err = self._raw(actions, refusing, state, T0 + dt.timedelta(minutes=5 * index))
            self.assertEqual(self.cli.EXIT_UNAVAILABLE, code,
                             f'poll {index + 1} still has a refused receipt: {err}')
            self.assertEqual([], report['abandoned'], 'nothing is given up on before the bound')
            owed = report['pending_verdicts']
        self.assertEqual(2, owed, 'the gap and the verdict it came with')
        code, report, err = self._raw(actions, refusing, state, T0 + dt.timedelta(minutes=60))
        self.assertEqual(self.cli.EXIT_OK, code,
                         'a verdict this source has given up on is not a tick that failed')
        self.assertEqual(owed, len(report['abandoned']))
        self.assertEqual(owed, report['abandoned_verdicts'])
        self.assertEqual(0, report['pending_verdicts'], 'and the table is empty, not full of refusals')
        self.assertEqual([], report['receipts'], 'an abandoned row is not offered a thirteenth time')
        self.assertEqual({'ci.run.failed', f'{RULE_COVERAGE}.job-logs-not-wired'},
                         {item['rule_id'] for item in report['abandoned']},
                         'every verdict that was owed is named, not swallowed')
        for item in report['abandoned']:
            self.assertEqual(PENDING_MAX_ATTEMPTS, item['attempts'])
            self.assertIn(f'{PENDING_MAX_ATTEMPTS} times', item['reason'])
            self.assertEqual(utc_text(T0), item['decided_at'],
                             'the report names the poll that decided it, which is the one to look at')
            self.assertFalse(item['reoffered'],
                             'and this poll says neither of them again: both runs are behind the cursor, '
                             'so the retired row really was the last word about that break')
        again_code, again, err = self._raw(actions, refusing, state, T0 + dt.timedelta(minutes=65))
        self.assertEqual(self.cli.EXIT_OK, again_code,
                         'and a later tick is not held at `refused` by a row that is gone')
        self.assertEqual([], again['abandoned'])

    def test_owed_evidence_past_its_own_lifetime_is_not_offered_again(self):
        """A verdict whose proof has expired is a page about a window nobody can check.

        Every event this source builds stamps its evidence with `expires_at`, fifteen days after the
        window it cites. An outage longer than that leaves rows whose re-delivery would open an incident
        on the strength of evidence the platform has already discarded, so the row is retired at the
        lifetime the event itself claims, named in the report, and the tick that retired it is the last
        one that mentions it as a refusal.
        """
        state = f'{self.temp.name}/old-outage.sqlite3'
        actions = ActionsFake(runs=[run_payload(1261, SHA_A, branch='main', event='push')],
                              jobs={1261: [job(1)]}, log_text=BAD_EXCERPT)
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        long_ago = T0 - dt.timedelta(days=PENDING_EVIDENCE_LIFETIME_DAYS + 5)
        code, first, err = self._raw(actions, refusing, state, long_ago)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertEqual(2, first['pending_verdicts'])
        code, report, err = self._raw(actions, refusing, state, T0)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual(2, report['abandoned_verdicts'])
        self.assertEqual(0, report['pending_verdicts'])
        for item in report['abandoned']:
            self.assertIn('evidence', item['reason'])
            self.assertEqual(1, item['attempts'], 'this is the lifetime ceiling, not the attempt one')
            self.assertEqual(utc_text(long_ago), item['decided_at'])
        self.assertIn(RULE_FAILURE, [item['rule_id'] for item in report['abandoned']])
        self.assertIn(f'{RULE_COVERAGE}.job-logs-not-wired',
                      [item['rule_id'] for item in report['abandoned']],
                      'a gap verdict is owed exactly as a failure verdict is, and expires the same way')

    # ---- what a refused closure owes, and what an unwired poll owes --------------------

    def test_a_refused_coverage_closure_is_never_owed_and_a_returning_gap_is_never_resolved(self):
        """A gap this poll can read is not recovered, and a stale closure may not say that it is.

        A workflow verdict has to be kept when the platform refuses it: the failing run behind it is behind
        the cursor, and nothing else would ever say it again. A coverage *closure* is the opposite case -- it
        is re-derived every poll from the marker plus the absence of the gap -- and owing it produced exactly
        the harm a round-one review called a blocker. The poll that read the gap gone had its `resolved`
        refused; the next poll read the gap *again*, and because a plan says nothing about a gap it is
        carrying, the stored closure was not superseded by anything: it was replayed. The platform booked a
        recovery that had not happened and an outbox row for it, the marker was cleared from the replayed
        receipt -- this source forgot a gap it was still reading -- and the poll after that re-fired the same
        condition, re-paging an operator for the flap. Four polls, one flapping log endpoint, one outage:
        nothing may ever reach the platform about the gap except the truth of the poll that sent it.
        """
        state = f'{self.temp.name}/stale-closure.sqlite3'
        actions = ActionsFake(runs=[run_payload(1301, SHA_A, branch='main', event='push')],
                              jobs={1301: [job(1)]}, log_status=307)
        platform = StoreBackedPlatform(f'{self.temp.name}/stale-closure-platform.sqlite3')
        gaps = (f'{RULE_COVERAGE}.job-log-status-307', f'{RULE_COVERAGE}.job-log-absent')
        self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        with CiFailureStore(state) as store:
            marker = store.incident_key_state(COVERAGE_SUBJECT)
        self.assertEqual({rule: 1301 for rule in gaps},
                         {rule: rung['open'] for rule, rung in marker.items() if rule in gaps},
                         'both gap conditions are open, stamped with the run that carried them')

        # The endpoint is fixed and the platform is down for one poll: both closures are refused.
        actions.log_status, actions.log_text = 200, BAD_EXCERPT
        actions.runs.append(run_payload(1302, SHA_B, branch='main', event='push'))
        actions.jobs[1302] = [job(2)]
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        code, refused, err = self._raw(actions, refusing, state, T0 + dt.timedelta(minutes=5),
                                      log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, 'a refused closure is still a failed send')
        said = {receipt['rule_id']: receipt['event_status'] for receipt in refused['receipts']}
        self.assertEqual({rule: 'resolved' for rule in gaps}, {rule: said[rule] for rule in gaps},
                         'the poll that read the gap gone says so: ' + str(said))
        with CiFailureStore(state) as store:
            owed = store.pending_verdicts()
            self.assertNotIn(COVERAGE_SUBJECT, owed,
                             'a refused coverage closure is not owed -- the next poll that reads no gap '
                             'says it again, with a window that is true of that poll')
            self.assertEqual(1, store.pending_verdict_count(),
                             'what is owed is the workflow verdict, which nothing else can re-decide')

        # The endpoint breaks again while the platform is healthy. The stale rows are gone, so the only
        # thing this poll has to say is about the build, not about the gap it is carrying again.
        actions.log_status = 307
        actions.runs.append(run_payload(1303, SHA_C, branch='main', event='push'))
        actions.jobs[1303] = [job(3)]
        back = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10),
                          log_reader=actions.log_reader)
        self.assertEqual([], [receipt for receipt in back['receipts'] if receipt['rule_id'] in gaps],
                         'neither the stale closure nor a fresh firing travels for a gap that never left')
        for rule in gaps:
            self.assertEqual(1, len(platform.offered(rule)),
                             f'the platform was told about {rule} exactly once: {platform.offered(rule)}')
            self.assertEqual('open', platform.status_of(rule), 'and it is still paging about it')
        with CiFailureStore(state) as store:
            marker = store.incident_key_state(COVERAGE_SUBJECT)
        self.assertEqual({rule: 1301 for rule in gaps},
                         {rule: marker[rule]['open'] for rule in marker if rule in gaps},
                         'the marker still remembers the gap this source is reading')

        # And the gap that stays broken costs no second page when the bound eventually retires its row.
        actions.runs.append(run_payload(1304, SHA_A, branch='main', event='push'))
        actions.jobs[1304] = [job(4)]
        self._tick(actions, platform, state, T0 + dt.timedelta(minutes=15),
                   log_reader=actions.log_reader)
        for rule in gaps:
            self.assertEqual(1, len(platform.incidents()[rule]),
                             f'one incident for one open condition, however many polls carried it: {rule}')
            self.assertEqual('open', platform.status_of(rule))

    def test_a_verdict_owed_to_no_platform_waits_for_one_rather_than_being_given_up_on(self):
        """`not-configured` is not a refusal, and must not be counted as one.

        The recommended ramp-up is board-free *and* platform-free: run the poller, read its report, wire the
        platform later. The attempts ceiling retires a row the platform proved it did not want, but the
        ceiling counted every poll that wrote a row -- including thirteen polls with nobody wired to answer
        one -- so an unwired deployment deleted its whole backlog after an hour of a five-minute timer and
        reported the loss as "offered twelve times and never taken". Then the operator wired the platform,
        and this source had nothing left to send: no incident was ever opened, so the green run that came
        next had nothing to close either. A counter of *offers* counts polls a platform could answer.
        """
        state = f'{self.temp.name}/unwired.sqlite3'
        actions = ActionsFake(runs=[run_payload(1311, SHA_A, branch='main', event='push')],
                              jobs={1311: [job(1)]}, log_text=BAD_EXCERPT)
        for index in range(PENDING_MAX_ATTEMPTS + 1):
            code, report, err = self._raw(actions, None, state,
                                         T0 + dt.timedelta(minutes=5 * index))
            self.assertEqual(self.cli.EXIT_OK, code, err)
            self.assertEqual([], report['abandoned'],
                              f'poll {index + 1} with no platform wired gives up on nothing')
            self.assertEqual('not-configured', report['platform_admission'])
        with CiFailureStore(state) as store:
            owed = store.pending_verdicts()
            self.assertEqual(2, store.pending_verdict_count(), f'the backlog is still here: {owed}')
            self.assertEqual({1}, {row['attempts'] for rules in owed.values() for row in rules.values()},
                             'thirteen polls nobody could answer are not thirteen offers')

        platform = StoreBackedPlatform(f'{self.temp.name}/unwired-platform.sqlite3')
        wired = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5 * 14))
        self.assertEqual('admitted', wired['platform_admission'],
                         'the first poll with a platform delivers the whole backlog')
        self.assertEqual(0, wired['pending_verdicts'])
        self.assertEqual('open', platform.status_of(RULE_FAILURE))
        self.assertEqual('open', platform.status_of(f'{RULE_COVERAGE}.job-logs-not-wired'))

    def test_an_unwired_wait_still_ends_at_the_lifetime_the_event_claims(self):
        """The ceiling that is about the *event* keeps working with nothing wired.

        Only the attempt counter needs a platform; an owed event whose evidence has passed its own
        `expires_at` would page about a window the platform can no longer check whoever is (not) wired to
        receive it, so the fifteen-day lifetime retires an unwired row exactly as it retires a refused one.
        """
        state = f'{self.temp.name}/unwired-expiry.sqlite3'
        actions = ActionsFake(runs=[run_payload(1321, SHA_A, branch='main', event='push')],
                              jobs={1321: [job(1)]}, log_text=BAD_EXCERPT)
        long_ago = T0 - dt.timedelta(days=PENDING_EVIDENCE_LIFETIME_DAYS + 2)
        code, first, err = self._raw(actions, None, state, long_ago)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual(2, first['pending_verdicts'], 'both rows wait for a platform that is not there')
        code, later, err = self._raw(actions, None, state, T0)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual(0, later['pending_verdicts'])
        self.assertEqual(2, later['abandoned_verdicts'])
        for item in later['abandoned']:
            self.assertIn('evidence', item['reason'])
            self.assertFalse(item['reoffered'], 'nothing re-decided these verdicts: the run is history')

    def test_a_gap_still_being_read_is_said_so_when_its_owed_row_hits_the_bound(self):
        """A retired row and a re-filed condition are two different facts, and the report says both.

        The bound exists so one permanently unsendable event cannot hold every later tick at exit `3`. For
        a verdict about a run the store has passed, it does exactly that. For a coverage gap this poll is
        *still reading*, the row it deletes was the only thing telling the planner the condition had already
        been said -- so the same tick files a fresh `firing` for it. That is the right outcome (the gap is
        real and the platform is still refusing it), but the report used to call the retired row "a page that
        will not be sent" on the tick that was sending it, and the docs promised a monitor would see `0`
        from then on. `reoffered` is the planner's answer, so a reader can tell the two cases apart instead
        of being told one sentence that is true of one and false of the other.
        """
        state = f'{self.temp.name}/bound-and-carried.sqlite3'
        actions = ActionsFake(runs=[], jobs={}, log_status=307)
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        gaps = (f'{RULE_COVERAGE}.job-log-status-307', f'{RULE_COVERAGE}.job-log-absent')
        for index in range(PENDING_MAX_ATTEMPTS + 1):
            run_id = 1331 + index
            actions.runs.append(run_payload(run_id, format(index, '040x'), branch='main', event='push'))
            actions.jobs[run_id] = [job(run_id * 10)]
            code, report, err = self._raw(actions, refusing, state,
                                         T0 + dt.timedelta(minutes=6 * index),
                                         log_reader=actions.log_reader)
            self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, f'poll {index + 1}: {err}')
            if index < PENDING_MAX_ATTEMPTS:
                self.assertEqual([], report['abandoned'], 'nothing is given up on before the bound')
        retired = {item['rule_id']: item for item in report['abandoned']}
        self.assertEqual({RULE_FAILURE, *gaps}, set(retired), f'every exhausted row is named: {retired}')
        fired = {receipt['rule_id'] for receipt in report['receipts']
                 if receipt['event_status'] == 'firing'}
        for rule in gaps:
            self.assertTrue(retired[rule]['reoffered'],
                            f'the report says the page is cancelled while the same tick offers {rule}')
            self.assertIn(rule, fired, 'and it really is being offered again on this tick')
        self.assertEqual(set(gaps), fired & set(gaps), 'only the gaps are said again: no extras invented')
        self.assertEqual(len(gaps) + 1, report['pending_verdicts'],
                         'the retired rows are back on the table, re-offered from this poll\'s own reads')
        with CiFailureStore(state) as store:
            held = store.pending_verdicts()[COVERAGE_SUBJECT]
        for rule in gaps:
            self.assertEqual(1, held[rule]['attempts'], 'a re-filed firing is a new row, not the old one')
            self.assertEqual(utc_text(T0 + dt.timedelta(minutes=6 * PENDING_MAX_ATTEMPTS)),
                             held[rule]['event']['window']['end'],
                             'and its window is this poll, not the one that decided the retired row')
        # `test_a_verdict_refused_twelve_times_is_given_up_on_and_said_so` pins the other half: a verdict
        # about a run this store has already passed cannot be re-decided, and says so (`reoffered: false`).

    def test_a_refused_run_row_still_carries_the_gaps_its_reads_found(self):
        """A row this poll could not parse is not a run whose reads came back clean.

        The job list and the log are asked for *before* `parse_run` sees the object, so a run whose
        `head_sha` is not a commit id still proves that the jobs endpoint never answered. Refusing the row
        used to discard that knowledge with it: the notes were attached to a fact that never existed, and
        the closure rule -- which is built from facts -- could not see them. The poll after one such run
        therefore resolved `job-list-unavailable` (and `job-id-absent`, `job-list-absent`) on the strength
        of a neighbouring green build, while the endpoint was still down and the refusal row itself proves
        the read was made. The notes now travel on the refusal.
        """
        state = f'{self.temp.name}/refused-carries.sqlite3'
        actions = ActionsFake(runs=[run_payload(1351, SHA_A, branch='main', event='push')],
                              jobs={1351: [job(1)]}, log_text=BAD_EXCERPT,
                              faults={'jobs:1351': 'unavailable'})
        platform = StoreBackedPlatform(f'{self.temp.name}/refused-carries-platform.sqlite3')
        gaps = (f'{RULE_COVERAGE}.job-list-unavailable', f'{RULE_COVERAGE}.job-id-absent',
                f'{RULE_COVERAGE}.job-list-absent')
        first = self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        self.assertEqual({RULE_FAILURE, *gaps},
                         {receipt['rule_id'] for receipt in first['receipts']})

        # A green build whose reads work, and a run whose jobs endpoint is still down but whose row this
        # parser refuses. The green build says nothing about the endpoint; the refused row says plenty.
        actions.runs.append(run_payload(1352, SHA_B, branch='main', event='push',
                                       conclusion='success'))
        actions.jobs[1352] = [job(2, conclusion='success')]
        broken = run_payload(1353, 'not-a-commit-id', branch='main', event='push')
        actions.runs.append(broken)
        actions.faults['jobs:1353'] = 'unavailable'
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5),
                            log_reader=actions.log_reader)
        self.assertEqual(1, second['refusals'], 'the unparseable row is refused, as it must be')
        self.assertEqual([], [receipt for receipt in second['receipts']
                             if receipt['rule_id'] in gaps and receipt['event_status'] == 'resolved'],
                         'a poll whose own read came back empty has not read that gap back')
        self.assertIn(RULE_FAILURE, [receipt['rule_id'] for receipt in second['receipts']],
                      'the green build still closes the incident it closed -- the fix is not a mute button')
        for rule in gaps:
            self.assertEqual('open', platform.status_of(rule), f'{rule} is still the gap it was')
        with CiFailureStore(state) as store:
            marker = store.incident_key_state(COVERAGE_SUBJECT)
            refusals = store.refusal_rows()
        self.assertEqual({rule: 1351 for rule in gaps},
                         {rule: rung['open'] for rule, rung in marker.items() if rule in gaps},
                         'the marker still names the run whose endpoint never answered')
        self.assertIn('run-malformed', json.dumps(refusals), 'and the refusal is still recorded by name')

        # Deferred, not lost: once the broken row is gone, the poll that reads the endpoint working again
        # closes what it could not close while the gap was being carried.
        actions.runs.remove(broken)
        actions.runs.append(run_payload(1354, 'd' * 40, branch='main', event='push',
                                       conclusion='success'))
        actions.jobs[1354] = [job(4, conclusion='success')]
        actions.faults.pop('jobs:1353')
        third = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10),
                           log_reader=actions.log_reader)
        self.assertEqual({'resolved'},
                         {receipt['event_status'] for receipt in third['receipts']
                          if receipt['rule_id'] in gaps},
                         'the gap closes on the poll that can really read it back')
        for rule in gaps:
            self.assertEqual('resolved', platform.status_of(rule))

    def _refusals(self, state: str) -> list[dict[str, Any]]:
        """The refusal rows as of now, without opening a second store inside a scenario's own `with`."""
        with CiFailureStore(state) as store:
            return store.refusal_rows()

    def test_a_below_cursor_run_this_poll_refuses_is_not_a_read_that_came_back_clean(self):
        """The second refusal site had the same hole, and the notes have to survive there too.

        A run whose id is already behind the cursor is re-read by `_refresh_open_runs`, one bounded GET per
        run, and that path has its own `except MalformedSource`. It wrote the refusal row and dropped the
        row's notes, so the one run this poll knew something about contributed nothing: a poll that also
        read a neighbouring clean build held only that build's reads, and answered "the endpoint answers
        now" about a gap whose only witness it had just thrown away.
        """
        state = f'{self.temp.name}/refused-refresh.sqlite3'
        queued = run_payload(1200, SHA_C, status='queued', conclusion='', branch='feature/one')
        actions = ActionsFake(runs=[run_payload(1201, SHA_A, branch='main', event='push'), queued],
                              jobs={1201: [job(1)]}, log_text=BAD_EXCERPT,
                              faults={'jobs:1200': 'unavailable', 'jobs:1201': 'unavailable'})
        platform = StoreBackedPlatform(f'{self.temp.name}/refused-refresh-platform.sqlite3')
        # Two runs a page, so the queued one scrolls below the cursor on the tick that reads it.
        paged = {'LO_CI_PER_PAGE': '2', 'LO_CI_MAX_PAGES': '3'}
        first = self._tick(actions, platform, state, T0, log_reader=actions.log_reader, env=paged)
        gap = f'{RULE_COVERAGE}.job-list-unavailable'
        self.assertIn(gap, [receipt['rule_id'] for receipt in first['receipts']],
                      'the red run files the gap its endpoint never answered')
        with CiFailureStore(state) as store:
            self.assertEqual(1201, store.incident_key_state(COVERAGE_SUBJECT)[gap]['open'])
            self.assertEqual([1200], store.open_run_ids(REPO),
                             'and the queued run is left below the cursor, to be asked again')

        # The queued row drifts (a `head_sha` that is not a commit id is enough) while its endpoint is still
        # down. A green build arrives above the cursor, so this poll does have clean reads to reason from.
        queued['head_sha'] = 'not-a-commit-id'
        actions.runs.append(run_payload(1202, SHA_C, branch='main', event='push', conclusion='success'))
        actions.jobs[1202] = [job(2, conclusion='success')]
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5),
                            log_reader=actions.log_reader, env=paged)
        # The refusal is on the record: the refresh path writes it to the refusals table (the report's
        # `refusals` count is the page walk's, and a below-cursor row is not part of that walk).
        self.assertEqual([(1200, 'run-malformed')],
                         [(row['run_id'], row['reason']) for row in self._refusals(state)
                          if row['reason'] == 'run-malformed'],
                         'the drifted row is refused, as it must be')
        self.assertEqual([], [receipt for receipt in second['receipts']
                             if receipt['rule_id'] == gap and receipt['event_status'] == 'resolved'],
                         'a poll whose only witness it refused has not read that gap back')
        self.assertEqual('open', platform.status_of(gap), 'so the platform is still paging about it')
        with CiFailureStore(state) as store:
            self.assertEqual(1201, store.incident_key_state(COVERAGE_SUBJECT)[gap]['open'],
                             'and the marker still names the run whose endpoint never answered')

        # Deferred, not lost: the refresh that can read the row closes what this one could not.
        actions.faults.pop('jobs:1200')
        actions.faults.pop('jobs:1201')
        queued['head_sha'] = SHA_C
        queued.update(status='completed', conclusion='success')
        actions.jobs[1200] = [job(3, conclusion='success')]
        third = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10),
                           log_reader=actions.log_reader, env=paged)
        self.assertEqual(['resolved'], [receipt['event_status'] for receipt in third['receipts']
                                        if receipt['rule_id'] == gap],
                         'the gap closes on the poll that can really read it back')
        self.assertEqual('resolved', platform.status_of(gap))

    def test_a_coverage_closure_left_in_the_table_by_an_earlier_build_is_retired_not_sent(self):
        """A row written by a build that owed closures must not travel either.

        The rule that stops owing a coverage closure only governs new writes, so a state file that already
        holds one -- refused by a platform during an outage, on a build from before the rule -- is judged by
        the replay. That replay asks one question: did this poll speak about the pair? For a gap the poll is
        carrying, the plan deliberately says nothing (it never re-files an open condition and never closes a
        carried one), so the stale `resolved` is offered as "read again" for a gap this poller has in its
        hands. What the platform answers depends on whether it still holds the firing's bytes: a differing
        window is a recovery it books and an outbox row it sends -- and the marker is then cleared from a
        receipt this source should not have honoured -- and the same window is `Event retry changed
        contents`, a refusal that never converges and pins every later tick to exit 3. Both shapes are the
        same row sent; a row found in this state is dropped on the tick it is found, without being sent.
        """
        state = f'{self.temp.name}/legacy-closure.sqlite3'
        actions = ActionsFake(runs=[run_payload(1361, SHA_A, branch='main', event='push')],
                              jobs={1361: [job(1)]}, log_status=307)
        platform = StoreBackedPlatform(f'{self.temp.name}/legacy-closure-platform.sqlite3')
        gap = f'{RULE_COVERAGE}.job-log-status-307'
        self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        self.assertEqual('open', platform.status_of(gap))

        green = parse_run(REPO, run_payload(1362, SHA_B, branch='main', event='push',
                                           conclusion='success'), jobs=[job(2, conclusion='success')],
                          log=BAD_EXCERPT)
        stale = plan_incident_keys([green], {COVERAGE_SUBJECT: {gap: {'open': 1361, 'closed': 0}}}, now=T0)
        closure = next(event for event in stale.events if event['rule_id'] == gap)
        self.assertEqual('resolved', closure['status'], 'the shape an earlier build left behind')
        with CiFailureStore(state) as store:
            store.record_pending_verdicts([{'key': COVERAGE_SUBJECT, 'rule_id': gap, 'event': closure,
                                            'open_run': 0, 'closed_run': 1362,
                                            'reason': 'intake refused with status 503: unavailable'}],
                                         now=T0)

        # The gap is back, the platform is healthy, and the poll has nothing true to say about the reason.
        actions.runs.append(run_payload(1363, SHA_C, branch='main', event='push'))
        actions.jobs[1363] = [job(3)]
        second = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=5),
                            log_reader=actions.log_reader)
        self.assertEqual([], [receipt for receipt in second['receipts'] if receipt['rule_id'] == gap],
                         'neither the stale closure nor a re-fire travels')
        self.assertEqual(1, len(platform.offered(gap)),
                         f'the platform was told about the gap once, when it was really found: {gap}')
        self.assertEqual('open', platform.status_of(gap), 'and it is still paging about it')
        self.assertEqual(0, second['pending_verdicts'], 'the legacy row is off the table, not lingering')
        with CiFailureStore(state) as store:
            self.assertEqual(1361, store.incident_key_state(COVERAGE_SUBJECT)[gap]['open'],
                             'the marker still says what this source is still reading')


    def test_a_row_refused_at_its_first_check_holds_the_gaps_that_poll_read(self):
        """A version-drift row is not a read that came back clean, in either direction.

        `parse_run` appends `job-list-absent` and `job-log-absent` *after* the status, conclusion, branch,
        event, path and workflow-identity checks -- which are exactly the checks a new status word trips. So
        the row this poll refused handed back a note list missing the two gaps this poll's own reads had
        found, and the closure rule read "not carried" as "came back clean": the platform was told
        `job-log-absent` had healed -- a `resolved`, a recovery page -- and this source's own marker was
        zeroed, stamped with the id of the row the parser had refused, while the log endpoint was still
        answering 307. The refusal now carries the read-level gaps it skipped past, and it says of itself
        that it is not a complete read, so it licenses no closure at all.
        """
        state = f'{self.temp.name}/refused-first-check.sqlite3'
        gaps = (coverage_rule('job-log-absent'), coverage_rule('job-log-status-307'))
        actions = ActionsFake(runs=[run_payload(9821, SHA_A, branch='main', event='push')],
                              jobs={9821: [job(1)]}, log_status=307)
        platform = RefusablePlatform(f'{self.temp.name}/refused-first-check-platform.sqlite3')
        opened = self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        self.assertEqual({RULE_FAILURE, *gaps}, {r['rule_id'] for r in opened['receipts']},
                         'the drift begins as it always does: the gap is read and said')
        for gap in gaps:
            self.assertEqual('open', platform.status_of(gap), f'the platform pages about {gap}')

        # The forge starts answering a status word this parser does not know. Every row above the cursor is
        # refused at its first check, and the log endpoint has not changed: it is still answering 307.
        actions.runs = [run_payload(9823, SHA_B, branch='main', event='push', status='succeeded')]
        actions.jobs[9823] = [job(3)]
        for minute, label in ((5, 'the first drifted poll'), (10, 'and the poll after it')):
            code, report, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=minute),
                                          log_reader=actions.log_reader)
            self.assertEqual(self.cli.EXIT_OK, code, err)
            self.assertEqual(1, report['refusals'], f'{label}: the drift row is refused, and named')
            self.assertEqual(0, report['events'],
                             f'{label}: a poll whose only read was a refusal has read nothing back, so it '
                             'says nothing -- not even that the gap it just refused has healed')
            self.assertEqual([], report['abandoned'], f'{label}: and it gives up on nothing either')
            for gap in gaps:
                self.assertEqual('open', platform.status_of(gap),
                                 f'{label}: the platform still pages about {gap}')
                self.assertEqual(9821, coverage_markers(state)[gap]['open'],
                                 f'{label}: and this source still knows which run carried {gap}')

        # The drift ends: a parseable red run, the log endpoint still 307. The gap is still there, so the
        # only thing this poll may say is its verdict. Re-filing the gap under a fresh window is what a poll
        # that had falsely closed it would have to do -- two pages for one condition that never changed.
        actions.runs.append(run_payload(9825, SHA_C, branch='main', event='push'))
        actions.jobs[9825] = [job(5)]
        ended = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=15),
                           log_reader=actions.log_reader)
        self.assertEqual([RULE_FAILURE], [r['rule_id'] for r in ended['receipts']],
                         'one event: the verdict, and no second claim about the reads')
        for gap in gaps:
            self.assertEqual(9821, coverage_markers(state)[gap]['open'],
                             'the marker never moved: the gap was never closed, so it never re-opened')
            self.assertEqual(1, len(platform.offered(gap)),
                             f'{gap} was said to the platform exactly once, when it was really met')

    def test_a_refused_row_carried_holds_a_gap_it_never_named_open(self):
        """The second half of the fix: a carrier may hold a gap open, but may not report one healed.

        The two parser-derived notes `_unread_notes` can rebuild are the two a drift row plausibly loses,
        and they are not the only ones at risk: `job-log-unreadable` and the `timestamp-unavailable` notes
        come from fields a refusal never reached, so no reconstruction can promise them. What covers those
        is the carrier saying it is not a complete read: it contributes its notes to "is this gap still
        here" and nothing at all to "what did this poll read back". A marker open for a reason no surviving
        note names is the case that pins the difference.
        """
        gap = coverage_rule('timestamp-unavailable')
        markers = {COVERAGE_SUBJECT: {gap: {'open': 1361, 'closed': 0}}}
        carrier = coverage_only_fact(REPO, 1362, [CoverageNote('job-log-absent')])
        self.assertFalse(carrier.read_complete,
                         'a refused row says so, so the planner can act on that and not on a docstring')
        self.assertTrue(parse_run(REPO, run_payload(1361, SHA_A), jobs=[job(1)],
                                  log='boom').read_complete,
                        'a row that came through the parser is a read this poll may cite')

        spoken = plan_incident_keys([], markers, now=T0, read_facts=[carrier])
        self.assertEqual([], [event for event in spoken.events if event['status'] == 'resolved'],
                         'the notes of a row this poll could not parse are not evidence that somebody\'s '
                         'clock fields started arriving')
        self.assertEqual({coverage_rule('job-log-absent')}, set(spoken.carried),
                         'the gap the carrier did name is held open by it -- and the one it could not '
                         'name is not, which is exactly why this poll may not speak about it')

    def test_a_coverage_carrier_handed_over_as_a_verdict_is_refused(self):
        """The carrier's safety is a property now, not a sentence in a docstring.

        `coverage_only_fact` is built to answer "is this gap still here" and nothing else: every field a
        verdict reads is `unknown` by construction. Handed to the *verdict* list it was not inert. A status
        of `unknown` is not `completed`, which the planner reads as a run that is starved, filed under the
        fabricated workflow identity `unknown` -- an incident no green run could ever match, so it could only
        ever be opened and never closed. Both call sites already hand the carrier to `read_facts`, and that
        was the only thing standing between this shape and a phantom incident on a real platform.
        """
        carrier = coverage_only_fact(REPO, 9902, [CoverageNote('job-log-absent')])
        with self.assertRaises(CiFailureError) as raised:
            plan_incident_keys([carrier], None, now=T0)
        self.assertIn('read_facts', str(raised.exception),
                      'the refusal names where the fact belongs, not just that it does not')
        verdict = parse_run(REPO, run_payload(9902, SHA_A), jobs=[job(1)])
        with self.assertRaises(CiFailureError):
            build_events(carrier, card_identity(verdict), now=T0)
        # As a read, the same fact is exactly what it claims to be: a note, holding a gap open, firing nothing.
        spoken = plan_incident_keys([], None, now=T0, read_facts=[carrier])
        self.assertEqual((), spoken.events)
        self.assertEqual({coverage_rule('job-log-absent')}, set(spoken.carried))

    def test_a_refused_coverage_closure_on_a_quiet_repository_is_said_again(self):
        """A closure the platform refused is said again on a repository that stops building.

        Both halves of the round-4 rule were sound and together they were lossy: a refused coverage closure
        was kept by nothing, and it was re-derived only by a poll that *read a run* -- which, on a repository
        that lands one build and goes quiet, is never. The two coverage incidents stayed `open` on the
        platform while the poller exited 0, owed nothing and abandoned nothing, for as long as nobody pushed
        to that branch -- one day later the report still read `events 0 pending 0 abandoned []`. The licence
        is now the poll's own read rather than a run's, so the word comes back on the next good tick.
        """
        state = f'{self.temp.name}/quiet-repository.sqlite3'
        gaps = (coverage_rule('job-log-absent'), coverage_rule('job-log-status-307'))
        actions = ActionsFake(runs=[run_payload(9840, SHA_A, branch='main', event='push')],
                              jobs={9840: [job(1)], 9841: [job(2, conclusion='success')]},
                              log_status=307)
        platform = RefusablePlatform(f'{self.temp.name}/quiet-repository-platform.sqlite3')
        self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        for gap in gaps:
            self.assertEqual('open', platform.status_of(gap))

        # The log endpoint is fixed and a green build lands -- and the platform hiccups on every send.
        actions.runs.append(run_payload(9841, SHA_B, branch='main', event='push', conclusion='success'))
        actions.log_status, actions.log_text = 200, BAD_EXCERPT
        platform.refusing = True
        code, report, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=5),
                                      log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertEqual({'resolved'}, {r['event_status'] for r in report['receipts']},
                         'the closures are spoken, and refused')
        self.assertEqual(1, report['pending_verdicts'],
                         'only the verdict is owed: a coverage closure is re-derived, not owed')
        for gap in gaps:
            self.assertEqual(9840, coverage_markers(state)[gap]['open'],
                             'and a refused claim does not move this source\'s own marker')

        # The repository then goes quiet: nothing new above the cursor, the platform healthy again. The
        # closures travel on the strength of this poll's own completed read.
        platform.refusing = False
        healed = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10),
                            log_reader=actions.log_reader)
        self.assertEqual(0, healed['recorded'], 'this poll read no new run at all')
        self.assertEqual({RULE_FAILURE, *gaps}, {r['rule_id'] for r in healed['receipts']},
                         'the whole refused set travels again: the verdict on its owed row, the two '
                         'closures on this poll\'s own read')
        self.assertEqual({'resolved'}, {r['event_status'] for r in healed['receipts']})
        self.assertEqual(0, healed['pending_verdicts'], 'and it owes nothing after saying it')
        self.assertEqual('resolved', platform.status_of(RULE_FAILURE))
        for gap in gaps:
            self.assertEqual('resolved', platform.status_of(gap), f'{gap} closed on a quiet repository')
            self.assertEqual(1, len([row for row in platform.offered(gap) if row['status'] == 'resolved']),
                             'said once, in the end: the refused tick left no duplicate behind')
            self.assertEqual(0, coverage_markers(state)[gap]['open'])

        again = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=15),
                           log_reader=actions.log_reader)
        self.assertEqual([], again['receipts'],
                         'a third quiet poll says it a third time to nobody: once the marker is clear, '
                         'there is nothing left to close')

    def test_a_poll_whose_own_read_failed_closes_no_coverage_gap(self):
        """The licence for a closure is a read that came back, so a failed read must not carry one.

        The quiet-repository rule licenses a poll that read *nothing* on the strength of the read it did
        make. That is only honest while the read happened: a poll whose page fetch failed, or that spent its
        page budget, or that refused every row it reached, does not know what it did not read, and must not
        spend that ignorance on a recovery page. The heal is then said by the next poll that can.
        """
        state = f'{self.temp.name}/failed-read-closes-nothing.sqlite3'
        gaps = (coverage_rule('job-log-absent'), coverage_rule('job-log-status-307'))
        actions = ActionsFake(runs=[run_payload(9860, SHA_A, branch='main', event='push')],
                              jobs={9860: [job(1)], 9861: [job(2, conclusion='success')]},
                              log_status=307)
        platform = RefusablePlatform(f'{self.temp.name}/failed-read-platform.sqlite3')
        self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        actions.log_status, actions.log_text = 200, BAD_EXCERPT
        platform.refusing = True
        code, refused, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=5),
                                       log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertEqual(2, len(refused['receipts']))
        platform.refusing = False

        actions.faults['page:1'] = 'unavailable'
        code, outage, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=10),
                                      log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertFalse(outage['complete'])
        self.assertEqual('SourceUnavailable', outage['error'])
        self.assertEqual([], outage['receipts'],
                         'a poll that could not read the forge says nothing about what it could not read')
        for gap in gaps:
            self.assertEqual('open', platform.status_of(gap), f'{gap} is still open on the platform')
            self.assertEqual(9860, coverage_markers(state)[gap]['open'],
                             'and still open in this source\'s own book')
        del actions.faults['page:1']

        back = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=15),
                          log_reader=actions.log_reader)
        self.assertEqual(sorted(gaps), sorted(r['rule_id'] for r in back['receipts']),
                         'the outage cost the word one poll, not the branch\'s remaining history')
        for gap in gaps:
            self.assertEqual('resolved', platform.status_of(gap))

    def test_a_gap_met_by_a_refused_row_stays_open_beside_a_clean_green_run(self):
        """The two halves of round 4 in one tick: a clean green run, and a row refused at its first check.

        With every row refused the closure is licensed by nothing, and that is the easy case. With one
        parseable green neighbour the poll's read *did* come back, so a licence exists and only `carried`
        still stands between a healed gap and a `resolved`. The gap here is the 307 on the row the poll
        could not parse: the endpoint is broken for that run and healthy for its neighbour, so filing
        `recovered` would report a recovery this poll did not read -- while the workflow verdict the green
        run did earn still travels, which is the half that must not be over-fixed.
        """
        state = f'{self.temp.name}/drift-beside-green.sqlite3'
        # A 307 with no body is read as two gaps at once -- the log is not there, and the endpoint said so
        # -- so this tick meets `job-log-absent` and `job-log-status-307` on the row it refuses.
        gap = coverage_rule('job-log-absent')
        actions = ActionsFake(runs=[run_payload(9880, SHA_A, branch='main', event='push')],
                              jobs={9880: [job(1)], 9881: [job(2, conclusion='success')],
                                    9882: [job(3)]}, log_status=307)
        platform = RefusablePlatform(f'{self.temp.name}/drift-beside-green-platform.sqlite3')
        self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        self.assertEqual('open', platform.status_of(gap))

        def only_for_the_refused_run(path):
            """The endpoint is broken for one run's log and answers normally for the other."""
            return (307, None) if '/runs/9882/' in path else (200, BAD_EXCERPT)

        # The green build is filed under the same commit as the failing one, so it really can close that
        # verdict; `status="succeeded"` on 9882 is the field a run has never carried, and that row is
        # refused the moment its own 307 has been noted.
        actions.runs = [run_payload(9881, SHA_A, branch='main', event='push', conclusion='success'),
                        run_payload(9882, SHA_C, branch='main', event='push', status='succeeded')]
        code, report, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=5),
                                      log_reader=only_for_the_refused_run)
        self.assertEqual(1, report['refusals'], err)
        self.assertEqual([], [r['rule_id'] for r in report['receipts']
                              if r['rule_id'].startswith(RULE_COVERAGE)],
                         'neither gap this poll met in the row it refused is reported healed, whatever '
                         'the neighbour next to it read')
        self.assertEqual('open', platform.status_of(gap),
                         'and the platform is not told the log endpoint came back for it')
        self.assertEqual(9880, coverage_markers(state)[gap]['open'],
                         'the marker keeps the id of the run that really was read, not the refused one')
        self.assertEqual([RULE_FAILURE], [r['rule_id'] for r in report['receipts']
                                          if r['event_status'] == 'resolved'],
                         'the workflow verdict the clean green run did earn still travels')

    def test_a_stored_coverage_closure_is_said_or_retired_by_what_this_poll_read(self):
        """A stored closure is judged against this poll's read, and the report says which way it went.

        Round 4 graded the retirement right in the common case -- a legacy closure whose firing the platform
        never took would be a lie -- and asked, as the minimum repair, that the drop be *named* like every
        other drop this store makes. What a poll really has to choose between is three things: the gap is
        back in this poll's hands (retire it, and say so), this poll could not read its source (neither send
        it nor give up on it), or the marker that kept it open is gone while nothing carries the gap (say
        it -- it is the only true statement left about an incident the platform may still be holding).
        """
        state = f'{self.temp.name}/stored-closure.sqlite3'
        gap = coverage_rule('job-log-absent')
        actions = ActionsFake(runs=[run_payload(9900, SHA_A, branch='main', event='push')],
                              jobs={9900: [job(1)], 9901: [job(2, conclusion='success')]},
                              log_status=307)
        platform = RefusablePlatform(f'{self.temp.name}/stored-closure-platform.sqlite3')
        self._tick(actions, platform, state, T0, log_reader=actions.log_reader)
        actions.log_status, actions.log_text = 200, BAD_EXCERPT
        healed = plan_incident_keys(
            [parse_run(REPO, run_payload(9901, SHA_B, branch='main', event='push',
                                         conclusion='success'),
                       jobs=[job(2, conclusion='success')], log=BAD_EXCERPT)],
            {COVERAGE_SUBJECT: {gap: {'open': 9900, 'closed': 0}}},
            now=T0 + dt.timedelta(minutes=5))
        claim = next(item for item in healed.claims if item.rule_id == gap)
        closure = healed.events[claim.index]

        def clear_marker():
            """Delete the marker the way the *previous* release's upgrade recipe told an operator to."""
            with sqlite3.connect(state) as connection:
                connection.execute('DELETE FROM meta WHERE key=?',
                                   (KEY_MARKER_PREFIX + COVERAGE_SUBJECT,))
                connection.commit()

        def owe(moment):
            with CiFailureStore(state) as store:
                store.record_pending_verdicts([{'key': COVERAGE_SUBJECT, 'rule_id': gap,
                                                'event': closure, 'open_run': 0, 'closed_run': 9901,
                                                'reason': 'intake refused with status 503: unavailable'}],
                                              now=moment)
            clear_marker()

        # (a) the marker is gone -- the shape the *previous* release's upgrade recipe left an operator with,
        # since it deleted `incident-key:*` rows including this one -- and this poll reads its source clean
        # with nothing carrying the gap: the row travels, and the stranded incident closes.
        owe(T0 + dt.timedelta(minutes=5))
        said = self._tick(actions, platform, state, T0 + dt.timedelta(minutes=10),
                          log_reader=actions.log_reader)
        self.assertEqual([gap], [r['rule_id'] for r in said['receipts']])
        self.assertEqual('resolved', platform.status_of(gap),
                         'the incident the recipe stranded is closed by the row that knew about it')
        self.assertEqual([], said['abandoned'], 'it was sent, not given up on')
        self.assertEqual(0, said['pending_verdicts'])

        # (b) the same row and the same cleared marker, on a poll that cannot read the forge: neither sent
        # (this poll has no evidence for it) nor retired (the next poll may). The bound retires it later.
        owe(T0 + dt.timedelta(minutes=15))
        actions.faults['page:1'] = 'unavailable'
        code, outage, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=20),
                                      log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertEqual([], outage['receipts'], 'no closure travels on a read that did not come back')
        self.assertEqual(1, outage['pending_verdicts'],
                         'the row waits rather than being spent on a poll that cannot stand behind it')
        self.assertEqual([], outage['abandoned'])
        del actions.faults['page:1']

        # (c) the gap is back in this poll's hands *and still open on the platform*, so the plan has
        # nothing to say about the pair -- and the stored word about it is a lie. The row is retired and
        # *named*, which is the promise every other drop in `store.py` keeps.
        actions.log_status, actions.log_text = 307, None
        actions.runs.append(run_payload(9902, SHA_C, branch='main', event='push'))
        actions.jobs[9902] = [job(3)]
        owe(T0 + dt.timedelta(minutes=25))
        with CiFailureStore(state) as store:
            store.record_incident_keys([KeyTransition(COVERAGE_SUBJECT, gap, open_run=9900)],
                                       now=T0 + dt.timedelta(minutes=25))
        code, back, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=30),
                                    log_reader=actions.log_reader)
        self.assertEqual(self.cli.EXIT_OK, code, err)
        self.assertEqual([], [r for r in back['receipts'] if r['rule_id'] == gap
                              and r['event_status'] == 'resolved'],
                         'no recovery travels for a gap this poll is reading')
        retired = [entry for entry in back['abandoned'] if entry['rule_id'] == gap]
        self.assertEqual(1, len(retired), f'the retirement is in the report: {back["abandoned"]}')
        self.assertIn('reading', retired[0]['reason'],
                      f'and it says which kind of retirement this was: {retired[0]["reason"]}')
        self.assertEqual('resolved', retired[0]['event_status'], 'it names the row it dropped')
        self.assertFalse(retired[0]['reoffered'], 'the closure was not said again...')
        self.assertFalse(retired[0]['withdrawn'], '...and neither was anything else about that pair')
        self.assertEqual(0, back['pending_verdicts'], 'and it is off the table, not lingering')
        markers = coverage_markers(state)
        self.assertEqual({'open': 9900, 'closed': 0}, markers[gap],
                         'the retired row never touched the marker: the platform still holds that gap '
                         'open, which is why the stored closure was a lie')
        self.assertEqual(9902, markers[coverage_rule('job-log-status-307')]['open'],
                         'and the gap this poll actually read is open under its own rule id')

    def test_a_pair_this_poll_withdrew_is_not_reported_as_reoffered(self):
        """`reoffered` means the page is being sent again, because that is what the docs tell a reader.

        The field was computed by matching `(key, rule_id)` alone, so it said "this poll is saying the
        condition again" about a pair the same poll had just *withdrawn*: the thirteenth offer of a firing
        exhausted by the twelve-offer ceiling, on a tick whose only event for that pair was the `resolved`
        a green run earned, with the incident closed and nothing owed. Matching the pair is right for one of
        those two shapes and wrong for the other, so the status this poll spoke decides the word, and the
        opposite direction has its own.
        """
        state = f'{self.temp.name}/withdrawn-not-reoffered.sqlite3'
        actions = ActionsFake(runs=[run_payload(9920, SHA_A, branch='main', event='push')],
                              jobs={9920: [job(1)], 9921: [job(2)], 9922: [job(3, conclusion='success')]},
                              log_text=BAD_EXCERPT)
        platform = RefusablePlatform(f'{self.temp.name}/withdrawn-platform.sqlite3')
        first = self._tick(actions, platform, state, T0)
        self.assertEqual('admitted', first['platform_admission'],
                         'the first firing lands, so the key is open on the platform')

        # The platform stops answering. A second red build is refused on every poll until the ceiling
        # retires its row -- and the poll that retires it reads a green build.
        platform.refusing = True
        actions.runs.append(run_payload(9921, SHA_B, branch='main', event='push'))
        for index in range(PENDING_MAX_ATTEMPTS):
            code, report, err = self._raw(actions, platform, state,
                                          T0 + dt.timedelta(minutes=5 * (index + 1)))
            self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, f'poll {index + 1}: {err}')
            self.assertEqual([], report['abandoned'], 'nothing is given up on before the ceiling')
        actions.runs.append(run_payload(9922, SHA_C, branch='main', event='push', conclusion='success'))
        platform.refusing = False
        code, report, err = self._raw(actions, platform, state, T0 + dt.timedelta(minutes=65))
        self.assertEqual(self.cli.EXIT_OK, code, err)

        exhausted = [entry for entry in report['abandoned'] if entry['rule_id'] == RULE_FAILURE]
        self.assertEqual(1, len(exhausted), f'the exhausted row is named: {report["abandoned"]}')
        self.assertEqual(PENDING_MAX_ATTEMPTS, exhausted[0]['attempts'])
        self.assertEqual('firing', exhausted[0]['event_status'], 'what the row stood for')
        self.assertFalse(exhausted[0]['reoffered'],
                         'this poll did not offer that firing again, so the field must not say it did')
        self.assertTrue(exhausted[0]['withdrawn'],
                        'it withdrew it: the only thing that left this process for that pair was a closure')
        self.assertEqual([RULE_FAILURE], [r['rule_id'] for r in report['receipts']])
        self.assertEqual('resolved', report['receipts'][0]['event_status'],
                         'and the page that went instead was the resolved')
        self.assertEqual('resolved', platform.status_of(RULE_FAILURE), 'the incident is closed')
        self.assertEqual(0, report['pending_verdicts'])

    def test_the_rows_a_bound_evicted_are_in_the_report_that_counts_them(self):
        """A count pinned at a ceiling is not a count of the backlog.

        With `attempts` advanced only on real offers, the twelve-offer ceiling cannot drain an unwired
        backlog, which leaves the 200-row table bound as the only ceiling -- and it used to evict inside the
        write that owed the rows, silently. The repro decided 261 verdicts and reported
        `pending_verdicts = 200, abandoned = []`: 61 pages had already gone, and the one number an operator
        is told to read before wiring a platform said nothing had. The write now answers with the rows it
        dropped, and the tick report lists them beside the rows the ceilings retired.
        """
        state = f'{self.temp.name}/bound-names-its-cuts.sqlite3'
        actions = ActionsFake(runs=[], jobs={}, log_text=BAD_EXCERPT)
        refusing = PlatformFake(event=(503, {'error': 'unavailable'}))
        facts = [parse_run(REPO, run_payload(2200 + index, format(index, '040x'), branch='main',
                                             event='push', workflow=f'ci-{index}',
                                             workflow_id=f'ci-{index}.yml'),
                           jobs=[job(2200 + index)], log=BAD_EXCERPT)
                 for index in range(PENDING_VERDICTS_BOUND)]
        decided = plan_incident_keys(facts, None, now=T0)
        rows = [{'key': claim.key, 'rule_id': claim.rule_id, 'event': decided.events[claim.index],
                 'open_run': 2200 + index, 'closed_run': None,
                 'reason': 'intake refused with status 503: unavailable'}
                for index, claim in enumerate(decided.claims)]
        self.assertEqual(PENDING_VERDICTS_BOUND, len(rows), 'one firing per workflow, exactly at the bound')
        with CiFailureStore(state) as store:
            write = store.record_pending_verdicts(rows, now=T0)
        self.assertEqual((), write.evicted, 'a table exactly at its bound has evicted nothing')
        self.assertEqual(PENDING_VERDICTS_BOUND, write.written)

        # One more failing workflow than the table can hold, offered to a platform that refuses it.
        actions.runs = [run_payload(2500, format(2500, '040x'), branch='main', event='push')]
        actions.jobs[2500] = [job(2500)]
        code, report, err = self._raw(actions, refusing, state, T0 + dt.timedelta(minutes=5))
        self.assertEqual(self.cli.EXIT_UNAVAILABLE, code, err)
        self.assertGreater(report['events'], PENDING_VERDICTS_BOUND,
                           'this poll decided more verdicts than the table can hold')
        self.assertEqual(PENDING_VERDICTS_BOUND, report['pending_verdicts'],
                         'and the count still reads at the bound, which is the whole problem')
        dropped = [entry for entry in report['abandoned']
                   if str(PENDING_VERDICTS_BOUND) in entry['reason']]
        self.assertTrue(dropped, f'the rows above the bound were named by nothing: {report["abandoned"]}')
        self.assertEqual(len(dropped), report['abandoned_verdicts'],
                         'nothing else was given up on, so the count and the list agree')
        self.assertGreaterEqual(report['pending_verdicts'] + len(dropped), report['events'],
                                'every verdict this poll decided is either owed or named -- nothing is '
                                'both uncounted and invisible')
        self.assertEqual(len(dropped), len({(entry['key'], entry['rule_id']) for entry in dropped}),
                         'one entry per verdict, even where the bound dropped the same row twice')
        for entry in dropped:
            self.assertEqual({'key', 'rule_id', 'reason', 'attempts', 'decided_at', 'event_status',
                              'reoffered', 'withdrawn'}, set(entry))
            self.assertIn('pending-verdicts table', entry['reason'])
        with CiFailureStore(state) as store:
            owed = {(subject, rule) for subject, rules in store.pending_verdicts().items()
                    for rule in rules}
        self.assertEqual(PENDING_VERDICTS_BOUND, len(owed), 'the table is the size it says it is')
        fresh = incident_key(parse_run(REPO, actions.runs[0], jobs=[job(2500)], log=BAD_EXCERPT))
        self.assertIn((fresh, RULE_FAILURE), owed,
                      'the verdict this poll decided is on the table: what the bound gives up on is what '
                      'has waited longest, not what just happened')
        for entry in dropped:
            self.assertTrue(entry['reoffered'] or (entry['key'], entry['rule_id']) not in owed,
                            f'a named row is either off the table or being said again this tick, and the '
                            f'entry says which: {entry}')

        # The next tick has nothing to add: the overflow was this poll's, and the rows that stayed cost
        # nothing. A bound that reported a fresh crisis every five minutes would train nobody to read it.
        quiet = self._raw(actions, refusing, state, T0 + dt.timedelta(minutes=10))[1]
        self.assertEqual([], quiet['abandoned'], 'the eviction was named once, on the tick that did it')
        self.assertEqual(PENDING_VERDICTS_BOUND, quiet['pending_verdicts'])

    def test_a_plan_that_replayed_a_verdict_says_that_it_spoke_it(self):
        """`IncidentKeyPlan.spoken` means what its docstring says, on every path that returns one.

        `_admit` re-offers stored verdicts by appending them to the plan it returns -- events, claims and
        their marker moves and all -- while leaving `spoken` at the planner's answer, so the object handed
        back described a poll that had said nothing about pairs it had just sent. Nothing reads the returned
        `spoken` today, which is the reason this belongs in a test rather than in a comment: the next caller
        that trusts it would offer a stored verdict a second time in the same tick.
        """
        state = f'{self.temp.name}/spoken-after-replay.sqlite3'
        fact = parse_run(REPO, run_payload(2600, SHA_A, branch='main', event='push'),
                         jobs=[job(2600)], log=BAD_EXCERPT)
        stored = plan_incident_keys([fact], None, now=T0)
        claim = next(item for item in stored.claims if item.rule_id == RULE_FAILURE)
        with CiFailureStore(state) as store:
            store.record_pending_verdicts([{'key': claim.key, 'rule_id': RULE_FAILURE,
                                            'event': stored.events[claim.index], 'open_run': 2600,
                                            'closed_run': None,
                                            'reason': 'intake refused with status 503: unavailable'}],
                                         now=T0)
        actions = ActionsFake(runs=[], jobs={}, log_text=BAD_EXCERPT)
        refusing = PlatformIntake(PlatformFake(event=(503, {'error': 'unavailable'}))).admit
        built = service(actions, None, state, log_reader=actions.log_reader,
                        admission=PlatformAdmission(refusing))
        try:
            with SocketGuard():
                # Nothing to read and nothing to judge: the only thing this poll says is what the table owes.
                _receipts, plan, owed, abandoned = built.pipeline._admit(
                    [], {}, T0 + dt.timedelta(minutes=5), {})
        finally:
            built.close()
        self.assertEqual(1, len(plan.events), 'the owed firing travelled')
        self.assertEqual(1, len(plan.claims))
        self.assertEqual([(claim.key, RULE_FAILURE)], [(item.key, item.rule_id) for item in plan.claims])
        self.assertEqual({(claim.key, RULE_FAILURE)}, set(plan.spoken),
                         'and the returned plan knows it spoke about that pair')
        self.assertEqual(1, owed, 'refused again, so owed still')
        self.assertEqual((), abandoned, 'a refused row is owed, not given up on')


class OperatorRecipeTests(unittest.TestCase):
    """The SQL an operator is told to run, and the consequences told with it, are product surface.

    The upgrade paragraph in `docs/units/ci-failures.md` names the `meta` rows to delete when the markers
    written by an earlier build cannot be trusted, and states what that costs. Both halves are claims about
    this code: that the statement clears the rows it means to and only those, and that the outcome it
    describes is the outcome the poller produces. The first is checked by running the statement out of the
    document against a state file that holds both kinds of marker -- the workflow key and the reserved
    coverage subject, which share the `meta` table and its prefix. The second by the sentence that has to
    be there and the one that must not.
    """

    @classmethod
    def setUpClass(cls):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, 'docs', 'units', 'ci-failures.md'), encoding='utf-8') as handle:
            cls.doc = handle.read()
        with open(os.path.join(root, 'CHANGELOG.md'), encoding='utf-8') as handle:
            cls.changelog = handle.read()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def _statements(self, text: str) -> list[str]:
        return [item.strip() for item in re.findall(r'DELETE FROM meta[^;`]*;', text)]

    def test_the_upgrade_statement_clears_the_workflow_markers_and_keeps_the_gap_markers(self):
        """`incident-key:ci.intake.coverage` is the row a healed gap still needs to close itself.

        A coverage incident is closed by the next poll that reads the gap gone, and that rule reads the
        marker's `open` half -- so a statement that sweeps the prefix also strands every coverage incident
        the earlier build delivered that is not being re-read at upgrade time: nothing this source does
        afterwards can close it, which is the defect the closure rules exist to prevent. A reason that is
        still carried re-fires and heals; a healed one is orphaned.
        """
        statements = self._statements(self.doc)
        self.assertEqual(1, len(statements), f'the document gives exactly one upgrade DELETE: {statements}')
        key = incident_key(parse_run(REPO, run_payload(1601, SHA_A, branch='main', event='push'),
                                    jobs=[job(1)], log=BAD_EXCERPT))
        gap = f'{RULE_COVERAGE}.job-log-absent'
        state = f'{self.temp.name}/upgrade-recipe.sqlite3'
        with CiFailureStore(state) as store:
            store.record_incident_keys([KeyTransition(key, RULE_FAILURE, open_run=1601),
                                        KeyTransition(COVERAGE_SUBJECT, gap, open_run=1601)], now=T0)
            self.assertEqual(2, len(store.incident_key_states()))
        with sqlite3.connect(state) as connection:
            connection.execute(statements[0].rstrip(';'))
            connection.commit()
        with CiFailureStore(state) as store:
            keys = store.incident_key_states()
        self.assertNotIn(key, keys, 'the unverified workflow marker is the row the recipe means to clear')
        self.assertIn(COVERAGE_SUBJECT, keys,
                      'the gap markers are not: the statement has to name the exception, or following it '
                      'leaves coverage incidents open that nothing can close')
        self.assertEqual({gap: 1601}, {rule: rung['open'] for rule, rung in keys[COVERAGE_SUBJECT].items()
                                      if rung['open']}, 'and they survive intact, not zeroed')

    def test_the_changelog_quotes_the_same_statement_the_document_gives(self):
        """Two copies of a destructive statement diverge; this one is pinned to the other."""
        self.assertEqual(self._statements(self.doc), self._statements(self.changelog),
                         'the release note and the unit document must hand over the same SQL')

    def test_the_upgrade_paragraph_says_the_closure_is_lost_rather_than_delayed(self):
        """What the recipe costs is a closure that can never be sent, not one that arrives late.

        The closure rule needs `open`, and `open` is what the statement deletes, so a green run cannot close
        a delivered incident afterwards -- the earlier text promised a closure that will never arrive and
        told the operator to wait for it.
        """
        statement = self._statements(self.doc)[0]
        block = self.doc.split(statement, 1)[1].split('\n* **A marker never moves backwards.**', 1)[0]
        self.assertIn('by hand', block,
                      'the document has to say a delivered incident is closed by hand: ' + block[:400])
        self.assertNotIn('until a green run closes it', block,
                         'and must not promise a closure the deleted marker can no longer make derivable')
        self.assertIn(COVERAGE_SUBJECT, block,
                      'the coverage exception is stated where the statement is, not left to be discovered')


class IncidentWidthTests(unittest.TestCase):
    """How wide an incident is, one event per key per poll, and what closes it.

    The width is a claim about `Store.intake`'s identity rule, so every claim here is read back out of a
    real platform store (`StoreBackedPlatform`) rather than from this package's own report: an incident
    that exists only in the sender's opinion is not a claim this file makes.
    """

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp.cleanup()

    def _platform(self, name='platform'):
        return StoreBackedPlatform(f'{self.temp.name}/{name}.sqlite3')

    def _failing(self, run_id, sha=SHA_A, *, branch='main', event='push', workflow_id='ci.yml',
                 workflow='ci', when=T0, status='completed', conclusion='failure'):
        return run_payload(run_id, sha, branch=branch, event=event, workflow=workflow,
                           workflow_id=workflow_id, when=when, status=status, conclusion=conclusion)

    def _fact(self, run_id, sha=SHA_A, **kwargs):
        status = kwargs.get('status', 'completed')
        conclusion = kwargs.get('conclusion', 'failure')
        jobs = kwargs.pop('jobs', None) or [job(1, conclusion=conclusion if status == 'completed' else '',
                                                status=status)]
        return parse_run(kwargs.pop('repository', REPO),
                         self._failing(run_id, sha, **kwargs), jobs=jobs, log=BAD_EXCERPT)

    def _tick(self, actions, platform, state, moment):
        platform.now = moment  # the platform judges the event at the instant the poll judged it
        built = service(actions, None, state, log_reader=actions.log_reader,
                        admission=PlatformAdmission(PlatformIntake(platform).admit))
        try:
            with SocketGuard():
                return built.pipeline.poll_once(now=moment)
        finally:
            built.close()

    # ---- width --------------------------------------------------------------

    def test_the_platform_holds_one_incident_per_workflow_and_plane_not_per_run(self):
        """Three runs of one workflow on main are one incident; a second workflow is a second one."""
        state = f'{self.temp.name}/width.sqlite3'
        runs = [self._failing(1401, SHA_A), self._failing(1402, SHA_B),
                self._failing(1403, SHA_C, workflow_id='nightly.yml', workflow='nightly')]
        actions = ActionsFake(runs=runs, jobs={row['id']: [job(row['id'])] for row in runs},
                              log_text=BAD_EXCERPT)
        platform = self._platform('width')
        report = self._tick(actions, platform, state, T0)
        self.assertEqual(2, report.keys, 'two workflows, two incident subjects')
        self.assertEqual('admitted', report.platform_admission)
        self.assertEqual((), report.superseded, 'nothing was green here, so nothing was folded away')
        self.assertEqual(2, len(platform.incidents()[RULE_FAILURE]),
                         f'one incident per workflow, not per run: {platform.incidents()}')
        subjects = {row['resource_id'] for row in platform.store.records('incidents')
                    if row['resource_id']}
        self.assertEqual(2, len(subjects), 'the two workflows name two different subjects')
        self.assertEqual(2, len(platform.offered(RULE_FAILURE)),
                         'one poll, two subjects, two verdicts -- and one of them speaks for two runs')
        severities = {event['severity'] for event in platform.offered(RULE_FAILURE)}
        self.assertEqual({'critical'}, severities, 'every run of a red main is main-red')
        with CiFailureStore(state) as store:
            rows = store.connection.execute('SELECT run_id FROM occurrences').fetchall()
        self.assertEqual(3, len(rows), 'the occurrences the card counts are untouched by key width')

    def test_the_plane_sets_the_loudness_and_the_key_without_editing_the_rules(self):
        """main is critical, a scheduled run is a warning, and the pull plane is neither: it is recorded."""
        main = self._fact(1411)
        scheduled = self._fact(1412, branch='nightly-scan', event='schedule')
        pull = self._fact(1413, branch='feature/one', event='pull_request')
        self.assertEqual(('main', 'branch', 'pull'), (main.plane, scheduled.plane, pull.plane))
        keys = [incident_key(fact) for fact in (main, scheduled, pull)]
        self.assertEqual(3, len(set(keys)), 'one workflow on three planes is three incident subjects')
        plan = plan_incident_keys([main, scheduled, pull], None, now=T0)
        verdicts = {str(event['resource_id']): event for event in plan.events
                    if event['rule_id'] == RULE_FAILURE}
        self.assertEqual(3, len(verdicts), f'one event per key: {plan.events}')
        shapes = sorted((event['status'], event['severity']) for event in verdicts.values())
        self.assertEqual([('firing', 'critical'), ('firing', 'warning'), ('unknown', 'info')], shapes,
                         'main pages critical, other branches warn, the pull plane does not open')
        for event in plan.events:
            validate_event(event, T0)
        self.assertEqual(2, len(plan.transitions),
                         'only the two planes that opened anything are tracked for closure')
        self.assertEqual({resource_id_for_key(key) for key in keys}, set(verdicts))

    def test_a_pull_request_failure_is_admitted_and_opens_no_incident_at_all(self):
        """The platform's own answer, read back: the event is there, the incident is not."""
        state = f'{self.temp.name}/pull.sqlite3'
        runs = [self._failing(1421, SHA_A, branch='feature/one', event='pull_request'),
                self._failing(1422, SHA_B, branch='feature/one', event='pull_request')]
        actions = ActionsFake(runs=runs, jobs={row['id']: [job(row['id'])] for row in runs},
                              log_text=BAD_EXCERPT)
        platform = self._platform('pull')
        report = self._tick(actions, platform, state, T0)
        self.assertEqual('admitted', report.platform_admission, 'nothing was refused')
        self.assertEqual(1, report.keys, 'the two runs are one subject')
        self.assertEqual(0, report.resolved)
        failure = [receipt for receipt in report.receipts if receipt.rule_id == RULE_FAILURE]
        self.assertEqual(1, len(failure))
        self.assertEqual('admitted', failure[0].status)
        self.assertEqual(PULL_STATUS, failure[0].event_status,
                         'the receipt says the verdict was recorded, not that it opened anything')
        self.assertEqual([None], list(platform.incidents()[RULE_FAILURE]),
                         'the only incident id this rule has is null: no incident exists')
        self.assertEqual(0, len(platform.store.records('incidents')),
                         'and the incidents table itself holds nothing at all')
        with CiFailureStore(state) as store:
            self.assertEqual({}, store.incident_key_states(),
                             'a pull-plane failure opens nothing, so no closure is owed for it later')

    def test_the_key_names_the_workflow_not_the_run_and_survives_odd_names(self):
        """Two workflows can never share a key, and every key fits the platform's own character class."""
        plain = self._fact(1431, workflow_id='ci.yml')
        second = self._fact(1432, workflow_id='release.yml')
        spaced = self._fact(1433, workflow_id='a b.yml')
        dashed = self._fact(1434, workflow_id='a-b.yml')
        long_repo = self._fact(1435, repository='acme/' + ('x' * 120))
        same_prefix = self._fact(1436, repository='acme/' + ('x' * 119 + 'y'))
        keys = [incident_key(fact) for fact in (plain, second, spaced, dashed, long_repo, same_prefix)]
        self.assertEqual(6, len(set(keys)), f'workflows share a key: {keys}')
        self.assertEqual(6, len({resource_id_for_key(key) for key in keys}))
        for key in keys:
            self.assertEqual(key, bounded_label(key),
                             'a key must pass state.label, the class intake applies')
            self.assertLessEqual(len(key), 128)
            identifier(resource_id_for_key(key))
        dot_collision = [incident_key(self._fact(1437, repository='ac.me/widgets')),
                         incident_key(self._fact(1438, repository='ac/me.widgets'))]
        self.assertNotEqual(dot_collision[0], dot_collision[1],
                            'folding `/` to `.` must not merge two repositories onto one incident')
        self.assertEqual(incident_key(plain), incident_key(self._fact(1439, workflow_id='ci.yml')),
                         'and the same workflow keeps its key whatever the run id or SHA is')
        with self.assertRaises(CiFailureError):
            resource_id_for_key('not/a/label')

    def test_a_live_run_naming_a_numeric_workflow_id_still_keys_on_the_path_file(self):
        """`path` and `workflow_id` together are one workflow, and the file is the half that identifies it.

        The captured live shape carries `path` and leaves `workflow_id` null; the field-bearing detail
        shape carries `workflow_id` as a file name and no path. A forge version that answered *both* -- a
        path and a numeric or ref-qualified id -- used to key under the id, which splits one workflow
        across two incident subjects as soon as the two endpoints disagree, and a starvation fired under
        one of them can never be closed by the verdict that arrives under the other: closure is keyed,
        never looked up. The width rules are driven through the live shape here for that reason.
        """
        path = 'ci.yml@refs/heads/main'
        as_listed = parse_run(REPO, gitea_run(1471, SHA_A, path=path), jobs=[gitea_job(1)],
                              log=BAD_EXCERPT)
        with_id = parse_run(REPO, dict(gitea_run(1472, SHA_B, path=path), workflow_id=9007),
                            jobs=[gitea_job(1)], log=BAD_EXCERPT)
        self.assertEqual('ci.yml', with_id.workflow_id,
                         'the path\'s file wins the identity; the numeric id is not dropped, it is second')
        self.assertEqual(incident_key(as_listed), incident_key(with_id),
                         'one workflow file is one incident subject whatever else the payload names')
        plan = plan_incident_keys([as_listed, with_id], None, now=T0)
        verdicts = [event for event in plan.events if event['rule_id'] == RULE_FAILURE]
        self.assertEqual(1, len(verdicts), f'one poll, both shapes, one verdict: {plan.events}')
        self.assertEqual(1, len({event['resource_id'] for event in verdicts}))
        self.assertEqual(1, len(plan.transitions), 'one key, one marker move')
        self.assertEqual(max(as_listed.run_id, with_id.run_id), plan.transitions[0].open_run)
        # And the key still says which file it is about, so an operator reading the incident can name the
        # workflow without a lookup table of numeric ids.
        self.assertIn('ci.yml', incident_key(as_listed))

    # ---- one event per key ---------------------------------------------------

    def test_one_poll_folds_every_failing_run_of_a_key_into_one_event(self):
        facts = [self._fact(1440 + index, format(index, '040x')) for index in range(1, 6)]
        plan = plan_incident_keys(facts, None, now=T0)
        verdicts = [event for event in plan.events if event['rule_id'] == RULE_FAILURE]
        self.assertEqual(1, len(verdicts), 'five runs, one key, one verdict')
        snapshot = verdicts[0]['evidence'][0]['parameters']['snapshot_id']
        self.assertIn('-n5-', snapshot)
        for fact in facts:
            self.assertIn(f'-r{fact.run_id}', snapshot, 'every folded run is named')
        self.assertEqual(1, len(plan.transitions))
        self.assertEqual(max(fact.run_id for fact in facts), plan.transitions[0].open_run)
        for event in plan.events:
            validate_event(event, T0)

    def test_a_batch_that_does_not_fit_says_so_instead_of_looking_complete(self):
        facts = [self._fact(1450 + index, format(index, '040x')) for index in range(1, 31)]
        plan = plan_incident_keys(facts, None, now=T0)
        snapshot = [event for event in plan.events if event['rule_id'] == RULE_FAILURE][0]['evidence'][
            0]['parameters']['snapshot_id']
        self.assertLessEqual(len(snapshot), MAX_SNAPSHOT_CHARS,
                             'this product cuts the id at MAX_SNAPSHOT_CHARS, inside what the intake allows')
        self.assertIn('-n30-', snapshot, 'the count is the whole batch, never the shown part')
        shown = snapshot.count('-r')
        self.assertIn(f'-cut{30 - shown}', snapshot)
        self.assertLess(shown, 30, 'so yes, something was cut -- and the id is where it says so')

    def test_a_still_running_run_never_pages_and_a_starved_one_is_its_own_rule(self):
        starved = self._fact(1471, status='waiting', conclusion='',
                             jobs=[job(1, conclusion='', status='waiting', steps=[])])
        self.assertNotEqual('completed', starved.status)
        plan = plan_incident_keys([starved], None, now=T0)
        stuck = [event for event in plan.events if event['rule_id'] == RULE_STUCK]
        self.assertEqual(1, len(stuck))
        self.assertEqual('warning', stuck[0]['severity'])
        self.assertEqual(resource_id_for_key(incident_key(starved)), stuck[0]['resource_id'],
                         'the starvation is about the same workflow, so it is the same subject')

    # ---- closure -------------------------------------------------------------

    def test_a_newer_success_closes_the_incident_the_failure_opened(self):
        state = f'{self.temp.name}/close.sqlite3'
        platform = self._platform('close')
        first = ActionsFake(runs=[self._failing(1481, SHA_A)], jobs={1481: [job(1)]},
                            log_text=BAD_EXCERPT)
        opened = self._tick(first, platform, state, T0)
        self.assertEqual('open', platform.status_of(RULE_FAILURE))
        self.assertEqual(0, opened.resolved)
        with CiFailureStore(state) as store:
            marker = store.incident_key_state(incident_key(self._fact(1481)))
            self.assertEqual({'open': 1481, 'closed': 0}, marker[RULE_FAILURE])
        second = ActionsFake(runs=[self._failing(1482, SHA_B, conclusion='success')],
                             jobs={1482: [job(1, conclusion='success')]}, log_text='all good')
        closed = self._tick(second, platform, state, T0 + dt.timedelta(minutes=5))
        self.assertEqual(1, closed.events, 'the green run is a verdict about the key, so it is sent')
        # The closure costs no read of its own. The same page, handed to a store with nothing open, is a
        # poll that would file nothing -- and it asks the forge for exactly the same requests, in the same
        # order. Nothing here goes looking for the run that opened an incident.
        alone_platform = self._platform('close-alone')
        alone_state = f'{self.temp.name}/close-alone.sqlite3'
        alone = ActionsFake(runs=[self._failing(1482, SHA_B, conclusion='success')],
                            jobs={1482: [job(1, conclusion='success')]}, log_text='all good')
        quiet = self._tick(alone, alone_platform, alone_state, T0 + dt.timedelta(minutes=5))
        self.assertEqual(0, quiet.events, 'and a green run with nothing open is still not a verdict')
        self.assertEqual([(method, path, params) for method, path, params in alone.calls],
                         [(method, path, params) for method, path, params in second.calls],
                         'closing cost nothing a green-only tick does not already pay')
        self.assertEqual(alone.log_calls, second.log_calls)
        self.assertEqual(1, closed.resolved)
        self.assertEqual('admitted', closed.platform_admission)
        self.assertEqual('resolved', platform.status_of(RULE_FAILURE),
                         'the platform closed the incident it opened')
        self.assertEqual(2, platform.paths.count('/v1/events'), 'one verdict in, one closure out')
        self.assertEqual(0, platform.paths.count('/v1/evidence'),
                         'a closure cites the same kind of query as the verdict it closes')
        with CiFailureStore(state) as store:
            marker = store.incident_key_state(incident_key(self._fact(1481)))
            self.assertEqual({'open': 0, 'closed': 1482}, marker[RULE_FAILURE])
        third = ActionsFake(runs=[self._failing(1483, SHA_C, conclusion='success')],
                            jobs={1483: [job(1, conclusion='success')]}, log_text='all good')
        quiet = self._tick(third, platform, state, T0 + dt.timedelta(minutes=10))
        self.assertEqual(0, quiet.events, 'a key already closed is not closed twice')
        self.assertEqual('no-events', quiet.platform_admission)

    def test_an_older_success_closes_nothing(self):
        key = 'ci.yml.main:deadbeef'
        states = {key: {RULE_FAILURE: {'open': 1500, 'closed': 0}}}
        older = self._fact(1491, conclusion='success')
        plan = plan_incident_keys([older], states, now=T0)
        self.assertEqual((), tuple(event for event in plan.events if event['status'] == 'resolved'),
                         'a run older than the failure is not evidence that anything was fixed')
        self.assertEqual((), plan.transitions)

    def test_a_late_failure_cannot_move_a_marker_backwards_or_close_a_newer_one(self):
        """A run that settles late is a new fact carrying an old id, and the marker must not listen.

        `_refresh_open_runs` exists for exactly that run: a low-id build the page walk passed comes back
        on a later tick with its verdict. Fired on its own it is the newest thing this poll read, so the
        transition used to say `open: 800` against a marker already at 900 -- and the next green run, at
        850, then satisfied the closure test and resolved an incident whose newest failure is still red.
        The invariant is `open_run = max(every failure ever fired)`, and a `resolved` requires
        `newest_green >= open`.
        """
        late = self._fact(800)
        key = incident_key(late)
        states = {key: {RULE_FAILURE: {'open': 900, 'closed': 0}}}
        plan = plan_incident_keys([late], states, now=T0)
        self.assertEqual(1, len(plan.transitions))
        self.assertEqual(900, plan.transitions[0].open_run, 'the marker stays at the newest failure')
        green = self._fact(850, conclusion='success')
        follow = plan_incident_keys([green], states, now=T0)
        self.assertEqual((), plan_incident_keys([green], states, now=T0).transitions,
                         'run 850 is green and run 900 is still red: nothing is closed here')
        self.assertEqual((), follow.events)
        state = f'{self.temp.name}/marker-monotonic.sqlite3'
        with CiFailureStore(state) as store:
            store.record_incident_keys([KeyTransition(key, RULE_FAILURE, open_run=900)], now=T0)
            store.record_incident_keys([KeyTransition(key, RULE_FAILURE, open_run=800)], now=T0)
            self.assertEqual(900, store.incident_key_state(key)[RULE_FAILURE]['open'],
                             'and the store refuses the backward move a replay could hand it')
            store.record_incident_keys([KeyTransition(key, RULE_FAILURE, open_run=0, closed_run=950)],
                                       now=T0)
            self.assertEqual(0, store.incident_key_state(key)[RULE_FAILURE]['open'],
                             'a closure is the one move that may go down')

    def test_a_schedule_of_the_default_branch_is_main_and_pages_like_it(self):
        """Loudness follows the ref, not the trigger: `ci.yml@refs/heads/main` is the main plane.

        `plane_of` reads the branch, and a scheduled run of the default branch has one, so the nightly
        that cannot build is as loud as the push that cannot build. The row this replaces in the docs
        promised `warning` for "a scheduled run", which is true only of a schedule on another branch --
        and a nightly main-plane failure paging quieter than it does would be a surprise delivered as a
        table.
        """
        nightly = self._fact(1412, branch='main', event='schedule')
        other = self._fact(1413, branch='nightly-scan', event='schedule')
        self.assertEqual(('main', 'branch'), (nightly.plane, other.plane),
                         'the event names the trigger and the ref names the plane')
        # The live shape is the one that makes this worth pinning: a scheduled run arrives with no
        # `head_branch` at all, and the plane comes out of `ci.yml@refs/heads/main` alone.
        nightly_live = parse_run(REPO, gitea_run(1414, SHA_C, path='ci.yml@refs/heads/main',
                                                 event='schedule'), jobs=[gitea_job(1)],
                                 log=BAD_EXCERPT)
        self.assertEqual('main', nightly_live.plane,
                         'a schedule on the default branch is routed by its ref, not by its trigger')
        plan = plan_incident_keys([nightly, other, nightly_live], None, now=T0)
        severities = {incident_key(fact): event['severity'] for fact in (nightly, other, nightly_live)
                      for event in plan.events if event['rule_id'] == RULE_FAILURE
                      and event['resource_id'] == resource_id_for_key(incident_key(fact))}
        self.assertEqual(2, len(set(severities.values())),
                         'the live nightly shares the branch-shape nightly\'s subject, not a third one')
        self.assertEqual('critical', severities[incident_key(nightly)],
                         'the default branch is critical whatever trigger reached it')
        self.assertEqual('critical', severities[incident_key(nightly_live)])
        self.assertEqual('warning', severities[incident_key(other)],
                         'a schedule on another branch is the warning the table describes')
        for event in plan.events:
            validate_event(event, T0)

    def test_a_resolved_for_a_key_the_platform_never_opened_is_a_no_op(self):
        """The intake's answer, not this package's hope: accepted, no incident, no delivery booked.

        A marker can outlive the incident it refers to -- an operator closed it by hand, or the firing
        send never reached the platform -- so the closure arrives for a condition with no row. If that
        answer were a refusal, every tick would report a refused send for a workflow that is green.
        """
        platform = self._platform('unknown-key')
        fact = self._fact(1501, conclusion='success')
        key = incident_key(fact)
        states = {key: {RULE_FAILURE: {'open': 1500, 'closed': 0}}}
        plan = plan_incident_keys([fact], states, now=T0)
        resolved = [event for event in plan.events if event['status'] == 'resolved']
        self.assertEqual(1, len(resolved))
        outcome = platform.store.intake(dict(resolved[0]), platform.actor, now=T0)
        self.assertEqual('accepted', outcome['status'])
        self.assertIsNone(outcome['incident_id'], 'nothing was closed because nothing was open')
        self.assertIsNone(outcome['transition'], 'and no transition means no delivery was booked')
        self.assertEqual([], platform.store.records('incidents'))
        self.assertEqual([], platform.store.records('outbox'))
        receipts = PlatformAdmission(PlatformIntake(platform).admit).admit(resolved)
        self.assertEqual(['admitted'], [receipt.status for receipt in receipts],
                         'so the boundary calls it admitted, not refused -- a harmless answer')
        self.assertEqual('resolved', receipts[0].event_status)

    def test_a_recovery_and_a_closure_are_reported_together_and_never_invented_apart(self):
        """`recovered[]` keeps its meaning, and now points at the event it actually offered."""
        state = f'{self.temp.name}/both.sqlite3'
        platform = self._platform('both')
        queued = self._failing(1511, SHA_A, status='queued', conclusion='', when=T0)
        first = ActionsFake(runs=[queued], jobs={1511: [job(1, conclusion='', status='waiting',
                                                           steps=[])]}, log_text='all good')
        starved = self._tick(first, platform, state, T0 + dt.timedelta(hours=3))
        self.assertEqual('open', platform.status_of(RULE_STUCK))
        self.assertEqual((), starved.recovered)
        done = dict(queued, status='completed', conclusion='success')
        second = ActionsFake(runs=[done], jobs={1511: [job(1, conclusion='success')]},
                             log_text='all good')
        back = self._tick(second, platform, state, T0 + dt.timedelta(hours=4))
        self.assertEqual(1, len(back.recovered))
        self.assertEqual({'sent': True, 'reason': 'resolved-offered'},
                         back.recovered[0]['incident_statement'])
        self.assertEqual('resolved', platform.status_of(RULE_STUCK))
        self.assertEqual(1, back.resolved)


if __name__ == '__main__':
    unittest.main()

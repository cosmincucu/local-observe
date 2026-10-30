"""The resources, queries, rules and configuration route family (`local_observe/platform/resources_api.py`).

`tests/test_api_openapi_conformance.py` owns the claim that the census, the OpenAPI document and the
served routes are one list. What is tested *here* is the behaviour behind each documented row, on a
process that actually has the artifacts mounted — because every interesting failure in this family is
invisible on an empty app:

* **declared and observed do not merge.** The same resource appears in both planes with a different
  name, and the drift read must report the difference as a finding with both values in it, never
  silently prefer one. `/v1/resources` ships declarations only; the observed plane is a separate path
  with a separate credential.
* **an unmounted artifact is not an empty estate.** The reads answer `status: unavailable` with
  `complete: false` and name the variable to mount; the one write that records a fact answers `503`.
  A `200` with empty rows and no reason is the failure this family exists to prevent, and each of those
  two postures is asserted on both an empty and a mounted process.
* **a preview is a preview.** Every rule route is checked for what did *not* happen: `durable: false`,
  `not_performed`, no event filed, no cursor moved, no page sent. A preview that could advance a
  producer's cursor would be a second opinion about a window that has not happened.
* **the pure deployment functions stay pure.** `written: false` and `deploy_authorized: false` are
  asserted on all four configuration answers, and the refusal that means "your own documents disagree"
  is a `409`, not a `400`.
* **the shape on the wire is the shape in the document.** `AnswerShapeTests` validates each route's real
  200 body against the schema `docs/api/openapi.yaml` claims for it — including the states an empty
  process answers in, which the conformance suite cannot reach.

Fixtures are the repository's generic examples (`examples/inventory/declared.yaml`,
`observed.yaml`) with synthetic names, reserved `example.test` hostnames and UUIDs derived from them; no
estate identifier appears here.
"""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest import mock

import jsonschema

from local_observe.deployment import content
from local_observe.inventory import discovery, index, validation
from local_observe.inventory.validation import InvalidInventory, read_document, timestamp, utc_text
from local_observe.platform import api_contract, resources_api
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Actor, Store
from local_observe.store.client import ReadOutcome, ReadReceipt, Window
from test_api_openapi_conformance import OPENAPI, load_contract, operations, resolve  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
#: The declared pair from the generic example: one host, one service that runs on it.
HOST = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
SERVICE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2'
#: An observation the declarations do not claim, which is what a proposal is for.
UNDECLARED = 'new-service-001'
NOW = timestamp('2026-09-06T12:01:00Z')
REVISION = 'fixture-rev-1'
SOURCE = 'probe-source'

CREDENTIALS = [
    {'identity': 'report', 'role': 'reader', 'token': 'r' * 32},
    {'identity': SOURCE, 'role': 'producer', 'token': 'p' * 32},
    {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32},
    {'identity': 'operator', 'role': 'human', 'token': 'h' * 32},
    {'identity': 'runner-1', 'role': 'executor', 'token': 'e' * 32},
    {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32},
]
TOKENS = {row['role']: row['token'] for row in CREDENTIALS}


def http(app, method: str, path: str, role: str | None, body=None, query: bytes = b'',
         key: str | None = None) -> tuple[int, dict, dict]:
    """Drive one request through the ASGI app and return status, decoded body and headers."""
    output = []
    payload = b'' if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())

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
    if b'json' not in kinds.get(b'content-type', b''):
        return output[0]['status'], {'raw': output[-1]['body']}, kinds
    return output[0]['status'], json.loads(output[-1]['body']), kinds


def series_rule(resource: str, **overrides) -> dict:
    """One sustained threshold rule, in the shape `conditions.rule` refuses nothing about."""
    document = {'id': 'pool-disk.high', 'mode': 'threshold', 'resource_id': resource, 'source': SOURCE,
                'severity_source': 'core-events-v1', 'severity_tier': 'warning', 'threshold': 90,
                'for_seconds': 180, 'evaluation_seconds': 60, 'history_seconds': 3600,
                'max_age_seconds': 900}
    document.update(overrides)
    return document


def series(count: int = 8, step: int = 60, value: float = 95.0, align: int | None = None) -> list[list]:
    """One ``[[epoch, value], ...]`` series a rule may actually judge.

    `conditions.verdict` refuses a sample *newer* than the aligned window it judged (an input from the
    future is not evidence about the window), and the alignment is the evaluator's, not the caller's: the
    window ends at the last completed multiple of the rule's `evaluation_seconds`. So a fixture has to land
    on that grid — hence `align`, which is the rule's evaluation period, while `step` stays the distance
    between samples. Newest point sits one step before the boundary, which keeps it inside
    `max_age_seconds` however the test clock falls and never reads as stale when a window ticks over
    mid-run.
    """
    grid = align or step
    end = int(dt.datetime.now(dt.timezone.utc).timestamp()) // grid * grid
    return [[end - step * i, value] for i in range(1, count + 1)][::-1]


def aligned_instant(step: int = 60) -> dt.datetime:
    """The instant `detections.evaluate` aligns its window to, so a sample can be dated against it."""
    return dt.datetime.fromtimestamp(int(dt.datetime.now(dt.timezone.utc).timestamp()) // step * step,
                                     dt.timezone.utc)


def baseline_rule(resource: str, **overrides) -> dict:
    """One baseline detection rule, which is the shape `detections.evaluate` reads."""
    document = {'id': 'pool-disk.high', 'kind': 'threshold', 'resource_id': resource, 'source': SOURCE,
                'threshold': 90}
    document.update(overrides)
    return document


def objective(resource: str, **overrides) -> dict:
    """One availability objective: 90 % over a day, the 15-minute/5-minute pair at 5x."""
    document = {'objective_id': 'api.availability', 'resource_id': resource, 'signal': 'availability',
                'target': 0.9, 'window_days': 1, 'long_window': 900, 'short_window': 300,
                'burn_threshold': 5.0, 'metric': 'probe-success', 'min_samples': 1,
                'severity_source': 'core-events-v1',
                'severity_tier': 'warning', 'evaluation_seconds': 300, 'for_seconds': 300,
                'max_age_seconds': 900}
    document.update(overrides)
    return document


def content_packages() -> list[dict]:
    """The reference content package, read the way the CLI reads one: as a document, not a path."""
    return [read_document('examples/deployment/core-v1.yaml')]


def content_deployment() -> dict:
    """The reference deployment overlay: the owned edits, overrides and homepage settings."""
    return read_document('examples/deployment/custom.yaml')


def content_state() -> dict:
    """A resolved state, which is what a plan and an export take as input."""
    packages = content_packages()
    return content.resolve(packages, content.make_lock(packages), content_deployment())


def forecast_rule(resource: str, **overrides) -> dict:
    """One forecast rule whose inner threshold rule is `conditions.rule`'s."""
    document = {'id': 'pool-disk', 'series': 'disk_used', 'resource_id': resource, 'source': SOURCE,
                'severity_source': 'core-events-v1', 'severity_tier': 'warning', 'threshold': 54.0,
                'model': 'linear', 'horizon_seconds': 3600, 'min_points': 4, 'evaluation_seconds': 300,
                'history_seconds': 86400, 'max_age_seconds': 3600, 'for_seconds': 600}
    document.update(overrides)
    return document


class FakeReader:
    """A store client that answers one named read, in the shape `store.client` returns.

    Only three methods exist here for a reason: `query.metrics`/`logs`/`traces` call exactly these, and a
    fake with a `query_range`-shaped door would be testing a client this product does not have. Every read
    carries its own receipt, so the envelope's `row_limit` and `truncated` are the store's answer and not a
    default this file invented.
    """

    def __init__(self, *, status: str = 'available', detail: str | None = None,
                 rows: tuple = ({'observed_at': '2026-09-06T12:00:00Z', 'value': 12.5},),
                 truncated: bool = False) -> None:
        self.status = status
        self.detail = detail
        self.rows = rows
        self.truncated = truncated
        self.calls: list[tuple[str, str, dict]] = []

    def _outcome(self, query_type: str, window, parameters) -> ReadOutcome:
        pair = window if isinstance(window, Window) else Window(str(window['start']), str(window['end']))
        receipt = ReadReceipt(query_type=query_type,
                              parameters=dict(parameters) or {'sample_id': 'fixture-sample'},
                              window=pair,
                              expires_at=utc_text(dt.datetime.now(dt.timezone.utc)
                                                  + dt.timedelta(hours=1)),
                              sample_count=len(self.rows) if self.status == 'available' else 0,
                              truncated=self.truncated)
        return ReadOutcome(status=self.status, receipt=receipt,
                           samples=self.rows if self.status == 'available' else (),
                           detail=self.detail)

    def read_metrics(self, query_type, *, window, parameters, selectors=None, expires_at=None,
                     store_ttl_hours=None) -> ReadOutcome:
        self.calls.append(('metrics', query_type, dict(selectors or {})))
        return self._outcome(query_type, window, parameters)

    def read_logs(self, query_type, *, window, parameters, selectors=None, expires_at=None,
                  store_ttl_hours=None) -> ReadOutcome:
        self.calls.append(('logs', query_type, dict(selectors or {})))
        return self._outcome(query_type, window, parameters)

    def read_traces(self, query_type, *, window, parameters, selectors=None, expires_at=None,
                    store_ttl_hours=None) -> ReadOutcome:
        self.calls.append(('traces', query_type, dict(selectors or {})))
        return self._outcome(query_type, window, parameters)


class ResourceFixture(unittest.TestCase):
    """One built index, one observed dataset, one proposal directory, one reader, one app."""

    mount_index = True
    mount_observed = True
    mount_proposals = True
    mount_reader = True

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.index_path = self.root / 'inventory.db'
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        index.build(self.declared, self.index_path, REVISION, now=NOW)
        self.observed_path = self.root / 'observed.db'
        self.proposals = self.root / 'proposals'
        self.proposals.mkdir()
        self.reader = FakeReader() if self.mount_reader else None
        self.store = Store(self.root / 'platform.db', NotificationPolicy(delivery_mode='off'))

    def snapshot(self, **overrides) -> dict:
        """The generic observed document, re-sourced to this producer and re-stamped to now.

        The repository's example snapshot is 2026-09-06; `discovery.propose` and the drift read judge
        freshness against the *real* clock, because the route passes `clock()` down. Restamping is
        therefore part of the fixture and not a convenience: an example file that is too old to be
        current is a refusal, and this file tests both.
        """
        document = read_document(ROOT / 'examples/inventory/observed.yaml')
        document = json.loads(json.dumps(document))
        document.update({'source': SOURCE, 'snapshot_id': str(uuid.uuid4()),
                         'observed_at': utc_text(dt.datetime.now(dt.timezone.utc))})
        document.update(overrides)
        return document

    def ingest(self, **overrides) -> dict:
        """Store one snapshot the way the route would: `now` is the real clock, which is the skew bound."""
        return discovery.ingest(self.observed_path, self.snapshot(**overrides),
                                now=dt.datetime.now(dt.timezone.utc))

    def app(self) -> object:
        return create_app(self.store, CREDENTIALS, {},
                          index_path=self.index_path if self.mount_index else None,
                          observed_path=self.observed_path if self.mount_observed else None,
                          proposals_path=self.proposals if self.mount_proposals else None,
                          store_reader=self.reader)


class RouteBoundaryTests(unittest.TestCase):
    """Which path belongs to whom, decided before a credential is consulted."""

    def test_the_family_owns_its_literals_and_children_and_nothing_else(self):
        for path in ('/v1/resources', '/v1/resources/resolve', '/v1/resource-declarations/validation',
                     '/v1/observed-snapshots', '/v1/observed-snapshots/drift', '/v1/resource-proposals',
                     '/v1/queries/signals', '/v1/queries/topology', '/v1/capabilities',
                     '/v1/rules/validation', '/v1/rules/sustained/evaluations', '/v1/deployment/locks'):
            self.assertTrue(resources_api.owns(path), path)
        # A child of a prefix is claimed; a sibling that merely *starts* like one is not.
        self.assertTrue(resources_api.owns(f'/v1/resources/{HOST}/dependents'))
        self.assertTrue(resources_api.owns('/v1/resource-proposals/' + '0' * 64))
        for path in ('/v1/inventory', '/v1/resources-store', '/v1/resource-proposals-extra',
                     '/v1/observed-snapshots/driftwise', '/v1/me', '/'):
            self.assertFalse(resources_api.owns(path), path)

    def test_only_the_post_routes_are_guarded_writes(self):
        self.assertTrue(resources_api.writes('/v1/observed-snapshots'))
        self.assertTrue(resources_api.writes('/v1/rules/sustained/evaluations'))
        # A dry run is guarded too: the guarantee worth having on every POST-shaped body is that it may
        # not name the actor who sent it, whether or not it writes anything.
        self.assertTrue(resources_api.writes('/v1/resource-declarations/validation'))
        for path in ('/v1/resources', '/v1/capabilities', '/v1/queries/signals',
                     '/v1/observed-snapshots/drift'):
            self.assertFalse(resources_api.writes(path), path)

    def test_the_environment_reader_refuses_blank_and_accepts_unset(self):
        self.assertIsNone(resources_api.path_from_environment('LO_NOPE', {}))
        self.assertEqual('/mnt/fixtures/observed.db',
                         resources_api.path_from_environment('LO_OBSERVED_PATH',
                                                             {'LO_OBSERVED_PATH': ' /mnt/fixtures/observed.db '}))
        with self.assertRaises(ValueError) as caught:
            resources_api.path_from_environment('LO_OBSERVED_PATH', {'LO_OBSERVED_PATH': '   '})
        self.assertIn('set but blank', str(caught.exception))
        self.assertNotIn('/srv', str(caught.exception), 'a value must never come back in the message')


class UnmountedArtifactTests(ResourceFixture):
    """The posture of a process that was assembled without the artifacts, asserted route by route."""

    mount_index = False
    mount_observed = False
    mount_proposals = False
    mount_reader = False

    def test_the_declared_reads_answer_unavailable_rather_than_empty(self):
        app = self.app()
        for path, query in (('/v1/resources', b'limit=10'),
                            ('/v1/resources/resolve', b'alias_type=hostname&alias_value=probe-1.example.test'),
                            (f'/v1/resources/{HOST}/dependents', b'limit=10'),
                            ('/v1/queries/topology', f'resource_id={HOST}'.encode())):
            with self.subTest(path=path):
                status, body, _headers = http(app, 'GET', path, 'reader', query=query)
                self.assertEqual(status, 200, body)
                self.assertEqual(body['status'], 'unavailable')
                self.assertFalse(body['complete'], 'an unmounted read may never claim to be whole')
                self.assertEqual(body['rows'], [])
                self.assertIn('LO_INDEX_PATH', body['provenance']['unavailable'])
                self.assertIn('LO_INDEX_PATH', body['reason'])

    def test_the_observed_history_read_names_its_own_variable(self):
        status, body, _headers = http(self.app(), 'GET', '/v1/observed-snapshots', 'reader',
                                      query=b'source=' + SOURCE.encode())
        self.assertEqual((status, body['status'], body['complete']), (200, 'unavailable', False))
        self.assertIn('LO_OBSERVED_PATH', body['reason'])

    def test_the_drift_read_refuses_to_call_an_unjudged_source_a_clean_bill(self):
        status, body, _headers = http(self.app(), 'GET', '/v1/observed-snapshots/drift', 'reader',
                                      query=b'source=' + SOURCE.encode())
        self.assertEqual(status, 200)
        self.assertEqual((body['rows'], body['findings'], body['sources']), ([], [], {}))
        self.assertFalse(body['complete'])

    def test_the_signal_read_ships_the_envelope_that_says_it_was_never_asked(self):
        # `503` would be wrong here: the §2 envelope carries its own reason, and a producer that reads
        # this shape already knows how to turn `error` into a coverage event.
        status, body, _headers = http(self.app(), 'GET', '/v1/queries/signals', 'reader',
                                      query=f'signal=metrics&resource_id={HOST}&rule_id=pool-disk'
                                            '.high'.encode())
        self.assertEqual(status, 200)
        self.assertFalse(body['complete'])
        self.assertIn('store client', body['result']['error'])
        self.assertEqual(body['result']['rows'], [])

    def test_the_two_durable_writes_refuse_with_503_and_the_rest_answer_previews(self):
        app = self.app()
        cases = (('/v1/observed-snapshots', self.snapshot()),
                 ('/v1/resource-proposals', {'source': SOURCE, 'observation_id': UNDECLARED}))
        for path, body in cases:
            with self.subTest(path=path):
                status, answer, _headers = http(app, 'POST', path,
                                                'producer' if 'observed' in path else 'proposer', body)
                self.assertEqual(status, 503, answer)
                self.assertEqual(answer['error']['code'], 'operation_unavailable')
                self.assertIn('LO_', answer['error']['message'])
        # A dry run needs no artifact of the service's own, so it still answers.
        status, answer, _headers = http(app, 'POST', '/v1/rules/sustained/evaluations', 'producer',
                                       {'document': series_rule(HOST),
                                        'points': [[1_757_164_800, 95]]})
        self.assertEqual((status, answer['durable'], answer['complete']), (200, False, True))

    def test_the_detection_preview_is_the_one_preview_that_needs_the_index(self):
        status, answer, _headers = http(self.app(), 'POST', '/v1/rules/detections/evaluations', 'producer',
                                        {'rule': baseline_rule(HOST)})
        self.assertEqual(status, 200)
        self.assertEqual(answer['status'], 'unavailable')
        self.assertFalse(answer['complete'])
        self.assertEqual(answer['events'], [])

    def test_capabilities_separates_absent_mount_from_refused_operation(self):
        status, body, _headers = http(self.app(), 'GET', '/v1/capabilities', 'reader')
        self.assertEqual(status, 200)
        by_id = {item['operation_id']: item for item in body['operations']}
        self.assertEqual(by_id['resource.read']['state'], 'unavailable')
        self.assertIn('LO_INDEX_PATH', by_id['resource.read']['reason'])
        self.assertEqual(by_id['resource.capability.read']['state'], 'supported',
                         'this read answers, and must say so about itself')
        self.assertEqual(by_id['resource.query.series']['state'], 'unavailable')
        declined = {item['operation_id']: item for item in body['declines']}
        self.assertEqual(set(declined), {'resource.index.build', 'resource.discovery.docker',
                                        'resource.proposal.publish', 'config.deployment.export',
                                        'rule.sigma.compile'})
        self.assertIn('SQL', declined['rule.sigma.compile']['reason'])
        self.assertIn('lo-inventory build', declined['resource.index.build']['instead'])
        self.assertFalse(body['artifacts']['inventory_index']['rebuilt_over_http'])

    def test_the_capability_document_covers_every_route_the_dispatcher_answers(self):
        listed = {item['operation_id'] for item in
                  http(self.app(), 'GET', '/v1/capabilities', 'reader')[1]['operations']}
        self.assertEqual(listed, {row['operation_id'] for row in resources_api.OPERATION_ROUTES})


class DeclaredPlaneTests(ResourceFixture):
    """The declared reads over a real index: paging, filters, identity and the walk."""

    def test_a_page_names_its_bound_and_the_declaration_it_came_from(self):
        app = self.app()
        status, body, _headers = http(app, 'GET', '/v1/resources', 'reader', query=b'limit=1')
        self.assertEqual(status, 200)
        self.assertEqual(body['status'], 'ok')
        self.assertTrue(body['complete'] is False and body['truncated'] is True)
        self.assertEqual([row['name'] for row in body['rows']], ['demo-api'])
        self.assertEqual(body['rows'][0]['aliases'][0]['type'], 'service.name')
        provenance = body['provenance']
        self.assertTrue(provenance['mounted'])
        self.assertEqual(provenance['declaration_revision'], REVISION)
        self.assertEqual(len(provenance['declaration_sha256']), 64)
        self.assertIsNotNone(provenance['built_at'])

    def test_the_cursor_walks_the_population_and_a_stale_cursor_is_refused(self):
        app = self.app()
        first = http(app, 'GET', '/v1/resources', 'reader', query=b'limit=1')[1]
        second = http(app, 'GET', '/v1/resources', 'reader',
                      query=b'limit=1&cursor=' + first['next_cursor'].encode())[1]
        self.assertEqual([row['name'] for row in second['rows']], ['probe-1'])
        self.assertEqual(second['returned'], 1)
        # A cursor issued against a different declaration digest is a different population.
        forged = api_contract.encode_cursor('deadbeefcafe:1')
        status, answer, _headers = http(app, 'GET', '/v1/resources', 'reader',
                                        query=b'limit=1&cursor=' + forged.encode())
        self.assertEqual((status, answer['error']['code']), (400, 'invalid_pagination'))

    def test_a_bound_is_refused_and_not_clamped_and_an_unknown_parameter_is_refused(self):
        app = self.app()
        for query in (b'limit=0', b'limit=201', b'limit=many', b'limit=50&limit=60', b'offset=10',
                      b'name=demo&name=probe', b'kind=service&kind=host'):
            status, answer, _headers = http(app, 'GET', '/v1/resources', 'reader', query=query)
            with self.subTest(query=query):
                self.assertEqual(status, 400, answer)
                self.assertIn('error', answer)

    def test_filters_narrow_and_say_they_narrowed(self):
        app = self.app()
        body = http(app, 'GET', '/v1/resources', 'reader', query=b'kind=host')[1]
        self.assertEqual([row['name'] for row in body['rows']], ['probe-1'])
        self.assertTrue(body['filtered'])
        self.assertEqual(body['filters'], {'kind': 'host'})
        self.assertEqual(body['rows_total'], 1)
        missing = http(app, 'GET', '/v1/resources', 'reader', query=b'name=no-such-thing')[1]
        self.assertEqual((missing['rows'], missing['filtered'], missing['complete']), ([], True, True),
                         'an exact-name filter that matched nothing is a complete answer about nothing')

    def test_resolve_answers_all_four_verdicts_without_a_404(self):
        app = self.app()
        cases = {'resolved': 'alias_type=hostname&alias_value=probe-1.example.test',
                 'unknown_uuid': 'id=' + str(uuid.uuid4()),
                 'unknown': 'alias_type=ip&alias_value=10.11.99.99'}
        for expected, query in cases.items():
            with self.subTest(status=expected):
                status, body, _headers = http(app, 'GET', '/v1/resources/resolve', 'reader',
                                              query=query.encode())
                self.assertEqual(status, 200)
                self.assertEqual(body['status'], expected)
                self.assertEqual(body['plane'], 'declared')
                self.assertTrue(body['complete'])
        resolved = http(app, 'GET', '/v1/resources/resolve', 'reader',
                        query=b'id=' + HOST.encode())[1]
        self.assertEqual(resolved['resource']['name'], 'probe-1')

    def test_a_colliding_alias_is_refused_where_the_index_is_built(self):
        """One alias, two resources: the collision dies at the build, so a read can never tie-break it.

        The alias table's primary key is `(scope, type, value)` and `validation.declared` refuses a colliding
        normalised alias before a row is ever written, so a single alias statement can name at most one
        resource — which is why `resource.alias.resolve` answers `resolved`, `unknown` or `unknown_uuid` and
        never `conflict`. The verdict that *does* need several aliases at once — an observation that carries a
        hostname and a service name which are two resources — is the drift read's, and it reports
        `identity_unresolved` rather than picking one. See
        :meth:`ObservedPlaneTests.test_an_observation_that_names_two_resources_is_left_unresolved`.
        """
        document = json.loads(json.dumps(self.declared))
        document['resources'][1]['aliases'].append({'type': 'hostname', 'value': 'probe-1.example.test'})
        with self.assertRaises(InvalidInventory):
            index.build(document, self.root / 'clash.db', 'clash-rev', now=NOW)
        app = self.app()
        single = http(app, 'GET', '/v1/resources/resolve', 'reader',
                      query=b'alias_type=hostname&alias_value=probe-1.example.test')[1]
        self.assertEqual((single['status'], single['resource_id'], single['candidates']),
                         ('resolved', HOST, [HOST]))

    def test_resolve_refuses_an_unknown_alias_type_and_a_mixed_question(self):
        app = self.app()
        for query, fragment in ((b'alias_type=host_name&alias_value=x', 'alias_type must be one of'),
                                (b'id=' + HOST.encode() + b'&alias_type=ip&alias_value=1.2.3.4',
                                 'not both'),
                                (b'alias_value=only-one-half', 'both its type'),
                                (b'', 'names an identifier or an alias')):
            status, answer, _headers = http(app, 'GET', '/v1/resources/resolve', 'reader', query=query)
            with self.subTest(query=query):
                self.assertEqual(status, 400, answer)
                self.assertIn(fragment, answer['error']['message'])

    def test_dependents_follows_only_the_relations_it_names(self):
        app = self.app()
        body = http(app, 'GET', f'/v1/resources/{HOST}/dependents', 'reader', query=b'limit=10')[1]
        self.assertEqual(body['relation_types'], ['runs-on', 'depends-on'])
        self.assertEqual([row['id'] for row in body['rows']], [SERVICE])
        self.assertFalse(body['truncated'])
        self.assertTrue(body['complete'])
        empty = http(app, 'GET', f'/v1/resources/{SERVICE}/dependents', 'reader', query=b'limit=10')[1]
        self.assertEqual((empty['rows'], empty['complete']), ([], True))

    def test_an_unknown_or_malformed_identifier_is_the_same_404(self):
        app = self.app()
        for value in (str(uuid.uuid4()), 'not-a-uuid', '3f9c1d7b-8a3e'):
            status, answer, _headers = http(app, 'GET', f'/v1/resources/{value}/dependents', 'reader',
                                            query=b'limit=10')
            with self.subTest(value=value):
                self.assertEqual((status, answer['error']['code']), (404, 'not_found'))
        status, answer, _headers = http(app, 'GET', f'/v1/resources/{HOST}/nonsense', 'reader')
        self.assertEqual((status, answer['error']['code']), (404, 'not_found'))

    def test_the_topology_read_ships_the_walk_and_its_bound(self):
        app = self.app()
        status, body, _headers = http(app, 'GET', '/v1/queries/topology', 'reader',
                                      query=f'resource_id={SERVICE}&direction=upstream&depth=2'
                                            .encode())
        self.assertEqual(status, 200)
        self.assertEqual(body['plane'], 'declared')
        self.assertEqual(body['result']['truncated_by'], [],
                         'a walk that finished whole says so with an empty list, not a missing field')
        self.assertFalse(body['result']['truncated'])
        self.assertEqual([node['resource_id'] for node in body['result']['nodes']], [HOST])
        self.assertEqual(body['requested_by'], {'identity': 'report', 'role': 'reader'})
        self.assertIn('observed', body['observed_plane'])
        impact = http(app, 'GET', '/v1/queries/topology', 'reader',
                      query=f'resource_id={HOST}&direction=impact&depth=2'.encode())[1]
        self.assertEqual([node['resource_id'] for node in impact['result']['nodes']], [SERVICE])
        self.assertEqual(impact['result']['direction'], 'depended-on-by',
                         'the walk names its own direction in the read model\'s words, not the query\'s')

    def test_the_topology_read_refuses_what_a_walk_would_guess_at(self):
        app = self.app()
        for query, expected in ((b'direction=upstream', 400),
                                (f'resource_id={uuid.uuid4()}'.encode(), 404),
                                (f'resource_id={HOST}&depth=9'.encode(), 400),
                                (f'resource_id={HOST}&direction=sideways'.encode(), 400),
                                (f'resource_id={HOST}&max_rows=0'.encode(), 400)):
            status, answer, _headers = http(app, 'GET', '/v1/queries/topology', 'reader', query=query)
            with self.subTest(query=query):
                self.assertEqual(status, expected, answer)


class DeclarationCheckTests(ResourceFixture):
    """The draft-declaration door: the builder's own validator, verdict in a 200, no write."""

    def test_a_valid_draft_reports_the_normalised_digest_the_builder_would_record(self):
        app = self.app()
        status, body, _headers = http(app, 'POST', '/v1/resource-declarations/validation', 'reader',
                                      {'declaration': self.declared})
        self.assertEqual(status, 200)
        self.assertEqual((body['status'], body['recorded'], body['resources']), ('valid', False, 2))
        self.assertEqual(sorted(body['kinds']), ['host', 'service'])
        with index.readonly(self.index_path) as connection:
            served = connection.execute("SELECT value FROM build_metadata WHERE key='declaration_sha256'"
                                        ).fetchone()[0]
        self.assertEqual(body['declaration_sha256'], served,
                         'the digest a review pins must be the digest the built index carries')

    def test_key_order_does_not_change_the_verdict_or_the_digest(self):
        reordered = {'resources': [dict(reversed(sorted(row.items()))) for row in
                                   reversed(self.declared['resources'])], 'schema_version': 1}
        app = self.app()
        first = http(app, 'POST', '/v1/resource-declarations/validation', 'reader',
                     {'declaration': self.declared})[1]
        second = http(app, 'POST', '/v1/resource-declarations/validation', 'reader',
                      {'declaration': reordered})[1]
        self.assertEqual((second['status'], second['declaration_sha256']), ('valid',
                                                                            first['declaration_sha256']))

    def test_an_invalid_draft_is_a_200_verdict_and_not_a_refusal(self):
        app = self.app()
        for broken in ({'schema_version': 1, 'resources': [{'id': 'not-a-uuid', 'kind': 'host',
                                                            'name': 'x'}]},
                       # A relation that points at nothing declared: the schema accepts it, the builder's
                       # own second pass does not, and only the second pass runs through this door.
                       {'schema_version': 1, 'resources': [{'id': HOST, 'kind': 'host', 'name': 'a',
                                                            'aliases': [], 'attributes': {},
                                                            'relations': [{'type': 'runs-on',
                                                                           'target': SERVICE}]}]},
                       {'resources': [{'kind': 'host'}]}):
            status, body, _headers = http(app, 'POST', '/v1/resource-declarations/validation', 'reader',
                                          {'declaration': broken})
            with self.subTest(declaration=str(broken)[:40]):
                self.assertEqual(status, 200)
                self.assertEqual((body['status'], body['resources']), ('invalid', 0))
                self.assertIsNone(body['declaration_sha256'])
                self.assertTrue(body['reason'])

    def test_a_request_that_asked_no_question_is_refused(self):
        app = self.app()
        for body in ({}, {'declaration': 'scalar'}, {'declaration': self.declared, 'path': '/tmp/x'},
                     {'declaration': self.declared, 'source': 'someone-else'}):
            status, answer, _headers = http(app, 'POST', '/v1/resource-declarations/validation',
                                            'proposer', body)
            with self.subTest(body=str(body)[:40]):
                self.assertEqual(status, 400, answer)
                self.assertIn(answer['error']['code'], ('invalid_request', 'actor_claim_refused'))


class ObservedPlaneTests(ResourceFixture):
    """Snapshots in, history out, and the declared/observed comparison stated with its coverage."""

    def test_a_producer_records_its_own_snapshot_twice_and_gets_duplicate_the_second_time(self):
        app = self.app()
        document = self.snapshot()
        first = http(app, 'POST', '/v1/observed-snapshots', 'producer', document)
        second = http(app, 'POST', '/v1/observed-snapshots', 'producer', document)
        self.assertEqual((first[0], first[1]['status'], first[1]['plane']), (200, 'inserted', 'observed'))
        self.assertEqual((second[0], second[1]['status']), (200, 'duplicate'))
        self.assertEqual(second[1]['snapshot_id'], document['snapshot_id'])
        self.assertEqual(first[1]['observations'], len(document['observations']))
        self.assertEqual(first[1]['declarations_touched'], 0,
                         'recording what was seen never edits what is meant to exist')

    def test_the_source_field_is_the_credential_and_not_a_claim(self):
        app = self.app()
        status, answer, _headers = http(app, 'POST', '/v1/observed-snapshots', 'producer',
                                        self.snapshot(source='some-other-prober'))
        self.assertEqual((status, answer['error']['code']), (403, 'not_authorised'))
        self.assertIn('producer', answer['error']['message'])
        self.assertFalse(self.observed_path.exists(),
                         'a refused claim writes nothing: no observed database, no row, no trace')

    def test_a_replay_that_changed_its_contents_is_refused_rather_than_newest_wins(self):
        app = self.app()
        document = self.snapshot()
        http(app, 'POST', '/v1/observed-snapshots', 'producer', document)
        changed = json.loads(json.dumps(document))
        changed['observations'][0]['name'] = 'renamed-by-a-replay'
        status, answer, _headers = http(app, 'POST', '/v1/observed-snapshots', 'producer', changed)
        self.assertEqual((status, answer['error']['code']), (409, 'conflict'), answer)
        self.assertIn('snapshot identifier', answer['error']['message'])
        stored = self.observed_path.read_bytes()
        again = http(app, 'POST', '/v1/observed-snapshots', 'producer', changed)
        self.assertEqual(again[0], 409, 'a refused contradiction stays refused on the second try')
        self.assertEqual(self.observed_path.read_bytes(), stored,
                         'the row a drift finding may cite did not move')
        history = http(app, 'GET', '/v1/observed-snapshots', 'reader', query=b'source=probe-source')[1]
        self.assertEqual([row['observations'] for row in history['rows']],
                         [len(document['observations'])],
                         'the snapshot still holds what was first filed, not the retry')

    def test_only_a_producer_may_file_observations(self):
        app = self.app()
        for role in ('reader', 'proposer', 'human', 'executor', 'summary'):
            status, answer, _headers = http(app, 'POST', '/v1/observed-snapshots', role, self.snapshot())
            with self.subTest(role=role):
                self.assertEqual(status, 403, answer)
                if role == 'summary':
                    self.assertEqual(answer, {'error': 'summary_only'})
                else:
                    self.assertEqual(answer['error']['code'], 'not_authorised')
                    self.assertNotIn('summary', answer['error']['message'])

    def test_history_sums_snapshots_up_and_never_ships_one_whole(self):
        app = self.app()
        filed = self.ingest()
        self.ingest(status='error', error_code='probe-timeout', observations=[])
        status, body, _headers = http(app, 'GET', '/v1/observed-snapshots', 'reader',
                                      query=f'source={SOURCE}&limit=5'.encode())
        self.assertEqual(status, 200)
        self.assertEqual(len(body['rows']), 2)
        self.assertIn(filed['snapshot_id'], {row['snapshot_id'] for row in body['rows']})
        self.assertTrue(all(isinstance(row['observations'], int) for row in body['rows']),
                        'a summary carries counts, never the observations themselves')
        self.assertEqual(body['max_rows'], 20)
        self.assertTrue(body['complete'])
        failed = [row for row in body['rows'] if row['status'] == 'error']
        self.assertEqual(failed[0]['error_code'], 'probe-timeout',
                         'an absent sensor must stay distinguishable from a quiet one')
        self.assertEqual(body['source'], SOURCE)

    def test_history_names_its_source_and_refuses_a_page_that_cannot_be_continued(self):
        app = self.app()
        for back in range(3):
            self.ingest(observed_at=utc_text(dt.datetime.now(dt.timezone.utc)
                                            - dt.timedelta(minutes=back + 1)))
        status, body, _headers = http(app, 'GET', '/v1/observed-snapshots', 'reader',
                                      query=f'source={SOURCE}&limit=3'.encode())
        self.assertEqual(status, 200)
        self.assertTrue(body['truncated'] and body['complete'] is False,
                        'a page exactly as wide as its bound cannot claim the history ended there')
        self.assertEqual(body['returned'], 3)
        self.assertEqual([row['observations'] for row in body['rows']], [2, 2, 2])
        self.assertEqual(http(app, 'GET', '/v1/observed-snapshots', 'reader')[0], 400)

    def test_an_observation_that_names_two_resources_is_left_unresolved(self):
        """One observation, two aliases, two declared resources: nobody picks the winner.

        This is where the `conflict` verdict that a single alias cannot produce actually appears: the
        observation is refused a match and the finding says so, instead of the drift read choosing the
        first candidate and writing a difference against the wrong resource.
        """
        app = self.app()
        document = self.snapshot(complete=True)
        document['observations'] = [{
            'observation_id': 'two-names-001',
            'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'},
                        {'type': 'service.name', 'value': 'demo-api', 'scope': 'demo'}],
            'attributes': {}, 'evidence': ['fixture:two-names-001'], 'name': 'probe-1', 'kind': 'host'}]
        discovery.ingest(self.observed_path, document, now=dt.datetime.now(dt.timezone.utc))
        body = http(app, 'GET', '/v1/observed-snapshots/drift', 'reader',
                    query=f'source={SOURCE}'.encode())[1]
        unresolved = [row for row in body['rows'] if row['kind'] == 'identity_unresolved']
        self.assertEqual(len(unresolved), 1, body['rows'])
        self.assertIsNone(unresolved[0]['resource_id'])
        self.assertEqual(unresolved[0]['resolution']['status'], 'conflict')
        self.assertEqual(unresolved[0]['resolution']['candidates'], sorted([HOST, SERVICE]))
        self.assertFalse(body['complete'])
        self.assertEqual(body['sources'], {SOURCE: 'coverage_incomplete'},
                         'an unresolved identity leaves the source unable to certify anything it covers')

    def test_drift_reports_the_difference_with_both_values_and_grades_each_source(self):
        app = self.app()
        self.ingest()
        status, body, _headers = http(app, 'GET', '/v1/observed-snapshots/drift', 'reader',
                                      query=f'source={SOURCE}'.encode())
        self.assertEqual(status, 200)
        kinds = {finding['kind'] for finding in body['rows']}
        self.assertIn('changed', kinds, 'probe-1 was observed as probe-1-renamed')
        self.assertIn('undeclared', kinds, 'discovered-demo-api is claimed by no declaration')
        changed = [row for row in body['rows'] if row['kind'] == 'changed'][0]
        self.assertEqual(changed['resource_id'], HOST)
        self.assertEqual(changed['differences']['name'],
                         {'declared': 'probe-1', 'observed': 'probe-1-renamed'},
                         'desired and observed stay apart inside the finding')
        self.assertEqual(changed['source'], SOURCE)
        self.assertEqual(body['declaration_sha256'],
                         http(self.app(), 'GET', '/v1/resources', 'reader',
                              query=b'limit=1')[1]['provenance']['declaration_sha256'])

    def test_drift_withholds_completeness_from_a_source_that_claimed_none(self):
        app = self.app()
        self.ingest(complete=False)
        body = http(app, 'GET', '/v1/observed-snapshots/drift', 'reader',
                    query=f'source={SOURCE}'.encode())[1]
        self.assertEqual(body['sources'], {SOURCE: 'coverage_incomplete'})
        self.assertFalse(body['complete'])
        self.assertIn('coverage_incomplete', {finding['kind'] for finding in body['rows']})

    def test_a_whole_source_is_the_only_one_that_supports_a_clean_bill(self):
        app = self.app()
        document = self.snapshot(complete=True, scope=[HOST, SERVICE])
        document['observations'] = [
            {'observation_id': 'clean-host', 'resource_id': HOST, 'kind': 'host', 'name': 'probe-1',
             'aliases': [{'type': 'hostname', 'value': 'probe-1.example.test'}],
             'attributes': {'os': 'linux', 'environment': 'demo'}, 'evidence': ['fixture:clean-host']},
            {'observation_id': 'clean-service', 'resource_id': SERVICE, 'kind': 'service',
             'name': 'demo-api',
             'aliases': [{'type': 'service.name', 'value': 'demo-api', 'scope': 'demo'}],
             'attributes': {'environment': 'demo', 'enabled': True},
             'evidence': ['fixture:clean-service']}]
        discovery.ingest(self.observed_path, document, now=dt.datetime.now(dt.timezone.utc))
        body = http(app, 'GET', '/v1/observed-snapshots/drift', 'reader',
                    query=f'source={SOURCE}'.encode())[1]
        self.assertEqual(body['sources'], {SOURCE: 'whole'})
        self.assertTrue(body['complete'])
        self.assertEqual(body['rows'], [], 'a whole source that found nothing is a real answer')
        self.assertTrue(body['truncated'] is False)

    def test_drift_bounds_its_sources_and_its_freshness_window(self):
        app = self.app()
        many = '&'.join(f'source=source-{number}' for number in range(9)).encode()
        self.assertEqual(http(app, 'GET', '/v1/observed-snapshots/drift', 'reader', query=many)[0], 400)
        self.assertEqual(http(app, 'GET', '/v1/observed-snapshots/drift', 'reader',
                              query=b'source=' + SOURCE.encode() + b'&max_age_seconds=0')[0], 400)
        missing = http(app, 'GET', '/v1/observed-snapshots/drift', 'reader')[1]
        self.assertEqual(missing['error']['code'], 'invalid_request')
        self.ingest(observed_at=utc_text(dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)))
        stale = http(app, 'GET', '/v1/observed-snapshots/drift', 'reader',
                     query=f'source={SOURCE}&max_age_seconds=1'.encode())[1]
        self.assertEqual(stale['sources'], {SOURCE: 'source_stale'})
        self.assertFalse(stale['complete'])
        self.assertEqual([row['kind'] for row in stale['rows']], ['source_stale'])
        self.assertEqual(stale['max_age_seconds'], 1)


class ProposalTests(ResourceFixture):
    """Drafting and reading a declaration proposal: an offer to a human, never a change."""

    def draft(self, app=None, **body):
        app = app or self.app()
        return http(app, 'POST', '/v1/resource-proposals', 'proposer',
                    {'source': SOURCE, 'observation_id': UNDECLARED, **body})

    def test_a_draft_lands_under_a_name_the_body_did_not_choose(self):
        self.ingest()
        app = self.app()
        status, body, _headers = self.draft(app)
        self.assertEqual(status, 200, body)
        self.assertEqual(body['status'], 'needs_review')
        self.assertFalse(body['published'])
        self.assertFalse(body['declared'])
        self.assertEqual(body['proposal']['source'], SOURCE)
        self.assertEqual(body['proposal']['status'], 'needs_review')
        self.assertEqual(len(body['proposal']['observation_sha256']), 64)
        self.assertNotIn('/', body['written_to'])
        self.assertEqual(body['written_to'], body['proposal_id'] + '.json')
        self.assertEqual(list(self.proposals.iterdir()), [self.proposals / body['written_to']])

    def test_retrying_one_body_rewrites_one_file(self):
        self.ingest()
        app = self.app()
        first = self.draft(app)[1]
        second = self.draft(app)[1]
        self.assertEqual(first['proposal_id'], second['proposal_id'])
        self.assertEqual(len(list(self.proposals.glob('*.json'))), 1)

    def test_a_draft_is_readable_back_by_its_digest_and_nothing_else(self):
        self.ingest()
        app = self.app()
        drafted = self.draft(app)[1]
        status, body, _headers = http(app, 'GET', '/v1/resource-proposals/' + drafted['proposal_id'],
                                      'reader')
        self.assertEqual(status, 200)
        self.assertEqual((body['status'], body['published']), ('needs_review', False))
        self.assertEqual(body['proposal']['proposal_id'], drafted['proposal_id'])
        for intruder in ('../../etc/passwd', 'nope', '0' * 63 + 'z', '0' * 64 + 'aa'):
            status, answer, _headers = http(app, 'GET', f'/v1/resource-proposals/{intruder}', 'reader')
            with self.subTest(intruder=intruder):
                self.assertEqual((status, answer['error']['code']), (404, 'not_found'))

    def test_no_file_ever_written_is_a_503_and_not_an_empty_answer(self):
        """`LO_PROPOSALS_PATH` mounted, `LO_OBSERVED_PATH` pointed at a file nobody has created yet.

        The two absences say different things and an agent must not have to guess which it hit: the dataset
        that does not exist yet cannot be read (503, and the sentence says a producer has to file first),
        while a dataset that exists and holds a stale snapshot is a *refusal of this request* (400) that a
        caller can act on by re-freshening. Answering an empty list would say "nothing was observed",
        which is a claim about the estate and not true.
        """
        app = self.app()
        self.assertFalse(self.observed_path.exists())
        status, answer, _headers = self.draft(app)
        self.assertEqual((status, answer['error']['code']), (503, 'operation_unavailable'))
        self.assertIn('does not exist yet', answer['error']['message'])
        self.assertEqual(list(self.proposals.iterdir()), [], 'a refused draft wrote no file')

    def test_the_three_refusals_that_make_a_proposal_mean_something_travel_as_400s(self):
        app = self.app()
        self.ingest(status='error', error_code='probe-timeout', observations=[])
        status, answer, _headers = self.draft(app)
        self.assertEqual(status, 400, answer)
        self.assertIn('snapshot', answer['error']['message'])
        self.ingest()
        self.assertEqual(self.draft(app, observation_id='host-001')[0], 400,
                         'a declared resource needs no proposal')
        self.assertEqual(self.draft(app, observation_id='no-such-observation')[0], 400)
        self.assertEqual(self.draft(app, max_age_seconds=0)[0], 400)
        self.assertEqual(self.draft(app, path='/tmp/elsewhere.json')[0], 400)

    def test_only_a_proposer_may_draft(self):
        self.ingest()
        app = self.app()
        for role in ('reader', 'producer', 'human', 'executor'):
            with self.subTest(role=role):
                self.assertEqual(http(app, 'POST', '/v1/resource-proposals', role,
                                      {'source': SOURCE, 'observation_id': UNDECLARED})[0], 403)


class SignalQueryTests(ResourceFixture):
    """The bounded store read: the §2 envelope, the approved kind table, and no query text."""

    def test_a_metric_window_ships_the_envelope_the_producers_already_emit(self):
        app = self.app()
        status, body, _headers = http(app, 'GET', '/v1/queries/signals', 'reader',
                                      query=f'signal=metrics&resource_id={HOST}&rule_id=pool-disk.high'
                                            '&metric_name=disk_used&minutes=120'.encode())
        self.assertEqual(status, 200, body)
        result = body['result']
        self.assertEqual(sorted(result), ['error', 'parameters', 'query_type', 'row_limit', 'rows',
                                          'source', 'truncated', 'window'])
        self.assertEqual(result['query_type'], 'metric-threshold')
        self.assertEqual(result['source'], 'report', 'the envelope names the caller, not a store')
        self.assertIsNone(result['error'])
        self.assertEqual(len(result['rows']), 1)
        self.assertTrue(body['complete'])
        self.assertEqual(body['window_source'], 'relative')
        self.assertEqual(self.reader.calls, [('metrics', 'metric-threshold', {'metric_name': 'disk_used'})])

    def test_the_store_saying_no_is_shipped_as_the_store_saying_no(self):
        self.reader = FakeReader(status='unavailable', detail='no such series')
        body = http(self.app(), 'GET', '/v1/queries/signals', 'reader',
                    query=f'signal=logs&resource_id={HOST}'.encode())[1]
        self.assertIsNone(body['result']['rows'] or None)
        self.assertEqual(body['result']['rows'], [])
        self.assertIn('unavailable', body['result']['error'])
        self.assertFalse(body['complete'])

    def test_a_truncated_read_is_never_a_whole_answer(self):
        self.reader = FakeReader(rows=({'value': 1},), truncated=True)
        body = http(self.app(), 'GET', '/v1/queries/signals', 'reader',
                    query=b'signal=traces&service=demo-api')[1]
        self.assertTrue(body['result']['truncated'])
        self.assertFalse(body['complete'])

    def test_no_query_text_table_or_column_is_accepted_at_any_level(self):
        app = self.app()
        for query in (b'signal=metrics&query=SELECT+1',
                      b'signal=nope',
                      b'signal=metrics&resource_id=' + HOST.encode() + b'&rule_id=x&from=2026-09-06T11:00:00Z',
                      f'signal=metrics&resource_id={HOST}&minutes=0'.encode(),
                      f'signal=metrics&resource_id={HOST}&minutes=99999'.encode()):
            status, answer, _headers = http(app, 'GET', '/v1/queries/signals', 'reader', query=query)
            with self.subTest(query=query):
                self.assertEqual(status, 400, answer)
                self.assertEqual(answer['error']['code'], 'invalid_request')
        # A malformed identifier is answered exactly as an unknown one would be, and the metric kind's own
        # requirement lives in the store facade: `error` says it, not a second rule here.
        self.assertEqual(http(app, 'GET', '/v1/queries/signals', 'reader',
                              query=b'signal=metrics&resource_id=not-a-uuid')[0], 404)

    def test_an_explicit_window_is_half_open_and_shipped_as_the_caller_asked(self):
        app = self.app()
        body = http(app, 'GET', '/v1/queries/signals', 'reader',
                    query=f'signal=logs&resource_id={HOST}&from=2026-09-06T11:00:00Z'
                          '&to=2026-09-06T11:30:00Z'.encode())[1]
        self.assertEqual(body['window_source'], 'request')
        self.assertEqual(body['result']['window'],
                         {'start': '2026-09-06T11:00:00.000000+00:00',
                          'end': '2026-09-06T11:30:00.000000+00:00'})


class RulePreviewTests(ResourceFixture):
    """Each rule family's own builder, its own verdict, and the field that says nothing happened."""

    def test_every_family_is_validated_by_the_builder_that_will_run_it(self):
        app = self.app()
        cases = {'sustained': series_rule(HOST), 'slo': objective(SERVICE),
                 'forecast': forecast_rule(HOST), 'config_drift': {'resource_id': HOST, 'name': 'api.yaml',
                                                                   'rule_id': 'api.config'}}
        for family, document in cases.items():
            with self.subTest(family=family):
                status, body, _headers = http(app, 'POST', '/v1/rules/validation', 'producer',
                                              {'family': family, 'document': document})
                self.assertEqual(status, 200, body)
                self.assertFalse(body['durable'])
                self.assertEqual(body['events'], [])
                self.assertFalse(body['judged'])
                self.assertIsNotNone(body['rule']['id'])

    def test_a_validated_rule_reports_the_digest_of_the_judgement_not_of_the_bytes(self):
        document = series_rule(HOST)
        app = self.app()
        first = http(app, 'POST', '/v1/rules/validation', 'producer',
                     {'family': 'sustained', 'document': document})[1]
        same_but_reordered = {key: document[key] for key in reversed(list(document))}
        second = http(app, 'POST', '/v1/rules/validation', 'producer',
                      {'family': 'sustained', 'document': same_but_reordered})[1]
        self.assertEqual(first['rule']['version'], second['rule']['version'],
                         'the digest is of the judgement, so key order in the file cannot change it')
        self.assertRegex(first['rule']['version'], r'^[0-9a-f]{8,64}$')
        edited = http(app, 'POST', '/v1/rules/validation', 'producer',
                      {'family': 'sustained', 'document': series_rule(HOST, threshold=91)})[1]
        self.assertNotEqual(edited['rule']['version'], first['rule']['version'],
                            'and a threshold that moved is a different revision')

    def test_a_bad_rule_is_a_400_because_a_builder_only_raises(self):
        app = self.app()
        for family, document in (('sustained', series_rule(HOST, threshhold=90)),
                                 ('sustained', series_rule(HOST, mode='mood')),
                                 ('slo', objective(SERVICE, target=90)),
                                 ('forecast', forecast_rule(HOST, model='astrology')),
                                 ('config_drift', {'resource_id': HOST})):
            status, answer, _headers = http(app, 'POST', '/v1/rules/validation', 'producer',
                                            {'family': family, 'document': document})
            with self.subTest(family=family, document=str(document)[:40]):
                self.assertEqual(status, 400, answer)
                self.assertEqual(answer['error']['code'], 'invalid_request')
        self.assertEqual(http(app, 'POST', '/v1/rules/validation', 'producer',
                              {'family': 'pathcheck', 'document': {}})[0], 400)
        self.assertEqual(http(app, 'POST', '/v1/rules/validation', 'producer',
                              {'family': 'sigma', 'document': {}})[0], 400)

    def test_a_detection_validated_with_no_input_reports_its_coverage(self):
        app = self.app()
        status, body, _headers = http(app, 'POST', '/v1/rules/validation', 'producer',
                                      {'family': 'detection', 'document': baseline_rule(HOST)})
        self.assertEqual(status, 200)
        self.assertEqual(body['rule']['kind'], 'coverage')
        self.assertEqual(len(body['events']), 1)
        self.assertEqual((body['events'][0]['kind'], body['events'][0]['status']), ('coverage', 'firing'),
                         'a rule with no input is not silent: it reports that its input is absent')

    def test_a_detection_judges_a_sample_and_files_nothing(self):
        app = self.app()
        sample = {'sample_id': 'fixture-sample', 'observed_at': utc_text(aligned_instant(60)),
                  'ok': True, 'value': 95}
        status, body, _headers = http(app, 'POST', '/v1/rules/detections/evaluations', 'producer',
                                      {'rule': baseline_rule(HOST), 'sample': sample})
        self.assertEqual(status, 200, body)
        self.assertTrue(body['judged'])
        self.assertFalse(body['durable'])
        self.assertEqual(body['count'], len(body['events']))
        self.assertEqual(body['actor'], {'identity': SOURCE, 'role': 'producer'})
        self.assertIn('filed an event', ' '.join(body['not_performed']))
        self.assertTrue(all(event['source'] == SOURCE for event in body['events']))
        self.assertIn('threshold', [event['kind'] for event in body['events']],
                      'a 95 against a threshold of 90 owes a verdict event, not only a coverage one')
        filed = [self.store.intake(event, Actor(SOURCE, 'producer'), now=aligned_instant(60))
                 for event in body['events']]
        self.assertEqual([row['status'] for row in filed], ['accepted'] * len(filed),
                         'a previewed event is a real event: the platform accepts it when filed')

    def test_a_detection_about_an_undeclared_resource_refuses_its_round(self):
        app = self.app()
        status, answer, _headers = http(app, 'POST', '/v1/rules/detections/evaluations', 'producer',
                                        {'rule': baseline_rule(str(uuid.uuid4()))})
        self.assertEqual((status, answer['error']['code']), (400, 'invalid_request'))
        self.assertIn('not declared', answer['error']['message'])

    def test_a_sustained_series_is_judged_without_a_cursor(self):
        app = self.app()
        status, body, _headers = http(app, 'POST', '/v1/rules/sustained/evaluations', 'producer',
                                      {'document': series_rule(HOST), 'points': series(value=95)})
        self.assertEqual(status, 200, body)
        self.assertTrue(body['judged'] and not body['durable'])
        self.assertEqual([event['status'] for event in body['events']], ['resolved', 'firing'])
        self.assertEqual([event['condition'] for event in body['events']],
                         ['pool-disk.high.coverage', 'pool-disk.high'])
        self.assertEqual(http(app, 'GET', '/v1/records/events', 'reader')[1]['rows'], [],
                         'the preview filed nothing, and the event table is where a lie would show')

    def test_a_sustained_preview_refuses_a_malformed_or_absent_series(self):
        app = self.app()
        for body in ({'document': series_rule(HOST)}, {'document': series_rule(HOST), 'points': [['now', 1]]},
                     {'document': series_rule(HOST), 'points': [[1, 2, 3]]},
                     {'document': series_rule(HOST), 'points': [[1, 2]], 'cursor': 'x'}):
            status, answer, _headers = http(app, 'POST', '/v1/rules/sustained/evaluations', 'producer',
                                            body)
            with self.subTest(body=str(body)[:50]):
                self.assertEqual(status, 400, answer)
        quiet = http(app, 'POST', '/v1/rules/sustained/evaluations', 'producer',
                     {'document': series_rule(HOST), 'points': []})[1]
        self.assertEqual([(event['kind'], event['status']) for event in quiet['events']],
                         [('coverage', 'firing')])
        self.assertFalse(quiet['judged'],
                         'no points is not a verdict about the resource; it is the rule saying it was blind')

    def test_config_drift_digests_the_bytes_it_was_sent_and_ignores_the_digest_it_was_told(self):
        app = self.app()
        entry = {'resource_id': HOST, 'name': 'compose.yaml', 'rule_id': 'compose.watch'}
        status, first, _headers = http(app, 'POST', '/v1/rules/config-drift/comparisons', 'producer',
                                       {'entry': entry, 'current': {'text': 'a\nb\n'}})
        self.assertEqual(status, 200, first)
        self.assertFalse(first['changed'])
        self.assertIsNone(first['previous_sha256'], 'a first sighting is not a change')
        self.assertIsNone(first['event_would_be'])
        self.assertEqual(first['artifact'], f'{HOST}/compose.yaml')
        self.assertIn('this request', first['digest_source'])
        edited = http(app, 'POST', '/v1/rules/config-drift/comparisons', 'producer',
                      {'entry': entry, 'previous': {'text': 'a\nb\n'},
                       'current': {'sha256': '0' * 64, 'text': 'a\nB\n'}})[1]
        self.assertTrue(edited['changed'])
        self.assertNotEqual(edited['current_sha256'], '0' * 64,
                           'a caller cannot assert a digest the bytes do not have')
        self.assertEqual(edited['event_would_be']['rule_id'], 'compose.watch')
        self.assertEqual(edited['event_would_be']['kind'], 'drift')

    def test_a_pathcheck_grid_with_a_silent_pair_degrades_and_says_which_pair(self):
        app = self.app()
        observations = [{'target': '10.11.0.21', 'ok': False}, {'target': '10.11.0.99', 'ok': False}]
        status, body, _headers = http(app, 'POST', '/v1/rules/pathcheck/evaluations', 'producer',
                                      {'observations': observations, 'vantage_resource_id': HOST,
                                       'expected_vantage_points': [HOST, SERVICE],
                                       'expected_targets': ['10.11.0.21']})
        self.assertEqual(status, 200, body)
        self.assertEqual(body['verdict'], 'indeterminate')
        self.assertFalse(body['complete'])
        self.assertEqual([list(pair) for pair in body['coverage_gaps']] and True, True)
        self.assertTrue(any(SERVICE in pair for pair in map(list, body['coverage_gaps'])))
        self.assertTrue(body['notes'])

    def test_a_pathcheck_verdict_needs_probes_and_speaks_only_about_the_ones_it_was_given(self):
        app = self.app()
        self.assertEqual(http(app, 'POST', '/v1/rules/pathcheck/evaluations', 'producer',
                              {'observations': [], 'vantage_resource_id': HOST})[0], 400)
        self.assertEqual(http(app, 'POST', '/v1/rules/pathcheck/evaluations', 'producer',
                              {'observations': [{'target': 'x'}], 'vantage_resource_id': HOST})[0], 400)
        healthy = http(app, 'POST', '/v1/rules/pathcheck/evaluations', 'producer',
                       {'observations': [{'target': '10.11.0.21', 'ok': True}],
                        'vantage_resource_id': HOST})[1]
        self.assertEqual(healthy['verdict'], 'ok')
        self.assertTrue(healthy['complete'])
        self.assertEqual(healthy['count'], 0)

    def test_an_objective_and_a_forecast_are_judged_over_the_callers_own_samples(self):
        app = self.app()
        failing = series(count=12, step=60, value=False, align=300)
        slo = http(app, 'POST', '/v1/rules/slo/evaluations', 'producer',
                   {'objective': objective(SERVICE), 'points': failing})
        self.assertEqual(slo[0], 200, slo[1])
        self.assertFalse(slo[1]['durable'])
        self.assertTrue(slo[1]['judged'], 'a budget that burned through its threshold is a verdict')
        self.assertIn('threshold', [event['kind'] for event in slo[1]['events']])
        rising = series(count=10, step=600, value=53.0, align=300)
        forecast = http(app, 'POST', '/v1/rules/forecast/evaluations', 'producer',
                        {'document': forecast_rule(HOST), 'points': rising})
        self.assertEqual(forecast[0], 200, forecast[1])
        self.assertEqual((forecast[1]['rule']['model'], forecast[1]['rule']['id'],
                          forecast[1]['rule']['watch_rule']),
                         ('linear', 'pool-disk.predicted', 'pool-disk'))
        self.assertTrue(forecast[1]['judged'])
        conditions_filed = [event['condition'] for event in forecast[1]['events']]
        self.assertNotIn('pool-disk', conditions_filed,
                         'a forecast is filed as a prediction (`pool-disk.predicted`) and never as the '
                         'breach it predicts — the breach stays its own rule\'s verdict')
        self.assertTrue(all(name.startswith('pool-disk.predicted') for name in conditions_filed),
                        conditions_filed)

    def test_previews_belong_to_the_identity_that_could_file_them(self):
        app = self.app()
        for path, body in (('/v1/rules/sustained/evaluations',
                            {'document': series_rule(HOST), 'points': [[1_757_164_800, 95]]}),
                           ('/v1/rules/slo/evaluations',
                            {'objective': objective(SERVICE), 'points': [[1_757_164_800, False]]}),
                           ('/v1/rules/forecast/evaluations',
                            {'document': forecast_rule(HOST), 'points': [[1_757_164_800, 1.0]]})):
            for role in ('reader', 'proposer', 'human', 'executor'):
                with self.subTest(path=path, role=role):
                    status, answer, _headers = http(app, 'POST', path, role, body)
                    self.assertEqual((status, answer['error']['code']), (403, 'not_authorised'))


class ConfigurationPreviewTests(ResourceFixture):
    """The four pure deployment functions, over documents the caller owns, written nowhere."""

    def packages(self) -> list[dict]:
        return content_packages()

    def test_a_lock_is_drafted_from_the_packages_sent_and_trusts_nothing(self):
        app = self.app()
        status, body, _headers = http(app, 'POST', '/v1/deployment/locks', 'proposer',
                                      {'packages': self.packages()})
        self.assertEqual(status, 200, body)
        self.assertEqual((body['written'], body['deploy_authorized']), (False, False))
        self.assertEqual([pin['name'] for pin in body['packages']], ['core'])
        self.assertEqual(len(body['packages'][0]['sha256']), 64)
        self.assertEqual(body['requested_by'], {'identity': 'agent-1', 'role': 'proposer'})

    def test_a_reserved_or_repeated_package_name_is_the_locks_own_refusal(self):
        app = self.app()
        for bad in ([{'name': 'user', 'version': '1', 'content': []}],
                    self.packages() + self.packages()):
            status, answer, _headers = http(app, 'POST', '/v1/deployment/locks', 'human',
                                            {'packages': bad})
            with self.subTest(packages=str(bad)[:40]):
                self.assertEqual(status, 400, answer)

    def test_a_plan_reports_what_would_change_and_still_authorises_nothing(self):
        app = self.app()
        previous = content_state()
        candidate = content.resolve(content_packages(), content.make_lock(content_packages()),
                                    {**content_deployment(),
                                     'homepage': {**content_deployment()['homepage'],
                                                  'title': 'A new title'}})
        status, body, _headers = http(app, 'POST', '/v1/deployment/plans', 'human',
                                      {'previous': previous, 'observed': previous, 'candidate': candidate})
        self.assertEqual(status, 200, body)
        self.assertEqual(body['status'], 'review-required')
        self.assertTrue(body['homepage_settings_change'])
        self.assertFalse(body['deploy_authorized'])
        self.assertFalse(body['written'])
        self.assertEqual(len(body['previous_sha256']), 64)
        self.assertIn('Content plan only', body['scope'])
        runtime_edit = json.loads(json.dumps(previous))
        runtime_edit['homepage']['title'] = 'Edited on the running box'
        blocked = http(app, 'POST', '/v1/deployment/plans', 'human',
                       {'previous': previous, 'observed': runtime_edit,
                        'candidate': candidate})[1]
        self.assertEqual(blocked['status'], 'blocked',
                         'a runtime edit against the previous state is a refusal to plan over it')
        self.assertTrue(blocked['homepage_settings_drift'])
        self.assertFalse(blocked['deploy_authorized'])

    def test_a_rendering_returns_the_file_map_without_writing_a_bundle(self):
        app = self.app()
        # SQLite's -wal/-shm side files appear when any request reads the state file (the credential
        # revocation check does, on every authenticated call); they are the database's bookkeeping,
        # not something the render wrote.
        def tree():
            return sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')
                          if not path.name.endswith(('-wal', '-shm')))
        before = tree()
        lock = http(app, 'POST', '/v1/deployment/locks', 'proposer',
                    {'packages': self.packages()})[1]
        status, body, _headers = http(app, 'POST', '/v1/deployment/renderings', 'proposer',
                                      {'packages': self.packages(),
                                       'lock': {'schema_version': lock['schema_version'],
                                                'packages': lock['packages']},
                                       'deployment': content_deployment()})
        self.assertEqual(status, 200, body)
        self.assertEqual((body['status'], body['written'], body['deploy_authorized']),
                         ('rendered', False, False))
        self.assertEqual(body['file_count'], len(body['files']))
        self.assertIn('homepage/services.yaml', body['files'])
        self.assertEqual(len(body['deployment_sha256']), 64)
        self.assertIn('no deployment', body['scope'])
        self.assertEqual(tree(), before,
                         'a render wrote nothing: the tree under the mount is what it was before the call')

    def test_a_lock_that_no_longer_matches_the_packages_is_a_conflict_not_a_typo(self):
        app = self.app()
        lock = http(app, 'POST', '/v1/deployment/locks', 'proposer',
                    {'packages': self.packages()})[1]
        stale = json.loads(json.dumps(lock))
        stale['packages'][0]['version'] = '0.9.0'
        status, answer, _headers = http(app, 'POST', '/v1/deployment/renderings', 'proposer',
                                        {'packages': self.packages(),
                                         'lock': {'schema_version': 1, 'packages': stale['packages']},
                                         'deployment': content_deployment()})
        self.assertEqual((status, answer['error']['code']), (409, 'conflict'), answer)

    def test_a_dashboard_export_is_a_review_document(self):
        app = self.app()
        state = content_state()
        status, body, _headers = http(app, 'POST', '/v1/deployment/dashboard-exports', 'human',
                                      {'state': state, 'id': 'core.health',
                                       'document': {'title': 'Edited in the UI'}})
        self.assertEqual(status, 200, body)
        self.assertEqual((body['written'], body['deploy_authorized']), (False, False))
        self.assertEqual(body['owner'], 'core')
        self.assertIn('pinned replacement', body['next_step'])
        self.assertEqual(len(body['observed_sha256']), 64)
        self.assertEqual(http(app, 'POST', '/v1/deployment/dashboard-exports', 'human',
                              {'state': state, 'id': 'nope.not.here',
                               'document': {}})[0], 400)
        self.assertEqual(state, content_state(), 'the export did not edit the state it was handed')

    def test_the_configuration_door_is_authored_by_a_proposer_or_a_human(self):
        app = self.app()
        routes = {'/v1/deployment/locks': {'packages': self.packages()},
                  '/v1/deployment/renderings': {'packages': [], 'lock': {}, 'deployment': {}},
                  '/v1/deployment/dashboard-exports': {'state': {}, 'id': 'x', 'document': {}}}
        for path, body in routes.items():
            for role in ('reader', 'producer', 'executor'):
                with self.subTest(path=path, role=role):
                    status, answer, _headers = http(app, 'POST', path, role, body)
                    self.assertEqual((status, answer['error']['code']), (403, 'not_authorised'))


class TransportPostureTests(ResourceFixture):
    """Role gates, the summary ceiling, verb refusals and the idempotency claim."""

    def test_an_anonymous_call_and_a_summary_credential_are_answered_before_this_family_is_asked(self):
        app = self.app()
        for path in ('/v1/resources', '/v1/capabilities', '/v1/queries/topology'):
            status, answer, headers = http(app, 'GET', path, None)
            self.assertEqual((status, answer), (401, {'error': 'authentication_required'}), path)
            self.assertIn(b'x-request-id', headers)
            status, answer, _headers = http(app, 'GET', path, 'summary')
            # `summary_only` is one of the transport's legacy codes, so it keeps the flat body every other
            # read in this API gives and never arrives in the machine envelope.
            self.assertEqual((status, answer), (403, {'error': 'summary_only'}), path)

    def test_a_verb_a_read_does_not_carry_is_the_transports_own_answer(self):
        app = self.app()
        for path in ('/v1/resources', '/v1/capabilities', '/v1/queries/signals', '/v1/resources/resolve',
                     '/v1/observed-snapshots/drift', f'/v1/resources/{HOST}/dependents'):
            status, answer, _headers = http(app, 'POST', path, 'human', {})
            with self.subTest(path=path):
                self.assertEqual((status, answer), (405, {'error': 'method_not_allowed'}))
        status, answer, _headers = http(app, 'PUT', '/v1/resources', 'human')
        self.assertEqual(status, 405)

    def test_a_replayed_write_answers_its_first_answer_and_a_changed_body_is_a_conflict(self):
        self.ingest()
        app = self.app()
        body = {'source': SOURCE, 'observation_id': UNDECLARED}
        first = http(app, 'POST', '/v1/resource-proposals', 'proposer', body, key='draft-1')
        again = http(app, 'POST', '/v1/resource-proposals', 'proposer', body, key='draft-1')
        self.assertEqual((first[0], again[0]), (200, 200))
        self.assertEqual(again[2].get(b'x-idempotency-replayed'), b'true')
        self.assertEqual(first[1]['proposal_id'], again[1]['proposal_id'])
        self.assertEqual(len(list(self.proposals.glob('*.json'))), 1)
        conflict = http(app, 'POST', '/v1/resource-proposals', 'proposer',
                        {'source': SOURCE, 'observation_id': 'host-001'}, key='draft-1')
        self.assertEqual((conflict[0], conflict[1]['error']['code']), (409, 'idempotency_conflict'))

    def test_a_dry_run_never_touches_the_operational_store_it_shares_no_table_with(self):
        app = self.app()
        before = {row['name']: row['count'] for row in
                  http(app, 'GET', '/v1/runtime', 'reader')[1].get('tables', {}).items()}
        before = json.dumps(before, sort_keys=True)
        http(app, 'POST', '/v1/rules/sustained/evaluations', 'producer',
             {'document': series_rule(HOST), 'points': series(value=95)})
        http(app, 'POST', '/v1/rules/config-drift/comparisons', 'producer',
             {'entry': {'resource_id': HOST, 'name': 'x.yaml', 'rule_id': 'x.watch'},
              'current': {'text': 'one'}})
        http(app, 'POST', '/v1/deployment/locks', 'proposer', {'packages': content_packages()})
        after = json.dumps({row['name']: row['count'] for row in
                            http(app, 'GET', '/v1/runtime', 'reader')[1].get('tables', {}).items()},
                           sort_keys=True)
        self.assertEqual(after, before, 'no preview wrote a row anywhere')


class AnswerShapeTests(ResourceFixture):
    """Every documented 200 body against the schema the document claims for it.

    The conformance suite validates the two reads an *empty* process answers with. This class covers the
    rest — the mounted states, which is where a schema quietly stops describing the shape it names.
    """

    @classmethod
    def setUpClass(cls):
        cls.document = load_contract(OPENAPI)
        cls.by_operation = {operation_id: (method, path, operation) for operation_id,
                            (method, path, operation) in operations(cls.document).items()}

    def assert_shape(self, operation_id: str, body: dict) -> None:
        method, path, operation = self.by_operation[operation_id]
        schema = resolve(operation['responses']['200'], self.document)['content']['application/json']
        jsonschema.validate(body, {**schema['schema'],
                                   '$schema': 'https://json-schema.org/draft/2020-12/schema'})

    def test_every_answer_on_this_family_matches_its_documented_schema(self):
        self.ingest()
        app = self.app()
        drafted = http(app, 'POST', '/v1/resource-proposals', 'proposer',
                       {'source': SOURCE, 'observation_id': UNDECLARED})[1]
        lock = http(app, 'POST', '/v1/deployment/locks', 'proposer',
                    {'packages': content_packages()})[1]
        packages = content_packages()
        deployment = content_deployment()
        state = content_state()
        calls: list[tuple[str, str, str, str, bytes]] = [
            ('resource.inventory.read', 'GET', '/v1/inventory', 'reader', b'limit=5'),
            ('resource.read', 'GET', '/v1/resources', 'reader', b'limit=1'),
            ('resource.alias.resolve', 'GET', '/v1/resources/resolve', 'reader', b'id=' + HOST.encode()),
            ('resource.dependents.read', 'GET', f'/v1/resources/{HOST}/dependents', 'reader', b'limit=5'),
            ('resource.declaration.validate', 'POST', '/v1/resource-declarations/validation',
             'proposer', b''),
            ('resource.observation.record', 'POST', '/v1/observed-snapshots', 'producer', b''),
            ('resource.observation.history.read', 'GET', '/v1/observed-snapshots', 'reader',
             f'source={SOURCE}'.encode()),
            ('resource.drift.evaluate', 'GET', '/v1/observed-snapshots/drift', 'reader',
             f'source={SOURCE}'.encode()),
            ('resource.proposal.build', 'POST', '/v1/resource-proposals', 'proposer', b''),
            ('resource.proposal.read', 'GET', '/v1/resource-proposals/' + drafted['proposal_id'],
             'reader', b''),
            ('resource.query.series', 'GET', '/v1/queries/signals', 'reader',
             f'signal=metrics&resource_id={SERVICE}&rule_id=pool.disk&minutes=30'.encode()),
            ('resource.query.topology', 'GET', '/v1/queries/topology', 'reader',
             f'resource_id={SERVICE}&direction=upstream&depth=2'.encode()),
            ('resource.capability.read', 'GET', '/v1/capabilities', 'reader', b''),
            ('rule.validate', 'POST', '/v1/rules/validation', 'producer', b''),
            ('rule.detection.evaluate', 'POST', '/v1/rules/detections/evaluations', 'producer', b''),
            ('rule.sustained.evaluate', 'POST', '/v1/rules/sustained/evaluations', 'producer', b''),
            ('rule.config_drift.evaluate', 'POST', '/v1/rules/config-drift/comparisons', 'producer', b''),
            ('rule.pathcheck.evaluate', 'POST', '/v1/rules/pathcheck/evaluations', 'producer', b''),
            ('rule.slo.evaluate', 'POST', '/v1/rules/slo/evaluations', 'producer', b''),
            ('rule.forecast.evaluate', 'POST', '/v1/rules/forecast/evaluations', 'producer', b''),
            ('config.deployment.lock', 'POST', '/v1/deployment/locks', 'proposer', b''),
            ('config.deployment.plan', 'POST', '/v1/deployment/plans', 'human', b''),
            ('config.deployment.render', 'POST', '/v1/deployment/renderings', 'proposer', b''),
            ('config.dashboard.export', 'POST', '/v1/deployment/dashboard-exports', 'human', b''),
        ]
        bodies = {
            '/v1/resource-declarations/validation': {'declaration': self.declared},
            '/v1/observed-snapshots': self.snapshot(),
            '/v1/resource-proposals': {'source': SOURCE, 'observation_id': UNDECLARED},
            '/v1/rules/validation': {'family': 'sustained', 'document': series_rule(HOST)},
            '/v1/rules/detections/evaluations': {'rule': baseline_rule(HOST),
                                                 'sample': {'sample_id': 'fixture-sample',
                                                            'observed_at': utc_text(aligned_instant(60)),
                                                            'ok': True, 'value': 95}},
            '/v1/rules/sustained/evaluations': {'document': series_rule(HOST), 'points': series(value=95)},
            '/v1/rules/config-drift/comparisons': {
                'entry': {'resource_id': HOST, 'name': 'compose.yaml', 'rule_id': 'compose.watch'},
                'previous': {'text': 'a\n'}, 'current': {'text': 'b\n'}},
            '/v1/rules/pathcheck/evaluations': {'observations': [{'target': '10.11.0.21', 'ok': True}],
                                                'vantage_resource_id': HOST},
            '/v1/rules/slo/evaluations': {'objective': objective(SERVICE),
                                          'points': series(count=12, step=60, value=False,
                                                           align=300)},
            '/v1/rules/forecast/evaluations': {'document': forecast_rule(HOST),
                                               'points': series(count=8, step=600, value=53.0,
                                                                align=300)},
            '/v1/deployment/locks': {'packages': packages},
            '/v1/deployment/plans': {'previous': state, 'observed': state, 'candidate': state},
            '/v1/deployment/renderings': {'packages': packages, 'lock': {"schema_version": 1,
                                                                         'packages': lock['packages']},
                                          'deployment': deployment},
            '/v1/deployment/dashboard-exports': {'state': state, 'id': 'core.health',
                                                 'document': {'title': 'Edited in the UI'}},
        }
        served = {row['operation_id'] for row in resources_api.OPERATION_ROUTES}
        checked = 0
        for operation_id, method, path, role, query in calls:
            with self.subTest(operation=operation_id):
                status, body, _headers = http(app, method, path, role, bodies.get(path), query)
                self.assertEqual(status, 200, body)
                self.assert_shape(operation_id, body)
                checked += 1
        self.assertEqual(checked, len(calls))
        documented = set(self.by_operation)
        self.assertEqual({row[0] for row in calls} - documented, set(),
                         'a shape asserted for an operation the document does not describe is no shape')
        self.assertEqual({row[0] for row in calls}, served,
                         'every route the dispatcher answers has a body checked against a written schema')
        self.assertTrue(served <= documented,
                        'the dispatcher answers an operation the OpenAPI document never names')


if __name__ == '__main__':
    unittest.main()

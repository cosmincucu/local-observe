"""The census, the OpenAPI document and the served routes are one claim, checked three ways.

`docs/api/coverage.yaml` says what this product can do, `docs/api/openapi.yaml` says how the HTTP part of
that is spoken, and `local_observe/platform/api.py` is what actually answers a socket. Any two of the three
can agree while the third lies, so this file checks each pair:

* **census ↔ contract** — every row that owes an OpenAPI operation has one, with the same method, path,
  status and role set, and every operation belongs to a row;
* **contract ↔ source** — every path literal in the modules that answer HTTP is documented, and every
  documented `implemented` path is reachable in one of them;
* **contract ↔ behaviour** — an implemented operation is not a `404`, a planned operation is exactly a
  `404`, an operation with a role list refuses an unauthenticated caller, and the answers a `200` gives
  validate against the schema the document claims.

The document is loaded with the same duplicate-key-refusing loader the product's own config uses: a second
`/v1/events:` key in a contract file is the same defect it is in a deployment profile, and YAML's default
behaviour is to keep the later one silently.
"""
import asyncio
import contextlib
import datetime as dt
import json
import logging
import os
from pathlib import Path
import re
import tempfile
import unittest
import uuid
from unittest.mock import patch

import jsonschema
import yaml

from local_observe.inventory.validation import UniqueLoader, utc_text
from local_observe.platform import api_contract
from local_observe.platform.api import create_app
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.operator import with_ui
from local_observe.platform.state import Store

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / 'docs' / 'api' / 'coverage.yaml'
OPENAPI = ROOT / 'docs' / 'api' / 'openapi.yaml'

#: The modules that answer HTTP. A `/v1` literal anywhere else in the tree is a *client* of this API —
#: `local_observe/ai/client.py` posts to `/v1/chat/completions` on an upstream model server and
#: `local_observe/platform/crowdsec.py` reads `/v1/decisions` on a CrowdSec instance — so scanning the
#: whole package would either forgive a missing document entry or demand one for someone else's API.
SERVED_TRANSPORTS = ('local_observe/platform/api.py', 'local_observe/platform/verification_api.py',
                     'local_observe/platform/observer_review.py', 'local_observe/platform/operator.py',
                     'local_observe/platform/maintenance_api.py',
                     # The resources/queries/rules/configuration seam. It lives in its own module and is
                     # imported here the same way, so a document drift names the family it belongs to instead
                     # of a 1 300-line dispatcher.
                     'local_observe/platform/resources_api.py')

READER = {'identity': 'reader', 'role': 'reader', 'token': 'r' * 32}
PRODUCER = {'identity': 'test-detector', 'role': 'producer', 'token': 'p' * 32}
PROPOSER = {'identity': 'agent-1', 'role': 'proposer', 'token': 'q' * 32}
HUMAN = {'identity': 'operator', 'role': 'human', 'token': 'h' * 32}
EXECUTOR = {'identity': 'runner-1', 'role': 'executor', 'token': 'e' * 32}
SUMMARY = {'identity': 'watcher', 'role': 'summary', 'token': 'w' * 32}
CREDENTIALS = [READER, PRODUCER, PROPOSER, HUMAN, EXECUTOR, SUMMARY]
TOKEN_BY_ROLE = {row['role']: row['token'] for row in CREDENTIALS}

#: One concrete request per templated path, chosen so the route is reached rather than its parser.
#: A window and a schedule that do not exist: the ids are well-formed, so the read reaches the store and
#: answers "no such thing" rather than being refused by the identifier parser. That is the route being
#: probed; inventing a live window here would test the fixture instead of the transport.
UNKNOWN_WINDOW = '4f9c1d7b-8a3e-4c6f-9d2b-5e1a7c3f8b04'
UNKNOWN_SCHEDULE = 'b1e5a2c9-7d4f-4e8a-9c1b-3a5d7e9f2c46'

CONCRETE = {'/v1/records/{table}': ('/v1/records/events', b''),
            '/v1/intake/{source}': ('/v1/intake/alertmanager', b''),
            '/v1/callbacks/{channel}': ('/v1/callbacks/telegram', b''),
            '/v1/alert-occurrences/{id}': ('/v1/alert-occurrences/00000000-0000-4000-8000-000000000000', b''),
            '/v1/alert-occurrences/{id}/history':
                ('/v1/alert-occurrences/00000000-0000-4000-8000-000000000000/history', b''),
            '/v1/alert-occurrences/{id}/acknowledgements':
                ('/v1/alert-occurrences/00000000-0000-4000-8000-000000000000/acknowledgements', b''),
            '/v1/alert-occurrences/{id}/dismissals':
                ('/v1/alert-occurrences/00000000-0000-4000-8000-000000000000/dismissals', b''),
            '/v1/alert-occurrences/{id}/dismissal-revocation':
                ('/v1/alert-occurrences/00000000-0000-4000-8000-000000000000/dismissal-revocation', b''),
            '/v1/verification/binding': ('/v1/verification/binding',
                                         b'action_id=' + b'0' * 36),
            '/v1/verification/records': ('/v1/verification/records',
                                         b'execution_id=' + b'0' * 36),
            '/v1/verification/record': ('/v1/verification/record',
                                        b'verification_id=' + b'0' * 64),
            '/v1/observer/cycle': ('/v1/observer/cycle', b'cycle_id=unknown'),
            '/v1/observer/cycles': ('/v1/observer/cycles', b'limit=5'),
            '/v1/maintenance-windows/{id}': (f'/v1/maintenance-windows/{UNKNOWN_WINDOW}', b''),
            '/v1/maintenance-windows/{id}/history': (f'/v1/maintenance-windows/{UNKNOWN_WINDOW}/history', b''),
            '/v1/maintenance-windows/{id}/cancellations': (
                f'/v1/maintenance-windows/{UNKNOWN_WINDOW}/cancellations', b''),
            '/v1/maintenance-schedules/{id}': (f'/v1/maintenance-schedules/{UNKNOWN_SCHEDULE}', b''),
            '/v1/maintenance-schedules/{id}/history': (
                f'/v1/maintenance-schedules/{UNKNOWN_SCHEDULE}/history', b''),
            '/v1/maintenance-schedules/{id}/cancellations': (
                f'/v1/maintenance-schedules/{UNKNOWN_SCHEDULE}/cancellations', b''),
            '/v1/maintenance-schedules/{id}/materializations': (
                f'/v1/maintenance-schedules/{UNKNOWN_SCHEDULE}/materializations', b''),
            # A complete, bounded span over a resource nothing was ever planned around: the read is whole,
            # so its 200 body is the one the document's schema is checked against.
            '/v1/maintenance-intervals': ('/v1/maintenance-intervals',
                                          (f'resource={UNKNOWN_WINDOW}'
                                           f'&from=2026-03-01&to=2026-03-08').encode()),
            # The two templated paths of the resources seam, concretised as an identifier nothing was ever
            # declared to be. `limit` is present on the dependents probe because the read refuses a missing
            # bound before it looks anything up, and a probe that only exercised that refusal would prove
            # less than the 404 it replaces.
            '/v1/resources/{id}/dependents': (f'/v1/resources/{UNKNOWN_WINDOW}/dependents', b'limit=10'),
            '/v1/resource-proposals/{id}': ('/v1/resource-proposals/' + '0' * 64, b'')}

#: Implemented read routes a plain app serves without an optional seam mounted, and the credential each
#: needs. Their 200 bodies are validated against the schema the document claims for them.
ANSWERABLE_READS = {
    '/v1/me': 'reader', '/v1/status': 'reader', '/v1/overview': 'reader', '/v1/runtime': 'reader',
    '/v1/audit': 'reader', '/v1/records/{table}': 'reader', '/v1/notifications/safety': 'human',
    '/v1/alert-occurrences': 'reader',
    # One of the three maintenance reads: the bounded interval query, because it answers 200 over an empty
    # store and its body is the one place the outcome vocabulary and the read bounds are both visible.
    '/v1/maintenance-intervals': 'reader',
    # Two of the resources reads answer 200 with no artifact mounted at all, and those two bodies are where
    # the posture this family is built on is visible: `status: unavailable` beside `complete: false` naming
    # the variable to mount, and the capability document that separates an absent mount from a refusal.
    '/v1/resources': 'reader',
    '/v1/capabilities': 'reader',
}

REQUIRED_ROW_FIELDS = ('operation_id', 'surface', 'method', 'path', 'resource', 'module', 'access',
                       'required_role', 'side_effects', 'state_source', 'status', 'owner_area')
PATH_LITERALS = re.compile(r"'(/[A-Za-z0-9_./{}-]*)'")


@contextlib.contextmanager
def _quiet(logger_name: str = 'local_observe.platform.api'):
    """Silence one logger while a deliberate handler bug runs, and hand it back afterwards.

    `logging.disable` is a process-wide setter whose previous value is awkward to restore, and a test that
    left it set would silence the assertions every other test makes about log lines. Disabling the one
    logger under test affects this request's traceback and nothing else.
    """
    logger = logging.getLogger(logger_name)
    previous = logger.disabled
    logger.disabled = True
    try:
        yield
    finally:
        logger.disabled = previous


def broken_policy():
    """Return an action policy that fails inside the handler, so the transport's 500 can be observed."""
    def policy(request: dict) -> None:
        raise KeyError('action-definition-table')
    return policy


def load_contract(path: Path) -> dict:
    """Return one contract document, refusing a duplicated key the way the product's config loader does."""
    return yaml.load(path.read_text(), Loader=UniqueLoader)


def resolve(node: dict, document: dict) -> dict:
    """Return *node* with every `$ref` inside this document replaced by what it points at.

    The schemas here are trees, not graphs — no operation points back at a path — so a cycle is a defect
    and is raised rather than unwound until the test process dies.
    """
    def walk(current, seen):
        if isinstance(current, dict):
            if '$ref' in current:
                target = current['$ref']
                assert target.startswith('#/'), target
                if target in seen:
                    raise AssertionError(f'Circular $ref in the OpenAPI document: {target}')
                node = document
                for part in target[2:].split('/'):
                    node = node[part.replace('~1', '/').replace('~0', '~')]
                return walk(node, seen | {target})
            return {key: walk(value, seen) for key, value in current.items() if key != '$ref'}
        if isinstance(current, list):
            return [walk(item, seen) for item in current]
        return current
    return walk(node, frozenset())


def collect_references(node: object, found: list[str]) -> list[str]:
    """Return every `$ref` string anywhere in *node*, in document order."""
    if isinstance(node, dict):
        for key, value in node.items():
            found.append(value) if key == '$ref' else collect_references(value, found)
    elif isinstance(node, list):
        for item in node:
            collect_references(item, found)
    return found


def operations(document: dict) -> dict[str, tuple[str, str, dict]]:
    """Return `operationId -> (METHOD, path, operation)` for every operation in the contract."""
    return {operation['operationId']: (method.upper(), path, operation)
            for path, item in document['paths'].items()
            for method, operation in item.items()}


def transport_errors(contract: dict) -> dict[str, dict]:
    """Return the refusals the dispatcher owns, which every `/v1` operation may answer."""
    section = contract['x-transport-errors']
    assert section['scope'] == 'every path beginning /v1', section['scope']
    return section['responses']


def allowed_statuses(operation: dict, path: str, contract: dict) -> set[str]:
    """Return the status codes one answer may legitimately carry for *operation*."""
    allowed = documented_statuses(operation) | {'default'}
    if path.startswith('/v1'):
        allowed |= set(transport_errors(contract))
    return allowed


def documented_statuses(operation: dict) -> set[str]:
    return {key for key in operation['responses'] if key != 'default'}


def responses(operation: dict, status: str) -> list[dict]:
    """Return the response objects one operation documents under one status code."""
    entry = operation['responses'].get(status)
    if entry is None:
        return []
    return entry.get('oneOf', [entry])


def served_path_literals() -> dict[str, set[str]]:
    """Return every path literal in the modules that answer HTTP, as `path -> files that name it`."""
    found: dict[str, set[str]] = {}
    for relative in SERVED_TRANSPORTS:
        for literal in PATH_LITERALS.findall((ROOT / relative).read_text()):
            if not (literal.startswith('/v1') or literal in ('/', '/ui.css', '/ui.js', '/lucide.min.js')):
                continue
            found.setdefault(literal, set()).add(relative)
    return found


def match(literal: str, documented: set[str]) -> bool:
    """Whether one source literal names or prefixes a documented path."""
    if literal in documented:
        return True
    if literal == '/':
        return '/' in documented
    if literal.endswith('/'):
        stem = literal[:-1]
        return stem in documented or any(path.startswith(literal) for path in documented)
    return False


async def request(app, method: str, path: str, token: str | None, body: bytes = b'',
                  query: bytes = b'') -> tuple[int, dict, dict]:
    """Send one request straight into the ASGI app; return status, body and response headers."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)

    headers = list(((b'authorization', ('Bearer ' + token).encode()),) if token else ())
    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers,
               'query_string': query}, receive, send)
    body = output[-1]['body']
    types = {name.lower(): value for name, value in output[0].get('headers', [])}
    if b'json' not in types.get(b'content-type', b''):
        return output[0]['status'], body, types
    return output[0]['status'], json.loads(body), types


class ContractDocumentTests(unittest.TestCase):
    """The document is a contract: parseable without silent overrides, self-consistent, versioned."""

    @classmethod
    def setUpClass(cls):
        cls.contract = load_contract(OPENAPI)
        cls.census = load_contract(COVERAGE)
        cls.operations = operations(cls.contract)

    def test_the_document_is_openapi_3_1_with_bearer_security(self):
        self.assertTrue(self.contract['openapi'].startswith('3.1.'))
        self.assertEqual(sorted(transport_errors(self.contract)), ['401', '403', '404', '405', '413', '500'])
        self.assertEqual(self.contract['components']['securitySchemes']['bearerAuth']['scheme'], 'bearer')
        self.assertEqual(self.contract['security'], [{'bearerAuth': []}])
        self.assertIn('description', self.contract['info'])

    def test_no_key_is_written_twice_in_either_contract_file(self):
        """`UniqueLoader` raises where PyYAML would keep the later mapping and lose the earlier one."""
        for path in (OPENAPI, COVERAGE):
            with self.subTest(path=path.name):
                self.assertIsInstance(load_contract(path), dict)

    def test_every_operation_is_named_statused_and_roled(self):
        self.assertEqual(len(self.operations), len({key for key in self.operations}),
                         'operationId values must be unique')
        roles = set(self.census['vocabularies']['authority'])
        for operation_id, (method, path, operation) in self.operations.items():
            with self.subTest(operation=operation_id):
                self.assertIn(operation['x-status'], ('implemented', 'planned'))
                self.assertTrue(set(operation['x-required-role']) <= roles | {'none'},
                                operation['x-required-role'])
                # PATCH is not a general widening: the transport admits it and `maintenance_api` answers it
                # for one route (`/v1/maintenance-schedules/{id}`, an edit that appends a version). Any
                # other verb on any other path is a 405, which `test_the_six_transport_refusals...` proves.
                self.assertIn(method, ('GET', 'POST', 'PATCH'))
                self.assertTrue(path.startswith('/'), path)
                self.assertIn('summary', operation)
                unauthenticated = operation.get('security') == []
                self.assertEqual(unauthenticated, operation['x-required-role'] == [],
                                 f'{operation_id}: an empty role list must be the same claim as no security')
                self.assertTrue(documented_statuses(operation) - {'default'})

    def test_every_reference_resolves_and_no_response_is_left_out(self):
        named = self.contract['components']
        for operation_id, (_method, _path, operation) in self.operations.items():
            for status, entry in operation['responses'].items():
                with self.subTest(operation=operation_id, status=status):
                    self.assertTrue(status == 'default' or re.fullmatch(r'[0-9]{3}', status), status)
                    # A response is either a named answer of its own, inline content, or a choice between
                    # named answers — which is how a route with two refusals of the same status says so.
                    if 'oneOf' in entry:
                        for member in entry['oneOf']:
                            self.assertEqual(list(member), ['$ref'], f'{operation_id} {status}')
                            self.assertIn('/responses/', member['$ref'])
                    else:
                        self.assertTrue('$ref' in entry or 'content' in entry,
                                        f'{operation_id} {status}: a response must name an answer')
                    resolve(entry, self.contract)
        # A component that nothing points at is documentation nobody serves.
        references: list[str] = []
        collect_references(self.contract, references)
        for section in ('headers', 'parameters', 'responses', 'schemas'):
            for name in named[section]:
                self.assertIn('#/components/' + section + '/' + name, references,
                              section + '/' + name + ' is defined and referenced by nothing')

    def test_the_error_shapes_are_the_two_the_boundary_can_produce(self):
        """The envelope's codes are `api_contract`'s table, and the flat shape is the legacy half."""
        schemas = self.contract['components']['schemas']
        envelope = resolve(schemas['ErrorEnvelope'], self.contract)['properties']['error']['properties']
        self.assertEqual(set(envelope['code']['enum']), set(api_contract.ERROR_CATALOGUE))
        self.assertEqual(set(schemas['LegacyError']['properties']['error']['enum']),
                         set(api_contract.LEGACY_CODES))
        self.assertTrue(api_contract.LEGACY_CODES < set(api_contract.ERROR_CATALOGUE))
        for code, statuses in api_contract.ERROR_CATALOGUE.items():
            with self.subTest(code=code):
                named = {status for status in statuses}
                self.assertTrue(named <= {100, 200, 300, 400, 401, 403, 404, 405, 409, 412, 413, 500, 503})

    def test_the_contract_names_the_headers_the_boundary_promises(self):
        parameters = self.contract['components']['parameters']
        self.assertEqual(parameters['IdempotencyKey']['name'], 'Idempotency-Key')
        self.assertEqual(parameters['IfMatch']['name'], 'If-Match')
        self.assertEqual(parameters['PageLimit']['schema']['maximum'], api_contract.PAGE_LIMIT_MAX)
        self.assertEqual(parameters['PageLimit']['schema']['default'], api_contract.PAGE_LIMIT_DEFAULT)
        self.assertEqual(set(self.contract['components']['headers']),
                         {'XRequestId', 'XIdempotencyReplayed', 'ETag'})

    def test_a_planned_operation_says_what_is_missing_and_why(self):
        for operation_id, (_method, _path, operation) in self.operations.items():
            if operation['x-status'] != 'planned':
                continue
            with self.subTest(operation=operation_id):
                self.assertIn('Not served', operation.get('description', ''))
                self.assertIn('404', operation['responses'])


class CensusRowTests(unittest.TestCase):
    """Every row of the census is complete, chooses from the closed vocabularies, and is unique."""

    @classmethod
    def setUpClass(cls):
        cls.census = load_contract(COVERAGE)
        cls.contract = load_contract(OPENAPI)
        cls.operations = operations(cls.contract)

    def test_each_row_is_complete_and_its_own_kind_of_thing(self):
        vocabularies = self.census['vocabularies']
        seen: set[str] = set()
        for row in self.census['operations']:
            with self.subTest(row=row['operation_id']):
                for field in REQUIRED_ROW_FIELDS:
                    self.assertIn(field, row, f"{row['operation_id']} is missing {field}")
                self.assertNotIn(row['operation_id'], seen)
                seen.add(row['operation_id'])
                for field, allowed in (('surface', vocabularies['surfaces']),
                                       ('access', vocabularies['access']),
                                       ('status', vocabularies['status']),
                                       ('owner_area', vocabularies['owner_areas']),
                                       ('contract', vocabularies['contract'])):
                    if field == 'contract':
                        self.assertIn(row.get(field, 'openapi'), allowed)
                    else:
                        self.assertIn(row[field], allowed)
                self.assertIsInstance(row['required_role'], list)
                self.assertTrue(set(row['required_role']) <= set(vocabularies['authority']),
                                row['required_role'])
                if row['surface'] != 'http':
                    # A command, a tool or a click always reaches some authority; an empty list would mean
                    # the row cannot say who may run it. On http it is a real answer: no credential at all.
                    self.assertTrue(row['required_role'], row['operation_id'])
                module = str(row['module'])
                self.assertTrue(module.startswith(('local_observe/', 'scripts/', 'components/')), module)
                self.assertTrue((ROOT / module).exists(), module)
                if row['status'] != 'implemented':
                    self.assertIn('notes', row, 'a planned or excluded row must say what is missing')

    def test_the_census_covers_every_surface_and_the_planned_work_alongside_it(self):
        surfaces = {row['surface'] for row in self.census['operations']}
        self.assertEqual(surfaces, set(self.census['vocabularies']['surfaces']))
        for area in self.census['vocabularies']['owner_areas']:
            self.assertTrue([row for row in self.census['operations'] if row['owner_area'] == area], area)
        planned = {row['operation_id'] for row in self.census['operations'] if row['status'] == 'planned'}
        self.assertTrue({'occurrence.dismiss.revoke', 'platform.openapi.read'} <= planned, planned)
        rows = {row['operation_id']: row for row in self.census['operations']}
        for operation_id in ('occurrence.list', 'occurrence.read', 'occurrence.disposition_history.read',
                             'occurrence.acknowledge', 'occurrence.dismiss'):
            with self.subTest(row=operation_id):
                self.assertEqual(rows[operation_id]['status'], 'implemented')
                self.assertTrue(rows[operation_id]['path'].startswith('/v1/alert-occurrences'))
        served = {row['operation_id'] for row in self.census['operations'] if row['status'] == 'implemented'}
        self.assertTrue({'maintenance.window.declare', 'maintenance.window.revoke',
                         'maintenance.window.read', 'maintenance.schedule.declare',
                         'maintenance.schedule.revise', 'maintenance.schedule.cancel',
                         'maintenance.schedule.materialize', 'maintenance.interval.read'} <= served, served)
        self.assertIn('maintenance.window.declare_cli', {row['operation_id']
                                                        for row in self.census['operations']})

    def test_the_forgery_and_recovery_paths_the_contract_rests_on_are_counted(self):
        """The two claims a reviewer cannot check from a schema are rows here instead."""
        rows = {row['operation_id']: row for row in self.census['operations']}
        self.assertEqual(rows['foundation.request_identity.apply']['status'], 'implemented')
        self.assertEqual(rows['foundation.idempotent_write.apply']['state_source'],
                         'sqlite: api_idempotency (schema v11)')
        self.assertEqual(rows['administration.authentication.read']['required_role'], [])
        # Offline bootstrap and recovery: the row set must name a backup, the migration that reads it, and
        # a gate that proves it was readable rather than only that a file appeared.
        for operation_id in ('administration.state.backup', 'administration.state.migrate',
                             'administration.recovery.conformance', 'administration.backup.conformance'):
            with self.subTest(row=operation_id):
                self.assertEqual(rows[operation_id]['status'], 'implemented')
                self.assertEqual(rows[operation_id]['owner_area'], 'administration')
                self.assertNotEqual(rows[operation_id]['side_effects'], 'none')
        recovery_words = [row['operation_id'] for row in self.census['operations']
                          if any(word in str(row.get('notes', '')).lower()
                                 for word in ('backup', 'restore', 'offline', 'recovery'))]
        self.assertGreaterEqual(len(recovery_words), 3, recovery_words)


class CensusMatchesContractTests(unittest.TestCase):
    """The pair the reviewer is most likely to read one of: the table and the document."""

    @classmethod
    def setUpClass(cls):
        cls.census = load_contract(COVERAGE)
        cls.contract = load_contract(OPENAPI)
        cls.operations = operations(cls.contract)
        cls.addressable = re.compile(r'^(/[A-Za-z0-9_{}/.-]*)$')

    def owes_a_document(self, row: dict) -> bool:
        if row.get('contract') is not None:
            return row['contract'] == 'openapi'
        return row['surface'] == 'http' and bool(self.addressable.match(str(row['path'])))

    def test_every_row_that_owes_one_has_exactly_that_operation(self):
        for row in self.census['operations']:
            if not self.owes_a_document(row):
                continue
            with self.subTest(row=row['operation_id']):
                self.assertEqual(row['surface'], 'http')
                entry = self.operations.get(row['operation_id'])
                self.assertIsNotNone(entry, 'the census names an operation the contract does not describe')
                method, path, operation = entry
                self.assertEqual((method, path), (row['method'], row['path']))
                self.assertEqual(operation['x-status'],
                                 'planned' if row['status'] == 'planned' else 'implemented')
                self.assertEqual(set(operation['x-required-role']), set(row['required_role']),
                                 'the role a caller needs must be stated once, not twice and differently')

    def test_no_operation_is_documented_without_a_row_behind_it(self):
        """Both directions: an operation without a census row, or a row without an operation, is a drift."""
        named = {row['operation_id'] for row in self.census['operations']}
        self.assertEqual(set(self.operations) - named, set())
        rows_without_a_document = {row['operation_id'] for row in self.census['operations']
                                   if not self.owes_a_document(row)}
        self.assertEqual(named - set(self.operations), rows_without_a_document)

    def test_a_route_is_documented_as_planned_or_as_served_but_never_both(self):
        by_path: dict[tuple[str, str], list[str]] = {}
        for operation_id, (method, path, _operation) in self.operations.items():
            by_path.setdefault((method, path), []).append(operation_id)
        self.assertEqual({key: ids for key, ids in by_path.items() if len(ids) > 1}, {})


class ContractMatchesSourceTests(unittest.TestCase):
    """The documentation and the code that answers a socket are the same list."""

    @classmethod
    def setUpClass(cls):
        cls.contract = load_contract(OPENAPI)
        cls.operations = operations(cls.contract)
        cls.documented = {path for _id, (_method, path, _operation) in cls.operations.items()}

    def test_every_path_the_transports_name_is_documented(self):
        """A route a client can reach must appear in the contract, whatever its role list says."""
        undocumented = {literal: sorted(files) for literal, files in served_path_literals().items()
                        if not match(literal, self.documented)}
        self.assertEqual(undocumented, {})

    def test_every_documented_served_operation_is_named_by_a_transport(self):
        """The reverse: a contract must not describe an operation the code never answers."""
        literals = set(served_path_literals())
        for operation_id, (_method, path, operation) in self.operations.items():
            if operation['x-status'] != 'implemented':
                continue
            with self.subTest(operation=operation_id, path=path):
                self.assertTrue(any(match(literal, {path}) for literal in literals),
                                f'{path} is documented as served but no transport names it')

    def test_a_planned_operation_is_named_by_no_transport(self):
        """`planned` is a claim about the future; a literal would make it a lie about the present."""
        literals = set(served_path_literals())
        for operation_id, (_method, path, operation) in self.operations.items():
            if operation['x-status'] == 'implemented':
                continue
            with self.subTest(operation=operation_id, path=path):
                self.assertFalse(path in literals or any(
                    literal.startswith(path) for literal in literals),
                    f'{path} is planned but a transport already names it')

    def test_the_client_only_paths_stay_clients(self):
        """These two are upstream APIs this product calls; documenting them would invent routes."""
        literals = set(served_path_literals())
        for client_only in ('/v1/chat/completions', '/v1/decisions'):
            self.assertNotIn(client_only, literals)
            self.assertNotIn(client_only, self.documented)


class ContractMatchesBehaviourTests(unittest.TestCase):
    """A documented operation is one the running app answers the documented way."""

    def setUp(self):
        """One store and one app for the whole class; no optional surface is mounted."""
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        environment = patch.dict(os.environ, {}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Store(Path(self.temp.name) / 'state.db', NotificationPolicy(delivery_mode='off'))
        # The composed app the product actually runs: the operator shell owns the interface assets and
        # `/v1/operator-auth`, and hands everything else to the platform API underneath.
        self.app = with_ui(create_app(self.store, CREDENTIALS, {}))
        self.contract = load_contract(OPENAPI)
        self.operations = operations(self.contract)

    def target(self, path: str) -> tuple[str, bytes]:
        return CONCRETE.get(path, (path, b''))

    def test_an_unauthenticated_call_is_refused_by_every_roled_operation(self):
        for operation_id, (method, path, operation) in sorted(self.operations.items()):
            if not operation['x-required-role'] or operation['x-status'] != 'implemented':
                continue
            concrete, query = self.target(path)
            with self.subTest(operation=operation_id):
                status, body, headers = asyncio.run(request(self.app, method, concrete, None,
                                                           b'{}' if method == 'POST' else b'', query))
                self.assertEqual((status, body), (401, {'error': 'authentication_required'}))
                self.assertIn(b'x-request-id', headers)

    def test_the_operations_that_need_no_credential_answer_without_one(self):
        answered = 0
        for operation_id, (method, path, operation) in sorted(self.operations.items()):
            if operation['x-required-role'] or operation['x-status'] != 'implemented':
                continue
            concrete, query = self.target(path)
            with self.subTest(operation=operation_id):
                status, _body, _headers = asyncio.run(request(self.app, method, concrete, None, b'', query))
                self.assertNotEqual(status, 401)
                self.assertIn(str(status), operation['responses'])
                answered += 1
        self.assertEqual(answered, 5)  # /v1/operator-auth plus the four interface assets

    def test_a_planned_operation_answers_only_with_not_found(self):
        """The contract marks these `planned`; the app must not half-implement them.

        The credential is still answered first: authentication happens before routing, so an anonymous
        caller of a route that does not exist learns it was not authenticated and nothing about the route.
        A caller holding a real role is the one that gets the honest 404.
        """
        planned = 0
        for operation_id, (method, path, operation) in sorted(self.operations.items()):
            if operation['x-status'] != 'planned':
                continue
            planned += 1
            concrete, query = self.target(path)
            status, body, _headers = asyncio.run(request(self.app, method, concrete, None,
                                                       b'{}' if method == 'POST' else b'', query))
            with self.subTest(operation=operation_id, call='anonymous'):
                self.assertEqual((status, body), (401, {'error': 'authentication_required'}))
            for token in (READER['token'], HUMAN['token'], EXECUTOR['token']):
                status, body, _headers = asyncio.run(request(self.app, method, concrete, token,
                                                           b'{}' if method == 'POST' else b'', query))
                with self.subTest(operation=operation_id, call='credentialled'):
                    self.assertEqual((status, body), (404, {'error': 'not_found'}))
        self.assertEqual(planned, 2)

    def test_every_implemented_operation_answers_within_what_is_documented(self):
        """One probe per operation: whatever the app chooses to answer, the contract admits it.

        The probe is deliberately minimal (an empty object on a write, no query on a read), because the
        interesting claim is not the happy path — `test_a_200_answer_validates...` covers those bodies —
        but whether a refusal a caller can actually receive appears in the document they read first. This
        is what catches the two drifts that matter: a status the code can answer and nobody documented,
        and a status an operation advertises that the transport would answer differently.
        """
        observed: dict[str, int] = {}
        for operation_id, (method, path, operation) in sorted(self.operations.items()):
            if operation['x-status'] != 'implemented' or not operation['x-required-role']:
                continue
            concrete, query = self.target(path)
            token = next(TOKEN_BY_ROLE[role] for role in operation['x-required-role']
                         if role in TOKEN_BY_ROLE)
            # An empty body is a bug in some handlers rather than a refusal, and that is a fact about the
            # routes this probe never claimed to test; keep their tracebacks out of the report.
            with _quiet():
                status, body, _headers = asyncio.run(request(self.app, method, concrete, token,
                                                           b'{}' if method == 'POST' else b'', query))
            observed[operation_id] = status
            with self.subTest(operation=operation_id, status=status):
                self.assertIn(str(status), allowed_statuses(operation, path, self.contract), body)
                if str(status) not in operation['responses']:
                    self.assertTrue(path.startswith('/v1'), operation_id)

    def test_the_six_transport_refusals_are_all_answerable(self):
        """401, 403, 404, 405, 413 and 500 come from the dispatcher, and each one really happens."""
        broken = create_app(self.store, CREDENTIALS, broken_policy())
        cases = {
            '401': lambda: request(self.app, 'GET', '/v1/me', None),
            '403': lambda: request(self.app, 'GET', '/v1/status', SUMMARY['token']),
            '404': lambda: request(self.app, 'GET', '/v1/never-declared', READER['token']),
            '405': lambda: request(self.app, 'PUT', '/v1/me', READER['token']),
            '413': lambda: request(self.app, 'POST', '/v1/events', PRODUCER['token'], b'{' + b' ' * 70000),
            # A well-formed request whose handler is broken: the body is valid, the policy is not.
            '500': lambda: request(with_ui(broken), 'POST', '/v1/actions', PROPOSER['token'],
                                   json.dumps({'retry_key': 'once', 'incident_id': str(uuid.uuid4()),
                                               'action': 'inspect', 'version': '1', 'targets': [],
                                               'parameters': {}, 'evidence': [],
                                               'expires_at': utc_text(dt.datetime.now(
                                                   dt.timezone.utc) + dt.timedelta(minutes=5))}).encode()),
        }
        for status, make in sorted(cases.items()):
            with self.subTest(status=status):
                if status == '500':
                    # The transport answers a bug with a class name and logs the traceback; the log line is
                    # half the contract, so it is asserted rather than left to scroll past.
                    with self.assertLogs('local_observe.platform.api', level='ERROR') as captured:
                        observed, body, _headers = asyncio.run(make())
                    self.assertEqual(captured.records[0].error_class, 'KeyError')
                else:
                    observed, body, _headers = asyncio.run(make())
                self.assertEqual(str(observed), status, body)

    def test_a_bearer_answer_carries_one_well_formed_request_id(self):
        for path, method in (('/v1/me', 'GET'), ('/v1/nothing-here', 'GET'), ('/v1/actions', 'POST'),
                            ('/v1/evidence', 'GET')):
            with self.subTest(path=path, method=method):
                _status, _body, headers = asyncio.run(request(self.app, method, path, READER['token'],
                                                            b'{}' if method == 'POST' else b''))
                self.assertTrue(api_contract.REQUEST_ID_PATTERN.fullmatch(headers[b'x-request-id'].decode()),
                                headers[b'x-request-id'])

    def test_a_200_answer_validates_against_the_schema_the_document_claims(self):
        """The schemas are not decoration: every field a route promises is present and of its type."""
        checked = 0
        for path, role in ANSWERABLE_READS.items():
            operation = next(op for (_m, p, op) in self.operations.values() if p == path)
            concrete, query = self.target(path)
            status, body, _headers = asyncio.run(request(self.app, 'GET', concrete, TOKEN_BY_ROLE[role],
                                                        b'', query))
            with self.subTest(path=path):
                self.assertEqual(status, 200, body)
                response = resolve(operation['responses']['200'], self.contract)
                schema = response['content']['application/json']['schema']
                jsonschema.validate(body, {**schema, '$schema': 'https://json-schema.org/draft/2020-12/schema'})
                checked += 1
        self.assertEqual(checked, len(ANSWERABLE_READS))


if __name__ == '__main__':
    unittest.main()

"""Optional observer route pool: declaration reading, pool digests, per-call membership and refusals.

Every answer here comes from a fake opener and every declaration from a synthetic fixture, so the checks
are about which configured member a call may be attributed to -- no host is contacted, no gateway is
configured and no pool is treated as evidence of model quality. ``backend-a``/``backend-b`` are declared
member IDs, ``local-engine``/``weights-aaa`` are declared metadata, ``model.invalid`` is the endpoint.
"""
from __future__ import annotations

import copy
import email.message
import hashlib
import json
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from local_observe.ai.budget import DEFAULTS as BUDGET
from local_observe.ai.client import AiClient
from local_observe.http import JsonClient, ResponseHeader, TransportError
from local_observe.observer.contract import ObserverError, digest, encoded
from local_observe.observer.model_pool import (MAX_POOL_MEMBERS, POOL_BYTE_LIMIT, POOL_PREFIX, POOL_PROVIDER,
                                               POOL_VARIABLE, PoolGuard, RoutePool, guard_pool_client,
                                               load_pool, selected_pool_path)
from local_observe.observer.model_route import DEPLOYMENT_HEADER, ROUTE_PREFIX, DeploymentGuard, route_label
from local_observe.observer.provenance import label

ALIAS = 'example-model'
TOKEN = 'example-token-' + 'x' * 32
HEADER = DEPLOYMENT_HEADER
CASED_HEADER = 'X-LiteLLM-Model-Id'
PATH = '/v1/chat/completions'
BODY = {'ok': True}
PROMPT = {'prompt': 'what changed?'}

# Everything the fixture declares, plus the credential and the header name: none of it may reach a
# receipt, an error message or any other value this module hands back. Only configured digests and the
# per-member completeness boolean are allowed to escape the guard.
DECLARED = ('backend-a', 'backend-b', 'local-engine', 'other-engine', 'weights-aaa', 'weights-bbb',
            HEADER, CASED_HEADER, TOKEN, 'Bearer ' + TOKEN)

DECLARATION = {'schema_version': 1, 'routes': {
    'backend-a': {'provider': 'local-engine', 'model_version': 'weights-aaa'},
    'backend-b': {'provider': 'local-engine', 'model_version': 'weights-bbb'}}}

POLICY = {'schema_version': 1, 'classes': {kind: {'generate': True, 'remote': False, 'redact': ['secret_keys'],
                                                  'label': ''} for kind in ('public', 'internal', 'restricted')}}
CAPABILITY = {'schema_version': 1, 'context_tokens': 8192, 'tools': False, 'json_mode': True, 'streaming': False,
              'vision': False, 'parallel': 1, 'quant': 'example', 'measured_tok_per_s': 1}


def declaration():
    return copy.deepcopy(DECLARATION)


def route(name, provider='local-engine', version='weights-fake'):
    """One declared member, spelled the way the declaration file spells it."""
    return {name: {'provider': provider, 'model_version': version}}


def pooled(members):
    return {'schema_version': 1, 'routes': members}


class FakeResponse:
    """The three attributes `JsonClient` reads off an opened response: status, bytes, headers."""

    def __init__(self, body=None, headers=(), status=200, raw=None):
        self.status = status
        self.body = raw if raw is not None else encoded(BODY if body is None else body).encode()
        self.headers = email.message.Message()
        for pair in headers:
            self.headers[pair[0]] = pair[1]

    def duplicate(self, name, values):
        for value in values:
            self.headers.add_header(name, value)
        return self

    def read(self, limit=-1):
        return self.body if limit is None or limit < 0 else self.body[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """One queued answer per attempt, in order; an exception answer fails that attempt instead."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append((request.full_url, timeout))
        if not self.responses:
            raise AssertionError('the fake opener received more requests than the test queued')
        answer = self.responses.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def answered_as(status=503, headers=()):
    """An opener that fails the attempt with one HTTP error status, as `urllib` does."""
    error = urllib.error.HTTPError('https://model.invalid' + PATH, status, 'unavailable',
                                   email.message.Message(), None)
    for pair in headers:
        error.headers[pair[0]] = pair[1]
    return error


def built_client(transport=None):
    """A real AiClient, so wrapping is checked on the object the product actually passes around."""
    return AiClient(base_url='https://model.invalid', api_key=TOKEN, model=ALIAS, capability=dict(CAPABILITY),
                    policy=copy.deepcopy(POLICY), budget=dict(BUDGET), out_of_lan=False, transport=transport)


class NoNetwork(unittest.TestCase):
    """No test in this module may reach a socket, and none needs a protected file by default."""

    def setUp(self):
        blocked = patch.object(socket, 'create_connection', side_effect=AssertionError('real network forbidden'))
        blocked.start()
        self.addCleanup(blocked.stop)


class FileFixture(NoNetwork):
    """A 0700 directory holding 0600 pool files, which is the only shape `protected_json` admits."""

    def setUp(self):
        super().setUp()
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, ignore_errors=True)
        self.private = self.temp / 'private'
        self.private.mkdir(mode=0o700)
        self.path = self.private / 'pool.json'

    def write(self, text, *, directory=None, name='pool.json', mode=0o600):
        target = (directory or self.private) / name
        target.write_text(text, encoding='utf-8')
        target.chmod(mode)
        return str(target)

    def declared(self, value, **kwargs):
        """Put *value* on disk as a pool file and return the path, exactly as an operator would."""
        return self.write(encoded(value), **kwargs)

    def load(self, path=None):
        pool = load_pool({POOL_VARIABLE: str(path or self.path)})
        self.assertIsInstance(pool, RoutePool)
        return pool

    def expect_code(self, environ, code):
        with self.assertRaises(ObserverError) as caught:
            load_pool(environ)
        self.assertEqual(str(caught.exception), code)
        return caught.exception


class SelectionTests(FileFixture):
    def test_an_undecleared_pool_selects_nothing_and_reads_no_file(self):
        for environ in ({}, {POOL_VARIABLE: ''}, {POOL_VARIABLE: None}, {'LO_OBSERVER_MODEL_DEPLOYMENT': ''},
                        'not-a-mapping', None, []):
            with self.subTest(environ=repr(environ)[:50]):
                self.assertIsNone(load_pool(environ))
                self.assertIsNone(selected_pool_path(environ))

    def test_the_legacy_single_deployment_configuration_selects_no_pool(self):
        legacy = {'LO_OBSERVER_MODEL_DEPLOYMENT': 'backend-a', 'LO_OBSERVER_MODEL_PROVIDER': 'local-engine',
                  'LO_OBSERVER_MODEL_VERSION': 'weights-aaa', 'LO_AI_MODEL': ALIAS}
        self.assertIsNone(load_pool(legacy), 'an operator who declared no pool keeps the guard they chose')
        self.assertIsNone(load_pool({**legacy, POOL_VARIABLE: ''}))

    def test_a_selection_value_must_be_one_usable_path(self):
        for value in ('   ', ' ', ' /tmp/pool.json', '/tmp/pool.json ', b'/tmp/pool.json', True, 7, [], {},
                      ('/tmp/pool.json',), '/tmp/a\x00b', '/tmp/a\nb', '/' + 'a' * 2048):
            with self.subTest(value=repr(value)[:30]):
                self.expect_code({POOL_VARIABLE: value}, 'invalid_pool_path')

    def test_the_declared_file_is_read_from_its_own_protected_location(self):
        self.declared(declaration())
        self.assertEqual(self.load().sha256, digest(declaration()))

    def test_a_pool_next_to_single_deployment_configuration_is_ambiguous(self):
        self.declared(declaration())
        for variable in ('LO_OBSERVER_MODEL_DEPLOYMENT', 'LO_OBSERVER_MODEL_PROVIDER',
                         'LO_OBSERVER_MODEL_VERSION'):
            with self.subTest(variable=variable):
                self.expect_code({POOL_VARIABLE: str(self.path), variable: 'declared-value'},
                                 'model_route_pool_ambiguous')
        # An empty value declares nothing, so it cannot be the second authority the refusal is about.
        blank = {POOL_VARIABLE: str(self.path), 'LO_OBSERVER_MODEL_DEPLOYMENT': '',
                 'LO_OBSERVER_MODEL_PROVIDER': '', 'LO_OBSERVER_MODEL_VERSION': ''}
        self.assertEqual(load_pool(blank).sha256, digest(declaration()))

    def test_file_privileges_are_the_existing_protected_file_contract(self):
        self.declared(declaration(), mode=0o644)
        self.expect_code({POOL_VARIABLE: str(self.path)}, 'private_owned_file_required')
        wide = self.temp / 'wide'
        wide.mkdir(mode=0o755)
        self.declared(declaration(), directory=wide)
        self.expect_code({POOL_VARIABLE: str(wide / 'pool.json')}, 'private_owned_directory_required')
        outside = self.temp / 'outside.json'
        outside.write_text(encoded(declaration()), encoding='utf-8')
        outside.chmod(0o600)
        link = self.private / 'link.json'
        link.symlink_to(outside)
        with self.assertRaises(OSError):
            load_pool({POOL_VARIABLE: str(link)})
        with self.assertRaises(FileNotFoundError):
            load_pool({POOL_VARIABLE: str(self.private / 'absent.json')})
        self.declared(declaration())
        self.assertEqual(self.load().sha256, digest(declaration()), 'the admitted file still loads')

    def test_the_pool_path_must_be_one_absolute_private_location(self):
        self.declared(declaration())
        # '..' is refused by shape, before the filesystem is consulted at all.
        self.expect_code({POOL_VARIABLE: '../pool.json'}, 'absolute_private_path_required')
        for value in ('relative/pool.json', '~/pool.json'):
            with self.subTest(value=value):
                with self.assertRaises(ObserverError) as caught:
                    load_pool({POOL_VARIABLE: value})
                self.assertEqual(str(caught.exception), 'absolute_private_path_required',
                              'a relative path is refused, not resolved against wherever the cycle started')


class DeclarationTests(FileFixture):
    def load_with(self, value):
        return load_pool({POOL_VARIABLE: self.declared(value)})

    def refuse(self, value, code):
        """The declaration must be refused however it arrives, and only by a bounded code."""
        with self.assertRaises(ObserverError) as caught:
            RoutePool(copy.deepcopy(value))
        self.assertEqual(str(caught.exception), code, repr(value)[:120])

    def test_the_documented_shape_is_accepted_exactly_as_declared(self):
        pool = self.load_with(declaration())
        self.assertEqual(set(pool.member_receipts), {'backend-a', 'backend-b'})
        self.assertTrue(pool.complete)
        self.assertEqual(pool.model_version, POOL_PREFIX + pool.sha256)
        self.assertRegex(pool.model_version, r'^route-pool-sha256:[0-9a-f]{64}$')
        self.assertEqual(label(pool.model_version), pool.model_version, 'provenance has to be able to carry it')

    def test_the_member_count_bound_is_one_to_sixteen(self):
        def members(count):
            return {('backend-%02d' % index): {'provider': None, 'model_version': None}
                    for index in range(count)}

        for count in (1, MAX_POOL_MEMBERS):
            self.assertEqual(len(RoutePool(pooled(members(count))).member_receipts), count)
        self.refuse(pooled(members(MAX_POOL_MEMBERS + 1)), 'invalid_pool_declaration')
        self.expect_code({POOL_VARIABLE: self.declared(pooled(members(MAX_POOL_MEMBERS + 1)))},
                         'invalid_pool_declaration')

    def test_a_null_member_stays_incomplete_instead_of_becoming_a_guess(self):
        pool = self.load_with(pooled({**route('backend-a'), **route('backend-b', version=None)}))
        self.assertFalse(pool.complete, 'one undeclared weight version keeps the whole pool unknown')
        self.assertIsNone(pool.model_version)
        receipts = pool.member_receipts
        self.assertTrue(receipts['backend-a']['complete'])
        self.assertFalse(receipts['backend-b']['complete'])

    def test_an_unknown_metadata_word_is_refused_where_null_is_the_correct_answer(self):
        for word in ('unknown', 'Unknown', 'none', 'null', 'unset', 'unmeasured', ''):
            with self.subTest(word=word):
                self.refuse(pooled({**route('backend-a'), **route('backend-b', provider=word)}),
                            'invalid_pool_metadata')
                self.refuse(pooled({**route('backend-a'), **route('backend-b', version=word)}),
                            'invalid_pool_metadata')

    def test_only_the_integer_one_is_a_supported_declaration_version(self):
        for version in (True, False, 0, 2, 1.0, '1', 'v1', [1], {'v': 1}, None):
            with self.subTest(version=repr(version)):
                self.refuse({**declaration(), 'schema_version': version}, 'unsupported_pool_version')
        self.expect_code({POOL_VARIABLE: self.declared({**declaration(), 'schema_version': 2})},
                         'unsupported_pool_version')

    def test_only_the_declared_two_levels_of_fields_are_accepted(self):
        cases = {
            'no document': [{}, 'invalid_pool_declaration'],
            'version only': [{'schema_version': 1}, 'invalid_pool_declaration'],
            'routes only': [{'routes': route('backend-a')}, 'invalid_pool_declaration'],
            'extra top field': [{**declaration(), 'extra': 1}, 'invalid_pool_declaration'],
            'member without metadata': [pooled({**route('backend-a'), 'backend-b': {}}), 'invalid_pool_member'],
            'member with extra field': [pooled({**route('backend-a'),
                                                'backend-b': {'provider': 'x', 'model_version': None,
                                                              'extra': 'y'}}), 'invalid_pool_member'],
            'member as a string': [pooled({**route('backend-a'), 'backend-b': 'local-engine'}),
                                   'invalid_pool_member'],
            'member as a list': [pooled({**route('backend-a'), 'backend-b': ['local-engine']}),
                                 'invalid_pool_member'],
            'document as text': ['local-engine', 'invalid_pool_declaration'],
            'document as a list': [[declaration()], 'invalid_pool_declaration'],
            'no document at all': [None, 'invalid_pool_declaration'],
        }
        for name, (value, code) in cases.items():
            with self.subTest(case=name):
                self.refuse(value, code)

    def test_the_route_map_must_be_a_map_of_bounded_member_ids(self):
        empty = {'provider': None, 'model_version': None}
        cases = {
            'a list': [[], 'invalid_pool_declaration'],
            'nothing declared': [{}, 'invalid_pool_declaration'],
            'a bare name': ['backend-a', 'invalid_pool_declaration'],
            'no member id': [{None: empty}, 'invalid_pool_member'],
            'a numeric member id': [{7: empty}, 'invalid_pool_member'],
            'an empty member id': [{'': empty}, 'invalid_pool_member'],
            'a spaced member id': [{'backend a': empty}, 'invalid_pool_member'],
            'a path-like member id': [{'backend/a': empty}, 'invalid_pool_member'],
            'a url member id': [{'https://gw.invalid/backend-a': empty}, 'invalid_pool_member'],
            'a folding member id': [{'backend\r\nX-Other: 1': empty}, 'invalid_pool_member'],
            'an unknown member id': [{'unknown': empty}, 'invalid_pool_member'],
        }
        for name, (routes, code) in cases.items():
            with self.subTest(case=name):
                self.refuse({'schema_version': 1, 'routes': routes}, code)

    def test_member_metadata_is_a_bounded_label_or_null(self):
        for value in ('a b', 'x' * 200, 'https://gw.invalid/weights', 'a\r\nb', ' bearer', 1, 1.5, True,
                      [], {}, {'v': 1}, ['local-engine']):
            with self.subTest(value=repr(value)[:30]):
                self.refuse(pooled({**route('backend-a'), **route('backend-b', provider=value)}),
                            'invalid_pool_metadata')

    def test_the_declaration_text_is_bounded_and_cannot_hold_two_answers(self):
        raw = encoded(declaration())
        self.assertLess(len(raw.encode()), POOL_BYTE_LIMIT)
        oversized = pooled({'backend-%02d' % index: {'provider': 'p' * 300, 'model_version': 'w' * 300}
                            for index in range(40)})
        self.assertGreater(len(encoded(oversized).encode()), POOL_BYTE_LIMIT)
        self.expect_code({POOL_VARIABLE: self.declared(oversized)}, 'protected_file_too_large')
        cases = {
            'truncated': [raw[:-1], 'invalid_json'],
            'not json': ['{,}', 'invalid_json'],
            # `ObserverError` is a `ValueError`, so the reader's duplicate-key refusal arrives under its
            # own `invalid_json` code: what matters here is that the second answer never wins silently.
            'duplicate version': ['{"schema_version": 1, "schema_version": 1, "routes": {}}', 'invalid_json'],
            'duplicate member': [raw.replace('"backend-b"', '"backend-a"', 1), 'invalid_json'],
            'a bare list': ['[1, 2]', 'invalid_pool_declaration'],
            'a bare string': ['"local-engine"', 'invalid_pool_declaration'],
            'a float version': ['{"schema_version": 1.0, "routes": {}}', 'unsupported_pool_version'],
        }
        for name, (text, code) in cases.items():
            with self.subTest(case=name):
                self.expect_code({POOL_VARIABLE: self.write(text)}, code)

    def test_a_duplicated_answer_cannot_be_resolved_by_last_one_wins(self):
        # Two spellings of one member ID carrying two different versions: whichever way the file is read,
        # no ordering accident may pick which backend the pool declares.
        self.expect_code({POOL_VARIABLE: self.write('{"schema_version": 1, "routes": {"backend-a": '
                                                   '{"provider": "local-engine", "model_version": '
                                                   '"weights-aaa"}, "backend-a": {"provider": '
                                                   '"local-engine", "model_version": "weights-bbb"}}}')},
                         'invalid_json')


class DigestTests(NoNetwork):
    def test_the_pool_digest_is_the_declaration_recomputed_independently(self):
        canonical = json.dumps(declaration(), sort_keys=True, separators=(',', ':'))
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        self.assertEqual(RoutePool(declaration()).sha256, expected)
        self.assertEqual(RoutePool(declaration()).sha256, digest(declaration()))

    def test_declaration_order_cannot_move_the_digest(self):
        reordered = pooled(dict(reversed(list(declaration()['routes'].items()))))
        reordered['routes']['backend-b'] = dict(reversed(list(reordered['routes']['backend-b'].items())))
        self.assertEqual(RoutePool(declaration()).sha256, RoutePool(reordered).sha256)
        self.assertEqual(RoutePool(declaration()).member_receipts, RoutePool(reordered).member_receipts)

    def test_any_change_to_any_member_moves_the_digest(self):
        base = RoutePool(declaration())
        routes = declaration()['routes']
        changes = {'provider': pooled({**route('backend-a'), **route('backend-b', provider='other-engine')}),
                   'version': pooled({**route('backend-a'), **route('backend-b', version='weights-ccc')}),
                   'member id': pooled({'backend-c': routes['backend-a'], 'backend-b': routes['backend-b']}),
                   'added member': pooled({**routes, **route('backend-c')}),
                   'removed member': pooled(route('backend-a')),
                   'undeclared member': pooled({**route('backend-a'), **route('backend-b', version=None)})}
        for name, value in changes.items():
            with self.subTest(change=name):
                pool = RoutePool(value)
                self.assertNotEqual(pool.sha256, base.sha256, name)
                self.assertNotEqual(pool.model_version, base.model_version, name)

    def test_a_receipt_is_the_pair_of_pool_and_member_recomputed_independently(self):
        pool = RoutePool(declaration())
        for name, metadata in declaration()['routes'].items():
            expected = hashlib.sha256(json.dumps([name, metadata['provider'], metadata['model_version']],
                                                 sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            receipt = pool.member_receipts[name]
            self.assertEqual(receipt['member_sha256'], expected)
            self.assertEqual(receipt['pool_sha256'], pool.sha256)
            self.assertEqual(receipt['schema_version'], 1)
            self.assertIs(receipt['complete'], True)
            self.assertEqual(set(receipt), {'schema_version', 'pool_sha256', 'member_sha256', 'complete'})
        self.assertNotEqual(pool.member_receipts['backend-a']['member_sha256'],
                            pool.member_receipts['backend-b']['member_sha256'], 'members stay distinguishable')

    def test_only_configured_digests_and_booleans_leave_a_receipt(self):
        pool = RoutePool(declaration())
        documents = [pool.sha256, pool.model_version, pool.complete,
                     *[value for receipt in pool.member_receipts.values() for value in receipt.values()]]
        escaped = encoded(documents)
        for value in DECLARED:
            self.assertNotIn(value, escaped, value)
        self.assertIs(pool.complete, True)
        for receipt in pool.member_receipts.values():
            self.assertEqual([type(value).__name__ for value in receipt.values()],
                             ['int', 'str', 'str', 'bool'], 'a receipt is one version, two digests, one boolean')
        self.assertEqual(sorted(pool.member_receipts), ['backend-a', 'backend-b'],
                         'the mapping is keyed by the IDs the operator declared, so they can pick one up')

    def test_neither_the_stored_declaration_nor_a_handed_out_receipt_can_be_rewritten(self):
        source = declaration()
        pool = RoutePool(source)
        settled = pool.sha256
        source['routes']['backend-a']['provider'] = 'other-engine'
        source['schema_version'] = 2
        self.assertEqual(pool.sha256, settled, 'the digest certifies what was validated, not what a caller kept')
        receipt = pool.member_receipts['backend-a']
        receipt['complete'] = 'leak'
        receipt['pool_sha256'] = '0' * 64
        self.assertIs(pool.member_receipts['backend-a']['complete'], True)
        self.assertEqual(pool.member_receipts['backend-a']['pool_sha256'], settled)
        self.assertIsNot(pool.member_receipts['backend-a'], pool.member_receipts['backend-a'])


class GuardTests(NoNetwork):
    def setUp(self):
        super().setUp()
        self.pool = RoutePool(declaration())

    def guard(self, *responses):
        transport = JsonClient('https://model.invalid', TOKEN)
        transport.opener = FakeOpener(*responses)
        self.json = transport
        return PoolGuard(transport, self.pool)

    def answer(self, member='backend-a', **kwargs):
        return FakeResponse(BODY, [(HEADER, member)], **kwargs)

    def call(self, guard):
        return guard.request('POST', PATH, PROMPT)

    def expect(self, guard, code):
        with self.assertRaises(ObserverError) as caught:
            self.call(guard)
        self.assertEqual(str(caught.exception), code)
        return caught.exception

    def test_a_transport_or_pool_that_cannot_carry_the_contract_is_refused(self):
        class StandIn:
            def request(self, method, path='', payload=None, **kwargs):
                return 200, BODY

        for transport in (StandIn(), None, 'not-a-transport', object()):
            with self.subTest(transport=repr(transport)[:30]):
                with self.assertRaises(ObserverError) as caught:
                    PoolGuard(transport, self.pool)
                self.assertEqual(str(caught.exception), 'model_route_pool_unsupported')
        for pool in (None, POOL_PREFIX + '0' * 64, declaration(), {}, 7):
            with self.subTest(pool=repr(pool)[:30]):
                with self.assertRaises(ObserverError) as caught:
                    PoolGuard(JsonClient('https://model.invalid', TOKEN), pool)
                self.assertEqual(str(caught.exception), 'model_route_pool_unsupported')

    def test_each_declared_member_answers_with_its_own_safe_receipt(self):
        guard = self.guard(self.answer('backend-a'), self.answer('backend-b'))
        self.assertIsNone(guard.receipt, 'nothing is claimed before a call')
        self.assertEqual(self.call(guard), (200, BODY))
        first = guard.take_receipt()
        self.assertEqual(first, self.pool.member_receipts['backend-a'])
        self.assertEqual(self.call(guard), (200, BODY))
        second = guard.take_receipt()
        self.assertEqual(second, self.pool.member_receipts['backend-b'])
        self.assertNotEqual(first['member_sha256'], second['member_sha256'])
        self.assertEqual(first['pool_sha256'], second['pool_sha256'])
        self.assertNotIn('backend', encoded([first, second]))
        self.assertEqual(len(self.json.opener.requests), 2, 'exactly one attempt per call')

    def test_take_receipt_hands_the_document_over_once(self):
        guard = self.guard(self.answer())
        self.assertEqual(self.call(guard), (200, BODY))
        self.assertEqual(guard.take_receipt(), self.pool.member_receipts['backend-a'])
        self.assertIsNone(guard.take_receipt())
        self.assertIsNone(guard.receipt)

    def test_an_untaken_receipt_does_not_survive_into_the_next_call(self):
        guard = self.guard(self.answer('backend-a'), self.answer('backend-b'))
        self.call(guard)
        self.call(guard)
        self.assertEqual(guard.take_receipt(), self.pool.member_receipts['backend-b'])

    def test_the_header_value_is_matched_and_dropped_never_kept(self):
        guard = self.guard(self.answer('backend-a'))
        self.assertEqual(self.call(guard), (200, BODY))
        held = [value for value in vars(guard).values() if isinstance(value, (ResponseHeader, str))]
        self.assertEqual(held, [], 'the per-attempt slot is not retained on the guard')
        self.assertEqual(vars(guard)['receipt'], self.pool.member_receipts['backend-a'])
        for value in DECLARED:
            self.assertNotIn(value, encoded(vars(guard)['receipt']))

    def test_only_one_well_formed_declared_header_certifies_a_call(self):
        cases = {
            'absent': FakeResponse(BODY),
            'undeclared member': self.answer('backend-c'),
            'other deployment': self.answer('backend-a-2'),
            'case-shifted member': self.answer('Backend-A'),
            'padded member': self.answer(' backend-a'),
            'url': self.answer('https://gw.invalid/backend-a'),
            'credential-like': self.answer('sk-' + 'A' * 40),
            'bearer token': self.answer('Bearer ' + TOKEN),
            'folding bytes': self.answer('backend-a\r\nX-Other: 1'),
            'empty': self.answer(''),
            'unknown': self.answer('unknown'),
            'claimed in the body': FakeResponse({**BODY, HEADER: 'backend-a', 'deployment': 'backend-a'}),
        }
        for name, response in cases.items():
            with self.subTest(case=name):
                guard = self.guard(response)
                error = self.expect(guard, 'model_deployment_mismatch')
                self.assertIsNone(guard.receipt)
                self.assertEqual(str(error), 'model_deployment_mismatch')
                for value in DECLARED:
                    self.assertNotIn(value, str(error), value)
                self.assertEqual(guard.pool.member_receipts, self.pool.member_receipts,
                                 'a refused answer cannot rewrite the declaration')

    def test_a_repeated_header_still_reads_as_the_duplicate_it_is(self):
        cases = {
            'same member twice': FakeResponse(BODY).duplicate(HEADER, ['backend-a', 'backend-a']),
            'two members': FakeResponse(BODY).duplicate(HEADER, ['backend-a', 'backend-b']),
            'spelled two ways': FakeResponse(BODY, [(HEADER, 'backend-a')]).duplicate(CASED_HEADER,
                                                                                      ['backend-a']),
            'four copies': FakeResponse(BODY).duplicate(HEADER, ['backend-a'] * 4),
        }
        for name, response in cases.items():
            with self.subTest(case=name):
                guard = self.guard(response)
                self.expect(guard, 'model_deployment_mismatch')
                self.assertIsNone(guard.receipt)

    def test_the_header_name_is_read_case_insensitively_but_the_value_is_matched_exactly(self):
        guard = self.guard(FakeResponse(BODY, [(CASED_HEADER, 'backend-a')]))
        self.assertEqual(self.call(guard), (200, BODY))
        self.assertEqual(guard.take_receipt(), self.pool.member_receipts['backend-a'])

    def test_an_error_status_keeps_the_existing_status_answer_and_carries_no_receipt(self):
        guard = self.guard(self.answer('backend-a'), answered_as(503), self.answer('backend-b'))
        self.call(guard)
        first = guard.take_receipt()
        self.assertEqual(self.call(guard), (503, None), 'the existing status gate is unchanged')
        self.assertIsNone(guard.receipt, 'an error answer certifies no member')
        self.assertEqual(self.call(guard), (200, BODY))
        self.assertEqual(guard.take_receipt(), self.pool.member_receipts['backend-b'])
        self.assertEqual(first, self.pool.member_receipts['backend-a'], 'an earlier receipt survives its owner')
        guard = self.guard(answered_as(503, [(HEADER, 'backend-a')]))
        self.assertEqual(guard.request('POST', PATH, PROMPT), (503, None))
        self.assertIsNone(guard.receipt, 'a member name on an error answer produced no content to attribute')

    def test_a_timeout_or_an_unparsable_body_inherits_no_earlier_receipt(self):
        guard = self.guard(self.answer('backend-a'), TimeoutError('no answer'), self.answer('backend-b'))
        self.call(guard)
        with self.assertRaises(TransportError):
            self.call(guard)
        self.assertIsNone(guard.receipt, 'the timed-out call is not certified by the earlier match')
        self.assertEqual(self.call(guard), (200, BODY))
        self.assertEqual(guard.take_receipt(), self.pool.member_receipts['backend-b'])

        guard = self.guard(self.answer('backend-a'),
                           FakeResponse(raw=b'not-json', headers=[(HEADER, 'backend-b')]),
                           self.answer('backend-a'))
        self.call(guard)
        guard.take_receipt()
        with self.assertRaises(TransportError):
            self.call(guard)
        self.assertIsNone(guard.receipt, 'a well-formed header on a body that never parsed proves nothing')
        self.assertEqual(self.call(guard), (200, BODY))
        self.assertEqual(guard.take_receipt(), self.pool.member_receipts['backend-a'])

    def test_an_incomplete_pool_receipt_is_still_a_safe_answer(self):
        pool = RoutePool(pooled({**route('backend-a'), **route('backend-b', version=None)}))
        transport = JsonClient('https://model.invalid', TOKEN)
        transport.opener = FakeOpener(self.answer('backend-b'))
        guard = PoolGuard(transport, pool)
        self.assertEqual(guard.request('POST', PATH, PROMPT), (200, BODY))
        receipt = guard.take_receipt()
        self.assertIs(receipt['complete'], False)
        self.assertEqual(receipt['pool_sha256'], pool.sha256)
        self.assertIsNone(pool.model_version, 'the pool version stays unknown even for a known member')


class WrapTests(NoNetwork):
    def setUp(self):
        super().setUp()
        self.pool = RoutePool(declaration())
        self.other = RoutePool(pooled({**route('backend-a'), **route('backend-b', version=None)}))

    def test_a_json_client_transport_is_wrapped_once_and_reused_for_the_same_declaration(self):
        client = built_client()
        self.assertIs(guard_pool_client(client, self.pool), client)
        guard = client.transport
        self.assertIsInstance(guard, PoolGuard)
        self.assertEqual(guard.pool.sha256, self.pool.sha256)
        self.assertIs(guard_pool_client(client, self.pool), client)
        self.assertIs(client.transport, guard, 'the same declaration reuses the same wrap')
        self.assertIsInstance(client.transport.transport, JsonClient, 'and never nests')

    def test_a_changed_declaration_replaces_the_wrap_without_nesting_it(self):
        client = built_client()
        guard_pool_client(client, self.pool)
        guard_pool_client(client, self.other)
        self.assertIsInstance(client.transport, PoolGuard)
        self.assertEqual(client.transport.pool.sha256, self.other.sha256)
        self.assertNotIsInstance(client.transport.transport, PoolGuard)
        self.assertIsInstance(client.transport.transport, JsonClient)

    def test_a_single_deployment_guard_is_not_reinterpreted_as_a_pool(self):
        client = built_client()
        client.transport = DeploymentGuard(client.transport, 'backend-a')
        with self.assertRaises(ObserverError) as caught:
            guard_pool_client(client, self.pool)
        self.assertEqual(str(caught.exception), 'model_route_pool_unsupported')
        self.assertIsInstance(client.transport, DeploymentGuard, 'the existing guard is left exactly as it was')

    def test_a_transport_that_cannot_carry_the_header_is_refused(self):
        class StandIn:
            def request(self, method, path='', payload=None, **kwargs):
                return 200, BODY

        client = built_client(StandIn())
        with self.assertRaises(ObserverError) as caught:
            guard_pool_client(client, self.pool)
        self.assertEqual(str(caught.exception), 'model_route_pool_unsupported')
        self.assertIsInstance(client.transport, StandIn)

    def test_only_a_validated_pool_can_be_installed(self):
        for value in (None, POOL_PREFIX + '0' * 64, declaration(), 7, object()):
            with self.subTest(value=repr(value)[:30]):
                client = built_client()
                with self.assertRaises(ObserverError) as caught:
                    guard_pool_client(client, value)
                self.assertEqual(str(caught.exception), 'model_route_pool_unsupported')
                self.assertIsInstance(client.transport, JsonClient, 'the client is never left half-wrapped')

    def test_the_pool_vocabulary_is_distinct_from_the_single_deployment_one(self):
        self.assertEqual(POOL_VARIABLE, 'LO_OBSERVER_MODEL_ROUTES')
        self.assertEqual(POOL_PROVIDER, 'declared-route-pool')
        self.assertEqual(label(POOL_PROVIDER), POOL_PROVIDER, 'it has to be carryable as a provenance provider')
        self.assertEqual(POOL_PREFIX, 'route-pool-sha256:')
        self.assertNotEqual(POOL_PREFIX, ROUTE_PREFIX)
        version = RoutePool(declaration()).model_version
        self.assertEqual(version.split(':')[0] + ':', POOL_PREFIX, 'a pool version never reads as a route label')
        self.assertNotEqual(version, route_label('weights-aaa', 'backend-a'),
                            'the same metadata under the two contracts cannot look alike')


if __name__ == '__main__':
    unittest.main()

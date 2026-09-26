"""Boundary tests for `platform/verification_policy.py` .

Written against the frozen public contract alone — `load_policy(path, credentials)`,
`policy_from_environment(credentials, environ=None)`, `CONFIG_ENVIRONMENT`, `PolicyLoadError` — with the
existing `VerificationPolicy` left as the only schema owner: which bytes and paths may be read and how
little a refusal says about them, that the environment is read at the call and never defaulted, and that
every verifier identity is bound to a producer credential by role. No network, no API.
"""
import builtins
import io
import json
import os
import threading
import unittest
from pathlib import Path
from unittest import mock

from local_observe.platform.verification_policy import (CONFIG_ENVIRONMENT, PolicyLoadError,
                                                        load_policy, policy_from_environment)
from local_observe.platform.verification_records import MAX_POLICY_BYTES, VerificationPolicy
from test_verification_records import (OTHER_PIN, READER, RULE, SECOND_VERIFIER, VERIFIER,
                                       VerificationFixture)

REFUSALS = (PolicyLoadError,)
PRODUCERS = V, W = VERIFIER.identity, SECOND_VERIFIER.identity
ROLES = ('reader', 'producer', 'proposer', 'human', 'executor', 'summary')
#: Every file and every spare identity here carries this word, so one sentinel pins path/identity leaks.
SENTINEL = 'sentinel'
CONFIG_NAME = SENTINEL + '-policy.json'
#: One well-formed non-verifier credential row; each case below changes exactly one thing about it.
ROW = {'identity': SENTINEL + '-extra', 'role': 'reader', 'token': 'k' * 32}
MISSING_TOKEN = {key: ROW[key] for key in ('identity', 'role')}
_DEFAULT_CREDENTIALS = object()


class PoisonToken:
    """A credential token whose every reading — stringified, sized, compared, hashed — is a breach."""

    __slots__ = ()

    def _breach(self, *args, **kwargs):
        raise AssertionError('a credential token value was read')

    __str__ = __repr__ = __format__ = __len__ = __bool__ = __hash__ = __eq__ = __ne__ = _breach
    __lt__ = __le__ = __gt__ = __ge__ = __iter__ = __getitem__ = __contains__ = __call__ = _breach


class WatchList(list):
    """A credential argument that counts its own reads: the parse-then-crosscheck order is observable."""

    def __init__(self, rows):
        super().__init__(rows)
        self.touched = 0

    def _read(self, value):
        self.touched += 1
        return value

    def __iter__(self):
        return self._read(list.__iter__(self))

    def __len__(self):
        return self._read(list.__len__(self))

    def __getitem__(self, item):
        return self._read(list.__getitem__(self, item))


class LoaderFixture(VerificationFixture):
    """Shared ground: one temp config path, the credential rows a policy names, the refusal shape."""

    def config(self, payload, name=CONFIG_NAME) -> Path:
        """Write one config file from bytes or text, and return its path."""
        path = self.root / name
        path.write_bytes(payload.encode() if isinstance(payload, str) else payload)
        return path

    def text(self, **changes) -> bytes:
        """This scenario's reviewed policy as JSON bytes, changed only as asked."""
        return json.dumps(self.document(**changes)).encode()

    def credentials(self, *identities, token=None, extra=()) -> list:
        """One producer row per identity (default: both reviewed verifiers), then `extra` rows as given."""
        rows = [{'identity': identity, 'role': 'producer',
                 'token': token() if token else identity + '-' + 'k' * (24 + position)}
                for position, identity in enumerate(identities or PRODUCERS)]
        return rows + [dict(row) for row in extra]

    def load(self, raw, credentials=_DEFAULT_CREDENTIALS):
        """`load_policy` over one freshly written file and these credential rows."""
        rows = self.credentials() if credentials is _DEFAULT_CREDENTIALS else credentials
        return load_policy(self.config(raw), rows)

    def outcome(self, thunk):
        """Return the refusal one call raised, or `None` when it answered, so a thread can carry it out."""
        try:
            thunk()
        except REFUSALS as caught:
            return caught

    def duplicated(self, key, *, last=False) -> str:
        """Policy JSON repeating one existing pair verbatim, so last-wins would load it unchanged."""
        text = json.dumps(self.document(), separators=(',', ':'))
        start = text.rindex(json.dumps(key) + ':') if last else text.index(json.dumps(key) + ':')
        stop = min(index for index in (text.find(',', start), text.find('}', start)) if index != -1)
        return text[:start] + text[start:stop] + ',' + text[start:]

    def no_opens(self) -> list:
        """Count every entry point a config read could use, so 'nothing was opened' is assertable."""
        probes = []
        for owner, name in ((builtins, 'open'), (io, 'open'), (os, 'open')):
            patch = mock.patch.object(owner, name, mock.MagicMock(side_effect=getattr(owner, name)))
            patch.start()
            self.addCleanup(patch.stop)
            probes.append(patch.new)
        return probes

    def refuse(self, thunk, *sentinels, pinned=False) -> Exception:
        """Assert one refusal: a short single line naming nothing, with nothing chained into its traceback.

        All file, parser, schema and credential failures must be normalized to PolicyLoadError.
        """
        error = self.outcome(thunk)
        self.assertIsInstance(error, REFUSALS, 'the loader accepted input it must refuse')
        message = str(error)
        self.assertTrue(message and '\n' not in message, 'a refusal names itself, on one line')
        self.assertLess(len(message), 200, 'a fixed sentence is short; a long one carries a payload')
        for sentinel in sentinels:
            self.assertNotIn(sentinel, message, 'a refusal never names the offending input')
        if pinned:
            self.assertIsInstance(error, PolicyLoadError, 'this failure belongs to the loader itself')
        if isinstance(error, PolicyLoadError):
            self.assertIsNone(error.__cause__, 'a loader failure chains nothing')
            self.assertTrue(error.__context__ is None or error.__suppress_context__,
                            'and no foreign exception rides in its traceback')
        return error


class PolicyLoaderTests(LoaderFixture):
    """The config file and the value naming it, then the credential crosscheck behind both doors."""

    def test_a_config_file_loads_the_policy_object_a_store_accepts(self):
        """A str or a `Path` answers with a `VerificationPolicy` that is a snapshot, not a live handle."""
        self.assertEqual(CONFIG_ENVIRONMENT, 'LO_VERIFICATION_POLICY')
        path = self.config(self.text())
        policy = load_policy(str(path), self.credentials())
        self.assertIsInstance(policy, VerificationPolicy)
        self.assertEqual(policy.verifiers, PRODUCERS)
        self.assertEqual(policy.mappings[0]['threshold'], 90.0)
        self.assertIsInstance(load_policy(path, self.credentials()), VerificationPolicy)
        self.config(self.text(mapping=self.mapping(threshold=1.0)))
        self.assertEqual(policy.mappings[0]['threshold'], 90.0, 'a loaded policy is a snapshot')
        self.assertEqual(load_policy(path, self.credentials()).mappings[0]['threshold'], 1.0,
                         'a second load re-reads the file: no cache, no hot reload')

    def test_the_environment_is_read_at_the_call_and_an_absent_key_reads_nothing(self):
        """Absent is `None` with no file opened and no row looked at; the next call sees the next value."""
        good = str(self.config(self.text()))
        other = str(self.config(self.text(verifiers=[W]), 'sentinel-other.json'))
        probes, watched = self.no_opens(), WatchList(self.credentials())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(policy_from_environment(watched))
            self.assertIsNone(policy_from_environment(watched, environ={}))
            self.assertEqual(watched.touched, 0, 'an absent key may not iterate the credential rows')
            self.assertEqual(sum(probe.call_count for probe in probes), 0, 'no file is opened')
            for value, wanted in ((good, PRODUCERS), (other, (W,))):
                os.environ[CONFIG_ENVIRONMENT] = value
                self.assertEqual(policy_from_environment(self.credentials()).verifiers, wanted)
            self.assertEqual(policy_from_environment(self.credentials(),
                         environ={CONFIG_ENVIRONMENT: good}).verifiers, PRODUCERS)

    def test_a_value_or_path_that_is_unusable_refuses_instead_of_defaulting(self):
        """Blank, whitespace and a non-string refuse at both doors: off is an absent key and nothing else."""
        rows = self.credentials()
        for value in ('', ' ', '\t\n', '  \r', 0, 12, None, False, b'\xff', Path('sentinel-path'), ['a']):
            with self.subTest(value=repr(value)[:24]):
                self.refuse(lambda value=value: policy_from_environment(
                    rows, environ={CONFIG_ENVIRONMENT: value}), SENTINEL, pinned=True)
        for junk in ('   ', '\n', {}, object(), Path(), os.devnull, self.root,
                     self.root / 'sentinel-absent.json', str(self.root / 'sentinel-absent.json')):
            with self.subTest(path=repr(junk)[:26]):
                self.refuse(lambda junk=junk: load_policy(junk, rows), SENTINEL, pinned=True)

    @unittest.skipUnless(getattr(os, 'name', '') == 'posix' and hasattr(os, 'mkfifo'),
                         'posix-only: a named pipe needs mkfifo')
    def test_a_fifo_is_refused_at_once_rather_than_waited_on(self):
        """A real FIFO, unspoofed, under a thread deadline: a blocking read is a hang, not a slow refusal."""
        path = self.root / 'sentinel-fifo'
        os.mkfifo(path)
        answers = []
        worker = threading.Thread(target=lambda: answers.append(
            self.outcome(lambda: load_policy(path, self.credentials()))), daemon=True)
        worker.start()
        worker.join(20)
        self.assertFalse(worker.is_alive(), 'the loader must not block a start waiting for a writer')
        self.assertIsInstance(answers[0], PolicyLoadError)

    def test_the_bytes_read_are_utf8_with_ordinary_whitespace_and_a_byte_bound(self):
        """Byte boundaries: ASCII padding is data, another encoding or one byte past 64 KiB is a refusal."""
        payload = self.text()
        cases = (('ascii padding', b'\n \t' + payload + b'\r\n', None),
                 ('bom', b'\xef\xbb\xbf' + payload, True),
                 ('utf-16', payload.decode().encode('utf-16'), True),
                 ('nul first', b'\x00' + payload, True),
                 ('truncated multibyte', payload + b'\xc3', True),
                 ('nbsp indent', b'\xc2\xa0' + payload, True),
                 ('nonascii label', json.dumps(self.document(verifiers=['caf\xe9']),
                                               ensure_ascii=False).encode(), False))
        for name, raw, pinned in cases:
            with self.subTest(case=name):
                if pinned is None:
                    self.assertIsInstance(self.load(raw), VerificationPolicy)
                else:
                    self.refuse(lambda raw=raw, pinned=pinned: self.load(raw), SENTINEL, pinned=pinned)
        compact = json.dumps(self.document(), separators=(',', ':')).encode()
        self.assertLess(len(compact), MAX_POLICY_BYTES, 'the fixture must fit inside the bound')
        exact = b' ' * (MAX_POLICY_BYTES - len(compact)) + compact
        self.assertEqual(len(exact), MAX_POLICY_BYTES)
        self.assertIsInstance(self.load(exact), VerificationPolicy)
        self.refuse(lambda: self.load(b' ' + exact), pinned=True)

    def test_a_repeated_key_at_any_depth_is_refused_rather_than_last_wins(self):
        """Kills the dropped-pairs-hook mutation: every pair below is repeated verbatim, so only an
        object hook can see it, and last-write-wins would load the document unchanged."""
        for depth, raw in (('root', self.duplicated('schema_version')),
                           ('read scope', self.duplicated('artifact_sha256')),
                           ('mapping tail', self.duplicated('artifact_sha256', last=True)),
                           ('mapping middle', self.duplicated('window_seconds'))):
            with self.subTest(depth=depth):
                self.refuse(lambda raw=raw: self.load(raw.encode()), SENTINEL, pinned=True)
        self.assertIsInstance(
            self.load(json.dumps(self.document(), separators=(',', ':')).encode()), VerificationPolicy)

    def test_the_document_vocabulary_is_bounded_json_and_nothing_else(self):
        """No comments, no tail, no YAML, no non-object root, no non-finite number, no runaway depth."""
        text = json.dumps(self.document(), separators=(',', ':'))
        cases = (('empty', ''), ('truncated', text[:-1]), ('trailing document', text + '{}'),
                 ('line comment', '//' + text), ('block comment', '/*' + text + '*/'),
                 ('single quotes', text.replace('"', "'")), ('yaml', 'schema_version: 1'),
                 ('root array', '[]'), ('root null', 'null'),
                 ('runaway depth', '{"a": ' * 10_000 + '1' + '}' * 10_000))
        for name, raw in cases:
            with self.subTest(case=name):
                self.refuse(lambda raw=raw: self.load(raw.encode()), SENTINEL, pinned=True)
        numbers = json.dumps(self.document(mapping=self.mapping(threshold=90)), separators=(',', ':'))
        for spelling in ('NaN', 'Infinity', '-Infinity', '1e400', '9' * 400):
            with self.subTest(number=spelling):
                self.refuse(lambda spelling=spelling: self.load(numbers.replace(
                    '"threshold":90', '"threshold":' + spelling).encode()), SENTINEL)

    def test_credentials_are_crosschecked_only_after_the_document_parsed(self):
        """A config that never became a document may not read the role list at all."""
        broken = self.config(b'{"schema_version": 1', 'sentinel-broken.json')
        for name, path in (('unparsable', broken), ('absent', self.root / 'sentinel-absent.json'),
                           ('directory', self.root)):
            watched = WatchList(self.credentials())
            with self.subTest(config=name):
                self.refuse(lambda path=path, watched=watched: load_policy(path, watched), SENTINEL,
                            pinned=True)
                self.assertEqual(watched.touched, 0, 'a refused document may not read credentials')

    def test_a_rewritten_config_file_leaves_an_existing_binding_alone(self):
        """A loaded policy is ordinary `Store` input: old actions keep the origin they bound under."""
        path = self.config(self.text())
        case = self.executed(self.bound('config-rewrite', policy=load_policy(path, self.credentials())))
        case['verification_id'] = self.put(case)['verification_id']
        self.assertEqual(self.stored(case)['verdict'], 'cleared', 'the loaded policy is the authority')
        self.config(self.text(verifiers=[W], mapping=self.mapping(
            threshold=50.0, artifact_sha256=OTHER_PIN,
            parameters={'resource_id': self.host, 'rule_id': RULE, 'artifact_sha256': OTHER_PIN})))
        reopened = self.open('config-rewrite', policy=load_policy(path, self.credentials(W)))
        self.assertEqual(reopened.get_verification_binding(case['action_id'], READER), case['binding'],
                         'a config rewrite may not re-derive a captured origin')
        fired = self.fire(reopened, minute=1, parameters={'resource_id': self.host, 'rule_id': RULE,
                                                        'artifact_sha256': OTHER_PIN})
        result, _ = self.propose(reopened, case['incident_id'], [fired['event_id']],
                                 retry_key='after-rewrite')
        binding = reopened.get_verification_binding(result['action_id'], READER)
        self.assertEqual((binding['status'], binding['origin']['threshold']), ('bound', 50.0))
        self.assertNotEqual(binding['binding_id'], case['binding_id'])

    def test_every_verifier_identity_is_bound_to_a_producer_credential(self):
        """Kills the disabled-role-binding mutation: each verifier needs a producer row, and no row of
        another role may carry its identity."""
        refused = (('no rows at all', []), ('one verifier has no row', self.credentials(W)),
                   ('a verifier is only a reader', self.credentials(W, extra=[{**ROW, 'identity': V}])),
                   ('a verifier is also an executor', self.credentials(
                       extra=[{**ROW, 'identity': V, 'role': 'executor'}])),
                   ('a verifier is also a human', self.credentials(
                       extra=[{**ROW, 'identity': W, 'role': 'human'}])))
        for name, rows in refused:
            with self.subTest(refused=name):
                self.refuse(lambda rows=rows: self.load(self.text(), credentials=rows), V, W, SENTINEL,
                            pinned=True)
        accepted = (('two producer tokens for one identity', self.credentials(V, W, V)),
                    ('a tuple of rows', tuple(self.credentials())),
                    ('every other role in the same file', self.credentials(extra=[
                        {**ROW, 'identity': role + '-operator', 'role': role} for role in ROLES])))
        for name, rows in accepted:
            with self.subTest(accepted=name):
                self.assertIsInstance(self.load(self.text(), credentials=rows), VerificationPolicy)

    def test_the_credential_argument_is_bounded_plain_rows_and_no_token_is_ever_read(self):
        """Up to 256 rows of exactly identity/role/token, and a token value no path may read."""
        base, poison = self.credentials(), self.credentials(token=PoisonToken)
        self.assertIsInstance(self.load(self.text(), credentials=poison), VerificationPolicy)
        self.assertRaises(AssertionError, lambda: str(poison[0]['token']))
        exact = self.credentials(*PRODUCERS, *[f'{SENTINEL}-extra-{p}' for p in range(254)])
        self.assertEqual(len(exact), 256)
        self.assertIsInstance(self.load(self.text(), credentials=tuple(exact)), VerificationPolicy)
        over = exact + [{**ROW, 'identity': f'{SENTINEL}-extra-254', 'role': 'producer'}]
        cases = (('257 rows', over), ('no rows', []), ('a dict', {}), ('a string', 'producer'),
                 ('nothing', None), ('a generator', (row for row in base)),
                 ('a row that is not a dict', base + ['producer']),
                 ('a row missing its token', base + [dict(MISSING_TOKEN)]),
                 ('a row with an extra key', base + [{**ROW, 'scope': 'x'}]),
                 ('an unknown role', base + [{**ROW, 'role': 'verifier'}]),
                 ('an identity that is not a label', base + [{**ROW, 'identity': SENTINEL + ' spaced'}]),
                 ('an empty identity', base + [{**ROW, 'identity': ''}]),
                 ('a non-string identity', base + [{**ROW, 'identity': 7}]))
        for name, rows in cases:
            with self.subTest(rows=name):
                self.refuse(lambda rows=rows: self.load(self.text(), credentials=rows), SENTINEL,
                            pinned=True)
        revoked = self.credentials(W, token=PoisonToken)
        self.refuse(lambda: self.load(self.text(), credentials=revoked), pinned=True)

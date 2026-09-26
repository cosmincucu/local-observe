"""The verification workflow (worker A): the service factory's verification preflight, and where the routes hook in.

Two halves, and both are about *ordering* rather than about behaviour somebody else owns.

1. **What `app_factory` decides before it may open a database.** The role list is judged
   (`api.validate_credentials`, extracted verbatim from `create_app`) and the mounted verification policy
   is loaded (`verification_policy.policy_from_environment`) *before* `Store` is constructed, so a
   deployment with a repeated token, a 23-character secret, a seventh role or an unusable policy file
   refuses without creating or migrating a state file. Everything that refused first still refuses
   first: the retired environment value, the blank/conflicting mode declarations and the code pin all
   outrank these two, and `intake.rules_from_environment` keeps its place *after* the store. An unset
   `LO_VERIFICATION_POLICY` mounts `None` and opens nothing.
2. **The two hook points in `api.py`.** The verification paths are handed to `VerificationAPI` after
   authentication and before the old `GET` role/summary gate and before any POST body is read; lifespan
   shutdown closes that admission and drains it before the owner lock goes back. Worker B's own tests
   judge the service's parsing, authority, offload and cancellation; what is pinned here is the seam this
   file owns, so moving the hook back inside the old handler cannot quietly re-break a verifier's read.

The negative controls are chosen so a plausible wrong implementation fails, not just a missing one:

* a producer's read refused by `verification_records._reader` answers **403 `not_authorised`** where the
  pre-existing `GET` gate answers **400 `not_authorised`** for the same credential — same word, different
  status, so the answer says which gate judged it (and removing the hook altogether answers 404);
* a policy refusal is asserted with `LO_ACTION_POLICY` naming a *directory*, so code that loaded the
  policy too late would fail here as an `OSError` instead of the refusal it now reports;
* a mounted policy is asserted through the answer the same bytes get on and off (`503
  verification_unavailable` vs `404 not_found`), never by reading a private attribute back;
* the `summary` refusal on a verification POST reads no body and writes no `action.refused` row, while
  the four audited routes still write theirs.

Real temporary `Store` files, direct ASGI calls, no network, no live state, no socket, and no mock of the
feature itself.
"""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from local_observe.platform import api
from local_observe.platform.api import app_factory, create_app, validate_credentials
from local_observe.platform.notification_safety import NotificationPolicy
from local_observe.platform.state import Store
from local_observe.platform.verification_policy import CONFIG_ENVIRONMENT, PolicyLoadError
from local_observe.platform.verification_records import VerificationPolicy

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = json.loads((ROOT / 'examples/platform/verification-policy.json').read_text())
VERIFIER = DOCUMENT['verifiers'][0]
TOKENS = {'producer': 'p' * 32, 'reader': 'r' * 32, 'summary': 's' * 32, 'human': 'h' * 32}
CREDENTIALS = [{'identity': VERIFIER, 'role': 'producer', 'token': TOKENS['producer']},
               {'identity': 'reader', 'role': 'reader', 'token': TOKENS['reader']},
               {'identity': 'operator', 'role': 'summary', 'token': TOKENS['summary']},
               {'identity': 'staff', 'role': 'human', 'token': TOKENS['human']}]
BINDING_ID = 'a' * 64
MISSING_ACTION = '6f9f1c1f-2b0e-4a55-9b7a-2f4a1d6b0c11'
MISSING_EXECUTION = '2b1c73f4-8a0e-4d8b-9c1d-6e0f2a5b7c44'
BINDING_QUERY = 'action_id=' + MISSING_ACTION
#: Shape-valid and about nothing: an `unavailable` read with no receipt and no rows, so the only thing
#: the state layer can say about it is that no such execution exists.
WINDOW = {'start': '2026-01-01T00:00:00+00:00', 'end': '2026-01-01T00:05:00+00:00'}
RECORD = {'execution_id': MISSING_EXECUTION, 'binding_id': BINDING_ID, 'window': WINDOW,
          'outcome': 'unavailable', 'receipt': None, 'samples': []}


def request(method: str, path: str, *, query: str = '', token: str, body: bytes = b'') -> dict:
    return {'type': 'http', 'method': method, 'path': path, 'query_string': query.encode(),
            'headers': [(b'authorization', ('Bearer ' + token).encode())], 'body': body}


async def call(app, message: dict, receive=None) -> tuple[int, dict]:
    """Drive one request through the raw ASGI surface and return its status and decoded body."""
    sent: list[dict] = []

    async def send(item: dict) -> None:
        sent.append(item)

    async def default_receive() -> dict:
        return {'type': 'http.request', 'body': message.get('body', b''), 'more_body': False}

    await app({key: value for key, value in message.items() if key != 'body'},
              receive or default_receive, send)
    return sent[0]['status'], json.loads(sent[1]['body'])


class Forbidden:
    """Reports the one thing that must never happen to it: being looked inside."""

    def __getattr__(self, name: str):
        raise AssertionError(f'the transport touched the store before validating ({name})')


class CredentialValidationTests(unittest.TestCase):
    """`validate_credentials` is `create_app`'s old first eight lines, and nothing else."""

    def sentence(self, thunk) -> str:
        with self.assertRaises(ValueError) as caught:
            thunk()
        return str(caught.exception)

    def test_todays_admissible_shape_still_passes_unchanged(self):
        self.assertIsNone(validate_credentials(CREDENTIALS))
        # The boundaries as they are today, spelled: 24 characters admissible, 23 not, and exactly the
        # six known roles. Neither may move here — widening either is a contract change, not this one.
        self.assertIsNone(validate_credentials([{'identity': 'x', 'role': 'executor', 'token': 'x' * 24}]))
        self.assertEqual(self.sentence(lambda: validate_credentials(
            [{'identity': 'x', 'role': 'executor', 'token': 'x' * 23}])),
            'Invalid platform credential configuration')
        self.assertEqual(self.sentence(lambda: validate_credentials(
            [{'identity': 'x', 'role': 'verifier', 'token': 'x' * 32}])),
            'Invalid platform credential configuration')

    def test_the_two_sentences_are_the_only_answers_and_carry_no_token(self):
        for bad in ([], [{'identity': 'a', 'role': 'reader', 'token': 'a' * 32},
                         {'identity': 'b', 'role': 'reader', 'token': 'a' * 32}]):
            with self.subTest(bad=bad):
                self.assertEqual(self.sentence(lambda: validate_credentials(bad)),
                                 'Missing or duplicate platform credentials')
        text = self.sentence(lambda: validate_credentials(
            [{'identity': 'a', 'role': 'wizard', 'token': 'q' * 40}]))
        self.assertEqual(text, 'Invalid platform credential configuration')
        self.assertNotIn('q' * 40, text)

    def test_create_app_still_validates_before_it_touches_the_store(self):
        for bad in ([], [{'identity': 'a', 'role': 'reader', 'token': 'a' * 32},
                         {'identity': 'b', 'role': 'producer', 'token': 'a' * 32}],
                    [{'identity': 'a', 'role': 'reader', 'token': 'a' * 20}]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                create_app(Forbidden(), bad, {})


class FactoryPreflightTests(unittest.TestCase):
    """What `app_factory` settles before it is allowed to open a database."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.actions = self.root / 'actions.json'
        self.actions.write_text('{}', encoding='utf-8')
        self.credentials = self.root / 'platform-credentials.json'
        self.state_path = self.root / 'state.db'
        self.mount_credentials(CREDENTIALS)
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def mount_credentials(self, rows) -> None:
        self.credentials.write_text(json.dumps(rows), encoding='utf-8')

    def environment(self, **extra) -> dict:
        return dict({'LO_NOTIFICATION_MODE': 'off', 'LO_ACTION_POLICY': str(self.actions),
                     'LO_PLATFORM_CREDENTIALS': str(self.credentials),
                     'LO_STATE_PATH': str(self.state_path), 'LO_INDEX_PATH': 'unused'}, **extra)

    def policy_file(self, document=None, *, raw: bytes | None = None,
                    name: str = 'verification-policy.json') -> Path:
        path = self.root / name
        path.write_bytes(raw if raw is not None else json.dumps(document).encode())
        return path

    def test_bad_credentials_refuse_before_the_store_is_created(self):
        cases = [([], 'Missing or duplicate platform credentials'),
                 ([CREDENTIALS[0], dict(CREDENTIALS[1], token=TOKENS['producer'])],
                  'Missing or duplicate platform credentials'),
                 ([dict(CREDENTIALS[0], token='p' * 23)], 'Invalid platform credential configuration'),
                 ([dict(CREDENTIALS[1], role='verifier')], 'Invalid platform credential configuration')]
        for rows, sentence in cases:
            with self.subTest(sentence=sentence):
                self.mount_credentials(rows)
                env = self.environment(**{CONFIG_ENVIRONMENT: str(self.policy_file(
                    document=DOCUMENT, name='policy-' + sentence[:7] + '.json'))})
                with patch.dict(os.environ, env), \
                        patch('local_observe.platform.api.Store') as store, \
                        patch('local_observe.platform.verification_policy.policy_from_environment') as load:
                    with self.assertRaisesRegex(ValueError, sentence):
                        app_factory()
                store.assert_not_called()
                # The policy loader sits *after* credential validation, so a role list this transport may
                # not serve never reaches the question of which policy it would have mounted.
                load.assert_not_called()
                self.assertFalse(self.state_path.exists())

    def test_a_useless_policy_refuses_before_the_store_and_before_anything_else_is_read(self):
        unusable = [self.policy_file({'schema_version': 2, 'verifiers': [VERIFIER], 'mappings': []},
                                     name='version.json'),
                    # Well-formed document, verifier nobody mounts as a producer: the credential
                    # crosscheck has to have run, and it has to have refused before the state file.
                    self.policy_file({**DOCUMENT, 'verifiers': ['nobody-mounted']}, name='verifier.json'),
                    self.policy_file(raw=b'\xff\xfe{"schema_version": 1}', name='bytes.json')]
        for path in unusable:
            with self.subTest(policy=path.name):
                # `LO_ACTION_POLICY` names a *directory*: reach it and the failure is an `OSError`, which
                # is exactly the "policy loaded too late" bug this test exists to catch.
                env = self.environment(**{CONFIG_ENVIRONMENT: str(path),
                                          'LO_ACTION_POLICY': str(self.root)})
                with patch.dict(os.environ, env), \
                        patch('local_observe.platform.api.Store') as store, \
                        patch('local_observe.platform.intake.rules_from_environment') as rules:
                    with self.assertRaises(PolicyLoadError):
                        app_factory()
                store.assert_not_called()
                rules.assert_not_called()
                self.assertFalse(self.state_path.exists())

    def test_an_unset_policy_mounts_nothing_and_opens_no_file(self):
        with patch.dict(os.environ, self.environment()), \
                patch('local_observe.platform.api.Store') as store, \
                patch('local_observe.platform.verification_policy.load_policy') as read:
            app = app_factory()
        store.assert_called_once()
        self.assertIs(store.call_args.kwargs['verification_policy'], None)
        read.assert_not_called()
        # Only the two input files exist: no state file, and no policy file to have opened.
        self.assertEqual(sorted(item.name for item in self.root.iterdir()),
                         [self.actions.name, self.credentials.name])
        # One service per app, and nothing shared between apps (the `refusal_audit_dispatch` precedent).
        second = create_app(store.return_value, CREDENTIALS, {})
        self.assertIsNot(app.verification_api, second.verification_api)

    def test_a_mounted_policy_reaches_the_store_by_keyword_and_nowhere_else(self):
        env = self.environment(**{CONFIG_ENVIRONMENT: str(self.policy_file(document=DOCUMENT))})
        with patch.dict(os.environ, env), patch('local_observe.platform.api.Store') as store:
            app_factory()
        store.assert_called_once()
        # Two positional arguments (path, notification policy) and the policy *by name*: `Store`'s third
        # positional parameter is the keyword-only `channel_policies`, so a positional policy would be a
        # different argument entirely — and `migrate` stays defaulted off.
        self.assertEqual(len(store.call_args.args), 2)
        self.assertEqual(str(store.call_args.args[0]), str(self.state_path))
        self.assertNotIn('migrate', store.call_args.kwargs)
        mounted = store.call_args.kwargs['verification_policy']
        self.assertIsInstance(mounted, VerificationPolicy)
        self.assertEqual(mounted.verifiers, (VERIFIER,))
        self.assertEqual(len(mounted.mappings), 1)

    def test_every_earlier_boot_refusal_still_outranks_the_two_new_ones(self):
        unusable = self.policy_file({'schema_version': '1'}, name='refused.json')
        self.mount_credentials([])
        conflicting = self.root / 'safety.json'
        conflicting.write_text('{"delivery_mode":"live"}', encoding='utf-8')
        cases = [({'LO_PLATFORM_CREDENTIALS_JSON': '[]'}, 'retired'),
                 ({'LO_NOTIFICATION_MODE': '   '}, 'set but blank'),
                 ({'LO_NOTIFICATION_POLICY': str(conflicting)}, 'Conflicting notification'),
                 ({'LO_PLATFORM_CODE_ROOT': str(ROOT)}, 'pinned together'),
                 ({'LO_PLATFORM_CODE_SHA256': '0' * 64}, 'pinned together')]
        for extra, marker in cases:
            with self.subTest(marker=marker):
                env = self.environment(**extra, **{CONFIG_ENVIRONMENT: str(unusable)})
                with patch.dict(os.environ, env), \
                        patch('local_observe.platform.api.Store') as store, \
                        patch('local_observe.platform.verification_policy.policy_from_environment') as load:
                    with self.assertRaisesRegex(ValueError, marker):
                        app_factory()
                store.assert_not_called()
                load.assert_not_called()
                self.assertFalse(self.state_path.exists())

    def test_the_new_preflight_sits_between_the_code_pin_and_the_store(self):
        from local_observe.platform import intake as intake_module
        from local_observe.platform import verification_policy as policy_module
        order: list[str] = []
        real_validate = api.validate_credentials
        real_load = policy_module.policy_from_environment
        real_rules = intake_module.rules_from_environment

        def validate(rows):
            order.append('credentials')
            return real_validate(rows)

        def load(rows, **kwargs):
            order.append('policy')
            return real_load(rows, **kwargs)

        def rules():
            order.append('rules')
            return real_rules()

        def opened(*args, **kwargs):
            order.append('store')
            return MagicMock()

        env = self.environment(**{CONFIG_ENVIRONMENT: str(self.policy_file(document=DOCUMENT))})
        with patch.dict(os.environ, env), \
                patch('local_observe.platform.api.validate_credentials', validate), \
                patch('local_observe.platform.verification_policy.policy_from_environment', load), \
                patch('local_observe.platform.intake.rules_from_environment', rules), \
                patch('local_observe.platform.api.Store', side_effect=opened):
            app_factory()
        self.assertLess(order.index('credentials'), order.index('store'))
        self.assertLess(order.index('policy'), order.index('store'))
        # Unmoved: the intake rules are still read last, after the store they must never pre-empt.
        self.assertLess(order.index('store'), order.index('rules'))

    def test_the_mounted_policy_is_the_difference_between_503_and_404_on_one_shape(self):
        """The factory's keyword reaches the state layer, and the answer on the wire says so."""
        body = json.dumps(RECORD, separators=(',', ':')).encode()
        with patch.dict(os.environ, self.environment()):
            off = app_factory()
            refused = asyncio.run(call(off, request('POST', '/v1/verification/records',
                                                    token=TOKENS['producer'], body=body)))
        self.assertEqual(refused[0], 503)
        self.assertEqual(refused[1]['error'], 'verification_unavailable')

        env = self.environment(**{CONFIG_ENVIRONMENT: str(self.policy_file(document=DOCUMENT))})
        with patch.dict(os.environ, env):
            on = app_factory()
            answered = asyncio.run(call(on, request('POST', '/v1/verification/records',
                                                    token=TOKENS['producer'], body=body)))
        # Allowlisted verifier, mounted policy: the write gets as far as the state layer, and there is no
        # such execution. Off, the same bytes never reached it. Both halves need the hook: with it
        # removed, a producer POST on this path answers 404 either way.
        self.assertEqual(answered[1]['error'], 'not_found')
        self.assertEqual(answered[0], 404)


class RouteAndLifecycleTests(unittest.TestCase):
    """The two `api.py` hook points: ahead of the old gates, drained ahead of the owner lock."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = patch.dict(os.environ, {}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def store(self, policy: VerificationPolicy | None = None) -> Store:
        return Store(self.root / 'state.db', NotificationPolicy(delivery_mode='off'),
                     verification_policy=policy)

    def test_a_producer_read_is_judged_by_the_state_layer_not_by_the_old_get_gate(self):
        app = create_app(self.store(), CREDENTIALS, {})
        status, body = asyncio.run(call(app, request('GET', '/v1/verification/binding',
                                                     query=BINDING_QUERY, token=TOKENS['producer'])))
        # The old gate answers a producer 400 `not_authorised`; `_reader` answers 403. The status is the
        # whole assertion: it says the hook ran first, and that authority came from the module that knows
        # whether this producer is a verifier under the policy mounted *now*.
        self.assertEqual(status, 403)
        self.assertEqual(body['error'], 'not_authorised')

    def test_admission_to_the_verification_routes_widens_no_other_route(self):
        app = create_app(self.store(), CREDENTIALS, {})
        for path in ('/v1/me', '/v1/status', '/v1/overview', '/v1/records/incidents', '/v1/audit'):
            with self.subTest(path=path):
                status, body = asyncio.run(call(app, request('GET', path, token=TOKENS['producer'])))
                self.assertEqual((status, body['error']), (400, 'not_authorised'))
        # No bearer, no service: authentication stays the transport's, ahead of every new route.
        anonymous = {'type': 'http', 'method': 'GET', 'path': '/v1/verification/binding',
                     'query_string': BINDING_QUERY.encode(), 'headers': []}
        self.assertEqual(asyncio.run(call(app, anonymous))[0], 401)

    def test_the_summary_refusal_on_a_verification_post_reads_no_body_and_audits_nothing(self):
        store = self.store()
        app = create_app(store, CREDENTIALS, {})
        reads: list[int] = []

        async def receive() -> dict:
            reads.append(1)
            return {'type': 'http.disconnect'}

        status, body = asyncio.run(call(app, request('POST', '/v1/verification/records',
                                                     token=TOKENS['summary']), receive=receive))
        self.assertEqual((status, body['error']), (403, 'summary_only'))
        self.assertEqual(reads, [])
        # These routes are not `REFUSAL_POST_ROUTES`: the transport audits one refusal and no more.
        self.assertEqual(store.refusal_audit_status()['written'], 0)
        asyncio.run(call(app, request('POST', '/v1/actions', token=TOKENS['summary'], body=b'{}')))
        self.assertEqual(store.refusal_audit_status()['written'], 1)

    def test_shutdown_closes_and_drains_verification_before_the_owner_lock_goes(self):
        store = self.store(VerificationPolicy(DOCUMENT))
        app = create_app(store, CREDENTIALS, {})
        service = app.verification_api
        events: list[str] = []
        real_owner, real_idle = api.exclusive_owner, service.wait_idle

        class Owner:
            """The real owner lock, with the two moments this test needs to see in order."""

            def __init__(self, path):
                self.inner = real_owner(path)

            def __enter__(self):
                value = self.inner.__enter__()
                events.append('owner-acquired')
                return value

            def __exit__(self, *exc):
                events.append('owner-released')
                return self.inner.__exit__(*exc)

        async def wait_idle():
            await real_idle()
            events.append('verification-drained')

        async def scenario():
            messages: asyncio.Queue = asyncio.Queue()
            started = asyncio.Event()

            async def send(message: dict) -> None:
                if message['type'] == 'lifespan.startup.complete':
                    started.set()
                if message['type'] == 'lifespan.shutdown.complete':
                    events.append('shutdown-complete')

            task = asyncio.create_task(app({'type': 'lifespan'}, messages.get, send))
            await messages.put({'type': 'lifespan.startup'})
            await asyncio.wait_for(started.wait(), timeout=5)
            # Admission open: a reader's well-formed read reaches `Store` and finds no such action.
            serving = await call(app, request('GET', '/v1/verification/binding',
                                              query=BINDING_QUERY, token=TOKENS['reader']))
            await messages.put({'type': 'lifespan.shutdown'})
            await asyncio.wait_for(task, timeout=5)
            # Admission closed: the same bytes are refused without a `Store` call, and stay refused.
            closed = await call(app, request('GET', '/v1/verification/binding',
                                             query=BINDING_QUERY, token=TOKENS['reader']))
            return serving, closed

        with patch.object(api, 'exclusive_owner', Owner), patch.object(service, 'wait_idle', wait_idle):
            serving, closed = asyncio.run(scenario())
        self.assertEqual((serving[0], serving[1]['error']), (404, 'not_found'))
        self.assertEqual(closed[0], 503)
        self.assertEqual(closed[1]['error'], 'verification_busy')
        # The drain is what the lock waits behind, in this order and no other.
        self.assertEqual(events, ['owner-acquired', 'verification-drained', 'owner-released',
                                 'shutdown-complete'])

    def test_an_app_served_without_a_lifespan_answers_both_surfaces(self):
        app = create_app(self.store(), CREDENTIALS, {})
        status, body = asyncio.run(call(app, request('GET', '/v1/verification/record',
                                                    query='verification_id=' + BINDING_ID,
                                                    token=TOKENS['reader'])))
        # A well-formed id that was never recorded is "no such record", not a malformed request.
        self.assertEqual((status, body['error']), (404, 'not_found'))
        self.assertEqual(asyncio.run(call(app, request('GET', '/v1/me', token=TOKENS['reader'])))[0], 200)


if __name__ == '__main__':
    unittest.main()

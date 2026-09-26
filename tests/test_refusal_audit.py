"""The refusal audit: the durable refusal audit — one row per refusal, bounded, and never a lie.

`tests/test_action_invariants.py` asks the lifecycle's central question ("did the firewall hold?").
This file asks the one that invariant could not answer until the refusal audit: **is the refusal itself
durable, and does the record say only true things about it?** Four things are pinned, each for a way
the feature could be quietly wrong:

* **Ordering.** A refusal's partial state is rolled back and its connection closed *before* the audit
  row commits, and the audit row never commits refused state. Asserted behaviourally (a sentinel
  written inside a refused transaction is gone while the refusal row remains) and structurally (an AST
  check that the wrapper is the first statement of each audited method, that every `self.transaction()`
  sits inside it, and that `self.audit` is never called from an `except` block) — because a comment
  cannot hold that property through a refactor.
* **Content.** Fixed attempt and reason words; an identity that is a real platform `Actor` with a
  bounded label and a known role; a subject that is a canonical UUID or the `unbound` sentinel. A
  planted string is walked out of every audit column and every log record. An identity the state layer
  cannot validate produces **no row at all**, rather than a hashed or invented one.
* **Rate, honestly.** A process-local token bucket (capacity 64, 1 token/second, a real monotonic
  clock) bounds how fast refusal rows may be written — nothing more. `written`/`dropped`/`failed`/
  `unauditable` are observable, the counters reset on a restart while the rows do not, and a failed
  write still spends its token.
* **No collateral.** Exactly one row per refusal (never two: the API does not re-audit what the store
  wrote), zero rows for anything unauthenticated or rejected by the parser, size, shape or route gates,
  and no accepted transition, status code, error body or lifecycle row moves. The one exception is a
  decision, not an oversight: the `summary` role gate on those four routes answers before the body is
  read, so malformed or oversized bytes from a `summary` credential are audited as the role denial they
  already are (`test_the_summary_gate_answers_a_refusal_before_the_body_is_read`).

Fixture style follows `tests/test_api_errors.py` (a real `Store` on a temp path, the ASGI app called
directly, no socket) and `tests/test_action_invariants.py` (the inventory index an action policy
needs). Nothing here sleeps, opens a network connection, touches a live host or imports an optional
package.
"""
import ast
import asyncio
import datetime as dt
import json
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from local_observe.inventory import index
from local_observe.inventory.validation import InvalidInventory, read_document, timestamp, utc_text
from local_observe.platform import detections, refusals
from local_observe.platform.api import create_app
from local_observe.platform.policy import action_policy
from local_observe.platform.state import Actor, StateError, Store

ROOT = Path(__file__).resolve().parents[1]
NOW = timestamp('2026-09-06T12:01:00Z')
LATER = NOW + dt.timedelta(hours=2)
PRODUCER = Actor('test-detector', 'producer')
AGENT = Actor('agent-1', 'proposer')
HUMAN = Actor('operator', 'human')
RUNNER = Actor('runner-1', 'executor')
SUMMARY = Actor('watcher', 'summary')
# A string planted everywhere a caller can put text. It must reach no audit column, no log record and
# no error body: the point of an audit surface is that nobody may write through it.
SENTINEL = 'never-in-a-row-or-a-log-line'

CREDENTIALS = [{'identity': AGENT.identity, 'role': 'proposer', 'token': 'proposer-token-for-tests-00000000'},
               {'identity': HUMAN.identity, 'role': 'human', 'token': 'human-token-for-tests-000000000000'},
               {'identity': RUNNER.identity, 'role': 'executor', 'token': 'executor-token-for-tests-00000'},
               {'identity': 'reader-1', 'role': 'reader', 'token': 'reader-token-for-tests-0000000000'},
               {'identity': SUMMARY.identity, 'role': 'summary', 'token': 'summary-token-for-tests-0000000'}]
TOKENS = {row['identity']: row['token'] for row in CREDENTIALS}

STATE_LOGGER = 'local_observe.platform.state'
API_LOGGER = 'local_observe.platform.api'

# The refusal matrix: (attempt word, reason word, provoking case, `MUTATING` when the case has to change
# durable state to be reachable at all — those run last, and the state-purity test names them rather
# than quietly dropping them). Declared as data so the taxonomy tests can read the vocabulary without
# touching a database, and so a new platform sentence that needs a word is visible in the same list a
# test has to extend.
MUTATING = True
MATRIX_CASES = (
    ('propose', 'actor-not-authorised', 'propose_wrong_role', not MUTATING),
    ('propose', 'request-fields', 'propose_wrong_shape', not MUTATING),
    ('propose', 'bad-label', 'propose_bad_label', not MUTATING),
    ('propose', 'bad-identifier', 'propose_bad_identifier', not MUTATING),
    ('propose', 'bad-timestamp', 'propose_bad_timestamp', not MUTATING),
    ('propose', 'expiry-out-of-range', 'propose_expiry_out_of_range', not MUTATING),
    ('propose', 'policy-targets-shape', 'propose_targets_shape', not MUTATING),
    ('propose', 'policy-not-allowlisted', 'propose_not_allowlisted', not MUTATING),
    ('propose', 'policy-parameters-size', 'propose_parameters_size', not MUTATING),
    ('propose', 'policy-parameters-schema', 'propose_parameters_schema', not MUTATING),
    ('propose', 'policy-target-opt-in', 'propose_target_not_opted_in', not MUTATING),
    ('propose', 'incident-not-open', 'propose_incident_absent', not MUTATING),
    ('propose', 'evidence-unbounded', 'propose_evidence_unbounded', not MUTATING),
    ('propose', 'evidence-off-incident', 'propose_evidence_off_incident', not MUTATING),
    ('decide', 'actor-not-authorised', 'decide_wrong_role', not MUTATING),
    ('decide', 'decision-word', 'decide_bad_word', not MUTATING),
    ('decide', 'action-not-pending', 'decide_unknown_action', not MUTATING),
    ('claim', 'actor-not-authorised', 'claim_wrong_role', not MUTATING),
    ('claim', 'action-not-dispatchable', 'claim_already_executing', not MUTATING),
    ('outcome', 'actor-not-authorised', 'outcome_wrong_role', not MUTATING),
    ('outcome', 'outcome-word', 'outcome_bad_word', not MUTATING),
    ('outcome', 'execution-not-reportable', 'outcome_execution_absent', not MUTATING),
    ('outcome', 'runner-credential-mismatch', 'outcome_wrong_token', not MUTATING),
    ('outcome', 'reconciliation-state', 'outcome_human_over_executing', not MUTATING),
    ('propose', 'retry-changed-contents', 'propose_retry_changed_contents', MUTATING),
    ('outcome', 'execution-not-reportable', 'outcome_after_terminal', MUTATING),
    ('claim', 'incident-recovered', 'claim_incident_recovered', MUTATING),
)


class FakeMonotonic:
    """A monotonic clock the test drives, so a refill is observed without a sleep.

    Production builds the bucket with `time.monotonic`; this stands in for it. It is *not* the `now=`
    argument a `Store` method accepts, and the two are never connected — a rate budget whose clock a
    caller holds is not a budget.
    """

    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds

    def set_to(self, seconds: float) -> None:
        """Name the next instant exactly.

        `advance` accumulates, and accumulated tenths are not tenths (`59.9 + 0.1 + 59.8 + 0.1` is
        119.89999999999999), so a test that means to stand 60.0 s after a stamp sets the stamp rather
        than summing towards it.
        """
        self.value = seconds


class SteppingMonotonic:
    """A monotonic source that moves a little on every read, so read order and grant order can differ.

    A clock frozen at one instant cannot expose a throttle that samples it *outside* the lock it needs:
    every thread sees the same value either way. One step per read means a stale sample can name an
    instant earlier than the one the lock holder just recorded, which is the reordering the log throttle
    must not lose.
    """

    def __init__(self, step: float = 7.0) -> None:
        self.step = step
        self.value = 0.0
        self._reads = threading.Lock()

    def __call__(self) -> float:
        with self._reads:
            current = self.value
            self.value += self.step
            return current


async def request(app, method: str, path: str, body: bytes = b'',
                  headers: list | None = None) -> tuple[int, dict]:
    """One in-process ASGI exchange, with the header list left editable for the doubled-bearer cases."""
    output = []

    async def receive():
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)

    await app({'type': 'http', 'method': method, 'path': path,
               'headers': headers if headers is not None else [], 'query_string': b''}, receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


def bearer(identity: str) -> list:
    return [(b'authorization', ('Bearer ' + TOKENS[identity]).encode())]


async def request_counting_reads(app, method: str, path: str, body: bytes,
                                headers: list) -> tuple[int, dict, int]:
    """One ASGI exchange that reports how many times the handler awaited `receive()`.

    "The body was never read" and "the body was never offered" look identical from the response alone;
    the count is what tells them apart, and the same bytes handed to a route that does read them proves
    the counter is not stuck at zero.
    """
    output, reads = [], []

    async def receive():
        reads.append(1)
        return {'type': 'http.request', 'body': body, 'more_body': False}

    async def send(message):
        output.append(message)

    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers, 'query_string': b''},
              receive, send)
    return output[0]['status'], json.loads(output[1]['body']), len(reads)


async def request_forbidding_body(app, method: str, path: str, headers: list) -> tuple[int, dict]:
    """One ASGI exchange where reaching for the body is a failure, not a detail.

    An answer the transport can give from the credential role and the path alone must never await a
    chunk. If it ever does, this `receive()` raises and the handler's own `except Exception` turns the
    request into a 500 — a wrong answer this file's assertions catch, rather than a silent extra read.
    """
    output = []

    async def receive():
        raise AssertionError('this gate must answer before any body chunk is read')

    async def send(message):
        output.append(message)

    await app({'type': 'http', 'method': method, 'path': path, 'headers': headers, 'query_string': b''},
              receive, send)
    return output[0]['status'], json.loads(output[1]['body'])


def self_call(node: ast.AST, names: tuple[str, ...]) -> bool:
    """Is this node a `self.<name>(...)` call for one of `names`?"""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in names and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'self')


def opens_refusal(node: ast.AST) -> bool:
    """Is this node `with self.refusal(...):`?"""
    return bool(isinstance(node, ast.With) and node.items and self_call(node.items[0].context_expr,
                                                                        ('refusal',)))


def literal_raises(tree: ast.AST, names: set[str]) -> set[str]:
    """Every whole literal sentence raised as `StateError`/`InvalidInventory` inside `names`.

    `Store`'s methods and the module-level validators are matched by name; the names used here are
    unique in the two files this probe reads, which is checked by the assertion that the probe found
    anything at all.
    """
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in names:
            continue
        for raise_node in ast.walk(node):
            if not isinstance(raise_node, ast.Raise) or not isinstance(raise_node.exc, ast.Call):
                continue
            callee = raise_node.exc.func
            name = getattr(callee, 'id', None) or getattr(callee, 'attr', None)
            if name not in ('StateError', 'InvalidInventory') or not raise_node.exc.args:
                continue
            first = raise_node.exc.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add(first.value)
    return found


class LifecycleFixture:
    """The action lifecycle a refusal needs, plus the read helpers every assertion shares.

    Mixed into `TestCase` subclasses only; it defines no tests. `build()` opens the store with an
    injectable monotonic clock so a test can watch the write budget refill.
    """

    def build(self) -> Store:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.clock = FakeMonotonic()
        self.store = Store(self.root / 'state.db', refusal_clock=self.clock)
        self.declared = read_document(ROOT / 'examples/inventory/declared.yaml')
        self.host = self.declared['resources'][0]['id']
        self.declared['resources'][0]['attributes']['remediation_enabled'] = True
        # The second declared resource stays opted out: it is how `policy-target-opt-in` is provoked.
        self.other = self.declared['resources'][1]['id']
        self.index = self.root / 'inventory.db'
        index.build(self.declared, self.index, 'fixture', now=NOW)
        self.policy = action_policy(self.index, {'inspect': {'version': '1', 'parameters': {
            'type': 'object', 'properties': {}, 'additionalProperties': False}}})
        self.incident = self.open_incident()
        # An approved action, still dispatchable and never claimed: the shape every refusal below needs.
        self.approved_id = self.approved(retry_key='matrix-approved')
        self.executing_id, self.claim = self.dispatched(retry_key='matrix-executing')
        self.absent = str(uuid.uuid4())
        return self.store

    # ------------------------------------------------------------- the happy path, once

    def event(self, status='firing', minute=0):
        end = NOW + dt.timedelta(minutes=minute)
        window = {'start': utc_text(end - dt.timedelta(minutes=1)), 'end': utc_text(end)}
        return detections.event(PRODUCER.identity, self.host, 'availability', 'availability', status,
                                window, {'sample_id': f'fixture-{minute}'}, query_type='gatus-result')

    def open_incident(self, minute=0, status='firing'):
        return self.store.intake(self.event(status, minute), PRODUCER, now=NOW + dt.timedelta(minutes=minute))

    def request_document(self, retry_key='once', **overrides):
        document = {'retry_key': retry_key, 'incident_id': self.incident['incident_id'],
                    'action': 'inspect', 'version': '1', 'targets': [self.host], 'parameters': {},
                    'evidence': [self.incident['event_id']],
                    'expires_at': utc_text(NOW + dt.timedelta(hours=1))}
        document.update(overrides)
        return document

    def proposed(self, retry_key='once', actor=AGENT, **overrides):
        return self.store.propose_action(self.request_document(retry_key, **overrides), actor,
                                         self.policy, now=NOW)['action_id']

    def approved(self, retry_key='once'):
        action_id = self.proposed(retry_key=retry_key)
        self.store.decide(action_id, 'approved', HUMAN, now=NOW)
        return action_id

    def dispatched(self, retry_key='once'):
        """An approved action that has been claimed; returns `(action_id, claim)`."""
        action_id = self.approved(retry_key=retry_key)
        return action_id, self.store.claim_action(action_id, RUNNER, self.policy, now=NOW)

    # ------------------------------------------------------------- the matrix's provokers
    # Each returns a zero-argument callable that attempts one refusal and must raise `StateError`
    # (or, for `bad-timestamp`, the `InvalidInventory` the inventory validator raises).

    def propose(self, retry_key, actor=AGENT, **overrides):
        document = self.request_document(retry_key, **overrides)
        return lambda: self.store.propose_action(document, actor, self.policy, now=NOW)

    def outcome(self, execution_id, answer, actor, token=None):
        return lambda: self.store.execution_outcome(execution_id, answer, actor, token, now=NOW)

    def _retry_changed_contents(self):
        """The same retry key carrying different bytes: a conflict about state the caller cannot see.

        The field that changes is `expires_at`, not `parameters`: the policy gate re-checks parameters
        before the retry fingerprint is ever computed, so a different `parameters` document is refused as
        a schema failure and would never reach the sentence this case exists to provoke.
        """
        self.store.propose_action(self.request_document('matrix-retry'), AGENT, self.policy, now=NOW)
        self.store.propose_action(self.request_document(
            'matrix-retry', expires_at=utc_text(NOW + dt.timedelta(hours=2))), AGENT, self.policy, now=NOW)

    def _outcome_after_terminal(self):
        action_id, claim = self.dispatched(retry_key='matrix-terminal')
        self.store.execution_outcome(claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'],
                                     now=NOW)
        self.store.execution_outcome(claim['execution_id'], 'failed', RUNNER, claim['runner_token'],
                                     now=NOW)

    def _claim_incident_recovered(self):
        closing_id = self.approved(retry_key='matrix-recovered')
        self.store.intake(self.event('resolved', 6), PRODUCER, now=NOW + dt.timedelta(minutes=6))
        self.store.claim_action(closing_id, RUNNER, self.policy, now=NOW + dt.timedelta(minutes=6))

    def attempt(self, case: str):
        """Return the zero-argument callable for one named matrix case."""
        cases = {
            'propose_wrong_role': self.propose('p-role', actor=RUNNER),
            'propose_wrong_shape': lambda: self.store.propose_action({'not': 'a request'}, AGENT,
                                                                    self.policy, now=NOW),
            'propose_bad_label': self.propose(retry_key='spaces are refused'),
            'propose_bad_identifier': self.propose('p-uuid', incident_id=SENTINEL),
            'propose_bad_timestamp': self.propose('p-stamp', expires_at='yesterday'),
            'propose_expiry_out_of_range': self.propose(
                'p-far', expires_at=utc_text(NOW + dt.timedelta(days=3))),
            'propose_targets_shape': self.propose('p-targets', targets=[]),
            'propose_not_allowlisted': self.propose('p-unlisted', action='not-declared'),
            'propose_parameters_size': self.propose('p-size', parameters={'blob': 'x' * 9000}),
            'propose_parameters_schema': self.propose('p-schema', parameters={'unexpected': 1}),
            'propose_target_not_opted_in': self.propose('p-optin', targets=[self.other]),
            'propose_incident_absent': self.propose('p-absent', incident_id=self.absent),
            'propose_evidence_unbounded': self.propose('p-noevidence', evidence=[]),
            'propose_evidence_off_incident': self.propose('p-offincident', evidence=[self.absent]),
            'decide_wrong_role': lambda: self.store.decide(self.approved_id, 'approved', AGENT, now=NOW),
            'decide_bad_word': lambda: self.store.decide(self.approved_id, 'sideways', HUMAN, now=NOW),
            'decide_unknown_action': lambda: self.store.decide(self.absent, 'approved', HUMAN, now=NOW),
            'claim_wrong_role': lambda: self.store.claim_action(self.approved_id, HUMAN, self.policy,
                                                                now=NOW),
            'claim_already_executing': lambda: self.store.claim_action(self.executing_id, RUNNER,
                                                                      self.policy, now=NOW),
            'outcome_wrong_role': self.outcome(self.claim['execution_id'], 'succeeded', AGENT,
                                               self.claim['runner_token']),
            'outcome_bad_word': self.outcome(self.claim['execution_id'], 'sideways', RUNNER,
                                             self.claim['runner_token']),
            'outcome_execution_absent': self.outcome(self.absent, 'succeeded', RUNNER, 'a-token'),
            'outcome_wrong_token': self.outcome(self.claim['execution_id'], 'succeeded', RUNNER,
                                                'wrong-token'),
            'outcome_human_over_executing': self.outcome(self.claim['execution_id'], 'succeeded', HUMAN),
            'propose_retry_changed_contents': self._retry_changed_contents,
            'outcome_after_terminal': self._outcome_after_terminal,
            'claim_incident_recovered': self._claim_incident_recovered,
        }
        if case not in cases:
            raise AssertionError(f'no matrix case named {case}')
        return cases[case]

    def run_matrix(self, *, include_mutating=True):
        """Provoke every matrix case and return the attempts made, asserting one row for each.

        The three mutating cases sit last in `MATRIX_CASES`: they need the shared incident still open
        and the shared execution still `executing`, which the earlier attempts leave untouched because a
        refusal writes no state at all.
        """
        made = []
        for attempt, reason, case, mutating in MATRIX_CASES:
            if mutating and not include_mutating:
                continue
            before = len(self.refusal_rows())
            with self.assertRaises((StateError, InvalidInventory), msg=f'{attempt}/{reason} was not refused'):
                self.attempt(case)()
            written = self.refusal_rows()[before:]
            self.assertEqual(len(written), 1, f'{attempt}/{reason} wrote {len(written)} rows')
            detail = json.loads(written[0]['detail'])
            self.assertEqual((detail['attempt'], detail['reason']), (attempt, reason),
                             f'{attempt}/{reason} was classified as {detail}')
            made.append((attempt, reason, case))
        return made

    # ------------------------------------------------------------------- what got written

    def raw_audit(self) -> list[dict]:
        """Every audit row, straight from the file, in write order, with no redaction in between."""
        columns = ('sequence', 'at', 'actor', 'operation', 'subject', 'detail')
        with closing(sqlite3.connect(self.store.path)) as db:
            return [dict(zip(columns, row)) for row in db.execute('SELECT * FROM audit ORDER BY sequence')]

    def refusal_rows(self) -> list[dict]:
        return [row for row in self.raw_audit() if row['operation'] == refusals.OPERATION]

    def audits(self, operation: str) -> list[dict]:
        return [row for row in self.store.records('audit', 100) if row['operation'] == operation]

    def lifecycle_state(self) -> dict:
        """Everything the refusal audit must not touch, in one comparable value.

        `audit` is excluded because it is what grows, and the tables `Store.records` has no bounded
        reader for are read from the file so a write into one of them cannot hide.
        """
        tables = ('events', 'incidents', 'conditions', 'evidence', 'actions', 'executions', 'outbox',
                  'notification_attempts', 'notification_control', 'notification_reservations',
                  'notification_suppressions', 'verification_bindings', 'verification_records')
        with closing(sqlite3.connect(self.store.path)) as db:
            rows = {name: db.execute(f'SELECT * FROM {name}').fetchall() for name in tables}
        return {'status': self.store.status(), 'tables': rows}

    def counters(self) -> dict:
        return self.store.refusal_audit_status()

    def action_status(self, action_id: str) -> str:
        return next(row['status'] for row in self.store.records('actions', 100) if row['id'] == action_id)


AUDITED_METHOD_NAMES = ('propose_action', 'decide', 'claim_action', 'execution_outcome')


class RefusalVocabularyTests(unittest.TestCase):
    """The map is closed and exact, and nobody has to guess what an unmapped sentence becomes."""

    def test_a_known_platform_sentence_maps_to_exactly_one_word(self):
        for sentence, word in refusals.SENTENCES.items():
            with self.subTest(sentence=sentence):
                self.assertEqual(refusals.reason_for(StateError(sentence)), word)

    def test_matching_is_the_whole_sentence_and_never_a_substring(self):
        """A caller cannot steer the classification by wrapping a platform sentence in its own text.

        `api.stable_code` deliberately tolerates substring matching for a transient error body; a
        durable record may not, because part of the text it matched on came off the wire.
        """
        wrapped = StateError(f'{SENTINEL} Action is not pending {SENTINEL}')
        self.assertEqual(refusals.reason_for(wrapped), refusals.UNCLASSIFIED)
        self.assertEqual(refusals.reason_for(ValueError('Action is not pending')), 'action-not-pending')

    def test_an_unknown_sentence_is_unclassified_rather_than_a_guess_or_an_echo(self):
        self.assertEqual(refusals.reason_for(StateError(f'a policy closure said {SENTINEL}')),
                         refusals.UNCLASSIFIED)

    def test_transport_words_and_state_words_are_disjoint(self):
        """One refusal, one row: the two layers cannot produce the same word, so neither can double-count.

        This is the whole duplicate-prevention mechanism, which is why it is a property of the
        vocabulary and not a per-request "already audited?" flag a future handler could forget.
        """
        self.assertEqual(set(refusals.SENTENCES.values()) & refusals.TRANSPORT_REASONS, set())
        self.assertEqual(refusals.TRANSPORT_REASONS, {refusals.SUMMARY_ONLY})
        self.assertEqual(refusals.ALL_REASONS, refusals.REASONS | refusals.TRANSPORT_REASONS)
        self.assertNotIn(refusals.UNCLASSIFIED, refusals.SENTENCES.values())

    def test_the_role_vocabulary_is_the_one_the_api_accepts(self):
        """`refusals.ROLES` and `create_app`'s credential check must not drift apart.

        If they did, a seventh role would either be refused by the API and never reach an audit row, or
        reach a row while the audit's own list called it unknown. Both are a lie in a security record,
        and neither would be noticed by a functional test.
        """
        with tempfile.TemporaryDirectory() as temp:
            store = Store(Path(temp) / 'state.db')
        for role in refusals.ROLES:
            create_app(store, [{'identity': 'x', 'role': role, 'token': 't' * 30}], {})
        with self.assertRaises(ValueError):
            create_app(store, [{'identity': 'x', 'role': 'superhuman', 'token': 't' * 30}], {})

    def test_rows_are_built_only_from_closed_vocabularies(self):
        """`refusal_row` answers None instead of improvising: an unknown attempt or reason writes nothing."""
        self.assertEqual(refusals.refusal_row('decide', 'action-not-pending', HUMAN, 'not-an-id'),
                         ('operator', refusals.UNBOUND,
                          {'attempt': 'decide', 'reason': 'action-not-pending', 'role': 'human'}))
        self.assertIsNone(refusals.refusal_row('callback', 'action-not-pending', HUMAN))
        self.assertIsNone(refusals.refusal_row('decide', 'intake-not-allowed', HUMAN))
        self.assertIsNone(refusals.refusal_row(None, 'action-not-pending', HUMAN))
        self.assertIsNone(refusals.refusal_row('decide', None, HUMAN))
        # `unclassified` is a legal reason — it is what a deployment's own policy closure gets — so the
        # row is built, and it names no more than that one word.
        self.assertEqual(refusals.refusal_row('decide', refusals.UNCLASSIFIED, HUMAN),
                         ('operator', refusals.UNBOUND,
                          {'attempt': 'decide', 'reason': refusals.UNCLASSIFIED, 'role': 'human'}))

    def test_a_non_string_attempt_or_reason_is_no_row_rather_than_a_new_exception(self):
        """The helper that decides what a refusal may say may not raise while deciding.

        `reason in ALL_REASONS` hashes its argument, so an unhashable reason (a `list`, a `dict`) used
        to escape `refusal_row` as `TypeError` — from the refusal path itself, ahead of its write
        guard, which is a second failure where a client was owed a denial. A closed vocabulary is
        consulted by identity, so the type test runs first and everything else is simply "not in the
        vocabulary", which is what `None` already means. This is not a promise about arbitrary objects:
        an input whose own `__eq__`/`__hash__` raises is out of the contract `refusal_row` states.
        """
        shapes = ([], ['action-not-pending'], {'reason': 'action-not-pending'}, {}, True, False, 7, 0,
                  3.5, b'action-not-pending', None, 'a-reason-nobody-declared')
        for reason in shapes:
            with self.subTest(reason=repr(reason)):
                self.assertIsNone(refusals.refusal_row('decide', reason, HUMAN, str(uuid.uuid4())))
        for attempt in ([], {'attempt': 'decide'}, True, 7, None, 'decide '):
            with self.subTest(attempt=repr(attempt)):
                self.assertIsNone(refusals.refusal_row(attempt, 'action-not-pending', HUMAN))
        # The pair the state layer actually produces still builds a row: nothing here narrowed a word.
        self.assertIsNotNone(refusals.refusal_row('decide', 'action-not-pending', HUMAN))

    def test_subject_and_identity_fields_refuse_what_they_cannot_bound(self):
        one_id = str(uuid.uuid4())
        self.assertEqual(refusals.subject_field(one_id), one_id)
        for value in ('', '  ', 'x' * 300, 'SELECT 1', 'a/b', 'line\nbreak', SENTINEL, None, 7, 0):
            with self.subTest(value=repr(value)):
                self.assertEqual(refusals.subject_field(value), refusals.UNBOUND)
        self.assertIsNone(refusals.attribution(Actor('bad identity with spaces', 'human')))
        self.assertIsNone(refusals.attribution(Actor('a' * 129, 'human')))
        self.assertEqual(refusals.attribution(Actor('a' * 128, 'human')), ('a' * 128, 'human'))

    def test_a_now_the_module_cannot_format_is_ignored_rather_than_stored(self):
        """`now=` is caller configuration; a value that is not an aware datetime must not become a stamp."""
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'state.db'
            store = Store(path)
            for value in ('yesterday', 1750000000, dt.datetime(2026, 9, 6, 12, 1), None):
                store.record_refusal('decide', HUMAN, 'action-not-pending', str(uuid.uuid4()), now=value)
            with closing(sqlite3.connect(path)) as db:
                stamps = [row[0] for row in db.execute('SELECT at FROM audit ORDER BY sequence')]
        self.assertEqual(len(stamps), 4)
        for stamp in stamps:
            self.assertIsNotNone(dt.datetime.fromisoformat(stamp).tzinfo)


class RefusalClassificationCoverageTests(unittest.TestCase):
    """No platform refusal sentence can enter the audited paths without a word of its own.

    The extraction is read-only `ast` over the source, not a hand-maintained list: the day somebody
    adds `raise StateError('New refusal')` to one of the four methods, this test is the review.
    """

    def source(self, relative):
        return ast.parse((ROOT / relative).read_text())

    def sentences(self):
        state = self.source('local_observe/platform/state.py')
        audited = literal_raises(state, set(AUDITED_METHOD_NAMES))
        gates = literal_raises(state, {'require', 'label', 'identifier'})
        policy = literal_raises(self.source('local_observe/platform/policy.py'), {'validate'})
        return audited, gates, policy

    def test_every_platform_sentence_on_the_audited_paths_has_a_word(self):
        """`unclassified` must stay unreachable from the platform's own text.

        It stays reachable for a deployment-supplied policy closure that raises sentences of its own —
        one fixed word, no echo — which is the honest limit of a whole-sentence map.
        """
        audited, gates, policy = self.sentences()
        self.assertTrue(audited, 'the four audited methods raised nothing literal; the source moved')
        self.assertTrue(gates, 'require/label/identifier raised nothing literal; the source moved')
        self.assertTrue(policy, 'policy.py raised nothing literal; the source moved')
        for sentence in sorted(audited | gates | policy):
            with self.subTest(sentence=sentence):
                self.assertIn(sentence, refusals.SENTENCES)
                self.assertNotEqual(refusals.reason_for(StateError(sentence)), refusals.UNCLASSIFIED)

    def test_every_declared_word_and_attempt_is_reachable_from_a_provable_refusal(self):
        """Both directions, so a renamed word cannot survive as dead vocabulary."""
        self.assertEqual({reason for _, reason, _, _ in MATRIX_CASES}, set(refusals.SENTENCES.values()))
        self.assertEqual({attempt for attempt, _, _, _ in MATRIX_CASES}, set(refusals.ATTEMPTS))

    def test_state_does_not_import_refusals_at_module_level(self):
        """The one import arrow is `refusals` -> `state`, so no load-time cycle exists.

        `refusals.py` reuses `state.label`/`state.identifier` at module level; if `state.py` ever
        imports this module at its top as well, the failure is an `ImportError` when the service starts.
        The precedent already in that file is how it imports `notification_safety` — from inside the
        function that needs it — and this pins the same shape.
        """
        for node in self.source('local_observe/platform/state.py').body:
            if isinstance(node, ast.ImportFrom):
                self.assertNotEqual(node.module, 'refusals',
                                    f'state.py imports refusals at module level on line {node.lineno}')
            if isinstance(node, ast.Import):
                self.assertFalse(any(alias.name.endswith('refusals') for alias in node.names),
                                 f'state.py imports refusals at module level on line {node.lineno}')

    def test_the_wrapper_covers_exactly_the_four_audited_methods(self):
        """The scope statement in `docs/units/refusal-audit.md` has to match the code, method by method."""
        store_class = next(node for node in self.source('local_observe/platform/state.py').body
                           if isinstance(node, ast.ClassDef) and node.name == 'Store')
        wrapped = sorted(node.name for node in store_class.body if isinstance(node, ast.FunctionDef)
                         and node.body and opens_refusal(node.body[0]))
        self.assertEqual(wrapped, sorted(AUDITED_METHOD_NAMES))

    def test_every_transaction_in_an_audited_method_sits_inside_the_wrapper(self):
        """The ordering guarantee is a nesting property, so it is pinned as one.

        If a `transaction()` call ever moves out of the wrapper — or the wrapper stops being the first
        statement, which is what puts the role gate and the validations inside it — the audit row can
        again be committed beside refused state or erase itself in the rollback. Either change fails
        here instead of in production.
        """
        store_class = next(node for node in self.source('local_observe/platform/state.py').body
                           if isinstance(node, ast.ClassDef) and node.name == 'Store')
        seen = 0
        for method in store_class.body:
            if not isinstance(method, ast.FunctionDef) or method.name not in AUDITED_METHOD_NAMES:
                continue
            seen += 1
            wrapper = method.body[0]
            self.assertTrue(opens_refusal(wrapper), f'{method.name} must open with self.refusal(...)')
            nested = [node for node in ast.walk(wrapper) if self_call(node, ('transaction',))]
            self.assertTrue(nested, f'{method.name} lost its transaction')
            outside = [node.lineno for node in ast.walk(method)
                       if self_call(node, ('transaction',)) and node not in nested]
            self.assertEqual(outside, [], f'{method.name} opens a transaction outside the wrapper '
                                          f'at lines {outside}')
        self.assertEqual(seen, len(AUDITED_METHOD_NAMES))

    def test_no_audit_row_is_written_from_inside_an_exception_handler(self):
        """`self.audit` is the connection-level writer: called from an `except`, it would run inside the
        transaction that is being discarded — the exact failure this card exists to close."""
        tree = self.source('local_observe/platform/state.py')
        offenders = [handler.lineno for handler in ast.walk(tree) if isinstance(handler, ast.ExceptHandler)
                     for node in ast.walk(handler) if self_call(node, ('audit',))]
        self.assertEqual(offenders, [], f'self.audit called from an except block at lines {offenders}')


class RefusalAuditStoreTests(unittest.TestCase, LifecycleFixture):
    """One row per refusal, written after the refused state is gone, and nothing else moved."""

    def setUp(self):
        self.build()

    def test_a_wrong_role_decision_leaves_one_row_and_the_same_refusal(self):
        with self.assertRaises(StateError) as caught:
            self.store.decide(self.approved_id, 'approved', AGENT, now=NOW)
        self.assertEqual(str(caught.exception), 'Actor is not authorised for this operation')
        rows = self.refusal_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row['actor'], row['subject'], row['at']),
                         (AGENT.identity, self.approved_id, utc_text(NOW)))
        self.assertEqual(json.loads(row['detail']),
                         {'attempt': 'decide', 'reason': 'actor-not-authorised', 'role': 'proposer'})
        self.assertEqual(self.counters()['written'], 1)
        self.assertEqual(self.action_status(self.approved_id), 'approved',
                         'the refusal did not move the approval it refused')

    def test_one_row_per_refusal_across_the_whole_taxonomy(self):
        """Every word in the map is provoked, and each arrival leaves exactly one row and no state."""
        made = self.run_matrix()
        rows = self.refusal_rows()
        self.assertEqual(len(made), len(MATRIX_CASES))
        self.assertEqual(len(rows), len(made))
        self.assertEqual({(json.loads(row['detail'])['attempt'], json.loads(row['detail'])['reason'])
                          for row in rows}, {(attempt, reason) for attempt, reason, _ in made})
        self.assertEqual({row['operation'] for row in self.raw_audit()} - {refusals.OPERATION},
                         {'event.intake', 'action.proposed', 'action.approved', 'execution.claimed',
                          'execution.succeeded'},
                         'the refusal audit wrote an operation word nobody declared here')
        status = self.counters()
        self.assertEqual((status['written'], status['dropped'], status['failed'], status['unauditable']),
                         (len(made), 0, 0, 0))

    def test_refusals_change_no_lifecycle_row_and_no_lifecycle_state(self):
        """The gap this card closed must not have opened another: the audit table is the only diff."""
        attempts = self.run_matrix(include_mutating=False)
        state = self.lifecycle_state()
        for attempt, reason, case in attempts:
            with self.subTest(attempt=attempt, reason=reason):
                with self.assertRaises((StateError, InvalidInventory)):
                    self.attempt(case)()
        after = self.lifecycle_state()
        self.assertEqual(after['tables'], state['tables'], 'a refusal wrote outside the audit table')
        self.assertEqual(after['status'], state['status'], 'a refusal moved Store.status()')
        self.assertEqual(len(self.refusal_rows()), 2 * len(attempts),
                         'the count below is what the audit table grew by, and nothing else')

    def test_the_refused_partial_state_is_gone_before_the_audit_row_is_committed(self):
        """The behavioural half of the ordering guarantee.

        A sentinel is written inside a transaction that then raises the platform's own sentence: the
        refusal row must survive it and the sentinel must not. The structural half is
        `test_every_transaction_in_an_audited_method_sits_inside_the_wrapper` above, which is what keeps
        a later refactor from moving a `transaction()` call out of the wrapper and quietly turning this
        back into the gap the card was opened for.
        """
        before = self.lifecycle_state()
        with self.assertRaises(StateError):
            with self.store.refusal('decide', HUMAN, self.approved_id, now=NOW):
                with self.store.transaction() as connection:
                    connection.execute('INSERT INTO actions(id,requester,retry_key,fingerprint,payload,'
                                       'status,created_at,expires_at,decided_by) VALUES (?,?,?,?,?,?,?,?,?)',
                                       ('sentinel-action', 'x', 'x', 'x', '{}', 'pending',
                                        utc_text(NOW), utc_text(NOW), None))
                    raise StateError('Action is not pending')
        self.assertNotIn('sentinel-action', {row['id'] for row in self.store.records('actions', 100)})
        rows = self.refusal_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['detail'])['reason'], 'action-not-pending')
        self.assertEqual(self.lifecycle_state()['tables']['actions'],
                         before['tables']['actions'], 'the refused write survived the rollback')

    def test_a_canonical_uuid_subject_is_stored_and_anything_else_is_the_sentinel(self):
        """The subject points at a row, or says it cannot; it never repeats caller text."""
        with self.assertRaises(StateError):
            self.store.decide(self.approved_id, 'approved', AGENT, now=NOW)
        self.assertEqual(self.refusal_rows()[-1]['subject'], self.approved_id)
        for value in ('', '  ', 'x' * 300, 'SELECT 1', 'line\nbreak', SENTINEL, None, 7):
            with self.subTest(value=repr(value)):
                self.store.record_refusal('decide', HUMAN, 'action-not-pending', value, now=NOW)
                self.assertEqual(self.refusal_rows()[-1]['subject'], refusals.UNBOUND)

    def test_an_unauditable_identity_writes_no_row_counts_one_and_still_refuses(self):
        """No fabricated actor, ever: an identity the module cannot validate leaves no row at all.

        The positive control at the end is what makes this a test rather than a restatement of "nothing
        is ever written": the one spelling the platform accepts does produce a granted transition.
        """
        class NotAnActor:
            identity, role = 'operator', 'human'

        rejected = (None, 'human', {'identity': 'operator', 'role': 'human'}, NotAnActor(),
                    Actor(f'{SENTINEL}\n{"k" * 200}', 'proposer'), Actor(None, 'proposer'),
                    Actor('', 'proposer'), Actor('operator', 'superhuman'), Actor('operator', 'Human'),
                    Actor('operator', 'human '), Actor('operator', ''))
        for actor in rejected:
            with self.subTest(actor=repr(actor)):
                with self.assertRaises(StateError) as caught:
                    self.store.decide(self.approved_id, 'approved', actor, now=NOW)
                self.assertIn('not authorised', str(caught.exception))
        self.assertEqual(self.refusal_rows(), [], 'a row naming an unverifiable identity was written')
        status = self.counters()
        self.assertEqual((status['unauditable'], status['written']), (len(rejected), 0))
        self.assertEqual(self.action_status(self.approved_id), 'approved',
                         'an unverifiable caller still could not move the action')
        control = self.proposed(retry_key='unauditable-control')
        self.assertEqual(self.store.decide(control, 'approved', HUMAN, now=NOW), {'status': 'approved'})
        self.assertEqual(self.counters()['written'], 0, 'a granted transition is not a refusal')

    def test_a_reason_outside_the_string_vocabulary_costs_a_count_and_no_sql(self):
        """The store half of that contract: no exception, no connection, no row, one count per call.

        `record_refusal` is reached with a non-string only by a caller that broke its own contract (the
        platform's own path passes `reason_for(...)`, always a `str`), which is exactly why the count has
        to be `unauditable` rather than a `TypeError` climbing out of the refusal the caller is owed. The
        connection is wrapped, not replaced, so "no SQL" is a measured call count instead of an absent row.
        """
        shapes = ([], {'reason': 'action-not-pending'}, True, 7, None, 'a-reason-nobody-declared')
        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            for reason in shapes:
                with self.subTest(reason=repr(reason)):
                    self.store.record_refusal('decide', HUMAN, reason, self.approved_id)
        self.assertEqual(connect.call_count, 0, 'an unauditable refusal reached the database anyway')
        self.assertEqual(self.counters()['unauditable'], len(shapes))
        self.assertEqual((self.counters()['written'], self.counters()['dropped'],
                          self.counters()['failed']), (0, 0, 0))
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.action_status(self.approved_id), 'approved',
                         'accounting for a refusal is not a lifecycle write')

    def test_a_direct_store_actor_is_attribution_and_not_authentication(self):
        """What the row can and cannot prove, stated by the test that has to hold it.

        At the HTTP edge the identity is decided by a bearer token. Here the platform only records the
        `Actor` object its caller was handed, so the row says *who this process believed was calling*,
        not *who was proved to be calling*. The test builds a perfect-looking `Actor` in-process and
        watches the name land in the audit column: that is the boundary, documented as a fact rather
        than as a claim about a security control.
        """
        impersonator = Actor(HUMAN.identity, 'proposer')
        with self.assertRaises(StateError):
            self.store.decide(self.approved_id, 'approved', impersonator, now=NOW)
        row = self.refusal_rows()[-1]
        self.assertEqual((row['actor'], json.loads(row['detail'])['role']), (HUMAN.identity, 'proposer'))

    def test_an_unknown_custom_policy_refusal_is_unclassified_and_echoes_nothing(self):
        """A deployment closure that raises its own sentence gets one fixed word, and no copy of it."""
        def custom(policy_request):
            raise StateError(f'private allowlist vocabulary {SENTINEL}')

        with self.assertRaises(StateError) as caught:
            self.store.propose_action(self.request_document('custom-policy'), AGENT, custom, now=NOW)
        self.assertIn(SENTINEL, str(caught.exception))
        rows = self.refusal_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['detail'])['reason'], refusals.UNCLASSIFIED)
        self.assertNotIn(SENTINEL, json.dumps(rows))

    def test_a_bug_inside_the_policy_is_not_a_refusal_and_writes_no_row(self):
        """`KeyError` is a server bug: it stays a 500, it stays logged as one, and it is not a denial."""
        def broken(policy_request):
            raise KeyError('action-definition-table')

        with self.assertRaises(KeyError):
            self.store.propose_action(self.request_document('broken-policy'), AGENT, broken, now=NOW)
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.counters()['written'], 0)

    def test_the_refusal_row_text_is_bounded_in_width(self):
        """The worst legal row, measured in the database rather than estimated in a comment."""
        widest = Actor('w' * 128, 'human')
        longest_reason = max(refusals.SENTENCES.values(), key=len)
        self.store.record_refusal('outcome', widest, longest_reason, str(uuid.uuid4()), now=NOW)
        row = self.refusal_rows()[-1]
        self.assertEqual(json.loads(row['detail'])['reason'], longest_reason)
        self.assertLessEqual(refusals.row_text_width(row), refusals.ROW_TEXT_LIMIT)

    def test_no_caller_supplied_text_reaches_any_audit_column(self):
        """Plant the sentinel in every place a caller can put text; it must reach no row, in any column.

        The identity positions use a spelling `state.label` refuses, and that is deliberate: a
        label-valid string handed to `Store` directly *is* the identity the platform records, and a
        test that demanded its absence would be asking the audit to falsify who called. At the HTTP
        edge no caller-supplied text reaches an identity at all — see the bearer test below.
        """
        unverifiable = f'{SENTINEL}\n{"k" * 200}'
        attempts = (lambda: self.store.propose_action(
            {'retry_key': SENTINEL, 'incident_id': SENTINEL, 'action': SENTINEL, 'version': '1',
             'targets': [SENTINEL], 'parameters': {SENTINEL: SENTINEL}, 'evidence': [SENTINEL],
             'expires_at': SENTINEL}, AGENT, self.policy, now=NOW),
            lambda: self.store.decide(SENTINEL, SENTINEL, HUMAN, now=NOW),
            lambda: self.store.claim_action(SENTINEL, Actor(unverifiable, 'executor'), self.policy,
                                            now=NOW),
            lambda: self.store.execution_outcome(SENTINEL, SENTINEL, Actor(unverifiable, 'executor'),
                                                 SENTINEL, now=NOW),
            lambda: self.store.decide(self.approved_id, 'approved', Actor(unverifiable, 'proposer'),
                                      now=NOW))
        for attempt in attempts:
            with self.assertRaises(StateError):
                attempt()
        for row in self.raw_audit():
            self.assertNotIn(SENTINEL, json.dumps(row), f'a planted value reached row {row["sequence"]}')

    def test_the_rows_are_durable_across_a_reopen_while_counters_reset(self):
        with self.assertRaises(StateError):
            self.store.decide(self.approved_id, 'approved', AGENT, now=NOW)
        written = [(row['actor'], row['subject'], row['detail']) for row in self.refusal_rows()]
        self.assertEqual(self.counters()['written'], 1)

        reopened = Store(self.store.path)
        rows = [(row['actor'], row['subject'], row['detail']) for row in reopened.records('audit', 100)
                if row['operation'] == refusals.OPERATION]
        self.assertEqual(rows, written)
        self.assertEqual(reopened.refusal_audit_status()['written'], 0,
                         'counters are per-process; a reopened store must not claim another process')

    def test_accepted_decisions_denied_expired_and_idempotent_repeats_write_no_refusal_row(self):
        """The controls: nothing the platform granted may read as a refusal.

        A human who proposed may approve (the firewall is a role firewall, not a two-human rule); a
        `denied` decision is a decision; an approval that aged out answers `expired`; and an idempotent
        repeat of a terminal outcome raises nothing, so it audits nothing.
        """
        self_approval = self.proposed(retry_key='control-self', actor=HUMAN)
        self.assertEqual(self.store.decide(self_approval, 'approved', HUMAN, now=NOW), {'status': 'approved'})
        denied = self.proposed(retry_key='control-denied')
        self.assertEqual(self.store.decide(denied, 'denied', HUMAN, now=NOW), {'status': 'denied'})
        aged = self.proposed(retry_key='control-aged')
        self.assertEqual(self.store.decide(aged, 'approved', HUMAN, now=LATER), {'status': 'expired'})
        action_id, claim = self.dispatched(retry_key='control-claimed')
        args = (claim['execution_id'], 'succeeded', RUNNER, claim['runner_token'])
        self.assertEqual(self.store.execution_outcome(*args, now=NOW), {'status': 'succeeded'})
        self.assertEqual(self.store.execution_outcome(*args, now=NOW), {'status': 'succeeded'})
        approved_but_aged = self.approved(retry_key='control-claim-aged')
        self.assertEqual(self.store.claim_action(approved_but_aged, RUNNER, self.policy, now=LATER),
                         {'status': 'expired'})
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.counters()['written'], 0)
        self.assertEqual([row['operation'] for row in self.audits('action.denied')], ['action.denied'])
        self.assertEqual([self.action_status(row) for row in (self_approval, denied, aged, action_id)],
                         ['approved', 'denied', 'expired', 'succeeded'])
        self.assertEqual(self.action_status(approved_but_aged), 'expired')

    def test_a_refused_call_is_not_logged_while_it_is_written(self):
        """No per-refusal log line: the durable row is the record, and a line would double the surface."""
        with self.assertNoLogs(STATE_LOGGER, level='INFO'), self.assertNoLogs(API_LOGGER, level='INFO'):
            for _ in range(10):
                with self.assertRaises(StateError):
                    self.store.decide(self.approved_id, 'approved', AGENT, now=NOW)
        self.assertEqual(self.counters()['written'], 10)

    def test_concurrent_refusals_each_land_once_and_no_caller_sees_a_lock_error(self):
        """The audit row goes through the same single-writer path every other mutation uses."""
        failures = []

        def refuse():
            try:
                with self.assertRaises(StateError):
                    self.store.decide(self.approved_id, 'approved', AGENT, now=NOW)
            except Exception as exc:  # broad on purpose: the assertion is that this list stays empty
                failures.append(exc)

        threads = [threading.Thread(target=refuse) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(len(self.refusal_rows()), 8)
        self.assertEqual(self.counters()['written'], 8)

    def test_the_refusal_counters_live_beside_status_and_not_inside_it(self):
        """`Store.status()` is not widened: its exact shape is pinned elsewhere in the suite."""
        self.assertEqual(sorted(self.store.status()),
                         ['actions', 'incidents', 'notifications', 'schema_version'])
        self.assertEqual(sorted(self.counters()),
                         sorted([*refusals.COUNTERS, 'saturated', 'capacity', 'refill_tokens_per_second',
                                 'tokens_available', 'scope', 'resets_on_restart']))
        self.assertNotIn(refusals.OPERATION, json.dumps(self.store.status()))


class RefusalBudgetTests(unittest.TestCase, LifecycleFixture):
    """64 in a burst, one a second after that, and every one of those facts visible to a reader."""

    def setUp(self):
        self.build()
        self.action_id = self.approved(retry_key='budget')

    def refused(self, action_id=None):
        """One refused decision; True when its row was written, False when the budget said no."""
        before = self.counters()['written']
        with self.assertRaises(StateError):
            self.store.decide(action_id or self.action_id, 'approved', AGENT, now=NOW)
        return self.counters()['written'] > before

    def test_a_burst_of_sixty_four_is_written_and_the_sixty_fifth_is_dropped(self):
        written = sum(self.refused() for _ in range(64))
        self.assertEqual(written, refusals.CAPACITY)
        self.assertEqual(self.counters()['dropped'], 0)
        self.assertFalse(self.refused(), 'the refusal after the burst should have had no token')
        self.assertEqual((self.counters()['written'], self.counters()['dropped']), (64, 1))
        self.assertEqual(len(self.refusal_rows()), 64)

    def test_the_bucket_refills_from_the_monotonic_clock_and_not_from_wall_time(self):
        for _ in range(64):
            self.refused()
        self.assertFalse(self.refused())
        self.clock.advance(0.4)
        self.assertFalse(self.refused(), '0.4 seconds must not buy a token')
        self.clock.advance(0.6)
        self.assertTrue(self.refused(), '1.0 seconds must buy exactly one token')
        self.assertFalse(self.refused())
        self.clock.advance(5)
        self.assertEqual(sum(self.refused() for _ in range(5)), 5, 'refill is one token per second')
        self.clock.advance(10_000)
        self.assertEqual(self.counters()['tokens_available'], refusals.CAPACITY,
                         'refilled tokens do not accumulate past capacity')

    def test_the_callers_now_argument_never_moves_the_rate_clock(self):
        """A caller may stamp a row with any instant; it may not decide how fast the audit fills up.

        Every refusal below passes a `now` a thousand years out while the bucket's monotonic clock is
        frozen: were the budget ever to read the caller's timestamp, this would be an unbounded write
        budget handed to whoever already holds a credential.
        """
        far = NOW + dt.timedelta(days=365_000)
        for _ in range(64):
            with self.assertRaises(StateError):
                self.store.decide(self.action_id, 'approved', AGENT, now=far)
        self.assertFalse(self.refused())
        self.assertEqual((self.counters()['written'], self.counters()['dropped']), (64, 1))

    def test_a_restart_resets_the_counters_and_keeps_the_rows(self):
        for _ in range(3):
            self.refused()
        rows = len(self.refusal_rows())
        reopened = Store(self.store.path)
        status = reopened.refusal_audit_status()
        self.assertEqual(status['written'], 0)
        self.assertEqual(status['scope'], refusals.SCOPE)
        self.assertTrue(status['resets_on_restart'])
        self.assertEqual(len([row for row in reopened.records('audit', 100)
                              if row['operation'] == refusals.OPERATION]), rows)
        self.assertEqual(self.counters()['written'], 3, 'the old process keeps its own tally')

    def test_a_failing_write_still_spends_quota_so_a_broken_database_is_not_hammered(self):
        """Quota is spent by the attempt: a refusal whose write failed is counted, not retried."""
        opened = []

        def locked(*args, **kwargs):
            opened.append(1)
            raise sqlite3.OperationalError('database is locked')

        with patch('local_observe.platform.state.sqlite3.connect', side_effect=locked):
            for _ in range(70):
                self.refused()
        status = self.counters()
        self.assertEqual((status['written'], status['failed'], status['dropped']), (0, 64, 6))
        self.assertEqual(len(opened), refusals.CAPACITY, 'the budget stopped asking before the 65th write')

    def test_the_original_denial_survives_a_failed_audit_write_on_insert(self):
        """An audit failure may not upgrade, replace or echo the refusal it was trying to record."""
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute(f"CREATE TRIGGER audit_refuse BEFORE INSERT ON audit BEGIN "
                       f"SELECT RAISE(ABORT,'{SENTINEL}'); END")
        with self.assertRaises(StateError) as caught, self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
            self.store.decide(self.action_id, 'approved', AGENT, now=NOW)
        self.assertEqual(str(caught.exception), 'Actor is not authorised for this operation')
        self.assertEqual(self.action_status(self.action_id), 'approved', 'the denial changed state')
        self.assertEqual((self.counters()['written'], self.counters()['failed']), (0, 1))
        record = logs.records[0]
        self.assertEqual(record.levelname, 'WARNING')
        self.assertEqual(record.getMessage(), 'Refusal audit write failed')
        self.assertEqual(record.error_class, 'IntegrityError')
        self.assertNotIn(SENTINEL, str(logs.output), 'the driver message reached the log')
        self.assertEqual(self.refusal_rows(), [])

    def test_the_original_denial_survives_a_failed_audit_write_on_connect(self):
        """Same assertion, other failure point: opening the connection rather than inserting the row."""
        with patch('local_observe.platform.state.sqlite3.connect',
                   side_effect=sqlite3.OperationalError(f'{SENTINEL}: cannot open')):
            with self.assertRaises(StateError) as caught, self.assertLogs(STATE_LOGGER,
                                                                         level='WARNING') as logs:
                self.store.decide(self.action_id, 'approved', AGENT, now=NOW)
        self.assertEqual(str(caught.exception), 'Actor is not authorised for this operation')
        self.assertEqual(self.counters()['failed'], 1)
        self.assertNotIn(SENTINEL, str(logs.output))

    def test_audit_failures_are_logged_once_every_sixty_seconds_not_once_a_refusal(self):
        """Bounded log volume is part of the flood design: the counter is the count, the line is the signal."""
        with patch('local_observe.platform.state.sqlite3.connect',
                   side_effect=sqlite3.OperationalError('database is locked')):
            with self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
                for _ in range(20):
                    self.refused()
            self.assertEqual([record.getMessage() for record in logs.records], ['Refusal audit write failed'])
            self.clock.set_to(59.9)
            with self.assertNoLogs(STATE_LOGGER, level='WARNING'):
                self.refused()
            self.clock.set_to(60.0)
            with self.assertLogs(STATE_LOGGER, level='WARNING') as second:
                self.refused()
            self.assertEqual(len(second.records), 1, 'sixty seconds of real elapsed time is worth one more line')
            with self.assertNoLogs(STATE_LOGGER, level='WARNING'):
                self.refused()
        self.assertEqual(self.counters()['failed'], 23)

    def test_the_failure_log_is_spaced_by_elapsed_time_and_not_by_a_minute_bucket(self):
        """The throttle measures from the line it printed, so a minute boundary buys it nothing.

        The first failure here lands at 59.9 on the fake monotonic clock, 0.1 s before an aligned bucket
        would turn over: the throttle that sampled `clock // 60` printed a second line at 60.0, and one
        line per minute of *name* was never one line per minute of *waiting*. No sleeping, and no sleep
        in the assertion either — the clock is the test's.
        """
        audit = refusals.RefusalAudit(clock=FakeMonotonic(59.9))
        self.assertTrue(audit.should_log_failure(), 'the first failure is worth the line')
        audit._clock.set_to(60.0)
        self.assertFalse(audit.should_log_failure(),
                         'crossing a minute boundary 0.1 s later is not a new interval')
        audit._clock.set_to(119.89999)
        self.assertFalse(audit.should_log_failure(), '59.9 s after the line that printed is not either')
        audit._clock.set_to(119.9)
        self.assertTrue(audit.should_log_failure(), 'the line is owed 60 s after the one that printed')
        self.assertFalse(audit.should_log_failure(), 'and the next failure in the same instant is not')

    def test_racing_failure_logs_cannot_overtake_the_clock_they_are_measured_against(self):
        """Every grant is >=60 s after the previous grant's own instant, whatever the interleaving.

        The clock is read inside the accounting lock for this reason: sample it outside, and two threads
        can each hold a sample, one stale, and both conclude the interval elapsed. A stepping source makes
        that visible (a stale sample can name an instant *earlier* than the one just recorded), which a
        frozen clock never shows.
        """
        audit = refusals.RefusalAudit(clock=SteppingMonotonic(step=7.0))
        threads, guard, granted = 8, threading.Lock(), []
        barrier = threading.Barrier(threads)

        def race():
            barrier.wait()
            mine = []
            for _ in range(25):
                if audit.should_log_failure():
                    mine.append(audit._last_failure_logged_at)
            with guard:
                granted.extend(mine)

        running = [threading.Thread(target=race) for _ in range(threads)]
        for thread in running:
            thread.start()
        for thread in running:
            thread.join()
        ordered = sorted(granted)
        self.assertGreaterEqual(len(ordered), 2, 'the throttle never fired twice over 200 reads')
        self.assertLessEqual(len(ordered), 1 + (threads * 25) // 9, 'the failure log is not unbounded')
        gaps = [later - earlier for earlier, later in zip(ordered, ordered[1:])]
        self.assertTrue(all(gap >= refusals.FAILURE_LOG_INTERVAL_SECONDS for gap in gaps),
                        f'two lines landed {min(gaps)} s apart, under the 60 s bound')

    def test_a_flood_of_distinct_subjects_adds_no_keys_to_the_accounting(self):
        """The bound is on rate, not on identity: nothing here may be cached per subject or per actor."""
        def shape():
            audit = self.store._refusal_audit
            return (sorted(vars(audit)),
                    {key: len(value) for key, value in vars(audit).items()
                     if isinstance(value, (dict, list, set, tuple))})

        before = shape()
        for _ in range(100):
            self.refused(str(uuid.uuid4()))
        self.assertEqual(shape(), before, 'per-subject state appeared in the write budget')
        self.assertEqual((self.counters()['written'], self.counters()['dropped']),
                         (refusals.CAPACITY, 100 - refusals.CAPACITY))

    def test_counters_saturate_and_say_so_instead_of_wrapping(self):
        """A counter that cannot overflow is a counter that reports its own ceiling."""
        audit = refusals.RefusalAudit(clock=FakeMonotonic())
        audit._counters['written'] = refusals.COUNTER_LIMIT
        for _ in range(5):
            audit.count('written')
            audit.count('dropped')
        status = audit.status()
        self.assertEqual(status['written'], refusals.COUNTER_LIMIT)
        self.assertEqual(status['saturated'], ['written'])
        self.assertEqual(status['dropped'], 5)

    def test_a_concurrent_burst_cannot_spend_more_tokens_than_the_bucket_holds(self):
        """8 threads x 20 attempts on a frozen clock: exactly 64 successes, whatever the interleaving."""
        audit = refusals.RefusalAudit(clock=FakeMonotonic())
        barrier = threading.Barrier(8)
        taken = []
        guard = threading.Lock()

        def spend():
            barrier.wait()
            mine = sum(1 for _ in range(20) if audit.reserve())
            with guard:
                taken.append(mine)

        threads = [threading.Thread(target=spend) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(taken), refusals.CAPACITY)
        self.assertEqual(audit.status()['tokens_available'], 0)
        self.assertEqual(audit.status()['capacity'], refusals.CAPACITY)
        self.assertEqual(audit.status()['refill_tokens_per_second'], refusals.REFILL_TOKENS_PER_SECOND)


class RefusalAuditApiTests(unittest.TestCase, LifecycleFixture):
    """The edge adds one row of its own, adds none twice, and writes none for a stranger."""

    def setUp(self):
        self.build()
        self.action_id = self.approved(retry_key='api')

    def app(self, policy=None):
        return create_app(self.store, CREDENTIALS, self.policy if policy is None else policy)

    def post(self, path, body, identity=None, headers=None, raw=None):
        payload = raw if raw is not None else (body if isinstance(body, bytes)
                                               else json.dumps(body).encode())
        return asyncio.run(request(self.app(), 'POST', path, payload,
                                   headers if headers is not None else bearer(identity)))

    def get(self, path, identity='reader-1'):
        return asyncio.run(request(self.app(), 'GET', path, b'', bearer(identity)))

    def test_a_summary_credential_is_audited_on_exactly_the_write_routes_it_may_not_use(self):
        """One durable row per audited route, and the 403 body and status are the ones it always sent."""
        expected = {'/v1/actions': 'propose', '/v1/actions/decision': 'decide',
                    '/v1/actions/claim': 'claim', '/v1/executions/outcome': 'outcome'}
        for path in expected:
            with self.subTest(path=path):
                status, body = self.post(path, {'anything': SENTINEL}, SUMMARY.identity)
                self.assertEqual((status, body), (403, {'error': 'summary_only'}))
        rows = self.refusal_rows()
        self.assertEqual(len(rows), len(expected))
        for row in rows:
            detail = json.loads(row['detail'])
            self.assertEqual((row['actor'], row['subject'], detail['reason'], detail['role']),
                             (SUMMARY.identity, refusals.UNBOUND, refusals.SUMMARY_ONLY, 'summary'))
        self.assertEqual({json.loads(row['detail'])['attempt'] for row in rows},
                         set(expected.values()))
        self.assertEqual(self.counters()['written'], len(expected))

    def test_a_summary_refusal_on_an_unaudited_route_stays_write_free(self):
        """`/v1/events`, the notification routes and the callback route are not action attempts."""
        for path in ('/v1/events', '/v1/notifications/retry', '/v1/notifications/reset-safety',
                     '/v1/callbacks/primary'):
            with self.subTest(path=path):
                status, body = self.post(path, {'anything': SENTINEL}, SUMMARY.identity)
                self.assertEqual((status, body), (403, {'error': 'summary_only'}))
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.counters()['written'], 0)

    def test_the_summary_gate_answers_a_refusal_before_the_body_is_read(self):
        """The role gate precedes the parser: unusable bytes from a `summary` token are an audited 403.

        This is the boundary the docs had been overstating in both directions. A malformed, oversized or
        wrongly shaped body stays write-free *when one of those gates is what answers* — but a `summary`
        credential is refused before the first `receive()`, so the same bytes are a summary-role write
        denial with its one budgeted row, not a 400 or a 413 with none. Three mechanisms, because "no row
        appeared" alone would also be satisfied by a request whose body nobody offered:

        * the unusable bytes are supplied and `receive()` is counted — the count stays zero;
        * the same four routes run against a `receive()` that raises, and still answer 403 with a row;
        * the identical bytes from a `human` credential *are* read and stay write-free, so the counter
          and those gates are shown to be alive inside the same test.
        """
        routes = {'/v1/actions': 'propose', '/v1/actions/decision': 'decide',
                  '/v1/actions/claim': 'claim', '/v1/executions/outcome': 'outcome'}
        unusable = (('malformed json', b'{broken', 400),
                    ('oversized body', b'[' + SENTINEL.encode() + b']' + b' ' * 70_000, 413),
                    ('shape outside the route', b'{"anything": "' + SENTINEL.encode() + b'"}', 404))
        for name, raw, human_status in unusable:
            for path, attempt in routes.items():
                with self.subTest(body=name, path=path):
                    status, payload, reads = asyncio.run(request_counting_reads(
                        self.app(), 'POST', path, raw, bearer(SUMMARY.identity)))
                    self.assertEqual((status, payload), (403, {'error': 'summary_only'}))
                    self.assertNotEqual(status, human_status,
                                        'the summary answer must not be the one those bytes earn for '
                                        'a role that reaches the parser')
                    self.assertEqual(reads, 0, f'the summary gate awaited a chunk for {name}')
                    row = self.refusal_rows()[-1]
                    self.assertEqual(json.loads(row['detail']),
                                     {'attempt': attempt, 'reason': refusals.SUMMARY_ONLY, 'role': 'summary'})
                    self.assertEqual((row['actor'], row['subject']),
                                     (SUMMARY.identity, refusals.UNBOUND))
        self.assertEqual(len(self.refusal_rows()), len(unusable) * len(routes))
        self.assertEqual(self.counters()['written'], len(unusable) * len(routes))
        for name, raw, human_status in unusable:
            with self.subTest(control=name):
                status, payload, reads = asyncio.run(request_counting_reads(
                    self.app(), 'POST', '/v1/actions/decision', raw, bearer('operator')))
                self.assertEqual((status, payload['error']), (human_status, payload['error']))
                self.assertGreater(reads, 0, f'the {name} control never read a body either')
        self.assertEqual(len(self.refusal_rows()), len(unusable) * len(routes),
                         'a parser, size or shape gate grew a row')
        self.assertNotIn(SENTINEL, json.dumps(self.raw_audit()))
        for path, attempt in routes.items():
            with self.subTest(tripwire=path):
                status, payload = asyncio.run(request_forbidding_body(
                    self.app(), 'POST', path, bearer(SUMMARY.identity)))
                self.assertEqual((status, payload), (403, {'error': 'summary_only'}))
                self.assertEqual(json.loads(self.refusal_rows()[-1]['detail']),
                                 {'attempt': attempt, 'reason': refusals.SUMMARY_ONLY, 'role': 'summary'},
                                 'a body nobody was offered still changed what the row claimed')
        self.assertEqual(len(self.refusal_rows()), (len(unusable) + 1) * len(routes))

    def test_an_exhausted_budget_still_refuses_at_the_edge_and_counts_what_it_did_not_write(self):
        """The transport writer obeys the bucket it was handed: 64 rows, then 403 with `dropped` growing.

        `RefusalBudgetTests` pins the bucket and the `Store` behind it; this pins the extra writer this
        edge added, because a route that audited around its own budget would be the flood with a new
        door. The monotonic clock is the fixture's and never moves here, so no token is ever refunded
        and nothing sleeps.
        """
        app = self.app()
        for _ in range(refusals.CAPACITY):
            status, payload = asyncio.run(request(app, 'POST', '/v1/actions/claim',
                                                  json.dumps({'anything': SENTINEL}).encode(),
                                                  bearer(SUMMARY.identity)))
            self.assertEqual((status, payload), (403, {'error': 'summary_only'}))
        self.assertEqual((self.counters()['written'], self.counters()['dropped']),
                         (refusals.CAPACITY, 0))
        self.assertEqual(len(self.refusal_rows()), refusals.CAPACITY)
        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            for _ in range(6):
                status, payload = asyncio.run(request(app, 'POST', '/v1/actions/claim',
                                                      json.dumps({'anything': SENTINEL}).encode(),
                                                      bearer(SUMMARY.identity)))
                self.assertEqual((status, payload), (403, {'error': 'summary_only'}),
                                 'an empty budget must not become a 500 or an acceptance')
            self.assertEqual(connect.call_count, 0, 'an over-quota refusal opened the database anyway')
        status, runtime = self.get('/v1/runtime')
        self.assertEqual((runtime['refusal_audit']['written'], runtime['refusal_audit']['dropped'],
                          runtime['refusal_audit']['tokens_available']), (refusals.CAPACITY, 6, 0))
        self.assertEqual(len(self.refusal_rows()), refusals.CAPACITY,
                         'the audit kept growing after the bucket emptied')

    def test_a_failed_summary_audit_write_keeps_the_early_403_and_one_safe_line(self):
        """Both audit failure points, at the transport edge: unchanged 403, `failed`, bounded log.

        The `Store` cases prove the same for a lifecycle method; the summary branch is the one write this
        card added to the handler itself, and an audit failure there must not become a 500, a retry, a
        traceback, a driver message or a body read. The last two halves also show the log throttle is the
        process's, not one caller's: the next line is owed 60 s of elapsed time, not a fresh route.
        """
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute('CREATE TRIGGER audit_refuse BEFORE INSERT ON audit BEGIN '
                       f"SELECT RAISE(ABORT,'{SENTINEL}'); END")
        with self.assertLogs(STATE_LOGGER, level='WARNING') as logs:
            status, payload, reads = asyncio.run(request_counting_reads(
                self.app(), 'POST', '/v1/actions/decision', b'{broken', bearer(SUMMARY.identity)))
        self.assertEqual((status, payload), (403, {'error': 'summary_only'}))
        self.assertEqual(reads, 0, 'a failing audit reached for the body on the way out')
        self.assertEqual((self.counters()['written'], self.counters()['failed']), (0, 1))
        self.assertEqual(self.refusal_rows(), [])
        record = logs.records[0]
        self.assertEqual((record.levelname, record.getMessage(), record.error_class),
                         ('WARNING', 'Refusal audit write failed', 'IntegrityError'))
        self.assertEqual(len(logs.records), 1)
        self.assertNotIn(SENTINEL, str(logs.output), 'the driver message reached the log')

        self.clock.set_to(refusals.FAILURE_LOG_INTERVAL_SECONDS)
        with patch('local_observe.platform.state.sqlite3.connect',
                   side_effect=sqlite3.OperationalError(f'{SENTINEL}: cannot open')):
            with self.assertLogs(STATE_LOGGER, level='WARNING') as second:
                status, payload = asyncio.run(request(self.app(), 'POST', '/v1/executions/outcome',
                                                      b'{"execution_id": "not-a-uuid"}',
                                                      bearer(SUMMARY.identity)))
        self.assertEqual((status, payload), (403, {'error': 'summary_only'}))
        self.assertEqual(self.counters()['failed'], 2)
        self.assertEqual([record.error_class for record in second.records], ['OperationalError'])
        self.assertNotIn(SENTINEL, str(second.output))
        self.assertEqual(self.refusal_rows(), [])

        with patch('local_observe.platform.state.sqlite3.connect',
                   side_effect=sqlite3.OperationalError('database is locked')):
            with self.assertNoLogs(STATE_LOGGER, level='WARNING'):
                status, payload = asyncio.run(request(self.app(), 'POST', '/v1/actions', b'{}',
                                                      bearer(SUMMARY.identity)))
        self.assertEqual((status, payload), (403, {'error': 'summary_only'}))
        self.assertEqual(self.counters()['failed'], 3, 'an unlogged failure went uncounted')

    def test_a_state_layer_refusal_leaves_exactly_one_row_not_two(self):
        """The API does not re-audit a `StateError`: one refusal, one row, whatever the layer count."""
        cases = [('/v1/actions/decision', {'action_id': str(uuid.uuid4()), 'decision': 'approved'},
                  'reader-1', 'not_authorised'),
                 ('/v1/actions/decision', {'action_id': str(uuid.uuid4()), 'decision': 'approved'},
                  'operator', 'conflict'),
                 ('/v1/actions/claim', {'action_id': str(uuid.uuid4())}, 'runner-1', 'conflict'),
                 ('/v1/executions/outcome', {'execution_id': str(uuid.uuid4()), 'outcome': 'succeeded'},
                  'runner-1', 'conflict'),
                 ('/v1/actions', {'retry_key': 'api-refused', 'incident_id': str(uuid.uuid4()),
                                  'action': 'inspect', 'version': '1', 'targets': [], 'parameters': {},
                                  'evidence': [], 'expires_at': utc_text(dt.datetime.now(
                                      dt.timezone.utc) + dt.timedelta(hours=1))},
                  'agent-1', 'invalid_request')]
        for path, body, identity, code in cases:
            with self.subTest(path=path, identity=identity):
                status, payload = self.post(path, body, identity)
                self.assertEqual((status, payload['error']), (400, code))
        rows = self.refusal_rows()
        self.assertEqual(len(rows), len(cases))
        self.assertEqual(self.counters()['written'], len(cases))

    def test_the_durable_row_names_the_bearer_identity_and_never_the_body(self):
        """An `X-Identity` header and `actor`/`role`/`approver` body fields are data, not identity.

        A body field outside the route's declared shape is a 404 (the route does not match), so both
        halves are asserted: the shaped request that reaches the state layer records the bearer's
        identity, and the request carrying forged identity fields never becomes a writer at all.
        """
        status, body = self.post('/v1/actions/decision',
                                 {'action_id': self.action_id, 'decision': 'approved'},
                                 headers=bearer('reader-1') + [(b'x-identity', SENTINEL.encode())])
        self.assertEqual((status, body['error']), (400, 'not_authorised'))
        self.assertEqual(self.refusal_rows()[-1]['actor'], 'reader-1')
        self.assertNotIn(SENTINEL, json.dumps(self.raw_audit()))
        forged = {'action_id': self.action_id, 'decision': 'approved', 'actor': SENTINEL,
                  'role': 'human', 'approver': SENTINEL}
        status, body = self.post('/v1/actions/decision', forged, 'reader-1')
        self.assertEqual((status, body['error']), (404, 'not_found'))
        self.assertNotIn(SENTINEL, json.dumps(self.raw_audit()))

    def test_malformed_unknown_and_unauthenticated_requests_never_open_the_write_path(self):
        """Not merely "wrote no row": no connection is even opened, so a stranger cannot be a writer.

        Counting `sqlite3.connect` calls is what makes this an assertion rather than an absence of one;
        the request body is not even read for an unauthenticated call (authentication still runs before
        `receive()`), and the counters stay exactly as they were. Every case here is a role that was
        allowed to reach the parser: the `summary` gate in front of it is a different decision and is
        pinned separately, so this test must not be read as "malformed bytes never produce a row".
        """
        good = bearer('operator')
        decision = {'action_id': self.action_id, 'decision': 'approved'}
        attempts = (('bogus bearer', '/v1/actions/decision', json.dumps(decision).encode(),
                     [(b'authorization', b'Bearer wrong-token-000000000000000000')], 401),
                    ('no authorization header', '/v1/actions/decision', json.dumps(decision).encode(),
                     [], 401),
                    ('two authorization values', '/v1/actions/decision', json.dumps(decision).encode(),
                     [('Authorization', 'Bearer ' + TOKENS['operator']),
                      ('Authorization', 'Bearer ' + TOKENS['operator'])], 401),
                    ('empty bearer', '/v1/actions/decision', json.dumps(decision).encode(),
                     [(b'authorization', b'Bearer ')], 401),
                    ('scheme spelled wrong', '/v1/actions/decision', json.dumps(decision).encode(),
                     [(b'authorization', ('Token ' + TOKENS['operator']).encode())], 401),
                    ('unknown route, valid token', '/v1/nothing-here', b'{}', good, 404),
                    ('body shape outside the route', '/v1/actions/decision',
                     json.dumps(dict(decision, role='human')).encode(), good, 404),
                    ('malformed json', '/v1/actions/decision',
                     b'{"' + SENTINEL.encode() + b'": ,', good, 400),
                    ('array body', '/v1/actions/decision', b'[' + SENTINEL.encode() + b']', good, 400),
                    ('wrong method', '/v1/actions/decision', b'', good, 405))
        with patch('local_observe.platform.state.sqlite3.connect', wraps=sqlite3.connect) as connect:
            for name, path, raw, headers, status in attempts:
                with self.subTest(case=name):
                    connect.reset_mock()
                    method = 'PUT' if name == 'wrong method' else 'POST'
                    got, payload = asyncio.run(request(self.app(), method, path, raw, headers))
                    self.assertEqual(got, status, name)
                    self.assertNotIn(SENTINEL, json.dumps(payload))
                    self.assertEqual(connect.call_count, 0,
                                     f'{name} opened a database connection')
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.counters(), {**{name: 0 for name in refusals.COUNTERS},
                                           'saturated': [], 'capacity': refusals.CAPACITY,
                                           'refill_tokens_per_second': refusals.REFILL_TOKENS_PER_SECOND,
                                           'tokens_available': refusals.CAPACITY,
                                           'scope': refusals.SCOPE, 'resets_on_restart': True})

    def test_an_oversized_body_is_refused_without_a_row(self):
        """413 costs no write: the size gate runs before any state, and stays that way.

        The credential here is a `human`, i.e. one the role gate let through to the size gate. A
        `summary` credential sending the same bytes is refused two statements earlier and is audited
        for it, which is the precedence the unit doc states.
        """
        status, body = self.post('/v1/events', b'[' + SENTINEL.encode() + b']' + b' ' * 70000,
                                 identity='operator')
        self.assertEqual((status, body['error']), (413, 'body_too_large'))
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.counters()['written'], 0)

    def test_the_error_bodies_and_statuses_are_the_ones_the_suite_already_pins(self):
        """Nothing here rewords or renumbers an answer: the audit write is the only observable change."""
        status, body = self.post('/v1/actions/decision', {'action_id': str(uuid.uuid4()),
                                                          'decision': 'sideways'}, 'operator')
        self.assertEqual((status, body), (400, {'error': 'invalid_request', 'detail': 'Invalid decision'}))
        status, body = self.post('/v1/executions/outcome', {'execution_id': str(uuid.uuid4()),
                                                            'outcome': 'succeeded'}, 'runner-1')
        self.assertEqual((status, body['error']), (400, 'conflict'))
        status, body = self.post('/v1/actions/decision', {'action_id': str(uuid.uuid4()),
                                                          'decision': 'approved'}, 'reader-1')
        self.assertEqual(body['detail'], 'Actor is not authorised for this operation')

    def test_a_refused_request_emits_no_api_log_record(self):
        """One refusal is one row, not a row plus a line — and a handler bug is still exactly one ERROR.

        The second half is `tests/test_api_errors.py`'s assertion that a 500 logs one record; a
        per-refusal line at this edge would sit two statements from that expectation and double the
        flood surface the durable row already covers.
        """
        self.post('/v1/actions/decision', {'action_id': str(uuid.uuid4()), 'decision': 'approved'},
                  'reader-1')
        with self.assertNoLogs(API_LOGGER, level='INFO'):
            for _ in range(3):
                self.post('/v1/actions/decision', {'action_id': str(uuid.uuid4()),
                                                   'decision': 'approved'}, 'reader-1')

    def test_runtime_reports_the_counters_and_the_budget_that_produced_them(self):
        status, runtime = self.get('/v1/runtime')
        self.assertEqual(status, 200)
        self.assertEqual(runtime['refusal_audit'], self.store.refusal_audit_status())
        self.post('/v1/actions/decision', {'action_id': str(uuid.uuid4()), 'decision': 'approved'},
                  'reader-1')
        status, runtime = self.get('/v1/runtime')
        self.assertEqual(runtime['refusal_audit']['written'], 1)
        self.assertEqual(runtime['refusal_audit']['scope'], 'process-local')
        self.assertTrue(runtime['refusal_audit']['resets_on_restart'])
        self.assertEqual(self.get('/v1/status')[1], self.store.status(),
                         'the refusal counters did not leak into Store.status()')
        self.assertNotIn(refusals.OPERATION, json.dumps(self.get('/v1/status')[1]))

    def test_the_callback_route_is_not_a_refusal_audit_subject_in_this_scope(self):
        """No callback audit here: a `reader` callback token and a wrong code both write nothing.

        The refusal audit's boundary is the four action methods. `record_callback` refuses with platform
        sentences and answers `None` for a code that matches nothing, and neither path is audited —
        naming that in a test is what keeps it from being quietly read as covered later.
        """
        status, body = self.post('/v1/callbacks/primary', {'token': 't' * 40,
                                                           'action_id': str(uuid.uuid4())}, 'reader-1')
        self.assertEqual((status, body['error']), (400, 'not_authorised'))
        status, body = self.post('/v1/callbacks/primary', {'token': 't' * 40,
                                                           'action_id': str(uuid.uuid4())}, 'operator')
        self.assertEqual((status, body['error']), (401, 'callback_unauthorised'))
        self.assertEqual(self.refusal_rows(), [])
        self.assertEqual(self.counters()['written'], 0)

    def test_a_refusal_through_asgi_is_readable_as_an_audit_row_after_a_reopen(self):
        self.post('/v1/actions/claim', {'action_id': str(uuid.uuid4())}, 'runner-1')
        reopened = Store(self.store.path)
        rows = [row for row in reopened.records('audit', 100) if row['operation'] == refusals.OPERATION]
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0]['detail']),
                         {'attempt': 'claim', 'reason': 'action-not-dispatchable', 'role': 'executor'})
        self.assertEqual(rows[0]['actor'], RUNNER.identity)

    def test_the_reader_can_list_refusal_rows_through_the_records_api(self):
        """The record has to reach the operator, or it is only a counter with a database attached."""
        self.post('/v1/actions/decision', {'action_id': str(uuid.uuid4()), 'decision': 'approved'},
                  'reader-1')
        status, body = self.get('/v1/records/audit')
        self.assertEqual(status, 200)
        rows = [row for row in body['rows'] if row['operation'] == refusals.OPERATION]
        self.assertEqual(len(rows), 1)
        self.assertNotIn(SENTINEL, json.dumps(body))


class RefusalStructurePointerTests(unittest.TestCase):
    """`docs/STRUCTURE.md` is a two-column table, and one draft line put two units in one row.

    Narrow on purpose: three assertions about the two rows this card touched, no Markdown parser and no
    claim about the rest of the file. The failure it pins is silent in a rendered page and loud in a
    diff — a pointer appended to the previous physical line leaves that line a legal-looking 1200-char
    row and takes the row below it out of the table.
    """

    def row_naming(self, needle: str) -> str:
        rows = [line for line in (ROOT / 'docs/STRUCTURE.md').read_text().splitlines()
                if line.startswith('| ') and needle in line]
        self.assertEqual(len(rows), 1, f'STRUCTURE.md must hold exactly one table row naming {needle!r}')
        return rows[0]

    def test_the_refusal_unit_pointer_occupies_its_own_two_column_row(self):
        row = self.row_naming('units/refusal-audit.md')
        self.assertTrue(row.startswith('| [Refusal audit](units/refusal-audit.md) |'),
                        'the refusal pointer is not the row its text says it is')
        self.assertEqual(row.count('|'), 3, 'a two-column row gained a cell (or a neighbour)')
        self.assertTrue(row.endswith(' |'))

    def test_the_shared_http_row_kept_its_own_row(self):
        """The pre-existing row this card's draft swallowed, pinned byte for byte."""
        self.assertEqual(self.row_naming('local_observe/http.py'),
                         '| Shared HTTP, `local_observe/http.py` | Explicit client trust configuration '
                         'shared by integrations; no global TLS changes |')
